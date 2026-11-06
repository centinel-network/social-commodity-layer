/**
 * @file common/blockchain/mmr.h
 * @brief Satocialist Protocol: Append-Only Merkle Mountain Range (MMR) Interface
 *
 * @details
 * Declares the public API for the append-only Merkle Mountain Range (MMR) cryptographic accumulator.
 * MMR trees serve as the primary cryptographic state commitment mechanism for:
 * 1. Historical coin minting and remaining subunit balances (`state->bc.mmr`).
 * 2. Shielded Centinel validation commitments (`state->bc.centinel.validation_commitments`).
 *
 * @section protocol_invariants Protocol Invariants Maintained
  * - Binary Peak Invariant: For any MMR containing N leaves, the number of independent mountain
  *   peaks strictly equals the population count (Hamming weight) of N:
  *   peak_count = popcount(N)
  * - Deterministic Bagging: The unified MMR state root is computed by hashing the concatenated
  *   array of peak digests in descending order of mountain height from left to right.
  * - Logarithmic Inclusion Proof Bounds: The length of an inclusion proof path is strictly bounded
  *   above by floor(log2(N)) <= MAX_PATH_LEN (64 levels), supporting up to 2^64 leaves.
  * - Subunit Balance Peak Mutation: Modifying a leaf's remaining subunit balance in place executes
  *   in O(log N) time along the verified inclusion path, updating the mountain apex without triggering
  *   expensive O(N^2) global tree recomputations.
 *
 * @section thread_safety Concurrency Model & Lock Discipline
 * - MMR structures do not maintain internal synchronization locks.
 * - Thread-safety is enforced by the caller: access to `state->bc.mmr` and
 *   `state->bc.centinel.validation_commitments` must be guarded by `state->bc.rwlock`.
 * - Read operations (root evaluation, proof generation, leaf lookups) require shared read acquisition
 *   (`pthread_rwlock_rdlock`).
 * - Mutation operations (leaf insertion, proof-based peak updates, memory pruning) require exclusive
 *   write acquisition (`pthread_rwlock_wrlock`).
 */

#ifndef MMR_H
#define MMR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include "constants.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: ACCUMULATOR LIFECYCLE MANAGEMENT                                  */
/* ============================================================================ */

/**
 * @brief Initializes an empty Merkle Mountain Range accumulator.
 *
 * @details
 * Sets the initial dynamic arrays (`nodes` and `peaks`) to NULL, resets entry counts
 * to zero, and clears the disk persistence commitment watermark (`uncommitted_start`).
 *
 * @param[out] mmr Pointer to uninitialized @ref MMR structure.
 * @return 0 on success; -1 if `mmr` is NULL.
 *
 * @pre `mmr` must point to valid, allocated memory.
 * @post `mmr->nodes == NULL`, `mmr->peaks == NULL`, `mmr->count == 0`, `mmr->peak_count == 0`.
 * @thread_safety Caller must ensure exclusive access during initialization.
 * @complexity Time: O(1), Space: O(1).
 */
int mmr_init(MMR *mmr);

/**
 * @brief Deallocates all dynamic memory buffers associated with an MMR instance.
 *
 * @details
 * Releases the linear node array (`mmr->nodes`) and the mountain peak index array (`mmr->peaks`),
 * zeroing all structural counters. Safe to call on NULL or already destroyed accumulators.
 *
 * @param[in,out] mmr Pointer to initialized @ref MMR structure (safe if NULL).
 *
 * @pre No concurrent threads may be reading or mutating `mmr`.
 * @post `mmr->nodes` and `mmr->peaks` are freed and set to NULL; counters reset to 0.
 * @thread_safety Unsafe if called concurrently with active readers or writers.
 * @complexity Time: O(1), Space: O(1).
 */
void mmr_destroy(MMR *mmr);

/* ============================================================================ */
/* SECTION 2: LEAF INSERTION & PEAK ACCUMULATION                                */
/* ============================================================================ */

/**
 * @brief Appends a new coin leaf node to the MMR and merges balanced peaks.
 *
 * @details
 * Derives the leaf hash using @ref hash_leaf:
 * `leaf_hash = SHA256(coin_id || htobe64(remaining_subunits))`
 * Appends the leaf to `mmr->nodes` at height 0 and pushes its index to `mmr->peaks`.
 * Evaluates the peak merging loop: while the last two peaks share identical tree heights,
 * combines them into an internal parent node via @ref hash_node:
 * `parent_hash = SHA256(left_peak_hash || right_peak_hash)`
 * Replaces the two merged peaks on the peak stack with the parent index, maintaining the invariant
 * that peak heights are strictly decreasing from left to right.
 *
 * @param[in,out] mmr Pointer to initialized @ref MMR structure.
 * @param[in] coin_id 32-byte unique coin identifier.
 * @param[in] remaining_subunits Unspent subunit balance to commit in the leaf digest.
 * @return 0 on success; -1 on parameter or memory allocation failure.
 *
 * @pre `mmr` and `coin_id` must be non-NULL.
 * @pre Caller must hold `state->bc.rwlock` in write mode if part of ledger state.
 * @post Total leaf count increments by 1; internal parent nodes allocated as required.
 * @complexity Time: O(log N) amortized peak merges, Space: O(1) amortized reallocation.
 */
int mmr_add(MMR *mmr, const uint8_t *coin_id, uint64_t remaining_subunits);

/**
 * @brief Appends a pre-computed 32-byte digest directly as an MMR leaf node.
 *
 * @details
 * Used by the Centinel shielded UTXO subsystem to append validation commitments
 * (C = SHA256(BdlopCommitment)) without applying the secondary coin serialization wrapper.
 * Executes the identical mountain-merging cascade as @ref mmr_add.
 *
 * @param[in,out] mmr Pointer to initialized @ref MMR structure.
 * @param[in] leaf_hash 32-byte pre-computed cryptographic digest.
 * @return 0 on success; -1 on parameter or allocation error.
 *
 * @pre `mmr` and `leaf_hash` must be non-NULL.
 * @pre Caller must hold write synchronization if part of shared ledger state.
 * @post A new height-0 node with `hash == leaf_hash` is appended; peaks updated.
 * @complexity Time: O(log N) amortized, Space: O(1) amortized.
 */
int mmr_add_leaf_hash(MMR *mmr, const uint8_t *leaf_hash);

/* ============================================================================ */
/* SECTION 3: ROOT EVALUATION & PROOF GENERATION                                */
/* ============================================================================ */

/**
 * @brief Computes the unified state root of the Merkle Mountain Range.
 *
 * @details
 * Evaluates the root commitment:
 * - If `peak_count == 0`, produces 32 zero bytes (empty tree).
 * - If `peak_count == 1`, directly outputs the single peak's 32-byte hash (no hashing required).
 * - If `peak_count > 1`, concatenates all peak digests in `mmr->peaks` from left to right
 *   and evaluates a single SHA-256 digest over the combined buffer ("bagging the peaks"):
 *   root = SHA256(peak_0 || peak_1 || ... || peak_{k-1})
 *
 * @param[in] mmr Pointer to @ref MMR structure.
 * @param[out] output 32-byte destination buffer receiving the state root hash.
 *
 * @pre `mmr` and `output` must be non-NULL.
 * @post `output` contains the deterministic 32-byte state root.
 * @complexity Time: O(peak_count) = O(log N), Space: O(peak_count * 32) temporary heap allocation.
 */
void mmr_get_root(MMR *mmr, uint8_t *output);

/**
 * @brief Convenience wrapper extracting the state root of a Blockchain container's primary MMR.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[out] output 32-byte destination buffer receiving the state root.
 *
 * @pre `bc`, `bc->mmr`, and `output` must be non-NULL.
 * @post `output` contains the current 32-byte primary MMR state root.
 * @complexity Time: O(log N), Space: O(log N).
 */
void get_mmr_root(const Blockchain *bc, uint8_t *output);

/**
 * @brief Locates the array index position of a specific coin leaf within the MMR node array.
 *
 * @param[in] mmr Pointer to @ref MMR structure.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @param[in] remaining_subunits Unspent subunit balance matching the target leaf commitment.
 * @return Non-negative node position index on match; -1 if the leaf is absent or uncommitted.
 *
 * @pre `mmr` and `coin_id` must be non-NULL.
 * @complexity Time: O(N) linear scan over height-0 leaf nodes, Space: O(1).
 */
ssize_t mmr_get_leaf_position(MMR *mmr, const uint8_t *coin_id, uint64_t remaining_subunits);

/**
 * @brief Constructs a complete Merkle Mountain Range inclusion proof for a leaf node.
 *
 * @details
 * Traverses from `leaf_idx` upward along parent pointers to its enclosing mountain peak,
 * recording sibling digests into `path_hashes` and their relative positions (left vs right) into `is_left`.
 * Once the apex peak is reached, partitions all other mountain peaks in the accumulator into
 * `left_peaks` (peaks strictly to the left of the target mountain) and `right_peaks` (peaks strictly
 * to the right), providing all cryptographic witness components required for standalone verification.
 *
 * @param[in] mmr Pointer to @ref MMR structure.
 * @param[in] leaf_idx Position index of the target leaf node in `mmr->nodes`.
 * @param[out] path_hashes Array receiving sibling node hashes along the Merkle mountain path.
 * @param[out] is_left Array of flags indicating whether each sibling is a left child (1) or right child (0).
 * @param[out] path_len Destination receiving total sibling count along the path.
 * @param[out] left_peaks Array receiving peak hashes located to the left of the target mountain.
 * @param[out] left_peaks_len Destination receiving count of left peaks.
 * @param[out] right_peaks Array receiving peak hashes located to the right of the target mountain.
 * @param[out] right_peaks_len Destination receiving count of right peaks.
 * @return 0 on success; -1 if parameters are invalid, `leaf_idx` is not a leaf, or buffer bounds are exceeded.
 *
 * @pre `mmr`, `path_hashes`, `is_left`, `path_len`, `left_peaks`, `left_peaks_len`, `right_peaks`, and `right_peaks_len` must be non-NULL.
 * @pre `leaf_idx < mmr->count` and `mmr->nodes[leaf_idx].height == 0`.
 * @post Output arrays populated with valid proof elements bounded by @ref MAX_PATH_LEN and @ref MAX_PEAKS.
 * @complexity Time: O(log N), Space: O(1) stack operations.
 */
int mmr_generate_proof(MMR *mmr, size_t leaf_idx, uint8_t path_hashes[MAX_PATH_LEN][COIN_ID_LEN],
                       int is_left[MAX_PATH_LEN], size_t *path_len,
                       uint8_t left_peaks[MAX_PEAKS][COIN_ID_LEN], size_t *left_peaks_len,
                       uint8_t right_peaks[MAX_PEAKS][COIN_ID_LEN], size_t *right_peaks_len);

/**
 * @brief Cryptographically verifies an MMR leaf inclusion proof against an expected state root.
 *
 * @details
 * 1. Accumulates the leaf hash along the Merkle path hashes using `is_left` positional flags:
 *    - If `is_left[i] == true`: `current = SHA256(path_hashes[i] || current)`.
 *    - If `is_left[i] == false`: `current = SHA256(current || path_hashes[i])`.
 *    The resulting digest represents the reconstructed apex peak of the target mountain.
 * 2. Concatenates `left_peaks`, the reconstructed peak, and `right_peaks` into a contiguous buffer.
 * 3. Evaluates the bagged root hash: if total peaks equals 1, root is the peak itself; otherwise
 *    evaluates SHA-256 over all concatenated peaks.
 * 4. Compares the recomputed root with `root_hash` in constant time.
 *
 * @param[in] leaf_hash 32-byte cryptographic digest of the candidate leaf node.
 * @param[in] proof Pointer to @ref MMRProof structure containing path and peak witness data.
 * @param[in] root_hash 32-byte expected MMR state root commitment.
 * @return 1 if the proof is mathematically valid and matches `root_hash`; 0 on rejection or format error.
 *
 * @pre `leaf_hash`, `proof`, and `root_hash` must be non-NULL.
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(path_len + peaks_len) = O(log N), Space: O(peaks_len * 32) heap allocation.
 */
int verify_mmr_proof(const uint8_t *leaf_hash, const MMRProof *proof, const uint8_t *root_hash);

/* ============================================================================ */
/* SECTION 4: IN-PLACE PEAK MUTATION & STATE PRUNING                            */
/* ============================================================================ */

/**
 * @brief Updates an MMR leaf balance and its corresponding mountain peak in place using an inclusion proof.
 *
 * @details
 * Eliminates O(N^2) global tree recomputations when updating remaining coin balances during transactions.
 * Uses the verified inclusion proof path to rehash intermediate parent digests up to the mountain apex peak,
 * mutating the peak digest in O(log N) time while leaving other independent mountains untouched.
 *
 * @param[in,out] mmr Pointer to @ref MMR structure.
 * @param[in] coin_id 32-byte coin identifier of the leaf being updated.
 * @param[in] old_subunits Previous subunit balance used to locate the leaf index.
 * @param[in] new_subunits Updated subunit balance to commit into the leaf.
 * @param[in] proof Pointer to verified @ref MMRProof inclusion proof.
 * @return 0 on success; -1 if the leaf cannot be located or parameters are invalid.
 *
 * @pre `mmr`, `coin_id`, and `proof` must be non-NULL.
 * @pre Caller must hold `state->bc.rwlock` in write mode (`pthread_rwlock_wrlock`).
 * @post The target leaf and its mountain peak reflect `new_subunits`; subsequent calls to @ref mmr_get_root reflect the change.
 * @complexity Time: O(log N), Space: O(1).
 */
int mmr_update_leaf_with_proof(MMR *mmr, const uint8_t *coin_id, uint64_t old_subunits, uint64_t new_subunits, const MMRProof *proof);

/**
 * @brief Updates a leaf balance and its ancestors using LOCAL tree digests only.
 *
 * @details H-4 fix: rehashes the leaf-to-peak path from the node's own child
 * digests; peer-supplied MMRProof path hashes can never define the apex.
 *
 * @param[in,out] mmr Pointer to @ref MMR structure.
 * @param[in] coin_id 32-byte coin identifier of the leaf being updated.
 * @param[in] old_subunits Previous subunit balance used to locate the leaf index.
 * @param[in] new_subunits Updated subunit balance to commit into the leaf.
 * @return 0 on success; -1 if the leaf cannot be located or the tree is inconsistent.
 */
int mmr_update_leaf_local(MMR *mmr, const uint8_t *coin_id, uint64_t old_subunits, uint64_t new_subunits);

/**
 * @brief Prunes finalized historical non-peak nodes from memory and disk storage.
 *
 * @details
 * Maintains strict O(1) memory consumption across multi-year blockchain execution:
 * 1. Iterates through all nodes committed prior to `uncommitted_start`.
 * 2. Preserves only nodes referenced in `mmr->peaks`; zeroes all non-peak internal node digests.
 * 3. Releases physical RAM pages back to the operating system using `madvise(..., MADV_DONTNEED)`
 *    on Linux/macOS, retaining virtual memory addresses without unmapping.
 * 4. Evicts pruned historical nodes from persistent libmdbx storage using @ref scl_db_prune_mmr_nodes_except_peaks.
 *
 * @param[in,out] mmr Pointer to @ref MMR structure to prune.
 *
 * @pre `mmr` must be non-NULL (safe if count is 0); caller must hold exclusive write lock on ledger state.
 * @post Non-peak nodes prior to `uncommitted_start` are purged from physical memory and disk.
 * @complexity Time: O(uncommitted_start), Space: O(1).
 */
void mmr_prune(MMR *mmr);

#ifdef __cplusplus
}
#endif

#endif // MMR_H
