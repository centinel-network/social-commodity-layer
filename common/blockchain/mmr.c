/**
 * @file common/blockchain/mmr.c
 * @brief Satocialist Protocol: Append-Only Merkle Mountain Range (MMR) Accumulator Implementation
 *
 * @details
 * Implements the linear-array Merkle Mountain Range (MMR) cryptographic accumulator.
 * Provides logarithmic inclusion proof generation, peak accumulation matching popcount arithmetic,
 * in-place peak mutation for fast UTXO balance updating without O(N^2) global rebuilds,
 * constant-time proof verification, and virtual memory physical page dropping via madvise.
 *
 * @section algorithmic_mechanics Algorithmic Mechanics
 * - Mountain Aggregation: A new leaf is appended at height 0 and added to the peak list.
 *   Whenever the two most recent peaks have equal height h, they merge into a parent node at height h+1.
 *   This ensures that the peak stack has at most ceil(log2(N)) elements, corresponding to the
 *   binary representation of N.
 * - Direct Leaf Hashing: Supports appending pre-computed 32-byte digests via @ref mmr_add_leaf_hash
 *   for shielded Centinel validation commitments and batch state synchronization.
 * - Bagging the Peaks: Multiple mountain peaks are accumulated into a single 32-byte state root by hashing
 *   the concatenation of all peak digests from left to right.
 * - Inclusion Proof Paths: The Merkle path is formed by walking from the leaf to its mountain peak,
 *   collecting sibling hashes. Peak positions to the left and right complete the proof.
 * - Proof-Based Peak Updates: When a coin's remaining subunits are altered, @ref mmr_update_leaf_with_proof
 *   climbs the known Merkle path in O(log N) steps to update the apex peak directly, avoiding full tree recomputations.
 * - Constant-Time Verification: Inclusion proofs are verified in constant time via @ref verify_mmr_proof
 *   using @ref secure_memcmp to defend against timing side-channel attacks.
 *
 * @section memory_concurrency Concurrency & Memory Management
 * - Node allocations dynamically double capacity (`capacity * 2`) when `count == capacity`.
 * - Peak array allocations dynamically double (`peak_capacity * 2`) when `peak_count == peak_capacity`.
 * - Topological Pruning: Finalized non-peak nodes are zeroed and released to the OS via
 *   `madvise(..., MADV_DONTNEED)` or `posix_madvise(..., POSIX_MADV_DONTNEED)`, while database entries
 *   are pruned via @ref scl_db_prune_mmr_nodes_except_peaks to bound memory footprint to O(1).
 * - Synchronized via caller-held `state->bc.rwlock`: shared read for queries, exclusive write for mutations.
 */

#include <stddef.h>
#include <openssl/sha.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "mmr.h"
#include "constants.h"
#include "types.h"
#include "utils.h"
#include "database.h"

/* Route local diagnostic logging directly through structured telemetry filters */
#undef printf
#define printf(...) scl_printf(__VA_ARGS__)
#undef fprintf
#define fprintf(stream, ...) do { \
    if (stream == stderr) { \
        scl_log_stderr("MMR", __VA_ARGS__); \
    } else { \
        scl_fprintf(stream, __VA_ARGS__); \
    } \
} while(0)

/* ============================================================================ */
/* SECTION 1: ACCUMULATOR LIFECYCLE MANAGEMENT                                  */
/* ============================================================================ */

int mmr_init(MMR *mmr) {
    if (!mmr) return -1;

    // Initialize empty linear node buffer, peak stack, and capacity counters
    mmr->nodes = NULL;
    mmr->peaks = NULL;
    mmr->count = 0;
    mmr->peak_count = 0;
    mmr->capacity = 0;
    mmr->peak_capacity = 0;
    mmr->uncommitted_start = 0;

    return 0;
}

void mmr_destroy(MMR *mmr) {
    if (!mmr) return;

    // Deallocate dynamic linear node buffer and peak stack allocations
    if (mmr->nodes) {
        free(mmr->nodes);
        mmr->nodes = NULL;
    }
    if (mmr->peaks) {
        free(mmr->peaks);
        mmr->peaks = NULL;
    }

    mmr->count = 0;
    mmr->peak_count = 0;
    mmr->capacity = 0;
    mmr->peak_capacity = 0;
    mmr->uncommitted_start = 0;
}

/* ============================================================================ */
/* SECTION 2: LEAF INSERTION & BINARY PEAK MERGING                              */
/* ============================================================================ */

int mmr_add(MMR *mmr, const uint8_t *coin_id, uint64_t remaining_subunits) {
    if (!mmr || !coin_id) return -1;

    scl_log(LOG_LEVEL_TRACE, "MMR", "mmr_add: inserting leaf node");

    // 1. Expand linear node capacity if saturated
    if (mmr->count >= mmr->capacity) {
        size_t new_cap = (mmr->capacity == 0) ? 1024 : mmr->capacity * 2;
        while (new_cap <= mmr->count) {
            new_cap *= 2;
        }
        MMRNode *new_nodes = realloc(mmr->nodes, new_cap * sizeof(MMRNode));
        if (!new_nodes) {
            perror("Failed to allocate MMR nodes");
            return -1;
        }
        mmr->nodes = new_nodes;
        mmr->capacity = new_cap;
    }

    // 2. Initialize new height-0 leaf node
    size_t new_leaf_idx = mmr->count;
    hash_leaf(coin_id, remaining_subunits, mmr->nodes[new_leaf_idx].hash);
    mmr->nodes[new_leaf_idx].position = new_leaf_idx;
    mmr->nodes[new_leaf_idx].height = 0;
    mmr->nodes[new_leaf_idx].parent = -1;
    mmr->nodes[new_leaf_idx].left_child = -1;
    mmr->nodes[new_leaf_idx].right_child = -1;
    mmr->count++;

    // 3. Expand peak index stack capacity if saturated
    if (mmr->peak_count >= mmr->peak_capacity) {
        size_t new_cap = (mmr->peak_capacity == 0) ? 64 : mmr->peak_capacity * 2;
        while (new_cap <= mmr->peak_count) {
            new_cap *= 2;
        }
        size_t *new_peaks = realloc(mmr->peaks, new_cap * sizeof(size_t));
        if (!new_peaks) {
            perror("Failed to allocate MMR peaks");
            return -1;
        }
        mmr->peaks = new_peaks;
        mmr->peak_capacity = new_cap;
    }
    mmr->peaks[mmr->peak_count++] = new_leaf_idx;

    // 4. Cascade merge balanced peaks of equal height
    while (mmr->peak_count >= 2) {
        size_t last = mmr->peaks[mmr->peak_count - 1];
        size_t second_last = mmr->peaks[mmr->peak_count - 2];

        // Break if heights diverge (peak stack remains ordered descending by height)
        if (mmr->nodes[last].height != mmr->nodes[second_last].height) {
            break;
        }

        // Expand node array capacity if parent node requires allocation
        if (mmr->count >= mmr->capacity) {
            size_t new_cap = (mmr->capacity == 0) ? 1024 : mmr->capacity * 2;
            while (new_cap <= mmr->count) {
                new_cap *= 2;
            }
            MMRNode *new_nodes = realloc(mmr->nodes, new_cap * sizeof(MMRNode));
            if (!new_nodes) {
                perror("Failed to allocate parent MMR nodes");
                return -1;
            }
            mmr->nodes = new_nodes;
            mmr->capacity = new_cap;
        }

        // Construct internal parent node
        hash_node(mmr->nodes[second_last].hash, mmr->nodes[last].hash, mmr->nodes[mmr->count].hash);
        mmr->nodes[mmr->count].position = mmr->count;
        mmr->nodes[mmr->count].height = mmr->nodes[last].height + 1;
        mmr->nodes[mmr->count].parent = -1;
        mmr->nodes[mmr->count].left_child = (ssize_t)second_last;
        mmr->nodes[mmr->count].right_child = (ssize_t)last;

        size_t parent_idx = mmr->count++;
        mmr->nodes[second_last].parent = (ssize_t)parent_idx;
        mmr->nodes[last].parent = (ssize_t)parent_idx;

        // Replace merged children on peak stack with new parent
        mmr->peak_count--;
        mmr->peaks[mmr->peak_count - 1] = parent_idx;
    }

    scl_log(LOG_LEVEL_TRACE, "MMR", "mmr_add: insertion complete, total_nodes=%zu, peak_count=%zu",
            mmr->count, mmr->peak_count);
    return 0;
}

int mmr_add_leaf_hash(MMR *mmr, const uint8_t *leaf_hash) {
    if (!mmr || !leaf_hash) return -1;

    // 1. Expand linear node capacity if saturated
    if (mmr->count >= mmr->capacity) {
        size_t new_cap = (mmr->capacity == 0) ? 1024 : mmr->capacity * 2;
        while (new_cap <= mmr->count) {
            new_cap *= 2;
        }
        MMRNode *new_nodes = realloc(mmr->nodes, new_cap * sizeof(MMRNode));
        if (!new_nodes) {
            perror("Failed to allocate MMR nodes");
            return -1;
        }
        mmr->nodes = new_nodes;
        mmr->capacity = new_cap;
    }

    // 2. Direct copy of pre-computed digest into height-0 leaf node
    size_t new_leaf_idx = mmr->count;
    memcpy(mmr->nodes[new_leaf_idx].hash, leaf_hash, COIN_ID_LEN);
    mmr->nodes[new_leaf_idx].position = new_leaf_idx;
    mmr->nodes[new_leaf_idx].height = 0;
    mmr->nodes[new_leaf_idx].parent = -1;
    mmr->nodes[new_leaf_idx].left_child = -1;
    mmr->nodes[new_leaf_idx].right_child = -1;
    mmr->count++;

    // 3. Expand peak index stack capacity if saturated
    if (mmr->peak_count >= mmr->peak_capacity) {
        size_t new_cap = (mmr->peak_capacity == 0) ? 64 : mmr->peak_capacity * 2;
        while (new_cap <= mmr->peak_count) {
            new_cap *= 2;
        }
        size_t *new_peaks = realloc(mmr->peaks, new_cap * sizeof(size_t));
        if (!new_peaks) {
            perror("Failed to allocate MMR peaks");
            return -1;
        }
        mmr->peaks = new_peaks;
        mmr->peak_capacity = new_cap;
    }
    mmr->peaks[mmr->peak_count++] = new_leaf_idx;

    // 4. Cascade merge balanced peaks of equal height
    while (mmr->peak_count >= 2) {
        size_t last = mmr->peaks[mmr->peak_count - 1];
        size_t second_last = mmr->peaks[mmr->peak_count - 2];

        // Break if heights diverge (peak stack remains ordered descending by height)
        if (mmr->nodes[last].height != mmr->nodes[second_last].height) {
            break;
        }

        // Expand node array capacity if parent node requires allocation
        if (mmr->count >= mmr->capacity) {
            size_t new_cap = (mmr->capacity == 0) ? 1024 : mmr->capacity * 2;
            while (new_cap <= mmr->count) {
                new_cap *= 2;
            }
            MMRNode *new_nodes = realloc(mmr->nodes, new_cap * sizeof(MMRNode));
            if (!new_nodes) {
                perror("Failed to allocate parent MMR nodes");
                return -1;
            }
            mmr->nodes = new_nodes;
            mmr->capacity = new_cap;
        }

        // Construct internal parent node
        hash_node(mmr->nodes[second_last].hash, mmr->nodes[last].hash, mmr->nodes[mmr->count].hash);
        mmr->nodes[mmr->count].position = mmr->count;
        mmr->nodes[mmr->count].height = mmr->nodes[last].height + 1;
        mmr->nodes[mmr->count].parent = -1;
        mmr->nodes[mmr->count].left_child = (ssize_t)second_last;
        mmr->nodes[mmr->count].right_child = (ssize_t)last;

        size_t parent_idx = mmr->count++;
        mmr->nodes[second_last].parent = (ssize_t)parent_idx;
        mmr->nodes[last].parent = (ssize_t)parent_idx;

        // Replace merged children on peak stack with new parent
        mmr->peak_count--;
        mmr->peaks[mmr->peak_count - 1] = parent_idx;
    }

    return 0;
}

/* ============================================================================ */
/* SECTION 3: ROOT CALCULATION & BAGGING                                        */
/* ============================================================================ */

void mmr_get_root(MMR *mmr, uint8_t *output) {
    if (!mmr || !output) {
        scl_log(LOG_LEVEL_ERROR, "MMR", "mmr_get_root: invalid null parameter");
        return;
    }

    // Case 1: Empty accumulator
    if (mmr->peak_count == 0) {
        memset(output, 0, COIN_ID_LEN);
        scl_log(LOG_LEVEL_TRACE, "MMR", "mmr_get_root: empty accumulator (zero root)");
        return;
    }

    // Case 2: Single mountain peak (root is identical to peak digest, no bagging)
    if (mmr->peak_count == 1) {
        memcpy(output, mmr->nodes[mmr->peaks[0]].hash, COIN_ID_LEN);
        return;
    }

    // Case 3: Bagging multiple peaks via linear SHA-256
    uint8_t *combined = malloc(mmr->peak_count * COIN_ID_LEN);
    if (!combined) {
        perror("mmr_get_root: peak allocation failed");
        memset(output, 0, COIN_ID_LEN);
        return;
    }
    
    // Concatenate peak digests from left to right and hash
    size_t offset = 0;
    for (size_t i = 0; i < mmr->peak_count; i++) {
        memcpy(combined + offset, mmr->nodes[mmr->peaks[i]].hash, COIN_ID_LEN);
        offset += COIN_ID_LEN;
    }

    SHA256(combined, offset, output);
    free(combined);
}

void get_mmr_root(const Blockchain *bc, uint8_t *output) {
    // Forward state root query to the primary blockchain MMR
    if (!bc || !bc->mmr || !output) return;
    mmr_get_root(bc->mmr, output);
}

ssize_t mmr_get_leaf_position(MMR *mmr, const uint8_t *coin_id, uint64_t remaining_subunits) {
    if (!mmr || !coin_id) {
        scl_log(LOG_LEVEL_ERROR, "MMR", "mmr_get_leaf_position: invalid parameter");
        return -1;
    }

    // Compute expected leaf hash from coin ID and balance
    uint8_t target_hash[COIN_ID_LEN];
    hash_leaf(coin_id, remaining_subunits, target_hash);

    // Linear probe across leaf nodes (height == 0)
    for (size_t i = 0; i < mmr->count; i++) {
        if (mmr->nodes[i].height == 0) {
            if (memcmp(mmr->nodes[i].hash, target_hash, COIN_ID_LEN) == 0) {
                return (ssize_t)i;
            }
        }
    }

    return -1;
}

/* ============================================================================ */
/* SECTION 4: INCLUSION PROOF GENERATION & VERIFICATION                         */
/* ============================================================================ */

int mmr_generate_proof(MMR *mmr, size_t leaf_idx, uint8_t path_hashes[MAX_PATH_LEN][COIN_ID_LEN],
                       int is_left[MAX_PATH_LEN], size_t *path_len,
                       uint8_t left_peaks[MAX_PEAKS][COIN_ID_LEN], size_t *left_peaks_len,
                       uint8_t right_peaks[MAX_PEAKS][COIN_ID_LEN], size_t *right_peaks_len) {
    if (!mmr || leaf_idx >= mmr->count || mmr->nodes[leaf_idx].height != 0) {
        scl_log(LOG_LEVEL_ERROR, "MMR", "Invalid MMR or leaf index: mmr=%p, leaf_idx=%zu", (void*)mmr, leaf_idx);
        return -1;
    }

    *path_len = 0;
    *left_peaks_len = 0;
    *right_peaks_len = 0;
    size_t current_idx = leaf_idx;

    // 1. Traverse upward from leaf to its mountain peak, recording siblings
    while (mmr->nodes[current_idx].parent != -1) {
        ssize_t parent_idx = mmr->nodes[current_idx].parent;
        ssize_t sibling_idx = (mmr->nodes[parent_idx].left_child == (ssize_t)current_idx) ?
                               mmr->nodes[parent_idx].right_child : mmr->nodes[parent_idx].left_child;

        if (sibling_idx < 0 || (size_t)sibling_idx >= mmr->count) {
            return -1;
        }
        if (*path_len >= MAX_PATH_LEN) {
            return -1;
        }

        memcpy(path_hashes[*path_len], mmr->nodes[sibling_idx].hash, COIN_ID_LEN);
        // Sibling is to the left if its array position is less than current node
        is_left[*path_len] = (sibling_idx < (ssize_t)current_idx) ? 1 : 0;
        (*path_len)++;

        current_idx = (size_t)parent_idx;
    }

    // 2. Identify index of the apex peak within mmr->peaks
    ssize_t peak_idx = -1;
    for (size_t i = 0; i < mmr->peak_count; i++) {
        if (mmr->peaks[i] == current_idx) {
            peak_idx = (ssize_t)i;
            break;
        }
    }
    if (peak_idx == -1) {
        return -1;
    }

    // 3. Accumulate left peaks (mountains with index < peak_idx)
    for (size_t i = 0; i < (size_t)peak_idx; i++) {
        if (*left_peaks_len >= MAX_PEAKS) {
            return -1;
        }
        memcpy(left_peaks[*left_peaks_len], mmr->nodes[mmr->peaks[i]].hash, COIN_ID_LEN);
        (*left_peaks_len)++;
    }

    // 4. Accumulate right peaks (mountains with index > peak_idx)
    for (size_t i = (size_t)peak_idx + 1; i < mmr->peak_count; i++) {
        if (*right_peaks_len >= MAX_PEAKS) {
            return -1;
        }
        memcpy(right_peaks[*right_peaks_len], mmr->nodes[mmr->peaks[i]].hash, COIN_ID_LEN);
        (*right_peaks_len)++;
    }

    scl_log(LOG_LEVEL_DEBUG, "MMR", "Proof generated: path_len=%zu, left_peaks=%zu, right_peaks=%zu",
            *path_len, *left_peaks_len, *right_peaks_len);
    return 0;
}

int verify_mmr_proof(const uint8_t *leaf_hash, const MMRProof *proof, const uint8_t *root_hash) {
    if (!proof || !leaf_hash || !root_hash) {
        fprintf(stderr, "[MMR] Invalid null proof parameters in verify_mmr_proof\n");
        return 0;
    }

    if (proof->path_len > MAX_PATH_LEN || proof->left_peaks_len > MAX_PEAKS ||
        proof->right_peaks_len > MAX_PEAKS) {
        fprintf(stderr, "[MMR] Proof dimensions exceed protocol limits: path=%zu, left=%zu, right=%zu\n",
                proof->path_len, proof->left_peaks_len, proof->right_peaks_len);
        return 0;
    }

    uint8_t current[COIN_ID_LEN];
    memcpy(current, leaf_hash, COIN_ID_LEN);

    // 1. Reconstruct mountain peak along Merkle sibling path
    for (size_t i = 0; i < proof->path_len; i++) {
        if (proof->is_left[i]) {
            hash_node(proof->path_hashes[i], current, current);
        } else {
            hash_node(current, proof->path_hashes[i], current);
        }
    }

    // 2. Bag peaks: [left_peaks] || [reconstructed_peak] || [right_peaks]
    size_t total_peaks = proof->left_peaks_len + 1 + proof->right_peaks_len;
    uint8_t *peaks = calloc(total_peaks, COIN_ID_LEN);
    if (!peaks) {
        fprintf(stderr, "[MMR] Peak staging allocation failed\n");
        return 0;
    }

    size_t offset = 0;
    for (size_t i = 0; i < proof->left_peaks_len; i++) {
        memcpy(peaks + offset, proof->left_peaks[i], COIN_ID_LEN);
        offset += COIN_ID_LEN;
    }

    memcpy(peaks + offset, current, COIN_ID_LEN);
    offset += COIN_ID_LEN;

    for (size_t i = 0; i < proof->right_peaks_len; i++) {
        memcpy(peaks + offset, proof->right_peaks[i], COIN_ID_LEN);
        offset += COIN_ID_LEN;
    }

    // 3. Evaluate candidate root
    uint8_t computed_root[COIN_ID_LEN];
    if (total_peaks == 1) {
        memcpy(computed_root, current, COIN_ID_LEN);
    } else {
        SHA256(peaks, total_peaks * COIN_ID_LEN, computed_root);
    }
    free(peaks);

    // 4. Constant-time verification against expected root commitment
    return (secure_memcmp(computed_root, root_hash, COIN_ID_LEN) == 0) ? 1 : 0;
}

/* ============================================================================ */
/* SECTION 5: IN-PLACE PEAK MUTATION & TOPOLOGICAL PRUNING                      */
/* ============================================================================ */

int mmr_update_leaf_with_proof(MMR *mmr, const uint8_t *coin_id, uint64_t old_subunits, uint64_t new_subunits, const MMRProof *proof) {
    if (!mmr || !coin_id || !proof) return -1;

    // Locate leaf position corresponding to original balance
    ssize_t leaf_idx = mmr_get_leaf_position(mmr, coin_id, old_subunits);
    if (leaf_idx < 0) return -1;

    // Compute updated leaf hash reflecting new subunit balance
    uint8_t curr_hash[COIN_ID_LEN];
    hash_leaf(coin_id, new_subunits, curr_hash);

    // Update in-memory leaf digest if it has not been evicted by pruning
    if (!is_zeroed(mmr->nodes[leaf_idx].hash, COIN_ID_LEN)) {
        memcpy(mmr->nodes[leaf_idx].hash, curr_hash, COIN_ID_LEN);
    }

    // Recompute path hashes upward using the client's inclusion proof
    for (size_t i = 0; i < proof->path_len; i++) {
        if (proof->is_left[i]) {
            hash_node(proof->path_hashes[i], curr_hash, curr_hash);
        } else {
            hash_node(curr_hash, proof->path_hashes[i], curr_hash);
        }
    }

    // Ascend to the mountain apex peak
    size_t curr = (size_t)leaf_idx;
    while (mmr->nodes[curr].parent != -1) {
        curr = (size_t)mmr->nodes[curr].parent;
    }

    // Mutate the apex peak digest directly (bypasses full O(N^2) tree rebuild)
    memcpy(mmr->nodes[curr].hash, curr_hash, COIN_ID_LEN);
    return 0;
}

void mmr_prune(MMR *mmr) {
    if (!mmr || mmr->count == 0) return;

    scl_log(LOG_LEVEL_INFO, "MMR", "Pruning finalized Merkle Mountain Range to preserve O(1) RAM footprint");

    // 1. Zero out non-peak nodes in memory prior to the uncommitted boundary
    for (size_t i = 0; i < mmr->uncommitted_start; i++) {
        bool is_peak = false;
        for (size_t p = 0; p < mmr->peak_count; p++) {
            if (mmr->peaks[p] == i) {
                is_peak = true;
                break;
            }
        }
        if (!is_peak && mmr->nodes[i].height > 0) {
            memset(mmr->nodes[i].hash, 0, COIN_ID_LEN);
        }
    }

#if defined(__linux__) || defined(__APPLE__)
    // 2. Release physical RAM pages to OS while preserving virtual address space
    size_t bytes_to_free = mmr->uncommitted_start * sizeof(MMRNode);
    size_t page_size = (size_t)getpagesize();
    bytes_to_free = (bytes_to_free / page_size) * page_size; // Align to hardware page boundary

    if (bytes_to_free > 0 && mmr->nodes) {
#if defined(POSIX_MADV_DONTNEED)
        posix_madvise(mmr->nodes, bytes_to_free, POSIX_MADV_DONTNEED);
#elif defined(MADV_DONTNEED)
        madvise(mmr->nodes, bytes_to_free, MADV_DONTNEED);
#endif
    }
#endif

    // 3. Purge committed non-peak nodes from persistent libmdbx storage
    scl_db_prune_mmr_nodes_except_peaks(mmr->peaks, mmr->peak_count, mmr->uncommitted_start);
}
