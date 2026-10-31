/**
 * @file common/blockchain/blockchain.h
 * @brief Satocialist Protocol: Core Blockchain Ledger, Pointer State, and UTXO Subsystem Interface
 *
 * @details
 * Declares the foundational public application programming interfaces for managing the Satocialist
 * Cryptographic Ledger (SCL). This includes lifecycle management of the @ref Blockchain container,
 * creation and range partitioning of discrete @ref SCLCoin and @ref Pointer UTXO structures,
 * greedy pointer selection algorithms, state-transition updates with Merkle Mountain Range (MMR)
 * peak tracking, transaction broadcast pipelines, balance/fee accounting routines, and fast-lookup
 * Bloom filter operations for spent ZK-PRF nullifiers.
 *
 * @section protocol_invariants Protocol Invariants Maintained
 * - Conservation of Subunit Volume (Lean 4 invariants.lean: Theorem 11): In any valid transaction
 *   state transition executed via @ref update_transfer_state, the sum of input pointer subunits
 *   strictly equals the sum of output transfer subunits, fee burn/recycled subunits, and change subunits.
 * - Supply Hard-Cap Boundary (Lean 4 invariants.lean: Theorem 5): Lifetime issued and rewarded subunits
 *   cannot exceed @ref MAX_TOTAL_SUBUNITS (2,560,000,000,000,000 subunits = 16,000,000 SCL).
 * - Non-Overlapping Subunit Ranges: Subunit ranges `[start_subunit, end_subunit]` within any parent
 *   @ref SCLCoin are disjoint, contiguous, and bounded strictly by `[0, total_subunits - 1]`.
 * - Staking State Separation: Pointers flagged with `staked = 1` are locked under threshold committee
 *   custody and cannot be spent in standard peer-to-peer transfers without an authenticated unstake ceremony.
 *
 * @section threading_model Concurrency and Synchronization Architecture
 * - Read-Write Lock Ordering: Operations inspecting or mutating the blockchain must adhere to the
 *   descending synchronization hierarchy:
 *     1. `state->mutex` (Global coordinator mutex)
 *     2. `state->ledger_mutex` (Tip block and reorganization lock)
 *     3. `bc->rwlock` (Blockchain state read-write lock: shared read for balance audits, exclusive write for mutations)
 *     4. `state->user_wallet.utxo_mutex` (Private wallet UTXO lock)
 *     5. `bc->centinel.bloom_mutex` (Bloom filter mutation lock)
 * - Lock-Free Lookups: Mempool conflict checks execute using atomic acquire loads on `state->pending_operations`.
 */

#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "types.h"
#include "constants.h"
#include "consensus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: BLOCKCHAIN CONTAINER LIFECYCLE                                    */
/* ============================================================================ */

/**
 * @brief Allocates and initializes the in-memory Blockchain ledger subsystem.
 *
 * @details
 * Allocates and initializes the primary state Merkle Mountain Range (@ref MMR), the coin hash table,
 * the pointer hash table, the coin-to-pointer index table, the chronological coin insertion array,
 * the POSIX read-write lock (`bc->rwlock`), and the shielded Centinel ZK-PRF sub-state (nullifier
 * hash table, validation commitment MMR, and nullifier Bloom filter).
 *
 * @param[out] bc Pointer to uninitialized @ref Blockchain structure.
 * @return 0 on successful initialization; -1 on memory allocation or mutex/rwlock failure.
 *
 * @pre `bc` must point to allocated, writable memory.
 * @post `bc` is fully configured and ready for concurrent read/write transactions.
 * @sideeffect Allocates heap memory for MMR nodes, hash tables, and Bloom filter buffers.
 * @thread_safety Not thread-safe during initial setup. Caller must ensure exclusive access.
 * @complexity Time: O(1), Space: O(1) baseline heap allocations.
 */
int blockchain_init(Blockchain *bc);

/**
 * @brief Destroys the Blockchain ledger subsystem and releases all associated heap memory.
 *
 * @details
 * Destroys and frees the primary MMR, coin table, pointer table, coin-to-pointer mappings,
 * chronological insert-order array, Centinel nullifier set, validation commitment MMR,
 * nullifier Bloom filter, and internal synchronization primitives.
 *
 * @param[in,out] bc Pointer to initialized @ref Blockchain structure (safe if NULL).
 *
 * @pre No concurrent threads may be actively reading or writing to `bc`.
 * @post All dynamic heap structures within `bc` are freed; `bc->rwlock` is destroyed.
 * @sideeffect Reclaims dynamic memory allocated to ledger indices and trees.
 * @thread_safety Unsafe if called concurrently with readers or writers.
 * @complexity Time: O(N) where N is the total number of live entries in hash tables and MMRs, Space: O(1).
 */
void blockchain_destroy(Blockchain *bc);

/* ============================================================================ */
/* SECTION 2: ASSET CREATION & RANGE POINTER MANAGEMENT                         */
/* ============================================================================ */

/**
 * @brief Inserts an authenticated Pointer range into the pointer index and coin-to-pointer table.
 *
 * @details
 * Verifies that the parent @ref SCLCoin exists within `bc->coin_table`, verifies that the
 * subunit range `[start_subunit, end_subunit]` is valid and bounded by the parent coin's total capacity,
 * and indexes the pointer into both `bc->pointer_table` (keyed by `pointer_id`) and `bc->coin_pointers`
 * (keyed by `parent_coin_id`).
 *
 * @param[in,out] bc Pointer to initialized @ref Blockchain structure.
 * @param[in] pointer Pointer to the @ref Pointer structure to insert.
 *
 * @pre Caller must hold `bc->rwlock` in write mode (`pthread_rwlock_wrlock`).
 * @pre `pointer` must specify valid `parent_coin_id` and bounds `start_subunit <= end_subunit < parent->total_subunits`.
 * @post Pointer is indexed and discoverable across ledger query functions.
 * @sideeffect Allocates entries in `bc->pointer_table` and `bc->coin_pointers`.
 * @thread_safety Synchronized via caller-held `bc->rwlock` write lock.
 * @complexity Time: O(1) amortized hash table insertion, Space: O(1).
 */
void blockchain_add_pointer(Blockchain *bc, const Pointer *pointer);

/**
 * @brief Instantiates a new root issuance SCLCoin asset structure.
 *
 * @details
 * Derives the owner address from the owner's Dilithium5 public verification key:
 * `owner_address = SHA256(owner_pubkey, PUBKEY_LEN)`.
 * Computes the unique 32-byte coin identifier:
 * `coin_id = SHA256(creation_tx_hash || owner_pubkey)`.
 * Initializes total and remaining subunits to @ref SUBUNITS_PER_COIN (160,000,000 subunits = 1 SCL).
 *
 * @param[in] creation_tx_hash 32-byte hash of the transaction or coinbase block creating this coin.
 * @param[in] owner_pubkey 2,592-byte Dilithium5 public key of the initial recipient.
 * @return Fully initialized @ref SCLCoin structure.
 *
 * @pre `creation_tx_hash` must point to at least 32 readable bytes.
 * @pre `owner_pubkey` must point to a valid 2,592-byte Dilithium5 public key.
 * @post Returns an SCLCoin with `total_subunits = remaining_subunits = SUBUNITS_PER_COIN`.
 * @sideeffect None (pure stack computation).
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(1), Space: O(1).
 */
SCLCoin create_coin(const uint8_t *creation_tx_hash, const uint8_t *owner_pubkey);

/**
 * @brief Selects a minimal set of unspent input pointers satisfying a target subunit amount using a greedy strategy.
 *
 * @details
 * Scans `bc->pointer_table` for unspent pointers matching the caller's 32-byte User ID
 * (`SHA256(pubkey)`), matching the requested staking status (`staked == select_staked`).
 * If `exclude_mempool == true`, pointers already referenced as inputs in pending mempool operations
 * are filtered out to prevent double-spend rejection.
 * Available candidate pointers are sorted in descending order of subunit capacity via `qsort`
 * and greedily accumulated until the target amount is satisfied or the input limit (@ref MAX_SELECTED_POINTERS) is reached.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the pointer owner.
 * @param[in] target_subunits Minimum cumulative subunits required (principal + fee).
 * @param[out] num_selected Destination pointer receiving the count of selected pointers.
 * @param[in] select_staked Flag: `true` selects staked pointers (for unstaking); `false` selects liquid pointers.
 * @param[in] exclude_mempool Flag: `true` filters out pointers currently locked in mempool transactions.
 * @return Dynamically allocated array of @ref Pointer structures on success (caller must free);
 *         NULL if available balance is insufficient or allocation fails (with `*num_selected = 0`).
 *
 * @pre `state`, `pubkey`, and `num_selected` must be non-NULL; `target_subunits > 0`.
 * @post On success, returns heap array of length `*num_selected` whose sum of subunits is `>= target_subunits`.
 * @sideeffect Allocates heap memory for candidate and result pointer arrays; acquires `bc->rwlock` in read mode.
 * @thread_safety Acquires `state->bc.rwlock` in read mode internally.
 * @complexity Time: O(N log N) where N is available unspent pointers matching criteria, Space: O(N) heap allocations.
 */
Pointer *select_pointers(State *state, const uint8_t pubkey[PUBKEY_LEN], uint64_t target_subunits,
                         size_t *num_selected, bool select_staked, bool exclude_mempool);

/* ============================================================================ */
/* SECTION 3: TRANSACTION CREATION & ON-CHAIN BROADCAST PIPELINES               */
/* ============================================================================ */

/**
 * @brief Constructs, signs, proves, and broadcasts a peer-to-peer subunit pointer transfer transaction.
 *
 * @details
 * Execution pipeline:
 * 1. Evaluates standard fee via @ref calculate_fee (`amount_subunits`, `halve = false`).
 * 2. Selects unspent input pointers via @ref select_pointers. If pointers are locked in mempool, returns 2 for retry.
 * 3. Generates MMR inclusion proofs for each input pointer against the current state root.
 * 4. Computes the Merkle root of input pointers and signs it with the sender's Dilithium5 private key.
 * 5. Evaluates the Module-SIS PRF nullifier and generates a zero-knowledge proof of knowledge (@ref generate_zk_prf_proof).
 * 6. Signs the consensus-critical transaction fields and constructs an @ref OP_TRANSFER_POINTER operation.
 * 7. Enqueues operation into the local mempool via @ref add_pending_operation and broadcasts across P2P gossip.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] recipient_pubkey 2,592-byte Dilithium5 public key of the recipient.
 * @param[in] amount_subunits Volume of subunits to transfer (excluding fee).
 * @param[in] is_recreation Flag: `true` indicates background worker recreation; suppresses duplicate log warnings.
 * @return 0 on successful construction and broadcast;
 *         2 if required input pointers are temporarily locked in mempool (caller should defer);
 *         -1 on parameter, cryptographic, or balance failure.
 *
 * @pre `state` and `recipient_pubkey` must be non-NULL; `amount_subunits > 0`.
 * @post On success (0), new operation is added to `state->pending_operations` and broadcasted to network.
 * @sideeffect Allocates thread-local arena memory; acquires `state->mutex` and `state->bc.rwlock`.
 * @thread_safety Thread-safe; acquires internal synchronization locks as needed.
 * @complexity Time: O(N * ZK_KAPPA) where N is input count and ZK_KAPPA is Stern proof rounds (219), Space: O(ZK_PROOF_MAX_LEN).
 */
int create_and_broadcast_transfer(State *state, const uint8_t *recipient_pubkey, uint64_t amount_subunits, bool is_recreation);

/**
 * @brief Constructs, orchestrates threshold signing, and broadcasts a staking transaction (@ref OP_STAKE).
 *
 * @details
 * Locks unspent liquid pointers under the custody of the active threshold committee public key.
 * Evaluates the halved fee via @ref calculate_fee (`halve = true`). Initiates a decentralized
 * threshold signing ceremony across connected validator peers to authorize the stake receipt.
 * Upon successful threshold signature aggregation, broadcasts the resulting @ref OP_STAKE operation.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] amount_subunits Volume of subunits to lock in staking status.
 * @param[in] is_recreation Flag: `true` if invoked by background recreation worker.
 * @return 0 on successful construction and broadcast;
 *         2 if input pointers are temporarily locked in mempool (caller should defer);
 *         -1 on parameter, cryptographic, balance, or threshold timeout failure.
 *
 * @pre `state` must be non-NULL; `amount_subunits > 0`.
 * @post Staked pointers transitioned to `staked = 1` upon block commitment.
 * @sideeffect Spawns partial signature collector threads; broadcasts network messages.
 * @thread_safety Synchronizes via `state->mutex`, `state->p2p_network.mutex`, and `state->bc.rwlock`.
 * @complexity Time: O(N + threshold_signing_time), Space: O(MAX_INPUTS * sizeof(Pointer)).
 */
int create_and_broadcast_stake(State *state, uint64_t amount_subunits, bool is_recreation);

/**
 * @brief Constructs, orchestrates threshold signing, and broadcasts an unstaking transaction (@ref OP_UNSTAKE).
 *
 * @details
 * Unlocks staked pointers (`staked = 1`) held under threshold committee custody, returning liquid
 * subunits to the validator's local public key. Evaluates halved fee rate. Gathers partial threshold
 * signatures from active committee peers to authorize release of the staked principal and fee deduction.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] amount_subunits Volume of staked subunits to unlock.
 * @param[in] is_recreation Flag: `true` if invoked by background recreation worker.
 * @return 0 on successful construction and broadcast;
 *         2 if staked pointers are temporarily locked in mempool (caller should defer);
 *         -1 on parameter, cryptographic, balance, or threshold timeout failure.
 *
 * @pre `state` must be non-NULL; `amount_subunits > 0`.
 * @post Resulting output pointers flagged with `staked = 0` (liquid) upon block confirmation.
 * @sideeffect Communicates with threshold peers; stages operation in mempool.
 * @thread_safety Synchronizes via `state->mutex`, `state->p2p_network.mutex`, and `state->bc.rwlock`.
 * @complexity Time: O(N + threshold_signing_time), Space: O(MAX_INPUTS * sizeof(Pointer)).
 */
int create_and_broadcast_unstake(State *state, uint64_t amount_subunits, bool is_recreation);

/**
 * @brief Interactive terminal routine guiding user through transfer recipient input, balance verification, and dispatch.
 *
 * @param[in] user Pointer to the local operator's @ref User profile.
 * @param[in,out] state Pointer to global node state container.
 *
 * @pre `user` and `state` must be non-NULL.
 * @post If inputs are validated, delegates to @ref create_and_broadcast_transfer.
 * @thread_safety Acquires `state->mutex` for balance queries.
 * @complexity Time: O(CLI input + transfer construction), Space: O(1).
 */
void initiate_transfer(User *user, State *state);

/**
 * @brief Interactive terminal routine guiding user through staking amount entry and dispatch.
 *
 * @param[in] user Pointer to the local operator's @ref User profile.
 * @param[in,out] state Pointer to global node state container.
 * @return 0 on successful initiation or queuing; -1 on input error or abort.
 *
 * @pre `user` and `state` must be non-NULL.
 * @post If inputs are validated, delegates to @ref create_and_broadcast_stake (or enqueues background retry).
 * @thread_safety Acquires `state->mutex` for balance queries and scheduled subunit updates.
 * @complexity Time: O(CLI input + stake construction), Space: O(1).
 */
int initiate_stake(User *user, State *state);

/**
 * @brief Interactive terminal routine guiding user through unstaking amount entry and dispatch.
 *
 * @param[in] user Pointer to the local operator's @ref User profile.
 * @param[in,out] state Pointer to global node state container.
 * @return 0 on successful initiation or queuing; -1 on input error or abort.
 *
 * @pre `user` and `state` must be non-NULL.
 * @post If inputs are validated, delegates to @ref create_and_broadcast_unstake (or enqueues background retry).
 * @thread_safety Acquires `state->mutex` for balance queries and scheduled subunit updates.
 * @complexity Time: O(CLI input + unstake construction), Space: O(1).
 */
int initiate_unstake(User *user, State *state);

/* ============================================================================ */
/* SECTION 4: STATE TRANSITION EXECUTION (BLOCK APPLICATION)                    */
/* ============================================================================ */

/**
 * @brief Applies the state transitions of a pointer transfer, stake, or unstake operation to the ledger.
 *
 * @details
 * Formalized under Lean 4 (`Satocialist.utxo_conservation` and `Satocialist.applyOp`).
 * For each input pointer:
 * 1. Verifies unspent status and owner address match in `bc->pointer_table`.
 * 2. Partitions the input range into up to three outputs:
 *    - Transfer Output: Subunits assigned to `recipient_pubkey` with `staked = set_stake_flag`.
 *    - Fee Output: Subunits marked with `spent = 2` (recycled fee pool pointer).
 *    - Change Output: Remaining subunits retained by original owner with status unchanged.
 * 3. Marks original input pointer as `spent = 1` in memory and persistent storage (`scl_db_put_pointer`).
 * 4. Deducts consumed fees from parent coin balances in O(1) time and updates the state MMR leaf
 *    using the client's inclusion proof, completely eliminating O(N^2) tree rebuilds.
 * 5. If any validation step fails, all mutations are rolled back atomically.
 *
 * @param[in,out] bc Pointer to Blockchain state container.
 * @param[in] input_pointers Array of input @ref Pointer structures to spend.
 * @param[in] proofs Array of @ref MMRProof inclusion proofs corresponding to each input (optional; may be NULL).
 * @param[in] num_inputs Count of input pointers (must be in range `[1, MAX_INPUTS]`).
 * @param[in] recipient_pubkey 2,592-byte Dilithium5 public key receiving the transfer output.
 * @param[in] amount Principal subunit volume transferred to recipient.
 * @param[in] tx_hash 32-byte transaction identifier creating the new pointer outputs.
 * @param[in] set_stake_flag Flag: `true` sets `staked = 1` on transfer output; `false` sets `staked = 0`.
 * @param[in] fee Non-refundable transaction fee in subunits allocated to fee pointers.
 * @return 1 on successful state mutation; 0 on error with full rollback.
 *
 * @pre Caller must hold `bc->rwlock` in write mode (`pthread_rwlock_wrlock`).
 * @pre `amount + fee <= sum(inputs[i].subunits)`.
 * @post Input pointers marked `spent = 1`; new output, fee, and change pointers inserted and persisted.
 * @sideeffect Mutates `bc->pointer_table`, `bc->coin_pointers`, `bc->coin_table`, and disk database.
 * @thread_safety Synchronized via caller-held `bc->rwlock` write lock.
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(num_inputs) rollback arrays.
 */
int update_transfer_state(Blockchain *bc, Pointer *input_pointers, MMRProof *proofs, size_t num_inputs,
                          const uint8_t *recipient_pubkey, uint64_t amount, uint8_t tx_hash[COIN_ID_LEN],
                          bool set_stake_flag, uint64_t fee);

/* ============================================================================ */
/* SECTION 5: BALANCE AUDITING & SUPPLY ACCOUNTING                              */
/* ============================================================================ */

/**
 * @brief Computes the cumulative unspent subunit balance owned by a public key.
 *
 * @details
 * Traverses `bc->pointer_table` under a read lock, accumulating subunits (`end_subunit - start_subunit + 1`)
 * for all unspent pointers (`spent == 0`) whose `owner_address` matches `SHA256(pubkey)`
 * and whose `staked` flag matches the requested parameter.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key to audit.
 * @param[in] staked Flag: `true` queries staked balance; `false` queries liquid balance.
 * @return Cumulative unspent subunits owned by the key.
 *
 * @pre `bc` and `pubkey` must be non-NULL.
 * @thread_safety Acquires `bc->rwlock` in read mode internally.
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_balance_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN], bool staked);

/**
 * @brief Computes the cumulative subunits locked in unconfirmed pending mempool operations for an identity.
 *
 * @details
 * Inspects all active slots in `state->pending_operations` via atomic acquire loads.
 * Accumulates amount plus fee for matching operations:
 * - Liquid transfers (@ref OP_TRANSFER_POINTER) and stakes (@ref OP_STAKE) when `expect_staked == false`.
 * - Unstakes (@ref OP_UNSTAKE) when `expect_staked == true`.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the sender.
 * @param[in] expect_staked Flag: `true` checks pending unstaking operations; `false` checks liquid spends.
 * @return Total subunits in-flight across unconfirmed mempool operations.
 *
 * @pre `state` and `pubkey` must be non-NULL.
 * @thread_safety Lock-free inspection of atomic pointer array slots.
 * @complexity Time: O(MAX_PENDING_OPS), Space: O(1).
 */
uint64_t calculate_pending_consumed_subunits(State *state, const uint8_t *pubkey, bool expect_staked);

/**
 * @brief Computes total staked subunits currently locked under a specific threshold public key.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[in] pubkey 2,592-byte threshold committee public key.
 * @return Total staked subunits locked under the key.
 *
 * @pre `bc` and `pubkey` must be non-NULL.
 * @thread_safety Acquires `bc->rwlock` in read mode internally.
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_staked_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN]);

/**
 * @brief Computes total staked subunits attributable to an individual validator identity.
 *
 * @details
 * Resolves ownership by comparing pointer `owner_address` against the validator's local threshold
 * address and cached public key entries in `state->pubkey_cache`.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] target_pk 2,592-byte Dilithium5 public key of the validator.
 * @return Total staked subunits attributable to the validator.
 *
 * @pre `state` and `target_pk` must be non-NULL.
 * @thread_safety Acquires `state->bc.rwlock` in read mode internally.
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_staked_subunits_by_owner(State *state, const uint8_t target_pk[PUBKEY_LEN]);

/**
 * @brief Computes total staked subunits across all active pointers in the entire ledger.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @return Grand total of all staked subunits currently locked across the network.
 *
 * @pre `bc` must be non-NULL; caller must hold `bc->rwlock` in read or write mode.
 * @thread_safety Requires caller-held synchronization on `bc->rwlock`.
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_total_staked_subunits(const Blockchain *bc);

/**
 * @brief Computes total transaction fee subunits currently held in un-recycled fee pointers (`spent == 2`).
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @return Cumulative unspent fee pool balance in atomic subunits.
 *
 * @pre `bc` must be non-NULL; caller must hold `bc->rwlock` in read or write mode.
 * @thread_safety Requires caller-held synchronization on `bc->rwlock`.
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_total_fees_subunits(const Blockchain *bc);

/**
 * @brief Computes cumulative lifetime transaction fees paid by a specific user identity.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the user.
 * @return Cumulative fee subunits generated by this user across all historical fee pointers.
 *
 * @pre `bc` and `pubkey` must be non-NULL.
 * @thread_safety Acquires `bc->rwlock` in read mode internally.
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_fees_paid_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN]);

/**
 * @brief Collects and marks unspent fee pointers (`spent == 2`) for recycling into post-cap block rewards.
 *
 * @details
 * Formalized under Lean 4 (`Satocialist.mint` post-cap phase).
 * Iterates through `bc->pointer_table`, selecting fee pointers up to `max_fees` count,
 * transitions their status to `spent = 1` (recycled), persists changes to the database,
 * and returns the cumulative recycled subunit volume.
 *
 * @param[in,out] bc Pointer to Blockchain state container.
 * @param[out] fees Destination array receiving copies of the collected fee pointers.
 * @param[in] max_fees Maximum count of fee pointers to harvest.
 * @return Total recycled subunits collected.
 *
 * @pre `bc` and `fees` must be non-NULL; `max_fees > 0`.
 * @post Harvested fee pointers are marked with `spent = 1` in memory and disk storage.
 * @thread_safety Acquires `bc->rwlock` in write mode internally.
 * @complexity Time: O(total_pointers), Space: O(1) auxiliary.
 */
uint64_t collect_fee_pointers(Blockchain *bc, Pointer *fees, uint32_t max_fees);

/* ============================================================================ */
/* SECTION 6: SHIELDED CENTINEL BLOOM FILTER ACCELERATION                       */
/* ============================================================================ */

/**
 * @brief Inserts a 32-byte spent ZK-PRF nullifier into the fast-lookup Bloom filter.
 *
 * @details
 * Hashes the nullifier into three independent 32-bit bit indices:
 * `bit1 = h1 % BITS`, `bit2 = h2 % BITS`, `bit3 = h3 % BITS`, setting the corresponding bits
 * to 1. Enables sub-microsecond pre-filtering to prevent expensive disk I/O lookups.
 *
 * @param[in,out] filter Pointer to Bloom filter byte array of size @ref NULLIFIER_BLOOM_BYTES.
 * @param[in] nullifier 32-byte spent ZK-PRF nullifier buffer.
 *
 * @pre `filter` and `nullifier` must be non-NULL.
 * @post Corresponding bit lanes in `filter` are set to 1.
 * @thread_safety Caller must synchronize concurrent writes via `bc->centinel.bloom_mutex`.
 * @complexity Time: O(1), Space: O(1).
 */
void nullifier_bloom_add(uint8_t *filter, const uint8_t *nullifier);

/**
 * @brief Probes the Bloom filter for potential membership of a spent ZK-PRF nullifier.
 *
 * @param[in] filter Pointer to Bloom filter byte array.
 * @param[in] nullifier 32-byte nullifier to test.
 * @return `true` if all three bit lanes are set (potential match; requires database confirmation);
 *         `false` if any bit lane is 0 (guaranteed unspent; eliminates disk lookup).
 *
 * @pre `filter` and `nullifier` must be non-NULL.
 * @thread_safety Safe for concurrent read access.
 * @complexity Time: O(1), Space: O(1).
 */
bool nullifier_bloom_check(const uint8_t *filter, const uint8_t *nullifier);

#ifdef __cplusplus
}
#endif

#endif // BLOCKCHAIN_H
