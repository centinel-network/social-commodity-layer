/**
 * @file common/blockchain/database.h
 * @brief Satocialist Protocol: Persistent Storage Engine Interface (libmdbx / Flat-File)
 *
 * @details
 * Declares the persistent storage abstraction layer governing ledger durability across node restarts.
 * Utilizes `libmdbx` (high-performance transactional key-value store with MVCC snapshot isolation)
 * when available, with a portable binary append-only flat-file fallback for constrained environments.
 *
 * @section tables Database Table (DBI) Layout
 * - `coins`: Maps 32-byte `coin_id` -> Serialized @ref SCLCoin structure.
 * - `pointers`: Maps 32-byte `pointer_id` -> Serialized @ref Pointer structure.
 * - `nullifiers`: Key-only table storing 32-byte spent ZK-PRF nullifiers.
 * - `scl_blocks`: Maps 8-byte big-endian `block_height` -> Full serialized block byte stream.
 * - `scl_mmr`: Maps 8-byte big-endian `node_position` -> Serialized @ref MMRNode record.
 * - `scl_checkpoints`: Maps 8-byte big-endian `block_height` -> 32-byte MMR state root digest.
 * - `dkg_state.bin`: Binary flat-file storing local validator Joint-RSS DKG epoch credentials.
 *
 * @section architectural_invariants Architectural Invariants
 * - Atomic Block Transactions: Block execution mutations (coins, pointers, nullifiers, checkpoints)
 *   are wrapped within a single thread-local write transaction via @ref scl_db_begin_block_txn,
 *   committing via @ref scl_db_commit_block_txn or aborting via @ref scl_db_abort_block_txn on failure.
 * - Lexicographical Nullifier Sorting: To eliminate the libmdbx random-write B-tree fragmentation penalty,
 *   batched nullifier insertions (@ref scl_db_write_nullifiers_batch) sort keys in RAM prior to disk writes.
 * - Fork Reversion via Checkpoints: Chain reorganizations roll back block history and invert RAM tables
 *   down to the closest 440-block boundary (@ref scl_db_rollback_state_to_checkpoint).
 *
 * @section thread_safety Thread Safety & Concurrency
 * - Read transactions execute lock-free concurrently under libmdbx MVCC snapshot isolation.
 * - Write operations are serialized across threads by `state->ledger_mutex` or `state->bc.rwlock`.
 * - Thread-local variable `active_block_txn` binds open write transactions to the proposing thread.
 */

#ifndef DATABASE_H
#define DATABASE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: DATABASE ENVIRONMENT LIFECYCLE & TRANSACTION SCOPES              */
/* ============================================================================ */

/**
 * @brief Initializes the persistent storage environment and opens all required sub-databases.
 *
 * @details
 * Configures libmdbx with up to 16 named databases and opens the environment under `MDBX_LIFORECLAIM`
 * mode. Opens the six primary tables: `coins`, `pointers`, `nullifiers`, `scl_blocks`, `scl_mmr`,
 * and `scl_checkpoints`. Under fallback mode, opens dedicated flat-file handles.
 *
 * @param[in] db_path Directory path hosting the libmdbx environment file or flat-file prefix.
 * @return 0 on success; -1 on initialization failure.
 *
 * @pre `db_path` must point to an existing, writable filesystem directory.
 * @post Environment initialized; table handles active for read/write transactions.
 * @complexity Time: O(1), Space: O(1).
 */
int scl_db_init(const char *db_path);

/**
 * @brief Flushes pending transactions and closes the persistent database environment.
 *
 * @pre No threads may be actively executing database reads or writes.
 * @post Environment and file handles closed; `db_env` reset to NULL.
 * @thread_safety Unsafe if called concurrently with active transactions.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_db_close(void);

/**
 * @brief Begins an atomic block execution transaction bound to the calling thread.
 *
 * @details
 * Opens a thread-local write transaction (`active_block_txn`). Subsequent calls to
 * `scl_db_put_coin`, `scl_db_put_pointer`, and `scl_db_put_block` enroll in this transaction
 * without standalone autocommit.
 *
 * @return 0 on success; -1 on transaction creation failure.
 *
 * @pre Caller must hold `state->ledger_mutex` to serialize write transactions.
 * @post `active_block_txn` is populated and active.
 * @complexity Time: O(1), Space: O(1).
 */
int scl_db_begin_block_txn(void);

/**
 * @brief Commits the active thread-local block write transaction to disk.
 *
 * @return 0 on success; -1 on commit error.
 *
 * @pre Caller must have an active block transaction opened via @ref scl_db_begin_block_txn.
 * @post All enrolled mutations written atomically; `active_block_txn` reset to NULL.
 * @complexity Time: O(disk_sync), Space: O(1).
 */
int scl_db_commit_block_txn(void);

/**
 * @brief Aborts and rolls back the active thread-local block write transaction.
 *
 * @pre Safe to call even if no transaction is active (no-op).
 * @post Uncommitted enrolled mutations discarded; `active_block_txn` reset to NULL.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_db_abort_block_txn(void);

/* ============================================================================ */
/* SECTION 2: COIN & POINTER UTXO PERSISTENCE                                   */
/* ============================================================================ */

/**
 * @brief Writes or updates an @ref SCLCoin record in the persistent `coins` table.
 *
 * @param[in] coin_id 32-byte unique coin identifier key.
 * @param[in] coin Pointer to @ref SCLCoin data structure to store.
 * @return 0 on success; -1 on write failure.
 *
 * @pre `coin_id` and `coin` must be non-NULL.
 * @post Coin record is inserted or updated in the persistent database.
 * @complexity Time: O(log N) B-tree lookup/insert, Space: O(sizeof(SCLCoin)).
 */
int scl_db_put_coin(const uint8_t *coin_id, const SCLCoin *coin);

/**
 * @brief Retrieves an @ref SCLCoin record by its 32-byte identifier from the `coins` table.
 *
 * @param[in] coin_id 32-byte coin identifier key.
 * @param[out] coin_out Destination buffer receiving the deserialized coin structure.
 * @return 0 on success; -1 if the coin is not found or retrieval fails.
 *
 * @pre `coin_id` and `coin_out` must be non-NULL.
 * @post On success, `coin_out` is populated with stored SCLCoin data.
 * @complexity Time: O(log N), Space: O(1).
 */
int scl_db_get_coin(const uint8_t *coin_id, SCLCoin *coin_out);

/**
 * @brief Writes or updates a @ref Pointer record in the persistent `pointers` table.
 *
 * @param[in] pointer_id 32-byte pointer identifier key.
 * @param[in] pointer Pointer to @ref Pointer structure to store.
 * @return 0 on success; -1 on write failure.
 *
 * @pre `pointer_id` and `pointer` must be non-NULL.
 * @post Pointer record is inserted or updated in the persistent database.
 * @complexity Time: O(log N), Space: O(sizeof(Pointer)).
 */
int scl_db_put_pointer(const uint8_t *pointer_id, const Pointer *pointer);

/**
 * @brief Retrieves a @ref Pointer record by its 32-byte identifier from the `pointers` table.
 *
 * @param[in] pointer_id 32-byte pointer identifier key.
 * @param[out] pointer_out Destination buffer receiving the deserialized pointer structure.
 * @return 0 on success; -1 if the pointer is not found or retrieval fails.
 *
 * @pre `pointer_id` and `pointer_out` must be non-NULL.
 * @post On success, `pointer_out` is populated with stored Pointer data.
 * @complexity Time: O(log N), Space: O(1).
 */
int scl_db_get_pointer(const uint8_t *pointer_id, Pointer *pointer_out);

/* ============================================================================ */
/* SECTION 3: SHIELDED CENTINEL NULLIFIER PERSISTENCE                           */
/* ============================================================================ */

/**
 * @brief Writes a batch of spent ZK-PRF nullifiers with RAM lexicographical pre-sorting.
 *
 * @details
 * Invariant: Sorts nullifiers in memory using `qsort` prior to libmdbx ingestion to eliminate
 * random-write B-tree page splits and resolve the MDBX random-insertion performance cliff.
 *
 * @param[in,out] nullifiers Array of 32-byte nullifiers (sorted in place).
 * @param[in] count Number of nullifiers in the batch.
 * @return 0 on success; -1 on database error.
 *
 * @pre `nullifiers` must contain at least `count * NULLIFIER_LEN` bytes (non-NULL if count > 0).
 * @post Nullifiers persisted to the `nullifiers` table; searchable via @ref scl_db_has_nullifier.
 * @complexity Time: O(count log count) sorting + O(count log N) sequential B-tree writes, Space: O(1).
 */
int scl_db_write_nullifiers_batch(uint8_t (*nullifiers)[NULLIFIER_LEN], size_t count);

/**
 * @brief Probes persistent storage to determine if a ZK-PRF nullifier has already been spent.
 *
 * @param[in] nullifier 32-byte nullifier to query.
 * @return `true` if nullifier exists in database (spent); `false` if unspent.
 *
 * @pre `nullifier` must point to 32 readable bytes.
 * @thread_safety Thread-safe under MVCC snapshot transaction.
 * @complexity Time: O(log N), Space: O(1).
 */
bool scl_db_has_nullifier(const uint8_t *nullifier);

/**
 * @brief Deletes a batch of spent nullifiers from persistent storage during chain rollbacks.
 * @param[in] nullifiers Array of 32-byte nullifiers to remove from disk.
 * @param[in] count Number of entries in the array.
 * @return 0 on success (including no-op), -1 on storage failure.
 */
int scl_db_delete_nullifiers_batch(uint8_t (*nullifiers)[NULLIFIER_LEN], size_t count);

/* ============================================================================ */
/* SECTION 4: DISTRIBUTED KEY GENERATION (DKG) STATE PERSISTENCE                */
/* ============================================================================ */

/**
 * @brief Sets an active DKG ceremony lock with an explicit expiration TTL in MDBX.
 *
 * @param[in] epoch Epoch height currently running ceremony.
 * @param[in] session_id 32-byte unique DKG session identifier.
 * @param[in] ttl_ms Duration in milliseconds until the lock expires.
 * @return 0 on success; -1 on database error.
 */
int scl_db_set_dkg_lock(uint64_t epoch, const uint8_t session_id[COIN_ID_LEN], uint64_t ttl_ms);

/**
 * @brief Probes MDBX for an active DKG ceremony lock and evaluates expiration status.
 *
 * @param[out] out_epoch Destination receiving locked epoch number.
 * @param[out] out_session_id Destination receiving 32-byte session ID.
 * @param[out] out_is_expired True if the lock's expiration timestamp is in the past.
 * @return 0 if lock exists; -1 if no lock is recorded.
 */
int scl_db_check_dkg_lock(uint64_t *out_epoch, uint8_t out_session_id[COIN_ID_LEN], bool *out_is_expired);

/**
 * @brief Removes the active DKG ceremony lock from MDBX upon completion or abort.
 *
 * @return 0 on success; -1 on database error.
 */
int scl_db_clear_dkg_lock(void);

/**
 * @brief Encrypts and writes Tier-A Joint-RSS DKG epoch secret shares to MDBX.
 *
 * @details
 * Serializes local committee membership, point ID, matrix expansion seed rho,
 * and polynomial share vectors (s1, s2), encrypting the payload with an AES-256-GCM
 * key derived from the user's master signing secret via HKDF.
 *
 * @param[in] state Global node state container.
 * @return 0 on success; -1 on serialization, encryption, or write failure.
 *
 * @pre `state` must be non-NULL.
 * @thread_safety Synchronizes via `state->epoch_mutex` and `state->wallet_mutex`.
 * @complexity Time: O(subsets * poly_size), Space: O(payload_size) heap buffer.
 */
int scl_db_save_dkg_state(State *state);

/**
 * @brief Decrypts and authenticates Tier-A Joint-RSS DKG epoch secret shares from MDBX.
 *
 * @details
 * Invariant: Verifies that the decrypted rho matches the current blockchain epoch committee
 * public key (`state->game_state.epoch_threshold_pubkey`). Stale or mismatched credentials
 * are rejected to prevent poisoning the epoch signing state.
 *
 * @param[in,out] state Global node state container.
 * @return 0 on successful validation and load; -1 if absent, corrupt, or stale.
 *
 * @pre `state` must be non-NULL.
 * @thread_safety Synchronizes via `state->game_state.mutex`, `state->wallet_mutex`, and `state->epoch_mutex`.
 * @complexity Time: O(subsets * poly_size), Space: O(payload_size) heap buffer.
 */
int scl_db_load_dkg_state(State *state);

/**
 * @brief Self-test verifying MDBX DKG lock TTL expiry and at-rest encrypted share persistence.
 * @param[in,out] state Global node state container.
 * @return 0 on success; -1 if assertions fail.
 */
int scl_db_run_dkg_selftest(State *state);

/* ============================================================================ */
/* SECTION 5: BLOCK & HISTORICAL CHAIN PERSISTENCE                              */
/* ============================================================================ */

/**
 * @brief Persists a serialized block byte stream keyed by its 8-byte big-endian height.
 *
 * @param[in] block_height Numeric chain height.
 * @param[in] serialized_block Binary serialized block buffer.
 * @param[in] length Byte size of the serialized block buffer.
 * @return 0 on success; -1 on write failure.
 *
 * @pre `serialized_block` must be non-NULL; `length > 0`.
 * @post Serialized block is stored in `scl_blocks` table keyed by big-endian height.
 * @complexity Time: O(log N), Space: O(1).
 */
int scl_db_put_block(uint64_t block_height, const uint8_t *serialized_block, size_t length);

/**
 * @brief Retrieves a serialized block byte stream from storage by its chain height.
 *
 * @param[in] block_height Target chain height.
 * @param[out] serialized_block_out Dynamically allocated buffer receiving block bytes (caller frees).
 * @param[out] length_out Destination receiving total byte length.
 * @return 0 on success; -1 if block is not found or allocation fails.
 *
 * @pre `serialized_block_out` and `length_out` must be non-NULL.
 * @post On success, `*serialized_block_out` contains allocated memory of length `*length_out`.
 * @complexity Time: O(log N), Space: O(block_size) heap allocation.
 */
int scl_db_get_block(uint64_t block_height, uint8_t **serialized_block_out, size_t *length_out);

/**
 * @brief Deletes all blocks stored at heights strictly greater than `block_height`.
 *
 * @details
 * Traverses a database cursor starting at `block_height + 1` and deletes matching records
 * to support chain reorganization rollbacks.
 *
 * @param[in] block_height Highest block height to retain.
 * @return 0 on success; -1 on deletion error.
 *
 * @post Blocks with height > `block_height` are removed from the `scl_blocks` table.
 * @complexity Time: O(deleted_blocks * log N), Space: O(1).
 */
int scl_db_delete_blocks_after(uint64_t block_height);

/* ============================================================================ */
/* SECTION 6: MMR BATCHING & CHECKPOINT REVERSION                               */
/* ============================================================================ */

/**
 * @brief Writes a batch of uncommitted MMR nodes to the persistent `scl_mmr` table.
 *
 * @param[in] nodes Array of @ref MMRNode structures to store.
 * @param[in] count Number of nodes in the batch.
 * @return 0 on success; -1 on write error.
 *
 * @pre `nodes` must be non-NULL if `count > 0`.
 * @post Nodes are stored in `scl_mmr` table keyed by big-endian node position.
 * @complexity Time: O(count * log N), Space: O(1).
 */
int scl_db_put_mmr_batch(const MMRNode *nodes, size_t count);

/**
 * @brief Records a periodic state checkpoint (height -> 32-byte MMR state root).
 *
 * @param[in] block_height Checkpoint block height (typically multiple of @ref BLOCKS_PER_DAY).
 * @param[in] state_root 32-byte state root commitment at the checkpoint.
 * @return 0 on success; -1 on error.
 *
 * @pre `state_root` must point to 32 readable bytes.
 * @post Checkpoint record is stored in `scl_checkpoints` table.
 * @complexity Time: O(log N), Space: O(1).
 */
int scl_db_put_checkpoint(uint64_t block_height, const uint8_t state_root[32]);

/**
 * @brief Locates the highest available checkpoint at or below `max_height`.
 *
 * @param[in] max_height Maximum allowable checkpoint height.
 * @param[out] checkpoint_height_out Destination receiving checkpoint height.
 * @param[out] state_root_out Destination receiving 32-byte state root at checkpoint.
 * @return 0 on success; -1 if no suitable checkpoint exists.
 *
 * @pre `checkpoint_height_out` and `state_root_out` must be non-NULL.
 * @complexity Time: O(log N), Space: O(1).
 */
int scl_db_get_highest_checkpoint(uint64_t max_height, uint64_t *checkpoint_height_out, uint8_t state_root_out[32]);

/**
 * @brief Rolls back local ledger state from `fork_height` down to a target `checkpoint_height`.
 *
 * @details
 * Inverts state mutations in reverse chronological order:
 * 1. Deserializes blocks from `fork_height` down to `checkpoint_height + 1`.
 * 2. Un-mints coinbase coins, restoring previous remaining subunit pools.
 * 3. Restores spent input pointers to unspent status (`spent = 0`).
 * 4. Evicts spent nullifiers and confirmed transaction IDs from RAM tables.
 * 5. Purges rolled-back block records from persistent storage via @ref scl_db_delete_blocks_after.
 * 6. Restores 10x10 Game Audit matrix state from the checkpoint block.
 *
 * @param[in,out] state Global node state container.
 * @param[in] checkpoint_height Height of the target checkpoint to restore.
 * @param[in] fork_height Height of the invalidated fork tip.
 * @return 0 on success; -1 on rollback error.
 *
 * @pre `state` must be non-NULL; `fork_height >= checkpoint_height`.
 * @pre Caller must hold `state->ledger_mutex` and `state->bc.rwlock` in write mode.
 * @post Ledger tables, Game Audit state, and disk history are reverted to `checkpoint_height` state.
 * @complexity Time: O(fork_depth * block_operations), Space: O(block_size).
 */
int scl_db_rollback_state_to_checkpoint(State *state, uint64_t checkpoint_height, uint64_t fork_height);

/**
 * @brief Prunes historical non-peak MMR nodes from disk while preserving active peaks.
 *
 * @param[in] peaks Array of node positions representing currently active mountain peaks.
 * @param[in] peak_count Number of elements in `peaks`.
 * @param[in] max_position Maximum node position below which non-peaks are deleted.
 * @return 0 on success; -1 on error.
 *
 * @pre `peaks` must be non-NULL if `peak_count > 0`.
 * @post Non-peak nodes with position < `max_position` are purged from `scl_mmr` table.
 * @complexity Time: O(max_position * log N), Space: O(1).
 */
int scl_db_prune_mmr_nodes_except_peaks(const size_t *peaks, size_t peak_count, size_t max_position);

#ifdef __cplusplus
}
#endif

#endif // DATABASE_H
