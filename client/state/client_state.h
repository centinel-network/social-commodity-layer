/**
 * @file client/state/client_state.h
 * @brief Satocialist Protocol: Client State Container Lifecycle & Resource Management Interface
 *
 * @details
 * Declares the initialization and teardown lifecycles for the master @ref State container.
 * The master State structure unifies blockchain storage, lock-free mempool tables, consensus
 * voting queues, peer network directories, background thread pools, and cryptographic wallet keys.
 *
 * @section lifecycle_invariants Lifecycle Invariants
 * - Atomic Initialization: Subsystems are allocated and initialized in strict dependency order:
 *   1. Configuration defaults & atomic flags
 *   2. Mempool lock-free arrays & synchronization condition variables
 *   3. Hash tables (processed blocks, voted heights, orphan pool, user table, tx index, consensus)
 *   4. Game state & blockchain ledger (MMR accumulator, persistent libmdbx database)
 *   5. Worker thread pools (work-stealing recreation, RPC engine, crypto verifiers, hypergraph maintainer)
 *   6. Persistent state hydration via local disk blockchain scan
 * - Orderly Teardown: Subsystems are dismantled in reverse dependency order:
 *   1. Signal `global_shutdown = true`; wake all waiting condition variables.
 *   2. Stop and join worker pools (autopilot, recreation, hypergraph maintainer, RPC, crypto, submission).
 *   3. Destroy threshold stake processes, DKG sessions, and peer network connections.
 *   4. Flush and close persistent database environment (`scl_db_close`) and blockchain MMR.
 *   5. Destroy generic hash tables, user arrays, and synchronization primitives.
 *   6. Securely unlock, zeroize private key material in physical RAM, and reset shutdown flag.
 *
 * @section thread_safety Thread Safety & Concurrency
 * - `client_state_init` and `client_state_destroy` are NOT thread-safe; they must be called
 *   exclusively from the primary initialization/termination thread during node bootstrap or shutdown.
 */

#ifndef CLIENT_STATE_H
#define CLIENT_STATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "user.h"
#include "queue.h"
#include "blockchain.h"
#include "constants.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* 1. STATE CONTAINER LIFECYCLE INTERFACES                                      */
/* ============================================================================ */

/**
 * @brief Allocates and initializes all internal subsystems within the master State container.
 *
 * @details
 * Configures configuration defaults, initializes the lock-free mempool array, allocates
 * and initializes all generic hash tables, opens the persistent database environment,
 * initializes the blockchain MMR accumulator, spawns work-stealing recreation workers,
 * RPC worker threads, crypto verification workers, and the hypergraph maintainer thread,
 * sets up condition variables, initializes epoch ceremony trackers, and hydrates existing chain state.
 *
 * @param[out] state Pointer to caller-allocated @ref State structure to initialize.
 * @param[in] is_bootstrap Flag: 1 if initializing as a network bootstrap seed node; 0 for client node.
 * @return 0 on successful initialization; -1 on any memory allocation or mutex initialization failure.
 *
 * @pre `state` must point to allocated, zero-initialized or writable memory.
 * @post Subsystems fully initialized; worker thread pools spawned and awaiting tasks.
 * @thread_safety Unsafe for concurrent invocation. Must be called once during process bootstrap.
 * @complexity Time: O(worker_count + table_sizes), Space: O(heap allocations across all subsystems).
 */
int client_state_init(State *state, int is_bootstrap);

/**
 * @brief Hydrates in-memory ledger state from persistent block storage on startup.
 *
 * @details
 * Probes the persistent database for committed blocks starting from genesis (Block 0) up
 * to the highest contiguous block height. Sequentially deserializes and applies each block
 * to reconstruct in-memory UTXO tables, coin balances, Merkle Mountain Range (MMR) leaves,
 * and game audit matrix rows. Recomputes state tip hash and updates the game state snapshot,
 * persistent DKG epoch credentials, and user wallet validation UTXOs.
 *
 * @param[in,out] state Pointer to initialized @ref State structure to hydrate.
 * @return Number of blocks successfully loaded and applied from disk; 0 if the database is
 *         empty or uninitialized; -1 on critical parameter error.
 *
 * @pre `state` must point to an allocated, initialized State container (e.g., via @ref client_state_init).
 * @post `state->current_block_number`, `state->current_block_hash`, and `state->bc.sync_epoch`
 *       reflect the tip of the local persistent blockchain.
 * @thread_safety Acquires `state->ledger_mutex` and `state->bc.rwlock` internally.
 * @complexity Time: O(loaded_blocks * apply_block_time), Space: O(MAX_MESSAGE_SIZE).
 */
int scl_load_local_blockchain(State *state);

/**
 * @brief Gracefully terminates background worker threads and dismantles all State subsystems.
 *
 * @details
 * Signals global shutdown, broadcasts condition variable wakes, joins worker thread pools
 * (Auto-Pilot, recreation workers, RPC workers, crypto verifiers, submission processors, hypergraph maintainer),
 * closes database handles, frees hash tables and peer address tables, destroys synchronization
 * primitives, securely unlocks and zeroes all private key buffers, and resets global shutdown state.
 *
 * @param[in,out] state Pointer to initialized @ref State structure to destroy (safe if NULL).
 *
 * @pre No external threads may be actively executing operations using `state`.
 * @post All dynamic memory freed, threads joined, file descriptors closed, and keys zeroed.
 * @thread_safety Unsafe for concurrent invocation. Must be called once during process shutdown.
 * @complexity Time: O(worker_threads_join + total_allocated_resources), Space: O(1).
 */
void client_state_destroy(State *state);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_STATE_H
