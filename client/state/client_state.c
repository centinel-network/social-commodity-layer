/**
 * @file client/state/client_state.c
 * @brief Satocialist Protocol: Client State Container Lifecycle & Resource Management Implementation
 *
 * @details
 * Implements the initialization, resource allocation, and multi-phase teardown sequences for the master
 * @ref State container. Unifies the blockchain ledger, lock-free transaction pools, consensus voting
 * queues, peer routing tables, work-stealing thread pools, and cryptographic wallet keys.
 *
 * @section protocol_invariants System Invariants Enforced
 * - Strict Layered Teardown: Subsystems are shut down in reverse dependency order:
 *   1. Signal `global_shutdown = true`; wake all waiting condition variables.
 *   2. Stop and join crypto verification workers, Auto-Pilot, recreation thread pools, RPC workers, and hypergraph maintainers.
 *   3. Free threshold processes, DKG sessions, and peer connections.
 *   4. Flush and close the persistent libmdbx database environment.
 *   5. Destroy generic hash tables, user arrays, and condition variables.
 *   6. Securely unpin and zeroize private key material in physical RAM.
 * - Memory Hygiene: All secret keys (Dilithium5 private keys, Kyber private keys, Module-SIS PRF keys, and UTXO secrets) are unlocked,
 *   wiped via @ref explicit_bzero, and deallocated.
 * - Clean Shutdown Reset: Resets `global_shutdown = false` upon destruction completion so that
 *   subsequent test iterations execute without stale shutdown flags.
 *
 * @section concurrency_model Threading & Concurrency
 * - `client_state_init` and `client_state_destroy` are executed exclusively by the main thread.
 * - Background worker thread counts dynamically scale to host CPU core counts (`sysconf(_SC_NPROCESSORS_ONLN)`).
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#include <direct.h>
#define SCL_MKDIR(dir) _mkdir(dir)
#else
#define SCL_MKDIR(dir) mkdir(dir, 0755)
#endif
#include "client_state.h"
#include "database.h"
#include "network.h"
#include "rpc.h"
#include "client_network.h"
#include "hash_table.h"
#include "crypto.h"
#include "constants.h"
#include "utils.h"
#include "protocol.h"
#include "consensus.h"

extern void *crypto_verify_worker_loop(void *arg);

/* ============================================================================ */
/* SECTION 1: STATE ALLOCATION & SUBSYSTEM INITIALIZATION                       */
/* ============================================================================ */

/**
 * @brief Allocates and initializes all internal subsystems within the master State container.
 *
 * @param[out] state Pointer to caller-allocated @ref State structure to initialize.
 * @param[in] is_bootstrap Flag: 1 if initializing as a network bootstrap seed node; 0 for client node.
 * @return 0 on success; -1 on memory allocation or mutex initialization failure.
 *
 * @pre `state` must point to allocated, writable memory.
 * @post All hash tables, MMR trees, thread pools, and condition variables are initialized and active.
 * @complexity Time: O(worker_count + table_sizes), Space: O(heap allocations across all subsystems).
 */
int client_state_init(State *state, int is_bootstrap) {
    if (!state) {
        fprintf(stderr, "[ClientState] ERROR: NULL State pointer\n");
        return -1;
    }

    fprintf(stderr, "[ClientState] Initializing client state (is_bootstrap=%d)\n", is_bootstrap);

    // Apply configuration defaults and initialize autopilot state
    if (state->config.mempool_async_threshold == 0) {
        state->config.mempool_async_threshold = 50;
    }
    if (state->config.max_pending_ops_config == 0) {
        state->config.max_pending_ops_config = 1000;
    }
    if (state->config.autopilot_valuations_per_hour == 0) {
        state->config.autopilot_valuations_per_hour = 1;
    }
    if (state->config.autopilot_stake_ratio == 0 && !state->config.autopilot_enabled) {
        state->config.autopilot_stake_ratio = 50;
    }
    atomic_init(&state->autopilot_running, false);

    // Pending operations lock-free array
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        atomic_init(&state->pending_operations[i], NULL);
    }
    atomic_init(&state->pending_operations_count, 0);
    state->pending_ops_received = 0;

    // Processed blocks hash table
    state->processed_blocks = malloc(sizeof(HashTable));
    if (!state->processed_blocks || hash_table_init(state->processed_blocks, 1024, COIN_ID_LEN, NULL, NULL, NULL, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate processed_blocks: %s\n", strerror(errno));
        if (state->processed_blocks) free(state->processed_blocks);
        return -1;
    }

    // Voted heights hash table
    state->voted_heights = malloc(sizeof(HashTable));
    if (!state->voted_heights || hash_table_init(state->voted_heights, 1024, USER_ID_LEN, hash_func, memcmp, free, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate voted_heights: %s\n", strerror(errno));
        if (state->voted_heights) free(state->voted_heights);
        return -1;
    }

    // Orphan pool hash table
    state->orphan_pool = malloc(sizeof(HashTable));
    if (!state->orphan_pool || hash_table_init(state->orphan_pool, 1024, COIN_ID_LEN, NULL, memcmp, NULL, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate orphan_pool: %s\n", strerror(errno));
        if (state->orphan_pool) free(state->orphan_pool);
        return -1;
    }

    // Game state (embedded)
    if (game_state_init(state, is_bootstrap) != 0) return -1;

    // Database and Blockchain Initialization
    SCL_MKDIR("db");
    if (scl_db_init("db") != 0) {
        fprintf(stderr, "[ClientState] WARNING: Database initialization failed at path 'db'\n");
    }

    if (blockchain_init(&state->bc) != 0) return -1;
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);

    // Blockchain sync fields
    state->blockchain_sync_received_end = 0;
    state->in_blockchain_sync = 0;
    state->network_target_block_number = 0;
    memset(state->sync_peer_pubkey, 0, DILITHIUM_PUBKEY_LEN);
    
    // Threshold stake processes hash table
    state->threshold_stake_processes = malloc(sizeof(HashTable));
    if (!state->threshold_stake_processes || hash_table_init(state->threshold_stake_processes, 16, COIN_ID_LEN, NULL, memcmp, free_threshold_process, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate threshold_stake_processes: %s\n", strerror(errno));
        return -1;
    }

    // Users array and table
    state->users = calloc(MAX_CLIENTS, sizeof(User));
    if (!state->users) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate users array: %s\n", strerror(errno));
        return -1;
    }
    state->user_count = 0;
    state->user_table = malloc(sizeof(HashTable));
    if (!state->user_table || hash_table_init(state->user_table, 1024, COIN_ID_LEN, NULL, NULL, NULL, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate user_table: %s\n", strerror(errno));
        if (state->user_table) free(state->user_table);
        return -1;
    }

    // Processed transactions
    state->processed_txs = malloc(sizeof(HashTable));
    if (!state->processed_txs || hash_table_init(state->processed_txs, 1024, COIN_ID_LEN, NULL, NULL, NULL, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate processed_txs: %s\n", strerror(errno));
        if (state->processed_txs) free(state->processed_txs);
        return -1;
    }

    // Block consensus
    state->block_consensus = malloc(sizeof(HashTable));
    if (!state->block_consensus || hash_table_init(state->block_consensus, 1024, SHA256_DIGEST_LENGTH, NULL, memcmp, free_block_vote_queue, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate block_consensus: %s\n", strerror(errno));
        if (state->block_consensus) free(state->block_consensus);
        return -1;
    }

    // Block proposers
    state->block_proposers = malloc(sizeof(HashTable));
    if (!state->block_proposers || hash_table_init(state->block_proposers, 1024, COIN_ID_LEN, NULL, memcmp, free, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate block_proposers: %s\n", strerror(errno));
        if (state->block_proposers) free(state->block_proposers);
        return -1;
    }
    
    // Pubkey cache
    state->pubkey_cache = malloc(sizeof(HashTable));
    if (!state->pubkey_cache || hash_table_init(state->pubkey_cache, 1024, USER_ID_LEN, hash_func, memcmp, NULL, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate pubkey_cache: %s\n", strerror(errno));
        if (state->pubkey_cache) free(state->pubkey_cache);
        return -1;
    }
    fprintf(stderr, "[ClientState] Pubkey cache initialized\n");
    
    // Submission queue for serializing owner valuations
    queue_init(&state->submission_queue);
    state->submission_running = 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    state->submission_workers_count = 1;
#else
    int sub_procs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (sub_procs <= 0) sub_procs = 4;
    // Seed nodes max out all available host vCPUs; local nodes scale conservatively to 1 worker
    state->submission_workers_count = is_bootstrap ? sub_procs : 1;
#endif
    state->submission_workers = calloc(state->submission_workers_count, sizeof(pthread_t));

    // Audit fields
    state->audit_received = 0;
    
    // Atomic counters
    atomic_init(&state->scheduled_consumed_subunits, 0);
    atomic_init(&state->scheduled_staked_subunits, 0);

    // Synchronization primitives
    if (pthread_mutex_init(&state->mutex, NULL) != 0 ||
        pthread_mutex_init(&state->ledger_mutex, NULL) != 0 ||
        pthread_mutex_init(&state->wallet_mutex, NULL) != 0 ||
        pthread_mutex_init(&state->submission_mutex, NULL) != 0 ||
        pthread_mutex_init(&state->block_proposers_lock, NULL) != 0 ||
        pthread_mutex_init(&state->processed_blocks_mutex, NULL) != 0 ||
        pthread_mutex_init(&state->threshold_mutex, NULL) != 0) {
        fprintf(stderr, "[ClientState] ERROR: Failed to initialize mutex: %s\n", strerror(errno));
        return -1;
    }
    if (pthread_cond_init(&state->audit_cond, NULL) != 0 ||
        pthread_cond_init(&state->pending_ops_cond, NULL) != 0 ||
        pthread_cond_init(&state->submission_cond, NULL) != 0 ||
        pthread_cond_init(&state->blockchain_sync_cond, NULL) != 0) {
        fprintf(stderr, "[ClientState] ERROR: Failed to initialize condition variable: %s\n", strerror(errno));
        return -1;
    }

    atomic_init(&state->sync_thread_active, false);
    
    // Work-stealing recreation worker queue
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    state->recreation_workers_count = 1;
#else
    int rec_procs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (rec_procs <= 0) rec_procs = 4;
    state->recreation_workers_count = is_bootstrap ? rec_procs : 1;
#endif
        
    state->recreation_queues = calloc(state->recreation_workers_count, sizeof(WorkStealingQueue));
    state->recreation_workers = calloc(state->recreation_workers_count, sizeof(pthread_t));
    if (!state->recreation_queues || !state->recreation_workers) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate recreation structures\n");
        return -1;
    }
    
    pthread_cond_init(&state->recreation_cond, NULL);
    pthread_mutex_init(&state->recreation_sleep_mutex, NULL);
    atomic_init(&state->round_robin_idx, 0);

    for (int i = 0; i < state->recreation_workers_count; i++) {
        pthread_mutex_init(&state->recreation_queues[i].mutex, NULL);
        state->recreation_queues[i].head = NULL;
        state->recreation_queues[i].tail = NULL;
    }

    // Initialize RPC Engine
    pthread_mutex_init(&state->rpc_engine.incoming_rpc_queue.mutex, NULL);
    state->rpc_engine.incoming_rpc_queue.head = NULL;
    state->rpc_engine.incoming_rpc_queue.tail = NULL;
    atomic_init(&state->rpc_engine.active_global_queries, 0);
    atomic_init(&state->rpc_engine.requests_total, 0);
    atomic_init(&state->rpc_engine.rejected_rate_limit, 0);
    atomic_init(&state->rpc_engine.rejected_auth_fail, 0);
    atomic_init(&state->rpc_engine.rejected_checksum_mismatch, 0);
    atomic_init(&state->rpc_engine.latency_microseconds_sum, 0);
    for (int i = 0; i < 12; i++) {
        atomic_init(&state->rpc_engine.method_requests_ok[i], 0);
        atomic_init(&state->rpc_engine.method_requests_err[i], 0);
        atomic_init(&state->rpc_engine.method_latency[i], 0);
    }
    
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    // Spawn RPC worker threads (max out on GCP seed nodes; scale down to 2 on local nodes)
    int num_rpc_workers = is_bootstrap ? MAX_RPC_WORKERS : 2;
    for (int i = 0; i < num_rpc_workers; i++) {
        struct WorkerArgs *wa = malloc(sizeof(struct WorkerArgs));
        if (wa) {
            wa->s = state;
            wa->id = i;
            if (pthread_create(&state->rpc_engine.worker_threads[i], &attr, rpc_worker_loop, wa) != 0) {
                fprintf(stderr, "[ClientState] ERROR: Failed to create RPC worker %d\n", i);
            }
        }
    }

    // Spawn recreation worker threads
    for (int i = 0; i < state->recreation_workers_count; i++) {
        struct WorkerArgs *wa = malloc(sizeof(struct WorkerArgs));
        if (!wa) {
            fprintf(stderr, "[ClientState] ERROR: Failed to allocate worker args for worker %d\n", i);
            return -1;
        }
        wa->s = state;
        wa->id = i;
        if (pthread_create(&state->recreation_workers[i], &attr, recreation_worker_loop, wa) != 0) {
            fprintf(stderr, "[ClientState] ERROR: Failed to create recreation worker %d\n", i);
            return -1;
        }
    }
#endif
    pthread_attr_destroy(&attr);
        
    atomic_init(&state->active_background_threads, 0);
    fprintf(stderr, "[ClientState] Initialization complete with %d recreation workers (work-stealing queues)\n", state->recreation_workers_count);

    // Initialize Crypto Verification Workers Pool
    state->crypto_verify_head = NULL;
    state->crypto_verify_tail = NULL;
    state->crypto_verify_running = 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    state->crypto_verify_workers_count = 1;
#else
    int cryp_procs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (cryp_procs <= 0) cryp_procs = 4;
    state->crypto_verify_workers_count = is_bootstrap ? cryp_procs : (cryp_procs > 2 ? 2 : 1);
#endif
    state->crypto_verify_workers = calloc(state->crypto_verify_workers_count, sizeof(pthread_t));
    pthread_mutex_init(&state->crypto_verify_mutex, NULL);
    pthread_cond_init(&state->crypto_verify_cond, NULL);

    pthread_attr_t crypto_attr;
    pthread_attr_init(&crypto_attr);
    pthread_attr_setstacksize(&crypto_attr, 8 * 1024 * 1024);
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    // Spawn crypto verification worker threads
    for (int i = 0; i < state->crypto_verify_workers_count; i++) {
        if (pthread_create(&state->crypto_verify_workers[i], &crypto_attr, crypto_verify_worker_loop, state) != 0) {
            fprintf(stderr, "[ClientState] ERROR: Failed to create crypto verify worker %d\n", i);
        }
    }
#endif
    pthread_attr_destroy(&crypto_attr);

    // Epoch Process and Cache Trackers
    state->epoch_processes = malloc(sizeof(HashTable));
    if (!state->epoch_processes || hash_table_init(state->epoch_processes, 16, COIN_ID_LEN, NULL, memcmp, free_threshold_process, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate epoch_processes: %s\n", strerror(errno));
        return -1;
    }

    state->epoch_sign_data_cache = malloc(sizeof(HashTable));
    if (!state->epoch_sign_data_cache || hash_table_init(state->epoch_sign_data_cache, 16, COIN_ID_LEN, NULL, memcmp, free, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate epoch_sign_data_cache: %s\n", strerror(errno));
        return -1;
    }
    
    // Active DKG Sessions
    state->dkg_active_sessions = malloc(sizeof(HashTable));
    if (!state->dkg_active_sessions || hash_table_init(state->dkg_active_sessions, 16, COIN_ID_LEN, NULL, memcmp, free_dkg_session, NULL)) {
        fprintf(stderr, "[ClientState] ERROR: Failed to allocate dkg_active_sessions: %s\n", strerror(errno));
        return -1;
    }

    polyvec_init(&state->epoch_t_global, DILITHIUM_K);
    state->current_committee_count = 0; // Explicitly initialize

    if (pthread_mutex_init(&state->epoch_mutex, NULL) != 0) {
        fprintf(stderr, "[ClientState] ERROR: Failed to initialize epoch_mutex: %s\n", strerror(errno));
        return -1;
    }
    scl_log(LOG_LEVEL_INFO, "ClientState", "Epoch ceremony trackers initialized");
    
    // Initialize Hypergraph State
    initialize_hypergraph(&state->hypergraph);
    
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    // Start Hypergraph Background Maintainer Thread
    pthread_attr_t h_attr;
    pthread_attr_init(&h_attr);
    pthread_attr_setstacksize(&h_attr, 8 * 1024 * 1024);
    if (pthread_create(&state->hypergraph_maintainer_thread, &h_attr, maintain_hypergraph_state_thread, state) != 0) {
        fprintf(stderr, "[ClientState] ERROR: Failed to create hypergraph maintainer thread\n");
    }
    pthread_attr_destroy(&h_attr);
#endif
    scl_log(LOG_LEVEL_INFO, "ClientState", "Hypergraph maintainer thread spawned");
    
    // Check if persistent database exists and hydrate local blockchain state
    scl_load_local_blockchain(state);

    return 0;
}

/**
 * @brief Hydrates in-memory ledger state from persistent block storage on startup.
 *
 * @param[in,out] state Master state container.
 * @return Number of blocks successfully loaded and applied from disk.
 */
int scl_load_local_blockchain(State *state) {
    if (!state) return -1;
    uint8_t *ser_block = NULL;
    size_t ser_len = 0;

    // Check if Block 0 (Genesis) exists in the persistent store
    if (scl_db_get_block(0, &ser_block, &ser_len) != 0) {
        return 0; // Fresh database: no blocks on disk
    }
    free(ser_block);
    ser_block = NULL;

    scl_log(LOG_LEVEL_INFO, "Database", "Existing blockchain database detected. Hydrating local chain from disk...");

    pthread_mutex_lock(&state->ledger_mutex);
    pthread_rwlock_wrlock(&state->bc.rwlock);

    // Sequentially deserialize and apply persisted blocks from height 0
    uint64_t h = 0;
    uint64_t loaded_count = 0;
    while (scl_db_get_block(h, &ser_block, &ser_len) == 0) {
        Block *block = calloc(1, sizeof(Block));
        if (!block) {
            free(ser_block);
            break;
        }
        if (deserialize_block(block, ser_block, ser_len) != 0) {
            free_block(block);
            free(ser_block);
            break;
        }
        free(ser_block);
        ser_block = NULL;

        if (apply_block(state, block) == 0) {
            state->current_block_number = block->block_number;
            uint8_t b_hash[COIN_ID_LEN];
            compute_block_hash(block, b_hash);
            memcpy(state->current_block_hash, b_hash, COIN_ID_LEN);
            state->bc.sync_epoch = block->block_number + 1;
            loaded_count++;
        } else {
            fprintf(stderr, "[Database] WARNING: Failed to apply block %llu from disk\n", (unsigned long long)h);
            free_block(block);
            break;
        }
        free_block(block);
        h++;
    }

    pthread_rwlock_unlock(&state->bc.rwlock);
    pthread_mutex_unlock(&state->ledger_mutex);

    if (loaded_count > 0) {
        // Hydrate Game Audit matrix from the latest block's mint snapshot to restore state continuity
        pthread_mutex_lock(&state->game_state.mutex);
        if (state->game_state.valuation_count == 0) {
            for (uint64_t b = state->current_block_number + 1; b > 0; b--) {
                uint8_t *sb = NULL;
                size_t slen = 0;
                if (scl_db_get_block(b - 1, &sb, &slen) == 0) {
                    Block *blk = calloc(1, sizeof(Block));
                    if (blk && deserialize_block(blk, sb, slen) == 0) {
                        bool found_mint = false;
                        for (size_t op_i = 0; op_i < blk->operation_count; op_i++) {
                            if (blk->operations[op_i].type == OP_MINT_COIN) {
                                SCLCoin *c = &blk->operations[op_i].data.mint_coin.coin;
                                if (c->snapshot_count > 0) {
                                    memcpy(state->game_state.game_audit, c->audit_snapshot, sizeof(Valuation) * AUDIT_SIZE);
                                    state->game_state.valuation_count = c->snapshot_count;
                                    state->game_state.current_audit_index = c->snapshot_audit_index;
                                    size_t latest_idx = (c->snapshot_audit_index == 0) ? AUDIT_SIZE - 1 : c->snapshot_audit_index - 1;
                                    state->game_state.audit_timestamp = c->audit_snapshot[latest_idx].timestamp;
                                    found_mint = true;
                                    scl_log(LOG_LEVEL_INFO, "Database", "Restored Game Audit state from Block %llu snapshot (%u valuations)",
                                            (unsigned long long)(b - 1), c->snapshot_count);
                                    break;
                                }
                            }
                        }
                        free_block(blk);
                        free(sb);
                        if (found_mint) break;
                    } else {
                        if (blk) free_block(blk);
                        free(sb);
                    }
                }
            }
        }
        pthread_mutex_unlock(&state->game_state.mutex);

        // Recompute game snapshot, hydrate DKG state, and rescan wallet UTXOs
        update_game_state_snapshot(state);
        scl_db_load_dkg_state(state);
        scl_wallet_rescan_utxos(state);
        scl_log(LOG_LEVEL_INFO, "Database", "Successfully loaded %llu blocks from disk (Current tip: Block %llu)",
                (unsigned long long)loaded_count, (unsigned long long)state->current_block_number);
    }
    return (int)loaded_count;
}

/* ============================================================================ */
/* SECTION 2: MULTI-PHASE TEARDOWN & SECURE MEMORY ZEROIZATION                  */
/* ============================================================================ */

/**
 * @brief Gracefully terminates background worker threads and dismantles all State subsystems.
 *
 * @param[in,out] state Pointer to initialized @ref State structure to destroy (safe if NULL).
 *
 * @pre No external threads may be actively executing operations using `state`.
 * @post All dynamic memory freed, threads joined, file descriptors closed, and keys zeroed.
 * @complexity Time: O(worker_threads_join + total_allocated_resources), Space: O(1).
 */
void client_state_destroy(State *state) {
    if (!state) {
        fprintf(stderr, "[GameState] WARNING: NULL state in client_state_destroy\n");
        return;
    }
    fprintf(stderr, "[GameState] Initiating client state destruction\n");

    // Temporarily signal shutdown to allow background threads to terminate
    atomic_store(&global_shutdown, true);
    state->submission_running = 0;

    // Wake any threads waiting on submission queue condition
    pthread_mutex_lock(&state->submission_mutex);
    pthread_cond_broadcast(&state->submission_cond);
    pthread_mutex_unlock(&state->submission_mutex);

    // Stop and join crypto verification workers first to prevent them accessing freed memory
    if (state->crypto_verify_running) {
        state->crypto_verify_running = 0;
        pthread_mutex_lock(&state->crypto_verify_mutex);
        pthread_cond_broadcast(&state->crypto_verify_cond);
        pthread_mutex_unlock(&state->crypto_verify_mutex);
        
        if (state->crypto_verify_workers) {
            for (int i = 0; i < state->crypto_verify_workers_count; i++) {
                if (state->crypto_verify_workers[i] != 0) {
                    pthread_join(state->crypto_verify_workers[i], NULL);
                }
            }
            free(state->crypto_verify_workers);
            state->crypto_verify_workers = NULL;
        }
        pthread_mutex_destroy(&state->crypto_verify_mutex);
        pthread_cond_destroy(&state->crypto_verify_cond);
        
        CryptoVerifyTask *task = state->crypto_verify_head;
        while (task) {
            CryptoVerifyTask *next = task->next;
            if (task->conn) {
                scl_connection_release(task->conn);
            }
            free(task);
            task = next;
        }
        state->crypto_verify_head = state->crypto_verify_tail = NULL;
    }

    // ====================== PHASE 1: Stop background operations ======================
    if (atomic_load(&state->autopilot_running)) {
        stop_autopilot_thread(state);
    }
    state->in_blockchain_sync = 0;  // Signal to stop any sync operations
    
    // ====================== PHASE 1.5: Shutdown recreation thread pool ======================
    pthread_mutex_lock(&state->recreation_sleep_mutex);
    pthread_cond_broadcast(&state->recreation_cond);
    pthread_mutex_unlock(&state->recreation_sleep_mutex);
 
    // Join recreation workers
    if (state->recreation_workers) {
        for (int i = 0; i < state->recreation_workers_count; i++) {
            if (state->recreation_workers[i] != 0) {
                pthread_join(state->recreation_workers[i], NULL);
            }
        }
        free(state->recreation_workers);
        state->recreation_workers = NULL;
    }
    
    // Destroy hypergraph thread
    if (state->hypergraph_maintainer_thread) {
        pthread_join(state->hypergraph_maintainer_thread, NULL);
        state->hypergraph_maintainer_thread = 0;
    }
    pthread_mutex_destroy(&state->hypergraph.lock);
    pthread_mutex_destroy(&state->hypergraph.puzzle_cache_lock);
    fprintf(stderr, "[GameState] Hypergraph maintainer thread destroyed\n");
    
    if (state->recreation_queues) {
        for (int i = 0; i < state->recreation_workers_count; i++) {
            pthread_mutex_destroy(&state->recreation_queues[i].mutex);
            // Note: The queue items (RecreationTask) should have been processed or freed by workers
            // No need to traverse and free here as workers should have taken ownership
        }
        free(state->recreation_queues);
        state->recreation_queues = NULL;
    }

    // Stop and join RPC worker threads
    for (int i = 0; i < MAX_RPC_WORKERS; i++) {
        if (state->rpc_engine.worker_threads[i] != 0) {
            pthread_join(state->rpc_engine.worker_threads[i], NULL);
            state->rpc_engine.worker_threads[i] = 0;
        }
    }
    pthread_mutex_destroy(&state->rpc_engine.incoming_rpc_queue.mutex);
    
    pthread_mutex_destroy(&state->recreation_sleep_mutex);
    pthread_cond_destroy(&state->recreation_cond);
    fprintf(stderr, "[GameState] Recreation thread pool destroyed\n");
    
    // ====================== PHASE 2: Destroy threshold stake processes ======================
    cleanup_all_threshold_processes(state);
    
    // ====================== PHASE 3: Destroy pubkey cache ======================
    if (state->pubkey_cache) {
        hash_table_destroy(state->pubkey_cache);
        free(state->pubkey_cache);
        state->pubkey_cache = NULL;
        fprintf(stderr, "[GameState] Pubkey cache destroyed\n");
    }

    // ====================== PHASE 4: Destroy blockchain components ======================
    blockchain_destroy(&state->bc);
    scl_db_close();
    fprintf(stderr, "[GameState] Blockchain and database closed\n");

    // ====================== PHASE 5: Destroy user management ======================
    // Destroy users array
    if (state->users) {
        for (size_t i = 0; i < state->user_count; i++) {
            destroy_user(&state->users[i]);
        }
        free(state->users);
        state->users = NULL;
        state->user_count = 0;
        fprintf(stderr, "[GameState] Users array destroyed\n");
    }

    // Destroy user table
    if (state->user_table) {
        hash_table_destroy(state->user_table);
        free(state->user_table);
        state->user_table = NULL;
        fprintf(stderr, "[GameState] User hash table destroyed\n");
    }

    // ====================== PHASE 6: Destroy hash tables ======================
    // Destroy processed transactions
    if (state->processed_txs) {
        hash_table_destroy(state->processed_txs);
        free(state->processed_txs);
        state->processed_txs = NULL;
        fprintf(stderr, "[GameState] Processed transactions hash table destroyed\n");
    }
    
    // Destroy active DKG sessions
    if (state->dkg_active_sessions) {
        hash_table_destroy(state->dkg_active_sessions);
        free(state->dkg_active_sessions);
        state->dkg_active_sessions = NULL;
        fprintf(stderr, "[GameState] DKG active sessions destroyed\n");
    }

    // Destroy block consensus
    if (state->block_consensus) {
        hash_table_destroy(state->block_consensus);
        free(state->block_consensus);
        state->block_consensus = NULL;
        fprintf(stderr, "[GameState] Block consensus destroyed\n");
    }

    // Destroy block proposers
    if (state->block_proposers) {
        pthread_mutex_lock(&state->block_proposers_lock);
        hash_table_destroy(state->block_proposers);
        free(state->block_proposers);
        state->block_proposers = NULL;
        pthread_mutex_unlock(&state->block_proposers_lock);
        pthread_mutex_destroy(&state->block_proposers_lock);
        fprintf(stderr, "[GameState] Block proposers hash table destroyed\n");
    }

    // Destroy pending operations lock-free array
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *op = atomic_exchange(&state->pending_operations[i], NULL);
        if (op) free(op);
    }
    atomic_store(&state->pending_operations_count, 0);
    fprintf(stderr, "[GameState] Pending operations lock-free array destroyed\n");
    
    // Destroy processed blocks
    if (state->processed_blocks) {
        pthread_mutex_lock(&state->processed_blocks_mutex);
        hash_table_destroy(state->processed_blocks);
        free(state->processed_blocks);
        state->processed_blocks = NULL;
        pthread_mutex_unlock(&state->processed_blocks_mutex);
        pthread_mutex_destroy(&state->processed_blocks_mutex);
        fprintf(stderr, "[GameState] Processed blocks hash table destroyed\n");
    }

    // Destroy voted heights
    if (state->voted_heights) {
        hash_table_destroy(state->voted_heights);
        free(state->voted_heights);
        state->voted_heights = NULL;
        fprintf(stderr, "[GameState] Voted heights hash table destroyed\n");
    }

    // Destroy orphan pool
    if (state->orphan_pool) {
        hash_table_destroy(state->orphan_pool);
        free(state->orphan_pool);
        state->orphan_pool = NULL;
        fprintf(stderr, "[GameState] Orphan pool hash table destroyed\n");
    }
    
    // Destroy submission queue and thread
    if (state->submission_workers) {
        for (int i = 0; i < state->submission_workers_count; i++) {
            if (state->submission_workers[i] != 0) {
                pthread_join(state->submission_workers[i], NULL);
                fprintf(stderr, "[ClientState] Submission processor thread %d joined\n", i);
            }
        }
        free(state->submission_workers);
        state->submission_workers = NULL;
    }
    queue_destroy(&state->submission_queue);
    fprintf(stderr, "[ClientState] Submission queue destroyed\n");

    // ====================== PHASE 7: Destroy network components ======================
    // Destroy message queue
    queue_destroy(&state->message_queue);
    fprintf(stderr, "[GameState] Message queue destroyed\n");

    // Destroy P2P network
    if (state->p2p_network.known_peers) {
        pthread_mutex_lock(&state->p2p_network.mutex);
        for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
            if (state->p2p_network.known_peers[i]) {
                if (state->p2p_network.known_peers[i]->conn) {
                    if (global_shim) {
                        if (global_shim->unregister_connection(global_shim, state->p2p_network.known_peers[i]->conn->cid)) {
                            scl_connection_release(state->p2p_network.known_peers[i]->conn);
                        }
                    }
                    scl_connection_release(state->p2p_network.known_peers[i]->conn);
                }
                free(state->p2p_network.known_peers[i]);
            }
        }
        free(state->p2p_network.known_peers);
        state->p2p_network.known_peers = NULL;
        state->p2p_network.num_known_peers = 0;
        pthread_mutex_unlock(&state->p2p_network.mutex);
        pthread_mutex_destroy(&state->p2p_network.mutex);
        fprintf(stderr, "[GameState] P2P network destroyed\n");
    }

    // ====================== PHASE 8: Cleanup remaining state ======================
    // Securely unlock and zeroize cryptographic keys and validation UTXO secrets
    pthread_mutex_lock(&state->wallet_mutex);
    
    // Unlock locked memory
    if (scl_secure_unlock(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN) != 0) {
        fprintf(stderr, "[ClientState] WARNING: Failed to unlock user Dilithium private key memory\n");
    }
    if (scl_secure_unlock(&state->user_wallet.prf_key, sizeof(PRFKey)) != 0) {
        fprintf(stderr, "[ClientState] WARNING: Failed to unlock user PRF key memory\n");
    }
    if (scl_secure_unlock(state->p2p_network.local_peer.peer_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN) != 0) {
        fprintf(stderr, "[ClientState] WARNING: Failed to unlock peer Dilithium private key memory\n");
    }
    if (scl_secure_unlock(state->p2p_network.local_peer.peer_wallet.kyber_privkey, KYBER_SECRETKEY_LEN) != 0) {
        fprintf(stderr, "[ClientState] WARNING: Failed to unlock peer Kyber private key memory\n");
    }

    explicit_bzero(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    explicit_bzero(&state->user_wallet.prf_key, sizeof(PRFKey));
    if (state->user_wallet.val_utxos) {
        explicit_bzero(state->user_wallet.val_utxos, state->user_wallet.cap_val_utxos * sizeof(ValidationUTXO));
        free(state->user_wallet.val_utxos);
        state->user_wallet.val_utxos = NULL;
    }
    pthread_mutex_destroy(&state->user_wallet.utxo_mutex);
    explicit_bzero(state->p2p_network.local_peer.peer_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    explicit_bzero(state->p2p_network.local_peer.peer_wallet.kyber_privkey, KYBER_SECRETKEY_LEN);
    pthread_mutex_unlock(&state->wallet_mutex);
    fprintf(stderr, "[GameState] Wallet keys securely wiped\n");

    // Deallocate epoch polynomial vectors and global commitments
    for (int i = 0; i < 10; i++) {
        if (state->epoch_s1_subsets[i].vec) polyvec_free(&state->epoch_s1_subsets[i]);
        if (state->epoch_s2_subsets[i].vec) polyvec_free(&state->epoch_s2_subsets[i]);
    }
    if (state->epoch_t_global.vec) polyvec_free(&state->epoch_t_global);
    
    // Release active atomic game state snapshot
    GameStateSnapshot *snap = (GameStateSnapshot *)atomic_exchange_explicit(&state->active_snapshot_ptr, 0, memory_order_acquire);
    if (snap) release_game_state_snapshot(snap);
    pthread_mutex_destroy(&state->snapshot_update_mutex);

    // ====================== PHASE 9: Destroy synchronization primitives ======================
    // Destroy game state mutex
    pthread_mutex_destroy(&state->game_state.mutex);
    fprintf(stderr, "[GameState] Game state mutex destroyed\n");

    // Destroy main mutexes
    pthread_mutex_destroy(&state->mutex);
    pthread_mutex_destroy(&state->ledger_mutex);
    pthread_mutex_destroy(&state->wallet_mutex);
    pthread_mutex_destroy(&state->submission_mutex);
    fprintf(stderr, "[GameState] Main mutexes destroyed\n");

    // Destroy condition variables
    pthread_cond_destroy(&state->audit_cond);
    pthread_cond_destroy(&state->pending_ops_cond);
    pthread_cond_destroy(&state->submission_cond);
    fprintf(stderr, "[GameState] Condition variables destroyed\n");

    // Destroy blockchain sync cond (LAST - may be used until final cleanup)
    pthread_cond_destroy(&state->blockchain_sync_cond);
    fprintf(stderr, "[GameState] Blockchain sync condition destroyed\n");

    // Reset global_shutdown to false so subsequent unit tests/operations can run
    atomic_store(&global_shutdown, false);

    fprintf(stderr, "[GameState] Client state destruction complete\n");
}
