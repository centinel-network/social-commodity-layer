/**
 * @file client/network/client_network.c
 * @brief Satocialist Protocol: Client-Side Network Synchronization & Dispatch Implementation
 *
 * @details
 * Implements the client-level blockchain synchronization worker loops, initial block download (IBD),
 * audit matrix synchronization, mempool catch-up, and incoming P2P message handlers for coin
 * transfers and consensus votes.
 *
 * @section protocol_invariants System Invariants Enforced
 * - Dependency-Gated Synchronization: Synchronization executes in strict sequential order:
 *   1. Historical Blocks (`sync_blockchain`)
 *   2. 10x10 Game Audit Matrix (`sync_audit`)
 *   3. Pending Mempool Operations (`sync_pending_operations`)
 * - Fork-Triggered Checkpoint Rollback: When a synchronization fork is detected, state is rolled back
 *   to the nearest 440-block checkpoint via @ref scl_db_rollback_state_to_checkpoint rather than wiping the chain.
 * - Genesis Initialization: Un-synchronized nodes initialize Block 0 natively before syncing to
 *   establish `sync_epoch = 1`, preventing integer underflow bugs during simulation.
 *
 * @section concurrency_model Threading & Concurrency
 * - `blockchain_sync_worker`: Executes as an asynchronous background thread with an 8 MiB stack.
 * - Global synchronization is protected by `state->mutex`, condition variables, and `state->sync_thread_active`.
 */

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <errno.h>
#include "client_network.h"
#include "client_aux.h"
#include "network.h"
#include "mmr.h"
#include "blockchain.h"
#include "game_state.h"
#include "hash_table.h"
#include "crypto.h"
#include "protocol.h"
#include "constants.h"
#include "types.h"
#include "utils.h"
#include "database.h"

#define fprintf scl_fprintf
#define printf scl_printf

/* ============================================================================ */
/* SECTION 1: ASYNCHRONOUS INITIAL BLOCK DOWNLOAD WORKER                        */
/* ============================================================================ */

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
/**
 * @brief Dedicated worker thread executing initial block download and checkpoint rollbacks.
 *
 * @param[in] arg Heap-allocated pointer to @ref SyncThreadArgs structure (freed by callee).
 * @return NULL upon thread termination.
 *
 * @complexity Time: O(missing_blocks * apply_block_time), Space: O(MAX_MESSAGE_SIZE).
 */
static void *blockchain_sync_worker(void *arg) {
    SyncThreadArgs *args = (SyncThreadArgs *)arg;
    
    fprintf(stderr, "[Network] Async sync worker started for peer (first 8 bytes): %02x%02x%02x%02x...\n",
            args->peer_pubkey[0], args->peer_pubkey[1], args->peer_pubkey[2], args->peer_pubkey[3]);
            
    // If this is a forced sync (due to a fork), execute MVCC rollback to the nearest checkpoint instead of wiping!
    if (args->force && args->state->current_block_number > 0) {
        uint64_t fork_height = args->state->current_block_number;
        uint64_t checkpoint_height = 0;
        uint8_t checkpoint_root[32] = {0};
        
        if (scl_db_get_highest_checkpoint(fork_height > 0 ? fork_height - 1 : 0, &checkpoint_height, checkpoint_root) == 0) {
            fprintf(stderr, "[Network] Forced sync triggered. Rolling back local state to Checkpoint %llu.\n", checkpoint_height);
        } else {
            fprintf(stderr, "[Network] Forced sync triggered. No checkpoint found, rolling back to Genesis.\n");
            checkpoint_height = 0;
        }

        pthread_mutex_lock(&args->state->ledger_mutex);
        pthread_rwlock_wrlock(&args->state->bc.rwlock);
        
        // Execute Graceful MVCC Reversion Pipeline natively using the DB Checkpoint
        scl_db_rollback_state_to_checkpoint(args->state, checkpoint_height, fork_height);

        args->state->current_block_number = checkpoint_height;
        args->state->bc.sync_epoch = checkpoint_height;
        
        if (checkpoint_height == 0) {
            // Re-create and apply standard genesis block if rolled back to zero
            memset(args->state->current_block_hash, 0, COIN_ID_LEN);
            Block *genesis = malloc(sizeof(Block));
            if (genesis) {
                *genesis = create_standard_genesis_block();
                apply_block(args->state, genesis);
                free_block(genesis);
            }
        } else {
            // Fast-load the checkpoint block to update the tip hash
            uint8_t *ser_block = NULL;
            size_t ser_len = 0;
            if (scl_db_get_block(checkpoint_height, &ser_block, &ser_len) == 0) {
                Block *cp_block = calloc(1, sizeof(Block));
                if (cp_block && deserialize_block(cp_block, ser_block, ser_len) == 0) {
                    compute_block_hash(cp_block, args->state->current_block_hash);
                }
                if (cp_block) free_block(cp_block);
                free(ser_block);
            }
        }
        
        pthread_rwlock_unlock(&args->state->bc.rwlock);
        pthread_mutex_unlock(&args->state->ledger_mutex);
    }
            
    // Perform the blocking sync operation with strict dependency gating
    if (sync_blockchain(args->state, args->peer_pubkey) == 0) {
        if (!atomic_load(&global_shutdown)) sync_audit(args->state, args->peer_pubkey);
        if (!atomic_load(&global_shutdown)) sync_pending_operations(args->state, args->peer_pubkey);
    } else {
        fprintf(stderr, "[Network] ERROR: Async blockchain sync failed. Skipping audit/mempool sync.\n");
    }
    
    // Tear down the sync lock globally only after all layers conclude
    pthread_mutex_lock(&args->state->mutex);
    args->state->in_blockchain_sync = 0;
    memset(args->state->sync_peer_pubkey, 0, DILITHIUM_PUBKEY_LEN);
    bool is_caught_up = (args->state->network_target_block_number == 0 ||
                         args->state->current_block_number >= args->state->network_target_block_number);
    pthread_mutex_unlock(&args->state->mutex);

    // Trigger proposal ONLY if we are fully synchronized and caught up with the network tip
    if (!atomic_load(&global_shutdown) && is_caught_up) {
        trigger_proposer_if_eligible(args->state);
    }
        
    atomic_store(&args->state->sync_thread_active, false); // Mark thread as dead
    free(args);
    arena_cleanup();
    return NULL;
}
#endif

/* ============================================================================ */
/* SECTION 2: SYNCHRONIZATION PIPELINES (BLOCKS, AUDIT, MEMPOOL)                */
/* ============================================================================ */

/**
 * @brief Triggers an asynchronous background thread to synchronize ledger state with a peer.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of the remote sync peer.
 * @param[in] force Flag: `true` forces synchronization and checkpoint rollback even if cooldown is active.
 *
 * @complexity Time: O(1), Space: O(1) thread control structures.
 */
void trigger_async_sync(State *state, const uint8_t *peer_pubkey, bool force) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)peer_pubkey; (void)force;
    if (state) {
        pthread_mutex_lock(&state->mutex);
        state->in_blockchain_sync = 0;
        pthread_mutex_unlock(&state->mutex);
    }
    return;
#else
    static _Atomic uint64_t last_sync_trigger_time = 0;
    uint64_t now = get_time_ms();
    uint64_t last = atomic_load(&last_sync_trigger_time);
    // Bypass cooldown if local blockchain is completely un-synced or wiped (height is 0) or force is true
    if (!force && state->current_block_number > 0 && now - last < 10000) { // 10-second cooldown
        fprintf(stderr, "[Network] Sync trigger throttled due to cooldown (circuit breaker active).\n");
        pthread_mutex_lock(&state->mutex);
        // Only release lock if we were previously actively syncing; otherwise keep it clean
        if (state->in_blockchain_sync) {
            state->in_blockchain_sync = 0;
        }
        pthread_mutex_unlock(&state->mutex);
        return;
    }

    SyncThreadArgs *args = malloc(sizeof(SyncThreadArgs));
    if (!args) {
        fprintf(stderr, "[Network] ERROR: Failed to allocate sync args\n");
        pthread_mutex_lock(&state->mutex);
        state->in_blockchain_sync = 0;
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    atomic_store(&last_sync_trigger_time, now);
    args->state = state;
    memcpy(args->peer_pubkey, peer_pubkey, DILITHIUM_PUBKEY_LEN);
    args->force = force;
    
    // Allocate 8 MiB stack size to safely handle recursive verification cascades
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    
    atomic_store(&state->sync_thread_active, true);
    if (pthread_create(&state->sync_thread, &attr, blockchain_sync_worker, args) != 0) {
        fprintf(stderr, "[Network] ERROR: Failed to create sync thread\n");
        atomic_store(&state->sync_thread_active, false);
        free(args);
        pthread_mutex_lock(&state->mutex);
        state->in_blockchain_sync = 0;
        pthread_mutex_unlock(&state->mutex);
    }
    pthread_attr_destroy(&attr);
#endif
}

/**
 * @brief Executes synchronous, sequential historical block synchronization with a selected peer.
 *
 * @details
 * Probes the peer's block height, requests missing blocks sequentially starting from local tip + 1,
 * applies incoming blocks to the ledger, and re-injects uncommitted local private UTXOs into
 * the MMR via @ref OP_CLAIM_VALIDATION broadcast upon completion.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of the sync peer.
 * @return 0 on successful block synchronization; -1 on timeout or transmission failure.
 *
 * @complexity Time: O(missing_blocks * apply_block_time), Space: O(MAX_MESSAGE_SIZE).
 */
int sync_blockchain(State *state, uint8_t *peer_pubkey) {
    int ret = -1;
    Message *block_query = NULL;
    int timed_out = 0;
    
    if (!state || !peer_pubkey) {
        fprintf(stderr, "[Client] ERROR: Invalid arguments for blockchain sync\n");
        return -1;
    }

    // Initialize genesis block natively if this node is completely empty.
    // This establishes state->bc.sync_epoch = 1, preventing UINT64_MAX underflow
    // that permanently locks out the game state simulator.
    if (state->current_block_number == 0 && state->bc.sync_epoch == 0) {
        if (initialize_genesis_block(state) != 0) {
            fprintf(stderr, "[Client] ERROR: Failed to initialize genesis block prior to sync\n");
            return -1;
        }
    }

    // Notice we do NOT blindly wipe the state!
    // If a hard fork conflict appears down the pipeline natively from the blocks, it will safely self-trigger.
    pthread_mutex_lock(&state->mutex);
    state->blockchain_sync_received_end = 0;
    state->in_blockchain_sync = 1;
    memcpy(state->sync_peer_pubkey, peer_pubkey, DILITHIUM_PUBKEY_LEN);
    pthread_mutex_unlock(&state->mutex);
    
    // Reset sync status variables
    pthread_mutex_lock(&state->mutex);
    state->sync_received_block_number_value = 0;
    memset(state->sync_received_block_hash, 0, COIN_ID_LEN);
    pthread_mutex_unlock(&state->mutex);

    // Query peer's active height first to determine if block transfer is needed
    Message *bn_query = calloc(1, sizeof(Message));
    if (bn_query) {
        bn_query->type = MSG_BLOCK_NUMBER_QUERY;
        bn_query->length = 0;
        send_message(state, peer_pubkey, bn_query);
        free(bn_query);
    }

    // Await peer block number response (up to 3 seconds)
    pthread_mutex_lock(&state->mutex);
    struct timespec bn_ts;
    clock_gettime(CLOCK_REALTIME, &bn_ts);
    bn_ts.tv_sec += 3;
    while (state->sync_received_block_number_value == 0 && !atomic_load(&global_shutdown)) {
        if (pthread_cond_timedwait(&state->blockchain_sync_cond, &state->mutex, &bn_ts) == ETIMEDOUT) {
            break;
        }
    }
    uint64_t peer_height = state->sync_received_block_number_value;
    uint8_t peer_hash[COIN_ID_LEN];
    memcpy(peer_hash, state->sync_received_block_hash, COIN_ID_LEN);
    uint64_t current_height = state->current_block_number;
    pthread_mutex_unlock(&state->mutex);

    // Fast-path: local chain is already caught up with or ahead of the peer
    if (peer_height > 0 && peer_height <= current_height) {
        if (peer_height == current_height && memcmp(peer_hash, state->current_block_hash, COIN_ID_LEN) == 0) {
            fprintf(stderr, "[Client] Local blockchain is already at peer's tip (height: %llu). Sync complete.\n", (unsigned long long)current_height);
            ret = 0;
            goto sync_finish_utxos;
        } else if (peer_height < current_height) {
            fprintf(stderr, "[Client] Local blockchain (height: %llu) is ahead of peer (height: %llu). Sync complete.\n", (unsigned long long)current_height, (unsigned long long)peer_height);
            ret = 0;
            goto sync_finish_utxos;
        }
    }

    // Sync Centinel states (Private UTXOs / Off-chain Validations) only when peer is ahead or on a different branch
    Message *centinel_query = calloc(1, sizeof(Message));
    if (centinel_query) {
        centinel_query->type = MSG_CENTINEL_QUERY;
        centinel_query->length = 0;
        send_message(state, peer_pubkey, centinel_query);
        free(centinel_query);
    }

    // Request missing blocks dynamically starting from local tip + 1
    block_query = calloc(1, sizeof(Message));
    if (!block_query) goto cleanup_sync;
    block_query->type = MSG_GET_BLOCKS;
    block_query->length = sizeof(uint64_t);
    uint64_t request_height = htobe64(state->current_block_number + 1);
    memcpy(block_query->payload, &request_height, sizeof(uint64_t));

    if (!send_message(state, peer_pubkey, block_query)) {
        fprintf(stderr, "[Client] ERROR: Failed to send MSG_GET_BLOCKS\n");
        goto cleanup_sync;
    }

    // Adaptive sync loop: resets watchdog on each block applied to state
    pthread_mutex_lock(&state->mutex);
    uint64_t last_applied_height = state->current_block_number;
    uint64_t last_progress_time = get_time_ms();

    while (!state->blockchain_sync_received_end && !atomic_load(&global_shutdown)) {
        // Break early if we reached the peer's reported height
        if (peer_height > 0 && state->current_block_number >= peer_height) {
            state->blockchain_sync_received_end = 1;
            break;
        }

        struct timespec step_ts;
        clock_gettime(CLOCK_REALTIME, &step_ts);
        step_ts.tv_sec += 2; // 2-second check window

        pthread_cond_timedwait(&state->blockchain_sync_cond, &state->mutex, &step_ts);

        // Reset progress timer if any new block was applied
        if (state->current_block_number > last_applied_height) {
            last_applied_height = state->current_block_number;
            last_progress_time = get_time_ms();
        } else {
            uint64_t elapsed_stall = get_time_ms() - last_progress_time;
            // If batch ended or stalled for >2 seconds without reaching target, re-request from current tip
            if (elapsed_stall >= 2000 && !state->blockchain_sync_received_end) {
                uint64_t next_needed = state->current_block_number + 1;
                if (peer_height == 0 || next_needed <= peer_height) {
                    pthread_mutex_unlock(&state->mutex);
                    Message *batch_req = calloc(1, sizeof(Message));
                    if (batch_req) {
                        batch_req->type = MSG_GET_BLOCKS;
                        batch_req->length = sizeof(uint64_t);
                        uint64_t req_h_be = htobe64(next_needed);
                        memcpy(batch_req->payload, &req_h_be, sizeof(uint64_t));
                        send_message(state, peer_pubkey, batch_req);
                        free(batch_req);
                    }
                    pthread_mutex_lock(&state->mutex);
                    last_progress_time = get_time_ms();
                }
            }
            if (elapsed_stall >= 30000) { // 30s timeout ceiling
                timed_out = 1;
                break;
            }
        }
    }

    if (state->blockchain_sync_received_end || (peer_height > 0 && state->current_block_number >= peer_height)) {
        ret = 0; // Fully synchronized
    } else if (state->current_block_number > 0 && !timed_out) {
        ret = 0; // Progress made and stream ended cleanly
    }
    pthread_mutex_unlock(&state->mutex);

sync_finish_utxos:

    if (ret == 0) {
        fprintf(stderr, "[Client] Blockchain sync completed successfully via verifiable blocks (new height: %llu)\n", state->current_block_number);
                    
        // Re-inject local Private UTXOs *after* the global chronological state has been mapped
        pthread_rwlock_wrlock(&state->bc.rwlock);
        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
            ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&utxo->commitment, sizeof(BdlopCommitment), commitment_hash);
            
            // Check if commitment has already been added to the Centinel MMR
            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, commitment_hash, 0) < 0) {
                mmr_add(state->bc.centinel.validation_commitments, commitment_hash, 0);
                
                // Construct and broadcast OP_CLAIM_VALIDATION operation for uncommitted UTXOs
                Operation *claim_op = calloc(1, sizeof(Operation));
                if (claim_op) {
                    claim_op->type = OP_CLAIM_VALIDATION;
                    memcpy(&claim_op->data.claim_validation.commitment, &utxo->commitment, sizeof(BdlopCommitment));
                    memcpy(claim_op->data.claim_validation.pubkey, utxo->pubkey, PUBKEY_LEN);
                    dilithium_sign(commitment_hash, COIN_ID_LEN, state->user_wallet.dilithium_privkey, claim_op->data.claim_validation.signature);
                        
                    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
                    pthread_rwlock_unlock(&state->bc.rwlock);
                        
                    int claim_added = -1;
                    Message *claim_msg = calloc(1, sizeof(Message));
                    if (claim_msg) {
                        claim_msg->type = MSG_PENDING_OPERATION;
                        claim_msg->length = serialize_operation(claim_op, claim_msg->payload, MAX_MESSAGE_SIZE);
                            
                        pthread_mutex_lock(&state->mutex);
                        claim_added = add_pending_operation(state, claim_op);
                        pthread_mutex_unlock(&state->mutex);
                            
                        p2p_broadcast(state, claim_msg);
                        free(claim_msg);
                    }
                    if (claim_added != 0) {
                        free(claim_op);
                    }
                        
                    pthread_rwlock_wrlock(&state->bc.rwlock);
                    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
                }
            }
        }
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
        pthread_rwlock_unlock(&state->bc.rwlock);
            
    } else {
        fprintf(stderr, "[Client] ERROR: Verifiable Block Sync timed out or incomplete after 60 seconds\n");
    }

cleanup_sync:
    if (block_query) free(block_query);
    return ret;
}

/**
 * @brief Synchronizes the 10x10 Game Audit circular valuation matrix with a remote peer.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of the target peer.
 * @return 0 on successful audit synchronization; -1 on failure after 3 retries.
 *
 * @complexity Time: O(retries * timeout), Space: O(sizeof(Message)).
 */
int sync_audit(State *state, uint8_t *peer_pubkey) {
    if (!state || !peer_pubkey) return -1;

    int retries = 3;
    while (retries-- > 0) {
        if (atomic_load(&global_shutdown)) break;
        
        pthread_mutex_lock(&state->mutex);
        state->audit_received = 0;
        pthread_mutex_unlock(&state->mutex);

        // Reset local audit state to forcibly accept the remote state during explicit synchronization
        pthread_mutex_lock(&state->game_state.mutex);
        state->game_state.audit_timestamp = 0;
        pthread_mutex_unlock(&state->game_state.mutex);

        Message *req = calloc(1, sizeof(Message));
        if (!req) continue;
        req->type = MSG_GET_AUDIT;
        req->length = 0;
        int sent = send_message(state, peer_pubkey, req);
        free(req);
        if (!sent) {
            fprintf(stderr, "[Client] ERROR: Failed to send MSG_GET_AUDIT\n");
            continue;
        }

        pthread_mutex_lock(&state->mutex);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;

        int wait_ret = 0;
        if (!state->audit_received) {
            while (!state->audit_received) {
                if (atomic_load(&global_shutdown)) break;
                wait_ret = pthread_cond_timedwait(&state->audit_cond, &state->mutex, &ts);
                if (wait_ret == ETIMEDOUT) break;
            }
        }
        
        if (atomic_load(&global_shutdown)) {
            pthread_mutex_unlock(&state->mutex);
            break;
        }

        if (wait_ret == ETIMEDOUT || wait_ret != 0) {
            pthread_mutex_unlock(&state->mutex);
            fprintf(stderr, "[Client] WARNING: Audit sync attempt failed, retrying (%d left)...\n", retries);
            continue;
        }

        if (state->audit_received) {
            int current_idx = state->game_state.current_audit_index;
            int val_cnt = state->game_state.valuation_count;
            pthread_mutex_unlock(&state->mutex);

            fprintf(stderr, "[Client] Game audit sync completed successfully, current_audit_index=%d, valuation_count=%d\n", current_idx, val_cnt);
            return 0; // Success
        }

        pthread_mutex_unlock(&state->mutex);
        // Backoff delay before next retry attempt
        usleep(1000000);
    }

    fprintf(stderr, "[Client] ERROR: Audit sync failed after retries\n");
    return -1; // Failure
}

/**
 * @brief Synchronizes unconfirmed mempool transactions from a remote peer.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of target peer.
 * @return 0 on successful mempool synchronization; -1 on timeout or failure.
 *
 * @complexity Time: O(timeout + mempool_size * add_pending_operation), Space: O(MAX_MESSAGE_SIZE).
 */
int sync_pending_operations(State *state, uint8_t *peer_pubkey) {
    if (!state || !peer_pubkey) return -1;

    pthread_mutex_lock(&state->mutex);
    state->pending_ops_received = 0;
    pthread_mutex_unlock(&state->mutex);

    Message *query = calloc(1, sizeof(Message));
    if (!query) return -1;
    query->type = MSG_GET_PENDING_OPERATIONS;
    query->length = 0;
    int sent = send_message(state, peer_pubkey, query);
    free(query);
    if (!sent) {
        fprintf(stderr, "[Client] ERROR: Failed to send MSG_GET_PENDING_OPERATIONS\n");
        return -1;
    }

    pthread_mutex_lock(&state->mutex);
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 30; // Increased to handle CPU saturation during large async recreation cascades
    
    // Await inbound pending operations batch with 30-second timeout
    int timed_out = 0;
    while (!state->pending_ops_received) {
        if (atomic_load(&global_shutdown)) {
            timed_out = 1;
            break;
        }
        if (pthread_cond_timedwait(&state->pending_ops_cond, &state->mutex, &timeout) == ETIMEDOUT) {
            timed_out = 1;
            break;
        }
    }
    
    int received = state->pending_ops_received;
    pthread_mutex_unlock(&state->mutex);

    if (timed_out || !received) {
        fprintf(stderr, "[Client] ERROR: Pending operations sync timed out or incomplete\n");
        return -1;
    }

    fprintf(stderr, "[Client] Pending operations sync completed successfully\n");
    return 0;
}

/* ============================================================================ */
/* SECTION 3: CONSENSUS VOTE & COIN TRANSFER INGRESS HANDLERS                   */
/* ============================================================================ */

/**
 * @brief Decodes, validates, and registers an incoming consensus vote message (`MSG_VOTE`).
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] msg Network message containing serialized @ref Vote payload (`MSG_VOTE`).
 * @param[in] sender_pubkey Authenticated 2,592-byte Dilithium5 public key of sender.
 *
 * @complexity Time: O(Dilithium5_verify + existing_votes), Space: O(1).
 */
void handle_vote(State *state, Message *msg, uint8_t *sender_pubkey) {
    // Validate inputs
    if (!state || !msg || msg->type != MSG_VOTE || !sender_pubkey) {
        fprintf(stderr, "[Client] ERROR: Invalid inputs for handle_vote\n");
        return;
    }

    // Deserialize vote
    Vote vote;
    if (deserialize_vote(msg, &vote) != 0) {
        scl_log(LOG_LEVEL_DEBUG, "Client", "Failed to deserialize vote");
        return;
    }

    // Verify vote signature
    if (!verify_vote(&vote, vote.block_hash)) {
        fprintf(stderr, "[Client] ERROR: Invalid vote signature\n");
        return;
    }

    uint8_t block_hash[COIN_ID_LEN];
    memcpy(block_hash, vote.block_hash, COIN_ID_LEN);

    // Lock state->mutex to access block_consensus
    pthread_mutex_lock(&state->mutex);
    BlockVoteQueue *queue = hash_table_lookup(state->block_consensus, block_hash, false);
    if (!queue) {
        pthread_mutex_unlock(&state->mutex);
        // Queue might have been cleaned up if consensus was already reached
        return;
    }
    
    // Lock queue->vote_lock and increment ref_count
    pthread_mutex_lock(&queue->vote_lock);
    queue->ref_count++;
    pthread_mutex_unlock(&state->mutex);

    // Check if votes array is valid
    if (!queue->votes) {
        fprintf(stderr, "[Client] ERROR: Vote queue votes array is null for block_hash=\n");
        pthread_mutex_unlock(&queue->vote_lock);
        free_block_vote_queue(queue);
        return;
    }

    // Check for duplicate votes
    for (size_t i = 0; i < queue->count; i++) {
        if (memcmp(queue->votes[i].voter_pubkey, vote.voter_pubkey, PUBKEY_LEN) == 0) {
            pthread_mutex_unlock(&queue->vote_lock);
            free_block_vote_queue(queue);
            return;
        }
    }

    int consensus_reached_just_now = 0;
    size_t saved_yes_votes = 0;
    size_t saved_count = 0;
    uint64_t saved_block_height = queue->block_height;

    // Add valid vote to queue
    if (queue->count < queue->size) {
        queue->votes[queue->count] = vote;
        queue->count++;
        if (vote.vote) {
            queue->yes_votes++;
            
            // Calculate threshold based on strictly deduplicated active peers
            size_t num_peers = 0;
            pthread_mutex_lock(&state->p2p_network.mutex);
            // Filter and deduplicate active peers with valid Dilithium public keys
            const uint8_t **active_pubkeys = malloc(state->p2p_network.num_known_peers * sizeof(const uint8_t *));
            if (active_pubkeys) {
                size_t active_count = 0;
                for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                    Peer *peer = state->p2p_network.known_peers[i];
                    if (!is_zeroed(peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) &&
                        validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey) &&
                        peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                        active_pubkeys[active_count++] = peer->peer_wallet.dilithium_pubkey;
                    }
                }
                if (active_count > 0) {
                    qsort(active_pubkeys, active_count, sizeof(const uint8_t *), compare_pubkey_ptrs);
                    num_peers = 1;
                    for (size_t i = 1; i < active_count; i++) {
                        if (memcmp(active_pubkeys[i], active_pubkeys[i - 1], PUBKEY_LEN) != 0) {
                            num_peers++;
                        }
                    }
                }
                free(active_pubkeys);
            }
            pthread_mutex_unlock(&state->p2p_network.mutex);

            // Safety: prevent division by zero or invalid thresholding if disconnected
            if (num_peers == 0) num_peers = 1;

            size_t required_votes = (size_t)ceil((double)num_peers * CONSENSUS_THRESHOLD);
            
            // Check if consensus is reached
            if (queue->yes_votes >= required_votes) {
                consensus_reached_just_now = 1;
                saved_yes_votes = queue->yes_votes;
                saved_count = queue->count;
            }
        }
        
        // Signal the vote collector thread
        pthread_cond_signal(&queue->cond);
    } else {
        fprintf(stderr, "[Client] ERROR: Vote queue full\n");
    }

    pthread_mutex_unlock(&queue->vote_lock);
    free_block_vote_queue(queue);

    // If consensus triggered on this precise evaluation, we can safely acquire the state->mutex lock
    // to wipe out any active competing forks now that the vote_lock is completely yielded
    if (consensus_reached_just_now) {
        fprintf(stderr, "[Client] Consensus reached for block_hash=");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", block_hash[i]);
        fprintf(stderr, "... yes_votes=%zu, total=%zu\n", saved_yes_votes, saved_count);

        // Clean other vote queues for the same block height (Competing forks)
        pthread_mutex_lock(&state->mutex);
        for (size_t i = 0; i < state->block_consensus->size; i++) {
            GenericHashEntry *entry = state->block_consensus->buckets[i];
            while (entry) {
                GenericHashEntry *next_entry = entry->next;
                if (entry->type == HASH_ENTRY_VOTE_QUEUE) {
                    BlockVoteQueue *other_queue = entry->data.queue;
                    if (other_queue != queue && other_queue->block_height == saved_block_height) {
                        // Found another vote queue for the same height: Remove it
                        // hash_table_remove will invoke the registered free_entry_fn which safely decrements ref_count
                        hash_table_remove(state->block_consensus, entry->key);
                        // Restart bucket scan or break is acceptable here; break for safety
                        break;
                    }
                }
                entry = next_entry;
            }
        }
        pthread_mutex_unlock(&state->mutex);
    }
}

/**
 * @brief Ingress handler processing unconfirmed on-chain pointer transfer requests (`MSG_PTR_TRANSFER`).
 *
 * @param[in,out] net Pointer to P2P network subsystem container.
 * @param[in,out] state Pointer to global node state container.
 * @param[in] msg Inbound message container.
 * @param[in] sender_pubkey Authenticated 2,592-byte Dilithium5 public key of sender.
 *
 * @complexity Time: O(num_inputs * MMR_verify + ZK_verify + Dilithium5_verify), Space: O(sizeof(Operation)).
 */
void handle_coin_transfer(P2PNetwork *net, State *state, Message *msg, uint8_t *sender_pubkey) {
    if (!net || !state || !msg || msg->type != MSG_PTR_TRANSFER || msg->length < 44 || !sender_pubkey) {
        scl_log(LOG_LEVEL_DEBUG, "Client", "Invalid inputs for coin transfer");
        return;
    }

    size_t fn_mark = arena_mark();
    TransferData *tx = NULL;
    size_t signed_data_len;
    if (deserialize_transfer_payload(msg, &tx, &signed_data_len) != 0) {
        scl_log(LOG_LEVEL_DEBUG, "Client", "Failed to deserialize transfer payload.");
        arena_reset(fn_mark);
        return;
    }
    printf("[Client] Deserialized tx: num_inputs=%u, amount=%llu\n", tx->num_inputs, tx->amount);

    if (tx->num_inputs == 0 || tx->num_inputs > MAX_INPUTS) {
        fprintf(stderr, "[Client] Invalid num_inputs: %u\n", tx->num_inputs);
        arena_reset(fn_mark);
        return;
    }

    // Verify client MMR root matches current local ledger root
    uint8_t client_root[COIN_ID_LEN];
    get_mmr_root(&state->bc, client_root);
    if (memcmp(tx->client_root, client_root, COIN_ID_LEN) != 0) {
        log_hex("[Client] MMR root mismatch: client_root=", tx->client_root, COIN_ID_LEN, 16);
        log_hex("[Client]              our_root=", client_root, COIN_ID_LEN, 16);
        arena_reset(fn_mark);
        return;
    }

    pthread_mutex_lock(&state->mutex);
    
    // Validate input pointers, parent coins, MMR membership proofs, and ownership
    uint64_t total_subunits = 0;
    for (size_t i = 0; i < tx->num_inputs; i++) {
        Pointer *ptr = &tx->inputs[i];
        MMRProof *proof = &tx->proofs[i];
        if (ptr->start_subunit > ptr->end_subunit) {
            fprintf(stderr, "[Client] Invalid pointer %zu: start=%llu, end=%llu\n",
                        i, ptr->start_subunit, ptr->end_subunit);
            pthread_mutex_unlock(&state->mutex);
            arena_reset(fn_mark);
            return;
        }

        SCLCoin *coin = hash_table_lookup(state->bc.coin_table, ptr->parent_coin_id, false);
        if (!coin) {
            log_hex("[Client] Parent coin not found: ", ptr->parent_coin_id, COIN_ID_LEN, 16);
            pthread_mutex_unlock(&state->mutex);
            arena_reset(fn_mark);
            return;
        }

        uint8_t leaf_hash[COIN_ID_LEN];
        hash_leaf(ptr->parent_coin_id, coin->remaining_subunits, leaf_hash);
        if (!verify_mmr_proof(leaf_hash, proof, client_root)) {
            fprintf(stderr, "[Client] MMR proof failed for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            arena_reset(fn_mark);
            return;
        }

        Pointer *existing = hash_table_lookup(state->bc.pointer_table, ptr->pointer_id, false);
        if (!existing || existing->spent || memcmp(existing->owner_address, ptr->owner_address, USER_ID_LEN) != 0) {
            fprintf(stderr, "[Client] Invalid pointer %zu: not found, spent, or owner mismatch\n", i);
            pthread_mutex_unlock(&state->mutex);
            arena_reset(fn_mark);
            return;
        }
                    
        // Ensure all inputs have the same owner, a requirement for the Merkle root signature scheme
        if (memcmp(ptr->owner_address, tx->inputs[0].owner_address, USER_ID_LEN) != 0) {
            fprintf(stderr, "[Client] ERROR: All input pointers must have the same owner.\n");
            pthread_mutex_unlock(&state->mutex);
            arena_reset(fn_mark);
            return;
        }

        total_subunits += existing->end_subunit - existing->start_subunit + 1;
    }

    if (total_subunits < tx->amount) {
        fprintf(stderr, "[Client] Insufficient subunits: available=%llu, required=%llu\n",
                total_subunits, tx->amount);
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }

    // Verify the Merkle root of inputs and the signature on that root
    uint8_t computed_merkle_root[COIN_ID_LEN];
    compute_inputs_merkle_root(tx->inputs, tx->num_inputs, computed_merkle_root);
    if (memcmp(computed_merkle_root, tx->inputs_merkle_root, COIN_ID_LEN) != 0) {
        fprintf(stderr, "[Client] ERROR: Inputs Merkle root mismatch.\n");
        log_hex("[Client]  Computed: ", computed_merkle_root, COIN_ID_LEN, 16);
        log_hex("[Client]  Received: ", tx->inputs_merkle_root, COIN_ID_LEN, 16);
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }
        
    if (dilithium_verify(tx->inputs_merkle_root, COIN_ID_LEN, tx->inputs_root_signature, sender_pubkey) != 0) {
        fprintf(stderr, "[Client] ERROR: Inputs Merkle root signature verification failed.\n");
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }

    // Verify the main transaction signature and ID with verified lower bound
    size_t signed_buf_size = msg->length > 8192 ? msg->length : 8192;
    uint8_t *signed_data_buf = arena_alloc(signed_buf_size);
    if (!signed_data_buf) {
        fprintf(stderr, "[Client] Failed to allocate memory for signature verification.\n");
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }
        
    size_t temp_signed_data_len;
    if (serialize_transfer_payload(tx, signed_data_buf, &temp_signed_data_len) != 0) {
        fprintf(stderr, "[Client] Failed to serialize transfer payload for verification.\n");
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }

    if (dilithium_verify(signed_data_buf, temp_signed_data_len, tx->signature, sender_pubkey) != 0) {
        fprintf(stderr, "[Client] Main transaction signature verification failed.\n");
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }

    uint8_t computed_tx_id[COIN_ID_LEN];
    SHA256(signed_data_buf, temp_signed_data_len, computed_tx_id);
    
    if (memcmp(computed_tx_id, tx->tx_id, COIN_ID_LEN) != 0) {
        log_hex("[Client] tx_id mismatch: computed=", computed_tx_id, COIN_ID_LEN, 16);
        log_hex("[Client]           received=", tx->tx_id, COIN_ID_LEN, 16);
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }

    // Check duplicate
    int is_duplicate = (hash_table_lookup(state->processed_txs, tx->tx_id, true) != NULL);
    if (is_duplicate) {
        log_hex("[Client] Duplicate transaction ID: ", tx->tx_id, COIN_ID_LEN, 16);
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }

    // Create operation and add to pending operations
    Operation *op = calloc(1, sizeof(Operation));
    if (!op) {
        fprintf(stderr, "[Client] ERROR: Failed to allocate memory for operation\n");
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }
    op->type = OP_TRANSFER_POINTER;
    op->data.transfer_pointer = *tx;

    pthread_mutex_unlock(&state->mutex);
    // Perform compute-intensive zero-knowledge or signature checks outside mutex
    if (verify_operation_heavy_crypto(op) != CRYPTO_SUCCESS) {
        free(op);
        arena_reset(fn_mark);
        return;
    }
    pthread_mutex_lock(&state->mutex);

    int added = add_pending_operation(state, op);
    if (added != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to insert operation into pending_operations\n");
        free(op);
        pthread_mutex_unlock(&state->mutex);
        arena_reset(fn_mark);
        return;
    }

    // Mark transaction as processed to prevent duplicates
    hash_table_insert(state->processed_txs, tx->tx_id, NULL, HASH_ENTRY_TX);
    
    pthread_mutex_unlock(&state->mutex);
    arena_reset(fn_mark);
}
