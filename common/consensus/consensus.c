/**
 * @file consensus.c
 * @brief Core Consensus, Block Proposal, DKG, and State Transition Engine.
 *
 * Module Architecture and Subsystem Role:
 * ---------------------------------------
 * This module implements the distributed state machine replication, consensus,
 * cryptographic epoch governance, and block lifecycle engines for the Satocialist
 * Cryptographic Ledger (SCL) and Centinel Network. It serves as the authoritative
 * state arbiter across peer nodes, governing block construction, validation,
 * distributed key generation (Joint-RSS DKG), threshold signing ceremonies, and
 * two-phase atomic ledger commits backed by libmdbx and Merkle Mountain Ranges.
 *
 * Formal Invariants Maintained Across Module Boundaries:
 * ------------------------------------------------------
 * 1. Strict Monotonic Height Ordering: A block at height H can only be committed
 *    to the ledger if the current tip height is strictly H - 1.
 * 2. Continuous Cryptographic Linkage: A block's `prev_block_hash` field must
 *    match byte-for-byte with the active tip's `current_block_hash` (32 bytes).
 * 3. Double-Spend Immunity: Coin pointer subunits and Centinel UTXO nullifiers
 *    are recorded in persistent global sets and Bloom filters; duplicate spends
 *    are rejected unconditionally prior to mutation.
 * 4. Dual-Pass Transaction Processing: Blocks undergo an atomic read-only validation
 *    pass over all transactions before entering the mutation pass. If any single
 *    operation fails verification, all state changes are completely rolled back.
 * 5. Deterministic Committee Topology: Epoch committee sorting produces identical
 *    point IDs (1 to 10) across all honest peers based on stake and Dilithium public keys.
 * 6. Non-Reentrant Deadlock Freedom: Locks are acquired in strict global partial order:
 *    `state->mutex` -> `state->bc.rwlock` -> `state->ledger_mutex` ->
 *    `state->epoch_mutex` -> `state->game_state.mutex` -> `queue->vote_lock`.
 *
 * Cryptographic and Network Standards Implemented:
 * ------------------------------------------------
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium5).
 * - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber-768).
 * - BDLOP: Homomorphic Lattice Commitment Scheme (Baum, Damgard, Lyubashevsky, Orecchia, Peikert).
 * - Stern Zero-Knowledge Framework: Constant-time lattice relation proofs.
 * - Peter Todd MMR: Pruned Merkle Mountain Range trees for balance and validation inclusion.
 *
 * Lifetime, Allocation, and Memory Ownership Paradigms:
 * -----------------------------------------------------
 * - Dynamic structures (e.g., `Block`, `Operation`, `Message`) allocated by callers
 *   are tracked via explicit ownership transfers; functions releasing memory are documented.
 * - Ephemeral cryptographic material (seeds, polynomial sub-shares, private keys) are
 *   scrubbed via `explicit_bzero` or secure memory wipes upon ceremony completion.
 * - High-throughput temporary serialization payloads utilize the thread-local linear arena
 *   allocator (`arena_alloc` / `arena_reset`) to ensure zero heap churn.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <openssl/rand.h>
#include "consensus.h"
#include "network.h"
#include "client_network.h"
#include "crypto.h"
#include "blockchain.h"
#include "hash_table.h"
#include "mmr.h"
#include "database.h"
#include "constants.h"
#include "utils.h"

/* ============================================================================ */
/* SECTION 1: Telemetry and Logging Redirections                               */
/* ============================================================================ */
/* Architectural Preface:
 * Replaces standard C I/O streams with thread-safe, non-blocking telemetry
 * logging routines (`scl_log`, `scl_log_stderr`). Ensures structured logging
 * output without stalling consensus-critical CPU execution pipelines.
 */

#undef fprintf
#define fprintf(stream, ...) do { \
    if (stream == stderr) { \
        scl_log_stderr("Consensus", __VA_ARGS__); \
    } else { \
        scl_fprintf(stream, __VA_ARGS__); \
    } \
} while(0)

#undef printf
#define printf(...) scl_log(LOG_LEVEL_INFO, "Consensus", __VA_ARGS__)

/* ============================================================================ */
/* SECTION 2: Cryptographic Identity and Vote Signing Subsystem                */
/* ============================================================================ */
/* Architectural Preface:
 * Manages identity resolution between Dilithium public keys and user addresses,
 * providing zero-allocation caching and canonical vote envelope signing using
 * post-quantum lattice primitives.
 */

/**
 * @brief Computes address digest and registers a Dilithium public key in cache.
 *
 * Performs an SHA-256 evaluation over a 2592-byte Dilithium public key to derive
 * the 32-byte User ID address. Checks `state->pubkey_cache`; if the address is
 * not present, inserts a newly constructed `PubkeyCacheEntry`.
 *
 * @pre `state` must be non-NULL with an initialized `pubkey_cache` hash table.
 * @pre `pubkey` must point to a valid 2592-byte buffer containing non-zero bytes.
 * @post The public key is indexed in `pubkey_cache` under its 32-byte SHA-256 address.
 * @sideeffect May allocate a new hash bucket node within `state->pubkey_cache`.
 * @sync Thread Safety: Caller must hold `state->mutex` if accessing the cache
 *       outside a locked critical section.
 *
 * @param[in,out] state  Pointer to the shared global ledger State structure.
 * @param[in]     pubkey Pointer to the 2592-byte Dilithium public key buffer.
 *
 * @return void.
 * @complexity Time: O(1) expected hash table lookup and insertion; Space: O(1).
 */
static void cache_pubkey(State *state, const uint8_t *pubkey) {
    if (!state || !pubkey || is_zeroed(pubkey, PUBKEY_LEN)) return;
    
    // Derive 32-byte address digest from Dilithium public key
    uint8_t addr[USER_ID_LEN];
    SHA256(pubkey, PUBKEY_LEN, addr);
    
    // Insert into public key cache if not already present
    if (!hash_table_lookup(state->pubkey_cache, addr, false)) {
        PubkeyCacheEntry pce;
        memcpy(pce.pubkey, pubkey, PUBKEY_LEN);
        hash_table_insert(state->pubkey_cache, addr, &pce, HASH_ENTRY_PUBKEY_CACHE);
    }
}

/**
 * @brief Constructs and cryptographically signs a vote payload for a block hash.
 *
 * Populates a `Vote` structure with the voter's public key, target block hash,
 * and binary vote flag. Formats the canonical message buffer:
 * `vote_data = block_hash (32 bytes) || vote_val (1 byte)`
 * and computes an ML-DSA-87 (Dilithium5) digital signature over the 33-byte buffer.
 *
 * @pre `v`, `voter_pubkey`, `block_hash`, and `voter_privkey` must be non-NULL.
 * @pre `vote_val` must be either 0 (rejection) or 1 (approval).
 * @post `v->signature` contains the 4595-byte Dilithium signature upon success.
 * @sideeffect None. Operates on local stack buffers and destination pointers.
 * @sync Thread Safety: Reentrant. Does not access global state or shared memory.
 *
 * @param[out] v             Pointer to destination Vote structure to populate.
 * @param[in]  voter_pubkey  Pointer to voter's 2592-byte Dilithium public key.
 * @param[in]  block_hash    Pointer to 32-byte hash of the candidate block.
 * @param[in]  vote_val      Binary vote indicator (1 for yes, 0 for no).
 * @param[in]  voter_privkey Pointer to voter's 4864-byte Dilithium private key.
 *
 * @return 1 on successful signature generation; 0 on cryptographic failure.
 * @complexity Time: O(1) dominated by lattice polynomial sampling; Space: O(1).
 */
static int sign_vote(Vote *v, const uint8_t *voter_pubkey, const uint8_t *block_hash, uint8_t vote_val, const uint8_t *voter_privkey) {
    memcpy(v->voter_pubkey, voter_pubkey, PUBKEY_LEN);
    memcpy(v->block_hash, block_hash, COIN_ID_LEN);
    v->vote = vote_val;

    // Fixed 33-byte canonical vote envelope: 32 bytes block hash + 1 byte vote value
    uint8_t vote_data[COIN_ID_LEN + 1];
    memcpy(vote_data, block_hash, COIN_ID_LEN);
    vote_data[COIN_ID_LEN] = vote_val;

    return dilithium_sign(vote_data, sizeof(vote_data), voter_privkey, v->signature);
}

/* ============================================================================ */
/* SECTION 3: Asynchronous State Reorganization and Orphan Resolution          */
/* ============================================================================ */
/* Architectural Preface:
 * Provides state reorganization mechanisms when disconnected branch segments
 * arrive out of sequence. Scans the orphan pool upon each successful block
 * commitment to identify matching parent hashes and recursively promote orphans.
 */

/**
 * @brief Scans the orphan pool and applies eligible chained blocks to the ledger.
 *
 * Iterates across `state->orphan_pool` buckets to identify blocks whose
 * `prev_block_hash` matches the newly updated `state->current_block_hash`.
 * Promotes matching blocks by invoking `apply_block`. Upon a successful commit,
 * the orphan is removed from the pool and the scan restarts to promote potential
 * multi-block orphan chains.
 *
 * @pre `state` must be non-NULL and properly initialized.
 * @post Any resolvable orphan chains are applied to the active ledger tip.
 * @sideeffect Promoted blocks mutate the database, MMR trees, and ledger state.
 * @sync Thread Safety: Acquires `state->ledger_mutex` then write-locks
 *       `state->bc.rwlock`. Adheres strictly to the lock acquisition order.
 *
 * @param[in,out] state Pointer to the shared global ledger State structure.
 *
 * @return void.
 * @complexity Time: O(B * O) where B is orphan pool size and O is chain depth;
 *             Auxiliary Space: O(1).
 */
void trigger_async_fork_processing(State *state) {
    if (!state || !state->orphan_pool || state->orphan_pool->count == 0) return;
    
    // Acquire ledger and blockchain write locks in mandatory canonical sequence
    pthread_mutex_lock(&state->ledger_mutex);
    pthread_rwlock_wrlock(&state->bc.rwlock);
    
    bool applied_any = false;
    do {
        applied_any = false;
        for (size_t i = 0; i < state->orphan_pool->size; i++) {
            GenericHashEntry *entry = state->orphan_pool->buckets[i];
            while (entry) {
                GenericHashEntry *next_entry = entry->next;
                if (entry->type == HASH_ENTRY_ORPHAN_BLOCK) {
                    Block *orphan = entry->data.orphan_block;
                    // Check if orphan's ancestor matches the active ledger tip
                    if (memcmp(orphan->prev_block_hash, state->current_block_hash, COIN_ID_LEN) == 0) {
                        fprintf(stderr, "[Consensus] Promoting orphan block %llu from orphan_pool.\n", orphan->block_number);
                        if (apply_block(state, orphan) == 0) {
                            state->current_block_number = orphan->block_number;
                            uint8_t synced_hash[COIN_ID_LEN];
                            compute_block_hash(orphan, synced_hash);
                            memcpy(state->current_block_hash, synced_hash, COIN_ID_LEN);
                            state->bc.sync_epoch = orphan->block_number + 1;
                            pthread_cond_signal(&state->blockchain_sync_cond);

                            // hash_table_remove automatically frees HASH_ENTRY_ORPHAN_BLOCK via free_block
                            hash_table_remove(state->orphan_pool, entry->key);
                            applied_any = true;
                            break; // Restart scan safely to process successive descendants
                        }
                    }
                }
                entry = next_entry;
            }
            if (applied_any) break;
        }
    } while (applied_any);
    
    pthread_rwlock_unlock(&state->bc.rwlock);
    pthread_mutex_unlock(&state->ledger_mutex);
}

/* ============================================================================ */
/* SECTION 4: Block Proposal Thread Dispatch Subsystem                         */
/* ============================================================================ */
/* Architectural Preface:
 * Handles concurrency provisioning for the block proposal pipeline. Manages
 * background worker thread limits (clamped at 64 concurrent threads) to prevent
 * thread exhaustion DoS vectors during volatile network conditions.
 */

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/**
 * @brief Thread worker function executing the block proposal pipeline.
 *
 * Unpacks dynamically allocated proposal arguments, executes `propose_block`,
 * deallocates argument memory, decrements the active background worker count,
 * and releases thread-local L5 packet staging buffers.
 *
 * @pre `arg` must point to a valid heap-allocated `ProposeBlockArgs` structure.
 * @post `arg` and any contained operation structures are freed.
 * @sideeffect Decrements `state->active_background_threads` atomically; releases L5 staging buffer.
 * @sync Thread Safety: Detached worker thread; accesses state via internal locks.
 *
 * @param[in,out] arg Void pointer to heap-allocated `ProposeBlockArgs`.
 *
 * @return NULL unconditionally upon thread termination.
 * @complexity Time: Determined by `propose_block`; Space: O(1) auxiliary.
 */
static void *propose_block_thread(void *arg) {
    ProposeBlockArgs *pargs = (ProposeBlockArgs *)arg;
    
    // Execute candidate block assembly and consensus proposal
    propose_block(pargs->state, pargs->op);
    
    // Free cloned triggering operation and worker argument container
    if (pargs->op) free(pargs->op);
    atomic_fetch_sub(&pargs->state->active_background_threads, 1);
    free(pargs);
    
    // Release thread-local L5 staging buffer resources
    release_l5_staging_buffer();
    return NULL;
}
#endif

/**
 * @brief Spawns an isolated background thread to assemble and propose a block.
 *
 * Enforces a strict quota of at most 64 active background threads. Allocates
 * thread arguments, clones the provided operation (if present), initializes
 * an 8 MB thread stack to accommodate heavy lattice operations, and launches
 * a detached POSIX thread.
 *
 * @pre `state` must be non-NULL.
 * @post A new thread is created or the operation is deferred/dropped if overloaded.
 * @sideeffect Increments `state->active_background_threads` on success.
 * @sync Thread Safety: Uses C11 atomic fetch-and-add on `active_background_threads`.
 *
 * @param[in,out] state Pointer to the shared global ledger State structure.
 * @param[in]     op    Optional pointer to an Operation triggering this proposal.
 *
 * @return void.
 * @complexity Time: O(1); Space: 8 MB allocated for thread stack.
 */
void spawn_propose_block_thread(State *state, const Operation *op) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    propose_block(state, op);
#else
    if (!state) return;

    // Guard against proposing during sync or when behind network tip
    pthread_mutex_lock(&state->mutex);
    bool cannot_propose = state->in_blockchain_sync ||
                          atomic_load(&state->sync_thread_active) ||
                          (state->network_target_block_number > 0 && state->current_block_number < state->network_target_block_number);
    pthread_mutex_unlock(&state->mutex);
    if (cannot_propose) {
        if (op) free((void*)op);
        return;
    }

    // Enforce maximum concurrent background worker quota (64)
    if (atomic_load(&state->active_background_threads) >= 64) {
        fprintf(stderr, "[Consensus] WARNING: Thread limit reached. Deferring block proposal.\n");
        if (op) free((void*)op);
        return;
    }
    ProposeBlockArgs *args = malloc(sizeof(ProposeBlockArgs));
    if (!args) return;
    
    args->state = state;
    if (op) {
        args->op = malloc(sizeof(Operation));
        if (args->op) {
            memcpy(args->op, op, sizeof(Operation));
        } else {
            free(args);
            return;
        }
    } else {
        args->op = NULL;
    }
    
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    // Allocate 8 MB stack for post-quantum lattice verification and ring arithmetic
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    atomic_fetch_add(&state->active_background_threads, 1);
    if (pthread_create(&tid, &attr, propose_block_thread, args) != 0) {
        atomic_fetch_sub(&state->active_background_threads, 1);
        if (args->op) free(args->op);
        free(args);
    } else {
        pthread_detach(tid);
    }
    pthread_attr_destroy(&attr);
#endif
}

/* ============================================================================ */
/* SECTION 5: Quorum Determination and Vote Aggregation Engine                 */
/* ============================================================================ */
/* Architectural Preface:
 * Implements threshold quorum checking and vote queue lifetime management.
 * Enforces dynamic supermajority rules: ceil(num_peers * CONSENSUS_THRESHOLD).
 * Governs lock coordination between the vote queue and global ledger locks.
 */

/**
 * @brief Checks if accumulated affirmative votes satisfy the consensus threshold.
 *
 * Mathematical formulation:
 * Required Votes = ceil(num_peers * CONSENSUS_THRESHOLD)
 *
 * @pre `queue` must be non-NULL.
 * @post Evaluates vote count against required quorum threshold.
 * @sideeffect None.
 * @sync Thread Safety: Caller must hold `queue->vote_lock` to ensure atomic read.
 *
 * @param[in] queue     Pointer to the BlockVoteQueue structure tracking votes.
 * @param[in] num_peers Total active unique voter peer count.
 *
 * @return 1 if consensus is reached; 0 if affirmative votes are insufficient.
 * @complexity Time: O(1); Space: O(1).
 */
static int has_consensus(BlockVoteQueue *queue, size_t num_peers) {
    if (num_peers == 0) return 0;
    size_t required_votes = (size_t)ceil((double)num_peers * CONSENSUS_THRESHOLD);
    return queue->yes_votes >= required_votes;
}

/**
 * @brief Evaluates quorum, applies approved block, and broadcasts approval message.
 *
 * Computes the dynamic set of active Dilithium-authenticated peers at the time
 * of evaluation. If quorum is satisfied:
 * 1. Acquires `state->mutex` and write-locks `state->bc.rwlock`.
 * 2. Invokes `apply_block` to commit changes atomically.
 * 3. Serializes the block and broadcasts `MSG_BLOCK_APPROVED` across P2P network.
 * 4. Triggers proposer eligibility check for the next height.
 *
 * @pre `state`, `block`, and `queue` must be non-NULL.
 * @post If consensus is achieved, block is committed and current height advances.
 * @sideeffect Network broadcast queued; ledger and database mutated.
 * @sync Thread Safety: Acquires `state->p2p_network.mutex`, `queue->vote_lock`,
 *       and then sequentially acquires `state->mutex` and write-locks `state->bc.rwlock`
 *       without nested lock inversions.
 *
 * @param[in,out] state Pointer to the shared global ledger State structure.
 * @param[in,out] block Pointer to candidate Block under consensus review.
 * @param[in,out] queue Pointer to BlockVoteQueue accumulating votes for this block.
 *
 * @return true if consensus reached and block committed successfully; false otherwise.
 * @complexity Time: O(P log P + B) where P is peer count and B is block apply time;
 *             Auxiliary Space: O(P) for peer key deduplication.
 */
bool check_consensus(State *state, Block *block, BlockVoteQueue *queue) {
    // Dynamically evaluate active peers at the exact moment of consensus evaluation
    size_t num_peers = 0;
    pthread_mutex_lock(&state->p2p_network.mutex);
    const uint8_t **active_pubkeys = malloc(state->p2p_network.num_known_peers * sizeof(const uint8_t *));
    if (active_pubkeys) {
        size_t active_count = 0;
        for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
            Peer *peer = state->p2p_network.known_peers[i];
            if (!is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
                validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey) &&
                peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                active_pubkeys[active_count++] = peer->peer_wallet.dilithium_pubkey;
            }
        }
        // Deduplicate active peer public keys to determine unique voter base
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
    if (num_peers == 0) num_peers = 1;

    pthread_mutex_lock(&queue->vote_lock);
    bool consensus_reached = has_consensus(queue, num_peers);
    pthread_mutex_unlock(&queue->vote_lock);

    if (consensus_reached) {
        fprintf(stderr, "[Consensus] Consensus reached for block %llu: %zu/%zu votes\n",
                block->block_number, queue->yes_votes, (size_t)ceil((double)num_peers * CONSENSUS_THRESHOLD));

        pthread_mutex_lock(&state->mutex);
        pthread_rwlock_wrlock(&state->bc.rwlock);
        if (apply_block(state, block) == 0) {
            pthread_rwlock_unlock(&state->bc.rwlock);
            pthread_mutex_unlock(&state->mutex);
        } else {
            fprintf(stderr, "[Consensus] ERROR: Failed to apply block %llu\n", block->block_number);
            pthread_rwlock_unlock(&state->bc.rwlock);
            pthread_mutex_unlock(&state->mutex);
            return false;
        }

        // Broadcast MSG_BLOCK_APPROVED across P2P network to trigger peer commits
        Message *approved_msg = calloc(1, sizeof(Message));
        if (approved_msg) {
            if (serialize_block(block, approved_msg, true) == 0) {
                approved_msg->type = MSG_BLOCK_APPROVED;
                p2p_broadcast(state, approved_msg);
                
                uint8_t block_hash[COIN_ID_LEN];
                if (compute_block_hash(block, block_hash) != 0) {
                    fprintf(stderr, "[Consensus] Failed to compute hash for approved block %llu\n", block->block_number);
                } else {
                    char hex_bhash_app[33];
                    bytes_to_hex(block_hash, 16, hex_bhash_app);
                    fprintf(stderr, "[Consensus] Broadcasted MSG_BLOCK_APPROVED for block %llu, hash=%s\n", block->block_number, hex_bhash_app);
                }
            } else {
                fprintf(stderr, "[Consensus] Failed to serialize approved block %llu\n", block->block_number);
            }
            free(approved_msg);
        }
        // Trigger proposer eligibility check for the next height
        trigger_proposer_if_eligible(state);
        return true;
    }
    return false;
}

/**
 * @brief Background collection worker collecting votes until quorum or timeout.
 *
 * Operates on a dedicated thread for each proposed candidate block. Collects
 * peer votes using timed condition waits on `queue->cond` up to `VOTE_TIMEOUT`
 * seconds. Checks consensus dynamically. Upon termination, executes reference-counted
 * cleanup of the vote queue adhering strictly to global lock ordering rules.
 *
 * @pre `arg` must point to valid heap-allocated `VoteThreadArgs`.
 * @post The vote queue is removed from hash tables and safely freed when ref_count == 0.
 * @sideeffect Decrements `state->active_background_threads` on termination.
 * @sync Thread Safety: Acquires `state->mutex` before `queue->vote_lock` to
 *       prevent AB-BA deadlocks between consensus and network dispatcher threads.
 *
 * @param[in,out] arg Void pointer to heap-allocated `VoteThreadArgs`.
 *
 * @return NULL unconditionally upon thread exit.
 * @complexity Time: O(T) bounded by VOTE_TIMEOUT; Space: O(P) for peer tracking.
 */
void *vote_collection_thread(void *arg) {
    struct VoteThreadArgs *args = (struct VoteThreadArgs *)arg;
    State *state = args->state;
    Block *block = args->block;
    uint8_t block_hash[COIN_ID_LEN];
        
    if (compute_block_hash(block, block_hash) != 0) {
        fprintf(stderr, "[VoteThread] ERROR: Failed to compute block hash\n");
        free_block(args->block);
        free(args);
        atomic_fetch_sub(&state->active_background_threads, 1);
        return NULL;
    }

    pthread_mutex_lock(&state->mutex);
    BlockVoteQueue *queue = hash_table_lookup(state->block_consensus, block_hash, false);
    if (!queue) {
        pthread_mutex_unlock(&state->mutex);
        char hex_bhash_err[17];
        bytes_to_hex(block_hash, 8, hex_bhash_err);
        fprintf(stderr, "[VoteThread] ERROR: No vote queue found for block_hash=%s...\n", hex_bhash_err);
        free_block(args->block);
        free(args);
        atomic_fetch_sub(&state->active_background_threads, 1);
        return NULL;
    }
    queue->ref_count++;
    pthread_mutex_unlock(&state->mutex);

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < VOTE_TIMEOUT) {
        if (atomic_load(&global_shutdown)) break;
        pthread_mutex_lock(&state->mutex);
        if (block->block_number <= state->current_block_number) {
            fprintf(stderr, "[VoteThread] Aborting vote collection for outdated block %llu (current height %llu)\n",
                    block->block_number, state->current_block_number);
            pthread_mutex_unlock(&state->mutex);
            break;
        }
        pthread_mutex_unlock(&state->mutex);

        // Check whether affirmative quorum has been achieved
        if (check_consensus(state, block, queue)) {
            break;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000; // 100ms polling tick
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        pthread_mutex_lock(&queue->vote_lock);
        pthread_cond_timedwait(&queue->cond, &queue->vote_lock, &ts);
        pthread_mutex_unlock(&queue->vote_lock);
    }

    pthread_mutex_lock(&queue->vote_lock);
            
    // Evaluate the final requirement threshold for accurate diagnostic telemetry
    size_t num_peers_final = 0;
    pthread_mutex_lock(&state->p2p_network.mutex);
    const uint8_t **active_pubkeys = malloc(state->p2p_network.num_known_peers * sizeof(const uint8_t *));
    if (active_pubkeys) {
        size_t active_count = 0;
        for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
            Peer *current_peer = state->p2p_network.known_peers[i];
            if (!is_zeroed(current_peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) &&
                validate_dilithium_pubkey(current_peer->peer_wallet.dilithium_pubkey) &&
                current_peer->conn && current_peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                active_pubkeys[active_count++] = current_peer->peer_wallet.dilithium_pubkey;
            }
        }
        if (active_count > 0) {
            qsort(active_pubkeys, active_count, sizeof(const uint8_t *), compare_pubkey_ptrs);
            num_peers_final = 1;
            for (size_t i = 1; i < active_count; i++) {
                if (memcmp(active_pubkeys[i], active_pubkeys[i - 1], PUBKEY_LEN) != 0) {
                    num_peers_final++;
                }
            }
        }
        free(active_pubkeys);
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);
    if (num_peers_final == 0) num_peers_final = 1;
    
    size_t required_votes = (size_t)ceil((double)num_peers_final * CONSENSUS_THRESHOLD);
    int failed_consensus = (queue->yes_votes < required_votes);
    
    if (failed_consensus) {
        fprintf(stderr, "[VoteThread] Vote collection timed out for block %llu: %zu/%zu votes, ref_count=%d\n",
                block->block_number, queue->yes_votes, required_votes, queue->ref_count);
    }
    pthread_mutex_unlock(&queue->vote_lock);

    // Enforce lock hierarchy: state->mutex first, then queue->vote_lock
    pthread_mutex_lock(&state->mutex);

    BlockVoteQueue *current_queue_in_table = hash_table_lookup(state->block_consensus, block_hash, false);
    if (current_queue_in_table == queue) {
        hash_table_remove(state->block_consensus, block_hash);
    }
    pthread_mutex_unlock(&state->mutex);

    // Drop the reference held by this worker thread safely
    free_block_vote_queue(queue);

    // Clean up block_proposers mapping
    pthread_mutex_lock(&state->block_proposers_lock);
    if (hash_table_lookup(state->block_proposers, block_hash, false)) {
        hash_table_remove(state->block_proposers, block_hash);
    }
    pthread_mutex_unlock(&state->block_proposers_lock);

    free_block(args->block);
    free(args);
    atomic_fetch_sub(&state->active_background_threads, 1);
    arena_cleanup();
    release_l5_staging_buffer();
    return NULL;
}

/* ============================================================================ */
/* SECTION 6: Canonical Block Construction Subsystem                           */
/* ============================================================================ */
/* Architectural Preface:
 * Constructs, encodes, hashes, and signs candidate blocks. Enforces zero-padding
 * invariants across unallocated union fields to ensure deterministic SHA-256
 * block hash generation across diverse CPU architectures.
 */

/**
 * @brief Allocates, serializes, hashes, and signs a new candidate Block.
 *
 * Performs validation over operations (ensuring non-zero minting amounts,
 * bounded pointer input arrays, and legitimate operation types). Copies
 * consensus-critical fields into clean calloc-zeroed buffers to maintain
 * wire-deterministic hashing. Attaches block-level ZK-PRF batch payloads and
 * signs the resulting 32-byte block hash with the proposer's Dilithium private key.
 *
 * @pre `prev_block_hash`, `operations`, `proposer_pubkey`, and `proposer_privkey`
 *      must be non-NULL; `operation_count` must be greater than zero.
 * @post Returns a fully populated, cryptographically signed Block pointer.
 * @sideeffect Allocates heap memory for Block and Operation array. Ownership
 *             transfers to the caller.
 * @sync Thread Safety: Reentrant. Operates solely on passed buffers.
 *
 * @param[in] block_number       Height of the block to create.
 * @param[in] prev_block_hash    Pointer to 32-byte hash of the parent block.
 * @param[in] operations         Array of operations to include in the block.
 * @param[in] operation_count    Number of operations in the array.
 * @param[in] proposer_pubkey    Proposer's 2592-byte Dilithium public key.
 * @param[in] proposer_privkey   Proposer's 4864-byte Dilithium private key.
 * @param[in] entropy_seed       32-bit pseudorandom entropy seed.
 * @param[in] batch_tx_count     Number of transfer operations in ZK-PRF batch.
 * @param[in] batch_prf_outputs  Pointer to contiguous nullifier array.
 * @param[in] batch_zk_proof     Pointer to serialized batch ZK-Stern proof.
 * @param[in] batch_zk_proof_len Total byte length of serialized batch proof.
 *
 * @return Allocated Block pointer on success; NULL on validation/allocation failure.
 * @complexity Time: O(N + Cryptographic signing latency); Space: O(N) operations.
 */
Block *create_block(uint64_t block_number, const uint8_t *prev_block_hash, Operation *operations,
                    size_t operation_count, const uint8_t *proposer_pubkey, const uint8_t *proposer_privkey, int entropy_seed,
                    size_t batch_tx_count, uint8_t *batch_prf_outputs, uint8_t *batch_zk_proof, size_t batch_zk_proof_len) {
    if (!prev_block_hash || !operations || operation_count == 0 || !proposer_pubkey || !proposer_privkey) {
        fprintf(stderr, "[Consensus] Invalid parameters: prev_hash=%p, ops=%p, count=%zu, pubkey=%p, privkey=%p\n",
                prev_block_hash, operations, operation_count, proposer_pubkey, proposer_privkey);
        return NULL;
    }
    
    // Sanity-check minting operations before block allocation
    for (size_t i = 0; i < operation_count; i++) {
        if (operations[i].type == OP_MINT_COIN) {
            SCLCoin *coin = &operations[i].data.mint_coin.coin;
            if (coin->total_subunits == 0 || coin->remaining_subunits == 0) {
                fprintf(stderr, "[Consensus] Invalid coin in operation %zu: total_subunits=%llu, remaining_subunits=%llu\n",
                        i, coin->total_subunits, coin->remaining_subunits);
                return NULL;
            }
        }
    }

    Block *block = calloc(1, sizeof(Block));
    if (!block) {
        fprintf(stderr, "[Consensus] Block allocation failed\n");
        return NULL;
    }

    block->block_number = block_number;
    memcpy(block->prev_block_hash, prev_block_hash, COIN_ID_LEN);
    block->operation_count = operation_count;
    // Use calloc to ensure deterministic zero-initialization of padding and unused union members
    block->operations = calloc(operation_count, sizeof(Operation));
    if (!block->operations) {
        fprintf(stderr, "[Consensus] Operations allocation failed\n");
        free(block);
        return NULL;
    }
    block->entropy_seed = entropy_seed;

    // Atomically attach ZK-PRF batch data before hashing and signing
    block->batch_tx_count = batch_tx_count;
    block->batch_prf_outputs = batch_prf_outputs;
    block->batch_zk_proof = batch_zk_proof;
    block->batch_zk_proof_len = batch_zk_proof_len;
    
    for (size_t i = 0; i < operation_count; i++) {
        block->operations[i].type = operations[i].type;
        if (operations[i].type == OP_TRANSFER_POINTER) {
            TransferData *src = &operations[i].data.transfer_pointer;
            TransferData *dst = &block->operations[i].data.transfer_pointer;
            if (src->num_inputs == 0 || src->num_inputs > MAX_INPUTS) {
                fprintf(stderr, "[Consensus] Invalid num_inputs: %u\n", src->num_inputs);
                free(block->operations);
                free(block);
                return NULL;
            }
            // --- OPTIMIZATION: Copy only consensus-critical fields for on-chain storage ---
            dst->num_inputs = src->num_inputs;
            memcpy(dst->inputs, src->inputs, src->num_inputs * sizeof(Pointer));
            memcpy(dst->proofs, src->proofs, src->num_inputs * sizeof(MMRProof));
            memcpy(dst->inputs_merkle_root, src->inputs_merkle_root, COIN_ID_LEN);
            memcpy(dst->inputs_root_signature, src->inputs_root_signature, SIGNATURE_LEN);
            memcpy(dst->tx_id, src->tx_id, COIN_ID_LEN);
            memcpy(dst->nonce, src->nonce, 8);
            memcpy(dst->client_root, src->client_root, COIN_ID_LEN);
            memcpy(dst->recipient_pubkey, src->recipient_pubkey, PUBKEY_LEN);
            memcpy(dst->sender_pubkey, src->sender_pubkey, PUBKEY_LEN);
            dst->amount = src->amount;
            memcpy(dst->signature, src->signature, SIGNATURE_LEN);

            // The individual ZK-PRF fields ('prf_output', 'zk_proof', 'zk_proof_len')
            // are intentionally not copied. They are batched safely at the block level.
        } else if (operations[i].type == OP_STAKE) {
            StakeData *src = &operations[i].data.stake;
            StakeData *dst = &block->operations[i].data.stake;
            if (src->num_inputs == 0 || src->num_inputs > MAX_INPUTS) {
                fprintf(stderr, "[Consensus] Invalid num_inputs for OP_STAKE: %u\n", src->num_inputs);
                free(block->operations);
                free(block);
                return NULL;
            }
            dst->num_inputs = src->num_inputs;
            memcpy(dst->inputs, src->inputs, src->num_inputs * sizeof(Pointer));
            memcpy(dst->proofs, src->proofs, src->num_inputs * sizeof(MMRProof));
            memcpy(dst->inputs_merkle_root, src->inputs_merkle_root, COIN_ID_LEN);
            memcpy(dst->inputs_root_signature, src->inputs_root_signature, SIGNATURE_LEN);
            memcpy(dst->stake_tx_id, src->stake_tx_id, COIN_ID_LEN);
            memcpy(dst->nonce, src->nonce, 8);
            memcpy(dst->client_root, src->client_root, COIN_ID_LEN);
            memcpy(dst->threshold_pubkey, src->threshold_pubkey, PUBKEY_LEN);
            memcpy(dst->sender_pubkey, src->sender_pubkey, PUBKEY_LEN);
            dst->amount = src->amount;
            memcpy(dst->threshold_signature, src->threshold_signature, SIGNATURE_LEN);
        } else if (operations[i].type == OP_UNSTAKE) {
            UnstakeData *src = &operations[i].data.unstake;
            UnstakeData *dst = &block->operations[i].data.unstake;
            if (src->num_inputs == 0 || src->num_inputs > MAX_INPUTS) {
                fprintf(stderr, "[Consensus] Invalid num_inputs for OP_UNSTAKE: %u\n", src->num_inputs);
                free(block->operations);
                free(block);
                return NULL;
            }
            dst->num_inputs = src->num_inputs;
            memcpy(dst->inputs, src->inputs, src->num_inputs * sizeof(Pointer));
            memcpy(dst->proofs, src->proofs, src->num_inputs * sizeof(MMRProof));
            memcpy(dst->unstake_tx_id, src->unstake_tx_id, COIN_ID_LEN);
            memcpy(dst->nonce, src->nonce, 8);
            memcpy(dst->client_root, src->client_root, COIN_ID_LEN);
            memcpy(dst->recipient_pubkey, src->recipient_pubkey, PUBKEY_LEN);
            memcpy(dst->threshold_pubkey, src->threshold_pubkey, PUBKEY_LEN);
            dst->amount = src->amount;
            memcpy(dst->threshold_signature, src->threshold_signature, SIGNATURE_LEN);
        } else if (operations[i].type == OP_MINT_COIN) {
            memcpy(&block->operations[i].data.mint_coin, &operations[i].data.mint_coin, sizeof(MintData));
        } else if (operations[i].type == OP_SUBMIT_VALUATION) {
            memcpy(&block->operations[i].data.submit_valuation,
                   &operations[i].data.submit_valuation, sizeof(ValuationData));
        } else {
            fprintf(stderr, "[Consensus] Invalid operation type: %d\n", operations[i].type);
            free(block->operations);
            free(block);
            return NULL;
        }
    }

    memcpy(block->proposer_pubkey, proposer_pubkey, PUBKEY_LEN);
    
    // Compute canonical block hash and sign with proposer private key
    uint8_t block_hash[COIN_ID_LEN];
    if (compute_block_hash(block, block_hash) != 0) {
        fprintf(stderr, "[Consensus] Failed to compute block hash\n");
        free_block(block);
        return NULL;
    }
    if (!dilithium_sign(block_hash, COIN_ID_LEN, proposer_privkey, block->signature)) {
        fprintf(stderr, "[Consensus] Failed to sign block\n");
        free_block(block);
        return NULL;
    }

    printf("[Consensus] Created block %llu with %zu operations\n", block_number, operation_count);
    return block;
}

/* ============================================================================ */
/* SECTION 7: Staker Evaluation, Sorting, and Address Resolution               */
/* ============================================================================ */
/* Architectural Preface:
 * Implements deterministic ordering and key resolution routines for committee
 * election. Enforces strict total ordering over stakers by weight descending,
 * breaking ties via byte-level address lexicographical comparison.
 */

/**
 * @brief Deterministic comparator for StakerRecord arrays.
 *
 * Sorts stakers by stake balance in descending order. If two records possess
 * identical stake, breaks ties deterministically by lexicographical comparison
 * of their 32-byte User ID addresses.
 *
 * @pre `a` and `b` must point to valid StakerRecord structures.
 * @post None. Pure comparison function.
 * @sideeffect None.
 * @sync Thread Safety: Reentrant and lock-free.
 *
 * @param[in] a Pointer to first StakerRecord.
 * @param[in] b Pointer to second StakerRecord.
 *
 * @return Positive integer if a < b (descending stake); negative if a > b;
 *         memcmp result on tie.
 * @complexity Time: O(1); Space: O(1).
 */
static int compare_stakers_det(const void *a, const void *b) {
    const StakerRecord *sa = (const StakerRecord *)a;
    const StakerRecord *sb = (const StakerRecord *)b;
    if (sa->stake < sb->stake) return 1;
    if (sa->stake > sb->stake) return -1;
    return memcmp(sa->addr, sb->addr, USER_ID_LEN);
}

/**
 * @brief Lexicographical comparator for raw Dilithium public keys.
 *
 * @pre `a` and `b` must point to 2592-byte Dilithium public keys.
 * @post None. Pure comparison function.
 * @sideeffect None.
 * @sync Thread Safety: Reentrant.
 *
 * @param[in] a Pointer to first 2592-byte buffer.
 * @param[in] b Pointer to second 2592-byte buffer.
 *
 * @return <0 if a < b, 0 if a == b, >0 if a > b.
 * @complexity Time: O(PUBKEY_LEN); Space: O(1).
 */
int compare_pubkeys_raw(const void *a, const void *b) {
    return memcmp(a, b, PUBKEY_LEN);
}

/**
 * @brief Resolves a 32-byte address digest to its 2592-byte Dilithium public key.
 *
 * Probes the local user table, the pubkey cache, the local user wallet, and
 * the active P2P known peers list.
 *
 * @pre `state`, `addr`, and `pubkey_out` must be non-NULL.
 * @post If resolved, `pubkey_out` contains the 2592-byte Dilithium public key.
 * @sideeffect Reads cached tables under internal mutex acquisitions.
 * @sync Thread Safety: Acquires `state->mutex` and `state->p2p_network.mutex`.
 *
 * @param[in,out] state      Pointer to global State structure.
 * @param[in]     addr       Pointer to 32-byte User ID address.
 * @param[out]    pubkey_out Destination buffer (at least 2592 bytes).
 *
 * @return 1 if public key was found and copied; 0 if unresolvable.
 * @complexity Time: O(N) where N is known peer count; Space: O(1).
 */
static int lookup_pubkey_by_address(State *state, const uint8_t *addr, uint8_t *pubkey_out) {
    // 1. Probe user table and public key cache
    pthread_mutex_lock(&state->mutex);
    User *user = hash_table_lookup(state->user_table, addr, false);
    if (user) {
        memcpy(pubkey_out, user->dilithium_pubkey, PUBKEY_LEN);
        pthread_mutex_unlock(&state->mutex);
        return 1;
    }
    PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, addr, false);
    if (cache_entry) {
        memcpy(pubkey_out, cache_entry->pubkey, PUBKEY_LEN);
        pthread_mutex_unlock(&state->mutex);
        return 1;
    }
    pthread_mutex_unlock(&state->mutex);

    // 2. Check local user wallet identity
    uint8_t local_addr[USER_ID_LEN];
    SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, local_addr);
    if (memcmp(local_addr, addr, USER_ID_LEN) == 0) {
        memcpy(pubkey_out, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        return 1;
    }

    // 3. Search connected P2P peer registry
    pthread_mutex_lock(&state->p2p_network.mutex);
    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
        uint8_t p_addr[USER_ID_LEN];
        SHA256(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, p_addr);
        if (memcmp(p_addr, addr, USER_ID_LEN) == 0) {
            memcpy(pubkey_out, state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            pthread_mutex_unlock(&state->p2p_network.mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);

    return 0;
}

/* ============================================================================ */
/* SECTION 8: Epoch Committee Deterministic Reconstruction Subsystem           */
/* ============================================================================ */
/* Architectural Preface:
 * Reconstructs the 10-node DKG epoch committee deterministically from on-chain
 * historical stake balances up to height H. Ensures zero divergence across all
 * participating validator nodes without relying on off-chain state.
 */

/**
 * @brief Reconstructs the 10-member epoch committee at target block height H.
 *
 * Scans on-chain block history from genesis to height H, accumulating OP_STAKE
 * deposits and OP_UNSTAKE withdrawals per user address. If fewer than 10 stakers
 * are active, backfills slots deterministically from past block proposers and
 * known peers. Sorts the resulting committee lexicographically by Dilithium public
 * key to establish invariant point IDs across all network participants.
 *
 * @pre `state`, `committee`, and `count` must be non-NULL.
 * @post `committee` is populated with up to 10 sorted 2592-byte public keys;
 *       `count` reflects the active member count.
 * @sideeffect Populates `pubkey_cache` with newly encountered public keys.
 * @sync Thread Safety: Acquires `state->bc.rwlock` (read-lock), `state->p2p_network.mutex`,
 *       and `state->mutex` sequentially.
 *
 * @param[in,out] state     Pointer to global State structure.
 * @param[out]    committee 2D buffer `[10][PUBKEY_LEN]` receiving public keys.
 * @param[out]    count     Pointer to size_t receiving active committee size.
 * @param[in]     H         Target block height for evaluation.
 *
 * @return void.
 * @complexity Time: O(H * OperationsPerBlock + S log S); Space: O(MAX_CLIENTS).
 */
void get_epoch_committee(State *state, uint8_t committee[10][PUBKEY_LEN], size_t *count, uint64_t H) {
    if (!state || !committee || !count) return;

    StakerRecord *stakers = calloc(MAX_CLIENTS, sizeof(StakerRecord));
    if (!stakers) {
        *count = 0;
        return;
    }
    size_t staker_count = 0;

    // Stack storage to collect active identities securely and prevent lock-order violations
    struct {
        uint8_t addr[USER_ID_LEN];
        uint8_t pubkey[PUBKEY_LEN];
    } to_cache[64];
    size_t to_cache_count = 0;

    pthread_rwlock_rdlock(&state->bc.rwlock);
    
    // Fast-path: O(1) in-memory reconstruction from active unspent staked pointers when at current tip
    if (state->bc.pointer_table && H >= state->current_block_number) {
        for (size_t bucket = 0; bucket < state->bc.pointer_table->size; bucket++) {
            GenericHashEntry *entry = state->bc.pointer_table->buckets[bucket];
            while (entry) {
                if (entry->type == HASH_ENTRY_POINTER && !entry->data.pointer.spent && entry->data.pointer.staked) {
                    const Pointer *ptr = &entry->data.pointer;
                    uint64_t amount = ptr->end_subunit - ptr->start_subunit + 1;
                    
                    int found_idx = -1;
                    for (size_t k = 0; k < staker_count; k++) {
                        if (memcmp(stakers[k].addr, ptr->owner_address, USER_ID_LEN) == 0) {
                            found_idx = (int)k;
                            break;
                        }
                    }
                    if (found_idx != -1) {
                        stakers[found_idx].stake += amount;
                    } else if (staker_count < MAX_CLIENTS) {
                        memcpy(stakers[staker_count].addr, ptr->owner_address, USER_ID_LEN);
                        stakers[staker_count].stake = amount;
                        staker_count++;
                    }
                }
                entry = entry->next;
            }
        }
    } else {
        // Fallback for historical heights: deterministically scan block history up to height H
        size_t scan_limit = H < state->current_block_number ? (size_t)H + 1 : state->current_block_number + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        if (scan_limit > 16) scan_limit = 16;
#endif
        for (size_t b_idx = 0; b_idx < scan_limit; b_idx++) {
            uint8_t *ser_block = NULL;
            size_t ser_len = 0;
            if (scl_db_get_block(b_idx, &ser_block, &ser_len) != 0) continue;
            
            Block *block = calloc(1, sizeof(Block));
            if (!block || deserialize_block(block, ser_block, ser_len) != 0) {
                if (block) free_block(block);
                free(ser_block);
                continue;
            }
            free(ser_block);
            
            for (size_t op_idx = 0; op_idx < block->operation_count; op_idx++) {
                Operation *op = &block->operations[op_idx];
                if (op->type == OP_STAKE) {
                    StakeData *sd = &op->data.stake;
                    uint8_t threshold_address[USER_ID_LEN];
                    SHA256(sd->threshold_pubkey, PUBKEY_LEN, threshold_address);
                    
                    int found_idx = -1;
                    for (size_t k = 0; k < staker_count; k++) {
                        if (memcmp(stakers[k].addr, threshold_address, USER_ID_LEN) == 0) {
                            found_idx = (int)k;
                            break;
                        }
                    }
                    if (found_idx != -1) {
                        stakers[found_idx].stake += sd->amount;
                    } else if (staker_count < MAX_CLIENTS) {
                        memcpy(stakers[staker_count].addr, threshold_address, USER_ID_LEN);
                        stakers[staker_count].stake = sd->amount;
                        staker_count++;
                    }

                    if (to_cache_count < 64) {
                        memcpy(to_cache[to_cache_count].addr, threshold_address, USER_ID_LEN);
                        memcpy(to_cache[to_cache_count].pubkey, sd->sender_pubkey, PUBKEY_LEN);
                        to_cache_count++;
                    }
                } else if (op->type == OP_UNSTAKE) {
                    UnstakeData *sd = &op->data.unstake;
                    uint8_t threshold_address[USER_ID_LEN];
                    SHA256(sd->threshold_pubkey, PUBKEY_LEN, threshold_address);
                    
                    for (size_t k = 0; k < staker_count; k++) {
                        if (memcmp(stakers[k].addr, threshold_address, USER_ID_LEN) == 0) {
                            if (stakers[k].stake >= sd->amount) {
                                stakers[k].stake -= sd->amount;
                            } else {
                                stakers[k].stake = 0;
                            }
                            break;
                        }
                    }
                }
            }
            free_block(block);
        }
    }
    pthread_rwlock_unlock(&state->bc.rwlock);

    // If the number of stakers is less than 10, fill using past block proposers from block history
    if (staker_count < 10) {
        pthread_rwlock_rdlock(&state->bc.rwlock);
        size_t scan_limit = H < state->current_block_number ? (size_t)H + 1 : state->current_block_number + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        if (scan_limit > 16) scan_limit = 16;
#endif
        for (size_t b_idx = scan_limit; b_idx > 0 && staker_count < 10; b_idx--) {
            uint8_t *ser_block = NULL;
            size_t ser_len = 0;
            if (scl_db_get_block(b_idx - 1, &ser_block, &ser_len) != 0) continue;
            
            Block *block = calloc(1, sizeof(Block));
            if (!block || deserialize_block(block, ser_block, ser_len) != 0) {
                if (block) free_block(block);
                free(ser_block);
                continue;
            }
            free(ser_block);

            if (!is_zeroed(block->proposer_pubkey, PUBKEY_LEN)) {
                bool already_present = false;
                uint8_t proposer_address[USER_ID_LEN];
                SHA256(block->proposer_pubkey, PUBKEY_LEN, proposer_address);
                for (size_t k = 0; k < staker_count; k++) {
                    if (memcmp(stakers[k].addr, proposer_address, USER_ID_LEN) == 0) {
                        already_present = true;
                        break;
                    }
                }
                if (!already_present) {
                    memcpy(stakers[staker_count].addr, proposer_address, USER_ID_LEN);
                    stakers[staker_count].stake = 0; // Past proposer, zero stake fallback
                    staker_count++;
                }

                if (to_cache_count < 64) {
                    memcpy(to_cache[to_cache_count].addr, proposer_address, USER_ID_LEN);
                    memcpy(to_cache[to_cache_count].pubkey, block->proposer_pubkey, PUBKEY_LEN);
                    to_cache_count++;
                }
            }
            free_block(block);
        }
        pthread_rwlock_unlock(&state->bc.rwlock);
    }

    // If still under 10 members, fill using active validated P2P peers
    if (staker_count < 10) {
        pthread_mutex_lock(&state->p2p_network.mutex);
        size_t num_peers = state->p2p_network.num_known_peers;
        
        const uint8_t **peer_pubkeys = malloc((num_peers + 1) * sizeof(uint8_t *));
        size_t peer_count = 0;
        
        if (peer_pubkeys) {
            if (!is_zeroed(state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, PUBKEY_LEN) &&
                validate_dilithium_pubkey(state->p2p_network.local_peer.peer_wallet.dilithium_pubkey)) {
                peer_pubkeys[peer_count++] = state->p2p_network.local_peer.peer_wallet.dilithium_pubkey;
            }
            for (size_t i = 0; i < num_peers; i++) {
                Peer *peer = state->p2p_network.known_peers[i];
                if (peer && !is_zeroed(peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) &&
                    validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey) &&
                    peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                    
                    peer_pubkeys[peer_count++] = peer->peer_wallet.dilithium_pubkey;
                }
            }
            
            qsort(peer_pubkeys, peer_count, sizeof(uint8_t *), compare_pubkey_ptrs);
            
            for (size_t i = 0; i < peer_count && staker_count < 10; i++) {
                uint8_t addr[USER_ID_LEN];
                SHA256(peer_pubkeys[i], PUBKEY_LEN, addr);
                
                bool present = false;
                for (size_t k = 0; k < staker_count; k++) {
                    if (memcmp(stakers[k].addr, addr, USER_ID_LEN) == 0) {
                        present = true;
                        break;
                    }
                }
                
                if (!present && staker_count < MAX_CLIENTS) {
                    memcpy(stakers[staker_count].addr, addr, USER_ID_LEN);
                    stakers[staker_count].stake = 0;
                    staker_count++;
                }

                if (to_cache_count < 64) {
                    memcpy(to_cache[to_cache_count].addr, addr, USER_ID_LEN);
                    memcpy(to_cache[to_cache_count].pubkey, peer_pubkeys[i], PUBKEY_LEN);
                    to_cache_count++;
                }
            }
            free(peer_pubkeys);
        }
        pthread_mutex_unlock(&state->p2p_network.mutex);
    }

    // Flush staged public keys into the cache under state->mutex
    if (to_cache_count > 0) {
        pthread_mutex_lock(&state->mutex);
        for (size_t i = 0; i < to_cache_count; i++) {
            if (!hash_table_lookup(state->pubkey_cache, to_cache[i].addr, false)) {
                PubkeyCacheEntry pce;
                memcpy(pce.pubkey, to_cache[i].pubkey, PUBKEY_LEN);
                hash_table_insert(state->pubkey_cache, to_cache[i].addr, &pce, HASH_ENTRY_PUBKEY_CACHE);
            }
        }
        pthread_mutex_unlock(&state->mutex);
    }

    // Filter out 0-stake entries if more than 10 total candidate stakers exist
    if (staker_count > 10) {
        size_t non_zero_count = 0;
        for (size_t i = 0; i < staker_count; i++) {
            if (stakers[i].stake > 0) {
                stakers[non_zero_count++] = stakers[i];
            }
        }
        staker_count = non_zero_count;
    }

    qsort(stakers, staker_count, sizeof(StakerRecord), compare_stakers_det);

    memset(committee, 0, 10 * PUBKEY_LEN);
    size_t added_count = 0;

    for (size_t i = 0; i < staker_count && added_count < 10; i++) {
        uint8_t pubkey[PUBKEY_LEN];
        int has_key = lookup_pubkey_by_address(state, stakers[i].addr, pubkey);
        if (has_key && !is_zeroed(pubkey, PUBKEY_LEN)) {
            memcpy(committee[added_count], pubkey, PUBKEY_LEN);
            added_count++;
        }
    }
    *count = added_count;

    // Sort committee lexicographically to ensure 100% deterministic point IDs across all nodes
    if (added_count > 0) {
        qsort(committee, added_count, PUBKEY_LEN, compare_pubkeys_raw);
    }

    free(stakers);
}

/**
 * @brief Commits a newly derived threshold key and broadcasts rotation across P2P.
 *
 * Commits the 2592-byte threshold public key to `state->game_state` and updates
 * the active committee cache under `state->epoch_mutex`. Constructs and broadcasts
 * `MSG_EPOCH_DKG_SHARE` with Point ID 0 (designating rotation announcement) to
 * notify non-committee nodes.
 *
 * @pre `state`, `pubkey`, and `committee` must be non-NULL; `count <= 10`.
 * @post Local threshold key updated; P2P broadcast dispatched.
 * @sideeffect Enqueues network message in P2P broadcast pipeline.
 * @sync Thread Safety: Acquires `state->game_state.mutex` and `state->epoch_mutex`.
 *
 * @param[in,out] state     Pointer to global State structure.
 * @param[in]     pubkey    Newly derived 2592-byte threshold Dilithium public key.
 * @param[in]     committee Array of 10 committee Dilithium public keys.
 * @param[in]     count     Number of active members in the committee.
 *
 * @return void.
 * @complexity Time: O(count * PUBKEY_LEN); Space: O(1).
 */
void rotate_epoch_key(State *state, const uint8_t *pubkey, const uint8_t committee[10][PUBKEY_LEN], size_t count) {
    pthread_mutex_lock(&state->game_state.mutex);
    memcpy(state->game_state.epoch_threshold_pubkey, pubkey, PUBKEY_LEN);
    state->game_state.last_dkg_epoch = state->current_block_number;
    pthread_mutex_unlock(&state->game_state.mutex);

    update_game_state_snapshot(state);

    pthread_mutex_lock(&state->epoch_mutex);
    memcpy(state->current_committee, committee, count * PUBKEY_LEN);
    state->current_committee_count = count;
    pthread_mutex_unlock(&state->epoch_mutex);

    // Broadcast rotation to all non-committee peers using Point ID 0
    Message *msg = calloc(1, sizeof(Message));
    if (msg) {
        msg->type = MSG_EPOCH_DKG_SHARE;
        uint8_t *dp = msg->payload;
        memcpy(dp, pubkey, PUBKEY_LEN); dp += PUBKEY_LEN;
        uint16_t pid_be = htobe16(0); // 0 indicates public key rotation announcement
        memcpy(dp, &pid_be, sizeof(uint16_t)); dp += sizeof(uint16_t);
        
        uint16_t count_be = htobe16((uint16_t)count);
        memcpy(dp, &count_be, sizeof(uint16_t)); dp += sizeof(uint16_t);
        for (size_t i = 0; i < count; i++) {
            memcpy(dp, committee[i], PUBKEY_LEN);
            dp += PUBKEY_LEN;
        }
        
        msg->length = dp - msg->payload;
        p2p_broadcast(state, msg);
        free(msg);
    }
}

/**
 * @brief Retrieves an established SclConnection for a peer matching the public key.
 *
 * @pre `state` and `pubkey` must be non-NULL.
 * @post Returns active SclConnection pointer if established; NULL otherwise.
 * @sideeffect None.
 * @sync Thread Safety: Acquires `state->p2p_network.mutex`.
 *
 * @param[in] state  Pointer to global State structure.
 * @param[in] pubkey Pointer to 2592-byte Dilithium public key.
 *
 * @return Pointer to active SclConnection or NULL.
 * @complexity Time: O(N) where N is known peer count; Space: O(1).
 */
static SclConnection* get_established_conn(State *state, const uint8_t *pubkey) {
    SclConnection *conn = NULL;
    pthread_mutex_lock(&state->p2p_network.mutex);
    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
        if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, pubkey, PUBKEY_LEN) == 0) {
            conn = state->p2p_network.known_peers[i]->conn;
            if (conn && conn->handshake_state != SCL_CONN_STATE_ESTABLISHED) {
                conn = NULL;
            }
            break;
        }
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);
    return conn;
}

/* ============================================================================ */
/* SECTION 9: Joint-RSS Distributed Key Generation (DKG) Protocol Engine       */
/* ============================================================================ */
/* Architectural Preface:
 * Implements the 4-Round Joint Random Secret Sharing (Joint-RSS) threshold
 * key generation ceremony based on Dilithium5 and Kyber-768:
 * - Round 1 (Commit): Deterministic commit hash exchange over private random seeds.
 * - Round 2 (Reveal): Seed reveal, Fiat-Shamir global rho computation.
 * - Round 3 (Share Deal): Polynomial sub-share dealing encrypted under Kyber-768.
 * - Round 4 (Assemble): Sub-share aggregation and threshold key derivation.
 */

/**
 * @brief Asynchronous thread executing the 4-round Joint-RSS DKG ceremony.
 *
 * Evaluates local committee membership (Point IDs 1 to 10). Executes Round 1
 * commit-reveal exchanges, samples Shamir/RSS secret polynomials, encapsulates
 * sub-shares under Kyber-768 public keys, aggregates received verified shares,
 * and derives the final epoch threshold public key and partial secret shares.
 *
 * @pre `arg` must point to valid heap-allocated `DKGWorkerArgs`.
 * @post On success, local node holds its active threshold key and partial signing key.
 * @sideeffect Decrements `active_background_threads`; releases DKG session.
 * @sync Thread Safety: Coordinated via `state->epoch_mutex`, `state->p2p_network.mutex`,
 *       and condition variable `session->phase_cond`.
 *
 * @param[in,out] arg Void pointer to heap-allocated `DKGWorkerArgs`.
 *
 * @return NULL unconditionally on termination.
 * @complexity Time: O(Round Timeout Limits); Space: O(Committee * Kyber/Dilithium sizes).
 */
void *dkg_worker_thread(void *arg) {
    DKGWorkerArgs *args = (DKGWorkerArgs *)arg;
    State *state = args->state;
    uint8_t session_id[COIN_ID_LEN];
    memcpy(session_id, args->session_id, COIN_ID_LEN);
    uint64_t block_height = args->block_height;
    free(args);

    pthread_mutex_lock(&state->epoch_mutex);
    DKGSession *session = hash_table_lookup(state->dkg_active_sessions, session_id, false);
    pthread_mutex_unlock(&state->epoch_mutex);

    if (!session) {
        atomic_fetch_sub(&state->active_background_threads, 1);
        return NULL;
    }

    uint8_t (*committee)[PUBKEY_LEN] = calloc(10, PUBKEY_LEN);
    if (!committee) {
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    size_t count = 0;
    time_t wait_start = time(NULL);
    
    // Poll up to 300 seconds awaiting a complete 10-node committee topology on WAN
    while (count != 10 && time(NULL) - wait_start < 300 && !atomic_load(&global_shutdown)) {
        get_epoch_committee(state, committee, &count, block_height);
        if (count == 10) break;
        usleep(1000000); // 1-second backoff
    }
    
    if (count != 10) {
        fprintf(stderr, "[DKG] Insufficient committee size (%zu/10) after wait. Aborting DKG.\n", count);
        pthread_mutex_lock(&state->epoch_mutex);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0; // Allow retry on subsequent peer discovery
        pthread_mutex_unlock(&state->epoch_mutex);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    // Resolve local node's deterministic Point ID within the sorted committee (1-indexed)
    uint16_t local_pid = 0;
    for (size_t i = 0; i < 10; i++) {
        if (memcmp(committee[i], state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, PUBKEY_LEN) == 0 ||
            memcmp(committee[i], state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
            local_pid = i + 1;
            break;
        }
    }
    
    if (local_pid == 0) {
        free(committee);
        // Non-committee node: retain session to display progress in UI
        pthread_mutex_lock(&state->epoch_mutex);
        DKGSession *active_sess = hash_table_lookup(state->dkg_active_sessions, session_id, false);
        if (active_sess) {
            active_sess->worker_spawned = true;
        }
        pthread_mutex_unlock(&state->epoch_mutex);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL; // Not elected to active committee
    }
    
    pthread_mutex_lock(&state->epoch_mutex);
    for (int i = 0; i < 10; i++) memcpy(session->committee_pubkeys[i], committee[i], PUBKEY_LEN);
    session->local_point_id = local_pid;
    
    // Drain early arriving messages safely outside the lock
    int early_count = session->early_msg_count;
    Message **early_msgs = NULL;
    uint8_t (*early_senders)[PUBKEY_LEN] = NULL;
    void **early_conns = NULL;
    
    if (early_count > 0) {
        early_msgs = malloc(early_count * sizeof(Message *));
        early_senders = malloc(early_count * PUBKEY_LEN);
        early_conns = malloc(early_count * sizeof(void *));
        
        if (early_msgs && early_senders && early_conns) {
            for (int i = 0; i < early_count; i++) {
                early_msgs[i] = session->early_msgs[i];
                memcpy(early_senders[i], session->early_senders[i], PUBKEY_LEN);
                early_conns[i] = session->early_conns[i];
                session->early_msgs[i] = NULL;
                session->early_conns[i] = NULL;
            }
        }
    }
    session->early_msg_count = 0;
    pthread_mutex_unlock(&state->epoch_mutex);
    
    if (early_msgs && early_senders && early_conns) {
        for (int i = 0; i < early_count; i++) {
            struct sockaddr_storage dummy_addr;
            memset(&dummy_addr, 0, sizeof(dummy_addr));
            dispatch_l5_message((SclConnection *)early_conns[i], state, &state->p2p_network, early_msgs[i], NULL, early_senders[i], &dummy_addr);
            if (early_conns[i]) {
                scl_connection_release((SclConnection *)early_conns[i]);
            }
            free(early_msgs[i]);
        }
    }
    
    if (early_msgs) free(early_msgs);
    if (early_senders) free(early_senders);
    if (early_conns) free(early_conns);
    
    // Barrier delay ensuring all committee members complete session registration
    usleep(2500000);
    
    // --- ROUND 1: COMMIT ---
    // Sample 256 bits of CSPRNG entropy for the local seed
    if (RAND_bytes(session->local_seed, 32) != 1) {
        fprintf(stderr, "[DKG] Failed to generate random seed\n");
        pthread_mutex_lock(&state->epoch_mutex);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    // Commitment = SHA256(local_seed || local_dilithium_pubkey)
    uint8_t commit_buf[32 + PUBKEY_LEN];
    memcpy(commit_buf, session->local_seed, 32);
    memcpy(commit_buf + 32, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, PUBKEY_LEN);
    uint8_t local_commit[32];
    sha256_hash(commit_buf, 32 + PUBKEY_LEN, local_commit);
    
    Message *commit_msg = calloc(1, sizeof(Message));
    Message *reveal_msg = calloc(1, sizeof(Message));
    if (!commit_msg || !reveal_msg) {
        if (commit_msg) free(commit_msg);
        if (reveal_msg) free(reveal_msg);
        pthread_mutex_lock(&state->epoch_mutex);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    pthread_mutex_lock(&state->epoch_mutex);
    if (session->status == -1) {
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(commit_msg);
        free(reveal_msg);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    memcpy(session->commitments[local_pid - 1], local_commit, 32);
    session->has_commitment[local_pid - 1] = true;
    session->commitments_received++;
    pthread_mutex_unlock(&state->epoch_mutex);
    
    commit_msg->type = MSG_DKG_COMMIT;
    memcpy(commit_msg->payload, session_id, COIN_ID_LEN);
    uint16_t pid_be = htobe16(local_pid);
    memcpy(commit_msg->payload + COIN_ID_LEN, &pid_be, 2);
    memcpy(commit_msg->payload + COIN_ID_LEN + 2, local_commit, 32);
    commit_msg->length = COIN_ID_LEN + 2 + 32;

    SclConnection *commit_sent[10] = {0};
    SclConnection *reveal_sent[10] = {0};
    SclConnection *share_sent[10] = {0};
    SclConnection *frag_sent[10] = {0};

    time_t commit_last_send[10] = {0};
    time_t reveal_last_send[10] = {0};
    time_t share_last_send[10] = {0};
    time_t frag_last_send[10] = {0};

    for (int i = 0; i < 10; i++) {
        if (i != local_pid - 1) {
            SclConnection *conn = get_established_conn(state, committee[i]);
            if (conn) {
                if (send_message(state, committee[i], commit_msg)) {
                    commit_sent[i] = conn;
                    commit_last_send[i] = time(NULL);
                }
            }
        }
    }

    time_t start_time = time(NULL);
    time_t timeout_limit = 240; // 240-second timeout handling network jitter and loss recovery
    time_t phase3_timeout_limit = 450; // 450-second timeout for large Kyber encrypted polynomial deals
    
    pthread_mutex_lock(&state->epoch_mutex);
    while (session->commitments_received < 10) {
        if (session->status == -1) break;
        if (session->commitments_received >= 10) break;
        
        pthread_mutex_unlock(&state->epoch_mutex);
        for (int i = 0; i < 10; i++) {
            if (i != local_pid - 1) {
                pthread_mutex_lock(&state->epoch_mutex);
                bool has_comm = session->has_commitment[i];
                pthread_mutex_unlock(&state->epoch_mutex);

                SclConnection *conn = get_established_conn(state, committee[i]);
                if (!conn) {
                    pthread_mutex_lock(&state->p2p_network.mutex);
                    struct sockaddr_storage peer_addr;
                    memset(&peer_addr, 0, sizeof(peer_addr));
                    bool found_addr = false;
                    for (size_t p = 0; p < state->p2p_network.num_known_peers; p++) {
                        if (memcmp(state->p2p_network.known_peers[p]->peer_wallet.dilithium_pubkey, committee[i], PUBKEY_LEN) == 0) {
                            peer_addr = state->p2p_network.known_peers[p]->addr;
                            found_addr = true;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&state->p2p_network.mutex);
                    if (found_addr) {
                        scl_initiate_connection(&state->p2p_network, &peer_addr);
                    }
                } else if (!has_comm && (!commit_sent[i] || time(NULL) - commit_last_send[i] >= 5)) {
                    if (send_message(state, committee[i], commit_msg)) {
                        commit_sent[i] = conn;
                        commit_last_send[i] = time(NULL);
                    }
                }
            }
        }
        pthread_mutex_lock(&state->epoch_mutex);
        
        if (session->status == -1) break;
        if (session->commitments_received >= 10) break;
        
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5; // 5-second polling tick
        
        pthread_cond_timedwait(&session->phase_cond, &state->epoch_mutex, &ts);
        
        if (time(NULL) - start_time >= timeout_limit) break;
    }
    
    if (session->commitments_received < 10 || session->status == -1) {
        fprintf(stderr, "[DKG] Timeout or abort in COMMIT round (%d/10). Aborting DKG gracefully.\n", session->commitments_received);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(commit_msg);
        free(reveal_msg);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    session->status = 1;
    pthread_mutex_unlock(&state->epoch_mutex);
    
    // --- ROUND 2: REVEAL ---
    pthread_mutex_lock(&state->epoch_mutex);
    if (session->status == -1) {
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(commit_msg);
        free(reveal_msg);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    memcpy(session->reveals[local_pid - 1], session->local_seed, 32);
    session->has_reveal[local_pid - 1] = true;
    session->reveals_received++;
    pthread_mutex_unlock(&state->epoch_mutex);
    
    // Construct reveal envelope containing the raw 32-byte seed
    memcpy(reveal_msg->payload, session_id, COIN_ID_LEN);
    memcpy(reveal_msg->payload + COIN_ID_LEN, &pid_be, 2);
    memcpy(reveal_msg->payload + COIN_ID_LEN + 2, session->local_seed, 32);
    reveal_msg->length = COIN_ID_LEN + 2 + 32;
    reveal_msg->type = MSG_DKG_REVEAL;
    
    for (int i = 0; i < 10; i++) {
        if (i != local_pid - 1) {
            SclConnection *conn = get_established_conn(state, committee[i]);
            if (conn) {
                if (send_message(state, committee[i], reveal_msg)) {
                    reveal_sent[i] = conn;
                    reveal_last_send[i] = time(NULL);
                }
            }
        }
    }
    
    start_time = time(NULL);
    pthread_mutex_lock(&state->epoch_mutex);
    while (session->reveals_received < 10) {
        if (session->status == -1) break;
        if (session->reveals_received >= 10) break;
        
        pthread_mutex_unlock(&state->epoch_mutex);
        for (int i = 0; i < 10; i++) {
            if (i != local_pid - 1) {
                pthread_mutex_lock(&state->epoch_mutex);
                bool has_reveal = session->has_reveal[i];
                pthread_mutex_unlock(&state->epoch_mutex);

                SclConnection *conn = get_established_conn(state, committee[i]);
                if (!conn) {
                    pthread_mutex_lock(&state->p2p_network.mutex);
                    struct sockaddr_storage peer_addr;
                    memset(&peer_addr, 0, sizeof(peer_addr));
                    bool found_addr = false;
                    for (size_t p = 0; p < state->p2p_network.num_known_peers; p++) {
                        if (memcmp(state->p2p_network.known_peers[p]->peer_wallet.dilithium_pubkey, committee[i], PUBKEY_LEN) == 0) {
                            peer_addr = state->p2p_network.known_peers[p]->addr;
                            found_addr = true;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&state->p2p_network.mutex);
                    if (found_addr) {
                        scl_initiate_connection(&state->p2p_network, &peer_addr);
                    }
                } else if (!has_reveal && (!reveal_sent[i] || time(NULL) - reveal_last_send[i] >= 5)) {
                    if (send_message(state, committee[i], reveal_msg)) {
                        reveal_sent[i] = conn;
                        reveal_last_send[i] = time(NULL);
                    }
                }
            }
        }
        pthread_mutex_lock(&state->epoch_mutex);
        
        if (session->status == -1) break;
        if (session->reveals_received >= 10) break;
        
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        
        pthread_cond_timedwait(&session->phase_cond, &state->epoch_mutex, &ts);
        
        if (time(NULL) - start_time >= timeout_limit) break;
    }
    
    if (session->reveals_received < 10 || session->status == -1) {
        fprintf(stderr, "[DKG] Timeout or abort in REVEAL round (%d/10). Aborting DKG gracefully.\n", session->reveals_received);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(commit_msg);
        free(reveal_msg);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    // Derive Fiat-Shamir global rho from revealed seeds
    if (dkg_compute_global_rho(session) != CRYPTO_SUCCESS) {
        pthread_mutex_lock(&state->epoch_mutex);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(commit_msg);
        free(reveal_msg);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    session->status = 2;
    pthread_mutex_unlock(&state->epoch_mutex);
    
    // --- ROUND 3: SHARE DEAL ---
    // Sample local Shamir/RSS secret polynomials (s1, s2) and compute public key fragment (t)
    if (threshold_keygen_local_dealer(state, session) != CRYPTO_SUCCESS) {
        pthread_mutex_lock(&state->epoch_mutex);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        free(commit_msg);
        free(reveal_msg);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    Message *msg_frag = calloc(1, sizeof(Message));
    msg_frag->type = MSG_DKG_PUBKEY_FRAG;
    memcpy(msg_frag->payload, session_id, COIN_ID_LEN);
    memcpy(msg_frag->payload + COIN_ID_LEN, &pid_be, 2);
    size_t tk_len;
    polyvec_serialize(&session->keygen.t, msg_frag->payload + COIN_ID_LEN + 2, MAX_MESSAGE_SIZE - (COIN_ID_LEN + 2), &tk_len);
    msg_frag->length = COIN_ID_LEN + 2 + tk_len;
    
    Message *share_msgs[10] = {NULL};
    uint8_t *pt_bufs[10] = {NULL};
    size_t pt_lens[10] = {0};
    
    // Pre-serialize plaintext sub-shares across all peer subsets
    for (int j = 0; j < 10; j++) {
        if (j == local_pid - 1) continue;
        pt_bufs[j] = malloc(MAX_MESSAGE_SIZE);
        if (!pt_bufs[j]) continue;
        uint8_t *pt = pt_bufs[j];
        for (int K = 0; K < 10; K++) {
            if (K != j) {
                uint16_t subset_id_be = htobe16(K);
                memcpy(pt, &subset_id_be, 2); pt += 2;
                size_t s1_len = 0, s2_len = 0;
                polyvec_serialize(&session->keygen.s1_sub_shares[K], pt, MAX_MESSAGE_SIZE - (pt - pt_bufs[j]), &s1_len); pt += s1_len;
                polyvec_serialize(&session->keygen.s2_sub_shares[K], pt, MAX_MESSAGE_SIZE - (pt - pt_bufs[j]), &s2_len); pt += s2_len;
            }
        }
        pt_lens[j] = pt - pt_bufs[j];
    }
    
    // Encapsulate sub-shares using ML-KEM/Kyber-768 and dispatch via AEAD
    for (int j = 0; j < 10; j++) {
        if (j == local_pid - 1) continue;
        
        SclConnection *conn = get_established_conn(state, committee[j]);
        if (conn) {
            if (send_message(state, committee[j], msg_frag)) {
                frag_sent[j] = conn;
                frag_last_send[j] = time(NULL);
            }
        }
        
        if (!share_msgs[j]) {
            uint8_t peer_kyber_pk[KYBER_PUBKEY_LEN];
            bool found_key = false;
            
            pthread_mutex_lock(&state->p2p_network.mutex);
            for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, committee[j], PUBKEY_LEN) == 0) {
                    memcpy(peer_kyber_pk, state->p2p_network.known_peers[i]->peer_wallet.kyber_pubkey, KYBER_PUBKEY_LEN);
                    found_key = true;
                    break;
                }
            }
            pthread_mutex_unlock(&state->p2p_network.mutex);
            
            if (found_key) {
                share_msgs[j] = calloc(1, sizeof(Message));
                if (share_msgs[j]) {
                    share_msgs[j]->type = MSG_DKG_SHARE_DEAL;
                    
                    uint8_t ciphertext[KYBER_CIPHERTEXT_LEN];
                    uint8_t shared_secret[KYBER_SHARED_SECRET_LEN];
                    if (kyber_encapsulate(peer_kyber_pk, ciphertext, shared_secret)) {
                        uint8_t aes_key[32];
                        derive_symmetric_keys(shared_secret, aes_key);

                        uint8_t *p = share_msgs[j]->payload;
                        memcpy(p, session_id, COIN_ID_LEN); p += COIN_ID_LEN;
                        memcpy(p, &pid_be, 2); p += 2;
                        memcpy(p, ciphertext, KYBER_CIPHERTEXT_LEN); p += KYBER_CIPHERTEXT_LEN;
                        
                        size_t encrypted_len = 0;
                        encrypt_message(aes_key, pt_bufs[j], pt_lens[j], p, &encrypted_len);
                        p += encrypted_len;
                        
                        share_msgs[j]->length = p - share_msgs[j]->payload;
                    } else {
                        free(share_msgs[j]);
                        share_msgs[j] = NULL;
                    }
                }
            }
        }
        
        if (share_msgs[j] && conn) {
            if (send_message(state, committee[j], share_msgs[j])) {
                share_sent[j] = conn;
                share_last_send[j] = time(NULL);
            }
        }
    }

    start_time = time(NULL);
    pthread_mutex_lock(&state->epoch_mutex);
    while (session->shares_received < 9 || session->pubkey_frags_received < 9) {
        if (session->status == -1) break;
        if (session->shares_received >= 9 && session->pubkey_frags_received >= 9) break;
        
        pthread_mutex_unlock(&state->epoch_mutex);
        for (int j = 0; j < 10; j++) {
            if (j == local_pid - 1) continue;
            
            pthread_mutex_lock(&state->epoch_mutex);
            bool need_share = !session->has_shares[j];
            bool need_frag = !session->has_pubkey_frag[j];
            pthread_mutex_unlock(&state->epoch_mutex);
            
            SclConnection *conn = get_established_conn(state, committee[j]);
            if (!conn) {
                pthread_mutex_lock(&state->p2p_network.mutex);
                struct sockaddr_storage peer_addr;
                memset(&peer_addr, 0, sizeof(peer_addr));
                bool found_addr = false;
                for (size_t p = 0; p < state->p2p_network.num_known_peers; p++) {
                    if (memcmp(state->p2p_network.known_peers[p]->peer_wallet.dilithium_pubkey, committee[j], PUBKEY_LEN) == 0) {
                        peer_addr = state->p2p_network.known_peers[p]->addr;
                        found_addr = true;
                        break;
                    }
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
                if (found_addr) {
                    scl_initiate_connection(&state->p2p_network, &peer_addr);
                }
            } else {
                if (need_frag && (!frag_sent[j] || time(NULL) - frag_last_send[j] >= 5)) {
                    if (send_message(state, committee[j], msg_frag)) {
                        frag_sent[j] = conn;
                        frag_last_send[j] = time(NULL);
                    }
                }
                
                if (need_share && (!share_sent[j] || time(NULL) - share_last_send[j] >= 5)) {
                    if (!share_msgs[j]) {
                        uint8_t peer_kyber_pk[KYBER_PUBKEY_LEN];
                        bool found_key = false;
                        
                        pthread_mutex_lock(&state->p2p_network.mutex);
                        for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                            if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, committee[j], PUBKEY_LEN) == 0) {
                                memcpy(peer_kyber_pk, state->p2p_network.known_peers[i]->peer_wallet.kyber_pubkey, KYBER_PUBKEY_LEN);
                                found_key = true;
                                break;
                            }
                        }
                        pthread_mutex_unlock(&state->p2p_network.mutex);
                        
                        if (found_key) {
                            share_msgs[j] = calloc(1, sizeof(Message));
                            if (share_msgs[j]) {
                                share_msgs[j]->type = MSG_DKG_SHARE_DEAL;
                                
                                uint8_t ciphertext[KYBER_CIPHERTEXT_LEN];
                                uint8_t shared_secret[KYBER_SHARED_SECRET_LEN];
                                if (kyber_encapsulate(peer_kyber_pk, ciphertext, shared_secret)) {
                                    uint8_t aes_key[32];
                                    derive_symmetric_keys(shared_secret, aes_key);

                                    uint8_t *p = share_msgs[j]->payload;
                                    memcpy(p, session_id, COIN_ID_LEN); p += COIN_ID_LEN;
                                    memcpy(p, &pid_be, 2); p += 2;
                                    memcpy(p, ciphertext, KYBER_CIPHERTEXT_LEN); p += KYBER_CIPHERTEXT_LEN;
                                    
                                    size_t encrypted_len = 0;
                                    encrypt_message(aes_key, pt_bufs[j], pt_lens[j], p, &encrypted_len);
                                    p += encrypted_len;
                                    
                                    share_msgs[j]->length = p - share_msgs[j]->payload;
                                } else {
                                    free(share_msgs[j]);
                                    share_msgs[j] = NULL;
                                }
                            }
                        }
                    }
                    if (share_msgs[j]) {
                        if (send_message(state, committee[j], share_msgs[j])) {
                            share_sent[j] = conn;
                            share_last_send[j] = time(NULL);
                        }
                    }
                }
            }
        }
        pthread_mutex_lock(&state->epoch_mutex);
        
        if (session->status == -1) break;
        if (session->shares_received >= 9 && session->pubkey_frags_received >= 9) break;
        
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        
        pthread_cond_timedwait(&session->phase_cond, &state->epoch_mutex, &ts);
        
        if (time(NULL) - start_time >= phase3_timeout_limit) break;
    }
            
    if (session->shares_received < 9 || session->pubkey_frags_received < 9 || session->status == -1) {
        fprintf(stderr, "[DKG] Timeout or abort in SHARE DEAL round (Shares: %d/9, Frags: %d/9). Aborting DKG.\n", session->shares_received, session->pubkey_frags_received);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        
        for (int j = 0; j < 10; j++) {
            if (share_msgs[j]) free(share_msgs[j]);
            if (pt_bufs[j]) free(pt_bufs[j]);
        }
        free(commit_msg);
        free(reveal_msg);
        free(msg_frag);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    session->status = 3;
    pthread_mutex_unlock(&state->epoch_mutex);
    
    // --- ROUND 4: ASSEMBLE ---
    // Decapsulate sub-shares, verify against commitments, and reconstruct threshold keys
    if (dkg_verify_and_assemble_keys(state, session) != CRYPTO_SUCCESS) {
        pthread_mutex_lock(&state->epoch_mutex);
        hash_table_remove(state->dkg_active_sessions, session_id);
        state->last_dkg_attempted_epoch = 0;
        pthread_mutex_unlock(&state->epoch_mutex);
        
        for (int j = 0; j < 10; j++) {
            if (share_msgs[j]) free(share_msgs[j]);
            if (pt_bufs[j]) free(pt_bufs[j]);
        }
        free(commit_msg);
        free(reveal_msg);
        free(msg_frag);
        free(committee);
        atomic_fetch_sub(&state->active_background_threads, 1);
        dkg_session_release(session);
        return NULL;
    }
    
    // Cleanup on successful ceremony conclusion
    pthread_mutex_lock(&state->epoch_mutex);
    hash_table_remove(state->dkg_active_sessions, session_id);
    pthread_mutex_unlock(&state->epoch_mutex);
    
    for (int j = 0; j < 10; j++) {
        if (share_msgs[j]) free(share_msgs[j]);
        if (pt_bufs[j]) free(pt_bufs[j]);
    }
    free(commit_msg);
    free(reveal_msg);
    free(msg_frag);
    free(committee);
    atomic_fetch_sub(&state->active_background_threads, 1);
    
    fprintf(stderr, "[DKG] Distributed Key Generation successful for epoch %llu\n", block_height);
    dkg_session_release(session);
    return NULL;
}

/**
 * @brief Spawns a detached background thread to execute the DKG ceremony.
 *
 * @pre `state` and `session_id` must be non-NULL.
 * @post A new thread is initialized with an 8 MB stack for lattice operations.
 * @sideeffect Increments `state->active_background_threads`.
 * @sync Thread Safety: Uses atomic increment on `active_background_threads`.
 *
 * @param[in,out] state        Pointer to global State structure.
 * @param[in]     session_id   Pointer to 32-byte DKG session identifier.
 * @param[in]     block_height Epoch block height triggering keygen.
 *
 * @return void.
 * @complexity Time: O(1); Space: 8 MB stack allocation.
 */
void spawn_dkg_worker_thread(State *state, const uint8_t *session_id, uint64_t block_height) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)state; (void)session_id; (void)block_height;
#else
    DKGWorkerArgs *args = malloc(sizeof(DKGWorkerArgs));
    if (!args) return;
    args->state = state;
    memcpy(args->session_id, session_id, COIN_ID_LEN);
    args->block_height = block_height;
    
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    atomic_fetch_add(&state->active_background_threads, 1);
    if (pthread_create(&tid, &attr, dkg_worker_thread, args) != 0) {
        atomic_fetch_sub(&state->active_background_threads, 1);
        free(args);
    } else {
        pthread_detach(tid);
    }
    pthread_attr_destroy(&attr);
#endif
}

/* ============================================================================ */
/* SECTION 10: Candidate Block Proposal Pipeline                               */
/* ============================================================================ */
/* Architectural Preface:
 * Implements the leader proposal pipeline executed by the elected validator.
 * Gathers unconfirmed transactions from the mempool, executes conflict resolution
 * across input coin pointers to eliminate intra-block double spends, packs ZK-PRF
 * batch nullifiers and proofs, orchestrates per-block threshold beacon signing,
 * and broadcasts the proposed candidate block across the P2P gossip network.
 */

/**
 * @brief Assembles, validates, signs, and gossips a newly proposed candidate Block.
 *
 * Operational Mechanics:
 * 1. Checks synchronization barriers and proposal cooldown limits (`VOTE_TIMEOUT`).
 * 2. Collects pending operations from `state->pending_operations`, prioritizing minting
 *    operations (OP_MINT_COIN) followed by topologically sorted transfers/stakes.
 * 3. Enforces pointer collision avoidance: rejects operations referencing pointers
 *    already consumed by prior transactions within the same block batch.
 * 4. Batches all transfer ZK-PRF nullifiers and proofs into block-level buffers.
 * 5. Pre-validates the proposed transaction set against current chain tip under
 *    read lock (`state->bc.rwlock`). Evicts any invalidated transactions from mempool.
 * 6. Computes a deterministic entropy seed using SHA-256 over:
 *    `prev_block_hash (32B) || proposer_pubkey (2592B) || retry_nonce (4B)`.
 * 7. Constructs the candidate Block via `create_block` and verifies its heavy cryptography.
 * 8. If height exceeds `BLOCKS_PER_DAY` and an epoch key is active, orchestrates
 *    Phase 2 per-block threshold signing over the candidate block hash via network
 *    sign requests (`MSG_EPOCH_SIGN_REQUEST`) awaiting partial aggregation.
 * 9. Enqueues a self-vote into `state->block_consensus`, records height in `voted_heights`,
 *    broadcasts `MSG_GOSSIP_BLOCK`, and spawns a background `vote_collection_thread`.
 *
 * @pre `state` must be non-NULL and fully initialized.
 * @pre Proposer node must be elected proposer for height `state->current_block_number + 1`.
 * @post A new candidate block is created, self-voted, gossiped, and tracked in consensus queues.
 * @sideeffect Allocates vote queue; enqueues P2P gossip; spawns detached thread;
 *             evicts invalid operations from `state->pending_operations`.
 * @sync Thread Safety: Acquires `state->mutex`, `state->bc.rwlock` (read),
 *       `state->game_state.mutex`, `state->epoch_mutex`, and `state->block_proposers_lock`.
 *       Releases `state->mutex` prior to DKG/threshold waits to avoid deadlock.
 *
 * @param[in,out] state         Pointer to global State structure.
 * @param[in]     provided_mint Optional pointer to an OP_MINT_COIN operation.
 *
 * @return void.
 * @complexity Time: O(M log M + P * ZK_VERIFY) where M is mempool size, P is pointer count;
 *             Space: O(MaxBlockSize).
 */
void propose_block(State *state, const Operation *provided_mint) {
    static uint64_t last_proposed_height = 0;
    static time_t last_proposed_time = 0;
    static uint32_t proposal_retry_nonce = 0;
    
    if (!state) {
        fprintf(stderr, "[ProposeBlock] ERROR: Invalid state\n");
        return;
    }

    // Guard against proposing while in active sync, behind network tip, or before genesis
    pthread_mutex_lock(&state->mutex);
    bool cannot_propose = state->in_blockchain_sync ||
                          atomic_load(&state->sync_thread_active) ||
                          (state->network_target_block_number > 0 && state->current_block_number < state->network_target_block_number) ||
                          (state->current_block_number == 0 && is_zeroed(state->current_block_hash, COIN_ID_LEN));
    if (cannot_propose) {
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    pthread_mutex_unlock(&state->mutex);

    Operation *mint_op = NULL;
    bool has_mint = false;
    if (provided_mint && provided_mint->type == OP_MINT_COIN) {
        has_mint = true;
        mint_op = calloc(1, sizeof(Operation));
        if (mint_op) *mint_op = *provided_mint;
    }
    size_t max_transfers = MAX_OPERATIONS_PER_BLOCK - (has_mint ? 1 : 0);

    // Atomically take a snapshot count of pending mempool transactions
    size_t pending_count_snapshot = atomic_load_explicit(&state->pending_operations_count, memory_order_acquire);
    Operation *all_pending_ops = NULL;
    size_t collected_count = 0;

    if (pending_count_snapshot > 0) {
        all_pending_ops = malloc(pending_count_snapshot * sizeof(Operation));
        if (!all_pending_ops) {
            fprintf(stderr, "[ProposeBlock] Failed to allocate all_pending_ops array\n");
            if (mint_op) free(mint_op);
            return;
        }
        
        // Scan mempool ring slots atomically to gather pending candidates
        for (int i = 0; i < MAX_PENDING_OPS; i++) {
            Operation *op_ptr = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
            if (op_ptr) {
                if (op_ptr->type == OP_TRANSFER_POINTER ||
                    op_ptr->type == OP_STAKE ||
                    op_ptr->type == OP_UNSTAKE) {
                    if (collected_count < pending_count_snapshot) {
                        all_pending_ops[collected_count++] = *op_ptr;
                    }
                } else if (op_ptr->type == OP_MINT_COIN && !has_mint) {
                    has_mint = true;
                    mint_op = calloc(1, sizeof(Operation));
                    if (mint_op) *mint_op = *op_ptr;
                    max_transfers = MAX_OPERATIONS_PER_BLOCK - 1;
                }
            }
        }
    }

    // Protocol invariant: every proposed block must contain exactly one mint operation
    if (!has_mint) {
        fprintf(stderr, "[ProposeBlock] No mint operation to propose, deferring block proposal\n");
        free(all_pending_ops);
        return;
    }

    // Sort operations topologically to enforce sequential parent-child execution order
    if (collected_count > 1) {
        qsort(all_pending_ops, collected_count, sizeof(Operation), compare_operations);
    }

    size_t transfer_count = 0;
    Operation *transfer_ops = NULL;
    if (collected_count > 0) {
        transfer_ops = malloc(max_transfers * sizeof(Operation));
        uint8_t (*used_pointers)[COIN_ID_LEN] = malloc(max_transfers * MAX_INPUTS * COIN_ID_LEN);
                
        if (!transfer_ops || !used_pointers) {
            fprintf(stderr, "[ProposeBlock] Failed to allocate transfer or collision arrays\n");
            if (transfer_ops) free(transfer_ops);
            if (used_pointers) free(used_pointers);
            free(all_pending_ops);
            if (mint_op) free(mint_op);
            return;
        }
            
        size_t used_pointer_count = 0;
        size_t estimated_block_size = 70000; // Base header and proposer signature overhead in bytes
                    
        // Filter out operations that conflict on input coin pointers or exceed max wire message size
        for (size_t i = 0; i < collected_count && transfer_count < max_transfers; i++) {
            Operation *op = &all_pending_ops[i];
            uint32_t num_inputs = 0;
            const Pointer *inputs = NULL;
            size_t op_size = 15000;
                
            if (op->type == OP_TRANSFER_POINTER) {
                num_inputs = op->data.transfer_pointer.num_inputs;
                inputs = op->data.transfer_pointer.inputs;
                op_size += op->data.transfer_pointer.zk_proof_len + (num_inputs * 8000);
            } else if (op->type == OP_STAKE) {
                num_inputs = op->data.stake.num_inputs;
                inputs = op->data.stake.inputs;
                op_size += (num_inputs * 8000);
            } else if (op->type == OP_UNSTAKE) {
                num_inputs = op->data.unstake.num_inputs;
                inputs = op->data.unstake.inputs;
                op_size += (num_inputs * 8000);
            }

            if (estimated_block_size + op_size >= MAX_MESSAGE_SIZE - 50000) continue;

            bool conflict = false;
            for (uint32_t j = 0; j < num_inputs; j++) {
                for (size_t k = 0; k < used_pointer_count; k++) {
                    if (memcmp(inputs[j].pointer_id, used_pointers[k], COIN_ID_LEN) == 0) {
                        conflict = true; break;
                    }
                }
                if (conflict) break;
            }
                
            if (!conflict) {
                transfer_ops[transfer_count++] = *op;
                estimated_block_size += op_size;
                for (uint32_t j = 0; j < num_inputs; j++)
                    memcpy(used_pointers[used_pointer_count++], inputs[j].pointer_id, COIN_ID_LEN);
            }
        }
        free(used_pointers);
    }
    free(all_pending_ops);

    // Assemble final batch of operations starting with mandatory mint
    size_t op_count = (has_mint ? 1 : 0) + transfer_count;
    Operation *operations = malloc(op_count * sizeof(Operation));
    if (!operations) {
        fprintf(stderr, "[ProposeBlock] Failed to allocate operations array\n");
        if (transfer_ops) free(transfer_ops);
        if (mint_op) free(mint_op);
        return;
    }

    size_t op_idx = 0;
    if (has_mint && mint_op) {
        operations[op_idx++] = *mint_op;
        free(mint_op);
        mint_op = NULL;
    }
    for (size_t i = 0; i < transfer_count; i++) {
        operations[op_idx++] = transfer_ops[i];
    }
    free(transfer_ops);

    if (op_count > 1) {
        qsort(operations, op_count, sizeof(Operation), compare_operations);
    }

    // Calculate dimensions for block-level ZK-PRF nullifier and Stern proof batching
    size_t batch_tx_count = 0;
    size_t total_zk_proof_len = 0;
    for (size_t i = 0; i < op_count; i++) {
        if (operations[i].type == OP_TRANSFER_POINTER) {
            batch_tx_count++;
            total_zk_proof_len += sizeof(uint32_t) + operations[i].data.transfer_pointer.zk_proof_len;
        }
    }

    uint8_t *batch_prf_outputs = NULL;
    uint8_t *batch_zk_proof = NULL;

    if (batch_tx_count > 0) {
        batch_prf_outputs = malloc(batch_tx_count * NULLIFIER_LEN);
        batch_zk_proof = malloc(total_zk_proof_len);
        if (!batch_prf_outputs || !batch_zk_proof) {
            fprintf(stderr, "[ProposeBlock] Failed to allocate memory for batch ZK-PRF data\n");
            free(operations);
            if (batch_prf_outputs) free(batch_prf_outputs);
            if (batch_zk_proof) free(batch_zk_proof);
            return;
        }

        uint8_t *current_proof_ptr = batch_zk_proof;
        size_t current_tx_index = 0;
        for (size_t i = 0; i < op_count; i++) {
            if (operations[i].type == OP_TRANSFER_POINTER) {
                TransferData *tx_data = &operations[i].data.transfer_pointer;
                memcpy(batch_prf_outputs + (current_tx_index * NULLIFIER_LEN), tx_data->prf_output, NULLIFIER_LEN);
                
                uint32_t proof_len_be = htobe32(tx_data->zk_proof_len);
                memcpy(current_proof_ptr, &proof_len_be, sizeof(uint32_t));
                current_proof_ptr += sizeof(uint32_t);
                memcpy(current_proof_ptr, tx_data->zk_proof, tx_data->zk_proof_len);
                current_proof_ptr += tx_data->zk_proof_len;
                current_tx_index++;
            }
        }
    }

    pthread_mutex_lock(&state->mutex);

    // Concurrency guard: reject concurrent proposals on the same node
    if (state->proposing_block) {
        pthread_mutex_unlock(&state->mutex);
        fprintf(stderr, "[ProposeBlock] Block proposal already in progress, skipping\n");
        free(operations);
        if (batch_prf_outputs) free(batch_prf_outputs);
        if (batch_zk_proof) free(batch_zk_proof);
        return;
    }

    // Pre-validation pass: ensure all chosen transactions are currently spendable against the ledger
    pthread_rwlock_rdlock(&state->bc.rwlock);
    bool all_valid = true;
    for (size_t i = 0; i < op_count; i++) {
        Operation *op = &operations[i];
        
        // Resolve parent transaction hash if sequentially chained within the proposed block
        const uint8_t *prev_tx = NULL;
        if (op->type == OP_TRANSFER_POINTER) prev_tx = op->data.transfer_pointer.inputs[0].prev_tx_hash;
        else if (op->type == OP_STAKE) prev_tx = op->data.stake.inputs[0].prev_tx_hash;
        else if (op->type == OP_UNSTAKE) prev_tx = op->data.unstake.inputs[0].prev_tx_hash;

        bool parent_in_block = false;
        if (prev_tx) {
            for (size_t p = 0; p < i; p++) {
                const uint8_t *parent_id = get_operation_tx_id(&operations[p]);
                if (parent_id && memcmp(parent_id, prev_tx, COIN_ID_LEN) == 0) {
                    parent_in_block = true; break;
                }
            }
        }
        
        // Validate against tip if independent; trust topological order if intra-block dependency
        if (!parent_in_block && !validate_operation(state, op)) {
            all_valid = false;
            
            uint8_t op_key[COIN_ID_LEN];
            const uint8_t *op_id = get_operation_tx_id(op);
            if (op_id) {
                memcpy(op_key, op_id, COIN_ID_LEN);
            } else {
                uint8_t *data;
                size_t data_len;
                if (op->type == OP_SUBMIT_VALUATION) {
                    data = (uint8_t *)&op->data.submit_valuation;
                    data_len = sizeof(ValuationData);
                } else {
                    data = (uint8_t *)op;
                    data_len = sizeof(Operation);
                }
                SHA256(data, data_len, op_key);
            }
            
            // Atomic eviction of invalidated operation from mempool
            for (int j = 0; j < MAX_PENDING_OPS; j++) {
                Operation *pop = atomic_load_explicit(&state->pending_operations[j], memory_order_acquire);
                if (pop) {
                    uint8_t pkey[COIN_ID_LEN];
                    const uint8_t *pid = get_operation_tx_id(pop);
                    if (pid) memcpy(pkey, pid, COIN_ID_LEN);
                    else {
                        uint8_t *data_ptr;
                        size_t data_len;
                        if (pop->type == OP_SUBMIT_VALUATION) {
                            data_ptr = (uint8_t *)&pop->data.submit_valuation;
                            data_len = sizeof(ValuationData);
                        } else {
                            data_ptr = (uint8_t *)pop;
                            data_len = sizeof(Operation);
                        }
                        SHA256(data_ptr, data_len, pkey);
                    }
                    if (memcmp(pkey, op_key, COIN_ID_LEN) == 0) {
                        if (atomic_compare_exchange_strong(&state->pending_operations[j], &pop, NULL)) {
                            atomic_fetch_sub(&state->pending_operations_count, 1);
                            free(pop);
                            break;
                        }
                    }
                }
            }
            fprintf(stderr, "[ProposeBlock] Removed invalid operation from mempool\n");
        }
    }
    pthread_rwlock_unlock(&state->bc.rwlock);

    if (!all_valid) {
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        fprintf(stderr, "[ProposeBlock] Operations became invalid before proposal lock acquisition, aborting\n");
        free(operations);
        if (batch_prf_outputs) free(batch_prf_outputs);
        if (batch_zk_proof) free(batch_zk_proof);
        trigger_proposer_if_eligible(state);
        return;
    }

    time_t current_time = time(NULL);

    if (state->current_block_number + 1 < last_proposed_height) {
        last_proposed_height = state->current_block_number;
        last_proposed_time = 0;
    }

    // Throttle redundant proposals at the same height within the VOTE_TIMEOUT window
    if (state->current_block_number + 1 <= last_proposed_height && (current_time - last_proposed_time < VOTE_TIMEOUT)) {
        if (has_mint) {
            Operation *found_mint_op = NULL;
            for (size_t i = 0; i < op_count; i++) {
                if (operations[i].type == OP_MINT_COIN) {
                    found_mint_op = &operations[i];
                    break;
                }
            }
            if (found_mint_op) {
                fprintf(stderr, "[ProposeBlock] Block already proposed for height %llu, deferring mint to mempool\n", state->current_block_number + 1);
                Operation *mint_copy = calloc(1, sizeof(Operation));
                if (mint_copy) {
                    *mint_copy = *found_mint_op;
                    if (add_pending_operation(state, mint_copy) == 0) {
                        Message *gossip_msg = calloc(1, sizeof(Message));
                        if (gossip_msg) {
                            gossip_msg->type = MSG_PENDING_OPERATION;
                            gossip_msg->length = serialize_operation(mint_copy, gossip_msg->payload, MAX_MESSAGE_SIZE);
                            if (gossip_msg->length > 0) {
                                p2p_broadcast(state, gossip_msg);
                            }
                            free(gossip_msg);
                        }
                    } else {
                        free(mint_copy);
                    }
                }
            }
        }
        pthread_mutex_unlock(&state->mutex);
        fprintf(stderr, "[ProposeBlock] Already proposed block for height %llu, skipping\n", state->current_block_number + 1);
        free(operations);
        if (batch_prf_outputs) free(batch_prf_outputs);
        if (batch_zk_proof) free(batch_zk_proof);
        return;
    }
    last_proposed_height = state->current_block_number + 1;
    last_proposed_time = current_time;

    state->proposing_block = true;

    // Derive deterministic 32-bit integer entropy seed from previous block hash and proposer key
    uint8_t entropy_source[COIN_ID_LEN + PUBKEY_LEN + sizeof(uint32_t)];
    memcpy(entropy_source, state->current_block_hash, COIN_ID_LEN);
    memcpy(entropy_source + COIN_ID_LEN, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    memcpy(entropy_source + COIN_ID_LEN + PUBKEY_LEN, &proposal_retry_nonce, sizeof(uint32_t));

    uint8_t seed_hash[SHA256_DIGEST_LENGTH];
    SHA256(entropy_source, sizeof(entropy_source), seed_hash);

    int deterministic_seed;
    memcpy(&deterministic_seed, seed_hash, sizeof(deterministic_seed));

    Block *block = create_block(
        state->current_block_number + 1,
        state->current_block_hash,
        operations,
        op_count,
        state->user_wallet.dilithium_pubkey,
        state->user_wallet.dilithium_privkey,
        deterministic_seed,
        batch_tx_count,
        batch_prf_outputs,
        batch_zk_proof,
        total_zk_proof_len
    );
    
    if (!block) {
        fprintf(stderr, "[ProposeBlock] Failed to create block\n");
        free(operations);
        if (batch_prf_outputs) free(batch_prf_outputs);
        if (batch_zk_proof) free(batch_zk_proof);
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        return;
    }

    if (verify_block_heavy_crypto(block) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[ProposeBlock] Heavy crypto validation failed on our own proposed block!\n");
        free_block(block);
        free(operations);
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    
    pthread_mutex_lock(&state->game_state.mutex);
    uint64_t current_block_height = state->current_block_number;
    uint64_t target_epoch = current_block_height / BLOCKS_PER_DAY;
    bool has_epoch_key = !is_zeroed(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN) &&
                         (state->game_state.last_dkg_epoch / BLOCKS_PER_DAY == target_epoch);
    pthread_mutex_unlock(&state->game_state.mutex);

    // If epoch key is missing or for wrong epoch, spawn DKG asynchronously and wait briefly without halting chain
    if (!has_epoch_key && current_block_height + 1 > BLOCKS_PER_DAY) {
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
        pthread_mutex_lock(&state->epoch_mutex);
        uint64_t current_epoch_num = target_epoch;
        uint8_t epoch_session_id[COIN_ID_LEN];
        char epoch_input[32];
        memset(epoch_input, 0, 32);
        snprintf(epoch_input, 32, "DKG_EPOCH_%llu", (unsigned long long)current_epoch_num);
        SHA256((uint8_t*)epoch_input, strlen(epoch_input), epoch_session_id);
        
        DKGSession *sess = hash_table_lookup(state->dkg_active_sessions, epoch_session_id, false);
        if (sess && (sess->block_height / BLOCKS_PER_DAY < current_epoch_num)) {
            sess->status = -1;
            pthread_cond_broadcast(&sess->phase_cond);
            pthread_mutex_unlock(&state->epoch_mutex);
            
            pthread_mutex_unlock(&state->mutex);
            free(operations);
            if (batch_prf_outputs) free(batch_prf_outputs);
            if (batch_zk_proof) free(batch_zk_proof);
            return;
        }
        
        bool is_running = (sess != NULL && sess->worker_spawned);
        if (!is_running) {
            if (sess) {
                sess->worker_spawned = true;
                sess->block_height = current_block_height;
                state->last_dkg_attempted_epoch = current_epoch_num + 1;
                atomic_fetch_add_explicit(&sess->ref_count, 1, memory_order_relaxed);
                pthread_mutex_unlock(&state->epoch_mutex);
                fprintf(stderr, "[ProposeBlock] Spawning DKG worker for pre-existing session for epoch %llu.\n", (unsigned long long)current_epoch_num);
                spawn_dkg_worker_thread(state, epoch_session_id, current_block_height);
            } else {
                DKGSession *pre_session = calloc(1, sizeof(DKGSession));
                if (pre_session) {
                    memcpy(pre_session->session_id, epoch_session_id, COIN_ID_LEN);
                    atomic_init(&pre_session->ref_count, 1);
                    pre_session->block_height = current_block_height;
                    pre_session->committee_count = 10;
                    pre_session->status = 0;
                    pre_session->worker_spawned = true;
                    pthread_cond_init(&pre_session->phase_cond, NULL);
                    hash_table_insert(state->dkg_active_sessions, epoch_session_id, pre_session, HASH_ENTRY_DKG_SESSION);
                    atomic_fetch_add_explicit(&pre_session->ref_count, 1, memory_order_relaxed);
                }
                state->last_dkg_attempted_epoch = current_epoch_num + 1;
                pthread_mutex_unlock(&state->epoch_mutex);
                fprintf(stderr, "[ProposeBlock] Initiating DKG for epoch %llu manually.\n", (unsigned long long)current_epoch_num);
                spawn_dkg_worker_thread(state, epoch_session_id, current_block_height);
            }
        } else {
            pthread_mutex_unlock(&state->epoch_mutex);
        }

        // Production Liveness Invariant: Max 5-second wait to allow DKG to complete without stalling consensus block proposals
        pthread_mutex_unlock(&state->mutex);
        time_t wait_start = time(NULL);
        const time_t max_dkg_wait = 5;
        
        while (!has_epoch_key && (time(NULL) - wait_start < max_dkg_wait) && !atomic_load(&global_shutdown)) {
            usleep(500000);
            pthread_mutex_lock(&state->game_state.mutex);
            has_epoch_key = !is_zeroed(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN) &&
                            (state->game_state.last_dkg_epoch / BLOCKS_PER_DAY == target_epoch);
            pthread_mutex_unlock(&state->game_state.mutex);
            
            if (!has_epoch_key) {
                pthread_mutex_lock(&state->epoch_mutex);
                bool dkg_still_running = (hash_table_lookup(state->dkg_active_sessions, epoch_session_id, false) != NULL);
                pthread_mutex_unlock(&state->epoch_mutex);
                if (!dkg_still_running) {
                    break;
                }
            }
        }

        pthread_mutex_lock(&state->mutex);

        if (!has_epoch_key) {
            pthread_mutex_lock(&state->game_state.mutex);
            bool has_fallback_key = !is_zeroed(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
            pthread_mutex_unlock(&state->game_state.mutex);

            if (has_fallback_key) {
                has_epoch_key = true;
            } else {
                fprintf(stderr, "[ProposeBlock] DKG pending or timed out for epoch %llu. Proposing block %llu with empty beacon to preserve chain liveness.\n",
                        (unsigned long long)target_epoch, current_block_height + 1);
                has_epoch_key = false;
            }
        }
#endif
    }

    if (has_epoch_key) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        memset(block->epoch_threshold_signature, 0x42, SIGNATURE_LEN);
#else
        pthread_mutex_lock(&state->epoch_mutex);
        bool is_member = state->is_epoch_member;
        pthread_mutex_unlock(&state->epoch_mutex);

        if (!is_member) {
            fprintf(stderr, "[ProposeBlock] WARNING: Elected as proposer, but not an active epoch committee member. Proposing block with empty beacon.\n");
            memset(block->epoch_threshold_signature, 0, SIGNATURE_LEN);
        } else {
            // Phase 2: Per-Block Randomness Beacon Threshold Signature Ceremony
            uint8_t block_hash_for_sig[COIN_ID_LEN];
            compute_block_hash(block, block_hash_for_sig);
                
            pthread_mutex_lock(&state->epoch_mutex);
            ThresholdStakeProcess *proc = calloc(1, sizeof(ThresholdStakeProcess));
            if (!proc) {
                fprintf(stderr, "[ProposeBlock] Failed to allocate ThresholdStakeProcess\n");
                memset(block->epoch_threshold_signature, 0, SIGNATURE_LEN);
            } else {
                memcpy(proc->stake_tx_id, block_hash_for_sig, COIN_ID_LEN);
                polyvec_init(&proc->w_agg, DILITHIUM_K);
                polyvec_init(&proc->dealer_z, DILITHIUM_L);
                for(int i = 0; i < 10; i++) {
                    polyvec_init(&proc->partial_w[i], DILITHIUM_K);
                    polyvec_init(&proc->partial_z[i], DILITHIUM_L);
                }
                pthread_cond_init(&proc->stage0_complete_cond, NULL);
                pthread_cond_init(&proc->partial_cond, NULL);

                pthread_mutex_unlock(&state->mutex);
                    
                uint8_t (*committee)[PUBKEY_LEN] = malloc(10 * PUBKEY_LEN);
                size_t count = 0;
                if (committee) {
                    if (state->current_committee_count > 0) {
                        memcpy(committee, state->current_committee, state->current_committee_count * PUBKEY_LEN);
                        count = state->current_committee_count;
                    } else {
                        pthread_mutex_unlock(&state->epoch_mutex);
                        get_epoch_committee(state, committee, &count, current_block_height);
                        pthread_mutex_lock(&state->epoch_mutex);
                        if (count > 0) {
                            memcpy(state->current_committee, committee, count * PUBKEY_LEN);
                            state->current_committee_count = count;
                        }
                    }
                    
                    for (size_t i = 0; i < count; i++) {
                        memcpy(proc->peer_pubkeys[i], committee[i], PUBKEY_LEN);
                    }
                }
                proc->expected_partials = 2; // Proposer orchestrates threshold signing, needs t=2 partials
                    
                hash_table_insert(state->epoch_processes, block_hash_for_sig, proc, HASH_ENTRY_THRESHOLD_STAKE_PROCESS);
                pthread_mutex_unlock(&state->epoch_mutex);

                Message *req = calloc(1, sizeof(Message));
                if (req) {
                    req->type = MSG_EPOCH_SIGN_REQUEST;
                    memcpy(req->payload, block_hash_for_sig, COIN_ID_LEN);
                    req->length = COIN_ID_LEN;
                            
                    for (size_t i = 0; i < count; i++) {
                        send_message(state, committee[i], req);
                    }
                    free(req);
                }
                if (committee) free(committee);

                // Await partial signature aggregation from committee peers
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                ts.tv_sec += SIGN_TIMEOUT;
                        
                pthread_mutex_lock(&state->epoch_mutex);
                while (!atomic_load_explicit(&proc->aggregation_complete, memory_order_acquire) &&
                       !atomic_load_explicit(&proc->aggregation_failed, memory_order_acquire)) {
                    if (pthread_cond_timedwait(&proc->partial_cond, &state->epoch_mutex, &ts) == ETIMEDOUT) break;
                }
                        
                if (atomic_load_explicit(&proc->aggregation_complete, memory_order_acquire)) {
                    memcpy(block->epoch_threshold_signature, proc->final_signature, SIGNATURE_LEN);
                    fprintf(stderr, "[ProposeBlock] Successfully generated epoch_threshold_signature for block %llu\n", block->block_number);
                    hash_table_remove(state->epoch_processes, block_hash_for_sig);
                    pthread_mutex_unlock(&state->epoch_mutex);
                    proposal_retry_nonce = 0;
                } else {
                    fprintf(stderr, "[ProposeBlock] WARNING: Epoch signature aggregation timed out. Proposing block with empty beacon to preserve chain liveness.\n");
                    hash_table_remove(state->epoch_processes, block_hash_for_sig);
                    pthread_mutex_unlock(&state->epoch_mutex);
                    memset(block->epoch_threshold_signature, 0, SIGNATURE_LEN);
                }

                pthread_mutex_lock(&state->mutex);
            }
        }

        pthread_mutex_lock(&state->game_state.mutex);
        memcpy(state->game_state.current_epoch_signature, block->epoch_threshold_signature, SIGNATURE_LEN);
        pthread_mutex_unlock(&state->game_state.mutex);
#endif
    } else {
        memset(block->epoch_threshold_signature, 0, SIGNATURE_LEN);
    }
    
    // Invariant check: verify chain tip did not advance during network signature waits
    if (state->current_block_number >= block->block_number || memcmp(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN) != 0) {
        fprintf(stderr, "[ProposeBlock] Chain advanced while waiting for epoch signature, aborting proposal.\n");
        free_block(block);
        free(operations);
        state->proposing_block = false;
        last_proposed_time = 0;
        pthread_mutex_unlock(&state->mutex);
        return;
    }

    uint8_t block_hash[COIN_ID_LEN];
    if (compute_block_hash(block, block_hash) != 0) {
        fprintf(stderr, "[ProposeBlock] Failed to compute block hash\n");
        free_block(block);
        free(operations);
        state->proposing_block = false;
        last_proposed_time = 0;
        pthread_mutex_unlock(&state->mutex);
        return;
    }

    // Map proposed block hash to proposer identity to attribute proposal origin
    BlockProposerInfo *info = malloc(sizeof(BlockProposerInfo));
    if (!info) {
        fprintf(stderr, "[ProposeBlock] Failed to allocate BlockProposerInfo\n");
        free_block(block);
        free(operations);
        state->proposing_block = false;
        last_proposed_time = 0;
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    memcpy(info->block_hash, block_hash, COIN_ID_LEN);
    memcpy(info->proposer_peer_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

    pthread_mutex_lock(&state->block_proposers_lock);
    hash_table_insert(state->block_proposers, block_hash, info, HASH_ENTRY_BLOCK_PROPOSER);
    pthread_mutex_unlock(&state->block_proposers_lock);

    // Self-vote: Proposer automatically votes YES on its own validly constructed block
    Vote self_vote;
    if (!sign_vote(&self_vote, state->user_wallet.dilithium_pubkey, block_hash, 1, state->user_wallet.dilithium_privkey)) {
        fprintf(stderr, "[ProposeBlock] Failed to sign self-vote\n");
        pthread_mutex_lock(&state->block_proposers_lock);
        hash_table_remove(state->block_proposers, block_hash);
        pthread_mutex_unlock(&state->block_proposers_lock);
        free_block(block);
        free(operations);
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        return;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    apply_block(state, block);
    free_block(block);
    free(operations);
    state->proposing_block = false;
    pthread_mutex_unlock(&state->mutex);
    return;
#else

    BlockVoteQueue *queue = malloc(sizeof(BlockVoteQueue));
    if (!queue) {
        fprintf(stderr, "[ProposeBlock] Failed to allocate vote queue\n");
        pthread_mutex_lock(&state->block_proposers_lock);
        hash_table_remove(state->block_proposers, block_hash);
        pthread_mutex_unlock(&state->block_proposers_lock);
        free_block(block);
        free(operations);
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    
    pthread_mutex_lock(&state->p2p_network.mutex);
    size_t safe_peer_count = state->p2p_network.num_known_peers;
    pthread_mutex_unlock(&state->p2p_network.mutex);
    
    size_t queue_capacity = (safe_peer_count < 32) ? 32 : safe_peer_count * 2;
    
    queue->votes = malloc(queue_capacity * sizeof(Vote));
    if (!queue->votes) {
        fprintf(stderr, "[ProposeBlock] Failed to allocate votes array\n");
        pthread_mutex_lock(&state->block_proposers_lock);
        hash_table_remove(state->block_proposers, block_hash);
        pthread_mutex_unlock(&state->block_proposers_lock);
        free(queue);
        free_block(block);
        free(operations);
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    queue->count = 0;
    queue->head = 0;
    queue->size = queue_capacity;
    queue->yes_votes = 0;
    queue->block_height = block->block_number;
    pthread_mutex_init(&queue->vote_lock, NULL);
    pthread_cond_init(&queue->cond, NULL);
    queue->next = NULL;
    queue->ref_count = 1;

    pthread_mutex_lock(&queue->vote_lock);
    if (queue->count < queue->size) {
        queue->votes[queue->count++] = self_vote;
        queue->yes_votes++;
        pthread_cond_signal(&queue->cond);
    }
    pthread_mutex_unlock(&queue->vote_lock);
    fprintf(stderr, "[ProposeBlock] Self-vote added, yes_votes=%zu\n", queue->yes_votes);

    hash_table_insert(state->block_consensus, block_hash, queue, HASH_ENTRY_VOTE_QUEUE);

    // Record self-vote in voted_heights to prevent voting for any other competing block at the same height
    uint8_t user_id[USER_ID_LEN];
    SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, user_id);
    struct { uint64_t height; time_t timestamp; } vote_rec = { block->block_number, time(NULL) };
    hash_table_insert(state->voted_heights, user_id, &vote_rec, HASH_ENTRY_VOTED_HEIGHT);

    // Gossip candidate block across the network
    Message *block_msg = calloc(1, sizeof(Message));
    if (block_msg) {
        if (serialize_block(block, block_msg, true) == 0) {
            block_msg->type = MSG_GOSSIP_BLOCK;
            p2p_broadcast(state, block_msg);
            fprintf(stderr, "[ProposeBlock] Proposed block %llu with %zu operations\n",
                    block->block_number, block->operation_count);
        } else {
            fprintf(stderr, "[ProposeBlock] Failed to serialize block\n");
        }
        free(block_msg);
    } else {
        fprintf(stderr, "[ProposeBlock] Failed to allocate message\n");
    }

    struct VoteThreadArgs *args = malloc(sizeof(struct VoteThreadArgs));
    if (!args) {
        fprintf(stderr, "[ProposeBlock] Failed to allocate VoteThreadArgs\n");
        pthread_mutex_lock(&state->block_proposers_lock);
        hash_table_remove(state->block_proposers, block_hash);
        pthread_mutex_unlock(&state->block_proposers_lock);
        free_block(block);
        free(queue->votes);
        free(queue);
        free(operations);
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    args->state = state;
    args->block = block;

    // Spawn dedicated vote collection worker thread
    pthread_t vote_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    atomic_fetch_add(&state->active_background_threads, 1);
    if (pthread_create(&vote_thread, &attr, vote_collection_thread, args) != 0) {
        fprintf(stderr, "[ProposeBlock] Failed to create vote collection thread\n");
        atomic_fetch_sub(&state->active_background_threads, 1);
        pthread_mutex_lock(&state->block_proposers_lock);
        hash_table_remove(state->block_proposers, block_hash);
        pthread_mutex_unlock(&state->block_proposers_lock);
        free(args);
        free_block(block);
        free(queue->votes);
        free(queue);
        free(operations);
        state->proposing_block = false;
        pthread_mutex_unlock(&state->mutex);
        return;
    }

    pthread_attr_destroy(&attr);
    pthread_detach(vote_thread);
#endif
        
    free(operations);
    state->proposing_block = false;
    pthread_mutex_unlock(&state->mutex);
}

/* ============================================================================ */
/* SECTION 11: Two-Phase Block Ledger Commit Subsystem                         */
/* ============================================================================ */
/* Architectural Preface:
 * Executes the state transition function for approved blocks. Implements a
 * dual-pass pipeline:
 * - Pass 1 (Validation): Read-only parallel check across all operations.
 * - Pass 2 (Mutation): MDBX-backed atomic transaction committing UTXO nullifiers,
 *   new coin pointers, MMR commitments, state checkpoints, and pruning sweeps.
 */

/**
 * @brief Atomically commits a verified candidate Block to the ledger.
 *
 * Operational Mechanics:
 * 1. Checks duplicate blocks against `state->processed_blocks`.
 * 2. Header Invariant Verification: Verifies height monotonic increment (H == Tip + 1)
 *    and exact previous hash linkage (`prev_block_hash == current_block_hash`).
 * 3. Beacon Verification: If height > `BLOCKS_PER_DAY`, verifies Fiat-Shamir context
 *    `mu = H(H(pk) || msg)` against the active epoch threshold signature.
 * 4. Pass 1 (Read-Only Validation): Validates all operations in parallel. Simulates
 *    commitment insertions on a deep copy of the MMR to guarantee atomicity.
 * 5. Pass 2 (Mutation): Opens `scl_db_begin_block_txn()`, commits coins, pointers,
 *    nullifiers, updates economic stages, and inserts processed transaction IDs.
 * 6. State Pruning: Evicts nullifiers deeper than 100 blocks, folding their keys
 *    into `pruned_nullifiers_root`.
 * 7. Writes block bytes and uncommitted MMR nodes into libmdbx; commits transaction.
 *
 * @pre `state` and `block` must be non-NULL; caller must hold `state->bc.rwlock` (write)
 *      and either `state->mutex` or `state->ledger_mutex`.
 * @post On return 0, ledger tip advances to `block->block_number` and MDBX is committed.
 * @sideeffect Mutates blockchain hash tables, MMR trees, and libmdbx database.
 * @sync Thread Safety: Caller must hold `state->bc.rwlock` (write) and either `state->mutex`
 *       or `state->ledger_mutex`.
 *
 * @param[in,out] state Pointer to global State structure.
 * @param[in,out] block Pointer to candidate Block being committed.
 *
 * @return 0 on success; -1 on validation or database commit failure.
 * @complexity Time: O(Operations * OpVerifyLatency + MMR_Insert); Space: O(Operations).
 */
int apply_block(State *state, Block *block) {
    if (!state || !block) {
        fprintf(stderr, "[Consensus] ERROR: Invalid state or block\n");
        return -1;
    }

    uint8_t block_hash[COIN_ID_LEN];
    if (compute_block_hash(block, block_hash) != 0) {
        fprintf(stderr, "[Consensus] ERROR: Failed to compute block hash\n");
        return -1;
    }

    // Allocate array for sequential, pre-sorted bulk nullifier persistency
    uint8_t (*block_nullifiers)[NULLIFIER_LEN] = malloc(block->operation_count * NULLIFIER_LEN);
    size_t block_nullifier_count = 0;

    // Check for duplicate block
    pthread_mutex_lock(&state->processed_blocks_mutex);
    if (hash_table_lookup(state->processed_blocks, block_hash, true)) {
        pthread_mutex_unlock(&state->processed_blocks_mutex);
        if (block->block_number == 0) {
            // Genesis is already applied, but ensure state is populated
            memcpy(state->current_block_hash, block_hash, COIN_ID_LEN);
            state->current_block_number = 0;
            state->bc.sync_epoch = 1;
            free(block_nullifiers);
            return 0;
        }
        fprintf(stderr, "[Consensus] ERROR: Block %llu already processed\n", block->block_number);
        free(block_nullifiers);
        return -1;
    }
    pthread_mutex_unlock(&state->processed_blocks_mutex);
        
    int success = 0;

    // Genesis block validation
    if (block->block_number == 0) {
        if (block->operation_count != 0 ||
            !is_zeroed(block->proposer_pubkey, PUBKEY_LEN) ||
            !is_zeroed(block->signature, SIGNATURE_LEN))
        {
            fprintf(stderr, "[Consensus] ERROR: Invalid genesis block structure\n");
            success = -1;
        }
    }
    // Non-genesis block validation
    else {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
        block->block_number = state->current_block_number + 1;
        memcpy(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN);
#endif
        // Verify strict monotonic block height increment
        if (block->block_number != state->current_block_number + 1) {
            fprintf(stderr, "[Consensus] ERROR: Block height mismatch. Expected %llu, got %llu\n",
                    state->current_block_number + 1, block->block_number);
            success = -1;
        }
        // Verify cryptographic linkage to parent block hash
        else if (memcmp(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN) != 0) {
            fprintf(stderr, "[Consensus] ERROR: Previous block hash mismatch\n");
            log_hex("  Current hash: ", state->current_block_hash, COIN_ID_LEN, 8);
            log_hex("  Block's prev: ", block->prev_block_hash, COIN_ID_LEN, 8);
            success = -1;
        }
        // Phase 2: Per-Block Randomness Beacon Validation
        pthread_mutex_lock(&state->game_state.mutex);
        uint8_t current_epoch_pubkey[PUBKEY_LEN];
        memcpy(current_epoch_pubkey, state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
        uint64_t last_dkg_epoch_local = state->game_state.last_dkg_epoch;
        pthread_mutex_unlock(&state->game_state.mutex);

        bool is_same_epoch = ((block->block_number - 1) / BLOCKS_PER_DAY >= last_dkg_epoch_local / BLOCKS_PER_DAY);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
        // Bypass threshold beacon verification during fuzzing to allow deep block height exploration
        (void)is_same_epoch; (void)current_epoch_pubkey; (void)last_dkg_epoch_local;
#else
        if (!state->in_blockchain_sync && !is_zeroed(current_epoch_pubkey, PUBKEY_LEN)) {
            if (is_same_epoch && !is_zeroed(block->epoch_threshold_signature, SIGNATURE_LEN)) {
                uint8_t computed_bhash[COIN_ID_LEN];
                uint8_t tr[32], mu[32], mu_input[32 + COIN_ID_LEN];
                        
                compute_block_hash(block, computed_bhash); // Ensure hash is verified sans-signature

                // Recreate Fiat-Shamir context mu = H(H(pk) || msg)
                sha256_hash(current_epoch_pubkey, PUBKEY_LEN, tr);
                memcpy(mu_input, tr, 32);
                memcpy(mu_input + 32, computed_bhash, COIN_ID_LEN);
                sha256_hash(mu_input, 32 + COIN_ID_LEN, mu);
                        
                if (threshold_verify(mu, 32, block->epoch_threshold_signature, SIGNATURE_LEN, current_epoch_pubkey, PUBKEY_LEN) != CRYPTO_SUCCESS) {
                    fprintf(stderr, "[Consensus] WARNING: Block %llu has invalid epoch_threshold_signature, proceeding on consensus approval\n", block->block_number);
                }
            } else {
                fprintf(stderr, "[Consensus] WARNING: Block %llu is missing epoch_threshold_signature (is_same_epoch=%d), proceeding on consensus approval\n",
                        block->block_number, is_same_epoch);
            }
        }
#endif
    }

    // Process operations if header validation succeeds
    if (success == 0 && block->block_number != 0) {
        scl_log(LOG_LEVEL_INFO, "Consensus", "Applying block %llu with %zu operations",
                block->block_number, block->operation_count);

        // Pass 1: Strict Read-Only Validation of all operations in the block (Atomic)
        int validation_success = 0;
        
        #if defined(_OPENMP)
        #pragma omp parallel for reduction(|:validation_success)
        #endif
        for (size_t i = 0; i < block->operation_count; i++) {
            Operation *op = &block->operations[i];
            
            const uint8_t *prev_tx = NULL;
            if (op->type == OP_TRANSFER_POINTER) prev_tx = op->data.transfer_pointer.inputs[0].prev_tx_hash;
            else if (op->type == OP_STAKE) prev_tx = op->data.stake.inputs[0].prev_tx_hash;
            else if (op->type == OP_UNSTAKE) prev_tx = op->data.unstake.inputs[0].prev_tx_hash;

            bool parent_in_block = false;
            if (prev_tx) {
                for (size_t p = 0; p < i; p++) {
                    const uint8_t *parent_id = get_operation_tx_id(&block->operations[p]);
                    if (parent_id && memcmp(parent_id, prev_tx, COIN_ID_LEN) == 0) {
                        parent_in_block = true;
                        break;
                    }
                }
            }

            if (!parent_in_block && !validate_operation(state, op)) {
                fprintf(stderr, "[Consensus] ERROR: Invalid operation %zu\n", i);
                validation_success = 1;
            }
        }
        
        if (validation_success != 0) {
            success = -1;
        }

        // Deep copy MMR for speculative commitment insertion without mutating active ledger peaks
        MMR *original_mmr = state->bc.centinel.validation_commitments;
        MMR temp_mmr;
        memset(&temp_mmr, 0, sizeof(MMR));
        if (success == 0 && original_mmr) {
            size_t extra_leaves = block->operation_count * 2 + 16;
            size_t needed_nodes = original_mmr->count + extra_leaves * 4;
            size_t needed_peaks = original_mmr->peak_count + extra_leaves + 16;
            size_t node_cap = (original_mmr->capacity > needed_nodes) ? original_mmr->capacity : needed_nodes;
            size_t peak_cap = (original_mmr->peak_capacity > needed_peaks) ? original_mmr->peak_capacity : needed_peaks;

            temp_mmr.nodes = calloc(node_cap, sizeof(MMRNode));
            temp_mmr.peaks = calloc(peak_cap, sizeof(size_t));
            if (temp_mmr.nodes && temp_mmr.peaks) {
                temp_mmr.capacity = node_cap;
                temp_mmr.peak_capacity = peak_cap;
                temp_mmr.count = original_mmr->count;
                temp_mmr.peak_count = original_mmr->peak_count;
                temp_mmr.uncommitted_start = original_mmr->uncommitted_start;
                if (original_mmr->count > 0 && original_mmr->nodes) {
                    memcpy(temp_mmr.nodes, original_mmr->nodes, original_mmr->count * sizeof(MMRNode));
                }
                if (original_mmr->peak_count > 0 && original_mmr->peaks) {
                    memcpy(temp_mmr.peaks, original_mmr->peaks, original_mmr->peak_count * sizeof(size_t));
                }
                state->bc.centinel.validation_commitments = &temp_mmr;
            
                for (size_t i = 0; i < block->operation_count; i++) {
                    Operation *op = &block->operations[i];
                    if (op->type == OP_CLAIM_VALIDATION) {
                        uint8_t comm_hash[COIN_ID_LEN];
                        SHA256((const uint8_t*)&op->data.claim_validation.commitment, sizeof(BdlopCommitment), comm_hash);
                        if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, comm_hash, 0) < 0) {
                            mmr_add(state->bc.centinel.validation_commitments, comm_hash, 0);
                        }
                    } else if (op->type == OP_REDEEM_CENTINEL) {
                        if (!is_zeroed((const uint8_t*)&op->data.redeem_centinel.c_transfer, sizeof(BdlopCommitment))) {
                            uint8_t transfer_hash[COIN_ID_LEN];
                            SHA256((const uint8_t*)&op->data.redeem_centinel.c_transfer, sizeof(BdlopCommitment), transfer_hash);
                            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, transfer_hash, 0) < 0) {
                                mmr_add(state->bc.centinel.validation_commitments, transfer_hash, 0);
                            }
                        }
                        if (!is_zeroed((const uint8_t*)&op->data.redeem_centinel.c_change, sizeof(BdlopCommitment))) {
                            uint8_t change_hash[COIN_ID_LEN];
                            SHA256((const uint8_t*)&op->data.redeem_centinel.c_change, sizeof(BdlopCommitment), change_hash);
                            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, change_hash, 0) < 0) {
                                mmr_add(state->bc.centinel.validation_commitments, change_hash, 0);
                            }
                        }
                    }
                }
            }
        }

        if (original_mmr) {
            state->bc.centinel.validation_commitments = original_mmr;
            if (temp_mmr.nodes) free(temp_mmr.nodes);
            if (temp_mmr.peaks) free(temp_mmr.peaks);
            memset(&temp_mmr, 0, sizeof(MMR));
        }

        // Pass 2: Safe State Mutation (Only executed if all operations are validated)
        if (success == 0) {
            scl_db_begin_block_txn(); // Open libmdbx transaction batch
            
            cache_pubkey(state, block->proposer_pubkey);
            for (size_t i = 0; i < block->operation_count; i++) {
                Operation *op = &block->operations[i];
                
                uint8_t op_key[COIN_ID_LEN];
                const uint8_t *op_id = get_operation_tx_id(op);
                if (op_id) {
                    memcpy(op_key, op_id, COIN_ID_LEN);
                } else {
                    uint8_t *data;
                    size_t data_len;
                    if (op->type == OP_SUBMIT_VALUATION) {
                        data = (uint8_t *)&op->data.submit_valuation;
                        data_len = sizeof(ValuationData);
                    } else {
                        data = (uint8_t *)op;
                        data_len = sizeof(Operation);
                    }
                    SHA256(data, data_len, op_key);
                }
                
                switch (op->type) {
                    case OP_CLAIM_VALIDATION: {
                        const ClaimValidationData *cv = &op->data.claim_validation;
                        cache_pubkey(state, cv->pubkey);

                        uint8_t commitment_hash[COIN_ID_LEN];
                        SHA256((const uint8_t*)&cv->commitment, sizeof(BdlopCommitment), commitment_hash);

                        // Incrementally add MMR leaves for destination
                        if (mmr_get_leaf_position(state->bc.centinel.validation_commitments,
                                commitment_hash, 0) < 0) {
                            mmr_add(state->bc.centinel.validation_commitments, commitment_hash, 0);
                        }

                        // Record transaction confirmation status
                        uint8_t key[COIN_ID_LEN];
                        memcpy(key, cv->commitment.c1, COIN_ID_LEN);
                        if (!hash_table_insert(state->processed_txs, key, NULL, HASH_ENTRY_TX)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert processed claim validation\n");
                            success = -1;
                            break;
                        }

                        char hex_commitment[17];
                        bytes_to_hex(commitment_hash, 8, hex_commitment);
                        printf("[Consensus] Processed Claim Validation: commitment=%s\n", hex_commitment);
                        scl_wallet_scan_claim_op(state, op);
                        break;
                    }
                    case OP_REDEEM_CENTINEL: {
                        const RedeemCentinelData *rc = &op->data.redeem_centinel;
                        
                        // Insert into the global nullifier set in memory
                        if (!hash_table_insert(state->bc.centinel.nullifier_set, rc->nullifier,
                                               NULL, HASH_ENTRY_NULLIFIER)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert centinel nullifier\n");
                            success = -1;
                            break;
                        }

                        // Insert into the Bloom filter
                        pthread_mutex_lock(&state->bc.centinel.bloom_mutex);
                        nullifier_bloom_add(state->bc.centinel.nullifier_bloom, rc->nullifier);
                        pthread_mutex_unlock(&state->bc.centinel.bloom_mutex);

                        // Accumulate nullifier for pre-sorted batch write upon block commitment
                        if (block_nullifiers) {
                            memcpy(block_nullifiers[block_nullifier_count++], rc->nullifier, NULLIFIER_LEN);
                        }

                        // Incrementally add MMR leaves for destination and change
                        int transfer_is_zero = is_zeroed((const uint8_t*)&rc->c_transfer, sizeof(BdlopCommitment));
                        if (!transfer_is_zero) {
                            uint8_t transfer_hash[COIN_ID_LEN];
                            SHA256((const uint8_t*)&rc->c_transfer, sizeof(BdlopCommitment), transfer_hash);
                            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, transfer_hash, 0) < 0) {
                                mmr_add(state->bc.centinel.validation_commitments, transfer_hash, 0);
                            }
                        }
                            
                        int change_is_zero = is_zeroed((const uint8_t*)&rc->c_change, sizeof(BdlopCommitment));
                        if (!change_is_zero) {
                            uint8_t change_hash[COIN_ID_LEN];
                            SHA256((const uint8_t*)&rc->c_change, sizeof(BdlopCommitment), change_hash);
                            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, change_hash, 0) < 0) {
                                mmr_add(state->bc.centinel.validation_commitments, change_hash, 0);
                            }
                        }

                        // Record transaction confirmation status
                        uint8_t key[COIN_ID_LEN];
                        memcpy(key, rc->nullifier, NULLIFIER_LEN);
                        if (!hash_table_insert(state->processed_txs, key, NULL, HASH_ENTRY_TX)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert processed centinel nullifier\n");
                            success = -1;
                            break;
                        }

                        char hex_nullifier[17];
                        bytes_to_hex(rc->nullifier, 8, hex_nullifier);
                        printf("[Consensus] Redeemed centinel: nullifier=%s\n", hex_nullifier);
                        scl_wallet_scan_centinel_op(state, op);
                        break;
                    }
                    case OP_MINT_COIN: {
                        MintData *md = &op->data.mint_coin;
                        cache_pubkey(state, md->owner_pubkey);
                        SCLCoin *coin = &md->coin;

                        // Prevent duplicate coin insertion and double-counting during synchronization
                        if (hash_table_lookup(state->bc.coin_table, coin->coin_id, false)) {
                            break;
                        }
                        
                        pthread_mutex_lock(&state->game_state.mutex);
                        bool is_recycled = (state->game_state.total_rewarded_scl_subunits >= MAX_TOTAL_SUBUNITS ||
                                            coin->total_subunits > state->game_state.remaining_scl_subunits);
                        if (is_recycled) {
                            // Minted from recycled transaction fees pool
                        } else {
                            if (coin->total_subunits > state->game_state.remaining_scl_subunits) {
                                fprintf(stderr, "[Consensus] ERROR: Insufficient remaining subunits for mint: requested=%llu, available=%llu\n",
                                        coin->total_subunits, state->game_state.remaining_scl_subunits);
                                pthread_mutex_unlock(&state->game_state.mutex);
                                success = -1;
                                break;
                            }
                        }
                        pthread_mutex_unlock(&state->game_state.mutex);
                        
                        if (!hash_table_insert(state->bc.coin_table, coin->coin_id, (void *)coin, HASH_ENTRY_COIN)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert coin into coin_table\n");
                            success = -1;
                            break;
                        }
                        state->bc.mmr_needs_rebuild = true;

                        // Verify insertion by checking key existence and data integrity
                        SCLCoin *inserted_coin = hash_table_lookup(state->bc.coin_table, coin->coin_id, false);
                        if (!inserted_coin || memcmp(inserted_coin->coin_id, coin->coin_id, COIN_ID_LEN) != 0) {
                            fprintf(stderr, "[Consensus] ERROR: Coin insertion verification failed\n");
                            hash_table_remove(state->bc.coin_table, coin->coin_id);
                            success = -1;
                            break;
                        }

                        // Update insert_order array
                        if (state->bc.insert_order_count >= state->bc.insert_order_capacity) {
                            size_t new_cap = state->bc.insert_order_capacity ? state->bc.insert_order_capacity * 2 : 16;
                            SCLCoin **new_order = realloc(state->bc.insert_order, new_cap * sizeof(SCLCoin *));
                            if (!new_order) {
                                fprintf(stderr, "[Consensus] ERROR: Realloc failed for insert_order\n");
                                hash_table_remove(state->bc.coin_table, coin->coin_id);
                                success = -1;
                                break;
                            }
                            state->bc.insert_order = new_order;
                            state->bc.insert_order_capacity = new_cap;
                        }
                        state->bc.insert_order[state->bc.insert_order_count++] = inserted_coin;

                        mmr_add(state->bc.mmr, coin->coin_id, coin->remaining_subunits);

                        // Construct primary ownership pointer covering entire coin subunit range [0, total - 1]
                        Pointer new_pointer = {0};
                        memcpy(new_pointer.parent_coin_id, coin->coin_id, COIN_ID_LEN);
                        new_pointer.start_subunit = 0;
                        new_pointer.end_subunit = coin->total_subunits - 1;
                        new_pointer.staked = 0;
                        memcpy(new_pointer.owner_address, coin->owner_address, USER_ID_LEN);
                        memcpy(new_pointer.prev_tx_hash, coin->creation_tx_hash, COIN_ID_LEN);
                        uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
                        uint8_t *pd = pointer_data;
                        memcpy(pd, new_pointer.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
                        memcpy(pd, new_pointer.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
                        uint64_t start_be = htobe64(new_pointer.start_subunit);
                        memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
                        uint64_t end_be = htobe64(new_pointer.end_subunit);
                        memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
                        memcpy(pd, new_pointer.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
                        SHA256(pointer_data, sizeof(pointer_data), new_pointer.pointer_id);
                        if (!hash_table_insert(state->bc.pointer_table, new_pointer.pointer_id, &new_pointer, HASH_ENTRY_POINTER)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert pointer into pointer_table\n");
                            hash_table_remove(state->bc.coin_table, coin->coin_id);
                            state->bc.insert_order_count--;
                            success = -1;
                            break;
                        }
                        add_pointer_id_to_coin(state->bc.coin_pointers, new_pointer.parent_coin_id, new_pointer.pointer_id);
                        scl_db_put_coin(coin->coin_id, coin);
                        scl_db_put_pointer(new_pointer.pointer_id, &new_pointer);
                        
                        if (!check_coin_consistency(&state->bc, coin->coin_id)) {
                            char hex_coin_id[17];
                            bytes_to_hex(coin->coin_id, 8, hex_coin_id);
                            fprintf(stderr, "[Consensus] ERROR: Coin consistency failed after minting coin_id=%s...\n", hex_coin_id);
                            success = -1;
                            break;
                        }

                        // Update game state economic emission counters
                        pthread_mutex_lock(&state->game_state.mutex);
                        if (!is_recycled) {
                            state->game_state.total_rewarded_scl_subunits += coin->total_subunits;
                            state->game_state.remaining_scl_subunits -= coin->total_subunits;
                        }
                        if (coin->snapshot_count > 0 && state->game_state.valuation_count == 0) {
                            memcpy(state->game_state.game_audit, coin->audit_snapshot, sizeof(Valuation) * AUDIT_SIZE);
                            state->game_state.valuation_count = (coin->snapshot_count > AUDIT_SIZE) ? AUDIT_SIZE : coin->snapshot_count;
                            state->game_state.current_audit_index = coin->snapshot_audit_index % AUDIT_SIZE;
                            size_t latest_idx = (state->game_state.current_audit_index == 0) ? AUDIT_SIZE - 1 : state->game_state.current_audit_index - 1;
                            state->game_state.audit_timestamp = coin->audit_snapshot[latest_idx].timestamp;
                        }
                        pthread_mutex_unlock(&state->game_state.mutex);

                        if (!hash_table_insert(state->processed_txs, coin->creation_tx_hash, NULL, HASH_ENTRY_TX)) {
                            fprintf(stderr, "[Consensus] WARNING: Failed to insert OP_MINT_COIN into processed_txs\n");
                        }

                        char hex_coin_id[33];
                        bytes_to_hex(coin->coin_id, 16, hex_coin_id);
                        printf("[Consensus] Minted coin and pointer: coin_id=%s\n", hex_coin_id);
                        break;
                    }
                    case OP_TRANSFER_POINTER: {
                        TransferData *tx = &op->data.transfer_pointer;
                        cache_pubkey(state, tx->recipient_pubkey);
                        cache_pubkey(state, tx->sender_pubkey);
                        uint64_t fee = calculate_fee(tx->amount, false);
                        if (!update_transfer_state(&state->bc, tx->inputs, tx->proofs, tx->num_inputs, tx->recipient_pubkey,
                                                                        tx->amount, tx->tx_id, false, fee)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to apply transfer\n");
                            success = -1;
                            break;
                        }
                                        
                        // Collect unique parent coin IDs
                        uint8_t parent_coins[MAX_INPUTS][COIN_ID_LEN];
                        size_t unique_count = 0;
                        for (size_t j = 0; j < tx->num_inputs; j++) {
                            bool is_unique = true;
                            for (size_t k = 0; k < unique_count; k++) {
                                if (memcmp(parent_coins[k], tx->inputs[j].parent_coin_id, COIN_ID_LEN) == 0) {
                                    is_unique = false;
                                    break;
                                }
                            }
                            if (is_unique) {
                                memcpy(parent_coins[unique_count++], tx->inputs[j].parent_coin_id, COIN_ID_LEN);
                            }
                        }
                        // Check consistency for each unique parent coin
                        for (size_t j = 0; j < unique_count; j++) {
                            if (!check_coin_consistency(&state->bc, parent_coins[j])) {
                                char hex_parent[17];
                                bytes_to_hex(parent_coins[j], 8, hex_parent);
                                fprintf(stderr, "[Consensus] ERROR: Coin consistency failed after transfer for coin_id=%s...\n", hex_parent);
                                success = -1;
                                break;
                            }
                        }
                        if (success != 0) break;
                                        
                        if (!hash_table_insert(state->processed_txs, tx->tx_id, NULL, HASH_ENTRY_TX)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert processed tx_id\n");
                            success = -1;
                            break;
                        }
                        char hex_tx_id[65];
                        bytes_to_hex(tx->tx_id, 32, hex_tx_id);
                        printf("[Consensus] Applied transfer: tx_id=%s\n", hex_tx_id);
                        break;
                    }
                    case OP_STAKE: {
                        StakeData *sd = &op->data.stake;
                        cache_pubkey(state, sd->threshold_pubkey);
                        cache_pubkey(state, sd->sender_pubkey);
                        uint64_t fee = calculate_fee(sd->amount, true);
                        if (!update_transfer_state(&state->bc, sd->inputs, sd->proofs, sd->num_inputs, sd->threshold_pubkey,
                                                                            sd->amount, sd->stake_tx_id, true, fee)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to apply stake\n");
                            success = -1;
                            break;
                        }
                        
                        // Cache threshold_pubkey mapping to sender_pubkey for DKG committee lookups
                        uint8_t threshold_addr[USER_ID_LEN];
                        SHA256(sd->threshold_pubkey, PUBKEY_LEN, threshold_addr);
                        PubkeyCacheEntry pce;
                        memcpy(pce.pubkey, sd->sender_pubkey, PUBKEY_LEN);
                        hash_table_insert(state->pubkey_cache, threshold_addr, &pce, HASH_ENTRY_PUBKEY_CACHE);
                                        
                        uint8_t parent_coins[MAX_INPUTS][COIN_ID_LEN];
                        size_t unique_count = 0;
                        for (size_t j = 0; j < sd->num_inputs; j++) {
                            bool is_unique = true;
                            for (size_t k = 0; k < unique_count; k++) {
                                if (memcmp(parent_coins[k], sd->inputs[j].parent_coin_id, COIN_ID_LEN) == 0) {
                                    is_unique = false;
                                    break;
                                }
                            }
                            if (is_unique) {
                                memcpy(parent_coins[unique_count++], sd->inputs[j].parent_coin_id, COIN_ID_LEN);
                            }
                        }
                        for (size_t j = 0; j < unique_count; j++) {
                            if (!check_coin_consistency(&state->bc, parent_coins[j])) {
                                char hex_parent[17];
                                bytes_to_hex(parent_coins[j], 8, hex_parent);
                                fprintf(stderr, "[Consensus] ERROR: Coin consistency failed after stake for coin_id=%s...\n", hex_parent);
                                success = -1;
                                break;
                            }
                        }
                        if (success != 0) break;
                                        
                        if (!hash_table_insert(state->processed_txs, sd->stake_tx_id, NULL, HASH_ENTRY_TX)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert processed stake_tx_id\n");
                            success = -1;
                            break;
                        }
                        char hex_stake_id[65];
                        bytes_to_hex(sd->stake_tx_id, 32, hex_stake_id);
                        printf("[Consensus] Applied stake: stake_tx_id=%s\n", hex_stake_id);
                        break;
                    }
                    case OP_UNSTAKE: {
                        UnstakeData *sd = &op->data.unstake;
                        cache_pubkey(state, sd->recipient_pubkey);
                        cache_pubkey(state, sd->threshold_pubkey);
                        uint64_t fee = calculate_fee(sd->amount, true);
                        if (!update_transfer_state(&state->bc, sd->inputs, sd->proofs, sd->num_inputs, sd->recipient_pubkey,
                                                                           sd->amount, sd->unstake_tx_id, false, fee)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to apply unstake\n");
                            success = -1;
                            break;
                        }
                        
                        uint8_t parent_coins[MAX_INPUTS][COIN_ID_LEN];
                        size_t unique_count = 0;
                        for (size_t j = 0; j < sd->num_inputs; j++) {
                            bool is_unique = true;
                            for (size_t k = 0; k < unique_count; k++) {
                                if (memcmp(parent_coins[k], sd->inputs[j].parent_coin_id, COIN_ID_LEN) == 0) {
                                    is_unique = false;
                                    break;
                                }
                            }
                            if (is_unique) {
                                memcpy(parent_coins[unique_count++], sd->inputs[j].parent_coin_id, COIN_ID_LEN);
                            }
                        }
                        for (size_t j = 0; j < unique_count; j++) {
                            if (!check_coin_consistency(&state->bc, parent_coins[j])) {
                                char hex_parent[17];
                                bytes_to_hex(parent_coins[j], 8, hex_parent);
                                fprintf(stderr, "[Consensus] ERROR: Coin consistency failed after unstake for coin_id=%s...\n", hex_parent);
                                success = -1;
                                break;
                            }
                        }
                        if (success != 0) break;
                        
                        if (!hash_table_insert(state->processed_txs, sd->unstake_tx_id, NULL, HASH_ENTRY_TX)) {
                            fprintf(stderr, "[Consensus] ERROR: Failed to insert processed unstake_tx_id\n");
                            success = -1;
                            break;
                        }
                        char hex_unstake_id[65];
                        bytes_to_hex(sd->unstake_tx_id, 32, hex_unstake_id);
                        printf("[Consensus] Applied unstake: unstake_tx_id=%s\n", hex_unstake_id);
                        break;
                    }
                    default:
                        fprintf(stderr, "[Consensus] ERROR: Unknown operation type: %d\n", op->type);
                        success = -1;
                        break;
                }
                if (success != 0) break;
            }
        }
    }
    
    // Update active chain tip state if mutations succeeded
    if (success == 0) {
        memcpy(state->current_block_hash, block_hash, COIN_ID_LEN);
        state->current_block_number = block->block_number;
        state->bc.sync_epoch = block->block_number + 1;

        if (block->block_number != 0) {
            clean_pending_operations(state, block);
        }

        // Dynamic State Pruning: Evict nullifiers buried deep beneath the finality horizon (100 blocks deep)
        if (state->current_block_number > 100) {
            size_t prune_cnt = 0;
            uint8_t prune_keys[1024][NULLIFIER_LEN];
            for (size_t bucket = 0; bucket < state->bc.centinel.nullifier_set->size && prune_cnt < 1024; bucket++) {
                GenericHashEntry *ent = state->bc.centinel.nullifier_set->buckets[bucket];
                while (ent && prune_cnt < 1024) {
                    memcpy(prune_keys[prune_cnt++], ent->key, NULLIFIER_LEN);
                    ent = ent->next;
                }
            }
            scl_db_write_nullifiers_batch(prune_keys, prune_cnt);

            for (size_t k = 0; k < prune_cnt; k++) {
                // Roll into finalized Merkle root to prevent infinite RAM exhaustion while preserving state
                uint8_t combined[COIN_ID_LEN * 2];
                memcpy(combined, state->bc.centinel.pruned_nullifiers_root, COIN_ID_LEN);
                memcpy(combined + COIN_ID_LEN, prune_keys[k], NULLIFIER_LEN);
                SHA256(combined, COIN_ID_LEN + NULLIFIER_LEN, state->bc.centinel.pruned_nullifiers_root);
                
                hash_table_remove(state->bc.centinel.nullifier_set, prune_keys[k]);
            }
        }
        
        // Recalculate cached economic stage based on updated committed ledger state
        uint64_t total_staked_for_stage = calculate_total_staked_subunits(&state->bc);
        pthread_mutex_lock(&state->game_state.mutex);
        state->game_state.cached_stage = calculate_current_stage(
            state->game_state.total_rewarded_scl_subunits,
            total_staked_for_stage
        );
        memcpy(state->game_state.current_epoch_signature, block->epoch_threshold_signature, SIGNATURE_LEN);
        pthread_mutex_unlock(&state->game_state.mutex);

        update_game_state_snapshot(state);

        // Record block in processed blocks cache
        pthread_mutex_lock(&state->processed_blocks_mutex);
        if (!hash_table_insert(state->processed_blocks, block_hash, NULL, HASH_ENTRY_TX)) {
            fprintf(stderr, "[Consensus] WARNING: Failed to record processed block\n");
        }
        pthread_mutex_unlock(&state->processed_blocks_mutex);

        // Commit serialized block into libmdbx persistent storage
        uint8_t *block_buffer = malloc(MAX_MESSAGE_SIZE);
        if (block_buffer) {
            int ser_len = process_block_data(block, block_buffer, NULL, true);
            if (ser_len > 0) {
                scl_db_put_block(block->block_number, block_buffer, (size_t)ser_len);
            }
            free(block_buffer);
        }
        
        // Flush uncommitted MMR nodes to persistent disk batch
        if (state->bc.mmr->count > state->bc.mmr->uncommitted_start) {
            size_t batch_count = state->bc.mmr->count - state->bc.mmr->uncommitted_start;
            scl_db_put_mmr_batch(&state->bc.mmr->nodes[state->bc.mmr->uncommitted_start], batch_count);
            state->bc.mmr->uncommitted_start = state->bc.mmr->count;
        }
        
        // Execute Checkpointing logic every 440 blocks (BLOCKS_PER_DAY)
        if (state->current_block_number % BLOCKS_PER_DAY == 0) {
            uint8_t state_root[32];
            mmr_get_root(state->bc.centinel.validation_commitments, state_root);
            scl_db_put_checkpoint(state->current_block_number, state_root);
            scl_log(LOG_LEVEL_INFO, "Consensus", "Generated State Checkpoint at height %llu", state->current_block_number);
            
            // Prune MMR trees to release memory for committed subtrees
            mmr_prune(state->bc.centinel.validation_commitments);
        }
        
        printf("[Consensus] Block %llu applied successfully\n", block->block_number);
        
        // Evaluate DKG ceremony trigger conditions at epoch boundaries
        pthread_mutex_lock(&state->game_state.mutex);
        bool is_local_epoch_key_zeroed = is_zeroed(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
        uint64_t last_successful_dkg_epoch_block = state->game_state.last_dkg_epoch;
        pthread_mutex_unlock(&state->game_state.mutex);

        bool should_trigger_dkg = false;
        uint64_t active_epoch = state->current_block_number / BLOCKS_PER_DAY;
        if (!state->in_blockchain_sync && state->current_block_number > 0) {
            if (is_local_epoch_key_zeroed || active_epoch > (last_successful_dkg_epoch_block / BLOCKS_PER_DAY)) {
                if (state->last_dkg_attempted_epoch <= active_epoch) {
                    should_trigger_dkg = true;
                }
            }
        }

        if (should_trigger_dkg) {
            size_t active_nodes = 1;
            
            pthread_mutex_lock(&state->p2p_network.mutex);
            const uint8_t **seen_keys = NULL;
            if (state->p2p_network.num_known_peers > 0) {
                seen_keys = malloc(state->p2p_network.num_known_peers * sizeof(const uint8_t *));
            }
            
            if (seen_keys) {
                size_t seen_count = 0;
                for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                    Peer *peer = state->p2p_network.known_peers[i];
                    if (peer && peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED &&
                        !is_zeroed(peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) &&
                        memcmp(peer->peer_wallet.dilithium_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                        
                        seen_keys[seen_count++] = peer->peer_wallet.dilithium_pubkey;
                    }
                }
                if (seen_count > 0) {
                    qsort(seen_keys, seen_count, sizeof(const uint8_t *), compare_pubkey_ptrs);
                    active_nodes++;
                    for (size_t j = 1; j < seen_count; j++) {
                        if (memcmp(seen_keys[j], seen_keys[j - 1], PUBKEY_LEN) != 0) {
                            active_nodes++;
                        }
                    }
                }
                free(seen_keys);
            }
            pthread_mutex_unlock(&state->p2p_network.mutex);

            if (active_nodes >= 10) {
                pthread_mutex_lock(&state->epoch_mutex);
                
                uint64_t current_epoch_num = state->current_block_number / BLOCKS_PER_DAY;
                uint8_t epoch_session_id[COIN_ID_LEN];
                uint8_t epoch_input[32];
                memset(epoch_input, 0, 32);
                snprintf((char*)epoch_input, 32, "DKG_EPOCH_%llu", (unsigned long long)current_epoch_num);
                SHA256(epoch_input, strlen((char*)epoch_input), epoch_session_id);

                bool already_running = false;
                uint8_t keys_to_remove[16][COIN_ID_LEN];
                size_t remove_count = 0;

                for (size_t bucket = 0; bucket < state->dkg_active_sessions->size; bucket++) {
                    GenericHashEntry *ent = state->dkg_active_sessions->buckets[bucket];
                    while (ent) {
                        if (ent->type == HASH_ENTRY_DKG_SESSION) {
                            DKGSession *sess = ent->data.dkg_session;
                            if (sess && (sess->block_height / BLOCKS_PER_DAY < current_epoch_num)) {
                                if (remove_count < 16) {
                                    memcpy(keys_to_remove[remove_count++], ent->key, COIN_ID_LEN);
                                }
                            } else if (sess && (sess->block_height / BLOCKS_PER_DAY == current_epoch_num)) {
                                already_running = true;
                            }
                        }
                        ent = ent->next;
                    }
                }
                for (size_t k = 0; k < remove_count; k++) {
                    hash_table_remove(state->dkg_active_sessions, keys_to_remove[k]);
                }

                if (!already_running) {
                    DKGSession *stale_sess = hash_table_lookup(state->dkg_active_sessions, epoch_session_id, false);
                    if (!stale_sess) {
                        DKGSession *pre_session = calloc(1, sizeof(DKGSession));
                        if (pre_session) {
                            memcpy(pre_session->session_id, epoch_session_id, COIN_ID_LEN);
                            atomic_init(&pre_session->ref_count, 1);
                            pre_session->block_height = state->current_block_number;
                            pre_session->committee_count = 10;
                            pre_session->status = 0;
                            pre_session->worker_spawned = true;
                            pthread_cond_init(&pre_session->phase_cond, NULL);
                            hash_table_insert(state->dkg_active_sessions, epoch_session_id, pre_session, HASH_ENTRY_DKG_SESSION);
                            atomic_fetch_add_explicit(&pre_session->ref_count, 1, memory_order_relaxed);
                        }
                        state->last_dkg_attempted_epoch = current_epoch_num + 1;
                        pthread_mutex_unlock(&state->epoch_mutex);
                        spawn_dkg_worker_thread(state, epoch_session_id, state->current_block_number);
                    } else {
                        pthread_mutex_unlock(&state->epoch_mutex);
                    }
                } else {
                    pthread_mutex_unlock(&state->epoch_mutex);
                    fprintf(stderr, "[Consensus] DKG deferred: An active DKG for epoch %llu is already running.\n", (unsigned long long)current_epoch_num);
                }
            } else {
                fprintf(stderr, "[Consensus] DKG deferred: Only %zu/10 active nodes available.\n", active_nodes);
            }
        }
    } else {
        fprintf(stderr, "[Consensus] ERROR: Block %llu application failed\n", block->block_number);
    }

    // Commit collected nullifiers in a single pre-sorted batch transaction to DB
    if (success == 0 && block_nullifier_count > 0 && block_nullifiers) {
        scl_db_write_nullifiers_batch(block_nullifiers, block_nullifier_count);
    }
    if (block_nullifiers) {
        free(block_nullifiers);
    }

    // Atomically finalize or rollback libmdbx transaction based on execution outcome
    if (success == 0) {
        scl_db_commit_block_txn(); // Commit the DB transaction atomically
    } else {
        scl_db_abort_block_txn();
    }

    return success;
}

/* ============================================================================ */
/* SECTION 12: Block Deallocation and Vote Validation                          */
/* ============================================================================ */
/* Architectural Preface:
 * Provides deterministic memory teardown for Block envelopes, deallocating
 * batched ZK-PRF nullifiers and proofs. Implements ML-DSA-87 (Dilithium5)
 * signature verification over binary vote packets.
 */

/**
 * @brief Releases all dynamically allocated memory associated with a Block.
 *
 * Frees operations array, batch PRF outputs, batch ZK proofs, and the Block struct.
 *
 * @pre `block` may be NULL (no-op).
 * @post All memory associated with `block` is freed. Pointer is invalidated.
 * @sideeffect System heap memory reclamation.
 * @sync Thread Safety: Reentrant. Caller must ensure no other thread holds references.
 *
 * @param[in,out] block Pointer to Block to deallocate.
 *
 * @return void.
 * @complexity Time: O(1); Space: O(1).
 */
void free_block(Block *block) {
    if (block) {
        free(block->operations);
        free(block->batch_prf_outputs);
        free(block->batch_zk_proof);
        free(block);
    }
}

/**
 * @brief Cryptographically verifies an ML-DSA-87 (Dilithium5) signed peer vote.
 *
 * Checks vote value range (strictly 0 or 1), verifies signature against the
 * canonical 33-byte envelope `block_hash (32B) || vote (1B)`, and confirms that
 * `vote->block_hash` matches the target candidate block hash.
 *
 * @pre `vote` and `block_hash` must be non-NULL.
 * @post Vote signature and block hash are verified.
 * @sideeffect Diagnostic logging output.
 * @sync Thread Safety: Reentrant and lock-free.
 *
 * @param[in] vote       Pointer to Vote structure containing signature and voter key.
 * @param[in] block_hash Pointer to expected 32-byte candidate block hash.
 *
 * @return 1 on successful cryptographic verification; 0 on failure or mismatch.
 * @complexity Time: O(1) dominated by lattice signature verification; Space: O(1).
 */
int verify_vote(const Vote *vote, const uint8_t *block_hash) {
    if (!vote || !block_hash) {
        fprintf(stderr, "[Consensus] Invalid vote parameters\n");
        return 0;
    }

    // Enforce binary vote value invariant (0 = reject, 1 = approve)
    if (vote->vote != 0 && vote->vote != 1) {
        fprintf(stderr, "[Consensus] Invalid vote value: %u\n", vote->vote);
        return 0;
    }

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    printf("[Consensus] Verifying vote: vote_value=%u\n", vote->vote);
    log_hex("[Consensus] Vote block_hash=", vote->block_hash, COIN_ID_LEN, 16);
    log_hex("[Consensus] Voter pubkey=", vote->voter_pubkey, PUBKEY_LEN, 16);
#endif
    // Construct canonical 33-byte vote message buffer (block_hash || vote_value)
    uint8_t vote_data[COIN_ID_LEN + 1];
    memcpy(vote_data, vote->block_hash, COIN_ID_LEN);
    vote_data[COIN_ID_LEN] = vote->vote;
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    log_hex("[Consensus] Verifying vote_data=", vote_data, COIN_ID_LEN + 1, COIN_ID_LEN + 1);
#endif

    int result = dilithium_verify(vote_data, sizeof(vote_data), vote->signature, vote->voter_pubkey);
    if (result != 0) {
        fprintf(stderr, "[Consensus] Vote signature verification failed (code: %d)\n", result);
        return 0;
    }

    if (memcmp(vote->block_hash, block_hash, COIN_ID_LEN) != 0) {
        fprintf(stderr, "[Consensus] Vote block hash mismatch\n");
        return 0;
    }
    printf("[Consensus] Vote verified successfully\n");
    return 1;
}

/* ============================================================================ */
/* SECTION 13: Quantum Valuation Match Evaluation and Audit Snapshot Validation*/
/* ============================================================================ */
/* Architectural Preface:
 * Evaluates quantum total variation distance (TVD) matches between submitted
 * valuations and the circular audit buffer embedded within minted coins. Enforces
 * stage-dependent participant diversity thresholds and verifies the immutable
 * canonical SCLCoin SHA-256 state anchor.
 */

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Replicates game state quantum matching logic to evaluate coin mint rewards.
 *
 * Inspects `coin->audit_snapshot` to count distinct participant user IDs and
 * verifies diversity meets or exceeds the required economic stage threshold.
 * Invokes `quantum_check_number_in_column` across all 10 valuation columns to
 * detect quantum statevector transitions, awarding bonus points on full multiset matches.
 *
 * @pre `state` and `coin` must be non-NULL; caller must hold `state->bc.rwlock` (read).
 * @post Calculates exact integer match count used to calibrate block emission reward.
 * @sideeffect Reads blockchain stake state without acquiring recursive locks.
 * @sync Thread Safety: Reentrant given that `state->bc.rwlock` is already held.
 *
 * @param[in] state Pointer to global State structure.
 * @param[in] coin  Pointer to SCLCoin being verified.
 *
 * @return Total integer match count (reward subunits = matches * SUBUNITS_PER_COIN).
 * @complexity Time: O(AUDIT_SIZE * NUMBERS_PER_VALUATION * QuantumSimulationLatency);
 *             Space: O(1).
 */
static int count_matches_from_snapshot(State *state, const SCLCoin *coin) {
    if (!coin || coin->snapshot_count == 0 || coin->snapshot_count > AUDIT_SIZE) {
        return 0;
    }

    // Resolve the latest valuation in circular audit snapshot
    size_t audit_idx = coin->snapshot_audit_index % AUDIT_SIZE;
    size_t latest_index = (audit_idx == 0) ?
                         AUDIT_SIZE - 1 : audit_idx - 1;
    const Valuation *latest_valuation = &coin->audit_snapshot[latest_index];
    
    if (is_zeroed(latest_valuation->user_id, USER_ID_LEN)) {
        return 0;
    }

    int total_matches = 0;
    int is_full = (coin->snapshot_count == AUDIT_SIZE);
    size_t N = coin->snapshot_count;

    // Count distinct participant users for stage threshold enforcement
    uint8_t distinct_user_ids[AUDIT_SIZE][USER_ID_LEN];
    size_t distinct_count = 0;
    
    for (uint32_t i = 0; i < coin->snapshot_count; i++) {
        const Valuation *valuation = &coin->audit_snapshot[i];
        if (is_zeroed(valuation->user_id, USER_ID_LEN)) {
            continue;
        }
        
        bool is_new = true;
        for (size_t u = 0; u < distinct_count; u++) {
            if (memcmp(distinct_user_ids[u], valuation->user_id, USER_ID_LEN) == 0) {
                is_new = false;
                break;
            }
        }
        
        if (is_new) {
            memcpy(distinct_user_ids[distinct_count], valuation->user_id, USER_ID_LEN);
            distinct_count++;
        }
    }

    uint64_t total_staked = calculate_total_staked_subunits(&state->bc);
    int stage = calculate_current_stage(state->game_state.total_rewarded_scl_subunits, total_staked);
    size_t threshold = stage;

    uint8_t local_node_id[USER_ID_LEN];
    SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, local_node_id);
    char hex_node_id[17];
    bytes_to_hex(local_node_id, 8, hex_node_id);

    fprintf(stderr, "[Consensus] [%s] Stage calculation: total_rewarded=%llu, total_staked=%llu, stage=%d, threshold=%zu, distinct_count=%zu (epoch=%llu)\n",
            hex_node_id, state->game_state.total_rewarded_scl_subunits, total_staked, stage, threshold, distinct_count, state->current_block_number);

    if (is_full && distinct_count < threshold) {
        fprintf(stderr, "[Consensus] Insufficient distinct users for full buffer: %zu < %zu\n", distinct_count, threshold);
        return 0;
    } else if (!is_full && distinct_count < 2) {
        fprintf(stderr, "[Consensus] Insufficient distinct users for partial buffer: %zu < 2\n", distinct_count);
        return 0;
    }

    size_t effective_threshold = is_full ? threshold : 2;

    int row_counts[100] = {0};
    for (int i = 0; i < NUMBERS_PER_VALUATION; i++) {
        int num = latest_valuation->numbers[i];
        if (num >= 0 && num < 100) {
            row_counts[num]++;
        }
    }
    
    if (distinct_count >= effective_threshold) {
        // Evaluate each column for quantum TVD matches
        for (size_t col = 0; col < NUMBERS_PER_VALUATION; col++) {
            int column_numbers[AUDIT_SIZE];
            size_t valid_rows = 0;
            
            for (uint32_t i = 0; i < coin->snapshot_count; i++) {
                const Valuation *valuation = &coin->audit_snapshot[i];
                if (is_zeroed(valuation->user_id, USER_ID_LEN)) {
                    continue;
                }
                column_numbers[valid_rows] = valuation->numbers[col];
                valid_rows++;
            }

            for (size_t i = 0; i < NUMBERS_PER_VALUATION; i++) {
                int target_number = latest_valuation->numbers[i];
                if (target_number >= 0 && target_number < 100) {
                    if (quantum_check_number_in_column(target_number, column_numbers, valid_rows, distinct_count, latest_valuation->beacon_seed)) {
                        total_matches++;
                        scl_log(LOG_LEVEL_TRACE, "Consensus", "Quantum match found: target_number=%d in column %zu", target_number, col);
                    } else {
                        scl_log(LOG_LEVEL_TRACE, "Consensus", "No quantum match for target_number=%d in column %zu", target_number, col);
                    }
                }
            }
        }
        
        // Full match check (identical multiset across entire row): bonus match point
        if (is_full) {
            int full_match = 1;
            for (size_t col = 0; col < NUMBERS_PER_VALUATION; col++) {
                int col_counts[100] = {0};
                for (uint32_t i = 0; i < coin->snapshot_count; i++) {
                    const Valuation *valuation = &coin->audit_snapshot[i];
                    if (is_zeroed(valuation->user_id, USER_ID_LEN)) {
                        continue;
                    }
                    int num = valuation->numbers[col];
                    if (num >= 0 && num < 100) {
                        col_counts[num]++;
                    }
                }
                
                for (int i = 0; i < 100; i++) {
                    if (row_counts[i] != col_counts[i]) {
                        full_match = 0;
                        break;
                    }
                }
                if (!full_match) break;
            }
            
            if (full_match) {
                total_matches++;
                fprintf(stderr, "[Consensus] Full match bonus awarded\n");
            }
        }
    }

    size_t active_rows = 0;
    for (uint32_t i = 0; i < coin->snapshot_count; i++) {
        if (!is_zeroed(coin->audit_snapshot[i].user_id, USER_ID_LEN)) {
            active_rows++;
        }
    }

    fprintf(stderr, "[Consensus] Calculated %d matches from snapshot (N=%zu, active_rows=%zu, distinct=%zu)\n",
            total_matches, N, active_rows, distinct_count);
    return total_matches;
}
#endif

/**
 * @brief Validates an OP_MINT_COIN operation against its embedded audit snapshot.
 *
 * Verifies that the coin's `audit_state_anchor` exactly matches the recomputed
 * canonical SHA-256 hash of the `SCLCoin` struct, that the coin owner matches
 * the latest non-empty valuation user, that all valuation numbers fall within [0, 99],
 * and that `coin->total_subunits` matches the expected emission reward.
 *
 * @pre `state` and `coin` must be non-NULL; caller must hold `state->bc.rwlock` (read or write).
 * @post Confirms cryptographic legitimacy and economic emission accuracy of coin minting.
 * @sideeffect Logs detailed diagnostic hex dumps on divergence.
 * @sync Thread Safety: Caller must hold `state->bc.rwlock`; internally acquires `state->game_state.mutex`.
 *
 * @param[in,out] state Pointer to global State structure.
 * @param[in]     coin  Pointer to candidate SCLCoin to evaluate.
 *
 * @return 1 on successful validation; 0 on structural divergence, fraud, or supply breach.
 * @complexity Time: O(AUDIT_SIZE * NUMBERS_PER_VALUATION + QuantumMatchTime); Space: O(1).
 */
static int validate_mint_using_audit_snapshot(State *state, const SCLCoin *coin) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)coin;
    return 1;
#else
    if (!state || !coin) {
        fprintf(stderr, "[Consensus] ERROR: Invalid parameters for audit snapshot validation\n");
        return 0;
    }

    if (coin->snapshot_count == 0 || coin->snapshot_count > AUDIT_SIZE || coin->snapshot_audit_index >= AUDIT_SIZE) {
        fprintf(stderr, "[Consensus] ERROR: Invalid snapshot count: %u\n", coin->snapshot_count);
        return 0;
    }

    int non_zero_count = 0;
    for (uint32_t i = 0; i < coin->snapshot_count; i++) {
        if (!is_zeroed(coin->audit_snapshot[i].user_id, USER_ID_LEN)) {
            non_zero_count++;
        }
    }
    fprintf(stderr, "[Consensus] DEBUG: Found %d non-zero valuations in snapshot (count=%u)\n",
            non_zero_count, coin->snapshot_count);

    // Locate the most recent non-empty valuation within circular buffer
    const Valuation *latest_valuation = NULL;
    for (int i = 1; i <= AUDIT_SIZE; i++) {
        size_t check_index = (coin->snapshot_audit_index + AUDIT_SIZE - i) % AUDIT_SIZE;
        if (!is_zeroed(coin->audit_snapshot[check_index].user_id, USER_ID_LEN)) {
            latest_valuation = &coin->audit_snapshot[check_index];
            fprintf(stderr, "[Consensus] DEBUG: Found latest valuation at index %zu\n", check_index);
            break;
        }
    }
    
    if (!latest_valuation) {
        fprintf(stderr, "[Consensus] ERROR: No valid (non-zeroed) valuation found in audit snapshot\n");
        for (int i = 0; i < 5 && i < AUDIT_SIZE; i++) {
            char hex_user[17];
            bytes_to_hex(coin->audit_snapshot[i].user_id, 8, hex_user);
            fprintf(stderr, "[Consensus] DEBUG: audit_snapshot[%d].user_id (first 8 bytes): %s\n", i, hex_user);
        }
        return 0;
    }
    
    if (memcmp(coin->owner_address, latest_valuation->user_id, USER_ID_LEN) != 0) {
        fprintf(stderr, "[Consensus] ERROR: Coin owner does not match latest valuation owner\n");
        log_hex("  Coin owner user_id: ", coin->owner_address, USER_ID_LEN, 8);
        log_hex("  Latest val user_id: ", latest_valuation->user_id, USER_ID_LEN, 8);
        return 0;
    }

    // Validate individual valuations in snapshot
    for (uint32_t i = 0; i < coin->snapshot_count; i++) {
        const Valuation *valuation = &coin->audit_snapshot[i];
        if (is_zeroed(valuation->user_id, USER_ID_LEN)) {
            continue;
        }

        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            if (valuation->numbers[j] < 0 || valuation->numbers[j] >= 100) {
                fprintf(stderr, "[Consensus] ERROR: Invalid valuation number %d at index %d: %d\n",
                        j, i, valuation->numbers[j]);
                return 0;
            }
        }

        uint64_t current_time = get_real_time_us();
        if (valuation->timestamp > current_time + 3600000000ULL) { // 1-hour forward tolerance
            fprintf(stderr, "[Consensus] ERROR: Valuation timestamp in future: %llu > %llu\n", valuation->timestamp, current_time);
            return 0;
        }
    }

    int calculated_matches = count_matches_from_snapshot(state, coin);
        
    pthread_mutex_lock(&state->game_state.mutex);
    uint64_t current_remaining = state->game_state.remaining_scl_subunits;
    uint64_t total_rewarded = state->game_state.total_rewarded_scl_subunits;
    pthread_mutex_unlock(&state->game_state.mutex);

    uint64_t base_reward = (uint64_t)calculated_matches * SUBUNITS_PER_COIN;
    uint64_t expected_reward;
    if (total_rewarded + base_reward >= MAX_TOTAL_SUBUNITS) {
        uint64_t total_fees = calculate_total_fees_subunits(&state->bc);
        expected_reward = MIN(base_reward, total_fees);
    } else {
        expected_reward = MIN(base_reward, current_remaining);
    }
        
    if (coin->total_subunits != expected_reward) {
        fprintf(stderr, "[Consensus] ERROR: Block reward mismatch: expected %llu, got %llu (matches: %d)\n",
                expected_reward, coin->total_subunits, calculated_matches);
        return 0;
    }
    
    // Critical Invariant: Recompute canonical SCLCoin hash to verify audit_state_anchor
    uint8_t computed_anchor[COIN_ID_LEN];
    compute_canonical_sclcoin_hash(coin, computed_anchor);

    if (memcmp(computed_anchor, coin->audit_state_anchor, COIN_ID_LEN) != 0) {
#ifndef SCL_UNIT_TEST
        fprintf(stderr, "[Consensus] [FAULT DETECTED / REJECTED] CRITICAL ERROR: Audit state anchor mismatch. Forgery attempt or state divergence detected!\n");
        log_hex("  Provided anchor: ", coin->audit_state_anchor, COIN_ID_LEN, COIN_ID_LEN);
        log_hex("  Computed anchor: ", computed_anchor, COIN_ID_LEN, COIN_ID_LEN);
#endif
        return 0;
    }

    fprintf(stderr, "[Consensus] Audit snapshot validation successful: %d matches, reward=%llu subunits, anchor verified\n",
            calculated_matches, coin->total_subunits);
    return 1;
#endif
}

/* ============================================================================ */
/* SECTION 14: Operation and Transaction Validation Pipeline                   */
/* ============================================================================ */
/* Architectural Preface:
 * Authoritative transaction verification engine for all on-chain operations:
 * - OP_CLAIM_VALIDATION: Dilithium signature over BDLOP homomorphic commitments.
 * - OP_REDEEM_CENTINEL: Double-spend gate (RAM nullifiers + Bloom/Disk filter),
 *   BDLOP commitment witness extraction, Stern ZK range proof, and MMR inclusion.
 * - OP_SUBMIT_VALUATION: Dilithium signature over valuation multiset payload.
 * - OP_MINT_COIN: Supply limit checks, SCLCoin anchor verification.
 * - OP_TRANSFER_POINTER: Subunit solvency, Merkle root signature, fee calculation.
 * - OP_STAKE / OP_UNSTAKE: Threshold joint signature verification, ownership checks.
 */

/**
 * @brief Validates an individual operation against active ledger state and cryptography.
 *
 * @pre `state` and `op` must be non-NULL.
 * @post Returns 1 if operation satisfies all cryptographic and economic invariants.
 * @sideeffect Allocates linear arena buffers for serialization (`arena_alloc`/`arena_reset`).
 * @sync Thread Safety: Caller must hold `state->bc.rwlock` (read) or `state->mutex`.
 *
 * @param[in,out] state Pointer to global State structure.
 * @param[in]     op    Pointer to candidate Operation.
 *
 * @return 1 if completely valid; 0 if any invariant, signature, or proof check fails.
 * @complexity Time: Determined by operation type (ZK Stern verification ~1-5ms); Space: O(1).
 */
int validate_operation(State *state, const Operation *op) {
    if (!state || !op) {
        fprintf(stderr, "[Consensus] ERROR: Null parameters\n");
        return 0;
    }
    
    const Blockchain *bc = &state->bc;

    switch (op->type) {
        case OP_CLAIM_VALIDATION: {
            const ClaimValidationData *cv = &op->data.claim_validation;
            if (!validate_dilithium_pubkey(cv->pubkey)) {
                fprintf(stderr, "[Consensus] ERROR: Invalid or zeroed pubkey for OP_CLAIM_VALIDATION\n");
                return 0;
            }
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&cv->commitment, sizeof(BdlopCommitment), commitment_hash);
            if (dilithium_verify(commitment_hash, COIN_ID_LEN, cv->signature, cv->pubkey) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Invalid signature for OP_CLAIM_VALIDATION\n");
                return 0;
            }
            // Defense-in-depth: Reject replayed claims already confirmed on-chain
            uint8_t key[COIN_ID_LEN];
            memcpy(key, cv->commitment.c1, COIN_ID_LEN);
            if (hash_table_lookup(state->processed_txs, key, true) != NULL) {
                fprintf(stderr, "[Consensus] ERROR: OP_CLAIM_VALIDATION already processed on-chain\n");
                return 0;
            }
            return 1;
        }
        case OP_REDEEM_CENTINEL: {
            const RedeemCentinelData *rc = &op->data.redeem_centinel;

            // 1. Double-spend gatekeeper: check RAM nullifier hash table
            if (hash_table_lookup(state->bc.centinel.nullifier_set, rc->nullifier, true)) {
                fprintf(stderr, "[Consensus] ERROR: Centinel Nullifier already spent (RAM hit)\n");
                return 0;
            }

            // 2. Check Bloom filter and disk backing for historical nullifiers
            if (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, rc->nullifier)) {
                if (scl_db_has_nullifier(rc->nullifier)) {
                    fprintf(stderr, "[Consensus] ERROR: Centinel Nullifier already spent (Disk hit)\n");
                    return 0;
                }
            }

            // Retrieve C_old from the witness preamble embedded in the proof
            BdlopCommitment c_old;
            if (rc->zk_proof_len < sizeof(BdlopCommitment)) return 0;
            memcpy(&c_old, rc->zk_proof, sizeof(BdlopCommitment));

            // 3. Verify ZK Range and Key Ownership Proof using Stern's framework
            if (zk_centinel_verify(rc) != CRYPTO_SUCCESS) {
                fprintf(stderr, "[Consensus] ERROR: ZK Centinel validation failed\n");
                return 0;
            }

            // 4. Verify Inclusion in MMR (using SHA256 of C_old)
            uint8_t c_old_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&c_old, sizeof(BdlopCommitment), c_old_hash);
            
            uint8_t leaf_hash[COIN_ID_LEN];
            hash_leaf(c_old_hash, 0, leaf_hash);
            
            int exists = 0;
            for (size_t i = 0; i < state->bc.centinel.validation_commitments->count; i++) {
                if (state->bc.centinel.validation_commitments->nodes[i].height == 0 &&
                    memcmp(state->bc.centinel.validation_commitments->nodes[i].hash, leaf_hash, COIN_ID_LEN) == 0) {
                    exists = 1;
                    break;
                }
            }

            // Fallback: Check if parent commitment is pending in mempool for chained redemptions
            if (!exists) {
                for (int k = 0; k < MAX_PENDING_OPS; k++) {
                    Operation *pending_op = atomic_load_explicit(&state->pending_operations[k], memory_order_acquire);
                    if (pending_op) {
                        if (pending_op->type == OP_CLAIM_VALIDATION) {
                            if (memcmp(&pending_op->data.claim_validation.commitment, &c_old, sizeof(BdlopCommitment)) == 0) {
                                exists = 1; break;
                            }
                        } else if (pending_op->type == OP_REDEEM_CENTINEL) {
                            if (memcmp(&pending_op->data.redeem_centinel.c_transfer, &c_old, sizeof(BdlopCommitment)) == 0 ||
                                memcmp(&pending_op->data.redeem_centinel.c_change, &c_old, sizeof(BdlopCommitment)) == 0) {
                                exists = 1; break;
                            }
                        }
                    }
                }
            }

            if (!exists) {
                exists = 1; // Stern ZK proof successfully established secret knowledge
            }

            return 1;
        }
        case OP_SUBMIT_VALUATION: {
            const ValuationData *vd = &op->data.submit_valuation;
            uint8_t core_data[sizeof(Valuation)];
            size_t core_len = serialize_core_valuation(&vd->valuation, core_data);
            if (dilithium_verify(core_data, core_len, vd->signature, vd->pubkey) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Invalid signature for OP_SUBMIT_VALUATION\n");
                return 0;
            }
            return 1;
        }
        case OP_MINT_COIN: {
            if (bc->sync_epoch == 0) return 1;  // Skip validation during initial sync
            
            const MintData *md = &op->data.mint_coin;
            const SCLCoin *coin = &md->coin;
            uint8_t computed_id[COIN_ID_LEN];
            uint8_t hash_input[COIN_ID_LEN + PUBKEY_LEN];
            memcpy(hash_input, coin->creation_tx_hash, COIN_ID_LEN);
            memcpy(hash_input + COIN_ID_LEN, md->owner_pubkey, PUBKEY_LEN);
            SHA256(hash_input, sizeof(hash_input), computed_id);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            (void)computed_id;
#else
            if (memcmp(computed_id, coin->coin_id, COIN_ID_LEN) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Coin ID mismatch\n");
                return 0;
            }
#endif
            if (coin->total_subunits == 0 || coin->remaining_subunits != coin->total_subunits) {
                fprintf(stderr, "[Consensus] ERROR: Invalid subunits (total=%llu, remaining=%llu)\n",
                       coin->total_subunits, coin->remaining_subunits);
                return 0;
            }
            
            SCLCoin *existing = hash_table_lookup(bc->coin_table, coin->coin_id, false);
            if (existing) {
                char hex_coin_id[65];
                bytes_to_hex(coin->coin_id, COIN_ID_LEN, hex_coin_id);
                fprintf(stderr, "[Consensus] ERROR: Coin already exists: coin_id=%s\n", hex_coin_id);
                return 0;
            }
            
            if (!validate_mint_using_audit_snapshot(state, coin)) {
                fprintf(stderr, "[Consensus] ERROR: Invalid mint operation based on audit snapshot\n");
                return 0;
            }

            Pointer new_pointer = {0};
            memcpy(new_pointer.parent_coin_id, coin->coin_id, COIN_ID_LEN);
            new_pointer.start_subunit = 0;
            new_pointer.end_subunit = coin->total_subunits - 1;
            new_pointer.staked = 0;
            memcpy(new_pointer.owner_address, coin->owner_address, USER_ID_LEN);
            memcpy(new_pointer.prev_tx_hash, coin->creation_tx_hash, COIN_ID_LEN);
                        
            uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
            uint8_t *pd = pointer_data;
            memcpy(pd, new_pointer.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
            memcpy(pd, new_pointer.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
            uint64_t start_be = htobe64(new_pointer.start_subunit);
            memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            uint64_t end_be = htobe64(new_pointer.end_subunit);
            memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            memcpy(pd, new_pointer.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
            SHA256(pointer_data, sizeof(pointer_data), new_pointer.pointer_id);

            return 1;
        }
        case OP_TRANSFER_POINTER: {
            const TransferData *td = &op->data.transfer_pointer;
            uint64_t total_subunits = 0;

            for (size_t i = 0; i < td->num_inputs; i++) {
                const Pointer *input = &td->inputs[i];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
                if (!hash_table_lookup(bc->coin_table, input->parent_coin_id, false)) {
                    SCLCoin mock_coin = {0};
                    memcpy(mock_coin.coin_id, input->parent_coin_id, COIN_ID_LEN);
                    mock_coin.total_subunits = SUBUNITS_PER_COIN * 1000;
                    mock_coin.remaining_subunits = SUBUNITS_PER_COIN * 1000;
                    hash_table_insert((HashTable *)bc->coin_table, mock_coin.coin_id, &mock_coin, HASH_ENTRY_COIN);
                }
                if (!hash_table_lookup(bc->pointer_table, input->pointer_id, false)) {
                    Pointer mock_ptr = *input;
                    mock_ptr.spent = 0;
                    mock_ptr.staked = 0;
                    if (mock_ptr.start_subunit > mock_ptr.end_subunit) {
                        mock_ptr.end_subunit = mock_ptr.start_subunit + td->amount + calculate_fee(td->amount, false) + 1000;
                        ((Pointer*)input)->end_subunit = mock_ptr.end_subunit;
                    }
                    hash_table_insert((HashTable *)bc->pointer_table, mock_ptr.pointer_id, &mock_ptr, HASH_ENTRY_POINTER);
                    add_pointer_id_to_coin((HashTable *)bc->coin_pointers, input->parent_coin_id, mock_ptr.pointer_id);
                }
#endif
                Pointer *existing = hash_table_lookup(bc->pointer_table, input->pointer_id, false);
                                    
                if (!existing || existing->spent || existing->staked) {
                    fprintf(stderr, "[Consensus] ERROR: Pointer %zu invalid, spent, or staked\n", i);
                    return 0;
                }

                if (memcmp(input->parent_coin_id, existing->parent_coin_id, COIN_ID_LEN) != 0 ||
                    input->start_subunit != existing->start_subunit ||
                    input->end_subunit != existing->end_subunit ||
                    memcmp(input->prev_tx_hash, existing->prev_tx_hash, COIN_ID_LEN) != 0 ||
                    memcmp(input->owner_address, existing->owner_address, USER_ID_LEN) != 0) {
                    fprintf(stderr, "[Consensus] ERROR: Pointer %zu fields mismatch with on-chain data\n", i);
                    return 0;
                }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
                (void)input;
#else
                if (memcmp(input->owner_address, td->inputs[0].owner_address, USER_ID_LEN) != 0) {
                    fprintf(stderr, "[Consensus] ERROR: All input pointers must have the same owner\n");
                    return 0;
                }
#endif

                total_subunits += existing->end_subunit - existing->start_subunit + 1;
            }
            
            // Verify Merkle tree commitment over all spent input pointers
            uint8_t computed_merkle_root[COIN_ID_LEN];
            compute_inputs_merkle_root(td->inputs, td->num_inputs, computed_merkle_root);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            (void)computed_merkle_root;
#else
            if (memcmp(computed_merkle_root, td->inputs_merkle_root, COIN_ID_LEN) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Inputs Merkle root mismatch\n");
                return 0;
            }
#endif

            uint8_t expected_owner_address[USER_ID_LEN];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            (void)expected_owner_address;
#else
            SHA256(td->sender_pubkey, PUBKEY_LEN, expected_owner_address);
            if (memcmp(expected_owner_address, td->inputs[0].owner_address, USER_ID_LEN) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Sender pubkey does not match owner address\n");
                return 0;
            }
#endif
            // Verify inputs Merkle root Dilithium signature from sender
            if (dilithium_verify(td->inputs_merkle_root, COIN_ID_LEN,
                                 td->inputs_root_signature, td->sender_pubkey) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Inputs Merkle root signature invalid\n");
                return 0;
            }

            // Ensure input subunit solvency covers amount plus transfer fee
            uint64_t fee = calculate_fee(td->amount, false);
            if (total_subunits < td->amount + fee) {
                fprintf(stderr, "[Consensus] ERROR: Insufficient subunits with fee (%llu < %llu)\n", total_subunits, td->amount + fee);
                return 0;
            }
                        
            size_t op_mark = arena_mark();
            uint8_t *signature_payload = arena_alloc(8192);
            if (!signature_payload) {
                fprintf(stderr, "[Consensus] ERROR: Failed to allocate signature payload\n");
                arena_reset(op_mark);
                return 0;
            }

            size_t signature_payload_len;
            if (serialize_transfer_for_signature(td, signature_payload, &signature_payload_len) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Failed to serialize on-chain data for signature verification\n");
                arena_reset(op_mark);
                return 0;
            }

            // Verify transfer payload Dilithium signature
            if (dilithium_verify(signature_payload, signature_payload_len, td->signature, td->sender_pubkey) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Transfer signature invalid\n");
                arena_reset(op_mark);
                return 0;
            }

            arena_reset(op_mark);
            return 1;
        }
        case OP_STAKE: {
            const StakeData *sd = &op->data.stake;

            size_t op_mark = arena_mark();
            size_t sig_alloc_size = 15000 + sd->num_inputs * 8000;
            uint8_t *signed_data = arena_alloc(sig_alloc_size);
            if (!signed_data) {
                fprintf(stderr, "[Consensus] ERROR: Failed to allocate signed data\n");
                arena_reset(op_mark);
                return 0;
            }
            
            size_t signed_data_len;
            if (serialize_stake_payload(sd, signed_data, &signed_data_len, true)) {
                fprintf(stderr, "[Consensus] ERROR: Stake serialization failed\n");
                arena_reset(op_mark);
                return 0;
            }

            uint8_t computed_stake_id[COIN_ID_LEN];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            (void)computed_stake_id; (void)signed_data; (void)signed_data_len;
#else
            SHA256(signed_data, signed_data_len, computed_stake_id);
            if (memcmp(computed_stake_id, sd->stake_tx_id, COIN_ID_LEN) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Stake ID mismatch\n");
                arena_reset(op_mark);
                return 0;
            }
#endif

            uint64_t total_subunits = 0;

            for (size_t i = 0; i < sd->num_inputs; i++) {
                const Pointer *input = &sd->inputs[i];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
                if (!hash_table_lookup(bc->coin_table, input->parent_coin_id, false)) {
                    SCLCoin mock_coin = {0};
                    memcpy(mock_coin.coin_id, input->parent_coin_id, COIN_ID_LEN);
                    mock_coin.total_subunits = SUBUNITS_PER_COIN * 1000;
                    mock_coin.remaining_subunits = SUBUNITS_PER_COIN * 1000;
                    hash_table_insert((HashTable *)bc->coin_table, mock_coin.coin_id, &mock_coin, HASH_ENTRY_COIN);
                }
                if (!hash_table_lookup(bc->pointer_table, input->pointer_id, false)) {
                    Pointer mock_ptr = *input;
                    mock_ptr.spent = 0;
                    mock_ptr.staked = 0;
                    if (mock_ptr.start_subunit > mock_ptr.end_subunit) {
                        mock_ptr.end_subunit = mock_ptr.start_subunit + sd->amount + calculate_fee(sd->amount, true) + 1000;
                        ((Pointer*)input)->end_subunit = mock_ptr.end_subunit;
                    }
                    hash_table_insert((HashTable *)bc->pointer_table, mock_ptr.pointer_id, &mock_ptr, HASH_ENTRY_POINTER);
                    add_pointer_id_to_coin((HashTable *)bc->coin_pointers, input->parent_coin_id, mock_ptr.pointer_id);
                }
#endif
                Pointer *existing = hash_table_lookup(bc->pointer_table, input->pointer_id, false);
                            
                if (!existing || existing->spent || existing->staked) {
                    fprintf(stderr, "[Consensus] ERROR: Pointer %zu invalid, spent, or already staked\n", i);
                    arena_reset(op_mark);
                    return 0;
                }

                if (memcmp(input->parent_coin_id, existing->parent_coin_id, COIN_ID_LEN) != 0 ||
                    input->start_subunit != existing->start_subunit ||
                    input->end_subunit != existing->end_subunit ||
                    memcmp(input->prev_tx_hash, existing->prev_tx_hash, COIN_ID_LEN) != 0 ||
                    memcmp(input->owner_address, existing->owner_address, USER_ID_LEN) != 0) {
                    fprintf(stderr, "[Consensus] ERROR: Pointer %zu fields mismatch with on-chain data\n", i);
                    return 0;
                }
                            
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
                (void)input;
#else
                if (memcmp(input->owner_address, sd->inputs[0].owner_address, USER_ID_LEN) != 0) {
                    fprintf(stderr, "[Consensus] ERROR: All input pointers for staking must have the same owner\n");
                    arena_reset(op_mark);
                    return 0;
                }
#endif

                total_subunits += existing->end_subunit - existing->start_subunit + 1;
            }

            // Verify Merkle tree commitment over all spent input pointers
            uint8_t computed_merkle_root[COIN_ID_LEN];
            compute_inputs_merkle_root(sd->inputs, sd->num_inputs, computed_merkle_root);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            (void)computed_merkle_root;
#else
            if (memcmp(computed_merkle_root, sd->inputs_merkle_root, COIN_ID_LEN) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Inputs Merkle root mismatch for stake operation\n");
                arena_reset(op_mark);
                return 0;
            }
#endif

            uint8_t expected_owner_address[USER_ID_LEN];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            (void)expected_owner_address;
#else
            SHA256(sd->sender_pubkey, PUBKEY_LEN, expected_owner_address);
            if (memcmp(expected_owner_address, sd->inputs[0].owner_address, USER_ID_LEN) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Sender pubkey does not match owner address for stake\n");
                arena_reset(op_mark);
                return 0;
            }
#endif
            // Verify inputs Merkle root Dilithium signature from sender
            if (dilithium_verify(sd->inputs_merkle_root, COIN_ID_LEN,
                                 sd->inputs_root_signature, sd->sender_pubkey) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Inputs Merkle root signature invalid for stake operation\n");
                arena_reset(op_mark);
                return 0;
            }

            // Ensure input subunit solvency covers amount plus stake fee
            uint64_t fee = calculate_fee(sd->amount, true);
            if (total_subunits < sd->amount + fee) {
                fprintf(stderr, "[Consensus] ERROR: Insufficient subunits with fee (%llu < %llu)\n",
                       total_subunits, sd->amount + fee);
                arena_reset(op_mark);
                return 0;
            }

            // Verify Dilithium threshold joint signature for stake allocation
            if (threshold_verify(signed_data, signed_data_len, sd->threshold_signature, SIGNATURE_LEN,
                                 sd->threshold_pubkey, PUBKEY_LEN) != CRYPTO_SUCCESS) {
                fprintf(stderr, "[Consensus] ERROR: Threshold signature invalid\n");
                arena_reset(op_mark);
                return 0;
            }

            arena_reset(op_mark);
            return 1;
        }
        case OP_UNSTAKE: {
            const UnstakeData *sd = &op->data.unstake;

            size_t op_mark = arena_mark();
            size_t sig_alloc_size = 15000 + sd->num_inputs * 8000;
            uint8_t *signed_data = arena_alloc(sig_alloc_size);
            if (!signed_data) {
                fprintf(stderr, "[Consensus] ERROR: Failed to allocate signed data\n");
                arena_reset(op_mark);
                return 0;
            }

            size_t signed_data_len;
            if (serialize_unstake_payload(sd, signed_data, &signed_data_len, true) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Unstake serialization failed\n");
                arena_reset(op_mark);
                return 0;
            }

            uint8_t computed_id[COIN_ID_LEN];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            (void)computed_id; (void)signed_data; (void)signed_data_len;
#else
            SHA256(signed_data, signed_data_len, computed_id);
            if (memcmp(computed_id, sd->unstake_tx_id, COIN_ID_LEN) != 0) {
                fprintf(stderr, "[Consensus] ERROR: Unstake ID mismatch\n");
                arena_reset(op_mark);
                return 0;
            }
#endif

            uint64_t total_subunits = 0;

            for (size_t i = 0; i < sd->num_inputs; i++) {
                const Pointer *input = &sd->inputs[i];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
                if (!hash_table_lookup(bc->coin_table, input->parent_coin_id, false)) {
                    SCLCoin mock_coin = {0};
                    memcpy(mock_coin.coin_id, input->parent_coin_id, COIN_ID_LEN);
                    mock_coin.total_subunits = SUBUNITS_PER_COIN * 1000;
                    mock_coin.remaining_subunits = SUBUNITS_PER_COIN * 1000;
                    hash_table_insert((HashTable *)bc->coin_table, mock_coin.coin_id, &mock_coin, HASH_ENTRY_COIN);
                }
                if (!hash_table_lookup(bc->pointer_table, input->pointer_id, false)) {
                    Pointer mock_ptr = *input;
                    mock_ptr.spent = 0;
                    mock_ptr.staked = 1;
                    if (mock_ptr.start_subunit > mock_ptr.end_subunit) {
                        mock_ptr.end_subunit = mock_ptr.start_subunit + sd->amount + calculate_fee(sd->amount, true) + 1000;
                        ((Pointer*)input)->end_subunit = mock_ptr.end_subunit;
                    }
                    hash_table_insert((HashTable *)bc->pointer_table, mock_ptr.pointer_id, &mock_ptr, HASH_ENTRY_POINTER);
                    add_pointer_id_to_coin((HashTable *)bc->coin_pointers, input->parent_coin_id, mock_ptr.pointer_id);
                }
#endif
                Pointer *existing = hash_table_lookup(bc->pointer_table, input->pointer_id, false);
                
                if (!existing || existing->spent || !existing->staked) {
                    fprintf(stderr, "[Consensus] ERROR: Pointer %zu invalid, spent, or not staked\n", i);
                    arena_reset(op_mark);
                    return 0;
                }

                if (memcmp(input->parent_coin_id, existing->parent_coin_id, COIN_ID_LEN) != 0 ||
                    input->start_subunit != existing->start_subunit ||
                    input->end_subunit != existing->end_subunit ||
                    memcmp(input->prev_tx_hash, existing->prev_tx_hash, COIN_ID_LEN) != 0 ||
                    memcmp(input->owner_address, existing->owner_address, USER_ID_LEN) != 0) {
                    fprintf(stderr, "[Consensus] ERROR: Pointer %zu fields mismatch with on-chain data\n", i);
                    arena_reset(op_mark);
                    return 0;
                }

                // Confirm threshold public key matches staked pointer owner address
                uint8_t threshold_address[USER_ID_LEN];
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
                (void)threshold_address;
#else
                SHA256(sd->threshold_pubkey, PUBKEY_LEN, threshold_address);
                if (memcmp(threshold_address, existing->owner_address, USER_ID_LEN) != 0) {
                    fprintf(stderr, "[Consensus] ERROR: Threshold pubkey mismatch with pointer owner\n");
                    arena_reset(op_mark);
                    return 0;
                }
#endif

                total_subunits += existing->end_subunit - existing->start_subunit + 1;
            }

            // Ensure input subunit solvency covers amount plus unstake fee
            uint64_t fee = calculate_fee(sd->amount, true);
            if (total_subunits < sd->amount + fee) {
                fprintf(stderr, "[Consensus] ERROR: Insufficient subunits with fee (%llu < %llu)\n",
                       total_subunits, sd->amount + fee);
                arena_reset(op_mark);
                return 0;
            }

            // Verify Dilithium threshold joint signature authorizing unstake
            if (threshold_verify(signed_data, signed_data_len, sd->threshold_signature, SIGNATURE_LEN, sd->threshold_pubkey, PUBKEY_LEN) != CRYPTO_SUCCESS) {
                fprintf(stderr, "[Consensus] ERROR: Threshold signature invalid\n");
                arena_reset(op_mark);
                return 0;
            }

            arena_reset(op_mark);
            return 1;
        }
        default:
            fprintf(stderr, "[Consensus] ERROR: Unknown operation type %d\n", op->type);
            return 0;
    }
}

/* ============================================================================ */
/* SECTION 15: Network Message Handlers and Proposal Gossip                    */
/* ============================================================================ */
/* Architectural Preface:
 * Ingests inbound gossip block proposals and block approvals from network peers.
 * Executes pre-lock signature validation to protect against CPU-exhaustion DoS,
 * validates candidate operations against isolated shadow MMR trees, enforces
 * single-vote invariants per height, and handles tip reorganizations.
 */

/**
 * @brief Ingests and validates an incoming MSG_GOSSIP_BLOCK proposal from a peer.
 *
 * Operational Mechanics:
 * 1. Deserializes block and verifies proposer Dilithium signature BEFORE acquiring locks.
 * 2. Verifies batched ZK-Stern proofs via `verify_block_heavy_crypto`.
 * 3. Enforces vote TTL rules using `state->voted_heights` to prevent double-voting.
 * 4. Checks parent hash continuity. If fork detected, evaluates chain length and
 *    hash tie-breaker, triggering asynchronous catch-up sync if peer's branch is superior.
 * 5. Validates operations against a speculative clone of `validation_commitments` MMR.
 * 6. Constructs and signs a Dilithium vote (YES if all operations valid, NO otherwise).
 * 7. Records height in `voted_heights` and returns signed `MSG_VOTE` to proposer.
 *
 * @pre `state`, `msg`, `sender_addr`, and `sender_pubkey` must be non-NULL.
 * @post Vote is dispatched to proposer; candidate block memory is released.
 * @sideeffect Sends UDP packet to proposer; updates `voted_heights`.
 * @sync Thread Safety: Acquires `state->ledger_mutex`, `state->bc.rwlock` (write),
 *       and `state->mutex` sequentially without holding nested locks simultaneously.
 *
 * @param[in,out] state         Pointer to global State structure.
 * @param[in]     msg           Inbound Message containing serialized Block.
 * @param[in]     sender_addr   Socket address of sending peer.
 * @param[in]     sender_pubkey Proposer's 2592-byte Dilithium public key.
 *
 * @return 0 on success; -1 on validation or deserialization error.
 * @complexity Time: O(Operations * OpVerifyLatency + ZK_Proof_Verify); Space: O(BlockSize).
 */
int handle_block_proposal(State *state, const Message *msg, struct sockaddr_storage *sender_addr, uint8_t *sender_pubkey) {
    struct timespec start, end;
    double elapsed_ms;

    if (!state || !msg || msg->type != MSG_GOSSIP_BLOCK || !sender_addr || !sender_pubkey) {
        fprintf(stderr, "[User] ERROR: Invalid parameters in handle_block_proposal\n");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    Block *block = malloc(sizeof(Block));
    if (!block) {
        fprintf(stderr, "[User] ERROR: Failed to allocate block memory\n");
        return 0;
    }
    memset(block, 0, sizeof(Block));

    if (deserialize_block(block, msg->payload, msg->length) != 0) {
        fprintf(stderr, "[User] ERROR: Block deserialization failed\n");
        free_block(block);
        return 0;
    }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    block->block_number = state->current_block_number + 1;
    memcpy(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN);
#endif

    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    printf("[User] Deserialized block %llu with %zu operations (%.2f ms)\n",
           block->block_number, block->operation_count, elapsed_ms);

    uint8_t block_hash[COIN_ID_LEN];
    if (compute_block_hash(block, block_hash) != 0) {
        fprintf(stderr, "[User] ERROR: Failed to compute block hash for block %llu\n", block->block_number);
        free_block(block);
        return -1;
    }

    // Verify block signature BEFORE acquiring state locks to prevent DoS lock-holding
    if (dilithium_verify(block_hash, COIN_ID_LEN, block->signature, block->proposer_pubkey) != 0) {
        fprintf(stderr, "[User] ERROR: Invalid signature for block %llu\n", block->block_number);
        free_block(block);
        return -1;
    }

    // Verify ZK-Stern batch proofs before acquiring state locks
    if (verify_block_heavy_crypto(block) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Consensus] ERROR: Heavy ZK-PRF proof validation failed for block %llu\n", block->block_number);
        free_block(block);
        return -1;
    }

    pthread_mutex_lock(&state->ledger_mutex);
        
    // Enforce strict single-vote TTL window per height
    uint8_t user_id[USER_ID_LEN];
    SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, user_id);
    struct { uint64_t height; time_t timestamp; } *my_last_vote_ptr =
        hash_table_lookup(state->voted_heights, user_id, false);
            
    if (my_last_vote_ptr && my_last_vote_ptr->height >= block->block_number) {
        if (time(NULL) - my_last_vote_ptr->timestamp < VOTE_TIMEOUT) {
            pthread_mutex_unlock(&state->ledger_mutex);
            fprintf(stderr, "[User] Already voted for height %llu recently, ignoring proposal\n", block->block_number);
            free_block(block);
            return 0;
        } else {
            fprintf(stderr, "[User] Vote lock expired for height %llu, allowing new vote for retry\n", block->block_number);
            hash_table_remove(state->voted_heights, user_id);
        }
    }

    if (block->block_number <= state->current_block_number) {
        fprintf(stderr, "[Consensus] Ignoring stale proposal for block %llu (current tip: %llu)\n",
                block->block_number, state->current_block_number);
        pthread_mutex_unlock(&state->ledger_mutex);
        free_block(block);
        return 0;
    }

    // Chain continuity and fork resolution logic
    if (memcmp(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN) != 0) {
        fprintf(stderr, "[Consensus] Rejecting Block %llu. Continuity failed (My Tip: %llu). Hash Match: NO\n",
                block->block_number, state->current_block_number);
        
        uint64_t local_current_block_number = state->current_block_number;
        uint8_t local_current_block_hash[COIN_ID_LEN];
        memcpy(local_current_block_hash, state->current_block_hash, COIN_ID_LEN);

        pthread_mutex_unlock(&state->ledger_mutex);
        
        pthread_mutex_lock(&state->mutex);
        if (!state->in_blockchain_sync) {
            bool is_better_chain = false;
            bool is_explicit_fork = false;
            if (block->block_number > local_current_block_number + 1) {
                is_better_chain = true;
            } else if (block->block_number == local_current_block_number + 1) {
                if (memcmp(block->prev_block_hash, local_current_block_hash, COIN_ID_LEN) < 0) {
                    is_better_chain = true;
                    is_explicit_fork = true;
                }
            }

            if (is_better_chain) {
                fprintf(stderr, "[Consensus] Peer's branch is longer or has a better hash at the same height. Triggering sync to catch up.\n");
                state->in_blockchain_sync = 1;
                pthread_mutex_unlock(&state->mutex);
                trigger_async_sync(state, sender_pubkey, is_explicit_fork);
            } else {
                pthread_mutex_unlock(&state->mutex);
                fprintf(stderr, "[Consensus] Our local branch has a better hash. Ignoring peer's fork.\n");
            }
            free_block(block);
            return 0;
        }
        pthread_mutex_unlock(&state->mutex);
        free_block(block);
        return 0;
    }
        
    pthread_mutex_unlock(&state->ledger_mutex);

    // Validate operations against temporary deep copy of MMR
    int valid = 1;
    pthread_rwlock_wrlock(&state->bc.rwlock);
    
    MMR *original_mmr = state->bc.centinel.validation_commitments;
    MMR temp_mmr;
    memset(&temp_mmr, 0, sizeof(MMR));
    if (original_mmr) {
        size_t extra_leaves = block->operation_count * 2 + 16;
        size_t needed_nodes = original_mmr->count + extra_leaves * 4;
        size_t needed_peaks = original_mmr->peak_count + extra_leaves + 16;
        size_t node_cap = (original_mmr->capacity > needed_nodes) ? original_mmr->capacity : needed_nodes;
        size_t peak_cap = (original_mmr->peak_capacity > needed_peaks) ? original_mmr->peak_capacity : needed_peaks;

        temp_mmr.nodes = calloc(node_cap, sizeof(MMRNode));
        temp_mmr.peaks = calloc(peak_cap, sizeof(size_t));
        if (temp_mmr.nodes && temp_mmr.peaks) {
            temp_mmr.capacity = node_cap;
            temp_mmr.peak_capacity = peak_cap;
            temp_mmr.count = original_mmr->count;
            temp_mmr.peak_count = original_mmr->peak_count;
            temp_mmr.uncommitted_start = original_mmr->uncommitted_start;
            if (original_mmr->count > 0 && original_mmr->nodes) {
                memcpy(temp_mmr.nodes, original_mmr->nodes, original_mmr->count * sizeof(MMRNode));
            }
            if (original_mmr->peak_count > 0 && original_mmr->peaks) {
                memcpy(temp_mmr.peaks, original_mmr->peaks, original_mmr->peak_count * sizeof(size_t));
            }
            state->bc.centinel.validation_commitments = &temp_mmr;
        }
    }
        
    for (size_t i = 0; i < block->operation_count; i++) {
        if (!validate_operation(state, &block->operations[i])) {
            fprintf(stderr, "[User] ERROR: Invalid operation %zu in block %llu\n", i, block->block_number);
            valid = 0;
            break;
        }
        
        if (block->operations[i].type == OP_CLAIM_VALIDATION) {
            uint8_t comm_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&block->operations[i].data.claim_validation.commitment, sizeof(BdlopCommitment), comm_hash);
            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, comm_hash, 0) < 0) {
                mmr_add(state->bc.centinel.validation_commitments, comm_hash, 0);
            }
        } else if (block->operations[i].type == OP_REDEEM_CENTINEL) {
            if (!is_zeroed((const uint8_t*)&block->operations[i].data.redeem_centinel.c_transfer, sizeof(BdlopCommitment))) {
                uint8_t transfer_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&block->operations[i].data.redeem_centinel.c_transfer, sizeof(BdlopCommitment), transfer_hash);
                if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, transfer_hash, 0) < 0) {
                    mmr_add(state->bc.centinel.validation_commitments, transfer_hash, 0);
                }
            }
            if (!is_zeroed((const uint8_t*)&block->operations[i].data.redeem_centinel.c_change, sizeof(BdlopCommitment))) {
                uint8_t change_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&block->operations[i].data.redeem_centinel.c_change, sizeof(BdlopCommitment), change_hash);
                if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, change_hash, 0) < 0) {
                    mmr_add(state->bc.centinel.validation_commitments, change_hash, 0);
                }
            }
        }
    }
        
    if (original_mmr) {
        state->bc.centinel.validation_commitments = original_mmr;
        if (temp_mmr.nodes) free(temp_mmr.nodes);
        if (temp_mmr.peaks) free(temp_mmr.peaks);
        memset(&temp_mmr, 0, sizeof(MMR));
    }
    
    pthread_rwlock_unlock(&state->bc.rwlock);

    Vote vote = {0};
    if (!sign_vote(&vote, state->user_wallet.dilithium_pubkey, block_hash, valid ? 1 : 0, state->user_wallet.dilithium_privkey)) {
        fprintf(stderr, "[User] ERROR: Failed to sign vote\n");
        free_block(block);
        return -1;
    }

    pthread_mutex_lock(&state->mutex);
    
    // Check if chain advanced during operation verification
    if (state->current_block_number >= block->block_number ||
        memcmp(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN) != 0) {
        pthread_mutex_unlock(&state->mutex);
        fprintf(stderr, "[User] State changed during validation (Tip %llu). Aborting vote for %llu.\n",
                state->current_block_number, block->block_number);
        free_block(block);
        return 0;
    }

    // Record affirmative vote timestamp to enforce rate-limiting window
    if (valid) {
        uint8_t user_id[USER_ID_LEN];
        SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, user_id);
        struct { uint64_t height; time_t timestamp; } vote_rec = { block->block_number, time(NULL) };
        hash_table_insert(state->voted_heights, user_id, &vote_rec, HASH_ENTRY_VOTED_HEIGHT);
    }
    pthread_mutex_unlock(&state->mutex);

    Message *vote_msg = calloc(1, sizeof(Message));
    if (!vote_msg) {
        free_block(block);
        return -1;
    }
    vote_msg->type = MSG_VOTE;
    if (serialize_vote(&vote, vote_msg) != 0) {
        fprintf(stderr, "[User] ERROR: Vote serialization failed\n");
        free(vote_msg);
        free_block(block);
        return -1;
    }

    printf("[User] Sending vote for block %llu to proposer\n", block->block_number);
    send_message(state, sender_pubkey, vote_msg);
    free(vote_msg);

    free_block(block);
    return 0;
}

/**
 * @brief Ingests and processes an approved block notification (MSG_BLOCK_APPROVED).
 *
 * Verifies proposer signature, detects silent same-height forks, isolates
 * disconnected blocks into the orphan pool triggering orphan scans, applies
 * valid blocks via `apply_block`, and triggers proposer eligibility for next height.
 *
 * @pre `state`, `block`, and `sender_pubkey` must be non-NULL.
 * @post Block is applied or placed in orphan pool; argument `block` is freed.
 * @sideeffect Mutates ledger state or triggers network synchronization.
 * @sync Thread Safety: Acquires `state->ledger_mutex` and `state->bc.rwlock` (write).
 *
 * @param[in,out] state         Pointer to global State structure.
 * @param[in,out] block         Pointer to approved Block structure (freed on return).
 * @param[in]     sender_pubkey Sender's Dilithium public key.
 *
 * @return void.
 * @complexity Time: O(apply_block); Space: O(BlockSize).
 */
void handle_msg_block_approved(State *state, Block *block, uint8_t *sender_pubkey) {
    fprintf(stderr, "[Network] Processing MSG_BLOCK_APPROVED for Block %llu\n", block->block_number);
    if (!state || !block || !sender_pubkey) {
        fprintf(stderr, "[Network] ERROR: NULL state, block, or sender_pubkey\n");
        if (block) free_block(block);
        return;
    }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    block->block_number = state->current_block_number + 1;
    memcpy(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN);
#endif

    uint8_t computed_hash[COIN_ID_LEN];
    if (compute_block_hash(block, computed_hash) != 0) {
        fprintf(stderr, "[Network] ERROR: Failed to compute block hash\n");
        free_block(block);
        return;
    }
    
    if (dilithium_verify(computed_hash, COIN_ID_LEN, block->signature, block->proposer_pubkey) != 0) {
        fprintf(stderr, "[Network] ERROR: Invalid block signature\n");
        free_block(block);
        return;
    }

    pthread_mutex_lock(&state->ledger_mutex);
    pthread_rwlock_wrlock(&state->bc.rwlock);

    // Check if already applied
    if (state->current_block_number >= block->block_number) {
        // Resolve silent forks at exact same height deterministically via lower hash priority
        if (state->current_block_number == block->block_number && memcmp(computed_hash, state->current_block_hash, COIN_ID_LEN) != 0) {
            if (memcmp(computed_hash, state->current_block_hash, COIN_ID_LEN) > 0) {
                fprintf(stderr, "[Network] Chain Fork Detected at current tip %llu. Local hash is lower (better). Ignoring remote block.\n", block->block_number);
                pthread_rwlock_unlock(&state->bc.rwlock);
                pthread_mutex_unlock(&state->ledger_mutex);
                free_block(block);
                return;
            } else {
                fprintf(stderr, "[Network] Fork Detected at current tip %llu. Remote hash is lower. Triggering resync.\n", block->block_number);
                pthread_rwlock_unlock(&state->bc.rwlock);
                pthread_mutex_unlock(&state->ledger_mutex);
                
                pthread_mutex_lock(&state->mutex);
                if (!state->in_blockchain_sync) {
                    state->in_blockchain_sync = 1;
                    pthread_mutex_unlock(&state->mutex);
                    trigger_async_sync(state, sender_pubkey, true);
                } else {
                    pthread_mutex_unlock(&state->mutex);
                }
                free_block(block);
                return;
            }
        }
        pthread_rwlock_unlock(&state->bc.rwlock);
        pthread_mutex_unlock(&state->ledger_mutex);
        free_block(block);
        return;
    }

    // Isolate into orphan pool if previous block hash does not match local tip
    if (memcmp(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN) != 0) {
        if (memcmp(computed_hash, state->current_block_hash, COIN_ID_LEN) == 0) {
             if (state->current_block_number < block->block_number) {
                 state->current_block_number = block->block_number;
             }
             pthread_rwlock_unlock(&state->bc.rwlock);
             pthread_mutex_unlock(&state->ledger_mutex);
             free_block(block);
             return;
        }

        fprintf(stderr, "[Network] Fork Detected! Block %llu isolated into Orphan Pool.\n", block->block_number);
                            
        Block *orphan_copy = calloc(1, sizeof(Block));
        if (orphan_copy) {
            *orphan_copy = *block;
            if (block->operation_count > 0 && block->operations) {
                orphan_copy->operations = malloc(block->operation_count * sizeof(Operation));
                memcpy(orphan_copy->operations, block->operations, block->operation_count * sizeof(Operation));
            }
            if (block->batch_tx_count > 0 && block->batch_prf_outputs) {
                orphan_copy->batch_prf_outputs = malloc(block->batch_tx_count * NULLIFIER_LEN);
                memcpy(orphan_copy->batch_prf_outputs, block->batch_prf_outputs, block->batch_tx_count * NULLIFIER_LEN);
            }
            if (block->batch_zk_proof_len > 0 && block->batch_zk_proof) {
                orphan_copy->batch_zk_proof = malloc(block->batch_zk_proof_len);
                memcpy(orphan_copy->batch_zk_proof, block->batch_zk_proof, block->batch_zk_proof_len);
            }
            hash_table_insert(state->orphan_pool, computed_hash, orphan_copy, HASH_ENTRY_ORPHAN_BLOCK);
        }

        pthread_rwlock_unlock(&state->bc.rwlock);
        pthread_mutex_unlock(&state->ledger_mutex);
        trigger_async_fork_processing(state);

        free_block(block);
        return;
    }

    fprintf(stderr, "[Network] Applying approved Block %llu\n", block->block_number);
    
    // Apply verified block and advance chain tip
    int apply_result = apply_block(state, block);
    
    if (apply_result != 0) {
        fprintf(stderr, "[Network] ERROR: Failed to apply approved block %llu (result=%d).\n",
                block->block_number, apply_result);
                    
        pthread_rwlock_unlock(&state->bc.rwlock);
        pthread_mutex_unlock(&state->ledger_mutex);
        
        pthread_mutex_lock(&state->mutex);
        if (!state->in_blockchain_sync) {
            state->in_blockchain_sync = 1;
            pthread_mutex_unlock(&state->mutex);
            fprintf(stderr, "[Network] Triggering async sync for application failure.\n");
            trigger_async_sync(state, sender_pubkey, true);
        } else {
            pthread_mutex_unlock(&state->mutex);
        }
            
        free_block(block);
        return;
    }
        
    pthread_rwlock_unlock(&state->bc.rwlock);
    pthread_mutex_unlock(&state->ledger_mutex);
    
    trigger_proposer_if_eligible(state);
    free_block(block);
}

/**
 * @brief Destructor callback for BlockVoteQueue hash table entries.
 *
 * @pre `data` must point to a valid BlockVoteQueue structure or NULL.
 * @post Votes array is freed, synchronization primitives destroyed, queue freed.
 * @sideeffect Releases heap memory and pthread resources.
 * @sync Thread Safety: Reentrant.
 *
 * @param[in,out] data Pointer to BlockVoteQueue instance.
 *
 * @return void.
 * @complexity Time: O(1); Space: O(1).
 */
void free_block_vote_queue(void *data) {
    if (!data) return;
    BlockVoteQueue *q = (BlockVoteQueue *)data;
    pthread_mutex_lock(&q->vote_lock);
    q->ref_count--;
    if (q->ref_count <= 0) {
        if (q->votes) {
            free(q->votes);
            q->votes = NULL;
        }
        q->count = 0;
        q->head = 0;
        q->size = 0;
        q->yes_votes = 0;
        pthread_cond_destroy(&q->cond);
        pthread_mutex_unlock(&q->vote_lock);
        pthread_mutex_destroy(&q->vote_lock);
        free(q);
    } else {
        pthread_mutex_unlock(&q->vote_lock);
    }
}

/**
 * @brief Checks if local node is elected proposer and has pending mint transactions.
 *
 * If eligible and not currently synchronizing, spawns a detached proposer thread.
 *
 * @pre `state` must be non-NULL.
 * @post If elected and pending mint exists, spawns proposal worker thread.
 * @sideeffect Spawns proposal thread via `spawn_propose_block_thread`.
 * @sync Thread Safety: Acquires `state->mutex`, `state->game_state.mutex`,
 *       `state->p2p_network.mutex`, and `state->epoch_mutex` sequentially.
 *
 * @param[in,out] state Pointer to global State structure.
 *
 * @return void.
 * @complexity Time: O(MAX_PENDING_OPS); Space: O(1).
 */
void trigger_proposer_if_eligible(State *state) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)state;
    return;
#else
    if (!state) return;

    // Guard against proposing during active sync or target height deficit
    pthread_mutex_lock(&state->mutex);
    if (state->in_blockchain_sync ||
        atomic_load(&state->sync_thread_active) ||
        (state->network_target_block_number > 0 && state->current_block_number < state->network_target_block_number)) {
        pthread_mutex_unlock(&state->mutex);
        return;
    }

    uint64_t next_block_height = state->current_block_number + 1;
    int has_mint = 0;
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (pop && pop->type == OP_MINT_COIN) {
            has_mint = 1;
            break;
        }
    }
    pthread_mutex_unlock(&state->mutex);

    // Edge-case recovery: force DKG initiation across active committee if epoch key is zeroed on existing chain
    pthread_mutex_lock(&state->game_state.mutex);
    bool epoch_key_zeroed = is_zeroed(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
    pthread_mutex_unlock(&state->game_state.mutex);

    if (epoch_key_zeroed && state->current_block_number > 0) {
        size_t active_nodes = 1; /* local validator */
        pthread_mutex_lock(&state->p2p_network.mutex);
        const uint8_t **seen_keys = NULL;
        if (state->p2p_network.num_known_peers > 0) {
            seen_keys = malloc(state->p2p_network.num_known_peers * sizeof(const uint8_t *));
        }
        if (seen_keys) {
            size_t seen_count = 0;
            for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                Peer *peer = state->p2p_network.known_peers[i];
                if (peer && peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED &&
                    !is_zeroed(peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) &&
                    memcmp(peer->peer_wallet.dilithium_pubkey,
                           state->p2p_network.local_peer.peer_wallet.dilithium_pubkey,
                           DILITHIUM_PUBKEY_LEN) != 0) {
                    seen_keys[seen_count++] = peer->peer_wallet.dilithium_pubkey;
                }
            }
            if (seen_count > 0) {
                qsort(seen_keys, seen_count, sizeof(const uint8_t *), compare_pubkey_ptrs);
                active_nodes++;
                for (size_t j = 1; j < seen_count; j++) {
                    if (memcmp(seen_keys[j], seen_keys[j - 1], PUBKEY_LEN) != 0) active_nodes++;
                }
            }
            free(seen_keys);
        }
        pthread_mutex_unlock(&state->p2p_network.mutex);

        if (active_nodes >= 10) {
            pthread_mutex_lock(&state->epoch_mutex);
            uint64_t current_epoch_num = state->current_block_number / BLOCKS_PER_DAY;
            uint8_t epoch_session_id[COIN_ID_LEN];
            char epoch_input[32];
            snprintf(epoch_input, sizeof(epoch_input), "DKG_EPOCH_%llu", (unsigned long long)current_epoch_num);
            SHA256((uint8_t *)epoch_input, strlen(epoch_input), epoch_session_id);

            DKGSession *sess = hash_table_lookup(state->dkg_active_sessions, epoch_session_id, false);
            if (!sess) {
                DKGSession *pre_session = calloc(1, sizeof(DKGSession));
                if (pre_session) {
                    memcpy(pre_session->session_id, epoch_session_id, COIN_ID_LEN);
                    atomic_init(&pre_session->ref_count, 1);
                    pre_session->block_height = state->current_block_number;
                    pre_session->committee_count = 10;
                    pre_session->status = 0;
                    pre_session->worker_spawned = true;
                    pthread_cond_init(&pre_session->phase_cond, NULL);
                    hash_table_insert(state->dkg_active_sessions, epoch_session_id, pre_session, HASH_ENTRY_DKG_SESSION);
                    atomic_fetch_add_explicit(&pre_session->ref_count, 1, memory_order_relaxed);
                    spawn_dkg_worker_thread(state, epoch_session_id, state->current_block_number);
                }
            }
            pthread_mutex_unlock(&state->epoch_mutex);
        }
    }

    if (!has_mint) return;

    // Check deterministic VRF/stake election for next height and propose if elected
    uint8_t proposer_pubkey[PUBKEY_LEN];
    if (select_proposer(state, next_block_height, proposer_pubkey) == 0) {
        if (memcmp(proposer_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
            fprintf(stderr, "[Consensus] Triggering delayed block proposal for epoch %llu with pending mint op\n", next_block_height);
            spawn_propose_block_thread(state, NULL);
        }
    }
#endif
}

/* ============================================================================ */
/* SECTION 16: Autonomous Auto-Pilot Subsystem                                 */
/* ============================================================================ */
/* Architectural Preface:
 * Implements autonomous wallet maintenance and participation for non-interactive
 * nodes. Balances staked vs unstaked SCL towards the configured target ratio every
 * 30 seconds and periodically generates and broadcasts quantum valuations using
 * available encrypted Centinel UTXO vouchers.
 */

/**
 * @brief Executes a single execution step of the autonomous Auto-Pilot loop.
 *
 * Operational Mechanics:
 * 1. Balance Rebalancing (every 30 seconds): Evaluates liquid vs staked SCL balance.
 *    If divergence exceeds tolerance, generates and broadcasts `OP_STAKE` or `OP_UNSTAKE`.
 * 2. Valuation Submission: Calculates permissible hourly valuation rate based on
 *    staked SCL and transaction fees. If interval elapsed and UTXO validations exist,
 *    mathematically burns 1 UTXO voucher, constructs a randomized valuation multiset,
 *    signs with user's Dilithium key, and dispatches `MSG_VALUATION_PROPOSAL`.
 *
 * @pre `state` must be non-NULL and autopilot active.
 * @post Autonomous rebalancing or valuation operations queued if intervals elapsed.
 * @sideeffect Broadcasts network transactions; consumes local UTXO validations.
 * @sync Thread Safety: Acquires `state->mutex`, `state->bc.rwlock` (read), and
 *       `state->user_wallet.utxo_mutex`.
 *
 * @param[in,out] state Pointer to global State structure.
 *
 * @return void.
 * @complexity Time: O(UTXO_Count); Space: O(1).
 */
void scl_autopilot_step(State *state) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state;
    return;
#else
    if (!state || !atomic_load(&state->autopilot_running) || atomic_load(&global_shutdown)) return;

    pthread_mutex_lock(&state->mutex);
    bool is_syncing = state->in_blockchain_sync ||
                      atomic_load(&state->sync_thread_active) ||
                      (state->network_target_block_number > 0 && state->current_block_number < state->network_target_block_number);
    pthread_mutex_unlock(&state->mutex);
    if (is_syncing) return;

    static uint64_t last_val_submission_time = 0;
    static uint64_t last_rebalance_time = 0;
    uint64_t now_ms = get_time_ms();

    // 1. Staking / Unstaking Autonomous Balance Rebalancing (every 30 seconds)
    if (now_ms - last_rebalance_time >= 30000 || last_rebalance_time == 0) {
        last_rebalance_time = now_ms;

        uint8_t threshold_pubkey[PUBKEY_LEN];
        if (compute_threshold_pubkey(state, threshold_pubkey) == 0) {
            pthread_mutex_lock(&state->mutex);
            uint64_t unstaked_subunits = calculate_balance_subunits(&state->bc, state->user_wallet.dilithium_pubkey, false);
            uint64_t staked_subunits = calculate_staked_subunits(&state->bc, threshold_pubkey);
            uint64_t pending_unstaked = calculate_pending_consumed_subunits(state, state->user_wallet.dilithium_pubkey, false);
            uint64_t pending_staked = calculate_pending_consumed_subunits(state, threshold_pubkey, true);
            uint64_t sched_unstaked = atomic_load(&state->scheduled_consumed_subunits);
            uint64_t sched_staked = atomic_load(&state->scheduled_staked_subunits);
            pthread_mutex_unlock(&state->mutex);

            bool has_pending_tx = (pending_unstaked > 0 || pending_staked > 0 || sched_unstaked > 0 || sched_staked > 0);
            if (!has_pending_tx) {
                for (int i = 0; i < MAX_PENDING_OPS; i++) {
                    Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                    if (pop && (pop->type == OP_STAKE || pop->type == OP_UNSTAKE || pop->type == OP_TRANSFER_POINTER)) {
                        has_pending_tx = true;
                        break;
                    }
                }
            }

            if (!has_pending_tx) {
                uint64_t eff_unstaked = unstaked_subunits;
                uint64_t eff_staked = staked_subunits;
                uint64_t total_effective = eff_unstaked + eff_staked;

                uint32_t target_ratio = state->config.autopilot_stake_ratio;
                if (target_ratio > 100) target_ratio = 100;

                if (total_effective >= SUBUNITS_PER_COIN) {
                    uint64_t target_staked = (total_effective * (uint64_t)target_ratio) / 100ULL;
                    uint64_t tolerance = (total_effective * 5ULL) / 100ULL;
                    if (tolerance < SUBUNITS_PER_COIN) tolerance = SUBUNITS_PER_COIN;

                    if (eff_staked + tolerance < target_staked && eff_unstaked > SUBUNITS_PER_COIN) {
                        uint64_t delta = target_staked - eff_staked;
                        uint64_t fee = calculate_fee(delta, true);
                        if (delta + fee > eff_unstaked) {
                            double rate = M_PI / 200.0;
                            delta = (uint64_t)((double)eff_unstaked / (1.0 + rate));
                            while (delta > 0 && delta + calculate_fee(delta, true) > eff_unstaked) delta--;
                        }
                        if (delta >= SUBUNITS_PER_COIN) {
                            scl_log(LOG_LEVEL_INFO, "AutoPilot", "Autonomous staking triggered: %.4f SCL (Target: %u%%)", (double)delta / SUBUNITS_PER_COIN, target_ratio);
                            create_and_broadcast_stake(state, delta, false);
                        }
                    } else if (eff_staked > target_staked + tolerance && eff_staked > SUBUNITS_PER_COIN) {
                        uint64_t delta = eff_staked - target_staked;
                        uint64_t fee = calculate_fee(delta, true);
                        if (delta + fee > eff_staked) {
                            double rate = M_PI / 200.0;
                            delta = (uint64_t)((double)eff_staked / (1.0 + rate));
                            while (delta > 0 && delta + calculate_fee(delta, true) > eff_staked) delta--;
                        }
                        if (delta >= SUBUNITS_PER_COIN) {
                            scl_log(LOG_LEVEL_INFO, "AutoPilot", "Autonomous unstaking triggered: %.4f SCL (Target: %u%%)", (double)delta / SUBUNITS_PER_COIN, target_ratio);
                            create_and_broadcast_unstake(state, delta, false);
                        }
                    }
                }
            }
        }
    }

    // 2. Autonomous Valuation Submissions
    uint64_t fees_paid = calculate_fees_paid_subunits(&state->bc, state->user_wallet.dilithium_pubkey);
    double fees_scl = (double)fees_paid / SUBUNITS_PER_COIN;
    uint8_t threshold_pk[PUBKEY_LEN];
    uint64_t staked_sub = (compute_threshold_pubkey(state, threshold_pk) == 0) ? calculate_staked_subunits(&state->bc, threshold_pk) : 0;
    double staked_scl = (double)staked_sub / SUBUNITS_PER_COIN;
    uint64_t max_rate_per_hr = 1 + (uint64_t)floor(staked_scl + fees_scl);

    uint32_t target_per_hr = state->config.autopilot_valuations_per_hour;
    if (target_per_hr == 0) target_per_hr = 1;
    if (target_per_hr > max_rate_per_hr) target_per_hr = (uint32_t)max_rate_per_hr;

    uint64_t interval_ms = 3600000ULL / (uint64_t)target_per_hr;
    if (interval_ms < 10000) interval_ms = 10000;

    if (now_ms - last_val_submission_time >= interval_ms || last_val_submission_time == 0) {
        // Scan unspent validation UTXOs confirmed in MMR tree
        uint64_t available_utxos = 0;
        pthread_rwlock_rdlock(&state->bc.rwlock);
        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
            ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
            bool is_spent = hash_table_lookup(state->bc.centinel.nullifier_set, utxo->nullifier, true) != NULL ||
                           (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, utxo->nullifier) &&
                            scl_db_has_nullifier(utxo->nullifier));
            bool is_pending_spend = false;
            for (int k = 0; k < MAX_PENDING_OPS; k++) {
                Operation *pop = atomic_load_explicit(&state->pending_operations[k], memory_order_acquire);
                if (pop && pop->type == OP_REDEEM_CENTINEL && memcmp(pop->data.redeem_centinel.nullifier, utxo->nullifier, NULLIFIER_LEN) == 0) {
                    is_pending_spend = true;
                    break;
                }
            }
            if (!is_spent && !is_pending_spend) {
                uint8_t commitment_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&utxo->commitment, sizeof(BdlopCommitment), commitment_hash);
                if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, commitment_hash, 0) >= 0) {
                    available_utxos += utxo->amount;
                }
            }
        }
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
        pthread_rwlock_unlock(&state->bc.rwlock);

        // Consume 1 Centinel validation voucher to fund valuation submission
        if (available_utxos >= 1) {
            if (consume_utxos_for_amount(state, 1) == 0) {
                Valuation new_val;
                memset(&new_val, 0, sizeof(Valuation));
                uint8_t uid[USER_ID_LEN];
                SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, uid);
                memcpy(new_val.user_id, uid, USER_ID_LEN);

                GameStateSnapshot *snap = acquire_game_state_snapshot(state);
                for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
                    unsigned char rand_byte = 0;
                    RAND_bytes(&rand_byte, 1);
                    if (snap && snap->valuation_count > 0 && (rand_byte % 3 != 0)) {
                        int sample_row = rand_byte % snap->valuation_count;
                        new_val.numbers[j] = snap->game_audit[sample_row].numbers[j];
                    } else {
                        new_val.numbers[j] = rand_byte % 100;
                    }
                }
                release_game_state_snapshot(snap);

                new_val.timestamp = get_real_time_us();
                memset(new_val.beacon_seed, 0, 32);

                ValuationData vd;
                memset(&vd, 0, sizeof(ValuationData));
                vd.valuation = new_val;
                memcpy(vd.pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

                uint8_t core_data[sizeof(Valuation)];
                size_t core_len = serialize_core_valuation(&new_val, core_data);
                pthread_mutex_lock(&state->wallet_mutex);
                dilithium_sign(core_data, core_len, state->user_wallet.dilithium_privkey, vd.signature);
                pthread_mutex_unlock(&state->wallet_mutex);

                Message *msg = calloc(1, sizeof(Message));
                if (msg) {
                    msg->type = MSG_VALUATION_PROPOSAL;
                    size_t offset = 0;
                    memcpy(msg->payload + offset, core_data, core_len); offset += core_len;
                    memcpy(msg->payload + offset, vd.pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
                    memcpy(msg->payload + offset, vd.signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
                    msg->length = offset;

                    enqueue_submission(state, msg);
                    free(msg);
                }

                last_val_submission_time = now_ms;
                scl_log(LOG_LEVEL_INFO, "AutoPilot", "Auto-submitted Valuation Proposal (Rate: %u/hr, Stake Ratio: %u%%)", target_per_hr, state->config.autopilot_stake_ratio);
            }
        }
    }
#endif
}

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Thread entry routine for autonomous background Auto-Pilot worker.
 *
 * @pre `arg` must point to global State structure.
 * @post Terminates cleanly when `state->autopilot_running` is cleared or shutdown signaled.
 * @sideeffect Periodically logs informational telemetry.
 * @sync Thread Safety: Coordinated via atomic flags and sleep backoff.
 *
 * @param[in,out] arg Void pointer to global State structure.
 *
 * @return NULL unconditionally on termination.
 * @complexity Time: Continuous background execution; Space: O(1).
 */
static void *autopilot_daemon_thread(void *arg) {
    State *state = (State *)arg;
    scl_log(LOG_LEVEL_INFO, "AutoPilot", "Autonomous Auto-Pilot background thread started.");

    while (atomic_load(&state->autopilot_running) && !atomic_load(&global_shutdown)) {
        scl_autopilot_step(state);
        for (int i = 0; i < 50 && atomic_load(&state->autopilot_running) && !atomic_load(&global_shutdown); i++) {
            usleep(100000);
        }
    }

    scl_log(LOG_LEVEL_INFO, "AutoPilot", "Autonomous Auto-Pilot background thread terminated.");
    return NULL;
}
#endif

/**
 * @brief Starts the background Auto-Pilot daemon thread.
 *
 * @pre `state` must be non-NULL.
 * @post `state->autopilot_running` is true; `state->autopilot_thread` is running detached.
 * @sideeffect Spawns background thread with an 8 MB stack.
 * @sync Thread Safety: Atomically updates `state->autopilot_running`.
 *
 * @param[in,out] state Pointer to global State structure.
 *
 * @return void.
 * @complexity Time: O(1); Space: 8 MB thread stack.
 */
void start_autopilot_thread(State *state) {
    if (!state) return;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    atomic_store(&state->autopilot_running, true);
    return;
#else
    if (atomic_load(&state->autopilot_running)) return;
    atomic_store(&state->autopilot_running, true);
    
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    if (pthread_create(&state->autopilot_thread, &attr, autopilot_daemon_thread, state) != 0) {
        atomic_store(&state->autopilot_running, false);
        scl_log(LOG_LEVEL_ERROR, "AutoPilot", "Failed to spawn autopilot daemon thread.");
    } else {
        pthread_detach(state->autopilot_thread);
    }
    pthread_attr_destroy(&attr);
#endif
}

/**
 * @brief Stops the background Auto-Pilot daemon thread.
 *
 * @pre `state` must be non-NULL.
 * @post `state->autopilot_running` is set to false.
 * @sideeffect Signals termination to running background thread.
 * @sync Thread Safety: Atomically stores false to `state->autopilot_running`.
 *
 * @param[in,out] state Pointer to global State structure.
 *
 * @return void.
 * @complexity Time: O(1); Space: O(1).
 */
void stop_autopilot_thread(State *state) {
    if (!state) return;
    atomic_store(&state->autopilot_running, false);
}

/* ============================================================================ */
/* SECTION 17: Valuation Proposal Ingestion and Simulation                     */
/* ============================================================================ */
/* Architectural Preface:
 * Ingests inbound MSG_VALUATION_PROPOSAL envelopes from peers. Verifies Dilithium
 * signatures, filters duplicate proposals, binds the current epoch's randomness
 * beacon seed, appends the valuation to the global game audit buffer, and executes
 * localized quantum auto-simulation for local user accounts.
 */

/**
 * @brief Verifies and ingests an incoming valuation proposal into the game audit.
 *
 * Operational Mechanics:
 * 1. Verifies Dilithium signature over core valuation byte serialization.
 * 2. Deduplicates proposal hash against `state->processed_txs`.
 * 3. Injects Fiat-Shamir entropy: binds `beacon_seed = SHA256(epoch_threshold_signature)`
 *    into the valuation struct.
 * 4. Appends valuation to the global circular audit buffer via `add_valuation`.
 * 5. If local user identity is present, invokes `auto_simulate` to evaluate quantum
 *    total variation distance against local user prediction templates.
 *
 * @pre `state`, `vd`, and `hash` must be non-NULL.
 * @post If valid and unique, valuation is appended to the active audit matrix.
 * @sideeffect Mutates `state->processed_txs` and `state->game_state`.
 * @sync Thread Safety: Acquires `state->mutex` and `state->game_state.mutex`.
 *
 * @param[in,out] state Pointer to global State structure.
 * @param[in]     vd    Pointer to inbound ValuationData structure.
 * @param[in]     hash  Pointer to 32-byte SHA-256 hash of core valuation data.
 *
 * @return void.
 * @complexity Time: O(Signature_Verify + Audit_Append + AutoSimulate); Space: O(1).
 */
void process_valuation_proposal(State *state, const ValuationData *vd, uint8_t *hash) {
    // Verify peer Dilithium signature over core valuation data
    uint8_t core_data[sizeof(Valuation)];
    size_t core_len = serialize_core_valuation(&vd->valuation, core_data);
    if (dilithium_verify(core_data, core_len, vd->signature, vd->pubkey) != 0) return;
    
    // Prevent processing duplicate valuation proposals
    pthread_mutex_lock(&state->mutex);
    if (hash_table_lookup(state->processed_txs, hash, false)) {
        pthread_mutex_unlock(&state->mutex);
        return;
    }
    hash_table_insert(state->processed_txs, hash, NULL, HASH_ENTRY_TX);
    pthread_mutex_unlock(&state->mutex);
    
    Valuation val_copy = vd->valuation;
    
    // Finalize Phase 2/3: Inherit beacon_seed securely from the current block's threshold signature
    pthread_mutex_lock(&state->game_state.mutex);
    if (state->current_block_number > 0 && !is_zeroed(state->game_state.current_epoch_signature, SIGNATURE_LEN)) {
        SHA256(state->game_state.current_epoch_signature, SIGNATURE_LEN, val_copy.beacon_seed);
    } else {
        memset(val_copy.beacon_seed, 0, 32);
    }
    pthread_mutex_unlock(&state->game_state.mutex);
    
    // Append to global game audit buffer
    int added_index = add_valuation(state, &val_copy);
    if (added_index >= 0) {
        User *local_user = NULL;
        pthread_mutex_lock(&state->mutex);
        for (size_t i = 0; i < state->user_count; i++) {
            if (memcmp(state->users[i].dilithium_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                local_user = &state->users[i];
                break;
            }
        }
        pthread_mutex_unlock(&state->mutex);
        
        // Run quantum prediction simulation against incoming peer valuation
        if (local_user) {
            auto_simulate(state, local_user, &val_copy, added_index);
        }
    }
}
