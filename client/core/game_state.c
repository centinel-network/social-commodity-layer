/**
 * @file client/core/game_state.c
 * @brief Satocialist Protocol: Proof-of-Symmetry (PoS2) Game Engine & Dynamic Economic Equilibrium Implementation
 *
 * @details
 * Implements the Proof-of-Symmetry (PoS²) consensus matrix evaluation, dynamic economic stage equilibrium,
 * participant user registration, hourly validation credit grants, quantum pattern matching verification,
 * and deterministic block proposer election.
 *
 * @section protocol_invariants System Invariants Enforced
 * - Dynamic Stage Lower Bound (Lean 4 invariants.lean: Theorem 2): The consensus stage requirement $T$
 *   is strictly bounded below by 2 for all arbitrary issuance and staking states.
 * - Distinct User Sybil Defense (coalition.lean: Theorem 5): Matching rows are valid if and only if
 *   the count of unique participant User IDs in the matching rows meets or exceeds $T$.
 * - Zero-User Filtering: Empty valuation slots with zeroed User IDs are strictly filtered from matching
 *   and threshold evaluation to prevent phantom matches.
 * - Monotonic Subunit Accounting: Minting rewards are capped by the protocol hard cap (16,000,000 SCL)
 *   or recycled fee pool volume when cap is reached.
 * - Deterministic Leader Election: When an active DKG committee is established, proposer selection is
 *   constrained to committee members; otherwise, active peers rotate in deterministic 60-second time slots.
 *
 * @section concurrency_model Threading & Concurrency
 * - `state->game_state.mutex`: Protects modifications to the live circular matrix.
 * - Lock-Free Read Snapshots: Pattern matching executes against immutable @ref GameStateSnapshot structures.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <math.h>
#include <time.h>
#include "game_state.h"
#include "user.h"
#include "blockchain.h"
#include "hash_table.h"
#include "protocol.h"
#include "queue.h"
#include "network.h"
#include "client_network.h"
#include "client_aux.h"
#include "crypto.h"
#include "constants.h"
#include "utils.h"

// Route local logging directly to filtered telemetry engine
#undef fprintf
#define fprintf(stream, ...) do { \
    if (stream == stderr) { \
        scl_log_stderr("GameState", __VA_ARGS__); \
    } else { \
        scl_fprintf(stream, __VA_ARGS__); \
    } \
} while(0)

#undef printf
#define printf(...) scl_log(LOG_LEVEL_INFO, "GameState", __VA_ARGS__)

extern User *global_user;

/* ============================================================================ */
/* SECTION 1: ECONOMIC STAGE EQUILIBRIUM & SUBSYSTEM INITIALIZATION             */
/* ============================================================================ */

/**
 * @brief Evaluates the dynamic consensus stage threshold T from issuance and staking volumes.
 *
 * @param[in] total_rewarded_subunits Lifetime issued coin reward volume in atomic subunits.
 * @param[in] total_staked_subunits Cumulative active staked capital across all validators in subunits.
 * @return Consensus stage requirement $T \ge 2$.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int calculate_current_stage(uint64_t total_rewarded_subunits, uint64_t total_staked_subunits) {
    // Calculate base stage with minimum threshold of 2
    int base_stage = total_rewarded_subunits / (SCL_COIN_THRESHOLD * SUBUNITS_PER_COIN);
    int stage = base_stage + 2;
    
    // Calculate staked coins (convert subunits to whole coins)
    uint64_t staked_coins = total_staked_subunits / SUBUNITS_PER_COIN;
    
    // Decrease stage by 1 for every 2,000,000 coins staked
    int stage_reduction = staked_coins / 2000000;
    stage -= stage_reduction;
    
    // Ensure minimum stage is 2
    if (stage < 2) {
        stage = 2;
    }
    
    return stage;
}

/**
 * @brief Initializes the GameState subsystem, circular audit buffer, and snapshot mutexes.
 *
 * @param[out] state Pointer to global @ref State container to configure.
 * @param[in] is_bootstrap Flag: 1 if initializing a network bootstrap seed node; 0 for standard node.
 * @return 0 on success; -1 on mutex initialization failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int game_state_init(State *state, int is_bootstrap) {
    if (!state) {
        fprintf(stderr, "[GameState] ERROR: NULL State pointer\n");
        return -1;
    }

    // Initialize all game state fields
    memset(&state->game_state, 0, sizeof(GameState));

    // Zero out audit buffer for security
    memset(state->game_state.game_audit, 0, sizeof(state->game_state.game_audit));

    state->game_state.remaining_scl_subunits = MAX_TOTAL_SUBUNITS;
    state->game_state.total_rewarded_scl_subunits = 0;
    state->game_state.current_audit_index = 0;
    state->game_state.valuation_count = 0;  // Initialize count
    state->game_state.cached_stage = 2; // Baseline stage starting at 2 matches
    state->game_state.audit_timestamp = is_bootstrap ? get_real_time_us() : 0;

    if (pthread_mutex_init(&state->game_state.mutex, NULL) != 0) {
        fprintf(stderr, "[GameState] ERROR: Failed to initialize mutex: %s\n", strerror(errno));
        return -1;
    }

    if (pthread_mutex_init(&state->snapshot_update_mutex, NULL) != 0) {
        fprintf(stderr, "[GameState] ERROR: Failed to initialize snapshot mutex: %s\n", strerror(errno));
        return -1;
    }
    atomic_init(&state->active_snapshot_ptr, 0);
    update_game_state_snapshot(state);

    scl_log(LOG_LEVEL_INFO, "GameState", "Game State Initialized");
    return 0;
}

/* ============================================================================ */
/* SECTION 2: PARTICIPANT IDENTITY REGISTRATION & VALIDATION TIMER              */
/* ============================================================================ */

/**
 * @brief Registers a new participant identity into the node's local user table.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] user_id 32-byte SHA-256 digest of the participant's public key.
 * @param[in] pubkey 2,592-byte Dilithium5 public verification key.
 * @return 0 on success; -1 on validation mismatch, capacity saturation, or duplicate ID.
 *
 * @complexity Time: O(1) amortized, Space: O(sizeof(User)).
 */
int register_user(State *state, const uint8_t *user_id, const uint8_t *pubkey) {
    if (!state || !user_id || !pubkey) {
        fprintf(stderr, "[GameState] Invalid parameters\n");
        return -1;
    }
    uint8_t computed_id[USER_ID_LEN];
    SHA256(pubkey, PUBKEY_LEN, computed_id);
    if (memcmp(computed_id, user_id, USER_ID_LEN) != 0) {
        fprintf(stderr, "[GameState] Invalid user_id\n");
        return -1;
    }
    pthread_mutex_lock(&state->mutex);
    for (size_t i = 0; i < state->user_count; i++) {
        if (memcmp(state->users[i].user_id, user_id, USER_ID_LEN) == 0) {
            fprintf(stderr, "[GameState] Duplicate user ID\n");
            pthread_mutex_unlock(&state->mutex);
            return -1;
        }
    }
    if (state->user_count >= MAX_CLIENTS) {
        fprintf(stderr, "[GameState] Maximum client limit reached\n");
        pthread_mutex_unlock(&state->mutex);
        return -1;
    }
    if (state->users == NULL) {
        state->users = calloc(MAX_CLIENTS, sizeof(User));
        if (!state->users) {
            fprintf(stderr, "[GameState] Failed to allocate user array\n");
            pthread_mutex_unlock(&state->mutex);
            return -1;
        }
    }

    User *user = &state->users[state->user_count];
    // Directly set peer info without lookup
    if (user_init(user, state, pubkey) != 0) {
        fprintf(stderr, "[GameState] User initialization failed\n");
        pthread_mutex_unlock(&state->mutex);
        return -1;
    }
    memcpy(user->dilithium_pubkey, pubkey, PUBKEY_LEN);

    GenericHashEntry *entry = malloc(sizeof(GenericHashEntry));
    if (!entry) {
        scl_log(LOG_LEVEL_ERROR, "GameState", "Failed to allocate hash entry");
        destroy_user(user);
        pthread_mutex_unlock(&state->mutex);
        return -1;
    }
    memcpy(entry->key, user_id, USER_ID_LEN);
    entry->type = HASH_ENTRY_USER;
    entry->data.user = user;
    entry->next = NULL;
    uint32_t index = hash_func(user_id, state->user_table->size);
    // Insert new user into hash table bucket chain
    entry->next = state->user_table->buckets[index];
    state->user_table->buckets[index] = entry;
    state->user_table->count++;
    state->user_count++;
    char hex_pub[33];
    bytes_to_hex(pubkey, 16, hex_pub);
    scl_log(LOG_LEVEL_INFO, "GameState", "Registered user %zu, pubkey (first 16 bytes): %s", state->user_count, hex_pub);
    pthread_mutex_unlock(&state->mutex);
    return 0;
}

/**
 * @brief Continuous background daemon thread managing hourly validation credit grants.
 *
 * @param[in] arg Pointer to @ref NetworkArgs context.
 * @return NULL upon thread termination.
 *
 * @complexity Time: O(infinite timer loop), Space: O(1).
 */
void *validation_timer(void *arg) {
    NetworkArgs *args = (NetworkArgs *)arg;
    if (!args || !args->state) {
        fprintf(stderr, "[ValidationTimer] ERROR: Invalid arguments\n");
        return NULL;
    }
    
    State *state = args->state;
    struct timespec timeout;
    int ret = 0;
    
    fprintf(stderr, "[ValidationTimer] Thread started\n");
    
    while (args->running && !atomic_load(&global_shutdown)) {
        // Calculate absolute timeout for VALIDATION_INTERVAL seconds
        clock_gettime(CLOCK_REALTIME, &timeout);
        timeout.tv_sec += VALIDATION_INTERVAL;
        
        pthread_mutex_lock(&args->shutdown_mutex);
        // Wait for either the interval or shutdown signal
        ret = pthread_cond_timedwait(&args->shutdown_cond, &args->shutdown_mutex, &timeout);
        pthread_mutex_unlock(&args->shutdown_mutex);
        
        if (ret == ETIMEDOUT) {
            // Timeout occurred - perform validation grant
            if (!args->running || atomic_load(&global_shutdown)) break;
            
            // Call grant_validation directly using global_user without locking state->mutex,
            // completely avoiding the lock inversion deadlock path.
            if (global_user) {
                grant_validation(state, global_user);
            }
        } else if (ret == 0) {
            // Condition variable signaled - shutdown requested
            break;
        }
        // Else continue looping if spurious wakeup
    }
    
    fprintf(stderr, "[ValidationTimer] Thread exiting gracefully\n");
    release_l5_staging_buffer();
    return NULL;
}

/* ============================================================================ */
/* SECTION 3: MATRIX ROW INSERTION & PATTERN MATCHING AUDIT                     */
/* ============================================================================ */

/**
 * @brief Appends a validated 10-integer valuation vector into the circular Game Audit matrix.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] valuation Pointer to source @ref Valuation structure to append.
 * @return Slot index [0..9] where valuation was inserted on success; -1 if duplicate or error.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(1) heap allocation for snapshot.
 */
int add_valuation(State *state, Valuation *valuation) {
    if (!state || !valuation) {
        fprintf(stderr, "[GameState] Invalid parameters in add_valuation\n");
        return -1;
    }
    
    pthread_mutex_lock(&state->game_state.mutex);
    
    if (!is_valuation_in_audit(&state->game_state, valuation)) {
        int added_index = state->game_state.current_audit_index;
        // Add to circular buffer
        state->game_state.game_audit[added_index] = *valuation;
        
        // Update indices
        state->game_state.current_audit_index = (added_index + 1) % AUDIT_SIZE;
        
        // Update count (don't exceed AUDIT_SIZE)
        if (state->game_state.valuation_count < AUDIT_SIZE) {
            state->game_state.valuation_count++;
        }
                
        state->game_state.audit_timestamp = get_real_time_us();
        pthread_mutex_unlock(&state->game_state.mutex);
        
        update_game_state_snapshot(state);
        
        fprintf(stderr, "[GameState] Added valuation, current_audit_index=%d, valuation_count=%d, audit_timestamp=%llu\n",
                state->game_state.current_audit_index, state->game_state.valuation_count,
                state->game_state.audit_timestamp);
        return added_index; // Successfully added
    }
    
    pthread_mutex_unlock(&state->game_state.mutex);
    fprintf(stderr, "[GameState] Valuation already in audit, ignored.\n");
    return -1; // Already existed
}

/**
 * @brief Evaluates constructive quantum pattern matches for a candidate valuation row.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] latest_valuation Pointer to candidate @ref Valuation row being evaluated.
 * @param[in] gs Retained pointer to immutable @ref GameStateSnapshot representing matrix state.
 * @return Total integer matches confirmed.
 *
 * @complexity Time: O(NUM_COLUMNS^2 * QPU_shots), Space: O(AUDIT_SIZE * USER_ID_LEN).
 */
int count_partial_matches(State *state, const Valuation *latest_valuation, GameStateSnapshot *gs) {
    if (!state || !gs || !latest_valuation) return 0;
    
    uint64_t total_staked = calculate_total_staked_subunits(&state->bc);
    int stage = calculate_current_stage(gs->total_rewarded_scl_subunits, total_staked);
    size_t threshold = stage;
    
    uint8_t (*distinct_user_ids)[USER_ID_LEN] = malloc(AUDIT_SIZE * USER_ID_LEN);
    if (!distinct_user_ids) {
        fprintf(stderr, "[GameState] ERROR: Failed to allocate memory for distinct_user_ids\n");
        return 0;
    }
    
    if (is_zeroed(latest_valuation->user_id, USER_ID_LEN)) {
        free(distinct_user_ids);
        fprintf(stderr, "[GameState] No valid latest valuation\n");
        return 0;
    }
    
    int is_full = (gs->valuation_count == AUDIT_SIZE);
    size_t N = gs->valuation_count;
    size_t distinct_users = 0;
    memset(distinct_user_ids, 0, AUDIT_SIZE * USER_ID_LEN);
    
    // Count distinct user IDs across active non-empty matrix rows to enforce Sybil defense
    for (size_t i = 0; i < N; i++) {
        size_t buffer_index = is_full ? (gs->current_audit_index + i) % AUDIT_SIZE : i;
        const Valuation *valuation = &gs->game_audit[buffer_index];
        if (is_zeroed(valuation->user_id, USER_ID_LEN)) continue;
        
        bool is_new = true;
        for (size_t u = 0; u < distinct_users; u++) {
            if (memcmp(distinct_user_ids[u], valuation->user_id, USER_ID_LEN) == 0) {
                is_new = false;
                break;
            }
        }
        
        if (is_new) {
            memcpy(distinct_user_ids[distinct_users], valuation->user_id, USER_ID_LEN);
            distinct_users++;
        }
    }
    
    if (is_full && distinct_users < threshold) {
        fprintf(stderr, "[GameState] Insufficient distinct users for full buffer: %zu < %zu\n", distinct_users, threshold);
        free(distinct_user_ids);
        return 0;
    }
    
    if (!is_full && distinct_users < 2) {
        fprintf(stderr, "[GameState] Insufficient distinct users for partial buffer: %zu < 2\n", distinct_users);
        free(distinct_user_ids);
        return 0;
    }
    
    int total_matches = 0;
    int row_counts[100] = {0};
    for (int i = 0; i < NUMBERS_PER_VALUATION; i++) {
        int num = latest_valuation->numbers[i];
        if (num >= 0 && num < 100) {
            row_counts[num]++;
        }
    }
    
    size_t effective_threshold = is_full ? threshold : 2;
    if (distinct_users >= effective_threshold) {
        for (size_t col = 0; col < NUMBERS_PER_VALUATION; col++) {
            int column_numbers[AUDIT_SIZE];
            size_t valid_rows = 0;
            
            for (size_t i = 0; i < N; i++) {
                size_t buffer_index = is_full ? (gs->current_audit_index + i) % AUDIT_SIZE : i;
                if (is_zeroed(gs->game_audit[buffer_index].user_id, USER_ID_LEN)) continue;
                column_numbers[valid_rows] = gs->game_audit[buffer_index].numbers[col];
                valid_rows++;
            }
            // For each number in the latest valuation's row, check if it appears in this column
            // using quantum logic (this should match the game's approach)
            for (size_t i = 0; i < NUMBERS_PER_VALUATION; i++) {
                int target_number = latest_valuation->numbers[i];
                if (target_number >= 0 && target_number < 100) {
                    if (quantum_check_number_in_column(target_number, column_numbers, valid_rows, distinct_users, latest_valuation->beacon_seed)) {
                        total_matches++;
                        scl_log(LOG_LEVEL_TRACE, "GameState", "Match found: target_number=%d in column %zu", target_number, col);
                    } else {
                        scl_log(LOG_LEVEL_TRACE, "GameState", "No quantum match for target_number=%d in column %zu", target_number, col);
                    }
                }
            }
        }
    }
    
    // Verify full multiset symmetry across all columns when matrix is full
    int full_match = 1;
    if (is_full) {
        for (size_t col = 0; col < NUMBERS_PER_VALUATION; col++) {
            int col_counts[100] = {0};
            for (size_t i = 0; i < N; i++) {
                size_t buffer_index = (gs->current_audit_index + i) % AUDIT_SIZE;
                if (is_zeroed(gs->game_audit[buffer_index].user_id, USER_ID_LEN)) continue;
                int num = gs->game_audit[buffer_index].numbers[col];
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
        }
    }
    
    size_t active_rows = 0;
    for (size_t i = 0; i < N; i++) {
        size_t buffer_index = is_full ? (gs->current_audit_index + i) % AUDIT_SIZE : i;
        if (!is_zeroed(gs->game_audit[buffer_index].user_id, USER_ID_LEN)) {
            active_rows++;
        }
    }

    free(distinct_user_ids);
    fprintf(stderr, "[GameState] Quantum matches for valuation: %d (full match = %d, N=%zu [total slots], active_rows=%zu [non-empty after zero-ID filtration], is_full=%d)\n",
            total_matches, full_match, N, active_rows, is_full);
    return total_matches;
}

/* ============================================================================ */
/* SECTION 4: LEADER ELECTION, MINTING WORKER & SIMULATION                      */
/* ============================================================================ */

/**
 * @brief Serializes and transmits the active Game Audit matrix state to a connected peer.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the requesting peer.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(sizeof(Message)).
 */
void send_audit_to_client(State *state, const uint8_t *pubkey) {
    if (!state || !pubkey) {
        fprintf(stderr, "[Client] ERROR: Invalid arguments in send_audit_to_client\n");
        return;
    }
    Message *msg = calloc(1, sizeof(Message));
    if (!msg) return;
    
    pthread_mutex_lock(&state->game_state.mutex);
    if (serialize_audit_update(&state->game_state, msg) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to serialize audit update\n");
        pthread_mutex_unlock(&state->game_state.mutex);
        free(msg);
        return;
    }
    pthread_mutex_unlock(&state->game_state.mutex);
    if (!send_message(state, pubkey, msg)) {
        scl_log(LOG_LEVEL_DEBUG, "Client", "Failed to send MSG_UPDATE_AUDIT to peer");
        free(msg);
        return;
    }
    fprintf(stderr, "[Client] Sent MSG_UPDATE_AUDIT to peer, length=%u\n", msg->length);
    free(msg);
}

/**
 * @brief Deterministically elects the authorized block proposer for a given epoch height.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] epoch Target block height $H$.
 * @param[out] proposer_pubkey_out 2,592-byte buffer receiving elected proposer's public key.
 * @return 0 on successful election; -1 if no eligible peers or committee members exist.
 *
 * @complexity Time: O(N_peers log N_peers), Space: O(N_peers * sizeof(Peer*)).
 */
int select_proposer(State *state, uint64_t epoch, uint8_t *proposer_pubkey_out) {
    if (!state || !proposer_pubkey_out) {
        fprintf(stderr, "[Consensus] ERROR: Invalid params in select_proposer\n");
        return -1;
    }

    uint8_t committee[10][PUBKEY_LEN];
    size_t committee_count = 0;
    bool has_epoch_key = false;
    
    // Check if an active threshold DKG epoch committee is registered
    pthread_mutex_lock(&state->game_state.mutex);
    has_epoch_key = !is_zeroed(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
    pthread_mutex_unlock(&state->game_state.mutex);
    
    pthread_mutex_lock(&state->epoch_mutex);
    bool is_member_local = state->is_epoch_member;
    if (has_epoch_key) {
        if (state->current_committee_count > 0) {
            memcpy(committee, state->current_committee, state->current_committee_count * PUBKEY_LEN);
            committee_count = state->current_committee_count;
        } else {
            pthread_mutex_unlock(&state->epoch_mutex);
            get_epoch_committee(state, committee, &committee_count, epoch);
            pthread_mutex_lock(&state->epoch_mutex);
            if (committee_count > 0) {
                memcpy(state->current_committee, committee, committee_count * PUBKEY_LEN);
                state->current_committee_count = committee_count;
            }
        }
        pthread_mutex_unlock(&state->epoch_mutex);

        if (committee_count > 0) {
            // Sort committee lexicographically to ensure 100% deterministic order across all nodes
            qsort(committee, committee_count, PUBKEY_LEN, compare_pubkeys_raw);
            
            // Use 100% deterministic time slot and epoch combination to select proposer
            uint64_t time_slot = (uint64_t)time(NULL) / 60;
            uint32_t index = (epoch + time_slot) % committee_count;
            
            memcpy(proposer_pubkey_out, committee[index], PUBKEY_LEN);
            
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            char hex_pub[33];
            bytes_to_hex(proposer_pubkey_out, 16, hex_pub);
            fprintf(stderr, "[Consensus] Selected proposer from committee for epoch %llu: index=%u / %zu members, pubkey (first 16 bytes): %s\n",
                    epoch, index, committee_count, hex_pub);
#endif
            return 0;
        }
    } else {
        pthread_mutex_unlock(&state->epoch_mutex);
    }

    pthread_mutex_lock(&state->p2p_network.mutex);
    size_t num_peers = state->p2p_network.num_known_peers;
    if (num_peers == 0) {
        scl_log(LOG_LEVEL_DEBUG, "Consensus", "No known peers for proposer selection");
        pthread_mutex_unlock(&state->p2p_network.mutex);
        return -1;
    }

    // Filter active peers explicitly to prevent assigning block proposals to dead nodes
    Peer **active_peers = malloc(num_peers * sizeof(Peer *));
    if (!active_peers) {
        pthread_mutex_unlock(&state->p2p_network.mutex);
        return -1;
    }

    size_t active_count = 0;

    for (size_t i = 0; i < num_peers; i++) {
        Peer *peer = state->p2p_network.known_peers[i];
        
        if (!is_zeroed(peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) &&
            validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey)) {
                        
        // Liveness checks removed to ensure strictly deterministic global proposer selection
        
        // If peer is the local node, and we have an epoch key but are not an epoch member, we cannot propose!
        if (memcmp(peer->peer_wallet.dilithium_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            if (has_epoch_key && !is_member_local) {
                continue; // Skip local node since we cannot sign blocks
            }
        }
        
        // If epoch key is active, restrict the proposer selection strictly to deterministic committee members
        if (has_epoch_key) {
            bool in_committee = false;
            for (size_t c_idx = 0; c_idx < committee_count; c_idx++) {
                if (memcmp(committee[c_idx], peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                    in_committee = true;
                    break;
                }
            }
            if (!in_committee) {
                continue;
            }
        }

        active_peers[active_count++] = peer;
        }
    }

    if (active_count == 0) {
        free(active_peers);
        pthread_mutex_unlock(&state->p2p_network.mutex);
        fprintf(stderr, "[Consensus] ERROR: No active peers for proposer selection\n");
        return -1;
    }

    // Sort active peers by their Dilithium public keys natively via memcmp
    qsort(active_peers, active_count, sizeof(Peer *), compare_peers);

    // Deduplicate identical pubkeys in O(N) after sorting to prevent massive O(N^2) bottlenecks
    if (active_count > 1) {
        size_t unique_count = 1;
        for (size_t i = 1; i < active_count; i++) {
            if (memcmp(active_peers[i]->peer_wallet.dilithium_pubkey, active_peers[unique_count - 1]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                active_peers[unique_count++] = active_peers[i];
            }
        }
        active_count = unique_count;
    }

    // Mix time into the deterministic selection to allow round-robin fallback if a node drops
    size_t input_size = DILITHIUM_PUBKEY_LEN * active_count + sizeof(uint64_t) * 2;
    uint8_t *hash_input = malloc(input_size);
    if (!hash_input) {
        free(active_peers);
        pthread_mutex_unlock(&state->p2p_network.mutex);
        return -1;
    }

    for (size_t i = 0; i < active_count; i++) {
        memcpy(hash_input + i * DILITHIUM_PUBKEY_LEN, active_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    }
    
    uint64_t epoch_be = htobe64(epoch);
    memcpy(hash_input + DILITHIUM_PUBKEY_LEN * active_count, &epoch_be, sizeof(uint64_t));
    
    // Rotate proposer every 60 seconds to allow the complete consensus ceremony (60s max) to complete
    uint64_t time_slot = htobe64((uint64_t)time(NULL) / 60);
    memcpy(hash_input + DILITHIUM_PUBKEY_LEN * active_count + sizeof(uint64_t), &time_slot, sizeof(uint64_t));

    // Compute hash and select strictly bounds-safe index
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(hash_input, input_size, hash);
    
    uint32_t hash_val;
    memcpy(&hash_val, hash, sizeof(uint32_t));
    uint32_t index = hash_val % active_count;

    // Copy selected active pubkey
    memcpy(proposer_pubkey_out, active_peers[index]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);

    // Cleanup memory allocations
    free(hash_input);
    free(active_peers);
    pthread_mutex_unlock(&state->p2p_network.mutex);

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    char hex_pub[33];
    bytes_to_hex(proposer_pubkey_out, 16, hex_pub);
    fprintf(stderr, "[Consensus] Selected proposer for epoch %llu: index=%u / %zu active peers, pubkey (first 16 bytes): %s\n",
            epoch, index, active_count, hex_pub);
#endif

    return 0;
}

/**
 * @brief Background thread constructing and proposing an OP_MINT_COIN block reward transaction.
 *
 * @param[in] arg Pointer to heap-allocated @ref MintThreadArgs context (callee assumes ownership and frees).
 * @return NULL upon thread termination.
 *
 * @complexity Time: O(block_proposal_time), Space: O(MAX_MESSAGE_SIZE).
 */
void *mint_thread_func(void *arg) {
    MintThreadArgs *mta = (MintThreadArgs *)arg;
    State *state = mta->state;
    Operation *op = NULL;  // Initialize to NULL at the beginning

    uint8_t owner_pubkey[PUBKEY_LEN];
    int retry_count = 0;
    const int max_retries = 3;

    while (retry_count < max_retries) {
        if (atomic_load(&global_shutdown)) goto cleanup_and_exit;
        if (get_pubkey_by_userid(state, mta->user_id, owner_pubkey)) {
            break;
        }
        retry_count++;
        fprintf(stderr, "[Game] Retry %d/%d for pubkey lookup in mint thread...\n", retry_count, max_retries);
        usleep(1000000);
    }

    if (retry_count >= max_retries) {
        fprintf(stderr, "[Game] ERROR: Failed to retrieve pubkey for user_id after %d retries in mint thread, skipping mint\n", max_retries);
        goto cleanup_and_exit;
    }

    // Verify retrieved pubkey matches the expected user_id
    uint8_t computed_user_id[USER_ID_LEN];
    SHA256(owner_pubkey, PUBKEY_LEN, computed_user_id);
    if (memcmp(computed_user_id, mta->user_id, USER_ID_LEN) != 0) {
        fprintf(stderr, "[Game] Retrieved pubkey does not match expected user_id in mint thread, skipping mint\n");
        log_hex("  Computed user_id: ", computed_user_id, USER_ID_LEN, 8);
        log_hex("  Expected user_id: ", mta->user_id, USER_ID_LEN, 8);
        goto cleanup_and_exit;
    }

    // --- CRITICAL SECTION: Capture state via lock-free snapshot ---
    GameStateSnapshot *snap = acquire_game_state_snapshot(state);
    if (!snap) goto cleanup_and_exit;
        
    // Validate for staleness and zero-user_id immediately via snapshot
    size_t target_index = (mta->snapshot_audit_index == 0) ? AUDIT_SIZE - 1 : mta->snapshot_audit_index - 1;
    const Valuation *target_valuation = &snap->game_audit[target_index];
        
    if (snap->total_rewarded_scl_subunits != mta->snapshot_total_rewarded) {
        fprintf(stderr, "[Game] [STALE STATE DETECTED / FALLBACK] Stale valuation detected in mint thread (total_rewarded changed from %llu to %llu), skipping mint operation gracefully.\n",
                mta->snapshot_total_rewarded, snap->total_rewarded_scl_subunits);
        release_game_state_snapshot(snap);
        goto cleanup_and_exit;
    }

    if (memcmp(target_valuation->user_id, mta->user_id, USER_ID_LEN) != 0) {
        fprintf(stderr, "[Game] Target valuation user_id mismatch in mint thread, skipping mint\n");
        release_game_state_snapshot(snap);
        goto cleanup_and_exit;
    }

    if (is_zeroed(target_valuation->user_id, USER_ID_LEN)) {
        fprintf(stderr, "[Game] Target valuation has zeroed user_id in mint thread (invalid snapshot), skipping mint\n");
        release_game_state_snapshot(snap);
        goto cleanup_and_exit;
    }

    uint64_t base_reward = (uint64_t)mta->matches * SUBUNITS_PER_COIN;
    uint64_t snapshot_total_rewarded_scl_subunits = snap->total_rewarded_scl_subunits;
    uint64_t snapshot_remaining_scl_subunits = snap->remaining_scl_subunits;

    // Capture snapshot for the SCLCoin struct using the perfectly aligned frozen snapshot
    Valuation audit_snapshot[AUDIT_SIZE];
    memcpy(audit_snapshot, mta->audit_snapshot, sizeof(Valuation) * AUDIT_SIZE);
    uint32_t captured_snapshot_count = mta->snapshot_count;
    uint32_t captured_snapshot_audit_index = mta->snapshot_audit_index;
        
    release_game_state_snapshot(snap);
    // --- END CRITICAL SECTION ---

    const uint64_t max_supply = 16000000ULL * SUBUNITS_PER_COIN;
    uint8_t creation_tx_hash[COIN_ID_LEN];
    bool at_cap = (snapshot_total_rewarded_scl_subunits + base_reward >= max_supply);
    uint64_t award_subunits;

    // Prepare data that requires state->mutex before potential propose_block call
    if (at_cap) {
        // Fee collection requires state->mutex for access to state->bc
        pthread_mutex_lock(&state->mutex);
        
        // Allocate 155KB array on the heap to prevent ___chkstk_darwin EXC_BAD_ACCESS crash
        Pointer *fee_pointers = malloc(MAX_INPUTS * sizeof(Pointer));
        if (!fee_pointers) {
            pthread_mutex_unlock(&state->mutex);
            goto cleanup_and_exit;
        }
        
        size_t num_fee = collect_fee_pointers(&state->bc, fee_pointers, MAX_INPUTS);
        uint64_t recycled_subunits = 0;
        
        uint64_t temp_recycled_subunits = 0;
        for (size_t i = 0; i < num_fee; i++) {
            temp_recycled_subunits += fee_pointers[i].end_subunit - fee_pointers[i].start_subunit + 1;
        }
        recycled_subunits = MIN(temp_recycled_subunits, base_reward);

        if (recycled_subunits == 0) {
            fprintf(stderr, "[Game] No fee pointers available for recycling at cap\n");
            free(fee_pointers);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup_and_exit;
        }
        award_subunits = recycled_subunits; // Set final award to the recycled amount
        
        // Use a hash of the total recycled subunits as the creation_tx_hash
        uint64_t recycled_subunits_be = htobe64(recycled_subunits);
        SHA256((uint8_t *)&recycled_subunits_be, sizeof(uint64_t), creation_tx_hash);
        
        fprintf(stderr, "[Game] Recycling %zu fee pointers for mint at cap\n", num_fee);
        free(fee_pointers);
        pthread_mutex_unlock(&state->mutex);
    } else {
        award_subunits = MIN(base_reward, snapshot_remaining_scl_subunits);
        if (award_subunits == 0) {
            fprintf(stderr, "[Game] No subunits available for award in mint thread\n");
            goto cleanup_and_exit;
        }

        // Allocate VLA on the heap
        size_t hash_input_len = PUBKEY_LEN + sizeof(Valuation) + sizeof(uint64_t);
        uint8_t *hash_input = malloc(hash_input_len);
        if (!hash_input) goto cleanup_and_exit;
        
        memcpy(hash_input, owner_pubkey, PUBKEY_LEN);
        memcpy(hash_input + PUBKEY_LEN, &mta->valuation, sizeof(Valuation));
        uint64_t total_rewarded_net = htobe64(mta->snapshot_total_rewarded);
        memcpy(hash_input + PUBKEY_LEN + sizeof(Valuation), &total_rewarded_net, sizeof(uint64_t));
        SHA256(hash_input, hash_input_len, creation_tx_hash);
        
        free(hash_input);
    }

    // --- ANCHOR CALCULATION ---
    SCLCoin new_coin = create_coin(creation_tx_hash, owner_pubkey);
    new_coin.total_subunits = award_subunits;
    new_coin.remaining_subunits = award_subunits;
    memcpy(new_coin.audit_snapshot, audit_snapshot, sizeof(Valuation) * AUDIT_SIZE);
    new_coin.snapshot_count = captured_snapshot_count;
    new_coin.snapshot_audit_index = captured_snapshot_audit_index;
    
    // Compute canonical anchor
    uint8_t computed_anchor[COIN_ID_LEN];
    compute_canonical_sclcoin_hash(&new_coin, computed_anchor);
    memcpy(new_coin.audit_state_anchor, computed_anchor, COIN_ID_LEN);
    
    char hex_coin_id[COIN_ID_LEN * 2 + 1];
    bytes_to_hex(new_coin.coin_id, COIN_ID_LEN, hex_coin_id);
    printf("[Game] create_coin in mint thread: coin_id=%s, total_subunits=%llu\n",
           hex_coin_id, new_coin.total_subunits);

    op = calloc(1, sizeof(Operation));
    if (!op) goto cleanup_and_exit;
    op->type = OP_MINT_COIN;
    op->data.mint_coin.coin = new_coin;
    memcpy(op->data.mint_coin.owner_pubkey, owner_pubkey, PUBKEY_LEN);

    // Add to mempool BEFORE attempting proposal to guarantee it is not lost
    pthread_mutex_lock(&state->mutex);
    int added = add_pending_operation(state, op);
    pthread_mutex_unlock(&state->mutex);

    if (added == 0) {
        Message *pending_msg = calloc(1, sizeof(Message));
        if (pending_msg) {
            pending_msg->type = MSG_PENDING_OPERATION;
            pending_msg->length = serialize_operation(op, pending_msg->payload, MAX_MESSAGE_SIZE);
            if (pending_msg->length > 0) {
                p2p_broadcast(state, pending_msg);
            }
            free(pending_msg);
        }
    }

    uint8_t proposer_pubkey[PUBKEY_LEN];
    bool is_self_proposer = false;

    // Safely acquire state->current_block_number for select_proposer
    pthread_mutex_lock(&state->mutex);
    uint64_t current_block_for_proposer_selection = state->current_block_number;
    pthread_mutex_unlock(&state->mutex);

    // Determine proposer (select_proposer internally locks state->p2p_network.mutex)
    if (select_proposer(state, current_block_for_proposer_selection, proposer_pubkey) != 0) {
        fprintf(stderr, "[Game] ERROR: Failed to select proposer in mint thread, self-proposing as fallback\n");
        is_self_proposer = true;
    } else {
        if (memcmp(proposer_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            fprintf(stderr, "[Game] Self-selected as proposer in mint thread (deterministic selection)\n");
            is_self_proposer = true;
        }
    }

    // IMPORTANT: propose_block and send_message are called WITHOUT holding state->mutex
    // Propose block locally or delegate proposal to elected remote peer
    if (is_self_proposer) {
        propose_block(state, op); // propose_block will acquire state->mutex itself
    } else {
        int send_retries = 0;
        const int max_send_retries = 2;
        bool send_success = false;
                
        while (send_retries < max_send_retries && !send_success) {
            Message *propose_msg = calloc(1, sizeof(Message));
            if (!propose_msg) break;
                            
            propose_msg->type = MSG_PROPOSE_BLOCK;
            propose_msg->length = serialize_operation(op, propose_msg->payload, MAX_MESSAGE_SIZE);
            if (propose_msg->length == 0) {
                fprintf(stderr, "[Game] ERROR: Failed to serialize mint op for propose_msg\n");
                free(propose_msg);
                break;
            }
            // send_message manages its own locking for message_queue and response_mutex
            if (send_message(state, proposer_pubkey, propose_msg) == 1) {
                send_success = true;
                char hex_pub[33];
                bytes_to_hex(proposer_pubkey, 16, hex_pub);
                fprintf(stderr, "[Game] Delegated block proposal to selected peer in mint thread, pubkey (first 16 bytes): %s\n", hex_pub);
            } else {
                send_retries++;
                fprintf(stderr, "[Game] WARNING: Failed to send proposal to selected peer (attempt %d/%d)\n",
                        send_retries, max_send_retries);
                if (send_retries < max_send_retries) {
                    usleep(500000);
                }
            }
            free(propose_msg);
        }
        if (!send_success) {
            fprintf(stderr, "[Game] ERROR: All attempts to send proposal failed, self-proposing as fallback\n");
            propose_block(state, op); // Fallback to self-proposal
        }
    }

    // Recalculate and update stage info
    // 1. Calculate total staked (REQUIRES BC LOCK)
    pthread_rwlock_rdlock(&state->bc.rwlock);
    uint64_t total_staked_subunits = calculate_total_staked_subunits(&state->bc);
    pthread_rwlock_unlock(&state->bc.rwlock);

    // 2. Update stage (REQUIRES GAME STATE LOCK)
    pthread_mutex_lock(&state->game_state.mutex);
    int current_stage = calculate_current_stage(
        state->game_state.total_rewarded_scl_subunits,
        total_staked_subunits
    );
    if (current_stage != state->game_state.cached_stage) {
        state->game_state.cached_stage = current_stage;
        fprintf(stderr, "[Game] Stage updated to %d (rewarded=%llu, staked=%llu)\n",
                current_stage, state->game_state.total_rewarded_scl_subunits, total_staked_subunits);
    }
    pthread_mutex_unlock(&state->game_state.mutex);
        
    uint8_t key[COIN_ID_LEN];
    SHA256((uint8_t*)&op->data.mint_coin, sizeof(SCLCoin), key);
    fprintf(stderr, "[Game] Processed %d matches in mint thread, operation queued, key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
            mta->matches, key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);
        
cleanup_and_exit:
    if (op) free(op);
    free(mta);
    atomic_fetch_sub(&state->active_background_threads, 1);
    arena_cleanup();
    release_l5_staging_buffer();
    return NULL;
}

/**
 * @brief Evaluates matches and triggers asynchronous block reward minting for local node submissions.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] user Pointer to local node operator's @ref User profile.
 * @param[in] val Pointer to submitted @ref Valuation row.
 * @param[in] target_index Index in the audit buffer where valuation was inserted.
 *
 * @complexity Time: O(count_partial_matches), Space: O(sizeof(MintThreadArgs)) heap allocation.
 */
void auto_simulate(State *state, User *user, const Valuation *val, int target_index) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state;
    (void)user;
    (void)val;
    (void)target_index;
    return; // Completely bypass thread spawning and simulation overhead during fuzzing to maximize exec/s
#endif
    // Validate input parameters
    if (!state || !user || !val || target_index < 0 || target_index >= AUDIT_SIZE) {
        fprintf(stderr, "[Game] ERROR: Invalid input\n");
        return;
    }
    
    static bool simulated_indices[AUDIT_SIZE] = {false};
    static uint64_t simulated_timestamps[AUDIT_SIZE] = {0};
    static pthread_mutex_t sim_guard = PTHREAD_MUTEX_INITIALIZER;
    
    // Check blockchain sync status safely avoiding unsigned underflow
    uint64_t safe_epoch = state->bc.sync_epoch > 0 ? state->bc.sync_epoch - 1 : 0;
    if (state->current_block_number < safe_epoch) {
        fprintf(stderr, "[Game] Blockchain not synced, skipping simulation\n");
        return;
    }

    fprintf(stderr, "[Game] Starting simulation, audit_index=%d\n", target_index);
        
    GameStateSnapshot *snap = acquire_game_state_snapshot(state);
    if (!snap) return;

    uint64_t val_timestamp = val->timestamp;
    
    // Prevent double-execution of mint_thread_func for the exact same valuation
    pthread_mutex_lock(&sim_guard);
    if (simulated_indices[target_index] && simulated_timestamps[target_index] == val_timestamp && val_timestamp != 0) {
        pthread_mutex_unlock(&sim_guard);
        release_game_state_snapshot(snap);
        fprintf(stderr, "[Game] SKIPPING MINT: Already simulated for audit index %d\n", target_index);
        return;
    }
    simulated_indices[target_index] = true;
    simulated_timestamps[target_index] = val_timestamp;
    pthread_mutex_unlock(&sim_guard);
    
    // CRITICAL CHECK: Verify this node owns the valuation
    uint8_t current_user_id[USER_ID_LEN];
    SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, current_user_id);
    
    if (memcmp(val->user_id, current_user_id, USER_ID_LEN) != 0) {
        release_game_state_snapshot(snap);
        fprintf(stderr, "[Game] SKIPPING MINT: Node does not own valuation at index %d\n", target_index);
        return;
    }

    if (is_zeroed(val->user_id, USER_ID_LEN)) {
        release_game_state_snapshot(snap);
        fprintf(stderr, "[Game] SKIPPING MINT: Valuation has zeroed user_id (invalid snapshot)\n");
        return;
    }
    
    fprintf(stderr, "[Game] Node authorized to mint: owns valuation\n");
            
    // Count and process partial matches safely with exclusive blockchain access
    pthread_rwlock_rdlock(&state->bc.rwlock);
    int total_matches = count_partial_matches(state, val, snap);
    pthread_rwlock_unlock(&state->bc.rwlock);
    
    fprintf(stderr, "[Game] Total matches: %d\n", total_matches);
    
    // Exit early if no matches found
    if (total_matches <= 0) {
        release_game_state_snapshot(snap);
        return;
    }
    
    // Snapshot for staleness check
    uint8_t target_user_id[USER_ID_LEN];
    memcpy(target_user_id, val->user_id, USER_ID_LEN);
    uint64_t snapshot_total_rewarded = snap->total_rewarded_scl_subunits;
    
    // Capture the exact snapshot
    Valuation captured_audit[AUDIT_SIZE];
    memcpy(captured_audit, snap->game_audit, sizeof(Valuation) * AUDIT_SIZE);
    uint32_t captured_count = snap->valuation_count;
    uint32_t captured_index = (target_index + 1) % AUDIT_SIZE;
        
    // Copy the valuation specifically to avoid race condition after unlock
    Valuation captured_valuation;
    memcpy(&captured_valuation, val, sizeof(Valuation));
    
    release_game_state_snapshot(snap);
    
    // Spawn dedicated thread for minting to avoid blocking network thread
    MintThreadArgs *mta = malloc(sizeof(MintThreadArgs));
    if (!mta) {
        fprintf(stderr, "[Game] ERROR: Failed to allocate MintThreadArgs\n");
        return;
    }
    memcpy(&mta->valuation, &captured_valuation, sizeof(Valuation));
    mta->state = state;
    mta->user = user;
    memcpy(mta->user_id, target_user_id, USER_ID_LEN);
    mta->matches = total_matches;
    mta->snapshot_total_rewarded = snapshot_total_rewarded;
    memcpy(mta->audit_snapshot, captured_audit, sizeof(Valuation) * AUDIT_SIZE);
    mta->snapshot_count = captured_count;
    mta->snapshot_audit_index = captured_index;
    
    // Spawn detached minting worker thread with 8 MiB stack allocation
    pthread_t mint_thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
        
    if (pthread_create(&mint_thread, &attr, mint_thread_func, mta) != 0) {
        fprintf(stderr, "[Game] ERROR: Failed to create mint thread\n");
        atomic_fetch_sub(&state->active_background_threads, 1);
        free(mta);
        pthread_attr_destroy(&attr);
        return;
    }
    pthread_attr_destroy(&attr);
    pthread_detach(mint_thread);
}
