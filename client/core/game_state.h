/**
 * @file client/core/game_state.h
 * @brief Satocialist Protocol: Proof-of-Symmetry (PoS2) Game Engine & Dynamic Economic Equilibrium Interface
 *
 * @details
 * Declares the public interfaces governing the Proof-of-Symmetry (PoS²) consensus matrix, dynamic
 * economic stage calculations, participant account registration, hourly validation grants,
 * quantum pattern matching verification, and deterministic block proposer election across the SCL protocol.
 *
 * @section game_invariants Economic & Game-Theoretic Invariants
 * - Dynamic Stage Lower Bound (Lean 4 invariants.lean: Theorem 2): The consensus stage requirement
 *   $T$ is strictly bounded below by 2 across all issuance and staking states:
 *   $$T = \max\left(2, \; 2 + \left\lfloor \frac{C_{\text{issued}}}{2{,}000{,}000} \right\rfloor - \left\lfloor \frac{C_{\text{staked}}}{2{,}000{,}000} \right\rfloor\right)$$
 * - Staking Stage Monotonicity (Theorem 12): Increasing staked capital monotonically non-increases
 *   the consensus stage requirement, providing mathematical incentives for network capital lockup.
 * - Sybil Resistance via Distinct User Test (coalition.lean: Theorem 5): A candidate valuation
 *   match registers valid block reward subunits if and only if the count of unique participant User IDs
 *   in the matching audit rows satisfies $\text{distinct\_users} \ge T$.
 * - 10x10 Matrix Circularity: The Game Audit buffer contains exactly @ref AUDIT_SIZE (10) valuation rows.
 *   Submissions overwrite the oldest row in circular FIFO order, advancing `current_audit_index`.
 * - Zero-User Filtering: Empty valuation slots with zeroed User IDs are strictly filtered from matching
 *   and threshold evaluation to prevent phantom matches.
 * - Deterministic Leader Election: When an active DKG committee is established, proposer selection is
 *   constrained to committee members; otherwise, active peers rotate in deterministic 60-second time slots.
 *
 * @section thread_safety Concurrency Model & Lock Discipline
 * - Mutations to the live game matrix synchronize via `state->game_state.mutex`.
 * - Lock-free evaluations execute against immutable, reference-counted @ref GameStateSnapshot structures
 *   acquired via @ref acquire_game_state_snapshot and released via @ref release_game_state_snapshot.
 */

#ifndef GAME_STATE_H
#define GAME_STATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include "blockchain.h"
#include "user.h"
#include "constants.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: ECONOMIC STAGE EQUILIBRIUM & SUBSYSTEM INITIALIZATION             */
/* ============================================================================ */

/**
 * @brief Evaluates the dynamic consensus stage threshold T from issuance and staking volumes.
 *
 * @details
 * Formalized under Lean 4 (`Satocialist.calculateCurrentStage`).
 * Evaluates the deterministic economic equation:
 * $$\text{base\_stage} = \left\lfloor \frac{\text{rewarded\_subunits}}{2{,}000{,}000 \times 160{,}000{,}000} \right\rfloor$$
 * $$\text{initial\_stage} = \text{base\_stage} + 2$$
 * $$\text{reduction} = \left\lfloor \frac{\text{staked\_subunits} / 160{,}000{,}000}{2{,}000{,}000} \right\rfloor$$
 * $$\text{stage} = \max(2, \; \text{initial\_stage} - \text{reduction})$$
 *
 * @param[in] total_rewarded_subunits Lifetime issued coin reward volume in atomic subunits.
 * @param[in] total_staked_subunits Cumulative active staked capital across all validators in subunits.
 * @return Consensus stage requirement $T \ge 2$ (representing minimum matching rows required).
 *
 * @thread_safety Pure mathematical function; reentrant and thread-safe.
 * @complexity Time: O(1), Space: O(1).
 */
int calculate_current_stage(uint64_t total_rewarded_subunits, uint64_t total_staked_subunits);

/**
 * @brief Initializes the GameState subsystem, circular audit buffer, and snapshot mutexes.
 *
 * @param[out] state Pointer to global @ref State container to configure.
 * @param[in] is_bootstrap Flag: 1 if initializing a network bootstrap seed node; 0 for standard node.
 * @return 0 on success; -1 on mutex initialization failure.
 *
 * @pre `state` must point to valid writable memory.
 * @post `state->game_state` zeroed; initial snapshot published; mutexes initialized.
 * @complexity Time: O(1), Space: O(1).
 */
int game_state_init(State *state, int is_bootstrap);

/* ============================================================================ */
/* SECTION 2: PARTICIPANT REGISTRATION & VALIDATION GRANTS                      */
/* ============================================================================ */

/**
 * @brief Registers a new participant identity into the node's local user table.
 *
 * @details
 * Verifies that `user_id == SHA256(pubkey, 2592)`. Allocates and initializes a @ref User structure
 * via @ref user_init, sets initial hourly grant timers, and indexes the account into `state->user_table`.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] user_id 32-byte SHA-256 digest of the participant's public key.
 * @param[in] pubkey 2,592-byte Dilithium5 public verification key.
 * @return 0 on success; -1 on validation mismatch, capacity saturation, or duplicate ID.
 *
 * @pre `state`, `user_id`, and `pubkey` must be non-NULL.
 * @thread_safety Acquires `state->mutex` internally.
 * @complexity Time: O(1) amortized hash table insertion, Space: O(sizeof(User)).
 */
int register_user(State *state, const uint8_t *user_id, const uint8_t *pubkey);

/**
 * @brief Continuous background daemon thread managing hourly validation credit grants.
 *
 * @param[in] args Pointer to @ref NetworkArgs context (contains state and shutdown condition).
 * @return NULL upon thread termination.
 *
 * @thread_safety Waits on `args->shutdown_cond` with timed wait of `VALIDATION_INTERVAL` (3,600s).
 * @complexity Time: O(infinite timer loop), Space: O(1).
 */
void *validation_timer(void *args);

/* ============================================================================ */
/* SECTION 3: MATRIX MUTATION & PATTERN MATCHING AUDIT                          */
/* ============================================================================ */

/**
 * @brief Appends a validated 10-integer valuation vector into the circular Game Audit matrix.
 *
 * @details
 * Checks for deduplication against existing active rows. If novel, inserts `valuation` into
 * `game_audit[current_audit_index]`, advances the circular index modulo @ref AUDIT_SIZE (10),
 * updates `audit_timestamp`, and atomically publishes an updated @ref GameStateSnapshot.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] valuation Pointer to source @ref Valuation structure to append.
 * @return Slot index [0..9] where valuation was inserted on success; -1 if duplicate or error.
 *
 * @thread_safety Acquires `state->game_state.mutex` and `state->snapshot_update_mutex`.
 * @complexity Time: O(AUDIT_SIZE), Space: O(1) heap allocation for snapshot.
 */
int add_valuation(State *state, Valuation *valuation);

/**
 * @brief Evaluates constructive quantum pattern matches for a candidate valuation row.
 *
 * @details
 * Verification sequence:
 * 1. Checks Distinct User Test: Counts unique User IDs in active matrix; requires $\text{count} \ge T$.
 * 2. Column Superposition: For each of the 10 columns, extracts integers across active rows and evaluates
 *    constructive interference observation via @ref quantum_check_number_in_column.
 * 3. Multiset Bonus: Awards +1 bonus match if the valuation row multiset matches a column exactly.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] latest_valuation Pointer to candidate @ref Valuation row being evaluated.
 * @param[in] snapshot Retained pointer to immutable @ref GameStateSnapshot representing matrix state.
 * @return Total integer matches confirmed (determines minted SCLCoin reward: `matches * 160M subunits`).
 *
 * @pre `state`, `latest_valuation`, and `snapshot` must be non-NULL.
 * @thread_safety Lock-free read path operating on immutable snapshot memory.
 * @complexity Time: O(NUM_COLUMNS^2 * QPU_shots), Space: O(AUDIT_SIZE * USER_ID_LEN) stack/heap buffer.
 */
int count_partial_matches(State *state, const Valuation *latest_valuation, GameStateSnapshot *snapshot);

/**
 * @brief Evaluates matches and triggers asynchronous block reward minting for local node submissions.
 *
 * @details
 * Confirms that `val->user_id` matches the local node operator. Evaluates matches via
 * @ref count_partial_matches. If matches $> 0$, captures a frozen audit snapshot and spawns
 * a detached POSIX thread executing @ref mint_thread_func to construct and propose an `OP_MINT_COIN` operation.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] user Pointer to local node operator's @ref User profile.
 * @param[in] val Pointer to submitted @ref Valuation row.
 * @param[in] target_index Index in the audit buffer where valuation was inserted.
 *
 * @thread_safety Reentrant; spawns independent detached worker thread.
 * @complexity Time: O(count_partial_matches), Space: O(sizeof(MintThreadArgs)) heap allocation.
 */
void auto_simulate(State *state, User *user, const Valuation *val, int target_index);

/**
 * @brief Serializes and transmits the active Game Audit matrix state to a connected peer.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the requesting peer.
 *
 * @thread_safety Acquires `state->game_state.mutex`.
 * @complexity Time: O(AUDIT_SIZE), Space: O(sizeof(Message)).
 */
void send_audit_to_client(State *state, const uint8_t *pubkey);

/* ============================================================================ */
/* SECTION 4: LEADER ELECTION & REWARD MINTING THREADS                          */
/* ============================================================================ */

/**
 * @brief Deterministically elects the authorized block proposer for a given epoch height.
 *
 * @details
 * Evaluates leader election:
 * - If an epoch threshold committee key is active: elect leader from the 10 committee members using
 *   $\text{index} = (H + \text{time\_slot}) \bmod 10$.
 * - Otherwise: sorts active connected peers lexicographically by Dilithium public key and evaluates
 *   $\text{index} = \text{SHA256}(\text{peers} \parallel H \parallel \text{time\_slot}) \bmod N_{\text{peers}}$.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] epoch Target block height $H$.
 * @param[out] proposer_pubkey_out 2,592-byte buffer receiving elected proposer's public key.
 * @return 0 on successful election; -1 if no eligible peers or committee members exist.
 *
 * @thread_safety Acquires `state->game_state.mutex`, `state->epoch_mutex`, and `state->p2p_network.mutex`.
 * @complexity Time: O(N_peers log N_peers), Space: O(N_peers * sizeof(Peer*)).
 */
int select_proposer(State *state, uint64_t epoch, uint8_t *proposer_pubkey_out);

/**
 * @brief Background thread constructing and proposing an OP_MINT_COIN block reward transaction.
 *
 * @param[in] arg Pointer to heap-allocated @ref MintThreadArgs context (callee assumes ownership and frees).
 * @return NULL upon thread termination.
 *
 * @thread_safety Thread-safe detached worker thread.
 * @complexity Time: O(block_proposal_time), Space: O(MAX_MESSAGE_SIZE).
 */
void *mint_thread_func(void *arg);

#ifdef __cplusplus
}
#endif

#endif // GAME_STATE_H
