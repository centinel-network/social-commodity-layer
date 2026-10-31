/**
 * @file common/consensus/consensus.h
 * @brief Satocialist Protocol: Consensus Engine, Block Lifecycle, and DKG Committee Interface
 *
 * @details
 * Declares the public interfaces governing distributed consensus, deterministic leader election,
 * block proposal assembly, two-phase Byzantine voting, Joint-RSS Distributed Key Generation (DKG)
 * epoch ceremonies, fork resolution, and autonomous validator operation across the Satocialist
 * Cryptographic Ledger (SCL).
 *
 * @section consensus_invariants Core Consensus Invariants
 * - Strict Supermajority Consensus: A candidate block proposal achieves approved status if and
 *   only if the number of affirmative validator votes satisfies:
 *   $$\text{votes} \ge \lceil N_{\text{peers}} \times \text{CONSENSUS\_THRESHOLD} \rceil \quad (\text{threshold} = 0.67)$$
 * - Deterministic Proposer Election: For any block height $H$, the authorized block proposer
 *   is deterministically elected by evaluating:
 *   $$\text{index} = (\text{SHA256}(H \parallel \text{time\_slot} \parallel \text{peers}) \bmod N_{\text{eligible}})$$
 *   preventing ambiguous or collusive multi-leader proposals.
 * - Anti-Equivocation Invariant: Validators record voted heights in `state->voted_heights`; casting
 *   more than one vote for distinct blocks at identical height $H$ within `VOTE_TIMEOUT` (30s) is prohibited.
 * - Supply Hard-Cap & Conservation: Block reward issuance via `OP_MINT_COIN` enforces the hard cap
 *   of 2,560,000,000,000,000 subunits (16,000,000 SCL). Post-cap issuance draws exclusively from
 *   recycled transaction fee pools.
 *
 * @section lock_hierarchy Concurrency Model & Lock Ordering
 * Mutex and read-write lock acquisitions must strictly adhere to the descending hierarchy:
 * 1. `state->mutex` (Global node coordinator lock)
 * 2. `state->ledger_mutex` (Blockchain tip & reorganization lock)
 * 3. `state->bc.rwlock` (Ledger MMR & UTXO state read-write lock)
 * 4. `state->wallet_mutex` (Validator signing key lock)
 * 5. `state->epoch_mutex` (DKG committee session barrier lock)
 * 6. `state->game_state.mutex` (Economic state & valuation matrix lock)
 * 7. `queue->vote_lock` (Per-block vote accumulation lock)
 */

#ifndef CONSENSUS_H
#define CONSENSUS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "types.h"
#include "constants.h"
#include "crypto.h"
#include "blockchain.h"
#include "user.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: COMMITTEE ELECTION & PUBLIC KEY COMPARATORS                       */
/* ============================================================================ */

/**
 * @brief Lexicographically compares two raw Dilithium5 public keys.
 *
 * @param[in] a Pointer to first 2,592-byte public key buffer.
 * @param[in] b Pointer to second 2,592-byte public key buffer.
 * @return Negative integer if a < b, zero if a == b, positive integer if a > b.
 *
 * @pre `a` and `b` must point to at least `PUBKEY_LEN` (2,592) readable bytes.
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(PUBKEY_LEN), Space: O(1).
 */
int compare_pubkeys_raw(const void *a, const void *b);

/**
 * @brief Deterministically derives the 10-member validator committee for epoch block height H.
 *
 * @details
 * Reconstructs active stake weights up to height H by scanning confirmed transactions from database
 * storage. Eligible validators are sorted descending by staked subunits; ties are broken by lexicographical
 * User ID comparison. If fewer than 10 staked identities exist, past block proposers and active network
 * peers are deterministically incorporated to fulfill the 10-member Joint-RSS threshold baseline.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[out] committee Array of 10 buffers receiving 2,592-byte Dilithium5 committee public keys.
 * @param[out] count Pointer receiving the count of populated committee members (saturates at 10).
 * @param[in] H Reference block height defining the epoch evaluation boundary.
 *
 * @pre `state`, `committee`, and `count` must be non-NULL; `H >= 0`.
 * @post `committee` populated with `*count` sorted, unique public keys.
 * @thread_safety Acquires `state->bc.rwlock` in read mode, `state->p2p_network.mutex`, and `state->mutex` (when caching).
 * @complexity Time: O(H * operations_per_block + N log N), Space: O(MAX_CLIENTS * sizeof(StakerRecord)).
 */
void get_epoch_committee(State *state, uint8_t committee[10][PUBKEY_LEN], size_t *count, uint64_t H);

/**
 * @brief Updates local state and gossips a newly finalized DKG epoch master public key.
 *
 * @details
 * Commits the 2,592-byte threshold master public key to `state->game_state.epoch_threshold_pubkey`,
 * updates the cached committee table in `state->current_committee`, refreshes the active game state
 * snapshot, and broadcasts an authenticated `MSG_EPOCH_DKG_SHARE` message to all network peers.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] pubkey Pointer to the 2,592-byte aggregated Dilithium5 threshold public key.
 * @param[in] committee Array of member public verification keys comprising the signing committee.
 * @param[in] count Number of committee members (typically 10).
 *
 * @pre `state`, `pubkey`, and `committee` must be non-NULL; `count > 0 && count <= 10`.
 * @post `state->game_state.epoch_threshold_pubkey` updated; network gossip message queued.
 * @thread_safety Acquires `state->game_state.mutex` and `state->epoch_mutex`.
 * @complexity Time: O(count * PUBKEY_LEN), Space: O(sizeof(Message)) heap allocation.
 */
void rotate_epoch_key(State *state, const uint8_t *pubkey, const uint8_t committee[10][PUBKEY_LEN], size_t count);

/* ============================================================================ */
/* SECTION 2: DISTRIBUTED KEY GENERATION (DKG) WORKER THREADS                   */
/* ============================================================================ */

/**
 * @brief Background worker thread executing the multi-round Joint-RSS DKG ceremony.
 *
 * @details
 * Orchestrates the 4-round non-interactive Joint-RSS key generation protocol:
 * 1. Round 1 (Commit): Samples random seed $r_i$, computes $c_i = \text{SHA256}(r_i \parallel \text{pk}_i)$, broadcasts `MSG_DKG_COMMIT`.
 * 2. Round 2 (Reveal): Broadcasts $r_i$ via `MSG_DKG_REVEAL`, verifies peer commitments, computes global matrix seed $\rho$.
 * 3. Round 3 (Share Deal): Generates local subset polynomials, encrypts shares via ML-KEM/Kyber-768 KEM to peers (`MSG_DKG_SHARE_DEAL`).
 * 4. Round 4 (Assembly): Reconstructs secret subsets $s_1, s_2$, verifies public contributions $t_i$, derives epoch threshold key.
 *
 * @param[in] arg Heap-allocated pointer to @ref DKGWorkerArgs structure (callee assumes ownership and frees).
 * @return NULL on thread termination.
 *
 * @pre `arg` must contain valid `state`, `session_id`, and `block_height`.
 * @post DKG session concluded; keys installed on success or session aborted on timeout/failure.
 * @sideeffect Opens connections, transmits KEM ciphertexts, mutates `state->epoch_processes`.
 * @thread_safety Thread-safe; coordinates phase barriers via `session->phase_cond` and `state->epoch_mutex`.
 * @complexity Time: O(rounds * timeout_limit), Space: O(NUM_SUBSETS * sizeof(polyvec_t)).
 */
void *dkg_worker_thread(void *arg);

/**
 * @brief Spawns an asynchronous detached worker thread to participate in a DKG epoch ceremony.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] session_id 32-byte unique DKG session identifier (SHA-256 of epoch tag).
 * @param[in] block_height Block height initiating the DKG ceremony.
 *
 * @pre `state` and `session_id` must be non-NULL; `block_height >= 0`.
 * @post Spawns detached POSIX thread executing @ref dkg_worker_thread with 8 MiB stack ceiling.
 * @sideeffect Increments `state->active_background_threads`.
 * @complexity Time: O(1), Space: O(1) thread control blocks.
 */
void spawn_dkg_worker_thread(State *state, const uint8_t *session_id, uint64_t block_height);

/* ============================================================================ */
/* SECTION 3: BLOCK CONSTRUCTION & PROPOSAL DELEGATION                          */
/* ============================================================================ */

/**
 * @brief Instantiates, signs, and hashes a candidate Block structure.
 *
 * @details
 * Allocates a @ref Block structure, copies operation arrays, attaches batch ZK-PRF nullifiers and
 * aggregated Stern proofs, computes the pre-signature SHA-256 block hash via @ref compute_block_hash,
 * and signs the digest with the proposer's ML-DSA-87 (Dilithium5) private key.
 *
 * @param[in] block_number Sequential block height being proposed.
 * @param[in] prev_block_hash 32-byte SHA-256 digest of previous tip block.
 * @param[in] operations Array of @ref Operation structures packed into candidate block.
 * @param[in] operation_count Number of operations in array (bounded by @ref MAX_OPERATIONS_PER_BLOCK).
 * @param[in] proposer_pubkey 2,592-byte Dilithium5 public verification key of proposer.
 * @param[in] proposer_privkey 4,864-byte Dilithium5 private signing key of proposer.
 * @param[in] entropy_seed Deterministic 32-bit pseudorandom seed.
 * @param[in] batch_tx_count Count of transfer transactions included in ZK batch proof.
 * @param[in] batch_prf_outputs Concatenated 32-byte nullifiers for batched transfers.
 * @param[in] batch_zk_proof Serialized aggregated zero-knowledge Stern proof buffer.
 * @param[in] batch_zk_proof_len Total byte length of `batch_zk_proof`.
 * @return Pointer to heap-allocated @ref Block structure on success; NULL on parameter or signing failure.
 *
 * @pre `prev_block_hash`, `operations`, `proposer_pubkey`, and `proposer_privkey` must be non-NULL; `operation_count > 0`.
 * @post Returned Block is fully initialized, signed, and ready for network gossip.
 * @sideeffect Allocates heap memory for Block and enclosed operation buffers (caller frees via @ref free_block).
 * @complexity Time: O(operation_count + Dilithium5_sign), Space: O(block_size) heap allocation.
 */
Block *create_block(uint64_t block_number, const uint8_t *prev_block_hash, Operation *operations,
                    size_t operation_count, const uint8_t *proposer_pubkey, const uint8_t *proposer_privkey, int entropy_seed,
                    size_t batch_tx_count, uint8_t *batch_prf_outputs, uint8_t *batch_zk_proof, size_t batch_zk_proof_len);

/**
 * @brief Constructs a candidate block proposal, coordinates epoch beacon signing, and broadcasts gossip.
 *
 * @details
 * Operational steps:
 * 1. Validates local eligibility; aborts if already proposing or synchronization is active.
 * 2. Collects unconfirmed operations from mempool, enforcing non-overlapping input pointer constraints.
 * 3. Incorporates `OP_MINT_COIN` coinbase reward; packs batch ZK-PRF nullifiers and proofs.
 * 4. Gathers threshold randomness beacon signature from epoch DKG committee if height > @ref BLOCKS_PER_DAY.
 * 5. Instantiates @ref Block, signs self-vote, initializes @ref BlockVoteQueue, and broadcasts `MSG_GOSSIP_BLOCK`.
 * 6. Spawns detached vote collection thread (@ref vote_collection_thread) to await consensus supermajority.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] provided_mint Optional pre-constructed coinbase mint operation (NULL generates from mempool).
 *
 * @pre `state` must be non-NULL; node must be elected leader for current height.
 * @post Candidate block broadcasted to peers; local vote queue registered.
 * @thread_safety Acquires `state->mutex`, `state->bc.rwlock` (read mode), `state->game_state.mutex`, `state->epoch_mutex`, and `state->block_proposers_lock`.
 * @complexity Time: O(N_ops * ZK_verify + Dilithium5_sign + network_broadcast), Space: O(MAX_MESSAGE_SIZE).
 */
void propose_block(State *state, const Operation *provided_mint);

/**
 * @brief Spawns an asynchronous worker thread to propose a block, avoiding blocking the caller.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] op Optional operation pointer to include in the proposed block.
 *
 * @pre `state` must be non-NULL.
 * @post Asynchronous thread dispatched; increments `state->active_background_threads`.
 * @complexity Time: O(1), Space: O(1) thread control structures.
 */
void spawn_propose_block_thread(State *state, const Operation *op);

/**
 * @brief Deallocates all dynamic heap memory associated with a Block structure.
 *
 * @param[in,out] block Pointer to @ref Block structure to free (safe if NULL).
 *
 * @post `block->operations`, `block->batch_prf_outputs`, `block->batch_zk_proof`, and `block` are freed.
 * @complexity Time: O(1), Space: O(1).
 */
void free_block(Block *block);

/* ============================================================================ */
/* SECTION 4: VOTING, CONSENSUS VERIFICATION & REORGANIZATION                   */
/* ============================================================================ */

/**
 * @brief Cryptographically validates a validator Vote structure.
 *
 * @param[in] vote Pointer to candidate @ref Vote structure.
 * @param[in] block_hash Expected 32-byte block hash digest.
 * @return 1 if vote is authentic, well-formed, and matches `block_hash`; 0 on defect or signature failure.
 *
 * @pre `vote` and `block_hash` must be non-NULL; `vote->vote in {0, 1}`.
 * @complexity Time: O(Dilithium5_verify), Space: O(1).
 */
int verify_vote(const Vote *vote, const uint8_t *block_hash);

/**
 * @brief Evaluates whether a proposed block has accumulated supermajority approval votes.
 *
 * @details
 * Calculates required vote threshold:
 * $$\text{required} = \lceil N_{\text{deduplicated\_peers}} \times \text{CONSENSUS\_THRESHOLD} \rceil$$
 * If `queue->yes_votes >= required`, commits the block via @ref apply_block, broadcasts
 * `MSG_BLOCK_APPROVED` across P2P gossip, and triggers subsequent block proposal rounds.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] block Pointer to candidate @ref Block under vote evaluation.
 * @param[in,out] queue Pointer to @ref BlockVoteQueue accumulating validator votes for this block.
 * @return `true` if consensus threshold was reached and block committed; `false` otherwise.
 *
 * @pre `state`, `block`, and `queue` must be non-NULL.
 * @post If consensus reached: block applied to ledger, confirmed in database, and broadcasted.
 * @thread_safety Acquires `queue->vote_lock`, `state->p2p_network.mutex`, `state->mutex`, and `state->bc.rwlock`.
 * @complexity Time: O(N_peers + apply_block_time), Space: O(sizeof(Message)).
 */
bool check_consensus(State *state, Block *block, BlockVoteQueue *queue);

/**
 * @brief Thread entrypoint accumulating incoming validator votes until consensus or timeout.
 *
 * @param[in] arg Pointer to heap-allocated @ref VoteThreadArgs structure (freed by callee).
 * @return NULL upon thread termination.
 *
 * @sideeffect Decrements `state->active_background_threads` upon exit.
 * @thread_safety Waits on `queue->cond` with `VOTE_TIMEOUT` (30s); cleans up queue ref counts.
 * @complexity Time: O(VOTE_TIMEOUT), Space: O(1) auxiliary per thread.
 */
void *vote_collection_thread(void *arg);

/**
 * @brief Ingests and registers an incoming validator vote into the matching block vote queue.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] msg Network message containing serialized @ref Vote payload (`MSG_VOTE`).
 * @param[in] sender_pubkey Authenticated 2,592-byte Dilithium5 public key of the sending peer.
 *
 * @pre `state`, `msg`, and `sender_pubkey` must be non-NULL; `msg->type == MSG_VOTE`.
 * @post Valid vote appended to queue; triggers consensus check if affirmative.
 * @thread_safety Acquires `state->mutex` and `queue->vote_lock`.
 * @complexity Time: O(existing_votes + Dilithium5_verify), Space: O(1).
 */
void handle_vote(State *state, Message *msg, uint8_t *sender_pubkey);

/**
 * @brief Deallocates a BlockVoteQueue structure when its reference count drops to zero.
 *
 * @param[in,out] data Untyped pointer to @ref BlockVoteQueue structure.
 *
 * @post Frees `queue->votes`, destroys `queue->vote_lock` and `queue->cond`, and frees `queue`.
 * @complexity Time: O(1), Space: O(1).
 */
void free_block_vote_queue(void *data);

/* ============================================================================ */
/* SECTION 5: BLOCK APPLICATION & TRANSACTION VALIDATION                        */
/* ============================================================================ */

/**
 * @brief Performs strict consensus validation on an individual transactional operation.
 *
 * @details
 * Validates operation constraints without mutating state:
 * - `OP_CLAIM_VALIDATION`: Verifies Dilithium signature over BDLOP commitment digest; checks duplicate status.
 * - `OP_REDEEM_CENTINEL`: Verifies nullifier is unspent in RAM/Bloom/Disk; validates 219-round ZK-Stern proof.
 * - `OP_SUBMIT_VALUATION`: Verifies user signature over core 10-integer valuation vector.
 * - `OP_MINT_COIN`: Validates coin ID derivation, total subunit bounds, and audit snapshot anchor hash.
 * - `OP_TRANSFER_POINTER`: Verifies input pointer validity, unspent status, Merkle root signature, and fee totals.
 * - `OP_STAKE` / `OP_UNSTAKE`: Verifies threshold signature, input pointer validity, and halved fee deduction.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] op Pointer to candidate @ref Operation structure to validate.
 * @return 1 if operation is valid and passes all consensus checks; 0 on failure.
 *
 * @pre Caller must hold `state->bc.rwlock` (read or write mode).
 * @complexity Time: Dependent on operation type (O(1) to O(ZK_verify)), Space: O(1).
 */
int validate_operation(State *state, const Operation *op);

/**
 * @brief Applies all state transitions within a validated block to the ledger atomically.
 *
 * @details
 * State Transition Pipeline:
 * 1. Verifies block height continuity (`block->block_number == state->current_block_number + 1`).
 * 2. Verifies ancestor hash linkage (`block->prev_block_hash == state->current_block_hash`).
 * 3. Verifies epoch threshold randomness beacon signature if height > @ref BLOCKS_PER_DAY.
 * 4. Dual-Pass Execution:
 *    - Pass 1 (Read-Only): Validates every operation against current ledger state; aborts on defect.
 *    - Pass 2 (Mutation): Begins database transaction (@ref scl_db_begin_block_txn), updates coin/pointer
 *      tables, adds MMR leaves, updates game state valuation matrix, and commits to persistent storage.
 * 5. Evicts confirmed transactions from mempool via @ref clean_pending_operations.
 * 6. Generates state checkpoints every 440 blocks (@ref BLOCKS_PER_DAY) and triggers MMR pruning.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] block Pointer to candidate @ref Block to commit.
 * @return 0 on successful application; -1 on validation failure or state inconsistency (transaction aborted).
 *
 * @pre Caller must hold `state->bc.rwlock` in write mode and either `state->ledger_mutex` or `state->mutex`.
 * @post Ledger tip updated (`state->current_block_number`, `state->current_block_hash`); state persisted to disk.
 * @sideeffect Mutates UTXO tables, MMR accumulator, database records, and Game Audit matrix.
 * @complexity Time: O(operation_count * op_apply_time + disk_sync), Space: O(block_size).
 */
int apply_block(State *state, Block *block);

/**
 * @brief Ingress handler processing block proposals broadcasted over the gossip network.
 *
 * @details
 * Validates deserialized block header, verifies proposer signature and heavy zero-knowledge proofs
 * before acquiring locks, checks height continuity against local tip, validates operation rules,
 * signs an affirmative or negative @ref Vote, and transmits vote back to the proposer.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] msg Network message containing serialized @ref Block payload (`MSG_GOSSIP_BLOCK`).
 * @param[in] sender_addr Network source socket address of proposer.
 * @param[in] sender_pubkey Authenticated 2,592-byte Dilithium5 public key of proposer.
 * @return 0 on success; -1 on structural defect, signature failure, or memory error.
 *
 * @thread_safety Acquires `state->ledger_mutex`, `state->bc.rwlock` (write mode), and `state->mutex` sequentially.
 * @complexity Time: O(block_verification_time + Dilithium5_sign), Space: O(MAX_MESSAGE_SIZE).
 */
int handle_block_proposal(State *state, const Message *msg, struct sockaddr_storage *sender_addr, uint8_t *sender_pubkey);

/**
 * @brief Ingress handler processing finalized block approval broadcasts (`MSG_BLOCK_APPROVED`).
 *
 * @details
 * Verifies block hash and proposer signature. If block extends current tip sequentially, commits
 * via @ref apply_block. If an ancestor mismatch is detected, isolates block into `state->orphan_pool`
 * and initiates fork resolution or asynchronous block synchronization.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in,out] block Pointer to deserialized @ref Block structure (callee assumes ownership and frees).
 * @param[in] sender_pubkey Authenticated 2,592-byte public key of broadcasting peer.
 *
 * @post Block committed to ledger or enqueued to orphan pool; `block` memory is freed.
 * @thread_safety Acquires `state->ledger_mutex` and `state->bc.rwlock` in write mode (and optionally `state->mutex` on resync).
 * @complexity Time: O(apply_block_time), Space: O(1).
 */
void handle_msg_block_approved(State *state, Block *block, uint8_t *sender_pubkey);

/* ============================================================================ */
/* SECTION 6: FORK RESOLUTION & AUTONOMOUS AUTO-PILOT                           */
/* ============================================================================ */

/**
 * @brief Evaluates whether isolated blocks in the orphan pool can be attached to the ledger tip.
 *
 * @details
 * Iterates through `state->orphan_pool` under write lock. Promotes orphan blocks whose `prev_block_hash`
 * matches `state->current_block_hash`, committing them sequentially via @ref apply_block until no further
 * chained ancestors remain.
 *
 * @param[in,out] state Pointer to global node state container.
 *
 * @thread_safety Acquires `state->ledger_mutex` and `state->bc.rwlock` in write mode.
 * @complexity Time: O(orphan_pool_size * apply_block_time), Space: O(1).
 */
void trigger_async_fork_processing(State *state);

/**
 * @brief Checks mempool for pending coinbase mints and initiates block proposal if node is elected leader.
 *
 * @param[in,out] state Pointer to global node state container.
 *
 * @pre `state` must be non-NULL.
 * @thread_safety Acquires `state->mutex`, `state->game_state.mutex`, `state->p2p_network.mutex`, and `state->epoch_mutex` sequentially.
 * @complexity Time: O(mempool_size + proposer_selection_time), Space: O(1).
 */
void trigger_proposer_if_eligible(State *state);

/**
 * @brief Ingests an authenticated valuation proposal into the circular Game Audit matrix.
 *
 * @details
 * Verifies Dilithium signature over valuation numbers, derives epoch randomness beacon from the current
 * block threshold signature, inserts row into `state->game_state.game_audit`, and triggers local
 * match simulation (@ref auto_simulate) if submitted by the local node operator.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] vd Pointer to validated @ref ValuationData structure.
 * @param[in] hash 32-byte SHA-256 digest of core valuation data.
 *
 * @thread_safety Acquires `state->mutex` and `state->game_state.mutex`.
 * @complexity Time: O(AUDIT_SIZE + auto_simulate_time), Space: O(1).
 */
void process_valuation_proposal(State *state, const ValuationData *vd, uint8_t *hash);

/**
 * @brief Executes a single iteration of the autonomous Auto-Pilot portfolio rebalancing and valuation loop.
 *
 * @details
 * 1. Portfolio Rebalancing: Audits liquid vs. staked SCL balances; executes `create_and_broadcast_stake`
 *    or `create_and_broadcast_unstake` if deviation from `autopilot_stake_ratio` exceeds tolerance.
 * 2. Valuation Submissions: Enforces hourly rate ceiling `autopilot_valuations_per_hour`; consumes
 *    1 UTXO validation credit and submits a 10-integer valuation row to the Game Audit matrix.
 *
 * @param[in,out] state Pointer to global node state container.
 *
 * @pre `state` non-NULL; `state->autopilot_running` evaluates true.
 * @thread_safety Reentrant; acquires subsystem locks internally.
 * @complexity Time: O(rebalance_time + valuation_time), Space: O(1).
 */
void scl_autopilot_step(State *state);

/**
 * @brief Launches the autonomous Auto-Pilot background daemon thread.
 *
 * @param[in,out] state Pointer to global node state container.
 *
 * @post Sets `state->autopilot_running = true`; spawns detached thread executing `autopilot_daemon_thread`.
 * @complexity Time: O(1), Space: O(1) thread control blocks.
 */
void start_autopilot_thread(State *state);

/**
 * @brief Signals and terminates the autonomous Auto-Pilot background daemon thread.
 *
 * @param[in,out] state Pointer to global node state container.
 *
 * @post Sets `state->autopilot_running = false`, triggering graceful daemon exit on next cycle.
 * @complexity Time: O(1), Space: O(1).
 */
void stop_autopilot_thread(State *state);

#ifdef __cplusplus
}
#endif

#endif // CONSENSUS_H
