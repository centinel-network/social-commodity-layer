/**
 * @file client/network/client_network.h
 * @brief Satocialist Protocol: Client-Side Network Synchronization & Dispatch Interface
 *
 * @details
 * Declares the client-level synchronization routines, initial block download (IBD) pipelines,
 * audit matrix synchronization handlers, mempool catch-up routines, and incoming P2P message
 * handlers for coin transfers and consensus votes.
 *
 * @section sync_invariants Synchronization Invariants
 * - Strict Sequential Catch-Up: Historical block synchronization requests missing blocks
 *   monotonically starting from `current_block_number + 1` via `MSG_GET_BLOCKS`.
 * - Genesis Initialization: Un-synchronized nodes initialize Block 0 natively before syncing to
 *   establish `sync_epoch = 1`, preventing integer underflow during state transitions.
 * - Dependency-Gated Execution: Synchronization proceeds through strict layered phases:
 *   1. Verifiable Historical Blocks (`sync_blockchain`)
 *   2. 10x10 Game Audit Matrix (`sync_audit`)
 *   3. Unconfirmed Memory Pool Operations (`sync_pending_operations`)
 * - Fork-Triggered Checkpoint Rollback: If a sync stream diverges from local tip history,
 *   the node executes an MVCC rollback to the closest checkpoint rather than wiping state.
 *
 * @section thread_safety Concurrency Model & Lock Invariants
 * - Asynchronous synchronization executes within dedicated worker threads (`blockchain_sync_worker`).
 * - Only one synchronization thread may execute concurrently, gated by `state->sync_thread_active`.
 * - Handlers synchronize with the ledger using `state->mutex`, `state->ledger_mutex`, and `state->bc.rwlock`.
 */

#ifndef CLIENT_NETWORK_H
#define CLIENT_NETWORK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "client_state.h"
#include "protocol.h"
#include "game_state.h"
#include "constants.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: ASYNCHRONOUS INITIAL BLOCK DOWNLOAD & RESYNCHRONIZATION           */
/* ============================================================================ */

/**
 * @brief Triggers an asynchronous background thread to synchronize ledger state with a peer.
 *
 * @details
 * Enforces a 10-second circuit breaker cooldown to prevent sync request storms. If permitted,
 * allocates a @ref SyncThreadArgs descriptor, sets `state->sync_thread_active = true`, and spawns
 * a background worker thread executing `blockchain_sync_worker` with an 8 MiB stack allocation.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of the remote sync peer.
 * @param[in] force Flag: `true` forces synchronization and checkpoint rollback even if cooldown is active.
 *
 * @pre `state` and `peer_pubkey` must be non-NULL.
 * @post Background sync thread spawned if not already active; sets `state->in_blockchain_sync = 1`.
 * @thread_safety Acquires `state->mutex` to update synchronization flags safely.
 * @complexity Time: O(1), Space: O(1) thread control structures.
 */
void trigger_async_sync(State *state, const uint8_t *peer_pubkey, bool force);

/**
 * @brief Executes synchronous, sequential historical block synchronization with a selected peer.
 *
 * @details
 * Queries peer block height and Centinel private UTXO states, transmits `MSG_GET_BLOCKS` specifying
 * `state->current_block_number + 1` as the start height, synchronously waits on
 * `state->blockchain_sync_cond` for missing blocks, and re-injects local private UTXOs into the MMR
 * via `OP_CLAIM_VALIDATION` upon completion.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of the sync peer.
 * @return 0 on successful block synchronization; -1 on timeout or transmission failure.
 *
 * @pre Caller must be executing within a dedicated worker thread (blocks up to 60 seconds).
 * @thread_safety Synchronizes via `state->mutex` and condition variable `state->blockchain_sync_cond`.
 * @complexity Time: O(missing_blocks * apply_block_time), Space: O(MAX_MESSAGE_SIZE).
 */
int sync_blockchain(State *state, uint8_t *peer_pubkey);

/**
 * @brief Synchronizes the 10x10 Game Audit circular valuation matrix with a remote peer.
 *
 * @details
 * Transmits `MSG_GET_AUDIT` and waits on `state->audit_cond` with a 5-second timeout, retrying
 * up to 3 times on timeout. Installs remote valuation rows into `state->game_state.game_audit`.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of the target peer.
 * @return 0 on successful audit synchronization; -1 on failure after 3 retries.
 *
 * @thread_safety Synchronizes via `state->mutex`, `state->game_state.mutex`, and `state->audit_cond`.
 * @complexity Time: O(retries * timeout), Space: O(sizeof(Message)).
 */
int sync_audit(State *state, uint8_t *peer_pubkey);

/**
 * @brief Synchronizes unconfirmed mempool transactions from a remote peer.
 *
 * @details
 * Transmits `MSG_GET_PENDING_OPERATIONS` and waits on `state->pending_ops_cond` with a 30-second
 * timeout. Ingests deserialized operations into the local mempool via @ref add_pending_operation.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] peer_pubkey 2,592-byte Dilithium5 public key of target peer.
 * @return 0 on successful mempool synchronization; -1 on timeout or failure.
 *
 * @thread_safety Synchronizes via `state->mutex` and `state->pending_ops_cond`.
 * @complexity Time: O(timeout + mempool_size * add_pending_operation), Space: O(MAX_MESSAGE_SIZE).
 */
int sync_pending_operations(State *state, uint8_t *peer_pubkey);

/* ============================================================================ */
/* SECTION 2: CONSENSUS & TRANSACTION INGRESS HANDLERS                          */
/* ============================================================================ */

/**
 * @brief Decodes, validates, and registers an incoming consensus vote message (`MSG_VOTE`).
 *
 * @details
 * Deserializes @ref Vote from `msg->payload`, validates the Dilithium5 digital signature against
 * `vote.block_hash`, verifies the voter's public key, checks for duplicate votes in the vote queue,
 * increments `queue->yes_votes`, signals `queue->cond`, and purges competing block forks for the
 * same height upon achieving the supermajority threshold.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] msg Inbound network message container (`msg->type == MSG_VOTE`).
 * @param[in] sender_pubkey Authenticated 2,592-byte Dilithium5 public key of sender.
 *
 * @pre `state`, `msg`, and `sender_pubkey` must be non-NULL.
 * @thread_safety Acquires `state->mutex` and `queue->vote_lock`.
 * @complexity Time: O(Dilithium5_verify + existing_votes), Space: O(1).
 */
void handle_vote(State *state, Message *msg, uint8_t *sender_pubkey);

/**
 * @brief Ingress handler processing unconfirmed on-chain pointer transfer requests (`MSG_PTR_TRANSFER`).
 *
 * @details
 * Deserializes @ref TransferData from the message payload:
 * 1. Verifies MMR inclusion proofs for all input pointers against local state root.
 * 2. Verifies that input pointers exist, are unspent, and share a common owner address.
 * 3. Verifies Merkle root of input pointers and caller's Dilithium5 signature over the root.
 * 4. Verifies main transaction signature over consensus-critical fields.
 * 5. Verifies Module-SIS ZK-PRF proof of nullifier evaluation.
 * 6. Stages transaction into local mempool via @ref add_pending_operation.
 *
 * @param[in,out] net Pointer to P2P network subsystem container.
 * @param[in,out] state Pointer to global node state container.
 * @param[in] msg Inbound message container.
 * @param[in] sender_pubkey Authenticated 2,592-byte Dilithium5 public key of sender.
 *
 * @pre `net`, `state`, `msg`, and `sender_pubkey` must be non-NULL.
 * @thread_safety Acquires `state->mutex` and `state->bc.rwlock`.
 * @complexity Time: O(num_inputs * MMR_verify + ZK_verify + Dilithium5_verify), Space: O(sizeof(Operation)).
 */
void handle_coin_transfer(P2PNetwork *net, State *state, Message *msg, uint8_t *sender_pubkey);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_NETWORK_H
