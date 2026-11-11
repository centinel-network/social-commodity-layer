/**
 * @file common/network/rpc.h
 * @brief Satocialist Protocol: L5 Native RPC Execution Engine Interface
 *
 * @details
 * Declares worker thread entrypoints, dispatch routines, and request routing interfaces
 * for the native binary RPC protocol (wire format: @ref SclRpcHeader).
 * Supports zero-copy wire casting, LZ4 decompression bomb defenses, ML-DSA-87 (Dilithium5)
 * signature authentication, 64-second anti-replay tracking, Centinel/on-chain payment receipt
 * verification, and client telemetry.
 *
 * @section rpc_methods Supported RPC Methods (0x0000..0x000B)
 * - `0x0000`: `GetRegistry` &mdash; Query protocol version, active method catalogue, and computational costs.
 * - `0x0001`: `GetBalance` &mdash; Query liquid/staked balances, fees paid, private UTXOs, and pointers.
 * - `0x0002`: `GetBlock` &mdash; Stream raw block data matching paginated cursor height ranges.
 * - `0x0003`: `SubmitTx` &mdash; Inject signed on-chain transactions into the local mempool.
 * - `0x0004`: `GetAudit` &mdash; Query current 10x10 Game Audit circular valuation matrix rows.
 * - `0x0005`: `GetValuations` &mdash; Query total rewarded supply, remaining cap, and consensus stage.
 * - `0x0006`: `GetRecentTxs` &mdash; Paginated scan over unconfirmed and recently mined transaction IDs.
 * - `0x0007`: `GetTransaction` &mdash; Locate confirmed transaction payload from mempool or database history.
 * - `0x0008`: `GetChainInfo` &mdash; Query tip height, DKG status, staker committees, and local identity keys.
 * - `0x0009`: `SyncWalletKeys` &mdash; Synchronize or hot-swap node daemon keys from external browser clients.
 * - `0x000A`: `QuantumTvdAudit` &mdash; Generate cryptographic Total Variation Distance drift certificates (monetized query).
 * - `0x000B`: `Autopilot` &mdash; Query or reconfigure autonomous background portfolio rebalancing and staking.
 *
 * @section concurrency_model Threading & Concurrency Guarantees
 * - Multiple worker threads (`state->rpc_engine.worker_threads`) consume tasks from a work-stealing queue.
 * - Per-connection concurrency is capped at @ref MAX_CONCURRENT_RPCS_PER_CONN (3 streams) via atomic counters.
 * - Leaky token bucket rate limiting prevents computational exhaustion from expensive queries.
 */

#ifndef SCL_RPC_H
#define SCL_RPC_H

#include "types.h"
#include "protocol.h"
#include "network.h"
#include "crypto.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* 1. WORKER DAEMON & DISPATCH INTERFACES                                       */
/* ============================================================================ */

/**
 * @brief Continuous background worker loop dequeuing and processing inbound L5 RPC tasks.
 *
 * @details
 * Worker execution flow:
 * 1. Pops an `RpcTask` node from `state->rpc_engine.incoming_rpc_queue`.
 * 2. Measures execution duration using high-resolution microsecond timers (`get_time_us`).
 * 3. Dispatches task to @ref handle_rpc_request.
 * 4. Records telemetry latency metrics (`state->rpc_engine.latency_microseconds_sum`).
 * 5. Decrements active stream and reference counters on `task->conn` before freeing memory.
 *
 * @param[in] arg Heap-allocated pointer to `struct WorkerArgs` containing node state and worker ID.
 * @return NULL upon thread termination.
 *
 * @pre `arg` must point to allocated `struct WorkerArgs`.
 * @post Worker frees `arg` internally; executes until `global_shutdown` is signaled.
 * @thread_safety Reentrant worker function. Multiple instances run in parallel.
 * @complexity Time: O(infinite loop over tasks), Space: O(1) auxiliary per thread.
 */
void *rpc_worker_loop(void *arg);

/**
 * @brief Decodes, authenticates, and routes an individual L5 RPC command frame.
 *
 * @details
 * Validates the 32-byte header, checks the 64-second anti-replay sliding window,
 * verifies client token budget, enforces LZ4 decompression size boundaries (preventing zip bombs),
 * authenticates Dilithium5 signatures on signed methods, extracts and validates micropayment receipts
 * (OP_TRANSFER_POINTER or OP_REDEEM_CENTINEL) when present, dispatches to specific method handlers
 * (0x0000..0x000B), and encodes the framed binary response back onto `task->conn->tx_stream_queue`.
 *
 * @param[in,out] state Global node state container.
 * @param[in,out] task Dispatch context wrapping the inbound Message, connection handle, and caller pubkey.
 *
 * @pre `state` and `task` must be non-NULL; `task->msg->length >= sizeof(SclRpcHeader)`.
 * @post Response frame enqueued to connection stream queue; telemetry error/success counters updated.
 * @note Thread-safe. Acquires read/write locks on specific ledger components as needed per method.
 * @complexity Time: O(method_execution_time + serialization), Space: O(response_payload_size).
 */
void handle_rpc_request(State *state, RpcTask *task);

/* ============================================================================
 * 2. SCL402 SERVER-SIDE CHALLENGE REGISTRY
 * ============================================================================ */

/**
 * @brief Records a freshly issued SCL402 payment challenge in the server-side registry.
 *
 * @details Called at every 402 issuance (rpc.c and websocket_bridge.c). The
 *          registry maps the 32-byte challenge_hash to the issuance-time quote
 *          (amount, fee recipient, expiry), closing the gap where the receipt's
 *          price_rate_lock_id echo was purely informational.
 *
 * @param[in,out] state Global node state container (owns the registry in @ref SclRpcEngine).
 * @param[in] challenge_hash 32-byte salted SHA-256 challenge key (no endianness).
 * @param[in] amount_subunits Required payment quoted at issuance (host byte order).
 * @param[in] recipient_address 32-byte fee recipient User ID locked at issuance.
 * @param[in] valid_until_ms Expiry timestamp in milliseconds on the issuance clock.
 * @return true on registration; false on NULL arguments or a full registry
 *         (the challenge is still emitted; worst case its receipts re-quote).
 * @thread_safety Acquires the registry mutex in write mode internally.
 */
bool scl402_challenge_register(State *state, const uint8_t challenge_hash[COIN_ID_LEN],
                               uint64_t amount_subunits, const uint8_t recipient_address[USER_ID_LEN],
                               uint64_t valid_until_ms);

/**
 * @brief Resolves a live (unexpired) SCL402 challenge by its 32-byte key.
 *
 * @details The TTL is enforced here: an entry past its valid_until_ms is
 *          reclaimed and reported as a miss, so stale receipts re-trigger the
 *          402 challenge flow instead of settling forever. The entry is copied
 *          out under the registry mutex so the caller works on a stable snapshot.
 *
 * @param[in,out] state Global node state container (owns the registry in @ref SclRpcEngine).
 * @param[in] challenge_hash 32-byte challenge key echoed by the receipt.
 * @param[out] out_entry Destination receiving the live challenge snapshot.
 * @return true if a live challenge matched; false on miss, expiry, or NULL arguments.
 * @thread_safety Acquires the registry mutex in write mode internally.
 */
bool scl402_challenge_resolve(State *state, const uint8_t challenge_hash[COIN_ID_LEN],
                              Scl402ChallengeEntry *out_entry);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SCL_RPC_H
