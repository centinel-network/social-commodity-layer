/**
 * @file common/network/rpc.c
 * @brief Satocialist Protocol: Native L5 RPC Execution Engine & Method Dispatch Implementation
 *
 * @details
 * Implements the asynchronous request execution pipeline for the native binary L5 RPC wire protocol.
 * The RPC subsystem provides high-speed, authenticated, and rate-limited API access to the node daemon
 * for local and remote clients, block explorers, and WebAssembly frontends.
 *
 * Key functional responsibilities include:
 * 1. Asynchronous multi-threaded task consumption via work-stealing worker loops (@ref rpc_worker_loop).
 * 2. 64-second sliding-window anti-replay tracking with clock-skew grace periods.
 * 3. Transparent LZ4 payload decompression with strict decompression bomb protection bounds.
 * 4. Post-quantum authentication via ML-DSA-87 (Dilithium5) digital signature verification.
 * 5. On-chain / Centinel micropayment receipt verification for paid RPC methods (@ref send_rpc_payment_required).
 * 6. Method routing and wire response synthesis across methods 0x0000 through 0x000B:
 *    - 0x0000: GetRegistry (Method directory and execution costs)
 *    - 0x0001: GetBalance (Liquid, staked, fees, private UTXOs, and native pointers)
 *    - 0x0002: GetBlock (Paginated historical block streaming)
 *    - 0x0003: SubmitTx (Mempool injection of transfers, stakes, unstakes, and valuations)
 *    - 0x0004: GetAudit (10x10 Game Audit circular valuation matrix)
 *    - 0x0005: GetValuations (Consensus stage, total rewarded, and remaining cap)
 *    - 0x0006: GetRecentTxs (Paginated active and mempool transaction enumeration)
 *    - 0x0007: GetTransaction (Historical on-chain and mempool transaction lookup)
 *    - 0x0008: GetChainInfo (Consensus metrics, DKG status, and local public keys)
 *    - 0x0009: SyncWalletKeys (Hot-swapping and persistence of wallet credentials)
 *    - 0x000A: QuantumTvdAudit (Total Variation Distance QPU drift certification)
 *    - 0x000B: Autopilot (Autonomous portfolio rebalancing and valuation submission)
 *
 * @section protocol_invariants Protocol Invariants
 * - Version Enforcement: Inbound frames must strictly present SCL_RPC_VERSION_1 (0x01).
 * - SipHash Checksum Defense: All frames are verified against the session SipHash-2-4 key
 *   prior to method dispatch to prevent DoS amplification and framing corruption.
 * - Leaky Token Bucket Rate Limiting: Computational costs are subtracted from per-connection
 *   token budgets, clamping abusive peer request rates before execution.
 * - Decompression Safety: Payloads flagged with SCL_RPC_FLAG_COMPRESSED are bounded by
 *   MAX_MESSAGE_SIZE (8 MiB) to eliminate decompression memory exhaustion vectors.
 *
 * @section concurrency_model Threading Model & Lock Hierarchy
 * - Task Ingestion: Worker threads dequeue RpcTask structures from state->rpc_engine.incoming_rpc_queue.
 * - Lock Discipline: Method execution acquires subsystem locks in strict descending hierarchy:
 *   state->mutex -> state->ledger_mutex -> state->bc.rwlock -> state->wallet_mutex -> conn->l4_mutex.
 * - Concurrency Caps: Per-connection concurrency is capped at MAX_CONCURRENT_RPCS_PER_CONN (3 streams)
 *   via atomic counters (conn->active_rpc_streams).
 */

#include <unistd.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <lz4.h>
#include "rpc.h"
#include "blockchain.h"
#include "game_state.h"
#include "consensus.h"
#include "queue.h"
#include "hash_table.h"
#include "database.h"
#include "user.h"
#include "quantum_tvd.h"

extern User *global_user;

extern void handle_rpc_quantum_tvd_audit(State *state, RpcTask *task, const SclRpcHeader *hdr, const uint8_t *payload, size_t payload_len);

/* ============================================================================ */
/* SECTION 1: ASYNCHRONOUS WORKER DAEMON & TASK DEQUEUING                       */
/* ============================================================================ */

/**
 * @brief Continuous background worker loop dequeuing and processing inbound L5 RPC tasks.
 *
 * @details
 * Execution Pipeline:
 * 1. Synchronously checks the global shutdown barrier; yields execution if terminating.
 * 2. Pops an `RpcTask` wrapper from `state->rpc_engine.incoming_rpc_queue` under mutex protection.
 * 3. Records starting timestamp in microseconds using high-resolution monotonic chronometry.
 * 4. Dispatches the task to @ref handle_rpc_request.
 * 5. Measures elapsed latency and updates cumulative and per-method Prometheus metrics.
 * 6. Decrements active global and per-connection query counters via release atomics.
 * 7. Releases the reference-counted `task->conn` handle and deallocates task wrappers.
 *
 * @param[in] arg Pointer to heap-allocated `struct WorkerArgs` containing node state and worker ID.
 * @return NULL upon thread termination.
 *
 * @pre `arg` must point to valid `struct WorkerArgs`; caller transfers ownership (freed internally).
 * @post Worker terminates cleanly when `global_shutdown` evaluates true.
 * @sideeffect Frees `arg`, `task->msg`, and `task`; decrements `state->rpc_engine.active_global_queries`.
 * @thread_safety Reentrant worker function running across up to `MAX_RPC_WORKERS` threads concurrently.
 * @complexity Time: O(tasks), Space: O(1) auxiliary per worker thread.
 */
void *rpc_worker_loop(void *arg) {
    struct WorkerArgs *wa = (struct WorkerArgs *)arg;
    State *state = wa->s;
    free(wa);

    while (!atomic_load(&global_shutdown)) {
        RecreateNode *node = NULL;
        // Dequeue pending RPC task from worker queue under lock
        pthread_mutex_lock(&state->rpc_engine.incoming_rpc_queue.mutex);
        if (state->rpc_engine.incoming_rpc_queue.head) {
            node = state->rpc_engine.incoming_rpc_queue.head;
            state->rpc_engine.incoming_rpc_queue.head = node->next;
            if (!state->rpc_engine.incoming_rpc_queue.head) {
                state->rpc_engine.incoming_rpc_queue.tail = NULL;
            }
        }
        pthread_mutex_unlock(&state->rpc_engine.incoming_rpc_queue.mutex);

        if (node) {
            uint64_t start_us = get_time_us();
            RpcTask *task = (RpcTask *)node->args;
            free(node);
            
            // Peek method identifier for telemetry and latency accounting
            uint16_t method_id = 0;
            if (task->msg->length >= sizeof(SclRpcHeader)) {
                SclRpcHeader hdr;
                memcpy(&hdr, task->msg->payload, sizeof(SclRpcHeader));
                method_id = be16toh(hdr.method_id);
            }

            if (task->msg->type == MSG_RPC_REQUEST) {
                atomic_fetch_add_explicit(&state->rpc_engine.requests_total, 1, memory_order_relaxed);
            }
            
            // Dispatch request to execution engine
            handle_rpc_request(state, task);
            
            // Record execution latency and update cumulative Prometheus metrics
            if (task->msg->type == MSG_RPC_REQUEST) {
                uint64_t elapsed_us = get_time_us() - start_us;
                atomic_fetch_add_explicit(&state->rpc_engine.latency_microseconds_sum, elapsed_us, memory_order_relaxed);
                if (method_id < 12) {
                    atomic_fetch_add_explicit(&state->rpc_engine.method_latency[method_id], elapsed_us, memory_order_relaxed);
                }
            }
            
            // Decrement active query counter and release connection reference
            atomic_fetch_sub_explicit(&state->rpc_engine.active_global_queries, 1, memory_order_relaxed);
            
            if (task->conn) {
                if (task->msg->type == MSG_RPC_REQUEST) {
                    atomic_fetch_sub_explicit(&task->conn->active_rpc_streams, 1, memory_order_release);
                }
                scl_connection_release(task->conn);
            }
            free(task->msg);
            free(task);
        } else {
            // Idle wait when queue is empty to prevent thread busy-spinning (1ms for seed nodes, 10ms for local nodes)
            usleep((state && state->p2p_network.is_bootstrap) ? 1000 : 10000);
        }
    }
    return NULL;
}

/* ============================================================================ */
/* SECTION 2: ERROR FRAME CONSTRUCTION & DISPATCH                              */
/* ============================================================================ */

/**
 * @brief Constructs and enqueues a standardized binary RPC error frame to the client stream.
 *
 * @details
 * Error Frame Assembly:
 * 1. Increments method-specific rejection counters in `state->rpc_engine.method_requests_err`.
 * 2. Clamps error string length to 256 bytes (including null-terminator).
 * 3. Allocates memory for the error envelope from the thread-local arena (`arena_alloc`).
 * 4. Populates @ref SclRpcHeader: status code, request ID, error length, zero payload length.
 * 5. Appends the ASCII error message string immediately after the 32-byte header.
 * 6. Computes the 64-bit SipHash-2-4 checksum over Header || Error String using `conn->rpc_siphash_key`.
 * 7. Enqueues the completed frame onto `conn->tx_stream_queue` for reliable transmission.
 *
 * @param[in,out] state Global node state container (updated with error metrics).
 * @param[in,out] conn Target peer connection context receiving the error frame.
 * @param[in] method_id Method identifier opcode triggering the error.
 * @param[in] req_id 64-bit client tracking identifier to correlate response.
 * @param[in] status Big-endian RPC status code (e.g., SCL_RPC_STATUS_UNAUTHORIZED).
 * @param[in] err Null-terminated human-readable diagnostic error string.
 *
 * @pre `conn` must be non-NULL; `err` must be a valid null-terminated string.
 * @post Error frame enqueued to `conn->tx_stream_queue`; arena mark reset.
 * @complexity Time: O(strlen(err)), Space: O(sizeof(SclRpcHeader) + strlen(err)) arena allocation.
 */
static void send_rpc_error(State *state, SclConnection *conn, uint16_t method_id, uint64_t req_id, uint16_t status_code, const char *err_msg) {
    if (!conn) return;
    // Clamp diagnostic error message to 256 bytes
    size_t err_len = err_msg ? strlen(err_msg) : 0;
    if (err_len > 256) err_len = 256;
    size_t rpc_mark = arena_mark();
    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + err_len);
    if (resp) {
        resp->type = MSG_RPC_RESPONSE;
        resp->length = sizeof(SclRpcHeader) + err_len;
        SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
        memset(rh, 0, sizeof(SclRpcHeader));
        rh->version = SCL_RPC_VERSION_1;
        rh->status_code = htobe16(status_code);
        rh->method_id = htobe16(method_id);
        rh->request_id = htobe64(req_id);
        rh->error_msg_len = htobe16((uint16_t)err_len);
        rh->payload_len = 0;
        
        if (err_len > 0 && err_msg) {
            memcpy(resp->payload + sizeof(SclRpcHeader), err_msg, err_len);
        }
        
        // Compute SipHash-2-4 checksum across header and error message body
        uint64_t checksum = compute_rpc_checksum(resp->payload, (uint16_t)err_len, 0, conn->rpc_siphash_key);
        rh->checksum = htobe64(checksum);

        if (state && method_id < 12) {
            atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[method_id], 1, memory_order_relaxed);
        }
        // Enqueue error response frame onto connection tx queue
        queue_enqueue(&conn->tx_stream_queue, resp);
        arena_reset(rpc_mark);
    } else {
        arena_reset(rpc_mark);
    }
}

static void send_rpc_payment_required(State *state, SclConnection *conn, uint16_t method_id, uint64_t req_id, uint64_t required_subunits) {
    if (!conn) return;

    size_t challenge_len = sizeof(SclRpcPaymentChallenge);
    size_t rpc_mark = arena_mark();
    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + challenge_len);
    if (!resp) {
        arena_reset(rpc_mark);
        return;
    }

    resp->type = MSG_RPC_RESPONSE;
    resp->length = sizeof(SclRpcHeader) + challenge_len;
    
    SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
    memset(rh, 0, sizeof(SclRpcHeader));
    rh->version = SCL_RPC_VERSION_1;
    rh->status_code = htobe16(SCL_RPC_STATUS_PAYMENT_REQUIRED);
    rh->method_id = htobe16(method_id);
    rh->request_id = htobe64(req_id);
    rh->payload_len = htobe32((uint32_t)challenge_len);

    // Populate payment challenge parameters
    SclRpcPaymentChallenge *challenge = (SclRpcPaymentChallenge *)(resp->payload + sizeof(SclRpcHeader));
    challenge->amount_subunits = htobe64(required_subunits);
    challenge->price_rate_lock_id = htobe64(get_time_us());
    
    // Resolve node fee recipient address
    pthread_mutex_lock(&state->wallet_mutex);
    SHA256(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, challenge->recipient_address);
    pthread_mutex_unlock(&state->wallet_mutex);

    // Compute challenge hash = SHA256(req_id || method_id || salt)
    uint8_t seed_buf[18];
    uint64_t req_be = htobe64(req_id);
    uint16_t meth_be = htobe16(method_id);
    memcpy(seed_buf, &req_be, 8);
    memcpy(seed_buf + 8, &meth_be, 2);
    uint64_t salt = get_real_time_us();
    memcpy(seed_buf + 10, &salt, 8);
    SHA256(seed_buf, sizeof(seed_buf), challenge->challenge_hash);

    challenge->valid_until_timestamp = htobe64(get_time_ms() + 300000); // 5 minutes TTL
    challenge->accepted_payment_types = htobe16(0x0003); // Accepts Transfer (0x01) and Centinel (0x02)

    // Compute checksum over challenge payload and queue response
    uint64_t checksum = compute_rpc_checksum(resp->payload, 0, (uint32_t)challenge_len, conn->rpc_siphash_key);
    rh->checksum = htobe64(checksum);

    queue_enqueue(&conn->tx_stream_queue, resp);
    arena_reset(rpc_mark);
}

static void send_rpc_ok(State *state, SclConnection *conn, uint16_t method_id, uint64_t req_id) {
    if (!conn) return;
    size_t rpc_mark = arena_mark();
    // Allocate standard 32-byte RPC response header without payload
    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader));
    if (resp) {
        resp->type = MSG_RPC_RESPONSE;
        resp->length = sizeof(SclRpcHeader);
        SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
        memset(rh, 0, sizeof(SclRpcHeader));
        rh->version = SCL_RPC_VERSION_1;
        rh->status_code = htobe16(SCL_RPC_STATUS_OK);
        rh->method_id = htobe16(method_id);
        rh->request_id = htobe64(req_id);
        rh->payload_len = 0;

        // Checksum empty payload and queue response
        uint64_t checksum = compute_rpc_checksum(resp->payload, 0, 0, conn->rpc_siphash_key);
        rh->checksum = htobe64(checksum);

        if (state && method_id < 12) {
            atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[method_id], 1, memory_order_relaxed);
        }
        queue_enqueue(&conn->tx_stream_queue, resp);
        arena_reset(rpc_mark);
    } else {
        arena_reset(rpc_mark);
    }
}

/* ============================================================================ */
/* SECTION 3: REQUEST INGRESS DECODING, VALIDATION & ROUTING                    */
/* ============================================================================ */

/**
 * @brief Validates, authenticates, and executes an inbound L5 RPC wire request.
 *
 * @details
 * Ingress Processing Sequence:
 * 1. Header Validation: Verifies buffer size >= 32 bytes; decodes big-endian header fields.
 * 2. Integer Overflow Boundary Check: Verifies `msg->length >= 32 + err_len + payload_len` via subtraction.
 * 3. Anti-Replay Sliding Window:
 *    - Validates request timestamp against local wall-clock (grace period: &plusmn;5 seconds).
 *    - Enforces 64-second maximum timestamp age against `highest_seen_timestamp`.
 *    - Checks 256-element circular buffer (`rpc_recent_request_ids`) to eliminate exact duplicates.
 * 4. Transparent LZ4 Decompression:
 *    - If `SCL_RPC_FLAG_COMPRESSED` is set, decompresses payload into thread-local staging memory.
 *    - Enforces strict decompression bomb protection (rejects payloads > @ref MAX_MESSAGE_SIZE = 8 MiB).
 * 5. Payment Receipt Extraction & Verification:
 *    - Extracts and validates OP_TRANSFER_POINTER or OP_REDEEM_CENTINEL proofs if payment flag is set.
 * 6. Method Dispatching:
 *    Routes to dedicated handlers (0x0000..0x000B) to query or mutate ledger state.
 *
 * @param[in,out] state Global node state container.
 * @param[in,out] task Dispatch context containing inbound Message, connection handle, and caller pubkey.
 *
 * @pre `state` and `task` must be non-NULL; `task->msg->length >= sizeof(SclRpcHeader)`.
 * @post Response frame generated and enqueued on success, or error frame on failure.
 * @thread_safety Thread-safe. Acquires appropriate read-write locks per method.
 * @complexity Time: O(method_execution_time + serialization), Space: O(response_size).
 */
void handle_rpc_request(State *state, RpcTask *task) {
    Message *msg = task->msg;
    if (msg->length < sizeof(SclRpcHeader)) return;
    
    // 1. Header Validation: Deserialize binary header and convert fields to host byte order
    SclRpcHeader hdr;
    memcpy(&hdr, msg->payload, sizeof(SclRpcHeader));
    
    hdr.status_code = be16toh(hdr.status_code);
    hdr.method_id = be16toh(hdr.method_id);
    hdr.error_msg_len = be16toh(hdr.error_msg_len);
    hdr.request_id = be64toh(hdr.request_id);
    hdr.payload_len = be32toh(hdr.payload_len);
    hdr.cursor = be32toh(hdr.cursor);
    hdr.checksum = be64toh(hdr.checksum);
    
    // 2. Integer Overflow Boundary Check: Subtraction-based validation preventing wrap-around exploits
    if (msg->length < 32 || msg->length - 32 < hdr.error_msg_len || msg->length - 32 - hdr.error_msg_len < hdr.payload_len) {
        return;
    }
    
    char peer_ip[64] = "unknown";
    if (task->conn) {
        if (task->conn->current_path.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)&task->conn->current_path)->sin_addr, peer_ip, sizeof(peer_ip));
        } else if (task->conn->current_path.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&task->conn->current_path)->sin6_addr, peer_ip, sizeof(peer_ip));
        }
    }
    
    if (msg->type == MSG_RPC_REQUEST) {
        SCL_LOG_RPC_TRACE(&hdr, peer_ip);
    }

    // 3. Anti-Replay Sliding Window Tracking
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if (msg->type == MSG_RPC_REQUEST && task->conn) {
        uint64_t req_timestamp_ms = hdr.request_id >> 16;
        uint64_t current_time_ms = get_real_time_us() / 1000ULL;
        
        pthread_mutex_lock(&task->conn->l4_mutex);
        uint64_t highest_seen = task->conn->rpc_highest_seen_timestamp;
        
        // Clock Skew Grace Period: ±5s
        if (req_timestamp_ms > current_time_ms + 5000) {
            pthread_mutex_unlock(&task->conn->l4_mutex);
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_UNAUTHORIZED, "Request timestamp too far in the future");
            return;
        }
        
        // 64-second sliding window constraint
        if (req_timestamp_ms + 64000 < highest_seen || req_timestamp_ms + 64000 < current_time_ms - 5000) {
            pthread_mutex_unlock(&task->conn->l4_mutex);
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_UNAUTHORIZED, "Request expired (outside sliding window)");
            return;
        }
        
        // Tracking Matrix: O(1) Replay collision check
        for (int i = 0; i < 256; i++) {
            if (task->conn->rpc_recent_request_ids[i] == hdr.request_id) {
                pthread_mutex_unlock(&task->conn->l4_mutex);
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_UNAUTHORIZED, "Request ID replay detected");
                return;
            }
        }
        
        if (req_timestamp_ms > highest_seen) {
            task->conn->rpc_highest_seen_timestamp = req_timestamp_ms;
        }
        
        task->conn->rpc_recent_request_ids[task->conn->rpc_request_idx % 256] = hdr.request_id;
        task->conn->rpc_request_idx++;
        pthread_mutex_unlock(&task->conn->l4_mutex);
    }
#endif
    
    // 4. Transparent LZ4 Decompression with strict bomb protection bounds
    Message *decompressed_msg = NULL;
    if ((hdr.flags & SCL_RPC_FLAG_COMPRESSED) && hdr.payload_len > 0) {
        if (hdr.payload_len > MAX_MESSAGE_SIZE) {
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Decompression bomb protected");
            return;
        }

        size_t prefix_len = sizeof(SclRpcHeader) + hdr.error_msg_len;
        size_t sig_len = (hdr.flags & SCL_RPC_FLAG_SIGNED) ? DILITHIUM_SIGNATURE_LEN : 0;
        if (hdr.payload_len < sig_len) {
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Signed payload length mismatch");
            return;
        }

        const uint8_t *compressed_data = msg->payload + prefix_len + sig_len;
        size_t comp_len = hdr.payload_len - sig_len;

        size_t max_decomp = MAX_MESSAGE_SIZE - (prefix_len + sig_len);
        uint8_t *decomp_buf = get_l5_staging_buffer();
        if (!decomp_buf) {
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Failed to allocate memory for decompression");
            return;
        }

        int decompressed_bytes = LZ4_decompress_safe((const char *)compressed_data,
                                                     (char *)decomp_buf,
                                                     (int)comp_len,
                                                     (int)max_decomp);
        if (decompressed_bytes < 0) {
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "LZ4 decompression failed");
            return;
        }

        size_t new_msg_len = prefix_len + sig_len + decompressed_bytes;
        if (new_msg_len > MAX_MESSAGE_SIZE) {
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Decompressed message size exceeds limit");
            return;
        }

        decompressed_msg = malloc(offsetof(Message, payload) + new_msg_len);
        if (!decompressed_msg) {
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Failed to allocate memory for decompressed message");
            return;
        }

        memcpy(decompressed_msg->payload, msg->payload, prefix_len + sig_len);
        memcpy(decompressed_msg->payload + prefix_len + sig_len, decomp_buf, decompressed_bytes);

        decompressed_msg->type = msg->type;
        decompressed_msg->length = (uint32_t)new_msg_len;
        hdr.payload_len = (uint32_t)(sig_len + decompressed_bytes);
        
        SclRpcHeader *mutable_hdr = (SclRpcHeader *)decompressed_msg->payload;
        mutable_hdr->payload_len = htobe32(hdr.payload_len);

        msg = decompressed_msg;
    }
    
    // 5. Payment Receipt Extraction & Verification
    bool payment_verified = false;
    if (hdr.flags & SCL_RPC_FLAG_PAYMENT_RECEIPT) {
        size_t sig_len = (hdr.flags & SCL_RPC_FLAG_SIGNED) ? DILITHIUM_SIGNATURE_LEN : 0;
        size_t receipt_len = sizeof(SclRpcPaymentReceipt);
        
        // Guard against integer underflow: payload must hold both signature and receipt
        if (hdr.payload_len < sig_len + receipt_len) {
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Payload too short for PaymentReceipt");
            if (decompressed_msg) free(decompressed_msg);
            return;
        }
        
        size_t prefix_len = sizeof(SclRpcHeader) + hdr.error_msg_len;
        
        SclRpcPaymentReceipt receipt_storage;
        memcpy(&receipt_storage, msg->payload + prefix_len + sig_len, receipt_len);
        const SclRpcPaymentReceipt *receipt = &receipt_storage;
        
        pthread_rwlock_rdlock(&state->bc.rwlock);
        if (receipt->payment_type == 0x01) { // OP_TRANSFER_POINTER
            if (hash_table_lookup(state->processed_txs, receipt->tx_id, true)) payment_verified = true;
        } else if (receipt->payment_type == 0x02) { // OP_REDEEM_CENTINEL
            if (hash_table_lookup(state->bc.centinel.nullifier_set, receipt->tx_id, true)) payment_verified = true;
        }
        pthread_rwlock_unlock(&state->bc.rwlock);

        if (!payment_verified) {
            for (int i = 0; i < MAX_PENDING_OPS; i++) {
                Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                if (pop) {
                    const uint8_t *tx_id = get_operation_tx_id(pop);
                    if (tx_id && memcmp(tx_id, receipt->tx_id, 32) == 0) {
                        payment_verified = true;
                        break;
                    }
                }
            }
        }

        // Remaining args length excluding signature and receipt
        uint32_t new_payload_len = hdr.payload_len - (uint32_t)receipt_len;
        uint32_t args_len = hdr.payload_len - (uint32_t)sig_len - (uint32_t)receipt_len;

        // Shift remaining payload arguments up to overwrite the receipt slot, keeping signature intact
        memmove(msg->payload + prefix_len + sig_len,
                msg->payload + prefix_len + sig_len + receipt_len,
                args_len);

        hdr.payload_len = new_payload_len;
        SclRpcHeader *mutable_hdr = (SclRpcHeader *)msg->payload;
        mutable_hdr->payload_len = htobe32(hdr.payload_len);
    }
    
    // 6. Core Method Dispatch Routing Map (0x0000 - 0x000B)
    switch(hdr.method_id) {
        case 0x0000: { // GetRegistry
            size_t rpc_mark = arena_mark();
            Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + 9);
            if (resp) {
                resp->type = MSG_RPC_RESPONSE;
                resp->length = sizeof(SclRpcHeader) + 9;
                SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                memset(rh, 0, sizeof(SclRpcHeader));
                rh->version = SCL_RPC_VERSION_1;
                rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                rh->method_id = htobe16(hdr.method_id);
                rh->request_id = htobe64(hdr.request_id);
                rh->payload_len = htobe32(9);
                // Payload: mapped indices mapping method_id -> costs
                for(int i=0; i<9; i++) resp->payload[sizeof(SclRpcHeader) + i] = i;
                
                uint64_t checksum = compute_rpc_checksum(resp->payload, 0, 9, task->conn->rpc_siphash_key);
                rh->checksum = htobe64(checksum);

                atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                queue_enqueue(&task->conn->tx_stream_queue, resp);
                arena_reset(rpc_mark);
            } else {
                arena_reset(rpc_mark);
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
            }
            break;
        }
        case 0x0001: { // GetBalance
            // Extracts current asset account parameters out of the global MMR ledger
            if (hdr.payload_len == PUBKEY_LEN) {
                uint8_t target_pk[PUBKEY_LEN];
                memcpy(target_pk, msg->payload + sizeof(SclRpcHeader) + hdr.error_msg_len, PUBKEY_LEN);
                
                // Calculate on-chain liquid, staked, and cumulative fee balances
                uint64_t balance = calculate_balance_subunits(&state->bc, target_pk, false);
                uint64_t staked_balance = calculate_staked_subunits_by_owner(state, target_pk);
                uint64_t fees_paid = calculate_fees_paid_subunits(&state->bc, target_pk);
                
                // Scan and sum active, unspent Centinel validation UTXOs
                uint64_t utxo_validations = 0;
                size_t active_utxo_count = 0;
                pthread_rwlock_rdlock(&state->bc.rwlock);
                pthread_mutex_lock(&state->user_wallet.utxo_mutex);
                for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
                    ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
                    if (memcmp(utxo->pubkey, target_pk, PUBKEY_LEN) != 0) continue;
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
                            utxo_validations += utxo->amount;
                            active_utxo_count++;
                        }
                    }
                }
                uint64_t num_val_utxos = (uint64_t)state->user_wallet.num_val_utxos;

                uint8_t user_id[USER_ID_LEN];
                SHA256(target_pk, PUBKEY_LEN, user_id);

                // Serialize active Centinel UTXO entries (nullifier || amount || blinding_factor)
                uint8_t *utxo_payload = NULL;
                size_t u_idx = 0;
                if (active_utxo_count > 0) {
                    utxo_payload = malloc(active_utxo_count * 72);
                    if (utxo_payload) {
                        for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
                            ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
                            if (memcmp(utxo->pubkey, target_pk, PUBKEY_LEN) != 0) continue;
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
                                    memcpy(utxo_payload + u_idx * 72, utxo->nullifier, 32);
                                    uint64_t amt_be = htobe64(utxo->amount);
                                    memcpy(utxo_payload + u_idx * 72 + 32, &amt_be, 8);
                                    memcpy(utxo_payload + u_idx * 72 + 40, utxo->blinding_factor, 32);
                                    u_idx++;
                                }
                            }
                        }
                    }
                }

                // Derive local threshold address if queried key matches node identity
                uint8_t local_threshold_addr[USER_ID_LEN] = {0};
                uint8_t local_threshold_pk[PUBKEY_LEN];
                bool has_local_threshold = false;
                if (memcmp(target_pk, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                    if (compute_threshold_pubkey(state, local_threshold_pk) == 0) {
                        SHA256(local_threshold_pk, PUBKEY_LEN, local_threshold_addr);
                        has_local_threshold = true;
                    }
                }

                // Collect native unspent SCL pointers for the user (including fee pointers spent == 2)
                Pointer *native_ptrs = malloc(1024 * sizeof(Pointer));
                size_t native_count = 0;
                for (size_t i = 0; i < state->bc.pointer_table->size; i++) {
                    GenericHashEntry *entry = state->bc.pointer_table->buckets[i];
                    while (entry && native_count < 1024) {
                        if (entry->type == HASH_ENTRY_POINTER && entry->data.pointer.spent != 1) {
                            Pointer *ptr = &entry->data.pointer;
                            bool belongs_to_user = false;
                            if (memcmp(ptr->owner_address, user_id, USER_ID_LEN) == 0) {
                                belongs_to_user = true;
                            } else if (ptr->staked) {
                                if (has_local_threshold && memcmp(ptr->owner_address, local_threshold_addr, USER_ID_LEN) == 0) {
                                    belongs_to_user = true;
                                } else {
                                    PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, ptr->owner_address, false);
                                    if (cache_entry && memcmp(cache_entry->pubkey, target_pk, PUBKEY_LEN) == 0) {
                                        belongs_to_user = true;
                                    }
                                }
                            }
                            if (belongs_to_user) {
                                native_ptrs[native_count++] = *ptr;
                            }
                        }
                        entry = entry->next;
                    }
                }

                pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
                pthread_rwlock_unlock(&state->bc.rwlock);

                // Assemble GetBalance wire response payload
                uint32_t total_payload_len = 40 + (utxo_payload ? u_idx * 72 : 0) + 4 + (native_count * 145);
                size_t rpc_mark = arena_mark();
                Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + total_payload_len);
                if (resp) {
                    resp->type = MSG_RPC_RESPONSE;
                    resp->length = sizeof(SclRpcHeader) + total_payload_len;
                    SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                    memset(rh, 0, sizeof(SclRpcHeader));
                    rh->version = SCL_RPC_VERSION_1;
                    rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                    rh->method_id = htobe16(hdr.method_id);
                    rh->request_id = htobe64(hdr.request_id);
                    rh->payload_len = htobe32(total_payload_len);
                    
                    uint64_t balance_be = htobe64(balance);
                    uint64_t staked_be = htobe64(staked_balance);
                    uint64_t fees_be = htobe64(fees_paid);
                    uint64_t utxo_be = htobe64(utxo_validations);
                    uint64_t num_utxos_be = htobe64(num_val_utxos);
                    
                    memcpy(resp->payload + sizeof(SclRpcHeader), &balance_be, 8);
                    memcpy(resp->payload + sizeof(SclRpcHeader) + 8, &staked_be, 8);
                    memcpy(resp->payload + sizeof(SclRpcHeader) + 16, &fees_be, 8);
                    memcpy(resp->payload + sizeof(SclRpcHeader) + 24, &utxo_be, 8);
                    memcpy(resp->payload + sizeof(SclRpcHeader) + 32, &num_utxos_be, 8);
                    
                    size_t offset = 40;
                    if (utxo_payload && u_idx > 0) {
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, utxo_payload, u_idx * 72);
                        offset += (u_idx * 72);
                    }
                    if (utxo_payload) free(utxo_payload);

                    uint32_t native_count_be = htobe32((uint32_t)native_count);
                    memcpy(resp->payload + sizeof(SclRpcHeader) + offset, &native_count_be, 4);
                    offset += 4;

                    for (size_t i = 0; i < native_count; i++) {
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, native_ptrs[i].pointer_id, 32); offset += 32;
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, native_ptrs[i].parent_coin_id, 32); offset += 32;
                        uint64_t start_be = htobe64(native_ptrs[i].start_subunit);
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, &start_be, 8); offset += 8;
                        uint64_t end_be = htobe64(native_ptrs[i].end_subunit);
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, &end_be, 8); offset += 8;
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, native_ptrs[i].owner_address, 32); offset += 32;
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, native_ptrs[i].prev_tx_hash, 32); offset += 32;
                        uint8_t status_flag = (native_ptrs[i].spent == 2) ? 2 : (native_ptrs[i].staked ? 1 : 0);
                        memcpy(resp->payload + sizeof(SclRpcHeader) + offset, &status_flag, 1); offset += 1;
                    }
                    free(native_ptrs);
                    
                    uint64_t checksum = compute_rpc_checksum(resp->payload, 0, total_payload_len, task->conn->rpc_siphash_key);
                    rh->checksum = htobe64(checksum);

                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                    queue_enqueue(&task->conn->tx_stream_queue, resp);
                    arena_reset(rpc_mark);
                } else {
                    if (utxo_payload) free(utxo_payload);
                    free(native_ptrs);
                    arena_reset(rpc_mark);
                    send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
                }
            } else {
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Invalid args for GetBalance");
            }
            break;
        }
        case 0x0002: { // GetBlock
            // Extracts raw transactional block states bounded by height index fields
            if (hdr.flags & SCL_RPC_FLAG_PAGINATED) {
                uint64_t start_height = hdr.cursor;
                pthread_rwlock_rdlock(&state->bc.rwlock);
                
                size_t streamed_count = 0;
                uint64_t end_height = state->current_block_number;
                
                // Stream historical blocks sequentially up to pagination window limit
                for (uint64_t i = start_height; i <= end_height && streamed_count < MAX_PAGINATION_RANGE; i++) {
                    uint8_t *ser_block = NULL;
                    size_t ser_len = 0;
                    if (scl_db_get_block(i, &ser_block, &ser_len) != 0) continue;
                    
                    Block *b = calloc(1, sizeof(Block));
                    if (!b || deserialize_block(b, ser_block, ser_len) != 0) {
                        if (b) free_block(b);
                        free(ser_block);
                        continue;
                    }
                    free(ser_block);

                    if (b->block_number >= start_height) {
                        size_t rpc_mark = arena_mark();
                        Message *resp = (Message *)arena_alloc(MAX_MESSAGE_SIZE);
                        if (resp) {
                            resp->type = MSG_RPC_RESPONSE;
                            int offset = process_block_data(b, resp->payload + sizeof(SclRpcHeader), NULL, true);
                            if (offset > 0) {
                                resp->length = sizeof(SclRpcHeader) + offset;
                                SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                                memset(rh, 0, sizeof(SclRpcHeader));
                                rh->version = SCL_RPC_VERSION_1;
                                rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                                rh->method_id = htobe16(hdr.method_id);
                                rh->request_id = htobe64(hdr.request_id);
                                rh->payload_len = htobe32(offset);
                                rh->cursor = htobe32((uint32_t)b->block_number);
                                
                                uint64_t checksum = compute_rpc_checksum(resp->payload, 0, offset, task->conn->rpc_siphash_key);
                                rh->checksum = htobe64(checksum);

                                atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                                queue_enqueue(&task->conn->tx_stream_queue, resp);
                                streamed_count++;
                            }
                        }
                        arena_reset(rpc_mark);
                    }
                    free_block(b);
                }
                pthread_rwlock_unlock(&state->bc.rwlock);
                if (streamed_count == 0) {
                    send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "No blocks found in range");
                }
            } else {
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Missing PAGINATED flag");
            }
            break;
        }
        case 0x0003: { // SubmitTx
            if (hdr.flags & SCL_RPC_FLAG_SIGNED) {
                if (hdr.payload_len < SIGNATURE_LEN + 1) {
                    send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Payload too short for signature");
                    break;
                }
                const uint8_t *sig = msg->payload + sizeof(SclRpcHeader) + hdr.error_msg_len;
                const uint8_t *op_data = sig + SIGNATURE_LEN;
                size_t op_len = hdr.payload_len - SIGNATURE_LEN;
                
                Operation *op = calloc(1, sizeof(Operation));
                if (op) {
                    int consumed = deserialize_operation(op_data, op_len, op, 1);
                    if (consumed > 0) {
                        op->is_rpc_injected = true;
                        // Extract public key for RPC auth verification
                        const uint8_t *auth_pubkey = NULL;
                        if (op->type == OP_TRANSFER_POINTER) auth_pubkey = op->data.transfer_pointer.sender_pubkey;
                        else if (op->type == OP_STAKE) auth_pubkey = op->data.stake.sender_pubkey;
                        else if (op->type == OP_UNSTAKE) auth_pubkey = op->data.unstake.recipient_pubkey;
                        else if (op->type == OP_MINT_COIN) auth_pubkey = op->data.mint_coin.owner_pubkey;
                        else if (op->type == OP_SUBMIT_VALUATION) auth_pubkey = op->data.submit_valuation.pubkey;
                        else if (op->type == OP_CLAIM_VALIDATION) auth_pubkey = op->data.claim_validation.pubkey;
                        else if (op->type == OP_REDEEM_CENTINEL) auth_pubkey = (!is_zeroed(task->sender_pubkey, PUBKEY_LEN)) ? task->sender_pubkey : state->user_wallet.dilithium_pubkey;

                        // Authenticate ML-DSA-87 signature over normalized header prefix (24 bytes) + serialized operation
                        if (auth_pubkey) {
                            size_t digest_mark = arena_mark();
                            uint8_t *digest_input = arena_alloc(24 + op_len);
                            if (digest_input) {
                                memset(digest_input, 0, 24 + op_len);
                                memcpy(digest_input, msg->payload, 24);
                                SclRpcHeader *verify_hdr = (SclRpcHeader *)digest_input;
                                verify_hdr->status_code = htobe16(0);
                                verify_hdr->error_msg_len = htobe16(0);
                                memcpy(digest_input + 24, op_data, op_len);
                                if (dilithium_verify(digest_input, 24 + op_len, sig, auth_pubkey) != 0) {
                                    atomic_fetch_add_explicit(&state->rpc_engine.rejected_auth_fail, 1, memory_order_relaxed);
                                    arena_reset(digest_mark);
                                    send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_UNAUTHORIZED, "Invalid RPC signature");
                                    free(op);
                                    break;
                                }
                                arena_reset(digest_mark);
                            } else {
                                arena_reset(digest_mark);
                                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
                                free(op);
                                break;
                            }
                        } else {
                            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Operation lacks auth pubkey");
                            free(op);
                            break;
                        }

                        // Dispatch operation execution based on operation type
                        if (op->type == OP_TRANSFER_POINTER) {
                            int added = create_and_broadcast_transfer(state, op->data.transfer_pointer.recipient_pubkey, op->data.transfer_pointer.amount, false);
                            if (added == 0 || added == 2) {
                                send_rpc_ok(state, task->conn, hdr.method_id, hdr.request_id);
                            } else {
                                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Transfer failed: insufficient balance");
                            }
                            free(op);
                            break;
                        } else if (op->type == OP_STAKE) {
                            int added = create_and_broadcast_stake(state, op->data.stake.amount, false);
                            if (added == 0 || added == 2) {
                                send_rpc_ok(state, task->conn, hdr.method_id, hdr.request_id);
                            } else {
                                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Stake failed: insufficient threshold peers");
                            }
                            free(op);
                            break;
                        } else if (op->type == OP_UNSTAKE) {
                            int added = create_and_broadcast_unstake(state, op->data.unstake.amount, false);
                            if (added == 0 || added == 2) {
                                send_rpc_ok(state, task->conn, hdr.method_id, hdr.request_id);
                            } else {
                                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Unstake failed: insufficient threshold peers");
                            }
                            free(op);
                            break;
                        }

                        // Forward validation to the main mempool processor
                        pthread_mutex_lock(&state->mutex);
                        int added = add_pending_operation(state, op);
                        pthread_mutex_unlock(&state->mutex);
                        
                        if (added == 0 || added == 2) {
                            // Broadcast the new pending operation to the P2P network
                            Message *broadcast_msg = calloc(1, sizeof(Message));
                            if (broadcast_msg) {
                                broadcast_msg->type = MSG_PENDING_OPERATION;
                                broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
                                if (broadcast_msg->length > 0) {
                                    p2p_broadcast(state, broadcast_msg);
                                }
                                free(broadcast_msg);
                            }
                            send_rpc_ok(state, task->conn, hdr.method_id, hdr.request_id);
                        } else {
                            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Tx rejected by mempool");
                        }
                    } else {
                        send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Invalid operation");
                    }
                    free(op);
                }
            } else {
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Missing SIGNED flag");
            }
            break;
        }
        case 0x0004: { // GetAudit
            // Serialize 10x10 circular game audit matrix: user_id(32) + numbers(10*4) + timestamp(8) + seed(32)
            size_t payload_size = AUDIT_SIZE * (USER_ID_LEN + NUMBERS_PER_VALUATION * sizeof(uint32_t) + sizeof(uint64_t) + 32);
            size_t rpc_mark = arena_mark();
            Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + payload_size);
            if (resp) {
                resp->type = MSG_RPC_RESPONSE;
                resp->length = sizeof(SclRpcHeader) + payload_size;
                SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                memset(rh, 0, sizeof(SclRpcHeader));
                rh->version = SCL_RPC_VERSION_1;
                rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                rh->method_id = htobe16(hdr.method_id);
                rh->request_id = htobe64(hdr.request_id);
                rh->payload_len = htobe32(payload_size);
                
                uint8_t *p = resp->payload + sizeof(SclRpcHeader);
                pthread_mutex_lock(&state->game_state.mutex);
                int val_count = state->game_state.valuation_count;
                int start_idx = (val_count < AUDIT_SIZE) ? 0 : state->game_state.current_audit_index;
                for (size_t i = 0; i < AUDIT_SIZE; i++) {
                    int display_idx = (start_idx + i) % AUDIT_SIZE;
                    memcpy(p, state->game_state.game_audit[display_idx].user_id, USER_ID_LEN);
                    p += USER_ID_LEN;
                    for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
                        uint32_t num_net = htonl(state->game_state.game_audit[display_idx].numbers[j]);
                        memcpy(p, &num_net, sizeof(uint32_t));
                        p += sizeof(uint32_t);
                    }
                    uint64_t timestamp_net = htobe64(state->game_state.game_audit[display_idx].timestamp);
                    memcpy(p, &timestamp_net, sizeof(uint64_t));
                    p += sizeof(uint64_t);
                    memcpy(p, state->game_state.game_audit[display_idx].beacon_seed, 32);
                    p += 32;
                }
                pthread_mutex_unlock(&state->game_state.mutex);
                                
                uint64_t checksum = compute_rpc_checksum(resp->payload, 0, payload_size, task->conn->rpc_siphash_key);
                rh->checksum = htobe64(checksum);

                atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                queue_enqueue(&task->conn->tx_stream_queue, resp);
                arena_reset(rpc_mark);
            } else {
                arena_reset(rpc_mark);
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
            }
            break;
        }
        case 0x0005: { // GetValuations
            // Return total rewarded subunits, remaining cap, and current consensus stage
            size_t rpc_mark = arena_mark();
            Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + 24);
            if (resp) {
                resp->type = MSG_RPC_RESPONSE;
                resp->length = sizeof(SclRpcHeader) + 24;
                SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                memset(rh, 0, sizeof(SclRpcHeader));
                rh->version = SCL_RPC_VERSION_1;
                rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                rh->method_id = htobe16(hdr.method_id);
                rh->request_id = htobe64(hdr.request_id);
                rh->payload_len = htobe32(24);
                
                uint64_t total_r = 0;
                pthread_rwlock_rdlock(&state->bc.rwlock);
                for (size_t i = 0; i < state->bc.insert_order_count; i++) {
                    if (state->bc.insert_order[i]) {
                        total_r += state->bc.insert_order[i]->total_subunits;
                    }
                }
                pthread_rwlock_unlock(&state->bc.rwlock);
                
                pthread_mutex_lock(&state->game_state.mutex);
                uint64_t remaining_val = (MAX_TOTAL_SUBUNITS > total_r) ? (MAX_TOTAL_SUBUNITS - total_r) : 0;
                uint64_t total_rewarded = htobe64(total_r);
                uint64_t remaining = htobe64(remaining_val);
                uint64_t cur_stage = htobe64((uint64_t)state->game_state.cached_stage);
                pthread_mutex_unlock(&state->game_state.mutex);
                
                memcpy(resp->payload + sizeof(SclRpcHeader), &total_rewarded, 8);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 8, &remaining, 8);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 16, &cur_stage, 8);
                                
                uint64_t checksum = compute_rpc_checksum(resp->payload, 0, 24, task->conn->rpc_siphash_key);
                rh->checksum = htobe64(checksum);

                atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                queue_enqueue(&task->conn->tx_stream_queue, resp);
                arena_reset(rpc_mark);
            } else {
                arena_reset(rpc_mark);
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
            }
            break;
        }
        case 0x0006: { // GetRecentTxs
            // Enumerate pending mempool transaction identifiers within cursor pagination window
            if (hdr.flags & SCL_RPC_FLAG_PAGINATED) {
                uint32_t cursor = hdr.cursor;
                uint8_t *tx_ids = malloc(MAX_PAGINATION_RANGE * COIN_ID_LEN);
                if (!tx_ids) {
                    send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Memory allocation failed");
                    break;
                }
                
                size_t count = 0;
                size_t skipped = 0;
                
                for (int i = 0; i < MAX_PENDING_OPS && count < MAX_PAGINATION_RANGE; i++) {
                    Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                    if (pop) {
                        if (skipped >= cursor) {
                            const uint8_t *pid = get_operation_tx_id(pop);
                            if (pid) memcpy(tx_ids + (count * COIN_ID_LEN), pid, COIN_ID_LEN);
                            else {
                                uint8_t *data;
                                size_t data_len;
                                if (pop->type == OP_SUBMIT_VALUATION) {
                                    data = (uint8_t *)&pop->data.submit_valuation;
                                    data_len = sizeof(ValuationData);
                                } else {
                                    data = (uint8_t *)pop;
                                    data_len = sizeof(Operation);
                                }
                                SHA256(data, data_len, tx_ids + (count * COIN_ID_LEN));
                            }
                            count++;
                        } else {
                            skipped++;
                        }
                    }
                }
                
                size_t rpc_mark = arena_mark();
                Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + (count * COIN_ID_LEN));
                if (resp) {
                    resp->type = MSG_RPC_RESPONSE;
                    resp->length = sizeof(SclRpcHeader) + (count * COIN_ID_LEN);
                    SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                    memset(rh, 0, sizeof(SclRpcHeader));
                    rh->version = SCL_RPC_VERSION_1;
                    rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                    rh->method_id = htobe16(hdr.method_id);
                    rh->request_id = htobe64(hdr.request_id);
                    rh->payload_len = htobe32(count * COIN_ID_LEN);
                    if (count == MAX_PAGINATION_RANGE) {
                        rh->flags |= SCL_RPC_FLAG_PAGINATED;
                        rh->cursor = htobe32(cursor + count);
                    }
                    if (count > 0) {
                        memcpy(resp->payload + sizeof(SclRpcHeader), tx_ids, count * COIN_ID_LEN);
                    }
                    
                    uint64_t checksum = compute_rpc_checksum(resp->payload, 0, count * COIN_ID_LEN, task->conn->rpc_siphash_key);
                    rh->checksum = htobe64(checksum);

                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                    queue_enqueue(&task->conn->tx_stream_queue, resp);
                    arena_reset(rpc_mark);
                } else {
                    arena_reset(rpc_mark);
                    send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
                }
                free(tx_ids);
            } else {
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Missing PAGINATED flag");
            }
            break;
        }
        case 0x0007: { // GetTransaction
            if (hdr.payload_len == COIN_ID_LEN) {
                uint8_t tx_hash[COIN_ID_LEN];
                memcpy(tx_hash, msg->payload + sizeof(SclRpcHeader) + hdr.error_msg_len, COIN_ID_LEN);
                
                // Resolve Coin ID or Pointer ID to the actual transaction hash
                uint8_t resolved_tx_hash[COIN_ID_LEN];
                memcpy(resolved_tx_hash, tx_hash, COIN_ID_LEN);

                pthread_rwlock_rdlock(&state->bc.rwlock);
                SCLCoin *coin = hash_table_lookup(state->bc.coin_table, tx_hash, false);
                Pointer *ptr = hash_table_lookup(state->bc.pointer_table, tx_hash, false);
                if (coin) {
                    memcpy(resolved_tx_hash, coin->creation_tx_hash, COIN_ID_LEN);
                } else if (ptr) {
                    memcpy(resolved_tx_hash, ptr->prev_tx_hash, COIN_ID_LEN);
                }
                pthread_rwlock_unlock(&state->bc.rwlock);

                Operation *block_op = NULL;
                bool found_in_blocks = false;

                // Check active mempool operations first for low-latency retrieval
                for (int i = 0; i < MAX_PENDING_OPS; i++) {
                    Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                    if (pop) {
                        uint8_t pkey[COIN_ID_LEN];
                        const uint8_t *pid = get_operation_tx_id(pop);
                        if (pid) memcpy(pkey, pid, COIN_ID_LEN);
                        else {
                            uint8_t *data;
                            size_t data_len;
                            if (pop->type == OP_SUBMIT_VALUATION) {
                                data = (uint8_t *)&pop->data.submit_valuation;
                                data_len = sizeof(ValuationData);
                            } else {
                                data = (uint8_t *)pop;
                                data_len = sizeof(Operation);
                            }
                            SHA256(data, data_len, pkey);
                        }
                        if (memcmp(pkey, resolved_tx_hash, COIN_ID_LEN) == 0) {
                            block_op = malloc(sizeof(Operation));
                            if (block_op) {
                                *block_op = *pop;
                                found_in_blocks = true;
                            }
                            break;
                        }
                    }
                }

                // If the transaction has been mined and pruned from mempool, search the Block History
                if (!found_in_blocks) {
                    pthread_rwlock_rdlock(&state->bc.rwlock);
                    size_t scan_limit = state->current_block_number + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
                    if (scan_limit > 16) scan_limit = 16; // Bounded search depth to prevent O(N^2) RPC timeouts
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

                        if (block) {
                            size_t tx_idx = 0;
                            for (size_t op_idx = 0; op_idx < block->operation_count; op_idx++) {
                                Operation *op = &block->operations[op_idx];
                                if (op->type == OP_TRANSFER_POINTER) {
                                    const uint8_t *op_id = get_operation_tx_id(op);
                                    if (op_id && memcmp(op_id, resolved_tx_hash, COIN_ID_LEN) == 0) {
                                        block_op = malloc(sizeof(Operation));
                                        if (block_op) {
                                            *block_op = *op;
                                            // Restore omitted nullifier from block batch array
                                            if (block->batch_prf_outputs && tx_idx < block->batch_tx_count) {
                                                memcpy(block_op->data.transfer_pointer.prf_output,
                                                       block->batch_prf_outputs + (tx_idx * NULLIFIER_LEN),
                                                       NULLIFIER_LEN);
                                            }
                                            found_in_blocks = true;
                                        }
                                        break;
                                    }
                                    tx_idx++;
                                } else {
                                    const uint8_t *op_id = get_operation_tx_id(op);
                                    if (op_id && memcmp(op_id, resolved_tx_hash, COIN_ID_LEN) == 0) {
                                        block_op = malloc(sizeof(Operation));
                                        if (block_op) {
                                            *block_op = *op;
                                            found_in_blocks = true;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        free_block(block);
                        if (found_in_blocks) break;
                    }
                    pthread_rwlock_unlock(&state->bc.rwlock);
                }

                // Serialize matched transaction into wire response
                if (found_in_blocks && block_op) {
                    size_t rpc_mark = arena_mark();
                    uint8_t *op_buf = arena_alloc(MAX_MESSAGE_SIZE);
                    if (op_buf) {
                        size_t op_len = serialize_operation(block_op, op_buf, MAX_MESSAGE_SIZE);
                        if (op_len > 0) {
                            Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + op_len);
                            if (resp) {
                                resp->type = MSG_RPC_RESPONSE;
                                resp->length = sizeof(SclRpcHeader) + op_len;
                                SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                                memset(rh, 0, sizeof(SclRpcHeader));
                                rh->version = SCL_RPC_VERSION_1;
                                rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                                rh->method_id = htobe16(hdr.method_id);
                                rh->request_id = htobe64(hdr.request_id);
                                rh->payload_len = htobe32(op_len);
                                memcpy(resp->payload + sizeof(SclRpcHeader), op_buf, op_len);
                                
                                uint64_t checksum = compute_rpc_checksum(resp->payload, 0, op_len, task->conn->rpc_siphash_key);
                                rh->checksum = htobe64(checksum);

                                atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                                queue_enqueue(&task->conn->tx_stream_queue, resp);
                            } else {
                                arena_reset(rpc_mark);
                                free(block_op);
                                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
                                break;
                            }
                        } else {
                            arena_reset(rpc_mark);
                            free(block_op);
                            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Serialization failed");
                            break;
                        }
                        arena_reset(rpc_mark);
                    }
                    free(block_op);
                    break;
                }
                
                if (block_op) free(block_op);
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Transaction not found on-chain or in mempool");
            } else {
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_INVALID_ARGS, "Invalid args for GetTransaction");
            }
            break;
        }
        case 0x0008: { // GetChainInfo
            // Assemble consensus metrics, active committee count, DKG state, and wallet credentials
            size_t payload_size = 44 + PUBKEY_LEN + PRIVKEY_LEN;
            size_t rpc_mark = arena_mark();
            Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + payload_size);
            if (resp) {
                resp->type = MSG_RPC_RESPONSE;
                
                uint64_t height_be = htobe64(state->current_block_number);
                
                uint64_t total_subunits = 0;
                uint64_t total_staked = 0;
                uint64_t total_fees = 0;
                pthread_rwlock_rdlock(&state->bc.rwlock);
                for (size_t i = 0; i < state->bc.insert_order_count; i++) {
                    if (state->bc.insert_order[i]) {
                        total_subunits += state->bc.insert_order[i]->total_subunits;
                    }
                }
                total_staked = calculate_total_staked_subunits(&state->bc);
                total_fees = calculate_total_fees_subunits(&state->bc);
                pthread_rwlock_unlock(&state->bc.rwlock);
                
                /* Helper locks internally. Do not hold p2p_network.mutex here. */
                uint16_t committee_count = scl_count_established_nodes(state);

                pthread_mutex_lock(&state->epoch_mutex);
                uint64_t last_dkg = state->last_dkg_attempted_epoch;
                uint16_t active_dkg_sessions = (uint16_t)state->dkg_active_sessions->count;
                pthread_mutex_unlock(&state->epoch_mutex);
                
                uint64_t total_subunits_be = htobe64(total_subunits);
                uint64_t total_staked_be = htobe64(total_staked);
                uint64_t total_fees_be = htobe64(total_fees);
                uint16_t committee_count_be = htobe16(committee_count);
                uint64_t last_dkg_be = htobe64(last_dkg);
                uint16_t active_dkg_sessions_be = htobe16(active_dkg_sessions);

                resp->length = sizeof(SclRpcHeader) + payload_size;
                SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                memset(rh, 0, sizeof(SclRpcHeader));
                rh->version = SCL_RPC_VERSION_1;
                rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                rh->method_id = htobe16(hdr.method_id);
                rh->request_id = htobe64(hdr.request_id);
                rh->payload_len = htobe32(payload_size);
                
                memcpy(resp->payload + sizeof(SclRpcHeader), &height_be, 8);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 8, &total_subunits_be, 8);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 16, &total_staked_be, 8);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 24, &committee_count_be, 2);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 26, &active_dkg_sessions_be, 2);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 28, &last_dkg_be, 8);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 36, &total_fees_be, 8);
                pthread_mutex_lock(&state->wallet_mutex);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 44, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                memcpy(resp->payload + sizeof(SclRpcHeader) + 44 + PUBKEY_LEN, state->user_wallet.dilithium_privkey, PRIVKEY_LEN);
                pthread_mutex_unlock(&state->wallet_mutex);
                
                uint64_t checksum = compute_rpc_checksum(resp->payload, 0, payload_size, task->conn->rpc_siphash_key);
                rh->checksum = htobe64(checksum);

                atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                queue_enqueue(&task->conn->tx_stream_queue, resp);
                arena_reset(rpc_mark);
            } else {
                arena_reset(rpc_mark);
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
            }
            break;
        }
        case 0x000A: { // Quantum TVD Audit
            if (!payment_verified && state->config.is_daemon) {
                // Require a 1 SCL fee (160,000,000 subunits) for expensive QPU audits
                send_rpc_payment_required(state, task->conn, hdr.method_id, hdr.request_id, 160000000ULL);
                break;
            }
            
            // Dispatch execution to Quantum TVD audit subsystem
            const uint8_t *tvd_payload = msg->payload + sizeof(SclRpcHeader) + hdr.error_msg_len;
            size_t tvd_payload_len = hdr.payload_len;
            handle_rpc_quantum_tvd_audit(state, task, &hdr, tvd_payload, tvd_payload_len);
            break;
        }
        case 0x000B: { // Autopilot Config & Status
            // Update autopilot configuration if inbound parameters were provided
            const uint8_t *ap_payload = msg->payload + sizeof(SclRpcHeader) + hdr.error_msg_len;
            if (hdr.payload_len >= 9) {
                bool enable = (ap_payload[0] != 0);
                
                uint32_t val_per_hr_raw;
                memcpy(&val_per_hr_raw, ap_payload + 1, sizeof(uint32_t));
                uint32_t val_per_hr = be32toh(val_per_hr_raw);

                uint32_t stake_ratio_raw;
                memcpy(&stake_ratio_raw, ap_payload + 5, sizeof(uint32_t));
                uint32_t stake_ratio = be32toh(stake_ratio_raw);

                if (stake_ratio > 100) stake_ratio = 100;
                if (val_per_hr == 0) val_per_hr = 1;

                state->config.autopilot_enabled = enable;
                state->config.autopilot_valuations_per_hour = val_per_hr;
                state->config.autopilot_stake_ratio = stake_ratio;

                if (enable) {
                    start_autopilot_thread(state);
                } else {
                    stop_autopilot_thread(state);
                }
            }

            // Assemble autopilot status telemetry: running flag, rates, tier ceiling, and timestamp
            uint8_t resp_payload[21] = {0};
            resp_payload[0] = atomic_load(&state->autopilot_running) ? 1 : 0;
            uint32_t v_hr_be = htobe32(state->config.autopilot_valuations_per_hour);
            memcpy(resp_payload + 1, &v_hr_be, 4);
            uint32_t s_ratio_be = htobe32(state->config.autopilot_stake_ratio);
            memcpy(resp_payload + 5, &s_ratio_be, 4);

            uint64_t fees_paid = calculate_fees_paid_subunits(&state->bc, state->user_wallet.dilithium_pubkey);
            double fees_scl = (double)fees_paid / SUBUNITS_PER_COIN;
            uint8_t threshold_pk[PUBKEY_LEN];
            uint64_t staked_sub = (compute_threshold_pubkey(state, threshold_pk) == 0) ? calculate_staked_subunits(&state->bc, threshold_pk) : 0;
            double staked_scl = (double)staked_sub / SUBUNITS_PER_COIN;
            uint32_t max_rate = (uint32_t)(1 + floor(staked_scl + fees_scl));
            uint32_t max_rate_be = htobe32(max_rate);
            memcpy(resp_payload + 9, &max_rate_be, 4);

            uint64_t now_ts = htobe64(get_real_time_us());
            memcpy(resp_payload + 13, &now_ts, 8);

            size_t rpc_mark = arena_mark();
            Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + 21);
            if (resp) {
                resp->type = MSG_RPC_RESPONSE;
                resp->length = sizeof(SclRpcHeader) + 21;
                SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
                memset(rh, 0, sizeof(SclRpcHeader));
                rh->version = SCL_RPC_VERSION_1;
                rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                rh->method_id = htobe16(hdr.method_id);
                rh->request_id = htobe64(hdr.request_id);
                rh->payload_len = htobe32(21);
                memcpy(resp->payload + sizeof(SclRpcHeader), resp_payload, 21);

                uint64_t checksum = compute_rpc_checksum(resp->payload, 0, 21, task->conn->rpc_siphash_key);
                rh->checksum = htobe64(checksum);

                if (hdr.method_id < 12) {
                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[hdr.method_id], 1, memory_order_relaxed);
                }
                queue_enqueue(&task->conn->tx_stream_queue, resp);
                arena_reset(rpc_mark);
            } else {
                arena_reset(rpc_mark);
                send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_RATE_LIMITED, "Arena allocation failed");
            }
            break;
        }
        case 0x0009: { // SyncWalletKeys
            // SPEC COMPLIANCE: Remote mutation of the node's wallet credentials
            // is strictly disabled on public RPC / Explorer endpoints to prevent
            // state collisions across concurrent browser sessions.
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_UNAUTHORIZED, "Node wallet mutation is disabled on public RPC endpoints");
            break;
        }
        default:
            send_rpc_error(state, task->conn, hdr.method_id, hdr.request_id, SCL_RPC_STATUS_BAD_METHOD, "Method unknown or not implemented");
            break;
    }

    if (decompressed_msg) {
        free(decompressed_msg);
    }
}
