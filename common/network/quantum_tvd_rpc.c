/**
 * @file common/network/quantum_tvd_rpc.c
 * @brief Satocialist Protocol: Quantum TVD RPC Dispatch Handler Implementation (Method 0x000A)
 *
 * @details
 * Implements the server-side RPC execution handler for Method 0x000A (`QuantumTvdAudit`).
 * Parses incoming client parameters (measurement shot budget, beacon seed, optional OpenQASM circuit bytes),
 * orchestrates the QPU simulation and statistical Total Variation Distance (TVD) kernel,
 * generates an authenticated, BDLOP-committed @ref QuantumDriftCertificate, and transmits
 * the formatted response frame back to the client over the reliable connection stream.
 *
 * @section protocol_invariants System Invariants
 * - Shot Budget Bounds: The requested shot count `shots` is strictly validated: `0 < shots <= 100,000`.
 *   Requests outside these bounds are rejected without invoking simulation routines.
 * - Minimum Payload Dimensionality: Input payload must provide at least 36 bytes
 *   (4-byte big-endian shots + 32-byte beacon seed). Trailing bytes are treated as OpenQASM circuit data.
 * - Thread-Local Memory Isolation: Outgoing response allocations utilize the thread-local arena
 *   (`arena_alloc`), resetting linear offsets upon completion to eliminate dynamic heap fragmentation.
 * - Network Byte Order Invariance: Multi-byte fields (`status_code`, `method_id`, `request_id`,
 *   `payload_len`, `checksum`) are strictly formatted in Big-Endian network byte order.
 * - Checksum Authentication: Every response message frame is cryptographically authenticated
 *   via a 64-bit SipHash-2-4 digest keyed by the KEM session shared secret.
 *
 * @section thread_safety Thread Safety & Concurrency
 * - `handle_rpc_quantum_tvd_audit` is called concurrently across RPC worker threads (`MAX_RPC_WORKERS`).
 * - Internal certificate generation acquires `state->game_state.mutex` and `state->wallet_mutex`
 *   only when reading the beacon state or evaluating Dilithium5 signatures.
 * - Metrics counters are incremented using C11 atomic primitives (`memory_order_relaxed`).
 */

#include "types.h"
#include "protocol.h"
#include "network.h"
#include "crypto.h"
#include "utils.h"
#include "queue.h"
#include "quantum_tvd.h"
#include "scl_rpc_ffi_export.h"

/** @brief Method opcode identifier for Quantum Total Variation Distance (TVD) auditing. */
#define SCL_RPC_METHOD_QUANTUM_TVD_AUDIT 0x000A

/* ============================================================================ */
/* SECTION 1: RPC DISPATCH & RESPONSE FRAMING IMPLEMENTATION                    */
/* ============================================================================ */

/**
 * @brief Decodes an incoming Quantum TVD Audit RPC frame, executes the audit, and returns results.
 *
 * @details
 * Operational steps:
 * 1. Validates input pointers and confirms `payload_len >= 36` bytes.
 * 2. Unpacks 32-bit big-endian shot budget and verifies boundary conditions (`shots in [1, 100000]`).
 * 3. Extracts the 32-byte epoch randomness beacon seed and optional trailing OpenQASM circuit bytes.
 * 4. Invokes @ref quantum_tvd_audit_generate_certificate to evaluate ideal vs. noisy distributions,
 *    derive the fixed-point TVD metric, bind a homomorphic BDLOP lattice commitment, and sign
 *    the certificate with the validator's ML-DSA-87 (Dilithium5) private key.
 * 5. Allocates a response Message container from the thread-local memory arena.
 * 6. Formats the response header (Version 1, Status OK, Method 0x000A, Request ID), copies
 *    the serialized certificate, computes the 64-bit SipHash-2-4 checksum, and enqueues to the connection.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in,out] task Dispatch context wrapping the inbound Message and calling connection handle.
 * @param[in] hdr Parsed request header containing request ID and operational flags.
 * @param[in] payload Pointer to beginning of RPC arguments payload slice.
 * @param[in] payload_len Total byte length of argument slice.
 *
 * @pre `state`, `task`, `hdr`, and `payload` must be non-NULL.
 * @post Response frame enqueued to `task->conn->tx_stream_queue`; RPC metrics counters updated.
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(shots + circuit_len), Space: O(sizeof(QuantumDriftCertificate)) arena allocation.
 */
void handle_rpc_quantum_tvd_audit(State *state, RpcTask *task, const SclRpcHeader *hdr, const uint8_t *payload, size_t payload_len) {
    // Step 1: Validate input parameters and verify minimum payload dimensionality
    if (!state || !task || !hdr || !payload) return;

    // Minimum payload requirement: 4-byte shots + 32-byte beacon seed = 36 bytes
    if (payload_len < 36) {
        atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[SCL_RPC_METHOD_QUANTUM_TVD_AUDIT], 1, memory_order_relaxed);
        return;
    }

    // Decode 32-bit big-endian shot budget and enforce protocol bounds (using memcpy for unaligned safety)
    uint32_t shots_raw;
    memcpy(&shots_raw, payload, sizeof(uint32_t));
    uint32_t shots = be32toh(shots_raw);
    if (shots == 0 || shots > 100000) {
        atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[SCL_RPC_METHOD_QUANTUM_TVD_AUDIT], 1, memory_order_relaxed);
        return;
    }

    // Step 2: Extract 32-byte epoch beacon seed and optional trailing OpenQASM circuit bytes
    const uint8_t *beacon_seed = payload + 4;
    const uint8_t *circuit_bytes = (payload_len > 36) ? (payload + 36) : NULL;
    size_t circuit_len = (payload_len > 36) ? (payload_len - 36) : 0;

    // Step 3: Execute quantum TVD audit and generate authenticated BDLOP drift certificate
    QuantumDriftCertificate cert;
    int res = quantum_tvd_audit_generate_certificate(state, circuit_bytes, circuit_len, NULL, shots, beacon_seed, &cert);
    if (res != 0) {
        atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[SCL_RPC_METHOD_QUANTUM_TVD_AUDIT], 1, memory_order_relaxed);
        return;
    }

    // Step 4: Record success metrics and compute response framing dimensions
    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[SCL_RPC_METHOD_QUANTUM_TVD_AUDIT], 1, memory_order_relaxed);

    size_t resp_payload_len = sizeof(QuantumDriftCertificate);
    size_t total_msg_len = sizeof(SclRpcHeader) + resp_payload_len;

    // Step 5: Allocate response container from thread-local memory arena to eliminate heap fragmentation
    size_t mark = arena_mark();
    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + total_msg_len);
    if (!resp) {
        arena_reset(mark);
        return;
    }

    resp->type = MSG_RPC_RESPONSE;
    resp->length = (uint32_t)total_msg_len;

    // Step 6: Format SclRpcHeader in big-endian network byte order
    SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
    memset(rh, 0, sizeof(SclRpcHeader));
    rh->version = SCL_RPC_VERSION_1;
    rh->status_code = htobe16(SCL_RPC_STATUS_OK);
    rh->method_id = htobe16(SCL_RPC_METHOD_QUANTUM_TVD_AUDIT);
    rh->request_id = htobe64(hdr->request_id);
    rh->payload_len = htobe32((uint32_t)resp_payload_len);

    // Step 7: Serialize the certificate body immediately after the 32-byte header
    memcpy(resp->payload + sizeof(SclRpcHeader), &cert, sizeof(QuantumDriftCertificate));

    // Step 8: Compute SipHash-2-4 checksum, enqueue to connection stream, and release arena mark
    if (task->conn) {
        uint64_t checksum = compute_rpc_checksum(resp->payload, 0, (uint32_t)resp_payload_len, task->conn->rpc_siphash_key);
        rh->checksum = htobe64(checksum);
        // queue_enqueue deep-copies into the egress queue; arena allocation is safe to reset
        queue_enqueue(&task->conn->tx_stream_queue, resp);
    }
    arena_reset(mark);
}

/* ============================================================================
 * SECTION 2: ENTERPRISE DRIFT CERTIFICATE HISTOGRAM AUDIT (METHOD 0x000D)
 * ============================================================================ */

/** @brief Method opcode identifier for enterprise drift certificate histogram audits. */
#define SCL_RPC_METHOD_DRIFT_CERT_AUDIT 0x000D

/** @brief Fixed Hilbert-space dimensionality of the 7-qubit audit register (2^7). */
#define DRIFT_CERT_HISTOGRAM_DIM 128

/**
 * @brief Emits a framed SCL_RPC_STATUS_INVALID_ARGS error response for a drift
 *        certificate audit (mirrors rpc.c send_rpc_error, which is file-static).
 *
 * @details Validation failures previously only bumped the error metric and
 *          returned, leaving the client hanging on a request that would never
 *          be answered. This helper always answers with the exact reason.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in,out] task Dispatch context wrapping the calling connection handle.
 * @param[in] hdr Parsed request header carrying the request ID.
 * @param[in] err_msg Human-readable rejection reason (clamped to 256 bytes).
 */
static void drift_cert_send_error(State *state, RpcTask *task, const SclRpcHeader *hdr, const char *err_msg) {
    if (!state || !task || !task->conn || !hdr) return;
    size_t err_len = err_msg ? strlen(err_msg) : 0;
    if (err_len > 256) err_len = 256;

    size_t mark = arena_mark();
    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader) + err_len);
    if (!resp) {
        arena_reset(mark);
        return;
    }

    resp->type = MSG_RPC_RESPONSE;
    resp->length = (uint32_t)(sizeof(SclRpcHeader) + err_len);

    SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
    memset(rh, 0, sizeof(SclRpcHeader));
    rh->version = SCL_RPC_VERSION_1;
    rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
    rh->method_id = htobe16(SCL_RPC_METHOD_DRIFT_CERT_AUDIT);
    rh->request_id = htobe64(hdr->request_id);
    rh->error_msg_len = htobe16((uint16_t)err_len);
    if (err_len > 0 && err_msg) {
        memcpy(resp->payload + sizeof(SclRpcHeader), err_msg, err_len);
    }

    uint64_t checksum = compute_rpc_checksum(resp->payload, (uint16_t)err_len, 0, task->conn->rpc_siphash_key);
    rh->checksum = htobe64(checksum);

    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[SCL_RPC_METHOD_DRIFT_CERT_AUDIT], 1, memory_order_relaxed);
    queue_enqueue(&task->conn->tx_stream_queue, resp);
    arena_reset(mark);
}

/**
 * @brief Decodes a client-supplied QPU measurement histogram, executes the drift audit, and returns results.
 *
 * @details
 * Inbound payload layout (all multi-byte fields Big-Endian):
 * - Bytes 00..03: `shots` measurement budget (u32 BE, bounds-checked against [1, 100000]).
 * - Bytes 04..35: 32-byte DKG epoch beacon seed.
 * - Bytes 36..37: `hist_dim` histogram dimensionality (u16 BE, must equal 128).
 * - Bytes 38..549: `hist_dim` x 4-byte Big-Endian per-basis-state measurement counts.
 * - Bytes 550..N:  Optional trailing OpenQASM circuit bytes (audited against the qsim baseline).
 *
 * Statistical conservation invariant: sum(histogram) must equal `shots` exactly;
 * violations are rejected without invoking the TVD kernels. The histogram is passed
 * straight to @ref quantum_tvd_audit_generate_certificate as the physical QPU sample,
 * so the engine's Kraus noise simulation fallback is bypassed and the certificate
 * attests the client's actual hardware outcomes.
 */
void handle_rpc_drift_cert_audit(State *state, RpcTask *task, const SclRpcHeader *hdr, const uint8_t *payload, size_t payload_len) {
    // Step 1: Validate input pointers.
    // The trio (state, task, hdr) is required to emit an error response; if any is
    // missing we cannot describe the rejection, so this must remain a silent return.
    if (!state || !task || !hdr) return;
    if (!payload) {
        drift_cert_send_error(state, task, hdr, "NULL payload pointer received for drift certificate audit");
        return;
    }

    /* Minimum payload: 4-byte shots + 32-byte beacon + 2-byte histogram dimension = 38 bytes */
    if (payload_len < 38) {
        drift_cert_send_error(state, task, hdr, "Drift audit payload too short: expected 4-byte shots + 32-byte beacon + 2-byte histogram dimension (38 bytes minimum)");
        return;
    }

    // Step 2: Decode 32-bit big-endian shot budget and enforce protocol bounds
    uint32_t shots_raw;
    memcpy(&shots_raw, payload, sizeof(uint32_t));
    uint32_t shots = be32toh(shots_raw);
    if (shots == 0 || shots > 100000) {
        drift_cert_send_error(state, task, hdr, "Shot budget must be between 1 and 100,000");
        return;
    }

    const uint8_t *beacon_seed = payload + 4;

    // Step 3: Decode histogram dimensionality and enforce fixed 7-qubit register width
    uint16_t hist_dim_raw;
    memcpy(&hist_dim_raw, payload + 36, sizeof(uint16_t));
    uint16_t hist_dim = be16toh(hist_dim_raw);
    if (hist_dim != DRIFT_CERT_HISTOGRAM_DIM) {
        drift_cert_send_error(state, task, hdr, "Histogram dimension must be exactly 128 basis states (7-qubit register)");
        return;
    }

    if (payload_len < 38 + (size_t)hist_dim * 4) {
        drift_cert_send_error(state, task, hdr, "Histogram truncated: expected 128 x 4-byte big-endian counts (512 bytes)");
        return;
    }

    // Step 4: Decode 128 Big-Endian basis-state counts and enforce shot conservation
    uint32_t histogram[DRIFT_CERT_HISTOGRAM_DIM];
    uint64_t histogram_total = 0;
    for (uint16_t i = 0; i < hist_dim; i++) {
        uint32_t count_raw;
        memcpy(&count_raw, payload + 38 + (size_t)i * 4, sizeof(uint32_t));
        histogram[i] = be32toh(count_raw);
        if (histogram[i] > shots) {
            drift_cert_send_error(state, task, hdr, "Histogram bin exceeds the shot budget (counts must be non-negative and <= shots)");
            return;
        }
        histogram_total += histogram[i];
    }
    if (histogram_total != shots) {
        char conservation_err[128];
        snprintf(conservation_err, sizeof(conservation_err),
                 "Shot conservation violated: histogram totals %llu but the budget is %u",
                 (unsigned long long)histogram_total, shots);
        drift_cert_send_error(state, task, hdr, conservation_err);
        return;
    }

    // Step 5: Extract optional trailing OpenQASM circuit bytes
    size_t histogram_bytes = (size_t)hist_dim * 4;
    const uint8_t *circuit_bytes = (payload_len > 38 + histogram_bytes) ? (payload + 38 + histogram_bytes) : NULL;
    size_t circuit_len = (payload_len > 38 + histogram_bytes) ? (payload_len - 38 - histogram_bytes) : 0;

    // Step 6: Execute drift audit against the client's physical QPU histogram
    QuantumDriftCertificate cert;
    int res = quantum_tvd_audit_generate_certificate(state, circuit_bytes, circuit_len, histogram, shots, beacon_seed, &cert);
    if (res != 0) {
        drift_cert_send_error(state, task, hdr, "Drift audit engine failed to generate the certificate");
        return;
    }

    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[SCL_RPC_METHOD_DRIFT_CERT_AUDIT], 1, memory_order_relaxed);

    size_t resp_payload_len = sizeof(QuantumDriftCertificate);
    size_t total_msg_len = sizeof(SclRpcHeader) + resp_payload_len;

    size_t mark = arena_mark();
    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + total_msg_len);
    if (!resp) {
        arena_reset(mark);
        return;
    }

    resp->type = MSG_RPC_RESPONSE;
    resp->length = (uint32_t)total_msg_len;

    SclRpcHeader *rh = (SclRpcHeader *)resp->payload;
    memset(rh, 0, sizeof(SclRpcHeader));
    rh->version = SCL_RPC_VERSION_1;
    rh->status_code = htobe16(SCL_RPC_STATUS_OK);
    rh->method_id = htobe16(SCL_RPC_METHOD_DRIFT_CERT_AUDIT);
    rh->request_id = htobe64(hdr->request_id);
    rh->payload_len = htobe32((uint32_t)resp_payload_len);

    memcpy(resp->payload + sizeof(SclRpcHeader), &cert, sizeof(QuantumDriftCertificate));

    if (task->conn) {
        uint64_t checksum = compute_rpc_checksum(resp->payload, 0, (uint32_t)resp_payload_len, task->conn->rpc_siphash_key);
        rh->checksum = htobe64(checksum);
        queue_enqueue(&task->conn->tx_stream_queue, resp);
    }
    arena_reset(mark);
}
