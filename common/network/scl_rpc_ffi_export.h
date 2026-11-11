/**
 * @file common/network/scl_rpc_ffi_export.h
 * @brief Satocialist Protocol: Foreign Function Interface (FFI) & C-ABI Binary RPC Exports
 *
 * @details
 * Declares the stable C-ABI export symbols and convenience framing constructors for the native L5 RPC engine.
 * Exported across shared library boundaries (`libscl_rpc.so`, `libscl_rpc.dylib`) and cross-compiled into
 * WebAssembly bytecode (`libscl_rpc.wasm`) via Emscripten for browser UI integration.
 *
 * Key functional capabilities include:
 * 1. Opaque frame builder lifecycle with dynamic growth, Dilithium5 digital signatures, and wire serialization.
 * 2. Opaque frame parser with wire boundary decoding, error extraction, and status inspection.
 * 3. Transparent LZ4 payload decompression with 8 MiB decompression bomb protection.
 * 4. SipHash-2-4 checksum verification against session keys.
 * 5. Explorer-optimized convenience frame constructors for balance, tx, block, and chain queries.
 * 6. Micropayment challenge extraction and payment receipt injection for monetized methods.
 *
 * @section memory_concurrency Concurrency & Memory Ownership Constraints
 * - Thread-Affinity Requirement: Opaque `SclRpcBuilder` and `SclRpcParser` handles are NOT thread-safe.
 *   Each handle must be created, modified, queried, and destroyed from the single host thread that instantiated it.
 * - Lifetime Constraints: The pointer returned by @ref scl_rpc_parser_get_payload_ref is borrowed from the
 *   parser's internal decompressed buffer. It is immediately invalidated upon calling @ref scl_rpc_parser_destroy.
 * - Decompression Bomb Defense: Automatic LZ4 decompression rejects payloads exceeding @ref MAX_MESSAGE_SIZE (8 MiB).
 */

#ifndef SCL_RPC_FFI_EXPORT_H
#define SCL_RPC_FFI_EXPORT_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: OPAQUE BUILDER & PARSER CONTEXT HANDLES                           */
/* ============================================================================ */

/** @brief Opaque handle to an active RPC frame builder context. */
typedef void* SclRpcBuilder;
/** @brief Opaque handle to an active RPC frame parser context. */
typedef void* SclRpcParser;

/* ============================================================================ */
/* SECTION 2: FRAME BUILDER INTERFACES                                          */
/* ============================================================================ */

/**
 * @brief Allocates and initializes an opaque RPC frame builder context.
 *
 * @param[in] version Protocol wire version (must be @ref SCL_RPC_VERSION_1 = 0x01).
 * @param[in] method_id Target method identifier opcode (e.g., 0x0001 for GetBalance).
 * @param[in] request_id 64-bit monotonic tracking ID (timestamp << 16 | salt).
 * @return Opaque SclRpcBuilder pointer; NULL on allocation failure.
 *
 * @post Allocates heap memory for internal builder state; caller must free via @ref scl_rpc_builder_destroy.
 * @complexity Time: O(1), Space: O(1) initial heap buffer.
 */
SclRpcBuilder scl_rpc_builder_create(uint8_t version, uint16_t method_id, uint64_t request_id);

/**
 * @brief Configures operational flags on an RPC frame builder (e.g., SIGNED, PAGINATED, COMPRESSED).
 *
 * @param[in,out] builder Opaque builder handle.
 * @param[in] flags Bitmask of flags (`SCL_RPC_FLAG_SIGNED`, `SCL_RPC_FLAG_PAGINATED`, `SCL_RPC_FLAG_COMPRESSED`).
 *
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_builder_set_flags(SclRpcBuilder builder, uint8_t flags);

/**
 * @brief Sets the pagination cursor or block height parameter on an RPC frame builder.
 *
 * @param[in,out] builder Opaque builder handle.
 * @param[in] cursor 32-bit big-endian pagination offset or block height.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_builder_set_cursor(SclRpcBuilder builder, uint32_t cursor);

/**
 * @brief Appends a public verification key argument to the builder's payload buffer.
 *
 * @param[in,out] builder Opaque builder handle.
 * @param[in] pubkey Binary public key buffer.
 * @param[in] len Length of public key in bytes (typically 2,592 bytes for Dilithium5).
 * @return 0 on success; -1 on overflow or reallocation error.
 *
 * @complexity Time: O(len), Space: O(len) dynamic buffer expansion.
 */
int scl_rpc_builder_append_pubkey(SclRpcBuilder builder, const uint8_t* pubkey, size_t len);

/**
 * @brief Appends generic argument bytes to the builder's internal payload buffer.
 *
 * @param[in,out] builder Opaque builder handle.
 * @param[in] payload Pointer to argument byte slice.
 * @param[in] len Length of argument slice in bytes.
 * @return 0 on success; -1 on memory exhaustion.
 *
 * @complexity Time: O(len), Space: O(len).
 */
int scl_rpc_builder_append_args(SclRpcBuilder builder, const uint8_t* payload, size_t len);

/**
 * @brief Signs the pre-digest over `(Header[0..23] || args)` using an ML-DSA-87 private key.
 *
 * @details
 * Evaluates the detached Dilithium5 signature over the preliminary header and payload fields,
 * prepends the resulting 4,595-byte signature to the payload, and sets the `SCL_RPC_FLAG_SIGNED` flag.
 *
 * @param[in,out] builder Opaque builder handle.
 * @param[in] dilithium_privkey 4,864-byte Dilithium5 private signing key.
 * @return 0 on success; -1 on signature generation failure.
 *
 * @complexity Time: O(Dilithium5_sign), Space: O(DILITHIUM_SIGNATURE_LEN).
 */
int scl_rpc_builder_sign(SclRpcBuilder builder, const uint8_t* dilithium_privkey);

/**
 * @brief Finalizes the binary wire frame into a contiguous caller-allocated buffer.
 *
 * @details
 * Formats header fields in network byte order (Big-Endian), writes the packed 32-byte header,
 * appends the payload, and outputs the total serialized wire length.
 *
 * @param[in] builder Opaque builder handle.
 * @param[out] out_buffer Destination buffer receiving the complete wire frame.
 * @param[in] max_len Maximum writable capacity of `out_buffer`.
 * @param[out] serialized_len Destination receiving the exact written wire byte count.
 * @return 0 on success; -1 if `max_len` is insufficient.
 *
 * @complexity Time: O(payload_len), Space: O(1) auxiliary.
 */
int scl_rpc_builder_finalize(SclRpcBuilder builder, uint8_t* out_buffer, size_t max_len, size_t* serialized_len);

/**
 * @brief Destroys an RPC builder context and releases all allocated payload memory.
 *
 * @param[in,out] builder Opaque builder handle to deallocate (safe if NULL).
 *
 * @post Internal buffer freed; builder pointer invalidated.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_builder_destroy(SclRpcBuilder builder);

/* ============================================================================ */
/* SECTION 3: FRAME PARSER INTERFACES                                           */
/* ============================================================================ */

/**
 * @brief Instantiates a parser context and performs immediate wire header decoding.
 *
 * @details
 * Validates wire length against minimum header size (32 bytes), extracts status code,
 * verifies payload length bounds against integer overflow, and copies payload bytes.
 *
 * @param[in] wire_bytes Raw binary wire frame.
 * @param[in] len Length of wire frame in bytes.
 * @param[out] out_status Destination receiving extracted status code (or error indicator).
 * @return Opaque SclRpcParser pointer; NULL on malformed frame or allocation failure.
 *
 * @post Allocates heap memory for parser state; caller must free via @ref scl_rpc_parser_destroy.
 * @complexity Time: O(payload_len), Space: O(payload_len) heap copy.
 */
SclRpcParser scl_rpc_parser_create(const uint8_t* wire_bytes, size_t len, int* out_status);

/**
 * @brief Extracts the protocol version from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Protocol version byte (e.g., 0x01).
 */
uint8_t scl_rpc_parser_get_version(SclRpcParser parser);

/**
 * @brief Extracts the operational flags bitmask from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Flags bitmask (`SCL_RPC_FLAG_SIGNED`, `SCL_RPC_FLAG_PAGINATED`, `SCL_RPC_FLAG_COMPRESSED`).
 */
uint8_t scl_rpc_parser_get_flags(SclRpcParser parser);

/**
 * @brief Extracts the execution status code from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Big-endian status code (e.g., @ref SCL_RPC_STATUS_OK).
 */
uint16_t scl_rpc_parser_get_status(SclRpcParser parser);

/**
 * @brief Extracts the method opcode identifier from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Method opcode (0x0000..0x000B).
 */
uint16_t scl_rpc_parser_get_method_id(SclRpcParser parser);

/**
 * @brief Extracts the 64-bit request tracking identifier from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return 64-bit request ID.
 */
uint64_t scl_rpc_parser_get_request_id(SclRpcParser parser);

/**
 * @brief Extracts the pagination cursor or block height parameter from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return 32-bit cursor offset or block height.
 */
uint32_t scl_rpc_parser_get_cursor(SclRpcParser parser);

/**
 * @brief Copies the trailing null-terminated ASCII error string from a parsed frame into a buffer.
 *
 * @param[in] parser Opaque parser handle.
 * @param[out] out_str Destination string buffer.
 * @param[in] max_len Maximum bytes writable into `out_str` (including null-terminator).
 * @return 0 on success; -1 if no error string is present or parameters are invalid.
 *
 * @complexity Time: O(error_len), Space: O(1).
 */
int scl_rpc_parser_get_error(SclRpcParser parser, char* out_str, size_t max_len);

/**
 * @brief Extracts a borrowed pointer reference to the unpacked/decompressed payload block.
 *
 * @details
 * If `SCL_RPC_FLAG_COMPRESSED` is set, transparently executes LZ4 decompression into a thread-local
 * staging buffer, enforcing strict decompression bomb protection against exceeding @ref MAX_MESSAGE_SIZE (8 MiB).
 *
 * @param[in] parser Opaque parser handle.
 * @param[out] out_ptr Destination receiving borrowed pointer to payload bytes.
 * @param[out] out_len Destination receiving exact byte length of payload.
 * @return 0 on success; -1 on decompression failure or size limit breach.
 *
 * @warning The returned pointer's memory is borrowed and invalidated immediately when
 *          @ref scl_rpc_parser_destroy is called on `parser`.
 * @complexity Time: O(payload_len) or O(decompression_time), Space: O(1) borrowed or staging buffer.
 */
int scl_rpc_parser_get_payload_ref(SclRpcParser parser, const uint8_t** out_ptr, size_t* out_len);

/**
 * @brief Destroys a parser context and releases its allocated memory.
 *
 * @param[in,out] parser Opaque parser handle to deallocate (safe if NULL).
 *
 * @post Internal buffer freed; parser handle invalidated.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_parser_destroy(SclRpcParser parser);

/**
 * @brief Verifies the 64-bit SipHash-2-4 checksum of a raw wire frame against an expected session key.
 *
 * @param[in] wire_bytes Raw binary wire frame buffer.
 * @param[in] len Total length of wire frame in bytes.
 * @param[in] rpc_siphash_key 16-byte session SipHash key.
 * @return 0 on success (checksum matches or frame is unchecksummed loopback);
 *         -2 on checksum mismatch; -1 on parameter or length error.
 *
 * @complexity Time: O(len), Space: O(1).
 */
int scl_rpc_verify_checksum(const uint8_t* wire_bytes, size_t len, const uint8_t rpc_siphash_key[16]);

/* ============================================================================ */
/* SECTION 4: CONVENIENCE FRAME BUILDERS (EXPLORER & CLIENT OPTIMIZED)          */
/* ============================================================================ */

/**
 * @brief Constructs a complete wire frame for account balance queries (Method 0x0001).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] target_pubkey 2,592-byte Dilithium5 public key to audit.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_balance_query(uint64_t request_id, const uint8_t* target_pubkey, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame querying recent unconfirmed and confirmed transactions (Method 0x0006).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] cursor Pagination start index.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_recent_txs(uint64_t request_id, uint32_t cursor, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame querying a transaction by its 32-byte hash (Method 0x0007).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] tx_hash 32-byte transaction hash.
 * @param[in] hash_len Length of hash (must be 32).
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_get_tx(uint64_t request_id, const uint8_t* tx_hash, size_t hash_len, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame querying high-level chain status and validator metrics (Method 0x0008).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_chain_info(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame querying economic stage and total reward metrics (Method 0x0005).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_valuations_query(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame querying the 10x10 Game Audit circular matrix (Method 0x0004).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_audit_query(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame querying a specific block by its chain height (Method 0x0002).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] height Target block height.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_block_query(uint64_t request_id, uint32_t height, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame for dispatching a Quantum TVD Audit request (Method 0x000A).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] shots Measurement shot count budget (1..100,000).
 * @param[in] beacon_seed Optional 32-byte DKG beacon seed (NULL defaults to zero seed).
 * @param[in] circuit_bytes Optional OpenQASM circuit byte stream.
 * @param[in] circuit_len Byte length of circuit stream.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(circuit_len), Space: O(1).
 */
int scl_rpc_frame_quantum_tvd_audit(uint64_t request_id, uint32_t shots, const uint8_t* beacon_seed, const uint8_t* circuit_bytes, size_t circuit_len, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame for dispatching a Drift Certificate Audit request (Method 0x000D).
 *
 * @details
 * Enterprise QPU auditing variant of @ref scl_rpc_frame_quantum_tvd_audit: the client submits a
 * hardware-measured outcome histogram together with the shot budget, beacon seed, and an optional
 * OpenQASM reference circuit. The auditor evaluates the Total Variation Distance between the
 * measured QPU distribution and the ideal statevector distribution, seals the metric into a
 * BDLOP-committed, ML-DSA-87-signed QuantumDriftCertificate, and returns it for on-chain
 * application via an OP_APPLY_DRIFT_CERT transaction.
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] shots Measurement shot count budget (1..100,000).
 * @param[in] beacon_seed Optional 32-byte DKG beacon seed (NULL defaults to zero seed).
 * @param[in] histogram Client-measured QPU outcome histogram (exactly QUANTUM_STATE_DIM = 128 bins, fixed-width).
 * @param[in] circuit_bytes Optional OpenQASM circuit byte stream.
 * @param[in] circuit_len Byte length of circuit stream.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(QUANTUM_STATE_DIM + circuit_len), Space: O(1).
 */
int scl_rpc_frame_drift_cert_audit(uint64_t request_id, uint32_t shots, const uint8_t* beacon_seed, const uint32_t* histogram, const uint8_t* circuit_bytes, size_t circuit_len, uint8_t* out_frame, size_t max_len, size_t* out_len);

/**
 * @brief Constructs a wire frame for configuring or querying node Auto-Pilot automation (Method 0x000B).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] enable 1 to enable, 0 to disable, -1 to query status without altering.
 * @param[in] val_per_hr Automated valuation submission rate per hour.
 * @param[in] stake_ratio Target portfolio percentage ratio maintained in staked status [0..100].
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_rpc_frame_autopilot(uint64_t request_id, int enable, uint32_t val_per_hr, uint32_t stake_ratio, uint8_t* out_frame, size_t max_len, size_t* out_len);

/* ============================================================================ */
/* SECTION 5: MICROPAYMENT CHALLENGE & RECEIPT EXTENSIONS                       */
/* ============================================================================ */

/**
 * @brief Extracts payment challenge parameters from an SclRpcParser handle.
 * @param[in] parser Opaque parser handle.
 * @param[out] out_challenge Destination receiving the unpacked challenge payload.
 * @return 0 on success; -1 if status is not SCL_RPC_STATUS_PAYMENT_REQUIRED.
 */
int scl_rpc_parser_get_payment_challenge(SclRpcParser parser, SclRpcPaymentChallenge *out_challenge);

/**
 * @brief Prepends an SclRpcPaymentReceipt structure to an active frame builder context.
 * @param[in,out] builder Opaque builder handle.
 * @param[in] payment_type 0x01 (Transfer) or 0x02 (Centinel Redemption).
 * @param[in] tx_id 32-byte Transaction ID or Nullifier.
 * @param[in] challenge_hash 32-byte SHA-256 challenge_hash of the SCL402 challenge being settled.
 * @param[in] rate_lock_id Ephemeral price lock ID matching the challenge (informational echo).
 * @return 0 on success; -1 on memory expansion failure.
 */
int scl_rpc_builder_set_payment_receipt(SclRpcBuilder builder, uint8_t payment_type, const uint8_t *tx_id, const uint8_t *challenge_hash, uint64_t rate_lock_id);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SCL_RPC_FFI_EXPORT_H
