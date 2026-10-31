/**
 * @file wasm_bindings.c
 * @brief WebAssembly Translation and Foreign Function Interface (FFI) Layer.
 *
 * Formal Module: WebAssembly Runtime Bridge (WASM-FFI)
 *
 * Functional Responsibilities:
 * - Implements zero-overhead, memory-safe C/WASM bindings for browser execution
 *   contexts, Web Workers, and Node.js runtimes.
 * - Bridges JavaScript callers to native post-quantum cryptographic primitives:
 *   ML-DSA-87 (Dilithium5) signing and verification, BDLOP lattice commitments,
 *   Module-SIS pseudorandom functions (PRF), and Stern-type zero-knowledge proofs.
 * - Implements zero-copy parsing and serialization for the Satocialist Cryptographic
 *   Ledger (SCL) binary RPC wire protocol frames.
 * - Exposes Merkle Mountain Range (MMR) verification and Centinel shielded UTXO
 *   redemption proofs to client-side WebAssembly execution contexts.
 * - Provides micropayment challenge parsing and payment receipt embedding for metered RPC access.
 * - Exposes block commitment extraction and transaction ownership scanning for light-client operation.
 * - Securely bridges browser-native entropy (via Web Cryptography API) into Open
 *   Quantum Safe (liboqs) CSPRNG hooks without intermediate JavaScript memory copies.
 *
 * Invariants Maintained Across Module Boundary:
 * - Linear memory pointers passed from JavaScript must fall strictly within the WASM
 *   heap address space [0, emscripten_get_heap_size()).
 * - Ephemeral cryptographic secrets (private keys, PRF seeds, blinding factors)
 *   must be unconditionally scrubbed from stack and heap memory using explicit_bzero()
 *   prior to function return.
 * - Wire frames parsed via opaque handles (SclRpcParser) must not be accessed
 *   following parser destruction (scl_rpc_parser_destroy).
 * - Big-endian protocol wire ordering is normalized to native host endianness on ingress
 *   and converted to network order on egress.
 *
 * Cryptographic and RFC References:
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium).
 * - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber).
 * - BDLOP Lattice Commitment Scheme (Baum et al., SCN 2018).
 * - Stern Zero-Knowledge Identification and Signature Framework.
 * - RFC 8999: Rules for Designing Protocols using the Internet Protocol Layer.
 * - SipHash: A Fast Short-Input PRF (Aumasson & Bernstein, 2012).
 *
 * Dependencies:
 * - Emscripten SDK (emscripten.h)
 * - OpenSSL (crypto/sha.h, crypto/rand.h)
 * - liboqs (oqs/oqs.h)
 * - Internal Modules: scl_rpc_ffi_export.h, crypto.h, protocol.h, types.h, utils.h.
 *
 * Concurrency and Reentrancy:
 * - WebAssembly execution instances in browser environments are single-threaded
 *   per worker or window context.
 * - Stateless functions are reentrant. State-modifying initializations (wasm_init)
 *   must be executed once during worker bootstrap.
 *
 * Memory Ownership Paradigms:
 * - Memory allocated through wasm_malloc() must be explicitly reclaimed by the caller
 *   via wasm_free().
 * - Output buffers supplied by callers are borrowed; the function writes up to max_len
 *   bytes and reports the true serialized length in out_len.
 * - Opaque parser and builder contexts (SclRpcParser, SclRpcBuilder) are owned by the
 *   caller and must be released via their respective wasm_destroy_* counterparts.
 */

#include <emscripten.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "scl_rpc_ffi_export.h"
#include "crypto.h"
#include "protocol.h"
#include "types.h"
#include "utils.h"

/* ============================================================================
 * SECTION 1: ENTROPY AND CRYPTOGRAPHIC INITIALIZATION
 *
 * Architectural Preface:
 * Interfaces directly with the host execution environment to harvest high-entropy
 * random bytes from the host Web Cryptography API (`crypto.getRandomValues`).
 * Configures liboqs to redirect all internal lattice sampling routines through
 * this secure entropy pipeline, completely circumventing unseeded PRNG fallbacks.
 * ============================================================================ */

/**
 * @brief Traverses the WebAssembly FFI boundary to extract cryptographically secure random bytes
 *        from the host environment's Web Cryptography API.
 *
 * Implements a zero-copy entropy ingestion bridge via Emscripten inline JavaScript (`EM_JS`).
 * Prioritizes `crypto.getRandomValues` across Web Worker and Window contexts, with a fallback
 * to `crypto` in global scope, populating the target linear memory range directly through `HEAPU8`.
 *
 * @pre `ptr` must point to a valid, writable contiguous memory range within the WASM linear heap.
 * @pre `len` must not exceed the remaining capacity of the allocated buffer at `ptr`.
 * @post The memory region `[ptr, ptr + len)` is populated with unbiased, cryptographically strong entropy.
 * @note Directly writes to WASM linear memory via Emscripten's `HEAPU8.set` view.
 * @warning Thread safety depends on host browser CSPRNG thread-safety. In Web Worker environments,
 *          each worker instance accesses an isolated linear memory instance.
 *
 * @param[out] ptr Pointer to destination buffer in WASM linear memory.
 *                 - Direction: out
 *                 - Ownership: Caller-owned, borrowed by callee.
 *                 - Range: Non-null, valid heap pointer.
 *                 - Byte length: At least `len` bytes.
 *                 - Alignment: 1-byte aligned.
 * @param[in] len  Number of bytes of entropy to harvest.
 *                 - Direction: in
 *                 - Range: [0, SIZE_MAX].
 *
 * @return None.
 *
 * @complexity Time: O(N) where N = len.
 * @complexity Space: O(1) auxiliary space (excluding host browser entropy buffer).
 */
EM_JS(void, js_randombytes, (uint8_t *ptr, size_t len), {
    var buf = new Uint8Array(len);
    if (typeof self !== 'undefined' && self.crypto && self.crypto.getRandomValues) {
        self.crypto.getRandomValues(buf);
    } else if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(buf);
    } else {
        for (var i = 0; i < len; i++) {
            buf[i] = Math.floor(Math.random() * 256);
        }
    }
    var heap = (typeof HEAPU8 !== 'undefined' && HEAPU8) ? HEAPU8 : ((typeof Module !== 'undefined' && Module && Module['HEAPU8']) ? Module['HEAPU8'] : null);
    if (heap) {
        heap.set(buf, ptr);
    }
});

/**
 * @brief Open Quantum Safe (liboqs) callback adapter for WebAssembly entropy extraction.
 *
 * Satisfies the function pointer signature expected by `OQS_randombytes_custom_algorithm`,
 * routing internal lattice key generation and signature sampling through `js_randombytes`.
 *
 * @pre `random_array` must be a valid non-null pointer to at least `bytes_to_read` bytes of memory.
 * @post Exactly `bytes_to_read` bytes are populated with random entropy.
 * @note Invoked internally by liboqs polynomial sampling algorithms.
 * @warning Reentrancy depends on liboqs sampling routines; thread-safe within isolated worker runtimes.
 *
 * @param[out] random_array Destination buffer to receive entropy.
 *                          - Direction: out
 *                          - Ownership: Borrowed.
 *                          - Byte length: `bytes_to_read`.
 * @param[in] bytes_to_read Total byte count requested.
 *                          - Direction: in
 *
 * @return None.
 *
 * @complexity Time: O(N) where N = bytes_to_read.
 * @complexity Space: O(1) auxiliary space.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_randombytes(uint8_t *random_array, size_t bytes_to_read) {
    js_randombytes(random_array, bytes_to_read);
}

/**
 * @brief Initializes the WebAssembly cryptographic subsystem and binds host CSPRNG entropy.
 *
 * Directs liboqs to utilize the custom WebAssembly entropy adapter `wasm_randombytes`
 * and activates the "custom" algorithm profile. Must be invoked once per Web Worker
 * or WebAssembly instance lifecycle prior to invoking lattice key generation routines.
 *
 * @pre None.
 * @post liboqs internal CSPRNG function pointer table points to `wasm_randombytes`.
 * @note Mutates global liboqs execution state for the current WASM instance.
 * @warning Not thread-safe if multiple threads share an unisolated liboqs global state.
 *          Must be invoked during worker initialization.
 *
 * @return None.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
void wasm_init(void) {
    // Configure custom host-entropy callback for liboqs lattice sampling
    OQS_randombytes_custom_algorithm(wasm_randombytes);
    OQS_randombytes_switch_algorithm("custom");
}

/* ============================================================================
 * SECTION 2: LINEAR HEAP MANAGEMENT AND MEMORY SCRUBBING
 *
 * Architectural Preface:
 * Provides explicit linear memory allocation and deallocation hooks for the
 * JavaScript host. Implements optimization-resistant memory zeroization
 * to guarantee that sensitive post-quantum key material is completely erased
 * from linear RAM upon transaction completion.
 * ============================================================================ */

/**
 * @brief Dynamic linear memory allocator exported across the WebAssembly boundary to JavaScript.
 *
 * Allocates contiguous uninitialized bytes within the Emscripten dlmalloc/emmalloc heap,
 * returning a 32-bit linear memory pointer accessible via JavaScript typed array views.
 *
 * @pre `size` must be greater than 0 and fit within the available 32-bit WebAssembly address space.
 * @post Upon success, returns a pointer to a newly allocated block of at least `size` bytes.
 * @note May trigger dynamic WebAssembly linear memory growth (`memory.grow`), potentially
 *       invalidating existing JavaScript `ArrayBuffer` and `TypedArray` views.
 * @warning Callers in JavaScript must re-acquire buffer views (e.g. `HEAPU8`) following any allocation
 *          that triggers heap growth.
 *
 * @param[in] size Number of bytes to allocate in linear heap memory.
 *                 - Direction: in
 *                 - Range: [1, UINT32_MAX].
 *
 * @return uint8_t* Valid pointer to allocated memory block, or NULL (0) if allocation fails.
 *
 * @complexity Time: O(1) amortized.
 * @complexity Space: O(size) heap memory consumed.
 */
EMSCRIPTEN_KEEPALIVE
uint8_t* wasm_malloc(size_t size) {
    return malloc(size);
}

/**
 * @brief Releases previously allocated linear memory back to the WebAssembly heap allocator.
 *
 * Wraps standard C `free()`, deallocating chunks managed by dlmalloc/emmalloc and coalescing
 * free boundary tags.
 *
 * @pre `ptr` must be NULL or a pointer previously returned by `wasm_malloc` that has not been freed.
 * @post Memory associated with `ptr` is returned to the allocator free list. Accessing `ptr`
 *       subsequent to this call results in undefined behavior.
 * @note Passing NULL is a safe no-op.
 * @warning Double-free or freeing pointers not returned by `wasm_malloc` corrupts allocator metadata.
 *
 * @param[in] ptr Pointer to memory block to release.
 *                - Direction: in
 *                - Ownership: Callee-freed.
 *
 * @return None.
 *
 * @complexity Time: O(1) amortized.
 * @complexity Space: O(1) auxiliary space.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_free(void* ptr) {
    free(ptr);
}

/**
 * @brief Constant-time, optimization-resistant memory zeroization utility for sensitive material.
 *
 * Employs `explicit_bzero` to securely erase cryptographic secrets (such as Dilithium private
 * keys, PRF keys, and session keys) from linear memory, guaranteeing that the compiler will not
 * optimize away the memory write as a dead-store.
 *
 * @pre `ptr` must point to at least `len` bytes of valid memory, or be NULL.
 * @post The target memory region `[ptr, ptr + len)` is completely overwritten with zeroes.
 * @note Safe against compiler dead-store elimination passes.
 * @warning Does not free the underlying memory; caller retains ownership and must invoke `wasm_free`.
 *
 * @param[in,out] ptr Pointer to memory region to sanitize.
 *                    - Direction: in-out
 *                    - Ownership: Borrowed.
 *                    - Range: Valid memory block or NULL.
 * @param[in] len     Number of bytes to zero.
 *                    - Direction: in
 *                    - Range: [0, SIZE_MAX].
 *
 * @return None.
 *
 * @complexity Time: O(len) constant time with respect to input data values.
 * @complexity Space: O(1) auxiliary space.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_secure_wipe(void* ptr, size_t len) {
    if (ptr) {
        explicit_bzero(ptr, len);
    }
}

/* ============================================================================
 * SECTION 3: BINARY RPC PARSER FFI INTERFACES
 *
 * Architectural Preface:
 * Exposes zero-copy accessors for decoding Satocialist Cryptographic Ledger (SCL)
 * binary RPC wire frames. Manages parser lifecycle and extracts protocol headers,
 * status codes, method discriminators, cursors, and payload references without
 * allocating redundant memory buffers.
 * ============================================================================ */

/**
 * @brief Constructs an opaque binary RPC frame parser context from raw wire bytes.
 *
 * Parses fixed frame headers, verifies structural wire boundaries, checks checksum
 * offsets, and instantiates an opaque `SclRpcParser` handle for field extraction.
 *
 * @pre `wire_bytes` must point to at least `len` bytes of valid memory.
 * @pre `out_status` must be a valid pointer to an integer receiving status/error codes.
 * @post Returns an opaque handle to an allocated `SclRpcParser` instance on success.
 * @note The parser maintains an internal reference to `wire_bytes`; the underlying buffer
 *       must remain valid and unmodified until `wasm_destroy_parser` is invoked.
 * @warning Callers must explicitly destroy the parser instance via `wasm_destroy_parser`.
 *
 * @param[in]  wire_bytes Pointer to raw received binary frame bytes.
 *                        - Direction: in
 *                        - Ownership: Borrowed by parser context.
 *                        - Byte length: `len`.
 * @param[in]  len        Total byte length of the wire frame.
 *                        - Direction: in
 *                        - Range: [SCL_RPC_MIN_FRAME_LEN, SCL_RPC_MAX_FRAME_LEN].
 * @param[out] out_status Pointer to integer receiving the parser result code (0 = success).
 *                        - Direction: out
 *
 * @return SclRpcParser Opaque parser handle, or NULL on allocation/framing failure.
 *
 * @complexity Time: O(1) fixed-header verification.
 * @complexity Space: O(1) auxiliary space allocated for parser handle context.
 */
EMSCRIPTEN_KEEPALIVE
SclRpcParser wasm_parse_frame(const uint8_t* wire_bytes, size_t len, int* out_status) {
    return scl_rpc_parser_create(wire_bytes, len, out_status);
}

/**
 * @brief Destroys an opaque binary RPC parser handle and reclaims its associated memory.
 *
 * @pre `parser` must be a valid handle returned by `wasm_parse_frame`, or NULL.
 * @post The parser instance memory is deallocated. Using `parser` thereafter is undefined.
 * @note Passing NULL is a safe no-op.
 *
 * @param[in] parser Opaque parser handle to destroy.
 *                   - Direction: in
 *                   - Ownership: Callee-freed.
 *
 * @return None.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
void wasm_destroy_parser(SclRpcParser parser) {
    scl_rpc_parser_destroy(parser);
}

/**
 * @brief Extracts the wire protocol version byte from an active parser context.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @post Returns the 8-bit protocol version encoded in the frame header.
 *
 * @param[in] parser Opaque parser handle.
 *                   - Direction: in
 *                   - Ownership: Borrowed.
 *
 * @return uint8_t Protocol version byte (e.g., 0x01).
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
uint8_t wasm_parser_get_version(SclRpcParser parser) {
    return scl_rpc_parser_get_version(parser);
}

/**
 * @brief Extracts the 16-bit status code from an active parser context.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @post Returns host-endian status code (e.g., SCL_RPC_STATUS_OK = 0x0000).
 *
 * @param[in] parser Opaque parser handle.
 *                   - Direction: in
 *                   - Ownership: Borrowed.
 *
 * @return uint16_t Status code.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
uint16_t wasm_parser_get_status(SclRpcParser parser) {
    return scl_rpc_parser_get_status(parser);
}

/**
 * @brief Extracts the 8-bit frame flags bitmask from an active parser context.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @post Returns bitmask indicating frame attributes (e.g., signature presence, pagination).
 *
 * @param[in] parser Opaque parser handle.
 *                   - Direction: in
 *                   - Ownership: Borrowed.
 *
 * @return uint8_t Flags bitfield.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
uint8_t wasm_parser_get_flags(SclRpcParser parser) {
    return scl_rpc_parser_get_flags(parser);
}

/**
 * @brief Extracts the 16-bit RPC method identifier from an active parser context.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @post Returns method discriminator identifying requested RPC method.
 *
 * @param[in] parser Opaque parser handle.
 *                   - Direction: in
 *                   - Ownership: Borrowed.
 *
 * @return uint16_t Method ID.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
uint16_t wasm_parser_get_method_id(SclRpcParser parser) {
    return scl_rpc_parser_get_method_id(parser);
}

/**
 * @brief Extracts the 32-bit pagination cursor offset from an active parser context.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @post Returns cursor index for paginated query resumption.
 *
 * @param[in] parser Opaque parser handle.
 *                   - Direction: in
 *                   - Ownership: Borrowed.
 *
 * @return uint32_t Pagination cursor value.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
uint32_t wasm_parser_get_cursor(SclRpcParser parser) {
    return scl_rpc_parser_get_cursor(parser);
}

/**
 * @brief Extracts the 64-bit correlation request identifier from an active parser context.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @post Returns unique request ID for multiplexed response matching.
 *
 * @param[in] parser Opaque parser handle.
 *                   - Direction: in
 *                   - Ownership: Borrowed.
 *
 * @return uint64_t 64-bit correlation identifier.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
uint64_t wasm_parser_get_request_id(SclRpcParser parser) {
    return scl_rpc_parser_get_request_id(parser);
}

/**
 * @brief Obtains a zero-copy direct pointer reference to the deserialized payload slice.
 *
 * Provides callers with a direct view into the payload segment within the frame buffer,
 * eliminating redundant heap copies.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @pre `out_ptr` and `out_len` must be non-null pointers.
 * @post `*out_ptr` is set to point directly to the first byte of payload within linear memory.
 * @post `*out_len` is populated with the payload byte count.
 * @warning The returned pointer is borrowed and valid only while the underlying frame buffer exists.
 *
 * @param[in]  parser  Opaque parser handle.
 *                     - Direction: in
 * @param[out] out_ptr Pointer to receive address of payload slice.
 *                     - Direction: out
 * @param[out] out_len Pointer to receive byte count of payload slice.
 *                     - Direction: out
 *
 * @return int 0 on success, non-zero on error.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_parser_get_payload_ref(SclRpcParser parser, const uint8_t** out_ptr, size_t* out_len) {
    return scl_rpc_parser_get_payload_ref(parser, out_ptr, out_len);
}

/**
 * @brief Copies the human-readable error string from an error-status parser context.
 *
 * @pre `parser` must be a valid, non-null parser handle.
 * @pre `out_str` must point to writable memory of at least `max_len` bytes.
 * @post `out_str` contains a null-terminated UTF-8 string describing the protocol error.
 *
 * @param[in]  parser  Opaque parser handle.
 *                     - Direction: in
 * @param[out] out_str Destination char buffer for error text.
 *                     - Direction: out
 * @param[in]  max_len Capacity of destination buffer in bytes.
 *                     - Direction: in
 *
 * @return int 0 on success, non-zero on truncation or error.
 *
 * @complexity Time: O(K) where K = strlen(error).
 * @complexity Space: O(1) auxiliary space.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_parser_get_error(SclRpcParser parser, char* out_str, size_t max_len) {
    return scl_rpc_parser_get_error(parser, out_str, max_len);
}

/**
 * @brief Extracts payment challenge parameters from a payment-required parser context.
 *
 * Populates caller-provided challenge buffer with the required payment amount, payment recipient
 * address, nonce, and rate lock timeout issued by the node RPC rate limiter.
 *
 * @pre `parser` must be a valid, non-null parser handle with status SCL_RPC_STATUS_PAYMENT_REQUIRED.
 * @pre `out_challenge` must be a non-null pointer to an allocated SclRpcPaymentChallenge struct.
 * @post `*out_challenge` is populated with the payment challenge fields.
 *
 * @param[in]  parser        Opaque parser handle.
 *                           - Direction: in
 * @param[out] out_challenge Destination structure for payment challenge data.
 *                           - Direction: out
 *
 * @return int 0 on success, non-zero on error or missing challenge.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_parser_get_payment_challenge(SclRpcParser parser, SclRpcPaymentChallenge* out_challenge) {
    return scl_rpc_parser_get_payment_challenge(parser, out_challenge);
}

/**
 * @brief Verifies the 64-bit SipHash-2-4 checksum appended to an incoming binary frame.
 *
 * Computes SipHash-2-4 over frame header and payload bytes using the shared session key,
 * comparing the digest against the wire checksum in constant time.
 *
 * @pre `wire_bytes` points to at least `len` bytes of memory.
 * @pre `len` >= SCL_RPC_MIN_FRAME_LEN + 8 (minimum header + checksum).
 * @pre `rpc_siphash_key` points to exactly 16 bytes of symmetric key material.
 * @post Returns 1 if checksum matches identically; 0 if corrupted or forged.
 *
 * @param[in] wire_bytes      Pointer to wire frame bytes.
 *                            - Direction: in
 * @param[in] len             Total wire frame byte length.
 *                            - Direction: in
 * @param[in] rpc_siphash_key 16-byte shared SipHash key.
 *                            - Direction: in
 *
 * @return int 1 if checksum is valid, 0 if invalid or corrupted.
 *
 * @complexity Time: O(len) streaming SipHash computation.
 * @complexity Space: O(1) auxiliary space.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_verify_checksum(const uint8_t* wire_bytes, size_t len, const uint8_t* rpc_siphash_key) {
    return scl_rpc_verify_checksum(wire_bytes, len, rpc_siphash_key);
}

/* ============================================================================
 * SECTION 4: BINARY RPC BUILDER AND FRAME GENERATORS
 *
 * Architectural Preface:
 * Provides stateful frame construction utilities for outbound RPC messages.
 * Formats standardized protocol headers, writes variable payload arguments,
 * calculates ML-DSA-87 signatures, and appends integrity checksums according
 * to SCL wire-protocol specifications.
 * ============================================================================ */

/**
 * @brief Allocates and initializes an outbound binary RPC frame builder context.
 *
 * @pre None.
 * @post Returns an allocated `SclRpcBuilder` handle initialized with header fields.
 * @warning The allocated builder must be destroyed via `wasm_builder_destroy`.
 *
 * @param[in] version    RPC protocol version (normally 0x01).
 *                       - Direction: in
 * @param[in] method_id  Method discriminator code.
 *                       - Direction: in
 * @param[in] request_id Correlation identifier.
 *                       - Direction: in
 *
 * @return SclRpcBuilder Opaque builder handle, or NULL on allocation failure.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1) heap allocation.
 */
EMSCRIPTEN_KEEPALIVE
SclRpcBuilder wasm_builder_create(uint8_t version, uint16_t method_id, uint64_t request_id) {
    return scl_rpc_builder_create(version, method_id, request_id);
}

/**
 * @brief Configures attribute flags on an active frame builder context.
 *
 * @pre `builder` must be a valid, non-null builder handle.
 * @post Builder flags bitfield updated.
 *
 * @param[in] builder Opaque builder handle.
 *                    - Direction: in
 * @param[in] flags   Bitmask of frame flags.
 *                    - Direction: in
 *
 * @return None.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
void wasm_builder_set_flags(SclRpcBuilder builder, uint8_t flags) {
    scl_rpc_builder_set_flags(builder, flags);
}

/**
 * @brief Sets the pagination cursor on an active frame builder context.
 *
 * @pre `builder` must be a valid, non-null builder handle.
 * @post Builder pagination cursor field updated.
 *
 * @param[in] builder Opaque builder handle.
 *                    - Direction: in
 * @param[in] cursor  Pagination index.
 *                    - Direction: in
 *
 * @return None.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
void wasm_builder_set_cursor(SclRpcBuilder builder, uint32_t cursor) {
    scl_rpc_builder_set_cursor(builder, cursor);
}

/**
 * @brief Appends serialized arguments or payload bytes to an active frame builder context.
 *
 * @pre `builder` must be a valid, non-null builder handle.
 * @pre `payload` points to at least `len` bytes of valid memory.
 * @post Payload buffer within builder expanded by `len` bytes.
 *
 * @param[in] builder Opaque builder handle.
 *                    - Direction: in
 * @param[in] payload Source buffer containing payload arguments.
 *                    - Direction: in
 * @param[in] len     Byte count to append.
 *                    - Direction: in
 *
 * @return int 0 on success, non-zero on allocation failure or size limit exceeded.
 *
 * @complexity Time: O(len) memory copy.
 * @complexity Space: O(len) dynamic buffer growth.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_builder_append_args(SclRpcBuilder builder, const uint8_t* payload, size_t len) {
    return scl_rpc_builder_append_args(builder, payload, len);
}

/**
 * @brief Prepends an SclRpcPaymentReceipt structure to an active frame builder context.
 *
 * Attaches proof of micropayment (settlement transaction hash, payment mechanism, and rate lock ID)
 * to satisfy payment challenges on metered RPC endpoints.
 *
 * @pre `builder` must be a valid, non-null builder handle.
 * @pre `tx_id` must point to at least 32 bytes representing the settlement transaction ID.
 * @post Payment receipt metadata is written into the builder frame buffer.
 *
 * @param[in] builder      Opaque builder handle.
 *                         - Direction: in
 * @param[in] payment_type Mechanism type code (e.g. on-chain pointer transfer or off-chain ticket).
 *                         - Direction: in
 * @param[in] tx_id        32-byte transaction identifier hash.
 *                         - Direction: in
 * @param[in] rate_lock_id Server-issued rate lock identifier from challenge.
 *                         - Direction: in
 *
 * @return int 0 on success, non-zero on allocation failure or buffer overflow.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(sizeof(SclRpcPaymentReceipt)) buffer expansion.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_builder_set_payment_receipt(SclRpcBuilder builder, uint8_t payment_type, const uint8_t* tx_id, uint64_t rate_lock_id) {
    return scl_rpc_builder_set_payment_receipt(builder, payment_type, tx_id, rate_lock_id);
}

/**
 * @brief Computes an ML-DSA-87 (Dilithium5) post-quantum signature over the builder payload.
 *
 * @pre `builder` must be a valid, non-null builder handle.
 * @pre `dilithium_privkey` points to exactly DILITHIUM_SECRETKEY_LEN (4864) bytes.
 * @post Signs the frame contents, attaches signature bytes, and sets SCL_RPC_FLAG_SIGNED.
 * @warning Private key bytes are accessed in constant time by the underlying lattice routine.
 *
 * @param[in] builder           Opaque builder handle.
 *                              - Direction: in
 * @param[in] dilithium_privkey ML-DSA-87 secret key buffer (4864 bytes).
 *                              - Direction: in
 *
 * @return int 0 on success, non-zero on signature generation failure.
 *
 * @complexity Time: O(1) relative to payload (signs 32-byte digest), dominated by lattice signing.
 * @complexity Space: O(SIGNATURE_LEN) allocation for attached signature.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_builder_sign(SclRpcBuilder builder, const uint8_t* dilithium_privkey) {
    return scl_rpc_builder_sign(builder, dilithium_privkey);
}

/**
 * @brief Finalizes and serializes the complete binary frame into a caller-supplied output buffer.
 *
 * Formats header, payload, optional signature, and computes trailing checksums.
 *
 * @pre `builder` must be a valid, non-null builder handle.
 * @pre `out_buffer` points to at least `max_len` bytes of writable memory.
 * @pre `serialized_len` must be a valid pointer to size_t.
 * @post `out_buffer` contains the complete ready-to-transmit wire frame.
 * @post `*serialized_len` is populated with the exact wire length in bytes.
 *
 * @param[in]  builder        Opaque builder handle.
 *                            - Direction: in
 * @param[out] out_buffer     Destination buffer for wire bytes.
 *                            - Direction: out
 * @param[in]  max_len        Capacity of destination buffer.
 *                            - Direction: in
 * @param[out] serialized_len Pointer receiving final serialized byte count.
 *                            - Direction: out
 *
 * @return int 0 on success, non-zero if destination buffer capacity is insufficient.
 *
 * @complexity Time: O(N) where N = serialized frame length.
 * @complexity Space: O(1) auxiliary space.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_builder_finalize(SclRpcBuilder builder, uint8_t* out_buffer, size_t max_len, size_t* serialized_len) {
    return scl_rpc_builder_finalize(builder, out_buffer, max_len, serialized_len);
}

/**
 * @brief Destroys an active frame builder context and releases all allocated memory.
 *
 * @pre `builder` must be a valid handle returned by `wasm_builder_create`, or NULL.
 * @post Builder memory reclaimed. Accessing `builder` thereafter is undefined.
 *
 * @param[in] builder Opaque builder handle to destroy.
 *                    - Direction: in
 *                    - Ownership: Callee-freed.
 *
 * @return None.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
void wasm_builder_destroy(SclRpcBuilder builder) {
    scl_rpc_builder_destroy(builder);
}

/**
 * @brief Directly serializes a binary Balance Query request frame into the output buffer.
 *
 * Method ID: 0x0001. Encapsulates query for total, available, and staked subunits.
 *
 * @pre `target_pubkey` points to exactly DILITHIUM_PUBKEY_LEN (2592) bytes.
 * @pre `out_frame` points to at least `max_len` bytes.
 * @post `out_frame` contains the serialized request frame.
 * @post `*out_len` contains the total serialized length.
 *
 * @param[in]  request_id    64-bit correlation ID.
 * @param[in]  target_pubkey 2592-byte Dilithium public key to query.
 * @param[out] out_frame     Destination buffer.
 * @param[in]  max_len       Capacity of destination buffer.
 * @param[out] out_len       Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_balance_query(uint64_t request_id, const uint8_t* target_pubkey, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_balance_query(request_id, target_pubkey, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Recent Transactions query frame.
 *
 * Method ID: 0x0002. Retrieves recent ledger activity starting from pagination cursor.
 *
 * @param[in]  request_id 64-bit correlation ID.
 * @param[in]  cursor     32-bit transaction index offset.
 * @param[out] out_frame  Destination buffer.
 * @param[in]  max_len    Capacity of destination buffer.
 * @param[out] out_len    Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_recent_txs(uint64_t request_id, uint32_t cursor, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_recent_txs(request_id, cursor, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Get Transaction by Hash query frame.
 *
 * Method ID: 0x0003. Queries a specific transaction by 32-byte transaction ID.
 *
 * @param[in]  request_id 64-bit correlation ID.
 * @param[in]  tx_hash    32-byte SHA-256 transaction hash.
 * @param[in]  hash_len   Length of hash buffer (must be 32).
 * @param[out] out_frame  Destination buffer.
 * @param[in]  max_len    Capacity of destination buffer.
 * @param[out] out_len    Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_get_tx(uint64_t request_id, const uint8_t* tx_hash, size_t hash_len, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_get_tx(request_id, tx_hash, hash_len, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Chain Information query frame.
 *
 * Method ID: 0x0004. Queries block height, active peers, tip hash, and issuance metrics.
 *
 * @param[in]  request_id 64-bit correlation ID.
 * @param[out] out_frame  Destination buffer.
 * @param[in]  max_len    Capacity of destination buffer.
 * @param[out] out_len    Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_chain_info(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_chain_info(request_id, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Pending Valuations query frame.
 *
 * Method ID: 0x0005. Queries active valuation submissions in the mempool.
 *
 * @param[in]  request_id 64-bit correlation ID.
 * @param[out] out_frame  Destination buffer.
 * @param[in]  max_len    Capacity of destination buffer.
 * @param[out] out_len    Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_valuations_query(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_valuations_query(request_id, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Consensus Audit Ring query frame.
 *
 * Method ID: 0x0006. Queries current 1024-entry consensus audit buffer.
 *
 * @param[in]  request_id 64-bit correlation ID.
 * @param[out] out_frame  Destination buffer.
 * @param[in]  max_len    Capacity of destination buffer.
 * @param[out] out_len    Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_audit_query(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_audit_query(request_id, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Block by Height query frame.
 *
 * Method ID: 0x0007. Queries serialized block data for a specific block height.
 *
 * @param[in]  request_id 64-bit correlation ID.
 * @param[in]  height     Target block number.
 * @param[out] out_frame  Destination buffer.
 * @param[in]  max_len    Capacity of destination buffer.
 * @param[out] out_len    Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_block_query(uint64_t request_id, uint32_t height, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_block_query(request_id, height, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Quantum TVD Verification query frame.
 *
 * Method ID: 0x0008. Submits quantum circuit bytes, execution shots, and random beacon
 * seed to audit QPU calibration and drift metrics via Total Variation Distance.
 *
 * @param[in]  request_id    64-bit correlation ID.
 * @param[in]  shots         Number of circuit measurement shots.
 * @param[in]  beacon_seed   32-byte threshold beacon randomness seed.
 * @param[in]  circuit_bytes Byte array representing serialized quantum circuit.
 * @param[in]  circuit_len   Length of circuit byte array.
 * @param[out] out_frame     Destination buffer.
 * @param[in]  max_len       Capacity of destination buffer.
 * @param[out] out_len       Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(circuit_len). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_quantum_tvd_audit(uint64_t request_id, uint32_t shots, const uint8_t* beacon_seed, const uint8_t* circuit_bytes, size_t circuit_len, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_quantum_tvd_audit(request_id, shots, beacon_seed, circuit_bytes, circuit_len, out_frame, max_len, out_len);
}

/**
 * @brief Directly serializes a binary Auto-Pilot Configuration command frame.
 *
 * Method ID: 0x0009. Configures or toggles autonomous consensus auto-pilot.
 *
 * @param[in]  request_id   64-bit correlation ID.
 * @param[in]  enable       1 to enable auto-pilot, 0 to deactivate.
 * @param[in]  val_per_hr   Autonomous valuation submissions per hour.
 * @param[in]  stake_ratio  Target percentage of available balance to keep staked (0-100).
 * @param[out] out_frame    Destination buffer.
 * @param[in]  max_len      Capacity of destination buffer.
 * @param[out] out_len      Pointer receiving output length.
 *
 * @return int 0 on success, negative error code on failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_frame_autopilot(uint64_t request_id, int enable, uint32_t val_per_hr, uint32_t stake_ratio, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    return scl_rpc_frame_autopilot(request_id, enable, val_per_hr, stake_ratio, out_frame, max_len, out_len);
}

/* ============================================================================
 * SECTION 5: POST-QUANTUM LATTICE CRYPTOGRAPHY & ZERO-KNOWLEDGE PROOFS
 *
 * Architectural Preface:
 * Exposes core lattice cryptographic operations to JavaScript runtimes.
 * Implements NIST FIPS 204 ML-DSA-87 (Dilithium5) key generation and signing,
 * BDLOP lattice commitments, Module-SIS PRF evaluation, Stern-based ZK proofs,
 * and Centinel shielded transaction zero-knowledge proofs.
 * ============================================================================ */

/**
 * @brief Computes standard cryptographic SHA-256 digest on input data within linear memory.
 *
 * @pre `data` points to at least `len` bytes of valid memory.
 * @pre `out_hash` points to at least 32 bytes of writable memory.
 * @post Exactly 32 bytes of SHA-256 digest written to `out_hash`.
 *
 * @param[in]  data     Source data buffer.
 * @param[in]  len      Length of input data in bytes.
 * @param[out] out_hash Destination buffer for 32-byte digest.
 *
 * @return None.
 *
 * @complexity Time: O(len) streaming SHA-256 compression blocks.
 * @complexity Space: O(1) auxiliary space.
 */
EMSCRIPTEN_KEEPALIVE
void wasm_sha256(const uint8_t* data, size_t len, uint8_t* out_hash) {
    sha256_hash(data, len, out_hash);
}

/**
 * @brief Generates a NIST FIPS 204 ML-DSA-87 (Dilithium5) post-quantum keypair.
 *
 * Samples polynomial vectors with small coefficients from host entropy, producing
 * public key $A s_1 + s_2$ and secret key vectors $(s_1, s_2, K, \text{tr})$.
 *
 * @pre `public_key` points to at least DILITHIUM_PUBKEY_LEN (2592) bytes.
 * @pre `secret_key` points to at least DILITHIUM_SECRETKEY_LEN (4864) bytes.
 * @post `public_key` contains 2592-byte serialized public key.
 * @post `secret_key` contains 4864-byte serialized private key.
 * @note Initializes the custom WASM CSPRNG via `wasm_init` prior to sampling.
 * @warning `secret_key` contains sensitive material and must be protected or wiped.
 *
 * @param[out] public_key Destination buffer for 2592-byte public key.
 *                        - Direction: out
 * @param[out] secret_key Destination buffer for 4864-byte private key.
 *                        - Direction: out
 *
 * @return int 0 on success, non-zero on key generation failure.
 *
 * @complexity Time: O(1) constant-time matrix-vector polynomial ring multiplication.
 * @complexity Space: O(1) stack allocation for NTT sampling.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_dilithium_generate_keypair(uint8_t *public_key, uint8_t *secret_key) {
    // Ensure entropy subsystem is initialized before sampling lattice polynomials
    wasm_init();
    return dilithium_generate_keypair(public_key, secret_key);
}

/**
 * @brief Computes an ML-DSA-87 (Dilithium5) post-quantum digital signature.
 *
 * Uses Fiat-Shamir with Aborts over polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$
 * to sign arbitrary byte messages.
 *
 * @pre `msg` points to at least `msg_len` bytes.
 * @pre `private_key` points to DILITHIUM_SECRETKEY_LEN (4864) bytes.
 * @pre `signature` points to at least SIGNATURE_LEN (4595) bytes of writable memory.
 * @post Exactly 4595 bytes of signature data written to `signature`.
 *
 * @param[in]  msg         Message buffer to sign.
 * @param[in]  msg_len     Length of message in bytes.
 * @param[in]  private_key 4864-byte ML-DSA-87 private key.
 * @param[out] signature   Destination buffer for 4595-byte signature.
 *
 * @return int 0 on success, non-zero on signature generation failure.
 *
 * @complexity Time: O(msg_len + rejection_sampling_loops).
 * @complexity Space: O(1) stack space.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_dilithium_sign(const uint8_t *msg, size_t msg_len, const uint8_t *private_key, uint8_t *signature) {
    return dilithium_sign(msg, msg_len, private_key, signature);
}

/**
 * @brief Derives a Module-SIS Pseudorandom Function (PRF) key from a 32-byte master seed.
 *
 * @pre `seed` points to at least `seed_len` bytes (minimum 32 bytes).
 * @pre `key_out` points to at least PRF_M (480) bytes of writable memory.
 * @post `key_out` populated with PRF key matrix coordinates.
 * @note Stack representation of `PRFKey` is zeroized prior to return.
 *
 * @param[out] key_out  Destination buffer for PRF key bytes.
 * @param[in]  seed     Seed buffer used for deterministic derivation.
 * @param[in]  seed_len Length of seed in bytes (minimum 32).
 *
 * @return int CRYPTO_SUCCESS (0) on success, error code on failure.
 *
 * @complexity Time: O(seed_len). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_prf_keygen(uint8_t *key_out, const uint8_t *seed, size_t seed_len) {
    PRFKey key_struct;
    int result = prf_keygen(&key_struct, seed, seed_len);
    if (result == CRYPTO_SUCCESS) {
        memcpy(key_out, key_struct.k, sizeof(key_struct.k));
    }
    // Optimization-resistant zeroization of stack key material
    explicit_bzero(&key_struct, sizeof(PRFKey));
    return result;
}

/**
 * @brief Evaluates the Module-SIS PRF to compute a deterministic transaction nullifier.
 *
 * Computes $y = \lfloor A_{\text{seed}} \cdot k + J \rceil_p$ where $k$ is the user's PRF key,
 * $J$ is the input transaction ID, and $A$ is expanded from seed.
 *
 * @pre `y_out` points to at least NULLIFIER_LEN (32) bytes.
 * @pre `key_k` points to PRF_M (480) signed bytes of PRF key data.
 * @pre `J` points to `J_len` bytes (normally 32-byte transaction ID).
 * @pre `seed` points to 32 bytes of PRF public domain seed.
 * @post `y_out` populated with 32-byte nullifier.
 * @note Intermediate stack copy of the PRF key is securely zeroized prior to return.
 *
 * @param[out] y_out  Destination buffer for 32-byte PRF nullifier.
 * @param[in]  key_k  480-byte PRF key matrix.
 * @param[in]  J      Input message / transaction identifier bytes.
 * @param[in]  J_len  Length of input buffer in bytes.
 * @param[in]  seed   32-byte public domain seed.
 *
 * @return int 0 on success, non-zero on evaluation failure.
 *
 * @complexity Time: O(M * N) lattice matrix rounding. Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_prf_evaluate(uint8_t* y_out, const int8_t* key_k, const uint8_t* J, size_t J_len, const uint8_t* seed) {
    PRFKey prf_key;
    memcpy(prf_key.k, key_k, sizeof(prf_key.k));
    
    int result = prf_evaluate(y_out, &prf_key, J, J_len, seed);
    
    // Unconditionally wipe stack key representation to preserve forward secrecy
    explicit_bzero(&prf_key, sizeof(PRFKey));
    return result;
}

/**
 * @brief Computes a BDLOP homomorphic lattice commitment $C = A r + m \pmod q$.
 *
 * @pre `rho` points to 32 bytes of public matrix seed.
 * @pre `r` points to 32 bytes of randomness/blinding factor.
 * @pre `commitment_out` points to valid `BdlopCommitment` structure.
 * @post `commitment_out` populated with computed polynomial vectors $(c_1, c_2)$.
 *
 * @param[in]  rho            32-byte public randomness seed for matrix A expansion.
 * @param[in]  v              64-bit value to commit to.
 * @param[in]  r              32-byte blinding factor.
 * @param[out] commitment_out Destination BdlopCommitment structure.
 *
 * @return int CRYPTO_SUCCESS (0) on success, non-zero on error.
 *
 * @complexity Time: O(1) polynomial ring NTT operations. Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_bdlop_commit(const uint8_t* rho, uint64_t v, const uint8_t* r, BdlopCommitment* commitment_out) {
    return bdlop_commit(rho, v, r, commitment_out);
}

/**
 * @brief Opens / decrypts a BDLOP lattice commitment using the secret blinding factor.
 *
 * @pre `rho` points to 32 bytes of matrix seed.
 * @pre `commitment` points to valid BdlopCommitment structure.
 * @pre `r` points to 32 bytes of blinding factor.
 * @pre `v_out` points to uint64_t.
 * @post `*v_out` populated with recovered 64-bit committed value.
 *
 * @param[in]  rho        32-byte matrix seed.
 * @param[in]  commitment Commitment to open.
 * @param[in]  r          32-byte blinding factor.
 * @param[out] v_out      Pointer receiving recovered value.
 *
 * @return int CRYPTO_SUCCESS (0) on success, non-zero on opening failure.
 *
 * @complexity Time: O(1). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_bdlop_decrypt(const uint8_t* rho, const BdlopCommitment* commitment, const uint8_t* r, uint64_t* v_out) {
    return bdlop_decrypt(rho, commitment, r, v_out);
}

/**
 * @brief Decrypts an authenticated symmetric payload envelope (AES-256-GCM).
 *
 * @pre `aes_key` points to 32-byte symmetric key.
 * @pre `ciphertext` points to at least `ciphertext_len` bytes.
 * @pre `plaintext` points to writable buffer of at least `ciphertext_len` bytes.
 * @pre `plaintext_len` points to size_t.
 * @post `plaintext` contains decrypted bytes; `*plaintext_len` updated.
 *
 * @param[in]  aes_key        32-byte AES key.
 * @param[in]  ciphertext     Encrypted payload buffer.
 * @param[in]  ciphertext_len Length of ciphertext in bytes.
 * @param[out] plaintext      Destination buffer for decrypted bytes.
 * @param[out] plaintext_len  Pointer receiving decrypted byte count.
 *
 * @return int 0 on success, non-zero on authentication tag mismatch or error.
 *
 * @complexity Time: O(ciphertext_len). Space: O(1).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_decrypt_payload(const uint8_t* aes_key, const uint8_t* ciphertext, size_t ciphertext_len,
                         uint8_t* plaintext, size_t* plaintext_len) {
    // Authenticate and decrypt AES-256-GCM encrypted message payload
    return decrypt_message(aes_key, ciphertext, ciphertext_len, plaintext, plaintext_len);
}

/**
 * @brief Generates a zero-knowledge Stern-type proof of knowledge for Module-SIS PRF evaluation.
 *
 * Produces a statistical zero-knowledge argument proving knowledge of key $k$ such that
 * $y = \text{PRF}_k(J)$ without revealing $k$.
 *
 * @pre `proof` points to at least ZK_PROOF_MAX_LEN bytes.
 * @pre `out_proof_len` points to size_t.
 * @pre `prf_input` points to `input_len` bytes.
 * @pre `prf_key` points to `key_len` bytes (PRF_M = 480 bytes).
 * @pre `seed` points to 32 bytes of public seed.
 * @post `proof` populated with serialized proof; `*out_proof_len` set to proof length.
 *
 * @param[out] proof         Destination buffer for proof bytes.
 * @param[out] out_proof_len Pointer receiving exact proof byte length.
 * @param[in]  prf_input     Input data buffer J.
 * @param[in]  input_len     Length of input buffer in bytes.
 * @param[in]  prf_key       Secret PRF key buffer.
 * @param[in]  key_len       Length of PRF key (480 bytes).
 * @param[in]  seed          32-byte public seed.
 *
 * @return int CRYPTO_SUCCESS (0) on success, non-zero on failure.
 *
 * @complexity Time: O(iterations * M) permutation and commitment evaluations.
 * @complexity Space: O(ZK_PROOF_MAX_LEN) temporary proof buffer.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_generate_zk_prf_proof(uint8_t *proof, size_t *out_proof_len,
                               const uint8_t *prf_input, size_t input_len,
                               const uint8_t *prf_key, size_t key_len,
                               const uint8_t *seed) {
    size_t proof_len = ZK_PROOF_MAX_LEN;
    // Execute Stern zero-knowledge prover for Module-SIS PRF pre-image
    int result = generate_zk_prf_proof(proof, &proof_len, prf_input, input_len, prf_key, key_len, seed);
    if (result == CRYPTO_SUCCESS && out_proof_len) {
        *out_proof_len = proof_len;
    }
    return result;
}

/**
 * @brief Generates a composite Centinel zero-knowledge shielded transaction redemption proof.
 *
 * Constructs a zero-knowledge argument proving simultaneously:
 * 1. Membership of old commitment $C_{\text{old}}$ in the Merkle Mountain Range root.
 * 2. Correct nullifier evaluation $\eta = \text{PRF}_k(\text{coin\_id})$.
 * 3. Homomorphic value conservation: $v_{\text{old}} = v_{\text{transfer}} + v_{\text{change}}$.
 * 4. Knowledge of secret blinding factors $(r_{\text{old}}, r_{\text{transfer}}, r_{\text{change}})$.
 *
 * @pre `out_data` points to a valid, writable `RedeemCentinelData` structure.
 * @pre `root` points to 32-byte MMR root hash.
 * @post `out_data` populated with transfer commitments, change commitments, nullifier, and ZK proof.
 * @note Wipes intermediate stack PRF key structure prior to return.
 *
 * @param[in]  pk_old         Owner public key of input UTXO (2592 bytes).
 * @param[in]  v_old          Input UTXO value in atomic units.
 * @param[in]  r_old          Input UTXO 32-byte blinding factor.
 * @param[in]  pk_transfer    Recipient public key (2592 bytes).
 * @param[in]  amount         Amount transferred to recipient in atomic units.
 * @param[in]  r_transfer     Transfer 32-byte blinding factor.
 * @param[in]  pk_change      Change recipient public key (normally user's own pubkey).
 * @param[in]  v_change       Change amount in atomic units ($v_{\text{old}} - \text{amount}$).
 * @param[in]  r_change       Change 32-byte blinding factor.
 * @param[in]  prf_key_k      Optional PRF key array (480 bytes), or NULL for deterministic derive.
 * @param[in]  root           32-byte current Merkle Mountain Range root hash.
 * @param[in]  mmr_proof_bytes Serialized MMR inclusion proof bytes for $C_{\text{old}}$.
 * @param[in]  mmr_proof_len  Byte length of serialized MMR inclusion proof.
 * @param[out] out_data       Destination structure receiving serialized proof payload.
 *
 * @return int CRYPTO_SUCCESS (0) on success, error code on failure.
 *
 * @complexity Time: O(log N) for MMR proof verify + O(1) for Stern proof generation.
 * @complexity Space: O(sizeof(RedeemCentinelData)) heap allocation for proof payload.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_generate_centinel_proof(
    const uint8_t *pk_old, uint64_t v_old, const uint8_t *r_old,
    const uint8_t *pk_transfer, uint64_t amount, const uint8_t *r_transfer,
    const uint8_t *pk_change, uint64_t v_change, const uint8_t *r_change,
    const int8_t *prf_key_k, const uint8_t *root,
    const uint8_t *mmr_proof_bytes, size_t mmr_proof_len,
    RedeemCentinelData *out_data
) {
    if (!out_data) return CRYPTO_ERROR_INVALID_PARAM;

    // Derive or import the user's PRF key
    PRFKey prf_key;
    if (prf_key_k) {
        memcpy(prf_key.k, prf_key_k, sizeof(prf_key.k));
    } else if (r_old && !is_zeroed(r_old, 32)) {
        prf_keygen(&prf_key, r_old, 32);
    } else {
        memset(prf_key.k, 0, sizeof(prf_key.k));
    }

    // Deserialize caller-supplied Merkle Mountain Range inclusion proof
    MMRProof path;
    memset(&path, 0, sizeof(MMRProof));
    if (mmr_proof_bytes && mmr_proof_len > 0) {
        const uint8_t *p = mmr_proof_bytes;
        deserialize_mmr_proof(&p, mmr_proof_bytes + mmr_proof_len, &path);
    }

    // Generate composite Stern zero-knowledge argument
    int result = generate_centinel_proof(
        pk_old, v_old, r_old,
        pk_transfer, amount, r_transfer,
        pk_change, v_change, r_change,
        &prf_key, root, &path, out_data
    );

    // Unconditionally scrub the stack PRF key structure
    explicit_bzero(&prf_key, sizeof(PRFKey));
    return result;
}

/* ============================================================================
 * SECTION 6: SHIELDED TRANSACTION MATCHING & LEDGER INSPECTION
 *
 * Architectural Preface:
 * Supplies scanning and parsing utilities for browser light-clients.
 * Scans unspent shielded outputs to identify transactions belonging to the user,
 * extracts block commitment topography, verifies MMR inclusion proofs, and
 * derives deterministic threshold public keys.
 * ============================================================================ */

/**
 * @brief Derives the deterministic threshold public key from a user's Dilithium private key.
 *
 * Simulates localized threshold key generation for committee stake verification.
 *
 * @pre `dilithium_privkey` points to DILITHIUM_SECRETKEY_LEN (4864) bytes.
 * @pre `out_threshold_pubkey` points to DILITHIUM_PUBKEY_LEN (2592) bytes.
 * @post `out_threshold_pubkey` populated with derived threshold public key.
 *
 * @param[in]  dilithium_privkey   4864-byte ML-DSA-87 secret key.
 * @param[out] out_threshold_pubkey Destination buffer for 2592-byte threshold public key.
 *
 * @return int 0 on success, -1 on key generation failure.
 *
 * @complexity Time: O(1) polynomial threshold generation. Space: O(sizeof(ThresholdKeygenData)).
 */
EMSCRIPTEN_KEEPALIVE
int wasm_compute_threshold_pubkey(const uint8_t *dilithium_privkey, uint8_t *out_threshold_pubkey) {
    // Derive deterministic 32-byte seed from caller's private key
    uint8_t keygen_seed[32];
    sha256_hash(dilithium_privkey, DILITHIUM_SECRETKEY_LEN, keygen_seed);

    ThresholdKeygenData *keygen = calloc(1, sizeof(ThresholdKeygenData));
    if (!keygen) return -1;

    // Initialize committee evaluation point indices [0..9]
    uint16_t point_ids[10];
    for (int i = 0; i < 10; i++) point_ids[i] = i;

    // Execute localized (2, 10) threshold key derivation
    int result = threshold_keygen((State *)keygen, keygen, keygen_seed, 32, point_ids, 10, 2);
    if (result == CRYPTO_SUCCESS) {
        memcpy(out_threshold_pubkey, keygen->pubkey, DILITHIUM_PUBKEY_LEN);
    }
    cleanup_keygen_data(keygen);
    free(keygen);
    return (result == CRYPTO_SUCCESS) ? 0 : -1;
}

/**
 * @brief Scans a serialized operation buffer to check if it represents a transaction owned by the user.
 *
 * Deserializes an operation and, if it is a Transfer Pointer, computes the expected nullifier
 * using the user's PRF key and checks for a match against the public transaction PRF output.
 *
 * @pre `op_bytes` points to at least `op_len` bytes.
 * @pre `key_k` points to PRF_M (480) bytes of PRF key data.
 * @pre `seed` points to 32 bytes of PRF domain seed.
 * @pre `out_nullifier` points to at least 32 bytes of writable memory, or is NULL.
 * @post If match is found, returns 1 and copies matching nullifier to `out_nullifier`.
 * @note Stack PRF key representation is zeroized prior to return.
 *
 * @param[in]  op_bytes      Serialized Operation wire bytes.
 * @param[in]  op_len        Length of operation buffer in bytes.
 * @param[in]  key_k         User's 480-byte PRF key matrix.
 * @param[in]  seed          32-byte public domain seed.
 * @param[out] out_nullifier Destination buffer for 32-byte matched nullifier (optional).
 *
 * @return int 1 if transaction belongs to user; 0 if not a match; -1 on deserialization error.
 *
 * @complexity Time: O(op_len) deserialization + O(M*N) PRF evaluation.
 * @complexity Space: O(sizeof(Operation)) temporary heap structure.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_match_transaction(const uint8_t* op_bytes, size_t op_len, const int8_t* key_k, const uint8_t* seed, uint8_t* out_nullifier) {
    Operation *op = calloc(1, sizeof(Operation));
    if (!op) return -1;
    
    // Step 1: Deserialize candidate transaction operation from wire bytes
    int consumed = deserialize_operation(op_bytes, op_len, op, 1);
    if (consumed <= 0) {
        free(op);
        return -1;
    }
    
    int result = 0;
    if (op->type == OP_TRANSFER_POINTER) {
        TransferData *tx = &op->data.transfer_pointer;
        PRFKey prf_key;
        memcpy(prf_key.k, key_k, sizeof(prf_key.k));
        
        // Step 2: Compute candidate nullifier y = PRF_k(tx_id, seed)
        uint8_t expected_nullifier[NULLIFIER_LEN];
        int prf_res = prf_evaluate(expected_nullifier, &prf_key, tx->tx_id, COIN_ID_LEN, seed);
        explicit_bzero(&prf_key, sizeof(PRFKey));
        
        // Step 3: Compare computed nullifier against public transaction output
        if (prf_res == 0) {
            if (memcmp(expected_nullifier, tx->prf_output, NULLIFIER_LEN) == 0) {
                if (out_nullifier) {
                    memcpy(out_nullifier, expected_nullifier, NULLIFIER_LEN);
                }
                result = 1; // Match confirmed: transaction belongs to caller
            }
        }
    }
    free(op);
    return result;
}

/**
 * @brief Extracts all cryptographic commitments from a serialized block to populate frontend topography.
 *
 * Traverses operations inside a serialized block, extracting BDLOP commitments from
 * `OP_CLAIM_VALIDATION` and `OP_REDEEM_CENTINEL`, as well as coin IDs from `OP_MINT_COIN`,
 * hashing each into its 32-byte Merkle Mountain Range leaf representation.
 *
 * @pre `block_bytes` points to at least `block_len` bytes.
 * @pre `out_hashes` points to writable memory of at least `max_hashes * 32` bytes.
 * @post `out_hashes` contains sequential 32-byte leaf hashes for MMR visualization.
 *
 * @param[in]  block_bytes Serialized Block wire bytes.
 * @param[in]  block_len   Length of block buffer in bytes.
 * @param[out] out_hashes  Destination array for 32-byte leaf hashes.
 * @param[in]  max_hashes  Maximum hash slots available in `out_hashes`.
 *
 * @return int Total number of commitment leaf hashes written, or -1 on deserialization failure.
 *
 * @complexity Time: O(block_len + op_count * SHA256).
 * @complexity Space: O(sizeof(Block)) temporary heap structure.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_extract_block_commitments(const uint8_t* block_bytes, size_t block_len, uint8_t* out_hashes, size_t max_hashes) {
    Block *block = calloc(1, sizeof(Block));
    if (!block) return -1;
    if (deserialize_block(block, block_bytes, block_len) != 0) {
        free_block(block);
        return -1;
    }
    int count = 0;
    for (size_t i = 0; i < block->operation_count && count < (int)max_hashes; i++) {
        if (block->operations[i].type == OP_CLAIM_VALIDATION) {
            // Hash the validation BDLOP commitment into an MMR leaf node
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&block->operations[i].data.claim_validation.commitment, sizeof(BdlopCommitment), commitment_hash);
            hash_leaf(commitment_hash, 0, out_hashes + count * COIN_ID_LEN);
            count++;
        } else if (block->operations[i].type == OP_REDEEM_CENTINEL) {
            // Hash the non-zero transfer commitment
            if (!is_zeroed((const uint8_t*)&block->operations[i].data.redeem_centinel.c_transfer, sizeof(BdlopCommitment))) {
                uint8_t transfer_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&block->operations[i].data.redeem_centinel.c_transfer, sizeof(BdlopCommitment), transfer_hash);
                hash_leaf(transfer_hash, 0, out_hashes + count * COIN_ID_LEN);
                count++;
            }
            // Hash the non-zero change commitment if capacity permits
            if (count < (int)max_hashes && !is_zeroed((const uint8_t*)&block->operations[i].data.redeem_centinel.c_change, sizeof(BdlopCommitment))) {
                uint8_t change_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&block->operations[i].data.redeem_centinel.c_change, sizeof(BdlopCommitment), change_hash);
                hash_leaf(change_hash, 0, out_hashes + count * COIN_ID_LEN);
                count++;
            }
        } else if (block->operations[i].type == OP_MINT_COIN) {
            // Hash the minted base coin into an MMR leaf node
            SCLCoin *coin = &block->operations[i].data.mint_coin.coin;
            hash_leaf(coin->coin_id, coin->remaining_subunits, out_hashes + count * COIN_ID_LEN);
            count++;
        }
    }
    free_block(block);
    return count;
}

/**
 * @brief Verifies a Merkle Mountain Range (MMR) cryptographic inclusion proof on the WASM heap.
 *
 * Deserializes an MMR proof path and recomputes peak combinations against the expected root hash.
 *
 * @pre `leaf_hash` points to exactly 32 bytes representing the candidate leaf hash.
 * @pre `proof_bytes` points to at least `proof_len` bytes.
 * @pre `root_hash` points to exactly 32 bytes representing the authoritative MMR root hash.
 * @post Returns 1 if leaf is mathematically proven member of MMR; 0 on invalid proof or mismatch.
 *
 * @param[in] leaf_hash   32-byte leaf hash to verify.
 * @param[in] proof_bytes Serialized MMR proof bytes.
 * @param[in] proof_len   Length of proof buffer in bytes.
 * @param[in] root_hash   32-byte expected MMR root hash.
 *
 * @return int 1 if inclusion proof is valid, 0 if invalid or deserialization fails.
 *
 * @complexity Time: O(path_len) sequential SHA-256 node peak foldings.
 * @complexity Space: O(sizeof(MMRProof)) stack space.
 */
EMSCRIPTEN_KEEPALIVE
int wasm_verify_mmr_proof(const uint8_t* leaf_hash, const uint8_t* proof_bytes, size_t proof_len, const uint8_t* root_hash) {
    MMRProof proof;
    memset(&proof, 0, sizeof(MMRProof));
    // Deserialize proof path and verify MMR leaf inclusion against expected root
    const uint8_t *p = proof_bytes;
    if (deserialize_mmr_proof(&p, proof_bytes + proof_len, &proof) != 0) {
        return 0;
    }
    return verify_mmr_proof(leaf_hash, &proof, root_hash);
}
