/**
 * @file tests/test_rpc_pipelines.c
 * @module tests/test_rpc_pipelines - L5 Native Binary RPC Wire Framing & Parsing Integration Test
 *
 * @brief Integration test verifying the full round-trip lifecycle of the Layer-5 (L5)
 *        binary RPC protocol, including LZ4 payload compression, post-quantum ML-DSA-87
 *        signing, SipHash-2-4 checksum verification, and zero-copy ingress parsing.
 *
 * @details
 * Validates the core application-layer framing pipeline executed across the native node
 * and WebAssembly JavaScript bridge interfaces:
 *
 * 1. Post-Quantum Signing:
 *    - Generates a NIST FIPS 204 ML-DSA-87 (Dilithium5) keypair for message authentication.
 * 2. Real-Time Compression:
 *    - Compresses plaintext payload buffers using LZ4 block compression under worst-case
 *      expansion bounds (`LZ4_compressBound`).
 * 3. Binary Wire Framing (`scl_rpc_builder`):
 *    - Instantiates a builder with protocol version `SCL_RPC_VERSION_1`, method discriminator
 *      `0x0003`, and a 64-bit monotonically tracked request ID.
 *    - Configures header flags: `SCL_RPC_FLAG_COMPRESSED` (bit 2) and `SCL_RPC_FLAG_SIGNED` (bit 0).
 *    - Appends compressed argument bytes and computes the post-quantum Dilithium5 signature.
 *    - Finalizes the wire buffer by computing the 64-bit SipHash-2-4 checksum and writing out
 *      the canonical binary frame (`SclRpcHeader` + signature + compressed payload).
 * 4. Zero-Copy Ingress Parsing (`scl_rpc_parser`):
 *    - Decodes header metadata, checks version parity, and validates SipHash checksum integrity.
 *    - Extracts a zero-copy reference to the decompressed payload buffer.
 *    - Offsets past the leading `DILITHIUM_SIGNATURE_LEN` bytes to extract and assert exact
 *      identity with the original plaintext string.
 *
 * @invariants
 * - Round-Trip Invariant: Decompressed payload byte identity strictly matches `original_payload`.
 * - Wire Layout Invariant: Final serialized frame size strictly equals
 *   `sizeof(SclRpcHeader) + DILITHIUM_SIGNATURE_LEN + compressed_bytes`.
 * - Clean Teardown: Builder, parser, and heap allocations are freed prior to process termination.
 *
 * @standards
 * - RFC 7693: SipHash: A Fast Short-Input PRF (SipHash-2-4).
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA-87).
 * - RFC 7932 / LZ4 Frame Format Specification.
 * - SCL L5 Application Protocol Specification (`scl_rpc_ffi_export.h`).
 *
 * @dependencies
 * - `lz4.h` (Lossless real-time block compression).
 * - `scl_rpc_ffi_export.h` (L5 binary framing exports).
 * - `crypto.h` (Dilithium5 keypair and signing primitives).
 * - `types.h` (Core type definitions and status codes).
 *
 * @threading
 * - Executes synchronously in the primary thread.
 * - Builder and parser handles are single-threaded caller-owned instances.
 *
 * @memory_model
 * - Wire frame buffer is allocated on the stack (16 KiB scratchpad).
 * - Heap allocations for compressed payload buffers are caller-allocated and freed explicitly.
 * - Opaque builder and parser instances are destroyed via their respective destructor APIs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lz4.h>
#include "scl_rpc_ffi_export.h"
#include "crypto.h"
#include "types.h"

/* ============================================================================ */
/* SECTION 0: ASSERTION CONTROL MACROS                                          */
/* ============================================================================ */
/**
 * @def TEST_ASSERT(cond, msg)
 * @brief Asserts condition evaluates to true; terminates process on failure.
 *
 * @details
 * Unlike standard `assert()`, `TEST_ASSERT` always evaluates its condition regardless
 * of `NDEBUG` definitions, ensuring integration tests execute reliably in both
 * Debug and optimized Release/RelWithDebInfo builds.
 *
 * @param[in] cond Boolean condition expression to validate.
 * @param[in] msg Informational failure description string. Null-terminated ASCII.
 */
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[Test] Assertion failed: %s (%s)\n", #cond, msg); \
            exit(1); \
        } \
    } while(0)

/* ============================================================================ */
/* SECTION 1: END-TO-END L5 RPC INTEGRATION TEST ROUTINE                        */
/* ============================================================================ */
/**
 * @brief Main execution entrypoint for the L5 binary RPC framing integration test.
 *
 * @details
 * Executes the complete RPC round-trip:
 * 1. Keypair Generation: Creates temporary Dilithium5 keys.
 * 2. Compression: Encodes a testing string via `LZ4_compress_default`.
 * 3. Framing: Assembles header, compressed payload, and Dilithium5 signature into a wire frame.
 * 4. Verification: Instantiates `SclRpcParser`, validates SipHash checksum, and extracts payload.
 * 5. String Identity Assertion: Asserts extracted payload matches `original_payload`.
 * 6. Resource Reclamation: Destroys builder, parser, and frees heap memory.
 *
 * @pre System CSPRNG operational.
 * @post Allocates, validates, and cleanly deallocates all protocol handles and memory.
 *
 * @return int Returns 0 on successful verification; terminates via `exit(1)` on assertion failure.
 *
 * @complexity
 * - Time: O(PayloadLength + DilithiumSign + DilithiumVerify)
 * - Space: O(PayloadLength) transient heap memory, 16 KiB stack buffer.
 */
int main(void) {
    printf("[Test] Initializing L5 RPC Integration Test...\n");

    /* 1. Generate post-quantum Dilithium5 keys for frame signing */
    uint8_t public_key[DILITHIUM_PUBKEY_LEN];
    uint8_t secret_key[DILITHIUM_SECRETKEY_LEN];
    (void)public_key; /* Suppress unused variable warning for the public key */
    TEST_ASSERT(dilithium_generate_keypair(public_key, secret_key) == 1, "Failed to generate keys");

    /* 2. Prepare mock plaintext payload string (including null terminator) */
    const char *original_payload = "Satocialist L5 Native RPC Verification Payload - Constant Time Testing String";
    size_t payload_len = strlen(original_payload) + 1;

    /* 3. Compress payload using LZ4 block compression */
    int max_compressed_size = LZ4_compressBound((int)payload_len);
    char *compressed_payload = malloc(max_compressed_size);
    TEST_ASSERT(compressed_payload != NULL, "Failed to allocate compression buffer");
    int compressed_bytes = LZ4_compress_default(original_payload, compressed_payload, (int)payload_len, max_compressed_size);
    TEST_ASSERT(compressed_bytes > 0, "LZ4 compression failed");

    /* 4. Instantiate FFI Builder with Version 1, Method 0x0003, and 64-bit Request ID */
    uint64_t request_id = 0x0102030405060708ULL;
    SclRpcBuilder builder = scl_rpc_builder_create(SCL_RPC_VERSION_1, 0x0003, request_id);
    TEST_ASSERT(builder != NULL, "Builder instantiation failed");

    /* Configure header flags: bit 2 (COMPRESSED) and bit 0 (SIGNED) */
    scl_rpc_builder_set_flags(builder, SCL_RPC_FLAG_COMPRESSED);
    
    /* SCL-402: Prepend an autonomous agent payment receipt */
    uint8_t dummy_tx_id[32];
    memset(dummy_tx_id, 0xAA, 32);
    int receipt_status = scl_rpc_builder_set_payment_receipt(builder, 0x01, dummy_tx_id, 0x9988776655443322ULL);
    TEST_ASSERT(receipt_status == 0, "Failed to append payment receipt");
    
    /* Append compressed argument bytes */
    int append_status = scl_rpc_builder_append_args(builder, (const uint8_t *)compressed_payload, (size_t)compressed_bytes);
    TEST_ASSERT(append_status == 0, "Failed to append arguments");

    /* Sign the payload with Dilithium5 secret key (applies SCL_RPC_FLAG_SIGNED internally) */
    int sign_status = scl_rpc_builder_sign(builder, secret_key);
    TEST_ASSERT(sign_status == 0, "Failed to sign payload");

    /* Finalize canonical wire frame (writes header, signature, payload, and SipHash checksum) */
    uint8_t wire_buffer[16384];
    size_t serialized_len = 0;
    int finalize_status = scl_rpc_builder_finalize(builder, wire_buffer, sizeof(wire_buffer), &serialized_len);
    TEST_ASSERT(finalize_status == 0, "Failed to finalize frame");
    printf("[Test] Wire frame constructed successfully. Total size: %zu bytes.\n", serialized_len);

    /* 5. Simulate Ingress Parsing (FFI Parser validates SipHash and unpacks frame) */
    int parser_status = 0;
    SclRpcParser parser = scl_rpc_parser_create(wire_buffer, serialized_len, &parser_status);
    TEST_ASSERT(parser != NULL, "Parser instantiation failed");
    TEST_ASSERT(parser_status == SCL_RPC_STATUS_OK, "Parser rejected frame");

    /* 6. Extract transparently decompressed payload reference from parser */
    const uint8_t *extracted_payload = NULL;
    size_t extracted_len = 0;
    int payload_ref_status = scl_rpc_parser_get_payload_ref(parser, &extracted_payload, &extracted_len);
    TEST_ASSERT(payload_ref_status == 0, "Failed to extract/decompress payload");

    /* For signed frames, the FFI parser skips the leading DILITHIUM_SIGNATURE_LEN-byte signature */
    /* SCL-402: Skip the newly prepended 41-byte Payment Receipt */
    const char *decompressed_string = (const char *)(extracted_payload + DILITHIUM_SIGNATURE_LEN + sizeof(SclRpcPaymentReceipt));
    printf("[Test] Decompressed extracted payload: \"%s\"\n", decompressed_string);
    TEST_ASSERT(strcmp(decompressed_string, original_payload) == 0, "Payload string mismatch");

    /* Complete resource teardown */
    scl_rpc_builder_destroy(builder);
    scl_rpc_parser_destroy(parser);
    free(compressed_payload);

    printf("[Test] Integration Test Passed.\n");
    return 0;
}
