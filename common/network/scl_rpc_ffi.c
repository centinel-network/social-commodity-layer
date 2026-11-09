/**
 * @file common/network/scl_rpc_ffi.c
 * @brief Satocialist Protocol: Foreign Function Interface (FFI) & Binary Wire Serialization C-ABI Implementation
 *
 * @details
 * Implements the stable C-ABI export functions and convenience framing constructors for the native L5 RPC protocol.
 * Exported across shared library boundaries (`libscl_rpc.so`, `libscl_rpc.dylib`) and cross-compiled into
 * WebAssembly bytecode (`libscl_rpc.wasm`) via Emscripten for browser UI and WebWorker integration.
 *
 * Core architectural functions implemented:
 * 1. Opaque Builder Lifecycle: Allocation, argument appending, signing, wire finalization, and destruction.
 * 2. Opaque Parser Lifecycle: Ingress wire boundary decoding, flags extraction, error unpacking, and payload retrieval.
 * 3. Transparent LZ4 Decompression: Automatic client-side decompression of compressed payload blocks up to 8 MiB.
 * 4. SipHash-2-4 Wire Verification: Fast 64-bit checksum verification against shared session keys.
 * 5. Optimized Query Constructors: Specialized zero-copy wire frame builders for explorer and client queries.
 * 6. Micropayment Challenge & Receipt Handling: Challenge extraction and payment receipt wire framing.
 *
 * @section protocol_invariants Protocol Invariants
 * - Binary Wire Alignment: Wire frames conform strictly to @ref SclRpcHeader: 32 bytes packed, network byte order.
 * - Single-Threaded Handle Affinity: `SclRpcBuilder` and `SclRpcParser` handles are thread-affine and not thread-safe.
 * - Borrowed Payload Lifetime: Pointers returned by `scl_rpc_parser_get_payload_ref` are borrowed from internal buffers
 *   and become invalid immediately upon calling `scl_rpc_parser_destroy`.
 *
 * @section cross_platform_linking Dynamic Linking & Linker Stubs
 * When compiled into a standalone shared library or WebAssembly target, weak symbols (`SCL_WEAK`) resolve
 * unresolved consensus and transport symbols to enable independent execution of cryptographic framing routines.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <lz4.h>
#include "scl_rpc_ffi_export.h"
#include "crypto.h"
#include "types.h"
#include "utils.h"

/* ============================================================================ */
/* SECTION 1: GLOBAL LINKER SYMBOLS & WEAK ISOLATION STUBS                     */
/* ============================================================================ */

// Fallback weak stubs to satisfy linker when compiled as standalone libscl_rpc library
/** @brief Global shutdown sentinel exported to satisfy shared library linking references. */
atomic_bool global_shutdown = false;
/** @brief Global state context pointer exported to satisfy shared library linking references. */
State *global_state = NULL;

#if defined(__GNUC__) || defined(__clang__)
#define SCL_WEAK __attribute__((weak))
#else
#define SCL_WEAK
#endif

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
SCL_WEAK int add_valuation(State *state, Valuation *valuation) { (void)state; (void)valuation; return -1; }
SCL_WEAK void auto_simulate(State *state, User *user, const Valuation *val, int target_index) { (void)state; (void)user; (void)val; (void)target_index; }
SCL_WEAK int calculate_current_stage(uint64_t total_rewarded_subunits, uint64_t total_staked_subunits) { (void)total_rewarded_subunits; (void)total_staked_subunits; return 2; }
#endif

SCL_WEAK void crypto_verify_enqueue(State *state, SclConnection *conn, const Message *msg, const uint8_t *sender_pubkey, const struct sockaddr_storage *sender_addr) { (void)state; (void)conn; (void)msg; (void)sender_pubkey; (void)sender_addr; }
SCL_WEAK void handle_coin_transfer(P2PNetwork *net, State *state, Message *msg, uint8_t *sender_pubkey) { (void)net; (void)state; (void)msg; (void)sender_pubkey; }
SCL_WEAK void handle_vote(State *state, Message *msg, uint8_t *sender_pubkey) { (void)state; (void)msg; (void)sender_pubkey; }

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
SCL_WEAK int register_user(State *state, const uint8_t *user_id, const uint8_t *pubkey) { (void)state; (void)user_id; (void)pubkey; return -1; }
SCL_WEAK int select_proposer(State *state, uint64_t epoch, uint8_t *proposer_pubkey_out) { (void)state; (void)epoch; (void)proposer_pubkey_out; return -1; }
#endif

#if defined(__EMSCRIPTEN__)
SCL_WEAK void free_block(Block *block) {
    if (block) {
        if (block->operations) {
            free(block->operations);
        }
        if (block->batch_prf_outputs) {
            free(block->batch_prf_outputs);
        }
        if (block->batch_zk_proof) {
            free(block->batch_zk_proof);
        }
        free(block);
    }
}
#endif

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
SCL_WEAK void send_audit_to_client(State *state, const uint8_t *pubkey) { (void)state; (void)pubkey; }
#endif
SCL_WEAK void reset_simulated_valuation(int target_index) { (void)target_index; }
SCL_WEAK void recheck_and_mint_unminted_valuations(State *state) { (void)state; }
SCL_WEAK void trigger_async_sync(State *state, const uint8_t *peer_pubkey, bool force) { (void)state; (void)peer_pubkey; (void)force; }

#if defined(__EMSCRIPTEN__)
uint64_t calculate_staked_subunits_by_owner(State *state, const uint8_t target_pk[PUBKEY_LEN]) { (void)state; (void)target_pk; return 0; }
int quantum_check_number_in_column(int target_number, const int *column_numbers, size_t N, size_t active_nodes, const uint8_t *beacon_seed) { (void)target_number; (void)column_numbers; (void)N; (void)active_nodes; (void)beacon_seed; return 0; }
int queue_enqueue(Queue *q, const Message *msg) { (void)q; (void)msg; return -1; }
void trigger_async_fork_processing(State *state) { (void)state; }
int validate_operation(State *state, const Operation *op) { (void)state; (void)op; return 0; }
int apply_block(State *state, Block *block) { (void)state; (void)block; return -1; }
void p2p_broadcast(State *state, const Message *msg) { (void)state; (void)msg; }
void scl_initiate_connection(P2PNetwork *net, const struct sockaddr_storage *addr) { (void)net; (void)addr; }
int create_and_broadcast_transfer(State *state, const uint8_t *recipient_pubkey, uint64_t amount_subunits, bool is_recreation) { (void)state; (void)recipient_pubkey; (void)amount_subunits; (void)is_recreation; return -1; }
int create_and_broadcast_stake(State *state, uint64_t amount_subunits, bool is_recreation) { (void)state; (void)amount_subunits; (void)is_recreation; return -1; }
int create_and_broadcast_unstake(State *state, uint64_t amount_subunits, bool is_recreation) { (void)state; (void)amount_subunits; (void)is_recreation; return -1; }
uint64_t calculate_staked_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN]) { (void)bc; (void)pubkey; return 0; }
uint64_t calculate_fees_paid_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN]) { (void)bc; (void)pubkey; return 0; }
uint64_t calculate_total_staked_subunits(const Blockchain *bc) { (void)bc; return 0; }
void bloom_filter_add(uint8_t *filter, const uint8_t *cid) { (void)filter; (void)cid; }
bool scl_db_has_nullifier(const uint8_t *nullifier) { (void)nullifier; return false; }
void *hash_table_lookup(HashTable *ht, const uint8_t *key, bool return_entry) { (void)ht; (void)key; (void)return_entry; return NULL; }
bool hash_table_insert(HashTable *ht, const uint8_t *key, void *value, HashEntryType type) { (void)ht; (void)key; (void)value; (void)type; return false; }
bool hash_table_remove(HashTable *ht, const uint8_t *key) { (void)ht; (void)key; return false; }
void blockchain_add_pointer(Blockchain *bc, const Pointer *pointer) { (void)bc; (void)pointer; }
uint64_t calculate_total_fees_subunits(const Blockchain *bc) { (void)bc; return 0; }
int p2p_remove_peer_by_pubkey(P2PNetwork *net, const uint8_t *pubkey) { (void)net; (void)pubkey; return 0; }
void add_pointer_id_to_coin(HashTable *coin_pointers, const uint8_t *coin_id, const uint8_t *pointer_id) { (void)coin_pointers; (void)coin_id; (void)pointer_id; }
void remove_pointer_id_from_coin(HashTable *coin_pointers, const uint8_t *coin_id, const uint8_t *pointer_id) { (void)coin_pointers; (void)coin_id; (void)pointer_id; }
int scl_db_put_coin(const uint8_t *coin_id, const SCLCoin *coin) { (void)coin_id; (void)coin; return -1; }
int scl_db_put_pointer(const uint8_t *pointer_id, const Pointer *pointer) { (void)pointer_id; (void)pointer; return -1; }
int scl_db_write_nullifiers_batch(uint8_t (*nullifiers)[NULLIFIER_LEN], size_t count) { (void)nullifiers; (void)count; return -1; }
void rotate_epoch_key(State *state, const uint8_t *pubkey, const uint8_t committee[10][PUBKEY_LEN], size_t count) { (void)state; (void)pubkey; (void)committee; (void)count; }
void p2p_share_peers(State *state, uint8_t *recipient_pubkey) { (void)state; (void)recipient_pubkey; }
#endif

/* ============================================================================ */
/* SECTION 2: OPAQUE FRAME BUILDER IMPLEMENTATION                              */
/* ============================================================================ */

/**
 * @brief Allocates and initializes an opaque RPC frame builder context.
 *
 * @param[in] version Protocol wire version (must be @ref SCL_RPC_VERSION_1 = 0x01).
 * @param[in] method_id Target method identifier opcode (e.g., 0x0001 for GetBalance).
 * @param[in] request_id 64-bit monotonic tracking ID (timestamp << 16 | salt).
 * @return Opaque SclRpcBuilder pointer; NULL on allocation failure.
 *
 * @pre None.
 * @post Allocates `struct BuilderInternal` with an initial 4,096-byte payload buffer.
 * @thread_safety Single-threaded handle ownership. Distinct handles can execute concurrently.
 * @complexity Time: O(1), Space: O(1) initial heap buffer.
 */
SclRpcBuilder scl_rpc_builder_create(uint8_t version, uint16_t method_id, uint64_t request_id) {
    // Initialize builder context with 4 KiB initial payload capacity
    struct BuilderInternal *b = calloc(1, sizeof(struct BuilderInternal));
    if (b) {
        b->version = version;
        b->method_id = method_id;
        b->request_id = request_id;
        b->payload_cap = 4096;
        b->payload = malloc(b->payload_cap);
        if (!b->payload) {
            free(b);
            return NULL;
        }
    }
    return b;
}

/**
 * @brief Configures operational flags on an RPC frame builder.
 *
 * @param[in,out] builder Opaque builder handle.
 * @param[in] flags Bitmask of flags (`SCL_RPC_FLAG_SIGNED`, `SCL_RPC_FLAG_PAGINATED`, `SCL_RPC_FLAG_COMPRESSED`).
 *
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_builder_set_flags(SclRpcBuilder builder, uint8_t flags) {
    if (builder) ((struct BuilderInternal *)builder)->flags = flags;
}

/**
 * @brief Sets the pagination cursor or block height parameter on an RPC frame builder.
 *
 * @param[in,out] builder Opaque builder handle.
 * @param[in] cursor 32-bit big-endian pagination offset or block height.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_builder_set_cursor(SclRpcBuilder builder, uint32_t cursor) {
    if (builder) ((struct BuilderInternal *)builder)->cursor = cursor;
}

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
int scl_rpc_builder_append_pubkey(SclRpcBuilder builder, const uint8_t* pubkey, size_t len) {
    if (!builder || !pubkey) return -1;
    struct BuilderInternal *b = (struct BuilderInternal *)builder;
    // Enforce maximum wire message bound (8 MiB)
    if (b->payload_len + len > MAX_MESSAGE_SIZE) return -1;
    // Dynamically expand capacity with geometric 2x growth factor
    if (b->payload_len + len > b->payload_cap) {
        size_t new_cap = (b->payload_len + len) * 2;
        if (new_cap > MAX_MESSAGE_SIZE) new_cap = MAX_MESSAGE_SIZE;
        uint8_t *new_p = realloc(b->payload, new_cap);
        if (!new_p) return -1;
        b->payload = new_p;
        b->payload_cap = new_cap;
    }
    memcpy(b->payload + b->payload_len, pubkey, len);
    b->payload_len += len;
    return 0;
}

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
int scl_rpc_builder_append_args(SclRpcBuilder builder, const uint8_t* payload, size_t len) {
    return scl_rpc_builder_append_pubkey(builder, payload, len);
}

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
int scl_rpc_builder_sign(SclRpcBuilder builder, const uint8_t* dilithium_privkey) {
    if (!builder || !dilithium_privkey) return -1;
    struct BuilderInternal *b = (struct BuilderInternal *)builder;
    
    size_t digest_input_len = 24 + b->payload_len;
    uint8_t *digest_input = malloc(digest_input_len);
    if (!digest_input) return -1;
    
    // Construct pre-digest buffer: normalized 24-byte header prefix + arguments
    SclRpcHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = b->version;
    hdr.flags = b->flags | 1;
    hdr.status_code = htobe16(0);
    hdr.method_id = htobe16(b->method_id);
    hdr.error_msg_len = htobe16(0);
    hdr.request_id = htobe64(b->request_id);
    hdr.payload_len = htobe32(b->payload_len + DILITHIUM_SIGNATURE_LEN);
    hdr.cursor = htobe32(b->cursor);
    
    // Ensure strict 24-byte isolation to prevent stack padding bleed
    memset(digest_input, 0, digest_input_len);
    memcpy(digest_input, &hdr, 24);
    if (b->payload_len > 0) {
        memcpy(digest_input + 24, b->payload, b->payload_len);
    }
    
    // Compute post-quantum ML-DSA-87 digital signature
    uint8_t sig[DILITHIUM_SIGNATURE_LEN];
    if (dilithium_sign(digest_input, 24 + b->payload_len, dilithium_privkey, sig) != 1) {
        free(digest_input);
        return -1;
    }
    
    free(digest_input);
    
    // Prepend signature to payload buffer and assert SCL_RPC_FLAG_SIGNED
    if (b->payload_len + DILITHIUM_SIGNATURE_LEN > b->payload_cap) {
        size_t new_cap = b->payload_len + DILITHIUM_SIGNATURE_LEN + 1024;
        uint8_t *new_p = realloc(b->payload, new_cap);
        if (!new_p) return -1;
        b->payload = new_p;
        b->payload_cap = new_cap;
    }

    if (b->payload_len > 0) {
        memmove(b->payload + DILITHIUM_SIGNATURE_LEN, b->payload, b->payload_len);
    }
    memcpy(b->payload, sig, DILITHIUM_SIGNATURE_LEN);
    b->payload_len += DILITHIUM_SIGNATURE_LEN;
    b->flags |= 1; // SCL_RPC_FLAG_SIGNED
    
    return 0;
}

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
int scl_rpc_builder_finalize(SclRpcBuilder builder, uint8_t* out_buffer, size_t max_len, size_t* serialized_len) {
    if (!builder || !out_buffer || !serialized_len) return -1;
    struct BuilderInternal *b = (struct BuilderInternal *)builder;
    
    size_t total_len = sizeof(SclRpcHeader) + b->payload_len;
    if (total_len > max_len) return -1;
    
    // Populate final 32-byte header in network byte order (Big-Endian)
    SclRpcHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = b->version;
    hdr.flags = b->flags;
    hdr.status_code = htobe16(0);
    hdr.method_id = htobe16(b->method_id);
    hdr.error_msg_len = htobe16(0);
    hdr.request_id = htobe64(b->request_id);
    hdr.payload_len = htobe32(b->payload_len);
    hdr.cursor = htobe32(b->cursor);
    
    // The FFI wrapper delegates connection-specific SipHash calculation to the L4 multiplexer
    hdr.checksum = htobe64(0);
    
    // Copy header followed by payload body into destination output buffer
    memcpy(out_buffer, &hdr, sizeof(SclRpcHeader));
    if (b->payload_len > 0) {
        memcpy(out_buffer + sizeof(SclRpcHeader), b->payload, b->payload_len);
    }
    
    *serialized_len = total_len;
    return 0;
}

/**
 * @brief Destroys an RPC builder context and releases all allocated payload memory.
 *
 * @param[in,out] builder Opaque builder handle to deallocate (safe if NULL).
 *
 * @post Internal buffer freed; builder pointer invalidated.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_builder_destroy(SclRpcBuilder builder) {
    if (builder) {
        struct BuilderInternal *b = (struct BuilderInternal *)builder;
        if (b->payload) free(b->payload);
        free(b);
    }
}

/* ============================================================================ */
/* SECTION 3: OPAQUE FRAME PARSER IMPLEMENTATION                               */
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
SclRpcParser scl_rpc_parser_create(const uint8_t* wire_bytes, size_t len, int* out_status) {
    if (!wire_bytes || len < sizeof(SclRpcHeader)) {
        if (out_status) *out_status = 0x0001; // SCL_RPC_STATUS_BAD_VERSION
        return NULL;
    }
    
    SclRpcHeader hdr;
    memcpy(&hdr, wire_bytes, sizeof(SclRpcHeader));
    
    uint16_t err_len = be16toh(hdr.error_msg_len);
    uint32_t payload_len = be32toh(hdr.payload_len);
    
    // Subtraction-based bounds check to prevent integer wrap-around vulnerability
    if (len < sizeof(SclRpcHeader) || len - sizeof(SclRpcHeader) < err_len || len - sizeof(SclRpcHeader) - err_len < payload_len) {
        if (out_status) *out_status = 0x0001; // SCL_RPC_STATUS_BAD_VERSION
        return NULL;
    }
    
    // Checksum verified at node ingress independently
    struct ParserInternal *p = calloc(1, sizeof(struct ParserInternal));
    if (p) {
        p->version = hdr.version;
        p->flags = hdr.flags;
        p->status_code = be16toh(hdr.status_code);
        p->method_id = be16toh(hdr.method_id);
        p->request_id = be64toh(hdr.request_id);
        p->cursor = be32toh(hdr.cursor);
        // Extract error diagnostic string if present in wire frame
        if (err_len > 0) {
            size_t copy_err = (err_len > 255) ? 255 : err_len;
            memcpy(p->error_msg, wire_bytes + sizeof(SclRpcHeader), copy_err);
            p->error_msg[copy_err] = '\0';
        }
        // Allocate internal payload buffer and copy message contents
        if (payload_len > 0 && payload_len <= MAX_MESSAGE_SIZE) {
            p->payload = malloc(payload_len);
            if (p->payload) {
                memcpy(p->payload, wire_bytes + sizeof(SclRpcHeader) + err_len, payload_len);
                p->payload_len = payload_len;
            }
        }
        if (out_status) *out_status = p->status_code;
    }
    return p;
}

/**
 * @brief Extracts the protocol version from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Protocol version byte (e.g., 0x01).
 */
uint8_t scl_rpc_parser_get_version(SclRpcParser parser) { return parser ? ((struct ParserInternal *)parser)->version : 0; }

/**
 * @brief Extracts the operational flags bitmask from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Flags bitmask (`SCL_RPC_FLAG_SIGNED`, `SCL_RPC_FLAG_PAGINATED`, `SCL_RPC_FLAG_COMPRESSED`).
 */
uint8_t scl_rpc_parser_get_flags(SclRpcParser parser) { return parser ? ((struct ParserInternal *)parser)->flags : 0; }

/**
 * @brief Extracts the execution status code from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Big-endian status code (e.g., @ref SCL_RPC_STATUS_OK).
 */
uint16_t scl_rpc_parser_get_status(SclRpcParser parser) { return parser ? ((struct ParserInternal *)parser)->status_code : 0; }

/**
 * @brief Extracts the method opcode identifier from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return Method opcode (0x0000..0x000B).
 */
uint16_t scl_rpc_parser_get_method_id(SclRpcParser parser) { return parser ? ((struct ParserInternal *)parser)->method_id : 0; }

/**
 * @brief Extracts the 64-bit request tracking identifier from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return 64-bit request ID.
 */
uint64_t scl_rpc_parser_get_request_id(SclRpcParser parser) { return parser ? ((struct ParserInternal *)parser)->request_id : 0; }

/**
 * @brief Extracts the pagination cursor or block height parameter from a parsed frame header.
 *
 * @param[in] parser Opaque parser handle.
 * @return 32-bit cursor offset or block height.
 */
uint32_t scl_rpc_parser_get_cursor(SclRpcParser parser) { return parser ? ((struct ParserInternal *)parser)->cursor : 0; }

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
int scl_rpc_parser_get_error(SclRpcParser parser, char* out_str, size_t max_len) {
    if (!parser || !out_str || max_len == 0) return -1;
    struct ParserInternal *p = (struct ParserInternal *)parser;
    if (strlen(p->error_msg) == 0) return -1;
    strncpy(out_str, p->error_msg, max_len - 1);
    out_str[max_len - 1] = '\0';
    return 0;
}

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
int scl_rpc_parser_get_payload_ref(SclRpcParser parser, const uint8_t** out_ptr, size_t* out_len) {
    if (!parser || !out_ptr || !out_len) return -1;
    struct ParserInternal *p = (struct ParserInternal *)parser;
    
    if ((p->flags & 4) && p->payload_len > 0) { // SCL_RPC_FLAG_COMPRESSED
#ifdef __EMSCRIPTEN__
        static uint8_t decomp_buf[MAX_MESSAGE_SIZE]; // Max 8MB
#else
        static _Thread_local uint8_t decomp_buf[MAX_MESSAGE_SIZE]; // Max 8MB
#endif
        
        // Skip signature and payment receipt headers if present
        size_t sig_len = (p->flags & 1) ? DILITHIUM_SIGNATURE_LEN : 0;
        size_t receipt_len = (p->flags & SCL_RPC_FLAG_PAYMENT_RECEIPT) ? sizeof(SclRpcPaymentReceipt) : 0;
        size_t prefix_len = sig_len + receipt_len;
        if (p->payload_len < prefix_len) return -1;
        
        if (sig_len > 0) {
            memcpy(decomp_buf, p->payload, sig_len); // Preserve raw signature
        }
        if (receipt_len > 0) {
            memcpy(decomp_buf + sig_len, p->payload + sig_len, receipt_len); // Preserve raw payment receipt
        }
        
        size_t comp_len = p->payload_len - prefix_len;
        const uint8_t *comp_src = p->payload + prefix_len;
        
        int decomp_bytes = LZ4_decompress_safe((const char *)comp_src,
                                               (char *)(decomp_buf + prefix_len),
                                               (int)comp_len,
                                               (int)(MAX_MESSAGE_SIZE - prefix_len));
        if (decomp_bytes < 0 || (size_t)(prefix_len + decomp_bytes) > MAX_MESSAGE_SIZE) {
            return -1; // Decompression failure or bomb protection
        }
        
        *out_ptr = decomp_buf;
        *out_len = prefix_len + decomp_bytes;
        return 0;
    }
    
    // Return direct borrowed reference to uncompressed payload
    *out_ptr = p->payload;
    *out_len = p->payload_len;
    return 0;
}

int scl_rpc_parser_get_payment_challenge(SclRpcParser parser, SclRpcPaymentChallenge *out_challenge) {
    if (!parser || !out_challenge) return -1;
    struct ParserInternal *p = (struct ParserInternal *)parser;
    
    // Validate target status and available payload memory
    if (p->status_code != SCL_RPC_STATUS_PAYMENT_REQUIRED) return -1;
    if (p->payload_len < sizeof(SclRpcPaymentChallenge)) return -1;
    
    // Copy the raw payload
    memcpy(out_challenge, p->payload, sizeof(SclRpcPaymentChallenge));
    
    // Normalize to host byte order for the UI
    out_challenge->amount_subunits = be64toh(out_challenge->amount_subunits);
    out_challenge->price_rate_lock_id = be64toh(out_challenge->price_rate_lock_id);
    out_challenge->valid_until_timestamp = be64toh(out_challenge->valid_until_timestamp);
    out_challenge->accepted_payment_types = be16toh(out_challenge->accepted_payment_types);
    
    return 0;
}

int scl_rpc_builder_set_payment_receipt(SclRpcBuilder builder, uint8_t payment_type, const uint8_t *tx_id, uint64_t rate_lock_id) {
    if (!builder || !tx_id) return -1;
    struct BuilderInternal *b = (struct BuilderInternal *)builder;
    
    SclRpcPaymentReceipt receipt;
    receipt.payment_type = payment_type;
    memcpy(receipt.tx_id, tx_id, 32);
    receipt.price_rate_lock_id = htobe64(rate_lock_id);

    // Flag the frame as carrying a receipt
    b->flags |= SCL_RPC_FLAG_PAYMENT_RECEIPT;
    
    // Append the 41-byte receipt structurally ahead of generic payload args
    return scl_rpc_builder_append_args(builder, (const uint8_t *)&receipt, sizeof(SclRpcPaymentReceipt));
}

/**
 * @brief Destroys a parser context and releases its allocated memory.
 *
 * @param[in,out] parser Opaque parser handle to deallocate (safe if NULL).
 *
 * @post Internal buffer freed; parser handle invalidated.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_rpc_parser_destroy(SclRpcParser parser) {
    if (parser) {
        struct ParserInternal *p = (struct ParserInternal *)parser;
        if (p->payload) free(p->payload);
        free(p);
    }
}

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
int scl_rpc_verify_checksum(const uint8_t* wire_bytes, size_t len, const uint8_t rpc_siphash_key[16]) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    (void)wire_bytes; (void)len; (void)rpc_siphash_key;
    return 0;
#else
    if (!wire_bytes || len < sizeof(SclRpcHeader)) return -1;
    
    SclRpcHeader hdr;
    memcpy(&hdr, wire_bytes, sizeof(SclRpcHeader));
    
    uint64_t checksum = be64toh(hdr.checksum);
    if (checksum == 0) {
        return 0; // Gracefully pass unchecksummed local loopback diagnostic traffic
    }
    
    uint16_t err_len = be16toh(hdr.error_msg_len);
    uint32_t payload_len = be32toh(hdr.payload_len);
    
    // Validate wire framing bounds against error message and payload lengths
    if (len < sizeof(SclRpcHeader) || len - sizeof(SclRpcHeader) < err_len || len - sizeof(SclRpcHeader) - err_len < payload_len) {
        return -1;
    }
    
    // Recompute SipHash-2-4 over wire frame and compare with header checksum
    uint64_t computed = compute_rpc_checksum(wire_bytes, err_len, payload_len, rpc_siphash_key);
    
    return (checksum == computed) ? 0 : -2;
#endif
}

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
int scl_rpc_frame_balance_query(uint64_t request_id, const uint8_t* target_pubkey, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x0001: Query liquid/staked balances, fees, and private UTXOs for target Dilithium5 pubkey
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x0001, request_id); // SCL_RPC_VERSION_1
    if (!b) return -1;
    scl_rpc_builder_append_pubkey(b, target_pubkey, 2592); // DILITHIUM_PUBKEY_LEN
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_recent_txs(uint64_t request_id, uint32_t cursor, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x0006: Paginated scan over recent mempool and on-chain transactions
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x0006, request_id);
    if (!b) return -1;
    scl_rpc_builder_set_flags(b, 2); // SCL_RPC_FLAG_PAGINATED
    scl_rpc_builder_set_cursor(b, cursor);
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_get_tx(uint64_t request_id, const uint8_t* tx_hash, size_t hash_len, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x0007: Lookup confirmed transaction by 32-byte hash
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x0007, request_id);
    if (!b) return -1;
    scl_rpc_builder_append_args(b, tx_hash, hash_len);
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_chain_info(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x0008: Query blockchain height, metrics, committee, and node credentials
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x0008, request_id);
    if (!b) return -1;
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_valuations_query(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x0005: Query game emission progress and consensus stage
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x0005, request_id);
    if (!b) return -1;
    scl_rpc_builder_set_flags(b, SCL_RPC_FLAG_COMPRESSED);
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_audit_query(uint64_t request_id, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x0004: Query 10x10 Game Audit circular valuation matrix
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x0004, request_id);
    if (!b) return -1;
    scl_rpc_builder_set_flags(b, SCL_RPC_FLAG_COMPRESSED);
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_block_query(uint64_t request_id, uint32_t height, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x0002: Stream block at specified chain height
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x0002, request_id);
    if (!b) return -1;
    scl_rpc_builder_set_flags(b, SCL_RPC_FLAG_PAGINATED | SCL_RPC_FLAG_COMPRESSED);
    scl_rpc_builder_set_cursor(b, height);
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_quantum_tvd_audit(uint64_t request_id, uint32_t shots, const uint8_t* beacon_seed, const uint8_t* circuit_bytes, size_t circuit_len, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x000A: Request Total Variation Distance drift certification
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x000A, request_id);
    if (!b) return -1;
    uint32_t shots_be = htobe32(shots);
    scl_rpc_builder_append_args(b, (const uint8_t *)&shots_be, 4);
    uint8_t zero_seed[32] = {0};
    scl_rpc_builder_append_args(b, beacon_seed ? beacon_seed : zero_seed, 32);
    if (circuit_bytes && circuit_len > 0) {
        scl_rpc_builder_append_args(b, circuit_bytes, circuit_len);
    }
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

/**
 * @brief Constructs a wire frame for dispatching a Drift Certificate Histogram Audit request (Method 0x000D).
 *
 * @param[in] request_id 64-bit request identifier.
 * @param[in] shots Measurement shot count budget (1..100,000).
 * @param[in] beacon_seed Optional 32-byte DKG beacon seed (NULL defaults to zero seed).
 * @param[in] histogram Pointer to 128 Big-Endian u32 basis-state measurement counts.
 * @param[in] circuit_bytes Optional OpenQASM circuit byte stream.
 * @param[in] circuit_len Byte length of circuit stream.
 * @param[out] out_frame Output wire frame buffer.
 * @param[in] max_len Buffer capacity.
 * @param[out] out_len Destination receiving exact serialized frame length.
 * @return 0 on success; negative value on buffer overflow.
 *
 * @complexity Time: O(circuit_len), Space: O(1).
 */
int scl_rpc_frame_drift_cert_audit(uint64_t request_id, uint32_t shots, const uint8_t* beacon_seed, const uint32_t* histogram, const uint8_t* circuit_bytes, size_t circuit_len, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x000D: Enterprise drift certificate histogram audit (TVD platform)
    static const uint16_t kDriftHistogramDim = 128;
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x000D, request_id);
    if (!b) return -1;
    uint32_t shots_be = htobe32(shots);
    scl_rpc_builder_append_args(b, (const uint8_t *)&shots_be, 4);
    uint8_t zero_seed[32] = {0};
    scl_rpc_builder_append_args(b, beacon_seed ? beacon_seed : zero_seed, 32);
    uint16_t dim_be = htobe16(kDriftHistogramDim);
    scl_rpc_builder_append_args(b, (const uint8_t *)&dim_be, 2);
    if (histogram) {
        uint8_t hist_wire[512];
        for (uint16_t i = 0; i < kDriftHistogramDim; i++) {
            uint32_t count_be = htobe32(histogram[i]);
            memcpy(hist_wire + (size_t)i * 4, &count_be, 4);
        }
        scl_rpc_builder_append_args(b, hist_wire, sizeof(hist_wire));
    }
    if (circuit_bytes && circuit_len > 0) {
        scl_rpc_builder_append_args(b, circuit_bytes, circuit_len);
    }
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}

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
int scl_rpc_frame_autopilot(uint64_t request_id, int enable, uint32_t val_per_hr, uint32_t stake_ratio, uint8_t* out_frame, size_t max_len, size_t* out_len) {
    // Method 0x000B: Configure autonomous portfolio rebalancing and valuation daemon
    SclRpcBuilder b = scl_rpc_builder_create(0x01, 0x000B, request_id);
    if (!b) return -1;
    if (enable >= 0) {
        uint8_t payload[9];
        payload[0] = (uint8_t)(enable ? 1 : 0);
        uint32_t v_be = htobe32(val_per_hr);
        memcpy(payload + 1, &v_be, 4);
        uint32_t s_be = htobe32(stake_ratio);
        memcpy(payload + 5, &s_be, 4);
        scl_rpc_builder_append_args(b, payload, 9);
    }
    int ret = scl_rpc_builder_finalize(b, out_frame, max_len, out_len);
    scl_rpc_builder_destroy(b);
    return ret;
}
