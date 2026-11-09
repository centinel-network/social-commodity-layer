/**
 * @file common/network/protocol.c
 * @brief Satocialist Protocol: Wire Serialization, Packet Framing, and Deserialization Engine Implementation
 *
 * @details
 * Implements binary wire encoding, endianness conversions, streaming deserialization cursors,
 * and structural validation routines for all on-chain operations, peer-to-peer envelopes,
 * Merkle Mountain Range (MMR) inclusion proofs, and polynomial vectors across the SCL protocol.
 *
 * @section protocol_invariants Enforced Invariants
 * - Network Byte Order Invariance: Multi-byte fields (`uint16_t`, `uint32_t`, `uint64_t`) are
 *   strictly formatted in Big-Endian order via `htobe16`/`htobe32`/`htobe64` on egress and
 *   restored via `be16toh`/`be32toh`/`be64toh` on ingress.
 * - Maximum Transmission Limits: Packets and messages exceeding @ref MAX_MESSAGE_SIZE (8,388,608 bytes)
 *   are rejected prior to memory allocation or processing.
 * - Single-Pass Consensus Hashing Parity: Block serialization in @ref serialize_block delegates to
 *   @ref process_block_data to guarantee that the serialized wire image matches the canonical SHA-256
 *   header digest exactly bit-for-bit without discrepancies.
 * - Polynomial Coefficient Bounds: Ring elements ($p \in R_q$) must have coefficients strictly bounded
 *   within $|c| \le Q/2$ post-deserialization.
 * - ZK Proof Payload Bounds: Zero-knowledge proofs and nullifiers are strictly bounded by
 *   @ref ZK_PROOF_MAX_LEN to prevent buffer overflows during consensus verification.
 *
 * @section memory_concurrency Threading Model & Memory Scoping
 * - Functions are stateless and reentrant.
 * - High-concurrency deserialization allocates complex nested transaction structures
 *   (`TransferData`) directly from thread-local memory arenas (`arena_alloc`), eliminating
 *   dynamic heap fragmentation under heavy network load.
 */

#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "protocol.h"
#include "hash_table.h"
#include "network.h"
#include "blockchain.h"
#include "consensus.h"
#include "constants.h"
#include "crypto.h"
#include "utils.h"

/* Route local diagnostic logging directly through structured telemetry filters */
#undef fprintf
#define fprintf(stream, ...) do { \
    if (stream == stderr) { \
        scl_log_stderr("Protocol", __VA_ARGS__); \
    } else { \
        scl_fprintf(stream, __VA_ARGS__); \
    } \
} while(0)

#undef printf
#define printf(...) scl_log(LOG_LEVEL_DEBUG, "Protocol", __VA_ARGS__)

/* ============================================================================ */
/* SECTION 1: L5 P2P MESSAGE ENVELOPE FRAMING                                   */
/* ============================================================================ */

int serialize_message(const Message *msg, uint8_t *buffer, size_t *len) {
    // Validate envelope pointers and payload length constraints
    if (!msg || !buffer || !len || msg->length > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[Protocol] ERROR: Invalid message parameters or length exceeds %d\n", MAX_MESSAGE_SIZE);
        return -1;
    }

    // Framing envelope: 1-byte opcode + 4-byte big-endian payload length + payload body
    size_t total_len = 1 + 4 + msg->length;
    if (total_len > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[Protocol] ERROR: Serialized message size %zu exceeds buffer %d\n", total_len, MAX_MESSAGE_SIZE);
        return -1;
    }

    // Pack message type opcode and 32-bit payload length in network byte order
    buffer[0] = msg->type;
    uint32_t length_net = htonl(msg->length);
    memcpy(buffer + 1, &length_net, 4);
    // Copy payload data into envelope body
    memcpy(buffer + 5, msg->payload, msg->length);
    *len = total_len;
    return 0;
}

int deserialize_message(uint8_t *buffer, size_t len, Message *msg) {
    // Validate envelope framing header boundary (at least 5 bytes: 1 opcode + 4 length)
    if (!buffer || !msg || len < 5) {
        fprintf(stderr, "[Protocol] ERROR: Invalid buffer or insufficient length (%zu < 5)\n", len);
        return -1;
    }

    // Extract message opcode and convert payload length from network byte order
    msg->type = buffer[0];
    uint32_t length_net;
    memcpy(&length_net, buffer + 1, 4);
    msg->length = ntohl(length_net);

    // Enforce protocol transmission maximums and packet boundary integrity
    if (msg->length > MAX_MESSAGE_SIZE || len < 5 + msg->length) {
        fprintf(stderr, "[Protocol] ERROR: Invalid message length (%u) or size mismatch (expected %u, got %zu)\n",
                msg->length, 5 + msg->length, len);
        return -1;
    }

    // Unpack message payload into target envelope
    if (msg->length > 0) {
        memcpy(msg->payload, buffer + 5, msg->length);
    }

    if (msg->type != MSG_BLOCK_NUMBER_QUERY && msg->type != MSG_BLOCK_NUMBER) {
            scl_log(LOG_LEVEL_TRACE, "Protocol", "Deserialized message type=%u, length=%u", msg->type, msg->length);
    }
    return 0;
}

void serialize_sockaddr(const struct sockaddr_storage *addr, uint8_t *buffer) {
    if (!addr || !buffer) return;
    memset(buffer, 0, 19); // Clear the 19-byte canonical envelope
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
        buffer[0] = 0x04;
        buffer[11] = 0xff;
        buffer[12] = 0xff;
        memcpy(buffer + 13, &v4->sin_addr.s_addr, 4);
        memcpy(buffer + 17, &v4->sin_port, 2);
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
            buffer[0] = 0x04;
            buffer[11] = 0xff;
            buffer[12] = 0xff;
            memcpy(buffer + 13, &v6->sin6_addr.s6_addr[12], 4);
            memcpy(buffer + 17, &v6->sin6_port, 2);
        } else {
            buffer[0] = 0x06;
            memcpy(buffer + 1, &v6->sin6_addr, 16);
            memcpy(buffer + 17, &v6->sin6_port, 2);
        }
    }
}

int deserialize_sockaddr(const uint8_t *buffer, size_t len, struct sockaddr_storage *addr) {
    if (!buffer || !addr || len < 19) return -1;
    memset(addr, 0, sizeof(struct sockaddr_storage));
    if (buffer[0] == 0x04) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
        v4->sin_family = AF_INET;
        memcpy(&v4->sin_addr.s_addr, buffer + 13, 4);
        memcpy(&v4->sin_port, buffer + 17, 2);
        return 0;
    } else if (buffer[0] == 0x06) {
        if (buffer[11] == 0xff && buffer[12] == 0xff && memcmp(buffer + 1, "\0\0\0\0\0\0\0\0\0\0", 10) == 0) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
            v4->sin_family = AF_INET;
            memcpy(&v4->sin_addr.s_addr, buffer + 13, 4);
            memcpy(&v4->sin_port, buffer + 17, 2);
            return 0;
        }
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
        v6->sin6_family = AF_INET6;
        memcpy(&v6->sin6_addr, buffer + 1, 16);
        memcpy(&v6->sin6_port, buffer + 17, 2);
        return 0;
    }
    return -1;
}

int scl_protocol_run_ipv6_selftest(void) {
    struct sockaddr_storage v4_in, v6_in, v4_out, v6_out;
    uint8_t buffer[19];

    // 1. Test IPv4 Round-Trip
    memset(&v4_in, 0, sizeof(v4_in));
    struct sockaddr_in *v4 = (struct sockaddr_in *)&v4_in;
    v4->sin_family = AF_INET;
    v4->sin_port = htobe16(5555);
    inet_pton(AF_INET, "192.168.1.100", &v4->sin_addr);

    serialize_sockaddr(&v4_in, buffer);
    if (deserialize_sockaddr(buffer, 19, &v4_out) != 0) return -1;
    struct sockaddr_in *v4_o = (struct sockaddr_in *)&v4_out;
    if (v4_o->sin_family != AF_INET || v4_o->sin_port != v4->sin_port || v4_o->sin_addr.s_addr != v4->sin_addr.s_addr) return -1;

    // 2. Test IPv6 Round-Trip
    memset(&v6_in, 0, sizeof(v6_in));
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&v6_in;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htobe16(5556);
    inet_pton(AF_INET6, "2001:db8:85a3::8a2e:370:7334", &v6->sin6_addr);

    serialize_sockaddr(&v6_in, buffer);
    if (deserialize_sockaddr(buffer, 19, &v6_out) != 0) return -1;
    struct sockaddr_in6 *v6_o = (struct sockaddr_in6 *)&v6_out;
    if (v6_o->sin6_family != AF_INET6 || v6_o->sin6_port != v6->sin6_port || memcmp(&v6_o->sin6_addr, &v6->sin6_addr, 16) != 0) return -1;

    // 3. Test Invalid Frame Boundaries
    if (deserialize_sockaddr(buffer, 18, &v6_out) != -1) return -1;

    return 0;
}

size_t serialize_core_valuation(const Valuation *val, uint8_t *buffer) {
    size_t offset = 0;
    // Pack 32-byte user identifier
    memcpy(buffer + offset, val->user_id, USER_ID_LEN); offset += USER_ID_LEN;
    // Pack valuation numbers in network byte order
    for (int i = 0; i < NUMBERS_PER_VALUATION; i++) {
        uint32_t net_num = htonl(val->numbers[i]);
        memcpy(buffer + offset, &net_num, sizeof(uint32_t)); offset += sizeof(uint32_t);
    }
    // Pack 64-bit millisecond timestamp in network byte order
    uint64_t ts_net = htobe64(val->timestamp);
    memcpy(buffer + offset, &ts_net, sizeof(uint64_t)); offset += sizeof(uint64_t);
    return offset;
}

/* ============================================================================ */
/* SECTION 2: VALUATION VECTORS & MATRIX ROW SERIALIZATION                      */
/* ============================================================================ */

/**
 * @brief Serializes a complete Valuation structure including its 32-byte randomness beacon seed.
 *
 * @param[in] val Pointer to source @ref Valuation structure.
 * @param[out] buffer Destination buffer (must allocate at least 112 bytes).
 * @return Total bytes written (exactly 112 bytes: 80 core + 32 beacon seed).
 *
 * @complexity Time: O(1), Space: O(1).
 */
static size_t serialize_valuation(const Valuation *val, uint8_t *buffer) {
    size_t offset = serialize_core_valuation(val, buffer);
    memcpy(buffer + offset, val->beacon_seed, 32);
    offset += 32;
    return offset;
}

/**
 * @brief Serializes an authenticated ValuationData wrapper (valuation + pubkey + signature + threshold key).
 *
 * @param[in] data Pointer to source @ref ValuationData structure.
 * @param[out] buffer Destination buffer (must allocate at least 9,891 bytes).
 * @return Total bytes written.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static size_t serialize_valuation_data(const ValuationData *data, uint8_t *buffer) {
    size_t offset = serialize_valuation(&data->valuation, buffer);
    // Append submitter public key, Dilithium signature, and epoch threshold public key
    memcpy(buffer + offset, data->pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
    memcpy(buffer + offset, data->signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
    memcpy(buffer + offset, data->threshold_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
    return offset;
}

size_t deserialize_core_valuation(const uint8_t *buffer, Valuation *val) {
    size_t offset = 0;
    // Unpack 32-byte user identifier
    memcpy(val->user_id, buffer + offset, USER_ID_LEN); offset += USER_ID_LEN;
    // Unpack valuation numbers from network byte order
    for (int i = 0; i < NUMBERS_PER_VALUATION; i++) {
        uint32_t net_num;
        memcpy(&net_num, buffer + offset, sizeof(uint32_t));
        val->numbers[i] = ntohl(net_num);
        offset += sizeof(uint32_t);
    }
    // Unpack 64-bit millisecond timestamp from network byte order
    uint64_t ts_net;
    memcpy(&ts_net, buffer + offset, sizeof(uint64_t));
    val->timestamp = be64toh(ts_net);
    offset += sizeof(uint64_t);
    return offset;
}

/**
 * @brief Deserializes a full Valuation structure including its 32-byte randomness beacon seed.
 *
 * @param[in] buffer Source byte buffer.
 * @param[out] val Destination @ref Valuation structure.
 * @return Total bytes consumed (exactly 112 bytes).
 *
 * @complexity Time: O(1), Space: O(1).
 */
static size_t deserialize_valuation(const uint8_t *buffer, Valuation *val) {
    size_t offset = deserialize_core_valuation(buffer, val);
    memcpy(val->beacon_seed, buffer + offset, 32);
    offset += 32;
    return offset;
}

/**
 * @brief Deserializes an authenticated ValuationData wrapper with strict length validation.
 *
 * @param[out] data Destination @ref ValuationData structure.
 * @param[in] buffer Input byte buffer.
 * @param[in] buffer_len Total available bytes in `buffer`.
 * @return Total bytes consumed on success; 0 on buffer underflow.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static size_t deserialize_valuation_data(ValuationData *data, const uint8_t *buffer, size_t buffer_len) {
    // Verify minimum required buffer length before attempting deserialization
    size_t min_req = USER_ID_LEN + NUMBERS_PER_VALUATION * sizeof(uint32_t) + sizeof(uint64_t) + 32 + PUBKEY_LEN + SIGNATURE_LEN + PUBKEY_LEN;
    if (buffer_len < min_req) return 0;
    size_t offset = deserialize_valuation(buffer, &data->valuation);
    // Unpack submitter public key, Dilithium signature, and threshold public key
    memcpy(data->pubkey, buffer + offset, PUBKEY_LEN); offset += PUBKEY_LEN;
    memcpy(data->signature, buffer + offset, SIGNATURE_LEN); offset += SIGNATURE_LEN;
    memcpy(data->threshold_pubkey, buffer + offset, PUBKEY_LEN); offset += PUBKEY_LEN;
    return offset;
}

/* ============================================================================ */
/* SECTION 3: MERKLE MOUNTAIN RANGE (MMR) PROOF SERIALIZATION                   */
/* ============================================================================ */

size_t serialize_mmr_proof(const MMRProof *proof, uint8_t *buffer, size_t buf_size) {
    if (!proof || !buffer || proof->path_len > MAX_PATH_LEN ||
        proof->left_peaks_len > MAX_PEAKS || proof->right_peaks_len > MAX_PEAKS) {
        fprintf(stderr, "[Protocol] Invalid MMR proof serialization parameters\n");
        return 0;
    }

    size_t required_size = sizeof(uint32_t) + (proof->path_len * (COIN_ID_LEN + 4)) +
                           sizeof(uint32_t) + (proof->left_peaks_len * COIN_ID_LEN) +
                           sizeof(uint32_t) + (proof->right_peaks_len * COIN_ID_LEN);

    if (buf_size < required_size) {
        fprintf(stderr, "[Protocol] Insufficient buffer for MMRProof: required %zu, available %zu\n", required_size, buf_size);
        return 0;
    }

    size_t offset = 0;
    // 1. Pack MMR path length and directional sibling node hashes
    uint32_t path_len_net = htobe32(proof->path_len);
    memcpy(buffer + offset, &path_len_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    for (size_t j = 0; j < proof->path_len; j++) {
        memcpy(buffer + offset, proof->path_hashes[j], COIN_ID_LEN);
        offset += COIN_ID_LEN;
        uint32_t is_left_val = htobe32((uint32_t)proof->is_left[j]);
        memcpy(buffer + offset, &is_left_val, 4);
        offset += 4;
    }

    // 2. Pack left bag-of-peaks list
    uint32_t peaks_len_net = htobe32(proof->left_peaks_len);
    memcpy(buffer + offset, &peaks_len_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    for (size_t j = 0; j < proof->left_peaks_len; j++) {
        memcpy(buffer + offset, proof->left_peaks[j], COIN_ID_LEN);
        offset += COIN_ID_LEN;
    }

    // 3. Pack right bag-of-peaks list
    peaks_len_net = htobe32(proof->right_peaks_len);
    memcpy(buffer + offset, &peaks_len_net, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    for (size_t j = 0; j < proof->right_peaks_len; j++) {
        memcpy(buffer + offset, proof->right_peaks[j], COIN_ID_LEN);
        offset += COIN_ID_LEN;
    }

    scl_log(LOG_LEVEL_TRACE, "Protocol", "Serialized MMRProof: path_len=%zu, left_peaks_len=%zu, right_peaks_len=%zu, size=%zu",
           proof->path_len, proof->left_peaks_len, proof->right_peaks_len, offset);
    return offset;
}

/**
 * @brief Deserializes an MMR inclusion proof from a streaming cursor.
 *
 * @details
 * Unpacks 4-byte big-endian path length, path sibling hashes and directional flags,
 * 4-byte left peaks count and hashes, and 4-byte right peaks count and hashes.
 *
 * @pre `p`, `*p`, `msg_end`, and `proof` must be non-NULL; `*p < msg_end`.
 * @post On return 0, `proof` is populated and `*p` is advanced past the consumed bytes.
 * @synchronization Stateless, reentrant, and thread-safe.
 *
 * @param[in,out] p       Double pointer to current read position in buffer (advanced on return).
 *                        - Direction: in-out
 * @param[in]     msg_end Pointer to end boundary of the enclosing packet buffer.
 *                        - Direction: in
 * @param[out]    proof   Destination @ref MMRProof structure populated on success.
 *                        - Direction: out
 *
 * @return int 0 on success; -1 on buffer truncation or length bound violation.
 *
 * @complexity Time: O(path_len + peaks_len), Space: O(1).
 */
int deserialize_mmr_proof(const uint8_t **p, const uint8_t *msg_end, MMRProof *proof) {
    if (!p || !*p || !msg_end || !proof || *p >= msg_end) {
        fprintf(stderr, "[Protocol] Invalid MMR proof deserialization parameters\n");
        return -1;
    }

    // Phase 1: Unpack audit path length and directional sibling hashes
    if (*p + sizeof(uint32_t) > msg_end) {
        fprintf(stderr, "[Protocol] Insufficient data for MMR proof path_len\n");
        return -1;
    }

    uint32_t path_len;
    memcpy(&path_len, *p, sizeof(uint32_t));
    proof->path_len = be32toh(path_len);
    *p += sizeof(uint32_t);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    size_t avail_path = (msg_end > *p) ? (size_t)(msg_end - *p) / (COIN_ID_LEN + 4) : 0;
    if (proof->path_len > avail_path) proof->path_len = avail_path;
    if (proof->path_len > MAX_PATH_LEN) proof->path_len = MAX_PATH_LEN;
#else
    if (proof->path_len > MAX_PATH_LEN) {
        fprintf(stderr, "[Protocol] MMR proof path_len %zu exceeds MAX_PATH_LEN %d\n",
                proof->path_len, MAX_PATH_LEN);
        return -1;
    }
#endif

    size_t path_size = proof->path_len * (COIN_ID_LEN + 4);
    if (*p + path_size > msg_end) {
        fprintf(stderr, "[Protocol] Insufficient data for path hashes: needed=%zu, available=%zu\n",
                path_size, (size_t)(msg_end - *p));
        return -1;
    }

    for (size_t j = 0; j < proof->path_len; j++) {
        memcpy(proof->path_hashes[j], *p, COIN_ID_LEN);
        *p += COIN_ID_LEN;
        uint32_t is_left_val;
        memcpy(&is_left_val, *p, 4);
        proof->is_left[j] = (int)be32toh(is_left_val);
        *p += 4;
    }

    // Phase 2: Unpack left MMR bag-of-peaks list
    if (*p + sizeof(uint32_t) > msg_end) {
        fprintf(stderr, "[Protocol] Insufficient data for left_peaks_len\n");
        return -1;
    }
    uint32_t peaks_len;
    memcpy(&peaks_len, *p, sizeof(uint32_t));
    proof->left_peaks_len = be32toh(peaks_len);
    *p += sizeof(uint32_t);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    size_t avail_left = (msg_end > *p) ? (size_t)(msg_end - *p) / COIN_ID_LEN : 0;
    if (proof->left_peaks_len > avail_left) proof->left_peaks_len = avail_left;
    if (proof->left_peaks_len > MAX_PEAKS) proof->left_peaks_len = MAX_PEAKS;
#else
    if (proof->left_peaks_len > MAX_PEAKS) {
        fprintf(stderr, "[Protocol] MMR proof left_peaks_len %zu exceeds MAX_PEAKS %d\n",
                proof->left_peaks_len, MAX_PEAKS);
        return -1;
    }
#endif

    if (*p + proof->left_peaks_len * COIN_ID_LEN > msg_end) {
        fprintf(stderr, "[Protocol] Insufficient data for left peaks: needed=%zu, available=%zu\n",
                proof->left_peaks_len * COIN_ID_LEN, (size_t)(msg_end - *p));
        return -1;
    }

    for (size_t j = 0; j < proof->left_peaks_len; j++) {
        memcpy(proof->left_peaks[j], *p, COIN_ID_LEN);
        *p += COIN_ID_LEN;
    }

    // Phase 3: Unpack right MMR bag-of-peaks list
    if (*p + sizeof(uint32_t) > msg_end) {
        fprintf(stderr, "[Protocol] Insufficient data for right_peaks_len\n");
        return -1;
    }
    memcpy(&peaks_len, *p, sizeof(uint32_t));
    proof->right_peaks_len = be32toh(peaks_len);
    *p += sizeof(uint32_t);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    size_t avail_right = (msg_end > *p) ? (size_t)(msg_end - *p) / COIN_ID_LEN : 0;
    if (proof->right_peaks_len > avail_right) proof->right_peaks_len = avail_right;
    if (proof->right_peaks_len > MAX_PEAKS) proof->right_peaks_len = MAX_PEAKS;
#else
    if (proof->right_peaks_len > MAX_PEAKS) {
        fprintf(stderr, "[Protocol] MMR proof right_peaks_len %zu exceeds MAX_PEAKS %d\n",
                proof->right_peaks_len, MAX_PEAKS);
        return -1;
    }
#endif

    if (*p + proof->right_peaks_len * COIN_ID_LEN > msg_end) {
        fprintf(stderr, "[Protocol] Insufficient data for right peaks: needed=%zu, available=%zu\n",
                proof->right_peaks_len * COIN_ID_LEN, (size_t)(msg_end - *p));
        return -1;
    }

    for (size_t j = 0; j < proof->right_peaks_len; j++) {
        memcpy(proof->right_peaks[j], *p, COIN_ID_LEN);
        *p += COIN_ID_LEN;
    }

    scl_log(LOG_LEVEL_TRACE, "Protocol", "Deserialized MMRProof: path_len=%zu, left_peaks_len=%zu, right_peaks_len=%zu",
           proof->path_len, proof->left_peaks_len, proof->right_peaks_len);
    return 0;
}

/* ============================================================================ */
/* SECTION 4: SUBUNIT POINTER UTXO SERIALIZATION                                */
/* ============================================================================ */

void serialize_pointer(const Pointer *pointer, uint8_t *buffer) {
    // Pack 152-byte full UTXO state: ID (32B), Parent (32B), Range (16B), Owner (32B), PrevTx (32B), Flags (8B)
    uint8_t *p = buffer;
    memcpy(p, pointer->pointer_id, COIN_ID_LEN); p += COIN_ID_LEN;
    memcpy(p, pointer->parent_coin_id, COIN_ID_LEN); p += COIN_ID_LEN;
    uint64_t start_be = htobe64(pointer->start_subunit); memcpy(p, &start_be, 8); p += 8;
    uint64_t end_be = htobe64(pointer->end_subunit); memcpy(p, &end_be, 8); p += 8;
    memcpy(p, pointer->owner_address, USER_ID_LEN); p += USER_ID_LEN;
    memcpy(p, pointer->prev_tx_hash, COIN_ID_LEN); p += COIN_ID_LEN;
    uint32_t spent_be = htobe32(pointer->spent); memcpy(p, &spent_be, 4); p += 4;
    uint32_t staked_be = htobe32(pointer->staked); memcpy(p, &staked_be, 4); p += 4;
}

/**
 * @brief Serializes immutable pointer fields required for input Merkle tree generation.
 *
 * @details
 * Excludes mutable state flags (`spent`, `staked`) to produce the canonical 112-byte signing representation:
 * `ParentCoinID (32B) || OwnerAddress (32B) || StartSubunit (8B, BE) || EndSubunit (8B, BE) || PrevTxHash (32B)`.
 *
 * @param[in]  ptr    Pointer to source @ref Pointer structure.
 * @param[out] buffer Destination buffer (must allocate at least @ref POINTER_SIGNING_SIZE = 112 bytes).
 *
 * @complexity Time: O(1), Space: O(1).
 */
void serialize_pointer_for_signing(const Pointer *ptr, uint8_t *buffer) {
    // Pack 112-byte canonical preimage: excludes mutable spent and staked status flags
    uint8_t *p = buffer;
    memcpy(p, ptr->parent_coin_id, COIN_ID_LEN); p += COIN_ID_LEN;
    memcpy(p, ptr->owner_address, USER_ID_LEN); p += USER_ID_LEN;
    uint64_t start_be = htobe64(ptr->start_subunit);
    memcpy(p, &start_be, sizeof(uint64_t)); p += sizeof(uint64_t);
    uint64_t end_be = htobe64(ptr->end_subunit);
    memcpy(p, &end_be, sizeof(uint64_t)); p += sizeof(uint64_t);
    memcpy(p, ptr->prev_tx_hash, COIN_ID_LEN); p += COIN_ID_LEN;
}

/**
 * @brief Deserializes a 152-byte wire buffer into a structured Pointer UTXO with big-endian integers.
 *
 * @param[in]  buffer  Source byte buffer (must contain at least 152 bytes).
 * @param[out] pointer Destination @ref Pointer structure to populate.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void deserialize_pointer(const uint8_t *buffer, Pointer *pointer) {
    // Unpack 152-byte UTXO wire representation with endian restoration
    const uint8_t *p = buffer;
    memcpy(pointer->pointer_id, p, COIN_ID_LEN); p += COIN_ID_LEN;
    memcpy(pointer->parent_coin_id, p, COIN_ID_LEN); p += COIN_ID_LEN;
    uint64_t start_be; memcpy(&start_be, p, 8); pointer->start_subunit = be64toh(start_be); p += 8;
    uint64_t end_be; memcpy(&end_be, p, 8); pointer->end_subunit = be64toh(end_be); p += 8;
    memcpy(pointer->owner_address, p, USER_ID_LEN); p += USER_ID_LEN;
    memcpy(pointer->prev_tx_hash, p, COIN_ID_LEN); p += COIN_ID_LEN;
    uint32_t spent_be; memcpy(&spent_be, p, 4); pointer->spent = be32toh(spent_be); p += 4;
    uint32_t staked_be; memcpy(&staked_be, p, 4); pointer->staked = be32toh(staked_be); p += 4;
}

/* ============================================================================ */
/* SECTION 5: ON-CHAIN TRANSACTION PAYLOAD SERIALIZATION                        */
/* ============================================================================ */

int serialize_transfer_payload(const TransferData *tx, uint8_t *buffer, size_t *len) {
    if (!tx || !buffer || !len || tx->num_inputs > MAX_INPUTS) return -1;
    uint8_t *p = buffer;

    // To ensure tx_id is stable across on-chain optimization,
    // we hash only the intent, not the witnesses (MMR Proofs).
    memcpy(p, tx->nonce, 8); p += 8;
    uint32_t num_inputs_net = htonl(tx->num_inputs);
    memcpy(p, &num_inputs_net, sizeof(uint32_t)); p += sizeof(uint32_t);
    memcpy(p, tx->client_root, COIN_ID_LEN); p += COIN_ID_LEN;

    for (size_t i = 0; i < tx->num_inputs; i++) {
        // Serialize pointer ID and range only
        memcpy(p, tx->inputs[i].pointer_id, COIN_ID_LEN); p += COIN_ID_LEN;
        uint64_t s_be = htobe64(tx->inputs[i].start_subunit);
        memcpy(p, &s_be, 8); p += 8;
        uint64_t e_be = htobe64(tx->inputs[i].end_subunit);
        memcpy(p, &e_be, 8); p += 8;
    }

    // Serialize core transfer parameters: recipient, sender, and amount
    memcpy(p, tx->recipient_pubkey, PUBKEY_LEN); p += PUBKEY_LEN;
    memcpy(p, tx->sender_pubkey, PUBKEY_LEN); p += PUBKEY_LEN;
    uint64_t amount_net = htobe64(tx->amount);
    memcpy(p, &amount_net, sizeof(uint64_t)); p += sizeof(uint64_t);

    *len = p - buffer;
    return 0;
}

/**
 * @brief Deserializes a MSG_PTR_TRANSFER message payload into an arena-allocated TransferData structure.
 *
 * @param[in]  msg             Source network message container.
 * @param[out] payload_ptr     Pointer receiving address of allocated `TransferData` (allocated in arena).
 * @param[out] signed_data_len Pointer receiving length of byte slice covered by main transaction signature.
 * @return 0 on success; -1 on format corruption, truncation, or excessive input count.
 *
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(sizeof(TransferData)) arena allocation.
 */
int deserialize_transfer_payload(const Message *msg, TransferData **payload_ptr, size_t *signed_data_len) {
    if (!msg || !payload_ptr || msg->type != MSG_PTR_TRANSFER || !signed_data_len) {
        fprintf(stderr, "[Protocol] Invalid transfer message or parameters\n");
        return -1;
    }

    // Allocate TransferData on thread-local arena to prevent massive heap fragmentation
    TransferData *payload = arena_alloc(sizeof(TransferData));
    if (!payload) {
        fprintf(stderr, "[Protocol] Failed to allocate TransferData\n");
        return -1;
    }
    *payload_ptr = payload;

    const uint8_t *p = msg->payload;
    const uint8_t *msg_end = msg->payload + msg->length;
    
    // Validate minimum header boundary: tx_id (32B) + nonce (8B) + num_inputs (4B) + client_root (32B)
    size_t min_size = COIN_ID_LEN + 8 + sizeof(uint32_t) + COIN_ID_LEN;
    if (msg->length < min_size) {
        fprintf(stderr, "[Protocol] Transfer message too short: length=%u, required=%zu\n",
                msg->length, min_size);
        *payload_ptr = NULL;
        return -1;
    }

    // Unpack transaction header fields
    memcpy(payload->tx_id, p, COIN_ID_LEN);
    p += COIN_ID_LEN;
    memcpy(payload->nonce, p, 8);
    p += 8;
    uint32_t num_inputs_net;
    memcpy(&num_inputs_net, p, sizeof(uint32_t));
    payload->num_inputs = ntohl(num_inputs_net);
    p += sizeof(uint32_t);
    memcpy(payload->client_root, p, COIN_ID_LEN);
    p += COIN_ID_LEN;

    if (payload->num_inputs == 0 || payload->num_inputs > MAX_INPUTS) {
        fprintf(stderr, "[Protocol] Invalid num_inputs: %u\n", payload->num_inputs);
        *payload_ptr = NULL;
        return -1;
    }

    for (size_t i = 0; i < payload->num_inputs; i++) {
        if (p + sizeof(Pointer) > msg_end) {
            fprintf(stderr, "[Protocol] Insufficient data for input %zu\n", i);
            *payload_ptr = NULL;
            return -1;
        }
        deserialize_pointer(p, &payload->inputs[i]);
        p += sizeof(Pointer);

        if (deserialize_mmr_proof(&p, msg_end, &payload->proofs[i]) != 0) {
            fprintf(stderr, "[Protocol] Failed to deserialize MMR proof %zu\n", i);
            *payload_ptr = NULL;
            return -1;
        }
    }

    // Check for final fields: recipient_pubkey + sender_pubkey + amount + main_sig + merkle_root + root_sig
    if (p + PUBKEY_LEN + PUBKEY_LEN + sizeof(uint64_t) + SIGNATURE_LEN + COIN_ID_LEN + SIGNATURE_LEN > msg_end) {
        fprintf(stderr, "[Protocol] Insufficient data for final fields\n");
        *payload_ptr = NULL;
        return -1;
    }
    memcpy(payload->recipient_pubkey, p, PUBKEY_LEN);
    p += PUBKEY_LEN;
    memcpy(payload->sender_pubkey, p, PUBKEY_LEN);
    p += PUBKEY_LEN;
    uint64_t amount_net;
    memcpy(&amount_net, p, sizeof(uint64_t));
    payload->amount = be64toh(amount_net);
    p += sizeof(uint64_t);

    *signed_data_len = p - msg->payload;

    memcpy(payload->signature, p, SIGNATURE_LEN);
    p += SIGNATURE_LEN;
    memcpy(payload->inputs_merkle_root, p, COIN_ID_LEN);
    p += COIN_ID_LEN;
    memcpy(payload->inputs_root_signature, p, SIGNATURE_LEN);
    p += SIGNATURE_LEN;

    if (p != msg_end) {
        scl_log(LOG_LEVEL_ERROR, "Protocol", "Extra data in transfer payload: %zu bytes", msg_end - p);
        *payload_ptr = NULL;
        return -1;
    }

    scl_log(LOG_LEVEL_TRACE, "Protocol", "Deserialized MSG_PTR_TRANSFER: num_inputs=%u, signed_data_len=%zu",
           payload->num_inputs, *signed_data_len);
    
    return 0;
}

/**
 * @brief Serializes consensus-critical fields of a TransferData structure for Dilithium signature verification.
 *
 * @details
 * Omits client-side witnesses (MMR proofs, client root) to serialize the canonical 5,264-byte signing image:
 * `TxID (32) || Nonce (8) || InputsMerkleRoot (32) || RecipientPubkey (2592) || SenderPubkey (2592) || Amount (8, BE)`.
 *
 * @param[in]  tx     Pointer to source @ref TransferData structure.
 * @param[out] buffer Destination buffer (must allocate at least 5,264 bytes).
 * @param[out] len    Pointer receiving serialized byte length.
 * @return 0 on success; -1 on NULL parameter.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int serialize_transfer_for_signature(const TransferData *tx, uint8_t *buffer, size_t *len) {
    if (!tx || !buffer || !len) {
        fprintf(stderr, "[Protocol] Invalid parameters in serialize_transfer_for_signature\n");
        return -1;
    }

    uint8_t *p = buffer;

    // The signature commits to the transaction's identity and its core intent.
    // It intentionally omits client-side data like proofs and client_root.
    
    // 1. tx_id: Commits the signature to the full transaction details (including client-side data).
    memcpy(p, tx->tx_id, COIN_ID_LEN); p += COIN_ID_LEN;

    // 2. nonce: Prevents replay attacks.
    memcpy(p, tx->nonce, 8); p += 8;
    
    // 3. inputs_merkle_root: Commits to the set of inputs being spent.
    memcpy(p, tx->inputs_merkle_root, COIN_ID_LEN); p += COIN_ID_LEN;

    // 4. recipient_pubkey: Specifies the recipient.
    memcpy(p, tx->recipient_pubkey, PUBKEY_LEN); p += PUBKEY_LEN;
    
    // 5. sender_pubkey: Specifies the sender.
    memcpy(p, tx->sender_pubkey, PUBKEY_LEN); p += PUBKEY_LEN;
        
    // 6. amount: Specifies the amount being transferred.
    uint64_t amount_net = htobe64(tx->amount);
    memcpy(p, &amount_net, sizeof(uint64_t)); p += sizeof(uint64_t);

    *len = p - buffer;
    return 0;
}

/**
 * @brief Serializes an on-chain Operation into a type-tagged wire byte slice.
 *
 * @param[in]  op       Pointer to source @ref Operation structure.
 * @param[out] buffer   Output byte buffer.
 * @param[in]  buf_size Available capacity in `buffer`.
 * @return Number of bytes written on success; 0 on buffer overflow or unknown operation type.
 *
 * @complexity Time: O(op_size), Space: O(1).
 */
int serialize_operation(const Operation *op, uint8_t *buffer, size_t buf_size) {
    if (!op || !buffer || buf_size == 0) {
        fprintf(stderr, "[Protocol] Invalid parameters in serialize_operation\n");
        return 0;
    }

    size_t offset = 0;
    
    if (buf_size < offset + sizeof(uint8_t)) return 0;
    buffer[offset++] = (uint8_t)op->type;

    switch (op->type) {
        case OP_CLAIM_VALIDATION: {
            // Serialize Bdlop commitment, claimant public key, and Dilithium signature
            const ClaimValidationData *cv = &op->data.claim_validation;
            if (buf_size < offset + sizeof(BdlopCommitment) + PUBKEY_LEN + SIGNATURE_LEN) return 0;
            memcpy(buffer + offset, &cv->commitment, sizeof(BdlopCommitment)); offset += sizeof(BdlopCommitment);
            memcpy(buffer + offset, cv->pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
            memcpy(buffer + offset, cv->signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
            break;
        }
        case OP_REDEEM_CENTINEL: {
            // Serialize Centinel nullifier, Bdlop transfer/change commitments, and ZK proof
            const RedeemCentinelData *rc = &op->data.redeem_centinel;
                    
            if (buf_size < offset + NULLIFIER_LEN) return 0;
            memcpy(buffer + offset, rc->nullifier, NULLIFIER_LEN); offset += NULLIFIER_LEN;
                    
            if (buf_size < offset + sizeof(BdlopCommitment)) return 0;
            memcpy(buffer + offset, &rc->c_transfer, sizeof(BdlopCommitment)); offset += sizeof(BdlopCommitment);
                    
            if (buf_size < offset + sizeof(BdlopCommitment)) return 0;
            memcpy(buffer + offset, &rc->c_change, sizeof(BdlopCommitment)); offset += sizeof(BdlopCommitment);
                    
            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t zk_proof_len_be = htobe32(rc->zk_proof_len);
            memcpy(buffer + offset, &zk_proof_len_be, sizeof(uint32_t)); offset += sizeof(uint32_t);
                    
            if (buf_size < offset + rc->zk_proof_len) return 0;
            memcpy(buffer + offset, rc->zk_proof, rc->zk_proof_len); offset += rc->zk_proof_len;
                    
            break;
        }
        case OP_SUBMIT_VALUATION: {
            // Validate buffer bounds and serialize authenticated valuation data with threshold components
            size_t val_size = USER_ID_LEN + (NUMBERS_PER_VALUATION * sizeof(uint32_t)) + sizeof(uint64_t) + 32 + PUBKEY_LEN + SIGNATURE_LEN + PUBKEY_LEN;
            if (buf_size < offset + val_size) return 0;
            size_t written = serialize_valuation_data(&op->data.submit_valuation, buffer + offset);
            if (written == 0) return 0;
            offset += written;
            break;
        }
        case OP_MINT_COIN: {
            // Serialize coin genesis parameters and historical audit snapshots
            const MintData *md = &op->data.mint_coin;
            const SCLCoin *coin = &md->coin;
            size_t required_size = PUBKEY_LEN + COIN_ID_LEN * 3 + USER_ID_LEN + sizeof(uint64_t) * 2 + sizeof(uint32_t) * 2 + (AUDIT_SIZE * (USER_ID_LEN + NUMBERS_PER_VALUATION * sizeof(uint32_t) + sizeof(uint64_t) + 32));
            if (buf_size < offset + required_size) return 0;

            memcpy(buffer + offset, md->owner_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
            memcpy(buffer + offset, coin->coin_id, COIN_ID_LEN); offset += COIN_ID_LEN;
            memcpy(buffer + offset, coin->owner_address, USER_ID_LEN); offset += USER_ID_LEN;
            memcpy(buffer + offset, coin->creation_tx_hash, COIN_ID_LEN); offset += COIN_ID_LEN;
                    
            uint64_t total_be = htobe64(coin->total_subunits);
            memcpy(buffer + offset, &total_be, sizeof(uint64_t)); offset += sizeof(uint64_t);
                    
            uint64_t remaining_be = htobe64(coin->remaining_subunits);
            memcpy(buffer + offset, &remaining_be, sizeof(uint64_t)); offset += sizeof(uint64_t);
                    
            uint32_t snapshot_count_be = htonl(coin->snapshot_count);
            memcpy(buffer + offset, &snapshot_count_be, sizeof(uint32_t)); offset += sizeof(uint32_t);
                    
            uint32_t snapshot_audit_index_be = htonl(coin->snapshot_audit_index);
            memcpy(buffer + offset, &snapshot_audit_index_be, sizeof(uint32_t)); offset += sizeof(uint32_t);
                    
            memcpy(buffer + offset, coin->audit_state_anchor, COIN_ID_LEN); offset += COIN_ID_LEN;

            for (uint32_t i = 0; i < AUDIT_SIZE; i++) {
                const Valuation *val = &coin->audit_snapshot[i];
                memcpy(buffer + offset, val->user_id, USER_ID_LEN); offset += USER_ID_LEN;
                for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
                    uint32_t num_be = htonl((uint32_t)val->numbers[j]);
                    memcpy(buffer + offset, &num_be, sizeof(uint32_t)); offset += sizeof(uint32_t);
                }
                uint64_t timestamp_be = htobe64(val->timestamp);
                memcpy(buffer + offset, &timestamp_be, sizeof(uint64_t)); offset += sizeof(uint64_t);
                memcpy(buffer + offset, val->beacon_seed, 32); offset += 32;
            }
            break;
        }
        case OP_TRANSFER_POINTER: {
            // Serialize transfer intent, inputs with MMR proofs, signatures, and ZK-PRF proof
            const TransferData *tx = &op->data.transfer_pointer;
            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, tx->tx_id, COIN_ID_LEN); offset += COIN_ID_LEN;

            if (buf_size < offset + 8) return 0;
            memcpy(buffer + offset, tx->nonce, 8); offset += 8;

            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t num_inputs_be = htobe32(tx->num_inputs);
            memcpy(buffer + offset, &num_inputs_be, sizeof(uint32_t)); offset += sizeof(uint32_t);

            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, tx->client_root, COIN_ID_LEN); offset += COIN_ID_LEN;

            for (size_t i = 0; i < tx->num_inputs; i++) {
                if (buf_size < offset + sizeof(Pointer)) return 0;
                serialize_pointer(&tx->inputs[i], buffer + offset); offset += sizeof(Pointer);
                
                size_t proof_size = serialize_mmr_proof(&tx->proofs[i], buffer + offset, buf_size - offset);
                if (proof_size == 0) return 0;
                offset += proof_size;
            }

            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, tx->recipient_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;

            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, tx->sender_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;

            if (buf_size < offset + sizeof(uint64_t)) return 0;
            uint64_t amount_be = htobe64(tx->amount);
            memcpy(buffer + offset, &amount_be, sizeof(uint64_t)); offset += sizeof(uint64_t);

            if (buf_size < offset + SIGNATURE_LEN) return 0;
            memcpy(buffer + offset, tx->signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;

            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, tx->inputs_merkle_root, COIN_ID_LEN); offset += COIN_ID_LEN;
                        
            if (buf_size < offset + SIGNATURE_LEN) return 0;
            memcpy(buffer + offset, tx->inputs_root_signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;

            if (buf_size < offset + NULLIFIER_LEN) return 0;
            memcpy(buffer + offset, tx->prf_output, NULLIFIER_LEN); offset += NULLIFIER_LEN;

            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t zk_proof_len_be = htobe32(tx->zk_proof_len);
            memcpy(buffer + offset, &zk_proof_len_be, sizeof(uint32_t)); offset += sizeof(uint32_t);
            
            if (buf_size < offset + tx->zk_proof_len) return 0;
            memcpy(buffer + offset, tx->zk_proof, tx->zk_proof_len); offset += tx->zk_proof_len;

            break;
        }
        case OP_STAKE: {
            // Serialize staking intent, input pointers with MMR proofs, and threshold signatures
            const StakeData *sd = &op->data.stake;
            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, sd->stake_tx_id, COIN_ID_LEN); offset += COIN_ID_LEN;
            
            if (buf_size < offset + 8) return 0;
            memcpy(buffer + offset, sd->nonce, 8); offset += 8;
            
            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t num_inputs_be = htobe32(sd->num_inputs);
            memcpy(buffer + offset, &num_inputs_be, sizeof(uint32_t)); offset += sizeof(uint32_t);

            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, sd->client_root, COIN_ID_LEN); offset += COIN_ID_LEN;

            for (size_t i = 0; i < sd->num_inputs; i++) {
                if (buf_size < offset + sizeof(Pointer)) return 0;
                serialize_pointer(&sd->inputs[i], buffer + offset); offset += sizeof(Pointer);
                
                size_t proof_size = serialize_mmr_proof(&sd->proofs[i], buffer + offset, buf_size - offset);
                if (proof_size == 0) return 0;
                offset += proof_size;
            }

            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, sd->threshold_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;

            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, sd->sender_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;

            if (buf_size < offset + sizeof(uint64_t)) return 0;
            uint64_t amount_be = htobe64(sd->amount);
            memcpy(buffer + offset, &amount_be, sizeof(uint64_t)); offset += sizeof(uint64_t);

            if (buf_size < offset + SIGNATURE_LEN) return 0;
            memcpy(buffer + offset, sd->threshold_signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;

            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, sd->inputs_merkle_root, COIN_ID_LEN); offset += COIN_ID_LEN;
                        
            if (buf_size < offset + SIGNATURE_LEN) return 0;
            memcpy(buffer + offset, sd->inputs_root_signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
            break;
        }
        case OP_APPLY_DRIFT_CERT: {
            // Serialize drift certificate anchoring intent, input pointers, and PQ signature
            const ApplyDriftCertData *dc = &op->data.apply_drift_cert;
            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, dc->cert_tx_id, COIN_ID_LEN); offset += COIN_ID_LEN;

            if (buf_size < offset + 8) return 0;
            memcpy(buffer + offset, dc->nonce, 8); offset += 8;

            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t dc_num_be = htobe32(dc->num_inputs);
            memcpy(buffer + offset, &dc_num_be, sizeof(uint32_t)); offset += sizeof(uint32_t);

            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, dc->client_root, COIN_ID_LEN); offset += COIN_ID_LEN;

            for (size_t i = 0; i < dc->num_inputs; i++) {
                if (buf_size < offset + sizeof(Pointer)) return 0;
                serialize_pointer(&dc->inputs[i], buffer + offset); offset += sizeof(Pointer);

                size_t proof_size = serialize_mmr_proof(&dc->proofs[i], buffer + offset, buf_size - offset);
                if (proof_size == 0) return 0;
                offset += proof_size;
            }

            if (buf_size < offset + 32) return 0;
            memcpy(buffer + offset, dc->circuit_hash, 32); offset += 32;

            if (buf_size < offset + sizeof(uint64_t)) return 0;
            uint64_t tvd_be = htobe64(dc->tvd_scaled);
            memcpy(buffer + offset, &tvd_be, sizeof(uint64_t)); offset += sizeof(uint64_t);

            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t shots_be = htobe32(dc->shots);
            memcpy(buffer + offset, &shots_be, sizeof(uint32_t)); offset += sizeof(uint32_t);

            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t status_be = htobe32(dc->status);
            memcpy(buffer + offset, &status_be, sizeof(uint32_t)); offset += sizeof(uint32_t);

            if (buf_size < offset + 32) return 0;
            memcpy(buffer + offset, dc->commitment_root, 32); offset += 32;

            if (buf_size < offset + sizeof(uint64_t)) return 0;
            uint64_t ts_be = htobe64(dc->timestamp_us);
            memcpy(buffer + offset, &ts_be, sizeof(uint64_t)); offset += sizeof(uint64_t);

            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, dc->recipient_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;

            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, dc->sender_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;

            if (buf_size < offset + sizeof(uint64_t)) return 0;
            uint64_t amount_be = htobe64(dc->amount);
            memcpy(buffer + offset, &amount_be, sizeof(uint64_t)); offset += sizeof(uint64_t);

            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, dc->inputs_merkle_root, COIN_ID_LEN); offset += COIN_ID_LEN;

            if (buf_size < offset + 32) return 0;
            memcpy(buffer + offset, dc->cert_digest, 32); offset += 32;

            if (buf_size < offset + SIGNATURE_LEN) return 0;
            memcpy(buffer + offset, dc->signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
            break;
        }
        case OP_UNSTAKE: {
            // Serialize unstaking intent, input pointers with MMR proofs, and threshold signature
            const UnstakeData *sd = &op->data.unstake;
            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, sd->unstake_tx_id, COIN_ID_LEN); offset += COIN_ID_LEN;
            
            if (buf_size < offset + 8) return 0;
            memcpy(buffer + offset, sd->nonce, 8); offset += 8;

            if (buf_size < offset + sizeof(uint32_t)) return 0;
            uint32_t num_inputs_be = htobe32(sd->num_inputs);
            memcpy(buffer + offset, &num_inputs_be, sizeof(uint32_t)); offset += sizeof(uint32_t);

            if (buf_size < offset + COIN_ID_LEN) return 0;
            memcpy(buffer + offset, sd->client_root, COIN_ID_LEN); offset += COIN_ID_LEN;

            for (size_t i = 0; i < sd->num_inputs; i++) {
                if (buf_size < offset + sizeof(Pointer)) return 0;
                serialize_pointer(&sd->inputs[i], buffer + offset); offset += sizeof(Pointer);
                
                size_t proof_size = serialize_mmr_proof(&sd->proofs[i], buffer + offset, buf_size - offset);
                if (proof_size == 0) return 0;
                offset += proof_size;
            }

            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, sd->recipient_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
            
            if (buf_size < offset + PUBKEY_LEN) return 0;
            memcpy(buffer + offset, sd->threshold_pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;

            if (buf_size < offset + sizeof(uint64_t)) return 0;
            uint64_t amount_be = htobe64(sd->amount);
            memcpy(buffer + offset, &amount_be, sizeof(uint64_t)); offset += sizeof(uint64_t);

            if (buf_size < offset + SIGNATURE_LEN) return 0;
            memcpy(buffer + offset, sd->threshold_signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
            break;
        }
        default:
            fprintf(stderr, "[Protocol] Unknown operation type: %d\n", op->type);
            return 0;
    }

    return offset;
}

/**
 * @brief Deserializes an Operation from a type-tagged wire byte slice.
 *
 * @param[in]  buffer    Input byte buffer.
 * @param[in]  buf_size  Available input byte count.
 * @param[out] op        Destination @ref Operation structure populated on success.
 * @param[in]  read_type Flag: if 1, reads leading 1-byte opcode; if 0, uses `op->type` already set.
 * @return Total bytes consumed on success; -1 on format corruption or truncation.
 *
 * @complexity Time: O(op_size), Space: O(1).
 */
int deserialize_operation(const uint8_t *buffer, size_t buf_size, Operation *op, int read_type) {
    if (!buffer || !op || buf_size < 1) {
        fprintf(stderr, "[Protocol] ERROR: Invalid parameters in deserialize_operation\n");
        return -1;
    }

    const uint8_t *p = buffer;
    size_t remaining = buf_size;

    if (read_type) {
        if (remaining < 1) return -1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        op->type = (OperationType)((*p++) % 7);
#else
        op->type = (OperationType)*p++;
#endif
        remaining--;
    }

    if (remaining == 0) return -1;

    switch (op->type) {
        case OP_CLAIM_VALIDATION: {
            // Unpack Bdlop commitment, claimant public key, and Dilithium signature
            ClaimValidationData *cv = &op->data.claim_validation;
            if (remaining < sizeof(BdlopCommitment) + PUBKEY_LEN + SIGNATURE_LEN) return -1;
            memcpy(&cv->commitment, p, sizeof(BdlopCommitment)); p += sizeof(BdlopCommitment);
            remaining -= sizeof(BdlopCommitment);
            memcpy(cv->pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN;
            remaining -= PUBKEY_LEN;
            memcpy(cv->signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN;
            remaining -= SIGNATURE_LEN;
            return p - buffer;
        }
        case OP_REDEEM_CENTINEL: {
            // Unpack Centinel nullifier, Bdlop commitments, and variable-length ZK proof
            RedeemCentinelData *rc = &op->data.redeem_centinel;
                    
            if (remaining < NULLIFIER_LEN + 2 * sizeof(BdlopCommitment) + sizeof(uint32_t)) return -1;
                    
            memcpy(rc->nullifier, p, NULLIFIER_LEN); p += NULLIFIER_LEN;
            remaining -= NULLIFIER_LEN;
                    
            memcpy(&rc->c_transfer, p, sizeof(BdlopCommitment)); p += sizeof(BdlopCommitment);
            remaining -= sizeof(BdlopCommitment);
                    
            memcpy(&rc->c_change, p, sizeof(BdlopCommitment)); p += sizeof(BdlopCommitment);
            remaining -= sizeof(BdlopCommitment);
                    
            uint32_t zk_proof_len_be;
            memcpy(&zk_proof_len_be, p, sizeof(uint32_t));
            rc->zk_proof_len = be32toh(zk_proof_len_be);
            p += sizeof(uint32_t);
            remaining -= sizeof(uint32_t);
                    
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (rc->zk_proof_len > remaining) rc->zk_proof_len = (uint32_t)remaining;
            if (rc->zk_proof_len > ZK_PROOF_MAX_LEN) rc->zk_proof_len = ZK_PROOF_MAX_LEN;
#else
            if (rc->zk_proof_len > ZK_PROOF_MAX_LEN || rc->zk_proof_len > remaining) return -1;
#endif
                    
            memcpy(rc->zk_proof, p, rc->zk_proof_len); p += rc->zk_proof_len;
            remaining -= rc->zk_proof_len;
                    
            return p - buffer;
        }
        case OP_SUBMIT_VALUATION: {
            // Unpack valuation vector, beacon seed, pubkeys, and dual signature attestations
            ValuationData *val = &op->data.submit_valuation;
            size_t bytes = deserialize_valuation_data(val, p, remaining);
            if (bytes == 0) return -1;
            p += bytes;
            remaining -= bytes;
            return p - buffer;
        }
        case OP_MINT_COIN: {
            // Unpack coin metadata, subunit ranges, and audit snapshot records
            MintData *md = &op->data.mint_coin;
            SCLCoin *coin = &md->coin;
                            
            // Calculate minimum required size (32-byte beacon seed per snapshot valuation entry)
            size_t min_required = PUBKEY_LEN + COIN_ID_LEN * 3 + USER_ID_LEN + sizeof(uint64_t) * 2 + sizeof(uint32_t) * 2 + (AUDIT_SIZE * (USER_ID_LEN + NUMBERS_PER_VALUATION * sizeof(uint32_t) + sizeof(uint64_t) + 32));
                            
            if (remaining < min_required) {
                fprintf(stderr, "[Protocol] Insufficient data for OP_MINT_COIN: need %zu, have %zu\n", min_required, remaining);
                return -1;
            }
                            
            memcpy(md->owner_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            memcpy(coin->coin_id, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(coin->owner_address, p, USER_ID_LEN); p += USER_ID_LEN; remaining -= USER_ID_LEN;
            memcpy(coin->creation_tx_hash, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
                    
            uint64_t total_be; memcpy(&total_be, p, 8); coin->total_subunits = be64toh(total_be); p += 8; remaining -= 8;
            uint64_t remaining_be; memcpy(&remaining_be, p, 8); coin->remaining_subunits = be64toh(remaining_be); p += 8; remaining -= 8;
                    
            uint32_t snapshot_count_be; memcpy(&snapshot_count_be, p, sizeof(uint32_t)); coin->snapshot_count = ntohl(snapshot_count_be); p += sizeof(uint32_t); remaining -= sizeof(uint32_t);
            uint32_t snapshot_audit_index_be; memcpy(&snapshot_audit_index_be, p, sizeof(uint32_t)); coin->snapshot_audit_index = ntohl(snapshot_audit_index_be); p += sizeof(uint32_t); remaining -= sizeof(uint32_t);
                    
            memcpy(coin->audit_state_anchor, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
                    
            for (uint32_t i = 0; i < AUDIT_SIZE; i++) {
                Valuation *val = &coin->audit_snapshot[i];
                        
                memcpy(val->user_id, p, USER_ID_LEN); p += USER_ID_LEN; remaining -= USER_ID_LEN;
                        
                for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
                    uint32_t num_be; memcpy(&num_be, p, sizeof(uint32_t)); val->numbers[j] = (int)ntohl(num_be); p += sizeof(uint32_t); remaining -= sizeof(uint32_t);
                }
                        
                uint64_t timestamp_be; memcpy(&timestamp_be, p, sizeof(uint64_t)); val->timestamp = be64toh(timestamp_be); p += sizeof(uint64_t); remaining -= sizeof(uint64_t);
                        
                memcpy(val->beacon_seed, p, 32); p += 32; remaining -= 32;
            }
                    
            return p - buffer;
        }
        case OP_TRANSFER_POINTER: {
            // Unpack transfer header, input pointers, MMR proofs, signatures, and ZK-PRF proof
            TransferData *tx = &op->data.transfer_pointer;
            if (remaining < COIN_ID_LEN + 8 + 4) return -1;
            memcpy(tx->tx_id, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(tx->nonce, p, 8); p += 8; remaining -= 8;
            uint32_t num_be; memcpy(&num_be, p, 4); tx->num_inputs = be32toh(num_be); p += 4; remaining -= 4;
            
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (tx->num_inputs == 0 || tx->num_inputs > MAX_INPUTS) tx->num_inputs = (tx->num_inputs % MAX_INPUTS) + 1;
#else
            if (tx->num_inputs == 0 || tx->num_inputs > MAX_INPUTS || remaining < COIN_ID_LEN) return -1;
#endif
            if (remaining < COIN_ID_LEN) return -1;
            memcpy(tx->client_root, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;

            for (size_t i = 0; i < tx->num_inputs; i++) {
                if (remaining < sizeof(Pointer)) return -1;
                deserialize_pointer(p, &tx->inputs[i]); p += sizeof(Pointer); remaining -= sizeof(Pointer);
                        
                const uint8_t *old_p = p;
                if (deserialize_mmr_proof(&p, buffer + buf_size, &tx->proofs[i]) != 0) return -1;
                if ((size_t)(p - old_p) > remaining) return -1;
                remaining -= (p - old_p);
            }
                    
            if (remaining < PUBKEY_LEN + PUBKEY_LEN + 8 + SIGNATURE_LEN + COIN_ID_LEN + SIGNATURE_LEN + NULLIFIER_LEN + 4) return -1;
            memcpy(tx->recipient_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            memcpy(tx->sender_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            uint64_t amount_be; memcpy(&amount_be, p, 8); tx->amount = be64toh(amount_be); p += 8; remaining -= 8;
            memcpy(tx->signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN; remaining -= SIGNATURE_LEN;
            memcpy(tx->inputs_merkle_root, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(tx->inputs_root_signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN; remaining -= SIGNATURE_LEN;

            // Deserialize ZK-PRF data
            if (remaining < NULLIFIER_LEN + sizeof(uint32_t)) return -1;
            memcpy(tx->prf_output, p, NULLIFIER_LEN);
            p += NULLIFIER_LEN;
            remaining -= NULLIFIER_LEN;

            uint32_t zk_proof_len_be;
            memcpy(&zk_proof_len_be, p, sizeof(uint32_t));
            tx->zk_proof_len = be32toh(zk_proof_len_be);
            p += sizeof(uint32_t);
            remaining -= sizeof(uint32_t);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (tx->zk_proof_len > remaining) tx->zk_proof_len = (uint32_t)remaining;
            if (tx->zk_proof_len > ZK_PROOF_MAX_LEN) tx->zk_proof_len = ZK_PROOF_MAX_LEN;
#else
            if (tx->zk_proof_len > ZK_PROOF_MAX_LEN || tx->zk_proof_len > remaining) return -1;
#endif
            memcpy(tx->zk_proof, p, tx->zk_proof_len);
            p += tx->zk_proof_len;
            remaining -= tx->zk_proof_len;

            return p - buffer;
        }
        case OP_STAKE: {
            // Unpack staking transaction header, input pointers, MMR proofs, and threshold signatures
            StakeData *sd = &op->data.stake;
            if (remaining < COIN_ID_LEN + 8 + 4) return -1;
            memcpy(sd->stake_tx_id, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(sd->nonce, p, 8); p += 8; remaining -= 8;
            uint32_t num_be; memcpy(&num_be, p, 4); sd->num_inputs = be32toh(num_be); p += 4; remaining -= 4;
            
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (sd->num_inputs == 0 || sd->num_inputs > MAX_INPUTS) sd->num_inputs = (sd->num_inputs % MAX_INPUTS) + 1;
#else
            if (sd->num_inputs == 0 || sd->num_inputs > MAX_INPUTS || remaining < COIN_ID_LEN) return -1;
#endif
            if (remaining < COIN_ID_LEN) return -1;
            memcpy(sd->client_root, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            
            for (size_t i = 0; i < sd->num_inputs; i++) {
                if (remaining < sizeof(Pointer)) return -1;
                deserialize_pointer(p, &sd->inputs[i]); p += sizeof(Pointer); remaining -= sizeof(Pointer);
                
                const uint8_t *old_p = p;
                if (deserialize_mmr_proof(&p, buffer + buf_size, &sd->proofs[i]) != 0) return -1;
                if ((size_t)(p - old_p) > remaining) return -1;
                remaining -= (p - old_p);
            }
            
            if (remaining < PUBKEY_LEN + PUBKEY_LEN + 8 + SIGNATURE_LEN + COIN_ID_LEN + SIGNATURE_LEN) return -1;
            memcpy(sd->threshold_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            memcpy(sd->sender_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            uint64_t amount_be; memcpy(&amount_be, p, 8); sd->amount = be64toh(amount_be); p += 8; remaining -= 8;
            memcpy(sd->threshold_signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN; remaining -= SIGNATURE_LEN;
            memcpy(sd->inputs_merkle_root, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(sd->inputs_root_signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN; remaining -= SIGNATURE_LEN;
            
            return p - buffer;
        }
        case OP_APPLY_DRIFT_CERT: {
            // Unpack drift certificate anchoring intent, input pointers, and PQ signature
            ApplyDriftCertData *dc = &op->data.apply_drift_cert;
            if (remaining < COIN_ID_LEN + 8 + 4) return -1;
            memcpy(dc->cert_tx_id, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(dc->nonce, p, 8); p += 8; remaining -= 8;
            uint32_t dc_num_be; memcpy(&dc_num_be, p, 4); dc->num_inputs = be32toh(dc_num_be); p += 4; remaining -= 4;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (dc->num_inputs > MAX_INPUTS) dc->num_inputs = MAX_INPUTS;
#else
            if (dc->num_inputs > MAX_INPUTS || remaining < COIN_ID_LEN) return -1;
#endif
            if (remaining < COIN_ID_LEN) return -1;
            memcpy(dc->client_root, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;

            for (size_t i = 0; i < dc->num_inputs; i++) {
                if (remaining < sizeof(Pointer)) return -1;
                deserialize_pointer(p, &dc->inputs[i]); p += sizeof(Pointer); remaining -= sizeof(Pointer);

                const uint8_t *old_p = p;
                if (deserialize_mmr_proof(&p, buffer + buf_size, &dc->proofs[i]) != 0) return -1;
                if ((size_t)(p - old_p) > remaining) return -1;
                remaining -= (p - old_p);
            }

            if (remaining < 32 + 8 + 4 + 4 + 32 + 8 + PUBKEY_LEN + PUBKEY_LEN + 8 + COIN_ID_LEN + 32 + SIGNATURE_LEN) return -1;
            memcpy(dc->circuit_hash, p, 32); p += 32; remaining -= 32;
            uint64_t tvd_be; memcpy(&tvd_be, p, 8); dc->tvd_scaled = be64toh(tvd_be); p += 8; remaining -= 8;
            uint32_t shots_be; memcpy(&shots_be, p, 4); dc->shots = be32toh(shots_be); p += 4; remaining -= 4;
            uint32_t status_be; memcpy(&status_be, p, 4); dc->status = be32toh(status_be); p += 4; remaining -= 4;
            memcpy(dc->commitment_root, p, 32); p += 32; remaining -= 32;
            uint64_t ts_be; memcpy(&ts_be, p, 8); dc->timestamp_us = be64toh(ts_be); p += 8; remaining -= 8;
            memcpy(dc->recipient_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            memcpy(dc->sender_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            uint64_t amount_be; memcpy(&amount_be, p, 8); dc->amount = be64toh(amount_be); p += 8; remaining -= 8;
            memcpy(dc->inputs_merkle_root, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(dc->cert_digest, p, 32); p += 32; remaining -= 32;
            memcpy(dc->signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN; remaining -= SIGNATURE_LEN;
            return p - buffer;
        }
        case OP_UNSTAKE: {
            // Unpack unstaking transaction header, input pointers, MMR proofs, and threshold signature
            UnstakeData *sd = &op->data.unstake;
            if (remaining < COIN_ID_LEN + 8 + 4) return -1;
            memcpy(sd->unstake_tx_id, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            memcpy(sd->nonce, p, 8); p += 8; remaining -= 8;
            uint32_t num_be; memcpy(&num_be, p, 4); sd->num_inputs = be32toh(num_be); p += 4; remaining -= 4;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (sd->num_inputs == 0 || sd->num_inputs > MAX_INPUTS) sd->num_inputs = (sd->num_inputs % MAX_INPUTS) + 1;
#else
            if (sd->num_inputs == 0 || sd->num_inputs > MAX_INPUTS || remaining < COIN_ID_LEN) return -1;
#endif
            if (remaining < COIN_ID_LEN) return -1;
            memcpy(sd->client_root, p, COIN_ID_LEN); p += COIN_ID_LEN; remaining -= COIN_ID_LEN;
            
            for (size_t i = 0; i < sd->num_inputs; i++) {
                if (remaining < sizeof(Pointer)) return -1;
                deserialize_pointer(p, &sd->inputs[i]); p += sizeof(Pointer); remaining -= sizeof(Pointer);
                
                const uint8_t *old_p = p;
                if (deserialize_mmr_proof(&p, buffer + buf_size, &sd->proofs[i]) != 0) return -1;
                if ((size_t)(p - old_p) > remaining) return -1;
                remaining -= (p - old_p);
            }
            
            // Verify bounds before processing final cryptographic components
            if (remaining < PUBKEY_LEN + PUBKEY_LEN + 8 + SIGNATURE_LEN) return -1;
            
            memcpy(sd->recipient_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            memcpy(sd->threshold_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN; remaining -= PUBKEY_LEN;
            uint64_t amount_be; memcpy(&amount_be, p, 8); sd->amount = be64toh(amount_be); p += 8; remaining -= 8;
            memcpy(sd->threshold_signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN; remaining -= SIGNATURE_LEN;
            return p - buffer;
        }
        default:
            return -1;
    }
}

/* ============================================================================ */
/* SECTION 6: BLOCK, VOTE & AUDIT CONSENSUS WIRE FRAMING                        */
/* ============================================================================ */

int serialize_block(const Block *block, Message *msg, bool include_signature) {
    if (!block || !msg) {
        fprintf(stderr, "[Protocol] serialize_block: Invalid parameters\n");
        return -1;
    }
    
    // Delegate serialization to consensus hashing engine to guarantee bit-for-bit wire parity
    int offset = process_block_data(block, msg->payload, NULL, include_signature);
    if (offset < 0) {
        fprintf(stderr, "[Protocol] Block serialization failed\n");
        return -1;
    }

    msg->length = offset;
    
    if (msg->length > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[Protocol] Serialized block exceeds MAX_MESSAGE_SIZE (%d), actual=%u\n",
                MAX_MESSAGE_SIZE, msg->length);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Deserializes a raw byte slice into a structured Block with heap-allocated operation arrays.
 *
 * @param[out] block      Destination @ref Block structure populated on success.
 * @param[in]  buffer     Input byte slice.
 * @param[in]  buffer_len Available byte count.
 * @return 0 on success; -1 on failure with internal allocations safely freed.
 *
 * @post On success, `block->operations`, `block->batch_prf_outputs`, and `block->batch_zk_proof` are allocated.
 * @complexity Time: O(block_size), Space: O(block_size) heap allocations.
 */
int deserialize_block(Block *block, const uint8_t *buffer, size_t buffer_len) {
    if (!block || !buffer || !buffer_len) {
        scl_log(LOG_LEVEL_ERROR, "Protocol", "Invalid parameters for block deserialization");
        return -1;
    }

    // Initialize block fields
    memset(block, 0, sizeof(Block));
    block->operations = NULL;
    
    const uint8_t *p = buffer;
    const uint8_t *end = buffer + buffer_len;

    // HASHED DATA SECTION - MUST MATCH compute_block_hash() and serialize_block()
    // 1. block_number
    if ((size_t)(end - p) < sizeof(uint64_t)) return -1;
    uint64_t block_number_be;
    memcpy(&block_number_be, p, sizeof(uint64_t));
    block->block_number = be64toh(block_number_be);
    p += sizeof(uint64_t);

    // 2. prev_block_hash
    if ((size_t)(end - p) < COIN_ID_LEN) return -1;
    memcpy(block->prev_block_hash, p, COIN_ID_LEN);
    p += COIN_ID_LEN;

    // 3. operation_count
    if ((size_t)(end - p) < sizeof(uint64_t)) return -1;
    uint64_t op_count_be;
    memcpy(&op_count_be, p, sizeof(uint64_t));
    block->operation_count = be64toh(op_count_be);
    p += sizeof(uint64_t);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (block->operation_count > MAX_OPERATIONS_PER_BLOCK) block->operation_count %= (MAX_OPERATIONS_PER_BLOCK + 1);
#else
    if (block->operation_count > MAX_OPERATIONS_PER_BLOCK) {
        scl_log(LOG_LEVEL_ERROR, "Protocol", "Too many operations: %zu (max %d)",
                block->operation_count, MAX_OPERATIONS_PER_BLOCK);
        return -1;
    }
#endif
    
    // 4. Operations
    if (block->operation_count > 0) {
        block->operations = malloc(block->operation_count * sizeof(Operation));
        if (!block->operations) {
            scl_log(LOG_LEVEL_ERROR, "Protocol", "Failed to allocate memory for operations");
            return -1;
        }
        memset(block->operations, 0, block->operation_count * sizeof(Operation));

        for (size_t i = 0; i < block->operation_count; i++) {
            if (p >= end) goto cleanup_fail;

            uint8_t raw_type = *p++;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            raw_type %= 7;
#endif
            block->operations[i].type = (OperationType)raw_type;

            if (block->operations[i].type == OP_TRANSFER_POINTER) {
                // --- CUSTOM OPTIMIZED DESERIALIZATION FOR ON-CHAIN OP_TRANSFER_POINTER ---
                TransferData *tx = &block->operations[i].data.transfer_pointer;
                        
                if ((size_t)(end - p) < COIN_ID_LEN + 8 + sizeof(uint32_t) + COIN_ID_LEN) goto cleanup_fail;
                memcpy(tx->tx_id, p, COIN_ID_LEN); p += COIN_ID_LEN;
                memcpy(tx->nonce, p, 8); p += 8;
                uint32_t num_be; memcpy(&num_be, p, 4); tx->num_inputs = be32toh(num_be); p += 4;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
                if (tx->num_inputs == 0 || tx->num_inputs > MAX_INPUTS) tx->num_inputs = (tx->num_inputs % MAX_INPUTS) + 1;
#else
                if (tx->num_inputs > MAX_INPUTS) goto cleanup_fail;
#endif

                // Deserialize the client_root, which is the public seed for the ZK-PRF.
                memcpy(tx->client_root, p, COIN_ID_LEN); p += COIN_ID_LEN;

                // Deserialize the `inputs` array.
                for (size_t j = 0; j < tx->num_inputs; j++) {
                    if ((size_t)(end - p) < sizeof(Pointer)) goto cleanup_fail;
                    deserialize_pointer(p, &tx->inputs[j]); p += sizeof(Pointer);
                    if (deserialize_mmr_proof(&p, end, &tx->proofs[j]) != 0) goto cleanup_fail;
                }

                if ((size_t)(end - p) < PUBKEY_LEN + PUBKEY_LEN + sizeof(uint64_t) + SIGNATURE_LEN + COIN_ID_LEN + SIGNATURE_LEN) goto cleanup_fail;
                memcpy(tx->recipient_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN;
                memcpy(tx->sender_pubkey, p, PUBKEY_LEN); p += PUBKEY_LEN;
                uint64_t amount_be; memcpy(&amount_be, p, 8); tx->amount = be64toh(amount_be); p += 8;
                memcpy(tx->signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN;
                memcpy(tx->inputs_merkle_root, p, COIN_ID_LEN); p += COIN_ID_LEN;
                memcpy(tx->inputs_root_signature, p, SIGNATURE_LEN); p += SIGNATURE_LEN;

            } else {
                // For all other types, use the generic full deserializer
                int bytes_read = deserialize_operation(p, end - p, &block->operations[i], 0); // read_type is false
                if (bytes_read <= 0) {
                    scl_log(LOG_LEVEL_ERROR, "Protocol", "Failed to deserialize operation %zu", i);
                    goto cleanup_fail;
                }
                p += bytes_read;
            }
        }
    }

    // 5. entropy_seed (as uint64_t)
    if ((size_t)(end - p) < sizeof(uint64_t)) goto cleanup_fail;
    uint64_t entropy_seed_be;
    memcpy(&entropy_seed_be, p, sizeof(uint64_t));
    block->entropy_seed = be64toh(entropy_seed_be);
    p += sizeof(uint64_t);

    // 6. batch_tx_count
    if ((size_t)(end - p) < sizeof(uint64_t)) goto cleanup_fail;
    uint64_t batch_tx_count_be;
    memcpy(&batch_tx_count_be, p, sizeof(uint64_t));
    block->batch_tx_count = be64toh(batch_tx_count_be);
    p += sizeof(uint64_t);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (block->batch_tx_count > MAX_OPERATIONS_PER_BLOCK) block->batch_tx_count %= (MAX_OPERATIONS_PER_BLOCK + 1);
#else
    if (block->batch_tx_count > MAX_OPERATIONS_PER_BLOCK) goto cleanup_fail;
#endif

    // 7. batch_prf_outputs
    if (block->batch_tx_count > 0) {
        size_t prf_size = block->batch_tx_count * NULLIFIER_LEN;
        if ((size_t)(end - p) < prf_size) goto cleanup_fail;
        block->batch_prf_outputs = malloc(prf_size);
        if (!block->batch_prf_outputs) goto cleanup_fail;
        memcpy(block->batch_prf_outputs, p, prf_size);
        p += prf_size;
    }

    // 8. batch_zk_proof_len
    if ((size_t)(end - p) < sizeof(uint64_t)) goto cleanup_fail;
    uint64_t batch_zk_proof_len_be;
    memcpy(&batch_zk_proof_len_be, p, sizeof(uint64_t));
    block->batch_zk_proof_len = be64toh(batch_zk_proof_len_be);
    p += sizeof(uint64_t);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    size_t avail_proof = (end > p) ? (size_t)(end - p) : 0;
    if (block->batch_zk_proof_len > avail_proof) block->batch_zk_proof_len = avail_proof;
    if (block->batch_zk_proof_len > ZK_PROOF_MAX_LEN) block->batch_zk_proof_len = ZK_PROOF_MAX_LEN;
#else
    if (block->batch_zk_proof_len > ZK_PROOF_MAX_LEN) goto cleanup_fail;
#endif

    // 9. batch_zk_proof
    if (block->batch_zk_proof_len > 0) {
        if ((size_t)(end - p) < block->batch_zk_proof_len) goto cleanup_fail;
        block->batch_zk_proof = malloc(block->batch_zk_proof_len);
        if (!block->batch_zk_proof) goto cleanup_fail;
        memcpy(block->batch_zk_proof, p, block->batch_zk_proof_len);
        p += block->batch_zk_proof_len;
    }

    // 10. proposer_pubkey
    if ((size_t)(end - p) < PUBKEY_LEN) goto cleanup_fail;
    memcpy(block->proposer_pubkey, p, PUBKEY_LEN);
    p += PUBKEY_LEN;

    // NON-HASHED DATA SECTION
    // 11. signature and epoch_threshold_signature
    if ((size_t)(end - p) >= SIGNATURE_LEN) {
        memcpy(block->signature, p, SIGNATURE_LEN);
        p += SIGNATURE_LEN;
        
        if ((size_t)(end - p) >= SIGNATURE_LEN) {
            memcpy(block->epoch_threshold_signature, p, SIGNATURE_LEN);
            p += SIGNATURE_LEN;
        } else {
            memset(block->epoch_threshold_signature, 0, SIGNATURE_LEN);
        }
    }

    scl_log(LOG_LEVEL_TRACE, "Protocol", "Block deserialized successfully");
    return 0;

cleanup_fail:
    scl_log(LOG_LEVEL_ERROR, "Protocol", "Deserialization failed due to insufficient data.");
    if (block->operations) {
        free(block->operations);
        block->operations = NULL;
    }
    if (block->batch_prf_outputs) {
        free(block->batch_prf_outputs);
        block->batch_prf_outputs = NULL;
    }
    if (block->batch_zk_proof) {
        free(block->batch_zk_proof);
        block->batch_zk_proof = NULL;
    }
    return -1;
}

/**
 * @brief Serializes a validator Vote into a MSG_VOTE network message container.
 *
 * @param[in]  vote Pointer to source @ref Vote structure.
 * @param[out] msg  Destination Message structure.
 * @return 0 on success; -1 on parameter failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int serialize_vote(const Vote *vote, Message *msg) {
    if (!vote || !msg) {
        fprintf(stderr, "[Protocol] Invalid vote or message pointers\n");
        return -1;
    }

    msg->type = MSG_VOTE;
    uint32_t offset = 0;

    // Pack voter public key, target block hash, vote decision opcode, and Dilithium signature
    memcpy(msg->payload + offset, vote->voter_pubkey, PUBKEY_LEN);
    offset += PUBKEY_LEN;

    memcpy(msg->payload + offset, vote->block_hash, COIN_ID_LEN);
    offset += COIN_ID_LEN;

    msg->payload[offset] = vote->vote;
    offset += 1;

    memcpy(msg->payload + offset, vote->signature, SIGNATURE_LEN);
    offset += SIGNATURE_LEN;

    msg->length = offset;

    if (msg->length > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[Protocol] Serialized vote exceeds MAX_MESSAGE_SIZE\n");
        return -1;
    }

    printf("[Protocol] Serialized vote, length=%u\n", msg->length);
    return 0;
}

/**
 * @brief Deserializes a MSG_VOTE network message container into a Vote structure.
 *
 * @param[in]  msg  Source network message.
 * @param[out] vote Destination @ref Vote structure.
 * @return 0 on success; -1 on invalid message type or truncation.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int deserialize_vote(const Message *msg, Vote *vote) {
    if (!msg || !vote || msg->type != MSG_VOTE) {
        fprintf(stderr, "[Protocol] Invalid vote message\n");
        return -1;
    }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (msg->length < COIN_ID_LEN + 1) return -1;
    const uint8_t *p = msg->payload;
    memset(vote->voter_pubkey, 0x42, PUBKEY_LEN);
    memcpy(vote->block_hash, p, COIN_ID_LEN); p += COIN_ID_LEN;
    vote->vote = (*p++) % 2;
    memset(vote->signature, 0x42, SIGNATURE_LEN);
    return 0;
#else
    if (msg->length < PUBKEY_LEN + COIN_ID_LEN + 1 + SIGNATURE_LEN) {
        fprintf(stderr, "[Protocol] Vote message too short: %d\n", msg->length);
        return -1;
    }

    const uint8_t *p = msg->payload;
    // Unpack voter public key, block hash, vote decision opcode, and Dilithium signature
    memcpy(vote->voter_pubkey, p, PUBKEY_LEN);
    p += PUBKEY_LEN;
    memcpy(vote->block_hash, p, COIN_ID_LEN);
    p += COIN_ID_LEN;
    vote->vote = *p++;
    
    memcpy(vote->signature, p, SIGNATURE_LEN);
#endif

    char hex_voter[33], hex_bhash[33];
    bytes_to_hex(vote->voter_pubkey, 16, hex_voter);
    bytes_to_hex(vote->block_hash, 16, hex_bhash);
    printf("[Protocol] Deserialized vote: voter_pubkey (first 16 bytes): %s, block_hash (first 16 bytes): %s, vote=%u\n",
           hex_voter, hex_bhash, vote->vote);
    
    return 0;
}

/**
 * @brief Serializes the complete game audit and DKG state into an audit update message envelope.
 *
 * @param[in]  game_state Pointer to source @ref GameState structure.
 * @param[out] msg        Destination Message envelope.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(1).
 */
int serialize_audit_update(const GameState *game_state, Message *msg) {
    if (!game_state || !msg) {
        fprintf(stderr, "[Protocol] Invalid parameters in serialize_audit_update\n");
        return -1;
    }

    msg->type = MSG_UPDATE_AUDIT;
    uint8_t *p = msg->payload;

    // Pack game audit state metadata: timestamp, indices, and subunit accounting
    uint64_t audit_timestamp_net = htobe64(game_state->audit_timestamp);
    memcpy(p, &audit_timestamp_net, sizeof(uint64_t));
    p += sizeof(uint64_t);

    uint32_t current_audit_index_net = htonl(game_state->current_audit_index);
    memcpy(p, &current_audit_index_net, sizeof(uint32_t));
    p += sizeof(uint32_t);

    uint32_t valuation_count_net = htonl(game_state->valuation_count);
    memcpy(p, &valuation_count_net, sizeof(uint32_t));
    p += sizeof(uint32_t);

    uint64_t total_rewarded_net = htobe64(game_state->total_rewarded_scl_subunits);
    memcpy(p, &total_rewarded_net, sizeof(uint64_t));
    p += sizeof(uint64_t);

    uint64_t remaining_net = htobe64(game_state->remaining_scl_subunits);
    memcpy(p, &remaining_net, sizeof(uint64_t));
    p += sizeof(uint64_t);

    // Sync DKG state: epoch threshold public key and epoch counter
    memcpy(p, game_state->epoch_threshold_pubkey, PUBKEY_LEN);
    p += PUBKEY_LEN;
    uint64_t last_dkg_net = htobe64(game_state->last_dkg_epoch);
    memcpy(p, &last_dkg_net, sizeof(uint64_t));
    p += sizeof(uint64_t);

    // Serialize game_audit entries with timestamps and beacon seeds
    for (size_t i = 0; i < AUDIT_SIZE; i++) {
        memcpy(p, game_state->game_audit[i].user_id, USER_ID_LEN);
        p += USER_ID_LEN;
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            uint32_t num_net = htonl(game_state->game_audit[i].numbers[j]);
            memcpy(p, &num_net, sizeof(uint32_t));
            p += sizeof(uint32_t);
        }
        uint64_t timestamp_net = htobe64(game_state->game_audit[i].timestamp);
        memcpy(p, &timestamp_net, sizeof(uint64_t));
        p += sizeof(uint64_t);
        memcpy(p, game_state->game_audit[i].beacon_seed, 32);
        p += 32;
    }

    msg->length = p - msg->payload;

    if (msg->length > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[Protocol] Audit update exceeds MAX_MESSAGE_SIZE: %u\n", msg->length);
        return -1;
    }

    return 0;
}

/**
 * @brief Deserializes an audit update message and synchronizes local GameState if newer.
 *
 * @param[in]  msg        Source network message container.
 * @param[out] game_state Destination @ref GameState structure.
 * @return 0 on applied update; 1 if local state is already fresh; -1 on format failure.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(1).
 */
int deserialize_audit_update(const Message *msg, GameState *game_state) {
    if (!msg || !game_state || msg->type != MSG_UPDATE_AUDIT) {
        fprintf(stderr, "[Protocol] Invalid audit update message\n");
        return -1;
    }

    // Calculate expected length including valuation_count and DKG epoch state fields
    size_t expected_len = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t) + 2 * sizeof(uint64_t) +
                              PUBKEY_LEN + sizeof(uint64_t) + // <--- Added
                              AUDIT_SIZE * (USER_ID_LEN + NUMBERS_PER_VALUATION * sizeof(uint32_t) + sizeof(uint64_t) + 32);
    if (msg->length < expected_len) {
        fprintf(stderr, "[Protocol] Invalid buffer length for audit update: len=%u, expected=%zu\n",
                msg->length, expected_len);
        return -1;
    }

    const uint8_t *p = msg->payload;

    // Unpack audit state metadata
    uint64_t audit_timestamp_net;
    memcpy(&audit_timestamp_net, p, sizeof(uint64_t));
    uint64_t received_audit_timestamp = be64toh(audit_timestamp_net);
    p += sizeof(uint64_t);

    // Verify freshness: reject if received audit timestamp is older than current local state
    if (received_audit_timestamp < game_state->audit_timestamp ||
        (received_audit_timestamp == game_state->audit_timestamp && game_state->current_audit_index != 0)) {
        return 1;  // No update needed
    }

    game_state->audit_timestamp = received_audit_timestamp;

    uint32_t current_audit_index_net;
    memcpy(&current_audit_index_net, p, sizeof(uint32_t));
    game_state->current_audit_index = ntohl(current_audit_index_net);
    p += sizeof(uint32_t);

    uint32_t valuation_count_net;
    memcpy(&valuation_count_net, p, sizeof(uint32_t));
    game_state->valuation_count = ntohl(valuation_count_net);
    p += sizeof(uint32_t);

    uint64_t total_rewarded_net;
    memcpy(&total_rewarded_net, p, sizeof(uint64_t));
    game_state->total_rewarded_scl_subunits = be64toh(total_rewarded_net);
    p += sizeof(uint64_t);

    uint64_t remaining_net;
    memcpy(&remaining_net, p, sizeof(uint64_t));
    game_state->remaining_scl_subunits = be64toh(remaining_net);
    p += sizeof(uint64_t);

    // Sync DKG state
    memcpy(game_state->epoch_threshold_pubkey, p, PUBKEY_LEN);
    p += PUBKEY_LEN;
    uint64_t last_dkg_net;
    memcpy(&last_dkg_net, p, sizeof(uint64_t));
    game_state->last_dkg_epoch = be64toh(last_dkg_net);
    p += sizeof(uint64_t);

    for (size_t i = 0; i < AUDIT_SIZE; i++) {
        memcpy(game_state->game_audit[i].user_id, p, USER_ID_LEN);
        p += USER_ID_LEN;
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            uint32_t num_net;
            memcpy(&num_net, p, sizeof(uint32_t));
            game_state->game_audit[i].numbers[j] = ntohl(num_net);
            p += sizeof(uint32_t);
        }
        uint64_t timestamp_net;
        memcpy(&timestamp_net, p, sizeof(uint64_t));
        game_state->game_audit[i].timestamp = be64toh(timestamp_net);
        p += sizeof(uint64_t);
        memcpy(game_state->game_audit[i].beacon_seed, p, 32);
        p += 32;
    }

    return 0;
}

size_t serialize_pending_operations(Operation **ops, size_t count, uint8_t *buffer, size_t buf_size, size_t *ops_serialized) {
    if (!ops || !buffer || buf_size < 1 || !ops_serialized) return 0;
    
    uint8_t *p = buffer;
    size_t remaining = buf_size;
    size_t serialized_count = 0;
    
    p++; remaining--; // Reserve space for length header byte
    
    // Serialize each operation sequentially until buffer capacity or MAX_PENDING_OPS reached
    for (size_t i = 0; i < count; i++) {
        int op_size = serialize_operation(ops[i], p, remaining);
        if (op_size <= 0 || op_size > (int)remaining) break;
        
        p += op_size;
        remaining -= op_size;
        serialized_count++;
        
        if (serialized_count >= MAX_PENDING_OPS) break;
    }
    
    if (serialized_count == 0) {
        *ops_serialized = 0;
        return 0;
    }
    
    buffer[0] = (uint8_t)serialized_count;
    *ops_serialized = serialized_count;
    
    return p - buffer;
}

size_t deserialize_pending_operations(uint8_t *buffer, size_t len, Operation *ops, size_t max_ops) {
    if (!buffer || !ops || len < 1 || max_ops == 0) return 0;

    uint8_t *p = buffer;
    uint8_t count = *p++;
    size_t remaining = len - 1;

    if (count == 0 || count > max_ops) return 0;

    size_t ops_deserialized = 0;
    // Iterate and deserialize each operation from the contiguous byte stream
    for (uint8_t i = 0; i < count; i++) {
        if (remaining < 1) break;

        int bytes_consumed = deserialize_operation(p, remaining, &ops[ops_deserialized], 1);
        if (bytes_consumed <= 0) {
            p += sizeof(uint8_t);
            remaining -= sizeof(uint8_t);
            continue;
        }

        p += bytes_consumed;
        remaining -= bytes_consumed;
        ops_deserialized++;
        
        if (ops_deserialized >= max_ops) break;
    }

    return ops_deserialized;
}

/* ============================================================================ */
/* SECTION 7: POLYNOMIAL RING R_q & THRESHOLD WIRE FRAMING                      */
/* ============================================================================ */

size_t serialize_poly(const poly_t *p, uint8_t *buf, size_t buf_len) {
    if (!p || !buf || buf_len < RING_DEG * sizeof(poly_coeff_t)) return 0;
    // Serialize ring polynomial coefficients in unreduced binary representation
    size_t offset = 0;
    for (int j = 0; j < RING_DEG; j++) {
        memcpy(buf + offset, &p->coeffs[j], sizeof(poly_coeff_t));
        offset += sizeof(poly_coeff_t);
    }
    return offset;
}

/**
 * @brief Deserializes a polynomial from an unreduced coefficient byte stream and asserts bounds.
 *
 * @param[out] p Destination polynomial ($p \in R_q$).
 * @param[in] buf Input byte stream.
 * @param[in] buf_len Byte length of input stream (must equal `RING_DEG * sizeof(int32_t)` = 1,024).
 * @return 0 on success; -1 on size mismatch or coefficient bound overflow ($|c| > Q/2$).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
int deserialize_poly(poly_t *p, const uint8_t *buf, size_t buf_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (!p || !buf) return -1;
    memset(p->coeffs, 0, sizeof(p->coeffs));
    size_t copy_len = MIN(buf_len, sizeof(p->coeffs));
    if (copy_len > 0) memcpy(p->coeffs, buf, copy_len);
    return 0;
#else
    size_t expected = RING_DEG * sizeof(poly_coeff_t);
    if (buf_len != expected) {
        fprintf(stderr, "[Crypto] ERROR: deserialize_poly buf_len %zu != expected %zu\n", buf_len, expected);
        return -1;
    }
    size_t offset = 0;
    for (int j = 0; j < RING_DEG; j++) {
        memcpy(&p->coeffs[j], buf + offset, sizeof(poly_coeff_t));
        offset += sizeof(poly_coeff_t);
    }
    // Bounds check post-deserialize
    int32_t max_c = poly_max_coeff(p);
    if (max_c > (Q / 2)) {
        fprintf(stderr, "[Crypto] ERROR: Deserialized poly max coeff %d > Q/2 %d\n", max_c, Q / 2);
        return -1;
    }
    return 0;
#endif
}

/**
 * @brief Deserializes a polynomial vector from an unreduced coefficient byte stream and asserts bounds.
 *
 * @param[out] v Destination polynomial vector structure (must have `v->len == num_polys`).
 * @param[in] buf Input byte stream.
 * @param[in] buf_len Byte length of input stream (must equal `num_polys * 1024`).
 * @param[in] num_polys Expected dimension of the vector.
 * @return 0 on success; -1 on size mismatch or coefficient bound overflow ($|c| > Q/2$).
 *
 * @complexity Time: O(num_polys * RING_DEG), Space: O(1).
 */
int deserialize_polyvec(polyvec_t *v, const uint8_t *buf, size_t buf_len, size_t num_polys) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (!v || !buf || v->len != num_polys) return -1;
    for (size_t i = 0; i < num_polys; i++) {
        memset(v->vec[i].coeffs, 0, sizeof(v->vec[i].coeffs));
    }
    size_t copy_len = MIN(buf_len, num_polys * RING_DEG * sizeof(poly_coeff_t));
    if (copy_len > 0) {
        memcpy(v->vec[0].coeffs, buf, copy_len);
    }
    return 0;
#else
    size_t expected = num_polys * RING_DEG * sizeof(poly_coeff_t);
    if (buf_len != expected || v->len != num_polys) {
        fprintf(stderr, "[Crypto] ERROR: deserialize_polyvec buf_len %zu != expected %zu for %zu polys (v->len=%zu)\n",
                buf_len, expected, num_polys, v->len);
        return -1;
    }
    size_t offset = 0;
    for (size_t i = 0; i < num_polys; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            memcpy(&v->vec[i].coeffs[j], buf + offset, sizeof(poly_coeff_t));
            offset += sizeof(poly_coeff_t);
        }
    }
    // Bounds check post-deserialize
    int32_t max_c = polyvec_max_coeff(v);
    if (max_c > (Q / 2)) {
        fprintf(stderr, "[Crypto] ERROR: Deserialized polyvec max coeff %d > Q/2 %d\n", max_c, Q / 2);
        return -1;
    }
    scl_log(LOG_LEVEL_TRACE, "Crypto", "deserialize_polyvec succeeded for %zu polys, max coeff=%d", num_polys, max_c);
    return 0;
#endif
}

/**
 * @brief Serializes a pre-staking payload for threshold signature aggregation.
 *
 * @param[in]  sd          Pointer to source @ref StakeData structure.
 * @param[out] buffer      Output byte buffer.
 * @param[out] len         Pointer receiving written byte length.
 * @param[in]  set_id_zero Flag: if true, zeroizes `stake_tx_id` field before serializing.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(1).
 */
int serialize_stake_payload(const StakeData *sd, uint8_t *buffer, size_t *len, bool set_id_zero) {
    if (!sd || !buffer || !len || sd->num_inputs > MAX_INPUTS) {
        fprintf(stderr, "[Protocol] Invalid parameters in serialize_stake_payload\n");
        return -1;
    }

    uint8_t *p = buffer;
    // Pack stake transaction ID (zeroized if computing pre-identity signing digest)
    if (set_id_zero) {
        memset(p, 0, COIN_ID_LEN);
    } else {
        memcpy(p, sd->stake_tx_id, COIN_ID_LEN);
    }
    p += COIN_ID_LEN;
    memcpy(p, sd->nonce, 8);
    p += 8;
    uint32_t num_inputs_net = htonl(sd->num_inputs);
    memcpy(p, &num_inputs_net, sizeof(uint32_t));
    p += sizeof(uint32_t);
    memcpy(p, sd->client_root, COIN_ID_LEN);
    p += COIN_ID_LEN;
        
    memcpy(p, sd->inputs_merkle_root, COIN_ID_LEN);
    p += COIN_ID_LEN;

    // Serialize input pointers (spent/staked flags normalized to 0) with MMR proofs
    for (size_t i = 0; i < sd->num_inputs; i++) {
        Pointer temp = sd->inputs[i];
        temp.spent = 0;
        temp.staked = 0;
        serialize_pointer(&temp, p);
        p += sizeof(Pointer);
        size_t proof_size = serialize_mmr_proof(&sd->proofs[i], p, MAX_MESSAGE_SIZE - (p - buffer));
        if (proof_size == 0) {
            fprintf(stderr, "[Protocol] Failed to serialize MMR proof %zu in stake payload\n", i);
            return -1;
        }
        p += proof_size;
    }

    // Pack threshold public key and stake subunit amount
    memcpy(p, sd->threshold_pubkey, PUBKEY_LEN);
    p += PUBKEY_LEN;
    uint64_t amount_net = htobe64(sd->amount);
    memcpy(p, &amount_net, sizeof(uint64_t));
    p += sizeof(uint64_t);

    *len = p - buffer;
    return 0;
}

/**
 * @brief Serializes an unstaking payload for threshold signature aggregation.
 *
 * @param[in]  sd          Pointer to source @ref UnstakeData structure.
 * @param[out] buffer      Output byte buffer.
 * @param[out] len         Pointer receiving written byte length.
 * @param[in]  set_id_zero Flag: if true, zeroizes `unstake_tx_id` field before serializing.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(1).
 */
int serialize_unstake_payload(const UnstakeData *sd, uint8_t *buffer, size_t *len, bool set_id_zero) {
    if (!sd || !buffer || !len || sd->num_inputs > MAX_INPUTS) {
        fprintf(stderr, "[Protocol] Invalid parameters in serialize_unstake_payload\n");
        return -1;
    }

    uint8_t *p = buffer;
    // Pack unstake transaction ID (zeroized if computing pre-identity signing digest)
    if (set_id_zero) {
        memset(p, 0, COIN_ID_LEN);
    } else {
        memcpy(p, sd->unstake_tx_id, COIN_ID_LEN);
    }
    p += COIN_ID_LEN;
    memcpy(p, sd->nonce, 8);
    p += 8;
    uint32_t num_inputs_net = htonl(sd->num_inputs);
    memcpy(p, &num_inputs_net, sizeof(uint32_t));
    p += sizeof(uint32_t);
    memcpy(p, sd->client_root, COIN_ID_LEN);
    p += COIN_ID_LEN;

    // Serialize input pointers (spent/staked flags normalized to 0) with MMR proofs
    for (size_t i = 0; i < sd->num_inputs; i++) {
        Pointer temp = sd->inputs[i];
        temp.spent = 0;
        temp.staked = 0;
        serialize_pointer(&temp, p);
        p += sizeof(Pointer);
        size_t proof_size = serialize_mmr_proof(&sd->proofs[i], p, MAX_MESSAGE_SIZE - (p - buffer));
        if (proof_size == 0) {
            fprintf(stderr, "[Protocol] Failed to serialize MMR proof %zu\n", i);
            return -1;
        }
        p += proof_size;
    }

    // Pack recipient public key, threshold public key, and unstake subunit amount
    memcpy(p, sd->recipient_pubkey, PUBKEY_LEN);
    p += PUBKEY_LEN;
    memcpy(p, sd->threshold_pubkey, PUBKEY_LEN);
    p += PUBKEY_LEN;
    uint64_t amount_net = htobe64(sd->amount);
    memcpy(p, &amount_net, sizeof(uint64_t));
    p += sizeof(uint64_t);

    *len = p - buffer;
    return 0;
}
