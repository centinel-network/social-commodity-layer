/**
 * @file common/network/protocol.h
 * @brief Satocialist Protocol: Wire Serialization, Packet Framing, and Deserialization Engine
 *
 * @details
 * Declares the formal wire encoding and decoding interfaces for all on-chain operations,
 * peer-to-peer network messages, cryptographic inclusion proofs, polynomial vectors,
 * and block structures across the Satocialist Cryptographic Ledger (SCL).
 *
 * @section protocol_invariants System Invariants Maintained
 * - Network Byte Order Invariance: All multi-byte integers (16-bit, 32-bit, 64-bit) are encoded
 *   strictly in Big-Endian network byte order (`htobe16`, `htobe32`, `htobe64` on serialization;
 *   `be16toh`, `be32toh`, `be64toh` on deserialization).
 * - Bounded Message Framing: No message envelope may exceed @ref MAX_MESSAGE_SIZE (8,388,608 bytes).
 * - Structural Integrity: Serialized operations and blocks maintain exact identity with their
 *   corresponding cryptographic hashing contexts, guaranteeing tamper-evident transport.
 * - Polynomial Coefficient Bounds: Ring elements ($p \in R_q$) must have coefficients strictly bounded
 *   within $|c| \le Q/2$ post-deserialization.
 * - ZK Proof Payload Bounds: Zero-knowledge proofs and nullifiers are strictly bounded by
 *   @ref ZK_PROOF_MAX_LEN to prevent buffer overflows during consensus verification.
 *
 * @section memory_concurrency Concurrency and Memory Ownership
 * - Serialization functions read from caller-provided immutable structures and write into
 *   caller-allocated contiguous memory buffers.
 * - Deserialization routines construct parsed structures in caller-managed storage or allocate
 *   ephemeral working memory from thread-local memory arenas (`arena_alloc`).
 * - All interfaces declared herein are reentrant and stateless with respect to global synchronization.
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "user.h"
#include "blockchain.h"
#include "mmr.h"
#include <stddef.h>
#include <stdint.h>
#include "constants.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: L5 P2P MESSAGE ENVELOPE FRAMING                                   */
/* ============================================================================ */

/**
 * @brief Serializes a high-level Message structure into a contiguous wire buffer.
 *
 * @details
 * Encodes the 1-byte message type discriminator followed by a 4-byte big-endian
 * payload length prefix, followed by `msg->length` raw payload bytes.
 *
 * @param[in] msg Pointer to source Message structure.
 * @param[out] buffer Destination buffer receiving framed bytes (must hold at least 5 + msg->length bytes).
 * @param[out] len Destination receiving total serialized byte count (5 + msg->length).
 * @return 0 on success; -1 if parameters are NULL or payload length exceeds @ref MAX_MESSAGE_SIZE.
 *
 * @pre `msg` and `buffer` must be non-NULL; `msg->length <= MAX_MESSAGE_SIZE`.
 * @post `*len` reflects total written bytes: `1 + 4 + msg->length`.
 * @complexity Time: O(msg->length), Space: O(1) auxiliary.
 */
int serialize_message(const Message *msg, uint8_t *buffer, size_t *len);

/**
 * @brief Deserializes a framed wire buffer into a structured Message container.
 *
 * @details
 * Validates that `len >= 5`, extracts the 1-byte type opcode, reads the 4-byte
 * big-endian payload length, and copies the message payload into `msg->payload`.
 *
 * @param[in] buffer Raw input wire bytes.
 * @param[in] len Total length of input wire buffer.
 * @param[out] msg Destination Message structure populated on success.
 * @return 0 on success; -1 if buffer is malformed, truncated, or exceeds @ref MAX_MESSAGE_SIZE.
 *
 * @pre `buffer` and `msg` must be non-NULL; `len >= 5`.
 * @post `msg->type` and `msg->length` are populated; `msg->payload` contains body bytes.
 * @complexity Time: O(msg->length), Space: O(1) auxiliary.
 */
int deserialize_message(uint8_t *buffer, size_t len, Message *msg);

/**
 * @brief Serializes a network socket address into a canonical 19-byte cross-platform wire envelope.
 *
 * @details
 * Standardizes IPv4 and IPv6 representations into a deterministic 19-byte slice:
 * - Byte 00..00: Address Family flag (`SCL_ADDR_FAMILY_IPV4` = 0x04 or `SCL_ADDR_FAMILY_IPV6` = 0x06).
 * - Bytes 01..16: 16-byte address. IPv4 addresses are encoded as IPv4-mapped IPv6 (`::ffff:a.b.c.d`).
 * - Bytes 17..18: 16-bit port number in network byte order (Big-Endian).
 *
 * @param[in] addr Pointer to source @ref sockaddr_storage endpoint to serialize.
 * @param[out] buffer Destination buffer (must allocate at least @ref SCL_ADDR_WIRE_LEN = 19 bytes).
 *
 * @pre `addr` and `buffer` must be non-NULL; `addr->ss_family` must be `AF_INET` or `AF_INET6`.
 * @post `buffer[0..18]` populated with canonical address encoding.
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(1), Space: O(1).
 */
void serialize_sockaddr(const struct sockaddr_storage *addr, uint8_t *buffer);

/**
 * @brief Deserializes a canonical 19-byte wire envelope into a platform sockaddr_storage structure.
 *
 * @details
 * Parses the 1-byte family discriminator:
 * - If `SCL_ADDR_FAMILY_IPV4`: Reconstructs `AF_INET` structure with IPv4 address and port.
 * - If `SCL_ADDR_FAMILY_IPV6`: Reconstructs `AF_INET6` structure with full 128-bit address and port.
 *
 * @param[in] buffer Input byte buffer containing the 19-byte canonical wire representation.
 * @param[in] len Available byte length of `buffer` (must be $\ge$ @ref SCL_ADDR_WIRE_LEN).
 * @param[out] addr Destination @ref sockaddr_storage structure populated on success.
 * @return 0 on successful deserialization; -1 on buffer underflow or unrecognized family opcode.
 *
 * @pre `buffer` and `addr` must be non-NULL; `len >= SCL_ADDR_WIRE_LEN`.
 * @post On return 0, `addr` contains valid socket coordinates suitable for `bind` or `sendto`.
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(1), Space: O(1).
 */
int deserialize_sockaddr(const uint8_t *buffer, size_t len, struct sockaddr_storage *addr);

/**
 * @brief Architectural self-test verifying canonical 19-byte address serialization for IPv4 and IPv6.
 *
 * @details
 * Validates:
 * 1. Exact bit-level round-trip serialization and deserialization for IPv4 `sockaddr_in`.
 * 2. Exact bit-level round-trip serialization and deserialization for IPv6 `sockaddr_in6`.
 * 3. Robust rejection of truncated or malformed buffers (`len < SCL_ADDR_WIRE_LEN`).
 *
 * @return 0 if all assertions pass; -1 on regression or serialization failure.
 * @complexity Time: O(1), Space: O(1) stack allocation.
 */
int scl_protocol_run_ipv6_selftest(void);

/* ============================================================================ */
/* SECTION 2: MERKLE MOUNTAIN RANGE (MMR) PROOF SERIALIZATION                   */
/* ============================================================================ */

/**
 * @brief Serializes an MMR inclusion proof into a compact binary byte stream.
 *
 * @details
 * Encodes:
 * 1. 4-byte big-endian path length `P`.
 * 2. `P` records of 32-byte sibling hash + 4-byte big-endian `is_left` flag.
 * 3. 4-byte big-endian left peaks count `L` followed by `L * 32` bytes of peak hashes.
 * 4. 4-byte big-endian right peaks count `R` followed by `R * 32` bytes of peak hashes.
 *
 * @param[in] proof Pointer to source @ref MMRProof structure.
 * @param[out] buffer Output byte buffer.
 * @param[in] buf_size Available capacity of `buffer`.
 * @return Number of bytes written on success; 0 on buffer overflow or dimension invalidity.
 *
 * @pre `proof` and `buffer` non-NULL; `proof->path_len <= MAX_PATH_LEN`.
 * @complexity Time: O(P + L + R), Space: O(1) auxiliary.
 */
size_t serialize_mmr_proof(const MMRProof *proof, uint8_t *buffer, size_t buf_size);

/**
 * @brief Deserializes an MMR inclusion proof from a streaming cursor.
 *
 * @param[in,out] p Double pointer to current read position in buffer (advanced upon return).
 * @param[in] msg_end Pointer to end boundary of the enclosing packet buffer.
 * @param[out] proof Destination @ref MMRProof structure populated on success.
 * @return 0 on success; -1 on truncation, dimension bounds breach, or corrupt length prefix.
 *
 * @pre `p`, `*p`, `msg_end`, and `proof` must be non-NULL; `*p < msg_end`.
 * @post `*p` is advanced past the consumed proof bytes.
 * @complexity Time: O(path_len + peaks_len), Space: O(1) auxiliary.
 */
int deserialize_mmr_proof(const uint8_t **p, const uint8_t *msg_end, MMRProof *proof);

/* ============================================================================ */
/* SECTION 3: VALUATION VECTORS & MATRIX ROW SERIALIZATION                      */
/* ============================================================================ */

/**
 * @brief Serializes core valuation data (user ID, 10 integers, timestamp) without beacon seed.
 *
 * @param[in] val Pointer to source @ref Valuation structure.
 * @param[out] buffer Destination buffer (must allocate at least 80 bytes).
 * @return Total bytes written (exactly 80 bytes).
 *
 * @complexity Time: O(1), Space: O(1).
 */
size_t serialize_core_valuation(const Valuation *val, uint8_t *buffer);

/**
 * @brief Deserializes core valuation data from a byte buffer.
 *
 * @param[in] buffer Source byte buffer.
 * @param[out] val Destination @ref Valuation structure populated with core fields.
 * @return Total bytes consumed (exactly 80 bytes).
 *
 * @complexity Time: O(1), Space: O(1).
 */
size_t deserialize_core_valuation(const uint8_t *buffer, Valuation *val);

/* ============================================================================ */
/* SECTION 4: SUBUNIT POINTER UTXO SERIALIZATION                                */
/* ============================================================================ */

/**
 * @brief Serializes a full Pointer UTXO structure with big-endian integer fields.
 *
 * @details
 * Wire format (152 bytes):
 * - PointerID (32 bytes)
 * - ParentCoinID (32 bytes)
 * - StartSubunit (8 bytes, BE uint64)
 * - EndSubunit (8 bytes, BE uint64)
 * - OwnerAddress (32 bytes)
 * - PrevTxHash (32 bytes)
 * - Spent status (4 bytes, BE uint32)
 * - Staked status (4 bytes, BE uint32)
 *
 * @param[in] pointer Pointer to source @ref Pointer structure.
 * @param[out] buffer Destination buffer (must allocate at least 152 bytes).
 *
 * @complexity Time: O(1), Space: O(1).
 */
void serialize_pointer(const Pointer *pointer, uint8_t *buffer);

/**
 * @brief Serializes immutable pointer fields required for input Merkle tree generation.
 *
 * @details
 * Excludes mutable state flags (`spent`, `staked`) to produce the 112-byte signing representation:
 * ParentCoinID (32) || OwnerAddress (32) || StartSubunit (8, BE) || EndSubunit (8, BE) || PrevTxHash (32).
 *
 * @param[in] ptr Pointer to source @ref Pointer structure.
 * @param[out] buffer Destination buffer (must allocate at least 112 bytes).
 *
 * @complexity Time: O(1), Space: O(1).
 */
void serialize_pointer_for_signing(const Pointer *ptr, uint8_t *buffer);

/**
 * @brief Deserializes a 152-byte wire buffer into a structured Pointer UTXO.
 *
 * @param[in] buffer Source byte buffer.
 * @param[out] pointer Destination @ref Pointer structure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void deserialize_pointer(const uint8_t *buffer, Pointer *pointer);

/* ============================================================================ */
/* SECTION 5: ON-CHAIN TRANSACTION PAYLOAD SERIALIZATION                        */
/* ============================================================================ */

/**
 * @brief Serializes the complete wire payload of an on-chain transfer transaction.
 *
 * @param[in] tx Pointer to source @ref TransferData structure.
 * @param[out] buffer Output byte buffer.
 * @param[out] len Destination receiving total serialized length in bytes.
 * @return 0 on success; -1 on parameter failure or input count exceeding @ref MAX_INPUTS.
 *
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(1).
 */
int serialize_transfer_payload(const TransferData *tx, uint8_t *buffer, size_t *len);

/**
 * @brief Deserializes a MSG_PTR_TRANSFER message payload into an arena-allocated TransferData structure.
 *
 * @param[in] msg Source network message container.
 * @param[out] payload_ptr Pointer to receive address of deserialized TransferData (allocated in arena).
 * @param[out] signed_data_len Destination receiving length of byte slice covered by the main signature.
 * @return 0 on success; -1 on format corruption or truncation.
 *
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(sizeof(TransferData)) arena allocation.
 */
int deserialize_transfer_payload(const Message *msg, TransferData **payload_ptr, size_t *signed_data_len);

/**
 * @brief Serializes consensus-critical fields of a TransferData structure for Dilithium signature verification.
 *
 * @details
 * Excludes client-side witness data (MMR proofs, client root) to serialize the canonical 5,264-byte signing image:
 * TxID (32) || Nonce (8) || InputsMerkleRoot (32) || RecipientPubkey (2592) || SenderPubkey (2592) || Amount (8, BE).
 *
 * @param[in] tx Pointer to source @ref TransferData structure.
 * @param[out] buffer Destination buffer (must allocate at least 5,264 bytes).
 * @param[out] len Destination receiving serialized byte length.
 * @return 0 on success; -1 on NULL parameter.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int serialize_transfer_for_signature(const TransferData *tx, uint8_t *buffer, size_t *len);

/**
 * @brief Serializes an on-chain Operation into a type-tagged wire byte slice.
 *
 * @param[in] op Pointer to source @ref Operation structure.
 * @param[out] buffer Output byte buffer.
 * @param[in] buf_size Available capacity in `buffer`.
 * @return Number of bytes written on success; 0 on buffer overflow or unknown operation type.
 *
 * @complexity Time: O(op_size), Space: O(1).
 */
int serialize_operation(const Operation *op, uint8_t *buffer, size_t buf_size);

/**
 * @brief Deserializes an Operation from a type-tagged wire byte slice.
 *
 * @param[in] buffer Input byte buffer.
 * @param[in] buf_size Available input byte count.
 * @param[out] op Destination @ref Operation structure populated on success.
 * @param[in] read_type Flag: if 1, reads leading 1-byte opcode; if 0, uses `op->type` already set.
 * @return Total bytes consumed on success; -1 on format corruption or truncation.
 *
 * @complexity Time: O(op_size), Space: O(1).
 */
int deserialize_operation(const uint8_t *buffer, size_t buf_size, Operation *op, int read_type);

/**
 * @brief Serializes a pre-staking payload for threshold signature aggregation.
 *
 * @param[in] sd Pointer to source @ref StakeData structure.
 * @param[out] buffer Output byte buffer.
 * @param[out] len Destination receiving written byte length.
 * @param[in] set_id_zero Flag: if true, zeroizes `stake_tx_id` field before serializing.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(1).
 */
int serialize_stake_payload(const StakeData *sd, uint8_t *buffer, size_t *len, bool set_id_zero);

/**
 * @brief Serializes an unstaking payload for threshold signature aggregation.
 *
 * @param[in] sd Pointer to source @ref UnstakeData structure.
 * @param[out] buffer Output byte buffer.
 * @param[out] len Destination receiving written byte length.
 * @param[in] set_id_zero Flag: if true, zeroizes `unstake_tx_id` field before serializing.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(1).
 */
int serialize_unstake_payload(const UnstakeData *sd, uint8_t *buffer, size_t *len, bool set_id_zero);

/* ============================================================================ */
/* SECTION 6: BLOCK, VOTE & AUDIT CONSENSUS WIRE FRAMING                        */
/* ============================================================================ */

/**
 * @brief Serializes a complete Block into a network Message container.
 *
 * @param[in] block Pointer to source @ref Block structure.
 * @param[out] msg Destination Message structure.
 * @param[in] include_signature Flag: if true, includes validator signatures; if false, pre-sign image.
 * @return 0 on success; -1 on serialization error or length exceeding @ref MAX_MESSAGE_SIZE.
 *
 * @complexity Time: O(block_size), Space: O(1) auxiliary.
 */
int serialize_block(const Block *block, Message *msg, bool include_signature);

/**
 * @brief Deserializes a raw byte slice into a structured Block with heap-allocated operation arrays.
 *
 * @param[out] block Destination @ref Block structure populated on success.
 * @param[in] buffer Input byte slice.
 * @param[in] buffer_len Available byte count.
 * @return 0 on success; -1 on failure with internal allocations safely freed.
 *
 * @post On success, `block->operations`, `block->batch_prf_outputs`, and `block->batch_zk_proof`
 *       are allocated on heap. Caller must free via @ref free_block.
 * @complexity Time: O(block_size), Space: O(block_size) heap allocations.
 */
int deserialize_block(Block *block, const uint8_t *buffer, size_t buffer_len);

/**
 * @brief Serializes a validator Vote into a MSG_VOTE network message container.
 *
 * @param[in] vote Pointer to source @ref Vote structure.
 * @param[out] msg Destination Message structure.
 * @return 0 on success; -1 on parameter failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int serialize_vote(const Vote *vote, Message *msg);

/**
 * @brief Deserializes a MSG_VOTE network message container into a Vote structure.
 *
 * @param[in] msg Source network message.
 * @param[out] vote Destination @ref Vote structure.
 * @return 0 on success; -1 on invalid message type or truncation.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int deserialize_vote(const Message *msg, Vote *vote);

/**
 * @brief Serializes the complete Game Audit state, DKG threshold parameters, and beacon seeds.
 *
 * @details
 * Packs audit accounting metrics, current audit index, valuation entries (with 32-byte beacon seeds),
 * and the active epoch threshold public key with its corresponding DKG epoch counter.
 *
 * @param[in] game_state Pointer to source @ref GameState structure.
 * @param[out] msg Destination Message structure populated with MSG_UPDATE_AUDIT payload.
 * @return 0 on success; -1 on error.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(1).
 */
int serialize_audit_update(const GameState *game_state, Message *msg);

/**
 * @brief Deserializes a MSG_UPDATE_AUDIT message payload and synchronizes local GameState.
 *
 * @details
 * Validates message length including the DKG epoch state, unpacks metrics and valuation records,
 * and updates local state if the received audit timestamp is strictly newer.
 *
 * @param[in] msg Source network message container.
 * @param[out] game_state Destination @ref GameState structure.
 * @return 0 on success; 1 if remote timestamp is older than local; -1 on format corruption.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(1).
 */
int deserialize_audit_update(const Message *msg, GameState *game_state);

/**
 * @brief Serializes a batch of pending mempool operations into a length-prefixed byte stream.
 *
 * @param[in] ops Array of pointers to pending @ref Operation structures.
 * @param[in] count Number of candidate operations.
 * @param[out] buffer Output byte buffer.
 * @param[in] buf_size Available capacity in `buffer`.
 * @param[out] ops_serialized Destination receiving actual count of operations serialized.
 * @return Total bytes written; 0 on error or capacity exhaustion.
 *
 * @complexity Time: O(written_bytes), Space: O(1).
 */
size_t serialize_pending_operations(Operation **ops, size_t count, uint8_t *buffer, size_t buf_size, size_t *ops_serialized);

/**
 * @brief Deserializes a batch of pending mempool operations from a wire byte slice.
 *
 * @param[in] buffer Input byte buffer.
 * @param[in] len Total length of input buffer.
 * @param[out] ops Pre-allocated array of @ref Operation structures receiving deserialized data.
 * @param[in] max_ops Maximum allowable operations to unpack into `ops`.
 * @return Number of operations successfully deserialized.
 *
 * @complexity Time: O(consumed_bytes), Space: O(1).
 */
size_t deserialize_pending_operations(uint8_t *buffer, size_t len, Operation *ops, size_t max_ops);

/* ============================================================================ */
/* SECTION 7: POLYNOMIAL RING R_q SERIALIZATION                                 */
/* ============================================================================ */

/**
 * @brief Serializes an element polynomial in R_q (256 signed 32-bit coefficients = 1,024 bytes).
 *
 * @param[in] poly Pointer to source @ref poly_t structure.
 * @param[out] buf Output byte buffer (must allocate at least 1,024 bytes).
 * @param[in] buf_len Available buffer capacity.
 * @return Total bytes written (1,024 on success; 0 on buffer underflow).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
size_t serialize_poly(const poly_t *poly, uint8_t *buf, size_t buf_len);

/**
 * @brief Deserializes an element polynomial in R_q and verifies coefficient bounds (|c| <= Q/2).
 *
 * @param[out] poly Destination @ref poly_t structure.
 * @param[in] buf Input byte buffer containing exactly 1,024 bytes.
 * @param[in] buf_len Available input byte count.
 * @return 0 on success; -1 on length mismatch or coefficient bound overflow.
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
int deserialize_poly(poly_t *poly, const uint8_t *buf, size_t buf_len);

/**
 * @brief Deserializes a vector of polynomials in R_q^K or R_q^L and verifies coefficient bounds.
 *
 * @param[out] vec Destination @ref polyvec_t structure (must be initialized with `len == expected_len`).
 * @param[in] buf Input byte buffer.
 * @param[in] buf_len Available input byte count (must equal `expected_len * 1024`).
 * @param[in] expected_len Expected number of polynomials in vector.
 * @return 0 on success; -1 on length mismatch or coefficient bound overflow.
 *
 * @complexity Time: O(expected_len * RING_DEG), Space: O(1).
 */
int deserialize_polyvec(polyvec_t *vec, const uint8_t *buf, size_t buf_len, size_t expected_len);

#ifdef __cplusplus
}
#endif

#endif // PROTOCOL_H
