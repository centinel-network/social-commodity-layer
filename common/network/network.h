/**
 * @file common/network/network.h
 * @brief Satocialist Protocol: Transport Drivers, L1-L4 Networking, and QUIC-Parity Subsystem
 *
 * @details
 * Declares the core network transport abstractions, packet multiplexing mechanisms,
 * and reliable P2P communication interfaces for the Satocialist Cryptographic Ledger (SCL).
 * Supports both high-performance zero-copy kernel bypass (Linux AF_XDP) and a portable,
 * non-blocking POSIX UDP driver with epoll/kqueue event demultiplexing.
 *
 * @section protocol_layers Layered Transport Architecture
 * - L0 Raw Driver Shim: Polling event loops, XDP/UDP socket abstraction, ring buffers.
 * - L1 Routing & CID Table: 20-byte Connection ID hashing, stateless token verification, NAT traversal.
 * - L2 Authenticated Encryption: AES-256-GCM AEAD packet encapsulation with implicit nonces.
 * - L3 Multiplexer & FEC: Stream/datagram prioritization, 8+2 Reed-Solomon erasure coding over GF(2^8).
 * - L4 Reliability & Congestion: BBRv3 congestion control, smoothed RTT filtering, RFC 9002 loss detection.
 * - L5 Consensus Application: Decentralized message routing, cryptographic proof verification dispatch.
 *
 * @section protocol_invariants System Invariants
 * - Link MTU Safety: Maximum physical packet size is constrained to SCL_LINK_MTU (1,280 bytes)
 *   minus IP/UDP overhead (1,232 bytes maximum payload) to guarantee unfragmented traversal.
 * - Cryptographic Forward Secrecy: Ephemeral ML-KEM-512 (Kyber-512) keypairs are generated per
 *   session handshake and immediately zeroized post-decapsulation.
 * - Anti-Amplification & Anti-DoS: Servers never transmit responses exceeding 3x the bytes received
 *   until client address reachability is authenticated via stateless cookies or handshake tokens.
 * - Out-of-Order Memory Quota: Total memory allocated to out-of-order reassembly buffers across all
 *   connections is strictly bounded by `global_ooo_quota` (512 MiB).
 *
 * @section concurrency_model Concurrency and Synchronization
 * - Connection lifecycle is managed through atomic reference counting (`try_acquire_ref`, `scl_connection_release`).
 * - Lock-free single-producer single-consumer queues (SPSC) transfer packets from driver threads to workers.
 * - Per-connection reliability contexts are protected by `conn->l4_mutex`.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "constants.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef USE_XDP
/** @brief Thread-local hardware queue identifier for worker-to-XDP socket pinning. */
extern __thread int current_worker_id;
#endif

/** @brief Global abstract transport driver shim instance. */
extern struct SclTransportShim *global_shim;

void normalize_sockaddr(struct sockaddr_storage *addr);
bool sockaddr_storage_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b);
void prepare_dest_addr(const struct sockaddr_storage *src, struct sockaddr_storage *dst, socklen_t *dst_len);

/* ============================================================================ */
/* SECTION 1: ANTI-DOS RATE TRACKING & STATELESS TOKENS                         */
/* ============================================================================ */

/**
 * @brief Decrements the active connection or allocation counter for a specific IP/subnet.
 *
 * @param[in,out] table Pointer to the DoSTrackerTable hash table.
 * @param[in] key 16-byte IPv6 or IPv4-mapped address key.
 * @param[in] node_secret 16-byte random node secret used for SipHash bucketing.
 *
 * @pre `table`, `key`, and `node_secret` must be non-NULL.
 * @thread_safety Synchronized internally via `table->rwlock`.
 * @complexity Time: O(1) amortized, Space: O(1).
 */
void decrement_dos_count(DoSTrackerTable *table, const uint8_t key[16], const uint8_t *node_secret);

/**
 * @brief Generates an authenticated, encrypted stateless token for Handshake Flight 2.
 *
 * @details
 * Encrypts the 32-byte KEM shared secret inside an authenticated AEAD envelope using a key
 * derived via HKDF from the node's static secret, the client's 16-byte normalized address (IPv6 or ::ffff:IPv4),
 * and an expiration timestamp. Encodes token as: `[ Expiry (8B) | Random IV (8B) | Ciphertext + Tag (48B) ]` = 64 bytes total.
 *
 * @param[in] node_secret 32-byte static random node secret.
 * @param[in] shared_secret 32-byte Kyber-512 shared secret to encrypt.
 * @param[in] client_ip 16-byte normalized IPv6 or IPv4-mapped address buffer.
 * @param[in] expiry Millisecond timestamp when the token becomes invalid.
 * @param[out] token_out Destination buffer receiving the 64-byte token.
 *
 * @pre `token_out` must point to at least 64 writable bytes; `client_ip` must contain 16 bytes.
 * @complexity Time: O(1), Space: O(1).
 */
void generate_stateless_token(const uint8_t *node_secret, const uint8_t *shared_secret, const uint8_t client_ip[16], uint64_t expiry, uint8_t *token_out);

/**
 * @brief Verifies and decrypts an authenticated stateless token presented in Handshake Flight 3.
 *
 * @param[in] node_secret 32-byte static random node secret.
 * @param[in] token_in 64-byte token received from client.
 * @param[in] client_ip 16-byte normalized IPv6 or IPv4-mapped address of sending peer.
 * @param[out] shared_secret_out 32-byte destination receiving the recovered shared secret.
 * @return 0 on success; -1 if token is expired, forged, or fails authentication.
 *
 * @pre `token_in` must contain 64 readable bytes; `client_ip` must contain 16 bytes.
 * @complexity Time: O(1), Space: O(1).
 */
int verify_stateless_token(const uint8_t *node_secret, const uint8_t *token_in, const uint8_t client_ip[16], uint8_t *shared_secret_out);

/**
 * @brief Generates a 64-bit stateless cookie for client address verification in RETRY packets.
 *
 * @param[in] node_secret 32-byte random node secret.
 * @param[in] client_ip 16-byte normalized IPv6 or IPv4-mapped address buffer.
 * @return 64-bit SipHash-2-4 cookie.
 *
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t generate_stateless_cookie(const uint8_t *node_secret, const uint8_t client_ip[16]);

/**
 * @brief Verifies a 64-bit stateless cookie across a 5-minute rotating epoch boundary.
 *
 * @param[in] node_secret 32-byte random node secret.
 * @param[in] client_ip 16-byte normalized IPv6 or IPv4-mapped address of the sender.
 * @param[in] cookie 64-bit candidate cookie received in packet.
 * @return `true` if cookie matches current or previous epoch; `false` otherwise.
 *
 * @complexity Time: O(1), Space: O(1).
 */
bool verify_stateless_cookie(const uint8_t *node_secret, const uint8_t client_ip[16], uint64_t cookie);

/**
 * @brief Safely attempts to acquire an active reference on a connection without race conditions.
 *
 * @details
 * Uses a lock-free compare-and-swap loop on `conn->ref_count`. Fails if `ref_count == 0`
 * (indicating the connection has been tombstoned and is pending garbage collection).
 *
 * @param[in,out] conn Target connection context.
 * @return `true` if reference acquired; `false` if connection is dead/deallocated.
 *
 * @thread_safety Lock-free atomic operation with acquire semantics.
 * @complexity Time: O(1), Space: O(1).
 */
bool try_acquire_ref(SclConnection *conn);

/* ============================================================================ */
/* SECTION 2: TRANSPORT DRIVER SHIMS & CONNECTION LIFECYCLE                    */
/* ============================================================================ */

/**
 * @brief Instantiates the standard userspace POSIX UDP transport driver shim with dual-stack support.
 *
 * @details
 * Initializes a non-blocking dual-stack IPv6/IPv4 UDP socket (`IPV6_V6ONLY = 0`), configures
 * kernel socket buffers (up to 32 MiB), sets up epoll/kqueue/select polling descriptors,
 * pre-allocates zero-copy RX/TX rings, and memory-maps the 160 MiB L1 Handshake Slab Matrix.
 *
 * @param[in] ip Dual-stack interface address to bind (e.g., "0.0.0.0", "::", "[::]", or literal).
 * @param[in] port Local UDP port to bind (default: 5555).
 * @return Pointer to initialized SclTransportShim; NULL on bind/allocation failure.
 *
 * @complexity Time: O(1), Space: O(slab_size + ring_buffers).
 */
struct SclTransportShim* scl_userspace_shim_create(const char *ip, int port);

/**
 * @brief Instantiates the Linux AF_XDP kernel-bypass transport driver shim.
 *
 * @param[in] ifname Network interface name (e.g., "eth0").
 * @param[in] port Local UDP port to direct traffic towards.
 * @return Pointer to initialized SclTransportShim; NULL on XDP failure.
 *
 * @complexity Time: O(1), Space: O(UMEM_size).
 */
struct SclTransportShim* scl_xdp_shim_create(const char *ifname, int port);

/**
 * @brief Constructs and transmits Handshake Flight 1 to initiate connection setup with a peer.
 *
 * @param[in] net P2P network subsystem container.
 * @param[in,out] conn Pre-allocated connection context.
 * @param[in] addr Target remote socket address.
 *
 * @post Flight 1 packet padded to Path MTU queued for egress; status updated to FLIGHT1_SENT.
 * @complexity Time: O(2^pow_bits) for Proof-of-Work puzzle search, Space: O(Path_MTU) heap buffer.
 */
void scl_initiate_handshake(P2PNetwork *net, SclConnection *conn, const struct sockaddr_storage *addr);

/**
 * @brief Immediately destroys a connection context and frees all nested ring and OOO buffers.
 *
 * @param[in,out] conn Connection structure to deallocate.
 *
 * @warning Must only be called when `ref_count == 0` and after RCU grace period elapses.
 * @complexity Time: O(OOO_buffers + unacked_packets), Space: O(1).
 */
void scl_connection_destroy_now(SclConnection *conn);

/**
 * @brief Atomically releases a connection reference, deferring destruction to the RCU ring.
 *
 * @param[in,out] conn Connection structure.
 *
 * @thread_safety Atomic fetch-and-sub with release semantics.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_connection_release(SclConnection *conn);

/**
 * @brief Establishes an outbound connection to an address, creating connection state.
 *
 * @param[in,out] net P2P network subsystem container.
 * @param[in] addr Destination address.
 *
 * @thread_safety Acquires `net->mutex` internally.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_initiate_connection(P2PNetwork *net, const struct sockaddr_storage *addr);

/**
 * @brief Reserves and populates a slot in the L1 Handshake Slab for Flight 3 reassembly.
 *
 * @param[in,out] state Userspace transport state container.
 * @param[in] addr Remote client socket address (IPv4 or IPv6).
 * @param[in] conn_token 64-byte authenticated handshake token.
 * @param[in] is_tier1 Flag indicating Tier 1 (stake-weighted) rate-limit bypass.
 * @return Slot index [0..SCL_SLAB_SLOTS-1] on success; -1 if saturated or rate-limited.
 *
 * @complexity Time: O(1) bounded bucket probe, Space: O(1).
 */
int scl_slab_acquire_slot(UserSpaceState *state, const struct sockaddr_storage *addr, const uint8_t *conn_token, bool is_tier1);

/* ============================================================================ */
/* SECTION 3: P2P GOSSIP & PEER MANAGEMENT                                      */
/* ============================================================================ */

/**
 * @brief Queues an authenticated message for transmission to a specific peer by public key.
 *
 * @param[in] state Global node state container.
 * @param[in] recipient_pubkey 2,592-byte Dilithium5 public key of the target peer.
 * @param[in] msg Message container to transmit.
 * @return 1 on successful queuing; 0 if peer is disconnected, untrusted, or unmapped.
 *
 * @complexity Time: O(num_peers), Space: O(msg->length) queue node.
 */
int send_message(State *state, const uint8_t *recipient_pubkey, const Message *msg);

/**
 * @brief Broadcasts a message to all active, established peers in the network directory.
 *
 * @param[in] state Global node state container.
 * @param[in] msg Message container to broadcast.
 *
 * @complexity Time: O(num_peers), Space: O(num_peers * PUBKEY_LEN).
 */
void p2p_broadcast(State *state, const Message *msg);

/**
 * @brief Counts distinct established validator identities for the Active Nodes badge.
 *
 * @param[in] state Global node state. Must be non-NULL.
 * @return Unique remote Dilithium identities on a live non-self path, plus this node.
 *
 * @thread_safety Acquires `state->p2p_network.mutex`. Caller must not hold it
 *                (the mutex is not recursive).
 * @complexity Time: O(num_peers), Space: O(num_peers * PUBKEY_LEN).
 */
uint16_t scl_count_established_nodes(State *state);

/**
 * @brief Adds or updates a peer identity in the known peers table.
 *
 * @param[in,out] net P2P network subsystem container.
 * @param[in] dilithium_pubkey 2,592-byte Dilithium5 public key.
 * @param[in] kyber_pubkey 800-byte Kyber-512 public key.
 * @param[in] addr Remote network address.
 * @return PeerAddStatus code indicating whether peer was added, updated, or rejected.
 *
 * @complexity Time: O(num_peers), Space: O(1).
 */
PeerAddStatus p2p_add_peer(P2PNetwork *net, const uint8_t *dilithium_pubkey, const uint8_t *kyber_pubkey, const struct sockaddr_storage *addr);

/**
 * @brief Transmits a subset of known peers to a newly connected node for topology gossip.
 *
 * @param[in] state Global node state container.
 * @param[in] recipient_pubkey 2,592-byte public key of the requesting peer.
 *
 * @complexity Time: O(min(peers, 5)), Space: O(1).
 */
void p2p_share_peers(State *state, uint8_t *recipient_pubkey);

/**
 * @brief Removes a peer and terminates its connection using its Dilithium public key.
 *
 * @param[in,out] net P2P network subsystem container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key.
 * @return 1 on successful removal; 0 if not found; -1 on error.
 *
 * @complexity Time: O(num_peers), Space: O(1).
 */
int p2p_remove_peer_by_pubkey(P2PNetwork *net, const uint8_t *pubkey);

/**
 * @brief Dispatches an incoming network message to the thread pool for parallel verification.
 *
 * @param[in] state Global node state container.
 * @param[in] conn Connection context from which message arrived.
 * @param[in] msg Inbound message container.
 * @param[in] sender_pubkey Authenticated sender public key.
 * @param[in] sender_addr Source network address.
 *
 * @complexity Time: O(1), Space: O(sizeof(CryptoVerifyTask)).
 */
void crypto_verify_enqueue(State *state, SclConnection *conn, const Message *msg, const uint8_t *sender_pubkey, const struct sockaddr_storage *sender_addr);

/* ============================================================================ */
/* SECTION 4: L4 RELIABILITY, CONGESTION (BBRv3) & SPSC DEMUX                   */
/* ============================================================================ */

/**
 * @brief Routes an authenticated L5 message to the consensus or state machine handler.
 *
 * @details
 * Demultiplexes incoming messages by opcode:
 * - Native RPC queries and responses (`MSG_RPC_REQUEST`, `MSG_RPC_RESPONSE`).
 * - Distributed Key Generation (DKG) phases (`MSG_EPOCH_*`, `MSG_DKG_*`).
 * - Threshold signing ceremonies (`MSG_THRESHOLD_*`).
 * - UTXO, nullifier, and coin state synchronization (`MSG_CENTINEL_*`, `MSG_COIN_*`, `MSG_POINTER_*`).
 * - NAT traversal and blind packet relay routing (`MSG_ENDPOINT_*`, `MSG_RELAY_*`).
 * - Peer discovery, address book gossip, and disconnection (`MSG_PEER_*`).
 * - Mempool operations (`MSG_PENDING_OPERATION`, `MSG_GET_PENDING_OPERATIONS`).
 * - Consensus block sync and gossip (`MSG_GOSSIP_BLOCK`, `MSG_BLOCK_APPROVED`, `MSG_GET_BLOCKS`).
 *
 * @param[in] conn Active connection context.
 * @param[in,out] state Global node state container.
 * @param[in,out] net P2P network subsystem container.
 * @param[in] in_msg Parsed input message.
 * @param[out] out_msg Reusable response message buffer.
 * @param[in] sender_pubkey 2,592-byte sender public key.
 * @param[in] sender_addr Source network address.
 *
 * @complexity Time: O(handler_execution_time), Space: O(1).
 */
void dispatch_l5_message(SclConnection *conn, State *state, P2PNetwork *net, Message *in_msg, Message *out_msg, uint8_t *sender_pubkey, struct sockaddr_storage *sender_addr);

/**
 * @brief Commits an egress packet buffer, wrapping it in a blind relay envelope if required.
 *
 * @param[in] conn Connection context.
 * @param[in] token Transmission buffer token.
 * @param[in] len Serialized payload byte length.
 * @param[in] target_addr Final destination address.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void commit_tx_buffer_relayed(SclConnection *conn, void *token, size_t len, const struct sockaddr_storage *target_addr);

/**
 * @brief Updates smoothed Round-Trip Time and variance estimators per RFC 9002.
 *
 * @param[in,out] conn Connection context.
 * @param[in] latest_rtt Milliseconds elapsed between transmission and ACK.
 * @param[in] ack_delay Delay reported by remote receiver before sending ACK.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_l4_update_rtt(SclConnection *conn, uint64_t latest_rtt, uint64_t ack_delay);

/**
 * @brief Evaluates the current Probe Timeout (PTO) duration in milliseconds.
 *
 * @param[in] conn Connection context.
 * @return PTO duration in milliseconds, incorporating exponential backoff.
 *
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t scl_l4_get_pto(SclConnection *conn);

/**
 * @brief Scans unacknowledged in-flight packets, declaring losses and scheduling retransmissions.
 *
 * @param[in,out] conn Connection context.
 * @param[in] now Current monotonic timestamp in milliseconds.
 * @param[in] state Global node state container.
 * @param[in] is_ack_driven `true` if invoked on ACK receipt; `false` on timer expiry.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(unacked_packets), Space: O(1).
 */
void scl_l4_detect_lost_packets(SclConnection *conn, uint64_t now, State *state, bool is_ack_driven);

/**
 * @brief Records transmission metadata for an outbound packet to enable loss tracking.
 *
 * @param[in,out] conn Connection context.
 * @param[in] packet_num Monotonic sequence number assigned to packet.
 * @param[in] len Serialized wire byte size.
 * @param[in] is_datagram `true` for unreliable datagrams; `false` for retransmitted streams.
 * @param[in] is_fec_protected `true` if packet belongs to an FEC shard group.
 * @param[in] raw_packet Unencrypted payload copy retained for retransmission.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(1), Space: O(len) allocation for reliable streams.
 */
void scl_l4_on_packet_sent(SclConnection *conn, uint64_t packet_num, size_t len, bool is_datagram, bool is_fec_protected, const uint8_t *raw_packet);

/**
 * @brief Processes an incoming ACK frame, releasing tracked packets and updating BBRv3 bandwidth.
 *
 * @param[in,out] conn Connection context.
 * @param[in] acked_pkt Sequence number acknowledged by remote peer.
 * @param[in] ack_delay Delay in milliseconds reported by remote peer.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(unacked_packets), Space: O(1).
 */
void process_l4_ack(SclConnection *conn, uint64_t acked_pkt, uint64_t ack_delay);

/**
 * @brief Stages or flushes an ACK frame acknowledging receipt of a packet.
 *
 * @param[in,out] conn Connection context.
 * @param[in] acked_pkt Packet sequence number received (0 signals force-flush).
 * @param[in] rx_time Monotonic timestamp when packet arrived.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(pending_acks), Space: O(1).
 */
void send_l4_ack(SclConnection *conn, uint64_t acked_pkt, uint64_t rx_time);

/**
 * @brief Drains the SPSC ring queue transferring packets from L0 driver to application layer.
 *
 * @param[in,out] conn Connection context.
 * @param[in,out] state Global node state container.
 * @param[in,out] net P2P network subsystem container.
 * @param[in] decryption_buffer 8 MiB scratch buffer for AEAD decryption.
 * @param[out] in_msg Scratch container for parsed messages.
 * @param[out] out_msg Scratch container for response frames.
 *
 * @complexity Time: O(queued_packets * decrypt_time), Space: O(1).
 */
void process_spsc_queue(SclConnection *conn, State *state, P2PNetwork *net, uint8_t *decryption_buffer, Message *in_msg, Message *out_msg);

/**
 * @brief Paces and transmits staged datagram and stream messages according to BBRv3 budget.
 *
 * @param[in,out] conn Connection context.
 * @param[in] msg Scratch container for deserialization.
 *
 * @complexity Time: O(pacing_budget / MTU), Space: O(1).
 */
void process_egress_queues(SclConnection *conn, Message *msg);

/* ============================================================================ */
/* SECTION 5: GALOIS FIELD GF(2^8) REED-SOLOMON ERASURE CODING                  */
/* ============================================================================ */

/**
 * @brief Pre-computes exponential and logarithmic lookup tables for GF(2^8) Galois Field arithmetic.
 *
 * @details
 * Seeds `gf_exp` and `gf_log` tables using generator polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (0x11D),
 * enabling branchless constant-time multiplication and division in erasure coding routines.
 *
 * @post `fec_initialized` set to true; lookup tables ready for encoding and decoding.
 * @complexity Time: O(1), Space: O(1).
 */
void fec_init(void);

/**
 * @brief Generates two Cauchy Reed-Solomon parity shards (P0, P1) from up to 8 data shards.
 *
 * @param[in] data Array of pointers to up to 8 data shards of uniform length `len`.
 * @param[out] p0 Destination buffer receiving first parity shard (XOR summation).
 * @param[out] p1 Destination buffer receiving second parity shard (Galois field product).
 * @param[in] len Byte length of each shard (typically SCL_MAX_CHUNK_SIZE = 1,100 bytes).
 *
 * @complexity Time: O(len), Space: O(1).
 */
void fec_encode82(const uint8_t *data[8], uint8_t *p0, uint8_t *p1, size_t len);

/**
 * @brief Reconstructs up to two missing data shards in place using received shards and parity.
 *
 * @param[in,out] data Array of 8 shard pointers (missing shards populated on recovery).
 * @param[in] p0 First parity shard buffer.
 * @param[in] p1 Second parity shard buffer.
 * @param[in,out] present Boolean array tracking available data shards.
 * @param[in] p0_present True if P0 was received.
 * @param[in] p1_present True if P1 was received.
 * @param[in] len Byte length of each shard.
 * @return 0 on successful recovery; -1 if erasures exceed parity capacity (>2 erasures).
 *
 * @complexity Time: O(len), Space: O(len) stack buffer.
 */
int fec_decode82(uint8_t *data[8], const uint8_t *p0, const uint8_t *p1,
                 bool present[8], bool p0_present, bool p1_present, size_t len);

/* ============================================================================ */
/* SECTION 6: TRANSPORT-LAYER HYPERGRAPH PROOF-OF-WORK                          */
/* ============================================================================ */

/**
 * @brief Initializes the local peer reputation hypergraph and challenge caches.
 *
 * @param[out] graph LocalHypergraph structure to configure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void initialize_hypergraph(LocalHypergraph *graph);

/**
 * @brief Background thread maintaining hypergraph state, rotating puzzles, and aging Bloom filters.
 *
 * @param[in] arg Pointer to global State structure.
 * @return NULL upon thread termination.
 *
 * @complexity Time: O(infinite loop), Space: O(1).
 */
void* maintain_hypergraph_state_thread(void *arg);

/**
 * @brief Verifies that a Proof-of-Work nonce produces a hash matching required difficulty.
 *
 * @param[in] base 32-byte puzzle seed.
 * @param[in] nonce 64-bit candidate solution.
 * @param[in] difficulty Required leading zero-bit count.
 * @return `true` if solution is valid; `false` otherwise.
 *
 * @complexity Time: O(1), Space: O(1).
 */
bool verify_pow(const uint8_t *base, uint64_t nonce, uint8_t difficulty);

/**
 * @brief Computes a Proof-of-Work solution by linear nonce increment.
 *
 * @param[in] base 32-byte puzzle seed.
 * @param[in] difficulty Target leading zero-bit count.
 * @return Nonce satisfying difficulty.
 *
 * @complexity Time: O(2^difficulty), Space: O(1).
 */
uint64_t find_nonce(const uint8_t *base, uint8_t difficulty);

/**
 * @brief Adds a peer Connection ID (CID) to a 3-hash Bloom filter.
 *
 * @param[in,out] filter Bloom filter byte array of size @ref BLOOM_FILTER_SIZE.
 * @param[in] cid 20-byte Connection ID.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void bloom_filter_add(uint8_t *filter, const uint8_t *cid);

/**
 * @brief Probes a Bloom filter for membership of a Connection ID.
 *
 * @param[in] filter Bloom filter byte array.
 * @param[in] cid 20-byte Connection ID.
 * @return `true` if potentially present; `false` if definitely absent.
 *
 * @complexity Time: O(1), Space: O(1).
 */
bool bloom_filter_check(const uint8_t *filter, const uint8_t *cid);

/**
 * @brief Serializes a compact 64-byte snapshot of the local hypergraph topology for challenge seeds.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[out] out_snapshot 64-byte destination buffer.
 *
 * @complexity Time: O(nodes), Space: O(1).
 */
void sample_local_subgraph_optimized(const LocalHypergraph *graph, uint8_t *out_snapshot);

/**
 * @brief Locates node metadata in the local hypergraph by Connection ID.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] cid 20-byte Connection ID.
 * @return Pointer to NodeMetadata on match; NULL if not found.
 *
 * @complexity Time: O(node_count), Space: O(1).
 */
NodeMetadata* find_node(LocalHypergraph *graph, const uint8_t *cid);

/**
 * @brief Evaluates connection frequency of a peer over a 60-second sliding window.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] cid 20-byte Connection ID.
 * @return Interaction weight accumulated within the last 60 seconds.
 *
 * @complexity Time: O(edge_count), Space: O(1).
 */
uint32_t get_connection_rate_sliding_window(LocalHypergraph *graph, const uint8_t *cid);

/**
 * @brief Evaluates whether a peer exceeds maximum allowable connection frequency.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] cid 20-byte Connection ID.
 * @return `true` if rate exceeds @ref MAX_CONNECTIONS_PER_MINUTE; `false` otherwise.
 *
 * @complexity Time: O(edge_count), Space: O(1).
 */
bool is_high_frequency(LocalHypergraph *graph, const uint8_t *cid);

/**
 * @brief Calculates dynamic PoW puzzle difficulty based on peer reputation and activity rate.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] peer NodeMetadata pointer (or NULL for unknown peers).
 * @param[in] current_time Millisecond timestamp.
 * @return Scaled difficulty [10..20 bits].
 *
 * @complexity Time: O(edge_count), Space: O(1).
 */
uint8_t calculate_dynamic_difficulty_graceful(LocalHypergraph *graph, NodeMetadata* peer, uint64_t current_time);

/**
 * @brief Inserts or updates a directed temporal interaction edge in the reputation hypergraph.
 *
 * @param[in,out] graph LocalHypergraph structure.
 * @param[in] cid Peer Connection ID.
 * @param[in] edge_type Edge behavior category.
 * @param[in] weight Incremental score weight.
 *
 * @thread_safety Acquires `graph->lock`.
 * @complexity Time: O(edges), Space: O(1).
 */
void add_temporal_edge(LocalHypergraph *graph, const uint8_t *cid, EdgeType edge_type, uint32_t weight);

/**
 * @brief Generates a hybrid Proof-of-Work challenge (primary cookie + dynamic secondary puzzle).
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] incoming_cid Peer Connection ID.
 * @return Populated HybridCookieChallenge structure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
HybridCookieChallenge generate_hybrid_challenge(LocalHypergraph* graph, const uint8_t* incoming_cid);

/**
 * @brief Solves a hybrid Proof-of-Work challenge by searching for valid nonces.
 *
 * @param[in] challenge Challenge envelope to solve.
 * @param[out] out_primary_nonce Destination receiving primary 10-bit solution.
 * @param[out] out_secondary_nonce Destination receiving secondary dynamic solution.
 * @return `true` on success.
 *
 * @complexity Time: O(2^difficulty), Space: O(1).
 */
bool solve_hybrid_challenge(HybridCookieChallenge* challenge, uint64_t* out_primary_nonce, uint64_t* out_secondary_nonce);

/**
 * @brief Verifies that submitted nonces satisfy both primary and secondary challenge difficulties.
 *
 * @param[in,out] graph LocalHypergraph structure.
 * @param[in] challenge Issued challenge envelope.
 * @param[in] primary_nonce Submitted primary solution.
 * @param[in] secondary_nonce Submitted secondary solution.
 * @return `true` if both nonces verify and challenge is unexpired; `false` otherwise.
 *
 * @complexity Time: O(1), Space: O(1).
 */
bool verify_hybrid_challenge(LocalHypergraph* graph, HybridCookieChallenge* challenge, uint64_t primary_nonce, uint64_t secondary_nonce);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NETWORK_H
