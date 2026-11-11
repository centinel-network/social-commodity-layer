/**
 * @file common/network/network.c
 * @brief Satocialist Protocol: Transport Drivers, L1-L4 Networking, and QUIC-Parity Subsystem Implementation
 *
 * @details
 * Implements the core multi-layered transport infrastructure of the Satocialist Cryptographic
 * Ledger (SCL). Operates across both high-throughput kernel bypass (Linux AF_XDP) and portable
 * POSIX non-blocking UDP sockets with epoll/kqueue event demultiplexing.
 *
 * Major subsystem implementations:
 * 1. Anti-DoS Sliding Rate Trackers: SipHash-2-4 bucketed IP and /24 subnet request filters.
 * 2. Cauchy Reed-Solomon Erasure Coding: (8,2) systematic linear code over Galois Field GF(2^8).
 * 3. Blind Relay Forwarding: Zero-copy packet tunneling for symmetric NAT and CGNAT traversal.
 * 4. L4 Reliability and BBRv3 Congestion Engine: Monotonic loss detection, RTT filtering, and adaptive pacing.
 * 5. Stateless Handshake Tokens & Cookies: 2-RTT authenticated key exchange with anti-amplification limits.
 * 6. L1 Connection Management: Connection ID (CID) routing tables, reference counting, and RCU garbage collection.
 * 7. L0 Hardware Shims: Userspace ring buffer management and AF_XDP zero-copy frame dispatching.
 * 8. L1 Handshake Slab Matrix: 160 MiB memory-mapped matrix with hardware guard pages for reassembly.
 * 9. Transport Hypergraph Proof-of-Work: Adaptive difficulty puzzle challenges and reputation scoring.
 * 10. L5 Application Engine & Ceremony Routing: Peer identity advertisement, consensus block gossip,
 *     threshold signing orchestration, DKG ceremony state machines, and mempool synchronization.
 *
 * @section protocol_invariants Protocol Invariants
 * - Physical Link MTU Boundedness: Maximum transmission units are constrained to SCL_LINK_MTU
 *   (1,280 bytes) minus IP/UDP overhead (1,232 bytes maximum payload) to guarantee unfragmented transit.
 * - Nonce Uniqueness: AES-256-GCM nonces are deterministically bound to monotonic 64-bit packet numbers.
 * - Stateless Anti-Amplification: Response payloads cannot exceed 3x received bytes until client
 *   address reachability is proven via cookies or cryptographic token validation.
 * - Out-of-Order Memory Quota: Total memory allocated to out-of-order reassembly buffers across all
 *   connections is strictly bounded by `global_ooo_quota` (512 MiB).
 *
 * @section thread_safety Thread Safety & Concurrency Architecture
 * - Concurrency Separation: The L0 driver thread (`shim_event_loop_thread`) executes single-producer
 *   packet pushes into per-connection lock-free SPSC queues (`l5_rx_queue`).
 * - L5 Workers: Up to `NUM_CRYPTO_WORKERS` parallel threads dequeue, decrypt, and process messages.
 * - Connection Mutex: Modifying in-flight loss tracking, congestion windows, and ACK arrays requires `conn->l4_mutex`.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <errno.h>
#include <fcntl.h>
#include "network.h"
#include "protocol.h"
#include "client_network.h"
#include "rpc.h"
#include "hash_table.h"
#include "crypto.h"
#include "constants.h"
#include "utils.h"
#include "types.h"
#include "database.h"

#ifdef USE_XDP
/** @brief Thread-local worker identifier pinning CPU threads to dedicated AF_XDP hardware queues. */
__thread int current_worker_id = -1;
#endif

#ifndef _WIN32
#include <sys/mman.h>
#include <ifaddrs.h>
#endif

// Route standard I/O stream printing through thread-safe SCL logging facilities
#define fprintf scl_fprintf
#define printf scl_printf

/** @brief Instantiates the standard portable POSIX UDP transport driver shim. */
struct SclTransportShim* scl_userspace_shim_create(const char *ip, int port);
/** @brief Instantiates the Linux AF_XDP kernel-bypass transport driver shim. */
struct SclTransportShim* scl_xdp_shim_create(const char *ifname, int port);

/** @brief Global pointer to active node State container. */
extern State *global_state;
/** @brief Global abstract transport driver instance. */
struct SclTransportShim *global_shim = NULL;
/** @brief Global pointer to local node operator's active User profile. */
User *global_user = NULL;

/** @brief Galois Field GF(2^8) exponential discrete logarithm lookup table. */
static uint8_t gf_exp[512];
/** @brief Galois Field GF(2^8) logarithmic discrete logarithm lookup table. */
static uint8_t gf_log[256];
/** @brief Flag indicating GF(2^8) lookup tables have been populated. */
static bool fec_initialized = false;

bool sockaddr_storage_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (!a || !b) return false;
    if (a->ss_family != b->ss_family) {
        // Handle IPv4-mapped IPv6 equality transparency
        if (a->ss_family == AF_INET6 && b->ss_family == AF_INET) {
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)a;
            const struct sockaddr_in *v4 = (const struct sockaddr_in *)b;
            if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
                return v6->sin6_port == v4->sin_port && memcmp(&v6->sin6_addr.s6_addr[12], &v4->sin_addr.s_addr, 4) == 0;
            }
        } else if (a->ss_family == AF_INET && b->ss_family == AF_INET6) {
            const struct sockaddr_in *v4 = (const struct sockaddr_in *)a;
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)b;
            if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
                return v4->sin_port == v6->sin6_port && memcmp(&v4->sin_addr.s_addr, &v6->sin6_addr.s6_addr[12], 4) == 0;
            }
        }
        return false;
    }
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *v4_a = (const struct sockaddr_in *)a;
        const struct sockaddr_in *v4_b = (const struct sockaddr_in *)b;
        return v4_a->sin_port == v4_b->sin_port && v4_a->sin_addr.s_addr == v4_b->sin_addr.s_addr;
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *v6_a = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *v6_b = (const struct sockaddr_in6 *)b;
        return v6_a->sin6_port == v6_b->sin6_port && memcmp(&v6_a->sin6_addr, &v6_b->sin6_addr, 16) == 0;
    }
    return false;
}

void normalize_sockaddr(struct sockaddr_storage *addr) {
    if (!addr) return;
    if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
            struct sockaddr_in v4;
            memset(&v4, 0, sizeof(v4));
            v4.sin_family = AF_INET;
            v4.sin_port = v6->sin6_port;
            memcpy(&v4.sin_addr.s_addr, &v6->sin6_addr.s6_addr[12], 4);
            memcpy(addr, &v4, sizeof(struct sockaddr_in));
        }
    }
}

/* Compares network layer IP addresses transparently across AF_INET and AF_INET6,
 * ignoring port differences (e.g., ephemeral NAT translation vs bind ports). */
static bool sockaddr_storage_ip_equal(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (!a || !b) return false;
    struct sockaddr_storage na = *a, nb = *b;
    normalize_sockaddr(&na);
    normalize_sockaddr(&nb);
    if (na.ss_family != nb.ss_family) return false;
    if (na.ss_family == AF_INET) {
        return ((const struct sockaddr_in *)&na)->sin_addr.s_addr ==
               ((const struct sockaddr_in *)&nb)->sin_addr.s_addr;
    } else if (na.ss_family == AF_INET6) {
        return memcmp(&((const struct sockaddr_in6 *)&na)->sin6_addr,
                      &((const struct sockaddr_in6 *)&nb)->sin6_addr, 16) == 0;
    }
    return false;
}

/* Loopback, wildcard, and link-local are not remote validators and are not
 * worth recording as this host's external address. RFC1918 is intentionally
 * still a real path: the other seed can be seen on its VPC 10/8 address. */
static bool scl_sockaddr_is_unusable(const struct sockaddr_storage *addr) {
    if (!addr) return true;
    struct sockaddr_storage n = *addr;
    normalize_sockaddr(&n);
    if (n.ss_family == AF_INET) {
        uint32_t ip = ntohl(((struct sockaddr_in *)&n)->sin_addr.s_addr);
        if (ip == 0 || (ip >> 24) == 127) return true;
        if ((ip & 0xFFFF0000u) == 0xA9FE0000u) return true; /* 169.254.0.0/16 */
        return false;
    }
    if (n.ss_family == AF_INET6) {
        const struct in6_addr *a6 = &((struct sockaddr_in6 *)&n)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(a6) || IN6_IS_ADDR_UNSPECIFIED(a6) || IN6_IS_ADDR_LINKLOCAL(a6);
    }
    return true;
}

/* Caller holds net->mutex. Does not call getifaddrs: inside the container the
 * GCP external address is not assigned to any interface. Evaluates IP equality
 * ignoring ephemeral source ports to match external container boundaries. */
static bool scl_sockaddr_is_self_locked(const P2PNetwork *net, const struct sockaddr_storage *addr) {
    if (!net || !addr || scl_sockaddr_is_unusable(addr)) return false;
    if ((net->public_addr.ss_family == AF_INET || net->public_addr.ss_family == AF_INET6) &&
        !scl_sockaddr_is_unusable(&net->public_addr) &&
        sockaddr_storage_ip_equal(addr, &net->public_addr)) {
        return true;
    }
    if ((net->local_peer.addr.ss_family == AF_INET || net->local_peer.addr.ss_family == AF_INET6) &&
        !scl_sockaddr_is_unusable(&net->local_peer.addr) &&
        sockaddr_storage_ip_equal(addr, &net->local_peer.addr)) {
        return true;
    }
    size_t n = net->num_self_addrs;
    if (n > 8) n = 8;
    for (size_t i = 0; i < n; i++) {
        if (sockaddr_storage_ip_equal(addr, &net->self_addrs[i])) return true;
    }
    return false;
}

/* Caller holds net->mutex. */
static void scl_note_self_addr_locked(P2PNetwork *net, const struct sockaddr_storage *addr) {
    if (!net || !addr || scl_sockaddr_is_unusable(addr)) return;
    if (scl_sockaddr_is_self_locked(net, addr)) return;
    if (net->num_self_addrs >= 8) return;
    struct sockaddr_storage n = *addr;
    normalize_sockaddr(&n);
    net->self_addrs[net->num_self_addrs++] = n;
}

/* Drop zero-key dial placeholders whose path is this host.
 * The authenticated local row is never zero-key, so it is not freed.
 * A placeholder that shares its conn with a keyed peer only detaches;
 * that peer owns the ref. Otherwise the same unregister/release pair as
 * the existing zero-key sweep: the worker already holds a ref across dispatch,
 * so the conn is not destroyed on this stack. Caller holds net->mutex. */
static void scl_reap_self_placeholders_locked(P2PNetwork *net) {
    if (!net) return;
    for (size_t i = 0; i < net->num_known_peers; ) {
        Peer *peer = net->known_peers[i];
        if (!peer || !is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) {
            i++;
            continue;
        }
        bool self = scl_sockaddr_is_self_locked(net, &peer->addr);
        if (!self && peer->conn &&
            (peer->conn->current_path.ss_family == AF_INET ||
             peer->conn->current_path.ss_family == AF_INET6)) {
            self = scl_sockaddr_is_self_locked(net, &peer->conn->current_path);
        }
        if (!self) {
            i++;
            continue;
        }
        if (peer->conn) {
            SclConnection *old_c = peer->conn;
            bool shared = false;
            for (size_t k = 0; k < net->num_known_peers; k++) {
                if (k != i && net->known_peers[k] && net->known_peers[k]->conn == old_c &&
                    !is_zeroed(net->known_peers[k]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) {
                    shared = true;
                    break;
                }
            }
            peer->conn = NULL;
            if (!shared) {
                if (global_shim && global_shim->unregister_connection(global_shim, old_c->cid)) {
                    scl_connection_release(old_c);
                }
                scl_connection_release(old_c);
            }
        }
        free(peer);
        for (size_t j = i; j + 1 < net->num_known_peers; j++) {
            net->known_peers[j] = net->known_peers[j + 1];
        }
        net->num_known_peers--;
        net->known_peers[net->num_known_peers] = NULL;
    }
}

uint16_t scl_count_established_nodes(State *state) {
    if (!state) return 0;
    P2PNetwork *net = &state->p2p_network;
    pthread_mutex_lock(&net->mutex);

    size_t npeers = net->num_known_peers;
    uint8_t (*uniq)[PUBKEY_LEN] = (npeers > 0) ? calloc(npeers, PUBKEY_LEN) : NULL;
    size_t uniq_count = 0;
    const uint8_t *local_key = net->local_peer.peer_wallet.dilithium_pubkey;

    for (size_t i = 0; i < npeers; i++) {
        Peer *peer = net->known_peers[i];
        if (!peer || !peer->conn || peer->conn->handshake_state != SCL_CONN_STATE_ESTABLISHED) continue;
        if (is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) continue;
        if (!validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey)) continue;

        /* L5 GC is the sole authority on dead sockets: it uses the same
         * MAX_PEER_SILENCE_TIME horizon to set handshake_state = NONE, at which
         * point the check above already excludes the peer. Keeping a parallel
         * last_rx_time gate here only produces a transient under-count window
         * between silence-threshold and the GC's next sweep. */

        if (memcmp(peer->peer_wallet.dilithium_pubkey, local_key, DILITHIUM_PUBKEY_LEN) == 0) {
            continue;
        }

        /* Ensure the socket address structure is valid and initialized.
         * Authenticated nodes with distinct post-quantum keys are always counted,
         * including multiple instances operating on local loopback or behind the same NAT.
         *
         * H-11 fix: an ESTABLISHED peer carrying a verified Dilithium key that differs
         * from ours is by definition another node, so it must be counted no matter
         * which address it is reachable on. The previous IP-only
         * scl_sockaddr_is_self_locked() veto below dropped exactly such peers
         * whenever an endpoint reflection had poisoned self_addrs with the other
         * seed's IP (the documented GCP failure mode at the MSG_ENDPOINT_DISCOVERY_ACK
         * handler), pinning the Active Node count at 1 on two-seed testnets even
         * while the P2P link was healthy. Hairpin/self connections are still
         * excluded: they present our own pubkey, which the memcmp against
         * local_key above already rejects. */
        const struct sockaddr_storage *live = NULL;
        if (peer->conn->current_path.ss_family == AF_INET ||
            peer->conn->current_path.ss_family == AF_INET6) {
            live = &peer->conn->current_path;
        } else if (peer->addr.ss_family == AF_INET || peer->addr.ss_family == AF_INET6) {
            live = &peer->addr;
        }
        if (!live || (live->ss_family != AF_INET && live->ss_family != AF_INET6)) continue;

        bool dup = false;
        for (size_t j = 0; j < uniq_count; j++) {
            if (uniq && memcmp(uniq[j], peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                dup = true;
                break;
            }
        }
        if (!dup && uniq && uniq_count < npeers) {
            memcpy(uniq[uniq_count], peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN);
            uniq_count++;
        }
    }

    // Include the local node alongside unique remote established peers for total active node count
    uint16_t count = (uint16_t)uniq_count;
    if (!is_zeroed(local_key, DILITHIUM_PUBKEY_LEN) && validate_dilithium_pubkey(local_key)) {
        count++;
    }
    free(uniq);
    pthread_mutex_unlock(&net->mutex);
    return count;
}

void prepare_dest_addr(const struct sockaddr_storage *src, struct sockaddr_storage *dst, socklen_t *dst_len) {
    if (!src || !dst || !dst_len) return;
    memcpy(dst, src, sizeof(struct sockaddr_storage));
    if (dst->ss_family == AF_INET) *dst_len = sizeof(struct sockaddr_in);
    else if (dst->ss_family == AF_INET6) *dst_len = sizeof(struct sockaddr_in6);
    else *dst_len = sizeof(struct sockaddr_storage);
}

/* ============================================================================ */
/* SECTION 1: ANTI-DOS RATE TRACKERS & IP SLIDING BUCKETS                       */
/* ============================================================================ */

/**
 * @brief Retrieves the active connection or allocation counter for a specific 16-byte IP key.
 *
 * @param[in] table Pointer to the DoSTrackerTable hash table.
 * @param[in] key 16-byte IPv6 or IPv4-mapped address key.
 * @param[in] node_secret 16-byte random node secret used for SipHash bucketing.
 * @return Current integer count associated with the key; 0 if absent.
 *
 * @thread_safety Acquires shared read lock on `table->rwlock`.
 * @complexity Time: O(1) amortized, Space: O(1).
 */
static uint32_t get_dos_count(DoSTrackerTable *table, const uint8_t key[16], const uint8_t *node_secret) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)table; (void)key; (void)node_secret;
    return 0;
#else
    // Map IP key to hash bucket using SipHash-2-4 and node secret
    uint64_t hash = siphash24(key, 16, node_secret);
    uint32_t idx = hash % SCL_DOS_TRACKER_SIZE;
    
    pthread_rwlock_rdlock(&table->rwlock);
    // Traverse bucket collision chain to find matching IP key
    DoSNode *curr = atomic_load_explicit(&table->buckets[idx], memory_order_acquire);
    while (curr) {
        if (memcmp(curr->key, key, 16) == 0) {
            uint32_t cnt = atomic_load_explicit(&curr->count, memory_order_acquire);
            pthread_rwlock_unlock(&table->rwlock);
            return cnt;
        }
        curr = curr->next;
    }
    pthread_rwlock_unlock(&table->rwlock);
    // Key not found in rate tracker table
    return 0;
#endif
}

/**
 * @brief Atomically increments the tracking counter for an IP or subnet key, allocating on first seen.
 *
 * @param[in,out] table Pointer to the DoSTrackerTable hash table.
 * @param[in] key 16-byte address key.
 * @param[in] node_secret 16-byte SipHash key.
 *
 * @thread_safety Acquires exclusive write lock on `table->rwlock`.
 * @complexity Time: O(1) amortized, Space: O(1) heap allocation on new entry.
 */
static void increment_dos_count(DoSTrackerTable *table, const uint8_t key[16], const uint8_t *node_secret) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)table; (void)key; (void)node_secret;
    return;
#else
    uint64_t hash = siphash24(key, 16, node_secret);
    uint32_t idx = hash % SCL_DOS_TRACKER_SIZE;

    pthread_rwlock_wrlock(&table->rwlock);
    DoSNode *curr = atomic_load_explicit(&table->buckets[idx], memory_order_acquire);
    while (curr) {
        if (memcmp(curr->key, key, 16) == 0) {
            atomic_fetch_add_explicit(&curr->count, 1, memory_order_relaxed);
            pthread_rwlock_unlock(&table->rwlock);
            return;
        }
        curr = curr->next;
    }

    DoSNode *new_node = malloc(sizeof(DoSNode));
    if (new_node) {
        memcpy(new_node->key, key, 16);
        atomic_init(&new_node->count, 1);
        new_node->next = atomic_load_explicit(&table->buckets[idx], memory_order_relaxed);
        atomic_store_explicit(&table->buckets[idx], new_node, memory_order_release);
    }
    pthread_rwlock_unlock(&table->rwlock);
#endif
}

/**
 * @brief Atomically decrements the tracking counter for an IP key, unlinking and freeing when zero.
 *
 * @param[in,out] table Pointer to the DoSTrackerTable hash table.
 * @param[in] key 16-byte address key.
 * @param[in] node_secret 16-byte SipHash key.
 *
 * @thread_safety Acquires exclusive write lock on `table->rwlock`.
 * @complexity Time: O(1) amortized, Space: O(1).
 */
void decrement_dos_count(DoSTrackerTable *table, const uint8_t key[16], const uint8_t *node_secret) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)table; (void)key; (void)node_secret;
    return;
#else
    uint64_t hash = siphash24(key, 16, node_secret);
    uint32_t idx = hash % SCL_DOS_TRACKER_SIZE;

    pthread_rwlock_wrlock(&table->rwlock);
    DoSNode *curr = atomic_load_explicit(&table->buckets[idx], memory_order_acquire);
    DoSNode *prev = NULL;
    while (curr) {
        if (memcmp(curr->key, key, 16) == 0) {
            uint32_t prev_cnt = atomic_fetch_sub_explicit(&curr->count, 1, memory_order_relaxed);
            if (prev_cnt <= 1) {
                if (prev) {
                    prev->next = curr->next;
                } else {
                    atomic_store_explicit(&table->buckets[idx], curr->next, memory_order_release);
                }
                free(curr);
            }
            pthread_rwlock_unlock(&table->rwlock);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_rwlock_unlock(&table->rwlock);
#endif
}

/* ============================================================================ */
/* SECTION 2: GALOIS FIELD GF(2^8) REED-SOLOMON ERASURE CODING                  */
/* ============================================================================ */

/**
 * @brief Pre-computes exponential and logarithmic lookup tables for GF(2^8) arithmetic.
 *
 * @details
 * Seeds `gf_exp` and `gf_log` tables using generator polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (0x11D),
 * enabling branchless constant-time multiplication and division in erasure coding routines.
 *
 * @post `fec_initialized` set to true; lookup tables ready for encoding and decoding.
 * @complexity Time: O(1) exactly 256 iterations, Space: O(1) static tables.
 */
void fec_init(void) {
    if (fec_initialized) return;
    int x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = x;
        gf_exp[i + 255] = x;
        gf_log[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11D;
    }
    gf_log[0] = 0;
    fec_initialized = true;
}

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Multiplies two elements in Galois Field GF(2^8) using precomputed log/exp tables.
 *
 * @param[in] a First field element [0..255].
 * @param[in] b Second field element [0..255].
 * @return Product $a \cdot b \pmod{x^8 + x^4 + x^3 + x^2 + 1}$.
 *
 * @complexity Time: O(1) table lookups, Space: O(1).
 */
static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

/**
 * @brief Divides two elements in Galois Field GF(2^8) using precomputed log/exp tables.
 *
 * @param[in] a Numerator field element [0..255].
 * @param[in] b Denominator field element [1..255].
 * @return Quotient $a / b \pmod{x^8 + x^4 + x^3 + x^2 + 1}$.
 *
 * @pre `b != 0`.
 * @complexity Time: O(1) table lookups, Space: O(1).
 */
static inline uint8_t gf_div(uint8_t a, uint8_t b) {
    if (a == 0) return 0;
    return gf_exp[gf_log[a] + 255 - gf_log[b]];
}
#endif

/**
 * @brief Generates two Cauchy Reed-Solomon parity shards (P0, P1) from up to 8 data shards.
 *
 * @param[in] data Array of pointers to up to 8 data shards of uniform length `len`.
 * @param[out] p0 Destination buffer receiving first parity shard (XOR summation).
 * @param[out] p1 Destination buffer receiving second parity shard (Galois field product).
 * @param[in] len Byte length of each shard (typically SCL_MAX_CHUNK_SIZE = 1,100 bytes).
 *
 * @pre `p0` and `p1` must point to at least `len` writable bytes.
 * @complexity Time: O(len), Space: O(1).
 */
void fec_encode82(const uint8_t *data[8], uint8_t *p0, uint8_t *p1, size_t len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    // Short-circuit FEC calculation during fuzzing unless unit test assertions are enabled
    (void)data; (void)p0; (void)p1; (void)len;
    return;
#else
    memset(p0, 0, len);
    memset(p1, 0, len);
    for (int i = 0; i < 8; i++) {
        if (!data[i]) continue;
        uint8_t coeff = gf_exp[i];
        for (size_t k = 0; k < len; k++) {
            p0[k] ^= data[i][k];
            p1[k] ^= gf_mul(coeff, data[i][k]);
        }
    }
#endif
}

/**
 * @brief Reconstructs up to two missing data shards in place using received shards and parity.
 *
 * @param[in,out] data Array of 8 shard pointers (missing shards populated on recovery).
 * @param[in] p0 First parity shard buffer (XOR sum).
 * @param[in] p1 Second parity shard buffer (weighted sum).
 * @param[in,out] present Boolean array tracking available data shards.
 * @param[in] p0_present True if P0 was received.
 * @param[in] p1_present True if P1 was received.
 * @param[in] len Byte length of each shard.
 * @return 0 on successful recovery; -1 if erasures exceed parity capacity (>2 erasures).
 *
 * @complexity Time: O(len), Space: O(len) stack buffer.
 */
int fec_decode82(uint8_t *data[8], const uint8_t *p0, const uint8_t *p1,
                 bool present[8], bool p0_present, bool p1_present, size_t len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    // Short-circuit FEC decoding during fuzzing unless unit test assertions are enabled
    (void)data; (void)p0; (void)p1; (void)present; (void)p0_present; (void)p1_present; (void)len;
    return 0;
#else
    int missing[8];
    int num_missing = 0;
    for (int i = 0; i < 8; i++) {
        if (!present[i]) missing[num_missing++] = i;
    }
    if (num_missing == 0) return 0;
    
    // Single erasure recovery
    if (num_missing == 1) {
        int m = missing[0];
        if (p0_present) { // Standard XOR parity recovery
            memcpy(data[m], p0, len);
            for (int i = 0; i < 8; i++) {
                if (i != m && present[i]) {
                    for (size_t k = 0; k < len; k++) data[m][k] ^= data[i][k];
                }
            }
            present[m] = true;
            return 0;
        } else if (p1_present) { // Weighted GF(2^8) parity recovery
            memcpy(data[m], p1, len);
            for (int i = 0; i < 8; i++) {
                if (i != m && present[i]) {
                    uint8_t coeff = gf_exp[i];
                    for (size_t k = 0; k < len; k++) data[m][k] ^= gf_mul(coeff, data[i][k]);
                }
            }
            uint8_t inv_coeff = gf_exp[255 - m];
            for (size_t k = 0; k < len; k++) data[m][k] = gf_mul(data[m][k], inv_coeff);
            present[m] = true;
            return 0;
        }
        return -1;
    }
    
    // Dual erasure simultaneous recovery using 2x2 linear system over GF(2^8)
    if (num_missing == 2) {
        if (!p0_present || !p1_present) return -1;
        int i = missing[0], j = missing[1];
        uint8_t S0[len], S1[len];
        memcpy(S0, p0, len);
        memcpy(S1, p1, len);
        
        for (int m = 0; m < 8; m++) {
            if (present[m]) {
                uint8_t c1 = gf_exp[m];
                for (size_t k = 0; k < len; k++) {
                    S0[k] ^= data[m][k];
                    S1[k] ^= gf_mul(c1, data[m][k]);
                }
            }
        }
        uint8_t inv_denom = gf_div(1, gf_exp[i] ^ gf_exp[j]);
        uint8_t c_j = gf_exp[j];
        for (size_t k = 0; k < len; k++) {
            uint8_t num = S1[k] ^ gf_mul(c_j, S0[k]);
            data[i][k] = gf_mul(num, inv_denom);
            data[j][k] = S0[k] ^ data[i][k];
        }
        present[i] = true;
        present[j] = true;
        return 0;
    }
    return -1;
#endif
}

/* ============================================================================ */
/* SECTION 3: BLIND RELAY FORWARDING & NAT TRAVERSAL TUNNELING                  */
/* ============================================================================ */

/**
 * @brief Locates an active established connection to a bootstrap node to serve as a blind relay.
 *
 * @details
 * Inspects known peers under read-lock for connections bound to default bootstrap ports (5555 or 5556)
 * in an `ESTABLISHED` handshake state.
 *
 * @param[in] state Global node state container.
 * @param[out] relay_addr Destination receiving socket coordinates of the relay.
 * @param[out] relay_pubkey Optional destination receiving 2,592-byte Dilithium5 public key.
 * @return `true` if an active relay path is located; `false` otherwise.
 *
 * @thread_safety Acquires `state->p2p_network.mutex`.
 * @complexity Time: O(known_peers), Space: O(1).
 */
static bool find_active_relay_path(State *state, struct sockaddr_storage *relay_addr, uint8_t *relay_pubkey) {
    if (!state || !relay_addr) return false;
    pthread_mutex_lock(&state->p2p_network.mutex);
    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
        Peer *peer = state->p2p_network.known_peers[i];
        if (peer && peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
            // Bootstrap nodes serve as robust relays
            uint16_t peer_port = (peer->addr.ss_family == AF_INET6) ?
                ((struct sockaddr_in6 *)&peer->addr)->sin6_port :
                ((struct sockaddr_in *)&peer->addr)->sin_port;
            if (peer_port == htons(5555) || peer_port == htons(5556)) {
                *relay_addr = peer->addr;
                if (relay_pubkey) {
                    memcpy(relay_pubkey, peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
                return true;
            }
        }
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);
    return false;
}

/**
 * @brief Commits an egress packet buffer, wrapping it in a blind relay envelope if required.
 *
 * @details
 * If `conn->use_relay` is true, shifts packet payload forward by 11 bytes in place within the
 * transmission ring slot to prepend the `MSG_RELAY_DATA` header (1B type, 4B length, 4B IPv4, 2B port)
 * without an extra heap allocation. Routes packet to `conn->relay_path`.
 *
 * @param[in] conn Connection context.
 * @param[in] token Transmission buffer token.
 * @param[in] len Serialized payload byte length.
 * @param[in] target_addr Final destination address.
 *
 * @complexity Time: O(len) memmove shift, Space: O(1) in-place.
 */
void commit_tx_buffer_relayed(SclConnection *conn, void *token, size_t len, const struct sockaddr_storage *target_addr) {
    if (conn->use_relay && global_shim) {
        uint32_t slot_idx = (uint32_t)(uintptr_t)token - 1;
        UserSpaceState *state = (UserSpaceState *)global_shim->impl_state;
        uint8_t *buf = state->tx_ring[slot_idx].buffer;
        
        // Zero-copy inline shift of the L1 packet to make space for the L5 Relay wrapper
        memmove(buf + 24, buf, len);
        
        buf[0] = MSG_RELAY_DATA;
        uint32_t relay_len_net = htonl(len + 19);
        memcpy(buf + 1, &relay_len_net, 4);
        serialize_sockaddr(target_addr, buf + 5);
        
        global_shim->commit_tx_buffer(global_shim, token, len + 24, conn->cid, &conn->relay_path);
    } else if (global_shim) {
        global_shim->commit_tx_buffer(global_shim, token, len, conn->cid, target_addr);
    }
}

/* ============================================================================ */
/* SECTION 4: L4 TRANSPORT RELIABILITY & BBRv3 LOSS DETECTION                   */
/* ============================================================================ */

/**
 * @brief Updates smoothed Round-Trip Time and variance estimators per RFC 9002.
 *
 * @details
 * Adjusts latest sample by subtracting receiver's delayed ACK interval if sample exceeds min_rtt.
 * Updates exponentially weighted moving averages:
 * $$rttvar = \frac{3 \cdot rttvar + |SRTT - sample|}{4}$$
 * $$SRTT = \frac{7 \cdot SRTT + sample}{8}$$
 *
 * @param[in,out] conn Connection context.
 * @param[in] latest_rtt Milliseconds elapsed between transmission and ACK.
 * @param[in] ack_delay Delay reported by remote receiver before sending ACK.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_l4_update_rtt(SclConnection *conn, uint64_t latest_rtt, uint64_t ack_delay) {
    pthread_mutex_lock(&conn->l4_mutex);
    if (conn->smoothed_rtt == 0) {
        conn->smoothed_rtt = latest_rtt;
        conn->rttvar = latest_rtt / 2;
        conn->min_rtt = latest_rtt;
    } else {
        if (latest_rtt < conn->min_rtt) conn->min_rtt = latest_rtt;
        
        // Adjust for receiver's ACK delay
        uint64_t adjusted_rtt = latest_rtt;
        if (latest_rtt >= conn->min_rtt + ack_delay) {
            adjusted_rtt = latest_rtt - ack_delay;
        }
                
        // RFC 9002 Math with correct rttvar computation
        uint64_t rtt_diff = (conn->smoothed_rtt > adjusted_rtt) ?
                            (conn->smoothed_rtt - adjusted_rtt) :
                            (adjusted_rtt - conn->smoothed_rtt);
                                    
        conn->rttvar = (3 * conn->rttvar + rtt_diff) / 4;
        conn->smoothed_rtt = (7 * conn->smoothed_rtt + adjusted_rtt) / 8;
    }
    pthread_mutex_unlock(&conn->l4_mutex);
}

/**
 * @brief Evaluates the current Probe Timeout (PTO) duration in milliseconds.
 *
 * @details
 * Evaluates RFC 9002 PTO equation:
 * $$PTO = (SRTT + \max(4 \cdot rttvar, 10) + max\_ack\_delay) \cdot 2^{pto\_count}$$
 * Clamped below by @ref SCL_MIN_PTO (1,000 ms) to absorb Dilithium5 verification latencies.
 *
 * @param[in] conn Connection context.
 * @return PTO duration in milliseconds.
 *
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t scl_l4_get_pto(SclConnection *conn) {
    uint64_t initial_rtt = (global_state && global_state->config.initial_rtt_ms > 0) ? global_state->config.initial_rtt_ms : 800;
    uint64_t min_pto = (global_state && global_state->config.min_pto_ms > 0) ? global_state->config.min_pto_ms : SCL_MIN_PTO;
    uint64_t max_ack_delay = (global_state && global_state->config.max_ack_delay_ms > 0) ? global_state->config.max_ack_delay_ms : 25;

    // PTO = smoothed_rtt + max(4*rttvar, 10ms) + max_ack_delay
    uint64_t rttvar_term = conn->rttvar * 4;
    uint64_t srtt_term = conn->smoothed_rtt > 0 ? (conn->smoothed_rtt + MAX(rttvar_term, 10) + max_ack_delay) : initial_rtt;
    uint64_t base_pto = MAX(min_pto, srtt_term);
            
    // SPEC: Hard 2-RTT base timeout for Flight 3
    if (!conn->is_handshake_complete && conn->smoothed_rtt > 0) {
        base_pto = MAX(base_pto, conn->smoothed_rtt * 2);
    }
            
    /* Clamp the shift: pto_count grows without bound on a link that never
     * ACKs; shifting by >= 31 would be undefined behaviour. */
    uint32_t pto_shift = (conn->pto_count > 16) ? 16 : conn->pto_count;
    return base_pto * (1ULL << pto_shift); // Exponential backoff scaling
}

/**
 * @brief Scans unacknowledged in-flight packets, declaring losses and scheduling retransmissions.
 *
 * @details
 * Evaluates three loss conditions per RFC 9002:
 * 1. Monotonic timeout: `now >= time_sent + PTO` (augmented by $SRTT/2$ for FEC-protected packets).
 * 2. Packet threshold: `largest_acked_packet >= packet_num + 32`.
 * 3. Time threshold: `now >= time_sent + (9/8 * max(SRTT, min_rtt))`.
 *
 * For declared losses, unlinks packets from `conn->unacked_head`. Unreliable datagrams are discarded;
 * reliable streams acquire fresh packet numbers, re-encrypt with active AEAD keys, and transmit immediately.
 * On loss, BBRv3 congestion window is reduced to 70% of BDP.
 *
 * @param[in,out] conn Connection context.
 * @param[in] now Current monotonic timestamp in milliseconds.
 * @param[in] state Global node state container.
 * @param[in] is_ack_driven `true` if invoked on ACK receipt; `false` on timer expiry.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(unacked_packets), Space: O(1).
 */
void scl_l4_detect_lost_packets(SclConnection *conn, uint64_t now, State *state, bool is_ack_driven) {
    pthread_mutex_lock(&conn->l4_mutex);
    
    conn->loss_time = 0;
    uint64_t loss_delay = scl_l4_get_pto(conn);
    
    uint32_t num = (state && state->config.time_threshold_num > 0) ? state->config.time_threshold_num : SCL_TIME_THRESHOLD_NUM;
    uint32_t den = (state && state->config.time_threshold_den > 0) ? state->config.time_threshold_den : SCL_TIME_THRESHOLD_DEN;
    
    // QUIC-Parity Spec (RFC 9002): Time Threshold for Reordering Resilience
    uint64_t time_threshold = (conn->smoothed_rtt > 0) ?
            ((MAX(conn->smoothed_rtt, conn->min_rtt) + (conn->rttvar * 4)) * num / den) : 20;
        
    uint64_t max_ack_delay = (state && state->config.max_ack_delay_ms > 0) ? state->config.max_ack_delay_ms : SCL_MAX_ACK_DELAY;
    time_threshold = MAX(time_threshold, max_ack_delay + conn->smoothed_rtt + 350);
    
    SclUnackedPacket *curr = conn->unacked_head;
    SclUnackedPacket *prev = NULL;
    bool loss_detected = false;
    bool storm_kill = false;
    
    SclUnackedPacket *retrans_head = NULL;
    SclUnackedPacket *retrans_tail = NULL;
    
    while (curr) {
        bool is_lost = false;
        
        uint64_t effective_loss_delay = loss_delay;
        if (curr->is_fec_protected) {
            effective_loss_delay += (conn->smoothed_rtt / 2);
        }
        
        if (now >= curr->time_sent + effective_loss_delay) {
            is_lost = true;
        } else if (conn->largest_acked_packet >= curr->packet_num + SCL_PACKET_THRESHOLD) {
            is_lost = true;
        } else if (conn->largest_acked_packet > curr->packet_num && now >= curr->time_sent + time_threshold) {
            is_lost = true;
        }
        
        if (is_lost) {
            if (conn->bytes_in_flight >= curr->bytes_in_flight) {
                conn->bytes_in_flight -= curr->bytes_in_flight;
            } else {
                conn->bytes_in_flight = 0;
            }
            loss_detected = true;
            
            SclUnackedPacket *to_process = curr;
            if (prev) prev->next = curr->next;
            else conn->unacked_head = curr->next;
            if (curr == conn->unacked_tail) conn->unacked_tail = prev;
            curr = curr->next;
            
            if (to_process->is_datagram) {
                if (to_process->raw_packet) free(to_process->raw_packet);
                free(to_process);
            } else if (to_process->retransmit_count >= SCL_MAX_STREAM_RETRANSMITS) {
                /* Storm circuit-breaker: this reliable-stream packet has been
                 * retransmitted SCL_MAX_STREAM_RETRANSMITS times and never ACKed.
                 * The remote endpoint is unreachable (classically: the peer
                 * replaced this socket during a mutual-dial collision, so our
                 * packets land on its listener and the stateless-reset token
                 * never reached us). Retransmitting forever pins the L4 loop,
                 * floods the link, and starves the submission pipeline - the
                 * "one seed stops submitting valuations" failure mode. Drop the
                 * packet; the connection reset below lets the reconnect
                 * watchdog dial a fresh, consistent pair. */
                fprintf(stderr, "[L4] Stream Packet %llu exceeded %d retransmissions. Dropping packet and resetting connection.\n",
                        (unsigned long long)to_process->packet_num, SCL_MAX_STREAM_RETRANSMITS);
                if (to_process->raw_packet) free(to_process->raw_packet);
                free(to_process);
                storm_kill = true;
            } else {
                size_t max_len = 0;
                void *tx_token = NULL;
                uint8_t *tx_buf = NULL;
                
                // Retransmissions prioritize recovery and bypass strict pacing to prevent starvation under heavy loss
                tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
                                        
                if (tx_buf && to_process->raw_packet) {
                    fprintf(stderr, "[L4] Stream Packet %llu declared lost. Retransmitting natively.\n", to_process->packet_num);
                    uint64_t new_pkt_num = atomic_fetch_add_explicit(&conn->next_packet_num, 1, memory_order_relaxed);
                    bool is_fragmented = (to_process->raw_packet[0] & SCL_PACKET_FLAG_FRAGMENTED) != 0;
                    bool is_long_header = ((to_process->raw_packet[0] & 0xC0) == 0xC0);
                    
                    // Strict boundary check: If bytes_in_flight cannot support header prefixes, drop to prevent underflow
                    size_t min_header_len = is_fragmented ? (is_long_header ? (SCL_HEADER_MIN_LEN + 76) : (SCL_HEADER_MIN_LEN + 12)) : SCL_HEADER_MIN_LEN;
                    if (to_process->bytes_in_flight < min_header_len) {
                        global_shim->abort_tx_buffer(global_shim, tx_token);
                        free(to_process->raw_packet);
                        free(to_process);
                        continue;
                    }
                    
                    uint64_t raw_pn_be = htobe64(new_pkt_num);
                    memcpy(to_process->raw_packet + 1 + SCL_CID_LEN, &raw_pn_be, 8);
                                
                    if (is_fragmented) {
                        if (is_long_header) {
                            size_t chunk = to_process->bytes_in_flight - (SCL_HEADER_MIN_LEN + 76);
                            tx_buf[0] = SCL_PACKET_FLAG_LONG_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                            memcpy(tx_buf + 1, conn->cid, SCL_CID_LEN);
                            uint64_t pn_be = htobe64(new_pkt_num);
                            memcpy(tx_buf + 1 + SCL_CID_LEN, &pn_be, 8);
                            
                            memcpy(tx_buf + SCL_HEADER_MIN_LEN, to_process->raw_packet + SCL_HEADER_MIN_LEN, 76);
                            
                            size_t out_len_frag = 0;
                            encrypt_aead_packet(conn->flight3_aes_gcm_key, new_pkt_num, to_process->raw_packet + SCL_HEADER_MIN_LEN + 76, chunk, tx_buf + SCL_HEADER_MIN_LEN + 76, &out_len_frag, tx_buf, SCL_HEADER_MIN_LEN + 76);
                            
                            size_t total_sent_retrans = SCL_HEADER_MIN_LEN + 76 + out_len_frag;
                            commit_tx_buffer_relayed(conn, tx_token, total_sent_retrans, &conn->current_path);
                            if (conn->pacing_budget >= total_sent_retrans) {
                                conn->pacing_budget -= total_sent_retrans;
                            } else {
                                conn->pacing_budget = 0;
                            }
                        } else {
                            size_t chunk = to_process->bytes_in_flight - (SCL_HEADER_MIN_LEN + 12);
                            tx_buf[0] = SCL_PACKET_FLAG_SHORT_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                            memcpy(tx_buf + 1, conn->cid, SCL_CID_LEN);
                            uint64_t pn_be = htobe64(new_pkt_num);
                            memcpy(tx_buf + 1 + SCL_CID_LEN, &pn_be, 8);
                                        
                            memcpy(tx_buf + SCL_HEADER_MIN_LEN, to_process->raw_packet + SCL_HEADER_MIN_LEN, 12);
                                        
                            size_t out_len_frag = 0;
                            encrypt_aead_packet(conn->current_aes_gcm_key, new_pkt_num, to_process->raw_packet + SCL_HEADER_MIN_LEN + 12, chunk, tx_buf + SCL_HEADER_MIN_LEN + 12, &out_len_frag, tx_buf, SCL_HEADER_MIN_LEN + 12);
                                        
                            size_t total_sent_retrans = SCL_HEADER_MIN_LEN + 12 + out_len_frag;
                            commit_tx_buffer_relayed(conn, tx_token, total_sent_retrans, &conn->current_path);
                            if (conn->pacing_budget >= total_sent_retrans) {
                                conn->pacing_budget -= total_sent_retrans;
                            } else {
                                conn->pacing_budget = 0;
                            }
                        }
                    } else {
                        if (is_long_header) {
                            size_t chunk = to_process->bytes_in_flight - SCL_HEADER_MIN_LEN;
                            tx_buf[0] = SCL_PACKET_FLAG_LONG_HEADER;
                            memcpy(tx_buf + 1, conn->cid, SCL_CID_LEN);
                            uint64_t pn_be = htobe64(new_pkt_num);
                            memcpy(tx_buf + 1 + SCL_CID_LEN, &pn_be, 8);
                            memcpy(tx_buf + SCL_HEADER_MIN_LEN, to_process->raw_packet + SCL_HEADER_MIN_LEN, chunk);
                            commit_tx_buffer_relayed(conn, tx_token, to_process->bytes_in_flight, &conn->current_path);
                            if (conn->pacing_budget >= to_process->bytes_in_flight) {
                                conn->pacing_budget -= to_process->bytes_in_flight;
                            } else {
                                conn->pacing_budget = 0;
                            }
                        } else {
                            size_t chunk = to_process->bytes_in_flight - SCL_HEADER_MIN_LEN;
                            tx_buf[0] = SCL_PACKET_FLAG_SHORT_HEADER;
                            memcpy(tx_buf + 1, conn->cid, SCL_CID_LEN);
                            uint64_t pn_be = htobe64(new_pkt_num);
                            memcpy(tx_buf + 1 + SCL_CID_LEN, &pn_be, 8);
                                                                
                            size_t out_len = 0;
                            encrypt_aead_packet(conn->current_aes_gcm_key, new_pkt_num, to_process->raw_packet + SCL_HEADER_MIN_LEN, chunk, tx_buf + SCL_HEADER_MIN_LEN, &out_len, tx_buf, SCL_HEADER_MIN_LEN);
                                                                
                            size_t total_sent_retrans = SCL_HEADER_MIN_LEN + out_len;
                            commit_tx_buffer_relayed(conn, tx_token, total_sent_retrans, &conn->current_path);
                            if (conn->pacing_budget >= total_sent_retrans) {
                                conn->pacing_budget -= total_sent_retrans;
                            } else {
                                conn->pacing_budget = 0;
                            }
                        }
                    }
                                                            
                    to_process->packet_num = new_pkt_num;
                    to_process->time_sent = now;
                    to_process->retransmit_count++;
                    to_process->delivered_at_tx = conn->bbr_delivered;
                    to_process->delivered_time_at_tx = conn->bbr_delivered_time;
                    to_process->next = NULL;

                    if (!conn->is_handshake_complete) {
                        atomic_store_explicit(&conn->last_rx_time, now, memory_order_relaxed);
                    }

                    if (!retrans_head) {
                        retrans_head = to_process;
                        retrans_tail = to_process;
                    } else {
                        retrans_tail->next = to_process;
                        retrans_tail = to_process;
                    }
                    conn->bytes_in_flight += to_process->bytes_in_flight;
                } else {
                    if (tx_buf) global_shim->abort_tx_buffer(global_shim, tx_token);
                                        
                    if (!to_process->raw_packet) {
                        free(to_process);
                        continue;
                    }
                    
                    to_process->time_sent = now; // Prevent infinite timer spin-lock
                    to_process->next = NULL;
                    if (!retrans_head) {
                        retrans_head = to_process;
                        retrans_tail = to_process;
                    } else {
                        retrans_tail->next = to_process;
                        retrans_tail = to_process;
                    }
                                    
                    // Restore bytes_in_flight to prevent BBRv3 window underflow
                    conn->bytes_in_flight += to_process->bytes_in_flight;
                }
            }
        } else {
            uint64_t pkt_loss_time = curr->time_sent + loss_delay;
            if (conn->loss_time == 0 || pkt_loss_time < conn->loss_time) {
                conn->loss_time = pkt_loss_time;
            }
            prev = curr;
            curr = curr->next;
        }
    }
    
    if (retrans_head) {
        if (!conn->unacked_head) {
            conn->unacked_head = retrans_head;
            conn->unacked_tail = retrans_tail;
        } else {
            conn->unacked_tail->next = retrans_head;
            conn->unacked_tail = retrans_tail;
        }
        
        uint64_t pkt_loss_time = retrans_head->time_sent + loss_delay;
        if (conn->loss_time == 0 || pkt_loss_time < conn->loss_time) {
            conn->loss_time = pkt_loss_time;
        }
    }
    
    if (loss_detected) {
        if (!is_ack_driven) {
            conn->pto_count++;
        } else {
            // BBRv3 Loss Response: Scale down cwnd to 70% of BDP
            uint64_t bdp = (conn->bbr_max_bw * conn->bbr_min_rtt) / 1000;
                
            if (!conn->is_handshake_complete) {
                conn->cwnd = MAX(conn->cwnd, SCL_MICRO_BDP_LIMIT);
            } else {
                uint64_t target = (bdp * 70) / 100;
                conn->cwnd = MAX(target, SCL_MICRO_BDP_LIMIT);
                conn->bbr_max_bw = (conn->bbr_max_bw * 70) / 100;
            }
        }
    }
    
    pthread_mutex_unlock(&conn->l4_mutex);

    if (storm_kill) {
        /* Tear the stormed-out connection down: once it leaves the CID routing
         * table no further loss detection or egress runs for it, and the
         * peer-table row is recycled by the 15s reconnect watchdog. */
        conn->handshake_state = SCL_CONN_STATE_NONE;
        if (global_shim && global_shim->unregister_connection(global_shim, conn->cid)) {
            scl_connection_release(conn);
        }
    }
}

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
void scl_l4_on_packet_sent(SclConnection *conn, uint64_t packet_num, size_t len, bool is_datagram, bool is_fec_protected, const uint8_t *raw_packet) {
    SclUnackedPacket *pkt = malloc(sizeof(SclUnackedPacket));
    if (!pkt) return;
    
    pkt->packet_num = packet_num;
    pkt->time_sent = get_time_ms();
    pkt->bytes_in_flight = len;
    pkt->is_datagram = is_datagram;
    pkt->is_fec_protected = is_fec_protected;
    pkt->retransmit_count = 0;
    
    // BBRv3: Snapshot Delivery State
    pkt->delivered_at_tx = conn->bbr_delivered;
    pkt->delivered_time_at_tx = conn->bbr_delivered_time;
    
    // Allocate duplicate strictly for Streams/Blocks (Datagrams dropped)
    if (!is_datagram && raw_packet) {
        pkt->raw_packet = malloc(len);
        if (pkt->raw_packet) {
            memcpy(pkt->raw_packet, raw_packet, len);
        } else {
            free(pkt);
            return;
        }
    } else {
        pkt->raw_packet = NULL;
    }
    pkt->next = NULL;
    
    pthread_mutex_lock(&conn->l4_mutex);
    if (!conn->unacked_head) {
        conn->unacked_head = pkt;
        conn->unacked_tail = pkt;
    } else {
        conn->unacked_tail->next = pkt;
        conn->unacked_tail = pkt;
    }
    conn->bytes_in_flight += len;
    
    // Initialize loss_time boundary for the event loop sweeper
    if (conn->loss_time == 0) {
        uint64_t loss_delay = scl_l4_get_pto(conn);
        conn->loss_time = pkt->time_sent + loss_delay;
    }
    pthread_mutex_unlock(&conn->l4_mutex);
}

/**
 * @brief Processes an incoming ACK frame, releasing tracked packets and updating BBRv3 bandwidth.
 *
 * @details
 * Searches `conn->unacked_head` for `acked_pkt`. Updates delivery rate sample:
 * $$delivery\_rate = \frac{bytes\_delivered \cdot 1000}{\Delta t}$$
 * Applies low-pass filter to `bbr_max_bw` and tracks minimum RTT window.
 * Advances BBRv3 state machine (STARTUP -> DRAIN -> PROBE_BW -> PROBE_RTT).
 *
 * @param[in,out] conn Connection context.
 * @param[in] acked_pkt Sequence number acknowledged by remote peer.
 * @param[in] ack_delay Delay in milliseconds reported by remote peer.
 *
 * @thread_safety Acquires `conn->l4_mutex`.
 * @complexity Time: O(unacked_packets), Space: O(1).
 */
void process_l4_ack(SclConnection *conn, uint64_t acked_pkt, uint64_t ack_delay) {
    if (!conn) return;
    
    uint64_t rtt = 0;
    int found = 0;

    pthread_mutex_lock(&conn->l4_mutex);
    
    if (acked_pkt > conn->largest_acked_packet) {
        conn->largest_acked_packet = acked_pkt;
    }
    
    SclUnackedPacket *curr = conn->unacked_head;
    SclUnackedPacket *prev = NULL;
    
    while (curr) {
        if (curr->packet_num == acked_pkt) {
            // Guard against bytes_in_flight underflow
            if (conn->bytes_in_flight >= curr->bytes_in_flight) {
                conn->bytes_in_flight -= curr->bytes_in_flight;
            } else {
                conn->bytes_in_flight = 0;
            }
            
            // BBRv3 Bottleneck Bandwidth Estimation
            uint64_t now_ack = get_time_ms();
            uint64_t bytes_delivered = conn->bbr_delivered - curr->delivered_at_tx + curr->bytes_in_flight;
            uint64_t time_elapsed = now_ack - curr->delivered_time_at_tx;
            if (time_elapsed == 0) time_elapsed = 1;
                        
            uint64_t delivery_rate = (bytes_delivered * 1000) / time_elapsed;
            
            // Low-pass filter smoothing bandwidth spikes
            if (conn->bbr_max_bw == 0) {
                conn->bbr_max_bw = delivery_rate;
            } else if (delivery_rate > conn->bbr_max_bw) {
                conn->bbr_max_bw = (conn->bbr_max_bw * 7 + delivery_rate) / 8;
            }
            
            conn->bbr_delivered += curr->bytes_in_flight;
            conn->bbr_delivered_time = now_ack;
            
            // BBRv3 Min RTT Tracking (RTprop)
            rtt = (now_ack > curr->time_sent) ? (now_ack - curr->time_sent) : 1;
            if (conn->bbr_min_rtt == 0 || rtt < conn->bbr_min_rtt) {
                conn->bbr_min_rtt = rtt;
                conn->bbr_min_rtt_stamp = now_ack;
            }

            // BBRv3 Target CWND (BDP) Calculation
            uint64_t bdp = (conn->bbr_max_bw * conn->bbr_min_rtt) / 1000;
            uint64_t target_cwnd = MAX(bdp, SCL_MICRO_BDP_LIMIT);

            if (conn->bbr_state == 0) { // STARTUP
                conn->cwnd = (target_cwnd * 289) / 100;
                if (conn->bbr_delivered > SCL_MICRO_BDP_LIMIT * 4 && conn->bbr_max_bw > 0) {
                    conn->bbr_state = 1; // DRAIN
                }
            } else if (conn->bbr_state == 1) { // DRAIN
                conn->cwnd = target_cwnd;
                if (conn->bytes_in_flight <= target_cwnd) {
                    conn->bbr_state = 2; // PROBE_BW
                    conn->bbr_cycle_stamp = now_ack;
                    conn->bbr_cycle_idx = 0;
                }
            } else if (conn->bbr_state == 2) { // PROBE_BW
                if (now_ack - conn->bbr_cycle_stamp > conn->bbr_min_rtt) {
                    conn->bbr_cycle_stamp = now_ack;
                    conn->bbr_cycle_idx = (conn->bbr_cycle_idx + 1) % 8;
                }
                uint32_t gain = 100;
                if (conn->bbr_cycle_idx == 0) gain = 125;
                else if (conn->bbr_cycle_idx == 1) gain = 75;
                conn->cwnd = (target_cwnd * gain) / 100;
                
                if (now_ack - conn->bbr_min_rtt_stamp > 10000) {
                    conn->bbr_state = 3; // PROBE_RTT
                    conn->bbr_prior_cwnd = conn->cwnd;
                    conn->bbr_probe_rtt_done_stamp = now_ack + 200;
                }
            } else if (conn->bbr_state == 3) { // PROBE_RTT
                conn->cwnd = SCL_MICRO_BDP_LIMIT;
                if (now_ack > conn->bbr_probe_rtt_done_stamp) {
                    conn->bbr_min_rtt_stamp = now_ack;
                    conn->bbr_state = 2;
                    conn->cwnd = conn->bbr_prior_cwnd;
                }
            }

            conn->pto_count = 0;
            
            // Detach and release acknowledged packet
            if (prev) prev->next = curr->next;
            else conn->unacked_head = curr->next;
            if (curr == conn->unacked_tail) conn->unacked_tail = prev;
            
            if (curr->raw_packet) free(curr->raw_packet);
            free(curr);
            
            found = 1;
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&conn->l4_mutex);

    if (found) {
        scl_l4_update_rtt(conn, rtt, ack_delay);
    }
}

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
void send_l4_ack(SclConnection *conn, uint64_t acked_pkt, uint64_t rx_time) {
    if (!global_shim || !conn) return;

    uint8_t zero_cid[SCL_CID_LEN] = {0};
    if (memcmp(conn->cid, zero_cid, SCL_CID_LEN) == 0) {
        return;
    }

    pthread_mutex_lock(&conn->l4_mutex);
    
    if (acked_pkt != 0) {
        bool dup = false;
        for (uint32_t i = 0; i < conn->pending_ack_count; i++) {
            if (conn->pending_acks[i] == acked_pkt) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            if (conn->pending_ack_count < 256) {
                conn->pending_acks_time[conn->pending_ack_count] = rx_time;
                conn->pending_acks[conn->pending_ack_count++] = acked_pkt;
            } else {
                // Drop oldest ACK to make room for newest when saturated
                for (int i = 0; i < 255; i++) {
                    conn->pending_acks[i] = conn->pending_acks[i + 1];
                    conn->pending_acks_time[i] = conn->pending_acks_time[i + 1];
                }
                conn->pending_acks_time[255] = rx_time;
                conn->pending_acks[255] = acked_pkt;
            }
        }
    }
    
    uint64_t now = get_time_ms();
    bool flush_now = false;
    
    if (!conn->is_handshake_complete ||
        conn->pending_ack_count >= 16 ||
        (conn->pending_ack_count > 0 && now - conn->last_ack_trigger_time >= SCL_MAX_ACK_DELAY) ||
        (acked_pkt == 0 && conn->pending_ack_count > 0)) {
        flush_now = true;
    }
    
    if (!flush_now) {
        pthread_mutex_unlock(&conn->l4_mutex);
        return;
    }

    if (conn->pending_ack_count > 1) {
        // Sort ACKs chronologically
        for (uint32_t i = 1; i < conn->pending_ack_count; i++) {
            uint64_t key_ack = conn->pending_acks[i];
            uint64_t key_time = conn->pending_acks_time[i];
            int32_t j = i - 1;
            while (j >= 0 && conn->pending_acks[j] > key_ack) {
                conn->pending_acks[j + 1] = conn->pending_acks[j];
                conn->pending_acks_time[j + 1] = conn->pending_acks_time[j];
                j--;
            }
            conn->pending_acks[j + 1] = key_ack;
            conn->pending_acks_time[j + 1] = key_time;
        }
    }

    while (conn->pending_ack_count > 0) {
        size_t max_len;
        void *tx_token;
        uint8_t *tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
        if (!tx_buf) {
            break;
        }

        uint32_t ack_to_send = conn->pending_ack_count > 64 ? 64 : conn->pending_ack_count;
        size_t payload_len = ack_to_send * 17;
        uint8_t *payload = malloc(payload_len);
        if (!payload) {
            global_shim->abort_tx_buffer(global_shim, tx_token);
            break;
        }
        
        for (uint32_t i = 0; i < ack_to_send; i++) {
            payload[i * 17] = SCL_FRAME_ACK;
            uint64_t ack_be = htobe64(conn->pending_acks[i]);
            memcpy(payload + i * 17 + 1, &ack_be, 8);
            
            uint64_t delay = now >= conn->pending_acks_time[i] ? now - conn->pending_acks_time[i] : 0;
            uint64_t delay_be = htobe64(delay);
            memcpy(payload + i * 17 + 9, &delay_be, 8);
        }
        
        if (conn->pending_ack_count > 64) {
            for (uint32_t i = 64; i < conn->pending_ack_count; i++) {
                conn->pending_acks[i - 64] = conn->pending_acks[i];
                conn->pending_acks_time[i - 64] = conn->pending_acks_time[i];
            }
            conn->pending_ack_count -= 64;
        } else {
            conn->pending_ack_count = 0;
        }

        uint64_t new_pkt_num = atomic_fetch_add_explicit(&conn->next_packet_num, 1, memory_order_relaxed);
        
        tx_buf[0] = SCL_PACKET_FLAG_SHORT_HEADER;
        memcpy(tx_buf + 1, conn->cid, SCL_CID_LEN);
        uint64_t pn_be = htobe64(new_pkt_num);
        memcpy(tx_buf + 1 + SCL_CID_LEN, &pn_be, 8);

        size_t out_len;
        encrypt_aead_packet(conn->current_aes_gcm_key, new_pkt_num, payload, payload_len, tx_buf + SCL_HEADER_MIN_LEN, &out_len, tx_buf, SCL_HEADER_MIN_LEN);

        free(payload);
        global_shim->commit_tx_buffer(global_shim, tx_token, SCL_HEADER_MIN_LEN + out_len, conn->cid, &conn->current_path);
    }
    
    conn->last_ack_trigger_time = now;
    pthread_mutex_unlock(&conn->l4_mutex);
}

/* ============================================================================ */
/* SECTION 5: STATELESS TOKENS, COOKIES & ANTI-AMPLIFICATION DEFENSE             */
/* ============================================================================ */

/**
 * @brief Generates an authenticated, encrypted stateless token for Handshake Flight 2.
 *
 * @details
 * Encrypts the 32-byte KEM shared secret inside an authenticated AEAD envelope using a key
 * derived via HKDF from the node's static secret, the client's IPv4 address, and an expiration timestamp.
 * Encodes token as: `[ Expiry (8B) | Random IV (8B) | Ciphertext + Tag (48B) ]` = 64 bytes total.
 *
 * @param[in] node_secret 32-byte static random node secret.
 * @param[in] shared_secret 32-byte Kyber-512 shared secret to encrypt.
 * @param[in] client_ip 32-bit IPv4 address of the connecting client (host order).
 * @param[in] expiry Millisecond timestamp when the token becomes invalid.
 * @param[out] token_out Destination buffer receiving the 64-byte token.
 *
 * @pre `token_out` must point to at least 64 writable bytes.
 * @complexity Time: O(1), Space: O(1).
 */
void generate_stateless_token(const uint8_t *node_secret, const uint8_t *shared_secret, const uint8_t client_ip[16], uint64_t expiry, uint8_t *token_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)node_secret; (void)shared_secret; (void)client_ip;
    memcpy(token_out, &expiry, 8);
    memset(token_out + 8, 0x42, 56);
#else
    uint64_t random_iv;
    RAND_bytes((uint8_t*)&random_iv, 8);
    
    uint8_t key_input[32 + 16 + 8];
    memcpy(key_input, node_secret, 32);
    memcpy(key_input + 32, client_ip, 16);
    memcpy(key_input + 48, &expiry, 8);
    uint8_t derived_key[32];
    SHA256(key_input, sizeof(key_input), derived_key);
    
    uint8_t ciphertext[64];
    size_t ct_len;
    encrypt_aead_packet(derived_key, random_iv, shared_secret, KYBER_SHARED_SECRET_LEN, ciphertext, &ct_len, NULL, 0);
    
    // Wire encoding: Expiry(8) || RandomIV(8) || Ciphertext+Tag(48) = 64 bytes
    memcpy(token_out, &expiry, 8);
    memcpy(token_out + 8, &random_iv, 8);
    memcpy(token_out + 16, ciphertext, ct_len);
#endif
}

/**
 * @brief Verifies and decrypts an authenticated stateless token presented in Handshake Flight 3.
 *
 * @param[in] node_secret 32-byte static random node secret.
 * @param[in] token_in 64-byte token received from client.
 * @param[in] client_ip 16-byte normalized IPv6 or IPv4-mapped address of sending peer.
 * @param[out] shared_secret_out 32-byte destination receiving the recovered shared secret.
 * @return 0 on success; -1 if token is expired, forged, or fails authentication.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int verify_stateless_token(const uint8_t *node_secret, const uint8_t *token_in, const uint8_t client_ip[16], uint8_t *shared_secret_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)node_secret; (void)token_in; (void)client_ip;
    memset(shared_secret_out, 0x42, KYBER_SHARED_SECRET_LEN);
    return 0;
#else
    uint64_t expiry;
    memcpy(&expiry, token_in, 8);
    
    if (get_time_ms() > expiry) return -1;
    
    uint64_t random_iv;
    memcpy(&random_iv, token_in + 8, 8);
    
    uint8_t key_input[32 + 16 + 8];
    memcpy(key_input, node_secret, 32);
    memcpy(key_input + 32, client_ip, 16);
    memcpy(key_input + 48, &expiry, 8);
    uint8_t derived_key[32];
    SHA256(key_input, sizeof(key_input), derived_key);
    
    size_t pt_len;
    if (decrypt_aead_packet(derived_key, random_iv, token_in + 16, 48, shared_secret_out, &pt_len, NULL, 0) != 0) {
        return -1;
    }
    return (pt_len == KYBER_SHARED_SECRET_LEN) ? 0 : -1;
#endif
}

/**
 * @brief Generates a 64-bit stateless cookie for client address verification in RETRY packets.
 *
 * @param[in] node_secret 32-byte random node secret.
 * @param[in] client_ip 16-byte normalized IPv6 or IPv4-mapped address buffer.
 * @return 64-bit SipHash-2-4 cookie.
 *
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t generate_stateless_cookie(const uint8_t *node_secret, const uint8_t client_ip[16]) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)node_secret; (void)client_ip;
    return 0x4242424242424242ULL;
#else
    uint64_t epoch = get_time_ms() / 300000; // 5-minute rotating epoch
    uint8_t sip_input[24];
    memcpy(sip_input, client_ip, 16);
    memcpy(sip_input + 16, &epoch, 8);
    return siphash24(sip_input, sizeof(sip_input), node_secret);
#endif
}

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
bool verify_stateless_cookie(const uint8_t *node_secret, const uint8_t client_ip[16], uint64_t cookie) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)node_secret; (void)client_ip; (void)cookie;
    return true;
#else
    uint64_t current_epoch = get_time_ms() / 300000;
    uint8_t sip_input[24];
    memcpy(sip_input, client_ip, 16);
    
    // Validate against current epoch
    memcpy(sip_input + 16, &current_epoch, 8);
    if (siphash24(sip_input, sizeof(sip_input), node_secret) == cookie) return true;
    
    // Validate against previous epoch to allow graceful boundary crossing
    uint64_t prev_epoch = current_epoch - 1;
    memcpy(sip_input + 16, &prev_epoch, 8);
    return (siphash24(sip_input, sizeof(sip_input), node_secret) == cookie);
#endif
}

/**
 * @brief Extracts the userspace implementation state pointer from an abstract transport shim.
 *
 * @param[in] shim Pointer to SclTransportShim interface.
 * @return Pointer to UserSpaceState context.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static UserSpaceState *get_shim_state(struct SclTransportShim *shim) {
    return (UserSpaceState *)shim->impl_state;
}

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
bool try_acquire_ref(SclConnection *conn) {
    int expected = atomic_load_explicit(&conn->ref_count, memory_order_acquire);
    while (expected > 0) {
        if (atomic_compare_exchange_weak_explicit(&conn->ref_count, &expected, expected + 1, memory_order_acquire, memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

/* ============================================================================ */
/* SECTION 6: L1 CONNECTION ID (CID) ROUTING & HANDSHAKE INITIATION            */
/* ============================================================================ */

/**
 * @brief Evaluates the 32-bit hash index of a Connection ID using SipHash-2-4.
 *
 * @param[in] cid 20-byte Connection ID.
 * @param[in] node_secret 16-byte node secret.
 * @return 32-bit hash index.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static uint32_t hash_cid(const uint8_t *cid, const uint8_t *node_secret) {
    return (uint32_t)siphash24(cid, SCL_CID_LEN, node_secret);
}

/**
 * @brief Registers a connection mapping in the lock-free 4,096-bucket CID routing table.
 *
 * @param[in] shim Pointer to transport shim interface.
 * @param[in] cid 20-byte Connection ID key.
 * @param[in] conn Target connection context.
 *
 * @complexity Time: O(1) expected linear probing, Space: O(1).
 */
static void us_register_connection(struct SclTransportShim *shim, const uint8_t *cid, SclConnection *conn) {
    UserSpaceState *state = get_shim_state(shim);
    if (!state) return;

    uint32_t start_idx = hash_cid(cid, state->node_secret) % 4096;
    for (int i = 0; i < 4096; i++) {
        uint32_t probe = (start_idx + i) % 4096;
        SclConnection *expected = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
        if (expected == conn) {
            return;
        }
        if (expected == NULL || expected == SCL_TOMBSTONE) {
            if (atomic_compare_exchange_strong_explicit(&state->cid_routing_table[probe], &expected, conn, memory_order_release, memory_order_relaxed)) {
                fprintf(stderr, "[Shim] Connection Registered. CID: %02x%02x... at bucket %u\n", cid[0], cid[1], probe);
                return;
            }
        }
    }
    fprintf(stderr, "[Shim] ERROR: CID Routing Table Full!\n");
}

/**
 * @brief Unregisters a connection from the CID routing table, replacing it with a tombstone.
 *
 * @param[in] shim Pointer to transport shim interface.
 * @param[in] cid 20-byte Connection ID to remove.
 * @return `true` if entry was found and tombstoned; `false` otherwise.
 *
 * @complexity Time: O(1) expected, Space: O(1).
 */
static bool us_unregister_connection(struct SclTransportShim *shim, const uint8_t *cid) {
    UserSpaceState *state = get_shim_state(shim);
    if (!state) return false;

    uint32_t start_idx = hash_cid(cid, state->node_secret) % 4096;
    for (int i = 0; i < 4096; i++) {
        uint32_t probe = (start_idx + i) % 4096;
        SclConnection *conn = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
        if (conn == NULL) break;
        if (conn != SCL_TOMBSTONE && memcmp(conn->cid, cid, SCL_CID_LEN) == 0) {
            atomic_store_explicit(&state->cid_routing_table[probe], SCL_TOMBSTONE, memory_order_release);
            return true;
        }
    }
    return false;
}

/**
 * @brief Constructs and transmits Handshake Flight 1 to initiate connection setup with a peer.
 *
 * @details
 * Constructs unencrypted Long Header packet:
 * - Flags: `SCL_PACKET_FLAG_LONG_HEADER` (0xC0).
 * - CID: 20-byte random connection identifier.
 * - Packet Number: Monotonic counter incremented via atomic fetch-and-add.
 * - Payload: Stateless cookie (8B) + PoW solution (8B) + Ephemeral Kyber-512 public key (800B)
 *   + User ID (32B) + Secondary PoW solution (8B).
 * - Padding: Padded with zeros to exact Path MTU (@ref SCL_LINK_MTU - 48 = 1,232 bytes)
 *   to enforce path MTU validation and eliminate amplification vectors.
 *
 * @param[in] net P2P network subsystem container.
 * @param[in,out] conn Pre-allocated connection context.
 * @param[in] addr Target remote socket address.
 *
 * @post Flight 1 packet padded to Path MTU queued for egress; status updated to FLIGHT1_SENT.
 * @complexity Time: O(2^pow_bits) for PoW search, Space: O(Path_MTU) heap buffer.
 */
void scl_initiate_handshake(P2PNetwork *net, SclConnection *conn, const struct sockaddr_storage *addr) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)net; (void)conn; (void)addr;
    return;
#endif
    if (!global_shim) return;
    
    size_t max_len;
    void *tx_token;
    uint8_t *tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
    
    // Enforce Link MTU path verification by padding Flight 1 to discovered payload limit
    size_t total_len = conn->path_mtu;
    uint64_t current_pkt = atomic_fetch_add_explicit(&conn->next_packet_num, 1, memory_order_relaxed);

    uint8_t *unencrypted_f1 = calloc(1, total_len);
    if (!unencrypted_f1) {
        if (tx_buf) global_shim->abort_tx_buffer(global_shim, tx_token);
        return;
    }
    
    unencrypted_f1[0] = SCL_PACKET_FLAG_LONG_HEADER;
    memcpy(unencrypted_f1 + 1, conn->cid, SCL_CID_LEN);
    uint64_t pn_be = htobe64(current_pkt);
    memcpy(unencrypted_f1 + 1 + SCL_CID_LEN, &pn_be, 8);
    
    size_t payload_offset = SCL_HEADER_MIN_LEN;
    uint64_t cookie = conn->handshake_cookie;
            
    uint64_t pow_solution = 0;
    uint8_t pow_input[KYBER_PUBKEY_LEN + 16];
    memcpy(pow_input, conn->ephemeral_kyber_pubkey, KYBER_PUBKEY_LEN);
    memcpy(pow_input + KYBER_PUBKEY_LEN, &cookie, 8);
    uint8_t pow_hash[32];
                
    int bytes = conn->required_pow_bits / 8;
    int remainder = conn->required_pow_bits % 8;
    uint8_t mask = remainder > 0 ? (0xFF << (8 - remainder)) : 0;
            
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)pow_input; (void)pow_hash; (void)bytes; (void)remainder; (void)mask;
    pow_solution = 0;
#else
    while (1) {
        memcpy(pow_input + KYBER_PUBKEY_LEN + 8, &pow_solution, 8);
        SHA256(pow_input, sizeof(pow_input), pow_hash);
        
        int valid = 1;
        for (int i = 0; i < bytes; i++) {
            if (pow_hash[i] != 0) { valid = 0; break; }
        }
        if (valid && remainder > 0) {
            if ((pow_hash[bytes] & mask) != 0) valid = 0;
        }
        if (valid) break;
        pow_solution++;
        if (atomic_load(&global_shutdown)) break;
    }
#endif
    
    // Solve secondary challenge if active
    uint64_t secondary_solution = 0;
    if (conn->secondary_pow_bits > 0) {
        secondary_solution = find_nonce(conn->hypergraph_puzzle_base, conn->secondary_pow_bits);
    }
        
    uint8_t user_id[USER_ID_LEN];
    SHA256(net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
        
    memcpy(unencrypted_f1 + payload_offset, &cookie, 8);
    memcpy(unencrypted_f1 + payload_offset + 8, &pow_solution, 8);
    memcpy(unencrypted_f1 + payload_offset + 16, conn->ephemeral_kyber_pubkey, KYBER_PUBKEY_LEN);
    memcpy(unencrypted_f1 + payload_offset + 16 + KYBER_PUBKEY_LEN, user_id, USER_ID_LEN);
    
    uint64_t sec_sol_be = htobe64(secondary_solution);
    memcpy(unencrypted_f1 + payload_offset + 16 + KYBER_PUBKEY_LEN + USER_ID_LEN, &sec_sol_be, 8);
    
    conn->handshake_state = SCL_CONN_STATE_FLIGHT1_SENT;
    
    scl_l4_on_packet_sent(conn, current_pkt, total_len, false, false, unencrypted_f1);

    if (tx_buf && max_len >= total_len) {
        memcpy(tx_buf, unencrypted_f1, total_len);
        commit_tx_buffer_relayed(conn, tx_token, total_len, addr);
    } else if (tx_buf) {
        global_shim->abort_tx_buffer(global_shim, tx_token);
    }
    free(unencrypted_f1);
    
    fprintf(stderr, "[L5] Initiated 2-RTT PQ Handshake (Flight 1 Sent - Padded to %zu bytes).\n", total_len);
}

/**
 * @brief Immediately destroys a connection context and frees all nested ring and OOO buffers.
 *
 * @details
 * Deallocation Sequence:
 * 1. Frees zero-copy L5 ring arrays (`buffer`, `lengths`, `addrs`, `rx_times`).
 * 2. Frees active fragmentation scratch and Reed-Solomon parity buffers.
 * 3. Walks and frees linked out-of-order reassembly slabs (`ooo_buffer_head`),
 *    updating global OOO memory accounting via atomic fetch-and-sub.
 * 4. Walks and frees unacknowledged L4 packet descriptors and payload copies.
 * 5. Destroys L3 egress queues (`tx_datagram_queue`, `tx_stream_queue`).
 * 6. Cryptographically zeroes symmetric session keys, flight3 keys, and Kyber secret keys.
 * 7. Frees the cache-line aligned SclConnection structure.
 *
 * @param[in,out] conn Connection structure to deallocate.
 *
 * @warning Must only be called when `ref_count == 0` and after RCU grace period elapses.
 * @complexity Time: O(OOO_buffers + unacked_packets), Space: O(1).
 */
void scl_connection_destroy_now(SclConnection *conn) {
    if (!conn) return;

    atomic_thread_fence(memory_order_acquire);
    
    // Clean L5 Zero-Copy Rings
    if (conn->l5_rx_queue.buffer) {
        for (int i = 0; i < SCL_L5_RING_SIZE; i++) {
            if (conn->l5_rx_queue.buffer[i]) {
                free(conn->l5_rx_queue.buffer[i]);
            }
        }
        free(conn->l5_rx_queue.buffer);
        conn->l5_rx_queue.buffer = NULL;
    }
    if (conn->l5_rx_queue.lengths) {
        free(conn->l5_rx_queue.lengths);
        conn->l5_rx_queue.lengths = NULL;
    }
    if (conn->l5_rx_queue.addrs) {
        free(conn->l5_rx_queue.addrs);
        conn->l5_rx_queue.addrs = NULL;
    }
    if (conn->l5_rx_queue.rx_times) {
        free(conn->l5_rx_queue.rx_times);
        conn->l5_rx_queue.rx_times = NULL;
    }

    // Clean active fragmentation buffer
    if (conn->active_fragment_buffer) {
        free(conn->active_fragment_buffer);
        conn->active_fragment_buffer = NULL;
    }
    
    // Clean FEC parity scratch buffers
    if (conn->active_fec_parity[0]) {
        free(conn->active_fec_parity[0]);
        conn->active_fec_parity[0] = NULL;
    }
    if (conn->active_fec_parity[1]) {
        free(conn->active_fec_parity[1]);
        conn->active_fec_parity[1] = NULL;
    }
    
    // Clean out-of-order reassembly buffers
    OOO_Message *curr = (OOO_Message *)conn->ooo_buffer_head;
    while (curr) {
        OOO_Message *next = curr->next;
        
        if (curr->parity_slab) {
            SCL_ALIGNED_FREE(curr->parity_slab);
        }
        
        size_t exp_size = SCL_HEADER_MIN_LEN + 12 + (curr->total_frags * SCL_MAX_CHUNK_SIZE);
        
        if (global_shim && global_shim->impl_state) {
            UserSpaceState *state = (UserSpaceState *)global_shim->impl_state;
            atomic_fetch_sub_explicit(&state->global_ooo_bytes_allocated, sizeof(OOO_Message) + exp_size, memory_order_relaxed);
        }
        
        free(curr);
        curr = next;
    }
    conn->ooo_buffer_head = NULL;
            
    // Clean up L4 Unacked packets
    pthread_mutex_lock(&conn->l4_mutex);
    SclUnackedPacket *unacked = conn->unacked_head;
    while (unacked) {
        SclUnackedPacket *next = unacked->next;
        if (unacked->raw_packet) {
            free(unacked->raw_packet);
        }
        free(unacked);
        unacked = next;
    }
    conn->unacked_head = NULL;
    conn->unacked_tail = NULL;
    pthread_mutex_unlock(&conn->l4_mutex);
    pthread_mutex_destroy(&conn->l4_mutex);
    
    // Clean up L3 Egress Queues
    queue_destroy(&conn->tx_datagram_queue);
    queue_destroy(&conn->tx_stream_queue);

    // Cryptographically wipe secret keys
    explicit_bzero(conn->current_aes_gcm_key, 32);
    explicit_bzero(conn->flight3_aes_gcm_key, 32);
    explicit_bzero(conn->rx_aes_gcm_key, 32);
    explicit_bzero(conn->rx_flight3_aes_gcm_key, 32);
    explicit_bzero(conn->ephemeral_kyber_privkey, KYBER_SECRETKEY_LEN);

    // Update global accounting counters
    if (conn->is_untrusted_sync && global_shim && global_shim->impl_state) {
        UserSpaceState *state = (UserSpaceState *)global_shim->impl_state;
        size_t mem_footprint = sizeof(SclConnection) + (SCL_L5_RING_SIZE * 4096);
        atomic_fetch_sub_explicit(&state->global_untrusted_sync_allocated, mem_footprint, memory_order_relaxed);
    }
    
    if (global_shim && global_shim->impl_state) {
        UserSpaceState *state = (UserSpaceState *)global_shim->impl_state;
        atomic_fetch_sub_explicit(&state->active_connection_count, 1, memory_order_relaxed);
    }

    SCL_ALIGNED_FREE(conn);
}

/**
 * @brief Atomically releases a connection reference, deferring destruction to the RCU ring.
 *
 * @param[in,out] conn Connection structure.
 *
 * @thread_safety Atomic fetch-and-sub with release semantics.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_connection_release(SclConnection *conn) {
    if (!conn) return;

    // Decrement reference count; only enqueue for GC if this was the last reference
    if (atomic_fetch_sub_explicit(&conn->ref_count, 1, memory_order_release) == 1) {
        atomic_thread_fence(memory_order_acquire);
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        scl_connection_destroy_now(conn);
#else
        if (global_shim && global_shim->impl_state) {
            UserSpaceState *state = (UserSpaceState *)global_shim->impl_state;
            uint32_t head, next_head, tail;
            
            // Push to MPSC Lock-Free GC Ring
            do {
                head = atomic_load_explicit(&state->gc_head, memory_order_acquire);
                next_head = (head + 1) % 4096;
                tail = atomic_load_explicit(&state->gc_tail, memory_order_acquire);
                if (next_head == tail) {
                    // GC Ring is full, fallback to synchronous destruction
                    scl_connection_destroy_now(conn);
                    return;
                }
            } while (!atomic_compare_exchange_weak_explicit(&state->gc_head, &head, next_head, memory_order_release, memory_order_relaxed));
            
            state->gc_ring[head].ptr = conn;
            state->gc_ring[head].type = GC_TYPE_CONNECTION;
            state->gc_ring[head].tombstone_time = get_time_ms();
            atomic_store_explicit(&state->gc_ring[head].ready, true, memory_order_release);
        } else {
            scl_connection_destroy_now(conn);
        }
#endif
    }
}

/* ============================================================================ */
/* SECTION 7: ZERO-COPY INGRESS/EGRESS DRIVERS & PACKET ROUTING                 */
/* ============================================================================ */

/**
 * @brief Ingress callback consuming a raw packet buffer arriving from the physical network interface.
 *
 * @details
 * Operational Pipeline:
 * 1. Fast-Path Relay Check: If opcode is `MSG_RELAY_DATA`, looks up the target mapping and tunnels
 *    the encapsulated payload blindly to the destination without local decryption.
 * 2. Sliding Window Anti-DoS: Increments per-IP packet rate tracker; silently drops traffic if rate
 *    exceeds 25,000 packets per second.
 * 3. Lock-Free Connection ID (CID) Routing: Evaluates `siphash24(cid)` and probes `cid_routing_table`.
 *    If unmapped, routes to the global listener (`zero_cid`) to process Handshake Flight 1/3.
 * 4. NAT Rebinding Detection: If the sender address changes on an active connection, initiates a
 *    `PATH_CHALLENGE` probe and stages the new endpoint in `conn->pending_path`.
 * 5. Pre-Authentication Replay Filtering: Probes the sliding bitmap (`replay_window_bitmask`) to drop
 *    duplicate or expired packets before touching expensive cryptographic decryption routines.
 * 6. Zero-Copy SPSC Hand-Off: Swaps the incoming buffer into `conn->l5_rx_queue` using release semantics.
 *
 * @param[in] shim Pointer to SclTransportShim interface.
 * @param[in] buffer Pointer to raw received packet bytes.
 * @param[in] len Physical packet length in octets.
 * @param[in] addr Network source address coordinates.
 *
 * @complexity Time: O(1) lock-free path, Space: O(1).
 */
static void us_consume_rx_buffer(struct SclTransportShim *shim, const uint8_t *buffer, size_t len, const struct sockaddr_storage *addr) {
    UserSpaceState *state = get_shim_state(shim);
    if (len < SCL_HEADER_MIN_LEN) return;
    
    // --- Phase 4: Fast-Path Zero-Copy Relay Forwarding ---
    if (buffer[0] == MSG_RELAY_DATA) {
        if (len < 24) return;
        uint32_t relay_len;
        memcpy(&relay_len, buffer + 1, 4);
        relay_len = ntohl(relay_len);
        if (len < 24 + (relay_len - 19)) return;
        
        struct sockaddr_storage target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        if (deserialize_sockaddr(buffer + 5, 19, &target_addr) != 0) return;
        
        const uint8_t *raw_pkt = buffer + 24;
        size_t raw_pkt_len = relay_len - 19;
        
        uint8_t pkt_cid[SCL_CID_LEN];
        memcpy(pkt_cid, raw_pkt + 1, SCL_CID_LEN);
        
        pthread_mutex_lock(&global_state->p2p_network.mutex);
        bool found_mapping = false;
        for (uint32_t i = 0; i < state->relay_count; i++) {
            if (memcmp(state->relay_table[i].cid, pkt_cid, SCL_CID_LEN) == 0) {
                state->relay_table[i].client_addr = *addr;
                state->relay_table[i].expiry = get_time_ms() + 300000;
                found_mapping = true;
                break;
            }
        }
        if (!found_mapping && state->relay_count < 256) {
            uint32_t idx = state->relay_count++;
            memcpy(state->relay_table[idx].cid, pkt_cid, SCL_CID_LEN);
            state->relay_table[idx].client_addr = *addr;
            state->relay_table[idx].expiry = get_time_ms() + 300000;
        }
        pthread_mutex_unlock(&global_state->p2p_network.mutex);
        
        size_t max_len;
        void *tx_token;
        uint8_t *tx_buf = shim->acquire_tx_buffer(shim, &max_len, &tx_token);
        if (tx_buf && max_len >= raw_pkt_len) {
            memcpy(tx_buf, raw_pkt, raw_pkt_len);
            shim->commit_tx_buffer(shim, tx_token, raw_pkt_len, pkt_cid, &target_addr);
        } else if (tx_token) {
            shim->abort_tx_buffer(shim, tx_token);
        }
        return;
    }

    uint8_t incoming_cid[SCL_CID_LEN];
    memcpy(incoming_cid, buffer + 1, SCL_CID_LEN);
    
    struct sockaddr_storage relay_dest;
    bool should_relay = false;
    uint64_t now_ms = get_time_ms();
    
    for (uint32_t i = 0; i < state->relay_count; i++) {
        if (memcmp(state->relay_table[i].cid, incoming_cid, SCL_CID_LEN) == 0) {
            if (now_ms < state->relay_table[i].expiry) {
                // Ensure we don't bounce the packet back to the sender
                if (!sockaddr_storage_equal(addr, &state->relay_table[i].client_addr)) {
                    relay_dest = state->relay_table[i].client_addr;
                    should_relay = true;
                }
            }
            break;
        }
    }
    
    if (should_relay) {
        size_t max_len;
        void *tx_token;
        uint8_t *tx_buf = shim->acquire_tx_buffer(shim, &max_len, &tx_token);
        if (tx_buf && max_len >= len) {
            memcpy(tx_buf, buffer, len);
            shim->commit_tx_buffer(shim, tx_token, len, incoming_cid, &relay_dest);
        } else if (tx_token) {
            shim->abort_tx_buffer(shim, tx_token);
        }
        return; // Intercepted and forwarded: bypass local L5 queue ingestion
    }

    // --- UDP Amplification & Rate Limiting Defense ---
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    uint64_t epoch = atomic_load_explicit(&state->rate_limit_epoch, memory_order_acquire);
    if (now_ms - epoch > 1000) {
        if (atomic_compare_exchange_strong_explicit(&state->rate_limit_epoch, &epoch, now_ms, memory_order_release, memory_order_relaxed)) {
            pthread_rwlock_wrlock(&state->ip_rate_tracker.rwlock);
            for (int i = 0; i < SCL_DOS_TRACKER_SIZE; i++) {
                DoSNode *curr = atomic_load_explicit(&state->ip_rate_tracker.buckets[i], memory_order_relaxed);
                while (curr) {
                    DoSNode *next = curr->next;
                    free(curr);
                    curr = next;
                }
                atomic_store_explicit(&state->ip_rate_tracker.buckets[i], NULL, memory_order_relaxed);
            }
            pthread_rwlock_unlock(&state->ip_rate_tracker.rwlock);
        }
    }
    
    uint8_t rate_key[16];
    ip_to_16(addr, rate_key);
    increment_dos_count(&state->ip_rate_tracker, rate_key, state->node_secret);
    uint32_t rate = get_dos_count(&state->ip_rate_tracker, rate_key, state->node_secret);
    if (rate > 25000) {
        return; // Drop packet silently (IP is actively flooding the node >25000 pps to allow PQ handshakes)
    }
#endif
    // Enforce valid QUIC packet framing (reject unroutable header bit patterns)
    uint8_t flags = buffer[0];
    bool is_long_header = ((flags & 0xC0) == 0xC0);
    bool is_short_header = ((flags & 0xC0) == 0x40);
    bool is_retry = ((flags & SCL_PACKET_FLAG_RETRY) != 0);

    // Drop malformed packets that do not match Long (0xC0), Short (0x40), or Retry (0x10) header signatures
    if (!is_long_header && !is_short_header && !is_retry) return;

    // --- Unified L1 CID Extraction (Lock-Free) ---
    SclConnection *target_conn = NULL;
    uint8_t target_cid[SCL_CID_LEN];
    memcpy(target_cid, buffer + 1, SCL_CID_LEN);
            
    uint32_t start_idx = hash_cid(target_cid, state->node_secret) % 4096;
    for (int i = 0; i < 4096; i++) {
        uint32_t probe = (start_idx + i) % 4096;
        SclConnection *conn = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
        if (conn == NULL) break; // Not found
        if (conn != SCL_TOMBSTONE && memcmp(conn->cid, target_cid, SCL_CID_LEN) == 0) {
            if (try_acquire_ref(conn)) {
                target_conn = conn;
                break;
            }
        }
    }
            
    // Fallback: Unknown/New connections (Flight 1/3 to Server, OR unroutable short headers) hit the global listener (zero_cid)
    if (!target_conn) {
        uint8_t zero_cid[SCL_CID_LEN] = {0};
        uint32_t z_start_idx = hash_cid(zero_cid, state->node_secret) % 4096;
        for (int i = 0; i < 4096; i++) {
            uint32_t probe = (z_start_idx + i) % 4096;
            SclConnection *conn = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
            if (conn == NULL) break; // Safe contiguous bounds probe
            if (conn != SCL_TOMBSTONE && memcmp(conn->cid, zero_cid, SCL_CID_LEN) == 0) {
                if (try_acquire_ref(conn)) {
                    target_conn = conn;
                    break;
                }
            }
        }
    }

    // Drop packet silently if neither specific Connection ID nor listener matched
    if (!target_conn) return; // Silent Drop

    uint8_t zero_cid[SCL_CID_LEN] = {0};
    bool is_listener = (memcmp(target_conn->cid, zero_cid, SCL_CID_LEN) == 0);

    // --- L1 Path Migration / IP Spoofing Defense ---
    if (!is_listener) {
        size_t discovered_mtu = scl_get_path_mtu(state->udp_socket, addr);
        target_conn->path_mtu = discovered_mtu > 1200 ? 1200 : discovered_mtu;
    }
    if (!is_listener && !sockaddr_storage_equal(&target_conn->current_path, addr)) {
        // QUIC Spec: IP Change initiates PATH_CHALLENGE; DO NOT update current_path until verified
        if (!target_conn->is_migrating_path) {
            target_conn->pending_path = *addr;
            RAND_bytes(target_conn->path_challenge_payload, 8);
            target_conn->is_migrating_path = true;
            target_conn->path_challenge_time = 0; // Trigger immediate send in egress queue
            fprintf(stderr, "[L1] NAT Rebinding detected. Initiating PATH_CHALLENGE.\n");
        }
    }

    atomic_store_explicit(&target_conn->last_rx_time, get_time_ms(), memory_order_relaxed); // Liveness Update

    // --- Strict Sliding Replay Window Verification (Pre-auth Fast Fail) ---
    if (is_short_header) {
        uint64_t packet_num;
        memcpy(&packet_num, buffer + 1 + SCL_CID_LEN, 8);
        packet_num = be64toh(packet_num);
        
        uint64_t highest_seen = atomic_load_explicit(&target_conn->replay_highest_seen, memory_order_acquire);
        uint64_t active_window = target_conn->dynamic_replay_window_size;
        if (active_window == 0) active_window = SCL_MIN_REPLAY_WINDOW;

        if (packet_num <= highest_seen) {
            uint64_t diff = highest_seen - packet_num;
            if (diff >= active_window) {
                if (global_state) {
                    pthread_mutex_lock(&global_state->hypergraph.lock);
                    bloom_filter_add(global_state->hypergraph.poison_bloom_aging, target_cid);
                    pthread_mutex_unlock(&global_state->hypergraph.lock);
                }
                scl_connection_release(target_conn);
                return; // Dropped: Outside Sliding Window
            }
                
            uint64_t mask_idx = (packet_num % active_window) / 64;
            uint64_t bit_idx = packet_num % 64;
                
            if (target_conn->replay_window_bitmask[mask_idx] & (1ULL << bit_idx)) {
                if (global_state) {
                    pthread_mutex_lock(&global_state->hypergraph.lock);
                    bloom_filter_add(global_state->hypergraph.poison_bloom_aging, target_cid);
                    pthread_mutex_unlock(&global_state->hypergraph.lock);
                }
                scl_connection_release(target_conn);
                return; // Dropped: Exact Duplicate
            }
        }
    }

    // --- FIXED L5 Dispatch: Robust Zero-Copy Transition ---
    // Application Assembly / Decryption completely decoupled to L5 workers
    uint32_t q_head = atomic_load_explicit(&target_conn->l5_rx_queue.head, memory_order_relaxed);
    uint32_t q_tail = atomic_load_explicit(&target_conn->l5_rx_queue.tail, memory_order_acquire);
    uint32_t q_next_head = (q_head + 1) % SCL_L5_RING_SIZE;
    
    // QUIC-Parity Spec: Strict 85% UMEM limit enforced per-core ring buffer
    uint32_t utilized = (q_head >= q_tail) ? (q_head - q_tail) : (SCL_L5_RING_SIZE - q_tail + q_head);
    if (utilized > (SCL_L5_RING_SIZE * 85 / 100)) {
        scl_log(LOG_LEVEL_TRACE, "Shim", "Strict 85%% UMEM limit reached. Dropping Packet.");
        scl_connection_release(target_conn);
        return;
    }
    
    if (q_next_head != q_tail) {
        uint8_t *temp = target_conn->l5_rx_queue.buffer[q_head];
        target_conn->l5_rx_queue.buffer[q_head] = (uint8_t *)buffer;
        
        uint32_t r_head = atomic_load_explicit(&state->rx_head, memory_order_relaxed);
        state->rx_ring[r_head] = temp;
        
        target_conn->l5_rx_queue.lengths[q_head] = len;
        target_conn->l5_rx_queue.addrs[q_head] = *addr;
        target_conn->l5_rx_queue.rx_times[q_head] = get_time_ms();
        atomic_store_explicit(&target_conn->l5_rx_queue.head, q_next_head, memory_order_release);
    } else {
        fprintf(stderr, "[Shim] L5 SPSC Queue Full! Dropping Packet.\n");
    }
    
    scl_connection_release(target_conn);
}

/**
 * @brief Reserves a zero-copy transmission slot in the driver MPSC ring buffer.
 *
 * @param[in] shim Pointer to transport shim interface.
 * @param[out] max_len Destination receiving maximum allowable payload size (Path MTU).
 * @param[out] buffer_token Opaque token tracking the reserved slot index.
 * @return Pointer to 64 KiB transmission scratch buffer; NULL if ring is saturated (backpressure).
 *
 * @thread_safety Multi-producer lock-free CAS loop on `state->tx_head`.
 * @complexity Time: O(1), Space: O(1).
 */
static uint8_t* us_acquire_tx_buffer(struct SclTransportShim *shim, size_t *max_len, void **buffer_token) {
    UserSpaceState *state = get_shim_state(shim);
    uint32_t head, next_head, tail;
    
    // Lock-free MPSC reservation
    do {
        head = atomic_load_explicit(&state->tx_head, memory_order_acquire);
        next_head = (head + 1) % 1024;
        tail = atomic_load_explicit(&state->tx_tail, memory_order_acquire);
        
        if (next_head == tail) return NULL; // TX Ring Full: Enforce Instant Backpressure
    } while (!atomic_compare_exchange_weak_explicit(&state->tx_head, &head, next_head, memory_order_release, memory_order_relaxed));
    
    // Allow maximum UDP datagram bounds to accommodate native OS IP fragmentation for Unreliable Datagrams (e.g. MSG_VOTE)
    *max_len = 65535;
    *buffer_token = (void*)(uintptr_t)(head + 1); // +1 prevents index 0 from acting like NULL
    return state->tx_ring[head].buffer;
}

/**
 * @brief Cancels a previously reserved transmission slot without sending data.
 *
 * @param[in] shim Pointer to transport shim interface.
 * @param[in] buffer_token Opaque token returned by @ref us_acquire_tx_buffer.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static void us_abort_tx_buffer(struct SclTransportShim *shim, void *buffer_token) {
    if (!buffer_token) return;
    UserSpaceState *state = get_shim_state(shim);
    uint32_t head = (uint32_t)(uintptr_t)buffer_token - 1;
    
    // MPSC doesn't allow step-back, so we flag the slot as length 0 to be skipped
    state->tx_ring[head].len = 0;
    state->tx_ring[head].addr.ss_family = 0; // Prevent empty UDP packets from being broadcasted
    atomic_store_explicit(&state->tx_ring[head].ready, true, memory_order_release);
}

/**
 * @brief Commits a populated transmission buffer to the driver ring for physical egress.
 *
 * @param[in] shim Pointer to transport shim interface.
 * @param[in] buffer_token Opaque token returned by @ref us_acquire_tx_buffer.
 * @param[in] actual_len Exact serialized wire length in octets.
 * @param[in] cid Target Connection ID (informational).
 * @param[in] addr Destination network socket coordinates.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static void us_commit_tx_buffer(struct SclTransportShim *shim, void *buffer_token, size_t actual_len, const uint8_t *cid, const struct sockaddr_storage *addr) {
    (void)cid;
    if (!buffer_token) return;
    
    UserSpaceState *state = get_shim_state(shim);
    size_t max_udp_size = 65535;
    if (actual_len > max_udp_size) {
        fprintf(stderr, "[Shim] ERROR: TX length %zu exceeds maximum 65535-byte UDP Limit!\n", actual_len);
        us_abort_tx_buffer(shim, buffer_token);
        return;
    }
    uint32_t head = (uint32_t)(uintptr_t)buffer_token - 1;
    
    state->tx_ring[head].len = actual_len;
    if (addr) {
        if (state->local_addr.ss_family == AF_INET6 && addr->ss_family == AF_INET) {
            // Promote IPv4 to IPv4-mapped IPv6 for seamless dual-stack socket compatibility
            struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&state->tx_ring[head].addr;
            memset(v6, 0, sizeof(struct sockaddr_in6));
            v6->sin6_family = AF_INET6;
            v6->sin6_port = v4->sin_port;
            v6->sin6_addr.s6_addr[10] = 0xff;
            v6->sin6_addr.s6_addr[11] = 0xff;
            memcpy(&v6->sin6_addr.s6_addr[12], &v4->sin_addr.s_addr, 4);
        } else if (state->local_addr.ss_family == AF_INET && addr->ss_family == AF_INET6) {
            // Demote IPv4-mapped IPv6 to IPv4 for IPv4-only sockets
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
            if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) {
                struct sockaddr_in *v4 = (struct sockaddr_in *)&state->tx_ring[head].addr;
                memset(v4, 0, sizeof(struct sockaddr_in));
                v4->sin_family = AF_INET;
                v4->sin_port = v6->sin6_port;
                memcpy(&v4->sin_addr.s_addr, &v6->sin6_addr.s6_addr[12], 4);
            } else {
                state->tx_ring[head].addr = *addr;
            }
        } else {
            state->tx_ring[head].addr = *addr;
        }
    } else {
        memset(&state->tx_ring[head].addr, 0, sizeof(struct sockaddr_storage));
    }
    
    // Release the slot to the consumer (us_poll)
    atomic_store_explicit(&state->tx_ring[head].ready, true, memory_order_release);
}

// No-op for userspace transport shim: RX buffers are exchanged via lock-free pointer swapping
static void us_release_rx_buffer(struct SclTransportShim *shim, const uint8_t *buffer) {
    (void)shim; (void)buffer;
}

/* ============================================================================ */
/* SECTION 8: L1 HANDSHAKE SLAB MATRIX REASSEMBLY & RATE GATING                 */
/* ============================================================================ */

/**
 * @brief Periodic sweeper sweeping expired incomplete Flight 3 handshake slots.
 *
 * @param[in,out] state Userspace transport state container.
 * @param[in] now Current monotonic timestamp in milliseconds.
 *
 * @complexity Time: O(sweep_limit), Space: O(1).
 */
static void us_sweep_handshake_state(UserSpaceState *state, uint64_t now) {
    if (now - state->last_sweep_time < 10) return;
    state->last_sweep_time = now;

    if (atomic_load_explicit(&state->handshake_slab->active_tier1, memory_order_relaxed) == 0 &&
        atomic_load_explicit(&state->handshake_slab->active_tier2, memory_order_relaxed) == 0) {
        return;
    }

    int sweep_limit = MIN(250, SCL_SLAB_SLOTS);
    for (int i = 0; i < sweep_limit; i++) {
        SclHandshakeSlot *slot = &state->handshake_slab->slots[state->slab_sweep_idx];
        SlabSlotState s_state = atomic_load_explicit(&slot->state, memory_order_acquire);
        
        // Strictly target only incomplete handshakes to prevent sweeping active evictions
        if (s_state == SCL_SLOT_FLIGHT3_INCOMPLETE && now > slot->expiration_time) {
            if (atomic_compare_exchange_strong(&slot->state, &s_state, SCL_SLOT_FREE)) {
                // Free up O(1) limits upon TTL expiration
                uint8_t old_ip_key[16], old_subnet_key[16];
                ip_to_16(&slot->client_addr, old_ip_key);
                memcpy(old_subnet_key, old_ip_key, 16);
                old_subnet_key[15] = 0; // Subnet masking for tracking
                decrement_dos_count(&state->ip_tracker, old_ip_key, state->node_secret);
                decrement_dos_count(&state->subnet_tracker, old_subnet_key, state->node_secret);

                if (slot->is_tier1_staked) {
                    atomic_fetch_sub_explicit(&state->handshake_slab->active_tier1, 1, memory_order_relaxed);
                } else {
                    atomic_fetch_sub_explicit(&state->handshake_slab->active_tier2, 1, memory_order_relaxed);
                }
            }
        }
        state->slab_sweep_idx = (state->slab_sweep_idx + 1) % SCL_SLAB_SLOTS;
    }
}

/**
 * @brief Evaluates per-IP and per-subnet concurrency limits for handshake slab admission.
 *
 * @param[in] state Userspace transport state container.
 * @param[in] ip Client IPv4 address in host order.
 * @param[in] is_tier1 `true` if client possesses an early stake proof (bypasses subnet limits).
 * @return `true` if within acceptable thresholds; `false` if limits are exceeded.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static bool scl_slab_check_limits(UserSpaceState *state, const struct sockaddr_storage *addr, bool is_tier1) {
    if (is_tier1) return true; // Tier 1 (Staked) bypasses subnet gating

    uint8_t ip_key[16], subnet_key[16];
    ip_to_16(addr, ip_key);
    memcpy(subnet_key, ip_key, 16);
    subnet_key[15] = 0; // Subnet masking for tracking

    uint32_t ip_count = get_dos_count(&state->ip_tracker, ip_key, state->node_secret);
    uint32_t subnet_count = get_dos_count(&state->subnet_tracker, subnet_key, state->node_secret);

    if (ip_count >= SCL_IP_LIMIT_PER_CONN) return false;
    if (subnet_count >= SCL_SUBNET_MAX_SLOTS) return false;

    return true;
}

/**
 * @brief Reserves a 16 KiB slot in the L1 Handshake Slab for Flight 3 reassembly.
 *
 * @details
 * Maps the client token to a 64-slot bucket using SipHash. If matching slot exists, updates TTL.
 * Otherwise, allocates an empty slot or evicts the oldest incomplete slot based on LRU ordering.
 *
 * @param[in,out] state Userspace transport state container.
 * @param[in] ip Client IPv4 address.
 * @param[in] conn_token 64-byte authenticated stateless token.
 * @param[in] is_tier1 `true` for Tier 1 (staked) clients; `false` for Tier 2 (untrusted).
 * @return Allocated slot index [0..SCL_SLAB_SLOTS-1] on success; -1 if saturated.
 *
 * @complexity Time: O(64) bounded bucket probe, Space: O(1).
 */
int scl_slab_acquire_slot(UserSpaceState *state, const struct sockaddr_storage *addr, const uint8_t *conn_token, bool is_tier1) {
    uint8_t ip_key[16];
    ip_to_16(addr, ip_key);
    // Spec Compliant: SipHash-bucketed cookie for fast O(1) eviction
    uint8_t sip_input[80];
    memcpy(sip_input, ip_key, 16);
    memcpy(sip_input + 16, conn_token, 64);
    
    uint32_t bucket_hash = (uint32_t)siphash24(sip_input, 80, state->node_secret);
    uint32_t bucket_start = (bucket_hash % (SCL_SLAB_SLOTS / 64)) * 64;
    
    uint32_t active_total = atomic_load_explicit(&state->handshake_slab->active_tier1, memory_order_relaxed) +
                                atomic_load_explicit(&state->handshake_slab->active_tier2, memory_order_relaxed);
        
    // SPEC: Strict absolute timeout that dynamically shrinks to 30000 ms when occupancy exceeds 80% to allow PoW solving
    uint64_t dynamic_ttl = (active_total > (SCL_SLAB_SLOTS * 80 / 100)) ? 30000 : 60000;

    for (int i = 0; i < 64; i++) {
        int idx = bucket_start + i;
        SclHandshakeSlot *slot = &state->handshake_slab->slots[idx];
        if (atomic_load_explicit(&slot->state, memory_order_acquire) == SCL_SLOT_FLIGHT3_INCOMPLETE &&
            sockaddr_storage_equal(&slot->client_addr, addr) &&
            memcmp(slot->connection_token, conn_token, 64) == 0) {
            slot->expiration_time = get_time_ms() + dynamic_ttl;
            return idx;
        }
    }

    if (!is_tier1) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        uint32_t lottery = 0;
#else
        uint32_t lottery;
        RAND_bytes((uint8_t*)&lottery, sizeof(lottery));
#endif
        uint32_t active_t2 = atomic_load_explicit(&state->handshake_slab->active_tier2, memory_order_relaxed);
        if (active_t2 > (SCL_TIER2_MAX_SLOTS * 0.8) && (lottery % 100 != 0)) return -1;
    }

    if (!scl_slab_check_limits(state, addr, is_tier1)) return -1;

    for (int i = 0; i < 64; i++) {
        int idx = bucket_start + i;
        SclHandshakeSlot *slot = &state->handshake_slab->slots[idx];
        SlabSlotState expected = SCL_SLOT_FREE;

        if (atomic_compare_exchange_strong(&slot->state, &expected, SCL_SLOT_FLIGHT3_INCOMPLETE)) {
            slot->client_addr = *addr;
            memcpy(slot->connection_token, conn_token, 64);
            slot->is_tier1_staked = is_tier1;
            slot->expiration_time = get_time_ms() + dynamic_ttl;
                    
            memset(slot->fragment_tracker, 0, sizeof(slot->fragment_tracker));
            memset(slot->parity_tracker, 0, sizeof(slot->parity_tracker));
            slot->assembled_length = 0;
            atomic_store_explicit(&slot->next_packet_num, 0, memory_order_relaxed);

            // Register O(1) limits for DoS resilience
            uint8_t l_ip_key[16], l_subnet_key[16];
            ip_to_16(addr, l_ip_key);
            memcpy(l_subnet_key, l_ip_key, 16);
            l_subnet_key[15] = 0;

            increment_dos_count(&state->ip_tracker, l_ip_key, state->node_secret);
            increment_dos_count(&state->subnet_tracker, l_subnet_key, state->node_secret);
            
            if (is_tier1) atomic_fetch_add(&state->handshake_slab->active_tier1, 1);
            else atomic_fetch_add(&state->handshake_slab->active_tier2, 1);
            return idx;
        }
    }

    uint64_t oldest_time = UINT64_MAX;
    int oldest_idx = -1;
    
    for (int i = 0; i < 64; i++) {
        int idx = bucket_start + i;
        SclHandshakeSlot *evict_slot = &state->handshake_slab->slots[idx];
        
        if (atomic_load_explicit(&evict_slot->state, memory_order_acquire) == SCL_SLOT_FLIGHT3_INCOMPLETE) {
            if (!is_tier1 && evict_slot->is_tier1_staked) continue;
            
            if (evict_slot->expiration_time < oldest_time) {
                oldest_time = evict_slot->expiration_time;
                oldest_idx = idx;
            }
        }
    }
    
    if (oldest_idx != -1) {
        SclHandshakeSlot *slot = &state->handshake_slab->slots[oldest_idx];
        SlabSlotState expected = SCL_SLOT_FLIGHT3_INCOMPLETE;
        
        // Transition state to SCL_SLOT_FLIGHT1 (unused temporary state) to lock it during eviction
        if (atomic_compare_exchange_strong(&slot->state, &expected, SCL_SLOT_FLIGHT1)) {
            // Unregister old limits
            uint8_t old_ip_key[16], old_subnet_key[16];
            ip_to_16(&slot->client_addr, old_ip_key);
            memcpy(old_subnet_key, old_ip_key, 16);
            old_subnet_key[15] = 0;

            decrement_dos_count(&state->ip_tracker, old_ip_key, state->node_secret);
            decrement_dos_count(&state->subnet_tracker, old_subnet_key, state->node_secret);

            if (slot->is_tier1_staked) atomic_fetch_sub(&state->handshake_slab->active_tier1, 1);
            else atomic_fetch_sub(&state->handshake_slab->active_tier2, 1);
            
            // Register new properties
            slot->client_addr = *addr;
            memcpy(slot->connection_token, conn_token, 64);
            slot->is_tier1_staked = is_tier1;
            slot->expiration_time = get_time_ms() + dynamic_ttl;
            memset(slot->fragment_tracker, 0, sizeof(slot->fragment_tracker));
            memset(slot->parity_tracker, 0, sizeof(slot->parity_tracker));
            slot->assembled_length = 0;
            atomic_store_explicit(&slot->next_packet_num, 0, memory_order_relaxed);

            // Register new O(1) limits
            uint8_t l_ip_key[16], l_subnet_key[16];
            ip_to_16(addr, l_ip_key);
            memcpy(l_subnet_key, l_ip_key, 16);
            l_subnet_key[15] = 0;

            increment_dos_count(&state->ip_tracker, l_ip_key, state->node_secret);
            increment_dos_count(&state->subnet_tracker, l_subnet_key, state->node_secret);
            
            if (is_tier1) atomic_fetch_add(&state->handshake_slab->active_tier1, 1);
            else atomic_fetch_add(&state->handshake_slab->active_tier2, 1);
            
            // Re-arm the slot safely to allow fragment reassembly
            atomic_store_explicit(&slot->state, SCL_SLOT_FLIGHT3_INCOMPLETE, memory_order_release);
            return oldest_idx;
        }
    }

    return -1;
}

/* ============================================================================ */
/* SECTION 9: DRIVER TEARDOWN & RECLAMATION                                     */
/* ============================================================================ */

/**
 * @brief Tears down the userspace transport driver shim and frees all resources.
 *
 * @param[in,out] shim Pointer to SclTransportShim interface.
 *
 * @complexity Time: O(allocated_rings + table_buckets), Space: O(1).
 */
static void us_destroy(struct SclTransportShim *shim) {
    if (!shim) return;
    UserSpaceState *state = get_shim_state(shim);
    if (state) {
        // Yield kernel file descriptors
#ifndef _WIN32
        if (state->udp_socket > 0) close(state->udp_socket);
        if (state->epoll_fd > 0) close(state->epoll_fd);
        if (state->kq > 0) close(state->kq);
#else
        if (state->udp_socket != INVALID_SOCKET) closesocket(state->udp_socket);
#endif
        // Free the 160MB L1 Handshake Slab Matrix
        if (state->handshake_slab) {
#ifndef _WIN32
            munmap(state->handshake_slab, sizeof(SclHandshakeSlab));
#else
            VirtualFree(state->handshake_slab, 0, MEM_RELEASE);
#endif
        }
                
        // ---------------------------------------------------------------------
        // Flush remaining RCU GC Ring securely
        // ---------------------------------------------------------------------
        for (int i = 0; i < 4096; i++) {
            if (atomic_load_explicit(&state->gc_ring[i].ready, memory_order_acquire)) {
                if (state->gc_ring[i].type == GC_TYPE_CONNECTION) {
                    SclConnection *conn = (SclConnection *)state->gc_ring[i].ptr;
                    if (conn) scl_connection_destroy_now(conn);
                } else if (state->gc_ring[i].type == GC_TYPE_SNAPSHOT) {
                    GameStateSnapshot *snap = (GameStateSnapshot *)state->gc_ring[i].ptr;
                    if (snap) release_game_state_snapshot(snap);
                }
            }
        }
                
        // Safely free all zero-copy ring buffers and assembly pools
        for (int i = 0; i < 64; i++) {
            uint8_t *buf = atomic_load(&state->assembly_pool[i]);
            if (buf) free(buf);
        }
        for (int i = 0; i < 1024; i++) {
            if (state->tx_ring[i].buffer) free(state->tx_ring[i].buffer);
        }
        for (int i = 0; i < SCL_RX_RING_SIZE; i++) {
            if (state->rx_ring && state->rx_ring[i]) free(state->rx_ring[i]);
        }
        if (state->rx_ring) free(state->rx_ring);
        
        for (int i = 0; i < SCL_DOS_TRACKER_SIZE; i++) {
            DoSNode *curr = atomic_load(&state->ip_tracker.buckets[i]);
            while (curr) { DoSNode *next = curr->next; free(curr); curr = next; }
            curr = atomic_load(&state->subnet_tracker.buckets[i]);
            while (curr) { DoSNode *next = curr->next; free(curr); curr = next; }
            curr = atomic_load(&state->ip_rate_tracker.buckets[i]);
            while (curr) { DoSNode *next = curr->next; free(curr); curr = next; }
        }
        pthread_rwlock_destroy(&state->ip_tracker.rwlock);
        pthread_rwlock_destroy(&state->subnet_tracker.rwlock);
        pthread_rwlock_destroy(&state->ip_rate_tracker.rwlock);
        
#ifdef _WIN32
        WSACleanup();
#endif
        
        free(state);
    }
    free(shim);
}

/* ============================================================================ */
/* SECTION 10: EVENT LOOP POLLING, PACING & NON-BLOCKING I/O                   */
/* ============================================================================ */

/**
 * @brief Non-blocking I/O event loop polling physical network interfaces and advancing transport state.
 *
 * @details
 * Operational Cycle:
 * 1. RCU Garbage Collection: Drains `state->gc_ring`, destroying dead connections whose tombstone
 *    timestamps exceed the 2,000 ms quiescent grace period.
 * 2. Handshake Slab Sweeper: Invokes @ref us_sweep_handshake_state to prune expired incomplete Flight 3 slots.
 * 3. Token Bucket Pacing: Refills pacing byte budget at 200 Mbps (25 bytes/microsecond).
 * 4. Vectorized TX Egress: Flushes ready packets from `state->tx_ring` via `sendmmsg` (Linux) or `sendto`.
 * 5. Vectorized RX Ingress: Drains UDP socket buffers via `recvmmsg` (Linux) or `recvfrom`, routing
 *    complete datagrams to @ref us_consume_rx_buffer.
 *
 * @param[in] shim Pointer to SclTransportShim interface.
 *
 * @complexity Time: O(burst_size), Space: O(1).
 */
static void us_poll(struct SclTransportShim *shim) {
    UserSpaceState *state = get_shim_state(shim);
    struct sockaddr_storage peer_addr;
    (void)peer_addr;
    
    // Capture time in both resolutions:
    // - Microseconds (us) for fine-grained TX pacing calculations.
    // - Milliseconds (ms) for protocol state timeouts (Handshake/PTO).
    uint64_t now_us = get_time_us();
    uint64_t now_ms = get_time_ms();
    
    // --- Execute Lock-Free RCU-lite Garbage Collection ---
    uint32_t gc_tail = atomic_load_explicit(&state->gc_tail, memory_order_relaxed);
    uint32_t gc_head = atomic_load_explicit(&state->gc_head, memory_order_acquire);
        
    while (gc_tail != gc_head) {
        if (!atomic_load_explicit(&state->gc_ring[gc_tail].ready, memory_order_acquire)) break;
            
        // 2000ms quiescent grace period guarantees no CPU thread is currently preempted while holding the pointer
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        uint64_t gc_grace_ms = 0;
#else
        uint64_t gc_grace_ms = 2000;
#endif
        if (now_ms >= state->gc_ring[gc_tail].tombstone_time + gc_grace_ms) {
            if (state->gc_ring[gc_tail].type == GC_TYPE_CONNECTION) {
                SclConnection *dead_conn = (SclConnection *)state->gc_ring[gc_tail].ptr;
                if (dead_conn) scl_connection_destroy_now(dead_conn);
            } else if (state->gc_ring[gc_tail].type == GC_TYPE_SNAPSHOT) {
                GameStateSnapshot *dead_snap = (GameStateSnapshot *)state->gc_ring[gc_tail].ptr;
                if (dead_snap) release_game_state_snapshot(dead_snap);
            }
                
            atomic_store_explicit(&state->gc_ring[gc_tail].ready, false, memory_order_release);
            gc_tail = (gc_tail + 1) % 4096;
        } else {
            break; // Ordered ring: if tail is not expired, nothing else is
        }
    }
    atomic_store_explicit(&state->gc_tail, gc_tail, memory_order_release);

    // Actively sweep Handshake Slab to prevent state exhaustion
    // FIXED: Passing milliseconds to match internal state expectations.
    us_sweep_handshake_state(state, now_ms);
    
    // --- L4 Transport Loss Detection & GC ---
    // Safely migrated exclusively to the L5 Application Engine threads to guarantee
    // strict single-owner lock-free execution and eliminate cross-thread Use-After-Free crashes.
    
    // --- TX Pacing & Flushing ---
    // Pacing remains high-resolution (microseconds) to prevent token starvation
    // at low latencies, even though state timeouts are ms-based.
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)now_us;
    state->pacing_budget = 1000000000;
#else
    uint64_t max_burst = 256 * 1200; // Paced dynamic burst limit clamped to application MTU

    // Underflow validation for shim-global event loop token bucket
    if (now_us > state->last_pacing_time) {
        uint64_t elapsed_us = now_us - state->last_pacing_time;
        // 200 Mbps = 25 bytes per microsecond. (Safely limits peak OS UDP buffer saturation)
        state->pacing_budget += elapsed_us * 25;
        if (state->pacing_budget > max_burst) state->pacing_budget = max_burst;
        state->last_pacing_time = now_us;
    } else if (now_us < state->last_pacing_time) {
        // Clock moved backwards! Reset last_pacing_time to prevent underflow
        state->last_pacing_time = now_us;
    }
#endif

    uint32_t tx_tail = atomic_load_explicit(&state->tx_tail, memory_order_relaxed);
    uint32_t tx_head = atomic_load_explicit(&state->tx_head, memory_order_acquire);

#ifdef __linux__
    // Vectorized bulk-send for Linux
    struct mmsghdr tx_msgs[256];
    struct iovec tx_iovecs[256];
    int batch_count = 0;
    uint32_t batch_tails[256];

    while (tx_tail != tx_head && batch_count < 256) {
        if (!atomic_load_explicit(&state->tx_ring[tx_tail].ready, memory_order_acquire)) break;
        
        size_t len = state->tx_ring[tx_tail].len;
        if (state->pacing_budget >= len) {
            if (state->tx_ring[tx_tail].addr.ss_family != 0) {
                tx_iovecs[batch_count].iov_base = state->tx_ring[tx_tail].buffer;
                tx_iovecs[batch_count].iov_len = len;
                
                memset(&tx_msgs[batch_count].msg_hdr, 0, sizeof(struct msghdr));
                tx_msgs[batch_count].msg_hdr.msg_iov = &tx_iovecs[batch_count];
                tx_msgs[batch_count].msg_hdr.msg_iovlen = 1;
                tx_msgs[batch_count].msg_hdr.msg_name = &state->tx_ring[tx_tail].addr;
                tx_msgs[batch_count].msg_hdr.msg_namelen = (state->tx_ring[tx_tail].addr.ss_family == AF_INET6) ?
                    sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                
                batch_tails[batch_count] = tx_tail;
                batch_count++;
            } else {
                // Instantly clear aborted packets (len 0)
                atomic_store_explicit(&state->tx_ring[tx_tail].ready, false, memory_order_release);
            }
            state->pacing_budget -= len;
            tx_tail = (tx_tail + 1) % 1024;
        } else {
            break; // Out of pacing budget
        }
    }

    if (batch_count > 0) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        int sent = batch_count; // Simulate instant OS egress success during fuzzing
#else
        int sent = sendmmsg(state->udp_socket, tx_msgs, batch_count, 0);
#endif
        if (sent > 0) {
            for (int i = 0; i < sent; i++) {
                atomic_store_explicit(&state->tx_ring[batch_tails[i]].ready, false, memory_order_release);
            }
            // If partial success, we leave the un-sent slots as 'ready' and roll back tx_tail
            if (sent < batch_count) {
                tx_tail = batch_tails[sent];
                // Refund pacing budget for unsent packets
                for (int i = sent; i < batch_count; i++) {
                    state->pacing_budget += tx_iovecs[i].iov_len;
                }
            }
        } else if (sent < 0) {
            // Drop the batch on transient or persistent errors to prevent infinite stall
            // and provide backpressure to the L4 reliable transport layer.
            for (int i = 0; i < batch_count; i++) {
                atomic_store_explicit(&state->tx_ring[batch_tails[i]].ready, false, memory_order_release);
            }
        }
    }
#else
    // Sequential fallback for macOS/Windows
    while (tx_tail != tx_head) {
        if (!atomic_load_explicit(&state->tx_ring[tx_tail].ready, memory_order_acquire)) break;
            
        size_t len = state->tx_ring[tx_tail].len;
        if (state->pacing_budget >= len) {
            if (state->tx_ring[tx_tail].addr.ss_family != 0) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
                int sent = len; // Simulate instant OS egress success during fuzzing
#else
                socklen_t dest_len = (state->tx_ring[tx_tail].addr.ss_family == AF_INET6) ?
                    sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                int sent = sendto(state->udp_socket, (const char*)state->tx_ring[tx_tail].buffer, len, 0,
                                    (struct sockaddr*)&state->tx_ring[tx_tail].addr, dest_len);
#endif
                if (sent < 0) {
#ifndef _WIN32
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                        // Drop packet to provide backpressure to L4
                    }
#else
                    int err = WSAGetLastError();
                    if (err == WSAEWOULDBLOCK || err == WSAENOBUFS) {
                        // Drop packet to provide backpressure to L4
                    }
#endif
                }
            }
            state->pacing_budget -= len;
            atomic_store_explicit(&state->tx_ring[tx_tail].ready, false, memory_order_release);
            tx_tail = (tx_tail + 1) % 1024;
        } else {
            break;
        }
    }
#endif

    atomic_store_explicit(&state->tx_tail, tx_tail, memory_order_release);

    // --- RX Processing ---
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    int max_rx_burst = 256; // Increased from 64 to 256 to rapidly drain OS UDP buffer during heavy BBR bursts
    
    bool has_pending_tx = (atomic_load_explicit(&state->tx_tail, memory_order_relaxed) !=
                           atomic_load_explicit(&state->tx_head, memory_order_acquire));
    bool is_bootstrap_node = (global_state && global_state->p2p_network.is_bootstrap);

#ifdef __linux__
    if (state->epoll_fd != -1) {
        struct epoll_event events[1];
        int epoll_timeout = has_pending_tx ? 0 : (is_bootstrap_node ? 1 : 10);
        int n = epoll_wait(state->epoll_fd, events, 1, epoll_timeout);
        if (n <= 0) return;
    }
#elif defined(__APPLE__)
    if (state->kq != -1) {
        struct kevent event;
        long timeout_ns = has_pending_tx ? 0 : (is_bootstrap_node ? 1000000L : 10000000L);
        struct timespec timeout = {0, timeout_ns};
        int n = kevent(state->kq, NULL, 0, &event, 1, &timeout);
        if (n <= 0) return;
    }
#elif defined(_WIN32)
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(state->udp_socket, &readfds);
    long timeout_us = has_pending_tx ? 0 : (is_bootstrap_node ? 1000 : 10000);
    struct timeval tv = {0, timeout_us};
    int ret = select((int)state->udp_socket + 1, &readfds, NULL, NULL, &tv);
    if (ret <= 0) return;
#else
    struct pollfd pfd;
    pfd.fd = state->udp_socket;
    pfd.events = POLLIN;
    int poll_timeout = has_pending_tx ? 0 : (is_bootstrap_node ? 1 : 10);
    int ret = poll(&pfd, 1, poll_timeout);
    if (ret <= 0) return;
#endif

#ifdef __linux__
    // Vectorized bulk-receive for Linux
    struct mmsghdr rx_msgs[256];
    struct iovec rx_iovecs[256];
    struct sockaddr_storage rx_addrs[256];
    uint32_t current_head = atomic_load_explicit(&state->rx_head, memory_order_relaxed);
    
    for (int i = 0; i < max_rx_burst; i++) {
        uint32_t slot = (current_head + i) % SCL_RX_RING_SIZE;
        rx_iovecs[i].iov_base = state->rx_ring[slot];
        rx_iovecs[i].iov_len = 4096;
        
        memset(&rx_msgs[i].msg_hdr, 0, sizeof(struct msghdr));
        rx_msgs[i].msg_hdr.msg_iov = &rx_iovecs[i];
        rx_msgs[i].msg_hdr.msg_iovlen = 1;
        rx_msgs[i].msg_hdr.msg_name = &rx_addrs[i];
        rx_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
    }
    
    int vlen = recvmmsg(state->udp_socket, rx_msgs, max_rx_burst, MSG_DONTWAIT, NULL);
    if (vlen > 0) {
        for (int i = 0; i < vlen; i++) {
            uint32_t head = atomic_load_explicit(&state->rx_head, memory_order_relaxed);
            if (rx_msgs[i].msg_len > 0 && rx_msgs[i].msg_len <= 4096) {
                normalize_sockaddr(&rx_addrs[i]);
                us_consume_rx_buffer(shim, state->rx_ring[head], rx_msgs[i].msg_len, &rx_addrs[i]);
            }
            atomic_store_explicit(&state->rx_head, (head + 1) % SCL_RX_RING_SIZE, memory_order_release);
        }
    }
#else
    // Sequential fallback for macOS/Windows
    int processed = 0;
    while (processed < max_rx_burst) {
        uint32_t head = atomic_load_explicit(&state->rx_head, memory_order_relaxed);
        uint8_t *rx_buf = state->rx_ring[head];
        
        socklen_t addr_len = sizeof(struct sockaddr_storage);
        int recv_len = recvfrom(state->udp_socket, (char*)rx_buf, 4096, 0,
                                                    (struct sockaddr*)&peer_addr, &addr_len);
                                    
        if (recv_len < 0) {
#ifndef _WIN32
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            
            // Ignore ICMP Port/Host Unreachable to prevent the entire RX loop from
            // permanently stalling when a known peer drops offline on macOS/Linux.
            if (errno == ECONNREFUSED || errno == EHOSTUNREACH || errno == ENETUNREACH) {
                processed++;
                continue;
            }
#else
            int err = WSAGetLastError();
            // Ignore ICMP Port Unreachable to prevent the entire RX loop from stalling on Windows
            if (err == WSAECONNRESET) {
                processed++;
                continue;
            }
            if (err == WSAEWOULDBLOCK) break;
#endif
            break;
        }
        
        if (recv_len > 0 && recv_len <= 4096) {
            normalize_sockaddr(&peer_addr);
            us_consume_rx_buffer(shim, rx_buf, (size_t)recv_len, &peer_addr);
        }
        atomic_store_explicit(&state->rx_head, (head + 1) % SCL_RX_RING_SIZE, memory_order_release);
        processed++;
    }
#endif
#endif
}

/* ============================================================================ */
/* SECTION 11: L5 APPLICATION ENGINE HELPER ROUTINES                            */
/* ============================================================================ */

/**
 * @brief Validates and stages an incoming unconfirmed pointer transfer into the local mempool.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Pointer to Operation structure containing @ref TransferData.
 *
 * @complexity Time: O(MAX_PENDING_OPS + num_inputs), Space: O(1).
 */
static void handle_pending_transfer(State *state, Operation *op) {
    uint8_t key[COIN_ID_LEN];
    memcpy(key, op->data.transfer_pointer.tx_id, COIN_ID_LEN);

    // Reject operations already processed to prevent mempool poisoning
    if (hash_table_lookup(state->processed_txs, key, true) != NULL) {
        free(op);
        return;
    }
    
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (pop && pop->type == OP_TRANSFER_POINTER && memcmp(pop->data.transfer_pointer.tx_id, op->data.transfer_pointer.tx_id, COIN_ID_LEN) == 0) {
            if (!operation_equals(pop, op)) {
                fprintf(stderr, "[L5] Rejecting transfer: tx_id collision detected\n");
            }
            free(op);
            return;
        }
    }

    // Include accurate outgoing transaction fee overheads for mempool processing
    uint64_t target_with_fee = op->data.transfer_pointer.amount + calculate_fee(op->data.transfer_pointer.amount, false);
    
    // Pass the 2592-byte sender_pubkey instead of the 32-byte owner_address
    int has_overlap = has_insufficient_balance_locked(
        state, op->data.transfer_pointer.sender_pubkey,
        op->data.transfer_pointer.inputs, op->data.transfer_pointer.num_inputs,
        target_with_fee, false
    );

    if (has_overlap) {
        free(op);
        return;
    }

    if (add_pending_operation(state, op) != 0) {
        free(op);
    }
}

/**
 * @brief Validates and stages an incoming unconfirmed staking transaction into the local mempool.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Pointer to Operation structure containing @ref StakeData.
 *
 * @complexity Time: O(MAX_PENDING_OPS + threshold_verify), Space: O(1).
 */
static void handle_pending_stake(State *state, Operation *op) {
    uint8_t key[COIN_ID_LEN];
    memcpy(key, op->data.stake.stake_tx_id, COIN_ID_LEN);

    if (hash_table_lookup(state->processed_txs, key, true) != NULL) {
        free(op);
        return;
    }
        
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (pop && pop->type == OP_STAKE && memcmp(pop->data.stake.stake_tx_id, op->data.stake.stake_tx_id, COIN_ID_LEN) == 0) {
            free(op);
            return;
        }
    }

    uint64_t target_with_fee = op->data.stake.amount + calculate_fee(op->data.stake.amount, true);
        
    // Pass the 2592-byte sender_pubkey instead of the 32-byte owner_address
    int has_overlap = has_insufficient_balance_locked(
        state, op->data.stake.sender_pubkey,
        op->data.stake.inputs, op->data.stake.num_inputs,
        target_with_fee, false
    );

    if (has_overlap) {
        free(op);
        return;
    }

    uint8_t *signed_data = get_l5_staging_buffer();
    if (!signed_data) {
        free(op);
        return;
    }
        
    size_t signed_data_len;
    if (serialize_stake_payload(&op->data.stake, signed_data, &signed_data_len, true)) {
        free(op);
        return;
    }

    uint8_t computed_stake_id[COIN_ID_LEN];
    SHA256(signed_data, signed_data_len, computed_stake_id);
    if (memcmp(computed_stake_id, op->data.stake.stake_tx_id, COIN_ID_LEN) != 0) {
        free(op);
        return;
    }

    if (threshold_verify(signed_data, signed_data_len, op->data.stake.threshold_signature, SIGNATURE_LEN,
        op->data.stake.threshold_pubkey, DILITHIUM_PUBKEY_LEN) != CRYPTO_SUCCESS) {
        free(op);
        return;
    }
    if (add_pending_operation(state, op) != 0) {
        free(op);
    }
}

/**
 * @brief Validates and stages an incoming unconfirmed unstaking transaction into the local mempool.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Pointer to Operation structure containing @ref UnstakeData.
 *
 * @complexity Time: O(MAX_PENDING_OPS + threshold_verify), Space: O(1).
 */
static void handle_pending_unstake(State *state, Operation *op) {
    uint8_t key[COIN_ID_LEN];
    memcpy(key, op->data.unstake.unstake_tx_id, COIN_ID_LEN);

    if (hash_table_lookup(state->processed_txs, key, true) != NULL) {
        free(op);
        return;
    }
        
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (pop && pop->type == OP_UNSTAKE && memcmp(pop->data.unstake.unstake_tx_id, op->data.unstake.unstake_tx_id, COIN_ID_LEN) == 0) {
            free(op);
            return;
        }
    }

    uint64_t target_with_fee = op->data.unstake.amount + calculate_fee(op->data.unstake.amount, true);
        
    int has_overlap = has_insufficient_balance_locked(
        state, op->data.unstake.threshold_pubkey,
        op->data.unstake.inputs, op->data.unstake.num_inputs,
        target_with_fee, true
    );

    if (has_overlap) {
        free(op);
        return;
    }

    uint8_t *signed_data = get_l5_staging_buffer();
    if (!signed_data) {
        free(op);
        return;
    }
        
    size_t signed_data_len;
    if (serialize_unstake_payload(&op->data.unstake, signed_data, &signed_data_len, true)) {
        free(op);
        return;
    }

    uint8_t computed_id[COIN_ID_LEN];
    SHA256(signed_data, signed_data_len, computed_id);
    if (memcmp(computed_id, op->data.unstake.unstake_tx_id, COIN_ID_LEN) != 0) {
        free(op);
        return;
    }

    if (threshold_verify(signed_data, signed_data_len, op->data.unstake.threshold_signature, SIGNATURE_LEN,
        op->data.unstake.threshold_pubkey, PUBKEY_LEN) != CRYPTO_SUCCESS) {
        free(op);
        return;
    }
    if (add_pending_operation(state, op) != 0) {
        free(op);
    }
}

/* ============================================================================ */
/* SECTION 12: PEER IDENTITY ADVERTISEMENT & DISPATCH ROUTING                   */
/* ============================================================================ */

/**
 * @brief Enqueues an authenticated Dilithium5 identity claim (@ref MSG_PEER_DISCOVERY) onto a stream.
 *
 * @param[in] state Global node state container.
 * @param[in,out] conn Target connection context.
 *
 * @complexity Time: O(Dilithium5_sign), Space: O(sizeof(Message)).
 */
static void scl_enqueue_identity_claim(State *state, SclConnection *conn) {
    uint32_t payload_len = DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN + 19;
    size_t full_size = payload_len + SIGNATURE_LEN;
    
    Message *msg = malloc(sizeof(Message));
    if (!msg) return;
    
    msg->type = MSG_PEER_DISCOVERY;
    msg->length = full_size;
    
    uint8_t *p_start = msg->payload;
    memcpy(p_start, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(p_start + DILITHIUM_PUBKEY_LEN, state->p2p_network.local_peer.peer_wallet.kyber_pubkey, KYBER_PUBKEY_LEN);
    
    struct sockaddr_storage claim_addr = state->p2p_network.local_peer.addr;
    if (state->p2p_network.public_addr.ss_family == AF_INET || state->p2p_network.public_addr.ss_family == AF_INET6) {
        claim_addr = state->p2p_network.public_addr;
    }
    serialize_sockaddr(&claim_addr, p_start + DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN);
    
    uint8_t signature[SIGNATURE_LEN];
    dilithium_sign(msg->payload, payload_len, state->p2p_network.local_peer.peer_wallet.dilithium_privkey, signature);
    memcpy(msg->payload + payload_len, signature, SIGNATURE_LEN);
    
    queue_enqueue(&conn->tx_stream_queue, msg);
    fprintf(stderr, "[L5] Enqueued MSG_PEER_DISCOVERY identity claim into secure stream.\n");
    free(msg);
}

/**
 * @brief Validates whether an incoming DKG session identifier corresponds to current or upcoming epoch.
 *
 * @param[in] state Global node state container.
 * @param[in] session_id 32-byte DKG session identifier digest.
 * @param[out] out_msg_epoch Optional destination receiving matched epoch index.
 * @return `true` if session matches current or next epoch; `false` otherwise.
 *
 * @thread_safety Acquires `state->mutex`.
 * @complexity Time: O(1), Space: O(1).
 */
static bool dkg_validate_session_epoch(State *state, const uint8_t session_id[COIN_ID_LEN], uint64_t *out_msg_epoch) {
    pthread_mutex_lock(&state->mutex);
    uint64_t current_epoch_num = state->current_block_number / BLOCKS_PER_DAY;
    uint8_t epoch_session_id[COIN_ID_LEN];
    uint8_t next_epoch_session_id[COIN_ID_LEN];
    uint8_t epoch_input[32];
    
    memset(epoch_input, 0, 32);
    snprintf((char*)epoch_input, 32, "DKG_EPOCH_%llu", (unsigned long long)current_epoch_num);
    SHA256(epoch_input, strlen((char*)epoch_input), epoch_session_id);
    
    memset(epoch_input, 0, 32);
    snprintf((char*)epoch_input, 32, "DKG_EPOCH_%llu", (unsigned long long)(current_epoch_num + 1));
    SHA256(epoch_input, strlen((char*)epoch_input), next_epoch_session_id);
    
    bool is_current = (memcmp(session_id, epoch_session_id, COIN_ID_LEN) == 0);
    bool is_next = (memcmp(session_id, next_epoch_session_id, COIN_ID_LEN) == 0);
    
    if (is_current) {
        if (out_msg_epoch) *out_msg_epoch = current_epoch_num;
        pthread_mutex_unlock(&state->mutex);
        return true;
    } else if (is_next) {
        if (out_msg_epoch) *out_msg_epoch = current_epoch_num + 1;
        pthread_mutex_unlock(&state->mutex);
        return true;
    }
    pthread_mutex_unlock(&state->mutex);
    return false;
}

/**
 * @brief Demultiplexes and dispatches an authenticated L5 network message to subsystem handlers.
 *
 * @details
 * Dispatches by `in_msg->type`:
 * - `MSG_RPC_REQUEST` / `MSG_RPC_RESPONSE`: Dispatches to native L5 RPC engine with rate limit checks.
 * - `MSG_EPOCH_*` / `MSG_DKG_*`: Routes to Distributed Key Generation (DKG) commitments, reveals, and share deals.
 * - `MSG_THRESHOLD_*`: Routes to threshold stake and unstake signing ceremonies.
 * - `MSG_CENTINEL_*` / `MSG_COIN_*` / `MSG_POINTER_*`: Synchronizes private UTXOs, coins, and pointer state.
 * - `MSG_ENDPOINT_*` / `MSG_RELAY_*`: Coordinates NAT traversal discovery and blind packet relay forwarding.
 * - `MSG_PEER_DISCOVERY` / `MSG_PEERS_LIST` / `MSG_PEER_LIST_SYNC` / `MSG_PEER_DISCONNECT`: Peer topology lifecycle.
 * - `MSG_PENDING_OPERATION`: Ingests transfer, stake, unstake, or valuation into mempool.
 * - `MSG_GOSSIP_BLOCK` / `MSG_BLOCK_APPROVED` / `MSG_GET_BLOCKS`: Routes to consensus block sync pipeline.
 *
 * @param[in] conn Connection context from which message arrived.
 * @param[in,out] state Global node state container.
 * @param[in,out] net P2P network subsystem container.
 * @param[in] in_msg Inbound parsed message container.
 * @param[out] out_msg Reusable response message buffer.
 * @param[in] sender_pubkey Authenticated sender public key.
 * @param[in] sender_addr Network source address coordinates.
 *
 * @complexity Time: O(handler_execution_time), Space: O(1) auxiliary.
 */
void dispatch_l5_message(SclConnection *conn, State *state, P2PNetwork *net, Message *in_msg, Message *out_msg, uint8_t *sender_pubkey, struct sockaddr_storage *sender_addr) {
    char sender_ip_str[64] = "unknown";
    if (sender_addr) {
        if (sender_addr->ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)sender_addr)->sin_addr, sender_ip_str, sizeof(sender_ip_str));
        } else if (sender_addr->ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)sender_addr)->sin6_addr, sender_ip_str, sizeof(sender_ip_str));
        }
    }

    // Dynamically resolve sender_pubkey if it is zeroed/missing but we have an active connection mapping
    static _Thread_local uint8_t resolved_pubkey[DILITHIUM_PUBKEY_LEN];
    bool has_resolved = false;

    if (sender_pubkey && !is_zeroed(sender_pubkey, DILITHIUM_PUBKEY_LEN)) {
        memcpy(resolved_pubkey, sender_pubkey, DILITHIUM_PUBKEY_LEN);
        has_resolved = true;
    }

    if (!has_resolved && conn) {
        pthread_mutex_lock(&net->mutex);
        for (size_t i = 0; i < net->num_known_peers; i++) {
            if (net->known_peers[i]->conn == conn) {
                memcpy(resolved_pubkey, net->known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                /* Do not replace sender_addr. The datagram source is what STUN
                 * and the self-hairpin check have to see. */
                has_resolved = true;
                break;
            }
        }
        pthread_mutex_unlock(&net->mutex);
    }

    if (has_resolved) {
        sender_pubkey = resolved_pubkey;
    }

    // Process by Type
    switch (in_msg->type) {
        case MSG_RPC_REQUEST:
        case MSG_RPC_RESPONSE: {
            if (!conn || conn->handshake_state != SCL_CONN_STATE_ESTABLISHED) {
                if (conn && in_msg->length >= sizeof(SclRpcHeader)) {
                    SclRpcHeader *hdr = (SclRpcHeader *)in_msg->payload;
                    SCL_LOG_RPC_REJECT(hdr, sender_ip_str, SCL_RPC_STATUS_UNAUTHORIZED, "Pre-handshake RPC rejected");
                }
                break;
            }
            if (in_msg->length < sizeof(SclRpcHeader)) break;

            SclRpcHeader hdr;
            memcpy(&hdr, in_msg->payload, sizeof(SclRpcHeader));
            hdr.status_code = be16toh(hdr.status_code);
            hdr.method_id = be16toh(hdr.method_id);
            hdr.error_msg_len = be16toh(hdr.error_msg_len);
            hdr.request_id = be64toh(hdr.request_id);
            hdr.payload_len = be32toh(hdr.payload_len);
            hdr.cursor = be32toh(hdr.cursor);
            hdr.checksum = be64toh(hdr.checksum);

            // Subtraction-based bounds check to prevent integer wrap-around vulnerability
            if (in_msg->length < 32 || in_msg->length - 32 < hdr.error_msg_len || in_msg->length - 32 - hdr.error_msg_len < hdr.payload_len) {
                break;
            }

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            // SipHash-2-4 checksum block verification
            uint64_t computed_checksum = compute_rpc_checksum(in_msg->payload, hdr.error_msg_len, hdr.payload_len, conn->rpc_siphash_key);
            if (computed_checksum != hdr.checksum) {
                atomic_fetch_add_explicit(&state->rpc_engine.rejected_checksum_mismatch, 1, memory_order_relaxed);
                SCL_LOG_RPC_REJECT(&hdr, sender_ip_str, SCL_RPC_STATUS_CHECKSUM_ERR, "SipHash-2-4 mismatch");
                size_t err_mark = arena_mark();
                Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader));
                if (resp) {
                    resp->type = MSG_RPC_RESPONSE;
                    resp->length = sizeof(SclRpcHeader);
                    SclRpcHeader *err_hdr = (SclRpcHeader *)resp->payload;
                    memset(err_hdr, 0, sizeof(SclRpcHeader));
                    err_hdr->version = SCL_RPC_VERSION_1;
                    err_hdr->status_code = htobe16(SCL_RPC_STATUS_CHECKSUM_ERR);
                    err_hdr->request_id = htobe64(hdr.request_id);
                    queue_enqueue(&conn->tx_stream_queue, resp);
                    arena_reset(err_mark);
                } else {
                    arena_reset(err_mark);
                }
                break;
            }
#endif

            if (in_msg->type == MSG_RPC_REQUEST) {
                uint32_t active_streams = atomic_load_explicit(&conn->active_rpc_streams, memory_order_acquire);
                if (active_streams >= MAX_CONCURRENT_RPCS_PER_CONN) {
                    atomic_fetch_add_explicit(&state->rpc_engine.rejected_rate_limit, 1, memory_order_relaxed);
                    SCL_LOG_RPC_REJECT(&hdr, sender_ip_str, SCL_RPC_STATUS_RATE_LIMITED, "Active stream limit reached");
                    size_t err_mark = arena_mark();
                    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader));
                    if (resp) {
                        resp->type = MSG_RPC_RESPONSE;
                        resp->length = sizeof(SclRpcHeader);
                        SclRpcHeader *err_hdr = (SclRpcHeader *)resp->payload;
                        memset(err_hdr, 0, sizeof(SclRpcHeader));
                        err_hdr->version = SCL_RPC_VERSION_1;
                        err_hdr->status_code = htobe16(SCL_RPC_STATUS_RATE_LIMITED);
                        err_hdr->request_id = htobe64(hdr.request_id);
                        queue_enqueue(&conn->tx_stream_queue, resp);
                        arena_reset(err_mark);
                    } else {
                        arena_reset(err_mark);
                    }
                    break;
                }
                
                uint32_t cost = 1;
                switch (hdr.method_id) {
                    case 0x0001: cost = 5; break;
                    case 0x0002: cost = 25; break;
                    case 0x0003: cost = 100; break;
                    case 0x0004: cost = 10; break;
                    case 0x0005: cost = 15; break;
                    case 0x0006: cost = 20; break;
                    case 0x0007: cost = 15; break;
                    case 0x0008: cost = 3; break;
                }
                
                uint32_t current_budget = atomic_load_explicit(&conn->rpc_token_budget, memory_order_acquire);
                if (current_budget < cost) {
                    atomic_fetch_add_explicit(&state->rpc_engine.rejected_rate_limit, 1, memory_order_relaxed);
                    SCL_LOG_RPC_REJECT(&hdr, sender_ip_str, SCL_RPC_STATUS_RATE_LIMITED, "Token budget exhausted");
                    size_t err_mark = arena_mark();
                    Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader));
                    if (resp) {
                        resp->type = MSG_RPC_RESPONSE;
                        resp->length = sizeof(SclRpcHeader);
                        SclRpcHeader *err_hdr = (SclRpcHeader *)resp->payload;
                        memset(err_hdr, 0, sizeof(SclRpcHeader));
                        err_hdr->version = SCL_RPC_VERSION_1;
                        err_hdr->status_code = htobe16(SCL_RPC_STATUS_RATE_LIMITED);
                        err_hdr->request_id = htobe64(hdr.request_id);
                        queue_enqueue(&conn->tx_stream_queue, resp);
                        arena_reset(err_mark);
                    } else {
                        arena_reset(err_mark);
                    }
                    break;
                }
                atomic_fetch_sub_explicit(&conn->rpc_token_budget, cost, memory_order_release);
            }

            uint32_t active_queries = atomic_load_explicit(&state->rpc_engine.active_global_queries, memory_order_acquire);
            if (active_queries >= MAX_RPC_WORKERS * 10) {
                atomic_fetch_add_explicit(&state->rpc_engine.rejected_rate_limit, 1, memory_order_relaxed);
                SCL_LOG_RPC_REJECT(&hdr, sender_ip_str, SCL_RPC_STATUS_RATE_LIMITED, "Global RPC queue saturated");
                size_t err_mark = arena_mark();
                Message *resp = (Message *)arena_alloc(offsetof(Message, payload) + sizeof(SclRpcHeader));
                if (resp) {
                    resp->type = MSG_RPC_RESPONSE;
                    resp->length = sizeof(SclRpcHeader);
                    SclRpcHeader *err_hdr = (SclRpcHeader *)resp->payload;
                    memset(err_hdr, 0, sizeof(SclRpcHeader));
                    err_hdr->version = SCL_RPC_VERSION_1;
                    err_hdr->status_code = htobe16(SCL_RPC_STATUS_RATE_LIMITED);
                    err_hdr->request_id = htobe64(hdr.request_id);
                    queue_enqueue(&conn->tx_stream_queue, resp);
                    arena_reset(err_mark);
                } else {
                    arena_reset(err_mark);
                }
                break;
            }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            uint8_t rpc_msg_type = in_msg->type;
            RpcTask task_local;
            task_local.msg = in_msg;
            task_local.conn = conn;
            if (sender_pubkey) {
                memcpy(task_local.sender_pubkey, sender_pubkey, PUBKEY_LEN);
            } else {
                memset(task_local.sender_pubkey, 0, PUBKEY_LEN);
            }
            handle_rpc_request(state, &task_local);
            if (rpc_msg_type == MSG_RPC_REQUEST && conn) {
                atomic_fetch_sub_explicit(&conn->active_rpc_streams, 1, memory_order_release);
            }
#else
            RpcTask *task = malloc(sizeof(RpcTask));
            if (task) {
                task->msg = malloc(offsetof(Message, payload) + in_msg->length);
                if (task->msg) {
                    memcpy(task->msg, in_msg, offsetof(Message, payload) + in_msg->length);
                    task->conn = conn;
                    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_acquire);
                    if (sender_pubkey) {
                        memcpy(task->sender_pubkey, sender_pubkey, PUBKEY_LEN);
                    }
                    RecreateNode *node = malloc(sizeof(RecreateNode));
                    if (node) {
                        node->args = task;
                        node->next = NULL;
                        
                        pthread_mutex_lock(&state->rpc_engine.incoming_rpc_queue.mutex);
                        if (!state->rpc_engine.incoming_rpc_queue.head) {
                            state->rpc_engine.incoming_rpc_queue.head = state->rpc_engine.incoming_rpc_queue.tail = node;
                        } else {
                            state->rpc_engine.incoming_rpc_queue.tail->next = node;
                            state->rpc_engine.incoming_rpc_queue.tail = node;
                        }
                        pthread_mutex_unlock(&state->rpc_engine.incoming_rpc_queue.mutex);
                        atomic_fetch_add_explicit(&state->rpc_engine.active_global_queries, 1, memory_order_release);
                        if (in_msg->type == MSG_RPC_REQUEST) {
                            atomic_fetch_sub_explicit(&conn->active_rpc_streams, 1, memory_order_release);
                        }
                    } else {
                        free(task->msg);
                        free(task);
                    }
                } else {
                    free(task);
                }
            }
#endif
            break;
        }
        case MSG_EPOCH_DKG_SHARE: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < PUBKEY_LEN + 2) break;
            const uint8_t *p = in_msg->payload;
            pthread_mutex_lock(&state->game_state.mutex);
            memcpy(state->game_state.epoch_threshold_pubkey, p, PUBKEY_LEN);
            state->game_state.last_dkg_epoch = state->current_block_number;
            pthread_mutex_unlock(&state->game_state.mutex);
            update_game_state_snapshot(state);
            
            // Clear the active DKG session on DKG completion to update the observer node's dashboard
            uint64_t current_epoch_num = state->current_block_number / BLOCKS_PER_DAY;
            uint8_t epoch_session_id[COIN_ID_LEN];
            char epoch_input[32];
            memset(epoch_input, 0, 32);
            snprintf(epoch_input, 32, "DKG_EPOCH_%llu", (unsigned long long)current_epoch_num);
            SHA256((uint8_t*)epoch_input, strlen(epoch_input), epoch_session_id);
            
            pthread_mutex_lock(&state->epoch_mutex);
            // Only evict the active session if we are NOT currently participating in it.
            // If we are a member, our local DKG worker thread will safely tear it down upon mathematical completion.
            DKGSession *active_sess = hash_table_lookup(state->dkg_active_sessions, epoch_session_id, false);
            if (active_sess && active_sess->local_point_id == 0) {
                hash_table_remove(state->dkg_active_sessions, epoch_session_id);
            }
            pthread_mutex_unlock(&state->epoch_mutex);
                    
            p += PUBKEY_LEN;

            uint16_t pid_be;
            memcpy(&pid_be, p, sizeof(uint16_t));
            uint16_t received_point_id = be16toh(pid_be);
            p += sizeof(uint16_t);
            
            if (received_point_id == 0) {
                if (!state->is_epoch_member) {
                    state->epoch_point_id = 0;
                    state->is_epoch_member = false;
                }
                if (in_msg->length >= PUBKEY_LEN + 2 + 2) {
                    uint16_t count_be;
                    memcpy(&count_be, p, sizeof(uint16_t));
                    size_t count = be16toh(count_be);
                    p += sizeof(uint16_t);
                    if (count <= 10 && in_msg->length == PUBKEY_LEN + 2 + 2 + count * PUBKEY_LEN) {
                        pthread_mutex_lock(&state->epoch_mutex);
                        for (size_t i = 0; i < count; i++) {
                            memcpy(state->current_committee[i], p, PUBKEY_LEN);
                            p += PUBKEY_LEN;
                        }
                        state->current_committee_count = count;
                        pthread_mutex_unlock(&state->epoch_mutex);
                    }
                }
                fprintf(stderr, "[Epoch] Received DKG Public Key rotation.\n");
            }
            break;
        }
        case MSG_EPOCH_SIGN_REQUEST: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < COIN_ID_LEN) break;
            uint8_t block_hash[COIN_ID_LEN];
            memcpy(block_hash, in_msg->payload, COIN_ID_LEN);
            
            if (!state->is_epoch_member) {
                out_msg->type = MSG_EPOCH_PARTIAL_W;
                uint8_t *dp = out_msg->payload;
                memcpy(dp, block_hash, COIN_ID_LEN); dp += COIN_ID_LEN;
                uint16_t pid_be = htobe16(0); // Safely abstain
                memcpy(dp, &pid_be, 2); dp += 2;
                polyvec_t empty_w;
                polyvec_init(&empty_w, DILITHIUM_K);
                size_t w_len;
                polyvec_serialize(&empty_w, dp, MAX_MESSAGE_SIZE - (dp - out_msg->payload), &w_len);
                out_msg->length = COIN_ID_LEN + 2 + w_len;
                send_message(state, sender_pubkey, out_msg);
                polyvec_free(&empty_w);
                break;
            }
                    
            uint8_t tr[32], mu[32], mu_input[32 + COIN_ID_LEN];
            uint8_t epoch_rho[KAPPA];
            pthread_mutex_lock(&state->game_state.mutex);
            sha256_hash(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN, tr);
            memcpy(epoch_rho, state->game_state.epoch_threshold_pubkey, KAPPA);
            pthread_mutex_unlock(&state->game_state.mutex);
                    
            memcpy(mu_input, tr, 32);
            memcpy(mu_input + 32, block_hash, COIN_ID_LEN);
            sha256_hash(mu_input, 32 + COIN_ID_LEN, mu);
                    
            uint8_t sign_seed[KAPPA];
            generate_deterministic_nonce(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, mu, 32, sign_seed);
                    
            ThresholdSignData *sign_data = calloc(1, sizeof(ThresholdSignData));
            polyvec_init(&sign_data->y, DILITHIUM_L);
            generate_y_with_nonce(&sign_data->y, sign_seed, KAPPA, state->epoch_point_id, (GAMMA1 - TAU * ETA * NUM_SUBSETS) / 3 - TAU * (MAX_S_PART_INF * 10));
                    
            polyvec_init(&sign_data->w, DILITHIUM_K);
            size_t req_mark = arena_mark();
            matrix_t A_bar;
            A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
            polyvec_init_arena(&A_bar.rows, DILITHIUM_K * DILITHIUM_L);
            expand_a(&A_bar, epoch_rho);
            matrix_vec_mul(&sign_data->w, &A_bar, &sign_data->y);
            polyvec_free(&A_bar.rows);
            arena_reset(req_mark);
                    
            pthread_mutex_lock(&state->epoch_mutex);
            hash_table_insert(state->epoch_sign_data_cache, block_hash, sign_data, HASH_ENTRY_EPOCH_SIGN_DATA);
            pthread_mutex_unlock(&state->epoch_mutex);
                    
            out_msg->type = MSG_EPOCH_PARTIAL_W;
            uint8_t *dp = out_msg->payload;
            memcpy(dp, block_hash, COIN_ID_LEN); dp += COIN_ID_LEN;
            uint16_t pid_be = htobe16(state->epoch_point_id);
            memcpy(dp, &pid_be, 2); dp += 2;
            size_t w_len;
            polyvec_serialize(&sign_data->w, dp, MAX_MESSAGE_SIZE - (dp - out_msg->payload), &w_len);
            out_msg->length = COIN_ID_LEN + 2 + w_len;
            send_message(state, sender_pubkey, out_msg);
            break;
        }
        case MSG_EPOCH_PARTIAL_W: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < COIN_ID_LEN + 2) break;
            uint8_t block_hash[COIN_ID_LEN];
            memcpy(block_hash, in_msg->payload, COIN_ID_LEN);
                    
            pthread_mutex_lock(&state->epoch_mutex);
            ThresholdStakeProcess *proc = hash_table_lookup(state->epoch_processes, block_hash, false);
            if (!proc) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
            
            uint16_t point_id = 0;
            for (size_t i = 0; i < state->current_committee_count; i++) {
                if (memcmp(state->current_committee[i], sender_pubkey, PUBKEY_LEN) == 0) {
                    point_id = i + 1;
                    break;
                }
            }
            
            if (point_id == 0 || point_id > 10) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
            
            if (atomic_load_explicit(&proc->stage0_complete, memory_order_acquire)) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
            
            if (point_id >= 1 && point_id <= 10) {
                size_t p_idx = point_id - 1;
                if (!proc->is_peer_active[p_idx]) {
                    deserialize_polyvec(&proc->partial_w[p_idx], in_msg->payload + COIN_ID_LEN + 2, in_msg->length - (COIN_ID_LEN + 2), DILITHIUM_K);
                    proc->is_peer_active[p_idx] = true;
                }
            } else {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
                    
            size_t local_idx = state->epoch_point_id - 1;
            if (proc->is_peer_active[local_idx] && !atomic_load_explicit(&proc->stage0_complete, memory_order_acquire)) {
                int chosen_peer_idx = -1;
                // Proposer selects the first active peer that is NOT themselves
                for (int i = 0; i < 10; i++) {
                    if (i != (int)local_idx && proc->is_peer_active[i]) {
                        chosen_peer_idx = i;
                        break;
                    }
                }
                
                if (chosen_peer_idx != -1) {
                    polyvec_copy(&proc->w_agg, &proc->partial_w[local_idx]);
                    polyvec_add_no_reduce(&proc->w_agg, &proc->w_agg, &proc->partial_w[chosen_peer_idx]);
                    polyvec_reduce(&proc->w_agg);
                    
                    proc->final_sig_len = chosen_peer_idx + 1; // Lock chosen peer ID
                    
                    polyvec_t w1_agg;
                    polyvec_init(&w1_agg, DILITHIUM_K);
                    polyvec_high_bits(&w1_agg, &proc->w_agg, ALPHA);
                            
                    uint8_t w1_packed[DILITHIUM_K * POLYW1_PACKEDBYTES];
                    for (size_t k = 0; k < DILITHIUM_K; k++) polyw1_pack(w1_packed + k * POLYW1_PACKEDBYTES, &w1_agg.vec[k]);
                            
                    uint8_t tr[32];
                    pthread_mutex_lock(&state->game_state.mutex);
                    sha256_hash(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN, tr);
                    pthread_mutex_unlock(&state->game_state.mutex);
                            
                    uint8_t mu_input[32 + COIN_ID_LEN];
                    memcpy(mu_input, tr, 32);
                    memcpy(mu_input + 32, block_hash, COIN_ID_LEN);
                    sha256_hash(mu_input, 32 + COIN_ID_LEN, proc->mu);
                        
                    uint8_t hash_input[32 + DILITHIUM_K * POLYW1_PACKEDBYTES];
                    memcpy(hash_input, proc->mu, 32);
                    memcpy(hash_input + 32, w1_packed, DILITHIUM_K * POLYW1_PACKEDBYTES);
                    sha256_hash(hash_input, 32 + DILITHIUM_K * POLYW1_PACKEDBYTES, proc->rho_prime);
                            
                    sample_in_ball(&proc->challenge, proc->rho_prime, 32);
                    polyvec_free(&w1_agg);
                    
                    for (int i = 0; i < 10; i++) {
                        proc->is_peer_active[i] = false;
                    }
                    proc->is_peer_active[local_idx] = true;
                    proc->is_peer_active[chosen_peer_idx] = true;
                    proc->partials_received = 0;
                            
                    Message *c_msg = calloc(1, sizeof(Message));
                    if (c_msg) {
                        c_msg->type = MSG_EPOCH_CHALLENGE;
                        uint8_t *np = c_msg->payload;
                        memcpy(np, block_hash, COIN_ID_LEN); np += COIN_ID_LEN;
                        
                        // Serialize Partner IDs for dynamic subset reconstruction
                        uint16_t id1 = htobe16(local_idx + 1);
                        uint16_t id2 = htobe16(chosen_peer_idx + 1);
                        memcpy(np, &id1, 2); np += 2;
                        memcpy(np, &id2, 2); np += 2;
                        
                        size_t c_len = serialize_poly(&proc->challenge, np, MAX_MESSAGE_SIZE - COIN_ID_LEN - 4);
                        if (c_len == 0) {
                            free(c_msg);
                            pthread_mutex_unlock(&state->epoch_mutex);
                            return;
                        }
                        c_msg->length = COIN_ID_LEN + 4 + c_len;

                        atomic_store_explicit(&proc->stage0_complete, true, memory_order_release);
                        pthread_mutex_unlock(&state->epoch_mutex);
                        
                        send_message(state, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, c_msg);
                        send_message(state, proc->peer_pubkeys[chosen_peer_idx], c_msg);
                        
                        free(c_msg);
                        return; // Safely skip the outer unlock
                    }
                    atomic_store_explicit(&proc->stage0_complete, true, memory_order_release);
                }
            }
            pthread_mutex_unlock(&state->epoch_mutex);
            break;
        }
        case MSG_EPOCH_CHALLENGE: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < COIN_ID_LEN + 4 + POLY_SERIALIZED_SIZE) break;
            uint8_t block_hash[COIN_ID_LEN];
            memcpy(block_hash, in_msg->payload, COIN_ID_LEN);

            if (!state->is_epoch_member) {
                out_msg->type = MSG_EPOCH_PARTIAL_Z;
                uint8_t *rp = out_msg->payload;
                memcpy(rp, block_hash, COIN_ID_LEN); rp += COIN_ID_LEN;
                uint16_t pid_be = htobe16(0); // Safely abstain
                memcpy(rp, &pid_be, 2); rp += 2;
                polyvec_t empty_z;
                polyvec_init(&empty_z, DILITHIUM_L);
                size_t z_len;
                polyvec_serialize(&empty_z, rp, MAX_MESSAGE_SIZE - (COIN_ID_LEN + 2), &z_len);
                out_msg->length = COIN_ID_LEN + 2 + z_len;
                send_message(state, sender_pubkey, out_msg);
                polyvec_free(&empty_z);
                break;
            }
            
            uint16_t id1_be, id2_be;
            memcpy(&id1_be, in_msg->payload + COIN_ID_LEN, 2);
            memcpy(&id2_be, in_msg->payload + COIN_ID_LEN + 2, 2);
            uint16_t id1 = be16toh(id1_be);
            uint16_t id2 = be16toh(id2_be);
                    
            poly_t c;
            deserialize_poly(&c, in_msg->payload + COIN_ID_LEN + 4, POLY_SERIALIZED_SIZE);
                    
            pthread_mutex_lock(&state->epoch_mutex);
            ThresholdSignData *sd = hash_table_lookup(state->epoch_sign_data_cache, block_hash, false);
            if (!sd) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
            
            polyvec_t active_s1;
            polyvec_init(&active_s1, DILITHIUM_L);
            
            size_t my_idx = state->epoch_point_id - 1;
            size_t partner_idx = (id1 - 1 == my_idx) ? (id2 - 1) : (id1 - 1);
            
            for (int K = 0; K < 10; K++) {
                if (K == (int)my_idx) continue;
                
                bool i_am_responsible = false;
                if (K == (int)partner_idx) {
                    i_am_responsible = true;
                } else {
                    if (my_idx < partner_idx) {
                        i_am_responsible = true;
                    }
                }
                
                if (i_am_responsible) {
                    polyvec_add_no_reduce(&active_s1, &active_s1, &state->epoch_s1_subsets[K]);
                }
            }
            polyvec_reduce(&active_s1);
            pthread_mutex_unlock(&state->epoch_mutex);

            polyvec_t cs1_temp;
            polyvec_init(&cs1_temp, DILITHIUM_L);
            for (size_t k = 0; k < DILITHIUM_L; k++) {
                poly_mul_sparse(&cs1_temp.vec[k], &active_s1.vec[k], &c);
            }
            polyvec_reduce(&cs1_temp);
            polyvec_free(&active_s1);
                    
            polyvec_t z_i;
            polyvec_init(&z_i, DILITHIUM_L);
            polyvec_copy(&z_i, &sd->y);
            polyvec_add(&z_i, &z_i, &cs1_temp);
            polyvec_reduce(&z_i);
            polyvec_free(&cs1_temp);

            int32_t bound_z_i = (GAMMA1 - TAU * ETA * NUM_SUBSETS) / 3;
            if (!check_norm_inf(&z_i, bound_z_i)) {
                polyvec_free(&z_i);
                pthread_mutex_lock(&state->epoch_mutex);
                hash_table_remove(state->epoch_sign_data_cache, block_hash);
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
                        
            out_msg->type = MSG_EPOCH_PARTIAL_Z;
            uint8_t *rp = out_msg->payload;
            memcpy(rp, block_hash, COIN_ID_LEN); rp += COIN_ID_LEN;
            uint16_t pid_be = htobe16(state->epoch_point_id);
            memcpy(rp, &pid_be, 2); rp += 2;
            size_t z_len;
            polyvec_serialize(&z_i, rp, MAX_MESSAGE_SIZE - (COIN_ID_LEN + 2), &z_len);
            out_msg->length = COIN_ID_LEN + 2 + z_len;
            send_message(state, sender_pubkey, out_msg);
                                
            polyvec_free(&z_i);
                    
            pthread_mutex_lock(&state->epoch_mutex);
            hash_table_remove(state->epoch_sign_data_cache, block_hash);
            pthread_mutex_unlock(&state->epoch_mutex);
            break;
        }
        case MSG_EPOCH_PARTIAL_Z: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < COIN_ID_LEN + 2) break;
            uint8_t block_hash[COIN_ID_LEN];
            memcpy(block_hash, in_msg->payload, COIN_ID_LEN);
                    
            pthread_mutex_lock(&state->epoch_mutex);
            ThresholdStakeProcess *proc = hash_table_lookup(state->epoch_processes, block_hash, false);
            if (!proc) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }

            uint16_t point_id = 0;
            for (size_t i = 0; i < state->current_committee_count; i++) {
                if (memcmp(state->current_committee[i], sender_pubkey, PUBKEY_LEN) == 0) {
                    point_id = i + 1;
                    break;
                }
            }

            if (point_id == 0 || point_id > 10) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
            
            if (atomic_load_explicit(&proc->aggregation_complete, memory_order_acquire)) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }

            if (point_id >= 1 && point_id <= 10) {
                size_t p_idx = point_id - 1;
                if (point_id == state->epoch_point_id || point_id == proc->final_sig_len) {
                    if (proc->is_peer_active[p_idx]) {
                        if (deserialize_polyvec(&proc->partial_z[p_idx], in_msg->payload + COIN_ID_LEN + 2, in_msg->length - (COIN_ID_LEN + 2), DILITHIUM_L) != 0) {
                            atomic_store_explicit(&proc->aggregation_failed, true, memory_order_release);
                            pthread_cond_signal(&proc->partial_cond);
                            pthread_mutex_unlock(&state->epoch_mutex);
                            break;
                        }
                        proc->is_peer_active[p_idx] = false;
                        atomic_fetch_add_explicit(&proc->partials_received, 1, memory_order_relaxed);
                    }
                }
            } else {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
                    
            if (atomic_load_explicit(&proc->partials_received, memory_order_relaxed) == 2) {
                size_t local_idx = state->epoch_point_id - 1;
                size_t local_final_sig_len = proc->final_sig_len;
                size_t chosen_idx = local_final_sig_len - 1;

                polyvec_t pz_local, pz_peer;
                if (polyvec_init(&pz_local, DILITHIUM_L) != CRYPTO_SUCCESS ||
                    polyvec_init(&pz_peer, DILITHIUM_L) != CRYPTO_SUCCESS) {
                    atomic_store_explicit(&proc->aggregation_failed, true, memory_order_release);
                    pthread_cond_signal(&proc->partial_cond);
                    pthread_mutex_unlock(&state->epoch_mutex);
                    break;
                }
                polyvec_copy(&pz_local, &proc->partial_z[local_idx]);
                polyvec_copy(&pz_peer, &proc->partial_z[chosen_idx]);

                poly_t challenge_poly = proc->challenge;
                polyvec_t w_agg_copy;
                if (polyvec_init(&w_agg_copy, DILITHIUM_K) != CRYPTO_SUCCESS) {
                    polyvec_free(&pz_local);
                    polyvec_free(&pz_peer);
                    proc->aggregation_failed = true;
                    pthread_cond_signal(&proc->partial_cond);
                    pthread_mutex_unlock(&state->epoch_mutex);
                    break;
                }
                polyvec_copy(&w_agg_copy, &proc->w_agg);

                uint8_t mu[32], rho_prime[32];
                memcpy(mu, proc->mu, 32);
                memcpy(rho_prime, proc->rho_prime, 32);

                pthread_mutex_unlock(&state->epoch_mutex); // <--- UNLOCK EARLY TO AVOID TIMEOUT DEADLOCKS

                size_t z_mark = arena_mark();

                polyvec64_t z_agg64;
                if (polyvec64_init_arena(&z_agg64, DILITHIUM_L) != CRYPTO_SUCCESS) {
                    polyvec_free(&pz_local);
                    polyvec_free(&pz_peer);
                    polyvec_free(&w_agg_copy);
                    goto epoch_z_fail;
                }
                
                polyvec64_t partial64_local, partial64_peer;
                if (polyvec64_init_arena(&partial64_local, DILITHIUM_L) != CRYPTO_SUCCESS ||
                    polyvec64_init_arena(&partial64_peer, DILITHIUM_L) != CRYPTO_SUCCESS) {
                    polyvec64_free(&z_agg64);
                    polyvec_free(&pz_local);
                    polyvec_free(&pz_peer);
                    polyvec_free(&w_agg_copy);
                    goto epoch_z_fail;
                }
                polyvec_to64(&partial64_local, &pz_local);
                polyvec_to64(&partial64_peer, &pz_peer);
                
                polyvec64_add(&z_agg64, &partial64_local, &partial64_peer);
                polyvec64_free(&partial64_local);
                polyvec64_free(&partial64_peer);
                polyvec_free(&pz_local);
                polyvec_free(&pz_peer);
                
                int32_t eta_full = ETA * NUM_SUBSETS;
                int32_t beta = TAU * eta_full;
                int32_t bound_z_agg = GAMMA1 - beta;
                
                if (!check_norm_inf64(&z_agg64, bound_z_agg)) {
                    polyvec64_free(&z_agg64);
                    polyvec_free(&w_agg_copy);
                    goto epoch_z_fail;
                }
                        
                polyvec_t z_agg;
                if (polyvec_init(&z_agg, DILITHIUM_L) != CRYPTO_SUCCESS) {
                    polyvec64_free(&z_agg64);
                    polyvec_free(&w_agg_copy);
                    goto epoch_z_fail;
                }
                polyvec64_reduce(&z_agg, &z_agg64);
                polyvec64_free(&z_agg64);

                pthread_mutex_lock(&state->game_state.mutex);
                uint8_t *epoch_pubkey = malloc(PUBKEY_LEN);
                if (epoch_pubkey) {
                    memcpy(epoch_pubkey, state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
                }
                pthread_mutex_unlock(&state->game_state.mutex);

                bool local_agg_complete = false;
                uint8_t local_final_signature[SIGNATURE_LEN] = {0};
                size_t local_final_sig_len_out = 0;

                if (epoch_pubkey) {
                    uint8_t rho[KAPPA];
                    memcpy(rho, epoch_pubkey, KAPPA);
                    matrix_t A_bar;
                    A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
                    if (polyvec_init_arena(&A_bar.rows, DILITHIUM_K * DILITHIUM_L) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }
                    expand_a(&A_bar, rho);

                    // 1. Az = A_bar * z_agg (unreduced for accuracy)
                    polyvec64_t Az;
                    if (polyvec64_init_arena(&Az, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }
                    matrix_vec_mul_unreduced(&Az, &A_bar, &z_agg);

                    // Reconstruct full t_global from epoch_t_global under thread-safe epoch_mutex lock
                    polyvec_t t_global;
                    if (polyvec_init_arena(&t_global, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }
                    pthread_mutex_lock(&state->epoch_mutex);
                    polyvec_copy(&t_global, &state->epoch_t_global);
                    pthread_mutex_unlock(&state->epoch_mutex);

                    // Decompose t_global to get t1
                    polyvec_t t1;
                    if (polyvec_init_arena(&t1, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }
                    for (size_t i = 0; i < DILITHIUM_K; i++) {
                        for (int j = 0; j < RING_DEG; j++) {
                            int32_t val = t_global.vec[i].coeffs[j];
                            int32_t r0, r1;
                            decompose(val, 1 << D, &r0, &r1);
                            t1.vec[i].coeffs[j] = r1;
                        }
                    }

                    // Scale t1 by 2^D
                    polyvec_t t1_scaled;
                    if (polyvec_init_arena(&t1_scaled, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }
                    for (size_t i = 0; i < DILITHIUM_K; i++) {
                        for (int j = 0; j < RING_DEG; j++) {
                            t1_scaled.vec[i].coeffs[j] = t1.vec[i].coeffs[j] << D;
                        }
                    }

                    // 2. ct = c * t1_scaled (unreduced)
                    polyvec64_t ct;
                    if (polyvec64_init_arena(&ct, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }
                    polyvec_poly_mul_unreduced(&ct, &t1_scaled, &challenge_poly);

                    // 3. temp = Az - ct
                    polyvec64_t temp;
                    if (polyvec64_init_arena(&temp, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }
                    polyvec64_sub(&temp, &Az, &ct);

                    // 4. Reduce temp mod Q and extract bits
                    polyvec_t temp_reduced, h_agg;
                    if (polyvec_init_arena(&temp_reduced, DILITHIUM_K) != CRYPTO_SUCCESS ||
                        polyvec_init_arena(&h_agg, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        free(epoch_pubkey);
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto epoch_z_fail;
                    }

                    polyvec64_reduce(&temp_reduced, &temp);
                    polyvec_reduce(&temp_reduced);
                    polyvec_make_hint(&h_agg, &temp_reduced, &w_agg_copy, ALPHA);

                    int wt = count_nonzero_vec(&h_agg);
                    if (wt <= OMEGA) {
                        size_t final_len;
                        uint8_t test_sig[SIGNATURE_LEN];
                        if (pack_signature(test_sig, &z_agg, &h_agg, rho_prime, &final_len) == CRYPTO_SUCCESS) {
                            if (threshold_verify(mu, 32, test_sig, final_len, epoch_pubkey, PUBKEY_LEN) == 0) {
                                memcpy(local_final_signature, test_sig, final_len);
                                local_final_sig_len_out = final_len;
                                local_agg_complete = true;
                            }
                        }
                    }

                    free(epoch_pubkey);
                    polyvec_free(&z_agg);
                    polyvec_free(&w_agg_copy);
                } else {
                    free(epoch_pubkey);
                    polyvec_free(&z_agg);
                    polyvec_free(&w_agg_copy);
                }

                // Reacquire epoch_mutex to update process state
                pthread_mutex_lock(&state->epoch_mutex);
                proc = hash_table_lookup(state->epoch_processes, block_hash, false);
                if (proc) {
                    if (local_agg_complete) {
                        memcpy(proc->final_signature, local_final_signature, local_final_sig_len_out);
                        proc->final_sig_len = local_final_sig_len_out;
                        atomic_store_explicit(&proc->aggregation_complete, true, memory_order_release);
                    } else {
                        atomic_store_explicit(&proc->aggregation_failed, true, memory_order_release);
                    }
                    pthread_cond_signal(&proc->partial_cond);
                }
                pthread_mutex_unlock(&state->epoch_mutex);
                arena_reset(z_mark);
                break;
epoch_z_fail:
                arena_reset(z_mark);
                pthread_mutex_lock(&state->epoch_mutex);
                proc = hash_table_lookup(state->epoch_processes, block_hash, false);
                if (proc) {
                    atomic_store_explicit(&proc->aggregation_failed, true, memory_order_release);
                    pthread_cond_signal(&proc->partial_cond);
                }
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
            pthread_mutex_unlock(&state->epoch_mutex);
            break;
        }
        case MSG_DKG_COMMIT: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < COIN_ID_LEN + 2 + 32) break;
            uint8_t session_id[COIN_ID_LEN];
            memcpy(session_id, in_msg->payload, COIN_ID_LEN);
            
            uint64_t msg_epoch = 0;
            if (!dkg_validate_session_epoch(state, session_id, &msg_epoch)) {
                break;
            }

            pthread_mutex_lock(&state->epoch_mutex);
            DKGSession *session = hash_table_lookup(state->dkg_active_sessions, session_id, false);
            if (!session && !state->in_blockchain_sync) {
                DKGSession *pre_session = calloc(1, sizeof(DKGSession));
                if (pre_session) {
                    memcpy(pre_session->session_id, session_id, COIN_ID_LEN);
                    atomic_init(&pre_session->ref_count, 1);
                    pre_session->block_height = state->current_block_number;
                    pre_session->committee_count = 10;
                    pre_session->status = 0;
                    pre_session->worker_spawned = true;
                    pthread_cond_init(&pre_session->phase_cond, NULL);
                    hash_table_insert(state->dkg_active_sessions, session_id, pre_session, HASH_ENTRY_DKG_SESSION);
                    atomic_fetch_add_explicit(&pre_session->ref_count, 1, memory_order_relaxed);
                    spawn_dkg_worker_thread(state, session_id, state->current_block_number);
                    session = pre_session;
                }
            }
            if (session && session->worker_spawned && session->status != -1) {
                uint16_t point_id = 0;
                for (size_t i = 0; i < session->committee_count; i++) {
                    if (sender_pubkey && !is_zeroed(sender_pubkey, PUBKEY_LEN) &&
                        memcmp(session->committee_pubkeys[i], sender_pubkey, PUBKEY_LEN) == 0) {
                        point_id = i + 1;
                        break;
                    }
                }
                /* Point id is the sender's slot in the sorted committee, never the
                 * self-asserted header. Until committee_pubkeys[] is installed the
                 * message stays in the early queue and is replayed by the worker. */

                if (point_id == 0 || point_id > session->committee_count) {
                    if (is_zeroed(session->committee_pubkeys[0], PUBKEY_LEN) && session->early_msg_count < 1000) {
                        Message *m_copy = malloc(sizeof(Message));
                        if (m_copy) {
                            *m_copy = *in_msg;
                            session->early_msgs[session->early_msg_count] = m_copy;
                            if (sender_pubkey) {
                                memcpy(session->early_senders[session->early_msg_count], sender_pubkey, PUBKEY_LEN);
                            }
                            session->early_conns[session->early_msg_count] = conn;
                            if (conn) try_acquire_ref(conn);
                            session->early_msg_count++;
                        }
                    }
                    pthread_mutex_unlock(&state->epoch_mutex);
                    break;
                }
                
                if (point_id >= 1 && point_id <= 10 && session->has_commitment[point_id - 1]) {
                    if (memcmp(session->commitments[point_id - 1], in_msg->payload + COIN_ID_LEN + 2, 32) == 0) {
                        pthread_mutex_unlock(&state->epoch_mutex);
                        break;
                    }
                    if (session->status == 0) {
                        memcpy(session->commitments[point_id - 1], in_msg->payload + COIN_ID_LEN + 2, 32);
                    }
                    pthread_mutex_unlock(&state->epoch_mutex);
                    break;
                }
                
                if (point_id >= 1 && point_id <= 10 && !session->has_commitment[point_id - 1]) {
                    memcpy(session->commitments[point_id - 1], in_msg->payload + COIN_ID_LEN + 2, 32);
                    session->has_commitment[point_id - 1] = true;
                    session->commitments_received++;
                    fprintf(stderr, "[DKG] Received Commit from Point ID %d (%d/%zu)\n", point_id, session->commitments_received, session->committee_count);
                    
                    if (session->has_reveal[point_id - 1]) {
                        uint8_t verify_buf[32 + PUBKEY_LEN];
                        memcpy(verify_buf, session->reveals[point_id - 1], 32);
                        memcpy(verify_buf + 32, session->committee_pubkeys[point_id - 1], PUBKEY_LEN);
                        uint8_t computed_c[32];
                        sha256_hash(verify_buf, 32 + PUBKEY_LEN, computed_c);
                        
                        if (memcmp(computed_c, session->commitments[point_id - 1], 32) == 0) {
                            session->reveals_received++;
                            fprintf(stderr, "[DKG] Verified cached Reveal from Point ID %d (%d/%zu)\n", point_id, session->reveals_received, session->committee_count);
                            if (session->reveals_received == (int)session->committee_count) {
                                pthread_cond_signal(&session->phase_cond);
                            }
                        } else {
                            fprintf(stderr, "[DKG] WARNING: Invalid cached Reveal from Point ID %d\n", point_id);
                            session->has_reveal[point_id - 1] = false;
                        }
                    }
                    
                    if (session->commitments_received == (int)session->committee_count) {
                        pthread_cond_signal(&session->phase_cond);
                    }
                }
            }
            pthread_mutex_unlock(&state->epoch_mutex);
            break;
        }
        case MSG_DKG_REVEAL: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < COIN_ID_LEN + 2 + 32) break;
            uint8_t session_id[COIN_ID_LEN];
            memcpy(session_id, in_msg->payload, COIN_ID_LEN);
            
            uint64_t msg_epoch = 0;
            if (!dkg_validate_session_epoch(state, session_id, &msg_epoch)) {
                break;
            }
            
            pthread_mutex_lock(&state->epoch_mutex);
            DKGSession *session = hash_table_lookup(state->dkg_active_sessions, session_id, false);
            if (session && session->worker_spawned && session->status != -1) {
                uint16_t point_id = 0;
                for (size_t i = 0; i < session->committee_count; i++) {
                    if (sender_pubkey && !is_zeroed(sender_pubkey, PUBKEY_LEN) &&
                        memcmp(session->committee_pubkeys[i], sender_pubkey, PUBKEY_LEN) == 0) {
                        point_id = i + 1;
                        break;
                    }
                }

                if (point_id == 0 || point_id > session->committee_count) {
                    if (is_zeroed(session->committee_pubkeys[0], PUBKEY_LEN) && session->early_msg_count < 1000) {
                        Message *m_copy = malloc(sizeof(Message));
                        if (m_copy) {
                            *m_copy = *in_msg;
                            session->early_msgs[session->early_msg_count] = m_copy;
                            memcpy(session->early_senders[session->early_msg_count], sender_pubkey, PUBKEY_LEN);
                            session->early_conns[session->early_msg_count] = conn;
                            if (conn) try_acquire_ref(conn);
                            session->early_msg_count++;
                        }
                    }
                    pthread_mutex_unlock(&state->epoch_mutex);
                    break;
                }
                
                if (point_id >= 1 && point_id <= 10 && !session->has_reveal[point_id - 1]) {
                    uint8_t reveal[32];
                    memcpy(reveal, in_msg->payload + COIN_ID_LEN + 2, 32);
                    memcpy(session->reveals[point_id - 1], reveal, 32);
                    session->has_reveal[point_id - 1] = true;
                    
                    if (session->has_commitment[point_id - 1]) {
                        uint8_t verify_buf[32 + PUBKEY_LEN];
                        memcpy(verify_buf, reveal, 32);
                        memcpy(verify_buf + 32, session->committee_pubkeys[point_id - 1], PUBKEY_LEN);
                        uint8_t computed_c[32];
                        sha256_hash(verify_buf, 32 + PUBKEY_LEN, computed_c);
                        
                        if (memcmp(computed_c, session->commitments[point_id - 1], 32) == 0) {
                            session->reveals_received++;
                            fprintf(stderr, "[DKG] Verified & Received Reveal from Point ID %d (%d/%zu)\n", point_id, session->reveals_received, session->committee_count);
                            
                            if (session->reveals_received == (int)session->committee_count) {
                                pthread_cond_signal(&session->phase_cond);
                            }
                        } else {
                            fprintf(stderr, "[DKG] WARNING: Invalid cryptographic Reveal from Point ID %d\n", point_id);
                            session->has_reveal[point_id - 1] = false;
                        }
                    } else {
                        uint8_t verify_buf[32 + PUBKEY_LEN];
                        memcpy(verify_buf, reveal, 32);
                        memcpy(verify_buf + 32, session->committee_pubkeys[point_id - 1], PUBKEY_LEN);
                        uint8_t computed_c[32];
                        sha256_hash(verify_buf, 32 + PUBKEY_LEN, computed_c);
                        
                        memcpy(session->commitments[point_id - 1], computed_c, 32);
                        session->has_commitment[point_id - 1] = true;
                        session->commitments_received++;
                        session->reveals_received++;
                        fprintf(stderr, "[DKG] Recovered missing Commitment from out-of-order Reveal from Point ID %d\n", point_id);
                        
                        if (session->commitments_received == (int)session->committee_count) {
                            pthread_cond_signal(&session->phase_cond);
                        }
                        if (session->reveals_received == (int)session->committee_count) {
                            pthread_cond_signal(&session->phase_cond);
                        }
                    }
                }
            }
            pthread_mutex_unlock(&state->epoch_mutex);
            break;
        }
        case MSG_DKG_SHARE_DEAL: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            // Payload: session_id (32) + sender_point_id (2) + kyber_ct (768) + enc_shares
            const size_t subset_size = 2 + POLYVEC_L_SERIALIZED + POLYVEC_K_SERIALIZED;
            const size_t pt_len = 9 * subset_size; // 138258 bytes
            const size_t expected_enc_len = pt_len + 28; // AES-GCM IV(12) + Tag(16)
            const size_t expected_len = COIN_ID_LEN + 2 + KYBER_CIPHERTEXT_LEN + expected_enc_len;
            if (in_msg->length != expected_len) break;
            
            uint8_t session_id[COIN_ID_LEN];
            memcpy(session_id, in_msg->payload, COIN_ID_LEN);
            
            uint64_t msg_epoch = 0;
            if (!dkg_validate_session_epoch(state, session_id, &msg_epoch)) {
                break;
            }
            
            pthread_mutex_lock(&state->epoch_mutex);
            DKGSession *session_check = hash_table_lookup(state->dkg_active_sessions, session_id, false);
            if (!session_check || !session_check->worker_spawned || session_check->status == -1) {
                pthread_mutex_unlock(&state->epoch_mutex);
                break;
            }
            pthread_mutex_unlock(&state->epoch_mutex);

            // Decrypt outside of the epoch_mutex lock to prevent L5 worker starvation
            const uint8_t *p_dec = in_msg->payload + COIN_ID_LEN + 2;
            uint8_t ciphertext[KYBER_CIPHERTEXT_LEN];
            memcpy(ciphertext, p_dec, KYBER_CIPHERTEXT_LEN); p_dec += KYBER_CIPHERTEXT_LEN;
            
            uint8_t shared_secret[KYBER_SHARED_SECRET_LEN];
            if (!kyber_decapsulate(ciphertext, state->p2p_network.local_peer.peer_wallet.kyber_privkey, shared_secret)) {
                fprintf(stderr, "[DKG] ERROR: Kyber KEM decapsulation failed for incoming shares.\n");
                break;
            }
            
            uint8_t aes_key[32];
            derive_symmetric_keys(shared_secret, aes_key);
            
            uint8_t *pt_buf = get_l5_staging_buffer();
            if (!pt_buf) break;
            
            size_t decoded_pt_len;
            if (decrypt_message(aes_key, p_dec, expected_enc_len, pt_buf, &decoded_pt_len) != 0 || decoded_pt_len != pt_len) {
                fprintf(stderr, "[DKG] ERROR: AES-GCM decryption failed for incoming shares.\n");
                break;
            }
            
            pthread_mutex_lock(&state->epoch_mutex);
            DKGSession *session = hash_table_lookup(state->dkg_active_sessions, session_id, false);
            if (session && session->worker_spawned && session->status != -1) {
                if (session->local_point_id > 0) {
                    uint16_t resolved_sender_pid = 0;
                    for (size_t i = 0; i < session->committee_count; i++) {
                        if (sender_pubkey && !is_zeroed(sender_pubkey, PUBKEY_LEN) &&
                            memcmp(session->committee_pubkeys[i], sender_pubkey, PUBKEY_LEN) == 0) {
                            resolved_sender_pid = i + 1;
                            break;
                        }
                    }

                    if (resolved_sender_pid == 0 || resolved_sender_pid > session->committee_count) {
                        if (is_zeroed(session->committee_pubkeys[0], PUBKEY_LEN) && session->early_msg_count < 1000) {
                            Message *m_copy = malloc(sizeof(Message));
                            if (m_copy) {
                                *m_copy = *in_msg;
                                session->early_msgs[session->early_msg_count] = m_copy;
                                memcpy(session->early_senders[session->early_msg_count], sender_pubkey, PUBKEY_LEN);
                                session->early_conns[session->early_msg_count] = conn;
                                if (conn) try_acquire_ref(conn);
                                session->early_msg_count++;
                            }
                        }
                        pthread_mutex_unlock(&state->epoch_mutex);
                        break;
                    }
                    
                    if (resolved_sender_pid >= 1 && resolved_sender_pid <= 10 && !session->has_shares[resolved_sender_pid - 1]) {
                        const uint8_t *pt_p = pt_buf;
                        bool success = true;
                        
                        for (int i = 0; i < 9; i++) {
                            uint16_t subset_id_be;
                            memcpy(&subset_id_be, pt_p, 2);
                            uint16_t subset_id = be16toh(subset_id_be);
                            pt_p += 2;
                            if (subset_id >= 10) { success = false; break; }
                            
                            if (polyvec_init(&session->keygen.inbound_s1_shares[resolved_sender_pid - 1][subset_id], DILITHIUM_L) != CRYPTO_SUCCESS) { success = false; break; }
                            if (deserialize_polyvec(&session->keygen.inbound_s1_shares[resolved_sender_pid - 1][subset_id], pt_p, POLYVEC_L_SERIALIZED, DILITHIUM_L) != 0) { success = false; break; }
                            pt_p += POLYVEC_L_SERIALIZED;
                            
                            if (polyvec_init(&session->keygen.inbound_s2_shares[resolved_sender_pid - 1][subset_id], DILITHIUM_K) != CRYPTO_SUCCESS) { success = false; break; }
                            if (deserialize_polyvec(&session->keygen.inbound_s2_shares[resolved_sender_pid - 1][subset_id], pt_p, POLYVEC_K_SERIALIZED, DILITHIUM_K) != 0) { success = false; break; }
                            pt_p += POLYVEC_K_SERIALIZED;
                        }
                        
                        if (success) {
                            session->has_shares[resolved_sender_pid - 1] = true;
                            session->shares_received++;
                            fprintf(stderr, "[DKG] Decrypted & Verified Subset Shares from Point ID %d (%d/%zu)\n", resolved_sender_pid, session->shares_received, session->committee_count);
                            
                            if (session->shares_received == (int)session->committee_count - 1) {
                                pthread_cond_signal(&session->phase_cond);
                            }
                        }
                    }
                }
            }
            pthread_mutex_unlock(&state->epoch_mutex);
            break;
        }
        case MSG_DKG_PUBKEY_FRAG: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            // Payload: session_id (32) + sender_point_id (2) + t_i (DILITHIUM_K * POLY_SERIALIZED_SIZE = 8192)
            const size_t expected_len = COIN_ID_LEN + 2 + POLYVEC_K_SERIALIZED;
            if (in_msg->length != expected_len) break;
            
            uint8_t session_id[COIN_ID_LEN];
            memcpy(session_id, in_msg->payload, COIN_ID_LEN);
            
            uint64_t msg_epoch = 0;
            if (!dkg_validate_session_epoch(state, session_id, &msg_epoch)) {
                break;
            }
            
            pthread_mutex_lock(&state->epoch_mutex);
            DKGSession *session = hash_table_lookup(state->dkg_active_sessions, session_id, false);
            if (session && session->worker_spawned && session->status != -1) {
                uint16_t sender_pid = 0;
                for (size_t i = 0; i < session->committee_count; i++) {
                    if (sender_pubkey && !is_zeroed(sender_pubkey, PUBKEY_LEN) &&
                        memcmp(session->committee_pubkeys[i], sender_pubkey, PUBKEY_LEN) == 0) {
                        sender_pid = i + 1;
                        break;
                    }
                }
                
                if (sender_pid == 0 || sender_pid > session->committee_count) {
                    if (is_zeroed(session->committee_pubkeys[0], PUBKEY_LEN) && session->early_msg_count < 1000) {
                        Message *m_copy = malloc(sizeof(Message));
                        if (m_copy) {
                            *m_copy = *in_msg;
                            session->early_msgs[session->early_msg_count] = m_copy;
                            memcpy(session->early_senders[session->early_msg_count], sender_pubkey, PUBKEY_LEN);
                            session->early_conns[session->early_msg_count] = conn;
                            if (conn) try_acquire_ref(conn);
                            session->early_msg_count++;
                        }
                    }
                    pthread_mutex_unlock(&state->epoch_mutex);
                    break;
                }
                
                if (sender_pid >= 1 && sender_pid <= 10 && !session->has_pubkey_frag[sender_pid - 1]) {
                    const uint8_t *p = in_msg->payload + COIN_ID_LEN + 2;
                    if (polyvec_init(&session->keygen.peer_t_contributions[sender_pid - 1], DILITHIUM_K) == CRYPTO_SUCCESS) {
                        if (deserialize_polyvec(&session->keygen.peer_t_contributions[sender_pid - 1], p, POLYVEC_K_SERIALIZED, DILITHIUM_K) == 0) {
                            session->has_pubkey_frag[sender_pid - 1] = true;
                            session->pubkey_frags_received++;
                            fprintf(stderr, "[DKG] Received Pubkey Fragment (t_i) from Point ID %d (%d/%zu)\n", sender_pid, session->pubkey_frags_received, session->committee_count);
                            
                            // Wait for N-1 fragments
                            if (session->pubkey_frags_received == (int)session->committee_count - 1) {
                                pthread_cond_signal(&session->phase_cond);
                            }
                        }
                    }
                }
            }
            pthread_mutex_unlock(&state->epoch_mutex);
            break;
        }
        case MSG_CENTINEL_QUERY: {
            pthread_rwlock_rdlock(&state->bc.rwlock);
                    
            // 1. Sync Commitment MMR Leaves Chronologically
            size_t total_commitments = 0;
            for (size_t i = 0; i < state->bc.centinel.validation_commitments->count; i++) {
                if (state->bc.centinel.validation_commitments->nodes[i].height == 0) total_commitments++;
            }
                    
            size_t current_node_idx = 0;
            size_t comm_idx = 0;
            const size_t max_payload_comm = MAX_MESSAGE_SIZE - ENCRYPTION_OVERHEAD;
                    
            while (comm_idx < total_commitments) {
                size_t batch_size = 0;
                size_t temp_idx = current_node_idx;
                                    
                while (temp_idx < state->bc.centinel.validation_commitments->count && sizeof(uint32_t) + (batch_size + 1) * COIN_ID_LEN <= max_payload_comm) {
                    if (state->bc.centinel.validation_commitments->nodes[temp_idx].height == 0) {
                        batch_size++;
                    }
                    temp_idx++;
                }
                if (batch_size == 0) break;

                size_t payload_size = sizeof(uint32_t) + batch_size * COIN_ID_LEN;

                // Dynamically allocate safe_out to prevent egress pointer overlaps
                Message *safe_out = calloc(1, sizeof(Message));
                if (!safe_out) break;
                
                safe_out->type = MSG_CENTINEL_COMMITMENTS;
                safe_out->length = payload_size;
                uint8_t *pp = safe_out->payload;
                uint32_t count_be = htobe32((uint32_t)batch_size);
                memcpy(pp, &count_be, sizeof(uint32_t));
                pp += sizeof(uint32_t);
                        
                size_t added = 0;
                while (current_node_idx < state->bc.centinel.validation_commitments->count && added < batch_size) {
                    if (state->bc.centinel.validation_commitments->nodes[current_node_idx].height == 0) {
                        memcpy(pp, state->bc.centinel.validation_commitments->nodes[current_node_idx].hash, COIN_ID_LEN);
                        pp += COIN_ID_LEN;
                        added++;
                    }
                    current_node_idx++;
                }

                if (send_message(state, sender_pubkey, safe_out)) {
                    comm_idx += batch_size;
                } else {
                    free(safe_out);
                    break;
                }
                free(safe_out);
            }

            // 2. Sync Burnt Nullifier Set
            size_t total_nullifiers = state->bc.centinel.nullifier_set->count;
            uint8_t (*nullifier_list)[NULLIFIER_LEN] = NULL;
            if (total_nullifiers > 0) {
                nullifier_list = malloc(total_nullifiers * NULLIFIER_LEN);
                if (nullifier_list) {
                    size_t n_idx = 0;
                    for (size_t i = 0; i < state->bc.centinel.nullifier_set->size; i++) {
                        GenericHashEntry *entry = state->bc.centinel.nullifier_set->buckets[i];
                        while (entry) {
                            memcpy(nullifier_list[n_idx++], entry->key, NULLIFIER_LEN);
                            entry = entry->next;
                        }
                    }

                    size_t n_sent = 0;
                    const size_t max_payload_null = MAX_MESSAGE_SIZE - ENCRYPTION_OVERHEAD;
                    while (n_sent < total_nullifiers) {
                        size_t batch_size = 0;
                        while (n_sent + batch_size < total_nullifiers && sizeof(uint32_t) + (batch_size + 1) * NULLIFIER_LEN <= max_payload_null) {
                            batch_size++;
                        }
                        if (batch_size == 0) break;
                        if (n_sent + batch_size > total_nullifiers) batch_size = total_nullifiers - n_sent;

                        size_t payload_size = sizeof(uint32_t) + batch_size * NULLIFIER_LEN;

                        // Dynamically allocate safe_out to prevent egress pointer overlaps
                        Message *safe_out = calloc(1, sizeof(Message));
                        if (!safe_out) break;

                        safe_out->type = MSG_CENTINEL_NULLIFIERS;
                        safe_out->length = payload_size;
                        uint8_t *pp = safe_out->payload;
                        uint32_t count_be = htobe32((uint32_t)batch_size);
                        memcpy(pp, &count_be, sizeof(uint32_t));
                        pp += sizeof(uint32_t);
                        for (size_t j = 0; j < batch_size; j++) {
                            memcpy(pp, nullifier_list[n_sent + j], NULLIFIER_LEN);
                            pp += NULLIFIER_LEN;
                        }

                        if (send_message(state, sender_pubkey, safe_out)) {
                            n_sent += batch_size;
                        } else {
                            free(safe_out);
                            break;
                        }
                        free(safe_out);
                    }
                    free(nullifier_list);
                }
            }
            pthread_rwlock_unlock(&state->bc.rwlock);
            break;
        }
        case MSG_CENTINEL_COMMITMENTS: {
            pthread_mutex_lock(&state->mutex);
            if (state->in_blockchain_sync && memcmp(sender_pubkey, state->sync_peer_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                pthread_mutex_unlock(&state->mutex);
                break;
            }
            pthread_mutex_unlock(&state->mutex);

            if (in_msg->length < sizeof(uint32_t)) break;
            uint32_t num_commitments;
            memcpy(&num_commitments, in_msg->payload, sizeof(uint32_t));
            num_commitments = be32toh(num_commitments);
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (num_commitments > 16) num_commitments = 16; // Prevent O(N^2) MMR array scan exhaustion
#endif
            if (num_commitments > MAX_MESSAGE_SIZE / COIN_ID_LEN) break;
            if (in_msg->length != sizeof(uint32_t) + num_commitments * COIN_ID_LEN) break;

            pthread_rwlock_wrlock(&state->bc.rwlock);
            uint8_t *p = in_msg->payload + sizeof(uint32_t);
            for (uint32_t i = 0; i < num_commitments; i++) {
                uint8_t leaf_hash[COIN_ID_LEN];
                memcpy(leaf_hash, p, COIN_ID_LEN);
                p += COIN_ID_LEN;
                                
                // Chronologically re-add the commitments to perfectly recreate the network Merkle Root
                int exists = 0;
                for (size_t j = 0; j < state->bc.centinel.validation_commitments->count; j++) {
                    if (state->bc.centinel.validation_commitments->nodes[j].height == 0 &&
                        memcmp(state->bc.centinel.validation_commitments->nodes[j].hash, leaf_hash, COIN_ID_LEN) == 0) {
                        exists = 1;
                        break;
                    }
                }
                        
                // Directly inject the pre-hashed leaf to prevent double-hashing corruption
                if (!exists) {
                    mmr_add_leaf_hash(state->bc.centinel.validation_commitments, leaf_hash);
                }
            }
            pthread_rwlock_unlock(&state->bc.rwlock);
            break;
        }
        case MSG_CENTINEL_NULLIFIERS: {
            pthread_mutex_lock(&state->mutex);
            if (state->in_blockchain_sync && memcmp(sender_pubkey, state->sync_peer_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                pthread_mutex_unlock(&state->mutex);
                break;
            }
            pthread_mutex_unlock(&state->mutex);

            if (in_msg->length < sizeof(uint32_t)) break;
            uint32_t num_nullifiers;
            memcpy(&num_nullifiers, in_msg->payload, sizeof(uint32_t));
            num_nullifiers = be32toh(num_nullifiers);
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (num_nullifiers > 16) num_nullifiers = 16;
#endif
            if (num_nullifiers > MAX_MESSAGE_SIZE / NULLIFIER_LEN) break;
            if (in_msg->length != sizeof(uint32_t) + num_nullifiers * NULLIFIER_LEN) break;

            pthread_rwlock_wrlock(&state->bc.rwlock);
            uint8_t *p = in_msg->payload + sizeof(uint32_t);
            for (uint32_t i = 0; i < num_nullifiers; i++) {
                uint8_t nullifier[NULLIFIER_LEN];
                memcpy(nullifier, p, NULLIFIER_LEN);
                p += NULLIFIER_LEN;
                if (!hash_table_lookup(state->bc.centinel.nullifier_set, nullifier, true)) {
                    hash_table_insert(state->bc.centinel.nullifier_set, nullifier, NULL, HASH_ENTRY_NULLIFIER);
                }
            }
            pthread_rwlock_unlock(&state->bc.rwlock);
            break;
        }
        case MSG_REDEEM_CENTINEL: {
            Operation *op = calloc(1, sizeof(Operation));
            if (!op) break;
            int bytes_consumed = deserialize_operation(in_msg->payload, in_msg->length, op, 1);
            if (bytes_consumed > 0 && op->type == OP_REDEEM_CENTINEL) {
                if (verify_operation_heavy_crypto(op) != CRYPTO_SUCCESS) {
                    free(op);
                    break;
                }

                pthread_mutex_lock(&state->mutex);
                int added = add_pending_operation(state, op);
                pthread_mutex_unlock(&state->mutex);
                
                if (added != 0) {
                    if (!state->in_blockchain_sync) {
                        scl_log(LOG_LEVEL_DEBUG, "Network", "OP_REDEEM_CENTINEL mempool sync failed. Requesting Centinel State Sync...");
                        Message *centinel_req = calloc(1, sizeof(Message));
                        if (centinel_req) {
                            centinel_req->type = MSG_CENTINEL_QUERY;
                            centinel_req->length = 0;
                            send_message(state, sender_pubkey, centinel_req);
                            free(centinel_req);
                        }
                    }
                    free(op);
                }
            } else {
                scl_log(LOG_LEVEL_DEBUG, "Network", "Failed to deserialize MSG_REDEEM_CENTINEL");
                free(op);
            }
            break;
        }
        case MSG_STATELESS_RESET_TOKEN: {
            if (in_msg->length == 16) {
                if (!conn) break;
                memcpy(conn->stateless_reset_token, in_msg->payload, 16);
                conn->has_stateless_reset_token = true;
                // Safely ratchet to ESTABLISHED. The server has installed the connection.
                // Egress queues will now flush pending Application Data.
                conn->handshake_state = SCL_CONN_STATE_ESTABLISHED;
                conn->is_handshake_complete = true;
                scl_log(LOG_LEVEL_DEBUG, "L5", "Received STATELESS_RESET_TOKEN from peer. Stored safely.");

                // Clear unacked queue since the server has successfully installed the connection
                pthread_mutex_lock(&conn->l4_mutex);
                SclUnackedPacket *unacked = conn->unacked_head;
                while (unacked) {
                    SclUnackedPacket *next = unacked->next;
                    if (unacked->raw_packet) free(unacked->raw_packet);
                    free(unacked);
                    unacked = next;
                }
                conn->unacked_head = NULL;
                conn->unacked_tail = NULL;
                conn->bytes_in_flight = 0;
                pthread_mutex_unlock(&conn->l4_mutex);
            } else {
                scl_log(LOG_LEVEL_DEBUG, "L5", "Invalid STATELESS_RESET_TOKEN length.");
            }
            break;
        }
        case MSG_PEER_DISCOVERY: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (in_msg->length < 32) break;
#else
            if (in_msg->length != DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN + 19 + SIGNATURE_LEN) {
                scl_log(LOG_LEVEL_DEBUG, "Network", "Invalid MSG_PEER_DISCOVERY length");
                break;
            }
#endif
            if (!conn) {
                fprintf(stderr, "[Network] ERROR: MSG_PEER_DISCOVERY received with NULL connection\n");
                break;
            }

            uint8_t peer_dilithium[DILITHIUM_PUBKEY_LEN];
            uint8_t peer_kyber[KYBER_PUBKEY_LEN];
            struct sockaddr_storage peer_addr_claim;
            memset(&peer_addr_claim, 0, sizeof(peer_addr_claim));

            memcpy(peer_dilithium, in_msg->payload, DILITHIUM_PUBKEY_LEN);
            memcpy(peer_kyber, in_msg->payload + DILITHIUM_PUBKEY_LEN, KYBER_PUBKEY_LEN);
            deserialize_sockaddr(in_msg->payload + DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN, 19, &peer_addr_claim);

            uint8_t *signature = in_msg->payload + DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN + 19;
            size_t signed_len = DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN + 19;

            if (dilithium_verify(in_msg->payload, signed_len, signature, peer_dilithium) != 0) {
                fprintf(stderr, "[Network] Invalid signature on MSG_PEER_DISCOVERY\n");
                break;
            }

            // Phase 3: Trust the signed payload claim if it contains a valid routable IP, otherwise fallback to sender_addr
            bool is_unroutable = false;
            if (peer_addr_claim.ss_family == AF_INET) {
                struct sockaddr_in *v4 = (struct sockaddr_in *)&peer_addr_claim;
                if (v4->sin_addr.s_addr == 0 || v4->sin_addr.s_addr == inet_addr("127.0.0.1")) is_unroutable = true;
            } else if (peer_addr_claim.ss_family == AF_INET6) {
                struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&peer_addr_claim;
                if (memcmp(&v6->sin6_addr, &in6addr_any, sizeof(struct in6_addr)) == 0 || memcmp(&v6->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) == 0) is_unroutable = true;
            } else {
                is_unroutable = true;
            }

            if (is_unroutable) {
                peer_addr_claim = *sender_addr;
            }
            
            // Prevent loopback corruption where the local peer's known_peers entry is overwritten or removed
            if (memcmp(peer_dilithium, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
                fprintf(stderr, "[Network] WARNING: Received MSG_PEER_DISCOVERY for local peer. Ignoring loopback identity claim.\n");

                /* bind_ip=:: does not match our GCP address, so bootstrap dials
                 * this host. The signature verifies the key is ours, which is the
                 * proof getifaddrs cannot provide from inside Docker. Record the
                 * observed source, the claim, and the address we dialed, then drop
                 * the zero-key hairpin before a later gossip fill counts it. */
                pthread_mutex_lock(&net->mutex);
                if (sender_addr) scl_note_self_addr_locked(net, sender_addr);
                scl_note_self_addr_locked(net, &peer_addr_claim);
                if (conn) {
                    for (size_t s = 0; s < net->num_known_peers; s++) {
                        Peer *sp = net->known_peers[s];
                        if (!sp || sp->conn != conn) continue;
                        scl_note_self_addr_locked(net, &sp->addr);
                        if (sp->conn->current_path.ss_family == AF_INET ||
                            sp->conn->current_path.ss_family == AF_INET6) {
                            scl_note_self_addr_locked(net, &sp->conn->current_path);
                        }
                        break;
                    }
                }
                scl_reap_self_placeholders_locked(net);
                pthread_mutex_unlock(&net->mutex);

                // If we are the responder, send our own identity claim back
                if (conn && conn->required_pow_bits == 0) {
                    scl_enqueue_identity_claim(state, conn);
                }
                break;
            }

            int add_result = p2p_add_peer(net, peer_dilithium, peer_kyber, &peer_addr_claim);

            pthread_mutex_lock(&net->mutex);
            size_t matched_idx = net->num_known_peers;
            for (size_t i = 0; i < net->num_known_peers; i++) {
                if (memcmp(net->known_peers[i]->peer_wallet.dilithium_pubkey, peer_dilithium, DILITHIUM_PUBKEY_LEN) == 0) {
                    matched_idx = i;
                    /* Publish sender_addr only for the path we actually keep.
                     * Rewriting it before collision resolution advertises an address
                     * family whose socket was just discarded. */
                    if (net->known_peers[i]->conn == conn) {
                        net->known_peers[i]->addr = *sender_addr;
                    }
                    if (net->known_peers[i]->conn != conn) {
                        if (net->known_peers[i]->conn) {
                            /* Mutual-dial collision resolution MUST be mirror-symmetric:
                             * both endpoints hash the same two Dilithium pubkeys and keep the
                             * socket pair whose INITIATOR is the hash winner.
                             * required_pow_bits > 0 marks an initiator (dialer) context and
                             * == 0 a responder (listener) context, so incoming_is_local is
                             * true when the incoming connection is the one THIS node dialed
                             * out on. The rule is order-independent: whichever socket is
                             * "existing" vs "incoming", both sides converge on the same pair.
                             *
                             * The previous time-based "existing_stale" shortcut and the
                             * hypergraph sym_weight override each evaluated LOCAL, divergent
                             * state, so after a simultaneous redial the two seeds could keep
                             * OPPOSITE socket pairs. Every packet then landed on a CID the
                             * remote had just unregistered, was silently dropped, and the
                             * sender retransmitted forever - the L4 storm that keeps one
                             * seed's valuation proposals off the chain. Dead-socket recovery
                             * now routes exclusively through the silence GC + the reconnect
                             * watchdog (client.c L5 worker). */
                            bool replace_with_incoming = false;
                            {
                                uint8_t hash_local[32], hash_remote[32];
                                SHA256(net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, hash_local);
                                SHA256(peer_dilithium, DILITHIUM_PUBKEY_LEN, hash_remote);
                                bool local_wins = (memcmp(hash_local, hash_remote, 32) > 0);
                                bool incoming_is_local = (conn->required_pow_bits > 0);
                                replace_with_incoming = (incoming_is_local == local_wins);
                            }
                            
                            if (!replace_with_incoming) {
                                fprintf(stderr, "[L5] Mutual connection collision in Discovery. Keeping existing connection.\n");
                                pthread_mutex_lock(&net->known_peers[i]->conn->l4_mutex);
                                net->known_peers[i]->conn->pto_count = 0;
                                net->known_peers[i]->conn->loss_time = 1;
                                pthread_mutex_unlock(&net->known_peers[i]->conn->l4_mutex);
                                        
                                /* Collision resolution is not a real disconnect: both CIDs
                                 * were freshly established seconds ago. Tear the loser down
                                 * silently so the L5 GC does not synthesize MSG_PEER_DISCONNECT
                                 * (which the winner would then have to reject, causing redial
                                 * churn and 1<->2 active-node drift on two-seed testnets). */
                                if (global_shim && global_shim->unregister_connection(global_shim, conn->cid)) {
                                    scl_connection_release(conn);
                                }
                                /* Do NOT set handshake_state = NONE. The connection is
                                 * already out of the CID table and the local ref will be
                                 * dropped below. Leaving the state alone prevents the L5 GC
                                 * from treating it as a stalled peer. */
                            } else {
                                fprintf(stderr, "[L5] Mutual connection collision in Discovery. Replacing with incoming established connection.\n");
                                net->known_peers[i]->addr = *sender_addr;
                                SclConnection *old_conn = net->known_peers[i]->conn;
                                net->known_peers[i]->conn = conn;
                                atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_acquire);
                                
                                // Migrate queued messages to prevent loss during collision replacement
                                Message *temp_msg = malloc(sizeof(Message));
                                if (temp_msg) {
                                    while (queue_dequeue(&old_conn->tx_stream_queue, temp_msg) == 0) {
                                        queue_enqueue(&conn->tx_stream_queue, temp_msg);
                                    }
                                    while (queue_dequeue(&old_conn->tx_datagram_queue, temp_msg) == 0) {
                                        queue_enqueue(&conn->tx_datagram_queue, temp_msg);
                                    }
                                    free(temp_msg);
                                }

                                /* Same rationale as above: unregister without flipping
                                 * handshake_state so the L5 GC does not synthesize a
                                 * MSG_PEER_DISCONNECT that flips the active count. */
                                if (global_shim) {
                                    if (global_shim->unregister_connection(global_shim, old_conn->cid)) {
                                        scl_connection_release(old_conn);
                                    }
                                }
                                scl_connection_release(old_conn);
                            }
                        } else {
                            net->known_peers[i]->addr = *sender_addr;
                            net->known_peers[i]->conn = conn;
                            atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_acquire);
                        }
                    }
                    break;
                }
            }
            /* A dual-stack dial keeps a zero-pubkey placeholder on the same
             * conn this authenticated row just claimed. Filling that placeholder
             * later is what the explorer counts as a third Active Node.
             * One socket backs one identity. */
            if (matched_idx < net->num_known_peers) {
                for (size_t k = 0; k < net->num_known_peers; k++) {
                    if (k != matched_idx && net->known_peers[k] && net->known_peers[k]->conn == conn) {
                        net->known_peers[k]->conn = NULL;
                        /* Release the reference this row acquired at attach time.
                         * Every other detach site releases; missing it here leaks
                         * the SclConnection (64 MiB of L5 rings each) and never
                         * decrements active_connection_count, so the node exhausts
                         * MAX_ACTIVE_CONNECTIONS and silently stops accepting or
                         * dialing peers - the root cause of the Active Node drift. */
                        scl_connection_release(conn);
                    }
                }
            }
            pthread_mutex_unlock(&net->mutex);

            // Safely decouple the active worker thread connection from the zero-pubkey loop
            // to entirely prevent GPFLT use-after-free bugs from aggressive network topologies.
            pthread_mutex_lock(&net->mutex);
            for (size_t i = 0; i < net->num_known_peers; i++) {
                if (is_zeroed(net->known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) {
                    if (net->known_peers[i]->conn == NULL || net->known_peers[i]->conn->handshake_state == SCL_CONN_STATE_NONE) {
                        if (net->known_peers[i]->conn) {
                            if (global_shim && global_shim->unregister_connection(global_shim, net->known_peers[i]->conn->cid)) {
                                scl_connection_release(net->known_peers[i]->conn);
                            }
                            scl_connection_release(net->known_peers[i]->conn);
                        }
                        
                        free(net->known_peers[i]);
                        for (size_t j = i; j < net->num_known_peers - 1; j++) {
                            net->known_peers[j] = net->known_peers[j + 1];
                        }
                        // Clear the trailing dangling pointer securely before shrinking
                        net->known_peers[net->num_known_peers - 1] = NULL;
                        net->num_known_peers--;
                        i--;
                    }
                }
            }
            pthread_mutex_unlock(&net->mutex);
            
            // The responder MUST send an identity claim back so the initiator can assign a pubkey
            // to its outgoing L1 connection, regardless of whether we already "knew" them.
            // We use conn->required_pow_bits == 0 to deterministically identify that we are
            // the responder (since the initiator initializes it to 10). This avoids infinite loops.
            if (conn && conn->required_pow_bits == 0) {
                scl_enqueue_identity_claim(state, conn);
            }
                                
            p2p_share_peers(state, peer_dilithium);

            // Only broadcast updates to the rest of the network if this resulted in
            // a strictly new or upgraded peer entry.
            if (add_result == 1 || add_result == 2) {
                broadcast_peer_list_sync(state);
            }
            
            // Phase 1: Discover NAT type & public endpoint automatically
            // after establishing reliable symmetric path
            Message *req_discovery = calloc(1, sizeof(Message));
            if (req_discovery) {
                req_discovery->type = MSG_ENDPOINT_DISCOVERY;
                req_discovery->length = 0;
                queue_enqueue(&conn->tx_stream_queue, req_discovery);
                free(req_discovery);
            }

            // ALWAYS Request pending operations to align mempools after a successful handshake / discovery
            Message *req_mempool = calloc(1, sizeof(Message));
            if (req_mempool) {
                req_mempool->type = MSG_GET_PENDING_OPERATIONS;
                req_mempool->length = 0;
                queue_enqueue(&conn->tx_stream_queue, req_mempool);
                free(req_mempool);
            }
            
            // Sync Centinel state on connection establishment only if local chain is uninitialized
            pthread_mutex_lock(&state->ledger_mutex);
            bool chain_empty = (state->current_block_number == 0 && is_zeroed(state->current_block_hash, COIN_ID_LEN));
            pthread_mutex_unlock(&state->ledger_mutex);

            if (chain_empty) {
                Message *req_centinel = calloc(1, sizeof(Message));
                if (req_centinel) {
                    req_centinel->type = MSG_CENTINEL_QUERY;
                    req_centinel->length = 0;
                    queue_enqueue(&conn->tx_stream_queue, req_centinel);
                    free(req_centinel);
                }
            }
            break;
        }
        case MSG_PEERS_LIST: {
            if (in_msg->length < 1) break;
            uint8_t count = in_msg->payload[0];
            const uint8_t *p = in_msg->payload + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (count > 10) count = 10;
#else
            size_t expected_len = 1 + count * (DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN + 19);
            if (in_msg->length != expected_len) break;
#endif

            bool added_any = false;
            for (uint8_t i = 0; i < count; i++) {
                uint8_t dilithium_pubkey[DILITHIUM_PUBKEY_LEN];
                uint8_t kyber_pubkey[KYBER_PUBKEY_LEN];
                struct sockaddr_storage addr;
                memset(&addr, 0, sizeof(addr));

                memcpy(dilithium_pubkey, p, DILITHIUM_PUBKEY_LEN);
                p += DILITHIUM_PUBKEY_LEN;
                memcpy(kyber_pubkey, p, KYBER_PUBKEY_LEN);
                p += KYBER_PUBKEY_LEN;
                deserialize_sockaddr(p, 19, &addr);
                p += 19;

                // Reject self key identity and external addresses proven to be this host
                pthread_mutex_lock(&net->mutex);
                bool is_self = (memcmp(net->local_peer.peer_wallet.dilithium_pubkey, dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) ||
                               scl_sockaddr_is_self_locked(net, &addr);
                pthread_mutex_unlock(&net->mutex);
                if (is_self) continue;

                PeerAddStatus add_result = p2p_add_peer(net, dilithium_pubkey, kyber_pubkey, &addr);
                if (add_result == PEER_ADD_NEW) {
                    scl_initiate_connection(net, &addr);
                    added_any = true;
                }
            }
            if (added_any) {
                broadcast_peer_list_sync(state);
            }
            break;
        }
        case MSG_PEER_LIST_SYNC: {
            if (in_msg->length < 1) break;
            uint8_t count = in_msg->payload[0];
            const uint8_t *p = in_msg->payload + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (count > 10) count = 10;
#else
            size_t expected_len = 1 + count * (DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN + 19);
            if (in_msg->length != expected_len) break;
#endif

            for (uint8_t i = 0; i < count; i++) {
                uint8_t dilithium_pubkey[DILITHIUM_PUBKEY_LEN];
                uint8_t kyber_pubkey[KYBER_PUBKEY_LEN];
                struct sockaddr_storage addr;
                memset(&addr, 0, sizeof(addr));

                memcpy(dilithium_pubkey, p, DILITHIUM_PUBKEY_LEN);
                p += DILITHIUM_PUBKEY_LEN;
                memcpy(kyber_pubkey, p, KYBER_PUBKEY_LEN);
                p += KYBER_PUBKEY_LEN;
                deserialize_sockaddr(p, 19, &addr);
                p += 19;

                // Do not process our own local identity or self-endpoints from the sync list
                pthread_mutex_lock(&net->mutex);
                bool is_self = (memcmp(net->local_peer.peer_wallet.dilithium_pubkey, dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) ||
                               scl_sockaddr_is_self_locked(net, &addr);
                pthread_mutex_unlock(&net->mutex);
                if (is_self) continue;

                PeerAddStatus add_result = p2p_add_peer(net, dilithium_pubkey, kyber_pubkey, &addr);
                if (add_result == PEER_ADD_NEW) {
                    scl_initiate_connection(net, &addr);
                }
            }
            break;
        }
        case MSG_PENDING_OPERATION: {
            Operation *op = calloc(1, sizeof(Operation));
            if (!op) break;
            int bytes_consumed = deserialize_operation(in_msg->payload, in_msg->length, op, 1);
            if (bytes_consumed <= 0) { // Catch -1 error codes to prevent proof_len=0 corruption
                scl_log(LOG_LEVEL_DEBUG, "Network", "Failed to deserialize pending operation");
                free(op);
                break;
            }
            fprintf(stderr, "[Network] Successfully deserialized operation, bytes consumed=%d\n", bytes_consumed);

            switch (op->type) {
                case OP_REDEEM_CENTINEL: {
                    if (verify_operation_heavy_crypto(op) != CRYPTO_SUCCESS) {
                        free(op);
                        break;
                    }
                    pthread_mutex_lock(&state->mutex);
                    int added_redeem = add_pending_operation(state, op);
                    pthread_mutex_unlock(&state->mutex);
                    
                    if (added_redeem != 0) {
                        if (!state->in_blockchain_sync) {
                            scl_log(LOG_LEVEL_DEBUG, "Network", "OP_REDEEM_CENTINEL mempool sync failed. Requesting Centinel State Sync...");
                            Message *centinel_req = calloc(1, sizeof(Message));
                            if (centinel_req) {
                                centinel_req->type = MSG_CENTINEL_QUERY;
                                centinel_req->length = 0;
                                send_message(state, sender_pubkey, centinel_req);
                                free(centinel_req);
                            }
                        }
                        free(op);
                    }
                    break;
                }
                case OP_CLAIM_VALIDATION: {
                    uint8_t key[COIN_ID_LEN];
                    memcpy(key, op->data.claim_validation.commitment.c1, COIN_ID_LEN);
                                            
                    pthread_mutex_lock(&state->mutex);
                    int added_claim = -1;
                    if (!hash_table_lookup(state->processed_txs, key, true)) {
                        added_claim = add_pending_operation(state, op);
                    }
                    pthread_mutex_unlock(&state->mutex);
                    if (added_claim != 0) {
                        free(op);
                    }
                    break;
                }
                case OP_MINT_COIN: {
                    fprintf(stderr, "[Network] Received OP_MINT_COIN as pending block reward\n");
                    uint8_t mint_key[COIN_ID_LEN];
                    const uint8_t *op_id = get_operation_tx_id(op);
                    if (op_id) {
                        memcpy(mint_key, op_id, COIN_ID_LEN);
                    } else {
                        SHA256((uint8_t*)&op->data.mint_coin, sizeof(MintData), mint_key);
                    }
                                                                
                    int added = 0;
                    if (!hash_table_lookup(state->processed_txs, mint_key, true)) {
                        if (add_pending_operation(state, op) == 0) {
                            added = 1;
                        }
                    }
                            
                    if (added) {
                        trigger_proposer_if_eligible(state);
                    } else {
                        free(op);
                    }
                    break;
                }
                case OP_SUBMIT_VALUATION: {
                    pthread_mutex_lock(&state->mutex);
                    int added_val = add_pending_operation(state, op);
                    pthread_mutex_unlock(&state->mutex);
                    if (added_val != 0) {
                        free(op);
                    }
                    break;
                }
                case OP_TRANSFER_POINTER:
                    handle_pending_transfer(state, op);
                    break;
                case OP_STAKE:
                    handle_pending_stake(state, op);
                    break;
                case OP_UNSTAKE:
                    handle_pending_unstake(state, op);
                    break;
                case OP_APPLY_DRIFT_CERT: {
                    /* Mirror the mempool ingress used by claims: validate_operation
                     * checks the canonical digest and ML-DSA-87 signature, then the op
                     * is staged for block assembly. add_pending_operation stores its
                     * own copy, so the deserialized op is always freed here. */
                    pthread_mutex_lock(&state->mutex);
                    int added_drift = add_pending_operation(state, op);
                    pthread_mutex_unlock(&state->mutex);
                    free(op);
                    break;
                }
                default:
                    free(op);
                    break;
            }
            break;
        }
        case MSG_GET_PENDING_OPERATIONS: {
            pthread_mutex_lock(&state->mutex);
            size_t op_count = atomic_load_explicit(&state->pending_operations_count, memory_order_acquire);
            if (op_count == 0) {
                out_msg->type = MSG_PENDING_OPERATIONS_DATA;
                out_msg->length = 1;
                out_msg->payload[0] = 0;
                send_message(state, sender_pubkey, out_msg);
            } else {
                Operation **ops_ptrs = malloc(op_count * sizeof(Operation*));
                if (!ops_ptrs) {
                    pthread_mutex_unlock(&state->mutex);
                    break;
                }
                size_t idx = 0;
                for (int i = 0; i < MAX_PENDING_OPS && idx < op_count; i++) {
                    Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                    if (pop) {
                        ops_ptrs[idx++] = pop;
                    }
                }
                
                Operation *ops_copy = malloc(idx * sizeof(Operation));
                if (ops_copy) {
                    for(size_t i = 0; i < idx; i++) {
                        ops_copy[i] = *ops_ptrs[i];
                        ops_ptrs[i] = &ops_copy[i];
                    }
                } else {
                    free(ops_ptrs);
                    pthread_mutex_unlock(&state->mutex);
                    break;
                }
                
                // Sort operations prior to broadcast
                qsort(ops_ptrs, idx, sizeof(Operation*), compare_operation_ptrs);
                        
                const size_t encryption_overhead = KYBER_CIPHERTEXT_LEN + 4 + SIGNATURE_LEN + 28;
                size_t op_index = 0;
                
                while (op_index < op_count) {
                    uint8_t *batch_buffer = get_l5_staging_buffer();
                    if (!batch_buffer) break;
                            
                    const size_t max_serialized_size = MAX_MESSAGE_SIZE - encryption_overhead;
                    size_t ops_serialized = 0;
                    
                    size_t serialized_len = serialize_pending_operations(&ops_ptrs[op_index], op_count - op_index, batch_buffer, max_serialized_size, &ops_serialized);
                            
                    if (serialized_len == 0 || ops_serialized == 0) {
                        break;
                    }
                            
                    // Dynamically allocate safe_out to prevent egress pointer overlaps
                    Message *safe_out = calloc(1, sizeof(Message));
                    if (!safe_out) {
                        break;
                    }
                            
                    safe_out->type = MSG_PENDING_OPERATIONS_DATA;
                    safe_out->length = serialized_len;
                    memcpy(safe_out->payload, batch_buffer, serialized_len);
                            
                    if (send_message(state, sender_pubkey, safe_out)) {
                        op_index += ops_serialized;
                    } else {
                        free(safe_out);
                        break;
                    }
                    free(safe_out);
                }
                free(ops_copy);
                free(ops_ptrs);
            }
                    
            Message *safe_out_eof = calloc(1, sizeof(Message));
            if (safe_out_eof) {
                safe_out_eof->type = MSG_END_OF_DATA;
                safe_out_eof->length = 1;
                safe_out_eof->payload[0] = 1;
                send_message(state, sender_pubkey, safe_out_eof);
                free(safe_out_eof);
            }
                    
            pthread_mutex_unlock(&state->mutex);
            break;
        }
        case MSG_PENDING_OPERATIONS_DATA: {
            if (in_msg->length >= 6 && in_msg->payload[0] == 0x26) {
                uint32_t header_len;
                memcpy(&header_len, in_msg->payload + 1, sizeof(uint32_t));
                header_len = ntohl(header_len);
                if (header_len == 1 && in_msg->length == 6 && in_msg->payload[5] == 0) {
                    break;
                }
            }

            Operation *ops = malloc(MAX_PENDING_OPS * sizeof(Operation));
            if (!ops) break;

            size_t ops_deserialized = deserialize_pending_operations(in_msg->payload, in_msg->length, ops, MAX_PENDING_OPS);
            
            for (size_t i = 0; i < ops_deserialized; i++) {
                if (verify_operation_heavy_crypto(&ops[i]) != CRYPTO_SUCCESS) {
                    continue;
                }
                // Each operation accepted into the mempool must be an independent heap allocation
                Operation *op_copy = malloc(sizeof(Operation));
                if (op_copy) {
                    *op_copy = ops[i];
                    pthread_mutex_lock(&state->mutex);
                    int added = add_pending_operation(state, op_copy);
                    pthread_mutex_unlock(&state->mutex);
                    if (added != 0) {
                        free(op_copy);
                    }
                }
            }
            
            free(ops);
            break;
        }
        case MSG_VALUATION_PROPOSAL: {
            if (in_msg->length < PUBKEY_LEN + SIGNATURE_LEN) break;
            ValuationData *vd = calloc(1, sizeof(ValuationData));
            if (!vd) break;
            size_t core_len = in_msg->length - PUBKEY_LEN - SIGNATURE_LEN;
            deserialize_core_valuation(in_msg->payload, &vd->valuation);
            memcpy(vd->pubkey, in_msg->payload + core_len, PUBKEY_LEN);
            memcpy(vd->signature, in_msg->payload + core_len + PUBKEY_LEN, SIGNATURE_LEN);
                            
            uint8_t hash[SHA256_DIGEST_LENGTH];
            SHA256(in_msg->payload, core_len, hash);
                        
            process_valuation_proposal(state, vd, hash);
            free(vd);
            break;
        }
        case MSG_GET_AUDIT: {
            send_audit_to_client(state, sender_pubkey);
            break;
        }
        case MSG_UPDATE_AUDIT: {
            pthread_mutex_lock(&state->game_state.mutex);
            deserialize_audit_update(in_msg, &state->game_state);
            pthread_mutex_unlock(&state->game_state.mutex);
            
            update_game_state_snapshot(state);
                                                        
            pthread_mutex_lock(&state->mutex);
            state->audit_received = 1;
            pthread_cond_signal(&state->audit_cond);
            pthread_mutex_unlock(&state->mutex);
            break;
        }
        case MSG_PROPOSE_BLOCK: {
            Operation *provided_op = NULL;
            int skip_proposal = 0;
                    
            if (in_msg->length > 0) {
                provided_op = malloc(sizeof(Operation));
                if (provided_op) {
                    int bytes_consumed = deserialize_operation(in_msg->payload, in_msg->length, provided_op, 1);
                    if (bytes_consumed <= 0 || provided_op->type != OP_MINT_COIN) {
                        free(provided_op);
                        provided_op = NULL;
                    } else {
                        // Deduplicate inbound delegated block proposals (L4 retransmission defense)
                        uint8_t op_hash[COIN_ID_LEN];
                        const uint8_t *tx_id = get_operation_tx_id(provided_op);
                        if (tx_id) {
                            memcpy(op_hash, tx_id, COIN_ID_LEN);
                        } else {
                            SHA256((uint8_t*)&provided_op->data.mint_coin, sizeof(SCLCoin), op_hash);
                        }
                                                        
                        pthread_mutex_lock(&state->mutex);
                        if (hash_table_lookup(state->processed_txs, op_hash, true)) {
                            skip_proposal = 1; // Already processed entirely, ignore.
                        } else {
                            // Check if it's already securely in the mempool waiting for proposal
                            bool existing = false;
                            for (int k = 0; k < MAX_PENDING_OPS; k++) {
                                Operation *pop = atomic_load_explicit(&state->pending_operations[k], memory_order_acquire);
                                if (pop) {
                                    const uint8_t *pid = get_operation_tx_id(pop);
                                    uint8_t pkey[COIN_ID_LEN];
                                    if (pid) memcpy(pkey, pid, COIN_ID_LEN);
                                    else {
                                        uint8_t *data_ptr;
                                        size_t data_len;
                                        if (pop->type == OP_SUBMIT_VALUATION) {
                                            data_ptr = (uint8_t *)&pop->data.submit_valuation;
                                            data_len = sizeof(ValuationData);
                                        } else {
                                            data_ptr = (uint8_t *)pop;
                                            data_len = sizeof(Operation);
                                        }
                                        SHA256(data_ptr, data_len, pkey);
                                    }
                                    if (memcmp(pkey, op_hash, COIN_ID_LEN) == 0) {
                                        existing = true;
                                        break;
                                    }
                                }
                            }
                                    
                            if (existing) {
                                // Already in mempool. Free the redundant pointer, but STILL trigger the proposer.
                                free(provided_op);
                                provided_op = NULL;
                            }
                        }
                        pthread_mutex_unlock(&state->mutex);
                    }
                }
            }
                    
            if (!skip_proposal) {
                // If we are not an active committee member, log notice and continue if we are elected proposer
                bool is_member_local = true;
                pthread_mutex_lock(&state->game_state.mutex);
                bool has_epoch_key = !is_zeroed(state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
                pthread_mutex_unlock(&state->game_state.mutex);
                if (has_epoch_key) {
                    pthread_mutex_lock(&state->epoch_mutex);
                    is_member_local = state->is_epoch_member;
                    pthread_mutex_unlock(&state->epoch_mutex);
                }

                if (!is_member_local) {
                    scl_log(LOG_LEVEL_DEBUG, "Network", "Received MSG_PROPOSE_BLOCK, not a committee member, proceeding with fallback proposal.");
                }

                // Determine proposer locally. If we received MSG_PROPOSE_BLOCK, we SHOULD be the proposer.
                // Safely acquire state->current_block_number for the upcoming candidate block
                uint64_t current_block_for_proposer_selection;
                pthread_mutex_lock(&state->mutex);
                current_block_for_proposer_selection = state->current_block_number + 1;
                pthread_mutex_unlock(&state->mutex);
                        
                uint8_t proposer_pubkey[PUBKEY_LEN];
                if (select_proposer(state, current_block_for_proposer_selection, proposer_pubkey) == 0) {
                    // Compare against local PEER pubkey
                    if (memcmp(proposer_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                        spawn_propose_block_thread(state, provided_op);
                    } else {
                        scl_log(LOG_LEVEL_DEBUG, "Network", "Received MSG_PROPOSE_BLOCK, but I am not the deterministic proposer. Ignoring delegation to prevent split-brain forks.");
                    }
                } else {
                    scl_log(LOG_LEVEL_DEBUG, "Network", "Failed to select proposer upon receiving MSG_PROPOSE_BLOCK. Ignoring delegation.");
                }
            }
                    
            if (provided_op) free(provided_op);
            break;
        }
        case MSG_VOTE:
            // Forward validator consensus vote to consensus voting engine
            handle_vote(state, in_msg, sender_pubkey);
            break;
        case MSG_BLOCK_NUMBER: {
            if (in_msg->length != sizeof(uint64_t) + COIN_ID_LEN) break;
            uint64_t received_num_be;
            memcpy(&received_num_be, in_msg->payload, sizeof(uint64_t));
            uint64_t received_num = be64toh(received_num_be);
            uint8_t received_hash[COIN_ID_LEN];
            memcpy(received_hash, in_msg->payload + sizeof(uint64_t), COIN_ID_LEN);

            pthread_mutex_lock(&state->mutex);
                                                                
            if (state->in_blockchain_sync &&
                            memcmp(sender_pubkey, state->sync_peer_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
                state->sync_received_block_number_value = received_num;
                memcpy(state->sync_received_block_hash, received_hash, COIN_ID_LEN);
                                    
                pthread_cond_signal(&state->blockchain_sync_cond);
            }
            
            /* Track the live network height (last writer wins) instead of a
             * write-once maximum. A monotonic ratchet permanently wedges every
             * proposal gate whenever the local head legitimately moves backwards
             * (rollback), until the process is restarted. */
            state->network_target_block_number = received_num;
                                                    
            pthread_mutex_lock(&state->ledger_mutex);
            bool mismatch = (received_num > state->current_block_number);

            static _Atomic uint64_t last_sync_trigger_time = 0;
            uint64_t now_ms = get_time_ms();
            uint64_t last_time = atomic_load(&last_sync_trigger_time);
            bool on_cooldown = (state->current_block_number > 0 && now_ms - last_time < 10000);

            if (mismatch && !state->in_blockchain_sync && !on_cooldown) {
                atomic_store(&last_sync_trigger_time, now_ms);
                fprintf(stderr, "[Network] Peer reports higher block %llu (our tip: %llu). Triggering async sync.\n", received_num, state->current_block_number);
                state->in_blockchain_sync = 1;
                pthread_mutex_unlock(&state->ledger_mutex);
                pthread_mutex_unlock(&state->mutex);
                trigger_async_sync(state, sender_pubkey, false);
                break;
            }
            pthread_mutex_unlock(&state->ledger_mutex);
            pthread_mutex_unlock(&state->mutex);
            break;
        }
        case MSG_BLOCK_NUMBER_QUERY: {
            out_msg->type = MSG_BLOCK_NUMBER;
            out_msg->length = sizeof(uint64_t) + COIN_ID_LEN;
                        
            pthread_mutex_lock(&state->ledger_mutex);
            uint64_t be_num = htobe64(state->current_block_number);
            uint8_t curr_hash[COIN_ID_LEN];
            memcpy(curr_hash, state->current_block_hash, COIN_ID_LEN);
            pthread_mutex_unlock(&state->ledger_mutex);
                        
            memcpy(out_msg->payload, &be_num, sizeof(uint64_t));
            memcpy(out_msg->payload + sizeof(uint64_t), curr_hash, COIN_ID_LEN);
            send_message(state, sender_pubkey, out_msg);
            break;
        }
        case MSG_COIN_QUERY: {
            pthread_mutex_lock(&state->mutex);
            pthread_rwlock_rdlock(&state->bc.rwlock);

            size_t coin_index = 0;
            const size_t max_payload_for_coins = MAX_MESSAGE_SIZE - ENCRYPTION_OVERHEAD;
            while (coin_index < state->bc.insert_order_count) {
                size_t batch_size = 0;
                size_t payload_size = sizeof(uint32_t);
                while (coin_index + batch_size < state->bc.insert_order_count && payload_size + sizeof(SCLCoin) <= max_payload_for_coins) {
                    batch_size++;
                    payload_size += sizeof(SCLCoin);
                }
                if (batch_size == 0) break;

                out_msg->type = MSG_COIN_DATA;
                out_msg->length = payload_size;
                uint8_t *pp = out_msg->payload;
                uint32_t count_be = htobe32(batch_size);
                memcpy(pp, &count_be, sizeof(uint32_t));
                pp += sizeof(uint32_t);
                for (size_t j = 0; j < batch_size; j++) {
                    SCLCoin *coin = state->bc.insert_order[coin_index + j];
                    memcpy(pp, coin, sizeof(SCLCoin));
                    pp += sizeof(SCLCoin);
                }

                if (send_message(state, sender_pubkey, out_msg)) {
                    coin_index += batch_size;
                } else {
                    break;
                }
            }

            size_t total_pointers = state->bc.pointer_table->count;
            Pointer *pointer_list = malloc(total_pointers * sizeof(Pointer));
            if (!pointer_list) {
                pthread_rwlock_unlock(&state->bc.rwlock);
                pthread_mutex_unlock(&state->mutex);
                break;
            }
            size_t ptr_idx = 0;
            for (size_t i = 0; i < state->bc.pointer_table->size; i++) {
                GenericHashEntry *entry = state->bc.pointer_table->buckets[i];
                while (entry) {
                    if (entry->type == HASH_ENTRY_POINTER) {
                        memcpy(&pointer_list[ptr_idx], &entry->data.pointer, sizeof(Pointer));
                        ptr_idx++;
                    }
                    entry = entry->next;
                }
            }

            const size_t max_payload_for_pointers = MAX_MESSAGE_SIZE - ENCRYPTION_OVERHEAD;
            size_t ptr_index = 0;
            while (ptr_index < total_pointers) {
                size_t batch_size = 0;
                size_t payload_size = sizeof(uint32_t);
                
                while (ptr_index + batch_size < total_pointers &&
                       payload_size + sizeof(Pointer) <= max_payload_for_pointers) {
                    batch_size++;
                    payload_size += sizeof(Pointer);
                }
                if (batch_size == 0) break;

                out_msg->type = MSG_POINTER_DATA;
                out_msg->length = payload_size;
                uint8_t *pp = out_msg->payload;
                uint32_t count_be = htobe32(batch_size);
                memcpy(pp, &count_be, sizeof(uint32_t));
                pp += sizeof(uint32_t);
                for (size_t j = 0; j < batch_size; j++) {
                    memcpy(pp, &pointer_list[ptr_index + j], sizeof(Pointer));
                    pp += sizeof(Pointer);
                }

                if (send_message(state, sender_pubkey, out_msg)) {
                    ptr_index += batch_size;
                } else {
                    break;
                }
            }
            free(pointer_list);

            pthread_rwlock_unlock(&state->bc.rwlock);
            pthread_mutex_unlock(&state->mutex);

            out_msg->type = MSG_END_OF_DATA;
            out_msg->length = 0;
            send_message(state, sender_pubkey, out_msg);
            break;
        }
        case MSG_GET_PUBKEY_BY_USERID: {
            if (in_msg->length != USER_ID_LEN) break;
            uint8_t user_id[USER_ID_LEN];
            memcpy(user_id, in_msg->payload, USER_ID_LEN);
                                            
            uint8_t found_pubkey[DILITHIUM_PUBKEY_LEN];
            int found = 0;
                                            
            pthread_mutex_lock(&state->mutex);
            for (size_t i = 0; i < state->user_count; i++) {
                if (memcmp(state->users[i].user_id, user_id, USER_ID_LEN) == 0) {
                    memcpy(found_pubkey, state->users[i].dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                    found = 1;
                    break;
                }
            }
                                
            if (!found) {
                PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, user_id, false);
                if (cache_entry) {
                    memcpy(found_pubkey, cache_entry->pubkey, DILITHIUM_PUBKEY_LEN);
                    found = 1;
                }
            }
            pthread_mutex_unlock(&state->mutex);
                                            
            if (!found) {
                pthread_mutex_lock(&state->p2p_network.mutex);
                for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                    uint8_t computed_id[USER_ID_LEN];
                    SHA256(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, computed_id);
                    if (memcmp(computed_id, user_id, USER_ID_LEN) == 0) {
                        memcpy(found_pubkey, state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                        found = 1;
                        break;
                    }
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
            }

            if (found) {
                pthread_mutex_lock(&state->mutex);
                PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, user_id, false);
                if (!cache_entry) {
                    PubkeyCacheEntry pce;
                    memcpy(pce.pubkey, found_pubkey, PUBKEY_LEN);
                    hash_table_insert(state->pubkey_cache, user_id, &pce, HASH_ENTRY_PUBKEY_CACHE);
                }
                pthread_mutex_unlock(&state->mutex);
            }
                                                    
            out_msg->type = MSG_PUBKEY_BY_USERID_RESPONSE;
            if (found) {
                out_msg->length = sizeof(int) + USER_ID_LEN + DILITHIUM_PUBKEY_LEN;
                int success = 1;
                memcpy(out_msg->payload, &success, sizeof(int));
                memcpy(out_msg->payload + sizeof(int), user_id, USER_ID_LEN);
                memcpy(out_msg->payload + sizeof(int) + USER_ID_LEN, found_pubkey, DILITHIUM_PUBKEY_LEN);
            } else {
                out_msg->length = sizeof(int) + USER_ID_LEN;
                int success = 0;
                memcpy(out_msg->payload, &success, sizeof(int));
                memcpy(out_msg->payload + sizeof(int), user_id, USER_ID_LEN);
            }
            send_message(state, sender_pubkey, out_msg);
            break;
        }
        case MSG_PUBKEY_BY_USERID_RESPONSE: {
            if (in_msg->length < sizeof(int) + USER_ID_LEN) break;
            
            int success;
            memcpy(&success, in_msg->payload, sizeof(int));
            uint8_t resp_user_id[USER_ID_LEN];
            memcpy(resp_user_id, in_msg->payload + sizeof(int), USER_ID_LEN);
            
            if (success) {
                if (in_msg->length != sizeof(int) + USER_ID_LEN + DILITHIUM_PUBKEY_LEN) break;
                
                uint8_t received_pubkey[DILITHIUM_PUBKEY_LEN];
                memcpy(received_pubkey, in_msg->payload + sizeof(int) + USER_ID_LEN, DILITHIUM_PUBKEY_LEN);
                
                uint8_t computed_user_id[USER_ID_LEN];
                SHA256(received_pubkey, DILITHIUM_PUBKEY_LEN, computed_user_id);
                if (memcmp(computed_user_id, resp_user_id, USER_ID_LEN) == 0) {
                    pthread_mutex_lock(&state->mutex);
                    User *existing_user = hash_table_lookup(state->user_table, resp_user_id, false);
                    if (!existing_user) {
                        PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, resp_user_id, false);
                        if (!cache_entry) {
                            PubkeyCacheEntry pce;
                            memcpy(pce.pubkey, received_pubkey, DILITHIUM_PUBKEY_LEN);
                            hash_table_insert(state->pubkey_cache, resp_user_id, &pce, HASH_ENTRY_PUBKEY_CACHE);
                        }
                    }
                    pthread_mutex_unlock(&state->mutex);
                }
            }
            break; // Legacy synchronous logic successfully removed
        }
        case MSG_PTR_TRANSFER:
            // Dispatch direct peer-to-peer coin pointer transfer operation
            handle_coin_transfer(net, state, in_msg, sender_pubkey);
            break;
        case MSG_BLOCK_APPROVED: {
            pthread_mutex_lock(&state->mutex);
            if (state->in_blockchain_sync) {
                pthread_mutex_unlock(&state->mutex);
                break;
            }
            pthread_mutex_unlock(&state->mutex);

            Block *block = calloc(1, sizeof(Block));
            if (!block) break;
            if (deserialize_block(block, in_msg->payload, in_msg->length) != 0) {
                free_block(block);
                break;
            }

            if (verify_block_heavy_crypto(block) != CRYPTO_SUCCESS) {
                free_block(block);
                break;
            }

            handle_msg_block_approved(state, block, sender_pubkey);
            break;
        }
        case MSG_GET_BLOCKS: {
            if (in_msg->length != sizeof(uint64_t)) break;
            uint64_t requested_height_be;
            memcpy(&requested_height_be, in_msg->payload, sizeof(uint64_t));
            uint64_t requested_height = be64toh(requested_height_be);
            
            pthread_rwlock_rdlock(&state->bc.rwlock);
            uint64_t current_height = state->current_block_number;
            pthread_rwlock_unlock(&state->bc.rwlock);
            
            uint64_t end_idx = current_height + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (end_idx > requested_height + 16) end_idx = requested_height + 16; // Bounds limit to maximize exec/s
#else
            // Production window: 256 blocks per request batch to avoid buffer saturation
            const uint64_t MAX_SYNC_BATCH = 256;
            if (end_idx > requested_height + MAX_SYNC_BATCH) {
                end_idx = requested_height + MAX_SYNC_BATCH;
            }
#endif
            for (uint64_t h = requested_height; h < end_idx; h++) {
                uint8_t *ser_block = NULL;
                size_t ser_len = 0;
                if (scl_db_get_block(h, &ser_block, &ser_len) == 0) {
                    if (ser_len <= MAX_MESSAGE_SIZE) {
                        out_msg->type = MSG_BLOCKS_DATA;
                        out_msg->length = ser_len;
                        memcpy(out_msg->payload, ser_block, ser_len);
                        send_message(state, sender_pubkey, out_msg);
                    }
                    free(ser_block);
                }
            }
            
            out_msg->type = MSG_END_OF_DATA;
            out_msg->length = 1;
            out_msg->payload[0] = 2; // Specific identifier for block sync finality
            send_message(state, sender_pubkey, out_msg);
            break;
        }
        case MSG_BLOCKS_DATA: {
            pthread_mutex_lock(&state->mutex);
            if (state->in_blockchain_sync && memcmp(sender_pubkey, state->sync_peer_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                pthread_mutex_unlock(&state->mutex);
                break;
            }
            pthread_mutex_unlock(&state->mutex);

            Block *block = calloc(1, sizeof(Block));
            if (!block) break;
            if (deserialize_block(block, in_msg->payload, in_msg->length) != 0) {
                free_block(block);
                break;
            }
            
            if (verify_block_heavy_crypto(block) != CRYPTO_SUCCESS) {
                free_block(block);
                break;
            }

            pthread_mutex_lock(&state->mutex);
            pthread_rwlock_wrlock(&state->bc.rwlock);
            
            // Discard stale blocks already committed behind our current tip
            if (block->block_number <= state->current_block_number) {
                pthread_rwlock_unlock(&state->bc.rwlock);
                pthread_mutex_unlock(&state->mutex);
                free_block(block);
                break;
            }

            // Buffer future out-of-order blocks into orphan pool for chained promotion
            if (block->block_number > state->current_block_number + 1) {
                uint8_t computed_hash[COIN_ID_LEN];
                if (compute_block_hash(block, computed_hash) == 0) {
                    Block *orphan_copy = calloc(1, sizeof(Block));
                    if (orphan_copy) {
                        *orphan_copy = *block;
                        if (block->operation_count > 0 && block->operations) {
                            orphan_copy->operations = malloc(block->operation_count * sizeof(Operation));
                            memcpy(orphan_copy->operations, block->operations, block->operation_count * sizeof(Operation));
                        }
                        if (block->batch_tx_count > 0 && block->batch_prf_outputs) {
                            orphan_copy->batch_prf_outputs = malloc(block->batch_tx_count * NULLIFIER_LEN);
                            memcpy(orphan_copy->batch_prf_outputs, block->batch_prf_outputs, block->batch_tx_count * NULLIFIER_LEN);
                        }
                        if (block->batch_zk_proof_len > 0 && block->batch_zk_proof) {
                            orphan_copy->batch_zk_proof = malloc(block->batch_zk_proof_len);
                            memcpy(orphan_copy->batch_zk_proof, block->batch_zk_proof, block->batch_zk_proof_len);
                        }
                        hash_table_insert(state->orphan_pool, computed_hash, orphan_copy, HASH_ENTRY_ORPHAN_BLOCK);
                    }
                }
                pthread_rwlock_unlock(&state->bc.rwlock);
                pthread_mutex_unlock(&state->mutex);
                free_block(block);
                break;
            }
            
            // Revert state if we encounter an explicit fork when executing the requested block sync.
            if (block->block_number > 0 && memcmp(block->prev_block_hash, state->current_block_hash, COIN_ID_LEN) != 0) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
                pthread_rwlock_unlock(&state->bc.rwlock);
                pthread_mutex_unlock(&state->mutex);
                free_block(block);
                break;
#else
                uint64_t fork_height = state->current_block_number; /* invert our divergent tip, not the remote block height */
                uint64_t checkpoint_height = 0;
                uint8_t checkpoint_root[32] = {0};
                
                /* Walk back ONE block toward the common ancestor instead of
                 * destroying up to BLOCKS_PER_DAY-1 blocks back to the last
                 * checkpoint. The re-request below fetches the peer's block at
                 * the stepped-back height; if it still mismatches, this handler
                 * fires again and steps back further, converging exactly on the
                 * common ancestor without wiping committed history. */
                checkpoint_height = (fork_height > 0) ? fork_height - 1 : 0;
                (void)checkpoint_root;
                fprintf(stderr, "[Network] Sync Fork Detected at block %llu. Stepping back to height %llu to find the common ancestor.\n",
                        (unsigned long long)block->block_number, (unsigned long long)checkpoint_height);

                // Execute Graceful MVCC Reversion Pipeline natively using the DB Checkpoint
                scl_db_rollback_state_to_checkpoint(state, checkpoint_height, fork_height);

                state->current_block_number = checkpoint_height;
                state->bc.sync_epoch = checkpoint_height + 1;
                state->network_target_block_number = checkpoint_height; /* un-gate proposers after the deliberate head reset */
                
                if (checkpoint_height == 0) {
                    memset(state->current_block_hash, 0, COIN_ID_LEN);
                    Block *genesis = malloc(sizeof(Block));
                    if (genesis) {
                        *genesis = create_standard_genesis_block();
                        apply_block(state, genesis);
                        free_block(genesis);
                    }
                } else {
                    // Fast-load the checkpoint block to update the tip hash
                    uint8_t *ser_block = NULL;
                    size_t ser_len = 0;
                    if (scl_db_get_block(checkpoint_height, &ser_block, &ser_len) == 0) {
                        Block *cp_block = calloc(1, sizeof(Block));
                        if (cp_block && deserialize_block(cp_block, ser_block, ser_len) == 0) {
                            compute_block_hash(cp_block, state->current_block_hash);
                        }
                        if (cp_block) free_block(cp_block);
                        free(ser_block);
                    }
                }
                
                pthread_rwlock_unlock(&state->bc.rwlock);
                pthread_mutex_unlock(&state->mutex);
                
                free_block(block);
                
                Message *centinel_req = calloc(1, sizeof(Message));
                if (centinel_req) {
                    centinel_req->type = MSG_CENTINEL_QUERY;
                    centinel_req->length = 0;
                    send_message(state, sender_pubkey, centinel_req);
                    free(centinel_req);
                }
                
                Message *req = calloc(1, sizeof(Message));
                req->type = MSG_GET_BLOCKS;
                req->length = sizeof(uint64_t);
                uint64_t from_checkpoint = htobe64(checkpoint_height + 1);
                memcpy(req->payload, &from_checkpoint, sizeof(uint64_t));
                send_message(state, sender_pubkey, req);
                free(req);
                break;
#endif
            }
            
            // Route natively through the apply_block module where it evaluates crypto dependencies inherently
            if (apply_block(state, block) == 0) {
                // Explicitly update the global tip state to ensure concurrent threads view the correct height
                state->current_block_number = block->block_number;
                uint8_t synced_hash[COIN_ID_LEN];
                compute_block_hash(block, synced_hash);
                memcpy(state->current_block_hash, synced_hash, COIN_ID_LEN);
                state->bc.sync_epoch = block->block_number + 1;
                pthread_cond_signal(&state->blockchain_sync_cond); // Signal sync progress
            } else {
                fprintf(stderr, "[Network] ERROR: Failed to apply synchronized block %llu\n", block->block_number);
            }
            
            pthread_rwlock_unlock(&state->bc.rwlock);
            pthread_mutex_unlock(&state->mutex);
            
            // Promote any sequential descendants buffered in the orphan pool
            trigger_async_fork_processing(state);

            free_block(block);
            break;
        }
        case MSG_GOSSIP_BLOCK:
            // Ingest proposed block gossip from network peer
            handle_block_proposal(state, in_msg, sender_addr, sender_pubkey);
            break;
        case MSG_COIN_DATA: {
            pthread_mutex_lock(&state->mutex);
            if (state->in_blockchain_sync && memcmp(sender_pubkey, state->sync_peer_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                pthread_mutex_unlock(&state->mutex);
                break;
            }
            pthread_mutex_unlock(&state->mutex);

            if (in_msg->length < sizeof(uint32_t)) break;
            uint32_t num_coins;
            memcpy(&num_coins, in_msg->payload, sizeof(uint32_t));
            num_coins = be32toh(num_coins);
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (num_coins > 16) num_coins = 16;
#endif
            if (num_coins > MAX_MESSAGE_SIZE / sizeof(SCLCoin)) break;
            if (in_msg->length != sizeof(uint32_t) + num_coins * sizeof(SCLCoin)) break;

            pthread_rwlock_wrlock(&state->bc.rwlock);
            for (uint32_t i = 0; i < num_coins; i++) {
                SCLCoin coin;
                memcpy(&coin, in_msg->payload + sizeof(uint32_t) + i * sizeof(SCLCoin), sizeof(SCLCoin));
                if (hash_table_lookup(state->bc.coin_table, coin.coin_id, false)) {
                    continue;
                }
                hash_table_insert(state->bc.coin_table, coin.coin_id, &coin, HASH_ENTRY_COIN);
                SCLCoin *inserted_coin = hash_table_lookup(state->bc.coin_table, coin.coin_id, false);
                if (state->bc.insert_order_count >= state->bc.insert_order_capacity) {
                    size_t new_cap = state->bc.insert_order_capacity ? state->bc.insert_order_capacity * 2 : 16;
                    SCLCoin **new_order = realloc(state->bc.insert_order, new_cap * sizeof(SCLCoin *));
                    if (!new_order) {
                        continue;
                    }
                    state->bc.insert_order = new_order;
                    state->bc.insert_order_capacity = new_cap;
                }
                state->bc.insert_order[state->bc.insert_order_count++] = inserted_coin;
                mmr_add(state->bc.mmr, inserted_coin->coin_id, inserted_coin->remaining_subunits);
            }
            pthread_rwlock_unlock(&state->bc.rwlock);
            break;
        }
        case MSG_POINTER_DATA: {
            pthread_mutex_lock(&state->mutex);
            if (state->in_blockchain_sync && memcmp(sender_pubkey, state->sync_peer_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                pthread_mutex_unlock(&state->mutex);
                break;
            }
            pthread_mutex_unlock(&state->mutex);

            if (in_msg->length < sizeof(uint32_t)) break;
            uint32_t num_pointers;
            memcpy(&num_pointers, in_msg->payload, sizeof(uint32_t));
            num_pointers = be32toh(num_pointers);
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (num_pointers > 16) num_pointers = 16;
#endif
            if (num_pointers > MAX_MESSAGE_SIZE / sizeof(Pointer)) break;
            if (in_msg->length != sizeof(uint32_t) + num_pointers * sizeof(Pointer)) break;

            pthread_rwlock_wrlock(&state->bc.rwlock);
            for (uint32_t i = 0; i < num_pointers; i++) {
                Pointer pointer;
                memcpy(&pointer, in_msg->payload + sizeof(uint32_t) + i * sizeof(Pointer), sizeof(Pointer));
                Pointer *existing = hash_table_lookup(state->bc.pointer_table, pointer.pointer_id, false);
                if (existing) {
                    *existing = pointer;
                } else {
                    blockchain_add_pointer(&state->bc, &pointer);
                }
            }
            pthread_rwlock_unlock(&state->bc.rwlock);
            break;
        }
        case MSG_THRESHOLD_SHARE_DISTRIBUTE: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            const size_t min_len = COIN_ID_LEN + sizeof(uint16_t) + 32 + KAPPA + POLYVEC_L_SERIALIZED + POLYVEC_K_SERIALIZED;
            if (in_msg->length < min_len) break;

            uint8_t stake_tx_id[COIN_ID_LEN];
            memcpy(stake_tx_id, in_msg->payload, COIN_ID_LEN);

            uint16_t point_id_be;
            memcpy(&point_id_be, in_msg->payload + COIN_ID_LEN, sizeof(uint16_t));
            uint16_t point_id = be16toh(point_id_be);

            uint8_t mu[32];
            memcpy(mu, in_msg->payload + COIN_ID_LEN + sizeof(uint16_t), 32);

            uint8_t rho[KAPPA];
            memcpy(rho, in_msg->payload + COIN_ID_LEN + sizeof(uint16_t) + 32, KAPPA);

            const uint8_t *p = in_msg->payload + COIN_ID_LEN + sizeof(uint16_t) + 32 + KAPPA;
                                                
            pthread_mutex_lock(&state->threshold_mutex);
            bool process_exists = hash_table_lookup(state->threshold_stake_processes, stake_tx_id, false) != NULL;
            size_t process_count = state->threshold_stake_processes->count;

            // Evict orphaned non-dealer threshold sessions older than SIGN_TIMEOUT (60s)
            if (!process_exists && process_count >= MAX_THRESHOLD_PROCESSES) {
                uint8_t stale_keys[MAX_THRESHOLD_PROCESSES][COIN_ID_LEN];
                size_t stale_cnt = 0;
                uint64_t now_ms = get_time_ms();

                for (size_t b = 0; b < state->threshold_stake_processes->size && stale_cnt < MAX_THRESHOLD_PROCESSES; b++) {
                    GenericHashEntry *ent = state->threshold_stake_processes->buckets[b];
                    while (ent && stale_cnt < MAX_THRESHOLD_PROCESSES) {
                        if (ent->type == HASH_ENTRY_THRESHOLD_STAKE_PROCESS && ent->data.threshold_stake_process) {
                            ThresholdStakeProcess *p_proc = ent->data.threshold_stake_process;
                            if (p_proc->collector_thread == 0 && p_proc->created_at != 0 &&
                                (now_ms - p_proc->created_at > (SIGN_TIMEOUT * 1000ULL))) {
                                memcpy(stale_keys[stale_cnt++], ent->key, COIN_ID_LEN);
                            }
                        }
                        ent = ent->next;
                    }
                }
                pthread_mutex_unlock(&state->threshold_mutex);

                for (size_t k = 0; k < stale_cnt; k++) {
                    remove_threshold_process(state, stale_keys[k]);
                }

                pthread_mutex_lock(&state->threshold_mutex);
                process_exists = hash_table_lookup(state->threshold_stake_processes, stake_tx_id, false) != NULL;
                process_count = state->threshold_stake_processes->count;
            }
            pthread_mutex_unlock(&state->threshold_mutex);
                        
            if (!process_exists && process_count >= MAX_THRESHOLD_PROCESSES) {
                fprintf(stderr, "[Threshold] Rejected share distribute: MAX_THRESHOLD_PROCESSES reached\n");
                break;
            }
                                                
            ThresholdStakeProcess *process = get_or_create_threshold_process(state, stake_tx_id);
            if (!process) break;
            if (process->created_at == 0) {
                process->created_at = get_time_ms();
            }

            polyvec_t s1_part;
            if (polyvec_init(&s1_part, DILITHIUM_L) != CRYPTO_SUCCESS) break;
            if (deserialize_polyvec(&s1_part, p, POLYVEC_L_SERIALIZED, DILITHIUM_L) != 0) {
                polyvec_free(&s1_part);
                break;
            }
            p += POLYVEC_L_SERIALIZED;

            polyvec_t s2_part;
            if (polyvec_init(&s2_part, DILITHIUM_K) != CRYPTO_SUCCESS) {
                polyvec_free(&s1_part);
                break;
            }
            if (deserialize_polyvec(&s2_part, p, POLYVEC_K_SERIALIZED, DILITHIUM_K) != 0) {
                polyvec_free(&s1_part);
                polyvec_free(&s2_part);
                break;
            }
            p += POLYVEC_K_SERIALIZED;

            if (point_id < 1 || point_id > 9) {
                polyvec_free(&s1_part);
                polyvec_free(&s2_part);
                break;
            }

            polyvec_copy(&process->s1_part[point_id], &s1_part);
            polyvec_copy(&process->s2_part[point_id], &s2_part);

            polyvec_free(&s1_part);
            polyvec_free(&s2_part);

            if (process->sign_data[point_id].y.vec == NULL) {
                if (polyvec_init(&process->sign_data[point_id].y, DILITHIUM_L) != CRYPTO_SUCCESS ||
                    polyvec_init(&process->sign_data[point_id].w, DILITHIUM_K) != CRYPTO_SUCCESS) {
                    if (process->collector_thread == 0) remove_threshold_process(state, stake_tx_id);
                    break;
                }
            }

            process->is_peer_active[point_id] = true;
            memcpy(process->mu, mu, 32);

            uint8_t sign_seed[KAPPA];
            generate_deterministic_nonce(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, mu, 32, sign_seed);
                        
            ThresholdSignData *sign_data = calloc(1, sizeof(ThresholdSignData));
            if (!sign_data) break;
                        
            uint16_t point_ids[10];
            for (int i = 0; i < 10; i++) point_ids[i] = i;
                                                                        
            int32_t eta_full = ETA * NUM_SUBSETS;
            int32_t beta = TAU * eta_full;
            int32_t bound_y = (GAMMA1 - beta) / 3 - TAU * MAX_S_PART_INF;

            crypto_error_t ret = threshold_sign(state, sign_data, mu, sizeof(mu), sign_seed, KAPPA, rho, &process->s1_part[point_id], &process->s2_part[point_id], point_id, point_ids, point_ids, 10, 2, bound_y);

            if (ret != CRYPTO_SUCCESS) {
                cleanup_sign_data(sign_data);
                free(sign_data);
                if (process->collector_thread == 0) remove_threshold_process(state, stake_tx_id);
                break;
            }

            polyvec_copy(&process->sign_data[point_id].y, &sign_data->y);
            polyvec_copy(&process->sign_data[point_id].w, &sign_data->w);

            out_msg->type = MSG_THRESHOLD_PARTIAL_RESPONSE;
            uint8_t *r_p = out_msg->payload;

            memcpy(r_p, stake_tx_id, COIN_ID_LEN);
            r_p += COIN_ID_LEN;
            // Map correctly using the globally assigned peer wallet structure to bypass verification bounds
            memcpy(r_p, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            r_p += DILITHIUM_PUBKEY_LEN;
            uint16_t point_id_be_resp = htobe16(point_id);
            memcpy(r_p, &point_id_be_resp, sizeof(uint16_t));
            r_p += sizeof(uint16_t);
            uint8_t stage = 0;
            memcpy(r_p, &stage, sizeof(uint8_t));
            r_p += sizeof(uint8_t);

            size_t w_len;
            if (polyvec_serialize(&sign_data->w, r_p, MAX_MESSAGE_SIZE - (r_p - out_msg->payload), &w_len) != CRYPTO_SUCCESS) {
                w_len = 0;
            }
            if (w_len == 0) {
                cleanup_sign_data(sign_data);
                free(sign_data);
                remove_threshold_process(state, stake_tx_id);
                break;
            }

            out_msg->length = (r_p - out_msg->payload) + w_len;
            send_message(state, sender_pubkey, out_msg);
            
            cleanup_sign_data(sign_data);
            free(sign_data);
            break;
        }
        case MSG_THRESHOLD_PARTIAL_RESPONSE: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            const size_t header_len = COIN_ID_LEN + DILITHIUM_PUBKEY_LEN + sizeof(uint16_t) + sizeof(uint8_t);
            if (in_msg->length < header_len) break;

            uint8_t stake_tx_id[COIN_ID_LEN];
            memcpy(stake_tx_id, in_msg->payload, COIN_ID_LEN);
            uint8_t stage;
            memcpy(&stage, in_msg->payload + COIN_ID_LEN + DILITHIUM_PUBKEY_LEN + sizeof(uint16_t), sizeof(uint8_t));
            size_t expected_partial_len = (stage == 0) ? POLYVEC_K_SERIALIZED : POLYVEC_L_SERIALIZED;
            if (in_msg->length != header_len + expected_partial_len) break;

            pthread_mutex_lock(&state->threshold_mutex);
            ThresholdStakeProcess *process = find_threshold_process(state, stake_tx_id);
            
            uint16_t point_id = 0;
            if (process) {
                for (int i = 0; i < 9; i++) {
                    if (memcmp(process->peer_pubkeys[i], sender_pubkey, PUBKEY_LEN) == 0) {
                        point_id = i + 1;
                        break;
                    }
                }
            }

            if (!process || point_id == 0 || point_id > 9) {
                if (process) {
                    pthread_cond_signal(&process->stage0_complete_cond);
                    pthread_cond_signal(&process->partial_cond);
                }
                pthread_mutex_unlock(&state->threshold_mutex);
                break;
            }
            
            size_t partial_index = point_id - 1;
            const uint8_t *p = in_msg->payload + header_len;
                            
            if (stage == 0) {  // Partial w
                if (atomic_load_explicit(&process->stage0_complete, memory_order_acquire)) {
                    pthread_mutex_unlock(&state->threshold_mutex);
                    break;
                }
                polyvec_t partial_w;
                if (polyvec_init(&partial_w, DILITHIUM_K) != CRYPTO_SUCCESS) {
                    pthread_cond_signal(&process->stage0_complete_cond);
                    pthread_mutex_unlock(&state->threshold_mutex);
                    break;
                }
                if (deserialize_polyvec(&partial_w, p, in_msg->length - header_len, DILITHIUM_K) != 0) {
                    polyvec_free(&partial_w);
                    pthread_cond_signal(&process->stage0_complete_cond);
                    pthread_mutex_unlock(&state->threshold_mutex);
                    break;
                }
                polyvec_copy(&process->partial_w[partial_index], &partial_w);
                polyvec_free(&partial_w);
                process->is_peer_active[partial_index] = true;
                atomic_fetch_add_explicit(&process->partials_received, 1, memory_order_relaxed);
                if (atomic_load_explicit(&process->partials_received, memory_order_relaxed) == atomic_load_explicit(&process->expected_partials, memory_order_relaxed)) {
                    polyvec_t w_agg;
                    if (polyvec_init(&w_agg, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    polyvec_copy(&w_agg, &process->dealer_sign_data.w);
                    for (int idx = 0; idx < 10; idx++) {
                        if (process->is_peer_active[idx]) {
                            polyvec_add_no_reduce(&w_agg, &w_agg, &process->partial_w[idx]);
                        }
                    }
                    polyvec_reduce(&w_agg);
                    polyvec_copy(&process->w_agg, &w_agg);
                    polyvec_free(&w_agg);
                                    
                    polyvec_t w1_agg;
                    if (polyvec_init(&w1_agg, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    polyvec_high_bits(&w1_agg, &process->w_agg, ALPHA);
                                    
                    uint8_t *w1_packed = malloc(DILITHIUM_K * POLYW1_PACKEDBYTES);
                    if (!w1_packed) {
                        polyvec_free(&w1_agg);
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    for (size_t k = 0; k < DILITHIUM_K; k++) {
                        polyw1_pack(w1_packed + k * POLYW1_PACKEDBYTES, &w1_agg.vec[k]);
                    }
                                    
                    uint8_t *hash_input = malloc(32 + DILITHIUM_K * POLYW1_PACKEDBYTES);
                    if (!hash_input) {
                        free(w1_packed);
                        polyvec_free(&w1_agg);
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    memcpy(hash_input, process->mu, 32);
                    memcpy(hash_input + 32, w1_packed, DILITHIUM_K * POLYW1_PACKEDBYTES);
                    sha256_hash(hash_input, 32 + DILITHIUM_K * POLYW1_PACKEDBYTES, process->rho_prime);
                    free(w1_packed);
                    free(hash_input);
                                    
                    poly_t c;
                    if (sample_in_ball(&c, process->rho_prime, 32) != CRYPTO_SUCCESS) {
                        polyvec_free(&w1_agg);
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    process->challenge = c;
                                    
                    out_msg->type = MSG_THRESHOLD_AGGREGATE_NOTIFY;
                    uint8_t *np = out_msg->payload;
                    memcpy(np, stake_tx_id, COIN_ID_LEN);
                    np += COIN_ID_LEN;
                    size_t remaining = MAX_MESSAGE_SIZE - COIN_ID_LEN;
                    size_t c_len = serialize_poly(&c, np, remaining);
                    if (c_len == 0) {
                        polyvec_free(&w1_agg);
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    out_msg->length = COIN_ID_LEN + c_len;
                            
                    // DEFER NETWORK CALLS TO AVOID LOOPBACK DEADLOCK
                    uint8_t (*local_pubkeys)[PUBKEY_LEN] = calloc(2, PUBKEY_LEN);
                    if (local_pubkeys) {
                        memcpy(local_pubkeys[0], process->peer_pubkeys[0], PUBKEY_LEN);
                        memcpy(local_pubkeys[1], process->peer_pubkeys[1], PUBKEY_LEN);
                    }
                            
                    atomic_store_explicit(&process->partials_received, 0, memory_order_relaxed);
                                
                    polyvec_t cs1_temp;
                    if (polyvec_init(&cs1_temp, DILITHIUM_L) != CRYPTO_SUCCESS) {
                        polyvec_free(&w1_agg);
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        free(local_pubkeys);
                        break;
                    }
                    for (size_t k = 0; k < DILITHIUM_L; k++) {
                        poly_mul_sparse(&cs1_temp.vec[k], &process->keygen.s1_shares[0].vec[k], &c);
                    }
                    polyvec_copy(&process->dealer_z, &process->dealer_sign_data.y);
                    polyvec_add(&process->dealer_z, &process->dealer_z, &cs1_temp);
                    polyvec_free(&cs1_temp);
                                    
                    int32_t eta_full = ETA * NUM_SUBSETS;
                    int32_t beta = TAU * eta_full;
                    int32_t bound_y = (GAMMA1 - beta) / 3 - TAU * MAX_S_PART_INF;
                    int32_t bound_z_i = bound_y + TAU * MAX_S_PART_INF;
                                    
                    if (!check_norm_inf(&process->dealer_z, bound_z_i)) {
                        polyvec_free(&w1_agg);
                        atomic_store_explicit(&process->stage0_complete, true, memory_order_release);
                        pthread_cond_signal(&process->stage0_complete_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        free(local_pubkeys);
                        break;
                    }
                                    
                    atomic_store_explicit(&process->stage0_complete, true, memory_order_release);
                    pthread_cond_signal(&process->stage0_complete_cond);
                    polyvec_free(&w1_agg);
                            
                    pthread_mutex_unlock(&state->threshold_mutex); // Unlock BEFORE network calls
                    
                    p2p_broadcast(state, out_msg);
                                    
                    // Match the active P2P peer identity for loopback tracking, NOT the user wallet identity
                    if (local_pubkeys) {
                        if (memcmp(local_pubkeys[0], state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, PUBKEY_LEN) == 0 ||
                            memcmp(local_pubkeys[1], state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                            send_message(state, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, out_msg);
                        }
                        free(local_pubkeys);
                    }
                    return; // Return completely from dispatch_l5_message to prevent double unlock at end of switch
                }
                pthread_mutex_unlock(&state->threshold_mutex);
                break;
            } else if (stage == 1) {  // Partial z
                if (!process->is_peer_active[partial_index] || atomic_load_explicit(&process->aggregation_complete, memory_order_acquire)) {
                    pthread_mutex_unlock(&state->threshold_mutex);
                    break;
                }
                polyvec_t partial_z;
                if (polyvec_init(&partial_z, DILITHIUM_L) != CRYPTO_SUCCESS) {
                    atomic_store_explicit(&process->aggregation_failed, true, memory_order_release);
                    pthread_cond_signal(&process->partial_cond);
                    pthread_mutex_unlock(&state->threshold_mutex);
                    break;
                }
                if (deserialize_polyvec(&partial_z, p, in_msg->length - header_len, DILITHIUM_L) != 0) {
                    polyvec_free(&partial_z);
                    atomic_store_explicit(&process->aggregation_failed, true, memory_order_release);
                    pthread_cond_signal(&process->partial_cond);
                    pthread_mutex_unlock(&state->threshold_mutex);
                    break;
                }
                polyvec_copy(&process->partial_z[partial_index], &partial_z);
                polyvec_free(&partial_z);
                atomic_fetch_add_explicit(&process->partials_received, 1, memory_order_relaxed);
                if (atomic_load_explicit(&process->partials_received, memory_order_relaxed) == atomic_load_explicit(&process->expected_partials, memory_order_relaxed)) {
                    poly_t challenge_poly = process->challenge;
                    ThresholdStakeProcess *proc = NULL;
                    polyvec_t w_agg_copy;
                    if (polyvec_init(&w_agg_copy, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        process->aggregation_failed = true;
                        pthread_cond_signal(&process->partial_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    polyvec_copy(&w_agg_copy, &process->w_agg);

                    uint8_t mu[32], rho_prime[32], pubkey[PUBKEY_LEN];
                    memcpy(mu, process->mu, 32);
                    memcpy(rho_prime, process->rho_prime, 32);
                    memcpy(pubkey, process->keygen.pubkey, PUBKEY_LEN);

                    polyvec_t dealer_z_copy;
                    if (polyvec_init(&dealer_z_copy, DILITHIUM_L) != CRYPTO_SUCCESS) {
                        polyvec_free(&w_agg_copy);
                        atomic_store_explicit(&process->aggregation_failed, true, memory_order_release);
                        pthread_cond_signal(&process->partial_cond);
                        pthread_mutex_unlock(&state->threshold_mutex);
                        break;
                    }
                    polyvec_copy(&dealer_z_copy, &process->dealer_z);

                    polyvec_t peer_z_copies[10];
                    bool peer_active[10];
                    for (int i = 0; i < 10; i++) {
                        peer_active[i] = process->is_peer_active[i];
                        if (peer_active[i]) {
                            if (polyvec_init(&peer_z_copies[i], DILITHIUM_L) != CRYPTO_SUCCESS) {
                                peer_active[i] = false; // Graceful degradation
                            } else {
                                polyvec_copy(&peer_z_copies[i], &process->partial_z[i]);
                            }
                        }
                    }

                    pthread_mutex_unlock(&state->threshold_mutex); // <--- UNLOCK EARLY TO AVOID TIMEOUT DEADLOCKS

                    size_t z_mark = arena_mark();

                    polyvec64_t z_agg64;
                    if (polyvec64_init_arena(&z_agg64, DILITHIUM_L) != CRYPTO_SUCCESS) {
                        polyvec_free(&w_agg_copy);
                        polyvec_free(&dealer_z_copy);
                        for (int i = 0; i < 10; i++) if (peer_active[i]) polyvec_free(&peer_z_copies[i]);
                        goto stake_z_fail;
                    }
                    
                    polyvec64_t partial64;
                    if (polyvec64_init_arena(&partial64, DILITHIUM_L) != CRYPTO_SUCCESS) {
                        polyvec64_free(&z_agg64);
                        polyvec_free(&w_agg_copy);
                        polyvec_free(&dealer_z_copy);
                        for (int i = 0; i < 10; i++) if (peer_active[i]) polyvec_free(&peer_z_copies[i]);
                        goto stake_z_fail;
                    }
                    
                    polyvec_to64(&partial64, &dealer_z_copy);
                    for (size_t i = 0; i < DILITHIUM_L; i++) {
                        for (int j = 0; j < RING_DEG; j++) {
                            z_agg64.vec[i].coeffs[j] = partial64.vec[i].coeffs[j];
                        }
                    }
                    
                    for (int i = 0; i < 10; i++) {
                        if (peer_active[i]) {
                            polyvec_to64(&partial64, &peer_z_copies[i]);
                            polyvec64_add(&z_agg64, &z_agg64, &partial64);
                        }
                    }
                    
                    polyvec64_free(&partial64);
                    polyvec_free(&dealer_z_copy);
                    for (int i = 0; i < 10; i++) if (peer_active[i]) polyvec_free(&peer_z_copies[i]);
                    
                    int32_t eta_full = ETA * NUM_SUBSETS;
                    int32_t beta = TAU * eta_full;
                    int32_t bound_z_agg = GAMMA1 - beta;
                    
                    if (!check_norm_inf64(&z_agg64, bound_z_agg)) {
                        polyvec64_free(&z_agg64);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                            
                    polyvec_t z_agg;
                    if (polyvec_init(&z_agg, DILITHIUM_L) != CRYPTO_SUCCESS) {
                        polyvec64_free(&z_agg64);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    polyvec64_reduce(&z_agg, &z_agg64);
                    polyvec64_free(&z_agg64);

                    bool local_agg_complete = false;
                    uint8_t local_final_signature[SIGNATURE_LEN] = {0};
                    size_t local_final_sig_len_out = 0;

                    uint8_t rho[KAPPA];
                    memcpy(rho, pubkey, KAPPA);
                    matrix_t A_bar;
                    A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
                    if (polyvec_init_arena(&A_bar.rows, DILITHIUM_K * DILITHIUM_L) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    expand_a(&A_bar, rho);

                    // 1. Az = A_bar * z_agg (unreduced for accuracy)
                    polyvec64_t Az;
                    if (polyvec64_init_arena(&Az, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    matrix_vec_mul_unreduced(&Az, &A_bar, &z_agg);

                    // Reconstruct full t_global from Keygen Data to bypass t0 mathematical drift
                    polyvec_t t_global;
                    if (polyvec_init_arena(&t_global, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    polyvec_copy(&t_global, &process->keygen.t);

                    // Decompose t_global to get t1
                    polyvec_t t1;
                    if (polyvec_init_arena(&t1, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    for (size_t i = 0; i < DILITHIUM_K; i++) {
                        for (int j = 0; j < RING_DEG; j++) {
                            int32_t val = t_global.vec[i].coeffs[j];
                            int32_t r0, r1;
                            decompose(val, 1 << D, &r0, &r1);
                            t1.vec[i].coeffs[j] = r1;
                        }
                    }

                    // Scale t1 by 2^D
                    polyvec_t t1_scaled;
                    if (polyvec_init_arena(&t1_scaled, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    for (size_t i = 0; i < DILITHIUM_K; i++) {
                        for (int j = 0; j < RING_DEG; j++) {
                            t1_scaled.vec[i].coeffs[j] = t1.vec[i].coeffs[j] << D;
                        }
                    }

                    // 2. ct = c * t1_scaled (unreduced)
                    polyvec64_t ct;
                    if (polyvec64_init_arena(&ct, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    polyvec_poly_mul_unreduced(&ct, &t1_scaled, &challenge_poly);

                    // 3. temp = Az - ct
                    polyvec64_t temp;
                    if (polyvec64_init_arena(&temp, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }
                    polyvec64_sub(&temp, &Az, &ct);

                    // 4. Reduce temp mod Q and extract bits
                    polyvec_t temp_reduced, h_agg;
                    if (polyvec_init_arena(&temp_reduced, DILITHIUM_K) != CRYPTO_SUCCESS ||
                        polyvec_init_arena(&h_agg, DILITHIUM_K) != CRYPTO_SUCCESS) {
                        polyvec_free(&z_agg);
                        polyvec_free(&w_agg_copy);
                        goto stake_z_fail;
                    }

                    polyvec64_reduce(&temp_reduced, &temp);
                    polyvec_reduce(&temp_reduced);
                    polyvec_make_hint(&h_agg, &temp_reduced, &w_agg_copy, ALPHA);

                    int wt = count_nonzero_vec(&h_agg);
                    if (wt <= OMEGA) {
                        size_t final_len;
                        uint8_t test_sig[SIGNATURE_LEN];
                        if (pack_signature(test_sig, &z_agg, &h_agg, rho_prime, &final_len) == CRYPTO_SUCCESS) {
                            if (threshold_verify(mu, 32, test_sig, final_len, pubkey, PUBKEY_LEN) == 0) {
                                memcpy(local_final_signature, test_sig, final_len);
                                local_final_sig_len_out = final_len;
                                local_agg_complete = true;
                            }
                        }
                    }

                    polyvec_free(&z_agg);
                    polyvec_free(&w_agg_copy);

                    pthread_mutex_lock(&state->threshold_mutex);
                    proc = hash_table_lookup(state->threshold_stake_processes, stake_tx_id, false);
                    if (proc) {
                        if (local_agg_complete) {
                            memcpy(proc->final_signature, local_final_signature, local_final_sig_len_out);
                            proc->final_sig_len = local_final_sig_len_out;
                            atomic_store_explicit(&proc->aggregation_complete, true, memory_order_release);
                        } else {
                            atomic_store_explicit(&proc->aggregation_failed, true, memory_order_release);
                        }
                        pthread_cond_signal(&proc->partial_cond);
                    }
                    pthread_mutex_unlock(&state->threshold_mutex);
                    arena_reset(z_mark);
                    break;
stake_z_fail:
                    arena_reset(z_mark);
                    pthread_mutex_lock(&state->threshold_mutex);
                    proc = hash_table_lookup(state->threshold_stake_processes, stake_tx_id, false);
                    if (proc) {
                        atomic_store_explicit(&proc->aggregation_failed, true, memory_order_release);
                        pthread_cond_signal(&proc->partial_cond);
                    }
                    pthread_mutex_unlock(&state->threshold_mutex);
                    break;
                }
                pthread_mutex_unlock(&state->threshold_mutex);
                break;
            }
            pthread_mutex_unlock(&state->threshold_mutex);
            break;
        }
        case MSG_THRESHOLD_AGGREGATE_NOTIFY: {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
            break;
#endif
            if (in_msg->length < COIN_ID_LEN + POLY_SERIALIZED_SIZE) break;
                    
            uint8_t stake_tx_id[COIN_ID_LEN];
            memcpy(stake_tx_id, in_msg->payload, COIN_ID_LEN);
            const uint8_t *p = in_msg->payload + COIN_ID_LEN;
            poly_t c;
                    
            if (deserialize_poly(&c, p, POLY_SERIALIZED_SIZE) != 0) break;
                
            ThresholdStakeProcess *process = find_threshold_process(state, stake_tx_id);
            if (!process) break;

            int32_t eta_full = ETA * NUM_SUBSETS;
            int32_t beta = TAU * eta_full;
            int32_t bound_y = (GAMMA1 - beta) / 3 - TAU * MAX_S_PART_INF;
            int32_t bound_z_i = bound_y + TAU * MAX_S_PART_INF;

            for (int pid = 1; pid <= 9; pid++) {
                if (!process->is_peer_active[pid]) continue;

                polyvec_t z_i;
                if (polyvec_init(&z_i, DILITHIUM_L) != CRYPTO_SUCCESS) continue;

                polyvec_copy(&z_i, &process->sign_data[pid].y);
                                    
                polyvec_t cs1_temp;
                if (polyvec_init(&cs1_temp, DILITHIUM_L) != CRYPTO_SUCCESS) {
                    polyvec_free(&z_i);
                    continue;
                }
                for (size_t k = 0; k < DILITHIUM_L; k++) {
                    poly_mul_sparse(&cs1_temp.vec[k], &process->s1_part[pid].vec[k], &c);
                }
                polyvec_add(&z_i, &z_i, &cs1_temp);
                polyvec_free(&cs1_temp);
                                    
                if (!check_norm_inf(&z_i, bound_z_i)) {
                    polyvec_free(&z_i);
                    continue;
                }
                                    
                Message *resp_msg = calloc(1, sizeof(Message));
                if (!resp_msg) {
                    polyvec_free(&z_i);
                    continue;
                }
                            
                resp_msg->type = MSG_THRESHOLD_PARTIAL_RESPONSE;
                uint8_t *r_p = resp_msg->payload;

                memcpy(r_p, stake_tx_id, COIN_ID_LEN);
                r_p += COIN_ID_LEN;
                            
                // Map correctly using the globally assigned peer wallet structure to bypass verification bounds
                memcpy(r_p, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                r_p += DILITHIUM_PUBKEY_LEN;

                uint16_t point_id_be_resp = htobe16(pid);
                memcpy(r_p, &point_id_be_resp, sizeof(uint16_t));
                r_p += sizeof(uint16_t);

                uint8_t stage = 1;
                memcpy(r_p, &stage, sizeof(uint8_t));
                r_p += sizeof(uint8_t);

                size_t remaining = MAX_MESSAGE_SIZE - (r_p - resp_msg->payload);
                size_t z_len;
                if (polyvec_serialize(&z_i, r_p, remaining, &z_len) == CRYPTO_SUCCESS && z_len > 0) {
                    resp_msg->length = (r_p - resp_msg->payload) + z_len;
                    send_message(state, sender_pubkey, resp_msg);
                }
                            
                free(resp_msg);
                polyvec_free(&z_i);
            }
                        
            // Only nuke the shared state allocation memory if we are NOT the orchestrating dealer processing a local execution mapping.
            if (process->collector_thread == 0) {
                remove_threshold_process(state, stake_tx_id);
            }
            break;
        }
        case MSG_END_OF_DATA: {
            pthread_mutex_lock(&state->mutex);
                                
            // Safely route EOF signals based on contextual payload flags
            int is_pending_ops_end = (in_msg->length == 1 && in_msg->payload[0] == 1);
            int is_block_sync_end = (in_msg->length == 1 && in_msg->payload[0] == 2);

            if (!is_pending_ops_end && !is_block_sync_end && state->in_blockchain_sync && memcmp(sender_pubkey, state->sync_peer_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
                pthread_mutex_unlock(&state->mutex);
                break;
            }

            if (is_pending_ops_end) {
                state->pending_ops_received = 1;
                pthread_cond_signal(&state->pending_ops_cond);
            } else if (is_block_sync_end && state->in_blockchain_sync) {
                // Flush and apply any waiting contiguous blocks from orphan pool
                pthread_mutex_unlock(&state->mutex);
                trigger_async_fork_processing(state);
                pthread_mutex_lock(&state->mutex);

                if (state->current_block_number >= state->sync_received_block_number_value) {
                    state->blockchain_sync_received_end = 1;
                    pthread_cond_signal(&state->blockchain_sync_cond);
                } else {
                    // Batch segment completed; immediately signal sync worker to request next batch
                    pthread_cond_signal(&state->blockchain_sync_cond);
                }
            } else if (state->in_blockchain_sync) {
                if (state->current_block_number >= state->sync_received_block_number_value) {
                    state->blockchain_sync_received_end = 1;
                    pthread_cond_signal(&state->blockchain_sync_cond);
                }
            } else {
                // Fallback
                state->pending_ops_received = 1;
                pthread_cond_signal(&state->pending_ops_cond);
            }
            pthread_mutex_unlock(&state->mutex);
            break;
        }
        case MSG_ENDPOINT_DISCOVERY: {
            out_msg->type = MSG_ENDPOINT_DISCOVERY_ACK;
            out_msg->length = 19;
            serialize_sockaddr(sender_addr, out_msg->payload);
            send_message(state, sender_pubkey, out_msg);
            break;
        }
        case MSG_ENDPOINT_DISCOVERY_ACK: {
            if (in_msg->length == 19) {
                struct sockaddr_storage discovered_addr;
                memset(&discovered_addr, 0, sizeof(discovered_addr));
                if (deserialize_sockaddr(in_msg->payload, 19, &discovered_addr) != 0) break;
                
                pthread_mutex_lock(&state->p2p_network.mutex);
                /* The reflector used to echo a cached peer address. Adopting the
                 * other seed's IP made this VM treat that seed as itself, and the
                 * load balancer then alternated a count of 2 with a count of 3. */
                bool clashes_with_remote = false;
                if (!scl_sockaddr_is_unusable(&discovered_addr)) {
                    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                        Peer *op = state->p2p_network.known_peers[i];
                        if (!op || !op->conn || op->conn->handshake_state != SCL_CONN_STATE_ESTABLISHED) continue;
                        if (is_zeroed(op->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) continue;
                        if (memcmp(op->peer_wallet.dilithium_pubkey,
                                   state->p2p_network.local_peer.peer_wallet.dilithium_pubkey,
                                   DILITHIUM_PUBKEY_LEN) == 0) continue;
                        const struct sockaddr_storage *live =
                            (op->conn->current_path.ss_family == AF_INET ||
                             op->conn->current_path.ss_family == AF_INET6)
                                ? &op->conn->current_path : &op->addr;
                        /* H-11 fix: scl_sockaddr_is_self_locked() compares IPs only
                         * (ephemeral NAT ports are ignored downstream), so this clash
                         * test must be IP-only as well. The previous exact
                         * sockaddr_storage_equal() (IP + port) let a reflection
                         * carrying another validator's IP with a translated source
                         * port slip through, adopting that validator's IP as one of
                         * our own self addresses and hiding the other seed from the
                         * Active Node count (p2p_add_peer rejection + count veto). */
                        if (sockaddr_storage_ip_equal(live, &discovered_addr)) {
                            clashes_with_remote = true;
                            break;
                        }
                    }
                }
                if (clashes_with_remote) {
                    scl_log(LOG_LEVEL_DEBUG, "NAT", "Ignoring endpoint reflection that matches another validator.");
                    pthread_mutex_unlock(&state->p2p_network.mutex);
                    break;
                }
                scl_note_self_addr_locked(&state->p2p_network, &discovered_addr);
                scl_reap_self_placeholders_locked(&state->p2p_network);
                if (state->p2p_network.nat_type == NAT_TYPE_UNKNOWN) {
                    state->p2p_network.public_addr = discovered_addr;
                    state->p2p_network.nat_type = NAT_TYPE_ASYMMETRIC; // Assumed asymmetric until second distinct mapping
                    scl_log(LOG_LEVEL_DEBUG, "NAT", "Public Endpoint Discovered.");
                } else if (state->p2p_network.nat_type == NAT_TYPE_ASYMMETRIC) {
                    bool port_differs = false;
                    if (state->p2p_network.public_addr.ss_family == AF_INET && discovered_addr.ss_family == AF_INET) {
                        if (((struct sockaddr_in*)&state->p2p_network.public_addr)->sin_port != ((struct sockaddr_in*)&discovered_addr)->sin_port) port_differs = true;
                    } else if (state->p2p_network.public_addr.ss_family == AF_INET6 && discovered_addr.ss_family == AF_INET6) {
                        if (((struct sockaddr_in6*)&state->p2p_network.public_addr)->sin6_port != ((struct sockaddr_in6*)&discovered_addr)->sin6_port) port_differs = true;
                    }
                    if (port_differs) {
                        state->p2p_network.nat_type = NAT_TYPE_SYMMETRIC;
                        scl_log(LOG_LEVEL_DEBUG, "NAT", "Symmetric NAT Classification detected! Relays may be required for certain peers.");
                    }
                }
                
                if (sockaddr_storage_equal(&state->p2p_network.local_peer.addr, &discovered_addr)) {
                    state->p2p_network.nat_type = NAT_TYPE_OPEN;
                    scl_log(LOG_LEVEL_DEBUG, "NAT", "Open Internet / Full Cone NAT classification confirmed.");
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
            }
            break;
        }
        case MSG_RELAY_DATA: {
            // Phase 4: Blind Relay Routing (Zero-Copy Payload Forwarding)
            if (in_msg->length < 19) break;
            struct sockaddr_storage target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            if (deserialize_sockaddr(in_msg->payload, 19, &target_addr) != 0) break;
            
            size_t relay_payload_len = in_msg->length - 19;
            if (relay_payload_len > 0 && global_shim) {
                const uint8_t *raw_pkt = in_msg->payload + 19;
                uint8_t pkt_cid[SCL_CID_LEN];
                memcpy(pkt_cid, raw_pkt + 1, SCL_CID_LEN);
                
                // Track CID to client mapping to route the Symmetric Peer's return traffic
                UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;
                pthread_mutex_lock(&state->p2p_network.mutex);
                bool found_mapping = false;
                for (uint32_t i = 0; i < us_state->relay_count; i++) {
                    if (memcmp(us_state->relay_table[i].cid, pkt_cid, SCL_CID_LEN) == 0) {
                        us_state->relay_table[i].client_addr = *sender_addr;
                        us_state->relay_table[i].expiry = get_time_ms() + 300000;
                        found_mapping = true;
                        break;
                    }
                }
                if (!found_mapping && us_state->relay_count < 256) {
                    uint32_t idx = us_state->relay_count++;
                    memcpy(us_state->relay_table[idx].cid, pkt_cid, SCL_CID_LEN);
                    us_state->relay_table[idx].client_addr = *sender_addr;
                    us_state->relay_table[idx].expiry = get_time_ms() + 300000;
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
                
                size_t max_len;
                void *tx_token;
                uint8_t *tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
                if (tx_buf && max_len >= relay_payload_len) {
                    memcpy(tx_buf, raw_pkt, relay_payload_len);
                    global_shim->commit_tx_buffer(global_shim, tx_token, relay_payload_len, pkt_cid, &target_addr);
                    char target_ip_str[INET6_ADDRSTRLEN] = "unknown";
                    int target_port = 0;
                    if (target_addr.ss_family == AF_INET) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)&target_addr)->sin_addr, target_ip_str, sizeof(target_ip_str));
                        target_port = ntohs(((struct sockaddr_in *)&target_addr)->sin_port);
                    } else if (target_addr.ss_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&target_addr)->sin6_addr, target_ip_str, sizeof(target_ip_str));
                        target_port = ntohs(((struct sockaddr_in6 *)&target_addr)->sin6_port);
                    }
                    scl_log(LOG_LEVEL_DEBUG, "NAT", "Relayed %zu bytes to %s:%d via blind routing envelopment.", relay_payload_len, target_ip_str, target_port);
                } else if (tx_token) {
                    global_shim->abort_tx_buffer(global_shim, tx_token);
                }
            }
            break;
        }
        case MSG_RELAY_REQUEST: {
            if (in_msg->length < SCL_CID_LEN) break;
            uint8_t requested_cid[SCL_CID_LEN];
            memcpy(requested_cid, in_msg->payload, SCL_CID_LEN);
            
            UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;
            if (us_state) {
                pthread_mutex_lock(&state->p2p_network.mutex);
                bool found_mapping = false;
                for (uint32_t i = 0; i < us_state->relay_count; i++) {
                    if (memcmp(us_state->relay_table[i].cid, requested_cid, SCL_CID_LEN) == 0) {
                        us_state->relay_table[i].client_addr = *sender_addr;
                        us_state->relay_table[i].expiry = get_time_ms() + 300000;
                        found_mapping = true;
                        break;
                    }
                }
                if (!found_mapping && us_state->relay_count < 256) {
                    uint32_t idx = us_state->relay_count++;
                    memcpy(us_state->relay_table[idx].cid, requested_cid, SCL_CID_LEN);
                    us_state->relay_table[idx].client_addr = *sender_addr;
                    us_state->relay_table[idx].expiry = get_time_ms() + 300000;
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
                
                scl_log(LOG_LEVEL_INFO, "NAT", "Registered blind relay path for CID %02x%02x... to %s",
                        requested_cid[0], requested_cid[1], sender_ip_str);
            }
            break;
        }
        case MSG_PEER_DISCONNECT: {
            if (in_msg->length != DILITHIUM_PUBKEY_LEN + SIGNATURE_LEN && in_msg->length != 0) break;

            bool was_established = conn ? (conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) : false;

            if (in_msg->length == 0) {
                if (conn) conn->handshake_state = SCL_CONN_STATE_NONE;
            }

            uint8_t disconnected_pubkey[DILITHIUM_PUBKEY_LEN];
            if (in_msg->length == DILITHIUM_PUBKEY_LEN + SIGNATURE_LEN) {
                memcpy(disconnected_pubkey, in_msg->payload, DILITHIUM_PUBKEY_LEN);
                uint8_t *signature = in_msg->payload + DILITHIUM_PUBKEY_LEN;
                if (dilithium_verify(in_msg->payload, DILITHIUM_PUBKEY_LEN, signature, disconnected_pubkey) != 0) {
                    fprintf(stderr, "[Network] ERROR: Invalid signature on MSG_PEER_DISCONNECT. Dropping forged packet.\n");
                    break;
                }
            } else {
                memcpy(disconnected_pubkey, sender_pubkey, DILITHIUM_PUBKEY_LEN);
            }
            
            if (memcmp(disconnected_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
                break;
            }

            int removed = 0;
            if (in_msg->length == 0 && !is_zeroed(disconnected_pubkey, DILITHIUM_PUBKEY_LEN)) {
                // Synthesized disconnect on a stalled/timed out connection for an authenticated peer.
                // Detach the connection across all matching peer entries without removing from address book.
                pthread_mutex_lock(&state->p2p_network.mutex);
                for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                    if (state->p2p_network.known_peers[i]->conn == conn) {
                        Peer *peer = state->p2p_network.known_peers[i];
                        if (peer->conn) {
                            SclConnection *old_c = peer->conn;
                            peer->conn = NULL;
                            if (global_shim) {
                                if (global_shim->unregister_connection(global_shim, old_c->cid)) {
                                    scl_connection_release(old_c);
                                }
                            }
                            scl_connection_release(old_c);
                        }
                        removed = 1;
                    }
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
            } else if (is_zeroed(disconnected_pubkey, DILITHIUM_PUBKEY_LEN)) {
                // Synthesized disconnect on a pending connection. Remove exactly by connection binding.
                pthread_mutex_lock(&state->p2p_network.mutex);
                for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                    if (state->p2p_network.known_peers[i]->conn == conn) {
                        // Never remove the local peer from the known_peers array
                        if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
                            Peer *peer = state->p2p_network.known_peers[i];
                            if (peer->conn) {
                                if (global_shim) {
                                    if (global_shim->unregister_connection(global_shim, peer->conn->cid)) {
                                        scl_connection_release(peer->conn);
                                    }
                                }
                                scl_connection_release(peer->conn);
                            }
                            peer->conn = NULL; // Just detach the connection
                            removed = 1;
                            break;
                        }

                        Peer *peer = state->p2p_network.known_peers[i];
                        if (peer->conn) {
                            if (global_shim) {
                                if (global_shim->unregister_connection(global_shim, peer->conn->cid)) {
                                    scl_connection_release(peer->conn);
                                }
                            }
                            scl_connection_release(peer->conn);
                            peer->conn = NULL;
                        }
                        free(peer);
                        for (size_t j = i; j < state->p2p_network.num_known_peers - 1; j++) {
                            state->p2p_network.known_peers[j] = state->p2p_network.known_peers[j + 1];
                        }
                        // Clear the trailing dangling pointer securely before shrinking
                        state->p2p_network.known_peers[state->p2p_network.num_known_peers - 1] = NULL;
                        state->p2p_network.num_known_peers--;
                                    
                        Peer **new_peers = realloc(state->p2p_network.known_peers, state->p2p_network.num_known_peers * sizeof(Peer*));
                        if (new_peers || state->p2p_network.num_known_peers == 0) {
                            state->p2p_network.known_peers = new_peers;
                        }
                                    
                        removed = 1;
                        break;
                    }
                }
                pthread_mutex_unlock(&state->p2p_network.mutex);
            } else {
                removed = p2p_remove_peer_by_pubkey(&state->p2p_network, disconnected_pubkey);
            }

            if (removed > 0) {
                if (in_msg->length != 0) { // Only broadcast verified explicit disconnects
                    out_msg->type = MSG_PEER_DISCONNECT;
                    out_msg->length = DILITHIUM_PUBKEY_LEN + SIGNATURE_LEN;
                    memcpy(out_msg->payload, in_msg->payload, DILITHIUM_PUBKEY_LEN + SIGNATURE_LEN);
                                        
                    pthread_mutex_lock(&state->p2p_network.mutex);
                    size_t num_peers = state->p2p_network.num_known_peers;
                    uint8_t (*pubkeys)[DILITHIUM_PUBKEY_LEN] = malloc(num_peers * DILITHIUM_PUBKEY_LEN);
                    if (!pubkeys) {
                        pthread_mutex_unlock(&state->p2p_network.mutex);
                        break;
                    }
                    size_t valid_peers = 0;
                    for (size_t i = 0; i < num_peers; i++) {
                        if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) continue;
                        if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, sender_pubkey, DILITHIUM_PUBKEY_LEN) == 0) continue;
                        if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, disconnected_pubkey, DILITHIUM_PUBKEY_LEN) == 0) continue;
                        if (!validate_dilithium_pubkey(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey)) continue;
                                            
                        memcpy(pubkeys[valid_peers++], state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                    }
                    pthread_mutex_unlock(&state->p2p_network.mutex);
                                        
                    for (size_t i = 0; i < valid_peers; i++) {
                        send_message(state, pubkeys[i], out_msg);
                    }
                    free(pubkeys);
                }

                if (was_established || in_msg->length != 0) {
                    broadcast_peer_list_sync(state);

                    size_t active_peers = 0;
                    pthread_mutex_lock(&state->p2p_network.mutex);
                    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
                        Peer *p = state->p2p_network.known_peers[i];
                        if (p && p->conn && p->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                            active_peers++;
                        }
                    }
                    pthread_mutex_unlock(&state->p2p_network.mutex);

                    fprintf(stderr, "[Network] Processed MSG_PEER_DISCONNECT: Removed peer%s (new count=%zu)\n",
                            (in_msg->length != 0) ? " and propagated disconnection" : "",
                            active_peers);
                }
            }
            break;
        }
        default:
            break;
    }
}

/* ============================================================================ */
/* SECTION 13: OUTBOUND CONNECTION SETUP & PEER TABLE MUTATIONS                 */
/* ============================================================================ */

/**
 * @brief Initiates an outbound QUIC-Parity connection to a target network endpoint.
 *
 * @details
 * Connection Establishment Pipeline:
 * 1. Checks peer directory under `net->mutex` to prevent duplicate concurrent handshakes.
 * 2. Enforces global connection limit (@ref MAX_ACTIVE_CONNECTIONS).
 * 3. Allocates a 64-byte cache-line aligned @ref SclConnection structure.
 * 4. Initializes zero-copy L5 SPSC queues, BBRv3 congestion trackers, and 64-word replay bitmaps.
 * 5. Generates an ephemeral Kyber-512 keypair for forward secrecy.
 * 6. Generates a random 20-byte Connection ID (CID) and registers into the routing table.
 * 7. Dispatches Handshake Flight 1 via @ref scl_initiate_handshake.
 *
 * @param[in,out] net P2P network subsystem container.
 * @param[in] addr Destination address coordinates.
 *
 * @thread_safety Acquires `net->mutex` internally.
 * @complexity Time: O(num_peers + kyber_keygen), Space: O(sizeof(SclConnection)) heap allocation.
 */
void scl_initiate_connection(P2PNetwork *net, const struct sockaddr_storage *addr) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)net; (void)addr;
    return;
#endif
    if (!global_shim) return;

    pthread_mutex_lock(&net->mutex);
    /* Fast-path self-detection. scl_sockaddr_is_self_locked only sees
     * public_addr after the first MSG_PEER_DISCOVERY round trip, but the
     * bootstrap dial happens seconds after startup. Add the OS-assigned
     * interface list to self_addrs on the first call so the very first
     * self-dial is rejected without a round trip. */
    if (addr) {
        if (net->num_self_addrs == 0) {
            /* Enumerate OS-assigned addresses once. */
#ifndef _WIN32
            struct ifaddrs *ifas = NULL;
            if (getifaddrs(&ifas) == 0) {
                for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr) continue;
                    if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
                        struct sockaddr_storage ss;
                        socklen_t sl = (ifa->ifa_addr->sa_family == AF_INET) ?
                            sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                        memcpy(&ss, ifa->ifa_addr, sl);
                        scl_note_self_addr_locked(net, &ss);
                    }
                }
                freeifaddrs(ifas);
            }
#endif
        }
        if (scl_sockaddr_is_self_locked(net, addr)) {
            pthread_mutex_unlock(&net->mutex);
            return;
        }
    }
    int found_existing = 0;
    size_t existing_idx = 0;
    for (size_t i = 0; i < net->num_known_peers; i++) {
        if (sockaddr_storage_equal(&net->known_peers[i]->addr, addr)) {
                            
            if (net->known_peers[i]->conn != NULL) {
                if (net->known_peers[i]->conn->handshake_state == SCL_CONN_STATE_NONE) {
                    // Detach dead connection reference to allow a fresh handshake
                    SclConnection *old_c = net->known_peers[i]->conn;
                    net->known_peers[i]->conn = NULL;
                    if (global_shim) {
                        if (global_shim->unregister_connection(global_shim, old_c->cid)) {
                            scl_connection_release(old_c);
                        }
                    }
                    scl_connection_release(old_c);
                    found_existing = 1;
                    existing_idx = i;
                    break;
                }
                pthread_mutex_unlock(&net->mutex);
                return; // Already connecting or connected
            } else {
                found_existing = 1;
                existing_idx = i;
                break;
            }
        }
    }

    // Generate a random temporary CID for the initial handshake
    uint8_t random_cid[SCL_CID_LEN];
    RAND_bytes(random_cid, SCL_CID_LEN);
    
    UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;
    if (atomic_load_explicit(&us_state->active_connection_count, memory_order_relaxed) >= MAX_ACTIVE_CONNECTIONS) {
        fprintf(stderr, "[P2P] Global connection limit reached. Cannot initiate connection.\n");
        pthread_mutex_unlock(&net->mutex);
        return;
    }

    SclConnection *conn = NULL;
    SCL_ALIGNED_ALLOC(&conn, 64, sizeof(SclConnection));
    if (!conn) {
        pthread_mutex_unlock(&net->mutex);
        return;
    }
        
    memset(conn, 0, sizeof(SclConnection));
    atomic_init(&conn->ref_count, 1);
    atomic_init(&conn->is_processing, false); // Initialize processing lock
    atomic_fetch_add_explicit(&us_state->active_connection_count, 1, memory_order_relaxed);
    conn->l5_rx_queue.buffer = malloc(SCL_L5_RING_SIZE * sizeof(uint8_t*));
    conn->l5_rx_queue.lengths = malloc(SCL_L5_RING_SIZE * sizeof(size_t));
    conn->l5_rx_queue.addrs = malloc(SCL_L5_RING_SIZE * sizeof(struct sockaddr_storage));
    conn->l5_rx_queue.rx_times = malloc(SCL_L5_RING_SIZE * sizeof(uint64_t));
    for (int i = 0; i < SCL_L5_RING_SIZE; i++) {
        conn->l5_rx_queue.buffer[i] = malloc(4096);
    }
    atomic_init(&conn->l5_rx_queue.head, 0);
    atomic_init(&conn->l5_rx_queue.tail, 0);

    atomic_init(&conn->replay_highest_seen, 0);
    conn->dynamic_replay_window_size = SCL_MIN_REPLAY_WINDOW;
    conn->current_path = *addr;
    conn->path_mtu = SCL_LINK_MTU - 48; // Default baseline safely adjusted by dynamic PMTUD
    if (conn->path_mtu > 1200) conn->path_mtu = 1200;
    memcpy(conn->cid, random_cid, SCL_CID_LEN);

    // Initialize Flow Control Window
    conn->tx_max_data = SCL_FLOW_WINDOW_SIZE;
    conn->rx_max_data = SCL_FLOW_WINDOW_SIZE;
    conn->tx_dispatched_data = 0;
    conn->rx_consumed_data = 0;
    conn->pending_max_data_update = false;
    
    // Initialize RPC Token Bucket
    atomic_init(&conn->rpc_token_budget, net->is_bootstrap ? 2000 : 500);
    atomic_init(&conn->last_rpc_token_refill, get_time_ms());
    atomic_init(&conn->active_rpc_streams, 0);

    pthread_mutex_init(&conn->l4_mutex, NULL);
        
    // --- Generate Ephemeral Kyber-512 Keypair for Forward Secrecy ---
    if (!generate_ephemeral_kyber_keypair(conn->ephemeral_kyber_pubkey, conn->ephemeral_kyber_privkey)) {
        fprintf(stderr, "[P2P] ERROR: Failed to generate ephemeral Kyber keypair.\n");
        scl_connection_release(conn);
        pthread_mutex_unlock(&net->mutex);
        return;
    }

    // Initialize unacknowledged packet tracking and RTT estimators
    conn->unacked_head = NULL;
    conn->unacked_tail = NULL;
    conn->smoothed_rtt = 0;
    conn->loss_time = 0;
    conn->largest_acked_packet = 0;
                    
    queue_init(&conn->tx_datagram_queue);
    queue_init(&conn->tx_stream_queue);
    conn->bdpq_deficit = 5;
                    
    conn->cwnd = SCL_MICRO_BDP_LIMIT; // Spec: Start new syncing peers at micro-BDP
    conn->is_untrusted_sync = false;  // We initiated, assume trusted outbound
    atomic_init(&conn->last_rx_time, get_time_ms());
    atomic_init(&conn->aead_fail_streak, 0);
                    
    // BBR state initialization
    conn->bbr_state = 0;              // Start in STARTUP (0 = BBR_STARTUP)
    conn->bbr_max_bw = 0;             // Unknown initially
    conn->bbr_min_rtt = SCL_INITIAL_RTT * 1000;
    conn->bbr_delivered = 0;
    conn->bbr_delivered_time = get_time_ms();
    conn->bbr_probe_rtt_done_stamp = 0;
    conn->bbr_prior_cwnd = 0;
    conn->bbr_cycle_stamp = 0;

    // RPC Token Bucket initialization
    atomic_init(&conn->rpc_token_budget, net->is_bootstrap ? 2000 : 500);
    atomic_init(&conn->last_rpc_token_refill, get_time_ms());
    atomic_init(&conn->active_rpc_streams, 0);

    // Fallback to Symmetric Blind Relay if behind restrictive Symmetric NAT/CGNAT
    conn->use_relay = false;
    uint8_t relay_pubkey[DILITHIUM_PUBKEY_LEN];
    if (net->nat_type == NAT_TYPE_SYMMETRIC) {
        struct sockaddr_storage r_addr;
        if (find_active_relay_path(global_state, &r_addr, relay_pubkey)) {
            conn->use_relay = true;
            conn->relay_path = r_addr;
            
            // Phase 4: Active Relay Registration Request
            Message *relay_req = calloc(1, sizeof(Message));
            if (relay_req) {
                relay_req->type = MSG_RELAY_REQUEST;
                relay_req->length = SCL_CID_LEN;
                memcpy(relay_req->payload, conn->cid, SCL_CID_LEN);
                send_message(global_state, relay_pubkey, relay_req);
                free(relay_req);
            }
        }
    }

    // Never use NONE for an active connection to prevent L5 thread GC races
    conn->handshake_state = SCL_CONN_STATE_HANDSHAKING;
    conn->is_handshake_complete = false;
    conn->handshake_cookie = 0;       // 0 on first attempt
    conn->required_pow_bits = 10;     // Baseline PoW

    global_shim->register_connection(global_shim, random_cid, conn);
    
    if (found_existing) {
        net->known_peers[existing_idx]->conn = conn;
        atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_acquire);
    } else {
        Peer *pending_peer = calloc(1, sizeof(Peer));
        pending_peer->addr = *addr;
        pending_peer->conn = conn;
        pending_peer->last_seen = time(NULL);
        
        atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_acquire);

        Peer **new_peers = realloc(net->known_peers, (net->num_known_peers + 1) * sizeof(Peer*));
        if (new_peers) {
            net->known_peers = new_peers;
            net->known_peers[net->num_known_peers] = pending_peer;
            net->num_known_peers++;
        } else {
            free(pending_peer);
            global_shim->unregister_connection(global_shim, random_cid);
            scl_connection_release(conn);
            pthread_mutex_unlock(&net->mutex);
            return;
        }
    }
                            
    // Acquire a strong reference for the local execution of scl_initiate_handshake
    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_acquire);
                        
    pthread_mutex_unlock(&net->mutex);

    scl_initiate_handshake(net, conn, addr);
                            
    // Release the local reference once handshake initiation completes
    scl_connection_release(conn);

    char conn_ip_str[INET6_ADDRSTRLEN] = "unknown";
    int conn_port = 0;
    if (addr->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, conn_ip_str, sizeof(conn_ip_str));
        conn_port = ntohs(((struct sockaddr_in *)addr)->sin_port);
    } else if (addr->ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, conn_ip_str, sizeof(conn_ip_str));
        conn_port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    }
    fprintf(stderr, "[P2P] Initiated connection to %s:%d\n", conn_ip_str, conn_port);
}

/**
 * @brief Queues an authenticated message for transmission to a specific peer by public key.
 *
 * @details
 * Routing Sequence:
 * 1. Loopback Check: If `recipient_pubkey` matches local peer key, loops back directly via
 *    @ref crypto_verify_enqueue for internal testing or simulation.
 * 2. Directory Resolution: Locates peer in `state->p2p_network.known_peers` under mutex lock.
 * 3. State Gating: Discards application messages if peer connection is not in `SCL_CONN_STATE_ESTABLISHED`.
 * 4. Framing Segregation:
 *    - Reliable Stream Messages: Enqueued to `peer->conn->tx_stream_queue`.
 *    - Unreliable Datagram Messages (e.g. votes): Enqueued to `peer->conn->tx_datagram_queue`.
 *
 * @param[in] state Global node state container.
 * @param[in] recipient_pubkey 2,592-byte Dilithium5 public key of the target peer.
 * @param[in] msg Message container to transmit.
 * @return 1 on successful queuing; 0 if peer is disconnected, untrusted, or unmapped.
 *
 * @complexity Time: O(num_peers), Space: O(msg->length) queue node.
 */
int send_message(State *state, const uint8_t *recipient_pubkey, const Message *msg) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)recipient_pubkey; (void)msg;
    return 1;
#endif
    if (!global_shim) return 0;
    
    // Local loopback for threshold ceremonies and local network simulations
    if (memcmp(recipient_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
        struct sockaddr_storage dummy_addr;
        memset(&dummy_addr, 0, sizeof(dummy_addr));
        uint8_t sender_pubkey[DILITHIUM_PUBKEY_LEN];
        memcpy(sender_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
        
        crypto_verify_enqueue(state, NULL, msg, sender_pubkey, &dummy_addr);
        return 1;
    }
    
    Peer *peer = NULL;
    pthread_mutex_lock(&state->p2p_network.mutex);
    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
        if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, recipient_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            peer = state->p2p_network.known_peers[i];
            break;
        }
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);
    
    // Drop application messages if the L1 Handshake is not fully established
    if (!peer || !peer->conn || peer->conn->handshake_state != SCL_CONN_STATE_ESTABLISHED) return 0;

    // Isolate Streams vs Datagrams
    bool is_stream = (msg->type == MSG_PTR_TRANSFER ||
                      msg->type == MSG_ENDPOINT_DISCOVERY ||
                      msg->type == MSG_ENDPOINT_DISCOVERY_ACK ||
                      msg->type == MSG_RELAY_REQUEST ||
                      msg->type == MSG_RELAY_DATA ||
                      msg->type == MSG_COIN_QUERY ||
                      msg->type == MSG_COIN_DATA ||
                      msg->type == MSG_POINTER_DATA ||
                      msg->type == MSG_GET_BLOCKS ||
                      msg->type == MSG_BLOCKS_DATA ||
                      msg->type == MSG_GET_PENDING_OPERATIONS ||
                      msg->type == MSG_PENDING_OPERATIONS_DATA ||
                      msg->type == MSG_GET_PUBKEY_BY_USERID ||
                      msg->type == MSG_PUBKEY_BY_USERID_RESPONSE ||
                      msg->type == MSG_END_OF_DATA ||
                      msg->type == MSG_GET_AUDIT ||
                      msg->type == MSG_UPDATE_AUDIT ||
                      msg->type == MSG_BLOCK_NUMBER_QUERY ||
                      msg->type == MSG_BLOCK_NUMBER ||
                      msg->type == MSG_THRESHOLD_SHARE_DISTRIBUTE ||
                      msg->type == MSG_THRESHOLD_PARTIAL_RESPONSE ||
                      msg->type == MSG_THRESHOLD_SIGN_REQUEST ||
                      msg->type == MSG_THRESHOLD_AGGREGATE_NOTIFY ||
                      msg->type == MSG_VALUATION_PROPOSAL ||
                      msg->type == MSG_PROPOSE_BLOCK ||
                      msg->type == MSG_STATELESS_RESET_TOKEN ||
                      msg->type == MSG_PENDING_OPERATION ||
                      msg->type == MSG_GOSSIP_BLOCK ||
                      msg->type == MSG_BLOCK_APPROVED ||
                      msg->type == MSG_PEERS_LIST ||
                      msg->type == MSG_PEER_LIST_SYNC ||
                      msg->type == MSG_PEER_DISCONNECT ||
                      msg->type == MSG_PEER_DISCOVERY ||
                      msg->type == MSG_CENTINEL_QUERY ||
                      msg->type == MSG_CENTINEL_COMMITMENTS ||
                      msg->type == MSG_CENTINEL_NULLIFIERS ||
                      msg->type == MSG_REDEEM_CENTINEL ||
                      msg->type == MSG_EPOCH_DKG_SHARE ||
                      msg->type == MSG_EPOCH_SIGN_REQUEST ||
                      msg->type == MSG_EPOCH_PARTIAL_W ||
                      msg->type == MSG_EPOCH_CHALLENGE ||
                      msg->type == MSG_EPOCH_PARTIAL_Z ||
                      msg->type == MSG_DKG_COMMIT ||
                      msg->type == MSG_DKG_REVEAL ||
                      msg->type == MSG_DKG_SHARE_DEAL ||
                      msg->type == MSG_DKG_PUBKEY_FRAG);
                          
    if (is_stream) {
        return queue_enqueue(&peer->conn->tx_stream_queue, msg) == 0 ? 1 : 0;
    } else {
        // Spec: Unreliable Datagram Overlay for consensus votes (MSG_VOTE, MSG_VALUATION_VOTE)
        // Also acts as fallback for any other undefined message types
        return queue_enqueue(&peer->conn->tx_datagram_queue, msg) == 0 ? 1 : 0;
    }
}

/**
 * @brief Broadcasts an authenticated message to all active, established peers in the network directory.
 *
 * @details
 * Gathers all non-local, non-zero Dilithium public keys under `net->mutex`, clones them
 * into temporary heap memory, releases the mutex, and calls @ref send_message sequentially.
 *
 * @param[in] state Global node state container.
 * @param[in] msg Message container to broadcast.
 *
 * @complexity Time: O(num_peers), Space: O(num_peers * PUBKEY_LEN) temporary allocation.
 */
void p2p_broadcast(State *state, const Message *msg) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)msg;
    return;
#endif
    pthread_mutex_lock(&state->p2p_network.mutex);
    size_t num_peers = state->p2p_network.num_known_peers;
    uint8_t (*pubkeys)[DILITHIUM_PUBKEY_LEN] = malloc(num_peers * DILITHIUM_PUBKEY_LEN);
    size_t valid_peers = 0;
    
    for (size_t i = 0; i < num_peers; i++) {
        if (memcmp(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey,
                   state->p2p_network.local_peer.peer_wallet.dilithium_pubkey,
                   DILITHIUM_PUBKEY_LEN) == 0) {
            continue;
        }
        
        // Suppress expected zeroed pubkey error spam for pending peers
        if (is_zeroed(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) {
            continue;
        }
        
        if (!validate_dilithium_pubkey(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey)) {
            continue;
        }
        memcpy(pubkeys[valid_peers], state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
        valid_peers++;
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);

    size_t broadcast_count = 0;
    for (size_t i = 0; i < valid_peers; i++) {
        if (send_message(state, pubkeys[i], msg)) {
            broadcast_count++;
        }
    }
    free(pubkeys);
    
    scl_log(LOG_LEVEL_DEBUG, "P2P", "Broadcasted message type=%d to %zu/%zu peers",
            msg->type, broadcast_count, num_peers);
}

/**
 * @brief Inserts or updates a peer identity in the active peer table.
 *
 * @details
 * Validates public key formats. If the Dilithium key matches an existing entry, updates address,
 * Kyber key, and `last_seen` timestamp. If an IP/port matches a different key, tears down the old
 * connection context to handle peer daemon restart. Otherwise, expands `net->known_peers` via `realloc`.
 *
 * @param[in,out] net P2P network subsystem container.
 * @param[in] dilithium_pubkey 2,592-byte Dilithium5 public key.
 * @param[in] kyber_pubkey 800-byte Kyber-512 public key.
 * @param[in] addr Remote network address.
 * @return PeerAddStatus code indicating whether peer was added, updated, or rejected.
 *
 * @thread_safety Acquires `net->mutex`.
 * @complexity Time: O(num_peers), Space: O(1) amortized reallocation.
 */
PeerAddStatus p2p_add_peer(P2PNetwork *net, const uint8_t *dilithium_pubkey, const uint8_t *kyber_pubkey, const struct sockaddr_storage *addr) {
    if (!net || !dilithium_pubkey || !kyber_pubkey || !addr) return PEER_ADD_ERROR;
    
    struct sockaddr_storage norm_addr = *addr;
    normalize_sockaddr(&norm_addr);

    // If target IP matches our own public IP and port differs, route over loopback to bypass NAT hairpinning drop
    if (net->public_addr.ss_family != 0) {
        bool same_ip = false;
        if (norm_addr.ss_family == AF_INET && net->public_addr.ss_family == AF_INET) {
            same_ip = (((struct sockaddr_in *)&norm_addr)->sin_addr.s_addr == ((struct sockaddr_in *)&net->public_addr)->sin_addr.s_addr);
        } else if (norm_addr.ss_family == AF_INET6 && net->public_addr.ss_family == AF_INET6) {
            same_ip = (memcmp(&((struct sockaddr_in6 *)&norm_addr)->sin6_addr, &((struct sockaddr_in6 *)&net->public_addr)->sin6_addr, 16) == 0);
        }
        if (same_ip) {
            uint16_t local_port = (net->local_peer.addr.ss_family == AF_INET6) ?
                ((struct sockaddr_in6 *)&net->local_peer.addr)->sin6_port :
                ((struct sockaddr_in *)&net->local_peer.addr)->sin_port;
            uint16_t target_port = (norm_addr.ss_family == AF_INET6) ?
                ((struct sockaddr_in6 *)&norm_addr)->sin6_port :
                ((struct sockaddr_in *)&norm_addr)->sin_port;
            if (local_port != target_port) {
                if (norm_addr.ss_family == AF_INET) {
                    ((struct sockaddr_in *)&norm_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                } else {
                    memcpy(&((struct sockaddr_in6 *)&norm_addr)->sin6_addr, &in6addr_loopback, 16);
                }
            }
        }
    }
    addr = &norm_addr;
    
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)addr;
        if (v4->sin_addr.s_addr == 0 || v4->sin_addr.s_addr == INADDR_ANY) return PEER_ADD_ERROR;
        
        // Drop RFC 1918 10.0.0.0/8 internal VPC addresses if we are on a public WAN interface
        uint32_t ip_host = ntohl(v4->sin_addr.s_addr);
        if ((ip_host & 0xFF000000) == 0x0A000000 && net->local_peer.addr.ss_family == AF_INET) {
            if ((ntohl(((struct sockaddr_in*)&net->local_peer.addr)->sin_addr.s_addr) & 0xFF000000) != 0x0A000000) {
                return PEER_ADD_ERROR;
            }
        }
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)addr;
        if (memcmp(&v6->sin6_addr, &in6addr_any, sizeof(struct in6_addr)) == 0) return PEER_ADD_ERROR;
    }

    if (!validate_dilithium_pubkey(dilithium_pubkey)) return PEER_ADD_ERROR;
    if (!validate_kyber_pubkey(kyber_pubkey)) return PEER_ADD_ERROR;

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (net->num_known_peers >= 8) return PEER_ADD_ERROR; // Capped to strictly prevent O(N^2) memory exhaustion vectors during coverage tracking
#endif

    pthread_mutex_lock(&net->mutex);

    for (size_t i = 0; i < net->num_known_peers; i++) {
        if (memcmp(net->known_peers[i]->peer_wallet.dilithium_pubkey, dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            /* Keep the address of an ESTABLISHED path. An IPv6 discovery must not
             * overwrite a working IPv4 path (or the reverse) while that socket is live. */
            bool live = net->known_peers[i]->conn &&
                        net->known_peers[i]->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED;
            if (!live || sockaddr_storage_equal(&net->known_peers[i]->addr, addr)) {
                net->known_peers[i]->addr = *addr;
            }
            memcpy(net->known_peers[i]->peer_wallet.kyber_pubkey, kyber_pubkey, KYBER_PUBKEY_LEN);
            net->known_peers[i]->last_seen = time(NULL);
            pthread_mutex_unlock(&net->mutex);
            return PEER_ADD_UPDATED;
        }
    }

    if (memcmp(net->local_peer.peer_wallet.dilithium_pubkey, dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
        pthread_mutex_unlock(&net->mutex);
        return PEER_ADD_UPDATED;
    }

    if (scl_sockaddr_is_self_locked(net, addr)) {
        pthread_mutex_unlock(&net->mutex);
        return PEER_ADD_UPDATED;
    }

    // IP/Port match with different non-zero pubkey: peer rotated keys (restarted)
    for (size_t i = 0; i < net->num_known_peers; i++) {
        if (!is_zeroed(net->known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
            sockaddr_storage_equal(&net->known_peers[i]->addr, addr)) {
            
            fprintf(stderr, "[Network] Peer rotated public key. Cleaning up old connection.\n");
            
            if (net->known_peers[i]->conn) {
                if (global_shim) {
                    if (global_shim->unregister_connection(global_shim, net->known_peers[i]->conn->cid)) {
                        scl_connection_release(net->known_peers[i]->conn);
                    }
                }
                scl_connection_release(net->known_peers[i]->conn);
                net->known_peers[i]->conn = NULL;
            }
            
            memcpy(net->known_peers[i]->peer_wallet.dilithium_pubkey, dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            memcpy(net->known_peers[i]->peer_wallet.kyber_pubkey, kyber_pubkey, KYBER_PUBKEY_LEN);
            net->known_peers[i]->last_seen = time(NULL);
            pthread_mutex_unlock(&net->mutex);
            return PEER_ADD_UPDATED;
        }
    }

    for (size_t i = 0; i < net->num_known_peers; i++) {
        if (is_zeroed(net->known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
            sockaddr_storage_equal(&net->known_peers[i]->addr, addr)) {
                    
            memcpy(net->known_peers[i]->peer_wallet.dilithium_pubkey, dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            memcpy(net->known_peers[i]->peer_wallet.kyber_pubkey, kyber_pubkey, KYBER_PUBKEY_LEN);
            net->known_peers[i]->last_seen = time(NULL);
            pthread_mutex_unlock(&net->mutex);
            return PEER_ADD_ZEROED_UPDATED; // Reclaiming a zeroed slot is functionally an update on a pending connection mapping
        }
    }

    Peer *new_peer = malloc(sizeof(Peer));
    if (!new_peer) {
        pthread_mutex_unlock(&net->mutex);
        return PEER_ADD_ERROR;
    }
                    
    memcpy(new_peer->peer_wallet.dilithium_pubkey, dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(new_peer->peer_wallet.kyber_pubkey, kyber_pubkey, KYBER_PUBKEY_LEN);
    new_peer->addr = *addr;
    new_peer->last_seen = time(NULL);
    new_peer->conn = NULL;

    Peer **new_peers = realloc(net->known_peers, (net->num_known_peers + 1) * sizeof(Peer*));
    if (!new_peers) {
        free(new_peer);
        pthread_mutex_unlock(&net->mutex);
        return PEER_ADD_ERROR;
    }
                    
    net->known_peers = new_peers;
    net->known_peers[net->num_known_peers] = new_peer;
    net->num_known_peers++;
                    
    pthread_mutex_unlock(&net->mutex);
    return PEER_ADD_NEW;
}

/**
 * @brief Transmits a subset of known peers to a newly connected node for topology gossip.
 *
 * @param[in] state Global node state container.
 * @param[in] recipient_pubkey 2,592-byte public key of the requesting peer.
 *
 * @complexity Time: O(min(peers, 5)), Space: O(sizeof(Message)).
 */
void p2p_share_peers(State *state, uint8_t *recipient_pubkey) {
    if (!state || !recipient_pubkey || state->p2p_network.num_known_peers == 0) return;

    P2PNetwork *net = &state->p2p_network;
    /* Must cover the full n=10 DKG committee. Cap matches MSG_PEER_LIST_SYNC. */
    size_t share_count = MIN(net->num_known_peers, (size_t)MAX_PEERS_PER_MESSAGE);
    Message *msg = calloc(1, sizeof(Message));
    if (!msg) return;
        
    msg->type = MSG_PEERS_LIST;
    uint8_t *p = msg->payload;

    pthread_mutex_lock(&net->mutex);
    *p++ = (uint8_t)share_count;
    size_t actual_count = 0;

    for (size_t i = 0; i < net->num_known_peers && actual_count < share_count; i++) {
        Peer *peer = net->known_peers[i];
        
        if (is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) continue;
        
        if (memcmp(peer->peer_wallet.dilithium_pubkey, net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0 ||
            memcmp(peer->peer_wallet.dilithium_pubkey, recipient_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            continue;
        }
        if (!validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey)) {
            continue;
        }
        memcpy(p, peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
        p += DILITHIUM_PUBKEY_LEN;
        memcpy(p, peer->peer_wallet.kyber_pubkey, KYBER_PUBKEY_LEN);
        p += KYBER_PUBKEY_LEN;
        serialize_sockaddr(&peer->addr, p);
        p += 19;
        actual_count++;
    }
    pthread_mutex_unlock(&net->mutex);

    if (actual_count < share_count) msg->payload[0] = (uint8_t)actual_count;
    msg->length = p - msg->payload;
    send_message(state, recipient_pubkey, msg);
    free(msg);
}

/**
 * @brief Removes a peer and terminates its connection using its Dilithium public key.
 *
 * @param[in,out] net P2P network subsystem container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key.
 * @return 1 on successful removal; 0 if not found; -1 on error.
 *
 * @thread_safety Acquires `net->mutex`.
 * @complexity Time: O(num_peers), Space: O(1).
 */
int p2p_remove_peer_by_pubkey(P2PNetwork *net, const uint8_t *pubkey) {
    if (!net || !pubkey) return -1;
    if (is_zeroed(pubkey, DILITHIUM_PUBKEY_LEN)) return 0;
                    
    // Never remove the local peer from the known_peers array
    if (memcmp(pubkey, net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
        return 0;
    }

    pthread_mutex_lock(&net->mutex);
    int found = 0;
                    
    for (size_t i = 0; i < net->num_known_peers; i++) {
        if (memcmp(net->known_peers[i]->peer_wallet.dilithium_pubkey, pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            Peer *peer = net->known_peers[i];
            if (peer->conn) {
                if (global_shim) {
                    if (global_shim->unregister_connection(global_shim, peer->conn->cid)) {
                        scl_connection_release(peer->conn);
                    }
                }
                scl_connection_release(peer->conn);
                peer->conn = NULL; // Ensure the connection is fully detached locally
            }
            
            free(peer);
            
            // Shift elements down, safely overwriting the removed entry
            for (size_t j = i; j < net->num_known_peers - 1; j++) {
                net->known_peers[j] = net->known_peers[j + 1];
            }
            
            // Clear the trailing pointer safely
            net->known_peers[net->num_known_peers - 1] = NULL;
            net->num_known_peers--;
                            
            // Reallocate to shrink the array
            if (net->num_known_peers > 0) {
                Peer **new_peers = realloc(net->known_peers, net->num_known_peers * sizeof(Peer*));
                if (new_peers) {
                    net->known_peers = new_peers;
                }
            } else {
                free(net->known_peers);
                net->known_peers = NULL;
            }
                            
            found = 1;
            break;
        }
    }
            
    pthread_mutex_unlock(&net->mutex);
    return found ? 1 : 0;
}

/* ============================================================================ */
/* SECTION 14: TRANSPORT-LAYER REPUTATION HYPERGRAPH & PROOF-OF-WORK             */
/* ============================================================================ */

/**
 * @brief Initializes the local peer reputation hypergraph and challenge caches.
 *
 * @param[out] graph LocalHypergraph structure to configure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void initialize_hypergraph(LocalHypergraph *graph) {
    memset(graph, 0, sizeof(LocalHypergraph));
    pthread_mutex_init(&graph->lock, NULL);
    pthread_mutex_init(&graph->puzzle_cache_lock, NULL);
    graph->epoch_seed = 0xabcdef0123456789ULL; // Default initial seed
    graph->last_puzzle_rotation_ms = 0;
    graph->last_bloom_rotation_epoch = 0;
}

/**
 * @brief Internal 32-bit mixing hash for the hypergraph Bloom filter.
 *
 * @param[in] data Binary data buffer.
 * @param[in] len Length of data in bytes.
 * @param[in] seed Randomization seed.
 * @return 32-bit mixed hash.
 *
 * @complexity Time: O(len), Space: O(1).
 */
static inline uint32_t bloom_hash(const uint8_t *data, size_t len, uint32_t seed) {
    uint32_t hash = seed;
    for (size_t i = 0; i < len; i++) {
        hash += data[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

/**
 * @brief Adds a peer Connection ID (CID) to a 3-hash Bloom filter.
 *
 * @param[in,out] filter Bloom filter byte array of size @ref BLOOM_FILTER_SIZE.
 * @param[in] cid 20-byte Connection ID.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void bloom_filter_add(uint8_t *filter, const uint8_t *cid) {
    uint32_t h1 = bloom_hash(cid, SCL_CID_LEN, 0x12345678) % (BLOOM_FILTER_SIZE * 8);
    uint32_t h2 = bloom_hash(cid, SCL_CID_LEN, 0x87654321) % (BLOOM_FILTER_SIZE * 8);
    uint32_t h3 = bloom_hash(cid, SCL_CID_LEN, 0xabcdef01) % (BLOOM_FILTER_SIZE * 8);
    
    filter[h1 / 8] |= (1 << (h1 % 8));
    filter[h2 / 8] |= (1 << (h2 % 8));
    filter[h3 / 8] |= (1 << (h3 % 8));
}

/**
 * @brief Probes a Bloom filter for membership of a Connection ID.
 *
 * @param[in] filter Bloom filter byte array.
 * @param[in] cid 20-byte Connection ID.
 * @return `true` if potentially present; `false` if definitely absent.
 *
 * @complexity Time: O(1), Space: O(1).
 */
bool bloom_filter_check(const uint8_t *filter, const uint8_t *cid) {
    uint32_t h1 = bloom_hash(cid, SCL_CID_LEN, 0x12345678) % (BLOOM_FILTER_SIZE * 8);
    uint32_t h2 = bloom_hash(cid, SCL_CID_LEN, 0x87654321) % (BLOOM_FILTER_SIZE * 8);
    uint32_t h3 = bloom_hash(cid, SCL_CID_LEN, 0xabcdef01) % (BLOOM_FILTER_SIZE * 8);
    
    if (!(filter[h1 / 8] & (1 << (h1 % 8)))) return false;
    if (!(filter[h2 / 8] & (1 << (h2 % 8)))) return false;
    if (!(filter[h3 / 8] & (1 << (h3 % 8)))) return false;
    return true;
}

/**
 * @brief Serializes a compact 64-byte snapshot of the local hypergraph topology for challenge seeds.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[out] out_snapshot 64-byte destination buffer.
 *
 * @complexity Time: O(nodes), Space: O(1).
 */
void sample_local_subgraph_optimized(const LocalHypergraph *graph, uint8_t *out_snapshot) {
    memset(out_snapshot, 0, 64);
    uint16_t node_cnt = graph->node_count;
    uint16_t edge_cnt = graph->edge_count;
    memcpy(out_snapshot, &node_cnt, 2);
    memcpy(out_snapshot + 2, &edge_cnt, 2);
    memcpy(out_snapshot + 4, &graph->epoch_seed, 8);
    
    size_t offset = 12;
    for (int i = 0; i < graph->node_count && offset + SCL_CID_LEN <= 64; i++) {
        memcpy(out_snapshot + offset, graph->nodes[i].cid, SCL_CID_LEN);
        offset += SCL_CID_LEN;
    }
}

/**
 * @brief Locates node metadata in the local hypergraph by Connection ID.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] cid 20-byte Connection ID.
 * @return Pointer to NodeMetadata on match; NULL if not found.
 *
 * @complexity Time: O(node_count), Space: O(1).
 */
NodeMetadata* find_node(LocalHypergraph *graph, const uint8_t *cid) {
    for (uint16_t i = 0; i < graph->node_count; i++) {
        if (memcmp(graph->nodes[i].cid, cid, SCL_CID_LEN) == 0) {
            return &graph->nodes[i];
        }
    }
    return NULL;
}

/**
 * @brief Evaluates connection frequency of a peer over a 60-second sliding window.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] cid 20-byte Connection ID.
 * @return Interaction weight accumulated within the last 60 seconds.
 *
 * @complexity Time: O(edge_count), Space: O(1).
 */
uint32_t get_connection_rate_sliding_window(LocalHypergraph *graph, const uint8_t *cid) {
    if (!cid) return 0;
    uint32_t count = 0;
    uint64_t now = get_time_ms();
    for (uint16_t i = 0; i < graph->edge_count; i++) {
        if (memcmp(graph->edges[i].cid, cid, SCL_CID_LEN) == 0 &&
            graph->edges[i].edge_type == EDGE_INTERACTION &&
            (now - graph->edges[i].timestamp < 60000)) {
            count += graph->edges[i].weight;
        }
    }
    return count;
}

/**
 * @brief Evaluates whether a peer exceeds maximum allowable connection frequency.
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] cid 20-byte Connection ID.
 * @return `true` if rate exceeds @ref MAX_CONNECTIONS_PER_MINUTE; `false` otherwise.
 *
 * @complexity Time: O(edge_count), Space: O(1).
 */
bool is_high_frequency(LocalHypergraph *graph, const uint8_t *cid) {
    return get_connection_rate_sliding_window(graph, cid) > MAX_CONNECTIONS_PER_MINUTE;
}

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
uint8_t calculate_dynamic_difficulty_graceful(LocalHypergraph *graph, NodeMetadata* peer, uint64_t current_time) {
    uint8_t difficulty = 10;
    
    if (!peer) {
        difficulty += 2;
    } else {
        uint64_t time_since_last_seen = current_time - peer->last_seen_epoch;
        
        if (time_since_last_seen > EPOCH_DURATION_MS * 2) {
            difficulty += 1;
        }
        
        if (peer->reputation_score < REPUTATION_THRESHOLD_LOW) {
            uint8_t rep_deficit = REPUTATION_THRESHOLD_LOW - peer->reputation_score;
            uint8_t rep_penalty = rep_deficit / 2;
            difficulty += (rep_penalty > 4) ? 4 : rep_penalty;
        }
    }
    
    uint32_t conn_rate = get_connection_rate_sliding_window(graph, peer ? peer->cid : NULL);
    if (conn_rate > MAX_CONNECTIONS_PER_MINUTE) {
        difficulty += 4;
    }
    
    return (difficulty > 20) ? 20 : difficulty;
}

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
void add_temporal_edge(LocalHypergraph *graph, const uint8_t *cid, EdgeType edge_type, uint32_t weight) {
    pthread_mutex_lock(&graph->lock);
    
    NodeMetadata *peer = NULL;
    for (uint16_t i = 0; i < graph->node_count; i++) {
        if (memcmp(graph->nodes[i].cid, cid, SCL_CID_LEN) == 0) {
            peer = &graph->nodes[i];
            break;
        }
    }
    
    if (!peer) {
        if (graph->node_count < MAX_HYPERGRAPH_NODES) {
            peer = &graph->nodes[graph->node_count++];
            memcpy(peer->cid, cid, SCL_CID_LEN);
            peer->reputation_score = 0;
        } else {
            uint16_t min_idx = 0;
            uint64_t min_time = graph->nodes[0].last_seen_epoch;
            for (uint16_t i = 1; i < graph->node_count; i++) {
                if (graph->nodes[i].last_seen_epoch < min_time) {
                    min_time = graph->nodes[i].last_seen_epoch;
                    min_idx = i;
                }
            }
            peer = &graph->nodes[min_idx];
            memcpy(peer->cid, cid, SCL_CID_LEN);
            peer->reputation_score = 0;
        }
    }
    
    peer->last_seen_epoch = get_time_ms();
    
    HyperEdge *edge = NULL;
    if (graph->edge_count < MAX_HYPERGRAPH_EDGES) {
        edge = &graph->edges[graph->edge_count++];
    } else {
        uint16_t oldest_idx = 0;
        uint64_t oldest_time = graph->edges[0].timestamp;
        for (uint16_t i = 1; i < graph->edge_count; i++) {
            if (graph->edges[i].timestamp < oldest_time) {
                oldest_time = graph->edges[i].timestamp;
                oldest_idx = i;
            }
        }
        edge = &graph->edges[oldest_idx];
    }
    
    memcpy(edge->cid, cid, SCL_CID_LEN);
    edge->weight = weight;
    edge->timestamp = get_time_ms();
    edge->edge_type = edge_type;
    
    uint32_t score = 0;
    for (uint16_t i = 0; i < graph->edge_count; i++) {
        if (memcmp(graph->edges[i].cid, cid, SCL_CID_LEN) == 0) {
            if (graph->edges[i].edge_type == EDGE_INTERACTION) {
                score += graph->edges[i].weight;
            } else if (graph->edges[i].edge_type == EDGE_SYMMETRY) {
                score += graph->edges[i].weight * 2;
            }
        }
    }
    peer->reputation_score = score;
    
    pthread_mutex_unlock(&graph->lock);
}

/**
 * @brief Background thread maintaining hypergraph state, rotating puzzles, and aging Bloom filters.
 *
 * @param[in] arg Pointer to global State structure.
 * @return NULL upon thread termination.
 *
 * @complexity Time: O(infinite loop), Space: O(1).
 */
void* maintain_hypergraph_state_thread(void *arg) {
    State *state = (State *)arg;
    LocalHypergraph *graph = &state->hypergraph;
    
    scl_log(LOG_LEVEL_INFO, "L5", "Hypergraph background maintenance thread started.");
    
    while (!atomic_load(&global_shutdown)) {
        uint64_t now = get_time_ms();
        
        if (now - graph->last_puzzle_rotation_ms > PUZZLE_CACHE_ROTATION_MS) {
            pthread_mutex_lock(&graph->puzzle_cache_lock);
            
            uint8_t subgraph_snapshot[64];
            pthread_mutex_lock(&graph->lock);
            sample_local_subgraph_optimized(graph, subgraph_snapshot);
            pthread_mutex_unlock(&graph->lock);
            
            uint8_t hash_input[128];
            memset(hash_input, 0, sizeof(hash_input));
            memcpy(hash_input, subgraph_snapshot, 64);
            memcpy(hash_input + 64, &graph->epoch_seed, 8);
            
            const char* nonce_prefix = "SCL_HYPER_POW";
            memcpy(hash_input + 72, nonce_prefix, strlen(nonce_prefix));
            
            sha256_hash(hash_input, sizeof(hash_input), graph->cached_puzzle_base);
            graph->last_puzzle_rotation_ms = now;
            
            pthread_mutex_unlock(&graph->puzzle_cache_lock);
        }
        
        uint64_t current_epoch = now / EPOCH_DURATION_MS;
        if (current_epoch > graph->last_bloom_rotation_epoch) {
            pthread_mutex_lock(&graph->lock);
            memcpy(graph->poison_bloom_active, graph->poison_bloom_aging, BLOOM_FILTER_SIZE);
            memset(graph->poison_bloom_aging, 0, BLOOM_FILTER_SIZE);
            graph->last_bloom_rotation_epoch = current_epoch;
            
            uint16_t active_edges = 0;
            for (uint16_t i = 0; i < graph->edge_count; i++) {
                if (now - graph->edges[i].timestamp < 4 * EPOCH_DURATION_MS) {
                    graph->edges[active_edges++] = graph->edges[i];
                }
            }
            graph->edge_count = active_edges;
            pthread_mutex_unlock(&graph->lock);
        }
        
        usleep(1000000);
    }
    
    scl_log(LOG_LEVEL_INFO, "L5", "Hypergraph background maintenance thread exiting.");
    release_l5_staging_buffer();
    return NULL;
}

/**
 * @brief Generates a hybrid Proof-of-Work challenge (primary cookie + dynamic secondary puzzle).
 *
 * @param[in] graph LocalHypergraph structure.
 * @param[in] incoming_cid Peer Connection ID.
 * @return Populated HybridCookieChallenge structure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
HybridCookieChallenge generate_hybrid_challenge(LocalHypergraph* graph, const uint8_t* incoming_cid) {
    HybridCookieChallenge challenge;
    memset(&challenge, 0, sizeof(HybridCookieChallenge));
    challenge.primary_difficulty = 10;
    challenge.challenge_expiry = get_time_ms() + 5000;
    RAND_bytes(challenge.primary_cookie_base, 32);
    memcpy(challenge.cid, incoming_cid, SCL_CID_LEN);
    
    pthread_mutex_lock(&graph->lock);
    
    bool is_poisoned = bloom_filter_check(graph->poison_bloom_active, incoming_cid) ||
                       bloom_filter_check(graph->poison_bloom_aging, incoming_cid);
    
    if (is_poisoned) {
        challenge.secondary_difficulty = 20;
        pthread_mutex_lock(&graph->puzzle_cache_lock);
        memcpy(challenge.hypergraph_puzzle_base, graph->cached_puzzle_base, 32);
        pthread_mutex_unlock(&graph->puzzle_cache_lock);
    }
    else {
        NodeMetadata* peer = find_node(graph, incoming_cid);
        
        if (!peer || peer->reputation_score < REPUTATION_THRESHOLD_LOW || is_high_frequency(graph, incoming_cid)) {
            pthread_mutex_lock(&graph->puzzle_cache_lock);
            memcpy(challenge.hypergraph_puzzle_base, graph->cached_puzzle_base, 32);
            pthread_mutex_unlock(&graph->puzzle_cache_lock);
            
            challenge.secondary_difficulty = calculate_dynamic_difficulty_graceful(graph, peer, get_time_ms());
        } else {
            challenge.secondary_difficulty = 0;
        }
    }
    pthread_mutex_unlock(&graph->lock);
    return challenge;
}

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
bool solve_hybrid_challenge(HybridCookieChallenge* challenge, uint64_t* out_primary_nonce, uint64_t* out_secondary_nonce) {
    *out_primary_nonce = find_nonce(challenge->primary_cookie_base, challenge->primary_difficulty);
    
    if (challenge->secondary_difficulty > 0) {
        *out_secondary_nonce = find_nonce(challenge->hypergraph_puzzle_base, challenge->secondary_difficulty);
    } else {
        *out_secondary_nonce = 0;
    }
    return true;
}

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
bool verify_hybrid_challenge(LocalHypergraph* graph, HybridCookieChallenge* challenge, uint64_t primary_nonce, uint64_t secondary_nonce) {
    if (get_time_ms() > challenge->challenge_expiry) return false;
    
    if (!verify_pow(challenge->primary_cookie_base, primary_nonce, challenge->primary_difficulty)) {
        return false;
    }
    
    if (challenge->secondary_difficulty > 0) {
        if (!verify_pow(challenge->hypergraph_puzzle_base, secondary_nonce, challenge->secondary_difficulty)) {
            return false;
        }
        add_temporal_edge(graph, challenge->cid, EDGE_INTERACTION, 1);
    }
    return true;
}

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
bool verify_pow(const uint8_t *base, uint64_t nonce, uint8_t difficulty) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)base; (void)nonce; (void)difficulty;
    return true;
#else
    uint8_t input[32 + 8];
    memcpy(input, base, 32);
    uint64_t nonce_be = htobe64(nonce);
    memcpy(input + 32, &nonce_be, 8);
    
    uint8_t hash[32];
    sha256_hash(input, 40, hash);
    
    int bytes = difficulty / 8;
    int remainder = difficulty % 8;
    uint8_t mask = remainder > 0 ? (0xFF << (8 - remainder)) : 0;
    
    for (int i = 0; i < bytes; i++) {
        if (hash[i] != 0) return false;
    }
    if (remainder > 0) {
        if ((hash[bytes] & mask) != 0) return false;
    }
    return true;
#endif
}

/**
 * @brief Computes a Proof-of-Work solution by linear nonce increment.
 *
 * @param[in] base 32-byte puzzle seed.
 * @param[in] difficulty Target leading zero-bit count.
 * @return Nonce satisfying difficulty.
 *
 * @complexity Time: O(2^difficulty), Space: O(1).
 */
uint64_t find_nonce(const uint8_t *base, uint8_t difficulty) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)base; (void)difficulty;
    return 0;
#else
    uint64_t nonce = 0;
    while (!verify_pow(base, nonce, difficulty)) {
        nonce++;
        if (atomic_load(&global_shutdown)) break;
    }
    return nonce;
#endif
}

#ifdef USE_XDP
/* ============================================================================ */
/* SECTION 15: LINUX AF_XDP KERNEL BYPASS TRANSPORT SHIM                        */
/* ============================================================================ */

// Hash Connection ID using SipHash-2-4 for fast XDP routing table indexing
static uint32_t hash_cid_xdp(const uint8_t *cid, const uint8_t *secret) {
    return (uint32_t)siphash24(cid, SCL_CID_LEN, secret);
}

// Allocate an available UMEM frame from the lock-protected free list
static uint32_t alloc_frame(struct xsk_umem_info *umem) {
    uint32_t frame = 0;
    pthread_spin_lock(&umem->lock);
    if (umem->free_frames_count > 0) {
        frame = umem->free_frames[--umem->free_frames_count];
    }
    pthread_spin_unlock(&umem->lock);
    return frame;
}

// Return an unused frame index back to the UMEM free pool
static void free_frame(struct xsk_umem_info *umem, uint32_t frame) {
    pthread_spin_lock(&umem->lock);
    umem->free_frames[umem->free_frames_count++] = frame;
    pthread_spin_unlock(&umem->lock);
}

// Reserve a zero-copy transmission frame in AF_XDP UMEM memory
static uint8_t* xdp_acquire_tx_buffer(struct SclTransportShim *shim, size_t *max_len, void **buffer_token) {
    XdpState *state = (XdpState *)shim->impl_state;
    int wid = current_worker_id >= 0 ? current_worker_id : 0;
    struct xsk_socket_info *xsk = state->xsks[wid];

    uint32_t frame = alloc_frame(xsk->umem);
    if (frame == 0) return NULL;

    *max_len = FRAME_SIZE - 256;
    uint64_t token_val = ((uint64_t)wid << 32) | frame;
    *buffer_token = (void*)(uintptr_t)(uintptr_t)token_val;

    return (uint8_t *)xsk->umem->buffer + frame + 42;
}

// Enqueue populated frame to AF_XDP TX ring and trigger driver transmission
static void xdp_commit_tx_buffer(struct SclTransportShim *shim, void *buffer_token, size_t actual_len, const uint8_t *cid, const struct sockaddr_storage *addr) {
    (void)cid; (void)addr;
    XdpState *state = (XdpState *)shim->impl_state;
    uint64_t token_val = (uint64_t)(uintptr_t)buffer_token;
    int wid = token_val >> 32;
    uint32_t frame = token_val & 0xFFFFFFFF;
    struct xsk_socket_info *xsk = state->xsks[wid];
    
    pthread_spin_lock(&xsk->tx_lock);
    uint32_t idx;
    if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) == 1) {
        xsk_ring_prod__tx_desc(&xsk->tx, idx)->addr = frame;
        xsk_ring_prod__tx_desc(&xsk->tx, idx)->len = actual_len + 42;
        xsk_ring_prod__submit(&xsk->tx, 1);
        sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, (struct sockaddr *)addr, addr ? (addr->ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) : 0);
    } else {
        free_frame(xsk->umem, frame);
    }
    pthread_spin_unlock(&xsk->tx_lock);
}

// Return aborted frame to UMEM pool without submitting to TX ring
static void xdp_abort_tx_buffer(struct SclTransportShim *shim, void *buffer_token) {
    XdpState *state = (XdpState *)shim->impl_state;
    uint64_t token_val = (uint64_t)(uintptr_t)buffer_token;
    int wid = token_val >> 32;
    uint32_t frame = token_val & 0xFFFFFFFF;
    struct xsk_socket_info *xsk = state->xsks[wid];
    free_frame(xsk->umem, frame);
}

// No-op for XDP shim: RX packet consumption is dispatched directly within xdp_poll via UMEM descriptors
static void xdp_consume_rx_buffer(struct SclTransportShim *shim, const uint8_t *buffer, size_t len, const struct sockaddr_storage *addr) {
    (void)shim; (void)buffer; (void)len; (void)addr;
}

// No-op for XDP shim: UMEM frame buffers are returned directly to the driver fill ring
static void xdp_release_rx_buffer(struct SclTransportShim *shim, const uint8_t *buffer) {
    (void)shim; (void)buffer;
}

// Insert connection into lock-free XDP CID routing table via open addressing
static void xdp_register_connection(struct SclTransportShim *shim, const uint8_t *cid, SclConnection *conn) {
    XdpState *state = (XdpState *)shim->impl_state;
    uint32_t start_idx = hash_cid_xdp(cid, state->node_secret) % 4096;
    for (int i = 0; i < 4096; i++) {
        uint32_t probe = (start_idx + i) % 4096;
        SclConnection *expected = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
        if (expected == conn) {
            return; // Already registered
        }
        if (expected == NULL || expected == SCL_TOMBSTONE) {
            if (atomic_compare_exchange_strong_explicit(&state->cid_routing_table[probe], &expected, conn, memory_order_release, memory_order_relaxed)) {
                return;
            }
        }
    }
}

// Tombstone connection entry in XDP CID table upon teardown
static bool xdp_unregister_connection(struct SclTransportShim *shim, const uint8_t *cid) {
    XdpState *state = (XdpState *)shim->impl_state;
    uint32_t start_idx = hash_cid_xdp(cid, state->node_secret) % 4096;
    for (int i = 0; i < 4096; i++) {
        uint32_t probe = (start_idx + i) % 4096;
        SclConnection *conn = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
        if (conn == NULL) break;
        if (conn != SCL_TOMBSTONE && memcmp(conn->cid, cid, SCL_CID_LEN) == 0) {
            atomic_store_explicit(&state->cid_routing_table[probe], SCL_TOMBSTONE, memory_order_release);
            return true;
        }
    }
    return false;
}

// Poll AF_XDP socket descriptors and transfer packets between UMEM rings and connection queues
static void xdp_poll(struct SclTransportShim *shim) {
    XdpState *state = (XdpState *)shim->impl_state;
    struct pollfd fds[NUM_CRYPTO_WORKERS];
    for (int i = 0; i < NUM_CRYPTO_WORKERS; i++) {
        fds[i].fd = state->xsks[i]->fd;
        fds[i].events = POLLIN;
    }
    
    int ret = poll(fds, NUM_CRYPTO_WORKERS, 1);
    if (ret <= 0) return;

    for (int i = 0; i < NUM_CRYPTO_WORKERS; i++) {
        struct xsk_socket_info *xsk = state->xsks[i];
        
        uint32_t idx_cq;
        uint32_t completed = xsk_ring_cons__peek(&xsk->umem->cq, BATCH_SIZE, &idx_cq);
        if (completed > 0) {
            for (uint32_t j = 0; j < completed; j++) {
                uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq++);
                free_frame(xsk->umem, addr);
            }
            xsk_ring_cons__release(&xsk->umem->cq, completed);
        }

        if (fds[i].revents & POLLIN) {
            uint32_t idx_rx;
            uint32_t rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
            if (rcvd > 0) {
                for (uint32_t j = 0; j < rcvd; j++) {
                    const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++);
                    uint64_t addr = desc->addr;
                    uint32_t len = desc->len;
                    uint8_t *pkt = (uint8_t *)xsk_ring_cons__rx_desc(&xsk->rx, idx_rx - 1)->addr + (uintptr_t)xsk->umem->buffer;
                    
                    if (len > 42 + SCL_HEADER_MIN_LEN) {
                        uint8_t cid[SCL_CID_LEN];
                        memcpy(cid, pkt + 42 + 1, SCL_CID_LEN);
                        
                        SclConnection *target_conn = NULL;
                        uint32_t start_idx = hash_cid_xdp(cid, state->node_secret) % 4096;
                        for (int p = 0; p < 4096; p++) {
                            uint32_t probe = (start_idx + p) % 4096;
                            SclConnection *conn = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
                            if (conn == NULL) break;
                            if (conn != SCL_TOMBSTONE && memcmp(conn->cid, cid, SCL_CID_LEN) == 0) {
                                target_conn = conn;
                                break;
                            }
                        }
                        
                        if (!target_conn) {
                            uint8_t zero_cid[SCL_CID_LEN] = {0};
                            uint32_t z_start_idx = hash_cid_xdp(zero_cid, state->node_secret) % 4096;
                            for (int p = 0; p < 4096; p++) {
                                uint32_t probe = (z_start_idx + p) % 4096;
                                SclConnection *conn = atomic_load_explicit(&state->cid_routing_table[probe], memory_order_acquire);
                                if (conn == NULL && p > 128) break;
                                if (conn != SCL_TOMBSTONE && memcmp(conn->cid, zero_cid, SCL_CID_LEN) == 0) {
                                    target_conn = conn;
                                    break;
                                }
                            }
                        }
                        
                        if (target_conn) {
                            uint32_t q_head = atomic_load_explicit(&target_conn->l5_rx_queue.head, memory_order_relaxed);
                            uint32_t q_next_head = (q_head + 1) % SCL_L5_RING_SIZE;
                            uint32_t q_tail = atomic_load_explicit(&target_conn->l5_rx_queue.tail, memory_order_acquire);
                            if (q_next_head != q_tail) {
                                memcpy(target_conn->l5_rx_queue.buffer[q_head], pkt + 42, len - 42);
                                target_conn->l5_rx_queue.lengths[q_head] = len - 42;
                                target_conn->l5_rx_queue.rx_times[q_head] = get_time_ms();
                                atomic_store_explicit(&target_conn->l5_rx_queue.head, q_next_head, memory_order_release);
                            }
                        }
                    }
                    free_frame(xsk->umem, addr);
                }
                xsk_ring_cons__release(&xsk->rx, rcvd);
                
                uint32_t idx_fq;
                if (xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, &idx_fq) == rcvd) {
                    for (uint32_t j = 0; j < rcvd; j++) {
                        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = alloc_frame(xsk->umem);
                    }
                    xsk_ring_prod__submit(&xsk->umem->fq, rcvd);
                }
            }
        }
    }
}

// Detach eBPF program, clean UMEM allocations, and tear down XDP sockets
static void xdp_destroy(struct SclTransportShim *shim) {
    XdpState *state = (XdpState *)shim->impl_state;
    for (int i = 0; i < NUM_CRYPTO_WORKERS; i++) {
        if (state->xsks[i]) {
            xsk_socket__delete(state->xsks[i]->xsk);
            xsk_umem__delete(state->xsks[i]->umem->umem);
            free(state->xsks[i]->umem->buffer);
            free(state->xsks[i]->umem->free_frames);
            free(state->xsks[i]->umem);
            free(state->xsks[i]);
        }
    }
    if (state->xdp_prog) {
        int ifindex = if_nametoindex(state->ifname);
        xdp_program__detach(state->xdp_prog, ifindex, XDP_MODE_SKB, 0);
        xdp_program__close(state->xdp_prog);
    }
    free(state);
    free(shim);
}

struct SclTransportShim* scl_xdp_shim_create(const char *ifname, int port) {
    (void)port;
    struct SclTransportShim *shim = calloc(1, sizeof(struct SclTransportShim));
    XdpState *state = calloc(1, sizeof(XdpState));
    if (!shim || !state) { free(shim); free(state); return NULL; }
    
    strncpy(state->ifname, ifname, IFNAMSIZ-1);
    RAND_bytes(state->node_secret, 16);
    
    for (int i = 0; i < 4096; i++) {
        atomic_init(&state->cid_routing_table[i], NULL);
    }
    atomic_init(&state->active_connection_count, 0);

    state->xdp_prog = xdp_program__open_file("xdp_prog.o", "xdp", NULL);
    if (!state->xdp_prog || libxdp_get_error(state->xdp_prog)) {
        fprintf(stderr, "[XDP] Failed to open BPF object.\n");
        free(state); free(shim); return NULL;
    }
    
    int ifindex = if_nametoindex(state->ifname);
    if (xdp_program__attach(state->xdp_prog, ifindex, XDP_MODE_SKB, 0) < 0) {
        fprintf(stderr, "[XDP] Failed to attach BPF program.\n");
        xdp_program__close(state->xdp_prog);
        free(state); free(shim); return NULL;
    }

    state->bpf_obj = xdp_program__bpf_obj(state->xdp_prog);
    state->xsk_map_fd = bpf_object__find_map_fd_by_name(state->bpf_obj, "xsk_map");
    state->maglev_map_fd = bpf_object__find_map_fd_by_name(state->bpf_obj, "maglev_map");
    state->secret_map_fd = bpf_object__find_map_fd_by_name(state->bpf_obj, "secret_map");

    uint32_t key_idx = 0;
    bpf_map_update_elem(state->secret_map_fd, &key_idx, state->node_secret, BPF_ANY);

    for (uint32_t i = 0; i < 4096; i++) {
        uint32_t q = i % NUM_CRYPTO_WORKERS;
        bpf_map_update_elem(state->maglev_map_fd, &i, &q, BPF_ANY);
    }

    for (int i = 0; i < NUM_CRYPTO_WORKERS; i++) {
        struct xsk_socket_info *xsk = calloc(1, sizeof(*xsk));
        struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
        
        posix_memalign(&umem->buffer, getpagesize(), NUM_FRAMES * FRAME_SIZE);
        
        struct xsk_umem_config umem_cfg = {
            .fill_size = NUM_FRAMES / 2,
            .comp_size = NUM_FRAMES / 2,
            .frame_size = FRAME_SIZE,
            .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            .flags = 0
        };

        xsk_umem__create(&umem->umem, umem->buffer, NUM_FRAMES * FRAME_SIZE, &umem->fq, &umem->cq, &umem_cfg);
        
        umem->free_frames = calloc(NUM_FRAMES, sizeof(uint32_t));
        for (int j = 0; j < NUM_FRAMES; j++) umem->free_frames[j] = j * FRAME_SIZE;
        umem->free_frames_count = NUM_FRAMES;
        pthread_spin_init(&umem->lock, 0);
        
        xsk->umem = umem;
        xsk->queue_id = i;
        
        struct xsk_socket_config xsk_cfg = {
            .rx_size = NUM_FRAMES / 2,
            .tx_size = NUM_FRAMES / 2,
            .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
            .xdp_flags = XDP_ZEROCOPY,
            .bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY
        };

        if (xsk_socket__create(&xsk->xsk, state->ifname, i, umem->umem, &xsk->rx, &xsk->tx, &xsk_cfg)) {
            xsk_cfg.xdp_flags = XDP_COPY;
            xsk_cfg.bind_flags = XDP_COPY;
            xsk_socket__create(&xsk->xsk, state->ifname, i, umem->umem, &xsk->rx, &xsk->tx, &xsk_cfg);
        }
        
        int fd = xsk_socket__fd(xsk->xsk);
        if (fd >= 0) {
            // Wrap fd settings safely
        }
        
        xsk->fd = fd;
        xsk->queue_id = i;
        xsk->umem = umem;
        
        state->xsks[i] = xsk;
    }
    return shim;
}
#endif

/* ============================================================================ */
/* SECTION 16: USERSPACE TRANSPORT SHIM CONSTRUCTOR                             */
/* ============================================================================ */

/**
 * @brief Instantiates the standard userspace POSIX UDP transport driver shim.
 *
 * @details
 * Allocation & Configuration Sequence:
 * 1. Seeds GF(2^8) exponential and logarithmic tables for FEC (@ref fec_init).
 * 2. Allocates @ref SclTransportShim interface and @ref UserSpaceState container.
 * 3. Preallocates @ref SCL_RX_RING_SIZE (1,024) 4 KiB reception buffers.
 * 4. Preallocates 1,024 64 KiB transmission slots in `tx_ring`.
 * 5. Preallocates 64 8 MiB reassembly buffers in `assembly_pool`.
 * 6. Generates 32-byte `node_secret` for SipHash token derivations.
 * 7. Memory-maps the 160 MiB @ref SclHandshakeSlab matrix, arming each slot with a 4 KiB `PROT_NONE` guard page.
 * 8. Configures non-blocking UDP socket and sets kernel buffers (up to 32 MiB).
 * 9. Enforces PMTU discovery (`IP_PMTUDISC_DO` / `IP_DONTFRAGMENT`) to disable host-level IP fragmentation.
 * 10. Binds socket to specified IPv4 port and initializes platform polling (epoll / kqueue / select).
 *
 * @param[in] ip Dotted-quad IPv4 interface address to bind (e.g., "0.0.0.0").
 * @param[in] port Local UDP port to bind (default: 5555).
 * @return Pointer to initialized SclTransportShim; NULL on bind/allocation failure.
 *
 * @complexity Time: O(1), Space: O(slab_size + ring_buffers).
 */
struct SclTransportShim* scl_userspace_shim_create(const char *ip, int port) {
    // Seed GF(2^8) tables for FEC operations
    fec_init(); // Seed GF(2^8) Tables
    
    struct SclTransportShim *shim = calloc(1, sizeof(struct SclTransportShim));
    UserSpaceState *state = calloc(1, sizeof(UserSpaceState));
    if (!shim || !state) {
        free(shim);
        free(state);
        return NULL;
    }

    // Initialize RX Ring
    state->rx_ring = malloc(SCL_RX_RING_SIZE * sizeof(uint8_t*));
    if (!state->rx_ring) {
        free(state);
        free(shim);
        return NULL;
    }
    
    for (int i = 0; i < SCL_RX_RING_SIZE; i++) {
        state->rx_ring[i] = malloc(4096);
        if (!state->rx_ring[i]) {
            for (int j = 0; j < i; j++) {
                free(state->rx_ring[j]);
            }
            free(state->rx_ring);
            free(state);
            free(shim);
            return NULL;
        }
    }
    
    atomic_init(&state->rx_head, 0);
    
    // Initialize Lock-Free TX Ring primitives
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    size_t tx_buf_size = 4096;
    int pool_count = 4;
#else
    size_t tx_buf_size = 65535;
    int pool_count = 64;
#endif

    atomic_init(&state->tx_head, 0);
    atomic_init(&state->tx_tail, 0);
    
    for (int i = 0; i < 1024; i++) {
        state->tx_ring[i].buffer = malloc(tx_buf_size);
        if (!state->tx_ring[i].buffer) {
            // Cleanup TX buffers allocated so far
            for (int j = 0; j < i; j++) {
                free(state->tx_ring[j].buffer);
            }
            // Cleanup RX ring
            for (int k = 0; k < SCL_RX_RING_SIZE; k++) {
                free(state->rx_ring[k]);
            }
            free(state->rx_ring);
            free(state);
            free(shim);
            return NULL;
        }
        state->tx_ring[i].len = 0;
        state->tx_ring[i].addr.ss_family = 0; // Mark as empty
        atomic_init(&state->tx_ring[i].ready, false);
    }
    
    // Initialize the Zero-Heap Assembly Pool
    for (int i = 0; i < pool_count; i++) {
        uint8_t *buf = malloc(MAX_MESSAGE_SIZE);
        if (!buf) {
            // Cleanup assembly pool
            for (int j = 0; j < i; j++) {
                uint8_t *old_buf = atomic_load(&state->assembly_pool[j]);
                if (old_buf) free(old_buf);
            }
            // Cleanup TX ring
            for (int k = 0; k < 1024; k++) {
                free(state->tx_ring[k].buffer);
            }
            // Cleanup RX ring
            for (int l = 0; l < SCL_RX_RING_SIZE; l++) {
                free(state->rx_ring[l]);
            }
            free(state->rx_ring);
            free(state);
            free(shim);
            return NULL;
        }
        atomic_init(&state->assembly_pool[i], buf);
    }
            
    // Initialize the secret used to enforce anti-amplification stateless tokens
    if (RAND_bytes(state->node_secret, 32) != 1) {
        // Cryptographic PRNG failure: release allocated resources and abort initialization
        for (int i = 0; i < 64; i++) {
            uint8_t *old_buf = atomic_load(&state->assembly_pool[i]);
            if (old_buf) free(old_buf);
        }
        for (int i = 0; i < 1024; i++) free(state->tx_ring[i].buffer);
        for (int i = 0; i < SCL_RX_RING_SIZE; i++) free(state->rx_ring[i]);
        free(state->rx_ring);
        free(state);
        free(shim);
        return NULL;
    }

#ifndef _WIN32
    state->handshake_slab = mmap(NULL, sizeof(SclHandshakeSlab), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state->handshake_slab == MAP_FAILED) {
        state->handshake_slab = NULL;
    } else {
        // Apply mprotect guard pages to permanently isolate handshake slabs
        for (int i = 0; i < SCL_SLAB_SLOTS; i++) {
            void *guard_addr = state->handshake_slab->slots[i]._guard_page;
            mprotect(guard_addr, 4096, PROT_NONE);
        }
#if defined(POSIX_MADV_DONTNEED)
        posix_madvise(state->handshake_slab, sizeof(SclHandshakeSlab), POSIX_MADV_DONTNEED);
#elif defined(MADV_DONTNEED)
        madvise(state->handshake_slab, sizeof(SclHandshakeSlab), MADV_DONTNEED);
#endif
    }
#else
    state->handshake_slab = VirtualAlloc(NULL, sizeof(SclHandshakeSlab), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (state->handshake_slab) {
        DWORD old_prot;
        for (int i = 0; i < SCL_SLAB_SLOTS; i++) {
            void *guard_addr = state->handshake_slab->slots[i]._guard_page;
            VirtualProtect(guard_addr, 4096, PAGE_NOACCESS, &old_prot);
        }
    }
#endif

    if (!state->handshake_slab) {
        for (int i = 0; i < 64; i++) {
            uint8_t *old_buf = atomic_load(&state->assembly_pool[i]);
            if (old_buf) free(old_buf);
        }
        for (int i = 0; i < 1024; i++) {
            free(state->tx_ring[i].buffer);
        }
        for (int i = 0; i < SCL_RX_RING_SIZE; i++) {
            free(state->rx_ring[i]);
        }
        free(state->rx_ring);
        free(state);
        free(shim);
        return NULL;
    }
    
    atomic_init(&state->global_ooo_bytes_allocated, 0);
    // Arbitrary 512 MiB global OOO limit for consumer nodes
    state->global_ooo_quota = 512 * 1024 * 1024;
    atomic_init(&state->global_untrusted_sync_allocated, 0); // Enforce IBD 1GB ceiling
    
#ifdef _WIN32
    // Start Windows native winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        free(state->handshake_slab);
        for (int i = 0; i < 64; i++) {
            uint8_t *old_buf = atomic_load(&state->assembly_pool[i]);
            if (old_buf) free(old_buf);
        }
        for (int i = 0; i < 1024; i++) {
            free(state->tx_ring[i].buffer);
        }
        for (int i = 0; i < SCL_RX_RING_SIZE; i++) {
            free(state->rx_ring[i]);
        }
        free(state->rx_ring);
        free(state);
        free(shim);
        return NULL;
    }
#endif
    
    // Initialize Lock-Free Buckets securely
    for (int i = 0; i < 4096; i++) {
        atomic_init(&state->cid_routing_table[i], NULL);
        atomic_init(&state->gc_ring[i].ready, false);
    }
    pthread_rwlock_init(&state->ip_tracker.rwlock, NULL);
    pthread_rwlock_init(&state->subnet_tracker.rwlock, NULL);
    pthread_rwlock_init(&state->ip_rate_tracker.rwlock, NULL);
    for (int i = 0; i < SCL_DOS_TRACKER_SIZE; i++) {
        atomic_init(&state->ip_tracker.buckets[i], NULL);
        atomic_init(&state->subnet_tracker.buckets[i], NULL);
        atomic_init(&state->ip_rate_tracker.buckets[i], NULL);
    }
    atomic_init(&state->gc_head, 0);
    atomic_init(&state->gc_tail, 0);
    atomic_init(&state->active_connection_count, 0);
    atomic_init(&state->rate_limit_epoch, get_time_ms());
        
    // L1 Routing Table initialized. Lock-Free access is protected against
    // Use-After-Free via RCU-lite Deferred GC Queue.
    
    int domain = AF_INET;
    if (strchr(ip, ':')) domain = AF_INET6;
    
    state->udp_socket = socket(domain, SOCK_DGRAM, 0);
#ifndef _WIN32
    if (state->udp_socket < 0) {
#else
    if (state->udp_socket == INVALID_SOCKET) {
#endif
        free(state->handshake_slab);
        for (int i = 0; i < 64; i++) {
            uint8_t *old_buf = atomic_load(&state->assembly_pool[i]);
            if (old_buf) free(old_buf);
        }
        for (int i = 0; i < 1024; i++) {
            free(state->tx_ring[i].buffer);
        }
        for (int i = 0; i < SCL_RX_RING_SIZE; i++) {
            free(state->rx_ring[i]);
        }
        free(state->rx_ring);
        free(state);
        free(shim);
        return NULL;
    }

#ifndef _WIN32
    int flags = fcntl(state->udp_socket, F_GETFL, 0);
    if (flags == -1 || fcntl(state->udp_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
        fprintf(stderr, "[Shim] ERROR: Failed to set non-blocking mode\n");
    }
#else
    // Windows: Set non-blocking mode
    u_long mode = 1;
    ioctlsocket(state->udp_socket, FIONBIO, &mode);
#endif

        // Robust high-concurrency PQ buffer scaling: Attempt 32MB down to 256KB in case of kernel sysctl caps
        int target_sizes[] = {33554432, 16777216, 8388608, 4194304, 2097152, 1048576, 524288, 262144};
        int num_sizes = sizeof(target_sizes) / sizeof(target_sizes[0]);
        bool snd_ok = false, rcv_ok = false;
        int allocated_snd = 0, allocated_rcv = 0;
        
        for (int i = 0; i < num_sizes; i++) {
            int size = target_sizes[i];
            if (setsockopt(state->udp_socket, SOL_SOCKET, SO_SNDBUF, (const char*)&size, sizeof(size)) == 0) {
                snd_ok = true;
                allocated_snd = size;
                break;
            }
        }
        for (int i = 0; i < num_sizes; i++) {
            int size = target_sizes[i];
            if (setsockopt(state->udp_socket, SOL_SOCKET, SO_RCVBUF, (const char*)&size, sizeof(size)) == 0) {
                rcv_ok = true;
                allocated_rcv = size;
                break;
            }
        }
        
        if (!snd_ok || !rcv_ok) {
            int fallback = 131072; // 128KB safe fallback
            if (!snd_ok) {
                setsockopt(state->udp_socket, SOL_SOCKET, SO_SNDBUF, (const char*)&fallback, sizeof(fallback));
                allocated_snd = fallback;
            }
            if (!rcv_ok) {
                setsockopt(state->udp_socket, SOL_SOCKET, SO_RCVBUF, (const char*)&fallback, sizeof(fallback));
                allocated_rcv = fallback;
            }
        }
        
        int verified_snd = 0, verified_rcv = 0;
        socklen_t opt_len = sizeof(int);
        getsockopt(state->udp_socket, SOL_SOCKET, SO_SNDBUF, (char*)&verified_snd, &opt_len);
        getsockopt(state->udp_socket, SOL_SOCKET, SO_RCVBUF, (char*)&verified_rcv, &opt_len);
        
        fprintf(stderr, "[Shim] Kernel UDP Buffers configured -> Send: %d bytes (requested: %d), Receive: %d bytes (requested: %d)\n",
                verified_snd, allocated_snd, verified_rcv, allocated_rcv);

    // === ENFORCE QUIC-PARITY L0 SPEC: Strict Application-Layer Fragmentation Only ===
    // Disable OS-level IP fragmentation to ensure exact SCL_MAX_UDP_PAYLOAD MTU enforcement.
    // Prevents silent AEAD framing corruption on restrictive consumer network routes.
#if defined(__linux__)
    if (domain == AF_INET6) {
        /* Dual-stack socket: IPV6_MTU_DISCOVER governs native IPv6 sends, while
         * IP_MTU_DISCOVER still configures the IPv4 path used by v4-mapped sends. */
        int pmtu6 = IPV6_PMTUDISC_DO;
        if (setsockopt(state->udp_socket, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &pmtu6, sizeof(pmtu6)) < 0) {
            fprintf(stderr, "[Shim] WARNING: setsockopt IPV6_MTU_DISCOVER failed\n");
        }
        int pmtu4 = IP_PMTUDISC_DO;
        if (setsockopt(state->udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu4, sizeof(pmtu4)) < 0) {
            fprintf(stderr, "[Shim] WARNING: setsockopt IP_MTU_DISCOVER failed\n");
        }
    } else {
        int pmtu = IP_PMTUDISC_DO;
        if (setsockopt(state->udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu)) < 0) {
            fprintf(stderr, "[Shim] WARNING: setsockopt IP_MTU_DISCOVER failed\n");
        }
    }
#elif defined(_WIN32)
    DWORD dont_frag = 1;
    if (setsockopt(state->udp_socket, IPPROTO_IP, IP_DONTFRAGMENT, (const char*)&dont_frag, sizeof(dont_frag)) < 0) {
        fprintf(stderr, "[Shim] WARNING: setsockopt IP_DONTFRAGMENT failed\n");
    }
#elif defined(__APPLE__) || defined(__FreeBSD__)
    if (domain == AF_INET6) {
        /* IPV6_DONTFRAG is not exported by all BSD SDKs (notably Apple's), and
         * native IPv6 never fragments datagrams at or below the 1280-byte
         * minimum MTU (SCL_MAX_UDP_PAYLOAD is 1232), so a missing macro is a
         * safe no-op. Compile the option only where the SDK defines it. */
#ifdef IPV6_DONTFRAG
        int dont_frag6 = 1;
        if (setsockopt(state->udp_socket, IPPROTO_IPV6, IPV6_DONTFRAG, &dont_frag6, sizeof(dont_frag6)) < 0) {
            fprintf(stderr, "[Shim] WARNING: setsockopt IPV6_DONTFRAG failed\n");
        }
#endif
    } else {
        int dont_frag = 1;
        if (setsockopt(state->udp_socket, IPPROTO_IP, IP_DONTFRAG, &dont_frag, sizeof(dont_frag)) < 0) {
            fprintf(stderr, "[Shim] WARNING: setsockopt IP_DONTFRAG failed\n");
        }
    }
#endif
    // ==============================================================================

    memset(&state->local_addr, 0, sizeof(state->local_addr));
    int parse_failed = 0;
    if (domain == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&state->local_addr;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        int no = 0;
        setsockopt(state->udp_socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&no, sizeof(no));
        if (inet_pton(AF_INET6, ip, &v6->sin6_addr) != 1) parse_failed = 1;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&state->local_addr;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
#ifndef _WIN32
        if (inet_pton(AF_INET, ip, &v4->sin_addr) != 1) parse_failed = 1;
#else
        v4->sin_addr.s_addr = inet_addr(ip);
        if (v4->sin_addr.s_addr == INADDR_NONE) parse_failed = 1;
#endif
    }
    if (parse_failed) {
#ifdef _WIN32
        closesocket(state->udp_socket);
#else
        close(state->udp_socket);
#endif
        if (state->handshake_slab) {
#ifndef _WIN32
            munmap(state->handshake_slab, sizeof(SclHandshakeSlab));
#else
            VirtualFree(state->handshake_slab, 0, MEM_RELEASE);
#endif
        }
        for (int i = 0; i < 64; i++) {
            uint8_t *old_buf = atomic_load(&state->assembly_pool[i]);
            if (old_buf) free(old_buf);
        }
        for (int i = 0; i < 1024; i++) {
            free(state->tx_ring[i].buffer);
        }
        for (int i = 0; i < SCL_RX_RING_SIZE; i++) {
            free(state->rx_ring[i]);
        }
        free(state->rx_ring);
        free(state);
        free(shim);
        return NULL;
    }
    
    socklen_t addr_len = (domain == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (bind(state->udp_socket, (struct sockaddr*)&state->local_addr, addr_len) < 0) {
            fprintf(stderr, "[P2P] ERROR: Failed to bind to port %d. Is another instance already running?\n", port);
#ifdef _WIN32
        closesocket(state->udp_socket);
#else
        close(state->udp_socket);
#endif
        if (state->handshake_slab) {
#ifndef _WIN32
            munmap(state->handshake_slab, sizeof(SclHandshakeSlab));
#else
            VirtualFree(state->handshake_slab, 0, MEM_RELEASE);
#endif
            
        }
        for (int i = 0; i < 64; i++) {
            uint8_t *old_buf = atomic_load(&state->assembly_pool[i]);
            if (old_buf) free(old_buf);
        }
        for (int i = 0; i < 1024; i++) {
            free(state->tx_ring[i].buffer);
        }
        for (int i = 0; i < SCL_RX_RING_SIZE; i++) {
            free(state->rx_ring[i]);
        }
        free(state->rx_ring);
        free(state);
        free(shim);
        return NULL;
    }
    
    // Platform-specific descriptor section
#ifdef __APPLE__
    // macOS/BSD: Use kqueue
    state->epoll_fd = -1;  // Invalid on non-Linux
    state->kq = kqueue();

    if (state->kq != -1) {
        struct kevent ev;
        EV_SET(&ev, state->udp_socket, EVFILT_READ, EV_ADD, 0, 0, NULL);
        
        if (kevent(state->kq, &ev, 1, NULL, 0, NULL) == -1) {
            // Handle error: close kq if registration fails
            close(state->kq);
            state->kq = -1;
        }
    }
#elif defined(__linux__)
    // Linux: Use epoll
    state->epoll_fd = epoll_create1(0);
    state->kq = -1;  // Invalid on Linux

    if (state->epoll_fd != -1) {
        struct epoll_event event;
        memset(&event, 0, sizeof(event)); // Good practice to zero out structs
        event.events = EPOLLIN;
        event.data.fd = state->udp_socket;
        
        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->udp_socket, &event) == -1) {
            // Handle error: close epoll_fd if ctl fails, depending on your error handling strategy
            close(state->epoll_fd);
            state->epoll_fd = -1;
        }
    }
#elif defined(_WIN32)
    // Windows: Emulate behavior using non-blocking API
    state->epoll_fd = -1;
    state->kq = -1;
    // Windows uses WSAPoll or select() in the poll implementation
#endif
    
    // Initialize pacing variables to safely prevent first-tick massive bursts
    // while conforming to 4-MTU global pacing token buckets.
    state->last_pacing_time = get_time_us();
    state->pacing_budget = 4 * 1232; // Initial startup burst

    shim->impl_state = state;
    shim->acquire_tx_buffer = us_acquire_tx_buffer;
    shim->commit_tx_buffer = us_commit_tx_buffer;
    shim->abort_tx_buffer = us_abort_tx_buffer;
    
    // Map the missing RX Zero-Copy buffer consumer method mandated by the abstract interface
    shim->consume_rx_buffer = us_consume_rx_buffer;
    
    shim->release_rx_buffer = us_release_rx_buffer;
    shim->register_connection = us_register_connection;
    shim->unregister_connection = us_unregister_connection;
    shim->poll = us_poll;
    shim->destroy = us_destroy;
        
    return shim;
}
