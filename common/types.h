/**
 * @file common/types.h
 * @brief Satocialist Protocol Core Type System, Memory Models, and Synchronization Contexts
 *
 * @details
 * Declares all canonical structures, enumerations, type definitions, and memory layout agreements
 * across the consensus engine, cryptographic subsystems, L0-L4 transport drivers, lock-free
 * indexing tables, and blockchain state accumulators.
 *
 * @section memory_concurrency Concurrency and Memory Layout Guarantees
 * - Cache-Line Alignment: Structures subject to high-frequency cross-core contention
 *   (e.g., @ref SclConnection, @ref SclHandshakeSlot) are explicitly aligned to 64-byte or
 *   4,096-byte boundaries to eliminate false sharing and leverage hardware memory-protection units.
 * - Atomic Primitives: All state transitions shared across thread boundaries utilize C11
 *   `_Atomic` specifiers with explicit memory orders (acquire/release/relaxed) to guarantee
 *   deterministic memory visibility across weakly-ordered CPU architectures (ARM64, x86-64).
 * - Lock Ordering Protocol: To prevent circular deadlock, locks must strictly be acquired
 *   in the following descending hierarchy:
 *     1. `state->mutex` (Global coordinator lock)
 *     2. `state->ledger_mutex` (Blockchain tip & MVCC rollback lock)
 *     3. `state->bc.rwlock` (MMR and coin table read-write lock)
 *     4. `state->wallet_mutex` (Cryptographic key access lock)
 *     5. `state->epoch_mutex` (DKG session barrier lock)
 *     6. `conn->l4_mutex` (Per-connection loss detection & transmission lock)
 *     7. `queue->vote_lock` (Per-block vote queue lock)
 *
 * @section serialization_standards Byte Order and Wire Alignment
 * - All multi-byte integer quantities stored in wire packets or persistent database keys
 *   are strictly encoded in network byte order (Big-Endian) using `htobe16`, `htobe32`, and `htobe64`.
 * - SclRpcHeader is packed to 1-byte alignment and 32-byte total boundary for zero-copy wire casting.
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#ifdef __cplusplus
    #include <atomic>
    template<typename T>
    struct SclAtomicPod {
        T value;
        operator T() const volatile { return value; }
        T operator=(T v) volatile { value = v; return v; }
    };
    #define _Atomic(X) SclAtomicPod< X >
    typedef SclAtomicPod<bool> atomic_bool;

    template<typename T>
    inline T atomic_load(const SclAtomicPod<T>* a) { return a->value; }
    template<typename T>
    inline T atomic_load(const volatile SclAtomicPod<T>* a) { return a->value; }
    template<typename T>
    inline void atomic_store(SclAtomicPod<T>* a, T v) { a->value = v; }
    template<typename T>
    inline void atomic_store(volatile SclAtomicPod<T>* a, T v) { a->value = v; }
    template<typename T>
    inline void atomic_init(SclAtomicPod<T>* a, T v) { a->value = v; }
    template<typename T>
    inline T atomic_fetch_add(SclAtomicPod<T>* a, T v) { T old = a->value; a->value += v; return old; }
    template<typename T>
    inline T atomic_fetch_sub(SclAtomicPod<T>* a, T v) { T old = a->value; a->value -= v; return old; }
#else
    #include <stdatomic.h>
#endif
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <assert.h>
#include "constants.h"

#ifdef USE_XDP
    #include <xdp/xsk.h>
    #include <xdp/libxdp.h>
    #include <net/if.h>
#endif

/* ============================================================================ */
/* 1. TELEMETRY, LOGGING & CONFIGURATION TYPES                                  */
/* ============================================================================ */

/**
 * @enum LogLevel
 * @brief Discrete severity tiers for structured logging and diagnostic telemetry emission.
 */
typedef enum {
    LOG_LEVEL_TRACE = 0, /** High-frequency packet trace, XOF expansion, and per-byte diagnostics. */
    LOG_LEVEL_DEBUG = 1, /** Component lifecycle, state machine transitions, and verification steps. */
    LOG_LEVEL_INFO  = 2, /** Production-level milestones (block commitments, epoch rotations, connections). */
    LOG_LEVEL_WARN  = 3, /** Recoverable protocol faults (replay drops, packet timeouts, retries). */
    LOG_LEVEL_ERROR = 4, /** Cryptographic failures, malformed structures, and unrecoverable packet drops. */
    LOG_LEVEL_FATAL = 5  /** Catastrophic memory exhaustion or unrecoverable initialization failures. */
} LogLevel;

/**
 * @struct DaemonConfig
 * @brief Configuration parameters parsed from CLI arguments or `satocialist.conf`.
 *
 * @details
 * Governs network socket binding, logging granularity, BBRv3 congestion algorithms,
 * mempool thresholds, Prometheus exporter endpoints, and autonomous Auto-Pilot behaviors.
 */
typedef struct {
    char local_ip[64];                     /** Local IPv4/IPv6 address bound by the UDP socket (default "0.0.0.0"). */
    int port;                              /** UDP listening port for P2P transport (default 5555). */
    LogLevel log_level;                    /** Minimum severity threshold for log output filtering. */
    char config_file[256];                 /** Absolute or relative path to the active configuration file. */
    uint64_t initial_rtt_ms;               /** Initial Round-Trip Time baseline in milliseconds before first sample (default 800 ms). */
    uint64_t min_pto_ms;                   /** Minimum Probe Timeout floor in milliseconds preventing premature loss alarms (default 1000 ms). */
    uint64_t max_ack_delay_ms;             /** Maximum delayed ACK coalescence timer in milliseconds (default 25 ms). */
    uint32_t time_threshold_num;           /** Numerator for RFC 9002 loss time threshold (default 9). */
    uint32_t time_threshold_den;           /** Denominator for RFC 9002 loss time threshold (default 8). */
    bool rbf_enabled;                      /** Flag permitting Replace-By-Fee mempool transaction eviction. */
    uint32_t max_pending_ops_config;       /** Maximum unconfirmed operations held in memory (default 1000). */
    uint32_t mempool_async_threshold;      /** Mempool occupancy count triggering asynchronous orphan-pool sweeps. */
    int metrics_port;                      /** Local TCP port serving Prometheus HTTP metric scrape endpoints (default 8000). */
    int websocket_port;                    /** Local TCP port for the browser UI WebSocket bridge (default 5554). */
    char bootstrap_nodes_str[1024];        /** Comma-separated list of bootstrap seed node addresses ("IP:Port"). */
    bool is_daemon;                        /** When true, runs headless as a background system service; otherwise launches CLI menu. */
    bool autopilot_enabled;                /** Flag indicating if autonomous background staking/valuation is active. */
    uint32_t autopilot_valuations_per_hour;/** Automated valuation proposal submissions scheduled per hour. */
    uint32_t autopilot_stake_ratio;        /** Target portfolio percentage ratio of staked capital (0-100%). */
} DaemonConfig;

/* ============================================================================ */
/* 2. PLATFORM SOCKET & MULTIPLEXING HEADERS                                    */
/* ============================================================================ */

#ifndef _WIN32
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <pthread.h>
    #include <sched.h>
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#endif

#ifdef __APPLE__
    #include <sys/types.h>
    #include <sys/event.h>
    #include <sys/time.h>
#elif defined(__linux__)
    #include <sys/epoll.h>
#elif !defined(_WIN32)
    #include <poll.h>
#endif

/** @brief Global atomic shutdown flag observed across all background worker loops to initiate clean shutdown. */
extern atomic_bool global_shutdown;

/* ============================================================================ */
/* 3. LOW-LEVEL CRYPTOGRAPHIC EXTENDED CONTEXTS                                 */
/* ============================================================================ */

/**
 * @struct custom_shake256_inc_ctx
 * @brief OpenSSL-based incremental SHAKE-256 eXtendable Output Function (XOF) context.
 *
 * @details
 * Emulates continuous incremental squeezing of SHAKE-256 streams beyond single-shot digest limits.
 * Employs a pre-allocated 8 KiB inline buffer to eliminate heap allocations in standard verification rounds,
 * automatically promoting to dynamic heap storage if sampling rejection stretches beyond 8 KiB.
 */
typedef struct {
    EVP_MD_CTX *mdctx;         /** Pointer to OpenSSL digest context initialized to EVP_shake256(). */
    uint8_t *buffer;           /** Active squeeze buffer pointer (points to inline_buf or heap). */
    size_t buf_len;            /** Total capacity of the current squeeze buffer in bytes. */
    size_t buf_pos;            /** Current byte read cursor within the squeeze buffer. */
    uint8_t inline_buf[2048];  /** Pre-allocated stack/inline buffer to avoid heap churn. */
} custom_shake256_inc_ctx;

/**
 * @struct Message
 * @brief Standardized network message container for peer-to-peer transport.
 *
 * @details
 * Enforces a flat buffer layout containing a 1-byte message type discriminator, a 4-byte payload length,
 * and a contiguous byte payload bounded by @ref MAX_MESSAGE_SIZE with a 64-byte redzone to ensure safe
 * SIMD vector alignment during cryptographic parsing.
 */
typedef struct {
    uint8_t type;                           /** Message discriminator opcode (see @ref MessageType). */
    uint32_t length;                        /** Active logical payload length in bytes (Big-Endian). */
    uint8_t payload[MAX_MESSAGE_SIZE + 64]; /** Contiguous payload buffer padded with 64-byte SIMD alignment margin. */
} Message;

/**
 * @struct QueueNode
 * @brief Singly-linked list node wrapping a dynamically allocated network message.
 */
typedef struct QueueNode {
    Message *msg;                     /** Pointer to heap-allocated Message struct (owned by queue node). */
    struct QueueNode *next;           /** Pointer to subsequent node in FIFO queue, or NULL at tail. */
} QueueNode;

/**
 * @struct Queue
 * @brief Thread-safe FIFO message queue protected by a POSIX mutual exclusion lock.
 */
typedef struct {
    QueueNode *head;                  /** Pointer to the oldest unread node in the queue. */
    QueueNode *tail;                  /** Pointer to the newest inserted node in the queue. */
    pthread_mutex_t mutex;            /** Mutual exclusion lock serializing enqueue and dequeue operations. */
} Queue;

/* ============================================================================ */
/* 4. L5 RPC WIRE FORMAT & CONNECTION ROUTING STRUCTURES                        */
/* ============================================================================ */

#pragma pack(push, 1)
/**
 * @struct SclRpcHeader
 * @brief 32-byte wire header for L5 RPC commands and response frames.
 *
 * @details
 * Formatted with 1-byte packing and aligned to 32 bytes to allow zero-copy parsing.
 * All multi-byte fields are encoded in network byte order (Big-Endian).
 *
 * Wire Byte Layout:
 * - Bytes 00..00: Version (1 byte)
 * - Bytes 01..01: Flags bitmask (1 byte: Signed=1, Paginated=2, Compressed=4)
 * - Bytes 02..03: Status Code (2 bytes, big-endian)
 * - Bytes 04..05: Method ID (2 bytes, big-endian)
 * - Bytes 06..07: Error Message Byte Length (2 bytes, big-endian)
 * - Bytes 08..15: Request ID (8 bytes, big-endian: timestamp<<16 | salt)
 * - Bytes 16..19: Payload Byte Length (4 bytes, big-endian)
 * - Bytes 20..23: Pagination Cursor (4 bytes, big-endian)
 * - Bytes 24..31: 64-bit SipHash-2-4 checksum (8 bytes, big-endian)
 */
typedef struct {
    uint8_t  version;         /** Protocol version requirement (must match @ref SCL_RPC_VERSION_1). */
    uint8_t  flags;           /** Bitmask: 0x01=SIGNED, 0x02=PAGINATED, 0x04=COMPRESSED. */
    uint16_t status_code;     /** Big-endian status code (e.g., @ref SCL_RPC_STATUS_OK). */
    uint16_t method_id;       /** Big-endian method identifier (0x0000..0x000B). */
    uint16_t error_msg_len;   /** Big-endian length of ASCII error string following header. */
    uint64_t request_id;      /** Big-endian tracking ID: 48-bit timestamp | 16-bit salt. */
    uint32_t payload_len;     /** Big-endian byte count of the uncompressed/compressed argument block. */
    uint32_t cursor;          /** Big-endian pagination cursor or block height parameter. */
    uint64_t checksum;        /** Big-endian 64-bit SipHash-2-4 over Header[0..23] || Error || Payload. */
} SclRpcHeader;
#pragma pack(pop)

static_assert(sizeof(SclRpcHeader) == 32, "SclRpcHeader must be exactly 32 bytes for wire parity");

/**
 * @enum SclConnState
 * @brief Lifecycle states governing the 2-RTT post-quantum QUIC-Parity connection handshake.
 */
typedef enum {
    SCL_CONN_STATE_NONE = 0,             /** Inactive or tombstoned connection state. */
    SCL_CONN_STATE_HANDSHAKING = 1,      /** Initial handshake context initialized; awaiting Flight 1 transmission. */
    SCL_CONN_STATE_FLIGHT1_SENT = 2,     /** Flight 1 transmitted; awaiting Flight 2 response from server. */
    SCL_CONN_STATE_FLIGHT3_READY = 3,    /** Flight 2 received; client pacing Flight 3 reassembly fragments. */
    SCL_CONN_STATE_ESTABLISHED = 4       /** Full mutual authentication achieved; 1-RTT encrypted data transit active. */
} SclConnState;

/**
 * @struct DoSNode
 * @brief Lock-free chained hash table entry for IP and subnet rate-limiting trackers.
 */
typedef struct DoSNode {
    uint8_t key[16];                     /** 16-byte IPv6 or IPv4-mapped address key. */
    _Atomic(uint32_t) count;             /** Atomic counter tracking active incomplete slabs or packet rates. */
    struct DoSNode *next;                /** Collision bucket singly-linked list pointer. */
} DoSNode;

/**
 * @struct DoSTrackerTable
 * @brief Hash table tracking per-IP and per-subnet connection frequencies for anti-amplification defense.
 */
typedef struct {
    _Atomic(DoSNode *) buckets[SCL_DOS_TRACKER_SIZE]; /** Atomic pointer array to collision buckets. */
    pthread_rwlock_t rwlock;                          /** Read-write lock protecting table sweeps. */
} DoSTrackerTable;

/**
 * @brief Normalizes a sockaddr_storage (IPv4 or IPv6) into a canonical 16-byte key for DoS tracking.
 * @param[in] addr Pointer to sockaddr_storage endpoint.
 * @param[out] key 16-byte buffer populated with native IPv6 or ::ffff:IPv4.
 */
static inline void ip_to_16(const struct sockaddr_storage *addr, uint8_t key[16]) {
    memset(key, 0, 16);
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        key[10] = 0xFF;
        key[11] = 0xFF;
        memcpy(key + 12, &in->sin_addr.s_addr, 4);
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        memcpy(key, &in6->sin6_addr, 16);
    }
}

#define ip4_to_16(ip, key) do { \
    struct sockaddr_storage _temp_ss; \
    memset(&_temp_ss, 0, sizeof(_temp_ss)); \
    _temp_ss.ss_family = AF_INET; \
    ((struct sockaddr_in *)&_temp_ss)->sin_addr.s_addr = (ip); \
    ip_to_16(&_temp_ss, (key)); \
} while(0)

/**
 * @struct SclSpscQueue
 * @brief Lock-free Single-Producer Single-Consumer (SPSC) circular ring buffer for zero-copy L0 -> L5 packet transfer.
 *
 * @details
 * Decouples the raw UDP network driver (L0) from the heavy post-quantum cryptographic application workers (L5).
 * The driver writes to `head` using release semantics; the application worker reads from `tail` using acquire semantics.
 */
typedef struct {
    uint8_t **buffer;               /** Array of pointers to pre-allocated 4 KiB packet frame buffers. */
    size_t *lengths;                /** Array storing physical byte lengths of each incoming packet frame. */
    struct sockaddr_storage *addrs; /** Array storing network source socket addresses for each frame. */
    uint64_t *rx_times;             /** Array storing arrival timestamps in milliseconds for RTT jitter calculation. */
    _Atomic(uint32_t) head;         /** Write index modified strictly by the L0 network driver. */
    _Atomic(uint32_t) tail;         /** Read index modified strictly by the assigned L5 consumer thread. */
} SclSpscQueue;

/**
 * @struct SclUnackedPacket
 * @brief Metadata tracking an in-flight unacknowledged packet for RFC 9002 loss detection and BBRv3 congestion control.
 */
typedef struct SclUnackedPacket {
    uint64_t packet_num;              /** Monotonically increasing packet sequence number. */
    uint64_t time_sent;               /** Monotonic timestamp in milliseconds when packet was pushed to hardware. */
    size_t bytes_in_flight;           /** Serialized wire byte size contributing to network congestion volume. */
    bool is_datagram;                 /** When true, dropped on loss; when false, retransmitted on loss. */
    bool is_fec_protected;            /** When true, grants an additional 1/2 RTT timeout margin before loss declaration. */
    uint8_t retransmit_count;         /** Reliable-stream retransmission attempts for this packet (storm circuit-breaker). */
    uint64_t delivered_at_tx;         /** BBRv3: Cumulative bytes delivered at the moment this packet was sent. */
    uint64_t delivered_time_at_tx;    /** BBRv3: Monotonic timestamp at the moment this packet was sent. */
    uint8_t *raw_packet;              /** Heap-allocated copy of unencrypted stream payload for retransmission. */
    struct SclUnackedPacket *next;    /** Singly-linked list pointer in connection's unacknowledged queue. */
} SclUnackedPacket;

/**
 * @struct SclConnection
 * @brief 64-byte cache-line aligned connection context managing L1-L4 transport state.
 *
 * @details
 * Employs C11 anonymous structures aligned to 64-byte boundaries to segregate frequently accessed
 * fields onto independent cache lines, eliminating cross-core false sharing between the L0 driver,
 * BBRv3 pacing timers, and cryptographic workers.
 */
typedef struct __attribute__((aligned(64))) SclConnection {
    /* --- 1. Identity & L1 Path Migration --- */
    struct __attribute__((aligned(64))) {
        uint8_t cid[SCL_CID_LEN];                      /** Cryptographic Connection Identifier (20 bytes). */
        struct sockaddr_storage current_path;          /** Active verified address and port endpoint. */
        struct sockaddr_storage pending_path;          /** Candidate address undergoing PATH_CHALLENGE probe validation. */
        uint8_t path_challenge_payload[8];             /** 8-byte random challenge nonce transmitted in probe. */
        bool is_migrating_path;                        /** Flag indicating path validation is in progress. */
        uint64_t path_challenge_time;                  /** Monotonic timestamp of last PATH_CHALLENGE transmission. */
        bool has_pending_path_response;                /** Flag indicating PATH_RESPONSE frame must be dispatched. */
        uint8_t path_response_payload[8];              /** 8-byte challenge payload to reflect in PATH_RESPONSE. */
        bool pending_new_cid;                          /** Flag indicating NEW_CONNECTION_ID frame must be dispatched. */
        uint8_t new_cid_payload[SCL_CID_LEN];          /** Replacement CID payload to be scheduled for transmission. */
        uint8_t stateless_reset_token[16];             /** 16-byte HMAC token identifying surviving core reset signals. */
        bool has_stateless_reset_token;                /** Flag indicating valid stateless reset token is registered. */
    };

    /* --- 2. Congestion Control & Pacing (BBRv3) --- */
    struct __attribute__((aligned(64))) {
        _Atomic(uint64_t) next_packet_num;             /** Atomic monotonic packet counter for outbound framing. */
        uint32_t cwnd;                                 /** Congestion window in bytes governing in-flight capacity. */
        uint32_t bytes_in_flight;                      /** Sum of bytes of all sent packets currently unacknowledged. */
        size_t path_mtu;                               /** Discovered Path MTU in bytes (clamped to link bounds). */
        uint8_t bbr_state;                             /** BBRv3 state machine: 0=STARTUP, 1=DRAIN, 2=PROBE_BW, 3=PROBE_RTT. */
        uint64_t bbr_max_bw;                           /** Maximum bottleneck bandwidth filter estimate (bytes/sec). */
        uint64_t bbr_min_rtt;                          /** Minimum round-trip time tracking window in milliseconds. */
        uint64_t bbr_delivered;                        /** Cumulative bytes delivered and acknowledged over session life. */
        uint64_t bbr_delivered_time;                   /** Timestamp in milliseconds of most recent delivery update. */
        uint64_t bbr_cycle_stamp;                      /** Timestamp in milliseconds marking the current PROBE_BW phase. */
        uint8_t bbr_cycle_idx;                         /** Active index in the 8-phase PROBE_BW pacing gain cycle. */
        uint64_t bbr_min_rtt_stamp;                    /** Timestamp when min_rtt was last observed (expires at 10s). */
        uint64_t bbr_probe_rtt_done_stamp;             /** Expiration timestamp for the PROBE_RTT duration (200 ms). */
        uint32_t bbr_prior_cwnd;                       /** Saved congestion window restored upon exiting PROBE_RTT. */
        uint64_t pacing_budget;                        /** Leaky token bucket byte budget available for immediate transmit. */
        uint64_t last_pacing_time;                     /** Monotonic timestamp in microseconds of last pacing calculation. */
        uint64_t last_tx_time;                         /** Monotonic timestamp in milliseconds of last UDP egress activity. */
    };

    /* --- 3. L3 Fragmentation & FEC Matrix --- */
    struct __attribute__((aligned(64))) {
        uint8_t *active_fragment_buffer;               /** Pointer to heap buffer being incrementally paced into chunks. */
        size_t active_fragment_len;                    /** Total byte length of the payload undergoing fragmentation. */
        uint64_t active_fragment_stream_offset;        /** Stream offset identifier for head-of-line ordering. */
        uint16_t active_fragment_data_total;           /** Total number of data chunks dividing the active message. */
        uint16_t active_fragment_fec_total;            /** Total number of Reed-Solomon parity shards generated. */
        uint16_t active_fragment_current;              /** Index of the chunk currently queued for transmission. */
        bool active_fragment_is_datagram;              /** True if fragmented payload is an unreliable datagram. */
        bool active_fragment_is_flight3;               /** True if payload is Handshake Flight 3 (Long Header). */
        uint8_t *active_fec_parity[2];                 /** Pre-allocated 1100-byte scratch buffers for P0 and P1 parity. */
        uint64_t next_tx_stream_offset;                /** Next monotonic stream offset assigned to outbound streams. */
        uint64_t expected_rx_stream_offset;            /** Next contiguous stream offset expected by receiver. */
    };

    /* --- 4. Cryptographic Session State --- */
    struct __attribute__((aligned(64))) {
        uint8_t current_aes_gcm_key[32];               /** 256-bit symmetric AES-GCM session key for 1-RTT traffic. */
        uint8_t flight3_aes_gcm_key[32];               /** 256-bit intermediate key encrypting Flight 3 handshake slabs. */
        uint8_t ephemeral_kyber_pubkey[KYBER_PUBKEY_LEN];   /** Ephemeral Kyber-512 public key for forward secrecy. */
        uint8_t ephemeral_kyber_privkey[KYBER_SECRETKEY_LEN];/** Ephemeral Kyber-512 private key (wiped post-handshake). */
        uint8_t handshake_token[64];                   /** Anti-amplification token reflecting server stateless cookie. */
        uint8_t handshake_token_len;                   /** Byte length of active handshake token. */
        uint8_t rpc_siphash_key[16];                   /** 128-bit key for SipHash-2-4 L5 RPC fast checksumming. */
    };

    /* --- 5. Flow Control & L3 Egress Multiplexing --- */
    struct __attribute__((aligned(64))) {
        uint64_t tx_max_data;                          /** Cumulative stream bytes permitted to send by receiver. */
        uint64_t rx_max_data;                          /** Cumulative stream bytes permitted to receive by local node. */
        uint64_t tx_dispatched_data;                   /** Total stream payload bytes transmitted over session life. */
        uint64_t rx_consumed_data;                     /** Total stream payload bytes delivered to L5 application layer. */
        bool pending_max_data_update;                  /** Flag indicating MAX_DATA frame must be sent to expand window. */
        Queue tx_datagram_queue;                       /** High-priority queue for unreliable consensus votes. */
        Queue tx_stream_queue;                         /** Reliable queue for transactions, blocks, and RPC streams. */
        int32_t bdpq_deficit;                          /** Deficit round-robin balance arbiter between datagram and stream. */
    };

    /* --- 6. L4 Reliability & Loss Detection --- */
    struct __attribute__((aligned(64))) {
        uint64_t smoothed_rtt;                         /** RFC 9002 exponentially-weighted moving average RTT (ms). */
        uint64_t rttvar;                               /** RFC 9002 Round-Trip Time variation estimate (ms). */
        uint64_t min_rtt;                              /** Lowest observed RTT sample over current connection history (ms). */
        uint32_t pto_count;                            /** Number of consecutive Probe Timeouts without receiving ACK. */
        uint64_t largest_acked_packet;                 /** Highest packet sequence number acknowledged by remote peer. */
        uint64_t loss_time;                            /** Monotonic timestamp in milliseconds when next loss check is due. */
        SclUnackedPacket *unacked_head;                /** Oldest in-flight unacknowledged packet tracking node. */
        SclUnackedPacket *unacked_tail;                /** Newest in-flight unacknowledged packet tracking node. */
        pthread_mutex_t l4_mutex;                      /** Mutex protecting retransmission queues, RTT, and loss timers. */
        uint64_t pending_acks[256];                    /** Coalesced array of received packet numbers awaiting ACK. */
        uint64_t pending_acks_time[256];               /** Arrival timestamps of pending packets for delay calculation. */
        uint32_t pending_ack_count;                    /** Current count of un-flushed acknowledgments. */
        uint64_t last_ack_trigger_time;                /** Timestamp in milliseconds of most recent ACK dispatch. */
    };

    /* --- 7. Replay Protection --- */
    struct __attribute__((aligned(64))) {
        uint64_t replay_window_bitmask[SCL_MAX_REPLAY_WINDOW / 64]; /** Sliding bitmap tracking observed packet numbers. */
        _Atomic(uint64_t) replay_highest_seen;         /** Highest packet number successfully authenticated. */
        uint64_t dynamic_replay_window_size;           /** Active bit width of the sliding window (4,096 to 65,536). */
    };

    /* --- 8. Handshake, State Flags & Pointers --- */
    struct __attribute__((aligned(64))) {
        SclSpscQueue l5_rx_queue;                      /** Zero-copy SPSC queue transferring packets to application core. */
        void *ooo_buffer_head;                         /** Pointer to singly-linked list of active @ref OOO_Message slabs. */
        size_t ooo_bytes_allocated;                    /** Cumulative memory in bytes allocated to this connection's OOO pool. */
        bool is_handshake_complete;                    /** True once Flight 3 is verified and 1-RTT keys installed. */
        SclConnState handshake_state;                  /** Active progression stage of the handshake protocol. */
        uint64_t handshake_cookie;                     /** Stateless 64-bit cookie validating source IPv4 address. */
        uint8_t required_pow_bits;                     /** Proof-of-work zero-bit prefix difficulty for Flight 1. */
        uint8_t secondary_pow_bits;                    /** Secondary hypergraph puzzle difficulty applied during attack. */
        uint8_t hypergraph_puzzle_base[32];            /** 32-byte puzzle seed for secondary Proof-of-Work challenge. */
        bool is_untrusted_sync;                        /** True if connection is non-staked initial block download peer. */
        _Atomic(uint64_t) last_rx_time;                /** Timestamp in milliseconds of most recent packet arrival. */
        _Atomic(uint32_t) aead_fail_streak;            /** Consecutive AEAD authentication failures (session-divergence circuit-breaker). */
        _Atomic(int) ref_count;                        /** Lock-free reference counter governing object reclamation. */
        _Atomic(bool) is_processing;                   /** Spin-lock preventing concurrent worker processing of one context. */
        bool use_relay;                                /** True if traffic must encapsulate via blind TURN-like relay. */
        struct sockaddr_storage relay_path;            /** Destination socket coordinates of intermediate relay node. */
    };

    /* --- 9. RPC Multiplexer State --- */
    struct __attribute__((aligned(64))) {
        _Atomic(uint32_t) rpc_token_budget;            /** Leaky token bucket bounding inbound L5 RPC computational cost. */
        _Atomic(uint64_t) last_rpc_token_refill;       /** Timestamp in milliseconds of last token bucket replenishment. */
        _Atomic(uint8_t) active_rpc_streams;           /** Active concurrent RPC queries executing on this connection. */
        uint64_t rpc_recent_request_ids[256];          /** Circular buffer tracking recent request IDs for anti-replay. */
        uint32_t rpc_request_idx;                      /** Write cursor index within rpc_recent_request_ids. */
        uint64_t rpc_highest_seen_timestamp;          /** Highest observed request timestamp in milliseconds. */
    };
} SclConnection;

/**
 * @struct SclTransportShim
 * @brief Unified abstract interface for L0 network drivers (Linux XDP, BSD kqueue, Windows IOCP/select).
 */
struct SclTransportShim {
    /** @brief Reserves a zero-copy frame buffer in the driver transmission ring. */
    uint8_t* (*acquire_tx_buffer)(struct SclTransportShim *shim, size_t *max_len, void **buffer_token);
    /** @brief Commits an acquired transmission buffer and initiates immediate hardware egress. */
    void (*commit_tx_buffer)(struct SclTransportShim *shim, void *buffer_token, size_t actual_len, const uint8_t *cid, const struct sockaddr_storage *addr);
    /** @brief Releases an acquired transmission buffer without sending it. */
    void (*abort_tx_buffer)(struct SclTransportShim *shim, void *buffer_token);
    /** @brief Ingress callback processing raw packet buffers arriving from physical network interfaces. */
    void (*consume_rx_buffer)(struct SclTransportShim *shim, const uint8_t *buffer, size_t len, const struct sockaddr_storage *addr);
    /** @brief Returns an expired receive buffer back to the driver's free memory pool. */
    void (*release_rx_buffer)(struct SclTransportShim *shim, const uint8_t *buffer);
    /** @brief Maps a Connection ID (CID) to an active SclConnection instance in the driver routing table. */
    void (*register_connection)(struct SclTransportShim *shim, const uint8_t *cid, SclConnection *conn);
    /** @brief Removes a CID from the driver routing table, replacing it with a tombstone marker. */
    bool (*unregister_connection)(struct SclTransportShim *shim, const uint8_t *cid);
    /** @brief Non-blocking event loop iteration executing driver I/O and packet dispatching. */
    void (*poll)(struct SclTransportShim *shim);
    /** @brief Cleans up driver state, tears down kernel bypass interfaces, and releases sockets. */
    void (*destroy)(struct SclTransportShim *shim);
    void *impl_state; /** Opaque pointer to platform-specific state (XdpState or UserSpaceState). */
};

/**
 * @enum SlabSlotState
 * @brief State descriptor for individual slots in the L1 Handshake Reassembly Slab.
 */
typedef enum {
    SCL_SLOT_FREE = 0,               /** Slot is available for new connection allocation. */
    SCL_SLOT_FLIGHT1 = 1,            /** Transient state locking slot during eviction/replacement. */
    SCL_SLOT_FLIGHT3_INCOMPLETE = 2  /** Slot actively accumulating Flight 3 fragments from client. */
} SlabSlotState;

/**
 * @struct SclHandshakeSlot
 * @brief Pre-allocated 16 KiB slot in the L1 Handshake Matrix for reassembling Flight 3.
 *
 * @details
 * Aligned to 4,096 bytes and terminated with a hardware guard page (`_guard_page`) with `PROT_NONE`
 * to detect and instantly abort buffer overflows.
 */
typedef struct __attribute__((aligned(4096))) {
    _Atomic(SlabSlotState) state;                  /** Atomic slot progression state. */
    uint64_t expiration_time;                      /** Monotonic timestamp in milliseconds when slot expires. */
    struct sockaddr_storage client_addr;           /** Remote socket address (IPv4 or IPv6). */
    uint8_t connection_token[64];                  /** Authenticated stateless token identifying client context. */
    _Atomic(uint64_t) next_packet_num;             /** Monotonic packet sequence counter for stateless ACKs. */
    uint8_t fragment_tracker[64];                  /** Bitmap tracking arrival of up to 14 data chunks. */
    uint8_t parity_tracker[16];                    /** Bitmap tracking arrival of up to 16 parity shards. */
    uint8_t parity_buffers[16][SCL_MAX_CHUNK_SIZE];/** Contiguous memory holding received parity shards. */
    uint8_t buffer[SCL_SLAB_SLOT_SIZE];            /** Contiguous 16 KiB buffer holding reassembled Flight 3 payload. */
    size_t assembled_length;                       /** Cumulative byte count of reassembled data. */
    bool is_tier1_staked;                          /** True if client provided an early stake proof. */
    uint8_t _guard_page[4096];                     /** Page-aligned guard memory configured with PROT_NONE. */
} SclHandshakeSlot;

/**
 * @struct SclHandshakeSlab
 * @brief Fixed-size memory slab matrix (160 MiB) supporting up to 10,000 concurrent handshake reassemblies.
 */
typedef struct {
    SclHandshakeSlot slots[SCL_SLAB_SLOTS];        /** Array of 10,000 pre-allocated 16 KiB handshake slots. */
    _Atomic(uint32_t) active_tier1;                /** Active count of staked (Tier 1) connection slots. */
    _Atomic(uint32_t) active_tier2;                /** Active count of un-staked (Tier 2) connection slots. */
} SclHandshakeSlab;

/**
 * @struct SclTxRingSlot
 * @brief Individual slot within the lock-free MPSC transmission ring buffer.
 */
typedef struct {
    uint8_t *buffer;                               /** Pre-allocated transmission buffer (64 KiB). */
    size_t len;                                    /** Wire byte length of the staged packet. */
    struct sockaddr_storage addr;                  /** Destination network socket coordinates. */
    _Atomic(bool) ready;                           /** Atomic flag indicating slot is populated and ready for transmit. */
} SclTxRingSlot;

/**
 * @enum GcType
 * @brief Discriminator defining the pointer type held in a deferred garbage collection slot.
 */
typedef enum {
    GC_TYPE_CONNECTION,                            /** Slot holds an SclConnection pointer awaiting destruction. */
    GC_TYPE_SNAPSHOT                               /** Slot holds a GameStateSnapshot pointer awaiting release. */
} GcType;

/**
 * @struct SclGcSlot
 * @brief Individual entry in the RCU-lite deferred garbage collection ring buffer.
 */
typedef struct {
    void *ptr;                                     /** Pointer to resource undergoing deferred retirement. */
    GcType type;                                   /** Type tag indicating appropriate destructor routine. */
    uint64_t tombstone_time;                       /** Timestamp in milliseconds when resource was marked dead. */
    _Atomic(bool) ready;                           /** Atomic flag indicating tombstone slot is occupied. */
} SclGcSlot;

/**
 * @struct RelayMapping
 * @brief State entry mapping a Connection ID to a client's public address for blind relay routing.
 */
typedef struct {
    uint8_t cid[SCL_CID_LEN];                      /** Connection ID identifying the target traffic flow. */
    struct sockaddr_storage client_addr;           /** Public socket address of the target destination. */
    uint64_t expiry;                               /** Expiration timestamp in milliseconds (5-minute TTL). */
} RelayMapping;

#ifdef USE_XDP
/** @brief Internal XDP UMEM frame management structure for zero-copy Linux kernel bypass. */
struct xsk_umem_info {
    struct xsk_ring_prod fq;                       /** Fill ring queuing empty frames to kernel. */
    struct xsk_ring_cons cq;                       /** Completion ring receiving transmitted frames. */
    struct xsk_umem *umem;                         /** libbpf UMEM context handle. */
    void *buffer;                                  /** Memory-mapped packet buffer area. */
    pthread_spinlock_t lock;                       /** Spin-lock serializing frame allocations. */
    uint32_t *free_frames;                         /** Array of free frame offsets. */
    uint32_t free_frames_count;                    /** Available frame count. */
};

/** @brief Per-queue AF_XDP socket encapsulation. */
struct xsk_socket_info {
    struct xsk_ring_cons rx;                       /** Receive ring transferring incoming packets from driver. */
    struct xsk_ring_prod tx;                       /** Transmit ring passing outbound packets to driver. */
    struct xsk_umem_info *umem;                    /** Reference to backing UMEM memory structure. */
    struct xsk_socket *xsk;                        /** AF_XDP socket handle. */
    int queue_id;                                  /** Hardware network interface queue index. */
    int fd;                                        /** Socket file descriptor. */
    pthread_spinlock_t tx_lock;                    /** Spin-lock protecting transmit ring reservations. */
};

/** @brief Complete state container for the Linux eBPF/XDP transport driver shim. */
typedef struct {
    struct xsk_socket_info *xsks[NUM_CRYPTO_WORKERS];/** Array of per-core AF_XDP sockets. */
    struct bpf_object *bpf_obj;                    /** Parsed eBPF object reference. */
    int prog_fd;                                   /** File descriptor of loaded XDP program. */
    int xsk_map_fd;                                /** BPF map file descriptor routing packets to AF_XDP sockets. */
    int maglev_map_fd;                             /** BPF map file descriptor mapping hash buckets to queues. */
    int secret_map_fd;                             /** BPF map file descriptor storing SipHash key. */
    uint8_t node_secret[16];                       /** Node SipHash-2-4 secret key. */
    char ifname[IFNAMSIZ];                         /** Bound network interface name (e.g., "eth0"). */
    _Atomic(SclConnection *) cid_routing_table[4096];/** Maglev-style lock-free CID routing table. */
    _Atomic uint32_t active_connection_count;      /** Active connection count. */
    struct xdp_program *xdp_prog;                  /** libxdp program reference. */
} XdpState;
#endif

/**
 * @struct UserSpaceState
 * @brief Platform-agnostic state container for standard userspace POSIX UDP transport driver.
 */
typedef struct {
#ifndef _WIN32
    int udp_socket;                                /** Bound POSIX UDP socket descriptor. */
#else
    SOCKET udp_socket;                             /** Bound Winsock socket handle. */
#endif
    struct sockaddr_storage local_addr;            /** Local address and port to which socket is bound. */
    uint8_t **rx_ring;                             /** Array of pre-allocated 4 KiB reception buffers. */
    _Atomic(uint32_t) rx_head;                     /** Write cursor within the reception ring. */
    RelayMapping relay_table[256];                 /** NAT traversal blind relay routing table. */
    uint32_t relay_count;                          /** Count of registered relay routes. */
    SclTxRingSlot tx_ring[1024];                   /** Lock-free MPSC transmission ring buffer array. */
    _Atomic(uint32_t) tx_head;                     /** Reservation cursor for transmission slots. */
    _Atomic(uint32_t) tx_tail;                     /** Egress dispatch cursor for transmission slots. */
    _Atomic(uint8_t *) assembly_pool[64];          /** Pre-allocated 8 MiB buffers for zero-heap reassembly. */
    _Atomic(SclConnection *) cid_routing_table[4096];/** Lock-free CID lookup table (4,096 buckets). */
    SclGcSlot gc_ring[4096];                       /** Lock-free RCU-lite deferred garbage collection ring. */
    _Atomic(uint32_t) gc_head;                     /** Enqueue cursor for dead resource tombstones. */
    _Atomic(uint32_t) gc_tail;                     /** Retirement cursor for finalized resources. */
    uint64_t pacing_budget;                        /** Leaky token bucket byte budget for driver-level pacing. */
    uint64_t last_pacing_time;                     /** Timestamp in microseconds of last pacing update. */
    SclHandshakeSlab *handshake_slab;              /** Memory-mapped 160 MiB matrix for Flight 3 reassembly. */
    _Atomic(size_t) global_ooo_bytes_allocated;    /** Cumulative bytes allocated across all OOO message slabs. */
    size_t global_ooo_quota;                       /** Global ceiling on OOO allocations (512 MiB). */
    _Atomic(size_t) global_untrusted_sync_allocated;/** Cumulative memory allocated to untrusted sync connections. */
#ifndef _WIN32
    int epoll_fd;                                  /** Linux epoll file descriptor (or -1 on non-Linux). */
    int kq;                                        /** macOS/BSD kqueue file descriptor (or -1 on non-BSD). */
#endif
    uint8_t node_secret[32];                       /** Random node secret generating stateless tokens. */
    uint32_t slab_sweep_idx;                       /** Sweeper cursor index within handshake slab matrix. */
    uint64_t last_sweep_time;                      /** Timestamp in milliseconds of last fractional slab sweep. */
    DoSTrackerTable ip_tracker;                    /** Rate table tracking connections per IPv4 address. */
    DoSTrackerTable subnet_tracker;                /** Rate table tracking connections per /24 subnet. */
    DoSTrackerTable ip_rate_tracker;               /** Rate table tracking packets per second per IP. */
    _Atomic(uint32_t) active_connection_count;     /** Cumulative active connections handled by shim. */
    _Atomic(uint64_t) rate_limit_epoch;            /** Timestamp in milliseconds marking 1-second rate limit epoch. */
} UserSpaceState;

/**
 * @struct OOO_Message
 * @brief Slab-allocated out-of-order application message reassembly structure.
 *
 * @details
 * Employs a contiguous trailing flexible array (`buffer[]`) to hold payload chunks without
 * fragmentation. Arrival of up to 8,192 data chunks and 2,048 parity shards is tracked via
 * bitmasks (`data_mask` and `parity_mask`), enabling O(1) insertion and complete verification.
 */
typedef struct OOO_Message {
    uint64_t stream_offset;                        /** Sequential stream offset identifier. */
    uint16_t total_frags;                          /** Expected total count of data chunks (excludes parity). */
    uint64_t expiration_time;                      /** Monotonic timestamp in milliseconds when reassembly expires. */
    size_t assembled_length;                       /** Cumulative byte count of fully assembled data payload. */
    bool is_complete;                              /** Cached flag indicating all required data chunks are present. */
    uint64_t data_mask[SCL_DATA_MASK_WORDS];       /** Bitmask tracking received data chunk indices. */
    uint64_t parity_mask[SCL_PARITY_MASK_WORDS];   /** Bitmask tracking received Reed-Solomon parity shard indices. */
    uint8_t *parity_slab;                          /** 64-byte aligned slab holding RS parity shards (up to 2.2 MiB). */
    struct OOO_Message *next;                      /** Singly-linked list pointer in connection's OOO chain. */
    uint8_t buffer[];                              /** Flexible array member storing reassembled payload bytes. */
} OOO_Message;

/**
 * @struct SclRpcPaymentChallenge
 * @brief Binary challenge emitted by node when SCL_RPC_STATUS_PAYMENT_REQUIRED is returned.
 * Total size: 8 + 8 + 32 + 32 + 8 + 2 = 90 bytes.
 */
typedef struct __attribute__((aligned(1))) {
    uint64_t amount_subunits;          /** Required payment in atomic subunits (Big-Endian). */
    uint64_t price_rate_lock_id;       /** Ephemeral price lock ID for dynamic rates. */
    uint8_t  recipient_address[USER_ID_LEN]; /** 32-byte User ID / Address to receive payment. */
    uint8_t  challenge_hash[32];       /** SHA256(request_id || method_id || salt). */
    uint64_t valid_until_timestamp;    /** Milliseconds timestamp when challenge expires (Big-Endian). */
    uint16_t accepted_payment_types;   /** Bitmask: 0x01 = OP_TRANSFER_POINTER, 0x02 = OP_REDEEM_CENTINEL (Big-Endian). */
} SclRpcPaymentChallenge;

/**
 * @struct SclRpcPaymentReceipt
 * @brief Proof of payment attached by caller when replaying a metered request.
 * Total size: 1 + 32 + 8 = 41 bytes.
 */
typedef struct __attribute__((aligned(1))) {
    uint8_t  payment_type;             /** 0x01 = OP_TRANSFER_POINTER, 0x02 = OP_REDEEM_CENTINEL. */
    uint8_t  tx_id[COIN_ID_LEN];       /** Transaction ID or ZK Nullifier confirming payment. */
    uint64_t price_rate_lock_id;       /** Echos challenge price_rate_lock_id (Big-Endian). */
} SclRpcPaymentReceipt;

/* ============================================================================ */
/* 5. PROTOCOL OPCODES, ENUMERATIONS & MESSAGE DISCRIMINATORS                  */
/* ============================================================================ */

/**
 * @enum MessageType
 * @brief Wire protocol message type opcodes transmitted across P2P connections.
 */
typedef enum {
    MSG_UPDATE_AUDIT = 1,                /** Audit state matrix update. */
    MSG_COIN_QUERY = 2,                  /** Request for active coin UTXO entries. */
    MSG_COIN_DATA = 3,                   /** Batched coin UTXO response data. */
    MSG_END_OF_DATA = 4,                 /** Terminal delimiter for multi-message query responses. */
    MSG_PTR_TRANSFER = 5,                /** On-chain subunit pointer transfer transaction. */
    MSG_POINTER_DATA = 6,                /** Batched pointer UTXO response data. */
    MSG_PENDING_OPERATION = 7,           /** Mempool unconfirmed operation gossip broadcast. */
    MSG_PEER_DISCOVERY = 8,              /** Authenticated cryptographic peer identity advertisement. */
    MSG_PEERS_LIST = 9,                  /** Responsive list of known active peer addresses. */
    MSG_GOSSIP_BLOCK = 10,               /** Newly proposed block broadcast for consensus voting. */
    MSG_BLOCK_APPROVED = 11,             /** Finalized block broadcast confirmed by supermajority. */
    MSG_GET_PUBKEY_BY_USERID = 12,       /** Query mapping a 32-byte User ID to full Dilithium5 public key. */
    MSG_PUBKEY_BY_USERID_RESPONSE = 13,  /** Response returning the 2,592-byte Dilithium5 public key. */
    MSG_VOTE = 14,                       /** Validator vote on a proposed block height and hash. */
    MSG_VALUATION_PROPOSAL = 15,         /** Client submission adding a row to the 10x10 Game Audit matrix. */
    MSG_PEER_LIST_SYNC = 16,             /** Periodic gossip synchronizing known peer routing tables. */
    MSG_PROPOSE_BLOCK = 17,              /** Delegation message instructing elected leader to propose block. */
    MSG_GET_AUDIT = 18,                  /** Request for the current 10x10 Game Audit matrix state. */
    MSG_BLOCK_NUMBER_QUERY = 19,         /** Liveness ping querying current committed block height. */
    MSG_BLOCK_NUMBER = 20,               /** Response reporting local node's current block height and tip hash. */
    MSG_GET_PENDING_OPERATIONS = 21,     /** Request querying the local mempool for unconfirmed operations. */
    MSG_PENDING_OPERATIONS_DATA = 22,    /** Batched mempool operation response payload. */
    MSG_PEER_DISCONNECT = 23,            /** Authenticated notification that a peer is terminating session. */
    MSG_THRESHOLD_SHARE_DISTRIBUTE = 24, /** Leader distributing Joint-RSS polynomial shares to signers. */
    MSG_THRESHOLD_PARTIAL_RESPONSE = 25, /** Signer returning partial signature vector z_i to leader. */
    MSG_THRESHOLD_SIGN_REQUEST = 26,     /** Leader broadcasting Fiat-Shamir challenge to threshold signers. */
    MSG_THRESHOLD_AGGREGATE_NOTIFY = 27, /** Broadcast announcing successful threshold signature aggregation. */
    MSG_STATELESS_RESET_TOKEN = 28,      /** Server sending stateless reset HMAC token to client post-handshake. */
    MSG_REDEEM_CENTINEL = 29,            /** Broadcast redeeming a private off-chain Centinel validation ticket. */
    MSG_CENTINEL_QUERY = 30,             /** Request synchronizing global Centinel commitments and nullifiers. */
    MSG_CENTINEL_COMMITMENTS = 31,       /** Response delivering validation commitment MMR leaf hashes. */
    MSG_CENTINEL_NULLIFIERS = 32,        /** Response delivering set of spent ZK-PRF nullifiers. */
    MSG_EPOCH_DKG_SHARE = 33,            /** Proposer distributing DKG epoch master public key. */
    MSG_EPOCH_SIGN_REQUEST = 34,         /** Proposer requesting threshold beacon signature for block hash. */
    MSG_EPOCH_PARTIAL_W = 35,            /** Committee member returning partial commitment vector w_i. */
    MSG_EPOCH_CHALLENGE = 36,            /** Proposer distributing Fiat-Shamir challenge polynomial c. */
    MSG_EPOCH_PARTIAL_Z = 37,            /** Committee member returning partial signature response z_i. */
    MSG_DKG_COMMIT = 38,                 /** DKG Round 1: Broadcasting hash commitment of local seed contribution. */
    MSG_DKG_REVEAL = 39,                 /** DKG Round 2: Revealing local seed contribution. */
    MSG_DKG_SHARE_DEAL = 40,             /** DKG Round 3: Distributing encrypted Joint-RSS polynomial subsets. */
    MSG_DKG_PUBKEY_FRAG = 41,            /** DKG Round 3: Broadcasting public verification vector fragment t_i. */
    MSG_GET_BLOCKS = 42,                 /** Historical block synchronization query starting from specified height. */
    MSG_BLOCKS_DATA = 43,                /** Batched serialized historical blocks response payload. */
    MSG_ENDPOINT_DISCOVERY = 44,         /** STUN-like request probing external public socket endpoint. */
    MSG_ENDPOINT_DISCOVERY_ACK = 45,     /** STUN-like response reflecting observed sender IP and port. */
    MSG_RELAY_REQUEST = 46,              /** Request registering a blind relay route for symmetric NAT bypass. */
    MSG_RELAY_DATA = 47,                 /** Encapsulated UDP payload routed blindly by Connection ID. */
    MSG_RPC_REQUEST = 48,                /** Inbound client/explorer API command frame (see @ref SclRpcHeader). */
    MSG_RPC_RESPONSE = 49                /** Outbound client/explorer API response frame. */
} MessageType;

/**
 * @enum PeerAddStatus
 * @brief Result status returned when adding or updating a peer in the peer address table.
 */
typedef enum {
    PEER_ADD_ERROR = -1,                 /** Operation failed due to invalid arguments or table saturation. */
    PEER_ADD_UPDATED = 0,                /** Existing peer entry updated with new address or key. */
    PEER_ADD_NEW = 1,                    /** New peer successfully added to the address table. */
    PEER_ADD_ZEROED_UPDATED = 2          /** Reclaimed a pending placeholder entry that had a zeroed key. */
} PeerAddStatus;

/**
 * @enum OperationType
 * @brief Discriminator defining the operation payload contained in an on-chain @ref Operation.
 */
typedef enum {
    OP_SUBMIT_VALUATION,                 /** Valuation vector insertion into Game Audit matrix. */
    OP_MINT_COIN,                        /** Coinbase reward issuance creating a new @ref SCLCoin. */
    OP_TRANSFER_POINTER,                 /** Reassignment of an unspent subunit range to a new owner. */
    OP_STAKE,                            /** Locking an unspent subunit range under threshold committee custody. */
    OP_UNSTAKE,                          /** Unlocking a staked subunit range back to liquid status. */
    OP_REDEEM_CENTINEL,                  /** Private off-chain validation credit redemption via ZK-Stern proof. */
    OP_CLAIM_VALIDATION                  /** Initial validation claim registering a BDLOP commitment on-chain. */
} OperationType;

/**
 * @enum HashEntryType
 * @brief Memory ownership and data type descriptor for entries in the generic @ref HashTable.
 */
typedef enum {
    HASH_ENTRY_COIN,                     /** Value-copy storage of an @ref SCLCoin structure. */
    HASH_ENTRY_POINTER,                  /** Value-copy storage of a @ref Pointer structure. */
    HASH_ENTRY_VOTE_QUEUE,               /** Owned pointer to a dynamically allocated @ref BlockVoteQueue. */
    HASH_ENTRY_USER,                     /** Borrowed reference pointer to a @ref User in state->users. */
    HASH_ENTRY_BLOCK_PROPOSER,           /** Owned pointer to an allocated @ref BlockProposerInfo structure. */
    HASH_ENTRY_TX,                       /** Key-only presence marker (no associated data payload). */
    HASH_ENTRY_OPERATION,                /** Value-copy storage of an @ref Operation structure. */
    HASH_ENTRY_VOTED_HEIGHT,             /** Value-copy storage of height/timestamp vote tracking record. */
    HASH_ENTRY_THRESHOLD_STAKE_PROCESS,  /** Owned pointer to a @ref ThresholdStakeProcess structure. */
    HASH_ENTRY_PUBKEY_CACHE,             /** Value-copy storage of a @ref PubkeyCacheEntry structure. */
    HASH_ENTRY_NULLIFIER,                /** Key-only presence marker for spent ZK-PRF nullifiers. */
    HASH_ENTRY_EPOCH_SIGN_DATA,          /** Owned pointer to a @ref ThresholdSignData structure. */
    HASH_ENTRY_DKG_SESSION,              /** Owned pointer to an active @ref DKGSession structure. */
    HASH_ENTRY_ORPHAN_BLOCK              /** Owned pointer to an isolated @ref Block in the orphan pool. */
} HashEntryType;

/**
 * @struct PubkeyCacheEntry
 * @brief Cached public key record mapping a 32-byte User ID to full 2,592-byte Dilithium5 public key.
 */
typedef struct {
    uint8_t pubkey[PUBKEY_LEN];          /** 2,592-byte ML-DSA-87 public key. */
} PubkeyCacheEntry;

/* ============================================================================ */
/* 6. POST-QUANTUM WALLET & BEARER TOKEN DATA STRUCTURES                        */
/* ============================================================================ */

/**
 * @struct PeerWallet
 * @brief Cryptographic key material held by a peer node for transport security and consensus.
 */
typedef struct {
    uint8_t dilithium_pubkey[DILITHIUM_PUBKEY_LEN];     /** 2,592-byte Dilithium5 public verification key. */
    uint8_t dilithium_privkey[DILITHIUM_SECRETKEY_LEN]; /** 4,864-byte Dilithium5 private signing key (page-locked). */
    uint8_t kyber_pubkey[KYBER_PUBKEY_LEN];             /** 800-byte Kyber-512 public encapsulation key. */
    uint8_t kyber_privkey[KYBER_SECRETKEY_LEN];         /** 1,632-byte Kyber-512 private decapsulation key (page-locked). */
} PeerWallet;

/**
 * @struct PRFKey
 * @brief Sparse ternary secret key vector for the Module-SIS Pseudo-Random Function.
 *
 * @details
 * Vector of 1,024 coefficients in {-1, 0, 1} with fixed Hamming weight 250, partitioned across
 * K=4 polynomials of degree N=256. Memory is page-locked and securely zeroized upon release.
 */
typedef struct {
    int8_t k[PRF_M];                     /** 1,024 ternary coefficients in {-1, 0, 1}. */
} PRFKey;

/**
 * @struct BdlopCommitment
 * @brief Homomorphic lattice commitment over R_q = Z_q[X]/(X^256 + 1).
 *
 * @details
 * Evaluates `c1 = a*s + e1` and `c2 = b*s + e2 + v(X)`, where `a, b` are public parameters
 * expanded from @ref BDLOP_RHO_SEED, `s, e1, e2` are small noise polynomials sampled from [-ETA, ETA],
 * and `v(X)` encodes the monetary value decomposed across 21-bit limbs.
 */
typedef struct {
    uint8_t c1[BDLOP_COEFF_BYTES];       /** 1,024-byte serialized polynomial vector component c1 (256 * int32). */
    uint8_t c2[BDLOP_COEFF_BYTES];       /** 1,024-byte serialized polynomial vector component c2 (256 * int32). */
} BdlopCommitment;

/**
 * @struct ValidationUTXO
 * @brief Shielded private validation balance token held in the local user wallet.
 */
typedef struct {
    BdlopCommitment commitment;          /** Homomorphic BDLOP lattice commitment concealing balance. */
    uint64_t amount;                     /** Decrypted integer value in validation units. */
    uint8_t blinding_factor[32];         /** 32-byte randomness seed r generating noise polynomials s, e1, e2. */
    uint8_t pubkey[PUBKEY_LEN];          /** 2,592-byte Dilithium5 public key of the owner. */
    PRFKey prf_key;                      /** Module-SIS PRF secret key derived from blinding factor. */
    uint8_t nullifier[NULLIFIER_LEN];    /** 32-byte spent nullifier `N = PRF_k(Hash(commitment))`. */
} ValidationUTXO;

/**
 * @struct UserWallet
 * @brief Master client wallet state holding cryptographic identities and private UTXO balances.
 */
typedef struct {
    uint8_t dilithium_pubkey[DILITHIUM_PUBKEY_LEN];     /** 2,592-byte Dilithium5 master public key. */
    uint8_t dilithium_privkey[DILITHIUM_SECRETKEY_LEN]; /** 4,864-byte Dilithium5 master private key (page-locked). */
    PRFKey prf_key;                                     /** Master Module-SIS PRF key for transaction matching. */
    ValidationUTXO *val_utxos;                          /** Dynamically resized array of unspent private validation UTXOs. */
    size_t num_val_utxos;                               /** Active logical count of unspent validation UTXOs. */
    size_t cap_val_utxos;                               /** Allocated capacity of val_utxos array. */
    pthread_mutex_t utxo_mutex;                         /** Mutex serializing updates to the private UTXO array. */
} UserWallet;

/**
 * @struct Peer
 * @brief Encapsulation of a known remote peer node in the P2P network.
 */
typedef struct {
    PeerWallet peer_wallet;              /** Remote peer's public key material (private fields zeroed). */
    struct sockaddr_storage addr;        /** Remote socket address (IPv4 or IPv6). */
    time_t last_seen;                    /** Timestamp in seconds of most recent observed activity. */
    SclConnection *conn;                 /** Pointer to active SclConnection transport context, or NULL. */
} Peer;

/**
 * @struct Valuation
 * @brief Single participant row submission in the 10x10 Game Audit circular matrix.
 */
typedef struct {
    uint8_t user_id[USER_ID_LEN];        /** 32-byte SHA-256 hash of the submitting user's public key. */
    int numbers[NUMBERS_PER_VALUATION];  /** Array of 10 integers in range [0, 99]. */
    uint64_t timestamp;                  /** Microsecond monotonic submission timestamp. */
    uint8_t beacon_seed[32];             /** 32-byte randomness beacon seed inherited from the block signature. */
} Valuation;

/**
 * @struct SCLCoin
 * @brief Primary cryptocurrency coin structure representing a root issuance asset.
 *
 * @details
 * A coin is minted as a block reward and possesses an immutable total supply of subunits.
 * Portions of the coin's subunits are partitioned into spendable @ref Pointer structures.
 */
typedef struct {
    uint8_t coin_id[COIN_ID_LEN];            /** 32-byte unique identifier derived from creation_tx_hash and owner. */
    uint8_t owner_address[USER_ID_LEN];      /** 32-byte User ID of the initial coin recipient. */
    uint8_t creation_tx_hash[COIN_ID_LEN];   /** Hash of the minting transaction or recycled fee batch. */
    uint64_t total_subunits;                 /** Total immutable subunit capacity issued (subunits = coins * 160M). */
    uint64_t remaining_subunits;             /** Current active unspent subunit balance remaining in parent coin. */
    Valuation audit_snapshot[AUDIT_SIZE];    /** Frozen copy of the 10x10 Game Audit matrix when reward was calculated. */
    uint32_t snapshot_count;                 /** Active row count in audit_snapshot at mint time. */
    uint32_t snapshot_audit_index;           /** Circular buffer write cursor at mint time. */
    uint8_t audit_state_anchor[COIN_ID_LEN]; /** Canonical SHA-256 digest of SCLCoin fields locking state history. */
} SCLCoin;

/**
 * @struct Pointer
 * @brief Discrete spendable sub-range of subunits within an existing @ref SCLCoin.
 *
 * @details
 * Partitions parent coin assets without splitting root records. Subunits are represented
 * by the inclusive range `[start_subunit, end_subunit]`. Total value equals `end_subunit - start_subunit + 1`.
 */
typedef struct {
    uint8_t pointer_id[COIN_ID_LEN];     /** 32-byte SHA-256 digest over pointer fields. */
    uint8_t parent_coin_id[COIN_ID_LEN]; /** Reference identifier of the parent @ref SCLCoin. */
    uint64_t start_subunit;              /** Inclusive start index of the subunit slice. */
    uint64_t end_subunit;                /** Inclusive end index of the subunit slice. */
    uint8_t owner_address[USER_ID_LEN];  /** 32-byte User ID of current pointer owner. */
    uint8_t prev_tx_hash[COIN_ID_LEN];   /** Transaction hash creating this pointer output. */
    int spent;                           /** Spending status: 0=Unspent, 1=Spent, 2=Fee pool recycled. */
    int staked;                          /** Staking status: 0=Liquid, 1=Locked under threshold stake. */
} Pointer;

/**
 * @struct MintData
 * @brief Payload for coinbase issuance operations (@ref OP_MINT_COIN).
 */
typedef struct {
    SCLCoin coin;                        /** Newly initialized coin structure. */
    uint8_t owner_pubkey[PUBKEY_LEN];    /** Proposer's public key validating ownership during mempool intake. */
} MintData;

/**
 * @struct Vote
 * @brief Cryptographic vote cast by a committee validator evaluating a proposed block.
 */
typedef struct {
    uint8_t voter_pubkey[PUBKEY_LEN];   /** 2,592-byte Dilithium5 public verification key of voter. */
    uint8_t block_hash[COIN_ID_LEN];    /** 32-byte SHA-256 block digest being approved or rejected. */
    uint8_t vote;                       /** Vote discriminator: 1=Approve, 0=Reject. */
    uint8_t signature[SIGNATURE_LEN];   /** 4,595-byte Dilithium5 signature over `block_hash || vote`. */
} Vote;

/**
 * @struct ValuationData
 * @brief Wire container transmitting a user valuation proposal (@ref OP_SUBMIT_VALUATION).
 */
typedef struct {
    Valuation valuation;                  /** Core valuation vector data and microsecond timestamp. */
    uint8_t pubkey[PUBKEY_LEN];           /** Submitting user's 2,592-byte Dilithium5 public verification key. */
    uint8_t signature[SIGNATURE_LEN];     /** 4,595-byte Dilithium5 signature over core valuation data. */
    uint8_t threshold_pubkey[PUBKEY_LEN]; /** Active epoch DKG committee public verification key. */
} ValuationData;

/* ============================================================================ */
/* 7. POLYNOMIAL RING R_q & LATTICE ARITHMETIC TYPES                            */
/* ============================================================================ */

/** @brief Signed 32-bit integer coefficient within quotient ring R_q = Z_q[X]/(X^256 + 1). */
typedef int32_t poly_coeff_t;

/**
 * @struct poly_t
 * @brief Single ring element polynomial of degree N=256 with coefficients modulo Q = 8,380,417.
 */
typedef struct {
    int32_t coeffs[RING_DEG];  /** Array of 256 signed 32-bit coefficients centered in [-(Q-1)/2, (Q-1)/2]. */
} poly_t;

/**
 * @struct polyvec_t
 * @brief Vector of polynomials in R_q^K or R_q^L.
 */
typedef struct {
    poly_t *vec;       /** Dynamic heap or arena-allocated array of polynomials. */
    size_t len;        /** Dimensional length of vector (typically K=8 or L=7). */
    uint32_t magic;    /** Corruption sentinel: must evaluate strictly to 0xDEADBEEF. */
} polyvec_t;

/**
 * @struct poly64_t
 * @brief Single ring element polynomial storing 64-bit unreduced coefficients during matrix multiplication.
 */
typedef struct {
    int64_t coeffs[RING_DEG]; /** Array of 256 signed 64-bit unreduced intermediate convolution products. */
} poly64_t;

/**
 * @struct polyvec64_t
 * @brief Vector of unreduced 64-bit polynomials utilized in high-precision lattice calculations.
 */
typedef struct {
    poly64_t *vec;     /** Pointer to array of poly64_t elements. */
    size_t len;        /** Vector dimension. */
} polyvec64_t;

/**
 * @struct matrix_t
 * @brief Matrix of polynomials representing public operator A_bar in R_q^(K x L).
 */
typedef struct {
    polyvec_t rows;    /** Flattened array of K*L polynomials expanded from seed rho. */
} matrix_t;

/**
 * @enum crypto_error_t
 * @brief Status and failure codes emitted across cryptographic algorithms and proofs.
 */
typedef enum {
    CRYPTO_SUCCESS = 0,                  /** Operation completed successfully. */
    CRYPTO_ERROR_INVALID_PARAM = -1,     /** Invalid parameter provided. */
    CRYPTO_ERROR_MEMORY = -2,            /** Memory allocation failure. */
    CRYPTO_ERROR_RANDOM = -3,            /** Random number generation error. */
    CRYPTO_ERROR_NETWORK = -4,           /** Network communication error. */
    CRYPTO_ERROR_REJECT = -5,            /** Operation rejected by peer. */
    CRYPTO_ERROR_INVALID_SIGNATURE = -6, /** Signature verification failed. */
    CRYPTO_ERROR_RETRIES_EXCEEDED = -7,  /** Maximum retry attempts exceeded. */
    CRYPTO_ERROR_SERIALIZE = -8,         /** Data serialization error. */
    CRYPTO_ERROR_PACKING = -9,           /** Data packing/unpacking error. */
    CRYPTO_ERROR_COMPUTE = -10,          /** Cryptographic computation error. */
    CRYPTO_ERROR_PROOF_INVALID = -11,    /** ZK proof verification failed. */
    CRYPTO_ERROR_PROOF_FORMAT = -12,     /** Malformed proof structure. */
    CRYPTO_ERROR_OVERFLOW = -13          /** Arithmetic overflow. */
} crypto_error_t;

/* ============================================================================ */
/* 8. THRESHOLD CEREMONY & DISTRIBUTED KEY GENERATION (DKG) TYPES               */
/* ============================================================================ */

/**
 * @struct ThresholdKeygenData
 * @brief Master cryptographic state for Joint-RSS threshold key generation (n=10, t=2).
 */
typedef struct {
    matrix_t A_bar;                      /** Expanded matrix A. */
    polyvec_t s1, s2;                    /** Full secret vectors. */
    polyvec_t t0, t1, t;                 /** Public key components. */
    polyvec_t *s1_shares, *s2_shares;    /** Party secret shares. */
    polyvec_t *s1_sub_shares;            /** Subset secret shares s1. */
    polyvec_t *s2_sub_shares;            /** Subset secret shares s2. */
    polyvec_t inbound_s1_shares[10][10]; /** Tracking subset shares received from peers: [peer_id][subset_id]. */
    polyvec_t inbound_s2_shares[10][10]; /** Tracking s2 shares for localized mathematical VSS verification. */
    polyvec_t peer_t_contributions[10];  /** Inbound public commitments. */
    size_t num_subsets;                  /** Number of subsets C(n,t). */
    uint16_t *subset_indices;            /** Subset indices for party. */
    size_t num_party_subsets;            /** Subsets this party is in. */
    size_t n;                            /** Number of parties. */
    int32_t beta;                        /** Threshold-adjusted beta (TAU * ETA * NUM_SUBSETS). */
    uint8_t pubkey[PUBKEY_LEN];          /** Packed public key. */
    size_t pubkey_len;                   /** Public key length. */
} ThresholdKeygenData;

/**
 * @struct ThresholdSignData
 * @brief Ephemeral signing context for an individual party participating in threshold signing.
 */
typedef struct {
    uint8_t signature[SIGNATURE_LEN];    /** Partial/combined signature. */
    size_t sig_len;                      /** Actual length. */
    polyvec_t y;                         /** Random vector for signing. */
    polyvec_t w;                         /** w = A_bar * y. */
    matrix_t A_bar;                      /** Expanded matrix A. */
    size_t num_party_subsets;            /** Number of subsets for this party. */
    uint16_t *subset_indices;            /** Array of subset indices this party participates in. */
} ThresholdSignData;

/**
 * @struct ThresholdStakeProcess
 * @brief Coordinator tracking an active threshold staking or epoch beacon ceremony.
 */
typedef struct {
    uint8_t stake_tx_id[COIN_ID_LEN];           /** Unique ID for this stake operation. */
    ThresholdKeygenData keygen;                 /** Key generation data. */
    uint8_t peer_pubkeys[10][PUBKEY_LEN];       /** Pubkeys of the selected random peers. */
    struct sockaddr_storage peer_addrs[10];     /** Addresses of the selected peers. */
    polyvec_t partial_w[10];                    /** Partial w vectors from peers (stage 0). */
    uint8_t mu[32];                             /** Fiat-Shamir mu. */
    uint8_t rho_prime[32];                      /** Fiat-Shamir rho_prime. */
    polyvec_t w_agg;                            /** Aggregated w vector from stage 0. */
    ThresholdSignData dealer_sign_data;         /** Dealer's local sign data (y0, w0). */
    polyvec_t dealer_z;                         /** Dealer's local z0. */
    polyvec_t partial_z[10];                    /** Partial z vectors received from peers. */
    polyvec_t s1_part[10];                      /** For storing received s1 share. */
    polyvec_t s2_part[10];                      /** For storing received s2 share. */
    ThresholdSignData sign_data[10];            /** For storing signing data. */
    bool is_peer_active[10];                    /** Role tracker. */
    poly_t challenge;                           /** For storing the sampled challenge polynomial. */
    _Atomic(int) partials_received;             /** Count of received partial responses. */
    _Atomic(int) expected_partials;             /** Count of expected partial responses. */
    pthread_cond_t partial_cond;                /** Condition variable for waiting on partials (stage 1). */
    _Atomic(bool) stage0_complete;              /** Flag for stage 0 completion (w aggregation). */
    pthread_cond_t stage0_complete_cond;        /** Condition variable for stage 0 completion. */
    _Atomic(bool) aggregation_complete;         /** Flag indicating successful aggregation (stage 1). */
    _Atomic(bool) aggregation_failed;           /** Flag indicating aggregation cryptographically failed. */
    uint8_t final_signature[SIGNATURE_LEN];     /** Aggregated threshold signature. */
    size_t final_sig_len;                       /** Length of final signature. */
    pthread_t collector_thread;                 /** Thread for partial collection. */
    uint64_t created_at;                        /** Timestamp in ms when process was created/received. */
} ThresholdStakeProcess;

/**
 * @struct DKGSession
 * @brief State container for an interactive, decentralized Distributed Key Generation epoch session.
 */
typedef struct {
    uint8_t session_id[COIN_ID_LEN];            /** Deterministic epoch identifier (e.g., block hash). */
    _Atomic(int) ref_count;                     /** Reference count for safe memory reclamation. */
    uint64_t block_height;                     /** Epoch block height. */
    uint8_t committee_pubkeys[10][PUBKEY_LEN];  /** Committee Dilithium public keys. */
    size_t committee_count;                     /** Number of members (up to 10). */
    uint16_t local_point_id;                    /** This node's point ID in the committee (1-10, 0 if not in committee). */
    bool worker_spawned;                        /** Track if DKG worker thread has been spawned locally. */
    
    /* Phase 1: Commit Round */
    uint8_t local_seed[32];                     /** r_i generated by this node. */
    uint8_t commitments[10][32];                /** c_i = SHA256(r_i || pubkey_i). */
    bool has_commitment[10];                    /** Bitmap tracking received commitments. */
    int commitments_received;                   /** Total commitments received. */

    /* Phase 2: Reveal Round */
    uint8_t reveals[10][32];                    /** r_i revealed by peers. */
    bool has_reveal[10];                        /** Bitmap tracking received reveals. */
    int reveals_received;                       /** Total reveals received. */
    
    uint8_t global_rho[32];                     /** The trustless global seed rho. */
    
    /* Phase 3 & 4: Share Deal & Assembly */
    ThresholdKeygenData keygen;                 /** Local keygen structures. */
    bool has_shares[10];                        /** Bitmap tracking received shares. */
    int shares_received;                        /** Total shares received. */
    bool has_pubkey_frag[10];                   /** Bitmap tracking received public key fragments. */
    int pubkey_frags_received;                  /** Total public key fragments received. */

    pthread_cond_t phase_cond;                  /** Condition variable for phase barriers. */
    int status;                                 /** 0: Init, 1: Commit, 2: Reveal, 3: Shares, 4: PubkeyFrags, 5: Complete, -1: Failed. */
    Message *early_msgs[1000];                  /** Staged early messages received out of phase. */
    uint8_t early_senders[1000][PUBKEY_LEN];    /** Public keys of early senders. */
    void *early_conns[1000];                    /** Borrowed connection handles for early senders. */
    int early_msg_count;                        /** Count of staged early messages. */
} DKGSession;

/**
 * @struct ThresholdSharePayload
 * @brief Wire payload distributing encrypted Joint-RSS shares (@ref MSG_THRESHOLD_SHARE_DISTRIBUTE).
 */
typedef struct {
    uint16_t point_id;                          /** Recipient's point ID (0-2). */
    uint8_t s1_share[POLYVEC_L_SERIALIZED];     /** Serialized s1 share (polyvec_t with L polys) - 7168 bytes. */
    uint8_t s2_share[POLYVEC_K_SERIALIZED];     /** Serialized s2 share (polyvec_t with K polys) - 8192 bytes. */
} ThresholdSharePayload;

/**
 * @struct PartialSigPayload
 * @brief Wire payload returning partial response vector z_i (@ref MSG_THRESHOLD_PARTIAL_RESPONSE).
 */
typedef struct {
    uint8_t stake_tx_id[COIN_ID_LEN];           /** Reference to the stake process. */
    uint16_t point_id;                          /** Sender's point ID. */
    uint8_t partial_z[POLYVEC_L_SERIALIZED];    /** Serialized partial z (polyvec_t with L polys) - 7168 bytes. */
    uint8_t nonce[8];                           /** Anti-replay nonce. */
} PartialSigPayload;

/* ============================================================================ */
/* 9. MERKLE MOUNTAIN RANGE (MMR) TOPOGRAPHY & PROOFS                           */
/* ============================================================================ */

/**
 * @struct MMRNode
 * @brief Node representation within the append-only Merkle Mountain Range tree structure.
 */
typedef struct MMRNode {
    uint8_t hash[COIN_ID_LEN];        /** Node hash value. */
    size_t position;                  /** Index in nodes array. */
    int height;                       /** Tree level (0 = leaf). */
    ssize_t parent;                   /** Parent node index (-1 if none). */
    ssize_t left_child;               /** Left child index (-1 if none). */
    ssize_t right_child;              /** Right child index (-1 if none). */
} MMRNode;

/**
 * @struct MMR
 * @brief Merkle Mountain Range state accumulator managing dynamic leaf insertions and peaks.
 */
typedef struct MMR {
    MMRNode *nodes;                   /** Array of all MMR nodes. */
    size_t *peaks;                    /** Indices of peak nodes. */
    size_t count;                     /** Total node count. */
    size_t peak_count;                /** Number of peaks. */
    size_t capacity;                  /** Allocated capacity for nodes. */
    size_t peak_capacity;             /** Allocated capacity for peaks. */
    size_t uncommitted_start;         /** Index of the first uncommitted node for disk flushing. */
} MMR;

/**
 * @struct MMRProof
 * @brief Inclusion proof demonstrating membership of a leaf within an MMR root commitment.
 */
typedef struct {
    uint8_t path_hashes[MAX_PATH_LEN][COIN_ID_LEN]; /** Merkle path hashes. */
    int is_left[MAX_PATH_LEN];                      /** Sibling position flags. */
    size_t path_len;                                /** Length of Merkle path. */
    uint8_t left_peaks[MAX_PEAKS][COIN_ID_LEN];     /** Left peak hashes. */
    size_t left_peaks_len;                          /** Number of left peaks. */
    uint8_t right_peaks[MAX_PEAKS][COIN_ID_LEN];    /** Right peak hashes. */
    size_t right_peaks_len;                         /** Number of right peaks. */
} MMRProof;

/* ============================================================================ */
/* 10. ON-CHAIN TRANSACTION PAYLOADS & OPERATION MODELS                         */
/* ============================================================================ */

/**
 * @struct TransferData
 * @brief Transaction payload for on-chain subunit pointer transfers (@ref OP_TRANSFER_POINTER).
 */
typedef struct {
    uint8_t tx_id[COIN_ID_LEN];                          /** Transaction ID. */
    uint8_t nonce[8];                                    /** Anti-replay nonce. */
    uint32_t num_inputs;                                 /** Number of input pointers. */
    Pointer inputs[MAX_INPUTS];                          /** Input pointers array. */
    MMRProof proofs[MAX_INPUTS];                         /** Inclusion proofs for inputs. */
    uint8_t client_root[COIN_ID_LEN];                    /** Client's MMR root. */
    uint8_t recipient_pubkey[PUBKEY_LEN];                /** Recipient's public key. */
    uint8_t sender_pubkey[PUBKEY_LEN];                   /** Pubkey of the sender for mempool verification. */
    uint64_t amount;                                     /** Transfer amount in subunits. */
    uint8_t signature[SIGNATURE_LEN];                    /** Transaction signature. */
    uint8_t inputs_merkle_root[COIN_ID_LEN];             /** Merkle root of input pointer hashes. */
    uint8_t inputs_root_signature[SIGNATURE_LEN];        /** Signature of the Merkle root by the input owner. */
    uint8_t prf_output[NULLIFIER_LEN];                   /** Output of PRF evaluation y = PRF(k, J). */
    uint8_t zk_proof[ZK_PROOF_MAX_LEN];                  /** Zero-knowledge proof of PRF evaluation. */
    uint32_t zk_proof_len;                               /** Actual length of the ZK proof. */
} TransferData;

/**
 * @struct StakeData
 * @brief Transaction payload for locking subunits into staking status (@ref OP_STAKE).
 */
typedef struct {
    uint8_t stake_tx_id[COIN_ID_LEN];                    /** Stake transaction ID. */
    uint8_t nonce[8];                                    /** Anti-replay nonce. */
    uint32_t num_inputs;                                 /** Number of input pointers. */
    Pointer inputs[MAX_INPUTS];                          /** Input pointers array. */
    MMRProof proofs[MAX_INPUTS];                         /** Inclusion proofs for inputs. */
    uint8_t inputs_merkle_root[COIN_ID_LEN];             /** Merkle root of input pointer hashes. */
    uint8_t inputs_root_signature[SIGNATURE_LEN];        /** Signature of the Merkle root by the input owner. */
    uint8_t client_root[COIN_ID_LEN];                    /** Client's MMR root. */
    uint8_t threshold_pubkey[PUBKEY_LEN];                /** Public key for threshold signatures. */
    uint8_t sender_pubkey[PUBKEY_LEN];                   /** Sender's pubkey. */
    uint64_t amount;                                     /** Stake amount in subunits. */
    uint8_t threshold_signature[SIGNATURE_LEN];          /** Threshold signature. */
} StakeData;

/**
 * @struct UnstakeData
 * @brief Transaction payload unlocking staked subunits back to liquid status (@ref OP_UNSTAKE).
 */
typedef struct {
    uint8_t unstake_tx_id[COIN_ID_LEN];                  /** Unstake transaction ID. */
    uint8_t nonce[8];                                    /** Anti-replay nonce. */
    uint32_t num_inputs;                                 /** Number of input pointers. */
    Pointer inputs[MAX_INPUTS];                          /** Input pointers array. */
    MMRProof proofs[MAX_INPUTS];                         /** Inclusion proofs for inputs. */
    uint8_t inputs_merkle_root[COIN_ID_LEN];             /** Merkle root of input pointer hashes. */
    uint8_t inputs_root_signature[SIGNATURE_LEN];        /** Signature of the Merkle root. */
    uint8_t pointer_signatures[MAX_INPUTS][SIGNATURE_LEN];/** Input threshold signatures. */
    uint8_t client_root[COIN_ID_LEN];                    /** Client's MMR root. */
    uint8_t threshold_pubkey[PUBKEY_LEN];                /** Threshold public key used for staking. */
    uint8_t recipient_pubkey[PUBKEY_LEN];                /** Recipient's public key. */
    uint64_t amount;                                     /** Unstake amount in subunits. */
    uint8_t threshold_signature[SIGNATURE_LEN];          /** Threshold signature for the transaction. */
} UnstakeData;

/**
 * @struct BlockVoteQueue
 * @brief Thread-safe queue accumulating validator votes for a candidate block proposal.
 */
typedef struct BlockVoteQueue {
    Vote *votes;                        /** Array of vote objects. */
    size_t count;                       /** Current votes in queue. */
    size_t head;                        /** Queue head index. */
    size_t size;                        /** Maximum queue capacity. */
    size_t yes_votes;                   /** Positive votes count. */
    uint64_t block_height;              /** Block height being voted on. */
    pthread_mutex_t vote_lock;          /** Synchronization mutex. */
    pthread_cond_t cond;                /** Condition variable for waiting. */
    struct BlockVoteQueue *next;        /** Next queue in linked list. */
    int ref_count;                      /** Reference count for active users. */
    int removed;                        /** Flag indicating if queue has been removed. */
} BlockVoteQueue;

/**
 * @struct BlockProposerInfo
 * @brief Record indexing the leader who proposed a candidate block.
 */
typedef struct {
    uint8_t block_hash[COIN_ID_LEN];          /** Block hash. */
    uint8_t proposer_peer_pubkey[PUBKEY_LEN]; /** Proposer's public key. */
} BlockProposerInfo;

/* ============================================================================ */
/* 11. HASH TABLE, INDEXING & STORAGE MODELS                                    */
/* ============================================================================ */

/**
 * @struct HashTable
 * @brief Lock-free concurrent hash table implementing incremental resizing and separate chaining.
 */
typedef struct HashTable {
    struct GenericHashEntry **buckets;     /** Array of hash buckets. */
    struct GenericHashEntry **old_buckets; /** Incremental resizing target. */
    size_t size;                           /** Total bucket count. */
    size_t old_size;                       /** Old bucket count during resize. */
    size_t resize_progress;                /** Current migration index. */
    size_t count;                          /** Current entry count. */
    size_t key_len;                        /** Length of keys. */
    uint32_t (*hash_fn)(const uint8_t *, size_t); /** Hash function. */
    int (*compare_fn)(const void *, const void *, size_t); /** Comparison function. */
    void (*free_entry_fn)(void *);         /** Free function for entries. */
    void (*custom_insert_fn)(struct HashTable *, struct GenericHashEntry *, const uint8_t *, void *, HashEntryType); /** Custom insert function. */
    pthread_rwlock_t rwlock;               /** Protects table during resizing. */
} HashTable;

/**
 * @struct ClaimValidationData
 * @brief Transaction payload registering an off-chain BDLOP validation claim (@ref OP_CLAIM_VALIDATION).
 */
typedef struct {
    BdlopCommitment commitment;       /** The new Validation UTXO commitment. */
    uint8_t pubkey[PUBKEY_LEN];       /** Claiming user's public key. */
    uint8_t signature[SIGNATURE_LEN]; /** Signature of the commitment. */
} ClaimValidationData;

/**
 * @struct RedeemCentinelData
 * @brief Wire payload redeeming an off-chain Centinel bearer instrument (@ref OP_REDEEM_CENTINEL).
 */
typedef struct {
    uint8_t nullifier[NULLIFIER_LEN];    /** N_old = PRF_k(C_old). */
    BdlopCommitment c_transfer;          /** Encrypted destination validation. */
    BdlopCommitment c_change;            /** Encrypted change. */
    uint32_t zk_proof_len;               /** Actual length of the proof. */
    uint8_t zk_proof[ZK_PROOF_MAX_LEN];  /** The SNARK/Stern proof of the circuit. */
} RedeemCentinelData;

/**
 * @struct CentinelTicket
 * @brief Private off-chain bearer instrument encrypting transferable validation credits.
 */
typedef struct {
    BdlopCommitment c_transfer;          /** Encrypted destination validation. */
    BdlopCommitment c_change;            /** Encrypted change. */
    uint8_t nullifier[NULLIFIER_LEN];    /** N_old. */
    uint8_t *zk_proof;                   /** The SNARK/Stern proof of the circuit. */
    uint32_t zk_proof_len;               /** Actual length of the proof. */
    uint64_t amount;                     /** X (Transfer value). */
    uint8_t r_transfer[32];              /** Blinding factor for C_transfer. */
    uint8_t ephemeral_pubkey[PUBKEY_LEN];/** Ephemeral public key ensuring the ticket remains an independent Bearer Instrument. */
    PRFKey ephemeral_prf_key;            /** Ephemeral PRF key. */
} CentinelTicket;

/**
 * @struct Centinel
 * @brief Multi-ticket container grouping Centinel bearer instruments into an export structure.
 */
typedef struct {
    uint32_t num_tickets;                /** Number of active tickets. */
    CentinelTicket tickets[];            /** Flexible array member storing packed Centinel tickets. */
} Centinel;

/**
 * @struct CentinelState
 * @brief Global blockchain ledger state managing private UTXO validation commitments and nullifiers.
 */
typedef struct {
    HashTable *nullifier_set;            /** Tracks ZK-PRF outputs to prevent double spends. */
    MMR *validation_commitments;         /** Merkle tree of all encrypted validation balances. */
    uint8_t pruned_nullifiers_root[COIN_ID_LEN]; /** Accumulated root of evicted nullifiers. */
    uint8_t *nullifier_bloom;            /** Dedicated Bloom filter to avoid disk I/O during nullifier verification. */
    pthread_mutex_t bloom_mutex;         /** Mutex to protect concurrent writes to the bloom filter. */
} CentinelState;

/**
 * @struct Operation
 * @brief Unified container encapsulating any on-chain transactional operation.
 */
typedef struct {
    OperationType type;                       /** Operation type identifier. */
    bool is_rpc_injected;                     /** Flag for RPC telemetry tracking. */
    union {
        ValuationData submit_valuation;       /** Valuation operation data. */
        MintData mint_coin;                   /** Coin minting data. */
        TransferData transfer_pointer;        /** Transfer operation data. */
        StakeData stake;                      /** Stake operation data. */
        UnstakeData unstake;                  /** Unstake operation data. */
        RedeemCentinelData redeem_centinel;   /** Centinel redemption payload. */
        ClaimValidationData claim_validation; /** Global Sync Payload. */
    } data;
} Operation;

/**
 * @struct Block
 * @brief Candidate or finalized block in the Satocialist blockchain.
 *
 * @details
 * Encapsulates a chronologically ordered array of operations, an aggregated batch ZK-PRF proof
 * proving validity of all enclosed transfer nullifiers, and a threshold randomness beacon signature.
 */
typedef struct {
    uint64_t block_number;           /** Sequential block number. */
    uint8_t prev_block_hash[COIN_ID_LEN]; /** Previous block hash. */
    Operation *operations;           /** Array of operations. */
    size_t operation_count;          /** Number of operations. */
    uint8_t proposer_pubkey[PUBKEY_LEN]; /** Block proposer's public key. */
    uint8_t signature[SIGNATURE_LEN]; /** Block signature. */
    uint64_t entropy_seed;           /** Entropy seed for proposal. */
    size_t batch_tx_count;           /** Number of transfer operations in this block. */
    uint8_t *batch_prf_outputs;      /** Concatenated PRF outputs for all transfers. */
    uint8_t *batch_zk_proof;         /** A single, aggregated ZK proof for all transfers. */
    size_t batch_zk_proof_len;       /** The length of the aggregated proof. */
    uint8_t epoch_threshold_signature[SIGNATURE_LEN]; /** Daily DKG signature serving as Randomness Beacon. */
} Block;

/**
 * @struct Blockchain
 * @brief Ledger state container managing the state MMR, UTXO tables, and database interfaces.
 */
typedef struct Blockchain {
    MMR *mmr;                           /** Merkle Mountain Range structure. */
    HashTable *coin_table;              /** Primary coin storage. */
    HashTable *pointer_table;           /** Pointer storage. */
    HashTable *coin_pointers;           /** Coin-to-pointer mappings. */
    SCLCoin **insert_order;             /** Coin insertion order array. */
    size_t insert_order_count;          /** Current coins in insert_order. */
    size_t insert_order_capacity;       /** Capacity of insert_order array. */
    pthread_rwlock_t rwlock;            /** Read-Write lock for parallel validation. */
    uint64_t sync_epoch;                /** Synchronization epoch counter. */
    CentinelState centinel;             /** ZK-PRF Centinel State. */
    bool mmr_needs_rebuild;             /** Flag to avoid redundant rebuilds. */
} Blockchain;

/**
 * @struct User
 * @brief Identity account record tracking validation grant timing and credentials.
 */
typedef struct User {
    uint8_t user_id[USER_ID_LEN];           /** Unique user identifier. */
    time_t last_validation;                 /** Timestamp of last free validation. */
    uint8_t dilithium_pubkey[PUBKEY_LEN];   /** Dilithium public key. */
    pthread_mutex_t mutex;                  /** User state mutex. */
} User;

/**
 * @struct GenericHashEntry
 * @brief Unified collision-chain bucket entry for the generic @ref HashTable.
 */
typedef struct GenericHashEntry {
    uint8_t key[COIN_ID_LEN];               /** Lookup key (hash). */
    HashEntryType type;                     /** Data type identifier. */
    union {
        SCLCoin coin;                       /** Coin data. */
        Pointer pointer;                    /** Pointer data. */
        BlockVoteQueue *queue;              /** Vote queue. */
        User *user;                         /** User reference. */
        BlockProposerInfo *proposer;        /** Block proposer info. */
        Operation *operation;               /** Operation data pointer. */
        struct {
            uint64_t height;
            time_t timestamp;
        } voted_height_rec;                 /** TTL Vote tracking record. */
        ThresholdStakeProcess *threshold_stake_process; /** Stake data. */
        PubkeyCacheEntry pubkey_cache;      /** Cached public key entry. */
        ThresholdSignData *epoch_sign_data; /** Epoch sign data. */
        void *dkg_session;                  /** DKG Session pointer. */
        Block *orphan_block;                /** Orphan Block pointer. */
    } data;
    struct GenericHashEntry *next;          /** Next entry in collision chain. */
} GenericHashEntry;

/**
 * @enum NATType
 * @brief Classification of local router NAT traversal behavior determined via STUN probes.
 */
typedef enum {
    NAT_TYPE_UNKNOWN = 0,                   /** NAT behavior undetermined. */
    NAT_TYPE_OPEN = 1,                      /** Direct public IP or Full Cone NAT. */
    NAT_TYPE_ASYMMETRIC = 2,                /** Restricted cone NAT. */
    NAT_TYPE_SYMMETRIC = 3                  /** Symmetric NAT / CGNAT. */
} NATType;

/**
 * @struct P2PNetwork
 * @brief Network subsystem managing known peers, address discovery, and NAT traversal.
 *
 * Note on self_addrs: these are external IPs proven to belong to this process
 * (Docker has no GCP address on an interface, and bind_ip=:: never compares
 * equal to it). The port is ignored. This array is appended at the end so a
 * zeroed State remains valid.
 */
typedef struct {
    Peer local_peer;                     /** This node's peer information. */
    Peer **known_peers;                  /** Dynamic array of known peers. */
    size_t num_known_peers;              /** Current count of known peers. */
    pthread_mutex_t mutex;               /** Synchronization for thread-safe access. */
    int is_bootstrap;                    /** Whether this is a bootstrap node. */
    struct sockaddr_storage public_addr; /** Global STUN endpoint coordinates. */
    NATType nat_type;                    /** Symmetric vs asymmetric state classifier. */
    struct sockaddr_storage self_addrs[8]; /** External IPs proven to be this process. */
    size_t num_self_addrs;               /** Number of entries in self_addrs. */
} P2PNetwork;

/**
 * @struct GameStateSnapshot
 * @brief Immutable, reference-counted snapshot of the 10x10 Game Audit state for lock-free evaluations.
 */
typedef struct {
    uint64_t version;                       /** Monotonically increasing version ID. */
    uint64_t total_rewarded_scl_subunits;   /** Frozen reward total for deterministic calculation. */
    uint64_t remaining_scl_subunits;        /** Frozen remaining supply. */
    Valuation game_audit[AUDIT_SIZE];       /** Immutable copy of the valuation matrix. */
    uint32_t current_audit_index;           /** Frozen active index. */
    uint32_t valuation_count;               /** Frozen count of active valuations. */
    uint64_t audit_timestamp;               /** Timestamp of last update. */
    uint8_t epoch_threshold_pubkey[PUBKEY_LEN]; /** Active DKG committee public key. */
    uint64_t last_dkg_epoch;                /** Block height of last generation. */
    uint8_t current_epoch_signature[SIGNATURE_LEN]; /** Phase 3 signature. */
    _Atomic(uint32_t) ref_count;            /** Reference count for safe deferred reclamation. */
} GameStateSnapshot;

/**
 * @struct GameState
 * @brief Dynamic game economics and 10x10 valuation matrix state container.
 */
typedef struct {
    Valuation game_audit[AUDIT_SIZE];           /** Circular buffer of valuations. */
    int current_audit_index;                    /** Current write position. */
    int valuation_count;                        /** Number of valuations in buffer. */
    int cached_stage;                           /** Current economic stage. */
    uint64_t total_rewarded_scl_subunits;       /** Lifetime rewards issued. */
    uint64_t remaining_scl_subunits;            /** Remaining reward pool. */
    pthread_mutex_t mutex;                      /** State modification mutex. */
    uint64_t audit_timestamp;                   /** Last audit update time. */
    uint8_t epoch_threshold_pubkey[PUBKEY_LEN]; /** Active DKG committee public key. */
    uint64_t last_dkg_epoch;                    /** Block height of last generation. */
    uint8_t current_epoch_signature[SIGNATURE_LEN]; /** Track latest signature for entropy. */
} GameState;

/** @brief Task element wrapper for work-stealing queues. */
typedef struct RecreateNode {
    void *args;                                 /** Generic task argument pointer. */
    struct RecreateNode *next;                  /** Singly-linked list pointer. */
} RecreateNode;

/**
 * @struct WorkStealingQueue
 * @brief Thread-safe task queue supporting local FIFO popping and peer work-stealing.
 */
typedef struct {
    RecreateNode *head;                         /** Head of the task queue. */
    RecreateNode *tail;                         /** Tail of the task queue. */
    pthread_mutex_t mutex;                      /** Queue synchronization mutex. */
} WorkStealingQueue;

/**
 * @struct SclRpcEngine
 * @brief Multi-threaded execution engine processing inbound L5 RPC commands.
 */
typedef struct {
    WorkStealingQueue incoming_rpc_queue;        /** Interleaved L5 handoff queue. */
    pthread_t         worker_threads[MAX_RPC_WORKERS]; /** Dedicated worker threads. */
    _Atomic(uint32_t)  active_global_queries;    /** In-flight query counter. */
    _Atomic(uint64_t)  requests_total;           /** Cumulative requests received. */
    _Atomic(uint64_t)  rejected_rate_limit;      /** Rate-limited rejections. */
    _Atomic(uint64_t)  rejected_auth_fail;       /** Authentication failures. */
    _Atomic(uint64_t)  rejected_checksum_mismatch;/** Checksum validation errors. */
    _Atomic(uint64_t)  latency_microseconds_sum; /** Cumulative request latency in microseconds. */
    _Atomic(uint64_t)  method_requests_ok[12];   /** Per-method success counters. */
    _Atomic(uint64_t)  method_requests_err[12];  /** Per-method error counters. */
    _Atomic(uint64_t)  method_latency[12];       /** Per-method cumulative latency. */
} SclRpcEngine;

/**
 * @enum EdgeType
 * @brief Behavioral classification for hypergraph reputation edges.
 */
typedef enum {
    EDGE_INTERACTION = 0, /** Successful handshakes, data transfer. */
    EDGE_SYMMETRY    = 1  /** Balanced mutual participation. */
} EdgeType;

/**
 * @struct HyperEdge
 * @brief Directed hyperedge tracking peer participation weight over time.
 */
typedef struct {
    uint8_t cid[SCL_CID_LEN];                   /** Connection ID identifying target peer. */
    uint32_t weight;                            /** Temporal participation score. */
    uint64_t timestamp;                         /** Millisecond timestamp of last interaction. */
    EdgeType edge_type;                         /** Edge behavior category. */
} HyperEdge;

/**
 * @struct NodeMetadata
 * @brief Vertex metadata tracking peer reputation score within local hypergraph.
 */
typedef struct {
    uint8_t cid[SCL_CID_LEN];                   /** Peer Connection ID. */
    uint64_t last_seen_epoch;                   /** Millisecond timestamp of last activity. */
    uint32_t reputation_score;                  /** Derived from edge weights. */
} NodeMetadata;

/**
 * @struct LocalHypergraph
 * @brief Graph topology tracking local network interactions for anti-DoS proof-of-work difficulty scaling.
 */
typedef struct {
    uint64_t epoch_seed;                        /** Current epoch beacon hash. */
    NodeMetadata nodes[MAX_HYPERGRAPH_NODES];   /** Node vertex metadata array. */
    uint16_t node_count;                        /** Active node count. */
    HyperEdge edges[MAX_HYPERGRAPH_EDGES];      /** Temporal edge array. */
    uint16_t edge_count;                        /** Active edge count. */
    pthread_mutex_t lock;                       /** Thread-safe access for L5 Workers. */
    uint8_t cached_puzzle_base[32];             /** Pre-computed Proof-of-Work puzzle seed. */
    uint64_t last_puzzle_rotation_ms;           /** Last rotation timestamp in milliseconds. */
    pthread_mutex_t puzzle_cache_lock;          /** Mutex protecting cached puzzle updates. */
    uint8_t poison_bloom_active[BLOOM_FILTER_SIZE]; /** Primary Bloom filter tracking banned CIDs. */
    uint8_t poison_bloom_aging[BLOOM_FILTER_SIZE];  /** Aging Bloom filter for smooth rotation. */
    uint64_t last_bloom_rotation_epoch;         /** Epoch index of last Bloom filter rotation. */
} LocalHypergraph;

/**
 * @struct HybridCookieChallenge
 * @brief Proof-of-work puzzle envelope issued in Long Header RETRY packets.
 */
typedef struct {
    uint8_t primary_cookie_base[32];            /** Primary stateless cookie seed. */
    uint8_t hypergraph_puzzle_base[32];         /** SHA-256(local_subgraph || epoch_seed). */
    uint8_t primary_difficulty;                 /** Fixed at 10 bits. */
    uint8_t secondary_difficulty;               /** Dynamic: 0 (disabled), 12 to 20 bits. */
    uint64_t challenge_expiry;                  /** Millisecond timestamp when challenge expires. */
    uint8_t cid[SCL_CID_LEN];                   /** Connection ID bound to this challenge. */
} HybridCookieChallenge;

/**
 * @struct State
 * @brief Master application state container encapsulating all ledger, consensus, transport, and wallet subsystems.
 *
 * @details
 * Modularized physically via C11 anonymous structures to group functionally related fields,
 * optimizing CPU L1/L2 cache locality and guaranteeing deterministic memory boundaries.
 */
typedef struct State {
    DaemonConfig config; /** Active node configuration parameters. */

    /* --- 1. Core Blockchain & Economics (The Ledger) --- */
    struct {
        Blockchain bc;                                 /** Core blockchain and state MMR accumulator. */
        GameState game_state;                          /** Game economics and 10x10 valuation matrix state. */
        _Atomic(uintptr_t) active_snapshot_ptr;        /** Atomic pointer to latest @ref GameStateSnapshot. */
        pthread_mutex_t snapshot_update_mutex;         /** Mutex serializing snapshot publishing. */
        HashTable *processed_blocks;                  /** Set of 32-byte block hashes confirmed on-chain. */
        HashTable *processed_txs;                     /** Set of 32-byte transaction IDs confirmed on-chain. */
        uint64_t current_block_number;                 /** Current committed block height. */
        uint8_t current_block_hash[COIN_ID_LEN];       /** 32-byte SHA-256 digest of current tip block. */
        pthread_mutex_t processed_blocks_mutex;        /** Mutex protecting processed_blocks lookups. */
        pthread_mutex_t ledger_mutex;                  /** Mutex protecting block height advancement and MVCC rollback. */
    };

    /* --- 2. Consensus & Mempool --- */
    struct {
        _Atomic(Operation *) pending_operations[MAX_PENDING_OPS]; /** Lock-free mempool array. */
        _Atomic(uint32_t) pending_operations_count;    /** Active count of unconfirmed mempool operations. */
        HashTable *block_consensus;                    /** Table mapping block hashes to active @ref BlockVoteQueue structures. */
        HashTable *block_proposers;                    /** Table mapping block hashes to leader @ref BlockProposerInfo. */
        HashTable *threshold_stake_processes;         /** Active @ref ThresholdStakeProcess ceremonies. */
        HashTable *voted_heights;                      /** Fast anti-equivocation table tracking heights voted on. */
        HashTable *orphan_pool;                        /** Storage for valid blocks awaiting ancestor attachment. */
        bool proposing_block;                          /** True while local node is actively constructing a proposal. */
        pthread_mutex_t threshold_mutex;               /** Mutex protecting threshold ceremonies and keygen processes. */
        pthread_mutex_t block_proposers_lock;          /** Mutex protecting block_proposers table. */
    };

    /* --- 3. Network & Peer Management --- */
    struct {
        P2PNetwork p2p_network;                        /** Peer address book and NAT state. */
        HashTable *user_table;                         /** Table mapping 32-byte User IDs to @ref User structs. */
        HashTable *pubkey_cache;                       /** Cache mapping User IDs to full Dilithium5 public keys. */
        Queue message_queue;                           /** Inter-thread message queue for network dispatch. */
        uint8_t sync_peer_pubkey[DILITHIUM_PUBKEY_LEN];/** Public key of peer providing blockchain sync stream. */
        int in_blockchain_sync;                        /** Flag: 1 if node is actively syncing blocks, 0 otherwise. */
        int blockchain_sync_received_end;              /** Flag signaling receipt of MSG_END_OF_DATA during sync. */
        uint64_t sync_received_block_number_value;     /** Target chain height reported by sync peer. */
        uint64_t network_target_block_number;          /** Highest block height observed across network gossip. */
        uint8_t sync_received_block_hash[COIN_ID_LEN]; /** Target tip block hash reported by sync peer. */
    };

    /* --- 4. Background Workers & Concurrency --- */
    struct {
        pthread_t sync_thread;                         /** Thread handle for asynchronous Initial Block Download. */
        atomic_bool sync_thread_active;                /** True while sync_thread is executing. */
        WorkStealingQueue *recreation_queues;          /** Array of per-core work-stealing transaction task queues. */
        pthread_t *recreation_workers;                 /** Array of recreation worker thread handles. */
        int recreation_workers_count;                  /** Number of active recreation worker threads. */
        pthread_cond_t recreation_cond;                /** Condition variable waking recreation workers. */
        pthread_mutex_t recreation_sleep_mutex;        /** Sleep mutex for recreation worker pool. */
        _Atomic(uint32_t) round_robin_idx;             /** Counter round-robining tasks across recreation queues. */
        _Atomic(int) active_background_threads;        /** Counter bounding detached background worker threads. */
        pthread_t *submission_workers;                 /** Thread pool executing client valuation proposals. */
        int submission_workers_count;                  /** Count of submission worker threads. */
        volatile int submission_running;               /** Run-flag governing submission processor threads. */
        struct CryptoVerifyTask *crypto_verify_head;   /** Queue head of incoming cryptographic tasks. */
        struct CryptoVerifyTask *crypto_verify_tail;   /** Queue tail of incoming cryptographic tasks. */
        pthread_t *crypto_verify_workers;              /** Thread pool performing parallel cryptographic verification. */
        int crypto_verify_workers_count;               /** Count of crypto verification threads. */
        volatile int crypto_verify_running;            /** Run-flag governing crypto verification threads. */
        pthread_mutex_t crypto_verify_mutex;           /** Mutex protecting crypto verify task queue. */
        pthread_cond_t crypto_verify_cond;             /** Condition variable signaling new crypto task. */
        pthread_t autopilot_thread;                    /** Dedicated thread handle for Auto-Pilot daemon. */
        atomic_bool autopilot_running;                 /** True while Auto-Pilot automation loop is running. */
        SclRpcEngine rpc_engine;                       /** Multi-threaded L5 RPC execution engine. */
    };

    /* --- 5. Global Top-level User Data & Synchronization --- */
    struct {
        User *users;                                   /** Pre-allocated array of User structures. */
        size_t user_count;                             /** Active user count in `users`. */
        UserWallet user_wallet;                        /** Master wallet state of the local node operator. */
        Queue submission_queue;                        /** Queue serializing local valuation proposals. */
        _Atomic(uint64_t) scheduled_consumed_subunits; /** Subunits locked in pending outbound liquid transfers. */
        _Atomic(uint64_t) scheduled_staked_subunits;   /** Subunits locked in pending outbound unstaking requests. */
        int pending_ops_received;                      /** Flag signaling completion of mempool sync. */
        int audit_received;                            /** Flag signaling completion of audit matrix sync. */
        pthread_mutex_t mutex;                         /** Master coordinator mutex. */
        pthread_mutex_t wallet_mutex;                  /** Mutex protecting master private keys and wallet access. */
        pthread_mutex_t submission_mutex;              /** Mutex protecting submission_queue. */
        pthread_cond_t pending_ops_cond;               /** Condition variable signaling mempool sync completion. */
        pthread_cond_t audit_cond;                     /** Condition variable signaling audit sync completion. */
        pthread_cond_t blockchain_sync_cond;           /** Condition variable signaling block sync completion. */
        pthread_cond_t resync_cond;                    /** Condition variable signaling forced reorganization. */
        pthread_cond_t submission_cond;                /** Condition variable waking submission worker threads. */
    };
    
    /* --- 6. Epoch Beacons & Committee State --- */
    struct {
        polyvec_t epoch_s1_subsets[10];                /** Local Joint-RSS secret polynomial subsets s1. */
        polyvec_t epoch_s2_subsets[10];                /** Local Joint-RSS secret polynomial subsets s2. */
        polyvec_t epoch_t_global;                      /** Reconstructed global public verification vector t. */
        uint16_t epoch_point_id;                       /** Local signer index within active DKG committee (1..10). */
        bool is_epoch_member;                          /** True if local node is elected into active committee. */
        uint8_t epoch_rho[KAPPA];                      /** 32-byte global matrix expansion seed rho for active epoch. */
        HashTable *epoch_processes;                    /** Hash table tracking active beacon threshold ceremonies. */
        HashTable *epoch_sign_data_cache;              /** Cache storing ephemeral signing parameters. */
        HashTable *dkg_active_sessions;                /** Table indexing multi-round DKG sessions by session_id. */
        pthread_mutex_t epoch_mutex;                   /** Mutex protecting epoch keys, DKG state, and subsets. */
        uint8_t current_committee[10][PUBKEY_LEN];     /** Array of 10 committee member public verification keys. */
        size_t current_committee_count;                /** Committee member count (saturates at 10). */
        uint64_t last_dkg_attempted_epoch;             /** Epoch index of last DKG execution attempt. */
    };

    /* --- 7. Transport Layer Hypergraph PoW --- */
    struct {
        LocalHypergraph hypergraph;                    /** Hypergraph tracking peer reputations and PoW challenges. */
        pthread_t hypergraph_maintainer_thread;        /** Thread handle for background hypergraph state sweeps. */
    };
} State;

/* ============================================================================ */
/* 12. WORKER THREAD PARAMETER CONTEXT STRUCTURES                               */
/* ============================================================================ */

/** @brief Context arguments passed to the primary network background thread. */
typedef struct {
    State *state;                             /** Pointer to global ledger state. */
    User *user;                               /** Pointer to local user profile. */
    volatile int running;                     /** Thread run-flag. */
    pthread_mutex_t shutdown_mutex;           /** Mutex for shutdown synchronization. */
    pthread_cond_t shutdown_cond;             /** Condition variable for shutdown. */
} NetworkArgs;

/** @brief Context arguments passed to asynchronous vote collection threads. */
typedef struct VoteThreadArgs {
    State *state;                    /** Application state. */
    User *user;                      /** User state. */
    Block *block;                    /** Block being voted on. */
} VoteThreadArgs;

/** @brief Context arguments passed to partial signature collector threads. */
typedef struct {
    State *state;                           /** Application state. */
    uint8_t stake_tx_id[COIN_ID_LEN];       /** For stake process lookup (keyed by tx_id). */
    uint8_t threshold_pubkey[PUBKEY_LEN];   /** For unstake signing lookup (keyed by pubkey). */
} PartialCollectorArgs;

/** @brief Context arguments passed to the asynchronous coinbase reward minting thread. */
typedef struct {
    State *state;                             /** Pointer to global ledger state. */
    User *user;                               /** Pointer to local user profile. */
    uint8_t user_id[USER_ID_LEN];             /** Target recipient user ID. */
    Valuation valuation;                      /** Submitted valuation vector. */
    int matches;                              /** Computed match count. */
    uint64_t snapshot_total_rewarded;         /** Snapshot total reward supply. */
    Valuation audit_snapshot[AUDIT_SIZE];     /** Audit snapshot copy. */
    uint32_t snapshot_count;                  /** Active valuations in snapshot. */
    uint32_t snapshot_audit_index;            /** Circular write index at snapshot. */
} MintThreadArgs;

/** @brief Context arguments passed to valuation submission processor threads. */
typedef struct {
    State *state;  /** Pointer to the shared state containing the submission queue. */
    bool *running; /** Pointer to a flag controlling the processor thread's lifecycle. */
} SubmissionProcessorArgs;

/** @brief Context arguments passed to asynchronous transaction recreation workers. */
typedef struct {
    State *state;                         /** Pointer to global ledger state. */
    uint64_t amount;                      /** Transfer or stake amount in subunits. */
    bool is_stake;                        /** True for stake, false for unstake. */
    bool is_transfer;                     /** True if operation is a standard transfer. */
    uint8_t recipient_pubkey[PUBKEY_LEN]; /** Recipient public key. */
} RecreateArgs;

/** @brief Generic worker thread initialization argument. */
struct WorkerArgs {
    State *s;                             /** Pointer to global ledger state. */
    int id;                               /** Worker thread index. */
};

/** @brief Context arguments passed to background Initial Block Download synchronization thread. */
typedef struct {
    State *state;                              /** Pointer to global ledger state. */
    uint8_t peer_pubkey[DILITHIUM_PUBKEY_LEN]; /** Public key of selected sync peer. */
    bool force;                                /** Force synchronization flag. */
} SyncThreadArgs;

/** @brief Context arguments passed to cryptographic worker threads. */
typedef struct {
    SclConnection *test_conn;             /** Test connection reference. */
    int worker_id;                        /** Worker core identifier. */
} CryptoWorkerArgs;

/** @brief Context arguments passed to block proposal delegation threads. */
typedef struct {
    State *state;                         /** Pointer to global ledger state. */
    Operation *op;                        /** Injected operation pointer. */
} ProposeBlockArgs;

/** @brief Context arguments passed to the Distributed Key Generation worker thread. */
typedef struct {
    State *state;                         /** Pointer to global ledger state. */
    uint8_t session_id[COIN_ID_LEN];      /** Epoch session identifier. */
    uint64_t block_height;                /** Target block height. */
} DKGWorkerArgs;

/** @brief Thread-local linear memory arena header. */
typedef struct {
    uint8_t *memory;                      /** Pre-allocated arena buffer pointer. */
    size_t offset;                        /** Current linear allocation offset. */
} CryptoArena;

/** @brief Individual log message queue slot for asynchronous structured telemetry. */
typedef struct {
    FILE *stream;                         /** Target output file or stream. */
    char msg[1024];                       /** Zero-heap inline storage. */
    _Atomic(bool) ready;                  /** MPSC Concurrency Synchronization flag. */
} LogEntry;

/** @brief Task node queuing a network message for parallel cryptographic verification. */
typedef struct CryptoVerifyTask {
    Message msg;                               /** Inbound network message copy. */
    uint8_t sender_pubkey[DILITHIUM_PUBKEY_LEN];/** Authenticated sender public key. */
    struct sockaddr_storage sender_addr;       /** Sender network socket address. */
    SclConnection *conn;                       /** Connection context reference. */
    struct CryptoVerifyTask *next;             /** Next task in verification queue. */
} CryptoVerifyTask;

/** @brief Staker record sorting active validators deterministically by locked capital. */
typedef struct {
    uint8_t addr[USER_ID_LEN];            /** Validator user identifier. */
    uint64_t stake;                       /** Staked subunit balance. */
} StakerRecord;

/** @brief Dispatch task wrapping an inbound RPC frame for multi-threaded execution. */
typedef struct {
    Message *msg;                         /** Inbound RPC message pointer. */
    SclConnection *conn;                  /** Connection context pointer. */
    uint8_t sender_pubkey[PUBKEY_LEN];     /** Public key of the caller. */
} RpcTask;

/** @brief Internal implementation structure for the opaque SclRpcBuilder handle. */
struct BuilderInternal {
    uint8_t version;                      /** Protocol version. */
    uint16_t method_id;                   /** Method identifier. */
    uint64_t request_id;                  /** Request tracking ID. */
    uint8_t flags;                        /** Operational flags. */
    uint32_t cursor;                      /** Pagination cursor. */
    uint8_t *payload;                     /** Dynamic payload buffer. */
    size_t payload_len;                   /** Current payload length. */
    size_t payload_cap;                   /** Allocated payload capacity. */
};

/** @brief Internal implementation structure for the opaque SclRpcParser handle. */
struct ParserInternal {
    uint8_t version;                      /** Extracted protocol version. */
    uint8_t flags;                        /** Extracted operational flags. */
    uint16_t status_code;                 /** Extracted execution status code. */
    uint16_t method_id;                   /** Extracted method identifier. */
    uint64_t request_id;                  /** Extracted tracking identifier. */
    uint32_t cursor;                      /** Extracted pagination cursor. */
    char error_msg[256];                  /** Extracted ASCII error message. */
    uint8_t *payload;                     /** Extracted payload pointer. */
    size_t payload_len;                   /** Extracted payload length in bytes. */
};

#endif // TYPES_H
