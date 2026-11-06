/**
 * @file common/constants.h
 * @brief Satocialist Protocol Protocol-Wide Constants, Thresholds, and Architecture Parameters
 *
 * @details
 * This header defines immutable protocol boundaries, physical network link constraints,
 * polynomial quotient ring and lattice parameters, economic hard-caps, sliding-window quotas,
 * memory arena ceilings, and cross-platform byte-order / aligned allocation abstractions.
 *
 * @section protocol_invariants Protocol Invariants
 * - Total coin supply is strictly bounded by @ref MAX_TOTAL_SUBUNITS = 2,560,000,000,000,000 subunits
 *   (exactly 16,000,000 SCL coins). No state transition may increase total unspent + spent + rewarded above this ceiling.
 * - Polynomial arithmetic is grounded in the cyclotomic quotient ring R_q = Z_q[X]/(X^256 + 1)
 *   with prime modulus Q = 8,380,417 (D = 13, ALPHA = 523,776).
 * - Minimum link Maximum Transmission Unit (MTU) is fixed at 1,280 bytes to guarantee safe, unfragmented
 *   IPv6 and IPv4 transit across Internet backbones without host-level IP fragmentation.
 * - Cryptographic security conforms to NIST Level 5 post-quantum standards (ML-DSA-87 / Dilithium5,
 *   ML-KEM-512 / Kyber-512, Module-SIS PRF with 128-bit classical and quantum collision resistance).
 *
 * @section rfc_references Standards and RFC References
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA).
 * - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).
 * - RFC 8439 / SipHash-2-4: Pseudorandom Function for Denial-of-Service Defense.
 * - RFC 9000 / RFC 9002: QUIC In-Order Streaming, Loss Detection, and Congestion Control.
 * - BDLOP (Bootle, Lyubashevsky, Seiler et al.): Homomorphic Lattice Commitments over R_q.
 *
 * @section platform_model Platform & Concurrency Model
 * - Memory alignments, endianness transformations, and high-resolution timer fallbacks are
 *   supported natively across Linux, macOS, FreeBSD, Windows NT, and Emscripten (WebAssembly).
 * - Macro declarations are stateless, constant, and inherently thread-safe. Thread-local arena sizes
 *   define per-worker memory boundaries to prevent dynamic heap fragmentation.
 */

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <oqs/oqs.h>
#include <pthread.h>
#include <stdio.h>

/* ============================================================================ */
/* 1. CHARACTER CONVERSION & UTILITY MACROS                                     */
/* ============================================================================ */

/**
 * @brief Branchless ASCII case-folding macro.
 * @param[in] c Single character code (unsigned or signed char).
 * @return Lowercase character if c is uppercase ASCII ('A'-'Z'); otherwise returns c unchanged.
 */
#define SCL_TOLOWER(c) ((c) >= 'A' && (c) <= 'Z' ? (c) + 32 : (c))

/* ============================================================================ */
/* 2. L5 RPC WIRE FORMAT & OPERATIONAL STATUS CONSTANTS                         */
/* ============================================================================ */

/**
 * @brief Active version identifier for the native L5 RPC protocol.
 * All frames must present this version in Byte 0 of SclRpcHeader; mismatches trigger SCL_RPC_STATUS_BAD_VERSION.
 */
#define SCL_RPC_VERSION_1 0x01

/** @brief RPC Header Flag: Wire payload contains a leading 4,595-byte Dilithium5 signature. */
#define SCL_RPC_FLAG_SIGNED     (1 << 0)
/** @brief RPC Header Flag: Execution payload uses and requires pagination cursor bounds. */
#define SCL_RPC_FLAG_PAGINATED  (1 << 1)
/** @brief RPC Header Flag: Functional arguments/responses are compressed with LZ4. */
#define SCL_RPC_FLAG_COMPRESSED (1 << 2)
/** @brief RPC Header Flag: Indicates payload is prepended with an SclRpcPaymentReceipt. */
#define SCL_RPC_FLAG_PAYMENT_RECEIPT    (1 << 3)

/** @brief RPC Status Code: Execution succeeded without errors. */
#define SCL_RPC_STATUS_OK           0x0000
/** @brief RPC Status Code: Header version field does not match SCL_RPC_VERSION_1. */
#define SCL_RPC_STATUS_BAD_VERSION  0x0001
/** @brief RPC Status Code: Cryptographic signature verification or session authentication failed. */
#define SCL_RPC_STATUS_UNAUTHORIZED 0x0002
/** @brief RPC Status Code: Target method identifier is unrecognized or unmapped. */
#define SCL_RPC_STATUS_BAD_METHOD   0x0003
/** @brief RPC Status Code: Payload bounds, arguments, or serialized structures are malformed. */
#define SCL_RPC_STATUS_INVALID_ARGS 0x0004
/** @brief RPC Status Code: SipHash-2-4 checksum mismatch (packet corruption or DoS attempt). */
#define SCL_RPC_STATUS_CHECKSUM_ERR 0x0005
/** @brief RPC Status Code: Client token bucket or active concurrency quota exhausted. */
#define SCL_RPC_STATUS_RATE_LIMITED 0xFFFF
/** @brief RPC Status Code: Execution requires cryptographic fee payment (HTTP 402 parity). */
#define SCL_RPC_STATUS_PAYMENT_REQUIRED 0x0192

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    /** @brief Number of background RPC worker threads active under fuzzing (minimized to eliminate thread races). */
    #define MAX_RPC_WORKERS 1
#else
    /** @brief Number of background RPC worker threads active in production node runtime. */
    #define MAX_RPC_WORKERS 8
#endif

/** @brief Maximum concurrent in-flight RPC requests permitted per peer connection before rate-limiting triggers. */
#define MAX_CONCURRENT_RPCS_PER_CONN 3

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Maximum items returned in a single paginated query during fuzzing runs (reduced for speed). */
    #define MAX_PAGINATION_RANGE 16
#else
    /** @brief Maximum items returned in a single paginated query in production (e.g., GetRecentTxs). */
    #define MAX_PAGINATION_RANGE 500
#endif

/* ============================================================================ */
/* 3. RPC TELEMETRY & STRUCTURED LOGGING MACROS                                 */
/* ============================================================================ */

/* ANSI VT100 Terminal Color & Style Palette for Structured Logging */
#if defined(SCL_NO_COLOR)
    #define SCL_CLR_RESET        ""
    #define SCL_CLR_BOLD         ""
    #define SCL_CLR_DIM          ""
    #define SCL_CLR_RED          ""
    #define SCL_CLR_GREEN        ""
    #define SCL_CLR_YELLOW       ""
    #define SCL_CLR_BLUE         ""
    #define SCL_CLR_MAGENTA      ""
    #define SCL_CLR_CYAN         ""
    #define SCL_CLR_WHITE        ""
    #define SCL_CLR_GRAY         ""
    #define SCL_CLR_BRIGHT_RED   ""
#else
    #define SCL_CLR_RESET        "\x1b[0m"
    #define SCL_CLR_BOLD         "\x1b[1m"
    #define SCL_CLR_DIM          "\x1b[2m"
    #define SCL_CLR_RED          "\x1b[31m"
    #define SCL_CLR_GREEN        "\x1b[32m"
    #define SCL_CLR_YELLOW       "\x1b[33m"
    #define SCL_CLR_BLUE         "\x1b[34m"
    #define SCL_CLR_MAGENTA      "\x1b[35m"
    #define SCL_CLR_CYAN         "\x1b[36m"
    #define SCL_CLR_WHITE        "\x1b[37m"
    #define SCL_CLR_GRAY         "\x1b[90m"
    #define SCL_CLR_BRIGHT_RED   "\x1b[91m"
#endif

/**
 * @brief Emits a low-overhead structured trace entry for an accepted inbound RPC frame.
 * @param[in] hdr Pointer to the parsed SclRpcHeader structure.
 * @param[in] peer_ip C-string representing the remote peer IPv4/IPv6 address.
 */
#define SCL_LOG_RPC_TRACE(hdr, peer_ip) \
    if (unlikely(current_log_level <= LOG_LEVEL_TRACE)) { \
        scl_log(LOG_LEVEL_TRACE, SCL_CLR_GRAY "RPC_INBOUND" SCL_CLR_RESET, \
                SCL_CLR_GRAY "ReqID=" SCL_CLR_RESET "%llu" SCL_CLR_GRAY " | Method=" SCL_CLR_CYAN "0x%04X" SCL_CLR_GRAY " | Flags=0x%02X | Size=%u | Peer=" SCL_CLR_BLUE "%s" SCL_CLR_RESET, \
                (unsigned long long)(hdr)->request_id, (hdr)->method_id, (hdr)->flags, (hdr)->payload_len, peer_ip); \
    }

/**
 * @brief Emits a warning log for an RPC request rejected at node ingress.
 * @param[in] hdr Pointer to the parsed SclRpcHeader structure.
 * @param[in] peer_ip C-string representing the remote peer address.
 * @param[in] status_code Numeric rejection status code returned to sender.
 * @param[in] reason Human-readable diagnostic description.
 */
#define SCL_LOG_RPC_REJECT(hdr, peer_ip, status_code, reason) \
    if (unlikely(current_log_level <= LOG_LEVEL_WARN)) { \
        scl_log(LOG_LEVEL_WARN, SCL_CLR_YELLOW SCL_CLR_BOLD "RPC_REJECT" SCL_CLR_RESET, \
                "ReqID=%llu | " SCL_CLR_RED "Status=0x%04X" SCL_CLR_RESET " | Peer=" SCL_CLR_BLUE "%s" SCL_CLR_RESET " | " SCL_CLR_BOLD SCL_CLR_RED "Reason=%s" SCL_CLR_RESET, \
                (unsigned long long)(hdr)->request_id, status_code, peer_ip, reason); \
    }

/**
 * @brief Emits an informational log when an RPC-injected operation is finalized into a block.
 * @param[in] tx_id Hexadecimal string identifier of the confirmed transaction.
 * @param[in] block_height Numeric height of the committed block.
 */
#define SCL_LOG_RPC_TX_COMMIT(tx_id, block_height) \
    if (unlikely(current_log_level <= LOG_LEVEL_INFO)) { \
        scl_log(LOG_LEVEL_INFO, SCL_CLR_GREEN SCL_CLR_BOLD "RPC_CONSENSUS" SCL_CLR_RESET, \
                "TxInjected via RPC (" SCL_CLR_CYAN "%s" SCL_CLR_RESET ") incorporated successfully into Block " SCL_CLR_BOLD SCL_CLR_GREEN "#%llu" SCL_CLR_RESET, \
                tx_id, (unsigned long long)block_height); \
    }

/** @brief Ring capacity for the asynchronous lock-free log message queue (in entries). */
#define SCL_LOG_QUEUE_SIZE 8192

/** @brief Dedicated thread pool count for parallel cryptographic proof verification. */
#define NUM_CRYPTO_WORKERS 4

/** @brief Global hard ceiling on simultaneously active peer connection states per node instance. */
#define MAX_ACTIVE_CONNECTIONS 256

/** @brief Sentinel pointer representing an erased tombstone entry in lock-free Maglev CID routing tables. */
#define SCL_TOMBSTONE ((SclConnection *)-1)

/** @brief Maximum number of reusable 8MB staging buffers allowed across all threads before backpressure kicks in. */
#define MAX_STAGING_BUFFERS 256

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Thread-local linear crypto arena size in bytes during fuzzing runs (4 MiB). */
    #define CRYPTO_ARENA_SIZE (4 * 1024 * 1024)
#elif defined(CONFIG_CRYPTO_ARENA_SIZE)
    /** @brief Compile-time override for thread-local linear crypto arena size in bytes. */
    #define CRYPTO_ARENA_SIZE CONFIG_CRYPTO_ARENA_SIZE
#else
    /** @brief Default thread-local linear crypto arena size in bytes (128 MiB) to support batch ZK-proofs. */
    #define CRYPTO_ARENA_SIZE (128 * 1024 * 1024)
#endif

/* ============================================================================ */
/* 4. CROSS-PLATFORM BYTE ORDER & ALIGNED MEMORY ABSTRACTIONS                  */
/* ============================================================================ */

#if defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #include <unistd.h>
    
    #ifndef htobe64
        #define htobe64 OSSwapHostToBigInt64
    #endif
    #ifndef be64toh
        #define be64toh OSSwapBigToHostInt64
    #endif
    #ifndef htobe32
        #define htobe32 OSSwapHostToBigInt32
    #endif
    #ifndef be32toh
        #define be32toh OSSwapBigToHostInt32
    #endif
    #ifndef htobe16
        #define htobe16 OSSwapHostToBigInt16
    #endif
    #ifndef be16toh
        #define be16toh OSSwapBigToHostInt16
    #endif
    
    /** @brief Allocates heap memory aligned to specified boundary on macOS platforms using posix_memalign. */
    #define SCL_ALIGNED_ALLOC(ptr, alignment, size) \
        do { if (posix_memalign((void **)(ptr), (alignment), (size)) != 0) *(ptr) = NULL; } while(0)
    /** @brief Deallocates aligned memory on macOS platforms. */
    #define SCL_ALIGNED_FREE(ptr) free(ptr)

#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__EMSCRIPTEN__)
    #if defined(__linux__) || defined(__EMSCRIPTEN__)
        #include <endian.h>
    #else
        #include <sys/endian.h>
    #endif
    #include <unistd.h>
    
    /** @brief Allocates heap memory aligned to specified boundary on Linux/BSD/Emscripten platforms. */
    #define SCL_ALIGNED_ALLOC(ptr, alignment, size) \
        do { if (posix_memalign((void **)(ptr), (alignment), (size)) != 0) *(ptr) = NULL; } while(0)
    /** @brief Deallocates aligned memory on Linux/BSD/Emscripten platforms. */
    #define SCL_ALIGNED_FREE(ptr) free(ptr)

#elif defined(_WIN32) || defined(_WIN64)
    #include <winsock2.h>
    #include <windows.h>
    #include <malloc.h>
    
    #ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
        #define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
    #endif
    
    #define htobe64(x) htonll(x)
    #define be64toh(x) ntohll(x)
    #define htobe32(x) htonl(x)
    #define be32toh(x) ntohl(x)
    #define htobe16(x) htons(x)
    #define be16toh(x) ntohs(x)

    /**
     * @brief High-resolution microsecond sleep routine for Windows NT.
     * @param[in] usec Duration to sleep in microseconds.
     * Uses waitable timer handles where available, falling back to QPC polling with thread yielding.
     */
    static inline void scl_win_usleep(uint64_t usec) {
        static _Thread_local HANDLE timer = NULL;
        static _Thread_local int timer_initialized = 0;
        
        if (!timer_initialized) {
            timer = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
            if (!timer) {
                timer = CreateWaitableTimerW(NULL, TRUE, NULL);
            }
            timer_initialized = 1;
        }

        if (timer) {
            LARGE_INTEGER ft;
            ft.QuadPart = -(int64_t)(usec * 10);
            SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
            WaitForSingleObject(timer, INFINITE);
        } else {
            LARGE_INTEGER freq, start, current;
            QueryPerformanceFrequency(&freq);
            QueryPerformanceCounter(&start);
            uint64_t wait_ticks = (usec * freq.QuadPart) / 1000000ULL;
            
            DWORD ms = (DWORD)(usec / 1000);
            if (ms > 0) {
                Sleep(ms);
            }
            do {
                SwitchToThread();
                QueryPerformanceCounter(&current);
            } while ((uint64_t)(current.QuadPart - start.QuadPart) < wait_ticks);
        }
    }
    #define usleep(x) scl_win_usleep(x)
    
    /** @brief Allocates heap memory aligned to specified boundary on Windows using _aligned_malloc. */
    #define SCL_ALIGNED_ALLOC(ptr, alignment, size) \
        do { *(ptr) = _aligned_malloc((size), (alignment)); } while(0)
    /** @brief Deallocates aligned memory on Windows using _aligned_free. */
    #define SCL_ALIGNED_FREE(ptr) _aligned_free(ptr)

#else
    #error "Unsupported platform - byte order conversion and aligned allocation macros required"
#endif

#if !defined(_WIN32) && !defined(_WIN64)
    #if !defined(__APPLE__) && !defined(__linux__) && !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
        #include <unistd.h>
    #endif
#endif

/* ============================================================================ */
/* 5. GENERAL NUMERICAL & BRANCH PREDICTION MACROS                              */
/* ============================================================================ */

/** @brief Returns the greater of two comparable values. */
#define MAX(a, b) ((a) > (b) ? (a) : (b))
/** @brief Returns the smaller of two comparable values. */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#ifndef unlikely
/** @brief GCC/Clang branch weight hint indicating the enclosed condition evaluates false in the common path. */
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* ============================================================================ */
/* 6. HYPERGRAPH & TRANSPORT-LAYER PROOF-OF-WORK CONSTANTS                      */
/* ============================================================================ */

/** @brief Maximum node vertices tracked in the local peer reputation hypergraph. */
#define MAX_HYPERGRAPH_NODES       512
/** @brief Maximum directed hyperedges tracking temporal peer interactions. */
#define MAX_HYPERGRAPH_EDGES       4096
/** @brief Reputation threshold below which incoming connections face secondary proof-of-work puzzles. */
#define REPUTATION_THRESHOLD_LOW   10
/** @brief Threshold for connection attempts per minute triggering anti-spam secondary PoW difficulty. */
#define MAX_CONNECTIONS_PER_MINUTE 5
/** @brief Rotation cadence in milliseconds for the precomputed transport PoW challenge puzzle cache (relaxed for WAN). */
#define PUZZLE_CACHE_ROTATION_MS   60000
/** @brief Memory footprint in bytes of each dual-rotating Bloom filter guarding against graph poisoning (8 KiB). */
#define BLOOM_FILTER_SIZE          8192
/** @brief Duration of one network epoch in milliseconds (1 hour = 3,600,000 ms). */
#define EPOCH_DURATION_MS          3600000

/* ============================================================================ */
/* 7. L0/L1 TRANSPORT DRIVER & HANDSHAKE SLAB CONSTANTS (QUIC-PARITY)          */
/* ============================================================================ */

/** @brief Safe Link MTU in octets guaranteed to traverse Internet backbones without IPv4/IPv6 fragmentation. */
#define SCL_LINK_MTU 1280
/** @brief Dimensional length in bytes of the Cryptographic Connection Identifier (CID). */
#define SCL_CID_LEN 20

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Ring buffer capacity for the single-producer single-consumer L0->L5 queue during fuzzing. */
    #define SCL_L5_RING_SIZE 16
#else
    /** @brief Ring buffer capacity for the single-producer single-consumer L0->L5 queue in production (16,384 frames). */
    #define SCL_L5_RING_SIZE 16384
#endif

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    /** @brief Bucket count for SipHash IP and subnet anti-DoS rate tracking during fuzzing runs. */
    #define SCL_DOS_TRACKER_SIZE 16
#else
    /** @brief Bucket count for SipHash IP and subnet anti-DoS rate tracking in production (65,536 buckets). */
    #define SCL_DOS_TRACKER_SIZE 65536
#endif

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    /** @brief Preallocated slot count in the L1 Handshake Reassembly Slab under fuzzing (128 slots). */
    #define SCL_SLAB_SLOTS 128
#else
    /** @brief Preallocated slot count in the L1 Handshake Reassembly Slab in production (10,000 slots = 160 MB). */
    #define SCL_SLAB_SLOTS 10000
#endif

/** @brief Fixed byte size allocated for each reassembly slab slot (16 KiB = 16,384 bytes). */
#define SCL_SLAB_SLOT_SIZE 16384

/** @brief Maximum slots reserved for Tier 2 (untrusted / un-staked) initial connections (50% = 5,000 slots). */
#define SCL_TIER2_MAX_SLOTS (SCL_SLAB_SLOTS / 2)
/** @brief Maximum percentage of Tier 2 slots consumable by any single IPv4 /24 subnet (5%). */
#define SCL_SUBNET_LIMIT_PERCENT 5
/** @brief Strict slot ceiling allowed for a single IPv4 /24 subnet (250 slots). */
#define SCL_SUBNET_MAX_SLOTS ((SCL_TIER2_MAX_SLOTS * SCL_SUBNET_LIMIT_PERCENT) / 100)
/** @brief Maximum incomplete handshake slots permitted for a single client IP address. */
#define SCL_IP_LIMIT_PER_CONN 256

/* ============================================================================ */
/* 8. L4 REPLAY WINDOW & OUT-OF-ORDER (OOO) MEMORY QUOTAS                      */
/* ============================================================================ */

/** @brief Minimum bit width of the sliding replay window bitmask for packet deduplication. */
#define SCL_MIN_REPLAY_WINDOW  4096
/** @brief Maximum expanded bit width of the sliding replay window on high-bandwidth links. */
#define SCL_MAX_REPLAY_WINDOW  65536

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Size of the driver-level UDP packet reception ring buffer under fuzzing (16 slots). */
    #define SCL_RX_RING_SIZE       16
#else
    /** @brief Size of the driver-level UDP packet reception ring buffer in production (1,024 slots). */
    #define SCL_RX_RING_SIZE       1024
#endif

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Bounded heap quota per connection for out-of-order reassembly under fuzzing (256 KiB). */
    #define SCL_OOO_QUOTA_PER_CONN 262144
#else
    /** @brief Bounded heap quota per connection for out-of-order reassembly in production (16 MiB). */
    #define SCL_OOO_QUOTA_PER_CONN 16777216
#endif

/** @brief Global OOO memory threshold above which backpressure mode activates (8 MiB). */
#define SCL_OOO_CRUSH_LIMIT    8388608

/** @brief Maximum flow-control window size in bytes for stream multiplexing (16 MiB). */
#define SCL_FLOW_WINDOW_SIZE   16777216

/** @brief Number of 64-bit words needed to represent an 8,192-bit data fragment presence mask. */
#define SCL_DATA_MASK_WORDS    (8192 / 64)
/** @brief Number of 64-bit words needed to represent a 2,048-bit parity fragment presence mask. */
#define SCL_PARITY_MASK_WORDS  (2048 / 64)

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    /** @brief Maximum FEC parity shards generated or stored per fragment group during fuzzing. */
    #define SCL_MAX_PARITY_SHARDS  16
#else
    /** @brief Maximum FEC parity shards generated or stored per fragment group in production (2,048). */
    #define SCL_MAX_PARITY_SHARDS  2048
#endif

/* ============================================================================ */
/* 9. L2/L3 PACKET FLAGS & WIRE HEADER CONSTANTS                               */
/* ============================================================================ */

/** @brief Packet Header Flag: QUIC-style Long Header indicator (0b11000000). Used in handshake phases. */
#define SCL_PACKET_FLAG_LONG_HEADER  0xC0
/** @brief Packet Header Flag: QUIC-style Short Header indicator (0b01000000). Used in 1-RTT data transit. */
#define SCL_PACKET_FLAG_SHORT_HEADER 0x40
/** @brief Packet Header Flag: Packet contains fragmented application payload chunk. */
#define SCL_PACKET_FLAG_FRAGMENTED   0x20
/** @brief Packet Header Flag: Server RETRY packet carrying an updated stateless cookie and PoW difficulty. */
#define SCL_PACKET_FLAG_RETRY        0x10

/** @brief Minimum invariant byte length of an unencrypted wire header (Flags[1] + CID[20] + PktNum[8] = 29 bytes). */
#define SCL_HEADER_MIN_LEN (1 + SCL_CID_LEN + 8)

/** @brief Maximum payload byte capacity per individual unfragmented chunk within Link MTU (1,100 bytes). */
#define SCL_MAX_CHUNK_SIZE 1100

/* ============================================================================ */
/* 10. L4 RELIABILITY, CONGESTION & LOSS DETECTION (RFC 9002 & BBRv3)           */
/* ============================================================================ */

/** @brief Initial estimated smoothed Round-Trip Time before receiving first ACK sample (800 ms). */
#define SCL_INITIAL_RTT 800
/** @brief Hard floor on Probe Timeout (PTO) in milliseconds to absorb heavy post-quantum cryptographic latency. */
#define SCL_MIN_PTO 1000
/** @brief Maximum receiver delayed ACK interval in milliseconds before sending acknowledgment (25 ms). */
#define SCL_MAX_ACK_DELAY 25
/** @brief Duplicate ACK threshold triggering fast packet loss declaration (32 packets). */
#define SCL_PACKET_THRESHOLD 32
/** @brief Numerator for time-loss detection threshold (9/8 * SRTT). */
#define SCL_TIME_THRESHOLD_NUM 9
/** @brief Maximum reliable-stream retransmission attempts per packet before the connection is reset (storm circuit-breaker). */
#define SCL_MAX_STREAM_RETRANSMITS 10
/** @brief Denominator for time-loss detection threshold (9/8 * SRTT). */
#define SCL_TIME_THRESHOLD_DEN 8

/** @brief Baseline Bandwidth-Delay Product (BDP) congestion window floor (512 KiB). */
#define SCL_MICRO_BDP_LIMIT 524288
/** @brief Congestion window decay floor applied during persistent packet loss events (256 KiB). */
#define SCL_DECAYED_BDP_LIMIT 262144
/** @brief Duration of inactive receive time in milliseconds before an untrusted sync connection is declared stalled. */
#define SCL_STALL_TIMEOUT_MS 5000
/** @brief Cumulative memory quota across all concurrent untrusted Initial Block Download streams (1 GiB). */
#define SCL_GLOBAL_SYNC_QUOTA 1073741824ULL

/** @brief L4 Multiplexing Frame: Keepalive PING frame eliciting immediate ACK from receiver. */
#define SCL_FRAME_PING 0x01
/** @brief L4 Multiplexing Frame: Packet acknowledgment frame carrying highest acknowledged packet and delay. */
#define SCL_FRAME_ACK 0x02
/** @brief L4 Multiplexing Frame: Retires active CID and issues a cryptographically independent replacement CID. */
#define SCL_FRAME_NEW_CONNECTION_ID 0x04
/** @brief L4 Multiplexing Frame: Challenge frame for validating NAT rebinding and path migration. */
#define SCL_FRAME_PATH_CHALLENGE 0x05
/** @brief L4 Multiplexing Frame: Direct reflection of PATH_CHALLENGE payload verifying route reachability. */
#define SCL_FRAME_PATH_RESPONSE 0x06
/** @brief L4 Multiplexing Frame: Reliable, flow-controlled, in-order application stream byte segment. */
#define SCL_FRAME_STREAM 0x08
/** @brief L4 Multiplexing Frame: Credit update augmenting the cumulative receiver stream flow control window. */
#define SCL_FRAME_MAX_DATA 0x10
/** @brief L4 Multiplexing Frame: Unreliable, unordered datagram frame (used for ephemeral votes). */
#define SCL_FRAME_DATAGRAM 0x30

/* ============================================================================ */
/* 11. THRESHOLD DILITHIUM5 (ML-DSA-87) POLYNOMIAL RING PARAMETERS             */
/* ============================================================================ */

/** @brief Prime modulus Q = 8,380,417 = 2^23 - 2^13 + 1 defining the cyclotomic quotient ring R_q. */
#define Q 8380417
/** @brief Maximum absolute bound for small secret polynomial coefficients (in [-ETA, ETA], ETA = 2). */
#define ETA 2
/** @brief Hamming weight (number of +/- 1 coefficients) in the challenge polynomial c. */
#define TAU 60
/** @brief Uniform sampling bound for masking vector y (2^19 = 524,288). */
#define GAMMA1 (1 << 19)
/** @brief Maximum allowable count of non-zero coefficients in hint vectors h (for Dilithium5, OMEGA = 75). */
#define OMEGA 75
/** @brief Bit count dropped during Power2Round coefficient decomposition (D = 13). */
#define D 13
/** @brief Decomposition modulus parameter ALPHA = 2 * gamma2 = 523,776. */
#define ALPHA 523776
/** @brief Dimension K (row count of public matrix A_bar; vector length of t, w, h) for Dilithium5. */
#define DILITHIUM_K 8
/** @brief Dimension L (column count of public matrix A_bar; vector length of s1, y, z) for Dilithium5. */
#define DILITHIUM_L 7
/** @brief Degree N of the cyclotomic ring polynomial quotient X^256 + 1. */
#define RING_DEG 256
/** @brief Length in bytes of seeds, random nonces, and rho matrix expansions (32 bytes). */
#define KAPPA 32
/** @brief SHAKE-256 eXtendable Output Function (XOF) rate block size in bytes (168 bytes). */
#define SHAKE256_RATE 168

/** @brief Packed byte size of high-bits polynomial t1 (10 bits per coefficient * 256 = 320 bytes). */
#define POLYT1_PACKEDBYTES 320
/** @brief Packed byte size of signature response polynomial z (20 bits per coefficient * 256 = 640 bytes). */
#define POLYZ_PACKEDBYTES 640
/** @brief Packed byte size of w1 commitment polynomial (4 bits per coefficient * 256 = 128 bytes). */
#define POLYW1_PACKEDBYTES 128
/** @brief Packed byte size of hint vector h (OMEGA non-zero indices + K count delimiters = 83 bytes). */
#define POLYH_PACKEDBYTES (OMEGA + DILITHIUM_K)

/** @brief Fixed delay padding in microseconds applied during signing retries to prevent timing side-channels. */
#define SIGN_RETRY_DELAY_US 10000
/** @brief Total mathematical subsets in the Joint-RSS threshold scheme: C(10, 2-1) = 10 for n=10, t=2. */
#define NUM_SUBSETS 10
/** @brief Number of subset polynomial shares held by each threshold committee member: C(9, 1) = 9. */
#define SUBSETS_PER_PARTY 9
/** @brief Maximum infinity norm bound for an individual party's combined secret share (ETA * 9 = 18). */
#define MAX_S_PART_INF (ETA * SUBSETS_PER_PARTY)

/** @brief Uncompressed serialized byte size of a single polynomial in R_q (256 * 4 bytes = 1,024 bytes). */
#define POLY_SERIALIZED_SIZE (RING_DEG * sizeof(int32_t))
/** @brief Uncompressed serialized byte size of a vector of L polynomials (7 * 1,024 = 7,168 bytes). */
#define POLYVEC_L_SERIALIZED (DILITHIUM_L * POLY_SERIALIZED_SIZE)
/** @brief Uncompressed serialized byte size of a vector of K polynomials (8 * 1,024 = 8,192 bytes). */
#define POLYVEC_K_SERIALIZED (DILITHIUM_K * POLY_SERIALIZED_SIZE)

/** @brief Maximum concurrent interactive threshold signing/staking processes tracked per node. */
#define MAX_THRESHOLD_PROCESSES 10
/** @brief Hard timeout in seconds for collecting partial threshold signature shares before aborting. */
#define SIGN_TIMEOUT 60

/* ============================================================================ */
/* 12. POST-QUANTUM CRYPTOGRAPHIC KEY & SIGNATURE DIMENSIONS (FIPS 204/203)     */
/* ============================================================================ */

/** @brief Byte length of an ML-DSA-87 (Dilithium5) public verification key (2,592 bytes). */
#define DILITHIUM_PUBKEY_LEN OQS_SIG_dilithium_5_length_public_key
/** @brief Byte length of an ML-DSA-87 (Dilithium5) secret signing key (4,864 bytes). */
#define DILITHIUM_SECRETKEY_LEN OQS_SIG_dilithium_5_length_secret_key
/** @brief Byte length of an ML-DSA-87 (Dilithium5) detached signature (4,595 bytes). */
#define DILITHIUM_SIGNATURE_LEN OQS_SIG_dilithium_5_length_signature

/** @brief Byte length of an ML-KEM-512 (Kyber-512) public encapsulation key (800 bytes). */
#define KYBER_PUBKEY_LEN OQS_KEM_kyber_512_length_public_key
/** @brief Byte length of an ML-KEM-512 (Kyber-512) secret decapsulation key (1,632 bytes). */
#define KYBER_SECRETKEY_LEN OQS_KEM_kyber_512_length_secret_key
/** @brief Byte length of an ML-KEM-512 (Kyber-512) ciphertext envelope (768 bytes). */
#define KYBER_CIPHERTEXT_LEN OQS_KEM_kyber_512_length_ciphertext
/** @brief Byte length of an ML-KEM-512 (Kyber-512) established shared symmetric secret (32 bytes). */
#define KYBER_SHARED_SECRET_LEN OQS_KEM_kyber_512_length_shared_secret

/** @brief Diagnostic helper macro logging compiled ML-DSA-87 buffer constants to standard output. */
#define LOG_DILITHIUM_CONSTANTS() do { \
    printf("[P2P] Dilithium constants: PUBKEY_LEN=%d, PRIVKEY_LEN=%d, SIGNATURE_LEN=%d\n", \
           DILITHIUM_PUBKEY_LEN, DILITHIUM_SECRETKEY_LEN, DILITHIUM_SIGNATURE_LEN); \
    printf("[P2P] SCLCoin size: sizeof(SCLCoin)=%zu\n", \
           sizeof(SCLCoin)); \
} while (0)

/** @brief Diagnostic helper macro validating compiled ML-KEM-512 buffer lengths against NIST specifications. */
#define LOG_KYBER_CONSTANTS() do { \
    printf("[P2P] Kyber constants: PUBKEY_LEN=%d, PRIVKEY_LEN=%d, CIPHERTEXT_LEN=%d, SHARED_SECRET_LEN=%d\n", \
           KYBER_PUBKEY_LEN, KYBER_SECRETKEY_LEN, KYBER_CIPHERTEXT_LEN, KYBER_SHARED_SECRET_LEN); \
    if (KYBER_CIPHERTEXT_LEN != 768) { \
        fprintf(stderr, "[P2P] WARNING: KYBER_CIPHERTEXT_LEN=%d, expected 768 for Kyber-512\n", \
                KYBER_CIPHERTEXT_LEN); \
    } \
    if (KYBER_SHARED_SECRET_LEN != 32) { \
        fprintf(stderr, "[P2P] WARNING: KYBER_SHARED_SECRET_LEN=%d, expected 32 for Kyber-512\n", \
                KYBER_SHARED_SECRET_LEN); \
    } \
} while (0)

/* ============================================================================ */
/* 13. LEDGER, UTXO & MONETARY HARD-CAP CONSTANTS                              */
/* ============================================================================ */

/** @brief Length in bytes of standard cryptographic identifiers (SHA-256 digest = 32 bytes). */
#define COIN_ID_LEN 32
/** @brief Canonical length of master identity public keys (maps to DILITHIUM_PUBKEY_LEN = 2,592 bytes). */
#define PUBKEY_LEN DILITHIUM_PUBKEY_LEN
/** @brief Canonical length of master identity secret keys (maps to DILITHIUM_SECRETKEY_LEN = 4,864 bytes). */
#define PRIVKEY_LEN DILITHIUM_SECRETKEY_LEN
/** @brief Canonical length of consensus and transaction signatures (maps to DILITHIUM_SIGNATURE_LEN = 4,595 bytes). */
#define SIGNATURE_LEN DILITHIUM_SIGNATURE_LEN

/** @brief Number of indivisible atomic subunits per whole SCL coin (1 SCL = 160,000,000 subunits). */
#define SUBUNITS_PER_COIN 160000000ULL
/** @brief Absolute protocol hard-cap on whole circulating SCL coins (16,000,000 SCL). */
#define MAX_SCL_COINS 16000000ULL
/** @brief Immutable total subunit supply ceiling: 16M coins * 160M subunits = 2,560,000,000,000,000 subunits. */
#define MAX_TOTAL_SUBUNITS (MAX_SCL_COINS * SUBUNITS_PER_COIN)
/** @brief Supply issuance step threshold (in SCL coins) used to increment dynamic Stage requirement (2,000,000 SCL). */
#define SCL_COIN_THRESHOLD 2000000

/* ============================================================================ */
/* 14. DATA STRUCTURE, MERKLE ACCUMULATOR & CONSENSUS CAPACITY LIMITS          */
/* ============================================================================ */

/** @brief Maximum load factor threshold (count / size) triggering automatic doubling of hash table capacity. */
#define LOAD_FACTOR_THRESHOLD 0.7

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(CRYPTO_ZK_FUZZER)
    /** @brief Maximum Merkle Mountain Range proof path length under fuzzing (16 siblings). */
    #define MAX_PATH_LEN 16
    /** @brief Maximum Merkle Mountain Range peak count under fuzzing (16 peaks). */
    #define MAX_PEAKS 16
#else
    /** @brief Maximum Merkle Mountain Range proof path length in production (64 siblings = 2^64 leaf capacity). */
    #define MAX_PATH_LEN 64
    /** @brief Maximum Merkle Mountain Range peaks aggregated to form the unified state root (32 peaks). */
    #define MAX_PEAKS 32
#endif

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(CRYPTO_ZK_FUZZER)
    /** @brief Maximum input pointers allowed per transaction under fuzzing (4 inputs). */
    #define MAX_INPUTS 4
    /** @brief Maximum operations packed into a single proposed block under fuzzing (4 operations). */
    #define MAX_OPERATIONS_PER_BLOCK 4
#else
    /** @brief Maximum input pointers allowed per transaction in production (1,024 inputs). */
    #define MAX_INPUTS 1024
    /** @brief Maximum operations packed into a single proposed block in production (100 operations). */
    #define MAX_OPERATIONS_PER_BLOCK 100
#endif

/** @brief Upper bound on candidate pointers selectable in a single greedy balance aggregation. */
#define MAX_SELECTED_POINTERS MAX_INPUTS

/**
 * @brief Exact byte size of the serialized pointer data hashed for input Merkle tree generation.
 * ParentCoinID(32) + OwnerAddress(32) + StartSubunit(8) + EndSubunit(8) + PrevTxHash(32) = 112 bytes.
 */
#define POINTER_SIGNING_SIZE (2 * COIN_ID_LEN + 2 * sizeof(uint64_t) + USER_ID_LEN)

/** @brief Length in bytes of unique User IDs derived via SHA-256 from the master public key (32 bytes). */
#define USER_ID_LEN 32
/** @brief Number of integer entries in each submitted valuation vector (range [0, 99]). */
#define NUMBERS_PER_VALUATION 10
/** @brief Maximum number of pending valuations processed per client round. */
#define MAX_VALUATIONS 100
/** @brief Dimensional size (slot count) of the circular Game Audit matrix buffer (10 rows). */
#define AUDIT_SIZE 10

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(CRYPTO_ZK_FUZZER)
    /** @brief Upper bound on serialized network messages during fuzzing runs (256 KiB). */
    #define MAX_MESSAGE_SIZE 262144
#elif defined(CONFIG_MAX_MESSAGE_SIZE)
    /** @brief Compile-time override for maximum serialized network message size. */
    #define MAX_MESSAGE_SIZE CONFIG_MAX_MESSAGE_SIZE
#else
    /** @brief Default maximum serialized network message size (8 MiB) accommodating massive PQ batch blocks. */
    #define MAX_MESSAGE_SIZE 8388608
#endif

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Size of the lock-free mempool transaction pool during fuzzing runs (16 slots). */
    #define MAX_PENDING_OPS 16
#else
    /** @brief Size of the lock-free mempool transaction pool in production (10,000 slots). */
    #define MAX_PENDING_OPS 10000
#endif

/** @brief Maximum peer addresses gossiped in an individual MSG_PEER_LIST_SYNC message. */
#define MAX_PEERS_PER_MESSAGE 32

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Peer address book capacity under fuzzing (16 peers). */
    #define MAX_CLIENTS 16
#else
    /** @brief Peer address book capacity in production (10,000 peers). */
    #define MAX_CLIENTS 10000
#endif

/**
 * @brief Total cryptographic framing overhead in bytes prepended/appended to encrypted network messages.
 * KyberCiphertext(768) + LengthPrefix(4) + DilithiumSignature(4595) + AES-GCM-Tag/Padding(28) = 5,395 bytes.
 */
#define ENCRYPTION_OVERHEAD (KYBER_CIPHERTEXT_LEN + 4 + SIGNATURE_LEN + 28)

/** @brief Number of blocks comprising one DKG committee rotation epoch (440 blocks = ~24 hours at 3-min target). */
#define BLOCKS_PER_DAY 440
/** @brief Time interval in seconds between automatic grants of free validation credits (1 hour = 3,600 s). */
#define VALIDATION_INTERVAL 3600
/** @brief Initial validation credits awarded to a newly initialized wallet identity. */
#define INITIAL_VALIDATION_CREDITS 10ULL
/** @brief Forward lookahead scan window for discovering derived UTXO blinding factors during wallet sync. */
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(CRYPTO_ZK_FUZZER)
#define SCL_WALLET_SCAN_WINDOW 1
#else
#define SCL_WALLET_SCAN_WINDOW 128
#endif
/** @brief Fraction of affirmative peer votes required to commit a proposed block (2/3 supermajority = 2.0 / 3.0). */
#define CONSENSUS_THRESHOLD (2.0 / 3.0)
/** @brief Maximum duration in seconds a block proposal waits to collect consensus votes (30 seconds). */
#define VOTE_TIMEOUT 30

/** @brief Maximum duration of peer inactivity in seconds before declaring connection dead (60 seconds). */
#define MAX_PEER_SILENCE_TIME 60
/** @brief Maximum consecutive AEAD authentication failures tolerated on one connection before it is killed and re-handshaken. */
#define SCL_MAX_CONSECUTIVE_AEAD_FAILURES 3
/** @brief A peer only counts toward the consensus quorum base if it produced verified traffic within this window. */
#define SCL_QUORUM_LIVENESS_MS 45000
/** @brief Cadence in seconds for dispatching keepalive ping queries to connected peers (15 seconds). */
#define LIVENESS_CHECK_INTERVAL 15

/* ============================================================================ */
/* 15. MODULE-SIS ZERO-KNOWLEDGE PRF & BDLOP COMMITMENT RING PARAMETERS        */
/* ============================================================================ */

/** @brief Matrix rank of the Module-SIS PRF construction (K = 4 polynomials). */
#define PRF_K 4
/** @brief Total secret ternary coefficients across the Module-SIS key vector (4 * 256 = 1,024). */
#define PRF_M (PRF_K * RING_DEG)
/** @brief Degree of the PRF output polynomial (256 coefficients). */
#define PRF_OUT RING_DEG
/** @brief Byte length of the derived transaction nullifier output (32 bytes). */
#define NULLIFIER_LEN 32

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    /** @brief Memory footprint in bytes of the nullifier fast-lookup Bloom filter under fuzzing (1 KiB). */
    #define NULLIFIER_BLOOM_BYTES 1024
#else
    /** @brief Memory footprint in bytes of the nullifier fast-lookup Bloom filter in production (256 KiB). */
    #define NULLIFIER_BLOOM_BYTES 262144
#endif

/** @brief Total bit capacity of the nullifier Bloom filter. */
#define NULLIFIER_BLOOM_BITS  (NULLIFIER_BLOOM_BYTES * 8)

/** @brief Input bit length for PRF evaluation (128 bits). */
#define PRF_L 128
/** @brief Ring modulus for PRF operations (identical to Dilithium modulus Q = 8,380,417). */
#define PRF_Q Q
/** @brief Scaling divisor P for quotient extraction in the PRF rounding function (P = 256). */
#define PRF_P 256
/** @brief Fixed Hamming weight (count of non-zero coefficients) in secret PRF keys. */
#define PRF_HAMMING 250
/** @brief Bit width required to encode quotient remainder z coefficients (ceil(log2(Q/P)) = 15 bits). */
#define BITS_PER_COEFF 15
/** @brief Bit width required to pack ternary secret key coefficients in {-1, 0, 1} (2 bits). */
#define BITS_PER_KEY_COEFF 2
/** @brief Byte length of random seeds used for Stern permutation generation (32 bytes). */
#define PERM_SEED_LEN 32

/** @brief Bit-packed byte length of secret key vector k (1024 * 2 bits / 8 = 256 bytes). */
#define PI_B_K_PACKED_LEN ((PRF_M * BITS_PER_KEY_COEFF + 7) / 8)
/** @brief Bit-packed byte length of input index j (128 bits / 8 = 16 bytes). */
#define PI_J_PACKED_LEN   ((PRF_L + 7) / 8)
/** @brief Bit-packed byte length of remainder polynomial z (256 * 15 bits / 8 = 480 -> padded to 512 bytes). */
#define PI_B_Z_PACKED_LEN ((PRF_OUT * BITS_PER_COEFF + 7) / 8)

/** @brief Length in bytes of intermediate Merkle tree root commitments in ZK protocols (32 bytes). */
#define COMMITMENTS_LEN 32
/** @brief Length in bytes of Merkle tree sibling hashes in ZK protocols (32 bytes). */
#define MERKLE_SIBLING_LEN 32

/** @brief Number of Stern protocol round iterations required to achieve 128-bit sound zero-knowledge proof. */
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(CRYPTO_ZK_FUZZER)
    #define ZK_KAPPA 1
#else
    #define ZK_KAPPA 219
#endif

/** @brief Maximum revealed response payload per Stern round: PI_B_K(256) + PI_B_Z(512) = 768 bytes. */
#define ZK_MAX_RESPONSE_SIZE (PI_B_K_PACKED_LEN + PI_B_Z_PACKED_LEN)
/** @brief Total serialized byte capacity per single Stern round repetition: Commitments(32) + Response(768). */
#define ZK_MAX_REP_SIZE (COMMITMENTS_LEN + ZK_MAX_RESPONSE_SIZE)

#if defined(CRYPTO_ZK_FUZZER)
    /** @brief Maximum allowable ZK proof byte size for crypto ZK fuzzer (64 KiB to accommodate 14,656-byte Centinel proofs). */
    #define ZK_PROOF_MAX_LEN 65536
#elif defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    /** @brief Maximum allowable ZK proof byte size under fuzzing runs (4 KiB). */
    #define ZK_PROOF_MAX_LEN 4096
#else
    /** @brief Upper limit on total aggregated ZK-proof byte length in production (4,000,000 bytes). */
    #define ZK_PROOF_MAX_LEN 4000000
#endif

/** @brief Minimum structural length of a valid ZK Stern proof envelope: Root(32) + (219 rounds * 96 bytes). */
#define ZK_PROOF_MIN_LEN (32 + (ZK_KAPPA * 96))

/** @brief Length in bytes of random seed expanding the public BDLOP parameters a and b (32 bytes). */
#define BDLOP_PUBKEY_SEED_LEN 32
/** @brief Byte footprint of serialized BDLOP polynomial coefficients (256 * sizeof(int32_t) = 1,024 bytes). */
#define BDLOP_COEFF_BYTES 1024
/** @brief Immutable domain separator seed used to deterministically expand BDLOP matrix parameters. */
#define BDLOP_RHO_SEED "SCL_CENTINEL_LATTICE_BDLOP_V1_SEED"

/* ============================================================================ */
/* 16. SIPHASH-2-4 CONSTANTS & PRIMITIVE TRANSFORMATION ROUND MACRO            */
/* ============================================================================ */

/**
 * @brief 64-bit circular left rotation macro.
 * @param[in] x Value to rotate.
 * @param[in] b Number of bit positions to rotate left (0 <= b < 64).
 */
#define SIP_ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

/**
 * @brief Single round of the SipHash-2-4 permutation mixing internal 64-bit state registers v0, v1, v2, v3.
 * Implements the quarter-round ARX (Add-Rotate-XOR) sequence specified in RFC 8439.
 */
#define SIPROUND do { \
    v0 += v1; v1 = SIP_ROTL64(v1, 13); v1 ^= v0; v0 = SIP_ROTL64(v0, 32); \
    v2 += v3; v3 = SIP_ROTL64(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = SIP_ROTL64(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = SIP_ROTL64(v1, 17); v1 ^= v2; v2 = SIP_ROTL64(v2, 32); \
} while(0)

#endif // CONSTANTS_H
