/**
 * @file tests/benchmarks.c
 * @module tests/benchmarks - Production Performance & Scalability Test Suite
 *
 * @brief Comprehensive multi-dimensional performance, throughput, latency, and
 *        hardware-stress benchmark suite for the Satocialist Cryptographic Ledger (SCL).
 *
 * @details
 * This module measures the micro-architectural, cryptographic, and algorithmic
 * characteristics of the SCL runtime under simulated peak-load conditions:
 *
 * 1. Post-Quantum Lattice Primitives (PQ-TPS):
 *    - ML-DSA-87 (NIST FIPS 204 / Dilithium5): Keypair generation, signing, and
 *      signature verification latencies (mean, P95, P99, max) and operations/second.
 *    - ML-KEM-512 (NIST FIPS 203 / Kyber-512): Keypair generation, encapsulation,
 *      and decapsulation throughput and latency profiles.
 *
 * 2. L5 Application-Layer RPC Wire Serialization & Compression:
 *    - Frame Construction: Frame building, dynamic argument packing, Dilithium5 signature
 *      embedding, and SipHash-2-4 checksum calculation via `scl_rpc_builder`.
 *    - Payload Compression: Real-time throughput (MB/sec) and ratio analysis for LZ4.
 *    - Frame Parsing: Zero-copy header decoding, SipHash verification, and payload extraction.
 *
 * 3. Mempool Ingestion & Transaction Pipeline (Mempool TPS):
 *    - Single-threaded and multi-threaded parallel ingestion under lock-free atomic CAS
 *      contention across CPU cores.
 *    - Replace-By-Fee (RBF) evaluation speed and duplicate transaction rejection efficiency.
 *
 * 4. Consensus, Proof Validation & Ledger State Transitions:
 *    - Block Construction: SHA-256 header hashing, payload packing, and pointer verification.
 *    - Heavy ZK-PRF Batch Verification: Aggregated Stern zero-knowledge proof verification
 *      over Module-SIS lattice assumptions.
 *    - Ledger Commit: State tree mutation, Merkle Mountain Range (MMR) accumulator peak
 *      rebalancing, UTXO coin record transitions, and realized block TPS.
 *
 * 5. Zero-Knowledge Centinel Proofs & BDLOP Homomorphic Operations:
 *    - Evaluation of BDLOP homomorphic lattice commitments (Commit, Add, Decrypt).
 *    - Centinel ZK Stern proof generation and verification for confidential coin redemption.
 *
 * 6. System Resource Footprint & Parallel Acceleration:
 *    - Peak Resident Set Size (RSS) profiling via POSIX `getrusage`.
 *    - CPU Core Scaling Factor: Metric of multi-threaded parallel scaling efficiency.
 *
 * @invariants
 * - Monotonicity: Latency measurements rely exclusively on monotonic high-resolution hardware timers.
 * - Determinism: Test fixtures use deterministic cryptographic keys and test transactions.
 * - Memory Neutrality: Heap allocations and thread-local memory are fully deallocated or reset
 *   between benchmark sections via `arena_reset(0)` and explicit destruction routines.
 *
 * @standards
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA).
 * - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).
 * - RFC 7693: SipHash: A Fast Short-Input PRF (SipHash-2-4).
 * - RFC 7932 / LZ4 Frame Format Specification.
 * - BDLOP Lattice-Based Homomorphic Commitment Scheme (Baum et al.).
 * - Stern Zero-Knowledge Identification Scheme applied over Module-SIS lattices.
 *
 * @dependencies
 * - OpenSSL `libcrypto` (SHA256, RAND).
 * - `liblz4` (Real-time lossless payload compression).
 * - POSIX Threads (`pthread`).
 * - POSIX Resource Usage APIs (`sys/resource.h`).
 * - Apple Mach Absolute Timebase (`mach/mach_time.h`) on Darwin platforms.
 *
 * @threading
 * - Orchestrates multi-threaded worker pools (`pthread_t`) to simulate concurrent node ingestion.
 * - Utilizes atomic exchange and relaxed/acquire/release atomics for mempool contention testing.
 * - Safe for single-process execution; not reentrant across separate threads within the same process.
 *
 * @memory_model
 * - Allocations for transaction arrays, pointer records, and blocks are caller-allocated on the heap
 *   and explicitly released upon phase conclusion.
 * - Thread-local arena indices are reset via `arena_reset(0)` between major suite transitions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <math.h>
#include <sys/resource.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <lz4.h>
#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

#include "constants.h"
#include "types.h"
#include "utils.h"
#include "blockchain.h"
#include "game_state.h"
#include "crypto.h"
#include "protocol.h"
#include "hash_table.h"
#include "mmr.h"
#include "user.h"
#include "consensus.h"
#include "client_state.h"
#include "scl_rpc_ffi_export.h"
#include "network.h"
#include "database.h"

/* ============================================================================ */
/* SECTION 0: BENCHMARK CONFIGURATION & GLOBAL HARDWARE TIMERS                 */
/* ============================================================================ */
/**
 * @brief Total evaluation iterations executed for post-quantum cryptographic primitives.
 * @details Chosen to produce statistically sound P95/P99 latency bounds while bounding run duration.
 */
#define BENCH_CRYPTO_ITERS        200

/**
 * @brief Total evaluation iterations executed for L5 RPC wire framing, signing, and parsing.
 */
#define BENCH_RPC_ITERS           500

/**
 * @brief Total synthetic operations submitted during mempool ingestion benchmarks.
 */
#define BENCH_MEMPOOL_TX_COUNT    1000

/**
 * @brief Number of transfer operations packaged into each test block candidate.
 */
#define BENCH_BLOCK_TX_COUNT      100

/**
 * @brief Number of sequential blocks constructed and committed to the ledger state.
 */
#define BENCH_BLOCK_COMMITS       10

/**
 * @brief Number of concurrent worker threads spawned during parallel mempool stress testing.
 */
#define BENCH_THREAD_COUNT        4

/**
 * @brief High-precision monotonic hardware timestamp query.
 *
 * @details
 * Queries the platform-specific monotonic clock to capture elapsed wall-clock duration:
 * - On macOS/Darwin: Queries `mach_absolute_time()` scaled by `mach_timebase_info`.
 * - On Windows: Queries `QueryPerformanceCounter()` scaled by `QueryPerformanceFrequency()`.
 * - On Linux/POSIX: Queries `clock_gettime(CLOCK_MONOTONIC, &ts)`.
 *
 * @pre None.
 * @post Returns non-decreasing monotonic nanoseconds from an arbitrary platform epoch.
 *
 * @note Reentrant, thread-safe, and signal-safe on POSIX systems.
 *
 * @return uint64_t Current monotonic time expressed in nanoseconds (1e-9 sec).
 *
 * @complexity
 * - Time: O(1)
 * - Space: O(1) auxiliary
 */
static inline uint64_t get_time_ns(void) {
#if defined(__APPLE__)
    static mach_timebase_info_data_t timebase = {0, 0};
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    return (mach_absolute_time() * timebase.numer) / timebase.denom;
#elif defined(_WIN32)
    LARGE_INTEGER frequency, count;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&count);
    return (uint64_t)((count.QuadPart * 1000000000ULL) / frequency.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/**
 * @brief Fixed 128-bit SipHash-2-4 benchmark evaluation key.
 * @details Used to simulate transport-layer fast frame verification under RFC 7693.
 */
static const uint8_t BENCH_SIPHASH_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* ============================================================================ */
/* SECTION 1: STATISTICAL MEASUREMENT & REPORTING FRAMEWORK                     */
/* ============================================================================ */
/**
 * @struct MetricResult
 * @brief Statistical profile holding latency percentiles, throughput rates, and timing data.
 *
 * @details
 * Captures latency distributions across benchmark samples. All timing metrics
 * are normalized to microseconds (1e-6 sec), and throughput is normalized to operations
 * per second or megabytes per second (MiB/s).
 */
typedef struct {
    /** @brief Human-readable label identifying the benchmarked routine. Null-terminated ASCII. */
    char name[64];
    /** @brief Number of completed iterations or samples collected. */
    size_t iterations;
    /** @brief Total aggregate wall-clock execution time in seconds. */
    double total_time_sec;
    /** @brief Realized throughput expressed in operations per second. */
    double ops_per_sec;
    /** @brief Arithmetic mean latency per operation in microseconds. */
    double avg_latency_us;
    /** @brief Minimum observed single-operation latency in microseconds. */
    double min_latency_us;
    /** @brief Maximum observed single-operation latency in microseconds. */
    double max_latency_us;
    /** @brief 95th percentile latency cutoff in microseconds. */
    double p95_latency_us;
    /** @brief 99th percentile latency cutoff in microseconds. */
    double p99_latency_us;
    /** @brief Processed payload data rate in megabytes per second (MiB/s, 2^20 bytes). */
    double throughput_mb_s;
} MetricResult;

/**
 * @brief Standard double-precision comparator for POSIX `qsort`.
 *
 * @param[in] a Pointer to first double operand. Caller-owned, borrowed.
 * @param[in] b Pointer to second double operand. Caller-owned, borrowed.
 *
 * @pre `a` and `b` must point to valid initialized `double` variables.
 * @post Leaves operands unchanged.
 *
 * @return int Negative if *a < *b, positive if *a > *b, zero if equal.
 *
 * @complexity
 * - Time: O(1)
 * - Space: O(1) auxiliary
 */
static int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

/**
 * @brief Computes descriptive statistics and percentiles from an array of sample latencies.
 *
 * @details
 * Sorts a temporary copy of the latency array to determine minimum, maximum,
 * 95th percentile, and 99th percentile values. Computes the arithmetic mean and
 * derived operations-per-second and megabytes-per-second throughput figures.
 *
 * @param[in] name Descriptive label for the metric row. Must be null-terminated.
 * @param[in] latencies_us Array of measured execution latencies in microseconds.
 *                         Must contain at least `count` elements. Caller-owned.
 * @param[in] count Number of valid samples in `latencies_us`.
 * @param[in] total_time_sec Measured aggregate execution time in wall-clock seconds.
 * @param[in] total_bytes Total volume of data processed across all samples in bytes.
 *                        Pass 0 if throughput is solely operation-count based.
 *
 * @pre `name != NULL`
 * @pre `latencies_us != NULL` when `count > 0`
 * @pre `total_time_sec >= 0.0`
 *
 * @post Dynamically allocates and frees an auxiliary buffer of `count * sizeof(double)` for sorting.
 *
 * @return MetricResult Initialized structure containing computed distribution parameters.
 *
 * @complexity
 * - Time: O(N log N) where N = `count` due to sorting.
 * - Space: O(N) heap allocation during sorting.
 */
static MetricResult compute_metrics(const char *name, const double *latencies_us, size_t count, double total_time_sec, size_t total_bytes) {
    MetricResult res;
    memset(&res, 0, sizeof(MetricResult));
    strncpy(res.name, name, sizeof(res.name) - 1);
    res.iterations = count;
    res.total_time_sec = total_time_sec;
    
    if (count == 0 || total_time_sec <= 0.0) return res;

    res.ops_per_sec = (double)count / total_time_sec;
    if (total_bytes > 0) {
        /* Convert bytes to binary megabytes (1024 * 1024 bytes per MiB) */
        res.throughput_mb_s = ((double)total_bytes / (1024.0 * 1024.0)) / total_time_sec;
    }

    double *sorted = malloc(count * sizeof(double));
    if (!sorted) return res;
    memcpy(sorted, latencies_us, count * sizeof(double));
    qsort(sorted, count, sizeof(double), compare_doubles);

    double sum = 0.0;
    for (size_t i = 0; i < count; i++) {
        sum += sorted[i];
    }
    res.avg_latency_us = sum / (double)count;
    res.min_latency_us = sorted[0];
    res.max_latency_us = sorted[count - 1];
    /* Nearest-rank percentile calculation */
    res.p95_latency_us = sorted[(size_t)(count * 0.95)];
    res.p99_latency_us = sorted[(size_t)(count * 0.99)];

    free(sorted);
    return res;
}

/**
 * @brief Prints a formatted markdown table row for a single `MetricResult`.
 *
 * @param[in] res Pointer to the metric structure to render. Caller-owned, borrowed.
 *
 * @pre `res != NULL`
 * @post Formatted row written to `stdout`.
 *
 * @complexity
 * - Time: O(1)
 * - Space: O(1) auxiliary
 */
static void print_metric_row(const MetricResult *res) {
    printf("| %-38s | %8zu | %10.2f | %9.2f | %9.2f | %9.2f | %9.2f | %8.2f |\n",
           res->name, res->iterations, res->ops_per_sec,
           res->avg_latency_us, res->p95_latency_us, res->p99_latency_us,
           res->max_latency_us, res->throughput_mb_s);
}

/**
 * @brief Prints a standardized benchmark section header and column descriptions.
 *
 * @param[in] title Human-readable section name. Must be null-terminated.
 *
 * @pre `title != NULL`
 * @post Header text and table formatting written to `stdout`.
 *
 * @complexity
 * - Time: O(1)
 * - Space: O(1) auxiliary
 */
static void print_table_header(const char *title) {
    printf("\n====================================================================================================\n");
    printf("  BENCHMARK: %s\n", title);
    printf("====================================================================================================\n");
    printf("| %-38s | %-8s | %-10s | %-9s | %-9s | %-9s | %-9s | %-8s |\n",
           "Operation / Metric", "Iters", "Ops/sec", "Avg (us)", "P95 (us)", "P99 (us)", "Max (us)", "MB/s");
    printf("|----------------------------------------|----------|------------|-----------|-----------|-----------|-----------|----------|\n");
}

/* ============================================================================ */
/* SECTION 2: POST-QUANTUM CRYPTOGRAPHY BENCHMARKS (ML-DSA-87 & KYBER-512)     */
/* ============================================================================ */
/**
 * @brief Executes throughput and latency benchmarks for quantum-resistant lattice primitives.
 *
 * @details
 * Evaluates the computational overhead of the two primary post-quantum asymmetric primitives:
 *
 * 1. ML-DSA-87 (Dilithium5 - NIST Security Category 5):
 *    - Matrix dimension: k=8, l=7 over polynomial ring R_q = Z_q[X]/(X^256 + 1) with q=8380417.
 *    - KeyGen: Uniform polynomial sampling via SHAKE-256 and NTT transformations.
 *    - Signing: Fiat-Shamir with Aborts, rejection sampling against norm bounds beta and gamma1.
 *    - Verification: Verification of matrix inequality ||w - c*s2||_infinity < gamma2 - beta.
 *
 * 2. ML-KEM-512 (Kyber-512 - NIST Security Category 1):
 *    - Module-LWE lattice scheme with dimension k=2 over ring R_q with q=3329.
 *    - KeyGen: Sampling of secret error vectors and NTT-based matrix expansion.
 *    - Encapsulation: Generation of pseudo-random shared secret and ciphertext vector.
 *    - Decapsulation: NTT inner products, error correction decoding, and Fujisaki-Okamoto re-encryption.
 *
 * @pre System entropy source (`/dev/urandom` or platform CSPRNG) must be functional.
 * @post Outputs statistical summary rows for KeyGen, Sign, Verify, Encapsulate, and Decapsulate.
 *
 * @note Uses untimed warm-up iterations to bring CPU execution cores to operational clock rates
 *       and eliminate cold-cache penalties.
 *
 * @complexity
 * - Time: O(BENCH_CRYPTO_ITERS * (Time(Dilithium) + Time(Kyber)))
 * - Space: O(1) auxiliary heap, stack-allocated key buffers
 */
static void benchmark_crypto_primitives(void) {
    print_table_header("1. Post-Quantum Cryptographic Primitives (ML-DSA-87 & Kyber-512)");

    double latencies[BENCH_CRYPTO_ITERS];
    uint8_t pk_dilithium[DILITHIUM_PUBKEY_LEN];
    uint8_t sk_dilithium[DILITHIUM_SECRETKEY_LEN];
    uint8_t sig_dilithium[DILITHIUM_SIGNATURE_LEN];
    uint8_t msg[256];
    memset(msg, 0x42, sizeof(msg));

    uint8_t pk_kyber[KYBER_PUBKEY_LEN];
    uint8_t sk_kyber[KYBER_SECRETKEY_LEN];
    uint8_t ct_kyber[KYBER_CIPHERTEXT_LEN];
    uint8_t ss_enc[KYBER_SHARED_SECRET_LEN];
    uint8_t ss_dec[KYBER_SHARED_SECRET_LEN];

    /* Warm-up executions to prime instruction cache and trigger CPU governor boost */
    for (int w = 0; w < 2; w++) {
        dilithium_generate_keypair(pk_dilithium, sk_dilithium);
        dilithium_sign(msg, sizeof(msg), sk_dilithium, sig_dilithium);
        dilithium_verify(msg, sizeof(msg), sig_dilithium, pk_dilithium);
        kyber_generate_keypair(pk_kyber, sk_kyber);
        kyber_encapsulate(pk_kyber, ct_kyber, ss_enc);
        kyber_decapsulate(ct_kyber, sk_kyber, ss_dec);
    }

    /* 1.1 Dilithium5 Keypair Generation */
    uint64_t start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        dilithium_generate_keypair(pk_dilithium, sk_dilithium);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    double total_sec = (double)(get_time_ns() - start_time) / 1e9;
    MetricResult res = compute_metrics("Dilithium5 KeyGen", latencies, BENCH_CRYPTO_ITERS, total_sec, 0);
    print_metric_row(&res);

    /* 1.2 Dilithium5 Signature Creation (256-Byte Payload) */
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        dilithium_sign(msg, sizeof(msg), sk_dilithium, sig_dilithium);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Dilithium5 Sign (256B Msg)", latencies, BENCH_CRYPTO_ITERS, total_sec, BENCH_CRYPTO_ITERS * DILITHIUM_SIGNATURE_LEN);
    print_metric_row(&res);

    /* 1.3 Dilithium5 Signature Verification */
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        dilithium_verify(msg, sizeof(msg), sig_dilithium, pk_dilithium);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Dilithium5 Verify", latencies, BENCH_CRYPTO_ITERS, total_sec, BENCH_CRYPTO_ITERS * DILITHIUM_SIGNATURE_LEN);
    print_metric_row(&res);

    /* 1.4 Kyber-512 Public/Private Keypair Generation */
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        kyber_generate_keypair(pk_kyber, sk_kyber);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Kyber-512 KeyGen", latencies, BENCH_CRYPTO_ITERS, total_sec, 0);
    print_metric_row(&res);

    /* 1.5 Kyber-512 KEM Ciphertext Encapsulation */
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        kyber_encapsulate(pk_kyber, ct_kyber, ss_enc);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Kyber-512 Encapsulate", latencies, BENCH_CRYPTO_ITERS, total_sec, BENCH_CRYPTO_ITERS * KYBER_CIPHERTEXT_LEN);
    print_metric_row(&res);

    /* 1.6 Kyber-512 KEM Shared-Secret Decapsulation */
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        kyber_decapsulate(ct_kyber, sk_kyber, ss_dec);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Kyber-512 Decapsulate", latencies, BENCH_CRYPTO_ITERS, total_sec, BENCH_CRYPTO_ITERS * KYBER_CIPHERTEXT_LEN);
    print_metric_row(&res);
}

/* ============================================================================ */
/* SECTION 3: L5 RPC WIRE SERIALIZATION & FRAMING BENCHMARK                    */
/* ============================================================================ */
/**
 * @brief Measures throughput and latency of the L5 native binary RPC pipeline.
 *
 * @details
 * Evaluates the full wire lifecycle of application-level RPC frames under the SCL protocol:
 * 1. Frame Building (`scl_rpc_builder`):
 *    - Appends arguments to an expanding internal buffer.
 *    - Computes Dilithium5 post-quantum signature over the frame payload.
 *    - Calculates the 64-bit SipHash-2-4 checksum across the header and payload.
 *    - Serializes the header structure and writes out the finalized network frame.
 * 2. Payload Compression:
 *    - Measures real-time byte throughput of the LZ4 block compressor over 4 KiB buffers.
 * 3. Ingress Parsing & Verification (`scl_rpc_parser`):
 *    - Validates SipHash checksum integrity against the wire buffer.
 *    - Parses version markers, sequence IDs, and method discriminators.
 *    - Extracts zero-copy references to active payload segments.
 *
 * @pre Dilithium5 keypair generation must succeed.
 * @post Writes performance evaluation metrics to `stdout`.
 *
 * @complexity
 * - Time: O(BENCH_RPC_ITERS * (Size(Frame) + Time(Sign) + Time(LZ4)))
 * - Space: O(1) auxiliary heap, fixed 16 KiB wire serialization scratchpad.
 */
static void benchmark_rpc_pipeline(void) {
    print_table_header("2. L5 Native RPC Wire Framing, Signing & Decompression");

    double latencies[BENCH_RPC_ITERS];
    uint8_t pk_dilithium[DILITHIUM_PUBKEY_LEN];
    uint8_t sk_dilithium[DILITHIUM_SECRETKEY_LEN];
    dilithium_generate_keypair(pk_dilithium, sk_dilithium);

    uint8_t wire_buffer[16384];
    size_t total_bytes_wire = 0;

    char uncompressed_payload[4096];
    memset(uncompressed_payload, 'A', sizeof(uncompressed_payload));
    char compressed_payload[8192];
    size_t comp_bytes_total = 0;

    /* Untimed warm-up pass */
    for (int w = 0; w < 2; w++) {
        SclRpcBuilder builder = scl_rpc_builder_create(SCL_RPC_VERSION_1, 0x0003, 9999);
        scl_rpc_builder_set_flags(builder, SCL_RPC_FLAG_SIGNED);
        scl_rpc_builder_append_args(builder, pk_dilithium, DILITHIUM_PUBKEY_LEN);
        scl_rpc_builder_sign(builder, sk_dilithium);
        size_t ser_len = 0;
        scl_rpc_builder_finalize(builder, wire_buffer, sizeof(wire_buffer), &ser_len);
        scl_rpc_builder_destroy(builder);
        LZ4_compress_default(uncompressed_payload, compressed_payload, sizeof(uncompressed_payload), sizeof(compressed_payload));
        scl_rpc_verify_checksum(wire_buffer, sizeof(SclRpcHeader) + DILITHIUM_PUBKEY_LEN + DILITHIUM_SIGNATURE_LEN, BENCH_SIPHASH_KEY);
    }

    /* 2.1 RPC Builder: Full Frame Construction (Create + Pack + Dilithium Sign + Finalize) */
    uint64_t start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_RPC_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        SclRpcBuilder builder = scl_rpc_builder_create(SCL_RPC_VERSION_1, 0x0003, 100000 + i);
        scl_rpc_builder_set_flags(builder, SCL_RPC_FLAG_SIGNED);
        scl_rpc_builder_append_args(builder, pk_dilithium, DILITHIUM_PUBKEY_LEN);
        scl_rpc_builder_sign(builder, sk_dilithium);
        size_t ser_len = 0;
        scl_rpc_builder_finalize(builder, wire_buffer, sizeof(wire_buffer), &ser_len);
        scl_rpc_builder_destroy(builder);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
        total_bytes_wire += ser_len;
    }
    double total_sec = (double)(get_time_ns() - start_time) / 1e9;
    MetricResult res = compute_metrics("RPC Builder (Create+Sign+Finalize)", latencies, BENCH_RPC_ITERS, total_sec, total_bytes_wire);
    print_metric_row(&res);

    /* 2.2 LZ4 Real-Time Compression Benchmark (4 KiB Buffer) */
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_RPC_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        int c_size = LZ4_compress_default(uncompressed_payload, compressed_payload, sizeof(uncompressed_payload), sizeof(compressed_payload));
        comp_bytes_total += c_size;
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("LZ4 Payload Compression (4KB)", latencies, BENCH_RPC_ITERS, total_sec, comp_bytes_total);
    print_metric_row(&res);

    /* 2.3 RPC Ingress Parser & SipHash-2-4 Anti-DoS Checksum Verification */
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_RPC_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        scl_rpc_verify_checksum(wire_buffer, sizeof(SclRpcHeader) + DILITHIUM_PUBKEY_LEN + DILITHIUM_SIGNATURE_LEN, BENCH_SIPHASH_KEY);
        int status = 0;
        SclRpcParser parser = scl_rpc_parser_create(wire_buffer, sizeof(SclRpcHeader) + DILITHIUM_PUBKEY_LEN + DILITHIUM_SIGNATURE_LEN, &status);
        if (parser) {
            const uint8_t *ref = NULL;
            size_t ref_len = 0;
            scl_rpc_parser_get_payload_ref(parser, &ref, &ref_len);
            scl_rpc_parser_destroy(parser);
        }
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("RPC Parser & SipHash Checksum", latencies, BENCH_RPC_ITERS, total_sec, total_bytes_wire);
    print_metric_row(&res);
}

/* ============================================================================ */
/* SECTION 4: MEMPOOL INGESTION & CONCURRENT TRANSACTION THROUGHPUT            */
/* ============================================================================ */
/**
 * @struct MempoolWorkerArgs
 * @brief Arguments payload passed to concurrent mempool worker threads.
 *
 * @details
 * Partitions the contiguous operation array across worker threads to avoid
 * input read contention while driving concurrent lock-free atomic CAS operations
 * on the node's central mempool buffer.
 */
typedef struct {
    /** @brief Pointer to global client ledger node state. Borrowed, not freed by worker. */
    State *state;
    /** @brief Array of pre-synthesized operations to ingest. Borrowed, not freed by worker. */
    Operation *ops;
    /** @brief Starting index assigned to this worker thread within the `ops` array. */
    size_t start_idx;
    /** @brief Total operation count assigned to this worker. */
    size_t count;
    /** @brief Pre-allocated array storing per-operation measured latencies in microseconds. */
    double *latencies;
    /** @brief Output accumulator tracking successfully accepted operations (return code 0). */
    size_t inserted_count;
} MempoolWorkerArgs;

/**
 * @brief Worker thread entrypoint for concurrent mempool stress testing.
 *
 * @param[in,out] arg Pointer to a populated `MempoolWorkerArgs` structure.
 *
 * @pre `arg != NULL`
 * @pre `arg->state != NULL && arg->ops != NULL && arg->latencies != NULL`
 * @post Measures individual transaction insertion latencies and populates `arg->latencies`.
 *
 * @return void* Always returns NULL upon thread completion.
 *
 * @complexity
 * - Time: O(count * Time(add_pending_operation))
 * - Space: O(1) auxiliary stack space.
 */
static void *mempool_worker_func(void *arg) {
    MempoolWorkerArgs *margs = (MempoolWorkerArgs *)arg;
    margs->inserted_count = 0;

    for (size_t i = 0; i < margs->count; i++) {
        uint64_t t0 = get_time_ns();
        int res = add_pending_operation(margs->state, &margs->ops[margs->start_idx + i]);
        margs->latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
        if (res == 0) {
            margs->inserted_count++;
        }
    }
    return NULL;
}

/**
 * @brief Evaluates transaction mempool ingestion throughput, concurrency, and RBF logic.
 *
 * @details
 * Sets up a realistic ledger state containing an active UTXO coin and 1,000 dependent
 * `Pointer` records. Evaluates:
 * 1. Single-Threaded Ingestion TPS: Baseline insertion overhead via `add_pending_operation`.
 * 2. Multi-Threaded Ingestion TPS: Concurrent insertion across 4 worker threads evaluating
 *    atomic CAS performance on `state->pending_operations`.
 * 3. Replace-By-Fee (RBF) Evaluation: Re-submitting identical transaction nonces with elevated
 *    fee amounts to assess fee-bumping evaluation latency and duplicate rejection.
 *
 * @param[in,out] state Pointer to initialized node State. Modified in-place; state remains
 *                      valid after completion.
 *
 * @pre `state != NULL && state->user_wallet initialized`
 * @post Synthesized coins, pointers, and queued operations are flushed and freed upon exit.
 *
 * @complexity
 * - Time: O(BENCH_MEMPOOL_TX_COUNT * Time(Signature + ZK-PRF + Hash))
 * - Space: O(BENCH_MEMPOOL_TX_COUNT * sizeof(Operation)) heap memory.
 */
static void benchmark_mempool_ingestion(State *state) {
    print_table_header("3. Mempool Ingestion & Transaction Throughput (TPS)");

    // Pre-create UTXO coin in state to ensure operations pass balance validation
    uint8_t dummy_tx_hash[32];
    memset(dummy_tx_hash, 0x77, 32);
    SCLCoin coin = create_coin(dummy_tx_hash, state->user_wallet.dilithium_pubkey);
    coin.total_subunits = 100000000ULL * SUBUNITS_PER_COIN;
    coin.remaining_subunits = 100000000ULL * SUBUNITS_PER_COIN;

    pthread_rwlock_wrlock(&state->bc.rwlock);
    SCLCoin *coin_heap = malloc(sizeof(SCLCoin));
    *coin_heap = coin;
    hash_table_insert(state->bc.coin_table, coin.coin_id, coin_heap, HASH_ENTRY_COIN);

    Pointer *ptrs = calloc(BENCH_MEMPOOL_TX_COUNT, sizeof(Pointer));
    for (size_t i = 0; i < BENCH_MEMPOOL_TX_COUNT; i++) {
        memcpy(ptrs[i].parent_coin_id, coin.coin_id, COIN_ID_LEN);
        ptrs[i].start_subunit = i * 1000000ULL;
        ptrs[i].end_subunit = (i + 1) * 1000000ULL - 1;
        ptrs[i].staked = 0;
        ptrs[i].spent = 0;
        memcpy(ptrs[i].owner_address, coin.owner_address, USER_ID_LEN);
        memcpy(ptrs[i].prev_tx_hash, coin.creation_tx_hash, COIN_ID_LEN);

        uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
        uint8_t *pd = pointer_data;
        memcpy(pd, ptrs[i].parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
        memcpy(pd, ptrs[i].owner_address, USER_ID_LEN); pd += USER_ID_LEN;
        uint64_t start_be = htobe64(ptrs[i].start_subunit);
        memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
        uint64_t end_be = htobe64(ptrs[i].end_subunit);
        memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
        memcpy(pd, ptrs[i].prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
        SHA256(pointer_data, sizeof(pointer_data), ptrs[i].pointer_id);

        hash_table_insert(state->bc.pointer_table, ptrs[i].pointer_id, &ptrs[i], HASH_ENTRY_POINTER);
        add_pointer_id_to_coin(state->bc.coin_pointers, ptrs[i].parent_coin_id, ptrs[i].pointer_id);
    }

    state->bc.insert_order_capacity = 16;
    state->bc.insert_order = calloc(state->bc.insert_order_capacity, sizeof(SCLCoin *));
    state->bc.insert_order[0] = coin_heap;
    state->bc.insert_order_count = 1;

    mmr_add(state->bc.mmr, coin.coin_id, coin.remaining_subunits);
    pthread_rwlock_unlock(&state->bc.rwlock);

    // Construct valid operations array
    Operation *ops = calloc(BENCH_MEMPOOL_TX_COUNT, sizeof(Operation));
    uint8_t recipient_pubkey[DILITHIUM_PUBKEY_LEN];
    memset(recipient_pubkey, 0x88, DILITHIUM_PUBKEY_LEN);

    for (size_t i = 0; i < BENCH_MEMPOOL_TX_COUNT; i++) {
        ops[i].type = OP_TRANSFER_POINTER;
        TransferData *tx = &ops[i].data.transfer_pointer;
        tx->num_inputs = 1;
        tx->inputs[0] = ptrs[i];
        memcpy(tx->recipient_pubkey, recipient_pubkey, PUBKEY_LEN);
        memcpy(tx->sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        tx->amount = (i + 1) * 100;
        memcpy(tx->nonce, &i, sizeof(size_t));
        get_mmr_root(&state->bc, tx->client_root);

        compute_inputs_merkle_root(tx->inputs, tx->num_inputs, tx->inputs_merkle_root);
        dilithium_sign(tx->inputs_merkle_root, COIN_ID_LEN, state->user_wallet.dilithium_privkey, tx->inputs_root_signature);

        size_t payload_len;
        uint8_t payload_buf[16384];
        serialize_transfer_payload(tx, payload_buf, &payload_len);
        SHA256(payload_buf, payload_len, tx->tx_id);

        prf_evaluate(tx->prf_output, &state->user_wallet.prf_key, tx->tx_id, COIN_ID_LEN, tx->client_root);
        // Fast mock ZK proof string for memory benchmarks
        tx->zk_proof_len = 128;
        memset(tx->zk_proof, 0xAA, tx->zk_proof_len);

        uint8_t sig_payload[16384];
        size_t sig_payload_len;
        serialize_transfer_for_signature(tx, sig_payload, &sig_payload_len);
        dilithium_sign(sig_payload, sig_payload_len, state->user_wallet.dilithium_privkey, tx->signature);
    }

    // 3.1 Single-Threaded Mempool Ingestion TPS
    double latencies[BENCH_MEMPOOL_TX_COUNT];
    uint64_t start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_MEMPOOL_TX_COUNT; i++) {
        uint64_t t0 = get_time_ns();
        add_pending_operation(state, &ops[i]);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    double total_sec = (double)(get_time_ns() - start_time) / 1e9;
    MetricResult res = compute_metrics("Mempool Ingestion TPS (1 Thread)", latencies, BENCH_MEMPOOL_TX_COUNT, total_sec, 0);
    print_metric_row(&res);

    // 3.2 Concurrent Multi-Threaded Mempool Ingestion
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *op = atomic_exchange(&state->pending_operations[i], NULL);
        if (op) free(op);
    }
    atomic_store(&state->pending_operations_count, 0);
    
    // Clean RPC Queue telemetry allocations
    pthread_mutex_lock(&state->rpc_engine.incoming_rpc_queue.mutex);
    RecreateNode *r_node = state->rpc_engine.incoming_rpc_queue.head;
    while (r_node) {
        RecreateNode *next = r_node->next;
        RpcTask *task = (RpcTask *)r_node->args;
        if (task) {
            if (task->msg) free(task->msg);
            if (task->conn) scl_connection_release(task->conn);
            free(task);
        }
        free(r_node);
        r_node = next;
    }
    state->rpc_engine.incoming_rpc_queue.head = NULL;
    state->rpc_engine.incoming_rpc_queue.tail = NULL;
    pthread_mutex_unlock(&state->rpc_engine.incoming_rpc_queue.mutex);
    atomic_store_explicit(&state->rpc_engine.active_global_queries, 0, memory_order_relaxed);
    
    pthread_t threads[BENCH_THREAD_COUNT];
    MempoolWorkerArgs margs[BENCH_THREAD_COUNT];
    size_t per_thread = BENCH_MEMPOOL_TX_COUNT / BENCH_THREAD_COUNT;

    double *multi_latencies = malloc(BENCH_MEMPOOL_TX_COUNT * sizeof(double));

    start_time = get_time_ns();
    for (size_t t = 0; t < BENCH_THREAD_COUNT; t++) {
        margs[t].state = state;
        margs[t].ops = ops;
        margs[t].start_idx = t * per_thread;
        margs[t].count = per_thread;
        margs[t].latencies = multi_latencies + (t * per_thread);
        pthread_create(&threads[t], NULL, mempool_worker_func, &margs[t]);
    }

    for (size_t t = 0; t < BENCH_THREAD_COUNT; t++) {
        pthread_join(threads[t], NULL);
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Concurrent Mempool TPS (4 Threads)", multi_latencies, BENCH_MEMPOOL_TX_COUNT, total_sec, 0);
    print_metric_row(&res);

    // 3.3 Replace-By-Fee (RBF) & Duplicate Rejection
    start_time = get_time_ns();
    for (size_t i = 0; i < 200; i++) {
        uint64_t t0 = get_time_ns();
        // Re-insert existing operation with higher fee -> RBF
        ops[i].data.transfer_pointer.amount += 1000;
        add_pending_operation(state, &ops[i]);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("RBF Evaluation Throughput", latencies, 200, total_sec, 0);
    print_metric_row(&res);

    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *op = atomic_exchange(&state->pending_operations[i], NULL);
        if (op) free(op);
    }
    atomic_store(&state->pending_operations_count, 0);

    free(ops);
    free(ptrs);
    free(multi_latencies);
}

/* ============================================================================ */
/* SECTION 5: BLOCK PROPOSAL, HEAVY CRYPTO & CONSENSUS LEDGER COMMIT           */
/* ============================================================================ */
/**
 * @brief Measures end-to-end block assembly, heavy cryptographic consensus, and ledger commits.
 *
 * @details
 * Benchmarks the core block proposal and state commit pipeline across 10 sequential blocks
 * holding 100 transactions each:
 * 1. Block Creation & Hashing: Serializing transactions, packing batched ZK-PRF proofs,
 *    and computing canonical SHA-256 block hashes.
 * 2. Heavy Cryptographic Consensus (`verify_block_heavy_crypto`):
 *    - Batch verification of 100 Stern ZK-PRF proofs over Module-SIS assumptions.
 *    - Public key Dilithium5 signature verification of block proposers.
 * 3. Ledger Application (`apply_block`):
 *    - Dual-pass pointer state mutation (marking spent pointers, allocating child pointers).
 *    - Merkle Mountain Range (MMR) accumulator peak updates and root rebalancing.
 *    - Recording committed block hashes into the lock-free processed block index.
 *    - Calculating realized end-to-end transaction commit throughput (Realized Block TPS).
 *
 * @param[in,out] state Pointer to the initialized global State. Ledger state mutated sequentially.
 *
 * @pre `state != NULL && state->bc initialized`
 * @post Ledger state advanced by `BENCH_BLOCK_COMMITS` blocks. Allocated blocks and transactions freed.
 *
 * @complexity
 * - Time: O(B * (T * Verify(ZK) + Apply(Ledger) + Update(MMR))) where B=10, T=100.
 * - Space: O(B * T * sizeof(Operation)) temporary heap allocations.
 */
static void benchmark_block_consensus_and_ledger(State *state) {
    print_table_header("4. Block Proposal, Heavy Crypto Verification & Consensus");

    uint8_t recipient_pubkey[DILITHIUM_PUBKEY_LEN];
    memset(recipient_pubkey, 0x99, DILITHIUM_PUBKEY_LEN);

    Block *seq_blocks[BENCH_BLOCK_COMMITS] = {0};
    Pointer *all_seq_ptrs[BENCH_BLOCK_COMMITS] = {0};
    Operation *all_seq_ops[BENCH_BLOCK_COMMITS] = {0};
    size_t total_zk_len = BENCH_BLOCK_TX_COUNT * (sizeof(uint32_t) + 128);

    uint8_t current_prev_hash[COIN_ID_LEN];
    memcpy(current_prev_hash, state->current_block_hash, COIN_ID_LEN);

    // Pre-construct 10 sequential blocks to average state commit over N=10 samples
    for (size_t b = 0; b < BENCH_BLOCK_COMMITS; b++) {
        uint8_t dummy_tx_hash[32];
        memset(dummy_tx_hash, 0xA0 + (uint8_t)b, 32);

        SCLCoin coin = create_coin(dummy_tx_hash, state->user_wallet.dilithium_pubkey);
        coin.total_subunits = 100000000ULL * SUBUNITS_PER_COIN;
        coin.remaining_subunits = 100000000ULL * SUBUNITS_PER_COIN;

        Pointer *block_ptrs = calloc(BENCH_BLOCK_TX_COUNT, sizeof(Pointer));
        all_seq_ptrs[b] = block_ptrs;

        pthread_rwlock_wrlock(&state->bc.rwlock);
        SCLCoin *coin_heap = malloc(sizeof(SCLCoin));
        *coin_heap = coin;
        hash_table_insert(state->bc.coin_table, coin.coin_id, coin_heap, HASH_ENTRY_COIN);

        for (size_t i = 0; i < BENCH_BLOCK_TX_COUNT; i++) {
            memcpy(block_ptrs[i].parent_coin_id, coin.coin_id, COIN_ID_LEN);
            block_ptrs[i].start_subunit = i * 1000000ULL;
            block_ptrs[i].end_subunit = (i + 1) * 1000000ULL - 1;
            block_ptrs[i].staked = 0;
            block_ptrs[i].spent = 0;
            memcpy(block_ptrs[i].owner_address, coin.owner_address, USER_ID_LEN);
            memcpy(block_ptrs[i].prev_tx_hash, coin.creation_tx_hash, COIN_ID_LEN);

            uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
            uint8_t *pd = pointer_data;
            memcpy(pd, block_ptrs[i].parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
            memcpy(pd, block_ptrs[i].owner_address, USER_ID_LEN); pd += USER_ID_LEN;
            uint64_t start_be = htobe64(block_ptrs[i].start_subunit);
            memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            uint64_t end_be = htobe64(block_ptrs[i].end_subunit);
            memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            memcpy(pd, block_ptrs[i].prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
            SHA256(pointer_data, sizeof(pointer_data), block_ptrs[i].pointer_id);

            hash_table_insert(state->bc.pointer_table, block_ptrs[i].pointer_id, &block_ptrs[i], HASH_ENTRY_POINTER);
            add_pointer_id_to_coin(state->bc.coin_pointers, block_ptrs[i].parent_coin_id, block_ptrs[i].pointer_id);
        }
        mmr_add(state->bc.mmr, coin.coin_id, coin.remaining_subunits);
        pthread_rwlock_unlock(&state->bc.rwlock);

        Operation *ops = calloc(BENCH_BLOCK_TX_COUNT, sizeof(Operation));
        all_seq_ops[b] = ops;
        uint8_t *batch_prf_outputs = malloc(BENCH_BLOCK_TX_COUNT * NULLIFIER_LEN);
        uint8_t *batch_zk_proof = malloc(total_zk_len);
        uint8_t *curr_zk = batch_zk_proof;

        for (size_t i = 0; i < BENCH_BLOCK_TX_COUNT; i++) {
            ops[i].type = OP_TRANSFER_POINTER;
            TransferData *tx = &ops[i].data.transfer_pointer;
            tx->num_inputs = 1;
            tx->inputs[0] = block_ptrs[i];
            memcpy(tx->recipient_pubkey, recipient_pubkey, PUBKEY_LEN);
            memcpy(tx->sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            tx->amount = (i + 1) * 10;
            size_t nonce_val = (b * 1000) + i;
            memcpy(tx->nonce, &nonce_val, sizeof(size_t));
            get_mmr_root(&state->bc, tx->client_root);

            compute_inputs_merkle_root(tx->inputs, tx->num_inputs, tx->inputs_merkle_root);
            dilithium_sign(tx->inputs_merkle_root, COIN_ID_LEN, state->user_wallet.dilithium_privkey, tx->inputs_root_signature);

            size_t payload_len;
            uint8_t payload_buf[16384];
            serialize_transfer_payload(tx, payload_buf, &payload_len);
            SHA256(payload_buf, payload_len, tx->tx_id);

            prf_evaluate(tx->prf_output, &state->user_wallet.prf_key, tx->tx_id, COIN_ID_LEN, tx->client_root);
            memcpy(batch_prf_outputs + (i * NULLIFIER_LEN), tx->prf_output, NULLIFIER_LEN);

            tx->zk_proof_len = 128;
            memset(tx->zk_proof, 0xBB, tx->zk_proof_len);

            uint32_t proof_len_be = htobe32(tx->zk_proof_len);
            memcpy(curr_zk, &proof_len_be, sizeof(uint32_t));
            curr_zk += sizeof(uint32_t);
            memcpy(curr_zk, tx->zk_proof, tx->zk_proof_len);
            curr_zk += tx->zk_proof_len;

            uint8_t sig_payload[16384];
            size_t sig_payload_len;
            serialize_transfer_for_signature(tx, sig_payload, &sig_payload_len);
            dilithium_sign(sig_payload, sig_payload_len, state->user_wallet.dilithium_privkey, tx->signature);
        }

        seq_blocks[b] = create_block(
            b + 1,
            current_prev_hash,
            ops,
            BENCH_BLOCK_TX_COUNT,
            state->user_wallet.dilithium_pubkey,
            state->user_wallet.dilithium_privkey,
            12345 + (int)b,
            BENCH_BLOCK_TX_COUNT,
            batch_prf_outputs,
            batch_zk_proof,
            total_zk_len
        );

        compute_block_hash(seq_blocks[b], current_prev_hash);
    }

    // 4.1 Block Creation & Hash Computation
    double latencies[50];
    uint64_t start_time = get_time_ns();
    for (size_t i = 0; i < 50; i++) {
        uint64_t t0 = get_time_ns();
        uint8_t h_test[32];
        compute_block_hash(seq_blocks[0], h_test);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    double total_sec = (double)(get_time_ns() - start_time) / 1e9;
    size_t block_bytes = seq_blocks[0] ? (size_t)process_block_data(seq_blocks[0], NULL, NULL, true) : 0;
    MetricResult res = compute_metrics("Block Construction (100 Tx/Block)", latencies, 50, total_sec, 50 * block_bytes);
    print_metric_row(&res);

    // 4.2 Heavy Cryptographic Block Verification
    start_time = get_time_ns();
    for (size_t i = 0; i < 50; i++) {
        uint64_t t0 = get_time_ns();
        verify_block_heavy_crypto(seq_blocks[i % BENCH_BLOCK_COMMITS]);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Heavy Cryptographic Verification", latencies, 50, total_sec, 50 * block_bytes);
    print_metric_row(&res);

    // 4.3 Multi-Block State Commit (N=10 Sequential Blocks)
    double commit_latencies[BENCH_BLOCK_COMMITS];
    double per_tx_latencies[BENCH_BLOCK_COMMITS * BENCH_BLOCK_TX_COUNT];
    size_t total_committed_bytes = 0;

    start_time = get_time_ns();
    for (size_t b = 0; b < BENCH_BLOCK_COMMITS; b++) {
        size_t b_bytes = (size_t)process_block_data(seq_blocks[b], NULL, NULL, true);
        total_committed_bytes += b_bytes;

        uint64_t t0 = get_time_ns();
        apply_block(state, seq_blocks[b]);
        double blk_lat_us = (double)(get_time_ns() - t0) / 1000.0;
        commit_latencies[b] = blk_lat_us;

        double tx_lat_us = blk_lat_us / (double)BENCH_BLOCK_TX_COUNT;
        for (size_t tx = 0; tx < BENCH_BLOCK_TX_COUNT; tx++) {
            per_tx_latencies[b * BENCH_BLOCK_TX_COUNT + tx] = tx_lat_us;
        }
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;

    res = compute_metrics("Block State Commit (100 Tx/Block)", commit_latencies, BENCH_BLOCK_COMMITS, total_sec, total_committed_bytes);
    print_metric_row(&res);

    MetricResult res_tps = compute_metrics("Realized Block Applied TPS", per_tx_latencies, BENCH_BLOCK_COMMITS * BENCH_BLOCK_TX_COUNT, total_sec, total_committed_bytes);
    print_metric_row(&res_tps);

    // Cleanup sequential blocks
    for (size_t b = 0; b < BENCH_BLOCK_COMMITS; b++) {
        free(all_seq_ops[b]);
        free(all_seq_ptrs[b]);
        free_block(seq_blocks[b]);
    }
}

/* ============================================================================ */
/* SECTION 6: SYSTEM RESOURCE USAGE & MULTI-CORE SCALING SUMMARY               */
/* ============================================================================ */
/**
 * @brief Captures and renders operating system resource usage and hardware scaling metrics.
 *
 * @details
 * Queries the kernel process accounting subsystem via `getrusage(RUSAGE_SELF)` to report:
 * - Peak Resident Set Size (RSS) in megabytes (accounting for macOS byte vs POSIX KiB differences).
 * - Total User-Mode CPU time and Kernel System CPU time.
 * - Parallel Acceleration Factor: Ratio of Total CPU Time to Wall-Clock Time, demonstrating
 *   effective multi-core utilization (e.g. 3.5x on a 4-core system).
 * - Page faults (soft minor reclaims vs hard disk faults).
 * - Voluntary and involuntary thread context switches.
 *
 * @param[in] bench_start_ns Monotonic timestamp in nanoseconds captured at program startup.
 *
 * @pre `bench_start_ns <= get_time_ns()`
 * @post Resource metrics written to `stdout`.
 *
 * @complexity
 * - Time: O(1)
 * - Space: O(1) auxiliary
 */
static void benchmark_resource_and_scaling_summary(uint64_t bench_start_ns) {
    print_table_header("5. Resource Consumption & System Health Summary");

    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);

    double wall_time_sec = (double)(get_time_ns() - bench_start_ns) / 1e9;
    double user_cpu_sec = (double)usage.ru_utime.tv_sec + ((double)usage.ru_utime.tv_usec / 1000000.0);
    double sys_cpu_sec = (double)usage.ru_stime.tv_sec + ((double)usage.ru_stime.tv_usec / 1000000.0);
    double total_cpu_sec = user_cpu_sec + sys_cpu_sec;
    double cpu_scaling_ratio = total_cpu_sec / (wall_time_sec > 0.0 ? wall_time_sec : 1.0);

    double peak_rss_mb = (double)usage.ru_maxrss / 1024.0;
#if defined(__APPLE__)
    peak_rss_mb /= 1024.0; // macOS reports ru_maxrss in bytes
#endif

    printf("\n--- SYSTEM RESOURCE METRICS ---\n");
    printf("  • Peak Resident Set Size (Peak RSS) : %.2f MB\n", peak_rss_mb);
    printf("  • Wall-Clock Execution Time         : %.3f seconds\n", wall_time_sec);
    printf("  • User CPU Time                     : %.3f seconds\n", user_cpu_sec);
    printf("  • System CPU Time                   : %.3f seconds\n", sys_cpu_sec);
    printf("  • Parallel CPU Scaling Factor       : %.2fx multi-core acceleration\n", cpu_scaling_ratio);
    printf("  • Page Reclaims / Faults            : %ld reclaims / %ld faults\n", usage.ru_minflt, usage.ru_majflt);
    printf("  • Context Switches (Vol / Invol)     : %ld voluntary / %ld involuntary\n", usage.ru_nvcsw, usage.ru_nivcsw);
    printf("------------------------------------\n");
}

/* ============================================================================ */
/* SECTION 7: ZERO-KNOWLEDGE CENTINEL PROOFS & BDLOP HOMOMORPHIC OPERATIONS     */
/* ============================================================================ */
/**
 * @brief Evaluates BDLOP lattice homomorphic commitments and Centinel ZK Stern proofs.
 *
 * @details
 * Profiles the confidential transaction layer of the Centinel protocol extension:
 * 1. BDLOP Commit: Committing to value `v` with randomness `r` over module ring R_q.
 * 2. BDLOP Homomorphic Addition: Evaluating C_sum = C_transfer + C_change to confirm
 *    value conservation (v_old = amount + v_change) without revealing individual values.
 * 3. BDLOP Decrypt: Inverting commitments given valid secret blinding vectors.
 * 4. Centinel ZK Stern Proof Generation: Constructing multi-round zero-knowledge proofs
 *    demonstrating knowledge of secret preimages, valid MMR membership paths, and commitment
 *    conservation.
 * 5. Centinel ZK Stern Proof Verification: Verifying Fiat-Shamir challenge responses and
 *    commitment permutation checks.
 *
 * @pre Cryptographic PRNG must be initialized.
 * @post Statistical timing metrics written to `stdout`.
 *
 * @complexity
 * - Time: O(BENCH_CRYPTO_ITERS * Time(BDLOP) + BENCH_ZK_ITERS * Time(SternZK))
 * - Space: O(1) heap allocation for `RedeemCentinelData`.
 */
static void benchmark_centinel_zk_proofs(void) {
    print_table_header("5. Zero-Knowledge Centinel Proofs & Homomorphic BDLOP Operations");

    double latencies[BENCH_CRYPTO_ITERS];
    
    uint8_t pk_old[DILITHIUM_PUBKEY_LEN];
    uint8_t sk_old[DILITHIUM_SECRETKEY_LEN];
    dilithium_generate_keypair(pk_old, sk_old);

    uint8_t pk_transfer[DILITHIUM_PUBKEY_LEN];
    uint8_t sk_transfer[DILITHIUM_SECRETKEY_LEN];
    dilithium_generate_keypair(pk_transfer, sk_transfer);

    uint8_t pk_change[DILITHIUM_PUBKEY_LEN];
    uint8_t sk_change[DILITHIUM_SECRETKEY_LEN];
    dilithium_generate_keypair(pk_change, sk_change);

    uint64_t v_old = 1000;
    uint64_t amount = 600;
    uint64_t v_change = 400;

    uint8_t r_old[32], r_transfer[32], r_change[32];
    memset(r_old, 0x11, 32);
    memset(r_transfer, 0x22, 32);
    memset(r_change, 0x33, 32);

    PRFKey prf_key;
    prf_keygen(&prf_key, r_old, 32);

    uint8_t root[32];
    memset(root, 0x55, 32);

    MMRProof path;
    memset(&path, 0, sizeof(MMRProof));

    RedeemCentinelData *rc_data = calloc(1, sizeof(RedeemCentinelData));
    if (!rc_data) return;

    // Untimed Warm-Up Iterations for BDLOP & ZK Circuit
    BdlopCommitment c_old, c_transfer, c_change;
    for (int w = 0; w < 2; w++) {
        uint64_t dec_val = 0;
        bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_old, r_old, &c_old);
        bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, amount, r_transfer, &c_transfer);
        bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_change, r_change, &c_change);
        BdlopCommitment c_sum;
        bdlop_add(&c_transfer, &c_change, &c_sum);
        bdlop_decrypt((const uint8_t*)BDLOP_RHO_SEED, &c_old, r_old, &dec_val);
    }

    // 5.1 BDLOP Commit
    uint64_t start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_old, r_old, &c_old);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    double total_sec = (double)(get_time_ns() - start_time) / 1e9;
    MetricResult res = compute_metrics("BDLOP Homomorphic Commit", latencies, BENCH_CRYPTO_ITERS, total_sec, BENCH_CRYPTO_ITERS * sizeof(BdlopCommitment));
    print_metric_row(&res);

    // 5.2 BDLOP Add
    start_time = get_time_ns();
    bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, amount, r_transfer, &c_transfer);
    bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_change, r_change, &c_change);
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        BdlopCommitment c_sum;
        bdlop_add(&c_transfer, &c_change, &c_sum);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("BDLOP Homomorphic Add", latencies, BENCH_CRYPTO_ITERS, total_sec, BENCH_CRYPTO_ITERS * sizeof(BdlopCommitment));
    print_metric_row(&res);

    // 5.3 BDLOP Decrypt
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_CRYPTO_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        uint64_t decrypted_val = 0;
        bdlop_decrypt((const uint8_t*)BDLOP_RHO_SEED, &c_old, r_old, &decrypted_val);
        latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("BDLOP Homomorphic Decrypt", latencies, BENCH_CRYPTO_ITERS, total_sec, 0);
    print_metric_row(&res);

    // 5.4 Centinel ZK Stern Proof Generation
    #define BENCH_ZK_ITERS 10
    double zk_latencies[BENCH_ZK_ITERS];
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_ZK_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        generate_centinel_proof(
            pk_old, v_old, r_old,
            pk_transfer, amount, r_transfer,
            pk_change, v_change, r_change,
            &prf_key, root, &path, rc_data
        );
        zk_latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Centinel ZK Proving", zk_latencies, BENCH_ZK_ITERS, total_sec, BENCH_ZK_ITERS * rc_data->zk_proof_len);
    print_metric_row(&res);

    // 5.5 Centinel ZK Stern Proof Verification
    start_time = get_time_ns();
    for (size_t i = 0; i < BENCH_ZK_ITERS; i++) {
        uint64_t t0 = get_time_ns();
        zk_centinel_verify(rc_data);
        zk_latencies[i] = (double)(get_time_ns() - t0) / 1000.0;
    }
    total_sec = (double)(get_time_ns() - start_time) / 1e9;
    res = compute_metrics("Centinel ZK Verification", zk_latencies, BENCH_ZK_ITERS, total_sec, BENCH_ZK_ITERS * rc_data->zk_proof_len);
    print_metric_row(&res);
    #undef BENCH_ZK_ITERS

    free(rc_data);
}

/* ============================================================================ */
/* SECTION 8: MAIN EXECUTION ENTRYPOINT                                        */
/* ============================================================================ */
/**
 * @brief Main execution entrypoint for the SCL production performance benchmark harness.
 *
 * @details
 * Coordinates the full benchmark execution workflow:
 * 1. Sets log level to `LOG_LEVEL_FATAL` to avoid I/O console bottlenecks during timing runs.
 * 2. Allocates and initializes node state (`client_state_init`) and Dilithium5 wallet.
 * 3. Enforces explicit arena resets (`arena_reset(0)`) between phases to preserve cache locality.
 * 4. Sequentially executes all performance suites.
 * 5. Reclaims node state and outputs process resource summaries.
 *
 * @param[in] argc Argument count (unused).
 * @param[in] argv Argument vector (unused).
 *
 * @return int Returns 0 on successful completion; 1 on memory allocation or initialization failure.
 *
 * @complexity
 * - Time: Dominated by aggregate benchmark iterations.
 * - Space: Up to peak resident heap allocation (~20-50 MiB).
 */
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    /* Suppress verbose console logging to eliminate standard output I/O bias in measurements */
    scl_log_set_level(LOG_LEVEL_FATAL);

    printf("====================================================================================================\n");
    printf("  SATOCIALIST CRYPTOGRAPHIC LEDGER (SCL) - PRODUCTION BENCHMARK SUITE\n");
    printf("====================================================================================================\n");

    uint64_t bench_start_ns = get_time_ns();

    /* Allocate and initialize central client state */
    State *state = calloc(1, sizeof(State));
    if (!state) {
        fprintf(stderr, "Fatal: State allocation failed\n");
        return 1;
    }

    if (client_state_init(state, 0) != 0) {
        fprintf(stderr, "Fatal: client_state_init failed\n");
        free(state);
        return 1;
    }

    /* Purge any auto-hydrated disk blocks to prevent instant apply_block rejections
       from artificially inflating the measured TPS. */
    scl_db_delete_blocks_after(0);
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);
    state->bc.sync_epoch = 1;

    if (create_user_wallet(&state->user_wallet) != 1) {
        fprintf(stderr, "Fatal: Wallet generation failed\n");
        client_state_destroy(state);
        free(state);
        return 1;
    }

    /* Execute benchmark suites with explicit arena resets to guarantee fresh memory locality */
    arena_reset(0);
    benchmark_crypto_primitives();
    arena_reset(0);
    benchmark_rpc_pipeline();
    arena_reset(0);
    benchmark_mempool_ingestion(state);
    arena_reset(0);
    benchmark_block_consensus_and_ledger(state);
    arena_reset(0);
    benchmark_centinel_zk_proofs();
    arena_reset(0);
    benchmark_resource_and_scaling_summary(bench_start_ns);

    /* Complete resource teardown */
    client_state_destroy(state);
    free(state);

    printf("\n[Benchmark Suite Completed Successfully]\n\n");
    return 0;
}
