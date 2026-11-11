/**
 * @file common/utils.c
 * @brief Satocialist Protocol: Core Utilities, Telemetry, and Mathematical Operations
 *
 * @details
 * Implements foundational utility routines spanning:
 * 1. Asynchronous lock-free structured JSON telemetry and logging.
 * 2. High-precision monotonic chronometry and hardware timer abstraction.
 * 3. Exact 128-bit deterministic financial fee mathematics (formalized in Lean 4).
 * 4. Streaming single-pass block serialization and canonical hashing.
 * 5. Constant-time cryptographic memory operations and buffer zeroization.
 * 6. Lock-free mempool operation ingestion with Replace-By-Fee (RBF) logic.
 * 7. Autonomous Auto-Pilot portfolio rebalancing and valuation submission.
 * 8. Shielded Centinel UTXO balance scanning and off-chain ticket accounting.
 *
 * @section protocol_invariants Protocol Invariants
 * - Supply Conservation (Lean 4 invariants.lean: Theorems 4 & 5): Subunit quantities
 *   and fee arithmetic are bounded by MAX_TOTAL_SUBUNITS (2,560,000,000,000,000 subunits).
 * - Fee Calculation (Theorem 3.1 & 3.2): Integer fee evaluation executes in 128-bit
 *   multiplication space without numeric overflow.
 * - Monotonic Time Invariance: Network loss detection and pacing rely exclusively on
 *   non-decreasing monotonic timers (CLOCK_MONOTONIC_RAW) unaffected by NTP slewing.
 * - Constant-Time Invariants: Cryptographic memory comparisons (secure_memcmp) execute
 *   without early-exit branching or timing side-channels.
 *
 * @section concurrency_model Concurrency & Locking Architecture
 * - Telemetry queue operates via atomic head/tail indices in an MPSC ring buffer.
 * - Mempool modifications utilize atomic compare-and-swap (CAS) primitives on
 *   `state->pending_operations` array slots.
 * - Shared state mutations strictly respect the descending hierarchy:
 *   `state->mutex` -> `state->ledger_mutex` -> `state->bc.rwlock` -> `state->wallet_mutex`.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "utils.h"
#include "crypto.h"
#include "protocol.h"
#include "network.h"
#include "consensus.h"
#include "hash_table.h"
#include "queue.h"
#include "database.h"
#include "game_state.h"

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

#if defined(__linux__)
#include <sys/random.h>
#endif

#ifndef __EMSCRIPTEN__
#include "quantum_qsim.h"
#endif

/* ============================================================================ */
/* SECTION 1: GLOBAL TELEMETRY STATE & MEMORY STAGING ALLOCATORS               */
/* ============================================================================ */

/** @brief Active global log severity filter threshold. */
LogLevel current_log_level = LOG_LEVEL_INFO;

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
/** @brief Fixed ring buffer storing log entries for asynchronous worker emission. */
static LogEntry log_queue[SCL_LOG_QUEUE_SIZE];
/** @brief Atomic insertion head cursor for MPSC enqueue operations. */
static _Atomic uint32_t log_head = 0;
/** @brief Atomic extraction tail cursor for single-consumer disk flush. */
static _Atomic uint32_t log_tail = 0;
/** @brief Counter tracking telemetry events discarded due to ring saturation. */
static _Atomic uint32_t dropped_logs = 0;
/** @brief Flag indicating asynchronous worker spawn failed; triggers synchronous fallback. */
static _Atomic bool async_log_failed = false;
/** @brief Background telemetry flusher thread handle. */
static pthread_t log_thread;
/** @brief One-time pthread initializer for the logging subsystem. */
static pthread_once_t log_once = PTHREAD_ONCE_INIT;
#endif

/** @brief Global mutex serializing synchronous console output and fallback writes. */
pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @brief Thread-specific storage key binding thread-local 8 MiB scratch buffers. */
static pthread_key_t l5_staging_key;
/** @brief One-time pthread initializer for thread-specific storage key. */
static pthread_once_t l5_staging_key_once = PTHREAD_ONCE_INIT;
/** @brief Atomic counter tracking active 8 MiB thread-local scratch allocations. */
static _Atomic size_t staging_buffers_allocated = 0;

/**
 * @brief Destructor invoked upon thread termination to reclaim thread-local staging buffer.
 *
 * @param[in] ptr Raw pointer to the allocated 8 MiB buffer.
 *
 * @post Frees memory and decrements `staging_buffers_allocated` using release semantics.
 * @complexity Time: O(1), Space: O(1).
 */
static void l5_staging_destructor(void *ptr) {
    if (ptr) {
        free(ptr);
        atomic_fetch_sub_explicit(&staging_buffers_allocated, 1, memory_order_release);
    }
}

/**
 * @brief One-time constructor for the pthread thread-specific staging buffer key.
 */
static void make_l5_staging_key(void) {
    pthread_key_create(&l5_staging_key, l5_staging_destructor);
}

/**
 * @brief Acquires or reuses the calling thread's thread-local 8 MiB scratch buffer.
 *
 * @return Pointer to 8 MiB memory buffer, or NULL if allocation cap is exhausted.
 *
 * @pre None.
 * @post Allocates exactly MAX_MESSAGE_SIZE bytes on first invocation per thread.
 * @note Thread-safe via POSIX thread-specific storage. Eliminates repeated heap churn.
 * @complexity Time: O(1) amortized, Space: O(MAX_MESSAGE_SIZE) per active worker thread.
 */
uint8_t *get_l5_staging_buffer(void) {
    pthread_once(&l5_staging_key_once, make_l5_staging_key);
    uint8_t *buffer = pthread_getspecific(l5_staging_key);
    if (!buffer) {
        size_t current = atomic_load_explicit(&staging_buffers_allocated, memory_order_acquire);
        if (current >= MAX_STAGING_BUFFERS) {
            return NULL;
        }
        buffer = malloc(MAX_MESSAGE_SIZE);
        if (buffer) {
            pthread_setspecific(l5_staging_key, buffer);
            atomic_fetch_add_explicit(&staging_buffers_allocated, 1, memory_order_release);
        }
    }
    return buffer;
}

/**
 * @brief Releases the calling thread's thread-local 8 MiB scratch buffer immediately.
 *
 * @post Buffer memory freed and thread-specific pointer reset to NULL.
 * @complexity Time: O(1), Space: O(1).
 */
void release_l5_staging_buffer(void) {
    pthread_once(&l5_staging_key_once, make_l5_staging_key);
    uint8_t *buffer = pthread_getspecific(l5_staging_key);
    if (buffer) {
        free(buffer);
        pthread_setspecific(l5_staging_key, NULL);
        atomic_fetch_sub_explicit(&staging_buffers_allocated, 1, memory_order_release);
    }
}

/**
 * @brief Inspects physical socket options to determine Path MTU for IP fragmentation avoidance.
 *
 * @param[in] fd Bound UDP socket file descriptor.
 * @param[in] addr Remote destination address context.
 * @return Discovered Path MTU in octets (defaults to SCL_LINK_MTU - 48 = 1,232 bytes).
 *
 * @complexity Time: O(1), Space: O(1).
 */
size_t scl_get_path_mtu(int fd, const struct sockaddr_storage *addr) {
    (void)fd;
    (void)addr;
#if defined(__linux__) && defined(IP_MTU)
    int mtu = 0;
    socklen_t len = sizeof(mtu);
    if (addr && addr->ss_family == AF_INET6) {
#ifdef IPV6_MTU
        if (getsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &mtu, &len) == 0 && mtu > 0) {
            return (size_t)mtu;
        }
#endif
    } else {
        if (getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu, &len) == 0 && mtu > 0) {
            return (size_t)mtu;
        }
    }
#endif
    return SCL_LINK_MTU - 48; // Baseline: 1280 byte MTU minus 40 byte IPv6 header and 8 byte UDP header
}

/**
 * @brief Updates the minimum severity threshold for log emission.
 *
 * @param[in] level New minimum severity tier.
 */
void scl_log_set_level(LogLevel level) {
    current_log_level = level;
}

/**
 * @brief Formats and dispatches a diagnostic log message to stderr with heuristic severity classification.
 *
 * @param[in] component Subsystem tag identifying source of the diagnostic message.
 * @param[in] format Printf-style format string.
 * @param[in] ... Variadic argument list.
 *
 * @complexity Time: O(K) where K is formatted byte length, Space: O(1) stack buffer.
 */
void scl_log_stderr(const char *component, const char *format, ...) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)component; (void)format;
    return;
#else
    va_list args;
    va_start(args, format);
    char buf[2048];
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    // Heuristically map message content to standard severity tiers
    LogLevel level = LOG_LEVEL_INFO;
    if (strstr(buf, "ERROR") || strstr(buf, "Error") || strstr(buf, "failed") || strstr(buf, "Failed") || strstr(buf, "mismatch") || strstr(buf, "Invalid") || strstr(buf, "invalid") || strstr(buf, "corruption") || strstr(buf, "saturation")) {
        level = LOG_LEVEL_ERROR;
    } else if (strstr(buf, "WARNING") || strstr(buf, "Warning") || strstr(buf, "warn") || strstr(buf, "Warn")) {
        level = LOG_LEVEL_WARN;
    } else if (strstr(buf, "DEBUG") || strstr(buf, "debug") || strstr(buf, "trace") || strstr(buf, "processed") || strstr(buf, "done") || strstr(buf, "applied") || strstr(buf, "Applied")) {
        level = LOG_LEVEL_DEBUG;
    }
    
    scl_log(level, component, "%s", buf);
#endif
}

/**
 * @brief Maps numerical LogLevel enum value to its canonical uppercase ASCII string representation.
 *
 * @param[in] level Log severity tier.
 * @return Constant string literal pointer.
 */
const char* level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_TRACE: return SCL_CLR_GRAY "TRACE" SCL_CLR_RESET;
        case LOG_LEVEL_DEBUG: return SCL_CLR_CYAN "DEBUG" SCL_CLR_RESET;
        case LOG_LEVEL_INFO: return SCL_CLR_GREEN "INFO" SCL_CLR_RESET;
        case LOG_LEVEL_WARN: return SCL_CLR_YELLOW "WARN" SCL_CLR_RESET;
        case LOG_LEVEL_ERROR: return SCL_CLR_RED "ERROR" SCL_CLR_RESET;
        case LOG_LEVEL_FATAL: return SCL_CLR_BRIGHT_RED SCL_CLR_BOLD "FATAL" SCL_CLR_RESET;
        default: return "UNKNOWN";
    }
}

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
/**
 * @brief Dedicated background worker daemon consuming staged records from the telemetry ring buffer.
 *
 * @param[in] arg Unused thread argument pointer.
 * @return NULL upon thread completion.
 *
 * @complexity Time: O(queued messages), Space: O(1).
 */
static void* async_log_worker(void* arg) {
    (void)arg;
    while (!atomic_load(&global_shutdown)) {
        uint32_t tail = atomic_load_explicit(&log_tail, memory_order_acquire);
        uint32_t head = atomic_load_explicit(&log_head, memory_order_acquire);
        
        if (tail != head) {
            // Spin-wait briefly if producer has reserved index but has not completed memcpy
            if (!atomic_load_explicit(&log_queue[tail].ready, memory_order_acquire)) {
                usleep(100);
                continue;
            }

            uint32_t dropped = atomic_exchange_explicit(&dropped_logs, 0, memory_order_relaxed);
            FILE *stream = log_queue[tail].stream;
            
            if (stream) {
                pthread_mutex_lock(&output_mutex);
                if (dropped > 0) {
                    fprintf(stream, "{\"timestamp\": %llu, \"level\": \"WARN\", \"component\": \"Telemetry\", \"message\": \"%u telemetry events dropped due to async ring saturation\"}\n", (unsigned long long)get_time_ms(), dropped);
                }
                fputs(log_queue[tail].msg, stream);
                fflush(stream);
                pthread_mutex_unlock(&output_mutex);
            }
            
            atomic_store_explicit(&log_queue[tail].ready, false, memory_order_release);
            atomic_store_explicit(&log_tail, (tail + 1) % SCL_LOG_QUEUE_SIZE, memory_order_release);
        } else {
            usleep(10000); // Sleep 10ms during idle periods to prevent unnecessary wakeups
        }
    }
    
    // Drain remaining logs upon protocol shutdown
    uint32_t tail = atomic_load_explicit(&log_tail, memory_order_acquire);
    uint32_t head = atomic_load_explicit(&log_head, memory_order_acquire);
    while (tail != head) {
        if (atomic_load_explicit(&log_queue[tail].ready, memory_order_acquire)) {
            FILE *stream = log_queue[tail].stream;
            if (stream) {
                pthread_mutex_lock(&output_mutex);
                fputs(log_queue[tail].msg, stream);
                fflush(stream);
                pthread_mutex_unlock(&output_mutex);
            }
            atomic_store_explicit(&log_queue[tail].ready, false, memory_order_release);
        }
        tail = (tail + 1) % SCL_LOG_QUEUE_SIZE;
    }
    return NULL;
}

/**
 * @brief Initializes the asynchronous logging daemon thread.
 */
static void init_async_logger(void) {
    if (pthread_create(&log_thread, NULL, async_log_worker, NULL) != 0) {
        atomic_store_explicit(&async_log_failed, true, memory_order_release);
        return;
    }
    pthread_detach(log_thread);
}
#endif

/**
 * @brief Dispatches a structured, JSON-formatted telemetry entry to the asynchronous log queue.
 *
 * @param[in] level Severity tier of the log event.
 * @param[in] component Formal subsystem identifier emitting the log.
 * @param[in] format Printf-style format string.
 * @param[in] ... Variadic argument list matching format specifiers.
 *
 * @complexity Time: O(K) where K is formatted length, Space: O(1) stack buffer.
 */
void scl_log(LogLevel level, const char *component, const char *format, ...) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)level; (void)component; (void)format;
    return;
#else
    if (level < current_log_level) return;
    
    pthread_once(&log_once, init_async_logger);
    
    int sync_mode = atomic_load_explicit(&async_log_failed, memory_order_acquire);
    
    va_list args;
    va_start(args, format);
    char payload[2048];
    vsnprintf(payload, sizeof(payload), format, args);
    va_end(args);
    
    size_t payload_len = strlen(payload);
    while (payload_len > 0 && (payload[payload_len - 1] == '\n' || payload[payload_len - 1] == '\r')) {
        payload[--payload_len] = '\0';
    }

    // Escape control characters to ensure strict JSON schema compliance
    char escaped_payload[850];
    size_t j = 0;
    bool truncated = false;
    for (size_t i = 0; payload[i] != '\0'; i++) {
        if (j >= sizeof(escaped_payload) - 22) {
            truncated = true;
            break;
        }
        if (payload[i] == '"' || payload[i] == '\\') {
            escaped_payload[j++] = '\\';
            escaped_payload[j++] = payload[i];
        } else if (payload[i] == '\n') {
            escaped_payload[j++] = '\\';
            escaped_payload[j++] = 'n';
        } else if (payload[i] == '\r') {
            escaped_payload[j++] = '\\';
            escaped_payload[j++] = 'r';
        } else if (payload[i] == '\t') {
            escaped_payload[j++] = '\\';
            escaped_payload[j++] = 't';
        } else if ((unsigned char)payload[i] == '\x1b') {
            escaped_payload[j++] = payload[i];
        } else if ((unsigned char)payload[i] < 32) {
            j += snprintf(escaped_payload + j, 7, "\\u%04x", (unsigned char)payload[i]);
        } else {
            escaped_payload[j++] = payload[i];
        }
    }
    if (truncated) {
        strcpy(escaped_payload + j, "... [truncated]");
        j += 15;
    }
    escaped_payload[j] = '\0';

    uint64_t timestamp = get_time_ms();
    char colored_component[128];
    if (strchr(component, '\x1b') != NULL) {
        snprintf(colored_component, sizeof(colored_component), "%s", component);
    } else {
        snprintf(colored_component, sizeof(colored_component), SCL_CLR_BOLD SCL_CLR_BLUE "%s" SCL_CLR_RESET, component);
    }

    char json_msg[1024];
    snprintf(json_msg, sizeof(json_msg),
             "{\"timestamp\": %llu, \"level\": \"%s\", \"component\": \"%s\", \"message\": \"%s\"}\n",
             (unsigned long long)timestamp, level_to_string(level), colored_component, escaped_payload);

    FILE *target_stream = (level >= LOG_LEVEL_ERROR) ? stderr : stdout;

    if (sync_mode) {
        pthread_mutex_lock(&output_mutex);
        fprintf(target_stream, "%s", json_msg);
        fflush(target_stream);
        pthread_mutex_unlock(&output_mutex);
        return;
    }
    
    // MPSC lock-free reservation on the circular log queue
    uint32_t head, next_head, tail;
    do {
        head = atomic_load_explicit(&log_head, memory_order_acquire);
        next_head = (head + 1) % SCL_LOG_QUEUE_SIZE;
        tail = atomic_load_explicit(&log_tail, memory_order_acquire);
        
        if (next_head == tail) {
            atomic_fetch_add_explicit(&dropped_logs, 1, memory_order_relaxed);
            return;
        }
    } while (!atomic_compare_exchange_weak_explicit(&log_head, &head, next_head, memory_order_release, memory_order_relaxed));
    
    strncpy(log_queue[head].msg, json_msg, sizeof(log_queue[head].msg) - 1);
    log_queue[head].msg[sizeof(log_queue[head].msg) - 1] = '\0';
    log_queue[head].stream = target_stream;
    atomic_store_explicit(&log_queue[head].ready, true, memory_order_release);
#endif
}

/**
 * @brief Blocks calling thread synchronously until all staged asynchronous log queue entries flush.
 *
 * @post `log_tail` matches `log_head`.
 * @complexity Time: O(N) where N is queued entries, Space: O(1).
 */
void scl_log_flush(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    return;
#else
    uint64_t start_ms = get_time_ms();
    while (atomic_load_explicit(&log_tail, memory_order_acquire) != atomic_load_explicit(&log_head, memory_order_acquire)) {
        if (get_time_ms() - start_ms > 2000) {
            break;
        }
        usleep(1000);
    }
#endif
}

/**
 * @brief Enqueues a formatted string asynchronously to a specific output stream.
 *
 * @param[in,out] stream Target destination file stream.
 * @param[in] format Printf format string.
 * @param[in] ... Variadic argument list.
 *
 * @complexity Time: O(K), Space: O(1).
 */
void scl_fprintf(FILE *stream, const char *format, ...) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)stream; (void)format;
    return;
#else
    if (current_log_level == LOG_LEVEL_FATAL) return;

    pthread_once(&log_once, init_async_logger);
    
    va_list args;
    va_start(args, format);
    
    // Non-standard streams bypass the ring queue and write directly
    if (stream != stderr && stream != stdout) {
        vfprintf(stream, format, args);
        va_end(args);
        return;
    }
    
    if (atomic_load_explicit(&async_log_failed, memory_order_acquire)) {
        pthread_mutex_lock(&output_mutex);
        vfprintf(stream, format, args);
        fflush(stream);
        pthread_mutex_unlock(&output_mutex);
        va_end(args);
        return;
    }
    
    uint32_t head, next_head, tail;
    do {
        head = atomic_load_explicit(&log_head, memory_order_acquire);
        next_head = (head + 1) % SCL_LOG_QUEUE_SIZE;
        tail = atomic_load_explicit(&log_tail, memory_order_acquire);
        
        if (next_head == tail) {
            atomic_fetch_add_explicit(&dropped_logs, 1, memory_order_relaxed);
            va_end(args);
            return;
        }
    } while (!atomic_compare_exchange_weak_explicit(&log_head, &head, next_head, memory_order_release, memory_order_relaxed));
    
    va_list args_copy;
    va_copy(args_copy, args);
    vsnprintf(log_queue[head].msg, sizeof(log_queue[head].msg), format, args_copy);
    va_end(args_copy);
    
    log_queue[head].stream = stream;
    atomic_store_explicit(&log_queue[head].ready, true, memory_order_release);
    va_end(args);
#endif
}

/**
 * @brief Enqueues a formatted string asynchronously to stdout.
 *
 * @param[in] format Printf format string.
 * @param[in] ... Variadic argument list.
 *
 * @complexity Time: O(K), Space: O(1).
 */
void scl_printf(const char *format, ...) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)format;
    return;
#else
    if (current_log_level == LOG_LEVEL_FATAL) return;

    pthread_once(&log_once, init_async_logger);
    
    va_list args;
    va_start(args, format);
    
    if (atomic_load_explicit(&async_log_failed, memory_order_acquire)) {
        pthread_mutex_lock(&output_mutex);
        vfprintf(stdout, format, args);
        fflush(stdout);
        pthread_mutex_unlock(&output_mutex);
        va_end(args);
        return;
    }
    
    uint32_t head, next_head, tail;
    do {
        head = atomic_load_explicit(&log_head, memory_order_acquire);
        next_head = (head + 1) % SCL_LOG_QUEUE_SIZE;
        tail = atomic_load_explicit(&log_tail, memory_order_acquire);
        
        if (next_head == tail) {
            pthread_mutex_lock(&output_mutex);
            vfprintf(stdout, format, args);
            fflush(stdout);
            pthread_mutex_unlock(&output_mutex);
            va_end(args);
            return;
        }
    } while (!atomic_compare_exchange_weak_explicit(&log_head, &head, next_head, memory_order_release, memory_order_relaxed));
    
    va_list args_copy;
    va_copy(args_copy, args);
    vsnprintf(log_queue[head].msg, sizeof(log_queue[head].msg), format, args_copy);
    va_end(args_copy);
    
    log_queue[head].stream = stdout;
    atomic_store_explicit(&log_queue[head].ready, true, memory_order_release);
    va_end(args);
#endif
}

/* ============================================================================ */
/* SECTION 2: HIGH-RESOLUTION CHRONOMETRY & TIMERS                             */
/* ============================================================================ */

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Reads the hardware monotonic clock in microseconds, bypassing NTP slewing.
 *
 * @return Monotonic microseconds since boot anchor.
 * @complexity Time: O(1) hardware register read, Space: O(1).
 */
static uint64_t get_raw_monotonic_us(void) {
#if defined(_WIN32)
    LARGE_INTEGER frequency;
    LARGE_INTEGER count;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&count);
    return (uint64_t)((count.QuadPart * 1000000ULL) / frequency.QuadPart);
#elif defined(__APPLE__)
    static mach_timebase_info_data_t timebase = {0, 0};
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    uint64_t time = mach_absolute_time();
    return (time * timebase.numer / timebase.denom) / 1000ULL;
#else
    struct timespec ts;
    // Enforce CLOCK_MONOTONIC_RAW to guarantee immunity against NTP slewing perturbations
#ifdef __linux__
    #ifndef CLOCK_MONOTONIC_RAW
        #define CLOCK_MONOTONIC_RAW 4
    #endif
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (uint64_t)(ts.tv_sec) * 1000000ULL + (ts.tv_nsec / 1000ULL);
    }
#elif defined(CLOCK_MONOTONIC_RAW)
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (uint64_t)(ts.tv_sec) * 1000000ULL + (ts.tv_nsec / 1000ULL);
    }
#endif
    
    // Fallback to standard monotonic timer if RAW is unsupported
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)(ts.tv_sec) * 1000000ULL + (ts.tv_nsec / 1000ULL);
    }
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000000ULL + tv.tv_usec;
#endif
}
#endif

/**
 * @brief Returns strictly non-decreasing monotonic time in microseconds.
 *
 * @return Microseconds elapsed on monotonic clock.
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t get_time_us(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    static _Thread_local uint64_t fuzz_time_us = 1000000;
    return (fuzz_time_us += 10);
#else
    return get_raw_monotonic_us();
#endif
}

/**
 * @brief Returns system wall-clock time in microseconds since UNIX epoch (1970-01-01 UTC).
 *
 * @return Microseconds since UNIX epoch.
 * @note Subject to discontinuous NTP wall-clock adjustments. Used for transaction timestamps.
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t get_real_time_us(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    static _Thread_local uint64_t fuzz_real_time_us = 1600000000000000ULL;
    return (fuzz_real_time_us += 10);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (uint64_t)(ts.tv_sec) * 1000000ULL + (ts.tv_nsec / 1000ULL);
    }
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0) {
        return (uint64_t)(tv.tv_sec) * 1000000ULL + tv.tv_usec;
    }
    return 0;
#endif
}

/**
 * @brief Returns monotonic clock time converted to integer milliseconds.
 *
 * @return Milliseconds elapsed (`get_time_us() / 1000`).
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t get_time_ms(void) {
    return get_time_us() / 1000ULL;
}

/* ============================================================================ */
/* SECTION 3: SUBMISSION QUEUING & DETERMINISTIC FEE ARITHMETIC                 */
/* ============================================================================ */

/**
 * @brief Enqueues a validated transaction or valuation proposal to the local submission queue.
 *
 * @param[in,out] state Global node state container.
 * @param[in] msg Network message containing operation payload.
 * @return 0 on success; -1 on validation or enqueue failure.
 *
 * @pre `msg->type` must be MSG_PENDING_OPERATION or MSG_VALUATION_PROPOSAL.
 * @post Wakes a sleeping worker thread via `pthread_cond_signal(&state->submission_cond)`.
 * @complexity Time: O(1), Space: O(msg->length) heap allocation.
 */
int enqueue_submission(State *state, const Message *msg) {
    if (!state || !msg || (msg->type != MSG_PENDING_OPERATION && msg->type != MSG_VALUATION_PROPOSAL) || msg->length == 0) {
        fprintf(stderr, "[EnqueueSubmission] Invalid parameters or message\n");
        return -1;
    }
    int result = queue_enqueue(&state->submission_queue, msg);
    
    // Instantly wake sleeping submission worker thread
    if (result == 0) {
        pthread_mutex_lock(&state->submission_mutex);
        pthread_cond_signal(&state->submission_cond);
        pthread_mutex_unlock(&state->submission_mutex);
    }
    
    return result;
}

/**
 * @brief Deterministically computes required transaction fee in atomic subunits using 128-bit math.
 *
 * @details
 * Formally verified in Lean 4 (`Satocialist.calculateFee`).
 * Fixed-point arithmetic approximation of Pi/100:
 * - Rate: 3,141,592,653,589,793 / 10^17 (~3.14159265%) for normal peer-to-peer transfers.
 * - Staking / Unstaking: Denominator doubled to 2 * 10^17 (~1.57079632%).
 * Multiplications strictly fit within unsigned 128-bit space (< 2^128) without overflow
 * for any `amount <= MAX_TOTAL_SUBUNITS` (Theorem 3.1).
 *
 * @param[in] amount Asset volume in atomic subunits.
 * @param[in] halve Flag: `true` for 50% fee rate (staking/unstaking); `false` standard rate.
 * @return Exact required non-refundable transaction fee in subunits.
 *
 * @complexity Time: O(1) integer arithmetic, Space: O(1).
 */
uint64_t calculate_fee(uint64_t amount, bool halve) {
    unsigned __int128 numerator = 3141592653589793ULL;
    unsigned __int128 denominator = 100000000000000000ULL;
    
    if (halve) {
        denominator *= 2;
    }
    
    return (uint64_t)(((unsigned __int128)amount * numerator) / denominator);
}

/* ============================================================================ */
/* SECTION 4: COMPARATORS, SORTING & CONSTANT-TIME MEMORY UTILITIES             */
/* ============================================================================ */

/**
 * @brief Resolves canonical 32-byte unique identifier pointer for an on-chain operation.
 *
 * @param[in] op Operation container.
 * @return 32-byte identifier buffer pointer; NULL for unmapped types.
 * @complexity Time: O(1), Space: O(1).
 */
const uint8_t* get_operation_tx_id(const Operation *op) {
    switch (op->type) {
        case OP_CLAIM_VALIDATION:
            // BDLOP c1 polynomial slice serves as immutable claim identifier
            return op->data.claim_validation.commitment.c1;
        case OP_REDEEM_CENTINEL:
            // ZK-PRF nullifier guarantees unique, unforgeable transaction identity
            return op->data.redeem_centinel.nullifier;
        case OP_TRANSFER_POINTER:
            return op->data.transfer_pointer.tx_id;
        case OP_STAKE:
            return op->data.stake.stake_tx_id;
        case OP_UNSTAKE:
            return op->data.unstake.unstake_tx_id;
        case OP_MINT_COIN:
            return op->data.mint_coin.coin.creation_tx_hash;
        case OP_APPLY_DRIFT_CERT:
            return op->data.apply_drift_cert.cert_tx_id;
        default:
            return NULL;
    }
}

/**
 * @brief Sorts Pointer structures descending by subunit capacity (`end - start + 1`).
 *
 * @param[in] a Pointer to first Pointer reference.
 * @param[in] b Pointer to second Pointer reference.
 * @return Negative if a > b (larger first), positive if a < b, 0 if equal.
 * @complexity Time: O(1), Space: O(1).
 */
int compare_pointers_desc(const void *a, const void *b) {
    const Pointer *pa = *(const Pointer **)a;
    const Pointer *pb = *(const Pointer **)b;
    uint64_t subunits_a = pa->end_subunit - pa->start_subunit + 1;
    uint64_t subunits_b = pb->end_subunit - pb->start_subunit + 1;
    return (subunits_b > subunits_a) - (subunits_b < subunits_a);
}

/**
 * @brief Sorts Peer structures lexicographically by Dilithium public verification keys.
 *
 * @param[in] a Pointer to first Peer reference.
 * @param[in] b Pointer to second Peer reference.
 * @return memcmp result across 2,592-byte Dilithium5 public keys.
 * @complexity Time: O(DILITHIUM_PUBKEY_LEN), Space: O(1).
 */
int compare_peers(const void *a, const void *b) {
    const Peer *pa = *(const Peer **)a;
    const Peer *pb = *(const Peer **)b;
    return memcmp(pa->peer_wallet.dilithium_pubkey, pb->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
}

/**
 * @brief Sorts public key pointers lexicographically via memcmp.
 *
 * @param[in] a Pointer to first `const uint8_t*`.
 * @param[in] b Pointer to second `const uint8_t*`.
 * @return memcmp result across PUBKEY_LEN bytes.
 * @complexity Time: O(PUBKEY_LEN), Space: O(1).
 */
int compare_pubkey_ptrs(const void *a, const void *b) {
    return memcmp(*(const uint8_t **)a, *(const uint8_t **)b, PUBKEY_LEN);
}

/**
 * @brief Sorts Operation pointers deterministically by transaction ID.
 *
 * @param[in] a Pointer to first `const Operation*`.
 * @param[in] b Pointer to second `const Operation*`.
 * @return Lexicographical comparison result across 32-byte transaction IDs.
 * @complexity Time: O(COIN_ID_LEN), Space: O(1).
 */
int compare_operation_ptrs(const void *a, const void *b) {
    const Operation *op_a = *(const Operation **)a;
    const Operation *op_b = *(const Operation **)b;
    const uint8_t *id_a = get_operation_tx_id(op_a);
    const uint8_t *id_b = get_operation_tx_id(op_b);
    if (id_a && id_b) return memcmp(id_a, id_b, COIN_ID_LEN);
    if (id_a) return -1;
    if (id_b) return 1;
    return 0;
}

/**
 * @brief Comparator enforcing deterministic consensus block packaging order.
 *
 * @details
 * Invariant: Coinbase Mint operations (OP_MINT_COIN) are strictly placed at the head
 * of the block. Subsequent operations sort lexicographically by their 32-byte transaction ID.
 *
 * @param[in] a Pointer to first Operation structure.
 * @param[in] b Pointer to second Operation structure.
 * @return Negative if a precedes b, positive if b precedes a.
 * @complexity Time: O(COIN_ID_LEN), Space: O(1).
 */
int compare_operations(const void *a, const void *b) {
    const Operation *op_a = (const Operation *)a;
    const Operation *op_b = (const Operation *)b;

    // 1. Force Coinbase Mint operations to block head
    if (op_a->type == OP_MINT_COIN && op_b->type != OP_MINT_COIN) return -1;
    if (op_a->type != OP_MINT_COIN && op_b->type == OP_MINT_COIN) return 1;

    const uint8_t *id_a = get_operation_tx_id(op_a);
    const uint8_t *id_b = get_operation_tx_id(op_b);

    if (id_a && id_b) {
        return memcmp(id_a, id_b, COIN_ID_LEN);
    }
    
    if (id_a) return -1;
    if (id_b) return 1;
    return 0;
}

/**
 * @brief Converts a binary byte slice into lowercase hexadecimal string with null-terminator.
 *
 * @param[in] data Binary source buffer.
 * @param[in] len Length in bytes to format.
 * @param[out] out_buffer Destination buffer; must allocate at least (len * 2) + 1 bytes.
 * @complexity Time: O(len), Space: O(1) auxiliary.
 */
void bytes_to_hex(const uint8_t *data, size_t len, char *out_buffer) {
    char *p = out_buffer;
    for (size_t i = 0; i < len; i++) {
        p += snprintf(p, 3, "%02x", data[i]);
    }
    *p = '\0';
}

/**
 * @brief Constant-time cryptographic memory comparison resistant to timing analysis.
 *
 * @param[in] a Pointer to first memory buffer.
 * @param[in] b Pointer to second memory buffer.
 * @param[in] len Comparison byte length.
 * @return 0 if buffers are identical across all bytes; 1 if any bit diverges.
 *
 * @note Implemented using branchless bitwise accumulator to prevent microarchitectural branching leaks.
 * @complexity Time: O(len) strictly constant-time, Space: O(1).
 */
int secure_memcmp(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint32_t res = 0;

    for (size_t i = 0; i < len; i++) {
        res |= pa[i] ^ pb[i];
    }

    // Branchless conversion: evaluates strictly to 0 on match or 1 on divergence
    return (int)((res | (uint32_t)-(int32_t)res) >> 31);
}

/**
 * @brief Evaluates whether a memory buffer is filled entirely with zero bytes.
 *
 * @param[in] buf Pointer to buffer.
 * @param[in] len Byte count to verify.
 * @return `true` if all bytes are zero; `false` otherwise.
 * @complexity Time: O(len), Space: O(1).
 */
bool is_zeroed(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return false;
    }
    return true;
}

/**
 * @brief Overwrites memory with zeros using a compiler optimization barrier.
 *
 * @param[in,out] s Target buffer pointer.
 * @param[in] n Byte count to clear.
 * @post Guaranteed not to be omitted by dead-store compiler elimination passes.
 * @complexity Time: O(n), Space: O(1).
 */
void explicit_bzero(void *s, size_t n) {
#if defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(s, n);
#else
    volatile unsigned char *p = (volatile unsigned char *)s;
    while (n--) *p++ = 0;
#endif
}

/**
 * @brief Computes single-shot SHA-256 digest of an input byte stream via OpenSSL EVP.
 *
 * @param[in] input Source data pointer.
 * @param[in] in_len Length of source data in bytes.
 * @param[out] output 32-byte destination receiving SHA-256 digest.
 * @complexity Time: O(in_len), Space: O(1).
 */
void sha256_hash(const uint8_t *input, size_t in_len, uint8_t *output) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    SHA256(input, in_len, output);
    return;
#endif
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, in_len);
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);
}

/**
 * @brief Derives a high-resolution temporary transaction identifier from nonce and monotonic time.
 *
 * @param[in] nonce 8-byte salt.
 * @param[out] temp_tx_id 32-byte destination buffer receiving SHA256(nonce || microsecond_timestamp_be).
 * @complexity Time: O(1), Space: O(1).
 */
void compute_temp_tx_id(const uint8_t nonce[8], uint8_t temp_tx_id[COIN_ID_LEN]) {
    uint8_t temp_input[16];
    memcpy(temp_input, nonce, 8);
    uint64_t now_us = get_time_us();
    uint64_t now_be = htobe64(now_us);
    memcpy(temp_input + 8, &now_be, 8);
    SHA256(temp_input, 16, temp_tx_id);
}

/* ============================================================================ */
/* SECTION 5: BLOCK SERIALIZATION, HASHING & MERKLE CALCULATIONS               */
/* ============================================================================ */

/**
 * @brief Unified streaming block serializer and cryptographic digest generator.
 *
 * @details
 * Sequentially serializes block header, operations, batch ZK-PRF nullifiers, proofs,
 * and proposer keys into `out_buf` (if non-NULL) while simultaneously updating an
 * OpenSSL SHA-256 digest context `ctx` (if non-NULL). Guarantees exact binary identity
 * between serialization layout and hashing without redundant buffer copies.
 *
 * @param[in] block Block structure to process.
 * @param[out] out_buf Destination serialization buffer (or NULL for hashing-only mode).
 * @param[in,out] ctx OpenSSL SHA-256 context (or NULL for serialization-only mode).
 * @param[in] include_signature Flag: `true` appends consensus signatures; `false` computes pre-sign digest.
 * @return Total bytes processed on success; -1 on serialization error.
 *
 * @complexity Time: O(N) where N is block byte footprint, Space: O(1) auxiliary.
 */
int process_block_data(const Block *block, uint8_t *out_buf, EVP_MD_CTX *ctx, bool include_signature) {
    size_t offset = 0;
    
    // Routing macro dispatching to both hashing context and wire output buffer
    #define EMIT_DATA(src, len) do { \
        if (ctx) EVP_DigestUpdate(ctx, (src), (len)); \
        if (out_buf) memcpy(out_buf + offset, (src), (len)); \
        offset += (len); \
    } while(0)

    // 1. Block Number (uint64, big-endian)
    uint64_t block_number_be = htobe64(block->block_number);
    EMIT_DATA(&block_number_be, sizeof(uint64_t));

    // 2. Previous Block Hash (32 bytes)
    EMIT_DATA(block->prev_block_hash, COIN_ID_LEN);

    // 3. Operation Count (uint64, big-endian)
    uint64_t operation_count_be = htobe64(block->operation_count);
    EMIT_DATA(&operation_count_be, sizeof(uint64_t));

    // 4. Sequential Operations Array
    for (size_t i = 0; i < block->operation_count; i++) {
        if (block->operations[i].type == OP_TRANSFER_POINTER) {
            // Specialized compact serialization for on-chain transfer pointers
            const TransferData *tx = &block->operations[i].data.transfer_pointer;
            uint8_t op_type = (uint8_t)OP_TRANSFER_POINTER;
            EMIT_DATA(&op_type, 1);
            EMIT_DATA(tx->tx_id, COIN_ID_LEN);
            EMIT_DATA(tx->nonce, 8);
            uint32_t num_inputs_be = htobe32(tx->num_inputs);
            EMIT_DATA(&num_inputs_be, sizeof(uint32_t));
            EMIT_DATA(tx->client_root, COIN_ID_LEN);

            for (size_t j = 0; j < tx->num_inputs; j++) {
                uint8_t ptr_buf[sizeof(Pointer)];
                serialize_pointer(&tx->inputs[j], ptr_buf);
                EMIT_DATA(ptr_buf, sizeof(Pointer));
                
                uint8_t proof_buf[8192];
                size_t proof_size = serialize_mmr_proof(&tx->proofs[j], proof_buf, sizeof(proof_buf));
                if (proof_size > 0) {
                    EMIT_DATA(proof_buf, proof_size);
                }
            }

            EMIT_DATA(tx->recipient_pubkey, PUBKEY_LEN);
            EMIT_DATA(tx->sender_pubkey, PUBKEY_LEN);
            uint64_t amount_be = htobe64(tx->amount);
            EMIT_DATA(&amount_be, sizeof(uint64_t));
            EMIT_DATA(tx->signature, SIGNATURE_LEN);
            EMIT_DATA(tx->inputs_merkle_root, COIN_ID_LEN);
            EMIT_DATA(tx->inputs_root_signature, SIGNATURE_LEN);
        } else {
            // Generic serialization for Mint, Stake, Unstake, Valuation, and Centinel operations
            uint8_t *target_buf = out_buf ? (out_buf + offset) : NULL;
            size_t temp_mark = 0;
            
            size_t pass_size = 0;
            if (!out_buf) {
                temp_mark = arena_mark();
                size_t required_size = 15000;
                Operation *op = &block->operations[i];
                if (op->type == OP_STAKE) {
                    required_size += op->data.stake.num_inputs * 8000;
                } else if (op->type == OP_UNSTAKE) {
                    required_size += op->data.unstake.num_inputs * 8000;
                } else if (op->type == OP_MINT_COIN) {
                    required_size += 55000;
                }
                            
                target_buf = arena_alloc(required_size);
                if (!target_buf) {
                    arena_reset(temp_mark);
                    return -1;
                }
                pass_size = required_size;
            } else {
                pass_size = MAX_MESSAGE_SIZE - offset;
            }

            int bytes_written = serialize_operation(&block->operations[i], target_buf, pass_size);
            if (bytes_written <= 0) {
                if (!out_buf) arena_reset(temp_mark);
                return -1;
            }
                    
            if (ctx) EVP_DigestUpdate(ctx, target_buf, bytes_written);
            offset += bytes_written;
            
            if (!out_buf) arena_reset(temp_mark);
        }
    }

    // 5. Entropy Seed (uint64, big-endian)
    uint64_t entropy_seed_be = htobe64(block->entropy_seed);
    EMIT_DATA(&entropy_seed_be, sizeof(uint64_t));

    // 6. Batch Transfer Transaction Count (uint64, big-endian)
    uint64_t batch_tx_count_be = htobe64(block->batch_tx_count);
    EMIT_DATA(&batch_tx_count_be, sizeof(uint64_t));

    // 7. Aggregated PRF Nullifiers (32 bytes * batch_tx_count)
    if (block->batch_tx_count > 0 && block->batch_prf_outputs) {
        EMIT_DATA(block->batch_prf_outputs, block->batch_tx_count * NULLIFIER_LEN);
    }

    // 8. Aggregated ZK-PRF Batch Proof Byte Length (uint64, big-endian)
    uint64_t batch_zk_proof_len_be = htobe64(block->batch_zk_proof_len);
    EMIT_DATA(&batch_zk_proof_len_be, sizeof(uint64_t));

    // 9. Aggregated ZK-PRF Batch Proof Body
    if (block->batch_zk_proof_len > 0 && block->batch_zk_proof) {
        EMIT_DATA(block->batch_zk_proof, block->batch_zk_proof_len);
    }

    // 10. Proposer Dilithium5 Public Key (2,592 bytes)
    EMIT_DATA(block->proposer_pubkey, PUBKEY_LEN);

    // 11. Optional Signatures (included in finalized blocks; omitted in proposal hashes)
    if (include_signature) {
        EMIT_DATA(block->signature, SIGNATURE_LEN);
        EMIT_DATA(block->epoch_threshold_signature, SIGNATURE_LEN);
    }

    #undef EMIT_DATA
    return offset;
}

/**
 * @brief Evaluates canonical SHA-256 header hash of a block (excluding signatures).
 *
 * @param[in] block Block structure to evaluate.
 * @param[out] hash 32-byte destination receiving block hash digest.
 * @return 0 on success; -1 on failure.
 * @complexity Time: O(N) where N is block size, Space: O(1).
 */
int compute_block_hash(const Block *block, uint8_t *hash) {
    if (!block || !hash) return -1;

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    static _Thread_local EVP_MD_CTX *fuzz_ctx = NULL;
    if (!fuzz_ctx) fuzz_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(fuzz_ctx, EVP_sha256(), NULL);
    process_block_data(block, NULL, fuzz_ctx, false);
    EVP_DigestFinal_ex(fuzz_ctx, hash, NULL);
    return 0;
#endif

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (process_block_data(block, NULL, ctx, false) < 0) {
        scl_log(LOG_LEVEL_ERROR, "Protocol", "compute_block_hash: Failed to stream block data");
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    return 0;
}

/**
 * @brief Computes binary Merkle tree root over transaction input pointer signing hashes.
 *
 * @param[in] inputs Array of Pointer structures.
 * @param[in] num_inputs Active input count (clamped to MAX_INPUTS).
 * @param[out] root 32-byte destination receiving Merkle root hash.
 * @complexity Time: O(num_inputs log(num_inputs)), Space: O(num_inputs) stack buffer.
 */
void compute_inputs_merkle_root(const Pointer inputs[], uint32_t num_inputs, uint8_t *root) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST) && !defined(CRYPTO_ZK_FUZZER)
    (void)inputs; (void)num_inputs;
    memset(root, 0x42, COIN_ID_LEN);
    return;
#else
    if (num_inputs == 0) {
        memset(root, 0, COIN_ID_LEN);
        return;
    }

    if (num_inputs > MAX_INPUTS) {
        fprintf(stderr, "[Utils] ERROR: num_inputs exceeds MAX_INPUTS\n");
        memset(root, 0, COIN_ID_LEN);
        return;
    }

    uint8_t hashes[MAX_INPUTS][COIN_ID_LEN];

    // Compute individual leaf hashes from serialized signing pointers
    for (uint32_t i = 0; i < num_inputs; i++) {
        uint8_t pointer_data[POINTER_SIGNING_SIZE];
        serialize_pointer_for_signing(&inputs[i], pointer_data);
        SHA256(pointer_data, POINTER_SIGNING_SIZE, hashes[i]);
    }

    uint32_t current_level_count = num_inputs;

    // Reduce binary tree layer-by-layer
    while (current_level_count > 1) {
        uint32_t next_level_count = 0;
        for (uint32_t i = 0; i < current_level_count; i += 2) {
            if (i + 1 < current_level_count) {
                hash_node(hashes[i], hashes[i+1], hashes[next_level_count]);
            } else {
                // Odd elements pair with self-duplicate per standard Bitcoin/SCL Merkle rules
                hash_node(hashes[i], hashes[i], hashes[next_level_count]);
            }
            next_level_count++;
        }
        current_level_count = next_level_count;
    }

    memcpy(root, hashes[0], COIN_ID_LEN);
#endif
}

/**
 * @brief Computes SHA-256 digest of an MMR leaf node (`SHA256(coin_id || remaining_subunits_be)`).
 *
 * @param[in] coin_id Parent coin identifier.
 * @param[in] remaining_subunits Remaining unspent subunits.
 * @param[out] output 32-byte destination buffer.
 */
void hash_leaf(const uint8_t *coin_id, uint64_t remaining_subunits, uint8_t *output) {
    uint8_t data[COIN_ID_LEN + sizeof(uint64_t)];
    memcpy(data, coin_id, COIN_ID_LEN);
    memcpy(data + COIN_ID_LEN, &remaining_subunits, sizeof(uint64_t));
    SHA256(data, COIN_ID_LEN + sizeof(uint64_t), output);
}

/**
 * @brief Computes parent hash of two adjacent MMR child nodes (`SHA256(left || right)`).
 *
 * @param[in] left 32-byte left child digest.
 * @param[in] right 32-byte right child digest.
 * @param[out] output 32-byte destination buffer.
 */
void hash_node(const uint8_t *left, const uint8_t *right, uint8_t *output) {
    uint8_t combined[2 * COIN_ID_LEN];
    memcpy(combined, left, COIN_ID_LEN);
    memcpy(combined + COIN_ID_LEN, right, COIN_ID_LEN);
    SHA256(combined, 2 * COIN_ID_LEN, output);
}

/**
 * @brief Modulo hash function mapping binary keys to table bucket indices.
 *
 * @param[in] key Pointer to key buffer.
 * @param[in] table_size Total bucket count in target hash table.
 * @return Bucket index in range `[0, table_size - 1]`.
 */
uint32_t hash_func(const uint8_t *key, size_t table_size) {
    if (!key || table_size == 0) return 0;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(key, COIN_ID_LEN, hash);
    uint32_t result = 0;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i += sizeof(uint32_t)) {
        uint32_t chunk;
        memcpy(&chunk, hash + i, sizeof(uint32_t));
        result ^= chunk;
    }
    return result % table_size;
}

/**
 * @brief Formats binary slice into hexadecimal string and logs with prefix to stdout.
 *
 * @param[in] prefix Leading textual label.
 * @param[in] data Binary data pointer.
 * @param[in] len Active length in bytes.
 * @param[in] max_len Maximum bytes formatted.
 */
void log_hex(const char *prefix, const uint8_t *data, size_t len, size_t max_len) {
    size_t actual_len = (len < max_len) ? len : max_len;
    char *hex_str = malloc(actual_len * 2 + 1);
    if (hex_str) {
        bytes_to_hex(data, actual_len, hex_str);
        printf("%s%s\n", prefix, hex_str);
        free(hex_str);
    }
}

/**
 * @brief Instantiates a default genesis block (Block 0) initialized to all zeros.
 *
 * @return Zeroed Block structure with block_number=0.
 */
Block create_standard_genesis_block() {
    Block genesis = {0};
    genesis.block_number = 0;
    memset(genesis.prev_block_hash, 0, COIN_ID_LEN);
    genesis.operation_count = 0;
    genesis.operations = NULL;
    memset(genesis.proposer_pubkey, 0, PUBKEY_LEN);
    memset(genesis.signature, 0, SIGNATURE_LEN);
    genesis.entropy_seed = 0;
    return genesis;
}

/**
 * @brief Initializes and commits the canonical genesis block to state if chain is empty.
 *
 * @param[in,out] state Global node state container.
 * @return 0 on success; -1 on failure.
 *
 * @note Acquires `state->ledger_mutex` and `state->bc.rwlock` internally.
 * @complexity Time: O(1), Space: O(1).
 */
int initialize_genesis_block(State *state) {
    if (!state) {
        fprintf(stderr, "[Client] ERROR: NULL state\n");
        return -1;
    }

    pthread_mutex_lock(&state->ledger_mutex);
    pthread_rwlock_wrlock(&state->bc.rwlock);
    
    // Check if genesis already committed
    if (state->current_block_number > 0 ||
        (state->current_block_number == 0 &&
         !is_zeroed(state->current_block_hash, COIN_ID_LEN))) {
        fprintf(stderr, "[Client] Genesis block already exists\n");
        pthread_rwlock_unlock(&state->bc.rwlock);
        pthread_mutex_unlock(&state->ledger_mutex);
        return 0;
    }

    Block *genesis = malloc(sizeof(Block));
    if (!genesis) {
       pthread_rwlock_unlock(&state->bc.rwlock);
       pthread_mutex_unlock(&state->ledger_mutex);
       return -1;
    }
    *genesis = create_standard_genesis_block();

    uint8_t genesis_hash[COIN_ID_LEN];
    if (compute_block_hash(genesis, genesis_hash) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to compute genesis block hash\n");
        free(genesis);
        pthread_rwlock_unlock(&state->bc.rwlock);
        pthread_mutex_unlock(&state->ledger_mutex);
        return -1;
    }

    int apply_result = apply_block(state, genesis);
    if (apply_result != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to apply genesis block (%d)\n", apply_result);
        free(genesis);
        pthread_rwlock_unlock(&state->bc.rwlock);
        pthread_mutex_unlock(&state->ledger_mutex);
        return -1;
    }

    memcpy(state->current_block_hash, genesis_hash, COIN_ID_LEN);
    state->current_block_number = 0;
    state->bc.sync_epoch = 1;

    char hex_hash[33];
    bytes_to_hex(genesis_hash, 16, hex_hash);
    fprintf(stderr, "[Client] Initialized genesis block: hash=%s\n", hex_hash);

    pthread_rwlock_unlock(&state->bc.rwlock);
    pthread_mutex_unlock(&state->ledger_mutex);
    return 0;
}

/**
 * @brief Structural equality predicate comparing two on-chain operations.
 *
 * @param[in] op1 First operation pointer.
 * @param[in] op2 Second operation pointer.
 * @return 1 if operations possess identical types, parameters, and signatures; 0 otherwise.
 */
int operation_equals(const Operation *op1, const Operation *op2) {
    if (!op1 || !op2 || op1->type != op2->type) return 0;

    switch (op1->type) {
        case OP_CLAIM_VALIDATION: {
            const ClaimValidationData *c1 = &op1->data.claim_validation;
            const ClaimValidationData *c2 = &op2->data.claim_validation;
            return memcmp(&c1->commitment, &c2->commitment, sizeof(BdlopCommitment)) == 0 &&
                    memcmp(c1->pubkey, c2->pubkey, PUBKEY_LEN) == 0 &&
                    memcmp(c1->signature, c2->signature, SIGNATURE_LEN) == 0;
        }
        case OP_REDEEM_CENTINEL: {
            const RedeemCentinelData *r1 = &op1->data.redeem_centinel;
            const RedeemCentinelData *r2 = &op2->data.redeem_centinel;
            if (memcmp(r1->nullifier, r2->nullifier, NULLIFIER_LEN) != 0 ||
                memcmp(&r1->c_transfer, &r2->c_transfer, sizeof(BdlopCommitment)) != 0 ||
                memcmp(&r1->c_change, &r2->c_change, sizeof(BdlopCommitment)) != 0 ||
                r1->zk_proof_len != r2->zk_proof_len) {
                return 0;
            }
            return memcmp(r1->zk_proof, r2->zk_proof, r1->zk_proof_len) == 0;
        }
        case OP_SUBMIT_VALUATION: {
            const ValuationData *v1 = &op1->data.submit_valuation;
            const ValuationData *v2 = &op2->data.submit_valuation;
            return memcmp(v1->valuation.user_id, v2->valuation.user_id, USER_ID_LEN) == 0 &&
                   memcmp(v1->valuation.numbers, v2->valuation.numbers, NUMBERS_PER_VALUATION * sizeof(int)) == 0 &&
                   v1->valuation.timestamp == v2->valuation.timestamp &&
                   memcmp(v1->pubkey, v2->pubkey, PUBKEY_LEN) == 0 &&
                   memcmp(v1->signature, v2->signature, SIGNATURE_LEN) == 0;
        }
        case OP_MINT_COIN: {
            const MintData *m1 = &op1->data.mint_coin;
            const MintData *m2 = &op2->data.mint_coin;
            return memcmp(m1->coin.coin_id, m2->coin.coin_id, COIN_ID_LEN) == 0 &&
                    memcmp(m1->owner_pubkey, m2->owner_pubkey, PUBKEY_LEN) == 0 &&
                    memcmp(m1->coin.creation_tx_hash, m2->coin.creation_tx_hash, COIN_ID_LEN) == 0 &&
                    m1->coin.total_subunits == m2->coin.total_subunits &&
                    m1->coin.remaining_subunits == m2->coin.remaining_subunits;
        }
        case OP_TRANSFER_POINTER: {
            const TransferData *t1 = &op1->data.transfer_pointer;
            const TransferData *t2 = &op2->data.transfer_pointer;
            if (t1->num_inputs != t2->num_inputs ||
                memcmp(t1->tx_id, t2->tx_id, COIN_ID_LEN) != 0 ||
                memcmp(t1->nonce, t2->nonce, 8) != 0 ||
                memcmp(t1->recipient_pubkey, t2->recipient_pubkey, PUBKEY_LEN) != 0 ||
                memcmp(t1->sender_pubkey, t2->sender_pubkey, PUBKEY_LEN) != 0 ||
                t1->amount != t2->amount ||
                memcmp(t1->signature, t2->signature, SIGNATURE_LEN) != 0) {
                return 0;
            }
            return 1;
        }
        case OP_STAKE: {
            const StakeData *s1 = &op1->data.stake;
            const StakeData *s2 = &op2->data.stake;
            if (s1->num_inputs != s2->num_inputs ||
                memcmp(s1->stake_tx_id, s2->stake_tx_id, COIN_ID_LEN) != 0 ||
                memcmp(s1->sender_pubkey, s2->sender_pubkey, PUBKEY_LEN) != 0) {
                return 0;
            }
            return 1;
        }
        case OP_UNSTAKE: {
            const UnstakeData *u1 = &op1->data.unstake;
            const UnstakeData *u2 = &op2->data.unstake;
            if (u1->num_inputs != u2->num_inputs ||
                memcmp(u1->unstake_tx_id, u2->unstake_tx_id, COIN_ID_LEN) != 0 ||
                memcmp(u1->nonce, u2->nonce, 8) != 0 ||
                memcmp(u1->recipient_pubkey, u2->recipient_pubkey, PUBKEY_LEN) != 0 ||
                memcmp(u1->threshold_pubkey, u2->threshold_pubkey, PUBKEY_LEN) != 0 ||
                u1->amount != u2->amount ||
                memcmp(u1->threshold_signature, u2->threshold_signature, SIGNATURE_LEN) != 0) {
                return 0;
            }
            for (uint32_t i = 0; i < u1->num_inputs; i++) {
                if (memcmp(&u1->inputs[i], &u2->inputs[i], sizeof(Pointer)) != 0 ||
                    memcmp(&u1->proofs[i], &u2->proofs[i], sizeof(MMRProof)) != 0) {
                    return 0;
                }
            }
            return memcmp(u1->client_root, u2->client_root, COIN_ID_LEN) == 0;
        }
        default:
            fprintf(stderr, "[Network] Unsupported operation type in operation_equals: %u\n", op1->type);
            return 0;
    }
}

/**
 * @brief Validates that input pointers provide sufficient unspent subunits under caller's lock.
 *
 * @param[in] state Global node state container.
 * @param[in] owner_pubkey Expected owner's 2,592-byte Dilithium public key.
 * @param[in] inputs Array of Pointer structures.
 * @param[in] num_inputs Count of input pointers.
 * @param[in] required_amount Total required subunits (principal + fee).
 * @param[in] expect_staked `true` validates staked inputs (unstaking); `false` liquid inputs.
 * @return 0 if balance is sufficient and inputs valid; 1 if insufficient or invalid.
 *
 * @pre Caller must hold `state->bc.rwlock` in read mode.
 * @complexity Time: O(num_inputs^2) duplicate scan, Space: O(num_inputs) stack buffer.
 */
int has_insufficient_balance_locked(State *state, const uint8_t *owner_pubkey,
                                    const Pointer *inputs, uint32_t num_inputs,
                                    uint64_t required_amount, bool expect_staked) {
    if (!state || !owner_pubkey || !inputs || num_inputs == 0) {
        fprintf(stderr, "[Network] Invalid parameters in has_insufficient_balance_locked\n");
        return 1;
    }

    uint8_t expected_address[USER_ID_LEN];
    SHA256(owner_pubkey, PUBKEY_LEN, expected_address);

    uint64_t total_subunits = 0;
    uint8_t used_pointers[MAX_INPUTS][COIN_ID_LEN] = {0};
    uint32_t used_pointer_count = 0;

    for (uint32_t i = 0; i < num_inputs; i++) {
        const Pointer *ptr = &inputs[i];

        // 1. Verify owner address matches expected Dilithium pubkey hash
        if (memcmp(ptr->owner_address, expected_address, USER_ID_LEN) != 0) {
            fprintf(stderr, "[Network] Pointer %u owner mismatch\n", i);
            return 1;
        }

        // 2. Reject intra-transaction duplicate input pointers
        for (uint32_t j = 0; j < used_pointer_count; j++) {
            if (memcmp(used_pointers[j], ptr->pointer_id, COIN_ID_LEN) == 0) {
                fprintf(stderr, "[Network] Duplicate pointer in new operation\n");
                return 1;
            }
        }
        memcpy(used_pointers[used_pointer_count++], ptr->pointer_id, COIN_ID_LEN);

        // 3. Verify pointer exists on-chain and matches expected staking status
        Pointer *existing = hash_table_lookup(state->bc.pointer_table, ptr->pointer_id, false);
        if (!existing || existing->spent || (existing->staked != expect_staked)) {
            fprintf(stderr, "[Network] Pointer %u not found, already spent, or %sstaked\n", i, expect_staked ? "not " : "");
            return 1;
        }

        total_subunits += ptr->end_subunit - ptr->start_subunit + 1;
    }

    if (total_subunits < required_amount) {
        fprintf(stderr, "[Network] Insufficient subunits: available=%llu, required=%llu\n",
                total_subunits, required_amount);
        return 1;
    }

    return 0;
}

/* ============================================================================ */
/* SECTION 6: CLI VALIDATION & CRYPTOGRAPHIC IDENTITY RESOLUTION                */
/* ============================================================================ */

/**
 * @brief Reads and validates an integer from stdin in interactive CLI execution mode.
 *
 * @return Parsed non-negative integer; -1 on EOF, signal interruption, or shutdown.
 * @complexity Time: O(input length), Space: O(1) stack buffer.
 */
int validate_integer_input(void) {
    char buffer[1024];
    long value;

    while (!atomic_load(&global_shutdown)) {
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            if (atomic_load(&global_shutdown)) return -1;
            if (errno == EINTR) {
                clearerr(stdin);
                continue;
            }
            fprintf(stderr, "[P2P] Error reading input: %s\n", strerror(errno));
            return -1;
        }
        
        size_t len = strlen(buffer);
        int has_newline = 0;
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
            has_newline = 1;
            len--;
        }
        
        // Flush excess input only if newline was unreached
        if (!has_newline && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
        }

        if (buffer[0] == '\0') {
            printf("[P2P] Empty input. Please enter a valid integer.\n");
            continue;
        }
        char *endptr;
        errno = 0;
        value = strtol(buffer, &endptr, 10);
        if (errno == ERANGE || endptr == buffer || (*endptr && *endptr != '\0') || value < 0) {
            printf("[P2P] Invalid input. Please enter a valid integer.\n");
            continue;
        }
        return (int)value;
    }
    return -1;
}

/**
 * @brief Reads and parses a floating-point currency amount (SCL) from stdin.
 *
 * @return Positive floating-point amount; -1.0 on invalid input or shutdown.
 * @complexity Time: O(input length), Space: O(1).
 */
double validate_money_input(void) {
    char buffer[1024];
    char cleaned_buffer[1024];
    double value;

    while (!atomic_load(&global_shutdown)) {
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            if (atomic_load(&global_shutdown)) return -1.0;
            if (errno == EINTR) {
                clearerr(stdin);
                continue;
            }
            return -1.0;
        }
        
        size_t len = strlen(buffer);
        int has_newline = 0;
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
            has_newline = 1;
            len--;
        }
        
        if (!has_newline && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF);
        }

        const char *p = buffer;
        while (*p != '\0' && (isspace(*p) || *p == '$')) {
            p++;
        }
        char *q = cleaned_buffer;
        while (*p != '\0') {
            *q++ = *p++;
        }
        *q = '\0';
        if (cleaned_buffer[0] == '\0') {
            printf("Invalid input. Please enter a valid amount (e.g., 5 or $5): ");
            continue;
        }
        char *endptr;
        errno = 0;
        value = strtod(cleaned_buffer, &endptr);
        if (errno == ERANGE || *endptr != '\0' || value < 0) {
            printf("Invalid amount. Please enter a valid amount (e.g., 5 or $5): ");
        } else {
            return value;
        }
    }
    return -1.0;
}

/**
 * @brief Reads a fixed-length hexadecimal string from stdin and decodes into raw bytes.
 *
 * @param[out] buf Destination byte array.
 * @param[in] len Expected byte count (reads exactly len * 2 hex characters).
 * @return 0 on success; -1 on length mismatch, invalid character, or interrupt.
 * @complexity Time: O(len), Space: O(1) stack buffer.
 */
int read_hex_input(uint8_t *buf, size_t len) {
    char hex_str[256];
    
    while (!atomic_load(&global_shutdown)) {
        if (!fgets(hex_str, sizeof(hex_str), stdin)) {
            if (atomic_load(&global_shutdown)) return -1;
            if (errno == EINTR) {
                clearerr(stdin);
                continue;
            }
            return -1;
        }
        break;
    }
    
    size_t hex_len = strlen(hex_str);
    int has_newline = 0;
    if (hex_len > 0 && hex_str[hex_len - 1] == '\n') {
        hex_str[hex_len - 1] = '\0';
        has_newline = 1;
        hex_len--;
    }
    
    if (!has_newline && !feof(stdin)) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
    }
    
    if (hex_len != 2 * len) {
        fprintf(stderr, "Error: Invalid hex input length (expected %zu characters)\n", 2 * len);
        return -1;
    }
    for (size_t i = 0; i < hex_len; i++) {
        if (!isxdigit((unsigned char)hex_str[i])) {
            fprintf(stderr, "Error: Invalid hex character '%c'\n", hex_str[i]);
            return -1;
        }
    }
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex_str + 2*i, "%2x", &byte) != 1) {
            return -1;
        }
        buf[i] = (uint8_t)byte;
    }
    return 0;
}

/**
 * @brief Resolves a 32-byte User ID to its corresponding 2,592-byte Dilithium5 public key.
 *
 * @details
 * Performs hierarchical search:
 * 1. Checks local user table (`state->user_table`).
 * 2. Checks cached public keys (`state->pubkey_cache`).
 * 3. Checks active peer table (`state->p2p_network.known_peers`).
 * 4. Broadcasts network-wide query (`MSG_GET_PUBKEY_BY_USERID`) with exponential backoff.
 *
 * @param[in,out] state Global node state container.
 * @param[in] user_id 32-byte SHA-256 digest of target public key.
 * @param[out] pubkey_out Destination buffer receiving 2,592-byte public key.
 * @return 1 on successful resolution; 0 if unresolvable.
 *
 * @complexity Time: O(1) on cache hit; O(network timeout) on remote broadcast, Space: O(1).
 */
int get_pubkey_by_userid(State *state, const uint8_t *user_id, uint8_t *pubkey_out) {
    if (!state || !user_id || !pubkey_out) {
        printf("Error: Invalid parameters in get_pubkey_by_userid\n");
        return 0;
    }

    // 1. Check local user_table
    pthread_mutex_lock(&state->mutex);
    User *user = hash_table_lookup(state->user_table, user_id, false);
    if (user) {
        memcpy(pubkey_out, user->dilithium_pubkey, PUBKEY_LEN);
        pthread_mutex_unlock(&state->mutex);
        
        uint8_t computed_user_id[USER_ID_LEN];
        SHA256(pubkey_out, PUBKEY_LEN, computed_user_id);
        if (memcmp(computed_user_id, user_id, USER_ID_LEN) != 0) {
            printf("Error: Cached pubkey does not match user_id\n");
            return 0;
        }
        return 1;
    }
    pthread_mutex_unlock(&state->mutex);

    // 2. Check pubkey_cache
    pthread_mutex_lock(&state->mutex);
    PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, user_id, false);
    if (cache_entry) {
        memcpy(pubkey_out, cache_entry->pubkey, PUBKEY_LEN);
        pthread_mutex_unlock(&state->mutex);
        return 1;
    }
    pthread_mutex_unlock(&state->mutex);

    // 3. Check known_peers network directory
    pthread_mutex_lock(&state->p2p_network.mutex);
    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
        uint8_t computed_id[USER_ID_LEN];
        SHA256(state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, computed_id);
        if (memcmp(computed_id, user_id, USER_ID_LEN) == 0) {
            memcpy(pubkey_out, state->p2p_network.known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            pthread_mutex_unlock(&state->p2p_network.mutex);
            
            pthread_mutex_lock(&state->mutex);
            PubkeyCacheEntry pce;
            memcpy(pce.pubkey, pubkey_out, PUBKEY_LEN);
            hash_table_insert(state->pubkey_cache, user_id, &pce, HASH_ENTRY_PUBKEY_CACHE);
            pthread_mutex_unlock(&state->mutex);
            
            return 1;
        }
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    return 0;
#endif

    // 4. Broadcast network discovery query with exponential backoff
    int attempts = 0;
    const int max_attempts = 3;
    
    while (attempts < max_attempts) {
        Message *req = calloc(1, sizeof(Message));
        if (!req) break;
        req->type = MSG_GET_PUBKEY_BY_USERID;
        req->length = USER_ID_LEN;
        memcpy(req->payload, user_id, USER_ID_LEN);

        if (queue_enqueue(&state->message_queue, req) != 0) {
            free(req);
            fprintf(stderr, "[Client] Failed to enqueue pubkey request for user_id\n");
            attempts++;
            continue;
        }
        free(req);

        // Poll pubkey cache up to 5 seconds (50 iterations x 100ms)
        int wait_loops = 50;
        int found = 0;

        while (wait_loops-- > 0) {
            if (atomic_load(&global_shutdown)) return 0;

            pthread_mutex_lock(&state->mutex);
            PubkeyCacheEntry *entry = hash_table_lookup(state->pubkey_cache, user_id, false);
            if (entry) {
                memcpy(pubkey_out, entry->pubkey, PUBKEY_LEN);
                found = 1;
            }
            pthread_mutex_unlock(&state->mutex);

            if (found) {
                uint8_t computed_user_id[USER_ID_LEN];
                SHA256(pubkey_out, PUBKEY_LEN, computed_user_id);
                if (memcmp(computed_user_id, user_id, USER_ID_LEN) != 0) {
                    fprintf(stderr, "[Network] ERROR: Received pubkey does not match user_id\n");
                    return 0;
                }
                return 1;
            }
            
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            usleep(100000);
#endif
        }

        fprintf(stderr, "[Client] Attempt %d/%d failed to get pubkey for user_id, retrying...\n",
                attempts + 1, max_attempts);
        attempts++;
        
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        usleep(1000000 * (1 << attempts));
#endif
    }

    fprintf(stderr, "[Client] ERROR: Failed to retrieve recipient public key after %d attempts\n", max_attempts);
    return 0;
}

/**
 * @brief Dynamically resizes a valuation array buffer, doubling capacity when full.
 *
 * @param[in,out] valuations Pointer to dynamic array pointer.
 * @param[in] valuation_count Pointer to active element counter.
 * @param[in,out] valuation_capacity Pointer to allocated capacity.
 * @complexity Time: O(N) on reallocation, amortized O(1), Space: O(valuation_capacity).
 */
void resize_valuation_array(Valuation **valuations, unsigned int *valuation_count, unsigned int *valuation_capacity) {
    if (*valuation_count >= *valuation_capacity) {
        unsigned int new_capacity = (*valuation_capacity == 0) ? 1 : *valuation_capacity * 2;
        Valuation *new_valuations = realloc(*valuations, new_capacity * sizeof(Valuation));
        if (!new_valuations) {
            fprintf(stderr, "[Utils] Memory allocation failed during valuation array resize\n");
            return;
        }
        *valuations = new_valuations;
        *valuation_capacity = new_capacity;
    }
}

/**
 * @brief Dispatches a transaction recreation task to a round-robin work-stealing queue.
 *
 * @param[in,out] state Global node state container.
 * @param[in] args Heap-allocated recreation context; callee assumes ownership.
 * @complexity Time: O(1), Space: O(1).
 */
void spawn_recreation_thread(State *state, RecreateArgs *args) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)state;
    free(args);
    return;
#else
    RecreateNode *node = malloc(sizeof(RecreateNode));
    if (!node) { free(args); return; }
    node->args = args;
    node->next = NULL;
    
    uint32_t target_queue = atomic_fetch_add(&state->round_robin_idx, 1) % state->recreation_workers_count;
    
    pthread_mutex_lock(&state->recreation_queues[target_queue].mutex);
    if (!state->recreation_queues[target_queue].head) {
        state->recreation_queues[target_queue].head = state->recreation_queues[target_queue].tail = node;
    } else {
        state->recreation_queues[target_queue].tail->next = node;
        state->recreation_queues[target_queue].tail = node;
    }
    pthread_mutex_unlock(&state->recreation_queues[target_queue].mutex);
    
    pthread_mutex_lock(&state->recreation_sleep_mutex);
    pthread_cond_signal(&state->recreation_cond);
    pthread_mutex_unlock(&state->recreation_sleep_mutex);
#endif
}

/* ============================================================================ */
/* SECTION 7: TRANSACTION RECREATION, MEMPOOL CLEANUP & CANONICAL ANCHORING     */
/* ============================================================================ */

/**
 * @brief Background worker loop executing asynchronous transaction recreation with work stealing.
 *
 * @details
 * Thread-safe execution pipeline:
 * 1. Pops recreation task from worker's dedicated FIFO queue.
 * 2. If empty, iterates through sibling worker queues using `pthread_mutex_trylock` to steal work.
 * 3. Re-executes `create_and_broadcast_*` routines with fresh input pointer sets.
 * 4. Automatically handles transient lockouts (status 2) by re-enqueuing after a 500ms backoff.
 * 5. Reclaims scheduled subunit reservations upon terminal completion or failure.
 *
 * @param[in] vargs Pointer to heap-allocated `struct WorkerArgs`.
 * @return NULL on thread termination.
 * @complexity Time: O(work), Space: O(1) auxiliary per worker thread.
 */
void *recreation_worker_loop(void *vargs) {
    struct WorkerArgs *wa = (struct WorkerArgs *)vargs;
    State *state = wa->s;
    int my_id = wa->id;
    free(wa);
    
    while (state->submission_running && !atomic_load(&global_shutdown)) {
        RecreateNode *node = NULL;
        
        // 1. Check local dedicated FIFO task queue
        pthread_mutex_lock(&state->recreation_queues[my_id].mutex);
        if (state->recreation_queues[my_id].head) {
            node = state->recreation_queues[my_id].head;
            state->recreation_queues[my_id].head = node->next;
            if (!state->recreation_queues[my_id].head) state->recreation_queues[my_id].tail = NULL;
        }
        pthread_mutex_unlock(&state->recreation_queues[my_id].mutex);
        
        // 2. Work Stealing: Non-blocking trylock across peer queues to balance core load
        if (!node) {
            for (int i = 0; i < state->recreation_workers_count; i++) {
                if (i == my_id) continue;
                if (pthread_mutex_trylock(&state->recreation_queues[i].mutex) == 0) {
                    if (state->recreation_queues[i].head) {
                        node = state->recreation_queues[i].head;
                        state->recreation_queues[i].head = node->next;
                        if (!state->recreation_queues[i].head) state->recreation_queues[i].tail = NULL;
                    }
                    pthread_mutex_unlock(&state->recreation_queues[i].mutex);
                    if (node) break;
                }
            }
        }
        
        // 3. Execute Transaction Recreation
        if (node) {
            RecreateArgs *args = (RecreateArgs *)node->args;
            free(node);
            
            int success = -1;
            if (args->is_transfer) {
                success = create_and_broadcast_transfer(args->state, args->recipient_pubkey, args->amount, true);
            } else if (args->is_stake) {
                success = create_and_broadcast_stake(args->state, args->amount, true);
            } else if (args->is_drift_cert) {
                /* Re-anchor a deferred drift certificate from the persisted
                 * identity core. ApplyDriftCertData is heap-allocated (~4.4 MB
                 * at MAX_INPUTS=1024) to keep the worker stack bounded; the
                 * builder re-selects funding pointers, recomputes the digest
                 * chain, and re-signs under the node wallet. */
                ApplyDriftCertData *retry_cert = calloc(1, sizeof(ApplyDriftCertData));
                if (retry_cert) {
                    memcpy(retry_cert->circuit_hash, args->circuit_hash, 32);
                    retry_cert->tvd_scaled = args->tvd_scaled;
                    retry_cert->shots = args->shots;
                    retry_cert->status = args->status;
                    memcpy(retry_cert->commitment_root, args->commitment_root, 32);
                    retry_cert->timestamp_us = args->timestamp_us;
                    memcpy(retry_cert->recipient_pubkey, args->recipient_pubkey, PUBKEY_LEN);
                    retry_cert->amount = args->amount;
                    success = create_and_broadcast_apply_drift_cert(args->state, retry_cert, true, NULL);
                    free(retry_cert);
                } else {
                    fprintf(stderr, "[Recreation] Memory allocation failed for drift certificate retry, aborting.\n");
                }
            } else {
                success = create_and_broadcast_unstake(args->state, args->amount, true);
            }
            
            if (success == 2) {
                // Inputs are still locked in mempool; re-queue with 500ms backoff
                usleep(500000);
                spawn_recreation_thread(args->state, args);
            } else {
                if (success != 0) {
                    fprintf(stderr, "[Recreation] Hard failure recreating operation, aborting.\n");
                }
                // Release scheduled subunit reservations
                uint64_t fee = calculate_fee(args->amount, !args->is_transfer);
                uint64_t total_amount = args->amount + fee;
                
                if (args->is_transfer || args->is_stake || args->is_drift_cert) {
                    /* Transfers, stakes, and drift-certificate anchors all spend
                     * liquid subunits (anchor fee is charged at the halved
                     * staking-grade rate via !is_transfer above). */
                    uint64_t current = atomic_load(&args->state->scheduled_consumed_subunits);
                    if (current >= total_amount) atomic_fetch_sub(&args->state->scheduled_consumed_subunits, total_amount);
                    else atomic_store(&args->state->scheduled_consumed_subunits, 0);
                } else {
                    uint64_t current = atomic_load(&args->state->scheduled_staked_subunits);
                    if (current >= total_amount) atomic_fetch_sub(&args->state->scheduled_staked_subunits, total_amount);
                    else atomic_store(&args->state->scheduled_staked_subunits, 0);
                }
                free(args);
            }
        } else {
            // Sleep until condition signaled by incoming tasks
            pthread_mutex_lock(&state->recreation_sleep_mutex);
            while (state->submission_running && !atomic_load(&global_shutdown)) {
                bool has_work = false;
                for (int i = 0; i < state->recreation_workers_count; i++) {
                    if (state->recreation_queues[i].head != NULL) {
                        has_work = true;
                        break;
                    }
                }
                if (has_work) break;
                pthread_cond_wait(&state->recreation_cond, &state->recreation_sleep_mutex);
            }
            pthread_mutex_unlock(&state->recreation_sleep_mutex);
        }
    }
    release_l5_staging_buffer();
    return NULL;
}

/**
 * @brief Evicts confirmed operations from the local mempool following block commitment.
 *
 * @details
 * Performs two-pass sweep:
 * 1. Checks every pending operation against committed block operations, removing matched entries.
 * 2. Checks surviving operations for invalidation (spent pointers, spent nullifiers).
 * 3. Local node operations invalidated by external block confirmation are queued for
 *    background transaction recreation to preserve user intent.
 *
 * @param[in,out] state Global node state container.
 * @param[in] block Confirmed block committed to ledger.
 *
 * @complexity Time: O(MAX_PENDING_OPS * block->operation_count), Space: O(recreation arrays).
 */
void clean_pending_operations(State *state, Block *block) {
    if (!state || !block) {
        fprintf(stderr, "[Network] ERROR: Invalid state or block in clean_pending_operations\n");
        return;
    }

    if (atomic_load_explicit(&state->pending_operations_count, memory_order_acquire) == 0) {
        return;
    }

    size_t removed_count = 0;

    // Cache committed transaction keys in stack buffer
    uint8_t block_op_keys[MAX_OPERATIONS_PER_BLOCK][COIN_ID_LEN];
    size_t block_op_count = block ? block->operation_count : 0;
    if (block_op_count > MAX_OPERATIONS_PER_BLOCK) {
        block_op_count = MAX_OPERATIONS_PER_BLOCK;
    }
    for (size_t i = 0; i < block_op_count; i++) {
        Operation *block_op = &block->operations[i];
        const uint8_t *op_id = get_operation_tx_id(block_op);
        if (op_id) {
            memcpy(block_op_keys[i], op_id, COIN_ID_LEN);
        } else {
            uint8_t *data;
            size_t data_len;
            if (block_op->type == OP_SUBMIT_VALUATION) {
                data = (uint8_t *)&block_op->data.submit_valuation;
                data_len = sizeof(ValuationData);
            } else {
                data = (uint8_t *)block_op;
                data_len = sizeof(Operation);
            }
            SHA256(data, data_len, block_op_keys[i]);
        }
    }

    struct ToRecreateTransfer {
        uint8_t recipient_pubkey[PUBKEY_LEN];
        uint64_t amount;
    };
    struct ToRecreateTransfer *transfers_to_recreate = calloc(100, sizeof(struct ToRecreateTransfer));

    struct ToRecreateStakeUnstake {
        uint64_t amount;
    };
    struct ToRecreateStakeUnstake *stakes_to_recreate = calloc(100, sizeof(struct ToRecreateStakeUnstake));
    struct ToRecreateStakeUnstake *unstakes_to_recreate = calloc(100, sizeof(struct ToRecreateStakeUnstake));

    struct ToRecreateDriftCert {
        uint8_t circuit_hash[32];
        uint8_t commitment_root[32];
        uint64_t tvd_scaled;
        uint32_t shots;
        uint32_t status;
        uint64_t timestamp_us;
        uint8_t recipient_pubkey[PUBKEY_LEN];
        uint64_t amount;
    };
    struct ToRecreateDriftCert *drifts_to_recreate = calloc(100, sizeof(struct ToRecreateDriftCert));

    if (!transfers_to_recreate || !stakes_to_recreate || !unstakes_to_recreate || !drifts_to_recreate) {
        fprintf(stderr, "[Network] ERROR: Failed to allocate recreation arrays\n");
        free(transfers_to_recreate);
        free(stakes_to_recreate);
        free(unstakes_to_recreate);
        free(drifts_to_recreate);
        return;
    }

    size_t transfer_recreate_count = 0;
    size_t stake_recreate_count = 0;
    size_t unstake_recreate_count = 0;
    size_t drift_recreate_count = 0;

    // Scan mempool array slots
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *op = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (!op) continue;

        uint8_t key[COIN_ID_LEN];
        const uint8_t *op_id = get_operation_tx_id(op);
        if (op_id) memcpy(key, op_id, COIN_ID_LEN);
        else {
            uint8_t *data;
            size_t data_len;
            if (op->type == OP_SUBMIT_VALUATION) {
                data = (uint8_t *)&op->data.submit_valuation;
                data_len = sizeof(ValuationData);
            } else {
                data = (uint8_t *)op;
                data_len = sizeof(Operation);
            }
            SHA256(data, data_len, key);
        }

        int keep = 1;
        // Check 1: Evict operations included in committed block
        for (size_t j = 0; j < block_op_count; j++) {
            if (memcmp(key, block_op_keys[j], COIN_ID_LEN) == 0) {
                keep = 0;
                scl_log(LOG_LEVEL_DEBUG, "Network", "Removed block-included operation from pending");
                
                if (op->is_rpc_injected) {
                    char tx_id_str[65] = {0};
                    bytes_to_hex(key, COIN_ID_LEN, tx_id_str);
                    SCL_LOG_RPC_TX_COMMIT(tx_id_str, block ? block->block_number : 0);
                }
                break;
            }
        }

        // Check 2: Invalidate pending operations whose inputs are now spent on-chain
        bool spent_invalid = false;
        if (keep && op->type == OP_REDEEM_CENTINEL) {
            bool is_spent = hash_table_lookup(state->bc.centinel.nullifier_set, op->data.redeem_centinel.nullifier, true) != NULL ||
                            (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, op->data.redeem_centinel.nullifier) &&
                             scl_db_has_nullifier(op->data.redeem_centinel.nullifier));
            if (is_spent) {
                keep = 0;
                spent_invalid = true;
                scl_log(LOG_LEVEL_DEBUG, "Network", "Detected spent nullifier in pending operation, removing");
            }
        } else if (keep && (op->type == OP_TRANSFER_POINTER || op->type == OP_STAKE || op->type == OP_UNSTAKE || op->type == OP_APPLY_DRIFT_CERT)) {
            uint32_t num_inputs;
            Pointer *inputs;
            bool expect_staked = (op->type == OP_UNSTAKE);

            if (op->type == OP_TRANSFER_POINTER) {
                TransferData *td = &op->data.transfer_pointer;
                num_inputs = td->num_inputs;
                inputs = td->inputs;
            } else if (op->type == OP_STAKE) {
                StakeData *sd = &op->data.stake;
                num_inputs = sd->num_inputs;
                inputs = sd->inputs;
            } else if (op->type == OP_APPLY_DRIFT_CERT) {
                ApplyDriftCertData *dd = &op->data.apply_drift_cert;
                num_inputs = dd->num_inputs;
                inputs = dd->inputs;
            } else {
                UnstakeData *sd = &op->data.unstake;
                num_inputs = sd->num_inputs;
                inputs = sd->inputs;
            }

            for (uint32_t j = 0; j < num_inputs; j++) {
                Pointer *ptr = hash_table_lookup(state->bc.pointer_table, inputs[j].pointer_id, false);
                if (!ptr || ptr->spent || (ptr->staked != expect_staked)) {
                    keep = 0;
                    spent_invalid = true;
                    scl_log(LOG_LEVEL_DEBUG, "Network", "Detected spent/invalid pointer in pending operation");
                    break;
                }
            }
        } else if (keep && op->type == OP_CLAIM_VALIDATION) {
            if (hash_table_lookup(state->processed_txs, op->data.claim_validation.commitment.c1, true)) {
                keep = 0;
                spent_invalid = false;
                scl_log(LOG_LEVEL_DEBUG, "Network", "Detected confirmed OP_CLAIM_VALIDATION in pending operations, removing");
            }
        } else if (keep && op->type == OP_MINT_COIN) {
            if (!validate_operation(state, op)) {
                keep = 0;
                spent_invalid = false;
                scl_log(LOG_LEVEL_DEBUG, "Network", "Detected stale OP_MINT_COIN in pending operations");
            }
        }

        // Evict via atomic CAS
        if (!keep) {
            if (atomic_compare_exchange_strong(&state->pending_operations[i], &op, NULL)) {
                atomic_fetch_sub(&state->pending_operations_count, 1);
                removed_count++;

                // Queue local node operations for automatic recreation
                if (spent_invalid) {
                    uint8_t local_address[USER_ID_LEN];
                    SHA256(state->user_wallet.dilithium_pubkey, PUBKEY_LEN, local_address);

                    if (op->type == OP_TRANSFER_POINTER) {
                        TransferData *td = &op->data.transfer_pointer;
                        if (memcmp(td->inputs[0].owner_address, local_address, USER_ID_LEN) == 0) {
                            if (transfer_recreate_count < 100) {
                                bool dup = false;
                                for (size_t r = 0; r < transfer_recreate_count; r++) {
                                    if (transfers_to_recreate[r].amount == td->amount &&
                                        memcmp(transfers_to_recreate[r].recipient_pubkey, td->recipient_pubkey, PUBKEY_LEN) == 0) {
                                        dup = true;
                                        break;
                                    }
                                }
                                if (!dup) {
                                    memcpy(transfers_to_recreate[transfer_recreate_count].recipient_pubkey, td->recipient_pubkey, PUBKEY_LEN);
                                    transfers_to_recreate[transfer_recreate_count].amount = td->amount;
                                    transfer_recreate_count++;
                                    fprintf(stderr, "[Network] Collected local transfer for recreation, amount=%llu subunits\n", td->amount);
                                }
                            }
                        }
                    } else if (op->type == OP_STAKE) {
                        StakeData *sd = &op->data.stake;
                        if (memcmp(sd->inputs[0].owner_address, local_address, USER_ID_LEN) == 0) {
                            if (stake_recreate_count < 100) {
                                bool dup = false;
                                for (size_t r = 0; r < stake_recreate_count; r++) {
                                    if (stakes_to_recreate[r].amount == sd->amount) {
                                        dup = true;
                                        break;
                                    }
                                }
                                if (!dup) {
                                    stakes_to_recreate[stake_recreate_count].amount = sd->amount;
                                    stake_recreate_count++;
                                    fprintf(stderr, "[Network] Collected local stake for recreation, amount=%llu subunits\n", sd->amount);
                                }
                            }
                        }
                    } else if (op->type == OP_UNSTAKE) {
                        UnstakeData *sd = &op->data.unstake;
                        if (memcmp(sd->recipient_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                            if (unstake_recreate_count < 100) {
                                bool dup = false;
                                for (size_t r = 0; r < unstake_recreate_count; r++) {
                                    if (unstakes_to_recreate[r].amount == sd->amount) {
                                        dup = true;
                                        break;
                                    }
                                }
                                if (!dup) {
                                    unstakes_to_recreate[unstake_recreate_count].amount = sd->amount;
                                    unstake_recreate_count++;
                                    fprintf(stderr, "[Network] Collected local unstake for recreation, amount=%llu subunits\n", sd->amount);
                                }
                            }
                        }
                    } else if (op->type == OP_APPLY_DRIFT_CERT) {
                        ApplyDriftCertData *dc = &op->data.apply_drift_cert;
                        if (memcmp(dc->sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                            if (drift_recreate_count < 100) {
                                bool dup = false;
                                for (size_t r = 0; r < drift_recreate_count; r++) {
                                    if (memcmp(drifts_to_recreate[r].circuit_hash, dc->circuit_hash, 32) == 0 &&
                                        drifts_to_recreate[r].timestamp_us == dc->timestamp_us) {
                                        dup = true;
                                        break;
                                    }
                                }
                                if (!dup) {
                                    memcpy(drifts_to_recreate[drift_recreate_count].circuit_hash, dc->circuit_hash, 32);
                                    memcpy(drifts_to_recreate[drift_recreate_count].commitment_root, dc->commitment_root, 32);
                                    drifts_to_recreate[drift_recreate_count].tvd_scaled = dc->tvd_scaled;
                                    drifts_to_recreate[drift_recreate_count].shots = dc->shots;
                                    drifts_to_recreate[drift_recreate_count].status = dc->status;
                                    drifts_to_recreate[drift_recreate_count].timestamp_us = dc->timestamp_us;
                                    memcpy(drifts_to_recreate[drift_recreate_count].recipient_pubkey, dc->recipient_pubkey, PUBKEY_LEN);
                                    drifts_to_recreate[drift_recreate_count].amount = dc->amount;
                                    drift_recreate_count++;
                                    fprintf(stderr, "[Network] Collected local drift cert for recreation, amount=%llu subunits\n", dc->amount);
                                }
                            }
                        }
                    }
                }
                free(op);
            }
        }
    }

    scl_log(LOG_LEVEL_DEBUG, "Network", "Cleaned pending_operations, removed %zu operations", removed_count);

    // Spawn background recreation tasks
    for (size_t i = 0; i < transfer_recreate_count; i++) {
        RecreateArgs *args = calloc(1, sizeof(RecreateArgs));
        if (args) {
            args->state = state;
            args->amount = transfers_to_recreate[i].amount;
            args->is_transfer = true;
            args->is_stake = false;
            memcpy(args->recipient_pubkey, transfers_to_recreate[i].recipient_pubkey, PUBKEY_LEN);
            uint64_t fee = calculate_fee(args->amount, false);
            atomic_fetch_add(&state->scheduled_consumed_subunits, args->amount + fee);
            spawn_recreation_thread(state, args);
        }
    }

    for (size_t i = 0; i < stake_recreate_count; i++) {
        RecreateArgs *args = calloc(1, sizeof(RecreateArgs));
        if (args) {
            args->state = state;
            args->amount = stakes_to_recreate[i].amount;
            args->is_stake = true;
            args->is_transfer = false;
            uint64_t fee = calculate_fee(args->amount, true);
            atomic_fetch_add(&state->scheduled_consumed_subunits, args->amount + fee);
            spawn_recreation_thread(state, args);
        }
    }

    for (size_t i = 0; i < unstake_recreate_count; i++) {
        RecreateArgs *args = calloc(1, sizeof(RecreateArgs));
        if (args) {
            args->state = state;
            args->amount = unstakes_to_recreate[i].amount;
            args->is_stake = false;
            args->is_transfer = false;
            uint64_t fee = calculate_fee(args->amount, true);
            atomic_fetch_add(&state->scheduled_staked_subunits, args->amount + fee);
            spawn_recreation_thread(state, args);
        }
    }

    for (size_t i = 0; i < drift_recreate_count; i++) {
        RecreateArgs *args = calloc(1, sizeof(RecreateArgs));
        if (args) {
            args->state = state;
            args->is_drift_cert = true;
            args->is_transfer = false;
            args->is_stake = false;
            args->amount = drifts_to_recreate[i].amount;
            memcpy(args->circuit_hash, drifts_to_recreate[i].circuit_hash, 32);
            memcpy(args->commitment_root, drifts_to_recreate[i].commitment_root, 32);
            args->tvd_scaled = drifts_to_recreate[i].tvd_scaled;
            args->shots = drifts_to_recreate[i].shots;
            args->status = drifts_to_recreate[i].status;
            args->timestamp_us = drifts_to_recreate[i].timestamp_us;
            memcpy(args->recipient_pubkey, drifts_to_recreate[i].recipient_pubkey, PUBKEY_LEN);
            uint64_t fee = calculate_fee(args->amount, true);
            atomic_fetch_add(&state->scheduled_consumed_subunits, args->amount + fee);
            spawn_recreation_thread(state, args);
        }
    }

    free(transfers_to_recreate);
    free(stakes_to_recreate);
    free(unstakes_to_recreate);
    free(drifts_to_recreate);
}

/**
 * @brief Evaluates canonical SHA-256 state anchor digest over an SCLCoin structure.
 *
 * @details
 * Deterministically serializes immutable coin identity fields, total and remaining subunits,
 * and frozen 10x10 Game Audit matrix rows into a contiguous hashing buffer.
 *
 * @param[in] coin Source SCLCoin structure.
 * @param[out] hash 32-byte destination receiving canonical state anchor digest.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(1) heap allocation.
 */
void compute_canonical_sclcoin_hash(const SCLCoin *coin, uint8_t *hash) {
    size_t anchored_data_size = COIN_ID_LEN * 2 + USER_ID_LEN +
                                    sizeof(uint64_t) * 2 +
                                    sizeof(uint32_t) * 2 +
                                    AUDIT_SIZE * (USER_ID_LEN + NUMBERS_PER_VALUATION * sizeof(uint32_t) + sizeof(uint64_t) + 32);
                                
    uint8_t *hash_input = malloc(anchored_data_size);
    if (!hash_input) return;
        
    uint8_t *p = hash_input;
    
    // 1. SCLCoin Header Fields
    memcpy(p, coin->coin_id, COIN_ID_LEN); p += COIN_ID_LEN;
    memcpy(p, coin->owner_address, USER_ID_LEN); p += USER_ID_LEN;
    memcpy(p, coin->creation_tx_hash, COIN_ID_LEN); p += COIN_ID_LEN;
    
    uint64_t total_subunits_be = htobe64(coin->total_subunits);
    memcpy(p, &total_subunits_be, sizeof(uint64_t)); p += sizeof(uint64_t);
    uint64_t remaining_subunits_be = htobe64(coin->remaining_subunits);
    memcpy(p, &remaining_subunits_be, sizeof(uint64_t)); p += sizeof(uint64_t);

    // 2. Frozen 10x10 Game Audit Matrix Rows
    for (uint32_t i = 0; i < AUDIT_SIZE; i++) {
        const Valuation *val = &coin->audit_snapshot[i];
        memcpy(p, val->user_id, USER_ID_LEN); p += USER_ID_LEN;
            
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            uint32_t net_num = htonl((uint32_t)val->numbers[j]);
            memcpy(p, &net_num, sizeof(uint32_t)); p += sizeof(uint32_t);
        }
            
        uint64_t ts_net = htobe64(val->timestamp);
        memcpy(p, &ts_net, sizeof(uint64_t)); p += sizeof(uint64_t);
        memcpy(p, val->beacon_seed, 32); p += 32;
    }

    // 3. Audit Snapshot Metadata
    uint32_t snapshot_count_be = htonl(coin->snapshot_count);
    memcpy(p, &snapshot_count_be, sizeof(uint32_t)); p += sizeof(uint32_t);

    uint32_t snapshot_audit_index_be = htonl(coin->snapshot_audit_index);
    memcpy(p, &snapshot_audit_index_be, sizeof(uint32_t)); p += sizeof(uint32_t);
    
    SHA256(hash_input, p - hash_input, hash);
    free(hash_input);
}

/**
 * @brief Derives or returns cached Joint-RSS threshold public key for current epoch.
 *
 * @param[in,out] state Global node state container.
 * @param[out] threshold_pubkey 2,592-byte buffer receiving Dilithium5 threshold public key.
 * @return 0 on success; -1 on derivation failure.
 *
 * @complexity Time: O(1) when cached; O(threshold_keygen) on cache miss, Space: O(1).
 */
int compute_threshold_pubkey(State *state, uint8_t threshold_pubkey[PUBKEY_LEN]) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST) && !defined(CRYPTO_ZK_FUZZER)
    (void)state;
    if (threshold_pubkey) memset(threshold_pubkey, 0x42, PUBKEY_LEN);
    return 0;
#else
    if (!state || !threshold_pubkey) {
        fprintf(stderr, "[Client] ERROR: Invalid parameters in compute_threshold_pubkey\n");
        return -1;
    }
#endif

    // Cache the deterministic threshold key to eliminate redundant matrix math on balance checks
    static uint8_t cached_pubkey[PUBKEY_LEN];
    static uint8_t cached_seed[32];
    static bool is_cached = false;

    pthread_mutex_lock(&state->wallet_mutex);
    
    uint8_t keygen_seed[32];
    SHA256(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, keygen_seed);

    if (is_cached && memcmp(keygen_seed, cached_seed, 32) == 0) {
        memcpy(threshold_pubkey, cached_pubkey, PUBKEY_LEN);
        pthread_mutex_unlock(&state->wallet_mutex);
        return 0;
    }

    ThresholdKeygenData *keygen = calloc(1, sizeof(ThresholdKeygenData));
    if (!keygen) {
        pthread_mutex_unlock(&state->wallet_mutex);
        return -1;
    }

    uint16_t point_ids[10];
    for (int i = 0; i < 10; i++) point_ids[i] = i;
    
    int result = threshold_keygen(state, keygen, keygen_seed, 32, point_ids, 10, 2);
    
    if (result == CRYPTO_SUCCESS) {
        memcpy(threshold_pubkey, keygen->pubkey, PUBKEY_LEN);
        memcpy(cached_pubkey, keygen->pubkey, PUBKEY_LEN);
        memcpy(cached_seed, keygen_seed, 32);
        is_cached = true;
    }

    cleanup_keygen_data(keygen);
    free(keygen);
    
    pthread_mutex_unlock(&state->wallet_mutex);
    return (result == CRYPTO_SUCCESS) ? 0 : -1;
}

/**
 * @brief Evaluates whether a valuation vector is present in the circular Game Audit matrix.
 *
 * @param[in] gs GameState structure pointer.
 * @param[in] v Candidate Valuation pointer.
 * @return 1 if exact match exists; 0 otherwise.
 * @complexity Time: O(AUDIT_SIZE), Space: O(1).
 */
int is_valuation_in_audit(GameState *gs, const Valuation *v) {
    for (int i = 0; i < gs->valuation_count; i++) {
        int index = (gs->current_audit_index - gs->valuation_count + i + AUDIT_SIZE) % AUDIT_SIZE;
        if (memcmp(&gs->game_audit[index], v, sizeof(Valuation)) == 0) {
            return 1;
        }
    }
    return 0;
}

#ifndef __EMSCRIPTEN__
/**
 * @brief Evaluates whether a target integer collapses in a matrix column via quantum superposition.
 *
 * @param[in] target_number Integer tested for constructive interference (0..99).
 * @param[in] column_numbers Array of column integers.
 * @param[in] N Number of column rows.
 * @param[in] active_nodes Distinct validator identity count contributing to column.
 * @param[in] beacon_seed Current epoch randomness beacon seed.
 * @return 1 on measurement hit; 0 otherwise.
 * @complexity Time: O(M) where M is shot budget [1000..50000], Space: O(1).
 */
int quantum_check_number_in_column(int target_number, const int *column_numbers, size_t N, size_t active_nodes, const uint8_t *beacon_seed) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 1;
#endif
    return quantum_check_number_in_column_qsim(target_number, column_numbers, N, active_nodes, beacon_seed);
}
#endif

/**
 * @brief Evaluates whether two operations share identical input pointers or nullifiers.
 *
 * @param[in] op1 First operation pointer.
 * @param[in] op2 Second operation pointer.
 * @return `true` if double-spend conflict detected; `false` otherwise.
 * @complexity Time: O(num_inputs1 * num_inputs2), Space: O(1).
 */
static bool operations_share_inputs(const Operation *op1, const Operation *op2) {
    uint32_t num1 = 0, num2 = 0;
    const Pointer *in1 = NULL, *in2 = NULL;
    if (op1->type == OP_REDEEM_CENTINEL && op2->type == OP_REDEEM_CENTINEL) {
        if (memcmp(op1->data.redeem_centinel.nullifier, op2->data.redeem_centinel.nullifier, NULLIFIER_LEN) == 0) {
            return true;
        }
    }
    if (op1->type == OP_TRANSFER_POINTER) { num1 = op1->data.transfer_pointer.num_inputs; in1 = op1->data.transfer_pointer.inputs; }
    else if (op1->type == OP_STAKE) { num1 = op1->data.stake.num_inputs; in1 = op1->data.stake.inputs; }
    else if (op1->type == OP_UNSTAKE) { num1 = op1->data.unstake.num_inputs; in1 = op1->data.unstake.inputs; }
    else if (op1->type == OP_APPLY_DRIFT_CERT) { num1 = op1->data.apply_drift_cert.num_inputs; in1 = op1->data.apply_drift_cert.inputs; }

    if (op2->type == OP_TRANSFER_POINTER) { num2 = op2->data.transfer_pointer.num_inputs; in2 = op2->data.transfer_pointer.inputs; }
    else if (op2->type == OP_STAKE) { num2 = op2->data.stake.num_inputs; in2 = op2->data.stake.inputs; }
    else if (op2->type == OP_UNSTAKE) { num2 = op2->data.unstake.num_inputs; in2 = op2->data.unstake.inputs; }
    else if (op2->type == OP_APPLY_DRIFT_CERT) { num2 = op2->data.apply_drift_cert.num_inputs; in2 = op2->data.apply_drift_cert.inputs; }

    for (uint32_t i = 0; i < num1; i++) {
        for (uint32_t j = 0; j < num2; j++) {
            if (memcmp(in1[i].pointer_id, in2[j].pointer_id, COIN_ID_LEN) == 0) {
                return true;
            }
        }
    }
    return false;
}

/* ============================================================================ */
/* SECTION 8: SHIELDED CENTINEL UTXO MANAGEMENT & SCANNING                      */
/* ============================================================================ */

/**
 * @brief Consumes and burns unspent validation UTXOs to fund valuation submissions.
 *
 * @details
 * Selects candidate unspent ValidationUTXOs from local wallet:
 * 1. Verifies that candidate nullifier is unspent in RAM, Bloom filter, and disk DB.
 * 2. Generates ZK-Centinel redemption proof consuming C_old and creating change C_change.
 * 3. Broadcasts OP_REDEEM_CENTINEL to P2P network to finalize burning on-chain.
 *
 * @param[in,out] state Global node state container.
 * @param[in] amount Number of validation credits to burn.
 * @return 0 on success; -1 if available unspent validation credits are insufficient.
 *
 * @complexity Time: O(num_utxos), Space: O(num_utxos) heap buffers.
 */
int consume_utxos_for_amount(State *state, uint64_t amount) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)amount;
    return 0;
#else
    uint64_t accumulated = 0;
    size_t max_possible = state->user_wallet.num_val_utxos;
    if (max_possible == 0) return -1;
    BdlopCommitment *selected_commitments = malloc(max_possible * sizeof(BdlopCommitment));
    if (!selected_commitments) return -1;
    size_t num_selected = 0;

    pthread_rwlock_rdlock(&state->bc.rwlock);
    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
        ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
        bool is_spent = hash_table_lookup(state->bc.centinel.nullifier_set, utxo->nullifier, true) != NULL ||
                       (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, utxo->nullifier) &&
                        scl_db_has_nullifier(utxo->nullifier));
            
        bool is_pending_spend = false;
        for (int k = 0; k < MAX_PENDING_OPS; k++) {
            Operation *pop = atomic_load_explicit(&state->pending_operations[k], memory_order_acquire);
            if (pop && pop->type == OP_REDEEM_CENTINEL && memcmp(pop->data.redeem_centinel.nullifier, utxo->nullifier, NULLIFIER_LEN) == 0) {
                is_pending_spend = true;
                break;
            }
        }
                
        if (!is_spent && !is_pending_spend) {
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&utxo->commitment, sizeof(BdlopCommitment), commitment_hash);
            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, commitment_hash, 0) >= 0) {
                memcpy(&selected_commitments[num_selected++], &utxo->commitment, sizeof(BdlopCommitment));
                accumulated += utxo->amount;
                if (accumulated >= amount) {
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
    pthread_rwlock_unlock(&state->bc.rwlock);

    if (accumulated < amount) {
        free(selected_commitments);
        return -1;
    }

    uint64_t remaining_to_fulfill = amount;

    for (size_t i = 0; i < num_selected; i++) {
        uint64_t v_old = 0;
        uint8_t r_old[32] = {0};
        uint8_t pk_old[PUBKEY_LEN] = {0};
        PRFKey prf_key_old;
        int found = 0;

        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        for (size_t j = 0; j < state->user_wallet.num_val_utxos; j++) {
            if (memcmp(&state->user_wallet.val_utxos[j].commitment, &selected_commitments[i], sizeof(BdlopCommitment)) == 0) {
                ValidationUTXO *utxo = &state->user_wallet.val_utxos[j];
                v_old = utxo->amount;
                memcpy(r_old, utxo->blinding_factor, 32);
                memcpy(pk_old, utxo->pubkey, PUBKEY_LEN);
                prf_key_old = utxo->prf_key;
                found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

        if (!found) continue;

        uint64_t amount_to_take = (v_old > remaining_to_fulfill) ? remaining_to_fulfill : v_old;
        uint64_t change_amount = v_old - amount_to_take;

        uint8_t r_transfer[32], r_change[32];
        RAND_bytes(r_transfer, 32);
        if (change_amount > 0) {
            pthread_mutex_lock(&state->user_wallet.utxo_mutex);
            uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
            memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
            int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", state->user_wallet.num_val_utxos);
            SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, r_change);
            pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
        } else {
            RAND_bytes(r_change, 32);
        }

        uint8_t root[COIN_ID_LEN];
        pthread_rwlock_rdlock(&state->bc.rwlock);
        mmr_get_root(state->bc.centinel.validation_commitments, root);
        
        uint8_t c_old_hash[COIN_ID_LEN];
        SHA256((const uint8_t*)&selected_commitments[i], sizeof(BdlopCommitment), c_old_hash);
        ssize_t leaf_pos = mmr_get_leaf_position(state->bc.centinel.validation_commitments, c_old_hash, 0);
        MMRProof proof = {0};
        if (leaf_pos >= 0) {
            mmr_generate_proof(state->bc.centinel.validation_commitments, (size_t)leaf_pos, proof.path_hashes, proof.is_left, &proof.path_len, proof.left_peaks, &proof.left_peaks_len, proof.right_peaks, &proof.right_peaks_len);
        }
        pthread_rwlock_unlock(&state->bc.rwlock);

        uint8_t burn_pubkey[PUBKEY_LEN] = {0};
        RedeemCentinelData *rc_data = calloc(1, sizeof(RedeemCentinelData));
        if (!rc_data) continue;

        if (change_amount > 0) {
            generate_centinel_proof(
                pk_old, v_old, r_old,
                burn_pubkey, amount_to_take, r_transfer,
                state->user_wallet.dilithium_pubkey, change_amount, r_change,
                &prf_key_old, root, &proof, rc_data
            );
        } else {
            generate_centinel_proof(
                pk_old, v_old, r_old,
                burn_pubkey, amount_to_take, r_transfer,
                state->user_wallet.dilithium_pubkey, 0, r_change,
                &prf_key_old, root, &proof, rc_data
            );
            memset(&rc_data->c_change, 0, sizeof(BdlopCommitment));
        }

        Operation *burn_op = calloc(1, sizeof(Operation));
        if (!burn_op) {
            free(rc_data);
            continue;
        }
        burn_op->type = OP_REDEEM_CENTINEL;
        memcpy(&burn_op->data.redeem_centinel, rc_data, sizeof(RedeemCentinelData));
        free(rc_data);

        Message *burn_msg = calloc(1, sizeof(Message));
        burn_msg->type = MSG_REDEEM_CENTINEL;
        burn_msg->length = serialize_operation(burn_op, burn_msg->payload, MAX_MESSAGE_SIZE);

        if (verify_operation_heavy_crypto(burn_op) != CRYPTO_SUCCESS) {
            free(burn_msg);
            free(burn_op);
            continue;
        }

        int added = add_pending_operation(state, burn_op);

        if (added == 0) {
            p2p_broadcast(state, burn_msg);
        } else {
            printf("ERROR: Failed to add Centinel Ticket operation to mempool.\n");
        }
        free(burn_msg);
        free(burn_op);

        remaining_to_fulfill -= amount_to_take;
        if (remaining_to_fulfill == 0) break;
    }
    free(selected_commitments);
    return 0;
#endif
}

/**
 * @brief Finds the first sequential SCL_VAL_UTXO derivation tag whose nullifier is unspent.
 *
 * @details
 * Wallet blinding factors are derived deterministically as
 * `r = SHA256(privkey || "SCL_VAL_UTXO_<tag>")` and a UTXO's nullifier is a function of
 * (tag, amount). The wallet's tag counter (`num_val_utxos`) lives in RAM only, so it resets
 * on every restart while the persistent nullifier store (Bloom + libmdbx) remembers every
 * pre-restart spend. Re-minting a (tag, amount) pair that was already spent produces a
 * "born spent" UTXO that GetBalance's is_spent filter silently drops. This helper advances
 * past such collisions.
 *
 * @param[in] state Global node state container.
 * @param[in] privkey 4,864-byte Dilithium private key owning the tag space.
 * @param[in] amount Committed value the caller will pair with the tag.
 * @param[in] start_tag First tag index to probe (the wallet high-water mark).
 * @return First unspent tag, or start_tag if none is found within the guard window.
 *
 * @complexity Time: O(guard * BDLOP_COMMIT), Space: O(1).
 */
size_t scl_next_unspent_val_tag(State *state, const uint8_t *privkey, uint64_t amount, size_t start_tag) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)privkey; (void)amount;
    return start_tag;
#else
    if (!state || !privkey || is_zeroed(privkey, DILITHIUM_SECRETKEY_LEN)) return start_tag;
    if (!state->bc.centinel.nullifier_set) return start_tag;

    for (size_t tag = start_tag; tag < start_tag + 4096; tag++) {
        uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
        memcpy(r_input, privkey, DILITHIUM_SECRETKEY_LEN);
        int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", tag);
        uint8_t r_mint[32];
        SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, r_mint);

        BdlopCommitment probe;
        if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, amount, r_mint, &probe) != CRYPTO_SUCCESS) continue;

        uint8_t probe_hash[COIN_ID_LEN];
        SHA256((const uint8_t*)&probe, sizeof(BdlopCommitment), probe_hash);

        PRFKey probe_prf;
        prf_keygen(&probe_prf, r_mint, 32);
        uint8_t probe_nullifier[NULLIFIER_LEN];
        prf_evaluate(probe_nullifier, &probe_prf, probe_hash, COIN_ID_LEN, probe_hash);

        pthread_rwlock_rdlock(&state->bc.rwlock);
        bool spent = hash_table_lookup(state->bc.centinel.nullifier_set, probe_nullifier, true) != NULL ||
                     (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, probe_nullifier) &&
                      scl_db_has_nullifier(probe_nullifier));
        pthread_rwlock_unlock(&state->bc.rwlock);

        if (!spent) return tag;
    }
    return start_tag;
#endif
}

/**
 * @brief Scans an on-chain OP_REDEEM_CENTINEL operation to discover incoming transfer or change commitments.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Operation structure to inspect.
 *
 * @complexity Time: O(SCL_WALLET_SCAN_WINDOW), Space: O(1).
 */
void scl_wallet_scan_centinel_op(State *state, const Operation *op) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)op;
    return;
#else
    if (!state || !op || op->type != OP_REDEEM_CENTINEL) return;
    if (is_zeroed(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN)) return;
#endif

    const RedeemCentinelData *rc = &op->data.redeem_centinel;
    const BdlopCommitment *targets[2] = { &rc->c_transfer, &rc->c_change };

    uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

    size_t scan_idx_marker = 0;

    for (int t = 0; t < 2; t++) {
        if (is_zeroed((const uint8_t*)targets[t], sizeof(BdlopCommitment))) continue;

        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        bool already_have = false;
        for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
            if (memcmp(&state->user_wallet.val_utxos[i].commitment, targets[t], sizeof(BdlopCommitment)) == 0) {
                already_have = true;
                break;
            }
        }
        size_t scan_limit = state->user_wallet.num_val_utxos + SCL_WALLET_SCAN_WINDOW;
        if (scan_limit < SCL_WALLET_SCAN_WINDOW) scan_limit = SCL_WALLET_SCAN_WINDOW;
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

        if (already_have) continue;

        size_t start_idx = scan_idx_marker;
        
        for (size_t i = 0; i < scan_limit; i++) {
            size_t idx = (start_idx + i) % scan_limit;
            int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", idx);
            uint8_t candidate_r[32];
            SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, candidate_r);

            BdlopCommitment check_comm;
            if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, 0, candidate_r, &check_comm) != CRYPTO_SUCCESS) {
                continue;
            }
            if (memcmp(check_comm.c1, targets[t]->c1, BDLOP_COEFF_BYTES) != 0) {
                continue;
            }

            uint64_t amount = 0;
            if (bdlop_decrypt((const uint8_t*)BDLOP_RHO_SEED, targets[t], candidate_r, &amount) == CRYPTO_SUCCESS && amount > 0) {
                pthread_mutex_lock(&state->user_wallet.utxo_mutex);
                if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
                    size_t new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
                    ValidationUTXO *new_utxos = realloc(state->user_wallet.val_utxos, new_cap * sizeof(ValidationUTXO));
                    if (new_utxos) {
                        state->user_wallet.val_utxos = new_utxos;
                        state->user_wallet.cap_val_utxos = new_cap;
                    }
                }
                if (state->user_wallet.num_val_utxos < state->user_wallet.cap_val_utxos) {
                    ValidationUTXO *utxo = &state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++];
                    memset(utxo, 0, sizeof(ValidationUTXO));
                    memcpy(&utxo->commitment, targets[t], sizeof(BdlopCommitment));
                    utxo->amount = amount;
                    memcpy(utxo->blinding_factor, candidate_r, 32);
                    memcpy(utxo->pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                    prf_keygen(&utxo->prf_key, candidate_r, 32);

                    uint8_t commitment_hash[COIN_ID_LEN];
                    SHA256((const uint8_t*)&utxo->commitment, sizeof(BdlopCommitment), commitment_hash);
                    prf_evaluate(utxo->nullifier, &utxo->prf_key, commitment_hash, COIN_ID_LEN, commitment_hash);
                    
                    scl_log(LOG_LEVEL_INFO, "Wallet", "Auto-detected and registered new %llu UTXO validation grant in CLI wallet", amount);
                }
                pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
                scan_idx_marker = idx + 1;
                goto next_target;
            }
        }
next_target:;
    }
}

/**
 * @brief Scans historical block state from database to rebuild unspent validation UTXOs.
 *
 * @param[in,out] state Global node state container.
 *
 * @complexity Time: O(block_count * operations_per_block * scan_window), Space: O(commitments).
 */
void scl_wallet_rescan_utxos(State *state) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state;
    return;
#else
    if (!state) return;
    if (is_zeroed(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN)) return;
#endif

    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    state->user_wallet.num_val_utxos = 0; // Clear active UTXOs for rescan
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

    pthread_rwlock_rdlock(&state->bc.rwlock);
    if (!state->bc.centinel.validation_commitments || state->bc.centinel.validation_commitments->count == 0) {
        pthread_rwlock_unlock(&state->bc.rwlock);
        return;
    }
    pthread_rwlock_unlock(&state->bc.rwlock);

    size_t comm_cap = 64;
    size_t comm_count = 0;
    BdlopCommitment *block_comms = malloc(comm_cap * sizeof(BdlopCommitment));

    pthread_rwlock_rdlock(&state->bc.rwlock);
    size_t block_limit = state->current_block_number + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (block_limit > 16) block_limit = 16;
#endif
    for (size_t b_idx = 0; b_idx < block_limit; b_idx++) {
        uint8_t *ser_block = NULL;
        size_t ser_len = 0;
        if (scl_db_get_block(b_idx, &ser_block, &ser_len) != 0) continue;

        Block *block = calloc(1, sizeof(Block));
        if (!block || deserialize_block(block, ser_block, ser_len) != 0) {
            if (block) free_block(block);
            free(ser_block);
            continue;
        }
        free(ser_block);

        for (size_t i = 0; i < block->operation_count; i++) {
            const Operation *op = &block->operations[i];
            if (op->type == OP_CLAIM_VALIDATION) {
                if (comm_count >= comm_cap) {
                    comm_cap *= 2;
                    BdlopCommitment *new_comms = realloc(block_comms, comm_cap * sizeof(BdlopCommitment));
                    if (new_comms) block_comms = new_comms;
                }
                if (block_comms && comm_count < comm_cap) {
                    block_comms[comm_count++] = op->data.claim_validation.commitment;
                }
            } else if (op->type == OP_REDEEM_CENTINEL) {
                const RedeemCentinelData *rc = &op->data.redeem_centinel;
                if (!is_zeroed((const uint8_t*)&rc->c_transfer, sizeof(BdlopCommitment))) {
                    if (comm_count >= comm_cap) {
                        comm_cap *= 2;
                        BdlopCommitment *new_comms = realloc(block_comms, comm_cap * sizeof(BdlopCommitment));
                        if (new_comms) block_comms = new_comms;
                    }
                    if (block_comms && comm_count < comm_cap) {
                        block_comms[comm_count++] = rc->c_transfer;
                    }
                }
                if (!is_zeroed((const uint8_t*)&rc->c_change, sizeof(BdlopCommitment))) {
                    if (comm_count >= comm_cap) {
                        comm_cap *= 2;
                        BdlopCommitment *new_comms = realloc(block_comms, comm_cap * sizeof(BdlopCommitment));
                        if (new_comms) block_comms = new_comms;
                    }
                    if (block_comms && comm_count < comm_cap) {
                        block_comms[comm_count++] = rc->c_change;
                    }
                }
            }
        }
        free_block(block);
    }
    pthread_rwlock_unlock(&state->bc.rwlock);

    if (comm_count == 0 || !block_comms) {
        if (block_comms) free(block_comms);
        /* Born-spent genesis guard (restart fallback): derive at the first unspent
         * tag — computed BEFORE taking utxo_mutex because the helper acquires
         * bc.rwlock (read), and GetBalance takes those two locks in the opposite
         * order. Must match user_init()'s derivation so both minting sites agree. */
        uint8_t genesis_privkey[DILITHIUM_SECRETKEY_LEN];
        pthread_mutex_lock(&state->wallet_mutex);
        memcpy(genesis_privkey, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
        pthread_mutex_unlock(&state->wallet_mutex);
        size_t genesis_tag = scl_next_unspent_val_tag(state, genesis_privkey, INITIAL_VALIDATION_CREDITS, 0);
        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        if (state->user_wallet.num_val_utxos == 0) {
            uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
            memcpy(r_input, genesis_privkey, DILITHIUM_SECRETKEY_LEN);

            int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", genesis_tag);
            uint8_t r_init[32];
            SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, r_init);

            ValidationUTXO init_utxo = {0};
            init_utxo.amount = INITIAL_VALIDATION_CREDITS;
            memcpy(init_utxo.blinding_factor, r_init, 32);
            memcpy(init_utxo.pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            prf_keygen(&init_utxo.prf_key, r_init, 32);
            bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, INITIAL_VALIDATION_CREDITS, r_init, &init_utxo.commitment);

            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&init_utxo.commitment, sizeof(BdlopCommitment), commitment_hash);
            prf_evaluate(init_utxo.nullifier, &init_utxo.prf_key, commitment_hash, COIN_ID_LEN, commitment_hash);

            if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
                size_t new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
                ValidationUTXO *new_utxos = realloc(state->user_wallet.val_utxos, new_cap * sizeof(ValidationUTXO));
                if (new_utxos) {
                    state->user_wallet.val_utxos = new_utxos;
                    state->user_wallet.cap_val_utxos = new_cap;
                }
            }
            state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++] = init_utxo;
        }
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
        return;
    }

    uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
    pthread_mutex_lock(&state->wallet_mutex);
    memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    pthread_mutex_unlock(&state->wallet_mutex);

    pthread_rwlock_rdlock(&state->bc.rwlock);
    size_t mmr_leaf_count = state->bc.centinel.validation_commitments ? state->bc.centinel.validation_commitments->count : 0;
    pthread_rwlock_unlock(&state->bc.rwlock);

    size_t scan_limit = (comm_count > mmr_leaf_count ? comm_count : mmr_leaf_count) + SCL_WALLET_SCAN_WINDOW;
    for (size_t idx = 0; idx < scan_limit; idx++) {
        int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", idx);
        uint8_t candidate_r[32];
        SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, candidate_r);

        BdlopCommitment check_comm;
        if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, 0, candidate_r, &check_comm) != CRYPTO_SUCCESS) {
            continue;
        }

        for (size_t c_i = 0; c_i < comm_count; c_i++) {
            if (memcmp(check_comm.c1, block_comms[c_i].c1, BDLOP_COEFF_BYTES) != 0) {
                continue;
            }

            uint64_t amount = 0;
            if (bdlop_decrypt((const uint8_t*)BDLOP_RHO_SEED, &block_comms[c_i], candidate_r, &amount) == CRYPTO_SUCCESS && amount > 0) {
                uint8_t commitment_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&block_comms[c_i], sizeof(BdlopCommitment), commitment_hash);

                pthread_rwlock_rdlock(&state->bc.rwlock);
                bool leaf_exists = (mmr_get_leaf_position(state->bc.centinel.validation_commitments, commitment_hash, 0) >= 0);
                pthread_rwlock_unlock(&state->bc.rwlock);

                if (leaf_exists) {
                    PRFKey prf_key;
                    prf_keygen(&prf_key, candidate_r, 32);
                    uint8_t nullifier[NULLIFIER_LEN];
                    prf_evaluate(nullifier, &prf_key, commitment_hash, COIN_ID_LEN, commitment_hash);

                    pthread_rwlock_rdlock(&state->bc.rwlock);
                    bool is_spent = hash_table_lookup(state->bc.centinel.nullifier_set, nullifier, true) != NULL ||
                                   (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, nullifier) &&
                                    scl_db_has_nullifier(nullifier));
                    pthread_rwlock_unlock(&state->bc.rwlock);

                    if (!is_spent) {
                        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
                        bool already_have = false;
                        for (size_t h = 0; h < state->user_wallet.num_val_utxos; h++) {
                            if (memcmp(&state->user_wallet.val_utxos[h].commitment, &block_comms[c_i], sizeof(BdlopCommitment)) == 0) {
                                already_have = true;
                                break;
                            }
                        }
                        if (!already_have) {
                            if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
                                size_t new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
                                ValidationUTXO *new_utxos = realloc(state->user_wallet.val_utxos, new_cap * sizeof(ValidationUTXO));
                                if (new_utxos) {
                                    state->user_wallet.val_utxos = new_utxos;
                                    state->user_wallet.cap_val_utxos = new_cap;
                                }
                            }
                            if (state->user_wallet.num_val_utxos < state->user_wallet.cap_val_utxos) {
                                ValidationUTXO *utxo = &state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++];
                                memset(utxo, 0, sizeof(ValidationUTXO));
                                memcpy(&utxo->commitment, &block_comms[c_i], sizeof(BdlopCommitment));
                                utxo->amount = amount;
                                memcpy(utxo->blinding_factor, candidate_r, 32);
                                memcpy(utxo->pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                                utxo->prf_key = prf_key;
                                memcpy(utxo->nullifier, nullifier, NULLIFIER_LEN);
                            }
                        }
                        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
                    }
                }
            }
        }
        if ((idx & 0x1F) == 0) usleep(100);
    }
    free(block_comms);
}

/**
 * @brief Scans an on-chain OP_CLAIM_VALIDATION operation to register new validation UTXO commitments.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Operation structure to inspect.
 *
 * @complexity Time: O(SCL_WALLET_SCAN_WINDOW), Space: O(1).
 */
void scl_wallet_scan_claim_op(State *state, const Operation *op) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)op;
    return;
#else
    if (!state || !op || op->type != OP_CLAIM_VALIDATION) return;
    if (is_zeroed(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN)) return;
#endif

    const ClaimValidationData *cv = &op->data.claim_validation;
    if (memcmp(cv->pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) != 0) return;

    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    
    bool already_have = false;
    for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
        if (memcmp(&state->user_wallet.val_utxos[i].commitment, &cv->commitment, sizeof(BdlopCommitment)) == 0) {
            already_have = true;
            break;
        }
    }
    size_t scan_limit = state->user_wallet.num_val_utxos + SCL_WALLET_SCAN_WINDOW;
    if (scan_limit < SCL_WALLET_SCAN_WINDOW) scan_limit = SCL_WALLET_SCAN_WINDOW;
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

    if (already_have) {
        return;
    }

    uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
    
    for (size_t idx = 0; idx < scan_limit; idx++) {
        int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", idx);
        uint8_t candidate_r[32];
        SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, candidate_r);

        BdlopCommitment check_comm;
        if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, 0, candidate_r, &check_comm) != CRYPTO_SUCCESS) {
            continue;
        }
        if (memcmp(check_comm.c1, cv->commitment.c1, BDLOP_COEFF_BYTES) != 0) {
            continue;
        }

        uint64_t amount = 0;
        if (bdlop_decrypt((const uint8_t*)BDLOP_RHO_SEED, &cv->commitment, candidate_r, &amount) == CRYPTO_SUCCESS && amount > 0) {
            pthread_mutex_lock(&state->user_wallet.utxo_mutex);
            if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
                size_t new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
                ValidationUTXO *new_utxos = realloc(state->user_wallet.val_utxos, new_cap * sizeof(ValidationUTXO));
                if (new_utxos) {
                    state->user_wallet.val_utxos = new_utxos;
                    state->user_wallet.cap_val_utxos = new_cap;
                }
            }
            if (state->user_wallet.num_val_utxos < state->user_wallet.cap_val_utxos) {
                ValidationUTXO *utxo = &state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++];
                memset(utxo, 0, sizeof(ValidationUTXO));
                memcpy(&utxo->commitment, &cv->commitment, sizeof(BdlopCommitment));
                utxo->amount = amount;
                memcpy(utxo->blinding_factor, candidate_r, 32);
                memcpy(utxo->pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                prf_keygen(&utxo->prf_key, candidate_r, 32);

                uint8_t commitment_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&utxo->commitment, sizeof(BdlopCommitment), commitment_hash);
                prf_evaluate(utxo->nullifier, &utxo->prf_key, commitment_hash, COIN_ID_LEN, commitment_hash);
                
                scl_log(LOG_LEVEL_INFO, "Wallet", "Auto-detected and registered new %llu UTXO validation claim in CLI wallet", amount);
            }
            pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
            goto next_target_claim;
        }
    }
next_target_claim:;
}

/* ============================================================================ */
/* SECTION 9: MEMPOOL INGESTION & REPLACE-BY-FEE (RBF) ARCHITECTURE             */
/* ============================================================================ */

/**
 * @brief Ingests an unconfirmed operation into the lock-free mempool array with RBF eviction.
 *
 * @details
 * Ingestion pipeline:
 * 1. Derives canonical transaction key; rejects transactions already confirmed on-chain.
 * 2. Validates operation integrity and verifies spent input pointers exist and are unspent.
 * 3. Handles off-chain operations (Valuations, Centinel Redemptions, Claims) directly.
 * 4. Scans lock-free mempool array:
 *    - Replaces existing transaction if new transaction provides higher fee (Replace-By-Fee).
 *    - Rejects transaction if any input pointer or nullifier conflicts with an in-flight entry.
 *    - Tracks lowest-fee transaction in case mempool reaches capacity (MAX_PENDING_OPS).
 * 5. If slots remain, inserts via atomic CAS (`atomic_compare_exchange_strong_explicit`).
 * 6. If full, evicts lowest-fee entry provided new fee strictly exceeds it.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Operation structure to ingest.
 * @return 0 on successful insertion; -1 if rejected (duplicate, low fee); -2 on double-spend.
 *
 * @note Thread-safe. Lock-free insertion path using C11 atomics.
 * @complexity Time: O(MAX_PENDING_OPS), Space: O(sizeof(Operation)) heap copy.
 */
int add_pending_operation(State *state, const Operation *op) {
    if (!state || !op) return -1;
    
    uint8_t key[COIN_ID_LEN];
    const uint8_t *op_id = get_operation_tx_id(op);
    if (op_id) {
        memcpy(key, op_id, COIN_ID_LEN);
    } else {
        uint8_t *data;
        size_t data_len;
        if (op->type == OP_SUBMIT_VALUATION) {
            data = (uint8_t *)&op->data.submit_valuation;
            data_len = sizeof(ValuationData);
        } else {
            data = (uint8_t *)op;
            data_len = sizeof(Operation);
        }
        SHA256(data, data_len, key);
    }

    // Reject transactions already committed to ledger
    if (hash_table_lookup(state->processed_txs, key, true)) {
        if (op->type == OP_REDEEM_CENTINEL) return -2;
        return 0;
    }

    // Validate operation rules under blockchain read-lock
    pthread_rwlock_rdlock(&state->bc.rwlock);
    int valid = validate_operation(state, op);

    // Support unconfirmed parent-child transaction chains in mempool
    if (!valid && (op->type == OP_TRANSFER_POINTER || op->type == OP_STAKE || op->type == OP_UNSTAKE)) {
        const uint8_t *prev_tx = NULL;
        if (op->type == OP_TRANSFER_POINTER) prev_tx = op->data.transfer_pointer.inputs[0].prev_tx_hash;
        else if (op->type == OP_STAKE) prev_tx = op->data.stake.inputs[0].prev_tx_hash;
        else if (op->type == OP_UNSTAKE) prev_tx = op->data.unstake.inputs[0].prev_tx_hash;
        
        for (int i = 0; i < MAX_PENDING_OPS; i++) {
            Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
            if (pop) {
                const uint8_t *pid = get_operation_tx_id(pop);
                if (pid && memcmp(pid, prev_tx, COIN_ID_LEN) == 0) {
                    valid = 1; break;
                }
            }
        }
    }
    pthread_rwlock_unlock(&state->bc.rwlock);

    if (!valid) return -1;
    
    // Register nullifier in Bloom filter immediately to prevent disk I/O on subsequent checks
    if (op->type == OP_REDEEM_CENTINEL) {
        pthread_mutex_lock(&state->bc.centinel.bloom_mutex);
        nullifier_bloom_add(state->bc.centinel.nullifier_bloom, op->data.redeem_centinel.nullifier);
        pthread_mutex_unlock(&state->bc.centinel.bloom_mutex);
    }

    // Handle off-chain operations (Valuation proposals directly mutate audit matrix)
    if (op->type == OP_SUBMIT_VALUATION) {
        hash_table_insert(state->processed_txs, key, NULL, HASH_ENTRY_TX);

        Valuation val_copy = op->data.submit_valuation.valuation;

        if (op->is_rpc_injected) {
            uint8_t core_data[sizeof(Valuation)];
            size_t core_len = serialize_core_valuation(&val_copy, core_data);

            Message *prop_msg = calloc(1, sizeof(Message));
            if (prop_msg) {
                prop_msg->type = MSG_VALUATION_PROPOSAL;
                size_t offset = 0;
                memcpy(prop_msg->payload + offset, core_data, core_len); offset += core_len;
                memcpy(prop_msg->payload + offset, op->data.submit_valuation.pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
                memcpy(prop_msg->payload + offset, op->data.submit_valuation.signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
                prop_msg->length = offset;
                p2p_broadcast(state, prop_msg);
                free(prop_msg);
            }
        }

        pthread_mutex_lock(&state->game_state.mutex);
        if (state->current_block_number > 0 && !is_zeroed(state->game_state.current_epoch_signature, SIGNATURE_LEN)) {
            SHA256(state->game_state.current_epoch_signature, SIGNATURE_LEN, val_copy.beacon_seed);
        } else {
            memset(val_copy.beacon_seed, 0, 32);
        }
        pthread_mutex_unlock(&state->game_state.mutex);

        int added_index = add_valuation(state, &val_copy);
        if (added_index >= 0) {
            User *local_user = NULL;
            for (size_t i = 0; i < state->user_count; i++) {
                if (memcmp(state->users[i].dilithium_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                    local_user = &state->users[i];
                    break;
                }
            }

            if (local_user) {
                auto_simulate(state, local_user, &val_copy, added_index);
            }
        }

        scl_log(LOG_LEVEL_DEBUG, "Mempool", "Processed valuation proposal operation");
        return 0;
    }

    // Direct registration for off-chain shielded claims and redemptions
    if (op->type == OP_REDEEM_CENTINEL || op->type == OP_CLAIM_VALIDATION) {
        pthread_rwlock_wrlock(&state->bc.rwlock);
        if (op->type == OP_REDEEM_CENTINEL) {
            int transfer_is_zero = is_zeroed((const uint8_t*)&op->data.redeem_centinel.c_transfer, sizeof(BdlopCommitment));
            if (!transfer_is_zero) {
                uint8_t transfer_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&op->data.redeem_centinel.c_transfer, sizeof(BdlopCommitment), transfer_hash);
                if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, transfer_hash, 0) < 0) {
                    mmr_add(state->bc.centinel.validation_commitments, transfer_hash, 0);
                }
            }
                
            int change_is_zero = is_zeroed((const uint8_t*)&op->data.redeem_centinel.c_change, sizeof(BdlopCommitment));
            if (!change_is_zero) {
                uint8_t change_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&op->data.redeem_centinel.c_change, sizeof(BdlopCommitment), change_hash);
                if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, change_hash, 0) < 0) {
                    mmr_add(state->bc.centinel.validation_commitments, change_hash, 0);
                }
            }
            
            hash_table_insert(state->bc.centinel.nullifier_set, op->data.redeem_centinel.nullifier,
                            NULL, HASH_ENTRY_NULLIFIER);

            pthread_mutex_lock(&state->bc.centinel.bloom_mutex);
            nullifier_bloom_add(state->bc.centinel.nullifier_bloom, op->data.redeem_centinel.nullifier);
            pthread_mutex_unlock(&state->bc.centinel.bloom_mutex);

            uint8_t offchain_nullifier_batch[1][NULLIFIER_LEN];
            memcpy(offchain_nullifier_batch[0], op->data.redeem_centinel.nullifier, NULLIFIER_LEN);
            scl_db_write_nullifiers_batch(offchain_nullifier_batch, 1);
            
            scl_wallet_scan_centinel_op(state, op);
        } else {
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&op->data.claim_validation.commitment, sizeof(BdlopCommitment), commitment_hash);
            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, commitment_hash, 0) < 0) {
                mmr_add(state->bc.centinel.validation_commitments, commitment_hash, 0);
            }
            scl_wallet_scan_claim_op(state, op);
        }
        pthread_rwlock_unlock(&state->bc.rwlock);

        hash_table_insert(state->processed_txs, key, NULL, HASH_ENTRY_TX);
        scl_log(LOG_LEVEL_DEBUG, "Mempool", "Processed off-chain operation type=%u", op->type);
        return 0;
    }

    // Allocate copy for mempool storage, packing active fields only
    Operation *op_copy = malloc(sizeof(Operation));
    if (!op_copy) return -1;
    op_copy->type = op->type;
    op_copy->is_rpc_injected = op->is_rpc_injected;
    
    if (op->type == OP_TRANSFER_POINTER) {
        const TransferData *src = &op->data.transfer_pointer;
        TransferData *dest = &op_copy->data.transfer_pointer;
        if (src->num_inputs > MAX_INPUTS || src->zk_proof_len > ZK_PROOF_MAX_LEN) {
            free(op_copy);
            return -1;
        }
        memcpy(dest->tx_id, src->tx_id, COIN_ID_LEN);
        memcpy(dest->nonce, src->nonce, 8);
        dest->num_inputs = src->num_inputs;
        memcpy(dest->inputs, src->inputs, src->num_inputs * sizeof(Pointer));
        memcpy(dest->proofs, src->proofs, src->num_inputs * sizeof(MMRProof));
        memcpy(dest->client_root, src->client_root, COIN_ID_LEN);
        memcpy(dest->recipient_pubkey, src->recipient_pubkey, PUBKEY_LEN);
        memcpy(dest->sender_pubkey, src->sender_pubkey, PUBKEY_LEN);
        dest->amount = src->amount;
        memcpy(dest->signature, src->signature, SIGNATURE_LEN);
        memcpy(dest->inputs_merkle_root, src->inputs_merkle_root, COIN_ID_LEN);
        memcpy(dest->inputs_root_signature, src->inputs_root_signature, SIGNATURE_LEN);
        memcpy(dest->prf_output, src->prf_output, NULLIFIER_LEN);
        dest->zk_proof_len = src->zk_proof_len;
        if (src->zk_proof_len > 0) {
            memcpy(dest->zk_proof, src->zk_proof, src->zk_proof_len);
        }
    } else if (op->type == OP_STAKE) {
        const StakeData *src = &op->data.stake;
        StakeData *dest = &op_copy->data.stake;
        if (src->num_inputs > MAX_INPUTS) {
            free(op_copy);
            return -1;
        }
        memcpy(dest->stake_tx_id, src->stake_tx_id, COIN_ID_LEN);
        memcpy(dest->nonce, src->nonce, 8);
        dest->num_inputs = src->num_inputs;
        memcpy(dest->inputs, src->inputs, src->num_inputs * sizeof(Pointer));
        memcpy(dest->proofs, src->proofs, src->num_inputs * sizeof(MMRProof));
        memcpy(dest->inputs_merkle_root, src->inputs_merkle_root, COIN_ID_LEN);
        memcpy(dest->inputs_root_signature, src->inputs_root_signature, SIGNATURE_LEN);
        memcpy(dest->client_root, src->client_root, COIN_ID_LEN);
        memcpy(dest->threshold_pubkey, src->threshold_pubkey, PUBKEY_LEN);
        memcpy(dest->sender_pubkey, src->sender_pubkey, PUBKEY_LEN);
        dest->amount = src->amount;
        memcpy(dest->threshold_signature, src->threshold_signature, SIGNATURE_LEN);
    } else if (op->type == OP_UNSTAKE) {
        const UnstakeData *src = &op->data.unstake;
        UnstakeData *dest = &op_copy->data.unstake;
        if (src->num_inputs > MAX_INPUTS) {
            free(op_copy);
            return -1;
        }
        memcpy(dest->unstake_tx_id, src->unstake_tx_id, COIN_ID_LEN);
        memcpy(dest->nonce, src->nonce, 8);
        dest->num_inputs = src->num_inputs;
        memcpy(dest->inputs, src->inputs, src->num_inputs * sizeof(Pointer));
        memcpy(dest->proofs, src->proofs, src->num_inputs * sizeof(MMRProof));
        memcpy(dest->inputs_merkle_root, src->inputs_merkle_root, COIN_ID_LEN);
        memcpy(dest->inputs_root_signature, src->inputs_root_signature, SIGNATURE_LEN);
        memcpy(dest->pointer_signatures, src->pointer_signatures, src->num_inputs * SIGNATURE_LEN);
        memcpy(dest->client_root, src->client_root, COIN_ID_LEN);
        memcpy(dest->threshold_pubkey, src->threshold_pubkey, PUBKEY_LEN);
        memcpy(dest->recipient_pubkey, src->recipient_pubkey, PUBKEY_LEN);
        dest->amount = src->amount;
        memcpy(dest->threshold_signature, src->threshold_signature, SIGNATURE_LEN);
    } else if (op->type == OP_MINT_COIN) {
        op_copy->data.mint_coin = op->data.mint_coin;
    } else if (op->type == OP_APPLY_DRIFT_CERT) {
        const ApplyDriftCertData *src = &op->data.apply_drift_cert;
        if (src->num_inputs > MAX_INPUTS) {
            free(op_copy);
            return -1;
        }
        /* Plain-old-data struct copy: cert_tx_id, nonce, inputs, proofs,
         * inputs_merkle_root, client_root, digest fields, pubkeys, amount,
         * signature and cert_digest are all inline arrays/scalars. */
        op_copy->data.apply_drift_cert = *src;
    }

    uint64_t new_fee = 0;
    if (op->type == OP_TRANSFER_POINTER) new_fee = calculate_fee(op->data.transfer_pointer.amount, false);
    else if (op->type == OP_STAKE) new_fee = calculate_fee(op->data.stake.amount, true);
    else if (op->type == OP_UNSTAKE) new_fee = calculate_fee(op->data.unstake.amount, true);
    else if (op->type == OP_APPLY_DRIFT_CERT) new_fee = calculate_fee(op->data.apply_drift_cert.amount, true);

    int empty_slot = -1;
    uint64_t lowest_fee = UINT64_MAX;
    int lowest_fee_slot = -1;

    uint32_t active_ops_count = atomic_load_explicit(&state->pending_operations_count, memory_order_acquire);
    uint32_t ops_checked = 0;

    // Scan mempool slots for duplicate keys, input conflicts, or empty spaces
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (!pop) {
            if (empty_slot == -1) empty_slot = i;
            if (ops_checked >= active_ops_count && empty_slot != -1) break;
            continue;
        }
        ops_checked++;

        const uint8_t *pid = get_operation_tx_id(pop);
        uint8_t pkey[COIN_ID_LEN];
        if (pid) memcpy(pkey, pid, COIN_ID_LEN);
        else SHA256((uint8_t*)pop, sizeof(Operation), pkey);
        
        if (memcmp(pkey, key, COIN_ID_LEN) == 0) {
            // Replace-By-Fee (RBF) Evaluation
            uint64_t old_fee = 0;
            if (pop->type == OP_TRANSFER_POINTER) old_fee = calculate_fee(pop->data.transfer_pointer.amount, false);
            else if (pop->type == OP_STAKE) old_fee = calculate_fee(pop->data.stake.amount, true);
            else if (pop->type == OP_UNSTAKE) old_fee = calculate_fee(pop->data.unstake.amount, true);
            else if (pop->type == OP_APPLY_DRIFT_CERT) old_fee = calculate_fee(pop->data.apply_drift_cert.amount, true);
            
            if (new_fee > old_fee) {
                if (atomic_compare_exchange_strong_explicit(&state->pending_operations[i], &pop, op_copy, memory_order_release, memory_order_relaxed)) {
                    scl_log(LOG_LEVEL_INFO, "Mempool", "RBF: Replacing tx with higher fee (old=%lu, new=%lu)", old_fee, new_fee);
                    free(pop);
                    return 0;
                }
            }
            free(op_copy);
            return -1; // Duplicate transaction or insufficient fee increase
        }

        // Input pointer or nullifier conflict detection
        if (operations_share_inputs(op_copy, pop)) {
            scl_log(LOG_LEVEL_WARN, "Mempool", "Double-spend detected, rejecting transaction");
            free(op_copy);
            return -2;
        }

        uint64_t entry_fee = 0;
        if (pop->type == OP_TRANSFER_POINTER) entry_fee = calculate_fee(pop->data.transfer_pointer.amount, false);
        else if (pop->type == OP_STAKE) entry_fee = calculate_fee(pop->data.stake.amount, true);
        else if (pop->type == OP_UNSTAKE) entry_fee = calculate_fee(pop->data.unstake.amount, true);
        else if (pop->type == OP_APPLY_DRIFT_CERT) entry_fee = calculate_fee(pop->data.apply_drift_cert.amount, true);
        
        if (entry_fee < lowest_fee) {
            lowest_fee = entry_fee;
            lowest_fee_slot = i;
        }
    }

    // Insert into empty slot via atomic CAS
    if (empty_slot != -1) {
        Operation *expected = NULL;
        if (atomic_compare_exchange_strong_explicit(&state->pending_operations[empty_slot], &expected, op_copy, memory_order_release, memory_order_relaxed)) {
            atomic_fetch_add_explicit(&state->pending_operations_count, 1, memory_order_relaxed);
            if (state->config.mempool_async_threshold > 0 &&
                atomic_load_explicit(&state->pending_operations_count, memory_order_relaxed) > state->config.mempool_async_threshold) {
                trigger_async_fork_processing(state);
            }
            scl_log(LOG_LEVEL_DEBUG, "Mempool", "Added operation type=%u, mempool size=%u", op->type, atomic_load(&state->pending_operations_count));
            return 0;
        }
    } else if (lowest_fee_slot != -1 && new_fee > lowest_fee) {
        // Evict lowest-fee entry when mempool is completely saturated
        Operation *expected = atomic_load_explicit(&state->pending_operations[lowest_fee_slot], memory_order_acquire);
        if (atomic_compare_exchange_strong_explicit(&state->pending_operations[lowest_fee_slot], &expected, op_copy, memory_order_release, memory_order_relaxed)) {
            if (expected) free(expected);
            scl_log(LOG_LEVEL_INFO, "Mempool", "Evicted lowest fee transaction to free space");
            return 0;
        }
    }
    
    scl_log(LOG_LEVEL_WARN, "Mempool", "Mempool full and transaction fee too low for eviction");
    free(op_copy);
    return -1;
}

/* ============================================================================ */
/* SECTION 10: PEER SYNCHRONIZATION, LEDGER CONSISTENCY & SNAPSHOT ENGINE       */
/* ============================================================================ */

/**
 * @brief Blocks calling thread until bootstrap peer connections achieve ESTABLISHED status.
 *
 * @param[in,out] state Global node state container.
 * @param[in] timeout_seconds Maximum wait duration in seconds.
 *
 * @complexity Time: O(timeout_seconds), Space: O(1).
 */
void wait_for_valid_peers(State *state, int timeout_seconds) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    (void)state; (void)timeout_seconds;
    return;
#endif
    if (!state) return;

    P2PNetwork *net = &state->p2p_network;
    time_t start_time = time(NULL);
    int iterations = 0;
    int max_iterations = timeout_seconds * 10;
    int found_bootstrap = 0;

    // Parse bootstrap nodes from configuration
    struct sockaddr_storage bootstrap_addrs[32];
    size_t num_bootstrap = 0;

    char temp_str[1024];
    strncpy(temp_str, state->config.bootstrap_nodes_str, sizeof(temp_str) - 1);
    temp_str[sizeof(temp_str) - 1] = '\0';

    char *token = strtok(temp_str, ",");
    while (token && num_bootstrap < 32) {
        char ip[64];
        int port = 5555;
        memset(&bootstrap_addrs[num_bootstrap], 0, sizeof(struct sockaddr_storage));
        
        if (token[0] == '[') {
            if (sscanf(token, "[%63[^]]]:%d", ip, &port) >= 1) {
                struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&bootstrap_addrs[num_bootstrap];
                v6->sin6_family = AF_INET6;
                v6->sin6_port = htons(port);
                inet_pton(AF_INET6, ip, &v6->sin6_addr);
                num_bootstrap++;
            }
        } else if (sscanf(token, "%63[^:]:%d", ip, &port) >= 1) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)&bootstrap_addrs[num_bootstrap];
            v4->sin_family = AF_INET;
            v4->sin_port = htons(port);
            inet_pton(AF_INET, ip, &v4->sin_addr);
            num_bootstrap++;
        }
        token = strtok(NULL, ",");
    }

    scl_log(LOG_LEVEL_INFO, "P2P", "Waiting for valid bootstrap nodes...");

    while (time(NULL) - start_time < timeout_seconds && iterations < max_iterations) {
        pthread_mutex_lock(&net->mutex);
        for (size_t i = 0; i < net->num_known_peers; i++) {
            Peer *peer = net->known_peers[i];
            for (size_t j = 0; j < num_bootstrap; j++) {
                bool is_loopback = false;
                if (peer->addr.ss_family == AF_INET) {
                    struct sockaddr_in *v4 = (struct sockaddr_in *)&peer->addr;
                    if (v4->sin_addr.s_addr == inet_addr("127.0.0.1")) is_loopback = true;
                } else if (peer->addr.ss_family == AF_INET6) {
                    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&peer->addr;
                    if (memcmp(&v6->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) == 0) is_loopback = true;
                }
                
                if ((sockaddr_storage_equal(&peer->addr, &bootstrap_addrs[j]) || is_loopback) &&
                    !is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
                    peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                    
                    found_bootstrap = 1;
                    break;
                }
            }
            if (found_bootstrap) break;
        }
        pthread_mutex_unlock(&net->mutex);

        if (found_bootstrap) break;

        // Periodic reconnection attempt to bootstrap addresses every 3 seconds (30 iterations)
        if (iterations > 0 && iterations % 30 == 0) {
            for (size_t i = 0; i < num_bootstrap; i++) {
                if (sockaddr_storage_equal(&bootstrap_addrs[i], &net->local_peer.addr)) {
                    continue;
                }
                scl_initiate_connection(net, &bootstrap_addrs[i]);
            }
        }
        
        iterations++;
        usleep(100000);
    }
}

/**
 * @brief Broadcasts batched peer address synchronization messages across active connections.
 *
 * @param[in,out] state Global node state container.
 *
 * @complexity Time: O(num_known_peers), Space: O(num_known_peers) heap copy.
 */
void broadcast_peer_list_sync(State *state) {
    P2PNetwork *net = &state->p2p_network;
    pthread_mutex_lock(&net->mutex);
    
    size_t total_peers = net->num_known_peers;
    
    struct PeerInfoCopy {
        uint8_t dilithium_pubkey[DILITHIUM_PUBKEY_LEN];
        uint8_t kyber_pubkey[KYBER_PUBKEY_LEN];
        struct sockaddr_storage addr;
    };

    struct PeerInfoCopy *copied_peers = malloc(total_peers * sizeof(struct PeerInfoCopy));
    if (!copied_peers) {
        pthread_mutex_unlock(&net->mutex);
        return;
    }
    
    size_t valid_count = 0;
    for (size_t i = 0; i < total_peers; i++) {
        Peer *peer = net->known_peers[i];
        if (peer && !is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) {
            if (validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey) &&
                validate_kyber_pubkey(peer->peer_wallet.kyber_pubkey)) {
                memcpy(copied_peers[valid_count].dilithium_pubkey, peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                memcpy(copied_peers[valid_count].kyber_pubkey, peer->peer_wallet.kyber_pubkey, KYBER_PUBKEY_LEN);
                copied_peers[valid_count].addr = peer->addr;
                valid_count++;
            }
        }
    }
    
    // Unlock immediately; isolated copy prevents UAF during concurrent peer disconnect sweeps
    pthread_mutex_unlock(&net->mutex);
    
    size_t peers_sent = 0;
    while (peers_sent < valid_count) {
        size_t count_in_this_msg = valid_count - peers_sent;
        if (count_in_this_msg > MAX_PEERS_PER_MESSAGE) count_in_this_msg = MAX_PEERS_PER_MESSAGE;
        
        struct PeerChunk {
            uint8_t dilithium_pubkey[DILITHIUM_PUBKEY_LEN];
            uint8_t kyber_pubkey[KYBER_PUBKEY_LEN];
            struct sockaddr_storage addr;
        } *chunk_peers = malloc(count_in_this_msg * sizeof(struct PeerChunk));
        
        if (!chunk_peers) break;
        
        for (size_t i = 0; i < count_in_this_msg; i++) {
            memcpy(chunk_peers[i].dilithium_pubkey, copied_peers[peers_sent + i].dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            memcpy(chunk_peers[i].kyber_pubkey, copied_peers[peers_sent + i].kyber_pubkey, KYBER_PUBKEY_LEN);
            chunk_peers[i].addr = copied_peers[peers_sent + i].addr;
        }
        peers_sent += count_in_this_msg;
        
        Message *msg = calloc(1, sizeof(Message));
        if (!msg) {
            free(chunk_peers);
            break;
        }
        msg->type = MSG_PEER_LIST_SYNC;
        uint8_t *p = msg->payload;
        *p++ = (uint8_t)count_in_this_msg;
                
        for (size_t i = 0; i < count_in_this_msg; i++) {
            memcpy(p, chunk_peers[i].dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            p += DILITHIUM_PUBKEY_LEN;
            memcpy(p, chunk_peers[i].kyber_pubkey, KYBER_PUBKEY_LEN);
            p += KYBER_PUBKEY_LEN;
            serialize_sockaddr(&chunk_peers[i].addr, p);
            p += 19;
        }
        msg->length = p - msg->payload;
                
        p2p_broadcast(state, msg);
        free(msg);
        free(chunk_peers);
    }
    
    free(copied_peers);
}

/**
 * @brief Validates structural encoding bounds of a Dilithium5 public key.
 *
 * @param[in] pubkey 2,592-byte key buffer pointer.
 * @return 1 if valid; 0 if NULL or zeroed.
 */
int validate_dilithium_pubkey(const uint8_t *pubkey) {
    if (!pubkey || is_zeroed(pubkey, DILITHIUM_PUBKEY_LEN)) {
        scl_log(LOG_LEVEL_DEBUG, "Crypto", "Dilithium public key is NULL or zeroed");
        return 0;
    }
    return 1;
}

/**
 * @brief Validates structural encoding bounds of a Kyber-512 public key.
 *
 * @param[in] pubkey 800-byte key buffer pointer.
 * @return 1 if valid; 0 if NULL or zeroed.
 */
int validate_kyber_pubkey(const uint8_t *pubkey) {
    if (!pubkey || is_zeroed(pubkey, KYBER_PUBKEY_LEN)) {
        scl_log(LOG_LEVEL_DEBUG, "Crypto", "Kyber public key is NULL or zeroed");
        return 0;
    }
    return 1;
}

/**
 * @brief Calculates total unspent subunits remaining across all active pointers belonging to a coin.
 *
 * @param[in] bc Blockchain state container pointer.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @return Sum of unspent atomic subunits belonging to the coin.
 *
 * @pre Caller must hold `bc->rwlock` in read or write mode.
 * @complexity Time: O(mapped pointers), Space: O(mapped pointers) heap buffer.
 */
uint64_t calculate_coin_remaining(Blockchain *bc, const uint8_t coin_id[COIN_ID_LEN]) {
    if (!bc || !coin_id) {
        fprintf(stderr, "[Blockchain] Invalid parameters in calculate_coin_remaining\n");
        return 0;
    }

    uint8_t (*ptr_ids)[COIN_ID_LEN] = NULL;
    size_t count = 0;
    size_t capacity = 16;

    ptr_ids = malloc(capacity * COIN_ID_LEN);
    if (!ptr_ids) return 0;

    pthread_rwlock_rdlock(&bc->coin_pointers->rwlock);
    uint32_t index = bc->coin_pointers->hash_fn(coin_id, bc->coin_pointers->size);
    GenericHashEntry *entry = bc->coin_pointers->buckets[index];

    while (entry != NULL) {
        if (entry->type == HASH_ENTRY_POINTER && memcmp(entry->key, coin_id, COIN_ID_LEN) == 0) {
            if (count >= capacity) {
                capacity *= 2;
                uint8_t (*new_ptr_ids)[COIN_ID_LEN] = realloc(ptr_ids, capacity * COIN_ID_LEN);
                if (!new_ptr_ids) {
                    pthread_rwlock_unlock(&bc->coin_pointers->rwlock);
                    free(ptr_ids);
                    return 0;
                }
                ptr_ids = new_ptr_ids;
            }
            memcpy(ptr_ids[count], entry->data.pointer.pointer_id, COIN_ID_LEN);
            count++;
        }
        entry = entry->next;
    }
    pthread_rwlock_unlock(&bc->coin_pointers->rwlock);

    uint64_t total_remaining = 0;
    for (size_t i = 0; i < count; i++) {
        Pointer *actual_ptr = hash_table_lookup(bc->pointer_table, ptr_ids[i], false);
        if (actual_ptr && !actual_ptr->spent && memcmp(actual_ptr->parent_coin_id, coin_id, COIN_ID_LEN) == 0) {
            total_remaining += (actual_ptr->end_subunit - actual_ptr->start_subunit + 1);
        }
    }

    free(ptr_ids);
    return total_remaining;
}

/**
 * @brief O(1) invariant verification that a coin's unspent balance never exceeds total capacity.
 *
 * @param[in] bc Blockchain state container pointer.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @return 1 if invariant holds (`remaining <= total`); 0 if corrupted.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int check_coin_consistency(Blockchain *bc, const uint8_t coin_id[COIN_ID_LEN]) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)bc; (void)coin_id;
    return 1;
#else
    if (!bc || !coin_id) {
        fprintf(stderr, "[Blockchain] Invalid parameters in check_coin_consistency\n");
        return 0;
    }

    SCLCoin *coin = hash_table_lookup(bc->coin_table, coin_id, false);
    if (!coin) {
        fprintf(stderr, "[Blockchain] Coin not found in check_coin_consistency\n");
        return 0;
    }

    // Mathematical supply boundary check: unspent balance cannot exceed minted total
    if (coin->remaining_subunits > coin->total_subunits) {
        char hex_str[17];
        bytes_to_hex(coin_id, 8, hex_str);
        
        fprintf(stderr, "[Blockchain] Coin consistency check failed for coin %s: unspent=%llu exceeds total=%llu\n",
                hex_str, coin->remaining_subunits, coin->total_subunits);
        return 0;
    }
    return 1;
#endif
}

/**
 * @brief Atomically publishes an updated immutable GameStateSnapshot reflecting latest game state.
 *
 * @details
 * Freezes current audit matrix rows, total reward issuance, and epoch threshold keys into a
 * reference-counted structure. Enqueues superseded snapshot to the RCU garbage collection ring.
 *
 * @param[in,out] state Global node state container.
 *
 * @note Acquires `state->game_state.mutex` and `state->snapshot_update_mutex`.
 * @complexity Time: O(AUDIT_SIZE), Space: O(sizeof(GameStateSnapshot)) heap allocation.
 */
void update_game_state_snapshot(State *state) {
    GameStateSnapshot *new_snap = calloc(1, sizeof(GameStateSnapshot));
    if (!new_snap) return;
    
    pthread_mutex_lock(&state->game_state.mutex);
    new_snap->total_rewarded_scl_subunits = state->game_state.total_rewarded_scl_subunits;
    new_snap->remaining_scl_subunits = state->game_state.remaining_scl_subunits;
    memcpy(new_snap->game_audit, state->game_state.game_audit, sizeof(Valuation) * AUDIT_SIZE);
    new_snap->current_audit_index = state->game_state.current_audit_index;
    new_snap->valuation_count = state->game_state.valuation_count;
    new_snap->audit_timestamp = state->game_state.audit_timestamp;
    memcpy(new_snap->epoch_threshold_pubkey, state->game_state.epoch_threshold_pubkey, PUBKEY_LEN);
    new_snap->last_dkg_epoch = state->game_state.last_dkg_epoch;
    memcpy(new_snap->current_epoch_signature, state->game_state.current_epoch_signature, SIGNATURE_LEN);
    pthread_mutex_unlock(&state->game_state.mutex);
    
    atomic_init(&new_snap->ref_count, 1);
    
    pthread_mutex_lock(&state->snapshot_update_mutex);
    GameStateSnapshot *old_snap = (GameStateSnapshot *)atomic_exchange_explicit(&state->active_snapshot_ptr, (uintptr_t)new_snap, memory_order_release);
    if (old_snap) {
        new_snap->version = old_snap->version + 1;
        
        bool enqueued = false;
        if (global_shim && global_shim->impl_state) {
            UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;
            uint32_t head, next_head, tail;
            do {
                head = atomic_load_explicit(&us_state->gc_head, memory_order_acquire);
                next_head = (head + 1) % 4096;
                tail = atomic_load_explicit(&us_state->gc_tail, memory_order_acquire);
                if (next_head == tail) {
                    break;
                }
            } while (!atomic_compare_exchange_weak_explicit(&us_state->gc_head, &head, next_head, memory_order_release, memory_order_relaxed));
            
            if (next_head != tail) {
                us_state->gc_ring[head].ptr = old_snap;
                us_state->gc_ring[head].type = GC_TYPE_SNAPSHOT;
                us_state->gc_ring[head].tombstone_time = get_time_ms();
                atomic_store_explicit(&us_state->gc_ring[head].ready, true, memory_order_release);
                enqueued = true;
            }
        }
        if (!enqueued) {
            release_game_state_snapshot(old_snap);
        }
    } else {
        new_snap->version = 1;
    }
    pthread_mutex_unlock(&state->snapshot_update_mutex);
}

/**
 * @brief Acquires reference to current GameStateSnapshot with atomic reference increment.
 *
 * @param[in] state Global node state container.
 * @return Retained GameStateSnapshot pointer; must be released via `release_game_state_snapshot`.
 *
 * @note Lock-free atomic load path.
 * @complexity Time: O(1), Space: O(1).
 */
GameStateSnapshot *acquire_game_state_snapshot(State *state) {
    GameStateSnapshot *snap = (GameStateSnapshot *)atomic_load_explicit(&state->active_snapshot_ptr, memory_order_acquire);
    if (snap) {
        atomic_fetch_add_explicit(&snap->ref_count, 1, memory_order_relaxed);
    }
    return snap;
}

/**
 * @brief Decrements snapshot reference count, releasing memory when counter reaches zero.
 *
 * @param[in] snapshot GameStateSnapshot pointer to release.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void release_game_state_snapshot(GameStateSnapshot *snapshot) {
    if (!snapshot) return;
    if (atomic_fetch_sub_explicit(&snapshot->ref_count, 1, memory_order_release) == 1) {
        atomic_thread_fence(memory_order_acquire);
        free(snapshot);
    }
}

/**
 * @brief Computes 64-bit SipHash-2-4 checksum over wire message header and payload.
 *
 * @details
 * Invariant: Checksum hashes Header bytes 0..23 (excluding checksum field itself) concatenated
 * with optional error string and payload bytes using the 128-bit session SipHash key.
 *
 * @param[in] msg_payload Serialized RPC message buffer.
 * @param[in] error_msg_len Byte length of error message string.
 * @param[in] payload_len Byte length of payload arguments.
 * @param[in] rpc_siphash_key 16-byte SipHash key derived from KEM shared secret.
 * @return 64-bit unsigned SipHash digest.
 *
 * @complexity Time: O(24 + error_msg_len + payload_len), Space: O(1) stack or staging buffer.
 */
uint64_t compute_rpc_checksum(const uint8_t *msg_payload, uint16_t error_msg_len, uint32_t payload_len, const uint8_t rpc_siphash_key[16]) {
    if (!msg_payload) return 0;
#ifdef __EMSCRIPTEN__
    size_t staging_size = 24 + error_msg_len + payload_len;
    uint8_t *staging = malloc(staging_size);
    if (!staging) return 0;
    memcpy(staging, msg_payload, 24);
    if (error_msg_len > 0) {
        memcpy(staging + 24, msg_payload + 32, error_msg_len);
    }
    if (payload_len > 0) {
        memcpy(staging + 24 + error_msg_len, msg_payload + 32 + error_msg_len, payload_len);
    }
    uint64_t hash = siphash24(staging, staging_size, rpc_siphash_key);
    free(staging);
    return hash;
#else
    size_t total_len = 24 + error_msg_len + payload_len;
    if (total_len <= 8192) {
        uint8_t stack_buf[8192];
        memcpy(stack_buf, msg_payload, 24);
        if (error_msg_len > 0) {
            memcpy(stack_buf + 24, msg_payload + 32, error_msg_len);
        }
        if (payload_len > 0) {
            memcpy(stack_buf + 24 + error_msg_len, msg_payload + 32 + error_msg_len, payload_len);
        }
        return siphash24(stack_buf, total_len, rpc_siphash_key);
    }
    uint8_t *staging = get_l5_staging_buffer();
    if (!staging) return 0;
    memcpy(staging, msg_payload, 24);
    if (error_msg_len > 0) {
        memcpy(staging + 24, msg_payload + 32, error_msg_len);
    }
    if (payload_len > 0) {
        memcpy(staging + 24 + error_msg_len, msg_payload + 32 + error_msg_len, payload_len);
    }
    return siphash24(staging, 24 + error_msg_len + payload_len, rpc_siphash_key);
#endif
}
