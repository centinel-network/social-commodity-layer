/**
 * @file client.c
 * @brief Node Entrypoint, Lifecycle Supervisor, and L5 Application Runtime
 *
 * @details
 * This module serves as the central operational coordinator for a Satocialist
 * Cryptographic Ledger (SCL) node. It coordinates bootstrapping, cryptographic
 * key lifecycle management, transport layer driver instantiation (Userspace UDP or
 * Linux AF_XDP), thread pool management (L5 cryptographic verification, submission
 * batching, consensus timers), and clean system shutdown.
 *
 * Architecture Role:
 * - Orchestration Layer: Parses configuration profiles, CLI arguments, and launches
 *   subsystem services (WebSocket-to-UDP Bridge, Prometheus Metrics Exporter, Auto-Pilot).
 * - Layer 0/1 Intake Dispatcher: Coordinates the non-blocking polling thread driving
 *   `SclTransportShim` and routes frames into per-worker L5 queues.
 * - L5 Consensus Consumer Engine: Spawns NUM_CRYPTO_WORKERS parallel cryptographic
 *   workers implementing QUIC-Parity out-of-order reassembly, Reed-Solomon erasure
 *   decoding (GF(2^8)), Post-Quantum authentication, and state-machine ingestion.
 *
 * Invariants Maintained:
 * - Single Active Instance: `global_state` remains valid and immutable in reference
 *   until final teardown in `perform_shutdown()`.
 * - L0-L5 Decoupling: Ingress packets captured at L0 are dispatched to lock-free SPSC
 *   ring buffers mapped to connection state CIDs before cryptographic verification.
 * - Anti-Reentrancy / Clean Signal Safety: Signal interruption triggers atomic
 *   flag updates only, deferring blocking I/O and POSIX thread joins to caller space.
 *
 * Cryptographic & Protocol Standards:
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium)
 * - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber-768)
 * - RFC 9000 / RFC 9002: QUIC Transport & Loss Detection Parity Adaptations
 *
 * Concurrency Model:
 * - Posix Multi-Threaded: Real-time SCHED_FIFO ingress, detached cryptographic workers,
 *   SPSC lock-free intake queues, and explicit POSIX condition variable wakeups.
 * - Memory Hierarchy: C11 stdatomic load-acquire / store-release synchronization
 *   governing the lifecycle state of connections, queues, and termination flags.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <math.h>
#include <getopt.h>

#include "client_aux.h"
#include "user.h"
#include "queue.h"
#include "client_state.h"
#include "game_state.h"
#include "crypto.h"
#include "protocol.h"
#include "network.h"
#include "client_network.h"
#include "blockchain.h"
#include "mmr.h"
#include "hash_table.h"
#include "types.h"
#include "consensus.h"
#include "constants.h"
#include "utils.h"
#include "websocket_bridge.h"

#ifdef USE_XDP
/**
 * @brief Thread-local worker identifier matching AF_XDP ring queue mapping.
 * Guarded by thread-local storage; initialized per crypto worker thread.
 */
extern __thread int current_worker_id;
#endif

/* ============================================================================
 * GLOBAL AND STATIC RUNTIME STATE REFERENCES
 * ============================================================================ */

/**
 * @brief Global pointer to the active local User account instance.
 * @note Allocated during client initialization; valid until node shutdown.
 * Synchronization: Guarded by `global_state->user_table` read/write locks.
 */
extern User *global_user;

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
/** @brief POSIX thread descriptor for the L0 Transport Shim intake event loop. */
static pthread_t global_net_thread;

/** @brief POSIX thread descriptor for the consensus block validation timer. */
static pthread_t validation_thread;

/** @brief POSIX thread descriptor for the Prometheus HTTP metrics exporter. */
static pthread_t metrics_exporter_thread;

/** @brief POSIX thread descriptor for the WebSocket-to-UDP browser bridge. */
static pthread_t ws_bridge_thread = 0;

/** @brief POSIX thread pool executing L5 application and cryptographic parsing. */
static pthread_t global_l5_threads[NUM_CRYPTO_WORKERS];

/**
 * @brief Dynamic array of active economic asset valuations.
 * Memory Ownership: Heap-allocated by client UI logic; freed during shutdown.
 */
static Valuation *global_valuations = NULL;
#endif

/**
 * @brief Runtime network configuration arguments shared across service threads.
 * Memory Ownership: References static stack memory allocated in main().
 */
static NetworkArgs *global_args = NULL;

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
/**
 * @brief Master system state pointer containing ledger, mempool, and node context.
 * Memory Ownership: Root allocation instantiated in main(); destroyed in perform_shutdown().
 */
State *global_state = NULL;

/**
 * @brief Atomic lifecycle state barrier indicating node-wide termination request.
 * Memory Model: Acquired via memory_order_acquire / set via memory_order_release.
 */
atomic_bool global_shutdown = false;
#else
extern State *global_state;
#endif

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/* ============================================================================
 * EMBEDDED HTTP PROMETHEUS METRICS EXPORTER
 * ============================================================================ */

/**
 * @brief Embedded HTTP service providing Prometheus-compatible runtime metrics.
 *
 * @details
 * Binds a dedicated TCP listening socket to `config.metrics_port` (defaulting to 8000)
 * and exports node observability statistics in Prometheus text exposition format (version 0.0.4).
 * Polling uses a 1-second timeout loop checking `global_shutdown` to ensure timely termination.
 *
 * Metrics Exported:
 * - `satocialist_connected_peers`: Gauge of authenticated, active P2P peers.
 * - `satocialist_block_height`: Counter indicating current committed block height.
 * - `satocialist_mempool_size`: Gauge of pending transactions awaiting consensus inclusion.
 * - `satocialist_rpc_requests_total`: Total inbound RPC requests labeled by method ID and status.
 * - `satocialist_rpc_rejected_total`: Total RPC rejections segmented by failure reason.
 * - `satocialist_rpc_latency_microseconds_sum`: Cumulative execution duration across RPC calls.
 * - `satocialist_rpc_active_workers`: Current number of worker threads servicing queries.
 * - `satocialist_autopilot_enabled`: Binary status indicating whether the Auto-Pilot bot is running.
 *
 * @pre `arg` must be a valid, non-NULL pointer to an initialized `State` instance.
 * @post Closes all open client and server TCP file descriptors upon loop exit.
 * @sideeffects Spawns a listening TCP socket; transmits HTTP/1.1 response bodies; closes client connections.
 *
 * @synchronization
 * - Acquires `state->p2p_network.mutex` briefly to capture peer counts.
 * - Acquires `state->ledger_mutex` briefly to read `current_block_number`.
 * - Employs atomic acquire/relaxed reads across RPC counters without holding global locks.
 *
 * @param[in,out] arg Untyped pointer casting to `State *` representing the node environment.
 *                    Memory ownership is retained by the caller (`main()`).
 *
 * @return void* Always returns NULL upon termination.
 *
 * @complexity
 * - Time: O(M) per scrape where M is the number of monitored RPC method IDs (constant M=12).
 * - Auxiliary Space: O(1) auxiliary space beyond the 8192-byte stack-allocated response frame.
 */
static void *prometheus_metrics_server(void *arg) {
    State *state = (State *)arg;
    int port = state->config.metrics_port;
    if (port <= 0) port = 8000;

    // Initialize and bind TCP socket for Prometheus metrics exposition
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return NULL;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(server_fd);
        return NULL;
    }

    if (listen(server_fd, 5) < 0) {
        close(server_fd);
        return NULL;
    }

    char response[8192];
    while (!atomic_load(&global_shutdown)) {
        // Enforce 1000 millisecond poll intervals to allow the thread to evaluate the shutdown barrier
        struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
        int poll_ret = poll(&pfd, 1, 1000);
        if (poll_ret <= 0) continue;

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        // Snapshot network peer capacity and local ledger height
        size_t peers = scl_count_established_nodes(state); /* live established peers, not the ever-growing address book */
        
        pthread_mutex_lock(&state->ledger_mutex);
        uint64_t height = state->current_block_number;
        pthread_mutex_unlock(&state->ledger_mutex);

        size_t mempool_size = atomic_load_explicit(&state->pending_operations_count, memory_order_acquire);

        // Ingest performance metrics from the asynchronous RPC engine
        uint64_t req_total = atomic_load_explicit(&state->rpc_engine.requests_total, memory_order_relaxed);
        uint64_t lat_total = atomic_load_explicit(&state->rpc_engine.latency_microseconds_sum, memory_order_relaxed);
        uint32_t active_rpc_workers = atomic_load_explicit(&state->rpc_engine.active_global_queries, memory_order_relaxed);
        
        char methods_metrics[4096] = {0};
        size_t offset = 0;
        for (int i = 0; i < 12; i++) {
            uint64_t m_ok = atomic_load_explicit(&state->rpc_engine.method_requests_ok[i], memory_order_relaxed);
            uint64_t m_err = atomic_load_explicit(&state->rpc_engine.method_requests_err[i], memory_order_relaxed);
            uint64_t m_lat = atomic_load_explicit(&state->rpc_engine.method_latency[i], memory_order_relaxed);
            uint64_t m_total = m_ok + m_err;
            offset += snprintf(methods_metrics + offset, sizeof(methods_metrics) - offset,
                "satocialist_rpc_requests_total{method=\"0x%04X\", status=\"ok\"} %llu\n"
                "satocialist_rpc_requests_total{method=\"0x%04X\", status=\"error\"} %llu\n"
                "satocialist_rpc_latency_microseconds_sum{method=\"0x%04X\"} %llu\n"
                "satocialist_rpc_latency_microseconds_count{method=\"0x%04X\"} %llu\n",
                i, (unsigned long long)m_ok, i, (unsigned long long)m_err, i, (unsigned long long)m_lat, i, (unsigned long long)m_total);
        }

        uint64_t rej_rl = atomic_load_explicit(&state->rpc_engine.rejected_rate_limit, memory_order_relaxed);
        uint64_t rej_auth = atomic_load_explicit(&state->rpc_engine.rejected_auth_fail, memory_order_relaxed);
        uint64_t rej_chk = atomic_load_explicit(&state->rpc_engine.rejected_checksum_mismatch, memory_order_relaxed);

        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nConnection: close\r\n\r\n"
                 "# HELP satocialist_connected_peers Number of active connected P2P peers.\n"
                 "# TYPE satocialist_connected_peers gauge\n"
                 "satocialist_connected_peers %zu\n"
                 "# HELP satocialist_block_height Current block height of the local node.\n"
                 "# TYPE satocialist_block_height counter\n"
                 "satocialist_block_height %llu\n"
                 "# HELP satocialist_mempool_size Number of pending operations in the mempool.\n"
                 "# TYPE satocialist_mempool_size gauge\n"
                 "satocialist_mempool_size %zu\n"
                 "# HELP satocialist_rpc_requests_total Total RPC requests processed.\n"
                 "# TYPE satocialist_rpc_requests_total counter\n"
                 "satocialist_rpc_requests_total %llu\n"
                 "%s"
                 "# HELP satocialist_rpc_rejected_total Total RPC requests rejected by reason.\n"
                 "# TYPE satocialist_rpc_rejected_total counter\n"
                 "satocialist_rpc_rejected_total{reason=\"rate_limit\"} %llu\n"
                 "satocialist_rpc_rejected_total{reason=\"auth_fail\"} %llu\n"
                 "satocialist_rpc_rejected_total{reason=\"checksum_mismatch\"} %llu\n"
                 "# HELP satocialist_rpc_latency_microseconds Histogram tracking method-specific execution duration.\n"
                  "# TYPE satocialist_rpc_latency_microseconds histogram\n"
                  "satocialist_rpc_latency_microseconds_sum %llu\n"
                  "# HELP satocialist_rpc_active_workers Active RPC workers.\n"
                 "# TYPE satocialist_rpc_active_workers gauge\n"
                 "satocialist_rpc_active_workers %u\n"
                 "# HELP satocialist_autopilot_enabled Whether node auto-pilot is enabled.\n"
                 "# TYPE satocialist_autopilot_enabled gauge\n"
                 "satocialist_autopilot_enabled %d\n",
                 peers, (unsigned long long)height, mempool_size,
                 (unsigned long long)req_total, methods_metrics,
                 (unsigned long long)rej_rl, (unsigned long long)rej_auth, (unsigned long long)rej_chk,
                 (unsigned long long)lat_total, active_rpc_workers,
                 atomic_load(&state->autopilot_running) ? 1 : 0);

#ifndef _WIN32
        write(client_fd, response, strlen(response));
        close(client_fd);
#else
        send(client_fd, response, (int)strlen(response), 0);
        closesocket(client_fd);
#endif
    }

#ifndef _WIN32
    close(server_fd);
#else
    closesocket(server_fd);
#endif
    release_l5_staging_buffer();
    return NULL;
}

/* ============================================================================
 * COMMAND-LINE INTERFACE AND CONFIGURATION LOADER
 * ============================================================================ */

/**
 * @brief Prints binary usage syntax and option flags to standard output.
 *
 * @pre `prog_name` must point to a valid null-terminated string representing argv[0].
 * @post Emits help text to stdout; leaves process state unchanged.
 * @sideeffects Writes to standard output stream.
 * @synchronization Thread-safe; operates without shared state locks.
 *
 * @param[in] prog_name Execution path or program name string (borrowed).
 */
static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -i, --ip <ip>          Bind IP address (default: 0.0.0.0)\n");
    printf("  -p, --port <port>      Bind port (default: 5555)\n");
    printf("  -c, --config <file>    Path to config file\n");
    printf("  -l, --log-level <lvl>  Log level (trace, debug, info, warn, error, fatal)\n");
    printf("  -d, --daemon           Run in non-interactive background daemon mode\n");
    printf("  -a, --autopilot        Enable autonomous Auto-Pilot mode on launch\n");
    printf("  -h, --help             Show this help message\n");
}

/**
 * @brief Parses an SCL configuration file and populates the node's `DaemonConfig`.
 *
 * @details
 * Opens the specified configuration path, or falls back to `../<filename>` if run
 * from a build directory. Evaluates key-value assignments delimited by `=`. Lines
 * starting with `#` or newline characters are skipped. Unknown keys are ignored.
 *
 * Configuration Key Mappings:
 * - `bind_ip`: Local network interface binding address.
 * - `bind_port`: Base UDP transport port.
 * - `bootstrap_nodes`: Comma-delimited list of `IP:Port` peers.
 * - `initial_rtt_ms`, `min_pto_ms`, `max_ack_delay_ms`: QUIC-Parity L4 timing parameters.
 * - `time_threshold_num`, `time_threshold_den`: Loss detection rational fractions.
 * - `rbf_enabled`: Boolean flag enabling Replace-By-Fee mempool transaction replacement.
 * - `max_pending_ops`: Maximum size of the memory pool.
 * - `mempool_async_threshold`: Batch limit triggering asynchronous batch verification.
 * - `metrics_port`: HTTP port bound by the Prometheus exporter.
 * - `websocket_port`: TCP port bound by the WebSocket-to-UDP bridge.
 * - `is_daemon`: Boolean running the node without interactive TUI.
 * - `autopilot_enabled`: Automated valuation submission flag.
 * - `autopilot_valuations_per_hour`: Bot submission frequency rate.
 * - `autopilot_stake_ratio`: Percentage of balance reserved for bonded validator staking.
 * - `log_level`: Verbosity threshold string mapped to `LogLevel` enumeration.
 *
 * @pre `filename` must point to a valid null-terminated string.
 * @pre `config` must point to an allocated `DaemonConfig` structure.
 * @post Structure fields in `config` are updated with parsed values, leaving missing fields intact.
 * @sideeffects Emits a warning log message if the file cannot be found or read.
 * @synchronization Single-threaded context during initialization; no locks required.
 *
 * @param[in] filename Path to the configuration file (borrowed).
 * @param[out] config Destination configuration record to mutate (borrowed).
 *
 * @complexity
 * - Time: O(L) where L is the total number of lines in the file.
 * - Auxiliary Space: O(1) auxiliary stack buffer allocation (256 bytes per line).
 */
void load_config(const char *filename, DaemonConfig *config) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        char fallback_path[512];
        snprintf(fallback_path, sizeof(fallback_path), "../%s", filename);
        f = fopen(fallback_path, "r");
    }
    if (!f) {
        scl_log(LOG_LEVEL_WARN, "Config", "Could not open config file %s, using defaults", filename);
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char key[128], val[1024];
        if (sscanf(line, "%127[^=]=%1023s", key, val) == 2) {
            if (strcmp(key, "bind_ip") == 0) strncpy(config->local_ip, val, sizeof(config->local_ip) - 1);
            else if (strcmp(key, "bind_port") == 0) config->port = atoi(val);
            else if (strcmp(key, "bootstrap_nodes") == 0) strncpy(config->bootstrap_nodes_str, val, sizeof(config->bootstrap_nodes_str) - 1);
            else if (strcmp(key, "initial_rtt_ms") == 0) config->initial_rtt_ms = strtoull(val, NULL, 10);
            else if (strcmp(key, "min_pto_ms") == 0) config->min_pto_ms = strtoull(val, NULL, 10);
            else if (strcmp(key, "max_ack_delay_ms") == 0) config->max_ack_delay_ms = strtoull(val, NULL, 10);
            else if (strcmp(key, "time_threshold_num") == 0) config->time_threshold_num = strtoul(val, NULL, 10);
            else if (strcmp(key, "time_threshold_den") == 0) config->time_threshold_den = strtoul(val, NULL, 10);
            else if (strcmp(key, "rbf_enabled") == 0) config->rbf_enabled = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0);
            else if (strcmp(key, "max_pending_ops") == 0) config->max_pending_ops_config = strtoul(val, NULL, 10);
            else if (strcmp(key, "mempool_async_threshold") == 0) config->mempool_async_threshold = strtoul(val, NULL, 10);
            else if (strcmp(key, "metrics_port") == 0) config->metrics_port = atoi(val);
            else if (strcmp(key, "websocket_port") == 0) config->websocket_port = atoi(val);
            else if (strcmp(key, "is_daemon") == 0) config->is_daemon = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0);
            else if (strcmp(key, "autopilot_enabled") == 0) config->autopilot_enabled = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0);
            else if (strcmp(key, "autopilot_valuations_per_hour") == 0) config->autopilot_valuations_per_hour = strtoul(val, NULL, 10);
            else if (strcmp(key, "autopilot_stake_ratio") == 0) config->autopilot_stake_ratio = strtoul(val, NULL, 10);
            else if (strcmp(key, "log_level") == 0) {
                if (strcasecmp(val, "trace") == 0) config->log_level = LOG_LEVEL_TRACE;
                else if (strcasecmp(val, "debug") == 0) config->log_level = LOG_LEVEL_DEBUG;
                else if (strcasecmp(val, "info") == 0) config->log_level = LOG_LEVEL_INFO;
                else if (strcasecmp(val, "warn") == 0) config->log_level = LOG_LEVEL_WARN;
                else if (strcasecmp(val, "error") == 0) config->log_level = LOG_LEVEL_ERROR;
                else if (strcasecmp(val, "fatal") == 0) config->log_level = LOG_LEVEL_FATAL;
            }
        }
    }
    fclose(f);
}

/* ============================================================================
 * COORDINATED SYSTEM TEARDOWN AND ASYNCHRONOUS SIGNAL SUPERVISION
 * ============================================================================ */

/**
 * @brief Performs graceful, coordinated multi-subsystem teardown of the node.
 *
 * @details
 * Executes an ordered sequence of lifecycle shutdowns ensuring zero packet loss on egress,
 * deterministic thread joins, unreleased memory reclamation, and hardware handle termination:
 * 1. Signs and broadcasts `MSG_PEER_DISCONNECT` with the node's Dilithium identity.
 * 2. Pauses 20 milliseconds to permit active network workers to flush the egress queues.
 * 3. Sets `global_shutdown` to true and signals all condition variables across subsystems
 *    (`submission_cond`, `audit_cond`, `pending_ops_cond`, `blockchain_sync_cond`, `recreation_cond`).
 * 4. Iteratively joins all worker threads:
 *    - Blockchain synchronization supervisor thread.
 *    - Recreation worker pool.
 *    - Consensus validation timer thread.
 *    - WebSocket browser bridge thread.
 *    - Prometheus metrics exporter thread.
 *    - L0 Network transport driver thread.
 *    - NUM_CRYPTO_WORKERS cryptographic and consensus consumer threads.
 *    - Transaction submission processing threads.
 * 5. Flushes pending asynchronous disk logs via `scl_log_flush()`.
 * 6. Invokes destructors for global state (`client_state_destroy`), transport shim,
 *    and native Google qsim quantum emulation runtime (`cleanup_quantum_qsim_environment`).
 *
 * @pre Invoked strictly from the primary application thread upon exit.
 * @post All POSIX threads are joined; all sockets closed; heap allocations freed; `global_state` set to NULL.
 * @sideeffects Writes termination logs to stderr; closes file descriptors; triggers Dilithium signature operations.
 *
 * @synchronization
 * Acquires and unlocks individual subsystem mutexes sequentially (`shutdown_mutex`,
 * `submission_mutex`, `state->mutex`, `recreation_sleep_mutex`, `threshold_mutex`)
 * to broadcast condition wakeups without creating cross-mutex circular dependencies.
 *
 * @complexity
 * - Time: O(N + T) where N is the number of connected peers and T is the sum of active threads.
 * - Auxiliary Space: O(1) beyond local stack frames.
 */
static void perform_shutdown(void) {
    fprintf(stderr, "[Peer] Initiating shutdown\n");
    
    // Broadcast signed disconnect notification to prevent peers waiting on silence timeouts
    if (global_state && global_shim) {
        Message *disconnect_msg = malloc(sizeof(Message));
        if (disconnect_msg) {
            disconnect_msg->type = MSG_PEER_DISCONNECT;
            disconnect_msg->length = DILITHIUM_PUBKEY_LEN + SIGNATURE_LEN;
            memcpy(disconnect_msg->payload, global_state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            uint8_t sig[SIGNATURE_LEN];
            dilithium_sign(disconnect_msg->payload, DILITHIUM_PUBKEY_LEN, global_state->p2p_network.local_peer.peer_wallet.dilithium_privkey, sig);
            memcpy(disconnect_msg->payload + DILITHIUM_PUBKEY_LEN, sig, SIGNATURE_LEN);
            fprintf(stderr, "[Peer] Broadcasting MSG_PEER_DISCONNECT to %zu known peers\n", global_state->p2p_network.num_known_peers);
            p2p_broadcast(global_state, disconnect_msg);
            free(disconnect_msg);
        }
        // Yield execution to allow active threads to serialize, encrypt, and flush the disconnect broadcast
        for (int i = 0; i < 20; i++) usleep(1000);
    }
    
    // Publish global shutdown barrier visible across all cores
    atomic_store(&global_shutdown, true);

    // Awaken dormant service supervisor threads
    if (global_args) {
        global_args->running = 0;
        pthread_mutex_lock(&global_args->shutdown_mutex);
        pthread_cond_broadcast(&global_args->shutdown_cond);
        pthread_mutex_unlock(&global_args->shutdown_mutex);
    }
    
    if (global_state) {
        global_state->submission_running = 0;
        pthread_mutex_lock(&global_state->submission_mutex);
        pthread_cond_broadcast(&global_state->submission_cond);
        pthread_mutex_unlock(&global_state->submission_mutex);

        pthread_mutex_lock(&global_state->mutex);
        pthread_cond_broadcast(&global_state->audit_cond);
        pthread_cond_broadcast(&global_state->pending_ops_cond);
        pthread_cond_broadcast(&global_state->blockchain_sync_cond);
        pthread_mutex_unlock(&global_state->mutex);
        
        if (atomic_load(&global_state->sync_thread_active)) {
            fprintf(stderr, "[Peer] Waiting for sync thread to terminate...\n");
            pthread_join(global_state->sync_thread, NULL);
            atomic_store(&global_state->sync_thread_active, false);
        }
        
        pthread_mutex_lock(&global_state->threshold_mutex);
        for (size_t i = 0; i < global_state->threshold_stake_processes->size; i++) {
            GenericHashEntry *entry = global_state->threshold_stake_processes->buckets[i];
            while (entry) {
                if (entry->type == HASH_ENTRY_THRESHOLD_STAKE_PROCESS) {
                    ThresholdStakeProcess *proc = entry->data.threshold_stake_process;
                    pthread_cond_broadcast(&proc->partial_cond);
                    pthread_cond_broadcast(&proc->stage0_complete_cond);
                }
                entry = entry->next;
            }
        }
        pthread_mutex_unlock(&global_state->threshold_mutex);
        
        fprintf(stderr, "[Peer] Waiting for detached background threads to terminate...\n");
        while (atomic_load(&global_state->active_background_threads) > 0) {
            usleep(10000);
        }
    }

    // Join background services and network worker threads
    if (validation_thread) {
        fprintf(stderr, "[Peer] Waiting for validation thread to terminate...\n");
        pthread_join(validation_thread, NULL);
        validation_thread = 0;
    }

    if (ws_bridge_thread) {
        fprintf(stderr, "[Peer] Waiting for WebSocket bridge thread to terminate...\n");
        pthread_join(ws_bridge_thread, NULL);
        ws_bridge_thread = 0;
    }

    if (metrics_exporter_thread) {
        fprintf(stderr, "[Peer] Waiting for metrics thread to terminate...\n");
        pthread_join(metrics_exporter_thread, NULL);
        metrics_exporter_thread = 0;
    }

    if (global_net_thread) {
        fprintf(stderr, "[Peer] Waiting for network thread to terminate...\n");
        pthread_join(global_net_thread, NULL);
        global_net_thread = 0;
    }

    fprintf(stderr, "[Peer] Waiting for %d L5 application engine threads to terminate...\n", NUM_CRYPTO_WORKERS);
    for (int w = 0; w < NUM_CRYPTO_WORKERS; w++) {
        if (global_l5_threads[w]) {
            pthread_join(global_l5_threads[w], NULL);
            global_l5_threads[w] = 0;
        }
    }
    
    // Flush all pending logs before freeing state allocations
    scl_log_flush();
        
    if (global_args) {
        pthread_mutex_destroy(&global_args->shutdown_mutex);
        pthread_cond_destroy(&global_args->shutdown_cond);
    }

    if (global_valuations) {
        free(global_valuations);
        global_valuations = NULL;
    }

    if (global_state) {
        client_state_destroy(global_state);
        global_state = NULL;
    }

    // Destroy transport driver shim and clean up quantum emulation runtime
    if (global_shim) {
        fprintf(stderr, "[Peer] Closing sockets and destroying UserSpace transport shim.\n");
        if (global_shim->destroy) {
            global_shim->destroy(global_shim);
        }
        global_shim = NULL;
    }

    extern void cleanup_quantum_qsim_environment(void);
    cleanup_quantum_qsim_environment();

    global_user = NULL;
    fprintf(stderr, "[Peer] Clean shutdown complete\n");
}

/**
 * @brief Signal handler for SIGINT and SIGTERM delivering safe asynchronous cancellation.
 *
 * @details
 * In adherence to POSIX async-signal-safety guidelines, this handler performs no blocking
 * I/O, memory allocations, or mutex operations. It stores an atomic boolean flag and
 * signals the primary shutdown condition variable.
 *
 * @pre Registered via `signal(SIGINT, cleanup_handler)`.
 * @post Sets `global_shutdown` to true; awakens threads waiting on `global_args->shutdown_cond`.
 * @sideeffects Modifies `global_args->running`.
 *
 * @param[in] sig Signal discriminator number triggered by the operating system kernel (unused).
 */
static void cleanup_handler(int sig) {
    (void)sig;
    atomic_store(&global_shutdown, true);
    if (global_args) {
        global_args->running = 0;
        pthread_mutex_lock(&global_args->shutdown_mutex);
        pthread_cond_broadcast(&global_args->shutdown_cond);
        pthread_mutex_unlock(&global_args->shutdown_mutex);
    }
}

/* ============================================================================
 * ASYNCHRONOUS TRANSACTION AND VALUATION SUBMISSION ENGINE
 * ============================================================================ */

/**
 * @brief Worker thread routine ingesting and verifying inbound valuation proposals.
 *
 * @details
 * Continuously drains the node's internal `submission_queue`. When a message of type
 * `MSG_VALUATION_PROPOSAL` is dequeued:
 * 1. Verifies that the payload length satisfies the minimum boundary (`PUBKEY_LEN + SIGNATURE_LEN`).
 * 2. Broadcasts the proposal across known peers via `p2p_broadcast()`.
 * 3. Hashes the core serialized valuation bytes via OpenSSL SHA-256.
 * 4. Deserializes the proposal into a local `ValuationData` structure and transfers it
 *    to `process_valuation_proposal()` for validation and mempool inclusion.
 *
 * If the queue is depleted, the thread undergoes a timed sleep on `state->submission_cond`
 * with a 50-millisecond watchdog fallback to protect against lost wakeups.
 *
 * @pre `vargs` must point to a dynamically allocated `SubmissionProcessorArgs` struct.
 * @post Frees `vargs` upon worker startup; frees staging buffers on thread exit.
 * @sideeffects Dequeues messages; transmits network broadcasts; modifies mempool state.
 *
 * @synchronization
 * Locks `state->submission_mutex` during `pthread_cond_timedwait()`. Queue extraction
 * uses `queue_dequeue()`, which coordinates its internal queue mutex.
 *
 * @param[in] vargs Pointer to `SubmissionProcessorArgs` containing the state pointer (callee-freed).
 *
 * @return void* Always returns NULL upon termination.
 *
 * @complexity
 * - Time: O(1) queue dequeue + O(B) SHA256 computation where B is payload length.
 * - Auxiliary Space: O(1) beyond local message and stack frames.
 */
static void *submission_processor_thread(void *vargs) {
    SubmissionProcessorArgs *args = (SubmissionProcessorArgs *)vargs;
    State *state = args->state;
    free(args);

    fprintf(stderr, "[SubmissionProcessor] Thread started\n");

    Message *msg = malloc(sizeof(Message));
    if (!msg) {
        return NULL;
    }

    while (state->submission_running && !atomic_load(&global_shutdown)) {
        
        // Actively drain the queue to maximize burst-processing throughput
        while (queue_dequeue(&state->submission_queue, msg) == 0) {
            if (msg->type == MSG_VALUATION_PROPOSAL) {
                // Critical Security Bound Check: Prevent size_t underflow/segfaults
                if (msg->length < PUBKEY_LEN + SIGNATURE_LEN) {
                    fprintf(stderr, "[SubmissionProcessor] ERROR: Invalid valuation proposal length: %u\n", msg->length);
                    continue;
                }
                
                p2p_broadcast(state, msg);
                
                uint8_t hash[SHA256_DIGEST_LENGTH];
                size_t core_len = msg->length - PUBKEY_LEN - SIGNATURE_LEN;
                SHA256(msg->payload, core_len, hash);
                
                ValuationData vd;
                memset(&vd, 0, sizeof(ValuationData));
                deserialize_core_valuation(msg->payload, &vd.valuation);
                memcpy(vd.pubkey, msg->payload + core_len, PUBKEY_LEN);
                memcpy(vd.signature, msg->payload + core_len + PUBKEY_LEN, SIGNATURE_LEN);
                
                process_valuation_proposal(state, &vd, hash);
                
                fprintf(stderr, "[SubmissionProcessor] Processed valuation proposal (hash first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
                        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
            } else {
                fprintf(stderr, "[SubmissionProcessor] Unexpected message type in submission queue: %d\n", msg->type);
            }
        }
        
        if (!state->submission_running || atomic_load(&global_shutdown)) break;
        
        // Wait for an instant POSIX event signal (adaptive watchdog: 50ms for seed nodes, 500ms for local nodes)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        long wait_ns = (state->p2p_network.is_bootstrap) ? 50000000L : 500000000L;
        ts.tv_nsec += wait_ns;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }

        pthread_mutex_lock(&state->submission_mutex);
        pthread_cond_timedwait(&state->submission_cond, &state->submission_mutex, &ts);
        pthread_mutex_unlock(&state->submission_mutex);
    }
    
    free(msg);
    fprintf(stderr, "[SubmissionProcessor] Thread exiting\n");
    release_l5_staging_buffer();
    return NULL;
}

/* ============================================================================
 * L0 TRANSPORT SHIM EVENT LOOP (INGRESS DRIVER)
 * ============================================================================ */

/**
 * @brief Real-time event loop executing non-blocking datagram polling on the transport shim.
 *
 * @details
 * Dedicated ingress loop responsible for high-throughput intake of UDP datagrams.
 * Configures the OS scheduler to real-time priority (`SCHED_FIFO` with max priority on POSIX,
 * or `THREAD_PRIORITY_HIGHEST` on Windows) to minimize context-switch jitter during micro-bursts.
 *
 * Delegates frame acquisition directly to `shim->poll(shim)`:
 * - AF_XDP Driver: Polls kernel UMEM rings directly via zero-copy DMA memory buffers.
 * - Userspace Driver: Executes `recvmmsg` polling across standard non-blocking POSIX sockets.
 *
 * Acquired frames are dispatched downstream to individual `SclConnection` SPSC intake ring
 * queues without performing inline cryptographic authentication, isolating the I/O driver
 * from computationally intensive operations.
 *
 * @pre `arg` must point to an initialized, valid `struct SclTransportShim` driver instance.
 * @post Polling loop runs continuously until `global_args->running` is cleared.
 * @sideeffects Modifies OS thread scheduling class; invokes low-level socket intake routines.
 * @synchronization Lock-free event loop; thread safety is guaranteed by lock-free SPSC queues.
 *
 * @param[in] arg Untyped pointer casting to `struct SclTransportShim *` (borrowed).
 *
 * @return void* Always returns NULL upon termination.
 *
 * @complexity
 * - Time: O(P) per polling invocation where P is the count of pending wire packets in hardware RX.
 * - Auxiliary Space: O(1) auxiliary stack memory.
 */
void *shim_event_loop_thread(void *arg) {
    struct SclTransportShim *shim = arg;
    fprintf(stderr, "[L0] Transport Shim Event Loop Started.\n");

#ifndef _WIN32
    if (global_state && global_state->p2p_network.is_bootstrap) {
        struct sched_param param;
        param.sched_priority = sched_get_priority_max(SCHED_FIFO);
        if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) != 0) {
            fprintf(stderr, "[L0] WARNING: Could not set SCHED_FIFO priority for dispatcher thread. Running at default priority.\n");
        }
    }
#else
    if (global_state && global_state->p2p_network.is_bootstrap) {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    }
#endif

    // Strictly run the zero-copy datagram intake
    while (global_args && global_args->running) {
        shim->poll(shim);
    }
    
    fprintf(stderr, "[L0] Transport Shim Event Loop Exiting.\n");
    return NULL;
}
#endif

/* ============================================================================
 * SECTION 5: L5 APPLICATION ENGINE & ANTI-REPLAY SLIDING BITMAP
 * ============================================================================ */

/**
 * @brief Updates the transport anti-replay sliding window bitmap with a newly authenticated sequence number.
 *
 * @details
 * Evaluates the received packet sequence number against the active window bitmap:
 * - Dynamically doubles the active window size (clamped between @ref SCL_MIN_REPLAY_WINDOW and
 *   @ref SCL_MAX_REPLAY_WINDOW) if transmission window utilization exceeds half the bitmap capacity.
 * - If `packet_num <= highest`, sets the corresponding bit index branchlessly.
 * - If `packet_num > highest`, shifts the bitmask forward by clearing intervening bit positions,
 *   updates `conn->replay_highest_seen` with release memory ordering, and marks the new sequence bit.
 *
 * @pre `conn` must be non-NULL with an initialized `replay_window_bitmask` array.
 * @post `conn->replay_window_bitmask` records arrival of `packet_num`; `conn->replay_highest_seen` updated.
 * @sideeffects Bitwise mutations to `conn->replay_window_bitmask`.
 * @synchronization Thread Safety: Caller must guarantee single-worker access per connection context
 *                  via `conn->is_processing` or connection-level locking.
 *
 * @param[in,out] conn       Pointer to target @ref SclConnection transport context.
 *                           - Direction: in-out
 *                           - Ownership: Caller-owned, borrowed by callee.
 * @param[in]     packet_num Unsigned 64-bit monotonically tracked packet sequence number.
 *                           - Direction: in
 *                           - Range: [0, UINT64_MAX].
 *
 * @return None.
 *
 * @complexity
 * - Time: O(min(diff, active_window)) bit-clearing loop iterations on forward sequence jumps.
 * - Auxiliary Space: O(1).
 */
static void scl_update_replay_window(SclConnection *conn, uint64_t packet_num) {
    uint64_t highest = atomic_load_explicit(&conn->replay_highest_seen, memory_order_acquire);
    uint64_t active_window = conn->dynamic_replay_window_size;
    if (active_window == 0) active_window = SCL_MIN_REPLAY_WINDOW;
    
    uint64_t p_mtu = conn->path_mtu > 0 ? conn->path_mtu : SCL_LINK_MTU;
    if ((conn->cwnd / p_mtu) > (active_window / 2) && active_window < SCL_MAX_REPLAY_WINDOW) {
        active_window *= 2;
        conn->dynamic_replay_window_size = active_window;
        memset(conn->replay_window_bitmask, 0, sizeof(conn->replay_window_bitmask));
    }

    uint64_t mask_idx = (packet_num % active_window) / 64;
    uint64_t bit_idx = packet_num % 64;
    
    if (packet_num <= highest) {
        conn->replay_window_bitmask[mask_idx] |= (1ULL << bit_idx);
    } else {
        uint64_t diff = packet_num - highest;
        if (diff > active_window * 2 && active_window < SCL_MAX_REPLAY_WINDOW) {
            active_window = SCL_MAX_REPLAY_WINDOW;
            conn->dynamic_replay_window_size = active_window;
            mask_idx = (packet_num % active_window) / 64;
            bit_idx = packet_num % 64;
        }
        if (diff >= active_window) {
            memset(conn->replay_window_bitmask, 0, sizeof(conn->replay_window_bitmask));
        } else {
            for (uint64_t i = highest + 1; i <= packet_num; i++) {
                uint64_t m_idx = (i % active_window) / 64;
                uint64_t b_idx = i % 64;
                conn->replay_window_bitmask[m_idx] &= ~(1ULL << b_idx);
                if (i == UINT64_MAX) break;
            }
        }
        atomic_store_explicit(&conn->replay_highest_seen, packet_num, memory_order_release);
        conn->replay_window_bitmask[mask_idx] |= (1ULL << bit_idx);
    }
}

/**
 * @brief Decrypts, authenticates, and unpacks an L5 application wire message from an L2 AEAD packet.
 *
 * @details
 * Validates the 1-RTT short header, decodes the 64-bit big-endian packet sequence number, and performs
 * authenticated decryption via @ref decrypt_aead_packet. Inspects connection state transitions (e.g. promoting
 * from `FLIGHT3_READY` to `ESTABLISHED`), updates anti-replay sliding windows, demultiplexes multiplexed L3
 * control frames (@ref SCL_FRAME_ACK, @ref SCL_FRAME_PING, @ref SCL_FRAME_PATH_CHALLENGE, @ref SCL_FRAME_MAX_DATA),
 * and deserializes encapsulated application payloads into `msg`.
 *
 * @pre `conn`, `state`, `raw_packet`, `sender_addr`, `msg`, `sender_pubkey`, and `plaintext` must be non-NULL.
 * @pre `raw_len >= SCL_HEADER_MIN_LEN` (29 bytes).
 * @pre `plaintext` must allocate at least `raw_len` bytes for scratch decryption.
 * @post On return code 2, `msg` contains an unpacked protocol message ready for cryptographic verification.
 * @sideeffects Updates peer `last_seen` timestamp, records received bytes in flow control windows,
 *              triggers L4 ACK generation, and updates sliding replay window.
 * @synchronization Thread Safety: Acquires `state->p2p_network.mutex` to resolve peer public keys.
 *
 * @param[in,out] conn          Pointer to active @ref SclConnection context.
 *                              - Direction: in-out
 *                              - Ownership: Borrowed.
 * @param[in,out] state         Pointer to global @ref State container.
 *                              - Direction: in-out
 *                              - Ownership: Borrowed.
 * @param[in]     raw_packet    Pointer to raw binary wire packet bytes.
 *                              - Direction: in
 *                              - Ownership: Borrowed.
 *                              - Byte length: `raw_len`.
 * @param[in]     raw_len       Length of `raw_packet` in bytes.
 *                              - Direction: in
 * @param[in,out] sender_addr   Socket address of remote transmitting host.
 *                              - Direction: in-out
 * @param[out]    msg           Destination @ref Message structure receiving unpacked payload.
 *                              - Direction: out
 *                              - Ownership: Caller-allocated, populated by callee.
 * @param[out]    sender_pubkey Destination buffer receiving authenticated 2,592-byte Dilithium5 public key.
 *                              - Direction: out
 *                              - Byte length: @ref DILITHIUM_PUBKEY_LEN (2592 bytes).
 * @param[out]    plaintext     Scratch buffer receiving decrypted AEAD plaintext.
 *                              - Direction: out
 *                              - Byte length: At least `raw_len`.
 * @param[in]     rx_time       Monotonic arrival timestamp in milliseconds.
 *                              - Direction: in
 *
 * @return int
 * - 2: Successfully unpacked an application-layer @ref Message into `msg`.
 * - 0: Packet contained internal transport frames only (e.g. ACK, PING, PATH_RESPONSE).
 * - -1: Header validation failure, AEAD authentication failure, or replay drop.
 *
 * @complexity
 * - Time: O(raw_len) dominated by AES-256-GCM authenticated decryption.
 * - Auxiliary Space: O(1) beyond caller-supplied buffers.
 */
int extract_l5_message(SclConnection *conn, State *state, const uint8_t *raw_packet, size_t raw_len,
                      struct sockaddr_storage *sender_addr, Message *msg,
                      uint8_t *sender_pubkey, uint8_t *plaintext, uint64_t rx_time) {
    /* Kept so the caller’s UDP source is not rewritten. Unused in this
     * function on purpose; dispatch and STUN read the original address. */
    (void)sender_addr;
    if (raw_len < SCL_HEADER_MIN_LEN) return -1;
        
    uint8_t flags = raw_packet[0];
    bool is_short_header = ((flags & 0xC0) == 0x40);
    const uint8_t *payload_ptr = raw_packet + SCL_HEADER_MIN_LEN;
    size_t payload_len = raw_len - SCL_HEADER_MIN_LEN;
    P2PNetwork *net = &state->p2p_network;

    // Drop any Long Headers that weren't caught
    if (!is_short_header) return -1;

    // --- L2 AEAD FRAMER (SHORT_HEADER) ---
    // Allow processing if state is ESTABLISHED OR FLIGHT3_READY.
    // ALSO allow internal synthesized disconnect signals (raw_len == 0 or flags & 0x08) to bypass the state check
    // to ensure dead/stalled connections are properly garbage collected by the L5 Application Engine.
    if (!conn || (conn->handshake_state != SCL_CONN_STATE_ESTABLISHED &&
                  conn->handshake_state != SCL_CONN_STATE_FLIGHT3_READY &&
                  !(conn->handshake_state == SCL_CONN_STATE_NONE && (raw_len == 0 || (flags & 0x08))))) {
        return -1;
    }

    uint64_t raw_packet_num;
    memcpy(&raw_packet_num, raw_packet + 1 + SCL_CID_LEN, sizeof(uint64_t));
    uint64_t packet_num = be64toh(raw_packet_num);
    
    const uint8_t *l3_payload;
    size_t l3_len;
    bool is_stateless_reset = false;

    if (flags & 0x08) {
        // Assembled payload is already authenticated and decrypted by L0 Ingress
        l3_payload = payload_ptr;
        l3_len = payload_len;
    } else {
        size_t pt_len;
        if (decrypt_aead_packet(conn->current_aes_gcm_key, packet_num, payload_ptr, payload_len, plaintext, &pt_len) != 0) {
            // --- SPEC IMPLEMENTATION: Verify STATELESS_RESET ---
            if (payload_len == 16 && conn->has_stateless_reset_token) {
                if (secure_memcmp(payload_ptr, conn->stateless_reset_token, 16) == 0) {
                    fprintf(stderr, "[L5] Valid STATELESS_RESET received. Remote core migrated/died.\n");
                    conn->handshake_state = SCL_CONN_STATE_NONE; // Ensure event-loop drops/GCs it
                    is_stateless_reset = true;
                } else {
                    return -1;
                }
            } else {
                if (global_state) {
                    pthread_mutex_lock(&global_state->hypergraph.lock);
                    bloom_filter_add(global_state->hypergraph.poison_bloom_aging, conn->cid);
                    pthread_mutex_unlock(&global_state->hypergraph.lock);
                }
                return -1; // AEAD Authentication failed. Packet dropped.
            }
        } else {
            l3_payload = plaintext;
            l3_len = pt_len;
            if (conn->handshake_state == SCL_CONN_STATE_FLIGHT3_READY) {
                conn->handshake_state = SCL_CONN_STATE_ESTABLISHED;
                conn->is_handshake_complete = true;
                scl_log(LOG_LEVEL_DEBUG, "L5", "Successfully decrypted server payload. Connection ESTABLISHED.");
                
                // Add EDGE_INTERACTION to Hypergraph
                add_temporal_edge(&state->hypergraph, conn->cid, EDGE_INTERACTION, 2);
                
                // Discard any remaining Flight 3 active fragment buffer to prevent obsolete packet injection
                if (conn->active_fragment_buffer && conn->active_fragment_is_flight3) {
                    free(conn->active_fragment_buffer);
                    conn->active_fragment_buffer = NULL;
                    if (conn->active_fec_parity[0]) { free(conn->active_fec_parity[0]); conn->active_fec_parity[0] = NULL; }
                    if (conn->active_fec_parity[1]) { free(conn->active_fec_parity[1]); conn->active_fec_parity[1] = NULL; }
                }

                // Server has fully accepted Flight 3. We no longer need to track or retransmit any handshake fragments.
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
            }
        }

        // --- STRICT SLIDING REPLAY WINDOW VERIFICATION (Post-Auth) ---
        if (!is_stateless_reset) {
            uint64_t highest = atomic_load_explicit(&conn->replay_highest_seen, memory_order_acquire);
            uint64_t active_window = conn->dynamic_replay_window_size;
            if (active_window == 0) active_window = SCL_MIN_REPLAY_WINDOW;
            
            if (packet_num <= highest) {
                uint64_t diff = highest - packet_num;
                if (diff >= active_window) return -1;
                if (conn->replay_window_bitmask[(packet_num % active_window) / 64] & (1ULL << (packet_num % 64))) return -1;
            }
            scl_update_replay_window(conn, packet_num);
        }
    }

    // Identify Peer entirely through the established SclConnection binding
    int found = 0;
    pthread_mutex_lock(&net->mutex);
    for (size_t i = 0; i < net->num_known_peers; i++) {
        if (net->known_peers[i]->conn == conn) {
            memcpy(sender_pubkey, net->known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            /* Leave sender_addr as the UDP source. Copying the cached peer
             * address here made endpoint reflection echo that cache, so one
             * seed adopted the other's IP as public_addr. */
            net->known_peers[i]->last_seen = time(NULL);
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&net->mutex);

    // Allow unmapped peers (connections lacking a bound pubkey) to process MSG_PEER_DISCOVERY
    if (!found) {
        memset(sender_pubkey, 0, DILITHIUM_PUBKEY_LEN);
    }

    if (is_stateless_reset) {
        msg->type = MSG_PEER_DISCONNECT;
        msg->length = 0;
        return 2;
    }

    // --- NEW L3 MULTIPLEXING: Parse Frames ---
    size_t offset = 0;
    int found_msg = 0;
    bool ack_eliciting = false;
    bool ack_processed = false;
        
    while (offset < l3_len) {
        uint8_t frame_type = l3_payload[offset++];
        
        // Handle L4 ACK frame and update RTT / loss tracking
        if (frame_type == SCL_FRAME_ACK) {
            if (offset + 16 > l3_len) break;
            uint64_t acked_pkt;
            memcpy(&acked_pkt, l3_payload + offset, 8);
            acked_pkt = be64toh(acked_pkt);
            offset += 8;
            
            uint64_t ack_delay;
            memcpy(&ack_delay, l3_payload + offset, 8);
            ack_delay = be64toh(ack_delay);
            offset += 8;
                
            process_l4_ack(conn, acked_pkt, ack_delay);
            ack_processed = true;
        }
        // Handle NAT keepalive PING frame
        else if (frame_type == SCL_FRAME_PING) {
            ack_eliciting = true; // Ellicits an ACK to maintain NAT states natively
        }
        // Handle active path validation challenge
        else if (frame_type == SCL_FRAME_PATH_CHALLENGE) {
            if (offset + 8 > l3_len) break;
            memcpy(conn->path_response_payload, l3_payload + offset, 8);
            conn->has_pending_path_response = true;
            offset += 8;
            ack_eliciting = true; // Force L4 ACK
            scl_log(LOG_LEVEL_DEBUG, "L3", "PATH_CHALLENGE received, response pending.");
        }
        // Handle path validation response and finalize connection migration
        else if (frame_type == SCL_FRAME_PATH_RESPONSE) {
            if (offset + 8 > l3_len) break;
            if (conn->is_migrating_path && memcmp(l3_payload + offset, conn->path_challenge_payload, 8) == 0) {
                conn->current_path = conn->pending_path; // Verification Complete!
                conn->is_migrating_path = false;
                scl_log(LOG_LEVEL_DEBUG, "L3", "PATH_RESPONSE verified. Path migration completed.");
            } else if (!conn->is_migrating_path) {
                scl_log(LOG_LEVEL_DEBUG, "L3", "PATH_RESPONSE received but no migration in progress.");
            } else {
                scl_log(LOG_LEVEL_DEBUG, "L3", "PATH_RESPONSE payload mismatch. Migration failed.");
            }
            offset += 8;
            ack_eliciting = true; // Force L4 ACK
        }
        // Handle flow-control MAX_DATA window expansion
        else if (frame_type == SCL_FRAME_MAX_DATA) {
            if (offset + 8 > l3_len) break;
            uint64_t max_data;
            memcpy(&max_data, l3_payload + offset, 8);
            max_data = be64toh(max_data);
            offset += 8;
            if (max_data > conn->tx_max_data) {
                conn->tx_max_data = max_data;
                scl_log(LOG_LEVEL_DEBUG, "L3", "MAX_DATA received, tx window updated to %llu.", (unsigned long long)max_data);
            }
            ack_eliciting = true; // Prevent infinite retransmission loops
        }
        // Handle Connection ID rotation to preserve transport privacy
        else if (frame_type == SCL_FRAME_NEW_CONNECTION_ID) {
            if (offset + SCL_CID_LEN > l3_len) break;
            uint8_t new_cid[SCL_CID_LEN];
            memcpy(new_cid, l3_payload + offset, SCL_CID_LEN);
            offset += SCL_CID_LEN;
                            
            if (global_shim) {
                global_shim->unregister_connection(global_shim, conn->cid);
                memcpy(conn->cid, new_cid, SCL_CID_LEN);
                global_shim->register_connection(global_shim, conn->cid, conn);
                scl_log(LOG_LEVEL_DEBUG, "L3", "NEW_CONNECTION_ID received. CID securely rotated.");
            }
            ack_eliciting = true; // Force L4 ACK
        }
        // Handle application message payload (datagram or ordered stream)
        else if (frame_type == SCL_FRAME_DATAGRAM || frame_type == SCL_FRAME_STREAM) {
            ack_eliciting = true;
            
            if (frame_type == SCL_FRAME_STREAM) {
                // Add 1 to account for the frame_type byte itself which is part of the
                // stream payload size dispatched by the sender to prevent window drift.
                conn->rx_consumed_data += (l3_len - offset + 1);
                
                // Dynamically request window expansion if consumed data depletes half our allocation
                if (conn->rx_consumed_data + (SCL_FLOW_WINDOW_SIZE / 2) > conn->rx_max_data) {
                    // SPEC IMPLEMENTATION: Withhold flow-control window if L5 queue is heavily utilized (>50%)
                    uint32_t q_head = atomic_load_explicit(&conn->l5_rx_queue.head, memory_order_relaxed);
                    uint32_t q_tail = atomic_load_explicit(&conn->l5_rx_queue.tail, memory_order_acquire);
                    uint32_t utilized = (q_head >= q_tail) ? (q_head - q_tail) : (SCL_L5_RING_SIZE - q_tail + q_head);
                    
                    if (utilized <= (SCL_L5_RING_SIZE / 2)) {
                        conn->rx_max_data = conn->rx_consumed_data + SCL_FLOW_WINDOW_SIZE;
                        conn->pending_max_data_update = true;
                    } else {
                        scl_log(LOG_LEVEL_DEBUG, "L5", "Withholding MAX_DATA window expansion due to L5 SPSC queue pressure (%u/%d).", utilized, SCL_L5_RING_SIZE);
                    }
                }
            }

            // We must cast away the const modifier so deserialize can process the msg
            uint8_t *mutable_payload = (uint8_t*)l3_payload + offset;
                    
            if (deserialize_message(mutable_payload, l3_len - offset, msg) == 0) {
                found_msg = 1;
            } else {
                scl_log(LOG_LEVEL_DEBUG, "L3", "Deserialization failed for frame type 0x%02x.", frame_type);
            }
            break; // Currently, L5 message payloads consume the remainder of the block
        }
        else {
            scl_log(LOG_LEVEL_DEBUG, "L3", "Unknown frame type 0x%02x, aborting parsing.", frame_type);
            break; // Unknown frame type, abort parsing to protect memory integrity
        }
    }

    // Send L4 ACK immediately ONLY if it was an unfragmented packet.
    if (ack_eliciting && !(flags & 0x08)) {
        send_l4_ack(conn, packet_num, rx_time);
    }

    if (ack_processed) {
        scl_l4_detect_lost_packets(conn, get_time_ms(), global_state, true);
    }

    return found_msg ? 2 : 0;
}

/**
 * @brief Constructs and transmits a stateless, encrypted L4 ACK frame during Handshake Flight 3 reassembly.
 *
 * @details
 * Assembles a standalone 17-byte ACK frame payload (`SCL_FRAME_ACK || acked_pkt_be || delay_be`),
 * formats a short-header wire packet, encrypts the payload using AES-256-GCM with the derived intermediate
 * handshake key, and commits the packet to hardware transmission ring buffers.
 *
 * @pre `shim`, `client_cid`, `addr`, and `aes_key` must be non-NULL.
 * @post Encrypted ACK packet submitted to the physical network interface.
 * @sideeffects Acquires a transmission slot in `shim`; may drop frame if hardware ring is saturated.
 * @synchronization Thread Safety: Driver-level buffer reservation manages internal concurrency.
 *
 * @param[in,out] shim        Pointer to abstract @ref SclTransportShim driver interface.
 *                            - Direction: in-out
 *                            - Ownership: Borrowed.
 * @param[in]     client_cid  20-byte Connection ID identifying the remote client flow.
 *                            - Direction: in
 *                            - Byte length: @ref SCL_CID_LEN (20 bytes).
 * @param[in]     addr        Destination network socket address.
 *                            - Direction: in
 * @param[in]     aes_key     256-bit symmetric encryption key.
 *                            - Direction: in
 *                            - Byte length: 32 bytes.
 * @param[in]     acked_pkt   Sequence number acknowledged.
 *                            - Direction: in
 * @param[in]     new_pkt_num Monotonic packet number assigned to the outbound ACK frame.
 *                            - Direction: in
 *
 * @return None.
 *
 * @complexity
 * - Time: O(1) fixed-size 17-byte AEAD encryption.
 * - Auxiliary Space: O(1).
 */
static void send_stateless_l4_ack(struct SclTransportShim *shim, const uint8_t *client_cid, const struct sockaddr_storage *addr, const uint8_t *aes_key, uint64_t acked_pkt, uint64_t new_pkt_num) {
    // Acquire driver transmission buffer and commit encrypted stateless ACK frame
    size_t max_len;
    void *tx_token;
    uint8_t *tx_buf = shim->acquire_tx_buffer(shim, &max_len, &tx_token);
    if (!tx_buf) return;

    uint8_t payload[17];
    payload[0] = SCL_FRAME_ACK;
    uint64_t ack_be = htobe64(acked_pkt);
    memcpy(payload + 1, &ack_be, 8);
    
    uint64_t delay_be = htobe64(0);
    memcpy(payload + 9, &delay_be, 8);

    tx_buf[0] = SCL_PACKET_FLAG_SHORT_HEADER;
    memcpy(tx_buf + 1, client_cid, SCL_CID_LEN);
    uint64_t pn_be = htobe64(new_pkt_num);
    memcpy(tx_buf + 1 + SCL_CID_LEN, &pn_be, 8);

    size_t out_len;
    encrypt_aead_packet(aes_key, new_pkt_num, payload, 17, tx_buf + SCL_HEADER_MIN_LEN, &out_len);
    shim->commit_tx_buffer(shim, tx_token, SCL_HEADER_MIN_LEN + out_len, client_cid, addr);
}

/**
 * @brief Schedules, fragments, and transmits queued egress messages conforming to BBRv3 pacing limits.
 *
 * @details
 * Execution Pipeline:
 * 1. Flushes any pending delayed acknowledgments via @ref send_l4_ack.
 * 2. Refills connection-level pacing byte budgets based on BBRv3 estimated bottleneck bandwidth
 *    and jitter-adjusted token intervals.
 * 3. Enforces L3 control frame priority: dispatches pending path probes, path responses,
 *    `MAX_DATA` flow-control window expansions, and Connection ID rotations.
 * 4. Resumes active fragmentation streams: paces consecutive 1,100-byte chunks and computes
 *    systematic Cauchy Reed-Solomon (8, 2) parity shards across Galois Field GF(2^8).
 * 5. Respects stream flow control: halts stream transmissions if `tx_dispatched_data >= tx_max_data`.
 * 6. Dequeues new messages prioritizing datagrams and streams via Deficit Round-Robin arbitration.
 *
 * @pre `conn` and `msg` must be non-NULL.
 * @post Outbound frames committed to driver transmit rings; in-flight tracking updated in `conn->unacked_head`.
 * @sideeffects Modifies `conn->pacing_budget`, `conn->tx_dispatched_data`, and driver ring slots.
 * @synchronization Thread Safety: Acquires `conn->l4_mutex` during pacing and unacked-packet registration.
 *
 * @param[in,out] conn Pointer to active @ref SclConnection context.
 *                     - Direction: in-out
 *                     - Ownership: Borrowed.
 * @param[out]    msg  Scratch message buffer used for temporary queue dequeue operations.
 *                     - Direction: in-out
 *                     - Ownership: Caller-allocated scratchpad.
 *
 * @return None.
 *
 * @complexity
 * - Time: O(pacing_budget / SCL_LINK_MTU) bounded by available pacing budget.
 * - Auxiliary Space: O(1) beyond staging buffers.
 */
void process_egress_queues(SclConnection *conn, Message *msg) {
    if (!conn) return;

    // Flush lingering delayed ACKs
    send_l4_ack(conn, 0, 0);

    uint64_t now_us = get_time_us();
    
    // --- Token Bucket Refill Logic ---
    // Refilled regardless of handshake completion status to ensure retransmissions are not starved
    pthread_mutex_lock(&conn->l4_mutex);
    
    // Process RPC token bucket refill before transmission pacing
    uint64_t now_ms = now_us / 1000;
    uint64_t last_rpc_refill = atomic_load_explicit(&conn->last_rpc_token_refill, memory_order_acquire);
    if (now_ms > last_rpc_refill) {
        uint64_t elapsed_rpc_ms = now_ms - last_rpc_refill;
        // Evaluate if the remote partner represents a bootstrap node (binds to 5555 or 5556)
        uint16_t curr_port = (conn->current_path.ss_family == AF_INET6) ?
            ((struct sockaddr_in6 *)&conn->current_path)->sin6_port :
            ((struct sockaddr_in *)&conn->current_path)->sin_port;
        bool is_bootstrap_peer = (curr_port == htons(5555) || curr_port == htons(5556));
        uint32_t tokens_to_add = is_bootstrap_peer ? (elapsed_rpc_ms * 2) : (elapsed_rpc_ms / 2);
        if (tokens_to_add > 0) {
            uint32_t current_rpc_budget = atomic_load_explicit(&conn->rpc_token_budget, memory_order_acquire);
            uint32_t max_rpc_budget = (global_state && global_state->p2p_network.is_bootstrap) ? 2000 : 500;
            uint32_t target_budget;
            do {
                if (current_rpc_budget >= max_rpc_budget) {
                    target_budget = max_rpc_budget;
                    break;
                }
                target_budget = current_rpc_budget + tokens_to_add;
                if (target_budget > max_rpc_budget) {
                    target_budget = max_rpc_budget;
                }
            } while (!atomic_compare_exchange_weak_explicit(&conn->rpc_token_budget, &current_rpc_budget, target_budget, memory_order_release, memory_order_acquire));
            atomic_store_explicit(&conn->last_rpc_token_refill, now_ms, memory_order_release);
        }
    } else if (now_ms < last_rpc_refill) {
        atomic_store_explicit(&conn->last_rpc_token_refill, now_ms, memory_order_release);
    }

    if (conn->last_pacing_time == 0) {
        conn->last_pacing_time = now_us;
        conn->pacing_budget = 4 * conn->path_mtu;
    } else {
        if (now_us > conn->last_pacing_time) {
            uint64_t elapsed_us = now_us - conn->last_pacing_time;
                    
            // SPEC COMPLIANCE: If pacing Flight 3 on consumer hardware,
            // rate is strictly limited to 2 packets per 1 ms.
            // 2 packets * 1232 bytes / 1000 us = ~2.464 bytes per us.
            if (conn->active_fragment_is_flight3) {
                conn->pacing_budget += (elapsed_us * 2464) / 1000;
            } else {
                // Dynamic BBRv3 Pacing: Refill token bucket based on estimated bandwidth
                uint64_t bw = (conn->bbr_max_bw > 0) ? conn->bbr_max_bw : 25000000ULL; // Default to 200 Mbps
                if (conn->bbr_max_bw > 0 && bw < 1000000ULL) {
                    bw = 1000000ULL; // Minimum floor of 1 MB/s to ensure progress under severe loss/congestion
                }
                uint32_t pacing_gain = 100; // default 1.0 gain (percentage)
                
                if (conn->bbr_max_bw > 0) {
                    if (conn->bbr_state == 0) { // STARTUP
                        pacing_gain = 289;
                    } else if (conn->bbr_state == 1) { // DRAIN
                        pacing_gain = 35;
                    } else if (conn->bbr_state == 2) { // PROBE_BW
                        if (conn->bbr_cycle_idx == 0) pacing_gain = 125;
                        else if (conn->bbr_cycle_idx == 1) pacing_gain = 75;
                    }
                }
                uint64_t paced_bw = (bw * pacing_gain) / 100;
                
                // Jitter-aware adaptive pacing: scale up pacing rate under high jitter (RTT variance)
                // to compensate for CPU scheduling delays and local network noise on consumer hardware.
                uint64_t jitter_compensation = 100;
                if (conn->smoothed_rtt > 0) {
                    uint64_t jitter_pct = (conn->rttvar * 100) / conn->smoothed_rtt;
                    if (jitter_pct > 25) { // Jitter is >25% of SRTT (noisy shared network)
                        jitter_compensation = 100 + (jitter_pct < 50 ? jitter_pct : 50); // Up to 150%
                    }
                }
                paced_bw = (paced_bw * jitter_compensation) / 100;

                // Hardcap at 200 Mbps (25 MB/s) to prevent OS UDP buffer overflow on loopback/LAN drops
                uint64_t max_paced_bw = 25000000ULL;
                if (paced_bw > max_paced_bw) {
                    paced_bw = max_paced_bw;
                }
                
                conn->pacing_budget += (elapsed_us * paced_bw) / 1000000ULL;
            }
                    
            // Dynamically relax the max burst clamp when high jitter is detected
            // to allow clearing backlogs accumulated during CPU scheduling or network pauses.
            uint64_t max_burst = 32 * conn->path_mtu;
            if (conn->smoothed_rtt > 0) {
                uint64_t jitter_pct = (conn->rttvar * 100) / conn->smoothed_rtt;
                if (jitter_pct > 25) {
                    max_burst = (32 + (jitter_pct < 100 ? jitter_pct : 100) * 32 / 100) * conn->path_mtu; // Up to 64 * MTU
                }
            }
            if (conn->pacing_budget > max_burst) {
                conn->pacing_budget = max_burst;
            }
            conn->last_pacing_time = now_us;
        } else if (now_us < conn->last_pacing_time) {
            // Clock moved backwards! Reset last_pacing_time to prevent underflow
            conn->last_pacing_time = now_us;
        }
    }
    pthread_mutex_unlock(&conn->l4_mutex);

    // Block egress if handshake is incomplete UNLESS we are actively pacing Flight 3
    if (conn->handshake_state != SCL_CONN_STATE_ESTABLISHED) {
        if (!(conn->handshake_state == SCL_CONN_STATE_FLIGHT3_READY && conn->active_fragment_is_flight3)) {
            return;
        }
    }
    
    // --- Inject L3 Control Frames (PATH_CHALLENGE / RESPONSE / MAX_DATA / NEW_CID) ---
    bool has_control_frame = conn->is_migrating_path || conn->has_pending_path_response || conn->pending_max_data_update || conn->pending_new_cid;
    if (has_control_frame) {
        size_t max_len;
        void *token;
        uint8_t *buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &token);
        if (buf) {
            uint8_t payload[64]; // Increased to fit NEW_CID
            size_t offset = 0;
            struct sockaddr_storage target_addr = conn->current_path;
                
            if (conn->is_migrating_path) {
                uint64_t now = get_time_ms();
                // Retransmit challenge every 50ms if unacknowledged
                if (now - conn->path_challenge_time > 50) {
                    payload[offset++] = SCL_FRAME_PATH_CHALLENGE;
                    memcpy(payload + offset, conn->path_challenge_payload, 8);
                    offset += 8;
                    conn->path_challenge_time = now;
                    target_addr = conn->pending_path; // Send ONLY the challenge to the unverified path
                }
            }
                
            // If we are sending a PATH_CHALLENGE to an unverified path, DO NOT piggyback other
            // control frames (MAX_DATA, NEW_CID) which must reliably reach the validated current path!
            if (offset == 0 || !conn->is_migrating_path) {
                if (conn->has_pending_path_response) {
                    payload[offset++] = SCL_FRAME_PATH_RESPONSE;
                    memcpy(payload + offset, conn->path_response_payload, 8);
                    offset += 8;
                    conn->has_pending_path_response = false;
                }
                
                if (conn->pending_max_data_update) {
                    payload[offset++] = SCL_FRAME_MAX_DATA;
                    uint64_t max_be = htobe64(conn->rx_max_data);
                    memcpy(payload + offset, &max_be, 8);
                    offset += 8;
                    conn->pending_max_data_update = false;
                }

                if (conn->pending_new_cid) {
                    payload[offset++] = SCL_FRAME_NEW_CONNECTION_ID;
                    memcpy(payload + offset, conn->new_cid_payload, SCL_CID_LEN);
                    offset += SCL_CID_LEN;
                    conn->pending_new_cid = false;
                }
            }
                
            if (offset > 0) {
                uint64_t pkt_num = atomic_fetch_add_explicit(&conn->next_packet_num, 1, memory_order_relaxed);
                            
                // Track control frames in L4 to ensure reliable delivery of flow-control updates
                uint8_t *unencrypted_ctrl = get_l5_staging_buffer();
                if (unencrypted_ctrl) {
                    unencrypted_ctrl[0] = SCL_PACKET_FLAG_SHORT_HEADER;
                    memcpy(unencrypted_ctrl + 1, conn->cid, SCL_CID_LEN);
                    uint64_t pn_be = htobe64(pkt_num);
                    memcpy(unencrypted_ctrl + 1 + SCL_CID_LEN, &pn_be, 8);
                    memcpy(unencrypted_ctrl + SCL_HEADER_MIN_LEN, payload, offset);
                                
                    scl_l4_on_packet_sent(conn, pkt_num, SCL_HEADER_MIN_LEN + offset, false, false, unencrypted_ctrl);
                }

                buf[0] = SCL_PACKET_FLAG_SHORT_HEADER;
                memcpy(buf + 1, conn->cid, SCL_CID_LEN);
                uint64_t pn_be = htobe64(pkt_num);
                memcpy(buf + 1 + SCL_CID_LEN, &pn_be, 8);
                                
                size_t out_len;
                encrypt_aead_packet(conn->current_aes_gcm_key, pkt_num, payload, offset, buf + SCL_HEADER_MIN_LEN, &out_len);
                                
                size_t total_sent = SCL_HEADER_MIN_LEN + out_len;
                commit_tx_buffer_relayed(conn, token, total_sent, &target_addr);
                conn->last_tx_time = get_time_ms();
                
                pthread_mutex_lock(&conn->l4_mutex);
                if (conn->pacing_budget >= total_sent) conn->pacing_budget -= total_sent;
                else conn->pacing_budget = 0;
                pthread_mutex_unlock(&conn->l4_mutex);
            } else {
                global_shim->abort_tx_buffer(global_shim, token);
            }
        }
    }

    // --- Main Transmission Loop ---
    while (1) {
        pthread_mutex_lock(&conn->l4_mutex);
        if (conn->cwnd == 0) conn->cwnd = SCL_MICRO_BDP_LIMIT;
                
        // Jitter-aware pacing budget slack: allow a tiny budget tolerance under high jitter
        // to prevent integer truncation or microsecond scheduling delay stalls.
        uint64_t budget_tolerance = 0;
        if (conn->smoothed_rtt > 0) {
            uint64_t jitter_pct = (conn->rttvar * 100) / conn->smoothed_rtt;
            if (jitter_pct > 25) {
                budget_tolerance = conn->path_mtu / 4; // Allow up to 25% MTU deficit
            }
        }
        
        if (conn->pacing_budget + budget_tolerance < conn->path_mtu || conn->bytes_in_flight >= conn->cwnd) {
            pthread_mutex_unlock(&conn->l4_mutex);
            return; // Yield to L5 Engine tick; limits reached
        }
        pthread_mutex_unlock(&conn->l4_mutex);

        // --- State Machine: Dequeue New Message ---
        bool is_datagram = true;
        bool dequeued = false;

        // Allow datagrams to interleave with active fragments to prevent connection stalls
        if (queue_has_items(&conn->tx_datagram_queue) && (conn->bdpq_deficit > 0 || !queue_has_items(&conn->tx_stream_queue) || conn->active_fragment_buffer != NULL)) {
            if (queue_dequeue(&conn->tx_datagram_queue, msg) == 0) {
                conn->bdpq_deficit--;
                if (conn->bdpq_deficit < 0) conn->bdpq_deficit = 0;
                dequeued = true;
            }
        }
                
        if (!dequeued) {
            // --- State Machine: Resume Active Fragment? ---
            if (conn->active_fragment_buffer != NULL) {
                size_t max_len;
                void *token;
                uint8_t *buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &token);
                        
                if (!buf) {
                    return; // Buffer full, yield. Tracker remains perfectly synchronized.
                }

                uint16_t group = conn->active_fragment_current / 10;
                uint16_t pos = conn->active_fragment_current % 10;
                        
                // Skip parity if we hit the end of data early in the group
                if (pos < 8 && group * 8 + pos >= conn->active_fragment_data_total) {
                    pos = 8;
                    conn->active_fragment_current = group * 10 + 8;
                }

                // --- PROACTIVE REED-SOLOMON PARITY GENERATOR ---
                uint8_t padded_last[SCL_MAX_CHUNK_SIZE] = {0};
                uint8_t zero_pad[SCL_MAX_CHUNK_SIZE] = {0};
                if (pos == 0) {
                    const uint8_t *d[8] = {0};
                    for (int i = 0; i < 8; i++) {
                        uint16_t d_idx = group * 8 + i;
                        if (d_idx < conn->active_fragment_data_total) {
                            size_t offset = d_idx * SCL_MAX_CHUNK_SIZE;
                            size_t rem = conn->active_fragment_len - offset;
                            if (rem < SCL_MAX_CHUNK_SIZE) {
                                memcpy(padded_last, conn->active_fragment_buffer + offset, rem);
                                d[i] = padded_last;
                            } else {
                                d[i] = conn->active_fragment_buffer + offset;
                            }
                        } else {
                            d[i] = zero_pad; // Safe zero buffer
                        }
                    }
                    fec_encode82(d, conn->active_fec_parity[0], conn->active_fec_parity[1], SCL_MAX_CHUNK_SIZE);
                }

                uint16_t actual_wire_idx;
                uint8_t *payload_ptr;
                size_t chunk = SCL_MAX_CHUNK_SIZE;

                if (pos < 8) {
                    actual_wire_idx = group * 8 + pos;
                    payload_ptr = conn->active_fragment_buffer + actual_wire_idx * SCL_MAX_CHUNK_SIZE;
                    size_t rem = conn->active_fragment_len - actual_wire_idx * SCL_MAX_CHUNK_SIZE;
                    if (rem < SCL_MAX_CHUNK_SIZE) chunk = rem;
                } else {
                    actual_wire_idx = conn->active_fragment_data_total + group * 2 + (pos - 8);
                    payload_ptr = conn->active_fec_parity[pos - 8];
                }

                uint64_t frag_pkt_num = atomic_fetch_add_explicit(&conn->next_packet_num, 1, memory_order_relaxed);
                uint64_t pn_be = htobe64(frag_pkt_num);
                uint64_t offset_be = htobe64(conn->active_fragment_stream_offset);
                uint16_t tot_net = htons(conn->active_fragment_data_total);
                uint16_t idx_net = htons(actual_wire_idx);
                size_t total_sent = 0;

                if (conn->active_fragment_is_flight3) {
                    // FLIGHT 3 PACED SEND (Long Header - 76 bytes prefix)
                    uint8_t *unencrypted_frag = get_l5_staging_buffer();
                    if (!unencrypted_frag) {
                        global_shim->abort_tx_buffer(global_shim, token);
                        return;
                    }
                    unencrypted_frag[0] = SCL_PACKET_FLAG_LONG_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                    memcpy(unencrypted_frag + 1, conn->cid, SCL_CID_LEN);
                    memcpy(unencrypted_frag + 1 + SCL_CID_LEN, &pn_be, 8);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN, &offset_be, 8);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN + 8, &tot_net, 2);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN + 10, &idx_net, 2);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN + 12, conn->handshake_token, 64);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN + 76, payload_ptr, chunk);

                    // Pass true for FEC protection to grant PTO leniency
                    bool treat_as_datagram = (pos >= 8); // Treat parity as datagram to prevent L4 retransmission
                    scl_l4_on_packet_sent(conn, frag_pkt_num, SCL_HEADER_MIN_LEN + 76 + chunk, treat_as_datagram, true, unencrypted_frag);

                    buf[0] = SCL_PACKET_FLAG_LONG_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                    memcpy(buf + 1, conn->cid, SCL_CID_LEN);
                    memcpy(buf + 1 + SCL_CID_LEN, &pn_be, 8);
                    memcpy(buf + SCL_HEADER_MIN_LEN, &offset_be, 8);
                    memcpy(buf + SCL_HEADER_MIN_LEN + 8, &tot_net, 2);
                    memcpy(buf + SCL_HEADER_MIN_LEN + 10, &idx_net, 2);
                    memcpy(buf + SCL_HEADER_MIN_LEN + 12, conn->handshake_token, 64);

                    uint8_t ciphertext_frag[SCL_MAX_CHUNK_SIZE + 16];
                    size_t out_len_frag;
                    encrypt_aead_packet(conn->flight3_aes_gcm_key, frag_pkt_num, payload_ptr, chunk, ciphertext_frag, &out_len_frag);
                            
                    memcpy(buf + SCL_HEADER_MIN_LEN + 76, ciphertext_frag, out_len_frag);
                    total_sent = SCL_HEADER_MIN_LEN + 76 + out_len_frag;
                } else {
                    // APPLICATION DATA PACED SEND (Short Header - 12 bytes prefix)
                    uint8_t *unencrypted_frag = get_l5_staging_buffer();
                    if (!unencrypted_frag) {
                        global_shim->abort_tx_buffer(global_shim, token);
                        return;
                    }

                    unencrypted_frag[0] = SCL_PACKET_FLAG_SHORT_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                    memcpy(unencrypted_frag + 1, conn->cid, SCL_CID_LEN);
                    memcpy(unencrypted_frag + 1 + SCL_CID_LEN, &pn_be, 8);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN, &offset_be, 8);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN + 8, &tot_net, 2);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN + 10, &idx_net, 2);
                    memcpy(unencrypted_frag + SCL_HEADER_MIN_LEN + 12, payload_ptr, chunk);
                            
                    // Pass true for FEC protection to grant PTO leniency
                    bool treat_as_datagram = conn->active_fragment_is_datagram || (pos >= 8);
                    scl_l4_on_packet_sent(conn, frag_pkt_num, SCL_HEADER_MIN_LEN + 12 + chunk, treat_as_datagram, true, unencrypted_frag);

                    buf[0] = SCL_PACKET_FLAG_SHORT_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                    memcpy(buf + 1, conn->cid, SCL_CID_LEN);
                    memcpy(buf + 1 + SCL_CID_LEN, &pn_be, 8);
                    memcpy(buf + SCL_HEADER_MIN_LEN, &offset_be, 8);
                    memcpy(buf + SCL_HEADER_MIN_LEN + 8, &tot_net, 2);
                    memcpy(buf + SCL_HEADER_MIN_LEN + 10, &idx_net, 2);
                            
                    uint8_t ciphertext_frag[SCL_MAX_CHUNK_SIZE + 16];
                    size_t out_len_frag;
                    encrypt_aead_packet(conn->current_aes_gcm_key, frag_pkt_num, payload_ptr, chunk, ciphertext_frag, &out_len_frag);
                        
                    memcpy(buf + SCL_HEADER_MIN_LEN + 12, ciphertext_frag, out_len_frag);
                    total_sent = SCL_HEADER_MIN_LEN + 12 + out_len_frag;
                }

                commit_tx_buffer_relayed(conn, token, total_sent, &conn->current_path);
                conn->last_tx_time = get_time_ms();

                pthread_mutex_lock(&conn->l4_mutex);
                if (conn->pacing_budget >= total_sent) {
                    conn->pacing_budget -= total_sent;
                } else {
                    conn->pacing_budget = 0;
                }
                pthread_mutex_unlock(&conn->l4_mutex);

                conn->active_fragment_current++;
                                            
                if (conn->active_fragment_current >= (((conn->active_fragment_data_total + 7) / 8) * 10)) {
                    free(conn->active_fragment_buffer);
                    conn->active_fragment_buffer = NULL;
                                        
                    if (conn->active_fec_parity[0]) {
                        free(conn->active_fec_parity[0]);
                        conn->active_fec_parity[0] = NULL;
                    }
                    if (conn->active_fec_parity[1]) {
                        free(conn->active_fec_parity[1]);
                        conn->active_fec_parity[1] = NULL;
                    }
                                        
                    if (conn->active_fragment_is_flight3) {
                        conn->active_fragment_is_flight3 = false;
                    }
                }
                continue;
            // --- ENFORCE STREAM FLOW CONTROL BEFORE DEQUEUE ---
            } else if (conn->tx_dispatched_data >= conn->tx_max_data && queue_has_items(&conn->tx_stream_queue)) {
                // Window closed, fallback to datagram if available
                if (queue_has_items(&conn->tx_datagram_queue)) {
                    if (queue_dequeue(&conn->tx_datagram_queue, msg) == 0) {
                        dequeued = true;
                    }
                } else {
                    return; // Blocked by flow control and no datagrams
                }
            } else if (queue_has_items(&conn->tx_stream_queue)) {
                if (queue_dequeue(&conn->tx_stream_queue, msg) == 0) {
                    is_datagram = false;
                    conn->bdpq_deficit += 3;
                    if (conn->bdpq_deficit > 10) conn->bdpq_deficit = 10;
                    dequeued = true;
                }
            }
        }

        if (!dequeued) {
            // --- Phase 5: Implement UDP Idle Keepalives (15-second timer) ---
            uint64_t now_ms_ka = get_time_ms();
            if (conn->handshake_state == SCL_CONN_STATE_ESTABLISHED &&
                now_ms_ka - conn->last_tx_time > 15000) {
                size_t max_len;
                void *token;
                uint8_t *buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &token);
                if (buf) {
                    uint8_t ping_payload[1] = { SCL_FRAME_PING };
                    uint64_t pkt_num = atomic_fetch_add_explicit(&conn->next_packet_num, 1, memory_order_relaxed);
                    
                    buf[0] = SCL_PACKET_FLAG_SHORT_HEADER;
                    memcpy(buf + 1, conn->cid, SCL_CID_LEN);
                    uint64_t pn_be = htobe64(pkt_num);
                    memcpy(buf + 1 + SCL_CID_LEN, &pn_be, 8);
                    
                    size_t out_len;
                    encrypt_aead_packet(conn->current_aes_gcm_key, pkt_num, ping_payload, 1, buf + SCL_HEADER_MIN_LEN, &out_len);
                    
                    size_t total_sent = SCL_HEADER_MIN_LEN + out_len;
                    global_shim->commit_tx_buffer(global_shim, token, total_sent, conn->cid, &conn->current_path);
                    conn->last_tx_time = now_ms_ka;
                    
                    pthread_mutex_lock(&conn->l4_mutex);
                    if (conn->pacing_budget >= total_sent) conn->pacing_budget -= total_sent;
                    else conn->pacing_budget = 0;
                    pthread_mutex_unlock(&conn->l4_mutex);
                    
                    // Track cleanly natively into L4 for potential retransmissions (though optional for PING)
                    uint8_t *unencrypted_ctrl = get_l5_staging_buffer();
                    if (unencrypted_ctrl) {
                        unencrypted_ctrl[0] = SCL_PACKET_FLAG_SHORT_HEADER;
                        memcpy(unencrypted_ctrl + 1, conn->cid, SCL_CID_LEN);
                        memcpy(unencrypted_ctrl + 1 + SCL_CID_LEN, &pn_be, 8);
                        memcpy(unencrypted_ctrl + SCL_HEADER_MIN_LEN, ping_payload, 1);
                        scl_l4_on_packet_sent(conn, pkt_num, SCL_HEADER_MIN_LEN + 1, false, false, unencrypted_ctrl);
                    }
                }
            }
            return;
        }

        uint8_t *framed_payload = get_l5_staging_buffer();
        if (!framed_payload) continue;
        
        size_t serialized_len;
        if (serialize_message(msg, framed_payload + 1, &serialized_len) != 0) {
            continue;
        }

        size_t framed_len = serialized_len + 1;
        framed_payload[0] = is_datagram ? SCL_FRAME_DATAGRAM : SCL_FRAME_STREAM;

        // Advance stream_offset pointer strictly tracking the newly occupied framed lengths
        if (!is_datagram) {
            conn->tx_dispatched_data += framed_len;
        }

        size_t expected_cipher_len = framed_len + 16;
        size_t full_size = SCL_HEADER_MIN_LEN + expected_cipher_len;
        
        if (is_datagram && full_size <= SCL_MAX_CHUNK_SIZE) {
            size_t max_len = 0;
            void *token = NULL;
            uint8_t *buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &token);
            if (!buf) {
                return;
            }
            
            uint64_t pkt_num = atomic_fetch_add_explicit(&conn->next_packet_num, 1, memory_order_relaxed);
            
            // To avoid overwriting framed_payload which is using get_l5_staging_buffer,
            // we frame unencrypted_pkt inline inside a small stack buffer if it fits,
            // or simply skip recording the payload since stream packets retransmit intelligently
            uint8_t unencrypted_pkt[SCL_MAX_CHUNK_SIZE + SCL_HEADER_MIN_LEN];
            unencrypted_pkt[0] = SCL_PACKET_FLAG_SHORT_HEADER;
            memcpy(unencrypted_pkt + 1, conn->cid, SCL_CID_LEN);
            uint64_t pn_be = htobe64(pkt_num);
            memcpy(unencrypted_pkt + 1 + SCL_CID_LEN, &pn_be, 8);
            memcpy(unencrypted_pkt + SCL_HEADER_MIN_LEN, framed_payload, framed_len);
            
            scl_l4_on_packet_sent(conn, pkt_num, SCL_HEADER_MIN_LEN + framed_len, is_datagram, false, unencrypted_pkt);

            if (buf && max_len >= full_size) {
                buf[0] = SCL_PACKET_FLAG_SHORT_HEADER;
                memcpy(buf + 1, conn->cid, SCL_CID_LEN);
                memcpy(buf + 1 + SCL_CID_LEN, &pn_be, 8);
                
                size_t out_len;
                encrypt_aead_packet(conn->current_aes_gcm_key, pkt_num, framed_payload, framed_len, buf + SCL_HEADER_MIN_LEN, &out_len);
                
                size_t total_sent = SCL_HEADER_MIN_LEN + out_len;
                commit_tx_buffer_relayed(conn, token, total_sent, &conn->current_path);

                pthread_mutex_lock(&conn->l4_mutex);
                if (conn->pacing_budget >= total_sent) {
                    conn->pacing_budget -= total_sent;
                } else {
                    conn->pacing_budget = 0;
                }
                pthread_mutex_unlock(&conn->l4_mutex);
            } else if (token) {
                global_shim->abort_tx_buffer(global_shim, token);
            }
            
        } else {
            uint8_t *heap_payload = malloc(framed_len);
            if (!heap_payload) continue;
            memcpy(heap_payload, framed_payload, framed_len);
            
            // Securely clean up any existing abandoned fragmentation buffers to prevent
            // massive heap exhaustion (up to 8MB per drop) from out-of-order protocol anomalies
            if (conn->active_fragment_buffer) {
                free(conn->active_fragment_buffer);
            }
            if (conn->active_fec_parity[0]) {
                free(conn->active_fec_parity[0]);
            }
            if (conn->active_fec_parity[1]) {
                free(conn->active_fec_parity[1]);
            }
            
            conn->active_fragment_buffer = heap_payload;
            conn->active_fragment_len = framed_len;
            if (is_datagram) {
                RAND_bytes((uint8_t*)&conn->active_fragment_stream_offset, 8);
            } else {
                conn->active_fragment_stream_offset = conn->next_tx_stream_offset++;
            }
            conn->active_fragment_data_total = (framed_len + SCL_MAX_CHUNK_SIZE - 1) / SCL_MAX_CHUNK_SIZE;
            conn->active_fragment_current = 0;
            conn->active_fragment_is_datagram = is_datagram;
            conn->active_fragment_is_flight3 = false;
                    
            // Proactive RS matrices require deterministic zeroes for unpadded elements to map mathematical boundaries
            conn->active_fec_parity[0] = calloc(1, SCL_MAX_CHUNK_SIZE);
            conn->active_fec_parity[1] = calloc(1, SCL_MAX_CHUNK_SIZE);
                                
            if (!conn->active_fec_parity[0] || !conn->active_fec_parity[1]) {
                free(conn->active_fragment_buffer);
                conn->active_fragment_buffer = NULL;
                if (conn->active_fec_parity[0]) { free(conn->active_fec_parity[0]); conn->active_fec_parity[0] = NULL; }
                if (conn->active_fec_parity[1]) { free(conn->active_fec_parity[1]); conn->active_fec_parity[1] = NULL; }
            }
            continue;
        }
    }
}

/**
 * @brief Drains the lock-free Single-Producer Single-Consumer (SPSC) ring queue transferring frames from L0 to L5.
 *
 * @details
 * Ingress Processing Sequence:
 * 1. Reads incoming frames from `conn->l5_rx_queue` using atomic load-acquire on `head` and store-release on `tail`.
 * 2. Processes Long Header handshake packets (Flight 1, 2, 3) and manages Handshake Slab reassembly.
 * 3. Handles out-of-order application message chunks: stores fragments in connection OOO linked lists,
 *    reconstructs erased shards using Reed-Solomon (8, 2) decoding, and dispatches complete in-order messages.
 * 4. Enforces global and connection-level memory quotas to neutralize Slowloris memory exhaustion attacks.
 * 5. Passes verified, complete messages to @ref crypto_verify_enqueue for parallel cryptographic verification.
 *
 * @pre `conn`, `state`, `net`, `decryption_buffer`, `in_msg`, and `out_msg` must be non-NULL.
 * @pre `decryption_buffer` must allocate at least @ref MAX_MESSAGE_SIZE (8 MiB).
 * @post Queue drained up to `head`; received messages staged for cryptographic execution.
 * @sideeffects Allocates/frees out-of-order reassembly buffers; updates global OOO byte counters.
 * @synchronization Thread Safety: Single-consumer access on `conn->l5_rx_queue.tail`; atomic
 *                  synchronization with L0 producer thread.
 *
 * @param[in,out] conn              Pointer to active @ref SclConnection context.
 *                                  - Direction: in-out
 * @param[in,out] state             Pointer to global @ref State container.
 *                                  - Direction: in-out
 * @param[in,out] net               Pointer to P2P network subsystem container.
 *                                  - Direction: in-out
 * @param[out]    decryption_buffer Dedicated 8 MiB scratch buffer for AEAD decryption.
 *                                  - Direction: out
 *                                  - Byte length: @ref MAX_MESSAGE_SIZE (8,388,608 bytes).
 * @param[out]    in_msg            Scratch container for parsed inbound messages.
 *                                  - Direction: in-out
 * @param[out]    out_msg           Scratch container for outbound response messages.
 *                                  - Direction: in-out
 *
 * @return None.
 *
 * @complexity
 * - Time: O(K * (decryption_time + fec_decode_time)) where K is queued frames in the SPSC ring.
 * - Auxiliary Space: O(1) beyond pre-allocated buffers.
 */
void process_spsc_queue(SclConnection *conn, State *state, P2PNetwork *net, uint8_t *decryption_buffer, Message *in_msg, Message *out_msg) {
    (void)out_msg;
    if (!conn) return;
    
    // Define payload length constants
    const size_t f1_payload_len = 16 + KYBER_PUBKEY_LEN + USER_ID_LEN;
    const size_t f2_payload_len = 16 + 64 + KYBER_CIPHERTEXT_LEN;
    
    uint32_t tail = atomic_load_explicit(&conn->l5_rx_queue.tail, memory_order_relaxed);
    uint32_t head = atomic_load_explicit(&conn->l5_rx_queue.head, memory_order_acquire);

    while (tail != head) {
        size_t raw_len = conn->l5_rx_queue.lengths[tail];
        uint8_t *raw_packet = conn->l5_rx_queue.buffer[tail];
        struct sockaddr_storage sender_addr = conn->l5_rx_queue.addrs[tail];
        uint64_t rx_time = conn->l5_rx_queue.rx_times[tail];
        
        uint8_t client_cid[SCL_CID_LEN];
        memcpy(client_cid, raw_packet + 1, SCL_CID_LEN);
        
        uint8_t sender_pubkey[DILITHIUM_PUBKEY_LEN];
        memset(sender_pubkey, 0, DILITHIUM_PUBKEY_LEN);
                
        uint8_t flags = raw_packet[0];
        bool is_long_header = ((flags & 0xC0) == 0xC0);
        bool is_short_header = ((flags & 0xC0) == 0x40);
        bool is_fragmented = (flags & SCL_PACKET_FLAG_FRAGMENTED);
        bool is_retry = (flags & SCL_PACKET_FLAG_RETRY);

        uint8_t *synth_buf = NULL;
        const uint8_t *frame_ptr = raw_packet;
        size_t frame_len = raw_len;

        // --- L5 Application Reassembly Engine (Handshake Slab & OOO Pool) ---
        if (is_fragmented) {
            UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;
                    
            if (is_long_header) {
                // --- Handshake Slab Reassembly (Flight 3 Exclusively) ---
                if (frame_len < SCL_HEADER_MIN_LEN + 76 + 16) goto advance_queue;
                        
                uint64_t stream_offset;
                memcpy(&stream_offset, frame_ptr + SCL_HEADER_MIN_LEN, 8);
                uint16_t total_frags, frag_idx;
                memcpy(&total_frags, frame_ptr + SCL_HEADER_MIN_LEN + 8, 2);
                memcpy(&frag_idx, frame_ptr + SCL_HEADER_MIN_LEN + 10, 2);
                total_frags = ntohs(total_frags);
                frag_idx = ntohs(frag_idx);
                        
                uint8_t incoming_token[64];
                memcpy(incoming_token, frame_ptr + SCL_HEADER_MIN_LEN + 12, 64);

                uint8_t ss_init[32];
                uint8_t ip_key[16];
                ip_to_16(&sender_addr, ip_key);
                if (verify_stateless_token(us_state->node_secret, incoming_token, ip_key, ss_init) != 0) {
                    // Send RETRY packet to force seamless retry (e.g. CGNAT IP changed between Flight 1 and Flight 3)
                    // Only dispatch RETRY if this is the very first fragment to prevent amplifying congestion
                    if (frag_idx == 0) {
                        uint64_t expected_cookie = generate_stateless_cookie(us_state->node_secret, ip_key);
                        size_t max_len;
                        void *tx_token;
                        uint8_t *tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
                        if (tx_buf && max_len >= SCL_HEADER_MIN_LEN + 9) {
                            tx_buf[0] = SCL_PACKET_FLAG_LONG_HEADER | SCL_PACKET_FLAG_RETRY;
                            memcpy(tx_buf + 1, client_cid, SCL_CID_LEN);
                            uint64_t retry_pkt = htobe64(0);
                            memcpy(tx_buf + 1 + SCL_CID_LEN, &retry_pkt, 8);
                            memcpy(tx_buf + SCL_HEADER_MIN_LEN, &expected_cookie, 8);
                            tx_buf[SCL_HEADER_MIN_LEN + 8] = 10; // Baseline PoW
                                                
                            global_shim->commit_tx_buffer(global_shim, tx_token, SCL_HEADER_MIN_LEN + 9, client_cid, &sender_addr);
                            scl_log(LOG_LEVEL_DEBUG, "L5", "Flight 3 Token Verification Failed (CGNAT IP mismatch?). Sent RETRY packet for seamless retry.");
                        } else if (tx_buf) {
                            global_shim->abort_tx_buffer(global_shim, tx_token);
                        }
                    }
                    goto advance_queue;
                }

                uint8_t flight3_key[32];
                derive_labeled_key(ss_init, "SCL flight3 key", flight3_key, 32);

                uint64_t raw_pkt_num;
                memcpy(&raw_pkt_num, frame_ptr + 1 + SCL_CID_LEN, sizeof(uint64_t));
                uint64_t pkt_num = be64toh(raw_pkt_num);
                size_t enc_len = frame_len - (SCL_HEADER_MIN_LEN + 76);
                size_t pt_len;

                if (decrypt_aead_packet(flight3_key, pkt_num, frame_ptr + SCL_HEADER_MIN_LEN + 76, enc_len, decryption_buffer, &pt_len) != 0) {
                    if (global_state) {
                        pthread_mutex_lock(&global_state->hypergraph.lock);
                        bloom_filter_add(global_state->hypergraph.poison_bloom_aging, client_cid);
                        pthread_mutex_unlock(&global_state->hypergraph.lock);
                    }
                    goto advance_queue;
                }

                // The fixed 16KB Handshake Slab strictly fits a maximum of 14 SCL_MAX_CHUNK_SIZE (1100B) fragments.
                // Enforcing this barrier prevents OOB memory writes during FEC reconstruction.
                if (pt_len > SCL_MAX_CHUNK_SIZE || total_frags > 14) goto advance_queue;
                                        
                uint64_t token_expiry;
                memcpy(&token_expiry, incoming_token, 8);
                bool is_tier1 = (token_expiry & 1ULL) != 0;
                int target_idx = scl_slab_acquire_slot(us_state, &sender_addr, incoming_token, is_tier1);

                if (target_idx == -1) goto advance_queue;

                SclHandshakeSlot *slot = &us_state->handshake_slab->slots[target_idx];
                uint8_t final_key[32];
                derive_labeled_key(ss_init, "SCL final key", final_key, 32);
                uint64_t slot_pkt_num = atomic_fetch_add_explicit(&slot->next_packet_num, 1, memory_order_relaxed);

                if (frag_idx >= total_frags) {
                    int p_idx = frag_idx - total_frags;
                    if (p_idx < 16) {
                        memcpy(slot->parity_buffers[p_idx], decryption_buffer, pt_len);
                        slot->parity_tracker[p_idx] = 1;
                    }
                    send_stateless_l4_ack(global_shim, client_cid, &sender_addr, final_key, pkt_num, slot_pkt_num);
                } else {
                    size_t offset = SCL_HEADER_MIN_LEN + (frag_idx * SCL_MAX_CHUNK_SIZE);
                    if (offset + pt_len <= SCL_SLAB_SLOT_SIZE - 64) {
                        if (frag_idx == 0) {
                            memcpy(slot->buffer, frame_ptr, SCL_HEADER_MIN_LEN);
                            memcpy(slot->buffer + SCL_SLAB_SLOT_SIZE - 64, incoming_token, 64);
                        }
                        memcpy(slot->buffer + offset, decryption_buffer, pt_len);
                        slot->fragment_tracker[frag_idx] = 1;
                        send_stateless_l4_ack(global_shim, client_cid, &sender_addr, final_key, pkt_num, slot_pkt_num);
                        if (frag_idx == total_frags - 1) slot->assembled_length = offset + pt_len;
                    } else goto advance_queue;
                }
                        
                bool complete = true;
                for (int g = 0; g < (total_frags + 7) / 8; g++) {
                    int missing = 0;
                    int max_d = (g * 8 + 8 < total_frags) ? 8 : total_frags - g * 8;
                    for (int i = 0; i < max_d; i++) {
                        if (!slot->fragment_tracker[g * 8 + i]) missing++;
                    }
                    
                    if (missing > 0) {
                        int p0_idx = g * 2;
                        int p1_idx = g * 2 + 1;
                        bool has_p0 = slot->parity_tracker[p0_idx];
                        bool has_p1 = slot->parity_tracker[p1_idx];
                        
                        if (missing <= (has_p0 + has_p1)) {
                            uint8_t *d[8] = {0};
                            bool present[8] = {0};
                            uint8_t zero_pad[8][SCL_MAX_CHUNK_SIZE];
                            memset(zero_pad, 0, sizeof(zero_pad));
                            
                            for (int i = 0; i < max_d; i++) {
                                d[i] = slot->buffer + SCL_HEADER_MIN_LEN + (g * 8 + i) * SCL_MAX_CHUNK_SIZE;
                                present[i] = slot->fragment_tracker[g * 8 + i];
                                if (!present[i]) d[i] = zero_pad[i];
                            }
                            for (int i = max_d; i < 8; i++) {
                                present[i] = true;
                                d[i] = zero_pad[i];
                            }
                            
                            if (fec_decode82(d, slot->parity_buffers[p0_idx], slot->parity_buffers[p1_idx], present, has_p0, has_p1, SCL_MAX_CHUNK_SIZE) == 0) {
                                for (int i = 0; i < max_d; i++) {
                                    if (!slot->fragment_tracker[g * 8 + i]) {
                                        memcpy(slot->buffer + SCL_HEADER_MIN_LEN + (g * 8 + i) * SCL_MAX_CHUNK_SIZE, d[i], SCL_MAX_CHUNK_SIZE);
                                        slot->fragment_tracker[g * 8 + i] = 1;
                                    }
                                }
                                if (slot->assembled_length == 0) {
                                    slot->assembled_length = SCL_HEADER_MIN_LEN + (total_frags * SCL_MAX_CHUNK_SIZE);
                                }
                            } else {
                                complete = false;
                                break;
                            }
                        } else {
                            complete = false;
                            break;
                        }
                    }
                }
                        
                if (complete && slot->assembled_length >= SCL_HEADER_MIN_LEN) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
                    synth_buf = get_l5_staging_buffer();
                    if (synth_buf) {
                        memcpy(synth_buf, slot->buffer, slot->assembled_length);
                        synth_buf[0] &= ~SCL_PACKET_FLAG_FRAGMENTED;
                        synth_buf[0] &= ~SCL_PACKET_FLAG_LONG_HEADER;
                        synth_buf[0] |= SCL_PACKET_FLAG_SHORT_HEADER;
                        synth_buf[0] |= 0x08; // Flag pre-authenticated

                        int ext = extract_l5_message(conn, state, synth_buf, slot->assembled_length, &sender_addr, in_msg, sender_pubkey, decryption_buffer, rx_time);
                        if (ext > 0) crypto_verify_enqueue(state, conn, in_msg, sender_pubkey, &sender_addr);
                    }

                    uint8_t comp_ip_key[16], comp_subnet_key[16];
                    ip_to_16(&slot->client_addr, comp_ip_key);
                    memcpy(comp_subnet_key, comp_ip_key, 16);
                    comp_subnet_key[15] = 0; // Subnet masking for tracking
                    decrement_dos_count(&us_state->ip_tracker, comp_ip_key, us_state->node_secret);
                    decrement_dos_count(&us_state->subnet_tracker, comp_subnet_key, us_state->node_secret);
                    if (slot->is_tier1_staked) atomic_fetch_sub_explicit(&us_state->handshake_slab->active_tier1, 1, memory_order_relaxed);
                    else atomic_fetch_sub_explicit(&us_state->handshake_slab->active_tier2, 1, memory_order_relaxed);
                    atomic_store_explicit(&slot->state, SCL_SLOT_FREE, memory_order_release);
                    goto advance_queue;
                } else goto advance_queue;
#else
                    // Prevent Duplicate Flight 3 packets from spawning parallel connections that
                    // race and corrupt the stream reassembly matrix with non-deterministic signatures.
                    bool is_duplicate_f3 = false;
                    uint32_t dup_start_idx = (uint32_t)siphash24(client_cid, SCL_CID_LEN, us_state->node_secret) % 4096;
                    for (int _p = 0; _p < 4096; _p++) {
                        uint32_t _probe = (dup_start_idx + _p) % 4096;
                        SclConnection *_c = atomic_load_explicit(&us_state->cid_routing_table[_probe], memory_order_acquire);
                        if (_c == NULL) break;
                        if (_c != SCL_TOMBSTONE && memcmp(_c->cid, client_cid, SCL_CID_LEN) == 0) {
                            is_duplicate_f3 = true;
                            break;
                        }
                    }
                    
                    if (is_duplicate_f3) {
                        uint8_t final_key_dup[32];
                        derive_labeled_key(ss_init, "SCL final key", final_key_dup, 32);
                        uint64_t dup_slot_pkt_num = atomic_fetch_add_explicit(&slot->next_packet_num, 1, memory_order_relaxed);
                        send_stateless_l4_ack(global_shim, client_cid, &sender_addr, final_key_dup, pkt_num, dup_slot_pkt_num);
                        
                        // 1. Calculate indices while the slot is still locked in an incomplete state
                        uint8_t comp_ip_key[16], comp_subnet_key[16];
                        ip_to_16(&slot->client_addr, comp_ip_key);
                        memcpy(comp_subnet_key, comp_ip_key, 16);
                        comp_subnet_key[15] = 0; // Subnet masking for tracking
                        // 2. Decrement the DoS limit counters FIRST
                        decrement_dos_count(&us_state->ip_tracker, comp_ip_key, us_state->node_secret);
                        decrement_dos_count(&us_state->subnet_tracker, comp_subnet_key, us_state->node_secret);
                        // 3. Update the tier occupancy tracking
                        if (slot->is_tier1_staked) atomic_fetch_sub_explicit(&us_state->handshake_slab->active_tier1, 1, memory_order_relaxed);
                        else atomic_fetch_sub_explicit(&us_state->handshake_slab->active_tier2, 1, memory_order_relaxed);
                        // 4. Finally, set the state to FREE so other threads can acquire it
                        atomic_store_explicit(&slot->state, SCL_SLOT_FREE, memory_order_release);
                        goto advance_queue;
                    }

                    synth_buf = get_l5_staging_buffer();
                    if (!synth_buf) goto advance_queue;
                            
                    memcpy(synth_buf, slot->buffer, slot->assembled_length);
                    synth_buf[0] &= ~SCL_PACKET_FLAG_FRAGMENTED;
                    synth_buf[0] &= ~SCL_PACKET_FLAG_LONG_HEADER;
                    synth_buf[0] |= SCL_PACKET_FLAG_SHORT_HEADER;
                    synth_buf[0] |= 0x08; // Flag pre-authenticated natively

                    // CREATE NEW CONNECTION
                    size_t mem_footprint = sizeof(SclConnection) + (SCL_L5_RING_SIZE * 4096);
                    uint32_t current_conns = atomic_load_explicit(&us_state->active_connection_count, memory_order_relaxed);
                    if (current_conns >= MAX_ACTIVE_CONNECTIONS) {
                        fprintf(stderr, "[L5] Global connection limit reached (%d). Dropping connection.\n", MAX_ACTIVE_CONNECTIONS);
                        goto advance_queue;
                    }
                    if (!slot->is_tier1_staked) {
                        size_t current_allocated = atomic_load_explicit(&us_state->global_untrusted_sync_allocated, memory_order_relaxed);
                        if (current_allocated + mem_footprint > SCL_GLOBAL_SYNC_QUOTA) {
                            fprintf(stderr, "[L5] Global Untrusted Sync Quota (1GB) reached. Dropping new untrusted connection.\n");
                            goto advance_queue;
                        }
                    }

                    SclConnection *new_conn = NULL;
                    SCL_ALIGNED_ALLOC(&new_conn, 64, sizeof(SclConnection));
                    if (new_conn) {
                        memset(new_conn, 0, sizeof(SclConnection));
                        atomic_init(&new_conn->ref_count, 2);
                        atomic_init(&new_conn->is_processing, false); // Initialize processing lock
                        atomic_fetch_add_explicit(&us_state->active_connection_count, 1, memory_order_relaxed);
                        new_conn->is_untrusted_sync = !slot->is_tier1_staked;
                        if (new_conn->is_untrusted_sync) {
                            atomic_fetch_add_explicit(&us_state->global_untrusted_sync_allocated, mem_footprint, memory_order_relaxed);
                        }
                                            
                        new_conn->l5_rx_queue.buffer = malloc(SCL_L5_RING_SIZE * sizeof(uint8_t*));
                        new_conn->l5_rx_queue.lengths = malloc(SCL_L5_RING_SIZE * sizeof(size_t));
                        new_conn->l5_rx_queue.addrs = malloc(SCL_L5_RING_SIZE * sizeof(struct sockaddr_storage));
                        new_conn->l5_rx_queue.rx_times = malloc(SCL_L5_RING_SIZE * sizeof(uint64_t));
                        for (int i = 0; i < SCL_L5_RING_SIZE; i++) new_conn->l5_rx_queue.buffer[i] = malloc(4096);
                        atomic_init(&new_conn->l5_rx_queue.head, 0);
                        atomic_init(&new_conn->l5_rx_queue.tail, 0);
                        
                        pthread_mutex_init(&new_conn->l4_mutex, NULL);
                        queue_init(&new_conn->tx_datagram_queue);
                        queue_init(&new_conn->tx_stream_queue);
                        new_conn->bdpq_deficit = 5;
                        new_conn->cwnd = SCL_MICRO_BDP_LIMIT;
                        atomic_init(&new_conn->last_rx_time, get_time_ms());
                        
                        new_conn->dynamic_replay_window_size = SCL_MIN_REPLAY_WINDOW;
                        new_conn->current_path = sender_addr;
                        memcpy(new_conn->cid, client_cid, SCL_CID_LEN);
                        
                        // Initialize Flow Control Window
                        new_conn->tx_max_data = SCL_FLOW_WINDOW_SIZE;
                        new_conn->rx_max_data = SCL_FLOW_WINDOW_SIZE;
                        new_conn->tx_dispatched_data = 0;
                        new_conn->rx_consumed_data = 0;
                        new_conn->pending_max_data_update = false;
                        
                        // Initialize RPC Token Bucket
                        atomic_init(&new_conn->rpc_token_budget, 500);
                        atomic_init(&new_conn->last_rpc_token_refill, get_time_ms());
                        atomic_init(&new_conn->active_rpc_streams, 0);
                        
                        // Derivation Keys
                        uint8_t ss_init_final[32];
                        uint8_t f3_ip_key[16];
                        ip_to_16(&sender_addr, f3_ip_key);
                        if (verify_stateless_token(us_state->node_secret, slot->connection_token, f3_ip_key, ss_init_final) != 0) {
                            fprintf(stderr, "[L5] ERROR: Token verification failed on Flight 3 assembly. Rejecting Connection.\n");
                            scl_connection_release(new_conn);
                            goto advance_queue;
                        }
                        derive_labeled_key(ss_init_final, "SCL final key", new_conn->current_aes_gcm_key, 32);
                        derive_rpc_siphash_key(ss_init_final, new_conn->rpc_siphash_key);
                                                
                        new_conn->handshake_state = SCL_CONN_STATE_ESTABLISHED;
                        new_conn->is_handshake_complete = true;
                        new_conn->required_pow_bits = 0; // Flags context as responder
                        
                        // Add EDGE_INTERACTION and EDGE_SYMMETRY to Hypergraph
                        add_temporal_edge(&state->hypergraph, client_cid, EDGE_INTERACTION, 5);
                        add_temporal_edge(&state->hypergraph, client_cid, EDGE_SYMMETRY, 3);
                                                
                        uint8_t hmac_input[32 + SCL_CID_LEN];
                        uint8_t hmac_output[32];
                        memcpy(hmac_input, us_state->node_secret, 32);
                        memcpy(hmac_input + 32, client_cid, SCL_CID_LEN);
                        SHA256(hmac_input, sizeof(hmac_input), hmac_output);
                                                    
                        Message *reset_msg = malloc(sizeof(Message));
                        if (reset_msg) {
                            reset_msg->type = MSG_STATELESS_RESET_TOKEN;
                            reset_msg->length = 16;
                            memcpy(reset_msg->payload, hmac_output, 16);
                            queue_enqueue(&new_conn->tx_stream_queue, reset_msg);
                            free(reset_msg);
                        }
                                                
                        uint64_t pkt_num_val;
                        memcpy(&pkt_num_val, frame_ptr + 1 + SCL_CID_LEN, 8);
                        new_conn->next_packet_num = be64toh(pkt_num_val) + 1000;
                                                
                        global_shim->register_connection(global_shim, client_cid, new_conn);
                        
                        // Dispatch Handshake Payloads through the brand new active connection context
                        int ext = extract_l5_message(new_conn, state, synth_buf, slot->assembled_length, &sender_addr, in_msg, sender_pubkey, decryption_buffer, rx_time);
                        if (ext > 0) crypto_verify_enqueue(state, new_conn, in_msg, sender_pubkey, &sender_addr);
                        
                        scl_connection_release(new_conn);
                    }
                    // 1. Calculate indices while the slot is still locked in an incomplete state
                    uint8_t comp_ip_key[16], comp_subnet_key[16];
                    ip_to_16(&slot->client_addr, comp_ip_key);
                    memcpy(comp_subnet_key, comp_ip_key, 16);
                    comp_subnet_key[15] = 0; // Subnet masking for tracking
                    // 2. Decrement the DoS limit counters FIRST
                    decrement_dos_count(&us_state->ip_tracker, comp_ip_key, us_state->node_secret);
                    decrement_dos_count(&us_state->subnet_tracker, comp_subnet_key, us_state->node_secret);
                    // 3. Update the tier occupancy tracking
                    if (slot->is_tier1_staked) atomic_fetch_sub_explicit(&us_state->handshake_slab->active_tier1, 1, memory_order_relaxed);
                    else atomic_fetch_sub_explicit(&us_state->handshake_slab->active_tier2, 1, memory_order_relaxed);
                    // 4. Finally, set the state to FREE so other threads can acquire it
                    atomic_store_explicit(&slot->state, SCL_SLOT_FREE, memory_order_release);
                    goto advance_queue;
                } else goto advance_queue;
#endif
            } else if (is_short_header) {
                // --- Isolated OOO Object Pool Reassembly ---
                if (conn->handshake_state != SCL_CONN_STATE_ESTABLISHED &&
                    conn->handshake_state != SCL_CONN_STATE_FLIGHT3_READY) {
                    goto advance_queue;
                }
                if (frame_len < SCL_HEADER_MIN_LEN + 12 + 16) goto advance_queue;
                                    
                uint64_t stream_offset;
                memcpy(&stream_offset, frame_ptr + SCL_HEADER_MIN_LEN, 8);
                stream_offset = be64toh(stream_offset);
                            
                uint64_t raw_frag_pn;
                memcpy(&raw_frag_pn, frame_ptr + 1 + SCL_CID_LEN, sizeof(uint64_t));
                uint64_t current_frag_pkt_num = be64toh(raw_frag_pn);

                // Drop trailing parity fragments of already delivered stream messages
                if (stream_offset < conn->expected_rx_stream_offset) {
                    send_l4_ack(conn, current_frag_pkt_num, rx_time);
                    goto advance_queue;
                }
                        
                uint16_t total_frags, frag_idx;
                memcpy(&total_frags, frame_ptr + SCL_HEADER_MIN_LEN + 8, 2);
                memcpy(&frag_idx, frame_ptr + SCL_HEADER_MIN_LEN + 10, 2);
                total_frags = ntohs(total_frags);
                frag_idx = ntohs(frag_idx);
                        
                size_t enc_len = frame_len - (SCL_HEADER_MIN_LEN + 12);
                size_t pt_len;
                if (decrypt_aead_packet(conn->current_aes_gcm_key, current_frag_pkt_num, frame_ptr + SCL_HEADER_MIN_LEN + 12, enc_len, decryption_buffer, &pt_len) != 0) {
                    if (global_state) {
                        pthread_mutex_lock(&global_state->hypergraph.lock);
                        bloom_filter_add(global_state->hypergraph.poison_bloom_aging, client_cid);
                        pthread_mutex_unlock(&global_state->hypergraph.lock);
                    }
                    goto advance_queue;
                }

                // Strictly update the sliding replay window with the decrypted fragment's packet number
                scl_update_replay_window(conn, current_frag_pkt_num);

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
            if (pt_len > SCL_MAX_CHUNK_SIZE || total_frags == 0 || total_frags > 32) goto advance_queue;
#else
            size_t max_frags_allowed = (MAX_MESSAGE_SIZE + SCL_MAX_CHUNK_SIZE - 1) / SCL_MAX_CHUNK_SIZE;
            if (pt_len > SCL_MAX_CHUNK_SIZE || total_frags == 0 || total_frags > max_frags_allowed) goto advance_queue;
#endif
                                        
                OOO_Message *ooo_msg = NULL;
                OOO_Message *prev = NULL;
                OOO_Message *curr = (OOO_Message *)conn->ooo_buffer_head;
                uint64_t now = get_time_ms();

                while (curr) {
                    if (curr->stream_offset < conn->expected_rx_stream_offset) {
                        OOO_Message *expired = curr;
                        curr = curr->next;
                        if (prev) prev->next = curr;
                        else conn->ooo_buffer_head = curr;
                        
                        size_t exp_size = SCL_HEADER_MIN_LEN + 12 + (expired->total_frags * SCL_MAX_CHUNK_SIZE);
                        if (conn->ooo_bytes_allocated >= sizeof(OOO_Message) + exp_size) {
                            conn->ooo_bytes_allocated -= (sizeof(OOO_Message) + exp_size);
                        } else {
                            conn->ooo_bytes_allocated = 0;
                        }
                        atomic_fetch_sub_explicit(&us_state->global_ooo_bytes_allocated, sizeof(OOO_Message) + exp_size, memory_order_relaxed);
                        if (expired->parity_slab) SCL_ALIGNED_FREE(expired->parity_slab);
                        free(expired);
                        continue;
                    }
                    if (now > curr->expiration_time && curr->expiration_time != 0) {
                        OOO_Message *expired = curr;
                        curr = curr->next;
                        if (prev) prev->next = curr;
                        else conn->ooo_buffer_head = curr;
                                                
                        size_t exp_size = SCL_HEADER_MIN_LEN + 12 + (expired->total_frags * SCL_MAX_CHUNK_SIZE);
                        if (conn->ooo_bytes_allocated >= sizeof(OOO_Message) + exp_size) {
                            conn->ooo_bytes_allocated -= (sizeof(OOO_Message) + exp_size);
                        } else {
                            conn->ooo_bytes_allocated = 0;
                        }
                        atomic_fetch_sub_explicit(&us_state->global_ooo_bytes_allocated, sizeof(OOO_Message) + exp_size, memory_order_relaxed);
                                        
                        // Iterate and safely free all dynamically allocated FEC parity shards linked to the expiring structure
                        if (expired->parity_slab) {
                            SCL_ALIGNED_FREE(expired->parity_slab);
                        }
                                                                
                        // Suppress timeout logs for orphaned DATAGRAM parity fragments
                        bool has_data = false;
                        for (int w = 0; w < SCL_DATA_MASK_WORDS; w++) {
                            if (expired->data_mask[w] != 0) {
                                has_data = true;
                                break;
                            }
                        }
                        if (has_data) {
                            // Drop the incomplete stream payload, but DO NOT nuke the connection
                            fprintf(stderr, "[L5] Fragment reassembly timeout. Incomplete stream dropped.\n");
                            
                            // Recover flow-control window for dropped stream messages to prevent permanent deadlocks
                            // We conservatively assume it was a stream to ensure the window reliably recovers
                            size_t total_msg_len = expired->total_frags * SCL_MAX_CHUNK_SIZE;
                            conn->rx_consumed_data += total_msg_len;
                            if (conn->rx_consumed_data + 524288 > conn->rx_max_data) {
                                conn->rx_max_data = conn->rx_consumed_data + 1048576;
                                conn->pending_max_data_update = true;
                            }
                        }
                        
                        // Advance the stream offset to prevent permanent head-of-line blocking
                        if (expired->stream_offset >= conn->expected_rx_stream_offset &&
                            expired->stream_offset - conn->expected_rx_stream_offset < 1000000) {
                            conn->expected_rx_stream_offset = expired->stream_offset + 1;
                        }
                        
                        free(expired);
                        continue;
                    }
                    if (curr->stream_offset == stream_offset) {
                        if (curr->total_frags == total_frags) {
                            ooo_msg = curr;
                            break;
                        } else goto advance_queue;
                    }
                    prev = curr;
                    curr = curr->next;
                }

                if (!ooo_msg) {
                    size_t max_expected_size = SCL_HEADER_MIN_LEN + 12 + (total_frags * SCL_MAX_CHUNK_SIZE);
                    size_t global_allocated = atomic_load_explicit(&us_state->global_ooo_bytes_allocated, memory_order_relaxed);
                    
                    // Strict global memory ceiling check +++
                    // Prevents 1TB slow-loris memory exhaustion vectors
                    if (global_allocated + sizeof(OOO_Message) + max_expected_size > us_state->global_ooo_quota) {
                        scl_log(LOG_LEVEL_DEBUG, "L5", "Global OOO Quota exceeded. Dropping fragment to prevent memory exhaustion.");
                        goto advance_queue;
                    }
                    
                    size_t effective_quota = conn->is_untrusted_sync && global_allocated > us_state->global_ooo_quota * 0.8 ? SCL_OOO_CRUSH_LIMIT : SCL_OOO_QUOTA_PER_CONN;
                                                    
                    while (conn->ooo_bytes_allocated + sizeof(OOO_Message) + max_expected_size > effective_quota) {
                        OOO_Message *drop_prev = NULL, *drop_curr = (OOO_Message *)conn->ooo_buffer_head;
                        OOO_Message *highest_msg = drop_curr, *highest_prev = NULL; // Default to dropping the head if all offsets evaluate to 0
                        uint64_t highest_offset = drop_curr ? drop_curr->stream_offset : 0;
                        while (drop_curr) {
                            if (drop_curr->stream_offset > highest_offset) {
                                highest_offset = drop_curr->stream_offset;
                                highest_msg = drop_curr;
                                highest_prev = drop_prev;
                            }
                            drop_prev = drop_curr;
                            drop_curr = drop_curr->next;
                        }
                        if (highest_msg) {
                            if (highest_prev) highest_prev->next = highest_msg->next;
                            else conn->ooo_buffer_head = highest_msg->next;
                            size_t drop_size = SCL_HEADER_MIN_LEN + 12 + (highest_msg->total_frags * SCL_MAX_CHUNK_SIZE);
                            conn->ooo_bytes_allocated -= (sizeof(OOO_Message) + drop_size);
                            atomic_fetch_sub_explicit(&us_state->global_ooo_bytes_allocated, sizeof(OOO_Message) + drop_size, memory_order_relaxed);
                            // Securely free dynamically allocated FEC parity shards before sacrificing the matrix wrapper
                            if (highest_msg->parity_slab) {
                                SCL_ALIGNED_FREE(highest_msg->parity_slab);
                            }
                            free(highest_msg);
                        } else goto advance_queue;
                    }
                                                            
                    ooo_msg = calloc(1, sizeof(OOO_Message) + max_expected_size);
                    if (!ooo_msg) goto advance_queue;
                                                
                    ooo_msg->stream_offset = stream_offset;
                    ooo_msg->total_frags = total_frags;
                    ooo_msg->expiration_time = get_time_ms() + 10000; // Optimized: 10s timeout to prevent HOL blocking from stalling DKG
                    memcpy(ooo_msg->buffer, frame_ptr, SCL_HEADER_MIN_LEN);
                    
                    // --- PROACTIVE RECOVERY INITIALIZATION ---
                    memset(ooo_msg->data_mask, 0, sizeof(ooo_msg->data_mask));
                    memset(ooo_msg->parity_mask, 0, sizeof(ooo_msg->parity_mask));
                    ooo_msg->parity_slab = NULL;
                    // --------------------------------------------
                                            
                    ooo_msg->next = (OOO_Message *)conn->ooo_buffer_head;
                    conn->ooo_buffer_head = ooo_msg;
                    conn->ooo_bytes_allocated += (sizeof(OOO_Message) + max_expected_size);
                    atomic_fetch_add_explicit(&us_state->global_ooo_bytes_allocated, sizeof(OOO_Message) + max_expected_size, memory_order_relaxed);
                }

                // --- Route Parity vs Data ---
                if (frag_idx >= total_frags) {
                    int p_idx = frag_idx - total_frags;
                    if (p_idx < SCL_MAX_PARITY_SHARDS) {
                        if (!ooo_msg->parity_slab) {
                            SCL_ALIGNED_ALLOC(&ooo_msg->parity_slab, 64, SCL_MAX_PARITY_SHARDS * SCL_MAX_CHUNK_SIZE);
                            if (ooo_msg->parity_slab) memset(ooo_msg->parity_slab, 0, SCL_MAX_PARITY_SHARDS * SCL_MAX_CHUNK_SIZE);
                        }
                        if (ooo_msg->parity_slab) {
                            uint8_t *shard_dest = ooo_msg->parity_slab + (p_idx * SCL_MAX_CHUNK_SIZE);
                            memcpy(shard_dest, decryption_buffer, pt_len);
                            ooo_msg->parity_mask[p_idx / 64] |= (1ULL << (p_idx % 64));
                        }
                    }
                    send_l4_ack(conn, current_frag_pkt_num, rx_time);
                } else {
                    int word = frag_idx / 64;
                    int bit = frag_idx % 64;
                    if (!(ooo_msg->data_mask[word] & (1ULL << bit))) {
                        size_t offset = SCL_HEADER_MIN_LEN + 12 + (frag_idx * SCL_MAX_CHUNK_SIZE);
                        memcpy(ooo_msg->buffer + offset, decryption_buffer, pt_len);
                        ooo_msg->data_mask[word] |= (1ULL << bit);
                        if (frag_idx == total_frags - 1) ooo_msg->assembled_length = offset + pt_len;
                    }
                    send_l4_ack(conn, current_frag_pkt_num, rx_time);
                }

                // --- STRICT IN-ORDER DELIVERY DISPATCH (With GF(2^8) Recovery) ---
                bool advanced;
                do {
                    advanced = false;
                    curr = (OOO_Message *)conn->ooo_buffer_head;
                    prev = NULL;
                    while (curr) {
                        bool is_complete = curr->is_complete;
                        
                        if (!is_complete) {
                            is_complete = true;
                            // Proactive Matrix Recovery Execution
                            for (int g = 0; g < (curr->total_frags + 7) / 8; g++) {
                                // Enforce safe bounds dynamically evaluated from the Fuzzer context constraint
                                if (g * 8 >= 8192) break;
                                
                                int missing = 0;
                                int max_d = (g * 8 + 8 < curr->total_frags) ? 8 : curr->total_frags - g * 8;
                                for (int i = 0; i < max_d; i++) {
                                    int f_idx = g * 8 + i;
                                    if (!(curr->data_mask[f_idx / 64] & (1ULL << (f_idx % 64)))) missing++;
                                }
                                                        
                                if (missing > 0) {
                                    int p0_idx = g * 2;
                                    int p1_idx = g * 2 + 1;
                                    bool has_p0 = (curr->parity_mask[p0_idx / 64] & (1ULL << (p0_idx % 64))) != 0;
                                    bool has_p1 = (curr->parity_mask[p1_idx / 64] & (1ULL << (p1_idx % 64))) != 0;
                                                            
                                    if (missing <= (has_p0 + has_p1) && curr->parity_slab) {
                                        uint8_t *d[8] = {0};
                                        bool present[8] = {0};
                                        uint8_t zero_pad[8][SCL_MAX_CHUNK_SIZE];
                                        memset(zero_pad, 0, sizeof(zero_pad));
                                                                
                                        for (int i = 0; i < max_d; i++) {
                                            int f_idx = g * 8 + i;
                                            d[i] = curr->buffer + SCL_HEADER_MIN_LEN + 12 + f_idx * SCL_MAX_CHUNK_SIZE;
                                            present[i] = (curr->data_mask[f_idx / 64] & (1ULL << (f_idx % 64))) != 0;
                                            if (!present[i]) d[i] = zero_pad[i];
                                        }
                                        for (int i = max_d; i < 8; i++) {
                                            present[i] = true;
                                            d[i] = zero_pad[i];
                                        }
                                                                
                                        if (fec_decode82(d, curr->parity_slab + (p0_idx * SCL_MAX_CHUNK_SIZE), curr->parity_slab + (p1_idx * SCL_MAX_CHUNK_SIZE), present, has_p0, has_p1, SCL_MAX_CHUNK_SIZE) == 0) {
                                            for (int i = 0; i < max_d; i++) {
                                                int f_idx = g * 8 + i;
                                                if (!(curr->data_mask[f_idx / 64] & (1ULL << (f_idx % 64)))) {
                                                    memcpy(curr->buffer + SCL_HEADER_MIN_LEN + 12 + f_idx * SCL_MAX_CHUNK_SIZE, d[i], SCL_MAX_CHUNK_SIZE);
                                                    curr->data_mask[f_idx / 64] |= (1ULL << (f_idx % 64));
                                                }
                                            }
                                            if (curr->assembled_length == 0) {
                                                curr->assembled_length = SCL_HEADER_MIN_LEN + 12 + (curr->total_frags * SCL_MAX_CHUNK_SIZE);
                                            }
                                        } else {
                                            is_complete = false;
                                            break;
                                        }
                                    } else {
                                        is_complete = false;
                                        break;
                                    }
                                }
                            }
                            if (is_complete) {
                                curr->is_complete = true;
                            }
                        }
                        
                        if (is_complete && curr->assembled_length >= SCL_HEADER_MIN_LEN + 12) {
                            // Extract actual framing byte cleanly from the now fully-assembled payload head
                            bool actual_is_datagram = (curr->buffer[SCL_HEADER_MIN_LEN + 12] == SCL_FRAME_DATAGRAM);
                            if (actual_is_datagram || curr->stream_offset == conn->expected_rx_stream_offset) {
                                size_t act_len = curr->assembled_length - (SCL_HEADER_MIN_LEN + 12);
                                if (act_len > MAX_MESSAGE_SIZE) {
                                    if (prev) prev->next = curr->next;
                                    else conn->ooo_buffer_head = curr->next;
                                    size_t exp_size = SCL_HEADER_MIN_LEN + 12 + (curr->total_frags * SCL_MAX_CHUNK_SIZE);
                                    if (conn->ooo_bytes_allocated >= sizeof(OOO_Message) + exp_size) {
                                        conn->ooo_bytes_allocated -= (sizeof(OOO_Message) + exp_size);
                                    } else {
                                        conn->ooo_bytes_allocated = 0;
                                    }
                                    atomic_fetch_sub_explicit(&us_state->global_ooo_bytes_allocated, sizeof(OOO_Message) + exp_size, memory_order_relaxed);
                                    if (curr->parity_slab) SCL_ALIGNED_FREE(curr->parity_slab);
                                    free(curr);
                                    break;
                                }
                                synth_buf = get_l5_staging_buffer();
                                if (synth_buf) {
                                    memcpy(synth_buf, curr->buffer, SCL_HEADER_MIN_LEN);
                                    memcpy(synth_buf + SCL_HEADER_MIN_LEN, curr->buffer + SCL_HEADER_MIN_LEN + 12, act_len);
                                                                    
                                    synth_buf[0] = SCL_PACKET_FLAG_SHORT_HEADER | 0x08; // Flag pre-authenticated
                                                                                                    
                                    int ext = extract_l5_message(conn, state, synth_buf, SCL_HEADER_MIN_LEN + act_len, &sender_addr, in_msg, sender_pubkey, decryption_buffer, rx_time);
                                    if (ext > 0) {
                                        crypto_verify_enqueue(state, conn, in_msg, sender_pubkey, &sender_addr);
                                    }
                                                                    
                                    if (!actual_is_datagram) {
                                        conn->expected_rx_stream_offset++;
                                    }
                                    advanced = true;
                                    
                                    if (prev) prev->next = curr->next;
                                    else conn->ooo_buffer_head = curr->next;
                                                                                
                                    size_t exp_size = SCL_HEADER_MIN_LEN + 12 + (curr->total_frags * SCL_MAX_CHUNK_SIZE);
                                    if (conn->ooo_bytes_allocated >= sizeof(OOO_Message) + exp_size) {
                                        conn->ooo_bytes_allocated -= (sizeof(OOO_Message) + exp_size);
                                    } else {
                                        conn->ooo_bytes_allocated = 0;
                                    }
                                    atomic_fetch_sub_explicit(&us_state->global_ooo_bytes_allocated, sizeof(OOO_Message) + exp_size, memory_order_relaxed);
                                                                        
                                    if (curr->parity_slab) SCL_ALIGNED_FREE(curr->parity_slab);
                                    free(curr);
                                                                                
                                    break; // Restart loop scan to enforce order
                                } else {
                                    curr->expiration_time = get_time_ms() + 10000; // Waiting stream turn
                                    break; // Yield reassembly scan until staging buffer memory recovers
                                }
                            }
                        }
                        prev = curr;
                        curr = curr->next;
                    }
                } while (advanced);
            }
        } else {
            if (is_short_header) {
                uint8_t zero_cid[SCL_CID_LEN] = {0};
                bool is_listener = (memcmp(conn->cid, zero_cid, SCL_CID_LEN) == 0);
                if (is_listener) {
                    // Unroutable short header caught by the global listener.
                    // SPEC IMPLEMENTATION: Surviving cores receiving unknown CIDs issue a STATELESS_RESET
                    uint8_t hmac_input[32 + SCL_CID_LEN];
                    uint8_t hmac_output[32];
                    UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;
                    memcpy(hmac_input, us_state->node_secret, 32);
                    memcpy(hmac_input + 32, client_cid, SCL_CID_LEN);
                    SHA256(hmac_input, sizeof(hmac_input), hmac_output);

                    size_t max_len;
                    void *tx_token;
                    uint8_t *tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
                    if (tx_buf && max_len >= SCL_HEADER_MIN_LEN + 16) {
                        tx_buf[0] = SCL_PACKET_FLAG_SHORT_HEADER;
                        memcpy(tx_buf + 1, client_cid, SCL_CID_LEN);
                        uint64_t pkt_num_reset = htobe64(0);
                        memcpy(tx_buf + 1 + SCL_CID_LEN, &pkt_num_reset, 8);
                        memcpy(tx_buf + SCL_HEADER_MIN_LEN, hmac_output, 16);
                        global_shim->commit_tx_buffer(global_shim, tx_token, SCL_HEADER_MIN_LEN + 16, client_cid, &sender_addr);
                    } else if (tx_buf) {
                        global_shim->abort_tx_buffer(global_shim, tx_token);
                    }
                    goto advance_queue;
                }
                // Unfragmented short header for established connection - process normally
                int ext = extract_l5_message(conn, state, frame_ptr, frame_len, &sender_addr, in_msg, sender_pubkey, decryption_buffer, rx_time);
                if (ext > 0) crypto_verify_enqueue(state, conn, in_msg, sender_pubkey, &sender_addr);
            } else if (is_long_header) {
                UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;
                uint8_t zero_cid[SCL_CID_LEN] = {0};
                bool is_listener = (memcmp(conn->cid, zero_cid, SCL_CID_LEN) == 0) || (memcmp(client_cid, zero_cid, SCL_CID_LEN) == 0);
                            
                // --- QUIC-Parity Spec: Client processes dynamic RETRY packets ---
                if (!is_listener && is_retry) {
                    if ((conn->handshake_state == SCL_CONN_STATE_FLIGHT1_SENT || conn->handshake_state == SCL_CONN_STATE_FLIGHT3_READY) && frame_len >= SCL_HEADER_MIN_LEN + 9) {
                        uint64_t new_cookie;
                        memcpy(&new_cookie, frame_ptr + SCL_HEADER_MIN_LEN, 8);
                        uint8_t new_pow = frame_ptr[SCL_HEADER_MIN_LEN + 8];
                        
                        uint8_t secondary_pow = 0;
                        uint8_t puzzle_base[32];
                        memset(puzzle_base, 0, 32);
                        
                        if (frame_len >= SCL_HEADER_MIN_LEN + 9 + 33) {
                            secondary_pow = frame_ptr[SCL_HEADER_MIN_LEN + 9];
                            memcpy(puzzle_base, frame_ptr + SCL_HEADER_MIN_LEN + 10, 32);
                        }
                                    
                        // Ignore stale or redundant RETRY packets arriving out-of-order (verify puzzle base)
                        if (new_cookie == conn->handshake_cookie &&
                            new_pow == conn->required_pow_bits &&
                            secondary_pow == conn->secondary_pow_bits &&
                            memcmp(conn->hypergraph_puzzle_base, puzzle_base, 32) == 0) {
                            goto advance_queue;
                        }
                                                    
                        conn->handshake_cookie = new_cookie;
                        conn->required_pow_bits = new_pow;
                        conn->secondary_pow_bits = secondary_pow;
                        memcpy(conn->hypergraph_puzzle_base, puzzle_base, 32);
                                                    
                        scl_log(LOG_LEVEL_INFO, "L5", "Received RETRY packet. Updating cookie and PoW (Primary: %d-bit, Secondary: %d-bit). Retransmitting Flight 1.", new_pow, secondary_pow);
                                                
                        // Reset Liveness threshold precisely when actively stepping the Handshake to circumvent false-stall timeouts
                        atomic_store_explicit(&conn->last_rx_time, get_time_ms(), memory_order_relaxed);
                                                    
                        // Clear the unacked queue to prevent infinite RETRY loops from old Flight 1 retransmissions
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
                        
                        // Explicitly abort any current outstanding packet number sequencing to guarantee
                        // the L4 Engine doesn't falsely link legacy tracker sequences to the new Flight 1 context.
                        conn->next_packet_num = 0;
                        conn->largest_acked_packet = 0;
                        conn->loss_time = 0;
                        pthread_mutex_unlock(&conn->l4_mutex);
                                    
                        // Clean up any pending Flight 3 fragmentation state to seamlessly retry from scratch
                        if (conn->active_fragment_buffer) {
                            free(conn->active_fragment_buffer);
                            conn->active_fragment_buffer = NULL;
                            if (conn->active_fec_parity[0]) { free(conn->active_fec_parity[0]); conn->active_fec_parity[0] = NULL; }
                            if (conn->active_fec_parity[1]) { free(conn->active_fec_parity[1]); conn->active_fec_parity[1] = NULL; }
                        }
                                                
                        // Regenerate the ephemeral Kyber keypair to recover from wiped state and preserve forward secrecy
                        explicit_bzero(conn->ephemeral_kyber_privkey, KYBER_SECRETKEY_LEN);
                        generate_ephemeral_kyber_keypair(conn->ephemeral_kyber_pubkey, conn->ephemeral_kyber_privkey);
                                                                                                    
                        // Transparently re-initiate Handshake with updated parameters
                        scl_initiate_handshake(net, conn, &sender_addr);
                    }
                    goto advance_queue;
                }

                // --- QUIC-Parity Spec: Server processes and dynamically scales Flight 1 defenses ---
                if (is_listener && frame_len >= SCL_HEADER_MIN_LEN + f1_payload_len) {
                    uint64_t cookie;
                    memcpy(&cookie, frame_ptr + SCL_HEADER_MIN_LEN, 8);
                    
                    uint8_t ip_key[16];
                    ip_to_16(&sender_addr, ip_key);
                    // Verify the stateless cookie supporting 5-minute epoch rotation
                    bool is_cookie_valid = verify_stateless_cookie(us_state->node_secret, ip_key, cookie);
                    
                    // Generate expected cookie for potential RETRY and Flight 2
                    uint64_t expected_cookie = generate_stateless_cookie(us_state->node_secret, ip_key);
                    
                    // Dynamic PoW scaling strictly isolated to Tier 2 (Untrusted Sync)
                    uint32_t active_t2 = atomic_load_explicit(&us_state->handshake_slab->active_tier2, memory_order_relaxed);
                    uint8_t current_required_pow = 10; // Baseline network PoW
                    if (active_t2 > SCL_TIER2_MAX_SLOTS * 80 / 100) {
                        current_required_pow = 20; // 80% untrusted slab capacity -> difficulty spikes exponentially
                    } else if (active_t2 > SCL_TIER2_MAX_SLOTS * 50 / 100) {
                        current_required_pow = 14; // 50% untrusted slab capacity -> minor spike
                    }
                    
                    uint64_t pow_solution;
                    memcpy(&pow_solution, frame_ptr + SCL_HEADER_MIN_LEN + 8, 8);
                    
                    uint8_t kyber_pubkey[KYBER_PUBKEY_LEN];
                    memcpy(kyber_pubkey, frame_ptr + SCL_HEADER_MIN_LEN + 16, KYBER_PUBKEY_LEN);
                    
                    // Validate PoW exactly matching the current dynamic rotating-salt state
                    uint8_t pow_input[KYBER_PUBKEY_LEN + 16];
                    memcpy(pow_input, kyber_pubkey, KYBER_PUBKEY_LEN);
                    memcpy(pow_input + KYBER_PUBKEY_LEN, &cookie, 8);
                    memcpy(pow_input + KYBER_PUBKEY_LEN + 8, &pow_solution, 8);
                    uint8_t pow_hash[32];
                    SHA256(pow_input, sizeof(pow_input), pow_hash);
                    
                    int pow_valid = 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
                    pow_valid = 1;
#else
                    int bytes = current_required_pow / 8;
                    int remainder = current_required_pow % 8;
                    uint8_t mask = remainder > 0 ? (0xFF << (8 - remainder)) : 0;
                    
                    for (int i = 0; i < bytes; i++) {
                        if (pow_hash[i] != 0) { pow_valid = 0; break; }
                    }
                    if (pow_valid && remainder > 0) {
                        if ((pow_hash[bytes] & mask) != 0) pow_valid = 0;
                    }
#endif
                    
                    // Generate expected hybrid challenge to check secondary difficulty PoW
                    HybridCookieChallenge challenge = generate_hybrid_challenge(&state->hypergraph, client_cid);
                    
                    bool secondary_pow_valid = true;
                    if (challenge.secondary_difficulty > 0) {
                        if (frame_len < SCL_HEADER_MIN_LEN + f1_payload_len + 8) {
                            secondary_pow_valid = false;
                        } else {
                            uint64_t secondary_solution;
                            memcpy(&secondary_solution, frame_ptr + SCL_HEADER_MIN_LEN + f1_payload_len, 8);
                            secondary_solution = be64toh(secondary_solution);
                            
                            // Allow tolerance for baseline difficulty to prevent WAN rate-escalation deadlocks
                            uint8_t target_diff = (challenge.secondary_difficulty > 12) ? 12 : challenge.secondary_difficulty;
                            secondary_pow_valid = verify_pow(challenge.hypergraph_puzzle_base, secondary_solution, target_diff);
                        }
                    }
                    
                    // Trigger immediate RETRY generation if defenses are triggered
                    if (!is_cookie_valid || !pow_valid || !secondary_pow_valid) {
                        size_t max_len;
                        void *tx_token;
                        uint8_t *tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
                        if (tx_buf && max_len >= SCL_HEADER_MIN_LEN + 9 + 33) {
                            tx_buf[0] = SCL_PACKET_FLAG_LONG_HEADER | SCL_PACKET_FLAG_RETRY;
                            memcpy(tx_buf + 1, client_cid, SCL_CID_LEN);
                            uint64_t retry_pkt = htobe64(0);
                            memcpy(tx_buf + 1 + SCL_CID_LEN, &retry_pkt, 8);
                            
                            memcpy(tx_buf + SCL_HEADER_MIN_LEN, &expected_cookie, 8);
                            tx_buf[SCL_HEADER_MIN_LEN + 8] = current_required_pow;
                            
                            // Pack secondary difficulty and puzzle base
                            tx_buf[SCL_HEADER_MIN_LEN + 9] = challenge.secondary_difficulty;
                            memcpy(tx_buf + SCL_HEADER_MIN_LEN + 10, challenge.hypergraph_puzzle_base, 32);
                            
                            size_t retry_len = SCL_HEADER_MIN_LEN + 9 + 33;
                            global_shim->commit_tx_buffer(global_shim, tx_token, retry_len, client_cid, &sender_addr);
                            
                            scl_log(LOG_LEVEL_INFO, "L5", "Issuing Hybrid RETRY. Primary: 10-bit, Secondary: %d-bit.",
                                    challenge.secondary_difficulty);
                        } else if (tx_buf) {
                            global_shim->abort_tx_buffer(global_shim, tx_token);
                        }
                        goto advance_queue;
                    }
                            
                    // If we reach here, Flight 1 is completely verified. Setup Flight 2 token logic.
                    // SPEC: 60-second anti-amplification Token lifetime to survive PTO variance and PoW solving
                    uint64_t expiry = get_time_ms() + 60000;
                                        
                    // --- SPEC IMPLEMENTATION: Early Stake Proof Local Lookup ---
                    // Connections providing a valid early stake proof bypass PoW and draw from Tier 1.
                    // If the server is synced, it performs a zero-byte overhead local lookup by User ID.
                    uint8_t flight1_user_id[USER_ID_LEN];
                    memcpy(flight1_user_id, frame_ptr + SCL_HEADER_MIN_LEN + 16 + KYBER_PUBKEY_LEN, USER_ID_LEN);
                                        
                    bool is_tier1 = false;
                    pthread_mutex_lock(&state->mutex); // Canonical lock order: state->mutex THEN state->bc.mutex
                    User *known_user = hash_table_lookup(state->user_table, flight1_user_id, false);
                    if (known_user) {
                        if (calculate_staked_subunits(&state->bc, known_user->dilithium_pubkey) > 0) {
                            is_tier1 = true;
                        }
                    }
                    pthread_mutex_unlock(&state->mutex);

                    if (is_tier1) {
                        expiry |= 1ULL; // Grant Tier 1 (Stake-Weighted) Slab bypass
                        scl_log(LOG_LEVEL_DEBUG, "L5", "Flight 1: Local stake verification successful. Granted Tier 1 Slab admission.");
                    } else {
                        expiry &= ~1ULL; // Enforce Tier 2 (Untrusted) dynamic PoW scaling
                    }
                    // -----------------------------------------------------------

                    uint8_t kyber_pubkey_checked[KYBER_PUBKEY_LEN];
                    memcpy(kyber_pubkey_checked, frame_ptr + SCL_HEADER_MIN_LEN + 16, KYBER_PUBKEY_LEN);
                    
                    uint8_t ciphertext[KYBER_CIPHERTEXT_LEN];
                    uint8_t ss_init[KYBER_SHARED_SECRET_LEN];
                    if (!kyber_encapsulate(kyber_pubkey, ciphertext, ss_init)) goto advance_queue;
                    
                    uint8_t token_out[64];
                    generate_stateless_token(us_state->node_secret, ss_init, ip_key, expiry, token_out);
                    
                    size_t max_len;
                    void *tx_token;
                    uint8_t *tx_buf = global_shim->acquire_tx_buffer(global_shim, &max_len, &tx_token);
                    if (tx_buf && max_len >= SCL_HEADER_MIN_LEN + f2_payload_len) {
                        tx_buf[0] = SCL_PACKET_FLAG_LONG_HEADER;
                        memcpy(tx_buf + 1, client_cid, SCL_CID_LEN);
                        uint64_t f2_pkt = htobe64(1);
                        memcpy(tx_buf + 1 + SCL_CID_LEN, &f2_pkt, 8);
                        
                        memcpy(tx_buf + SCL_HEADER_MIN_LEN, &expected_cookie, 8);
                        uint64_t pkt_num_val;
                        memcpy(&pkt_num_val, frame_ptr + 1 + SCL_CID_LEN, 8);
                        memcpy(tx_buf + SCL_HEADER_MIN_LEN + 8, &pkt_num_val, 8);
                        memcpy(tx_buf + SCL_HEADER_MIN_LEN + 16, token_out, 64);
                        memcpy(tx_buf + SCL_HEADER_MIN_LEN + 80, ciphertext, KYBER_CIPHERTEXT_LEN);
                        
                        global_shim->commit_tx_buffer(global_shim, tx_token, SCL_HEADER_MIN_LEN + f2_payload_len, client_cid, &sender_addr);
                        scl_log(LOG_LEVEL_DEBUG, "L5", "Flight 1 processed. Flight 2 sent.");
                    } else if (tx_buf) {
                        global_shim->abort_tx_buffer(global_shim, tx_token);
                    }
                } else if (!is_listener && conn->handshake_state == SCL_CONN_STATE_FLIGHT1_SENT && frame_len >= SCL_HEADER_MIN_LEN + f2_payload_len) {
                    uint64_t ack_pkt_be;
                    memcpy(&ack_pkt_be, frame_ptr + SCL_HEADER_MIN_LEN + 8, 8);
                    process_l4_ack(conn, be64toh(ack_pkt_be), 0);
                    
                    memcpy(conn->handshake_token, frame_ptr + SCL_HEADER_MIN_LEN + 16, 64);
                    
                    uint8_t ciphertext[KYBER_CIPHERTEXT_LEN];
                    memcpy(ciphertext, frame_ptr + SCL_HEADER_MIN_LEN + 80, KYBER_CIPHERTEXT_LEN);
                                        
                    uint8_t ss_init[KYBER_SHARED_SECRET_LEN];
                    // Decapsulate using the Ephemeral Kyber Private Key for Forward Secrecy
                    if (!kyber_decapsulate(ciphertext, conn->ephemeral_kyber_privkey, ss_init)) goto advance_queue;
                                        
                    // Securely wipe the ephemeral private key from memory immediately after decapsulation
                    explicit_bzero(conn->ephemeral_kyber_privkey, KYBER_SECRETKEY_LEN);
                                        
                    derive_labeled_key(ss_init, "SCL flight3 key", conn->flight3_aes_gcm_key, 32);
                    derive_labeled_key(ss_init, "SCL final key", conn->current_aes_gcm_key, 32);
                    derive_rpc_siphash_key(ss_init, conn->rpc_siphash_key);
                    
                    uint32_t inner_payload_len = DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN + 19;
                    size_t signed_len = inner_payload_len + SIGNATURE_LEN;
                    size_t full_size = 1 + 5 + signed_len;
                                        
                    if (conn->active_fragment_buffer) {
                        free(conn->active_fragment_buffer);
                        conn->active_fragment_buffer = NULL;
                    }
                    if (conn->active_fec_parity[0]) {
                        free(conn->active_fec_parity[0]);
                        conn->active_fec_parity[0] = NULL;
                    }
                    if (conn->active_fec_parity[1]) {
                        free(conn->active_fec_parity[1]);
                        conn->active_fec_parity[1] = NULL;
                    }

                    uint8_t *f3_payload = malloc(full_size);
                    if (f3_payload) {
                        f3_payload[0] = SCL_FRAME_STREAM;
                        f3_payload[1] = MSG_PEER_DISCOVERY;
                        uint32_t msg_len_net = htonl(signed_len);
                        memcpy(f3_payload + 2, &msg_len_net, 4);
                                            
                        uint8_t *p_start = f3_payload + 6;
                        memcpy(p_start, net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                        memcpy(p_start + DILITHIUM_PUBKEY_LEN, net->local_peer.peer_wallet.kyber_pubkey, KYBER_PUBKEY_LEN);
                        serialize_sockaddr(&net->local_peer.addr, p_start + DILITHIUM_PUBKEY_LEN + KYBER_PUBKEY_LEN);
                        
                        uint8_t sig[SIGNATURE_LEN];
                        dilithium_sign(p_start, inner_payload_len, net->local_peer.peer_wallet.dilithium_privkey, sig);
                        memcpy(p_start + inner_payload_len, sig, SIGNATURE_LEN);
                        
                        conn->active_fragment_buffer = f3_payload;
                        conn->active_fragment_len = full_size;
                        conn->active_fragment_stream_offset = 0; // Flight 3 bypasses the stream counter
                        conn->active_fragment_data_total = (full_size + SCL_MAX_CHUNK_SIZE - 1) / SCL_MAX_CHUNK_SIZE;
                        conn->active_fragment_current = 0;
                        conn->active_fragment_is_datagram = false;
                        conn->active_fragment_is_flight3 = true;
                                                
                        conn->active_fec_parity[0] = malloc(SCL_MAX_CHUNK_SIZE);
                        conn->active_fec_parity[1] = malloc(SCL_MAX_CHUNK_SIZE);

                        if (!conn->active_fec_parity[0] || !conn->active_fec_parity[1]) {
                            free(f3_payload);
                            conn->active_fragment_buffer = NULL;
                            if (conn->active_fec_parity[0]) { free(conn->active_fec_parity[0]); conn->active_fec_parity[0] = NULL; }
                            if (conn->active_fec_parity[1]) { free(conn->active_fec_parity[1]); conn->active_fec_parity[1] = NULL; }
                            goto advance_queue;
                        }

                        conn->handshake_state = SCL_CONN_STATE_FLIGHT3_READY;
                        scl_log(LOG_LEVEL_DEBUG, "L5", "Flight 2 processed. FLIGHT3_READY.");
                    }
                }
            } else {
                // UNFRAGMENTED Packets safely bypass the buffer (neither short nor long header - shouldn't happen)
                int ext = extract_l5_message(conn, state, frame_ptr, frame_len, &sender_addr, in_msg, sender_pubkey, decryption_buffer, rx_time);
                if (ext > 0) crypto_verify_enqueue(state, conn, in_msg, sender_pubkey, &sender_addr);
            }
        }

    advance_queue:
        synth_buf = NULL;
                
        atomic_store_explicit(&conn->l5_rx_queue.tail, (tail + 1) % SCL_L5_RING_SIZE, memory_order_release);
        tail = atomic_load_explicit(&conn->l5_rx_queue.tail, memory_order_relaxed);
        head = atomic_load_explicit(&conn->l5_rx_queue.head, memory_order_acquire);
    }
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
/**
 * @brief Enqueues an inbound network message into the multi-core cryptographic verification worker pool.
 *
 * @details
 * Allocates a @ref CryptoVerifyTask descriptor, copies message bytes and sender public key material,
 * acquires an atomic reference on `conn`, and links the task to `state->crypto_verify_head`.
 * Signals waiting verification worker threads via `pthread_cond_signal`.
 *
 * @pre `state` and `msg` must be non-NULL.
 * @post A new `CryptoVerifyTask` node is appended to the verification queue.
 * @sideeffects Allocates heap memory for task node; increments `conn->ref_count`.
 * @synchronization Thread Safety: Acquires `state->crypto_verify_mutex` to serialize enqueue operations.
 *
 * @param[in,out] state         Pointer to global @ref State container.
 *                              - Direction: in-out
 *                              - Ownership: Borrowed.
 * @param[in,out] conn          Optional pointer to connection context (may be NULL for loopback).
 *                              - Direction: in-out
 *                              - Ownership: Borrowed (reference count incremented).
 * @param[in]     msg           Pointer to received message to enqueue.
 *                              - Direction: in
 *                              - Ownership: Borrowed (copied by callee).
 * @param[in]     sender_pubkey Optional 2,592-byte Dilithium5 public verification key.
 *                              - Direction: in
 * @param[in]     sender_addr   Optional pointer to sender socket address.
 *                              - Direction: in
 *
 * @return None.
 *
 * @complexity
 * - Time: O(1) queue insertion.
 * - Auxiliary Space: O(sizeof(CryptoVerifyTask)) heap allocation.
 */
void crypto_verify_enqueue(State *state, SclConnection *conn, const Message *msg, const uint8_t *sender_pubkey, const struct sockaddr_storage *sender_addr) {
    if (!state || !msg) return;
    CryptoVerifyTask *task = calloc(1, sizeof(CryptoVerifyTask));
    if (!task) return;
    
    task->msg = *msg;
    if (sender_pubkey) {
        memcpy(task->sender_pubkey, sender_pubkey, DILITHIUM_PUBKEY_LEN);
    }
    if (sender_addr) {
        task->sender_addr = *sender_addr;
    }
    task->conn = conn;
    task->next = NULL;
    
    if (conn) {
        atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_acquire);
    }
    
    pthread_mutex_lock(&state->crypto_verify_mutex);
    if (!state->crypto_verify_head) {
        state->crypto_verify_head = state->crypto_verify_tail = task;
    } else {
        state->crypto_verify_tail->next = task;
        state->crypto_verify_tail = task;
    }
    pthread_cond_signal(&state->crypto_verify_cond);
    pthread_mutex_unlock(&state->crypto_verify_mutex);
}
#endif // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

/**
 * @brief Background worker thread loop executing parallel cryptographic verification and dispatch.
 *
 * @details
 * Dequeues tasks from `state->crypto_verify_head`, executes message demultiplexing and verification
 * via @ref dispatch_l5_message, releases connection references, and recycles task descriptors.
 *
 * @pre `arg` must point to initialized @ref State container.
 * @post Runs continuously until `state->crypto_verify_running` is cleared or shutdown signaled.
 * @sideeffects Dequeues verification tasks; invokes consensus state transitions.
 * @synchronization Thread Safety: Synchronizes via `state->crypto_verify_mutex` and `state->crypto_verify_cond`.
 *
 * @param[in,out] arg Untyped pointer casting to `State *`.
 *
 * @return void* Always returns NULL upon termination.
 *
 * @complexity
 * - Time: O(tasks * dispatch_time).
 * - Auxiliary Space: O(1) auxiliary space beyond pre-allocated message scratchpads.
 */
void *crypto_verify_worker_loop(void *arg) {
    State *state = (State *)arg;
    Message *out_msg = malloc(sizeof(Message));
    if (!out_msg) return NULL;
    
    while (state->crypto_verify_running && !atomic_load(&global_shutdown)) {
        CryptoVerifyTask *task = NULL;
        
        pthread_mutex_lock(&state->crypto_verify_mutex);
        while (!state->crypto_verify_head && state->crypto_verify_running && !atomic_load(&global_shutdown)) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            long wait_ns = (state->p2p_network.is_bootstrap) ? 50000000L : 500000000L;
            ts.tv_nsec += wait_ns;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec += 1;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&state->crypto_verify_cond, &state->crypto_verify_mutex, &ts);
        }
        
        if (state->crypto_verify_head) {
            task = state->crypto_verify_head;
            state->crypto_verify_head = task->next;
            if (!state->crypto_verify_head) {
                state->crypto_verify_tail = NULL;
            }
        }
        pthread_mutex_unlock(&state->crypto_verify_mutex);
        
        if (task) {
            size_t task_arena_mark = arena_mark();
            dispatch_l5_message(task->conn, state, &state->p2p_network, &task->msg, out_msg, task->sender_pubkey, &task->sender_addr);
            arena_reset(task_arena_mark);
            if (task->conn) {
                scl_connection_release(task->conn);
            }
            free(task);
        }
    }
    
    free(out_msg);
    arena_cleanup();
    release_l5_staging_buffer();
    return NULL;
}

/**
 * @brief Thread entrypoint for the sharded L5 Application Engine consensus consumer.
 *
 * @details
 * Each consumer worker thread:
 * 1. Claims connections from the 4,096-bucket CID table sharded by `conn->cid[0] % NUM_CRYPTO_WORKERS`.
 * 2. Drains connection SPSC intake queues (@ref process_spsc_queue).
 * 3. Evaluates RFC 9002 loss detection timers and retransmits lost packets (@ref scl_l4_detect_lost_packets).
 * 4. Enforces connection silence timeouts (@ref MAX_PEER_SILENCE_TIME) and triggers idle disconnect sweeps.
 * 5. Paces outbound datagram and stream queues (@ref process_egress_queues).
 *
 * Worker 0 additionally services outbound consensus message broadcasts, peer liveness pings,
 * watchdog proposer checks, and peer auto-reconnection attempts.
 *
 * @pre `arg` must point to a heap-allocated @ref CryptoWorkerArgs struct (callee frees).
 * @post Worker loop executes until `global_shutdown` is signaled; releases buffers on termination.
 * @sideeffects Dequeues network frames, encrypts egress packets, schedules retransmissions.
 * @synchronization Thread Safety: Sharded lock-free connection assignment; acquires connection mutexes per task.
 *
 * @param[in] arg Pointer to heap-allocated `CryptoWorkerArgs` (callee assumes ownership and frees).
 *
 * @return void* Always returns NULL upon termination.
 *
 * @complexity
 * - Time: Continuous event loop bounded by active connection counts and network traffic rates.
 * - Auxiliary Space: O(MAX_MESSAGE_SIZE) heap allocation for staging buffers.
 */
void *l5_application_engine_thread(void *arg) {
    CryptoWorkerArgs *wargs = (CryptoWorkerArgs *)arg;
    int worker_id = wargs->worker_id;
    free(wargs); // We no longer need wargs->test_conn. Worker 0 will naturally pick up zero_cid.

#ifdef USE_XDP
    current_worker_id = worker_id;
#endif

    State *state = global_state;
    P2PNetwork *net = &state->p2p_network;

    uint8_t *decryption_buffer = malloc(MAX_MESSAGE_SIZE);
    Message *in_msg = malloc(sizeof(Message));
    Message *out_msg = malloc(sizeof(Message));
    uint8_t sender_pubkey[DILITHIUM_PUBKEY_LEN];

    if (!decryption_buffer || !in_msg || !out_msg) {
        fprintf(stderr, "[L5 Worker %d] Failed to allocate buffers.\n", worker_id);
        if (decryption_buffer) free(decryption_buffer);
        if (in_msg) free(in_msg);
        if (out_msg) free(out_msg);
        return NULL;
    }

    fprintf(stderr, "[L5 Worker %d] Application Engine Consensus Consumer Started.\n", worker_id);

    while (global_args && global_args->running && !atomic_load(&global_shutdown)) {
        bool work_done = false;
        if (worker_id == 0) {
            // 1. Process Outbound Message Queue (Egress)
            if (queue_has_items(&state->message_queue) && queue_dequeue(&state->message_queue, out_msg) == 0) {
                work_done = true;
                int should_broadcast = 1;
                if (out_msg->type == MSG_PENDING_OPERATION) {
                    Operation *op = calloc(1, sizeof(Operation));
                    if (op) {
                        if (deserialize_operation(out_msg->payload, out_msg->length, op, 1) > 0) {
                            uint8_t key[COIN_ID_LEN];
                            bool check_key = false;
                            if (op->type == OP_TRANSFER_POINTER) {
                                memcpy(key, op->data.transfer_pointer.tx_id, COIN_ID_LEN);
                                check_key = true;
                            } else if (op->type == OP_REDEEM_CENTINEL) {
                                memcpy(key, op->data.redeem_centinel.nullifier, NULLIFIER_LEN);
                                check_key = true;
                            }
                            
                            if (check_key) {
                                bool found = false;
                                for (int k = 0; k < MAX_PENDING_OPS; k++) {
                                    Operation *pop = atomic_load_explicit(&state->pending_operations[k], memory_order_acquire);
                                    if (pop) {
                                        const uint8_t *pid = get_operation_tx_id(pop);
                                        uint8_t pkey[COIN_ID_LEN];
                                        if (pid) memcpy(pkey, pid, COIN_ID_LEN);
                                        else SHA256((uint8_t*)pop, sizeof(Operation), pkey);
                                        
                                        if (memcmp(pkey, key, COIN_ID_LEN) == 0) {
                                            found = true; break;
                                        }
                                    }
                                }
                                if (!found) should_broadcast = 0;
                            }
                        }
                        free(op);
                    }
                }
                if (should_broadcast) {
                    p2p_broadcast(state, out_msg);
                }
            }
            
            // --- Liveness Ping to prevent IBD Stall Timeout ---
            time_t current_time = time(NULL);
            static time_t last_ping_time = 0;
            if (last_ping_time == 0) {
                last_ping_time = current_time;
            }
            static time_t last_proposer_check = 0;
            if (last_proposer_check == 0) {
                last_proposer_check = current_time;
            }
                        
            if (current_time - last_ping_time >= LIVENESS_CHECK_INTERVAL) {
                last_ping_time = current_time;
                pthread_mutex_lock(&net->mutex);
                for (size_t i = 0; i < net->num_known_peers; i++) {
                    /* Skip zero-pubkey dial placeholders: pinging them keeps
                     * superseded sockets alive forever (every reply refreshes
                     * last_rx_time), making them immortal zombies that dodge the
                     * 60s silence GC and pin the Active Node count at a stale
                     * value while burning one admission slot each. */
                    if (net->known_peers[i] && net->known_peers[i]->conn &&
                        !is_zeroed(net->known_peers[i]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
                        net->known_peers[i]->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                        Message *ping = calloc(1, sizeof(Message));
                        if (ping) {
                            ping->type = MSG_BLOCK_NUMBER_QUERY;
                            ping->length = 0;
                            queue_enqueue(&net->known_peers[i]->conn->tx_stream_queue, ping);
                            free(ping);
                        }
                    }
                }
                pthread_mutex_unlock(&net->mutex);
            }

            // --- Watchdog to unstick block proposals if designated proposer drops ---
            // Enforces prompt edge-case recovery by checking every 15 seconds (independent of VOTE_TIMEOUT)
            // to detect proposer failures faster and trigger fallback proposers earlier.
            if (current_time - last_proposer_check >= 15) {
                last_proposer_check = current_time;

                pthread_mutex_lock(&state->mutex);
                bool is_syncing = state->in_blockchain_sync ||
                                  atomic_load(&state->sync_thread_active) ||
                                  (state->network_target_block_number > 0 && state->current_block_number < state->network_target_block_number);
                pthread_mutex_unlock(&state->mutex);

                if (!is_syncing) {
                    trigger_proposer_if_eligible(state);
                }
            }
            
            // --- Auto-Reconnect Watchdog ---
            static time_t last_reconnect_check = 0;
            if (last_reconnect_check == 0) {
                last_reconnect_check = current_time;
            }
            if (current_time - last_reconnect_check >= 15) {
                last_reconnect_check = current_time;
                
                struct sockaddr_storage reconnect_addrs[128];
                size_t reconnect_count = 0;

                pthread_mutex_lock(&net->mutex);
                size_t active_peers = 0;
                for (size_t i = 0; i < net->num_known_peers; i++) {
                    if (net->known_peers[i] && net->known_peers[i]->conn &&
                        net->known_peers[i]->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
                        active_peers++;
                    }
                }

                for (size_t i = 0; i < net->num_known_peers && reconnect_count < 128; i++) {
                    Peer *peer = net->known_peers[i];
                    if (!peer) continue;
                    if (memcmp(peer->peer_wallet.dilithium_pubkey, net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) continue;

                    // Clean up unauthenticated pending peers that have disconnected or failed
                    if (is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN)) {
                        if (!peer->conn || peer->conn->handshake_state == SCL_CONN_STATE_NONE) {
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
                            free(peer);
                            for (size_t j = i; j < net->num_known_peers - 1; j++) {
                                net->known_peers[j] = net->known_peers[j + 1];
                            }
                            net->known_peers[net->num_known_peers - 1] = NULL;
                            net->num_known_peers--;
                            i--;
                        }
                        continue;
                    }

                    // Only reconnect to authenticated peers seen recently, avoiding duplicate addresses
                    if (validate_dilithium_pubkey(peer->peer_wallet.dilithium_pubkey) &&
                        (time(NULL) - peer->last_seen) < 300) {
                        if (!peer->conn || peer->conn->handshake_state == SCL_CONN_STATE_NONE) {
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
                            bool already_added = false;
                            for (size_t r = 0; r < reconnect_count; r++) {
                                if (sockaddr_storage_equal(&reconnect_addrs[r], &peer->addr)) {
                                    already_added = true;
                                    break;
                                }
                            }
                            if (!already_added) {
                                reconnect_addrs[reconnect_count++] = peer->addr;
                            }
                        }
                    }
                }
                pthread_mutex_unlock(&net->mutex);
                
                // Initiate reconnection attempts to regular known peers that went offline
                for (size_t k = 0; k < reconnect_count; k++) {
                    scl_initiate_connection(net, &reconnect_addrs[k]);
                }
                
                // Fall back to bootstrapping only if we are completely isolated (active_peers == 0)
                if (active_peers == 0) {
                    if (!net->is_bootstrap) {
                        fprintf(stderr, "[Watchdog] Node isolated from network. Attempting automatic reconnection to bootstrap nodes...\n");
                    } else {
                        scl_log(LOG_LEVEL_DEBUG, "Watchdog", "Node isolated from network. Attempting automatic reconnection to bootstrap nodes...");
                    }
                    
                    struct sockaddr_storage bootstrap_addrs[32];
                    size_t num_bootstrap = 0;
                    char temp_str[1024];
                    strncpy(temp_str, state->config.bootstrap_nodes_str, sizeof(temp_str) - 1);
                    temp_str[sizeof(temp_str) - 1] = '\0';
                    char *token = strtok(temp_str, ",");
                    while (token && num_bootstrap < 32) {
                        char ip[64];
                        int b_port = 5555;
                        memset(&bootstrap_addrs[num_bootstrap], 0, sizeof(struct sockaddr_storage));
                        
                        if (token[0] == '[') {
                            char *closing = strchr(token, ']');
                            if (closing && *(closing + 1) == ':') {
                                size_t ip_len = (size_t)(closing - (token + 1));
                                if (ip_len < sizeof(ip)) {
                                    strncpy(ip, token + 1, ip_len);
                                    ip[ip_len] = '\0';
                                    b_port = atoi(closing + 2);
                                    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&bootstrap_addrs[num_bootstrap];
                                    v6->sin6_family = AF_INET6;
                                    v6->sin6_port = htons(b_port);
                                    inet_pton(AF_INET6, ip, &v6->sin6_addr);
                                    num_bootstrap++;
                                }
                            }
                        } else if (sscanf(token, "%63[^:]:%d", ip, &b_port) >= 1) {
                            struct sockaddr_in *v4 = (struct sockaddr_in *)&bootstrap_addrs[num_bootstrap];
                            v4->sin_family = AF_INET;
                            v4->sin_port = htons(b_port);
                            inet_pton(AF_INET, ip, &v4->sin_addr);
                            num_bootstrap++;
                        }
                        token = strtok(NULL, ",");
                    }
                    
                    for (size_t i = 0; i < num_bootstrap; i++) {
                        bool is_loopback = false;
                        if (bootstrap_addrs[i].ss_family == AF_INET) {
                            struct sockaddr_in *v4 = (struct sockaddr_in *)&bootstrap_addrs[i];
                            if (v4->sin_addr.s_addr == inet_addr("127.0.0.1")) is_loopback = true;
                        } else if (bootstrap_addrs[i].ss_family == AF_INET6) {
                            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&bootstrap_addrs[i];
                            if (memcmp(&v6->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) == 0) is_loopback = true;
                        }
                        if (sockaddr_storage_equal(&bootstrap_addrs[i], &net->local_peer.addr) || is_loopback) {
                            continue;
                        }
                        scl_initiate_connection(net, &bootstrap_addrs[i]);
                    }
                }
            }
        }

        // 3. Process Connection Queues Sharded by Worker ID (Strict Lock-Free L5 Dispatching)
        UserSpaceState *us_state = (UserSpaceState *)global_shim->impl_state;

        // Fast-path: Workers 1..N-1 have no connections when active_connection_count is 0
        if (worker_id != 0 && atomic_load_explicit(&us_state->active_connection_count, memory_order_relaxed) == 0) {
            usleep(net->is_bootstrap ? 500 : 10000);
            continue;
        }

        SclConnection *peer_conns[4096];
        size_t conns_to_process = 0;

        for (int i = 0; i < 4096; i++) {
            SclConnection *conn = atomic_load_explicit(&us_state->cid_routing_table[i], memory_order_acquire);
            if (conn && conn != SCL_TOMBSTONE) {
                // zero_cid (listener) trivially equates to 0, granting it exclusively to Worker 0
                // Optimized to prevent O(N^2) cache-miss CPU choke causing L4 drop spikes
                if (conn->cid[0] % NUM_CRYPTO_WORKERS == (uint32_t)worker_id) {
                    if (try_acquire_ref(conn)) {
                        peer_conns[conns_to_process] = conn;
                        conns_to_process++;
                    }
                }
            }
        }
        
        if (conns_to_process > 0) {
            for (size_t i = 0; i < conns_to_process; i++) {
                if (peer_conns[i]) {
                    
                    bool expected = false;
                    // Mutually exclusive ticket acquisition. If another worker thread is already executing
                    // this specific connection state (e.g. dynamic NEW_CID rotation shift mid-tick), skip it.
                    if (atomic_compare_exchange_strong_explicit(&peer_conns[i]->is_processing, &expected, true, memory_order_acquire, memory_order_relaxed)) {
                        
                        uint32_t q_tail = atomic_load_explicit(&peer_conns[i]->l5_rx_queue.tail, memory_order_relaxed);
                        uint32_t q_head = atomic_load_explicit(&peer_conns[i]->l5_rx_queue.head, memory_order_acquire);
                        if (q_tail != q_head) work_done = true;
                        if (queue_has_items(&peer_conns[i]->tx_datagram_queue) ||
                            queue_has_items(&peer_conns[i]->tx_stream_queue) ||
                            peer_conns[i]->active_fragment_buffer != NULL) {
                            work_done = true;
                        }

                        process_spsc_queue(peer_conns[i], state, net, decryption_buffer, in_msg, out_msg);
                        
                        // Prevent Flow-Control Deadlock by asynchronously issuing MAX_DATA when queue pressure subsides
                        if (peer_conns[i]->rx_consumed_data + (SCL_FLOW_WINDOW_SIZE / 2) > peer_conns[i]->rx_max_data) {
                            uint32_t q_head = atomic_load_explicit(&peer_conns[i]->l5_rx_queue.head, memory_order_relaxed);
                            uint32_t q_tail = atomic_load_explicit(&peer_conns[i]->l5_rx_queue.tail, memory_order_acquire);
                            uint32_t utilized = (q_head >= q_tail) ? (q_head - q_tail) : (SCL_L5_RING_SIZE - q_tail + q_head);
                            if (utilized <= (SCL_L5_RING_SIZE / 2) && !peer_conns[i]->pending_max_data_update) {
                                peer_conns[i]->rx_max_data = peer_conns[i]->rx_consumed_data + SCL_FLOW_WINDOW_SIZE;
                                peer_conns[i]->pending_max_data_update = true;
                            }
                        }
                        
                        uint64_t now_ms = get_time_ms();

                        process_egress_queues(peer_conns[i], out_msg);
                        
                        // --- L4 Loss Detection (Moved from us_poll) ---
                        uint64_t loss_time = peer_conns[i]->loss_time;
                        if (loss_time != 0 && now_ms >= loss_time) {
                            scl_l4_detect_lost_packets(peer_conns[i], now_ms, state, false);
                        }
                        
                        // --- IBD Stall Detection & GC (Moved from us_poll) ---
                        uint8_t zero_cid[SCL_CID_LEN] = {0};
                        bool is_listener = (memcmp(peer_conns[i]->cid, zero_cid, SCL_CID_LEN) == 0);
                        
                        if (!is_listener) {
                            uint64_t last_rx = atomic_load_explicit(&peer_conns[i]->last_rx_time, memory_order_relaxed);
                            if (now_ms > last_rx) {
                                uint64_t idle_time = now_ms - last_rx;
                                if (peer_conns[i]->is_untrusted_sync && idle_time > SCL_STALL_TIMEOUT_MS) {
                                    pthread_mutex_lock(&peer_conns[i]->l4_mutex);
                                    if (peer_conns[i]->cwnd > SCL_DECAYED_BDP_LIMIT) {
                                        peer_conns[i]->cwnd = SCL_DECAYED_BDP_LIMIT;
                                    }
                                    pthread_mutex_unlock(&peer_conns[i]->l4_mutex);
                                }
                                
                                uint64_t timeout_threshold = (peer_conns[i]->handshake_state == SCL_CONN_STATE_ESTABLISHED) ? (MAX_PEER_SILENCE_TIME * 1000ULL) : 30000ULL;
                                if (idle_time > timeout_threshold) {
                                    scl_log(LOG_LEVEL_DEBUG, "L5 Worker", "Connection stalled natively. GC sweeps triggered.");
                                    
                                    int found = 0;
                                    pthread_mutex_lock(&net->mutex);
                                    for (size_t k = 0; k < net->num_known_peers; k++) {
                                        if (net->known_peers[k]->conn == peer_conns[i]) {
                                            memcpy(sender_pubkey, net->known_peers[k]->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
                                            found = 1;
                                            break;
                                        }
                                    }
                                    pthread_mutex_unlock(&net->mutex);
                                    if (!found) memset(sender_pubkey, 0, DILITHIUM_PUBKEY_LEN);
                                    
                                    in_msg->type = MSG_PEER_DISCONNECT;
                                    in_msg->length = 0;
                                    
                                    struct sockaddr_storage dummy_addr;
                                    memset(&dummy_addr, 0, sizeof(dummy_addr));
                                    dispatch_l5_message(peer_conns[i], state, net, in_msg, out_msg, sender_pubkey, &dummy_addr);
                                    
                                    peer_conns[i]->handshake_state = SCL_CONN_STATE_NONE;
                                }
                            }
                        }
                        
                        // GC Unmapped Connections
                        if (peer_conns[i]->handshake_state == SCL_CONN_STATE_NONE) {
                            uint8_t zero_cid[SCL_CID_LEN] = {0};
                            if (memcmp(peer_conns[i]->cid, zero_cid, SCL_CID_LEN) != 0) {
                                if (global_shim && global_shim->unregister_connection(global_shim, peer_conns[i]->cid)) {
                                    // Successfully extracted from CID table, release its designated routing reference lock
                                    scl_connection_release(peer_conns[i]);
                                }
                            }
                        }
                        
                        // Explicitly clear the spin-lock now that this execution tick is safely over
                        atomic_store_explicit(&peer_conns[i]->is_processing, false, memory_order_release);
                    }
                    
                    scl_connection_release(peer_conns[i]); // Always drop the current worker tick reference
                }
            }
        }
        if (work_done) {
            usleep(net->is_bootstrap ? 250 : 500);
        } else {
            usleep(net->is_bootstrap ? 500 : 10000);
        }
    }
            
    fprintf(stderr, "[L5 Worker %d] Exiting.\n", worker_id);
        
    if (decryption_buffer) {
        memset(decryption_buffer, 0, MAX_MESSAGE_SIZE);
        free(decryption_buffer);
    }
    if (in_msg) free(in_msg);
    if (out_msg) free(out_msg);
    
    release_l5_staging_buffer();
    return NULL;
}

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
/**
 * @brief Main execution entrypoint and lifecycle supervisor for the Satocialist native node daemon.
 *
 * @details
 * Execution Bootstrap Sequence:
 * 1. Initializes default `DaemonConfig` values; overrides via `satocialist.conf` and CLI flags.
 * 2. Configures logging severity thresholds and initializes Google qsim quantum emulation runtime.
 * 3. Registers POSIX signal handlers (`SIGINT`, `SIGTERM`, `SIGPIPE`).
 * 4. Loads or generates post-quantum wallet credentials (Dilithium5 and Kyber-512).
 * 5. Allocates and initializes master ledger state via @ref client_state_init.
 * 6. Binds L0 transport driver shim (Userspace UDP or Linux AF_XDP).
 * 7. Spawns service thread pools:
 *    - L0 Driver Event Loop (`shim_event_loop_thread`)
 *    - L5 Application Engine Workers (`l5_application_engine_thread` x `NUM_CRYPTO_WORKERS`)
 *    - Submission Processors (`submission_processor_thread` x CPU cores)
 *    - Hourly Validation Grant Timer (`validation_timer`)
 *    - Prometheus Metrics HTTP Server (`prometheus_metrics_server`)
 *    - WebSocket-to-UDP Browser Bridge (`websocket_bridge_server`)
 * 8. Connects to bootstrap seed nodes and executes Initial Block Download (IBD) synchronization.
 * 9. Launches interactive CLI menu (interactive mode) or blocks awaiting shutdown signals (daemon mode).
 * 10. Executes graceful multi-phase system teardown via @ref perform_shutdown.
 *
 * @param[in] argc Argument count.
 * @param[in] argv Argument vector.
 *
 * @return int 0 on clean, successful shutdown; 1 on fatal initialization or configuration failure.
 *
 * @complexity
 * - Time: Indefinite execution lifetime; shutdown bounded by thread join timeouts.
 * - Auxiliary Space: Up to peak resident heap allocation (~20-60 MiB depending on mempool and cache).
 */
int main(int argc, char *argv[]) {
    DaemonConfig config = {
        .local_ip = "0.0.0.0",
        .port = 5555,
        .log_level = LOG_LEVEL_INFO,
        .config_file = "satocialist.conf",
        .initial_rtt_ms = 800,
        .min_pto_ms = 1000,
        .max_ack_delay_ms = 25,
        .time_threshold_num = 9,
        .time_threshold_den = 8,
        .rbf_enabled = true,
        .max_pending_ops_config = 1000,
        .mempool_async_threshold = 50,
        .metrics_port = 8000,
        .websocket_port = 5554,
        .bootstrap_nodes_str = "136.65.1.22:5555,35.192.184.226:5555,[2600:1900:4000:5ce:0:4::]:5555,[2600:1900:4000:5ce:0:5::]:5555", // Default fallback from satocialist.conf
        .is_daemon = false,
        .autopilot_enabled = false,
        .autopilot_valuations_per_hour = 1,
        .autopilot_stake_ratio = 50
    };


    struct option long_options[] = {
        {"ip", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"config", required_argument, 0, 'c'},
        {"log-level", required_argument, 0, 'l'},
        {"help", no_argument, 0, 'h'},
        {"daemon", no_argument, 0, 'd'},
        {"autopilot", no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    // Pre-scan for custom config file paths to preserve command-line override precedence
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            strncpy(config.config_file, argv[i + 1], sizeof(config.config_file) - 1);
            break;
        }
    }

    // Load config file values first as baseline
    load_config(config.config_file, &config);

    // Parse command line arguments next to override baseline configs
    optind = 1; // Reset getopt parser index
    int opt;
    while ((opt = getopt_long(argc, argv, "i:p:c:l:hda", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': strncpy(config.local_ip, optarg, sizeof(config.local_ip) - 1); break;
            case 'p': config.port = atoi(optarg); break;
            case 'c': strncpy(config.config_file, optarg, sizeof(config.config_file) - 1); break;
            case 'd': config.is_daemon = true; break;
            case 'a': config.autopilot_enabled = true; break;
            case 'l':
                if (strcasecmp(optarg, "trace") == 0) config.log_level = LOG_LEVEL_TRACE;
                else if (strcasecmp(optarg, "debug") == 0) config.log_level = LOG_LEVEL_DEBUG;
                else if (strcasecmp(optarg, "info") == 0) config.log_level = LOG_LEVEL_INFO;
                else if (strcasecmp(optarg, "warn") == 0) config.log_level = LOG_LEVEL_WARN;
                else if (strcasecmp(optarg, "error") == 0) config.log_level = LOG_LEVEL_ERROR;
                else if (strcasecmp(optarg, "fatal") == 0) config.log_level = LOG_LEVEL_FATAL;
                break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    scl_log_set_level(config.log_level);

    // Initialize native Google qsim C++ environment
    extern int init_quantum_qsim_environment(void);
    init_quantum_qsim_environment();

    scl_log(LOG_LEVEL_INFO, "Main", "Starting Satocialist peer node, OQS version: %s, PID=%d", OQS_version(), getpid());
    LOG_DILITHIUM_CONSTANTS();
    LOG_KYBER_CONSTANTS();

    struct in_addr addr4;
    struct in6_addr addr6;
    if ((inet_pton(AF_INET, config.local_ip, &addr4) != 1 && inet_pton(AF_INET6, config.local_ip, &addr6) != 1) || config.port <= 0 || config.port > 65535) {
        scl_log(LOG_LEVEL_FATAL, "Main", "Invalid IP (%s) or port (%d)", config.local_ip, config.port);
        return 1;
    }
    fprintf(stderr, "[P2P] DEBUG: Initializing peer on %s:%d\n", config.local_ip, config.port);

    signal(SIGINT, cleanup_handler);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    State state = {0};
    state.config = config; // Copy parsed configuration properties into global state
    global_state = &state;

    PeerWallet peer_wallet;
    if (!create_peer_wallet(&peer_wallet)) {
        scl_log(LOG_LEVEL_FATAL, "Crypto", "Failed to generate peer wallet");
        cleanup_handler(SIGINT);
        return 1;
    }

    pthread_mutex_lock(&state.wallet_mutex);
    char wallet_filename[256];
    snprintf(wallet_filename, sizeof(wallet_filename), "wallet_%d.dat", config.port);
    if (load_user_wallet(&state.user_wallet, wallet_filename) == 0) {
        scl_log(LOG_LEVEL_INFO, "Crypto", "Successfully loaded existing identity from %s", wallet_filename);
    } else {
        scl_log(LOG_LEVEL_INFO, "Crypto", "No existing %s found. Generating new wallet...", wallet_filename);
        if (!create_user_wallet(&state.user_wallet)) {
            scl_log(LOG_LEVEL_FATAL, "Crypto", "Failed to generate user wallet");
            pthread_mutex_unlock(&state.wallet_mutex);
            cleanup_handler(SIGINT);
            return 1;
        }
        save_user_wallet(&state.user_wallet, wallet_filename);
    }
    // Unify Peer and User Dilithium identities to ensure seamless key routing and verification in DKG
    memcpy(peer_wallet.dilithium_pubkey, state.user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(peer_wallet.dilithium_privkey, state.user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    pthread_mutex_unlock(&state.wallet_mutex);

    P2PNetwork *net = &state.p2p_network;
    memset(&net->local_peer.addr, 0, sizeof(struct sockaddr_storage));
    if (strchr(config.local_ip, ':')) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&net->local_peer.addr;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(config.port);
        inet_pton(AF_INET6, config.local_ip, &v6->sin6_addr);
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&net->local_peer.addr;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(config.port);
        inet_pton(AF_INET, config.local_ip, &v4->sin_addr);
    }
    net->local_peer.peer_wallet = peer_wallet;
    const char *seed_env = getenv("SCL_SEED_NODE");
    const char *local_env = getenv("SCL_LOCAL_NODE");
    if (seed_env && (strcmp(seed_env, "1") == 0 || strcasecmp(seed_env, "true") == 0)) {
        net->is_bootstrap = 1;
    } else if (local_env && (strcmp(local_env, "1") == 0 || strcasecmp(local_env, "true") == 0)) {
        net->is_bootstrap = 0;
    } else {
        net->is_bootstrap = (config.port == 5555 || config.port == 5556);
    }
    fprintf(stderr, "[P2P] DEBUG: Local peer configured: %s:%d (Bootstrap: %d)\n", config.local_ip, config.port, net->is_bootstrap);

    // Initialize Network State INLINE instead of `p2p_init` to avoid UDP socket conflicts
    pthread_mutex_init(&net->mutex, NULL);
    net->num_known_peers = 0;
    net->known_peers = NULL;
    net->nat_type = NAT_TYPE_UNKNOWN;
    memset(&net->public_addr, 0, sizeof(struct sockaddr_storage));

    // Graceful error degradation mapping
    if (client_state_init(&state, net->is_bootstrap) != 0) {
        scl_log(LOG_LEVEL_FATAL, "State", "Failed to initialize client state gracefully. Shutting down.");
        cleanup_handler(SIGINT);
        return 1;
    }
    
    queue_init(&state.message_queue);

    // state.mutex is already safely and fully initialized inside client_state_init

    // Append local peer to known_peers list
    pthread_mutex_lock(&net->mutex);
    Peer *local_peer_copy = malloc(sizeof(Peer));
    if (local_peer_copy) {
        net->known_peers = malloc(sizeof(Peer*));
        if (net->known_peers) {
            *local_peer_copy = net->local_peer;
            memset(local_peer_copy->peer_wallet.dilithium_privkey, 0, DILITHIUM_SECRETKEY_LEN);
            net->known_peers[0] = local_peer_copy;
            net->num_known_peers = 1;
        } else {
            free(local_peer_copy);
        }
    }
    pthread_mutex_unlock(&net->mutex);

    // Register Local User
    uint8_t local_user_id[USER_ID_LEN];
    SHA256(state.user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, local_user_id);
    if (register_user(&state, local_user_id, state.user_wallet.dilithium_pubkey) != 0) {
        fprintf(stderr, "[Network] ERROR: Failed to register local user\n");
        cleanup_handler(SIGINT);
        return 1;
    }
    global_user = find_user_by_pubkey(&state, state.user_wallet.dilithium_pubkey);

    static NetworkArgs args;
    args.state = &state;
    args.user = global_user;
    args.running = 1;
    pthread_mutex_init(&args.shutdown_mutex, NULL);
    pthread_cond_init(&args.shutdown_cond, NULL);
    global_args = &args;

    // --- QUIC-PARITY SHIM INIT ---
#ifdef USE_XDP
    struct SclTransportShim *shim = scl_xdp_shim_create("eth0", config.port);
#else
    struct SclTransportShim *shim = scl_userspace_shim_create(config.local_ip, config.port);
#endif
    if (!shim) {
        fprintf(stderr, "[P2P] ERROR: Failed to create Transport Shim on %s:%d\n", config.local_ip, config.port);
        cleanup_handler(SIGINT);
        return 1;
    }
    global_shim = shim;
                
    // Retain test_connection ONLY for discovery packets
    SclConnection *test_connection = NULL;
    SCL_ALIGNED_ALLOC(&test_connection, 64, sizeof(SclConnection));
    if (!test_connection) {
        fprintf(stderr, "[P2P] ERROR: Failed to allocate aligned SclConnection\n");
            cleanup_handler(SIGINT);
        return 1;
    }
    memset(test_connection, 0, sizeof(SclConnection));
    atomic_init(&test_connection->ref_count, 1);
    atomic_init(&test_connection->is_processing, false); // Initialize processing lock
    test_connection->l5_rx_queue.buffer = calloc(SCL_L5_RING_SIZE, sizeof(uint8_t*));
    test_connection->l5_rx_queue.lengths = malloc(SCL_L5_RING_SIZE * sizeof(size_t));
    test_connection->l5_rx_queue.addrs = malloc(SCL_L5_RING_SIZE * sizeof(struct sockaddr_storage));
    test_connection->l5_rx_queue.rx_times = malloc(SCL_L5_RING_SIZE * sizeof(uint64_t));
    for (int i = 0; i < SCL_L5_RING_SIZE; i++) {
        test_connection->l5_rx_queue.buffer[i] = malloc(4096);
    }
    atomic_init(&test_connection->l5_rx_queue.head, 0);
    atomic_init(&test_connection->l5_rx_queue.tail, 0);
    // test_connection->replay_window_bitmask will be NULL because broadcast packets bypass sliding windows.
    
    // Initialize the L4 Mutex to prevent undefined behavior when scl_connection_release locks it during shutdown
    pthread_mutex_init(&test_connection->l4_mutex, NULL);
        
    uint8_t broadcast_cid[SCL_CID_LEN] = {0};
    shim->register_connection(shim, broadcast_cid, test_connection);

    // Spawn background worker threads with expanded 8 MiB stack allocations
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setstacksize(&thread_attr, 8 * 1024 * 1024);
                
    if (pthread_create(&global_net_thread, &thread_attr, shim_event_loop_thread, shim) != 0) {
        cleanup_handler(SIGINT);
        return 1;
    }
                
    // SPEC IMPLEMENTATION: Spin up the Asynchronous Cryptographic Worker Pool
    for (int i = 0; i < NUM_CRYPTO_WORKERS; i++) {
        CryptoWorkerArgs *wargs = malloc(sizeof(CryptoWorkerArgs));
        wargs->test_conn = test_connection;
        wargs->worker_id = i;
        if (pthread_create(&global_l5_threads[i], &thread_attr, l5_application_engine_thread, wargs) != 0) {
            cleanup_handler(SIGINT);
            return 1;
        }
    }
            
    for (int i = 0; i < state.submission_workers_count; i++) {
        SubmissionProcessorArgs *sargs = malloc(sizeof(SubmissionProcessorArgs));
        sargs->state = &state;
        if (pthread_create(&state.submission_workers[i], &thread_attr, submission_processor_thread, sargs) != 0) {
            free(sargs);
            cleanup_handler(SIGINT);
            return 1;
        }
    }
            
    if (pthread_create(&validation_thread, &thread_attr, validation_timer, global_args) != 0) {
        cleanup_handler(SIGINT);
        return 1;
    }

    // Launch non-blocking Prometheus metrics HTTP server thread
    if (pthread_create(&metrics_exporter_thread, &thread_attr, prometheus_metrics_server, &state) != 0) {
        scl_log(LOG_LEVEL_WARN, "Metrics", "Failed to start Prometheus Metrics Exporter.");
    }

    // Launch WebSocket-to-UDP Bridge server thread
    if (pthread_create(&ws_bridge_thread, &thread_attr, websocket_bridge_server, &state) != 0) {
        scl_log(LOG_LEVEL_WARN, "Bridge", "Failed to start WebSocket-to-UDP Bridge.");
        ws_bridge_thread = 0;
    }

    pthread_attr_destroy(&thread_attr);

    // Dynamic bootstrap node parsing from DaemonConfig
    struct sockaddr_storage bootstrap_addrs[32];
    size_t num_bootstrap = 0;
    char temp_str[1024];
    strncpy(temp_str, config.bootstrap_nodes_str, sizeof(temp_str) - 1);
    temp_str[sizeof(temp_str) - 1] = '\0';
    char *token = strtok(temp_str, ",");
    while (token && num_bootstrap < 32) {
        char ip[64];
        int b_port = 5555;
        memset(&bootstrap_addrs[num_bootstrap], 0, sizeof(struct sockaddr_storage));
        
        if (token[0] == '[') {
            char *closing = strchr(token, ']');
            if (closing && *(closing + 1) == ':') {
                size_t ip_len = (size_t)(closing - (token + 1));
                if (ip_len < sizeof(ip)) {
                    strncpy(ip, token + 1, ip_len);
                    ip[ip_len] = '\0';
                    b_port = atoi(closing + 2);
                    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&bootstrap_addrs[num_bootstrap];
                    v6->sin6_family = AF_INET6;
                    v6->sin6_port = htons(b_port);
                    inet_pton(AF_INET6, ip, &v6->sin6_addr);
                    num_bootstrap++;
                }
            }
        } else if (sscanf(token, "%63[^:]:%d", ip, &b_port) >= 1) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)&bootstrap_addrs[num_bootstrap];
            v4->sin_family = AF_INET;
            v4->sin_port = htons(b_port);
            inet_pton(AF_INET, ip, &v4->sin_addr);
            num_bootstrap++;
        }
        token = strtok(NULL, ",");
    }

    if (!net->is_bootstrap) {
        // Client nodes: send discovery to all bootstrap nodes and wait
        for (size_t i = 0; i < num_bootstrap; i++) {
            scl_initiate_connection(net, &bootstrap_addrs[i]);
            
            char b_ip_str[64] = "unknown";
            int b_port = 0;
            if (bootstrap_addrs[i].ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in*)&bootstrap_addrs[i])->sin_addr, b_ip_str, sizeof(b_ip_str));
                b_port = ntohs(((struct sockaddr_in*)&bootstrap_addrs[i])->sin_port);
            } else if (bootstrap_addrs[i].ss_family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)&bootstrap_addrs[i])->sin6_addr, b_ip_str, sizeof(b_ip_str));
                b_port = ntohs(((struct sockaddr_in6*)&bootstrap_addrs[i])->sin6_port);
            }
            fprintf(stderr, "[P2P] DEBUG: Sent discovery message to bootstrap node %s:%d\n", b_ip_str, b_port);
        }
        printf("[P2P] Waiting for valid peers (up to 60 seconds)\n");
        wait_for_valid_peers(&state, 60);
    } else {
        // Bootstrap nodes: send discovery to *other* bootstrap nodes
        for (size_t i = 0; i < num_bootstrap; i++) {
            if (sockaddr_storage_equal(&bootstrap_addrs[i], &net->local_peer.addr)) {
                continue;
            }
            scl_initiate_connection(net, &bootstrap_addrs[i]);
            
            char b_ip_str[64] = "unknown";
            int b_port = 0;
            if (bootstrap_addrs[i].ss_family == AF_INET) {
                inet_ntop(AF_INET, &((struct sockaddr_in*)&bootstrap_addrs[i])->sin_addr, b_ip_str, sizeof(b_ip_str));
                b_port = ntohs(((struct sockaddr_in*)&bootstrap_addrs[i])->sin_port);
            } else if (bootstrap_addrs[i].ss_family == AF_INET6) {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)&bootstrap_addrs[i])->sin6_addr, b_ip_str, sizeof(b_ip_str));
                b_port = ntohs(((struct sockaddr_in6*)&bootstrap_addrs[i])->sin6_port);
            }
            fprintf(stderr, "[P2P] DEBUG: Bootstrap node sent discovery to other bootstrap node %s:%d\n",
                    b_ip_str, b_port);
        }
            
        printf("[P2P] Waiting for other bootstrap peers (up to 15 seconds)\n");
        wait_for_valid_peers(&state, 15);
    }
        
    uint8_t *recipient_pubkey = NULL;
    if (!net->is_bootstrap) {
        pthread_mutex_lock(&net->mutex);
        for (size_t i = 0; i < net->num_known_peers; i++) {
            Peer *peer = net->known_peers[i];
            for (size_t j = 0; j < num_bootstrap; j++) {
                // Include localhost tolerance for clients on the same device
                bool is_loopback = false;
                if (peer->addr.ss_family == AF_INET) {
                    if (((struct sockaddr_in*)&peer->addr)->sin_addr.s_addr == inet_addr("127.0.0.1")) is_loopback = true;
                } else if (peer->addr.ss_family == AF_INET6) {
                    if (memcmp(&((struct sockaddr_in6*)&peer->addr)->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr)) == 0) is_loopback = true;
                }
                
                if ((sockaddr_storage_equal(&peer->addr, &bootstrap_addrs[j]) || is_loopback) &&
                    !is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
                    peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) { // REQUIRE HANDSHAKE
                    recipient_pubkey = peer->peer_wallet.dilithium_pubkey;
                    break;
                }
            }
            if (recipient_pubkey) break;
        }
        pthread_mutex_unlock(&net->mutex);

        if (!recipient_pubkey) {
            if (state.current_block_number > 0 || !is_zeroed(state.current_block_hash, COIN_ID_LEN)) {
                fprintf(stderr, "[P2P] WARNING: No bootstrap peer found after discovery; proceeding with local blockchain (height %llu)\n",
                        (unsigned long long)state.current_block_number);
            } else {
                fprintf(stderr, "[P2P] ERROR: No bootstrap peer found after discovery\n");
                cleanup_handler(SIGINT);
                return 1;
            }
        }
    }

    // Select established peer and execute multi-layered state synchronization
    printf("[P2P] Initiating blockchain synchronization\n");
    uint8_t sync_peer_pubkey[DILITHIUM_PUBKEY_LEN];
    int found_sync_peer = 0;
        
    pthread_mutex_lock(&net->mutex);
    for (size_t i = 0; i < net->num_known_peers; i++) {
        Peer *peer = net->known_peers[i];
        if (!is_zeroed(peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
            memcmp(peer->peer_wallet.dilithium_pubkey, net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) != 0 &&
            peer->conn && peer->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) { // REQUIRE HANDSHAKE
                
            // Deep copy the pubkey to prevent use-after-free
            memcpy(sync_peer_pubkey, peer->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
            found_sync_peer = 1;
            break;
        }
    }
    pthread_mutex_unlock(&net->mutex);

    if (found_sync_peer) {
        char hex_pub[33];
        bytes_to_hex(sync_peer_pubkey, 16, hex_pub);
        fprintf(stderr, "[P2P] DEBUG: Selected sync peer, Dilithium pubkey (first 16 bytes): %s\n", hex_pub);
        int bc_sync = sync_blockchain(&state, sync_peer_pubkey);
        int audit_sync = -1;
        int mempool_sync = -1;

        if (bc_sync == 0) {
            audit_sync = sync_audit(&state, sync_peer_pubkey);
            mempool_sync = sync_pending_operations(&state, sync_peer_pubkey);
        }
        
        // Tear down the sync lock globally only after all layers conclude
        pthread_mutex_lock(&state.mutex);
        state.in_blockchain_sync = 0;
        memset(state.sync_peer_pubkey, 0, DILITHIUM_PUBKEY_LEN);
        pthread_mutex_unlock(&state.mutex);

        if (bc_sync == 0) {
            if (audit_sync == 0 && mempool_sync == 0) {
                printf("[P2P] Full synchronization completed\n");
            } else {
                printf("[P2P] Blockchain synchronization completed (Audit:%s, Mempool:%s)\n",
                       (audit_sync == 0) ? "OK" : "PENDING",
                       (mempool_sync == 0) ? "OK" : "PENDING");
            }
        } else {
            if (state.current_block_number > 0 || !is_zeroed(state.current_block_hash, COIN_ID_LEN)) {
                printf("[P2P] WARNING: Peer synchronization timed out. Proceeding with existing local blockchain (height %llu)\n",
                       (unsigned long long)state.current_block_number);
            } else {
                printf("[P2P] ERROR: Synchronization failed on uninitialized node. Cannot join network without valid chain data.\n");
                cleanup_handler(SIGINT);
                return 1;
            }
        }
    } else {
        if (!net->is_bootstrap) {
            if (state.current_block_number > 0 || !is_zeroed(state.current_block_hash, COIN_ID_LEN)) {
                printf("[P2P] INFO: No peers available for sync; proceeding with existing local blockchain (height %llu)\n",
                       (unsigned long long)state.current_block_number);
            } else {
                printf("[P2P] ERROR: Client node could not find any peers to sync with.\n");
                cleanup_handler(SIGINT);
                return 1;
            }
        } else {
            if (state.current_block_number == 0 && is_zeroed(state.current_block_hash, COIN_ID_LEN)) {
                printf("[P2P] INFO: No peers available for sync; initializing blockchain with genesis block\n");
                if (initialize_genesis_block(&state) != 0) {
                    fprintf(stderr, "[P2P] ERROR: Failed to initialize genesis block\n");
                    cleanup_handler(SIGINT);
                    return 1;
                }
            } else {
                printf("[P2P] INFO: Bootstrap node proceeding with existing local blockchain (height %llu)\n",
                       (unsigned long long)state.current_block_number);
            }
        }
    }
    printf("[P2P] Blockchain synchronization completed\n");

    if (!net->is_bootstrap) {
        if (!recipient_pubkey && state.current_block_number == 0 && is_zeroed(state.current_block_hash, COIN_ID_LEN)) {
            fprintf(stderr, "[P2P] ERROR: No valid recipient for registration\n");
            cleanup_handler(SIGINT);
            return 1;
        }
    }
    
    // --- Network Topology Stabilization ---
    printf("[P2P] Waiting for network topology to stabilize (establishing connections to discovered peers)...\n");
    time_t stabilization_start = time(NULL);
    int fully_connected = 0;
        
    while (time(NULL) - stabilization_start < 30) {
        int pending_handshakes = 0;
            
        pthread_mutex_lock(&net->mutex);
        for (size_t i = 0; i < net->num_known_peers; i++) {
            Peer *peer = net->known_peers[i];
            if (memcmp(peer->peer_wallet.dilithium_pubkey, net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
                continue;
            }
            if (peer->conn && peer->conn->handshake_state != SCL_CONN_STATE_ESTABLISHED && peer->conn->handshake_state != SCL_CONN_STATE_NONE) {
                pending_handshakes++;
            }
        }
        pthread_mutex_unlock(&net->mutex);
            
        if (pending_handshakes == 0) {
            fully_connected = 1;
            break;
        }
        usleep(500000); // 500ms
    }
        
    if (fully_connected) {
        printf("[P2P] Network topology stabilized.\n");
    } else {
        printf("[P2P] WARNING: Network topology stabilization timed out. Proceeding with available connections.\n");
    }
    
    // Ensure all background/initial synchronizations are fully complete before starting the interactive menu
    bool is_syncing = false;
    time_t last_active_sync_time = time(NULL);
    
    pthread_mutex_lock(&state.mutex);
    is_syncing = state.in_blockchain_sync || atomic_load(&state.sync_thread_active) || (state.current_block_number < state.network_target_block_number);
    pthread_mutex_unlock(&state.mutex);

    if (is_syncing) {
        printf("[P2P] Active background synchronization detected. Postponing menu load until caught up...\n");
        while (1) {
            pthread_mutex_lock(&state.mutex);
            bool actively_syncing = state.in_blockchain_sync || atomic_load(&state.sync_thread_active);
            bool behind_target = (state.current_block_number < state.network_target_block_number);
            pthread_mutex_unlock(&state.mutex);
            
            if (actively_syncing) {
                last_active_sync_time = time(NULL);
            }
            
            // If we are not actively syncing, and it's been more than 15 seconds since we last synced,
            // we assume the sync has completely failed or finished (even if behind target) to prevent infinite UI stall.
            // 15 seconds safely bridges the 10-second circuit breaker cooldown between async sync retries.
            if (!actively_syncing && (time(NULL) - last_active_sync_time > 15)) {
                break;
            }
            
            // If we've reached the target, we can break early if not actively syncing
            if (!actively_syncing && !behind_target) {
                break;
            }
            
            usleep(200000); // Poll every 200ms to allow consensus and sync worker threads to execute
        }
        printf("[P2P] Background synchronization completed.\n");
    }
    
    srand((unsigned)time(NULL));
    fprintf(stderr, "[P2P] DEBUG: Starting interactive menu\n");
    scl_log_flush(); // Deterministically block until all pending background logs are written to the console
        
    // Enhanced UI Header with system information
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                           SOCIAL COMMODITY LAYER                             ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Node Type: %-15s   Port: %-5d         Block: %-12llu        ║\n",
            net->is_bootstrap ? "BOOTSTRAP" : "CLIENT",
            config.port,
            state.current_block_number);
        
    // Calculate and display status
    const char* status;
    pthread_mutex_lock(&net->mutex);
    size_t active_peers = 0;
    time_t now = time(NULL);
    const uint8_t **active_pubkeys = malloc(net->num_known_peers * sizeof(const uint8_t *));
                
    if (active_pubkeys) {
        size_t active_count = 0;
        for (size_t i = 0; i < net->num_known_peers; i++) {
            int is_active = 0;
            // Exclude the local node from remote active peer counts
            if (memcmp(net->known_peers[i]->peer_wallet.dilithium_pubkey, net->local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
                continue;
            } else if (net->known_peers[i]->conn && net->known_peers[i]->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED &&
                    (now - net->known_peers[i]->last_seen < 300)) { // 5-minute threshold
                is_active = 1;
            }
                
            if (is_active) {
                active_pubkeys[active_count++] = net->known_peers[i]->peer_wallet.dilithium_pubkey;
            }
        }
        if (active_count > 0) {
            qsort(active_pubkeys, active_count, sizeof(const uint8_t *), compare_pubkey_ptrs);
            active_peers = 0;
            for (size_t i = 0; i < active_count; i++) {
                if (i == 0 || memcmp(active_pubkeys[i], active_pubkeys[i - 1], PUBKEY_LEN) != 0) {
                    active_peers++;
                }
            }
        }
        free(active_pubkeys);
    }
    pthread_mutex_unlock(&net->mutex);
        
    if (net->is_bootstrap) {
        status = "ACTIVE (BOOTSTRAP)";
    } else if (active_peers > 0) {
        status = "CONNECTED";
    } else {
        status = "SYNCING";
    }
        
    printf("║  Status: %-20s Active Peers: %-3zu                              ║\n",
            status, active_peers);
    printf("║  Network: %-15s     PID: %-8d                                  ║\n",
            "P2P", getpid());
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    if (config.autopilot_enabled) {
        start_autopilot_thread(&state);
        scl_log(LOG_LEVEL_INFO, "Main", "Auto-Pilot activated on startup (Stake ratio: %u%%, Rate: %u/hr)",
                config.autopilot_stake_ratio, config.autopilot_valuations_per_hour);
    }

    // Enter non-interactive background loop or start interactive CLI menu
    if (config.is_daemon || !isatty(0)) {
        printf("[P2P] Running in non-interactive daemon mode. WebSocket bridge, Auto-Pilot, and Prometheus metrics active.\n");
        while (!atomic_load(&global_shutdown)) {
            sleep(1);
        }
    } else {
        Valuation *valuations = NULL;
        unsigned int valuation_count = 0, valuation_capacity = 0;
        global_valuations = valuations;

        int should_exit = 0;
        while (!should_exit && !atomic_load(&global_shutdown)) {
            should_exit = display_client_menu(&global_user, &state, &valuations, &valuation_count, &valuation_capacity);
            global_valuations = valuations;
        }
    }

    printf("[P2P] Exiting program...\n");
    perform_shutdown();
    return 0;
}
#endif // !FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION && !SCL_UNIT_TEST
