/**
 * @file common/network/websocket_bridge.c
 * @brief Satocialist Protocol: Local TCP WebSocket-to-UDP Bridge Server Implementation
 *
 * @details
 * Implements the bidirectional bridge server connecting browser-based clients (Auditor Viewport,
 * Blockchain Explorer) to the native SCL node daemon over a local TCP loopback port (default: 5554).
 *
 * Architectural Workflow:
 * 1. Accepts incoming TCP client connections on the configured WebSocket port.
 * 2. Enforces optional HTTP 402 Payment Required gating for automated agent requests, then executes RFC 6455
 *    HTTP upgrade handshakes via SHA-1 and Base64 `Sec-WebSocket-Accept` computation.
 * 3. Spawns a dedicated client handler thread configured with an 8 MiB execution stack to accommodate
 *    heavy post-quantum cryptographic proof verifications.
 * 4. Demultiplexes binary WebSocket frames (opcode 0x02) and unmasks payloads.
 * 5. Direct Local RPC Dispatch: Intercepts native L5 RPC frames (`SCL_RPC_VERSION_1`, methods 0x0001 through 0x000C)
 *    and evaluates them locally without passing through UDP network serialization.
 * 6. UDP Loopback Proxying: Forwards raw P2P datagrams between the browser and local UDP daemon.
 *
 * @section protocol_invariants System Invariants
 * - RFC 6455 Compliance: Handshake and frame headers strictly adhere to RFC 6455 binary framing rules.
 * - Localhost Isolation: The bridge binds to the local interface and does not emit telemetry or credentials
 *   outside of the local system boundary.
 * - Decompression Safety: Payloads flagged with `SCL_RPC_FLAG_COMPRESSED` are bounded by @ref MAX_MESSAGE_SIZE (8 MiB).
 *
 * @section concurrency_model Threading & Concurrency
 * - `websocket_bridge_server`: Runs as an isolated background thread spawned during daemon bootstrap.
 * - Client Threads: Each accepted TCP socket is serviced by a detached thread (`ws_client_handler`)
 *   polling across both TCP and ephemeral UDP loopback descriptors using non-blocking I/O.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifndef _WIN32
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define SCL_CLOSE_SOCKET(fd) close(fd)
#define SCL_WRITE_SOCKET(fd, buf, len) write(fd, buf, len)
#define SCL_READ_SOCKET(fd, buf, len) read(fd, buf, len)
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define poll(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)
#define SCL_CLOSE_SOCKET(fd) closesocket(fd)
#define SCL_WRITE_SOCKET(fd, buf, len) send(fd, (const char *)(buf), (int)(len), 0)
#define SCL_READ_SOCKET(fd, buf, len) recv(fd, (char *)(buf), (int)(len), 0)
#endif
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <lz4.h>
#include "websocket_bridge.h"
#include "constants.h"
#include "utils.h"
#include "user.h"
#include "game_state.h"

extern User *global_user;
#include "blockchain.h"
#include "hash_table.h"
#include "protocol.h"
#include "crypto.h"
#include "network.h"
#include "database.h"
#include "quantum_tvd.h"
#include "rpc.h"

/** @brief RFC 6455 WebSocket handshake GUID salt string. */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
/** @brief Preallocated receive buffer size for HTTP upgrade headers. */
#define WS_HANDSHAKE_BUFFER_SIZE 2048
/** @brief Default loopback TCP port for browser WebSocket connections. */
#define WS_BRIDGE_TCP_PORT 5554

/**
 * @struct WsClientContext
 * @brief Context data passed to individual client worker threads.
 */
typedef struct {
    int tcp_fd;                         /** Connected TCP client socket descriptor. */
    State *state;                       /** Pointer to global ledger state container. */
    struct sockaddr_storage client_addr;/** Client socket address (IPv4 or IPv6). */
} WsClientContext;

/* ============================================================================ */
/* SECTION 1: RFC 6455 HANDSHAKE & UTILITY ROUTINES                             */
/* ============================================================================ */

/**
 * @brief Reliably writes a full buffer to a non-blocking TCP socket, handling partial writes.
 *
 * @param[in] fd File descriptor of target TCP socket.
 * @param[in] buf Pointer to source data buffer.
 * @param[in] len Total bytes to write.
 * @return Total bytes written on success; -1 on socket error or disconnect.
 *
 * @complexity Time: O(len), Space: O(1).
 */
static ssize_t safe_ws_write(int fd, const uint8_t *buf, size_t len) {
    size_t total_written = 0;
    int stall_retries = 0;
    while (total_written < len) {
        ssize_t written = SCL_WRITE_SOCKET(fd, buf + total_written, len - total_written);
        if (written < 0) {
            // Wait for socket to become writable if write buffer is temporarily full
#ifndef _WIN32
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Bound the retry: a browser client that stops reading must not
                 * pin this thread - and the bc.rwlock held by the GetBlock
                 * streamer - forever. ~10s ceiling, then drop the client. */
                if (++stall_retries > 100) return -1;
                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                poll(&pfd, 1, 100);
                if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
                continue;
            }
#else
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                poll(&pfd, 1, 100);
                continue;
            }
#endif
            return -1;
        }
        if (written == 0) return -1;
        total_written += written;
    }
    return (ssize_t)total_written;
}

/**
 * @brief Base64 encodes a binary buffer using OpenSSL EVP interfaces.
 *
 * @param[in] in Source binary data buffer.
 * @param[in] in_len Length of source data in bytes.
 * @param[out] out Destination buffer receiving null-terminated Base64 string.
 * @param[in] out_max Maximum writable capacity of `out`.
 * @return 0 on success; -1 on buffer overflow or encoding failure.
 *
 * @complexity Time: O(in_len), Space: O(1) auxiliary.
 */
static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max) {
    int ret = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
    return (ret >= 0 && (size_t)ret < out_max) ? 0 : -1;
}

/**
 * @brief Computes single-shot SHA-1 digest required by RFC 6455 handshake protocol.
 *
 * @param[in] in Source byte buffer.
 * @param[in] in_len Length of source data in bytes.
 * @param[out] out 20-byte destination buffer receiving the SHA-1 digest.
 *
 * @complexity Time: O(in_len), Space: O(1).
 */
static void sha1_hash(const uint8_t *in, size_t in_len, uint8_t *out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx) {
        EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
        EVP_DigestUpdate(mdctx, in, in_len);
        unsigned int len = 20;
        EVP_DigestFinal_ex(mdctx, out, &len);
        EVP_MD_CTX_free(mdctx);
    }
}

/**
 * @brief Parses an HTTP Upgrade request and transmits the RFC 6455 Switching Protocols response.
 *
 * @details
 * Extracts `Sec-WebSocket-Key`, concatenates the standard GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`,
 * computes SHA-1, Base64 encodes the result to derive `Sec-WebSocket-Accept`, and sends HTTP 101.
 *
 * @param[in] fd Client socket file descriptor.
 * @param[in] req_buf Buffer containing raw HTTP upgrade request text.
 * @param[in] req_len Length of HTTP request text in bytes.
 * @return 0 on successful handshake; -1 on missing key, malformed request, or write error.
 *
 * @complexity Time: O(req_len), Space: O(1) stack buffers.
 */
static int perform_handshake(State *state, int fd, char *req_buf, size_t req_len) {
    /* H-2 fix: Origin allowlist + mandatory SCL402 bearer token on public deployments.
     * Loopback deployments (the default bind after this patch) keep working for local
     * tooling; public deployments (SCL_BRIDGE_BIND_PUBLIC=1) must present a token that
     * matches SCL_BRIDGE_AUTH_TOKEN via 'Authorization: SCL402 <token>' or as the
     * second Sec-WebSocket-Protocol subprotocol entry (browsers cannot set custom
     * headers on WebSocket upgrades). */
    const char *public_env = getenv("SCL_BRIDGE_BIND_PUBLIC");
    bool is_public = (public_env != NULL && strcmp(public_env, "1") == 0);
    const char *auth_token = getenv("SCL_BRIDGE_AUTH_TOKEN");

    /* Cross-site WebSocket hijacking gate: browsers always send Origin on upgrades.
     * Absent Origin (native clients) is allowed; present-but-unknown Origin is not. */
    const char *origin_header = strstr(req_buf, "Origin:");
    if (!origin_header) origin_header = strstr(req_buf, "origin:");
    if (origin_header && is_public) {
        char origin_val[256];
        const char *ov = origin_header + 7;
        while (*ov == ' ' || *ov == '\t') ov++;
        const char *oe = ov;
        while (*oe && *oe != '\r' && *oe != '\n') oe++;
        while (oe > ov && (*(oe - 1) == ' ' || *(oe - 1) == '\t')) oe--;
        size_t o_len = (size_t)(oe - ov);
        if (o_len >= sizeof(origin_val)) o_len = sizeof(origin_val) - 1;
        memcpy(origin_val, ov, o_len);
        origin_val[o_len] = '\0';

        char allowlist[512];
        const char *allowed = getenv("SCL_BRIDGE_ALLOWED_ORIGINS");
        if (allowed && allowed[0] != '\0') {
            snprintf(allowlist, sizeof(allowlist), "%s", allowed);
        } else {
            snprintf(allowlist, sizeof(allowlist),
                     "https://centinel.network,https://explore.centinel.network,http://localhost,http://127.0.0.1");
        }

        bool origin_ok = false;
        char *save = NULL;
        for (char *tok = strtok_r(allowlist, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
            while (*tok == ' ' || *tok == '\t') tok++;
            if (strcmp(origin_val, tok) == 0) { origin_ok = true; break; }
        }
        if (!origin_ok) {
            char response[512];
            int resp_len = snprintf(response, sizeof(response),
                                    "HTTP/1.1 403 Forbidden\r\n"
                                    "Content-Type: text/plain\r\n"
                                    "Connection: close\r\n\r\n"
                                    "Origin not allowed\r\n");
            safe_ws_write(fd, (const uint8_t *)response, resp_len);
            return -1;
        }
    }

    /* Extract the presented SCL402 token from the Authorization header or the
     * Sec-WebSocket-Protocol subprotocol list, then compare in constant time. */
    char supplied[256];
    supplied[0] = '\0';
    const char *auth_header = strstr(req_buf, "Authorization: SCL402 ");
    if (!auth_header) auth_header = strstr(req_buf, "authorization: scl402 ");
    if (auth_header) {
        const char *tv = auth_header + 21;
        while (*tv == ' ' || *tv == '\t') tv++;
        const char *te = tv;
        while (*te && *te != '\r' && *te != '\n') te++;
        size_t t_len = (size_t)(te - tv);
        if (t_len >= sizeof(supplied)) t_len = sizeof(supplied) - 1;
        memcpy(supplied, tv, t_len);
        supplied[t_len] = '\0';
    } else {
        const char *subproto = strstr(req_buf, "Sec-WebSocket-Protocol:");
        if (!subproto) subproto = strstr(req_buf, "sec-websocket-protocol:");
        if (subproto) {
            const char *line_end = subproto;
            while (*line_end && *line_end != '\r' && *line_end != '\n') line_end++;
            const char *comma = memchr(subproto, ',', (size_t)(line_end - subproto));
            if (comma) {
                const char *tv = comma + 1;
                while (*tv == ' ' || *tv == '\t') tv++;
                const char *te = tv;
                while (*te && *te != '\r' && *te != '\n') te++;
                size_t t_len = (size_t)(te - tv);
                if (t_len >= sizeof(supplied)) t_len = sizeof(supplied) - 1;
                memcpy(supplied, tv, t_len);
                supplied[t_len] = '\0';
            }
        }
    }

    if (is_public) {
        if (!auth_token || auth_token[0] == '\0') {
            char response[512];
            int resp_len = snprintf(response, sizeof(response),
                                    "HTTP/1.1 403 Forbidden\r\n"
                                    "Content-Type: text/plain\r\n"
                                    "Connection: close\r\n\r\n"
                                    "Bridge misconfigured\r\n");
            safe_ws_write(fd, (const uint8_t *)response, resp_len);
            return -1;
        }
        size_t tok_len = strlen(auth_token);
        size_t sup_len = strlen(supplied);
        unsigned diff = 0;
        for (size_t k = 0; k < tok_len && k < sup_len; k++) {
            diff |= (unsigned char)auth_token[k] ^ (unsigned char)supplied[k];
        }
        if (supplied[0] == '\0' || tok_len != sup_len || diff != 0) {
            char challenge_json[512];
            uint8_t node_address[USER_ID_LEN];

            pthread_mutex_lock(&state->wallet_mutex);
            SHA256(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, node_address);
            pthread_mutex_unlock(&state->wallet_mutex);

            char node_addr_hex[65];
            bytes_to_hex(node_address, USER_ID_LEN, node_addr_hex);

            snprintf(challenge_json, sizeof(challenge_json),
                     "{\"error\":\"Payment Required\",\"cost_subunits\":160000000,"
                     "\"recipient\":\"%s\",\"token_type\":\"SCL_CENTINEL_V1\"}",
                     node_addr_hex);

            char response[1024];
            int resp_len = snprintf(response, sizeof(response),
                                    "HTTP/1.1 402 Payment Required\r\n"
                                    "Content-Type: application/json\r\n"
                                    "WWW-Authenticate: SCL402 realm=\"Centinel Node Access\", recipient=\"%s\"\r\n"
                                    "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"
                                    "X-Content-Type-Options: nosniff\r\n"
                                    "X-Frame-Options: DENY\r\n"
                                    "Content-Security-Policy: frame-ancestors 'none'\r\n"
                                    "Referrer-Policy: no-referrer\r\n"
                                    "Content-Length: %zu\r\n"
                                    "Connection: close\r\n\r\n%s",
                                    node_addr_hex, strlen(challenge_json), challenge_json);

            safe_ws_write(fd, (const uint8_t *)response, resp_len);
            return -1; /* Terminate unauthenticated connection */
        }
    }


    // 2. Locate Sec-WebSocket-Key header case-insensitively
    char *key_start = NULL;
    const char *target = "sec-websocket-key:";
    size_t t_len = 18;
    
    if (req_len >= t_len) {
        for (size_t i = 0; i <= req_len - t_len; i++) {
            int match = 1;
            for (size_t j = 0; j < t_len; j++) {
                if (SCL_TOLOWER((unsigned char)req_buf[i+j]) != target[j]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                key_start = req_buf + i;
                break;
            }
        }
    }
    if (!key_start) return -1;

    key_start += t_len;
    while (*key_start == ' ' || *key_start == '\t') key_start++;
    char *key_end = key_start;
    while (*key_end && *key_end != '\r' && *key_end != '\n') key_end++;

    // Trim trailing spaces to prevent SHA-1 corruption
    char *trim_end = key_end;
    while (trim_end > key_start && (*(trim_end - 1) == ' ' || *(trim_end - 1) == '\t')) {
        trim_end--;
    }
    size_t key_len = trim_end - key_start;
    if (key_len == 0 || key_len > 128) return -1;

    // 3. Compute Sec-WebSocket-Accept = Base64(SHA1(Key || WS_GUID))
    char combined[256];
    memcpy(combined, key_start, key_len);
    memcpy(combined + key_len, WS_GUID, 36);
    combined[key_len + 36] = '\0';

    uint8_t sha1_out[20];
    sha1_hash((uint8_t *)combined, key_len + 36, sha1_out);

    char accept_key[64];
    if (base64_encode(sha1_out, 20, accept_key, sizeof(accept_key)) != 0) return -1;

    // 4. Transmit HTTP 101 Switching Protocols response
    /* RFC 6455 §4.2.2: when the client offers Sec-WebSocket-Protocol the server
     * MUST echo exactly one selected subprotocol in its 101 response. Chromium,
     * Edge and Brave abort the connection when a requested subprotocol is not
     * selected (Firefox/Safari tolerate the omission) — the SCL402 bearer token
     * rides as the second offered subprotocol entry, so every Chromium-based
     * visitor was left with a dead pipeline and a silent reconnect loop. */
    const char *offered_proto = strstr(req_buf, "Sec-WebSocket-Protocol:");
    if (!offered_proto) offered_proto = strstr(req_buf, "sec-websocket-protocol:");
    bool echo_subprotocol = (offered_proto != NULL && strstr(offered_proto, "SCL402") != NULL);

    char response[512];
    int resp_len;
    if (echo_subprotocol) {
        resp_len = snprintf(response, sizeof(response),
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: %s\r\n"
                            "Sec-WebSocket-Protocol: SCL402\r\n\r\n", accept_key);
    } else {
        resp_len = snprintf(response, sizeof(response),
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: %s\r\n\r\n", accept_key);
    }

    if (safe_ws_write(fd, (const uint8_t *)response, resp_len) != resp_len) return -1;
    return 0;
}

/* ============================================================================ */
/* SECTION 2: RFC 6455 BINARY FRAME ENCODING & DECODING                         */
/* ============================================================================ */

/**
 * @brief Unmasks and decodes an incoming RFC 6455 WebSocket frame.
 *
 * @details
 * Validates header bounds (supports 7-bit, 16-bit, and 64-bit payload lengths), unmasks payload
 * bytes using the 4-byte client XOR mask key, and outputs total frame bytes consumed.
 *
 * @param[in] in_buf Input buffer containing raw frame bytes.
 * @param[in] in_len Available byte count in `in_buf`.
 * @param[out] out_payload Destination buffer receiving unmasked payload data.
 * @param[out] out_len Destination receiving unmasked payload length in bytes.
 * @param[out] frame_bytes_consumed Destination receiving total wire bytes consumed (header + mask + payload).
 * @return 1 on successful frame decode;
 *         0 if frame is incomplete (more data required from socket);
 *         -1 on frame size violation (> MAX_MESSAGE_SIZE);
 *         -2 if connection close frame (opcode 0x08) is received.
 *
 * @complexity Time: O(payload_len), Space: O(1).
 */
static int ws_decode_frame(uint8_t *in_buf, size_t in_len, uint8_t *out_payload, size_t *out_len, size_t *frame_bytes_consumed, uint8_t *out_opcode) {
    if (in_len < 2) return 0; // Need more data

    uint8_t b0 = in_buf[0];
    uint8_t b1 = in_buf[1];

    uint8_t opcode = b0 & 0x0F;
    if (out_opcode) *out_opcode = opcode;
    bool masked = (b1 & 0x80) != 0;
    uint64_t payload_len = b1 & 0x7F;

    size_t header_offset = 2;

    // Parse extended payload length (16-bit or 64-bit)
    if (payload_len == 126) {
        if (in_len < 4) return 0;
        payload_len = (in_buf[2] << 8) | in_buf[3];
        header_offset += 2;
    } else if (payload_len == 127) {
        if (in_len < 10) return 0;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | in_buf[2 + i];
        }
        header_offset += 8;
    }

    if (payload_len > MAX_MESSAGE_SIZE) return -1; // Protect against memory exhaustion

    // Extract 4-byte client masking key if mask bit is set
    uint8_t mask_key[4] = {0};
    if (masked) {
        if (in_len < header_offset + 4) return 0;
        memcpy(mask_key, in_buf + header_offset, 4);
        header_offset += 4;
    }

    if (in_len < header_offset + payload_len) return 0;

    // Unmask payload bytes using 4-byte repeating XOR mask
    uint8_t *raw_payload = in_buf + header_offset;
    if (masked) {
        for (uint64_t i = 0; i < payload_len; i++) {
            out_payload[i] = raw_payload[i] ^ mask_key[i % 4];
        }
    } else {
        memcpy(out_payload, raw_payload, payload_len);
    }

    *out_len = payload_len;
    *frame_bytes_consumed = header_offset + payload_len;

    // Handle connection close frame
    if (opcode == 0x08) return -2;

    return 1; // Success
}

/**
 * @brief Encapsulates binary data into an unmasked RFC 6455 binary frame (opcode 0x82).
 *
 * @param[in] payload Data payload to encapsulate.
 * @param[in] len Length of payload in bytes.
 * @param[out] out_buf Destination buffer receiving the complete WebSocket frame.
 * @param[in] max_out Maximum writable capacity of `out_buf`.
 * @param[out] out_frame_len Destination receiving total frame length in bytes.
 * @return 0 on success; -1 if `max_out` is insufficient.
 *
 * @complexity Time: O(len), Space: O(1).
 */
static int ws_encode_frame(const uint8_t *payload, size_t len, uint8_t *out_buf, size_t max_out, size_t *out_frame_len) {
    size_t header_len = 2;
    if (len >= 126 && len <= 65535) header_len += 2;
    else if (len > 65535) header_len += 8;

    if (header_len + len > max_out) return -1;

    // Populate unmasked server binary frame header (FIN=1, Opcode=2)
    out_buf[0] = 0x82; // FIN=1, Opcode=2 (Binary Frame)

    if (len < 126) {
        out_buf[1] = (uint8_t)len;
    } else if (len <= 65535) {
        out_buf[1] = 126;
        out_buf[2] = (uint8_t)(len >> 8);
        out_buf[3] = (uint8_t)(len & 0xFF);
    } else {
        out_buf[1] = 127;
        for (int i = 0; i < 8; i++) {
            out_buf[2 + i] = (uint8_t)(len >> (56 - i * 8));
        }
    }

    memcpy(out_buf + header_len, payload, len);
    *out_frame_len = header_len + len;
    return 0;
}

/* ============================================================================ */
/* SECTION 2b: SCL402 IDEMPOTENT SETTLEMENT MEMO                               */
/* ============================================================================ */

/** @brief Cached SubmitTx custodial echo: request id + authoritative identity. */
typedef struct {
    uint64_t request_id;            /** SubmitTx request id of the settlement / anchor intent. */
    uint8_t  op_type;               /** 0x02 = OP_TRANSFER_POINTER settlement, 0x07 = OP_APPLY_DRIFT_CERT anchor. */
    uint8_t  tx_id[COIN_ID_LEN];    /** Authoritative mempool tx id echoed for that request. */
    bool     used;                  /** Slot occupancy flag. */
} SettlementMemoEntry;

/** @brief Ring of recently echoed custodial settlements. The browser
 *  retransmits an unacknowledged SubmitTx intent every 5 s (at-least-once
 *  delivery across the scl-ws-map load balancer / TLS front ends / proxies);
 *  64 entries comfortably span a full 20-attempt retransmission window plus
 *  concurrent browser sessions. */
static SettlementMemoEntry g_settlement_memos[64];
static size_t g_settlement_memo_cursor = 0;
static pthread_mutex_t g_settlement_memo_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Looks up the cached custodial echo for a SubmitTx request id.
 * @param[in] request_id SubmitTx request id from the RPC header.
 * @param[out] op_type Operation discriminator of the memoized echo.
 * @param[out] tx_id Authoritative mempool tx id previously echoed.
 * @return true when this request id was already executed (echo is replayable).
 */
static bool settlement_memo_lookup(uint64_t request_id, uint8_t *op_type, uint8_t *tx_id) {
    bool found = false;
    pthread_mutex_lock(&g_settlement_memo_mutex);
    for (size_t i = 0; i < sizeof(g_settlement_memos) / sizeof(g_settlement_memos[0]); i++) {
        if (g_settlement_memos[i].used && g_settlement_memos[i].request_id == request_id) {
            *op_type = g_settlement_memos[i].op_type;
            memcpy(tx_id, g_settlement_memos[i].tx_id, COIN_ID_LEN);
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&g_settlement_memo_mutex);
    return found;
}

/**
 * @brief Records the authoritative custodial identity produced for a SubmitTx request id.
 * @param[in] request_id SubmitTx request id from the RPC header.
 * @param[in] op_type Operation discriminator (0x02 settlement / 0x07 anchor).
 * @param[in] tx_id Authoritative mempool tx id to re-echo on retransmission.
 */
static void settlement_memo_store(uint64_t request_id, uint8_t op_type, const uint8_t *tx_id) {
    pthread_mutex_lock(&g_settlement_memo_mutex);
    SettlementMemoEntry *slot = &g_settlement_memos[g_settlement_memo_cursor];
    slot->used = true;
    slot->request_id = request_id;
    slot->op_type = op_type;
    memcpy(slot->tx_id, tx_id, COIN_ID_LEN);
    g_settlement_memo_cursor = (g_settlement_memo_cursor + 1) %
                               (sizeof(g_settlement_memos) / sizeof(g_settlement_memos[0]));
    pthread_mutex_unlock(&g_settlement_memo_mutex);
}

/* ============================================================================ */
/* SECTION 3: DIRECT LOCAL RPC DISPATCHING & RESPONSE SYNTHESIS                 */
/* ============================================================================ */

/**
 * @brief Decodes and executes an L5 RPC frame locally, bypassing UDP transport overhead.
 *
 * @details
 * Inbound frames from browser frontends (e.g., GetBalance, GetBlock, SubmitTx, GetAudit)
 * are parsed, decompressed if necessary via LZ4, routed directly through the state engine,
 * packaged into a binary RPC response frame, encoded into an RFC 6455 binary frame,
 * and transmitted back over the client TCP socket.
 *
 * @param[in,out] state Global node state container.
 * @param[in] req_buf Raw binary wire request buffer.
 * @param[in] req_len Total length of request buffer in bytes.
 * @param[in] tcp_fd Client TCP socket descriptor for response writing.
 *
 * @pre `state` non-NULL; `req_len >= 32`.
 * @complexity Time: O(method_execution_time + serialization), Space: O(MAX_MESSAGE_SIZE) heap allocation.
 */
static void handle_local_rpc_request(State *state, const uint8_t *req_buf, size_t req_len, int tcp_fd) {
    if (req_len < 32) return;

    // Safely copy header via memcpy to prevent unaligned memory access UB
    SclRpcHeader hdr_storage;
    memcpy(&hdr_storage, req_buf, sizeof(SclRpcHeader));
    const SclRpcHeader *hdr = &hdr_storage;

    uint16_t method_id = be16toh(hdr->method_id);
    uint16_t err_len = be16toh(hdr->error_msg_len);
    uint32_t payload_len = be32toh(hdr->payload_len);
    uint64_t req_id = be64toh(hdr->request_id);

    if (req_len < 32 + err_len + payload_len) return;
    const uint8_t *payload = req_buf + 32 + err_len;

    uint8_t *decomp_buf = NULL;
    const uint8_t *final_payload = payload;
    uint32_t final_payload_len = payload_len;

    // Decompress inbound LZ4-compressed payload if compression flag is asserted
    if ((hdr->flags & SCL_RPC_FLAG_COMPRESSED) && payload_len > 0) {
        if (payload_len > MAX_MESSAGE_SIZE) {
            return;
        }
        
        size_t sig_len = (hdr->flags & SCL_RPC_FLAG_SIGNED) ? 4595 : 0;
        if (payload_len < sig_len) return;

        decomp_buf = malloc(MAX_MESSAGE_SIZE);
        if (!decomp_buf) return;

        if (sig_len > 0) {
            memcpy(decomp_buf, payload, sig_len);
        }

        const uint8_t *compressed_data = payload + sig_len;
        size_t comp_len = payload_len - sig_len;

        int decomp_bytes = LZ4_decompress_safe((const char *)compressed_data,
                                               (char *)(decomp_buf + sig_len),
                                               (int)comp_len,
                                               (int)(MAX_MESSAGE_SIZE - sig_len));
        if (decomp_bytes < 0 || (size_t)(sig_len + decomp_bytes) > MAX_MESSAGE_SIZE) {
            free(decomp_buf);
            return;
        }

        final_payload = decomp_buf;
        final_payload_len = sig_len + decomp_bytes;
    }

    size_t resp_max = MAX_MESSAGE_SIZE + 4096;
    uint8_t *resp_buf = malloc(resp_max);
    if (!resp_buf) {
        if (decomp_buf) free(decomp_buf);
        return;
    }

    // Initialize 32-byte binary response header
    memset(resp_buf, 0, 32);
    SclRpcHeader *rh = (SclRpcHeader *)resp_buf;
    rh->version = SCL_RPC_VERSION_1;
    rh->status_code = htobe16(SCL_RPC_STATUS_OK);
    rh->method_id = htobe16(method_id);
    rh->request_id = htobe64(req_id);

    size_t actual_payload_len = 0;

    /* ------------------------------------------------------------------
     * SCL402 (receipt strip): Payment Receipt Extraction & Verification.
     * Mirror rpc.c. The wasm builder prepends a SclRpcPaymentReceipt
     * (sizeof-tracked, natural-alignment wire layout) ahead of the method
     * args when SCL_RPC_FLAG_PAYMENT_RECEIPT is set; consume and strip it
     * here so handlers parse real arguments at final_payload[0]. Without
     * this the 0x000A handler reads receipt bytes as `shots` -> INVALID_ARGS.
     * ------------------------------------------------------------------ */
    bool payment_verified = false;
    if (hdr->flags & SCL_RPC_FLAG_PAYMENT_RECEIPT) {
        size_t sig_len = (hdr->flags & SCL_RPC_FLAG_SIGNED) ? DILITHIUM_SIGNATURE_LEN : 0;
        size_t receipt_len = sizeof(SclRpcPaymentReceipt);

        if (final_payload_len >= sig_len + receipt_len) {
            SclRpcPaymentReceipt receipt_storage;
            memcpy(&receipt_storage, final_payload + sig_len, receipt_len);

            /* SCL402 challenge binding (mirror of rpc.c): resolve the challenge
             * this receipt claims to settle against the server-side registry
             * (challenge_hash key), then compute the metered method's required
             * amount from the replayed request's own arguments. The effective
             * demand is the MAXIMUM of the issuance-time quote and the
             * replay-derived cost, so cheaper replay args cannot discount the
             * challenged fee while heavier replays still pay their own cost.
             * required == 0 means the method is unmetered for this node (or
             * non-daemon) and existence alone suffices — exactly the legacy
             * behaviour. */
            uint64_t receipt_required_subunits = 0;
            Scl402ChallengeEntry receipt_challenge = {0};
            bool receipt_challenge_live = false;
            if (state->config.is_daemon) {
                /* TTL enforcement (previously unenforced on replay): an unknown
                 * or expired challenge_hash leaves payment_verified false and
                 * the metering gate below re-issues a fresh 402 challenge. */
                receipt_challenge_live = scl402_challenge_resolve(state, receipt_storage.challenge_hash, &receipt_challenge);

                const uint8_t *scl402_args = final_payload + sig_len + receipt_len;
                uint32_t scl402_args_len = final_payload_len - (uint32_t)sig_len - (uint32_t)receipt_len;
                if (method_id == 0x000D) {
                    uint32_t dc_shots = 15000;
                    if (scl402_args_len >= 4) {
                        uint32_t shots_raw;
                        memcpy(&shots_raw, scl402_args, sizeof(uint32_t));
                        dc_shots = be32toh(shots_raw);
                    }
                    receipt_required_subunits = 160000000ULL + 32000000ULL * (((uint64_t)dc_shots + 9999) / 10000);
                } else if (method_id == 0x000A && scl402_args_len > 36) {
                    receipt_required_subunits = 160000000ULL; /* 1 SCL fee (parity with the gate below) */
                }

                if (receipt_challenge_live && receipt_challenge.amount_subunits > receipt_required_subunits) {
                    receipt_required_subunits = receipt_challenge.amount_subunits;
                }
            }

            /* Fee recipient the challenge demanded: SHA-256 of the node wallet's
             * Dilithium5 pubkey (identical formula to the 402 challenge issuer). */
            uint8_t scl402_fee_address[USER_ID_LEN];
            pthread_mutex_lock(&state->wallet_mutex);
            SHA256(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, scl402_fee_address);
            pthread_mutex_unlock(&state->wallet_mutex);

            if (state->config.is_daemon && !receipt_challenge_live) {
                /* Unknown or expired challenge: this receipt settles nothing the
                 * node actually issued within its TTL. Leave payment_verified
                 * false; the metering gate below re-issues a fresh 402 challenge. */
            } else if (receipt_storage.payment_type == 0x02) { // OP_REDEEM_CENTINEL
                /* Private redemption: amount and destination are sealed inside
                 * BDLOP commitments by design, so only nullifier spentness is
                 * enforceable on the transparent RPC surface. */
                pthread_rwlock_rdlock(&state->bc.rwlock);
                if (hash_table_lookup(state->bc.centinel.nullifier_set, receipt_storage.tx_id, true)) payment_verified = true;
                pthread_rwlock_unlock(&state->bc.rwlock);
            } else if (receipt_storage.payment_type == 0x01) { // OP_TRANSFER_POINTER
                /* Bind the receipt: the referenced transfer must have paid at
                 * least the required amount TO the node's fee address. Mempool
                 * first, then — once confirmed — a tip-first bounded block
                 * scan mirroring the GetTransaction pattern (challenges expire
                 * after 5 minutes, so settlements are always recent). */
                pthread_rwlock_rdlock(&state->bc.rwlock);
                bool scl402_confirmed = hash_table_lookup(state->processed_txs, receipt_storage.tx_id, true) != NULL;
                pthread_rwlock_unlock(&state->bc.rwlock);

                if (!scl402_confirmed) {
                    bool scl402_found = false;
                    bool scl402_is_transfer = false;
                    uint64_t scl402_paid_amount = 0;
                    uint8_t scl402_paid_recipient[PUBKEY_LEN];

                    for (int i = 0; i < MAX_PENDING_OPS; i++) {
                        Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                        if (pop) {
                            const uint8_t *tx_id = get_operation_tx_id(pop);
                            if (tx_id && memcmp(tx_id, receipt_storage.tx_id, 32) == 0) {
                                scl402_found = true;
                                scl402_is_transfer = (pop->type == OP_TRANSFER_POINTER);
                                if (scl402_is_transfer) {
                                    scl402_paid_amount = pop->data.transfer_pointer.amount;
                                    memcpy(scl402_paid_recipient, pop->data.transfer_pointer.recipient_pubkey, PUBKEY_LEN);
                                }
                                break;
                            }
                        }
                    }

                    if (scl402_found) {
                        if (receipt_required_subunits == 0) {
                            payment_verified = true; /* Unmetered method: existence suffices */
                        } else if (scl402_is_transfer) {
                            uint8_t paid_address[USER_ID_LEN];
                            SHA256(scl402_paid_recipient, PUBKEY_LEN, paid_address);
                            /* Challenge-authoritative recipient when a live registry
                             * entry exists; wallet-derived address otherwise (legacy
                             * non-daemon parity). */
                            const uint8_t *receipt_required_recipient =
                                receipt_challenge_live ? receipt_challenge.recipient_address : scl402_fee_address;
                            payment_verified = (scl402_paid_amount >= receipt_required_subunits) &&
                                               (memcmp(paid_address, receipt_required_recipient, USER_ID_LEN) == 0);
                        }
                    }
                } else if (receipt_required_subunits == 0) {
                    payment_verified = true; /* Unmetered method: existence suffices */
                } else {
                    pthread_rwlock_rdlock(&state->bc.rwlock);
                    uint64_t scan_limit = state->current_block_number + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
                    if (scan_limit > 16) scan_limit = 16; /* Bounded search depth (parity with rpc.c) */
#endif
                    for (uint64_t b_idx = 0; b_idx < scan_limit && !payment_verified; b_idx++) {
                        uint8_t *ser_block = NULL;
                        size_t ser_len = 0;
                        if (scl_db_get_block(state->current_block_number - b_idx, &ser_block, &ser_len) != 0) continue;

                        Block *blk = calloc(1, sizeof(Block));
                        if (!blk || deserialize_block(blk, ser_block, ser_len) != 0) {
                            if (blk) free_block(blk);
                            free(ser_block);
                            continue;
                        }
                        free(ser_block);

                        for (size_t op_idx = 0; op_idx < blk->operation_count; op_idx++) {
                            const Operation *bop = &blk->operations[op_idx];
                            const uint8_t *op_id = get_operation_tx_id(bop);
                            if (!op_id || memcmp(op_id, receipt_storage.tx_id, COIN_ID_LEN) != 0) continue;
                            if (bop->type == OP_TRANSFER_POINTER) {
                                uint8_t paid_address[USER_ID_LEN];
                                SHA256(bop->data.transfer_pointer.recipient_pubkey, PUBKEY_LEN, paid_address);
                                /* Challenge-authoritative recipient when a live registry
                                 * entry exists; wallet-derived address otherwise (legacy
                                 * non-daemon parity). */
                                const uint8_t *receipt_required_recipient =
                                    receipt_challenge_live ? receipt_challenge.recipient_address : scl402_fee_address;
                                payment_verified = (bop->data.transfer_pointer.amount >= receipt_required_subunits) &&
                                                   (memcmp(paid_address, receipt_required_recipient, USER_ID_LEN) == 0);
                            }
                            break;
                        }
                        free_block(blk);
                    }
                    pthread_rwlock_unlock(&state->bc.rwlock);
                }
            }

            /* Single-use challenges (mirror of rpc.c): a settled receipt
             * consumes the registry entry, so a captured challenge_hash
             * cannot settle a second metered call before TTL expiry.
             * Unsettled attempts keep the entry live — no double-billing. */
            if (payment_verified && receipt_challenge_live) {
                scl402_challenge_consume(state, receipt_storage.challenge_hash);
            }

            final_payload += sig_len + receipt_len;
            final_payload_len -= (uint32_t)(sig_len + receipt_len);
        }
    }

    /* First-time signed metered frames (0x000A/0x000B/0x000D): the wasm
     * builder prepends the ML-DSA-87 signature at payload[0], so true method
     * args begin at final_payload + sig_len. Replay frames already advanced
     * past sig + receipt above. Stripping globally would break SubmitTx
     * (0x0003), whose handler consumes the signature in place at
     * final_payload[0] — so the offset is applied to the metered methods
     * only, mirroring rpc.c's per-handler sig alignment. */
    if ((hdr->flags & SCL_RPC_FLAG_SIGNED) && !(hdr->flags & SCL_RPC_FLAG_PAYMENT_RECEIPT) &&
        (method_id == 0x000A || method_id == 0x000B || method_id == 0x000D)) {
        if (final_payload_len < DILITHIUM_SIGNATURE_LEN) {
            free(resp_buf);
            if (decomp_buf) free(decomp_buf);
            return;
        }
        final_payload += DILITHIUM_SIGNATURE_LEN;
        final_payload_len -= DILITHIUM_SIGNATURE_LEN;
    }

    /* SCL402 scope fix: meter only client-supplied OpenQASM circuits
     * (final_payload_len > 36, the handler's own circuit_bytes detection).
     * The default 7-qubit telemetry audit (~1-2 ms local qsim) feeds the
     * explorer's "Quantum TVD Audit & Noise-Model Fidelity" panel; every
     * other telemetry method is unmetered, and gating this one left the
     * panel stuck on "Awaiting Telemetry" because auto-settlement needs
     * liquid SCL the fresh testnet identity wallet does not hold.
     * Enterprise drift-certificate audits (0x000D) always carry a
     * client-supplied QPU histogram and are therefore always metered,
     * mirroring the rpc.c P2P gate exactly: 1 SCL base + 0.2 SCL per
     * commenced 10,000 shots. */
    bool tvd_custom_circuit = (final_payload_len > 36);
    uint64_t scl402_required_subunits = 0;
    if (!payment_verified && state->config.is_daemon) {
        if (method_id == 0x000D) {
            uint32_t dc_shots = 15000;
            if (final_payload_len >= 4) {
                uint32_t shots_raw;
                memcpy(&shots_raw, final_payload, sizeof(uint32_t));
                dc_shots = be32toh(shots_raw);
            }
            scl402_required_subunits = 160000000ULL + 32000000ULL * (((uint64_t)dc_shots + 9999) / 10000);
        } else if (method_id == 0x000A && tvd_custom_circuit) {
            scl402_required_subunits = 160000000ULL; /* 1 SCL fee (parity with rpc.c:1330) */
        }
    }
    if (scl402_required_subunits > 0) {
        rh->status_code = htobe16(SCL_RPC_STATUS_PAYMENT_REQUIRED);

        SclRpcPaymentChallenge *challenge = (SclRpcPaymentChallenge *)(resp_buf + 32);
        memset(challenge, 0, sizeof(SclRpcPaymentChallenge));
        challenge->amount_subunits = htobe64(scl402_required_subunits);
        challenge->price_rate_lock_id = htobe64(get_time_us());

        pthread_mutex_lock(&state->wallet_mutex);
        SHA256(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, challenge->recipient_address);
        pthread_mutex_unlock(&state->wallet_mutex);

        /* challenge_hash = SHA256(request_id || method_id || salt) */
        uint8_t seed_buf[18];
        uint64_t req_be = htobe64(req_id);
        uint16_t meth_be = htobe16(method_id);
        memcpy(seed_buf, &req_be, 8);
        memcpy(seed_buf + 8, &meth_be, 2);
        uint64_t salt = get_real_time_us();
        memcpy(seed_buf + 10, &salt, 8);
        SHA256(seed_buf, sizeof(seed_buf), challenge->challenge_hash);

        uint64_t valid_until_ms = get_time_ms() + SCL402_CHALLENGE_TTL_MS; /* 5-minute TTL */
        challenge->valid_until_timestamp = htobe64(valid_until_ms);
        challenge->accepted_payment_types = htobe16(0x0003); /* Transfer (0x01) + Centinel (0x02) */

        /* Server-side challenge registry (mirror of rpc.c): remember what this
         * node actually issued (amount, recipient, expiry) keyed by
         * challenge_hash, so replay-side verification above can enforce the
         * challenge TTL and bind settlements to the issuance-time quote. */
        scl402_challenge_register(state, challenge->challenge_hash, scl402_required_subunits,
                                  challenge->recipient_address, valid_until_ms);

        rh->payload_len = htobe32((uint32_t)sizeof(SclRpcPaymentChallenge));
        size_t challenge_resp_len = 32 + sizeof(SclRpcPaymentChallenge);

        size_t ws_max402 = challenge_resp_len + 16;
        uint8_t *ws_buf402 = malloc(ws_max402);
        if (ws_buf402) {
            size_t ws_frame_len402 = 0;
            if (ws_encode_frame(resp_buf, challenge_resp_len, ws_buf402, ws_max402, &ws_frame_len402) == 0) {
                safe_ws_write(tcp_fd, ws_buf402, ws_frame_len402);
            }
            free(ws_buf402);
        }
        free(resp_buf);
        if (decomp_buf) free(decomp_buf);
        return;
    }

    // Dispatch local method execution by opcode
    switch (method_id) {
        case 0x0001: { // GetBalance
            if (final_payload_len == PUBKEY_LEN) {
                uint8_t target_pk[PUBKEY_LEN];
                memcpy(target_pk, final_payload, PUBKEY_LEN);
                
                // Calculate liquid, staked, and cumulative fee balances
                uint64_t balance = calculate_balance_subunits(&state->bc, target_pk, false);
                uint64_t staked_balance = calculate_staked_subunits_by_owner(state, target_pk);
                uint64_t fees_paid = calculate_fees_paid_subunits(&state->bc, target_pk);
                
                uint64_t utxo_validations = 0;
                size_t u_idx = 0;
                
                pthread_rwlock_rdlock(&state->bc.rwlock);
                pthread_mutex_lock(&state->user_wallet.utxo_mutex);

                uint8_t *utxo_payload = NULL;
                if (state->user_wallet.num_val_utxos > 0) {
                    utxo_payload = malloc(state->user_wallet.num_val_utxos * 72);
                }

                // Enumerate active unspent Centinel validation UTXOs
                for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
                    ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
                    if (memcmp(utxo->pubkey, target_pk, PUBKEY_LEN) != 0) continue;
                    
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
                            utxo_validations += utxo->amount;
                            if (utxo_payload) {
                                memcpy(utxo_payload + u_idx * 72, utxo->nullifier, 32);
                                uint64_t amt_be = htobe64(utxo->amount);
                                memcpy(utxo_payload + u_idx * 72 + 32, &amt_be, 8);
                                memcpy(utxo_payload + u_idx * 72 + 40, utxo->blinding_factor, 32);
                                u_idx++;
                            }
                        }
                    }
                }
                /* R-index allocation fix: report the wallet-global tag
                 * high-water mark (num_val_utxos), not the active count
                 * (u_idx). Blinding-factor tags are allocated sequentially
                 * from state->user_wallet.num_val_utxos by grant_validation()
                 * and consume_utxos_for_amount(), and the auditor worker marks
                 * r-indices [0, numValUtxos) as consumed before choosing the
                 * next free index for redemption outputs. Reporting u_idx
                 * undercounts (spent UTXOs and the C-1 testnet-identity
                 * mirror UTXOs are excluded), so the worker re-used indices
                 * whose derived commitments/nullifiers were already spent or
                 * mirrored — redemption outputs were born spent or duplicate,
                 * and 'Audited UTXO Validations' never updated after a
                 * successful redeem. */
                uint64_t num_val_utxos = (uint64_t)state->user_wallet.num_val_utxos;

                uint8_t user_id[USER_ID_LEN];
                SHA256(target_pk, PUBKEY_LEN, user_id);

                uint8_t local_threshold_addr[USER_ID_LEN] = {0};
                uint8_t local_threshold_pk[PUBKEY_LEN];
                bool has_local_threshold = false;
                if (memcmp(target_pk, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                    if (compute_threshold_pubkey(state, local_threshold_pk) == 0) {
                        SHA256(local_threshold_pk, PUBKEY_LEN, local_threshold_addr);
                        has_local_threshold = true;
                    }
                }

                // Collect native unspent SCL pointers for the user (including fee pointers spent == 2)
                Pointer *native_ptrs = malloc(1024 * sizeof(Pointer));
                size_t native_count = 0;
                for (size_t i = 0; i < state->bc.pointer_table->size; i++) {
                    GenericHashEntry *entry = state->bc.pointer_table->buckets[i];
                    while (entry && native_count < 1024) {
                        if (entry->type == HASH_ENTRY_POINTER && entry->data.pointer.spent != 1) {
                            Pointer *ptr = &entry->data.pointer;
                            bool belongs_to_user = false;
                            if (memcmp(ptr->owner_address, user_id, USER_ID_LEN) == 0) {
                                belongs_to_user = true;
                            } else if (ptr->staked) {
                                if (has_local_threshold && memcmp(ptr->owner_address, local_threshold_addr, USER_ID_LEN) == 0) {
                                    belongs_to_user = true;
                                } else {
                                    PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, ptr->owner_address, false);
                                    if (cache_entry && memcmp(cache_entry->pubkey, target_pk, PUBKEY_LEN) == 0) {
                                        belongs_to_user = true;
                                    }
                                }
                            }
                            if (belongs_to_user) {
                                native_ptrs[native_count++] = *ptr;
                            }
                        }
                        entry = entry->next;
                    }
                }

                pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
                pthread_rwlock_unlock(&state->bc.rwlock);

                // Pack balance response fields into binary output buffer
                uint64_t balance_be = htobe64(balance);
                uint64_t staked_be = htobe64(staked_balance);
                uint64_t fees_be = htobe64(fees_paid);
                uint64_t utxo_be = htobe64(utxo_validations);
                uint64_t num_utxos_be = htobe64(num_val_utxos);
                
                memcpy(resp_buf + 32, &balance_be, 8);
                memcpy(resp_buf + 32 + 8, &staked_be, 8);
                memcpy(resp_buf + 32 + 16, &fees_be, 8);
                memcpy(resp_buf + 32 + 24, &utxo_be, 8);
                memcpy(resp_buf + 32 + 32, &num_utxos_be, 8);
                
                size_t offset = 40;
                if (utxo_payload && u_idx > 0) {
                    memcpy(resp_buf + 32 + offset, utxo_payload, u_idx * 72);
                    offset += (u_idx * 72);
                }
                if (utxo_payload) free(utxo_payload);

                uint32_t native_count_be = htobe32((uint32_t)native_count);
                memcpy(resp_buf + 32 + offset, &native_count_be, 4);
                offset += 4;

                for (size_t i = 0; i < native_count; i++) {
                    memcpy(resp_buf + 32 + offset, native_ptrs[i].pointer_id, 32); offset += 32;
                    memcpy(resp_buf + 32 + offset, native_ptrs[i].parent_coin_id, 32); offset += 32;
                    uint64_t start_be = htobe64(native_ptrs[i].start_subunit);
                    memcpy(resp_buf + 32 + offset, &start_be, 8); offset += 8;
                    uint64_t end_be = htobe64(native_ptrs[i].end_subunit);
                    memcpy(resp_buf + 32 + offset, &end_be, 8); offset += 8;
                    memcpy(resp_buf + 32 + offset, native_ptrs[i].owner_address, 32); offset += 32;
                    memcpy(resp_buf + 32 + offset, native_ptrs[i].prev_tx_hash, 32); offset += 32;
                    uint8_t status_flag = (native_ptrs[i].spent == 2) ? 2 : (native_ptrs[i].staked ? 1 : 0);
                    memcpy(resp_buf + 32 + offset, &status_flag, 1); offset += 1;
                }
                free(native_ptrs);

                actual_payload_len = offset;
            } else {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
            }
            break;
        }
        case 0x0002: { // GetBlock
            uint32_t start_height = be32toh(hdr->cursor);
            pthread_rwlock_rdlock(&state->bc.rwlock);
            
            size_t streamed_count = 0;
            size_t block_resp_max = MAX_MESSAGE_SIZE + 4096;
            uint8_t *block_resp_buf = malloc(block_resp_max);
            if (!block_resp_buf) {
                pthread_rwlock_unlock(&state->bc.rwlock);
                free(resp_buf);
                if (decomp_buf) free(decomp_buf);
                return;
            }

            // Stream sequential blocks up to pagination range
            uint64_t end_height = state->current_block_number;
            for (uint64_t i = start_height; i <= end_height && streamed_count < MAX_PAGINATION_RANGE; i++) {
                uint8_t *ser_block = NULL;
                size_t ser_len = 0;
                if (scl_db_get_block(i, &ser_block, &ser_len) != 0) continue;
                
                Block *b = calloc(1, sizeof(Block));
                if (!b || deserialize_block(b, ser_block, ser_len) != 0) {
                    if (b) free_block(b);
                    free(ser_block);
                    continue;
                }
                free(ser_block);

                if (b->block_number >= start_height) {
                    
                    memset(block_resp_buf, 0, 32);
                    SclRpcHeader *rh = (SclRpcHeader *)block_resp_buf;
                    rh->version = SCL_RPC_VERSION_1;
                    rh->status_code = htobe16(SCL_RPC_STATUS_OK);
                    rh->method_id = htobe16(method_id);
                    rh->request_id = htobe64(req_id);
                    rh->cursor = htobe32((uint32_t)b->block_number);
                    
                    int offset = process_block_data(b, block_resp_buf + 32, NULL, true);
                    if (offset > 0) {
                        actual_payload_len = offset;
                        
                        if ((hdr->flags & SCL_RPC_FLAG_COMPRESSED) && actual_payload_len > 0) {
                            int max_comp_size = LZ4_compressBound((int)actual_payload_len);
                            uint8_t *comp_buf = malloc(max_comp_size);
                            if (comp_buf) {
                                int comp_bytes = LZ4_compress_default((const char*)(block_resp_buf + 32), (char*)comp_buf, (int)actual_payload_len, max_comp_size);
                                if (comp_bytes > 0 && comp_bytes < (int)actual_payload_len) {
                                    memcpy(block_resp_buf + 32, comp_buf, comp_bytes);
                                    actual_payload_len = comp_bytes;
                                    rh->flags |= SCL_RPC_FLAG_COMPRESSED;
                                }
                                free(comp_buf);
                            }
                        }
                        
                        rh->payload_len = htobe32((uint32_t)actual_payload_len);
                        size_t total_resp_len = 32 + actual_payload_len;

                        size_t ws_max = total_resp_len + 16;
                        uint8_t *ws_buf = malloc(ws_max);
                        if (ws_buf) {
                            size_t ws_frame_len = 0;
                            if (ws_encode_frame(block_resp_buf, total_resp_len, ws_buf, ws_max, &ws_frame_len) == 0) {
                                if (safe_ws_write(tcp_fd, ws_buf, ws_frame_len) < 0) {
                                    free(ws_buf);
                                    free(block_resp_buf);
                                    pthread_rwlock_unlock(&state->bc.rwlock);
                                    free(resp_buf);
                                    if (decomp_buf) free(decomp_buf);
                                    return; /* release the chain read lock immediately on a stalled client */
                                }
                            }
                            free(ws_buf);
                        }
                        streamed_count++;
                    }
                }
                free_block(b);
            }
            free(block_resp_buf);
            pthread_rwlock_unlock(&state->bc.rwlock);
            
            if (streamed_count == 0) {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                const char *err_msg = "No blocks found in range";
                size_t err_len = strlen(err_msg) + 1;
                rh->error_msg_len = htobe16((uint16_t)err_len);
                memcpy(resp_buf + 32, err_msg, err_len);
                actual_payload_len = err_len;
                break;
            } else {
                free(resp_buf); // Free the outer buffer to prevent memory leaks on early return
                if (decomp_buf) free(decomp_buf);
                return;
            }
        }
        case 0x0003: { // SubmitTx
            if (hdr->flags & SCL_RPC_FLAG_SIGNED) {
                if (final_payload_len < SIGNATURE_LEN + 1) {
                    rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                    break;
                }
                const uint8_t *sig = final_payload;
                const uint8_t *op_data = sig + SIGNATURE_LEN;
                size_t op_len = final_payload_len - SIGNATURE_LEN;
                
                Operation *op = calloc(1, sizeof(Operation));
                if (op) {
                    int consumed = deserialize_operation(op_data, op_len, op, 1);
                    if (consumed > 0) {
                        op->is_rpc_injected = true;
                        
                        const uint8_t *auth_pubkey = NULL;
                        if (op->type == OP_TRANSFER_POINTER) auth_pubkey = op->data.transfer_pointer.sender_pubkey;
                        else if (op->type == OP_STAKE) auth_pubkey = op->data.stake.sender_pubkey;
                        else if (op->type == OP_UNSTAKE) auth_pubkey = op->data.unstake.recipient_pubkey;
                        else if (op->type == OP_MINT_COIN) auth_pubkey = op->data.mint_coin.owner_pubkey;
                        else if (op->type == OP_SUBMIT_VALUATION) auth_pubkey = op->data.submit_valuation.pubkey;
                        else if (op->type == OP_CLAIM_VALIDATION) auth_pubkey = op->data.claim_validation.pubkey;
                        else if (op->type == OP_APPLY_DRIFT_CERT) auth_pubkey = op->data.apply_drift_cert.sender_pubkey;
                        else if (op->type == OP_REDEEM_CENTINEL) auth_pubkey = state->user_wallet.dilithium_pubkey;

                        if (auth_pubkey) {
                            size_t digest_mark = arena_mark();
                            uint8_t *digest_input = arena_alloc(24 + op_len);
                            if (digest_input) {
                                // Authenticate ML-DSA-87 signature over 24-byte header prefix + operation data
                                memset(digest_input, 0, 24 + op_len);
                                memcpy(digest_input, req_buf, 24);
                                SclRpcHeader *verify_hdr = (SclRpcHeader *)digest_input;
                                verify_hdr->status_code = htobe16(0);
                                verify_hdr->error_msg_len = htobe16(0);
                                memcpy(digest_input + 24, op_data, op_len);
                                
                                int verify_res = dilithium_verify(digest_input, 24 + op_len, sig, auth_pubkey);
                                if (verify_res != 0 && op->type == OP_REDEEM_CENTINEL) {
                                    if (zk_centinel_verify(&op->data.redeem_centinel) == CRYPTO_SUCCESS) {
                                        verify_res = 0;
                                    } else {
                                        for (size_t u_idx = 0; u_idx < state->user_count; u_idx++) {
                                            if (dilithium_verify(digest_input, 24 + op_len, sig, state->users[u_idx].dilithium_pubkey) == 0) {
                                                verify_res = 0;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if (verify_res != 0) {
                                    rh->status_code = htobe16(SCL_RPC_STATUS_UNAUTHORIZED);
                                    const char *err_msg = "Invalid RPC signature";
                                    size_t err_len = strlen(err_msg) + 1;
                                    rh->error_msg_len = htobe16((uint16_t)err_len);
                                    memcpy(resp_buf + 32, err_msg, err_len);
                                    actual_payload_len = err_len;
                                    free(op);
                                    arena_reset(digest_mark);
                                    break;
                                }
                                arena_reset(digest_mark);
                            } else {
                                rh->status_code = htobe16(SCL_RPC_STATUS_RATE_LIMITED);
                                const char *err_msg = "Arena allocation failed";
                                size_t err_len = strlen(err_msg) + 1;
                                rh->error_msg_len = htobe16((uint16_t)err_len);
                                memcpy(resp_buf + 32, err_msg, err_len);
                                actual_payload_len = err_len;
                                free(op);
                                break;
                            }
                        } else {
                            rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                            const char *err_msg = "Operation lacks auth pubkey";
                            size_t err_len = strlen(err_msg) + 1;
                            rh->error_msg_len = htobe16((uint16_t)err_len);
                            memcpy(resp_buf + 32, err_msg, err_len);
                            actual_payload_len = err_len;
                            free(op);
                            break;
                        }

                        if (op->type == OP_TRANSFER_POINTER) {
                            /* Idempotent retransmission (SCL402 at-least-once
                             * delivery): the browser re-sends the identical
                             * SubmitTx intent every 5 s until the settlement
                             * echo arrives, because the scl-ws-map load balancer
                             * / TLS front ends / proxies can silently drop the
                             * frame in transit. If this request id already
                             * executed, replay the cached authoritative tx id
                             * instead of running the custodial transfer a second
                             * time — one settlement, billed exactly once. */
                            uint8_t memo_op_type = 0;
                            uint8_t memo_tx_id[COIN_ID_LEN];
                            if (settlement_memo_lookup(req_id, &memo_op_type, memo_tx_id) && memo_op_type == 0x02) {
                                resp_buf[32] = 0x02;
                                memcpy(resp_buf + 33, memo_tx_id, COIN_ID_LEN);
                                actual_payload_len = 1 + COIN_ID_LEN;
                                free(op);
                                break;
                            }

                            UserWallet funding_snapshot;
                            const UserWallet *funding_wallet = &state->user_wallet;

                            pthread_mutex_lock(&state->wallet_mutex);
                            if (memcmp(op->data.transfer_pointer.sender_pubkey,
                                       state->testnet_identity_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
                                funding_snapshot = state->testnet_identity_wallet;
                                funding_wallet = &funding_snapshot;
                            }
                            pthread_mutex_unlock(&state->wallet_mutex);

                            uint8_t settled_tx_id[COIN_ID_LEN];
                            int added = create_and_broadcast_transfer_as(state, funding_wallet,
                                        op->data.transfer_pointer.recipient_pubkey,
                                        op->data.transfer_pointer.amount, false,
                                        NULL, 0, NULL, settled_tx_id);
                            if (added == 0) {
                                /* Echo only the authoritative settlement identity —
                                 * [0x02 OP_TRANSFER_POINTER][32-byte mempool tx id] —
                                 * never the full ~425 KB serialized operation. The
                                 * client's SCL402 receipt needs the tx id alone, and
                                 * full-op echoes push 400 KB+ WebSocket frames through
                                 * the scl-ws-map load balancer / TLS front ends, which
                                 * can silently drop them and stall the replay at
                                 * "Settling autonomously..." forever. 33 bytes
                                 * satisfies the WASM client's 0x0003 parser exactly
                                 * (payload[0] = op type, tx id at bytes 1..33). */
                                resp_buf[32] = 0x02;
                                memcpy(resp_buf + 33, settled_tx_id, COIN_ID_LEN);
                                actual_payload_len = 1 + COIN_ID_LEN;
                                settlement_memo_store(req_id, 0x02, settled_tx_id);
                            } else if (added == 2) {
                                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                                const char *err_msg = "Settlement deferred: the funding wallet's inputs are locked by a pending mempool operation. Retry after the next block.";
                                size_t err_len = strlen(err_msg) + 1;
                                rh->error_msg_len = htobe16((uint16_t)err_len);
                                memcpy(resp_buf + 32, err_msg, err_len);
                                actual_payload_len = err_len;
                            } else if (added != 0) {
                                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                                const char *err_msg = "Settlement failed: the funding wallet cannot cover the payment plus network fee.";
                                size_t err_len = strlen(err_msg) + 1;
                                rh->error_msg_len = htobe16((uint16_t)err_len);
                                memcpy(resp_buf + 32, err_msg, err_len);
                                actual_payload_len = err_len;
                            }
                            free(op);
                            break;
                        } else if (op->type == OP_STAKE) {
                            int added = create_and_broadcast_stake(state, op->data.stake.amount, false);
                            if (added != 0 && added != 2) {
                                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                            }
                            free(op);
                            break;
                        } else if (op->type == OP_UNSTAKE) {
                            int added = create_and_broadcast_unstake(state, op->data.unstake.amount, false);
                            if (added != 0 && added != 2) {
                                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                            }
                            free(op);
                            break;
                        } else if (op->type == OP_APPLY_DRIFT_CERT) {
                            uint8_t anchored_cert_tx_id[COIN_ID_LEN];
                            /* Idempotent retransmission (mirror of the settlement
                             * path above): a re-sent anchoring intent re-receives
                             * the cached cert tx id instead of re-anchoring and
                             * double-charging the anchor fee. */
                            uint8_t memo_op_type = 0;
                            uint8_t memo_tx_id[COIN_ID_LEN];
                            if (settlement_memo_lookup(req_id, &memo_op_type, memo_tx_id) && memo_op_type == 0x07) {
                                resp_buf[32] = 0x07;
                                memcpy(resp_buf + 33, memo_tx_id, COIN_ID_LEN);
                                actual_payload_len = 1 + COIN_ID_LEN;
                                free(op);
                                break;
                            }
                            int dc_added = create_and_broadcast_apply_drift_cert(state, &op->data.apply_drift_cert, false, anchored_cert_tx_id);
                            if (dc_added == 0) {
                                resp_buf[32] = 0x07;
                                memcpy(resp_buf + 33, anchored_cert_tx_id, COIN_ID_LEN);
                                actual_payload_len = 1 + COIN_ID_LEN;
                                settlement_memo_store(req_id, 0x07, anchored_cert_tx_id);
                            } else if (dc_added == 2) {
                                /* Inputs locked: persist the certificate identity
                                 * core and let the background recreation worker
                                 * re-anchor after the next block (mirrors the P2P
                                 * engine's rpc.c auto-queue). */
                                RecreateArgs *retry = calloc(1, sizeof(RecreateArgs));
                                if (retry) {
                                    const ApplyDriftCertData *dc = &op->data.apply_drift_cert;
                                    retry->state = state;
                                    retry->is_drift_cert = true;
                                    retry->amount = dc->amount;
                                    memcpy(retry->circuit_hash, dc->circuit_hash, 32);
                                    retry->tvd_scaled = dc->tvd_scaled;
                                    retry->shots = dc->shots;
                                    retry->status = dc->status;
                                    memcpy(retry->commitment_root, dc->commitment_root, 32);
                                    retry->timestamp_us = dc->timestamp_us;
                                    memcpy(retry->recipient_pubkey, dc->recipient_pubkey, PUBKEY_LEN);
                                    atomic_fetch_add(&state->scheduled_consumed_subunits,
                                                     dc->amount + calculate_fee(dc->amount, true));
                                    spawn_recreation_thread(state, retry);
                                }
                                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                                const char *err_msg = "Anchoring deferred: the node wallet's inputs are locked by a pending mempool operation. The certificate has been queued for automatic background anchoring after the next block - do not resubmit.";
                                size_t err_len = strlen(err_msg) + 1;
                                rh->error_msg_len = htobe16((uint16_t)err_len);
                                memcpy(resp_buf + 32, err_msg, err_len);
                                actual_payload_len = err_len;
                            } else {
                                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                                const char *err_msg = "Drift certificate anchoring failed: the node wallet cannot cover the anchor fee plus the halved network fee.";
                                size_t err_len = strlen(err_msg) + 1;
                                rh->error_msg_len = htobe16((uint16_t)err_len);
                                memcpy(resp_buf + 32, err_msg, err_len);
                                actual_payload_len = err_len;
                            }
                            free(op);
                            break;
                        }

                        pthread_mutex_lock(&state->mutex);
                        int added = add_pending_operation(state, op);
                        pthread_mutex_unlock(&state->mutex);
                        
                        if (added == 0 || added == 2) {
                            // Broadcast the new pending operation to the P2P network
                            Message *broadcast_msg = calloc(1, sizeof(Message));
                            if (broadcast_msg) {
                                broadcast_msg->type = MSG_PENDING_OPERATION;
                                broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
                                if (broadcast_msg->length > 0) {
                                    p2p_broadcast(state, broadcast_msg);
                                    
                                    // Synchronously echo the payload metadata exclusively back to the requesting
                                    // Local WebAssembly viewport instead of discarding it to allow UI auto-updates.
                                    actual_payload_len = broadcast_msg->length;
                                    memcpy(resp_buf + 32, broadcast_msg->payload, actual_payload_len);
                                }
                                free(broadcast_msg);
                            }
                        } else {
                            rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                            const char *err_msg = (added == -2) ? "Double-spend detected: Centinel ticket already redeemed" : "Tx rejected by mempool";
                            size_t err_len = strlen(err_msg) + 1;
                            rh->error_msg_len = htobe16((uint16_t)err_len);
                            memcpy(resp_buf + 32, err_msg, err_len);
                            actual_payload_len = err_len;
                        }
                    } else {
                        rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                    }
                    free(op);
                } else {
                    rh->status_code = htobe16(SCL_RPC_STATUS_RATE_LIMITED);
                }
            } else {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
            }
            break;
        }
        case 0x0004: { // GetAudit
            // Copy circular game audit matrix rows chronologically
            size_t payload_size = AUDIT_SIZE * (USER_ID_LEN + NUMBERS_PER_VALUATION * sizeof(uint32_t) + sizeof(uint64_t) + 32);
            uint8_t *p = resp_buf + 32;
            pthread_mutex_lock(&state->game_state.mutex);
            int val_count = state->game_state.valuation_count;
            int start_idx = (val_count < AUDIT_SIZE) ? 0 : state->game_state.current_audit_index;
            for (size_t i = 0; i < AUDIT_SIZE; i++) {
                int display_idx = (start_idx + i) % AUDIT_SIZE;
                memcpy(p, state->game_state.game_audit[display_idx].user_id, USER_ID_LEN);
                p += USER_ID_LEN;
                for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
                    uint32_t num_net = htonl(state->game_state.game_audit[display_idx].numbers[j]);
                    memcpy(p, &num_net, sizeof(uint32_t));
                    p += sizeof(uint32_t);
                }
                uint64_t timestamp_net = htobe64(state->game_state.game_audit[display_idx].timestamp);
                memcpy(p, &timestamp_net, sizeof(uint64_t));
                p += sizeof(uint64_t);
                memcpy(p, state->game_state.game_audit[display_idx].beacon_seed, 32);
                p += 32;
            }
            pthread_mutex_unlock(&state->game_state.mutex);
            actual_payload_len = payload_size;
            break;
        }
        case 0x0005: { // GetValuations
            // Extract economic stage and reward supply metrics directly from true blockchain ledger state
            uint64_t total_rewarded = 0;
            pthread_rwlock_rdlock(&state->bc.rwlock);
            for (size_t i = 0; i < state->bc.insert_order_count; i++) {
                if (state->bc.insert_order[i]) {
                    total_rewarded += state->bc.insert_order[i]->total_subunits;
                }
            }
            pthread_rwlock_unlock(&state->bc.rwlock);
            
            GameStateSnapshot *snap = acquire_game_state_snapshot(state);
            uint64_t remaining = (MAX_TOTAL_SUBUNITS > total_rewarded) ? (MAX_TOTAL_SUBUNITS - total_rewarded) : 0;
            uint64_t cur_stage = snap ? (uint64_t)calculate_current_stage(total_rewarded, 0) : 2;
            release_game_state_snapshot(snap);

            uint64_t total_rewarded_be = htobe64(total_rewarded);
            uint64_t remaining_be = htobe64(remaining);
            uint64_t cur_stage_be = htobe64(cur_stage);

            memcpy(resp_buf + 32, &total_rewarded_be, 8);
            memcpy(resp_buf + 32 + 8, &remaining_be, 8);
            memcpy(resp_buf + 32 + 16, &cur_stage_be, 8);
            actual_payload_len = 24;
            break;
        }
        case 0x0006: { // GetRecentTxs
            // Collect pending mempool transaction hashes with cursor pagination
            uint32_t cursor = be32toh(hdr->cursor);
            uint8_t *tx_ids = malloc(MAX_PAGINATION_RANGE * COIN_ID_LEN);
            if (tx_ids) {
                size_t count = 0;
                size_t skipped = 0;
                for (int i = 0; i < MAX_PENDING_OPS && count < MAX_PAGINATION_RANGE; i++) {
                    Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                    if (pop) {
                        if (skipped >= cursor) {
                            const uint8_t *pid = get_operation_tx_id(pop);
                            if (pid) memcpy(tx_ids + (count * COIN_ID_LEN), pid, COIN_ID_LEN);
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
                                SHA256(data_ptr, data_len, tx_ids + (count * COIN_ID_LEN));
                            }
                            count++;
                        } else {
                            skipped++;
                        }
                    }
                }

                if (count > 0) {
                    memcpy(resp_buf + 32, tx_ids, count * COIN_ID_LEN);
                    actual_payload_len = count * COIN_ID_LEN;
                }
                if (count == MAX_PAGINATION_RANGE) {
                    rh->flags |= SCL_RPC_FLAG_PAGINATED;
                    rh->cursor = htobe32(cursor + count);
                }
                free(tx_ids);
            } else {
                rh->status_code = htobe16(SCL_RPC_STATUS_RATE_LIMITED);
            }
            break;
        }
        case 0x0007: { // GetTransaction
            // Query transaction by hash across mempool and historical block storage
            if (final_payload_len == COIN_ID_LEN) {
                uint8_t tx_hash[COIN_ID_LEN];
                memcpy(tx_hash, final_payload, COIN_ID_LEN);

                // Resolve Coin ID or Pointer ID to the actual transaction hash
                uint8_t resolved_tx_hash[COIN_ID_LEN];
                memcpy(resolved_tx_hash, tx_hash, COIN_ID_LEN);

                pthread_rwlock_rdlock(&state->bc.rwlock);
                SCLCoin *coin = hash_table_lookup(state->bc.coin_table, tx_hash, false);
                Pointer *ptr = hash_table_lookup(state->bc.pointer_table, tx_hash, false);
                if (coin) {
                    memcpy(resolved_tx_hash, coin->creation_tx_hash, COIN_ID_LEN);
                } else if (ptr) {
                    memcpy(resolved_tx_hash, ptr->prev_tx_hash, COIN_ID_LEN);
                }
                pthread_rwlock_unlock(&state->bc.rwlock);

                Operation *block_op = NULL;
                bool found_in_blocks = false;

                for (int i = 0; i < MAX_PENDING_OPS; i++) {
                    Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
                    if (pop) {
                        uint8_t pkey[COIN_ID_LEN];
                        const uint8_t *pid = get_operation_tx_id(pop);
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
                        if (memcmp(pkey, resolved_tx_hash, COIN_ID_LEN) == 0) {
                            block_op = malloc(sizeof(Operation));
                            if (block_op) {
                                *block_op = *pop;
                                found_in_blocks = true;
                            }
                            break;
                        }
                    }
                }

                // Search blockchain block history if not found in active mempool
                if (!found_in_blocks) {
                    pthread_rwlock_rdlock(&state->bc.rwlock);
                    size_t scan_limit = state->current_block_number + 1;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
                    if (scan_limit > 16) scan_limit = 16; // Bounded search depth to prevent O(N^2) RPC timeouts
#endif
                    for (size_t b_idx = 0; b_idx < scan_limit; b_idx++) {
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

                        if (block) {
                            size_t tx_idx = 0;
                            for (size_t op_idx = 0; op_idx < block->operation_count; op_idx++) {
                                Operation *op = &block->operations[op_idx];
                                if (op->type == OP_TRANSFER_POINTER) {
                                    const uint8_t *op_id = get_operation_tx_id(op);
                                    if (op_id && memcmp(op_id, resolved_tx_hash, COIN_ID_LEN) == 0) {
                                        block_op = malloc(sizeof(Operation));
                                        if (block_op) {
                                            *block_op = *op;
                                            // Restore omitted nullifier from block batch array
                                            if (block->batch_prf_outputs && tx_idx < block->batch_tx_count) {
                                                memcpy(block_op->data.transfer_pointer.prf_output,
                                                       block->batch_prf_outputs + (tx_idx * NULLIFIER_LEN),
                                                       NULLIFIER_LEN);
                                            }
                                            found_in_blocks = true;
                                        }
                                        break;
                                    }
                                    tx_idx++;
                                } else {
                                    const uint8_t *op_id = get_operation_tx_id(op);
                                    if (op_id && memcmp(op_id, resolved_tx_hash, COIN_ID_LEN) == 0) {
                                        block_op = malloc(sizeof(Operation));
                                        if (block_op) {
                                            *block_op = *op;
                                            found_in_blocks = true;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        free_block(block);
                        if (found_in_blocks) break;
                    }
                    pthread_rwlock_unlock(&state->bc.rwlock);
                }

                if (found_in_blocks && block_op) {
                    size_t op_len = serialize_operation(block_op, resp_buf + 32, MAX_MESSAGE_SIZE);
                    if (op_len > 0) {
                        actual_payload_len = op_len;
                    } else {
                        rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                        const char *err_msg = "Serialization failed";
                        size_t err_len = strlen(err_msg) + 1;
                        rh->error_msg_len = htobe16((uint16_t)err_len);
                        memcpy(resp_buf + 32, err_msg, err_len);
                        actual_payload_len = err_len;
                    }
                    free(block_op);
                    break;
                }
                
                if (block_op) free(block_op);
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                const char *err_msg = "Transaction not found on-chain or in mempool";
                size_t err_len = strlen(err_msg) + 1;
                rh->error_msg_len = htobe16((uint16_t)err_len);
                memcpy(resp_buf + 32, err_msg, err_len);
                actual_payload_len = err_len;
            } else {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                const char *err_msg = "Invalid final payload length";
                size_t err_len = strlen(err_msg) + 1;
                rh->error_msg_len = htobe16((uint16_t)err_len);
                memcpy(resp_buf + 32, err_msg, err_len);
                actual_payload_len = err_len;
            }
            break;
        }
        case 0x0008: { // GetChainInfo
            // Assemble node consensus height, committee peers, and local wallet keys
            uint64_t height_be = htobe64(state->current_block_number);
            
            GameStateSnapshot *snap = acquire_game_state_snapshot(state);
            uint64_t last_dkg = snap ? snap->last_dkg_epoch : 0;
            release_game_state_snapshot(snap);

            uint64_t total_subunits = 0;
            uint64_t total_staked = 0;
            uint64_t total_fees = 0;
            pthread_rwlock_rdlock(&state->bc.rwlock);
            for (size_t i = 0; i < state->bc.insert_order_count; i++) {
                if (state->bc.insert_order[i]) {
                    total_subunits += state->bc.insert_order[i]->total_subunits;
                }
            }
            total_staked = calculate_total_staked_subunits(&state->bc);
            total_fees = calculate_total_fees_subunits(&state->bc);
            pthread_rwlock_unlock(&state->bc.rwlock);

            /* Helper locks internally. Do not hold p2p_network.mutex here.
             * This is the handler the explorer WebSocket calls. */
            uint16_t committee_count = scl_count_established_nodes(state);

            uint16_t active_dkg_sessions = 0;
            if (pthread_mutex_trylock(&state->epoch_mutex) == 0) {
                if (state->dkg_active_sessions && state->dkg_active_sessions->count > 0) {
                    for (size_t i = 0; i < state->dkg_active_sessions->size; i++) {
                        GenericHashEntry *entry = state->dkg_active_sessions->buckets[i];
                        while (entry) {
                            if (entry->type == HASH_ENTRY_DKG_SESSION) {
                                DKGSession *sess = (DKGSession *)entry->data.dkg_session;
                                active_dkg_sessions = (uint16_t)(sess->status + 1);
                                break;
                            }
                            entry = entry->next;
                        }
                        if (active_dkg_sessions > 0) break;
                    }
                }
                pthread_mutex_unlock(&state->epoch_mutex);
            }

            uint64_t total_subunits_be = htobe64(total_subunits);
            uint64_t total_staked_be = htobe64(total_staked);
            uint64_t total_fees_be = htobe64(total_fees);
            uint16_t committee_count_be = htobe16(committee_count);
            uint64_t last_dkg_be = htobe64(last_dkg);
            uint16_t active_dkg_sessions_be = htobe16(active_dkg_sessions);

            memcpy(resp_buf + 32, &height_be, 8);
            memcpy(resp_buf + 32 + 8, &total_subunits_be, 8);
            memcpy(resp_buf + 32 + 16, &total_staked_be, 8);
            memcpy(resp_buf + 32 + 24, &committee_count_be, 2);
            memcpy(resp_buf + 32 + 26, &active_dkg_sessions_be, 2);
            memcpy(resp_buf + 32 + 28, &last_dkg_be, 8);
            memcpy(resp_buf + 32 + 36, &total_fees_be, 8);
            
            pthread_mutex_lock(&state->wallet_mutex);
            memcpy(resp_buf + 32 + 44, state->testnet_identity_wallet.dilithium_pubkey, PUBKEY_LEN);
            memcpy(resp_buf + 32 + 44 + PUBKEY_LEN, state->testnet_identity_wallet.dilithium_privkey, PRIVKEY_LEN);
            /* SCL402: append the fee-recipient pubkey (user_wallet — the wallet
             * whose SHA-256 address is SclRpcPaymentChallenge.recipient_address).
             * Public key only; the operator secret never leaves the node. Browsers
             * need the full 2,592-byte key to build the paying OP_TRANSFER_POINTER. */
            memcpy(resp_buf + 32 + 44 + PUBKEY_LEN + PRIVKEY_LEN, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            pthread_mutex_unlock(&state->wallet_mutex);
            actual_payload_len = 44 + PUBKEY_LEN + PRIVKEY_LEN + PUBKEY_LEN;
            break;
        }
        case 0x000A: { // Quantum TVD Audit
            // Execute Total Variation Distance quantum drift audit
            if (final_payload_len < 36) {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                actual_payload_len = 0;
                break;
            }
            uint32_t shots = be32toh(*(const uint32_t *)(final_payload));
            if (shots == 0 || shots > 100000) {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                actual_payload_len = 0;
                break;
            }
            const uint8_t *beacon_seed = final_payload + 4;
            const uint8_t *circuit_bytes = (final_payload_len > 36) ? (final_payload + 36) : NULL;
            size_t circuit_len = (final_payload_len > 36) ? (final_payload_len - 36) : 0;

            QuantumDriftCertificate cert;
            if (quantum_tvd_audit_generate_certificate(state, circuit_bytes, circuit_len, NULL, shots, beacon_seed, &cert) == 0) {
                memcpy(resp_buf + 32, &cert, sizeof(QuantumDriftCertificate));
                actual_payload_len = sizeof(QuantumDriftCertificate);
                
                if (method_id < 12) {
                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[method_id], 1, memory_order_relaxed);
                }
            } else {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                actual_payload_len = 0;
                
                if (method_id < 12) {
                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[method_id], 1, memory_order_relaxed);
                }
            }
            break;
        }
        case 0x000B: { // Autopilot Config & Status
            /* Exact-length guard (parity with rpc.c 0x000B and the 0x0001/
             * 0x0007 handlers): a 9-byte config update or a 0-byte status
             * query; anything else — including trailing garbage — is
             * rejected. First-time signed frames were sig-stripped above. */
            if (final_payload_len == 9) {
                bool enable = (final_payload[0] != 0);
                uint32_t val_per_hr = be32toh(*(const uint32_t *)(final_payload + 1));
                uint32_t stake_ratio = be32toh(*(const uint32_t *)(final_payload + 5));

                if (stake_ratio > 100) stake_ratio = 100;
                if (val_per_hr == 0) val_per_hr = 1;

                state->config.autopilot_enabled = enable;
                state->config.autopilot_valuations_per_hour = val_per_hr;
                state->config.autopilot_stake_ratio = stake_ratio;

                if (enable) {
                    start_autopilot_thread(state);
                } else {
                    stop_autopilot_thread(state);
                }
            } else if (final_payload_len != 0) {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                const char *err_msg = "Invalid args for Autopilot";
                size_t err_len = strlen(err_msg) + 1;
                rh->error_msg_len = htobe16((uint16_t)err_len);
                memcpy(resp_buf + 32, err_msg, err_len);
                actual_payload_len = err_len;
                break;
            }

            uint8_t resp_payload[21] = {0};
            resp_payload[0] = atomic_load(&state->autopilot_running) ? 1 : 0;
            uint32_t v_hr_be = htobe32(state->config.autopilot_valuations_per_hour);
            memcpy(resp_payload + 1, &v_hr_be, 4);
            uint32_t s_ratio_be = htobe32(state->config.autopilot_stake_ratio);
            memcpy(resp_payload + 5, &s_ratio_be, 4);

            uint64_t fees_paid = calculate_fees_paid_subunits(&state->bc, state->user_wallet.dilithium_pubkey);
            double fees_scl = (double)fees_paid / SUBUNITS_PER_COIN;
            uint8_t threshold_pk[PUBKEY_LEN];
            uint64_t staked_sub = (compute_threshold_pubkey(state, threshold_pk) == 0) ? calculate_staked_subunits(&state->bc, threshold_pk) : 0;
            double staked_scl = (double)staked_sub / SUBUNITS_PER_COIN;
            uint32_t max_rate = (uint32_t)(1 + floor(staked_scl + fees_scl));
            uint32_t max_rate_be = htobe32(max_rate);
            memcpy(resp_payload + 9, &max_rate_be, 4);

            uint64_t now_ts = htobe64(get_real_time_us());
            memcpy(resp_payload + 13, &now_ts, 8);

            memcpy(resp_buf + 32, resp_payload, 21);
            actual_payload_len = 21;
            break;
        }
        case 0x000C: { // GetBlockchainLedger (Coins & Child Pointers)
            // Enumerate full ledger coin and child pointer hierarchy for block explorer
            pthread_rwlock_rdlock(&state->bc.rwlock);
            uint32_t num_coins = (state->bc.insert_order) ? (uint32_t)state->bc.insert_order_count : 0;
            size_t offset = 0;
            uint32_t coins_be = htobe32(num_coins);
            memcpy(resp_buf + 32 + offset, &coins_be, 4);
            offset += 4;

            for (size_t c = 0; c < num_coins; c++) {
                SCLCoin *coin = state->bc.insert_order[c];
                if (!coin) continue;
                if (offset + 120 > resp_max - 64) break;

                memcpy(resp_buf + 32 + offset, coin->coin_id, 32); offset += 32;
                uint64_t tot_be = htobe64(coin->total_subunits);
                memcpy(resp_buf + 32 + offset, &tot_be, 8); offset += 8;
                uint64_t rem_be = htobe64(coin->remaining_subunits);
                memcpy(resp_buf + 32 + offset, &rem_be, 8); offset += 8;
                memcpy(resp_buf + 32 + offset, coin->creation_tx_hash, 32); offset += 32;
                memcpy(resp_buf + 32 + offset, coin->owner_address, 32); offset += 32;
                uint64_t blk_be = htobe64((uint64_t)c);
                memcpy(resp_buf + 32 + offset, &blk_be, 8); offset += 8;

                size_t ptr_count_offset = offset;
                offset += 4;
                uint32_t coin_ptr_count = 0;

                if (state->bc.pointer_table) {
                    for (size_t p = 0; p < state->bc.pointer_table->size; p++) {
                        GenericHashEntry *entry = state->bc.pointer_table->buckets[p];
                        while (entry) {
                            if (entry->type == HASH_ENTRY_POINTER) {
                                Pointer *ptr = &entry->data.pointer;
                                if (memcmp(ptr->parent_coin_id, coin->coin_id, 32) == 0) {
                                    if (offset + 146 > resp_max - 64) break;
                                    memcpy(resp_buf + 32 + offset, ptr->pointer_id, 32); offset += 32;
                                    memcpy(resp_buf + 32 + offset, ptr->parent_coin_id, 32); offset += 32;
                                    uint64_t s_be = htobe64(ptr->start_subunit);
                                    memcpy(resp_buf + 32 + offset, &s_be, 8); offset += 8;
                                    uint64_t e_be = htobe64(ptr->end_subunit);
                                    memcpy(resp_buf + 32 + offset, &e_be, 8); offset += 8;
                                    memcpy(resp_buf + 32 + offset, ptr->owner_address, 32); offset += 32;
                                    memcpy(resp_buf + 32 + offset, ptr->prev_tx_hash, 32); offset += 32;
                                    uint8_t sp_byte = (uint8_t)ptr->spent;
                                    memcpy(resp_buf + 32 + offset, &sp_byte, 1); offset += 1;
                                    uint8_t st_byte = ptr->staked ? 1 : 0;
                                    memcpy(resp_buf + 32 + offset, &st_byte, 1); offset += 1;
                                    coin_ptr_count++;
                                }
                            }
                            entry = entry->next;
                        }
                    }
                }
                uint32_t ptr_count_be = htobe32(coin_ptr_count);
                memcpy(resp_buf + 32 + ptr_count_offset, &ptr_count_be, 4);
            }

            pthread_rwlock_unlock(&state->bc.rwlock);
            actual_payload_len = offset;
            break;
        }
        case 0x000D: { // Enterprise Drift Certificate Histogram Audit (SCL402-metered)
            /* Wire layout (mirrors handle_rpc_drift_cert_audit, quantum_tvd_rpc.c):
             * [4B shots BE][32B beacon seed][2B hist_dim BE = 128]
             * [512B histogram: 128 x u32 BE basis-state counts][optional OpenQASM bytes].
             * Unlike the P2P handler, every validation failure returns
             * SCL_RPC_STATUS_INVALID_ARGS carrying a human-readable reason so the
             * browser can state exactly what is missing instead of hanging. */
            const char *dc_err = NULL;
            uint32_t shots = 0;
            uint16_t hist_dim = 0;
            uint32_t histogram[128];
            memset(histogram, 0, sizeof(histogram));

            if (final_payload_len < 38) {
                dc_err = "Drift audit payload too short: expected 4-byte shots + 32-byte beacon + 2-byte histogram dimension (38 bytes minimum)";
            } else {
                uint32_t shots_raw;
                memcpy(&shots_raw, final_payload, sizeof(uint32_t));
                shots = be32toh(shots_raw);
                if (shots == 0 || shots > 100000) {
                    dc_err = "Shot budget must be between 1 and 100,000";
                }
            }

            if (!dc_err) {
                uint16_t hist_dim_raw;
                memcpy(&hist_dim_raw, final_payload + 36, sizeof(uint16_t));
                hist_dim = be16toh(hist_dim_raw);
                if (hist_dim != 128) {
                    dc_err = "Histogram dimension must be exactly 128 basis states (7-qubit register)";
                } else if (final_payload_len < 38 + (size_t)hist_dim * 4) {
                    dc_err = "Histogram truncated: expected 128 x 4-byte big-endian counts (512 bytes)";
                }
            }

            if (!dc_err) {
                uint64_t histogram_total = 0;
                for (uint16_t i = 0; i < hist_dim; i++) {
                    uint32_t count_raw;
                    memcpy(&count_raw, final_payload + 38 + (size_t)i * 4, sizeof(uint32_t));
                    histogram[i] = be32toh(count_raw);
                    if (histogram[i] > shots) {
                        dc_err = "Histogram bin exceeds the shot budget (counts must be non-negative and <= shots)";
                        break;
                    }
                    histogram_total += histogram[i];
                }
                if (!dc_err && histogram_total != shots) {
                    dc_err = "Shot conservation violated: histogram bins must sum exactly to the shot budget";
                }
            }

            if (dc_err) {
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                size_t err_len = strlen(dc_err) + 1;
                rh->error_msg_len = htobe16((uint16_t)err_len);
                memcpy(resp_buf + 32, dc_err, err_len);
                actual_payload_len = err_len;
                if (method_id < 16) {
                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[method_id], 1, memory_order_relaxed);
                }
                break;
            }

            const uint8_t *beacon_seed = final_payload + 4;
            size_t histogram_bytes = (size_t)hist_dim * 4;
            const uint8_t *circuit_bytes = (final_payload_len > 38 + histogram_bytes) ? (final_payload + 38 + histogram_bytes) : NULL;
            size_t circuit_len = (final_payload_len > 38 + histogram_bytes) ? (final_payload_len - 38 - histogram_bytes) : 0;

            QuantumDriftCertificate cert;
            if (quantum_tvd_audit_generate_certificate(state, circuit_bytes, circuit_len, histogram, shots, beacon_seed, &cert) == 0) {
                memcpy(resp_buf + 32, &cert, sizeof(QuantumDriftCertificate));
                actual_payload_len = sizeof(QuantumDriftCertificate);
                if (method_id < 16) {
                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_ok[method_id], 1, memory_order_relaxed);
                }
            } else {
                const char *err_msg = "Drift audit engine failed to generate the certificate";
                rh->status_code = htobe16(SCL_RPC_STATUS_INVALID_ARGS);
                size_t err_len = strlen(err_msg) + 1;
                rh->error_msg_len = htobe16((uint16_t)err_len);
                memcpy(resp_buf + 32, err_msg, err_len);
                actual_payload_len = err_len;
                if (method_id < 16) {
                    atomic_fetch_add_explicit(&state->rpc_engine.method_requests_err[method_id], 1, memory_order_relaxed);
                }
            }
            break;
        }
        case 0x0009: { // SyncWalletKeys
            // SPEC COMPLIANCE: Remote mutation of the node's wallet credentials
            // is strictly disabled on public RPC / Explorer endpoints to prevent
            // state collisions across concurrent browser sessions.
            rh->status_code = htobe16(SCL_RPC_STATUS_UNAUTHORIZED);
            const char *err_msg = "Node wallet mutation is disabled on public RPC endpoints";
            size_t err_len = strlen(err_msg) + 1;
            rh->error_msg_len = htobe16((uint16_t)err_len);
            memcpy(resp_buf + 32, err_msg, err_len);
            actual_payload_len = err_len;
            break;
        }
        default: {
            rh->status_code = htobe16(SCL_RPC_STATUS_BAD_METHOD);
            break;
        }
    }

    // Compress outbound response payload using LZ4 if requested by client flags
    if ((hdr->flags & SCL_RPC_FLAG_COMPRESSED) && actual_payload_len > 0) {
        int max_comp_size = LZ4_compressBound((int)actual_payload_len);
        uint8_t *comp_buf = malloc(max_comp_size);
        if (comp_buf) {
            int comp_bytes = LZ4_compress_default((const char*)(resp_buf + 32), (char*)comp_buf, (int)actual_payload_len, max_comp_size);
            if (comp_bytes > 0 && comp_bytes < (int)actual_payload_len) {
                memcpy(resp_buf + 32, comp_buf, comp_bytes);
                actual_payload_len = comp_bytes;
                rh->flags |= SCL_RPC_FLAG_COMPRESSED;
            }
            free(comp_buf);
        }
    }

    rh->payload_len = htobe32((uint32_t)actual_payload_len);
    size_t total_resp_len = 32 + actual_payload_len;

    // Encapsulate binary RPC response into WebSocket frame and write to client TCP socket
    size_t ws_max = total_resp_len + 16;
    uint8_t *ws_buf = malloc(ws_max);
    if (ws_buf) {
        size_t ws_frame_len = 0;
        if (ws_encode_frame(resp_buf, total_resp_len, ws_buf, ws_max, &ws_frame_len) == 0) {
            safe_ws_write(tcp_fd, ws_buf, ws_frame_len);
        }
        free(ws_buf);
    }
    free(resp_buf);
    if (decomp_buf) free(decomp_buf);
}

/* ============================================================================ */
/* SECTION 4: CLIENT CONNECTION THREAD & SERVER DISPATCHER                      */
/* ============================================================================ */

/**
 * @brief Dedicated per-client worker thread handling WebSocket framing and UDP proxying.
 *
 * @details
 * Execution Pipeline:
 * 1. Reads and completes the HTTP WebSocket upgrade handshake.
 * 2. Creates an ephemeral non-blocking UDP socket directed to the node's local P2P port.
 * 3. Enters an event loop polling both TCP and UDP descriptors simultaneously using `poll`:
 *    - Ingress (Browser -> Node): Decodes WebSocket frames; routes RPC frames to @ref handle_local_rpc_request
 *      or forwards P2P packets via loopback UDP.
 *    - Egress (Node -> Browser): Receives UDP packets from local node; encapsulates into binary
 *      WebSocket frames and writes to client TCP socket.
 * 4. Tears down descriptors and frees context upon client disconnect or node shutdown.
 *
 * @param[in] arg Pointer to heap-allocated @ref WsClientContext (freed on exit).
 * @return NULL upon thread termination.
 *
 * @complexity Time: O(connection_lifetime), Space: O(MAX_MESSAGE_SIZE) heap buffers per connection.
 */
static void *ws_client_handler(void *arg) {
    WsClientContext *ctx = (WsClientContext *)arg;
    int tcp_fd = ctx->tcp_fd;
    State *state = ctx->state;

    scl_log(LOG_LEVEL_INFO, "Bridge", "Handling new WebSocket connection");

    char handshake_buf[WS_HANDSHAKE_BUFFER_SIZE];
    /* RFC 6455 §4.1: read the COMPLETE client handshake before responding.
     * The upgrade request can arrive split across TCP segments (TLS-terminating
     * proxies such as the GCLB front end frequently split it), and a single
     * read() returns as soon as any bytes are available — so accumulate until
     * the header terminator shows up, the buffer fills, or a 2s poll deadline
     * expires. HTTP headers contain no NUL bytes, so strstr is safe here. */
    size_t h_total = 0;
    while (h_total < sizeof(handshake_buf) - 1) {
        struct pollfd h_pfd = { .fd = tcp_fd, .events = POLLIN };
        if (poll(&h_pfd, 1, 2000) <= 0) break;
        ssize_t h_read = SCL_READ_SOCKET(tcp_fd, handshake_buf + h_total,
                                         sizeof(handshake_buf) - 1 - h_total);
        if (h_read <= 0) break;
        h_total += (size_t)h_read;
        handshake_buf[h_total] = '\0';
        if (strstr(handshake_buf, "\r\n\r\n") != NULL) break;
    }
    if (h_total == 0) {
        SCL_CLOSE_SOCKET(tcp_fd);
        free(ctx);
        return NULL;
    }
    handshake_buf[h_total] = '\0';

    if (perform_handshake(ctx->state, tcp_fd, handshake_buf, h_total) != 0) {
        scl_log(LOG_LEVEL_WARN, "Bridge", "WebSocket handshake failed or 402 Payment Required emitted");
        SCL_CLOSE_SOCKET(tcp_fd);
        free(ctx);
        return NULL;
    }

    // Ephemeral loopback UDP socket to talk directly with SCL node
    int udp_fd = -1;
    struct sockaddr_storage node_addr;
    memset(&node_addr, 0, sizeof(node_addr));
    
    if (strchr(state->config.local_ip, ':')) {
        udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&node_addr;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(state->config.port);
        inet_pton(AF_INET6, "::1", &v6->sin6_addr);
    } else {
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in *v4 = (struct sockaddr_in *)&node_addr;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(state->config.port);
        inet_pton(AF_INET, "127.0.0.1", &v4->sin_addr);
    }

    if (udp_fd < 0) {
        SCL_CLOSE_SOCKET(tcp_fd);
        free(ctx);
        return NULL;
    }

    // Configure TCP and UDP sockets for non-blocking I/O polling
#ifndef _WIN32
    fcntl(tcp_fd, F_SETFL, fcntl(tcp_fd, F_GETFL) | O_NONBLOCK);
    fcntl(udp_fd, F_SETFL, fcntl(udp_fd, F_GETFL) | O_NONBLOCK);
#else
    u_long mode = 1;
    ioctlsocket(tcp_fd, FIONBIO, &mode);
    ioctlsocket(udp_fd, FIONBIO, &mode);
#endif

    uint8_t *tcp_in_stream = malloc(MAX_MESSAGE_SIZE + 4096);
    uint8_t *payload_buf = malloc(MAX_MESSAGE_SIZE);
    uint8_t *udp_in_buf = malloc(MAX_MESSAGE_SIZE);
    uint8_t *ws_out_frame = malloc(MAX_MESSAGE_SIZE + 4096);

    if (!tcp_in_stream || !payload_buf || !udp_in_buf || !ws_out_frame) {
        goto cleanup;
    }

    size_t stream_pos = 0;
    struct pollfd fds[2];
    fds[0].fd = tcp_fd;
    fds[0].events = POLLIN;
    fds[1].fd = udp_fd;
    fds[1].events = POLLIN;

    // Main polling loop: multiplex bidirectional traffic between browser TCP and node UDP
    while (!atomic_load(&global_shutdown)) {
        int poll_ret = poll(fds, 2, 1000);
        if (poll_ret < 0) break;
        if (poll_ret == 0) continue;

        // 1. Data from browser (WebSocket) -> Forward via UDP to SCL Node
        if (fds[0].revents & POLLIN) {
            ssize_t r = SCL_READ_SOCKET(tcp_fd, tcp_in_stream + stream_pos, (MAX_MESSAGE_SIZE + 4096) - stream_pos);
            if (r < 0) {
#ifndef _WIN32
                if (errno != EAGAIN && errno != EWOULDBLOCK) break;
#else
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK) break;
#endif
            } else if (r == 0) {
                break; // Client disconnected gracefully
            } else {
                stream_pos += r;
            }

            size_t processed = 0;
            bool disconnect_requested = false;
            while (stream_pos - processed >= 2) {
                size_t frame_consumed = 0;
                size_t decoded_len = 0;
                uint8_t frame_opcode = 0;
                int dec_status = ws_decode_frame(tcp_in_stream + processed, stream_pos - processed,
                                                 payload_buf, &decoded_len, &frame_consumed, &frame_opcode);
                if (dec_status == 0) {
                    break; // Frame incomplete, wait for more bytes
                }
                if (dec_status == -1) {
                    disconnect_requested = true;
                    break; // Error in frame decoding
                }
                if (dec_status == -2) {
                    disconnect_requested = true;
                    break; // Connection close requested
                }
                if (frame_opcode == 0x09) {
                    /* RFC 6455 §5.5.2: a Ping MUST be answered with a Pong
                     * echoing the payload (control payloads are capped at 125
                     * bytes). Pings previously fell through to the non-RPC
                     * drop below and were never answered. */
                    if (decoded_len > 125) { // §5.5 control-frame payload cap
                        disconnect_requested = true;
                        break;
                    }
                    uint8_t pong_buf[2 + 125];
                    pong_buf[0] = 0x8A; // FIN=1, Opcode=0xA (Pong)
                    pong_buf[1] = (uint8_t)decoded_len;
                    if (decoded_len > 0) memcpy(pong_buf + 2, payload_buf, decoded_len);
                    safe_ws_write(tcp_fd, pong_buf, 2 + decoded_len);
                    processed += frame_consumed;
                    continue;
                }
                if (frame_opcode == 0x0A) {
                    // Unsolicited Pong (heartbeat reply): consume silently.
                    processed += frame_consumed;
                    continue;
                }

                if (decoded_len > 0) {
                    // Check if the packet is an RPC Request bypassing P2P framing
                    if (decoded_len >= 32) {
                        const SclRpcHeader *hdr = (const SclRpcHeader *)payload_buf;
                        uint16_t m_id = be16toh(hdr->method_id);
                        /* 0x000D (enterprise drift-certificate histogram audit) previously
                         * fell through to the drop below: the browser could never reach
                         * the drift-audit handler and the UI hung silently. */
                        if (hdr->version == SCL_RPC_VERSION_1 && (m_id >= 0x0001 && m_id <= 0x000D)) {
                            handle_local_rpc_request(state, payload_buf, decoded_len, tcp_fd);
                            processed += frame_consumed;
                            continue;
                        }
                    }
                    /* H-2 fix: the raw UDP proxy into the node's P2P listener is removed.
                     * The bridge executes legitimate RPC frames only (the explorer's whole
                     * pipeline, including SubmitTx 0x0003, is RPC); every other binary
                     * frame is dropped. */
                    fprintf(stderr, "[Bridge] Dropped non-RPC binary frame (%zu bytes): raw UDP proxy disabled\n", decoded_len);
                }
                processed += frame_consumed;
            }

            if (processed > 0) {
                memmove(tcp_in_stream, tcp_in_stream + processed, stream_pos - processed);
                stream_pos -= processed;
            }

            if (disconnect_requested) break;
        }

        /* 2. H-2 fix: the node-to-browser UDP return path is removed together with the
         * proxy. RPC responses are written back on the TCP socket by the RPC handlers
         * themselves; nothing else is forwarded. */
    }

cleanup:
    free(tcp_in_stream);
    free(payload_buf);
    free(udp_in_buf);
    free(ws_out_frame);
    SCL_CLOSE_SOCKET(tcp_fd);
    SCL_CLOSE_SOCKET(udp_fd);
    free(ctx);
    return NULL;
}

/**
 * @brief Main server loop listening for TCP connections and spawning WebSocket client handlers.
 *
 * @details
 * Binds a non-blocking TCP socket to `state->config.websocket_port` (default: 5554),
 * listens for inbound connections, performs RFC 6455 HTTP upgrade handshakes using
 * SHA-1 and Base64 `Sec-WebSocket-Accept` computation, and spawns detached client worker
 * threads configured with dedicated 8 MiB stack allocations to accommodate post-quantum proofs.
 *
 * @param[in] arg Pointer to global @ref State structure.
 * @return NULL upon thread exit.
 *
 * @pre `arg` must point to initialized State; `state->config.websocket_port` must be a valid open port.
 * @post Executes continuously until `global_shutdown` is signaled; closes server descriptor on exit.
 * @thread_safety Reentrant and thread-safe. Runs as an isolated background daemon.
 * @complexity Time: O(infinite event loop), Space: O(1) baseline server allocation.
 */
void *websocket_bridge_server(void *arg) {
    State *state = (State *)arg;

    // Create and configure TCP listening socket for WebSocket bridge (Dual-Stack IPv6)
    int domain = AF_INET6;
    int server_fd = (int)socket(domain, SOCK_STREAM, 0);
    if (server_fd < 0) {
        // Fallback to IPv4 if IPv6 is completely disabled on the host
        domain = AF_INET;
        server_fd = (int)socket(domain, SOCK_STREAM, 0);
    }
    if (server_fd < 0) {
        scl_log(LOG_LEVEL_FATAL, "Bridge", "Failed to create TCP socket");
        return NULL;
    }

    int opt = 1;
#ifndef _WIN32
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#else
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#endif

    /* H-2 fix: default-bind the bridge to loopback. Opt in to public binding with
     * SCL_BRIDGE_BIND_PUBLIC=1 (requires SCL_BRIDGE_AUTH_TOKEN; enforced in
     * perform_handshake, and fail-closed here). */
    const char *public_env = getenv("SCL_BRIDGE_BIND_PUBLIC");
    bool public_bind = (public_env != NULL && strcmp(public_env, "1") == 0);
    const char *bridge_auth_token = getenv("SCL_BRIDGE_AUTH_TOKEN");
    if (public_bind && (!bridge_auth_token || bridge_auth_token[0] == '\0')) {
        scl_log(LOG_LEVEL_FATAL, "Bridge", "SCL_BRIDGE_BIND_PUBLIC=1 requires SCL_BRIDGE_AUTH_TOKEN; refusing to start exposed");
        if (server_fd >= 0) SCL_CLOSE_SOCKET(server_fd);
        return NULL;
    }

    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    socklen_t addr_len;

    if (domain == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = public_bind ? in6addr_any : in6addr_loopback;
        v6->sin6_port = htons(state->config.websocket_port);
        addr_len = sizeof(struct sockaddr_in6);

        // Allow IPv4 mapped addresses
        int no = 0;
        setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&no, sizeof(no));
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = public_bind ? INADDR_ANY : htonl(INADDR_LOOPBACK);
        v4->sin_port = htons(state->config.websocket_port);
        addr_len = sizeof(struct sockaddr_in);
    }

    if (bind(server_fd, (struct sockaddr *)&address, addr_len) < 0) {
        // Try explicit IPv4 fallback if IPv6 bind fails
        if (domain == AF_INET6) {
            SCL_CLOSE_SOCKET(server_fd);
            domain = AF_INET;
            server_fd = (int)socket(domain, SOCK_STREAM, 0);
            if (server_fd >= 0) {
                setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
                memset(&address, 0, sizeof(address));
                struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
                v4->sin_family = AF_INET;
                v4->sin_addr.s_addr = public_bind ? INADDR_ANY : htonl(INADDR_LOOPBACK);
                v4->sin_port = htons(state->config.websocket_port);
                if (bind(server_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_in)) == 0) {
                    goto bind_success;
                }
            }
        }
        scl_log(LOG_LEVEL_FATAL, "Bridge", "Failed to bind TCP WebSocket bridge port");
        if (server_fd >= 0) SCL_CLOSE_SOCKET(server_fd);
        return NULL;
    }
bind_success:

    if (listen(server_fd, 10) < 0) {
        SCL_CLOSE_SOCKET(server_fd);
        return NULL;
    }

    scl_log(LOG_LEVEL_INFO, "Bridge", "WebSocket-to-UDP Bridge Listening on port %d", state->config.websocket_port);

    // Main accept loop: listen for inbound client TCP connections and spawn worker threads
    while (!atomic_load(&global_shutdown)) {
        struct pollfd pfd = { .fd = server_fd, .events = POLLIN };
        int r = poll(&pfd, 1, 1000);
        if (r < 0) break;
        if (r == 0) continue;

        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = (int)accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        WsClientContext *ctx = malloc(sizeof(WsClientContext));
        if (ctx) {
            ctx->tcp_fd = client_fd;
            ctx->state = state;
            ctx->client_addr = client_addr;

            pthread_t tid;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setstacksize(&attr, 8 * 1024 * 1024); // 8MB stack safety ceiling for heavy post-quantum proofs

            if (pthread_create(&tid, &attr, ws_client_handler, ctx) != 0) {
                SCL_CLOSE_SOCKET(client_fd);
                free(ctx);
            } else {
                pthread_detach(tid);
            }
            pthread_attr_destroy(&attr);
        } else {
            SCL_CLOSE_SOCKET(client_fd);
        }
    }

    SCL_CLOSE_SOCKET(server_fd);
    release_l5_staging_buffer();
    return NULL;
}
