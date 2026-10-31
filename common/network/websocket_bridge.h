/**
 * @file common/network/websocket_bridge.h
 * @brief Satocialist Protocol: Local TCP WebSocket-to-UDP Bridge Server Interface
 *
 * @details
 * Declares the server entrypoint for the embedded WebSocket bridge daemon.
 * Connects browser-based web frontends (Auditor Viewport, Blockchain Explorer)
 * to the native P2P core daemon via RFC 6455 WebSocket framing over TCP port 5554,
 * translating frames bidirectionally between browser clients and internal UDP sockets.
 *
 * @section architectural_role Architectural Role
 * - WebAssembly Sandbox Escape: Browser environments are prohibited from opening raw UDP sockets
 *   or binding P2P ports. The WebSocket bridge allows browser frontends to transmit signed L5 RPC
 *   frames directly to the local node daemon over a loopback TCP socket.
 * - Zero-Copy Framing: Binary WebSocket frames (opcode 0x02) carry exact L5 RPC wire frames
 *   (@ref SclRpcHeader) without intermediate transcoding or base64 overhead.
 * - Local Isolation: The bridge server binds strictly to the configured port (default 5554)
 *   and limits client worker threads to dedicated 8 MiB execution stacks.
 * - Autonomous Agent Gating: Enforces optional HTTP 402 Payment Required challenges for unauthenticated
 *   automated agents attempting WebSocket upgrades.
 *
 * @section thread_safety Thread Safety & Concurrency
 * - `websocket_bridge_server` executes as a dedicated background thread spawned during node bootstrap.
 * - Client sessions are handled by detached POSIX threads (`ws_client_handler`) with non-blocking I/O polling.
 */

#ifndef SCL_WEBSOCKET_BRIDGE_H
#define SCL_WEBSOCKET_BRIDGE_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* 1. WEBSOCKET SERVER ENTRYPOINT                                               */
/* ============================================================================ */

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
void *websocket_bridge_server(void *arg);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SCL_WEBSOCKET_BRIDGE_H
