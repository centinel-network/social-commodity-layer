/**
 * @file common/utils.h
 * @brief Satocialist Protocol: Core Helper Routines, Telemetry, and Utility Interfaces
 *
 * @details
 * Declares common helper functions, deterministic financial arithmetic, constant-time
 * cryptographic utilities, timekeeping routines, block serialization pipelines,
 * consensus validation routines, and memory management interfaces across the SCL protocol.
 *
 * @section protocol_invariants System Invariants Enforced
 * - Fee Calculation (Theorem 3): `calculate_fee` enforces deterministic integer division
 *   using an approximation of Pi scaled by 10^17, eliminating architecture-dependent
 *   floating-point discrepancies.
 * - Supply Conservation (Theorems 4 & 5): Operations and coin consistency checks guarantee
 *   unspent subunits cannot exceed total minted subunits.
 * - Constant-Time Invariants: Cryptographic memory comparisons (`secure_memcmp`) and
 *   buffer clearance (`explicit_bzero`) execute without early-exit branch dependencies.
 *
 * @section threading_concurrency Threading Model & Synchronization
 * - Functions interacting with global ledger structures require explicit caller-side lock
 *   acquisition adhering to the global descending hierarchy (`state->mutex` ->
 *   `state->ledger_mutex` -> `state->bc.rwlock` -> `state->wallet_mutex`).
 * - Thread-local staging memory is managed via POSIX thread-specific storage keys
 *   (`get_l5_staging_buffer` / `release_l5_staging_buffer`).
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <ctype.h>
#ifndef __EMSCRIPTEN__
#endif
#include <arpa/inet.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* 1. TELEMETRY, STRUCTURED LOGGING & DIAGNOSTICS                               */
/* ============================================================================ */

/** @brief Active global log severity filter threshold. */
extern LogLevel current_log_level;

/**
 * @brief Dispatches a structured, JSON-formatted telemetry entry to the asynchronous log queue.
 *
 * @param[in] level Severity tier of the log event (see @ref LogLevel).
 * @param[in] component Formal subsystem identifier emitting the log.
 * @param[in] format Printf-style format string.
 * @param[in] ... Variadic argument list matching format specifiers.
 *
 * @pre String arguments must be null-terminated and valid within current thread scope.
 * @post JSON log record staged to `log_queue`; dropped with counter increment if ring is saturated.
 * @note Thread-safe. Non-blocking when asynchronous worker is running; falls back to mutex-locked synchronous write.
 * @complexity Time: O(K) where K is message length, Space: O(1) auxiliary.
 */
void scl_log(LogLevel level, const char *component, const char *format, ...);

/**
 * @brief Formats and dispatches a diagnostic log message to stderr with heuristic severity classification.
 *
 * @param[in] component Subsystem tag identifying source of the diagnostic message.
 * @param[in] format Printf-style format string.
 * @param[in] ... Variadic argument list.
 *
 * @pre Format string and arguments must be valid.
 * @post Evaluates message keywords for severity level and dispatches through `scl_log`.
 * @note Thread-safe. Muted when fuzzing harnesses are active.
 * @complexity Time: O(K), Space: O(1) auxiliary (stack buffer).
 */
void scl_log_stderr(const char *component, const char *format, ...);

/**
 * @brief Sets the global runtime log level threshold.
 *
 * @param[in] level Lowest severity tier allowed to emit output.
 *
 * @post `current_log_level` updated atomically. Messages below this level are discarded early.
 * @note Thread-safe.
 * @complexity Time: O(1), Space: O(1).
 */
void scl_log_set_level(LogLevel level);

/**
 * @brief Maps a numerical LogLevel enum value to its canonical uppercase string representation.
 *
 * @param[in] level Log severity tier.
 * @return Statically allocated null-terminated string representation ("TRACE", "DEBUG", etc.).
 *
 * @complexity Time: O(1), Space: O(1).
 */
const char* level_to_string(LogLevel level);

/**
 * @brief Blocks calling thread synchronously until all staged asynchronous log queue entries flush to disk.
 *
 * @post `log_tail` matches `log_head`, ensuring all pending stdout/stderr output is serialized.
 * @warning Blocks caller up to 2,000 milliseconds before timing out if writer thread stalls.
 * @complexity Time: O(N) where N is queued entries, Space: O(1).
 */
void scl_log_flush(void);

/**
 * @brief Asynchronously enqueues a formatted string for emission to a standard output stream.
 *
 * @param[in,out] stream Target destination file stream (typically `stdout` or `stderr`).
 * @param[in] format Printf-style format string.
 * @param[in] ... Variadic arguments.
 *
 * @note Thread-safe.
 * @complexity Time: O(K) where K is formatted byte length, Space: O(1).
 */
void scl_fprintf(FILE *stream, const char *format, ...);

/**
 * @brief Asynchronously enqueues a formatted string for emission to standard output (`stdout`).
 *
 * @param[in] format Printf-style format string.
 * @param[in] ... Variadic arguments.
 *
 * @note Thread-safe.
 * @complexity Time: O(K), Space: O(1).
 */
void scl_printf(const char *format, ...);

/**
 * @brief Formats a binary byte slice into standard hexadecimal ASCII and logs to stdout.
 *
 * @param[in] prefix Textual label prepended to output line.
 * @param[in] data Pointer to binary buffer.
 * @param[in] len Logical length of binary data in bytes.
 * @param[in] max_len Maximum bytes printed from data (truncates if len > max_len).
 *
 * @pre `data` must point to at least `min(len, max_len)` readable bytes.
 * @complexity Time: O(min(len, max_len)), Space: O(min(len, max_len)) heap allocation.
 */
void log_hex(const char *prefix, const uint8_t *data, size_t len, size_t max_len);

/* ============================================================================ */
/* 2. HIGH-RESOLUTION TIMING & CHRONOMETRY                                      */
/* ============================================================================ */

/**
 * @brief Returns system wall-clock time in microseconds since UNIX epoch (UTC).
 *
 * @return Microseconds since UNIX epoch (1970-01-01 00:00:00 UTC).
 * @note Subject to NTP time adjustments and discontinuous wall-clock shifts.
 *       Used for transaction timestamps and audit matrix synchronization.
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t get_real_time_us(void);

/**
 * @brief Returns raw monotonic clock time in microseconds since an unspecified boot anchor.
 *
 * @return Microseconds elapsed on the monotonic timer.
 * @note Guaranteed strictly non-decreasing; immune to NTP time steps.
 *       Mandatory for transport loss detection, RTT calculations, and BBRv3 token pacing.
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t get_time_us(void);

/**
 * @brief Returns raw monotonic clock time converted to milliseconds.
 *
 * @return Milliseconds elapsed on monotonic timer (`get_time_us() / 1000`).
 * @complexity Time: O(1), Space: O(1).
 */
uint64_t get_time_ms(void);

/* ============================================================================ */
/* 3. DETERMINISTIC FINANCIAL ARITHMETIC & FEE MODEL                            */
/* ============================================================================ */

/**
 * @brief Deterministically evaluates required transaction fee in subunits using exact 128-bit integer math.
 *
 * @details
 * Formalized in Lean 4 (`Satocialist.calculateFee`). Computes integer division:
 * `floor((amount * 3,141,592,653,589,793) / 10^17)` for normal peer-to-peer transfers (~3.14159%),
 * or doubles the denominator to `2 * 10^17` when `halve = true` for staking/unstaking (~1.57079%).
 * Multiplications evaluate strictly within unsigned 128-bit space without overflow (Theorem 3.1).
 *
 * @param[in] amount Asset magnitude in atomic subunits.
 * @param[in] halve Flag: `true` halves fee rate (staking/unstaking); `false` standard fee.
 * @return Total non-refundable fee required in atomic subunits.
 *
 * @pre `amount <= MAX_TOTAL_SUBUNITS` to guarantee 128-bit multiplicative safety bounds.
 * @complexity Time: O(1) constant-time integer arithmetic, Space: O(1).
 */
uint64_t calculate_fee(uint64_t amount, bool halve);

/* ============================================================================ */
/* 4. CONSTANT-TIME CRYPTOGRAPHIC UTILITIES & HASHING                           */
/* ============================================================================ */

/**
 * @brief Encodes a byte array into lowercase hexadecimal ASCII string with null-termination.
 *
 * @param[in] data Pointer to binary source data.
 * @param[in] len Number of bytes to convert.
 * @param[out] out_buffer Destination buffer; must allocate at least `(len * 2) + 1` bytes.
 *
 * @pre `out_buffer` must not overlap with `data`.
 * @post `out_buffer` contains exactly `len * 2` hex chars followed by `\0`.
 * @complexity Time: O(N), Space: O(1) auxiliary.
 */
void bytes_to_hex(const uint8_t *data, size_t len, char *out_buffer);

/**
 * @brief Constant-time cryptographic memory comparison resistant to timing side-channels.
 *
 * @param[in] a Pointer to first memory buffer.
 * @param[in] b Pointer to second memory buffer.
 * @param[in] len Total bytes to compare.
 * @return 0 if buffers are identical across all `len` bytes; 1 if any bit diverges.
 *
 * @note Operates in constant execution time proportional strictly to `len`.
 * @complexity Time: O(N), Space: O(1).
 */
int secure_memcmp(const void *a, const void *b, size_t len);

/**
 * @brief Evaluates whether a memory buffer is filled entirely with zero bytes.
 *
 * @param[in] buf Pointer to memory buffer.
 * @param[in] len Length of buffer in bytes.
 * @return `true` if all bytes are zero (or len is 0); `false` if any non-zero byte encountered.
 *
 * @complexity Time: O(N) worst case, Space: O(1).
 */
bool is_zeroed(const uint8_t *buf, size_t len);

/**
 * @brief Securely clears sensitive memory buffers with a compiler-barrier preventing dead-store elimination.
 *
 * @param[in,out] s Pointer to target memory block.
 * @param[in] n Number of bytes to zeroize.
 *
 * @post Target memory block overwritten with zeros; guaranteed not to be optimized out.
 * @complexity Time: O(N), Space: O(1).
 */
void explicit_bzero(void *s, size_t n);

/**
 * @brief Computes single-shot SHA-256 digest of input buffer using OpenSSL EVP interfaces.
 *
 * @param[in] input Pointer to input byte stream.
 * @param[in] in_len Length of input stream in bytes.
 * @param[out] output 32-byte destination buffer receiving the SHA-256 digest.
 *
 * @pre `output` must point to at least 32 writable bytes.
 * @complexity Time: O(N), Space: O(1).
 */
void sha256_hash(const uint8_t *input, size_t in_len, uint8_t *output);

/**
 * @brief Generates an ephemeral transaction identifier derived from an anti-replay nonce and timestamp.
 *
 * @param[in] nonce 8-byte anti-replay salt.
 * @param[out] temp_tx_id 32-byte destination buffer receiving SHA256(nonce || microsecond_timestamp_be).
 *
 * @complexity Time: O(1), Space: O(1).
 */
void compute_temp_tx_id(const uint8_t nonce[8], uint8_t temp_tx_id[COIN_ID_LEN]);

/**
 * @brief Computes 64-bit SipHash-2-4 message checksum for L5 RPC wire framing.
 *
 * @param[in] msg_payload Complete serialized RPC wire message.
 * @param[in] error_msg_len Byte length of optional ASCII error string in header.
 * @param[in] payload_len Byte length of arguments/data payload in header.
 * @param[in] rpc_siphash_key 16-byte session SipHash key derived from KEM shared secret.
 * @return 64-bit unsigned SipHash-2-4 checksum.
 *
 * @complexity Time: O(M) where M is wire message length, Space: O(1) auxiliary.
 */
uint64_t compute_rpc_checksum(const uint8_t *msg_payload, uint16_t error_msg_len, uint32_t payload_len, const uint8_t rpc_siphash_key[16]);

/**
 * @brief Validates structural encoding bounds of a Dilithium5 public verification key.
 *
 * @param[in] pubkey Pointer to candidate 2,592-byte key buffer.
 * @return 1 if key is non-NULL and non-zeroed; 0 otherwise.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int validate_dilithium_pubkey(const uint8_t *pubkey);

/**
 * @brief Validates structural encoding bounds of a Kyber-512 public encapsulation key.
 *
 * @param[in] pubkey Pointer to candidate 800-byte key buffer.
 * @return 1 if key is non-NULL and non-zeroed; 0 otherwise.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int validate_kyber_pubkey(const uint8_t *pubkey);

/* ============================================================================ */
/* 5. TRANSACTION IDENTIFICATION, COMPARISON & EQUALITY PREDICATES              */
/* ============================================================================ */

/**
 * @brief Extracts canonical 32-byte transaction identifier from an operation payload.
 *
 * @param[in] op Pointer to Operation structure.
 * @return Pointer to 32-byte transaction hash or nullifier; NULL if operation type is invalid.
 *
 * @complexity Time: O(1), Space: O(1).
 */
const uint8_t* get_operation_tx_id(const Operation *op);

/**
 * @brief Comparator sorting Dilithium public key pointers lexicographically via memcmp.
 *
 * @param[in] a Pointer to first `const uint8_t*` pubkey pointer.
 * @param[in] b Pointer to second `const uint8_t*` pubkey pointer.
 * @return Negative if *a < *b, 0 if equal, positive if *a > *b.
 *
 * @complexity Time: O(PUBKEY_LEN), Space: O(1).
 */
int compare_pubkey_ptrs(const void *a, const void *b);

/**
 * @brief Comparator sorting Operation pointers deterministically by transaction ID.
 *
 * @param[in] a Pointer to first `const Operation*`.
 * @param[in] b Pointer to second `const Operation*`.
 * @return Negative if *a < *b, 0 if equal, positive if *a > *b.
 *
 * @complexity Time: O(COIN_ID_LEN), Space: O(1).
 */
int compare_operation_ptrs(const void *a, const void *b);

/**
 * @brief Deterministic comparator for qsort ordering operations for canonical block packing.
 *
 * @details
 * Enforces consensus invariant: Coinbase Mint operations (@ref OP_MINT_COIN) are prioritized
 * to the front of the block. Subsequent operations are sorted lexicographically by transaction ID.
 *
 * @param[in] a Pointer to first Operation struct.
 * @param[in] b Pointer to second Operation struct.
 * @return Negative if a precedes b, positive if b precedes a, 0 if equal.
 *
 * @complexity Time: O(COIN_ID_LEN), Space: O(1).
 */
int compare_operations(const void *a, const void *b);

/**
 * @brief Comparator sorting Pointer structures descending by subunit volume (`end - start + 1`).
 *
 * @param[in] a Pointer to first `const Pointer*`.
 * @param[in] b Pointer to second `const Pointer*`.
 * @return Negative if a > b (larger volume precedes), positive if a < b.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int compare_pointers_desc(const void *a, const void *b);

/**
 * @brief Comparator sorting Peer structures lexicographically by Dilithium public keys.
 *
 * @param[in] a Pointer to first `const Peer*`.
 * @param[in] b Pointer to second `const Peer*`.
 * @return Lexicographical comparison result of `peer_wallet.dilithium_pubkey`.
 *
 * @complexity Time: O(DILITHIUM_PUBKEY_LEN), Space: O(1).
 */
int compare_peers(const void *a, const void *b);

/**
 * @brief Structural equality predicate comparing two on-chain Operations.
 *
 * @param[in] op1 Pointer to first Operation.
 * @param[in] op2 Pointer to second Operation.
 * @return 1 if operations possess identical types, parameters, amounts, and signatures; 0 otherwise.
 *
 * @complexity Time: O(K) where K is operation payload size, Space: O(1).
 */
int operation_equals(const Operation *op1, const Operation *op2);

/* ============================================================================ */
/* 6. BLOCK SERIALIZATION, HASHING & MERKLE ACCUMULATION                        */
/* ============================================================================ */

/**
 * @brief Single-pass streaming block serializer and hashing engine.
 *
 * @details
 * Simultaneously writes serialized block wire bytes into `out_buf` (if non-NULL)
 * and updates an active OpenSSL EVP hashing digest context `ctx` (if non-NULL).
 * Guarantees binary identity between serialization and hash computation without double allocation.
 *
 * @param[in] block Pointer to source Block structure.
 * @param[out] out_buf Destination serialization buffer (or NULL for hashing-only mode).
 * @param[in,out] ctx OpenSSL SHA-256 context (or NULL for serialization-only mode).
 * @param[in] include_signature Flag: `true` includes consensus signatures; `false` computes pre-sign digest.
 * @return Total bytes written/hashed on success; negative value on error.
 *
 * @pre At least one of `out_buf` or `ctx` must be non-NULL.
 * @complexity Time: O(N) where N is block byte footprint, Space: O(1) auxiliary.
 */
int process_block_data(const Block *block, uint8_t *out_buf, EVP_MD_CTX *ctx, bool include_signature);

/**
 * @brief Evaluates the canonical SHA-256 header hash of a block (excluding signatures).
 *
 * @param[in] block Pointer to Block structure.
 * @param[out] hash 32-byte destination buffer receiving the block hash.
 * @return 0 on success, -1 on failure.
 *
 * @complexity Time: O(N) where N is block operation count, Space: O(1).
 */
int compute_block_hash(const Block *block, uint8_t *hash);

/**
 * @brief Computes binary Merkle tree root over transaction input pointer data.
 *
 * @param[in] inputs Array of Pointer structures representing spent inputs.
 * @param[in] num_inputs Number of elements in inputs array (clamped to @ref MAX_INPUTS).
 * @param[out] root 32-byte destination buffer receiving the computed Merkle root.
 *
 * @pre `num_inputs <= MAX_INPUTS`.
 * @complexity Time: O(M log M) where M = num_inputs, Space: O(M) stack buffers.
 */
void compute_inputs_merkle_root(const Pointer inputs[], uint32_t num_inputs, uint8_t *root);

/**
 * @brief Computes the SHA-256 digest of an MMR leaf node (`SHA256(coin_id || remaining_subunits_be)`).
 *
 * @param[in] coin_id 32-byte parent coin identifier.
 * @param[in] remaining_subunits Unspent subunit balance remaining on coin.
 * @param[out] output 32-byte destination buffer receiving the leaf hash.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void hash_leaf(const uint8_t *coin_id, uint64_t remaining_subunits, uint8_t *output);

/**
 * @brief Computes the SHA-256 parent node digest from left and right children in an MMR.
 *
 * @param[in] left 32-byte left child digest.
 * @param[in] right 32-byte right child digest.
 * @param[out] output 32-byte destination buffer receiving `SHA256(left || right)`.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void hash_node(const uint8_t *left, const uint8_t *right, uint8_t *output);

/**
 * @brief Generic modulo hash function mapping binary keys to table bucket indices.
 *
 * @param[in] key Pointer to key buffer.
 * @param[in] table_size Total bucket count in target hash table.
 * @return Bucket index in range `[0, table_size - 1]`.
 *
 * @complexity Time: O(1), Space: O(1).
 */
uint32_t hash_func(const uint8_t *key, size_t table_size);

/**
 * @brief Instantiates a default genesis block (Block 0) initialized to all zeros.
 *
 * @return Initialized Block struct with block_number=0 and zeroed hashes.
 * @complexity Time: O(1), Space: O(1).
 */
Block create_standard_genesis_block(void);

/**
 * @brief Initializes and commits the canonical genesis block to state if the blockchain is empty.
 *
 * @param[in,out] state Global node state container.
 * @return 0 on success or if genesis already committed; -1 on error.
 *
 * @pre Caller must not hold `state->ledger_mutex` or `state->bc.rwlock` (acquired internally).
 * @complexity Time: O(1), Space: O(1).
 */
int initialize_genesis_block(State *state);

/**
 * @brief Computes canonical SHA-256 state anchor digest over an SCLCoin structure.
 *
 * @details
 * Hashes immutable coin identity fields, total/remaining subunits, and frozen 10x10 Game Audit
 * snapshot rows to produce a tamper-evident anchor committed into minted block rewards.
 *
 * @param[in] coin Pointer to SCLCoin structure.
 * @param[out] hash 32-byte destination buffer receiving canonical digest.
 *
 * @complexity Time: O(1), Space: O(1) heap allocation.
 */
void compute_canonical_sclcoin_hash(const SCLCoin *coin, uint8_t *hash);

/* ============================================================================ */
/* 7. MEMORY STAGING, HARDWARE POOLING & NETWORK DRIVERS                        */
/* ============================================================================ */

/**
 * @brief Acquires thread-local 8 MiB scratch buffer for large serialization/deserialization workflows.
 *
 * @return Pointer to thread-local 8 MiB buffer; NULL if system memory budget exhausted.
 * @note Managed via POSIX thread-specific storage. Reusable across calls within the same thread.
 * @complexity Time: O(1), Space: O(1).
 */
uint8_t *get_l5_staging_buffer(void);

/**
 * @brief Releases and frees the calling thread's thread-local 8 MiB staging buffer.
 *
 * @post Thread-specific staging buffer memory freed and pointer reset to NULL.
 * @complexity Time: O(1), Space: O(1).
 */
void release_l5_staging_buffer(void);

/**
 * @brief Discovers current Path MTU for target destination socket to prevent IP fragmentation.
 *
 * @param[in] fd Bound UDP socket file descriptor.
 * @param[in] addr Remote destination address context.
 * @return Discovered Path MTU in octets (clamped to Link MTU boundaries: `[1232, 1280]`).
 *
 * @complexity Time: O(1), Space: O(1).
 */
size_t scl_get_path_mtu(int fd, const struct sockaddr_storage *addr);

/* ============================================================================ */
/* 8. USER ACCOUNT RESOLUTION & CLI INPUT VALIDATION                            */
/* ============================================================================ */

/**
 * @brief Resolves a 32-byte User ID to its corresponding 2,592-byte Dilithium5 public key.
 *
 * @details
 * Checks in order: 1) local user table, 2) local pubkey cache, 3) active P2P known peers,
 * 4) network-wide query broadcast (`MSG_GET_PUBKEY_BY_USERID`) with exponential backoff.
 *
 * @param[in,out] state Global node state container.
 * @param[in] user_id 32-byte SHA-256 digest of target public key.
 * @param[out] pubkey_out Destination buffer receiving 2,592-byte public key.
 * @return 1 on successful resolution; 0 if key cannot be resolved.
 *
 * @complexity Time: O(1) local cache hit; O(timeout) on network query.
 */
int get_pubkey_by_userid(State *state, const uint8_t *user_id, uint8_t *pubkey_out);

/**
 * @brief Reads and validates an integer from stdin in interactive CLI mode.
 *
 * @return Non-negative integer parsed from user input; -1 on EOF, interrupt, or shutdown.
 * @complexity Time: O(input length), Space: O(1).
 */
int validate_integer_input(void);

/**
 * @brief Reads and parses a floating-point currency amount (SCL) from stdin.
 *
 * @return Positive floating-point amount; -1.0 on invalid input or shutdown.
 * @complexity Time: O(input length), Space: O(1).
 */
double validate_money_input(void);

/**
 * @brief Reads a fixed-length hexadecimal string from stdin and decodes into raw bytes.
 *
 * @param[out] buf Destination byte array.
 * @param[in] len Expected byte length (reads exactly `len * 2` hex characters).
 * @return 0 on success; -1 on length mismatch, invalid character, or interrupt.
 *
 * @complexity Time: O(len), Space: O(len).
 */
int read_hex_input(uint8_t *buf, size_t len);

/* ============================================================================ */
/* 9. BLOCKCHAIN LEDGER, BALANCE CONSISTENCY & SNAPSHOTS                        */
/* ============================================================================ */

/**
 * @brief Calculates total unspent subunits remaining across all active pointers belonging to a coin.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @return Sum of unspent atomic subunits belonging to the coin.
 *
 * @pre Caller must hold `bc->rwlock` in read or write mode.
 * @complexity Time: O(P) where P is pointers mapped to coin, Space: O(P) temporary array.
 */
uint64_t calculate_coin_remaining(Blockchain *bc, const uint8_t coin_id[COIN_ID_LEN]);

/**
 * @brief Validates that a coin's remaining subunits do not exceed its immutable total subunits.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[in] coin_id 32-byte coin identifier.
 * @return 1 if consistent (`remaining <= total`); 0 if invariant violated.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int check_coin_consistency(Blockchain *bc, const uint8_t coin_id[COIN_ID_LEN]);

/**
 * @brief Atomically publishes a new immutable GameStateSnapshot reflecting latest game state.
 *
 * @param[in,out] state Global node state container.
 *
 * @post `state->active_snapshot_ptr` updated; previous snapshot enqueued for deferred RCU retirement.
 * @note Thread-safe. Acquires `state->game_state.mutex` and `state->snapshot_update_mutex`.
 * @complexity Time: O(AUDIT_SIZE), Space: O(1) heap allocation.
 */
void update_game_state_snapshot(State *state);

/**
 * @brief Acquires reference to the current active GameStateSnapshot with atomic reference count increment.
 *
 * @param[in] state Global node state container.
 * @return Retained pointer to current GameStateSnapshot; must be released via @ref release_game_state_snapshot.
 *
 * @note Lock-free read path.
 * @complexity Time: O(1), Space: O(1).
 */
GameStateSnapshot *acquire_game_state_snapshot(State *state);

/**
 * @brief Decrements snapshot reference count, freeing heap memory when count reaches zero.
 *
 * @param[in] snapshot Pointer to GameStateSnapshot to release.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void release_game_state_snapshot(GameStateSnapshot *snapshot);

/**
 * @brief Verifies whether candidate input pointers have sufficient unspent balance to satisfy a transfer/stake.
 *
 * @param[in] state Global node state container.
 * @param[in] owner_pubkey 2,592-byte Dilithium public key of expected owner.
 * @param[in] inputs Array of candidate Pointer structures.
 * @param[in] num_inputs Number of input pointers.
 * @param[in] required_amount Total required subunits (transfer amount + fee).
 * @param[in] expect_staked `true` validates staked inputs (unstaking); `false` validates liquid inputs.
 * @return 0 if balance is sufficient and inputs valid; 1 if insufficient or invalid.
 *
 * @pre Caller must hold `state->bc.rwlock` in read mode.
 * @complexity Time: O(num_inputs^2) duplicate scan, Space: O(num_inputs) stack buffer.
 */
int has_insufficient_balance_locked(State *state, const uint8_t *owner_pubkey,
                                    const Pointer *inputs, uint32_t num_inputs,
                                    uint64_t required_amount, bool expect_staked);

/* ============================================================================ */
/* 10. MEMPOOL INGESTION, FEE BUMPING & BACKGROUND TASK DELEGATION               */
/* ============================================================================ */

/**
 * @brief Enqueues a validated valuation proposal message to the local submission queue.
 *
 * @param[in,out] state Global node state container.
 * @param[in] msg Pointer to Message structure (`MSG_VALUATION_PROPOSAL` or `MSG_PENDING_OPERATION`).
 * @return 0 on success; -1 on validation or enqueue failure.
 *
 * @post Wakes sleeping submission worker thread via `pthread_cond_signal`.
 * @complexity Time: O(1), Space: O(msg->length) heap allocation.
 */
int enqueue_submission(State *state, const Message *msg);

/**
 * @brief Ingests an unconfirmed operation into the lock-free mempool with Replace-By-Fee evaluation.
 *
 * @details
 * Validates operation integrity, verifies inputs are unspent, enforces Replace-By-Fee (RBF)
 * rules requiring higher fees to replace existing transactions, and evicts lowest-fee
 * transactions if mempool capacity (@ref MAX_PENDING_OPS) is exhausted.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Pointer to Operation structure to ingest.
 * @return 0 on successful insertion; -1 if rejected (duplicate, low fee); -2 on double-spend.
 *
 * @note Thread-safe. Uses atomic CAS operations on `state->pending_operations` array slots.
 * @complexity Time: O(MAX_PENDING_OPS), Space: O(1) heap allocation.
 */
int add_pending_operation(State *state, const Operation *op);

/**
 * @brief Evicts confirmed operations from the local mempool following block commitment.
 *
 * @param[in,out] state Global node state container.
 * @param[in] block Committed block whose operations must be purged from mempool.
 *
 * @post Mempool slots occupied by block's transactions cleared; invalidated dependent transactions
 *       re-queued for background recreation.
 * @complexity Time: O(MAX_PENDING_OPS * block->operation_count), Space: O(1) heap buffers.
 */
void clean_pending_operations(State *state, Block *block);

/**
 * @brief Spawns or dispatches an asynchronous transaction recreation task to a work-stealing queue.
 *
 * @param[in,out] state Global node state container.
 * @param[in] args Heap-allocated recreation context; callee assumes ownership.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void spawn_recreation_thread(State *state, RecreateArgs *args);

/**
 * @brief Worker thread loop executing asynchronous transaction recreation with work-stealing.
 *
 * @param[in] arg Pointer to heap-allocated `struct WorkerArgs`.
 * @return NULL upon thread termination.
 * @complexity Time: O(work), Space: O(1).
 */
void *recreation_worker_loop(void *arg);

/**
 * @brief Blocks calling thread until specified number of valid peer connections achieve ESTABLISHED status.
 *
 * @param[in,out] state Global node state container.
 * @param[in] timeout_seconds Maximum wait duration in seconds.
 *
 * @complexity Time: O(timeout_seconds), Space: O(1).
 */
void wait_for_valid_peers(State *state, int timeout_seconds);

/**
 * @brief Broadcasts batched peer address synchronization messages across all active connections.
 *
 * @param[in,out] state Global node state container.
 *
 * @complexity Time: O(num_known_peers), Space: O(num_known_peers) stack/heap buffers.
 */
void broadcast_peer_list_sync(State *state);

/**
 * @brief Dynamically resizes a valuation array buffer doubling capacity when full.
 *
 * @param[in,out] valuations Pointer to dynamic array pointer.
 * @param[in] valuation_count Pointer to current element count.
 * @param[in,out] valuation_capacity Pointer to allocated capacity.
 *
 * @complexity Time: O(N) on reallocation, amortized O(1), Space: O(capacity).
 */
void resize_valuation_array(Valuation **valuations, unsigned int *valuation_count, unsigned int *valuation_capacity);

/* ============================================================================ */
/* 11. QUANTUM AUDITING & PROOF-OF-SYMMETRY (PoS2)                              */
/* ============================================================================ */

/**
 * @brief Evaluates whether a target integer appears in a matrix column via quantum superposition measurement.
 *
 * @param[in] target_number Integer tested for constructive interference (0..99).
 * @param[in] column_numbers Array of integers appearing in the target column.
 * @param[in] N Number of entries in column.
 * @param[in] active_nodes Distinct validator identity count contributing to column.
 * @param[in] beacon_seed 32-byte randomness beacon seed from current epoch threshold signature.
 * @return 1 if target number is measured upon quantum state collapse; 0 otherwise.
 *
 * @complexity Time: O(M) where M is shot budget [1000..50000], Space: O(1) statevector array.
 */
int quantum_check_number_in_column(int target_number, const int *column_numbers, size_t N, size_t active_nodes, const uint8_t *beacon_seed);

/**
 * @brief Verifies whether an exact valuation vector currently exists in the circular Game Audit matrix.
 *
 * @param[in] gs Pointer to GameState structure.
 * @param[in] v Pointer to candidate Valuation structure.
 * @return 1 if valuation matches an existing slot; 0 otherwise.
 *
 * @complexity Time: O(AUDIT_SIZE), Space: O(1).
 */
int is_valuation_in_audit(GameState *gs, const Valuation *v);

/**
 * @brief Computes or retrieves cached Joint-RSS threshold public key for current epoch committee.
 *
 * @param[in,out] state Global node state container.
 * @param[out] threshold_pubkey 2,592-byte buffer receiving Dilithium5 threshold public key.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(1) cached; O(keygen) if cache expired.
 */
int compute_threshold_pubkey(State *state, uint8_t threshold_pubkey[PUBKEY_LEN]);

/* ============================================================================ */
/* 12. SHIELDED CENTINEL UTXO SCANNING & BEARER TOKENS                          */
/* ============================================================================ */

/**
 * @brief Scans an on-chain OP_REDEEM_CENTINEL operation to detect incoming transfer or change commitments.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Pointer to Operation structure.
 *
 * @complexity Time: O(SCL_WALLET_SCAN_WINDOW), Space: O(1).
 */
void scl_wallet_scan_centinel_op(State *state, const Operation *op);

/**
 * @brief Scans an on-chain OP_CLAIM_VALIDATION operation to register new validation UTXO commitments.
 *
 * @param[in,out] state Global node state container.
 * @param[in] op Pointer to Operation structure.
 *
 * @complexity Time: O(SCL_WALLET_SCAN_WINDOW), Space: O(1).
 */
void scl_wallet_scan_claim_op(State *state, const Operation *op);

/**
 * @brief Rescans blockchain block history to rebuild the local wallet's unspent validation UTXO set.
 *
 * @param[in,out] state Global node state container.
 *
 * @complexity Time: O(block_count * operations_per_block * scan_window), Space: O(commitments).
 */
void scl_wallet_rescan_utxos(State *state);

/**
 * @brief Finds the first sequential SCL_VAL_UTXO derivation tag whose (tag, amount) nullifier is unspent.
 *
 * @param[in] state Global node state container.
 * @param[in] privkey 4,864-byte Dilithium private key owning the tag space.
 * @param[in] amount Committed value the caller will pair with the tag.
 * @param[in] start_tag First tag index to probe (wallet tag high-water mark).
 * @return First unspent tag, or start_tag when the guard window is exhausted.
 *
 * @complexity Time: O(guard * BDLOP_COMMIT), Space: O(1).
 */
size_t scl_next_unspent_val_tag(State *state, const uint8_t *privkey, uint64_t amount, size_t start_tag);

/**
 * @brief Consumes and burns unspent validation UTXOs to cover the cost of submitting valuations.
 *
 * @param[in,out] state Global node state container.
 * @param[in] amount Number of validation credits to burn.
 * @return 0 on success; -1 if available unspent validation credits are insufficient.
 *
 * @complexity Time: O(num_utxos), Space: O(num_utxos) heap buffers.
 */
int consume_utxos_for_amount(State *state, uint64_t amount);

#ifdef __cplusplus
}
#endif

#endif // UTILS_H
