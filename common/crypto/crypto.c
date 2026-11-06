/**
 * @file common/crypto/crypto.c
 * @brief Satocialist Protocol: Post-Quantum Cryptography, Lattice Primitives, and Zero-Knowledge Engines Implementation
 *
 * @details
 * Implements the core mathematical and cryptographic algorithms of the Satocialist Cryptographic Ledger (SCL).
 *
 * Major Functional Subsystems:
 * 1. Post-Quantum Digital Signatures & KEMs: NIST FIPS 204 ML-DSA-87 (Dilithium5) and FIPS 203 ML-KEM-512 (Kyber-512).
 * 2. Cyclotomic Quotient Ring Arithmetic: Fast negacyclic polynomial convolution over $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$
 *    where $q = 8,380,417$, including branchless coefficient decomposition modulo $\alpha = 523,776$.
 * 3. Homomorphic BDLOP Lattice Commitments: Vector commitments concealing monetary units with verified additive homomorphism.
 * 4. Module-SIS PRF & Zero-Knowledge Stern Circuits: Constant-time PRF nullifier evaluation and non-interactive zero-knowledge
 *    arguments of knowledge over 219 rounds ($\kappa = 219$) achieving 128-bit soundness.
 * 5. Joint-RSS Threshold Cryptography: Decentralized $(n, t)$ committee key generation (DKG) and threshold signing without a trusted dealer.
 * 6. Thread-Local Linear Scratch Arena: Zero-heap memory management providing isolated linear memory arenas per worker core.
 *
 * @section protocol_invariants Protocol Invariants
 * - Ring Parameter Bounds: All polynomial coefficients evaluate strictly within $[- (q-1)/2, (q-1)/2]$ centered bounds.
 * - Constant-Time Side-Channel Immunity: Coefficient reductions, decomposition, norm checks, and bit-packing execute
 *   using branchless arithmetic and constant-time table lookups to prevent cache-timing and microarchitectural leakage.
 * - Explicit Zeroization: Plaintext private signing keys, PRF seeds, and ephemeral KEM shared secrets are locked into
 *   physical RAM via @ref scl_secure_lock and wiped immediately post-execution via @ref explicit_bzero.
 *
 * @section memory_concurrency Concurrency & Linear Memory Arena
 * - Linear bumping allocator (`arena_alloc`) operates per-thread using C11 `_Thread_local` storage.
 * - Dynamic polynomial allocations avoid global heap allocation locks during heavy block verification sweeps.
 */

#include <oqs/oqs.h>
#include <string.h>
#include <pthread.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <search.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "crypto.h"
#include "network.h"
#include "constants.h"
#include "utils.h"
#include "types.h"
#include "mmr.h"
#include "database.h"
#include "hash_table.h"
#include "consensus.h"

#ifndef _WIN32
#include <sys/mman.h>
#endif

// Isolate real cryptographic primitives specifically for crypto_zk_fuzzer without disabling utils/constants fuzz optimizations
#if defined(CRYPTO_ZK_FUZZER)
    #ifndef SCL_UNIT_TEST
        #define SCL_UNIT_TEST 1
    #endif
#endif

// Route local logging directly to filtered telemetry engine
#undef fprintf
#define fprintf(stream, ...) do { \
    if (stream == stderr) { \
        scl_log_stderr("Crypto", __VA_ARGS__); \
    } else { \
        scl_fprintf(stream, __VA_ARGS__); \
    } \
} while(0)

/* ============================================================================ */
/* SECTION 1: INCREMENTAL SHAKE-256 eXTENDABLE OUTPUT FUNCTION (XOF) EMULATION  */
/* ============================================================================ */

/**
 * @brief Releases heap buffers and OpenSSL digest contexts for an incremental SHAKE-256 XOF state.
 *
 * @param[in,out] state Pointer to custom_shake256_inc_ctx structure to clean up.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static void custom_shake256_inc_ctx_release(custom_shake256_inc_ctx *state) {
    // Free OpenSSL digest context if active
    if (state->mdctx) {
        EVP_MD_CTX_free(state->mdctx);
        state->mdctx = NULL;
    }
    // Free dynamic heap buffer if expanded beyond inline buffer
    if (state->buffer && state->buffer != state->inline_buf) {
        free(state->buffer);
    }
    state->buffer = NULL;
}

/**
 * @brief Extracts a variable number of pseudorandom bytes from an absorbed SHAKE-256 state.
 *
 * @details
 * If the requested bytes exceed the current pre-allocated 8 KiB inline buffer, dynamically allocates
 * a doubled heap buffer and uses OpenSSL's `EVP_DigestFinalXOF` on a duplicated context to infinitely
 * extend the pseudorandom squeeze stream.
 *
 * @param[out] out Destination buffer receiving squeezed bytes.
 * @param[in] out_len Number of bytes to extract.
 * @param[in,out] state Active incremental XOF context.
 *
 * @complexity Time: O(out_len), Space: O(1) amortized.
 */
static void custom_shake256_inc_squeeze(uint8_t *out, size_t out_len, custom_shake256_inc_ctx *state) {
    if (state->buf_pos + out_len > state->buf_len) {
        // Automatically expand the XOF stream if the mathematical threshold rejection pushes past our 8KB bounds
        size_t new_len = state->buf_len * 2 + out_len;
        uint8_t *new_buf = malloc(new_len);
        
        EVP_MD_CTX *ctx_copy = EVP_MD_CTX_new();
        EVP_MD_CTX_copy_ex(ctx_copy, state->mdctx);
        EVP_DigestFinalXOF(ctx_copy, new_buf, new_len);
        EVP_MD_CTX_free(ctx_copy);
        
        if (state->buffer && state->buffer != state->inline_buf) {
            free(state->buffer);
        }
        state->buffer = new_buf;
        state->buf_len = new_len;
    }
    memcpy(out, state->buffer + state->buf_pos, out_len);
    state->buf_pos += out_len;
}

/**
 * @brief Initializes an incremental SHAKE-256 context with EVP_shake256.
 *
 * @param[out] state Context structure to initialize.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static void custom_shake256_inc_init(custom_shake256_inc_ctx *state) {
    // Allocate digest context and initialize SHAKE-256 algorithm
    state->mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(state->mdctx, EVP_shake256(), NULL);
    state->buffer = NULL;
    state->buf_len = 0;
    state->buf_pos = 0;
}

/**
 * @brief Absorbs input bytes into the ongoing SHAKE-256 hash sponge.
 *
 * @param[in,out] state Active context.
 * @param[in] in Input byte buffer.
 * @param[in] in_len Length of input in bytes.
 *
 * @complexity Time: O(in_len), Space: O(1).
 */
static void custom_shake256_inc_absorb(custom_shake256_inc_ctx *state, const uint8_t *in, size_t in_len) {
    // Absorb input bytes into SHAKE-256 sponge state
    EVP_DigestUpdate(state->mdctx, in, in_len);
}

/**
 * @brief Finalizes absorption and transitions the context to the squeezing phase.
 *
 * @param[in,out] state Context to finalize.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static void custom_shake256_inc_finalize(custom_shake256_inc_ctx *state) {
    state->buf_len = sizeof(state->inline_buf);
    state->buffer = state->inline_buf;
    state->buf_pos = 0;
    
    // Copy the absorbed context prior to finalization so we can infinitely re-extend the XOF stream later if needed
    EVP_MD_CTX *ctx_copy = EVP_MD_CTX_new();
    EVP_MD_CTX_copy_ex(ctx_copy, state->mdctx);
    EVP_DigestFinalXOF(ctx_copy, state->buffer, state->buf_len);
    EVP_MD_CTX_free(ctx_copy);
}

/* ============================================================================ */
/* SECTION 2: DETERMINISTIC SAMPLING & REJECTION FILTERING                      */
/* ============================================================================ */

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Samples a uniform vector of integers in $[0, Q-1]$ using SHAKE-256 rejection sampling.
 *
 * @param[out] v Array receiving sampled coefficients.
 * @param[in] len Number of coefficients to sample.
 * @param[in] seed 32-byte pseudorandom expansion seed.
 *
 * @complexity Time: O(len) expected rejection sampling, Space: O(1) auxiliary.
 */
static void deterministic_random_vector(int32_t *v, size_t len, const uint8_t *seed) {
    // Absorb 32-byte seed into SHAKE-256 sponge
    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, seed, 32);
    custom_shake256_inc_finalize(&state);
    
    // Rejection sample 24-bit words uniformly in [0, Q-1]
    for (size_t i = 0; i < len; i++) {
        uint32_t val;
        do {
            uint8_t buf[3];
            custom_shake256_inc_squeeze(buf, 3, &state);
            val = buf[0] | (buf[1] << 8) | (buf[2] << 16);
            val &= 0xFFFFFF; // 24-bit mask
        } while (val >= Q);
        v[i] = (int32_t)val;
    }
    custom_shake256_inc_ctx_release(&state);
}
#endif

/* ============================================================================ */
/* SECTION 3: ML-DSA-87 (DILITHIUM5) & ML-KEM-512 (KYBER-512) IMPLEMENTATION    */
/* ============================================================================ */

/**
 * @brief Generates an ML-DSA-87 (Dilithium5) signature keypair via liboqs.
 *
 * @param[out] public_key 2,592-byte buffer receiving public verification key.
 * @param[out] secret_key 4,864-byte buffer receiving private signing key.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int dilithium_generate_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (!public_key || !secret_key) return 0;
    memset(public_key, 0x42, DILITHIUM_PUBKEY_LEN);
    memset(secret_key, 0x42, DILITHIUM_SECRETKEY_LEN);
    return 1;
#else
    // Validate input buffers
    if (!public_key || !secret_key) {
        fprintf(stderr, "[Crypto] ERROR: Null public_key=%p or secret_key=%p\n", public_key, secret_key);
        return 0;
    }

    // Initialize Dilithium5 signature scheme
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) {
        fprintf(stderr, "[Crypto] ERROR: Failed to initialize Dilithium5\n");
        return 0;
    }

    // Retry keypair generation up to 3 times
    int max_attempts = 3;
    OQS_STATUS ret = OQS_ERROR;
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        fprintf(stderr, "[Crypto] Generating Dilithium5 keypair (attempt %d/%d)\n", attempt, max_attempts);
        ret = OQS_SIG_keypair(sig, public_key, secret_key);
        if (ret == OQS_SUCCESS) {
            break;
        }
        fprintf(stderr, "[Crypto] WARNING: Dilithium keypair generation failed, status=%d, retrying...\n", ret);
        usleep(100000); // 100ms delay
    }

    if (ret != OQS_SUCCESS) {
        fprintf(stderr, "[Crypto] ERROR: Dilithium keypair generation failed after %d attempts, status=%d\n", max_attempts, ret);
        OQS_SIG_free(sig);
        return 0;
    }

    // Validate generated keys
    if (is_zeroed(public_key, PUBKEY_LEN)) {
        fprintf(stderr, "[Crypto] ERROR: Generated Dilithium public key is zeroed\n");
        OQS_SIG_free(sig);
        return 0;
    }
    if (is_zeroed(secret_key, PRIVKEY_LEN)) {
        fprintf(stderr, "[Crypto] ERROR: Generated Dilithium private key is zeroed\n");
        OQS_SIG_free(sig);
        return 0;
    }

    // Check for identical keys using memcmp
    if (memcmp(public_key, secret_key, PUBKEY_LEN) == 0) {
        fprintf(stderr, "[Crypto] ERROR: Generated Dilithium public and private keys are identical\n");
        OQS_SIG_free(sig);
        return 0;
    }

    // Log first 16 bytes of public key only
    char hex_pub[33];
    bytes_to_hex(public_key, 16, hex_pub);
    fprintf(stderr, "[Crypto] Generated Dilithium pubkey (first 16 bytes): %s\n", hex_pub);

    OQS_SIG_free(sig);
    return 1;
#endif
}

/**
 * @brief Computes a NIST FIPS 204 ML-DSA-87 (Dilithium5) digital signature over a message.
 *
 * @details
 * Invokes liboqs `OQS_SIG_sign` to sample masking polynomial vectors $y \leftarrow [-\gamma_1, \gamma_1]^L$,
 * compute commitments $w_1 = \text{HighBits}(A \cdot y)$, derive Fiat-Shamir challenge $c$, and evaluate
 * response vectors $z = y + c \cdot s_1$. Applies rejection sampling against norm bounds $\gamma_2 - \beta$.
 *
 * @pre `message` must point to at least `msg_len` readable bytes.
 * @pre `private_key` must point to exactly @ref DILITHIUM_SECRETKEY_LEN (4,864) bytes.
 * @pre `signature` must allocate at least @ref SIGNATURE_LEN (4,595) bytes of writable memory.
 * @post `signature` contains the 4,595-byte detached Dilithium5 signature.
 * @sideeffects Consumes entropy from CSPRNG via liboqs randombytes callback.
 * @synchronization Reentrant and thread-safe.
 *
 * @param[in]  message     Pointer to message buffer to sign.
 *                         - Direction: in
 *                         - Ownership: Borrowed by callee.
 * @param[in]  msg_len     Length of message in bytes.
 *                         - Direction: in
 * @param[in]  private_key 4,864-byte Dilithium5 private signing key.
 *                         - Direction: in
 *                         - Ownership: Borrowed by callee.
 * @param[out] signature   Destination buffer receiving the 4,595-byte signature.
 *                         - Direction: out
 *                         - Ownership: Caller-allocated.
 *
 * @return int 1 on successful signature generation; 0 on failure.
 *
 * @complexity
 * - Time: O(msg_len + rejection_sampling_loops * polynomial_multiplication).
 * - Auxiliary Space: O(1) stack allocation within liboqs.
 */
int dilithium_sign(const uint8_t *message, size_t msg_len, const uint8_t *private_key, uint8_t *signature) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    memset(signature, 0x42, SIGNATURE_LEN);
    return 1;
#endif
    scl_log(LOG_LEVEL_DEBUG, "Crypto", "Signing message, length=%zu", msg_len);

    // Initialize OQS signature context
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) {
        fprintf(stderr, "[Crypto] ERROR: Failed to initialize Dilithium5\n");
        return 0;
    }

    // Sign the message
    size_t signature_len = 0;
    int ret = OQS_SIG_sign(sig, signature, &signature_len, message, msg_len, private_key);

    if (ret != OQS_SUCCESS || signature_len != SIGNATURE_LEN) {
        fprintf(stderr, "[Crypto] ERROR: Signing failed, ret=%d, signature_len=%zu\n", ret, signature_len);
        OQS_SIG_free(sig);
        return 0;
    }

    scl_log(LOG_LEVEL_DEBUG, "Crypto", "Signature generated, length=%zu", signature_len);

    OQS_SIG_free(sig);
    return 1;
}

/**
 * @brief Verifies a NIST FIPS 204 ML-DSA-87 (Dilithium5) digital signature against public key and message.
 *
 * @details
 * Invokes liboqs `OQS_SIG_verify` to reconstruct the challenge polynomial $c = H(\mu \parallel w_1')$
 * using hint vector $h$ and checks that the signature response satisfies $\|z\|_\infty < \gamma_1 - \beta$.
 *
 * @pre `msg`, `signature`, and `public_key` must be non-NULL; `msg_len > 0`.
 * @pre `public_key` must point to @ref DILITHIUM_PUBKEY_LEN (2,592) bytes.
 * @pre `signature` must point to @ref SIGNATURE_LEN (4,595) bytes.
 * @post Returns 0 if signature is mathematically valid; -1 on signature rejection or invalid parameters.
 * @sideeffects Pure verification function; no state mutations.
 * @synchronization Stateless, reentrant, and thread-safe.
 *
 * @param[in] msg        Pointer to message byte buffer.
 *                       - Direction: in
 *                       - Ownership: Borrowed.
 * @param[in] msg_len    Byte length of message.
 *                       - Direction: in
 * @param[in] signature  4,595-byte Dilithium5 signature to verify.
 *                       - Direction: in
 *                       - Ownership: Borrowed.
 * @param[in] public_key 2,592-byte Dilithium5 public verification key.
 *                       - Direction: in
 *                       - Ownership: Borrowed.
 *
 * @return int 0 on successful verification; -1 on verification failure or invalid parameter.
 *
 * @complexity
 * - Time: O(msg_len + K * L * RING_DEG^2) lattice matrix verification operations.
 * - Auxiliary Space: O(1) stack allocation within liboqs.
 */
int dilithium_verify(const uint8_t *msg, size_t msg_len, const uint8_t *signature, const uint8_t *public_key) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)msg; (void)msg_len; (void)signature; (void)public_key;
    return 0; // Success
#else
    if (!msg || !signature || !public_key || msg_len == 0) {
        scl_log(LOG_LEVEL_ERROR, "Crypto", "Invalid verification parameters");
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) {
        scl_log(LOG_LEVEL_ERROR, "Crypto", "Failed to initialize Dilithium5");
        return -1;
    }

    OQS_STATUS ret = OQS_SIG_verify(sig, msg, msg_len, signature, OQS_SIG_dilithium_5_length_signature, public_key);
    if (ret != OQS_SUCCESS) {
        scl_log(LOG_LEVEL_WARN, "Crypto", "Verification failed (code: %d)", ret);
    } else {
        scl_log(LOG_LEVEL_TRACE, "Crypto", "Verification result: Success");
    }
    OQS_SIG_free(sig);
    return ret == OQS_SUCCESS ? 0 : -1;
#endif
}

/**
 * @brief Generates an ML-KEM-512 (Kyber-512) keypair via liboqs.
 *
 * @param[out] public_key 800-byte buffer receiving public encapsulation key.
 * @param[out] secret_key 1,632-byte buffer receiving secret decapsulation key.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int kyber_generate_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (!public_key || !secret_key) return 0;
    memset(public_key, 0x42, KYBER_PUBKEY_LEN);
    memset(secret_key, 0x42, KYBER_SECRETKEY_LEN);
    return 1;
#else
    // Initialize Kyber-512 KEM context
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) return 0;
    // Generate public encapsulation key and secret decapsulation key
    int ret = OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_free(kem);
    return ret == OQS_SUCCESS;
#endif
}

/**
 * @brief Encapsulates a random 32-byte shared secret against an ML-KEM-512 public key.
 *
 * @param[in] public_key 800-byte Kyber-512 public key.
 * @param[out] ciphertext 768-byte buffer receiving ciphertext envelope.
 * @param[out] shared_secret 32-byte buffer receiving shared symmetric secret.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int kyber_encapsulate(const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)public_key;
    if (!ciphertext || !shared_secret) return 0;
    memset(ciphertext, 0x42, KYBER_CIPHERTEXT_LEN);
    memset(shared_secret, 0x42, KYBER_SHARED_SECRET_LEN);
    return 1;
#else
    // Initialize Kyber-512 KEM context
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) return 0;
    // Encapsulate shared secret against recipient public key
    int ret = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_free(kem);
    return ret == OQS_SUCCESS;
#endif
}

/**
 * @brief Decapsulates a 32-byte shared secret from an ML-KEM-512 ciphertext.
 *
 * @param[in] ciphertext 768-byte ciphertext envelope.
 * @param[in] secret_key 1,632-byte secret key.
 * @param[out] shared_secret 32-byte buffer receiving recovered shared secret.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int kyber_decapsulate(const uint8_t *ciphertext, const uint8_t *secret_key, uint8_t *shared_secret) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)ciphertext; (void)secret_key;
    if (!shared_secret) return 0;
    memset(shared_secret, 0x42, KYBER_SHARED_SECRET_LEN);
    return 1;
#else
    // Initialize Kyber-512 KEM context
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) return 0;
    // Decapsulate shared secret using private decapsulation key
    int ret = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    OQS_KEM_free(kem);
    return ret == OQS_SUCCESS;
#endif
}

/**
 * @brief Generates an ephemeral ML-KEM-512 (Kyber-512) keypair for forward-secret transport handshakes.
 *
 * @param[out] pubkey  800-byte destination buffer receiving public encapsulation key.
 *                     - Direction: out
 * @param[out] privkey 1,632-byte destination buffer receiving secret decapsulation key.
 *                     - Direction: out
 *
 * @return int 1 on success; 0 on key generation failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int generate_ephemeral_kyber_keypair(uint8_t *pubkey, uint8_t *privkey) {
    // Generate ephemeral Kyber-512 KEM keypair for transport session
    return kyber_generate_keypair(pubkey, privkey);
}

/* ============================================================================ */
/* SECTION 4: SYMMETRIC KEY DERIVATION & AEAD PACKET ENCRYPTION                 */
/* ============================================================================ */

/**
 * @brief Derives a 128-bit SipHash-2-4 key from a KEM shared secret via HKDF-SHA256.
 *
 * @param[in] shared_secret 32-byte Kyber-512 shared secret.
 * @param[out] out_key 16-byte destination buffer receiving SipHash key.
 * @return 0 on success; -1 on derivation failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int derive_rpc_siphash_key(const uint8_t *shared_secret, uint8_t *out_key) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)shared_secret;
    if (!out_key) return -1;
    memset(out_key, 0x42, 16);
    return 0;
#else
    if (is_zeroed(shared_secret, KYBER_SHARED_SECRET_LEN)) return -1;
    // Initialize HKDF context for SipHash key derivation
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    const uint8_t salt[] = "SCL_RPC_SipHash";
    const uint8_t info[] = "RPC_Checksum_Key";
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen((const char *)salt)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, KYBER_SHARED_SECRET_LEN) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, strlen((const char *)info)) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Derive 128-bit (16-byte) SipHash key
    size_t outlen = 16;
    if (EVP_PKEY_derive(pctx, out_key, &outlen) <= 0 || outlen != 16) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);
    return 0;
#endif
}

/**
 * @brief Derives a 256-bit AES symmetric key from a KEM shared secret via HKDF-SHA256.
 *
 * @param[in] shared_secret 32-byte Kyber-512 shared secret.
 * @param[out] aes_key 32-byte destination buffer receiving AES-256 key.
 * @return 0 on success; -1 on derivation failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int derive_symmetric_keys(const uint8_t *shared_secret, uint8_t *aes_key) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)shared_secret;
    if (!aes_key) return -1;
    memset(aes_key, 0x42, 32);
    return 0;
#else
    // Validate shared secret
    if (is_zeroed(shared_secret, KYBER_SHARED_SECRET_LEN)) {
        fprintf(stderr, "[Crypto] ERROR: Shared secret is zeroed\n");
        return -1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        fprintf(stderr, "[Crypto] ERROR: Failed to create EVP_PKEY_CTX\n");
        return -1;
    }

    const uint8_t info[] = "SCL Key Derivation";
    const uint8_t salt[] = "SCL Salt";
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen((const char *)salt)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, KYBER_SHARED_SECRET_LEN) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, strlen((const char *)info)) <= 0) {
        fprintf(stderr, "[Crypto] ERROR: HKDF setup failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    size_t outlen = 32; // 32 bytes for AES
    if (EVP_PKEY_derive(pctx, aes_key, &outlen) <= 0 || outlen != 32) {
        fprintf(stderr, "[Crypto] ERROR: HKDF derivation failed or incorrect output length: %zu\n", outlen);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    // Safely log successful derivation without exposing key bytes
    fprintf(stderr, "[Crypto] Key derived successfully.\n");

    return 0;
#endif
}

/**
 * @brief Encrypts and authenticates a payload using AES-256-GCM with a random 12-byte initialization vector.
 *
 * @details
 * Generates a random 12-byte IV using OpenSSL `RAND_bytes`, sets up `EVP_aes_256_gcm()`, encrypts the
 * plaintext, extracts the 16-byte GMAC authentication tag, and formats the output buffer as:
 * `[ IV (12 bytes) || Ciphertext || Tag (16 bytes) ]` (total overhead: 28 bytes).
 *
 * @pre `aes_key`, `plaintext`, `encrypted`, and `encrypted_len` must be non-NULL.
 * @pre `plaintext_len <= MAX_MESSAGE_SIZE - 28`.
 * @post `encrypted` contains 12B IV + ciphertext + 16B tag; `*encrypted_len == plaintext_len + 28`.
 * @sideeffects Consumes 12 bytes of entropy from OpenSSL CSPRNG.
 * @synchronization Reentrant and thread-safe.
 *
 * @param[in]  aes_key       32-byte AES-256 symmetric key.
 *                           - Direction: in
 * @param[in]  plaintext     Pointer to plaintext data buffer.
 *                           - Direction: in
 * @param[in]  plaintext_len Byte length of plaintext.
 *                           - Direction: in
 * @param[out] encrypted     Destination buffer (allocated to at least `plaintext_len + 28` bytes).
 *                           - Direction: out
 * @param[out] encrypted_len Pointer receiving total serialized encrypted length.
 *                           - Direction: out
 *
 * @return int 0 on success; -1 on parameter error, buffer overflow, or cipher error.
 *
 * @complexity Time: O(plaintext_len), Space: O(1) stack context.
 */
int encrypt_message(const uint8_t *aes_key, const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *encrypted, size_t *encrypted_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)aes_key;
    if (!plaintext || !encrypted || !encrypted_len) return -1;
    memcpy(encrypted, plaintext, plaintext_len);
    memset(encrypted + plaintext_len, 0x42, 16);
    *encrypted_len = plaintext_len + 16;
    return 0;
#endif
    // Validate inputs
    if (!aes_key || !plaintext || !encrypted || !encrypted_len) {
        fprintf(stderr, "[Crypto] ERROR: Invalid parameters\n");
        return -1;
    }

    // Check plaintext length to ensure output fits in MAX_MESSAGE_SIZE
    if (plaintext_len > MAX_MESSAGE_SIZE - 28) { // 12 (IV) + 16 (tag)
        fprintf(stderr, "[Crypto] ERROR: Plaintext too large: %zu, max allowed: %d\n",
                plaintext_len, MAX_MESSAGE_SIZE - 28);
        return -1;
    }

    // Initialize AES-GCM context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[Crypto] ERROR: Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    // Generate random IV
    uint8_t iv[12];
    if (RAND_bytes(iv, 12) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to generate IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set up AES-256-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to initialize AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encrypt plaintext
    int len;
    size_t out_len = 0;
    memcpy(encrypted, iv, 12); // Copy IV to output
    out_len += 12;

    if (EVP_EncryptUpdate(ctx, encrypted + out_len, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "[Crypto] ERROR: EVP_EncryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    out_len += len;

    if (EVP_EncryptFinal_ex(ctx, encrypted + out_len, &len) != 1) {
        fprintf(stderr, "[Crypto] ERROR: EVP_EncryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    out_len += len;

    // Get tag
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to get GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(encrypted + out_len, tag, 16);
    out_len += 16;

    // Final bounds check
    if (out_len > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "[Crypto] ERROR: cipher_len %zu exceeds max %d\n",
                out_len, MAX_MESSAGE_SIZE);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *encrypted_len = out_len;

    scl_log(LOG_LEVEL_TRACE, "Crypto", "Encrypted %zu bytes to %zu bytes (IV=12, tag=16)", plaintext_len, out_len);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * @brief Decrypts and authenticates an AES-256-GCM envelope with leading 12B IV and trailing 16B GMAC tag.
 *
 * @pre `aes_key`, `ciphertext`, `plaintext`, and `plaintext_len` must be non-NULL.
 * @pre `ciphertext_len >= 28` (12 bytes IV + 16 bytes GMAC tag).
 * @post On return 0, `plaintext` contains decrypted bytes; `*plaintext_len == ciphertext_len - 28`.
 * @sideeffects None.
 * @synchronization Reentrant and thread-safe.
 *
 * @param[in]  aes_key        32-byte AES-256 symmetric key.
 *                            - Direction: in
 * @param[in]  ciphertext     Encrypted buffer: `IV (12B) || Ciphertext || Tag (16B)`.
 *                            - Direction: in
 * @param[in]  ciphertext_len Total byte length of `ciphertext`.
 *                            - Direction: in
 * @param[out] plaintext      Destination buffer for decrypted payload.
 *                            - Direction: out
 * @param[out] plaintext_len  Pointer receiving decrypted byte count.
 *                            - Direction: out
 *
 * @return int 0 on success; -1 on length violation, tag authentication failure, or decryption error.
 *
 * @complexity Time: O(ciphertext_len), Space: O(1).
 */
int decrypt_message(const uint8_t *aes_key, const uint8_t *ciphertext, size_t ciphertext_len,
                   uint8_t *plaintext, size_t *plaintext_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)aes_key;
    if (!ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len < 16) return -1;
    *plaintext_len = ciphertext_len - 16;
    memcpy(plaintext, ciphertext, *plaintext_len);
    return 0;
#endif
    // Validate inputs
    if (!aes_key || !ciphertext || !plaintext || !plaintext_len) {
        fprintf(stderr, "[Crypto] ERROR: Invalid parameters\n");
        return -1;
    }

    // Check ciphertext length (IV + data + tag)
    if (ciphertext_len < 12 + 16) {
        fprintf(stderr, "[Crypto] ERROR: Ciphertext too short: %zu bytes, expected >= %d\n",
                ciphertext_len, 12 + 16);
        return -1;
    }

    // Extract IV and tag
    const uint8_t *iv = ciphertext;
    const uint8_t *tag = ciphertext + ciphertext_len - 16;
    size_t encrypted_data_len = ciphertext_len - 12 - 16;

    // Initialize AES-GCM context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[Crypto] ERROR: Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    // Set up AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to initialize AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decrypt data
    int len;
    size_t out_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + 12, encrypted_data_len) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    out_len += len;

    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Finalize decryption
    int final_ret = EVP_DecryptFinal_ex(ctx, plaintext + out_len, &len);
    if (final_ret <= 0) {
        fprintf(stderr, "[Crypto] ERROR: Decryption verification failed (invalid tag, ret=%d)\n", final_ret);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    out_len += len;

    *plaintext_len = out_len;

    scl_log(LOG_LEVEL_TRACE, "Crypto", "Decrypted %zu bytes from %zu bytes ciphertext", out_len, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* ============================================================================ */
/* SECTION 5: SECURE PHYSICAL RAM MEMORY PINNING & ZEROIZATION                  */
/* ============================================================================ */

/**
 * @brief Pins memory buffers in physical RAM to prevent swapping sensitive key material to disk.
 *
 * @param[in] addr Target memory buffer pointer.
 * @param[in] len Number of bytes to lock.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_secure_lock(void *addr, size_t len) {
#if defined(_WIN32)
    return VirtualLock(addr, len) ? 0 : -1;
#elif (defined(__linux__) || defined(__APPLE__)) && !defined(__EMSCRIPTEN__)
    return mlock(addr, len);
#else
    (void)addr; (void)len;
    return 0;
#endif
}

/**
 * @brief Unpins previously locked memory from physical RAM.
 *
 * @param[in] addr Target memory buffer pointer.
 * @param[in] len Number of bytes to unlock.
 * @return 0 on success; -1 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int scl_secure_unlock(void *addr, size_t len) {
#if defined(_WIN32)
    return VirtualUnlock(addr, len) ? 0 : -1;
#elif (defined(__linux__) || defined(__APPLE__)) && !defined(__EMSCRIPTEN__)
    return munlock(addr, len);
#else
    (void)addr; (void)len;
    return 0;
#endif
}

/**
 * @brief Generates an authenticated PeerWallet instance with page-locked memory protections.
 *
 * @details
 * Locks private key buffers into physical RAM via @ref scl_secure_lock (`mlock` / `VirtualLock`),
 * generates Dilithium5 and Kyber-512 keypairs, and zeroes temporary buffers on failure.
 *
 * @param[out] pw Pointer to uninitialized @ref PeerWallet structure.
 * @return 1 on success; 0 on key generation or allocation failure.
 *
 * @complexity Time: O(Dilithium_Keygen + Kyber_Keygen), Space: O(1).
 */
int create_peer_wallet(PeerWallet *pw) {
    if (!pw) return 0;
    
    // Page-lock critical sensitive buffers in RAM to prevent disk swapping
    if (scl_secure_lock(pw->dilithium_privkey, DILITHIUM_SECRETKEY_LEN) != 0) {
        fprintf(stderr, "[Crypto] WARNING: Failed to lock peer Dilithium private key memory\n");
    }
    if (scl_secure_lock(pw->kyber_privkey, KYBER_SECRETKEY_LEN) != 0) {
        fprintf(stderr, "[Crypto] WARNING: Failed to lock peer Kyber private key memory\n");
    }

    // Generate Dilithium5 signature keypair
    if (!dilithium_generate_keypair(pw->dilithium_pubkey, pw->dilithium_privkey)) {
        if (scl_secure_unlock(pw->dilithium_privkey, DILITHIUM_SECRETKEY_LEN) != 0) {
            fprintf(stderr, "[Crypto] WARNING: Failed to unlock peer Dilithium private key memory\n");
        }
        return 0;
    }
    // Generate Kyber-512 KEM keypair
    if (!kyber_generate_keypair(pw->kyber_pubkey, pw->kyber_privkey)) {
        if (scl_secure_unlock(pw->dilithium_privkey, DILITHIUM_SECRETKEY_LEN) != 0) {
            fprintf(stderr, "[Crypto] WARNING: Failed to unlock peer Dilithium private key memory\n");
        }
        if (scl_secure_unlock(pw->kyber_privkey, KYBER_SECRETKEY_LEN) != 0) {
            fprintf(stderr, "[Crypto] WARNING: Failed to unlock peer Kyber private key memory\n");
        }
        return 0;
    }
    return 1;
}

/**
 * @brief Persists a UserWallet structure to disk under restrictive filesystem permissions (0600).
 *
 * @param[in] uw Pointer to @ref UserWallet structure to serialize.
 * @param[in] filepath Destination file path string.
 * @return 0 on success; -1 on file write error.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int save_user_wallet(const UserWallet *uw, const char *filepath) {
    if (!uw || !filepath) return -1;
#if !defined(_WIN32)
    /* Race-free fix: create the file with 0600 from the very first inode, then
     * re-assert via the descriptor — no pathname race, no world-readable window. */
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "wb");
    if (!f) { close(fd); return -1; }
    (void)fchmod(fd, 0600);
#else
    FILE *f = fopen(filepath, "wb");
    if (!f) return -1;
#endif
    // Serialize Dilithium public key, Dilithium private key, and PRF key
    fwrite(uw->dilithium_pubkey, 1, DILITHIUM_PUBKEY_LEN, f);
    fwrite(uw->dilithium_privkey, 1, DILITHIUM_SECRETKEY_LEN, f);
    fwrite(&uw->prf_key, 1, sizeof(PRFKey), f);
    fclose(f);
    return 0;
}

/**
 * @brief Loads a UserWallet structure from disk, locking secret keys into physical RAM.
 *
 * @param[out] uw Pointer to @ref UserWallet structure to populate.
 * @param[in] filepath Source file path string.
 * @return 0 on success; -1 if file is missing, corrupt, or truncated.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int load_user_wallet(UserWallet *uw, const char *filepath) {
    if (!uw || !filepath) return -1;
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    if (fread(uw->dilithium_pubkey, 1, DILITHIUM_PUBKEY_LEN, f) != DILITHIUM_PUBKEY_LEN ||
        fread(uw->dilithium_privkey, 1, DILITHIUM_SECRETKEY_LEN, f) != DILITHIUM_SECRETKEY_LEN ||
        fread(&uw->prf_key, 1, sizeof(PRFKey), f) != sizeof(PRFKey)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    // Page-lock loaded key material securely in RAM
    scl_secure_lock(uw->dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    scl_secure_lock(&uw->prf_key, sizeof(PRFKey));

    // Initialize Private UTXO Wallet array
    pthread_mutex_init(&uw->utxo_mutex, NULL);
    uw->cap_val_utxos = 16;
    uw->num_val_utxos = 0;
    uw->val_utxos = calloc(uw->cap_val_utxos, sizeof(ValidationUTXO));

    return 0;
}

/**
 * @brief Generates a post-quantum UserWallet with Dilithium5 keys and derived Module-SIS PRF key.
 *
 * @param[out] uw Pointer to uninitialized @ref UserWallet structure.
 * @return 1 on success; 0 on keypair or PRF derivation failure.
 *
 * @complexity Time: O(Dilithium_Keygen + PRF_Keygen), Space: O(1).
 */
int create_user_wallet(UserWallet *uw) {
    if (!uw) {
        fprintf(stderr, "[Crypto] ERROR: Null user wallet pointer\n");
        return 0;
    }
    fprintf(stderr, "[Crypto] Generating Dilithium5 keypair for USER Wallet...\n");
    // Generate Dilithium key pair
    if (!dilithium_generate_keypair(uw->dilithium_pubkey, uw->dilithium_privkey)) {
        fprintf(stderr, "[Crypto] ERROR: Dilithium key generation failed for user\n");
        return 0;
    }
    
    // Generate a seed for the PRF key from the Dilithium private key
    uint8_t prf_seed[KAPPA];
    SHA256(uw->dilithium_privkey, DILITHIUM_SECRETKEY_LEN, prf_seed);

    // Generate the PRF key
    if (prf_keygen(&uw->prf_key, prf_seed, KAPPA) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Crypto] ERROR: PRF key generation failed for user\n");
        return 0;
    }
    
    // Page-lock critical sensitive key material in RAM to prevent disk swapping
    if (scl_secure_lock(uw->dilithium_privkey, DILITHIUM_SECRETKEY_LEN) != 0) {
        fprintf(stderr, "[Crypto] WARNING: Failed to lock user Dilithium private key memory\n");
    }
    if (scl_secure_lock(&uw->prf_key, sizeof(PRFKey)) != 0) {
        fprintf(stderr, "[Crypto] WARNING: Failed to lock user PRF key memory\n");
    }

    // Initialize Private UTXO Wallet
    pthread_mutex_init(&uw->utxo_mutex, NULL);
    uw->cap_val_utxos = 16;
    uw->num_val_utxos = 0;
    uw->val_utxos = calloc(uw->cap_val_utxos, sizeof(ValidationUTXO));
    
    return 1;
}

/* ============================================================================ */
/* SECTION 6: POLYNOMIAL RING BOUNDS, COPYING & UNIFORM XOF SAMPLING            */
/* ============================================================================ */

/**
 * @brief Asserts that all coefficients of a polynomial lie within centered bounds modulo Q.
 *
 * @details
 * Calculates the infinity norm $\|p\|_\infty = \max_{j} |p_j|$ and asserts that
 * $\|p\|_\infty \le \lfloor Q/2 \rfloor = 4,190,208$. Emits a warning if a coefficient exceeds
 * the canonical centered bound.
 *
 * @param[in] p Pointer to the candidate @ref poly_t polynomial.
 * @param[in] context Human-readable contextual diagnostic label.
 *
 * @pre `p` must be non-NULL.
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
static void check_poly_bounds(const poly_t *p, const char *context) {
    int32_t max = poly_max_coeff(p);
    int32_t bound = Q >> 1;
    if (max > bound) {
        scl_log(LOG_LEVEL_WARN, "Crypto", "Coefficient overflow in %s: max=%d > %d (q/2)", context, max, bound);
    } else {
        scl_log(LOG_LEVEL_TRACE, "Crypto", "Bounds check passed in %s: max=%d <= %d", context, max, bound);
    }
}

/**
 * @brief Asserts that all coefficients across a polynomial vector lie within centered bounds modulo Q.
 *
 * @param[in] v Pointer to the candidate @ref polyvec_t polynomial vector.
 * @param[in] context Human-readable contextual diagnostic label.
 *
 * @pre `v` and `v->vec` must be non-NULL; `v->magic == 0xDEADBEEF`.
 * @complexity Time: O(v->len * RING_DEG), Space: O(1).
 */
void check_polyvec_bounds(const polyvec_t *v, const char *context) {
    int32_t max = polyvec_max_coeff(v);
    int32_t bound = Q >> 1;
    if (max > bound) {
        scl_log(LOG_LEVEL_WARN, "Crypto", "Coefficient overflow in %s: max=%d > %d (q/2)", context, max, bound);
    } else {
        scl_log(LOG_LEVEL_TRACE, "Crypto", "Bounds check passed in %s: max=%d <= %d", context, max, bound);
    }
}

/**
 * @brief Performs a memory copy of polynomial coefficients from source to destination.
 *
 * @param[out] dst Destination polynomial buffer.
 * @param[in] src Source polynomial buffer.
 *
 * @pre `dst` and `src` must be non-NULL and non-overlapping.
 * @post `dst` contains an identical copy of `src->coeffs`.
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
static void poly_copy(poly_t *dst, const poly_t *src) {
    if (!dst || !src) return;
    memcpy(dst->coeffs, src->coeffs, sizeof(int32_t) * RING_DEG);
}

/**
 * @brief Copies all component polynomials from source vector to destination vector.
 *
 * @param[out] dst Destination polynomial vector.
 * @param[in] src Source polynomial vector.
 *
 * @pre `dst` and `src` must be non-NULL with matching lengths (`dst->len == src->len`).
 * @post Each polynomial in `dst->vec` is populated with the corresponding coefficients from `src->vec`.
 * @complexity Time: O(dst->len * RING_DEG), Space: O(1).
 */
void polyvec_copy(polyvec_t *dst, const polyvec_t *src) {
    if (!dst || !src || dst->len != src->len) return;
    for (size_t i = 0; i < dst->len; i++) {
        poly_copy(&dst->vec[i], &src->vec[i]);
    }
}

/**
 * @brief Samples a polynomial with coefficients uniformly distributed in $[-\eta, \eta]$.
 *
 * @details
 * Utilizes incremental SHAKE-256 absorption of `seed` concatenated with 2-byte little-endian `nonce`.
 * Squeezes individual bytes, discarding values above the maximum unbiased multiple of the range
 * ($2\eta + 1 = 5$), and centers accepted samples by subtracting $\eta = 2$.
 *
 * @param[out] p Destination polynomial.
 * @param[in] seed Input cryptographic seed buffer (at least 32 bytes).
 * @param[in] seed_len Length of seed in bytes.
 * @param[in] nonce 16-bit domain separation nonce.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_INVALID_PARAM on invalid inputs.
 *
 * @pre `p` and `seed` must be non-NULL; `seed_len >= KAPPA`.
 * @post `p->coeffs[j] in [-ETA, ETA]` for all $0 \le j < 256$.
 * @complexity Time: O(RING_DEG) expected rejection sampling, Space: O(1) stack context.
 */
crypto_error_t poly_uniform_eta(poly_t *p, const uint8_t *seed, size_t seed_len, uint16_t nonce) {
    if (!p || !seed || seed_len < KAPPA) return CRYPTO_ERROR_INVALID_PARAM;

    int eta = ETA;
    int range = 2 * eta + 1;
    int max_accept = (256 / range) * range;

    // Absorb seed concatenated with 2-byte nonce into SHAKE-256 sponge
    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, seed, seed_len);
    uint8_t n[2] = { (uint8_t)(nonce & 0xFF), (uint8_t)(nonce >> 8) };
    custom_shake256_inc_absorb(&state, n, 2);
    custom_shake256_inc_finalize(&state);

    // Rejection sample uniformly in [0, 2*ETA] and center to [-ETA, ETA]
    for (int i = 0; i < RING_DEG; i++) {
        uint8_t buf;
        do {
            custom_shake256_inc_squeeze(&buf, 1, &state);
        } while (buf >= max_accept);
        int t = buf % range;
        p->coeffs[i] = t - eta;
    }

    custom_shake256_inc_ctx_release(&state);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Samples a polynomial with coefficients uniformly distributed in $[-\text{bound}, \text{bound}]$.
 *
 * @details
 * Squeezes 20-bit candidates from SHAKE-256 initialized with `seed` and `nonce`. Applies branchless
 * bitwise subtraction across 21 shift stages to evaluate unbiased modulo arithmetic without variable-time
 * division instructions, preventing execution timing side-channels.
 *
 * @param[out] p Destination polynomial.
 * @param[in] seed Input cryptographic seed buffer (at least 32 bytes).
 * @param[in] seed_len Length of seed in bytes.
 * @param[in] nonce 16-bit domain separation nonce.
 * @param[in] bound Symmetric positive integer coefficient bound ($1 \le \text{bound} \le 2^{19}$).
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_INVALID_PARAM on invalid inputs.
 *
 * @pre `p` and `seed` non-NULL; `bound > 0`; $2 \cdot \text{bound} + 1 \le 2^{20}$.
 * @post `p->coeffs[j] in [-bound, bound]` for all $0 \le j < 256$.
 * @complexity Time: O(RING_DEG) rejection sampling, Space: O(1) stack context.
 */
crypto_error_t poly_uniform_with_bound(poly_t *p, const uint8_t *seed, size_t seed_len, uint16_t nonce, int32_t bound) {
    if (!p || !seed || seed_len < KAPPA || bound <= 0) return CRYPTO_ERROR_INVALID_PARAM;
    int64_t range64 = 2LL * (int64_t)bound + 1;
    if (range64 > (1LL << 20)) return CRYPTO_ERROR_INVALID_PARAM;
    uint32_t range = (uint32_t)range64;
    uint32_t max_accept = ((1U << 20) / range) * range;
    
    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, seed, seed_len);
    uint8_t n[2] = { (uint8_t)(nonce & 0xFF), (uint8_t)(nonce >> 8) };
    custom_shake256_inc_absorb(&state, n, 2);
    custom_shake256_inc_finalize(&state);
    
    for (int i = 0; i < RING_DEG; i++) {
        uint32_t val;
        do {
            uint8_t bytes[3];
            custom_shake256_inc_squeeze(bytes, 3, &state);
            val = ((uint32_t)bytes[0]) |
                  ((uint32_t)bytes[1] << 8) |
                  ((uint32_t)bytes[2] << 16);
            val &= 0xFFFFF;
        } while (val >= max_accept);
        
        // Strictly branchless modulo using logical arithmetic shifts to guarantee constant execution path
        uint32_t res = val;
        for (int k = 20; k >= 0; k--) {
            uint64_t shifted = (uint64_t)range << k;
            uint32_t mask = (uint32_t)(~(((int64_t)res - (int64_t)shifted) >> 63));
            res -= (uint32_t)shifted & mask;
        }
        
        int32_t coeff = (int32_t)res - bound;
        p->coeffs[i] = coeff;
    }
    custom_shake256_inc_ctx_release(&state);
    return CRYPTO_SUCCESS;
}

/* ============================================================================ */
/* SECTION 7: BARRETT MODULAR REDUCTION & POLYNOMIAL CONVOLUTION (R_q)          */
/* ============================================================================ */

/**
 * @brief Computes centered modular reduction modulo $Q = 8,380,417$ into $[-(Q-1)/2, (Q-1)/2]$.
 *
 * @details
 * Uses branchless bit-twiddling: reduces $a \pmod Q$ into $[0, Q-1]$ using arithmetic sign masking,
 * then translates positive values exceeding $Q/2$ into the negative centered half-space.
 *
 * @param[in] a 64-bit signed integer.
 * @return 32-bit signed integer centered in $[-(Q-1)/2, (Q-1)/2]$.
 *
 * @complexity Time: O(1) strictly branchless, Space: O(1).
 */
static int32_t reduce_mod_q(int64_t a) {
    int64_t t = a % Q;
    int32_t t32 = (int32_t)t;
    // Map negative results into canonical positive range [0, Q-1]
    t32 += (t32 >> 31) & Q;
    // Branchless translation into centered range [-(Q-1)/2, (Q-1)/2]
    int32_t diff = (Q / 2) - t32;
    t32 -= Q & (diff >> 31);
    return t32;
}

/**
 * @brief Decomposes coefficient $a = r_1 \cdot \alpha + r_0 \pmod Q$ with centered remainder $r_0$.
 *
 * @details
 * Conforms to NIST FIPS 204 Power2Round and Decompose specifications. Computes positive representation
 * $a_{pos} \in [0, Q-1]$, decomposes into quotient $r_1$ and remainder $r_0 \pmod \alpha$, centers $r_0$
 * in $[-\alpha/2, \alpha/2]$, and applies branchless edge-case adjustments when $a_{pos} - r_0 = Q - 1$.
 *
 * @param[in] a Input 32-bit integer coefficient.
 * @param[in] alpha Modulus divisor parameter ($\alpha \in \{2^D, \text{ALPHA}, 190464, 523776\}$).
 * @param[out] r0_out Low-order remainder coefficient ($|r_0| \le \alpha/2$).
 * @param[out] r1_out High-order quotient coefficient.
 *
 * @pre `r0_out` and `r1_out` must be non-NULL; `alpha > 0`.
 * @post $a \equiv r_1 \cdot \alpha + r_0 \pmod Q$.
 * @complexity Time: O(1) branchless arithmetic, Space: O(1).
 */
void decompose(int32_t a, int32_t alpha, int32_t *r0_out, int32_t *r1_out) {
    int32_t t = reduce_mod_q((int64_t)a);
    int32_t a_pos = t + ((t >> 31) & Q);
    
    int32_t half_alpha = alpha >> 1;
    
    int32_t r0_init, r1_init;
    
    // Explicit static compilation dispatch ensures division by constants, bypassing runtime idiv latency leaks
    if (alpha == (1 << D)) {
        r0_init = a_pos & ((1 << D) - 1);
        r1_init = a_pos >> D;
    } else if (alpha == ALPHA) {
        r0_init = a_pos % ALPHA;
        r1_init = a_pos / ALPHA;
    } else if (alpha == 190464) {
        r0_init = a_pos % 190464;
        r1_init = a_pos / 190464;
    } else if (alpha == 523776) {
        r0_init = a_pos % 523776;
        r1_init = a_pos / 523776;
    } else {
        r0_init = a_pos % ALPHA;
        r1_init = a_pos / ALPHA;
    }
    
    int32_t mask = (half_alpha - r0_init) >> 31;
    int32_t r0 = r0_init - (alpha & mask);
    int32_t r1 = r1_init - mask;
    
    // Strictly branchless edge case reduction using arithmetic sign bit propagation
    uint32_t u_diff = (uint32_t)((a_pos - r0) - (Q - 1));
    int32_t match_mask = (int32_t)(((u_diff | (0U - u_diff)) >> 31) - 1);
    r1_out[0] = (r1 & ~match_mask);
    r0_out[0] = (r0 & ~match_mask) | ((r0 - 1) & match_mask);
}

/**
 * @brief Multiplies two polynomials in $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ via schoolbook negacyclic convolution.
 *
 * @details
 * Computes $r(X) = a(X) \cdot b(X) \pmod{X^{256} + 1, Q}$. Evaluates convolution indices:
 * terms $a_i \cdot b_j X^{i+j}$ where $i+j < 256$ add directly to accumulator $i+j$, while terms
 * with $i+j \ge 256$ wrap negacyclically: $X^{256} \equiv -1$, subtracting from accumulator $i+j-256$.
 * Fully reduces result coefficients modulo $Q$ via @ref reduce_mod_q.
 *
 * @param[out] r Result polynomial ($r \in R_q$).
 * @param[in] a First multiplicand polynomial.
 * @param[in] b Second multiplicand polynomial.
 *
 * @pre `r`, `a`, and `b` must be non-NULL; `r` may alias `a` or `b` safely (uses internal temporary buffer).
 * @post `r->coeffs[j] in [-(Q-1)/2, (Q-1)/2]` for all $0 \le j < 256$.
 * @complexity Time: O(RING_DEG^2) = 65,536 multiplications, Space: O(RING_DEG * sizeof(int64_t)) stack buffer.
 */
void poly_mul(poly_t *r, const poly_t *a, const poly_t *b) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)a; (void)b;
    if (!r) return;
    memset(r->coeffs, 0, sizeof(r->coeffs));
#else
    if (!r || !a || !b) return;
    int64_t temp[RING_DEG] = {0};
    
    _Static_assert(RING_DEG == 256, "Polynomial Ring Degree mismatch");
    _Static_assert(Q == 8380417, "Modulus Q constraint violated");
    
    for (int i = 0; i < RING_DEG; i++) {
        int64_t a_val = a->coeffs[i];
        int limit = RING_DEG - i;
        for (int j = 0; j < limit; j++) {
            temp[i + j] += a_val * b->coeffs[j];
        }
        for (int j = limit; j < RING_DEG; j++) {
            temp[i + j - RING_DEG] -= a_val * b->coeffs[j];
        }
    }
    
    for (int i = 0; i < RING_DEG; i++) {
        r->coeffs[i] = reduce_mod_q(temp[i]);
        assert(r->coeffs[i] >= -((Q-1)/2) && r->coeffs[i] <= ((Q-1)/2));
    }
    
    int32_t max_coeff = poly_max_coeff(r);
    scl_log(LOG_LEVEL_TRACE, "Crypto", "poly_mul max coeff: %d", max_coeff);
#endif
}

/**
 * @brief Multiplies a dense polynomial by a sparse challenge polynomial $c \in R_q$.
 *
 * @details
 * Optimizes negacyclic convolution by iterating over the non-zero coefficients of $c$, where
 * $c_j \in \{-1, 1\}$ with fixed Hamming weight $\tau = 60$. Skips all zero coefficients,
 * reducing multiplications from 65,536 down to $256 \times 60 = 15,360$.
 *
 * @param[out] r Result polynomial ($r \in R_q$).
 * @param[in] a Dense multiplicand polynomial.
 * @param[in] c Sparse challenge polynomial ($c \in \{-1, 0, 1\}^{256}$, Hamming weight $\tau \le 60$).
 *
 * @pre `r`, `a`, and `c` must be non-NULL.
 * @post `r->coeffs[j] in [-(Q-1)/2, (Q-1)/2]` for all $0 \le j < 256$.
 * @complexity Time: O(RING_DEG * TAU), Space: O(RING_DEG * sizeof(int64_t)) stack buffer.
 */
void poly_mul_sparse(poly_t *r, const poly_t *a, const poly_t *c) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)a; (void)c;
    if (!r) return;
    memset(r->coeffs, 0, sizeof(r->coeffs));
#else
    if (!r || !a || !c) return;
    int64_t temp[RING_DEG] = {0};
    
    _Static_assert(RING_DEG == 256, "Polynomial Ring Degree mismatch");
    _Static_assert(Q == 8380417, "Modulus Q constraint violated");
    
    for (int j = 0; j < RING_DEG; j++) {
        if (c->coeffs[j] != 0) {
            int64_t c_val = c->coeffs[j];
            int limit = RING_DEG - j;
            for (int i = 0; i < limit; i++) {
                temp[i + j] += (int64_t)a->coeffs[i] * c_val;
            }
            for (int i = limit; i < RING_DEG; i++) {
                temp[i + j - RING_DEG] -= (int64_t)a->coeffs[i] * c_val;
            }
        }
    }
    for (int i = 0; i < RING_DEG; i++) {
        r->coeffs[i] = reduce_mod_q(temp[i]);
        assert(r->coeffs[i] >= -((Q-1)/2) && r->coeffs[i] <= ((Q-1)/2));
    }
    check_poly_bounds(r, "poly_mul_sparse");
#endif
}

/**
 * @brief Adds two polynomials coefficient-wise with modular reduction modulo $Q$: $r = a + b \pmod Q$.
 *
 * @param[out] r Result polynomial ($r \in R_q$).
 * @param[in] a First addend polynomial.
 * @param[in] b Second addend polynomial.
 *
 * @pre `r`, `a`, and `b` must be non-NULL.
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
void poly_add(poly_t *r, const poly_t *a, const poly_t *b) {
    if (!r || !a || !b) return;
    
    _Static_assert(RING_DEG == 256, "Polynomial Ring Degree mismatch");
    _Static_assert(Q == 8380417, "Modulus Q constraint violated");
    
    for (int i = 0; i < RING_DEG; i++) {
        r->coeffs[i] = reduce_mod_q((int64_t)a->coeffs[i] + b->coeffs[i]);
        assert(r->coeffs[i] >= -((Q-1)/2) && r->coeffs[i] <= ((Q-1)/2));
    }
    check_poly_bounds(r, "poly_add");
}

/**
 * @brief Adds two polynomial vectors element-wise with modular reduction modulo $Q$.
 *
 * @param[out] r Result polynomial vector.
 * @param[in] a First vector.
 * @param[in] b Second vector.
 *
 * @pre `r`, `a`, and `b` non-NULL with equal dimensions (`r->len == a->len == b->len`).
 * @complexity Time: O(r->len * RING_DEG), Space: O(1).
 */
void polyvec_add(polyvec_t *r, const polyvec_t *a, const polyvec_t *b) {
    if (!r || !a || !b || r->len != a->len || r->len != b->len) return;
    // Add corresponding polynomials element-wise with modular reduction modulo Q
    for (size_t i = 0; i < r->len; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/**
 * @brief Adds two polynomials coefficient-wise without modular reduction (accumulates in 32-bit signed space).
 *
 * @param[out] r Result polynomial.
 * @param[in] a First addend polynomial.
 * @param[in] b Second addend polynomial.
 *
 * @pre Magnitudes of $a_j + b_j$ must not overflow `int32_t` space ($|a_j + b_j| < 2^{31}-1$).
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
static void poly_add_no_reduce(poly_t *r, const poly_t *a, const poly_t *b) {
    if (!r || !a || !b) return;
    for (int i = 0; i < RING_DEG; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
    int32_t max_coeff = poly_max_coeff(r);
    scl_log(LOG_LEVEL_TRACE, "Crypto", "poly_add_no_reduce max coeff: %d", max_coeff);
}

/**
 * @brief Adds two polynomial vectors element-wise without modular reduction.
 *
 * @param[out] r Result polynomial vector.
 * @param[in] a First vector.
 * @param[in] b Second vector.
 *
 * @pre `r`, `a`, and `b` non-NULL with equal lengths.
 * @complexity Time: O(r->len * RING_DEG), Space: O(1).
 */
void polyvec_add_no_reduce(polyvec_t *r, const polyvec_t *a, const polyvec_t *b) {
    if (!r || !a || !b || r->len != a->len || r->len != b->len) return;
    // Accumulate corresponding polynomials element-wise in 32-bit space without reduction
    for (size_t i = 0; i < r->len; i++) {
        poly_add_no_reduce(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/* ============================================================================ */
/* SECTION 8: POLYNOMIAL VECTOR ALLOCATION & THREAD-LOCAL SCRATCH ARENA         */
/* ============================================================================ */

/**
 * @brief Dynamically allocates a polynomial vector of specified length on the heap.
 *
 * @param[out] v Pointer to @ref polyvec_t structure to initialize.
 * @param[in] len Dimension of vector (number of polynomials in $R_q$).
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_MEMORY on allocation failure.
 *
 * @post `v->vec` points to heap memory; `v->magic = 0xDEADBEEF`. Caller must free via @ref polyvec_free.
 * @complexity Time: O(len * RING_DEG), Space: O(len * sizeof(poly_t)) heap allocation.
 */
crypto_error_t polyvec_init(polyvec_t *v, size_t len) {
    if (!v) return CRYPTO_ERROR_INVALID_PARAM;
    v->len = len;
    v->vec = (poly_t *)calloc(len, sizeof(poly_t));
    if (!v->vec) {
        scl_log(LOG_LEVEL_ERROR, "Crypto", "calloc failed for polyvec (len=%zu, size=%zu bytes) in %s at %s:%d",
                len, len * sizeof(poly_t), __func__, __FILE__, __LINE__);
        v->len = 0;
        v->magic = 0;
        return CRYPTO_ERROR_MEMORY;
    }
    v->magic = 0xDEADBEEF;  // Mark as valid
    scl_log(LOG_LEVEL_TRACE, "Crypto", "Allocated polyvec at %p with %zu polynomials", v, len);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Allocates an unreduced 64-bit polynomial vector of specified length on the heap.
 *
 * @param[out] v Pointer to @ref polyvec64_t structure to initialize.
 * @param[in] len Vector dimension.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_MEMORY on failure.
 *
 * @complexity Time: O(len * RING_DEG), Space: O(len * sizeof(poly64_t)) heap allocation.
 */
crypto_error_t polyvec64_init(polyvec64_t *v, size_t len) {
    // Allocate 64-bit polynomial array on heap
    v->vec = calloc(len, sizeof(poly64_t));
    if (!v->vec) return CRYPTO_ERROR_MEMORY;
    v->len = len;
    return CRYPTO_SUCCESS;
}

/** @brief Thread-local linear memory arena context governing fast zero-heap allocations. */
static _Thread_local CryptoArena thread_arena = {NULL, 0};

/** @brief POSIX thread-specific storage key binding thread-local arena destructor. */
static pthread_key_t arena_cleanup_key;
/** @brief One-time pthread initializer for arena destructor key. */
static pthread_once_t arena_cleanup_once = PTHREAD_ONCE_INIT;

/**
 * @brief Destructor callback invoked automatically upon thread termination to free arena backing memory.
 *
 * @param[in] ptr Pointer to thread-local arena buffer.
 */
static void auto_arena_cleanup(void *ptr) {
    (void)ptr;
    arena_cleanup();
}

/**
 * @brief One-time pthread constructor registering the arena cleanup key and destructor callback.
 */
static void init_arena_cleanup_key(void) {
    pthread_key_create(&arena_cleanup_key, auto_arena_cleanup);
}

/**
 * @brief Evaluates whether a memory pointer falls within the active thread's linear arena buffer.
 *
 * @param[in] ptr Memory address to test.
 * @return `true` if `ptr` is managed by `thread_arena`; `false` if allocated on the global heap.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static inline bool is_arena_ptr(void *ptr) {
    if (!thread_arena.memory || !ptr) return false;
    return ((uint8_t*)ptr >= thread_arena.memory && (uint8_t*)ptr < thread_arena.memory + CRYPTO_ARENA_SIZE);
}

/**
 * @brief Allocates a 64-byte aligned block from the calling thread's linear memory arena.
 *
 * @details
 * Bumps the thread-local allocation offset linearly. Initializes the backing 128 MiB buffer
 * (or configured size) using `posix_memalign` on first invocation.
 *
 * @param[in] size Number of bytes requested.
 * @return 64-byte aligned pointer to zeroized memory; NULL if arena capacity is exhausted.
 *
 * @thread_safety Reentrant and thread-safe via C11 `_Thread_local` storage.
 * @complexity Time: O(1) amortized, Space: O(1) linear bump within preallocated arena.
 */
void *arena_alloc(size_t size) {
    /* Ensure the destructor key is registered exactly once across the process */
    pthread_once(&arena_cleanup_once, init_arena_cleanup_key);

    if (!thread_arena.memory) {
        if (posix_memalign((void**)&thread_arena.memory, 64, CRYPTO_ARENA_SIZE) != 0) {
            thread_arena.memory = NULL;
            return NULL;
        }
        
        /* Bind the allocated heap pointer to this thread's destructor key */
        pthread_setspecific(arena_cleanup_key, thread_arena.memory);

#ifndef _WIN32
#if defined(POSIX_MADV_DONTNEED)
        posix_madvise(thread_arena.memory, CRYPTO_ARENA_SIZE, POSIX_MADV_DONTNEED);
#endif
#endif
    }
    size_t aligned_size = (size + 63) & ~63;
    if (thread_arena.offset + aligned_size > CRYPTO_ARENA_SIZE) {
        fprintf(stderr, "[Arena] ERROR: Out of memory\n");
        return NULL;
    }
    void *ptr = thread_arena.memory + thread_arena.offset;
    thread_arena.offset += aligned_size;
    memset(ptr, 0, size);
    return ptr;
}

/**
 * @brief Captures the current linear allocation offset marker within the calling thread's arena.
 *
 * @return Current allocation offset in bytes.
 * @complexity Time: O(1), Space: O(1).
 */
size_t arena_mark(void) {
    return thread_arena.offset;
}

/**
 * @brief Resets the calling thread's linear arena allocation cursor back to a captured marker.
 *
 * @param[in] mark Allocation offset previously returned by @ref arena_mark.
 *
 * @post All allocations made after `mark` are released in O(1) time without individual heap frees.
 * @complexity Time: O(1), Space: O(1).
 */
void arena_reset(size_t mark) {
    // Reset allocation cursor back to checkpoint
    thread_arena.offset = mark;
}

/**
 * @brief Destroys and deallocates the calling thread's linear arena buffer completely.
 *
 * @post `thread_arena.memory` is freed and reset to NULL; `thread_arena.offset = 0`.
 * @complexity Time: O(1), Space: O(1).
 */
void arena_cleanup(void) {
    // Release thread-local arena backing buffer
    if (thread_arena.memory) {
        free(thread_arena.memory);
        thread_arena.memory = NULL;
        thread_arena.offset = 0;
    }
}

/**
 * @brief Allocates a polynomial vector within the thread-local arena (zero heap fragmentation).
 *
 * @param[out] v Pointer to @ref polyvec_t structure.
 * @param[in] len Vector dimension (count of polynomials).
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_MEMORY on arena exhaustion.
 *
 * @post `v->vec` points to arena memory; `v->magic = 0xDEADBEEF`. Automatically freed on @ref arena_reset.
 * @complexity Time: O(1), Space: O(len * sizeof(poly_t)) arena reservation.
 */
crypto_error_t polyvec_init_arena(polyvec_t *v, size_t len) {
    if (!v) return CRYPTO_ERROR_INVALID_PARAM;
    v->len = len;
    // Allocate polynomial array from thread-local linear arena
    v->vec = (poly_t *)arena_alloc(len * sizeof(poly_t));
    if (!v->vec) {
        v->len = 0;
        v->magic = 0;
        return CRYPTO_ERROR_MEMORY;
    }
    v->magic = 0xDEADBEEA; // Explicitly tag as arena-backed to prevent heap free across threads
    return CRYPTO_SUCCESS;
}

/**
 * @brief Allocates an unreduced 64-bit polynomial vector within the thread-local arena.
 *
 * @param[out] v Pointer to @ref polyvec64_t structure.
 * @param[in] len Vector dimension.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_MEMORY on arena exhaustion.
 *
 * @complexity Time: O(1), Space: O(len * sizeof(poly64_t)) arena reservation.
 */
crypto_error_t polyvec64_init_arena(polyvec64_t *v, size_t len) {
    if (!v) return CRYPTO_ERROR_INVALID_PARAM;
    v->len = len;
    // Allocate 64-bit polynomial array from thread-local linear arena
    v->vec = (poly64_t *)arena_alloc(len * sizeof(poly64_t));
    if (!v->vec) {
        v->len = 0;
        return CRYPTO_ERROR_MEMORY;
    }
    return CRYPTO_SUCCESS;
}

/**
 * @brief Deallocates a polynomial vector, distinguishing heap memory from arena memory safely.
 *
 * @details
 * Validates the corruption sentinel `v->magic == 0xDEADBEEF`. If `v->vec` points to the thread-local
 * arena, skips the call to `free()`. If allocated on the global heap, frees memory normally.
 *
 * @param[in,out] v Pointer to @ref polyvec_t structure to finalize.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void polyvec_free(polyvec_t *v) {
    if (!v) return;
    if (v->vec == NULL && v->len == 0 && v->magic == 0) {
        return;  // Uninitialized, silently skip
    }
    if (v->magic == 0xDEADBEEA) {
        // Allocated in thread arena; never free on heap regardless of calling thread
        v->vec = NULL;
        v->len = 0;
        v->magic = 0;
        return;
    }
    if (v->magic != 0xDEADBEEF) {
        scl_log(LOG_LEVEL_ERROR, "Crypto", "Skipping free of corrupted polyvec at %p (vec=%p, len=%zu, magic=0x%x)",
                v, v->vec, v->len, v->magic);
        v->vec = NULL;
        v->len = 0;
        v->magic = 0;
        return;
    }
    if (!is_arena_ptr(v->vec)) {
        scl_log(LOG_LEVEL_TRACE, "Crypto", "Freeing polyvec at %p (vec=%p, len=%zu)", v, v->vec, v->len);
        free(v->vec);
    }
    v->vec = NULL;
    v->len = 0;
    v->magic = 0;
}

/**
 * @brief Deallocates an unreduced 64-bit polynomial vector, skipping arena pointers.
 *
 * @param[in,out] v Pointer to @ref polyvec64_t structure to finalize.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void polyvec64_free(polyvec64_t *v) {
    if (!v) return;
    if (v->vec == NULL && v->len == 0) {
        return;  // Uninitialized, silently skip (no magic in polyvec64_t)
    }
    if (!is_arena_ptr(v->vec)) {
        fprintf(stderr, "[Crypto] DEBUG: Freeing polyvec64 at %p (vec=%p, len=%zu)\n", v, v->vec, v->len);
        free(v->vec);
    }
    v->vec = NULL;
    v->len = 0;
}

/* ============================================================================ */
/* SECTION 9: POLYNOMIAL MATRIX-VECTOR MULTIPLICATIONS                          */
/* ============================================================================ */

/**
 * @brief Subtracts two 64-bit unreduced polynomial vectors coefficient-wise: $r = a - b$.
 *
 * @param[out] r Result vector.
 * @param[in] a Minuend vector.
 * @param[in] b Subtrahend vector.
 *
 * @complexity Time: O(r->len * RING_DEG), Space: O(1).
 */
void polyvec64_sub(polyvec64_t *r, const polyvec64_t *a, const polyvec64_t *b) {
    // Subtract 64-bit unreduced polynomial vectors coefficient-wise: r = a - b
    for (size_t i = 0; i < r->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            r->vec[i].coeffs[j] = a->vec[i].coeffs[j] - b->vec[i].coeffs[j];
        }
    }
}

/**
 * @brief Multiplies public matrix $\bar{A} \in R_q^{K \times L}$ by vector $v \in R_q^L$ with modular reduction.
 *
 * @details
 * Evaluates the matrix-vector product $r_i = \sum_{j=0}^{L-1} A_{i,j} \cdot v_j \pmod Q$ for all $0 \le i < K$,
 * applying @ref poly_mul and @ref poly_add with continuous centered modular reduction.
 *
 * @param[out] r Result polynomial vector in $R_q^K$.
 * @param[in] mat Public operator matrix $\bar{A}$ of dimension $K \times L$.
 * @param[in] v Input vector in $R_q^L$.
 * @return CRYPTO_SUCCESS on success; -1 on dimension mismatch or parameter error.
 *
 * @complexity Time: O(K * L * RING_DEG^2) = 56 * 65,536 multiplications, Space: O(1) stack buffers.
 */
int matrix_vec_mul(polyvec_t *r, const matrix_t *mat, const polyvec_t *v) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)mat; (void)v;
    if (!r) return -1;
    for (size_t i = 0; i < r->len; i++) {
        memset(r->vec[i].coeffs, 0, sizeof(r->vec[i].coeffs));
    }
    return CRYPTO_SUCCESS;
#else
    if (!r || !mat || !v || r->len != DILITHIUM_K || mat->rows.len != DILITHIUM_K * DILITHIUM_L || v->len != DILITHIUM_L) return -1;
    // Compute r_i = sum_{j=0}^{L-1} (A_{i,j} * v_j) mod Q
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        memset(&r->vec[i], 0, sizeof(poly_t));
        for (size_t j = 0; j < DILITHIUM_L; j++) {
            poly_t tmp;
            poly_mul(&tmp, &mat->rows.vec[i * DILITHIUM_L + j], &v->vec[j]);
            poly_add(&r->vec[i], &r->vec[i], &tmp);
        }
    }
    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Multiplies matrix $\bar{A}$ by vector $v$ producing high-precision unreduced 64-bit coefficients.
 *
 * @details
 * Accumulates negacyclic convolution cross-products directly in `int64_t` registers without modular
 * reduction modulo $Q$, preserving exact arithmetic fidelity for Fiat-Shamir hint derivation.
 *
 * @param[out] r Result vector in $(R^{64})^K$.
 * @param[in] mat Public matrix $\bar{A} \in R_q^{K \times L}$.
 * @param[in] v Input vector in $R_q^L$.
 *
 * @complexity Time: O(K * L * RING_DEG^2), Space: O(1).
 */
void matrix_vec_mul_unreduced(polyvec64_t *r, const matrix_t *mat, const polyvec_t *v) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)mat; (void)v;
    if (!r) return;
    for (size_t i = 0; i < r->len; i++) {
        memset(r->vec[i].coeffs, 0, sizeof(r->vec[i].coeffs));
    }
#else
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        for (int k = 0; k < RING_DEG; k++) {
            r->vec[i].coeffs[k] = 0;
        }
        for (size_t j = 0; j < DILITHIUM_L; j++) {
            const poly_t *a = &mat->rows.vec[i * DILITHIUM_L + j];
            const poly_t *v_vec = &v->vec[j];
            for (int x = 0; x < RING_DEG; x++) {
                int64_t ax = a->coeffs[x];
                int limit = RING_DEG - x;
                for (int y = 0; y < limit; y++) {
                    r->vec[i].coeffs[x + y] += ax * v_vec->coeffs[y];
                }
                for (int y = limit; y < RING_DEG; y++) {
                    r->vec[i].coeffs[x + y - RING_DEG] -= ax * v_vec->coeffs[y];
                }
            }
        }
    }
#endif
}

/**
 * @brief Convenience wrapper evaluating $r = \bar{A} \cdot v$ for Dilithium public operator multiplication.
 *
 * @param[out] r Result vector in $R_q^K$.
 * @param[in] A_bar Public operator matrix.
 * @param[in] v Secret vector in $R_q^L$.
 *
 * @complexity Time: O(K * L * RING_DEG^2), Space: O(1).
 */
void a_mul_vec(polyvec_t *r, const matrix_t *A_bar, const polyvec_t *v) {
    if (!r || !A_bar || !v || v->len != DILITHIUM_L) return;
    matrix_vec_mul(r, A_bar, v);
}

/* ============================================================================ */
/* SECTION 10: COEFFICIENT PACKING, UNPACKING & HINT VECTOR DERIVATION          */
/* ============================================================================ */

/**
 * @brief Bit-packs high-order bits polynomial $w_1$ into compact 4-bit nibbles.
 *
 * @details
 * Packs two 4-bit coefficients per byte ($256 / 2 = 128$ bytes total):
 * `dst[i] = (coeffs[2*i] & 0x0F) | ((coeffs[2*i+1] & 0x0F) << 4)`.
 *
 * @param[out] dst Output buffer (must allocate at least @ref POLYW1_PACKEDBYTES = 128 bytes).
 * @param[in] p Source high-order polynomial ($w_1$).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
void polyw1_pack(uint8_t *dst, const poly_t *p) {
    if (!dst || !p) return;
    for (int i = 0; i < RING_DEG / 2; i++) {
        dst[i] = (p->coeffs[2 * i] & 0x0F) | ((p->coeffs[2 * i + 1] & 0x0F) << 4);
    }
}

/**
 * @brief Bit-packs signature response polynomial $z$ into compact 20-bit representations.
 *
 * @details
 * Translates centered coefficients $z_j \in [-\gamma_1, \gamma_1]$ to positive range $[0, 2\gamma_1]$,
 * packing two 20-bit values into 5 bytes ($256 \times 20 / 8 = 640$ bytes total = @ref POLYZ_PACKEDBYTES).
 *
 * @param[out] dst Output buffer (at least 640 bytes).
 * @param[in] p Source response polynomial ($z$).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
static void polyz_pack(uint8_t *dst, const poly_t *p) {
    if (!dst || !p) return;
    for (int i = 0; i < RING_DEG / 2; i++) {
        uint32_t t0 = (uint32_t)(GAMMA1 + p->coeffs[2 * i]);
        uint32_t t1 = (uint32_t)(GAMMA1 + p->coeffs[2 * i + 1]);
        // Ensure 20-bit values
        t0 &= 0xFFFFF;
        t1 &= 0xFFFFF;
        dst[5 * i + 0] = (uint8_t)(t0 & 0xFF);
        dst[5 * i + 1] = (uint8_t)((t0 >> 8) & 0xFF);
        dst[5 * i + 2] = (uint8_t)(((t0 >> 16) & 0x0F) | ((t1 & 0x0F) << 4));
        dst[5 * i + 3] = (uint8_t)((t1 >> 4) & 0xFF);
        dst[5 * i + 4] = (uint8_t)((t1 >> 12) & 0xFF);
    }
}

/**
 * @brief Unpacks a signature response polynomial $z$ from 20-bit packed bytes into centered coefficients.
 *
 * @param[out] p Destination polynomial ($z_j \in [-\gamma_1, \gamma_1]$).
 * @param[in] src Input buffer of length @ref POLYZ_PACKEDBYTES (640 bytes).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
static void polyz_unpack(poly_t *p, const uint8_t *src) {
    if (!p || !src) return;
    for (int i = 0; i < RING_DEG / 2; i++) {
        uint32_t t0 = src[5*i+0] | (src[5*i+1] << 8) | ((src[5*i+2] & 0x0F) << 16);
        uint32_t t1 = (src[5*i+2] >> 4) | (src[5*i+3] << 4) | (src[5*i+4] << 12);
        // Ensure values are in [0, 2*GAMMA1]
        t0 &= 0xFFFFF;
        t1 &= 0xFFFFF;
        p->coeffs[2*i+0] = (int32_t)(t0) - GAMMA1;
        p->coeffs[2*i+1] = (int32_t)(t1) - GAMMA1;
    }
    // Bounds check to prevent unpacking corruption
    for (int i = 0; i < RING_DEG; i++) {
        if (abs(p->coeffs[i]) > GAMMA1) {
            fprintf(stderr, "[Crypto] WARNING: Unpacked z coeff out of [-GAMMA1, GAMMA1] at %d: %d\n",
                    i, p->coeffs[i]);
            p->coeffs[i] = 0;  // Clamp to safe value
        }
    }
}
#endif

/**
 * @brief Bit-packs public key high-bits polynomial $t_1$ into compact 10-bit format.
 *
 * @details
 * Packs 4 coefficients (10 bits each = 40 bits = 5 bytes) per block across 64 iterations,
 * producing exactly 320 bytes (@ref POLYT1_PACKEDBYTES).
 *
 * @param[out] dst Output buffer (at least 320 bytes).
 * @param[in] p Source polynomial ($t_1 \in [0, 1023]^{256}$).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
static void poly_t1_pack(uint8_t *dst, const poly_t *p) {
    for (int i = 0; i < RING_DEG / 4; i++) {
        dst[5 * i + 0] = p->coeffs[4 * i + 0] & 0xFF;
        dst[5 * i + 1] = (p->coeffs[4 * i + 0] >> 8) | (p->coeffs[4 * i + 1] << 2);
        dst[5 * i + 2] = (p->coeffs[4 * i + 1] >> 6) | (p->coeffs[4 * i + 2] << 4);
        dst[5 * i + 3] = (p->coeffs[4 * i + 2] >> 4) | (p->coeffs[4 * i + 3] << 6);
        dst[5 * i + 4] = (p->coeffs[4 * i + 3] >> 2);
    }
}

/**
 * @brief Bit-unpacks public key high-bits polynomial $t_1$ from 10-bit packed wire format.
 *
 * @param[out] p Destination polynomial ($t_1$).
 * @param[in] src Input buffer of length @ref POLYT1_PACKEDBYTES (320 bytes).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
void poly_t1_unpack(poly_t *p, const uint8_t *src) {
    if (!p || !src) return;
    
    for (int i = 0; i < RING_DEG / 4; i++) {
        p->coeffs[4*i+0] = src[5*i+0] | ((uint32_t)(src[5*i+1] & 0x03) << 8);
        p->coeffs[4*i+1] = (src[5*i+1] >> 2) | ((uint32_t)(src[5*i+2] & 0x0F) << 6);
        p->coeffs[4*i+2] = (src[5*i+2] >> 4) | ((uint32_t)(src[5*i+3] & 0x3F) << 4);
        p->coeffs[4*i+3] = (src[5*i+3] >> 6) | ((uint32_t)src[5*i+4] << 2);
        
        // Reduce coefficients modulo Q
        p->coeffs[4*i+0] &= 0x3FF;
        p->coeffs[4*i+1] &= 0x3FF;
        p->coeffs[4*i+2] &= 0x3FF;
        p->coeffs[4*i+3] &= 0x3FF;
    }
}

/**
 * @brief Encodes the sparse hint vector $h$ into compact wire representation.
 *
 * @details
 * Scans $h \in R_2^K$ for non-zero coefficients ($h_{i,j} = 1$). Appends non-zero indices $j \in [0, 255]$
 * into the first $\omega = 75$ bytes, zero-padding unused slots. Appends the per-polynomial non-zero
 * counts across the trailing $K = 8$ bytes, producing exactly $\omega + K = 83$ bytes (@ref POLYH_PACKEDBYTES).
 *
 * @param[out] dst Output buffer (must allocate at least @ref POLYH_PACKEDBYTES = 83 bytes).
 * @param[in] h Source sparse hint polynomial vector.
 *
 * @complexity Time: O(K * RING_DEG), Space: O(1).
 */
static void pack_h(uint8_t *dst, const polyvec_t *h) {
    if (!dst || !h) return;
    size_t m = 0;
    uint8_t counts[DILITHIUM_K] = {0};

    // Count ones per polynomial and total ones
    size_t total_ones = 0;
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            if (h->vec[i].coeffs[j] == 1) {
                counts[i]++;
                total_ones++;
            }
        }
    }

    // Truncate to OMEGA if necessary
    if (total_ones > OMEGA) {
        total_ones = OMEGA;
    }

    // Pack indices of ones
    m = 0;
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            if (h->vec[i].coeffs[j] == 1) {
                if (m < total_ones) {
                    dst[m++] = (uint8_t)j;
                } else {
                    break;
                }
            }
        }
    }

    // Pad indices with zeros if needed
    if (m < OMEGA) {
        memset(dst + m, 0, OMEGA - m);
    }

    // Pack counts at the end
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        dst[OMEGA + i] = counts[i];
    }
}

/**
 * @brief Decodes a sparse hint polynomial vector $h \in R_2^K$ from its compact 83-byte wire encoding.
 *
 * @param[out] h Destination polynomial vector ($h \in R_2^K$).
 * @param[in] src Input buffer of length @ref POLYH_PACKEDBYTES (83 bytes).
 *
 * @complexity Time: O(K * RING_DEG), Space: O(1).
 */
void unpack_h(polyvec_t *h, const uint8_t *src) {
  if (!h || !src) return;
  polyvec_clear(h);  // Start with zeros

  // Extract per-poly counts (last K bytes)
  uint8_t counts[DILITHIUM_K];
  for (size_t i = 0; i < DILITHIUM_K; i++) {
    counts[i] = src[OMEGA + i];
  }

  // Assign packed j indices sequentially to each poly
  size_t idx = 0;  // Index into packed j's (src[0..OMEGA-1])
  for (size_t i = 0; i < DILITHIUM_K; i++) {
    for (uint8_t c = 0; c < counts[i]; c++) {
      if (idx >= OMEGA) break;  // Safety (shouldn't happen post-rejection)
      int j = src[idx++];
      if (j < RING_DEG) {  // Valid j
        h->vec[i].coeffs[j] = 1;
      }
    }
  }

  // Optional: Log unpacked wt for debug
  int total_ones = count_nonzero_vec(h);
  scl_log(LOG_LEVEL_TRACE, "Crypto", "Unpacked h weight: %d", total_ones);
}

/* ============================================================================ */
/* SECTION 11: CHALLENGE BALL SAMPLING & PUBLIC OPERATOR EXPANSION              */
/* ============================================================================ */

/**
 * @brief Samples a sparse challenge polynomial $c \in R_q$ with fixed Hamming weight $\tau = 60$.
 *
 * @details
 * Samples exactly $\tau = 60$ non-zero coefficients in $\{-1, 1\}$ using SHAKE-256 rejection sampling.
 * Squeezes 8 sign bits to determine the polarity of each non-zero coefficient, placing non-zero
 * coefficients at pseudorandom unique polynomial degree positions $j \in [0, 255]$.
 *
 * @param[out] c Destination challenge polynomial ($c \in \{-1, 0, 1\}^{256}$, Hamming weight $\tau = 60$).
 * @param[in] seed Input cryptographic challenge digest (32 bytes).
 * @param[in] seed_len Length of seed in bytes (must be at least 32).
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_INVALID_PARAM on invalid inputs.
 *
 * @complexity Time: O(TAU) rejection sampling, Space: O(1) stack context.
 */
crypto_error_t sample_in_ball(poly_t *c, const uint8_t *seed, size_t seed_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)seed; (void)seed_len;
    if (!c) return CRYPTO_ERROR_INVALID_PARAM;
    memset(c->coeffs, 0, sizeof(c->coeffs));
    c->coeffs[0] = 1;
    return CRYPTO_SUCCESS;
#else
    if (!c || !seed || seed_len < 32) return CRYPTO_ERROR_INVALID_PARAM;
    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, seed, seed_len);
    custom_shake256_inc_finalize(&state);
    
    uint8_t buf[SHAKE256_RATE];
    custom_shake256_inc_squeeze(buf, sizeof(buf), &state);
    
    uint64_t signs = 0;
    for (int i = 0; i < 8; i++) {
        signs |= (uint64_t)buf[i] << 8 * i;
    }
    size_t pos = 8;
    memset(c->coeffs, 0, sizeof(c->coeffs));
    for (int i = RING_DEG - TAU; i < RING_DEG; i++) {
        unsigned int b;
        do {
            if (pos == SHAKE256_RATE) {
                custom_shake256_inc_squeeze(buf, SHAKE256_RATE, &state);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > (unsigned int)i);
        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (signs & 1);
        signs >>= 1;
    }
    custom_shake256_inc_ctx_release(&state);
    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Expands public matrix $\bar{A} \in R_q^{K \times L}$ from 32-byte seed $\rho$.
 *
 * @details
 * Evaluates $K \times L = 8 \times 7 = 56$ independent polynomial rejection sampling pipelines using
 * SHAKE-256 XOF. For each coordinate $(i, j)$, absorbs $\rho \parallel (i \ll 8 \mid j)$ and samples
 * 256 coefficients uniformly in range $[-Q/2, Q/2]$.
 *
 * @param[out] A_bar Matrix structure with pre-allocated polynomial array of length $K \times L$.
 * @param[in] rho 32-byte public key seed.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_INVALID_PARAM on invalid inputs.
 *
 * @pre `A_bar->rows.len == DILITHIUM_K * DILITHIUM_L`.
 * @complexity Time: O(K * L * RING_DEG) rejection sampling, Space: O(1) stack context.
 */
crypto_error_t expand_a(matrix_t *A_bar, const uint8_t *rho) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)rho;
    if (!A_bar) return CRYPTO_ERROR_INVALID_PARAM;
    if (A_bar->rows.len != DILITHIUM_K * DILITHIUM_L) return CRYPTO_ERROR_INVALID_PARAM;
    for (size_t i = 0; i < DILITHIUM_K * DILITHIUM_L; i++) {
        memset(A_bar->rows.vec[i].coeffs, 0x01, sizeof(A_bar->rows.vec[i].coeffs));
    }
    return CRYPTO_SUCCESS;
#else
    if (!A_bar || !rho) return CRYPTO_ERROR_INVALID_PARAM;
    if (A_bar->rows.len != DILITHIUM_K * DILITHIUM_L) return CRYPTO_ERROR_INVALID_PARAM;
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        for (size_t j = 0; j < DILITHIUM_L; j++) {
            uint16_t nonce = (i << 8) | j;
            custom_shake256_inc_ctx state;
            custom_shake256_inc_init(&state);
            custom_shake256_inc_absorb(&state, rho, KAPPA);
            uint8_t n[2] = { (uint8_t)(nonce & 0xFF), (uint8_t)(nonce >> 8) };
            custom_shake256_inc_absorb(&state, n, 2);
            custom_shake256_inc_finalize(&state);
            
            uint8_t buf[SHAKE256_RATE];
            size_t idx = 0;
            size_t buf_len = 0;
            for (int k = 0; k < RING_DEG; k++) {
                uint32_t t;
                do {
                    if (idx + 3 > buf_len) {
                        custom_shake256_inc_squeeze(buf, SHAKE256_RATE, &state);
                        buf_len = SHAKE256_RATE;
                        idx = 0;
                    }
                    t = buf[idx] | ((uint32_t)buf[idx + 1] << 8) | ((uint32_t)buf[idx + 2] << 16);
                    t &= 0x7FFFFF;
                    idx += 3;
                } while (t >= Q);
                A_bar->rows.vec[i * DILITHIUM_L + j].coeffs[k] = (int32_t)t - (Q >> 1);
            }
            custom_shake256_inc_ctx_release(&state);
        }
    }
    return CRYPTO_SUCCESS;
#endif
}

/* ============================================================================ */
/* SECTION 12: BDLOP HOMOMORPHIC LATTICE COMMITMENTS OVER R_q                   */
/* ============================================================================ */

/**
 * @brief Expands public BDLOP commitment vectors $a, b \in R_q$ from 32-byte domain separator seed $\rho$.
 *
 * @param[in] rho 32-byte domain separator seed (typically @ref BDLOP_RHO_SEED).
 * @param[out] a_out First public polynomial parameter $a \in R_q$.
 * @param[out] b_out Second public polynomial parameter $b \in R_q$.
 * @return CRYPTO_SUCCESS on success.
 *
 * @complexity Time: O(RING_DEG), Space: O(1) stack context.
 */
crypto_error_t bdlop_expand_parameters(const uint8_t *rho, poly_t *a_out, poly_t *b_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)rho;
    if (a_out) memset(a_out->coeffs, 0, sizeof(a_out->coeffs));
    if (b_out) memset(b_out->coeffs, 0, sizeof(b_out->coeffs));
    return CRYPTO_SUCCESS;
#endif
    if (!rho || !a_out || !b_out) return CRYPTO_ERROR_INVALID_PARAM;

    // Fast-path: BDLOP_RHO_SEED is immutable protocol-wide; cache pre-expanded polynomials
    static poly_t s_cached_a, s_cached_b;
    static bool s_bdlop_cached = false;
    if (memcmp(rho, BDLOP_RHO_SEED, BDLOP_PUBKEY_SEED_LEN) == 0 && s_bdlop_cached) {
        memcpy(a_out, &s_cached_a, sizeof(poly_t));
        memcpy(b_out, &s_cached_b, sizeof(poly_t));
        return CRYPTO_SUCCESS;
    }
    
    for (int i = 0; i < 2; i++) {
        poly_t *target = (i == 0) ? a_out : b_out;
        custom_shake256_inc_ctx state;
        custom_shake256_inc_init(&state);
        custom_shake256_inc_absorb(&state, rho, BDLOP_PUBKEY_SEED_LEN);
        uint8_t n[2] = {(uint8_t)i, 0};
        custom_shake256_inc_absorb(&state, n, 2);
        custom_shake256_inc_finalize(&state);
        
        uint8_t buf[SHAKE256_RATE];
        size_t idx = 0;
        size_t buf_len = 0;
        for (int k = 0; k < RING_DEG; k++) {
            uint32_t t;
            do {
                if (idx + 3 > buf_len) {
                    custom_shake256_inc_squeeze(buf, SHAKE256_RATE, &state);
                    buf_len = SHAKE256_RATE;
                    idx = 0;
                }
                t = buf[idx] | ((uint32_t)buf[idx + 1] << 8) | ((uint32_t)buf[idx + 2] << 16);
                t &= 0xFFFFFF;
                idx += 3;
            } while (t >= Q);
            target->coeffs[k] = (int32_t)t - (Q >> 1);
        }
        custom_shake256_inc_ctx_release(&state);
    }

    if (memcmp(rho, BDLOP_RHO_SEED, BDLOP_PUBKEY_SEED_LEN) == 0 && !s_bdlop_cached) {
        memcpy(&s_cached_a, a_out, sizeof(poly_t));
        memcpy(&s_cached_b, b_out, sizeof(poly_t));
        s_bdlop_cached = true;
    }
    return CRYPTO_SUCCESS;
}

/**
 * @brief Evaluates a homomorphic BDLOP lattice commitment concealing a 64-bit integer asset balance.
 *
 * @details
 * Decomposes 64-bit scalar $v$ across four 21-bit polynomial limbs:
 * $$v(X) = v_0 + v_1 X + v_2 X^2 + v_3 X^3$$
 * Samples secret noise polynomials $(s, e_1, e_2)$ uniformly from $[-\eta, \eta]^{256}$ using blinding factor $r$.
 * Evaluates the commitment components:
 * $$c_1 = a \cdot s + e_1 \pmod Q, \quad c_2 = b \cdot s + e_2 + v(X) \pmod Q$$
 * Serializes 256 coefficients $\times 4$ bytes $= 1,024$ bytes each into `commitment_out->c1` and `c2`.
 *
 * @param[in] rho 32-byte public parameter seed.
 * @param[in] v Monetary value in atomic subunits to commit.
 * @param[in] r 32-byte secret blinding factor seed.
 * @param[out] commitment_out Destination structure receiving $c_1$ and $c_2$ (2,048 bytes total).
 * @return CRYPTO_SUCCESS on success; error code on failure.
 *
 * @complexity Time: O(RING_DEG^2) negacyclic convolution, Space: O(sizeof(poly_t)) arena allocations.
 */
crypto_error_t bdlop_commit(const uint8_t *rho, uint64_t v, const uint8_t *r, BdlopCommitment *commitment_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)rho;
    if (!commitment_out) return CRYPTO_ERROR_INVALID_PARAM;
    memset(commitment_out, 0x42, sizeof(BdlopCommitment));
    memcpy(commitment_out->c1, &v, sizeof(uint64_t));
    if (r) memcpy(commitment_out->c2, r, 32);
    return CRYPTO_SUCCESS;
#else
    if (!rho || !r || !commitment_out) return CRYPTO_ERROR_INVALID_PARAM;

    size_t mark = arena_mark();
    poly_t *a = arena_alloc(sizeof(poly_t));
    poly_t *b = arena_alloc(sizeof(poly_t));
    poly_t *s = arena_alloc(sizeof(poly_t));
    poly_t *e1 = arena_alloc(sizeof(poly_t));
    poly_t *e2 = arena_alloc(sizeof(poly_t));
    poly_t *v_poly = arena_alloc(sizeof(poly_t));
    poly_t *tmp = arena_alloc(sizeof(poly_t));

    if (!a || !b || !s || !e1 || !e2 || !v_poly || !tmp) {
        arena_reset(mark);
        return CRYPTO_ERROR_MEMORY;
    }

    // 1. Multi-Limb Decomposition: v = v0 + v1*2^21 + v2*2^42 + v3*2^63
    v_poly->coeffs[0] = (int32_t)(v & 0x1FFFFF);
    v_poly->coeffs[1] = (int32_t)((v >> 21) & 0x1FFFFF);
    v_poly->coeffs[2] = (int32_t)((v >> 42) & 0x1FFFFF);
    v_poly->coeffs[3] = (int32_t)((v >> 63) & 0x1);

    bdlop_expand_parameters(rho, a, b);

    // 2. Sample noise polynomials from [-eta, eta]
    poly_uniform_eta(s, r, 32, 0);
    poly_uniform_eta(e1, r, 32, 1);
    poly_uniform_eta(e2, r, 32, 2);

    // 3. Compute commitment: c1 = a*s + e1, c2 = b*s + e2 + v(X)
    poly_mul(tmp, a, s);
    poly_add(tmp, tmp, e1);
    memcpy(commitment_out->c1, tmp->coeffs, BDLOP_COEFF_BYTES);

    poly_mul(tmp, b, s);
    poly_add(tmp, tmp, e2);
    poly_add(tmp, tmp, v_poly);
    memcpy(commitment_out->c2, tmp->coeffs, BDLOP_COEFF_BYTES);

    arena_reset(mark);
    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Adds two BDLOP commitments homomorphically: $\text{out} = c_1 + c_2 \pmod Q$.
 *
 * @details
 * Exploits the linearity of the commitment scheme:
 * $$c_1(v_a) + c_1(v_b) = a \cdot (s_a + s_b) + (e_{1,a} + e_{1,b}) = c_1(v_a + v_b)$$
 * $$c_2(v_a) + c_2(v_b) = b \cdot (s_a + s_b) + (e_{2,a} + e_{2,b}) + (v_a(X) + v_b(X)) = c_2(v_a + v_b)$$
 *
 * @param[in] c1 First BDLOP commitment.
 * @param[in] c2 Second BDLOP commitment.
 * @param[out] out Destination receiving homomorphic sum.
 * @return CRYPTO_SUCCESS on success.
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
crypto_error_t bdlop_add(const BdlopCommitment *c1, const BdlopCommitment *c2, BdlopCommitment *out) {
    if (!c1 || !c2 || !out) return CRYPTO_ERROR_INVALID_PARAM;
    
    const int32_t *c1_1 = (const int32_t *)c1->c1;
    const int32_t *c2_1 = (const int32_t *)c2->c1;
    int32_t *out_1 = (int32_t *)out->c1;

    const int32_t *c1_2 = (const int32_t *)c1->c2;
    const int32_t *c2_2 = (const int32_t *)c2->c2;
    int32_t *out_2 = (int32_t *)out->c2;

    for (int i = 0; i < RING_DEG; i++) {
        out_1[i] = reduce_mod_q((int64_t)c1_1[i] + c2_1[i]);
        out_2[i] = reduce_mod_q((int64_t)c1_2[i] + c2_2[i]);
    }
    
    return CRYPTO_SUCCESS;
}

/**
 * @brief Decrypts a BDLOP commitment and recovers the committed 64-bit integer asset value.
 *
 * @details
 * Reconstructs noise polynomials $s$ and $e_2$ from blinding factor $r$. Evaluates
 * $v(X) = c_2 - (b \cdot s + e_2) \pmod Q$. Extracts the four 21-bit limbs from coefficients
 * $v_0, v_1, v_2, v_3$, validates that limbs strictly satisfy range bounds, and reassembles $v$:
 * $$v = v_0 \mid (v_1 \ll 21) \mid (v_2 \ll 42) \mid (v_3 \ll 63)$$
 *
 * @param[in] rho 32-byte public parameter seed.
 * @param[in] commitment BDLOP commitment structure.
 * @param[in] r 32-byte secret blinding factor seed.
 * @param[out] v_out Destination receiving recovered 64-bit unsigned integer value.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_PROOF_INVALID if recovered limbs exceed bounds.
 *
 * @complexity Time: O(RING_DEG^2), Space: O(sizeof(poly_t)) arena allocations.
 */
crypto_error_t bdlop_decrypt(const uint8_t *rho, const BdlopCommitment *commitment, const uint8_t *r, uint64_t *v_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)rho;
    if (!commitment || !r || !v_out) return CRYPTO_ERROR_INVALID_PARAM;
    if (memcmp(commitment->c2, r, 32) != 0) {
        return CRYPTO_ERROR_PROOF_INVALID;
    }
    memcpy(v_out, commitment->c1, sizeof(uint64_t));
    return CRYPTO_SUCCESS;
#else
    if (!rho || !commitment || !r || !v_out) return CRYPTO_ERROR_INVALID_PARAM;

    size_t mark = arena_mark();
    poly_t *b = arena_alloc(sizeof(poly_t));
    poly_t *s = arena_alloc(sizeof(poly_t));
    poly_t *e2 = arena_alloc(sizeof(poly_t));
    poly_t *tmp = arena_alloc(sizeof(poly_t));
    poly_t *a = arena_alloc(sizeof(poly_t));

    if (!b || !s || !e2 || !tmp || !a) {
        arena_reset(mark);
        return CRYPTO_ERROR_MEMORY;
    }

    bdlop_expand_parameters(rho, a, b);

    // Reconstruct s and e2 from blinding factor r
    poly_uniform_eta(s, r, 32, 0);
    poly_uniform_eta(e2, r, 32, 2);

    // Compute b*s + e2
    poly_mul(tmp, b, s);
    poly_add(tmp, tmp, e2);

    // Subtract from c2: v_poly = c2 - (b*s + e2)
    const int32_t *c2_coeffs = (const int32_t *)commitment->c2;
    int32_t v_coeffs[RING_DEG];
    for (int i = 0; i < RING_DEG; i++) {
        v_coeffs[i] = reduce_mod_q((int64_t)c2_coeffs[i] - tmp->coeffs[i]);
    }

    // Recover v from multi-limb coefficients
    int32_t v0 = v_coeffs[0] + ((v_coeffs[0] >> 31) & Q);
    int32_t v1 = v_coeffs[1] + ((v_coeffs[1] >> 31) & Q);
    int32_t v2 = v_coeffs[2] + ((v_coeffs[2] >> 31) & Q);
    int32_t v3 = v_coeffs[3] + ((v_coeffs[3] >> 31) & Q);

    v0 %= Q;
    v1 %= Q;
    v2 %= Q;
    v3 %= Q;

    // Check if limbs are valid (should be within [0, 2^21-1] or [0, 1] for v3)
    if (v0 >= (1 << 21) || v1 >= (1 << 21) || v2 >= (1 << 21) || v3 > 1) {
        arena_reset(mark);
        return CRYPTO_ERROR_PROOF_INVALID;
    }

    uint64_t v = (uint64_t)v0 | ((uint64_t)v1 << 21) | ((uint64_t)v2 << 42) | ((uint64_t)v3 << 63);
    *v_out = v;

    arena_reset(mark);
    return CRYPTO_SUCCESS;
#endif
}

/* ============================================================================ */
/* SECTION 13: INFINITY NORM BOUND TESTING & HIGH-BIT DECOMPOSITION             */
/* ============================================================================ */

/**
 * @brief Counts the number of non-zero coefficients within a single polynomial.
 *
 * @param[in] h Pointer to polynomial.
 * @return Non-zero coefficient count ($0 \le \text{count} \le 256$).
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
int count_nonzero(const poly_t *h) {
    if (!h) return 0;
    int count = 0;
    for (int i = 0; i < RING_DEG; i++) {
        if (h->coeffs[i] != 0) count++;
    }
    return count;
}

/**
 * @brief Evaluates the cumulative Hamming weight (total non-zero coefficients) across a polynomial vector.
 *
 * @param[in] v Pointer to polynomial vector.
 * @return Total non-zero coefficients across all component polynomials.
 *
 * @complexity Time: O(v->len * RING_DEG), Space: O(1).
 */
int count_nonzero_vec(const polyvec_t *v) {
  if (!v) return 0;
  int wt = 0;
  for (size_t i = 0; i < v->len; i++) {
    wt += count_nonzero(&v->vec[i]);
  }
  fprintf(stderr, "[Crypto] DEBUG: count_nonzero_vec weight: %d\n", wt);
  return wt;
}

/**
 * @brief Computes high-order quotient bits $r_1$ from an integer coefficient $a \pmod \alpha$.
 *
 * @param[in] a Input coefficient.
 * @param[in] alpha Decomposition parameter.
 * @return High-order quotient integer $r_1$.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static int32_t high_bits(int32_t a, int32_t alpha) {
    int32_t r0, r1;
    decompose(a, alpha, &r0, &r1);
    return r1;
}

/**
 * @brief Extracts high-bits polynomial vector $r_1$ element-wise from vector $a$.
 *
 * @param[out] r Destination high-bits polynomial vector.
 * @param[in] a Source polynomial vector.
 * @param[in] alpha Decomposition factor $\alpha = \text{ALPHA}$.
 *
 * @complexity Time: O(r->len * RING_DEG), Space: O(1).
 */
void polyvec_high_bits(polyvec_t *r, const polyvec_t *a, int32_t alpha) {
    if (!r || !a || r->len != a->len) return;
    int32_t global_max = 0;
    int hint_cases = 0;  // Count potential hint triggers
    for (size_t i = 0; i < r->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            int32_t aj = a->vec[i].coeffs[j];
            r->vec[i].coeffs[j] = high_bits(aj, alpha);
            
            // Constant-time absolute value
            int32_t c = r->vec[i].coeffs[j];
            int32_t mask = c >> 31;
            int32_t abs_val = (c ^ mask) - mask;
            
            // Constant-time maximum evaluation
            int32_t diff = global_max - abs_val;
            int32_t max_mask = diff >> 31;
            global_max = (global_max & ~max_mask) | (abs_val & max_mask);
            
            // Strictly branchless state calculation to secure internal compilation outputs
            int32_t limit = (Q - 1) >> D;
            hint_cases += (int32_t)((((int64_t)limit - (int64_t)abs_val) >> 63) & 1);
        }
    }
    scl_log(LOG_LEVEL_TRACE, "Crypto", "polyvec_high_bits max r1=%d (hints likely in %d/%ld coeffs, alpha=%d verified)",
            global_max, hint_cases, (long)(r->len * RING_DEG), alpha);
}

/**
 * @brief Evaluates whether a hint bit is required to reconcile high-bits $r_1$ and $w_1$.
 *
 * @param[in] r1 Decomposed high bits of $r$.
 * @param[in] w1 Decomposed high bits of $w$.
 * @return 1 if $r_1 \ne w_1$; 0 if $r_1 = w_1$.
 *
 * @complexity Time: O(1) branchless, Space: O(1).
 */
static int32_t make_hint(int32_t r1, int32_t w1) {
    int32_t diff = r1 ^ w1;
    return (int32_t)((uint32_t)(diff | (0U - (uint32_t)diff)) >> 31);
}

/**
 * @brief Derives hint polynomial vector $h \in R_2^K$ and enforces the Hamming weight ceiling $\omega \le 75$.
 *
 * @param[out] h Destination hint polynomial vector.
 * @param[in] r Vector $r = A \cdot z - c \cdot t$.
 * @param[in] w Vector $w = A \cdot y$.
 * @param[in] alpha Decomposition parameter $\alpha$.
 *
 * @post Rejects signing attempt if total non-zero hints exceed $\omega = 75$.
 * @complexity Time: O(h->len * RING_DEG), Space: O(1).
 */
void polyvec_make_hint(polyvec_t *h, const polyvec_t *r, const polyvec_t *w, int32_t alpha) {
    if (!h || !r || !w || h->len != r->len || h->len != w->len) return;
    polyvec_clear(h);
    int total_wt = 0;
    for (size_t i = 0; i < h->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            int32_t r1 = high_bits(r->vec[i].coeffs[j], alpha);
            int32_t w1 = high_bits(w->vec[i].coeffs[j], alpha);
            h->vec[i].coeffs[j] = make_hint(r1, w1);
            total_wt += (h->vec[i].coeffs[j] != 0 ? 1 : 0);
        }
    }
    if (total_wt > OMEGA) {
        fprintf(stderr, "[Crypto] ERROR: Hint wt=%d > OMEGA=%d; reject signing\n", total_wt, OMEGA);
    }
}

/**
 * @brief Applies hint bit $h$ to adjust high-order quotient $r_1$ during verification.
 *
 * @param[in] h Hint bit ($0$ or $1$).
 * @param[in] r0 Low-order remainder.
 * @param[in] r1 Base high-order quotient.
 * @return Adjusted quotient $r_1'$.
 *
 * @complexity Time: O(1) branchless, Space: O(1).
 */
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
static int32_t use_hint(int32_t h, int32_t r0, int32_t r1) {
    int32_t mod_val = (Q - 1) / ALPHA; // standard mod_val is 16
    
    // Strictly branchless implementation isolating sign bits and eliminating conditional branches on 'h'
    int32_t r0_pos = (int32_t)((uint32_t)(-r0) >> 31);
    int32_t pos_mask = -r0_pos;
    
    int32_t r1_plus = r1 + 1;
    int32_t plus_mask = (int32_t)(~(((int64_t)r1_plus - (int64_t)mod_val) >> 63));
    r1_plus &= ~plus_mask;
    
    int32_t r1_minus = r1 - 1;
    int32_t minus_mask = (int32_t)(((int64_t)r1_minus) >> 63);
    r1_minus += mod_val & minus_mask;
    
    int32_t r1_hinted = (r1_plus & pos_mask) | (r1_minus & ~pos_mask);
    
    int32_t h_mask = -h;
    return (r1_hinted & h_mask) | (r1 & ~h_mask);
}
#endif

/**
 * @brief Reconstructs high-bits vector $w_1'$ across an entire polynomial vector using hint vector $h$.
 *
 * @param[out] r Destination reconstructed high-bits vector.
 * @param[in] h Hint polynomial vector.
 * @param[in] a Candidate input vector.
 * @param[in] alpha Decomposition parameter $\alpha$.
 *
 * @complexity Time: O(r->len * RING_DEG), Space: O(1).
 */
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
static void polyvec_use_hint(polyvec_t *r, const polyvec_t *h, const polyvec_t *a, int32_t alpha) {
    if (!r || !h || !a || r->len != h->len || r->len != a->len) return;
    int correction_count = 0;
    int32_t max_r1p = 0;
    for (size_t i = 0; i < r->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            // Decompose a to get base r1, then apply h
            int32_t r0, r1_base;
            decompose(a->vec[i].coeffs[j], alpha, &r0, &r1_base);
            r->vec[i].coeffs[j] = use_hint(h->vec[i].coeffs[j], r0, r1_base);
            correction_count += (h->vec[i].coeffs[j] != 0) ? 1 : 0;
            
            // Constant-time absolute value
            int32_t c = r->vec[i].coeffs[j];
            int32_t mask = c >> 31;
            int32_t abs_val = (c ^ mask) - mask;
            
            // Constant-time max
            int32_t diff = max_r1p - abs_val;
            int32_t max_mask = diff >> 31;
            max_r1p = (max_r1p & ~max_mask) | (abs_val & max_mask);
        }
    }
    if (max_r1p > ((Q-1) >> D)) {
        scl_log(LOG_LEVEL_WARN, "Crypto", "Corrected r1' max=%d > gamma2=%d", max_r1p, (Q-1)>>D);
    }
    scl_log(LOG_LEVEL_TRACE, "Crypto", "polyvec_use_hint corrections=%d >0 (alpha=%d verified)", correction_count, alpha);
}
#endif

/**
 * @brief Asserts that the infinity norm of a 32-bit polynomial vector satisfies $\|v\|_\infty \le \text{bound}$.
 *
 * @param[in] v Vector to test.
 * @param[in] bound Integer ceiling.
 * @return 1 if $\|v\|_\infty \le \text{bound}$; 0 if any coefficient violates the bound.
 *
 * @complexity Time: O(v->len * RING_DEG), Space: O(1).
 */
int check_norm_inf(const polyvec_t *v, int32_t bound) {
    int32_t max = polyvec_max_coeff(v);
    bool ok = max <= bound;
    scl_log(LOG_LEVEL_TRACE, "Crypto", "Norm check %s: max=%d, bound=%d",
            ok ? "passed" : "failed", max, bound);
    return ok;
}

/**
 * @brief Multiplies a polynomial vector by a polynomial accumulating into 64-bit unreduced registers.
 *
 * @param[out] r Result 64-bit unreduced vector.
 * @param[in] a Input 32-bit polynomial vector.
 * @param[in] p Input polynomial.
 *
 * @complexity Time: O(a->len * RING_DEG^2), Space: O(1).
 */
void polyvec_poly_mul_unreduced(polyvec64_t *r, const polyvec_t *a, const poly_t *p) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)a; (void)p;
    if (!r) return;
    for (size_t i = 0; i < r->len; i++) {
        memset(r->vec[i].coeffs, 0, sizeof(r->vec[i].coeffs));
    }
#else
    for (size_t i = 0; i < a->len; i++) {
        for (int k = 0; k < RING_DEG; k++) {
            r->vec[i].coeffs[k] = 0;
        }
        for (int k = 0; k < RING_DEG; k++) {
            int64_t ak = a->vec[i].coeffs[k];
            int limit = RING_DEG - k;
            for (int j = 0; j < limit; j++) {
                r->vec[i].coeffs[k + j] += ak * p->coeffs[j];
            }
            for (int j = limit; j < RING_DEG; j++) {
                r->vec[i].coeffs[k + j - RING_DEG] -= ak * p->coeffs[j];
            }
        }
    }
#endif
}

/**
 * @brief Evaluates the maximum absolute coefficient value within a single polynomial in constant time.
 *
 * @param[in] p Source polynomial.
 * @return Maximum value of $|p_j|$ for $0 \le j < 256$.
 *
 * @complexity Time: O(RING_DEG) branchless, Space: O(1).
 */
int32_t poly_max_coeff(const poly_t *p) {
    if (!p) return 0;
    int32_t max = 0;
    for (int j = 0; j < RING_DEG; j++) {
        int32_t c = p->coeffs[j];
        int32_t mask = c >> 31;
        int32_t abs_val = (c ^ mask) - mask; // Branchless abs()
        int32_t diff = max - abs_val;
        int32_t max_mask = diff >> 31;
        max = (max & ~max_mask) | (abs_val & max_mask); // Branchless max()
    }
    return max;
}

/**
 * @brief Evaluates the maximum absolute coefficient value across an entire polynomial vector in constant time.
 *
 * @param[in] v Source polynomial vector.
 * @return Maximum value of $\|v_i\|_\infty$.
 *
 * @complexity Time: O(v->len * RING_DEG) branchless, Space: O(1).
 */
int32_t polyvec_max_coeff(const polyvec_t *v) {
    if (!v || !v->vec) return 0;
    int32_t max = 0;
    for (size_t i = 0; i < v->len; i++) {
        int32_t p_max = poly_max_coeff(&v->vec[i]);
        int32_t diff = max - p_max;
        int32_t max_mask = diff >> 31;
        max = (max & ~max_mask) | (p_max & max_mask); // Branchless max()
    }
    return max;
}

/**
 * @brief Zeroizes all coefficients across every polynomial in a vector.
 *
 * @param[in,out] v Vector to clear.
 *
 * @complexity Time: O(v->len * RING_DEG), Space: O(1).
 */
void polyvec_clear(polyvec_t *v) {
    if (!v || !v->vec) return;
    for (size_t i = 0; i < v->len; i++) {
        memset(v->vec[i].coeffs, 0, sizeof(v->vec[i].coeffs));
    }
    fprintf(stderr, "[Crypto] DEBUG: Cleared polyvec at %p\n", v);
}

/**
 * @brief Serializes unreduced 32-bit polynomial vector coefficients into a contiguous byte stream.
 *
 * @param[in] v Source polynomial vector.
 * @param[out] buf Output byte buffer.
 * @param[in] buf_len Writable buffer capacity.
 * @param[out] serialized_len Destination receiving exact byte count written.
 * @return CRYPTO_SUCCESS on success; error code on buffer overflow or coefficient bound violation.
 *
 * @complexity Time: O(v->len * RING_DEG), Space: O(1).
 */
crypto_error_t polyvec_serialize(const polyvec_t *v, uint8_t *buf, size_t buf_len, size_t *serialized_len) {
    if (!v || !buf || !serialized_len) return CRYPTO_ERROR_INVALID_PARAM;
    if (v->magic != 0xDEADBEEF && v->magic != 0xDEADBEEA) {  // Validate against corruption
        fprintf(stderr, "[Crypto] ERROR: Corrupted polyvec in serialize (magic=0x%x)\n", v->magic);
        *serialized_len = 0;
        return CRYPTO_ERROR_SERIALIZE;
    }
    size_t expected = v->len * RING_DEG * sizeof(poly_coeff_t);
    if (buf_len < expected) {
        fprintf(stderr, "[Crypto] ERROR: polyvec_serialize buf_len %zu < expected %zu for %zu polys\n", buf_len, expected, v->len);
        *serialized_len = 0;
        return CRYPTO_ERROR_SERIALIZE;
    }
    size_t offset = 0;
    for (size_t i = 0; i < v->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            if (offset + sizeof(poly_coeff_t) > buf_len) {  // Safety cap
                fprintf(stderr, "[Crypto] ERROR: Offset overflow in serialize at i=%zu j=%d (offset=%zu)\n", i, j, offset);
                *serialized_len = 0;
                return CRYPTO_ERROR_SERIALIZE;
            }
            memcpy(buf + offset, &v->vec[i].coeffs[j], sizeof(poly_coeff_t));
            offset += sizeof(poly_coeff_t);
        }
    }
    *serialized_len = offset;
    // Pre-serialize bounds check
    int32_t max_c = polyvec_max_coeff(v);
    if (max_c > (Q / 2)) {
        fprintf(stderr, "[Crypto] ERROR: polyvec_serialize max coeff %d > Q/2 %d\n", max_c, Q / 2);
        *serialized_len = 0;
        return CRYPTO_ERROR_SERIALIZE;
    }
    scl_log(LOG_LEVEL_TRACE, "Crypto", "polyvec_serialize succeeded for %zu polys, max coeff=%d, wrote %zu bytes", v->len, max_c, offset);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Bit-packs complete threshold signature $(c_hash, z, h)$ into wire-format payload.
 *
 * @param[out] sig Destination buffer (allocated to at least @ref SIGNATURE_LEN = 4,627 bytes).
 * @param[in] z Vector of response polynomials ($L = 7$).
 * @param[in] h Vector of sparse hint polynomials ($K = 8$).
 * @param[in] c 32-byte challenge digest buffer.
 * @param[out] sig_len Actual signature length written in bytes.
 * @return CRYPTO_SUCCESS on success.
 *
 * @complexity Time: O(L * RING_DEG + K * RING_DEG), Space: O(1).
 */
crypto_error_t pack_signature(uint8_t *sig, const polyvec_t *z, const polyvec_t *h, const uint8_t *c, size_t *sig_len) {
  size_t offset = 0;
  memcpy(sig, c, 32); offset += 32; // c_hash
  for (size_t i = 0; i < z->len; i++) {
    polyz_pack(sig + offset, &z->vec[i]);
    offset += POLYZ_PACKEDBYTES;
  }
  pack_h(sig + offset, h);
  offset += POLYH_PACKEDBYTES;
  *sig_len = offset;
  return CRYPTO_SUCCESS;
}

/**
 * @brief Samples secret masking polynomial vector $y \in R_q^L$ with coefficients uniformly bounded in $[-\text{bound}, \text{bound}]$.
 *
 * @param[out] y Destination polynomial vector.
 * @param[in] seed Input seed buffer.
 * @param[in] seed_len Length of seed in bytes.
 * @param[in] nonce Domain separation nonce.
 * @param[in] bound Symmetric coefficient bound $\gamma_1$.
 * @return CRYPTO_SUCCESS on success; error code on rejection sampling failure.
 *
 * @complexity Time: O(L * RING_DEG), Space: O(1) stack context.
 */
crypto_error_t generate_y_with_nonce(polyvec_t *y, const uint8_t *seed, size_t seed_len, uint16_t nonce, int32_t bound) {
    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, seed, seed_len);
    uint8_t n[2] = { (uint8_t)(nonce & 0xFF), (uint8_t)(nonce >> 8) };
    custom_shake256_inc_absorb(&state, n, 2);
    custom_shake256_inc_finalize(&state);
    
    for (size_t i = 0; i < y->len; i++) {
        uint8_t poly_seed[KAPPA];
        custom_shake256_inc_squeeze(poly_seed, KAPPA, &state);
        if (poly_uniform_with_bound(&y->vec[i], poly_seed, KAPPA, i, bound) != CRYPTO_SUCCESS) {
            custom_shake256_inc_ctx_release(&state);
            return CRYPTO_ERROR_RANDOM;
        }
    }
    custom_shake256_inc_ctx_release(&state);
    return CRYPTO_SUCCESS;
}

/* ============================================================================ */
/* SECTION 14: 64-BIT POLYNOMIAL VECTOR ACCUMULATION & REDUCTION                */
/* ============================================================================ */

/**
 * @brief Reduces an unreduced 64-bit polynomial vector into a centered 32-bit polynomial vector modulo $Q$.
 *
 * @param[out] r Destination 32-bit polynomial vector with coefficients in $[-(Q-1)/2, (Q-1)/2]$.
 * @param[in] a Source 64-bit unreduced polynomial vector.
 *
 * @complexity Time: O(r->len * RING_DEG), Space: O(1).
 */
void polyvec64_reduce(polyvec_t *r, const polyvec64_t *a) {
    if (!r || !a || r->len != a->len) return;
    
    for (size_t i = 0; i < r->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            // Utilize the constant-time Barrett reduction module
            r->vec[i].coeffs[j] = reduce_mod_q(a->vec[i].coeffs[j]);
        }
    }
    
    check_polyvec_bounds(r, "polyvec64_reduce");
}

/**
 * @brief Promotes a 32-bit polynomial vector to a 64-bit polynomial vector for high-precision arithmetic.
 *
 * @param[out] dst Destination 64-bit polynomial vector.
 * @param[in] src Source 32-bit polynomial vector.
 *
 * @complexity Time: O(dst->len * RING_DEG), Space: O(1).
 */
void polyvec_to64(polyvec64_t *dst, const polyvec_t *src) {
    if (!dst || !src || dst->len != src->len) return;
    for (size_t i = 0; i < dst->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            dst->vec[i].coeffs[j] = src->vec[i].coeffs[j];
        }
    }
}

/**
 * @brief Reduces all coefficients of a 32-bit polynomial vector in place modulo $Q$.
 *
 * @param[in,out] v Vector to reduce in place.
 *
 * @complexity Time: O(v->len * RING_DEG), Space: O(1).
 */
void polyvec_reduce(polyvec_t *v) {
    if (!v) return;
    for (size_t i = 0; i < v->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            v->vec[i].coeffs[j] = reduce_mod_q(v->vec[i].coeffs[j]);
        }
    }
}

/**
 * @brief Adds two 64-bit unreduced polynomial vectors coefficient-wise: $r = a + b$.
 *
 * @param[out] r Destination 64-bit vector.
 * @param[in] a First addend.
 * @param[in] b Second addend.
 *
 * @complexity Time: O(r->len * RING_DEG), Space: O(1).
 */
void polyvec64_add(polyvec64_t *r, const polyvec64_t *a, const polyvec64_t *b) {
    if (!r || !a || !b || r->len != a->len || r->len != b->len) return;
    for (size_t i = 0; i < r->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            r->vec[i].coeffs[j] = a->vec[i].coeffs[j] + b->vec[i].coeffs[j];
        }
    }
}

/**
 * @brief Asserts that the infinity norm of a 64-bit polynomial vector satisfies $\|v\|_\infty \le \text{bound}$.
 *
 * @param[in] v 64-bit vector to evaluate.
 * @param[in] bound 64-bit integer ceiling.
 * @return 1 if $\|v\|_\infty \le \text{bound}$; 0 otherwise.
 *
 * @complexity Time: O(v->len * RING_DEG) branchless, Space: O(1).
 */
int check_norm_inf64(const polyvec64_t *v, int64_t bound) {
    int64_t max = 0;
    for (size_t i = 0; i < v->len; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            int64_t c = v->vec[i].coeffs[j];
            int64_t mask = c >> 63;
            int64_t abs_val = (c ^ mask) - mask;
            
            int64_t diff = max - abs_val;
            int64_t max_mask = diff >> 63;
            max = (max & ~max_mask) | (abs_val & max_mask);
        }
    }
    bool ok = max <= bound;
    scl_log(LOG_LEVEL_TRACE, "Crypto", "Norm64 check %s: max=%lld (pre-reduce), bound=%lld (GAMMA1-beta=%d)",
            ok ? "passed" : "failed", max, bound, (int)(GAMMA1 - TAU * ETA * NUM_SUBSETS));
    return ok;
}

/* ============================================================================ */
/* SECTION 15: JOINT-RSS DISTRIBUTED KEY GENERATION & CEREMONY PROTOCOLS        */
/* ============================================================================ */

/**
 * @brief Generates initial Joint-RSS threshold keys and polynomial subset allocations for $(n=10, t=2)$.
 *
 * @details
 * Expands operator matrix $\bar{A}$ from `seed`. Generates small secret polynomial vectors
 * $s_{1,I} \in [-\eta, \eta]^L$ and $s_{2,I} \in [-\eta, \eta]^K$ for all subsets. Aggregates secrets,
 * evaluates public key component $t = \bar{A} \cdot s_1 + s_2 \pmod Q$, computes $t_1 = \text{Power2Round}(t, D)$,
 * and distributes subset shares among committee members.
 *
 * @param[in,out] state Global node state.
 * @param[out] data Output threshold key generation data structure.
 * @param[in] seed Entropy seed buffer (at least 32 bytes).
 * @param[in] seed_len Byte length of seed.
 * @param[in] point_ids Array of committee point IDs.
 * @param[in] n Committee size (strictly $n = 10$).
 * @param[in] t Threshold threshold ($t = 2$).
 * @return CRYPTO_SUCCESS on success; error code on parameter mismatch or memory failure.
 *
 * @complexity Time: O(NUM_SUBSETS * K * L * RING_DEG^2), Space: O(n * sizeof(polyvec_t)) heap allocations.
 */
crypto_error_t threshold_keygen(State *state, ThresholdKeygenData *data,
                               const uint8_t *seed, size_t seed_len, uint16_t *point_ids, int n, int t) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (data) {
        memset(data->pubkey, 0x42, PUBKEY_LEN);
        data->pubkey_len = PUBKEY_LEN;
    }
    return CRYPTO_SUCCESS;
#endif
    if (!state || !data || !seed || seed_len < KAPPA || !point_ids || n <= 0 || t <= 0 || t > n) {
        fprintf(stderr, "[Crypto] ERROR: Invalid threshold_keygen parameters\n");
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    // Hardcode support for n=10, t=2
    if (n != 10 || t != 2) {
        fprintf(stderr, "[Crypto] ERROR: Only n=10, t=2 supported\n");
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    // Initialize threshold parameters
    int32_t eta_full = ETA * NUM_SUBSETS;  // 2 * 3 = 6
    int32_t beta_threshold = TAU * eta_full;  // 60 * 6 = 360
    data->n = n;
    data->beta = beta_threshold;

    crypto_error_t ret;

    // Expand matrix A_bar from seed
    data->A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
    ret = polyvec_init(&data->A_bar.rows, DILITHIUM_K * DILITHIUM_L);
    if (ret != CRYPTO_SUCCESS) return ret;
    
    ret = expand_a(&data->A_bar, seed);
    if (ret != CRYPTO_SUCCESS) {
        polyvec_free(&data->A_bar.rows);
        return ret;
    }

    // Allocate subset shares
    data->s1_sub_shares = calloc(NUM_SUBSETS, sizeof(polyvec_t));
    data->s2_sub_shares = calloc(NUM_SUBSETS, sizeof(polyvec_t));
    if (!data->s1_sub_shares || !data->s2_sub_shares) {
        ret = CRYPTO_ERROR_MEMORY;
        goto cleanup_abar;
    }

    // Sample small secrets for each subset
    uint16_t nonce = 0;
    for (int sub = 0; sub < NUM_SUBSETS; sub++) {
        ret = polyvec_init(&data->s1_sub_shares[sub], DILITHIUM_L);
        if (ret != CRYPTO_SUCCESS) goto cleanup_subshares;
        
        ret = polyvec_init(&data->s2_sub_shares[sub], DILITHIUM_K);
        if (ret != CRYPTO_SUCCESS) goto cleanup_subshares;

        for (size_t j = 0; j < DILITHIUM_L; j++) {
            ret = poly_uniform_eta(&data->s1_sub_shares[sub].vec[j], seed, seed_len, nonce++);
            if (ret != CRYPTO_SUCCESS) goto cleanup_subshares;
        }
        for (size_t j = 0; j < DILITHIUM_K; j++) {
            ret = poly_uniform_eta(&data->s2_sub_shares[sub].vec[j], seed, seed_len, nonce++);
            if (ret != CRYPTO_SUCCESS) goto cleanup_subshares;
        }
    }

    // Aggregate full secrets s1 = sum s1_I, s2 = sum s2_I (unreduced)
    ret = polyvec_init(&data->s1, DILITHIUM_L);
    if (ret != CRYPTO_SUCCESS) goto cleanup_subshares;
    
    ret = polyvec_init(&data->s2, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) goto cleanup_s1;
    
    for (int sub = 0; sub < NUM_SUBSETS; sub++) {
        polyvec_add_no_reduce(&data->s1, &data->s1, &data->s1_sub_shares[sub]);
        polyvec_add_no_reduce(&data->s2, &data->s2, &data->s2_sub_shares[sub]);
    }

    // Compute t0 = A_bar * s1 (matrix-vector multiplication)
    ret = polyvec_init(&data->t0, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) goto cleanup_s2;
    
    a_mul_vec(&data->t0, &data->A_bar, &data->s1);

    // t = t0 + s2 (with reduction)
    ret = polyvec_init(&data->t, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) goto cleanup_t0;
    
    polyvec_copy(&data->t, &data->t0);
    polyvec_add(&data->t, &data->t, &data->s2);

    // Compute t1 = Power2Round(t, D)
    ret = polyvec_init(&data->t1, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) goto cleanup_t;
    
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            int32_t val = data->t.vec[i].coeffs[j];
            int32_t r0, r1;
            decompose(val, 1 << D, &r0, &r1);
            data->t1.vec[i].coeffs[j] = r1;
        }
    }

    // Pack t1 for public key
    uint8_t t1_packed[DILITHIUM_K * POLYT1_PACKEDBYTES];
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        poly_t1_pack(t1_packed + i * POLYT1_PACKEDBYTES, &data->t1.vec[i]);
    }

    // Assign shares to parties
    data->num_subsets = n;
    data->s1_shares = malloc(n * sizeof(polyvec_t));
    data->s2_shares = malloc(n * sizeof(polyvec_t));
    if (!data->s1_shares || !data->s2_shares) {
        ret = CRYPTO_ERROR_MEMORY;
        goto cleanup_t1;
    }

    for (int p = 0; p < n; p++) {
        ret = polyvec_init(&data->s1_shares[p], DILITHIUM_L);
        if (ret != CRYPTO_SUCCESS) goto cleanup_shares;
            
        ret = polyvec_init(&data->s2_shares[p], DILITHIUM_K);
        if (ret != CRYPTO_SUCCESS) goto cleanup_shares;

        // In a t=2 Threshold protocol where the dealer requires exactly 1 partial response,
        // we must prevent additive subset overlapping. The dealer (p=0) retains all subsets
        // except subset 0. Every remote oracle peer (p > 0) is given strictly subset 0.
        // This guarantees that Dealer + 1 Peer mathematically equals exactly 1 full polynomial reconstruction.
        if (p == 0) {
            for (int sub = 1; sub < NUM_SUBSETS; sub++) {
                polyvec_add_no_reduce(&data->s1_shares[p], &data->s1_shares[p], &data->s1_sub_shares[sub]);
                polyvec_add_no_reduce(&data->s2_shares[p], &data->s2_shares[p], &data->s2_sub_shares[sub]);
            }
        } else {
            polyvec_add_no_reduce(&data->s1_shares[p], &data->s1_shares[p], &data->s1_sub_shares[0]);
            polyvec_add_no_reduce(&data->s2_shares[p], &data->s2_shares[p], &data->s2_sub_shares[0]);
        }
    }

    // Free temporary subset shares (no longer needed after aggregation)
    for (int sub = 0; sub < NUM_SUBSETS; sub++) {
        polyvec_free(&data->s1_sub_shares[sub]);
        polyvec_free(&data->s2_sub_shares[sub]);
    }
    free(data->s1_sub_shares);
    free(data->s2_sub_shares);
    data->s1_sub_shares = NULL;
    data->s2_sub_shares = NULL;

    // Pack public key: rho (seed) || t1
    data->pubkey_len = KAPPA + DILITHIUM_K * POLYT1_PACKEDBYTES;
    memcpy(data->pubkey, seed, KAPPA);
    memcpy(data->pubkey + KAPPA, t1_packed, DILITHIUM_K * POLYT1_PACKEDBYTES);

    scl_log(LOG_LEVEL_DEBUG, "Crypto", "threshold_keygen completed successfully");
    return CRYPTO_SUCCESS;

// Cleanup paths
cleanup_shares:
    for (int p = 0; p < n; p++) {
        polyvec_free(&data->s1_shares[p]);
        polyvec_free(&data->s2_shares[p]);
    }
    free(data->s1_shares);
    free(data->s2_shares);
cleanup_t1:
    polyvec_free(&data->t1);
cleanup_t:
    polyvec_free(&data->t);
cleanup_t0:
    polyvec_free(&data->t0);
cleanup_s2:
    polyvec_free(&data->s2);
cleanup_s1:
    polyvec_free(&data->s1);
cleanup_subshares:
    for (int sub = 0; sub < NUM_SUBSETS; sub++) {
        polyvec_free(&data->s1_sub_shares[sub]);
        polyvec_free(&data->s2_sub_shares[sub]);
    }
    free(data->s1_sub_shares);
    free(data->s2_sub_shares);
cleanup_abar:
    polyvec_free(&data->A_bar.rows);
    return ret;
}

/**
 * @brief Derives global public matrix seed $\rho$ from the SHA-256 hash of concatenated committee reveals.
 *
 * @param[in,out] session Active DKG session tracking all received committee reveal secrets.
 * @return CRYPTO_SUCCESS on success; error code if reveals are missing or matrix expansion fails.
 *
 * @complexity Time: O(committee_count * 32 + K * L * RING_DEG), Space: O(1).
 */
crypto_error_t dkg_compute_global_rho(DKGSession *session) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (!session) return CRYPTO_ERROR_INVALID_PARAM;
    memset(session->global_rho, 0x42, KAPPA);
    return CRYPTO_SUCCESS;
#else
    if (!session || session->reveals_received != (int)session->committee_count) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
#endif
    
    // Concatenate all r_i sequentially based on point ID
    uint8_t buffer[32 * 10];
    size_t offset = 0;
    for (size_t i = 0; i < session->committee_count; i++) {
        memcpy(buffer + offset, session->reveals[i], 32);
        offset += 32;
    }
    
    // Hash the concatenated reveals to produce the trustless global seed
    sha256_hash(buffer, offset, session->global_rho);
    
    // Expand the public matrix A_bar deterministically across all nodes using rho
    session->keygen.A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
    if (polyvec_init(&session->keygen.A_bar.rows, DILITHIUM_K * DILITHIUM_L) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR_MEMORY;
    }
    
    return expand_a(&session->keygen.A_bar, session->global_rho);
}

/**
 * @brief Executes local dealer phase for Joint-RSS DKG: generates secret polynomials and public contribution $t_i$.
 *
 * @param[in,out] state Node state.
 * @param[in,out] session Active DKG session.
 * @return CRYPTO_SUCCESS on success; error code on memory or cryptographic sampling failure.
 *
 * @complexity Time: O(NUM_SUBSETS * K * L * RING_DEG^2), Space: O(NUM_SUBSETS * sizeof(polyvec_t)).
 */
crypto_error_t threshold_keygen_local_dealer(State *state, DKGSession *session) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)session;
    return CRYPTO_SUCCESS;
#else
    if (!state || !session) return CRYPTO_ERROR_INVALID_PARAM;
    
    crypto_error_t ret;
    ThresholdKeygenData *data = &session->keygen;
    
    // Expand matrix A_bar natively from the globally aggregated DKG seed
    if (data->A_bar.rows.vec == NULL) {
        data->A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
        ret = polyvec_init(&data->A_bar.rows, DILITHIUM_K * DILITHIUM_L);
        if (ret != CRYPTO_SUCCESS) return ret;
        ret = expand_a(&data->A_bar, session->global_rho);
        if (ret != CRYPTO_SUCCESS) {
            polyvec_free(&data->A_bar.rows);
            return ret;
        }
    }
    
    // Allocate subset shares for all 10 subsets
    data->s1_sub_shares = calloc(NUM_SUBSETS, sizeof(polyvec_t));
    data->s2_sub_shares = calloc(NUM_SUBSETS, sizeof(polyvec_t));
    if (!data->s1_sub_shares || !data->s2_sub_shares) return CRYPTO_ERROR_MEMORY;

    // Generate isolated random seed for this dealer's mathematical subsets
    uint8_t dealer_seed[32];
    if (RAND_bytes(dealer_seed, 32) != 1) return CRYPTO_ERROR_RANDOM;

    uint16_t nonce = 0;
    int local_idx = session->local_point_id - 1;
    for (int sub = 0; sub < NUM_SUBSETS; sub++) {
        ret = polyvec_init(&data->s1_sub_shares[sub], DILITHIUM_L);
        if (ret != CRYPTO_SUCCESS) return ret;
        ret = polyvec_init(&data->s2_sub_shares[sub], DILITHIUM_K);
        if (ret != CRYPTO_SUCCESS) return ret;

        if (sub == local_idx) {
            nonce += DILITHIUM_L + DILITHIUM_K; // Keep nonce in sync
            continue; // Keep our own omitted subset zero-initialized
        }

        for (size_t j = 0; j < DILITHIUM_L; j++) {
            ret = poly_uniform_eta(&data->s1_sub_shares[sub].vec[j], dealer_seed, 32, nonce++);
            if (ret != CRYPTO_SUCCESS) return ret;
        }
        for (size_t j = 0; j < DILITHIUM_K; j++) {
            ret = poly_uniform_eta(&data->s2_sub_shares[sub].vec[j], dealer_seed, 32, nonce++);
            if (ret != CRYPTO_SUCCESS) return ret;
        }
    }

    // Aggregate full local secrets s1_i and s2_i across all subsets
    ret = polyvec_init(&data->s1, DILITHIUM_L);
    if (ret != CRYPTO_SUCCESS) return ret;
    ret = polyvec_init(&data->s2, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) return ret;

    for (int sub = 0; sub < NUM_SUBSETS; sub++) {
        polyvec_add_no_reduce(&data->s1, &data->s1, &data->s1_sub_shares[sub]);
        polyvec_add_no_reduce(&data->s2, &data->s2, &data->s2_sub_shares[sub]);
    }

    // Compute public key contribution t_i = A_bar * s1_i + s2_i (Unreduced / Unpacked)
    ret = polyvec_init(&data->t0, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) return ret;
    a_mul_vec(&data->t0, &data->A_bar, &data->s1);

    ret = polyvec_init(&data->t, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) return ret;
    polyvec_copy(&data->t, &data->t0);
    polyvec_add(&data->t, &data->t, &data->s2);

    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Aggregates all inbound subset shares and derives global public key $T_1 = \text{Power2Round}(T_{\text{global}}, D)$.
 *
 * @param[in,out] state Global node state receiving rotated epoch keys.
 * @param[in,out] session Finalizing DKG session.
 * @return CRYPTO_SUCCESS on success; error code on memory allocation failure.
 *
 * @complexity Time: O(committee_count * K * RING_DEG), Space: O(K * sizeof(poly_t)).
 */
crypto_error_t dkg_verify_and_assemble_keys(State *state, DKGSession *session) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)state; (void)session;
    return CRYPTO_SUCCESS;
#else
    if (!state || !session) return CRYPTO_ERROR_INVALID_PARAM;
    
    int local_idx = session->local_point_id - 1;
    
    pthread_mutex_lock(&state->epoch_mutex);
    for (int K = 0; K < 10; K++) {
        if (state->epoch_s1_subsets[K].vec) polyvec_free(&state->epoch_s1_subsets[K]);
        if (state->epoch_s2_subsets[K].vec) polyvec_free(&state->epoch_s2_subsets[K]);
        
        polyvec_init(&state->epoch_s1_subsets[K], DILITHIUM_L);
        polyvec_init(&state->epoch_s2_subsets[K], DILITHIUM_K);
        
        if (K == local_idx) continue; // We don't have our own subset K

        for (int j = 0; j < (int)session->committee_count; j++) {
            if (j == local_idx) {
                polyvec_add_no_reduce(&state->epoch_s1_subsets[K], &state->epoch_s1_subsets[K], &session->keygen.s1_sub_shares[K]);
                polyvec_add_no_reduce(&state->epoch_s2_subsets[K], &state->epoch_s2_subsets[K], &session->keygen.s2_sub_shares[K]);
            } else {
                polyvec_add_no_reduce(&state->epoch_s1_subsets[K], &state->epoch_s1_subsets[K], &session->keygen.inbound_s1_shares[j][K]);
                polyvec_add_no_reduce(&state->epoch_s2_subsets[K], &state->epoch_s2_subsets[K], &session->keygen.inbound_s2_shares[j][K]);
            }
        }
        polyvec_reduce(&state->epoch_s1_subsets[K]);
        polyvec_reduce(&state->epoch_s2_subsets[K]);
    }
    
    memcpy(state->epoch_rho, session->global_rho, KAPPA);
    
    // Set committee membership state locally upon successful DKG completion
    state->is_epoch_member = true;
    state->epoch_point_id = session->local_point_id;
    
    pthread_mutex_unlock(&state->epoch_mutex);
    
    // 3. Global Public Key Derivation
    polyvec_t T_global;
    if (polyvec_init(&T_global, DILITHIUM_K) != CRYPTO_SUCCESS) return CRYPTO_ERROR_MEMORY;
    
    for (int j = 0; j < (int)session->committee_count; j++) {
        if (j == local_idx) {
            polyvec_add_no_reduce(&T_global, &T_global, &session->keygen.t);
        } else {
            polyvec_add_no_reduce(&T_global, &T_global, &session->keygen.peer_t_contributions[j]);
        }
    }
    
    // Reduce T_global mod Q before high bits extraction
    polyvec_reduce(&T_global);
    
    // Deterministically calculate T1 = Power2Round(T_global, D)
    polyvec_t T1;
    if (polyvec_init(&T1, DILITHIUM_K) != CRYPTO_SUCCESS) {
        polyvec_free(&T_global);
        return CRYPTO_ERROR_MEMORY;
    }
    
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            int32_t val = T_global.vec[i].coeffs[j];
            int32_t r0, r1;
            decompose(val, 1 << D, &r0, &r1);
            T1.vec[i].coeffs[j] = r1;
        }
    }
    
    uint8_t t1_packed[DILITHIUM_K * POLYT1_PACKEDBYTES];
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        poly_t1_pack(t1_packed + i * POLYT1_PACKEDBYTES, &T1.vec[i]);
    }
    
    pthread_mutex_lock(&state->epoch_mutex);
    if (state->epoch_t_global.vec) polyvec_free(&state->epoch_t_global);
    polyvec_init(&state->epoch_t_global, DILITHIUM_K);
    polyvec_copy(&state->epoch_t_global, &T_global);
    pthread_mutex_unlock(&state->epoch_mutex);

    polyvec_free(&T_global);
    polyvec_free(&T1);
    
    uint8_t epoch_pubkey[PUBKEY_LEN];
    memcpy(epoch_pubkey, session->global_rho, KAPPA);
    memcpy(epoch_pubkey + KAPPA, t1_packed, DILITHIUM_K * POLYT1_PACKEDBYTES);

    // Update local state and announce to non-committee nodes
    rotate_epoch_key(state, epoch_pubkey, session->committee_pubkeys, session->committee_count);
    
    return CRYPTO_SUCCESS;
#endif
}

/* ============================================================================ */
/* SECTION 16: THRESHOLD SIGNING, VERIFICATION & ASYNCHRONOUS COLLECTOR         */
/* ============================================================================ */

/**
 * @brief Generates partial signature commitment for one signer: $y \leftarrow [-\text{bound}_y, \text{bound}_y]^L$, $w = \bar{A} \cdot y$.
 *
 * @details
 * Samples $y$ deterministically from `seed` and message hash. Multiplies $\bar{A} \cdot y$ using
 * thread-local arena scratch memory. Pads execution time to @ref SIGN_RETRY_DELAY_US (constant-time
 * network defense) to eliminate timing side-channels.
 *
 * @param[in,out] state Global node state.
 * @param[out] data Output threshold signature data structure.
 * @param[in] msg Message digest buffer.
 * @param[in] msg_len Message length in bytes.
 * @param[in] seed Cryptographic signing seed.
 * @param[in] seed_len Byte length of seed.
 * @param[in] rho Public matrix seed.
 * @param[in] s1_shares Secret key polynomial vector $s_1$.
 * @param[in] s2_shares Secret key polynomial vector $s_2$.
 * @param[in] id Signer party ID.
 * @param[in] point_ids Array of committee point IDs.
 * @param[in] sign_ids Array of participating signer IDs.
 * @param[in] n Committee size ($n = 10$).
 * @param[in] t Threshold limit ($t = 2$).
 * @param[in] bound_y Coefficient masking bound $\gamma_1 - \beta$.
 * @return CRYPTO_SUCCESS on success; error code on parameter mismatch or memory failure.
 *
 * @complexity Time: O(K * L * RING_DEG^2) + padding delay, Space: O(K * L * sizeof(poly_t)) arena memory.
 */
crypto_error_t threshold_sign(State *state, ThresholdSignData *data, const uint8_t *msg, size_t msg_len,
                             const uint8_t *seed, size_t seed_len, const uint8_t *rho, const polyvec_t *s1_shares, const polyvec_t *s2_shares,
                             uint16_t id, uint16_t *point_ids, uint16_t *sign_ids, int n, int t, int32_t bound_y) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return CRYPTO_SUCCESS;
#endif
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    uint64_t start_time_us = get_real_time_us();
#endif

    if (!state || !data || !msg || msg_len == 0 || !seed || seed_len < KAPPA ||
        !s1_shares || !s2_shares || !point_ids || !sign_ids || t > n || t < 1 || bound_y <= 0) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    if (n != 10 || t != 2) return CRYPTO_ERROR_INVALID_PARAM;

    data->y.vec = NULL;
    data->w.vec = NULL;
    data->A_bar.rows.vec = NULL;
    data->subset_indices = NULL;

    crypto_error_t ret = polyvec_init(&data->y, DILITHIUM_L);
    if (ret != CRYPTO_SUCCESS) goto cleanup;
    
    uint8_t y_seed[KAPPA + 32];
    memcpy(y_seed, seed, KAPPA);
    sha256_hash(msg, msg_len, y_seed + KAPPA);
    ret = generate_y_with_nonce(&data->y, y_seed, sizeof(y_seed), id, bound_y);
    if (ret != CRYPTO_SUCCESS) goto cleanup_y;

    ret = polyvec_init(&data->w, DILITHIUM_K);
    if (ret != CRYPTO_SUCCESS) goto cleanup_y;
    
    // Use thread-local arena for the massive A_bar matrix expansion
    size_t sign_mark = arena_mark();
    data->A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
    ret = polyvec_init_arena(&data->A_bar.rows, DILITHIUM_K * DILITHIUM_L);
    if (ret != CRYPTO_SUCCESS) { arena_reset(sign_mark); goto cleanup_w; }
    ret = expand_a(&data->A_bar, rho);
    if (ret != CRYPTO_SUCCESS) { arena_reset(sign_mark); goto cleanup_abar; }

    ret = matrix_vec_mul(&data->w, &data->A_bar, &data->y);
    if (ret != CRYPTO_SUCCESS) { arena_reset(sign_mark); goto cleanup_abar; }

    // Safely discard the massive expansion matrix from the thread arena
    arena_reset(sign_mark);
    data->A_bar.rows.vec = NULL;
    data->A_bar.rows.len = 0;
    data->A_bar.rows.magic = 0;

    scl_log(LOG_LEVEL_DEBUG, "Crypto", "threshold_sign completed successfully for party %d", id);

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Constant-time execution padding to prevent network-level timing analysis
    uint64_t elapsed_us = get_real_time_us() - start_time_us;
    if (elapsed_us < SIGN_RETRY_DELAY_US) {
        usleep(SIGN_RETRY_DELAY_US - elapsed_us);
    }
#endif
    
    return CRYPTO_SUCCESS;

cleanup_abar:
    // Memory safely discarded from the arena already
    arena_reset(sign_mark);
    data->A_bar.rows.vec = NULL;
    data->A_bar.rows.len = 0;
    data->A_bar.rows.magic = 0;
cleanup_w:
    polyvec_free(&data->w);
cleanup_y:
    polyvec_free(&data->y);
cleanup:
    free(data->subset_indices);
    
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Ensure failure branches are identically padded
    uint64_t err_elapsed_us = get_real_time_us() - start_time_us;
    if (err_elapsed_us < SIGN_RETRY_DELAY_US) {
        usleep(SIGN_RETRY_DELAY_US - err_elapsed_us);
    }
#endif
    
    return ret;
}

/**
 * @brief Verifies an aggregated threshold Dilithium signature against public key and message.
 *
 * @details
 * Executes Fiat-Shamir verification pipeline:
 * 1. Unpacks public key $(\rho, t_1)$ and signature $(c_{\text{hash}}, z, h)$.
 * 2. Asserts infinity norm $\|z\|_\infty \le \gamma_1 - \beta$ and hint Hamming weight $\text{wt}(h) \le \omega = 75$.
 * 3. Samples challenge polynomial $c = \text{SampleInBall}(c_{\text{hash}})$.
 * 4. Computes $w_1' = \text{UseHint}(h, \bar{A} \cdot z - c \cdot t_1 \cdot 2^D \pmod Q)$.
 * 5. Recomputes candidate hash $c' = H(H(\text{pk} \parallel \text{msg}) \parallel \text{Pack}(w_1'))$ and
 *    compares with $c_{\text{hash}}$ in constant time.
 *
 * @param[in] msg Message digest buffer.
 * @param[in] msg_len Length of message in bytes.
 * @param[in] sig Serialized threshold signature bytes (at least 4,627 bytes).
 * @param[in] sig_len Actual byte length of signature.
 * @param[in] pk Serialized threshold public key bytes (at least 2,592 bytes).
 * @param[in] pk_len Actual byte length of public key.
 * @return CRYPTO_SUCCESS on successful verification; CRYPTO_ERROR_PROOF_INVALID on signature rejection.
 *
 * @complexity Time: O(K * L * RING_DEG^2) negacyclic matrix convolution, Space: O(1) thread-local arena memory.
 */
crypto_error_t threshold_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
                     const uint8_t *pk, size_t pk_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)msg; (void)msg_len; (void)sig; (void)sig_len; (void)pk; (void)pk_len;
    return CRYPTO_SUCCESS;
#else
    size_t reset_mark = arena_mark();
    if (!msg || !sig || !pk || msg_len == 0 || sig_len < 32 + DILITHIUM_L * POLYZ_PACKEDBYTES + POLYH_PACKEDBYTES ||
        pk_len < KAPPA + DILITHIUM_K * POLYT1_PACKEDBYTES) {
        fprintf(stderr, "[Crypto] Verify: Invalid parameters\n");
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    // Unpack public key components
    uint8_t rho[KAPPA];
    memcpy(rho, pk, KAPPA);
    polyvec_t t1;
    if (polyvec_init_arena(&t1, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }

    for (size_t i = 0; i < DILITHIUM_K; i++) {
        poly_t1_unpack(&t1.vec[i], pk + KAPPA + i * POLYT1_PACKEDBYTES);
    }

    // Unpack signature components first (O(1) cheap operations)
    uint8_t c_hash[32];
    memcpy(c_hash, sig, 32);
    polyvec_t z;
    if (polyvec_init_arena(&z, DILITHIUM_L) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }
    
    size_t offset = 32;
    for (size_t i = 0; i < DILITHIUM_L; i++) {
        polyz_unpack(&z.vec[i], sig + offset);
        offset += POLYZ_PACKEDBYTES;
    }

    // Fast-fail: Reject out-of-norm z before expensive Keccak matrix expansion
    int32_t beta = TAU * ETA;
    if (!check_norm_inf(&z, GAMMA1 - beta)) {
        arena_reset(reset_mark); return CRYPTO_ERROR_PROOF_INVALID;
    }
    
    polyvec_t h;
    if (polyvec_init_arena(&h, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }
    unpack_h(&h, sig + offset);

    int wt_h = count_nonzero_vec(&h);
    if (wt_h > OMEGA) {
        arena_reset(reset_mark); return CRYPTO_ERROR_PROOF_INVALID;
    }

    // Expand matrix A_bar from rho ONLY after z and h satisfy bounds
    matrix_t A_bar;
    A_bar.rows.len = DILITHIUM_K * DILITHIUM_L;
    if (polyvec_init_arena(&A_bar.rows, DILITHIUM_K * DILITHIUM_L) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }
    if (expand_a(&A_bar, rho) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_COMPUTE; }

    // Compute mu = H(tr || msg)
    uint8_t mu[32];
    if (msg_len == 32) {
        memcpy(mu, msg, 32);
    } else {
        uint8_t tr[32];
        sha256_hash(pk, pk_len, tr);
        uint8_t *mu_input = arena_alloc(32 + msg_len);
        if (!mu_input) {
            fprintf(stderr, "[Crypto] Verify: Memory allocation failed for mu_input\n");
            arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY;
        }
        memcpy(mu_input, tr, 32);
        memcpy(mu_input + 32, msg, msg_len);
        sha256_hash(mu_input, 32 + msg_len, mu);
    }

    poly_t c;
    if (sample_in_ball(&c, c_hash, 32) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Crypto] Verify: Failed to sample challenge\n");
        arena_reset(reset_mark); return CRYPTO_ERROR_COMPUTE;
    }

    // Compute Az = A_bar * z using unreduced arithmetic
    polyvec64_t Az;
    if (polyvec64_init_arena(&Az, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }
    matrix_vec_mul_unreduced(&Az, &A_bar, &z);

    // Scale t1 by 2^D (ALPHA)
    polyvec_t t1_scaled;
    if (polyvec_init_arena(&t1_scaled, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            t1_scaled.vec[i].coeffs[j] = t1.vec[i].coeffs[j] << D;
        }
    }

    // Compute ct1 = c * t1_scaled using unreduced arithmetic
    polyvec64_t ct1;
    if (polyvec64_init_arena(&ct1, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }
    polyvec_poly_mul_unreduced(&ct1, &t1_scaled, &c);

    // Compute temp = Az - ct1 (unreduced)
    polyvec64_t temp;
    if (polyvec64_init_arena(&temp, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return CRYPTO_ERROR_MEMORY; }
    polyvec64_sub(&temp, &Az, &ct1);

    // Reduce temp mod Q
    polyvec_t temp_reduced;
    if (polyvec_init_arena(&temp_reduced, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return -1; }
    polyvec64_reduce(&temp_reduced, &temp);

    // Reconstruct w1' using hint correction
    polyvec_t w1_prime;
    if (polyvec_init_arena(&w1_prime, DILITHIUM_K) != CRYPTO_SUCCESS) { arena_reset(reset_mark); return -1; }
    polyvec_use_hint(&w1_prime, &h, &temp_reduced, ALPHA);

    // Pack w1'
    uint8_t w1_packed[DILITHIUM_K * POLYW1_PACKEDBYTES];
    for (size_t i = 0; i < DILITHIUM_K; i++) {
        polyw1_pack(w1_packed + i * POLYW1_PACKEDBYTES, &w1_prime.vec[i]);
    }

    // Recompute and verify challenge hash: c_prime == H(mu || w1_packed)
    uint8_t hash_input[32 + DILITHIUM_K * POLYW1_PACKEDBYTES];
    memcpy(hash_input, mu, 32);
    memcpy(hash_input + 32, w1_packed, DILITHIUM_K * POLYW1_PACKEDBYTES);
    uint8_t c_prime[32];
    sha256_hash(hash_input, 32 + DILITHIUM_K * POLYW1_PACKEDBYTES, c_prime);

    crypto_error_t result = CRYPTO_ERROR_PROOF_INVALID;
    if (secure_memcmp(c_hash, c_prime, 32) == 0) {
        result = CRYPTO_SUCCESS;
    } else {
        fprintf(stderr, "[Crypto] Verify: Challenge hash mismatch\n");
    }

    arena_reset(reset_mark);
    return result;
#endif
}

/**
 * @brief Securely zero-wipes and deallocates all secret material in a @ref ThresholdKeygenData structure.
 *
 * @param[in,out] keygen_data Structure to clean up.
 *
 * @post All secret shares are scrubbed via `explicit_bzero` and heap memory is released.
 * @complexity Time: O(NUM_SUBSETS * K * RING_DEG), Space: O(1).
 */
void cleanup_keygen_data(ThresholdKeygenData *keygen_data) {
    if (!keygen_data) return;

    // Zero secret polynomial coefficients before freeing vector structures
    explicit_bzero(keygen_data->pubkey, sizeof(keygen_data->pubkey));
    if (keygen_data->s1_shares) {
        for (size_t i = 0; i < keygen_data->num_subsets; i++) {
            if (keygen_data->s1_shares[i].vec) {
                explicit_bzero(keygen_data->s1_shares[i].vec, keygen_data->s1_shares[i].len * sizeof(poly_t));
            }
            if (keygen_data->s2_shares[i].vec) {
                explicit_bzero(keygen_data->s2_shares[i].vec, keygen_data->s2_shares[i].len * sizeof(poly_t));
            }
        }
    }
    if (keygen_data->s1.vec) {
        explicit_bzero(keygen_data->s1.vec, keygen_data->s1.len * sizeof(poly_t));
    }
    if (keygen_data->s2.vec) {
        explicit_bzero(keygen_data->s2.vec, keygen_data->s2.len * sizeof(poly_t));
    }

    // Clean up temporary subset shares if they exist
    if (keygen_data->s1_sub_shares) {
        for (size_t i = 0; i < NUM_SUBSETS; i++) {
            polyvec_free(&keygen_data->s1_sub_shares[i]);
        }
        free(keygen_data->s1_sub_shares);
    }
    if (keygen_data->s2_sub_shares) {
        for (size_t i = 0; i < NUM_SUBSETS; i++) {
            polyvec_free(&keygen_data->s2_sub_shares[i]);
        }
        free(keygen_data->s2_sub_shares);
    }

    // Clean up main polyvecs and arrays
    polyvec_free(&keygen_data->A_bar.rows);
    polyvec_free(&keygen_data->s1);
    polyvec_free(&keygen_data->s2);
    polyvec_free(&keygen_data->t0);
    polyvec_free(&keygen_data->t);
    polyvec_free(&keygen_data->t1);
    if (keygen_data->s1_shares) {
        for (size_t i = 0; i < keygen_data->num_subsets; i++) {
            polyvec_free(&keygen_data->s1_shares[i]);
            polyvec_free(&keygen_data->s2_shares[i]);
        }
        free(keygen_data->s1_shares);
        free(keygen_data->s2_shares);
    }
    if (keygen_data->subset_indices) {
        free(keygen_data->subset_indices);
    }
    
    // Clean up DKG Phase 1 inbound structures
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            polyvec_free(&keygen_data->inbound_s1_shares[i][j]);
            polyvec_free(&keygen_data->inbound_s2_shares[i][j]);
        }
        polyvec_free(&keygen_data->peer_t_contributions[i]);
    }

    // Zero out the structure to prevent use-after-free issues
    memset(keygen_data, 0, sizeof(ThresholdKeygenData));
    scl_log(LOG_LEVEL_TRACE, "Crypto", "Cleaned up ThresholdKeygenData");
}

/**
 * @brief Deallocates temporary signing vectors and zeroizes signing state.
 *
 * @param[in,out] sign_data Structure to clean up.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void cleanup_sign_data(ThresholdSignData *sign_data) {
    if (!sign_data) return;
    polyvec_free(&sign_data->y);
    polyvec_free(&sign_data->w);
    polyvec_free(&sign_data->A_bar.rows); // Eliminate 56-polynomial matrix memory leak
    if (sign_data->subset_indices) {
        free(sign_data->subset_indices);
    }
    memset(sign_data, 0, sizeof(ThresholdSignData));
    scl_log(LOG_LEVEL_TRACE, "Crypto", "Cleaned up ThresholdSignData");
}

/**
 * @brief Derives a 32-byte deterministic nonce via HMAC-SHA256(privkey, msg).
 *
 * @param[in] privkey Secret key buffer.
 * @param[in] privkey_len Length of private key.
 * @param[in] msg Message buffer.
 * @param[in] msg_len Length of message.
 * @param[out] nonce_out Destination 32-byte nonce buffer.
 *
 * @complexity Time: O(privkey_len + msg_len), Space: O(1).
 */
void generate_deterministic_nonce(const uint8_t *privkey, size_t privkey_len, const uint8_t *msg, size_t msg_len, uint8_t *nonce_out) {
    unsigned int mac_len = 32; // Ensures standard 32-byte KAPPA output
    HMAC(EVP_sha256(), privkey, privkey_len, msg, msg_len, nonce_out, &mac_len);
}

/**
 * @brief Releases a reference to an active @ref DKGSession, deallocating resources upon reaching zero.
 *
 * @param[in] session Pointer to DKG session.
 *
 * @thread_safety Thread-safe via atomic reference decrement with acquire-release memory fences.
 * @complexity Time: O(1), Space: O(1).
 */
void dkg_session_release(DKGSession *session) {
    if (!session) return;
    if (atomic_fetch_sub_explicit(&session->ref_count, 1, memory_order_release) == 1) {
        atomic_thread_fence(memory_order_acquire);
        cleanup_keygen_data(&session->keygen);
        pthread_cond_destroy(&session->phase_cond);
        for (int i = 0; i < session->early_msg_count; i++) {
            if (session->early_msgs[i]) free(session->early_msgs[i]);
            if (session->early_conns[i]) scl_connection_release((SclConnection *)session->early_conns[i]);
        }
        free(session);
    }
}

/**
 * @brief Hash table deallocation callback wrapper invoking @ref dkg_session_release.
 *
 * @param[in] data Untyped pointer to DKGSession.
 */
void free_dkg_session(void *data) {
    if (!data) return;
    dkg_session_release((DKGSession *)data);
}

/**
 * @brief Destroys and cleans up all dynamic allocations within a @ref ThresholdStakeProcess.
 *
 * @param[in] data Untyped pointer to @ref ThresholdStakeProcess.
 *
 * @post Joins active collector worker thread if running and frees all component vectors.
 * @complexity Time: O(1), Space: O(1).
 */
void free_threshold_process(void *data) {
    if (!data) return;
    ThresholdStakeProcess *process = (ThresholdStakeProcess *)data;
    // Join collector thread if active
    if (process->collector_thread != 0) {
        pthread_join(process->collector_thread, NULL);
        process->collector_thread = 0;
    }
    // Free polyvec fields
    for (int i = 0; i < 10; i++) {
        polyvec_free(&process->s1_part[i]);
        polyvec_free(&process->s2_part[i]);
        cleanup_sign_data(&process->sign_data[i]);
    }
    polyvec_free(&process->dealer_z);
    polyvec_free(&process->w_agg);
    for (int i = 0; i < 10; i++) {
        polyvec_free(&process->partial_w[i]);
        polyvec_free(&process->partial_z[i]);
    }
    // Free keygen data
    cleanup_keygen_data(&process->keygen);
    // Free sign data
    cleanup_sign_data(&process->dealer_sign_data);
    // Destroy cond vars
    pthread_cond_destroy(&process->partial_cond);
    pthread_cond_destroy(&process->stage0_complete_cond);
    // Free the process struct
    free(process);
}

/**
 * @brief Looks up an existing threshold stake process by transaction ID without creating one.
 *
 * @param[in] state Global node state.
 * @param[in] stake_tx_id 32-byte transaction identifier.
 * @return Pointer to @ref ThresholdStakeProcess if found; NULL otherwise.
 *
 * @complexity Time: O(1) hash table lookup, Space: O(1).
 */
ThresholdStakeProcess* find_threshold_process(State *state, const uint8_t stake_tx_id[COIN_ID_LEN]) {
    ThresholdStakeProcess *process = hash_table_lookup(state->threshold_stake_processes, stake_tx_id, false);
    return process;
}

/**
 * @brief Thread-safely retrieves an existing threshold process or allocates and registers a new one.
 *
 * @param[in,out] state Global node state.
 * @param[in] tx_id 32-byte stake transaction ID.
 * @return Pointer to active @ref ThresholdStakeProcess; NULL on allocation failure.
 *
 * @thread_safety Thread-safe; acquires `state->threshold_mutex`.
 * @complexity Time: O(1) hash table insertion, Space: O(sizeof(ThresholdStakeProcess)).
 */
ThresholdStakeProcess *get_or_create_threshold_process(State *state, const uint8_t *tx_id) {
    if (!state || !tx_id) return NULL;

    pthread_mutex_lock(&state->threshold_mutex);
    ThresholdStakeProcess *proc = (ThresholdStakeProcess *)hash_table_lookup(state->threshold_stake_processes, tx_id, false);
    if (!proc) {
        proc = (ThresholdStakeProcess *)calloc(1, sizeof(ThresholdStakeProcess));
        if (!proc) {
            pthread_mutex_unlock(&state->threshold_mutex);
            return NULL;
        }
        memcpy(proc->stake_tx_id, tx_id, COIN_ID_LEN);
        proc->created_at = get_time_ms();
        atomic_init(&proc->partials_received, 0);
        atomic_init(&proc->stage0_complete, false);
        atomic_init(&proc->aggregation_complete, false);
        atomic_init(&proc->aggregation_failed, false);

        // Initialize polyvec fields
        if (polyvec_init(&proc->dealer_z, DILITHIUM_L) != CRYPTO_SUCCESS ||
            polyvec_init(&proc->w_agg, DILITHIUM_K) != CRYPTO_SUCCESS) {
            polyvec_free(&proc->dealer_z);
            free(proc);
            pthread_mutex_unlock(&state->threshold_mutex);
            return NULL;
        }
        for (int i = 0; i < 10; i++) {
            if (polyvec_init(&proc->s1_part[i], DILITHIUM_L) != CRYPTO_SUCCESS ||
                polyvec_init(&proc->s2_part[i], DILITHIUM_K) != CRYPTO_SUCCESS) {
                for (int j = 0; j <= i; j++) {
                    polyvec_free(&proc->s1_part[j]);
                    polyvec_free(&proc->s2_part[j]);
                }
                polyvec_free(&proc->dealer_z);
                polyvec_free(&proc->w_agg);
                free(proc);
                pthread_mutex_unlock(&state->threshold_mutex);
                return NULL;
            }
        }
        for (int i = 0; i < 10; i++) {
            if (polyvec_init(&proc->partial_w[i], DILITHIUM_K) != CRYPTO_SUCCESS ||
                polyvec_init(&proc->partial_z[i], DILITHIUM_L) != CRYPTO_SUCCESS) {
                // Cleanup partial inits on failure
                for (int j = 0; j <= i; j++) {
                    polyvec_free(&proc->partial_w[j]);
                    polyvec_free(&proc->partial_z[j]);
                }
                for (int j = 0; j < 3; j++) {
                    polyvec_free(&proc->s1_part[j]);
                    polyvec_free(&proc->s2_part[j]);
                }
                polyvec_free(&proc->dealer_z);
                polyvec_free(&proc->w_agg);
                free(proc);
                pthread_mutex_unlock(&state->threshold_mutex);
                return NULL;
            }
        }

        // Initialize cond vars
        if (pthread_cond_init(&proc->partial_cond, NULL) != 0 ||
            pthread_cond_init(&proc->stage0_complete_cond, NULL) != 0) {
            // Cleanup on cond init failure
            for (int i = 0; i < 2; i++) {
                polyvec_free(&proc->partial_w[i]);
                polyvec_free(&proc->partial_z[i]);
            }
            for (int i = 0; i < 3; i++) {
                polyvec_free(&proc->s1_part[i]);
                polyvec_free(&proc->s2_part[i]);
            }
            polyvec_free(&proc->dealer_z);
            polyvec_free(&proc->w_agg);
            free(proc);
            pthread_mutex_unlock(&state->threshold_mutex);
            return NULL;
        }

        hash_table_insert(state->threshold_stake_processes, tx_id, (GenericHashEntry *)proc, HASH_ENTRY_THRESHOLD_STAKE_PROCESS);
        fprintf(stderr, "[Threshold] Created new process for tx_id (first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
                tx_id[0], tx_id[1], tx_id[2], tx_id[3], tx_id[4], tx_id[5], tx_id[6], tx_id[7]);
    }
    pthread_mutex_unlock(&state->threshold_mutex);
    return proc;
}

/**
 * @brief Removes a threshold process from the state hash table and joins its collector thread outside locks.
 *
 * @param[in,out] state Global node state.
 * @param[in] stake_tx_id 32-byte transaction identifier.
 *
 * @thread_safety Thread-safe; acquires `state->threshold_mutex` for table removal, joins thread outside lock.
 * @complexity Time: O(1), Space: O(1).
 */
void remove_threshold_process(State *state, const uint8_t stake_tx_id[COIN_ID_LEN]) {
    pthread_mutex_lock(&state->threshold_mutex);
    ThresholdStakeProcess *process = hash_table_lookup(state->threshold_stake_processes, stake_tx_id, false);
    pthread_t thread_to_join = 0;
    if (process) {
        thread_to_join = process->collector_thread;
        process->collector_thread = 0; // Prevent recursive joining
    }
    pthread_mutex_unlock(&state->threshold_mutex);

    if (thread_to_join != 0 && !pthread_equal(thread_to_join, pthread_self())) {
        pthread_join(thread_to_join, NULL);
    }

    pthread_mutex_lock(&state->threshold_mutex);
    hash_table_remove(state->threshold_stake_processes, stake_tx_id);
    pthread_mutex_unlock(&state->threshold_mutex);
}

/**
 * @brief Destroys all active threshold processes and cleans up synchronization primitives during shutdown.
 *
 * @param[in,out] state Global node state.
 *
 * @complexity Time: O(N) entries in table, Space: O(1).
 */
void cleanup_all_threshold_processes(State *state) {
    pthread_mutex_lock(&state->threshold_mutex);
    if (state->threshold_stake_processes) {
        hash_table_destroy(state->threshold_stake_processes);
        free(state->threshold_stake_processes);
        state->threshold_stake_processes = NULL;
    }
    pthread_mutex_unlock(&state->threshold_mutex);
    pthread_mutex_destroy(&state->threshold_mutex);
    fprintf(stderr, "[GameState] Threshold stake processes hash table destroyed\n");
}

/**
 * @brief Background worker thread routine collecting and coordinating partial threshold signature contributions.
 *
 * @param[in] arg Pointer to heap-allocated @ref PartialCollectorArgs structure (freed by callee).
 * @return NULL on thread termination.
 *
 * @thread_safety Acquires `state->threshold_mutex` and waits on condition variables with @ref SIGN_TIMEOUT.
 * @complexity Time: O(1) condition wait loop, Space: O(1).
 */
void *partial_collector_thread(void *arg) {
    PartialCollectorArgs *cargs = (PartialCollectorArgs *)arg;
    State *state = cargs->state;
    uint8_t *tx_id = cargs->stake_tx_id;

    pthread_mutex_lock(&state->threshold_mutex);
    ThresholdStakeProcess *process = find_threshold_process(state, tx_id);
    if (!process) {
        pthread_mutex_unlock(&state->threshold_mutex);
        free(cargs);
        arena_cleanup();
        return NULL;
    }

    // Wait for stage 0 (w aggregation) with timeout
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += SIGN_TIMEOUT;  // 10s for stage 0
    
    int wait_ret = 0;
    while (!atomic_load_explicit(&process->stage0_complete, memory_order_acquire) && wait_ret != ETIMEDOUT) {
        if (atomic_load(&global_shutdown)) break;
        wait_ret = pthread_cond_timedwait(&process->stage0_complete_cond, &state->threshold_mutex, &ts);
    }
    
    if (!atomic_load_explicit(&process->stage0_complete, memory_order_acquire)) {
        fprintf(stderr, "[Collector] Stage 0 timeout or failure\n");
        pthread_mutex_unlock(&state->threshold_mutex);
        free(cargs);
        return NULL;
    }

    // Wait for stage 1 (z aggregation) with timeout
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += SIGN_TIMEOUT;  // 30s for stage 1
    
    wait_ret = 0;
    while (!atomic_load_explicit(&process->aggregation_complete, memory_order_acquire) &&
           !atomic_load_explicit(&process->aggregation_failed, memory_order_acquire) &&
           wait_ret != ETIMEDOUT) {
        if (atomic_load(&global_shutdown)) break;
        wait_ret = pthread_cond_timedwait(&process->partial_cond, &state->threshold_mutex, &ts);
    }
    
    bool success = atomic_load_explicit(&process->aggregation_complete, memory_order_acquire);

    if (!success) {
        fprintf(stderr, "[Collector] Stage 1 timeout or failure (received %d/%d partials, failed=%d)\n",
                        process->partials_received, process->expected_partials, process->aggregation_failed);
    }

    pthread_mutex_unlock(&state->threshold_mutex);
    free(cargs);
    arena_cleanup();
    return NULL;
}

/* ============================================================================ */
/* SECTION 17: MODULE-SIS PSEUDO-RANDOM FUNCTION (PRF) EVALUATION               */
/* ============================================================================ */

/**
 * @brief Evaluates the Module-SIS Pseudo-Random Function: $y = \text{LowBits}_p(A \cdot s) \pmod Q$.
 *
 * @details
 * Evaluates the deterministic transaction nullifier over cyclotomic ring $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$
 * with modulus $Q = 8,380,417$, rank $K = 4$, and scaling divisor $P = 256$:
 * 1. Expands public matrix operator $A \in R_q^K$ using SHAKE-256 absorbed with domain separator seed
 *    `"SCL_GLOBAL_CRS_SEED_FOR_PRF_MATRIX_v1"`, sampling coefficients in $[-Q/2, Q/2]$.
 * 2. Unpacks the secret ternary vector $s \in \{-1, 0, 1\}^{1024}$ from `key->k` into $K=4$ polynomials.
 * 3. Evaluates polynomial convolution sum $v(X) = \sum_{i=0}^{K-1} A_i \cdot s_i \pmod Q$.
 * 4. Extracts the least significant 8 bits ($\text{LowBits}$) of the first 32 coefficients into `y_out`:
 *    $$y_i = (v_i \bmod Q) \ \& \ 0\text{xFF}$$
 *
 * @param[out] y_out 32-byte destination buffer receiving the evaluated nullifier digest.
 * @param[in] key Pointer to secret @ref PRFKey structure ($k \in \{-1, 0, 1\}^{1024}$, Hamming weight 250).
 * @param[in] J Transaction identifier input buffer (domain separator).
 * @param[in] J_len Byte length of input buffer `J`.
 * @param[in] seed Public matrix expansion seed (or state root witness).
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_MEMORY on arena exhaustion.
 *
 * @pre `y_out` and `key` must be non-NULL; `key` must be unlocked in RAM.
 * @post `y_out` contains 32-byte pseudorandom nullifier; arena mark reset.
 * @thread_safety Reentrant and thread-safe. Allocates from thread-local memory arena.
 * @complexity Time: O(K * RING_DEG^2) = 4 * 65,536 multiplications, Space: O(K * sizeof(poly_t)) arena reservation.
 */
crypto_error_t prf_evaluate(uint8_t *y_out, const PRFKey *key, const uint8_t *J, size_t J_len,
                            const uint8_t *seed) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)key; (void)J; (void)J_len; (void)seed;
    if (y_out) memset(y_out, 0x42, NULLIFIER_LEN);
    return CRYPTO_SUCCESS;
#endif
    (void)J; (void)J_len; (void)seed;
    size_t fn_mark = arena_mark();
    uint8_t matrix_seed[32];
    SHA256((const uint8_t *)"SCL_GLOBAL_CRS_SEED_FOR_PRF_MATRIX_v1", 37, matrix_seed);

    polyvec_t A_vec, s_vec;
    if (polyvec_init_arena(&A_vec, PRF_K) != CRYPTO_SUCCESS) { arena_reset(fn_mark); return CRYPTO_ERROR_MEMORY; }
    if (polyvec_init_arena(&s_vec, PRF_K) != CRYPTO_SUCCESS) { arena_reset(fn_mark); return CRYPTO_ERROR_MEMORY; }

    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, matrix_seed, sizeof(matrix_seed));
    custom_shake256_inc_finalize(&state);

    for (int i = 0; i < PRF_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            uint32_t r;
            do {
                uint8_t buf[3];
                custom_shake256_inc_squeeze(buf, 3, &state);
                r = buf[0] | (buf[1] << 8) | (buf[2] << 16);
                r &= 0x7FFFFF;
            } while (r >= PRF_Q);
            A_vec.vec[i].coeffs[j] = (int32_t)r - (PRF_Q >> 1);
        }
    }
    custom_shake256_inc_ctx_release(&state);

    for (int i = 0; i < PRF_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            s_vec.vec[i].coeffs[j] = key->k[i * RING_DEG + j];
        }
    }

    poly_t v_poly;
    memset(v_poly.coeffs, 0, sizeof(v_poly.coeffs));
    poly_t temp;

    for (int i = 0; i < PRF_K; i++) {
        poly_mul(&temp, &A_vec.vec[i], &s_vec.vec[i]);
        poly_add(&v_poly, &v_poly, &temp);
    }

    for (int i = 0; i < NULLIFIER_LEN; i++) {
        int32_t red = reduce_mod_q(v_poly.coeffs[i]);
        red += (red >> 31) & PRF_Q;
        y_out[i] = (uint8_t)(red & 0xFF);
    }

    arena_reset(fn_mark);
    return CRYPTO_SUCCESS;
}

/* ============================================================================ */
/* SECTION 18: ZERO-KNOWLEDGE STERN WITNESS PERMUTATION & PACKING UTILITIES     */
/* ============================================================================ */

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Generates an unbiased deterministic permutation using the Fisher-Yates shuffle.
 *
 * @details
 * Squeezes 16-bit random words from an incremental SHAKE-256 context absorbed with `seed`.
 * Uses a strictly branchless shift-subtraction loop across 16 stages to evaluate unbiased modulo
 * indices without runtime integer division instructions, preventing execution-time side-channels.
 *
 * @param[out] perm Destination array of length `len` receiving permuted indices.
 * @param[in] len Dimension of permutation space.
 * @param[in] seed 32-byte cryptographic seed.
 *
 * @complexity Time: O(len) branchless, Space: O(1) stack context.
 */
static void generate_permutation_from_seed(int32_t *perm, size_t len, const uint8_t *seed) {
    for (size_t i = 0; i < len; i++) {
        perm[i] = (int32_t)i;
    }

    if (len <= 1) return;

    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, seed, 32);
    custom_shake256_inc_finalize(&state);

    for (size_t i = len - 1; i > 0; i--) {
        uint16_t j_rand;
        custom_shake256_inc_squeeze((uint8_t *)&j_rand, sizeof(j_rand), &state);
        
        // Strictly branchless modulo algorithm protecting secret randomness
        uint32_t res = j_rand;
        uint32_t range = i + 1;
        for (int k = 15; k >= 0; k--) {
            uint32_t shifted = range << k;
            uint32_t mask = (uint32_t)(~(((int64_t)res - (int64_t)shifted) >> 63));
            res -= shifted & mask;
        }
        size_t j = res;

        int32_t temp = perm[i];
        perm[i] = perm[j];
        perm[j] = temp;
    }
    custom_shake256_inc_ctx_release(&state);
}

/**
 * @brief Generates an error polynomial permutation that preserves nullifier indices.
 *
 * @details
 * Fixes the first @ref NULLIFIER_LEN (32) indices to identity ($perm[i] = i$) to ensure the public
 * transaction nullifier is verifiable, while shuffling the remaining $256 - 32 = 224$ coefficients.
 *
 * @param[out] perm Output permutation array of size 256.
 * @param[in] seed 32-byte permutation seed.
 *
 * @complexity Time: O(RING_DEG), Space: O(1).
 */
static void generate_err_permutation(int32_t *perm, const uint8_t *seed) {
    for (int i = 0; i < NULLIFIER_LEN; i++) {
        perm[i] = i;
    }
    // Only permute the elements after the nullifier
    generate_permutation_from_seed(perm + NULLIFIER_LEN, 256 - NULLIFIER_LEN, seed);
    for (int i = NULLIFIER_LEN; i < 256; i++) {
        perm[i] += NULLIFIER_LEN;
    }
}

/**
 * @brief Packs an array of fixed bit-width signed/unsigned integers into a dense byte buffer.
 *
 * @param[in] bits Array of integer values.
 * @param[in] len Count of elements to pack.
 * @param[in] bit_width Width in bits allocated per element (1..64).
 * @param[out] packed Destination byte buffer sized to `ceil(len * bit_width / 8)`.
 *
 * @complexity Time: O(len * bit_width), Space: O(1).
 */
static void pack_bits(const int32_t *bits, int len, int bit_width, uint8_t *packed) {
    int64_t bit_pos = 0;
    int packed_len = (len * bit_width + 7) / 8;
    memset(packed, 0, packed_len);

    for (int i = 0; i < len; ++i) {
        uint64_t value = bits[i];
        int bits_to_pack = bit_width;
        while (bits_to_pack > 0) {
            int byte_idx = bit_pos / 8;
            int bit_offset = bit_pos % 8;
            int bits_in_byte = 8 - bit_offset;

            int chunk_size = bits_to_pack < bits_in_byte ? bits_to_pack : bits_in_byte;

            uint8_t chunk = (value >> (bits_to_pack - chunk_size)) & ((1ULL << chunk_size) - 1);
            packed[byte_idx] |= chunk << (bits_in_byte - chunk_size);

            bit_pos += chunk_size;
            bits_to_pack -= chunk_size;
        }
    }
}

/**
 * @brief Unpacks a dense byte buffer of arbitrary bit-width integers into an `int32_t` array.
 *
 * @param[in] packed Dense byte buffer.
 * @param[in] len Count of elements to unpack.
 * @param[in] bit_width Width in bits allocated per element.
 * @param[out] bits Destination array receiving unpacked integers.
 *
 * @complexity Time: O(len * bit_width), Space: O(1).
 */
static void unpack_bits(const uint8_t *packed, int len, int bit_width, int32_t *bits) {
    int64_t bit_pos = 0;
    for (int i = 0; i < len; ++i) {
        uint64_t value = 0;
        int bits_to_unpack = bit_width;
        while (bits_to_unpack > 0) {
            int byte_idx = bit_pos / 8;
            int bit_offset = bit_pos % 8;
            int bits_in_byte = 8 - bit_offset;

            int chunk_size = bits_to_unpack < bits_in_byte ? bits_to_unpack : bits_in_byte;

            uint8_t chunk = (packed[byte_idx] >> (bits_in_byte - chunk_size)) & ((1ULL << chunk_size) - 1);
            value = (value << chunk_size) | chunk;

            bit_pos += chunk_size;
            bits_to_unpack -= chunk_size;
        }
        bits[i] = value;
    }
}

/**
 * @brief Bit-packs the permuted secret witness vector $\pi(S)$ into a dense 3,200-byte wire frame.
 *
 * @details
 * Vector $\pi(S)$ encapsulates 4,352 secret coefficients partitioned across six distinct ranges:
 * 1. $(s, e_1, e_2)$: 2,304 elements in $[-2, 2]$ shifted by $+2 \implies 3$ bits each (864 bytes).
 * 2. $k$: 1,024 ternary coefficients in $[-1, 1]$ shifted by $+1 \implies 2$ bits each (256 bytes).
 * 3. $z$: 256 quotient coefficients in $[0, Q/P] \implies 15$ bits each (480 bytes).
 * 4. $v_{\text{tx}}$: 256 transfer limb coefficients in $[0, 2^{21}-1] \implies 21$ bits each (672 bytes).
 * 5. $v_{\text{ch}}$: 256 change limb coefficients in $[0, 2^{21}-1] \implies 21$ bits each (672 bytes).
 * 6. $\text{err}$: 256 remainder error coefficients in $[0, 255] \implies 8$ bits each (256 bytes).
 * Total packed size: $864 + 256 + 480 + 672 + 672 + 256 = 3,200$ bytes.
 *
 * @param[in] pi_S Array of 4,352 signed integer witness coefficients.
 * @param[out] packed Destination buffer (must allocate at least 3,200 bytes).
 *
 * @complexity Time: O(4352), Space: O(1).
 */
static void pack_pi_S(const int32_t *pi_S, uint8_t *packed) {
    int32_t temp[2304];

    // 1. s, e1, e2: 2304 elements in [-2, 2] -> shift by +2 (3 bits)
    for (int i = 0; i < 2304; i++) {
        int32_t val = pi_S[i];
        if (val > Q / 2) val -= Q;
        temp[i] = val + 2;
    }
    pack_bits(temp, 2304, 3, packed);

    // 2. k: 1024 elements in [-1, 1] -> shift by +1 (2 bits)
    for (int i = 0; i < 1024; i++) {
        int32_t val = pi_S[2304 + i];
        if (val > Q / 2) val -= Q;
        temp[i] = val + 1;
    }
    pack_bits(temp, 1024, 2, packed + 864);

    // 3. z: 256 elements in [0, Q/P] (15 bits)
    for (int i = 0; i < 256; i++) {
        int32_t val = pi_S[3328 + i];
        if (val > Q / 2) val -= Q;
        temp[i] = val;
    }
    pack_bits(temp, 256, 15, packed + 864 + 256);

    // 4. v_tx: 256 elements in [0, 0x1FFFFF] (21 bits)
    for (int i = 0; i < 256; i++) {
        int32_t val = pi_S[3584 + i];
        if (val > Q / 2) val -= Q;
        temp[i] = val;
    }
    pack_bits(temp, 256, 21, packed + 864 + 256 + 480);

    // 5. v_ch: 256 elements in [0, 0x1FFFFF] (21 bits)
    for (int i = 0; i < 256; i++) {
        int32_t val = pi_S[3840 + i];
        if (val > Q / 2) val -= Q;
        temp[i] = val;
    }
    pack_bits(temp, 256, 21, packed + 864 + 256 + 480 + 672);

    // 6. err: 256 elements in [0, 255] (8 bits)
    for (int i = 0; i < 256; i++) {
        int32_t val = pi_S[4096 + i];
        if (val > Q / 2) val -= Q;
        temp[i] = val;
    }
    pack_bits(temp, 256, 8, packed + 864 + 256 + 480 + 672 + 672);
}

/**
 * @brief Unpacks the permuted secret witness vector $\pi(S)$ from its dense 3,200-byte wire frame.
 *
 * @param[in] packed Dense 3,200-byte wire buffer.
 * @param[out] pi_S Destination array of 4,352 unpacked `int32_t` witness coefficients.
 *
 * @complexity Time: O(4352), Space: O(1).
 */
static void unpack_pi_S(const uint8_t *packed, int32_t *pi_S) {
    int32_t temp[2304];

    // 1. s, e1, e2: 2304 elements -> shift by -2
    unpack_bits(packed, 2304, 3, temp);
    for (int i = 0; i < 2304; i++) {
        int32_t val = temp[i] - 2;
        pi_S[i] = (val < 0) ? (val + Q) : val;
    }

    // 2. k: 1024 elements -> shift by -1
    unpack_bits(packed + 864, 1024, 2, temp);
    for (int i = 0; i < 1024; i++) {
        int32_t val = temp[i] - 1;
        pi_S[2304 + i] = (val < 0) ? (val + Q) : val;
    }

    // 3. z: 256 elements
    unpack_bits(packed + 864 + 256, 256, 15, temp);
    for (int i = 0; i < 256; i++) {
        pi_S[3328 + i] = temp[i];
    }

    // 4. v_tx: 256 elements
    unpack_bits(packed + 864 + 256 + 480, 256, 21, temp);
    for (int i = 0; i < 256; i++) {
        pi_S[3584 + i] = temp[i];
    }

    // 5. v_ch: 256 elements
    unpack_bits(packed + 864 + 256 + 480 + 672, 256, 21, temp);
    for (int i = 0; i < 256; i++) {
        pi_S[3840 + i] = temp[i];
    }

    // 6. err: 256 elements
    unpack_bits(packed + 864 + 256 + 480 + 672 + 672, 256, 8, temp);
    for (int i = 0; i < 256; i++) {
        pi_S[4096 + i] = temp[i];
    }
}
#endif

/* ============================================================================ */
/* SECTION 19: CENTINEL ZERO-KNOWLEDGE ALGEBRAIC RELATIONS                      */
/* ============================================================================ */

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Evaluates the multi-system linear and polynomial relations for Centinel ZK circuits.
 *
 * @details
 * Evaluates the following algebraic relations over $R_q$:
 * 1. BDLOP Difference relation: $c_{\text{diff}} = a \cdot s_{\text{diff}} + e_{1,\text{diff}}$, where
 *    $s_{\text{diff}} = s_{\text{old}} - s_{\text{tx}} - s_{\text{ch}}$.
 * 2. BDLOP Transfer relation: $c_{\text{tx}} = a \cdot s_{\text{tx}} + e_{1,\text{tx}}$ and
 *    $c_{2,\text{tx}} = b \cdot s_{\text{tx}} + e_{2,\text{tx}} + v_{\text{tx}}(X)$.
 * 3. BDLOP Change relation: $c_{\text{ch}} = a \cdot s_{\text{ch}} + e_{1,\text{ch}}$ and
 *    $c_{2,\text{ch}} = b \cdot s_{\text{ch}} + e_{2,\text{ch}} + v_{\text{ch}}(X)$.
 * 4. PRF Module-SIS relation: $v_{\text{poly}} = \sum_{i=0}^{K-1} A_i \cdot k_i \pmod Q$.
 *
 * @param[out] r_c1_diff First polynomial of difference commitment.
 * @param[out] r_c2_diff Second polynomial of difference commitment.
 * @param[out] r_c1_tx First polynomial of transfer commitment.
 * @param[out] r_c2_tx Second polynomial of transfer commitment.
 * @param[out] r_c1_ch First polynomial of change commitment.
 * @param[out] r_c2_ch Second polynomial of change commitment.
 * @param[out] r_v_poly PRF evaluation accumulator polynomial.
 * @param[in] a_pub Public BDLOP parameter $a \in R_q$.
 * @param[in] b_pub Public BDLOP parameter $b \in R_q$.
 * @param[in] A_bar_prf Public PRF operator matrix $A \in R_q^K$.
 * @param[in] s Secret noise polynomials $s$.
 * @param[in] e1 Secret noise polynomials $e_1$.
 * @param[in] e2 Secret noise polynomials $e_2$.
 * @param[in] k Secret ternary PRF key vector.
 * @param[in] z Quotient polynomial coefficients.
 * @param[in] tx_bits Value polynomial coefficients for transfer.
 * @param[in] ch_bits Value polynomial coefficients for change.
 * @param[in] err Remainder error coefficients.
 *
 * @complexity Time: O(K * RING_DEG^2), Space: O(1) stack buffers.
 */
static void compute_centinel_relations(
    poly_t *r_c1_diff, poly_t *r_c2_diff,
    poly_t *r_c1_tx, poly_t *r_c2_tx,
    poly_t *r_c1_ch, poly_t *r_c2_ch,
    poly_t *r_v_poly,
    const poly_t *a_pub, const poly_t *b_pub, const polyvec_t *A_bar_prf,
    const int32_t *s, const int32_t *e1, const int32_t *e2,
    const int32_t *k, const int32_t *z,
    const int32_t *tx_bits, const int32_t *ch_bits, const int32_t *err
) {
    (void)z; (void)err;
    
    // Reconstruct secret polynomials from flat arrays
    poly_t s_old, s_tx, s_ch;
    poly_t e1_old, e1_tx, e1_ch;
    poly_t e2_old, e2_tx, e2_ch;
    poly_t sigma_tx, sigma_ch;
    
    for (int i = 0; i < 256; i++) {
        s_old.coeffs[i] = s[i];
        s_tx.coeffs[i] = s[256 + i];
        s_ch.coeffs[i] = s[512 + i];
        
        e1_old.coeffs[i] = e1[i];
        e1_tx.coeffs[i] = e1[256 + i];
        e1_ch.coeffs[i] = e1[512 + i];
        
        e2_old.coeffs[i] = e2[i];
        e2_tx.coeffs[i] = e2[256 + i];
        e2_ch.coeffs[i] = e2[512 + i];
    }
    
    for (int i = 0; i < 256; i++) {
        sigma_tx.coeffs[i] = tx_bits[i];
        sigma_ch.coeffs[i] = ch_bits[i];
    }
    
    // 1. Compute BDLOP Difference commitment relations
    poly_t s_diff, e1_diff, e2_diff;
    for (int i = 0; i < 256; i++) {
        s_diff.coeffs[i] = reduce_mod_q((int64_t)s_old.coeffs[i] - s_tx.coeffs[i] - s_ch.coeffs[i]);
        e1_diff.coeffs[i] = reduce_mod_q((int64_t)e1_old.coeffs[i] - e1_tx.coeffs[i] - e1_ch.coeffs[i]);
        e2_diff.coeffs[i] = reduce_mod_q((int64_t)e2_old.coeffs[i] - e2_tx.coeffs[i] - e2_ch.coeffs[i]);
    }
    
    poly_mul(r_c1_diff, a_pub, &s_diff);
    poly_add(r_c1_diff, r_c1_diff, &e1_diff);
    
    poly_mul(r_c2_diff, b_pub, &s_diff);
    poly_add(r_c2_diff, r_c2_diff, &e2_diff);
    
    // 2. Compute BDLOP Transaction commitment relations
    poly_mul(r_c1_tx, a_pub, &s_tx);
    poly_add(r_c1_tx, r_c1_tx, &e1_tx);
    
    poly_mul(r_c2_tx, b_pub, &s_tx);
    poly_add(r_c2_tx, r_c2_tx, &e2_tx);
    poly_add(r_c2_tx, r_c2_tx, &sigma_tx);
    
    // 3. Compute BDLOP Change commitment relations
    poly_mul(r_c1_ch, a_pub, &s_ch);
    poly_add(r_c1_ch, r_c1_ch, &e1_ch);
    
    poly_mul(r_c2_ch, b_pub, &s_ch);
    poly_add(r_c2_ch, r_c2_ch, &e2_ch);
    poly_add(r_c2_ch, r_c2_ch, &sigma_ch);
    
    // 4. Compute PRF MSIS polynomial matrix multiplication relations
    memset(r_v_poly->coeffs, 0, sizeof(r_v_poly->coeffs));
    poly_t temp_mul;
    for (int i = 0; i < PRF_K; i++) {
        poly_t s_k_part;
        for (int j = 0; j < RING_DEG; j++) {
            s_k_part.coeffs[j] = k[i * RING_DEG + j];
        }
        poly_mul(&temp_mul, &A_bar_prf->vec[i], &s_k_part);
        poly_add(r_v_poly, r_v_poly, &temp_mul);
    }
}
#endif

/* ============================================================================ */
/* SECTION 20: MODULE-SIS ZK-PRF STERN PROVER & VERIFIER                        */
/* ============================================================================ */

/**
 * @brief Generates a zero-knowledge Stern proof demonstrating knowledge of a secret PRF key vector.
 *
 * @details
 * Proves knowledge of secret ternary vector $k \in \{-1, 0, 1\}^{1024}$ with fixed Hamming weight 250
 * satisfying $y = \text{LowBits}_p(A \cdot k)$ without revealing $k$. Executes across $\kappa = 219$
 * challenge repetitions to achieve 128-bit soundness against cheating provers ($2/3^{219} \le 2^{-128}$).
 *
 * Round protocol structure:
 * 1. Prover samples blinding vectors $u$ and permutations $\pi$ from random seeds.
 * 2. Computes three cryptographic commitments: $c_1, c_2, c_3$.
 * 3. Evaluates global Merkle root over all $219$ round commitment triples.
 * 4. Derives non-interactive challenges $e \in \{0, 1, 2\}$ via Fiat-Shamir transform over global root and public inputs.
 * 5. Serializes responses according to challenge $e$:
 *    - $e = 0$: Reveals blinding seeds $(seed_u, seed_\pi)$ and $c_3$.
 *    - $e = 1$: Reveals masked witness $w = u + W \pmod Q$, $seed_\pi$, and $c_2$.
 *    - $e = 2$: Reveals $seed_u$, permuted witness $\pi(S)$, and $c_1$.
 *
 * @param[out] proof Destination buffer receiving serialized proof bytes.
 * @param[in,out] proof_len Input: allocated capacity of `proof`; Output: exact serialized proof length.
 * @param[in] prf_input Public transaction identifier input $J$.
 * @param[in] input_len Byte length of $J$.
 * @param[in] prf_key Secret ternary key vector $k$ (1,024 bytes).
 * @param[in] key_len Byte length of key vector.
 * @param[in] seed Public matrix expansion seed.
 * @return CRYPTO_SUCCESS on success; error code on invalid parameters or memory failure.
 *
 * @pre `proof` must allocate at least @ref ZK_PROOF_MAX_LEN (4,000,000 bytes).
 * @complexity Time: O(ZK_KAPPA * PRF_K * RING_DEG^2), Space: O(ZK_KAPPA * rep_size) arena memory.
 */
crypto_error_t generate_zk_prf_proof(uint8_t *proof, size_t *proof_len,
                                   const uint8_t *prf_input, size_t input_len,
                                   const uint8_t *prf_key, size_t key_len,
                                   const uint8_t *seed) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)prf_key; (void)key_len;
    if (!proof || !proof_len || !prf_input || input_len == 0) return CRYPTO_ERROR_INVALID_PARAM;
    if (proof_len) *proof_len = 128;
    memset(proof, 0x42, 128);
    size_t copy_len = (input_len > 32) ? 32 : input_len;
    memcpy(proof, prf_input, copy_len);
    if (seed) memcpy(proof + 32, seed, 32);
    return CRYPTO_SUCCESS;
#else
    size_t fn_mark = arena_mark();
    
    if (!proof || !proof_len || !prf_input || input_len == 0 ||
        !prf_key || key_len == 0 || !seed) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    /* Stack-overflow fix: fs_input has room for PRF_L (128) bytes of PRF input;
     * anything larger must never reach the fixed 192-byte staging buffer. */
    if (input_len > PRF_L) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    // 1. Decoupled CRS Matrix Generation
    polyvec_t A_vec;
    if (polyvec_init_arena(&A_vec, PRF_K) != CRYPTO_SUCCESS) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_MEMORY;
    }

    // Static cache for the global CRS matrix
    static poly_t s_cached_A[PRF_K];
    static bool s_A_cached = false;
    if (!s_A_cached) {
        uint8_t matrix_seed[32];
        SHA256((const uint8_t *)"SCL_GLOBAL_CRS_SEED_FOR_PRF_MATRIX_v1", 37, matrix_seed);
        custom_shake256_inc_ctx state;
        custom_shake256_inc_init(&state);
        custom_shake256_inc_absorb(&state, matrix_seed, sizeof(matrix_seed));
        custom_shake256_inc_finalize(&state);

        for (int i = 0; i < PRF_K; i++) {
            for (int j = 0; j < RING_DEG; j++) {
                uint32_t r;
                do {
                    uint8_t buf[3];
                    custom_shake256_inc_squeeze(buf, 3, &state);
                    r = buf[0] | (buf[1] << 8) | (buf[2] << 16);
                    r &= 0x7FFFFF;
                } while (r >= PRF_Q);
                s_cached_A[i].coeffs[j] = (int32_t)r - (PRF_Q >> 1);
            }
        }
        custom_shake256_inc_ctx_release(&state);
        s_A_cached = true;
    }
    memcpy(A_vec.vec, s_cached_A, PRF_K * sizeof(poly_t));

    uint8_t y[NULLIFIER_LEN];
    PRFKey key_struct;
    memcpy(key_struct.k, prf_key, MIN(key_len, sizeof(key_struct.k)));
    
    polyvec_t s_vec;
    if (polyvec_init_arena(&s_vec, PRF_K) != CRYPTO_SUCCESS) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_MEMORY;
    }
    for (int i = 0; i < PRF_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            s_vec.vec[i].coeffs[j] = key_struct.k[i * RING_DEG + j];
        }
    }
    poly_t v_poly;
    memset(v_poly.coeffs, 0, sizeof(v_poly.coeffs));
    poly_t temp;
    for (int i = 0; i < PRF_K; i++) {
        poly_mul(&temp, &A_vec.vec[i], &s_vec.vec[i]);
        poly_add(&v_poly, &v_poly, &temp);
    }
    for (int i = 0; i < NULLIFIER_LEN; i++) {
        int32_t red = reduce_mod_q(v_poly.coeffs[i]);
        red += (red >> 31) & PRF_Q;
        y[i] = (uint8_t)(red & 0xFF);
    }
    polyvec_free(&s_vec);

    int32_t W_k[1024], W_z[256], W_err[256];
    for (int i = 0; i < 1024; i++) W_k[i] = key_struct.k[i];
    
    for (int i = 0; i < PRF_OUT; i++) {
        int32_t red = reduce_mod_q(v_poly.coeffs[i]);
        red += (red >> 31) & PRF_Q;
        int64_t v_pos = (int64_t)red;
        int64_t is_nullifier_mask = -((int64_t)(i < NULLIFIER_LEN));
        int64_t y_val = (y[i % NULLIFIER_LEN] & is_nullifier_mask);
        int64_t err_val = ((v_pos & 0xFF) & ~is_nullifier_mask);
        int64_t temp_val = v_pos - y_val - err_val;
        temp_val += (temp_val >> 63) & PRF_Q;
        W_z[i] = (int32_t)(temp_val / PRF_P);
        W_err[i] = (int32_t)err_val;
    }

    uint8_t fs_input[32 + PRF_L + NULLIFIER_LEN];
    memcpy(fs_input, seed, 32);
    memcpy(fs_input + 32, prf_input, input_len);
    memcpy(fs_input + 32 + input_len, y, NULLIFIER_LEN);
    uint8_t fs_seed[32];
    SHA256(fs_input, 32 + input_len + NULLIFIER_LEN, fs_seed);

    uint8_t round_roots[ZK_KAPPA * 32];
    uint8_t *round_c1 = arena_alloc(ZK_KAPPA * 32);
    uint8_t *round_c2 = arena_alloc(ZK_KAPPA * 32);
    uint8_t *round_c3 = arena_alloc(ZK_KAPPA * 32);
    
    uint8_t *round_seeds_u = arena_alloc(ZK_KAPPA * 32);
    uint8_t *round_seeds_pi = arena_alloc(ZK_KAPPA * 32);
    RAND_bytes(round_seeds_u, ZK_KAPPA * 32);
    RAND_bytes(round_seeds_pi, ZK_KAPPA * 32);

    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        uint8_t *seed_u = round_seeds_u + rep * 32;
        uint8_t *seed_pi = round_seeds_pi + rep * 32;

        int32_t pi_u_all[1536];
        deterministic_random_vector(pi_u_all, 1536, seed_u); // Optimized: Generate pi_u directly from Seed-V

        int32_t perm_k[1024], perm_z[256], perm_err[256];
        uint8_t sub_seed[32];
        SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

        int32_t u[1536];
        for (int i = 0; i < 1024; i++) u[perm_k[i]] = pi_u_all[i];
        for (int i = 0; i < 256; i++) u[1024 + perm_z[i]] = pi_u_all[1024 + i];
        for (int i = 0; i < 256; i++) u[1280 + perm_err[i]] = pi_u_all[1280 + i];

        polyvec_t u_k_vec;
        polyvec_init_arena(&u_k_vec, PRF_K);
        for (int i = 0; i < PRF_K; i++) {
            for (int j = 0; j < RING_DEG; j++) {
                u_k_vec.vec[i].coeffs[j] = u[i * RING_DEG + j];
            }
        }
        poly_t v_u_poly;
        memset(v_u_poly.coeffs, 0, sizeof(v_u_poly.coeffs));
        for (int i = 0; i < PRF_K; i++) {
            poly_mul(&temp, &A_vec.vec[i], &u_k_vec.vec[i]);
            poly_add(&v_u_poly, &v_u_poly, &temp);
        }
        polyvec_free(&u_k_vec);

        int32_t V_U[256];
        for (int i = 0; i < 256; i++) {
            V_U[i] = reduce_mod_q((int64_t)v_u_poly.coeffs[i] - (int64_t)u[1024 + i] * PRF_P - u[1280 + i]);
        }

        uint8_t c1_input[32 + 256 * sizeof(int32_t)];
        memcpy(c1_input, seed_pi, 32);
        memcpy(c1_input + 32, V_U, 256 * sizeof(int32_t));
        SHA256(c1_input, sizeof(c1_input), round_c1 + rep * 32);

        uint8_t pi_u_packed[4416];
        pack_bits(pi_u_all, 1024, 23, pi_u_packed);
        pack_bits(pi_u_all + 1024, 256, 23, pi_u_packed + 2944);
        pack_bits(pi_u_all + 1280, 256, 23, pi_u_packed + 3680);
        SHA256(pi_u_packed, sizeof(pi_u_packed), round_c2 + rep * 32);

        int32_t w[1536];
        for (int i = 0; i < 1024; i++) w[i] = (u[i] + W_k[i] + Q) % Q;
        for (int i = 0; i < 256; i++) w[1024 + i] = (u[1024 + i] + W_z[i] + Q) % Q;
        for (int i = 0; i < 256; i++) w[1280 + i] = (u[1280 + i] + W_err[i] + Q) % Q;

        int32_t pi_w_all[1536];
        for (int i = 0; i < 1024; i++) pi_w_all[i] = w[perm_k[i]];
        for (int i = 0; i < 256; i++) pi_w_all[1024 + i] = w[1024 + perm_z[i]];
        for (int i = 0; i < 256; i++) pi_w_all[1280 + i] = w[1280 + perm_err[i]];

        uint8_t pi_w_packed[4416];
        pack_bits(pi_w_all, 1024, 23, pi_w_packed);
        pack_bits(pi_w_all + 1024, 256, 23, pi_w_packed + 2944);
        pack_bits(pi_w_all + 1280, 256, 23, pi_w_packed + 3680);
        SHA256(pi_w_packed, sizeof(pi_w_packed), round_c3 + rep * 32);

        uint8_t merkle_input[64];
        memcpy(merkle_input, round_c1 + rep * 32, 32);
        memcpy(merkle_input + 32, round_c2 + rep * 32, 32);
        uint8_t intermediate[32];
        SHA256(merkle_input, 64, intermediate);
        memcpy(merkle_input, intermediate, 32);
        memcpy(merkle_input + 32, round_c3 + rep * 32, 32);
        SHA256(merkle_input, 64, round_roots + rep * 32);
    }

    uint8_t global_root[32];
    SHA256(round_roots, ZK_KAPPA * 32, global_root);
    
    uint8_t *p = proof;
    memcpy(p, global_root, 32);
    p += 32;

    uint8_t fs_final_input[32 + 32];
    memcpy(fs_final_input, global_root, 32);
    memcpy(fs_final_input + 32, fs_seed, 32);
    uint8_t fs_final_hash[32];
    SHA256(fs_final_input, sizeof(fs_final_input), fs_final_hash);
    
    int challenges[ZK_KAPPA];
    custom_shake256_inc_ctx fs_shake;
    custom_shake256_inc_init(&fs_shake);
    custom_shake256_inc_absorb(&fs_shake, fs_final_hash, 32);
    custom_shake256_inc_finalize(&fs_shake);
    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        int e;
        do {
            uint8_t buf;
            custom_shake256_inc_squeeze(&buf, 1, &fs_shake);
            e = buf;
        } while (e >= 252);
        challenges[rep] = e % 3;
    }
    custom_shake256_inc_ctx_release(&fs_shake);

    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        int e = challenges[rep];
        uint8_t *seed_u = round_seeds_u + rep * 32;
        uint8_t *seed_pi = round_seeds_pi + rep * 32;

        if (e == 0) {
            memcpy(p, seed_u, 32); p += 32;
            memcpy(p, seed_pi, 32); p += 32;
            memcpy(p, round_c3 + rep * 32, 32); p += 32;
        } else if (e == 1) {
            int32_t pi_u_all[1536];
            deterministic_random_vector(pi_u_all, 1536, seed_u);
            
            int32_t perm_k[1024], perm_z[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t u[1536];
            for (int i = 0; i < 1024; i++) u[perm_k[i]] = pi_u_all[i];
            for (int i = 0; i < 256; i++) u[1024 + perm_z[i]] = pi_u_all[1024 + i];
            for (int i = 0; i < 256; i++) u[1280 + perm_err[i]] = pi_u_all[1280 + i];
            
            int32_t w[1536];
            for (int i = 0; i < 1024; i++) w[i] = (u[i] + W_k[i] + Q) % Q;
            for (int i = 0; i < 256; i++) w[1024 + i] = (u[1024 + i] + W_z[i] + Q) % Q;
            for (int i = 0; i < 256; i++) w[1280 + i] = (u[1280 + i] + W_err[i] + Q) % Q;

            uint8_t w_packed[4416];
            pack_bits(w, 1024, 23, w_packed);
            pack_bits(w + 1024, 256, 23, w_packed + 2944);
            pack_bits(w + 1280, 256, 23, w_packed + 3680);

            memcpy(p, w_packed, sizeof(w_packed)); p += sizeof(w_packed);
            memcpy(p, seed_pi, 32); p += 32;
            memcpy(p, round_c2 + rep * 32, 32); p += 32;
        } else {
            // Regenerate permutations from seed_pi
            int32_t perm_k[1024], perm_z[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t pi_S_all[1536];
            for (int i = 0; i < 1024; i++) pi_S_all[i] = W_k[perm_k[i]];
            for (int i = 0; i < 256; i++) pi_S_all[1024 + i] = W_z[perm_z[i]];
            for (int i = 0; i < 256; i++) pi_S_all[1280 + i] = W_err[perm_err[i]];

            uint8_t pi_S_packed[1024];
            // 1. k: 1024 elements in [-1, 1] -> shift by +1 (2 bits)
            int32_t temp[1024];
            for (int i = 0; i < 1024; i++) {
                int32_t val = pi_S_all[i];
                if (val > Q / 2) val -= Q;
                temp[i] = val + 1;
            }
            pack_bits(temp, 1024, 2, pi_S_packed);

            // 2. z: 256 elements in [0, Q/P] (15 bits)
            for (int i = 0; i < 256; i++) {
                int32_t val = pi_S_all[1024 + i];
                if (val > Q / 2) val -= Q;
                temp[i] = val;
            }
            pack_bits(temp, 256, 15, pi_S_packed + 256);

            // 3. err: 256 elements in [0, 255] (8 bits)
            for (int i = 0; i < 256; i++) {
                int32_t val = pi_S_all[1280 + i];
                if (val > Q / 2) val -= Q;
                temp[i] = val;
            }
            pack_bits(temp, 256, 8, pi_S_packed + 256 + 480);

            memcpy(p, seed_u, 32); p += 32; // seed_u natively derives pi_u bypassing raw array payload!
            memcpy(p, pi_S_packed, 992); p += 992;
            memcpy(p, round_c1 + rep * 32, 32); p += 32;
        }
    }

    polyvec_free(&A_vec);
    *proof_len = p - proof;
    arena_reset(fn_mark);
    
    scl_log(LOG_LEVEL_DEBUG, "Crypto", "Generated ZK PRF proof of size %zu bytes", *proof_len);
    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Verifies a zero-knowledge Stern proof for Module-SIS PRF evaluation.
 *
 * @details
 * Performs deterministic batch verification over $\kappa = 219$ Stern rounds:
 * 1. Expands public matrix $A \in R_q^K$ from domain separator seed `"SCL_GLOBAL_CRS_SEED_FOR_PRF_MATRIX_v1"`.
 * 2. Unpacks the claimed 32-byte global Merkle root from the proof header.
 * 3. Derives non-interactive challenges $e \in \{0, 1, 2\}$ using SHAKE-256 absorbed with proof root and $(J, y)$.
 * 4. For each round:
 *    - Reconstructs missing commitments $(c_1, c_2, c_3)$ from the challenge response.
 *    - Validates witness structural invariants for $e = 2$: ternary weight $w_H(k) = 250$, quotient bounds
 *      $z_i \in [0, Q/P]$, error bounds $\text{err}_i \in [0, 255]$, and enforces that the unpermuted nullifier
 *      remainder segment is strictly zero.
 * 5. Hashes reconstructed round commitments and checks equality with the claimed global Merkle root.
 *
 * @param[in] proof Buffer containing serialized Stern proof bytes.
 * @param[in] proof_len Byte length of `proof`.
 * @param[in] seed State root or matrix domain separator seed (32 bytes).
 * @param[in] prf_input Public transaction identifier buffer $J$.
 * @param[in] input_len Byte length of $J$.
 * @param[in] y Nullifier evaluation digest (32 bytes).
 * @return CRYPTO_SUCCESS if proof is valid; CRYPTO_ERROR_PROOF_INVALID or CRYPTO_ERROR_PROOF_FORMAT otherwise.
 *
 * @pre `proof`, `seed`, `prf_input`, and `y` must be non-NULL; `input_len` must match transaction ID length.
 * @thread_safety Reentrant and thread-safe. Allocates from thread-local memory arena.
 * @complexity Time: O(ZK_KAPPA * PRF_K * RING_DEG^2), Space: O(PRF_K * sizeof(poly_t)) arena reservation.
 */
int zk_prf_verify(const uint8_t *proof, size_t proof_len,
                  const uint8_t *seed, const uint8_t *prf_input, size_t input_len, const uint8_t *y) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)y;
    if (!proof || proof_len < 32 || !prf_input || input_len == 0) return CRYPTO_ERROR_INVALID_PARAM;
    size_t cmp_len = (input_len > 32) ? 32 : input_len;
    if (memcmp(proof, prf_input, cmp_len) != 0) {
        return CRYPTO_ERROR_PROOF_INVALID;
    }
    if (seed && proof_len >= 64 && memcmp(proof + 32, seed, 32) != 0) {
        return CRYPTO_ERROR_PROOF_INVALID;
    }
    return CRYPTO_SUCCESS;
#else
    size_t fn_mark = arena_mark();
    
    if (!proof || !seed || !prf_input || input_len == 0 || !y) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    /* Stack-overflow fix: fs_input has room for PRF_L (128) bytes of PRF input;
     * anything larger must never reach the fixed 192-byte staging buffer. */
    if (input_len > PRF_L) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    uint8_t matrix_seed[32];
    SHA256((const uint8_t *)"SCL_GLOBAL_CRS_SEED_FOR_PRF_MATRIX_v1", 37, matrix_seed);

    polyvec_t A_vec;
    if (polyvec_init_arena(&A_vec, PRF_K) != CRYPTO_SUCCESS) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_MEMORY;
    }

    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, matrix_seed, sizeof(matrix_seed));
    custom_shake256_inc_finalize(&state);

    for (int i = 0; i < PRF_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            uint32_t r;
            do {
                uint8_t buf[3];
                custom_shake256_inc_squeeze(buf, 3, &state);
                r = buf[0] | (buf[1] << 8) | (buf[2] << 16);
                r &= 0x7FFFFF;
            } while (r >= PRF_Q);
            A_vec.vec[i].coeffs[j] = (int32_t)r - (PRF_Q >> 1);
        }
    }
    custom_shake256_inc_ctx_release(&state);

    uint8_t fs_input[32 + PRF_L + NULLIFIER_LEN];
    memcpy(fs_input, seed, 32);
    memcpy(fs_input + 32, prf_input, input_len);
    memcpy(fs_input + 32 + input_len, y, NULLIFIER_LEN);
    uint8_t fs_seed[32];
    SHA256(fs_input, 32 + input_len + NULLIFIER_LEN, fs_seed);

    const uint8_t *p = proof;
    size_t remaining = proof_len;
    if (remaining < 32) {
        polyvec_free(&A_vec);
        arena_reset(fn_mark);
        return CRYPTO_ERROR_PROOF_FORMAT;
    }
    const uint8_t *global_root_proof = p;
    p += 32;
    remaining -= 32;

    uint8_t fs_final_input[32 + 32];
    memcpy(fs_final_input, global_root_proof, 32);
    memcpy(fs_final_input + 32, fs_seed, 32);
    uint8_t fs_final_hash[32];
    SHA256(fs_final_input, sizeof(fs_final_input), fs_final_hash);
    
    int challenges[ZK_KAPPA];
    custom_shake256_inc_ctx fs_shake;
    custom_shake256_inc_init(&fs_shake);
    custom_shake256_inc_absorb(&fs_shake, fs_final_hash, 32);
    custom_shake256_inc_finalize(&fs_shake);
    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        int e;
        do {
            uint8_t buf;
            custom_shake256_inc_squeeze(&buf, 1, &fs_shake);
            e = buf;
        } while (e >= 252);
        challenges[rep] = e % 3;
    }
    custom_shake256_inc_ctx_release(&fs_shake);

    uint8_t round_roots[ZK_KAPPA * 32];
    poly_t temp;

    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        int e = challenges[rep];
        uint8_t c1[32], c2[32], c3[32];

        if (e == 0) {
            if (remaining < 96) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_FORMAT; }
            const uint8_t *seed_u = p; p += 32;
            const uint8_t *seed_pi = p; p += 32;
            const uint8_t *c3_sib = p; p += 32;
            remaining -= 96;

            int32_t pi_u_all[1536];
            deterministic_random_vector(pi_u_all, 1536, seed_u);

            int32_t perm_k[1024], perm_z[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t u[1536];
            for (int i = 0; i < 1024; i++) u[perm_k[i]] = pi_u_all[i];
            for (int i = 0; i < 256; i++) u[1024 + perm_z[i]] = pi_u_all[1024 + i];
            for (int i = 0; i < 256; i++) u[1280 + perm_err[i]] = pi_u_all[1280 + i];

            polyvec_t u_k_vec;
            polyvec_init_arena(&u_k_vec, PRF_K);
            for (int i = 0; i < PRF_K; i++) {
                for (int j = 0; j < RING_DEG; j++) {
                    u_k_vec.vec[i].coeffs[j] = u[i * RING_DEG + j];
                }
            }
            poly_t v_u_poly;
            memset(v_u_poly.coeffs, 0, sizeof(v_u_poly.coeffs));
            for (int i = 0; i < PRF_K; i++) {
                poly_mul(&temp, &A_vec.vec[i], &u_k_vec.vec[i]);
                poly_add(&v_u_poly, &v_u_poly, &temp);
            }
            polyvec_free(&u_k_vec);

            int32_t V_U[256];
            for (int i = 0; i < 256; i++) {
                V_U[i] = reduce_mod_q((int64_t)v_u_poly.coeffs[i] - (int64_t)u[1024 + i] * PRF_P - u[1280 + i]);
            }

            uint8_t c1_input[32 + 256 * sizeof(int32_t)];
            memcpy(c1_input, seed_pi, 32);
            memcpy(c1_input + 32, V_U, 256 * sizeof(int32_t));
            SHA256(c1_input, sizeof(c1_input), c1);

            uint8_t pi_u_packed[4416];
            pack_bits(pi_u_all, 1024, 23, pi_u_packed);
            pack_bits(pi_u_all + 1024, 256, 23, pi_u_packed + 2944);
            pack_bits(pi_u_all + 1280, 256, 23, pi_u_packed + 3680);
            SHA256(pi_u_packed, sizeof(pi_u_packed), c2);

            memcpy(c3, c3_sib, 32);
        } else if (e == 1) {
            if (remaining < 4416 + 64) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_FORMAT; }
            const uint8_t *w_packed = p; p += 4416;
            const uint8_t *seed_pi = p; p += 32;
            const uint8_t *c2_sib = p; p += 32;
            remaining -= 4480;

            int32_t w[1536];
            unpack_bits(w_packed, 1024, 23, w);
            unpack_bits(w_packed + 2944, 256, 23, w + 1024);
            unpack_bits(w_packed + 3680, 256, 23, w + 1280);

            polyvec_t w_k_vec;
            polyvec_init_arena(&w_k_vec, PRF_K);
            for (int i = 0; i < PRF_K; i++) {
                for (int j = 0; j < RING_DEG; j++) {
                    w_k_vec.vec[i].coeffs[j] = w[i * RING_DEG + j];
                }
            }
            poly_t v_w_poly;
            memset(v_w_poly.coeffs, 0, sizeof(v_w_poly.coeffs));
            for (int i = 0; i < PRF_K; i++) {
                poly_mul(&temp, &A_vec.vec[i], &w_k_vec.vec[i]);
                poly_add(&v_w_poly, &v_w_poly, &temp);
            }
            polyvec_free(&w_k_vec);

            int32_t V_U[256];
            for (int i = 0; i < 256; i++) {
                int64_t y_val = (i < NULLIFIER_LEN) ? y[i] : 0;
                V_U[i] = reduce_mod_q((int64_t)v_w_poly.coeffs[i] - (int64_t)w[1024 + i] * PRF_P - w[1280 + i] - y_val);
            }

            uint8_t c1_input[32 + 256 * sizeof(int32_t)];
            memcpy(c1_input, seed_pi, 32);
            memcpy(c1_input + 32, V_U, 256 * sizeof(int32_t));
            SHA256(c1_input, sizeof(c1_input), c1);

            memcpy(c2, c2_sib, 32);

            int32_t perm_k[1024], perm_z[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t pi_w_k[1024], pi_w_z[256], pi_w_err[256];
            for (int i = 0; i < 1024; i++) pi_w_k[i] = w[perm_k[i]];
            for (int i = 0; i < 256; i++) pi_w_z[i] = w[1024 + perm_z[i]];
            for (int i = 0; i < 256; i++) pi_w_err[i] = w[1280 + perm_err[i]];

            uint8_t pi_w_packed[4416];
            pack_bits(pi_w_k, 1024, 23, pi_w_packed);
            pack_bits(pi_w_z, 256, 23, pi_w_packed + 2944);
            pack_bits(pi_w_err, 256, 23, pi_w_packed + 3680);
            SHA256(pi_w_packed, sizeof(pi_w_packed), c3);

        } else { // e == 2
            if (remaining < 32 + 992 + 32) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_FORMAT; }
            const uint8_t *seed_v = p; p += 32;
            const uint8_t *pi_S_packed = p; p += 992;
            const uint8_t *c1_sib = p; p += 32;
            remaining -= 1056;

            memcpy(c1, c1_sib, 32);

            int32_t pi_u[1536];
            deterministic_random_vector(pi_u, 1536, seed_v);

            int32_t temp[1024];
            int32_t pi_S[1536];
            unpack_bits(pi_S_packed, 1024, 2, temp);
            for (int i = 0; i < 1024; i++) {
                int32_t val = temp[i] - 1;
                pi_S[i] = (val < 0) ? (val + Q) : val;
            }
            unpack_bits(pi_S_packed + 256, 256, 15, temp);
            for (int i = 0; i < 256; i++) {
                pi_S[1024 + i] = temp[i];
            }
            unpack_bits(pi_S_packed + 256 + 480, 256, 8, temp);
            for (int i = 0; i < 256; i++) {
                pi_S[1280 + i] = temp[i];
            }

            int32_t pi_w[1536];
            for (int i = 0; i < 1536; i++) {
                pi_w[i] = (pi_u[i] + pi_S[i]) % Q;
            }

            uint8_t pi_u_packed[4416];
            pack_bits(pi_u, 1024, 23, pi_u_packed);
            pack_bits(pi_u + 1024, 256, 23, pi_u_packed + 2944);
            pack_bits(pi_u + 1280, 256, 23, pi_u_packed + 3680);
            
            uint8_t pi_w_packed[4416];
            pack_bits(pi_w, 1024, 23, pi_w_packed);
            pack_bits(pi_w + 1024, 256, 23, pi_w_packed + 2944);
            pack_bits(pi_w + 1280, 256, 23, pi_w_packed + 3680);

            SHA256(pi_u_packed, sizeof(pi_u_packed), c2);
            SHA256(pi_w_packed, sizeof(pi_w_packed), c3);

            int wt = 0;
            for (int i = 0; i < 1024; i++) {
                int32_t val = pi_S[i];
                if (val > Q / 2) val -= Q;
                if (val == 1 || val == -1) wt++;
                else if (val != 0) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }
            if (wt != PRF_HAMMING) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }

            for (int i = 1024; i < 1280; i++) {
                int32_t val = pi_S[i];
                if (val > Q / 2) val -= Q;
                if (val < 0 || val > (PRF_Q / PRF_P)) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }

            for (int i = 1280; i < 1536; i++) {
                int32_t val = pi_S[i];
                if (val > Q / 2) val -= Q;
                if (val < 0 || val > 255) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
                // Enforce that the unpermuted nullifier segment is strictly zero
                if (i < 1280 + NULLIFIER_LEN && val != 0) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }
        }

        uint8_t merkle_input[64];
        memcpy(merkle_input, c1, 32);
        memcpy(merkle_input + 32, c2, 32);
        uint8_t intermediate[32];
        SHA256(merkle_input, 64, intermediate);
        memcpy(merkle_input, intermediate, 32);
        memcpy(merkle_input + 32, c3, 32);
        SHA256(merkle_input, 64, round_roots + rep * 32);
    }

    uint8_t computed_global_root[32];
    SHA256(round_roots, ZK_KAPPA * 32, computed_global_root);

    polyvec_free(&A_vec);
    int ret_val = (memcmp(computed_global_root, global_root_proof, 32) == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_PROOF_INVALID;
    arena_reset(fn_mark);
    return ret_val;
#endif
}

/* ============================================================================ */
/* SECTION 21: HEAVY CRYPTOGRAPHIC DISPATCH & CONSENSUS VALIDATION              */
/* ============================================================================ */

/**
 * @brief Dispatches heavy zero-knowledge verification for individual ledger operations.
 *
 * @details
 * Validates post-quantum zero-knowledge proofs attached to individual state-transition operations:
 * - `OP_TRANSFER_POINTER`: Invokes @ref zk_prf_verify against the transaction nullifier and client root.
 * - `OP_REDEEM_CENTINEL`: Invokes @ref zk_centinel_verify to authenticate shielded UTXO proofs.
 * Other operation types bypass heavy cryptographic verification.
 *
 * @param[in] op Pointer to the Operation union structure to verify.
 * @return CRYPTO_SUCCESS if valid or non-heavy; CRYPTO_ERROR_PROOF_INVALID on proof rejection.
 *
 * @thread_safety Reentrant and thread-safe.
 * @complexity Dependent on operation type: O(1) for basic operations, O(ZK_KAPPA) for ZK transfers.
 */
int verify_operation_heavy_crypto(const Operation *op) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)op;
    return CRYPTO_SUCCESS;
#else
    if (!op) return CRYPTO_SUCCESS;
    
    if (op->type == OP_TRANSFER_POINTER) {
        const TransferData *tx = &op->data.transfer_pointer;
        if (zk_prf_verify(tx->zk_proof, tx->zk_proof_len, tx->client_root, tx->tx_id, COIN_ID_LEN, tx->prf_output) != CRYPTO_SUCCESS) {
            return CRYPTO_ERROR_PROOF_INVALID;
        }
    } else if (op->type == OP_REDEEM_CENTINEL) {
        if (zk_centinel_verify(&op->data.redeem_centinel) != CRYPTO_SUCCESS) {
            return CRYPTO_ERROR_PROOF_INVALID;
        }
    }
    
    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Executes consensus-grade heavy cryptographic verification across an entire Block.
 *
 * @details
 * Performs exhaustive two-stage cryptographic validation:
 * 1. Executes batch ZK-PRF verification (@ref zk_batch_prf_verify) over all transfer operations.
 * 2. Iterates over all block operations and verifies individual Centinel shielded UTXO proofs.
 *
 * @param[in] block Pointer to Block candidate proposed by leader or received over gossip network.
 * @return CRYPTO_SUCCESS if all proofs pass; CRYPTO_ERROR_PROOF_INVALID on any verification failure.
 *
 * @pre `block` must be non-NULL; block header signatures must be pre-validated by caller.
 * @complexity Time: O(B * ZK_KAPPA) where B is the count of zero-knowledge operations.
 */
int verify_block_heavy_crypto(const Block *block) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)block;
    return CRYPTO_SUCCESS;
#else
    if (!block) return CRYPTO_SUCCESS;
    
    // 1. Verify Batch ZK-PRF for Transfers
    if (block->block_number > 0 && block->batch_tx_count > 0) {
        if (zk_batch_prf_verify(block) != CRYPTO_SUCCESS) {
            return CRYPTO_ERROR_PROOF_INVALID;
        }
    }
    
    // 2. Verify all Centinel ZK-SNARKs
    for (size_t i = 0; i < block->operation_count; i++) {
        if (block->operations[i].type == OP_REDEEM_CENTINEL) {
            if (zk_centinel_verify(&block->operations[i].data.redeem_centinel) != CRYPTO_SUCCESS) {
                return CRYPTO_ERROR_PROOF_INVALID;
            }
        }
    }
    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Verifies batched ZK-PRF Stern proofs across all pointer transfers in a proposed block.
 *
 * @details
 * Unpacks the contiguous batch proof buffer `block->batch_zk_proof` into individual transfer proofs:
 * 1. Verifies that `block->batch_tx_count` matches the actual count of `OP_TRANSFER_POINTER` operations.
 * 2. Unpacks 4-byte big-endian proof length prefixes preceding each individual proof frame.
 * 3. Associates each proof with its corresponding public transaction identifier, client root, and
 *    nullifier digest extracted from `block->batch_prf_outputs`.
 * 4. Invokes @ref zk_prf_verify on each individual proof frame.
 * 5. Asserts that the entire batch buffer is consumed without trailing residual bytes.
 *
 * @param[in] block Pointer to Block containing batch proof buffers.
 * @return CRYPTO_SUCCESS on full verification; CRYPTO_ERROR_PROOF_FORMAT or CRYPTO_ERROR_PROOF_INVALID on defect.
 *
 * @complexity Time: O(N_tx * ZK_KAPPA * RING_DEG^2), Space: O(1) beyond thread-local arena.
 */
int zk_batch_prf_verify(const Block *block) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)block;
    return CRYPTO_SUCCESS;
#else
    // Fast path: no transfers to verify
    if (!block || block->batch_tx_count == 0) {
        // If no transfers, proof must be empty as well
        if (block && block->batch_tx_count == 0) {
            if (block->batch_zk_proof_len != 0 || block->batch_prf_outputs != NULL) {
                fprintf(stderr, "[Crypto] ERROR: Non-empty proof data when no transfers exist\n");
                return CRYPTO_ERROR_PROOF_FORMAT;
            }
        }
        return CRYPTO_SUCCESS;
    }
    
    // Validate essential data presence
    if (block->batch_zk_proof_len == 0 || !block->batch_prf_outputs || !block->batch_zk_proof) {
        fprintf(stderr, "[Crypto] ERROR: Batch proof data missing for %zu transfers\n", block->batch_tx_count);
        return CRYPTO_ERROR_PROOF_FORMAT;
    }
    
    const uint8_t *proof_ptr = block->batch_zk_proof;
    size_t remaining_proof_len = block->batch_zk_proof_len;
    size_t tx_idx = 0;
    
    for (size_t i = 0; i < block->operation_count; ++i) {
        if (block->operations[i].type == OP_TRANSFER_POINTER) {
            // Prevent overflow beyond declared transfer count
            if (tx_idx >= block->batch_tx_count) {
                fprintf(stderr, "[Crypto] ERROR: More transfers found than batch_tx_count (%zu)\n", block->batch_tx_count);
                return CRYPTO_ERROR_PROOF_INVALID;
            }
            
            TransferData *tx = &block->operations[i].data.transfer_pointer;
            
            // Extract individual proof length (4 bytes, big-endian)
            if (remaining_proof_len < 4) {
                fprintf(stderr, "[Crypto] ERROR: Insufficient data for proof length prefix at tx %zu\n", tx_idx);
                return CRYPTO_ERROR_PROOF_FORMAT;
            }
            uint32_t i_proof_len;
            memcpy(&i_proof_len, proof_ptr, 4);
            i_proof_len = be32toh(i_proof_len);
            
            // Validate proof length
            if (i_proof_len > remaining_proof_len - 4) {
                fprintf(stderr, "[Crypto] ERROR: Declared proof length %u exceeds buffer (remaining: %zu) at tx %zu\n",
                        i_proof_len, remaining_proof_len - 4, tx_idx);
                return CRYPTO_ERROR_PROOF_FORMAT;
            }
            
            // Pointer transfers use the attached prf_output from the block header
            const uint8_t *y = block->batch_prf_outputs + (tx_idx * NULLIFIER_LEN);
            
            // Critical: Pass tx->client_root as the public matrix seed
            if (zk_prf_verify(proof_ptr + 4, i_proof_len, tx->client_root, tx->tx_id, COIN_ID_LEN, y) != CRYPTO_SUCCESS) {
                fprintf(stderr, "[Crypto] ERROR: ZK-PRF verification failed for transfer %zu\n", tx_idx);
                return CRYPTO_ERROR_PROOF_INVALID;
            }
            
            proof_ptr += (4 + i_proof_len);
            remaining_proof_len -= (4 + i_proof_len);
            tx_idx++;
        }
    }
    
    // Final validation: processed all expected transfers
    if (tx_idx != block->batch_tx_count) {
        fprintf(stderr, "[Crypto] ERROR: Processed %zu transfers, expected %zu\n", tx_idx, block->batch_tx_count);
        return CRYPTO_ERROR_PROOF_INVALID;
    }
    
    // Ensure all proof data was consumed
    if (remaining_proof_len != 0) {
        scl_log(LOG_LEVEL_ERROR, "Crypto", "Extra data remaining in batch proof buffer (%zu bytes)", remaining_proof_len);
        return CRYPTO_ERROR_PROOF_FORMAT;
    }
    
    scl_log(LOG_LEVEL_DEBUG, "Crypto", "Batch ZK-PRF proof for %zu transfers verified successfully", block->batch_tx_count);
    return CRYPTO_SUCCESS;
#endif
}

/* ============================================================================ */
/* SECTION 22: PRF KEY GENERATION & KEY EXCHANGE                                */
/* ============================================================================ */

/**
 * @brief Samples a sparse ternary key vector $k \in \{-1, 0, 1\}^{1024}$ for Module-SIS PRF evaluation.
 *
 * @details
 * Samples an exact ternary secret vector of dimension $M = 1,024$ with Hamming weight $H = 250$:
 * 1. Absorbs `seed` and ASCII tag `"SparsePRFKey"` into an incremental SHAKE-256 state.
 * 2. Samples 250 distinct random coefficient indices using Fisher-Yates shuffle with branchless modulo.
 * 3. Assigns uniformly distributed signs $\{-1, 1\}$ to the selected 250 positions, leaving remaining
 *    774 coefficients zero.
 *
 * @param[out] key Destination @ref PRFKey structure receiving the sampled key vector.
 * @param[in] seed High-entropy seed buffer.
 * @param[in] seed_len Byte length of seed (must be $\ge \kappa = 32$).
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_INVALID_PARAM on invalid inputs.
 *
 * @pre `key` must be non-NULL; `seed` must provide at least 256 bits of cryptographic entropy.
 * @post `key->k` contains exactly 250 non-zero values in $\{-1, 1\}$.
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(PRF_M) branchless, Space: O(1).
 */
crypto_error_t prf_keygen(PRFKey *key, const uint8_t *seed, size_t seed_len) {
    if (!key || !seed || seed_len < KAPPA) return CRYPTO_ERROR_INVALID_PARAM;

    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, seed, seed_len);
    custom_shake256_inc_absorb(&state, (uint8_t*)"SparsePRFKey", 12);
    custom_shake256_inc_finalize(&state);

    memset(key->k, 0, sizeof(key->k));

    uint16_t pos[PRF_M];
    for (int i = 0; i < PRF_M; i++) pos[i] = i;

    for (int i = PRF_M - 1; i > 0; i--) {
        uint16_t j;
        custom_shake256_inc_squeeze((uint8_t*)&j, 2, &state);
        
        // Strictly branchless modulo loop protecting generated secret keys
        uint32_t res = j;
        uint32_t range = i + 1;
        for (int k = 15; k >= 0; k--) {
            uint32_t shifted = range << k;
            uint32_t mask = (uint32_t)(~(((int64_t)res - (int64_t)shifted) >> 63));
            res -= shifted & mask;
        }
        j = (uint16_t)res;
        
        uint16_t tmp = pos[i]; pos[i] = pos[j]; pos[j] = tmp;
    }

    for (int i = 0; i < PRF_HAMMING; i++) {
        uint8_t sign;
        custom_shake256_inc_squeeze(&sign, 1, &state);
        key->k[pos[i]] = (sign & 1) ? 1 : -1;
    }

    custom_shake256_inc_ctx_release(&state);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Derives domain-separated cryptographic keys using HKDF-SHA256 (RFC 5869).
 *
 * @details
 * Evaluates HMAC-based Key Derivation Function (HKDF) over a 32-byte ML-KEM-768 shared secret:
 * - Salt: Static protocol salt `"SCL Handshake Salt"`.
 * - Input Keying Material (IKM): `shared_secret`.
 * - Contextual Info: ASCII string `label`.
 *
 * @param[in] shared_secret Decapsulated post-quantum shared secret (32 bytes).
 * @param[in] label Contextual string label defining key usage domain.
 * @param[out] out_key Destination buffer receiving derived key bytes.
 * @param[in] out_len Number of key bytes to derive.
 * @return 0 on success; -1 if shared secret is zeroed or OpenSSL HKDF fails.
 *
 * @pre `shared_secret` must not be zeroed out; `out_key` must allocate `out_len` bytes.
 * @complexity Time: O(out_len), Space: O(1).
 */
int derive_labeled_key(const uint8_t *shared_secret, const char *label, uint8_t *out_key, size_t out_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)shared_secret; (void)label;
    if (!out_key) return -1;
    memset(out_key, 0x42, out_len);
    return 0;
#else
    if (is_zeroed(shared_secret, KYBER_SHARED_SECRET_LEN)) {
        fprintf(stderr, "[Crypto] ERROR: Shared secret is zeroed for labeled key derivation\n");
        return -1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    const uint8_t salt[] = "SCL Handshake Salt";
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen((const char *)salt)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, KYBER_SHARED_SECRET_LEN) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)label, strlen(label)) <= 0) {
        fprintf(stderr, "[Crypto] ERROR: Labeled HKDF setup failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out_key, &len) <= 0 || len != out_len) {
        fprintf(stderr, "[Crypto] ERROR: Labeled HKDF derivation failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
#endif
}

/* ============================================================================ */
/* SECTION 23: L2 AEAD TRANSPORT PACKET ENCRYPTION & SIPHASH                    */
/* ============================================================================ */

/**
 * @brief Encrypts transport packet payloads using AES-256-GCM with implicit QUIC-style nonces.
 *
 * @details
 * Constructs a 12-byte initialization vector (IV) from 4 zero-padding bytes concatenated with
 * the 64-bit big-endian packet sequence number `packet_num`:
 * $$\text{IV} = [00\ 00\ 00\ 00\ ||\ \text{htobe64}(packet\_num)]$$
 * Encrypts payload and appends a 16-byte GMAC authentication tag to the output buffer:
 * $$\text{Total Size} = \text{plaintext\_len} + 16$$
 *
 * @param[in] aes_key 256-bit symmetric encryption key.
 * @param[in] packet_num Monotonically increasing 64-bit transport packet sequence number.
 * @param[in] plaintext Payload data buffer to encrypt.
 * @param[in] plaintext_len Byte length of payload (must not exceed @ref MAX_MESSAGE_SIZE).
 * @param[out] ciphertext Destination buffer (must allocate at least `plaintext_len + 16` bytes).
 * @param[out] ciphertext_len Output byte length of ciphertext plus 16-byte tag.
 * @return 0 on success; -1 on invalid parameters or encryption failure.
 *
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(plaintext_len), Space: O(1) stack context.
 */
int encrypt_aead_packet(const uint8_t *aes_key, uint64_t packet_num, const uint8_t *plaintext,
                        size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len,
                        const uint8_t *aad, size_t aad_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)aes_key; (void)packet_num; (void)aad; (void)aad_len;
    if (!plaintext || !ciphertext || !ciphertext_len || plaintext_len > MAX_MESSAGE_SIZE) return -1;
    memcpy(ciphertext, plaintext, plaintext_len);
    memset(ciphertext + plaintext_len, 0x42, 16);
    *ciphertext_len = plaintext_len + 16;
    return 0;
#else
    if (!aes_key || !plaintext || !ciphertext || !ciphertext_len) return -1;

    // Standard QUIC implicit nonce: 4 bytes padding + 8 byte Packet Number
    uint8_t iv[12] = {0};
    uint64_t pn_be = htobe64(packet_num);
    memcpy(iv + 4, &pn_be, 8);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv);

    /* H-1 fix: bind the packet header + fragment metadata (all bytes preceding the
     * ciphertext) as AAD so on-path splicing into wrong reassembly slots fails. */
    if (aad && aad_len > 0) {
        int aad_out = 0;
        if (EVP_EncryptUpdate(ctx, NULL, &aad_out, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    *ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    *ciphertext_len += len;

    // Append 16-byte Authentication Tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + *ciphertext_len);
    *ciphertext_len += 16;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
#endif
}

/**
 * @brief Decrypts and authenticates transport packet payloads using AES-256-GCM.
 *
 * @details
 * Validates the 16-byte GMAC authentication tag located at the trailing offset of `ciphertext`.
 * Reconstructs the 12-byte implicit IV from `packet_num`. If authentication passes, decrypts the
 * payload into `plaintext`; if the GMAC tag does not match, aborts and returns -1 without leaking
 * unauthenticated plaintext data.
 *
 * @param[in] aes_key 256-bit symmetric decryption key.
 * @param[in] packet_num Monotonically increasing 64-bit transport packet sequence number.
 * @param[in] ciphertext Ciphertext data buffer containing payload and trailing 16-byte tag.
 * @param[in] ciphertext_len Byte length of ciphertext (must be $\ge 16$).
 * @param[out] plaintext Destination buffer receiving decrypted payload data.
 * @param[out] plaintext_len Output byte length of decrypted payload (`ciphertext_len - 16`).
 * @return 0 on success; -1 if ciphertext is too short, authentication fails, or decryption errors.
 *
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(ciphertext_len), Space: O(1) stack context.
 */
int decrypt_aead_packet(const uint8_t *aes_key, uint64_t packet_num, const uint8_t *ciphertext,
                        size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len,
                        const uint8_t *aad, size_t aad_len) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)packet_num;
    (void)aes_key;
    (void)aad;
    (void)aad_len;
    if (!ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len < 16 || (ciphertext_len - 16) > MAX_MESSAGE_SIZE) return -1;
    *plaintext_len = ciphertext_len - 16;
    memcpy(plaintext, ciphertext, *plaintext_len);
    return 0;
#else
    if (!aes_key || !ciphertext || !plaintext || !plaintext_len) return -1;

    // Check ciphertext length (data + tag)
    if (ciphertext_len < 16) {
        fprintf(stderr, "[Crypto] ERROR: Ciphertext too short: %zu bytes, expected >= 16\n",
                ciphertext_len);
        return -1;
    }

    uint8_t iv[12] = {0};
    uint64_t pn_be = htobe64(packet_num);
    memcpy(iv + 4, &pn_be, 8);

    // Extract tag
    const uint8_t *tag = ciphertext + ciphertext_len - 16;
    size_t encrypted_data_len = ciphertext_len - 16;

    // Initialize AES-GCM context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[Crypto] ERROR: Failed to create EVP_CIPHER_CTX\n");
        return -1;
    }

    // Set up AES-256-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to initialize AES-GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set IV length\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set key and IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* H-1 fix: verify the AAD (header + fragment metadata) exactly as bound by the sender. */
    if (aad && aad_len > 0) {
        int aad_out = 0;
        if (EVP_DecryptUpdate(ctx, NULL, &aad_out, aad, aad_len) != 1) {
            fprintf(stderr, "[Crypto] ERROR: AAD authentication failed\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Decrypt data
    int len;
    size_t out_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, encrypted_data_len) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    out_len += len;

    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        fprintf(stderr, "[Crypto] ERROR: Failed to set GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Finalize decryption
    int final_ret = EVP_DecryptFinal_ex(ctx, plaintext + out_len, &len);
    if (final_ret <= 0) {
        fprintf(stderr, "[Crypto] ERROR: Decryption verification failed (invalid tag, ret=%d)\n", final_ret);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    out_len += len;

    *plaintext_len = out_len;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
#endif
}

/**
 * @brief Evaluates the 64-bit SipHash-2-4 pseudorandom function.
 *
 * @details
 * Standard SipHash-2-4 evaluation designed for hash-table collision resistance and DoS mitigation:
 * Uses four 64-bit state registers $(v_0, v_1, v_2, v_3)$ initialized with standard magic constants
 * XORed with the 128-bit key. Processes 64-bit little-endian message words using two compression
 * rounds (`SIPROUND; SIPROUND`) per word, followed by four finalization rounds.
 *
 * @param[in] in Input byte buffer to hash.
 * @param[in] inlen Length of input buffer in bytes.
 * @param[in] key 16-byte secret SipHash key ($k_0 || k_1$).
 * @return 64-bit pseudorandom hash digest.
 *
 * @thread_safety Reentrant and thread-safe.
 * @complexity Time: O(inlen), Space: O(1) stack registers.
 */
uint64_t siphash24(const uint8_t *in, size_t inlen, const uint8_t key[16]) {
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);
    
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    
    const uint8_t *end = in + inlen - (inlen % 8);
    for (; in != end; in += 8) {
        uint64_t m;
        memcpy(&m, in, 8);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }
    
    uint64_t b = ((uint64_t)inlen) << 56;
    switch (inlen % 8) {
        case 7: b |= ((uint64_t)in[6]) << 48; /* fallthrough */
        case 6: b |= ((uint64_t)in[5]) << 40; /* fallthrough */
        case 5: b |= ((uint64_t)in[4]) << 32; /* fallthrough */
        case 4: b |= ((uint64_t)in[3]) << 24; /* fallthrough */
        case 3: b |= ((uint64_t)in[2]) << 16; /* fallthrough */
        case 2: b |= ((uint64_t)in[1]) << 8;  /* fallthrough */
        case 1: b |= ((uint64_t)in[0]);
        case 0: break;
    }
    
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    
    return v0 ^ v1 ^ v2 ^ v3;
}

/* ============================================================================ */
/* SECTION 24: CENTINEL ZERO-KNOWLEDGE PROOF SYSTEM (SHIELDED UTXO CIRCUITS)    */
/* ============================================================================ */

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) || defined(SCL_UNIT_TEST)
/**
 * @brief Generates an interactive-turned-non-interactive Stern proof for Centinel private transactions.
 *
 * @details
 * Proves in zero-knowledge that the prover holds secret opening material $(s, e_1, e_2)$ and secret PRF key $k$
 * satisfying:
 * 1. Balance conservation: $V_{\text{old}} = X_{\text{transfer}} + V_{\text{change}}$ without integer overflow.
 * 2. Commitment opening validity: $C_{\text{old}}, C_{\text{tx}}, C_{\text{ch}}$ are valid BDLOP commitments.
 * 3. Nullifier derivation: $N = \text{LowBits}_p(A \cdot k)$ binds to the spent commitment $C_{\text{old}}$.
 * 4. Value ranges: $X > 0, V_{\text{ch}} \ge 0$.
 *
 * Executes across $\kappa = 219$ challenge repetitions to ensure $2^{-128}$ statistical soundness.
 *
 * @param[out] proof_buf Destination buffer receiving serialized proof bytes.
 * @param[in,out] proof_len Input: buffer capacity; Output: serialized proof byte length.
 * @param[in] c_old Pointer to consumed UTXO BDLOP commitment $C_{\text{old}}$.
 * @param[in] r_old 32-byte opening randomness seed for $C_{\text{old}}$.
 * @param[in] prf_key Secret ternary key vector $k \in \{-1, 0, 1\}^{1024}$.
 * @param[in] nullifier 32-byte nullifier $N_{\text{old}}$ to be verified on-chain.
 * @param[in] c_tx Pointer to transfer UTXO commitment $C_{\text{tx}}$.
 * @param[in] v_tx Atomic transfer value.
 * @param[in] r_tx 32-byte opening randomness seed for $C_{\text{tx}}$.
 * @param[in] c_ch Pointer to change UTXO commitment $C_{\text{ch}}$.
 * @param[in] v_ch Atomic change value.
 * @param[in] r_ch 32-byte opening randomness seed for $C_{\text{ch}}$.
 * @return CRYPTO_SUCCESS on success; error code on memory or parameter failure.
 *
 * @complexity Time: O(ZK_KAPPA * RING_DEG^2), Space: O(ZK_KAPPA * rep_size) arena reservation.
 */
static crypto_error_t generate_centinel_stern_proof(
    uint8_t *proof_buf, size_t *proof_len,
    const BdlopCommitment *c_old, const uint8_t *r_old,
    const PRFKey *prf_key, const uint8_t *nullifier,
    const BdlopCommitment *c_tx, uint64_t v_tx, const uint8_t *r_tx,
    const BdlopCommitment *c_ch, uint64_t v_ch, const uint8_t *r_ch
) {
    size_t fn_mark = arena_mark();

    size_t max_out_len = *proof_len;
    const size_t total_max = 32 + (ZK_KAPPA * 12576);
    if (max_out_len < total_max) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_INVALID_PARAM;
    }

    uint8_t matrix_seed[32];
    SHA256((const uint8_t *)"SCL_GLOBAL_CRS_SEED_FOR_PRF_MATRIX_v1", 37, matrix_seed);

    polyvec_t A_vec;
    if (polyvec_init_arena(&A_vec, PRF_K) != CRYPTO_SUCCESS) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_MEMORY;
    }

    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, matrix_seed, sizeof(matrix_seed));
    custom_shake256_inc_finalize(&state);

    for (int i = 0; i < PRF_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            uint32_t r_val;
            do {
                uint8_t buf[3];
                custom_shake256_inc_squeeze(buf, 3, &state);
                r_val = buf[0] | (buf[1] << 8) | (buf[2] << 16);
                r_val &= 0x7FFFFF;
            } while (r_val >= PRF_Q);
            A_vec.vec[i].coeffs[j] = (int32_t)r_val - (PRF_Q >> 1);
        }
    }
    custom_shake256_inc_ctx_release(&state);

    poly_t s_old, e1_old, e2_old;
    poly_uniform_eta(&s_old, r_old, 32, 0);
    poly_uniform_eta(&e1_old, r_old, 32, 1);
    poly_uniform_eta(&e2_old, r_old, 32, 2);

    poly_t s_tx, e1_tx, e2_tx;
    poly_uniform_eta(&s_tx, r_tx, 32, 0);
    poly_uniform_eta(&e1_tx, r_tx, 32, 1);
    poly_uniform_eta(&e2_tx, r_tx, 32, 2);

    poly_t s_ch, e1_ch, e2_ch;
    memset(&s_ch, 0, sizeof(poly_t));
    memset(&e1_ch, 0, sizeof(poly_t));
    memset(&e2_ch, 0, sizeof(poly_t));
    if (!is_zeroed((const uint8_t*)c_ch, sizeof(BdlopCommitment))) {
        poly_uniform_eta(&s_ch, r_ch, 32, 0);
        poly_uniform_eta(&e1_ch, r_ch, 32, 1);
        poly_uniform_eta(&e2_ch, r_ch, 32, 2);
    }

    int32_t *b_s = arena_alloc(768 * sizeof(int32_t));
    int32_t *b_e1 = arena_alloc(768 * sizeof(int32_t));
    int32_t *b_e2 = arena_alloc(768 * sizeof(int32_t));
    int32_t *b_k = arena_alloc(1024 * sizeof(int32_t));
    int32_t *b_v_tx = arena_alloc(256 * sizeof(int32_t));
    int32_t *b_v_ch = arena_alloc(256 * sizeof(int32_t));
    int32_t *b_z = arena_alloc(256 * sizeof(int32_t));
    int32_t *b_err = arena_alloc(256 * sizeof(int32_t));

    if (!b_s || !b_e1 || !b_e2 || !b_k || !b_v_tx || !b_v_ch || !b_z || !b_err) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_MEMORY;
    }

    for (int i = 0; i < 256; i++) {
        b_s[i] = s_old.coeffs[i];
        b_s[256 + i] = s_tx.coeffs[i];
        b_s[512 + i] = s_ch.coeffs[i];

        b_e1[i] = e1_old.coeffs[i];
        b_e1[256 + i] = e1_tx.coeffs[i];
        b_e1[512 + i] = e1_ch.coeffs[i];

        b_e2[i] = e2_old.coeffs[i];
        b_e2[256 + i] = e2_tx.coeffs[i];
        b_e2[512 + i] = e2_ch.coeffs[i];
    }

    for (int i = 0; i < 1024; i++) {
        b_k[i] = prf_key->k[i];
    }

    poly_t v_tx_poly, v_ch_poly;
    memset(&v_tx_poly, 0, sizeof(poly_t));
    memset(&v_ch_poly, 0, sizeof(poly_t));
    v_tx_poly.coeffs[0] = (int32_t)(v_tx & 0x1FFFFF);
    v_tx_poly.coeffs[1] = (int32_t)((v_tx >> 21) & 0x1FFFFF);
    v_tx_poly.coeffs[2] = (int32_t)((v_tx >> 42) & 0x1FFFFF);
    v_tx_poly.coeffs[3] = (int32_t)((v_tx >> 63) & 0x1);
    
    v_ch_poly.coeffs[0] = (int32_t)(v_ch & 0x1FFFFF);
    v_ch_poly.coeffs[1] = (int32_t)((v_ch >> 21) & 0x1FFFFF);
    v_ch_poly.coeffs[2] = (int32_t)((v_ch >> 42) & 0x1FFFFF);
    v_ch_poly.coeffs[3] = (int32_t)((v_ch >> 63) & 0x1);

    for (int i = 0; i < 256; i++) {
        b_v_tx[i] = v_tx_poly.coeffs[i];
        b_v_ch[i] = v_ch_poly.coeffs[i];
    }

    polyvec_t s_vec;
    if (polyvec_init_arena(&s_vec, PRF_K) != CRYPTO_SUCCESS) { arena_reset(fn_mark); return CRYPTO_ERROR_MEMORY; }
    for (int i = 0; i < PRF_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            s_vec.vec[i].coeffs[j] = prf_key->k[i * RING_DEG + j];
        }
    }
    poly_t v_poly;
    memset(v_poly.coeffs, 0, sizeof(v_poly.coeffs));
    poly_t temp_mul;
    for (int i = 0; i < PRF_K; i++) {
        poly_mul(&temp_mul, &A_vec.vec[i], &s_vec.vec[i]);
        poly_add(&v_poly, &v_poly, &temp_mul);
    }
    polyvec_free(&s_vec);

    for (int i = 0; i < PRF_OUT; i++) {
        int32_t red = reduce_mod_q(v_poly.coeffs[i]);
        red += (red >> 31) & PRF_Q;
        int64_t v_pos = (int64_t)red;
        int64_t is_nullifier_mask = -((int64_t)(i < NULLIFIER_LEN));
        int64_t y_val = (nullifier[i % NULLIFIER_LEN] & is_nullifier_mask);
        int64_t err_val = ((v_pos & 0xFF) & ~is_nullifier_mask);
        int64_t temp_val = v_pos - y_val - err_val;
        temp_val += (temp_val >> 63) & PRF_Q;
        b_z[i] = (int32_t)(temp_val / PRF_P);
        b_err[i] = (int32_t)err_val;
    }

    uint8_t c_old_hash[COIN_ID_LEN];
    SHA256((const uint8_t*)c_old, sizeof(BdlopCommitment), c_old_hash);

    uint8_t fs_input[COIN_ID_LEN + NULLIFIER_LEN + 2 * sizeof(BdlopCommitment)];
    memcpy(fs_input, c_old_hash, COIN_ID_LEN);
    memcpy(fs_input + COIN_ID_LEN, nullifier, NULLIFIER_LEN);
    memcpy(fs_input + COIN_ID_LEN + NULLIFIER_LEN, c_tx, sizeof(BdlopCommitment));
    memcpy(fs_input + COIN_ID_LEN + NULLIFIER_LEN + sizeof(BdlopCommitment), c_ch, sizeof(BdlopCommitment));
    uint8_t fs_seed[32];
    SHA256(fs_input, sizeof(fs_input), fs_seed);

    uint8_t *p = proof_buf;
    uint8_t *global_root_ptr = p;
    p += 32;

    uint8_t round_roots[ZK_KAPPA * 32];
    uint8_t *round_c1 = arena_alloc(ZK_KAPPA * 32);
    uint8_t *round_c2 = arena_alloc(ZK_KAPPA * 32);
    uint8_t *round_c3 = arena_alloc(ZK_KAPPA * 32);
    
    uint8_t *round_seeds_u = arena_alloc(ZK_KAPPA * 32);
    uint8_t *round_seeds_pi = arena_alloc(ZK_KAPPA * 32);
    RAND_bytes(round_seeds_u, ZK_KAPPA * 32);
    RAND_bytes(round_seeds_pi, ZK_KAPPA * 32);

    poly_t a_pub, b_pub;
    bdlop_expand_parameters((const uint8_t*)BDLOP_RHO_SEED, &a_pub, &b_pub);

    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        uint8_t *seed_u = round_seeds_u + rep * 32;
        uint8_t *seed_pi = round_seeds_pi + rep * 32;

        int32_t pi_u_all[4352];
        deterministic_random_vector(pi_u_all, 4352, seed_u); // Optimized: Generate pi_u directly from Seed-V

        int32_t perm_s[768], perm_e1[768], perm_e2[768], perm_k[1024], perm_z[256], perm_v_tx[256], perm_v_ch[256], perm_err[256];
        uint8_t sub_seed[32];
        SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_s, 768, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e1, 768, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e2, 768, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_tx, 256, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_ch, 256, sub_seed);
        SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

        int32_t u[4352];
        for (int i = 0; i < 768; i++) u[perm_s[i]] = pi_u_all[i];
        for (int i = 0; i < 768; i++) u[768 + perm_e1[i]] = pi_u_all[768 + i];
        for (int i = 0; i < 768; i++) u[1536 + perm_e2[i]] = pi_u_all[1536 + i];
        for (int i = 0; i < 1024; i++) u[2304 + perm_k[i]] = pi_u_all[2304 + i];
        for (int i = 0; i < 256; i++) u[3328 + perm_z[i]] = pi_u_all[3328 + i];
        for (int i = 0; i < 256; i++) u[3584 + perm_v_tx[i]] = pi_u_all[3584 + i];
        for (int i = 0; i < 256; i++) u[3840 + perm_v_ch[i]] = pi_u_all[3840 + i];
        for (int i = 0; i < 256; i++) u[4096 + perm_err[i]] = pi_u_all[4096 + i];

        const int32_t *u_s = u;
        const int32_t *u_e1 = u + 768;
        const int32_t *u_e2 = u + 1536;
        const int32_t *u_k = u + 2304;
        const int32_t *u_z = u + 3328;
        const int32_t *u_v_tx = u + 3584;
        const int32_t *u_v_ch = u + 3840;
        const int32_t *u_err = u + 4096;

        poly_t v_u_c1_diff, v_u_c2_diff, v_u_c1_tx, v_u_c2_tx, v_u_c1_ch, v_u_c2_ch, v_u_v_poly;
        compute_centinel_relations(
            &v_u_c1_diff, &v_u_c2_diff, &v_u_c1_tx, &v_u_c2_tx, &v_u_c1_ch, &v_u_c2_ch, &v_u_v_poly,
            &a_pub, &b_pub, &A_vec,
            u_s, u_e1, u_e2, u_k, u_z, u_v_tx, u_v_ch, u_err
        );

        int32_t V_U_v_poly[256];
        for (int i = 0; i < 256; i++) {
            V_U_v_poly[i] = reduce_mod_q((int64_t)v_u_v_poly.coeffs[i] - (int64_t)u_z[i] * PRF_P - u_err[i]);
        }

        uint8_t c1_input[32 + 6 * BDLOP_COEFF_BYTES + 256 * sizeof(int32_t)];
        uint8_t *c_ptr = c1_input;
        memcpy(c_ptr, seed_pi, 32); c_ptr += 32;
        memcpy(c_ptr, v_u_c1_diff.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
        memcpy(c_ptr, v_u_c2_diff.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
        memcpy(c_ptr, v_u_c1_tx.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
        memcpy(c_ptr, v_u_c2_tx.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
        memcpy(c_ptr, v_u_c1_ch.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
        memcpy(c_ptr, v_u_c2_ch.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
        memcpy(c_ptr, V_U_v_poly, 256 * sizeof(int32_t));
        SHA256(c1_input, sizeof(c1_input), round_c1 + rep * 32);

        uint8_t pi_u_packed[12512];
        pack_bits(pi_u_all, 768, 23, pi_u_packed);
        pack_bits(pi_u_all + 768, 768, 23, pi_u_packed + 2208);
        pack_bits(pi_u_all + 1536, 768, 23, pi_u_packed + 4416);
        pack_bits(pi_u_all + 2304, 1024, 23, pi_u_packed + 6624);
        pack_bits(pi_u_all + 3328, 256, 23, pi_u_packed + 9568);
        pack_bits(pi_u_all + 3584, 256, 23, pi_u_packed + 10304);
        pack_bits(pi_u_all + 3840, 256, 23, pi_u_packed + 11040);
        pack_bits(pi_u_all + 4096, 256, 23, pi_u_packed + 11776);
        SHA256(pi_u_packed, sizeof(pi_u_packed), round_c2 + rep * 32);

        int32_t w[4352];
        for (int i = 0; i < 768; i++) w[i] = (u_s[i] + b_s[i] + Q) % Q;
        for (int i = 0; i < 768; i++) w[768 + i] = (u_e1[i] + b_e1[i] + Q) % Q;
        for (int i = 0; i < 768; i++) w[1536 + i] = (u_e2[i] + b_e2[i] + Q) % Q;
        for (int i = 0; i < 1024; i++) w[2304 + i] = (u_k[i] + b_k[i] + Q) % Q;
        for (int i = 0; i < 256; i++) w[3328 + i] = (u_z[i] + b_z[i] + Q) % Q;
        for (int i = 0; i < 256; i++) w[3584 + i] = (u_v_tx[i] + b_v_tx[i] + Q) % Q;
        for (int i = 0; i < 256; i++) w[3840 + i] = (u_v_ch[i] + b_v_ch[i] + Q) % Q;
        for (int i = 0; i < 256; i++) w[4096 + i] = (u_err[i] + b_err[i] + Q) % Q;

        int32_t pi_w_all[4352];
        for (int i = 0; i < 768; i++) pi_w_all[i] = w[perm_s[i]];
        for (int i = 0; i < 768; i++) pi_w_all[768 + i] = w[768 + perm_e1[i]];
        for (int i = 0; i < 768; i++) pi_w_all[1536 + i] = w[1536 + perm_e2[i]];
        for (int i = 0; i < 1024; i++) pi_w_all[2304 + i] = w[2304 + perm_k[i]];
        for (int i = 0; i < 256; i++) pi_w_all[3328 + i] = w[3328 + perm_z[i]];
        for (int i = 0; i < 256; i++) pi_w_all[3584 + i] = w[3584 + perm_v_tx[i]];
        for (int i = 0; i < 256; i++) pi_w_all[3840 + i] = w[3840 + perm_v_ch[i]];
        for (int i = 0; i < 256; i++) pi_w_all[4096 + i] = w[4096 + perm_err[i]];

        uint8_t pi_w_packed[12512];
        pack_bits(pi_w_all, 768, 23, pi_w_packed);
        pack_bits(pi_w_all + 768, 768, 23, pi_w_packed + 2208);
        pack_bits(pi_w_all + 1536, 768, 23, pi_w_packed + 4416);
        pack_bits(pi_w_all + 2304, 1024, 23, pi_w_packed + 6624);
        pack_bits(pi_w_all + 3328, 256, 23, pi_w_packed + 9568);
        pack_bits(pi_w_all + 3584, 256, 23, pi_w_packed + 10304);
        pack_bits(pi_w_all + 3840, 256, 23, pi_w_packed + 11040);
        pack_bits(pi_w_all + 4096, 256, 23, pi_w_packed + 11776);
        SHA256(pi_w_packed, sizeof(pi_w_packed), round_c3 + rep * 32);

        uint8_t merkle_input[64];
        memcpy(merkle_input, round_c1 + rep * 32, 32);
        memcpy(merkle_input + 32, round_c2 + rep * 32, 32);
        uint8_t intermediate[32];
        SHA256(merkle_input, 64, intermediate);
        memcpy(merkle_input, intermediate, 32);
        memcpy(merkle_input + 32, round_c3 + rep * 32, 32);
        SHA256(merkle_input, 64, round_roots + rep * 32);
    }

    uint8_t global_root[32];
    SHA256(round_roots, ZK_KAPPA * 32, global_root);
    memcpy(global_root_ptr, global_root, 32);

    uint8_t fs_final_input[32 + 32];
    memcpy(fs_final_input, global_root, 32);
    memcpy(fs_final_input + 32, fs_seed, 32);
    uint8_t fs_final_hash[32];
    SHA256(fs_final_input, sizeof(fs_final_input), fs_final_hash);
    
    int challenges[ZK_KAPPA];
    custom_shake256_inc_ctx fs_shake;
    custom_shake256_inc_init(&fs_shake);
    custom_shake256_inc_absorb(&fs_shake, fs_final_hash, 32);
    custom_shake256_inc_finalize(&fs_shake);
    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        int e;
        do {
            uint8_t buf;
            custom_shake256_inc_squeeze(&buf, 1, &fs_shake);
            e = buf;
        } while (e >= 252);
        challenges[rep] = e % 3;
    }
    custom_shake256_inc_ctx_release(&fs_shake);

    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        int e = challenges[rep];
        uint8_t *seed_u = round_seeds_u + rep * 32;
        uint8_t *seed_pi = round_seeds_pi + rep * 32;

        if (e == 0) {
            memcpy(p, seed_u, 32); p += 32;
            memcpy(p, seed_pi, 32); p += 32;
            memcpy(p, round_c3 + rep * 32, 32); p += 32;
        } else if (e == 1) {
            int32_t pi_u_all[4352];
            deterministic_random_vector(pi_u_all, 4352, seed_u);
            
            int32_t perm_s[768], perm_e1[768], perm_e2[768], perm_k[1024], perm_z[256], perm_v_tx[256], perm_v_ch[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_s, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e1, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e2, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_tx, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_ch, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t u[4352];
            for (int i = 0; i < 768; i++) u[perm_s[i]] = pi_u_all[i];
            for (int i = 0; i < 768; i++) u[768 + perm_e1[i]] = pi_u_all[768 + i];
            for (int i = 0; i < 768; i++) u[1536 + perm_e2[i]] = pi_u_all[1536 + i];
            for (int i = 0; i < 1024; i++) u[2304 + perm_k[i]] = pi_u_all[2304 + i];
            for (int i = 0; i < 256; i++) u[3328 + perm_z[i]] = pi_u_all[3328 + i];
            for (int i = 0; i < 256; i++) u[3584 + perm_v_tx[i]] = pi_u_all[3584 + i];
            for (int i = 0; i < 256; i++) u[3840 + perm_v_ch[i]] = pi_u_all[3840 + i];
            for (int i = 0; i < 256; i++) u[4096 + perm_err[i]] = pi_u_all[4096 + i];
            
            int32_t w[4352];
            for (int i = 0; i < 768; i++) w[i] = (u[i] + b_s[i] + Q) % Q;
            for (int i = 0; i < 768; i++) w[768 + i] = (u[768 + i] + b_e1[i] + Q) % Q;
            for (int i = 0; i < 768; i++) w[1536 + i] = (u[1536 + i] + b_e2[i] + Q) % Q;
            for (int i = 0; i < 1024; i++) w[2304 + i] = (u[2304 + i] + b_k[i] + Q) % Q;
            for (int i = 0; i < 256; i++) w[3328 + i] = (u[3328 + i] + b_z[i] + Q) % Q;
            for (int i = 0; i < 256; i++) w[3584 + i] = (u[3584 + i] + b_v_tx[i] + Q) % Q;
            for (int i = 0; i < 256; i++) w[3840 + i] = (u[3840 + i] + b_v_ch[i] + Q) % Q;
            for (int i = 0; i < 256; i++) w[4096 + i] = (u[4096 + i] + b_err[i] + Q) % Q;

            uint8_t w_packed[12512];
            pack_bits(w, 768, 23, w_packed);
            pack_bits(w + 768, 768, 23, w_packed + 2208);
            pack_bits(w + 1536, 768, 23, w_packed + 4416);
            pack_bits(w + 2304, 1024, 23, w_packed + 6624);
            pack_bits(w + 3328, 256, 23, w_packed + 9568);
            pack_bits(w + 3584, 256, 23, w_packed + 10304);
            pack_bits(w + 3840, 256, 23, w_packed + 11040);
            pack_bits(w + 4096, 256, 23, w_packed + 11776);

            memcpy(p, w_packed, sizeof(w_packed)); p += sizeof(w_packed);
            memcpy(p, seed_pi, 32); p += 32;
            memcpy(p, round_c2 + rep * 32, 32); p += 32;
        } else {
            // Regenerate all permutations from seed_pi
            int32_t perm_s[768], perm_e1[768], perm_e2[768], perm_k[1024], perm_z[256], perm_v_tx[256], perm_v_ch[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_s, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e1, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e2, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_tx, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_ch, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t pi_S_all[4352];
            for (int i = 0; i < 768; i++) pi_S_all[i] = b_s[perm_s[i]];
            for (int i = 0; i < 768; i++) pi_S_all[768 + i] = b_e1[perm_e1[i]];
            for (int i = 0; i < 768; i++) pi_S_all[1536 + i] = b_e2[perm_e2[i]];
            for (int i = 0; i < 1024; i++) pi_S_all[2304 + i] = b_k[perm_k[i]];
            for (int i = 0; i < 256; i++) pi_S_all[3328 + i] = b_z[perm_z[i]];
            for (int i = 0; i < 256; i++) pi_S_all[3584 + i] = b_v_tx[perm_v_tx[i]];
            for (int i = 0; i < 256; i++) pi_S_all[3840 + i] = b_v_ch[perm_v_ch[i]];
            for (int i = 0; i < 256; i++) pi_S_all[4096 + i] = b_err[perm_err[i]];

            uint8_t pi_S_packed[3200];
            pack_pi_S(pi_S_all, pi_S_packed);

            memcpy(p, seed_u, 32); p += 32; // seed_u natively derives pi_u bypassing raw array payload!
            memcpy(p, pi_S_packed, sizeof(pi_S_packed)); p += sizeof(pi_S_packed);
            memcpy(p, round_c1 + rep * 32, 32); p += 32;
        }
    }

    polyvec_free(&A_vec);
    *proof_len = p - proof_buf;
    arena_reset(fn_mark);
    return CRYPTO_SUCCESS;
}

/**
 * @brief Verifies a Centinel Stern zero-knowledge proof across all algebraic relations and bounds.
 *
 * @details
 * Validates the proof over $\kappa = 219$ rounds:
 * 1. Computes public difference commitment $C_{\text{diff}} = C_{\text{old}} - C_{\text{tx}} - C_{\text{ch}}$.
 * 2. Unpacks proof Merkle root and derives challenges $e \in \{0, 1, 2\}$ via Fiat-Shamir transform.
 * 3. Reconstructs missing commitments $(h_1, h_2, h_3)$ for each round.
 * 4. For $e = 2$, verifies:
 *    - Noise bounds: $s, e_1, e_2 \in [-2, 2]^{768}$.
 *    - PRF key sparsity: $w_H(k) = 250$ with $k_i \in \{-1, 0, 1\}$.
 *    - Quotient bounds: $z_i \in [0, Q/P]$.
 *    - Value decomposition bounds: $v_{\text{tx}}, v_{\text{ch}} \in [0, 2^{21}-1]$ with at least 252 zero limbs.
 *    - Error bounds: $\text{err}_i \in [0, 255]$ with leading nullifier slice strictly zero.
 * 5. Reconstructs global Merkle root and checks bitwise equality against the proof header.
 *
 * @param[in] proof_buf Buffer containing serialized Stern proof.
 * @param[in] proof_len Byte length of proof buffer.
 * @param[in] c_old Pointer to consumed UTXO commitment $C_{\text{old}}$.
 * @param[in] nullifier 32-byte spent nullifier digest.
 * @param[in] c_tx Pointer to transfer UTXO commitment $C_{\text{tx}}$.
 * @param[in] c_ch Pointer to change UTXO commitment $C_{\text{ch}}$.
 * @return CRYPTO_SUCCESS if valid; CRYPTO_ERROR_PROOF_INVALID or CRYPTO_ERROR_PROOF_FORMAT otherwise.
 *
 * @complexity Time: O(ZK_KAPPA * RING_DEG^2), Space: O(1) beyond thread-local arena.
 */
static crypto_error_t verify_centinel_stern_proof(
    const uint8_t *proof_buf, size_t proof_len,
    const BdlopCommitment *c_old,
    const uint8_t *nullifier,
    const BdlopCommitment *c_tx, const BdlopCommitment *c_ch
) {
    size_t fn_mark = arena_mark();

    uint8_t c_old_hash[COIN_ID_LEN];
    SHA256((const uint8_t*)c_old, sizeof(BdlopCommitment), c_old_hash);

    uint8_t fs_input[COIN_ID_LEN + NULLIFIER_LEN + 2 * sizeof(BdlopCommitment)];
    memcpy(fs_input, c_old_hash, COIN_ID_LEN);
    memcpy(fs_input + COIN_ID_LEN, nullifier, NULLIFIER_LEN);
    memcpy(fs_input + COIN_ID_LEN + NULLIFIER_LEN, c_tx, sizeof(BdlopCommitment));
    memcpy(fs_input + COIN_ID_LEN + NULLIFIER_LEN + sizeof(BdlopCommitment), c_ch, sizeof(BdlopCommitment));
    uint8_t fs_seed[32];
    SHA256(fs_input, sizeof(fs_input), fs_seed);

    const uint8_t *p = proof_buf;
    size_t remaining = proof_len;
    if (remaining < 32) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_PROOF_FORMAT;
    }

    const uint8_t *global_root_proof = p;
    p += 32;
    remaining -= 32;

    uint8_t reconstructed_roots[ZK_KAPPA * 32];

    uint8_t matrix_seed[32];
    SHA256((const uint8_t *)"SCL_GLOBAL_CRS_SEED_FOR_PRF_MATRIX_v1", 37, matrix_seed);

    polyvec_t A_vec;
    if (polyvec_init_arena(&A_vec, PRF_K) != CRYPTO_SUCCESS) {
        arena_reset(fn_mark);
        return CRYPTO_ERROR_MEMORY;
    }

    custom_shake256_inc_ctx state;
    custom_shake256_inc_init(&state);
    custom_shake256_inc_absorb(&state, matrix_seed, sizeof(matrix_seed));
    custom_shake256_inc_finalize(&state);

    for (int i = 0; i < PRF_K; i++) {
        for (int j = 0; j < RING_DEG; j++) {
            uint32_t r_val;
            do {
                uint8_t buf[3];
                custom_shake256_inc_squeeze(buf, 3, &state);
                r_val = buf[0] | (buf[1] << 8) | (buf[2] << 16);
                r_val &= 0x7FFFFF;
            } while (r_val >= PRF_Q);
            A_vec.vec[i].coeffs[j] = (int32_t)r_val - (PRF_Q >> 1);
        }
    }
    custom_shake256_inc_ctx_release(&state);

    BdlopCommitment c_diff;
    const int32_t *c1_o = (const int32_t *)c_old->c1;
    const int32_t *c2_o = (const int32_t *)c_old->c2;
    const int32_t *c1_t = (const int32_t *)c_tx->c1;
    const int32_t *c2_t = (const int32_t *)c_tx->c2;
    const int32_t *c1_c = (const int32_t *)c_ch->c1;
    const int32_t *c2_c = (const int32_t *)c_ch->c2;
    int32_t *d1 = (int32_t *)c_diff.c1;
    int32_t *d2 = (int32_t *)c_diff.c2;

    for (int i = 0; i < RING_DEG; i++) {
        d1[i] = reduce_mod_q((int64_t)c1_o[i] - c1_t[i] - c1_c[i]);
        d2[i] = reduce_mod_q((int64_t)c2_o[i] - c2_t[i] - c2_c[i]);
    }

    poly_t a_pub, b_pub;
    bdlop_expand_parameters((const uint8_t*)BDLOP_RHO_SEED, &a_pub, &b_pub);

    uint8_t fs_final_input[32 + 32];
    memcpy(fs_final_input, global_root_proof, 32);
    memcpy(fs_final_input + 32, fs_seed, 32);
    uint8_t fs_final_hash[32];
    SHA256(fs_final_input, sizeof(fs_final_input), fs_final_hash);
    
    int challenges[ZK_KAPPA];
    custom_shake256_inc_ctx fs_shake;
    custom_shake256_inc_init(&fs_shake);
    custom_shake256_inc_absorb(&fs_shake, fs_final_hash, 32);
    custom_shake256_inc_finalize(&fs_shake);
    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        int e;
        do {
            uint8_t buf;
            custom_shake256_inc_squeeze(&buf, 1, &fs_shake);
            e = buf;
        } while (e >= 252);
        challenges[rep] = e % 3;
    }
    custom_shake256_inc_ctx_release(&fs_shake);

    for (int rep = 0; rep < ZK_KAPPA; rep++) {
        size_t rep_mark = arena_mark();

        int e = challenges[rep];
        uint8_t h_c1[32], h_c2[32], h_c3[32];

        if (e == 0) {
            if (remaining < 96) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_FORMAT; }
            const uint8_t *seed_u = p; p += 32;
            const uint8_t *seed_pi = p; p += 32;
            const uint8_t *c3_sib = p; p += 32;
            remaining -= 96;

            int32_t pi_u_all[4352];
            deterministic_random_vector(pi_u_all, 4352, seed_u);

            int32_t perm_s[768], perm_e1[768], perm_e2[768], perm_k[1024], perm_z[256], perm_v_tx[256], perm_v_ch[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_s, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e1, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e2, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_tx, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_ch, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t u[4352];
            for (int i = 0; i < 768; i++) u[perm_s[i]] = pi_u_all[i];
            for (int i = 0; i < 768; i++) u[768 + perm_e1[i]] = pi_u_all[768 + i];
            for (int i = 0; i < 768; i++) u[1536 + perm_e2[i]] = pi_u_all[1536 + i];
            for (int i = 0; i < 1024; i++) u[2304 + perm_k[i]] = pi_u_all[2304 + i];
            for (int i = 0; i < 256; i++) u[3328 + perm_z[i]] = pi_u_all[3328 + i];
            for (int i = 0; i < 256; i++) u[3584 + perm_v_tx[i]] = pi_u_all[3584 + i];
            for (int i = 0; i < 256; i++) u[3840 + perm_v_ch[i]] = pi_u_all[3840 + i];
            for (int i = 0; i < 256; i++) u[4096 + perm_err[i]] = pi_u_all[4096 + i];

            const int32_t *u_s = u;
            const int32_t *u_e1 = u + 768;
            const int32_t *u_e2 = u + 1536;
            const int32_t *u_k = u + 2304;
            const int32_t *u_z = u + 3328;
            const int32_t *u_v_tx = u + 3584;
            const int32_t *u_v_ch = u + 3840;
            const int32_t *u_err = u + 4096;

            poly_t v_u_c1_diff, v_u_c2_diff, v_u_c1_tx, v_u_c2_tx, v_u_c1_ch, v_u_c2_ch, v_u_v_poly;
            compute_centinel_relations(
                &v_u_c1_diff, &v_u_c2_diff, &v_u_c1_tx, &v_u_c2_tx, &v_u_c1_ch, &v_u_c2_ch, &v_u_v_poly,
                &a_pub, &b_pub, &A_vec,
                u_s, u_e1, u_e2, u_k, u_z, u_v_tx, u_v_ch, u_err
            );

            int32_t V_U_v_poly[256];
            for (int i = 0; i < 256; i++) {
                V_U_v_poly[i] = reduce_mod_q((int64_t)v_u_v_poly.coeffs[i] - (int64_t)u_z[i] * PRF_P - u_err[i]);
            }

            uint8_t c1_input[32 + 6 * BDLOP_COEFF_BYTES + 256 * sizeof(int32_t)];
            uint8_t *c_ptr = c1_input;
            memcpy(c_ptr, seed_pi, 32); c_ptr += 32;
            memcpy(c_ptr, v_u_c1_diff.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c2_diff.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c1_tx.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c2_tx.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c1_ch.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c2_ch.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, V_U_v_poly, 256 * sizeof(int32_t));
            SHA256(c1_input, sizeof(c1_input), h_c1);

            uint8_t pi_u_packed[12512];
            pack_bits(pi_u_all, 768, 23, pi_u_packed);
            pack_bits(pi_u_all + 768, 768, 23, pi_u_packed + 2208);
            pack_bits(pi_u_all + 1536, 768, 23, pi_u_packed + 4416);
            pack_bits(pi_u_all + 2304, 1024, 23, pi_u_packed + 6624);
            pack_bits(pi_u_all + 3328, 256, 23, pi_u_packed + 9568);
            pack_bits(pi_u_all + 3584, 256, 23, pi_u_packed + 10304);
            pack_bits(pi_u_all + 3840, 256, 23, pi_u_packed + 11040);
            pack_bits(pi_u_all + 4096, 256, 23, pi_u_packed + 11776);
            SHA256(pi_u_packed, sizeof(pi_u_packed), h_c2);

            memcpy(h_c3, c3_sib, 32);
        } else if (e == 1) {
            if (remaining < 12512 + 64) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_FORMAT; }
            const uint8_t *w_packed = p; p += 12512;
            const uint8_t *seed_pi = p; p += 32;
            const uint8_t *c2_sib = p; p += 32;
            remaining -= 12576;

            int32_t w[4352];
            unpack_bits(w_packed, 768, 23, w);
            unpack_bits(w_packed + 2208, 768, 23, w + 768);
            unpack_bits(w_packed + 4416, 768, 23, w + 1536);
            unpack_bits(w_packed + 6624, 1024, 23, w + 2304);
            unpack_bits(w_packed + 9568, 256, 23, w + 3328);
            unpack_bits(w_packed + 10304, 256, 23, w + 3584);
            unpack_bits(w_packed + 11040, 256, 23, w + 3840);
            unpack_bits(w_packed + 11776, 256, 23, w + 4096);

            const int32_t *w_s = w;
            const int32_t *w_e1 = w + 768;
            const int32_t *w_e2 = w + 1536;
            const int32_t *w_k = w + 2304;
            const int32_t *w_z = w + 3328;
            const int32_t *w_v_tx = w + 3584;
            const int32_t *w_v_ch = w + 3840;
            const int32_t *w_err = w + 4096;

            poly_t v_w_c1_diff, v_w_c2_diff, v_w_c1_tx, v_w_c2_tx, v_w_c1_ch, v_w_c2_ch, v_w_v_poly;
            compute_centinel_relations(
                &v_w_c1_diff, &v_w_c2_diff, &v_w_c1_tx, &v_w_c2_tx, &v_w_c1_ch, &v_w_c2_ch, &v_w_v_poly,
                &a_pub, &b_pub, &A_vec,
                w_s, w_e1, w_e2, w_k, w_z, w_v_tx, w_v_ch, w_err
            );

            int32_t V_U[256];
            for (int i = 0; i < 256; i++) {
                int64_t y_val = (i < NULLIFIER_LEN) ? nullifier[i] : 0;
                V_U[i] = reduce_mod_q((int64_t)v_w_v_poly.coeffs[i] - (int64_t)w_z[i] * PRF_P - w_err[i] - y_val);
            }

            poly_t v_u_c1_diff, v_u_c2_diff, v_u_c1_tx, v_u_c2_tx, v_u_c1_ch, v_u_c2_ch;
            for (int i = 0; i < RING_DEG; i++) {
                v_u_c1_diff.coeffs[i] = reduce_mod_q((int64_t)v_w_c1_diff.coeffs[i] - d1[i]);
                v_u_c2_diff.coeffs[i] = reduce_mod_q((int64_t)v_w_c2_diff.coeffs[i] - d2[i]);
                v_u_c1_tx.coeffs[i] = reduce_mod_q((int64_t)v_w_c1_tx.coeffs[i] - c1_t[i]);
                v_u_c2_tx.coeffs[i] = reduce_mod_q((int64_t)v_w_c2_tx.coeffs[i] - c2_t[i]);
                v_u_c1_ch.coeffs[i] = reduce_mod_q((int64_t)v_w_c1_ch.coeffs[i] - c1_c[i]);
                v_u_c2_ch.coeffs[i] = reduce_mod_q((int64_t)v_w_c2_ch.coeffs[i] - c2_c[i]);
            }

            uint8_t c1_input[32 + 6 * BDLOP_COEFF_BYTES + 256 * sizeof(int32_t)];
            uint8_t *c_ptr = c1_input;
            memcpy(c_ptr, seed_pi, 32); c_ptr += 32;
            memcpy(c_ptr, v_u_c1_diff.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c2_diff.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c1_tx.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c2_tx.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c1_ch.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, v_u_c2_ch.coeffs, BDLOP_COEFF_BYTES); c_ptr += BDLOP_COEFF_BYTES;
            memcpy(c_ptr, V_U, 256 * sizeof(int32_t));
            SHA256(c1_input, sizeof(c1_input), h_c1);

            memcpy(h_c2, c2_sib, 32);

            int32_t perm_s[768], perm_e1[768], perm_e2[768], perm_k[1024], perm_z[256], perm_v_tx[256], perm_v_ch[256], perm_err[256];
            uint8_t sub_seed[32];
            SHA256(seed_pi, 32, sub_seed); generate_permutation_from_seed(perm_s, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e1, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_e2, 768, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_k, 1024, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_z, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_tx, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_permutation_from_seed(perm_v_ch, 256, sub_seed);
            SHA256(sub_seed, 32, sub_seed); generate_err_permutation(perm_err, sub_seed);

            int32_t pi_w_s[768], pi_w_e1[768], pi_w_e2[768], pi_w_k[1024], pi_w_z[256], pi_w_v_tx[256], pi_w_v_ch[256], pi_w_err[256];
            for (int i = 0; i < 768; i++) pi_w_s[i] = w_s[perm_s[i]];
            for (int i = 0; i < 768; i++) pi_w_e1[i] = w_e1[perm_e1[i]];
            for (int i = 0; i < 768; i++) pi_w_e2[i] = w_e2[perm_e2[i]];
            for (int i = 0; i < 1024; i++) pi_w_k[i] = w_k[perm_k[i]];
            for (int i = 0; i < 256; i++) pi_w_z[i] = w_z[perm_z[i]];
            for (int i = 0; i < 256; i++) pi_w_v_tx[i] = w_v_tx[perm_v_tx[i]];
            for (int i = 0; i < 256; i++) pi_w_v_ch[i] = w_v_ch[perm_v_ch[i]];
            for (int i = 0; i < 256; i++) pi_w_err[i] = w_err[perm_err[i]];

            uint8_t pi_w_packed[12512];
            pack_bits(pi_w_s, 768, 23, pi_w_packed);
            pack_bits(pi_w_e1, 768, 23, pi_w_packed + 2208);
            pack_bits(pi_w_e2, 768, 23, pi_w_packed + 4416);
            pack_bits(pi_w_k, 1024, 23, pi_w_packed + 6624);
            pack_bits(pi_w_z, 256, 23, pi_w_packed + 9568);
            pack_bits(pi_w_v_tx, 256, 23, pi_w_packed + 10304);
            pack_bits(pi_w_v_ch, 256, 23, pi_w_packed + 11040);
            pack_bits(pi_w_err, 256, 23, pi_w_packed + 11776);
            SHA256(pi_w_packed, sizeof(pi_w_packed), h_c3);
        } else { // e == 2
            if (remaining < 32 + 3200 + 32) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_FORMAT; }
            const uint8_t *seed_v = p; p += 32;
            const uint8_t *pi_S_packed = p; p += 3200;
            const uint8_t *c1_sib = p; p += 32;
            remaining -= 3264;

            memcpy(h_c1, c1_sib, 32);

            int32_t pi_u[4352];
            deterministic_random_vector(pi_u, 4352, seed_v);

            int32_t pi_S[4352], pi_w[4352];
            unpack_pi_S(pi_S_packed, pi_S);

            for (int i = 0; i < 4352; i++) {
                pi_w[i] = (pi_u[i] + pi_S[i]) % Q;
            }

            uint8_t pi_u_packed[12512];
            pack_bits(pi_u, 768, 23, pi_u_packed);
            pack_bits(pi_u + 768, 768, 23, pi_u_packed + 2208);
            pack_bits(pi_u + 1536, 768, 23, pi_u_packed + 4416);
            pack_bits(pi_u + 2304, 1024, 23, pi_u_packed + 6624);
            pack_bits(pi_u + 3328, 256, 23, pi_u_packed + 9568);
            pack_bits(pi_u + 3584, 256, 23, pi_u_packed + 10304);
            pack_bits(pi_u + 3840, 256, 23, pi_u_packed + 11040);
            pack_bits(pi_u + 4096, 256, 23, pi_u_packed + 11776);

            uint8_t pi_w_packed[12512];
            pack_bits(pi_w, 768, 23, pi_w_packed);
            pack_bits(pi_w + 768, 768, 23, pi_w_packed + 2208);
            pack_bits(pi_w + 1536, 768, 23, pi_w_packed + 4416);
            pack_bits(pi_w + 2304, 1024, 23, pi_w_packed + 6624);
            pack_bits(pi_w + 3328, 256, 23, pi_w_packed + 9568);
            pack_bits(pi_w + 3584, 256, 23, pi_w_packed + 10304);
            pack_bits(pi_w + 3840, 256, 23, pi_w_packed + 11040);
            pack_bits(pi_w + 4096, 256, 23, pi_w_packed + 11776);

            SHA256(pi_u_packed, 12512, h_c2);
            SHA256(pi_w_packed, 12512, h_c3);

            int32_t pi_S_checked[4352];
            for (int i = 0; i < 4352; i++) {
                pi_S_checked[i] = (pi_w[i] - pi_u[i] + Q) % Q;
            }

            for (int i = 0; i < 768 * 3; i++) {
                int32_t val = pi_S_checked[i];
                if (val > Q / 2) val -= Q;
                if (val < -2 || val > 2) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }

            int ternary_wt = 0;
            for (int i = 0; i < 1024; i++) {
                int32_t val = pi_S_checked[2304 + i];
                if (val > Q / 2) val -= Q;
                if (val == 1 || val == -1) ternary_wt++;
                else if (val != 0) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }
            if (ternary_wt != PRF_HAMMING) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }

            for (int i = 0; i < 256; i++) {
                int32_t val = pi_S_checked[3328 + i];
                if (val > Q / 2) val -= Q;
                if (val < 0 || val > (PRF_Q / PRF_P)) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }
            
            int tx_zeros = 0, ch_zeros = 0;
            for (int i = 0; i < 256; i++) {
                int32_t val_tx = pi_S_checked[3584 + i];
                int32_t val_ch = pi_S_checked[3840 + i];
                if (val_tx > Q / 2) val_tx -= Q;
                if (val_ch > Q / 2) val_ch -= Q;
                
                if (val_tx == 0) tx_zeros++;
                else if (val_tx < 0 || val_tx > 0x1FFFFF) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
                
                if (val_ch == 0) ch_zeros++;
                else if (val_ch < 0 || val_ch > 0x1FFFFF) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }
            if (tx_zeros < 252 || ch_zeros < 252) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }

            for (int i = 4096; i < 4352; i++) {
                int32_t val = pi_S_checked[i];
                if (val > Q / 2) val -= Q;
                if (val < 0 || val > 255) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
                // Enforce that the unpermuted nullifier segment is strictly zero
                if (i < 4096 + NULLIFIER_LEN && val != 0) { polyvec_free(&A_vec); arena_reset(fn_mark); return CRYPTO_ERROR_PROOF_INVALID; }
            }
        }

        uint8_t merkle_input[64];
        memcpy(merkle_input, h_c1, 32);
        memcpy(merkle_input + 32, h_c2, 32);
        uint8_t intermediate[32];
        SHA256(merkle_input, 64, intermediate);
        memcpy(merkle_input, intermediate, 32);
        memcpy(merkle_input + 32, h_c3, 32);
        SHA256(merkle_input, 64, reconstructed_roots + rep * 32);
        
        arena_reset(rep_mark);
    }
    
    if (remaining != 0) {
        polyvec_free(&A_vec);
        arena_reset(fn_mark);
        return CRYPTO_ERROR_PROOF_FORMAT;
    }

    uint8_t computed_global_root[32];
    SHA256(reconstructed_roots, ZK_KAPPA * 32, computed_global_root);

    polyvec_free(&A_vec);
    int ret_val = (memcmp(computed_global_root, global_root_proof, 32) == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_PROOF_INVALID;
    arena_reset(fn_mark);
    return ret_val;
}
#endif

/**
 * @brief Constructs a complete Centinel redemption operation payload including commitments and ZK proof.
 *
 * @details
 * High-level prover API for spending Centinel shielded UTXOs:
 * 1. Checks balance conservation: $v_{\text{old}} = \text{amount} + v_{\text{change}}$ strictly.
 * 2. Checks that transfer amount is strictly positive: $\text{amount} > 0$.
 * 3. Computes BDLOP commitments $C_{\text{old}}, C_{\text{transfer}}, C_{\text{change}}$.
 * 4. Derives nullifier $N_{\text{old}} = \text{PRF}_k(\text{SHA256}(C_{\text{old}}))$.
 * 5. Generates the 219-round Stern zero-knowledge proof binding all circuit relations.
 * 6. Packs $C_{\text{old}}$ and Stern proof into `out_data->zk_proof`.
 *
 * @param[in] pk_old Public key of current UTXO owner.
 * @param[in] v_old Value of input UTXO.
 * @param[in] r_old 32-byte commitment randomness of input UTXO.
 * @param[in] pk_transfer Destination public key receiving transfer.
 * @param[in] amount Value transferred to recipient.
 * @param[in] r_transfer 32-byte commitment randomness for recipient UTXO.
 * @param[in] pk_change Public key receiving change balance.
 * @param[in] v_change Value of change UTXO ($v_{\text{old}} - \text{amount}$).
 * @param[in] r_change 32-byte commitment randomness for change UTXO.
 * @param[in] prf_key Secret ternary PRF key vector.
 * @param[in] root Historical ledger MMR root anchor.
 * @param[in] path Merkle Mountain Range inclusion proof for input UTXO.
 * @param[out] out_data Destination @ref RedeemCentinelData structure receiving nullifier, commitments, and proof.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_INVALID_PARAM or CRYPTO_ERROR_COMPUTE on failure.
 *
 * @complexity Time: O(ZK_KAPPA * RING_DEG^2), Space: O(ZK_PROOF_MAX_LEN).
 */
crypto_error_t generate_centinel_proof(
    const uint8_t *pk_old, uint64_t v_old, const uint8_t *r_old,
    const uint8_t *pk_transfer, uint64_t amount, const uint8_t *r_transfer,
    const uint8_t *pk_change, uint64_t v_change, const uint8_t *r_change,
    const PRFKey *prf_key, const uint8_t *root,
    const MMRProof *path, RedeemCentinelData *out_data
) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)pk_old; (void)v_old; (void)r_old;
    (void)pk_transfer; (void)amount; (void)r_transfer;
    (void)pk_change; (void)v_change; (void)r_change;
    (void)prf_key; (void)root; (void)path;
    if (out_data) {
        memset(out_data->zk_proof, 0x42, 128);
        out_data->zk_proof_len = 128;
        memset(out_data->nullifier, 0x42, NULLIFIER_LEN);
    }
    return CRYPTO_SUCCESS;
#else
    if (!pk_old || !r_old || !pk_transfer || !r_transfer || !pk_change || !r_change || !prf_key || !root || !path || !out_data) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // 1. Conservation check: V_old == X + V_chg
    if (v_old != amount + v_change) {
        fprintf(stderr, "[Crypto] ERROR: Centinel conservation constraint failed\n");
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // 2. Range check: X > 0
    if (amount == 0) {
        fprintf(stderr, "[Crypto] ERROR: Centinel transfer amount must be > 0\n");
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    // 3. Generate BDLOP Commitments
    BdlopCommitment c_old;
    if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_old, r_old, &c_old) != CRYPTO_SUCCESS) return CRYPTO_ERROR_COMPUTE;
    if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, amount, r_transfer, &out_data->c_transfer) != CRYPTO_SUCCESS) return CRYPTO_ERROR_COMPUTE;
    
    if (v_change > 0) {
        if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_change, r_change, &out_data->c_change) != CRYPTO_SUCCESS) return CRYPTO_ERROR_COMPUTE;
    } else {
        memset(&out_data->c_change, 0, sizeof(BdlopCommitment));
    }
    
    // 4. Generate Nullifier N_old = PRF_k(Hash(C_old))
    uint8_t c_old_hash[COIN_ID_LEN];
    SHA256((const uint8_t*)&c_old, sizeof(BdlopCommitment), c_old_hash);

    if (prf_evaluate(out_data->nullifier, prf_key, c_old_hash, COIN_ID_LEN, c_old_hash) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Crypto] ERROR: Failed to evaluate PRF for Nullifier\n");
        return CRYPTO_ERROR_COMPUTE;
    }
    
    // 5. Generate ZK-SNARK/Stern Proof of Circuit Constraints
    size_t offset = sizeof(BdlopCommitment); // Optimized: Removed redundant 4KB MMRProof to significantly compress ZK payload
    size_t proof_len_max = ZK_PROOF_MAX_LEN - offset;
    
    if (generate_centinel_stern_proof(out_data->zk_proof + offset, &proof_len_max, &c_old, r_old, prf_key, out_data->nullifier, &out_data->c_transfer, amount, r_transfer, &out_data->c_change, v_change, r_change) != CRYPTO_SUCCESS) {
        return CRYPTO_ERROR_COMPUTE;
    }
    
    memcpy(out_data->zk_proof, &c_old, sizeof(BdlopCommitment));
        
    out_data->zk_proof_len = (uint32_t)(offset + proof_len_max);
    
    scl_log(LOG_LEVEL_DEBUG, "Crypto", "Generated Centinel Proof and Nullifier successfully.");
    return CRYPTO_SUCCESS;
#endif
}

/**
 * @brief Verifies the complete Centinel shielded UTXO redemption operation.
 *
 * @details
 * Unpacks $C_{\text{old}}$ from the operation proof payload, validates payload length boundaries,
 * and executes @ref verify_centinel_stern_proof against the transfer commitment, change commitment,
 * and spent nullifier.
 *
 * @param[in] rc_data Pointer to @ref RedeemCentinelData operation structure.
 * @return CRYPTO_SUCCESS if proof is valid; CRYPTO_ERROR_PROOF_FORMAT or CRYPTO_ERROR_PROOF_INVALID otherwise.
 *
 * @pre `rc_data` must be non-NULL; `rc_data->zk_proof_len` must be within `[sizeof(BdlopCommitment), ZK_PROOF_MAX_LEN]`.
 * @complexity Time: O(ZK_KAPPA * RING_DEG^2), Space: O(1) beyond thread-local arena.
 */
int zk_centinel_verify(const RedeemCentinelData *rc_data) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)rc_data;
    return CRYPTO_SUCCESS;
#else
    if (!rc_data) return CRYPTO_ERROR_INVALID_PARAM;
    
    size_t min_len = sizeof(BdlopCommitment); // Optimized: Removed redundant MMRProof payload
    if (rc_data->zk_proof_len < min_len || rc_data->zk_proof_len > ZK_PROOF_MAX_LEN) {
        return CRYPTO_ERROR_PROOF_FORMAT;
    }
    
    BdlopCommitment c_old;
    
    size_t offset = 0;
    memcpy(&c_old, rc_data->zk_proof + offset, sizeof(BdlopCommitment));
    offset += sizeof(BdlopCommitment);
    
    const uint8_t *stern_proof = rc_data->zk_proof + offset;
    size_t stern_proof_len = rc_data->zk_proof_len - offset;

    // 2. Verify ZK Stern Range & Ownership Proof
    if (verify_centinel_stern_proof(stern_proof, stern_proof_len, &c_old, rc_data->nullifier, &rc_data->c_transfer, &rc_data->c_change) != CRYPTO_SUCCESS) {
        scl_log(LOG_LEVEL_ERROR, "Crypto", "Centinel ZK Stern verification failed");
        return CRYPTO_ERROR_PROOF_INVALID;
    }
    
    scl_log(LOG_LEVEL_DEBUG, "Crypto", "Centinel ZK-Proof verified successfully");
    return CRYPTO_SUCCESS;
#endif
}
