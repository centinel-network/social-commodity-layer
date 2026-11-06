/**
 * @file common/crypto/crypto.h
 * @brief Satocialist Protocol: Post-Quantum Cryptography, Lattice Primitives, and Zero-Knowledge Proof Interfaces
 *
 * @details
 * Declares the public cryptographic API for the Satocialist Cryptographic Ledger (SCL).
 * Spans post-quantum digital signatures (ML-DSA-87 / Dilithium5), key encapsulation mechanisms
 * (ML-KEM-512 / Kyber-512), negacyclic cyclotomic polynomial quotient ring arithmetic over
 * $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ ($q = 8,380,417$), Module-SIS pseudo-random function evaluation,
 * zero-knowledge Stern-style range/membership proofs, homomorphic BDLOP lattice commitments,
 * Joint-RSS distributed key generation (DKG), and threshold signing ceremonies.
 *
 * @section cryptographic_standards Standards Implemented
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA-87).
 * - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM-512).
 * - Aumasson & Bernstein (2012): SipHash-2-4 Pseudorandom Function for Anti-DoS Routing.
 * - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
 * - Bootle, Lyubashevsky, Seiler et al.: BDLOP Lattice Commitments over Cyclotomic Quotient Rings.
 * - Stern Zero-Knowledge Protocol: Extended to Module-SIS polynomial relations with 128-bit soundness ($\kappa = 219$).
 *
 * @section memory_concurrency Threading Model & Memory Scoping
 * - Functions are reentrant. Cryptographic scratch buffers allocate from a thread-local linear memory
 *   arena (`arena_alloc` / `arena_reset`) with a preallocated per-thread capacity (CRYPTO_ARENA_SIZE) to prevent heap churn.
 * - All secret key material must be page-locked in RAM via @ref scl_secure_lock and zeroized
 *   immediately post-execution using @ref explicit_bzero.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: POST-QUANTUM SIGNATURES (ML-DSA-87 / DILITHIUM5)                  */
/* ============================================================================ */

/**
 * @brief Generates an ML-DSA-87 (Dilithium5) signature keypair.
 *
 * @param[out] public_key 2,592-byte destination buffer receiving verification key.
 * @param[out] secret_key 4,864-byte destination buffer receiving private signing key.
 * @return 1 on success; 0 on failure.
 *
 * @pre `public_key` and `secret_key` must point to allocated, writable buffers.
 * @post `secret_key` should be page-locked via @ref scl_secure_lock.
 * @complexity Time: O(1), Space: O(1).
 */
int dilithium_generate_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * @brief Generates a detached ML-DSA-87 (Dilithium5) signature over a message.
 *
 * @param[in] msg Pointer to message byte stream.
 * @param[in] msg_len Message length in bytes.
 * @param[in] private_key 4,864-byte Dilithium5 private key.
 * @param[out] signature 4,595-byte destination buffer receiving signature.
 * @return 1 on success; 0 on signing failure.
 *
 * @complexity Time: O(msg_len + signing_time), Space: O(1).
 */
int dilithium_sign(const uint8_t *msg, size_t msg_len, const uint8_t *private_key, uint8_t *signature);

/**
 * @brief Verifies an ML-DSA-87 (Dilithium5) detached signature against a message and public key.
 *
 * @param[in] msg Pointer to message byte stream.
 * @param[in] msg_len Message length in bytes.
 * @param[in] signature 4,595-byte Dilithium5 signature.
 * @param[in] public_key 2,592-byte Dilithium5 public verification key.
 * @return 0 on success (signature is valid); -1 on verification failure.
 *
 * @complexity Time: O(msg_len + verify_time), Space: O(1).
 */
int dilithium_verify(const uint8_t *msg, size_t msg_len, const uint8_t *signature, const uint8_t *public_key);

/* ============================================================================ */
/* SECTION 2: POST-QUANTUM KEY ENCAPSULATION (ML-KEM-512 / KYBER-512)           */
/* ============================================================================ */

/**
 * @brief Generates an ML-KEM-512 (Kyber-512) keypair.
 *
 * @param[out] public_key 800-byte destination buffer receiving public key.
 * @param[out] secret_key 1,632-byte destination buffer receiving secret decapsulation key.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int kyber_generate_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * @brief Encapsulates a random 32-byte shared secret against an ML-KEM-512 public key.
 *
 * @param[in] public_key 800-byte Kyber-512 public key.
 * @param[out] ciphertext 768-byte destination buffer receiving ciphertext envelope.
 * @param[out] shared_secret 32-byte destination buffer receiving symmetric shared secret.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int kyber_encapsulate(const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret);

/**
 * @brief Decapsulates a 32-byte shared secret from an ML-KEM-512 ciphertext.
 *
 * @param[in] ciphertext 768-byte Kyber-512 ciphertext envelope.
 * @param[in] secret_key 1,632-byte Kyber-512 secret key.
 * @param[out] shared_secret 32-byte destination buffer receiving recovered shared secret.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int kyber_decapsulate(const uint8_t *ciphertext, const uint8_t *secret_key, uint8_t *shared_secret);

/**
 * @brief Generates an ephemeral Kyber-512 keypair for 1-RTT forward-secret transport handshakes.
 *
 * @param[out] pubkey 800-byte public key buffer.
 * @param[out] privkey 1,632-byte private key buffer.
 * @return 1 on success; 0 on failure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int generate_ephemeral_kyber_keypair(uint8_t *pubkey, uint8_t *privkey);

/* ============================================================================ */
/* SECTION 3: SYMMETRIC CIPHERS, AEAD & KEY DERIVATION                          */
/* ============================================================================ */

/**
 * @brief Derives a 256-bit AES symmetric key from a KEM shared secret via HKDF-SHA256.
 *
 * @param[in] shared_secret 32-byte Kyber-512 shared secret.
 * @param[out] aes_key 32-byte buffer receiving derived AES-256 key.
 * @return 0 on success; -1 on error.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int derive_symmetric_keys(const uint8_t *shared_secret, uint8_t *aes_key);

/**
 * @brief Derives a 128-bit SipHash-2-4 key from a KEM shared secret via HKDF-SHA256.
 *
 * @param[in] shared_secret 32-byte Kyber-512 shared secret.
 * @param[out] out_key 16-byte buffer receiving derived SipHash key.
 * @return 0 on success; -1 on error.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int derive_rpc_siphash_key(const uint8_t *shared_secret, uint8_t *out_key);

/**
 * @brief Encrypts and authenticates a payload using AES-256-GCM with explicit random IV.
 *
 * @param[in] aes_key 32-byte AES key.
 * @param[in] plaintext Input plaintext buffer.
 * @param[in] plaintext_len Plaintext length in bytes.
 * @param[out] ciphertext Output buffer: `IV (12B) || Ciphertext || Tag (16B)`.
 * @param[out] ciphertext_len Destination receiving total encrypted length (`plaintext_len + 28`).
 * @return 0 on success; -1 on error.
 *
 * @complexity Time: O(plaintext_len), Space: O(1).
 */
int encrypt_message(const uint8_t *aes_key, const uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * @brief Decrypts and verifies an AES-256-GCM payload with explicit IV.
 *
 * @param[in] aes_key 32-byte AES key.
 * @param[in] ciphertext Input ciphertext buffer: `IV (12B) || Ciphertext || Tag (16B)`.
 * @param[in] ciphertext_len Total ciphertext length in bytes.
 * @param[out] plaintext Output buffer receiving recovered plaintext.
 * @param[out] plaintext_len Destination receiving recovered plaintext byte length.
 * @return 0 on success; -1 on authentication tag failure.
 *
 * @complexity Time: O(ciphertext_len), Space: O(1).
 */
int decrypt_message(const uint8_t *aes_key, const uint8_t *ciphertext, size_t ciphertext_len,
                    uint8_t *plaintext, size_t *plaintext_len);

/**
 * @brief Derives an application-specific subkey from a master secret via labeled HKDF-SHA256.
 *
 * @param[in] shared_secret Master input keying material (32-byte Kyber-512 shared secret).
 * @param[in] label ASCII domain-separation label string.
 * @param[out] out_key Destination buffer receiving derived key.
 * @param[in] out_len Required output key length in bytes.
 * @return 0 on success; -1 on error.
 *
 * @complexity Time: O(1), Space: O(1).
 */
int derive_labeled_key(const uint8_t *shared_secret, const char *label, uint8_t *out_key, size_t out_len);

/**
 * @brief Encapsulates an application payload in an authenticated AEAD packet with implicit nonce.
 *
 * @details
 * Formulates the 12-byte GCM IV from 4 bytes of static zero padding and the 8-byte big-endian
 * `packet_num`. Appends a 16-byte authentication tag to the output.
 *
 * @param[in] aes_key 32-byte AES key.
 * @param[in] packet_num 64-bit packet sequence number (used as nonce).
 * @param[in] plaintext Payload bytes.
 * @param[in] plaintext_len Payload length in bytes.
 * @param[out] ciphertext Output buffer: `Ciphertext || Tag (16B)`.
 * @param[out] ciphertext_len Destination receiving total length (`plaintext_len + 16`).
 * @return 0 on success; -1 on error.
 *
 * @complexity Time: O(plaintext_len), Space: O(1).
 */
int encrypt_aead_packet(const uint8_t *aes_key, uint64_t packet_num, const uint8_t *plaintext,
                        size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len,
                        const uint8_t *aad, size_t aad_len);

/**
 * @brief Decrypts an authenticated AEAD packet using an implicit packet-number nonce.
 *
 * @param[in] aes_key 32-byte AES key.
 * @param[in] packet_num 64-bit packet sequence number.
 * @param[in] ciphertext Input buffer: `Ciphertext || Tag (16B)`.
 * @param[in] ciphertext_len Total length in bytes.
 * @param[out] plaintext Output buffer receiving decrypted bytes.
 * @param[out] plaintext_len Destination receiving plaintext byte count.
 * @return 0 on success; -1 on tag mismatch.
 *
 * @complexity Time: O(ciphertext_len), Space: O(1).
 */
int decrypt_aead_packet(const uint8_t *aes_key, uint64_t packet_num, const uint8_t *ciphertext,
                        size_t ciphertext_len, uint8_t *plaintext, size_t *plaintext_len,
                        const uint8_t *aad, size_t aad_len);

/**
 * @brief Evaluates 64-bit SipHash-2-4 over an input byte slice.
 *
 * @param[in] in Input byte buffer.
 * @param[in] inlen Input length in bytes.
 * @param[in] key 16-byte SipHash key.
 * @return 64-bit unsigned SipHash digest.
 *
 * @complexity Time: O(inlen), Space: O(1).
 */
uint64_t siphash24(const uint8_t *in, size_t inlen, const uint8_t key[16]);

/* ============================================================================ */
/* SECTION 4: WALLET MANAGEMENT & MEMORY LOCKING                                */
/* ============================================================================ */

/** @brief Generates a PeerWallet structure holding post-quantum keypairs. */
int create_peer_wallet(PeerWallet *pw);
/** @brief Generates a UserWallet structure holding master Dilithium and PRF keys. */
int create_user_wallet(UserWallet *uw);
/** @brief Serializes and writes a UserWallet to disk with restricted permissions (0600). */
int save_user_wallet(const UserWallet *uw, const char *filepath);
/** @brief Deserializes a UserWallet from disk, restoring page-locked memory protections. */
int load_user_wallet(UserWallet *uw, const char *filepath);

/** @brief Pins memory in physical RAM via platform-specific mlock/VirtualLock calls. */
int scl_secure_lock(void *addr, size_t len);
/** @brief Unpins memory from physical RAM via munlock/VirtualUnlock. */
int scl_secure_unlock(void *addr, size_t len);

/* ============================================================================ */
/* SECTION 5: CYCLOTOMIC POLYNOMIAL RING ARITHMETIC ($R_q$)                    */
/* ============================================================================ */

/** @brief Verifies that polynomial vector coefficients do not exceed centered bound $Q/2$. */
void check_polyvec_bounds(const polyvec_t *v, const char *context);

/**
 * @brief Multiplies two polynomials in $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ via negacyclic convolution.
 *
 * @param[out] r Result polynomial: $a \cdot b \pmod{X^{256} + 1, q}$.
 * @param[in] a First factor polynomial.
 * @param[in] b Second factor polynomial.
 *
 * @complexity Time: O(N^2) where N=256, Space: O(1) stack buffers.
 */
void poly_mul(poly_t *r, const poly_t *a, const poly_t *b);

/**
 * @brief Negacyclic polynomial multiplication optimized for sparse polynomials (e.g., challenge $c$).
 *
 * @param[out] r Result polynomial.
 * @param[in] a Dense polynomial.
 * @param[in] c Sparse polynomial with coefficients in $\{-1, 0, 1\}$.
 *
 * @complexity Time: O(N \cdot \text{Hamming}(c)), Space: O(1).
 */
void poly_mul_sparse(poly_t *r, const poly_t *a, const poly_t *c);

/** @brief Adds two polynomials with modular reduction modulo $Q$: $r = a + b \pmod Q$. */
void poly_add(poly_t *r, const poly_t *a, const poly_t *b);

/** @brief Adds two polynomial vectors element-wise with modular reduction modulo $Q$. */
void polyvec_add(polyvec_t *r, const polyvec_t *a, const polyvec_t *b);

/** @brief Adds two polynomial vectors element-wise without modular reduction. */
void polyvec_add_no_reduce(polyvec_t *r, const polyvec_t *a, const polyvec_t *b);

/** @brief Copies contents of polynomial vector `src` into `dst`. */
void polyvec_copy(polyvec_t *dst, const polyvec_t *src);

/** @brief Multiplies public matrix $\bar{A}$ by polynomial vector $v$ ($r = \bar{A} \cdot v \pmod Q$). */
void a_mul_vec(polyvec_t *r, const matrix_t *A_bar, const polyvec_t *v);

/** @brief Extracts high-bits vector $r_1$ from polynomial vector $a$ using decomposition factor $\alpha$. */
void polyvec_high_bits(polyvec_t *r, const polyvec_t *a, int32_t alpha);

/** @brief Subtracts two 64-bit unreduced polynomial vectors: $r = a - b$. */
void polyvec64_sub(polyvec64_t *r, const polyvec64_t *a, const polyvec64_t *b);

/** @brief Multiplies matrix by polynomial vector with modular reduction modulo $Q$. */
int matrix_vec_mul(polyvec_t *r, const matrix_t *mat, const polyvec_t *v);

/** @brief Multiplies matrix by polynomial vector producing unreduced 64-bit products. */
void matrix_vec_mul_unreduced(polyvec64_t *r, const matrix_t *mat, const polyvec_t *v);

/** @brief Verifies that the infinity norm of a polynomial vector satisfies $\|v\|_\infty \le \text{bound}$. */
int check_norm_inf(const polyvec_t *v, int32_t bound);

/** @brief Returns maximum absolute coefficient value within a polynomial in constant time. */
int32_t poly_max_coeff(const poly_t *p);

/** @brief Returns maximum absolute coefficient value across an entire polynomial vector in constant time. */
int32_t polyvec_max_coeff(const polyvec_t *v);

/** @brief Multiplies polynomial vector by a polynomial without modular reduction into 64-bit registers. */
void polyvec_poly_mul_unreduced(polyvec64_t *r, const polyvec_t *a, const poly_t *p);

/** @brief Sets all coefficients of a polynomial vector to zero. */
void polyvec_clear(polyvec_t *v);

/** @brief Reduces 64-bit unreduced polynomial vector into standard centered range $[-Q/2, Q/2]$. */
void polyvec64_reduce(polyvec_t *r, const polyvec64_t *a);

/** @brief Promotes 32-bit polynomial vector into 64-bit unreduced vector structure. */
void polyvec_to64(polyvec64_t *dst, const polyvec_t *src);

/** @brief Reduces 32-bit polynomial vector coefficients in-place into centered range $[-Q/2, Q/2]$. */
void polyvec_reduce(polyvec_t *v);

/** @brief Adds two 64-bit unreduced polynomial vectors element-wise: $r = a + b$. */
void polyvec64_add(polyvec64_t *r, const polyvec64_t *a, const polyvec64_t *b);

/** @brief Verifies infinity norm of a 64-bit unreduced polynomial vector against an integer bound. */
int check_norm_inf64(const polyvec64_t *v, int64_t bound);

/* ============================================================================ */
/* SECTION 6: PACKING, UNPACKING & COEFFICIENT SAMPLING                         */
/* ============================================================================ */

/** @brief Bit-packs high-bits polynomial $w_1$ into compact 4-bit representation. */
void polyw1_pack(uint8_t *dst, const poly_t *p);

/** @brief Bit-unpacks high-bits polynomial $t_1$ from compact 10-bit format. */
void poly_t1_unpack(poly_t *p, const uint8_t *src);

/** @brief Generates hint polynomial vector $h$ correcting decomposition discrepancies. */
void polyvec_make_hint(polyvec_t *h, const polyvec_t *r, const polyvec_t *w, int32_t alpha);

/** @brief Unpacks hint vector $h$ from compact byte representation. */
void unpack_h(polyvec_t *h, const uint8_t *src);

/** @brief Counts non-zero coefficients within a single polynomial. */
int count_nonzero(const poly_t *h);

/** @brief Counts total non-zero coefficients across an entire polynomial vector. */
int count_nonzero_vec(const polyvec_t *v);

/** @brief Packs complete threshold signature $(c, z, h)$ into serialized byte array. */
crypto_error_t pack_signature(uint8_t *sig, const polyvec_t *z, const polyvec_t *h, const uint8_t *c, size_t *sig_len);

/** @brief Samples polynomial coefficients uniformly in range $[-\eta, \eta]$ via SHAKE-256 XOF. */
crypto_error_t poly_uniform_eta(poly_t *p, const uint8_t *seed, size_t seed_len, uint16_t nonce);

/** @brief Samples challenge polynomial $c$ with Hamming weight $\tau = 60$ in $\{-1, 1\}$. */
crypto_error_t sample_in_ball(poly_t *c, const uint8_t *seed, size_t seed_len);

/** @brief Expands public matrix $\bar{A} \in R_q^{K \times L}$ from seed $\rho$ via SHAKE-256 XOF. */
crypto_error_t expand_a(matrix_t *A_bar, const uint8_t *rho);

/** @brief Expands public BDLOP commitment parameters $(a, b)$ from seed $\rho$. */
crypto_error_t bdlop_expand_parameters(const uint8_t *rho, poly_t *a_out, poly_t *b_out);

/**
 * @brief Evaluates a homomorphic BDLOP lattice commitment concealing scalar $v$.
 *
 * @details
 * Decomposes $v$ across 21-bit polynomial limbs $v(X) = v_0 + v_1 X + v_2 X^2 + v_3 X^3$.
 * Samples noise polynomials $(s, e_1, e_2)$ from $[-\eta, \eta]$ and evaluates:
 * $$c_1 = a \cdot s + e_1, \quad c_2 = b \cdot s + e_2 + v(X)$$
 *
 * @param[in] rho 32-byte public parameter expansion seed.
 * @param[in] v Scalar value to commit.
 * @param[in] r 32-byte blinding factor generating noise polynomials.
 * @param[out] commitment_out Destination structure receiving $c_1$ and $c_2$.
 * @return CRYPTO_SUCCESS on success.
 *
 * @complexity Time: O(1), Space: O(1).
 */
crypto_error_t bdlop_commit(const uint8_t *rho, uint64_t v, const uint8_t *r, BdlopCommitment *commitment_out);

/** @brief Adds two BDLOP commitments homomorphically: $out = c_1 + c_2 \pmod Q$. */
crypto_error_t bdlop_add(const BdlopCommitment *c1, const BdlopCommitment *c2, BdlopCommitment *out);

/**
 * @brief Decrypts a BDLOP commitment using the secret blinding factor $r$.
 *
 * @param[in] rho 32-byte public expansion seed.
 * @param[in] commitment BDLOP commitment to decrypt.
 * @param[in] r 32-byte blinding factor.
 * @param[out] v_out Destination receiving recovered scalar value.
 * @return CRYPTO_SUCCESS on success; CRYPTO_ERROR_PROOF_INVALID if limbs are out of bounds.
 *
 * @complexity Time: O(1), Space: O(1).
 */
crypto_error_t bdlop_decrypt(const uint8_t *rho, const BdlopCommitment *commitment, const uint8_t *r, uint64_t *v_out);

/** @brief Samples polynomial coefficients uniformly in range $[-\text{bound}, \text{bound}]$. */
crypto_error_t poly_uniform_with_bound(poly_t *p, const uint8_t *seed, size_t seed_len, uint16_t nonce, int32_t bound);

/** @brief Generates masking polynomial vector $y$ bounded by $[-bound, bound]$ for signing. */
crypto_error_t generate_y_with_nonce(polyvec_t *y, const uint8_t *seed, size_t seed_len, uint16_t nonce, int32_t bound);

/** @brief Decomposes coefficient $a = r_1 \cdot \alpha + r_0 \pmod Q$ with centered remainder. */
void decompose(int32_t a, int32_t alpha, int32_t *r0_out, int32_t *r1_out);

/* ============================================================================ */
/* SECTION 7: LINEAR MEMORY ARENA & POLYNOMIAL ALLOCATION                       */
/* ============================================================================ */

/** @brief Allocates aligned memory from thread-local linear scratch arena. */
void *arena_alloc(size_t size);
/** @brief Captures current linear offset marker within thread-local arena. */
size_t arena_mark(void);
/** @brief Resets linear allocation cursor back to previously captured marker. */
void arena_reset(size_t mark);
/** @brief Deallocates thread-local arena backing memory entirely. */
void arena_cleanup(void);

/** @brief Allocates dynamic polynomial vector on heap. */
crypto_error_t polyvec_init(polyvec_t *v, size_t len);
/** @brief Allocates 64-bit unreduced polynomial vector on heap. */
crypto_error_t polyvec64_init(polyvec64_t *v, size_t len);
/** @brief Allocates polynomial vector within thread-local arena (zero heap churn). */
crypto_error_t polyvec_init_arena(polyvec_t *v, size_t len);
/** @brief Allocates 64-bit unreduced polynomial vector within thread-local arena. */
crypto_error_t polyvec64_init_arena(polyvec64_t *v, size_t len);
/** @brief Deallocates polynomial vector from heap. */
void polyvec_free(polyvec_t *v);
/** @brief Deallocates 64-bit polynomial vector from heap. */
void polyvec64_free(polyvec64_t *v);
/** @brief Serializes polynomial vector into contiguous unreduced byte array. */
crypto_error_t polyvec_serialize(const polyvec_t *v, uint8_t *buf, size_t buf_len, size_t *serialized_len);

/* ============================================================================ */
/* SECTION 8: THRESHOLD CRYPTOGRAPHY & DISTRIBUTED KEY GENERATION (DKG)         */
/* ============================================================================ */

/** @brief Generates deterministic RFC 6979-style signing nonce via HMAC-SHA256. */
void generate_deterministic_nonce(const uint8_t *privkey, size_t privkey_len, const uint8_t *msg, size_t msg_len, uint8_t *nonce_out);

/** @brief Generates Joint-RSS threshold key shares for an $(n, t)$ committee baseline. */
crypto_error_t threshold_keygen(State *state, ThresholdKeygenData *data, const uint8_t *seed, size_t seed_len, uint16_t *point_ids, int n, int t);

/** @brief Evaluates global matrix seed $\rho$ from gathered committee reveals in DKG Round 2. */
crypto_error_t dkg_compute_global_rho(DKGSession *session);

/** @brief Evaluates local dealer polynomial shares and public commitment fragment in DKG Round 3. */
crypto_error_t threshold_keygen_local_dealer(State *state, DKGSession *session);

/** @brief Verifies inbound subset shares and derives global public key in DKG Round 4. */
crypto_error_t dkg_verify_and_assemble_keys(State *state, DKGSession *session);

/** @brief Generates partial signature commitment $w_i = \bar{A} \cdot y_i$ and samples masking vector $y_i$. */
crypto_error_t threshold_sign(State *state, ThresholdSignData *data, const uint8_t *msg, size_t msg_len,
                             const uint8_t *seed, size_t seed_len, const uint8_t *rho, const polyvec_t *s1_shares, const polyvec_t *s2_shares,
                             uint16_t id, uint16_t *point_ids, uint16_t *sign_ids, int n, int t, int32_t bound_y);

/** @brief Verifies an aggregated threshold Dilithium signature against a message and public key. */
crypto_error_t threshold_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len,
                                const uint8_t *pk, size_t pk_len);

/** @brief Deallocates all dynamic polynomial vectors in a ThresholdKeygenData context. */
void cleanup_keygen_data(ThresholdKeygenData *data);
/** @brief Deallocates all dynamic polynomial vectors in a ThresholdSignData context. */
void cleanup_sign_data(ThresholdSignData *data);
/** @brief Decrements DKGSession reference counter, releasing memory when counter reaches zero. */
void dkg_session_release(DKGSession *session);
/** @brief Type-erased cleanup callback freeing a DKGSession structure. */
void free_dkg_session(void *data);
/** @brief Releases dynamic memory and joins collector thread for a ThresholdStakeProcess. */
void free_threshold_process(void *data);
/** @brief Queries or allocates an active ThresholdStakeProcess context by transaction ID. */
ThresholdStakeProcess* get_or_create_threshold_process(State *state, const uint8_t stake_tx_id[COIN_ID_LEN]);
/** @brief Queries an existing ThresholdStakeProcess by transaction ID. */
ThresholdStakeProcess* find_threshold_process(State *state, const uint8_t stake_tx_id[COIN_ID_LEN]);
/** @brief Removes and finalizes a ThresholdStakeProcess context. */
void remove_threshold_process(State *state, const uint8_t stake_tx_id[COIN_ID_LEN]);
/** @brief Destroys all active threshold processes upon daemon shutdown. */
void cleanup_all_threshold_processes(State *state);
/** @brief Asynchronous thread entrypoint collecting partial threshold signatures from peers. */
void *partial_collector_thread(void *arg);

/* ============================================================================ */
/* SECTION 9: MODULE-SIS PRF & ZERO-KNOWLEDGE PROOF ENGINES                     */
/* ============================================================================ */

/**
 * @brief Evaluates the Module-SIS PRF nullifier: $y = \text{LowBits}_p(A \cdot s) \pmod Q$.
 *
 * @param[out] y 32-byte destination receiving nullifier output.
 * @param[in] key Pointer to secret PRFKey structure ($k \in \{-1, 0, 1\}^{1024}$).
 * @param[in] J Transaction identifier input buffer.
 * @param[in] J_len Length of input buffer.
 * @param[in] seed Public matrix expansion seed.
 * @return CRYPTO_SUCCESS on success.
 *
 * @complexity Time: O(1), Space: O(1).
 */
crypto_error_t prf_evaluate(uint8_t *y, const PRFKey *key, const uint8_t *J, size_t J_len, const uint8_t *seed);

/**
 * @brief Generates a zero-knowledge Stern proof of PRF evaluation knowledge.
 *
 * @details
 * Proves knowledge of secret ternary vector $k$ with Hamming weight 250 satisfying $y = \text{LowBits}_p(A \cdot k)$
 * across $\kappa = 219$ challenge repetitions to achieve 128-bit sound zero-knowledge guarantees.
 *
 * @param[out] proof Destination buffer receiving serialized proof bytes.
 * @param[in,out] proof_len Destination receiving total proof length in bytes.
 * @param[in] prf_input Transaction ID input $J$.
 * @param[in] input_len Byte length of $J$.
 * @param[in] prf_key Secret ternary key vector $k$.
 * @param[in] key_len Byte length of key vector.
 * @param[in] seed Matrix expansion seed.
 * @return CRYPTO_SUCCESS on success.
 *
 * @complexity Time: O(ZK_KAPPA), Space: O(ZK_PROOF_MAX_LEN).
 */
crypto_error_t generate_zk_prf_proof(uint8_t *proof, size_t *proof_len, const uint8_t *prf_input, size_t input_len, const uint8_t *prf_key, size_t key_len, const uint8_t *seed);

/**
 * @brief Verifies a zero-knowledge Stern proof of PRF evaluation knowledge.
 *
 * @param[in] proof Serialized proof byte slice.
 * @param[in] proof_len Byte length of proof.
 * @param[in] seed Matrix expansion seed.
 * @param[in] prf_input Transaction ID input $J$.
 * @param[in] input_len Byte length of $J$.
 * @param[in] y 32-byte nullifier output being verified.
 * @return CRYPTO_SUCCESS on successful verification; error code on rejection.
 *
 * @complexity Time: O(ZK_KAPPA), Space: O(1) arena buffers.
 */
int zk_prf_verify(const uint8_t *proof, size_t proof_len,
                  const uint8_t *seed, const uint8_t *prf_input, size_t input_len, const uint8_t *y);

/** @brief Verifies all aggregated ZK-PRF proofs enclosed within a proposed block. */
int zk_batch_prf_verify(const Block *block);

/** @brief Generates a sparse ternary PRF secret key with fixed Hamming weight 250 from a seed. */
crypto_error_t prf_keygen(PRFKey *key, const uint8_t *seed, size_t seed_len);

/* ============================================================================ */
/* SECTION 10: CENTINEL SHIELDED UTXO ZK PROTOCOL                               */
/* ============================================================================ */

/**
 * @brief Generates a complete Centinel shielded UTXO redemption zero-knowledge proof.
 *
 * @details
 * Proves in zero knowledge that:
 * 1. The prover knows the secret key and blinding factor for commitment $C_{old}$.
 * 2. $V_{old} = \text{amount} + V_{change}$ (monetary balance conservation).
 * 3. $N_{old} = \text{PRF}_k(\text{Hash}(C_{old}))$ (correct nullifier derivation).
 * 4. $C_{transfer}$ and $C_{change}$ are well-formed BDLOP commitments.
 *
 * @param[in] pk_old Owner public key of input commitment.
 * @param[in] v_old Total balance of input commitment.
 * @param[in] r_old Blinding factor of input commitment.
 * @param[in] pk_transfer Destination public key.
 * @param[in] amount Volume transferred to destination.
 * @param[in] r_transfer Blinding factor for destination commitment.
 * @param[in] pk_change Public key receiving change output.
 * @param[in] v_change Balance allocated to change output.
 * @param[in] r_change Blinding factor for change commitment.
 * @param[in] prf_key Secret PRF key for nullifier generation.
 * @param[in] root Active MMR state root commitment.
 * @param[in] path MMR inclusion proof for $C_{old}$.
 * @param[out] out_data Populated RedeemCentinelData structure receiving nullifier, commitments, and proof.
 * @return CRYPTO_SUCCESS on success.
 *
 * @complexity Time: O(ZK_KAPPA), Space: O(ZK_PROOF_MAX_LEN).
 */
crypto_error_t generate_centinel_proof(
    const uint8_t *pk_old, uint64_t v_old, const uint8_t *r_old,
    const uint8_t *pk_transfer, uint64_t amount, const uint8_t *r_transfer,
    const uint8_t *pk_change, uint64_t v_change, const uint8_t *r_change,
    const PRFKey *prf_key, const uint8_t *root,
    const MMRProof *path, RedeemCentinelData *out_data
);

/**
 * @brief Verifies the validity of a Centinel zero-knowledge redemption proof.
 *
 * @param[in] rc_data Pointer to RedeemCentinelData structure.
 * @return CRYPTO_SUCCESS on success; error code on rejection.
 *
 * @complexity Time: O(ZK_KAPPA), Space: O(1) arena buffers.
 */
int zk_centinel_verify(const RedeemCentinelData *rc_data);

/** @brief Top-level validator verifying heavy zero-knowledge proofs for an individual operation. */
int verify_operation_heavy_crypto(const Operation *op);

/** @brief Top-level validator verifying heavy batch zero-knowledge proofs for an entire block. */
int verify_block_heavy_crypto(const Block *block);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_H
