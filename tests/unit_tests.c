/**
 * @file tests/unit_tests.c
 * @module tests/unit_tests - Core Unit & Integration Verification Suite
 *
 * @brief Comprehensive integration and unit test harness verifying core cryptographic
 *        primitives, data structures, state accumulators, transaction fee models,
 *        consensus lifecycles, and WebAssembly FFI bridge interfaces.
 *
 * @details
 * Validates algorithmic correctness and mathematical invariants across five critical subsystems:
 *
 * 1. Lock-Free Hash Table (`hash_table.c`):
 *    - Bucket allocation, concurrent lookups, incremental migration, load-factor (0.7) threshold resizing.
 *    - Session cleanup and resource destruction hooks across diverse entry types (`HASH_ENTRY_TX`,
 *      `HASH_ENTRY_DKG_SESSION`, `HASH_ENTRY_THRESHOLD_STAKE_PROCESS`).
 *
 * 2. Merkle Mountain Range Accumulator (`mmr.c`):
 *    - Leaf insertion and dynamic peak merging conforming to binary popcount invariants.
 *    - Audit path generation, peak aggregation, and cryptographic inclusion proof verification.
 *
 * 3. Post-Quantum Lattice Cryptography (`crypto.c`):
 *    - ML-DSA-87 (Dilithium5) keypair generation and secure virtual page locking (`mlock`/`munlock`).
 *    - Rejection-bounded polynomial uniform sampling, sparse polynomial multiplication in R_q,
 *      and high/low bit decomposition math.
 *    - Module-SIS Zero-Knowledge PRF proofs (Stern-type framework) and BDLOP homomorphic commitments.
 *
 * 4. Consensus Utilities & Fee Schedule (`utils.c`):
 *    - Non-linear transaction fee calculation, validating halved fees for validator staking/unstaking.
 *    - Canonical block serialization determinism and byte-invariant SHA-256 block hashing.
 *
 * 5. Integrated Ledger State Machine & WASM Bridge Workflows:
 *    - Complete block lifecycle: UTXO creation, pointer generation, transaction signing,
 *      heavy cryptographic verification (`verify_block_heavy_crypto`), and ledger state commit (`apply_block`).
 *    - Proof-of-Symmetry reward minting and audit state anchor integrity.
 *    - Native autopilot worker loop execution and WebAssembly FFI binary RPC builder/parser framing.
 *
 * @invariants
 * - Peak Invariant: For any MMR with N leaves, the number of active peaks equals popcount(N).
 * - Modulus Invariant: Polynomial ring operations strictly preserve coefficients in [-(Q-1)/2, (Q-1)/2].
 * - Decomposition Invariant: For all inputs a and alpha, (r1 * alpha + r0) mod Q == a mod Q.
 * - Fee Ratio Invariant: For all amounts > 100, calculate_fee(amount, false) / calculate_fee(amount, true) in [1.9, 2.1].
 *
 * @standards
 * - NIST FIPS 204: ML-DSA (Module-Lattice-Based Digital Signatures).
 * - NIST FIPS 203: ML-KEM (Module-Lattice-Based Key Encapsulation).
 * - RFC 7693: SipHash-2-4 checksum integrity.
 * - LZ4 Streaming and Block Compression Specification.
 *
 * @dependencies
 * - OpenSSL `libcrypto` (SHA-256, RAND).
 * - `liblz4` compression library.
 * - POSIX Threads (`pthread`).
 * - Core headers: `constants.h`, `types.h`, `utils.h`, `blockchain.h`, `game_state.h`, `crypto.h`,
 *   `protocol.h`, `hash_table.h`, `mmr.h`, `user.h`, `consensus.h`, `client_state.h`, `scl_rpc_ffi_export.h`.
 *
 * @threading
 * - Tests execute sequentially in the primary test thread.
 * - Internal routines test and enforce reader-writer lock acquisition (`rwlock`) and condition variable lifecycle.
 *
 * @memory_model
 * - Dynamic data structures (hash tables, MMR trees, blocks, transactions) are allocated on the heap
 *   and explicitly torn down within individual test scopes to guarantee zero leak propagation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <lz4.h>

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
/* SECTION 0: TEST RUNNER & ASSERTION CONTROL MACROS                            */
/* ============================================================================ */
/**
 * @def RUN_TEST(test_func)
 * @brief Executes a test function, printing standard execution progress banners.
 */
#define RUN_TEST(test_func) \
    do { \
        printf("[RUN] %s\n", #test_func); \
        test_func(); \
        printf("[PASS] %s\n\n", #test_func); \
    } while (0)

/**
 * @def ASSERT_TRUE(cond, msg)
 * @brief Evaluates a condition; on failure, prints source location and terminates via exit(1).
 */
#define ASSERT_TRUE(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] Assertion failed: %s (%s) at %s:%d\n", #cond, msg, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

/**
 * @def ASSERT_EQUAL_INT(val, expected, msg)
 * @brief Verifies that signed integer `val` strictly matches `expected`.
 */
#define ASSERT_EQUAL_INT(val, expected, msg) \
    do { \
        if ((val) != (expected)) { \
            fprintf(stderr, "[FAIL] Assertion failed: %s (got %lld, expected %lld) (%s) at %s:%d\n", #val, (long long)(val), (long long)(expected), msg, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

/* ============================================================================ */
/* SECTION 1.1: INCREMENTAL LOCK-FREE HASH TABLE TESTS (`hash_table.c`)         */
/* ============================================================================ */
/**
 * @brief Verifies initial allocation, default sizing, and zeroed state of `HashTable`.
 *
 * @pre Heap memory available.
 * @post Allocates, verifies structural invariants, and cleanly destroys a 4096-bucket hash table.
 *
 * @complexity
 * - Time: O(B) where B = 4096 buckets initialized.
 * - Space: O(B * sizeof(HashBucket)) heap memory.
 */
static void test_hash_table_init(void) {
    HashTable *ht = malloc(sizeof(HashTable));
    ASSERT_TRUE(ht != NULL, "Failed to allocate HashTable");

    int res = hash_table_init(ht, 4096, 32, NULL, NULL, NULL, NULL);
    ASSERT_EQUAL_INT(res, 0, "hash_table_init returned failure");
    ASSERT_TRUE(ht->buckets != NULL, "Buckets array should not be NULL");
    ASSERT_TRUE(ht->old_buckets == NULL, "old_buckets should be NULL initially");
    ASSERT_EQUAL_INT(ht->size, 4096, "Initial size should be 4096");
    ASSERT_EQUAL_INT(ht->count, 0, "Initial count should be 0");
    ASSERT_EQUAL_INT(ht->key_len, 32, "Initial key_len should be 32");

    hash_table_destroy(ht);
    free(ht);
}

/**
 * @brief Tests sequential insertion triggering automated load-factor resizing.
 *
 * @details
 * Inserts 500 keys into a hash table initialized with 128 buckets. With a load
 * factor threshold of 0.70 (resize occurs at count > 0.70 * size), this forces
 * multiple table doublings (128 -> 256 -> 512 -> 1024). Verifies that all 500
 * keys remain resolvable post-expansion.
 *
 * @pre None.
 * @post Table expands cleanly without dropped keys.
 *
 * @complexity
 * - Time: O(N) amortized across N=500 insertions.
 * - Space: O(N) heap memory.
 */
static void test_hash_table_insert_resize(void) {
    HashTable *ht = malloc(sizeof(HashTable));
    ASSERT_TRUE(ht != NULL, "Failed to allocate HashTable");
    int res = hash_table_init(ht, 128, 32, NULL, NULL, NULL, NULL);
    ASSERT_EQUAL_INT(res, 0, "hash_table_init failed");

    /* Insert 500 unique 32-byte keys sequentially to force table doubling */
    uint8_t keys[500][32];
    for (int i = 0; i < 500; i++) {
        memset(keys[i], 0, 32);
        memcpy(keys[i], &i, sizeof(int));
        bool inserted = hash_table_insert(ht, keys[i], NULL, HASH_ENTRY_TX);
        ASSERT_TRUE(inserted, "Failed to insert key");
    }

    ASSERT_EQUAL_INT(ht->count, 500, "Table count should be 500");

    /* Confirm full key retrievability post-resizing */
    for (int i = 0; i < 500; i++) {
        void *found = hash_table_lookup(ht, keys[i], true);
        ASSERT_TRUE(found != NULL, "Inserted key should be found");
    }

    hash_table_destroy(ht);
    free(ht);
}

/**
 * @brief Validates dual-bucket search semantics during active incremental migration.
 *
 * @details
 * Seeds the table to 44 items (44 / 64 = 0.6875 < 0.70 load factor). Inserts the 45th
 * item (45 / 64 = 0.7031 > 0.70), triggering active incremental migration where
 * `old_buckets` is non-NULL. Tests that lookups correctly traverse both old and new
 * bucket arrays during active migration.
 *
 * @pre None.
 * @post Destroys hash table and releases all allocated memory.
 *
 * @complexity
 * - Time: O(N) where N = 45.
 * - Space: O(1) auxiliary.
 */
static void test_hash_table_migration_lookup(void) {
    HashTable *ht = malloc(sizeof(HashTable));
    ASSERT_TRUE(ht != NULL, "Failed to allocate HashTable");
    int res = hash_table_init(ht, 64, 32, NULL, NULL, NULL, NULL);
    ASSERT_EQUAL_INT(res, 0, "hash_table_init failed");

    /* Insert 44 items (44 / 64 = 0.6875, below 0.7 load factor threshold) */
    uint8_t keys[100][32];
    for (int i = 0; i < 44; i++) {
        memset(keys[i], 0, 32);
        memcpy(keys[i], &i, sizeof(int));
        hash_table_insert(ht, keys[i], NULL, HASH_ENTRY_TX);
    }
    ASSERT_TRUE(ht->old_buckets == NULL, "old_buckets should remain NULL before threshold is crossed");

    /* Insert the 45th item to trip the 0.70 threshold (45 / 64 = 0.7031) */
    memset(keys[44], 0, 32);
    int val = 44;
    memcpy(keys[44], &val, sizeof(int));
    hash_table_insert(ht, keys[44], NULL, HASH_ENTRY_TX);

    /* Verify migration initialization and size doubling */
    ASSERT_TRUE(ht->old_buckets != NULL, "old_buckets should be allocated during active migration");
    ASSERT_EQUAL_INT(ht->size, 128, "Size should double to 128");

    /* Confirm lookups correctly bridge both bucket generations */
    for (int i = 0; i < 45; i++) {
        void *found = hash_table_lookup(ht, keys[i], true);
        ASSERT_TRUE(found != NULL, "All keys must be retrievable during active migration");
    }

    hash_table_destroy(ht);
    free(ht);
}

/**
 * @brief Tests polymorphic node cleanup and resource deallocation upon item removal.
 *
 * @details
 * Evaluates cleanup cascades for complex session objects:
 * - `HASH_ENTRY_THRESHOLD_STAKE_PROCESS`: Destroys condition variables (`partial_cond`, `stage0_complete_cond`).
 * - `HASH_ENTRY_DKG_SESSION`: Decrements reference count and frees session structures.
 *
 * @pre None.
 * @post Table count decrements to zero with associated synchronizers destroyed.
 *
 * @complexity
 * - Time: O(1) per removal.
 * - Space: O(1) auxiliary.
 */
static void test_hash_table_removal_cleanup(void) {
    HashTable *ht = malloc(sizeof(HashTable));
    ASSERT_TRUE(ht != NULL, "Failed to allocate HashTable");
    int res = hash_table_init(ht, 16, 32, NULL, NULL, NULL, NULL);
    ASSERT_EQUAL_INT(res, 0, "hash_table_init failed");

    uint8_t key1[32];
    memset(key1, 0x11, 32);
    ThresholdStakeProcess *proc = calloc(1, sizeof(ThresholdStakeProcess));
    ASSERT_TRUE(proc != NULL, "Failed to allocate ThresholdStakeProcess");
    pthread_cond_init(&proc->partial_cond, NULL);
    pthread_cond_init(&proc->stage0_complete_cond, NULL);

    bool inserted1 = hash_table_insert(ht, key1, proc, HASH_ENTRY_THRESHOLD_STAKE_PROCESS);
    ASSERT_TRUE(inserted1, "Failed to insert stake process");

    uint8_t key2[32];
    memset(key2, 0x22, 32);
    DKGSession *session = calloc(1, sizeof(DKGSession));
    ASSERT_TRUE(session != NULL, "Failed to allocate DKGSession");
    atomic_init(&session->ref_count, 1);
    pthread_cond_init(&session->phase_cond, NULL);

    bool inserted2 = hash_table_insert(ht, key2, session, HASH_ENTRY_DKG_SESSION);
    ASSERT_TRUE(inserted2, "Failed to insert DKG Session");

    ASSERT_EQUAL_INT(ht->count, 2, "Count should be 2");

    /* Remove key1 -> triggers free_threshold_process internally */
    bool removed1 = hash_table_remove(ht, key1);
    ASSERT_TRUE(removed1, "Failed to remove key1");
    ASSERT_EQUAL_INT(ht->count, 1, "Count should decrement to 1");

    /* Remove key2 -> triggers free_dkg_session internally */
    bool removed2 = hash_table_remove(ht, key2);
    ASSERT_TRUE(removed2, "Failed to remove key2");
    ASSERT_EQUAL_INT(ht->count, 0, "Count should decrement to 0");

    hash_table_destroy(ht);
    free(ht);
}

/* ============================================================================ */
/* SECTION 1.2: MERKLE MOUNTAIN RANGE ACCUMULATOR TESTS (`mmr.c`)               */
/* ============================================================================ */
/**
 * @brief Validates the Merkle Mountain Range popcount invariant: PeakCount(N) == popcount(N).
 *
 * @details
 * In an MMR structure, every binary representation bit of leaf count N corresponds
 * to a distinct isolated mountain peak. Tests leaf insertions from N = 1 to 32,
 * asserting that `mmr->peak_count` precisely equals `__builtin_popcount(N)`.
 *
 * @pre `mmr_init` succeeds.
 * @post MMR accumulator memory released via `mmr_destroy`.
 *
 * @complexity
 * - Time: O(N log N) across N=32 additions.
 * - Space: O(N) nodes in MMR node buffer.
 */
static void test_mmr_add_peaks(void) {
    MMR *mmr = malloc(sizeof(MMR));
    ASSERT_TRUE(mmr != NULL, "Failed to allocate MMR");
    int res = mmr_init(mmr);
    ASSERT_EQUAL_INT(res, 0, "mmr_init failed");

    /* Add up to 32 leaf nodes and verify peak counts match popcount of N */
    for (int N = 1; N <= 32; N++) {
        uint8_t coin_id[32];
        memset(coin_id, 0, 32);
        memcpy(coin_id, &N, sizeof(int));
        
        int add_res = mmr_add(mmr, coin_id, 100);
        ASSERT_EQUAL_INT(add_res, 0, "mmr_add failed");

        /* Compute expected peak count as Hamming weight (popcount) of N */
        size_t expected_peaks = 0;
        int temp = N;
        while (temp > 0) {
            if (temp & 1) expected_peaks++;
            temp >>= 1;
        }

        ASSERT_EQUAL_INT(mmr->peak_count, expected_peaks, "Peak count must match popcount of N");
    }

    mmr_destroy(mmr);
    free(mmr);
}

/**
 * @brief Tests MMR inclusion proof generation and cryptographic path verification.
 *
 * @details
 * Populates an MMR with 15 leaves (binary 1111_2 -> peaks of size 8, 4, 2, 1).
 * Generates an inclusion proof for leaf index 5 and asserts:
 * 1. Valid proofs verify against the MMR root (`verify_mmr_proof == 1`).
 * 2. 1-bit mutations to interior path hashes trigger immediate rejection (`verify_mmr_proof == 0`).
 * 3. 1-bit mutations to adjacent peak hashes trigger rejection (`verify_mmr_proof == 0`).
 *
 * @pre Leaf index 5 must exist.
 * @post Releases MMR memory.
 *
 * @complexity
 * - Time: O(log N) proof generation and verification.
 * - Space: O(log N) proof path length.
 */
static void test_mmr_proof_generation_and_verification(void) {
    MMR *mmr = malloc(sizeof(MMR));
    ASSERT_TRUE(mmr != NULL, "Failed to allocate MMR");
    mmr_init(mmr);

    /* Add 15 leaf nodes */
    uint8_t leaf_hashes[15][32];
    for (int i = 0; i < 15; i++) {
        uint8_t coin_id[32];
        memset(coin_id, 0, 32);
        memcpy(coin_id, &i, sizeof(int));
        hash_leaf(coin_id, 100, leaf_hashes[i]);
        mmr_add(mmr, coin_id, 100);
    }

    uint8_t root_hash[32];
    mmr_get_root(mmr, root_hash);

    size_t target_idx = 5;
    ssize_t leaf_pos = -1;
    for (size_t i = 0; i < mmr->count; i++) {
        if (mmr->nodes[i].height == 0) {
            uint8_t coin_id[32];
            memset(coin_id, 0, 32);
            memcpy(coin_id, &target_idx, sizeof(int));
            uint8_t expected_hash[32];
            hash_leaf(coin_id, 100, expected_hash);
            if (memcmp(mmr->nodes[i].hash, expected_hash, 32) == 0) {
                leaf_pos = (ssize_t)i;
                break;
            }
        }
    }
    ASSERT_TRUE(leaf_pos != -1, "Target leaf node not found in MMR");

    MMRProof proof;
    memset(&proof, 0, sizeof(MMRProof));
    int gen_res = mmr_generate_proof(mmr, (size_t)leaf_pos, proof.path_hashes, proof.is_left, &proof.path_len,
                                     proof.left_peaks, &proof.left_peaks_len, proof.right_peaks, &proof.right_peaks_len);
    ASSERT_EQUAL_INT(gen_res, 0, "mmr_generate_proof failed");
    ASSERT_TRUE(proof.path_len > 0, "Proof path length should be greater than 0");

    /* 1. Verify unmodified valid proof */
    int verify_ok = verify_mmr_proof(leaf_hashes[target_idx], &proof, root_hash);
    ASSERT_EQUAL_INT(verify_ok, 1, "verify_mmr_proof rejected a valid proof");

    /* 2. Mutate interior path hash bit -> must fail */
    proof.path_hashes[0][0] ^= 0xFF;
    int verify_fail1 = verify_mmr_proof(leaf_hashes[target_idx], &proof, root_hash);
    ASSERT_EQUAL_INT(verify_fail1, 0, "verify_mmr_proof should have rejected a mutated proof hash");

    /* 3. Restore and mutate adjacent peak hash -> must fail */
    proof.path_hashes[0][0] ^= 0xFF;
    if (proof.right_peaks_len > 0) {
        proof.right_peaks[0][0] ^= 0xFF;
        int verify_fail2 = verify_mmr_proof(leaf_hashes[target_idx], &proof, root_hash);
        ASSERT_EQUAL_INT(verify_fail2, 0, "verify_mmr_proof should have rejected a mutated right peak");
    }

    mmr_destroy(mmr);
    free(mmr);
}

/* ============================================================================ */
/* SECTION 1.3: POST-QUANTUM & LATTICE CRYPTOGRAPHY TESTS (`crypto.c`)          */
/* ============================================================================ */
/**
 * @brief Tests ML-DSA-87 (Dilithium5) key generation and memory page locking semantics.
 *
 * @details
 * Validates keypair synthesis and confirms that `scl_secure_lock` (`mlock`) and
 * `scl_secure_unlock` (`munlock`) execute without OS security errors.
 *
 * @pre CSPRNG functional.
 * @post Secret key zeroized and unlocked.
 *
 * @complexity
 * - Time: O(1) Dilithium keypair generation.
 * - Space: O(1) stack buffers.
 */
static void test_crypto_dilithium_keypair_locks(void) {
    uint8_t public_key[DILITHIUM_PUBKEY_LEN];
    uint8_t secret_key[DILITHIUM_SECRETKEY_LEN];

    int gen_ok = dilithium_generate_keypair(public_key, secret_key);
    ASSERT_EQUAL_INT(gen_ok, 1, "Failed to generate Dilithium keypair");

    int lock_ok = scl_secure_lock(secret_key, DILITHIUM_SECRETKEY_LEN);
    ASSERT_EQUAL_INT(lock_ok, 0, "scl_secure_lock failed on private key");

    int unlock_ok = scl_secure_unlock(secret_key, DILITHIUM_SECRETKEY_LEN);
    ASSERT_EQUAL_INT(unlock_ok, 0, "scl_secure_unlock failed");
}

/**
 * @brief Tests bounded uniform polynomial sampling and XOF determinism over R_q.
 *
 * @details
 * Verifies that `poly_uniform_with_bound`:
 * 1. Enforces coefficient bounds: |c_i| <= bound for all 256 coefficients.
 * 2. Generates deterministic polynomials given identical seed and nonce inputs.
 *
 * @pre Seed buffer non-NULL.
 * @post Leaves polynomials initialized.
 *
 * @complexity
 * - Time: O(RING_DEG) rejection sampling iterations.
 * - Space: O(RING_DEG) polynomial coefficient arrays.
 */
static void test_poly_uniform_with_bound(void) {
    poly_t p1, p2;
    uint8_t seed[32];
    memset(seed, 0xAB, 32);
    int32_t bound = 500;

    int res1 = poly_uniform_with_bound(&p1, seed, 32, 42, bound);
    ASSERT_EQUAL_INT(res1, 0, "poly_uniform_with_bound failed");

    for (int i = 0; i < RING_DEG; i++) {
        ASSERT_TRUE(p1.coeffs[i] >= -bound && p1.coeffs[i] <= bound, "Coeff out of bound");
    }

    /* Verify determinism of XOF sampling */
    int res2 = poly_uniform_with_bound(&p2, seed, 32, 42, bound);
    ASSERT_EQUAL_INT(res2, 0, "poly_uniform_with_bound determinism run failed");
    ASSERT_EQUAL_INT(memcmp(p1.coeffs, p2.coeffs, sizeof(p1.coeffs)), 0, "Determinism check failed");
}

/**
 * @brief Validates sparse polynomial multiplication and centered modulo reduction in R_q.
 *
 * @details
 * Evaluates `poly_mul_sparse` over R_q = Z_q[X]/(X^256 + 1) with q = 8380417, confirming
 * that resulting coefficients strictly obey centered bounds: -(Q-1)/2 <= r_i <= (Q-1)/2.
 *
 * @pre Coefficients initialized.
 * @post Result polynomial stored in `r`.
 *
 * @complexity
 * - Time: O(RING_DEG) sparse operations.
 * - Space: O(1) auxiliary.
 */
static void test_poly_mul_sparse(void) {
    poly_t a, c, r;
    memset(&a, 0, sizeof(poly_t));
    memset(&c, 0, sizeof(poly_t));

    /* Seed polynomial values */
    a.coeffs[0] = 12345;
    a.coeffs[1] = -54321;
    c.coeffs[0] = 1;
    c.coeffs[1] = -1;

    poly_mul_sparse(&r, &a, &c);

    int32_t limit = (Q - 1) / 2;
    for (int i = 0; i < RING_DEG; i++) {
        ASSERT_TRUE(r.coeffs[i] >= -limit && r.coeffs[i] <= limit, "Sparse multiplication modulus overflow");
    }
}

/**
 * @brief Evaluates the high/low bit decomposition identity: a = r1 * alpha + r0 (mod Q).
 *
 * @details
 * Tests boundary cases (0, 1, Q-1, arbitrary integers) across standard decomposition
 * factors alpha in {2^D, ALPHA}, asserting the reconstruction identity.
 *
 * @pre 0 <= a < Q.
 * @post Confirms algebraic correctness.
 *
 * @complexity
 * - Time: O(1) per decomposition.
 * - Space: O(1) auxiliary.
 */
static void test_decompose_math(void) {
    int32_t a_vals[] = {0, 1, Q - 1, 1234567, 8380415};
    int32_t alphas[] = {1 << D, ALPHA};

    for (size_t i = 0; i < sizeof(a_vals)/sizeof(a_vals[0]); i++) {
        for (size_t j = 0; j < sizeof(alphas)/sizeof(alphas[0]); j++) {
            int32_t r0, r1;
            decompose(a_vals[i], alphas[j], &r0, &r1);

            int32_t reconstructed = (r1 * alphas[j] + r0) % Q;
            if (reconstructed < 0) reconstructed += Q;
            int32_t original_mod = a_vals[i] % Q;
            if (original_mod < 0) original_mod += Q;

            ASSERT_EQUAL_INT(reconstructed, original_mod, "Decomposition math identity failed");
        }
    }
}

/**
 * @brief Tests Stern-type Zero-Knowledge PRF proof generation and Fiat-Shamir verification.
 *
 * @details
 * Evaluates Module-SIS knowledge proofs:
 * 1. PRF evaluation computes y = PRF(k, input, seed).
 * 2. Stern ZK proof generated for statement: "Knowledge of k such that PRF(k, input) = y".
 * 3. Asserts proof verification succeeds on correct input and fails on modified inputs.
 *
 * @pre None.
 * @post Frees temporary proof buffer.
 *
 * @complexity
 * - Time: O(ZK_PROOF_MAX_LEN) proof operations.
 * - Space: O(ZK_PROOF_MAX_LEN) heap allocation.
 */
static void test_zk_prf_stern_verification(void) {
    uint8_t prf_input[32];
    memset(prf_input, 0x11, 32);
    uint8_t seed[32];
    memset(seed, 0x33, 32);

    PRFKey key_struct;
    int keygen_res = prf_keygen(&key_struct, seed, 32);
    ASSERT_EQUAL_INT(keygen_res, 0, "prf_keygen failed");

    uint8_t prf_key[1024];
    memcpy(prf_key, key_struct.k, 1024);
    uint8_t y[32];
    int prf_ok = prf_evaluate(y, &key_struct, prf_input, 32, seed);
    ASSERT_EQUAL_INT(prf_ok, 0, "prf_evaluate failed");

    uint8_t *proof = malloc(ZK_PROOF_MAX_LEN);
    ASSERT_TRUE(proof != NULL, "Failed to allocate proof buffer");
    size_t proof_len = ZK_PROOF_MAX_LEN;
    int gen_ok = generate_zk_prf_proof(proof, &proof_len, prf_input, 32, prf_key, 1024, seed);
    ASSERT_EQUAL_INT(gen_ok, 0, "generate_zk_prf_proof failed");

    /* 1. Verify valid proof */
    int verify_ok = zk_prf_verify(proof, proof_len, seed, prf_input, 32, y);
    ASSERT_EQUAL_INT(verify_ok, 0, "zk_prf_verify rejected a valid Stern proof");

    /* 2. Verify invalid relation (altered input) */
    uint8_t wrong_input[32];
    memset(wrong_input, 0x99, 32);
    int verify_fail = zk_prf_verify(proof, proof_len, seed, wrong_input, 32, y);
    ASSERT_TRUE(verify_fail != 0, "zk_prf_verify should have rejected modified prf_input");

    free(proof);
}

/**
 * @brief Tests BDLOP lattice commitment generation and opening/decryption correctness.
 *
 * @details
 * Tests commitment C = Commit(rho, v, r). Verifies:
 * 1. Decryption with matching randomness r recovers value v.
 * 2. Decryption with invalid randomness fails.
 *
 * @pre Valid blinding factor r.
 * @post Confirms BDLOP binding and hiding properties.
 *
 * @complexity
 * - Time: O(1) ring operations.
 * - Space: O(1) auxiliary.
 */
static void test_bdlop_commit_decrypt(void) {
    uint8_t rho[32];
    memset(rho, 0x55, 32);
    uint64_t v = 987654321ULL;
    uint8_t r[32];
    memset(r, 0x66, 32);

    BdlopCommitment commitment;
    int commit_ok = bdlop_commit(rho, v, r, &commitment);
    ASSERT_EQUAL_INT(commit_ok, 0, "bdlop_commit failed");

    /* Decrypt with correct blinding factor */
    uint64_t decrypted_v = 0;
    int decrypt_ok = bdlop_decrypt(rho, &commitment, r, &decrypted_v);
    ASSERT_EQUAL_INT(decrypt_ok, 0, "bdlop_decrypt failed");
    ASSERT_TRUE(decrypted_v == v, "Decrypted value mismatch");

    /* Decrypt with invalid blinding factor */
    uint8_t wrong_r[32];
    memset(wrong_r, 0x99, 32);
    uint64_t wrong_v = 0;
    int decrypt_fail = bdlop_decrypt(rho, &commitment, wrong_r, &wrong_v);
    ASSERT_TRUE(decrypt_fail != 0, "bdlop_decrypt should have failed with incorrect blinding factor");
}

/* ============================================================================ */
/* SECTION 1.4: TRANSACTION FEES & BLOCK SERIALIZATION TESTS (`utils.c`)        */
/* ============================================================================ */
/**
 * @brief Validates the transaction fee schedule and 50% staking discount ratio.
 *
 * @details
 * Evaluates `calculate_fee` across dynamic amounts from 1 to 10^16 subunits.
 * Verifies that:
 * 1. Staking fees (`is_staking = true`) are strictly <= standard transfer fees.
 * 2. For amounts > 100 subunits, standard fees are exactly double staking fees (ratio in [1.9, 2.1]).
 *
 * @pre Amount array populated.
 * @post Asserts protocol fee invariants hold across all magnitudes.
 *
 * @complexity
 * - Time: O(N) where N = number of tested amounts.
 * - Space: O(1) auxiliary.
 */
static void test_calculate_fee(void) {
    uint64_t amounts[] = {1, 100, 10000, 1000000, 100000000ULL, 1000000000000ULL, 10000000000000000ULL};
    
    for (size_t i = 0; i < sizeof(amounts)/sizeof(amounts[0]); i++) {
        uint64_t fee_normal = calculate_fee(amounts[i], false);
        uint64_t fee_halved = calculate_fee(amounts[i], true);
        
        ASSERT_TRUE(fee_normal >= fee_halved, "Halved fee should be <= normal fee");
        if (amounts[i] > 100) {
            ASSERT_TRUE(fee_normal > 0, "Fee should be greater than 0 for large amounts");
            double ratio = (double)fee_normal / (double)fee_halved;
            ASSERT_TRUE(ratio >= 1.9 && ratio <= 2.1, "Fee halving proportion is incorrect");
        }
    }
}

/**
 * @brief Validates deterministic block serialization and SHA-256 hash invariance.
 *
 * @details
 * Verifies that serializing a block into wire-format bytes does not mutate its
 * contents and that repeated block hash computations yield identical 32-byte digests.
 *
 * @pre None.
 * @post Releases allocated block and serialization scratchpad.
 *
 * @complexity
 * - Time: O(BlockSize) serialization and SHA-256 hashing.
 * - Space: O(BlockSize) temporary heap buffer.
 */
static void test_process_block_data_serialization(void) {
    Block *block = calloc(1, sizeof(Block));
    ASSERT_TRUE(block != NULL, "Failed to allocate Block");
    
    block->block_number = 42;
    memset(block->prev_block_hash, 0x12, 32);
    block->entropy_seed = 12345;
    block->proposer_pubkey[0] = 0xAA;
    block->signature[0] = 0xBB;
    
    block->operation_count = 1;
    block->operations = calloc(1, sizeof(Operation));
    block->operations[0].type = OP_MINT_COIN;
    block->operations[0].data.mint_coin.coin.total_subunits = 160000000;
    block->operations[0].data.mint_coin.coin.remaining_subunits = 160000000;
    memset(block->operations[0].data.mint_coin.coin.coin_id, 0x33, 32);

    uint8_t hash1[32];
    int hash_res1 = compute_block_hash(block, hash1);
    ASSERT_EQUAL_INT(hash_res1, 0, "compute_block_hash failed");

    /* Serialize to wire-format buffer */
    uint8_t *buffer = malloc(65536);
    ASSERT_TRUE(buffer != NULL, "Failed to allocate serialization buffer");
    int bytes_written = process_block_data(block, buffer, NULL, false);
    ASSERT_TRUE(bytes_written > 0, "process_block_data should write more than 0 bytes");

    /* Recompute hash and assert identity */
    uint8_t hash2[32];
    int hash_res2 = compute_block_hash(block, hash2);
    ASSERT_EQUAL_INT(hash_res2, 0, "compute_block_hash failed on second run");
    ASSERT_EQUAL_INT(memcmp(hash1, hash2, 32), 0, "Block hashes must remain identical");

    free(buffer);
    free_block(block);
}

/* ============================================================================ */
/* SECTION 2.1: LEDGER STATE TRANSITIONS & INTEGRATION LIFECYCLE                */
/* ============================================================================ */
/**
 * @brief End-to-end integration test verifying transaction proposal, validation, and state commit.
 *
 * @details
 * Validates the full distributed state transition cycle:
 * 1. Sets up Node 1 with 1,000 SCL UTXO coin and derives associated pointer spanning full range.
 * 2. Constructs `OP_TRANSFER_POINTER` to Node 2 (100 SCL) with Dilithium5 signature and ZK-PRF proof.
 * 3. Enqueues operation into pending mempool via `add_pending_operation`.
 * 4. Assembles candidate block with batched ZK-PRF proofs.
 * 5. Verifies cryptographic consensus rules via `verify_block_heavy_crypto`.
 * 6. Commits block via `apply_block`, verifying insertion into `processed_blocks` hash table.
 *
 * @pre Clean client state.
 * @post State transitioned and fully reclaimed.
 *
 * @complexity
 * - Time: O(HeavyCrypto + ApplyBlock)
 * - Space: O(sizeof(State))
 */
static void test_integration_block_lifecycle(void) {
    State *state = calloc(1, sizeof(State));
    ASSERT_TRUE(state != NULL, "Failed to allocate State");

    int res = client_state_init(state, 0);
    ASSERT_EQUAL_INT(res, 0, "client_state_init failed");

    // Purge any auto-hydrated disk state to guarantee hermetic test execution
    scl_db_delete_blocks_after(0);
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);
    state->bc.sync_epoch = 1;

    int key_res = create_user_wallet(&state->user_wallet);
    ASSERT_EQUAL_INT(key_res, 1, "create_user_wallet failed");

    // Initialize mock balance for Node 1
    uint8_t dummy_tx_hash[32];
    memset(dummy_tx_hash, 0x55, 32);
    SCLCoin coin = create_coin(dummy_tx_hash, state->user_wallet.dilithium_pubkey);
    coin.total_subunits = 1000 * SUBUNITS_PER_COIN;
    coin.remaining_subunits = 1000 * SUBUNITS_PER_COIN;

    pthread_rwlock_wrlock(&state->bc.rwlock);
    SCLCoin *coin_heap = malloc(sizeof(SCLCoin));
    *coin_heap = coin;
    hash_table_insert(state->bc.coin_table, coin.coin_id, coin_heap, HASH_ENTRY_COIN);

    // Create a pointer spanning the entire range
    Pointer ptr = {0};
    memcpy(ptr.parent_coin_id, coin.coin_id, COIN_ID_LEN);
    ptr.start_subunit = 0;
    ptr.end_subunit = coin.total_subunits - 1;
    ptr.staked = 0;
    ptr.spent = 0;
    memcpy(ptr.owner_address, coin.owner_address, USER_ID_LEN);
    memcpy(ptr.prev_tx_hash, coin.creation_tx_hash, COIN_ID_LEN);
    uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
    uint8_t *pd = pointer_data;
    memcpy(pd, ptr.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
    memcpy(pd, ptr.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
    uint64_t start_be = htobe64(ptr.start_subunit);
    memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
    uint64_t end_be = htobe64(ptr.end_subunit);
    memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
    memcpy(pd, ptr.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
    SHA256(pointer_data, sizeof(pointer_data), ptr.pointer_id);
    hash_table_insert(state->bc.pointer_table, ptr.pointer_id, &ptr, HASH_ENTRY_POINTER);
    add_pointer_id_to_coin(state->bc.coin_pointers, ptr.parent_coin_id, ptr.pointer_id);

    // Update insert_order of blockchain to track it chronologically
    state->bc.insert_order_capacity = 4;
    state->bc.insert_order = calloc(state->bc.insert_order_capacity, sizeof(SCLCoin *));
    state->bc.insert_order[0] = coin_heap;
    state->bc.insert_order_count = 1;

    mmr_add(state->bc.mmr, coin.coin_id, coin.remaining_subunits);
    pthread_rwlock_unlock(&state->bc.rwlock);

    // Node 2 mock pubkey
    uint8_t node2_pubkey[DILITHIUM_PUBKEY_LEN];
    memset(node2_pubkey, 0xBB, DILITHIUM_PUBKEY_LEN);

    uint64_t transfer_amount = 100 * SUBUNITS_PER_COIN;

    // Create actual TransferData operation
    TransferData *tx = calloc(1, sizeof(TransferData));
    ASSERT_TRUE(tx != NULL, "Failed to allocate TransferData");
    tx->num_inputs = 1;
    tx->inputs[0] = ptr;
    memcpy(tx->recipient_pubkey, node2_pubkey, PUBKEY_LEN);
    memcpy(tx->sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    tx->amount = transfer_amount;
    memset(tx->nonce, 0x44, 8);
    get_mmr_root(&state->bc, tx->client_root);
    
    // Generate proof
    ssize_t leaf_pos = mmr_get_leaf_position(state->bc.mmr, coin.coin_id, coin.remaining_subunits);
    ASSERT_TRUE(leaf_pos != -1, "Leaf position must exist");
    mmr_generate_proof(state->bc.mmr, (size_t)leaf_pos, tx->proofs[0].path_hashes, tx->proofs[0].is_left, &tx->proofs[0].path_len,
                       tx->proofs[0].left_peaks, &tx->proofs[0].left_peaks_len, tx->proofs[0].right_peaks, &tx->proofs[0].right_peaks_len);
    
    compute_inputs_merkle_root(tx->inputs, tx->num_inputs, tx->inputs_merkle_root);
    dilithium_sign(tx->inputs_merkle_root, COIN_ID_LEN, state->user_wallet.dilithium_privkey, tx->inputs_root_signature);
    
    size_t payload_len;
    uint8_t payload_buf[65536];
    serialize_transfer_payload(tx, payload_buf, &payload_len);
    SHA256(payload_buf, payload_len, tx->tx_id);
    
    // ZK PRF
    prf_evaluate(tx->prf_output, &state->user_wallet.prf_key, tx->tx_id, COIN_ID_LEN, tx->client_root);
    size_t zk_len = ZK_PROOF_MAX_LEN;
    generate_zk_prf_proof(tx->zk_proof, &zk_len, tx->tx_id, COIN_ID_LEN, (const uint8_t*)state->user_wallet.prf_key.k, sizeof(state->user_wallet.prf_key.k), tx->client_root);
    tx->zk_proof_len = zk_len;
    
    uint8_t sig_payload[65536];
    size_t sig_payload_len;
    serialize_transfer_for_signature(tx, sig_payload, &sig_payload_len);
    dilithium_sign(sig_payload, sig_payload_len, state->user_wallet.dilithium_privkey, tx->signature);

    Operation *op = calloc(1, sizeof(Operation));
    ASSERT_TRUE(op != NULL, "Failed to allocate Operation");
    op->type = OP_TRANSFER_POINTER;
    op->data.transfer_pointer = *tx;

    // Insert to pending operations
    int added_pending = add_pending_operation(state, op);
    ASSERT_EQUAL_INT(added_pending, 0, "add_pending_operation failed");
    ASSERT_EQUAL_INT(atomic_load(&state->pending_operations_count), 1, "Pending count should be 1");

    // Format/pack the proof with the 4-byte big-endian length prefix expected by zk_batch_prf_verify
    uint8_t *batched_proof = malloc(4 + tx->zk_proof_len);
    if (batched_proof) {
        uint32_t proof_len_be = htobe32(tx->zk_proof_len);
        memcpy(batched_proof, &proof_len_be, 4);
        memcpy(batched_proof + 4, tx->zk_proof, tx->zk_proof_len);
    }

    uint8_t *batch_prf_outputs = malloc(NULLIFIER_LEN);
    if (batch_prf_outputs) {
        memcpy(batch_prf_outputs, tx->prf_output, NULLIFIER_LEN);
    }

    // Propose a block with this operation
    Block *proposed_block = create_block(
        1,
        state->current_block_hash,
        op,
        1,
        state->user_wallet.dilithium_pubkey,
        state->user_wallet.dilithium_privkey,
        12345,
        1,
        batch_prf_outputs,
        batched_proof,
        4 + tx->zk_proof_len
    );
    ASSERT_TRUE(proposed_block != NULL, "Failed to create block");

    // Verify and apply block
    int verify_status = verify_block_heavy_crypto(proposed_block);
    ASSERT_EQUAL_INT(verify_status, 0, "verify_block_heavy_crypto failed on proposed block");

    int apply_res = apply_block(state, proposed_block);
    ASSERT_EQUAL_INT(apply_res, 0, "apply_block failed to commit block");

    // Assert that the processed block is recorded
    pthread_mutex_lock(&state->processed_blocks_mutex);
    uint8_t block_hash[32];
    compute_block_hash(proposed_block, block_hash);
    void *found_block = hash_table_lookup(state->processed_blocks, block_hash, true);
    ASSERT_TRUE(found_block != NULL, "Block hash should be present in processed_blocks");
    pthread_mutex_unlock(&state->processed_blocks_mutex);

    // Clean up
    free(coin_heap);
    free(tx);
    free(op);
    free_block(proposed_block);
    client_state_destroy(state);
    free(state);
}

/**
 * @brief Validates the complete OP_APPLY_DRIFT_CERT anchoring lifecycle.
 *
 * @details
 * Exercises the end-to-end drift-certificate pipeline the RPC/consensus fuzzers
 * can only reach with mutation residue: custodial anchor construction
 * (`create_and_broadcast_apply_drift_cert` — canonical cert_digest, deterministic
 * cert_tx_id, funding-wallet ML-DSA-87 signature, heavy-crypto self-check),
 * mempool admission (`add_pending_operation`), block proposal (`create_block`),
 * heavy cryptographic verification (`verify_block_heavy_crypto`), ledger commit
 * (`apply_block` → `validate_operation` + `update_transfer_state` + validation-
 * commitments MMR leaf), and the processed_txs replay-gate hit.
 *
 * @pre Clean client state with a funded node wallet.
 * @post State transitioned and fully reclaimed.
 *
 * @complexity
 * - Time: O(DilithiumSign + DilithiumVerify + ApplyBlock)
 * - Space: O(sizeof(State) + sizeof(ApplyDriftCertData))
 */
static void test_integration_drift_cert_anchor_lifecycle(void) {
    State *state = calloc(1, sizeof(State));
    ASSERT_TRUE(state != NULL, "Failed to allocate State");

    int res = client_state_init(state, 0);
    ASSERT_EQUAL_INT(res, 0, "client_state_init failed");

    // Purge any auto-hydrated disk state to guarantee hermetic test execution
    scl_db_delete_blocks_after(0);
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);
    state->bc.sync_epoch = 1;

    int key_res = create_user_wallet(&state->user_wallet);
    ASSERT_EQUAL_INT(key_res, 1, "create_user_wallet failed");

    // Initialize mock funding balance for the node wallet (mirrors the block lifecycle test)
    uint8_t dummy_tx_hash[32];
    memset(dummy_tx_hash, 0x55, 32);
    SCLCoin coin = create_coin(dummy_tx_hash, state->user_wallet.dilithium_pubkey);
    coin.total_subunits = 1000 * SUBUNITS_PER_COIN;
    coin.remaining_subunits = 1000 * SUBUNITS_PER_COIN;

    pthread_rwlock_wrlock(&state->bc.rwlock);
    SCLCoin *coin_heap = malloc(sizeof(SCLCoin));
    *coin_heap = coin;
    hash_table_insert(state->bc.coin_table, coin.coin_id, coin_heap, HASH_ENTRY_COIN);

    // Create a pointer spanning the entire range
    Pointer ptr = {0};
    memcpy(ptr.parent_coin_id, coin.coin_id, COIN_ID_LEN);
    ptr.start_subunit = 0;
    ptr.end_subunit = coin.total_subunits - 1;
    ptr.staked = 0;
    ptr.spent = 0;
    memcpy(ptr.owner_address, coin.owner_address, USER_ID_LEN);
    memcpy(ptr.prev_tx_hash, coin.creation_tx_hash, COIN_ID_LEN);
    uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
    uint8_t *pd = pointer_data;
    memcpy(pd, ptr.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
    memcpy(pd, ptr.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
    uint64_t start_be = htobe64(ptr.start_subunit);
    memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
    uint64_t end_be = htobe64(ptr.end_subunit);
    memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
    memcpy(pd, ptr.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
    SHA256(pointer_data, sizeof(pointer_data), ptr.pointer_id);
    hash_table_insert(state->bc.pointer_table, ptr.pointer_id, &ptr, HASH_ENTRY_POINTER);
    add_pointer_id_to_coin(state->bc.coin_pointers, ptr.parent_coin_id, ptr.pointer_id);

    state->bc.insert_order_capacity = 4;
    state->bc.insert_order = calloc(state->bc.insert_order_capacity, sizeof(SCLCoin *));
    state->bc.insert_order[0] = coin_heap;
    state->bc.insert_order_count = 1;

    mmr_add(state->bc.mmr, coin.coin_id, coin.remaining_subunits);
    pthread_rwlock_unlock(&state->bc.rwlock);

    // Enterprise recipient wallet
    uint8_t enterprise_pubkey[DILITHIUM_PUBKEY_LEN];
    memset(enterprise_pubkey, 0xEE, DILITHIUM_PUBKEY_LEN);

    // Client anchoring intent: only the certificate identity core and fee are
    // meaningful — the node re-selects inputs, regenerates proofs, recomputes
    // the digest chain, and re-signs custodially.
    ApplyDriftCertData intent;
    memset(&intent, 0, sizeof(intent));
    const char *circuit_qasm = "OPENQASM 3.0; include \"stdgates.inc\"; qubit[7] q; h q; measure q;";
    SHA256((const uint8_t *)circuit_qasm, strlen(circuit_qasm), intent.circuit_hash);
    intent.tvd_scaled = 42000000ULL; /* 0.042 nano-scale fixed-point */
    intent.shots = 15000;
    intent.status = 0;               /* QPU_STATUS_FIDELITY_OPTIMAL */
    memset(intent.commitment_root, 0xA5, 32); /* raw c1 prefix (client convention) */
    intent.timestamp_us = 1700000000000000ULL;
    memcpy(intent.recipient_pubkey, enterprise_pubkey, PUBKEY_LEN);
    intent.amount = 10 * SUBUNITS_PER_COIN; /* anchor fee principal */

    // 1. SubmitTx-grade custodial anchor: build, sign, heavy-verify, mempool-admit
    uint8_t anchored_cert_tx_id[COIN_ID_LEN];
    int anchor_res = create_and_broadcast_apply_drift_cert(state, &intent, false, anchored_cert_tx_id, NULL);
    ASSERT_EQUAL_INT(anchor_res, 0, "create_and_broadcast_apply_drift_cert failed");
    ASSERT_EQUAL_INT(atomic_load(&state->pending_operations_count), 1, "Drift-cert op should occupy one mempool slot");

    // 2. Snapshot the mempool operation the anchor produced (proposal input)
    Operation *mempool_op = NULL;
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (pop) {
            const uint8_t *pid = get_operation_tx_id(pop);
            if (pid && memcmp(pid, anchored_cert_tx_id, COIN_ID_LEN) == 0) {
                mempool_op = malloc(sizeof(Operation));
                ASSERT_TRUE(mempool_op != NULL, "Failed to snapshot mempool op");
                *mempool_op = *pop;
                break;
            }
        }
    }
    ASSERT_TRUE(mempool_op != NULL, "Anchored drift-cert op must be resolvable in the mempool");
    ASSERT_EQUAL_INT(mempool_op->type, OP_APPLY_DRIFT_CERT, "Mempool op type mismatch");

    // 3. Propose a block carrying the anchor (no transfers => empty ZK batch)
    Block *proposed_block = create_block(
        1,
        state->current_block_hash,
        mempool_op,
        1,
        state->user_wallet.dilithium_pubkey,
        state->user_wallet.dilithium_privkey,
        12345,
        0,
        NULL,
        NULL,
        0
    );
    ASSERT_TRUE(proposed_block != NULL, "Failed to create block with OP_APPLY_DRIFT_CERT");

    // 4. Heavy cryptographic verification of the proposed block
    int verify_status = verify_block_heavy_crypto(proposed_block);
    ASSERT_EQUAL_INT(verify_status, 0, "verify_block_heavy_crypto failed on drift-cert block");

    // 5. Ledger commit: validate_operation (digest, tx id, signature, Merkle root,
    //    ownership, solvency) + update_transfer_state + commitments MMR leaf
    int apply_res = apply_block(state, proposed_block);
    ASSERT_EQUAL_INT(apply_res, 0, "apply_block failed to commit drift-cert block");

    // 6. processed_txs replay-gate hit: the anchor id must be spend-resistant
    pthread_rwlock_rdlock(&state->bc.rwlock);
    void *replay_entry = hash_table_lookup(state->processed_txs, anchored_cert_tx_id, true);
    pthread_rwlock_unlock(&state->bc.rwlock);
    ASSERT_TRUE(replay_entry != NULL, "cert_tx_id should be present in processed_txs");

    // 7. Validation-commitments accumulator carries the anchor leaf (cert_tx_id, tvd_scaled)
    ASSERT_TRUE(mmr_get_leaf_position(state->bc.centinel.validation_commitments,
                                      anchored_cert_tx_id, intent.tvd_scaled) >= 0,
               "Drift-cert anchor leaf missing from validation_commitments MMR");

    // Clean up
    free(coin_heap);
    free(mempool_op);
    free_block(proposed_block);
    client_state_destroy(state);
    free(state);
}

/**
 * @brief Validates PoS2 reward minting and canonical audit state anchor verification.
 *
 * @details
 * Validates coin minting via Proof-of-Symmetry:
 * 1. Simulates 10 user valuations in the circular audit buffer.
 * 2. Derives reward matches via `count_partial_matches`.
 * 3. Assembles candidate `OP_MINT_COIN` with canonical audit state anchor hash.
 * 4. Verifies that `validate_operation` accepts the valid anchor and rejects a corrupted anchor.
 *
 * @pre User registered.
 * @post Temporary client state destroyed.
 *
 * @complexity
 * - Time: O(AUDIT_SIZE * 10)
 * - Space: O(AUDIT_SIZE * sizeof(Valuation))
 */
static void test_integration_supply_reward_invariant(void) {
    State *state = calloc(1, sizeof(State));
    ASSERT_TRUE(state != NULL, "Failed to allocate State");
    client_state_init(state, 0);

    // Purge any auto-hydrated disk state to guarantee hermetic test execution
    scl_db_delete_blocks_after(0);
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);
    state->bc.sync_epoch = 1;

    int key_res = create_user_wallet(&state->user_wallet);
    ASSERT_EQUAL_INT(key_res, 1, "create_user_wallet failed");

    // Register local user to populate state->users[0] and user table
    uint8_t local_user_id[USER_ID_LEN];
    SHA256(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, local_user_id);
    register_user(state, local_user_id, state->user_wallet.dilithium_pubkey);

    state->bc.sync_epoch = 1;

    // Pre-load 10 user valuations to simulate the audit snapshot matching
    Valuation val;
    memset(&val, 0, sizeof(Valuation));
    memcpy(val.user_id, local_user_id, USER_ID_LEN);
    val.numbers[0] = 42;
    val.numbers[1] = 24;
    val.timestamp = get_real_time_us();

    for (int i = 0; i < AUDIT_SIZE; i++) {
        state->game_state.game_audit[i] = val;
        state->game_state.game_audit[i].user_id[0] = i + 1; // Distinct user IDs for threshold check
    }
    memcpy(state->game_state.game_audit[9].user_id, local_user_id, USER_ID_LEN); // Latest matches coin owner
    state->game_state.valuation_count = AUDIT_SIZE;
    state->game_state.current_audit_index = 0;
    
    update_game_state_snapshot(state);

    // Calculate current matches
    GameStateSnapshot *snap = acquire_game_state_snapshot(state);
    int matches = count_partial_matches(state, &val, snap);
    release_game_state_snapshot(snap);

    uint64_t expected_reward = (uint64_t)matches * SUBUNITS_PER_COIN;

    uint8_t creation_tx[32];
    memset(creation_tx, 0x77, 32);
    SCLCoin coin = create_coin(creation_tx, state->user_wallet.dilithium_pubkey);
    coin.total_subunits = expected_reward;
    coin.remaining_subunits = expected_reward;
    
    memcpy(coin.audit_snapshot, state->game_state.game_audit, sizeof(Valuation) * AUDIT_SIZE);
    coin.snapshot_count = AUDIT_SIZE;
    coin.snapshot_audit_index = 0;

    // Anchor check verification
    uint8_t computed_anchor[32];
    compute_canonical_sclcoin_hash(&coin, computed_anchor);
    memcpy(coin.audit_state_anchor, computed_anchor, 32);

    MintData md;
    md.coin = coin;
    memcpy(md.owner_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

    Operation *op = calloc(1, sizeof(Operation));
    ASSERT_TRUE(op != NULL, "Failed to allocate Operation");
    op->type = OP_MINT_COIN;
    op->data.mint_coin = md;

    int valid_mint = validate_operation(state, op);
    ASSERT_EQUAL_INT(valid_mint, 1, "validate_operation failed on OP_MINT_COIN");

    // Verify rejection if anchor is corrupted
    op->data.mint_coin.coin.audit_state_anchor[0] ^= 0xFF;
    int invalid_mint = validate_operation(state, op);
    ASSERT_EQUAL_INT(invalid_mint, 0, "validate_operation should reject mutated anchor");

    free(op);
    client_state_destroy(state);
    free(state);
}

/* ============================================================================ */
/* SECTION 2.2: WEBASSEMBLY TARGET & JS BRIDGE INTEGRATION TESTS                */
/* ============================================================================ */
/**
 * @brief Tests the automated background staking autopilot worker and RPC framing.
 *
 * @details
 * Verifies:
 * 1. Autopilot thread initialization and termination lifecycle (`start_autopilot_thread`, `stop_autopilot_thread`).
 * 2. Synchronous single-step execution via `scl_autopilot_step`.
 * 3. Method 0x000B RPC wire framing via `scl_rpc_frame_autopilot` and ingress parsing.
 *
 * @pre Client state initialized.
 * @post Autopilot thread stopped and memory freed.
 *
 * @complexity
 * - Time: O(1)
 * - Space: O(1) auxiliary.
 */
static void test_integration_autopilot_logic(void) {
    State *state = calloc(1, sizeof(State));
    ASSERT_TRUE(state != NULL, "Failed to allocate State for autopilot test");
    client_state_init(state, 0);

    // Purge any auto-hydrated disk state to guarantee hermetic test execution
    scl_db_delete_blocks_after(0);
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);
    state->bc.sync_epoch = 1;

    create_user_wallet(&state->user_wallet);

    state->config.autopilot_enabled = true;
    state->config.autopilot_stake_ratio = 50;
    state->config.autopilot_valuations_per_hour = 2;

    // Verify thread start & stop lifecycle
    start_autopilot_thread(state);
    ASSERT_TRUE(atomic_load(&state->autopilot_running) == true, "Autopilot thread should be running");

    // Execute synchronous single step
    scl_autopilot_step(state);

    stop_autopilot_thread(state);
    ASSERT_TRUE(atomic_load(&state->autopilot_running) == false, "Autopilot thread should be stopped");

    // Test RPC wire framing for Method 0x000B
    uint8_t out_frame[1024];
    size_t out_len = 0;
    int frame_res = scl_rpc_frame_autopilot(1234567ULL, 1, 4, 60, out_frame, sizeof(out_frame), &out_len);
    ASSERT_EQUAL_INT(frame_res, 0, "scl_rpc_frame_autopilot failed");
    ASSERT_TRUE(out_len >= sizeof(SclRpcHeader) + 9, "Framed autopilot payload size mismatch");

    int parser_status = 0;
    SclRpcParser parser = scl_rpc_parser_create(out_frame, out_len, &parser_status);
    ASSERT_TRUE(parser != NULL, "Parser creation failed for autopilot frame");
    ASSERT_EQUAL_INT(scl_rpc_parser_get_method_id(parser), 0x000B, "Method ID mismatch in parsed frame");

    scl_rpc_parser_destroy(parser);
    client_state_destroy(state);
    free(state);
}

/**
 * @brief Tests the WebAssembly FFI C-interface for binary RPC frame construction and parsing.
 *
 * @details
 * Tests WASM JavaScript bridge exports:
 * 1. `scl_rpc_builder_create` initializes builder with Method 0x0001 and request ID.
 * 2. Appends arguments and computes Dilithium5 signature on the frame payload.
 * 3. Finalizes wire frame and validates via `scl_rpc_parser_create`.
 * 4. Extracts zero-copy payload reference via `scl_rpc_parser_get_payload_ref`.
 *
 * @pre Keypair generated.
 * @post Builder and parser instances released.
 *
 * @complexity
 * - Time: O(FrameSize + DilithiumSign)
 * - Space: O(FrameSize) heap allocations.
 */
static void test_integration_wasm_ffi_interface(void) {
    uint8_t public_key[DILITHIUM_PUBKEY_LEN];
    uint8_t secret_key[DILITHIUM_SECRETKEY_LEN];
    ASSERT_EQUAL_INT(dilithium_generate_keypair(public_key, secret_key), 1, "Failed to generate keys");

    uint64_t request_id = 0x1122334455667788ULL;
    SclRpcBuilder builder = scl_rpc_builder_create(SCL_RPC_VERSION_1, 0x0001, request_id);
    ASSERT_TRUE(builder != NULL, "FFI Builder creation failed");

    scl_rpc_builder_set_flags(builder, SCL_RPC_FLAG_SIGNED);
    scl_rpc_builder_set_cursor(builder, 120);

    int append_res = scl_rpc_builder_append_args(builder, public_key, DILITHIUM_PUBKEY_LEN);
    ASSERT_EQUAL_INT(append_res, 0, "FFI Builder append args failed");

    int sign_res = scl_rpc_builder_sign(builder, secret_key);
    ASSERT_EQUAL_INT(sign_res, 0, "FFI Builder sign failed");

    uint8_t out_frame[8192];
    size_t out_len = 0;
    int finalize_res = scl_rpc_builder_finalize(builder, out_frame, sizeof(out_frame), &out_len);
    ASSERT_EQUAL_INT(finalize_res, 0, "FFI Builder finalize failed");
    ASSERT_TRUE(out_len > sizeof(SclRpcHeader), "Serialized length must be greater than header size");

    // Parse the finalized frame
    int parser_status = 0;
    SclRpcParser parser = scl_rpc_parser_create(out_frame, out_len, &parser_status);
    ASSERT_TRUE(parser != NULL, "FFI Parser creation failed");
    ASSERT_EQUAL_INT(parser_status, SCL_RPC_STATUS_OK, "Parser status code mismatch");

    // Extract payload reference
    const uint8_t *payload_ref = NULL;
    size_t payload_len = 0;
    int payload_res = scl_rpc_parser_get_payload_ref(parser, &payload_ref, &payload_len);
    ASSERT_EQUAL_INT(payload_res, 0, "FFI Parser get payload reference failed");
    ASSERT_TRUE(payload_len > 0, "Payload length must be greater than 0");

    scl_rpc_builder_destroy(builder);
    scl_rpc_parser_destroy(parser);
}

/* ============================================================================
 * SECTION 5.1: SHAKE256 KNOWN-ANSWER TESTS (H-8 fix)
 * ============================================================================
 */

static int shake256_xof(const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1 ||
        (msg_len > 0 && EVP_DigestUpdate(ctx, msg, msg_len) != 1) ||
        EVP_DigestFinalXOF(ctx, out, out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    return 0;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int digest_matches_hex(const uint8_t *digest, size_t digest_len, const char *expect_hex) {
    for (size_t i = 0; i < digest_len; i++) {
        int hi = hex_nibble(expect_hex[i * 2]);
        int lo = hex_nibble(expect_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0 || (uint8_t)((hi << 4) | lo) != digest[i]) return 0;
    }
    return 1;
}

/**
 * @brief SHAKE256 known-answer tests (NIST FIPS-202 reference vectors).
 *
 * Pins the OpenSSL XOF configuration used by the custom_shake256_inc_* sponge
 * (EVP_shake256 absorb/squeeze in crypto.c — the root of nullifier PRF
 * derivation, ZK Fiat-Shamir challenges, and threshold-signature challenges)
 * against published reference digests, plus an incremental-absorb equivalence
 * check mirroring the absorb/absorb/finalize/squeeze calling pattern. A
 * tampered or misconfigured SHAKE256 (wrong rate, wrong domain separation,
 * output truncation) fails here before it can silently corrupt nullifiers or
 * challenges.
 */
static void test_shake256_known_answer_vectors(void) {
    static const char *kat_empty =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    static const char *kat_abc =
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";
    static const char *kat_a1000 =
        "e262331ad290c96ab1c0fa045470244b415ba6696a934d60f2999b8e92aaa24e"
        "e8eb039abd7af7d64fde39fa73267b02fdd3a50e1b8651b846a9bb2cc4f344c5";

    uint8_t out[100];

    ASSERT_EQUAL_INT(shake256_xof(NULL, 0, out, 64), 0, "SHAKE256 KAT engine failure (empty)");
    ASSERT_TRUE(digest_matches_hex(out, 64, kat_empty), "SHAKE256 KAT mismatch for empty message");

    ASSERT_EQUAL_INT(shake256_xof((const uint8_t *)"abc", 3, out, 64), 0, "SHAKE256 KAT engine failure (abc)");
    ASSERT_TRUE(digest_matches_hex(out, 64, kat_abc), "SHAKE256 KAT mismatch for \"abc\"");

    uint8_t a1000[1000];
    memset(a1000, 'a', sizeof(a1000));
    ASSERT_EQUAL_INT(shake256_xof(a1000, sizeof(a1000), out, 64), 0, "SHAKE256 KAT engine failure (a x1000)");
    ASSERT_TRUE(digest_matches_hex(out, 64, kat_a1000), "SHAKE256 KAT mismatch for 1000 x 'a'");

    /* XOF stream-prefix property: squeezing 100 bytes shares its prefix with
     * any longer squeeze of the same absorbed message. */
    ASSERT_EQUAL_INT(shake256_xof((const uint8_t *)"abc", 3, out, 100), 0, "SHAKE256 KAT engine failure (100B)");
    ASSERT_TRUE(digest_matches_hex(out, 100,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78"), "SHAKE256 100-byte squeeze KAT mismatch");

    /* Incremental absorb equivalence: absorb("") then ("ab") then ("c") must
     * equal the one-shot digest of "abc" — the exact calling pattern of
     * custom_shake256_inc_absorb() in the PRF/Fiat-Shamir pipelines. */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    ASSERT_TRUE(ctx != NULL, "EVP_MD_CTX_new failed");
    ASSERT_EQUAL_INT(EVP_DigestInit_ex(ctx, EVP_shake256(), NULL), 1, "EVP_DigestInit_ex failed");
    ASSERT_EQUAL_INT(EVP_DigestUpdate(ctx, (const uint8_t *)"", 0), 1, "EVP_DigestUpdate (empty chunk) failed");
    ASSERT_EQUAL_INT(EVP_DigestUpdate(ctx, (const uint8_t *)"ab", 2), 1, "EVP_DigestUpdate (ab) failed");
    ASSERT_EQUAL_INT(EVP_DigestUpdate(ctx, (const uint8_t *)"c", 1), 1, "EVP_DigestUpdate (c) failed");
    ASSERT_EQUAL_INT(EVP_DigestFinalXOF(ctx, out, 64), 1, "EVP_DigestFinalXOF failed");
    EVP_MD_CTX_free(ctx);
    ASSERT_TRUE(digest_matches_hex(out, 64, kat_abc), "SHAKE256 incremental absorb diverges from one-shot digest");
}

/* ============================================================================
 * SECTION 5.2: INTRA-BLOCK FORGERY NEGATIVE TESTS (H-1 fix regression tests)
 * ============================================================================
 */

/**
 * @brief Funds a coin and a full-range pointer owned by `wallet` (hermetic).
 *
 * Mirrors the funding block of test_integration_block_lifecycle so the
 * forgery tests can arm two independent wallets (victim + attacker).
 */
static void forgery_fund_wallet(State *state, UserWallet *wallet, uint8_t tx_fill,
                                uint64_t total_subunits, SCLCoin *out_coin, Pointer *out_ptr) {
    uint8_t creation_hash[32];
    memset(creation_hash, tx_fill, 32);
    *out_coin = create_coin(creation_hash, wallet->dilithium_pubkey);
    out_coin->total_subunits = total_subunits;
    out_coin->remaining_subunits = total_subunits;

    SCLCoin *coin_heap = malloc(sizeof(SCLCoin));
    *coin_heap = *out_coin;
    hash_table_insert(state->bc.coin_table, out_coin->coin_id, coin_heap, HASH_ENTRY_COIN);

    memset(out_ptr, 0, sizeof(Pointer));
    memcpy(out_ptr->parent_coin_id, out_coin->coin_id, COIN_ID_LEN);
    out_ptr->start_subunit = 0;
    out_ptr->end_subunit = total_subunits - 1;
    out_ptr->staked = 0;
    out_ptr->spent = 0;
    memcpy(out_ptr->owner_address, out_coin->owner_address, USER_ID_LEN);
    memcpy(out_ptr->prev_tx_hash, out_coin->creation_tx_hash, COIN_ID_LEN);

    uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
    uint8_t *pd = pointer_data;
    memcpy(pd, out_ptr->parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
    memcpy(pd, out_ptr->owner_address, USER_ID_LEN); pd += USER_ID_LEN;
    uint64_t start_be = htobe64(out_ptr->start_subunit);
    memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
    uint64_t end_be = htobe64(out_ptr->end_subunit);
    memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
    memcpy(pd, out_ptr->prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
    SHA256(pointer_data, sizeof(pointer_data), out_ptr->pointer_id);

    hash_table_insert(state->bc.pointer_table, out_ptr->pointer_id, out_ptr, HASH_ENTRY_POINTER);
    add_pointer_id_to_coin(state->bc.coin_pointers, out_ptr->parent_coin_id, out_ptr->pointer_id);

    if (state->bc.insert_order_count < state->bc.insert_order_capacity) {
        state->bc.insert_order[state->bc.insert_order_count++] = coin_heap;
    }
    mmr_add(state->bc.mmr, out_coin->coin_id, out_coin->remaining_subunits);
}

/**
 * @brief Builds a fully signed OP_TRANSFER_POINTER spending `input`.
 *
 * All signatures are produced with `wallet` (ML-DSA-87 over the inputs Merkle
 * root and the canonical transfer payload); the ZK-PRF proof and nullifier are
 * generated with the wallet's PRF key, exactly as the wallet client does.
 */
static void forgery_build_transfer(State *state, UserWallet *wallet, const Pointer *input,
                                   const SCLCoin *parent_coin, const uint8_t *recipient_pubkey,
                                   uint64_t amount, uint8_t nonce_fill, bool attach_mmr_proof,
                                   TransferData *tx) {
    memset(tx, 0, sizeof(TransferData));
    tx->num_inputs = 1;
    tx->inputs[0] = *input;
    memcpy(tx->recipient_pubkey, recipient_pubkey, PUBKEY_LEN);
    memcpy(tx->sender_pubkey, wallet->dilithium_pubkey, PUBKEY_LEN);
    tx->amount = amount;
    memset(tx->nonce, nonce_fill, 8);
    get_mmr_root(&state->bc, tx->client_root);

    if (attach_mmr_proof) {
        ssize_t leaf_pos = mmr_get_leaf_position(state->bc.mmr, parent_coin->coin_id, parent_coin->remaining_subunits);
        ASSERT_TRUE(leaf_pos != -1, "Forgery test MMR leaf must exist");
        mmr_generate_proof(state->bc.mmr, (size_t)leaf_pos, tx->proofs[0].path_hashes, tx->proofs[0].is_left,
                           &tx->proofs[0].path_len, tx->proofs[0].left_peaks, &tx->proofs[0].left_peaks_len,
                           tx->proofs[0].right_peaks, &tx->proofs[0].right_peaks_len);
    }

    compute_inputs_merkle_root(tx->inputs, tx->num_inputs, tx->inputs_merkle_root);
    dilithium_sign(tx->inputs_merkle_root, COIN_ID_LEN, wallet->dilithium_privkey, tx->inputs_root_signature);

    size_t payload_len;
    uint8_t payload_buf[65536];
    serialize_transfer_payload(tx, payload_buf, &payload_len);
    SHA256(payload_buf, payload_len, tx->tx_id);

    prf_evaluate(tx->prf_output, &wallet->prf_key, tx->tx_id, COIN_ID_LEN, tx->client_root);
    size_t zk_len = ZK_PROOF_MAX_LEN;
    generate_zk_prf_proof(tx->zk_proof, &zk_len, tx->tx_id, COIN_ID_LEN,
                          (const uint8_t *)wallet->prf_key.k, sizeof(wallet->prf_key.k), tx->client_root);
    tx->zk_proof_len = zk_len;

    uint8_t sig_payload[65536];
    size_t sig_payload_len;
    serialize_transfer_for_signature(tx, sig_payload, &sig_payload_len);
    dilithium_sign(sig_payload, sig_payload_len, wallet->dilithium_privkey, tx->signature);
}

/**
 * @brief H-1 regression test: a block containing [legit transfer T] +
 *        [forged transfer of a victim pointer with prev_tx_hash = T.tx_id]
 *        MUST be rejected by apply_block.
 *
 * Pre-fix behavior: the forged child skipped validate_operation entirely in
 * Pass 1 (parent_in_block bypass) and update_transfer_state only checked the
 * spent flag in Pass 2, so the victim's pointer was reassigned to the
 * attacker. Post-fix, the child fails the sender/owner address binding in
 * Pass 1 (validate_operation_auth).
 */
static void test_intra_block_forgery_rejected(void) {
    State *state = calloc(1, sizeof(State));
    ASSERT_TRUE(state != NULL, "Failed to allocate State");
    ASSERT_EQUAL_INT(client_state_init(state, 0), 0, "client_state_init failed");

    scl_db_delete_blocks_after(0);
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);
    state->bc.sync_epoch = 1;

    ASSERT_EQUAL_INT(create_user_wallet(&state->user_wallet), 1, "create_user_wallet (victim) failed");

    UserWallet attacker_wallet;
    ASSERT_EQUAL_INT(create_user_wallet(&attacker_wallet), 1, "create_user_wallet (attacker) failed");

    state->bc.insert_order_capacity = 4;
    state->bc.insert_order = calloc(state->bc.insert_order_capacity, sizeof(SCLCoin *));
    state->bc.insert_order_count = 0;

    SCLCoin victim_coin, attacker_coin;
    Pointer victim_ptr, attacker_ptr;
    pthread_rwlock_wrlock(&state->bc.rwlock);
    forgery_fund_wallet(state, &state->user_wallet, 0x55, 1000 * SUBUNITS_PER_COIN, &victim_coin, &victim_ptr);
    forgery_fund_wallet(state, &attacker_wallet, 0x66, 1000 * SUBUNITS_PER_COIN, &attacker_coin, &attacker_ptr);
    pthread_rwlock_unlock(&state->bc.rwlock);

    const uint64_t transfer_amount = 100 * SUBUNITS_PER_COIN;

    /* Op 0: the attacker's own legitimate transfer (spends the attacker's
     * pointer, recipient = attacker). */
    TransferData t_tx;
    forgery_build_transfer(state, &attacker_wallet, &attacker_ptr, &attacker_coin,
                           attacker_wallet.dilithium_pubkey, transfer_amount, 0x44, true, &t_tx);

    /* Op 1: the forged child. Declares the VICTIM's pointer verbatim (so
     * update_transfer_state would find and move it) EXCEPT prev_tx_hash is set
     * to T's tx_id, which is what triggered the intra-block bypass. Signed by
     * the ATTACKER — the theft attempt. */
    TransferData f_tx;
    forgery_build_transfer(state, &attacker_wallet, &victim_ptr, &victim_coin,
                           attacker_wallet.dilithium_pubkey, transfer_amount, 0x77, false, &f_tx);
    memcpy(f_tx.inputs[0].prev_tx_hash, t_tx.tx_id, COIN_ID_LEN);
    /* Re-sign over the tampered input set: the attacker can and does produce
     * internally consistent signatures — the theft is an authorization
     * failure, not a signature-format failure. */
    compute_inputs_merkle_root(f_tx.inputs, f_tx.num_inputs, f_tx.inputs_merkle_root);
    dilithium_sign(f_tx.inputs_merkle_root, COIN_ID_LEN, attacker_wallet.dilithium_privkey, f_tx.inputs_root_signature);
    {
        size_t payload_len;
        uint8_t payload_buf[65536];
        serialize_transfer_payload(&f_tx, payload_buf, &payload_len);
        SHA256(payload_buf, payload_len, f_tx.tx_id);
    }
    prf_evaluate(f_tx.prf_output, &attacker_wallet.prf_key, f_tx.tx_id, COIN_ID_LEN, f_tx.client_root);
    {
        size_t zk_len = ZK_PROOF_MAX_LEN;
        generate_zk_prf_proof(f_tx.zk_proof, &zk_len, f_tx.tx_id, COIN_ID_LEN,
                              (const uint8_t *)attacker_wallet.prf_key.k, sizeof(attacker_wallet.prf_key.k), f_tx.client_root);
        f_tx.zk_proof_len = zk_len;
    }
    {
        uint8_t sig_payload[65536];
        size_t sig_payload_len;
        serialize_transfer_for_signature(&f_tx, sig_payload, &sig_payload_len);
        dilithium_sign(sig_payload, sig_payload_len, attacker_wallet.dilithium_privkey, f_tx.signature);
    }

    Operation ops[2];
    memset(ops, 0, sizeof(ops));
    ops[0].type = OP_TRANSFER_POINTER;
    ops[0].data.transfer_pointer = t_tx;
    ops[1].type = OP_TRANSFER_POINTER;
    ops[1].data.transfer_pointer = f_tx;

    /* Batch ZK-PRF data: 4-byte BE length prefix per proof (both proofs are
     * genuinely valid — the block is otherwise fully legitimate). */
    size_t batch_len = (4 + t_tx.zk_proof_len) + (4 + f_tx.zk_proof_len);
    uint8_t *batch_zk_proof = malloc(batch_len);
    uint8_t *batch_prf_outputs = malloc(2 * NULLIFIER_LEN);
    ASSERT_TRUE(batch_zk_proof && batch_prf_outputs, "Failed to allocate forgery batch buffers");
    {
        uint32_t be = htobe32((uint32_t)t_tx.zk_proof_len);
        memcpy(batch_zk_proof, &be, 4);
        memcpy(batch_zk_proof + 4, t_tx.zk_proof, t_tx.zk_proof_len);
        uint8_t *p2 = batch_zk_proof + 4 + t_tx.zk_proof_len;
        be = htobe32((uint32_t)f_tx.zk_proof_len);
        memcpy(p2, &be, 4);
        memcpy(p2 + 4, f_tx.zk_proof, f_tx.zk_proof_len);
        memcpy(batch_prf_outputs, t_tx.prf_output, NULLIFIER_LEN);
        memcpy(batch_prf_outputs + NULLIFIER_LEN, f_tx.prf_output, NULLIFIER_LEN);
    }

    Block *block = create_block(1, state->current_block_hash, ops, 2,
                                state->user_wallet.dilithium_pubkey,
                                state->user_wallet.dilithium_privkey,
                                12345, 2, batch_prf_outputs, batch_zk_proof, batch_len);
    ASSERT_TRUE(block != NULL, "Failed to create forgery block");

    /* The block is otherwise fully legitimate — exactly the stealth attack. */
    ASSERT_EQUAL_INT(verify_block_heavy_crypto(block), 0, "verify_block_heavy_crypto failed on forgery block");

    /* H-1 fix: the forged child must be rejected. */
    int apply_res = apply_block(state, block);
    ASSERT_EQUAL_INT(apply_res, -1, "apply_block MUST reject the intra-block forged transfer (fund-theft regression)");

    /* The victim's pointer must be intact and unspent. */
    Pointer *vp = hash_table_lookup(state->bc.pointer_table, victim_ptr.pointer_id, false);
    ASSERT_TRUE(vp != NULL, "Victim pointer must still exist after rejected block");
    ASSERT_TRUE(vp->spent == 0, "Victim pointer must remain unspent after rejected block");

    free(batch_zk_proof);
    free(batch_prf_outputs);
    free_block(block);
    for (size_t i = 0; i < state->bc.insert_order_count; i++) free(state->bc.insert_order[i]);
    free(state->bc.insert_order);
    client_state_destroy(state);
    free(state);
}

/**
 * @brief H-1 regression test: a chained child declaring ledger-mismatched
 *        input fields (lying end_subunit) MUST be rejected by the Pass 2
 *        re-validation.
 *
 * Pre-fix behavior: the chained child skipped validation and
 * update_transfer_state used the LEDGER's subunit range while trusting the
 * declared fields for nothing — a signed lie was silently accepted.
 */
static void test_pass2_revalidation_rejects_field_mismatch(void) {
    State *state = calloc(1, sizeof(State));
    ASSERT_TRUE(state != NULL, "Failed to allocate State");
    ASSERT_EQUAL_INT(client_state_init(state, 0), 0, "client_state_init failed");

    scl_db_delete_blocks_after(0);
    state->current_block_number = 0;
    memset(state->current_block_hash, 0, COIN_ID_LEN);
    state->bc.sync_epoch = 1;

    ASSERT_EQUAL_INT(create_user_wallet(&state->user_wallet), 1, "create_user_wallet failed");

    state->bc.insert_order_capacity = 4;
    state->bc.insert_order = calloc(state->bc.insert_order_capacity, sizeof(SCLCoin *));
    state->bc.insert_order_count = 0;

    SCLCoin coin;
    Pointer ptr;
    pthread_rwlock_wrlock(&state->bc.rwlock);
    forgery_fund_wallet(state, &state->user_wallet, 0x55, 1000 * SUBUNITS_PER_COIN, &coin, &ptr);
    pthread_rwlock_unlock(&state->bc.rwlock);

    const uint64_t transfer_amount = 100 * SUBUNITS_PER_COIN;

    /* Op 0: legitimate self-transfer (recipient = self, so the output pointer
     * belongs to the same wallet and the chained child is properly signed by
     * its true owner). */
    TransferData t_tx;
    forgery_build_transfer(state, &state->user_wallet, &ptr, &coin,
                           state->user_wallet.dilithium_pubkey, transfer_amount, 0x11, true, &t_tx);

    /* Op 1: chained child spending T's deterministic output pointer
     * [0, amount-1], but declaring end_subunit = amount (one past the real
     * end) while keeping the REAL pointer_id so the ledger lookup succeeds.
     * Fully signed by the true owner — only the declared fields lie. */
    Pointer child_input;
    memset(&child_input, 0, sizeof(Pointer));
    memcpy(child_input.parent_coin_id, coin.coin_id, COIN_ID_LEN);
    child_input.start_subunit = 0;
    child_input.end_subunit = transfer_amount - 1;
    memcpy(child_input.owner_address, ptr.owner_address, USER_ID_LEN);
    memcpy(child_input.prev_tx_hash, t_tx.tx_id, COIN_ID_LEN);
    {
        uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
        uint8_t *pd = pointer_data;
        memcpy(pd, child_input.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
        memcpy(pd, child_input.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
        uint64_t start_be = htobe64(child_input.start_subunit);
        memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
        uint64_t end_be = htobe64(child_input.end_subunit);
        memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
        memcpy(pd, child_input.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
        SHA256(pointer_data, sizeof(pointer_data), child_input.pointer_id);
    }
    /* The lie: declared range is [0, amount] while the real output ends at
     * amount-1. pointer_id stays the REAL one so Pass 2 finds the entry. */
    child_input.end_subunit = transfer_amount;

    TransferData c_tx;
    forgery_build_transfer(state, &state->user_wallet, &child_input, &coin,
                           state->user_wallet.dilithium_pubkey, 1 * SUBUNITS_PER_COIN, 0x22, false, &c_tx);
    /* prev_tx_hash must equal the parent's tx_id (the chaining trigger). */
    memcpy(c_tx.inputs[0].prev_tx_hash, t_tx.tx_id, COIN_ID_LEN);
    compute_inputs_merkle_root(c_tx.inputs, c_tx.num_inputs, c_tx.inputs_merkle_root);
    dilithium_sign(c_tx.inputs_merkle_root, COIN_ID_LEN, state->user_wallet.dilithium_privkey, c_tx.inputs_root_signature);
    {
        size_t payload_len;
        uint8_t payload_buf[65536];
        serialize_transfer_payload(&c_tx, payload_buf, &payload_len);
        SHA256(payload_buf, payload_len, c_tx.tx_id);
    }
    prf_evaluate(c_tx.prf_output, &state->user_wallet.prf_key, c_tx.tx_id, COIN_ID_LEN, c_tx.client_root);
    {
        size_t zk_len = ZK_PROOF_MAX_LEN;
        generate_zk_prf_proof(c_tx.zk_proof, &zk_len, c_tx.tx_id, COIN_ID_LEN,
                              (const uint8_t *)state->user_wallet.prf_key.k, sizeof(state->user_wallet.prf_key.k), c_tx.client_root);
        c_tx.zk_proof_len = zk_len;
    }
    {
        uint8_t sig_payload[65536];
        size_t sig_payload_len;
        serialize_transfer_for_signature(&c_tx, sig_payload, &sig_payload_len);
        dilithium_sign(sig_payload, sig_payload_len, state->user_wallet.dilithium_privkey, c_tx.signature);
    }

    Operation ops[2];
    memset(ops, 0, sizeof(ops));
    ops[0].type = OP_TRANSFER_POINTER;
    ops[0].data.transfer_pointer = t_tx;
    ops[1].type = OP_TRANSFER_POINTER;
    ops[1].data.transfer_pointer = c_tx;

    size_t batch_len = (4 + t_tx.zk_proof_len) + (4 + c_tx.zk_proof_len);
    uint8_t *batch_zk_proof = malloc(batch_len);
    uint8_t *batch_prf_outputs = malloc(2 * NULLIFIER_LEN);
    ASSERT_TRUE(batch_zk_proof && batch_prf_outputs, "Failed to allocate mismatch batch buffers");
    {
        uint32_t be = htobe32((uint32_t)t_tx.zk_proof_len);
        memcpy(batch_zk_proof, &be, 4);
        memcpy(batch_zk_proof + 4, t_tx.zk_proof, t_tx.zk_proof_len);
        uint8_t *p2 = batch_zk_proof + 4 + t_tx.zk_proof_len;
        be = htobe32((uint32_t)c_tx.zk_proof_len);
        memcpy(p2, &be, 4);
        memcpy(p2 + 4, c_tx.zk_proof, c_tx.zk_proof_len);
        memcpy(batch_prf_outputs, t_tx.prf_output, NULLIFIER_LEN);
        memcpy(batch_prf_outputs + NULLIFIER_LEN, c_tx.prf_output, NULLIFIER_LEN);
    }

    Block *block = create_block(1, state->current_block_hash, ops, 2,
                                state->user_wallet.dilithium_pubkey,
                                state->user_wallet.dilithium_privkey,
                                54321, 2, batch_prf_outputs, batch_zk_proof, batch_len);
    ASSERT_TRUE(block != NULL, "Failed to create mismatch block");
    ASSERT_EQUAL_INT(verify_block_heavy_crypto(block), 0, "verify_block_heavy_crypto failed on mismatch block");

    /* H-1 fix: Pass 2 re-validation must reject the lying declared fields. */
    int apply_res = apply_block(state, block);
    ASSERT_EQUAL_INT(apply_res, -1, "apply_block MUST reject chained op with ledger-mismatched declared fields");

    /* H-7 rollback: the parent's application must have been undone — the
     * original pointer is unspent again. */
    Pointer *pp = hash_table_lookup(state->bc.pointer_table, ptr.pointer_id, false);
    ASSERT_TRUE(pp != NULL, "Original pointer must be restored by rollback");
    ASSERT_TRUE(pp->spent == 0, "Original pointer must be unspent after rollback");

    free(batch_zk_proof);
    free(batch_prf_outputs);
    free_block(block);
    for (size_t i = 0; i < state->bc.insert_order_count; i++) free(state->bc.insert_order[i]);
    free(state->bc.insert_order);
    client_state_destroy(state);
    free(state);
}

/* ============================================================================ */
/* SECTION 3: MAIN TEST EXECUTION ENTRYPOINT                                    */
/* ============================================================================ */
/**
 * @brief Primary entrypoint for the core unit and integration test suite (`unit_tests.c`).
 *
 * @details
 * Sequentially invokes all 22 component test cases spanning hash tables, MMR trees,
 * lattice cryptography, SHAKE256 KATs, transaction utilities, block application,
 * intra-block forgery regression, and WASM FFI bridges.
 * Terminates via `exit(1)` immediately if any assertion fails.
 *
 * @return int Returns 0 on unconditional pass of all test suites.
 *
 * @complexity
 * - Time: ~1-2 seconds total execution.
 * - Space: Transient heap allocations per test scope.
 */
int main(void) {
    printf("[Suite] Starting Satocialist Cryptographic Ledger Test Suite...\n\n");

    /* Unit Tests - Section 1: Hash Tables */
    RUN_TEST(test_hash_table_init);
    RUN_TEST(test_hash_table_insert_resize);
    RUN_TEST(test_hash_table_migration_lookup);
    RUN_TEST(test_hash_table_removal_cleanup);

    /* Unit Tests - Section 2: Merkle Mountain Ranges */
    RUN_TEST(test_mmr_add_peaks);
    RUN_TEST(test_mmr_proof_generation_and_verification);

    /* Unit Tests - Section 3: Post-Quantum & Lattice Cryptography */
    RUN_TEST(test_crypto_dilithium_keypair_locks);
    RUN_TEST(test_shake256_known_answer_vectors);
    RUN_TEST(test_poly_uniform_with_bound);
    RUN_TEST(test_poly_mul_sparse);
    RUN_TEST(test_decompose_math);
    RUN_TEST(test_zk_prf_stern_verification);
    RUN_TEST(test_bdlop_commit_decrypt);

    /* Unit Tests - Section 4: Utility & Serialization */
    RUN_TEST(test_calculate_fee);
    RUN_TEST(test_process_block_data_serialization);

    /* Integration Tests - Section 5: Ledger Lifecycle & WebAssembly Bridges */
    RUN_TEST(test_integration_block_lifecycle);
    RUN_TEST(test_intra_block_forgery_rejected);
    RUN_TEST(test_pass2_revalidation_rejects_field_mismatch);
    RUN_TEST(test_integration_drift_cert_anchor_lifecycle);
    RUN_TEST(test_integration_supply_reward_invariant);
    RUN_TEST(test_integration_wasm_ffi_interface);
    RUN_TEST(test_integration_autopilot_logic);

    printf("[Suite] All test cases executed and passed successfully!\n");
    return 0;
}
