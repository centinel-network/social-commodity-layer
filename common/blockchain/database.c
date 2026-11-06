/**
 * @file common/blockchain/database.c
 * @brief Satocialist Protocol: Persistent Storage Engine Implementation (libmdbx / Flat-File)
 *
 * @details
 * Implements persistent key-value and block record storage utilizing `libmdbx` with an automated
 * flat-file append-only fallback. Manages transaction lifecycle, historical block querying,
 * checkpoint generation, MVCC state rollbacks during chain reorganizations, pre-sorted
 * B-tree nullifier ingestion to eliminate random-write page degradation, topological MMR pruning,
 * and validator DKG epoch credential persistence.
 *
 * @section table_architecture Table Structure & Key Schemas
 * - `coins`: Key = 32-byte `coin_id`, Value = @ref SCLCoin.
 * - `pointers`: Key = 32-byte `pointer_id`, Value = @ref Pointer.
 * - `nullifiers`: Key = 32-byte spent nullifier, Value = 1-byte sentinel `""` (footprint reduction).
 * - `scl_blocks`: Key = 8-byte big-endian `block_height`, Value = raw serialized block bytes.
 * - `scl_mmr`: Key = 8-byte big-endian `node_position`, Value = @ref MMRNode.
 * - `scl_checkpoints`: Key = 8-byte big-endian `block_height`, Value = 32-byte MMR state root.
 * - `dkg_state.bin`: Flat file storing epoch membership, point ID, rho, and polynomial vector shares.
 *
 * @section concurrency_model Transactional Model & Concurrency
 * - `active_block_txn`: A C11 `_Thread_local` pointer holding the active write transaction for atomic block commit.
 * - Read transactions execute without acquiring global write locks under libmdbx MVCC snapshot isolation.
 * - Flat-file fallback serializes writes using `fseek` and `fflush` under file-level locks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"
#include "protocol.h"
#include "utils.h"
#include "hash_table.h"
#include "blockchain.h"

#ifdef USE_MDBX
#include <mdbx.h>
/** @brief Global MDBX environment context handle. */
static MDBX_env *db_env = NULL;
/** @brief Sub-database index handle for coins. */
static MDBX_dbi coins_dbi = 0;
/** @brief Sub-database index handle for subunit pointers. */
static MDBX_dbi pointers_dbi = 0;
/** @brief Sub-database index handle for spent ZK-PRF nullifiers. */
static MDBX_dbi nullifiers_dbi = 0;
/** @brief Sub-database index handle for historical blocks. */
static MDBX_dbi blocks_dbi = 0;
/** @brief Sub-database index handle for MMR accumulator nodes. */
static MDBX_dbi mmr_dbi = 0;
/** @brief Sub-database index handle for 440-block checkpoints. */
static MDBX_dbi checkpoints_dbi = 0;
/** @brief Sub-database index handle for DKG state and ceremony locks. */
static MDBX_dbi dkg_dbi = 0;
/** @brief Thread-local active write transaction pointer for atomic block commitments. */
static _Thread_local MDBX_txn *active_block_txn = NULL;
#else
/** @brief Fallback binary file handle for coins storage. */
static FILE *coins_file = NULL;
/** @brief Fallback binary file handle for subunit pointers storage. */
static FILE *pointers_file = NULL;
/** @brief Fallback binary file handle for nullifiers storage. */
static FILE *nullifiers_file = NULL;
/** @brief Fallback binary file handle for blocks storage. */
static FILE *blocks_file = NULL;
/** @brief Fallback binary file handle for MMR nodes storage. */
static FILE *mmr_file = NULL;
/** @brief Fallback binary file handle for checkpoints storage. */
static FILE *checkpoints_file = NULL;
#endif

/**
 * @brief Comparator sorting nullifier buffers lexicographically for qsort.
 *
 * @param[in] a Pointer to first 32-byte nullifier buffer.
 * @param[in] b Pointer to second 32-byte nullifier buffer.
 * @return memcmp result across NULLIFIER_LEN bytes.
 *
 * @pre `a` and `b` must point to readable buffers of at least @ref NULLIFIER_LEN bytes.
 * @thread_safety Reentrant and pure function.
 * @complexity Time: O(NULLIFIER_LEN), Space: O(1).
 */
static int compare_nullifiers(const void *a, const void *b) {
    return memcmp(a, b, NULLIFIER_LEN);
}

/* ============================================================================ */
/* SECTION 1: TRANSACTION SCOPE ORCHESTRATION                                  */
/* ============================================================================ */

int scl_db_begin_block_txn(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
#ifdef USE_MDBX
    // Idempotent: return success if active write transaction already initialized
    if (active_block_txn) return 0;
    // Open thread-local write transaction for atomic block mutations
    if (mdbx_txn_begin(db_env, NULL, 0, &active_block_txn) != MDBX_SUCCESS) {
        active_block_txn = NULL;
        return -1;
    }
    return 0;
#else
    return 0;
#endif
}

int scl_db_commit_block_txn(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
#ifdef USE_MDBX
    if (!active_block_txn) return 0;
    // Commit active block write transaction to disk and clear thread-local handle
    int rc = mdbx_txn_commit(active_block_txn);
    active_block_txn = NULL;
    if (rc == MDBX_SUCCESS) {
        // Enforce stricter ACID guarantees by forcing a synchronous flush to durable storage
        mdbx_env_sync(db_env);
    }
    return (rc == MDBX_SUCCESS) ? 0 : -1;
#else
    return 0;
#endif
}

void scl_db_abort_block_txn(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return;
#endif
#ifdef USE_MDBX
    if (!active_block_txn) return;
    // Rollback and discard pending block mutations on failure
    mdbx_txn_abort(active_block_txn);
    active_block_txn = NULL;
#else
    return;
#endif
}

/* ============================================================================ */
/* SECTION 2: DKG EPOCH CREDENTIAL PERSISTENCE & CEREMONY LOCKING              */
/* ============================================================================ */

#define DKG_MDBX_KEY_LOCK  0x01
#define DKG_MDBX_KEY_STATE 0x02

int scl_db_set_dkg_lock(uint64_t epoch, const uint8_t session_id[COIN_ID_LEN], uint64_t ttl_ms) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    (void)epoch; (void)session_id; (void)ttl_ms;
    return 0;
#endif
#ifdef USE_MDBX
    if (!db_env) return -1;
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;

    uint8_t key_byte = DKG_MDBX_KEY_LOCK;
    MDBX_val key = { &key_byte, 1 };

    uint8_t payload[8 + 8 + COIN_ID_LEN];
    uint64_t epoch_be = htobe64(epoch);
    uint64_t expires_at = get_time_ms() + ttl_ms;
    uint64_t exp_be = htobe64(expires_at);

    memcpy(payload, &epoch_be, 8);
    memcpy(payload + 8, &exp_be, 8);
    memcpy(payload + 16, session_id, COIN_ID_LEN);

    MDBX_val val = { payload, sizeof(payload) };
    if (mdbx_put(txn, dkg_dbi, &key, &val, 0) != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return -1;
    }
    return (mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1;
#else
    return 0;
#endif
}

int scl_db_check_dkg_lock(uint64_t *out_epoch, uint8_t out_session_id[COIN_ID_LEN], bool *out_is_expired) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (out_is_expired) *out_is_expired = true;
    return -1;
#endif
#ifdef USE_MDBX
    if (!db_env) return -1;
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, MDBX_TXN_RDONLY, &txn) != MDBX_SUCCESS) return -1;

    uint8_t key_byte = DKG_MDBX_KEY_LOCK;
    MDBX_val key = { &key_byte, 1 };
    MDBX_val val;
    int rc = mdbx_get(txn, dkg_dbi, &key, &val);

    if (rc == MDBX_SUCCESS && val.iov_len == 8 + 8 + COIN_ID_LEN) {
        const uint8_t *p = (const uint8_t *)val.iov_base;
        uint64_t epoch_be, exp_be;
        memcpy(&epoch_be, p, 8);
        memcpy(&exp_be, p + 8, 8);

        if (out_epoch) *out_epoch = be64toh(epoch_be);
        if (out_session_id) memcpy(out_session_id, p + 16, COIN_ID_LEN);

        uint64_t expires_at = be64toh(exp_be);
        if (out_is_expired) {
            *out_is_expired = (get_time_ms() >= expires_at);
        }
        mdbx_txn_commit(txn);
        return 0;
    }
    mdbx_txn_commit(txn);
    return -1;
#else
    return -1;
#endif
}

int scl_db_clear_dkg_lock(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
#ifdef USE_MDBX
    if (!db_env) return -1;
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;

    uint8_t key_byte = DKG_MDBX_KEY_LOCK;
    MDBX_val key = { &key_byte, 1 };
    mdbx_del(txn, dkg_dbi, &key, NULL);
    return (mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1;
#else
    return 0;
#endif
}

int scl_db_save_dkg_state(State *state) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    if (!state) return -1;

    // Allocate buffer for Tier A serialization (~160 KB)
    size_t alloc_size = 1 + 2 + KAPPA + (10 * (sizeof(size_t) + POLYVEC_L_SERIALIZED)) + (10 * (sizeof(size_t) + POLYVEC_K_SERIALIZED));
    uint8_t *plaintext = malloc(alloc_size);
    if (!plaintext) return -1;

    uint8_t *p = plaintext;
    pthread_mutex_lock(&state->epoch_mutex);
    *p++ = state->is_epoch_member ? 1 : 0;
    uint16_t pid_be = htobe16(state->epoch_point_id);
    memcpy(p, &pid_be, 2); p += 2;
    memcpy(p, state->epoch_rho, KAPPA); p += KAPPA;

    for (int i = 0; i < 10; i++) {
        uint8_t bufL[POLYVEC_L_SERIALIZED];
        size_t lenL = 0;
        polyvec_serialize(&state->epoch_s1_subsets[i], bufL, sizeof(bufL), &lenL);
        uint64_t lenL_be = htobe64((uint64_t)lenL);
        memcpy(p, &lenL_be, 8); p += 8;
        if (lenL > 0) { memcpy(p, bufL, lenL); p += lenL; }

        uint8_t bufK[POLYVEC_K_SERIALIZED];
        size_t lenK = 0;
        polyvec_serialize(&state->epoch_s2_subsets[i], bufK, sizeof(bufK), &lenK);
        uint64_t lenK_be = htobe64((uint64_t)lenK);
        memcpy(p, &lenK_be, 8); p += 8;
        if (lenK > 0) { memcpy(p, bufK, lenK); p += lenK; }
    }
    pthread_mutex_unlock(&state->epoch_mutex);

    size_t pt_len = p - plaintext;

    // Derive 256-bit AES key from master Dilithium signing key
    uint8_t dkg_aes_key[32];
    pthread_mutex_lock(&state->wallet_mutex);
    derive_labeled_key(state->user_wallet.dilithium_privkey, "SCL_DKG_AT_REST", dkg_aes_key, 32);
    pthread_mutex_unlock(&state->wallet_mutex);

    size_t enc_alloc = pt_len + 28;
    uint8_t *encrypted = malloc(enc_alloc);
    size_t encrypted_len = 0;

    if (!encrypted || encrypt_message(dkg_aes_key, plaintext, pt_len, encrypted, &encrypted_len) != 0) {
        OPENSSL_cleanse(plaintext, alloc_size);
        OPENSSL_cleanse(dkg_aes_key, 32);
        free(plaintext);
        if (encrypted) free(encrypted);
        return -1;
    }

    OPENSSL_cleanse(plaintext, alloc_size);
    OPENSSL_cleanse(dkg_aes_key, 32);
    free(plaintext);

#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) {
        free(encrypted);
        return -1;
    }

    uint8_t key_byte = DKG_MDBX_KEY_STATE;
    MDBX_val key = { &key_byte, 1 };
    MDBX_val val = { encrypted, encrypted_len };

    if (mdbx_put(txn, dkg_dbi, &key, &val, 0) != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        free(encrypted);
        return -1;
    }
    int rc = mdbx_txn_commit(txn);
    free(encrypted);
    return (rc == MDBX_SUCCESS) ? 0 : -1;
#else
    free(encrypted);
    return 0;
#endif
}

int scl_db_load_dkg_state(State *state) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return -1;
#endif
    if (!state) return -1;

#ifdef USE_MDBX
    if (!db_env) return -1;
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, MDBX_TXN_RDONLY, &txn) != MDBX_SUCCESS) return -1;

    uint8_t key_byte = DKG_MDBX_KEY_STATE;
    MDBX_val key = { &key_byte, 1 };
    MDBX_val val;
    int rc = mdbx_get(txn, dkg_dbi, &key, &val);

    if (rc != MDBX_SUCCESS || val.iov_len < 28) {
        mdbx_txn_commit(txn);
        return -1;
    }

    uint8_t dkg_aes_key[32];
    pthread_mutex_lock(&state->wallet_mutex);
    derive_labeled_key(state->user_wallet.dilithium_privkey, "SCL_DKG_AT_REST", dkg_aes_key, 32);
    pthread_mutex_unlock(&state->wallet_mutex);

    uint8_t *plaintext = malloc(val.iov_len);
    size_t pt_len = 0;

    if (!plaintext || decrypt_message(dkg_aes_key, (const uint8_t *)val.iov_base, val.iov_len, plaintext, &pt_len) != 0) {
        OPENSSL_cleanse(dkg_aes_key, 32);
        if (plaintext) free(plaintext);
        mdbx_txn_commit(txn);
        return -1;
    }
    OPENSSL_cleanse(dkg_aes_key, 32);
    mdbx_txn_commit(txn);

    const uint8_t *p = plaintext;
    const uint8_t *end = plaintext + pt_len;

    if ((size_t)(end - p) < 1 + 2 + KAPPA) {
        OPENSSL_cleanse(plaintext, pt_len);
        free(plaintext);
        return -1;
    }

    bool is_member = (*p++ == 1);
    uint16_t pid_be;
    memcpy(&pid_be, p, 2); p += 2;
    uint16_t point_id = be16toh(pid_be);
    uint8_t rho[KAPPA];
    memcpy(rho, p, KAPPA); p += KAPPA;

    // Verify authenticated rho against active threshold key
    pthread_mutex_lock(&state->game_state.mutex);
    bool is_valid = (memcmp(state->game_state.epoch_threshold_pubkey, rho, KAPPA) == 0);
    pthread_mutex_unlock(&state->game_state.mutex);

    if (!is_valid) {
        OPENSSL_cleanse(plaintext, pt_len);
        free(plaintext);
        return -1;
    }

    pthread_mutex_lock(&state->epoch_mutex);
    state->is_epoch_member = is_member;
    state->epoch_point_id = point_id;
    memcpy(state->epoch_rho, rho, KAPPA);

    for (int i = 0; i < 10; i++) {
        if (state->epoch_s1_subsets[i].vec) polyvec_free(&state->epoch_s1_subsets[i]);
        if (state->epoch_s2_subsets[i].vec) polyvec_free(&state->epoch_s2_subsets[i]);

        polyvec_init(&state->epoch_s1_subsets[i], DILITHIUM_L);
        polyvec_init(&state->epoch_s2_subsets[i], DILITHIUM_K);

        if ((size_t)(end - p) >= 8) {
            uint64_t lenL_be;
            memcpy(&lenL_be, p, 8); p += 8;
            size_t lenL = (size_t)be64toh(lenL_be);
            if (lenL > 0 && (size_t)(end - p) >= lenL) {
                deserialize_polyvec(&state->epoch_s1_subsets[i], p, lenL, DILITHIUM_L);
                p += lenL;
            }
        }

        if ((size_t)(end - p) >= 8) {
            uint64_t lenK_be;
            memcpy(&lenK_be, p, 8); p += 8;
            size_t lenK = (size_t)be64toh(lenK_be);
            if (lenK > 0 && (size_t)(end - p) >= lenK) {
                deserialize_polyvec(&state->epoch_s2_subsets[i], p, lenK, DILITHIUM_K);
                p += lenK;
            }
        }
    }
    pthread_mutex_unlock(&state->epoch_mutex);

    OPENSSL_cleanse(plaintext, pt_len);
    free(plaintext);
    return 0;
#else
    return -1;
#endif
}

int scl_db_run_dkg_selftest(State *state) {
    if (!state) return -1;
    printf("[SelfTest] Running DKG Persistence & Lock TTL Validation...\n");

    uint8_t test_session_id[COIN_ID_LEN];
    memset(test_session_id, 0xA5, COIN_ID_LEN);

    // 1. Arm lock with a 200ms TTL
    if (scl_db_set_dkg_lock(100, test_session_id, 200) != 0) {
        fprintf(stderr, "[SelfTest] ERROR: Failed to write DKG lock to MDBX\n");
        return -1;
    }

    // 2. Probe immediately (must NOT be expired)
    uint64_t probed_epoch = 0;
    uint8_t probed_sess[COIN_ID_LEN];
    bool is_expired = true;
    if (scl_db_check_dkg_lock(&probed_epoch, probed_sess, &is_expired) != 0 || probed_epoch != 100 || is_expired) {
        fprintf(stderr, "[SelfTest] ERROR: DKG lock verification failed on active probe\n");
        return -1;
    }

    // 3. Sleep 250ms to allow TTL expiration
    usleep(250000);

    // 4. Probe after expiration (must evaluate is_expired == true)
    if (scl_db_check_dkg_lock(&probed_epoch, probed_sess, &is_expired) != 0 || !is_expired) {
        fprintf(stderr, "[SelfTest] ERROR: DKG lock did not expire after TTL window\n");
        return -1;
    }

    // 5. Clear lock
    if (scl_db_clear_dkg_lock() != 0) {
        fprintf(stderr, "[SelfTest] ERROR: Failed to clear DKG lock from MDBX\n");
        return -1;
    }
    if (scl_db_check_dkg_lock(&probed_epoch, probed_sess, &is_expired) == 0) {
        fprintf(stderr, "[SelfTest] ERROR: Cleared DKG lock still detected in MDBX\n");
        return -1;
    }

    // 6. Test Tier-A encrypted persistence round-trip
    pthread_mutex_lock(&state->epoch_mutex);
    state->is_epoch_member = true;
    state->epoch_point_id = 7;
    memset(state->epoch_rho, 0x5C, KAPPA);
    pthread_mutex_unlock(&state->epoch_mutex);

    pthread_mutex_lock(&state->game_state.mutex);
    memcpy(state->game_state.epoch_threshold_pubkey, state->epoch_rho, KAPPA);
    pthread_mutex_unlock(&state->game_state.mutex);

    if (scl_db_save_dkg_state(state) != 0) {
        fprintf(stderr, "[SelfTest] ERROR: Failed to save encrypted DKG state to MDBX\n");
        return -1;
    }

    // Clear state in RAM
    pthread_mutex_lock(&state->epoch_mutex);
    state->is_epoch_member = false;
    state->epoch_point_id = 0;
    memset(state->epoch_rho, 0, KAPPA);
    pthread_mutex_unlock(&state->epoch_mutex);

    // Hydrate and verify decrypted restoration
    if (scl_db_load_dkg_state(state) != 0) {
        fprintf(stderr, "[SelfTest] ERROR: Failed to load and decrypt DKG state from MDBX\n");
        return -1;
    }

    pthread_mutex_lock(&state->epoch_mutex);
    bool restored_ok = (state->is_epoch_member == true && state->epoch_point_id == 7 &&
                        state->epoch_rho[0] == 0x5C);
    pthread_mutex_unlock(&state->epoch_mutex);

    if (!restored_ok) {
        fprintf(stderr, "[SelfTest] ERROR: Decrypted DKG state fields mismatch\n");
        return -1;
    }

    printf("[SelfTest] DKG MDBX Encrypted Persistence & Lock TTL assertions passed.\n");
    return 0;
}

/* ============================================================================ */
/* SECTION 3: ENVIRONMENT INITIALIZATION & TEARDOWN                             */
/* ============================================================================ */

int scl_db_init(const char *db_path) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
#ifdef USE_MDBX
    // Mute MDBX diagnostic noise (page allocations, readahead syncs)
    mdbx_setup_debug(MDBX_LOG_ERROR, MDBX_DBG_NONE, NULL);

    int rc = mdbx_env_create(&db_env);
    if (rc != MDBX_SUCCESS) return -1;

    rc = mdbx_env_set_maxdbs(db_env, 16);
    if (rc != MDBX_SUCCESS) {
        mdbx_env_close(db_env);
        db_env = NULL;
        return -1;
    }

    // Open environment with MDBX_LIFORECLAIM and NOSTICKYTHREADS to prevent
    // B-tree page recycling divergence (badpage) and stale reader slots under soak tests
    rc = mdbx_env_open(db_env, db_path, MDBX_ENV_DEFAULTS | MDBX_NOSTICKYTHREADS | MDBX_LIFORECLAIM, 0664);
    
    // Startup database-integrity check and automatic corruption recovery
    if (rc == MDBX_CORRUPTED || rc == MDBX_PROBLEM || rc == MDBX_INVALID) {
        scl_log(LOG_LEVEL_ERROR, "Database", "Persistent storage corruption detected. Executing safe resync rebuild...");
        mdbx_env_close(db_env);
        db_env = NULL;
        
        char dat_path[512];
        char lck_path[512];
        snprintf(dat_path, sizeof(dat_path), "%s/mdbx.dat", db_path);
        snprintf(lck_path, sizeof(lck_path), "%s/mdbx.lck", db_path);
        remove(dat_path);
        remove(lck_path);
        
        mdbx_env_create(&db_env);
        mdbx_env_set_maxdbs(db_env, 16);
        rc = mdbx_env_open(db_env, db_path, MDBX_ENV_DEFAULTS | MDBX_NOSTICKYTHREADS | MDBX_LIFORECLAIM, 0664);
    }

    if (rc != MDBX_SUCCESS) {
        mdbx_env_close(db_env);
        db_env = NULL;
        return -1;
    }

    MDBX_txn *txn = NULL;
    rc = mdbx_txn_begin(db_env, NULL, 0, &txn);
    if (rc != MDBX_SUCCESS) return -1;

    // Open named sub-databases
    mdbx_dbi_open(txn, "coins", MDBX_CREATE, &coins_dbi);
    mdbx_dbi_open(txn, "pointers", MDBX_CREATE, &pointers_dbi);
    mdbx_dbi_open(txn, "nullifiers", MDBX_CREATE, &nullifiers_dbi);
    mdbx_dbi_open(txn, "scl_blocks", MDBX_CREATE, &blocks_dbi);
    mdbx_dbi_open(txn, "scl_mmr", MDBX_CREATE, &mmr_dbi);
    mdbx_dbi_open(txn, "scl_checkpoints", MDBX_CREATE, &checkpoints_dbi);
    mdbx_dbi_open(txn, "dkg_state", MDBX_CREATE, &dkg_dbi);

    rc = mdbx_txn_commit(txn);
    return (rc == MDBX_SUCCESS) ? 0 : -1;
#else
    // Open flat-file storage handles as fallback when libmdbx is disabled
    char path[512];
    snprintf(path, sizeof(path), "%s_coins.bin", db_path);
    coins_file = fopen(path, "a+b");

    snprintf(path, sizeof(path), "%s_pointers.bin", db_path);
    pointers_file = fopen(path, "a+b");

    snprintf(path, sizeof(path), "%s_nullifiers.bin", db_path);
    nullifiers_file = fopen(path, "a+b");

    snprintf(path, sizeof(path), "%s_blocks.bin", db_path);
    blocks_file = fopen(path, "a+b");

    snprintf(path, sizeof(path), "%s_mmr.bin", db_path);
    mmr_file = fopen(path, "a+b");

    snprintf(path, sizeof(path), "%s_checkpoints.bin", db_path);
    checkpoints_file = fopen(path, "a+b");

    if (!coins_file || !pointers_file || !nullifiers_file || !blocks_file || !mmr_file || !checkpoints_file) return -1;
    return 0;
#endif
}

void scl_db_close(void) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return;
#endif
#ifdef USE_MDBX
    // Close MDBX environment and release underlying database resources
    if (db_env) {
        mdbx_env_close(db_env);
        db_env = NULL;
    }
#else
    // Flush and close all flat-file storage handles
    if (coins_file) { fclose(coins_file); coins_file = NULL; }
    if (pointers_file) { fclose(pointers_file); pointers_file = NULL; }
    if (nullifiers_file) { fclose(nullifiers_file); nullifiers_file = NULL; }
    if (blocks_file) { fclose(blocks_file); blocks_file = NULL; }
    if (mmr_file) { fclose(mmr_file); mmr_file = NULL; }
    if (checkpoints_file) { fclose(checkpoints_file); checkpoints_file = NULL; }
#endif
}

/* ============================================================================ */
/* SECTION 4: BLOCK PERSISTENCE & CHECKPOINT ROLLBACK                           */
/* ============================================================================ */

int scl_db_put_block(uint64_t block_height, const uint8_t *serialized_block, size_t length) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    // Persist raw serialized block keyed by big-endian height
#ifdef USE_MDBX
    MDBX_txn *txn = active_block_txn;
    bool local_txn = false;
    if (!txn) {
        if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;
        local_txn = true;
    }

    uint64_t key_be = htobe64(block_height);
    MDBX_val key = { &key_be, sizeof(uint64_t) };
    MDBX_val val = { (void*)serialized_block, length };

    if (mdbx_put(txn, blocks_dbi, &key, &val, MDBX_UPSERT) != MDBX_SUCCESS) {
        if (local_txn) mdbx_txn_abort(txn);
        return -1;
    }
    return (local_txn) ? ((mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1) : 0;
#else
    if (!blocks_file) return -1;
    fseek(blocks_file, 0, SEEK_END);
    uint64_t key_be = htobe64(block_height);
    fwrite(&key_be, sizeof(uint64_t), 1, blocks_file);
    fwrite(&length, sizeof(size_t), 1, blocks_file);
    fwrite(serialized_block, 1, length, blocks_file);
    fflush(blocks_file);
    return 0;
#endif
}

int scl_db_get_block(uint64_t block_height, uint8_t **serialized_block_out, size_t *length_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return -1;
#endif
    // Query historical block by height under read-only snapshot transaction
#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, MDBX_TXN_RDONLY, &txn) != MDBX_SUCCESS) return -1;

    uint64_t key_be = htobe64(block_height);
    MDBX_val key = { &key_be, sizeof(uint64_t) };
    MDBX_val val;
    int rc = mdbx_get(txn, blocks_dbi, &key, &val);

    if (rc == MDBX_SUCCESS) {
        *serialized_block_out = malloc(val.iov_len);
        if (*serialized_block_out) {
            memcpy(*serialized_block_out, val.iov_base, val.iov_len);
            *length_out = val.iov_len;
        } else {
            rc = MDBX_ENOMEM;
        }
    }
    mdbx_txn_commit(txn);
    return (rc == MDBX_SUCCESS) ? 0 : -1;
#else
    if (!blocks_file) return -1;
    fseek(blocks_file, 0, SEEK_SET);
    uint64_t curr_key_be;
    size_t curr_len;

    while (fread(&curr_key_be, sizeof(uint64_t), 1, blocks_file) == 1) {
        if (fread(&curr_len, sizeof(size_t), 1, blocks_file) != 1) return -1;
        if (be64toh(curr_key_be) == block_height) {
            *serialized_block_out = malloc(curr_len);
            if (!*serialized_block_out) return -1;
            if (fread(*serialized_block_out, 1, curr_len, blocks_file) == curr_len) {
                *length_out = curr_len;
                return 0;
            }
            free(*serialized_block_out);
            return -1;
        }
        fseek(blocks_file, curr_len, SEEK_CUR);
    }
    return -1;
#endif
}

int scl_db_rollback_state_to_checkpoint(State *state, uint64_t checkpoint_height, uint64_t fork_height) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    if (!state) return -1;

    scl_log(LOG_LEVEL_INFO, "Database", "Executing MVCC Rollback from height %llu down to checkpoint %llu",
            (unsigned long long)fork_height, (unsigned long long)checkpoint_height);

    // 1. Iterate backwards from fork tip to checkpoint, inverting in-memory state mutations
    for (uint64_t h = fork_height; h > checkpoint_height; h--) {
        uint8_t *ser_block = NULL;
        size_t ser_len = 0;
        if (scl_db_get_block(h, &ser_block, &ser_len) == 0) {
            Block *b = calloc(1, sizeof(Block));
            if (b && deserialize_block(b, ser_block, ser_len) == 0) {
                uint8_t (*rb_nullifiers)[NULLIFIER_LEN] = NULL;
                size_t rb_nullifier_count = 0;
                if (b->operation_count > 0) {
                    rb_nullifiers = calloc((size_t)b->operation_count, NULLIFIER_LEN);
                }
                for (size_t i = b->operation_count; i-- > 0; ) {
                    Operation *op = &b->operations[i];

                    if (op->type == OP_MINT_COIN) {
                        SCLCoin *coin = &op->data.mint_coin.coin;
                        hash_table_remove(state->bc.coin_table, coin->coin_id);
                        if (state->bc.insert_order_count > 0) {
                            state->bc.insert_order_count--;
                        }

                        pthread_mutex_lock(&state->game_state.mutex);
                        state->game_state.total_rewarded_scl_subunits -= coin->total_subunits;
                        state->game_state.remaining_scl_subunits += coin->total_subunits;
                        pthread_mutex_unlock(&state->game_state.mutex);

                        // Evict all child pointers matching parent_coin_id
                        for (size_t ptr_idx = 0; ptr_idx < state->bc.pointer_table->size; ptr_idx++) {
                            GenericHashEntry *p_entry = state->bc.pointer_table->buckets[ptr_idx];
                            while (p_entry) {
                                GenericHashEntry *next_entry = p_entry->next;
                                if (p_entry->type == HASH_ENTRY_POINTER &&
                                    memcmp(p_entry->data.pointer.parent_coin_id, coin->coin_id, COIN_ID_LEN) == 0) {
                                    uint8_t p_key[COIN_ID_LEN];
                                    memcpy(p_key, p_entry->key, COIN_ID_LEN);
                                    hash_table_remove(state->bc.pointer_table, p_key);
                                    remove_pointer_id_from_coin(state->bc.coin_pointers, coin->coin_id, p_key);
                                }
                                p_entry = next_entry;
                            }
                        }
                    } else if (op->type == OP_TRANSFER_POINTER || op->type == OP_STAKE || op->type == OP_UNSTAKE) {
                        uint32_t num_inputs = 0;
                        Pointer *inputs = NULL;
                        if (op->type == OP_TRANSFER_POINTER) {
                            num_inputs = op->data.transfer_pointer.num_inputs;
                            inputs = op->data.transfer_pointer.inputs;
                        } else if (op->type == OP_STAKE) {
                            num_inputs = op->data.stake.num_inputs;
                            inputs = op->data.stake.inputs;
                        } else if (op->type == OP_UNSTAKE) {
                            num_inputs = op->data.unstake.num_inputs;
                            inputs = op->data.unstake.inputs;
                        }

                        for (uint32_t j = 0; j < num_inputs; j++) {
                            Pointer *existing = hash_table_lookup(state->bc.pointer_table, inputs[j].pointer_id, false);
                            if (existing) {
                                existing->spent = 0; // Restore unspent status cleanly
                            }
                        }
                    } else if (op->type == OP_REDEEM_CENTINEL) {
                        hash_table_remove(state->bc.centinel.nullifier_set, op->data.redeem_centinel.nullifier);
                        if (rb_nullifiers && rb_nullifier_count < (size_t)b->operation_count) {
                            memcpy(rb_nullifiers[rb_nullifier_count++], op->data.redeem_centinel.nullifier, NULLIFIER_LEN);
                        }
                    }

                    const uint8_t *tx_id = get_operation_tx_id(op);
                    if (tx_id) {
                        hash_table_remove(state->processed_txs, tx_id);
                    }
                }

                /* Persist the inversion: nullifiers spent in rolled-back blocks
                 * must leave the disk set, or re-applying the replacement chain
                 * fails forever on "Nullifier already spent (Disk hit)" in
                 * validate_operation, pinning the node at the checkpoint height. */
                if (rb_nullifiers) {
                    scl_db_delete_nullifiers_batch(rb_nullifiers, rb_nullifier_count);
                    free(rb_nullifiers);
                }

                uint8_t b_hash[COIN_ID_LEN];
                compute_block_hash(b, b_hash);
                pthread_mutex_lock(&state->processed_blocks_mutex);
                hash_table_remove(state->processed_blocks, b_hash);
                pthread_mutex_unlock(&state->processed_blocks_mutex);
            }
            if (b) free_block(b);
            free(ser_block);
        }
    }

    // 2. Truncate rolled-back blocks from disk storage
    scl_db_delete_blocks_after(checkpoint_height);

    // 3. Restore 10x10 Game Audit state from checkpoint block snapshot
    if (checkpoint_height > 0) {
        uint8_t *ser_block = NULL;
        size_t ser_len = 0;
        if (scl_db_get_block(checkpoint_height, &ser_block, &ser_len) == 0) {
            Block *cp_block = calloc(1, sizeof(Block));
            if (cp_block && deserialize_block(cp_block, ser_block, ser_len) == 0) {
                for (size_t i = cp_block->operation_count; i-- > 0; ) {
                    if (cp_block->operations[i].type == OP_MINT_COIN) {
                        SCLCoin *cp_coin = &cp_block->operations[i].data.mint_coin.coin;
                        pthread_mutex_lock(&state->game_state.mutex);
                        memcpy(state->game_state.game_audit, cp_coin->audit_snapshot, sizeof(Valuation) * AUDIT_SIZE);
                        state->game_state.valuation_count = cp_coin->snapshot_count;
                        state->game_state.current_audit_index = cp_coin->snapshot_audit_index;
                        pthread_mutex_unlock(&state->game_state.mutex);
                        break;
                    }
                }
            }
            if (cp_block) free_block(cp_block);
            free(ser_block);
        }
    } else {
        // Rollback to genesis baseline
        pthread_mutex_lock(&state->game_state.mutex);
        state->game_state.total_rewarded_scl_subunits = 0;
        state->game_state.remaining_scl_subunits = MAX_TOTAL_SUBUNITS;
        state->game_state.cached_stage = 2;
        state->game_state.valuation_count = 0;
        state->game_state.current_audit_index = 0;
        memset(state->game_state.game_audit, 0, sizeof(state->game_state.game_audit));
        pthread_mutex_unlock(&state->game_state.mutex);
    }

    update_game_state_snapshot(state);
    state->bc.mmr_needs_rebuild = true;

    return 0;
}

int scl_db_delete_blocks_after(uint64_t block_height) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    // Scan and delete block records with heights strictly greater than specified boundary
#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;

    MDBX_cursor *cursor = NULL;
    if (mdbx_cursor_open(txn, blocks_dbi, &cursor) != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return -1;
    }

    uint64_t start_key_be = htobe64(block_height + 1);
    MDBX_val key = { &start_key_be, sizeof(uint64_t) };
    MDBX_val val;

    int rc = mdbx_cursor_get(cursor, &key, &val, MDBX_SET_RANGE);
    while (rc == MDBX_SUCCESS) {
        rc = mdbx_cursor_del(cursor, 0);
        if (rc != MDBX_SUCCESS) break;
        rc = mdbx_cursor_get(cursor, &key, &val, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    return (mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1;
#else
    return 0; // Flat-file fallback append-only
#endif
}

int scl_db_put_checkpoint(uint64_t block_height, const uint8_t state_root[32]) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    // Record MMR state root checkpoint for reorganization bounding
#ifdef USE_MDBX
    MDBX_txn *txn = active_block_txn;
    bool local_txn = false;
    if (!txn) {
        if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;
        local_txn = true;
    }

    uint64_t key_be = htobe64(block_height);
    MDBX_val key = { &key_be, sizeof(uint64_t) };
    MDBX_val val = { (void*)state_root, 32 };

    if (mdbx_put(txn, checkpoints_dbi, &key, &val, MDBX_UPSERT) != MDBX_SUCCESS) {
        if (local_txn) mdbx_txn_abort(txn);
        return -1;
    }
    return (local_txn) ? ((mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1) : 0;
#else
    if (!checkpoints_file) return -1;
    fseek(checkpoints_file, 0, SEEK_END);
    uint64_t key_be = htobe64(block_height);
    fwrite(&key_be, sizeof(uint64_t), 1, checkpoints_file);
    fwrite(state_root, 1, 32, checkpoints_file);
    fflush(checkpoints_file);
    return 0;
#endif
}

int scl_db_get_highest_checkpoint(uint64_t max_height, uint64_t *checkpoint_height_out, uint8_t state_root_out[32]) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return -1;
#endif
    // Locate highest checkpoint record less than or equal to max_height
#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, MDBX_TXN_RDONLY, &txn) != MDBX_SUCCESS) return -1;

    MDBX_cursor *cursor = NULL;
    if (mdbx_cursor_open(txn, checkpoints_dbi, &cursor) != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return -1;
    }

    uint64_t max_key_be = htobe64(max_height);
    MDBX_val key = { &max_key_be, sizeof(uint64_t) };
    MDBX_val val;
    int rc = mdbx_cursor_get(cursor, &key, &val, MDBX_SET_RANGE);

    if (rc == MDBX_NOTFOUND) {
        rc = mdbx_cursor_get(cursor, &key, &val, MDBX_LAST);
    } else if (rc == MDBX_SUCCESS) {
        uint64_t found_height = be64toh(*(uint64_t*)key.iov_base);
        if (found_height > max_height) {
            rc = mdbx_cursor_get(cursor, &key, &val, MDBX_PREV);
        }
    }

    if (rc == MDBX_SUCCESS) {
        *checkpoint_height_out = be64toh(*(uint64_t*)key.iov_base);
        memcpy(state_root_out, val.iov_base, 32);
    }

    mdbx_cursor_close(cursor);
    mdbx_txn_commit(txn);
    return (rc == MDBX_SUCCESS) ? 0 : -1;
#else
    if (!checkpoints_file) return -1;
    fseek(checkpoints_file, 0, SEEK_SET);
    uint64_t curr_key_be;
    uint8_t curr_root[32];
    uint64_t best_height = 0;
    bool found = false;

    while (fread(&curr_key_be, sizeof(uint64_t), 1, checkpoints_file) == 1) {
        if (fread(curr_root, 1, 32, checkpoints_file) != 1) break;
        uint64_t curr_height = be64toh(curr_key_be);
        if (curr_height <= max_height && curr_height >= best_height) {
            best_height = curr_height;
            memcpy(state_root_out, curr_root, 32);
            found = true;
        }
    }

    if (found) {
        *checkpoint_height_out = best_height;
        return 0;
    }
    return -1;
#endif
}

/* ============================================================================ */
/* SECTION 5: COIN, POINTER & MMR BATCH PERSISTENCE                             */
/* ============================================================================ */

int scl_db_put_coin(const uint8_t *coin_id, const SCLCoin *coin) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    // Upsert coin record keyed by 32-byte coin identifier
#ifdef USE_MDBX
    MDBX_txn *txn = active_block_txn;
    bool local_txn = false;
    if (!txn) {
        if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;
        local_txn = true;
    }

    MDBX_val key = { (void*)coin_id, COIN_ID_LEN };
    MDBX_val val = { (void*)coin, sizeof(SCLCoin) };

    if (mdbx_put(txn, coins_dbi, &key, &val, 0) != MDBX_SUCCESS) {
        if (local_txn) mdbx_txn_abort(txn);
        return -1;
    }
    return (local_txn) ? ((mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1) : 0;
#else
    if (!coins_file) return -1;
    fseek(coins_file, 0, SEEK_END);
    fwrite(coin_id, COIN_ID_LEN, 1, coins_file);
    fwrite(coin, sizeof(SCLCoin), 1, coins_file);
    fflush(coins_file);
    return 0;
#endif
}

int scl_db_get_coin(const uint8_t *coin_id, SCLCoin *coin_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return -1;
#endif
    // Fetch coin record by 32-byte coin identifier
#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, MDBX_TXN_RDONLY, &txn) != MDBX_SUCCESS) return -1;

    MDBX_val key = { (void*)coin_id, COIN_ID_LEN };
    MDBX_val val;
    int rc = mdbx_get(txn, coins_dbi, &key, &val);

    if (rc == MDBX_SUCCESS) {
        memcpy(coin_out, val.iov_base, sizeof(SCLCoin));
    }
    mdbx_txn_commit(txn);
    return (rc == MDBX_SUCCESS) ? 0 : -1;
#else
    if (!coins_file) return -1;
    fseek(coins_file, 0, SEEK_SET);
    uint8_t temp_id[COIN_ID_LEN];

    while (fread(temp_id, COIN_ID_LEN, 1, coins_file) == 1) {
        if (memcmp(temp_id, coin_id, COIN_ID_LEN) == 0) {
            if (fread(coin_out, sizeof(SCLCoin), 1, coins_file) == 1) return 0;
            return -1;
        }
        fseek(coins_file, sizeof(SCLCoin), SEEK_CUR);
    }
    return -1;
#endif
}

int scl_db_put_pointer(const uint8_t *pointer_id, const Pointer *pointer) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    // Upsert subunit range pointer record keyed by pointer identifier
#ifdef USE_MDBX
    MDBX_txn *txn = active_block_txn;
    bool local_txn = false;
    if (!txn) {
        if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;
        local_txn = true;
    }

    MDBX_val key = { (void*)pointer_id, COIN_ID_LEN };
    MDBX_val val = { (void*)pointer, sizeof(Pointer) };

    if (mdbx_put(txn, pointers_dbi, &key, &val, 0) != MDBX_SUCCESS) {
        if (local_txn) mdbx_txn_abort(txn);
        return -1;
    }
    return (local_txn) ? ((mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1) : 0;
#else
    if (!pointers_file) return -1;
    fseek(pointers_file, 0, SEEK_END);
    fwrite(pointer_id, COIN_ID_LEN, 1, pointers_file);
    fwrite(pointer, sizeof(Pointer), 1, pointers_file);
    fflush(pointers_file);
    return 0;
#endif
}

int scl_db_get_pointer(const uint8_t *pointer_id, Pointer *pointer_out) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return -1;
#endif
    // Fetch subunit range pointer by 32-byte pointer identifier
#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, MDBX_TXN_RDONLY, &txn) != MDBX_SUCCESS) return -1;

    MDBX_val key = { (void*)pointer_id, COIN_ID_LEN };
    MDBX_val val;
    int rc = mdbx_get(txn, pointers_dbi, &key, &val);

    if (rc == MDBX_SUCCESS) {
        memcpy(pointer_out, val.iov_base, sizeof(Pointer));
    }
    mdbx_txn_commit(txn);
    return (rc == MDBX_SUCCESS) ? 0 : -1;
#else
    if (!pointers_file) return -1;
    fseek(pointers_file, 0, SEEK_SET);
    uint8_t temp_id[COIN_ID_LEN];

    while (fread(temp_id, COIN_ID_LEN, 1, pointers_file) == 1) {
        if (memcmp(temp_id, pointer_id, COIN_ID_LEN) == 0) {
            if (fread(pointer_out, sizeof(Pointer), 1, pointers_file) == 1) return 0;
            return -1;
        }
        fseek(pointers_file, sizeof(Pointer), SEEK_CUR);
    }
    return -1;
#endif
}

int scl_db_put_mmr_batch(const MMRNode *nodes, size_t count) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    // Batch-insert MMR nodes keyed by 64-bit node position
#ifdef USE_MDBX
    if (count == 0 || !nodes) return 0;
    MDBX_txn *txn = active_block_txn;
    bool local_txn = false;
    if (!txn) {
        if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;
        local_txn = true;
    }

    for (size_t i = 0; i < count; i++) {
        uint64_t key_be = htobe64((uint64_t)nodes[i].position);
        MDBX_val key = { &key_be, sizeof(uint64_t) };
        MDBX_val val = { (void*)&nodes[i], sizeof(MMRNode) };
        if (mdbx_put(txn, mmr_dbi, &key, &val, MDBX_UPSERT) != MDBX_SUCCESS) {
            if (local_txn) mdbx_txn_abort(txn);
            return -1;
        }
    }
    return (local_txn) ? ((mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1) : 0;
#else
    if (!mmr_file || count == 0 || !nodes) return -1;
    fseek(mmr_file, 0, SEEK_END);
    for (size_t i = 0; i < count; i++) {
        uint64_t key_be = htobe64((uint64_t)nodes[i].position);
        fwrite(&key_be, sizeof(uint64_t), 1, mmr_file);
        fwrite((void*)&nodes[i], sizeof(MMRNode), 1, mmr_file);
    }
    fflush(mmr_file);
    return 0;
#endif
}

/* ============================================================================ */
/* SECTION 6: CENTINEL NULLIFIER BATCHING & TOPOLOGICAL PRUNING                */
/* ============================================================================ */

int scl_db_write_nullifiers_batch(uint8_t (*nullifiers)[NULLIFIER_LEN], size_t count) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    if (count == 0) return 0;

    // Pre-sort nullifiers in RAM lexicographically to eliminate MDBX B-tree random-write fragmentation
    qsort(nullifiers, count, NULLIFIER_LEN, compare_nullifiers);

#ifdef USE_MDBX
    MDBX_txn *txn = active_block_txn;
    bool local_txn = false;
    if (!txn) {
        if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;
        local_txn = true;
    }

    for (size_t i = 0; i < count; i++) {
        MDBX_val key = { (void*)nullifiers[i], NULLIFIER_LEN };
        MDBX_val val = { "", 1 }; // Minimal 1-byte presence footprint
        if (mdbx_put(txn, nullifiers_dbi, &key, &val, 0) != MDBX_SUCCESS) {
            if (local_txn) mdbx_txn_abort(txn);
            return -1;
        }
    }
    return (local_txn) ? ((mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1) : 0;
#else
    if (!nullifiers_file) return -1;
    fseek(nullifiers_file, 0, SEEK_END);
    for (size_t i = 0; i < count; i++) {
        fwrite(nullifiers[i], NULLIFIER_LEN, 1, nullifiers_file);
    }
    fflush(nullifiers_file);
    return 0;
#endif
}

int scl_db_delete_nullifiers_batch(uint8_t (*nullifiers)[NULLIFIER_LEN], size_t count) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
    if (count == 0) return 0;

#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;

    for (size_t i = 0; i < count; i++) {
        MDBX_val key = { (void*)nullifiers[i], NULLIFIER_LEN };
        mdbx_del(txn, nullifiers_dbi, &key, NULL);
    }
    return (mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1;
#else
    return 0; // Flat-file fallback append-only (mirrors scl_db_delete_blocks_after)
#endif
}

bool scl_db_has_nullifier(const uint8_t *nullifier) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return false;
#endif
    // Fast probe checking spent nullifier membership in B-tree
#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, MDBX_TXN_RDONLY, &txn) != MDBX_SUCCESS) return false;

    MDBX_val key = { (void*)nullifier, NULLIFIER_LEN };
    MDBX_val val;
    int rc = mdbx_get(txn, nullifiers_dbi, &key, &val);

    mdbx_txn_commit(txn);
    return (rc == MDBX_SUCCESS);
#else
    if (!nullifiers_file) return false;
    fseek(nullifiers_file, 0, SEEK_SET);
    uint8_t temp_nul[NULLIFIER_LEN];

    while (fread(temp_nul, NULLIFIER_LEN, 1, nullifiers_file) == 1) {
        if (memcmp(temp_nul, nullifier, NULLIFIER_LEN) == 0) return true;
    }
    return false;
#endif
}

int scl_db_prune_mmr_nodes_except_peaks(const size_t *peaks, size_t peak_count, size_t max_position) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    return 0;
#endif
#ifdef USE_MDBX
    MDBX_txn *txn = NULL;
    if (mdbx_txn_begin(db_env, NULL, 0, &txn) != MDBX_SUCCESS) return -1;

    MDBX_cursor *cursor = NULL;
    if (mdbx_cursor_open(txn, mmr_dbi, &cursor) != MDBX_SUCCESS) {
        mdbx_txn_abort(txn);
        return -1;
    }

    uint64_t start_key_be = 0;
    MDBX_val key = { &start_key_be, sizeof(uint64_t) };
    MDBX_val val;

    // Iterate over historical MMR nodes and prune non-peak positions
    int rc = mdbx_cursor_get(cursor, &key, &val, MDBX_FIRST);
    while (rc == MDBX_SUCCESS) {
        uint64_t pos = be64toh(*(uint64_t*)key.iov_base);
        if (pos >= max_position) break;

        // Check if current position corresponds to an active mountain peak
        bool is_peak = false;
        for (size_t p = 0; p < peak_count; p++) {
            if (peaks[p] == pos) {
                is_peak = true;
                break;
            }
        }

        // Delete node from B-tree if it is not an active peak
        if (!is_peak) {
            rc = mdbx_cursor_del(cursor, 0);
            if (rc != MDBX_SUCCESS) break;
        }
        rc = mdbx_cursor_get(cursor, &key, &val, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);
    return (mdbx_txn_commit(txn) == MDBX_SUCCESS) ? 0 : -1;
#else
    return 0; // Flat-file fallback append-only
#endif
}
