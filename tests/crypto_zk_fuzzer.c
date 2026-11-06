/*
 * ==============================================================================
 * Satocialist Protocol: Post-Quantum Lattice & ZK Proof Cryptographic Fuzzer
 * ==============================================================================
 *
 * Target Subsystems:
 *   1. Zero-Knowledge Stern Circuit Verifier (zk_prf_verify, zk_batch_prf_verify)
 *   2. Centinel Shielded UTXO Verifier (zk_centinel_verify, generate_centinel_proof)
 *   3. Homomorphic BDLOP Lattice Commitments (bdlop_commit, bdlop_decrypt, bdlop_add)
 *   4. Threshold ML-DSA-87 / Dilithium5 Verifier (threshold_verify, sample_in_ball)
 *   5. Negacyclic Polynomial Arithmetic & Decompose Modules (decompose, poly_mul)
 * ==============================================================================
 */

#ifndef CRYPTO_ZK_FUZZER
#define CRYPTO_ZK_FUZZER 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#if defined(__linux__)
#include <malloc.h>
#elif defined(__APPLE__)
#include <malloc/malloc.h>
#endif

#ifdef _WIN32
#include <direct.h>
#define SCL_MKDIR(dir) _mkdir(dir)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define SCL_MKDIR(dir) mkdir(dir, 0777)
#endif

#include "constants.h"
#include "types.h"
#include "utils.h"
#include "crypto.h"
#include "blockchain.h"
#include "mmr.h"
#include "hash_table.h"
#include "client_state.h"
#include "scl_rpc_ffi_export.h"
#include "quantum_tvd.h"
#include "quantum_qsim.h"

#define NUM_CRYPTO_MODES 10

// Static State & Cryptographic Material for Seed Corpus & Replay Invariance
static int fuzzer_initialized = 0;
static uint8_t g_valid_dilithium_pk[DILITHIUM_PUBKEY_LEN];
static uint8_t g_valid_dilithium_sk[DILITHIUM_SECRETKEY_LEN];
static uint8_t g_valid_kyber_pk[KYBER_PUBKEY_LEN];
static uint8_t g_valid_kyber_sk[KYBER_SECRETKEY_LEN];
static PRFKey g_valid_prf_key;
static uint8_t g_canonical_rho[32];
static State g_fuzz_state;

static void write_seed_file(const char *dir, const char *name, const uint8_t *data, size_t len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    scl_log_set_level(LOG_LEVEL_FATAL); // Suppress terminal logging overhead

    const char *corpus_dir = "../crypto_zk_fuzzer_corpus";
    for (int i = 1; i < *argc; i++) {
        if ((*argv)[i][0] != '-') {
            corpus_dir = (*argv)[i];
            break;
        }
    }
    SCL_MKDIR(corpus_dir);

    // 1. Initialize Baseline Key Material and Static Fuzz State
    memset(&g_fuzz_state, 0, sizeof(State));
    blockchain_init(&g_fuzz_state.bc);

    pthread_mutex_init(&g_fuzz_state.mutex, NULL);
    pthread_mutex_init(&g_fuzz_state.ledger_mutex, NULL);
    pthread_mutex_init(&g_fuzz_state.wallet_mutex, NULL);
    pthread_mutex_init(&g_fuzz_state.epoch_mutex, NULL);
    pthread_mutex_init(&g_fuzz_state.threshold_mutex, NULL);
    pthread_mutex_init(&g_fuzz_state.user_wallet.utxo_mutex, NULL);
    pthread_mutex_init(&g_fuzz_state.game_state.mutex, NULL);

    dilithium_generate_keypair(g_valid_dilithium_pk, g_valid_dilithium_sk);
    kyber_generate_keypair(g_valid_kyber_pk, g_valid_kyber_sk);
    uint8_t prf_seed[32];
    memset(prf_seed, 0x5A, sizeof(prf_seed));
    prf_keygen(&g_valid_prf_key, prf_seed, 32);
    memcpy(g_canonical_rho, BDLOP_RHO_SEED, 32);

    memcpy(g_fuzz_state.user_wallet.dilithium_pubkey, g_valid_dilithium_pk, DILITHIUM_PUBKEY_LEN);
    memcpy(g_fuzz_state.user_wallet.dilithium_privkey, g_valid_dilithium_sk, DILITHIUM_SECRETKEY_LEN);
    memcpy(&g_fuzz_state.user_wallet.prf_key, &g_valid_prf_key, sizeof(PRFKey));

    // 2. Generate Seed 1: Valid Centinel ZK Proof Envelope (Mode 0x00)
    {
        uint64_t v_old = 1000;
        uint64_t amount = 600;
        uint64_t v_chg = 400;
        uint8_t r_old[32], r_tx[32], r_ch[32];
        memset(r_old, 0x11, 32);
        memset(r_tx, 0x22, 32);
        memset(r_ch, 0x33, 32);

        uint8_t mmr_root[32] = {0};
        MMRProof dummy_proof = {0};

        RedeemCentinelData *rc_data = calloc(1, sizeof(RedeemCentinelData));
        if (rc_data) {
            if (generate_centinel_proof(
                    g_valid_dilithium_pk, v_old, r_old,
                    g_valid_dilithium_pk, amount, r_tx,
                    g_valid_dilithium_pk, v_chg, r_ch,
                    &g_valid_prf_key, mmr_root, &dummy_proof, rc_data) == CRYPTO_SUCCESS) {

                size_t actual_body_sz = offsetof(RedeemCentinelData, zk_proof) + rc_data->zk_proof_len;
                size_t seed_sz = 1 + actual_body_sz;
                uint8_t *sbuf = malloc(seed_sz);
                if (sbuf) {
                    sbuf[0] = 0x00; // Mode: Centinel ZK
                    memcpy(sbuf + 1, rc_data, actual_body_sz);
                    write_seed_file(corpus_dir, "seed01_valid_centinel_zk.bin", sbuf, seed_sz);
                    free(sbuf);
                }
            }
            free(rc_data);
        }
    }

    // 3. Generate Seed 2: Valid Module-SIS ZK-PRF Stern Proof (Mode 0x01)
    {
        uint8_t prf_input[32];
        memset(prf_input, 0x77, 32);
        uint8_t crs_seed[32];
        memset(crs_seed, 0x88, 32);
        uint8_t y_out[NULLIFIER_LEN];
        prf_evaluate(y_out, &g_valid_prf_key, prf_input, 32, crs_seed);

        uint8_t *proof = malloc(ZK_PROOF_MAX_LEN);
        size_t proof_len = ZK_PROOF_MAX_LEN;

        if (proof && generate_zk_prf_proof(proof, &proof_len, prf_input, 32,
                                           (const uint8_t *)g_valid_prf_key.k, 1024,
                                           crs_seed) == CRYPTO_SUCCESS) {
            size_t seed_sz = 1 + 32 + 32 + NULLIFIER_LEN + 4 + proof_len;
            uint8_t *sbuf = malloc(seed_sz);
            if (sbuf) {
                sbuf[0] = 0x01; // Mode: ZK-PRF Stern
                uint8_t *p = sbuf + 1;
                memcpy(p, crs_seed, 32); p += 32;
                memcpy(p, prf_input, 32); p += 32;
                memcpy(p, y_out, NULLIFIER_LEN); p += NULLIFIER_LEN;
                uint32_t plen_be = htobe32((uint32_t)proof_len);
                memcpy(p, &plen_be, 4); p += 4;
                memcpy(p, proof, proof_len);
                write_seed_file(corpus_dir, "seed02_valid_zk_prf_stern.bin", sbuf, seed_sz);
                free(sbuf);
            }
        }
        if (proof) free(proof);
    }

    // 4. Generate Seed 3: Valid BDLOP Homomorphic Commitment (Mode 0x02)
    {
        uint8_t r_seed[32];
        memset(r_seed, 0x44, 32);
        BdlopCommitment comm;
        uint64_t val = 123456789ULL;

        if (bdlop_commit(g_canonical_rho, val, r_seed, &comm) == CRYPTO_SUCCESS) {
            size_t seed_sz = 1 + 32 + 8 + 32 + sizeof(BdlopCommitment);
            uint8_t *sbuf = malloc(seed_sz);
            if (sbuf) {
                sbuf[0] = 0x02; // Mode: BDLOP
                uint8_t *p = sbuf + 1;
                memcpy(p, g_canonical_rho, 32); p += 32;
                uint64_t val_be = htobe64(val);
                memcpy(p, &val_be, 8); p += 8;
                memcpy(p, r_seed, 32); p += 32;
                memcpy(p, &comm, sizeof(BdlopCommitment));
                write_seed_file(corpus_dir, "seed03_valid_bdlop_commitment.bin", sbuf, seed_sz);
                free(sbuf);
            }
        }
    }

    // 5. Generate Seed 4: Valid Threshold Dilithium Signature (Mode 0x03)
    {
        ThresholdKeygenData *keygen = calloc(1, sizeof(ThresholdKeygenData));
        if (keygen) {
            uint16_t pids[10] = {0,1,2,3,4,5,6,7,8,9};
            uint8_t kg_seed[32];
            memset(kg_seed, 0x99, 32);

            if (threshold_keygen(&g_fuzz_state, keygen, kg_seed, 32, pids, 10, 2) == CRYPTO_SUCCESS) {
                uint8_t msg[32];
                memset(msg, 0xAB, 32);
                uint8_t tr[32], mu[32];
                sha256_hash(keygen->pubkey, keygen->pubkey_len, tr);
                uint8_t mu_input[64];
                memcpy(mu_input, tr, 32);
                memcpy(mu_input + 32, msg, 32);
                sha256_hash(mu_input, 64, mu);

                ThresholdSignData *sign_data = calloc(1, sizeof(ThresholdSignData));
                if (sign_data) {
                    uint8_t s_seed[32];
                    memset(s_seed, 0xCD, 32);
                    int32_t bound_y = (GAMMA1 - TAU * ETA * NUM_SUBSETS) / 3 - TAU * MAX_S_PART_INF;

                    if (threshold_sign(&g_fuzz_state, sign_data, mu, 32, s_seed, 32, keygen->pubkey,
                       keygen->s1_shares, keygen->s2_shares, 0,
                       pids, pids, 10, 2, bound_y) == CRYPTO_SUCCESS) {

                        polyvec_t w1;
                        polyvec_init(&w1, DILITHIUM_K);
                        polyvec_high_bits(&w1, &sign_data->w, ALPHA);
                        uint8_t w1_packed[DILITHIUM_K * POLYW1_PACKEDBYTES];
                        for (size_t i = 0; i < DILITHIUM_K; i++) {
                            polyw1_pack(w1_packed + i * POLYW1_PACKEDBYTES, &w1.vec[i]);
                        }
                        uint8_t c_hash[32];
                        uint8_t hash_inp[32 + DILITHIUM_K * POLYW1_PACKEDBYTES];
                        memcpy(hash_inp, mu, 32);
                        memcpy(hash_inp + 32, w1_packed, sizeof(w1_packed));
                        sha256_hash(hash_inp, sizeof(hash_inp), c_hash);

                        polyvec_t h_vec;
                        polyvec_init(&h_vec, DILITHIUM_K);
                        polyvec_clear(&h_vec);

                        size_t sig_len = 0;
                        pack_signature(sign_data->signature, &sign_data->y, &h_vec, c_hash, &sig_len);
                        polyvec_free(&w1);
                        polyvec_free(&h_vec);

                        size_t seed_sz = 1 + PUBKEY_LEN + 32 + SIGNATURE_LEN;
                        uint8_t *sbuf = malloc(seed_sz);
                        if (sbuf) {
                            sbuf[0] = 0x03; // Mode: Threshold ML-DSA
                            uint8_t *p = sbuf + 1;
                            memcpy(p, keygen->pubkey, PUBKEY_LEN); p += PUBKEY_LEN;
                            memcpy(p, msg, 32); p += 32;
                            memcpy(p, sign_data->signature, SIGNATURE_LEN);
                            write_seed_file(corpus_dir, "seed04_valid_threshold_mldsa.bin", sbuf, seed_sz);
                            free(sbuf);
                        }
                    }
                    cleanup_sign_data(sign_data);
                    free(sign_data);
                }
                cleanup_keygen_data(keygen);
            }
            free(keygen);
        }
    }

    // 6. Generate Seed 5: Valid Polynomial Arithmetic & Decompose (Mode 0x04)
    {
        size_t seed_sz = 1 + 32 + 4 + 2 + 4;
        uint8_t *sbuf = malloc(seed_sz);
        if (sbuf) {
            sbuf[0] = 0x04; // Mode: Poly / Decomp
            uint8_t *p = sbuf + 1;
            memset(p, 0x33, 32); p += 32;
            uint32_t bound_be = htobe32(500);
            memcpy(p, &bound_be, 4); p += 4;
            uint16_t nonce_be = htobe16(42);
            memcpy(p, &nonce_be, 2); p += 2;
            uint32_t alpha_idx = htobe32(1); // ALPHA = 523776
            memcpy(p, &alpha_idx, 4);
            write_seed_file(corpus_dir, "seed05_valid_polynomial_arithmetic.bin", sbuf, seed_sz);
            free(sbuf);
        }
    }

    // 7. Generate Seed 6: Valid Dilithium5 & Kyber-512 (Mode 0x05)
    {
        uint8_t msg[32];
        memset(msg, 0x42, 32);
        uint8_t sig[DILITHIUM_SIGNATURE_LEN];
        dilithium_sign(msg, 32, g_valid_dilithium_sk, sig);

        uint8_t ct[KYBER_CIPHERTEXT_LEN];
        uint8_t ss[KYBER_SHARED_SECRET_LEN];
        kyber_encapsulate(g_valid_kyber_pk, ct, ss);

        size_t seed_sz = 1 + DILITHIUM_PUBKEY_LEN + 32 + DILITHIUM_SIGNATURE_LEN + KYBER_CIPHERTEXT_LEN + KYBER_SECRETKEY_LEN;
        uint8_t *sbuf = malloc(seed_sz);
        if (sbuf) {
            sbuf[0] = 0x05; // Mode: Dilithium & Kyber
            uint8_t *p = sbuf + 1;
            memcpy(p, g_valid_dilithium_pk, DILITHIUM_PUBKEY_LEN); p += DILITHIUM_PUBKEY_LEN;
            memcpy(p, msg, 32); p += 32;
            memcpy(p, sig, DILITHIUM_SIGNATURE_LEN); p += DILITHIUM_SIGNATURE_LEN;
            memcpy(p, ct, KYBER_CIPHERTEXT_LEN); p += KYBER_CIPHERTEXT_LEN;
            memcpy(p, g_valid_kyber_sk, KYBER_SECRETKEY_LEN);
            write_seed_file(corpus_dir, "seed06_valid_dilithium_kyber.bin", sbuf, seed_sz);
            free(sbuf);
        }
    }

    // 8. Generate Seed 7: Valid Symmetric AEAD, SipHash & HKDF (Mode 0x06)
    {
        uint8_t ss[32];
        memset(ss, 0x77, 32);
        uint64_t pn_be = htobe64(1);
        const char *test_msg = "SCL Cryptographic Fuzzer Payload Testing 2025";
        size_t msg_len = strlen(test_msg);

        size_t seed_sz = 1 + 32 + 8 + msg_len;
        uint8_t *sbuf = malloc(seed_sz);
        if (sbuf) {
            sbuf[0] = 0x06; // Mode: Symmetric AEAD & SipHash
            uint8_t *p = sbuf + 1;
            memcpy(p, ss, 32); p += 32;
            memcpy(p, &pn_be, 8); p += 8;
            memcpy(p, test_msg, msg_len);
            write_seed_file(corpus_dir, "seed07_valid_aead_siphash.bin", sbuf, seed_sz);
            free(sbuf);
        }
    }

    // 9. Generate Seed 8: Valid DKG Session Envelope (Mode 0x07)
    {
        size_t seed_sz = 1 + 2 + 10 * 32;
        uint8_t *sbuf = malloc(seed_sz);
        if (sbuf) {
            sbuf[0] = 0x07; // Mode: DKG Session
            sbuf[1] = 0x01; // local_pid
            sbuf[2] = 10;   // committee_count
            for (int i = 0; i < 10; i++) {
                memset(sbuf + 3 + i * 32, 0x10 + i, 32);
            }
            write_seed_file(corpus_dir, "seed08_valid_dkg_session.bin", sbuf, seed_sz);
            free(sbuf);
        }
    }

    // 10. Generate Seed 9: Valid Quantum TVD Drift Certificate (Mode 0x08)
    {
        uint8_t dummy_circuit[] = "OPENQASM 2.0; include \"qelib1.inc\"; qreg q[7]; h q[0]; cx q[0], q[1];";
        size_t circuit_len = strlen((char*)dummy_circuit);
        uint8_t beacon_seed[32];
        memset(beacon_seed, 0xEE, 32);

        QuantumDriftCertificate *cert = calloc(1, sizeof(QuantumDriftCertificate));
        if (cert) {
            if (quantum_tvd_audit_generate_certificate(&g_fuzz_state, dummy_circuit, circuit_len, NULL, 15000, beacon_seed, cert) == 0) {
                size_t seed_sz = 1 + sizeof(QuantumDriftCertificate);
                uint8_t *sbuf = malloc(seed_sz);
                if (sbuf) {
                    sbuf[0] = 0x08; // Mode: Quantum TVD
                    memcpy(sbuf + 1, cert, sizeof(QuantumDriftCertificate));
                    write_seed_file(corpus_dir, "seed09_valid_quantum_tvd.bin", sbuf, seed_sz);
                    free(sbuf);
                }
            }
            free(cert);
        }
    }

    fuzzer_initialized = 1;
    return 0;
}

static void dkg_session_free_internal_pointers(DKGSession *session) {
    if (!session) return;
    cleanup_keygen_data(&session->keygen);
    for (int i = 0; i < session->early_msg_count; i++) {
        if (session->early_msgs[i]) free(session->early_msgs[i]);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!fuzzer_initialized || size < 2) return 0;

    arena_reset(0);

    uint8_t mode = data[0] % NUM_CRYPTO_MODES;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    static _Thread_local RedeemCentinelData *rc_dyn = NULL;
    if (!rc_dyn) rc_dyn = calloc(1, sizeof(RedeemCentinelData));

    static _Thread_local Block *mock_block = NULL;
    if (!mock_block) mock_block = calloc(1, sizeof(Block));

    static _Thread_local Operation *mock_op = NULL;
    if (!mock_op) mock_op = calloc(1, sizeof(Operation));

    switch (mode) {
        // ====================================================================
        // MODE 0: Centinel Shielded ZK-Stern Verifier & Proof Engines
        // ====================================================================
        case 0: {
            if (rc_dyn) {
                size_t header_sz = offsetof(RedeemCentinelData, zk_proof);
                if (payload_len >= header_sz) {
                    memcpy(rc_dyn, payload, header_sz);
                    size_t proof_bytes = payload_len - header_sz;
                    if (rc_dyn->zk_proof_len > proof_bytes) {
                        rc_dyn->zk_proof_len = (uint32_t)proof_bytes;
                    }
                    if (rc_dyn->zk_proof_len > ZK_PROOF_MAX_LEN) {
                        rc_dyn->zk_proof_len = ZK_PROOF_MAX_LEN;
                    }
                    if (rc_dyn->zk_proof_len > 0) {
                        memcpy(rc_dyn->zk_proof, payload + header_sz, rc_dyn->zk_proof_len);
                    }
                } else {
                    memset(rc_dyn, 0, sizeof(RedeemCentinelData));
                    if (payload_len >= NULLIFIER_LEN) {
                        memcpy(rc_dyn->nullifier, payload, NULLIFIER_LEN);
                    }
                    size_t proof_bytes = MIN(payload_len, ZK_PROOF_MAX_LEN);
                    memcpy(rc_dyn->zk_proof, payload, proof_bytes);
                    rc_dyn->zk_proof_len = (uint32_t)proof_bytes;
                }

                zk_centinel_verify(rc_dyn);

                if (mock_op) {
                    mock_op->type = OP_REDEEM_CENTINEL;
                    memcpy(&mock_op->data.redeem_centinel, rc_dyn, sizeof(RedeemCentinelData));
                    // Bypass slow global mutexes in fuzzer loop to prevent deep contention locks
                    // scl_wallet_scan_centinel_op(&g_fuzz_state, mock_op);
                    mock_op->type = OP_CLAIM_VALIDATION;
                    memcpy(&mock_op->data.claim_validation.commitment, &rc_dyn->c_transfer, sizeof(BdlopCommitment));
                    memcpy(mock_op->data.claim_validation.pubkey, g_valid_dilithium_pk, PUBKEY_LEN);
                    // scl_wallet_scan_claim_op(&g_fuzz_state, mock_op);
                    g_fuzz_state.user_wallet.num_val_utxos = 0;
                }
            }

            break;
        }

        // ====================================================================
        // MODE 1: Module-SIS ZK-PRF Proof Verifier & Batch Engine
        // ====================================================================
        case 1: {
            uint8_t crs_seed[32];
            uint8_t prf_input[32];
            uint8_t y_out[NULLIFIER_LEN];
            memset(crs_seed, 0x88, 32);
            memset(prf_input, 0x77, 32);
            memset(y_out, 0xAA, NULLIFIER_LEN);

            if (payload_len >= 32) memcpy(crs_seed, payload, 32);
            if (payload_len >= 64) memcpy(prf_input, payload + 32, 32);
            if (payload_len >= 96) memcpy(y_out, payload + 64, NULLIFIER_LEN);

            const uint8_t *proof_buf = (payload_len >= 100) ? (payload + 100) : payload;
            size_t avail_proof_len = (payload_len >= 100) ? (payload_len - 100) : payload_len;
            if (payload_len >= 100) {
                uint32_t plen_be;
                memcpy(&plen_be, payload + 96, 4);
                uint32_t plen = be32toh(plen_be);
                if (plen > 0 && plen <= avail_proof_len) {
                    avail_proof_len = plen;
                }
            }

            // Direct PRF verification
            zk_prf_verify(proof_buf, avail_proof_len, crs_seed, prf_input, 32, y_out);

            // Direct PRF evaluation and key generation
            prf_evaluate(y_out, &g_valid_prf_key, prf_input, 32, crs_seed);
            static _Thread_local PRFKey fuzzed_key;
            memset(&fuzzed_key, 0, sizeof(fuzzed_key));
            memcpy(fuzzed_key.k, payload, MIN(payload_len, sizeof(fuzzed_key.k)));
            prf_evaluate(y_out, &fuzzed_key, prf_input, 32, crs_seed);

            if (payload_len >= KAPPA) {
                static _Thread_local PRFKey generated_key;
                prf_keygen(&generated_key, payload, payload_len);
            }

            // Block batch verifier and operation verification
            static _Thread_local uint8_t *batch_proof_buf = NULL;
            if (!batch_proof_buf) batch_proof_buf = malloc(ZK_PROOF_MAX_LEN + 4);

            static _Thread_local uint8_t s_y_out[NULLIFIER_LEN];
            memcpy(s_y_out, y_out, NULLIFIER_LEN);

            if (mock_block && mock_op && batch_proof_buf && avail_proof_len <= ZK_PROOF_MAX_LEN) {
                memset(mock_block, 0, sizeof(Block));
                memset(mock_op, 0, sizeof(Operation));

                mock_block->block_number = 1;
                mock_block->batch_tx_count = 1;
                mock_block->batch_prf_outputs = s_y_out;
                mock_block->batch_zk_proof_len = avail_proof_len + 4;

                uint32_t p_len_be = htobe32((uint32_t)avail_proof_len);
                memcpy(batch_proof_buf, &p_len_be, 4);
                memcpy(batch_proof_buf + 4, proof_buf, avail_proof_len);
                mock_block->batch_zk_proof = batch_proof_buf;

                mock_op->type = OP_TRANSFER_POINTER;
                memcpy(mock_op->data.transfer_pointer.client_root, crs_seed, 32);
                memcpy(mock_op->data.transfer_pointer.tx_id, prf_input, 32);
                mock_op->data.transfer_pointer.zk_proof_len = (uint32_t)avail_proof_len;
                mock_block->operation_count = 1;
                mock_block->operations = mock_op;

                verify_operation_heavy_crypto(mock_op);
                verify_block_heavy_crypto(mock_block);

                // Zero out to guarantee no dangling pointers survive across iterations
                memset(mock_block, 0, sizeof(Block));
                memset(mock_op, 0, sizeof(Operation));
            }
            break;
        }

        // ====================================================================
        // MODE 2: Homomorphic BDLOP Operations, Addition & Decryption
        // ====================================================================
        case 2: {
            uint8_t rho[32];
            memcpy(rho, g_canonical_rho, 32);
            if (payload_len >= 32) memcpy(rho, payload, 32);

            uint64_t v = 12345678ULL;
            if (payload_len >= 40) {
                uint64_t raw_v;
                memcpy(&raw_v, payload + 32, sizeof(uint64_t));
                v = be64toh(raw_v);
            }
            uint8_t r[32];
            memset(r, 0x44, 32);
            if (payload_len >= 72) memcpy(r, payload + 40, 32);

            BdlopCommitment comm1, comm2, comm_sum;
            if (bdlop_commit(rho, v, r, &comm1) == CRYPTO_SUCCESS) {
                uint64_t dec_out = 0;
                bdlop_decrypt(rho, &comm1, r, &dec_out);

                // Exercise homomorphic addition and sum decryption
                uint8_t r2[32];
                for (int i = 0; i < 32; i++) r2[i] = r[i] ^ 0x5A;
                if (bdlop_commit(rho, v >> 1, r2, &comm2) == CRYPTO_SUCCESS) {
                    bdlop_add(&comm1, &comm2, &comm_sum);
                }
            }

            // Decrypt arbitrary fuzzed commitments to stress bounds checking (aligned copy)
            if (payload_len >= sizeof(BdlopCommitment)) {
                static _Thread_local BdlopCommitment fuzzed_comm;
                memcpy(&fuzzed_comm, payload, sizeof(BdlopCommitment));
                uint64_t dec_fuzz = 0;
                bdlop_decrypt(rho, &fuzzed_comm, r, &dec_fuzz);
            }

            // Parameter expansion rejection sampling
            if (payload_len >= 32) {
                poly_t pa, pb;
                bdlop_expand_parameters(payload, &pa, &pb);
            }
            break;
        }

        // ====================================================================
        // MODE 3: Threshold Dilithium5 (ML-DSA-87) Verify, Hints & Packing
        // ====================================================================
        case 3: {
            static _Thread_local uint8_t pk[PUBKEY_LEN];
            memcpy(pk, g_valid_dilithium_pk, PUBKEY_LEN);
            if (payload_len >= PUBKEY_LEN) memcpy(pk, payload, PUBKEY_LEN);

            uint8_t msg[32];
            memset(msg, 0xAB, 32);
            if (payload_len >= PUBKEY_LEN + 32) memcpy(msg, payload + PUBKEY_LEN, 32);

            const uint8_t *sig = (payload_len >= PUBKEY_LEN + 64) ? (payload + PUBKEY_LEN + 32) : payload;
            size_t sig_len = (payload_len >= PUBKEY_LEN + 64) ? (payload_len - (PUBKEY_LEN + 32)) : payload_len;

            threshold_verify(msg, 32, sig, sig_len, pk, PUBKEY_LEN);

            uint8_t th_pk[PUBKEY_LEN];
            compute_threshold_pubkey(&g_fuzz_state, th_pk);

            poly_t ball_poly;
            sample_in_ball(&ball_poly, msg, 32);

            // Exercise unpack_h and count_nonzero_vec
            polyvec_t h_unpacked;
            if (polyvec_init_arena(&h_unpacked, DILITHIUM_K) == CRYPTO_SUCCESS) {
                uint8_t h_buf[POLYH_PACKEDBYTES];
                memset(h_buf, 0, sizeof(h_buf));
                memcpy(h_buf, payload, MIN(payload_len, sizeof(h_buf)));
                unpack_h(&h_unpacked, h_buf);
                count_nonzero_vec(&h_unpacked);
            }

            // Exercise polyw1_pack
            poly_t p_z;
            memset(&p_z, 0, sizeof(p_z));
            if (payload_len >= sizeof(poly_t)) {
                memcpy(&p_z, payload, sizeof(poly_t));
                uint8_t w1_packed[POLYW1_PACKEDBYTES];
                polyw1_pack(w1_packed, &p_z);
            }

            // Exercise poly_t1_unpack
            poly_t p_t1;
            if (payload_len >= POLYT1_PACKEDBYTES) {
                poly_t1_unpack(&p_t1, payload);
            }

            // Exercise hint generation and signature packing
            polyvec_t r_vec, w_vec, hint_vec;
            if (polyvec_init_arena(&r_vec, DILITHIUM_K) == CRYPTO_SUCCESS &&
                polyvec_init_arena(&w_vec, DILITHIUM_K) == CRYPTO_SUCCESS &&
                polyvec_init_arena(&hint_vec, DILITHIUM_K) == CRYPTO_SUCCESS) {
                for (size_t i = 0; i < DILITHIUM_K; i++) {
                    poly_uniform_eta(&r_vec.vec[i], msg, 32, (uint16_t)i);
                    poly_uniform_eta(&w_vec.vec[i], msg, 32, (uint16_t)(i + 10));
                }
                polyvec_make_hint(&hint_vec, &r_vec, &w_vec, ALPHA);

                // Exercise pack_signature
                static _Thread_local uint8_t packed_sig[SIGNATURE_LEN + 100];
                size_t out_sig_len = 0;
                polyvec_t z_vec;
                if (polyvec_init_arena(&z_vec, DILITHIUM_L) == CRYPTO_SUCCESS) {
                    for (size_t l = 0; l < DILITHIUM_L; l++) {
                        poly_uniform_with_bound(&z_vec.vec[l], msg, 32, (uint16_t)l, 500);
                    }
                    pack_signature(packed_sig, &z_vec, &hint_vec, msg, &out_sig_len);
                }
            }

            polyvec_t y_vec;
            if (polyvec_init_arena(&y_vec, DILITHIUM_L) == CRYPTO_SUCCESS) {
                generate_y_with_nonce(&y_vec, msg, 32, 1, 1000);
            }
            break;
        }

        // ====================================================================
        // MODE 4: Polynomial Ring Operations, Negacyclic Convolution & Decompose
        // ====================================================================
        case 4: {
            uint8_t seed[32];
            memset(seed, 0x33, 32);
            if (payload_len >= 32) memcpy(seed, payload, 32);

            int32_t bound = 500;
            if (payload_len >= 36) {
                uint32_t raw_b;
                memcpy(&raw_b, payload + 32, sizeof(uint32_t));
                bound = (int32_t)(be32toh(raw_b) % (1 << 20));
            }
            if (bound <= 0) bound = 1;

            uint16_t nonce = 42;
            if (payload_len >= 38) {
                uint16_t raw_n;
                memcpy(&raw_n, payload + 36, sizeof(uint16_t));
                nonce = be16toh(raw_n);
            }

            const int32_t valid_alphas[] = {1 << D, ALPHA, 190464, 523776};
            int32_t alpha = valid_alphas[1];
            if (payload_len >= 42) {
                uint32_t raw_a;
                memcpy(&raw_a, payload + 38, sizeof(uint32_t));
                alpha = valid_alphas[be32toh(raw_a) % 4];
            }

            poly_t p1, p2, p_res, p_sparse;
            memset(&p1, 0, sizeof(p1));
            memset(&p2, 0, sizeof(p2));

            poly_uniform_with_bound(&p1, seed, 32, nonce, bound);
            poly_uniform_eta(&p2, seed, 32, nonce + 1);

            poly_mul(&p_res, &p1, &p2);
            poly_mul_sparse(&p_sparse, &p1, &p2);
            poly_add(&p_res, &p1, &p2);

            poly_max_coeff(&p1);
            poly_max_coeff(&p_res);

            // Decomposition identity verification
            for (int i = 0; i < RING_DEG; i++) {
                int32_t r0 = 0, r1 = 0;
                decompose(p1.coeffs[i], alpha, &r0, &r1);
                int64_t recon = ((int64_t)r1 * alpha + r0) % Q;
                if (recon < 0) recon += Q;
                int64_t orig = (int64_t)p1.coeffs[i] % Q;
                if (orig < 0) orig += Q;
                assert(recon == orig && "Decomposition identity violated");
            }

            // Vector operations
            polyvec_t pv1, pv2, pv_out;
            if (polyvec_init_arena(&pv1, DILITHIUM_L) == CRYPTO_SUCCESS &&
                polyvec_init_arena(&pv2, DILITHIUM_L) == CRYPTO_SUCCESS &&
                polyvec_init_arena(&pv_out, DILITHIUM_L) == CRYPTO_SUCCESS) {

                for (size_t l = 0; l < DILITHIUM_L; l++) {
                    poly_uniform_with_bound(&pv1.vec[l], seed, 32, nonce + l, bound);
                    poly_uniform_eta(&pv2.vec[l], seed, 32, nonce + l + 10);
                }

                polyvec_add(&pv_out, &pv1, &pv2);
                polyvec_add_no_reduce(&pv_out, &pv1, &pv2);
                polyvec_copy(&pv_out, &pv1);
                polyvec_reduce(&pv_out);
                polyvec_high_bits(&pv_out, &pv1, alpha);
                check_norm_inf(&pv1, bound);
                polyvec_max_coeff(&pv1);
                check_polyvec_bounds(&pv1, "fuzz_pv1");

                matrix_t A_mat;
                A_mat.rows.len = DILITHIUM_K * DILITHIUM_L;
                if (polyvec_init_arena(&A_mat.rows, DILITHIUM_K * DILITHIUM_L) == CRYPTO_SUCCESS) {
                    expand_a(&A_mat, seed);
                    polyvec_t r_k;
                    if (polyvec_init_arena(&r_k, DILITHIUM_K) == CRYPTO_SUCCESS) {
                        matrix_vec_mul(&r_k, &A_mat, &pv1);
                        a_mul_vec(&r_k, &A_mat, &pv1);
                    }
                }

                static _Thread_local uint8_t ser_buf[POLYVEC_L_SERIALIZED];
                size_t ser_written = 0;
                if (polyvec_serialize(&pv1, ser_buf, sizeof(ser_buf), &ser_written) == CRYPTO_SUCCESS) {
                    deserialize_polyvec(&pv2, ser_buf, ser_written, DILITHIUM_L);
                }
                polyvec_clear(&pv1);
            }

            // 64-bit vector structures & unreduced multiplication
            polyvec64_t pv64_1, pv64_2, pv64_res;
            if (polyvec64_init_arena(&pv64_1, DILITHIUM_K) == CRYPTO_SUCCESS &&
                polyvec64_init_arena(&pv64_2, DILITHIUM_K) == CRYPTO_SUCCESS &&
                polyvec64_init_arena(&pv64_res, DILITHIUM_K) == CRYPTO_SUCCESS) {

                polyvec_t pvk;
                if (polyvec_init_arena(&pvk, DILITHIUM_K) == CRYPTO_SUCCESS) {
                    for (size_t k = 0; k < DILITHIUM_K; k++) {
                        poly_uniform_eta(&pvk.vec[k], seed, 32, nonce + k);
                    }
                    polyvec_to64(&pv64_1, &pvk);
                    polyvec_to64(&pv64_2, &pvk);
                    polyvec64_add(&pv64_res, &pv64_1, &pv64_2);
                    polyvec64_sub(&pv64_res, &pv64_1, &pv64_2);
                    check_norm_inf64(&pv64_res, 1000000);
                    polyvec64_reduce(&pvk, &pv64_res);

                    polyvec_poly_mul_unreduced(&pv64_res, &pvk, &p1);
                }
            }
            break;
        }

        // ====================================================================
        // MODE 5: Post-Quantum Digital Signatures (ML-DSA-87) & Key Encapsulation (ML-KEM-512)
        // ====================================================================
        case 5: {
            uint8_t d_msg[32];
            memset(d_msg, 0x42, 32);
            if (payload_len >= 32) memcpy(d_msg, payload, 32);

            // Verify with mutated input
            if (payload_len >= DILITHIUM_PUBKEY_LEN + 32 + DILITHIUM_SIGNATURE_LEN) {
                dilithium_verify(payload + DILITHIUM_PUBKEY_LEN, 32,
                                 payload + DILITHIUM_PUBKEY_LEN + 32,
                                 payload);
            }

            // Real Dilithium signing and verification with valid key
            static _Thread_local uint8_t generated_sig[DILITHIUM_SIGNATURE_LEN];
            size_t sign_len = MIN(payload_len, 256);
            if (sign_len == 0) sign_len = 1;
            if ((payload_len > 0 && (payload[0] & 0x07) == 0) || generated_sig[0] == 0) {
                if (dilithium_sign(payload, sign_len, g_valid_dilithium_sk, generated_sig)) {
                    dilithium_verify(payload, sign_len, generated_sig, g_valid_dilithium_pk);
                }
            } else {
                dilithium_verify(payload, sign_len, generated_sig, g_valid_dilithium_pk);
            }

            // Real Kyber encapsulation and decapsulation
            uint8_t ct[KYBER_CIPHERTEXT_LEN];
            uint8_t ss_enc[KYBER_SHARED_SECRET_LEN];
            uint8_t ss_dec[KYBER_SHARED_SECRET_LEN];
            if (kyber_encapsulate(g_valid_kyber_pk, ct, ss_enc)) {
                kyber_decapsulate(ct, g_valid_kyber_sk, ss_dec);
                assert(memcmp(ss_enc, ss_dec, KYBER_SHARED_SECRET_LEN) == 0);
            }

            // Decapsulate mutated / fuzzed ciphertext
            if (payload_len >= KYBER_CIPHERTEXT_LEN) {
                kyber_decapsulate(payload, g_valid_kyber_sk, ss_dec);
            }

            // Keypair generations on trigger byte
            if (payload_len > 0 && payload[0] == 0xAA) {
                static _Thread_local uint8_t ep_pk[KYBER_PUBKEY_LEN], ep_sk[KYBER_SECRETKEY_LEN];
                generate_ephemeral_kyber_keypair(ep_pk, ep_sk);
            }
            break;
        }

        // ====================================================================
        // MODE 6: Symmetric AEAD Framing, SipHash-2-4 & HKDF Key Derivations
        // ====================================================================
        case 6: {
            uint8_t shared_secret[32];
            memset(shared_secret, 0x77, 32);
            if (payload_len >= 32) memcpy(shared_secret, payload, 32);

            uint64_t packet_num = 1ULL;
            if (payload_len >= 40) {
                uint64_t raw_pn;
                memcpy(&raw_pn, payload + 32, sizeof(uint64_t));
                packet_num = be64toh(raw_pn);
            }
            const uint8_t *msg_data = (payload_len >= 40) ? (payload + 40) : payload;
            size_t msg_data_len = (payload_len >= 40) ? (payload_len - 40) : payload_len;

            uint8_t aes_key[32];
            uint8_t rpc_sip_key[16];
            uint8_t labeled_key[32];
            derive_symmetric_keys(shared_secret, aes_key);
            derive_rpc_siphash_key(shared_secret, rpc_sip_key);
            derive_labeled_key(shared_secret, "SCL fuzzer test label", labeled_key, 32);

            siphash24(msg_data, msg_data_len, rpc_sip_key);

            // Fee calculations across standard and halved rates
            calculate_fee(packet_num, false);
            calculate_fee(packet_num, true);

            // RPC Checksum evaluation (guaranteed >= 64-byte buffer to avoid OOB read)
            uint8_t dummy_rpc[64] = {0};
            size_t rpc_bytes = MIN(msg_data_len, sizeof(dummy_rpc));
            memcpy(dummy_rpc, msg_data, rpc_bytes);
            compute_rpc_checksum(dummy_rpc, 0, (uint32_t)(rpc_bytes >= 32 ? rpc_bytes - 32 : 0), rpc_sip_key);

            // Symmetric message and AEAD packet encryption/decryption
            if (msg_data_len > 0 && msg_data_len <= 1024) {
                size_t enc_mark = arena_mark();
                uint8_t *ct_out = arena_alloc(msg_data_len + 64);
                uint8_t *pt_out = arena_alloc(msg_data_len + 64);
                if (ct_out && pt_out) {
                    size_t ct_len = 0, pt_len = 0;
                    if (encrypt_message(aes_key, msg_data, msg_data_len, ct_out, &ct_len) == 0) {
                        decrypt_message(aes_key, ct_out, ct_len, pt_out, &pt_len);
                    }

                    size_t aead_ct_len = 0, aead_pt_len = 0;
                    if (encrypt_aead_packet(aes_key, packet_num, msg_data, msg_data_len, ct_out, &aead_ct_len, NULL, 0) == 0) {
                        decrypt_aead_packet(aes_key, packet_num, ct_out, aead_ct_len, pt_out, &aead_pt_len, NULL, 0);
                    }
                }
                arena_reset(enc_mark);
            }

            uint8_t nonce_out[32];
            generate_deterministic_nonce(g_valid_dilithium_sk, 32, msg_data, msg_data_len, nonce_out);
            uint8_t temp_tx_id[COIN_ID_LEN];
            uint8_t nonce8[8] = {1, 2, 3, 4, 5, 6, 7, 8};
            compute_temp_tx_id(nonce8, temp_tx_id);
            char hex_buf[65];
            bytes_to_hex(temp_tx_id, 32, hex_buf);
            is_zeroed(temp_tx_id, 32);
            secure_memcmp(temp_tx_id, nonce_out, 32);
            break;
        }

        // ====================================================================
        // MODE 7: Distributed Key Generation (DKG) Joint-RSS Protocol Steps
        // ====================================================================
        case 7: {
            static _Thread_local DKGSession *s_dkg_sess = NULL;
            if (!s_dkg_sess) s_dkg_sess = calloc(1, sizeof(DKGSession));
            if (s_dkg_sess) {
                // Call the specific internal un-allocator for DKG arrays before clearing
                dkg_session_free_internal_pointers(s_dkg_sess);
                memset(s_dkg_sess, 0, sizeof(DKGSession));
                s_dkg_sess->committee_count = 10;
                s_dkg_sess->reveals_received = 10;
                s_dkg_sess->commitments_received = 10;
                s_dkg_sess->shares_received = 9;
                s_dkg_sess->pubkey_frags_received = 9;
                s_dkg_sess->local_point_id = (payload_len > 0 ? (payload[0] % 10) : 0) + 1;

                for (size_t i = 0; i < 10; i++) {
                    if (payload_len >= (i + 1) * 32) {
                        memcpy(s_dkg_sess->reveals[i], payload + i * 32, 32);
                    } else {
                        memset(s_dkg_sess->reveals[i], 0x10 + i, 32);
                    }
                    memcpy(s_dkg_sess->committee_pubkeys[i], g_valid_dilithium_pk, DILITHIUM_PUBKEY_LEN);
                }

                dkg_compute_global_rho(s_dkg_sess);
                threshold_keygen_local_dealer(&g_fuzz_state, s_dkg_sess);
                dkg_verify_and_assemble_keys(&g_fuzz_state, s_dkg_sess);
                cleanup_keygen_data(&s_dkg_sess->keygen);
            }
            break;
        }

        // ====================================================================
        // MODE 8: Quantum TVD Audit Engine (Speed-Optimized)
        // ====================================================================
        case 8: {
            if (payload_len >= sizeof(QuantumDriftCertificate)) {
                QuantumDriftCertificate cert;
                memcpy(&cert, payload, sizeof(QuantumDriftCertificate));
                quantum_tvd_audit_verify_certificate(&cert, g_valid_dilithium_pk);
            }

            uint8_t beacon_seed[32];
            memset(beacon_seed, 0xEE, 32);
            if (payload_len >= 32) memcpy(beacon_seed, payload, 32);

            // Fuzzer bypass: The physical Quantum QPU noise simulator operates on massive
            // double-precision state vectors (QUANTUM_STATE_DIM). This is not lattice cryptography
            // and crushes execution speed. We bypass the physical sim but keep the cert verification above.
            break;
        }

        // ====================================================================
        // MODE 9: Consensus Operations, Mempool, Block Packaging & Consistency
        // ====================================================================
        case 9: {
            int target_num = payload_len > 0 ? (payload[0] % 100) : 42;
            int column_numbers[10];
            for (int i = 0; i < 10; i++) {
                column_numbers[i] = (payload_len > (size_t)i + 1) ? (payload[i + 1] % 100) : (i * 7) % 100;
            }
            uint8_t beacon[32];
            memset(beacon, 0x55, 32);
            if (payload_len >= 32) memcpy(beacon, payload, 32);

            quantum_check_number_in_column(target_num, column_numbers, 2, 2, beacon);

            // Exercise block hashing and serialization using heap mock_block
            if (mock_block) {
                memset(mock_block, 0, sizeof(Block));
                mock_block->block_number = (uint64_t)target_num;
                mock_block->entropy_seed = (uint64_t)target_num;
                memcpy(mock_block->prev_block_hash, beacon, 32);
                uint8_t b_hash[COIN_ID_LEN];
                compute_block_hash(mock_block, b_hash);
                memset(mock_block, 0, sizeof(Block));
            }

            // Exercise Merkle root computation over fuzzed inputs
            Pointer test_ptrs[2];
            memset(test_ptrs, 0, sizeof(test_ptrs));
            memcpy(test_ptrs[0].pointer_id, beacon, 32);
            memcpy(test_ptrs[1].pointer_id, beacon, 32);
            test_ptrs[1].pointer_id[0] ^= 0x01;
            uint8_t merkle_root[COIN_ID_LEN];
            compute_inputs_merkle_root(test_ptrs, 2, merkle_root);

            // Exercise operation comparisons using heap mock_op (zero stack footprint)
            if (mock_op) {
                memset(mock_op, 0, sizeof(Operation));
                mock_op->type = OP_MINT_COIN;
                memcpy(mock_op->data.mint_coin.coin.coin_id, beacon, COIN_ID_LEN);
                compare_operations(mock_op, mock_op);
                operation_equals(mock_op, mock_op);
                memset(mock_op, 0, sizeof(Operation));
            }

            SCLCoin mock_coin;
            memset(&mock_coin, 0, sizeof(SCLCoin));
            memcpy(mock_coin.coin_id, beacon, COIN_ID_LEN);
            mock_coin.total_subunits = 160000000ULL;
            mock_coin.remaining_subunits = 160000000ULL;
            uint8_t coin_hash[COIN_ID_LEN];
            compute_canonical_sclcoin_hash(&mock_coin, coin_hash);
            break;
        }
    }

    arena_reset(0);
    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
#ifdef __cplusplus
}
#endif

// Structure-Aware Custom Mutator for Cryptographic Envelopes
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (new_size < 2) return new_size;

    // Preserve mode identity 90% of the time to allow deep corpus evolution per mode
    uint8_t mode = (Data[0] < NUM_CRYPTO_MODES && (Seed % 10 != 0)) ? Data[0] : (Seed % NUM_CRYPTO_MODES);
    Data[0] = mode;

    switch (mode) {
        case 0: { // Centinel ZK
            size_t hdr_len = offsetof(RedeemCentinelData, zk_proof);
            if (new_size >= 1 + hdr_len) {
                size_t avail = new_size - 1 - hdr_len;
                uint32_t zk_len;
                if (Seed % 4 == 0) {
                    zk_len = (uint32_t)(sizeof(BdlopCommitment) + 32 + 96);
                } else if (Seed % 4 == 1) {
                    zk_len = (uint32_t)(sizeof(BdlopCommitment) + 32 + 3264);
                } else if (Seed % 4 == 2) {
                    zk_len = (uint32_t)(sizeof(BdlopCommitment) + 32 + 12576);
                } else {
                    zk_len = (uint32_t)(avail > 0 ? (Seed % avail) : 0);
                }
                if (zk_len > avail && avail > sizeof(BdlopCommitment)) zk_len = (uint32_t)avail;
                memcpy(Data + 1 + offsetof(RedeemCentinelData, zk_proof_len), &zk_len, sizeof(uint32_t));
            }
            break;
        }
        case 1: { // ZK-PRF Stern
            if (new_size >= 101) {
                size_t avail = new_size - 101;
                uint32_t plen;
                if (Seed % 4 == 0) plen = 128;
                else if (Seed % 4 == 1) plen = 1088;
                else if (Seed % 4 == 2) plen = 4512;
                else plen = (uint32_t)(avail > 0 ? (Seed % (avail + 1)) : 0);
                if (plen > avail) plen = (uint32_t)avail;
                uint32_t plen_be = htobe32(plen);
                memcpy(Data + 97, &plen_be, 4);
            }
            break;
        }
        case 2: { // BDLOP
            if (new_size >= 73) {
                if (Seed % 2 == 0) memcpy(Data + 1, g_canonical_rho, 32);
                if (Seed % 3 == 0) {
                    uint64_t edge_val = (Seed % 2 == 0) ? ((1ULL << 21) - 1) : ((1ULL << 42) - 1);
                    uint64_t edge_be = htobe64(edge_val);
                    memcpy(Data + 33, &edge_be, 8);
                }
            }
            break;
        }
        case 3: { // Threshold Dilithium
            if (new_size >= 1 + PUBKEY_LEN && Seed % 2 == 0) {
                memcpy(Data + 1, g_valid_dilithium_pk, PUBKEY_LEN);
            }
            break;
        }
        case 4: { // Poly / Decomp
            if (new_size >= 43) {
                uint32_t alphas[] = {1 << D, ALPHA, 190464, 523776};
                uint32_t chosen_alpha = htobe32(alphas[Seed % 4]);
                memcpy(Data + 39, &chosen_alpha, 4);
            }
            break;
        }
        case 5: { // Dilithium & Kyber
            if (new_size >= 1 + DILITHIUM_PUBKEY_LEN && Seed % 2 == 0) {
                memcpy(Data + 1, g_valid_dilithium_pk, DILITHIUM_PUBKEY_LEN);
            }
            break;
        }
        case 6: { // Symmetric AEAD & SipHash
            if (new_size >= 41) {
                uint64_t pn = htobe64((uint64_t)Seed);
                memcpy(Data + 33, &pn, 8);
            }
            break;
        }
        case 7: { // DKG Protocol
            if (new_size >= 1 + 2 + 10 * 32) {
                Data[1] = (Seed % 10) + 1;
                Data[2] = 10;
            }
            break;
        }
        case 8: { // Quantum TVD
            break;
        }
        case 9: { // Consensus & Mempool
            break;
        }
    }

    return new_size;
}
