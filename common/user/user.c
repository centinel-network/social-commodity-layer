/**
 * @file common/user/user.c
 * @brief Satocialist Protocol: User Account Implementation, Identity Binding & Grants
 *
 * @details
 * Implements participant user account initialization, cryptographic identity derivation,
 * resolution of public keys across local and network indices, and periodic validation
 * credit grant generation with BDLOP homomorphic lattice commitments.
 *
 * @section algorithmic_mechanics Algorithmic Mechanics
 * - User ID Derivation: `user_id = SHA256(dilithium_pubkey, 2592)`.
 * - Genesis UTXO Provisioning: Local node operator accounts are initialized with
 *   @ref INITIAL_VALIDATION_CREDITS (10 validations) concealed inside a BDLOP commitment:
 *   `c1 = a*s + e1`, `c2 = b*s + e2 + v(X)`.
 * - Periodic Validation Scaling: Granted credits follow:
 *   `credits = 1 + floor(staked_scl + fees_paid_scl)`,
 *   rewarding active consensus capital and network fee contribution.
 *
 * @section thread_safety Thread Safety Guarantees
 * - Individual accounts are protected by `user->mutex`.
 * - Global user registration and lookups synchronize via `state->mutex`.
 * - Local wallet UTXO modifications synchronize via `state->user_wallet.utxo_mutex`.
 */

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "user.h"
#include "game_state.h"
#include "crypto.h"
#include "protocol.h"
#include "blockchain.h"
#include "hash_table.h"
#include "network.h"
#include "client_network.h"
#include "consensus.h"
#include "utils.h"

/** @brief Global pointer reference to the local node operator's active User profile. */
extern User *global_user;

/* ============================================================================ */
/* 1. ACCOUNT INITIALIZATION & PROVISIONING                                     */
/* ============================================================================ */

int user_init(User *user, State *state, const uint8_t *pubkey) {
    if (!user || !state || !pubkey) {
        fprintf(stderr, "[User] Null pointer in user_init\n");
        return -1;
    }

    // Initialize per-user mutual exclusion primitive
    if (pthread_mutex_init(&user->mutex, NULL) != 0) {
        fprintf(stderr, "[User] Failed to initialize user mutex\n");
        return -1;
    }

    // Bind Dilithium5 public verification key (2,592 bytes)
    memcpy(user->dilithium_pubkey, pubkey, DILITHIUM_PUBKEY_LEN);

    // Derive deterministic 32-byte User ID: SHA256(pubkey, 2592)
    SHA256(user->dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user->user_id);
    
    user->last_validation = 0;

    // If account matches local node wallet, provision initial genesis validation credits
    if (memcmp(pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
        // Fast-path provisioning for fuzz testing harnesses
        ValidationUTXO init_utxo = {0};
        init_utxo.amount = INITIAL_VALIDATION_CREDITS;
        memcpy(init_utxo.pubkey, pubkey, PUBKEY_LEN);
        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
            size_t new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
            ValidationUTXO *new_utxos = realloc(state->user_wallet.val_utxos, new_cap * sizeof(ValidationUTXO));
            if (new_utxos) {
                state->user_wallet.val_utxos = new_utxos;
                state->user_wallet.cap_val_utxos = new_cap;
            }
        }
        state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++] = init_utxo;
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
#else
        // Deterministically derive initial blinding factor r from master private key
        uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
        memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
        int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_0");
        uint8_t r_init[32];
        SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, r_init);

        // Construct initial shielded ValidationUTXO record
        ValidationUTXO init_utxo = {0};
        init_utxo.amount = INITIAL_VALIDATION_CREDITS;
        memcpy(init_utxo.blinding_factor, r_init, 32);
        memcpy(init_utxo.pubkey, pubkey, PUBKEY_LEN);
        prf_keygen(&init_utxo.prf_key, r_init, 32);

        // Compute BDLOP homomorphic lattice commitment concealing the initial balance
        bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, INITIAL_VALIDATION_CREDITS, r_init, &init_utxo.commitment);
        
        // Evaluate PRF nullifier: N = PRF_k(SHA256(commitment))
        uint8_t commitment_hash[COIN_ID_LEN];
        SHA256((const uint8_t*)&init_utxo.commitment, sizeof(BdlopCommitment), commitment_hash);
        prf_evaluate(init_utxo.nullifier, &init_utxo.prf_key, commitment_hash, COIN_ID_LEN, commitment_hash);

        // Lock private wallet array and register initial UTXO if not already present
        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        bool already_exists = false;
        for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
            if (memcmp(&state->user_wallet.val_utxos[i].commitment, &init_utxo.commitment, sizeof(BdlopCommitment)) == 0) {
                already_exists = true;
                break;
            }
        }
        if (!already_exists) {
            // Dynamically expand local wallet validation UTXO array capacity
            if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
                size_t new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
                ValidationUTXO *new_utxos = realloc(state->user_wallet.val_utxos, new_cap * sizeof(ValidationUTXO));
                if (new_utxos) {
                    state->user_wallet.val_utxos = new_utxos;
                    state->user_wallet.cap_val_utxos = new_cap;
                } else {
                    scl_log(LOG_LEVEL_ERROR, "User", "Failed to reallocate val_utxos");
                }
            }
            if (state->user_wallet.num_val_utxos < state->user_wallet.cap_val_utxos) {
                state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++] = init_utxo;
            }
        }
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

        // Broadcast initial genesis validation claim on-chain to register commitment in MMR
        if (!already_exists) {
            Operation *claim_op = calloc(1, sizeof(Operation));
            if (claim_op) {
                claim_op->type = OP_CLAIM_VALIDATION;
                memcpy(&claim_op->data.claim_validation.commitment, &init_utxo.commitment, sizeof(BdlopCommitment));
                memcpy(claim_op->data.claim_validation.pubkey, pubkey, PUBKEY_LEN);
                dilithium_sign(commitment_hash, COIN_ID_LEN, state->user_wallet.dilithium_privkey, claim_op->data.claim_validation.signature);

                Message *claim_msg = calloc(1, sizeof(Message));
                if (claim_msg) {
                    claim_msg->type = MSG_PENDING_OPERATION;
                    claim_msg->length = serialize_operation(claim_op, claim_msg->payload, MAX_MESSAGE_SIZE);
                    
                    if (add_pending_operation(state, claim_op) == 0) {
                        p2p_broadcast(state, claim_msg);
                    }
                    free(claim_msg);
                }
                free(claim_op);
            }
            scl_log(LOG_LEVEL_INFO, "User", "Queued genesis claim for 10 Encrypted UTXO validations");
        }
#endif
    }

    // Log diagnostic key fingerprint
    char hex_pub[33];
    bytes_to_hex(user->dilithium_pubkey, 16, hex_pub);
    scl_log(LOG_LEVEL_INFO, "User", "Initialized user, Dilithium pubkey (first 16 bytes): %s", hex_pub);
    return 0;
}

/* ============================================================================ */
/* 2. ACCOUNT RESOLUTION & LOOKUP                                               */
/* ============================================================================ */

User *find_user_by_pubkey(State *state, const uint8_t *pubkey) {
    if (!state || !pubkey) {
        fprintf(stderr, "[User] ERROR: Invalid state or pubkey\n");
        return NULL;
    }

    // Derive 32-byte User ID for hash table lookup
    uint8_t user_id[USER_ID_LEN];
    SHA256(pubkey, DILITHIUM_PUBKEY_LEN, user_id);

    // Primary fast lookup: local user_table index
    pthread_mutex_lock(&state->mutex);
    User *user = hash_table_lookup(state->user_table, user_id, false);
    pthread_mutex_unlock(&state->mutex);

    if (user) {
        return user;
    }

    // Secondary fallback: query network and caches for full public key
    uint8_t temp_pubkey[PUBKEY_LEN];
    if (get_pubkey_by_userid(state, user_id, temp_pubkey)) {
        // Verified key matches queried identity; register account locally
        if (memcmp(temp_pubkey, pubkey, PUBKEY_LEN) == 0) {
            // Register account locally upon cryptographic verification
            if (register_user(state, user_id, pubkey) == 0) {
                pthread_mutex_lock(&state->mutex);
                user = hash_table_lookup(state->user_table, user_id, false);
                pthread_mutex_unlock(&state->mutex);
                if (user) {
                    return user;
                }
            }
        }
    }

    return NULL;
}

/* ============================================================================ */
/* 3. PERIODIC VALIDATION GRANTS & SCALING                                      */
/* ============================================================================ */

int grant_validation(State *state, User *user) {
    if (!state || !user) {
        fprintf(stderr, "[User] Null pointer in grant_validation\n");
        return 0;
    }

    time_t now = time(NULL);
    
    // Acquire user-level mutex to enforce the validation grant interval
    pthread_mutex_lock(&user->mutex);

    // Enforce hourly validation cooldown interval before calculating scaled grant
    if (now - user->last_validation >= VALIDATION_INTERVAL) {
        uint64_t total_validations = 1; // Default baseline grant: 1 validation/hr
        uint8_t threshold_pubkey[PUBKEY_LEN];
        
        // Dynamically compute committee threshold public key for stake lookup
        if (compute_threshold_pubkey(state, threshold_pubkey) != 0) {
            fprintf(stderr, "[User] ERROR: Failed to compute threshold_pubkey; granting default validation\n");
        } else {
            // Retrieve active staked capital and cumulative fees paid by this user
            uint64_t staked_subunits = calculate_staked_subunits(&state->bc, threshold_pubkey);
            uint64_t staked_scl = staked_subunits / SUBUNITS_PER_COIN;
            
            uint64_t fees_subunits = calculate_fees_paid_subunits(&state->bc, user->dilithium_pubkey);
            uint64_t fees_scl = fees_subunits / SUBUNITS_PER_COIN;
            
            // Economic scaling: 1 + floor(staked_scl + fees_scl)
            total_validations = 1 + (uint64_t)floor(staked_scl + fees_scl);
        }
        
        // Provision private UTXO records strictly for the local node operator's wallet
        if (memcmp(user->dilithium_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
            // Derive deterministic blinding factor r for this grant index
            uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
            memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
            int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", state->user_wallet.num_val_utxos);
            uint8_t r_mint[32];
            SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, r_mint);

            // Construct new shielded ValidationUTXO
            ValidationUTXO new_utxo = {0};
            new_utxo.amount = total_validations;
            memcpy(new_utxo.blinding_factor, r_mint, 32);
            memcpy(new_utxo.pubkey, user->dilithium_pubkey, PUBKEY_LEN);
            prf_keygen(&new_utxo.prf_key, r_mint, 32);
            bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, total_validations, r_mint, &new_utxo.commitment);
            
            // Evaluate PRF nullifier: N = PRF_k(SHA256(commitment))
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&new_utxo.commitment, sizeof(BdlopCommitment), commitment_hash);
            prf_evaluate(new_utxo.nullifier, &new_utxo.prf_key, commitment_hash, COIN_ID_LEN, commitment_hash);
            
            // Append newly minted UTXO to local wallet array
            pthread_mutex_lock(&state->user_wallet.utxo_mutex);
            // Dynamically expand local wallet validation UTXO capacity if limit reached
            if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
                size_t new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
                ValidationUTXO *new_utxos = realloc(state->user_wallet.val_utxos, new_cap * sizeof(ValidationUTXO));
                if (new_utxos) {
                    state->user_wallet.val_utxos = new_utxos;
                    state->user_wallet.cap_val_utxos = new_cap;
                } else {
                    fprintf(stderr, "[User] ERROR: Failed to reallocate val_utxos in grant_validation\n");
                }
            }
            state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++] = new_utxo;
            pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

            // Broadcast on-chain claim operation registering the commitment
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            Operation *claim_op = calloc(1, sizeof(Operation));
            if (claim_op) {
                claim_op->type = OP_CLAIM_VALIDATION;
                memcpy(&claim_op->data.claim_validation.commitment, &new_utxo.commitment, sizeof(BdlopCommitment));
                memcpy(claim_op->data.claim_validation.pubkey, user->dilithium_pubkey, PUBKEY_LEN);
                
                uint8_t comm_digest[COIN_ID_LEN];
                SHA256((const uint8_t*)&new_utxo.commitment, sizeof(BdlopCommitment), comm_digest);
                dilithium_sign(comm_digest, COIN_ID_LEN, state->user_wallet.dilithium_privkey, claim_op->data.claim_validation.signature);

                Message *claim_msg = calloc(1, sizeof(Message));
                if (claim_msg) {
                    claim_msg->type = MSG_PENDING_OPERATION;
                    claim_msg->length = serialize_operation(claim_op, claim_msg->payload, MAX_MESSAGE_SIZE);
                    
                    if (add_pending_operation(state, claim_op) == 0) {
                        p2p_broadcast(state, claim_msg);
                    }
                    free(claim_msg);
                }
                free(claim_op);
            }
#endif
            /* C-1/UX fix (split key): mirror the hourly grant to the shared testnet
             * identity so blank-connecting clients accrue Audited UTXO Validations
             * without ever receiving the operator's key. Recorded into the shared
             * pool under the testnet identity's own pubkey. */
            {
                uint8_t t_r_input[DILITHIUM_SECRETKEY_LEN + 32];
                memcpy(t_r_input, state->testnet_identity_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
                int t_tag_len = snprintf((char *)(t_r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", state->user_wallet.num_val_utxos);
                uint8_t t_r_mint[32];
                SHA256(t_r_input, DILITHIUM_SECRETKEY_LEN + t_tag_len, t_r_mint);

                ValidationUTXO t_utxo = {0};
                t_utxo.amount = total_validations;
                memcpy(t_utxo.blinding_factor, t_r_mint, 32);
                memcpy(t_utxo.pubkey, state->testnet_identity_wallet.dilithium_pubkey, PUBKEY_LEN);
                prf_keygen(&t_utxo.prf_key, t_r_mint, 32);
                bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, total_validations, t_r_mint, &t_utxo.commitment);

                uint8_t t_commitment_hash[COIN_ID_LEN];
                SHA256((const uint8_t*)&t_utxo.commitment, sizeof(BdlopCommitment), t_commitment_hash);
                prf_evaluate(t_utxo.nullifier, &t_utxo.prf_key, t_commitment_hash, COIN_ID_LEN, t_commitment_hash);

                pthread_mutex_lock(&state->user_wallet.utxo_mutex);
                if (state->user_wallet.num_val_utxos >= state->user_wallet.cap_val_utxos) {
                    size_t t_new_cap = state->user_wallet.cap_val_utxos ? state->user_wallet.cap_val_utxos * 2 : 16;
                    ValidationUTXO *t_new_utxos = realloc(state->user_wallet.val_utxos, t_new_cap * sizeof(ValidationUTXO));
                    if (t_new_utxos) {
                        state->user_wallet.val_utxos = t_new_utxos;
                        state->user_wallet.cap_val_utxos = t_new_cap;
                    }
                }
                if (state->user_wallet.num_val_utxos < state->user_wallet.cap_val_utxos) {
                    state->user_wallet.val_utxos[state->user_wallet.num_val_utxos++] = t_utxo;
                }
                pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
                Operation *t_claim_op = calloc(1, sizeof(Operation));
                if (t_claim_op) {
                    t_claim_op->type = OP_CLAIM_VALIDATION;
                    memcpy(&t_claim_op->data.claim_validation.commitment, &t_utxo.commitment, sizeof(BdlopCommitment));
                    memcpy(&t_claim_op->data.claim_validation.pubkey, state->testnet_identity_wallet.dilithium_pubkey, PUBKEY_LEN);

                    uint8_t t_comm_digest[COIN_ID_LEN];
                    SHA256((const uint8_t*)&t_utxo.commitment, sizeof(BdlopCommitment), t_comm_digest);
                    dilithium_sign(t_comm_digest, COIN_ID_LEN, state->testnet_identity_wallet.dilithium_privkey, t_claim_op->data.claim_validation.signature);

                    Message *t_claim_msg = calloc(1, sizeof(Message));
                    if (t_claim_msg) {
                        t_claim_msg->type = MSG_PENDING_OPERATION;
                        t_claim_msg->length = serialize_operation(t_claim_op, t_claim_msg->payload, MAX_MESSAGE_SIZE);
                        if (add_pending_operation(state, t_claim_op) == 0) {
                            p2p_broadcast(state, t_claim_msg);
                        }
                        free(t_claim_msg);
                    }
                    free(t_claim_op);
                }
#endif
            }
            fprintf(stderr, "[User] Queued claim for %llu Encrypted UTXO validations\n", total_validations);
        }
        
        // Update last validation timestamp to enforce cooldown interval
        user->last_validation = now;
        pthread_mutex_unlock(&user->mutex);
        return 1;
    }
    
    pthread_mutex_unlock(&user->mutex);
    return 0;
}

/* ============================================================================ */
/* 4. ACCOUNT DESTRUCTION & RESOURCE CLEANUP                                   */
/* ============================================================================ */

void destroy_user(User *user) {
    if (!user) {
        fprintf(stderr, "[User] Null user pointer in destroy_user\n");
        return;
    }
    // Release internal mutex synchronization primitive
    pthread_mutex_destroy(&user->mutex);
}
