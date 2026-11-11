/**
 * @file common/blockchain/blockchain.c
 * @brief Satocialist Protocol: Core Blockchain Ledger, Pointer State, and UTXO Subsystem Implementation
 *
 * @details
 * Implements core ledger mechanics, UTXO range pointer splits and merges, greedy asset selection,
 * Merkle Mountain Range (MMR) peak updating without O(N^2) rebuilds, balance calculations across
 * liquid and staked statuses, and transaction construction/broadcast orchestration.
 *
 * @section protocol_invariants Protocol Invariants Maintained
 * - Conservation of Subunit Volume (Lean 4 invariants.lean: Theorem 11): State mutations in
 *   @ref update_transfer_state conserve exact subunits: `inputs = transfer + fee + change`.
 * - Supply Hard-Cap Boundary (Lean 4 invariants.lean: Theorem 5): Total coins and subunits are strictly bounded
 *   by @ref MAX_TOTAL_SUBUNITS (2,560,000,000,000,000 subunits).
 * - Deterministic Double-Spend Prevention: Input pointers and ZK-PRF nullifiers are authenticated
 *   against RAM indices, Bloom filters, and persistent database storage prior to state mutation.
 *
 * @section concurrency_model Concurrency & Locking Rules
 * - Read/Write Locking: Access to `bc->coin_table`, `bc->pointer_table`, and `bc->coin_pointers` is guarded
 *   by `bc->rwlock`. Functions reading state acquire shared read locks (`pthread_rwlock_rdlock`);
 *   state transition functions acquire exclusive write locks (`pthread_rwlock_wrlock`).
 * - Lock Hierarchy: `state->mutex` -> `state->ledger_mutex` -> `bc->rwlock` -> `state->user_wallet.utxo_mutex`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include "blockchain.h"
#include "client_network.h"
#include "hash_table.h"
#include "crypto.h"
#include "mmr.h"
#include "consensus.h"
#include "network.h"
#include "game_state.h"
#include "database.h"
#include "constants.h"
#include "utils.h"

/* Route local diagnostic logging directly through structured telemetry filters */
#undef printf
#define printf(...) scl_printf(__VA_ARGS__)
#undef fprintf
#define fprintf(stream, ...) do { \
    if (stream == stderr) { \
        scl_log_stderr("Blockchain", __VA_ARGS__); \
    } else { \
        scl_fprintf(stream, __VA_ARGS__); \
    } \
} while(0)

/* ============================================================================ */
/* SECTION 1: LEDGER CONTAINER INITIALIZATION & TEARDOWN                        */
/* ============================================================================ */

/**
 * @brief Initializes the ledger structures, hash tables, MMR accumulators, and Centinel sub-state.
 *
 * @param[out] bc Pointer to uninitialized @ref Blockchain structure.
 * @return 0 on success; -1 on memory allocation failure or initialization error.
 *
 * @pre `bc` must point to allocated, writable memory.
 * @post All internal hash tables, MMR trees, Bloom filter arrays, and read-write locks are allocated and initialized.
 * @complexity Time: O(1), Space: O(1) baseline heap allocations.
 */
int blockchain_init(Blockchain *bc) {
    if (!bc) {
        fprintf(stderr, "[Blockchain] Invalid blockchain pointer\n");
        return -1;
    }

    // Allocate primary ledger tables and MMR accumulator structures
    bc->mmr = malloc(sizeof(MMR));
    bc->coin_table = malloc(sizeof(HashTable));
    bc->pointer_table = malloc(sizeof(HashTable));
    bc->coin_pointers = malloc(sizeof(HashTable));
    if (!bc->mmr || !bc->coin_table || !bc->pointer_table || !bc->coin_pointers) {
        fprintf(stderr, "[Blockchain] Memory allocation failed\n");
        goto cleanup;
    }

    if (mmr_init(bc->mmr) != 0) goto cleanup;
    if (hash_table_init(bc->coin_table, 4096, COIN_ID_LEN, NULL, NULL, NULL, NULL) != 0) goto cleanup;
    if (hash_table_init(bc->pointer_table, 4096, COIN_ID_LEN, NULL, NULL, NULL, NULL) != 0) goto cleanup;
    if (hash_table_init(bc->coin_pointers, 4096, COIN_ID_LEN, NULL, NULL, NULL, NULL) != 0) goto cleanup;
    bc->insert_order = NULL;
    bc->insert_order_count = 0;
    bc->insert_order_capacity = 0;
    bc->sync_epoch = 0;
    bc->mmr_needs_rebuild = true;
    
    // Block History is managed securely via libmdbx disk persistence
    
    // Initialize ZK-PRF Centinel State
    bc->centinel.nullifier_set = malloc(sizeof(HashTable));
    if (!bc->centinel.nullifier_set) {
        fprintf(stderr, "[Blockchain] Failed to allocate nullifier_set\n");
        goto cleanup;
    }
    if (hash_table_init(bc->centinel.nullifier_set, 1024, NULLIFIER_LEN, NULL, memcmp, NULL, NULL) != 0) goto cleanup;

    bc->centinel.validation_commitments = malloc(sizeof(MMR));
    if (!bc->centinel.validation_commitments) {
        fprintf(stderr, "[Blockchain] Failed to allocate validation_commitments\n");
        goto cleanup;
    }
    if (mmr_init(bc->centinel.validation_commitments) != 0) goto cleanup;

    bc->centinel.nullifier_bloom = calloc(1, NULLIFIER_BLOOM_BYTES);
    if (!bc->centinel.nullifier_bloom) {
        fprintf(stderr, "[Blockchain] Failed to allocate nullifier_bloom\n");
        goto cleanup;
    }
    pthread_mutex_init(&bc->centinel.bloom_mutex, NULL);
        
    if (pthread_rwlock_init(&bc->rwlock, NULL) != 0) goto cleanup;
    
    scl_log(LOG_LEVEL_INFO, "Blockchain", "Blockchain Initialized");
    return 0;

cleanup:
    if (bc->mmr) free(bc->mmr);
    if (bc->coin_table) free(bc->coin_table);
    if (bc->pointer_table) free(bc->pointer_table);
    if (bc->coin_pointers) free(bc->coin_pointers);
    if (bc->centinel.nullifier_set) free(bc->centinel.nullifier_set);
    if (bc->centinel.validation_commitments) free(bc->centinel.validation_commitments);
    return -1;
}

/* ============================================================================ */
/* SECTION 2: TEARDOWN & ASSET STRUCTURE CONSTRUCTORS                           */
/* ============================================================================ */

/**
 * @brief Deallocates all dynamic ledger tables, MMR trees, Bloom filter buffers, and locks.
 *
 * @param[in,out] bc Pointer to initialized @ref Blockchain structure.
 *
 * @pre No concurrent threads may be accessing `bc`.
 * @post All allocated dynamic heap memory is freed and internal pointers set to NULL.
 * @complexity Time: O(N) where N is total entries in tables, Space: O(1).
 */
void blockchain_destroy(Blockchain *bc) {
    if (!bc) return;

    if (bc->coin_table) {
        hash_table_destroy(bc->coin_table);
        free(bc->coin_table);
    }
    if (bc->mmr) {
        mmr_destroy(bc->mmr);
        free(bc->mmr);
    }
    if (bc->pointer_table) {
        hash_table_destroy(bc->pointer_table);
        free(bc->pointer_table);
    }
    if (bc->coin_pointers) {
        hash_table_destroy(bc->coin_pointers);
        free(bc->coin_pointers);
    }
    if (bc->centinel.nullifier_set) {
        hash_table_destroy(bc->centinel.nullifier_set);
        free(bc->centinel.nullifier_set);
    }
    if (bc->centinel.validation_commitments) {
        mmr_destroy(bc->centinel.validation_commitments);
        free(bc->centinel.validation_commitments);
    }
    if (bc->centinel.nullifier_bloom) {
        free(bc->centinel.nullifier_bloom);
    }
    pthread_mutex_destroy(&bc->centinel.bloom_mutex);
    if (bc->insert_order) {
        free(bc->insert_order);
    }
    
    // Block history memory automatically managed by libmdbx
    pthread_rwlock_destroy(&bc->rwlock);
}

/**
 * @brief Indexes a newly created Pointer into the pointer index and parent coin mapping tables.
 *
 * @param[in,out] bc Pointer to @ref Blockchain structure.
 * @param[in] pointer Pointer to the @ref Pointer structure to insert.
 *
 * @pre Caller must hold `bc->rwlock` in write mode (`pthread_rwlock_wrlock`).
 * @pre Pointer bounds must satisfy `start_subunit <= end_subunit < parent->total_subunits`.
 * @post Pointer is indexed into both `bc->pointer_table` and `bc->coin_pointers`.
 * @complexity Time: O(1) amortized, Space: O(1).
 */
void blockchain_add_pointer(Blockchain *bc, const Pointer *pointer) {
    if (!bc || !pointer) {
        fprintf(stderr, "[Blockchain] Invalid pointer or blockchain\n");
        return;
    }

    // Look up the coin
    SCLCoin *coin = hash_table_lookup(bc->coin_table, pointer->parent_coin_id, false);
    if (!coin) {
        fprintf(stderr, "[Blockchain] Parent coin not found\n");
        return;
    }

    // Validate pointer range
    if (pointer->start_subunit > pointer->end_subunit ||
        pointer->end_subunit >= coin->total_subunits) {
        fprintf(stderr, "[Blockchain] Invalid pointer range\n");
        return;
    }

    // Insertion operations
    hash_table_insert(bc->pointer_table, pointer->pointer_id, (void *)pointer, HASH_ENTRY_POINTER);
    add_pointer_id_to_coin(bc->coin_pointers, pointer->parent_coin_id, pointer->pointer_id);

    char hex_ptr_id[65];
    bytes_to_hex(pointer->pointer_id, COIN_ID_LEN, hex_ptr_id);
    printf("[Blockchain] Pointer added: pointer_id=%s\n", hex_ptr_id);
}

/**
 * @brief Constructs a new root SCLCoin asset structure with 160,000,000 atomic subunits.
 *
 * @param[in] creation_tx_hash 32-byte hash identifying the creating mint/recycled transaction.
 * @param[in] owner_pubkey 2,592-byte Dilithium5 public key of the initial recipient.
 * @return Fully initialized @ref SCLCoin structure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
SCLCoin create_coin(const uint8_t *creation_tx_hash, const uint8_t *owner_pubkey) {
    SCLCoin coin = {0};
    memcpy(coin.creation_tx_hash, creation_tx_hash, COIN_ID_LEN);
    
    // Hash the pubkey to a lightweight 32-byte address
    SHA256(owner_pubkey, PUBKEY_LEN, coin.owner_address);

    // Deterministically derive coin_id from creation transaction hash and owner public key
    uint8_t coin_id_data[COIN_ID_LEN + PUBKEY_LEN];
    memcpy(coin_id_data, creation_tx_hash, COIN_ID_LEN);
    memcpy(coin_id_data + COIN_ID_LEN, owner_pubkey, PUBKEY_LEN);
    SHA256(coin_id_data, COIN_ID_LEN + PUBKEY_LEN, coin.coin_id);
    
    // Initialize coin supply to default subunits and reset snapshot audit metrics
    coin.total_subunits = SUBUNITS_PER_COIN;
    coin.remaining_subunits = SUBUNITS_PER_COIN;
    coin.snapshot_count = 0;
    coin.snapshot_audit_index = 0;
    
    return coin;
}

/* ============================================================================ */
/* SECTION 3: GREEDY ASSET SELECTION & TRANSACTION ORCHESTRATION                */
/* ============================================================================ */

/**
 * @brief Greedily selects unspent input pointers satisfying a target subunit amount.
 *
 * @details
 * Filters out pointers locked in mempool if `exclude_mempool == true`. Sorts candidate pointers
 * descending by subunit capacity and selects the minimum number of pointers (up to @ref MAX_SELECTED_POINTERS)
 * required to satisfy `target_subunits`.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the owner.
 * @param[in] target_subunits Minimum required cumulative subunits (principal + fee).
 * @param[out] num_selected Count of selected pointers.
 * @param[in] select_staked Flag selecting staked pointers (`true`) or liquid pointers (`false`).
 * @param[in] exclude_mempool Flag filtering out pointers locked in pending mempool transactions.
 * @return Dynamically allocated array of @ref Pointer structures on success (caller frees); NULL on insufficient balance.
 *
 * @complexity Time: O(N log N) where N is eligible pointers, Space: O(N) heap allocations.
 */
Pointer *select_pointers(State *state, const uint8_t pubkey[PUBKEY_LEN], uint64_t target_subunits, size_t *num_selected, bool select_staked, bool exclude_mempool) {
    if (!state || !pubkey || !num_selected) {
        fprintf(stderr, "[Blockchain] Invalid parameters in select_pointers\n");
        return NULL;
    }

    uint8_t user_id[USER_ID_LEN];
    SHA256(pubkey, PUBKEY_LEN, user_id);

    Blockchain *bc = &state->bc;

    uint8_t (*locked_pointers)[COIN_ID_LEN] = NULL;
    size_t locked_count = 0;

    // Identify and exclude pointers already committed to pending mempool operations
    if (exclude_mempool) {
        uint32_t max_pending = state->config.max_pending_ops_config > 0 ? state->config.max_pending_ops_config : 10000;
        locked_pointers = malloc(max_pending * MAX_INPUTS * COIN_ID_LEN);
        if (!locked_pointers) {
            fprintf(stderr, "[Blockchain] Memory allocation failed for locked_pointers\n");
            return NULL;
        }
        for (int i = 0; i < MAX_PENDING_OPS; i++) {
            Operation *pop = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
            if (pop) {
                uint32_t p_num = 0;
                const Pointer *p_in = NULL;

                if (pop->type == OP_TRANSFER_POINTER) {
                    p_num = pop->data.transfer_pointer.num_inputs;
                    p_in = pop->data.transfer_pointer.inputs;
                } else if (pop->type == OP_STAKE) {
                    p_num = pop->data.stake.num_inputs;
                    p_in = pop->data.stake.inputs;
                } else if (pop->type == OP_UNSTAKE) {
                    p_num = pop->data.unstake.num_inputs;
                    p_in = pop->data.unstake.inputs;
                } else if (pop->type == OP_APPLY_DRIFT_CERT) {
                    p_num = pop->data.apply_drift_cert.num_inputs;
                    p_in = pop->data.apply_drift_cert.inputs;
                }

                for (uint32_t k = 0; k < p_num; k++) {
                    if (locked_count < max_pending * MAX_INPUTS) {
                        memcpy(locked_pointers[locked_count++], p_in[k].pointer_id, COIN_ID_LEN);
                    }
                }
            }
        }
    }

    pthread_rwlock_rdlock(&bc->rwlock);
    Pointer **available = malloc(bc->pointer_table->count * sizeof(Pointer *));
    if (!available) {
        pthread_rwlock_unlock(&bc->rwlock);
        fprintf(stderr, "[Blockchain] Memory allocation failed\n");
        return NULL;
    }

    // Scan pointer table for unspent candidates matching owner and staking criteria
    size_t avail_count = 0;
    for (size_t i = 0; i < bc->pointer_table->size; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER &&
                memcmp(entry->data.pointer.owner_address, user_id, USER_ID_LEN) == 0 &&
                !entry->data.pointer.spent &&
                entry->data.pointer.staked == select_staked) {
                
                bool is_locked = false;
                if (exclude_mempool) {
                    for (size_t k = 0; k < locked_count; k++) {
                        if (memcmp(entry->data.pointer.pointer_id, locked_pointers[k], COIN_ID_LEN) == 0) {
                            is_locked = true;
                            break;
                        }
                    }
                }

                if (!is_locked) {
                    SCLCoin *parent = hash_table_lookup(bc->coin_table, entry->data.pointer.parent_coin_id, false);
                    if (parent) {
                        available[avail_count] = &entry->data.pointer;
                        avail_count++;
                    }
                }
            }
            entry = entry->next;
        }
    }

    // Sort all available pointers from largest to smallest
    qsort(available, avail_count, sizeof(Pointer *), compare_pointers_desc);

    uint64_t total_subunits = 0;
    size_t selected_count = 0;
    for (size_t i = 0; i < avail_count; i++) {
        // Enforce maximum inputs limit after ensuring we are grabbing the largest pointers
        if (selected_count >= MAX_SELECTED_POINTERS) {
            break;
        }
        uint64_t subunits = available[i]->end_subunit - available[i]->start_subunit + 1;
        total_subunits += subunits;
        selected_count++;
        if (total_subunits >= target_subunits) break;
    }

    if (total_subunits < target_subunits) {
        free(available);
        if (locked_pointers) free(locked_pointers);
        pthread_rwlock_unlock(&bc->rwlock);
        *num_selected = 0;
        return NULL;
    }

    // Copy selected pointers into return buffer
    Pointer *selected = malloc(selected_count * sizeof(Pointer));
    if (!selected) {
        free(available);
        if (locked_pointers) free(locked_pointers);
        pthread_rwlock_unlock(&bc->rwlock);
        fprintf(stderr, "[Blockchain] Memory allocation failed\n");
        return NULL;
    }

    for (size_t i = 0; i < selected_count; i++) {
        selected[i] = *available[i];
    }
    *num_selected = selected_count;

    free(available);
    if (locked_pointers) free(locked_pointers);
    pthread_rwlock_unlock(&bc->rwlock);
    return selected;
}

/**
 * @brief Assembles, signs, generates ZK-PRF proofs for, and broadcasts an on-chain transfer transaction.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] recipient_pubkey 2,592-byte Dilithium5 public key of the recipient.
 * @param[in] amount_subunits Subunits transferred to recipient (excluding fee).
 * @param[in] is_recreation Flag indicating background worker recreation retry.
 * @return 0 on success; 2 if input pointers are locked in mempool; -1 on failure.
 *
 * @complexity Time: O(inputs * ZK_KAPPA), Space: O(ZK_PROOF_MAX_LEN).
 */
int create_and_broadcast_transfer(State *state, const uint8_t *recipient_pubkey, uint64_t amount_subunits, bool is_recreation) {
    /* Legacy custodial entry point: funds from the node operator wallet and
     * discards the serialized operation (existing callers do not need the tx id). */
    return create_and_broadcast_transfer_as(state, &state->user_wallet, recipient_pubkey, amount_subunits,
                                             is_recreation, NULL, 0, NULL, NULL);
}

int create_and_broadcast_transfer_as(State *state, const UserWallet *funding_wallet, const uint8_t *recipient_pubkey,
                                      uint64_t amount_subunits, bool is_recreation,
                                      uint8_t *out_serialized_op, size_t out_serialized_cap,
                                      size_t *out_serialized_len, uint8_t *out_tx_id) {
    int result = -1;
    Pointer *selected = NULL;
    TransferData *tx = NULL;
    uint8_t *serialized_data = NULL;
    uint8_t *signature_payload = NULL;
    Operation *op = NULL;
    Message *broadcast_msg = NULL;

    if (!state || !recipient_pubkey || amount_subunits == 0) {
        fprintf(stderr, "[Client] ERROR: Invalid parameters for %stransfer\n", is_recreation ? "recreated " : "");
        return -1;
    }

    uint64_t fee = calculate_fee(amount_subunits, false);
    uint64_t total_subunits = amount_subunits + fee;

    size_t fn_mark = arena_mark();

    // Allocate massive structures via thread-local memory arena to prevent heap fragmentation
    tx = arena_alloc(sizeof(TransferData));
    serialized_data = arena_alloc(15000 + MAX_INPUTS * 8000);
    signature_payload = arena_alloc(8192);
    op = arena_alloc(sizeof(Operation));
    broadcast_msg = arena_alloc(offsetof(Message, payload) + 15000 + MAX_INPUTS * 8000);

    if (!tx || !serialized_data || !signature_payload || !op || !broadcast_msg) {
        fprintf(stderr, "[Client] ERROR: Memory allocation failed in %stransfer\n", is_recreation ? "recreated " : "");
        result = -1;
        goto cleanup;
    }

    uint8_t local_privkey[DILITHIUM_SECRETKEY_LEN];
    PRFKey local_prf_key;

    pthread_mutex_lock(&state->mutex);
    size_t num_selected = 0;
        
    // First try excluding mempool
    selected = select_pointers(state, funding_wallet->dilithium_pubkey, total_subunits, &num_selected, false, true);
        
    if (!selected || num_selected == 0) {
        // We couldn't find enough unlocked. Try including mempool to see if we should defer.
        selected = select_pointers(state, funding_wallet->dilithium_pubkey, total_subunits, &num_selected, false, false);
        if (!selected || num_selected == 0) {
            fprintf(stderr, "[Client] ERROR: Failed to select pointers for %stransfer: insufficient balance\n", is_recreation ? "recreated " : "");
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
            
        // If we found them but they are locked, defer.
        if (!is_recreation) {
            fprintf(stderr, "[Client] Pointers locked in mempool. Queuing transfer for later...\n");
        }
        pthread_mutex_unlock(&state->mutex);
        result = 2;
        goto cleanup;
    }

    // Validate balance early to fail fast before heavy crypto
    if (has_insufficient_balance_locked(state, funding_wallet->dilithium_pubkey, selected, num_selected, total_subunits, false)) {
        fprintf(stderr, "[Client] ERROR: Insufficient balance (considering pending) for %stransfer\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }

    // Populate transfer transaction payload with selected inputs and recipient details
    tx->num_inputs = num_selected;
    memcpy(tx->inputs, selected, num_selected * sizeof(Pointer));
    memcpy(tx->recipient_pubkey, recipient_pubkey, PUBKEY_LEN);
    
    // Add the sender pubkey explicitly to the transaction so full nodes can verify it
    memcpy(tx->sender_pubkey, funding_wallet->dilithium_pubkey, PUBKEY_LEN);
    
    tx->amount = amount_subunits;
        
    if (RAND_bytes(tx->nonce, 8) != 1) {
        fprintf(stderr, "[Client] ERROR: Failed to generate nonce for %stransfer\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }
    get_mmr_root(&state->bc, tx->client_root);

    // Generate MMR proofs for input pointers
    for (size_t i = 0; i < num_selected; i++) {
        SCLCoin *parent = hash_table_lookup(state->bc.coin_table, tx->inputs[i].parent_coin_id, false);
        if (!parent) {
            fprintf(stderr, "[Client] ERROR: Parent coin not found for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        ssize_t pos = mmr_get_leaf_position(state->bc.mmr, parent->coin_id, parent->remaining_subunits);
        if (pos == -1) {
            fprintf(stderr, "[Client] ERROR: Leaf position not found for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        if (mmr_generate_proof(state->bc.mmr, (size_t)pos, tx->proofs[i].path_hashes, tx->proofs[i].is_left, &tx->proofs[i].path_len,
            tx->proofs[i].left_peaks, &tx->proofs[i].left_peaks_len,
            tx->proofs[i].right_peaks, &tx->proofs[i].right_peaks_len) != 0) {
            fprintf(stderr, "[Client] ERROR: Failed to generate MMR proof for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
    }

    // Copy keys to local stack to allow unlocking mutex during heavy crypto
    memcpy(local_privkey, funding_wallet->dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    local_prf_key = funding_wallet->prf_key;

    pthread_mutex_unlock(&state->mutex); // <--- UNLOCK EARLY

    // Compute the Merkle root of all input pointers
    compute_inputs_merkle_root(tx->inputs, tx->num_inputs, tx->inputs_merkle_root);

    // Sign the Merkle root
    if (dilithium_sign(tx->inputs_merkle_root, COIN_ID_LEN, local_privkey, tx->inputs_root_signature) != 1) {
        fprintf(stderr, "[Client] ERROR: Failed to sign inputs Merkle root for %stransfer\n", is_recreation ? "recreated " : "");
        goto cleanup;
    }

    size_t serialized_len;
    if (serialize_transfer_payload(tx, serialized_data, &serialized_len) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to serialize transfer for tx_id in %stransfer\n", is_recreation ? "recreated " : "");
        goto cleanup;
    }
    SHA256(serialized_data, serialized_len, tx->tx_id);

    // Evaluate Centinel ZK-PRF nullifier and generate zero-knowledge proof (thread-safe)
    if (prf_evaluate(tx->prf_output, &local_prf_key, tx->tx_id, COIN_ID_LEN, tx->client_root) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Client] ERROR: Failed to evaluate PRF for transfer\n");
        goto cleanup;
    }

    size_t proof_buf_len = ZK_PROOF_MAX_LEN;
    if (generate_zk_prf_proof(tx->zk_proof, &proof_buf_len, tx->tx_id, COIN_ID_LEN, (const uint8_t*)local_prf_key.k, sizeof(local_prf_key.k), tx->client_root) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Client] ERROR: Failed to generate ZK-PRF proof for transfer\n");
        goto cleanup;
    }
    tx->zk_proof_len = (uint32_t)proof_buf_len;

    size_t signature_payload_len;
    if (serialize_transfer_for_signature(tx, signature_payload, &signature_payload_len) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to serialize transfer for signing in %stransfer\n", is_recreation ? "recreated " : "");
        goto cleanup;
    }

    if (dilithium_sign(signature_payload, signature_payload_len, local_privkey, tx->signature) != 1) {
        fprintf(stderr, "[Client] ERROR: Failed to sign transaction in %stransfer\n", is_recreation ? "recreated " : "");
        goto cleanup;
    }

    op->type = OP_TRANSFER_POINTER;
    op->data.transfer_pointer = *tx; // Copy heap data to heap operation
    
    if (verify_operation_heavy_crypto(op) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Client] ERROR: Heavy crypto verification failed on local creation\n");
        result = -1;
        goto cleanup;
    }

    int added = add_pending_operation(state, op);
    if (added == -2) {
        if (!is_recreation) {
            fprintf(stderr, "[Client] Pointers locked in mempool. Queuing transfer for later...\n");
        }
        result = 2;
        goto cleanup;
    } else if (added != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to add %stransfer to pending operations\n", is_recreation ? "recreated " : "");
        goto cleanup;
    }

    broadcast_msg->type = MSG_PENDING_OPERATION;
    broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
    if (broadcast_msg->length == 0) {
        fprintf(stderr, "[Client] ERROR: Failed to serialize operation for broadcast in %stransfer\n", is_recreation ? "recreated " : "");
        goto cleanup;
    }
    p2p_broadcast(state, broadcast_msg);

    /* SCL402: hand the canonical serialized operation (authoritative tx id at
     * wire bytes 1..33) back to the caller so RPC bridges can echo it to the
     * client that funded the payment. The receipt the client builds from it
     * resolves against this exact mempool operation. Bridges that only need
     * the tx id pass out_serialized_op=NULL and use out_tx_id instead. */
    if (out_serialized_len) {
        *out_serialized_len = 0;
        if (out_serialized_op && out_serialized_cap > 0 && (size_t)broadcast_msg->length <= out_serialized_cap) {
            memcpy(out_serialized_op, broadcast_msg->payload, (size_t)broadcast_msg->length);
            *out_serialized_len = (size_t)broadcast_msg->length;
        }
    }
    if (out_tx_id) {
        memcpy(out_tx_id, tx->tx_id, COIN_ID_LEN);
    }

    fprintf(stderr, "[Client] %s transfer of %.8f SCL broadcasted (tx_id first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
            is_recreation ? "Recreated" : "Initiated", (double)amount_subunits / SUBUNITS_PER_COIN,
            tx->tx_id[0], tx->tx_id[1], tx->tx_id[2], tx->tx_id[3], tx->tx_id[4], tx->tx_id[5], tx->tx_id[6], tx->tx_id[7]);

    result = 0;

cleanup:
    if (selected) free(selected);
    arena_reset(fn_mark);
    return result;
}

/**
 * @brief Assembles, threshold-signs, and broadcasts a staking transaction (@ref OP_STAKE).
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] amount_subunits Subunits locked into staking status.
 * @param[in] is_recreation Flag indicating background worker recreation retry.
 * @return 0 on success; 2 if input pointers are locked in mempool; -1 on failure.
 *
 * @complexity Time: O(inputs + threshold_ceremony_time), Space: O(MAX_INPUTS * sizeof(Pointer)).
 */
int create_and_broadcast_stake(State *state, uint64_t amount_subunits, bool is_recreation) {
    int result = -1;
    Pointer *selected = NULL;
    StakeData *sd = NULL;
    uint8_t *signed_data = NULL;
    uint8_t *mu_input = NULL;
    Operation *op = NULL;
    Message *broadcast_msg = NULL;
    PartialCollectorArgs *cargs = NULL;
    ThresholdStakeProcess *process = NULL;

    if (!state || amount_subunits == 0) {
        fprintf(stderr, "[Client] ERROR: Invalid parameters for %sstake\n", is_recreation ? "recreated " : "");
        return -1;
    }

    uint64_t fee = calculate_fee(amount_subunits, true);
    uint64_t total_subunits = amount_subunits + fee;

    if (!is_recreation) {
        fprintf(stderr, "[Client] Calculated halved fee: %llu subunits (%.8f SCL) for stake of %.8f SCL\n",
            fee, (double)fee / SUBUNITS_PER_COIN, (double)amount_subunits / SUBUNITS_PER_COIN);
    }

    size_t fn_mark = arena_mark();

    // Allocate massive structures via thread-local memory arena to prevent heap fragmentation
    sd = arena_alloc(sizeof(StakeData));
    signed_data = arena_alloc(15000 + MAX_INPUTS * 8000);
    mu_input = arena_alloc(32 + 15000 + MAX_INPUTS * 8000);
    op = arena_alloc(sizeof(Operation));
    broadcast_msg = arena_alloc(offsetof(Message, payload) + 15000 + MAX_INPUTS * 8000);

    if (!sd || !signed_data || !mu_input || !op || !broadcast_msg) {
        fprintf(stderr, "[Client] ERROR: Memory allocation failed in %sstake\n", is_recreation ? "recreated " : "");
        result = -1;
        goto cleanup;
    }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    memset(sd->threshold_pubkey, 0x42, PUBKEY_LEN);
    memset(sd->threshold_signature, 0x42, SIGNATURE_LEN);
    memset(sd->stake_tx_id, 0x42, COIN_ID_LEN);

    op->type = OP_STAKE;
    op->data.stake = *sd;

    int added_fuzz = add_pending_operation(state, op);
    if (added_fuzz == 0) {
        broadcast_msg->type = MSG_PENDING_OPERATION;
        broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
        if (broadcast_msg->length > 0) {
            p2p_broadcast(state, broadcast_msg);
        }
    }
    result = 0;
    goto cleanup;
#endif

    pthread_mutex_lock(&state->mutex);
    size_t num_selected = 0;
        
    selected = select_pointers(state, state->user_wallet.dilithium_pubkey, total_subunits, &num_selected, false, true);
        
    if (!selected || num_selected == 0) {
        selected = select_pointers(state, state->user_wallet.dilithium_pubkey, total_subunits, &num_selected, false, false);
        if (!selected || num_selected == 0) {
            fprintf(stderr, "[Client] ERROR: Failed to select pointers for %sstake: insufficient balance\n", is_recreation ? "recreated " : "");
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
            
        if (!is_recreation) {
            fprintf(stderr, "[Client] Pointers locked in mempool. Queuing stake for later...\n");
        }
        pthread_mutex_unlock(&state->mutex);
        result = 2;
        goto cleanup;
    }

    sd->num_inputs = num_selected;
    memcpy(sd->inputs, selected, num_selected * sizeof(Pointer));
    sd->amount = amount_subunits;
    memcpy(sd->sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            
    if (RAND_bytes(sd->nonce, 8) != 1) {
        fprintf(stderr, "[Client] ERROR: Failed to generate nonce for %sstake\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }
    get_mmr_root(&state->bc, sd->client_root);

    // Validate balance considering pending operations
    if (has_insufficient_balance_locked(state, state->user_wallet.dilithium_pubkey, sd->inputs, sd->num_inputs, total_subunits, false)) {
        fprintf(stderr, "[Client] ERROR: Insufficient balance (considering pending) for %sstake\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }

    // Generate MMR proofs and sign pointers
    for (size_t i = 0; i < num_selected; i++) {
        SCLCoin *parent = hash_table_lookup(state->bc.coin_table, sd->inputs[i].parent_coin_id, false);
        if (!parent) {
            fprintf(stderr, "[Client] ERROR: Parent coin not found for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        ssize_t pos = mmr_get_leaf_position(state->bc.mmr, parent->coin_id, parent->remaining_subunits);
        if (pos == -1) {
            fprintf(stderr, "[Client] ERROR: Leaf position not found for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        if (mmr_generate_proof(state->bc.mmr, (size_t)pos, sd->proofs[i].path_hashes, sd->proofs[i].is_left, &sd->proofs[i].path_len,
            sd->proofs[i].left_peaks, &sd->proofs[i].left_peaks_len,
            sd->proofs[i].right_peaks, &sd->proofs[i].right_peaks_len) != 0) {
            fprintf(stderr, "[Client] ERROR: Failed to generate MMR proof for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }

        compute_inputs_merkle_root(sd->inputs, sd->num_inputs, sd->inputs_merkle_root);

        if (dilithium_sign(sd->inputs_merkle_root, COIN_ID_LEN, state->user_wallet.dilithium_privkey, sd->inputs_root_signature) != 1) {
            fprintf(stderr, "[Client] ERROR: Failed to sign inputs Merkle root for stake\n");
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
    }

    pthread_mutex_unlock(&state->mutex); // Mutex unlocked right before Threshold setup

    // Setup threshold process with valid peers filter to prevent infinite loop
    pthread_mutex_lock(&state->p2p_network.mutex);
    size_t *valid_peers = malloc(MAX_CLIENTS * sizeof(size_t));
    if (!valid_peers) {
        fprintf(stderr, "[Network] ERROR: Memory allocation failed for valid_peers\n");
        pthread_mutex_unlock(&state->p2p_network.mutex);
        goto cleanup;
    }
    size_t valid_count = 0;
        
    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
        Peer *p = state->p2p_network.known_peers[i];
        if (memcmp(p->peer_wallet.dilithium_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            continue; // Skip local peer
        }
        if (!is_zeroed(p->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
            p->conn && p->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
            valid_peers[valid_count++] = i;
        }
    }

    // Ensure at least one peer is available for 2-of-N threshold signing
    if (valid_count < 1) {
        fprintf(stderr, "[Network] ERROR: Insufficient ESTABLISHED peers for threshold execution (%zu < 1)\n", valid_count);
        free(valid_peers);
        pthread_mutex_unlock(&state->p2p_network.mutex);
        goto cleanup;
    }
        
    uint8_t temp_tx_id[COIN_ID_LEN];
    compute_temp_tx_id(sd->nonce, temp_tx_id);

    process = get_or_create_threshold_process(state, temp_tx_id);
    if (!process) {
        fprintf(stderr, "[Client] ERROR: Failed to create threshold process\n");
        free(valid_peers);
        pthread_mutex_unlock(&state->p2p_network.mutex);
        goto cleanup;
    }
    process->created_at = get_time_ms();
    atomic_init(&process->partials_received, 0);

    size_t peer_count = (valid_count > 9) ? 9 : valid_count; // Cap at 9 peer boundaries
    atomic_init(&process->expected_partials, 1); // Dealer (1) + Peer (1) = t (2)

    // Randomly shuffle established peers and select threshold signers
    for (size_t i = 0; i < peer_count; i++) {
        uint32_t rand_idx;
        RAND_bytes((uint8_t*)&rand_idx, sizeof(rand_idx));
        size_t swap_idx = i + (rand_idx % (valid_count - i));
        size_t temp = valid_peers[i];
        valid_peers[i] = valid_peers[swap_idx];
        valid_peers[swap_idx] = temp;
        
        Peer *peer = state->p2p_network.known_peers[valid_peers[i]];
        memcpy(process->peer_pubkeys[i], peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN);
        process->peer_addrs[i] = peer->addr;
    }
    free(valid_peers);
    pthread_mutex_unlock(&state->p2p_network.mutex);

    // Generate threshold keypair shares across selected peer points
    uint8_t keygen_seed[KAPPA];
    SHA256(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, keygen_seed);

    uint16_t point_ids[10];
    for (int i = 0; i < 10; i++) point_ids[i] = i;

    if (threshold_keygen(state, &process->keygen, keygen_seed, KAPPA, point_ids, 10, 2) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Stake] ERROR: Threshold key generation failed\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    memcpy(sd->threshold_pubkey, process->keygen.pubkey, PUBKEY_LEN);

    size_t signed_data_len;
    if (serialize_stake_payload(sd, signed_data, &signed_data_len, true) != 0) {
        fprintf(stderr, "[Stake] ERROR: Failed to serialize stake payload for message\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    // Derive challenge binding mu = H(tr || signed_payload)
    uint8_t tr[32];
    sha256_hash(process->keygen.pubkey, process->keygen.pubkey_len, tr);

    memcpy(mu_input, tr, 32);
    memcpy(mu_input + 32, signed_data, signed_data_len);
    sha256_hash(mu_input, 32 + signed_data_len, process->mu);

    uint8_t sign_seed[KAPPA];
    generate_deterministic_nonce(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, process->mu, 32, sign_seed);

    uint8_t rho[KAPPA];
    memcpy(rho, process->keygen.pubkey, KAPPA);

    int32_t eta_full = ETA * NUM_SUBSETS;
    int32_t beta = TAU * eta_full;
    int32_t bound_y = (GAMMA1 - beta) / 3 - TAU * MAX_S_PART_INF;

    if (threshold_sign(state, &process->dealer_sign_data, process->mu, 32, sign_seed, KAPPA, rho, &process->keygen.s1_shares[0], &process->keygen.s2_shares[0], 0, point_ids, point_ids, 10, 2, bound_y) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Stake] ERROR: Dealer threshold_sign failed\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    cargs = malloc(sizeof(PartialCollectorArgs));
    if (!cargs) {
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }
    memcpy(cargs->stake_tx_id, temp_tx_id, COIN_ID_LEN);
    cargs->state = state;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    free(cargs);
    cargs = NULL;
#else
    if (pthread_create(&process->collector_thread, NULL, partial_collector_thread, cargs) != 0) {
        free(cargs);
        cargs = NULL; // Avoid double free in cleanup if logic fails later
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }
#endif
    // Distribute threshold signing shares to participating peers
    for (size_t i = 0; i < peer_count; i++) {
        Message *msg = calloc(1, sizeof(Message));
        if (!msg) {
            remove_threshold_process(state, temp_tx_id);
            goto cleanup;
        }
        msg->type = MSG_THRESHOLD_SHARE_DISTRIBUTE;
        uint8_t *dp = msg->payload;
        memcpy(dp, temp_tx_id, COIN_ID_LEN); dp += COIN_ID_LEN;
        uint16_t point_id_be = htobe16(i + 1);
        memcpy(dp, &point_id_be, sizeof(uint16_t)); dp += sizeof(uint16_t);
        memcpy(dp, process->mu, 32); dp += 32;
        memcpy(dp, rho, KAPPA); dp += KAPPA; // Include rho for peer A_bar expansion
        size_t s1_len;
        if (polyvec_serialize(&process->keygen.s1_shares[i+1], dp, POLYVEC_L_SERIALIZED, &s1_len) != CRYPTO_SUCCESS) {
            free(msg);
            remove_threshold_process(state, temp_tx_id);
            goto cleanup;
        }
        dp += s1_len;
        size_t s2_len;
        if (polyvec_serialize(&process->keygen.s2_shares[i+1], dp, POLYVEC_K_SERIALIZED, &s2_len) != CRYPTO_SUCCESS) {
            free(msg);
            remove_threshold_process(state, temp_tx_id);
            goto cleanup;
        }
        dp += s2_len;
        msg->length = dp - msg->payload;
        send_message(state, process->peer_pubkeys[i], msg);
        free(msg);
    }

    pthread_join(process->collector_thread, NULL);
    process->collector_thread = 0;

    if (!process->aggregation_complete) {
        fprintf(stderr, "[Stake] ERROR: Threshold signature aggregation failed\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    memcpy(sd->threshold_pubkey, process->keygen.pubkey, PUBKEY_LEN);
    memcpy(sd->threshold_signature, process->final_signature, SIGNATURE_LEN);

    if (serialize_stake_payload(sd, signed_data, &signed_data_len, false) != 0) {
        fprintf(stderr, "[Stake] ERROR: Failed to serialize stake payload for ID computation\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }
    SHA256(signed_data, signed_data_len, sd->stake_tx_id);

    op->type = OP_STAKE;
    op->data.stake = *sd;

    int added = add_pending_operation(state, op);
    if (added == -2) {
        if (!is_recreation) {
            fprintf(stderr, "[Stake] Pointers locked in mempool. Queuing stake for later...\n");
        }
        remove_threshold_process(state, temp_tx_id);
        result = 2;
        goto cleanup;
    } else if (added != 0) {
        fprintf(stderr, "[Stake] ERROR: Failed to add OP_STAKE to pending operations\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    remove_threshold_process(state, temp_tx_id);

    broadcast_msg->type = MSG_PENDING_OPERATION;
    broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
    if (broadcast_msg->length == 0) {
        fprintf(stderr, "[Stake] ERROR: Failed to serialize OP_STAKE for broadcast\n");
        goto cleanup;
    }
    p2p_broadcast(state, broadcast_msg);
    
    fprintf(stderr, "[Client] %s stake of %.8f SCL broadcasted (stake_tx_id first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
            is_recreation ? "Recreated" : "Initiated",
            (double)amount_subunits / SUBUNITS_PER_COIN,
            sd->stake_tx_id[0], sd->stake_tx_id[1], sd->stake_tx_id[2], sd->stake_tx_id[3],
            sd->stake_tx_id[4], sd->stake_tx_id[5], sd->stake_tx_id[6], sd->stake_tx_id[7]);

    result = 0;

cleanup:
    if (selected) free(selected);
    arena_reset(fn_mark);
    return result;
}

/**
 * @brief Assembles, signs, and broadcasts a drift certificate anchoring transaction (@ref OP_APPLY_DRIFT_CERT).
 *
 * @details
 * Mirrors the @ref create_and_broadcast_stake funding model: selects the funding wallet's unspent
 * pointers, binds the client-attested certificate digest fields, signs the canonical certificate
 * digest with ML-DSA-87, and gossips the operation to the mempool. The authenticated client intent
 * op (deserialized from SubmitTx 0x0003) contributes the certificate identity and fee; this builder
 * re-anchors it under the node wallet exactly as browser-submitted transfers are executed.
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] client_cert Authenticated client intent carrying the certificate digest fields and fee.
 * @param[in] is_recreation Flag indicating background worker recreation retry.
 * @return 0 on success; 2 if input pointers are locked in mempool; -1 on failure.
 *
 * @complexity Time: O(inputs + Cost(Dilithium5)), Space: O(MAX_INPUTS * sizeof(Pointer)).
 */
int create_and_broadcast_apply_drift_cert(State *state, const ApplyDriftCertData *client_cert, bool is_recreation, uint8_t *out_cert_tx_id) {
    int result = -1;
    Pointer *selected = NULL;
    ApplyDriftCertData *dc = NULL;
    Operation *op = NULL;
    Message *broadcast_msg = NULL;

    if (!state || !client_cert || client_cert->amount == 0) {
        fprintf(stderr, "[DriftCert] ERROR: Invalid parameters for %sanchoring\n", is_recreation ? "recreated " : "");
        return -1;
    }

    /* Enterprise anchoring uses the halved (staking-grade) fee schedule */
    uint64_t fee = calculate_fee(client_cert->amount, true);
    uint64_t total_subunits = client_cert->amount + fee;

    size_t fn_mark = arena_mark();

    dc = arena_alloc(sizeof(ApplyDriftCertData));
    op = arena_alloc(sizeof(Operation));
    broadcast_msg = arena_alloc(offsetof(Message, payload) + 15000 + MAX_INPUTS * 8000);
    if (!dc || !op || !broadcast_msg) {
        fprintf(stderr, "[DriftCert] ERROR: Memory allocation failed in %sanchoring\n", is_recreation ? "recreated " : "");
        result = -1;
        goto cleanup;
    }

    uint8_t local_privkey[DILITHIUM_SECRETKEY_LEN];

    pthread_mutex_lock(&state->mutex);
    size_t num_selected = 0;

    selected = select_pointers(state, state->user_wallet.dilithium_pubkey, total_subunits, &num_selected, false, true);
    if (!selected || num_selected == 0) {
        selected = select_pointers(state, state->user_wallet.dilithium_pubkey, total_subunits, &num_selected, false, false);
        if (!selected || num_selected == 0) {
            fprintf(stderr, "[DriftCert] ERROR: Failed to select pointers for %sanchoring: insufficient balance\n", is_recreation ? "recreated " : "");
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        if (!is_recreation) {
            fprintf(stderr, "[DriftCert] Pointers locked in mempool. Queuing anchoring for later...\n");
        }
        pthread_mutex_unlock(&state->mutex);
        result = 2;
        goto cleanup;
    }

    if (has_insufficient_balance_locked(state, state->user_wallet.dilithium_pubkey, selected, num_selected, total_subunits, false)) {
        fprintf(stderr, "[DriftCert] ERROR: Insufficient balance (considering pending) for %sanchoring\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }

    memset(dc, 0, sizeof(ApplyDriftCertData));
    dc->num_inputs = (uint32_t)num_selected;
    memcpy(dc->inputs, selected, num_selected * sizeof(Pointer));

    /* Bind the audited certificate's cryptographic identity into the anchoring record */
    memcpy(dc->circuit_hash, client_cert->circuit_hash, 32);
    dc->tvd_scaled = client_cert->tvd_scaled;
    dc->shots = client_cert->shots;
    dc->status = client_cert->status;
    memcpy(dc->commitment_root, client_cert->commitment_root, 32);
    dc->timestamp_us = client_cert->timestamp_us;
    memcpy(dc->recipient_pubkey, client_cert->recipient_pubkey, PUBKEY_LEN);
    memcpy(dc->sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    dc->amount = client_cert->amount;

    if (RAND_bytes(dc->nonce, 8) != 1) {
        fprintf(stderr, "[DriftCert] ERROR: Failed to generate nonce for %sanchoring\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }
    get_mmr_root(&state->bc, dc->client_root);

    for (size_t i = 0; i < num_selected; i++) {
        SCLCoin *parent = hash_table_lookup(state->bc.coin_table, dc->inputs[i].parent_coin_id, false);
        if (!parent) {
            fprintf(stderr, "[DriftCert] ERROR: Parent coin not found for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        ssize_t pos = mmr_get_leaf_position(state->bc.mmr, parent->coin_id, parent->remaining_subunits);
        if (pos == -1) {
            fprintf(stderr, "[DriftCert] ERROR: Leaf position not found for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        if (mmr_generate_proof(state->bc.mmr, (size_t)pos, dc->proofs[i].path_hashes, dc->proofs[i].is_left, &dc->proofs[i].path_len,
            dc->proofs[i].left_peaks, &dc->proofs[i].left_peaks_len,
            dc->proofs[i].right_peaks, &dc->proofs[i].right_peaks_len) != 0) {
            fprintf(stderr, "[DriftCert] ERROR: Failed to generate MMR proof for pointer %zu\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
    }

    memcpy(local_privkey, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    pthread_mutex_unlock(&state->mutex);

    compute_inputs_merkle_root(dc->inputs, dc->num_inputs, dc->inputs_merkle_root);

    /* Canonical certificate digest: SHA-256 over the audited attestation core */
    {
        SHA256_CTX digest_ctx;
        SHA256_Init(&digest_ctx);
        SHA256_Update(&digest_ctx, dc->circuit_hash, 32);
        uint64_t tvd_be = htobe64(dc->tvd_scaled);   SHA256_Update(&digest_ctx, &tvd_be, 8);
        uint32_t shots_be = htobe32(dc->shots);      SHA256_Update(&digest_ctx, &shots_be, 4);
        uint32_t status_be = htobe32(dc->status);    SHA256_Update(&digest_ctx, &status_be, 4);
        SHA256_Update(&digest_ctx, dc->commitment_root, 32);
        uint64_t ts_be = htobe64(dc->timestamp_us);  SHA256_Update(&digest_ctx, &ts_be, 8);
        SHA256_Final(dc->cert_digest, &digest_ctx);
    }

    /* Sign the certificate digest with the funding wallet's ML-DSA-87 key */
    if (dilithium_sign(dc->cert_digest, 32, local_privkey, dc->signature) != 1) {
        fprintf(stderr, "[DriftCert] ERROR: Failed to sign certificate digest for %sanchoring\n", is_recreation ? "recreated " : "");
        goto cleanup;
    }

    /* Deterministic operation identity: SHA-256(cert_digest || amount || nonce) */
    {
        uint8_t tx_id_input[48];
        memcpy(tx_id_input, dc->cert_digest, 32);
        uint64_t amount_be = htobe64(dc->amount);
        memcpy(tx_id_input + 32, &amount_be, 8);
        memcpy(tx_id_input + 40, dc->nonce, 8);
        SHA256(tx_id_input, sizeof(tx_id_input), dc->cert_tx_id);
    }

    op->type = OP_APPLY_DRIFT_CERT;
    op->data.apply_drift_cert = *dc;

    if (verify_operation_heavy_crypto(op) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[DriftCert] ERROR: Heavy crypto verification failed on local creation\n");
        result = -1;
        goto cleanup;
    }

    int added = add_pending_operation(state, op);
    if (added == -2) {
        if (!is_recreation) {
            fprintf(stderr, "[DriftCert] Pointers locked in mempool. Queuing anchoring for later...\n");
        }
        result = 2;
        goto cleanup;
    } else if (added != 0) {
        fprintf(stderr, "[DriftCert] ERROR: Failed to add OP_APPLY_DRIFT_CERT to pending operations\n");
        goto cleanup;
    }

    broadcast_msg->type = MSG_PENDING_OPERATION;
    broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
    if (broadcast_msg->length == 0) {
        fprintf(stderr, "[DriftCert] ERROR: Failed to serialize OP_APPLY_DRIFT_CERT for broadcast\n");
        goto cleanup;
    }
    p2p_broadcast(state, broadcast_msg);

    fprintf(stderr, "[DriftCert] %s anchoring of %.8f SCL fee broadcasted (cert_tx_id first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
            is_recreation ? "Recreated" : "Initiated",
            (double)client_cert->amount / SUBUNITS_PER_COIN,
            dc->cert_tx_id[0], dc->cert_tx_id[1], dc->cert_tx_id[2], dc->cert_tx_id[3],
            dc->cert_tx_id[4], dc->cert_tx_id[5], dc->cert_tx_id[6], dc->cert_tx_id[7]);

    result = 0;

    /* Export the authoritative on-chain identity so ingress paths can echo
     * [0x07][cert_tx_id] back to the submitting client. */
    if (out_cert_tx_id) {
        memcpy(out_cert_tx_id, dc->cert_tx_id, COIN_ID_LEN);
    }

cleanup:
    if (selected) free(selected);
    arena_reset(fn_mark);
    return result;
}

/**
 * @brief Assembles, threshold-signs, and broadcasts an unstaking transaction (@ref OP_UNSTAKE).
 *
 * @param[in,out] state Pointer to global node state container.
 * @param[in] amount_subunits Subunits unlocked from staking status back to liquid.
 * @param[in] is_recreation Flag indicating background worker recreation retry.
 * @return 0 on success; 2 if staked pointers are locked in mempool; -1 on failure.
 *
 * @complexity Time: O(inputs + threshold_ceremony_time), Space: O(MAX_INPUTS * sizeof(Pointer)).
 */
int create_and_broadcast_unstake(State *state, uint64_t amount_subunits, bool is_recreation) {
    int result = -1;
    Pointer *selected = NULL;
    UnstakeData *sd = NULL;
    uint8_t *signed_data = NULL;
    uint8_t *mu_input = NULL;
    Operation *op = NULL;
    Message *broadcast_msg = NULL;
    PartialCollectorArgs *cargs = NULL;
    ThresholdStakeProcess *process = NULL;

    if (!state || amount_subunits == 0) {
        fprintf(stderr, "[Client] ERROR: Invalid parameters for %sunstake\n", is_recreation ? "recreated " : "");
        return -1;
    }

    uint8_t threshold_pubkey[PUBKEY_LEN];
    if (compute_threshold_pubkey(state, threshold_pubkey) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to compute threshold pubkey for %sunstake\n", is_recreation ? "recreated " : "");
        return -1;
    }

    uint64_t fee = calculate_fee(amount_subunits, true);
    uint64_t total_subunits = amount_subunits + fee;

    if (!is_recreation) {
        fprintf(stderr, "[Client] Calculated halved fee: %llu subunits (%.8f SCL) for unstake of %.8f SCL\n",
            fee, (double)fee / SUBUNITS_PER_COIN, (double)amount_subunits / SUBUNITS_PER_COIN);
    }

    size_t fn_mark = arena_mark();

    // Allocate massive structures via thread-local memory arena to prevent heap fragmentation
    sd = arena_alloc(sizeof(UnstakeData));
    signed_data = arena_alloc(15000 + MAX_INPUTS * 8000);
    mu_input = arena_alloc(32 + 15000 + MAX_INPUTS * 8000);
    op = arena_alloc(sizeof(Operation));
    broadcast_msg = arena_alloc(offsetof(Message, payload) + 15000 + MAX_INPUTS * 8000);

    if (!sd || !signed_data || !mu_input || !op || !broadcast_msg) {
        fprintf(stderr, "[Client] ERROR: Memory allocation failed in %sunstake\n", is_recreation ? "recreated " : "");
        result = -1;
        goto cleanup;
    }

#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    memset(sd->recipient_pubkey, 0x42, PUBKEY_LEN);
    memset(sd->threshold_pubkey, 0x42, PUBKEY_LEN);
    memset(sd->threshold_signature, 0x42, SIGNATURE_LEN);
    memset(sd->unstake_tx_id, 0x42, COIN_ID_LEN);

    op->type = OP_UNSTAKE;
    op->data.unstake = *sd;

    int added_fuzz = add_pending_operation(state, op);
    if (added_fuzz == 0) {
        broadcast_msg->type = MSG_PENDING_OPERATION;
        broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
        if (broadcast_msg->length > 0) {
            p2p_broadcast(state, broadcast_msg);
        }
    }
    result = 0;
    goto cleanup;
#endif

    pthread_mutex_lock(&state->mutex);
    size_t num_selected = 0;
        
    selected = select_pointers(state, threshold_pubkey, total_subunits, &num_selected, true, true);
        
    if (!selected || num_selected == 0) {
        selected = select_pointers(state, threshold_pubkey, total_subunits, &num_selected, true, false);
        if (!selected || num_selected == 0) {
            fprintf(stderr, "[Client] ERROR: Failed to select staked pointers for %sunstaking\n", is_recreation ? "recreated " : "");
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
            
        if (!is_recreation) {
            fprintf(stderr, "[Client] Pointers locked in mempool. Queuing unstake for later...\n");
        }
        pthread_mutex_unlock(&state->mutex);
        result = 2;
        goto cleanup;
    }

    sd->num_inputs = num_selected;
    memcpy(sd->inputs, selected, num_selected * sizeof(Pointer));
    sd->amount = amount_subunits;
    if (RAND_bytes(sd->nonce, 8) != 1) {
        fprintf(stderr, "[Client] ERROR: Failed to generate nonce for %sunstake\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }
    get_mmr_root(&state->bc, sd->client_root);

    if (has_insufficient_balance_locked(state, threshold_pubkey, sd->inputs, sd->num_inputs, amount_subunits, true)) {
        fprintf(stderr, "[Client] ERROR: Insufficient staked balance (considering pending) for %sunstake\n", is_recreation ? "recreated " : "");
        pthread_mutex_unlock(&state->mutex);
        goto cleanup;
    }

    for (size_t i = 0; i < num_selected; i++) {
        SCLCoin *coin = hash_table_lookup(state->bc.coin_table, sd->inputs[i].parent_coin_id, false);
        if (!coin) {
            fprintf(stderr, "[Client] ERROR: Failed to find parent coin for pointer %zu in unstake\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        ssize_t pos = mmr_get_leaf_position(state->bc.mmr, coin->coin_id, coin->remaining_subunits);
        if (pos == -1) {
            fprintf(stderr, "[Client] ERROR: Failed to find leaf position for pointer %zu in unstake\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
        if (mmr_generate_proof(state->bc.mmr, (size_t)pos, sd->proofs[i].path_hashes, sd->proofs[i].is_left, &sd->proofs[i].path_len,
                               sd->proofs[i].left_peaks, &sd->proofs[i].left_peaks_len,
                               sd->proofs[i].right_peaks, &sd->proofs[i].right_peaks_len) != 0) {
            fprintf(stderr, "[Client] ERROR: MMR proof generation failed for pointer %zu in unstake\n", i);
            pthread_mutex_unlock(&state->mutex);
            goto cleanup;
        }
    }

    memcpy(sd->threshold_pubkey, threshold_pubkey, PUBKEY_LEN);
    memcpy(sd->recipient_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

    pthread_mutex_unlock(&state->mutex); // Mutex unlocked right before Threshold setup

    // Setup threshold process with valid peers filter to prevent infinite loop
    pthread_mutex_lock(&state->p2p_network.mutex);
    size_t *valid_peers = malloc(MAX_CLIENTS * sizeof(size_t));
    if (!valid_peers) {
        fprintf(stderr, "[Network] ERROR: Memory allocation failed for valid_peers\n");
        pthread_mutex_unlock(&state->p2p_network.mutex);
        goto cleanup;
    }
    size_t valid_count = 0;
        
    for (size_t i = 0; i < state->p2p_network.num_known_peers; i++) {
        Peer *p = state->p2p_network.known_peers[i];
        if (memcmp(p->peer_wallet.dilithium_pubkey, state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) == 0) {
            continue; // Skip local peer
        }
        if (!is_zeroed(p->peer_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) &&
            p->conn && p->conn->handshake_state == SCL_CONN_STATE_ESTABLISHED) {
            valid_peers[valid_count++] = i;
        }
    }
    
    // Ensure at least one peer is available for 2-of-N threshold signing
    if (valid_count < 1) {
        fprintf(stderr, "[Network] ERROR: Insufficient ESTABLISHED peers for threshold execution (%zu < 1)\n", valid_count);
        free(valid_peers);
        pthread_mutex_unlock(&state->p2p_network.mutex);
        goto cleanup;
    }
        
    uint8_t temp_tx_id[COIN_ID_LEN];
    compute_temp_tx_id(sd->nonce, temp_tx_id);

    process = get_or_create_threshold_process(state, temp_tx_id);
    if (!process) {
        fprintf(stderr, "[Client] ERROR: Failed to create threshold process\n");
        free(valid_peers);
        pthread_mutex_unlock(&state->p2p_network.mutex);
        goto cleanup;
    }
    atomic_init(&process->partials_received, 0);

    size_t peer_count = (valid_count > 9) ? 9 : valid_count;
    atomic_init(&process->expected_partials, 1); // Dealer (1) + Peer (1) = t (2)

    // Randomly shuffle established peers and select threshold signers
    for (size_t i = 0; i < peer_count; i++) {
        uint32_t rand_idx;
        RAND_bytes((uint8_t*)&rand_idx, sizeof(rand_idx));
        size_t swap_idx = i + (rand_idx % (valid_count - i));
        size_t temp = valid_peers[i];
        valid_peers[i] = valid_peers[swap_idx];
        valid_peers[swap_idx] = temp;
        
        Peer *peer = state->p2p_network.known_peers[valid_peers[i]];
        memcpy(process->peer_pubkeys[i], peer->peer_wallet.dilithium_pubkey, PUBKEY_LEN);
        process->peer_addrs[i] = peer->addr;
    }
    free(valid_peers);
    pthread_mutex_unlock(&state->p2p_network.mutex);
    
    // Generate threshold keypair shares across selected peer points
    uint8_t keygen_seed[KAPPA];
    SHA256(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, keygen_seed);

    uint16_t point_ids[10];
    for (int i = 0; i < 10; i++) point_ids[i] = i;

    if (threshold_keygen(state, &process->keygen, keygen_seed, KAPPA, point_ids, 10, 2) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Client] ERROR: Threshold key generation failed for unstake\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    size_t signed_data_len;
    if (serialize_unstake_payload(sd, signed_data, &signed_data_len, true) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to serialize unstake payload for message\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    // Derive challenge binding mu = H(tr || signed_payload)
    uint8_t tr[32];
    sha256_hash(process->keygen.pubkey, process->keygen.pubkey_len, tr);

    memcpy(mu_input, tr, 32);
    memcpy(mu_input + 32, signed_data, signed_data_len);
    sha256_hash(mu_input, 32 + signed_data_len, process->mu);

    uint8_t sign_seed[KAPPA];
    generate_deterministic_nonce(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, process->mu, 32, sign_seed);

    uint8_t rho[KAPPA];
    memcpy(rho, process->keygen.pubkey, KAPPA);

    int32_t eta_full = ETA * NUM_SUBSETS;
    int32_t beta = TAU * eta_full;
    int32_t bound_y = (GAMMA1 - beta) / 3 - TAU * MAX_S_PART_INF;

    if (threshold_sign(state, &process->dealer_sign_data, process->mu, 32, sign_seed, KAPPA, rho, &process->keygen.s1_shares[0], &process->keygen.s2_shares[0], 0, point_ids, point_ids, 10, 2, bound_y) != CRYPTO_SUCCESS) {
        fprintf(stderr, "[Client] ERROR: Dealer threshold_sign failed for unstake\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    cargs = malloc(sizeof(PartialCollectorArgs));
    if (!cargs) {
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }
    memcpy(cargs->stake_tx_id, temp_tx_id, COIN_ID_LEN);
    cargs->state = state;
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    free(cargs);
    cargs = NULL;
#else
    if (pthread_create(&process->collector_thread, NULL, partial_collector_thread, cargs) != 0) {
        free(cargs);
        cargs = NULL;
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }
#endif
    // Distribute threshold signing shares to participating peers
    for (size_t i = 0; i < peer_count; i++) {
        Message *msg = calloc(1, sizeof(Message));
        if (!msg) {
            remove_threshold_process(state, temp_tx_id);
            goto cleanup;
        }
        msg->type = MSG_THRESHOLD_SHARE_DISTRIBUTE;
        uint8_t *dp = msg->payload;
        memcpy(dp, temp_tx_id, COIN_ID_LEN); dp += COIN_ID_LEN;
        uint16_t point_id_be = htobe16(i + 1);
        memcpy(dp, &point_id_be, sizeof(uint16_t)); dp += sizeof(uint16_t);
        memcpy(dp, process->mu, 32); dp += 32;
        memcpy(dp, rho, KAPPA); dp += KAPPA;
        size_t s1_len;
        if (polyvec_serialize(&process->keygen.s1_shares[i+1], dp, POLYVEC_L_SERIALIZED, &s1_len) != CRYPTO_SUCCESS) {
            free(msg);
            remove_threshold_process(state, temp_tx_id);
            goto cleanup;
        }
        dp += s1_len;
        size_t s2_len;
        if (polyvec_serialize(&process->keygen.s2_shares[i+1], dp, POLYVEC_K_SERIALIZED, &s2_len) != CRYPTO_SUCCESS) {
            free(msg);
            remove_threshold_process(state, temp_tx_id);
            goto cleanup;
        }
        dp += s2_len;
        msg->length = dp - msg->payload;
        send_message(state, process->peer_pubkeys[i], msg);
        free(msg);
    }

    pthread_join(process->collector_thread, NULL);
    process->collector_thread = 0;

    if (!process->aggregation_complete) {
        fprintf(stderr, "[Client] ERROR: Threshold signature aggregation failed for unstake\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }

    memcpy(sd->threshold_signature, process->final_signature, SIGNATURE_LEN);

    if (serialize_unstake_payload(sd, signed_data, &signed_data_len, false) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to serialize unstake payload for ID computation\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }
    SHA256(signed_data, signed_data_len, sd->unstake_tx_id);

    op->type = OP_UNSTAKE;
    op->data.unstake = *sd;

    int added = add_pending_operation(state, op);
    if (added == -2) {
        if (!is_recreation) {
            fprintf(stderr, "[Unstake] Pointers locked in mempool. Queuing unstake for later...\n");
        }
        remove_threshold_process(state, temp_tx_id);
        result = 2;
        goto cleanup;
    } else if (added != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to add unstake operation to pending\n");
        remove_threshold_process(state, temp_tx_id);
        goto cleanup;
    }
    
    remove_threshold_process(state, temp_tx_id);

    broadcast_msg->type = MSG_PENDING_OPERATION;
    broadcast_msg->length = serialize_operation(op, broadcast_msg->payload, MAX_MESSAGE_SIZE);
    if (broadcast_msg->length == 0) {
        fprintf(stderr, "[Client] ERROR: Failed to serialize operation for broadcast in unstake\n");
        goto cleanup;
    }
    p2p_broadcast(state, broadcast_msg);

    fprintf(stderr, "[Client] %s unstake of %.8f SCL broadcasted (unstake_tx_id first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
            is_recreation ? "Recreated" : "Initiated",
            (double)amount_subunits / SUBUNITS_PER_COIN,
            sd->unstake_tx_id[0], sd->unstake_tx_id[1], sd->unstake_tx_id[2], sd->unstake_tx_id[3],
            sd->unstake_tx_id[4], sd->unstake_tx_id[5], sd->unstake_tx_id[6], sd->unstake_tx_id[7]);

    result = 0;

cleanup:
    if (selected) free(selected);
    arena_reset(fn_mark);
    return result;
}

/* ============================================================================ */
/* SECTION 4: INTERACTIVE CLI PROMPTS & DISPATCH WRAPPERS                       */
/* ============================================================================ */

/**
 * @brief Interactive CLI routine prompting user for transfer parameters and dispatching transaction.
 *
 * @param[in] user Pointer to local @ref User account profile.
 * @param[in,out] state Pointer to global node state container.
 */
void initiate_transfer(User *user, State *state) {
    if (!user || !state) {
        fprintf(stderr, "[Client] ERROR: Invalid user or state for transfer\n");
        return;
    }

    pthread_mutex_lock(&state->mutex);
    uint64_t balance_subunits = calculate_balance_subunits(&state->bc, state->user_wallet.dilithium_pubkey, false);
    uint64_t pending_subunits = calculate_pending_consumed_subunits(state, state->user_wallet.dilithium_pubkey, false);
    uint64_t scheduled_subunits = atomic_load(&state->scheduled_consumed_subunits);
    pthread_mutex_unlock(&state->mutex);

    uint64_t total_outbound = pending_subunits + scheduled_subunits;

    // Calculate maximum available balance in exact subunits considering fees
    uint64_t available_subunits = 0;
    if (balance_subunits > total_outbound) {
        uint64_t usable = balance_subunits - total_outbound;
        double rate = M_PI / 100.0;
        available_subunits = (uint64_t)(usable / (1.0 + rate));
        while (available_subunits + calculate_fee(available_subunits, false) <= usable) {
            available_subunits++;
        }
        available_subunits--;
    }

    uint64_t display_units = (available_subunits * 5) / 8;
    double available_balance_scl = (double)display_units / 100000000.0;

    printf("[Client] Current balance: %.8f SCL (pending: %.8f SCL, scheduled: %.8f SCL)\n",
            (double)balance_subunits / SUBUNITS_PER_COIN,
            (double)pending_subunits / SUBUNITS_PER_COIN,
            (double)scheduled_subunits / SUBUNITS_PER_COIN);
    
    if (available_subunits == 0) {
        fprintf(stderr, "[Client] ERROR: No SCL available for transfer (including pending/scheduled transfers and estimated fees)\n");
        return;
    }

    // Get recipient user ID
    uint8_t recipient_user_id[USER_ID_LEN];
    printf("Enter recipient's user ID (hex, %d bytes): ", USER_ID_LEN);
    if (read_hex_input(recipient_user_id, USER_ID_LEN) != 0) {
        fprintf(stderr, "[Client] ERROR: Invalid recipient user ID format\n");
        return;
    }

    // Retrieve recipient pubkey
    uint8_t recipient_pubkey[PUBKEY_LEN];
    if (!get_pubkey_by_userid(state, recipient_user_id, recipient_pubkey)) {
        fprintf(stderr, "[Client] ERROR: Failed to retrieve recipient public key\n");
        return;
    }

    // Get transfer amount
    printf("Amount to transfer (max %.8f SCL): ", available_balance_scl);
    double amount_scl_double = validate_money_input();
    if (amount_scl_double <= 0) {
        fprintf(stderr, "[Client] ERROR: Invalid transfer amount\n");
        return;
    }
    
    // Safely round floating point translation to avoid sub-unit precision drops
    uint64_t amount_subunits = (uint64_t)round(amount_scl_double * SUBUNITS_PER_COIN);
    if (fabs(amount_scl_double - available_balance_scl) < 1e-9) {
        amount_subunits = available_subunits; // Bypass truncation for exact MAX executions
    }
    if (amount_subunits > available_subunits) {
        fprintf(stderr, "[Client] ERROR: Transfer amount exceeds available balance\n");
        return;
    }

    // Create and broadcast the transfer
    int ret = create_and_broadcast_transfer(state, recipient_pubkey, amount_subunits, false);
    if (ret == 2) {
        fprintf(stderr, "[Client] Queuing transfer in background until previous operations confirm...\n");
        RecreateArgs *args = calloc(1, sizeof(RecreateArgs)); // Explicit memory zeroing
        if (args) {
            args->state = state;
            args->amount = amount_subunits;
            args->is_transfer = true;
            args->is_stake = false;
            memcpy(args->recipient_pubkey, recipient_pubkey, PUBKEY_LEN);
            // Record that this amount is now scheduled to prevent concurrent re-selection
            uint64_t expected_fee = calculate_fee(amount_subunits, false);
            atomic_fetch_add(&state->scheduled_consumed_subunits, amount_subunits + expected_fee);
            spawn_recreation_thread(state, args);
        }
    } else if (ret != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to create and broadcast transfer\n");
    }
}

/**
 * @brief Interactive CLI routine prompting user for staking amount and dispatching @ref OP_STAKE.
 *
 * @param[in] user Pointer to local @ref User account profile.
 * @param[in,out] state Pointer to global node state container.
 * @return 0 on success or queued; -1 on error.
 */
int initiate_stake(User *user, State *state) {
    if (!user || !state) {
        fprintf(stderr, "[Client] ERROR: Invalid user or state for stake\n");
        return -1;
    }

    pthread_mutex_lock(&state->mutex);
    uint64_t balance_subunits = calculate_balance_subunits(&state->bc, state->user_wallet.dilithium_pubkey, false);
    uint64_t pending_subunits = calculate_pending_consumed_subunits(state, state->user_wallet.dilithium_pubkey, false);
    uint64_t scheduled_subunits = atomic_load(&state->scheduled_consumed_subunits);
    pthread_mutex_unlock(&state->mutex);
    
    uint64_t total_outbound = pending_subunits + scheduled_subunits;

    // Calculate maximum available balance in exact subunits considering fees
    uint64_t available_subunits = 0;
    if (balance_subunits > total_outbound) {
        uint64_t usable = balance_subunits - total_outbound;
        double rate = M_PI / 200.0;
        available_subunits = (uint64_t)(usable / (1.0 + rate));
        while (available_subunits + calculate_fee(available_subunits, true) <= usable) {
            available_subunits++;
        }
        available_subunits--;
    }

    uint64_t display_units = (available_subunits * 5) / 8;
    double available_balance_scl = (double)display_units / 100000000.0;
        
    printf("[Client] Current balance: %.8f SCL (pending: %.8f SCL, scheduled: %.8f SCL)\n",
            (double)balance_subunits / SUBUNITS_PER_COIN,
            (double)pending_subunits / SUBUNITS_PER_COIN,
            (double)scheduled_subunits / SUBUNITS_PER_COIN);
    
    if (available_subunits == 0) {
        fprintf(stderr, "[Client] ERROR: No SCL available for staking (including pending/scheduled operations and estimated fees)\n");
        return -1;
    }

    printf("Amount to stake (max %.8f SCL): ", available_balance_scl);
    double amount_scl_double = validate_money_input();
    if (amount_scl_double <= 0) {
        fprintf(stderr, "[Client] ERROR: Invalid stake amount\n");
        return -1;
    }
    
    // Safely round floating point translation to avoid sub-unit precision drops
    uint64_t amount_subunits = (uint64_t)round(amount_scl_double * SUBUNITS_PER_COIN);
    if (fabs(amount_scl_double - available_balance_scl) < 1e-9) {
        amount_subunits = available_subunits; // Bypass truncation for exact MAX executions
    }
    if (amount_subunits > available_subunits) {
        fprintf(stderr, "[Client] ERROR: Stake amount exceeds available balance\n");
        return -1;
    }

    // Create and broadcast the stake
    int ret = create_and_broadcast_stake(state, amount_subunits, false);
    if (ret == 2) {
        fprintf(stderr, "[Client] Queuing stake in background until previous operations confirm...\n");
        RecreateArgs *args = calloc(1, sizeof(RecreateArgs)); // Explicit memory zeroing
        if (args) {
            args->state = state;
            args->amount = amount_subunits;
            args->is_stake = true;
            args->is_transfer = false;
            // Record that this amount is now scheduled to prevent concurrent re-selection
            uint64_t expected_fee = calculate_fee(amount_subunits, true);
            atomic_fetch_add(&state->scheduled_consumed_subunits, amount_subunits + expected_fee);
            spawn_recreation_thread(state, args);
        }
        return 0; // Return success since it's natively queued
    }
    return ret;
}

/**
 * @brief Interactive CLI routine prompting user for unstaking amount and dispatching @ref OP_UNSTAKE.
 *
 * @param[in] user Pointer to local @ref User account profile.
 * @param[in,out] state Pointer to global node state container.
 * @return 0 on success or queued; -1 on error.
 */
int initiate_unstake(User *user, State *state) {
    if (!user || !state) {
        fprintf(stderr, "[Client] ERROR: Invalid user or state for unstake\n");
        return -1;
    }

    uint8_t threshold_pubkey[PUBKEY_LEN];
    if (compute_threshold_pubkey(state, threshold_pubkey) != 0) {
        fprintf(stderr, "[Client] ERROR: Failed to compute threshold pubkey for unstake\n");
        return -1;
    }

    pthread_mutex_lock(&state->mutex);
    uint64_t staked_subunits = calculate_staked_subunits(&state->bc, threshold_pubkey);
    uint64_t pending_staked = calculate_pending_consumed_subunits(state, threshold_pubkey, true);
    uint64_t scheduled_staked = atomic_load(&state->scheduled_staked_subunits);
    pthread_mutex_unlock(&state->mutex);

    uint64_t total_outbound_staked = pending_staked + scheduled_staked;

    // Calculate maximum available balance in exact subunits considering fees
    uint64_t available_staked_subunits = 0;
    if (staked_subunits > total_outbound_staked) {
        uint64_t usable = staked_subunits - total_outbound_staked;
        double rate = M_PI / 200.0;
        available_staked_subunits = (uint64_t)(usable / (1.0 + rate));
        while (available_staked_subunits + calculate_fee(available_staked_subunits, true) <= usable) {
            available_staked_subunits++;
        }
        available_staked_subunits--;
    }

    uint64_t display_units = (available_staked_subunits * 5) / 8;
    double available_staked_scl = (double)display_units / 100000000.0;

    printf("[Client] Available staked amount: %.8f SCL (total staked: %.8f, pending: %.8f, scheduled: %.8f)\n",
            available_staked_scl,
            (double)staked_subunits / SUBUNITS_PER_COIN,
            (double)pending_staked / SUBUNITS_PER_COIN,
            (double)scheduled_staked / SUBUNITS_PER_COIN);
        
    if (available_staked_subunits == 0) {
        fprintf(stderr, "[Client] ERROR: No staked SCL available for unstaking (including pending/scheduled operations and estimated fees)\n");
        return -1;
    }

    printf("Amount to unstake (max %.8f SCL): ", available_staked_scl);
    double amount_scl_double = validate_money_input();
    if (amount_scl_double <= 0) {
        fprintf(stderr, "[Client] ERROR: Invalid unstake amount\n");
        return -1;
    }
    
    // Safely round floating point translation to avoid sub-unit precision drops
    uint64_t amount_subunits = (uint64_t)round(amount_scl_double * SUBUNITS_PER_COIN);
    if (fabs(amount_scl_double - available_staked_scl) < 1e-9) {
        amount_subunits = available_staked_subunits; // Bypass truncation for exact MAX executions
    }
    if (amount_subunits > available_staked_subunits) {
        fprintf(stderr, "[Client] ERROR: Unstake amount exceeds available staked balance\n");
        return -1;
    }
    
    // Create and broadcast the unstake
    int ret = create_and_broadcast_unstake(state, amount_subunits, false);
    if (ret == 2) {
        fprintf(stderr, "[Client] Queuing unstake in background until previous operations confirm...\n");
        RecreateArgs *args = calloc(1, sizeof(RecreateArgs)); // Explicit memory zeroing
        if (args) {
            args->state = state;
            args->amount = amount_subunits;
            args->is_stake = false;
            args->is_transfer = false;
            // Record that this amount is now scheduled to prevent concurrent re-selection
            uint64_t expected_fee = calculate_fee(amount_subunits, true);
            atomic_fetch_add(&state->scheduled_staked_subunits, amount_subunits + expected_fee);
            spawn_recreation_thread(state, args);
        }
        return 0; // Return success since it's natively queued
    }
    return ret;
}

/* ============================================================================ */
/* SECTION 5: STATE TRANSITION EXECUTION (ATOMIC LEDGER MUTATION)               */
/* ============================================================================ */

/**
 * @brief Applies the state transitions of a pointer transfer, stake, or unstake operation to the ledger.
 *
 * @details
 * Partitions input pointers into transfer, fee (`spent = 2`), and change outputs. Marks original input
 * pointers as `spent = 1` in memory and disk database. Deducts fees from parent coins in O(1) time
 * and updates state MMR peaks cryptographically from LOCAL digests only (peer-supplied proof paths are never trusted).
 * Rollback occurs atomically if any step fails.
 *
 * @param[in,out] bc Pointer to Blockchain state container.
 * @param[in] input_pointers Array of input @ref Pointer structures to spend.
 * @param[in] proofs Array of @ref MMRProof inclusion proofs corresponding to inputs.
 * @param[in] num_inputs Count of input pointers.
 * @param[in] recipient_pubkey 2,592-byte Dilithium5 public key receiving the transfer output.
 * @param[in] amount Principal subunit volume transferred to recipient.
 * @param[in] tx_hash 32-byte transaction identifier creating new pointer outputs.
 * @param[in] set_stake_flag Flag setting `staked = 1` on transfer output.
 * @param[in] fee Non-refundable transaction fee allocated to fee pointers.
 * @return 1 on successful state mutation; 0 on error with full rollback.
 *
 * @pre Caller must hold `bc->rwlock` in write mode (`pthread_rwlock_wrlock`).
 * @complexity Time: O(num_inputs * log(MMR_leaves)), Space: O(num_inputs) rollback buffers.
 */
int update_transfer_state(Blockchain *bc, Pointer *input_pointers, MMRProof *proofs, size_t num_inputs,
                         const uint8_t *recipient_pubkey, uint64_t amount, uint8_t tx_hash[COIN_ID_LEN],
                         bool set_stake_flag, uint64_t fee) {
    if (!bc || !input_pointers || num_inputs == 0 || !recipient_pubkey || !tx_hash || amount == 0) {
        fprintf(stderr, "[Blockchain] Invalid parameters in update_transfer_state\n");
        return 0;
    }
    (void)proofs;  /* H-4 fix: proofs intentionally unused; verified by caller, MMR update rehashes from local digests. Kept for API stability. */

    Pointer *added_pointers = malloc(num_inputs * sizeof(Pointer) * 2);  // Allow for splits
    uint8_t (*added_pointer_ids)[COIN_ID_LEN] = malloc(num_inputs * COIN_ID_LEN * 2);
    if (!added_pointers || !added_pointer_ids) {
        fprintf(stderr, "[Blockchain] Memory allocation failed for rollback data\n");
        free(added_pointers);
        free(added_pointer_ids);
        return 0;
    }
    size_t added_count = 0;

    uint64_t remaining_amount = amount;
    uint64_t remaining_fee = fee;

    // O(1) Incremental Coin Balance Accounting
    uint64_t fee_deductions[MAX_INPUTS] = {0};

    for (size_t i = 0; i < num_inputs; i++) {
        Pointer *input = &input_pointers[i];
        SCLCoin *coin = hash_table_lookup(bc->coin_table, input->parent_coin_id, false);
        if (!coin) {
            fprintf(stderr, "[Blockchain] Coin not found\n");
            goto error;
        }

        GenericHashEntry *entry = hash_table_lookup(bc->pointer_table, input->pointer_id, true);
        if (!entry || entry->type != HASH_ENTRY_POINTER || entry->data.pointer.spent) {
            fprintf(stderr, "[Blockchain] Pointer invalid or spent\n");
            goto error;
        }
        Pointer *original = &entry->data.pointer;

        uint64_t current_start = original->start_subunit;
        uint64_t original_end = original->end_subunit;

        uint8_t old_pointer_id[COIN_ID_LEN];
        memcpy(old_pointer_id, original->pointer_id, COIN_ID_LEN);

        // Allocate to amount if needed
        if (remaining_amount > 0) {
            uint64_t alloc_size = (original_end - current_start + 1 <= remaining_amount) ? (original_end - current_start + 1) : remaining_amount;
            Pointer output = {0};
            output.spent = 0;
            memcpy(output.parent_coin_id, original->parent_coin_id, COIN_ID_LEN);
            memcpy(output.prev_tx_hash, tx_hash, COIN_ID_LEN);
            SHA256(recipient_pubkey, PUBKEY_LEN, output.owner_address);
            output.staked = set_stake_flag;
            output.start_subunit = current_start;
            output.end_subunit = current_start + alloc_size - 1;

            // Compute pointer_id
            uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
            uint8_t *pd = pointer_data;
            memcpy(pd, output.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
            memcpy(pd, output.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
            uint64_t start_be = htobe64(output.start_subunit);
            memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            uint64_t end_be = htobe64(output.end_subunit);
            memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            memcpy(pd, output.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
            SHA256(pointer_data, sizeof(pointer_data), output.pointer_id);

            if (!hash_table_insert(bc->pointer_table, output.pointer_id, &output, HASH_ENTRY_POINTER)) {
                fprintf(stderr, "[Blockchain] Failed to insert output pointer\n");
                goto error;
            }
            add_pointer_id_to_coin(bc->coin_pointers, output.parent_coin_id, output.pointer_id);
            scl_db_put_pointer(output.pointer_id, &output);

            memcpy(added_pointer_ids[added_count], output.pointer_id, COIN_ID_LEN);
            added_pointers[added_count] = output;
            added_count++;

            current_start += alloc_size;
            remaining_amount -= alloc_size;
        }

        // Allocate to fee if needed and remaining in input
        uint64_t remaining_in_input = original_end - current_start + 1;
        if (remaining_fee > 0 && remaining_in_input > 0) {
            uint64_t alloc_size = (remaining_in_input <= remaining_fee) ? remaining_in_input : remaining_fee;
            Pointer output = {0};
            output.spent = 2;
            memcpy(output.parent_coin_id, original->parent_coin_id, COIN_ID_LEN);
            memcpy(output.prev_tx_hash, tx_hash, COIN_ID_LEN);
            memcpy(output.owner_address, input->owner_address, USER_ID_LEN);
            output.staked = 0;
            output.start_subunit = current_start;
            output.end_subunit = current_start + alloc_size - 1;

            // Compute pointer_id
            uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
            uint8_t *pd = pointer_data;
            memcpy(pd, output.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
            memcpy(pd, output.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
            uint64_t start_be = htobe64(output.start_subunit);
            memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            uint64_t end_be = htobe64(output.end_subunit);
            memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            memcpy(pd, output.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
            SHA256(pointer_data, sizeof(pointer_data), output.pointer_id);

            if (!hash_table_insert(bc->pointer_table, output.pointer_id, &output, HASH_ENTRY_POINTER)) {
                fprintf(stderr, "[Blockchain] Failed to insert fee pointer\n");
                goto error;
            }
            add_pointer_id_to_coin(bc->coin_pointers, output.parent_coin_id, output.pointer_id);
            
            // Track fee deducted for O(1) balance accounting
            fee_deductions[i] = alloc_size;

            memcpy(added_pointer_ids[added_count], output.pointer_id, COIN_ID_LEN);
            added_pointers[added_count] = output;
            added_count++;

            current_start += alloc_size;
            remaining_fee -= alloc_size;
        }

        // Create updated pointer for any remaining subunits
        remaining_in_input = original_end - current_start + 1;
        if (remaining_in_input > 0) {
            Pointer updated_pointer = *original;
            updated_pointer.start_subunit = current_start;
            updated_pointer.end_subunit = original_end;
            memcpy(updated_pointer.prev_tx_hash, tx_hash, COIN_ID_LEN); // Update hash before serializing to preserve consistency

            // Compute new pointer_id
            uint8_t pointer_data[COIN_ID_LEN + USER_ID_LEN + sizeof(uint64_t) * 2 + COIN_ID_LEN];
            uint8_t *pd = pointer_data;
            memcpy(pd, updated_pointer.parent_coin_id, COIN_ID_LEN); pd += COIN_ID_LEN;
            memcpy(pd, updated_pointer.owner_address, USER_ID_LEN); pd += USER_ID_LEN;
            uint64_t start_be = htobe64(updated_pointer.start_subunit);
            memcpy(pd, &start_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            uint64_t end_be = htobe64(updated_pointer.end_subunit);
            memcpy(pd, &end_be, sizeof(uint64_t)); pd += sizeof(uint64_t);
            memcpy(pd, updated_pointer.prev_tx_hash, COIN_ID_LEN); pd += COIN_ID_LEN;
            SHA256(pointer_data, sizeof(pointer_data), updated_pointer.pointer_id);

            // Mark old pointer as spent in the database prior to eviction from memory table
            original->spent = 1;
            scl_db_put_pointer(old_pointer_id, original);

            if (!hash_table_remove(bc->pointer_table, old_pointer_id)) {
                fprintf(stderr, "[Blockchain] Failed to remove old pointer ID\n");
                goto error;
            }

            if (!hash_table_insert(bc->pointer_table, updated_pointer.pointer_id, &updated_pointer, HASH_ENTRY_POINTER)) {
                fprintf(stderr, "[Blockchain] Failed to insert updated pointer\n");
                goto error;
            }

            remove_pointer_id_from_coin(bc->coin_pointers, updated_pointer.parent_coin_id, old_pointer_id);
            add_pointer_id_to_coin(bc->coin_pointers, updated_pointer.parent_coin_id, updated_pointer.pointer_id);
            scl_db_put_pointer(updated_pointer.pointer_id, &updated_pointer);
        } else {
            // Fully consumed: mark original as spent
            original->spent = 1;
            scl_db_put_pointer(original->pointer_id, original);
        }
    }

    if (remaining_amount > 0 || remaining_fee > 0) {
        fprintf(stderr, "[Blockchain] Insufficient subunits after processing\n");
        goto error;
    }

    // Update remaining_subunits of modified parent coins using O(1) Delta Math
    for (size_t i = 0; i < num_inputs; i++) {
        SCLCoin *parent_coin = hash_table_lookup(bc->coin_table, input_pointers[i].parent_coin_id, false);
        if (parent_coin) {
            uint64_t old_sub = parent_coin->remaining_subunits;
            
            // O(1) Delta Accounting: ONLY re-calculate if the remaining balance actively changed (fees deducted)
            if (fee_deductions[i] > 0) {
                if (parent_coin->remaining_subunits >= fee_deductions[i]) {
                    parent_coin->remaining_subunits -= fee_deductions[i];
                } else {
                    parent_coin->remaining_subunits = 0;
                }
                scl_db_put_coin(parent_coin->coin_id, parent_coin);
                
                /* H-4 fix: rehash the peak from LOCAL sibling digests only — the
                 * client's proof path is never trusted to define the state root. */
                mmr_update_leaf_local(bc->mmr, parent_coin->coin_id, old_sub, parent_coin->remaining_subunits);
            }
        }
    }
    free(added_pointers);
    free(added_pointer_ids);
    return 1;

error:
    // Rollback state mutations on failure by purging newly inserted pointers
    for (size_t i = 0; i < added_count; i++) {
        hash_table_remove(bc->pointer_table, added_pointer_ids[i]);
        remove_pointer_id_from_coin(bc->coin_pointers, added_pointers[i].parent_coin_id, added_pointer_ids[i]);
    }
    free(added_pointers);
    free(added_pointer_ids);
    return 0;
}

/* ============================================================================ */
/* SECTION 6: BALANCE & SUPPLY AUDITING IMPLEMENTATION                          */
/* ============================================================================ */

/**
 * @brief Computes the cumulative unspent subunit balance owned by a public key.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key to audit.
 * @param[in] staked Flag: `true` queries staked balance; `false` queries liquid balance.
 * @return Cumulative unspent subunits owned by the key.
 *
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_balance_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN], bool staked) {
    uint64_t balance = 0;
    uint8_t user_id[USER_ID_LEN];
    SHA256(pubkey, PUBKEY_LEN, user_id);
    
    pthread_rwlock_rdlock(&((Blockchain *)bc)->rwlock);
    for (size_t i = 0; i < bc->pointer_table->size; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER &&
                memcmp(entry->data.pointer.owner_address, user_id, USER_ID_LEN) == 0 &&
                !entry->data.pointer.spent &&
                entry->data.pointer.staked == staked) {  // Filter by staked flag
                SCLCoin *parent = hash_table_lookup(bc->coin_table, entry->data.pointer.parent_coin_id, false);
                if (parent && entry->data.pointer.start_subunit <= entry->data.pointer.end_subunit &&
                    entry->data.pointer.end_subunit <= parent->total_subunits) {
                    balance += entry->data.pointer.end_subunit - entry->data.pointer.start_subunit + 1;
                }
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(&((Blockchain *)bc)->rwlock);
    return balance;
}

/**
 * @brief Computes cumulative subunits locked in unconfirmed pending mempool operations for an identity.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the sender.
 * @param[in] expect_staked Flag: `true` checks unstake operations; `false` checks liquid spends.
 * @return Total subunits locked in in-flight mempool transactions.
 *
 * @complexity Time: O(MAX_PENDING_OPS), Space: O(1).
 */
uint64_t calculate_pending_consumed_subunits(State *state, const uint8_t *pubkey, bool expect_staked) {
    if (!state || !pubkey) return 0;

    uint8_t user_id[USER_ID_LEN];
    SHA256(pubkey, PUBKEY_LEN, user_id);

    uint64_t total_pending = 0;
    
    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        Operation *op = atomic_load_explicit(&state->pending_operations[i], memory_order_acquire);
        if (!op) continue;
        
        bool is_consuming = false;
        uint64_t amount = 0;
        const uint8_t *op_pubkey = NULL;
                
        if (!expect_staked) {
            if (op->type == OP_TRANSFER_POINTER) {
                is_consuming = true;
                amount = op->data.transfer_pointer.amount + calculate_fee(op->data.transfer_pointer.amount, false);
                op_pubkey = op->data.transfer_pointer.inputs[0].owner_address;
            } else if (op->type == OP_STAKE) {
                is_consuming = true;
                amount = op->data.stake.amount + calculate_fee(op->data.stake.amount, true);
                op_pubkey = op->data.stake.inputs[0].owner_address;
            } else if (op->type == OP_APPLY_DRIFT_CERT && op->data.apply_drift_cert.num_inputs > 0) {
                /* Drift certificate anchoring spends liquid pointers under the
                 * halved (staking-grade) fee schedule — mirror the mempool's
                 * fee accounting (add_pending_operation / validate_operation)
                 * so in-flight anchors reserve amount + fee exactly like
                 * transfers and stakes. */
                is_consuming = true;
                amount = op->data.apply_drift_cert.amount + calculate_fee(op->data.apply_drift_cert.amount, true);
                op_pubkey = op->data.apply_drift_cert.inputs[0].owner_address;
            }
        } else {
            if (op->type == OP_UNSTAKE) {
                is_consuming = true;
                amount = op->data.unstake.amount + calculate_fee(op->data.unstake.amount, true);
                op_pubkey = op->data.unstake.inputs[0].owner_address;
            }
        }
                
        if (is_consuming && op_pubkey != NULL && memcmp(op_pubkey, user_id, USER_ID_LEN) == 0) {
            total_pending += amount;
        }
    }
    
    return total_pending;
}

/**
 * @brief Computes total staked subunits currently locked under a specific threshold public key.
 *
 * @param[in] bc Pointer to Blockchain state container.
 * @param[in] pubkey 2,592-byte threshold committee public key.
 * @return Total staked subunits locked under the key.
 *
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_staked_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN]) {
    if (!bc || !pubkey) {
        fprintf(stderr, "[Blockchain] Invalid parameters in calculate_staked_subunits\n");
        return 0;
    }

    uint8_t user_id[USER_ID_LEN];
    SHA256(pubkey, PUBKEY_LEN, user_id);

    uint64_t balance = 0;
    pthread_rwlock_rdlock(&((Blockchain *)bc)->rwlock);
    for (size_t i = 0; i < bc->pointer_table->size; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER &&
                memcmp(entry->data.pointer.owner_address, user_id, USER_ID_LEN) == 0 &&
                !entry->data.pointer.spent &&
                entry->data.pointer.staked) {
                SCLCoin *parent = hash_table_lookup(bc->coin_table, entry->data.pointer.parent_coin_id, false);
                if (parent && entry->data.pointer.start_subunit <= entry->data.pointer.end_subunit &&
                    entry->data.pointer.end_subunit <= parent->total_subunits) {
                    balance += entry->data.pointer.end_subunit - entry->data.pointer.start_subunit + 1;
                }
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(&((Blockchain *)bc)->rwlock);
    return balance;
}

/**
 * @brief Computes total staked subunits attributable to an individual validator identity.
 *
 * @param[in] state Pointer to global node state container.
 * @param[in] target_pk 2,592-byte Dilithium5 public key of the validator.
 * @return Total staked subunits attributable to the validator.
 *
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_staked_subunits_by_owner(State *state, const uint8_t target_pk[PUBKEY_LEN]) {
    if (!state || !target_pk) return 0;
    uint64_t staked_balance = 0;
    Blockchain *bc = &state->bc;
    
    uint8_t local_threshold_addr[USER_ID_LEN] = {0};
    uint8_t local_threshold_pk[PUBKEY_LEN];
    bool has_local_threshold = false;
    if (memcmp(target_pk, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) == 0) {
        if (compute_threshold_pubkey(state, local_threshold_pk) == 0) {
            SHA256(local_threshold_pk, PUBKEY_LEN, local_threshold_addr);
            has_local_threshold = true;
        }
    }

    pthread_rwlock_rdlock(&bc->rwlock);
    for (size_t i = 0; i < bc->pointer_table->size; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER && !entry->data.pointer.spent && entry->data.pointer.staked) {
                Pointer *ptr = &entry->data.pointer;
                bool belongs_to_user = false;
                if (has_local_threshold && memcmp(ptr->owner_address, local_threshold_addr, USER_ID_LEN) == 0) {
                    belongs_to_user = true;
                } else {
                    PubkeyCacheEntry *cache_entry = hash_table_lookup(state->pubkey_cache, ptr->owner_address, false);
                    if (cache_entry && memcmp(cache_entry->pubkey, target_pk, PUBKEY_LEN) == 0) {
                        belongs_to_user = true;
                    }
                }
                if (belongs_to_user) {
                    SCLCoin *parent = hash_table_lookup(bc->coin_table, ptr->parent_coin_id, false);
                    if (parent && ptr->start_subunit <= ptr->end_subunit && ptr->end_subunit <= parent->total_subunits) {
                        staked_balance += ptr->end_subunit - ptr->start_subunit + 1;
                    }
                }
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(&bc->rwlock);
    return staked_balance;
}

/**
 * @brief Calculates the cumulative staked subunits across all active pointers in the entire ledger.
 *
 * @details
 * Iterates across `bc->pointer_table` buckets, accumulating range volumes
 * (`end_subunit - start_subunit + 1`) for all unspent pointers (`spent == 0`)
 * flagged as staked (`staked == 1`).
 *
 * @pre `bc` must be non-NULL.
 * @pre Caller MUST hold `bc->rwlock` in read or write mode before invocation.
 * @post Returns non-negative integer subunit total bounded by @ref MAX_TOTAL_SUBUNITS.
 * @sideeffects Pure inspection function; no state mutations.
 * @synchronization Caller-synchronized via `bc->rwlock`.
 *
 * @param[in] bc Pointer to Blockchain state container.
 *               - Direction: in
 *               - Ownership: Borrowed.
 *
 * @return uint64_t Total staked subunits across all network participants.
 *
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_total_staked_subunits(const Blockchain *bc) {
    if (!bc || !bc->pointer_table) {
        fprintf(stderr, "[Blockchain] Invalid parameters in calculate_total_staked_subunits\n");
        return 0;
    }

    uint64_t total_staked = 0;
    pthread_rwlock_rdlock(&bc->pointer_table->rwlock);
    
    // Iterate through all pointers in the primary pointer table
    for (size_t i = 0; i < bc->pointer_table->size; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER &&
                !entry->data.pointer.spent &&
                entry->data.pointer.staked) {
                
                Pointer *ptr = &entry->data.pointer;
                SCLCoin *parent = hash_table_lookup(bc->coin_table, ptr->parent_coin_id, false);
                
                if (parent && ptr->start_subunit <= ptr->end_subunit &&
                    ptr->end_subunit <= parent->total_subunits) {
                    total_staked += ptr->end_subunit - ptr->start_subunit + 1;
                }
            }
            entry = entry->next;
        }
    }

    // Traverse unmigrated legacy buckets if incremental resizing is in progress
    if (bc->pointer_table->old_buckets) {
        for (size_t i = bc->pointer_table->resize_progress; i < bc->pointer_table->old_size; i++) {
            GenericHashEntry *entry = bc->pointer_table->old_buckets[i];
            while (entry) {
                if (entry->type == HASH_ENTRY_POINTER &&
                    !entry->data.pointer.spent &&
                    entry->data.pointer.staked) {
                    
                    Pointer *ptr = &entry->data.pointer;
                    SCLCoin *parent = hash_table_lookup(bc->coin_table, ptr->parent_coin_id, false);
                    
                    if (parent && ptr->start_subunit <= ptr->end_subunit &&
                        ptr->end_subunit <= parent->total_subunits) {
                        total_staked += ptr->end_subunit - ptr->start_subunit + 1;
                    }
                }
                entry = entry->next;
            }
        }
    }
    
    pthread_rwlock_unlock(&bc->pointer_table->rwlock);
    return total_staked;
}

/**
 * @brief Calculates the cumulative transaction fee subunits currently held in fee pointers (`spent == 2`).
 *
 * @pre `bc` must be non-NULL.
 * @post Returns cumulative unspent recycled fee balance.
 * @synchronization Internally acquires `bc->pointer_table->rwlock` in read mode.
 *
 * @param[in] bc Pointer to Blockchain state container.
 *               - Direction: in
 *
 * @return uint64_t Total accumulated fee subunits awaiting recycling.
 *
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_total_fees_subunits(const Blockchain *bc) {
    if (!bc || !bc->pointer_table) {
        return 0;
    }

    uint64_t total_fees = 0;
    pthread_rwlock_rdlock(&bc->pointer_table->rwlock);
    
    // Accumulate unspent subunits held in fee pointers (spent == 2) in primary buckets
    for (size_t i = 0; i < bc->pointer_table->size; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER && entry->data.pointer.spent == 2) {
                SCLCoin *parent = hash_table_lookup(bc->coin_table, entry->data.pointer.parent_coin_id, false);
                if (parent) {
                    total_fees += entry->data.pointer.end_subunit - entry->data.pointer.start_subunit + 1;
                }
            }
            entry = entry->next;
        }
    }

    // Accumulate unspent subunits held in unmigrated old buckets if table is resizing
    if (bc->pointer_table->old_buckets) {
        for (size_t i = bc->pointer_table->resize_progress; i < bc->pointer_table->old_size; i++) {
            GenericHashEntry *entry = bc->pointer_table->old_buckets[i];
            while (entry) {
                if (entry->type == HASH_ENTRY_POINTER && entry->data.pointer.spent == 2) {
                    SCLCoin *parent = hash_table_lookup(bc->coin_table, entry->data.pointer.parent_coin_id, false);
                    if (parent) {
                        total_fees += entry->data.pointer.end_subunit - entry->data.pointer.start_subunit + 1;
                    }
                }
                entry = entry->next;
            }
        }
    }

    pthread_rwlock_unlock(&bc->pointer_table->rwlock);
    return total_fees;
}

/**
 * @brief Calculates cumulative lifetime transaction fees paid by a specific user identity.
 *
 * @details
 * Derives the user address via `SHA256(pubkey)` and accumulates range volumes across
 * all historical fee pointers (`spent == 2`) matching that owner address.
 *
 * @pre `bc` and `pubkey` must be non-NULL.
 * @post Returns cumulative fee subunits generated by user.
 * @synchronization Acquires `bc->rwlock` in read mode internally.
 *
 * @param[in] bc     Pointer to Blockchain state container.
 *                   - Direction: in
 * @param[in] pubkey 2,592-byte Dilithium5 public key of the user.
 *                   - Direction: in
 *
 * @return uint64_t Cumulative fee subunits paid by this identity.
 *
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t calculate_fees_paid_subunits(const Blockchain *bc, const uint8_t pubkey[PUBKEY_LEN]) {
    if (!bc || !pubkey) {
        fprintf(stderr, "[Blockchain] Invalid parameters in calculate_fees_paid_subunits\n");
        return 0;
    }

    uint8_t user_id[USER_ID_LEN];
    SHA256(pubkey, PUBKEY_LEN, user_id);

    uint64_t total_fees = 0;
    pthread_rwlock_rdlock(&((Blockchain *)bc)->rwlock);
    
    // Iterate through all pointers in the pointer table
    for (size_t i = 0; i < bc->pointer_table->size; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER &&
                entry->data.pointer.spent == 2 && // Fee pointers are marked with spent=2
                memcmp(entry->data.pointer.owner_address, user_id, USER_ID_LEN) == 0) {
                
                Pointer *ptr = &entry->data.pointer;
                SCLCoin *parent = hash_table_lookup(bc->coin_table, ptr->parent_coin_id, false);
                
                if (parent && ptr->start_subunit <= ptr->end_subunit &&
                    ptr->end_subunit <= parent->total_subunits) {
                    total_fees += ptr->end_subunit - ptr->start_subunit + 1;
                }
            }
            entry = entry->next;
        }
    }
    
    pthread_rwlock_unlock(&((Blockchain *)bc)->rwlock);
    return total_fees;
}

/**
 * @brief Harvests unspent fee pointers (`spent == 2`) to recycle into block rewards post-cap.
 *
 * @param[in,out] bc Pointer to Blockchain state container.
 * @param[out] fees Array receiving copies of harvested fee pointers.
 * @param[in] max_fees Maximum count of fee pointers to harvest.
 * @return Total recycled subunits harvested.
 *
 * @complexity Time: O(total_pointers), Space: O(1).
 */
uint64_t collect_fee_pointers(Blockchain *bc, Pointer *fees, uint32_t max_fees) {
    uint64_t total_subunits = 0;
    uint32_t fee_count = 0;
    pthread_rwlock_wrlock(&bc->rwlock);
    for (size_t i = 0; i < bc->pointer_table->size && fee_count < max_fees; i++) {
        GenericHashEntry *entry = bc->pointer_table->buckets[i];
        while (entry && fee_count < max_fees) {
            if (entry->type == HASH_ENTRY_POINTER && entry->data.pointer.spent == 2) { // No owner check
                SCLCoin *parent = hash_table_lookup(bc->coin_table, entry->data.pointer.parent_coin_id, false);
                if (parent) {
                    fees[fee_count] = entry->data.pointer;
                    total_subunits += fees[fee_count].end_subunit - fees[fee_count].start_subunit + 1;
                    entry->data.pointer.spent = 1; // Mark as recycled
                    scl_db_put_pointer(entry->data.pointer.pointer_id, &entry->data.pointer);
                    fee_count++;
                }
            }
            entry = entry->next;
        }
    }
    pthread_rwlock_unlock(&bc->rwlock);
    return total_subunits;
}

/* ============================================================================ */
/* SECTION 7: SHIELDED CENTINEL BLOOM FILTER IMPLEMENTATION                     */
/* ============================================================================ */

/**
 * @brief Sets Bloom filter bits corresponding to a 32-byte spent ZK-PRF nullifier.
 *
 * @param[in,out] filter Pointer to Bloom filter byte array of size @ref NULLIFIER_BLOOM_BYTES.
 * @param[in] nullifier 32-byte spent ZK-PRF nullifier.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void nullifier_bloom_add(uint8_t *filter, const uint8_t *nullifier) {
    if (!filter || !nullifier) return;
    uint32_t h1, h2, h3;
    memcpy(&h1, nullifier, 4);
    memcpy(&h2, nullifier + 4, 4);
    memcpy(&h3, nullifier + 8, 4);

    // Map hash slices to Bloom filter bit positions and set flags
    uint32_t bit1 = h1 & (NULLIFIER_BLOOM_BITS - 1);
    uint32_t bit2 = h2 & (NULLIFIER_BLOOM_BITS - 1);
    uint32_t bit3 = h3 & (NULLIFIER_BLOOM_BITS - 1);

    filter[bit1 / 8] |= (1 << (bit1 % 8));
    filter[bit2 / 8] |= (1 << (bit2 % 8));
    filter[bit3 / 8] |= (1 << (bit3 % 8));
}

/**
 * @brief Tests the Bloom filter for potential membership of a spent ZK-PRF nullifier.
 *
 * @param[in] filter Pointer to Bloom filter byte array.
 * @param[in] nullifier 32-byte nullifier to test.
 * @return `true` if all bit lanes are set (potential match); `false` if definitely unspent.
 *
 * @complexity Time: O(1), Space: O(1).
 */
bool nullifier_bloom_check(const uint8_t *filter, const uint8_t *nullifier) {
    if (!filter || !nullifier) return false;
    uint32_t h1, h2, h3;
    memcpy(&h1, nullifier, 4);
    memcpy(&h2, nullifier + 4, 4);
    memcpy(&h3, nullifier + 8, 4);

    // Map hash slices to Bloom filter bit positions and verify presence
    uint32_t bit1 = h1 & (NULLIFIER_BLOOM_BITS - 1);
    uint32_t bit2 = h2 & (NULLIFIER_BLOOM_BITS - 1);
    uint32_t bit3 = h3 & (NULLIFIER_BLOOM_BITS - 1);

    if (!(filter[bit1 / 8] & (1 << (bit1 % 8)))) return false;
    if (!(filter[bit2 / 8] & (1 << (bit2 % 8)))) return false;
    if (!(filter[bit3 / 8] & (1 << (bit3 % 8)))) return false;
    return true;
}
