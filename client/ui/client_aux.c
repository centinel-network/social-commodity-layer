/**
 * @file client_aux.c
 * @brief Client Auxiliary Interface, Terminal Interaction, and Centinel Bearer Protocol Subsystem.
 *
 * Formal Module: Client Auxiliary & Terminal User Interface Subsystem (CLIENT-AUX)
 *
 * Functional Responsibilities:
 * - Implements interactive Command-Line Interface (CLI) workflows for node operators,
 *   including transaction initiation, staking, audit ring inspection, and wallet management.
 * - Computes real-time financial ledger balances (unspent, staked, pending, and scheduled
 *   SCL atomic subunits) and evaluates unspent Encrypted UTXO Validations.
 * - Manages valuation proposal authoring, zero-knowledge validation burning, and ML-DSA-87
 *   digital signature authentication prior to ingestion into the consensus engine.
 * - Implements the off-chain Centinel shielded bearer instrument protocol:
 *   - Encapsulation: Burns on-chain validation UTXOs to mint self-contained, homomorphic
 *     BDLOP bearer instruments accompanied by zero-knowledge Stern inclusion proofs.
 *   - Redemption: Deserializes off-chain Centinel tickets, validates commitment homomorphic
 *     bounds and Merkle Mountain Range (MMR) peaks, generates non-interactive zero-knowledge
 *     redemption proofs, and injects OP_REDEEM_CENTINEL operations into the mempool.
 * - Exposes interactive control over autonomous consensus auto-pilot parameters.
 * - Implements interactive wallet credential hot-reloading and P2P identity updating
 *   from persistent key storage files (`load_wallet_credentials_interactive`).
 *
 * Invariants Maintained Across Module Boundary:
 * - Strict Lock Hierarchy: Mutexes and read-write locks must always be acquired in the
 *   deterministic canonical order:
 *   1. `state->mutex`
 *   2. `user->mutex`
 *   3. `state->bc.rwlock`
 *   4. `state->user_wallet.utxo_mutex`
 *   5. `state->wallet_mutex`
 *   Violating this order introduces provable circular deadlock risk with P2P network threads.
 * - Encrypted UTXO Double-Spend Invariant: A validation UTXO is deemed spendable if and
 *   only if its nullifier is absent from RAM nullifier hash tables, libmdbx disk nullifier
 *   storage, Bloom filters, and local unconfirmed pending mempool operations.
 * - Homomorphic Value Conservation: For any Centinel split or redemption operation,
 *   the sum of transferred and change values must equal the original UTXO value:
 *   \f$ v_{\text{old}} = v_{\text{transfer}} + v_{\text{change}} \f$.
 * - Ephemeral Secret Sanitation: Private keys, PRF states, and blinding factors generated
 *   on the stack during Centinel operations must be zeroized prior to function return.
 *
 * Cryptographic and RFC References:
 * - BDLOP Lattice Commitment Scheme: Baum et al., SCN 2018.
 * - Stern Zero-Knowledge Identification and Signature Framework.
 * - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA-87 / Dilithium5).
 * - Merkle Mountain Range (MMR) Dynamic Append-Only Tree Specification.
 * - RFC 8999: Rules for Designing Protocols using the Internet Protocol Layer.
 *
 * Dependencies:
 * - Standard C Library: stdio.h, stdlib.h, string.h, math.h, unistd.h, fcntl.h, time.h.
 * - OpenSSL: openssl/sha.h (SHA-256), openssl/rand.h (CSPRNG entropy).
 * - Internal Modules: client_aux.h, game_state.h, client_network.h, consensus.h, network.h,
 *   blockchain.h, hash_table.h, mmr.h, user.h, queue.h, protocol.h, client_state.h,
 *   constants.h, crypto.h, utils.h, database.h.
 *
 * Concurrency and Reentrancy:
 * - CLI presentation routines execute on the node main thread.
 * - Non-reentrant terminal I/O functions access shared state protected by fine-grained
 *   concurrency primitives (pthread_mutex_t and pthread_rwlock_t).
 *
 * Memory Ownership Paradigms:
 * - Dynamic valuation arrays (*valuations) are reallocated in-place and owned by the caller.
 * - Centinel ticket allocations are ephemeral and freed immediately following serialization
 *   or transaction broadcast.
 * - Snapshot copies of GameState are acquired via `acquire_game_state_snapshot()` and
 *   must be released with `release_game_state_snapshot()`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "client_aux.h"
#include "game_state.h"
#include "client_network.h"
#include "consensus.h"
#include "network.h"
#include "blockchain.h"
#include "hash_table.h"
#include "mmr.h"
#include "user.h"
#include "queue.h"
#include "protocol.h"
#include "client_state.h"
#include "constants.h"
#include "crypto.h"
#include "utils.h"
#include "database.h"

/* ============================================================================
 * SECTION 1: INSTRUCTIONAL AND INFORMATIONAL VIEWS
 *
 * Architectural Preface:
 * Formats and renders node participation documentation and wallet cryptographic
 * identity parameters to standard output. Translates binary Dilithium keys,
 * PRF matrices, and seeds into human-readable hexadecimal representations.
 * ============================================================================ */

/**
 * @brief Renders instructional participation guidelines for consensus operators.
 *
 * @pre `state` must point to an allocated, initialized GameState structure.
 * @post Renders operational instructions to stdout; no internal state is modified.
 * @note Currently a placeholder for dynamic consensus rule rendering.
 * @warning Thread-safe; does not access mutable state.
 *
 * @param[in] state Pointer to GameState structure.
 *                  - Direction: in
 *                  - Ownership: Caller-owned, borrowed by callee.
 *
 * @return None.
 *
 * @complexity Time: O(1).
 * @complexity Space: O(1).
 */
void show_instructions(GameState *state) {
    (void)state;
}

/**
 * @brief Exports and displays full cryptographic wallet parameters and seeds in terminal.
 *
 * Translates the operator's ML-DSA-87 (Dilithium5) public and secret keys, peer network
 * public key, Module-SIS PRF evaluation key, and 32-byte viewport seed into hexadecimal
 * format and renders them to the terminal.
 *
 * @pre `user` must point to a valid User context, or be NULL.
 * @pre `state` must be non-null and point to an initialized State structure.
 * @post Wallet public and secret parameters are rendered to stdout.
 * @note Allocates heap memory for hexadecimal formatting strings to avoid stack exhaustion.
 * @warning Acquires `state->wallet_mutex`. Private key material is read directly under lock.
 *
 * @param[in] user  Pointer to User structure (currently unused, borrowed).
 * @param[in] state Pointer to global State structure containing user_wallet.
 *
 * @return None.
 *
 * @complexity Time: O(DILITHIUM_SECRETKEY_LEN + PRF_M) byte-to-hex conversions.
 * @complexity Space: O(DILITHIUM_SECRETKEY_LEN + DILITHIUM_PUBKEY_LEN + PRF_M) heap buffers.
 */
void view_wallet(User *user, State *state) {
    (void)user;
    if (!state) return;

    // Buffer allocations for hexadecimal string formatting (2 hex chars per byte + null terminator)
    char hex_peer[65];
    char hex_uid[USER_ID_LEN * 2 + 1];
    
    // Allocate public key, private key, and PRF buffers on heap to prevent stack overflow
    size_t pub_len = DILITHIUM_PUBKEY_LEN * 2 + 1;
    char *hex_pub = malloc(pub_len);
    if (!hex_pub) return;

    size_t prf_len = PRF_M * 2 + 1;
    char *hex_prf = malloc(prf_len);
    if (!hex_prf) {
        free(hex_pub);
        return;
    }

    size_t priv_len = DILITHIUM_SECRETKEY_LEN * 2 + 1;
    char *hex_priv = malloc(priv_len);
    if (!hex_priv) {
        free(hex_pub);
        free(hex_prf);
        return;
    }

    // Protect wallet reads against concurrent signature or key-rotation operations
    pthread_mutex_lock(&state->wallet_mutex);
    uint8_t user_id[USER_ID_LEN];
    sha256_hash(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);

    // Perform conversions directly from synchronized state wallet context
    bytes_to_hex(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, hex_pub);
    bytes_to_hex(state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, 32, hex_peer);
    bytes_to_hex(user_id, USER_ID_LEN, hex_uid);
    bytes_to_hex((const uint8_t *)state->user_wallet.prf_key.k, PRF_M, hex_prf);
    bytes_to_hex(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, hex_priv);

    uint8_t prf_seed[KAPPA];
    sha256_hash(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN, prf_seed);
    pthread_mutex_unlock(&state->wallet_mutex);

    // Format derived viewport seed into hexadecimal representation
    char hex_seed[KAPPA * 2 + 1];
    bytes_to_hex(prf_seed, KAPPA, hex_seed);

    printf("\n=== Wallet Details ===\n");
    printf("Unique Identifier (User ID): %s\n", hex_uid);
    printf("Dilithium Public Key (Full): %s\n", hex_pub);
    printf("Peer Dilithium Pubkey (32B): %s\n", hex_peer);
    printf("User PRF Key (%d bytes):     %s\n", PRF_M, hex_prf);
    printf("Dilithium Private Key (Full):%s\n", hex_priv);
    printf("Viewport Seed (32B Hex):     %s\n", hex_seed);

    // Scrub and deallocate temporary heap buffers
    explicit_bzero(hex_priv, priv_len);
    free(hex_pub);
    free(hex_prf);
    free(hex_priv);
}

/* ============================================================================
 * SECTION 2: BALANCE AND ECONOMIC VALUATION INSPECTION
 *
 * Architectural Preface:
 * Aggregates on-chain and off-chain financial state. Scans the local UTXO table,
 * cross-verifying candidate nullifiers against in-memory nullifier tables,
 * disk-backed libmdbx storage, Bloom filters, and mempool spend locks.
 * Computes atomic subunit economics ($1\text{ SCL} = 160,000,000\text{ subunits}$)
 * and consensus stage thresholds.
 * ============================================================================ */

/**
 * @brief Calculates the spendable count of mature Encrypted UTXO Validations.
 *
 * Scans `state->user_wallet.val_utxos`, verifying for each unspent output:
 * 1. Absence of nullifier in `state->bc.centinel.nullifier_set` (RAM).
 * 2. Negative result on Bloom filter / disk verification (`scl_db_has_nullifier`).
 * 3. Absence of nullifier in active local mempool operations (`OP_REDEEM_CENTINEL`).
 * 4. Presence of the BDLOP commitment hash in the Merkle Mountain Range leaf tree.
 *
 * @pre `state` must be non-null and point to an initialized State structure.
 * @post Returns count of spendable validation tickets.
 * @note Acquires `state->bc.rwlock` (read) followed by `state->user_wallet.utxo_mutex`.
 * @warning Must not be called while holding `state->user_wallet.utxo_mutex` (deadlock).
 *
 * @param[in] state Pointer to global State structure.
 *
 * @return uint64_t Total quantity of available, mature validation units.
 *
 * @complexity Time: O(N * (log M + hash)), where N = num_val_utxos, M = MMR leaf count.
 * @complexity Space: O(1) auxiliary space.
 */
static uint64_t get_available_utxo_validations(State *state) {
    uint64_t utxo_validations = 0;
    pthread_rwlock_rdlock(&state->bc.rwlock);
    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
        ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
        
        // Gatekeeper check: RAM nullifier set -> Bloom filter -> Persistent disk database
        bool is_spent = hash_table_lookup(state->bc.centinel.nullifier_set, utxo->nullifier, true) != NULL ||
                       (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, utxo->nullifier) &&
                        scl_db_has_nullifier(utxo->nullifier));
            
        // Check if locked in local mempool pending block inclusion
        bool is_pending_spend = false;
        for (int k = 0; k < MAX_PENDING_OPS; k++) {
            Operation *pop = atomic_load_explicit(&state->pending_operations[k], memory_order_acquire);
            if (pop && pop->type == OP_REDEEM_CENTINEL && memcmp(pop->data.redeem_centinel.nullifier, utxo->nullifier, NULLIFIER_LEN) == 0) {
                is_pending_spend = true;
                break;
            }
        }

        // Verify that commitment has been anchored in the Merkle Mountain Range
        if (!is_spent && !is_pending_spend) {
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&utxo->commitment, sizeof(BdlopCommitment), commitment_hash);
            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, commitment_hash, 0) >= 0) {
                utxo_validations += utxo->amount;
            }
        }
    }
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
    pthread_rwlock_unlock(&state->bc.rwlock);
    return utxo_validations;
}

/**
 * @brief Displays operator balances, pending spends, fees, and Encrypted UTXO Validations.
 *
 * Aggregates spendable SCL subunits, staked subunits, outbound mempool deductions,
 * scheduled consensus deductions, and cumulative fees paid. Disaggregates mature vs.
 * unconfirmed validation UTXOs.
 *
 * @pre `user` and `state` must be non-null and fully initialized.
 * @post Formatted balances rendered to stdout.
 * @warning Enforces canonical lock order:
 *          1. `state->mutex`
 *          2. `user->mutex`
 *          3. `state->bc.rwlock` (read)
 *          4. `state->user_wallet.utxo_mutex`
 *
 * @param[in] user  Pointer to active User structure.
 * @param[in] state Pointer to global State structure.
 *
 * @return None.
 *
 * @complexity Time: O(P + U * log M) where P = pointer count, U = UTXO count, M = MMR size.
 * @complexity Space: O(1) auxiliary space.
 */
void show_balances(User *user, State *state) {
    if (!user || !state) return;
    
    // Acquire outer state and user synchronization locks
    pthread_mutex_lock(&state->mutex);
    pthread_mutex_lock(&user->mutex);
    
    uint8_t threshold_pubkey[PUBKEY_LEN];
    if (compute_threshold_pubkey(state, threshold_pubkey) != 0) {
        pthread_mutex_unlock(&user->mutex);
        pthread_mutex_unlock(&state->mutex);
        return;
    }

    // 1. Calculate SCL Balances across Ledger Pointer Graph
    uint64_t total_subunits = calculate_balance_subunits(&state->bc, user->dilithium_pubkey, false);
    uint64_t staked_subunits = calculate_staked_subunits(&state->bc, threshold_pubkey);
    uint64_t pending_unstaked = calculate_pending_consumed_subunits(state, user->dilithium_pubkey, false);
    uint64_t pending_staked_consumed = calculate_pending_consumed_subunits(state, threshold_pubkey, true);
    
    uint64_t scheduled_unstaked = atomic_load(&state->scheduled_consumed_subunits);
    uint64_t scheduled_staked = atomic_load(&state->scheduled_staked_subunits);

    // 2. Calculate Transaction Fees Paid by User Pubkey
    uint64_t fees_paid = calculate_fees_paid_subunits(&state->bc, user->dilithium_pubkey);
    double fees_paid_scl = (double)fees_paid / SUBUNITS_PER_COIN;
    
    // 3. Calculate Encrypted UTXO Validation Balance (Mature vs. Pending MMR Anchor)
    uint64_t utxo_validations = 0;
    uint64_t pending_utxo_validations = 0;
    
    pthread_rwlock_rdlock(&state->bc.rwlock);
    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
        ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
        if (memcmp(utxo->pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN) != 0) continue;
        
        // Multi-tier double-spend check: RAM nullifier table -> Bloom filter -> Disk DB
        bool is_spent = hash_table_lookup(state->bc.centinel.nullifier_set, utxo->nullifier, true) != NULL ||
                       (nullifier_bloom_check(state->bc.centinel.nullifier_bloom, utxo->nullifier) &&
                        scl_db_has_nullifier(utxo->nullifier));
            
        // Local mempool reservation check
        bool is_pending_spend = false;
        for (int k = 0; k < MAX_PENDING_OPS; k++) {
            Operation *pop = atomic_load_explicit(&state->pending_operations[k], memory_order_acquire);
            if (pop && pop->type == OP_REDEEM_CENTINEL && memcmp(pop->data.redeem_centinel.nullifier, utxo->nullifier, NULLIFIER_LEN) == 0) {
                is_pending_spend = true;
                break;
            }
        }

        // Categorize into mature (anchored in MMR) vs pending (mined in recent block but unanchored)
        if (!is_spent && !is_pending_spend) {
            uint8_t commitment_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&utxo->commitment, sizeof(BdlopCommitment), commitment_hash);
            if (mmr_get_leaf_position(state->bc.centinel.validation_commitments, commitment_hash, 0) >= 0) {
                utxo_validations += utxo->amount;
            } else {
                pending_utxo_validations += utxo->amount;
            }
        }
    }
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
    pthread_rwlock_unlock(&state->bc.rwlock);

    // 4. Convert Atomic Subunits to Whole SCL (1 SCL = 160,000,000 subunits)
    double total_scl = (double)total_subunits / SUBUNITS_PER_COIN;
    double staked_scl = (double)staked_subunits / SUBUNITS_PER_COIN;
            
    double available_scl = 0.0;
    uint64_t total_outbound_unstaked = pending_unstaked + scheduled_unstaked;
    if (total_subunits > total_outbound_unstaked) {
        uint64_t usable_gross = total_subunits - total_outbound_unstaked;
        available_scl = (double)usable_gross / SUBUNITS_PER_COIN;
    }
            
    double available_staked_scl = 0.0;
    uint64_t total_outbound_staked = pending_staked_consumed + scheduled_staked;
    if (staked_subunits > total_outbound_staked) {
        uint64_t usable_staked = staked_subunits - total_outbound_staked;
        available_staked_scl = (double)usable_staked / SUBUNITS_PER_COIN;
    }
    
    // 5. Render Financial Status to Console
    printf("\n=== Wallet Balances ===\n");
    
    if (pending_utxo_validations > 0) {
        printf("Encrypted UTXO Validations: %llu [+%llu/hr] (pending: %llu)\n",
                utxo_validations, (1 + (uint64_t)floor(staked_scl + fees_paid_scl)), pending_utxo_validations);
    } else {
        printf("Encrypted UTXO Validations: %llu [+%llu/hr]\n",
                utxo_validations, (1 + (uint64_t)floor(staked_scl + fees_paid_scl)));
    }
    
    printf("Total SCL Balance:     %.8f\n", total_scl);
    printf("Staked SCL:            %.8f\n", staked_scl);
    
    printf("Available SCL:         %.8f (pending: %.4f, scheduled: %.4f)\n",
           available_scl,
           (double)pending_unstaked / SUBUNITS_PER_COIN,
           (double)scheduled_unstaked / SUBUNITS_PER_COIN);
           
    printf("Available Staked SCL:  %.8f (pending: %.4f, scheduled: %.4f)\n",
           available_staked_scl,
           (double)pending_staked_consumed / SUBUNITS_PER_COIN,
           (double)scheduled_staked / SUBUNITS_PER_COIN);
           
    printf("Transaction Fees Paid: %.8f SCL\n", fees_paid_scl);

    pthread_mutex_unlock(&user->mutex);
    pthread_mutex_unlock(&state->mutex);
}

/**
 * @brief Computes and outputs macro-level SCL monetary economics, staking ratios, and difficulty.
 *
 * Traverses ledger state to sum total minted subunits, active staked subunits, and total
 * burned fees. Determines consensus stage difficulty and progress toward the next threshold.
 *
 * @pre `state` must point to an initialized State structure.
 * @post Renders macroeconomic metrics to stdout.
 * @warning Acquires `state->bc.rwlock` (read) and `state->game_state.mutex`.
 *
 * @param[in] state Pointer to State structure.
 *
 * @return None.
 *
 * @complexity Time: O(P) where P = number of pointer entries in pointer_table.
 * @complexity Space: O(sizeof(GameStateSnapshot)) temporary snapshot.
 */
void show_scl_coin_economics(const State *state) {
    if (!state) return;
    
    pthread_rwlock_rdlock(&((Blockchain *)&state->bc)->rwlock);
    
    // Read total rewarded subunits under game_state mutex
    pthread_mutex_lock(&((State *)state)->game_state.mutex);
    uint64_t total_subunits = ((State *)state)->game_state.total_rewarded_scl_subunits;
    pthread_mutex_unlock(&((State *)state)->game_state.mutex);
    
    // Accumulate total active staked subunits across all unspent pointers
    uint64_t total_staked_subunits = 0;
    for (size_t i = 0; i < state->bc.pointer_table->size; i++) {
        GenericHashEntry *entry = state->bc.pointer_table->buckets[i];
        while (entry) {
            if (entry->type == HASH_ENTRY_POINTER &&
                !entry->data.pointer.spent &&
                entry->data.pointer.staked) {
                    
                Pointer *ptr = &entry->data.pointer;
                SCLCoin *parent = hash_table_lookup(state->bc.coin_table, ptr->parent_coin_id, false);
                    
                if (parent && ptr->start_subunit <= ptr->end_subunit &&
                    ptr->end_subunit <= parent->total_subunits) {
                    total_staked_subunits += ptr->end_subunit - ptr->start_subunit + 1;
                }
            }
            entry = entry->next;
        }
    }
    
    pthread_rwlock_unlock(&((Blockchain *)&state->bc)->rwlock);
    
    // Convert to SCL whole coins
    double total_scl = (double)total_subunits / SUBUNITS_PER_COIN;
    double total_staked_scl = (double)total_staked_subunits / SUBUNITS_PER_COIN;
    
    GameStateSnapshot *snap = acquire_game_state_snapshot((State *)state);
    uint64_t total_rewarded_scl_subunits = snap ? snap->total_rewarded_scl_subunits : 0;
    release_game_state_snapshot(snap);

    // Calculate consensus matching stage
    int stage = calculate_current_stage(total_rewarded_scl_subunits, total_staked_subunits);
    
    // Calculate percentage staked
    double staked_percentage = 0.0;
    if (total_scl > 0) {
        staked_percentage = (total_staked_scl / total_scl) * 100.0;
    }
    
    // Calculate milestone completion progress toward next 2M coin threshold
    double progress = (total_scl >= MAX_SCL_COINS) ? 100.0 : (total_scl / 2000000.0) * 100.0;
    
    // Calculate total fees paid
    uint64_t total_fees_subunits = calculate_total_fees_subunits(&state->bc);
    double total_fees_scl = (double)total_fees_subunits / SUBUNITS_PER_COIN;
    
    printf("\nSCL Coin Issuance Status:\n");
    printf("Total SCL Coins Issued: %.0f\n", total_scl);
    printf("Total SCL Coins Staked: %.0f (%.2f%% of total)\n", total_staked_scl, staked_percentage);
    printf("Total Transaction Fees Paid: %.8f SCL\n", total_fees_scl);
    printf("Current Stage: %d matches\n", stage);
    
    if (total_scl >= MAX_SCL_COINS) {
        printf("Maximum SCL Coins (16,000,000) reached.\n");
        printf("Progress to Next Threshold: 100.0%%\n");
        printf("[████████████████████]\n");
    } else {
        printf("Next Threshold: %.0f coins\n", 2000000.0 * (floor(total_scl / 2000000.0) + 1));
        printf("Progress to Next Threshold: %.1f%%\n", progress);
        printf("[");
        int filled = (int)(progress / 5.0);
        for (int i = 0; i < 20; i++) printf("%s", i < filled ? "█" : "□");
        printf("]\n");
    }
    
    printf("\nStaking Economics:\n");
    printf("Base Stage (without staking): %d\n",
           (int)(total_rewarded_scl_subunits / (SCL_COIN_THRESHOLD * SUBUNITS_PER_COIN)) + 2);
    printf("Stage Reduction from Staking: %d (per 2,000,000 coins staked)\n",
           (int)(total_staked_scl / 2000000));
    printf("Current Effective Stage: %d\n", stage);
}

/**
 * @brief Traverses and displays the complete in-memory blockchain coin and pointer graph.
 *
 * Iterates through `state->bc.insert_order`, displaying Coin IDs, denominations,
 * and associated child pointers (unspent, fee, or staked).
 *
 * @pre `state` must point to an initialized State structure.
 * @post Ledger topography rendered to stdout.
 * @warning Acquires `state->bc.rwlock` (read).
 *
 * @param[in] state Pointer to State structure.
 *
 * @return None.
 *
 * @complexity Time: O(C * P) where C = coin count, P = pointers per coin.
 * @complexity Space: O(1) auxiliary space.
 */
void display_blockchain(const State *state) {
    pthread_rwlock_rdlock(&((State *)state)->bc.rwlock);
    printf("\n=== Blockchain (1 SCL = 160,000,000 units) ===\n");
    if (state->bc.coin_table == NULL || state->bc.insert_order == NULL || state->bc.insert_order_count == 0) {
        printf("Blockchain not initialized yet. Please try again later.\n");
        pthread_rwlock_unlock(&((State *)state)->bc.rwlock);
        return;
    }
    for (size_t i = 0; i < state->bc.insert_order_count; i++) {
        SCLCoin *coin = state->bc.insert_order[i];
        double scl_amount = (double)coin->total_subunits / SUBUNITS_PER_COIN;
        char hex_coin_id[COIN_ID_LEN * 2 + 1];
        bytes_to_hex(coin->coin_id, COIN_ID_LEN, hex_coin_id);
        printf("Coin %zu:\n  ID: %s\n  Amount: %llu units (%.8f SCL)\n",
               i, hex_coin_id, coin->total_subunits, scl_amount);
        // Iterate over all child subunit range pointers belonging to this coin
        for (size_t p = 0; p < state->bc.pointer_table->size; p++) {
            GenericHashEntry *ptr_entry = state->bc.pointer_table->buckets[p];
            while (ptr_entry) {
                if (ptr_entry->type == HASH_ENTRY_POINTER) {
                    Pointer *ptr = &ptr_entry->data.pointer;
                    if (memcmp(ptr->parent_coin_id, coin->coin_id, COIN_ID_LEN) == 0) {
                        printf("    Pointer:\n      ID: ");
                        char hex_ptr[65];
                        bytes_to_hex(ptr->pointer_id, COIN_ID_LEN, hex_ptr);
                        printf("%s", hex_ptr);
                        char hex_owner[65];
                        bytes_to_hex(ptr->owner_address, 32, hex_owner);
                        printf("\n      Owner (first 32 bytes): %s", hex_owner);
                        if (ptr->spent == 1) {
                            printf("\n      Status: Spent\n");
                        } else if (ptr->spent == 2) {
                            double ptr_scl = (double)(ptr->end_subunit - ptr->start_subunit + 1) / SUBUNITS_PER_COIN;
                            printf("\n      Status: Fee\n");
                            printf("      Range: %llu - %llu units (%.8f SCL)\n",
                                   ptr->start_subunit, ptr->end_subunit, ptr_scl);
                        } else {
                            double ptr_scl = (double)(ptr->end_subunit - ptr->start_subunit + 1) / SUBUNITS_PER_COIN;
                            printf("\n      Range: %llu - %llu units (%.8f SCL)\n",
                                   ptr->start_subunit, ptr->end_subunit, ptr_scl);
                            printf("      Staked: %s\n", ptr->staked ? "Yes" : "No");
                        }
                    }
                }
                ptr_entry = ptr_entry->next;
            }
        }
    }
    pthread_rwlock_unlock(&((State *)state)->bc.rwlock);
}

/* ============================================================================
 * SECTION 3: CONSENSUS VALUATION AUTHORING AND SUBMISSION
 *
 * Architectural Preface:
 * Implements interactive and automated creation of consensus Valuation proposals.
 * For every valuation created, an Encrypted UTXO Validation is burned via zero-knowledge
 * proof. Valuation data is authenticated via NIST FIPS 204 ML-DSA-87 signatures
 * before being queued for P2P network broadcast.
 * ============================================================================ */

/**
 * @brief Interactively authors consensus Valuation proposals and enqueues them for network submission.
 *
 * Prompts the operator for 10 integer values per valuation, burns corresponding UTXO validations,
 * computes an ML-DSA-87 digital signature over the serialized core valuation payload, and enqueues
 * the proposal into `state->submission_queue`.
 *
 * @pre `valuations`, `valuation_count`, `valuation_capacity`, `user`, and `state` must be non-null.
 * @post `*valuation_count` is incremented by the number of valuations created.
 * @post `*valuations` array is expanded if necessary.
 * @note Burns UTXOs using `consume_utxos_for_amount()`.
 * @warning Acquires `state->wallet_mutex` during ML-DSA-87 signing.
 *
 * @param[in,out] valuations         Pointer to dynamic array of Valuation structs.
 *                                   - Ownership: Caller-owned, reallocated by callee.
 * @param[in,out] valuation_count    Pointer to active valuation count.
 * @param[in,out] valuation_capacity Pointer to allocated capacity of valuations array.
 * @param[in]     user               Pointer to active User identity.
 * @param[in,out] state              Pointer to global State context.
 *
 * @return None.
 *
 * @complexity Time: O(count * (Dilithium_Sign + SHA256)).
 * @complexity Space: O(count * sizeof(Valuation)) dynamic array growth.
 */
void create_valuations(Valuation **valuations, unsigned int *valuation_count, unsigned int *valuation_capacity,
                       User *user, State *state) {
    if (!valuations || !valuation_count || !valuation_capacity || !user || !state) {
        fprintf(stderr, "[CreateValuations] Invalid parameters\n");
        return;
    }

    uint64_t utxo_validations = get_available_utxo_validations(state);

    if (utxo_validations <= 0) {
        printf("\nNo Encrypted UTXO Validations available.\n");
        return;
    }

    printf("\nAvailable UTXO validations: %llu\n", utxo_validations);
    printf("How many valuations to create? ");
    int count = validate_integer_input();
    if (count <= 0 || (uint64_t)count > utxo_validations) {
        printf("Invalid number. Max available: %llu\n", utxo_validations);
        return;
    }

    if (count > MAX_VALUATIONS) {
        printf("Limiting to %d valuations to prevent overflow.\n", MAX_VALUATIONS);
        count = MAX_VALUATIONS;
    }

    printf("\n[Centinel] Mathematically burning %d UTXO validations for submissions via ZK-Proof...\n", count);
    
    // Burn validations mathematically using zero-knowledge nullifiers
    if (consume_utxos_for_amount(state, count) != 0) {
        printf("Error: Insufficient Encrypted UTXO Validations. Please wait for an hourly award or redeem a Centinel Ticket.\n");
        return;
    }

    // Author and sign each individual valuation
    for (int i = 0; i < count; i++) {
        resize_valuation_array(valuations, valuation_count, valuation_capacity);
        Valuation new_val;
        memset(&new_val, 0, sizeof(Valuation));
        memcpy(new_val.user_id, user->user_id, USER_ID_LEN);
        printf("\nCreating Valuation %d:\n", *valuation_count + 1);
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            printf("Enter number %2d/10 (0-99): ", j + 1);
            int num = validate_integer_input();
            while (num < 0 || num > 99) {
                printf("Invalid number. Enter 0-99: ");
                num = validate_integer_input();
            }
            new_val.numbers[j] = num;
        }
        new_val.timestamp = get_real_time_us();
        memset(new_val.beacon_seed, 0, 32);
        (*valuations)[(*valuation_count)++] = new_val;

        ValuationData vd;
        memset(&vd, 0, sizeof(ValuationData));
        vd.valuation = new_val;
        memcpy(vd.pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        
        uint8_t core_data[sizeof(Valuation)];
        size_t core_len = serialize_core_valuation(&new_val, core_data);
        
        // Sign serialized core valuation under wallet lock
        pthread_mutex_lock(&state->wallet_mutex);
        dilithium_sign(core_data, core_len, state->user_wallet.dilithium_privkey, vd.signature);
        pthread_mutex_unlock(&state->wallet_mutex);
        
        // Package into network message and enqueue for submission processing
        Message *msg = calloc(1, sizeof(Message));
        if (!msg) continue;
        msg->type = MSG_VALUATION_PROPOSAL;
        size_t offset = 0;
        memcpy(msg->payload + offset, core_data, core_len); offset += core_len;
        memcpy(msg->payload + offset, vd.pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
        memcpy(msg->payload + offset, vd.signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
        msg->length = offset;
        
        enqueue_submission(state, msg);
        free(msg);

        // Compute valuation hash for diagnostic tracing
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256(core_data, core_len, hash);

        fprintf(stderr, "[CreateValuations] Enqueued MSG_VALUATION_PROPOSAL, hash=");
        for (size_t j = 0; j < 16; j++) fprintf(stderr, "%02x", hash[j]);
        fprintf(stderr, "\n");
    }

    printf("\nCreated %d valuations.\n", count);
}

/**
 * @brief Automatically generates random consensus valuations using cryptographically secure entropy.
 *
 * Samples 10 random integers in $[0, 99]$ via OpenSSL `RAND_bytes`, consumes UTXO validations,
 * signs proposals using ML-DSA-87, and queues them into `state->submission_queue`.
 *
 * @pre `valuations`, `valuation_count`, `valuation_capacity`, `user`, and `state` must be non-null.
 * @post `*valuation_count` is incremented by `count`.
 * @post Array `*valuations` is resized as necessary.
 * @warning Acquires `state->wallet_mutex` during digital signature generation.
 *
 * @param[in,out] valuations         Pointer to array of Valuation structs.
 * @param[in,out] valuation_count    Pointer to valuation count.
 * @param[in,out] valuation_capacity Pointer to valuation capacity.
 * @param[in]     user               Pointer to active User identity.
 * @param[in,out] state              Pointer to global State context.
 *
 * @return None.
 *
 * @complexity Time: O(count * (RAND_bytes + Dilithium_Sign)).
 * @complexity Space: O(count * sizeof(Valuation)) dynamic array growth.
 */
void generate_valuations(Valuation **valuations, unsigned int *valuation_count, unsigned int *valuation_capacity,
                         User *user, State *state) {
    if (!valuations || !valuation_count || !valuation_capacity || !user || !state) {
        fprintf(stderr, "[GenerateValuations] Invalid parameters\n");
        return;
    }

    uint64_t utxo_validations = get_available_utxo_validations(state);

    if (utxo_validations <= 0) {
        printf("\nNo Encrypted UTXO Validations available.\n");
        return;
    }

    printf("\nAvailable UTXO validations: %llu\n", utxo_validations);
    printf("How many valuations to create? ");
    int count = validate_integer_input();
    if (count <= 0 || (uint64_t)count > utxo_validations) {
        printf("Invalid number. Max available: %llu\n", utxo_validations);
        return;
    }

    if (count > MAX_VALUATIONS) {
        printf("Limiting to %d valuations to prevent overflow.\n", MAX_VALUATIONS);
        count = MAX_VALUATIONS;
    }

    printf("\n[Centinel] Mathematically burning %d UTXO validations for submissions via ZK-Proof...\n", count);
    
    if (consume_utxos_for_amount(state, count) != 0) {
        printf("Error: Insufficient Encrypted UTXO Validations. Please wait for an hourly award or redeem a Centinel Ticket.\n");
        return;
    }

    // Generate random valuations and submit
    for (int i = 0; i < count; i++) {
        resize_valuation_array(valuations, valuation_count, valuation_capacity);
        Valuation new_val;
        memset(&new_val, 0, sizeof(Valuation));
        memcpy(new_val.user_id, user->user_id, USER_ID_LEN);
        
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            unsigned char rand_byte;
            if (RAND_bytes(&rand_byte, 1) != 1) {
                fprintf(stderr, "[GenerateValuations] RAND_bytes failed, using fallback\n");
                rand_byte = 0;
            }
            new_val.numbers[j] = rand_byte % 100;
        }
        new_val.timestamp = get_real_time_us();
        memset(new_val.beacon_seed, 0, 32);
        (*valuations)[(*valuation_count)++] = new_val;

        ValuationData vd;
        memset(&vd, 0, sizeof(ValuationData));
        vd.valuation = new_val;
        memcpy(vd.pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        
        uint8_t core_data[sizeof(Valuation)];
        size_t core_len = serialize_core_valuation(&new_val, core_data);
        
        pthread_mutex_lock(&state->wallet_mutex);
        dilithium_sign(core_data, core_len, state->user_wallet.dilithium_privkey, vd.signature);
        pthread_mutex_unlock(&state->wallet_mutex);
        
        Message *msg = calloc(1, sizeof(Message));
        if (!msg) continue;
        msg->type = MSG_VALUATION_PROPOSAL;
        size_t offset = 0;
        memcpy(msg->payload + offset, core_data, core_len); offset += core_len;
        memcpy(msg->payload + offset, vd.pubkey, PUBKEY_LEN); offset += PUBKEY_LEN;
        memcpy(msg->payload + offset, vd.signature, SIGNATURE_LEN); offset += SIGNATURE_LEN;
        msg->length = offset;
        
        enqueue_submission(state, msg);
        free(msg);

        // Compute valuation hash for diagnostic tracing
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256(core_data, core_len, hash);

        fprintf(stderr, "[GenerateValuations] Enqueued MSG_VALUATION_PROPOSAL, hash=");
        for (size_t j = 0; j < 16; j++) fprintf(stderr, "%02x", hash[j]);
        fprintf(stderr, "\n");
    }

    printf("\nGenerated %d valuations.\n", count);
}

/**
 * @brief Renders the operator's current in-memory valuation submissions to standard output.
 *
 * @pre `valuations` points to at least `count` Valuation instances if `count > 0`.
 * @post Renders valuations to stdout.
 *
 * @param[in] valuations Pointer to Valuation array.
 * @param[in] count      Number of valuations in array.
 *
 * @return None.
 *
 * @complexity Time: O(count). Space: O(1).
 */
void display_all_valuations(const Valuation *valuations, int count) {
    printf("\n=== Your Valuations ===\n");
    if (count == 0) {
        printf("No valuations created yet.\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        printf("%4d: ", i + 1);
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            printf("%02d ", valuations[i].numbers[j]);
        }
        printf("\n");
    }
}

/**
 * @brief Renders the global consensus circular audit buffer in chronological order.
 *
 * Acquires a thread-safe snapshot of the global audit ring (`AUDIT_SIZE = 1024`) and
 * unwraps the circular buffer starting from the oldest available entry.
 *
 * @pre `state` must point to an initialized State structure.
 * @post Renders chronological audit entries to stdout.
 *
 * @param[in] state Pointer to global State structure.
 *
 * @return None.
 *
 * @complexity Time: O(AUDIT_SIZE). Space: O(AUDIT_SIZE * sizeof(Valuation)) snapshot copy.
 */
void display_audit(State *state) {
    GameStateSnapshot *snap = acquire_game_state_snapshot(state);
    if (!snap) {
        printf("\n=== Current Audit ===\n");
        printf("Audit is empty.\n");
        return;
    }
    int valuation_count = snap->valuation_count;
    int current_index = snap->current_audit_index;
    Valuation game_audit[AUDIT_SIZE];

    memcpy(game_audit, snap->game_audit, sizeof(game_audit));
    release_game_state_snapshot(snap);

    printf("\n=== Current Audit ===\n");
    
    if (valuation_count == 0) {
        printf("Audit is empty.\n");
        return;
    }
    
    // Determine the oldest entry in the circular ring buffer
    int start_index;
    if (valuation_count < AUDIT_SIZE) {
        start_index = 0;
    } else {
        start_index = current_index;
    }
    
    // Display entries in strict chronological sequence
    for (int i = 0; i < valuation_count; i++) {
        int display_index = (start_index + i) % AUDIT_SIZE;
        printf("%4d: ", i + 1);
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            printf("%02d ", game_audit[display_index].numbers[j]);
        }
        printf("\n");
    }
}

/* ============================================================================
 * SECTION 4: CENTINEL SHIELDED BEARER INSTRUMENT PROTOCOLS
 *
 * Architectural Preface:
 * Implements encapsulation and redemption for off-chain Centinel bearer tickets.
 * - Encapsulation (create_centinel): Burns on-chain validation UTXOs to generate
 *   self-contained bearer instruments. Generates an ephemeral ML-DSA-87 keypair,
 *   computes BDLOP commitments and Stern ZK proofs of value conservation and MMR
 *   inclusion, and serializes the bearer token to disk.
 * - Redemption (redeem_centinel): Reads an off-chain Centinel file, verifies
 *   homomorphic commitments, checks MMR root anchoring, constructs a zero-knowledge
 *   redemption proof that credits the user's wallet, and broadcasts an OP_REDEEM_CENTINEL
 *   operation to the peer network.
 * ============================================================================ */

/**
 * @brief Encapsulates on-chain Encrypted UTXO Validations into an off-chain Centinel bearer file.
 *
 * Selects mature unspent UTXOs to satisfy the requested amount. For each selected UTXO:
 * 1. Computes the split amounts (\f$v_{\text{transfer}}\f$ and \f$v_{\text{change}}\f$).
 * 2. Generates an ephemeral ML-DSA-87 keypair and PRF key for the recipient ticket.
 * 3. Extracts an MMR inclusion proof from `state->bc.centinel.validation_commitments`.
 * 4. Generates a Stern-based zero-knowledge proof proving valid spend and value conservation.
 * 5. Injects an `OP_REDEEM_CENTINEL` operation into the local mempool and broadcasts it.
 * 6. Serializes the bearer instrument containing blinding factors and keys to disk.
 *
 * @pre `user` and `state` must be non-null and fully initialized.
 * @post A binary file `centinel_<timestamp>.dat` is written to disk.
 * @post Spent UTXOs are locked in the mempool and marked for confirmation.
 * @warning Enforces canonical lock order:
 *          1. `state->bc.rwlock` (read)
 *          2. `state->user_wallet.utxo_mutex`
 *          3. `state->mutex` (for mempool insertion)
 *
 * @param[in]     user  Pointer to active User identity.
 * @param[in,out] state Pointer to global State context.
 *
 * @return None.
 *
 * @complexity Time: O(num_utxos * (ZK_Proof_Gen + MMR_Proof_Gen + Dilithium_Keygen)).
 * @complexity Space: O(num_utxos * sizeof(CentinelTicket)) temporary heap allocation.
 */
void create_centinel(User *user, State *state) {
    if (!user || !state) return;

    printf("\n=== Create Centinel Ticket ===\n");
    printf("Enter number of validations to encapsulate: ");
    uint64_t amount = validate_integer_input();
    if (amount <= 0) {
        printf("Invalid amount.\n");
        return;
    }

    uint64_t accumulated = 0;
    size_t max_possible = state->user_wallet.num_val_utxos;
    if (max_possible == 0) {
        printf("Error: Insufficient Encrypted UTXO Validations. Please wait for an hourly award or redeem a Centinel Ticket.\n");
        return;
    }
    BdlopCommitment *selected_commitments = malloc(max_possible * sizeof(BdlopCommitment));
    if (!selected_commitments) return;
    size_t num_selected = 0;

    // Greedy coin selection for spendable UTXOs
    pthread_rwlock_rdlock(&state->bc.rwlock);
    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    for (size_t i = 0; i < state->user_wallet.num_val_utxos; i++) {
        ValidationUTXO *utxo = &state->user_wallet.val_utxos[i];
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
                memcpy(&selected_commitments[num_selected++], &utxo->commitment, sizeof(BdlopCommitment));
                accumulated += utxo->amount;
                if (accumulated >= amount) break;
            }
        }
    }
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
    pthread_rwlock_unlock(&state->bc.rwlock);

    if (accumulated < amount) {
        printf("Error: Insufficient Encrypted UTXO Validations. Please wait for an hourly award or redeem a Centinel Ticket.\n");
        free(selected_commitments);
        return;
    }

    Centinel *multi_ticket = calloc(1, sizeof(Centinel) + num_selected * sizeof(CentinelTicket));
    if (!multi_ticket) {
        free(selected_commitments);
        return;
    }

    uint64_t remaining_to_fulfill = amount;

    for (size_t i = 0; i < num_selected; i++) {
        uint64_t v_old = 0;
        uint8_t r_old[32] = {0};
        uint8_t pk_old[PUBKEY_LEN] = {0};
        PRFKey prf_key_old;
        int found = 0;

        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        for (size_t j = 0; j < state->user_wallet.num_val_utxos; j++) {
            if (memcmp(&state->user_wallet.val_utxos[j].commitment, &selected_commitments[i], sizeof(BdlopCommitment)) == 0) {
                ValidationUTXO *utxo = &state->user_wallet.val_utxos[j];
                v_old = utxo->amount;
                memcpy(r_old, utxo->blinding_factor, 32);
                memcpy(pk_old, utxo->pubkey, PUBKEY_LEN);
                prf_key_old = utxo->prf_key;
                found = 1;
                break;
            }
        }
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

        if (!found) continue;

        uint64_t amount_to_take = (v_old > remaining_to_fulfill) ? remaining_to_fulfill : v_old;
        uint64_t change_amount = v_old - amount_to_take;

        printf("\n[Centinel] Using %llu from UTXO for ticket (%llu change)\n", amount_to_take, change_amount);

        // Sample blinding factors
        uint8_t r_transfer[32], r_change[32];
        RAND_bytes(r_transfer, 32);
        if (change_amount > 0) {
            pthread_mutex_lock(&state->user_wallet.utxo_mutex);
            uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
            memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
            int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", state->user_wallet.num_val_utxos);
            SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, r_change);
            pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
        } else {
            RAND_bytes(r_change, 32);
        }

        // Generate ephemeral Dilithium keypair and PRF key for the bearer ticket
        uint8_t ephemeral_pubkey[PUBKEY_LEN];
        uint8_t ephemeral_privkey[DILITHIUM_SECRETKEY_LEN];
        dilithium_generate_keypair(ephemeral_pubkey, ephemeral_privkey);
        
        PRFKey ephemeral_prf_key;
        uint8_t prf_seed[KAPPA];
        SHA256(ephemeral_privkey, DILITHIUM_SECRETKEY_LEN, prf_seed);
        prf_keygen(&ephemeral_prf_key, prf_seed, KAPPA);

        // Fetch current MMR root and generate path proof
        uint8_t root[COIN_ID_LEN];
        pthread_rwlock_rdlock(&state->bc.rwlock);
        mmr_get_root(state->bc.centinel.validation_commitments, root);
        
        BdlopCommitment c_old_data;
        if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_old, r_old, &c_old_data) != CRYPTO_SUCCESS) {
            printf("ERROR: Failed to compute BDLOP commitment.\n");
            pthread_rwlock_unlock(&state->bc.rwlock);
            continue;
        }
        uint8_t c_old_hash[COIN_ID_LEN];
        SHA256((const uint8_t*)&c_old_data, sizeof(BdlopCommitment), c_old_hash);
        ssize_t leaf_pos = mmr_get_leaf_position(state->bc.centinel.validation_commitments, c_old_hash, 0);
        MMRProof proof = {0};
        if (leaf_pos >= 0) {
            mmr_generate_proof(state->bc.centinel.validation_commitments, (size_t)leaf_pos,
                proof.path_hashes, proof.is_left, &proof.path_len, proof.left_peaks, &proof.left_peaks_len, proof.right_peaks, &proof.right_peaks_len);
        }
        pthread_rwlock_unlock(&state->bc.rwlock);
        
        RedeemCentinelData *rc_data = calloc(1, sizeof(RedeemCentinelData));
        if (!rc_data) {
            printf("ERROR: Memory allocation failed for RedeemCentinelData.\n");
            continue;
        }
        
        // Generate zero-knowledge Centinel proof
        if (change_amount > 0) {
            generate_centinel_proof(
                pk_old, v_old, r_old,
                ephemeral_pubkey, amount_to_take, r_transfer,
                state->user_wallet.dilithium_pubkey, change_amount, r_change,
                &prf_key_old, root,
                &proof,
                rc_data
            );
        } else {
            generate_centinel_proof(
                pk_old, v_old, r_old,
                ephemeral_pubkey, amount_to_take, r_transfer,
                state->user_wallet.dilithium_pubkey, 0, r_change,
                &prf_key_old, root,
                &proof,
                rc_data
            );
            memset(&rc_data->c_change, 0, sizeof(BdlopCommitment));
        }

        // Construct OP_REDEEM_CENTINEL operation to commit nullifiers and change output on-chain
        Operation *op = calloc(1, sizeof(Operation));
        op->type = OP_REDEEM_CENTINEL;
        memcpy(&op->data.redeem_centinel, rc_data, sizeof(RedeemCentinelData));

        Message *msg = calloc(1, sizeof(Message));
        msg->type = MSG_REDEEM_CENTINEL;
        msg->length = serialize_operation(op, msg->payload, MAX_MESSAGE_SIZE);

        if (verify_operation_heavy_crypto(op) != CRYPTO_SUCCESS) {
            printf("ERROR: Heavy crypto verification failed locally.\n");
            free(msg);
            free(op);
            free(rc_data);
            continue;
        }

        pthread_mutex_lock(&state->mutex);
        int added = add_pending_operation(state, op);
        pthread_mutex_unlock(&state->mutex);

        if (added == 0) {
            p2p_broadcast(state, msg);

            // Package ticket payload with ephemeral secrets into bearer instrument
            CentinelTicket *ticket = &multi_ticket->tickets[multi_ticket->num_tickets++];
            memcpy(&ticket->c_transfer, &rc_data->c_transfer, sizeof(BdlopCommitment));
            memcpy(&ticket->c_change, &rc_data->c_change, sizeof(BdlopCommitment));
            memcpy(ticket->nullifier, rc_data->nullifier, NULLIFIER_LEN);
            ticket->zk_proof_len = rc_data->zk_proof_len;
            ticket->zk_proof = malloc(rc_data->zk_proof_len);
            if (ticket->zk_proof) {
                memcpy(ticket->zk_proof, rc_data->zk_proof, rc_data->zk_proof_len);
            }
            ticket->amount = amount_to_take;
            memcpy(ticket->r_transfer, r_transfer, 32);
            memcpy(ticket->ephemeral_pubkey, ephemeral_pubkey, PUBKEY_LEN);
            ticket->ephemeral_prf_key = ephemeral_prf_key;
            
        } else {
            printf("ERROR: Failed to add Centinel Ticket operation to mempool.\n");
        }
        free(msg);
        free(op);
        free(rc_data);

        // Zero ephemeral private key from stack
        explicit_bzero(ephemeral_privkey, DILITHIUM_SECRETKEY_LEN);

        remaining_to_fulfill -= amount_to_take;
        if (remaining_to_fulfill == 0) break;
    }

    // Serialize composite bearer ticket to binary disk file
    char filename[256];
    snprintf(filename, sizeof(filename), "centinel_%llu.dat", (unsigned long long)time(NULL));
    FILE *f = fopen(filename, "wb");
    if (f) {
        fwrite(&multi_ticket->num_tickets, sizeof(uint32_t), 1, f);
        for (uint32_t i = 0; i < multi_ticket->num_tickets; i++) {
            CentinelTicket *t = &multi_ticket->tickets[i];
            fwrite(&t->c_transfer, sizeof(BdlopCommitment), 1, f);
            fwrite(&t->c_change, sizeof(BdlopCommitment), 1, f);
            fwrite(t->nullifier, NULLIFIER_LEN, 1, f);
            fwrite(&t->zk_proof_len, sizeof(uint32_t), 1, f);
            fwrite(t->zk_proof, 1, t->zk_proof_len, f);
            fwrite(&t->amount, sizeof(uint64_t), 1, f);
            fwrite(t->r_transfer, 32, 1, f);
            fwrite(t->ephemeral_pubkey, PUBKEY_LEN, 1, f);
            fwrite(&t->ephemeral_prf_key, sizeof(PRFKey), 1, f);
        }
        fclose(f);
        printf("Centinel Ticket for %llu validations created successfully!\n", amount);
        printf("Saved off-chain instrument to: %s\n", filename);
    } else {
        printf("ERROR: Failed to save Centinel Ticket to %s\n", filename);
    }

    free(selected_commitments);
    for (uint32_t i = 0; i < multi_ticket->num_tickets; i++) {
        if (multi_ticket->tickets[i].zk_proof) {
            free(multi_ticket->tickets[i].zk_proof);
        }
    }
    free(multi_ticket);
}

/**
 * @brief Redeems an off-chain Centinel bearer instrument file into the local operator wallet.
 *
 * Reads an off-chain binary Centinel file:
 * 1. Recomputes and verifies the homomorphic commitment \f$C_{\text{transfer}} = \text{BDLOP}(\rho, v, r)\f$.
 * 2. Fetches the current MMR root and generates a path inclusion proof for the ticket.
 * 3. Derives deterministic blinding factors for the new wallet UTXO.
 * 4. Generates a Stern zero-knowledge redemption proof crediting the user's Dilithium public key.
 * 5. Serializes an `OP_REDEEM_CENTINEL` operation, adds it to `state->pending_operations`,
 *    and broadcasts it to peers.
 *
 * @pre `user` and `state` must be non-null and fully initialized.
 * @post Redeemed UTXOs are queued in the local mempool and broadcast to the network.
 * @warning Enforces canonical lock order:
 *          1. `state->bc.rwlock` (read)
 *          2. `state->user_wallet.utxo_mutex`
 *          3. `state->mutex` (mempool insertion)
 *
 * @param[in]     user  Pointer to active User identity.
 * @param[in,out] state Pointer to global State context.
 *
 * @return None.
 *
 * @complexity Time: O(num_tickets * (BDLOP_Verify + MMR_Proof + ZK_Proof_Gen)).
 * @complexity Space: O(num_tickets * (sizeof(CentinelTicket) + ZK_PROOF_MAX_LEN)).
 */
void redeem_centinel(User *user, State *state) {
    if (!user || !state) return;

    printf("\n=== Redeem Centinel Ticket ===\n");
    printf("Enter filename of the Centinel Ticket (e.g., centinel_1700000000.dat): ");
    char filename[256];
    if (!fgets(filename, sizeof(filename), stdin)) return;
    filename[strcspn(filename, "\r\n")] = 0;

    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("ERROR: Could not open file %s\n", filename);
        return;
    }

    uint32_t num_tickets = 0;
    if (fread(&num_tickets, sizeof(uint32_t), 1, f) != 1) {
        printf("ERROR: Invalid Centinel Ticket format.\n");
        fclose(f);
        return;
    }
    
    // Guard against excessive allocation vectors
    if (num_tickets > 100000) {
        printf("ERROR: Centinel Ticket contains too many entries or is corrupted.\n");
        fclose(f);
        return;
    }
    
    Centinel *multi_ticket = calloc(1, sizeof(Centinel) + num_tickets * sizeof(CentinelTicket));
    if (!multi_ticket) {
        fclose(f);
        return;
    }
    
    multi_ticket->num_tickets = num_tickets;
    
    // Deserialize tickets and attached ZK proofs
    for (uint32_t i = 0; i < num_tickets; i++) {
        CentinelTicket *t = &multi_ticket->tickets[i];
        if (fread(&t->c_transfer, sizeof(BdlopCommitment), 1, f) != 1 ||
            fread(&t->c_change, sizeof(BdlopCommitment), 1, f) != 1 ||
            fread(t->nullifier, NULLIFIER_LEN, 1, f) != 1 ||
            fread(&t->zk_proof_len, sizeof(uint32_t), 1, f) != 1) {
            printf("ERROR: Invalid Centinel Ticket format.\n");
            for (uint32_t j = 0; j < i; j++) {
                if (multi_ticket->tickets[j].zk_proof) free(multi_ticket->tickets[j].zk_proof);
            }
            free(multi_ticket);
            fclose(f);
            return;
        }
        
        t->zk_proof = malloc(t->zk_proof_len);
        if (!t->zk_proof || t->zk_proof_len > ZK_PROOF_MAX_LEN ||
            fread(t->zk_proof, 1, t->zk_proof_len, f) != t->zk_proof_len ||
            fread(&t->amount, sizeof(uint64_t), 1, f) != 1 ||
            fread(t->r_transfer, 32, 1, f) != 1 ||
            fread(t->ephemeral_pubkey, PUBKEY_LEN, 1, f) != 1 ||
            fread(&t->ephemeral_prf_key, sizeof(PRFKey), 1, f) != 1) {
            printf("ERROR: Invalid Centinel Ticket format.\n");
            if (t->zk_proof) free(t->zk_proof);
            for (uint32_t j = 0; j < i; j++) {
                if (multi_ticket->tickets[j].zk_proof) free(multi_ticket->tickets[j].zk_proof);
            }
            free(multi_ticket);
            fclose(f);
            return;
        }
    }
    fclose(f);

    uint64_t total_redeemed = 0;

    // Process and redeem each ticket part
    for (uint32_t i = 0; i < multi_ticket->num_tickets; i++) {
        CentinelTicket *ticket = &multi_ticket->tickets[i];

        // Step 1: Homomorphic commitment verification
        BdlopCommitment expected_c_transfer;
        if (bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, ticket->amount, ticket->r_transfer, &expected_c_transfer) != CRYPTO_SUCCESS) {
            printf("ERROR: Failed to compute BDLOP commitment for ticket part %d.\n", i);
            continue;
        }

        if (memcmp(&expected_c_transfer, &ticket->c_transfer, sizeof(BdlopCommitment)) != 0) {
            printf("ERROR: Homomorphic Commitment verification failed for ticket part %d! Invalid or counterfeit.\n", i);
            continue;
        }
        printf("Homomorphic bounds verified for ticket part %d. The ticket contains exactly %llu validations.\n", i, ticket->amount);

        uint8_t pk_old[PUBKEY_LEN];
        memcpy(pk_old, ticket->ephemeral_pubkey, PUBKEY_LEN);
        uint64_t v_old = ticket->amount;
        uint8_t r_old[32];
        memcpy(r_old, ticket->r_transfer, 32);
        PRFKey prf_key_old = ticket->ephemeral_prf_key;
                
        uint8_t c_old_hash[COIN_ID_LEN];
        BdlopCommitment c_old_data;
        bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, v_old, r_old, &c_old_data);
        SHA256((const uint8_t*)&c_old_data, sizeof(BdlopCommitment), c_old_hash);
        
        // Step 2: Fetch current MMR root and generate inclusion path proof
        pthread_rwlock_rdlock(&state->bc.rwlock);
        uint8_t root[COIN_ID_LEN];
        mmr_get_root(state->bc.centinel.validation_commitments, root);
        
        ssize_t leaf_pos = mmr_get_leaf_position(state->bc.centinel.validation_commitments, c_old_hash, 0);
        MMRProof proof = {0};
        if (leaf_pos >= 0) {
            mmr_generate_proof(state->bc.centinel.validation_commitments, (size_t)leaf_pos, proof.path_hashes, proof.is_left, &proof.path_len, proof.left_peaks, &proof.left_peaks_len, proof.right_peaks, &proof.right_peaks_len);
        } else {
           printf("ERROR: Centinel Ticket UTXO not found in the global state.\n");
           pthread_rwlock_unlock(&state->bc.rwlock);
           continue;
        }
        pthread_rwlock_unlock(&state->bc.rwlock);

        // Step 3: Derive deterministic transfer blinding factor for the recipient wallet
        pthread_mutex_lock(&state->user_wallet.utxo_mutex);
        uint8_t r_input[DILITHIUM_SECRETKEY_LEN + 32];
        memcpy(r_input, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
        int tag_len = snprintf((char *)(r_input + DILITHIUM_SECRETKEY_LEN), 32, "SCL_VAL_UTXO_%zu", state->user_wallet.num_val_utxos);
        uint8_t r_transfer_new[32];
        SHA256(r_input, DILITHIUM_SECRETKEY_LEN + tag_len, r_transfer_new);
        pthread_mutex_unlock(&state->user_wallet.utxo_mutex);
        
        uint8_t r_change_new[32];
        RAND_bytes(r_change_new, 32);

        // Step 4: Construct the Stern zero-knowledge redemption proof
        RedeemCentinelData *rc_data = calloc(1, sizeof(RedeemCentinelData));
        if (!rc_data) continue;
        generate_centinel_proof(
            pk_old, v_old, r_old,
            state->user_wallet.dilithium_pubkey, v_old, r_transfer_new,
            state->user_wallet.dilithium_pubkey, 0, r_change_new,
            &prf_key_old, root,
            &proof,
            rc_data
        );
        memset(&rc_data->c_change, 0, sizeof(BdlopCommitment));
        
        Operation *op = calloc(1, sizeof(Operation));
        if (!op) {
            free(rc_data);
            continue;
        }

        op->type = OP_REDEEM_CENTINEL;
        memcpy(&op->data.redeem_centinel, rc_data, sizeof(RedeemCentinelData));
        free(rc_data);

        Message *msg = calloc(1, sizeof(Message));
        if (!msg) {
            free(op);
            continue;
        }
        msg->type = MSG_REDEEM_CENTINEL;
        msg->length = serialize_operation(op, msg->payload, MAX_MESSAGE_SIZE);

        if (msg->length == 0) {
            printf("ERROR: Failed to serialize Centinel redemption.\n");
            free(msg);
            free(op);
            continue;
        }

        // Local verification prior to mempool admission
        if (verify_operation_heavy_crypto(op) != CRYPTO_SUCCESS) {
            printf("ERROR: Heavy crypto verification failed locally.\n");
            free(msg);
            free(op);
            continue;
        }

        // Step 5: Admission to local mempool and network broadcast
        pthread_mutex_lock(&state->mutex);
        int added = add_pending_operation(state, op);
        pthread_mutex_unlock(&state->mutex);

        if (added == 0) {
            p2p_broadcast(state, msg);
            total_redeemed += v_old;
        } else {
            printf("ERROR: Failed to add Centinel Ticket operation to mempool.\n");
        }
        
        free(msg);
        free(op);
    }
            
    if (total_redeemed > 0) {
        printf("Centinel Ticket for %llu total validations redeemed and broadcasted successfully!\n", total_redeemed);
        printf("Encrypted Validations seamlessly added to Private UTXO Wallet.\n");
    }

    for (uint32_t i = 0; i < multi_ticket->num_tickets; i++) {
        if (multi_ticket->tickets[i].zk_proof) {
            free(multi_ticket->tickets[i].zk_proof);
        }
    }
    free(multi_ticket);
}

/* ============================================================================
 * SECTION 5: AUTOPILOT CONFIGURATION AND INTERACTIVE DISPATCHER LOOP
 *
 * Architectural Preface:
 * Implements interactive operator configuration for autonomous background consensus
 * agents, and houses the primary terminal command dispatcher loop (`display_client_menu`).
 * ============================================================================ */

/**
 * @brief Interactively configures or toggles autonomous consensus Auto-Pilot execution.
 *
 * Prompts the operator for target staking ratio percentage ($0-100\%$) and autonomous
 * valuation submission rate (per hour), updating configuration properties and signaling
 * background autopilot worker threads.
 *
 * @pre `state` must point to an initialized State structure.
 * @post If active, terminates autopilot thread; if disabled, starts autopilot thread.
 * @note Calls `start_autopilot_thread()` or `stop_autopilot_thread()`.
 *
 * @param[in,out] state Pointer to global State structure.
 *
 * @return None.
 *
 * @complexity Time: O(1). Space: O(1).
 */
void toggle_autopilot_interactive(State *state) {
    if (!state) return;
    bool current_state = atomic_load(&state->autopilot_running);
    if (current_state) {
        stop_autopilot_thread(state);
        state->config.autopilot_enabled = false;
        printf("\n[AutoPilot] Deactivated successfully.\n");
    } else {
        printf("\n=== Configure & Activate Auto-Pilot ===\n");
        printf("Enter target staking ratio %% (0-100, default %u): ", state->config.autopilot_stake_ratio ? state->config.autopilot_stake_ratio : 50);
        int ratio_in = validate_integer_input();
        if (ratio_in >= 0 && ratio_in <= 100) {
            state->config.autopilot_stake_ratio = (uint32_t)ratio_in;
        } else if (state->config.autopilot_stake_ratio == 0) {
            state->config.autopilot_stake_ratio = 50;
        }

        uint64_t fees_paid = calculate_fees_paid_subunits(&state->bc, state->user_wallet.dilithium_pubkey);
        double fees_scl = (double)fees_paid / SUBUNITS_PER_COIN;
        uint8_t threshold_pk[PUBKEY_LEN];
        uint64_t staked_sub = (compute_threshold_pubkey(state, threshold_pk) == 0) ? calculate_staked_subunits(&state->bc, threshold_pk) : 0;
        double staked_scl = (double)staked_sub / SUBUNITS_PER_COIN;
        uint32_t max_rate = (uint32_t)(1 + floor(staked_scl + fees_scl));

        uint32_t default_rate = state->config.autopilot_valuations_per_hour ? state->config.autopilot_valuations_per_hour : 1;
        if (default_rate > max_rate) default_rate = max_rate;

        printf("Enter valuation submissions per hour (min 1, max %u, default %u): ", max_rate, default_rate);
        int rate_in;
        while (1) {
            rate_in = validate_integer_input();
            if (rate_in < 0) return;
            if (rate_in == 0) {
                rate_in = (int)default_rate;
                break;
            }
            if ((uint32_t)rate_in > max_rate) {
                printf("Error: Rate (%d/hr) exceeds node's current validation rate of %u/hr. Enter 1-%u: ", rate_in, max_rate, max_rate);
                continue;
            }
            break;
        }

        state->config.autopilot_valuations_per_hour = (uint32_t)rate_in;

        state->config.autopilot_enabled = true;
        start_autopilot_thread(state);
        printf("[AutoPilot] Activated successfully! Autonomously managing %u%% stake ratio and %u valuations/hr.\n",
               state->config.autopilot_stake_ratio, state->config.autopilot_valuations_per_hour);
    }
}

/**
 * @brief Interactively loads wallet credentials from a wallet_*.dat file.
 *
 * @details
 * Prompts the operator for a file path, verifies and deserializes the stored UserWallet structure,
 * unlocks pinned memory pages, copies new cryptographic keys (Dilithium5 and PRF keys), updates
 * the primary User table entry, synchronizes the local P2P network peer descriptor, and triggers
 * an on-chain validation UTXO rescan.
 *
 * @pre `state` must point to an initialized State structure.
 * @post Local wallet keys, User ID, and P2P peer identities updated in memory.
 * @warning Acquires `state->wallet_mutex`, `state->user_wallet.utxo_mutex`, `state->mutex`,
 *          and `state->p2p_network.mutex`.
 *
 * @param[in,out] user_ptr Pointer to active User pointer (updated on success).
 * @param[in,out] state    Pointer to global State context.
 *
 * @complexity Time: O(disk_read + UTXO_rescan_time). Space: O(sizeof(UserWallet)).
 */
void load_wallet_credentials_interactive(User **user_ptr, State *state) {
    if (!state) return;
    printf("\n=== Load Wallet Credentials ===\n");
    printf("Enter wallet filename to load (e.g., wallet_5555.dat): ");
    char filename[256];
    if (!fgets(filename, sizeof(filename), stdin)) return;
    filename[strcspn(filename, "\r\n")] = '\0';
    if (filename[0] == '\0') {
        printf("Error: Filename cannot be empty.\n");
        return;
    }

    UserWallet loaded_wallet;
    memset(&loaded_wallet, 0, sizeof(UserWallet));
    if (load_user_wallet(&loaded_wallet, filename) != 0) {
        printf("Error: Failed to load wallet credentials from %s\n", filename);
        return;
    }

    // Unlock secure memory pages and copy new private key parameters
    pthread_mutex_lock(&state->wallet_mutex);
    scl_secure_unlock(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    scl_secure_unlock(&state->user_wallet.prf_key, sizeof(PRFKey));

    memcpy(state->user_wallet.dilithium_pubkey, loaded_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(state->user_wallet.dilithium_privkey, loaded_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    memcpy(&state->user_wallet.prf_key, &loaded_wallet.prf_key, sizeof(PRFKey));

    scl_secure_lock(state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    scl_secure_lock(&state->user_wallet.prf_key, sizeof(PRFKey));

    pthread_mutex_lock(&state->user_wallet.utxo_mutex);
    state->user_wallet.num_val_utxos = 0;
    pthread_mutex_unlock(&state->user_wallet.utxo_mutex);

    uint8_t user_id[USER_ID_LEN];
    SHA256(state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
    pthread_mutex_unlock(&state->wallet_mutex);

    explicit_bzero(&loaded_wallet, sizeof(UserWallet));

    // Re-key active primary user profile and re-index in user_table
    pthread_mutex_lock(&state->mutex);
    if (state->user_count > 0 && state->users) {
        uint8_t old_user_id[USER_ID_LEN];
        memcpy(old_user_id, state->users[0].user_id, USER_ID_LEN);
        hash_table_remove(state->user_table, old_user_id);

        destroy_user(&state->users[0]);
        user_init(&state->users[0], state, state->user_wallet.dilithium_pubkey);
        hash_table_insert(state->user_table, user_id, &state->users[0], HASH_ENTRY_USER);
        extern User *global_user;
        global_user = &state->users[0];
        if (user_ptr) *user_ptr = global_user;
    }
    pthread_mutex_unlock(&state->mutex);

    // Propagate new wallet identity to local P2P network peer descriptor
    pthread_mutex_lock(&state->p2p_network.mutex);
    memcpy(state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(state->p2p_network.local_peer.peer_wallet.dilithium_privkey, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    if (state->p2p_network.num_known_peers > 0 && state->p2p_network.known_peers[0]) {
        memcpy(state->p2p_network.known_peers[0]->peer_wallet.dilithium_pubkey, state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
        memcpy(state->p2p_network.known_peers[0]->peer_wallet.dilithium_privkey, state->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);
    }
    pthread_mutex_unlock(&state->p2p_network.mutex);

    // Rescan unspent validation UTXOs associated with the newly loaded public key
    scl_wallet_rescan_utxos(state);
    printf("Successfully loaded wallet credentials from %s\n", filename);
}

/**
 * @brief Primary interactive terminal command loop and user interface dispatcher.
 *
 * Renders the primary console menu options, parses integer input, detects EOF/hangup,
 * and routes execution to corresponding subsystem modules.
 *
 * @pre `user_ptr`, `*user_ptr`, `state`, `valuations`, `valuation_count`, and `valuation_capacity`
 *      must be non-null.
 * @post Executes requested command; returns 1 on exit request or EOF, 0 to continue looping.
 *
 * @param[in,out] user_ptr           Pointer to User pointer (allows rebinding).
 * @param[in,out] state              Pointer to global State context.
 * @param[in,out] valuations         Pointer to Valuation array pointer.
 * @param[in,out] valuation_count    Pointer to active valuation count.
 * @param[in,out] valuation_capacity Pointer to valuation array capacity.
 *
 * @return int 1 if the node CLI should terminate, 0 if it should continue displaying menu.
 *
 * @complexity Time: Determined by operator command selection.
 * @complexity Space: O(1) auxiliary space.
 */
int display_client_menu(User **user_ptr, State *state, Valuation **valuations,
                 unsigned int *valuation_count, unsigned int *valuation_capacity) {
    
    User *user = *user_ptr;
    
    printf("\n=== Main Menu ===\n");
    printf("1. How to Participate\n2. Show Balances\n");
    printf("3. Create Valuations\n4. Show Valuations\n");
    printf("5. Display Audit\n6. Auto-Generate\n");
    printf("7. Economics Info\n8. View Wallet\n");
    printf("9. Transfer SCL Coins\n10. View Blockchain\n");
    printf("11. Stake SCL Coins\n12. Unstake SCL Coins\n");
    printf("13. Create Centinel\n14. Redeem Centinel\n");
    printf("15. Toggle Auto-Pilot Mode [%s (Ratio: %u%%, Rate: %u/hr)]\n",
           atomic_load(&state->autopilot_running) ? "ACTIVE" : "DISABLED",
           state->config.autopilot_stake_ratio,
           state->config.autopilot_valuations_per_hour);
    printf("16. Load Wallet Credentials\n");
    printf("17. Exit\n");
    printf("Choose an option: ");
    
    int choice = validate_integer_input();
    if (choice < 0) {
        if (feof(stdin)) {
            printf("[P2P] EOF detected on stdin. Transitioning to non-interactive wait.\n");
            while (!atomic_load(&global_shutdown)) {
                sleep(1);
            }
            return 1;
        }
        printf("[P2P] Invalid input. Please enter a valid number.\n");
        return 0;
    }
    
    // Dispatch execution to selected CLI subsystem action
    switch (choice) {
        case 1:
            show_instructions(&state->game_state);
            break;
        case 2:
            show_balances(user, state);
            break;
        case 3:
            create_valuations(valuations, valuation_count, valuation_capacity, user, state);
            break;
        case 4:
            display_all_valuations(*valuations, *valuation_count);
            break;
        case 5:
            display_audit(state);
            break;
        case 6:
            generate_valuations(valuations, valuation_count, valuation_capacity, user, state);
            break;
        case 7:
            show_scl_coin_economics(state);
            break;
        case 8:
            view_wallet(user, state);
            break;
        case 9:
            initiate_transfer(user, state);
            break;
        case 10:
            display_blockchain(state);
            break;
        case 11:
            initiate_stake(user, state);
            break;
        case 12:
            initiate_unstake(user, state);
            break;
        case 13:
            create_centinel(user, state);
            break;
        case 14:
            redeem_centinel(user, state);
            break;
        case 15:
            toggle_autopilot_interactive(state);
            break;
        case 16:
            load_wallet_credentials_interactive(user_ptr, state);
            break;
        case 17:
            return 1;
        default:
            printf("[P2P] Invalid choice.\n");
            break;
    }
    return 0;
}
