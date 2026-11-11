/*
 * ==============================================================================
 * Satocialist Protocol: Blockchain Topology & Consensus Sync Fuzzer
 * ==============================================================================
 *
 * Target: apply_block(), check_consensus(), and block gossip handlers.
 *
 * Objective: Inject intentionally malformed MSG_GOSSIP_BLOCK and
 *            MSG_BLOCK_APPROVED structures into the consensus engine.
 *
 * Vulnerability Focus:
 *   - Mismatched Merkle roots and corrupt ZK-PRF nullifiers.
 *   - Invalid threshold signatures or missing Fiat-Shamir bounds.
 *   - Overlapping chronological timestamps or identical-height fork collisions.
 *   - Hardening the Merkle Mountain Range (MMR) state accumulation.
 *   - Orphan block pool promotion logic.
 *   - The ledger's strict mathematical double-spend invariants.
 * ==============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <pthread.h>

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
#include "blockchain.h"
#include "hash_table.h"
#include "game_state.h"
#include "client_state.h"
#include "crypto.h"
#include "protocol.h"
#include "network.h"
#include "consensus.h"
#include "queue.h"
#include "database.h"
#include "scl_rpc_ffi_export.h"
#include "client_network.h"

extern State *global_state;
static int fuzzer_initialized = 0;

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
    // Mute standard runtime logs to guarantee blazing-fast execution bounds
    scl_log_set_level(LOG_LEVEL_FATAL);

    const char *corpus_dir = "../consensus_fuzzer_corpus";
    for (int i = 1; i < *argc; i++) {
        if ((*argv)[i][0] != '-') {
            corpus_dir = (*argv)[i];
            break;
        }
    }
    SCL_MKDIR(corpus_dir);

    // Initialize Global Node State
    global_state = calloc(1, sizeof(State));
    if (!global_state) return 0;
    client_state_init(global_state, 0);

    // Bootstrap local node wallets to fulfill authentication constraints internally
    create_user_wallet(&global_state->user_wallet);
    memcpy(global_state->p2p_network.local_peer.peer_wallet.dilithium_pubkey,
           global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    memcpy(global_state->p2p_network.local_peer.peer_wallet.dilithium_privkey,
           global_state->user_wallet.dilithium_privkey, PRIVKEY_LEN);

    uint8_t user_id[USER_ID_LEN];
    SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
    register_user(global_state, user_id, global_state->user_wallet.dilithium_pubkey);

    // Generate Seed Corpus: Genesis Block Gossip
    Block *genesis = malloc(sizeof(Block));
    if (genesis) {
        *genesis = create_standard_genesis_block();
        Message *msg = malloc(sizeof(Message));
        if (msg && serialize_block(genesis, msg, true) == 0) {
            uint8_t *seed_buf = malloc(MAX_MESSAGE_SIZE);
            if (seed_buf) {
                seed_buf[0] = MSG_GOSSIP_BLOCK;
                memcpy(seed_buf + 1, msg->payload, msg->length);
                write_seed_file(corpus_dir, "seed01_gossip_genesis.bin", seed_buf, msg->length + 1);

                seed_buf[0] = MSG_BLOCK_APPROVED;
                write_seed_file(corpus_dir, "seed02_approved_genesis.bin", seed_buf, msg->length + 1);
                free(seed_buf);
            }
        }
        if (msg) free(msg);
        free(genesis);
    }

    // Helper macro to generate valid block seed files
    #define GENERATE_BLOCK_SEED(block_ptr, fname_gossip, fname_approved) do { \
        memcpy((block_ptr)->proposer_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN); \
        uint8_t bhash[COIN_ID_LEN]; \
        if (compute_block_hash((block_ptr), bhash) == 0) { \
            dilithium_sign(bhash, COIN_ID_LEN, global_state->user_wallet.dilithium_privkey, (block_ptr)->signature); \
            Message *msg_seed = malloc(sizeof(Message)); \
            if (msg_seed && serialize_block((block_ptr), msg_seed, true) == 0) { \
                uint8_t *sbuf = malloc(MAX_MESSAGE_SIZE); \
                if (sbuf) { \
                    sbuf[0] = MSG_GOSSIP_BLOCK; \
                    memcpy(sbuf + 1, msg_seed->payload, msg_seed->length); \
                    write_seed_file(corpus_dir, fname_gossip, sbuf, msg_seed->length + 1); \
                    sbuf[0] = MSG_BLOCK_APPROVED; \
                    write_seed_file(corpus_dir, fname_approved, sbuf, msg_seed->length + 1); \
                    free(sbuf); \
                } \
            } \
            if (msg_seed) free(msg_seed); \
        } \
    } while(0)

    // Seed Corpus: Basic Mint Block
    Block *block_mint = calloc(1, sizeof(Block));
    if (block_mint) {
        block_mint->block_number = 1;
        memset(block_mint->prev_block_hash, 0, COIN_ID_LEN);
        block_mint->operation_count = 1;
        block_mint->operations = calloc(1, sizeof(Operation));
        
        SCLCoin coin = create_coin(block_mint->prev_block_hash, global_state->user_wallet.dilithium_pubkey);
        coin.total_subunits = SUBUNITS_PER_COIN * 100;
        coin.remaining_subunits = SUBUNITS_PER_COIN * 100;
        
        block_mint->operations[0].type = OP_MINT_COIN;
        block_mint->operations[0].data.mint_coin.coin = coin;
        memcpy(block_mint->operations[0].data.mint_coin.owner_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        
        GENERATE_BLOCK_SEED(block_mint, "seed03_gossip_mint.bin", "seed03_approved_mint.bin");
        free_block(block_mint);
    }

    // Seed Corpus: Transfer Pointer Block
    Block *block_tx = calloc(1, sizeof(Block));
    if (block_tx) {
        block_tx->block_number = 1;
        memset(block_tx->prev_block_hash, 0, COIN_ID_LEN);
        block_tx->operation_count = 1;
        block_tx->operations = calloc(1, sizeof(Operation));
        block_tx->operations[0].type = OP_TRANSFER_POINTER;
        TransferData *tx = &block_tx->operations[0].data.transfer_pointer;
        tx->num_inputs = 1;
        memset(tx->inputs[0].pointer_id, 0x11, COIN_ID_LEN);
        memset(tx->inputs[0].parent_coin_id, 0x22, COIN_ID_LEN);
        tx->inputs[0].start_subunit = 0;
        tx->inputs[0].end_subunit = SUBUNITS_PER_COIN - 1;
        SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, tx->inputs[0].owner_address);
        memset(tx->inputs[0].prev_tx_hash, 0, COIN_ID_LEN);
        tx->proofs[0].path_len = 1;
        memset(tx->proofs[0].path_hashes[0], 0x33, COIN_ID_LEN);
        tx->proofs[0].is_left[0] = 1;
        memset(tx->recipient_pubkey, 0x55, PUBKEY_LEN);
        memcpy(tx->sender_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        tx->amount = SUBUNITS_PER_COIN * 10;
        memset(tx->nonce, 0x01, 8);
        memset(tx->tx_id, 0xAA, COIN_ID_LEN);
        memset(tx->client_root, 0xBB, COIN_ID_LEN);
        memset(tx->inputs_merkle_root, 0xCC, COIN_ID_LEN);
        tx->zk_proof_len = 128;
        memset(tx->zk_proof, 0x42, 128);
        memset(tx->prf_output, 0x77, NULLIFIER_LEN);

        GENERATE_BLOCK_SEED(block_tx, "seed04_gossip_transfer.bin", "seed04_approved_transfer.bin");
        free_block(block_tx);
    }

    // Seed Corpus: Stake Block
    Block *block_stake = calloc(1, sizeof(Block));
    if (block_stake) {
        block_stake->block_number = 1;
        memset(block_stake->prev_block_hash, 0, COIN_ID_LEN);
        block_stake->operation_count = 1;
        block_stake->operations = calloc(1, sizeof(Operation));
        block_stake->operations[0].type = OP_STAKE;
        StakeData *sd = &block_stake->operations[0].data.stake;
        sd->num_inputs = 1;
        memset(sd->inputs[0].pointer_id, 0x11, COIN_ID_LEN);
        memset(sd->inputs[0].parent_coin_id, 0x22, COIN_ID_LEN);
        sd->inputs[0].start_subunit = 0;
        sd->inputs[0].end_subunit = SUBUNITS_PER_COIN - 1;
        SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, sd->inputs[0].owner_address);
        memset(sd->inputs[0].prev_tx_hash, 0, COIN_ID_LEN);
        sd->proofs[0].path_len = 1;
        memset(sd->proofs[0].path_hashes[0], 0x33, COIN_ID_LEN);
        memset(sd->stake_tx_id, 0xDD, COIN_ID_LEN);
        memset(sd->nonce, 0x02, 8);
        memset(sd->client_root, 0xEE, COIN_ID_LEN);
        memcpy(sd->threshold_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        memcpy(sd->sender_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        sd->amount = SUBUNITS_PER_COIN * 5;
        memset(sd->inputs_merkle_root, 0xFF, COIN_ID_LEN);

        GENERATE_BLOCK_SEED(block_stake, "seed05_gossip_stake.bin", "seed05_approved_stake.bin");
        free_block(block_stake);
    }

    // Seed Corpus: Unstake Block
    Block *block_unstake = calloc(1, sizeof(Block));
    if (block_unstake) {
        block_unstake->block_number = 1;
        memset(block_unstake->prev_block_hash, 0, COIN_ID_LEN);
        block_unstake->operation_count = 1;
        block_unstake->operations = calloc(1, sizeof(Operation));
        block_unstake->operations[0].type = OP_UNSTAKE;
        UnstakeData *ud = &block_unstake->operations[0].data.unstake;
        ud->num_inputs = 1;
        memset(ud->inputs[0].pointer_id, 0x11, COIN_ID_LEN);
        memset(ud->inputs[0].parent_coin_id, 0x22, COIN_ID_LEN);
        ud->inputs[0].start_subunit = 0;
        ud->inputs[0].end_subunit = SUBUNITS_PER_COIN - 1;
        SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, ud->inputs[0].owner_address);
        memset(ud->inputs[0].prev_tx_hash, 0, COIN_ID_LEN);
        ud->inputs[0].staked = 1;
        ud->proofs[0].path_len = 1;
        memset(ud->proofs[0].path_hashes[0], 0x33, COIN_ID_LEN);
        memset(ud->unstake_tx_id, 0xDE, COIN_ID_LEN);
        memset(ud->nonce, 0x03, 8);
        memset(ud->client_root, 0xFE, COIN_ID_LEN);
        memcpy(ud->recipient_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        memcpy(ud->threshold_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        ud->amount = SUBUNITS_PER_COIN * 5;

        GENERATE_BLOCK_SEED(block_unstake, "seed06_gossip_unstake.bin", "seed06_approved_unstake.bin");
        free_block(block_unstake);
    }

    // Seed Corpus: Redeem Centinel Block
    Block *block_centinel = calloc(1, sizeof(Block));
    if (block_centinel) {
        block_centinel->block_number = 1;
        memset(block_centinel->prev_block_hash, 0, COIN_ID_LEN);
        block_centinel->operation_count = 1;
        block_centinel->operations = calloc(1, sizeof(Operation));
        block_centinel->operations[0].type = OP_REDEEM_CENTINEL;
        RedeemCentinelData *rc = &block_centinel->operations[0].data.redeem_centinel;
        memset(rc->nullifier, 0x88, NULLIFIER_LEN);
        memset(&rc->c_transfer, 0x12, sizeof(BdlopCommitment));
        memset(&rc->c_change, 0x34, sizeof(BdlopCommitment));
        rc->zk_proof_len = 128;
        memset(rc->zk_proof, 0x42, 128);

        GENERATE_BLOCK_SEED(block_centinel, "seed07_gossip_redeem.bin", "seed07_approved_redeem.bin");
        free_block(block_centinel);
    }

    // Seed Corpus: Claim Validation Block
    Block *block_claim = calloc(1, sizeof(Block));
    if (block_claim) {
        block_claim->block_number = 1;
        memset(block_claim->prev_block_hash, 0, COIN_ID_LEN);
        block_claim->operation_count = 1;
        block_claim->operations = calloc(1, sizeof(Operation));
        block_claim->operations[0].type = OP_CLAIM_VALIDATION;
        ClaimValidationData *cv = &block_claim->operations[0].data.claim_validation;
        memset(&cv->commitment, 0x56, sizeof(BdlopCommitment));
        memcpy(cv->pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

        GENERATE_BLOCK_SEED(block_claim, "seed08_gossip_claim.bin", "seed08_approved_claim.bin");
        free_block(block_claim);
    }

    // Seed Corpus: Valuation Proposal Block
    Block *block_val = calloc(1, sizeof(Block));
    if (block_val) {
        block_val->block_number = 1;
        memset(block_val->prev_block_hash, 0, COIN_ID_LEN);
        block_val->operation_count = 1;
        block_val->operations = calloc(1, sizeof(Operation));
        block_val->operations[0].type = OP_SUBMIT_VALUATION;
        ValuationData *vd = &block_val->operations[0].data.submit_valuation;
        SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, vd->valuation.user_id);
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) vd->valuation.numbers[j] = (j * 7) % 100;
        vd->valuation.timestamp = 1000000;
        memcpy(vd->pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        memcpy(vd->threshold_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

        GENERATE_BLOCK_SEED(block_val, "seed09_gossip_valuation.bin", "seed09_approved_valuation.bin");
        free_block(block_val);
    }

    // Seed Corpus: Multi-Operation Batch Block
    Block *block_multi = calloc(1, sizeof(Block));
    if (block_multi) {
        block_multi->block_number = 1;
        memset(block_multi->prev_block_hash, 0, COIN_ID_LEN);
        block_multi->operation_count = 2;
        block_multi->operations = calloc(2, sizeof(Operation));

        SCLCoin coin_m = create_coin(block_multi->prev_block_hash, global_state->user_wallet.dilithium_pubkey);
        coin_m.total_subunits = SUBUNITS_PER_COIN * 100;
        coin_m.remaining_subunits = SUBUNITS_PER_COIN * 100;
        block_multi->operations[0].type = OP_MINT_COIN;
        block_multi->operations[0].data.mint_coin.coin = coin_m;
        memcpy(block_multi->operations[0].data.mint_coin.owner_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

        block_multi->operations[1].type = OP_CLAIM_VALIDATION;
        memset(&block_multi->operations[1].data.claim_validation.commitment, 0x77, sizeof(BdlopCommitment));
        memcpy(block_multi->operations[1].data.claim_validation.pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

        GENERATE_BLOCK_SEED(block_multi, "seed10_gossip_multi.bin", "seed10_approved_multi.bin");
        free_block(block_multi);
    }

    // Seed Corpus: Consensus Vote Message
    Vote vote_seed;
    memset(&vote_seed, 0, sizeof(Vote));
    memcpy(vote_seed.voter_pubkey, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    memset(vote_seed.block_hash, 0x55, COIN_ID_LEN);
    vote_seed.vote = 1;
    uint8_t vote_data_seed[COIN_ID_LEN + 1];
    memcpy(vote_data_seed, vote_seed.block_hash, COIN_ID_LEN);
    vote_data_seed[COIN_ID_LEN] = vote_seed.vote;
    dilithium_sign(vote_data_seed, sizeof(vote_data_seed), global_state->user_wallet.dilithium_privkey, vote_seed.signature);

    Message *msg_vote = malloc(sizeof(Message));
    if (msg_vote && serialize_vote(&vote_seed, msg_vote) == 0) {
        uint8_t *vbuf = malloc(msg_vote->length + 1);
        if (vbuf) {
            vbuf[0] = MSG_VOTE;
            memcpy(vbuf + 1, msg_vote->payload, msg_vote->length);
            write_seed_file(corpus_dir, "seed11_vote_approve.bin", vbuf, msg_vote->length + 1);
            free(vbuf);
        }
    }
    if (msg_vote) free(msg_vote);

    #undef GENERATE_BLOCK_SEED

    fuzzer_initialized = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!fuzzer_initialized || size < 2) return 0;

    // Fast-path state clearing to prevent memory exhaustion and logic bleed across iterations
    if (global_state) {
        pthread_rwlock_wrlock(&global_state->bc.rwlock);

#define CLEAR_HT_IF_ACTIVE(ht) do { \
    if ((ht) && ((ht)->count > 0 || (ht)->old_buckets != NULL)) { \
        hash_table_clear(ht); \
    } \
} while(0)

        // Clear Consensus Memory Pools
        for (int i = 0; i < MAX_PENDING_OPS; i++) {
            Operation *op = atomic_exchange(&global_state->pending_operations[i], NULL);
            if (op) free(op);
        }
        atomic_store(&global_state->pending_operations_count, 0);
        
        // Ensure abandoned background RPC tasks are purged from the memory pool
        pthread_mutex_lock(&global_state->rpc_engine.incoming_rpc_queue.mutex);
        RecreateNode *r_node = global_state->rpc_engine.incoming_rpc_queue.head;
        while (r_node) {
            RecreateNode *next = r_node->next;
            RpcTask *task = (RpcTask *)r_node->args;
            if (task) {
                if (task->msg) free(task->msg);
                if (task->conn) scl_connection_release(task->conn);
                free(task);
            }
            free(r_node);
            r_node = next;
        }
        global_state->rpc_engine.incoming_rpc_queue.head = NULL;
        global_state->rpc_engine.incoming_rpc_queue.tail = NULL;
        pthread_mutex_unlock(&global_state->rpc_engine.incoming_rpc_queue.mutex);
        atomic_store_explicit(&global_state->rpc_engine.active_global_queries, 0, memory_order_relaxed);
        
        CLEAR_HT_IF_ACTIVE(global_state->processed_txs);
        CLEAR_HT_IF_ACTIVE(global_state->orphan_pool);
        CLEAR_HT_IF_ACTIVE(global_state->processed_blocks);
        CLEAR_HT_IF_ACTIVE(global_state->block_consensus);
        CLEAR_HT_IF_ACTIVE(global_state->block_proposers);
        
        // ** FIX: Prevent the OOM Memory Leak directly **
        CLEAR_HT_IF_ACTIVE(global_state->pubkey_cache);
        CLEAR_HT_IF_ACTIVE(global_state->voted_heights);
        CLEAR_HT_IF_ACTIVE(global_state->dkg_active_sessions);
        CLEAR_HT_IF_ACTIVE(global_state->epoch_processes);
        CLEAR_HT_IF_ACTIVE(global_state->epoch_sign_data_cache);
        CLEAR_HT_IF_ACTIVE(global_state->threshold_stake_processes);

        CLEAR_HT_IF_ACTIVE(global_state->bc.coin_table);
        CLEAR_HT_IF_ACTIVE(global_state->bc.pointer_table);
        CLEAR_HT_IF_ACTIVE(global_state->bc.coin_pointers);
        CLEAR_HT_IF_ACTIVE(global_state->bc.centinel.nullifier_set);

        // Wipe blockchain history natively to prevent Deep Heap allocations from carrying over
        scl_db_delete_blocks_after(0);
                
        global_state->bc.insert_order_count = 0;
        global_state->current_block_number = 0;
        memset(global_state->current_block_hash, 0, COIN_ID_LEN);
        global_state->bc.sync_epoch = 1; // Explicitly prevents underflows
        global_state->sync_received_block_number_value = 0;
        memset(global_state->sync_received_block_hash, 0, COIN_ID_LEN);
        global_state->blockchain_sync_received_end = 0;

        // Reallocate strict MMR Bounds ensuring Topography resets correctly
        if (global_state->bc.mmr && global_state->bc.mmr->count > 0) {
            mmr_destroy(global_state->bc.mmr);
            mmr_init(global_state->bc.mmr);
        }
        if (global_state->bc.centinel.validation_commitments && global_state->bc.centinel.validation_commitments->count > 0) {
            mmr_destroy(global_state->bc.centinel.validation_commitments);
            mmr_init(global_state->bc.centinel.validation_commitments);
        }
        if (global_state->bc.centinel.nullifier_bloom) {
            memset(global_state->bc.centinel.nullifier_bloom, 0, NULLIFIER_BLOOM_BYTES);
        }
        memset(global_state->hypergraph.poison_bloom_active, 0, BLOOM_FILTER_SIZE);
        memset(global_state->hypergraph.poison_bloom_aging, 0, BLOOM_FILTER_SIZE);

        // Unlock bc.rwlock before modifying user_table to prevent deadlocks from register_user
        pthread_rwlock_unlock(&global_state->bc.rwlock);

        // Prevent `user_table` bloat alongside `pubkey_cache`
        if (global_state->user_count > 1 || (global_state->user_count == 1 && memcmp(global_state->users[0].dilithium_pubkey, global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN) != 0)) {
            CLEAR_HT_IF_ACTIVE(global_state->user_table);
            for (size_t i = 0; i < global_state->user_count; i++) {
                destroy_user(&global_state->users[i]);
            }
            global_state->user_count = 0;
            global_state->user_wallet.num_val_utxos = 0;

            uint8_t user_id[USER_ID_LEN];
            SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
            register_user(global_state, user_id, global_state->user_wallet.dilithium_pubkey);
        } else if (global_state->user_count == 0) {
            uint8_t user_id[USER_ID_LEN];
            SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
            register_user(global_state, user_id, global_state->user_wallet.dilithium_pubkey);
        }

        // Unset in_blockchain_sync so all consensus & fork detection paths can execute
        global_state->in_blockchain_sync = 0;
    }

    uint8_t mode = data[0] % 4;
    uint8_t msg_type;
    if (mode == 0) msg_type = MSG_GOSSIP_BLOCK;
    else if (mode == 1) msg_type = MSG_BLOCK_APPROVED;
    else if (mode == 2) msg_type = MSG_VOTE;
    else msg_type = MSG_PROPOSE_BLOCK;

    static _Thread_local Message *msg = NULL;
    if (!msg) msg = malloc(sizeof(Message));
    msg->type = msg_type;
    msg->length = size - 1;
    if (msg->length > MAX_MESSAGE_SIZE) {
        msg->length = MAX_MESSAGE_SIZE;
    }
    memcpy(msg->payload, data + 1, msg->length);

    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    sender_addr.sin_family = AF_INET;

    uint8_t sender_pubkey[DILITHIUM_PUBKEY_LEN];
    memcpy(sender_pubkey, global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);

    if (msg->type == MSG_GOSSIP_BLOCK) {
        handle_block_proposal(global_state, msg, &sender_addr, sender_pubkey);
    } else if (msg->type == MSG_BLOCK_APPROVED) {
        Block *block = calloc(1, sizeof(Block));
        if (block) {
            if (deserialize_block(block, msg->payload, msg->length) == 0) {
                if (verify_block_heavy_crypto(block) == CRYPTO_SUCCESS) {
                    handle_msg_block_approved(global_state, block, sender_pubkey);
                } else {
                    free_block(block);
                }
            } else {
                free_block(block);
            }
        }
    } else if (msg->type == MSG_VOTE) {
        handle_vote(global_state, msg, sender_pubkey);
    } else if (msg->type == MSG_PROPOSE_BLOCK) {
        Operation *provided_op = calloc(1, sizeof(Operation));
        if (provided_op) {
            if (deserialize_operation(msg->payload, msg->length, provided_op, 1) > 0) {
                propose_block(global_state, provided_op);
            }
            free(provided_op);
        }
    }

    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
#ifdef __cplusplus
}
#endif

// Custom Mutator ensuring structural protocol alignment for consensus blocks
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (new_size < 1) return new_size;

    uint8_t mode = Seed % 4;

    if (mode == 2) { // MSG_VOTE
        Data[0] = MSG_VOTE;
        size_t min_vote = 1 + COIN_ID_LEN + 1;
        if (new_size < min_vote) new_size = min_vote;
        if (new_size > MaxSize) new_size = MaxSize;
        Data[0] = MSG_VOTE;
        Data[1 + COIN_ID_LEN] = (Seed & 1);
        return new_size;
    }

    if (mode == 3 && Seed % 3 == 0) { // MSG_PROPOSE_BLOCK
        Data[0] = MSG_PROPOSE_BLOCK;
        if (new_size > 1) {
            Data[1] = (Seed >> 2) % 8;
        }
        return new_size;
    }

    // MSG_GOSSIP_BLOCK or MSG_BLOCK_APPROVED
    Data[0] = (mode == 0) ? MSG_GOSSIP_BLOCK : MSG_BLOCK_APPROVED;

    size_t header_len = 1 + 8 + COIN_ID_LEN + 8; // 49 bytes
    if (new_size < header_len) {
        if (MaxSize < header_len) return new_size;
        new_size = header_len;
    }

    uint64_t block_height = (Seed % 5 == 0) ? 0 : (Seed % 200);
    uint64_t block_height_be = htobe64(block_height);
    memcpy(Data + 1, &block_height_be, 8);

    if (block_height == 0) {
        memset(Data + 1 + 8, 0, COIN_ID_LEN);
    } else if (global_state && (Seed % 2 == 0)) {
        memcpy(Data + 1 + 8, global_state->current_block_hash, COIN_ID_LEN);
    }

    size_t op_count = (Seed >> 3) % (MAX_OPERATIONS_PER_BLOCK + 1);
    if (block_height == 0) op_count = 0;

    size_t curr_pos = header_len;
    size_t batch_tx_count = 0;

    for (size_t op_idx = 0; op_idx < op_count; op_idx++) {
        uint8_t op_type = (Seed + op_idx * 3) % 8;
        size_t needed = 0;
        switch (op_type) {
            case 0: needed = 9892; break;  // OP_SUBMIT_VALUATION
            case 1: needed = 3897; break;  // OP_MINT_COIN
            case 2: needed = 14691; break; // OP_TRANSFER_POINTER
            case 3: needed = 14691; break; // OP_STAKE
            case 4: needed = 10064; break; // OP_UNSTAKE
            case 5: needed = 4261; break;  // OP_REDEEM_CENTINEL
            case 6: needed = 9236; break;  // OP_CLAIM_VALIDATION
            case 7: needed = 10216; break; // OP_APPLY_DRIFT_CERT (1 input, 48-byte MMR proof)
        }

        size_t estimated_tail = 8 + 8 + 32 + 8 + 128 + PUBKEY_LEN + SIGNATURE_LEN + SIGNATURE_LEN;
        if (curr_pos + needed + estimated_tail > MaxSize) {
            op_count = op_idx;
            break;
        }

        uint8_t *op_start = Data + curr_pos;
        op_start[0] = op_type;

        if (op_type == 0 && global_state) {
            memcpy(op_start + 1 + 80 + 32, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        } else if (op_type == 1) {
            if (global_state) memcpy(op_start + 1, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            uint64_t total_sub = htobe64(100ULL * SUBUNITS_PER_COIN);
            memcpy(op_start + 1 + 2592 + 32 + 32 + 32, &total_sub, 8);
            memcpy(op_start + 1 + 2592 + 32 + 32 + 32 + 8, &total_sub, 8);
            uint32_t scnt = htobe32(10), sidx = htobe32(0);
            memcpy(op_start + 1 + 2592 + 32 + 32 + 32 + 16, &scnt, 4);
            memcpy(op_start + 1 + 2592 + 32 + 32 + 32 + 20, &sidx, 4);
        } else if (op_type == 2) {
            uint32_t num_in = htobe32(1);
            memcpy(op_start + 1 + 32 + 8, &num_in, 4);
            uint32_t plen_be = htobe32(1), zero_be = htobe32(0);
            memcpy(op_start + 229, &plen_be, 4);
            memcpy(op_start + 229 + 40, &zero_be, 4);
            memcpy(op_start + 229 + 44, &zero_be, 4);
            size_t off = 229 + 48;
            if (global_state) {
                memcpy(op_start + off, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                memcpy(op_start + off + PUBKEY_LEN, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            }
            uint64_t amt_be = htobe64(10ULL * SUBUNITS_PER_COIN);
            memcpy(op_start + off + 2 * PUBKEY_LEN, &amt_be, 8);
            batch_tx_count++;
        } else if (op_type == 3) {
            uint32_t num_in = htobe32(1);
            memcpy(op_start + 1 + 32 + 8, &num_in, 4);
            uint32_t plen_be = htobe32(1), zero_be = htobe32(0);
            memcpy(op_start + 229, &plen_be, 4);
            memcpy(op_start + 229 + 40, &zero_be, 4);
            memcpy(op_start + 229 + 44, &zero_be, 4);
            size_t off = 229 + 48;
            if (global_state) {
                memcpy(op_start + off, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                memcpy(op_start + off + PUBKEY_LEN, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            }
            uint64_t amt_be = htobe64(5ULL * SUBUNITS_PER_COIN);
            memcpy(op_start + off + 2 * PUBKEY_LEN, &amt_be, 8);
        } else if (op_type == 4) {
            uint32_t num_in = htobe32(1);
            memcpy(op_start + 1 + 32 + 8, &num_in, 4);
            uint32_t staked_be = htobe32(1);
            memcpy(op_start + 77 + 148, &staked_be, 4);
            uint32_t plen_be = htobe32(1), zero_be = htobe32(0);
            memcpy(op_start + 229, &plen_be, 4);
            memcpy(op_start + 229 + 40, &zero_be, 4);
            memcpy(op_start + 229 + 44, &zero_be, 4);
            size_t off = 229 + 48;
            if (global_state) {
                memcpy(op_start + off, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                memcpy(op_start + off + PUBKEY_LEN, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            }
            uint64_t amt_be = htobe64(5ULL * SUBUNITS_PER_COIN);
            memcpy(op_start + off + 2 * PUBKEY_LEN, &amt_be, 8);
        } else if (op_type == 5) {
            uint32_t zk_len_be = htobe32(128);
            memcpy(op_start + 1 + 32 + 2048 + 2048, &zk_len_be, 4);
        } else if (op_type == 6 && global_state) { // OP_CLAIM_VALIDATION
            memcpy(op_start + 1 + 2048, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        } else if (op_type == 7) { // OP_APPLY_DRIFT_CERT
            /* Wire: type(1) cert_tx_id(32) nonce(8) num_inputs(4,BE)
             * client_root(32) [pointer(152) mmr_proof(48: path_len=1)]*
             * circuit_hash(32) tvd_scaled(8,BE) shots(4,BE) status(4,BE)
             * commitment_root(32) timestamp_us(8,BE) recipient(2592)
             * sender(2592) amount(8,BE) inputs_merkle_root(32)
             * cert_digest(32) signature(4595). The 88-byte digest core
             * shifts the pubkey fields +88 past the transfer/stake layout. */
            uint32_t num_in = htobe32(1);
            memcpy(op_start + 1 + 32 + 8, &num_in, 4);
            uint32_t plen_be = htobe32(1), zero_be = htobe32(0);
            memcpy(op_start + 229, &plen_be, 4);
            memcpy(op_start + 229 + 40, &zero_be, 4);
            memcpy(op_start + 229 + 44, &zero_be, 4);
            size_t off = 229 + 48 + 88;
            if (global_state) {
                memcpy(op_start + off, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                memcpy(op_start + off + PUBKEY_LEN, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            }
            uint64_t amt_be = htobe64(1ULL * SUBUNITS_PER_COIN);
            memcpy(op_start + off + 2 * PUBKEY_LEN, &amt_be, 8);
        }

        curr_pos += needed;
    }

    uint64_t op_count_be = htobe64(op_count);
    memcpy(Data + 1 + 8 + COIN_ID_LEN, &op_count_be, 8);

    uint64_t entropy_seed_be = htobe64(Seed);
    memcpy(Data + curr_pos, &entropy_seed_be, 8); curr_pos += 8;

    uint64_t b_tx_cnt_be = htobe64(batch_tx_count);
    memcpy(Data + curr_pos, &b_tx_cnt_be, 8); curr_pos += 8;

    if (batch_tx_count > 0) {
        memset(Data + curr_pos, 0x77, batch_tx_count * 32);
        curr_pos += batch_tx_count * 32;
    }

    uint64_t zk_proof_len = batch_tx_count > 0 ? (batch_tx_count * (4 + 128)) : 0;
    uint64_t zk_proof_len_be = htobe64(zk_proof_len);
    memcpy(Data + curr_pos, &zk_proof_len_be, 8); curr_pos += 8;

    if (zk_proof_len > 0) {
        for (size_t b = 0; b < batch_tx_count; b++) {
            uint32_t plen = htobe32(128);
            memcpy(Data + curr_pos, &plen, 4);
            memset(Data + curr_pos + 4, 0x42, 128);
            curr_pos += (4 + 128);
        }
    }

    if (global_state) {
        memcpy(Data + curr_pos, global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    } else {
        memset(Data + curr_pos, 0x42, PUBKEY_LEN);
    }
    curr_pos += PUBKEY_LEN;

    memset(Data + curr_pos, 0xAA, SIGNATURE_LEN);
    curr_pos += SIGNATURE_LEN;

    memset(Data + curr_pos, 0xBB, SIGNATURE_LEN);
    curr_pos += SIGNATURE_LEN;

    new_size = curr_pos;
    return new_size;
}
