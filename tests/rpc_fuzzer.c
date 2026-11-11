/*
 * ==============================================================================
 * Satocialist Protocol: L5 Native RPC Wire Framing & Dispatch Fuzzer
 * ==============================================================================
 *
 * Target: scl_rpc_parser_create(), scl_rpc_verify_checksum(), and handle_rpc_request()
 *
 * Objective: Inject raw, length-prefixed, signed, compressed (LZ4), and paginated
 *            L5 RPC binary frames into the node's ingress API processor.
 *
 * Vulnerability Focus:
 *   - SclRpcHeader 32-byte wire format alignment & integer overflow bounds.
 *   - SipHash-2-4 fast-path DoS checksum verification & token bucket rate-limiting.
 *   - LZ4 payload decompression bomb defense and dynamic memory allocation limits.
 *   - ML-DSA-87 (Dilithium5) signature authentication & 64-second anti-replay tracking.
 *   - Method dispatch handlers (0x0000..0x0009: Balances, Blocks, Txs, Audit, Keys).
 *   - Custom mutator integrity ensuring checksum alignment across mutated frames.
 * ==============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <lz4.h>

#ifdef _WIN32
#include <direct.h>
#define SCL_MKDIR(dir) _mkdir(dir)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define SCL_MKDIR(dir) mkdir(dir, 0777)
#endif

#include "scl_rpc_ffi_export.h"
#include "constants.h"
#include "types.h"
#include "utils.h"
#include "blockchain.h"
#include "game_state.h"
#include "rpc.h"
#include "hash_table.h"
#include "queue.h"
#include "database.h"

static uint8_t global_fuzz_pubkey[DILITHIUM_PUBKEY_LEN];
static uint8_t global_fuzz_privkey[DILITHIUM_SECRETKEY_LEN];
static PRFKey global_fuzz_prf_key;
static uint8_t global_fuzz_coin_id[COIN_ID_LEN];
static uint8_t global_fuzz_ptr_id[COIN_ID_LEN];
static uint8_t global_fuzz_staked_ptr_id[COIN_ID_LEN];
static uint8_t global_fuzz_tx_id[COIN_ID_LEN];
static ValidationUTXO global_fuzz_val_utxo;
static int global_keys_initialized = 0;

static const uint8_t dummy_siphash_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// destroy_mock_state removed as state is now maintained statically across iterations

static void init_mock_state(State *s) {
    memset(s, 0, sizeof(State));

    s->config.port = 5555;
    s->config.rbf_enabled = true;
    s->config.max_pending_ops_config = 1000;
    s->config.mempool_async_threshold = 50;

    pthread_mutex_init(&s->mutex, NULL);
    pthread_mutex_init(&s->ledger_mutex, NULL);
    pthread_mutex_init(&s->wallet_mutex, NULL);
    pthread_mutex_init(&s->block_proposers_lock, NULL);
    pthread_mutex_init(&s->processed_blocks_mutex, NULL);
    pthread_mutex_init(&s->threshold_mutex, NULL);

    blockchain_init(&s->bc);

    for (int i = 0; i < MAX_PENDING_OPS; i++) {
        atomic_init(&s->pending_operations[i], NULL);
    }
    atomic_init(&s->pending_operations_count, 0);

    s->processed_blocks = malloc(sizeof(HashTable));
    hash_table_init(s->processed_blocks, 1024, COIN_ID_LEN, NULL, NULL, NULL, NULL);

    s->voted_heights = malloc(sizeof(HashTable));
    hash_table_init(s->voted_heights, 1024, USER_ID_LEN, hash_func, memcmp, free, NULL);

    s->orphan_pool = malloc(sizeof(HashTable));
    hash_table_init(s->orphan_pool, 1024, COIN_ID_LEN, NULL, memcmp, NULL, NULL);

    s->threshold_stake_processes = malloc(sizeof(HashTable));
    hash_table_init(s->threshold_stake_processes, 16, COIN_ID_LEN, NULL, memcmp, free_threshold_process, NULL);

    s->user_table = malloc(sizeof(HashTable));
    hash_table_init(s->user_table, 1024, COIN_ID_LEN, NULL, NULL, NULL, NULL);

    s->processed_txs = malloc(sizeof(HashTable));
    hash_table_init(s->processed_txs, 1024, COIN_ID_LEN, NULL, NULL, NULL, NULL);

    s->block_consensus = malloc(sizeof(HashTable));
    hash_table_init(s->block_consensus, 1024, SHA256_DIGEST_LENGTH, NULL, memcmp, free_block_vote_queue, NULL);

    s->block_proposers = malloc(sizeof(HashTable));
    hash_table_init(s->block_proposers, 1024, COIN_ID_LEN, NULL, memcmp, free, NULL);

    s->pubkey_cache = malloc(sizeof(HashTable));
    hash_table_init(s->pubkey_cache, 1024, USER_ID_LEN, hash_func, memcmp, NULL, NULL);

    s->epoch_processes = malloc(sizeof(HashTable));
    hash_table_init(s->epoch_processes, 16, COIN_ID_LEN, NULL, memcmp, free_threshold_process, NULL);

    s->epoch_sign_data_cache = malloc(sizeof(HashTable));
    hash_table_init(s->epoch_sign_data_cache, 16, COIN_ID_LEN, NULL, memcmp, free, NULL);

    s->dkg_active_sessions = malloc(sizeof(HashTable));
    hash_table_init(s->dkg_active_sessions, 16, COIN_ID_LEN, NULL, memcmp, free_dkg_session, NULL);

    pthread_mutex_init(&s->epoch_mutex, NULL);
    polyvec_init(&s->epoch_t_global, DILITHIUM_K);

    game_state_init(s, 1);

    pthread_mutex_init(&s->p2p_network.mutex, NULL);
    s->p2p_network.num_known_peers = 0;
    s->p2p_network.known_peers = NULL;
}

static void init_global_fuzz_keys(void) {
    dilithium_generate_keypair(global_fuzz_pubkey, global_fuzz_privkey);
    uint8_t prf_seed[KAPPA];
    SHA256(global_fuzz_privkey, DILITHIUM_SECRETKEY_LEN, prf_seed);
    prf_keygen(&global_fuzz_prf_key, prf_seed, KAPPA);
    global_keys_initialized = 1;
}

static void init_mock_state_and_populate(State *s) {
    init_mock_state(s);

    if (!global_keys_initialized) {
        init_global_fuzz_keys();
    }

    // Reuse pre-generated cryptographic keys to avoid massive generation bottleneck on every iteration
    memcpy(s->user_wallet.dilithium_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(s->user_wallet.dilithium_privkey, global_fuzz_privkey, DILITHIUM_SECRETKEY_LEN);
    memcpy(&s->user_wallet.prf_key, &global_fuzz_prf_key, sizeof(PRFKey));

    // Initialize local peer wallet keys
    memcpy(s->p2p_network.local_peer.peer_wallet.dilithium_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(s->p2p_network.local_peer.peer_wallet.dilithium_privkey, global_fuzz_privkey, DILITHIUM_SECRETKEY_LEN);

    // Initialize Private UTXO Wallet fields
    pthread_mutex_init(&s->user_wallet.utxo_mutex, NULL);
    s->user_wallet.cap_val_utxos = 16;
    s->user_wallet.num_val_utxos = 1;
    s->user_wallet.val_utxos = calloc(s->user_wallet.cap_val_utxos, sizeof(ValidationUTXO));

    // Populate mock validation UTXO
    memset(&global_fuzz_val_utxo, 0, sizeof(ValidationUTXO));
    global_fuzz_val_utxo.amount = 100;
    memset(global_fuzz_val_utxo.blinding_factor, 0x55, 32);
    memcpy(global_fuzz_val_utxo.pubkey, s->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    prf_keygen(&global_fuzz_val_utxo.prf_key, global_fuzz_val_utxo.blinding_factor, 32);
    bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, 100, global_fuzz_val_utxo.blinding_factor, &global_fuzz_val_utxo.commitment);
    uint8_t comm_hash[COIN_ID_LEN];
    SHA256((const uint8_t*)&global_fuzz_val_utxo.commitment, sizeof(BdlopCommitment), comm_hash);
    prf_evaluate(global_fuzz_val_utxo.nullifier, &global_fuzz_val_utxo.prf_key, comm_hash, COIN_ID_LEN, comm_hash);
    s->user_wallet.val_utxos[0] = global_fuzz_val_utxo;
    mmr_add(s->bc.centinel.validation_commitments, comm_hash, 0);

    // Populate mock coin into state
    uint8_t dummy_tx_hash[32] = {0};
    memset(dummy_tx_hash, 0x77, 32);
    memcpy(global_fuzz_tx_id, dummy_tx_hash, 32);
    SCLCoin coin = create_coin(dummy_tx_hash, s->user_wallet.dilithium_pubkey);
    coin.total_subunits = 0xFFFFFFFFFFFFFFFFULL;
    coin.remaining_subunits = coin.total_subunits;
    hash_table_insert(s->bc.coin_table, coin.coin_id, &coin, HASH_ENTRY_COIN);
    memcpy(global_fuzz_coin_id, coin.coin_id, COIN_ID_LEN);

    // Normal pointer
    Pointer ptr = {0};
    memcpy(ptr.parent_coin_id, coin.coin_id, COIN_ID_LEN);
    ptr.start_subunit = 0;
    ptr.end_subunit = (coin.total_subunits / 2) - 1;
    memcpy(ptr.owner_address, coin.owner_address, USER_ID_LEN);
    memcpy(ptr.prev_tx_hash, dummy_tx_hash, COIN_ID_LEN);
    SHA256(coin.coin_id, COIN_ID_LEN, ptr.pointer_id);
    hash_table_insert(s->bc.pointer_table, ptr.pointer_id, &ptr, HASH_ENTRY_POINTER);
    add_pointer_id_to_coin(s->bc.coin_pointers, coin.coin_id, ptr.pointer_id);
    memcpy(global_fuzz_ptr_id, ptr.pointer_id, COIN_ID_LEN);

    // Staked pointer
    Pointer staked_ptr = {0};
    memcpy(staked_ptr.parent_coin_id, coin.coin_id, COIN_ID_LEN);
    staked_ptr.start_subunit = coin.total_subunits / 2;
    staked_ptr.end_subunit = coin.total_subunits - 1000;
    staked_ptr.staked = 1;
    memcpy(staked_ptr.prev_tx_hash, dummy_tx_hash, COIN_ID_LEN);
    uint8_t threshold_pubkey[PUBKEY_LEN];
    compute_threshold_pubkey(s, threshold_pubkey);
    SHA256(threshold_pubkey, PUBKEY_LEN, staked_ptr.owner_address);
    SHA256(staked_ptr.owner_address, USER_ID_LEN, staked_ptr.pointer_id);
    hash_table_insert(s->bc.pointer_table, staked_ptr.pointer_id, &staked_ptr, HASH_ENTRY_POINTER);
    add_pointer_id_to_coin(s->bc.coin_pointers, staked_ptr.parent_coin_id, staked_ptr.pointer_id);
    memcpy(global_fuzz_staked_ptr_id, staked_ptr.pointer_id, COIN_ID_LEN);

    // Fee pointer (spent == 2)
    Pointer fee_ptr = {0};
    memcpy(fee_ptr.parent_coin_id, coin.coin_id, COIN_ID_LEN);
    fee_ptr.start_subunit = coin.total_subunits - 999;
    fee_ptr.end_subunit = coin.total_subunits - 1;
    fee_ptr.spent = 2;
    memcpy(fee_ptr.owner_address, coin.owner_address, USER_ID_LEN);
    memcpy(fee_ptr.prev_tx_hash, dummy_tx_hash, COIN_ID_LEN);
    SHA256(fee_ptr.owner_address, USER_ID_LEN, fee_ptr.pointer_id);
    hash_table_insert(s->bc.pointer_table, fee_ptr.pointer_id, &fee_ptr, HASH_ENTRY_POINTER);
    add_pointer_id_to_coin(s->bc.coin_pointers, fee_ptr.parent_coin_id, fee_ptr.pointer_id);

    // Set insert_order
    s->bc.insert_order_capacity = 16;
    s->bc.insert_order = calloc(s->bc.insert_order_capacity, sizeof(SCLCoin *));
    s->bc.insert_order[0] = &coin;
    s->bc.insert_order_count = 1;
    mmr_add(s->bc.mmr, coin.coin_id, coin.remaining_subunits);

    // Register user
    uint8_t user_id[USER_ID_LEN];
    SHA256(s->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
    register_user(s, user_id, s->user_wallet.dilithium_pubkey);

    // Populate game state
    s->game_state.total_rewarded_scl_subunits = 1000 * SUBUNITS_PER_COIN;
    s->game_state.remaining_scl_subunits = MAX_TOTAL_SUBUNITS - s->game_state.total_rewarded_scl_subunits;
    s->game_state.cached_stage = 2;
    s->game_state.valuation_count = AUDIT_SIZE;
    for (int i = 0; i < AUDIT_SIZE; i++) {
        memset(&s->game_state.game_audit[i], 0, sizeof(Valuation));
        s->game_state.game_audit[i].user_id[0] = i + 1;
        for (int j = 0; j < NUMBERS_PER_VALUATION; j++) {
            s->game_state.game_audit[i].numbers[j] = (i * 10 + j) % 100;
        }
        s->game_state.game_audit[i].timestamp = 1000000 + i;
    }
    update_game_state_snapshot(s);

    // Mock blocks in DB (Block 0, Block 1 with operations, Block 150)
    Block b0 = create_standard_genesis_block();
    uint8_t *ser_b0 = malloc(65536);
    if (ser_b0) {
        int len0 = process_block_data(&b0, ser_b0, NULL, true);
        if (len0 > 0) scl_db_put_block(0, ser_b0, len0);
        free(ser_b0);
    }

    uint8_t b0_hash[COIN_ID_LEN];
    compute_block_hash(&b0, b0_hash);

    // Block 1 with operations
    Block b1 = {0};
    b1.block_number = 1;
    memcpy(b1.prev_block_hash, b0_hash, COIN_ID_LEN);
    memcpy(b1.proposer_pubkey, s->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    b1.operation_count = 1;
    b1.operations = calloc(1, sizeof(Operation));
    if (b1.operations) {
        b1.operations[0].type = OP_TRANSFER_POINTER;
        b1.operations[0].data.transfer_pointer.num_inputs = 1;
        b1.operations[0].data.transfer_pointer.inputs[0] = ptr;
        b1.operations[0].data.transfer_pointer.amount = 1000;
        memcpy(b1.operations[0].data.transfer_pointer.recipient_pubkey, s->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        memcpy(b1.operations[0].data.transfer_pointer.sender_pubkey, s->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        memcpy(b1.operations[0].data.transfer_pointer.tx_id, dummy_tx_hash, COIN_ID_LEN);

        uint8_t *ser_b1 = malloc(65536);
        if (ser_b1) {
            int len1 = process_block_data(&b1, ser_b1, NULL, true);
            if (len1 > 0) scl_db_put_block(1, ser_b1, len1);
            free(ser_b1);
        }
        free(b1.operations);
    }

    // Mock a block in the DB to test GetBlock retrieval and serialization
    Block b_mock = {0};
    b_mock.block_number = 150;
    memset(b_mock.prev_block_hash, 0x11, COIN_ID_LEN);
    b_mock.operation_count = 0;
    memcpy(b_mock.proposer_pubkey, s->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    uint8_t *ser_block = malloc(65536);
    if (ser_block) {
        int ser_len = process_block_data(&b_mock, ser_block, NULL, true);
        if (ser_len > 0) {
            scl_db_put_block(150, ser_block, ser_len);
        }
        free(ser_block);
    }

    s->current_block_number = 150;
}

static void write_seed_file(const char *dir, const char *name, uint8_t version, uint8_t flags, uint16_t status_code, uint16_t method_id, uint64_t request_id, uint32_t cursor, const uint8_t *payload, uint32_t payload_len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) return;

    SclRpcHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = version;
    hdr.flags = flags;
    hdr.status_code = htobe16(status_code);
    hdr.method_id = htobe16(method_id);
    hdr.error_msg_len = htobe16(0);
    hdr.request_id = htobe64(request_id);
    hdr.payload_len = htobe32(payload_len);
    hdr.cursor = htobe32(cursor);

    // Compute valid checksum
    uint8_t *temp_buf = malloc(sizeof(SclRpcHeader) + payload_len);
    if (temp_buf) {
        memcpy(temp_buf, &hdr, sizeof(SclRpcHeader));
        if (payload_len > 0 && payload) {
            memcpy(temp_buf + sizeof(SclRpcHeader), payload, payload_len);
        }
        uint64_t checksum = compute_rpc_checksum(temp_buf, 0, payload_len, dummy_siphash_key);
        hdr.checksum = htobe64(checksum);
        free(temp_buf);
    }

    fwrite(&hdr, 1, sizeof(SclRpcHeader), f);
    if (payload_len > 0 && payload) {
        fwrite(payload, 1, payload_len, f);
    }
    fclose(f);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Quiet logging to prevent performance-killing I/O flooding during fuzzing
    scl_log_set_level(LOG_LEVEL_FATAL);

    if (!global_keys_initialized) {
        init_global_fuzz_keys();
    }

    const char *corpus_dir = "../rpc_fuzzer_corpus";

    // Dynamically resolve target corpus directory from command line arguments
    for (int i = 1; i < *argc; i++) {
        if ((*argv)[i][0] != '-') {
            corpus_dir = (*argv)[i];
            break;
        }
    }

    SCL_MKDIR(corpus_dir);

    // Seed 1: GetRegistry, Status OK, plain
    write_seed_file(corpus_dir, "seed01_get_registry.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0000, 10001, 0, NULL, 0);

    // Seed 2: GetBalance, Status OK, with dummy 2592-byte Dilithium pubkey
    uint8_t dummy_pubkey[2592];
    memset(dummy_pubkey, 0x11, 2592);
    write_seed_file(corpus_dir, "seed02_get_balance.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0001, 10002, 0, dummy_pubkey, 2592);

    // Seed 3: GetBlock, Status OK, Paginated flag, cursor = 150
    write_seed_file(corpus_dir, "seed03_get_block_paginated.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_PAGINATED, SCL_RPC_STATUS_OK, 0x0002, 10003, 150, NULL, 0);

    // Ensure keys are ready to derive exact pointer IDs for the seeds
    if (!global_keys_initialized) {
        init_global_fuzz_keys();
    }

    uint8_t dummy_tx_hash[32] = {0};
    uint8_t owner_address[USER_ID_LEN];
    SHA256(global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN, owner_address);

    uint8_t coin_id_data[COIN_ID_LEN + PUBKEY_LEN];
    memcpy(coin_id_data, dummy_tx_hash, COIN_ID_LEN);
    memcpy(coin_id_data + COIN_ID_LEN, global_fuzz_pubkey, PUBKEY_LEN);
    uint8_t coin_id[COIN_ID_LEN];
    SHA256(coin_id_data, COIN_ID_LEN + PUBKEY_LEN, coin_id);

    uint64_t total_subunits = 160000000ULL * 100; // Just some large number
    
    // Normal Pointer
    Pointer normal_ptr = {0};
    memcpy(normal_ptr.parent_coin_id, coin_id, COIN_ID_LEN);
    normal_ptr.start_subunit = 0;
    normal_ptr.end_subunit = (total_subunits / 2) - 1;
    memcpy(normal_ptr.owner_address, owner_address, USER_ID_LEN);
    SHA256(coin_id, COIN_ID_LEN, normal_ptr.pointer_id);

    // Staked Pointer
    Pointer staked_ptr = {0};
    memcpy(staked_ptr.parent_coin_id, coin_id, COIN_ID_LEN);
    staked_ptr.start_subunit = total_subunits / 2;
    staked_ptr.end_subunit = total_subunits - 1;
    staked_ptr.staked = 1;
    uint8_t threshold_pubkey[PUBKEY_LEN] = {0};
    // In fuzzing mode, compute_threshold_pubkey zeros the pubkey.
    uint8_t threshold_address[USER_ID_LEN];
    SHA256(threshold_pubkey, PUBKEY_LEN, threshold_address);
    memcpy(staked_ptr.owner_address, threshold_address, USER_ID_LEN);
    SHA256(staked_ptr.owner_address, USER_ID_LEN, staked_ptr.pointer_id);

    // Seed 4.0 - 4.6: SubmitTx Operations
    Operation op_dummy = {0};
    uint8_t op_buf[16384];
    size_t op_sz;
    
    // Seed 4.0: OP_CLAIM_VALIDATION
    op_dummy.type = OP_CLAIM_VALIDATION;
    memcpy(op_dummy.data.claim_validation.pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    if (op_sz > 0) {
        uint8_t *s_payload = calloc(1, DILITHIUM_SIGNATURE_LEN + op_sz);
        if (s_payload) {
            memcpy(s_payload + DILITHIUM_SIGNATURE_LEN, op_buf, op_sz);
            write_seed_file(corpus_dir, "seed04_0_submit_tx_claim.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED, SCL_RPC_STATUS_OK, 0x0003, 100040, 0, s_payload, DILITHIUM_SIGNATURE_LEN + op_sz);
            free(s_payload);
        }
    }

    // Seed 4.1: OP_REDEEM_CENTINEL
    memset(&op_dummy, 0, sizeof(Operation));
    op_dummy.type = OP_REDEEM_CENTINEL;
    op_dummy.data.redeem_centinel.zk_proof_len = 128;
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    if (op_sz > 0) {
        uint8_t *s_payload = calloc(1, DILITHIUM_SIGNATURE_LEN + op_sz);
        if (s_payload) {
            memcpy(s_payload + DILITHIUM_SIGNATURE_LEN, op_buf, op_sz);
            write_seed_file(corpus_dir, "seed04_1_submit_tx_redeem.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED, SCL_RPC_STATUS_OK, 0x0003, 100041, 0, s_payload, DILITHIUM_SIGNATURE_LEN + op_sz);
            free(s_payload);
        }
    }

    // Seed 4.2: OP_SUBMIT_VALUATION
    memset(&op_dummy, 0, sizeof(Operation));
    op_dummy.type = OP_SUBMIT_VALUATION;
    memcpy(op_dummy.data.submit_valuation.pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    if (op_sz > 0) {
        uint8_t *s_payload = calloc(1, DILITHIUM_SIGNATURE_LEN + op_sz);
        if (s_payload) {
            memcpy(s_payload + DILITHIUM_SIGNATURE_LEN, op_buf, op_sz);
            write_seed_file(corpus_dir, "seed04_2_submit_tx_val.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED, SCL_RPC_STATUS_OK, 0x0003, 100042, 0, s_payload, DILITHIUM_SIGNATURE_LEN + op_sz);
            free(s_payload);
        }
    }

    // Seed 4.3: OP_MINT_COIN
    memset(&op_dummy, 0, sizeof(Operation));
    op_dummy.type = OP_MINT_COIN;
    memcpy(op_dummy.data.mint_coin.owner_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    if (op_sz > 0) {
        uint8_t *s_payload = calloc(1, DILITHIUM_SIGNATURE_LEN + op_sz);
        if (s_payload) {
            memcpy(s_payload + DILITHIUM_SIGNATURE_LEN, op_buf, op_sz);
            write_seed_file(corpus_dir, "seed04_3_submit_tx_mint.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED, SCL_RPC_STATUS_OK, 0x0003, 100043, 0, s_payload, DILITHIUM_SIGNATURE_LEN + op_sz);
            free(s_payload);
        }
    }

    // Seed 4.4: OP_TRANSFER_POINTER
    memset(&op_dummy, 0, sizeof(Operation));
    op_dummy.type = OP_TRANSFER_POINTER;
    op_dummy.data.transfer_pointer.num_inputs = 1;
    op_dummy.data.transfer_pointer.inputs[0] = normal_ptr;
    op_dummy.data.transfer_pointer.amount = 1000;
    memcpy(op_dummy.data.transfer_pointer.sender_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    op_dummy.data.transfer_pointer.zk_proof_len = 128;
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    if (op_sz > 0) {
        uint8_t *s_payload = calloc(1, DILITHIUM_SIGNATURE_LEN + op_sz);
        if (s_payload) {
            memcpy(s_payload + DILITHIUM_SIGNATURE_LEN, op_buf, op_sz);
            write_seed_file(corpus_dir, "seed04_4_submit_tx_transfer.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED, SCL_RPC_STATUS_OK, 0x0003, 100044, 0, s_payload, DILITHIUM_SIGNATURE_LEN + op_sz);
            free(s_payload);
        }
    }

    // Seed 4.5: OP_STAKE
    memset(&op_dummy, 0, sizeof(Operation));
    op_dummy.type = OP_STAKE;
    op_dummy.data.stake.num_inputs = 1;
    op_dummy.data.stake.inputs[0] = normal_ptr;
    op_dummy.data.stake.amount = 1000;
    memcpy(op_dummy.data.stake.sender_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    if (op_sz > 0) {
        uint8_t *s_payload = calloc(1, DILITHIUM_SIGNATURE_LEN + op_sz);
        if (s_payload) {
            memcpy(s_payload + DILITHIUM_SIGNATURE_LEN, op_buf, op_sz);
            write_seed_file(corpus_dir, "seed04_5_submit_tx_stake.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED, SCL_RPC_STATUS_OK, 0x0003, 100045, 0, s_payload, DILITHIUM_SIGNATURE_LEN + op_sz);
            free(s_payload);
        }
    }

    // Seed 4.6: OP_UNSTAKE
    memset(&op_dummy, 0, sizeof(Operation));
    op_dummy.type = OP_UNSTAKE;
    op_dummy.data.unstake.num_inputs = 1;
    op_dummy.data.unstake.inputs[0] = staked_ptr;
    op_dummy.data.unstake.amount = 1000;
    memcpy(op_dummy.data.unstake.recipient_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(op_dummy.data.unstake.threshold_pubkey, threshold_pubkey, DILITHIUM_PUBKEY_LEN);
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    if (op_sz > 0) {
        uint8_t *s_payload = calloc(1, DILITHIUM_SIGNATURE_LEN + op_sz);
        if (s_payload) {
            memcpy(s_payload + DILITHIUM_SIGNATURE_LEN, op_buf, op_sz);
            write_seed_file(corpus_dir, "seed04_6_submit_tx_unstake.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED, SCL_RPC_STATUS_OK, 0x0003, 100046, 0, s_payload, DILITHIUM_SIGNATURE_LEN + op_sz);
            free(s_payload);
        }
    }

    // Seed 16: SyncWalletKeys (Method 0x0009)
    size_t sync_keys_len = DILITHIUM_PUBKEY_LEN + DILITHIUM_SECRETKEY_LEN + sizeof(PRFKey);
    uint8_t *sync_keys_payload = calloc(1, sync_keys_len);
    if (sync_keys_payload) {
        memcpy(sync_keys_payload, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
        memcpy(sync_keys_payload + DILITHIUM_PUBKEY_LEN, global_fuzz_privkey, DILITHIUM_SECRETKEY_LEN);
        memcpy(sync_keys_payload + DILITHIUM_PUBKEY_LEN + DILITHIUM_SECRETKEY_LEN, &global_fuzz_prf_key, sizeof(PRFKey));
        write_seed_file(corpus_dir, "seed16_sync_keys.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0009, 10016, 0, sync_keys_payload, sync_keys_len);
        free(sync_keys_payload);
    }

    // Seed 17-20: GetTransaction (Method 0x0007) targeted at exact active UTXO hashes
    write_seed_file(corpus_dir, "seed17_get_exact_tx_hash.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0007, 10017, 0, dummy_tx_hash, COIN_ID_LEN);
    write_seed_file(corpus_dir, "seed18_get_exact_tx_coin.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0007, 10018, 0, coin_id, COIN_ID_LEN);
    write_seed_file(corpus_dir, "seed19_get_exact_tx_ptr.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0007, 10019, 0, normal_ptr.pointer_id, COIN_ID_LEN);
    write_seed_file(corpus_dir, "seed20_get_exact_tx_stk.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0007, 10020, 0, staked_ptr.pointer_id, COIN_ID_LEN);

    // Seed 21: GetBlock (Method 0x0002) targeting exact mocked block height (150)
    write_seed_file(corpus_dir, "seed21_get_block_exact.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_PAGINATED, SCL_RPC_STATUS_OK, 0x0002, 10021, 150, NULL, 0);

    // Seed 22: GetRecentTxs (Method 0x0006) spanning maximum paginated cursor bounds
    write_seed_file(corpus_dir, "seed22_get_recent_txs_max.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_PAGINATED, SCL_RPC_STATUS_OK, 0x0006, 10022, MAX_PAGINATION_RANGE - 1, NULL, 0);

    // Seed 23: Quantum TVD Audit (Method 0x000A)
    uint8_t tvd_payload[36];
    uint32_t tvd_shots_be = htobe32(15000);
    memcpy(tvd_payload, &tvd_shots_be, 4);
    memset(tvd_payload + 4, 0x42, 32);
    write_seed_file(corpus_dir, "seed23_quantum_tvd_audit.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x000A, 10023, 0, tvd_payload, 36);

    // Seed 24: Auto-Pilot Config & Status (Method 0x000B)
    uint8_t ap_seed_payload[9];
    ap_seed_payload[0] = 1;
    uint32_t ap_val_be = htobe32(5);
    memcpy(ap_seed_payload + 1, &ap_val_be, 4);
    uint32_t ap_ratio_be = htobe32(50);
    memcpy(ap_seed_payload + 5, &ap_ratio_be, 4);
    write_seed_file(corpus_dir, "seed24_autopilot_config.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x000B, 10024, 0, ap_seed_payload, 9);

    // Seed 25: Quantum TVD Audit with Payment Receipt (Method 0x000A)
    uint8_t tvd_receipt_payload[36 + 41];
    SclRpcPaymentReceipt dummy_receipt;
    dummy_receipt.payment_type = 0x01;
    memset(dummy_receipt.tx_id, 0xBB, 32);
    dummy_receipt.price_rate_lock_id = htobe64(123456789);
    memcpy(tvd_receipt_payload, &dummy_receipt, 41);
    memcpy(tvd_receipt_payload + 41, tvd_payload, 36);
    write_seed_file(corpus_dir, "seed25_quantum_tvd_audit_receipt.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_PAYMENT_RECEIPT, SCL_RPC_STATUS_OK, 0x000A, 10025, 0, tvd_receipt_payload, 77);

    // Provide a realistic dummy payload for compression seeds (like GetValuations response)
    uint8_t dummy_response_payload[1024];
    memset(dummy_response_payload, 0x55, sizeof(dummy_response_payload));
    size_t orig_len = sizeof(dummy_response_payload);
    int max_comp = LZ4_compressBound((int)orig_len);
    
    // Seed 5: GetAudit, Status OK, Compressed flag
    uint8_t *comp_buf = malloc(max_comp);
    if (comp_buf) {
        int comp_len = LZ4_compress_default((const char *)dummy_response_payload, (char *)comp_buf, (int)orig_len, max_comp);
        if (comp_len > 0) {
            write_seed_file(corpus_dir, "seed05_get_audit_compressed.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_COMPRESSED, SCL_RPC_STATUS_OK, 0x0004, 10005, 0, comp_buf, comp_len);
        }
        free(comp_buf);
    }

    // Seed 6: GetValuations, Status OK, Compressed flag
    uint8_t *comp_buf2 = malloc(max_comp);
    if (comp_buf2) {
        int comp_len = LZ4_compress_default((const char *)dummy_response_payload, (char *)comp_buf2, (int)orig_len, max_comp);
        if (comp_len > 0) {
            write_seed_file(corpus_dir, "seed06_get_valuations_compressed.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_COMPRESSED, SCL_RPC_STATUS_OK, 0x0005, 10006, 0, comp_buf2, comp_len);
        }
        free(comp_buf2);
    }

    // Seed 7: GetRecentTxs, Status OK, Paginated flag, cursor = 1000
    write_seed_file(corpus_dir, "seed07_get_recent_txs.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_PAGINATED, SCL_RPC_STATUS_OK, 0x0006, 10007, 1000, NULL, 0);

    // Seed 8: GetTransaction, Status OK, targeting 32-byte transaction hash
    uint8_t tx_hash[32];
    memset(tx_hash, 0x77, 32);
    write_seed_file(corpus_dir, "seed08_get_transaction.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0007, 10008, 0, tx_hash, 32);

    // Seed 9: GetChainInfo, Status OK, plain
    write_seed_file(corpus_dir, "seed09_get_chain_info.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_OK, 0x0008, 10009, 0, NULL, 0);

    // Seed 10: GetBalance, Unauthorized Status
    write_seed_file(corpus_dir, "seed10_get_balance_unauthorized.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_UNAUTHORIZED, 0x0001, 10010, 0, dummy_pubkey, 2592);

    // Seed 11: SubmitTx, Bad Version Status
    write_seed_file(corpus_dir, "seed11_submit_tx_bad_version.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_BAD_VERSION, 0x0003, 10011, 0, NULL, 0);

    // Seed 12: GetBlock, Invalid Args Status
    write_seed_file(corpus_dir, "seed12_get_block_invalid_args.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_INVALID_ARGS, 0x0002, 10012, 0, NULL, 0);

    // Seed 13: GetAudit, Rate Limited Status
    write_seed_file(corpus_dir, "seed13_get_audit_rate_limited.bin", SCL_RPC_VERSION_1, 0, SCL_RPC_STATUS_RATE_LIMITED, 0x0004, 10013, 0, NULL, 0);

    // Seed 14: SubmitTx, Signed + Compressed payload
    op_dummy.type = OP_TRANSFER_POINTER;
    op_dummy.data.transfer_pointer.num_inputs = 1;
    op_dummy.data.transfer_pointer.inputs[0] = normal_ptr;
    op_dummy.data.transfer_pointer.amount = 1000;
    memcpy(op_dummy.data.transfer_pointer.sender_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
    op_dummy.data.transfer_pointer.zk_proof_len = 128;
    op_sz = serialize_operation(&op_dummy, op_buf, sizeof(op_buf));
    
    if (op_sz > 0) {
        int max_op_comp = LZ4_compressBound((int)op_sz);
        uint8_t *comp_buf3 = malloc(max_op_comp);
        if (comp_buf3) {
            int comp_len = LZ4_compress_default((const char *)op_buf, (char *)comp_buf3, (int)op_sz, max_op_comp);
            if (comp_len > 0) {
                size_t c_s_len = DILITHIUM_SIGNATURE_LEN + comp_len;
                uint8_t *c_s_payload = calloc(1, c_s_len);
                if (c_s_payload) {
                    memset(c_s_payload, 0xAA, DILITHIUM_SIGNATURE_LEN);
                    memcpy(c_s_payload + DILITHIUM_SIGNATURE_LEN, comp_buf3, comp_len);
                    write_seed_file(corpus_dir, "seed14_submit_tx_signed_compressed.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_SIGNED | SCL_RPC_FLAG_COMPRESSED, SCL_RPC_STATUS_OK, 0x0003, 10014, 0, c_s_payload, c_s_len);
                    free(c_s_payload);
                }
            }
            free(comp_buf3);
        }
    }

    // Seed 15: GetBlock, Max Pagination Cursor
    write_seed_file(corpus_dir, "seed15_get_block_max_cursor.bin", SCL_RPC_VERSION_1, SCL_RPC_FLAG_PAGINATED, SCL_RPC_STATUS_OK, 0x0002, 10015, 0xFFFFFFFF, NULL, 0);

    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
#ifdef __cplusplus
}
#endif

// Custom Mutator ensuring structurally integrated checksum updates
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (new_size >= sizeof(SclRpcHeader)) {
        SclRpcHeader *hdr = (SclRpcHeader *)Data;
        
        size_t remaining = new_size - sizeof(SclRpcHeader);
        uint16_t err_len = be16toh(hdr->error_msg_len);
        
        if (err_len > remaining) {
            err_len = remaining;
        }
        uint32_t payload_len = remaining - err_len;

        // Keep version pinned to SCL_RPC_VERSION_1 to bypass quick exit constraints
        hdr->version = SCL_RPC_VERSION_1;

        // Dynamically sync the request_id timestamp to perfectly map into the sliding anti-replay window
        uint64_t now_ms = get_time_ms();
        uint64_t valid_req_id = (now_ms << 16) | (Seed & 0xFFFF);
        hdr->request_id = htobe64(valid_req_id);

        // Force a valid method_id to ensure we hit all dispatch paths (0x0000 through 0x000B)
        uint16_t method = Seed % 12;
        if (Seed % 13 != 0) {
            hdr->method_id = htobe16(method);
        } else {
            method = be16toh(hdr->method_id);
        }

        // Drop the COMPRESSED flag natively so libFuzzer explores raw Operations parsing
        hdr->flags &= ~SCL_RPC_FLAG_COMPRESSED;

        // --- METHOD-SPECIFIC STRUCTURAL REPAIR ---
        if (method == 0x0000 || method == 0x0004 || method == 0x0005 || method == 0x0008) {
            // GetRegistry, GetAudit, GetValuations, GetChainInfo take 0-length request payloads
            payload_len = 0;
        } else if (method == 0x0001) { // GetBalance
            payload_len = 2592;
            if (sizeof(SclRpcHeader) + err_len + 2592 <= MaxSize && Seed % 2 == 0) {
                memcpy(Data + sizeof(SclRpcHeader) + err_len, global_fuzz_pubkey, 2592);
            }
        } else if (method == 0x0002 || method == 0x0006) { // GetBlock, GetRecentTxs
            hdr->flags |= SCL_RPC_FLAG_PAGINATED;
            if (method == 0x0002) {
                uint32_t heights[] = {0, 1, 150};
                hdr->cursor = htobe32((Seed % 4 == 0) ? heights[Seed % 3] : (Seed % 200));
            } else {
                hdr->cursor = htobe32(Seed % 50);
            }
            payload_len = 0;
        } else if (method == 0x0007) { // GetTransaction
            payload_len = 32;
            if (sizeof(SclRpcHeader) + err_len + 32 <= MaxSize) {
                switch (Seed % 4) {
                    case 0: memcpy(Data + sizeof(SclRpcHeader) + err_len, global_fuzz_coin_id, 32); break;
                    case 1: memcpy(Data + sizeof(SclRpcHeader) + err_len, global_fuzz_ptr_id, 32); break;
                    case 2: memcpy(Data + sizeof(SclRpcHeader) + err_len, global_fuzz_tx_id, 32); break;
                    default: break;
                }
            }
        } else if (method == 0x0009) { // SyncWalletKeys
            payload_len = 2592 + 4864 + sizeof(PRFKey); // 8480
            if (sizeof(SclRpcHeader) + err_len + payload_len <= MaxSize && Seed % 3 == 0) {
                memcpy(Data + sizeof(SclRpcHeader) + err_len, global_fuzz_pubkey, 2592);
                memcpy(Data + sizeof(SclRpcHeader) + err_len + 2592, global_fuzz_privkey, 4864);
                memcpy(Data + sizeof(SclRpcHeader) + err_len + 2592 + 4864, &global_fuzz_prf_key, sizeof(PRFKey));
            }
        } else if (method == 0x000A) { // Quantum TVD Audit
            payload_len = 36;
            if (sizeof(SclRpcHeader) + err_len + 36 <= MaxSize) {
                uint32_t shots = (Seed % 50 == 0) ? ((Seed % 15000) + 10) : ((Seed % 500) + 10);
                uint32_t shots_be = htobe32(shots);
                memcpy(Data + sizeof(SclRpcHeader) + err_len, &shots_be, 4);
                memset(Data + sizeof(SclRpcHeader) + err_len + 4, (uint8_t)Seed, 32);
            }
        } else if (method == 0x000B) { // Autopilot
            payload_len = 9;
            if (sizeof(SclRpcHeader) + err_len + 9 <= MaxSize) {
                Data[sizeof(SclRpcHeader) + err_len] = (Seed & 1);
                uint32_t val_per_hr = htobe32((Seed % 10) + 1);
                memcpy(Data + sizeof(SclRpcHeader) + err_len + 1, &val_per_hr, 4);
                uint32_t stake_ratio = htobe32(Seed % 101);
                memcpy(Data + sizeof(SclRpcHeader) + err_len + 5, &stake_ratio, 4);
            }
        } else if (method == 0x0003) { // SubmitTx
            hdr->flags |= SCL_RPC_FLAG_SIGNED;
            uint8_t op_type = (Seed >> 3) % 8;
            size_t needed = 0;
            switch (op_type) {
                case 0: needed = 9892; break; // OP_SUBMIT_VALUATION
                case 1: needed = 3897; break; // OP_MINT_COIN
                case 2: needed = 14819; break; // OP_TRANSFER_POINTER
                case 3: needed = 14655; break; // OP_STAKE
                case 4: needed = 10028; break; // OP_UNSTAKE
                case 5: needed = 4261; break;  // OP_REDEEM_CENTINEL
                case 6: needed = 9236; break;  // OP_CLAIM_VALIDATION
                case 7: needed = 10180; break; // OP_APPLY_DRIFT_CERT (1 input, 12-byte MMR proof)
            }
            size_t sig_len = DILITHIUM_SIGNATURE_LEN;
            if (sizeof(SclRpcHeader) + err_len + sig_len + needed <= MaxSize) {
                payload_len = sig_len + needed;
                uint8_t *op_start = Data + sizeof(SclRpcHeader) + err_len + sig_len;
                if (Seed % 13 != 0) {
                    op_start[0] = op_type;
                    if (op_type == 0) { // OP_SUBMIT_VALUATION
                        memcpy(op_start + 1 + 32 + 40 + 8 + 32, global_fuzz_pubkey, 2592);
                    } else if (op_type == 1) { // OP_MINT_COIN
                        memcpy(op_start + 1, global_fuzz_pubkey, 2592);
                    } else if (op_type == 2) { // OP_TRANSFER_POINTER
                        uint32_t num_in = htobe32(1);
                        memcpy(op_start + 1 + 32 + 8, &num_in, 4);
                        size_t off = 1 + 32 + 8 + 4 + 32 + sizeof(Pointer) + 12;
                        memcpy(op_start + off, global_fuzz_pubkey, 2592);
                        memcpy(op_start + off + 2592, global_fuzz_pubkey, 2592);
                    } else if (op_type == 3) { // OP_STAKE
                        uint32_t num_in = htobe32(1);
                        memcpy(op_start + 1 + 32 + 8, &num_in, 4);
                        size_t off = 1 + 32 + 8 + 4 + 32 + sizeof(Pointer) + 12;
                        memcpy(op_start + off, global_fuzz_pubkey, 2592);
                        memcpy(op_start + off + 2592, global_fuzz_pubkey, 2592);
                    } else if (op_type == 4) { // OP_UNSTAKE
                        uint32_t num_in = htobe32(1);
                        memcpy(op_start + 1 + 32 + 8, &num_in, 4);
                        size_t off = 1 + 32 + 8 + 4 + 32 + sizeof(Pointer) + 12;
                        memcpy(op_start + off, global_fuzz_pubkey, 2592);
                        memcpy(op_start + off + 2592, global_fuzz_pubkey, 2592);
                    } else if (op_type == 5) { // OP_REDEEM_CENTINEL
                        uint32_t zk_len_be = htobe32(128);
                        memcpy(op_start + 1 + 32 + 4096, &zk_len_be, 4);
                    } else if (op_type == 6) { // OP_CLAIM_VALIDATION
                        memcpy(op_start + 1 + 2048, global_fuzz_pubkey, 2592);
                    } else if (op_type == 7) { // OP_APPLY_DRIFT_CERT
                        /* Wire: type(1) cert_tx_id(32) nonce(8) num_inputs(4,BE)
                         * client_root(32) [pointer(152) mmr_proof(12)]*
                         * circuit_hash(32) tvd_scaled(8,BE) shots(4,BE)
                         * status(4,BE) commitment_root(32) timestamp_us(8,BE)
                         * recipient(2592) sender(2592) amount(8,BE)
                         * inputs_merkle_root(32) cert_digest(32) signature(4595).
                         * The 88-byte digest core sits between the proof and
                         * recipient, so the pubkey offsets are shifted +88
                         * relative to the transfer/stake layout. */
                        uint32_t num_in = htobe32(1);
                        memcpy(op_start + 1 + 32 + 8, &num_in, 4);
                        size_t off = 1 + 32 + 8 + 4 + 32 + sizeof(Pointer) + 12 + 88;
                        memcpy(op_start + off, global_fuzz_pubkey, 2592);
                        memcpy(op_start + off + 2592, global_fuzz_pubkey, 2592);
                    }
                }
            } else {
                payload_len = sig_len + 128;
            }
        }

        if (sizeof(SclRpcHeader) + err_len + payload_len <= MaxSize) {
            new_size = sizeof(SclRpcHeader) + err_len + payload_len;
            hdr->payload_len = htobe32(payload_len);
            hdr->error_msg_len = htobe16(err_len);
        } else {
            payload_len = MaxSize - sizeof(SclRpcHeader) - err_len;
            hdr->payload_len = htobe32(payload_len);
            hdr->error_msg_len = htobe16(err_len);
            new_size = MaxSize;
        }

        // Apply dynamic LZ4 compression over the raw mutated data 15% of the time
        if ((Seed % 7 == 0) && payload_len > 0) {
            size_t sig_len = (hdr->flags & SCL_RPC_FLAG_SIGNED) ? DILITHIUM_SIGNATURE_LEN : 0;
            if (payload_len > sig_len) {
                size_t uncompressed_len = payload_len - sig_len;
                const uint8_t *src = Data + sizeof(SclRpcHeader) + err_len + sig_len;
                
                int max_dst_size = LZ4_compressBound((int)uncompressed_len);
                static _Thread_local uint8_t *comp_buf = NULL;
                static _Thread_local size_t comp_buf_cap = 0;
                if (comp_buf_cap < (size_t)max_dst_size) {
                    comp_buf = realloc(comp_buf, max_dst_size);
                    comp_buf_cap = max_dst_size;
                }
                if (comp_buf) {
                    int comp_len = LZ4_compress_default((const char *)src, (char *)comp_buf, (int)uncompressed_len, max_dst_size);
                    if (comp_len > 0 && sizeof(SclRpcHeader) + err_len + sig_len + comp_len <= MaxSize) {
                        memcpy(Data + sizeof(SclRpcHeader) + err_len + sig_len, comp_buf, comp_len);
                        payload_len = sig_len + comp_len;
                        hdr->payload_len = htobe32(payload_len);
                        new_size = sizeof(SclRpcHeader) + err_len + payload_len;
                        hdr->flags |= SCL_RPC_FLAG_COMPRESSED;
                    }
                }
            }
        }

        // Auto-recalculate correct checksum on mutated payload
        uint64_t computed = compute_rpc_checksum(Data, err_len, payload_len, dummy_siphash_key);
        hdr->checksum = htobe64(computed);
    }
    return new_size;
}

static void process_single_chunk(State *state, SclConnection *conn, const uint8_t *ptr, size_t chunk_len) {
    // Exercise checksum verification pathway
    scl_rpc_verify_checksum(ptr, chunk_len, dummy_siphash_key);
    
    // Run the main FFI parser
    int status = 0;
    SclRpcParser parser = scl_rpc_parser_create(ptr, chunk_len, &status);
    
    if (parser) {
        scl_rpc_parser_get_version(parser);
        scl_rpc_parser_get_flags(parser);
        scl_rpc_parser_get_status(parser);
        scl_rpc_parser_get_method_id(parser);
        scl_rpc_parser_get_request_id(parser);
        scl_rpc_parser_get_cursor(parser);
        
        char err_buf[256];
        scl_rpc_parser_get_error(parser, err_buf, sizeof(err_buf));
        
        const uint8_t *payload_ptr = NULL;
        size_t payload_len = 0;
        scl_rpc_parser_get_payload_ref(parser, &payload_ptr, &payload_len);
        
        scl_rpc_parser_destroy(parser);
    }

    // Fuzz the FFI Builder interface and convenience endpoints
    if (chunk_len >= 32) {
        SclRpcBuilder builder = scl_rpc_builder_create(SCL_RPC_VERSION_1, ptr[4], 12345);
        if (builder) {
            scl_rpc_builder_set_flags(builder, ptr[1]);
            scl_rpc_builder_set_cursor(builder, ptr[20]);
            scl_rpc_builder_append_args(builder, ptr + 32, chunk_len - 32);
            if (ptr[0] % 2 == 0) {
                scl_rpc_builder_sign(builder, global_fuzz_privkey);
            }
            static _Thread_local uint8_t *builder_out_buf = NULL;
            if (!builder_out_buf) builder_out_buf = malloc(MAX_MESSAGE_SIZE);
            if (builder_out_buf) {
                size_t out_ser_len = 0;
                scl_rpc_builder_finalize(builder, builder_out_buf, MAX_MESSAGE_SIZE, &out_ser_len);
            }
            scl_rpc_builder_destroy(builder);
        }

        uint8_t method = ptr[4] % 12;
        uint8_t frame_buf[16384];
        size_t frame_len = 0;
        switch (method) {
            case 1: scl_rpc_frame_balance_query(123, global_fuzz_pubkey, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 2: scl_rpc_frame_block_query(123, 150, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 4: scl_rpc_frame_audit_query(123, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 5: scl_rpc_frame_valuations_query(123, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 6: scl_rpc_frame_recent_txs(123, 0, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 7: scl_rpc_frame_get_tx(123, global_fuzz_coin_id, COIN_ID_LEN, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 8: scl_rpc_frame_chain_info(123, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 10: scl_rpc_frame_quantum_tvd_audit(123, 15000, NULL, NULL, 0, frame_buf, sizeof(frame_buf), &frame_len); break;
            case 11: scl_rpc_frame_autopilot(123, 1, 5, 50, frame_buf, sizeof(frame_buf), &frame_len); break;
            default: break;
        }
    }

    // Exercise handle_rpc_request directly with the current message chunk
    RpcTask task;
    size_t alloc_size = offsetof(Message, payload) + chunk_len;
    task.msg = malloc(alloc_size);
    if (task.msg) {
        task.msg->type = MSG_RPC_REQUEST;
        task.msg->length = chunk_len;
        memcpy(task.msg->payload, ptr, task.msg->length);
        task.conn = conn;
        memcpy(task.sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

        // Execute the main RPC dispatch handler safely
        handle_rpc_request(state, &task);

        free(task.msg);
    }
}

static State *global_fuzz_state = NULL;
static SclConnection *global_fuzz_conn = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int assertions_verified = 0;
    if (!assertions_verified) {
        // Cross-architecture alignment tests
        assert(sizeof(SclRpcHeader) == 32);
        assert(offsetof(SclRpcHeader, version) == 0);
        assert(offsetof(SclRpcHeader, flags) == 1);
        assert(offsetof(SclRpcHeader, status_code) == 2);
        assert(offsetof(SclRpcHeader, method_id) == 4);
        assert(offsetof(SclRpcHeader, error_msg_len) == 6);
        assert(offsetof(SclRpcHeader, request_id) == 8);
        assert(offsetof(SclRpcHeader, payload_len) == 16);
        assert(offsetof(SclRpcHeader, cursor) == 20);
        assert(offsetof(SclRpcHeader, checksum) == 24);
        assertions_verified = 1;
    }
    
    if (size < 32) return 0; // Minimum requirement: 32-byte header

    if (!global_fuzz_state) {
        global_fuzz_state = calloc(1, sizeof(State));
        if (!global_fuzz_state) return 0;
        init_mock_state_and_populate(global_fuzz_state);
    } else {
        // Fast path: clear only the hash tables mutated during RPC processing
        for (int i = 0; i < MAX_PENDING_OPS; i++) {
            Operation *op = atomic_exchange(&global_fuzz_state->pending_operations[i], NULL);
            if (op) free(op);
        }
        atomic_store(&global_fuzz_state->pending_operations_count, 0);
        
        hash_table_clear(global_fuzz_state->processed_txs);
        hash_table_clear(global_fuzz_state->pubkey_cache);
        if (global_fuzz_state->bc.centinel.nullifier_set) {
            hash_table_clear(global_fuzz_state->bc.centinel.nullifier_set);
        }
        if (global_fuzz_state->bc.centinel.validation_commitments && global_fuzz_state->bc.centinel.validation_commitments->count > 1) {
            mmr_destroy(global_fuzz_state->bc.centinel.validation_commitments);
            mmr_init(global_fuzz_state->bc.centinel.validation_commitments);
            uint8_t comm_hash[COIN_ID_LEN];
            SHA256((const uint8_t*)&global_fuzz_val_utxo.commitment, sizeof(BdlopCommitment), comm_hash);
            mmr_add(global_fuzz_state->bc.centinel.validation_commitments, comm_hash, 0);
        }
        
        // Restore user keys in case SyncWalletKeys mutated them
        memcpy(global_fuzz_state->user_wallet.dilithium_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
        memcpy(global_fuzz_state->user_wallet.dilithium_privkey, global_fuzz_privkey, DILITHIUM_SECRETKEY_LEN);
        memcpy(&global_fuzz_state->user_wallet.prf_key, &global_fuzz_prf_key, sizeof(PRFKey));
        global_fuzz_state->user_wallet.val_utxos[0] = global_fuzz_val_utxo;
        global_fuzz_state->user_wallet.num_val_utxos = 1;
        
        // Restore local peer wallet keys
        memcpy(global_fuzz_state->p2p_network.local_peer.peer_wallet.dilithium_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN);
        memcpy(global_fuzz_state->p2p_network.local_peer.peer_wallet.dilithium_privkey, global_fuzz_privkey, DILITHIUM_SECRETKEY_LEN);

        // Ensure user_table contains global_fuzz_pubkey
        if (global_fuzz_state->user_count > 1 || memcmp(global_fuzz_state->users[0].dilithium_pubkey, global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN) != 0) {
            hash_table_clear(global_fuzz_state->user_table);
            for (size_t i = 0; i < global_fuzz_state->user_count; i++) {
                destroy_user(&global_fuzz_state->users[i]);
            }
            global_fuzz_state->user_count = 0;
            
            uint8_t user_id[USER_ID_LEN];
            SHA256(global_fuzz_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
            register_user(global_fuzz_state, user_id, global_fuzz_pubkey);
        }
        global_fuzz_state->current_block_number = 150;
        global_fuzz_state->sync_received_block_number_value = 0;
        memset(global_fuzz_state->sync_received_block_hash, 0, COIN_ID_LEN);
        global_fuzz_state->blockchain_sync_received_end = 0;
    }

    if (!global_fuzz_conn) {
        global_fuzz_conn = calloc(1, sizeof(SclConnection));
        if (!global_fuzz_conn) return 0;
        atomic_init(&global_fuzz_conn->ref_count, 1);
        pthread_mutex_init(&global_fuzz_conn->l4_mutex, NULL);
        queue_init(&global_fuzz_conn->tx_stream_queue);
        queue_init(&global_fuzz_conn->tx_datagram_queue);
        memcpy(global_fuzz_conn->rpc_siphash_key, dummy_siphash_key, 16);
    } else {
        // Fast path: drain egress queues off-stack to prevent 8MB overflow
        static _Thread_local Message *temp_msg = NULL;
        if (!temp_msg) {
            temp_msg = malloc(sizeof(Message));
        }
        
        if (temp_msg) {
            while (queue_dequeue(&global_fuzz_conn->tx_stream_queue, temp_msg) == 0) {}
            while (queue_dequeue(&global_fuzz_conn->tx_datagram_queue, temp_msg) == 0) {}
        }
        
        memset(global_fuzz_conn->rpc_recent_request_ids, 0, sizeof(global_fuzz_conn->rpc_recent_request_ids));
        global_fuzz_conn->rpc_request_idx = 0;
        global_fuzz_conn->rpc_highest_seen_timestamp = 0;
    }

    State *state = global_fuzz_state;
    SclConnection *conn = global_fuzz_conn;

    atomic_store(&conn->rpc_token_budget, 1000000); // Unlimited token budget for fuzzer
    atomic_store(&conn->last_rpc_token_refill, get_time_ms());
    
    // Pre-warm connection state to established to bypass initial handshake filters
    conn->handshake_state = SCL_CONN_STATE_ESTABLISHED;
    conn->is_handshake_complete = true;

    // Process the entire fuzzer input strictly as a single unified RPC frame
    // This perfectly aligns the data payload with the Custom Mutator's expectations
    process_single_chunk(state, conn, data, size);

    return 0;
}
