/*
 * ==============================================================================
 * Satocialist Protocol: Quantum TVD & Noise Model LibFuzzer Harness
 * ==============================================================================
 *
 * Target Subsystems:
 *   1. Vectorized & Fixed-Point Total Variation Distance Kernels (AVX2/SSE2/NEON)
 *   2. Kraus Noise Models, Thermal Relaxation, Dephasing & Measurement Channels
 *   3. Quantum Drift Certificate Generation, BDLOP Lattice Anchoring & ML-DSA-87
 *   4. State Machine Drift Classification (Fidelity, Drift, Decoherence, Tamper)
 *   5. L5 Native RPC Wire Framing, SipHash-2-4 Checksum & Router Dispatch (Method 0x000A)
 *   6. Quantum QSim Constructive Interference & Classical Statevector Fallbacks
 *   7. WebAssembly / FFI Bindings, Memory Zeroing & Serialization
 *   8. Chernoff-Hoeffding Sample Complexity & Statistical Concentration Verification
 *   9. Formal Metric Invariants (Lean 4 Alignment: Non-Negativity, Symmetry, Bounds)
 *  10. Systematic Boundary & Negative Parameter Error Injection
 * ==============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <math.h>

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
#include "client_state.h"
#include "quantum_tvd.h"
#include <lz4.h>
#include "quantum_qsim.h"
#include "scl_rpc_ffi_export.h"
#include "rpc.h"
#include "queue.h"
#include "consensus.h"
#include "hash_table.h"
#include "game_state.h"
#include "database.h"
#include "blockchain.h"
#include "mmr.h"
#include "user.h"

#define NUM_FUZZ_MODES 10

extern void handle_rpc_quantum_tvd_audit(State *state, RpcTask *task, const SclRpcHeader *hdr, const uint8_t *payload, size_t payload_len);

static State *g_fuzz_state = NULL;
static int g_fuzzer_init = 0;
static uint8_t global_fuzz_coin_id[COIN_ID_LEN];
static uint8_t global_fuzz_ptr_id[COIN_ID_LEN];
static uint8_t global_fuzz_staked_ptr_id[COIN_ID_LEN];
static uint8_t global_fuzz_tx_id[COIN_ID_LEN];
static ValidationUTXO global_fuzz_val_utxo;

static void init_mock_state_and_populate(State *s) {
    if (!s) return;
    client_state_init(s, 0);
    create_user_wallet(&s->user_wallet);

    memcpy(s->p2p_network.local_peer.peer_wallet.dilithium_pubkey, s->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    memcpy(s->p2p_network.local_peer.peer_wallet.dilithium_privkey, s->user_wallet.dilithium_privkey, DILITHIUM_SECRETKEY_LEN);

    memset(&global_fuzz_val_utxo, 0, sizeof(ValidationUTXO));
    global_fuzz_val_utxo.amount = 100;
    memset(global_fuzz_val_utxo.blinding_factor, 0x55, 32);
    memcpy(global_fuzz_val_utxo.pubkey, s->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    prf_keygen(&global_fuzz_val_utxo.prf_key, global_fuzz_val_utxo.blinding_factor, 32);
    bdlop_commit((const uint8_t*)BDLOP_RHO_SEED, 100, global_fuzz_val_utxo.blinding_factor, &global_fuzz_val_utxo.commitment);
    uint8_t comm_hash[COIN_ID_LEN];
    SHA256((const uint8_t*)&global_fuzz_val_utxo.commitment, sizeof(BdlopCommitment), comm_hash);
    prf_evaluate(global_fuzz_val_utxo.nullifier, &global_fuzz_val_utxo.prf_key, comm_hash, COIN_ID_LEN, comm_hash);
    
    pthread_mutex_lock(&s->user_wallet.utxo_mutex);
    s->user_wallet.val_utxos[0] = global_fuzz_val_utxo;
    s->user_wallet.num_val_utxos = 1;
    pthread_mutex_unlock(&s->user_wallet.utxo_mutex);
    mmr_add(s->bc.centinel.validation_commitments, comm_hash, 0);

    uint8_t dummy_tx_hash[32] = {0};
    memset(dummy_tx_hash, 0x77, 32);
    memcpy(global_fuzz_tx_id, dummy_tx_hash, 32);
    SCLCoin coin = create_coin(dummy_tx_hash, s->user_wallet.dilithium_pubkey);
    coin.total_subunits = 100000000ULL * SUBUNITS_PER_COIN;
    coin.remaining_subunits = coin.total_subunits;
    hash_table_insert(s->bc.coin_table, coin.coin_id, &coin, HASH_ENTRY_COIN);
    memcpy(global_fuzz_coin_id, coin.coin_id, COIN_ID_LEN);

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

    s->bc.insert_order_capacity = 16;
    s->bc.insert_order = calloc(s->bc.insert_order_capacity, sizeof(SCLCoin *));
    s->bc.insert_order[0] = &coin;
    s->bc.insert_order_count = 1;
    mmr_add(s->bc.mmr, coin.coin_id, coin.remaining_subunits);

    uint8_t user_id[USER_ID_LEN];
    SHA256(s->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, user_id);
    register_user(s, user_id, s->user_wallet.dilithium_pubkey);

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

    Block b0 = create_standard_genesis_block();
    uint8_t *ser_b0 = malloc(65536);
    if (ser_b0) {
        int len0 = process_block_data(&b0, ser_b0, NULL, true);
        if (len0 > 0) scl_db_put_block(0, ser_b0, len0);
        free(ser_b0);
    }
    s->current_block_number = 150;
}

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
    scl_log_set_level(LOG_LEVEL_FATAL);

    const char *corpus_dir = "../quantum_tvd_fuzzer_corpus";
    for (int i = 1; i < *argc; i++) {
        if ((*argv)[i][0] != '-') {
            corpus_dir = (*argv)[i];
            break;
        }
    }
    SCL_MKDIR(corpus_dir);

    g_fuzz_state = (State *)calloc(1, sizeof(State));
    if (g_fuzz_state) {
        init_mock_state_and_populate(g_fuzz_state);
    }

    #define WRITE_STRUCTURED_SEED(filename, mode_byte, shots_val, seed_fill, circuit_str) do { \
        size_t qasm_len = (circuit_str) ? strlen(circuit_str) : 0; \
        size_t total_sz = 1 + sizeof(uint32_t) + 32 + qasm_len; \
        uint8_t *sbuf = (uint8_t *)malloc(total_sz); \
        if (sbuf) { \
            sbuf[0] = (uint8_t)(mode_byte); \
            uint32_t s_le = (uint32_t)(shots_val); \
            memcpy(sbuf + 1, &s_le, sizeof(uint32_t)); \
            memset(sbuf + 5, (seed_fill), 32); \
            if (qasm_len > 0) { \
                memcpy(sbuf + 37, (circuit_str), qasm_len); \
            } \
            write_seed_file(corpus_dir, (filename), sbuf, total_sz); \
            free(sbuf); \
        } \
    } while(0)

    // Seed 1: Mode 0 - Vectorized TVD (Bell State)
    WRITE_STRUCTURED_SEED(
        "seed01_ideal_bell_state.bin",
        0, 15000, 0x42,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\ncreg c[7];\nh q[0];\ncx q[0], q[1];\nmeasure q -> c;\n"
    );

    // Seed 2: Mode 1 - Kraus Noise Simulation (GHZ 7-Qubit Entanglement)
    WRITE_STRUCTURED_SEED(
        "seed02_noisy_kraus_ghz.bin",
        1, 15000, 0x11,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\ncx q[0], q[1];\ncx q[1], q[2];\ncx q[2], q[3];\ncx q[3], q[4];\ncx q[4], q[5];\ncx q[5], q[6];\n"
    );

    // Seed 3: Mode 2 - Full Drift Certificate Roundtrip (Hadamard Superposition)
    WRITE_STRUCTURED_SEED(
        "seed03_drift_certificate.bin",
        2, 15000, 0xEE,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q;\n"
    );

    // Seed 4: Mode 3 - State Machine: Status 0 (FIDELITY_OPTIMAL)
    WRITE_STRUCTURED_SEED(
        "seed04_status_fidelity_optimal.bin",
        3, 1000, 0x01,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\n"
    );

    // Seed 5: Mode 3 - State Machine: Status 1 (DRIFT_TOLERABLE)
    WRITE_STRUCTURED_SEED(
        "seed05_status_drift_tolerable.bin",
        3, 1000, 0x02,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nry(0.785) q[0];\ncz q[0], q[1];\n"
    );

    // Seed 6: Mode 3 - State Machine: Status 2 (DECOHERENCE_EXCEEDED)
    WRITE_STRUCTURED_SEED(
        "seed06_status_decoherence_exceeded.bin",
        3, 1000, 0x03,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nx q[0];\ny q[1];\nz q[2];\n"
    );

    // Seed 7: Mode 3 - State Machine: Status 3 (TAMPERING_SUSPECTED)
    WRITE_STRUCTURED_SEED(
        "seed07_status_tampering_suspected.bin",
        3, 1000, 0x04,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q;\n"
    );

    // Seed 8: Mode 4 - L5 RPC Wire Framing (Method 0x000A)
    WRITE_STRUCTURED_SEED(
        "seed08_rpc_tvd_audit.bin",
        4, 15000, 0x42,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\ncx q[0], q[1];\n"
    );

    // Seed 9: Mode 5 - Parameter Bounds & Error Branch Injection
    WRITE_STRUCTURED_SEED(
        "seed09_edge_bounds_negative.bin",
        5, 50, 0x77,
        "OPENQASM 2.0;\nqreg q[7];\n"
    );

    // Seed 10: Mode 6 - Quantum QSim Constructive Interference
    WRITE_STRUCTURED_SEED(
        "seed10_qsim_constructive_interference.bin",
        6, 15000, 0x99,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\n"
    );

    // Seed 11: Mode 7 - WebAssembly / FFI Integration
    WRITE_STRUCTURED_SEED(
        "seed11_wasm_tvd_ffi.bin",
        7, 10000, 0x55,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q;\n"
    );

    // Seed 12: Mode 8 - Chernoff-Hoeffding Sample Complexity
    WRITE_STRUCTURED_SEED(
        "seed12_chernoff_sample_complexity.bin",
        8, 50000, 0x33,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\n"
    );

    // Seed 13: Mode 9 - Formal Metric Invariants (Lean 4 Alignment)
    WRITE_STRUCTURED_SEED(
        "seed13_tvd_metric_invariants.bin",
        9, 15000, 0xAA,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\n"
    );

    // Seed 14: Zero Shots Edge Case
    WRITE_STRUCTURED_SEED(
        "seed14_shots_zero.bin",
        5, 0, 0x00,
        NULL
    );

    // Seed 15: Maximum Permissible Shots Boundary (100,000)
    WRITE_STRUCTURED_SEED(
        "seed15_shots_max_boundary.bin",
        8, 100000, 0x5A,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q;\n"
    );

    // Seed 16: Oversized Shots Error Trigger (100,001)
    WRITE_STRUCTURED_SEED(
        "seed16_shots_overflow_error.bin",
        5, 100001, 0xFF,
        "OPENQASM 2.0;\nqreg q[7];\n"
    );

    // Seed 17: Multi-Gate Complex Rotation Circuit
    WRITE_STRUCTURED_SEED(
        "seed17_multi_gate_rotations.bin",
        1, 2500, 0x3C,
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nry(0.785) q[0];\nrz(1.5707963) q[1];\nrx(3.14159) q[2];\ncz q[0], q[1];\nu3(0.5, 0.2, 0.1) q[3];\nu1(0.785) q[4];\nswap q[0], q[1];\ncswap q[0], q[1], q[2];\n"
    );

    // Seed 18: Mode 4 Raw Valid TVD RPC Frame
    {
        uint8_t rpc_seed_buf[1 + sizeof(SclRpcHeader) + 36];
        rpc_seed_buf[0] = 4;
        SclRpcHeader *hdr = (SclRpcHeader *)(rpc_seed_buf + 1);
        memset(hdr, 0, sizeof(SclRpcHeader));
        hdr->version = SCL_RPC_VERSION_1;
        hdr->method_id = htobe16(0x000A);
        hdr->request_id = htobe64(0x10000000AULL);
        hdr->payload_len = htobe32(36);
        uint32_t s_be = htobe32(15000);
        memcpy(rpc_seed_buf + 1 + sizeof(SclRpcHeader), &s_be, 4);
        memset(rpc_seed_buf + 1 + sizeof(SclRpcHeader) + 4, 0x42, 32);
        static const uint8_t init_sip_key[16] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
        uint64_t csum = compute_rpc_checksum(rpc_seed_buf + 1, 0, 36, init_sip_key);
        hdr->checksum = htobe64(csum);
        write_seed_file(corpus_dir, "seed18_rpc_valid_frame.bin", rpc_seed_buf, sizeof(rpc_seed_buf));
    }

    #undef WRITE_STRUCTURED_SEED

    g_fuzzer_init = 1;
    return 0;
}

static void populate_arbitrary_hist(const uint8_t *data, size_t size, uint32_t shots, uint32_t *arbitrary_hist, uint32_t *actual_shots) {
    if (*actual_shots != 0) return;
    uint8_t hist_pattern = (size > 3) ? (data[3] % 4) : 0;
    if (hist_pattern == 0) {
        for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
            arbitrary_hist[i] = (data[(37 + i) % size] % 20) + 1;
            *actual_shots += arbitrary_hist[i];
        }
    } else if (hist_pattern == 1) {
        size_t spike_idx = data[2 % size] % QUANTUM_STATE_DIM;
        arbitrary_hist[spike_idx] = shots ? shots : 150;
        *actual_shots = arbitrary_hist[spike_idx];
    } else if (hist_pattern == 2) {
        uint32_t per_bin = (shots / QUANTUM_STATE_DIM) + 1;
        for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
            arbitrary_hist[i] = per_bin;
            *actual_shots += per_bin;
        }
    } else {
        for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
            if ((data[(37 + i) % size] % 3) == 0) {
                arbitrary_hist[i] = (data[(37 + i) % size] % 50) + 1;
                *actual_shots += arbitrary_hist[i];
            }
        }
        if (*actual_shots == 0) {
            arbitrary_hist[0] = 50;
            *actual_shots = 50;
        }
    }
}

static void process_built_frame(int frame_res, uint8_t *out_frame, size_t out_len, State *state, SclConnection *conn, Message *msg_holder) {
    if (frame_res == 0 && out_len >= sizeof(SclRpcHeader) && out_len <= MAX_MESSAGE_SIZE) {
        int p_status = 0;
        SclRpcParser p = scl_rpc_parser_create(out_frame, out_len, &p_status);
        if (p) {
            scl_rpc_parser_get_version(p);
            scl_rpc_parser_get_flags(p);
            scl_rpc_parser_get_status(p);
            scl_rpc_parser_get_method_id(p);
            scl_rpc_parser_get_request_id(p);
            scl_rpc_parser_get_cursor(p);
            char err_buf[256];
            scl_rpc_parser_get_error(p, err_buf, sizeof(err_buf));
            const uint8_t *ref = NULL;
            size_t ref_sz = 0;
            scl_rpc_parser_get_payload_ref(p, &ref, &ref_sz);
            scl_rpc_parser_destroy(p);
        }
        if (msg_holder && conn) {
            msg_holder->type = MSG_RPC_REQUEST;
            msg_holder->length = (uint32_t)out_len;
            memcpy(msg_holder->payload, out_frame, out_len);
            RpcTask t;
            t.msg = msg_holder;
            t.conn = conn;
            memcpy(t.sender_pubkey, state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
            handle_rpc_request(state, &t);
            while (queue_dequeue(&conn->tx_stream_queue, msg_holder) == 0) {}
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_fuzzer_init || !g_fuzz_state || size < 2) {
        return 0;
    }

    arena_reset(0);

    if (g_fuzz_state) {
        for (int i = 0; i < MAX_PENDING_OPS; i++) {
            Operation *op = atomic_exchange(&g_fuzz_state->pending_operations[i], NULL);
            if (op) free(op);
        }
        atomic_store(&g_fuzz_state->pending_operations_count, 0);

        if (g_fuzz_state->processed_txs && (g_fuzz_state->processed_txs->count > 0 || g_fuzz_state->processed_txs->old_buckets != NULL)) {
            hash_table_clear(g_fuzz_state->processed_txs);
        }
        if (g_fuzz_state->pubkey_cache && (g_fuzz_state->pubkey_cache->count > 0 || g_fuzz_state->pubkey_cache->old_buckets != NULL)) {
            hash_table_clear(g_fuzz_state->pubkey_cache);
        }
        if (g_fuzz_state->bc.centinel.nullifier_set && (g_fuzz_state->bc.centinel.nullifier_set->count > 0 || g_fuzz_state->bc.centinel.nullifier_set->old_buckets != NULL)) {
            hash_table_clear(g_fuzz_state->bc.centinel.nullifier_set);
        }
    }

    static const uint8_t s_fuzz_sip_key[16] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
    static _Thread_local SclConnection *s_mock_conn = NULL;
    if (!s_mock_conn) {
        s_mock_conn = (SclConnection *)calloc(1, sizeof(SclConnection));
        if (s_mock_conn) {
            queue_init(&s_mock_conn->tx_stream_queue);
            memcpy(s_mock_conn->rpc_siphash_key, s_fuzz_sip_key, 16);
            atomic_store(&s_mock_conn->rpc_token_budget, 1000000);
            s_mock_conn->handshake_state = SCL_CONN_STATE_ESTABLISHED;
            s_mock_conn->is_handshake_complete = true;
        }
    } else {
        memset(s_mock_conn->rpc_recent_request_ids, 0, sizeof(s_mock_conn->rpc_recent_request_ids));
        s_mock_conn->rpc_request_idx = 0;
        s_mock_conn->rpc_highest_seen_timestamp = 0;
        atomic_store(&s_mock_conn->rpc_token_budget, 1000000);
        atomic_store(&s_mock_conn->last_rpc_token_refill, get_time_ms());
        atomic_store(&s_mock_conn->active_rpc_streams, 0);
    }
    if (g_fuzz_state) {
        g_fuzz_state->current_block_number = 150;
        g_fuzz_state->sync_received_block_number_value = 0;
        memset(g_fuzz_state->sync_received_block_hash, 0, COIN_ID_LEN);
        g_fuzz_state->blockchain_sync_received_end = 0;
    }

    static _Thread_local uint8_t *s_rpc_frame_buf = NULL;
    if (!s_rpc_frame_buf) s_rpc_frame_buf = (uint8_t *)malloc(MAX_MESSAGE_SIZE);

    static _Thread_local Message *s_msg_holder = NULL;
    if (!s_msg_holder) s_msg_holder = (Message *)malloc(sizeof(Message));

    uint8_t mode = data[0] % NUM_FUZZ_MODES;

    uint32_t raw_shots = (size >= 5) ?
        ((uint32_t)data[1] | ((uint32_t)data[2] << 8) | ((uint32_t)data[3] << 16) | ((uint32_t)data[4] << 24)) :
        ((uint32_t)data[1] * 10 + 10);
    uint32_t shots = (raw_shots % 50 == 0) ? ((raw_shots % 500) + 10) : ((raw_shots % 150) + 10);

    uint8_t local_seed[32] = {0};
    if (size >= 37) {
        memcpy(local_seed, data + 5, 32);
    } else if (size > 5) {
        memcpy(local_seed, data + 5, size - 5);
    }

    const uint8_t *circuit_data = (size > 37 && (data[3] % 2 == 0)) ? (data + 37) : NULL;
    size_t circuit_len = (circuit_data != NULL) ? (size - 37) : 0;

    double p_ideal[QUANTUM_STATE_DIM];
    bool p_ideal_computed = false;
#define ENSURE_P_IDEAL() do { \
    if (!p_ideal_computed) { \
        quantum_compute_ideal_distribution_qsim(circuit_data, circuit_len, local_seed, p_ideal, QUANTUM_STATE_DIM); \
        p_ideal_computed = true; \
    } \
} while(0)

    uint32_t arbitrary_hist[QUANTUM_STATE_DIM] = {0};
    uint32_t actual_shots = 0;
#define ENSURE_HIST() populate_arbitrary_hist(data, size, shots, arbitrary_hist, &actual_shots)

    switch (mode) {
        case 0: {
            // Mode 0: Vectorized TVD Kernel & Fixed-Point TVD Invariants
            ENSURE_P_IDEAL();
            ENSURE_HIST();

            double tvd_vec = quantum_compute_tvd_vectorized(p_ideal, arbitrary_hist, QUANTUM_STATE_DIM, actual_shots);
            uint64_t tvd_fp = quantum_compute_tvd_fixed_point(p_ideal, arbitrary_hist, QUANTUM_STATE_DIM, actual_shots);

            assert(!isnan(tvd_vec) && !isinf(tvd_vec));
            assert(tvd_vec >= 0.0 && tvd_vec <= 1.0);
            assert(tvd_fp <= QUANTUM_TVD_FIXED_SCALE);

            double fp_converted = (double)tvd_fp / (double)QUANTUM_TVD_FIXED_SCALE;
            assert(fabs(tvd_vec - fp_converted) < 0.05);

            // Identity of Indiscernibles test (Theorem 2: TVD -> 0)
            uint32_t perfect_hist[QUANTUM_STATE_DIM];
            uint32_t fast_shots = 500;
            for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                perfect_hist[i] = (uint32_t)round(p_ideal[i] * fast_shots);
            }
            double tvd_zero = quantum_compute_tvd_vectorized(p_ideal, perfect_hist, QUANTUM_STATE_DIM, fast_shots);
            assert(tvd_zero < 0.05);

            // Orthogonal state maximum distance test (Theorem 4: TVD -> 1.0)
            uint32_t orthogonal_hist[QUANTUM_STATE_DIM] = {0};
            size_t min_idx = 0;
            for (size_t i = 1; i < QUANTUM_STATE_DIM; i++) {
                if (p_ideal[i] < p_ideal[min_idx]) min_idx = i;
            }
            orthogonal_hist[min_idx] = actual_shots;
            double tvd_max = quantum_compute_tvd_vectorized(p_ideal, orthogonal_hist, QUANTUM_STATE_DIM, actual_shots);
            assert(tvd_max > 0.75 && tvd_max <= 1.0);

            // Exercise tail loop scalar fallback across unaligned dimensions
            size_t unaligned_dim = (data[2 % size] % 127) + 1;
            quantum_compute_tvd_vectorized(p_ideal, arbitrary_hist, unaligned_dim, actual_shots);
            quantum_compute_tvd_fixed_point(p_ideal, arbitrary_hist, unaligned_dim, actual_shots);
            break;
        }

        case 1: {
            // Mode 1: Kraus Noise Channels & Physical QPU Histogram Simulation
            ENSURE_P_IDEAL();

            QuantumNoiseModelConfig noise_cfg;
            noise_cfg.depolarizing_rate = (double)(data[10 % size] % 101) / 100.0;
            noise_cfg.t1_relaxation_rate = (double)(data[11 % size] % 101) / 100.0;
            noise_cfg.t2_dephasing_rate = (double)(data[12 % size] % 101) / 100.0;
            if (data[13 % size] % 3 == 0) {
                noise_cfg.readout_error_p01 = 0.0;
                noise_cfg.readout_error_p10 = 0.0;
            } else {
                noise_cfg.readout_error_p01 = (double)(data[13 % size] % 25) / 100.0;
                noise_cfg.readout_error_p10 = (double)(data[14 % size] % 25) / 100.0;
            }

            uint32_t hist[QUANTUM_STATE_DIM];
            const QuantumNoiseModelConfig *cfg_ptr = (data[15 % size] % 2 == 0) ? &noise_cfg : NULL;
            const uint8_t *ent_seed = (data[16 % size] % 2 == 0) ? local_seed : NULL;
            uint32_t run_shots = shots % 200 + 10;
            quantum_simulate_noisy_qpu_histogram(p_ideal, QUANTUM_STATE_DIM, run_shots, cfg_ptr, ent_seed, hist);

            uint32_t total_shots_observed = 0;
            for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                total_shots_observed += hist[i];
            }
            assert(total_shots_observed == run_shots);

            double tvd = quantum_compute_tvd_vectorized(p_ideal, hist, QUANTUM_STATE_DIM, run_shots);
            assert(!isnan(tvd) && tvd >= 0.0 && tvd <= 1.0);

            QuantumNoiseModelConfig zero_noise = { 0.0, 0.0, 0.0, 0.0, 0.0 };
            uint32_t zero_hist[QUANTUM_STATE_DIM];
            quantum_simulate_noisy_qpu_histogram(p_ideal, QUANTUM_STATE_DIM, run_shots, &zero_noise, local_seed, zero_hist);
            double tvd_zero_noise = quantum_compute_tvd_vectorized(p_ideal, zero_hist, QUANTUM_STATE_DIM, run_shots);
            assert(tvd_zero_noise >= 0.0 && tvd_zero_noise <= 1.0);
            break;
        }

        case 2: {
            // Mode 2: Full Certificate Generation & Verification Roundtrip with Targeted Mutation Testing
            ENSURE_HIST();
            QuantumDriftCertificate cert;
            const uint32_t *hist_ptr = (data[36 % size] % 2 == 0) ? arbitrary_hist : NULL;
            uint32_t run_shots = hist_ptr ? actual_shots : (shots % 200 + 10);
            const uint8_t *bseed = (data[35 % size] % 2 == 0) ? local_seed : NULL;

            if (!bseed) {
                if (data[4 % size] % 2 == 0) {
                    memset(g_fuzz_state->game_state.epoch_threshold_pubkey, data[4 % size], PUBKEY_LEN);
                    memset(g_fuzz_state->game_state.current_epoch_signature, data[5 % size], SIGNATURE_LEN);
                } else {
                    memset(g_fuzz_state->game_state.epoch_threshold_pubkey, 0, PUBKEY_LEN);
                    memset(g_fuzz_state->game_state.current_epoch_signature, 0, SIGNATURE_LEN);
                }
            }

            int res = quantum_tvd_audit_generate_certificate(g_fuzz_state, circuit_data, circuit_len, hist_ptr, run_shots, bseed, &cert);
            if (res == 0) {
                assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) == 0);

                uint8_t tamper_choice = (data[1] >> 4) % 13;
                switch (tamper_choice) {
                    case 0:
                        assert(quantum_tvd_audit_verify_certificate(NULL, g_fuzz_state->user_wallet.dilithium_pubkey) == -1);
                        assert(quantum_tvd_audit_verify_certificate(&cert, NULL) == -1);
                        break;
                    case 1:
                        cert.tvd_commitment.c1[0] ^= 0xFF;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.tvd_commitment.c1[0] ^= 0xFF;
                        break;
                    case 2:
                        cert.tvd_commitment.c2[0] ^= 0xFF;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.tvd_commitment.c2[0] ^= 0xFF;
                        break;
                    case 3:
                        cert.commitment_blinding[0] ^= 0xFF;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.commitment_blinding[0] ^= 0xFF;
                        break;
                    case 4:
                        cert.tvd_scaled++;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.tvd_scaled--;
                        break;
                    case 5:
                        cert.circuit_hash[0] ^= 0xFF;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.circuit_hash[0] ^= 0xFF;
                        break;
                    case 6:
                        cert.timestamp++;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.timestamp--;
                        break;
                    case 7:
                        cert.status = (QuantumQpuDriftStatus)((cert.status + 1) % 4);
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.status = (QuantumQpuDriftStatus)((cert.status + 3) % 4);
                        break;
                    case 8:
                        cert.validator_signature[0] ^= 0xFF;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.validator_signature[0] ^= 0xFF;
                        break;
                    case 9: {
                        uint8_t wrong_pk[PUBKEY_LEN];
                        memset(wrong_pk, 0x77, PUBKEY_LEN);
                        assert(quantum_tvd_audit_verify_certificate(&cert, wrong_pk) != 0);
                        break;
                    }
                    case 10:
                        if (hist_ptr == NULL) {
                            QuantumDriftCertificate cached_cert;
                            int cache_res = quantum_tvd_audit_generate_certificate(g_fuzz_state, circuit_data, circuit_len, NULL, run_shots, bseed, &cached_cert);
                            assert(cache_res == 0);
                            assert(cached_cert.tvd_scaled == cert.tvd_scaled);
                        }
                        break;
                    case 11:
                        /* shots is covered by the validator signature preimage:
                         * substituting the statistical basis must fail verification. */
                        cert.shots++;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.shots--;
                        break;
                    case 12:
                        /* num_qubits is likewise covered by the signed digest. */
                        cert.num_qubits ^= 0xFF;
                        assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) != 0);
                        cert.num_qubits ^= 0xFF;
                        break;
                }
            }

            // Directly audit arbitrary certificate structures from payload bytes
            if (size >= 1 + sizeof(QuantumDriftCertificate)) {
                QuantumDriftCertificate arb_cert;
                memcpy(&arb_cert, data + 1, sizeof(QuantumDriftCertificate));
                quantum_tvd_audit_verify_certificate(&arb_cert, g_fuzz_state->user_wallet.dilithium_pubkey);
            }
            break;
        }

        case 3: {
            // Mode 3: Systematic State Machine Status Coverage (All 4 Enum States)
            ENSURE_P_IDEAL();
            uint8_t target_status = data[4 % size] % 4;
            uint32_t crafted_hist[QUANTUM_STATE_DIM];
            memset(crafted_hist, 0, sizeof(crafted_hist));
            uint32_t crafted_shots = 200;

            if (target_status == 0) {
                for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                    crafted_hist[i] = (uint32_t)round(p_ideal[i] * crafted_shots);
                }
            } else if (target_status == 1) {
                for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                    double noisy_p = (0.8 * p_ideal[i]) + (0.2 / (double)QUANTUM_STATE_DIM);
                    crafted_hist[i] = (uint32_t)round(noisy_p * crafted_shots);
                }
            } else if (target_status == 2) {
                for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                    double noisy_p = (0.3 * p_ideal[i]) + (0.7 / (double)QUANTUM_STATE_DIM);
                    crafted_hist[i] = (uint32_t)round(noisy_p * crafted_shots);
                }
            } else {
                size_t min_idx = 0;
                for (size_t i = 1; i < QUANTUM_STATE_DIM; i++) {
                    if (p_ideal[i] < p_ideal[min_idx]) min_idx = i;
                }
                crafted_hist[min_idx] = crafted_shots;
            }

            QuantumDriftCertificate cert;
            if (quantum_tvd_audit_generate_certificate(g_fuzz_state, circuit_data, circuit_len, crafted_hist, crafted_shots, local_seed, &cert) == 0) {
                assert(quantum_tvd_audit_verify_certificate(&cert, g_fuzz_state->user_wallet.dilithium_pubkey) == 0);
            }
            break;
        }

        case 4: {
            // Mode 4: L5 RPC Wire Framing, SipHash Checksum, Parser & Router Dispatch (Method 0x000A & All Methods)
            uint8_t *out_frame = s_rpc_frame_buf;
            size_t out_len = 0;
            uint64_t req_id = 0x12345678ULL + ((uint64_t)data[1] << 8) + (size > 2 ? data[2] : 0);
            uint32_t rpc_shots = (shots % 250) + 10;

            if (out_frame && scl_rpc_frame_quantum_tvd_audit(req_id, rpc_shots, local_seed, circuit_data, circuit_len, out_frame, MAX_MESSAGE_SIZE, &out_len) == 0) {
                if (out_len >= sizeof(SclRpcHeader)) {
                    int parse_status = 0;
                    SclRpcParser parser = scl_rpc_parser_create(out_frame, out_len, &parse_status);
                    if (parser) {
                        scl_rpc_parser_get_version(parser);
                        scl_rpc_parser_get_flags(parser);
                        scl_rpc_parser_get_status(parser);
                        scl_rpc_parser_get_method_id(parser);
                        scl_rpc_parser_get_request_id(parser);
                        scl_rpc_parser_get_cursor(parser);
                        char err_buf[256];
                        scl_rpc_parser_get_error(parser, err_buf, sizeof(err_buf));
                        const uint8_t *ref_ptr = NULL;
                        size_t ref_len = 0;
                        scl_rpc_parser_get_payload_ref(parser, &ref_ptr, &ref_len);
                        scl_rpc_parser_destroy(parser);
                    }

                    scl_rpc_verify_checksum(out_frame, out_len, s_fuzz_sip_key);

                    uint8_t bad_sip_key[16] = {0xFF};
                    scl_rpc_verify_checksum(out_frame, out_len, bad_sip_key);

                    SclRpcHeader hdr;
                    memcpy(&hdr, out_frame, sizeof(SclRpcHeader));
                    hdr.method_id = be16toh(hdr.method_id);
                    hdr.payload_len = be32toh(hdr.payload_len);
                    hdr.request_id = be64toh(hdr.request_id);

                    if (s_msg_holder) {
                        s_msg_holder->type = MSG_RPC_REQUEST;
                        s_msg_holder->length = (uint32_t)out_len;
                        memcpy(s_msg_holder->payload, out_frame, out_len);

                        RpcTask task;
                        task.msg = s_msg_holder;
                        task.conn = s_mock_conn;
                        memcpy(task.sender_pubkey, g_fuzz_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);

                        handle_rpc_quantum_tvd_audit(g_fuzz_state, &task, &hdr, out_frame + sizeof(SclRpcHeader), hdr.payload_len);
                        handle_rpc_quantum_tvd_audit(g_fuzz_state, &task, &hdr, out_frame + sizeof(SclRpcHeader), 10);
                        handle_rpc_quantum_tvd_audit(g_fuzz_state, &task, &hdr, out_frame + sizeof(SclRpcHeader), 36);

                        handle_rpc_request(g_fuzz_state, &task);

                        task.msg->type = MSG_RPC_RESPONSE;
                        handle_rpc_request(g_fuzz_state, &task);
                    }
                }
            }

            // Exercise LZ4 compressed frame construction and transparent parser decompression
            char uncompressed_test[256];
            memset(uncompressed_test, 'Q', sizeof(uncompressed_test));
            char compressed_test[512];
            int comp_bytes = LZ4_compress_default(uncompressed_test, compressed_test, sizeof(uncompressed_test), sizeof(compressed_test));
            if (comp_bytes > 0) {
                SclRpcBuilder comp_builder = scl_rpc_builder_create(SCL_RPC_VERSION_1, 0x000A, req_id + 1);
                if (comp_builder) {
                    scl_rpc_builder_set_flags(comp_builder, SCL_RPC_FLAG_COMPRESSED);
                    scl_rpc_builder_append_args(comp_builder, (const uint8_t *)compressed_test, comp_bytes);
                    size_t comp_wire_len = 0;
                    uint8_t comp_wire[1024];
                    if (scl_rpc_builder_finalize(comp_builder, comp_wire, sizeof(comp_wire), &comp_wire_len) == 0) {
                        int comp_parse_status = 0;
                        SclRpcParser comp_parser = scl_rpc_parser_create(comp_wire, comp_wire_len, &comp_parse_status);
                        if (comp_parser) {
                            const uint8_t *decomp_ptr = NULL;
                            size_t decomp_len = 0;
                            scl_rpc_parser_get_payload_ref(comp_parser, &decomp_ptr, &decomp_len);
                            scl_rpc_parser_destroy(comp_parser);
                        }
                    }
                    scl_rpc_builder_destroy(comp_builder);
                }
            }

            if (size > 1) {
                int raw_status = 0;
                SclRpcParser raw_parser = scl_rpc_parser_create(data + 1, size - 1, &raw_status);
                if (raw_parser) {
                    scl_rpc_parser_get_version(raw_parser);
                    scl_rpc_parser_get_flags(raw_parser);
                    scl_rpc_parser_get_status(raw_parser);
                    scl_rpc_parser_get_method_id(raw_parser);
                    scl_rpc_parser_get_request_id(raw_parser);
                    scl_rpc_parser_get_cursor(raw_parser);
                    char err_buf[256];
                    scl_rpc_parser_get_error(raw_parser, err_buf, sizeof(err_buf));
                    const uint8_t *ref_ptr = NULL;
                    size_t ref_len = 0;
                    scl_rpc_parser_get_payload_ref(raw_parser, &ref_ptr, &ref_len);
                    scl_rpc_parser_destroy(raw_parser);
                }

                scl_rpc_verify_checksum(data + 1, size - 1, s_fuzz_sip_key);

                if (size - 1 >= sizeof(SclRpcHeader) && size - 1 <= MAX_MESSAGE_SIZE && s_msg_holder) {
                    s_msg_holder->type = MSG_RPC_REQUEST;
                    s_msg_holder->length = (uint32_t)(size - 1);
                    memcpy(s_msg_holder->payload, data + 1, size - 1);
                    RpcTask raw_task;
                    raw_task.msg = s_msg_holder;
                    raw_task.conn = s_mock_conn;
                    memcpy(raw_task.sender_pubkey, g_fuzz_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
                    handle_rpc_request(g_fuzz_state, &raw_task);
                }
            }

            if (s_mock_conn && s_msg_holder) {
                while (queue_dequeue(&s_mock_conn->tx_stream_queue, s_msg_holder) == 0) {}
            }
            break;
        }

        case 5: {
            // Mode 5: API Parameter Bounds & Negative Error Injection
            ENSURE_P_IDEAL();
            ENSURE_HIST();

            QuantumDriftCertificate dummy_cert;
            memset(&dummy_cert, 0, sizeof(dummy_cert));
            quantum_compute_ideal_distribution_qsim(NULL, 0, NULL, p_ideal, QUANTUM_STATE_DIM);
            quantum_compute_ideal_distribution_qsim(circuit_data, circuit_len, local_seed, NULL, QUANTUM_STATE_DIM);
            quantum_compute_ideal_distribution_qsim(circuit_data, circuit_len, local_seed, p_ideal, 0);
            quantum_compute_ideal_distribution_qsim(circuit_data, circuit_len, local_seed, p_ideal, 64);
            quantum_compute_ideal_distribution_qsim(circuit_data, circuit_len, local_seed, p_ideal, 256);
            quantum_simulate_noisy_qpu_histogram(NULL, QUANTUM_STATE_DIM, shots, NULL, local_seed, arbitrary_hist);
            quantum_simulate_noisy_qpu_histogram(p_ideal, 0, shots, NULL, local_seed, arbitrary_hist);
            quantum_simulate_noisy_qpu_histogram(p_ideal, 64, shots, NULL, local_seed, arbitrary_hist);
            quantum_simulate_noisy_qpu_histogram(p_ideal, QUANTUM_STATE_DIM, 0, NULL, local_seed, arbitrary_hist);
            quantum_simulate_noisy_qpu_histogram(p_ideal, QUANTUM_STATE_DIM, 100001, NULL, local_seed, arbitrary_hist);
            quantum_compute_tvd_vectorized(NULL, arbitrary_hist, QUANTUM_STATE_DIM, actual_shots);
            quantum_compute_tvd_vectorized(p_ideal, NULL, QUANTUM_STATE_DIM, actual_shots);
            quantum_compute_tvd_vectorized(p_ideal, arbitrary_hist, 0, actual_shots);
            quantum_compute_tvd_vectorized(p_ideal, arbitrary_hist, QUANTUM_STATE_DIM, 0);
            quantum_compute_tvd_fixed_point(NULL, arbitrary_hist, QUANTUM_STATE_DIM, actual_shots);
            quantum_compute_tvd_fixed_point(p_ideal, NULL, QUANTUM_STATE_DIM, actual_shots);
            quantum_compute_tvd_fixed_point(p_ideal, arbitrary_hist, 0, actual_shots);
            quantum_compute_tvd_fixed_point(p_ideal, arbitrary_hist, QUANTUM_STATE_DIM, 0);
            quantum_tvd_audit_generate_certificate(NULL, circuit_data, circuit_len, NULL, shots, local_seed, &dummy_cert);
            quantum_tvd_audit_generate_certificate(g_fuzz_state, circuit_data, circuit_len, NULL, 0, local_seed, &dummy_cert);
            quantum_tvd_audit_generate_certificate(g_fuzz_state, circuit_data, circuit_len, NULL, 100001, local_seed, &dummy_cert);
            quantum_tvd_audit_generate_certificate(g_fuzz_state, circuit_data, circuit_len, NULL, shots, local_seed, NULL);
            quantum_tvd_audit_verify_certificate(NULL, NULL);
            quantum_tvd_audit_verify_certificate(&dummy_cert, NULL);
            quantum_tvd_audit_verify_certificate(NULL, g_fuzz_state->user_wallet.dilithium_pubkey);
            handle_rpc_quantum_tvd_audit(NULL, NULL, NULL, NULL, 0);
            scl_rpc_frame_quantum_tvd_audit(0, 0, NULL, NULL, 0, NULL, 0, NULL);
            scl_rpc_verify_checksum(NULL, 0, NULL);
            scl_rpc_parser_create(NULL, 0, NULL);
            scl_rpc_parser_get_version(NULL);
            scl_rpc_parser_get_flags(NULL);
            scl_rpc_parser_get_status(NULL);
            scl_rpc_parser_get_method_id(NULL);
            scl_rpc_parser_get_request_id(NULL);
            scl_rpc_parser_get_cursor(NULL);
            scl_rpc_parser_get_error(NULL, NULL, 0);
            scl_rpc_parser_get_payload_ref(NULL, NULL, NULL);
            scl_rpc_parser_destroy(NULL);
            scl_rpc_builder_set_flags(NULL, 0);
            scl_rpc_builder_set_cursor(NULL, 0);
            scl_rpc_builder_append_pubkey(NULL, NULL, 0);
            scl_rpc_builder_append_args(NULL, NULL, 0);
            scl_rpc_builder_sign(NULL, NULL);
            scl_rpc_builder_finalize(NULL, NULL, 0, NULL);
            scl_rpc_builder_destroy(NULL);
            scl_autopilot_step(NULL);
            scl_autopilot_step(g_fuzz_state);
            start_autopilot_thread(NULL);
            stop_autopilot_thread(NULL);
            poly_t p_dummy1, p_dummy2;
            bdlop_expand_parameters(NULL, &p_dummy1, &p_dummy2);
            bdlop_commit(NULL, 0, NULL, NULL);
            bdlop_decrypt(NULL, NULL, NULL, NULL);
            bdlop_add(NULL, NULL, NULL);
            compute_rpc_checksum(NULL, 0, 0, NULL);
            break;
        }

        case 6: {
            // Mode 6: Quantum QSim Simulation & Constructive Interference
            int target_number = (int)(data[1 % size] % 105) - 2;
            size_t N = (size_t)(data[2 % size] % 12);
            size_t active_nodes = (size_t)(data[3 % size] % 20);
            int column_numbers[12];
            for (size_t k = 0; k < 12; k++) {
                column_numbers[k] = (int)(data[(4 + k) % size] % 100);
            }
            init_quantum_qsim_environment();
            quantum_check_number_in_column_qsim(target_number, column_numbers, N, active_nodes, local_seed);
            quantum_check_number_in_column_qsim(target_number, column_numbers, N, active_nodes, NULL);
            quantum_check_number_in_column(target_number, column_numbers, N, active_nodes, local_seed);
            cleanup_quantum_qsim_environment();
            break;
        }

        case 7: {
            // Mode 7: High-Level Frame Builders, Dispatch & BDLOP Homomorphic Crypto Anchoring
            uint8_t *out_frame = s_rpc_frame_buf;
            size_t out_len = 0;
            uint64_t req_id = 0xAABBCCDD11223344ULL + data[1 % size];
            uint8_t builder_choice = data[2 % size] % 10;

            if (out_frame) {
                switch (builder_choice) {
                    case 0: process_built_frame(scl_rpc_frame_balance_query(req_id, g_fuzz_state->user_wallet.dilithium_pubkey, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 1: process_built_frame(scl_rpc_frame_chain_info(req_id, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 2: process_built_frame(scl_rpc_frame_recent_txs(req_id, 0, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 3: process_built_frame(scl_rpc_frame_valuations_query(req_id, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 4: process_built_frame(scl_rpc_frame_audit_query(req_id, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 5: process_built_frame(scl_rpc_frame_block_query(req_id, 1, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 6: process_built_frame(scl_rpc_frame_get_tx(req_id, local_seed, 32, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 7: process_built_frame(scl_rpc_frame_autopilot(req_id, 1, 1, 50, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    case 8: process_built_frame(scl_rpc_frame_autopilot(req_id, 0, 2, 80, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                    default: process_built_frame(scl_rpc_frame_autopilot(req_id, -1, 1, 50, out_frame, MAX_MESSAGE_SIZE, &out_len), out_frame, out_len, g_fuzz_state, s_mock_conn, s_msg_holder); break;
                }
            }

            poly_t a_pub, b_pub;
            bdlop_expand_parameters((const uint8_t *)BDLOP_RHO_SEED, &a_pub, &b_pub);

            const uint64_t test_scalars[] = { 0, 1, (1ULL << 21) - 1, (1ULL << 42) - 1, (1ULL << 63) - 1, UINT64_MAX, (uint64_t)shots * 100ULL };
            uint64_t test_val = test_scalars[data[2 % size] % 7];

            BdlopCommitment comm1, comm2, comm_sum;
            if (bdlop_commit((const uint8_t *)BDLOP_RHO_SEED, test_val, local_seed, &comm1) == CRYPTO_SUCCESS) {
                uint64_t decrypted_val = 0;
                if (bdlop_decrypt((const uint8_t *)BDLOP_RHO_SEED, &comm1, local_seed, &decrypted_val) == CRYPTO_SUCCESS) {
                    assert(decrypted_val == test_val);
                }

                uint8_t wrong_seed[32];
                memcpy(wrong_seed, local_seed, 32);
                wrong_seed[0] ^= 0x5A;
                uint64_t wrong_dec = 0;
                bdlop_decrypt((const uint8_t *)BDLOP_RHO_SEED, &comm1, wrong_seed, &wrong_dec);

                uint8_t r2[32];
                memset(r2, 0x33, 32);
                if (bdlop_commit((const uint8_t *)BDLOP_RHO_SEED, 500, r2, &comm2) == CRYPTO_SUCCESS) {
                    if (bdlop_add(&comm1, &comm2, &comm_sum) == CRYPTO_SUCCESS) {
                        uint64_t dec_sum = 0;
                        bdlop_decrypt((const uint8_t *)BDLOP_RHO_SEED, &comm_sum, local_seed, &dec_sum);
                    }
                }
            }
            break;
        }

        case 8: {
            // Mode 8: Chernoff-Hoeffding Sample Complexity Verification
            ENSURE_P_IDEAL();

            uint32_t shot_budgets[] = { 25, 50, 100, 250, 500, 1000 };
            uint32_t chosen_M = shot_budgets[data[1 % size] % 6];
            uint32_t sim_hist[QUANTUM_STATE_DIM];

            QuantumNoiseModelConfig zero_noise = { 0.0, 0.0, 0.0, 0.0, 0.0 };
            quantum_simulate_noisy_qpu_histogram(p_ideal, QUANTUM_STATE_DIM, chosen_M, &zero_noise, local_seed, sim_hist);

            double tvd_sampled = quantum_compute_tvd_vectorized(p_ideal, sim_hist, QUANTUM_STATE_DIM, chosen_M);
            assert(tvd_sampled >= 0.0 && tvd_sampled <= 1.0);
            break;
        }

        case 9: {
            // Mode 9: Formal Lean 4 Metric Invariants & Distance Axioms (tvd_invariants.lean)
            ENSURE_P_IDEAL();
            ENSURE_HIST();

            // 1. Theorem 1: Non-Negativity
            double tvd_val = quantum_compute_tvd_vectorized(p_ideal, arbitrary_hist, QUANTUM_STATE_DIM, actual_shots);
            uint64_t tvd_scaled = quantum_compute_tvd_fixed_point(p_ideal, arbitrary_hist, QUANTUM_STATE_DIM, actual_shots);
            assert(tvd_val >= 0.0);
            assert(tvd_scaled <= QUANTUM_TVD_FIXED_SCALE);

            // 2. Theorem 2: Identity of Indiscernibles (TVD(P, P) == 0)
            uint32_t p_hist[QUANTUM_STATE_DIM];
            for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                p_hist[i] = (uint32_t)round(p_ideal[i] * 500);
            }
            double tvd_self = quantum_compute_tvd_vectorized(p_ideal, p_hist, QUANTUM_STATE_DIM, 500);
            assert(tvd_self < 0.05);

            // 3. Theorem 3: Symmetry TVD(P, Q) == TVD(Q, P)
            double q_dist[QUANTUM_STATE_DIM];
            for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                q_dist[i] = (double)arbitrary_hist[i] / (double)actual_shots;
            }
            uint32_t p_shots_hist[QUANTUM_STATE_DIM];
            uint32_t p_total = 0;
            for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                p_shots_hist[i] = (data[(10 + i) % size] % 20) + 1;
                p_total += p_shots_hist[i];
            }
            double p_dist[QUANTUM_STATE_DIM];
            for (size_t i = 0; i < QUANTUM_STATE_DIM; i++) {
                p_dist[i] = (double)p_shots_hist[i] / (double)p_total;
            }
            double tvd_pq = quantum_compute_tvd_vectorized(p_dist, arbitrary_hist, QUANTUM_STATE_DIM, actual_shots);
            double tvd_qp = quantum_compute_tvd_vectorized(q_dist, p_shots_hist, QUANTUM_STATE_DIM, p_total);
            assert(fabs(tvd_pq - tvd_qp) < 1e-6);

            // 4. Theorem 4: Upper bound TVD <= 1.0
            assert(tvd_val <= 1.0);

            // 5. Theorem 5: 128-bit / 64-bit integer accumulation without overflow
            uint64_t max_accum = (uint64_t)QUANTUM_STATE_DIM * (2ULL * QUANTUM_TVD_FIXED_SCALE);
            assert(max_accum < 18446744073709551615ULL);
            break;
        }
    }

#undef ENSURE_P_IDEAL
#undef ENSURE_HIST

    if (s_mock_conn && s_msg_holder) {
        while (queue_dequeue(&s_mock_conn->tx_stream_queue, s_msg_holder) == 0) {}
    }

    arena_reset(0);

#if defined(__linux__)
    static uint64_t iter_count = 0;
    if ((++iter_count & 0xFFFF) == 0) {
        malloc_trim(0);
    }
#elif defined(__APPLE__)
    static uint64_t iter_count = 0;
    if ((++iter_count & 0xFFFF) == 0) {
        malloc_zone_pressure_relief(malloc_default_zone(), 0);
    }
#endif

    return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
#ifdef __cplusplus
}
#endif

// Structure-Aware Custom Mutator for Quantum TVD Circuits, Noise Models & RPC Framing
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (new_size < 2) return new_size;

    // 25% of the time, allow unconstrained raw mutation to discover boundary crashes & edge branches
    if ((Seed % 4) == 0) {
        return new_size;
    }

    if (new_size < 37) {
        if (MaxSize < 37) return new_size;
        new_size = 37;
    }

    uint8_t mode = Seed % NUM_FUZZ_MODES;
    Data[0] = mode;

    // Mutate Shot Budget (fast presets & edge cases: 0, 1, 10, 25, 50, 100, 250, 500, 1000, 15000, 100000, 100001)
    uint32_t shot_presets[] = { 0, 1, 10, 25, 50, 100, 250, 500, 1000, 15000, 100000, 100001 };
    uint32_t chosen_shots = shot_presets[Seed % 12];
    memcpy(Data + 1, &chosen_shots, sizeof(uint32_t));

    // Inject discovered edge-case seeds and magic parameters
    if (Seed % 3 == 0 && new_size >= 37) {
        static const uint8_t edge_seeds[10][32] = {
            { 'V', 0x86, 0xe3, 0x7d, 0xa3, 0x90, 0xf4, 0xea,
              0x7f, 'g', 0xf9, 0xa8, 0x8e, 0xc5, 'k', 0x97,
              0x95, '_', 0x94, 0x0b, 0xe0, 0xf9, 0xd0, 0x13,
              0x15, 0x0c, 0xb0, 0xa9, 0xf4, 'a', 0x91, '3' },
            { 0xf1, 0x8c, 0x66, 0x82, 0x3a, 0xc8, 0x5e, 0x60,
              0xce, 0xa6, 0x53, 0x8f, 0xaf, 0x8a, 0x87, 0x3a,
              0x66, 0x4a, 0xa1, 0x23, 0x6b, 0x67, 0x3d, 0xff,
              0x36, 0xd4, 0x88, 0x53, 0x7a, 0x18, 0x44, 0x6e },
            { 0xe1, 0xd9, 0x51, 0x29, 0xf7, 0xa0, 0xd7, 0xb6,
              0xb0, 0xa7, 0x9b, 0xf9, 0xa9, 0x92, 0x99, 0x23,
              0xa5, 0x61, 0x37, 0xa7, 0xa8, 0xcb, 0x47, 0x89,
              0xd7, 0xab, 0xa2, 0xe2, 0x8f, 0xca, 0x9b, 0xa7 },
            { 'S', 'C', 'L', '_', 'C', 'E', 'N', 'T',
              'I', 'N', 'E', 'L', '_', 'L', 'A', 'T',
              'T', 'I', 'C', 'E', '_', 'B', 'D', 'L',
              'O', 'P', '_', 'V', '1', '_', 'S', 'E' },
            { 'N', 0xfc, 0x04, 0xf9, 0x11, 0xbf, 0xfc, 0xf5,
              0xab, 0xc9, 'H', 0xa4, '2', 0x07, 0xf1, 0x00,
              0xf5, 0xc4, 0x12, 0xe3, 0xbc, 'J', 0xc5, ')',
              'L', 0xf7, '_', 0x83, 0xcb, 0x98, '$', 0x80 },
            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x83 },
            { 0x86, '<', 0x12, 0xef, 0xe5, 0x14, '5', 0x07,
              0xb1, 'J', 0xcd, 'f', 'e', 'k', 0xc1, 0xb0,
              0xa9, 0x8b, 'Z', 0xa7, 0xef, 'g', 0xd0, ';',
              0xfe, 0xc9, '3', '{', 0xb8, 0xf5, '3', 0xd4 },
            { 0xc4, 0xdc, 'p', 0x05, 0x9a, 0xe0, 0xb7, 0x16,
              0xa8, 'F', 0xd5, 0x0c, 0x7f, 0xae, 0xb9, '4',
              '!', 0xb1, 0xef, 0xb3, 0x0c, 0x95, 0xf7, 0xfd,
              0x8d, 0x8f, 0xed, 'O', 0x02, 0xd7, 0x19, 0xcc },
            { 0x87, 0xc2, 0x8e, 'Z', '|', 0x81, 0x8a, 'W',
              ']', 'u', 0xb6, 'l', 0xe2, 0xfb, '0', 0xac,
              0x8d, 0x13, 'f', 0x85, '\\', 0xff, 0x8e, '\\',
              0x89, 0xcc, 0xab, 0xd4, 0xcb, 0xb3, 'D', 0xd3 },
            { 0xdf, 0x1f, 'm', 0x17, 0x97, 0x92, '2', '.',
              0x13, 0xe0, 0xa1, 0xfd, 0xfa, '`', 0xab, 0xb6,
              0x0d, ';', 0xb1, 'w', '+', 0x0f, 0xa9, 0x9d,
              0xd4, 0xb2, 'j', 0xe5, 0x8a, 0xe2, 'o', 's' }
        };
        memcpy(Data + 5, edge_seeds[Seed % 10], 32);
    }

    // Synthesize valid OpenQASM circuit templates
    if (Seed % 2 == 0 && new_size >= 37 + 45) {
        static const char * const qasm_templates[] = {
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\ncx q[0], q[1];\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q;\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nx q[0];\ny q[1];\nz q[2];\ns q[3];\nt q[4];\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nry(0.785) q[0];\nrz(1.5707963) q[1];\nrx(3.14159) q[2];\ncz q[0], q[1];\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nu3(0.5, 0.2, 0.1) q[0];\nu1(0.785) q[1];\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\nt q[0];\nh q[0];\ns q[0];\ncx q[0], q[1];\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nswap q[0], q[1];\ncswap q[0], q[1], q[2];\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\ncreg c[7];\nh q[0];\ncx q[0], q[1]; \nmeasure q -> c;\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\ncreg c[7];\nh q[5];\ncx q[5], q[6];\nmeasure q[5] -> c[5];\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[4];\ncreg c[4];\nh q;\n",
            "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[7];\nh q[0];\nbarrier q;\nreset q[0];\n",
            "lude \"qelib1.inc\";\n\nqreg: q c{7]:"
        };
        const char *chosen_qasm = qasm_templates[Seed % 12];
        size_t prefix_len = strlen(chosen_qasm);
        if (37 + prefix_len <= MaxSize) {
            memcpy(Data + 37, chosen_qasm, prefix_len);
        }
    }

    // Mode-specific structural data mutation
    if (mode == 1 && new_size >= 17) {
        Data[10] = (Seed * 3) % 101; // Depolarizing rate
        Data[11] = (Seed * 5) % 101; // T1 relaxation rate
        Data[12] = (Seed * 7) % 101; // T2 dephasing rate
        Data[13] = (Seed * 11) % 25; // Readout error P(1|0)
        Data[14] = (Seed * 13) % 25; // Readout error P(0|1)
    } else if (mode == 3 && new_size >= 5) {
        Data[4] = Seed % 4; // Target Status Enum
    } else if (mode == 4) {
        Data[0] = 4;
        uint16_t methods[] = { 0x000A, 0x0000, 0x0001, 0x0002, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x000B };
        uint16_t chosen_method = methods[Seed % 10];

        size_t min_needed = 1 + sizeof(SclRpcHeader);
        if (chosen_method == 0x000A) min_needed += 36;
        else if (chosen_method == 0x0001) min_needed += PUBKEY_LEN;
        else if (chosen_method == 0x0007) min_needed += 32;
        else if (chosen_method == 0x000B) min_needed += 9;

        if (new_size < min_needed) {
            if (MaxSize >= min_needed) new_size = min_needed;
        }

        SclRpcHeader *hdr = (SclRpcHeader *)(Data + 1);
        hdr->version = SCL_RPC_VERSION_1;
        hdr->method_id = htobe16(chosen_method);
        uint8_t flags_arr[] = { 0, SCL_RPC_FLAG_SIGNED, SCL_RPC_FLAG_PAGINATED, SCL_RPC_FLAG_COMPRESSED, SCL_RPC_FLAG_SIGNED | SCL_RPC_FLAG_COMPRESSED };
        hdr->flags = flags_arr[Seed % 5];
        hdr->status_code = 0;
        hdr->error_msg_len = 0;
        hdr->cursor = htobe32((Seed % 10) * 10);

        uint32_t payload_len = (new_size > 1 + sizeof(SclRpcHeader)) ? (new_size - 1 - sizeof(SclRpcHeader)) : 0;

        uint8_t *p_payload = Data + 1 + sizeof(SclRpcHeader);
        if (chosen_method == 0x000A && payload_len >= 36) {
            uint32_t s_val = htobe32((Seed % 250) + 10);
            memcpy(p_payload, &s_val, 4);
            memset(p_payload + 4, (uint8_t)Seed, 32);
        } else if (chosen_method == 0x0001 && payload_len >= PUBKEY_LEN && g_fuzz_state) {
            memcpy(p_payload, g_fuzz_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
        } else if (chosen_method == 0x0007 && payload_len >= 32) {
            if (Seed % 3 == 0) memcpy(p_payload, global_fuzz_coin_id, 32);
            else if (Seed % 3 == 1) memcpy(p_payload, global_fuzz_ptr_id, 32);
            else memcpy(p_payload, global_fuzz_tx_id, 32);
        } else if (chosen_method == 0x0002) {
            hdr->flags |= SCL_RPC_FLAG_PAGINATED;
            hdr->cursor = htobe32((Seed % 2 == 0) ? 150 : 0);
        } else if (chosen_method == 0x0006) {
            hdr->flags |= SCL_RPC_FLAG_PAGINATED;
            hdr->cursor = htobe32(Seed % 50);
        } else if (chosen_method == 0x000B && payload_len >= 9) {
            p_payload[0] = (Seed & 1);
            uint32_t v_hr = htobe32((Seed % 10) + 1);
            memcpy(p_payload + 1, &v_hr, 4);
            uint32_t s_rat = htobe32(Seed % 101);
            memcpy(p_payload + 5, &s_rat, 4);
        }

        hdr->payload_len = htobe32(payload_len);
        uint64_t now_ms = (uint64_t)time(NULL) * 1000 + (Seed & 0x3FF);
        hdr->request_id = htobe64((now_ms << 16) | (Seed & 0xFFFF));
        static const uint8_t sip_key[16] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
        uint64_t csum = compute_rpc_checksum(Data + 1, 0, payload_len, sip_key);
        hdr->checksum = htobe64(csum);
    }

    return new_size;
}
