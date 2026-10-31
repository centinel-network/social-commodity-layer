/*
 * ==============================================================================
 * Satocialist Protocol: L1 Handshake & Transport Reassembly Fuzzer
 * ==============================================================================
 *
 * Target: extract_l5_message(), process_spsc_queue(), and L0/L1 multiplexer
 * Objective: Feed fragmented, out-of-order, and heavily mutated QUIC-Parity
 *            binary payloads into the network receiver to stress-test:
 *            1. OOO_Message linked-list bounds & Head-of-Line blocking
 *            2. 160MB SclHandshakeSlot reassembly slab limits
 *            3. GF(2^8) Reed-Solomon FEC parity decoding
 *            4. BBRv3 adaptive bandwidth pacing tracking
 * ==============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#if defined(__linux__)
#include <malloc.h>
#elif defined(__APPLE__)
#include <malloc/malloc.h>
#endif

#include "scl_rpc_ffi_export.h"
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
#include "queue.h"
#include "database.h"

// Externs for background engine orchestration
extern State *global_state;
extern struct SclTransportShim *global_shim;

static int fuzzer_initialized = 0;
static SclConnection *fuzz_conn = NULL;
static SclConnection *listener_conn = NULL;
static struct sockaddr_in fuzz_addr;
static uint8_t fuzz_cid[SCL_CID_LEN];
static uint8_t zero_cid[SCL_CID_LEN] = {0};
static uint8_t expected_flight3_key[32];
static uint8_t fuzz_user_id[USER_ID_LEN];
static uint32_t fuzz_idx_ip = 0;
static uint32_t fuzz_idx_sub = 0;

static const uint8_t dummy_aes_key[32] = {
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};

// Synchronous dispatch override for libFuzzer coverage tracking
void crypto_verify_enqueue(State *state, SclConnection *conn, const Message *msg, const uint8_t *sender_pubkey, const struct sockaddr_in *sender_addr) {
    static _Thread_local Message *out_msg = NULL;
    if (!out_msg) out_msg = malloc(sizeof(Message));
    dispatch_l5_message(conn, state, &state->p2p_network, (Message*)msg, out_msg, (uint8_t*)sender_pubkey, (struct sockaddr_in*)sender_addr);
}

// Seed corpus generation utility to jumpstart path discovery
static inline void queue_flush_fast(Queue *q) {
    if (!q) return;
    pthread_mutex_lock(&q->mutex);
    QueueNode *node = q->head;
    while (node) {
        QueueNode *next = node->next;
        if (node->msg) free(node->msg);
        free(node);
        node = next;
    }
    q->head = NULL;
    q->tail = NULL;
    pthread_mutex_unlock(&q->mutex);
}

static inline void ooo_cleanup_conn(SclConnection *conn, UserSpaceState *us_state) {
    if (!conn) return;
    if (conn->ooo_buffer_head) {
        OOO_Message *ooo = (OOO_Message *)conn->ooo_buffer_head;
        while (ooo) {
            OOO_Message *next = ooo->next;
            if (ooo->parity_slab) {
                SCL_ALIGNED_FREE(ooo->parity_slab);
            }
            if (us_state) {
                size_t exp_size = SCL_HEADER_MIN_LEN + 12 + (ooo->total_frags * SCL_MAX_CHUNK_SIZE);
                atomic_fetch_sub_explicit(&us_state->global_ooo_bytes_allocated, sizeof(OOO_Message) + exp_size, memory_order_relaxed);
            }
            free(ooo);
            ooo = next;
        }
        conn->ooo_buffer_head = NULL;
        conn->ooo_bytes_allocated = 0;
    }

    if (conn->active_fragment_buffer) {
        free(conn->active_fragment_buffer);
        conn->active_fragment_buffer = NULL;
    }
    if (conn->active_fec_parity[0]) {
        free(conn->active_fec_parity[0]);
        conn->active_fec_parity[0] = NULL;
    }
    if (conn->active_fec_parity[1]) {
        free(conn->active_fec_parity[1]);
        conn->active_fec_parity[1] = NULL;
    }
}

static inline void unacked_cleanup_conn(SclConnection *conn) {
    if (!conn) return;
    pthread_mutex_lock(&conn->l4_mutex);
    SclUnackedPacket *unacked = conn->unacked_head;
    while (unacked) {
        SclUnackedPacket *next = unacked->next;
        if (unacked->raw_packet) free(unacked->raw_packet);
        free(unacked);
        unacked = next;
    }
    conn->unacked_head = NULL;
    conn->unacked_tail = NULL;
    conn->bytes_in_flight = 0;
    pthread_mutex_unlock(&conn->l4_mutex);
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
    // Mute IO for fuzzing speed
    scl_log_set_level(LOG_LEVEL_FATAL);

    const char *corpus_dir = "../network_fuzzer_corpus";
    for (int i = 1; i < *argc; i++) {
        if ((*argv)[i][0] != '-') {
            corpus_dir = (*argv)[i];
            break;
        }
    }
    mkdir(corpus_dir, 0777);

    // Initialize Global Node State
    global_state = calloc(1, sizeof(State));
    if (!global_state) return 0;
    client_state_init(global_state, 0);

    // Bootstrap local wallets to satisfy internal validations
    create_user_wallet(&global_state->user_wallet);
    memcpy(global_state->p2p_network.local_peer.peer_wallet.dilithium_pubkey,
           global_state->user_wallet.dilithium_pubkey, PUBKEY_LEN);
    memcpy(global_state->p2p_network.local_peer.peer_wallet.dilithium_privkey,
           global_state->user_wallet.dilithium_privkey, PRIVKEY_LEN);

    SHA256(global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN, fuzz_user_id);

    // Initialize UserSpace L0/L1 Shim
    global_shim = scl_userspace_shim_create("127.0.0.1", 5555);
    if (!global_shim) return 0;

    // Synchronous execution mode for deterministic, high-throughput fuzzing

    // Pre-allocate and strictly pin the target Fuzz Connection
    memset(fuzz_cid, 0x42, SCL_CID_LEN);
    fuzz_addr.sin_family = AF_INET;
    fuzz_addr.sin_port = htons(12345);
    fuzz_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    fuzz_conn = calloc(1, sizeof(SclConnection));
    if (!fuzz_conn) return 0;

    atomic_init(&fuzz_conn->ref_count, 100); // Elevate to prevent GC sweeps during fuzz iteration
    atomic_init(&fuzz_conn->is_processing, false);
    
    fuzz_conn->l5_rx_queue.buffer = malloc(SCL_L5_RING_SIZE * sizeof(uint8_t*));
    fuzz_conn->l5_rx_queue.lengths = malloc(SCL_L5_RING_SIZE * sizeof(size_t));
    fuzz_conn->l5_rx_queue.addrs = malloc(SCL_L5_RING_SIZE * sizeof(struct sockaddr_in));
    fuzz_conn->l5_rx_queue.rx_times = malloc(SCL_L5_RING_SIZE * sizeof(uint64_t));
    for (int i = 0; i < SCL_L5_RING_SIZE; i++) {
        fuzz_conn->l5_rx_queue.buffer[i] = malloc(4096);
    }
    atomic_init(&fuzz_conn->l5_rx_queue.head, 0);
    atomic_init(&fuzz_conn->l5_rx_queue.tail, 0);

    pthread_mutex_init(&fuzz_conn->l4_mutex, NULL);
    queue_init(&fuzz_conn->tx_datagram_queue);
    queue_init(&fuzz_conn->tx_stream_queue);

    memcpy(fuzz_conn->cid, fuzz_cid, SCL_CID_LEN);
    memset(fuzz_conn->rpc_siphash_key, 0x42, 16);
    fuzz_conn->current_path = fuzz_addr;
    fuzz_conn->path_mtu = 1280 - 48;
    fuzz_conn->tx_max_data = SCL_FLOW_WINDOW_SIZE;
    fuzz_conn->rx_max_data = SCL_FLOW_WINDOW_SIZE;
    fuzz_conn->dynamic_replay_window_size = SCL_MIN_REPLAY_WINDOW;

    // Derive expected Flight 3 AEAD key once for all iterations
    uint8_t zero_ss[32] = {0};
    derive_labeled_key(zero_ss, "SCL flight3 key", expected_flight3_key, 32);

    // Pre-allocate and register listener connection (zero_cid) for Long Header / Handshake processing
    listener_conn = calloc(1, sizeof(SclConnection));
    if (!listener_conn) return 0;
    atomic_init(&listener_conn->ref_count, 100);
    atomic_init(&listener_conn->is_processing, false);
    listener_conn->l5_rx_queue.buffer = malloc(SCL_L5_RING_SIZE * sizeof(uint8_t*));
    listener_conn->l5_rx_queue.lengths = malloc(SCL_L5_RING_SIZE * sizeof(size_t));
    listener_conn->l5_rx_queue.addrs = malloc(SCL_L5_RING_SIZE * sizeof(struct sockaddr_in));
    listener_conn->l5_rx_queue.rx_times = malloc(SCL_L5_RING_SIZE * sizeof(uint64_t));
    for (int i = 0; i < SCL_L5_RING_SIZE; i++) {
        listener_conn->l5_rx_queue.buffer[i] = malloc(4096);
    }
    atomic_init(&listener_conn->l5_rx_queue.head, 0);
    atomic_init(&listener_conn->l5_rx_queue.tail, 0);
    pthread_mutex_init(&listener_conn->l4_mutex, NULL);
    queue_init(&listener_conn->tx_datagram_queue);
    queue_init(&listener_conn->tx_stream_queue);
    listener_conn->current_path = fuzz_addr;
    listener_conn->path_mtu = 1280 - 48;
    memcpy(listener_conn->rpc_siphash_key, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);

    // Register into the global shim routing table so L5 picks it up
    global_shim->register_connection(global_shim, fuzz_cid, fuzz_conn);
    global_shim->register_connection(global_shim, zero_cid, listener_conn);

    uint8_t remote_pubkey[DILITHIUM_PUBKEY_LEN];
    memset(remote_pubkey, 0xEE, DILITHIUM_PUBKEY_LEN);
    uint8_t remote_kyber[KYBER_PUBKEY_LEN];
    memset(remote_kyber, 0xEE, KYBER_PUBKEY_LEN);
    p2p_add_peer(&global_state->p2p_network, remote_pubkey, remote_kyber, &fuzz_addr);
    for (size_t i = 0; i < global_state->p2p_network.num_known_peers; i++) {
        if (global_state->p2p_network.known_peers[i]->addr.sin_port == fuzz_addr.sin_port) {
            global_state->p2p_network.known_peers[i]->conn = fuzz_conn;
            break;
        }
    }

    UserSpaceState *us_state_init = (UserSpaceState *)global_shim->impl_state;
    uint8_t ip_k[16], sub_k[16];
    ip4_to_16(fuzz_addr.sin_addr.s_addr, ip_k);
    ip4_to_16(fuzz_addr.sin_addr.s_addr & 0xFFFFFF00, sub_k);
    fuzz_idx_ip = (uint32_t)siphash24(ip_k, 16, us_state_init->node_secret) % SCL_DOS_TRACKER_SIZE;
    fuzz_idx_sub = (uint32_t)siphash24(sub_k, 16, us_state_init->node_secret) % SCL_DOS_TRACKER_SIZE;

    // Helper to construct correctly packed chunk seeds
    #define WRITE_CHUNK_SEED(fname, mode_val, frags_val, p_data, p_len) do { \
        uint8_t s_buf[6 + (p_len)]; \
        s_buf[0] = ((mode_val) << 5) | 0x10; \
        s_buf[1] = (frags_val); \
        s_buf[2] = 0; \
        uint16_t pl_le = (uint16_t)(p_len); \
        memcpy(s_buf + 3, &pl_le, 2); \
        s_buf[5] = 0; \
        if ((p_len) > 0) memcpy(s_buf + 6, (p_data), (p_len)); \
        write_seed_file(corpus_dir, (fname), s_buf, sizeof(s_buf)); \
    } while(0)

    // Seed 1: Mode 3 (Unfragmented Short Header Stream - MSG_PEER_DISCOVERY)
    uint8_t p_disc[11] = { 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    WRITE_CHUNK_SEED("seed01_single_stream_disc.bin", 3, 1, p_disc, sizeof(p_disc));

    // Seed 2: Mode 4 (Fragmented Short Header Stream - MSG_PTR_TRANSFER)
    uint8_t p_tx[32] = { 0x04, 0x00, 0x00, 0x00, 0x00 };
    memset(p_tx + 5, 0x77, 27);
    WRITE_CHUNK_SEED("seed02_ooo_multi_frag_tx.bin", 4, 3, p_tx, sizeof(p_tx));

    // Seed 3: Mode 0 (Long Header Flight 1 Handshake Initiation)
    uint8_t p_f1[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    WRITE_CHUNK_SEED("seed03_long_header_flight1.bin", 0, 1, p_f1, sizeof(p_f1));

    // Seed 4: Mode 1 (Long Header Flight 2 Handshake Response)
    uint8_t p_f2[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    WRITE_CHUNK_SEED("seed04_long_header_flight2.bin", 1, 1, p_f2, sizeof(p_f2));

    // Seed 5: Mode 2 (Long Header Flight 3 Slab Reassembly)
    uint8_t p_f3[16] = { 0x07, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };
    WRITE_CHUNK_SEED("seed05_long_header_flight3_slab.bin", 2, 2, p_f3, sizeof(p_f3));

    // Seed 6: Mode 3 (RPC Request - Method 0x0001 GetBalance)
    uint8_t p_rpc_bal[5 + sizeof(SclRpcHeader) + 2592];
    memset(p_rpc_bal, 0, sizeof(p_rpc_bal));
    p_rpc_bal[0] = 47; // Maps to MSG_RPC_REQUEST (48)
    SclRpcHeader *hdr_bal = (SclRpcHeader *)(p_rpc_bal + 5);
    hdr_bal->version = SCL_RPC_VERSION_1;
    hdr_bal->method_id = htobe16(0x0001);
    hdr_bal->request_id = htobe64(((uint64_t)time(NULL) * 1000) << 16);
    hdr_bal->payload_len = htobe32(2592);
    memcpy(p_rpc_bal + 5 + sizeof(SclRpcHeader), global_state->user_wallet.dilithium_pubkey, DILITHIUM_PUBKEY_LEN);
    hdr_bal->checksum = htobe64(compute_rpc_checksum((const uint8_t*)hdr_bal, 0, 2592, fuzz_conn->rpc_siphash_key));
    WRITE_CHUNK_SEED("seed06_rpc_get_balance.bin", 3, 1, p_rpc_bal, sizeof(p_rpc_bal));

    // Seed 7: Mode 3 (RPC Request - Method 0x0008 GetChainInfo)
    uint8_t p_rpc_info[5 + sizeof(SclRpcHeader)];
    memset(p_rpc_info, 0, sizeof(p_rpc_info));
    p_rpc_info[0] = 47;
    SclRpcHeader *hdr_info = (SclRpcHeader *)(p_rpc_info + 5);
    hdr_info->version = SCL_RPC_VERSION_1;
    hdr_info->method_id = htobe16(0x0008);
    hdr_info->request_id = htobe64(((uint64_t)time(NULL) * 1000) << 16);
    hdr_info->checksum = htobe64(compute_rpc_checksum((const uint8_t*)hdr_info, 0, 0, fuzz_conn->rpc_siphash_key));
    WRITE_CHUNK_SEED("seed07_rpc_chain_info.bin", 3, 1, p_rpc_info, sizeof(p_rpc_info));

    // Seed 8: Mode 5 (L4 Control Frames: PING, ACK, MAX_DATA, NEW_CID, PATH_CHALLENGE)
    uint8_t p_ctrl[16] = { 0x01, 0x02, 0x03, 0x04 };
    WRITE_CHUNK_SEED("seed08_l4_control_frames.bin", 5, 1, p_ctrl, sizeof(p_ctrl));

    // Seed 9: Mode 6 (Long Header RETRY Packet)
    uint8_t p_retry[8] = { 0x00 };
    WRITE_CHUNK_SEED("seed09_long_header_retry.bin", 6, 1, p_retry, sizeof(p_retry));

    // Seed 10: Mode 3 (Blockchain Gossip Block - MSG_GOSSIP_BLOCK)
    uint8_t p_block[32] = { 0x09 };
    memset(p_block + 5, 0x11, 27);
    WRITE_CHUNK_SEED("seed10_gossip_block.bin", 3, 1, p_block, sizeof(p_block));

    // Seed 11: Mode 3 (MSG_BLOCK_APPROVED)
    uint8_t p_block_app[32] = { 0x0A };
    memset(p_block_app + 5, 0x22, 27);
    WRITE_CHUNK_SEED("seed11_block_approved.bin", 3, 1, p_block_app, sizeof(p_block_app));

    // Seed 12: Mode 3 (MSG_PENDING_OPERATION - OP_TRANSFER_POINTER)
    uint8_t p_op_tx[40] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x02 };
    memset(p_op_tx + 6, 0x33, 34);
    WRITE_CHUNK_SEED("seed12_pending_op_transfer.bin", 3, 1, p_op_tx, sizeof(p_op_tx));

    // Seed 13: Mode 3 (MSG_PENDING_OPERATION - OP_STAKE)
    uint8_t p_op_stk[40] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x03 };
    memset(p_op_stk + 6, 0x44, 34);
    WRITE_CHUNK_SEED("seed13_pending_op_stake.bin", 3, 1, p_op_stk, sizeof(p_op_stk));

    // Seed 14: Mode 3 (MSG_PENDING_OPERATION - OP_UNSTAKE)
    uint8_t p_op_unstk[40] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x04 };
    memset(p_op_unstk + 6, 0x55, 34);
    WRITE_CHUNK_SEED("seed14_pending_op_unstake.bin", 3, 1, p_op_unstk, sizeof(p_op_unstk));

    // Seed 15: Mode 3 (MSG_PENDING_OPERATION - OP_MINT_COIN)
    uint8_t p_op_mint[40] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x01 };
    memset(p_op_mint + 6, 0x66, 34);
    WRITE_CHUNK_SEED("seed15_pending_op_mint.bin", 3, 1, p_op_mint, sizeof(p_op_mint));

    // Seed 16: Mode 3 (MSG_PENDING_OPERATION - OP_REDEEM_CENTINEL)
    uint8_t p_op_redeem[40] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x05 };
    memset(p_op_redeem + 6, 0x77, 34);
    WRITE_CHUNK_SEED("seed16_pending_op_redeem.bin", 3, 1, p_op_redeem, sizeof(p_op_redeem));

    // Seed 17: Mode 3 (MSG_PENDING_OPERATION - OP_CLAIM_VALIDATION)
    uint8_t p_op_claim[40] = { 0x06, 0x00, 0x00, 0x00, 0x00, 0x06 };
    memset(p_op_claim + 6, 0x88, 34);
    WRITE_CHUNK_SEED("seed17_pending_op_claim.bin", 3, 1, p_op_claim, sizeof(p_op_claim));

    // Seed 18: Mode 3 (MSG_VOTE)
    uint8_t p_vote[38] = { 0x0D, 0x00, 0x00, 0x00, 0x00 };
    memset(p_vote + 5, 0x55, 32);
    p_vote[37] = 1;
    WRITE_CHUNK_SEED("seed18_vote.bin", 3, 1, p_vote, sizeof(p_vote));

    // Seed 19: Mode 3 (MSG_VALUATION_PROPOSAL)
    uint8_t p_val_prop[20] = { 0x0E, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    WRITE_CHUNK_SEED("seed19_val_proposal.bin", 3, 1, p_val_prop, sizeof(p_val_prop));

    // Seed 20: Mode 3 (MSG_GET_BLOCKS)
    uint8_t p_get_blocks[13] = { 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    WRITE_CHUNK_SEED("seed20_get_blocks.bin", 3, 1, p_get_blocks, sizeof(p_get_blocks));

    // Seed 21: Mode 3 (MSG_CENTINEL_QUERY)
    uint8_t p_cent_query[5] = { 0x1D, 0x00, 0x00, 0x00, 0x00 };
    WRITE_CHUNK_SEED("seed21_centinel_query.bin", 3, 1, p_cent_query, sizeof(p_cent_query));

    // Seed 22: Mode 3 (MSG_COIN_QUERY)
    uint8_t p_coin_query[5] = { 0x01, 0x00, 0x00, 0x00, 0x00 };
    WRITE_CHUNK_SEED("seed22_coin_query.bin", 3, 1, p_coin_query, sizeof(p_coin_query));

    // Seed 23: Mode 3 (MSG_GET_PENDING_OPERATIONS)
    uint8_t p_get_pending[5] = { 0x14, 0x00, 0x00, 0x00, 0x00 };
    WRITE_CHUNK_SEED("seed23_get_pending_ops.bin", 3, 1, p_get_pending, sizeof(p_get_pending));

    // Seed 24: Mode 3 (MSG_GET_PUBKEY_BY_USERID)
    uint8_t p_get_pk[37] = { 0x0B, 0x00, 0x00, 0x00, 0x00 };
    memcpy(p_get_pk + 5, fuzz_user_id, USER_ID_LEN);
    WRITE_CHUNK_SEED("seed24_get_pubkey_userid.bin", 3, 1, p_get_pk, sizeof(p_get_pk));

    // Seed 25: Mode 3 (MSG_ENDPOINT_DISCOVERY)
    uint8_t p_ep_disc[5] = { 0x2B, 0x00, 0x00, 0x00, 0x00 };
    WRITE_CHUNK_SEED("seed25_endpoint_discovery.bin", 3, 1, p_ep_disc, sizeof(p_ep_disc));

    // Seed 26: Mode 3 (MSG_RELAY_REQUEST)
    uint8_t p_relay_req[25] = { 0x2D, 0x00, 0x00, 0x00, 0x00 };
    memcpy(p_relay_req + 5, fuzz_cid, SCL_CID_LEN);
    WRITE_CHUNK_SEED("seed26_relay_request.bin", 3, 1, p_relay_req, sizeof(p_relay_req));

    // Seed 27: Mode 7 (Raw L0 MSG_RELAY_DATA Envelopment)
    uint8_t p_raw_relay[32] = { 0x2F, 0x00, 0x00, 0x00, 0x15, 0x7F, 0x00, 0x00, 0x01, 0x30, 0x39, 0x40 };
    memcpy(p_raw_relay + 12, fuzz_cid, SCL_CID_LEN);
    write_seed_file(corpus_dir, "seed27_raw_l0_relay_data.bin", p_raw_relay, sizeof(p_raw_relay));

    #undef WRITE_CHUNK_SEED

    fuzzer_initialized = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!fuzzer_initialized || size < 6) return 0;

    // Reset thread-local crypto arena at each iteration start to prevent linear arena expansion
    arena_reset(0);

    UserSpaceState *us_state = (global_shim && global_shim->impl_state) ? (UserSpaceState *)global_shim->impl_state : NULL;

    // Clear state hash tables, blockchain history, and queues mutated during network processing to prevent cross-iteration memory accumulation
    if (global_state) {
        pthread_rwlock_wrlock(&global_state->bc.rwlock);

#define CLEAR_HT_IF_ACTIVE(ht) do { \
    if ((ht) && ((ht)->count > 0 || (ht)->old_buckets != NULL)) { \
        hash_table_clear(ht); \
    } \
} while(0)

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
        CLEAR_HT_IF_ACTIVE(global_state->pubkey_cache);
        CLEAR_HT_IF_ACTIVE(global_state->orphan_pool);
        CLEAR_HT_IF_ACTIVE(global_state->dkg_active_sessions);
        CLEAR_HT_IF_ACTIVE(global_state->epoch_processes);
        CLEAR_HT_IF_ACTIVE(global_state->epoch_sign_data_cache);
        CLEAR_HT_IF_ACTIVE(global_state->threshold_stake_processes);
        CLEAR_HT_IF_ACTIVE(global_state->voted_heights);
        CLEAR_HT_IF_ACTIVE(global_state->block_consensus);
        CLEAR_HT_IF_ACTIVE(global_state->block_proposers);
        CLEAR_HT_IF_ACTIVE(global_state->processed_blocks);

        CLEAR_HT_IF_ACTIVE(global_state->bc.coin_table);
        CLEAR_HT_IF_ACTIVE(global_state->bc.pointer_table);
        CLEAR_HT_IF_ACTIVE(global_state->bc.coin_pointers);
        CLEAR_HT_IF_ACTIVE(global_state->bc.centinel.nullifier_set);

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

        // Rollback database block storage
        scl_db_delete_blocks_after(0);
        
        if (global_state->bc.insert_order_capacity > 16) {
            free(global_state->bc.insert_order);
            global_state->bc.insert_order = NULL;
            global_state->bc.insert_order_capacity = 0;
        }
        global_state->bc.insert_order_count = 0;
        global_state->current_block_number = 0;
        memset(global_state->current_block_hash, 0, COIN_ID_LEN);
        global_state->sync_received_block_number_value = 0;
        memset(global_state->sync_received_block_hash, 0, COIN_ID_LEN);
        global_state->blockchain_sync_received_end = 0;
        memset(global_state->game_state.epoch_threshold_pubkey, 0, DILITHIUM_PUBKEY_LEN);
        memset(global_state->game_state.current_epoch_signature, 0, SIGNATURE_LEN);
        global_state->game_state.valuation_count = 0;
        global_state->game_state.current_audit_index = 0;
        memset(global_state->game_state.game_audit, 0, sizeof(global_state->game_state.game_audit));

        // Retain known_peers[0] (pinned to fuzz_conn) and trim extra dynamic peers
        if (global_state->p2p_network.num_known_peers > 1) {
            for (size_t i = 1; i < global_state->p2p_network.num_known_peers; i++) {
                if (global_state->p2p_network.known_peers[i]) {
                    free(global_state->p2p_network.known_peers[i]);
                    global_state->p2p_network.known_peers[i] = NULL;
                }
            }
            global_state->p2p_network.num_known_peers = 1;
        }
        if (global_state->p2p_network.known_peers && global_state->p2p_network.known_peers[0]) {
            global_state->p2p_network.known_peers[0]->conn = fuzz_conn;
        }

        if (atomic_load(&global_state->autopilot_running)) {
            stop_autopilot_thread(global_state);
        }
        queue_flush_fast(&global_state->submission_queue);
        queue_flush_fast(&global_state->message_queue);
        
        global_state->hypergraph.node_count = 0;
        global_state->hypergraph.edge_count = 0;
        global_state->bc.sync_epoch = 1; // Explicitly prevents underflow and aligns state validation

        // Release stale active snapshot to prevent memory accumulation
        GameStateSnapshot *snap = (GameStateSnapshot *)atomic_exchange_explicit(&global_state->active_snapshot_ptr, 0, memory_order_acquire);
        if (snap) release_game_state_snapshot(snap);
        update_game_state_snapshot(global_state);

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
        global_state->user_wallet.num_val_utxos = 0;

        // Unset in_blockchain_sync so all block/coin/pointer/centinel message handlers can execute
        global_state->in_blockchain_sync = 0;
    }

    // Clean up dynamic connections registered in cid_routing_table and GC ring from previous iterations safely
    if (us_state) {
        atomic_store_explicit(&us_state->global_ooo_bytes_allocated, 0, memory_order_relaxed);
        atomic_store_explicit(&us_state->active_connection_count, 2, memory_order_relaxed);

        SclConnection *to_free[4096];
        size_t to_free_count = 0;

        for (int i = 0; i < 4096; i++) {
            SclConnection *conn = atomic_exchange_explicit(&us_state->cid_routing_table[i], NULL, memory_order_relaxed);
            if (conn && conn != SCL_TOMBSTONE && conn != fuzz_conn && conn != listener_conn) {
                bool found = false;
                for (size_t k = 0; k < to_free_count; k++) {
                    if (to_free[k] == conn) { found = true; break; }
                }
                if (!found && to_free_count < 4096) {
                    to_free[to_free_count++] = conn;
                }
            }
        }

        // Drain GC ring entries and deduplicate against to_free list
        for (int i = 0; i < 4096; i++) {
            if (atomic_load_explicit(&us_state->gc_ring[i].ready, memory_order_acquire)) {
                if (us_state->gc_ring[i].type == GC_TYPE_CONNECTION) {
                    SclConnection *dconn = (SclConnection *)us_state->gc_ring[i].ptr;
                    if (dconn && dconn != fuzz_conn && dconn != listener_conn) {
                        bool found = false;
                        for (size_t k = 0; k < to_free_count; k++) {
                            if (to_free[k] == dconn) { found = true; break; }
                        }
                        if (!found && to_free_count < 4096) {
                            to_free[to_free_count++] = dconn;
                        }
                    }
                } else if (us_state->gc_ring[i].type == GC_TYPE_SNAPSHOT) {
                    GameStateSnapshot *dsnap = (GameStateSnapshot *)us_state->gc_ring[i].ptr;
                    if (dsnap) release_game_state_snapshot(dsnap);
                }
                atomic_store_explicit(&us_state->gc_ring[i].ready, false, memory_order_release);
            }
        }
        atomic_store_explicit(&us_state->gc_head, 0, memory_order_release);
        atomic_store_explicit(&us_state->gc_tail, 0, memory_order_release);
        us_state->relay_count = 0;

        for (size_t k = 0; k < to_free_count; k++) {
            scl_connection_destroy_now(to_free[k]);
        }
        
        // Wipe TX Ring to prevent pacing budget lockouts from stalling the fuzzer
        uint32_t head = atomic_load_explicit(&us_state->tx_head, memory_order_relaxed);
        uint32_t tail = atomic_load_explicit(&us_state->tx_tail, memory_order_relaxed);
        while (tail != head) {
            atomic_store_explicit(&us_state->tx_ring[tail].ready, false, memory_order_relaxed);
            tail = (tail + 1) % 1024;
        }
        atomic_store_explicit(&us_state->tx_tail, tail, memory_order_relaxed);
        us_state->pacing_budget = 4 * 1280; // Reset token bucket explicitly

        if (us_state->handshake_slab) {
            for (int i = 0; i < SCL_SLAB_SLOTS; i++) {
                SclHandshakeSlot *slot = &us_state->handshake_slab->slots[i];
                if (atomic_load_explicit(&slot->state, memory_order_relaxed) != SCL_SLOT_FREE) {
                    atomic_store_explicit(&slot->state, SCL_SLOT_FREE, memory_order_relaxed);
                    slot->assembled_length = 0;
                    memset(slot->fragment_tracker, 0, sizeof(slot->fragment_tracker));
                    memset(slot->parity_tracker, 0, sizeof(slot->parity_tracker));
                    memset(slot->connection_token, 0, sizeof(slot->connection_token));
                    memset(&slot->client_addr, 0, sizeof(slot->client_addr));
                }
            }
            atomic_store_explicit(&us_state->handshake_slab->active_tier1, 0, memory_order_relaxed);
            atomic_store_explicit(&us_state->handshake_slab->active_tier2, 0, memory_order_relaxed);
        }
        
        for (int i = 0; i < SCL_DOS_TRACKER_SIZE; i++) {
            DoSNode *curr = atomic_exchange_explicit(&us_state->ip_tracker.buckets[i], NULL, memory_order_relaxed);
            while (curr) { DoSNode *next = curr->next; free(curr); curr = next; }
            
            curr = atomic_exchange_explicit(&us_state->subnet_tracker.buckets[i], NULL, memory_order_relaxed);
            while (curr) { DoSNode *next = curr->next; free(curr); curr = next; }
            
            curr = atomic_exchange_explicit(&us_state->ip_rate_tracker.buckets[i], NULL, memory_order_relaxed);
            while (curr) { DoSNode *next = curr->next; free(curr); curr = next; }
        }
    }

    // Pin ref_count and re-register fuzz_conn & listener_conn to prevent ASan heap-use-after-free
    atomic_store_explicit(&fuzz_conn->ref_count, 1000, memory_order_relaxed);
    atomic_store_explicit(&listener_conn->ref_count, 1000, memory_order_relaxed);
    global_shim->register_connection(global_shim, fuzz_cid, fuzz_conn);
    global_shim->register_connection(global_shim, zero_cid, listener_conn);
    atomic_store_explicit(&listener_conn->l5_rx_queue.head, 0, memory_order_relaxed);
    atomic_store_explicit(&listener_conn->l5_rx_queue.tail, 0, memory_order_relaxed);

    // Reset the target connection securely for this fuzz iteration
    pthread_mutex_lock(&fuzz_conn->l4_mutex);
    fuzz_conn->handshake_state = SCL_CONN_STATE_ESTABLISHED;
    fuzz_conn->is_handshake_complete = true;
    fuzz_conn->pacing_budget = 1000000000; // Infinite budget for fuzzing
    fuzz_conn->cwnd = 1000000000;          // Infinite window for fuzzing
    fuzz_conn->bytes_in_flight = 0;
    fuzz_conn->tx_dispatched_data = 0;
    memcpy(fuzz_conn->current_aes_gcm_key, dummy_aes_key, 32);
    memcpy(fuzz_conn->flight3_aes_gcm_key, expected_flight3_key, 32);
    memset(fuzz_conn->rpc_siphash_key, 0x42, 16);
    atomic_store(&fuzz_conn->rpc_token_budget, 1000000);
    atomic_store(&fuzz_conn->last_rpc_token_refill, get_time_ms());
    atomic_store(&fuzz_conn->active_rpc_streams, 0);
    memset(fuzz_conn->rpc_recent_request_ids, 0, sizeof(fuzz_conn->rpc_recent_request_ids));
    fuzz_conn->rpc_request_idx = 0;
    fuzz_conn->rpc_highest_seen_timestamp = 0;
    atomic_store_explicit(&fuzz_conn->l5_rx_queue.head, 0, memory_order_relaxed);
    atomic_store_explicit(&fuzz_conn->l5_rx_queue.tail, 0, memory_order_relaxed);
    memset(fuzz_conn->replay_window_bitmask, 0, sizeof(fuzz_conn->replay_window_bitmask));
    atomic_store_explicit(&fuzz_conn->replay_highest_seen, 0, memory_order_release);
    fuzz_conn->rx_consumed_data = 0;
    fuzz_conn->expected_rx_stream_offset = 0;
    pthread_mutex_unlock(&fuzz_conn->l4_mutex);

    // Reset listener_conn state across iterations
    pthread_mutex_lock(&listener_conn->l4_mutex);
    listener_conn->handshake_state = SCL_CONN_STATE_ESTABLISHED;
    listener_conn->is_handshake_complete = true;
    listener_conn->pacing_budget = 1000000000;
    listener_conn->cwnd = 1000000000;
    listener_conn->bytes_in_flight = 0;
    listener_conn->tx_dispatched_data = 0;
    listener_conn->rx_consumed_data = 0;
    listener_conn->expected_rx_stream_offset = 0;
    listener_conn->next_tx_stream_offset = 0;
    atomic_store(&listener_conn->rpc_token_budget, 1000000);
    atomic_store(&listener_conn->last_rpc_token_refill, get_time_ms());
    atomic_store(&listener_conn->active_rpc_streams, 0);
    memset(listener_conn->rpc_recent_request_ids, 0, sizeof(listener_conn->rpc_recent_request_ids));
    listener_conn->rpc_request_idx = 0;
    listener_conn->rpc_highest_seen_timestamp = 0;
    atomic_store_explicit(&listener_conn->l5_rx_queue.head, 0, memory_order_relaxed);
    atomic_store_explicit(&listener_conn->l5_rx_queue.tail, 0, memory_order_relaxed);
    memset(listener_conn->replay_window_bitmask, 0, sizeof(listener_conn->replay_window_bitmask));
    atomic_store_explicit(&listener_conn->replay_highest_seen, 0, memory_order_release);
    pthread_mutex_unlock(&listener_conn->l4_mutex);

    ooo_cleanup_conn(fuzz_conn, us_state);
    ooo_cleanup_conn(listener_conn, us_state);
    unacked_cleanup_conn(fuzz_conn);
    unacked_cleanup_conn(listener_conn);

    queue_flush_fast(&fuzz_conn->tx_stream_queue);
    queue_flush_fast(&fuzz_conn->tx_datagram_queue);
    queue_flush_fast(&listener_conn->tx_stream_queue);
    queue_flush_fast(&listener_conn->tx_datagram_queue);

    const uint8_t *ptr = data;
    size_t remaining = size;
    uint64_t pkt_num = 1;
    uint64_t stream_offset = 0;
    int loop_limit = 0;

    static _Thread_local uint8_t *decryption_buffer = NULL;
    static _Thread_local Message *in_msg = NULL;
    static _Thread_local Message *out_msg = NULL;
    if (!decryption_buffer) decryption_buffer = malloc(MAX_MESSAGE_SIZE);
    if (!in_msg) in_msg = malloc(sizeof(Message));
    if (!out_msg) out_msg = malloc(sizeof(Message));

    while (remaining >= 6 && loop_limit++ < 128) {
        uint8_t ctrl = ptr[0];
        uint8_t total_frags_raw = ptr[1];
        uint16_t p_len_raw;
        memcpy(&p_len_raw, ptr + 3, 2);
        
        ptr += 6;
        remaining -= 6;

        size_t p_len = (p_len_raw % 1024) + 1;
        if (p_len > remaining) p_len = remaining;
        
        if (p_len == 0 && remaining == 0) {
            break;
        }

        uint8_t mode = (ctrl >> 5) & 0x07; // 8 distinct coverage modes

        uint8_t l5_formatted[8192];
        const uint8_t *payload_to_encrypt = ptr;
        size_t payload_to_encrypt_len = p_len;

        // Auto-frame payload as valid L5 message to guarantee deep execution
        if (((ctrl & 0x10) || p_len >= 1) && remaining >= 1) {
            l5_formatted[0] = (ctrl & 0x01) ? SCL_FRAME_DATAGRAM : SCL_FRAME_STREAM;
            uint8_t msg_type = (ptr[0] % 49) + 1; // Map to valid MessageType (1..49)
            l5_formatted[1] = msg_type;
            uint32_t msg_len = (uint32_t)(p_len > 5 ? p_len - 5 : 0);
            uint32_t msg_len_be = htobe32(msg_len);
            memcpy(l5_formatted + 2, &msg_len_be, 4);
            if (msg_len > 0) {
                memcpy(l5_formatted + 6, ptr + (p_len > 5 ? 5 : 0), msg_len);
            }

            // Auto-align RPC header version, timestamp window, and compute valid SipHash checksum for MSG_RPC_REQUEST
            if (msg_type == MSG_RPC_REQUEST && msg_len >= sizeof(SclRpcHeader)) {
                SclRpcHeader *hdr = (SclRpcHeader *)(l5_formatted + 6);
                hdr->version = SCL_RPC_VERSION_1;
                uint64_t now_ms = (uint64_t)time(NULL) * 1000;
                hdr->request_id = htobe64((now_ms << 16) | (ctrl & 0xFFFF));
                uint16_t err_len = be16toh(hdr->error_msg_len);
                uint32_t payload_len = be32toh(hdr->payload_len);
                if (sizeof(SclRpcHeader) + (size_t)err_len + (size_t)payload_len > msg_len) {
                    size_t rem = msg_len - sizeof(SclRpcHeader);
                    if (rem >= err_len) {
                        payload_len = rem - err_len;
                    } else {
                        err_len = rem;
                        payload_len = 0;
                    }
                    hdr->error_msg_len = htobe16(err_len);
                    hdr->payload_len = htobe32(payload_len);
                }
                uint64_t computed_csum = compute_rpc_checksum((const uint8_t*)hdr, err_len, payload_len, fuzz_conn->rpc_siphash_key);
                hdr->checksum = htobe64(computed_csum);
            }

            payload_to_encrypt = l5_formatted;
            payload_to_encrypt_len = 6 + msg_len;
        }

        uint8_t raw_packet[4096];
        size_t raw_len = 0;

        if (mode == 0) {
            // --- MODE 0: FLIGHT 1 / LONG HEADER HANDSHAKE INITIATION (Client -> Server) ---
            raw_packet[0] = SCL_PACKET_FLAG_LONG_HEADER;
            memcpy(raw_packet + 1, (ctrl & 0x01) ? fuzz_cid : zero_cid, SCL_CID_LEN);
            uint64_t pn_be = htobe64(pkt_num++);
            memcpy(raw_packet + 1 + SCL_CID_LEN, &pn_be, 8);

            uint64_t cookie = generate_stateless_cookie(us_state->node_secret, fuzz_addr.sin_addr.s_addr);
            memcpy(raw_packet + SCL_HEADER_MIN_LEN, &cookie, 8);
            uint64_t pow_sol = 0;
            memcpy(raw_packet + SCL_HEADER_MIN_LEN + 8, &pow_sol, 8);
            memcpy(raw_packet + SCL_HEADER_MIN_LEN + 16, global_state->p2p_network.local_peer.peer_wallet.kyber_pubkey, KYBER_PUBKEY_LEN);
            memcpy(raw_packet + SCL_HEADER_MIN_LEN + 16 + KYBER_PUBKEY_LEN, fuzz_user_id, USER_ID_LEN);
            uint64_t sec_pow = 0;
            memcpy(raw_packet + SCL_HEADER_MIN_LEN + 16 + KYBER_PUBKEY_LEN + USER_ID_LEN, &sec_pow, 8);

            raw_len = SCL_HEADER_MIN_LEN + 16 + KYBER_PUBKEY_LEN + USER_ID_LEN + 8;
            if (p_len > 0 && raw_len + p_len <= sizeof(raw_packet)) {
                memcpy(raw_packet + raw_len, ptr, p_len);
                raw_len += p_len;
            }

            uint32_t head = atomic_load_explicit(&listener_conn->l5_rx_queue.head, memory_order_relaxed);
            uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
            uint32_t tail = atomic_load_explicit(&listener_conn->l5_rx_queue.tail, memory_order_acquire);
            if (next_head == tail) {
                process_spsc_queue(listener_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                head = atomic_load_explicit(&listener_conn->l5_rx_queue.head, memory_order_relaxed);
                next_head = (head + 1) % SCL_L5_RING_SIZE;
                tail = atomic_load_explicit(&listener_conn->l5_rx_queue.tail, memory_order_acquire);
            }
            if (next_head != tail) {
                memcpy(listener_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                listener_conn->l5_rx_queue.lengths[head] = raw_len;
                listener_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                listener_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                atomic_store_explicit(&listener_conn->l5_rx_queue.head, next_head, memory_order_release);
            }
            ptr += p_len;
            remaining -= p_len;

        } else if (mode == 1) {
            // --- MODE 1: FLIGHT 2 / LONG HEADER HANDSHAKE RESPONSE (Server -> Client) ---
            fuzz_conn->handshake_state = SCL_CONN_STATE_FLIGHT1_SENT;
            fuzz_conn->is_handshake_complete = false;

            raw_packet[0] = SCL_PACKET_FLAG_LONG_HEADER;
            memcpy(raw_packet + 1, fuzz_cid, SCL_CID_LEN);
            uint64_t pn_be = htobe64(1);
            memcpy(raw_packet + 1 + SCL_CID_LEN, &pn_be, 8);

            uint64_t cookie = generate_stateless_cookie(us_state->node_secret, fuzz_addr.sin_addr.s_addr);
            memcpy(raw_packet + SCL_HEADER_MIN_LEN, &cookie, 8);
            uint64_t ack_pn_be = htobe64(pkt_num++);
            memcpy(raw_packet + SCL_HEADER_MIN_LEN + 8, &ack_pn_be, 8);

            uint64_t expiry = get_time_ms() + 60000;
            if (ctrl & 0x01) expiry |= 1ULL;
            uint8_t handshake_token[64];
            generate_stateless_token(us_state->node_secret, expected_flight3_key, fuzz_addr.sin_addr.s_addr, expiry, handshake_token);
            memcpy(raw_packet + SCL_HEADER_MIN_LEN + 16, handshake_token, 64);

            uint8_t dummy_kyber_ct[KYBER_CIPHERTEXT_LEN];
            memset(dummy_kyber_ct, 0x42, sizeof(dummy_kyber_ct));
            memcpy(raw_packet + SCL_HEADER_MIN_LEN + 80, dummy_kyber_ct, KYBER_CIPHERTEXT_LEN);

            raw_len = SCL_HEADER_MIN_LEN + 16 + 64 + KYBER_CIPHERTEXT_LEN;

            uint32_t head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
            uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
            uint32_t tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            if (next_head == tail) {
                process_spsc_queue(fuzz_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
                next_head = (head + 1) % SCL_L5_RING_SIZE;
                tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            }
            if (next_head != tail) {
                memcpy(fuzz_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                fuzz_conn->l5_rx_queue.lengths[head] = raw_len;
                fuzz_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                fuzz_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                atomic_store_explicit(&fuzz_conn->l5_rx_queue.head, next_head, memory_order_release);
            }
            ptr += p_len;
            remaining -= p_len;

        } else if (mode == 2) {
            // --- MODE 2: FLIGHT 3 / LONG HEADER SLAB REASSEMBLY (Client -> Server) ---
            uint16_t total_frags = (total_frags_raw % 3) + 1;
            uint64_t expiry = get_time_ms() + 60000;
            if (ctrl & 0x01) expiry |= 1ULL;

            // Generate unique dynamic CID to bypass duplicate bailout check in process_spsc_queue
            uint8_t dyn_cid[SCL_CID_LEN];
            memcpy(dyn_cid, fuzz_cid, SCL_CID_LEN);
            dyn_cid[0] = 0x50 | (ctrl & 0x0F);

            uint8_t handshake_token[64];
            generate_stateless_token(us_state->node_secret, expected_flight3_key, fuzz_addr.sin_addr.s_addr, expiry, handshake_token);

            for (uint16_t f_idx = 0; f_idx < total_frags; f_idx++) {
                raw_packet[0] = SCL_PACKET_FLAG_LONG_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                memcpy(raw_packet + 1, dyn_cid, SCL_CID_LEN);
                uint64_t pn_be = htobe64(pkt_num++);
                memcpy(raw_packet + 1 + SCL_CID_LEN, &pn_be, 8);

                uint64_t so_be = htobe64(stream_offset);
                memcpy(raw_packet + SCL_HEADER_MIN_LEN, &so_be, 8);
                uint16_t tf_be = htobe16(total_frags);
                memcpy(raw_packet + SCL_HEADER_MIN_LEN + 8, &tf_be, 2);
                uint16_t fi_be = htobe16(f_idx);
                memcpy(raw_packet + SCL_HEADER_MIN_LEN + 10, &fi_be, 2);
                memcpy(raw_packet + SCL_HEADER_MIN_LEN + 12, handshake_token, 64);

                size_t ct_len = 0;
                encrypt_aead_packet(expected_flight3_key, pkt_num - 1, payload_to_encrypt, payload_to_encrypt_len, raw_packet + SCL_HEADER_MIN_LEN + 76, &ct_len);
                raw_len = SCL_HEADER_MIN_LEN + 76 + ct_len;

                uint32_t head = atomic_load_explicit(&listener_conn->l5_rx_queue.head, memory_order_relaxed);
                uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
                uint32_t tail = atomic_load_explicit(&listener_conn->l5_rx_queue.tail, memory_order_acquire);
                if (next_head == tail) {
                    process_spsc_queue(listener_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                    head = atomic_load_explicit(&listener_conn->l5_rx_queue.head, memory_order_relaxed);
                    next_head = (head + 1) % SCL_L5_RING_SIZE;
                    tail = atomic_load_explicit(&listener_conn->l5_rx_queue.tail, memory_order_acquire);
                }
                if (next_head != tail) {
                    memcpy(listener_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                    listener_conn->l5_rx_queue.lengths[head] = raw_len;
                    listener_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                    listener_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                    atomic_store_explicit(&listener_conn->l5_rx_queue.head, next_head, memory_order_release);
                }
            }
            stream_offset++;
            ptr += p_len;
            remaining -= p_len;

        } else if (mode == 3) {
            // --- MODE 3: UNFRAGMENTED SHORT HEADER APPLICATION STREAM ---
            raw_packet[0] = SCL_PACKET_FLAG_SHORT_HEADER;
            memcpy(raw_packet + 1, fuzz_cid, SCL_CID_LEN);
            uint64_t pn_be = htobe64(pkt_num++);
            memcpy(raw_packet + 1 + SCL_CID_LEN, &pn_be, 8);

            size_t ct_len = 0;
            encrypt_aead_packet(fuzz_conn->current_aes_gcm_key, pkt_num - 1, payload_to_encrypt, payload_to_encrypt_len, raw_packet + SCL_HEADER_MIN_LEN, &ct_len);
            raw_len = SCL_HEADER_MIN_LEN + ct_len;

            uint32_t head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
            uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
            uint32_t tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            if (next_head == tail) {
                process_spsc_queue(fuzz_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
                next_head = (head + 1) % SCL_L5_RING_SIZE;
                tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            }
            if (next_head != tail) {
                memcpy(fuzz_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                fuzz_conn->l5_rx_queue.lengths[head] = raw_len;
                fuzz_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                fuzz_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                atomic_store_explicit(&fuzz_conn->l5_rx_queue.head, next_head, memory_order_release);
            }
            ptr += p_len;
            remaining -= p_len;

        } else if (mode == 4) {
            // --- MODE 4: FRAGMENTED SHORT HEADER OOO POOL INJECTION ---
            uint16_t total_frags = (total_frags_raw % 3) + 1;
            if (total_frags > 32) total_frags = 32;

            for (uint16_t f_idx = 0; f_idx < total_frags; f_idx++) {
                raw_packet[0] = SCL_PACKET_FLAG_SHORT_HEADER | SCL_PACKET_FLAG_FRAGMENTED;
                memcpy(raw_packet + 1, fuzz_cid, SCL_CID_LEN);
                uint64_t pn_be = htobe64(pkt_num++);
                memcpy(raw_packet + 1 + SCL_CID_LEN, &pn_be, 8);

                uint64_t so_be = htobe64(stream_offset);
                memcpy(raw_packet + SCL_HEADER_MIN_LEN, &so_be, 8);
                uint16_t tf_be = htobe16(total_frags);
                memcpy(raw_packet + SCL_HEADER_MIN_LEN + 8, &tf_be, 2);
                uint16_t fi_be = htobe16(f_idx);
                memcpy(raw_packet + SCL_HEADER_MIN_LEN + 10, &fi_be, 2);

                size_t ct_len = 0;
                encrypt_aead_packet(fuzz_conn->current_aes_gcm_key, pkt_num - 1, payload_to_encrypt, payload_to_encrypt_len, raw_packet + SCL_HEADER_MIN_LEN + 12, &ct_len);
                raw_len = SCL_HEADER_MIN_LEN + 12 + ct_len;

                uint32_t head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
                uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
                uint32_t tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
                if (next_head == tail) {
                    process_spsc_queue(fuzz_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                    head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
                    next_head = (head + 1) % SCL_L5_RING_SIZE;
                    tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
                }
                if (next_head != tail) {
                    memcpy(fuzz_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                    fuzz_conn->l5_rx_queue.lengths[head] = raw_len;
                    fuzz_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                    fuzz_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                    atomic_store_explicit(&fuzz_conn->l5_rx_queue.head, next_head, memory_order_release);
                }
            }
            stream_offset++;
            ptr += p_len;
            remaining -= p_len;

        } else if (mode == 5) {
            // --- MODE 5: SHORT HEADER L4 CONTROL FRAMES INJECTION ---
            uint8_t ctrl_frame[128];
            size_t ctrl_frame_len = 0;
            uint8_t frame_sub = ctrl & 0x07;

            switch (frame_sub) {
                case 0:
                    ctrl_frame[0] = SCL_FRAME_PING;
                    ctrl_frame_len = 1;
                    break;
                case 1: {
                    ctrl_frame[0] = SCL_FRAME_ACK;
                    uint64_t ack_pn = htobe64(pkt_num > 1 ? pkt_num - 1 : 1);
                    uint64_t ack_delay = htobe64(10);
                    memcpy(ctrl_frame + 1, &ack_pn, 8);
                    memcpy(ctrl_frame + 9, &ack_delay, 8);
                    ctrl_frame_len = 17;
                    break;
                }
                case 2: {
                    ctrl_frame[0] = SCL_FRAME_MAX_DATA;
                    uint64_t max_d = htobe64(SCL_FLOW_WINDOW_SIZE * 2);
                    memcpy(ctrl_frame + 1, &max_d, 8);
                    ctrl_frame_len = 9;
                    break;
                }
                case 3:
                    ctrl_frame[0] = SCL_FRAME_NEW_CONNECTION_ID;
                    memcpy(ctrl_frame + 1, fuzz_cid, SCL_CID_LEN);
                    ctrl_frame_len = 1 + SCL_CID_LEN;
                    break;
                case 4:
                    ctrl_frame[0] = SCL_FRAME_PATH_CHALLENGE;
                    memset(ctrl_frame + 1, 0x77, 8);
                    ctrl_frame_len = 9;
                    break;
                default:
                    ctrl_frame[0] = SCL_FRAME_PATH_RESPONSE;
                    memset(ctrl_frame + 1, 0x77, 8);
                    ctrl_frame_len = 9;
                    break;
            }

            raw_packet[0] = SCL_PACKET_FLAG_SHORT_HEADER;
            memcpy(raw_packet + 1, fuzz_cid, SCL_CID_LEN);
            uint64_t pn_be = htobe64(pkt_num++);
            memcpy(raw_packet + 1 + SCL_CID_LEN, &pn_be, 8);

            size_t ct_len = 0;
            encrypt_aead_packet(fuzz_conn->current_aes_gcm_key, pkt_num - 1, ctrl_frame, ctrl_frame_len, raw_packet + SCL_HEADER_MIN_LEN, &ct_len);
            raw_len = SCL_HEADER_MIN_LEN + ct_len;

            uint32_t head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
            uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
            uint32_t tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            if (next_head == tail) {
                process_spsc_queue(fuzz_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
                next_head = (head + 1) % SCL_L5_RING_SIZE;
                tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            }
            if (next_head != tail) {
                memcpy(fuzz_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                fuzz_conn->l5_rx_queue.lengths[head] = raw_len;
                fuzz_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                fuzz_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                atomic_store_explicit(&fuzz_conn->l5_rx_queue.head, next_head, memory_order_release);
            }
            ptr += p_len;
            remaining -= p_len;

        } else if (mode == 6) {
            // --- MODE 6: LONG HEADER RETRY PACKET INJECTION (Server -> Client) ---
            fuzz_conn->handshake_state = SCL_CONN_STATE_FLIGHT1_SENT;
            fuzz_conn->is_handshake_complete = false;

            raw_packet[0] = SCL_PACKET_FLAG_LONG_HEADER | SCL_PACKET_FLAG_RETRY;
            memcpy(raw_packet + 1, fuzz_cid, SCL_CID_LEN);
            uint64_t pn_be = htobe64(0);
            memcpy(raw_packet + 1 + SCL_CID_LEN, &pn_be, 8);

            uint64_t cookie = generate_stateless_cookie(us_state->node_secret, fuzz_addr.sin_addr.s_addr);
            memcpy(raw_packet + SCL_HEADER_MIN_LEN, &cookie, 8);
            raw_packet[SCL_HEADER_MIN_LEN + 8] = 10;
            raw_packet[SCL_HEADER_MIN_LEN + 9] = 0;
            memset(raw_packet + SCL_HEADER_MIN_LEN + 10, 0, 32);

            raw_len = SCL_HEADER_MIN_LEN + 8 + 1 + 1 + 32;

            uint32_t head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
            uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
            uint32_t tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            if (next_head == tail) {
                process_spsc_queue(fuzz_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
                next_head = (head + 1) % SCL_L5_RING_SIZE;
                tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            }
            if (next_head != tail) {
                memcpy(fuzz_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                fuzz_conn->l5_rx_queue.lengths[head] = raw_len;
                fuzz_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                fuzz_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                atomic_store_explicit(&fuzz_conn->l5_rx_queue.head, next_head, memory_order_release);
            }
            ptr += p_len;
            remaining -= p_len;

        } else {
            // --- RAW MUTATED PACKET INJECTION ---
            size_t raw_chunk_len = p_len > 0 ? p_len : (remaining > 0 ? 1 : 0);
            if (raw_chunk_len > sizeof(raw_packet)) raw_chunk_len = sizeof(raw_packet);
            if (raw_chunk_len > 0) {
                memcpy(raw_packet, ptr, raw_chunk_len);
            }
            raw_len = raw_chunk_len;

            uint32_t head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
            uint32_t next_head = (head + 1) % SCL_L5_RING_SIZE;
            uint32_t tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            if (next_head == tail) {
                process_spsc_queue(fuzz_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
                head = atomic_load_explicit(&fuzz_conn->l5_rx_queue.head, memory_order_relaxed);
                next_head = (head + 1) % SCL_L5_RING_SIZE;
                tail = atomic_load_explicit(&fuzz_conn->l5_rx_queue.tail, memory_order_acquire);
            }
            if (next_head != tail) {
                memcpy(fuzz_conn->l5_rx_queue.buffer[head], raw_packet, raw_len);
                fuzz_conn->l5_rx_queue.lengths[head] = raw_len;
                fuzz_conn->l5_rx_queue.addrs[head] = fuzz_addr;
                fuzz_conn->l5_rx_queue.rx_times[head] = get_time_ms();
                atomic_store_explicit(&fuzz_conn->l5_rx_queue.head, next_head, memory_order_release);
            }

            ptr += raw_chunk_len;
            remaining -= raw_chunk_len;
        }
    }

    // Process queues on both listener and application connections
    process_spsc_queue(listener_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);
    process_spsc_queue(fuzz_conn, global_state, &global_state->p2p_network, decryption_buffer, in_msg, out_msg);

    global_shim->poll(global_shim);

    // Drain TX egress queues immediately at end of iteration to free all buffers
    queue_flush_fast(&fuzz_conn->tx_stream_queue);
    queue_flush_fast(&fuzz_conn->tx_datagram_queue);
    queue_flush_fast(&listener_conn->tx_stream_queue);
    queue_flush_fast(&listener_conn->tx_datagram_queue);
    queue_flush_fast(&global_state->submission_queue);
    queue_flush_fast(&global_state->message_queue);

    ooo_cleanup_conn(fuzz_conn, us_state);
    ooo_cleanup_conn(listener_conn, us_state);
    unacked_cleanup_conn(fuzz_conn);
    unacked_cleanup_conn(listener_conn);

    arena_reset(0);

#if defined(__linux__)
    static uint64_t iter_count = 0;
    if ((++iter_count & 0x3F) == 0) { // Every 64 iterations, release fragmented pages to OS
        malloc_trim(0);
    }
#elif defined(__APPLE__)
    static uint64_t iter_count = 0;
    if ((++iter_count & 0x3F) == 0) { // Every 64 iterations, release cached pages to OS
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

// Custom Mutator ensuring structural protocol alignment across mutated packet chunks
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (new_size < 6) return new_size;

    size_t pos = 0;
    while (pos + 6 <= new_size) {
        uint16_t orig_len;
        memcpy(&orig_len, Data + pos + 3, 2);
        size_t chunk_len = (orig_len % 1024) + 1;

        if (pos + 6 + chunk_len > new_size) {
            chunk_len = new_size - (pos + 6);
            uint16_t adj_len = (uint16_t)chunk_len;
            memcpy(Data + pos + 3, &adj_len, 2);
        }

        if (chunk_len == 0 && pos + 6 == new_size) {
            break;
        }

        uint8_t *ptr = Data + pos + 6;
        uint8_t ctrl = Data[pos];
        uint8_t mode = (ctrl >> 5) & 0x07;

        // Auto-align RPC requests, blocks, votes, DKG, and operations across chunk payloads
        if ((mode == 2 || mode == 3 || mode == 4) && chunk_len >= 6) {
            uint8_t msg_type = ((Seed >> 1) % 49) + 1;
            ptr[0] = msg_type - 1; // Maps to msg_type via (ptr[0] % 49) + 1
            
            if (msg_type == MSG_RPC_REQUEST && chunk_len >= 5 + sizeof(SclRpcHeader)) {
                SclRpcHeader *hdr = (SclRpcHeader *)(ptr + 5);
                hdr->version = SCL_RPC_VERSION_1;
                
                uint16_t method = (Seed >> 3) % 12;
                if ((Seed % 13) != 0) {
                    hdr->method_id = htobe16(method);
                }

                uint16_t err_len = be16toh(hdr->error_msg_len);
                uint32_t payload_len = be32toh(hdr->payload_len);
                size_t max_payload = (chunk_len > 5 + sizeof(SclRpcHeader)) ? (chunk_len - 5 - sizeof(SclRpcHeader)) : 0;
                if ((size_t)err_len + (size_t)payload_len > max_payload) {
                    if (err_len > max_payload) err_len = (uint16_t)max_payload;
                    payload_len = (uint32_t)(max_payload - err_len);
                    hdr->error_msg_len = htobe16(err_len);
                    hdr->payload_len = htobe32(payload_len);
                }

                uint16_t cur_method = be16toh(hdr->method_id);
                if (cur_method == 0x0000 || cur_method == 0x0004 || cur_method == 0x0005 || cur_method == 0x0008) {
                    payload_len = 0;
                    hdr->payload_len = 0;
                } else if (cur_method == 0x0001 && max_payload >= 2592 && chunk_len >= 5 + sizeof(SclRpcHeader) + err_len + 2592 && global_state) { // GetBalance
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len, global_state->user_wallet.dilithium_pubkey, 2592);
                    hdr->payload_len = htobe32(2592);
                    payload_len = 2592;
                } else if (cur_method == 0x0002 || cur_method == 0x0006) { // GetBlock / GetRecentTxs
                    hdr->flags |= SCL_RPC_FLAG_PAGINATED;
                    hdr->cursor = htobe32((cur_method == 0x0002) ? (Seed % 151) : (Seed % 50));
                    payload_len = 0;
                    hdr->payload_len = 0;
                } else if (cur_method == 0x0003 && max_payload >= DILITHIUM_SIGNATURE_LEN + 1) { // SubmitTx
                    hdr->flags |= SCL_RPC_FLAG_SIGNED;
                    uint8_t op_type = (Seed >> 4) % 7;
                    size_t op_offset = 5 + sizeof(SclRpcHeader) + err_len + DILITHIUM_SIGNATURE_LEN;
                    if (chunk_len > op_offset) {
                        ptr[op_offset] = op_type;
                    }
                } else if (cur_method == 0x0007 && max_payload >= 32 && chunk_len >= 5 + sizeof(SclRpcHeader) + err_len + 32 && global_state) { // GetTransaction
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len, global_state->current_block_hash, 32);
                    hdr->payload_len = htobe32(32);
                    payload_len = 32;
                } else if (cur_method == 0x0009 && max_payload >= 8480 && chunk_len >= 5 + sizeof(SclRpcHeader) + err_len + 8480 && global_state) { // SyncWalletKeys
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len, global_state->user_wallet.dilithium_pubkey, 2592);
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len + 2592, global_state->user_wallet.dilithium_privkey, 4864);
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len + 2592 + 4864, &global_state->user_wallet.prf_key, sizeof(PRFKey));
                    hdr->payload_len = htobe32(8480);
                    payload_len = 8480;
                } else if (cur_method == 0x000A && max_payload >= 36 && chunk_len >= 5 + sizeof(SclRpcHeader) + err_len + 36) { // Quantum TVD Audit
                    uint32_t shots = (Seed % 50 == 0) ? ((Seed % 15000) + 10) : ((Seed % 500) + 10);
                    uint32_t shots_be = htobe32(shots);
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len, &shots_be, 4);
                    memset(ptr + 5 + sizeof(SclRpcHeader) + err_len + 4, (uint8_t)Seed, 32);
                    hdr->payload_len = htobe32(36);
                    payload_len = 36;
                } else if (cur_method == 0x000B && max_payload >= 9 && chunk_len >= 5 + sizeof(SclRpcHeader) + err_len + 9) { // Autopilot
                    ptr[5 + sizeof(SclRpcHeader) + err_len] = (Seed & 1);
                    uint32_t v_hr = htobe32((Seed % 10) + 1);
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len + 1, &v_hr, 4);
                    uint32_t s_rat = htobe32(Seed % 101);
                    memcpy(ptr + 5 + sizeof(SclRpcHeader) + err_len + 5, &s_rat, 4);
                    hdr->payload_len = htobe32(9);
                    payload_len = 9;
                }

                uint64_t now_ms = (uint64_t)time(NULL) * 1000 + (Seed & 0x3FF);
                hdr->request_id = htobe64((now_ms << 16) | (Seed & 0xFFFF));
                uint64_t csum = compute_rpc_checksum((const uint8_t*)hdr, err_len, payload_len, fuzz_conn->rpc_siphash_key);
                hdr->checksum = htobe64(csum);
            } else if ((msg_type == MSG_GOSSIP_BLOCK || msg_type == MSG_BLOCK_APPROVED || msg_type == MSG_BLOCKS_DATA) && chunk_len >= 5 + 8 + COIN_ID_LEN) {
                uint8_t *b_start = ptr + 5;
                uint64_t b_num = (Seed % 4 == 0) ? 0 : (global_state ? (global_state->current_block_number + 1) : (Seed % 100));
                uint64_t b_num_be = htobe64(b_num);
                memcpy(b_start, &b_num_be, 8);
                if (b_num == 0) {
                    memset(b_start + 8, 0, COIN_ID_LEN);
                } else if (global_state) {
                    memcpy(b_start + 8, global_state->current_block_hash, COIN_ID_LEN);
                }
            } else if (msg_type == MSG_VOTE && chunk_len >= 5 + PUBKEY_LEN + COIN_ID_LEN + 1) {
                uint8_t *v_start = ptr + 5;
                if (global_state) memcpy(v_start + PUBKEY_LEN, global_state->current_block_hash, COIN_ID_LEN);
                v_start[PUBKEY_LEN + COIN_ID_LEN] = (Seed & 1);
            } else if (msg_type == MSG_PENDING_OPERATION && chunk_len >= 6) {
                ptr[5] = (Seed >> 2) % 7;
            } else if (msg_type == MSG_GET_BLOCKS && chunk_len >= 5 + sizeof(uint64_t)) {
                uint64_t req_h = htobe64(global_state ? global_state->current_block_number : 0);
                memcpy(ptr + 5, &req_h, sizeof(uint64_t));
            } else if ((msg_type == MSG_DKG_COMMIT || msg_type == MSG_DKG_REVEAL || msg_type == MSG_DKG_PUBKEY_FRAG) && chunk_len >= 5 + COIN_ID_LEN + 2) {
                uint8_t epoch_sess[32];
                snprintf((char*)epoch_sess, 32, "DKG_EPOCH_0");
                SHA256(epoch_sess, strlen((char*)epoch_sess), ptr + 5);
                uint16_t pid_be = htobe16((Seed % 10) + 1);
                memcpy(ptr + 5 + COIN_ID_LEN, &pid_be, 2);
            } else if ((msg_type == MSG_EPOCH_SIGN_REQUEST || msg_type == MSG_EPOCH_PARTIAL_W || msg_type == MSG_EPOCH_CHALLENGE || msg_type == MSG_EPOCH_PARTIAL_Z) && chunk_len >= 5 + COIN_ID_LEN) {
                if (global_state) memcpy(ptr + 5, global_state->current_block_hash, COIN_ID_LEN);
            }
        }

        pos += 6 + chunk_len;
    }
    return new_size;
}
