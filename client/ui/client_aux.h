/**
 * @file client/ui/client_aux.h
 * @brief Satocialist Protocol: Terminal CLI User Interface & Auxiliary Operation Interfaces
 *
 * @details
 * Declares the interactive console menu routines, balance audit displays, manual/randomized
 * valuation vector generators, wallet viewers, blockchain ledger printers, off-chain Centinel
 * bearer ticket creation/redemption interfaces, and Auto-Pilot toggles for CLI node execution.
 *
 * @section ui_invariants User Interface Invariants
 * - Non-Destructive Display: Display and inspection functions operate under shared read locks
 *   without mutating on-chain ledger state or private wallet balances.
 * - Exact Integer Currency Representation: Display routines convert atomic subunits to whole SCL
 *   coins with exact 8-decimal precision (`subunits / 160,000,000.0`).
 * - Proof-of-Symmetry Range Integrity: Valuation vector generators constrain numbers strictly
 *   to integer bounds `[0, 99]`.
 *
 * @section thread_safety Thread Safety & Concurrency
 * - Menu execution runs on the main application thread. Functions query state while holding
 *   `state->mutex`, `user->mutex`, or `state->bc.rwlock` as needed.
 */

#ifndef CLIENT_AUX_H
#define CLIENT_AUX_H

#include <stdint.h>
#include <stddef.h>
#include "client_state.h"
#include "user.h"
#include "queue.h"
#include "game_state.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: BALANCE & LEDGER INSPECTION INTERFACES                            */
/* ============================================================================ */

/**
 * @brief Prints human-readable game rules and consensus instructions to stdout.
 *
 * @param[in] state Pointer to @ref GameState structure.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void show_instructions(GameState *state);

/**
 * @brief Displays liquid balances, staked capital, fees paid, and private validation UTXOs to stdout.
 *
 * @param[in] user Pointer to local @ref User account profile.
 * @param[in] state Pointer to global @ref State container.
 *
 * @thread_safety Acquires `state->mutex`, `user->mutex`, and `state->bc.rwlock` in read mode.
 * @complexity Time: O(total_pointers + total_utxos), Space: O(1).
 */
void show_balances(User *user, State *state);

/**
 * @brief Prints the entire blockchain coin and subunit range pointer ledger to stdout.
 *
 * @param[in] state Pointer to global @ref State container.
 *
 * @thread_safety Acquires `state->bc.rwlock` in read mode.
 * @complexity Time: O(total_coins * pointers_per_coin), Space: O(1).
 */
void display_blockchain(const State *state);

/**
 * @brief Displays economic issuance metrics, hard cap progress, and dynamic consensus stage to stdout.
 *
 * @param[in] state Pointer to global @ref State container.
 *
 * @thread_safety Acquires `state->bc.rwlock` and `state->game_state.mutex`.
 * @complexity Time: O(total_pointers), Space: O(1).
 */
void show_scl_coin_economics(const State *state);

/**
 * @brief Displays the local wallet's cryptographic keys, User ID, and viewport seed in hex format.
 *
 * @param[in] user Pointer to @ref User profile.
 * @param[in] state Pointer to global @ref State container.
 *
 * @thread_safety Acquires `state->wallet_mutex`.
 * @complexity Time: O(key_lengths), Space: O(hex_lengths) heap allocations.
 */
void view_wallet(User *user, State *state);

/**
 * @brief Displays the current 10x10 Game Audit circular valuation matrix in chronological order.
 *
 * @param[in] state Pointer to global @ref State container.
 *
 * @thread_safety Acquires snapshot lock via @ref acquire_game_state_snapshot.
 * @complexity Time: O(AUDIT_SIZE), Space: O(1).
 */
void display_audit(State *state);

/**
 * @brief Displays all created valuations currently stored in the local user array.
 *
 * @param[in] valuations Array of @ref Valuation structures.
 * @param[in] count Number of valuations in array.
 *
 * @complexity Time: O(count * NUMBERS_PER_VALUATION), Space: O(1).
 */
void display_all_valuations(const Valuation *valuations, int count);

/* ============================================================================ */
/* SECTION 2: VALUATION GENERATION & CENTINEL BEARER INSTRUMENTS                */
/* ============================================================================ */

/**
 * @brief Guides user through interactive manual creation and submission of valuation rows.
 *
 * @details
 * Prompts user for 10 integers in `[0, 99]`, burns required UTXO validation credits via
 * @ref consume_utxos_for_amount, signs the valuation data using Dilithium5, and enqueues
 * `MSG_VALUATION_PROPOSAL` to the submission queue.
 *
 * @param[in,out] valuations Pointer to dynamic array pointer of valuations.
 * @param[in,out] valuation_count Pointer to current valuation count.
 * @param[in,out] valuation_capacity Pointer to allocated array capacity.
 * @param[in] user Pointer to local @ref User profile.
 * @param[in,out] state Pointer to global node state container.
 *
 * @complexity Time: O(count * (CLI_input + Dilithium5_sign)), Space: O(count * sizeof(Valuation)).
 */
void create_valuations(Valuation **valuations, unsigned int *valuation_count, unsigned int *valuation_capacity,
                       User *user, State *state);

/**
 * @brief Automatically generates and submits random valuation vectors using CSPRNG entropy.
 *
 * @param[in,out] valuations Pointer to dynamic array pointer of valuations.
 * @param[in,out] valuation_count Pointer to current valuation count.
 * @param[in,out] valuation_capacity Pointer to allocated array capacity.
 * @param[in] user Pointer to local @ref User profile.
 * @param[in,out] state Pointer to global node state container.
 *
 * @complexity Time: O(count * (RAND_bytes + Dilithium5_sign)), Space: O(count * sizeof(Valuation)).
 */
void generate_valuations(Valuation **valuations, unsigned int *valuation_count, unsigned int *valuation_capacity,
                         User *user, State *state);

/**
 * @brief Encapsulates validation credits into an off-chain Centinel bearer instrument file (`.dat`).
 *
 * @details
 * Consumes local validation UTXOs, generates a zero-knowledge Stern proof binding BDLOP commitments,
 * broadcasts an `OP_REDEEM_CENTINEL` on-chain burn transaction, and serializes the bearer ticket
 * (`c_transfer`, `c_change`, `nullifier`, `zk_proof`, ephemeral keys) to disk.
 *
 * @param[in] user Pointer to local @ref User profile.
 * @param[in,out] state Pointer to global node state container.
 *
 * @complexity Time: O(ZK_proof_generation + disk_write), Space: O(ticket_file_size).
 */
void create_centinel(User *user, State *state);

/**
 * @brief Imports and redeems an off-chain Centinel bearer ticket file into private wallet balances.
 *
 * @param[in] user Pointer to local @ref User profile.
 * @param[in,out] state Pointer to global node state container.
 *
 * @complexity Time: O(ticket_parse + ZK_verify + broadcast), Space: O(ticket_size).
 */
void redeem_centinel(User *user, State *state);

/**
 * @brief Interactively configures and toggles the autonomous Auto-Pilot background daemon.
 *
 * @param[in,out] state Pointer to global node state container.
 *
 * @complexity Time: O(CLI_input), Space: O(1).
 */
void toggle_autopilot_interactive(State *state);

/**
 * @brief Displays the top-level interactive console menu and routes user selections.
 *
 * @param[in,out] user Pointer to local @ref User profile pointer.
 * @param[in,out] state Pointer to global node state container.
 * @param[in,out] valuations Dynamic array of local valuations.
 * @param[in,out] valuation_count Count of local valuations.
 * @param[in,out] valuation_capacity Capacity of valuations array.
 * @return 0 to continue execution loop; 1 to signal user exit.
 *
 * @complexity Time: O(CLI_menu_interaction), Space: O(1).
 */
int display_client_menu(User **user, State *state, Valuation **valuations,
                       unsigned int *valuation_count, unsigned int *valuation_capacity);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_AUX_H
