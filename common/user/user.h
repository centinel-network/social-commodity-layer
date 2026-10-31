/**
 * @file common/user/user.h
 * @brief Satocialist Protocol: User Account Lifecycle, Identity & Validation Grants
 *
 * @details
 * Declares data structures and interface contracts for participant user account initialization,
 * public key lookups, periodic validation credit grants, and account resource deallocation.
 *
 * @section protocol_invariants Invariants Maintained
 * - User ID Derivation: Every User ID is deterministically evaluated as `SHA256(dilithium_pubkey, 2592)`.
 * - Validation Grant Frequency: Validation credits are awarded at discrete intervals bounded
 *   below by @ref VALIDATION_INTERVAL (3,600 seconds). No account may accrue grants faster
 *   than one grant per elapsed interval.
 * - Non-Custodial Balance Privacy: Initial and periodic validation credits for local accounts are shielded
 *   via homomorphic BDLOP lattice commitments and broadcast as @ref OP_CLAIM_VALIDATION transactions.
 *
 * @section threading_model Concurrency & Locking
 * - Each @ref User struct incorporates an internal mutex (`user->mutex`) serializing account-level
 *   validation timers and grant emissions.
 * - Access to the global user array and table requires acquiring `state->mutex` prior to calling
 *   user lookup or registration routines.
 */

#ifndef USER_H
#define USER_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "constants.h"
#include "blockchain.h"
#include "protocol.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* 1. USER ACCOUNT LIFECYCLE INTERFACES                                         */
/* ============================================================================ */

/**
 * @brief Initializes a User account structure bound to a post-quantum Dilithium5 public key.
 *
 * @details
 * Sets up the internal account mutex, derives the 32-byte User ID from the Dilithium5
 * public key via SHA-256, initializes the validation grant timer, and—if the account
 * matches the local node operator's wallet—provisions initial validation credits
 * as an encrypted BDLOP commitment on-chain.
 *
 * @param[out] user Pointer to uninitialized User struct to configure.
 * @param[in,out] state Global node state context.
 * @param[in] pubkey 2,592-byte Dilithium5 public verification key.
 * @return 0 on successful initialization; -1 on null pointer or synchronization failure.
 *
 * @pre `user`, `state`, and `pubkey` must be non-NULL.
 * @post `user->mutex` initialized; `user->user_id` contains `SHA256(pubkey)`.
 * @complexity Time: O(1) without initial grant, Space: O(1) auxiliary.
 */
int user_init(User *user, State *state, const uint8_t *pubkey);

/**
 * @brief Resolves an existing User account pointer matching a specified Dilithium5 public key.
 *
 * @details
 * First queries the local hash table index `state->user_table`. If absent, queries the
 * network peer address book and external peers, registering the account locally if verified.
 *
 * @param[in,out] state Global node state context.
 * @param[in] pubkey 2,592-byte Dilithium5 public key to look up.
 * @return Pointer to resolved User structure; NULL if the account is unregistered or unresolvable.
 *
 * @pre `state` and `pubkey` must be non-NULL.
 * @note Acquires `state->mutex` during table inspection.
 * @complexity Time: O(1) local cache hit; O(network timeout) on remote query.
 */
User *find_user_by_pubkey(State *state, const uint8_t *pubkey);

/**
 * @brief Evaluates eligibility and issues periodic validation credit grants to a user account.
 *
 * @details
 * Enforces the hourly rate limit (`time(NULL) - user->last_validation >= VALIDATION_INTERVAL`).
 * The grant volume scales according to the user's active staked capital and cumulative fees paid:
 * `credits = 1 + floor(staked_scl + fees_scl)`. For local accounts, the grant is converted into
 * a private BDLOP lattice commitment and broadcast via @ref OP_CLAIM_VALIDATION.
 *
 * @param[in,out] state Global node state context.
 * @param[in,out] user Target User account to evaluate.
 * @return 1 if a validation grant was successfully awarded; 0 if interval has not elapsed or on failure.
 *
 * @pre `state` and `user` must be non-NULL.
 * @post `user->last_validation` updated to current timestamp if grant is issued.
 * @note Acquires `user->mutex`. Internally evaluates threshold staking and fees without deadlocks.
 * @complexity Time: O(1) nominal; O(network broadcast) when broadcasting claim.
 */
int grant_validation(State *state, User *user);

/**
 * @brief Releases internal synchronization primitives associated with a User account.
 *
 * @param[in,out] user Pointer to User struct being deallocated.
 *
 * @pre `user->mutex` must be unlocked prior to destruction.
 * @post `user->mutex` destroyed via `pthread_mutex_destroy`.
 * @complexity Time: O(1), Space: O(1).
 */
void destroy_user(User *user);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // USER_H
