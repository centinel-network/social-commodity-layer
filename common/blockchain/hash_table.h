/**
 * @file common/blockchain/hash_table.h
 * @brief Satocialist Protocol: Concurrent Incremental Resizing Hash Table Interface
 *
 * @details
 * Declares data structures and function contracts for the high-performance concurrent hash table
 * used throughout the SCL protocol to index UTXO coins, subunit range pointers, confirmed transactions,
 * block proposers, orphan blocks, and threshold cryptographic state.
 *
 * @section algorithmic_architecture Algorithmic Architecture
 * - Separate Chaining: Buckets store singly-linked lists of @ref GenericHashEntry nodes.
 * - Incremental Split-Bucket Migration: When the load factor exceeds @ref LOAD_FACTOR_THRESHOLD (0.7),
 *   the table doubles its bucket capacity. Rather than stalling concurrent threads with a monolithic
 *   rehash, entries are migrated incrementally in discrete steps (16 buckets per step) during subsequent
 *   mutations, maintaining strict O(1) latency bounds.
 * - Two-Phase Lookups During Migration: During an active resize, lookups seamlessly probe both the
 *   primary bucket array (`ht->buckets`) and the migrating legacy array (`ht->old_buckets`).
 *
 * @section thread_safety Concurrency Model & Lock Hierarchy
 * - All table operations synchronize internally using a POSIX read-write lock (`ht->rwlock`).
 * - Lookups acquire shared read locks (`pthread_rwlock_rdlock`).
 * - Insertions, deletions, and migration steps acquire exclusive write locks (`pthread_rwlock_wrlock`).
 */

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* SECTION 1: HASH TABLE LIFECYCLE INTERFACES                                   */
/* ============================================================================ */

/**
 * @brief Initializes a generic concurrent HashTable instance.
 *
 * @details
 * Allocates the initial bucket array, configures key dimensional bounds, sets custom or default
 * hashing/comparison callbacks, and initializes the internal POSIX read-write lock (`ht->rwlock`).
 *
 * @param[out] ht Pointer to caller-allocated @ref HashTable structure.
 * @param[in] initial_size Initial number of hash buckets (must be power of two recommended).
 * @param[in] key_len Length of lookup keys in bytes (e.g., 32 for @ref COIN_ID_LEN).
 * @param[in] hash_fn Optional custom hash function pointer; NULL defaults to @ref hash_func.
 * @param[in] compare_fn Optional custom key comparison callback; NULL defaults to `memcmp`.
 * @param[in] free_entry_fn Optional cleanup callback for custom payload types.
 * @param[in] custom_insert_fn Optional conflict resolution callback for existing keys.
 * @return 0 on success; -1 on allocation or synchronization primitive failure.
 *
 * @pre `ht` must point to valid writable memory; `initial_size > 0`; `key_len > 0`.
 * @post `ht->buckets` allocated with calloc; `ht->count = 0`; `ht->rwlock` initialized.
 * @thread_safety Not thread-safe during initial setup. Caller must ensure exclusive access.
 * @complexity Time: O(initial_size), Space: O(initial_size) heap allocation.
 */
int hash_table_init(HashTable *ht, size_t initial_size, size_t key_len,
                    uint32_t (*hash_fn)(const uint8_t *, size_t),
                    int (*compare_fn)(const void *, const void *, size_t),
                    void (*free_entry_fn)(void *),
                    void (*custom_insert_fn)(HashTable *, GenericHashEntry *, const uint8_t *, void *, HashEntryType));

/**
 * @brief Releases all bucket memory, entries, and internal locks within a HashTable.
 *
 * @param[in,out] ht Pointer to @ref HashTable structure to finalize (safe if NULL).
 *
 * @pre No concurrent threads may be actively reading or modifying `ht`.
 * @post All bucket arrays, entries, dynamic payloads, and read-write locks are freed and destroyed.
 * @thread_safety Unsafe if called concurrently with active readers or writers.
 * @complexity Time: O(count + size), Space: O(1).
 */
void hash_table_destroy(HashTable *ht);

/**
 * @brief Purges all entries from the hash table while retaining bucket capacity.
 *
 * @details
 * Frees all allocated @ref GenericHashEntry nodes and resets `ht->count` to 0 under write lock.
 * If an incremental resize was in progress, frees `ht->old_buckets`.
 *
 * @param[in,out] ht Pointer to @ref HashTable structure (safe if NULL).
 *
 * @pre `ht` points to an initialized @ref HashTable structure.
 * @post All entries and old buckets freed; primary buckets retained and `ht->count` reset to 0.
 * @thread_safety Acquires `ht->rwlock` in write mode internally.
 * @complexity Time: O(count + size), Space: O(1).
 */
void hash_table_clear(HashTable *ht);

/* ============================================================================ */
/* SECTION 2: ACCESS & MUTATION INTERFACES                                      */
/* ============================================================================ */

/**
 * @brief Inserts or updates an entry in the hash table.
 *
 * @details
 * Calculates bucket index under write lock. If the key already exists:
 * - Invokes `ht->custom_insert_fn` if registered.
 * - Otherwise overwrites entry data via internal update routine.
 * If the key does not exist:
 * - Allocates a new @ref GenericHashEntry node.
 * - Copies `key` and initializes data payload according to `type`.
 * - Prepends node to the bucket chain and increments `ht->count`.
 * - Triggers non-blocking incremental resize if load factor exceeds 0.7.
 *
 * @param[in,out] ht Pointer to target @ref HashTable structure.
 * @param[in] key Pointer to key buffer of length `ht->key_len`.
 * @param[in] value Pointer to source data payload (ownership rules depend on `type`).
 * @param[in] type Type discriminator identifying the payload variant in @ref GenericHashEntry.
 * @return `true` on successful insertion/update; `false` on allocation or parameter error.
 *
 * @pre `ht` and `key` must be non-NULL; `value` non-NULL (except for @ref HASH_ENTRY_TX / @ref HASH_ENTRY_NULLIFIER).
 * @post Entry is inserted or updated; triggers incremental resize if load factor exceeds threshold.
 * @thread_safety Acquires `ht->rwlock` in write mode internally.
 * @complexity Time: O(1) expected, O(chain_length) worst case, Space: O(1) heap allocation.
 */
bool hash_table_insert(HashTable *ht, const uint8_t *key, void *value, HashEntryType type);

/**
 * @brief Queries an entry in the hash table by its binary key.
 *
 * @details
 * Probes the primary bucket array `ht->buckets`. If migrating, also probes `ht->old_buckets`
 * for indices not yet migrated.
 *
 * @param[in] ht Pointer to @ref HashTable structure.
 * @param[in] key Pointer to key buffer of length `ht->key_len`.
 * @param[in] return_entry Flag: `true` returns pointer to enclosing @ref GenericHashEntry;
 *                         `false` returns pointer to data payload via @ref get_entry_data.
 * @return Pointer to entry or data payload on match; NULL if key is not found.
 *
 * @pre `ht` and `key` must be non-NULL.
 * @warning The returned pointer remains valid only while the entry is not modified or deleted.
 * @thread_safety Acquires `ht->rwlock` in read mode internally.
 * @complexity Time: O(1) expected, O(chain_length) worst case, Space: O(1).
 */
void *hash_table_lookup(HashTable *ht, const uint8_t *key, bool return_entry);

/**
 * @brief Removes an entry matching the specified key from the hash table.
 *
 * @details
 * Unlinks the node from its bucket chain under write lock, performs type-specific resource
 * deallocation (e.g., freeing vote queues, threshold processes, or heap operations),
 * frees the @ref GenericHashEntry node, and decrements `ht->count`.
 *
 * @param[in,out] ht Pointer to @ref HashTable structure.
 * @param[in] key Pointer to key buffer of length `ht->key_len`.
 * @return `true` if key was found and removed; `false` if not found or on error.
 *
 * @pre `ht` and `key` must be non-NULL.
 * @post On match, entry node and associated dynamic resources are freed, and `ht->count` is decremented.
 * @thread_safety Acquires `ht->rwlock` in write mode internally.
 * @complexity Time: O(1) expected, O(chain_length) worst case, Space: O(1).
 */
bool hash_table_remove(HashTable *ht, const uint8_t *key);

/**
 * @brief Extracts the raw data payload pointer from an enclosing GenericHashEntry node.
 *
 * @param[in] entry Pointer to @ref GenericHashEntry node.
 * @return Pointer to internal data union member; NULL for sentinel types or invalid nodes.
 *
 * @pre `entry` must be non-NULL.
 * @thread_safety Reentrant; safe while entry is not concurrently modified or freed.
 * @complexity Time: O(1), Space: O(1).
 */
void *get_entry_data(GenericHashEntry *entry);

/* ============================================================================ */
/* SECTION 3: COIN-TO-POINTER INDEX MAPPING HELPERS                             */
/* ============================================================================ */

/**
 * @brief Indexes a Pointer identifier under its parent Coin identifier in the mapping table.
 *
 * @param[in,out] coin_pointers Pointer to the mapping @ref HashTable instance.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @param[in] pointer_id 32-byte pointer identifier to associate.
 *
 * @pre `coin_pointers`, `coin_id`, and `pointer_id` must be non-NULL.
 * @post Pointer association entry is created and prepended to the coin's collision chain in `coin_pointers`.
 * @thread_safety Acquires `coin_pointers->rwlock` in write mode internally.
 * @complexity Time: O(1) amortized, Space: O(1) heap allocation.
 */
void add_pointer_id_to_coin(HashTable *coin_pointers, const uint8_t *coin_id, const uint8_t *pointer_id);

/**
 * @brief Removes a Pointer identifier association from its parent Coin mapping entry.
 *
 * @param[in,out] coin_pointers Pointer to the mapping @ref HashTable instance.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @param[in] pointer_id 32-byte pointer identifier to disassociate.
 *
 * @pre `coin_pointers`, `coin_id`, and `pointer_id` must be non-NULL.
 * @post On match, pointer association is unlinked and freed from the coin's collision chain.
 * @thread_safety Acquires `coin_pointers->rwlock` in write mode internally.
 * @complexity Time: O(pointers_per_coin), Space: O(1).
 */
void remove_pointer_id_from_coin(HashTable *coin_pointers, const uint8_t *coin_id, const uint8_t *pointer_id);

#ifdef __cplusplus
}
#endif

#endif // HASH_TABLE_H
