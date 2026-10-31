/**
 * @file common/blockchain/hash_table.c
 * @brief Satocialist Protocol: Concurrent Incremental Resizing Hash Table Implementation
 *
 * @details
 * Implements separate-chaining concurrent hash tables with incremental split-bucket rehashing,
 * type-discriminated payload storage, and two-phase concurrent lookups.
 *
 * @section algorithmic_mechanics Algorithmic Mechanics
 * - Incremental Rehashing: To eliminate pause-times associated with monolithic table doubling,
 *   when load factor exceeds @ref LOAD_FACTOR_THRESHOLD, `old_buckets` is retained and discrete
 *   migration steps (@ref hash_table_migrate_step, 16 buckets per step) migrate entries to the
 *   expanded bucket array during write operations.
 * - Dynamic Modulo Distribution: Hash indices are evaluated dynamically within caller-locked
 *   boundaries using `ht->hash_fn(key, ht->size)` to prevent race conditions during table doubling.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <errno.h>
#include "hash_table.h"
#include "user.h"
#include "constants.h"
#include "utils.h"

/* ============================================================================ */
/* SECTION 1: INTERNAL PAYLOAD SERIALIZATION & ENTRY MANAGEMENT                 */
/* ============================================================================ */

/**
 * @brief Updates entry data in-place without type revalidation (internal static routine).
 *
 * @param[in,out] entry Target hash entry node.
 * @param[in] value Source data pointer.
 * @param[in] type Type discriminator identifying the union member to update.
 *
 * @pre `entry` must be non-NULL; caller holds write lock.
 * @complexity Time: O(1), Space: O(1).
 */
static void update_entry_data(GenericHashEntry *entry, void *value, HashEntryType type) {
    switch (type) {
        case HASH_ENTRY_COIN:
            entry->data.coin = *(SCLCoin *)value;
            break;
        case HASH_ENTRY_POINTER:
            entry->data.pointer = *(Pointer *)value;
            break;
        case HASH_ENTRY_VOTE_QUEUE:
            entry->data.queue = value;
            break;
        case HASH_ENTRY_USER:
            entry->data.user = value;
            break;
        case HASH_ENTRY_BLOCK_PROPOSER:
            entry->data.proposer = value;
            break;
        case HASH_ENTRY_TX:
            break;
        case HASH_ENTRY_NULLIFIER:
            break;
        case HASH_ENTRY_OPERATION:
            if (entry->data.operation) free(entry->data.operation);
            entry->data.operation = malloc(sizeof(Operation));
            if (entry->data.operation && value) *entry->data.operation = *(Operation *)value;
            break;
        case HASH_ENTRY_VOTED_HEIGHT:
            memcpy(&entry->data.voted_height_rec, value, sizeof(entry->data.voted_height_rec));
            break;
        case HASH_ENTRY_THRESHOLD_STAKE_PROCESS:
            entry->data.threshold_stake_process = (ThresholdStakeProcess *)value;
            break;
        case HASH_ENTRY_PUBKEY_CACHE:
            memcpy(&entry->data.pubkey_cache, value, sizeof(PubkeyCacheEntry));
            break;
        case HASH_ENTRY_EPOCH_SIGN_DATA:
            entry->data.epoch_sign_data = value;
            break;
        case HASH_ENTRY_DKG_SESSION:
            entry->data.dkg_session = value;
            break;
        case HASH_ENTRY_ORPHAN_BLOCK:
            entry->data.orphan_block = (Block *)value;
            break;
        default:
            fprintf(stderr, "[HashTable] Invalid entry type: %d\n", type);
            break;
    }
}

/**
 * @brief Configures payload data in an allocated hash entry node with validation.
 *
 * @param[in,out] entry Pre-allocated hash entry node.
 * @param[in] value Pointer to source data payload.
 * @param[in] type Discriminator indicating value-copy or owned-pointer semantics.
 * @return `true` on successful assignment; `false` on NULL value or unsupported type.
 *
 * @complexity Time: O(1), Space: O(1).
 */
static bool set_entry_data(GenericHashEntry *entry, void *value, HashEntryType type) {
    if (!entry) {
        fprintf(stderr, "[HashTable] Invalid parameters in set_entry_data: entry=NULL\n");
        return false;
    }
    entry->type = type;
    switch (type) {
        case HASH_ENTRY_COIN:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_COIN\n");
                return false;
            }
            memcpy(&entry->data.coin, value, sizeof(SCLCoin));
            break;
        case HASH_ENTRY_POINTER:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_POINTER\n");
                return false;
            }
            memcpy(&entry->data.pointer, value, sizeof(Pointer));
            break;
        case HASH_ENTRY_VOTE_QUEUE:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_VOTE_QUEUE\n");
                return false;
            }
            entry->data.queue = (BlockVoteQueue *)value;
            break;
        case HASH_ENTRY_USER:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_USER\n");
                return false;
            }
            entry->data.user = (User *)value;
            break;
        case HASH_ENTRY_BLOCK_PROPOSER:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_BLOCK_PROPOSER\n");
                return false;
            }
            entry->data.proposer = (BlockProposerInfo *)value;
            break;
        case HASH_ENTRY_TX:
            if (value != NULL) {
                fprintf(stderr, "[HashTable] WARNING: value should be NULL for HASH_ENTRY_TX\n");
            }
            break;
        case HASH_ENTRY_NULLIFIER:
            if (value != NULL) {
                fprintf(stderr, "[HashTable] WARNING: value should be NULL for HASH_ENTRY_TX/NULLIFIER\n");
            }
            break;
        case HASH_ENTRY_OPERATION:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_OPERATION\n");
                return false;
            }
            entry->data.operation = malloc(sizeof(Operation));
            if (!entry->data.operation) return false;
            memcpy(entry->data.operation, value, sizeof(Operation));
            break;
        case HASH_ENTRY_VOTED_HEIGHT:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_VOTED_HEIGHT\n");
                return false;
            }
            memcpy(&entry->data.voted_height_rec, value, sizeof(entry->data.voted_height_rec));
            break;
        case HASH_ENTRY_THRESHOLD_STAKE_PROCESS:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_THRESHOLD_STAKE_PROCESS\n");
                return false;
            }
            entry->data.threshold_stake_process = (ThresholdStakeProcess *)value;
            break;
        case HASH_ENTRY_PUBKEY_CACHE:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_PUBKEY_CACHE\n");
                return false;
            }
            memcpy(&entry->data.pubkey_cache, value, sizeof(PubkeyCacheEntry));
            break;
        case HASH_ENTRY_EPOCH_SIGN_DATA:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_EPOCH_SIGN_DATA\n");
                return false;
            }
            entry->data.epoch_sign_data = (ThresholdSignData *)value;
            break;
        case HASH_ENTRY_DKG_SESSION:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_DKG_SESSION\n");
                return false;
            }
            entry->data.dkg_session = value;
            break;
        case HASH_ENTRY_ORPHAN_BLOCK:
            if (!value) {
                fprintf(stderr, "[HashTable] NULL value for HASH_ENTRY_ORPHAN_BLOCK\n");
                return false;
            }
            entry->data.orphan_block = (Block *)value;
            break;
        default:
            fprintf(stderr, "[HashTable] Unsupported entry type: %d\n", type);
            return false;
    }
    return true;
}

/* ============================================================================ */
/* SECTION 2: INCREMENTAL RESIZING & STEPPED MIGRATION                          */
/* ============================================================================ */

/**
 * @brief Initiates an incremental resize by allocating a doubled bucket array.
 *
 * @param[in,out] ht Hash table to resize.
 * @return `true` on successful allocation; `false` on memory exhaustion.
 *
 * @pre Caller must hold `ht->rwlock` in write mode (`pthread_rwlock_wrlock`).
 * @post `ht->old_buckets` holds prior bucket array; `ht->size` is doubled; `ht->resize_progress = 0`.
 * @complexity Time: O(1), Space: O(new_size) heap allocation.
 */
static bool hash_table_resize(HashTable *ht) {
    // Return immediately if incremental resizing is already in progress
    if (ht->old_buckets != NULL) return true;
    
    // Allocate doubled bucket array and stage existing buckets for incremental migration
    size_t new_size = ht->size * 2;
    GenericHashEntry **new_buckets = calloc(new_size, sizeof(GenericHashEntry *));
    if (!new_buckets) {
        fprintf(stderr, "[HashTable] Failed to allocate new buckets for resize\n");
        return false;
    }

    ht->old_buckets = ht->buckets;
    ht->old_size = ht->size;
    ht->buckets = new_buckets;
    ht->size = new_size;
    ht->resize_progress = 0;
    
    return true;
}

/**
 * @brief Migrates a fixed batch of buckets (16 buckets) from `old_buckets` to `buckets`.
 *
 * @details
 * Called incrementally during write operations to amortize rehashing cost across transactions.
 * When `resize_progress >= old_size`, frees `old_buckets` and concludes the migration phase.
 *
 * @param[in,out] ht Hash table undergoing active migration.
 *
 * @pre Caller must hold `ht->rwlock` in write mode.
 * @complexity Time: O(1) bounded by 16 buckets * average_chain_length, Space: O(1).
 */
static void hash_table_migrate_step(HashTable *ht) {
    if (ht->old_buckets == NULL) return;
    
    size_t steps = 16;
    // Migrate up to 16 bucket chains from old array to new array per step
    while (steps-- > 0 && ht->resize_progress < ht->old_size) {
        GenericHashEntry *entry = ht->old_buckets[ht->resize_progress];
        while (entry) {
            GenericHashEntry *next = entry->next;
            uint32_t new_index = ht->hash_fn(entry->key, ht->size);
            entry->next = ht->buckets[new_index];
            ht->buckets[new_index] = entry;
            entry = next;
        }
        ht->old_buckets[ht->resize_progress] = NULL;
        ht->resize_progress++;
    }
    
    // Conclude migration phase and release obsolete bucket array when completed
    if (ht->resize_progress >= ht->old_size) {
        free(ht->old_buckets);
        ht->old_buckets = NULL;
        ht->old_size = 0;
        ht->resize_progress = 0;
    }
}

/* ============================================================================ */
/* SECTION 3: ENTRY DATA EXTRACTION & TABLE INITIALIZATION                      */
/* ============================================================================ */

/**
 * @brief Extracts the raw data payload pointer from an enclosing GenericHashEntry node.
 *
 * @param[in] entry Pointer to @ref GenericHashEntry node.
 * @return Pointer to internal data union member; NULL for sentinel types or invalid nodes.
 *
 * @complexity Time: O(1), Space: O(1).
 */
void *get_entry_data(GenericHashEntry *entry) {
    switch (entry->type) {
        case HASH_ENTRY_COIN:
            return &entry->data.coin;
        case HASH_ENTRY_POINTER:
            return &entry->data.pointer;
        case HASH_ENTRY_VOTE_QUEUE:
            return entry->data.queue;
        case HASH_ENTRY_USER:
            return entry->data.user;
        case HASH_ENTRY_BLOCK_PROPOSER:
            return entry->data.proposer;
        case HASH_ENTRY_TX:
            return NULL;
        case HASH_ENTRY_NULLIFIER:
            return NULL;
        case HASH_ENTRY_OPERATION:
            return entry->data.operation;
        case HASH_ENTRY_VOTED_HEIGHT:
            return &entry->data.voted_height_rec;
        case HASH_ENTRY_THRESHOLD_STAKE_PROCESS:
            return entry->data.threshold_stake_process;
        case HASH_ENTRY_PUBKEY_CACHE:
            return &entry->data.pubkey_cache;
        case HASH_ENTRY_EPOCH_SIGN_DATA:
            return entry->data.epoch_sign_data;
        case HASH_ENTRY_DKG_SESSION:
            return entry->data.dkg_session;
        case HASH_ENTRY_ORPHAN_BLOCK:
            return entry->data.orphan_block;
        default:
            fprintf(stderr, "[HashTable] Invalid entry type: %d\n", entry->type);
            return NULL;
    }
}

/**
 * @brief Initializes a concurrent HashTable instance.
 *
 * @param[out] ht Caller-allocated @ref HashTable structure.
 * @param[in] initial_size Bucket count.
 * @param[in] key_len Byte length of keys.
 * @param[in] hash_fn Optional custom hash callback (defaults to @ref hash_func).
 * @param[in] compare_fn Optional custom comparison callback (defaults to `memcmp`).
 * @param[in] free_entry_fn Optional cleanup callback for custom types.
 * @param[in] custom_insert_fn Optional conflict resolution callback.
 * @return 0 on success; -1 on failure.
 *
 * @pre `ht` must point to allocated, writable memory; `initial_size > 0`; `key_len > 0`.
 * @post Bucket array is allocated, metadata configured, and `ht->rwlock` initialized.
 * @complexity Time: O(initial_size), Space: O(initial_size) heap allocation.
 */
int hash_table_init(HashTable *ht, size_t initial_size, size_t key_len,
                    uint32_t (*hash_fn)(const uint8_t *, size_t),
                    int (*compare_fn)(const void *, const void *, size_t),
                    void (*free_entry_fn)(void *),
                    void (*custom_insert_fn)(HashTable *, GenericHashEntry *, const uint8_t *, void *, HashEntryType)) {
    if (!ht) {
        scl_log(LOG_LEVEL_FATAL, "HashTable", "NULL hash table pointer");
        return -1;
    }
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (initial_size > 16) {
        initial_size = 16;
    }
#endif
    // Allocate primary bucket array
    ht->buckets = calloc(initial_size, sizeof(void *));
    if (!ht->buckets) {
        scl_log(LOG_LEVEL_FATAL, "HashTable", "Memory allocation failed");
        return -1;
    }
    // Initialize table state, callbacks, and read-write lock
    ht->old_buckets = NULL;
    ht->size = initial_size;
    ht->old_size = 0;
    ht->resize_progress = 0;
    ht->count = 0;
    ht->key_len = key_len;
    ht->hash_fn = hash_fn ? hash_fn : hash_func;
    ht->compare_fn = compare_fn ? compare_fn : memcmp;
    ht->free_entry_fn = free_entry_fn;
    ht->custom_insert_fn = custom_insert_fn;
    if (pthread_rwlock_init(&ht->rwlock, NULL) != 0) {
        free(ht->buckets);
        scl_log(LOG_LEVEL_FATAL, "HashTable", "RWLock Init Failed");
        return -1;
    }
    return 0;
}

/* ============================================================================ */
/* SECTION 4: CONCURRENT MUTATION & QUERY OPERATIONS                            */
/* ============================================================================ */

/**
 * @brief Inserts or updates an entry in the hash table under exclusive write lock.
 *
 * @param[in,out] ht Target hash table.
 * @param[in] key Lookup key of length `ht->key_len`.
 * @param[in] value Payload source pointer.
 * @param[in] type Payload variant tag.
 * @return `true` on success; `false` on parameter or memory error.
 *
 * @pre `ht` and `key` must be non-NULL; `value` non-NULL unless sentinel type.
 * @post Entry is inserted or updated; triggers incremental resize if load factor threshold is crossed.
 * @thread_safety Acquires `ht->rwlock` in write mode internally.
 * @complexity Time: O(1) expected, Space: O(1) heap allocation.
 */
bool hash_table_insert(HashTable *ht, const uint8_t *key, void *value, HashEntryType type) {
    if (!ht || !key || (value == NULL && type != HASH_ENTRY_TX && type != HASH_ENTRY_NULLIFIER)) {
        fprintf(stderr, "[HashTable] ERROR: Invalid insert parameters: ht=%p, key=%p, value=%p, type=%d\n",
                ht, key, value, type);
        return false;
    }

    if (pthread_rwlock_wrlock(&ht->rwlock) != 0) {
        fprintf(stderr, "[HashTable] ERROR: Failed to acquire write lock: errno=%d\n", errno);
        return false;
    }

    if (ht->buckets == NULL) {
        fprintf(stderr, "[HashTable] ERROR: Buckets array is NULL: size=%zu\n", ht->size);
        pthread_rwlock_unlock(&ht->rwlock);
        return false;
    }

    // Compute index dynamically *inside* the safe lock boundary
    if (ht->old_buckets) hash_table_migrate_step(ht);

    uint32_t index = ht->hash_fn(key, ht->size);
    if (index >= ht->size) {
        fprintf(stderr, "[HashTable] ERROR: Index out of bounds: index=%u, size=%zu\n", index, ht->size);
        pthread_rwlock_unlock(&ht->rwlock);
        return false;
    }

    // Search primary bucket chain for existing key to update in-place
    GenericHashEntry *entry = ht->buckets[index];
    while (entry) {
        if (ht->compare_fn(entry->key, key, ht->key_len) == 0) {
            if (ht->custom_insert_fn) {
                ht->custom_insert_fn(ht, entry, key, value, type);
            } else {
                update_entry_data(entry, value, type);
            }
            pthread_rwlock_unlock(&ht->rwlock);
            return true;
        }
        entry = entry->next;
    }
    
    // Check old buckets if table is undergoing active incremental resize
    if (ht->old_buckets) {
        uint32_t old_index = ht->hash_fn(key, ht->old_size);
        if (old_index >= ht->resize_progress) {
            GenericHashEntry *old_entry = ht->old_buckets[old_index];
            GenericHashEntry *prev = NULL;
            while (old_entry) {
                if (ht->compare_fn(old_entry->key, key, ht->key_len) == 0) {
                    if (ht->custom_insert_fn) {
                        ht->custom_insert_fn(ht, old_entry, key, value, type);
                    } else {
                        update_entry_data(old_entry, value, type);
                    }
                    // Migrate matching entry immediately to primary bucket chain
                    if (prev) prev->next = old_entry->next;
                    else ht->old_buckets[old_index] = old_entry->next;
                    
                    old_entry->next = ht->buckets[index];
                    ht->buckets[index] = old_entry;
                    
                    pthread_rwlock_unlock(&ht->rwlock);
                    return true;
                }
                prev = old_entry;
                old_entry = old_entry->next;
            }
        }
    }

    // Allocate and configure new hash entry node
    GenericHashEntry *new_entry = calloc(1, sizeof(GenericHashEntry));
    if (!new_entry) {
        fprintf(stderr, "[HashTable] ERROR: Memory allocation failed for new entry\n");
        pthread_rwlock_unlock(&ht->rwlock);
        return false;
    }

    memcpy(new_entry->key, key, ht->key_len);

    if (!set_entry_data(new_entry, value, type)) {
        fprintf(stderr, "[HashTable] ERROR: Failed to set entry data for key=");
        for (size_t i = 0; i < 8 && i < ht->key_len; i++) fprintf(stderr, "%02x", key[i]);
        fprintf(stderr, "\n");
        free(new_entry);
        pthread_rwlock_unlock(&ht->rwlock);
        return false;
    }

    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;
    ht->count++;

    // Trigger incremental resize if load factor exceeds threshold
    if ((float)ht->count / ht->size > LOAD_FACTOR_THRESHOLD) {
        if (!hash_table_resize(ht)) {
            fprintf(stderr, "[HashTable] ERROR: Failed to resize hash table from size=%zu\n", ht->size);
        }
    }

    pthread_rwlock_unlock(&ht->rwlock);
    return true;
}

/**
 * @brief Queries an entry in the hash table under shared read lock.
 *
 * @param[in] ht Target hash table.
 * @param[in] key Key buffer to find.
 * @param[in] return_entry `true` returns @ref GenericHashEntry*; `false` returns data payload.
 * @return Pointer to entry or payload on match; NULL if absent.
 *
 * @pre `ht` and `key` must be non-NULL.
 * @thread_safety Acquires `ht->rwlock` in read mode internally.
 * @complexity Time: O(1) expected, Space: O(1).
 */
void *hash_table_lookup(HashTable *ht, const uint8_t *key, bool return_entry) {
    if (!ht || !key) {
        fprintf(stderr, "[HashTable] Invalid lookup parameters: ht=%p, key=%p\n", ht, key);
        return NULL;
    }
    
    if (!ht->hash_fn) {
        fprintf(stderr, "[HashTable] ERROR: hash_fn is NULL\n");
        return NULL;
    }

    pthread_rwlock_rdlock(&ht->rwlock);

    if (ht->buckets == NULL) {
        fprintf(stderr, "[HashTable] ERROR: buckets is NULL for ht=%p, size=%zu\n", ht, ht->size);
        pthread_rwlock_unlock(&ht->rwlock);
        return NULL;
    }

    // Compute index dynamically *inside* the safe lock boundary
    uint32_t index = ht->hash_fn(key, ht->size);

    if (index >= ht->size) {
        fprintf(stderr, "[HashTable] ERROR: index %u out of bounds for ht=%p, size=%zu\n", index, ht, ht->size);
        pthread_rwlock_unlock(&ht->rwlock);
        return NULL;
    }

    // Search primary bucket chain for matching key
    GenericHashEntry *entry = ht->buckets[index];
    while (entry) {
        if (ht->compare_fn(entry->key, key, ht->key_len) == 0) {
            void *result = return_entry ? entry : get_entry_data(entry);
            pthread_rwlock_unlock(&ht->rwlock);
            return result;
        }
        entry = entry->next;
    }
    
    // Search unmigrated old buckets if table is undergoing active resize
    if (ht->old_buckets) {
        uint32_t old_index = ht->hash_fn(key, ht->old_size);
        if (old_index >= ht->resize_progress) {
            GenericHashEntry *old_entry = ht->old_buckets[old_index];
            while (old_entry) {
                if (ht->compare_fn(old_entry->key, key, ht->key_len) == 0) {
                    void *result = return_entry ? old_entry : get_entry_data(old_entry);
                    pthread_rwlock_unlock(&ht->rwlock);
                    return result;
                }
                old_entry = old_entry->next;
            }
        }
    }

    pthread_rwlock_unlock(&ht->rwlock);
    return NULL;
}

/**
 * @brief Removes an entry from the hash table and frees associated memory.
 *
 * @param[in,out] ht Target hash table.
 * @param[in] key Key of entry to delete.
 * @return `true` if found and removed; `false` otherwise.
 *
 * @pre `ht` and `key` must be non-NULL.
 * @post On match, entry node and associated dynamic payloads are freed.
 * @thread_safety Acquires `ht->rwlock` in write mode internally.
 * @complexity Time: O(1) expected, Space: O(1).
 */
bool hash_table_remove(HashTable *ht, const uint8_t *key) {
    if (!ht || !key) {
        fprintf(stderr, "[HashTable] Invalid parameters: ht=%p, key=%p\n", ht, key);
        return false;
    }

    if (pthread_rwlock_wrlock(&ht->rwlock) != 0) {
        fprintf(stderr, "[HashTable] Failed to acquire write lock for ht=%p\n", ht);
        return false;
    }

    if (!ht->buckets) {
        fprintf(stderr, "[HashTable] ERROR: buckets is NULL for ht=%p\n", ht);
        pthread_rwlock_unlock(&ht->rwlock);
        return false;
    }

    if (ht->old_buckets) hash_table_migrate_step(ht);

    // Compute index dynamically *inside* the safe lock boundary
    uint32_t index = ht->hash_fn(key, ht->size);
    if (index >= ht->size) {
        fprintf(stderr, "[HashTable] ERROR: index %u out of bounds for ht=%p, size=%zu\n", index, ht, ht->size);
        pthread_rwlock_unlock(&ht->rwlock);
        return false;
    }

    // Search primary bucket chain and unlink matching node
    GenericHashEntry *entry = ht->buckets[index];
    GenericHashEntry *prev = NULL;
    bool removed = false;
    
    while (entry) {
        if (ht->compare_fn(entry->key, key, ht->key_len) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                ht->buckets[index] = entry->next;
            }
            removed = true;
            break;
        }
        prev = entry;
        entry = entry->next;
    }
    
    // Search unmigrated old buckets if node was not found in primary chain
    if (!removed && ht->old_buckets) {
        uint32_t old_index = ht->hash_fn(key, ht->old_size);
        if (old_index >= ht->resize_progress) {
            entry = ht->old_buckets[old_index];
            prev = NULL;
            while (entry) {
                if (ht->compare_fn(entry->key, key, ht->key_len) == 0) {
                    if (prev) prev->next = entry->next;
                    else ht->old_buckets[old_index] = entry->next;
                    removed = true;
                    break;
                }
                prev = entry;
                entry = entry->next;
            }
        }
    }
    
    // Release dynamic memory held by entry payload and node structure
    if (removed && entry) {
        if (entry->type == HASH_ENTRY_THRESHOLD_STAKE_PROCESS) {
            free_threshold_process(entry->data.threshold_stake_process);
        } else if (entry->type == HASH_ENTRY_EPOCH_SIGN_DATA) {
            if (entry->data.epoch_sign_data) {
                cleanup_sign_data(entry->data.epoch_sign_data);
                free(entry->data.epoch_sign_data);
            }
        } else if (entry->type == HASH_ENTRY_DKG_SESSION) {
            if (entry->data.dkg_session) {
                free_dkg_session(entry->data.dkg_session);
            }
        } else if (entry->type == HASH_ENTRY_ORPHAN_BLOCK) {
            if (entry->data.orphan_block) {
                free_block(entry->data.orphan_block);
            }
        } else if (entry->type == HASH_ENTRY_BLOCK_PROPOSER) {
            if (entry->data.proposer) {
                free(entry->data.proposer);
            }
        } else if (entry->type == HASH_ENTRY_OPERATION && entry->data.operation) {
            free(entry->data.operation);
        }
        free(entry);
        ht->count--;
        pthread_rwlock_unlock(&ht->rwlock);
        return true;
    }
    pthread_rwlock_unlock(&ht->rwlock);
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    char hex_key[9];
    bytes_to_hex(key, 4, hex_key);
    fprintf(stderr, "[HashTable] Key not found: %s\n", hex_key);
#endif
    return false;
}

/* ============================================================================ */
/* SECTION 5: TEARDOWN & COIN-TO-POINTER INDEX HELPERS                          */
/* ============================================================================ */

/**
 * @brief Destroys a hash table, frees all entries, and destroys internal locks.
 *
 * @param[in,out] ht Target hash table (safe if NULL).
 *
 * @pre Caller must ensure no other concurrent threads are accessing `ht`.
 * @post All bucket arrays, entries, payloads, and read-write locks are deallocated.
 * @complexity Time: O(count + size), Space: O(1).
 */
void hash_table_destroy(HashTable *ht) {
    if (!ht) return;

    // Acquire write lock prior to tearing down internal bucket chains
    pthread_rwlock_wrlock(&ht->rwlock);
    
    // Deallocate entries and payload resources from primary bucket array
    for (size_t i = 0; i < ht->size; i++) {
        GenericHashEntry *entry = ht->buckets[i];
        while (entry) {
            GenericHashEntry *next = entry->next;
            if (entry->type == HASH_ENTRY_VOTE_QUEUE && entry->data.queue) {
                BlockVoteQueue *queue = entry->data.queue;
                pthread_mutex_destroy(&queue->vote_lock);
                pthread_cond_destroy(&queue->cond);
                free(queue->votes);
                free(queue);
            } else if (entry->type == HASH_ENTRY_THRESHOLD_STAKE_PROCESS) {
                free_threshold_process(entry->data.threshold_stake_process);
            } else if (entry->type == HASH_ENTRY_EPOCH_SIGN_DATA && entry->data.epoch_sign_data) {
                cleanup_sign_data(entry->data.epoch_sign_data);
                free(entry->data.epoch_sign_data);
            } else if (entry->type == HASH_ENTRY_DKG_SESSION && entry->data.dkg_session) {
                free_dkg_session(entry->data.dkg_session);
            } else if (entry->type == HASH_ENTRY_ORPHAN_BLOCK && entry->data.orphan_block) {
                free_block(entry->data.orphan_block);
            } else if (entry->type == HASH_ENTRY_BLOCK_PROPOSER && entry->data.proposer) {
                free(entry->data.proposer);
            }
            free(entry);
            entry = next;
        }
    }
    free(ht->buckets);
    ht->buckets = NULL;
    ht->size = 0;
    
    // Deallocate remaining entries from old bucket array if resize was in progress
    if (ht->old_buckets) {
        for (size_t i = ht->resize_progress; i < ht->old_size; i++) {
            GenericHashEntry *entry = ht->old_buckets[i];
            while (entry) {
                GenericHashEntry *next = entry->next;
                if (entry->type == HASH_ENTRY_VOTE_QUEUE && entry->data.queue) {
                    BlockVoteQueue *queue = entry->data.queue;
                    pthread_mutex_destroy(&queue->vote_lock);
                    pthread_cond_destroy(&queue->cond);
                    free(queue->votes);
                    free(queue);
                } else if (entry->type == HASH_ENTRY_THRESHOLD_STAKE_PROCESS) {
                    free_threshold_process(entry->data.threshold_stake_process);
                } else if (entry->type == HASH_ENTRY_EPOCH_SIGN_DATA && entry->data.epoch_sign_data) {
                    cleanup_sign_data(entry->data.epoch_sign_data);
                    free(entry->data.epoch_sign_data);
                } else if (entry->type == HASH_ENTRY_DKG_SESSION && entry->data.dkg_session) {
                    free_dkg_session(entry->data.dkg_session);
                } else if (entry->type == HASH_ENTRY_ORPHAN_BLOCK && entry->data.orphan_block) {
                    free_block(entry->data.orphan_block);
                } else if (entry->type == HASH_ENTRY_BLOCK_PROPOSER && entry->data.proposer) {
                    free(entry->data.proposer);
                }
                free(entry);
                entry = next;
            }
        }
        free(ht->old_buckets);
        ht->old_buckets = NULL;
        ht->old_size = 0;
        ht->resize_progress = 0;
    }
    ht->count = 0;
    
    pthread_rwlock_unlock(&ht->rwlock);
    pthread_rwlock_destroy(&ht->rwlock);
}

/**
 * @brief Purges all entries from the hash table under write lock while preserving buckets.
 *
 * @param[in,out] ht Target hash table (safe if NULL).
 *
 * @post Table entry count is reset to 0; all entries and old buckets freed; primary buckets retained.
 * @thread_safety Acquires `ht->rwlock` in write mode internally.
 * @complexity Time: O(count + size), Space: O(1).
 */
void hash_table_clear(HashTable *ht) {
    if (!ht) return;
    if (ht->count == 0 && ht->old_buckets == NULL) return;

    // Purge entries from primary bucket array while preserving bucket allocations
    pthread_rwlock_wrlock(&ht->rwlock);
    
    for (size_t i = 0; i < ht->size; i++) {
        GenericHashEntry *entry = ht->buckets[i];
        while (entry) {
            GenericHashEntry *next = entry->next;
            if (entry->type == HASH_ENTRY_VOTE_QUEUE && entry->data.queue) {
                BlockVoteQueue *queue = entry->data.queue;
                pthread_mutex_destroy(&queue->vote_lock);
                pthread_cond_destroy(&queue->cond);
                free(queue->votes);
                free(queue);
            } else if (entry->type == HASH_ENTRY_THRESHOLD_STAKE_PROCESS) {
                free_threshold_process(entry->data.threshold_stake_process);
            } else if (entry->type == HASH_ENTRY_EPOCH_SIGN_DATA && entry->data.epoch_sign_data) {
                cleanup_sign_data(entry->data.epoch_sign_data);
                free(entry->data.epoch_sign_data);
            } else if (entry->type == HASH_ENTRY_DKG_SESSION && entry->data.dkg_session) {
                free_dkg_session(entry->data.dkg_session);
            } else if (entry->type == HASH_ENTRY_ORPHAN_BLOCK && entry->data.orphan_block) {
                free_block(entry->data.orphan_block);
            } else if (entry->type == HASH_ENTRY_BLOCK_PROPOSER && entry->data.proposer) {
                free(entry->data.proposer);
            } else if (entry->type == HASH_ENTRY_OPERATION && entry->data.operation) {
                free(entry->data.operation);
            }
            free(entry);
            entry = next;
        }
        ht->buckets[i] = NULL;
    }
    
    // Purge remaining entries from old bucket array if resize was active
    if (ht->old_buckets) {
        for (size_t i = ht->resize_progress; i < ht->old_size; i++) {
            GenericHashEntry *entry = ht->old_buckets[i];
            while (entry) {
                GenericHashEntry *next = entry->next;
                if (entry->type == HASH_ENTRY_VOTE_QUEUE && entry->data.queue) {
                    BlockVoteQueue *queue = entry->data.queue;
                    pthread_mutex_destroy(&queue->vote_lock);
                    pthread_cond_destroy(&queue->cond);
                    free(queue->votes);
                    free(queue);
                } else if (entry->type == HASH_ENTRY_THRESHOLD_STAKE_PROCESS) {
                    free_threshold_process(entry->data.threshold_stake_process);
                } else if (entry->type == HASH_ENTRY_EPOCH_SIGN_DATA && entry->data.epoch_sign_data) {
                    cleanup_sign_data(entry->data.epoch_sign_data);
                    free(entry->data.epoch_sign_data);
                } else if (entry->type == HASH_ENTRY_DKG_SESSION && entry->data.dkg_session) {
                    free_dkg_session(entry->data.dkg_session);
                } else if (entry->type == HASH_ENTRY_ORPHAN_BLOCK && entry->data.orphan_block) {
                    free_block(entry->data.orphan_block);
                } else if (entry->type == HASH_ENTRY_BLOCK_PROPOSER && entry->data.proposer) {
                    free(entry->data.proposer);
                } else if (entry->type == HASH_ENTRY_OPERATION && entry->data.operation) {
                    free(entry->data.operation);
                }
                free(entry);
                entry = next;
            }
        }
        free(ht->old_buckets);
        ht->old_buckets = NULL;
        ht->old_size = 0;
        ht->resize_progress = 0;
    }
    ht->count = 0;
    
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && !defined(SCL_UNIT_TEST)
    if (ht->size > 16) {
        free(ht->buckets);
        ht->size = 16;
        ht->buckets = calloc(16, sizeof(GenericHashEntry *));
    }
#endif

    pthread_rwlock_unlock(&ht->rwlock);
}

/**
 * @brief Indexes a Pointer identifier under its parent Coin identifier in the mapping table.
 *
 * @param[in,out] coin_pointers Mapping table instance.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @param[in] pointer_id 32-byte pointer identifier.
 *
 * @pre `coin_pointers`, `coin_id`, and `pointer_id` must be non-NULL.
 * @post Pointer association is prepended to the coin's collision chain in `coin_pointers`.
 * @thread_safety Acquires `coin_pointers->rwlock` in write mode internally.
 * @complexity Time: O(1) amortized, Space: O(1) heap allocation.
 */
void add_pointer_id_to_coin(HashTable *coin_pointers, const uint8_t *coin_id, const uint8_t *pointer_id) {
    if (!coin_pointers || !coin_id || !pointer_id) {
        fprintf(stderr, "[HashTable] Invalid parameters in add_pointer_id_to_coin\n");
        return;
    }

    pthread_rwlock_wrlock(&coin_pointers->rwlock);
    
    GenericHashEntry *new_entry = calloc(1, sizeof(GenericHashEntry));
    if (new_entry) {
        memcpy(new_entry->key, coin_id, COIN_ID_LEN);
        new_entry->type = HASH_ENTRY_POINTER;
        memcpy(new_entry->data.pointer.parent_coin_id, coin_id, COIN_ID_LEN);
        memcpy(new_entry->data.pointer.pointer_id, pointer_id, COIN_ID_LEN);
        new_entry->next = NULL;

        uint32_t index = coin_pointers->hash_fn(coin_id, coin_pointers->size);
        new_entry->next = coin_pointers->buckets[index];
        coin_pointers->buckets[index] = new_entry;
        coin_pointers->count++;
    }
    
    pthread_rwlock_unlock(&coin_pointers->rwlock);
}

/**
 * @brief Removes a Pointer identifier association from its parent Coin mapping entry.
 *
 * @param[in,out] coin_pointers Mapping table instance.
 * @param[in] coin_id 32-byte parent coin identifier.
 * @param[in] pointer_id 32-byte pointer identifier.
 *
 * @pre `coin_pointers`, `coin_id`, and `pointer_id` must be non-NULL.
 * @post On match, pointer entry is unlinked and freed from the coin's collision chain.
 * @thread_safety Acquires `coin_pointers->rwlock` in write mode internally.
 * @complexity Time: O(pointers_per_coin), Space: O(1).
 */
void remove_pointer_id_from_coin(HashTable *coin_pointers, const uint8_t *coin_id, const uint8_t *pointer_id) {
    if (!coin_pointers || !coin_id || !pointer_id) {
        fprintf(stderr, "[HashTable] Invalid parameters in remove_pointer_id_from_coin\n");
        return;
    }

    pthread_rwlock_wrlock(&coin_pointers->rwlock);
    uint32_t index = coin_pointers->hash_fn(coin_id, coin_pointers->size);
    GenericHashEntry *entry = coin_pointers->buckets[index];
    GenericHashEntry *prev = NULL;

    // Traverse bucket chain to find and unlink matching pointer association
    while (entry) {
        if (entry->type == HASH_ENTRY_POINTER &&
            memcmp(entry->key, coin_id, COIN_ID_LEN) == 0 &&
            memcmp(entry->data.pointer.pointer_id, pointer_id, COIN_ID_LEN) == 0) {
            
            if (prev) {
                prev->next = entry->next;
            } else {
                coin_pointers->buckets[index] = entry->next;
            }
            free(entry);
            coin_pointers->count--;
            break;
        }
        prev = entry;
        entry = entry->next;
    }

    pthread_rwlock_unlock(&coin_pointers->rwlock);
}
