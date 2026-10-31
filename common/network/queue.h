/**
 * @file common/network/queue.h
 * @brief Satocialist Protocol: Thread-Safe FIFO Message Queue Interfaces
 *
 * @details
 * Declares data structures and synchronization primitives for thread-safe first-in,
 * first-out (FIFO) message queuing between transport multiplexers, consensus workers,
 * and P2P gossip pipelines.
 *
 * @section queue_invariants Enforced Invariants
 * - Strict FIFO Ordering: Elements are dequeued in the exact temporal sequence in which they were enqueued.
 * - Dynamic Compact Allocation: Payload memory allocations scale strictly with `msg->length`,
 *   preventing static 8 MiB allocations per queued message.
 *
 * @section memory_ownership Memory Ownership Model
 * - Enqueue: Deep-copies only the logical payload slice (`offsetof(Message, payload) + msg->length`),
 *   transferring heap node ownership to the queue.
 * - Dequeue: Copies message metadata and populated payload slice into caller-provided buffer,
 *   freeing the internal queue node and message container immediately.
 * - Destroy: Traverses and frees all remaining unread nodes, safely resetting head and tail pointers.
 *
 * @section thread_safety Thread Safety & Concurrency
 * - All operations (`enqueue`, `dequeue`, `has_items`, `destroy`) synchronize internally
 *   via `q->mutex`.
 * - Reentrant calls on the same queue from the same thread without releasing the lock
 *   will result in deadlock.
 */

#ifndef QUEUE_H
#define QUEUE_H

#include "protocol.h"
#include <pthread.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================ */
/* 1. QUEUE LIFECYCLE & MUTATION INTERFACES                                     */
/* ============================================================================ */

/**
 * @brief Initializes a thread-safe FIFO Message queue.
 *
 * @param[out] q Pointer to uninitialized Queue structure to configure.
 *
 * @pre `q` must point to valid, allocated memory.
 * @post `q->head` and `q->tail` set to NULL; `q->mutex` initialized.
 * @complexity Time: O(1), Space: O(1).
 */
void queue_init(Queue *q);

/**
 * @brief Enqueues a network Message into the FIFO queue with deep-copy heap allocation.
 *
 * @details
 * Dynamically allocates a new @ref QueueNode and a compact Message buffer sized exactly to
 * `offsetof(Message, payload) + msg->length`, eliminating memory bloat from unused MAX_MESSAGE_SIZE padding.
 * Appends node to queue tail under mutex protection.
 *
 * @param[in,out] q Target Queue structure.
 * @param[in] msg Source Message to copy and enqueue.
 * @return 0 on successful enqueue; -1 on memory allocation failure or invalid parameters.
 *
 * @pre `q` and `msg` must be non-NULL; `msg->length <= MAX_MESSAGE_SIZE`.
 * @post New node linked at `q->tail`; queue length increased by 1.
 * @note Thread-safe. Acquires and releases `q->mutex`.
 * @complexity Time: O(msg->length) for payload copy, Space: O(msg->length) heap allocation.
 */
int queue_enqueue(Queue *q, const Message *msg);

/**
 * @brief Dequeues the oldest Message from the queue into a caller-supplied buffer.
 *
 * @details
 * Removes node from `q->head`, copies message type, length, and payload slice into `msg`,
 * and frees internal heap allocations immediately.
 *
 * @param[in,out] q Target Queue structure.
 * @param[out] msg Destination Message buffer receiving dequeued data.
 * @return 0 on successful dequeue; -1 if queue is empty or parameters are NULL.
 *
 * @pre `q` and `msg` must be non-NULL.
 * @post `q->head` advanced to subsequent node; freed node memory reclaimed.
 * @note Thread-safe. Acquires and releases `q->mutex`.
 * @complexity Time: O(msg->length) for payload copy, Space: O(1) auxiliary.
 */
int queue_dequeue(Queue *q, Message *msg);

/**
 * @brief Thread-safe inspection predicate checking whether the queue contains any pending items.
 *
 * @param[in,out] q Target Queue structure.
 * @return 1 if queue contains one or more items (`q->head != NULL`); 0 if empty or NULL.
 *
 * @note Thread-safe. Acquires and releases `q->mutex`.
 * @complexity Time: O(1), Space: O(1).
 */
int queue_has_items(Queue *q);

/**
 * @brief Drains all remaining messages from the queue and destroys the internal mutex.
 *
 * @param[in,out] q Target Queue structure to finalize.
 *
 * @pre Queue must not be actively accessed by concurrent threads during destruction.
 * @post All internal nodes and messages freed; `q->head` and `q->tail` NULL; `q->mutex` destroyed.
 * @complexity Time: O(N) where N is queued nodes, Space: O(1).
 */
void queue_destroy(Queue *q);

#ifdef __cplusplus
}
#endif

#endif // QUEUE_H
