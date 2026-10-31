/**
 * @file common/network/queue.c
 * @brief Satocialist Protocol: Thread-Safe FIFO Message Queue Implementation
 *
 * @details
 * Implements singly-linked FIFO queuing routines with mutex-protected enqueue, dequeue,
 * inspection, and memory reclamation operations. Enforces compact dynamic allocation
 * proportional strictly to populated payload byte lengths.
 *
 * @section queue_invariants Enforced Invariants
 * - Strict FIFO Ordering: Elements are dequeued in the exact temporal sequence in which they were enqueued.
 * - Dynamic Compact Allocation: Payload memory allocations scale strictly with `msg->length`,
 *   preventing static 8 MiB allocations per queued message.
 *
 * @section memory_model Memory Architecture
 * - Queue nodes (@ref QueueNode) and message containers are allocated on the heap during enqueue.
 * - Slices allocated are bounded strictly by `offsetof(Message, payload) + msg->length`,
 *   preventing static 8 MiB allocations per queued message.
 * - Dequeued nodes are immediately unlinked, their payload memory freed, and node descriptors recycled.
 *
 * @section concurrency_model Synchronization Guarantees
 * - Operations acquire `q->mutex` unconditionally for the critical linked-list pointer updates.
 * - Lock holds are strictly localized to node pointer assignment and shallow buffer copying.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include "queue.h"
#include "utils.h"

#define fprintf scl_fprintf
#define printf scl_printf

/* ============================================================================ */
/* 1. QUEUE INITIALIZATION & INSPECTION                                         */
/* ============================================================================ */

void queue_init(Queue *q) {
    if (!q) {
        fprintf(stderr, "[Queue] Invalid queue pointer in queue_init\n");
        return;
    }
    // Initialize head and tail sentinels to NULL and instantiate mutex
    q->head = NULL;
    q->tail = NULL;
    pthread_mutex_init(&q->mutex, NULL);
}

int queue_has_items(Queue *q) {
    if (!q) {
        fprintf(stderr, "[Queue] Invalid queue pointer in queue_has_items\n");
        return 0;
    }
    // Protect linked-list head pointer read across thread boundaries
    pthread_mutex_lock(&q->mutex);
    int result = (q->head != NULL);
    pthread_mutex_unlock(&q->mutex);
    return result;
}

/* ============================================================================ */
/* 2. ENQUEUE & DEQUEUE PIPELINES                                               */
/* ============================================================================ */

int queue_enqueue(Queue *q, const Message *msg) {
    if (!q || !msg) {
        fprintf(stderr, "[Queue] Invalid queue or message pointer in queue_enqueue\n");
        return -1;
    }

    // Allocate singly-linked queue node descriptor
    QueueNode *node = malloc(sizeof(QueueNode));
    if (!node) {
        fprintf(stderr, "[Queue] Memory allocation failed in queue_enqueue\n");
        return -1;
    }

    // Allocate compact slice (header + populated payload) to avoid static MAX_MESSAGE_SIZE (8 MiB) bloat
    size_t msg_size = offsetof(Message, payload) + msg->length;
    node->msg = malloc(msg_size);
    if (!node->msg) {
        fprintf(stderr, "[Queue] Memory allocation failed for message in queue_enqueue\n");
        free(node);
        return -1;
    }

    // Populate message metadata and copy logical payload slice
    node->msg->type = msg->type;
    node->msg->length = msg->length;
    if (msg->length > 0) {
        memcpy(node->msg->payload, msg->payload, msg->length);
    }
    node->next = NULL;

    // Critical section: append node to tail of FIFO list
    pthread_mutex_lock(&q->mutex);
    if (!q->head) {
        q->head = q->tail = node;
    } else {
        q->tail->next = node;
        q->tail = node;
    }
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

int queue_dequeue(Queue *q, Message *msg) {
    if (!q || !msg) {
        fprintf(stderr, "[Queue] Invalid queue or message pointer in queue_dequeue\n");
        return -1;
    }

    // Critical section: unlink node from head of FIFO list
    pthread_mutex_lock(&q->mutex);
    if (!q->head) {
        pthread_mutex_unlock(&q->mutex);
        return -1; // Queue is empty
    }
    QueueNode *node = q->head;

    // Copy populated message metadata and payload slice into caller's destination buffer
    msg->type = node->msg->type;
    msg->length = node->msg->length;
    if (node->msg->length > 0) {
        memcpy(msg->payload, node->msg->payload, node->msg->length);
    }

    // Advance head cursor; reset tail if queue is now completely drained
    q->head = node->next;
    if (!q->head) {
        q->tail = NULL;
    }

    // Reclaim internal heap allocations immediately upon dequeue
    free(node->msg);
    free(node);
    pthread_mutex_unlock(&q->mutex);
    return 0;
}

/* ============================================================================ */
/* 3. TEARDOWN & RECLAMATION                                                    */
/* ============================================================================ */

void queue_destroy(Queue *q) {
    if (!q) {
        fprintf(stderr, "[Queue] Invalid queue pointer in queue_destroy\n");
        return;
    }

    // Drain all surviving queue nodes and message allocations
    pthread_mutex_lock(&q->mutex);
    while (q->head) {
        QueueNode *node = q->head;
        q->head = node->next;
        if (node->msg) {
            free(node->msg);
        }
        free(node);
    }
    q->tail = NULL;
    pthread_mutex_unlock(&q->mutex);

    // Destroy internal mutex primitive
    pthread_mutex_destroy(&q->mutex);
}
