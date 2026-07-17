/* cupqc_runtime.c - Internal Implementation */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>      /* Required for clock_gettime / timedwait */
#include <sys/time.h>
#include <stdatomic.h>
#include "cupqc_batch.h"


#define CUPQC_BATCH_SIZE 512
#define FLUSH_THRESHOLD 16

/* --- THE NEW JOB STRUCT --- */
typedef struct {
    unsigned char pub_key_storage[1184];
    unsigned char randomness_storage[32]; 
    unsigned char *shared_secret_out;     
    unsigned char *ciphertext_out;        
    void *opaque_job_ptr; 
    int status;
    unsigned long generation;
    /*  Every slot has a private lock and beeper */
    pthread_mutex_t lock;
    pthread_cond_t cond;
} cupqc_job_t;

/* --- THE RING BUFFER QUEUE --- */
typedef struct {
    cupqc_job_t jobs[CUPQC_BATCH_SIZE];
    int head;  // Where Nginx drops jobs
    int tail;  // Where Worker picks up jobs
    int count; // Total active jobs
    
    pthread_mutex_t lock;
    pthread_cond_t cond_has_jobs;
    pthread_cond_t cond_not_full;
    int shutdown;
} cupqc_batch_queue_t;

static cupqc_batch_queue_t global_queue;
static pthread_t batch_thread;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

atomic_long g_gpu_dispatch_count = 0;
atomic_long g_total_ops_batched = 0;

/* --- CLEANUP & INIT --- */
static void cupqc_shutdown(void) {
    pthread_mutex_lock(&global_queue.lock);
    global_queue.shutdown = 1;
    pthread_cond_broadcast(&global_queue.cond_has_jobs);
    pthread_mutex_unlock(&global_queue.lock);

    pthread_join(batch_thread, NULL);

    pthread_mutex_destroy(&global_queue.lock);
    pthread_cond_destroy(&global_queue.cond_has_jobs);
    pthread_cond_destroy(&global_queue.cond_not_full);

    for(int i=0; i<CUPQC_BATCH_SIZE; i++) {
        pthread_mutex_destroy(&global_queue.jobs[i].lock);
        pthread_cond_destroy(&global_queue.jobs[i].cond);
    }
}

static void* cupqc_batch_worker(void *arg);

static void cupqc_do_init(void) {
    pthread_mutex_init(&global_queue.lock, NULL);
    pthread_cond_init(&global_queue.cond_has_jobs, NULL);
    pthread_cond_init(&global_queue.cond_not_full, NULL);
    
    global_queue.head = 0;
    global_queue.tail = 0;
    global_queue.count = 0;
    global_queue.shutdown = 0;
    
    for(int i=0; i<CUPQC_BATCH_SIZE; i++) {
        pthread_mutex_init(&global_queue.jobs[i].lock, NULL);
        pthread_cond_init(&global_queue.jobs[i].cond, NULL);
        global_queue.jobs[i].status = 0;
        global_queue.jobs[i].generation = 0;
    }
    
    pthread_create(&batch_thread, NULL, cupqc_batch_worker, NULL);
    atexit(cupqc_shutdown);
}

static void cupqc_lazy_init(void) {
    pthread_once(&init_once, cupqc_do_init);
}

/* --- CALLBACKS --- */
static void (*cb_pause_job)(void) = NULL;
static void (*cb_wake_job)(void*) = NULL;
static void* (*cb_get_curr_job)(void) = NULL;
static void (*cb_prepare_wait)(void) = NULL;

void cupqc_set_callbacks(void (*prepare_wait)(void),void (*pause)(void), void (*wake)(void*), void* (*get_job)(void)) {
    cb_prepare_wait = prepare_wait;
    cb_pause_job = pause;
    cb_wake_job = wake;
    cb_get_curr_job = get_job;
}

/* --- THE WORKER THREAD --- */
void* cupqc_batch_worker(void *arg) {
    while (1) {
        pthread_mutex_lock(&global_queue.lock);

        while (global_queue.count == 0 && !global_queue.shutdown) {
            pthread_cond_wait(&global_queue.cond_has_jobs, &global_queue.lock);
        }
        if (global_queue.shutdown) {
            pthread_mutex_unlock(&global_queue.lock);
            break;
        }

        if (global_queue.count < FLUSH_THRESHOLD) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 300000;
            if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
            while (global_queue.count < FLUSH_THRESHOLD && !global_queue.shutdown) {
                int rc = pthread_cond_timedwait(&global_queue.cond_has_jobs, &global_queue.lock, &ts);
                if (rc == ETIMEDOUT) break;
            }
        }

        int batch_size = global_queue.count;
        unsigned char *pks[CUPQC_BATCH_SIZE];
        unsigned char *rnds[CUPQC_BATCH_SIZE];
        unsigned char *cts[CUPQC_BATCH_SIZE];
        unsigned char *sss[CUPQC_BATCH_SIZE];
        int slots_processing[CUPQC_BATCH_SIZE];

        for (int i = 0; i < batch_size; i++) {
            int slot = (global_queue.tail + i) % CUPQC_BATCH_SIZE;
            pks[i]  = global_queue.jobs[slot].pub_key_storage;
            rnds[i] = global_queue.jobs[slot].randomness_storage;
            cts[i]  = global_queue.jobs[slot].ciphertext_out;
            sss[i]  = global_queue.jobs[slot].shared_secret_out;
            slots_processing[i] = slot;
        }

        /* Do NOT advance tail/count/cond_not_full yet - these slots must
         * stay "claimed" until their owners have been signaled, otherwise
         * a new submission can reuse a slot and reset its status before
         * the original waiter observes completion. */
        pthread_mutex_unlock(&global_queue.lock);

        extern void cupqc_encaps_mlkem768_batch(int count, unsigned char **pk, unsigned char **rnd, unsigned char **ct, unsigned char **ss);
        cupqc_encaps_mlkem768_batch(batch_size, pks, rnds, cts, sss);
        atomic_fetch_add(&g_gpu_dispatch_count, 1);
        atomic_fetch_add(&g_total_ops_batched, batch_size);

        for (int i = 0; i < batch_size; i++) {
            int slot = slots_processing[i];
            pthread_mutex_lock(&global_queue.jobs[slot].lock);
            global_queue.jobs[slot].status = 1;
            pthread_cond_broadcast(&global_queue.jobs[slot].cond);
            pthread_mutex_unlock(&global_queue.jobs[slot].lock);
            if (global_queue.jobs[slot].opaque_job_ptr != NULL && cb_wake_job != NULL) {
                cb_wake_job(global_queue.jobs[slot].opaque_job_ptr);
            }
        }

        /* Only now is it safe to free these slots for reuse. */
        pthread_mutex_lock(&global_queue.lock);
        global_queue.tail = (global_queue.tail + batch_size) % CUPQC_BATCH_SIZE;
        global_queue.count -= batch_size;
        pthread_cond_broadcast(&global_queue.cond_not_full);
        pthread_mutex_unlock(&global_queue.lock);
    }
    return NULL;
}

/* --- PUBLIC API --- */
int cupqc_submit_encap_job(uint8_t *public_key, uint8_t *randomness, uint8_t *ciphertext_out, uint8_t *shared_secret_out) {
    cupqc_lazy_init();

    pthread_mutex_lock(&global_queue.lock);

    // If the lot is full, wait outside
    while (global_queue.count >= CUPQC_BATCH_SIZE) {
        pthread_cond_wait(&global_queue.cond_not_full, &global_queue.lock);
    }

    // Take the next available spot at the Head of the ring
    int slot = global_queue.head;
    global_queue.head = (global_queue.head + 1) % CUPQC_BATCH_SIZE;
    global_queue.jobs[slot].generation++;
    unsigned long my_generation = global_queue.jobs[slot].generation;

    // Secure Copy
    memcpy(global_queue.jobs[slot].pub_key_storage, public_key, 1184);
    memcpy(global_queue.jobs[slot].randomness_storage, randomness, 32);

    global_queue.jobs[slot].ciphertext_out = ciphertext_out;
    global_queue.jobs[slot].shared_secret_out = shared_secret_out;
    global_queue.jobs[slot].status = 0; // Reset status

    if (cb_get_curr_job) {
        global_queue.jobs[slot].opaque_job_ptr = cb_get_curr_job();
    } else {
        global_queue.jobs[slot].opaque_job_ptr = NULL;
    }
    void *current_job = global_queue.jobs[slot].opaque_job_ptr;
    /* Register this job's wait fd BEFORE signalling the worker - otherwise
     * the worker can race ahead and try to wake this job before it has
     * anything to wake it with. */
    if (current_job != NULL && cb_prepare_wait != NULL) {
        cb_prepare_wait();
    }
    global_queue.count++;
    
    // Signal worker that a job arrived
    pthread_cond_signal(&global_queue.cond_has_jobs);
    pthread_mutex_unlock(&global_queue.lock);

    if (current_job != NULL && cb_pause_job != NULL) {
        cb_pause_job();
    } else {
        // Fallback: Sleep on this job's PRIVATE condition variable
        pthread_mutex_lock(&global_queue.jobs[slot].lock);
        while (global_queue.jobs[slot].status == 0) {
            pthread_cond_wait(&global_queue.jobs[slot].cond, &global_queue.jobs[slot].lock);
        }
        if (global_queue.jobs[slot].generation != my_generation) {
            fprintf(stderr, "[RACE DETECTED] slot %d: claimed gen %lu, now gen %lu\n",
                    slot, my_generation, global_queue.jobs[slot].generation);
        }
        pthread_mutex_unlock(&global_queue.jobs[slot].lock);
    }

    return 1;
}
