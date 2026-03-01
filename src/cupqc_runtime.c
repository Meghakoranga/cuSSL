/* cupqc_runtime.c - Internal Implementation */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h> /* FIX #2: Explicit include for defensive correctness */

/* Include the clean Public API */
#include "cupqc_batch.h"

/* --- INTERNAL STRUCTURES (Hidden from OpenSSL) --- */
#define CUPQC_BATCH_SIZE 512

typedef struct {
    unsigned char pub_key_storage[1184];
    unsigned char randomness_storage[32]; 
    unsigned char *shared_secret_out;     
    unsigned char *ciphertext_out;        
    void *opaque_job_ptr; 
    int status;
} cupqc_job_t;

typedef struct {
    cupqc_job_t jobs[CUPQC_BATCH_SIZE];
    int count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_cond_t cond_done;
    int shutdown;
} cupqc_batch_queue_t;

/* --- GLOBAL STATE --- */
static cupqc_batch_queue_t global_queue;
static pthread_t batch_thread;
static int cupqc_initialized = 0;

/* --- CALLBACKS --- */
static void (*cb_pause_job)(void) = NULL;
static void (*cb_wake_job)(void*) = NULL;
static void* (*cb_get_curr_job)(void) = NULL;

void cupqc_set_callbacks(void (*pause)(void), 
                         void (*wake)(void*), 
                         void* (*get_job)(void)) 
{
    cb_pause_job = pause;
    cb_wake_job = wake;
    cb_get_curr_job = get_job;
}

/* --- WORKER THREAD --- */
void* cupqc_batch_worker(void *arg) {
    while (1) {
        pthread_mutex_lock(&global_queue.lock);

        while (global_queue.count == 0 && !global_queue.shutdown) {
            pthread_cond_wait(&global_queue.cond, &global_queue.lock);
        }

        if (global_queue.shutdown) {
            pthread_mutex_unlock(&global_queue.lock);
            break;
        }

        int batch_size = global_queue.count;

        // 1. Prepare Data
        unsigned char *pks[CUPQC_BATCH_SIZE];
        unsigned char *rnds[CUPQC_BATCH_SIZE];
        unsigned char *cts[CUPQC_BATCH_SIZE];
        unsigned char *sss[CUPQC_BATCH_SIZE];

        for(int i=0; i<batch_size; i++) {
            pks[i]  = global_queue.jobs[i].pub_key_storage;
            rnds[i] = global_queue.jobs[i].randomness_storage;
            cts[i]  = global_queue.jobs[i].ciphertext_out;
            sss[i]  = global_queue.jobs[i].shared_secret_out;
        }

        // 2. Call GPU Kernel (External Linkage)
        extern void cupqc_encap_mlkem768_batch(int count, 
                                                 unsigned char **pk, 
                                                 unsigned char **rnd, 
                                                 unsigned char **ct, 
                                                 unsigned char **ss);
        
        // Note: Signature is (pk, rnd, ct, ss) to match Shim
        cupqc_encap_mlkem768_batch(batch_size, pks, rnds, cts, sss);

        // 3. Notify Completion
        for(int i=0; i<batch_size; i++) {
            global_queue.jobs[i].status = 1;
            if (global_queue.jobs[i].opaque_job_ptr != NULL && cb_wake_job != NULL) {
                cb_wake_job(global_queue.jobs[i].opaque_job_ptr);
            }
        }

        pthread_cond_broadcast(&global_queue.cond_done);

        global_queue.count = 0;
        pthread_mutex_unlock(&global_queue.lock);
    }
    return NULL;
}

static void cupqc_lazy_init(void) {
    if (!cupqc_initialized) {
        pthread_mutex_init(&global_queue.lock, NULL);
        pthread_cond_init(&global_queue.cond, NULL);
        pthread_cond_init(&global_queue.cond_done, NULL);
        global_queue.count = 0;
        global_queue.shutdown = 0;
        pthread_create(&batch_thread, NULL, cupqc_batch_worker, NULL);
        cupqc_initialized = 1;
    }
}

/* --- PUBLIC API IMPLEMENTATION --- */
int cupqc_submit_encap_job(uint8_t *public_key, 
                           uint8_t *randomness,
                           uint8_t *ciphertext_out, 
                           uint8_t *shared_secret_out) 
{
    cupqc_lazy_init();

    pthread_mutex_lock(&global_queue.lock);

    while (global_queue.count >= CUPQC_BATCH_SIZE) {
        pthread_cond_wait(&global_queue.cond_done, &global_queue.lock);
    }

    int slot = global_queue.count;

    // Secure Copy
    memcpy(global_queue.jobs[slot].pub_key_storage, public_key, 1184);
    memcpy(global_queue.jobs[slot].randomness_storage, randomness, 32);

    global_queue.jobs[slot].ciphertext_out = ciphertext_out;
    global_queue.jobs[slot].shared_secret_out = shared_secret_out;
    global_queue.jobs[slot].status = 0;

    if (cb_get_curr_job) {
        global_queue.jobs[slot].opaque_job_ptr = cb_get_curr_job();
    } else {
        global_queue.jobs[slot].opaque_job_ptr = NULL;
    }

    global_queue.count++;
    
    if (global_queue.count >= 1) { 
        pthread_cond_signal(&global_queue.cond);
    }

    pthread_mutex_unlock(&global_queue.lock);

    // Wait Strategy
    void *current_job = (cb_get_curr_job) ? cb_get_curr_job() : NULL;

    if (current_job != NULL && cb_pause_job != NULL) {
        cb_pause_job();
    } else {
        pthread_mutex_lock(&global_queue.lock);
        while (global_queue.jobs[slot].status == 0) {
            /* FIX #1: Removed redundant signal. Just wait. */
            pthread_cond_wait(&global_queue.cond_done, &global_queue.lock);
        }
        pthread_mutex_unlock(&global_queue.lock);
    }

    return 1;
}
