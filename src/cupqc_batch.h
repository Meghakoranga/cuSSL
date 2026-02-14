#ifndef CUPQC_BATCH_H
#define CUPQC_BATCH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* * API: Submit an encapsulation job.
 * The runtime handles all batching, threading, and GPU offloading internally.
 */
int cupqc_submit_encap_job(
    uint8_t *public_key,
    uint8_t *randomness,
    uint8_t *ciphertext_out,
    uint8_t *shared_secret_out
);

/*
 * API: Register OpenSSL async callbacks.
 * Allows the runtime to pause/wake OpenSSL jobs during GPU wait times.
 */
void cupqc_set_callbacks(
    void (*pause)(void),
    void (*wake)(void *),
    void *(*get_job)(void)
);

#ifdef __cplusplus
}
#endif

#endif /* CUPQC_BATCH_H */
