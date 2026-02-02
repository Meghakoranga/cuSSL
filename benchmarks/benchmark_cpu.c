/* benchmark_cpu.c - Multi-Threaded CPU Benchmark */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ALGO_NAME "ML-KEM-768"

// Shared specific variables
int g_iterations_per_thread = 0;
EVP_PKEY *g_pkey = NULL;

// The Worker Thread Function
void *cpu_worker(void *arg) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(g_pkey, NULL);
    if (!ctx) return NULL;

    // We do NOT call Async init, so this runs on CPU Software path
    EVP_PKEY_encapsulate_init(ctx, NULL);

    unsigned char *secret = malloc(32);
    unsigned char *ciphertext = malloc(1088);
    size_t secret_len = 32;
    size_t ciphertext_len = 1088;

    for (int i = 0; i < g_iterations_per_thread; i++) {
        secret_len = 32;
        ciphertext_len = 1088;
        EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, secret, &secret_len);
    }

    free(secret);
    free(ciphertext);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

int main(int argc, char **argv) {
    int num_threads = 4; // Default to 4 cores
    int total_iters = 100000;

    if (argc > 1) num_threads = atoi(argv[1]);
    if (argc > 2) total_iters = atoi(argv[2]);

    g_iterations_per_thread = total_iters / num_threads;

    printf("Benchmarking Multi-Core CPU Performance\n");
    printf("Algorithm: %s\n", ALGO_NAME);
    printf("Threads:   %d\n", num_threads);
    printf("Total Ops: %d\n", num_threads * g_iterations_per_thread);

    // Generate Key (Once)
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, ALGO_NAME, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &g_pkey);
    EVP_PKEY_CTX_free(kctx);

    // Launch Threads
    pthread_t threads[num_threads];
    clock_t start = clock();
    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, cpu_worker, NULL);
    }

    // Wait for Threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    
    double time_spent = (ts_end.tv_sec - ts_start.tv_sec) + 
                        (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    printf("\n--- CPU Results ---\n");
    printf("Total Time: %.2f seconds\n", time_spent);
    printf("Ops/Sec:    %.2f\n", (double)(num_threads * g_iterations_per_thread) / time_spent);

    EVP_PKEY_free(g_pkey);
    return 0;
}
