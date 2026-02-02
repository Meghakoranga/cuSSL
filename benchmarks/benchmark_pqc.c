/* benchmark_pqc.c - Async Encapsulation Benchmark (FIXED) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/async.h>

#define ALGO_NAME "ML-KEM-768"
#define DEFAULT_JOBS 128
#define DEFAULT_ITERS 100000

// Structure to pass data into the Async Job
typedef struct {
    EVP_PKEY_CTX *ctx;
    unsigned char *secret;
    size_t secret_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    int result;
} JobArgs;

// The function that runs inside the Async Fiber
int encaps_job(void *arg) {
    JobArgs *args = (JobArgs *)arg;
    
    // reset output lengths (crucial for loop)
    args->secret_len = 32;   // ML-KEM-768 SS len
    args->ciphertext_len = 1088; // ML-KEM-768 CT len

    if (EVP_PKEY_encapsulate(args->ctx, 
                             args->ciphertext, &args->ciphertext_len,
                             args->secret, &args->secret_len) <= 0) {
        return 0; // Error
    }
    return 1; // Success
}

int main(int argc, char **argv) {
    int async_jobs = DEFAULT_JOBS;
    int total_iters = DEFAULT_ITERS;

    // 1. Simple Argument Parsing
    for(int i=1; i<argc; i++) {
        if(strcmp(argv[i], "-jobs")==0 && i+1<argc) async_jobs = atoi(argv[++i]);
        if(strcmp(argv[i], "-iters")==0 && i+1<argc) total_iters = atoi(argv[++i]);
    }

    printf("Benchmarking %s Encapsulation\n", ALGO_NAME);
    printf("Configuration: %d Parallel Jobs, %d Total Iterations\n", async_jobs, total_iters);

    // 2. Setup: Generate ONE Keypair (simulating a server key)
    printf("Generating Server Keypair...\n");
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, ALGO_NAME, NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    if (!pkey) {
        fprintf(stderr, "Error: Keygen failed. Is the algorithm name correct?\n");
        return 1;
    }

    // 3. Setup Async Pool
    ASYNC_JOB *jobs[async_jobs];
    ASYNC_WAIT_CTX *wait_ctxs[async_jobs];
    JobArgs args[async_jobs];
    int job_status[async_jobs]; // 0=Idle, 1=InProgress/Paused
    
    // Initialize Memory
    for (int i = 0; i < async_jobs; i++) {
        jobs[i] = NULL;
        wait_ctxs[i] = ASYNC_WAIT_CTX_new();
        job_status[i] = 0;
        
        // Each job needs its own context derived from the pubkey
        args[i].ctx = EVP_PKEY_CTX_new(pkey, NULL);
        
        // --- FIX IS HERE (added NULL) ---
        EVP_PKEY_encapsulate_init(args[i].ctx, NULL);
        
        args[i].secret = malloc(32);
        args[i].ciphertext = malloc(1088);
    }

    printf("Starting Benchmark...\n");
    clock_t start = clock();

    int started_count = 0;
    int finished_count = 0;
    int ret;

    // 4. The "Event Loop" (Round Robin Scheduler)
    while (finished_count < total_iters) {
        for (int i = 0; i < async_jobs; i++) {
            
            // Case A: Job is Idle, and we have work to do -> START IT
            if (job_status[i] == 0 && started_count < total_iters) {
                started_count++;
                job_status[i] = 1; // Mark active
                
                // Launch Job
                ret = ASYNC_start_job(&jobs[i], wait_ctxs[i], &ret, encaps_job, &args[i], sizeof(JobArgs));
                
                if (ret == ASYNC_PAUSE) {
                    // Good! It hit the GPU batch queue and paused.
                    // Loop continues to start next job...
                } else if (ret == ASYNC_FINISH) {
                    // It finished instantly (CPU fallback or fast path)
                    job_status[i] = 0;
                    finished_count++;
                }
            } 
            // Case B: Job is Paused (Waiting for GPU) -> RESUME IT
            else if (job_status[i] == 1) {
                // Resume Job
                ret = ASYNC_start_job(&jobs[i], wait_ctxs[i], &ret, encaps_job, &args[i], sizeof(JobArgs));
                
                if (ret == ASYNC_FINISH) {
                    // Now it's really done
                    job_status[i] = 0;
                    finished_count++;
                }
                // If ASYNC_PAUSE again, it means batch isn't full yet, keep looping.
            }
        }
    }

    clock_t end = clock();

    // 5. Cleanup & Report
    for (int i = 0; i < async_jobs; i++) {
        ASYNC_WAIT_CTX_free(wait_ctxs[i]);
        EVP_PKEY_CTX_free(args[i].ctx);
        free(args[i].secret);
        free(args[i].ciphertext);
    }
    EVP_PKEY_free(pkey);

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf("\n--- Results ---\n");
    printf("Total Time: %.2f seconds\n", time_spent);
    printf("Ops/Sec:    %.2f\n", total_iters / time_spent);

    return 0;
}
