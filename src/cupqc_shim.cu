#include <cupqc/pk.hpp>
#include <cupqc/cupqc.hpp>
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdexcept>
#include <mutex>
#include <thread>
#include <chrono>
#include <atomic>

using namespace cupqc;

#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            fprintf(stderr, "CUDA Error at %s:%d - %s\n", __FILE__, __LINE__, cudaGetErrorString(err)); \
            return; \
        } \
    } while(0)

#define CUDA_CHECK_RETRY(call) \
    do { \
        cudaError_t err; \
        int attempts = 0; \
        const int max_attempts = 60; \
        for (;;) { \
            err = call; \
            if (err == cudaSuccess) break; \
            attempts++; \
            fprintf(stderr, "[cussl] CUDA init retry at %s:%d - %s (attempt %d/%d)\n", \
                    __FILE__, __LINE__, cudaGetErrorString(err), attempts, max_attempts); \
            if (attempts >= max_attempts) break; \
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); \
        } \
        if (err != cudaSuccess) { \
            fprintf(stderr, "[cussl] FATAL: CUDA init failed at %s:%d - %s after %d attempts\n", \
                    __FILE__, __LINE__, cudaGetErrorString(err), max_attempts); \
            return; \
        } \
    } while(0)

using Encaps768 = decltype(ML_KEM_768{} + Function<function::Encaps>() + Block() + BlockDim<128>());

static uint8_t *g_d_pk = nullptr;
static uint8_t *g_d_ct = nullptr;
static uint8_t *g_d_ss = nullptr;
static uint8_t *g_d_entropy = nullptr;
static uint8_t *g_d_workspace = nullptr;

static uint8_t *g_h_pk = nullptr;
static uint8_t *g_h_ct = nullptr;
static uint8_t *g_h_ss = nullptr;
static uint8_t *g_h_entropy = nullptr;

static cudaStream_t g_stream;
static std::once_flag init_flag;
static std::atomic<bool> g_init_ok{false};
static std::mutex g_dispatch_mutex;

/* --- PCIe/kernel timing instrumentation --- */
static cudaEvent_t g_ev_start, g_ev_h2d_done, g_ev_kernel_done, g_ev_d2h_done;
static bool g_profile_enabled = false;

const int MAX_CAPACITY = 2048;

void init_cuda_buffers() {

    if (Encaps768::entropy_size != 32) {
        fprintf(stderr, "FATAL: cuPQC SDK entropy size does not match OpenSSL's 32-byte requirement!\n");
        exit(1);
    }
    CUDA_CHECK_RETRY(cudaMalloc(&g_d_pk, MAX_CAPACITY * Encaps768::public_key_size));
    CUDA_CHECK_RETRY(cudaMalloc(&g_d_ct, MAX_CAPACITY * Encaps768::ciphertext_size));
    CUDA_CHECK_RETRY(cudaMalloc(&g_d_ss, MAX_CAPACITY * Encaps768::shared_secret_size));
    CUDA_CHECK_RETRY(cudaMalloc(&g_d_entropy, MAX_CAPACITY * Encaps768::entropy_size));
    CUDA_CHECK_RETRY(cudaMalloc(&g_d_workspace, MAX_CAPACITY * Encaps768::workspace_size));

    CUDA_CHECK_RETRY(cudaMemset(g_d_workspace, 0, MAX_CAPACITY * Encaps768::workspace_size));

    CUDA_CHECK_RETRY(cudaHostAlloc(&g_h_pk, MAX_CAPACITY * Encaps768::public_key_size, cudaHostAllocDefault));
    CUDA_CHECK_RETRY(cudaHostAlloc(&g_h_ct, MAX_CAPACITY * Encaps768::ciphertext_size, cudaHostAllocDefault));
    CUDA_CHECK_RETRY(cudaHostAlloc(&g_h_ss, MAX_CAPACITY * Encaps768::shared_secret_size, cudaHostAllocDefault));
    CUDA_CHECK_RETRY(cudaHostAlloc(&g_h_entropy, MAX_CAPACITY * Encaps768::entropy_size, cudaHostAllocDefault));

    CUDA_CHECK_RETRY(cudaStreamCreate(&g_stream));

    /* --- PCIe/kernel timing instrumentation: create reusable events --- */
    CUDA_CHECK_RETRY(cudaEventCreate(&g_ev_start));
    CUDA_CHECK_RETRY(cudaEventCreate(&g_ev_h2d_done));
    CUDA_CHECK_RETRY(cudaEventCreate(&g_ev_kernel_done));
    CUDA_CHECK_RETRY(cudaEventCreate(&g_ev_d2h_done));

    const char* prof = getenv("CUPQC_PROFILE");
    g_profile_enabled = (prof != nullptr && prof[0] == '1');
    if (g_profile_enabled) {
        fprintf(stderr, "[cussl] Profiling enabled (CUPQC_PROFILE=1) -- per-dispatch H2D/kernel/D2H timing will print to stderr\n");
    }

    g_init_ok.store(true, std::memory_order_release);
}

__global__ void kernel_encaps_batch(
    uint8_t* flat_ct,
    uint8_t* flat_ss,
    const uint8_t* flat_pk,
    uint8_t* flat_entropy,
    uint8_t* flat_workspace
) {
    int job_id = blockIdx.x;

    uint8_t* my_ct = flat_ct + (job_id * Encaps768::ciphertext_size);
    uint8_t* my_ss = flat_ss + (job_id * Encaps768::shared_secret_size);
    const uint8_t* my_pk = flat_pk + (job_id * Encaps768::public_key_size);
    uint8_t* my_entropy = flat_entropy + (job_id * Encaps768::entropy_size);
    uint8_t* my_workspace = flat_workspace + (job_id * Encaps768::workspace_size);

    __shared__ uint8_t smem[Encaps768::shared_memory_size];

    Encaps768().execute(my_ct, my_ss, my_pk, my_entropy, my_workspace, smem);
}

extern "C" {

void cupqc_encaps_mlkem768_batch(
    int count,
    unsigned char **pk_ptrs,
    unsigned char **rnd_ptrs,
    unsigned char **ct_ptrs,
    unsigned char **ss_ptrs
) {
    if (count <= 0 || count > MAX_CAPACITY) return;

    std::call_once(init_flag, init_cuda_buffers);

    if (!g_init_ok.load(std::memory_order_acquire)) {
        fprintf(stderr, "[cussl] GPU not initialized for this worker, refusing dispatch (count=%d)\n", count);
        return;
    }

    std::lock_guard<std::mutex> dispatch_lock(g_dispatch_mutex);

    // GATHER
    for (int i = 0; i < count; i++) {
        if (pk_ptrs[i] && rnd_ptrs[i]) {
            memcpy(g_h_pk + (i * Encaps768::public_key_size), pk_ptrs[i], Encaps768::public_key_size);
            memcpy(g_h_entropy + (i * Encaps768::entropy_size), rnd_ptrs[i], Encaps768::entropy_size);
        }
    }

    // COPY & LAUNCH
    if (g_profile_enabled) CUDA_CHECK(cudaEventRecord(g_ev_start, g_stream));

    CUDA_CHECK(cudaMemcpyAsync(g_d_pk, g_h_pk, count * Encaps768::public_key_size, cudaMemcpyHostToDevice, g_stream));
    CUDA_CHECK(cudaMemcpyAsync(g_d_entropy, g_h_entropy, count * Encaps768::entropy_size, cudaMemcpyHostToDevice, g_stream));

    if (g_profile_enabled) CUDA_CHECK(cudaEventRecord(g_ev_h2d_done, g_stream));

    kernel_encaps_batch<<<count, 128, 0, g_stream>>>(g_d_ct, g_d_ss, g_d_pk, g_d_entropy, g_d_workspace);

    if (g_profile_enabled) CUDA_CHECK(cudaEventRecord(g_ev_kernel_done, g_stream));

    CUDA_CHECK(cudaMemcpyAsync(g_h_ct, g_d_ct, count * Encaps768::ciphertext_size, cudaMemcpyDeviceToHost, g_stream));
    CUDA_CHECK(cudaMemcpyAsync(g_h_ss, g_d_ss, count * Encaps768::shared_secret_size, cudaMemcpyDeviceToHost, g_stream));

    if (g_profile_enabled) CUDA_CHECK(cudaEventRecord(g_ev_d2h_done, g_stream));

    CUDA_CHECK(cudaStreamSynchronize(g_stream));

    if (g_profile_enabled) {
        float ms_h2d = 0, ms_kernel = 0, ms_d2h = 0, ms_total = 0;
        cudaEventElapsedTime(&ms_h2d, g_ev_start, g_ev_h2d_done);
        cudaEventElapsedTime(&ms_kernel, g_ev_h2d_done, g_ev_kernel_done);
        cudaEventElapsedTime(&ms_d2h, g_ev_kernel_done, g_ev_d2h_done);
        cudaEventElapsedTime(&ms_total, g_ev_start, g_ev_d2h_done);
        fprintf(stderr, "[cussl] batch=%d h2d_us=%.2f kernel_us=%.2f d2h_us=%.2f total_us=%.2f\n",
                count, ms_h2d * 1000.0f, ms_kernel * 1000.0f, ms_d2h * 1000.0f, ms_total * 1000.0f);
    }

    // SCATTER
    for (int i = 0; i < count; i++) {
        if (ct_ptrs[i]) {
            memcpy(ct_ptrs[i], g_h_ct + (i * Encaps768::ciphertext_size), Encaps768::ciphertext_size);
        }
        if (ss_ptrs[i]) {
            memcpy(ss_ptrs[i], g_h_ss + (i * Encaps768::shared_secret_size), Encaps768::shared_secret_size);
        }
    }
}

void cupqc_keygen_mlkem768(uint8_t *pk, uint8_t *sk) { return; }

} // extern "C"
