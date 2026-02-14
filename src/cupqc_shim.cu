/* cupqc_shim.cu - Fixed Signature Version */
#include <cupqc/pk.hpp>
#include <cupqc/cupqc.hpp>
#include <cuda_runtime.h>
#include <stdio.h>
#include <string.h>

using namespace cupqc;

/* --- 1. DEFINE THE ALGORITHM --- */
using Encaps768 = decltype(ML_KEM_768{} + Function<function::Encaps>() + Block() + BlockDim<256>());

/* --- 2. GLOBAL GPU BUFFERS --- */
static uint8_t *g_d_pk = nullptr;
static uint8_t *g_d_ct = nullptr;
static uint8_t *g_d_ss = nullptr;
static uint8_t *g_d_entropy = nullptr;
static uint8_t *g_d_workspace = nullptr;

static uint8_t *g_h_pk = nullptr;
static uint8_t *g_h_ct = nullptr;
static uint8_t *g_h_ss = nullptr;
static uint8_t *g_h_entropy = nullptr;

const int MAX_CAPACITY = 2048;

/* --- 3. THE KERNEL --- */
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

/* --- 4. HOST FUNCTION --- */
/* FIX: Argument order restored to (pk, rnd, ct, ss) to match Runtime */
void cupqc_encap_mlkem768_batch(
    int count, 
    unsigned char **pk_ptrs, 
    unsigned char **rnd_ptrs, 
    unsigned char **ct_ptrs,  /* Arg 3: Ciphertext (1088 bytes) */
    unsigned char **ss_ptrs   /* Arg 4: Shared Secret (32 bytes) */
) {
    if (count <= 0 || count > MAX_CAPACITY) return;

    // A. ALLOCATION
    if (g_d_pk == nullptr) {
        cudaMalloc(&g_d_pk, MAX_CAPACITY * Encaps768::public_key_size);
        cudaMalloc(&g_d_ct, MAX_CAPACITY * Encaps768::ciphertext_size);
        cudaMalloc(&g_d_ss, MAX_CAPACITY * Encaps768::shared_secret_size);
        cudaMalloc(&g_d_entropy, MAX_CAPACITY * Encaps768::entropy_size);
        cudaMalloc(&g_d_workspace, MAX_CAPACITY * Encaps768::workspace_size);

        cudaHostAlloc(&g_h_pk, MAX_CAPACITY * Encaps768::public_key_size, cudaHostAllocDefault);
        cudaHostAlloc(&g_h_ct, MAX_CAPACITY * Encaps768::ciphertext_size, cudaHostAllocDefault);
        cudaHostAlloc(&g_h_ss, MAX_CAPACITY * Encaps768::shared_secret_size, cudaHostAllocDefault);
        cudaHostAlloc(&g_h_entropy, MAX_CAPACITY * Encaps768::entropy_size, cudaHostAllocDefault);
    }

    // B. GATHER
    for (int i = 0; i < count; i++) {
        if (pk_ptrs[i] && rnd_ptrs[i]) {
            memcpy(g_h_pk + (i * Encaps768::public_key_size), pk_ptrs[i], Encaps768::public_key_size);
            memcpy(g_h_entropy + (i * Encaps768::entropy_size), rnd_ptrs[i], Encaps768::entropy_size);
        }
    }

    // C. COPY & LAUNCH
    cudaStream_t stream;
    cudaStreamCreate(&stream);

    cudaMemcpyAsync(g_d_pk, g_h_pk, count * Encaps768::public_key_size, cudaMemcpyHostToDevice, stream);
    cudaMemcpyAsync(g_d_entropy, g_h_entropy, count * Encaps768::entropy_size, cudaMemcpyHostToDevice, stream);

    kernel_encaps_batch<<<count, 256, 0, stream>>>(g_d_ct, g_d_ss, g_d_pk, g_d_entropy, g_d_workspace);

    cudaMemcpyAsync(g_h_ct, g_d_ct, count * Encaps768::ciphertext_size, cudaMemcpyDeviceToHost, stream);
    cudaMemcpyAsync(g_h_ss, g_d_ss, count * Encaps768::shared_secret_size, cudaMemcpyDeviceToHost, stream);

    cudaStreamSynchronize(stream);
    cudaStreamDestroy(stream);

    // D. SCATTER (Now safe because ct_ptrs is actually the big buffer)
    for (int i = 0; i < count; i++) {
        /* Write Ciphertext (1088 bytes) to ct_ptrs */
        if (ct_ptrs[i]) {
            memcpy(ct_ptrs[i], g_h_ct + (i * Encaps768::ciphertext_size), Encaps768::ciphertext_size);
        }
        /* Write Shared Secret (32 bytes) to ss_ptrs */
        if (ss_ptrs[i]) {
            memcpy(ss_ptrs[i], g_h_ss + (i * Encaps768::shared_secret_size), Encaps768::shared_secret_size);
        }
    }
}

void cupqc_keygen_mlkem768(uint8_t *pk, uint8_t *sk) { return; }

} // extern "C"
