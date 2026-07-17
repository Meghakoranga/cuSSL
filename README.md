# cuSSL

**GPU-accelerated ML-KEM-768 for OpenSSL 3.5** — offloads post-quantum key encapsulation to NVIDIA GPUs via a CUDA runtime built on NVIDIA's cuPQC SDK.

cuSSL patches OpenSSL 3.5 to offload ML-KEM-768 (the post-quantum key exchange used in TLS 1.3) to a GPU, with no changes to OpenSSL's public API and an automatic fallback to CPU execution whenever GPU offload is disabled. It uses a split-stack architecture — OpenSSL (C) is kept fully separate from the CUDA backend (C++) — for ABI stability, thread safety, and memory isolation.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
- [Benchmarks](#benchmarks)
- [Repository Structure](#repository-structure)
- [Roadmap](#roadmap)
- [Security & Compatibility](#security--compatibility)
- [License](#license)

---

## Features

- GPU-accelerated ML-KEM-768 encapsulation via NVIDIA cuPQC
- Async batching runtime, stress-tested up to 512 concurrent operations
- Patch-based OpenSSL 3.5 integration — no public API changes, no OpenSSL source redistributed
- Thread-safe job queue and runtime scheduler
- Automatic CPU fallback when GPU offload is disabled

---

## Architecture

Three layers, each independently testable:

| Layer | File | Role |
|---|---|---|
| OpenSSL Integration | `crypto/ml_kem/ml_kem.c` (patched) | Intercepts ML-KEM-768 requests, submits jobs to the runtime, falls back to CPU when GPU offload is off |
| cuSSL Runtime | `src/cupqc_runtime.c` | Thread-safe 512-slot batching queue, request scheduling, worker-thread coordination |
| CUDA Backend | `src/cupqc_shim.cu` | Runs batched `cupqc::ML_KEM_768` kernels, manages persistent GPU buffers and a reused CUDA stream |

---

## Requirements

**Hardware:** NVIDIA GPU, Turing/Ampere/Ada or newer, Compute Capability ≥ 7.5

**Software:** Linux (Ubuntu 20.04/22.04), OpenSSL 3.5.0 source, CUDA Toolkit 12+, NVIDIA cuPQC SDK, GCC 9+, NVCC

---

## Build

```bash
export CUPQC_HOME=/path/to/cupqc_sdk
export OPENSSL_ROOT=/path/to/openssl-3.5.0

# cuPQC ships as a pre-compiled, LTO-linked SDK — the build needs RDC + LTO
# flags and an explicit device-link step for symbol resolution.
export MISSING_INC_PATH=$(find ${CUPQC_HOME} -name "database.hpp" -exec dirname {} \; | head -n 1)

gcc -c src/cupqc_runtime.c -o cupqc_runtime.o -fPIC \
    -I${OPENSSL_ROOT}/include -I${OPENSSL_ROOT}/crypto/ml_kem

nvcc -c src/cupqc_shim.cu -o cupqc_shim.o \
    -rdc=true -dlto -std=c++17 -arch=sm_75 \
    -I${CUPQC_HOME}/include -I${CUPQC_HOME}/include/cupqc/detail -I$MISSING_INC_PATH \
    -Xcompiler -fPIC

nvcc -arch=sm_75 -dlink cupqc_shim.o -o cupqc_shim_dlink.o \
    -rdc=true -dlto -L${CUPQC_HOME}/lib -lcupqc-pk -Xcompiler -fPIC

g++ -shared -o libcussl.so \
    cupqc_runtime.o cupqc_shim.o cupqc_shim_dlink.o \
    -L${CUPQC_HOME}/lib -lcupqc-pk -L/usr/local/cuda/lib64 -lcudart -lpthread
```

Apply the patch and rebuild OpenSSL:

```bash
cd $OPENSSL_ROOT
patch -p1 < /path/to/cuSSL/openssl/patches/openssl-3.5.0-mlkem-cupqc.patch
make -j$(nproc)
```

---

## Usage

```bash
# Multi-process servers (Nginx, etc.): start MPS before the server, so worker
# processes share the GPU instead of context-switching between them.
sudo nvidia-cuda-mps-control -d

# Enable GPU offload
export ENABLE_CUPQC=1
openssl s_server -accept 4433 -cert cert.pem -key key.pem -tls1_3 -groups mlkem768

# Verify offload
nvitop   # or nvidia-smi — check GPU utilization during a handshake

# Disable GPU offload, fall back to CPU
unset ENABLE_CUPQC
```

---

## Benchmarks

Measured with two tools: the official `openssl speed -kem-algorithms ML-KEM-768` (raw encapsulation throughput) and `benchmark_tls` (this repo's own client, full TLS 1.3 handshakes against live Nginx).

| Kernel-level (`openssl speed`) | Throughput | vs. CPU |
|---|---|---|
| CPU (`-multi 4`) | 82,620 ops/sec | 1.0x |
| GPU, 1 process | 208,388 ops/sec | 2.5x |
| GPU, 4 processes + MPS | **265,974 ops/sec** | **3.2x** |

| Full handshake (`benchmark_tls`, live Nginx) | Throughput | vs. CPU |
|---|---|---|
| CPU-only | **1,523 hs/sec** | 1.0x |
| GPU, no MPS | 1,280 hs/sec | 0.84x |
| GPU + MPS | 1,362 hs/sec | 0.89x |

GPU wins decisively at the raw cryptographic kernel (3.2x). It does not yet win at the full-handshake level (~12% behind CPU) — a full handshake also costs a TCP handshake, TLS record processing, and an RSA certificate signature, none of which touch the GPU, and Nginx currently falls back to blocking one worker per request rather than batching (see [Roadmap](#roadmap)).

---

## Repository Structure

```
cuSSL/
├── benchmarks/
│   └── benchmark_tls.c          # Full TLS 1.3 handshake benchmark
├── include/cussl/
│   └── pqc.h                    # Public header
├── openssl/patches/
│   └── openssl-3.5.0-mlkem-cupqc.patch
├── src/
│   ├── cupqc_batch.h            # Job submission / callback API
│   ├── cupqc_runtime.c          # Runtime scheduler
│   └── cupqc_shim.cu            # CUDA backend
├── LICENSE
└── README.md
```

---

## Roadmap

1. Wire cuSSL as a proper OpenSSL ENGINE so servers can use true async-job batching instead of today's one-request-per-worker blocking fallback
2. Async-native server deployment (Envoy, HAProxy) to keep the GPU batching queue full without blocking
3. PCIe Gen 4/5 hardware to reduce transfer latency (current results: Tesla T4, PCIe Gen 3)
4. Expanded PQC algorithm and hybrid-TLS support
5. Published technical report on the batching architecture and results

---

## Security & Compatibility

Preserves OpenSSL's security model and public API. CUDA and OS-specific synchronization details are isolated from OpenSSL. CPU fallback is always available. Patch-based integration means no OpenSSL fork to maintain across versions.

---

## License

This repository contains integration code only. It does **not** include OpenSSL source, the NVIDIA cuPQC SDK, or the CUDA Toolkit — each must be obtained separately under its own license.
