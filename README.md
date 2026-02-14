# cuSSL: GPU-Accelerated ML-KEM-768 Integration for OpenSSL 3.5

**Hardware-Accelerated Post-Quantum Cryptography using NVIDIA cuPQC and CUDA**

cuSSL is a high-performance runtime and backend that offloads **ML-KEM-768** Key Encapsulation operations from OpenSSL 3.5 to NVIDIA GPUs. It integrates directly into the OpenSSL cryptographic core and enables high-throughput TLS 1.3 Post-Quantum handshakes.

cuSSL implements a **Split-Stack Architecture**, cleanly separating the OpenSSL cryptographic core (CPU/C) from the GPU execution backend (CUDA/C++), ensuring ABI stability, thread safety, and memory isolation.

---

##  Features

* GPU-accelerated ML-KEM-768 encapsulation using NVIDIA cuPQC
* Asynchronous batching runtime (up to 512 concurrent operations)
* Direct integration into OpenSSL 3.5 cryptographic core
* Thread-safe job queue and runtime scheduler
* Secure memory isolation between OpenSSL and GPU runtime
* Automatic CPU fallback when GPU offload is disabled
* Clean patch-based integration (no OpenSSL source redistribution)

---

## Architecture

cuSSL operates in three layers:

### 1. OpenSSL Integration Layer (Client)

**File:** `crypto/ml_kem/ml_kem.c` (patched)

Responsibilities:

* Intercepts ML-KEM encapsulation requests
* Submits jobs via cuSSL runtime API
* Uses OpenSSL Async Job framework (`ASYNC_pause_job`)
* Maintains full compatibility with OpenSSL execution model

---

### 2. cuSSL Runtime Layer (Manager)

**File:** `src/cupqc_runtime.c`

Responsibilities:

* Thread-safe batching queue
* Job scheduling and worker thread management
* Memory isolation between OpenSSL and CUDA
* Async job coordination

This layer acts as the bridge between OpenSSL and GPU backend.

---

### 3. CUDA Backend Layer (Worker)

**File:** `src/cupqc_shim.cu`

Responsibilities:

* Executes batched ML-KEM-768 encapsulation
* Launches cuPQC CUDA kernels
* Manages persistent GPU memory buffers
* Performs host/device memory transfers

Uses: cupqc::ML_KEM_768 from NVIDIA cuPQC SDK.

---

##  Prerequisites

Hardware:

* NVIDIA GPU (Turing / Ampere / Ada or newer)
* Compute Capability ≥ 7.5

Software:

* Linux (Ubuntu 20.04 / 22.04 recommended)
* OpenSSL 3.5.0 source
* NVIDIA CUDA Toolkit (12+)
* NVIDIA cuPQC SDK
* GCC 9+
* NVCC compiler

---

##  Build Instructions

### 1. Set Environment Variables

```
export CUPQC_HOME=/path/to/cupqc_sdk
export OPENSSL_ROOT=/path/to/openssl-3.5.0
```

---

### 2. Compile cuSSL Runtime and CUDA Backend

Compile runtime:
```
gcc -c src/cupqc_runtime.c -o cupqc_runtime.o -fPIC
-I${OPENSSL_ROOT}/include
-I${OPENSSL_ROOT}/crypto/ml_kem
```

Compile CUDA backend:

```
nvcc -c src/cupqc_shim.cu -o cupqc_shim.o
-rdc=true -dlto -std=c++17
-I${CUPQC_HOME}/include
-Xcompiler -fPIC
```

Device link:
```
nvcc -dlink cupqc_shim.o -o cupqc_shim_dlink.o
-rdc=true -dlto
-L${CUPQC_HOME}/lib -lcupqc-pk
```

Final shared library:
```
g++ -shared -o libcussl.so
cupqc_runtime.o cupqc_shim.o cupqc_shim_dlink.o
-L${CUPQC_HOME}/lib -lcupqc-pk
-L/usr/local/cuda/lib64 -lcudart -lpthread
```

---

### 3. Apply OpenSSL Patch

From OpenSSL root:

```
patch -p1 < /path/to/cuSSL/openssl/patches/openssl-3.5.0-mlkem-cupqc.patch
```

Rebuild OpenSSL:

```
make -j$(nproc)
```
---

##  Usage

Enable GPU offload:```export ENABLE_CUPQC=1```

Run OpenSSL TLS server:

```
openssl s_server -accept 4433 -cert cert.pem -key key.pem -tls1_3 -groups mlkem768
```
## Verify Offload
Use ```nvitop``` or ```nvidia-smi``` to verify GPU utilization during handshakes

--- 
**Disable GPU offload**:```unset ENABLE_CUPQC```

OpenSSL will fall back to CPU implementation automatically.

---

##  Performance Characteristics

GPU acceleration improves throughput significantly when batching is enabled.

Tradeoffs:

Latency:
* Higher for single requests (PCIe transfer overhead)

Throughput:
* Much higher under concurrent load
* Optimized for multi-connection TLS servers

Designed for:

* TLS termination servers
* PQC-enabled secure infrastructure
* GPU-accelerated cryptographic workloads

---

##  Security and Compatibility

cuSSL:

* Preserves OpenSSL security model
* Does not modify public OpenSSL APIs
* Uses isolated runtime
* Supports CPU fallback

Patch-based integration ensures maintainability across OpenSSL versions.

---

##  Licensing

This repository contains only integration code.

It does NOT include:

* OpenSSL source code
* NVIDIA cuPQC SDK
* CUDA Toolkit

Users must obtain those separately under their respective licenses.

---

## Project Status

The engine is fully functional and architecturally stable. It successfully performs hardware-offloaded ML-KEM-768 key encapsulation for standard OpenSSL TLS 1.3 connections.

**Core achievements include:**
<ul>
<li>Correctness: Validated bit-exact key exchange and successful handshake completion.</li>
<li>Stability: Zero crashes or memory leaks during sustained load testing.</li>
<li>Architecture: Strict separation of OpenSSL API and GPU runtime for full library compliance.</li>
<li>Performance: Asynchronous batching logic is implemented and operational, ready for multi-threaded deployment.</li>
</ul>
