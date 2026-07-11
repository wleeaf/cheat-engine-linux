// CUDA-side implementation of the pointer-range search.
//
// Compiled into the cecore_cuda_search target only when find_package(
// CUDAToolkit) succeeds. The C++ side (cuda_search.cpp) provides the
// matching stub when CUDA isn't available.

#include "scanner/cuda_search.hpp"

#include <cuda_runtime.h>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ce {

namespace {

// One thread per 8-byte slot. Block size 256 is a reasonable default for
// memory-bound scans on Maxwell+ (incl. GTX 1650).
__global__ void scanRangeKernel(const uint64_t* __restrict__ data,
                                size_t        slotCount,
                                uint64_t      lo,
                                uint64_t      hi,
                                size_t*       __restrict__ outIndices,
                                unsigned int* __restrict__ outCount,
                                size_t        outCap)
{
    size_t idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= slotCount) return;
    uint64_t v = data[idx];
    if (v >= lo && v <= hi) {
        // Reserve a slot via atomic increment, bounded by outCap.
        unsigned int slot = atomicAdd(outCount, 1u);
        if ((size_t)slot < outCap)
            outIndices[slot] = idx * 8;
    }
}

#define CUDA_TRY(expr) do {                              \
    cudaError_t _err = (expr);                           \
    if (_err != cudaSuccess) {                           \
        std::fprintf(stderr, "[CudaSearch] %s: %s\n",    \
            #expr, cudaGetErrorString(_err));            \
        return {};                                       \
    } } while (0)

} // namespace

CudaSearch::~CudaSearch() = default;

bool CudaSearch::available() {
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    return err == cudaSuccess && count > 0;
}

std::vector<size_t> CudaSearch::searchU64Range(
    const uint8_t* data, size_t size,
    uint64_t targetLow, uint64_t targetHigh)
{
    if (!data || size < 8 || !available()) return {};
    size_t slotCount = size / 8;
    size_t bytes = slotCount * sizeof(uint64_t);
    size_t outCap = 1u << 20;  // up to 1M hits per scan; fall back to CPU on overflow

    uint64_t* d_data = nullptr;
    size_t*   d_out  = nullptr;
    unsigned int* d_count = nullptr;

    CUDA_TRY(cudaMalloc(&d_data, bytes));
    CUDA_TRY(cudaMalloc(&d_out,  outCap * sizeof(size_t)));
    CUDA_TRY(cudaMalloc(&d_count, sizeof(unsigned int)));

    CUDA_TRY(cudaMemcpy(d_data, data, bytes, cudaMemcpyHostToDevice));
    unsigned int zero = 0;
    CUDA_TRY(cudaMemcpy(d_count, &zero, sizeof(zero), cudaMemcpyHostToDevice));

    constexpr int threadsPerBlock = 256;
    int blocks = (int)((slotCount + threadsPerBlock - 1) / threadsPerBlock);
    scanRangeKernel<<<blocks, threadsPerBlock>>>(
        d_data, slotCount, targetLow, targetHigh, d_out, d_count, outCap);

    cudaError_t launchErr = cudaGetLastError();
    if (launchErr != cudaSuccess) {
        std::fprintf(stderr, "[CudaSearch] kernel launch: %s\n", cudaGetErrorString(launchErr));
        cudaFree(d_data); cudaFree(d_out); cudaFree(d_count);
        return {};
    }
    CUDA_TRY(cudaDeviceSynchronize());

    unsigned int hits = 0;
    CUDA_TRY(cudaMemcpy(&hits, d_count, sizeof(hits), cudaMemcpyDeviceToHost));
    if (hits > outCap) hits = outCap;
    std::vector<size_t> out(hits);
    if (hits > 0)
        CUDA_TRY(cudaMemcpy(out.data(), d_out, hits * sizeof(size_t), cudaMemcpyDeviceToHost));

    cudaFree(d_data); cudaFree(d_out); cudaFree(d_count);
    return out;
}

} // namespace ce
