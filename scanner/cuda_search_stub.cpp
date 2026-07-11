/// CUDA stub — picked up by the build when find_package(CUDAToolkit)
/// didn't find anything. The .cu file in this directory provides the
/// real implementation; exactly one of them links into cecore.

#include "scanner/cuda_search.hpp"

namespace ce {

CudaSearch::~CudaSearch() = default;
bool CudaSearch::available() { return false; }
std::vector<size_t> CudaSearch::searchU64Range(
    const uint8_t*, size_t, uint64_t, uint64_t) { return {}; }

} // namespace ce
