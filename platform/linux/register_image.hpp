#pragma once

#include "platform/process_api.hpp"

namespace ce::os {

// Opaque kernel register images preserve extensions that CpuContext does not
// model. Capture and restoration require a stop owned by the calling thread.
// Linux does not expose deferred SVE/SME exec-time vector lengths in GETREGSET;
// restoring those banks can reset that hidden configuration. This interface
// verifies ptrace-visible state, not unexposed per-thread kernel metadata.
// ARM32 uses its VFP bank and any available legacy FPA/compat TLS images.
// Native ARM legacy FPA is verified read-only: its SETREGSET path can panic
// hardened-usercopy kernels. A changed image retains recovery rather than
// invoking that path. Native ARM TLS/IWMMXt require additional adapters.
struct NativeExtendedContext {
    struct Regset {
        unsigned note = 0;
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> verification;
    };
    std::vector<Regset> regsets;
};
Result<NativeExtendedContext> captureNativeExtendedContext(pid_t tid);
// Read-only verification, using buffers reserved during capture.
Result<void> verifyNativeExtendedContext(pid_t tid, NativeExtendedContext& saved);
// No allocation is needed during restoration. On failure the caller must keep
// its stop, original images and private memory until a verified retry succeeds.
Result<void> restoreNativeExtendedContext(pid_t tid, NativeExtendedContext& saved);

} // namespace ce::os
