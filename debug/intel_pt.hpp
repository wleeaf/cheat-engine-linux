#pragma once
/// Minimal Intel PT (Processor Trace) capture via perf_event_open.
///
/// Opens a PT event on the target tid, maps the AUX ring buffer, and lets
/// the caller drain raw trace bytes for offline decoding (typically via
/// libipt). Decoding is intentionally not done here — libipt isn't a hard
/// dependency, and most consumers want the raw bytes to feed into an
/// existing pipeline.
///
/// At runtime needs:
///   - Intel CPU with PT support
///   - Linux kernel exposing /sys/bus/event_source/devices/intel_pt
///   - CAP_SYS_ADMIN or kernel.perf_event_paranoid <= 1
///
/// available() returns false when any of the above is missing.

#include <cstddef>
#include <cstdint>
#include <sys/types.h>
#include <vector>

namespace ce {

class IntelPtTracer {
public:
    IntelPtTracer() = default;
    ~IntelPtTracer();

    IntelPtTracer(const IntelPtTracer&) = delete;
    IntelPtTracer& operator=(const IntelPtTracer&) = delete;

    /// Cheap probe: is intel_pt exposed as a perf event source?
    static bool available();

    /// Start sampling for `tid`. `dataPages` controls the perf data ring
    /// (must be power of two); `auxPages` the PT AUX buffer (the trace
    /// itself). Both default to sensible sizes.
    bool start(pid_t tid, int dataPages = 16, int auxPages = 64);

    /// Drain raw PT bytes accumulated since the last call. Empty when the
    /// tracer hasn't filled new bytes yet. Safe to call from any thread.
    std::vector<uint8_t> drain();

    void stop();

    bool isActive() const { return fd_ >= 0; }

private:
    int    fd_       = -1;
    void*  dataBase_ = nullptr;
    size_t dataSize_ = 0;
    void*  auxBase_  = nullptr;
    size_t auxSize_  = 0;
};

} // namespace ce
