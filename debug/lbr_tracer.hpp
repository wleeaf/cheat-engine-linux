#pragma once
/// Last Branch Record tracer — uses Linux perf_event_open with
/// PERF_SAMPLE_BRANCH_STACK to sample the CPU's hardware branch buffer.
/// Gives a stream of (from_ip, to_ip) pairs the target took, useful for
/// branch-coverage analysis and post-mortem control-flow recovery.
///
/// Requirements at runtime:
///   - Linux kernel with hardware LBR support (Intel: Sandy Bridge+).
///   - CAP_SYS_ADMIN, or kernel.perf_event_paranoid <= 1.
///   - The target thread is alive and `tid` is correct.
///
/// When perf_event_open fails, start() returns false; the tracer becomes
/// a no-op. Read available() to distinguish "kernel doesn't support" from
/// "wasn't enabled by the user".

#include <cstdint>
#include <cstddef>
#include <vector>
#include <sys/types.h>

namespace ce {

struct LbrEntry {
    uint64_t from;
    uint64_t to;
    bool mispred;
    bool predicted;
};

class LbrTracer {
public:
    LbrTracer() = default;
    ~LbrTracer();

    LbrTracer(const LbrTracer&) = delete;
    LbrTracer& operator=(const LbrTracer&) = delete;

    /// Whether perf_event_open with branch-stack sampling is available on
    /// this kernel + thread. Cheap to call.
    static bool available();

    /// Start sampling on `tid`. Returns false if perf_event_open fails.
    /// `mmapPages` controls the size of the ring buffer (must be power of two);
    /// default 64 pages = 256 KiB.
    bool start(pid_t tid, int mmapPages = 64);

    /// Drain accumulated samples since the last drain(). Returns the branch
    /// entries seen, in chronological order. Safe to call from any thread.
    std::vector<LbrEntry> drain();

    /// Stop sampling and release kernel resources.
    void stop();

    bool isActive() const { return fd_ >= 0; }

private:
    int    fd_       = -1;
    void*  mmapBase_ = nullptr;
    size_t mmapSize_ = 0;
    int    mmapPages_ = 0;
};

} // namespace ce
