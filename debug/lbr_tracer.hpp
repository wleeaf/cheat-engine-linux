#pragma once
/// Last Branch Record tracer — uses Linux perf_event_open with
/// PERF_SAMPLE_BRANCH_STACK to sample the CPU's hardware branch buffer.
/// Gives a stream of (from_ip, to_ip) pairs the target took, useful for
/// branch-coverage analysis and post-mortem control-flow recovery.
///
/// Requirements at runtime:
///   - A kernel and CPU/PMU supporting hardware branch-stack sampling.
///   - Permission to open a perf event for the selected thread.
///   - The target thread is alive and `tid` is correct.
///
/// When perf_event_open fails, start() returns false; the tracer becomes
/// a no-op. Use lastError() for the actual start failure. available() probes the calling
/// thread; target-specific permissions are checked by start().

#include <cstdint>
#include <cstddef>
#include <vector>
#include <mutex>
#include <string>
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
    /// `mmapPages` controls the size of the ring buffer (positive counts round up to a power of two);
    /// default 64 kernel pages.
    bool start(pid_t tid, int mmapPages = 64);

    /// Drain accumulated samples since the last drain(). Returns the branch
    /// entries in the kernel's branch-stack order. Safe to call from any thread.
    std::vector<LbrEntry> drain();

    /// Stop sampling and release kernel resources.
    void stop();

    bool isActive() const { std::lock_guard lock(mutex_);return fd_>=0; }
    std::string lastError() const { std::lock_guard lock(mutex_);return error_; }

private:
    void stopLocked();
    mutable std::mutex mutex_;
    std::string error_;
    size_t pageSize_=0;
    int    fd_       = -1;
    void*  mmapBase_ = nullptr;
    size_t mmapSize_ = 0;
};

} // namespace ce
