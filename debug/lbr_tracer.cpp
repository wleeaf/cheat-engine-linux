/// LBR tracer via perf_event_open(PERF_SAMPLE_BRANCH_STACK).

#include "debug/lbr_tracer.hpp"

#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>

#include <atomic>
#include <cstring>
#include <fstream>

namespace ce {

namespace {

long perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu,
                     int group_fd, unsigned long flags) {
    return ::syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

constexpr long PAGE_SZ = 4096;

// Per-sample record layout. We request PERF_SAMPLE_BRANCH_STACK only, so each
// sample is { u64 nr; perf_branch_entry[nr]; } prefixed by the header.
struct SampleHeader {
    struct perf_event_header h;
};

} // namespace

LbrTracer::~LbrTracer() { stop(); }

bool LbrTracer::available() {
    // Probe with a minimal attr; if perf_event_open works with branch-stack
    // sampling, the kernel supports it.
    struct perf_event_attr attr {};
    attr.type           = PERF_TYPE_HARDWARE;
    attr.size           = sizeof(attr);
    attr.config         = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    attr.disabled       = 1;
    attr.exclude_kernel = 1;
    attr.sample_type    = PERF_SAMPLE_BRANCH_STACK;
    attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_USER;
    attr.sample_period  = 1;
    int fd = (int)perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) return false;
    ::close(fd);
    return true;
}

bool LbrTracer::start(pid_t tid, int mmapPages) {
    stop();
    // Enforce power-of-two.
    int pages = 1;
    while (pages < mmapPages) pages <<= 1;

    struct perf_event_attr attr {};
    attr.type           = PERF_TYPE_HARDWARE;
    attr.size           = sizeof(attr);
    attr.config         = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    attr.disabled       = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv     = 1;
    attr.precise_ip     = 1;
    attr.sample_type    = PERF_SAMPLE_BRANCH_STACK;
    attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_USER;
    attr.sample_period  = 10'000;   // every 10k branches
    attr.wakeup_events  = 1;

    fd_ = (int)perf_event_open(&attr, tid, -1, -1, 0);
    if (fd_ < 0) { fd_ = -1; return false; }

    // 1 control page + N data pages.
    mmapSize_ = (1 + pages) * PAGE_SZ;
    mmapBase_ = ::mmap(nullptr, mmapSize_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (mmapBase_ == MAP_FAILED) {
        ::close(fd_);
        fd_ = -1;
        mmapBase_ = nullptr;
        mmapSize_ = 0;
        return false;
    }
    mmapPages_ = pages;

    ::ioctl(fd_, PERF_EVENT_IOC_RESET, 0);
    ::ioctl(fd_, PERF_EVENT_IOC_ENABLE, 0);
    return true;
}

std::vector<LbrEntry> LbrTracer::drain() {
    std::vector<LbrEntry> out;
    if (fd_ < 0 || !mmapBase_) return out;

    auto* mp = static_cast<perf_event_mmap_page*>(mmapBase_);
    uint64_t head = __atomic_load_n(&mp->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = mp->data_tail;
    const size_t dataSize = (size_t)mmapPages_ * PAGE_SZ;
    auto* dataBase = (uint8_t*)mmapBase_ + PAGE_SZ;

    // The perf data ring is a circular byte buffer of size dataSize; any record
    // may straddle the boundary. Copy each record into a linear scratch buffer
    // (handling the two-part wrap like intel_pt's drain) before parsing, and
    // bound everything by dataSize so we never read past the mapping.
    auto copyFromRing = [&](size_t off, void* dst, size_t n) {
        off %= dataSize;
        size_t first = (n < dataSize - off) ? n : (dataSize - off);
        std::memcpy(dst, dataBase + off, first);
        if (n > first)
            std::memcpy((uint8_t*)dst + first, dataBase, n - first);
    };

    // 8-byte-aligned scratch big enough for the largest record we accept
    // (header + u64 nr + up to 256 branch entries).
    alignas(8) uint8_t scratch[sizeof(perf_event_header) + sizeof(uint64_t) +
                               256 * sizeof(perf_branch_entry)];

    while (tail < head) {
        const uint64_t avail = head - tail;
        if (avail < sizeof(perf_event_header)) break;

        perf_event_header hdr;
        copyFromRing((size_t)(tail % dataSize), &hdr, sizeof(hdr));

        if (hdr.size < sizeof(perf_event_header) ||
            hdr.size > dataSize || hdr.size > avail)
            break;  // malformed / impossible size — stop draining

        if (hdr.type == PERF_RECORD_SAMPLE && hdr.size <= sizeof(scratch)) {
            // Linearize the whole record, then parse from the scratch copy.
            copyFromRing((size_t)(tail % dataSize), scratch, hdr.size);

            // Body is { u64 nr; perf_branch_entry[nr]; } after the header.
            uint64_t nr = 0;
            std::memcpy(&nr, scratch + sizeof(perf_event_header), sizeof(nr));
            // Validate the entries fit within this record before reading them.
            if (nr <= 256 &&
                sizeof(perf_event_header) + sizeof(uint64_t) +
                    nr * sizeof(perf_branch_entry) <= hdr.size) {
                auto* entries = reinterpret_cast<perf_branch_entry*>(
                    scratch + sizeof(perf_event_header) + sizeof(uint64_t));
                for (uint64_t i = 0; i < nr; ++i) {
                    LbrEntry e;
                    e.from = entries[i].from;
                    e.to   = entries[i].to;
                    e.mispred  = entries[i].mispred;
                    e.predicted = entries[i].predicted;
                    out.push_back(e);
                }
            }
        }

        tail += hdr.size;
    }

    __atomic_store_n(&mp->data_tail, tail, __ATOMIC_RELEASE);
    return out;
}

void LbrTracer::stop() {
    if (mmapBase_) {
        ::munmap(mmapBase_, mmapSize_);
        mmapBase_ = nullptr;
        mmapSize_ = 0;
    }
    if (fd_ >= 0) {
        ::ioctl(fd_, PERF_EVENT_IOC_DISABLE, 0);
        ::close(fd_);
        fd_ = -1;
    }
    mmapPages_ = 0;
}

} // namespace ce
