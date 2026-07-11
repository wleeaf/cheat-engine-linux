/// Intel PT tracer — opens a PT perf event, drains the AUX ring.

#include "debug/intel_pt.hpp"

#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>

#include <cstring>
#include <fstream>

namespace ce {

namespace {

long perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu,
                     int group_fd, unsigned long flags) {
    return ::syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

constexpr long PAGE_SZ = 4096;

uint32_t readIntelPtType() {
    std::ifstream f("/sys/bus/event_source/devices/intel_pt/type");
    if (!f.is_open()) return 0;
    uint32_t t = 0;
    f >> t;
    return t;
}

} // namespace

IntelPtTracer::~IntelPtTracer() { stop(); }

bool IntelPtTracer::available() {
    return readIntelPtType() != 0;
}

bool IntelPtTracer::start(pid_t tid, int dataPages, int auxPages) {
    stop();
    uint32_t ptType = readIntelPtType();
    if (ptType == 0) return false;

    auto pow2 = [](int v) { int p = 1; while (p < v) p <<= 1; return p; };
    dataPages = pow2(dataPages);
    auxPages  = pow2(auxPages);

    struct perf_event_attr attr {};
    attr.type           = ptType;
    attr.size           = sizeof(attr);
    attr.config         = 0;
    attr.disabled       = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv     = 1;

    fd_ = (int)perf_event_open(&attr, tid, -1, -1, 0);
    if (fd_ < 0) { fd_ = -1; return false; }

    // Data ring (control page + data pages).
    dataSize_ = (1 + dataPages) * PAGE_SZ;
    dataBase_ = ::mmap(nullptr, dataSize_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (dataBase_ == MAP_FAILED) {
        ::close(fd_); fd_ = -1;
        dataBase_ = nullptr; dataSize_ = 0;
        return false;
    }

    // AUX ring — set aux_offset / aux_size in the mmap page, then mmap at
    // aux_offset.
    auto* mp = static_cast<perf_event_mmap_page*>(dataBase_);
    auxSize_ = (size_t)auxPages * PAGE_SZ;
    mp->aux_offset = dataSize_;
    mp->aux_size   = auxSize_;
    auxBase_ = ::mmap(nullptr, auxSize_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, mp->aux_offset);
    if (auxBase_ == MAP_FAILED) {
        ::munmap(dataBase_, dataSize_);
        ::close(fd_); fd_ = -1;
        dataBase_ = nullptr; dataSize_ = 0;
        auxBase_  = nullptr; auxSize_  = 0;
        return false;
    }

    ::ioctl(fd_, PERF_EVENT_IOC_RESET, 0);
    ::ioctl(fd_, PERF_EVENT_IOC_ENABLE, 0);
    return true;
}

std::vector<uint8_t> IntelPtTracer::drain() {
    std::vector<uint8_t> out;
    if (fd_ < 0 || !auxBase_ || !dataBase_) return out;

    auto* mp = static_cast<perf_event_mmap_page*>(dataBase_);
    uint64_t head = __atomic_load_n(&mp->aux_head, __ATOMIC_ACQUIRE);
    uint64_t tail = __atomic_load_n(&mp->aux_tail, __ATOMIC_RELAXED);

    // head == tail means no new data. head < tail is impossible for a
    // monotonically-advancing ring; treat it as a corrupt/torn read and bail
    // rather than computing a wild "available" length.
    if (head <= tail) return out;
    uint64_t available = head - tail;
    if (available > auxSize_) available = auxSize_;
    out.reserve((size_t)available);

    // AUX is a circular byte buffer of size auxSize_.
    size_t start = (size_t)(tail % auxSize_);
    auto* base = (uint8_t*)auxBase_;
    if (start + available <= auxSize_) {
        out.insert(out.end(), base + start, base + start + (size_t)available);
    } else {
        size_t first = auxSize_ - start;
        out.insert(out.end(), base + start, base + start + first);
        out.insert(out.end(), base, base + ((size_t)available - first));
    }

    __atomic_store_n(&mp->aux_tail, head, __ATOMIC_RELEASE);
    // TODO(security): drain() is documented as callable from any thread but is
    // only safe for a single draining thread; concurrent drains would race the
    // aux_tail read-modify-write above. Enforce single-threaded drain or guard
    // with a mutex if multi-thread drain is ever needed.
    return out;
}

void IntelPtTracer::stop() {
    if (fd_ >= 0)
        ::ioctl(fd_, PERF_EVENT_IOC_DISABLE, 0);
    if (auxBase_) {
        ::munmap(auxBase_, auxSize_);
        auxBase_ = nullptr; auxSize_ = 0;
    }
    if (dataBase_) {
        ::munmap(dataBase_, dataSize_);
        dataBase_ = nullptr; dataSize_ = 0;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

} // namespace ce
