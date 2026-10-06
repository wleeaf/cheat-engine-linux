/// LBR tracer via perf_event_open(PERF_SAMPLE_BRANCH_STACK).

#include "debug/lbr_tracer.hpp"
#include "debug/perf_ring.hpp"
#include <cerrno>

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
    attr.exclude_hv=1;
    attr.sample_period  = 10'000;
    int fd = (int)perf_event_open(&attr, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) return false;
    ::close(fd);
    return true;
}

bool LbrTracer::start(pid_t tid, int mmapPages) {
    std::lock_guard lock(mutex_);stopLocked();error_.clear();
    if (tid<=0) {error_="Choose a positive target thread ID";return false;}
    const long page=sysconf(_SC_PAGESIZE);
    auto layout=page>0 ? detail::perfMappingSize(static_cast<size_t>(page),mmapPages) : std::nullopt;
    if (!layout) {error_="Invalid kernel page size or ring page count";return false;}
    pageSize_=page;

    struct perf_event_attr attr {};
    attr.type           = PERF_TYPE_HARDWARE;
    attr.size           = sizeof(attr);
    attr.config         = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    attr.disabled       = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv     = 1;
    attr.precise_ip     = 0; // Branch-stack samples do not request precise IP.
    attr.sample_type    = PERF_SAMPLE_BRANCH_STACK;
    attr.branch_sample_type = PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_USER;
    attr.sample_period  = 10'000;   // every 10k branches
    attr.wakeup_events  = 1;

    fd_ = (int)perf_event_open(&attr, tid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd_<0) {error_=std::strerror(errno);fd_=-1;return false;}

    // 1 control page + N data pages.
    mmapSize_=layout->mappingBytes;
    mmapBase_ = ::mmap(nullptr, mmapSize_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (mmapBase_ == MAP_FAILED) {
        error_=std::strerror(errno);
        ::close(fd_);
        fd_ = -1;
        mmapBase_ = nullptr;
        mmapSize_ = 0;
        return false;
    }
    if (::ioctl(fd_,PERF_EVENT_IOC_RESET,0)<0 || ::ioctl(fd_,PERF_EVENT_IOC_ENABLE,0)<0) {
        error_=std::strerror(errno);stopLocked();return false;
    }
    return true;
}

std::vector<LbrEntry> LbrTracer::drain() {
    std::lock_guard lock(mutex_);
    if (fd_<0 || !mmapBase_) return {};
    return detail::drainPerfBranches({static_cast<uint8_t*>(mmapBase_),mmapSize_},pageSize_);
}

void LbrTracer::stop() {std::lock_guard lock(mutex_);stopLocked();}

void LbrTracer::stopLocked() {
    if (fd_>=0) ::ioctl(fd_,PERF_EVENT_IOC_DISABLE,0);
    if (mmapBase_) {
        ::munmap(mmapBase_, mmapSize_);
        mmapBase_ = nullptr;
        mmapSize_ = 0;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    pageSize_=0;
}

} // namespace ce
