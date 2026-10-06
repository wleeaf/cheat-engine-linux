/// Intel PT tracer — opens a PT perf event, drains the AUX ring.

#include "debug/intel_pt.hpp"
#include "debug/perf_ring.hpp"
#include <cerrno>
#include <limits>

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
    std::lock_guard lock(mutex_);stopLocked();error_.clear();
    if (tid<=0) {error_="Choose a positive target thread ID";return false;}
    const long page=sysconf(_SC_PAGESIZE);
    auto data=page>0 ? detail::perfMappingSize(static_cast<size_t>(page),dataPages) : std::nullopt;
    auto aux=page>0 ? detail::perfMappingSize(static_cast<size_t>(page),auxPages) : std::nullopt;
    if (!data || !aux || data->mappingBytes>static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
        error_="Invalid kernel page size or ring page count";return false;
    }
    pageSize_=page;
    const uint32_t ptType=readIntelPtType();
    if (!ptType) {error_="Intel PT event source unavailable";return false;}

    struct perf_event_attr attr {};
    attr.type           = ptType;
    attr.size           = sizeof(attr);
    attr.config         = 0;
    attr.disabled       = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv     = 1;

    fd_ = (int)perf_event_open(&attr, tid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd_<0) {error_=std::strerror(errno);fd_=-1;return false;}

    // Data ring (control page + data pages).
    dataSize_=data->mappingBytes;
    dataBase_ = ::mmap(nullptr, dataSize_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
    if (dataBase_ == MAP_FAILED) {
        error_=std::strerror(errno);
        ::close(fd_); fd_ = -1;
        dataBase_ = nullptr; dataSize_ = 0;
        return false;
    }

    // AUX ring — set aux_offset / aux_size in the mmap page, then mmap at
    // aux_offset.
    auto* mp = static_cast<perf_event_mmap_page*>(dataBase_);
    auxSize_=aux->dataBytes;
    mp->aux_offset = dataSize_;
    mp->aux_size   = auxSize_;
    auxBase_ = ::mmap(nullptr, auxSize_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, mp->aux_offset);
    if (auxBase_ == MAP_FAILED) {
        error_=std::strerror(errno);
        ::munmap(dataBase_, dataSize_);
        ::close(fd_); fd_ = -1;
        dataBase_ = nullptr; dataSize_ = 0;
        auxBase_  = nullptr; auxSize_  = 0;
        return false;
    }

    if (::ioctl(fd_,PERF_EVENT_IOC_RESET,0)<0 || ::ioctl(fd_,PERF_EVENT_IOC_ENABLE,0)<0) {
        error_=std::strerror(errno);stopLocked();return false;
    }
    return true;
}

std::vector<uint8_t> IntelPtTracer::drain() {
    std::lock_guard lock(mutex_);
    if (fd_<0 || !auxBase_ || !dataBase_) return {};
    return detail::drainPerfAux({static_cast<uint8_t*>(dataBase_),dataSize_},
                               {static_cast<uint8_t*>(auxBase_),auxSize_},pageSize_);
}

void IntelPtTracer::stop() {std::lock_guard lock(mutex_);stopLocked();}

void IntelPtTracer::stopLocked() {
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
    pageSize_=0;
}

} // namespace ce
