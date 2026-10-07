// /proc memory addresses exceed signed 32-bit file offsets on 32-bit engines.
#if defined(__arm__) && !defined(_FILE_OFFSET_BITS)
#define _FILE_OFFSET_BITS 64
#endif
#include "platform/linux/memory_image.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/syscall_service.hpp"

#include <cerrno>
#include <fcntl.h>
#include <new>
#include <array>
#include <unistd.h>

namespace ce::os {
namespace {
std::error_code error() { return {errno, std::system_category()}; }
}

NativeMemoryImage::~NativeMemoryImage() { if (fd_ >= 0) close(fd_); }

std::expected<std::shared_ptr<NativeMemoryImage>,std::error_code> NativeMemoryImage::retainStoppedFd(
    int fd,const TargetProcessIdentity& identity,const TargetMachine& host) {
    try {
        auto image=std::make_shared<NativeMemoryImage>();
        image->identity_=identity;image->host_=host;
        do {image->fd_=fcntl(fd,F_DUPFD_CLOEXEC,0);} while(image->fd_<0 && errno==EINTR);
        if(image->fd_<0) return std::unexpected(error());
        return image;
    } catch(const std::bad_alloc&) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }
}

std::expected<std::shared_ptr<NativeMemoryImage>, std::error_code> NativeMemoryImage::capture(
    const TargetProcessIdentity& identity, const TargetMachine& host) {
    try {
        auto actual = processMemoryIdentity(identity.pid);
        if (!actual) return std::unexpected(actual.error());
        if (*actual != identity) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        auto task = processMemoryTask(identity.pid);
        if (!task) return std::unexpected(task.error());
        auto member = targetProcessIdentity(*task);
        if (!member) return std::unexpected(member.error());
        auto image = std::make_shared<NativeMemoryImage>();
        image->identity_ = identity;
        image->host_ = host;
        const auto path = "/proc/" + std::to_string(*task) + "/mem";
        image->fd_ = open(path.c_str(), O_RDWR | O_CLOEXEC);
        if (image->fd_ < 0) return std::unexpected(error());
        actual = processMemoryIdentity(identity.pid);
        auto now = targetProcessIdentity(*task);
        if (!actual || !now || *actual != identity || *now != *member)
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        auto live = image->check();
        if (!live) return std::unexpected(live.error());
        return image;
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }
}

std::expected<void, std::error_code> NativeMemoryImage::check() const {
    uint8_t byte = 0;
    ssize_t n;
    do { n = pread(fd_, &byte, 1, 0); } while (n < 0 && errno == EINTR);
    if (!n) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    // An unmapped address is EIO/EFAULT for a live mm. Retired mm_users==0
    // returns zero before testing whether this probe address is mapped.
    if (n < 0 && errno != EIO && errno != EFAULT) return std::unexpected(error());
    return {};
}

std::expected<void,std::error_code> NativeMemoryImage::sharesPrivateMapping(
    const NativeMemoryImage& owner,uintptr_t address) const {
    return sharesPrivateBytes(owner,address,16);
}

std::expected<void,std::error_code> NativeMemoryImage::sharesPrivateBytes(
    const NativeMemoryImage& owner,uintptr_t address,size_t count) const {
    if (!count || count>16) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    std::array<uint8_t,16> candidate{},original{},marker{},actual{};
    auto readCandidate=read(address,candidate.data(),count);
    if (!readCandidate) {
        if (readCandidate.error()==std::errc::io_error || readCandidate.error()==std::errc::bad_address)
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        return std::unexpected(readCandidate.error());
    }
    if (*readCandidate!=count) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    auto saved=owner.read(address,original.data(),count);
    if (!saved || *saved!=count) return std::unexpected(saved ? std::make_error_code(std::errc::io_error) : saved.error());
    for (size_t i=0;i<count;++i) marker[i]=candidate[i]^0xff;
    auto writeOwner=[&](const auto& bytes) -> Result<void> {
        ssize_t n;
        do {n=pwrite(owner.fd_,bytes.data(),count,static_cast<off_t>(address));} while(n<0 && errno==EINTR);
        if (n<0) return std::unexpected(error());
        if (!n) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (static_cast<size_t>(n)!=count) return std::unexpected(std::make_error_code(std::errc::io_error));
        auto verified=owner.read(address,actual.data(),count);
        if (!verified || *verified!=count || actual!=bytes)
            return std::unexpected(verified ? std::make_error_code(std::errc::io_error) : verified.error());
        return {};
    };
    auto written=writeOwner(marker);
    auto observed=written ? read(address,actual.data(),count) : Result<size_t>(std::unexpected(written.error()));
    const bool same=observed && *observed==count && actual==marker;
    // Even ambiguous/short failures may have changed the private mapping.
    auto restored=writeOwner(original);
    if (!restored) return std::unexpected(std::make_error_code(std::errc::state_not_recoverable));
    if (!written) return std::unexpected(written.error());
    if (!observed && observed.error()!=std::errc::io_error && observed.error()!=std::errc::bad_address)
        return std::unexpected(observed.error());
    if (!same) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    return {};
}

std::expected<int, std::error_code> NativeMemoryImage::duplicateFd() const {
    int fd;
    do { fd = fcntl(fd_, F_DUPFD_CLOEXEC, 0); } while (fd < 0 && errno == EINTR);
    if (fd < 0) return std::unexpected(error());
    return fd;
}

std::expected<size_t, std::error_code> NativeMemoryImage::read(uintptr_t address, void* buffer, size_t size) const {
    if (!size) return size_t(0);
    if (!buffer || size - 1 > UINTPTR_MAX - address)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    ssize_t n;
    do { n = pread(fd_, buffer, size, static_cast<off_t>(address)); } while (n < 0 && errno == EINTR);
    if (n < 0) return std::unexpected(error());
    if (!n) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    return static_cast<size_t>(n);
}

std::expected<size_t, std::error_code> NativeMemoryImage::write(
    uintptr_t address, std::span<const uint8_t> bytes, bool executable) const {
    if (executable && !host_.isX86() && host_.architecture != CpuArchitecture::Arm64)
        return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
    return memorySyscallService().writeCode(identity_, address, bytes, this);
}

std::expected<uintptr_t, std::error_code> NativeMemoryImage::allocate(size_t size, MemProt p, uintptr_t preferred) const {
    LinuxProcessHandle process(identity_.pid);
    return process.allocateInImage(size, p, preferred, this);
}

std::expected<void, std::error_code> NativeMemoryImage::protect(uintptr_t address, size_t size, MemProt p) const {
    LinuxProcessHandle process(identity_.pid);
    return process.protectInImage(address, size, p, this);
}

std::expected<void, std::error_code> NativeMemoryImage::free(uintptr_t address, size_t size) const {
    LinuxProcessHandle process(identity_.pid);
    return process.freeInImage(address, size, this);
}

std::expected<std::shared_ptr<NativeMemoryImage>, std::error_code> pinNativeMemoryImage(ProcessHandle& proc) {
    if (!dynamic_cast<LinuxProcessHandle*>(&proc)) return std::shared_ptr<NativeMemoryImage>{};
    auto identity = processMemoryIdentity(proc.pid());
    if (!identity) return std::unexpected(identity.error());
    return NativeMemoryImage::capture(*identity, proc.targetDescription().host);
}

} // namespace ce::os
