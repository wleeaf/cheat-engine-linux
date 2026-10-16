// 64-bit file offsets on 32-bit builds: /proc/<pid>/mem offsets are addresses.
#if !defined(_FILE_OFFSET_BITS)
#define _FILE_OFFSET_BITS 64
#endif
#include "platform/linux/kernel_driver.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <system_error>
#include <unistd.h>

namespace ce::os {

namespace {

static_assert(sizeof(off_t) == 8, "pread offsets must hold a full address");

std::error_code lastError() {
    return std::error_code(errno, std::generic_category());
}

std::string procPath(pid_t pid, const char* name) {
    return "/proc/" + std::to_string(pid) + "/" + name;
}

class FdGuard {
public:
    explicit FdGuard(int fd) : fd_(fd) {}
    ~FdGuard() { if (fd_ >= 0) ::close(fd_); }
    FdGuard(const FdGuard&) = delete;
    FdGuard& operator=(const FdGuard&) = delete;
    int get() const { return fd_; }

private:
    int fd_;
};

} // namespace

KernelDriverClient::~KernelDriverClient() {
    close();
}

bool KernelDriverClient::open(const std::string& path) {
    close();
    fd_ = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
    return fd_ >= 0;
}

void KernelDriverClient::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

Result<size_t> KernelDriverClient::readProcessMemory(
    pid_t pid,
    uintptr_t address,
    void* buffer,
    size_t size) {
    return accessProcessMemory(false, pid, address, buffer, size);
}

Result<size_t> KernelDriverClient::writeProcessMemory(
    pid_t pid,
    uintptr_t address,
    const void* buffer,
    size_t size) {
    return accessProcessMemory(true, pid, address, const_cast<void*>(buffer), size);
}

Result<size_t> KernelDriverClient::readPhysicalMemory(
    uint64_t physicalAddress,
    void* buffer,
    size_t size) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    if (!buffer && size != 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    cecore_kmod_phys_request mem{};
    mem.physical_address = physicalAddress;
    // Through uintptr_t so a 32-bit pointer is zero-extended, not sign-extended.
    mem.user_buffer = static_cast<__u64>(reinterpret_cast<uintptr_t>(buffer));
    mem.size = size;

    if (::ioctl(fd_, CECORE_KMOD_IOC_READ_PHYSICAL, &mem) < 0)
        return std::unexpected(lastError());
    // Never report more than was asked for, whatever the kernel side says.
    return static_cast<size_t>(std::min<uint64_t>(mem.bytes_transferred, size));
}

Result<VirtualAddressTranslation> KernelDriverClient::translateVirtualAddress(
    pid_t pid,
    uintptr_t virtualAddress) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    if (virtualAddress == 0 || pid <= 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    long pageSizeValue = ::sysconf(_SC_PAGESIZE);
    if (pageSizeValue <= 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    const auto pageSize = static_cast<uint64_t>(pageSizeValue);

    // pagemap: 8 bytes per page, bit 63 present, bits 0-54 the frame number
    // (zero unless the reader has CAP_SYS_ADMIN).
    FdGuard pagemap(::open(procPath(pid, "pagemap").c_str(), O_RDONLY | O_CLOEXEC));
    if (pagemap.get() < 0)
        return std::unexpected(lastError());
    const auto entryOffset = static_cast<off_t>((virtualAddress / pageSize) * sizeof(uint64_t));

    uint64_t entry = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        ssize_t got = ::pread(pagemap.get(), &entry, sizeof(entry), entryOffset);
        if (got < 0)
            return std::unexpected(lastError());
        if (got != static_cast<ssize_t>(sizeof(entry)))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        if ((entry >> 63) & 1)
            break;
        if (attempt == 0) {
            // Not resident: fault it in with a one-byte read, as the old ioctl did.
            uint8_t probe = 0;
            auto touched = readProcessMemory(pid, virtualAddress, &probe, 1);
            if (!touched)
                return std::unexpected(touched.error());
        }
    }
    if (!((entry >> 63) & 1))
        return std::unexpected(std::make_error_code(std::errc::no_such_device_or_address));

    const uint64_t pfn = entry & ((uint64_t{1} << 55) - 1);
    if (pfn == 0)
        return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));

    const auto pageOffset = static_cast<size_t>(virtualAddress % pageSize);
    return VirtualAddressTranslation{
        virtualAddress,
        pfn * pageSize + pageOffset,
        static_cast<size_t>(pageSize),
        pageOffset,
    };
}

Result<size_t> KernelDriverClient::accessProcessMemory(
    bool write,
    pid_t pid,
    uintptr_t address,
    void* buffer,
    size_t size) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    if ((!buffer && size != 0) || pid <= 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (size == 0)
        return size_t{0};

    // /proc/<pid>/mem checks ptrace access (Yama, LSMs) at open and forces
    // access like ptrace, so read-only code can be patched with copy-on-write.
    FdGuard mem(::open(procPath(pid, "mem").c_str(), (write ? O_RDWR : O_RDONLY) | O_CLOEXEC));
    if (mem.get() < 0)
        return std::unexpected(lastError());

    auto* bytes = static_cast<uint8_t*>(buffer);
    size_t done = 0;
    while (done < size) {
        auto offset = static_cast<off_t>(address + done);
        ssize_t moved = write ? ::pwrite(mem.get(), bytes + done, size - done, offset)
                              : ::pread(mem.get(), bytes + done, size - done, offset);
        if (moved < 0) {
            if (errno == EINTR)
                continue;
            if (done)
                break;
            return std::unexpected(lastError());
        }
        if (moved == 0)
            break;
        done += static_cast<size_t>(moved);
    }
    if (done == 0)
        return std::unexpected(std::make_error_code(std::errc::bad_address));
    return done;
}

} // namespace ce::os
