/// RemoteProcessHandle — adapts CEServerClient into the ProcessHandle interface.

#include "platform/linux/ceserver_process.hpp"

#include <cstdint>
#include <system_error>

namespace ce::os {

namespace {

// CE Win32-style page protection bits.
constexpr uint32_t PAGE_NOACCESS         = 0x01;
constexpr uint32_t PAGE_READONLY         = 0x02;
constexpr uint32_t PAGE_READWRITE        = 0x04;
constexpr uint32_t PAGE_EXECUTE          = 0x10;
constexpr uint32_t PAGE_EXECUTE_READ     = 0x20;
constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;

// CE memory type bits.
constexpr uint32_t MEM_PRIVATE = 0x20000;
constexpr uint32_t MEM_MAPPED  = 0x40000;
constexpr uint32_t MEM_IMAGE   = 0x1000000;

MemProt toMemProt(uint32_t ceProtection) {
    if (ceProtection & PAGE_EXECUTE_READWRITE) return MemProt::All;
    if (ceProtection & PAGE_EXECUTE_READ)      return MemProt::ReadExec;
    if (ceProtection & PAGE_EXECUTE)           return MemProt::Exec;
    if (ceProtection & PAGE_READWRITE)         return MemProt::ReadWrite;
    if (ceProtection & PAGE_READONLY)          return MemProt::Read;
    return MemProt::None;
}

uint32_t toCeProtection(MemProt p) {
    bool r = (uint32_t)p & (uint32_t)MemProt::Read;
    bool w = (uint32_t)p & (uint32_t)MemProt::Write;
    bool x = (uint32_t)p & (uint32_t)MemProt::Exec;
    if (x && r && w) return PAGE_EXECUTE_READWRITE;
    if (x && r)      return PAGE_EXECUTE_READ;
    if (x)           return PAGE_EXECUTE;
    if (r && w)      return PAGE_READWRITE;
    if (r)           return PAGE_READONLY;
    return PAGE_NOACCESS;
}

MemType toMemType(uint32_t ceType) {
    if (ceType & MEM_IMAGE)  return MemType::Image;
    if (ceType & MEM_MAPPED) return MemType::Mapped;
    return MemType::Private;
}

MemoryRegion toMemoryRegion(const CeRegion& cr) {
    MemoryRegion r;
    r.base = cr.baseAddress;
    r.size = cr.size;
    r.protection = toMemProt(cr.protection);
    r.type = toMemType(cr.type);
    r.state = cr.size > 0 ? MemState::Committed : MemState::Free;
    return r;
}

Error remoteError() {
    return std::make_error_code(std::errc::io_error);
}

} // namespace

std::unique_ptr<RemoteProcessHandle> RemoteProcessHandle::open(CEServerClient& client, pid_t pid) {
    auto handle = client.openProcess(static_cast<int32_t>(pid));
    if (!handle || *handle == 0) return nullptr;
    auto arch = client.getArchitecture(*handle);
    bool is64 = arch && (*arch == CeArchitecture::X86_64 || *arch == CeArchitecture::ARM64);
    return std::unique_ptr<RemoteProcessHandle>(
        new RemoteProcessHandle(client, pid, *handle, is64));
}

RemoteProcessHandle::~RemoteProcessHandle() {
    if (client_ && handle_ != 0) {
        client_->closeHandle(handle_);
    }
}

Result<size_t> RemoteProcessHandle::read(uintptr_t address, void* buffer, size_t size) {
    if (size == 0) return size_t{0};
    // The ceserver protocol carries a 32-bit length; reject oversized requests
    // instead of silently truncating and reporting a short read as success.
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->readProcessMemory(handle_, address, buffer, static_cast<uint32_t>(size));
    if (!r) return std::unexpected(remoteError());
    return static_cast<size_t>(*r);
}

Result<size_t> RemoteProcessHandle::write(uintptr_t address, const void* buffer, size_t size) {
    if (size == 0) return size_t{0};
    // writeProcessMemory carries a signed 32-bit length on the wire; reject
    // oversized requests rather than truncating to a (possibly negative) value.
    if (size > static_cast<size_t>(INT32_MAX)) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->writeProcessMemory(handle_, address, buffer, static_cast<int32_t>(size));
    if (!r) return std::unexpected(remoteError());
    return static_cast<size_t>(*r);
}

std::vector<MemoryRegion> RemoteProcessHandle::queryRegions() {
    auto r = client_->virtualQueryExFull(handle_, 0);
    if (!r) return {};
    std::vector<MemoryRegion> out;
    out.reserve(r->size());
    for (const auto& cr : *r) out.push_back(toMemoryRegion(cr));
    return out;
}

std::optional<MemoryRegion> RemoteProcessHandle::queryRegion(uintptr_t address) {
    auto r = client_->virtualQueryEx(handle_, address);
    if (!r || !r->has_value()) return std::nullopt;
    return toMemoryRegion(**r);
}

Result<uintptr_t> RemoteProcessHandle::allocate(size_t size, MemProt protection, uintptr_t preferredBase) {
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->allocateMemory(handle_, preferredBase, static_cast<uint32_t>(size), toCeProtection(protection));
    if (!r) return std::unexpected(remoteError());
    if (*r == 0) return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    return *r;
}

Result<void> RemoteProcessHandle::free(uintptr_t address, size_t size) {
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->freeMemory(handle_, address, static_cast<uint32_t>(size));
    if (!r) return std::unexpected(remoteError());
    return {};
}

Result<void> RemoteProcessHandle::protect(uintptr_t address, size_t size, MemProt newProtection) {
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->changeMemoryProtection(handle_, address,
        static_cast<uint32_t>(size), toCeProtection(newProtection));
    if (!r) return std::unexpected(remoteError());
    return {};
}

std::vector<ModuleInfo> RemoteProcessHandle::modules() {
    auto r = client_->enumModules(static_cast<int32_t>(pid_));
    if (!r) return {};
    std::vector<ModuleInfo> out;
    out.reserve(r->size());
    for (const auto& m : *r) {
        ModuleInfo mi;
        mi.base = m.baseAddress;
        mi.size = static_cast<size_t>(m.moduleSize);
        mi.path = m.name;
        // Strip directory portion to keep parity with the local /proc-backed enumerator.
        auto slash = m.name.find_last_of('/');
        mi.name = slash == std::string::npos ? m.name : m.name.substr(slash + 1);
        mi.is64bit = is64bit_;
        out.push_back(std::move(mi));
    }
    return out;
}

std::vector<ThreadInfo> RemoteProcessHandle::threads() {
    auto r = client_->enumThreads(static_cast<int32_t>(pid_));
    if (!r) return {};
    std::vector<ThreadInfo> out;
    out.reserve(r->size());
    for (auto tid : *r) out.push_back(ThreadInfo{static_cast<pid_t>(tid)});
    return out;
}

} // namespace ce::os
