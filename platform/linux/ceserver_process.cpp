/// RemoteProcessHandle — adapts CEServerClient into the ProcessHandle interface.

#include "platform/linux/ceserver_process.hpp"
#include <algorithm>

#include <cstdint>
#include <string_view>
#include <system_error>

namespace ce::os {

namespace {

// CE Win32-style page protection bits.
constexpr uint32_t PAGE_NOACCESS         = 0x01;
constexpr uint32_t PAGE_READONLY         = 0x02;
constexpr uint32_t PAGE_READWRITE        = 0x04;
constexpr uint32_t PAGE_WRITECOPY        = 0x08;
constexpr uint32_t PAGE_EXECUTE          = 0x10;
constexpr uint32_t PAGE_EXECUTE_READ     = 0x20;
constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;
constexpr uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;
constexpr uint32_t PAGE_GUARD             = 0x100;

// CE memory type bits.
constexpr uint32_t MEM_PRIVATE = 0x20000;
constexpr uint32_t MEM_MAPPED  = 0x40000;
constexpr uint32_t MEM_IMAGE   = 0x1000000;

MemProt toMemProt(uint32_t ceProtection) {
    if (ceProtection & PAGE_GUARD) return MemProt::None;
    if (ceProtection & (PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)) return MemProt::All;
    if (ceProtection & PAGE_EXECUTE_READ)      return MemProt::ReadExec;
    if (ceProtection & PAGE_EXECUTE)           return MemProt::Exec;
    if (ceProtection & (PAGE_READWRITE|PAGE_WRITECOPY)) return MemProt::ReadWrite;
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

// Upstream VirtualQueryEx answers an address between mappings with a
// PAGE_NOACCESS region of type 0 reaching the next mapping. That is free
// address space, which the local handle does not report as a region at all.
// (A real PROT_NONE mapping keeps its nonzero type.)
bool isGap(const CeRegion& cr) {
    return cr.size == 0 || (cr.protection == PAGE_NOACCESS && cr.type == 0);
}

MemoryRegion toMemoryRegion(const CeRegion& cr) {
    MemoryRegion r;
    r.base = cr.baseAddress;
    r.size = cr.size;
    r.protection = toMemProt(cr.protection);
    r.type = toMemType(cr.type);
    r.state = isGap(cr) ? MemState::Free : MemState::Committed;
    return r;
}

TargetMachine wireMachine(CeArchitecture architecture) {
    switch (architecture) {
        case CeArchitecture::X86:
            return {CpuArchitecture::X86_32, ByteOrder::Little, TargetAbi::LinuxI386, InstructionMode::X86_32, 4};
        case CeArchitecture::X86_64:
            return {CpuArchitecture::X86_64, ByteOrder::Little, TargetAbi::LinuxX86_64, InstructionMode::X86_64, 8};
        // The wire architecture carries no byte order, but the protocol frames
        // every integer in the server's host order. Talking to it at all means
        // a little-endian host, and Linux ARM userland byte order is system-wide.
        case CeArchitecture::ARM32:
            return {CpuArchitecture::Arm32, ByteOrder::Little, TargetAbi::LinuxArmEabi, InstructionMode::Arm, 4};
        case CeArchitecture::ARM64:
            return {CpuArchitecture::Arm64, ByteOrder::Little, TargetAbi::LinuxAarch64, InstructionMode::Aarch64, 8};
        default: return {};
    }
}

Error remoteError() {
    return std::make_error_code(std::errc::io_error);
}

} // namespace

std::unique_ptr<RemoteProcessHandle> RemoteProcessHandle::open(CEServerClient& client, pid_t pid) {
    auto operation=client.lockConnection();
    auto handle = client.openProcess(static_cast<int32_t>(pid));
    if (!handle || *handle <= 0) return nullptr;
    auto arch = client.getArchitecture(*handle);
    if (!arch) {
        if (client.isConnected()) (void)client.closeHandle(*handle);
        return nullptr;
    }
    TargetMachine machine=wireMachine(*arch);
    return std::unique_ptr<RemoteProcessHandle>(
        new RemoteProcessHandle(client, pid, *handle, machine));
}

TargetDescription RemoteProcessHandle::targetDescription() {
    // Asks the server each time: an exec can change the program's architecture
    // and pointer width under the same handle. Callers in loops take it once.
    auto operation=client_->lockConnection();
    description_.live=connectionValid();
    if (description_.live) {
        auto architecture=client_->getArchitecture(handle_);
        description_.live=connectionValid();
        description_.program=architecture ? wireMachine(*architecture) : TargetMachine{};
        is64bit_=description_.program.pointerWidth==8;
    }
    described_=std::chrono::steady_clock::now();
    describedOnce_=true;
    return description_;
}

TargetMachine RemoteProcessHandle::machineAt(uintptr_t) {
    auto operation=client_->lockConnection();
    if (describedOnce_ && description_.live && connectionValid() && std::chrono::steady_clock::now()-described_<=std::chrono::seconds(1))
        return description_.program;
    return targetDescription().program;
}

RemoteProcessHandle::~RemoteProcessHandle() {
    auto operation=client_->lockConnection();
    if (connectionValid() && handle_ != 0) {
        (void)client_->closeHandle(handle_);
    }
}

Result<size_t> RemoteProcessHandle::read(uintptr_t address, void* buffer, size_t size) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    if (size == 0) return size_t{0};
    // The ceserver protocol carries a 32-bit length; reject oversized requests
    // instead of silently truncating and reporting a short read as success.
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    // In pieces: each command has its own deadline, and one 64 MiB transfer
    // over a slow link timed out mid-payload, which closes the connection.
    constexpr size_t kChunk = size_t(1) << 20;
    size_t done = 0;
    while (done < size) {
        const size_t part = std::min(kChunk, size - done);
        auto r = client_->readProcessMemory(handle_, address + done, static_cast<uint8_t*>(buffer) + done,
                                            static_cast<uint32_t>(part));
        if (!r) {
            if (done) return done;   // the readable prefix, as a local partial read
            return std::unexpected(remoteError());
        }
        done += static_cast<size_t>(*r);
        if (static_cast<size_t>(*r) < part) break;   // end of readable memory
    }
    return done;
}

Result<size_t> RemoteProcessHandle::write(uintptr_t address, const void* buffer, size_t size) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    if (size == 0) return size_t{0};
    // writeProcessMemory carries a signed 32-bit length on the wire; reject
    // oversized requests rather than truncating to a (possibly negative) value.
    if (size > static_cast<size_t>(INT32_MAX)) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    constexpr size_t kChunk = size_t(1) << 20;   // see read()
    size_t done = 0;
    while (done < size) {
        const size_t part = std::min(kChunk, size - done);
        auto r = client_->writeProcessMemory(handle_, address + done, static_cast<const uint8_t*>(buffer) + done,
                                             static_cast<int32_t>(part));
        if (!r) {
            if (done) return done;
            return std::unexpected(remoteError());
        }
        done += static_cast<size_t>(*r);
        if (static_cast<size_t>(*r) < part) break;
    }
    return done;
}

std::vector<MemoryRegion> RemoteProcessHandle::queryRegions() {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return {};
    auto r = client_->virtualQueryExFull(handle_, 0);
    if (!r) return {};
    std::vector<MemoryRegion> out;
    out.reserve(r->size());
    for (const auto& cr : *r)
        if (!isGap(cr)) out.push_back(toMemoryRegion(cr));
    return out;
}

std::optional<MemoryRegion> RemoteProcessHandle::queryRegion(uintptr_t address) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::nullopt;
    auto r = client_->virtualQueryEx(handle_, address);
    if (!r || !r->has_value() || isGap(**r)) return std::nullopt;
    return toMemoryRegion(**r);
}

Result<uintptr_t> RemoteProcessHandle::allocate(size_t size, MemProt protection, uintptr_t preferredBase) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->allocateMemory(handle_, preferredBase, static_cast<uint32_t>(size), toCeProtection(protection));
    if (!r) return std::unexpected(remoteError());
    if (*r == 0) return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    return *r;
}

Result<void> RemoteProcessHandle::free(uintptr_t address, size_t size) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->freeMemory(handle_, address, static_cast<uint32_t>(size));
    if (!r || !*r) return std::unexpected(remoteError());
    return {};
}

Result<void> RemoteProcessHandle::protect(uintptr_t address, size_t size, MemProt newProtection) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    if (size > UINT32_MAX) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto r = client_->changeMemoryProtection(handle_, address,
        static_cast<uint32_t>(size), toCeProtection(newProtection));
    if (!r || !r->result) return std::unexpected(remoteError());
    return {};
}

std::vector<ModuleInfo> RemoteProcessHandle::modules() {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return {};
    auto r = client_->enumModules(static_cast<int32_t>(pid_));
    if (!r) return {};
    std::vector<ModuleInfo> out;
    out.reserve(r->size());
    for (const auto& m : *r) {
        ModuleInfo mi;
        mi.base = m.baseAddress;
        // The wire field is 32 bits: read it unsigned (a negative value from a
        // hostile server is not ~2^64), and never let base + size wrap.
        mi.size = static_cast<uint32_t>(m.moduleSize);
        if (mi.size > UINTPTR_MAX - mi.base) mi.size = UINTPTR_MAX - mi.base;
        mi.path = m.name;
        // Strip directory portion to keep parity with the local /proc-backed enumerator.
        auto slash = m.name.find_last_of('/');
        mi.name = slash == std::string::npos ? m.name : m.name.substr(slash + 1);
        // A library replaced on disk while mapped keeps the name it is known
        // by (as locally), so "libgame.so+1C" still resolves. The path keeps
        // the suffix the server sent.
        if (constexpr std::string_view deleted = " (deleted)"; mi.name.ends_with(deleted))
            mi.name.resize(mi.name.size() - deleted.size());
        mi.is64bit = is64bit_;
        out.push_back(std::move(mi));
    }
    return out;
}

std::vector<ThreadInfo> RemoteProcessHandle::threads() {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return {};
    auto r = client_->enumThreads(static_cast<int32_t>(pid_));
    if (!r) return {};
    std::vector<ThreadInfo> out;
    out.reserve(r->size());
    for (auto tid : *r) out.push_back(ThreadInfo{static_cast<pid_t>(tid)});
    return out;
}

} // namespace ce::os
