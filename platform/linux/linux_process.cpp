#include "platform/linux/linux_process.hpp"
#include "platform/linux/memory_image.hpp"
#include "platform/linux/syscall_service.hpp"
#include "platform/linux/runtime_probe.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <cstring>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
// Kernels ≥4.17 fail (rather than clobber) a fixed mmap whose address is taken;
// define a fallback so the build works on older libc headers.
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <cerrno>
#include <cstring>
#include "core/log.hpp"
#include "core/ns_attach.hpp"
#include "core/target_capabilities.hpp"
#include <sys/stat.h>
#include <poll.h>
#include <array>

namespace ce::os {

namespace fs = std::filesystem;

// ── LinuxProcessHandle ──

namespace {
uint64_t processStartTime(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!std::getline(f, line)) return 0;
    auto close = line.rfind(')');
    if (close == std::string::npos) return 0;
    std::istringstream fields(line.substr(close + 1));
    std::string field;
    for (int i = 0; i <= 19; ++i) if (!(fields >> field)) return 0;
    try { return std::stoull(field); } catch (...) { return 0; }
}
TargetMachine readElfMachine(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::array<uint8_t, 64> bytes{};
    f.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    auto machine = parseElfTarget({bytes.data(), static_cast<size_t>(f.gcount())});
    return machine ? *machine : TargetMachine{};
}
std::string asciiLower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return s;
}
template<class Operation> ssize_t memoryTransfer(pid_t pid,Operation operation) {
    auto result=operation(pid);
    if (result<0 && errno==ESRCH) {
        auto task=processMemoryTask(pid);
        if (task && *task!=pid) result=operation(*task);
        else if (!task) errno=task.error().value();
    }
    return result;
}
} // namespace

LinuxProcessHandle::LinuxProcessHandle(pid_t pid) : pid_(pid) {
    description_.transport = TargetTransport::Local;
    startTime_ = processStartTime(pid_);
#ifdef SYS_pidfd_open
    if (pid_ > 0) pidfd_ = static_cast<int>(syscall(SYS_pidfd_open, pid_, 0));
#endif
    if (processStartTime(pid_) != startTime_) {
        if (pidfd_ >= 0) close(pidfd_);
        pidfd_ = -1; startTime_ = 0;
    }
    refreshMachine();
}

LinuxProcessHandle::~LinuxProcessHandle() { if (pidfd_ >= 0) close(pidfd_); }

bool LinuxProcessHandle::sameProcess() const {
    if (pid_ <= 0 || !startTime_) return false;
    if (pidfd_ >= 0) {
        pollfd fd{pidfd_, POLLIN, 0};
        int rc;
        do { rc = poll(&fd, 1, 0); } while (rc < 0 && errno == EINTR);
        return rc == 0;
    }
    return processStartTime(pid_) == startTime_;
}

void LinuxProcessHandle::refreshMachine() {
    std::lock_guard lock(metadataMutex_);
    description_.live = sameProcess();
    if (!description_.live) { description_.host = {}; description_.program = {}; return; }
    auto task=processMemoryTask(pid_);
    std::string path = "/proc/" + std::to_string(task ? *task : pid_) + "/exe";
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    struct stat st{};
    if (fd < 0 || fstat(fd, &st) != 0) {
        if (fd >= 0) close(fd);
        description_.host = {}; description_.program = {}; programKnown_ = false;
        exeDevice_ = exeInode_ = 0;
        return;
    }
    if (exeDevice_ == static_cast<uint64_t>(st.st_dev) && exeInode_ == static_cast<uint64_t>(st.st_ino)) {
        close(fd); return;
    }
    std::array<uint8_t, 64> bytes{};
    ssize_t n;
    do { n = ::read(fd, bytes.data(), bytes.size()); } while (n < 0 && errno == EINTR);
    close(fd);
    auto machine = parseElfTarget({bytes.data(), n > 0 ? static_cast<size_t>(n) : 0});
    description_.host = machine ? *machine : TargetMachine{};
    description_.program = description_.host;
    description_.mixedCode = false;
    description_.runtime = TargetRuntime::Native;
    exeDevice_ = st.st_dev; exeInode_ = st.st_ino;
    programKnown_ = false;
    is64bit_ = description_.host.pointerWidth != 4;
    std::ifstream cmdline("/proc/" + std::to_string(task ? *task : pid_) + "/cmdline", std::ios::binary);
    std::string cmd(16 * 1024, '\0');
    cmdline.read(cmd.data(), cmd.size());
    cmd.resize(cmdline.gcount()); cmd = asciiLower(std::move(cmd));
    wineHint_ = hasWineLoader(task ? *task : pid_);
    if (cmd.find("qemu-") != std::string::npos || cmd.find("box64") != std::string::npos ||
        cmd.find("box86") != std::string::npos || cmd.find("fex-") != std::string::npos)
        description_.runtime = TargetRuntime::Emulated;
}

TargetDescription LinuxProcessHandle::targetDescription() {
    // An inspection callback on the owner can request this same metadata.
    // Query the owner before taking the handle lock to avoid lock inversion.
    const bool pending=hasPendingMemorySyscalls(pid_,startTime_);
    std::lock_guard lock(metadataMutex_);
    refreshMachine();
    if (!description_.live) return description_;
    if (wineHint_ && !programKnown_) {
        auto mods = modules();
        for (const auto& module : mods) {
            if (!asciiLower(module.name).ends_with(".exe") || module.machine.abi < TargetAbi::WindowsI386) continue;
            description_.program = module.machine;
            description_.runtime = TargetRuntime::Wine;
            description_.mixedCode = description_.host != description_.program;
            programKnown_ = true;
            break;
        }
    }
    description_.tracerPid = 0;
    description_.pendingRecovery = pending;
    std::ifstream status("/proc/" + std::to_string(pid_) + "/status");
    std::string line;
    while (std::getline(status, line))
        if (line.starts_with("TracerPid:")) {
            std::istringstream value(line.substr(10)); value >> description_.tracerPid; break;
        }
    return description_;
}

TargetMachine LinuxProcessHandle::machineAt(uintptr_t address) {
    auto description = targetDescription();
    if (description.runtime != TargetRuntime::Wine || address == 0) return description.program;
    auto mods = modules();
    const ModuleInfo* best = nullptr;
    for (const auto& m : mods)
        if (m.machine.architecture != CpuArchitecture::Unknown && address >= m.base && address - m.base < m.size &&
            (!best || m.size < best->size)) best = &m;
    return best ? best->machine : description.program;
}

bool LinuxProcessHandle::runs32BitCode() {
    return targetDescription().program.instructionMode == InstructionMode::X86_32;
}

Result<size_t> LinuxProcessHandle::read(uintptr_t address, void* buffer, size_t size) {
    if (!sameProcess()) return std::unexpected(std::make_error_code(std::errc::no_such_process));
    struct iovec local  = { buffer,          size };
    struct iovec remote = { (void*)address,  size };

    ssize_t n = memoryTransfer(pid_,[&](pid_t task){return process_vm_readv(task,&local,1,&remote,1,0);});
    if (n < 0) {
        // The usual cause of a blank memory/disassembly pane: EPERM from
        // ptrace_scope on a non-child same-user process. `CE_LOG=ptrace:debug`
        // makes the reason visible instead of a silent empty view.
        ce::log::debug(ce::log::Cat::Ptrace,
            "process_vm_readv pid={} @ {:#x} size={} failed: {}",
            pid_, address, size, std::strerror(errno));
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    return static_cast<size_t>(n);
}

void LinuxProcessHandle::readMany(const uintptr_t* addrs, size_t count, size_t size,
                                  uint8_t* out, uint8_t* ok) {
    if (size == 0 || !sameProcess()) { std::memset(ok, 0, count); return; }
    // process_vm_readv processes the iovec arrays in order and stops at the
    // first remote page fault, returning the bytes transferred so far. Batching
    // up to IOV_MAX addresses into one syscall turns a per-address scan (one
    // syscall each) into ~one syscall per 1024 addresses. On a fault we mark the
    // offending entry unreadable and re-batch the untouched remainder, so a
    // single bad address never poisons the rest of the batch.
    // Fast path for a dense, small-gap cluster — a scanned struct-array field,
    // whose matches are `stride` bytes apart. The scatter read below would give
    // each its own tiny iovec, so the kernel pins the same few pages thousands of
    // times. Instead read the whole span once into a reused (thread-local, so no
    // race with sibling scan threads) scratch buffer and scatter the values out.
    // A gap under a page can't hide an unmapped hole (mappings are page-aligned),
    // so the span is contiguous mapped memory; a fault (region unmapped since the
    // scan) drops to the batched path for the remainder.
    // Coalesce only tight gaps: the span read pulls the gap bytes too, so a
    // large stride would read many times the value bytes and lose to the scatter
    // read. 64 bytes keeps the over-read modest while covering densely-packed
    // fields (measured net win around here; larger strides fall through).
    constexpr size_t kMaxGap  = 64;
    constexpr size_t kSpanCap = 4u * 1024 * 1024; // max scratch span
    constexpr size_t kMinRun  = 8;                // min addresses to bother
    if (count >= kMinRun && (addrs[count - 1] + size - addrs[0]) <= kSpanCap &&
        (addrs[count - 1] + size - addrs[0]) > count * size) {
        bool dense = true;
        for (size_t k = 1; k < count; ++k)
            if (addrs[k] < addrs[k - 1] || addrs[k] - addrs[k - 1] > size + kMaxGap) { dense = false; break; }
        if (dense) {
            size_t span = addrs[count - 1] + size - addrs[0];
            thread_local std::vector<uint8_t> scratch;
            if (scratch.size() < span) scratch.resize(span);
            struct iovec l{ scratch.data(), span };
            struct iovec r{ reinterpret_cast<void*>(addrs[0]), span };
            ssize_t nr = memoryTransfer(pid_,[&](pid_t task){return process_vm_readv(task,&l,1,&r,1,0);});
            size_t got = nr < 0 ? 0 : static_cast<size_t>(nr);
            size_t k = 0;
            for (; k < count; ++k) {
                size_t off = addrs[k] - addrs[0];
                if (off + size <= got) { std::memcpy(out + k * size, scratch.data() + off, size); ok[k] = 1; }
                else break; // this value and the rest weren't fully transferred
            }
            if (k == count) return;
            // Fault at k: drop it and finish the remainder on the batched path.
            ok[k] = 0;
            ++k;
            addrs += k; out += k * size; ok += k; count -= k;
            if (count == 0) return;
        }
    }

    constexpr size_t kMaxIov = 1024; // <= IOV_MAX (1024 on Linux)
    std::vector<struct iovec> local, remote;
    local.reserve(kMaxIov);
    remote.reserve(kMaxIov);

    size_t i = 0;
    while (i < count) {
        // Coalesce back-to-back addresses (addrs[k+1] == addrs[k] + size) into
        // one iovec: consecutive matched values (a dense scan, an array field)
        // are contiguous in the target, so the kernel does one large copy per
        // run instead of thousands of size-byte copies. The local buffer stays
        // packed one value per slot, so a run maps to one contiguous local
        // iovec too, and the fault accounting below (full = n / size) is
        // unchanged. Build up to kMaxIov runs per syscall.
        local.clear();
        remote.clear();
        size_t end = i;
        while (end < count && local.size() < kMaxIov) {
            size_t runStart = end;
            uintptr_t base = addrs[end];
            ++end;
            while (end < count && addrs[end] == addrs[end - 1] + size) ++end;
            size_t runBytes = (end - runStart) * size;
            local.push_back({ out + runStart * size, runBytes });
            remote.push_back({ reinterpret_cast<void*>(base), runBytes });
        }
        size_t batch = end - i; // addresses covered by this syscall

        ssize_t n = memoryTransfer(pid_,[&](pid_t task){return process_vm_readv(task,local.data(),local.size(),
                                     remote.data(),remote.size(),0);});
        if (n < 0) {
            // The leading entry faulted before any transfer (or the process is
            // gone). Mark it unreadable and advance; the next iteration retries
            // the rest. Terminal errors (ESRCH) degrade to one failing syscall
            // per remaining entry, but correctness holds.
            ok[i] = 0;
            ++i;
            continue;
        }
        size_t full = static_cast<size_t>(n) / size; // fully-transferred leading entries
        if (full > batch) full = batch;
        std::memset(ok + i, 1, full);
        i += full;
        if (full < batch) {
            // The entry at `i` faulted (partial or zero transfer); the syscall
            // stopped there, so entries after it were not attempted. Skip it and
            // re-batch from i+1.
            ok[i] = 0;
            ++i;
        }
    }
}

Result<size_t> LinuxProcessHandle::write(uintptr_t address, const void* buffer, size_t size) {
    if (!sameProcess()) return std::unexpected(std::make_error_code(std::errc::no_such_process));
    if (size && buffer && size-1<=UINTPTR_MAX-address && nativeTargetMachine().architecture==CpuArchitecture::Arm64) {
        const auto regions=queryRegions();
        const uintptr_t last=address+size-1;
        for (const auto& region:regions) {
            if ((region.protection & MemProt::Exec) && region.size &&
                (region.base<=address ? address-region.base<region.size : region.base<=last)) {
                auto identity=processMemoryIdentity(pid_);
                if (!identity) return std::unexpected(identity.error());
                return memorySyscallService().writeCode(*identity,address,{static_cast<const uint8_t*>(buffer),size});
            }
        }
    }
    struct iovec local  = { const_cast<void*>(buffer), size };
    struct iovec remote = { (void*)address,            size };

    ssize_t n = memoryTransfer(pid_,[&](pid_t task){return process_vm_writev(task,&local,1,&remote,1,0);});
    if (n < 0) {
        const int transferError=errno;
        if (errno==EFAULT && size && buffer && size-1<=UINTPTR_MAX-address) {
            const uintptr_t last=address+size-1;
            for (const auto& region:queryRegions()) {
                if ((region.protection & MemProt::Exec) && region.size &&
                    (region.base<=address ? address-region.base<region.size : region.base<=last)) {
                    auto identity=processMemoryIdentity(pid_);
                    if (!identity) return std::unexpected(identity.error());
                    return memorySyscallService().writeCode(*identity,address,{static_cast<const uint8_t*>(buffer),size});
                }
            }
        }
        errno=transferError;
        ce::log::debug(ce::log::Cat::Ptrace,
            "process_vm_writev pid={} @ {:#x} size={} failed: {}",
            pid_, address, size, std::strerror(errno));
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    return static_cast<size_t>(n);
}

Result<size_t> LinuxProcessHandle::writeCode(uintptr_t address,const void* buffer,size_t size) {
    if (!sameProcess()) return std::unexpected(std::make_error_code(std::errc::no_such_process));
    if (!size) return size_t(0);
    if (!buffer || size-1>UINTPTR_MAX-address)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    const auto description=targetDescription();
    const auto native=nativeTargetMachine();
    if (!native.isX86() && native.architecture!=CpuArchitecture::Arm64)
        return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
    if (description.host.architecture!=native.architecture &&
        !(native.architecture==CpuArchitecture::X86_64 && description.host.architecture==CpuArchitecture::X86_32))
        return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
    if (native.architecture==CpuArchitecture::Arm64) {
        uintptr_t at=address;size_t remaining=size;
        while (remaining) {
            auto region=queryRegion(at);
            if (!region || !(region->protection & MemProt::Exec) || at<region->base || at-region->base>=region->size)
                return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
            const size_t count=std::min(remaining,region->size-(at-region->base));
            remaining-=count;
            if (remaining) at+=count;
        }
    }
    auto identity=processMemoryIdentity(pid_);
    if (!identity) return std::unexpected(identity.error());
    return memorySyscallService().writeCode(*identity,address,{static_cast<const uint8_t*>(buffer),size});
}

MemProt LinuxProcessHandle::parsePerms(const std::string& perms) const {
    auto p = MemProt::None;
    if (perms.size() >= 3) {
        if (perms[0] == 'r') p = p | MemProt::Read;
        if (perms[1] == 'w') p = p | MemProt::Write;
        if (perms[2] == 'x') p = p | MemProt::Exec;
    }
    return p;
}

std::vector<MemoryRegion> LinuxProcessHandle::queryRegions() {
    std::vector<MemoryRegion> regions;
    if (!sameProcess()) return regions;
    auto task=processMemoryTask(pid_);
    if (!task) return regions;
    std::ifstream maps("/proc/" + std::to_string(*task) + "/maps");
    if (!maps) return regions;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.empty()) continue;

        // Parse: "startaddr-endaddr perms offset dev inode pathname"
        auto dash = line.find('-');
        auto space1 = line.find(' ');
        if (dash == std::string::npos || space1 == std::string::npos) continue;

        MemoryRegion r;
        try {
            r.base = std::stoull(line.substr(0, dash), nullptr, 16);
            auto end = std::stoull(line.substr(dash + 1, space1 - dash - 1), nullptr, 16);
            r.size = end - r.base;
        } catch (...) {
            continue;
        }

        // perms is the 4-char field after the first space ("rwxp"). substr
        // clamps if fewer chars exist, and every indexing site below
        // bounds-checks perms.size(), so a malformed/truncated line can't
        // index out of range — it just yields weaker protection flags.
        // TODO(security): replace the single-space field counting below with a
        //   whitespace-run tokenizer (at most 6 fields, 6th = rest-of-line
        //   path) so the parser isn't tied to a fixed single-space layout.
        auto perms = line.substr(space1 + 1, 4);
        r.protection = parsePerms(perms);
        r.state = MemState::Committed;

        // Find the path (last field after inode)
        // Format: addr perms offset dev inode [pathname]
        size_t pos = space1 + 1; // past perms start
        int fields = 0;
        while (fields < 4 && pos < line.size()) {
            pos = line.find(' ', pos);
            if (pos == std::string::npos) break;
            while (pos < line.size() && line[pos] == ' ') ++pos;
            ++fields;
        }
        if (pos < line.size()) {
            r.path = line.substr(pos);
            // Trim
            while (!r.path.empty() && r.path.back() == ' ') r.path.pop_back();
        }

        if (!r.path.empty() && r.path[0] == '/')
            r.type = MemType::Image;
        else if (perms.size() > 3 && perms[3] == 's')
            r.type = MemType::Mapped;
        else
            r.type = MemType::Private;
        regions.push_back(std::move(r));
    }
    return regions;
}

std::optional<MemoryRegion> LinuxProcessHandle::queryRegion(uintptr_t address) {
    auto regions = queryRegions();
    for (auto& r : regions) {
        if (address >= r.base && address < r.base + r.size)
            return r;
    }
    return std::nullopt;
}

std::vector<std::pair<uintptr_t, uintptr_t>>
LinuxProcessHandle::residentRanges(uintptr_t base, size_t size) {
    // Coalesce the present/swapped pages of [base, base+size) into runs by
    // reading /proc/pid/pagemap (8 bytes per page: bit 63 = present, bit 62 =
    // swapped). Any failure falls back to the whole range so a scan never
    // silently drops readable memory.
    const std::vector<std::pair<uintptr_t, uintptr_t>> whole = {{base, base + size}};
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0 || size == 0) return whole;
    size_t pageSize = static_cast<size_t>(ps);

    if (!sameProcess()) return whole;
    auto task=processMemoryTask(pid_);
    if (!task) return whole;
    std::string path = "/proc/" + std::to_string(*task) + "/pagemap";
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return whole;

    uintptr_t start = base & ~static_cast<uintptr_t>(pageSize - 1);
    uintptr_t end   = base + size;

    std::vector<std::pair<uintptr_t, uintptr_t>> runs;
    uintptr_t runStart = 0;
    bool inRun = false;
    auto endRun = [&](uintptr_t runEnd) {
        // Clip the page-aligned run back to the requested [base, end).
        uintptr_t a = std::max(runStart, base);
        uintptr_t b = std::min(runEnd, end);
        if (b > a) runs.push_back({a, b});
    };

    constexpr size_t WIN = 4096;               // pagemap entries per read (32 KiB)
    std::vector<uint64_t> ent(WIN);
    for (uintptr_t addr = start; addr < end;) {
        size_t pagesLeft = (end - addr + pageSize - 1) / pageSize;
        size_t n = std::min(WIN, pagesLeft);
        off_t off = static_cast<off_t>((addr / pageSize) * sizeof(uint64_t));
        // Read n entries, retrying short/interrupted reads.
        size_t want = n * sizeof(uint64_t), got = 0;
        auto* p = reinterpret_cast<uint8_t*>(ent.data());
        bool readOk = true;
        while (got < want) {
            ssize_t r = ::pread(fd, p + got, want - got, off + static_cast<off_t>(got));
            if (r < 0) { if (errno == EINTR) continue; readOk = false; break; }
            if (r == 0) { readOk = false; break; }
            got += static_cast<size_t>(r);
        }
        if (!readOk) { ::close(fd); return whole; } // be safe: read everything

        for (size_t k = 0; k < n; ++k) {
            uintptr_t pageAddr = addr + k * pageSize;
            bool worth = (ent[k] >> 63) & 1;       // present
            worth |= (ent[k] >> 62) & 1;           // or swapped (still real data)
            if (worth && !inRun) { runStart = pageAddr; inRun = true; }
            else if (!worth && inRun) { endRun(pageAddr); inRun = false; }
        }
        addr += n * pageSize;
    }
    if (inRun) endRun(end);
    ::close(fd);
    return runs; // may be empty when nothing in the range is resident
}

namespace {
Result<size_t> pageRoundedSize(size_t size) {
    long page = sysconf(_SC_PAGESIZE);
    if (!size || page <= 0) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    size_t alignment = static_cast<size_t>(page);
    size_t remainder = size % alignment;
    size_t extra = remainder ? alignment - remainder : 0;
    if (size > SIZE_MAX - extra) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    return size + extra;
}
int nativeProtection(MemProt protection) {
    int prot = 0;
    if (protection & MemProt::Read) prot |= PROT_READ;
    if (protection & MemProt::Write) prot |= PROT_WRITE;
    if (protection & MemProt::Exec) prot |= PROT_EXEC;
    return prot;
}
}

Result<void> LinuxProcessHandle::retryPendingOperations() {
    if (!sameProcess()) return std::unexpected(std::make_error_code(std::errc::no_such_process));
    if (!hasPendingMemorySyscalls(pid_, startTime_)) return {};
    auto identity = processMemoryIdentity(pid_);
    if (!identity) return std::unexpected(identity.error());
    return memorySyscallService().recover(*identity);
}

Result<void> LinuxProcessHandle::resumePendingCallSignal(bool deliverSignal) {
    if (!sameProcess()) return std::unexpected(std::make_error_code(std::errc::no_such_process));
    auto identity=processMemoryIdentity(pid_);
    if (!identity) return std::unexpected(identity.error());
    return memorySyscallService().resumeCall(*identity,deliverSignal);
}

Result<uintptr_t> LinuxProcessHandle::allocate(size_t size, MemProt protection, uintptr_t preferredBase) {
    return allocateInImage(size,protection,preferredBase,nullptr);
}
Result<uintptr_t> LinuxProcessHandle::allocateInImage(size_t size,MemProt protection,uintptr_t preferredBase,const NativeMemoryImage* image) {
    if(image) {if(image->pid()!=pid_) return std::unexpected(std::make_error_code(std::errc::invalid_argument));auto live=image->check();if(!live) return std::unexpected(live.error());}
    auto allocSize = pageRoundedSize(size);
    if (!allocSize) return std::unexpected(allocSize.error());
    auto recovered = retryPendingOperations();
    if (!recovered) return std::unexpected(recovered.error());
    if (unsupportedTargetOperation(*this, TargetFeature::Allocate))
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    auto description = targetDescription();
    auto allocationMachine = preferredBase ? machineAt(preferredBase) : description.program;
    if (allocationMachine.pointerWidth == 4 && (*allocSize > UINT32_MAX || preferredBase > UINT32_MAX))
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    auto identity = image ? Result<TargetProcessIdentity>(image->identity()) : processMemoryIdentity(pid_);
    if (!identity) return std::unexpected(identity.error());
    const int prot = nativeProtection(protection);
    constexpr int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    auto mmapInTarget = [&](uintptr_t address, int extraFlags) -> Result<uint64_t> {
        return memorySyscallService().execute(*identity, description.host, MemorySyscall::Map,
            {address, *allocSize, static_cast<uint64_t>(prot), static_cast<uint64_t>(flags | extraFlags), UINT64_MAX, 0},image);
    };
    // Search the intersection of each free gap and the preferred branch range.
    // Unsigned bounds avoid signed subtraction/abs overflow at extreme addresses.
    auto allocateInGaps = [&](uintptr_t minimum, uintptr_t maximum, uintptr_t preferred) -> Result<uintptr_t> {
        uintptr_t prevEnd = 0;
        size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        for (const auto& region : queryRegions()) {
            uintptr_t start = std::max(prevEnd, minimum);
            if (region.base >= *allocSize) {
                uintptr_t end = std::min(region.base - *allocSize, maximum);
                if (start <= end) {
                    uintptr_t address = std::clamp(preferred, start, end);
                    address -= address % page;
                    if (address < start) address = start;
                    uintptr_t extra = (page - address % page) % page;
                    if (extra <= end - address) {
                        address += extra;
                        auto result = mmapInTarget(address, MAP_FIXED_NOREPLACE);
                        if (result) return static_cast<uintptr_t>(*result);
                        // EPERM also rejects candidates below mmap_min_addr.
                        // These are ordinary gap/address failures. Recovery and
                        // identity failures must stop the entire allocation.
                        auto error = result.error();
                        if (error != std::errc::file_exists && error != std::errc::invalid_argument &&
                            error != std::errc::not_enough_memory && error != std::errc::permission_denied &&
                            error != std::errc::operation_not_permitted)
                            return std::unexpected(error);
                    }
                }
            }
            prevEnd = region.size > UINTPTR_MAX - region.base ? UINTPTR_MAX : region.base + region.size;
        }
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    };
    if (preferredBase) {
        constexpr uintptr_t maxDistance = 0x7fff0000;
        uintptr_t minimum = preferredBase > maxDistance ? preferredBase - maxDistance : 0;
        uintptr_t maximum = preferredBase > UINTPTR_MAX - maxDistance ? UINTPTR_MAX : preferredBase + maxDistance;
        if (allocationMachine.pointerWidth == 4)
            maximum = std::min<uintptr_t>(maximum, UINT32_MAX - *allocSize + 1);
        auto nearby = allocateInGaps(minimum, maximum, preferredBase);
        if (nearby || nearby.error() != std::errc::not_enough_memory) return nearby;
    }
    int lowAddressFlag = 0;
#if defined(__x86_64__)
    if (allocationMachine.pointerWidth == 4 && description.host.architecture == CpuArchitecture::X86_64)
        lowAddressFlag = MAP_32BIT;
#endif
    auto result = mmapInTarget(0, lowAddressFlag);
    if (!result && lowAddressFlag && result.error() == std::errc::not_enough_memory) {
        // MAP_32BIT searches below 2 GiB, although a program's 32-bit pointers
        // can represent the full 4 GiB. Search the remaining free address space
        // without replacing any mapping when that preferred range is full.
        uintptr_t minimum = static_cast<uintptr_t>(sysconf(_SC_PAGESIZE));
        std::ifstream limit("/proc/sys/vm/mmap_min_addr");
        uintptr_t configured = 0;
        if (limit >> configured) minimum = std::max(minimum, configured);
        return allocateInGaps(minimum, UINT32_MAX - *allocSize + 1, UINT64_C(0x80000000));
    }
    if (!result) return std::unexpected(result.error());
    return static_cast<uintptr_t>(*result);
}

Result<void> LinuxProcessHandle::free(uintptr_t address, size_t size) {
    return freeInImage(address,size,nullptr);
}
Result<void> LinuxProcessHandle::freeInImage(uintptr_t address,size_t size,const NativeMemoryImage* image) {
    if(image) {if(image->pid()!=pid_) return std::unexpected(std::make_error_code(std::errc::invalid_argument));auto live=image->check();if(!live) return std::unexpected(live.error());}
    auto freeSize = pageRoundedSize(size);
    if (!freeSize) return std::unexpected(freeSize.error());
    if (address > UINTPTR_MAX - *freeSize) return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto recovered = retryPendingOperations();
    if (!recovered) return recovered;
    if (unsupportedTargetOperation(*this, TargetFeature::Allocate))
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    auto description = targetDescription();
    auto identity = image ? Result<TargetProcessIdentity>(image->identity()) : processMemoryIdentity(pid_);
    if (!identity) return std::unexpected(identity.error());
    auto result = memorySyscallService().execute(*identity, description.host, MemorySyscall::Unmap,
        {address, *freeSize, 0, 0, 0, 0},image);
    if (!result) return std::unexpected(result.error());
    return {};
}

Result<void> LinuxProcessHandle::protect(uintptr_t address, size_t size, MemProt newProtection) {
    return protectInImage(address,size,newProtection,nullptr);
}
Result<void> LinuxProcessHandle::protectInImage(uintptr_t address,size_t size,MemProt newProtection,const NativeMemoryImage* image) {
    if(image) {if(image->pid()!=pid_) return std::unexpected(std::make_error_code(std::errc::invalid_argument));auto live=image->check();if(!live) return std::unexpected(live.error());}
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || !size) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    uintptr_t pageStart = address - address % static_cast<uintptr_t>(page);
    size_t prefix = address - pageStart;
    if (size > SIZE_MAX - prefix || size > UINTPTR_MAX - address)
        return std::unexpected(std::make_error_code(std::errc::value_too_large));
    auto protSize = pageRoundedSize(size + prefix);
    if (!protSize) return std::unexpected(protSize.error());
    auto recovered = retryPendingOperations();
    if (!recovered) return recovered;
    if (unsupportedTargetOperation(*this, TargetFeature::Protect))
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    auto description = targetDescription();
    auto identity = image ? Result<TargetProcessIdentity>(image->identity()) : processMemoryIdentity(pid_);
    if (!identity) return std::unexpected(identity.error());
    auto result = memorySyscallService().execute(*identity, description.host, MemorySyscall::Protect,
        {pageStart, *protSize, static_cast<uint64_t>(nativeProtection(newProtection)), 0, 0, 0},image);
    if (!result) return std::unexpected(result.error());
    return {};
}

// Enumerate Wine PE modules by reading PE headers from the target's memory: a
// Windows game under Wine loads its .exe/.dll as PE IMAGES (MZ + PE headers) at
// their own bases, which /proc/maps attributes to whatever file each mapping is
// backed by (often a shared data file like c_1252.nls), so ELF-style module
// collapsing mis-attributes game-code addresses. Reading the actual PE header
// gives the real module base (SizeOfImage), name, and bitness (Machine field).
void LinuxProcessHandle::enumeratePeModules(std::vector<ModuleInfo>& mods,
                                            const std::vector<MemoryRegion>& regions) {
    auto rd = [&](uintptr_t a, void* buf, size_t n) {
        auto r = read(a, buf, n); return r && *r >= n;
    };
    for (const auto& region : regions) {
        if (!(region.protection & MemProt::Read)) continue;   // can't read a PE header there
        // Skip pages already inside a found PE image so a multi-section module is
        // enumerated once (only a mapping start can be a PE base).
        bool covered = false;
        for (const auto& m : mods)
            if (region.base > m.base && region.base < m.base + m.size) { covered = true; break; }
        if (covered) continue;

        std::array<uint8_t, 64> dos{};
        if (!rd(region.base, dos.data(), dos.size()) || dos[0] != 'M' || dos[1] != 'Z') continue;
        auto lfanew = *decodeTargetUnsigned(std::span(dos).subspan(0x3c, 4), ByteOrder::Little);
        if (lfanew < 0x40 || lfanew > 0x1000 || lfanew + 24 > UINTPTR_MAX - region.base) continue;
        std::array<uint8_t, 24> coff{};
        if (!rd(region.base + lfanew, coff.data(), coff.size())) continue;
        auto optionalSize = *decodeTargetUnsigned(std::span(coff).subspan(20, 2), ByteOrder::Little);
        if (optionalSize < 60 || optionalSize > 4096 || lfanew + 24 + optionalSize > UINTPTR_MAX - region.base) continue;
        std::vector<uint8_t> header(lfanew + 24 + optionalSize);
        if (!rd(region.base, header.data(), header.size())) continue;
        auto target = parsePeTarget(header);
        if (!target) continue;
        uint64_t sizeOfImage = *decodeTargetUnsigned(std::span(header).subspan(lfanew + 24 + 56, 4), ByteOrder::Little);
        if (sizeOfImage < 0x1000 || sizeOfImage > 0x40000000u || sizeOfImage > UINTPTR_MAX - region.base)
            continue;

        // Skip if this base is already listed (e.g. from the ELF pass).
        if (std::any_of(mods.begin(), mods.end(),
                        [&](const ModuleInfo& m){ return m.base == region.base; }))
            continue;

        ModuleInfo m;
        m.base = region.base;
        m.size = sizeOfImage;
        m.path = region.path;
        // Prefer the backing file's basename; PE images are usually file-backed.
        m.name = region.path.empty() ? ("pe_" + std::to_string(region.base))
                                     : fs::path(region.path).filename().string();
        m.machine = *target;
        m.is64bit = target->pointerWidth == 8;
        mods.push_back(std::move(m));
    }
}

std::vector<ModuleInfo> LinuxProcessHandle::modules() {
    std::vector<ModuleInfo> mods;
    auto regions = queryRegions();

    // Wine PE images first, so a game-code address attributes to its real PE
    // module rather than a nearby ELF/data mapping.
    enumeratePeModules(mods, regions);

    // Collapse regions with the same file path into modules
    for (auto& r : regions) {
        if (r.path.empty() || r.path[0] != '/') continue;

        auto it = std::find_if(mods.begin(), mods.end(),
            [&](const ModuleInfo& m) { return m.path == r.path; });

        if (it != mods.end()) {
            // Extend existing module
            auto end = r.base + r.size;
            auto modEnd = it->base + it->size;
            if (r.base < it->base) it->base = r.base;
            if (end > modEnd) it->size = end - it->base;
            else it->size = modEnd - it->base;
        } else {
            ModuleInfo m;
            m.base = r.base;
            m.size = r.size;
            m.path = r.path;
            m.name = fs::path(r.path).filename().string();
            m.is64bit = is64bit_;
            mods.push_back(std::move(m));
        }
    }
    // Make backing-file paths host-openable for sandboxed targets (Flatpak/Snap/
    // container): a path like /app/bin/game exists only inside the target's mount
    // namespace, so redirect it through /proc/<pid>/root so symbol loading and
    // module analysis work. Host paths remain valid only for the same backing inode. The
    // display name (m.name, a basename) is untouched.
    auto task=processMemoryTask(pid_);
    for (auto& m : mods) {
        if (!m.path.empty()) m.path = resolveProcPath(task ? *task : pid_, m.path);
        if (m.machine.architecture == CpuArchitecture::Unknown) {
            m.machine = readElfMachine(m.path);
            if (m.machine.hasPointers()) m.is64bit = m.machine.pointerWidth == 8;
        }
    }
    return mods;
}

std::vector<ThreadInfo> LinuxProcessHandle::threads() {
    std::vector<ThreadInfo> tids;
    if (!sameProcess()) return tids;
    auto taskDir = "/proc/" + std::to_string(pid_) + "/task";
    try {
        for (auto& entry : fs::directory_iterator(taskDir)) {
            auto name = entry.path().filename().string();
            try {
                ThreadInfo t;
                t.tid = std::stoi(name);
                std::ifstream stat(entry.path()/"stat"); std::string line;
                if (!std::getline(stat,line)) continue;
                const auto close=line.rfind(')');
                if (close==std::string::npos) continue;
                std::istringstream fields(line.substr(close+1)); char state=0;
                if (!(fields>>state) || state=='Z' || state=='X' || state=='x') continue;
                std::string ignored;
                for (unsigned field=4;field<9 && fields;++field) fields>>ignored;
                uint64_t flags=0;
                if (!(fields>>flags) || (flags&12)) continue; // PF_EXITING | PF_POSTCOREDUMP.
                tids.push_back(t);
            } catch (...) {}
        }
    } catch (...) {}
    return tids;
}

// ── LinuxProcessEnumerator ──

// Wine renames every process in a prefix to its main thread name (or the
// preloader name) so /proc/PID/comm reads things like "Main Thread",
// "wine64-preloader", "wineserver". When the user is looking for a game
// they'd recognise it as `mb_warband.exe` or similar, which lives in the
// argv that's preserved verbatim in /proc/PID/cmdline. Find the last
// .exe-suffixed argv token and use its basename when comm is one of the
// known Wine wrappers.
static bool isWineLikeComm(const std::string& comm) {
    if (comm == "Main Thread") return true;
    if (comm.find("wine") != std::string::npos) return true;       // wine, wine64, wineserver, winedevice.exe
    if (comm.find("preloader") != std::string::npos) return true;  // wine[64]-preloader
    return false;
}

static std::string basenameOfBackslashOrSlash(std::string p) {
    auto slash = p.find_last_of("/\\");
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

static std::string lowercase(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return s;
}

std::vector<ProcessInfo> LinuxProcessEnumerator::list() {
    std::vector<ProcessInfo> procs;
    try {
        for (auto& entry : fs::directory_iterator("/proc")) {
            auto name = entry.path().filename().string();
            pid_t pid;
            try { pid = std::stoi(name); } catch (...) { continue; }
            if (!entry.is_directory()) continue;

            ProcessInfo p;
            p.pid = pid;

            // Read comm for the kernel-known process name.
            std::string comm;
            { std::ifstream f("/proc/" + name + "/comm"); if (f) std::getline(f, comm); }
            p.name = comm;

            // Read /proc/PID/cmdline (NUL-separated argv list).
            std::string cmdline;
            { std::ifstream f("/proc/" + name + "/cmdline", std::ios::binary);
              if (f) { std::stringstream ss; ss << f.rdbuf(); cmdline = ss.str(); } }

            // Scan argv tokens for the last .exe path and prefer its basename
            // for display whenever found. The old gate on isWineLikeComm() was
            // too narrow — PortProton / Lutris / Heroic / Bottles wrappers
            // often set /proc/PID/comm to a launcher name that doesn't match
            // the Wine substring, so we'd miss the .exe in cmdline. We now
            // always prefer a .exe basename when present, falling back to the
            // raw comm otherwise.
            if (!cmdline.empty()) {
                std::string lastExeBasename;
                size_t pos = 0;
                while (pos < cmdline.size()) {
                    size_t nul = cmdline.find('\0', pos);
                    if (nul == std::string::npos) nul = cmdline.size();
                    std::string token = cmdline.substr(pos, nul - pos);
                    if (token.size() >= 4) {
                        auto suffix = lowercase(token.substr(token.size() - 4));
                        if (suffix == ".exe") lastExeBasename = basenameOfBackslashOrSlash(token);
                    }
                    pos = nul + 1;
                }
                if (!lastExeBasename.empty()) p.name = lastExeBasename;
            }
            (void)isWineLikeComm;  // kept for future PortProton/Lutris annotation

            // Read exe symlink for path. For Wine targets this resolves to
            // the wine-preloader binary, which is less useful than the
            // recognisable .exe inside cmdline. Preference order:
            //   1. cmdline (if it contains an .exe — covers all Wine/Proton
            //      wrappers including PortProton, Lutris, Heroic, Bottles)
            //   2. /proc/PID/exe symlink (native Linux process)
            //   3. cmdline as-is even without a .exe (helps with launchers,
            //      scripts, sandboxed processes — filter can match against it)
            std::string flattenedCmdline;
            if (!cmdline.empty()) {
                flattenedCmdline = cmdline;
                for (auto& c : flattenedCmdline) if (c == '\0') c = ' ';
                while (!flattenedCmdline.empty() && flattenedCmdline.back() == ' ')
                    flattenedCmdline.pop_back();
            }

            bool cmdlineHasExe = !cmdline.empty() &&
                lowercase(cmdline).find(".exe") != std::string::npos;
            if (cmdlineHasExe) {
                p.path = flattenedCmdline;
            } else {
                try {
                    auto task=processMemoryTask(pid);
                    p.path = fs::read_symlink("/proc/" + std::to_string(task ? *task : pid) + "/exe").string();
                } catch (...) {}
                if (p.path.empty() && !flattenedCmdline.empty())
                    p.path = flattenedCmdline;
            }

            // Flag sandboxed processes (Flatpak/Snap/Firejail/container) so the
            // picker can badge them; attach works but the user should know they are
            // reaching into a namespace.
            p.sandboxed = isPidNamespaced(pid);

            procs.push_back(std::move(p));
        }
    } catch (...) {}

    std::sort(procs.begin(), procs.end(),
        [](const ProcessInfo& a, const ProcessInfo& b) { return a.pid < b.pid; });
    return procs;
}

std::unique_ptr<ProcessHandle> LinuxProcessEnumerator::open(pid_t pid) {
    return std::make_unique<LinuxProcessHandle>(pid);
}

} // namespace ce::os
