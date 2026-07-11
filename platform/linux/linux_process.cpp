#include "platform/linux/linux_process.hpp"

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
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <cerrno>

namespace ce::os {

namespace fs = std::filesystem;

// ── LinuxProcessHandle ──

LinuxProcessHandle::LinuxProcessHandle(pid_t pid)
    : pid_(pid), is64bit_(detectIs64Bit()) {}

LinuxProcessHandle::~LinuxProcessHandle() = default;

bool LinuxProcessHandle::detectIs64Bit() const {
    auto path = "/proc/" + std::to_string(pid_) + "/exe";
    std::ifstream f(path, std::ios::binary);
    if (!f) return true; // default to 64-bit
    // Read and validate the 5-byte ELF identification prefix: magic 0x7f 'E'
    // 'L' 'F' followed by EI_CLASS. Only trust EI_CLASS if the read fully
    // succeeded and the magic matches; otherwise default to 64-bit rather than
    // acting on a short/garbled read.
    unsigned char ident[5] = {0};
    f.read(reinterpret_cast<char*>(ident), sizeof(ident));
    if (f.gcount() != static_cast<std::streamsize>(sizeof(ident)))
        return true; // short/failed read — default to 64-bit
    if (!(ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F'))
        return true; // not an ELF header we recognise
    return ident[4] != 1; // 1 = ELFCLASS32, 2 = ELFCLASS64
}

bool LinuxProcessHandle::runs32BitCode() {
    if (runs32_ >= 0) return runs32_ == 1;
    if (!is64bit_) { runs32_ = 1; return true; }   // native 32-bit ELF

    // WoW64: a 64-bit ELF process, but the game's PE modules may be 32-bit. This
    // is the reliable signal (read from the PE Machine field, no ptrace): if any
    // loaded module is 32-bit (a .so here is always 64-bit), the code is 32-bit.
    for (const auto& m : modules()) {
        if (!m.is64bit) { runs32_ = 1; return true; }
    }

    // Fallback (older/PE-less WoW64): probe thread CPU mode (CS=0x23 = 32-bit).
    // Sample a few threads read-only (attach + GETREGS + detach; no single-step,
    // so this is a debugger-style brief stop, not code injection). If any thread
    // is in compat mode, the process executes 32-bit code.
    runs32_ = 0;
    DIR* d = ::opendir(("/proc/" + std::to_string(pid_) + "/task").c_str());
    if (!d) return false;
    int probed = 0;
    while (struct dirent* e = ::readdir(d)) {
        if (probed >= 12) break;
        pid_t tid = (pid_t)atoi(e->d_name);
        if (tid <= 0) continue;
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != 0) continue;
        int st;
        if (waitpid(tid, &st, __WALL) == tid && WIFSTOPPED(st)) {
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) == 0 &&
                (r.cs & 0xFFu) == 0x23u) {
                runs32_ = 1;
            }
        }
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        ++probed;
        if (runs32_ == 1) break;
    }
    ::closedir(d);
    return runs32_ == 1;
}

Result<size_t> LinuxProcessHandle::read(uintptr_t address, void* buffer, size_t size) {
    struct iovec local  = { buffer,          size };
    struct iovec remote = { (void*)address,  size };

    ssize_t n = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
    if (n < 0)
        return std::unexpected(std::error_code(errno, std::system_category()));
    return static_cast<size_t>(n);
}

Result<size_t> LinuxProcessHandle::write(uintptr_t address, const void* buffer, size_t size) {
    struct iovec local  = { const_cast<void*>(buffer), size };
    struct iovec remote = { (void*)address,            size };

    ssize_t n = process_vm_writev(pid_, &local, 1, &remote, 1, 0);
    if (n < 0)
        return std::unexpected(std::error_code(errno, std::system_category()));
    return static_cast<size_t>(n);
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
    std::ifstream maps("/proc/" + std::to_string(pid_) + "/maps");
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

// Execute a syscall in the target process via ptrace
static int64_t remoteSyscall(pid_t pid, uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
    struct user_regs_struct oldRegs, regs;

    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
        return -1;
    // Validate the attach stop: the first wait must be the attach-SIGSTOP. If
    // it's something else, the tracee isn't cleanly stopped where we expect.
    // TODO(security): migrate to PTRACE_SEIZE+PTRACE_INTERRUPT and operate on a
    // specific tid for clean stop semantics against multithreaded targets.
    int status;
    if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return -1;
    }

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return -1;
    }

    // Use the ABI of the thread's CURRENT CPU mode, not the process's ELF class:
    // a WoW64 target (64-bit Wine running a 32-bit Windows game) has threads in
    // 32-bit compat mode (CS=0x23) while running game code, where the 64-bit
    // `syscall` instruction faults. In compat mode, go through `int 0x80` with the
    // i386 syscall number in eax and args in ebx/ecx/edx/esi/edi/ebp.
    const bool mode32 = ((oldRegs.cs & 0xFFu) == 0x23u);
    uint64_t instrWord;   // little-endian opcode bytes to poke at RIP
    regs = oldRegs;
    // If the thread was stopped inside a blocking syscall, the kernel would run
    // its syscall-restart machinery on resume and clobber our injected call;
    // orig_rax = -1 tells it there is nothing to restart.
    regs.orig_rax = (unsigned long long)-1;
    if (mode32) {
        // Translate the x86_64 numbers the callers pass to their i386 equivalents.
        uint32_t nr32 = (nr == 9) ? 192u   // mmap  -> mmap2 (pgoffset already 0 for anon)
                       : (nr == 11) ? 91u   // munmap
                       : (nr == 10) ? 125u  // mprotect
                       : (uint32_t)nr;
        regs.rax = nr32;
        regs.rbx = a1; regs.rcx = a2; regs.rdx = a3;
        regs.rsi = a4; regs.rdi = a5; regs.rbp = a6;
        instrWord = 0x80CDull;  // int 0x80
    } else {
        regs.rax = nr;
        regs.rdi = a1; regs.rsi = a2; regs.rdx = a3;
        regs.r10 = a4; regs.r8 = a5; regs.r9 = a6;
        instrWord = 0x050full;  // syscall
    }

    // Save and replace the instruction at RIP. Clear errno so a real 0xFFFF...
    // code word is distinguishable from a PEEKTEXT failure; bail before any
    // destructive POKETEXT if the read failed.
    errno = 0;
    uint64_t origInstr = ptrace(PTRACE_PEEKTEXT, pid, (void*)oldRegs.rip, nullptr);
    if (origInstr == (uint64_t)-1 && errno != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return -1;
    }
    if (ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip,
               (void*)((origInstr & ~0xFFFFULL) | instrWord)) < 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return -1;
    }

    int64_t result = -1;
    // The original instruction is now overwritten; always restore it below.
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == 0 &&
        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == 0) {
        if (waitpid(pid, &status, 0) == pid &&
            WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0)
                // In compat mode the result is 32-bit eax; sign-extend so an i386
                // -errno reads back negative.
                result = mode32 ? (int64_t)(int32_t)(regs.rax & 0xFFFFFFFFu)
                                : (int64_t)regs.rax;
        }
    }

    ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip, (void*)origInstr);
    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return result;
}


Result<uintptr_t> LinuxProcessHandle::allocate(size_t size, MemProt protection, uintptr_t preferredBase) {
    int prot = 0;
    if (protection & MemProt::Read)  prot |= 1; // PROT_READ
    if (protection & MemProt::Write) prot |= 2; // PROT_WRITE
    if (protection & MemProt::Exec)  prot |= 4; // PROT_EXEC

    int flags = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS
    size_t allocSize = (size + 4095) & ~4095ULL; // Page-align

    // remoteSyscall picks the right ABI (syscall vs int 0x80) from the thread's
    // CPU mode, and translates mmap(9) -> mmap2(192) in compat mode, so passing
    // the x86_64 numbers works for native-64, native-32, and WoW64 targets alike.
    auto mmapInTarget = [&](uintptr_t addr, size_t len, int p, int fl) -> int64_t {
        return remoteSyscall(pid_, 9, addr, len, p, fl, (uint64_t)-1, 0);
    };

    // Try near-allocation first (within ±2GB for RIP-relative addressing)
    if (preferredBase) {
        auto regions = queryRegions();
        constexpr int64_t MAX_DIST = 0x7FFF0000LL; // ~2GB

        // Search for gaps near preferredBase
        uintptr_t prevEnd = 0;
        for (auto& r : regions) {
            uintptr_t gapStart = prevEnd;
            uintptr_t gapEnd = r.base;

            if (gapEnd > gapStart && (gapEnd - gapStart) >= allocSize) {
                // Check if this gap is within ±2GB of preferred
                int64_t distStart = (int64_t)gapStart - (int64_t)preferredBase;
                int64_t distEnd = (int64_t)(gapEnd - allocSize) - (int64_t)preferredBase;

                if (std::abs(distStart) < MAX_DIST || std::abs(distEnd) < MAX_DIST) {
                    // Pick the address in this gap closest to preferredBase so
                    // the result is most likely within ±2GB (RIP-relative
                    // range). Clamp preferredBase into the usable window
                    // [gapStart, gapEnd - allocSize], then page-align. The
                    // window is non-empty here because the gap is >= allocSize.
                    uintptr_t windowEnd = gapEnd - allocSize; // safe: gap >= allocSize
                    uintptr_t allocAddr = std::clamp(preferredBase, gapStart, windowEnd);
                    allocAddr = (allocAddr + 4095) & ~4095ULL; // Page-align

                    if (allocAddr + allocSize <= gapEnd) {
                        // NOREPLACE (not plain MAP_FIXED=0x10): the walk relies on
                        // mmap FAILING when this gap address is already taken (the
                        // region snapshot can go stale before the target is stopped),
                        // so it can try the next gap instead of unmapping live memory.
                        int64_t result = mmapInTarget(allocAddr, allocSize, prot,
                                                      flags | MAP_FIXED_NOREPLACE);
                        if (result > 0 && result != -1)
                            return (uintptr_t)result;
                    }
                }
            }
            prevEnd = r.base + r.size;
        }
    }

    // Fallback: allocate anywhere
    int64_t result = mmapInTarget(0, allocSize, prot, flags);

    if (result <= 0 || result == -1)
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));

    return (uintptr_t)result;
}

Result<void> LinuxProcessHandle::free(uintptr_t address, size_t size) {
    size_t freeSize = (size + 4095) & ~4095ULL;
    int64_t result = remoteSyscall(pid_, 11 /*__NR_munmap*/, address, freeSize, 0, 0, 0, 0);
    if (result < 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    return {};
}

Result<void> LinuxProcessHandle::protect(uintptr_t address, size_t size, MemProt newProtection) {
    int prot = 0;
    if (newProtection & MemProt::Read)  prot |= 1;
    if (newProtection & MemProt::Write) prot |= 2;
    if (newProtection & MemProt::Exec)  prot |= 4;

    uintptr_t pageStart = address & ~uintptr_t(4095);
    uintptr_t pageEnd = (address + size + 4095) & ~uintptr_t(4095);
    size_t protSize = pageEnd - pageStart;

    int64_t result = remoteSyscall(pid_, 10 /*__NR_mprotect*/, pageStart, protSize, prot, 0, 0, 0);
    if (result < 0)
        return std::unexpected(std::make_error_code(std::errc::permission_denied));
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

        uint16_t mz = 0;
        if (!rd(region.base, &mz, 2) || mz != 0x5A4D) continue;         // "MZ"
        uint32_t lfanew = 0;
        if (!rd(region.base + 0x3C, &lfanew, 4)) continue;
        if (lfanew < 0x40 || lfanew > 0x1000) continue;                // sane e_lfanew
        uint32_t peSig = 0;
        if (!rd(region.base + lfanew, &peSig, 4) || peSig != 0x00004550) continue;  // "PE\0\0"
        uint16_t machine = 0;
        if (!rd(region.base + lfanew + 4, &machine, 2)) continue;
        if (machine != 0x14C && machine != 0x8664) continue;           // i386 / amd64 only
        uint32_t sizeOfImage = 0;
        // Optional header starts at lfanew+24; SizeOfImage is at its offset 56.
        rd(region.base + lfanew + 24 + 56, &sizeOfImage, 4);
        if (sizeOfImage < 0x1000 || sizeOfImage > 0x40000000u)         // 4KB..1GB sanity
            sizeOfImage = (uint32_t)region.size;

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
        m.is64bit = (machine == 0x8664);
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
    return mods;
}

std::vector<ThreadInfo> LinuxProcessHandle::threads() {
    std::vector<ThreadInfo> tids;
    auto taskDir = "/proc/" + std::to_string(pid_) + "/task";
    try {
        for (auto& entry : fs::directory_iterator(taskDir)) {
            auto name = entry.path().filename().string();
            try {
                ThreadInfo t;
                t.tid = std::stoi(name);
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
                    p.path = fs::read_symlink("/proc/" + name + "/exe").string();
                } catch (...) {}
                if (p.path.empty() && !flattenedCmdline.empty())
                    p.path = flattenedCmdline;
            }

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
