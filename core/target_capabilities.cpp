#include "core/target_capabilities.hpp"
#include <sys/ptrace.h>
#include <unistd.h>
#include <cerrno>
#include <fstream>
#include <sstream>
#include "arch/target_arch.hpp"

namespace ce {

const char* targetFeatureName(TargetFeature f) {
    switch (f) {
        case TargetFeature::ReadMemory: return "read memory";
        case TargetFeature::WriteMemory: return "write memory";
        case TargetFeature::NumericScan: return "numeric scan";
        case TargetFeature::PointerScan: return "pointer scan";
        case TargetFeature::Disassemble: return "disassemble";
        case TargetFeature::Assemble: return "assemble";
        case TargetFeature::Allocate: return "allocate memory";
        case TargetFeature::Protect: return "change protection";
        case TargetFeature::LibraryInjection: return "inject library";
        case TargetFeature::RemoteThread: return "create remote thread";
        case TargetFeature::CodeInjection: return "injection template / hook";
        case TargetFeature::Debugger: return "debugger";
        case TargetFeature::HardwareWatchpoint: return "hardware watchpoint";
        case TargetFeature::SoftwareWatchpoint: return "software watchpoint";
        case TargetFeature::Trace: return "instruction trace";
        case TargetFeature::GuestDebugging: return "guest debugging";
    }
    return "unknown";
}

const char* capabilityStateName(CapabilityState s) {
    switch (s) {
        case CapabilityState::Available: return "available";
        case CapabilityState::Partial: return "partial";
        case CapabilityState::Unsupported: return "unsupported";
        case CapabilityState::Blocked: return "blocked";
        case CapabilityState::Unknown: return "unknown";
    }
    return "unknown";
}

std::vector<TargetCapability> targetCapabilities(const TargetDescription& d) {
    using F = TargetFeature;
    using S = CapabilityState;
    std::vector<TargetCapability> result;
    bool local = d.transport == TargetTransport::Local;
    bool x86 = d.program.isX86();
    bool instructionBackend = disassemblerArchFor(d.program).has_value();
    bool nativeX86 = local && nativeTargetMachine().architecture == CpuArchitecture::X86_64 &&
        d.host.isX86() && (d.host.abi == TargetAbi::LinuxI386 || d.host.abi == TargetAbi::LinuxX86_64 || d.host.abi == TargetAbi::LinuxX32);
    bool nativeArmMemory=local && nativeTargetMachine().architecture==CpuArchitecture::Arm64 &&
        d.host.architecture==CpuArchitecture::Arm64 && d.host.abi==TargetAbi::LinuxAarch64;
    bool nativeMemory = nativeX86 || nativeArmMemory;
    bool nativeX86Debug = local && nativeTargetMachine().architecture == CpuArchitecture::X86_64 && d.host.isX86() &&
        (d.host.abi == TargetAbi::LinuxI386 || d.host.abi == TargetAbi::LinuxX86_64 || d.host.abi == TargetAbi::LinuxX32);
    bool ownedTracer = d.tracerPid == getpid() || (local && d.tracerPid > 0 &&
        access(("/proc/self/task/" + std::to_string(d.tracerPid)).c_str(), F_OK) == 0);
    bool tracedElsewhere = d.tracerPid != 0 && !ownedTracer;
    auto add = [&](F feature, S state, std::string reason = {}) {
        if (!d.live) { state = S::Blocked; reason = "Target exited or its identity changed"; }
        if (d.otherOwner) { state = S::Blocked; reason = "The process belongs to another user; only root can open it"; }
        result.push_back({feature, state, std::move(reason)});
    };
    bool byteTransport = d.transport == TargetTransport::Local || d.transport == TargetTransport::CEServer || d.transport==TargetTransport::Gdb;
    for (auto f : {F::ReadMemory, F::WriteMemory})
        add(f, byteTransport ? S::Available : S::Partial,
            byteTransport ? "Access permissions are checked by the memory operation" : "Process transport integration is incomplete or unknown");
    add(F::NumericScan, byteTransport && d.program.byteOrder!=ByteOrder::Unknown ? S::Available : S::Partial,
        d.program.byteOrder==ByteOrder::Unknown ? "Byte scans work; numeric scans need an explicit data byte order" :
        "Uses the selected program's data byte order; access permissions are checked at use");
    add(F::PointerScan, d.program.hasPointers() && d.program.byteOrder != ByteOrder::Unknown ? S::Available : S::Unknown,
        !d.program.hasPointers() ? "Target pointer width is unknown" :
        d.program.byteOrder == ByteOrder::Unknown ? "Target byte order is unknown" : "Uses the program's pointer width and byte order");
    for (auto f : {F::Disassemble, F::Assemble}) {
        auto instructions = disassemblerArchFor(d.program);
        auto assembler = instructions ? assemblerArchFor(*instructions) : std::expected<AsmArch, std::string>(std::unexpected(instructions.error()));
        if (f == F::Assemble && instructions && !assembler) add(f, S::Unsupported, assembler.error());
        else add(f, instructionBackend ? S::Available : S::Unsupported,
            instructionBackend ? "Select the module's instruction mode for mixed-code targets" :
                                 "No instruction backend for " + std::string(cpuArchitectureName(d.program.architecture)));
    }
    for (auto f : {F::Allocate, F::Protect}) {
        if (d.pendingRecovery) add(f, S::Blocked, "Pending syscall recovery; retry before another operation");
        else if (tracedElsewhere && local) add(f, S::Blocked, "Target is traced by another debugger");
        else if (d.transport == TargetTransport::CEServer) add(f, S::Available, "Executed by the remote server");
        else if (nativeArmMemory) add(f,S::Partial,
            "Linux syscall backend with vector-state recovery; live scalable vectors require an unfiltered kernel main stack without active GCS");
        else add(f, nativeMemory ? S::Available : S::Unsupported, nativeMemory ? "Linux syscall backend with retained recovery" : "Target syscall ABI has no backend yet");
    }
    for (auto f : {F::LibraryInjection, F::RemoteThread, F::Debugger, F::HardwareWatchpoint, F::SoftwareWatchpoint, F::Trace}) {
        if (d.pendingRecovery) { add(f, S::Blocked, "Target has pending syscall recovery"); continue; }
        if (tracedElsewhere) { add(f, S::Blocked, "Target is traced by another debugger"); continue; }
        bool nativeArmSession=local && nativeTargetMachine().architecture==CpuArchitecture::Arm64 &&
            d.host.architecture==CpuArchitecture::Arm64 && d.host.abi==TargetAbi::LinuxAarch64 &&
            d.program.architecture==CpuArchitecture::Arm64 && d.runtime==TargetRuntime::Native;
        if (f==F::SoftwareWatchpoint && (nativeX86 || nativeArmSession) && d.runtime==TargetRuntime::Native) {
            add(f,S::Partial,"Page guards observe user-mode faults; kernel writes and overlapping/bulk accesses need additional coverage");
            continue;
        }
        if ((f==F::Debugger || f==F::Trace || f==F::HardwareWatchpoint) && nativeArmSession) {
            add(f,S::Partial,"Native ARM64 session/trace/watchpoint backend; complete frontend and unwinding integration is pending");
            continue;
        }
        if ((f==F::LibraryInjection || f==F::RemoteThread) && d.runtime!=TargetRuntime::Wine && (nativeX86 || nativeArmSession)) {
            add(f,S::Partial,"Native call owner with retained private frames; requires an eligible native thread and target loader/pthread symbols");
            continue;
        }
        bool backend = f == F::LibraryInjection || f == F::RemoteThread || f == F::SoftwareWatchpoint ? nativeX86 : nativeX86Debug;
        if (!backend || !x86) {
            bool remoteDebugger = d.transport == TargetTransport::CEServer &&
                d.program.architecture == CpuArchitecture::X86_64 &&
                (f == F::Debugger || f == F::HardwareWatchpoint);
            add(f, remoteDebugger ? S::Partial : S::Unsupported,
                remoteDebugger ? "Remote context/events exist; local ptrace operations are unavailable" : "No complete backend for this target/transport");
        } else if (d.runtime == TargetRuntime::Wine && (f == F::LibraryInjection || f == F::RemoteThread))
            add(f, S::Unsupported, "Wine-safe loader calls and Windows thread initialization need a dedicated backend");
        else if (d.runtime == TargetRuntime::Wine && f == F::SoftwareWatchpoint)
            add(f, S::Unsupported, "Page guards conflict with Wine/Proton write-watch");
        else if (d.runtime == TargetRuntime::Wine && f == F::HardwareWatchpoint)
            add(f, S::Partial, "Transient watchpoints currently cover only the main thread");
        else add(f, S::Available);
    }
    add(F::CodeInjection, x86 && d.transport!=TargetTransport::Gdb ? S::Available : S::Unsupported,
        d.transport==TargetTransport::Gdb ? "Guest allocation, protection and relocation adapters are incomplete" :
        x86 ? "Allocation/protection and exact instruction relocation are also required" : "Injection templates and hooks currently require x86");
    add(F::GuestDebugging, d.transport==TargetTransport::Gdb ? S::Partial : S::Unsupported,
        d.transport==TargetTransport::Gdb ? "Guest memory and XML-described registers are available; debugger/MMU integration is incomplete" : "Guest CPU/MMU adapters are not complete");
    return result;
}

std::vector<TargetCapability> targetCapabilities(ProcessHandle& process) {
    return targetCapabilities(process.targetDescription());
}

std::optional<std::string> unsupportedTargetOperation(ProcessHandle& process, TargetFeature feature) {
    for (const auto& c : targetCapabilities(process))
        if (c.feature == feature && (c.state == CapabilityState::Unsupported ||
                                    c.state == CapabilityState::Blocked || c.state == CapabilityState::Unknown))
            return std::string(targetFeatureName(feature)) + ": " + c.reason;
    return std::nullopt;
}

std::string targetOperationError(ProcessHandle& process, TargetFeature feature, std::error_code error) {
    if (auto reason = unsupportedTargetOperation(process, feature)) return *reason;
    const auto transport = process.targetDescription().transport;
    if (transport != TargetTransport::Local && (feature == TargetFeature::Debugger || feature == TargetFeature::Trace ||
            feature == TargetFeature::HardwareWatchpoint || feature == TargetFeature::SoftwareWatchpoint))
        return std::string(targetFeatureName(feature)) + ": local ptrace operations are unavailable over this transport";
    if (error && error.category() == std::system_category() && error.value() == EPERM && transport == TargetTransport::Local) {
        std::string reason = std::string(targetFeatureName(feature)) + ": " + error.message();
        int scope = -1;
        std::ifstream("/proc/sys/kernel/yama/ptrace_scope") >> scope;
        if (scope >= 1)
            reason += " (kernel.yama.ptrace_scope=" + std::to_string(scope) + " only lets a process read its own "
                "descendants: start the target from this tool, run as root or with cap_sys_ptrace, or set ptrace_scope to 0)";
        return reason;
    }
    if (error) return std::string(targetFeatureName(feature)) + ": " + error.message();
    return std::string(targetFeatureName(feature)) + " failed";
}

bool processOwnedByCaller(pid_t pid) {
    if (pid <= 0) return false;
    const uid_t uid = getuid();
    if (uid == 0) return true;
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    bool uidsMatch = false, gidsMatch = false;
    for (std::string line; std::getline(status, line);) {
        const bool isUid = line.rfind("Uid:", 0) == 0, isGid = line.rfind("Gid:", 0) == 0;
        if (!isUid && !isGid) continue;
        std::istringstream ids(line.substr(4));
        const unsigned long want = isUid ? static_cast<unsigned long>(uid) : static_cast<unsigned long>(getgid());
        int count = 0;
        bool all = true;
        for (unsigned long id; ids >> id; ++count) all = all && id == want;
        (isUid ? uidsMatch : gidsMatch) = all && count == 4;
    }
    return uidsMatch && gidsMatch;
}

long seizeIfOwned(pid_t tid, unsigned long options) {
    if (!processOwnedByCaller(tid)) { errno = EPERM; return -1; }
    return ptrace(PTRACE_SEIZE, tid, nullptr, reinterpret_cast<void*>(options));
}

std::optional<std::string> memoryAccessProblem(ProcessHandle& process) {
    std::error_code last;
    int probed = 0;
    for (const auto& region : process.queryRegions()) {
        if (!(region.protection & MemProt::Read) || region.size == 0) continue;
        uint8_t byte = 0;
        auto read = process.read(region.base, &byte, 1);
        if (read && *read == 1) return std::nullopt;
        if (!read) last = read.error();
        if (++probed == 4) break;
    }
    if (!probed || !last) return std::nullopt;   // nothing readable to probe, or short reads only
    return targetOperationError(process, TargetFeature::ReadMemory, last);
}

} // namespace ce
