#pragma once

#include "core/target_machine.hpp"
#include <array>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>
#include <functional>
#include <sys/types.h>

namespace ce::os {
class NativeMemoryImage;

enum class MemorySyscall { Map, Unmap, Protect };
struct TargetProcessIdentity {
    pid_t pid = 0;
    uint64_t startTime = 0;
    uint64_t executableDevice = 0, executableInode = 0;
    bool operator==(const TargetProcessIdentity&) const = default;
};
std::expected<TargetProcessIdentity, std::error_code> targetProcessIdentity(pid_t pid);
// Select a live member without changing the process's public PID or birth.
// A leader may have exited while its siblings still own the address space.
std::expected<pid_t,std::error_code> processMemoryTask(pid_t pid);
std::expected<TargetProcessIdentity,std::error_code> processMemoryIdentity(pid_t pid);
struct TargetSyscallPlan {
    uint64_t number = 0;
    std::array<uint64_t, 6> arguments{};
    std::vector<uint8_t> instruction;
    uint8_t resultWidth = 0;
};

// Instruction mode comes from the stopped thread, independently of ELF bitness.
std::expected<TargetSyscallPlan, std::error_code> targetSyscallPlan(
    const TargetMachine& machine, InstructionMode mode, MemorySyscall operation,
    std::array<uint64_t, 6> arguments);

class TargetSyscallRecovery;
struct TargetTaskIdentity {
    pid_t tid=0;
    uint64_t startTime=0;
};
struct TargetSyscallFailure {
    std::error_code code;
    std::shared_ptr<TargetSyscallRecovery> recovery;
    std::optional<uint64_t> completedValue;
    int pendingSignal = 0;
    unsigned pendingEvent = 0;
    // Actual EXEC stop, including a nonleader's kernel TID replacement. The
    // borrowed ptrace owner must release this task rather than the old TID.
    std::optional<TargetTaskIdentity> replacementTask;
    TargetSyscallFailure(std::error_code error) : code(error) {}
    std::string message() const { return code.message(); }
    int value() const { return code.value(); }
};

class TargetSyscallRecovery {
public:
    // Retry on the thread that owns the ptrace relationship. Already completed
    // recovery is idempotent. Exited or exec-replaced targets are never replayed.
    std::expected<void, std::error_code> retry();
    // /proc/pid/mem pins the original mm, including across same-file exec.
    std::expected<void, std::error_code> checkImage() const;
    // A kernel exec or a retired mm invalidates this saved context even when
    // another CLONE_VM task keeps its original memory descriptor readable.
    bool imageRetired() const;
    std::optional<TargetTaskIdentity> replacementTask() const;
    // A stopped function may need its original signal delivered before it can
    // finish. Unexpected signals/events require this explicit owner decision;
    // process ptrace events before resuming with deliverSignal=false. retry()
    // alone never suppresses or delivers them. The result is available only
    // after the exact private return trap was observed.
    std::expected<void,std::error_code> resumeFunction(bool deliverSignal);
    std::optional<uint64_t> functionResult() const;
private:
    struct State;
    explicit TargetSyscallRecovery(std::shared_ptr<State> state) : state_(std::move(state)) {}
    std::shared_ptr<State> state_;
    friend std::expected<uint64_t, TargetSyscallFailure> executeMemorySyscallInternal(
        pid_t, const TargetMachine&, MemorySyscall, std::array<uint64_t, 6>, const TargetProcessIdentity*,
        const TargetSyscallRecovery*, bool, uintptr_t, bool,const NativeMemoryImage*,bool);
    friend std::expected<uint64_t,TargetSyscallFailure> executeStoppedFunction(
        pid_t,const TargetMachine&,uintptr_t,std::array<uint64_t,8>,uintptr_t,uintptr_t,int);
    friend std::expected<void,TargetSyscallFailure> executeThreadInspection(
        const TargetProcessIdentity&,const TargetMachine&,bool,const std::function<std::expected<void,std::error_code>()>&);
};

// Inspect or edit the selected native thread without executing a target syscall
// or stopping siblings. The callback runs under the calling ptrace owner. A
// failed callback restores GP state when writes were permitted; cleanup failure
// returns the same retained recovery record used by memory operations.
std::expected<void,TargetSyscallFailure> executeThreadInspection(
    const TargetProcessIdentity& identity,const TargetMachine& host,bool registerWrites,
    const std::function<std::expected<void,std::error_code>()>& callback);

// Seize only this thread. Preserve its register image, original syscall restart
// state. Execute an existing non-writable syscall instruction without patching
// shared program code, and verify register restoration before detaching. A failed
// restoration returns an owned recovery record and any successful syscall value.
// Recovery ownership is allocated before attachment; preflight/interrupt failures
// also retain ownership if the untouched target cannot be detached safely.
std::expected<uint64_t, TargetSyscallFailure> executeMemorySyscall(
    pid_t tid, const TargetMachine& host, MemorySyscall operation,
    std::array<uint64_t, 6> arguments, const TargetProcessIdentity* expectedIdentity = nullptr,
    const TargetSyscallRecovery* expectedImage = nullptr,const NativeMemoryImage* savedImage=nullptr);

// The caller already owns this stopped thread and a private executable scratch
// page. Execute at scratch (+16 for i386 compat mode) without patching shared
// program code or detaching. On failure, drain recovery on the same owner before
// resuming; pendingSignal belongs to the caller's next resume/detach operation.
// ARM32 Linux EABI supports this private-scratch primitive in ARM and Thumb
// modes on native ARM32 or an ARM64 compat controller. It runs SVC followed by
// an owned UDF trap, clears ITSTATE only during private execution, and verifies
// the original GP/extended/code snapshots before returning. The caller must
// supply a user-mode stop; parked/restart syscall adapters, borrowed ARM32 sites
// and native calls remain unsupported. Big-endian instruction modes are rejected.
std::expected<uint64_t, TargetSyscallFailure> executeStoppedMemorySyscall(
    pid_t tid, const TargetMachine& host, MemorySyscall operation,
    std::array<uint64_t, 6> arguments, uintptr_t scratch);

// All threads sharing this code must be stopped by the caller. Temporarily patch
// the stopped instruction site, retain recovery and leave the attachment owned.
// Used to release the private syscall page after restoring page guards.
std::expected<uint64_t, TargetSyscallFailure> executeQuiescedMemorySyscall(
    pid_t tid,const TargetMachine& host,MemorySyscall operation,std::array<uint64_t,6> arguments);

// The caller owns this stopped thread. Borrow an existing non-writable Unix
// syscall instruction, without changing shared code or detaching. This can
// release a private call frame while sibling threads keep running.
std::expected<uint64_t,TargetSyscallFailure> executeOwnedMemorySyscall(
    pid_t tid,const TargetMachine& host,MemorySyscall operation,std::array<uint64_t,6> arguments);

// Verify an existing saved mm while the caller owns the actual stopped task.
// Reclaim the fresh private proof mapping before returning; incomplete nested
// restoration/cleanup retains its own recovery without a caller allocation.
std::expected<void,TargetSyscallFailure> verifyStoppedMemoryImage(
    pid_t,const TargetMachine&,const NativeMemoryImage&);

// Read-only eligibility probe for selecting a native call thread. ARM64 syscall
// restart stops may have syscallno=-1 with PC rewound onto SVC; they still need
// a rendezvous adapter and must not be mistaken for ordinary user-mode stops.
std::expected<void,std::error_code> checkStoppedFunctionAbi(pid_t tid,const TargetMachine& host);

// Integer/pointer System V i386/AMD64 and AAPCS64 calls. The caller supplies a
// private executable code page and a private writable stack, aligned to 16 bytes
// with at least 64 bytes below stackTop. Keep both mapped until recovery finishes.
// Original program code and stack bytes are preserved on return. A timeout retains the live
// call; an unexpected signal retains its delivery stop for resumeFunction().
// Requires a user-mode stop without an interrupted syscall; mixed Windows/Unix
// modes are not a native call ABI. Callees must not change SVE/SME vector-length
// configuration. The original GP/extended context and mask are verified before returning
// ownership. This primitive leaves the original ptrace relationship intact.
std::expected<uint64_t,TargetSyscallFailure> executeStoppedFunction(
    pid_t tid,const TargetMachine& host,uintptr_t function,std::array<uint64_t,8> arguments,
    uintptr_t code,uintptr_t stackTop,int timeoutMs=5000);

} // namespace ce::os
