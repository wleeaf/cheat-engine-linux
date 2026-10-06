#include "platform/linux/target_debug.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#if defined(__x86_64__)
#include <sys/user.h>
#elif defined(__aarch64__)
#include <asm/ptrace.h>
#endif

namespace ce::os {
namespace {
Error kernelError() { return {errno, std::system_category()}; }
Error invalid() { return std::make_error_code(std::errc::invalid_argument); }
Error unsupported() { return std::make_error_code(std::errc::not_supported); }
Error brokenRestore() { return std::make_error_code(std::errc::state_not_recoverable); }

#if defined(__arm__) || defined(__aarch64__)
// Probe with room for either ABI: requesting only 72 bytes would truncate an
// AArch64 bank and incorrectly classify it as AArch32. The returned length is
// authoritative on both a native ARM kernel and an ARM64 compat kernel.
struct ArmGeneralBank {
    std::array<uint64_t,34> words{};
    size_t size = 0;
    bool compat() const { return size == 18 * sizeof(uint32_t); }
};
Result<ArmGeneralBank> readArmGeneral(pid_t tid) {
    ArmGeneralBank result;
    iovec io{result.words.data(), sizeof(result.words)};
    if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(NT_PRSTATUS), &io) < 0)
        return std::unexpected(kernelError());
    if (io.iov_len != sizeof(result.words) && io.iov_len != 18 * sizeof(uint32_t))
        return std::unexpected(unsupported());
    result.size = io.iov_len;
    return result;
}
Result<void> writeArmGeneral(pid_t tid, const ArmGeneralBank& bank) {
    iovec io{const_cast<uint64_t*>(bank.words.data()), bank.size};
    if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(NT_PRSTATUS), &io) < 0)
        return std::unexpected(kernelError());
    return {};
}
bool sameArmGeneral(const ArmGeneralBank& a, const ArmGeneralBank& b) {
    return a.size == b.size && std::memcmp(a.words.data(), b.words.data(), a.size) == 0;
}
#endif

#if defined(__x86_64__)
Result<uint64_t> readDr(pid_t tid, unsigned index) {
    errno = 0;
    long value = ptrace(PTRACE_PEEKUSER, tid,
                       reinterpret_cast<void*>(offsetof(user, u_debugreg) + index * sizeof(long)), nullptr);
    if (value == -1 && errno) return std::unexpected(kernelError());
    return static_cast<uint64_t>(value);
}
Result<void> writeDr(pid_t tid, unsigned index, uint64_t value) {
    if (ptrace(PTRACE_POKEUSER, tid,
               reinterpret_cast<void*>(offsetof(user, u_debugreg) + index * sizeof(long)),
               reinterpret_cast<void*>(value)) < 0) return std::unexpected(kernelError());
    return {};
}
// DR7 bit 10 and DR6 reserved bits are normalized by the kernel.
bool verifyDr(pid_t tid, unsigned index, uint64_t value) {
    auto observed = readDr(tid, index);
    uint64_t mask = index == 7 ? UINT64_C(0xffff03ff) : index == 6 ? UINT64_C(0xe00f) : UINT64_MAX;
    return observed && ((*observed ^ value) & mask) == 0;
}
#elif defined(__aarch64__)
template<class T> Result<void> readRegset(pid_t tid, unsigned note, T& value) {
    iovec io{&value, sizeof(value)};
    if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(uintptr_t(note)), &io) < 0)
        return std::unexpected(kernelError());
    if (io.iov_len != sizeof(value)) return std::unexpected(unsupported());
    return {};
}
template<class T> Result<void> writeRegset(pid_t tid, unsigned note, const T& value, size_t size = sizeof(T)) {
    iovec io{const_cast<T*>(&value), size};
    if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(uintptr_t(note)), &io) < 0)
        return std::unexpected(kernelError());
    return {};
}
Result<user_hwdebug_state> readArmBank(pid_t tid, bool execution) {
    user_pt_regs registers{};
    auto native=readRegset(tid,NT_PRSTATUS,registers);
    if (!native) return std::unexpected(native.error());
    user_hwdebug_state state{};
    auto read = readRegset(tid, execution ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH, state);
    if (!read) return std::unexpected(read.error());
    if ((state.dbg_info & 0xff) > 16) return std::unexpected(unsupported());
    return state;
}
// SETREGSET has no offset. Preserve the preceding slots and limit the write to
// the requested slot, avoiding creation of unused perf events for later slots.
Result<void> writeArmBank(pid_t tid, bool execution, const user_hwdebug_state& state, unsigned slot) {
    return writeRegset(tid, execution ? NT_ARM_HW_BREAK : NT_ARM_HW_WATCH, state,
                       offsetof(user_hwdebug_state, dbg_regs) + (slot + 1) * sizeof(state.dbg_regs[0]));
}
bool verifyArmBank(pid_t tid, bool execution, const user_hwdebug_state& state, unsigned slot) {
    auto observed = readArmBank(tid, execution);
    if (!observed) return false;
    for (unsigned i = 0; i <= slot; ++i)
        if (observed->dbg_regs[i].addr != state.dbg_regs[i].addr ||
            (state.dbg_regs[i].ctrl ? observed->dbg_regs[i].ctrl != state.dbg_regs[i].ctrl :
             (observed->dbg_regs[i].ctrl & 1u) != 0)) return false;
    // A previously absent perf event has ctrl=0. The kernel can represent its
    // restored disabled state with normalized length/type bits and enable=0.
    return true;
}
Result<void> restoreArmSnapshot(pid_t tid,bool execution,const user_hwdebug_state& original) {
    NativeHardwareBank saved;
    saved.count=original.dbg_info&0xff;
    for (unsigned i=0;i<saved.count;++i) saved.entries[i]={original.dbg_regs[i].addr,original.dbg_regs[i].ctrl};
    return restoreNativeHardwareBank(tid,execution,saved);
}
#endif
} // namespace

Result<CpuContext> readNativeContext(pid_t tid) {
    CpuContext context{};
#if defined(__x86_64__)
    user_regs_struct r{};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) < 0) return std::unexpected(kernelError());
    context.architecture = (r.cs & 0xffff) == 0x23 ? CpuArchitecture::X86_32 : CpuArchitecture::X86_64;
    context.rax=r.rax; context.rbx=r.rbx; context.rcx=r.rcx; context.rdx=r.rdx;
    context.rsi=r.rsi; context.rdi=r.rdi; context.rbp=r.rbp; context.rsp=r.rsp;
    context.r8=r.r8; context.r9=r.r9; context.r10=r.r10; context.r11=r.r11;
    context.r12=r.r12; context.r13=r.r13; context.r14=r.r14; context.r15=r.r15;
    context.rip=r.rip; context.rflags=r.eflags;
    context.cs=r.cs; context.ss=r.ss; context.ds=r.ds; context.es=r.es; context.fs=r.fs; context.gs=r.gs;
    auto d0=readDr(tid,0), d1=readDr(tid,1), d2=readDr(tid,2), d3=readDr(tid,3), d6=readDr(tid,6), d7=readDr(tid,7);
    context.debugRegistersValid = d0 && d1 && d2 && d3 && d6 && d7;
    if (context.debugRegistersValid) {
        context.dr0=*d0; context.dr1=*d1; context.dr2=*d2; context.dr3=*d3; context.dr6=*d6; context.dr7=*d7;
    }
#elif defined(__aarch64__) || defined(__arm__)
    auto bank = readArmGeneral(tid);
    if (!bank) return std::unexpected(bank.error());
    if (bank->compat()) {
        std::array<uint32_t,18> r{};
        std::memcpy(r.data(), bank->words.data(), sizeof(r));
        context.architecture = CpuArchitecture::Arm32;
        std::copy(r.begin(), r.begin()+13, context.x.begin());
        context.x[14] = r[14]; context.sp = r[13]; context.pc = r[15]; context.pstate = r[16];
    } else {
        context.architecture = CpuArchitecture::Arm64;
        std::copy(bank->words.begin(), bank->words.begin()+31, context.x.begin());
        context.sp = bank->words[31]; context.pc = bank->words[32]; context.pstate = bank->words[33];
    }
#else
    return std::unexpected(unsupported());
#endif
    return context;
}

Result<void> writeNativeContext(pid_t tid, const CpuContext& c) {
#if defined(__x86_64__)
    user_regs_struct original{};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &original) < 0) return std::unexpected(kernelError());
    auto architecture = (original.cs & 0xffff) == 0x23 ? CpuArchitecture::X86_32 : CpuArchitecture::X86_64;
    if (c.architecture != CpuArchitecture::Unknown && c.architecture != architecture)
        return std::unexpected(invalid());
    user_regs_struct r=original;
    r.rax=c.rax; r.rbx=c.rbx; r.rcx=c.rcx; r.rdx=c.rdx;
    r.rsi=c.rsi; r.rdi=c.rdi; r.rbp=c.rbp; r.rsp=c.rsp;
    r.r8=c.r8; r.r9=c.r9; r.r10=c.r10; r.r11=c.r11;
    r.r12=c.r12; r.r13=c.r13; r.r14=c.r14; r.r15=c.r15;
    r.rip=c.rip; r.eflags=c.rflags;
    r.cs=c.cs; r.ss=c.ss; r.ds=c.ds; r.es=c.es; r.fs=c.fs; r.gs=c.gs;
    constexpr std::array<unsigned,6> indices{0,1,2,3,6,7};
    std::array<uint64_t,6> saved{};
    std::array<uint64_t,6> desired{c.dr0,c.dr1,c.dr2,c.dr3,c.dr6,c.dr7};
    if (c.debugRegistersValid) {
        for (size_t i=0;i<indices.size();++i) {
            auto value=readDr(tid,indices[i]);
            if (!value) return std::unexpected(value.error());
            saved[i]=*value;
        }
    }
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &r) < 0) {
        // x86 SETREGS validates fields sequentially and can fail after writing
        // earlier registers. Restore the entire original bank on any failure.
        Error error=kernelError();
        bool restored=ptrace(PTRACE_SETREGS,tid,nullptr,&original)==0;
        user_regs_struct observed{};
        restored=ptrace(PTRACE_GETREGS,tid,nullptr,&observed)==0 &&
            std::memcmp(&original,&observed,sizeof(original))==0 && restored;
        return std::unexpected(restored ? error : brokenRestore());
    }
    if (!c.debugRegistersValid) return {};
    Error error;
    if (auto disable=writeDr(tid,7,0); !disable) error=disable.error();
    for (size_t i=0;!error && i<indices.size();++i) {
        auto write=writeDr(tid,indices[i],desired[i]);
        if (!write) error=write.error();
        else if (!verifyDr(tid,indices[i],desired[i])) error=std::make_error_code(std::errc::io_error);
    }
    if (!error) return {};
    bool restored=writeDr(tid,7,0).has_value();
    for (size_t i=0;i<indices.size();++i) restored=writeDr(tid,indices[i],saved[i]).has_value() && restored;
    restored=(ptrace(PTRACE_SETREGS,tid,nullptr,&original)==0) && restored;
    for (size_t i=0;i<indices.size();++i) restored=verifyDr(tid,indices[i],saved[i]) && restored;
    user_regs_struct observed{};
    restored=ptrace(PTRACE_GETREGS,tid,nullptr,&observed)==0 && std::memcmp(&original,&observed,sizeof(original))==0 && restored;
    return std::unexpected(restored ? error : brokenRestore());
#elif defined(__aarch64__) || defined(__arm__)
    auto original = readArmGeneral(tid);
    if (!original) return std::unexpected(original.error());
    ArmGeneralBank desired = *original;
    if (original->compat()) {
        if (c.architecture != CpuArchitecture::Arm32 || c.pc % ((c.pstate & 0x20) ? 2 : 4) ||
            c.pc > UINT32_MAX || c.sp > UINT32_MAX || c.pstate > UINT32_MAX || c.x[14] > UINT32_MAX ||
            !std::all_of(c.x.begin(), c.x.begin()+13, [](uint64_t value) { return value <= UINT32_MAX; }))
            return std::unexpected(invalid());
        std::array<uint32_t,18> r{};
        std::memcpy(r.data(), original->words.data(), sizeof(r));
        std::copy(c.x.begin(), c.x.begin()+13, r.begin());
        r[13] = c.sp; r[14] = c.x[14]; r[15] = c.pc; r[16] = c.pstate;
        // ORIG_R0 remains the actual kernel syscall-restart value.
        std::memcpy(desired.words.data(), r.data(), sizeof(r));
    } else {
        if (c.architecture != CpuArchitecture::Arm64 || c.pc % 4)
            return std::unexpected(invalid());
        std::copy(c.x.begin(), c.x.end(), desired.words.begin());
        desired.words[31] = c.sp; desired.words[32] = c.pc; desired.words[33] = c.pstate;
    }
    auto written = writeArmGeneral(tid, desired);
    Error failure = written ? Error{} : written.error();
    auto observed = readArmGeneral(tid);
    if (!failure && observed && sameArmGeneral(*observed, desired)) return {};
    if (!failure) failure = observed ? std::make_error_code(std::errc::io_error) : observed.error();
    auto restored = writeArmGeneral(tid, *original);
    observed = readArmGeneral(tid);
    if (!restored || !observed || !sameArmGeneral(*observed, *original))
        return std::unexpected(brokenRestore());
    return std::unexpected(failure);
#else
    return std::unexpected(unsupported());
#endif
}

bool isNativeSyscallStepTrap(pid_t tid,const siginfo_t& info) {
    if (info.si_signo!=SIGTRAP) return false;
#if defined(__x86_64__)
    if (info.si_code!=TRAP_BRKPT) return false;
    user_regs_struct registers{};
    // Linux user_single_step_report sends TRAP_BRKPT at the syscall's return
    // PC. Hardware INT3/INT1 traps reset orig_ax to -1, so they cannot match.
    return ptrace(PTRACE_GETREGS,tid,nullptr,&registers)==0 && registers.orig_rax!=UINT64_MAX &&
        reinterpret_cast<uintptr_t>(info.si_addr)==registers.rip;
#elif defined(__aarch64__)
    (void)tid;
    return info.si_code==SI_USER && info.si_pid==0 && info.si_uid==0;
#else
    (void)tid; return false;
#endif
}

Result<NativeVectorContext> readNativeVectors(pid_t tid) {
    NativeVectorContext result;
#if defined(__x86_64__)
    user_fpregs_struct fp{};
    if (ptrace(PTRACE_GETFPREGS,tid,nullptr,&fp)<0) return std::unexpected(kernelError());
    std::memcpy(result.registers.data(),fp.xmm_space,sizeof(fp.xmm_space));
    result.count=16; result.control=fp.mxcsr;
#elif defined(__aarch64__)
    user_fpsimd_state fp{};
    auto read=readRegset(tid,NT_FPREGSET,fp);
    if (!read) return std::unexpected(read.error());
    std::memcpy(result.registers.data(),fp.vregs,sizeof(fp.vregs));
    result.count=32; result.status=fp.fpsr; result.control=fp.fpcr;
#else
    return std::unexpected(unsupported());
#endif
    return result;
}

Result<NativeHardwareBank> readNativeHardwareBank(pid_t tid, bool execution) {
    NativeHardwareBank bank;
#if defined(__x86_64__)
    auto control=readDr(tid,7), status=readDr(tid,6);
    if (!control || !status) return std::unexpected(!control ? control.error() : status.error());
    bank.count=4; bank.control=*control; bank.status=*status;
    for (unsigned i=0;i<4;++i) {
        auto address=readDr(tid,i);
        if (!address) return std::unexpected(address.error());
        bank.entries[i]={*address,static_cast<uint32_t>(((*control>>(i*2))&3) | (((*control>>(16+i*4))&15)<<2))};
    }
#elif defined(__aarch64__)
    auto state=readArmBank(tid,execution);
    if (!state) return std::unexpected(state.error());
    bank.count=state->dbg_info&0xff;
    for (unsigned i=0;i<bank.count;++i) bank.entries[i]={state->dbg_regs[i].addr,state->dbg_regs[i].ctrl};
#else
    return std::unexpected(unsupported());
#endif
    return bank;
}

Result<void> restoreNativeHardwareBank(pid_t tid,bool execution,const NativeHardwareBank& saved) {
#if defined(__x86_64__)
    if (saved.count!=4) return std::unexpected(invalid());
    auto write=writeDr(tid,7,0);
    for (unsigned i=0;write && i<4;++i) write=writeDr(tid,i,saved.entries[i].address);
    if (write) write=writeDr(tid,6,saved.status);
    if (write) write=writeDr(tid,7,saved.control);
    if (!write) return write;
    for (unsigned i=0;i<4;++i)
        if (!verifyDr(tid,i,saved.entries[i].address)) return std::unexpected(brokenRestore());
    if (!verifyDr(tid,6,saved.status) || !verifyDr(tid,7,saved.control)) return std::unexpected(brokenRestore());
    return {};
#elif defined(__aarch64__)
    auto current=readArmBank(tid,execution);
    if (!current) return std::unexpected(current.error());
    if (!saved.count || saved.count!=(current->dbg_info&0xff)) return std::unexpected(invalid());
    unsigned changed=0;
    for (unsigned i=0;i<saved.count;++i) {
        // An absent event has ctrl=0. Once created, Linux keeps a disabled
        // event's length/type bits; ptrace cannot remove that perf event.
        bool sameControl=saved.entries[i].control ? current->dbg_regs[i].ctrl==saved.entries[i].control :
            (current->dbg_regs[i].ctrl&1u)==0;
        if (current->dbg_regs[i].addr!=saved.entries[i].address || !sameControl) changed=i+1;
    }
    if (!changed) return {};
    auto disabled=*current;
    for (unsigned i=0;i<changed;++i) disabled.dbg_regs[i].ctrl&=~1u;
    auto desired=*current;
    for (unsigned i=0;i<changed;++i) {
        desired.dbg_regs[i].addr=saved.entries[i].address;
        desired.dbg_regs[i].ctrl=saved.entries[i].control;
    }
    auto write=writeArmBank(tid,execution,disabled,changed-1);
    // Linux ignores length/type fields when ctrl.enabled is zero. Restore a
    // previously configured disabled slot by applying its attributes enabled,
    // then disabling it again, while the target remains stopped. Configure one
    // slot at a time instead of consuming resources for every disabled slot.
    auto configured=disabled;
    for (unsigned i=0;write && i<changed;++i) {
        if (!saved.entries[i].control || (saved.entries[i].control&1u) ||
            (current->dbg_regs[i].ctrl&~1u)==saved.entries[i].control) continue;
        configured.dbg_regs[i].addr=saved.entries[i].address;
        configured.dbg_regs[i].ctrl=saved.entries[i].control|1u;
        write=writeArmBank(tid,execution,configured,i);
        configured.dbg_regs[i].ctrl=saved.entries[i].control;
        if (write) write=writeArmBank(tid,execution,configured,i);
    }
    if (write) write=writeArmBank(tid,execution,desired,changed-1);
    if (!write) return write;
    if (!verifyArmBank(tid,execution,desired,changed-1)) return std::unexpected(brokenRestore());
    return {};
#else
    return std::unexpected(unsupported());
#endif
}

Result<void> setNativeHardwareBreakpoint(pid_t tid,unsigned slot,uintptr_t address,
                                        HardwareBreakpointAccess access,unsigned length) {
    if (access != HardwareBreakpointAccess::Execute && access != HardwareBreakpointAccess::Write &&
        access != HardwareBreakpointAccess::ReadWrite) return std::unexpected(invalid());
#if defined(__x86_64__)
    if (slot>=4 || (length!=1 && length!=2 && length!=4 && length!=8) || address%length ||
        (access==HardwareBreakpointAccess::Execute && length!=1)) return std::unexpected(invalid());
    if (length==8) {
        auto context=readNativeContext(tid);
        if (!context) return std::unexpected(context.error());
        if (context->architecture==CpuArchitecture::X86_32) return std::unexpected(invalid());
    }
    auto oldAddress=readDr(tid,slot), oldControl=readDr(tid,7);
    if (!oldAddress || !oldControl) return std::unexpected(!oldAddress ? oldAddress.error() : oldControl.error());
    unsigned type=access==HardwareBreakpointAccess::Execute ? 0 : access==HardwareBreakpointAccess::Write ? 1 : 3;
    unsigned len=length==1 ? 0 : length==2 ? 1 : length==4 ? 3 : 2;
    uint64_t control=(*oldControl & ~(UINT64_C(3)<<(slot*2)) & ~(UINT64_C(15)<<(16+slot*4))) |
                     (UINT64_C(1)<<(slot*2)) | (uint64_t(type | (len<<2))<<(16+slot*4));
    auto disable=writeDr(tid,7,*oldControl & ~(UINT64_C(3)<<(slot*2)));
    auto write=disable ? writeDr(tid,slot,address) : disable;
    if (write) write=writeDr(tid,7,control);
    if (write && verifyDr(tid,slot,address) && verifyDr(tid,7,control)) return {};
    Error error=write ? std::make_error_code(std::errc::io_error) : write.error();
    bool restored=writeDr(tid,7,*oldControl & ~(UINT64_C(3)<<(slot*2))).has_value();
    restored=writeDr(tid,slot,*oldAddress).has_value() && restored;
    restored=writeDr(tid,7,*oldControl).has_value() && restored;
    restored=verifyDr(tid,slot,*oldAddress) && verifyDr(tid,7,*oldControl) && restored;
    return std::unexpected(restored ? error : brokenRestore());
#elif defined(__aarch64__)
    bool execution=access==HardwareBreakpointAccess::Execute;
    if (slot>=16 || (execution ? length!=4 || address%4 :
        (length!=1 && length!=2 && length!=4 && length!=8) || (address%8)+length>8))
        return std::unexpected(invalid());
    auto original=readArmBank(tid,execution);
    if (!original) return std::unexpected(original.error());
    if (slot >= (original->dbg_info&0xff)) return std::unexpected(invalid());
    auto desired=*original;
    unsigned offset=execution ? 0 : address%8;
    unsigned mask=((1u<<length)-1)<<offset;
    unsigned type=execution ? 0 : access==HardwareBreakpointAccess::Write ? 2 : 3;
    desired.dbg_regs[slot].addr=execution ? address : address&~uintptr_t(7);
    desired.dbg_regs[slot].ctrl=1 | (2u<<1) | (type<<3) | (mask<<5);
    auto disabled=*original; disabled.dbg_regs[slot].ctrl&=~1u;
    auto write=writeArmBank(tid,execution,disabled,slot);
    if (write) write=writeArmBank(tid,execution,desired,slot);
    if (write && verifyArmBank(tid,execution,desired,slot)) return {};
    Error error=write ? std::make_error_code(std::errc::io_error) : write.error();
    auto restore=restoreArmSnapshot(tid,execution,*original);
    return std::unexpected(restore ? error : brokenRestore());
#else
    return std::unexpected(unsupported());
#endif
}

Result<void> removeNativeHardwareBreakpoint(pid_t tid,unsigned slot,bool execution) {
#if defined(__x86_64__)
    if (slot>=4) return std::unexpected(invalid());
    auto control=readDr(tid,7);
    if (!control) return std::unexpected(control.error());
    uint64_t desired=*control & ~(UINT64_C(3)<<(slot*2)) & ~(UINT64_C(15)<<(16+slot*4));
    auto write=writeDr(tid,7,desired);
    if (!write) return write;
    if (verifyDr(tid,7,desired)) return {};
    auto restore=writeDr(tid,7,*control);
    return std::unexpected(restore && verifyDr(tid,7,*control) ? std::make_error_code(std::errc::io_error) : brokenRestore());
#elif defined(__aarch64__)
    auto original=readArmBank(tid,execution);
    if (!original) return std::unexpected(original.error());
    if (slot >= (original->dbg_info&0xff)) return std::unexpected(invalid());
    auto desired=*original; desired.dbg_regs[slot].ctrl&=~1u;
    auto write=writeArmBank(tid,execution,desired,slot);
    if (write && verifyArmBank(tid,execution,desired,slot)) return {};
    Error error=write ? std::make_error_code(std::errc::io_error) : write.error();
    auto restore=restoreArmSnapshot(tid,execution,*original);
    return std::unexpected(restore ? error : brokenRestore());
#else
    return std::unexpected(unsupported());
#endif
}

Result<void> clearNativeHardwareStatus(pid_t tid) {
#if defined(__x86_64__)
    return writeDr(tid,6,0);
#elif defined(__aarch64__)
    // ARM64 identifies a hardware stop using siginfo.si_code/si_addr; no DR6.
    return {};
#else
    return std::unexpected(unsupported());
#endif
}
namespace {
Result<long> readCodeWord(pid_t tid,uintptr_t address) {
    errno=0;
    long word=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(address),nullptr);
    if (word==-1 && errno) return std::unexpected(kernelError());
    return word;
}
Result<void> patchCodeBytes(pid_t tid,const NativeSoftwareBreakpoint& breakpoint,bool restoring) {
    uintptr_t base=breakpoint.address-breakpoint.address%sizeof(long);
    auto word=readCodeWord(tid,base);
    if (!word) return std::unexpected(word.error());
    const auto& bytes=restoring ? breakpoint.original : breakpoint.trap;
    std::memcpy(reinterpret_cast<uint8_t*>(&*word)+(breakpoint.address-base),bytes.data(),breakpoint.size);
    // POKETEXT writes through the kernel's architecture-aware remote-memory
    // access, including ARM64 instruction-cache synchronization.
    if (ptrace(PTRACE_POKETEXT,tid,reinterpret_cast<void*>(base),reinterpret_cast<void*>(*word))<0)
        return std::unexpected(kernelError());
    auto verify=readCodeWord(tid,base);
    if (!verify) return std::unexpected(verify.error());
    if (std::memcmp(reinterpret_cast<const uint8_t*>(&*verify)+(breakpoint.address-base),bytes.data(),breakpoint.size))
        return std::unexpected(std::make_error_code(std::errc::io_error));
    return {};
}
}
std::expected<NativeSoftwareBreakpoint,NativeBreakpointFailure> installNativeSoftwareBreakpoint(
    pid_t tid,uintptr_t address,InstructionMode mode) {
    NativeSoftwareBreakpoint breakpoint;
    breakpoint.address=address;
#if defined(__arm__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // The ARM32 interface does not yet carry BE32 versus BE8 code format.
    // Do not guess an instruction encoding on a big-endian native engine.
    return std::unexpected(NativeBreakpointFailure{unsupported(),{}});
#endif
#if defined(__x86_64__)
    if (mode!=InstructionMode::X86_32 && mode!=InstructionMode::X86_64)
        return std::unexpected(NativeBreakpointFailure{unsupported(),{}});
    breakpoint.size=1; breakpoint.trap[0]=0xcc;
#elif defined(__aarch64__) || defined(__arm__)
    if (mode == InstructionMode::Arm) {
        if (address % 4) return std::unexpected(NativeBreakpointFailure{invalid(),{}});
        breakpoint.size = 4; breakpoint.trap = {0xf0,0x01,0xf0,0xe7}; // Linux ARM UDF trap.
    } else if (mode == InstructionMode::Thumb) {
        if (address % 2) return std::unexpected(NativeBreakpointFailure{invalid(),{}});
        breakpoint.size = 2; breakpoint.trap = {0x01,0xde,0,0}; // Linux Thumb UDF trap.
    } else if (mode == InstructionMode::Aarch64) {
        if (address % 4) return std::unexpected(NativeBreakpointFailure{invalid(),{}});
        breakpoint.size = 4; breakpoint.trap = {0,0,0x20,0xd4}; // BRK #0, instructions are LE.
    } else return std::unexpected(NativeBreakpointFailure{unsupported(),{}});
#else
    return std::unexpected(NativeBreakpointFailure{unsupported(),{}});
#endif
    auto context=readNativeContext(tid);
    if (!context) return std::unexpected(NativeBreakpointFailure{context.error(),{}});
#if defined(__aarch64__) || defined(__arm__)
    if (context->architecture != (mode == InstructionMode::Aarch64 ? CpuArchitecture::Arm64 : CpuArchitecture::Arm32))
        return std::unexpected(NativeBreakpointFailure{invalid(),{}});
    // A CPSR big-data-endian state does not distinguish BE32 from BE8 code.
    // Until the caller supplies that instruction format, avoid writing a trap
    // with an assumed byte order. AArch64 instructions always remain LE.
    if (context->architecture == CpuArchitecture::Arm32 && (context->pstate & 0x200))
        return std::unexpected(NativeBreakpointFailure{unsupported(),{}});
#endif
#if defined(__x86_64__)
    // WoW64 can enter a 32-bit code module from a native loader. The explicit
    // selected code mode controls encoding, rather than the stopped loader PC.
    if (mode==InstructionMode::X86_32 && address>UINT32_MAX)
        return std::unexpected(NativeBreakpointFailure{invalid(),{}});
#endif
    uintptr_t base=address-address%sizeof(long);
    auto word=readCodeWord(tid,base);
    if (!word) return std::unexpected(NativeBreakpointFailure{word.error(),{}});
    std::memcpy(breakpoint.original.data(),reinterpret_cast<const uint8_t*>(&*word)+(address-base),breakpoint.size);
    if (std::equal(breakpoint.original.begin(),breakpoint.original.begin()+breakpoint.size,breakpoint.trap.begin()))
        return std::unexpected(NativeBreakpointFailure{std::make_error_code(std::errc::file_exists),{}});
    breakpoint.installed=true;
    auto write=patchCodeBytes(tid,breakpoint,false);
    if (write) return breakpoint;
    auto error=write.error();
    auto restored=patchCodeBytes(tid,breakpoint,true);
    return std::unexpected(NativeBreakpointFailure{error,restored ? std::nullopt : std::optional(breakpoint)});
}
Result<void> removeNativeSoftwareBreakpoint(pid_t tid,NativeSoftwareBreakpoint& breakpoint) {
    if (!breakpoint.installed) return {};
    if (!breakpoint.size || breakpoint.size>4 ||
        breakpoint.address%sizeof(long)+breakpoint.size>sizeof(long)) return std::unexpected(invalid());
    uintptr_t base=breakpoint.address-breakpoint.address%sizeof(long);
    auto word=readCodeWord(tid,base);
    if (!word) return std::unexpected(word.error());
    auto bytes=reinterpret_cast<const uint8_t*>(&*word)+(breakpoint.address-base);
    if (!std::memcmp(bytes,breakpoint.original.data(),breakpoint.size)) { breakpoint.installed=false; return {}; }
    if (std::memcmp(bytes,breakpoint.trap.data(),breakpoint.size)) return std::unexpected(brokenRestore());
    auto restore=patchCodeBytes(tid,breakpoint,true);
    if (restore) breakpoint.installed=false;
    return restore;
}
uintptr_t nativeSoftwareBreakpointAddress(const CpuContext& context) {
    auto pc=context.instructionPointer();
    return context.hasArmRegisters() ? pc : pc ? pc-1 : 0;
}

} // namespace ce::os
