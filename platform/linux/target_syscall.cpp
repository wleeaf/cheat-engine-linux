// Native 32-bit engines still need full /proc memory offsets and inode values.
#if defined(__arm__) && !defined(_FILE_OFFSET_BITS)
#define _FILE_OFFSET_BITS 64
#endif
#include "platform/linux/target_syscall.hpp"
#include "platform/linux/memory_image.hpp"
#include "platform/linux/register_image.hpp"
#include "platform/linux/arm64_vector_return.hpp"
#include "core/log.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <limits>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <map>
#include <new>
#include <chrono>
#include <tuple>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h>
#include <dirent.h>
#if defined(__x86_64__) || defined(__i386__)
#include <sys/user.h>
#include "arch/disassembler.hpp"
#elif defined(__aarch64__)
#include <asm/ptrace.h>
#endif

namespace ce::os {
namespace {
std::unexpected<std::error_code> unsupported() {
    return std::unexpected(std::make_error_code(std::errc::not_supported));
}
std::error_code currentError() { return {errno, std::system_category()}; }
std::error_code invalid() { return std::make_error_code(std::errc::invalid_argument); }

// Task birth is independent of executable metadata and uses no heap storage.
std::expected<uint64_t, std::error_code> readTaskBirth(const char* path,char* state=nullptr,bool* exiting=nullptr) {
    char contents[4096];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::unexpected(currentError());
    ssize_t count;
    do { count = ::read(fd, contents, sizeof(contents) - 1); } while (count < 0 && errno == EINTR);
    auto error = currentError();
    close(fd);
    if (count < 0) return std::unexpected(error);
    contents[count] = '\0';
    char* field = std::strrchr(contents, ')');
    if (!field) return std::unexpected(invalid());
    ++field;
    if (state) { while (*field==' ') ++field; *state=*field; }
    for (int index = 0; index < 19; ++index) {
        while (*field == ' ') ++field;
        if (exiting && index==6) { // /proc stat field 9: exported task flags.
            char* end=nullptr; errno=0;
            const auto flags=std::strtoull(field,&end,10);
            if (errno || end==field || *end!=' ') return std::unexpected(invalid());
            // PF_POSTCOREDUMP is set on entry to do_exit, before the EXIT stop;
            // PF_EXITING follows before exit_mm. Neither task can return to user code.
            *exiting=(flags&12)!=0;
        }
        while (*field && *field != ' ') ++field;
        if (!*field) return std::unexpected(invalid());
    }
    while (*field == ' ') ++field;
    char* end = nullptr;
    errno = 0;
    uint64_t start = std::strtoull(field, &end, 10);
    if (errno || end == field || (*end != ' ' && *end != '\0') || !start) return std::unexpected(invalid());
    return start;
}
std::expected<uint64_t,std::error_code> taskStartTime(pid_t pid,char* state=nullptr,bool* exiting=nullptr) {
    char path[64];
    std::snprintf(path,sizeof(path),"/proc/%ld/stat",static_cast<long>(pid));
    return readTaskBirth(path,state,exiting);
}
} // namespace

std::expected<pid_t,std::error_code> processMemoryTask(pid_t pid) {
    char state=0;
    bool exiting=false;
    auto birth=taskStartTime(pid,&state,&exiting);
    if (!birth) return std::unexpected(birth.error());
    if (!exiting && state!='Z' && state!='X' && state!='x') return pid;
    char path[128];
    std::snprintf(path,sizeof(path),"/proc/%ld/task",static_cast<long>(pid));
    DIR* directory=opendir(path);
    if (!directory) return std::unexpected(currentError());
    std::unique_ptr<DIR,decltype(&closedir)> owned(directory,&closedir);
    while (auto* entry=readdir(directory)) {
        char* end=nullptr; errno=0;
        const long candidate=std::strtol(entry->d_name,&end,10);
        if (errno || !*entry->d_name || *end || candidate<=0 || candidate>INT32_MAX || candidate==pid) continue;
        std::snprintf(path,sizeof(path),"/proc/%ld/task/%ld/stat",static_cast<long>(pid),candidate);
        auto member=readTaskBirth(path,&state,&exiting);
        if (!member || exiting || state=='Z' || state=='X' || state=='x') continue;
        // Bind the numeric task used by process_vm/ptrace to this membership.
        auto actual=taskStartTime(static_cast<pid_t>(candidate),&state,&exiting);
        auto parent=taskStartTime(pid);
        if (!parent) return std::unexpected(parent.error());
        if (*parent!=*birth) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (actual && *actual==*member && !exiting && state!='Z' && state!='X' && state!='x') return static_cast<pid_t>(candidate);
    }
    return std::unexpected(std::make_error_code(std::errc::no_such_process));
}

std::expected<TargetProcessIdentity,std::error_code> processMemoryIdentity(pid_t pid) {
    auto birth=taskStartTime(pid);
    if (!birth) return std::unexpected(birth.error());
    auto task=processMemoryTask(pid);
    if (!task) return std::unexpected(task.error());
    auto identity=targetProcessIdentity(*task);
    if (!identity) return std::unexpected(identity.error());
    if (*task!=pid) {
        char path[128];
        std::snprintf(path,sizeof(path),"/proc/%ld/task/%ld/stat",static_cast<long>(pid),static_cast<long>(*task));
        auto member=readTaskBirth(path);
        if (!member || *member!=identity->startTime)
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    auto actual=taskStartTime(pid);
    if (!actual) return std::unexpected(actual.error());
    if (*actual!=*birth) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    identity->pid=pid; identity->startTime=*birth;
    return *identity;
}

std::expected<TargetProcessIdentity, std::error_code> targetProcessIdentity(pid_t pid) {
    auto birth=taskStartTime(pid);
    if (!birth) return std::unexpected(birth.error());
    char path[64];
    std::snprintf(path,sizeof(path),"/proc/%ld/exe",static_cast<long>(pid));
    struct stat executable{};
    const int read=stat(path,&executable);
    const auto imageError=read ? currentError() : std::error_code{};
    // Do not combine an old task birth with a replacement task's executable.
    auto actual=taskStartTime(pid);
    if (!actual) return std::unexpected(actual.error());
    if (*actual!=*birth) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    if (imageError) {
        // Missing /proc/pid/exe is not proof of task exit. The task is still
        // present, so callers must retain owned recovery rather than retire it.
        if (imageError==std::errc::no_such_file_or_directory || imageError==std::errc::no_such_process)
            return std::unexpected(std::make_error_code(std::errc::resource_unavailable_try_again));
        return std::unexpected(imageError);
    }
    return TargetProcessIdentity{pid,*birth,static_cast<uint64_t>(executable.st_dev),static_cast<uint64_t>(executable.st_ino)};
}

std::expected<TargetSyscallPlan, std::error_code> targetSyscallPlan(
    const TargetMachine& machine, InstructionMode mode, MemorySyscall operation,
    std::array<uint64_t, 6> arguments) {
    TargetSyscallPlan plan;
    plan.arguments = arguments;
    bool linuxX86 = machine.abi == TargetAbi::LinuxI386 || machine.abi == TargetAbi::LinuxX86_64 ||
                    machine.abi == TargetAbi::LinuxX32;
    if (mode == InstructionMode::X86_32 && machine.isX86() && linuxX86) {
        plan.number = operation == MemorySyscall::Map ? 192 : operation == MemorySyscall::Unmap ? 91 : 125;
        plan.instruction = {0xcd, 0x80}; plan.resultWidth = 4;
    } else if (mode == InstructionMode::X86_64 && machine.architecture == CpuArchitecture::X86_64 &&
               (machine.abi == TargetAbi::LinuxX86_64 || machine.abi == TargetAbi::LinuxX32)) {
        plan.number = operation == MemorySyscall::Map ? 9 : operation == MemorySyscall::Unmap ? 11 : 10;
        if (machine.abi == TargetAbi::LinuxX32) plan.number |= 0x40000000;
        plan.instruction = {0x0f, 0x05}; plan.resultWidth = 8;
    } else if (mode == InstructionMode::Aarch64 && machine.architecture == CpuArchitecture::Arm64 &&
               machine.abi == TargetAbi::LinuxAarch64) {
        plan.number = operation == MemorySyscall::Map ? 222 : operation == MemorySyscall::Unmap ? 215 : 226;
        plan.instruction = {0x01, 0x00, 0x00, 0xd4}; plan.resultWidth = 8;
    } else if ((mode == InstructionMode::Arm || mode == InstructionMode::Thumb) &&
               ((machine.abi == TargetAbi::LinuxArmEabi && machine.architecture == CpuArchitecture::Arm32) ||
                (machine.abi == TargetAbi::LinuxAarch64 && machine.architecture == CpuArchitecture::Arm64))) {
        plan.number = operation == MemorySyscall::Map ? 192 : operation == MemorySyscall::Unmap ? 91 : 125;
        plan.instruction = mode == InstructionMode::Thumb ? std::vector<uint8_t>{0x00, 0xdf}
                                                        : std::vector<uint8_t>{0x00, 0x00, 0x00, 0xef};
        if (machine.instructionByteOrder == ByteOrder::Big) std::reverse(plan.instruction.begin(), plan.instruction.end());
        else if (machine.instructionByteOrder == ByteOrder::Unknown) return unsupported();
        plan.resultWidth = 4;
    } else return unsupported();
    if (plan.resultWidth == 4 || machine.abi == TargetAbi::LinuxX32) {
        // mmap's fd=-1 is a signed sentinel; other pointer/size values must fit.
        for (size_t i = 0; i < plan.arguments.size(); ++i) {
            // x32 uses the common 64-bit mmap syscall: its file offset is
            // 64-bit even though addresses and lengths have four-byte types.
            if (machine.abi==TargetAbi::LinuxX32 && plan.resultWidth==8 &&
                operation==MemorySyscall::Map && i==5) continue;
            if (plan.arguments[i] > UINT32_MAX && !(operation == MemorySyscall::Map && i == 4 && plan.arguments[i] == UINT64_MAX))
                return std::unexpected(invalid());
            plan.arguments[i] = static_cast<uint32_t>(plan.arguments[i]);
        }
    }
    return plan;
}

namespace {
#if defined(__x86_64__)
using Registers = user_regs_struct;
std::expected<Registers, std::error_code> getRegisters(pid_t tid) {
    Registers r{};
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) < 0) return std::unexpected(currentError());
    return r;
}
bool setRegisters(pid_t tid, const Registers& r) { return ptrace(PTRACE_SETREGS, tid, nullptr, &r) == 0; }
uintptr_t pc(const Registers& r) { return r.rip; }
void setPc(Registers& r,uintptr_t address) { r.rip=address; }
InstructionMode mode(const Registers& r) { return (r.cs & 0xff) == 0x23 ? InstructionMode::X86_32 : InstructionMode::X86_64; }
void prepare(Registers& r, const TargetSyscallPlan& plan) {
    r.orig_rax = -1; r.rax = plan.number;
    const auto& a = plan.arguments;
    if (mode(r) == InstructionMode::X86_32) { r.rbx=a[0]; r.rcx=a[1]; r.rdx=a[2]; r.rsi=a[3]; r.rdi=a[4]; r.rbp=a[5]; }
    else { r.rdi=a[0]; r.rsi=a[1]; r.rdx=a[2]; r.r10=a[3]; r.r8=a[4]; r.r9=a[5]; }
}
uint64_t result(const Registers& r) { return r.rax; }
#elif defined(__aarch64__) || defined(__arm__)
#if defined(__aarch64__)
struct Registers : user_pt_regs {
    std::array<uint32_t,18> arm{};
    bool compat=false;
};
#else
struct Registers {
    std::array<uint32_t,18> arm{};
    bool compat=true;
};
#endif
std::expected<Registers, std::error_code> getRegisters(pid_t tid) {
    Registers r{};
#if defined(__aarch64__)
    iovec io{static_cast<user_pt_regs*>(&r),sizeof(user_pt_regs)};
#else
    std::array<uint64_t,34> maximum{};
    iovec io{maximum.data(),sizeof(maximum)};
#endif
    if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(NT_PRSTATUS),&io)<0)
        return std::unexpected(currentError());
    if (io.iov_len==sizeof(r.arm)) {
#if defined(__aarch64__)
        std::memcpy(r.arm.data(),static_cast<user_pt_regs*>(&r),sizeof(r.arm));
        *static_cast<user_pt_regs*>(&r)={};
#else
        std::memcpy(r.arm.data(),maximum.data(),sizeof(r.arm));
#endif
        r.compat=true;
        return r;
    }
#if defined(__aarch64__)
    if (io.iov_len==sizeof(user_pt_regs)) return r;
#endif
    return unsupported();
}
bool setRegisters(pid_t tid,const Registers& r) {
    iovec io{const_cast<uint32_t*>(r.arm.data()),sizeof(r.arm)};
#if defined(__aarch64__)
    if (!r.compat) io={const_cast<user_pt_regs*>(static_cast<const user_pt_regs*>(&r)),sizeof(user_pt_regs)};
#endif
    return ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(NT_PRSTATUS),&io)==0;
}
uintptr_t pc(const Registers& r) {
#if defined(__aarch64__)
    if (!r.compat) return r.pc;
#endif
    return r.arm[15];
}
void setPc(Registers& r,uintptr_t address) {
#if defined(__aarch64__)
    if (!r.compat) { r.pc=address; return; }
#endif
    r.arm[15]=address;
}
InstructionMode mode(const Registers& r) {
    return r.compat ? (r.arm[16]&0x20 ? InstructionMode::Thumb : InstructionMode::Arm) : InstructionMode::Aarch64;
}
void prepare(Registers& r,const TargetSyscallPlan& plan) {
    if (r.compat) {
        std::copy(plan.arguments.begin(),plan.arguments.end(),r.arm.begin());
        r.arm[7]=plan.number; r.arm[17]=UINT32_MAX;
        r.arm[16]&=~uint32_t(0x0600fc00); // Execute outside the original Thumb IT block.
        return;
    }
#if defined(__aarch64__)
    for (size_t i=0;i<plan.arguments.size();++i) r.regs[i]=plan.arguments[i];
    r.regs[8]=plan.number;
#endif
}
uint64_t result(const Registers& r) {
#if defined(__aarch64__)
    if (!r.compat) return r.regs[0];
#endif
    return r.arm[0];
}
bool equalRegisters(const Registers& a,const Registers& b) {
    if (a.compat!=b.compat) return false;
    if (a.compat) return a.arm==b.arm;
#if defined(__aarch64__)
    return std::memcmp(static_cast<const user_pt_regs*>(&a),static_cast<const user_pt_regs*>(&b),sizeof(user_pt_regs))==0;
#else
    return false;
#endif
}

#endif

#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
struct SavedWord { uintptr_t address; long original, replacement; unsigned long mask = 0; };
// Return the last byte needed by the saved instruction only when it might cross
// a page. Read aligned ptrace words and retain a partial x86 window if the next
// page is already absent; a short valid instruction must remain usable there.
std::expected<uintptr_t,std::error_code> returnInstructionLastByte(pid_t tid,const Registers& saved,uintptr_t page) {
    const uintptr_t at=pc(saved),remaining=page-at%page;
    const auto instructionMode=mode(saved);
    const size_t maximum=(instructionMode==InstructionMode::X86_32 || instructionMode==InstructionMode::X86_64) ? 15 : 4;
    if (remaining>=maximum) return at;
    std::array<uint8_t,15> bytes{};size_t count=0;
    while (count<maximum && at<=UINTPTR_MAX-count) {
        const uintptr_t address=at+count,aligned=address-address%sizeof(long);
        errno=0;const long word=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(aligned),nullptr);
        if (word==-1 && errno) {
            if (!count) return std::unexpected(currentError());
            break;
        }
        const size_t offset=address-aligned,size=std::min(maximum-count,sizeof(long)-offset);
        std::memcpy(bytes.data()+count,reinterpret_cast<const uint8_t*>(&word)+offset,size);
        count+=size;
    }
    size_t length=4;
    if (instructionMode==InstructionMode::Thumb) {
        if (count<2) return unsupported();
        const uint16_t prefix=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
        length=prefix>=0xe800 ? 4 : 2;
    }
#if defined(__x86_64__)
    else if (instructionMode==InstructionMode::X86_32 || instructionMode==InstructionMode::X86_64) {
        Disassembler decoder(instructionMode==InstructionMode::X86_32 ? Arch::X86_32 : Arch::X86_64);
        auto instruction=decoder.disassembleOne(at,{bytes.data(),count});
        if (!instruction || !instruction->size) return unsupported();
        length=instruction->size;
    }
#endif
    if (length-1>UINTPTR_MAX-at) return std::unexpected(invalid());
    return at+length-1;
}
pid_t waitStopped(pid_t tid, int& status) {
    pid_t waited;
    do { waited = waitpid(tid, &status, __WALL); } while (waited < 0 && errno == EINTR);
    return waited;
}

std::expected<uintptr_t,std::error_code> existingSyscallInstruction(
    pid_t tid,int memoryFd,const TargetSyscallPlan& plan,InstructionMode instructionMode,
    MemorySyscall operation,const std::array<uint64_t,6>& arguments) {
    std::ifstream maps("/proc/"+std::to_string(tid)+"/maps");
    if (!maps) return std::unexpected(errno ? currentError() : std::make_error_code(std::errc::io_error));
    auto nativePageSize=sysconf(_SC_PAGESIZE);
    if (nativePageSize<=0) return std::unexpected(invalid());
    auto pageSize=static_cast<uintptr_t>(nativePageSize);
    // Linux exports the normalized always-native range, including the
    // wraparound complement used for inclusive dispatch. Never alter either
    // the dispatch configuration or the target's selector byte.
    struct { uint64_t mode=0,selector=0,offset=0,length=0; } dispatch;
    auto dispatchRead=ptrace(static_cast<enum __ptrace_request>(0x4211),tid,
        reinterpret_cast<void*>(sizeof(dispatch)),&dispatch);
    if (dispatchRead<0 && errno!=EIO && errno!=EINVAL && errno!=ENOSYS)
        return std::unexpected(currentError());
    if (dispatchRead<0) dispatch={}; // Older kernels do not expose this request.
    if (dispatch.mode>1) return unsupported();
    bool selectorAllows=false;
    if (dispatch.mode && dispatch.selector) {
        uint8_t selector=1;
        ssize_t read;
        do { read=pread(memoryFd,&selector,sizeof(selector),static_cast<off_t>(dispatch.selector)); }
        while (read<0 && errno==EINTR);
        selectorAllows=read==sizeof(selector) && selector==0;
    }
    std::optional<uintptr_t> selectorCandidate;
    std::array<uint8_t,65536> bytes{};
    std::map<std::tuple<unsigned,unsigned,unsigned long long>,TargetMachine> modules;
    std::string line;
    while (std::getline(maps,line)) {
        unsigned long long start=0,end=0;
        unsigned long long offset=0,inode=0;
        unsigned major=0,minor=0;
        char permissions[5]{};
        if (std::sscanf(line.c_str(),"%llx-%llx %4s %llx %x:%x %llu",&start,&end,permissions,&offset,&major,&minor,&inode)!=7 ||
            start>=end || end>UINTPTR_MAX) continue;
        auto key=std::make_tuple(major,minor,inode);
        std::optional<TargetMachine> module;
        if (!offset) {
            std::array<uint8_t,64> header{};
            ssize_t read;
            do { read=pread(memoryFd,header.data(),header.size(),static_cast<off_t>(start)); } while (read<0 && errno==EINTR);
            if (read>0) {
                auto parsed=parseElfTarget({header.data(),static_cast<size_t>(read)});
                if (parsed) {
                    module=*parsed;
                    if (inode) modules.insert_or_assign(key,*parsed);
                }
            }
        } else if (inode) {
            auto found=modules.find(key);
            if (found!=modules.end()) module=found->second;
        }
        // Wine's PE mappings can contain Windows syscall opcodes interpreted
        // by its dispatcher. Use verified Unix ELF code of the execution ISA.
        if (!module || module->instructionMode!=instructionMode ||
            permissions[2]!='x' || permissions[1]=='w') continue;
        if (instructionMode==InstructionMode::X86_32) {
            if (start>UINT32_MAX) continue;
            end=std::min<unsigned long long>(end,UINT64_C(0x100000000));
        }
        for (uintptr_t at=static_cast<uintptr_t>(start);at<end;) {
            auto size=static_cast<size_t>(std::min<uint64_t>(bytes.size(),end-at));
            ssize_t read;
            do { read=pread(memoryFd,bytes.data(),size,static_cast<off_t>(at)); } while (read<0 && errno==EINTR);
            if (read<=0) break;
            auto limit=bytes.begin()+read;
            auto found=bytes.begin();
            while ((found=std::search(found,limit,plan.instruction.begin(),plan.instruction.end()))!=limit) {
                uintptr_t address=at+static_cast<uintptr_t>(found-bytes.begin());
                bool aligned=instructionMode!=InstructionMode::Aarch64 || address%4==0;
                bool destructive=operation==MemorySyscall::Unmap ||
                    (operation==MemorySyscall::Protect && !(arguments[2]&PROT_EXEC)) ||
                    (operation==MemorySyscall::Map && (arguments[3]&MAP_FIXED));
                uintptr_t firstPage=address-address%pageSize;
                uintptr_t last=address+plan.instruction.size()-1;
                uintptr_t lastPage=last-last%pageSize;
                bool affected=destructive && arguments[1] &&
                    firstPage<arguments[0]+arguments[1] &&
                    (lastPage>UINTPTR_MAX-pageSize || lastPage+pageSize>arguments[0]);
                if (aligned && !affected) {
                    // Dispatch compares the PC after the syscall instruction.
                    // Prefer a permanently native site even if the selector
                    // presently allows syscalls from other sites.
                    uint64_t postPc=address+plan.instruction.size();
                    if (!dispatch.mode || postPc-dispatch.offset<dispatch.length) return address;
                    if (selectorAllows && !selectorCandidate) selectorCandidate=address;
                }
                ++found;
            }
            if (static_cast<uint64_t>(read)==end-at) break;
            // Retain enough overlap to find an x86 opcode spanning read chunks.
            if (static_cast<size_t>(read)<plan.instruction.size()) break;
            at+=static_cast<uintptr_t>(read)-plan.instruction.size()+1;
        }
    }
    if (selectorCandidate) return *selectorCandidate;
    return unsupported();
}
#endif
}

struct TargetSyscallRecovery::State {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    pid_t tid = 0, owner = 0;
    pid_t groupLeader=0;
    uint64_t groupBirth=0;
    std::optional<TargetTaskIdentity> replacementTask;
    std::optional<int> groupExecStatus;
    Registers original{};
    NativeExtendedContext extended;
    std::vector<SavedWord> words;
    bool registersChanged = false, done = false, retired = false;
    bool seized = false, stopped = false, prepared = false;
    bool detach = true;
    int pendingSignal = 0;
    std::optional<siginfo_t> pendingSignalInfo;
    bool pendingStepTrap=false;
    uintptr_t stepEnd=0;
    uint64_t executableDevice = 0, executableInode = 0;
    uint64_t startTime = 0;
    int memoryFd = -1;
    std::shared_ptr<NativeMemoryImage> affinityImage;
    TargetMachine affinityHost;
    uintptr_t affinityAddress=0;
    size_t affinitySize=0;
    std::shared_ptr<TargetSyscallRecovery> affinityRecovery;
    Result<void> cleanupAffinity();
    void rememberAffinitySignal(const TargetSyscallFailure&);
    bool maskSaved=false;
    uint64_t originalMask=0;
    struct Function {
        uintptr_t trap=0,stack=0;
        bool started=false,running=false,interruptRequested=false,returned=false,awaitingSignal=false,compat=false;
        bool drainingInterrupt=false;
        int signal=0,waitMilliseconds=100;
        unsigned event=0;
        std::optional<int> stopStatus;
        std::optional<siginfo_t> info;
        std::optional<uint64_t> value;
    };
    std::optional<Function> function;
    Result<void> progressFunction(pid_t notified,int status);
    Result<pid_t> pollFunction(int& status);
    Result<int> seizeStopped(const TargetProcessIdentity& expected);
    ~State() { if (memoryFd >= 0) close(memoryFd); }
    void rememberStop(int status) {
        stopped=true;
        if ((status>>16)==0) {
            pendingSignal=WSTOPSIG(status);
            siginfo_t info{};
            if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0) pendingSignalInfo=info;
        }
    }
#if defined(__aarch64__)
    int oldSyscall = -1;
    bool syscallChanged = false;
    std::optional<Arm64VectorReturn> vectorReturn;
#endif
#endif
};

#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
Result<int> TargetSyscallRecovery::State::seizeStopped(const TargetProcessIdentity& expected) {
    if (ptrace(PTRACE_SEIZE,tid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACEEXEC)) < 0)
        return std::unexpected(currentError());
    seized = true;
    // Until binding succeeds, cleanup must release the task actually seized,
    // even if the requested numeric TID was reused before SEIZE.
    startTime = 0;
    auto birth = taskStartTime(tid);
    if (!birth) return std::unexpected(birth.error());
    startTime = *birth;
    auto actual = targetProcessIdentity(tid);
    if (!actual) return std::unexpected(actual.error());
    if (*actual != expected) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    if (ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr) < 0) {
        auto error = currentError();
        if (error == std::errc::no_such_process) done = true;
        return std::unexpected(error);
    }
    int status = 0;
    if (waitStopped(tid,status) != tid) return std::unexpected(currentError());
    if (!WIFSTOPPED(status)) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) done = true;
        return std::unexpected(std::make_error_code(std::errc::no_such_process));
    }
    rememberStop(status);
    if ((status >> 16) != PTRACE_EVENT_STOP || WSTOPSIG(status) != SIGTRAP)
        return std::unexpected(std::make_error_code(std::errc::interrupted));
    actual = targetProcessIdentity(tid);
    if (!actual) return std::unexpected(actual.error());
    if (*actual != expected) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    return status;
}

Result<void> TargetSyscallRecovery::State::progressFunction(pid_t notified,int status) {
#if defined(__arm__)
    (void)notified; (void)status; return unsupported();
#else
    auto& call=*function;
    if (!call.started || call.returned) return {};
    if (call.awaitingSignal) return std::unexpected(std::make_error_code(std::errc::interrupted));
    auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(call.waitMilliseconds);
    bool interruptDeadline=false;
    for (;;) {
        if (notified==tid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                done=true;
                return std::unexpected(std::make_error_code(std::errc::no_such_process));
            }
            if (!WIFSTOPPED(status)) return std::unexpected(std::make_error_code(std::errc::state_not_recoverable));
            call.stopStatus=status;
        }
        if (call.stopStatus) {
            status=*call.stopStatus;
            call.running=false; stopped=true;
            if ((status>>16)==PTRACE_EVENT_EXEC) {
                call.event=PTRACE_EVENT_EXEC;
                replacementTask=TargetTaskIdentity{tid,startTime};
                retired=true;
                done=true;
                return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            }
            if ((status>>16)==0) {
                siginfo_t info{};
                if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)<0) return std::unexpected(currentError());
                auto actual=getRegisters(tid);
                if (!actual) return std::unexpected(actual.error());
#if defined(__x86_64__)
                bool atTrap=(pc(*actual)==call.trap+1 || (call.value && call.interruptRequested && pc(*actual)==call.trap)) && actual->rsp==call.stack;
                bool ownSignal=info.si_code==TRAP_BRKPT || info.si_code==SI_KERNEL;
#else
                bool atTrap=pc(*actual)==call.trap && actual->sp==call.stack;
                bool ownSignal=info.si_code==TRAP_BRKPT && reinterpret_cast<uintptr_t>(info.si_addr)==call.trap;
#endif
                errno=0;
                uintptr_t aligned=call.trap&~uintptr_t(sizeof(long)-1);
                long instruction=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(aligned),nullptr);
                if (instruction==-1 && errno) return std::unexpected(currentError());
                bool opcode=true;
#if defined(__x86_64__)
                opcode=opcode && reinterpret_cast<const uint8_t*>(&instruction)[call.trap-aligned]==0xcc;
#else
                uint32_t brk=0;
                std::memcpy(&brk,reinterpret_cast<const uint8_t*>(&instruction)+call.trap-aligned,4);
                opcode=opcode && brk==0xd4200000;
#endif
                if (WSTOPSIG(status)==SIGTRAP && info.si_signo==SIGTRAP && atTrap && ownSignal && opcode) {
                    if (!call.value) call.value=call.compat ? static_cast<uint32_t>(result(*actual)) : result(*actual);
                    if (call.interruptRequested && !call.drainingInterrupt) {
                        // INTERRUPT can race an already queued return trap.
                        // Drain its job-control notification in private code
                        // before handing the original stop back to the caller.
                        // Repeating only the return trap also proves that no
                        // interrupt remains queued if the kernel coalesced it.
#if defined(__x86_64__)
                        setPc(*actual,call.trap);
                        if (!setRegisters(tid,*actual)) return std::unexpected(currentError());
                        auto rewound=getRegisters(tid);
                        if (!rewound) return std::unexpected(rewound.error());
                        if (pc(*rewound)!=call.trap || rewound->rsp!=call.stack)
                            return std::unexpected(std::make_error_code(std::errc::state_not_recoverable));
#endif
                        call.drainingInterrupt=true;
                        call.stopStatus.reset();
                        notified=0;
                        deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
                        interruptDeadline=true;
                        continue;
                    }
                    call.interruptRequested=false;
                    call.returned=true;
                    call.stopStatus.reset();
                    return {};
                }
                call.signal=WSTOPSIG(status); call.info=info; call.awaitingSignal=true;
                call.stopStatus.reset();
                return std::unexpected(std::make_error_code(std::errc::interrupted));
            }
            unsigned event=static_cast<unsigned>(status>>16);
            bool ownInterrupt=event==PTRACE_EVENT_STOP && WSTOPSIG(status)==SIGTRAP && call.interruptRequested;
            call.stopStatus.reset();
            if (!ownInterrupt) {
                call.event=event; call.awaitingSignal=true;
                return std::unexpected(std::make_error_code(std::errc::interrupted));
            }
            call.interruptRequested=false;
            if (call.drainingInterrupt) { call.returned=true; return {}; }
            if (interruptDeadline) return std::unexpected(std::make_error_code(std::errc::timed_out));
        }
        if (!call.running) {
            // A stopped callee may have executed an exec even when the caller
            // did not request TRACEEXEC. Never resume the private frame in a
            // replacement image, including a same-file exec.
            auto identity=targetProcessIdentity(tid);
            if (!identity) return std::unexpected(identity.error());
            uint8_t byte=0;
            auto read=pread(memoryFd,&byte,1,static_cast<off_t>(pc(original)));
            if (identity->startTime!=startTime || identity->executableDevice!=static_cast<uint64_t>(executableDevice) ||
                identity->executableInode!=static_cast<uint64_t>(executableInode) || read==0) {
                retired=true;
                done=true;
                return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            }
            if (read<0 && errno!=EIO && errno!=EFAULT) return std::unexpected(currentError());
            if (call.info && call.signal && ptrace(PTRACE_SETSIGINFO,tid,nullptr,&*call.info)<0)
                return std::unexpected(currentError());
            if (ptrace(PTRACE_CONT,tid,nullptr,reinterpret_cast<void*>(static_cast<intptr_t>(call.signal)))<0)
                return std::unexpected(currentError());
            call.running=true; stopped=false; call.signal=0; call.info.reset();
        }
        auto polled=pollFunction(status);
        if (!polled) return std::unexpected(polled.error());
        notified=*polled;
        if (notified==tid) continue;
        if (std::chrono::steady_clock::now()>=deadline) {
            if (interruptDeadline || call.interruptRequested)
                return std::unexpected(std::make_error_code(std::errc::timed_out));
            if (ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr)<0) return std::unexpected(currentError());
            call.interruptRequested=true; interruptDeadline=true;
            // Even an uninterruptible kernel wait must not hang the owner.
            deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
        }
        usleep(1000);
    }
#endif
}
Result<pid_t> TargetSyscallRecovery::State::pollFunction(int& status) {
    auto adoptExec=[&]() -> Result<pid_t> {
        unsigned long former=0;
        if (ptrace(PTRACE_GETEVENTMSG,groupLeader,nullptr,&former)<0) {
            auto error=currentError();
            // ESRCH can mean the consumed EXEC stop is not yet inspectable.
            // It cannot prove the old selected TID's whole process is gone.
            if (error==std::errc::no_such_process)
                error=std::make_error_code(std::errc::resource_unavailable_try_again);
            return std::unexpected(error);
        }
        auto birth=taskStartTime(groupLeader);
        if (!birth) return std::unexpected(birth.error());
        if (*birth!=groupBirth) return std::unexpected(std::make_error_code(std::errc::no_such_process));
        // Any exec in this original group retires the saved callee context.
        // In the callee-exec case GETEVENTMSG names exactly the original tid;
        // a sibling exec destroys it instead. Both release this actual stop.
        tid=groupLeader;startTime=*birth;status=*groupExecStatus;
        groupExecStatus.reset();stopped=true;retired=true;
        replacementTask=TargetTaskIdentity{tid,startTime};
        function->event=PTRACE_EVENT_EXEC;
        return tid;
    };
    if (groupExecStatus) return adoptExec();
    pid_t notified;
    do { notified=waitpid(tid,&status,__WALL|__WNOTHREAD|WNOHANG); } while (notified<0 && errno==EINTR);
    auto error=notified<0 ? currentError() : std::error_code{};
    if (function && groupLeader!=tid && notified==groupLeader &&
        WIFSTOPPED(status) && (status>>16)==PTRACE_EVENT_EXEC) {
        groupExecStatus=status;
        return adoptExec();
    }
    if (notified>0 || !function || !groupLeader || groupLeader==tid)
        return notified<0 ? Result<pid_t>(std::unexpected(error)) : Result<pid_t>(notified);

    // Peek only the original group leader, leaving other child/debugger stops
    // queued. Linux rejects ptrace inspection of a changed TID until the EXEC
    // notification has been consumed, so retain that actual status before
    // inspecting GETEVENTMSG; failed inspection must never replay old context.
    siginfo_t event{};
    int peek;
    do { peek=waitid(P_PID,groupLeader,&event,__WALL|__WNOTHREAD|WSTOPPED|WNOHANG|WNOWAIT); }
    while (peek<0 && errno==EINTR);
    if (peek==0 && event.si_pid==groupLeader && event.si_code==CLD_TRAPPED &&
        event.si_status==(SIGTRAP|(PTRACE_EVENT_EXEC<<8))) {
        auto birth=taskStartTime(groupLeader);
        if (!birth) return std::unexpected(birth.error());
        if (*birth==groupBirth) {
            do { notified=waitpid(groupLeader,&status,__WALL|__WNOTHREAD|WNOHANG); } while (notified<0 && errno==EINTR);
            if (notified<0) return std::unexpected(currentError());
            if (notified==groupLeader && WIFSTOPPED(status) && (status>>16)==PTRACE_EVENT_EXEC) {
                groupExecStatus=status;
                return adoptExec();
            }
            return std::unexpected(std::make_error_code(std::errc::state_not_recoverable));
        }
    }
    if (error==std::errc::no_child_process) {
        auto birth=taskStartTime(groupLeader);
        if (birth && *birth==groupBirth) return 0;
    }
    return error ? Result<pid_t>(std::unexpected(error)) : Result<pid_t>(0);
}
#endif

std::optional<uint64_t> TargetSyscallRecovery::functionResult() const {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    return state_->function ? state_->function->value : std::nullopt;
#else
    return std::nullopt;
#endif
}
bool TargetSyscallRecovery::imageRetired() const {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    return state_->retired;
#else
    return false;
#endif
}
std::optional<TargetTaskIdentity> TargetSyscallRecovery::replacementTask() const {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    return state_->replacementTask;
#else
    return std::nullopt;
#endif
}
Result<void> TargetSyscallRecovery::resumeFunction(bool deliverSignal) {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    if (syscall(SYS_gettid)!=state_->owner) return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
    if (state_->retired) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    if (!state_->function || !state_->function->awaitingSignal) return std::unexpected(invalid());
    if (state_->function->event && deliverSignal) return std::unexpected(invalid());
    if (!deliverSignal) { state_->function->signal=0; state_->function->info.reset(); }
    state_->function->event=0;
    state_->function->awaitingSignal=false;
    return retry();
#else
    return unsupported();
#endif
}

std::expected<void, std::error_code> TargetSyscallRecovery::checkImage() const {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    if (state_->retired || state_->groupExecStatus) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    uint8_t byte = 0;
    ssize_t read = pread(state_->memoryFd, &byte, 1, static_cast<off_t>(pc(state_->original)));
    if (read == 0) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    // An unmapped sample gives EIO while the old mm remains live. A dead mm
    // returns zero before memory access, regardless of the sample address.
    if (read < 0 && errno != EIO && errno != EFAULT) return std::unexpected(currentError());
    return {};
#else
    return unsupported();
#endif
}

#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
void TargetSyscallRecovery::State::rememberAffinitySignal(const TargetSyscallFailure& failure) {
    if (!failure.pendingSignal) return;
    pendingSignal=failure.pendingSignal;
    if (failure.recovery && failure.recovery->state_->pendingSignalInfo) {
        pendingSignalInfo=failure.recovery->state_->pendingSignalInfo;
    } else {
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0 && info.si_signo==pendingSignal)
            pendingSignalInfo=info;
    }
}
Result<void> TargetSyscallRecovery::State::cleanupAffinity() {
    // The nested syscall owns the currently borrowed context. Drain it before
    // this outer owner consumes events or releases its ptrace relationship.
    if (affinityRecovery) {
        auto restored=affinityRecovery->retry();
        if (affinityRecovery->state_->pendingSignal) {
            pendingSignal=affinityRecovery->state_->pendingSignal;
            pendingSignalInfo=affinityRecovery->state_->pendingSignalInfo;
        }
        if (!restored) return restored;
        affinityRecovery.reset();
    }
    if (!affinityAddress) return {};
    char status=0;bool exiting=false;
    auto birth=taskStartTime(tid,&status,&exiting);
    if ((!birth && (birth.error()==std::errc::no_such_process || birth.error()==std::errc::no_such_file_or_directory)) ||
        (birth && ((startTime && *birth!=startTime) || exiting || status=='Z' || status=='X' || status=='x'))) {
        affinityAddress=0;
        affinityImage.reset();
        done=true;
        return std::unexpected(std::make_error_code(std::errc::no_such_process));
    }
    if (!birth) return std::unexpected(birth.error());
    auto identity=processMemoryIdentity(tid);
    if (!identity) return std::unexpected(identity.error());
    auto current=NativeMemoryImage::capture(*identity,affinityHost);
    if (!current) return std::unexpected(current.error());
    auto same=(*current)->sharesPrivateMapping(*affinityImage,affinityAddress);
    if (!same) {
        if (same.error()==std::errc::operation_canceled) {
            // A replacement must never unmap the old private page. Its original
            // mm still owns it until its remaining users exit.
            affinityAddress=0;
            affinityImage.reset();
        }
        return same;
    }
    auto released=executeOwnedMemorySyscall(tid,affinityHost,MemorySyscall::Unmap,
        {affinityAddress,affinitySize,0,0,0,0});
    if (!released) {
        rememberAffinitySignal(released.error());
        affinityRecovery=released.error().recovery;
        if (released.error().completedValue) affinityAddress=0;
        return std::unexpected(released.error().code);
    }
    affinityAddress=0;
    affinityImage.reset();
    return {};
}
#endif

std::expected<void, std::error_code> TargetSyscallRecovery::retry() {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    auto& state = *state_;
    if (state.done) return {};
    if (syscall(SYS_gettid) != state.owner)
        return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
    if (!state.retired) {
        auto affinity=state.cleanupAffinity();
        if (!affinity) return affinity;
    }
    int observed = 0;
    pid_t notified;
    if (state.function) {
        auto polled=state.pollFunction(observed);
        if (!polled) return std::unexpected(polled.error());
        notified=*polled;
    } else {
        do { notified = waitpid(state.tid, &observed, __WALL | __WNOTHREAD | WNOHANG); } while (notified < 0 && errno == EINTR);
    }
    if (notified == state.tid && (WIFEXITED(observed) || WIFSIGNALED(observed))) {
        state.done = true;
        return std::unexpected(std::make_error_code(std::errc::no_such_process));
    }
    auto birth=taskStartTime(state.tid);
    if (!birth) {
        if (birth.error()==std::errc::no_such_process || birth.error()==std::errc::no_such_file_or_directory) {
            if (state.function && state.function->running && state.groupLeader!=state.tid)
                return state.progressFunction(notified,observed);
            state.done=true;
            return std::unexpected(std::make_error_code(std::errc::no_such_process));
        }
        return std::unexpected(birth.error());
    }
    if (state.startTime && *birth!=state.startTime) {
        state.done=true;
        return std::unexpected(std::make_error_code(std::errc::no_such_process));
    }
    if (!state.startTime) state.startTime=*birth;
    if (state.retired) {
        // The actual EXEC stop belongs to the replacement. Failed detach must
        // remain retryable without replaying any context from the old image.
        if (state.detach && ptrace(PTRACE_DETACH,state.tid,nullptr,nullptr)<0)
            return std::unexpected(currentError());
        state.done=true;
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    if (!state.prepared) {
        // No target bytes or registers have changed yet. A failed interrupt
        // can leave a seized task running; obtain a real stop before detach.
        // Never replay the default/unfinished register snapshot on this path.
        if (notified==state.tid && WIFSTOPPED(observed)) state.rememberStop(observed);
        if (!state.stopped) {
            if (ptrace(PTRACE_INTERRUPT,state.tid,nullptr,nullptr)<0) {
                auto error=currentError();
                if (error==std::errc::no_such_process) state.done=true;
                return std::unexpected(error);
            }
            if (waitStopped(state.tid,observed)!=state.tid) return std::unexpected(currentError());
            if (!WIFSTOPPED(observed)) {
                state.done=true;
                return std::unexpected(std::make_error_code(std::errc::no_such_process));
            }
            state.rememberStop(observed);
        }
        if (state.pendingSignal && state.pendingSignalInfo &&
            ptrace(PTRACE_SETSIGINFO,state.tid,nullptr,&*state.pendingSignalInfo)<0) return std::unexpected(currentError());
        if (state.detach && ptrace(PTRACE_DETACH,state.tid,nullptr,
            reinterpret_cast<void*>(static_cast<intptr_t>(state.pendingSignal)))<0) return std::unexpected(currentError());
        state.done=true;
        return {};
    }
    if (notified == state.tid && WIFSTOPPED(observed) && (observed >> 16) == PTRACE_EVENT_EXEC) {
        state.retired=true;
        state.stopped=true;
        if (state.function) state.function->event=PTRACE_EVENT_EXEC;
        if (state.detach && ptrace(PTRACE_DETACH, state.tid, nullptr, nullptr) < 0) return std::unexpected(currentError());
        state.done = true;
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    struct stat executable{};
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%ld/exe", static_cast<long>(state.tid));
    if (stat(path, &executable) != 0) {
        // The lifetime probe above proved this task still exists. Missing
        // image metadata must keep restoration owned and retryable.
        const auto error=currentError();
        if (error==std::errc::no_such_file_or_directory || error==std::errc::no_such_process)
            return std::unexpected(std::make_error_code(std::errc::resource_unavailable_try_again));
        return std::unexpected(error);
    }
    uint8_t originalByte = 0;
    ssize_t originalImage = pread(state.memoryFd, &originalByte, 1, static_cast<off_t>(pc(state.original)));
    if (executable.st_dev != state.executableDevice || executable.st_ino != state.executableInode || originalImage == 0) {
        if (state.detach && ptrace(PTRACE_DETACH, state.tid, nullptr, nullptr) < 0) return std::unexpected(currentError());
        state.retired=true;
        state.done = true;
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    if (state.function) {
        auto progressed=state.progressFunction(notified,observed);
        if (!progressed) return progressed;
    }
    while (state.pendingStepTrap) {
        auto ownTrap=[&](const siginfo_t& info) {
            return info.si_signo==SIGTRAP &&
                (((info.si_code==TRAP_BRKPT || info.si_code==TRAP_TRACE) &&
                  reinterpret_cast<uintptr_t>(info.si_addr)==state.stepEnd) ||
                 (nativeTargetMachine().architecture==CpuArchitecture::Arm64 && info.si_code==SI_USER &&
                  !info.si_pid && !info.si_uid));
        };
        bool queued=false;
        struct { uint64_t offset; uint32_t flags; int32_t count; } peek{0,0,32};
        std::array<siginfo_t,32> pending{};
        for (;;) {
            auto count=ptrace(PTRACE_PEEKSIGINFO,state.tid,&peek,pending.data());
            if (count<0) return std::unexpected(currentError());
            if (std::any_of(pending.begin(),pending.begin()+count,ownTrap)) { queued=true; break; }
            if (!count) break;
            peek.offset+=static_cast<uint64_t>(count);
        }
        if (!queued) { state.pendingStepTrap=false; break; }
        // A syscall-denial signal can precede the step trap already queued by
        // syscall exit. Consume that owned trap before restoring and detaching;
        // the queued synchronous trap stops us before another user instruction.
        if (ptrace(PTRACE_CONT,state.tid,nullptr,nullptr)<0) return std::unexpected(currentError());
        int status=0;
        if (waitStopped(state.tid,status)!=state.tid || !WIFSTOPPED(status)) {
            state.done=true;
            return std::unexpected(std::make_error_code(std::errc::no_such_process));
        }
        if ((status>>16)==PTRACE_EVENT_EXEC) {
            state.retired=true;
            state.stopped=true;
            if (state.detach && ptrace(PTRACE_DETACH,state.tid,nullptr,nullptr)<0) return std::unexpected(currentError());
            state.done=true;
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        }
        if ((status>>16)!=0) continue;
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO,state.tid,nullptr,&info)<0) return std::unexpected(currentError());
        if (ownTrap(info)) state.pendingStepTrap=false;
        else {
            state.pendingSignal=WSTOPSIG(status);
            state.pendingSignalInfo=info;
        }
    }
    bool restored = true;
    for (auto it = state.words.rbegin(); it != state.words.rend(); ++it) {
        errno = 0;
        long actual = ptrace(PTRACE_PEEKTEXT, state.tid, reinterpret_cast<void*>(it->address), nullptr);
        if (actual == -1 && errno) { restored = false; continue; }
        if ((static_cast<unsigned long>(actual) & it->mask) != (static_cast<unsigned long>(it->original) & it->mask)) {
            unsigned long wanted = (static_cast<unsigned long>(actual) & ~it->mask) |
                                   (static_cast<unsigned long>(it->original) & it->mask);
            ptrace(PTRACE_POKETEXT, state.tid, reinterpret_cast<void*>(it->address), reinterpret_cast<void*>(wanted));
            errno = 0;
            actual = ptrace(PTRACE_PEEKTEXT, state.tid, reinterpret_cast<void*>(it->address), nullptr);
            if ((actual == -1 && errno) || (static_cast<unsigned long>(actual) & it->mask) != (wanted & it->mask)) restored = false;
        }
    }
    if (state.registersChanged) {
        setRegisters(state.tid, state.original);
        auto actual = getRegisters(state.tid);
        Registers expected = state.original;
#if defined(__aarch64__)
        // PSTATE.SS is kernel-owned while ptrace single-step is active.
        expected.pstate &= ~(uint64_t{1} << 21);
        if (actual) actual->pstate &= ~(uint64_t{1} << 21);
#endif
#if defined(__aarch64__) || defined(__arm__)
        if (!actual || !equalRegisters(*actual,expected)) restored=false;
#else
        if (!actual || std::memcmp(&*actual,&expected,sizeof(expected))) restored=false;
#endif
    }
#if defined(__aarch64__)
    if (state.syscallChanged) {
        iovec io{&state.oldSyscall, sizeof(state.oldSyscall)};
        ptrace(PTRACE_SETREGSET, state.tid, reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL), &io);
        int actual = -1; io = {&actual, sizeof(actual)};
        if (ptrace(PTRACE_GETREGSET, state.tid, reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL), &io) < 0 || actual != state.oldSyscall) restored = false;
    }
#endif
    auto extended =
#if defined(__aarch64__)
        state.vectorReturn ? state.vectorReturn->restore(state.tid,state.memoryFd,state.original,state.extended,
            state.pendingSignal,state.pendingSignalInfo,state.pendingStepTrap,state.stepEnd) :
#endif
        restoreNativeExtendedContext(state.tid,state.extended);
    if (!extended)
        restored = false;
    if (state.maskSaved) {
        uint64_t actual=0;
        if (ptrace(PTRACE_GETSIGMASK,state.tid,reinterpret_cast<void*>(sizeof(actual)),&actual)<0) restored=false;
        else if (actual!=state.originalMask) {
            if (ptrace(PTRACE_SETSIGMASK,state.tid,reinterpret_cast<void*>(sizeof(actual)),&state.originalMask)<0 ||
                ptrace(PTRACE_GETSIGMASK,state.tid,reinterpret_cast<void*>(sizeof(actual)),&actual)<0 || actual!=state.originalMask) restored=false;
        }
    }
    if (!restored) return std::unexpected(std::make_error_code(std::errc::state_not_recoverable));
    if (state.pendingSignalInfo && ptrace(PTRACE_SETSIGINFO,state.tid,nullptr,&*state.pendingSignalInfo)<0)
        return std::unexpected(currentError());
    if (state.detach && ptrace(PTRACE_DETACH, state.tid, nullptr, reinterpret_cast<void*>(static_cast<intptr_t>(state.pendingSignal))) < 0)
        return std::unexpected(currentError());
    state.done = true;
    return {};
#else
    return unsupported();
#endif
}

std::expected<uint64_t, TargetSyscallFailure> executeMemorySyscallInternal(
    pid_t tid, const TargetMachine& host, MemorySyscall operation, std::array<uint64_t, 6> arguments,
    const TargetProcessIdentity* expectedIdentity, const TargetSyscallRecovery* expectedImage,
    bool alreadyStopped,uintptr_t scratch,bool existingOnly,const NativeMemoryImage* savedImage,bool checkOnly=false) {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    auto native = nativeTargetMachine();
    if (host.architecture != native.architecture &&
        !(native.architecture == CpuArchitecture::X86_64 && host.architecture == CpuArchitecture::X86_32) &&
        !(native.architecture == CpuArchitecture::Arm64 && host.architecture == CpuArchitecture::Arm32)) return unsupported();
    auto initialIdentity=targetProcessIdentity(tid);
    if (!initialIdentity) return std::unexpected(initialIdentity.error());
    if (expectedIdentity && *initialIdentity!=*expectedIdentity)
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    // Reserve both allocations before SEIZE, not merely before register/code
    // mutation. Even preflight/OOM errors must retain a failed detach owner.
    std::shared_ptr<TargetSyscallRecovery::State> recoveryState;
    std::shared_ptr<TargetSyscallRecovery> recovery;
    try {
        recoveryState=std::make_shared<TargetSyscallRecovery::State>();
        recovery=std::shared_ptr<TargetSyscallRecovery>(new TargetSyscallRecovery(recoveryState));
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }
    recoveryState->tid=tid; recoveryState->owner=static_cast<pid_t>(syscall(SYS_gettid));
    recoveryState->startTime=initialIdentity->startTime;
    recoveryState->detach=!alreadyStopped;
    auto execute=[&]() -> std::expected<uint64_t,TargetSyscallFailure> {
        int status=(SIGTRAP|(PTRACE_EVENT_STOP<<8))<<8|0x7f;
        if (!alreadyStopped) {
            auto stopped = recoveryState->seizeStopped(*initialIdentity);
            if (!stopped) return std::unexpected(stopped.error());
            status = *stopped;
        } else {
            recoveryState->seized=true;
            recoveryState->stopped=true;
        }
        if (WSTOPSIG(status) != SIGTRAP)
            return std::unexpected(std::make_error_code(std::errc::interrupted));
        auto identity = targetProcessIdentity(tid);
        if (!identity) return std::unexpected(identity.error());
        if (expectedIdentity && *identity != *expectedIdentity)
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (expectedImage) {
            auto checked = expectedImage->checkImage();
            if (!checked) return std::unexpected(checked.error());
        }
        if(savedImage) {auto checked=savedImage->check();if(!checked) return std::unexpected(checked.error());}
        if (savedImage) {
            auto currentIdentity=processMemoryIdentity(tid);
            if (!currentIdentity) return std::unexpected(currentIdentity.error());
            auto current=NativeMemoryImage::capture(*currentIdentity,host);
            if (!current) return std::unexpected(current.error());
            const long page=sysconf(_SC_PAGESIZE);
            if (page<=0) return std::unexpected(invalid());
            recoveryState->affinityImage=std::move(*current);
            recoveryState->affinityHost=host;
            recoveryState->affinitySize=static_cast<size_t>(page);
            auto mapped=executeOwnedMemorySyscall(tid,host,MemorySyscall::Map,
                {0,static_cast<uint64_t>(page),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
            if (!mapped) {
                recoveryState->rememberAffinitySignal(mapped.error());
                recoveryState->affinityRecovery=mapped.error().recovery;
                if (mapped.error().completedValue) recoveryState->affinityAddress=*mapped.error().completedValue;
                return std::unexpected(mapped.error().code);
            }
            recoveryState->affinityAddress=*mapped;
            auto same=savedImage->sharesPrivateMapping(*recoveryState->affinityImage,*mapped);
            if (!same) return std::unexpected(same.error());
            auto released=recoveryState->cleanupAffinity();
            if (!released) return std::unexpected(released.error());
        }
        if (checkOnly) return uint64_t{0};
        struct stat executable{};
        auto executablePath = "/proc/" + std::to_string(tid) + "/exe";
        if (stat(executablePath.c_str(), &executable) != 0) {
            return std::unexpected(currentError());
        }
        auto original = getRegisters(tid);
        if (!original) return std::unexpected(original.error());
        auto executionMode = mode(*original);
        const bool arm32=executionMode==InstructionMode::Arm || executionMode==InstructionMode::Thumb;
        if (arm32) {
            // Full borrowed-site and parked-syscall adapters remain separate.
            // This path executes only in caller-owned private scratch code.
            if (!alreadyStopped || !scratch || existingOnly || host.architecture!=CpuArchitecture::Arm32 ||
                host.abi!=TargetAbi::LinuxArmEabi || host.byteOrder!=ByteOrder::Little ||
                host.instructionByteOrder!=ByteOrder::Little) return unsupported();
#if defined(__aarch64__) || defined(__arm__)
            const int32_t value=static_cast<int32_t>(original->arm[0]);
            if (value==-512 || value==-513 || value==-514 || value==-516) return unsupported();
#endif
        }
        auto plan = targetSyscallPlan(host, executionMode, operation, arguments);
#if defined(__x86_64__)
        // A WoW64 operation on its Unix loader can have 64-bit addresses even
        // while Windows code runs in compat mode. Validate against the Unix ABI
        // before rejecting arguments that do not fit an i386 syscall.
        if (!plan && plan.error() == std::errc::invalid_argument &&
            executionMode == InstructionMode::X86_32 && host.abi == TargetAbi::LinuxX86_64) {
            executionMode = InstructionMode::X86_64;
            plan = targetSyscallPlan(host, executionMode, operation, arguments);
        }
#endif
        if (!plan) return std::unexpected(plan.error());
        const auto syscallSize=plan->instruction.size();
        if (arm32) {
            const std::vector<uint8_t> trap=executionMode==InstructionMode::Thumb ?
                std::vector<uint8_t>{0x01,0xde} : std::vector<uint8_t>{0xf0,0x01,0xf0,0xe7};
            plan->instruction.insert(plan->instruction.end(),trap.begin(),trap.end());
        }
        uintptr_t address = pc(*original);
        if (alreadyStopped && scratch) {
            if (scratch>UINTPTR_MAX-16) return std::unexpected(invalid());
            address=scratch+(mode(*original)==InstructionMode::X86_32 ? 16 : 0);
            if (mode(*original)==InstructionMode::X86_32 && address>UINT32_MAX) return std::unexpected(invalid());
        }
        if (arm32 && (address>UINT32_MAX || address%(executionMode==InstructionMode::Thumb ? 2 : 4)))
            return std::unexpected(invalid());
        if (plan->instruction.size() > UINTPTR_MAX - address) return std::unexpected(invalid());
        // The original return instruction must remain executable and mapped. The
        // selected syscall instruction is checked separately below.
        bool destructive = operation == MemorySyscall::Unmap ||
            (operation == MemorySyscall::Protect && !(arguments[2] & PROT_EXEC)) ||
            (operation == MemorySyscall::Map && (arguments[3] & MAP_FIXED));
        if (destructive && arguments[1]) {
            auto pageSize = sysconf(_SC_PAGESIZE);
            if (pageSize <= 0 || arguments[0] > UINTPTR_MAX || arguments[1] > UINTPTR_MAX - arguments[0])
                return std::unexpected(invalid());
            uintptr_t start = static_cast<uintptr_t>(arguments[0]);
            uintptr_t end = start + static_cast<uintptr_t>(arguments[1]);
            auto page = static_cast<uintptr_t>(pageSize);
            const uintptr_t originalPage=pc(*original)-pc(*original)%page;
#if defined(__x86_64__)
            // A syscall-interrupt stop exposes the PC after SYSCALL/INT 80.
            // The kernel rewinds it by two bytes when the saved error requests
            // restart. Protect that instruction even when it is on the previous
            // page, while allowing completed syscalls to release unused code.
            const int64_t savedError=mode(*original)==InstructionMode::X86_32 ?
                static_cast<int32_t>(original->rax) : static_cast<int64_t>(original->rax);
            if (static_cast<int32_t>(original->orig_rax)!=-1 &&
                (savedError==-512 || savedError==-513 || savedError==-514 || savedError==-516)) {
                if (pc(*original)<2) return std::unexpected(invalid());
                const uintptr_t restartPage=(pc(*original)-2)-(pc(*original)-2)%page;
                if ((originalPage>UINTPTR_MAX-page || start<originalPage+page) && end>restartPage)
                    return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
            }
#endif
            if ((originalPage>UINTPTR_MAX-page || start<originalPage+page) && end>originalPage)
                return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
            const uintptr_t nextPage=originalPage+page;
            if (nextPage>originalPage && end>nextPage && (nextPage>UINTPTR_MAX-page || start<nextPage+page)) {
                auto originalLast=returnInstructionLastByte(tid,*original,page);
                if (!originalLast) return std::unexpected(originalLast.error());
                const uintptr_t originalLastPage=*originalLast-*originalLast%page;
                if ((originalLastPage>UINTPTR_MAX-page || start<originalLastPage+page) && end>originalPage)
                    return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
            }
            uintptr_t pcPage = address - address % page;
            uintptr_t lastByte = address + plan->instruction.size() - 1;
            uintptr_t lastPage = lastByte - lastByte % page;
            // Kernel memory syscalls round the length up to a page boundary.
            if ((lastPage > UINTPTR_MAX - page || start < lastPage + page) && end > pcPage)
                return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
        }
        recoveryState->original = *original;
        recoveryState->detach=!alreadyStopped;
        recoveryState->executableDevice = executable.st_dev;
        recoveryState->executableInode = executable.st_ino;
        recoveryState->startTime = identity->startTime;
        char memoryPath[64];
        std::snprintf(memoryPath, sizeof(memoryPath), "/proc/%ld/mem", static_cast<long>(tid));
#if defined(__aarch64__)
        // A pinned writable mm permits bounded bulk signal-frame restoration.
        // Read-only proc mounts can still use the ptrace word fallback.
        recoveryState->memoryFd = open(memoryPath, O_RDWR | O_CLOEXEC);
        if (recoveryState->memoryFd < 0)
#endif
        recoveryState->memoryFd = open(memoryPath, O_RDONLY | O_CLOEXEC);
        if (recoveryState->memoryFd < 0) return std::unexpected(currentError());
        if (!alreadyStopped || existingOnly) {
            auto existing=existingSyscallInstruction(tid,recoveryState->memoryFd,*plan,executionMode,operation,arguments);
#if defined(__x86_64__)
            // New WoW64 has PE32 code but an ELF64 Unix loader. It need not map
            // any ELF32 syscall site. Execute one native loader syscall in long
            // mode and restore the entire saved Windows context before detach.
            if (!existing && existing.error() == std::errc::not_supported &&
                executionMode == InstructionMode::X86_32 && host.abi == TargetAbi::LinuxX86_64) {
                executionMode = InstructionMode::X86_64;
                plan = targetSyscallPlan(host, executionMode, operation, arguments);
                if (!plan) return std::unexpected(plan.error());
                existing = existingSyscallInstruction(tid,recoveryState->memoryFd,*plan,executionMode,operation,arguments);
            }
#endif
            if (!existing) return std::unexpected(existing.error());
            address=*existing;
        }
        std::vector<SavedWord> words;
        for (size_t i = 0; alreadyStopped && !existingOnly && i < plan->instruction.size(); ++i) {
            uintptr_t at = address + i, aligned = at & ~uintptr_t(sizeof(long) - 1);
            if (words.empty() || words.back().address != aligned) {
                errno = 0;
                long value = ptrace(PTRACE_PEEKTEXT, tid, reinterpret_cast<void*>(aligned), nullptr);
                if (value == -1 && errno) return std::unexpected(currentError());
                words.push_back({aligned, value, value, 0});
            }
            auto* bytes = reinterpret_cast<uint8_t*>(&words.back().replacement);
            bytes[at - aligned] = plan->instruction[i];
            reinterpret_cast<uint8_t*>(&words.back().mask)[at - aligned] = 0xff;
        }
        std::error_code error;
        uint64_t rawResult = 0;
        size_t changed = 0;
        bool registersChanged = false;
        bool haveResult = false;
#if defined(__aarch64__)
        int oldSyscall = -1;
        iovec syscallIo{&oldSyscall, sizeof(oldSyscall)};
        if (ptrace(PTRACE_GETREGSET, tid, reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL), &syscallIo) < 0 || syscallIo.iov_len != sizeof(oldSyscall)) {
            error = currentError(); if (!error) error=invalid();
        }
        bool syscallChanged = false;
#endif
        // Allocate recovery ownership before the first mutation. No heap allocation
        // is needed while the thread contains injected instructions or registers.
        recoveryState->words = words;
        auto extended = captureNativeExtendedContext(tid);
        if (!extended) return std::unexpected(extended.error());
        recoveryState->extended = std::move(*extended);
#if defined(__aarch64__)
        if (!error && !arm32) {
            auto returned=Arm64VectorReturn::prepare(tid,recoveryState->memoryFd,address,*original,oldSyscall,
                recoveryState->extended,operation,plan->arguments);
            if (!returned) return std::unexpected(returned.error());
            if (*returned && alreadyStopped) {
                // Private/quiesced syscall patches have already been removed by
                // recovery before vector restoration. Borrow a permanent SVC site
                // for rt_sigreturn instead of executing restored application code.
                auto returnSite=existingSyscallInstruction(tid,recoveryState->memoryFd,*plan,executionMode,operation,arguments);
                if (!returnSite) return std::unexpected(returnSite.error());
                (*returned)->syscallAddress=*returnSite;
            }
            recoveryState->vectorReturn=std::move(*returned);
        }
#endif
#if defined(__aarch64__)
        recoveryState->oldSyscall=oldSyscall;
#endif
        recoveryState->prepared=true;
        ce::log::debug(ce::log::Cat::Ptrace,
            "memory syscall tid={} nr={} pc={:#x} addr={:#x} size={:#x} prot={:#x} flags={:#x}",
            tid, plan->number, address, plan->arguments[0], plan->arguments[1], plan->arguments[2], plan->arguments[3]);
        if (!error) for (const auto& word : words) {
            errno = 0;
            long current = ptrace(PTRACE_PEEKTEXT, tid, reinterpret_cast<void*>(word.address), nullptr);
            if (current == -1 && errno) { error=currentError(); break; }
            unsigned long replacement = (static_cast<unsigned long>(current) & ~word.mask) |
                                        (static_cast<unsigned long>(word.replacement) & word.mask);
            ++changed;
            if (ptrace(PTRACE_POKETEXT, tid, reinterpret_cast<void*>(word.address), reinterpret_cast<void*>(replacement)) < 0) { error=currentError(); break; }
            errno=0;
            const long verified=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(word.address),nullptr);
            if ((verified==-1 && errno) || (static_cast<unsigned long>(verified)&word.mask)!=(replacement&word.mask)) {
                error=(verified==-1 && errno) ? currentError() : std::make_error_code(std::errc::io_error);
                break;
            }
        }
        Registers injected = *original;
#if defined(__x86_64__)
        if (executionMode != mode(*original)) injected.cs = 0x33; // Linux __USER_CS.
#endif
        prepare(injected, *plan);
        setPc(injected,address);
#if defined(__aarch64__)
        if (!error) {
            int noSyscall = -1; iovec io{&noSyscall, sizeof(noSyscall)};
            syscallChanged = true;
            recoveryState->syscallChanged=true;
            if (ptrace(PTRACE_SETREGSET, tid, reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL), &io) < 0) error=currentError();
        }
#endif
        if (!error) {
            // SETREGS can reject a later field after updating earlier ones.
            registersChanged = true;
            recoveryState->registersChanged=true;
            if (!setRegisters(tid, injected)) error = currentError();
        }
        int pendingSignal = 0;
        if (!error) {
            if (ptrace(arm32 ? PTRACE_CONT : PTRACE_SINGLESTEP,tid,nullptr,nullptr)<0) error=currentError();
            else if (waitStopped(tid, status) != tid || !WIFSTOPPED(status)) error=std::make_error_code(std::errc::no_such_process);
            else if ((status >> 16) == 0) {
                siginfo_t signalInfo{};
                if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &signalInfo) < 0) error=currentError();
                bool kernelSyscallStep = false;
#if defined(__aarch64__)
                // Linux user_single_step_report() uses SI_USER with zero sender
                // for an ARM64 syscall pseudo-step. A genuine kill/tgkill sender
                // is retained and delivered below. Completion still requires PC.
                kernelSyscallStep = signalInfo.si_code == SI_USER && signalInfo.si_pid == 0 && signalInfo.si_uid == 0;
#endif
                const bool privateTrap=arm32 && signalInfo.si_signo==SIGTRAP && signalInfo.si_code==TRAP_BRKPT &&
                    reinterpret_cast<uintptr_t>(signalInfo.si_addr)==address+syscallSize;
                if (WSTOPSIG(status)!=SIGTRAP || (arm32 ? !privateTrap : (signalInfo.si_code<=0 && !kernelSyscallStep))) {
                    pendingSignal=WSTOPSIG(status); error=std::make_error_code(std::errc::interrupted);
                    if (signalInfo.si_signo==WSTOPSIG(status)) recoveryState->pendingSignalInfo=signalInfo;
                }
                auto completed = getRegisters(tid);
                if (!completed) error=completed.error();
                else if (pc(*completed) != address + syscallSize) error=std::make_error_code(std::errc::interrupted);
                // Seccomp and syscall-user-dispatch can raise SIGSYS after advancing
                // PC without executing the syscall. Its unchanged number register
                // is not a completed mmap result and must never become an orphan.
                else if (WSTOPSIG(status)==SIGSYS && signalInfo.si_code>0 &&
                         static_cast<uint32_t>(signalInfo.si_syscall)==plan->number) {
                    // This fault belongs to our denied operation. Preserve the
                    // target's policy and resume its original context without
                    // injecting the synthetic denial into its signal handler.
                    pendingSignal=0;
                    recoveryState->pendingSignalInfo.reset();
                    recoveryState->pendingStepTrap=!arm32;
                    recoveryState->stepEnd=address+syscallSize;
                    error=std::make_error_code(std::errc::operation_not_permitted);
                } else {
                    rawResult = result(*completed); haveResult = true;
                }
            } else {
                error=std::make_error_code(std::errc::interrupted);
                if ((status >> 16) != PTRACE_EVENT_EXEC) {
                    auto completed = getRegisters(tid);
                    if (completed && pc(*completed) == address + syscallSize) {
                        rawResult = result(*completed); haveResult = true;
                    }
                }
            }
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            recoveryState->done=true;
            return std::unexpected(std::make_error_code(std::errc::no_such_process));
        }
        if (WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_EXEC) {
            recoveryState->prepared=false;
            recoveryState->retired=true;
            recoveryState->rememberStop(status);
            TargetSyscallFailure failure(std::make_error_code(std::errc::operation_canceled));
            failure.pendingEvent=PTRACE_EVENT_EXEC;
            return std::unexpected(std::move(failure));
        }
        recoveryState->words.resize(changed);
        recoveryState->registersChanged = registersChanged;
        recoveryState->pendingSignal = pendingSignal;
#if defined(__aarch64__)
        recoveryState->oldSyscall = oldSyscall;
        recoveryState->syscallChanged = syscallChanged;
#endif
        auto restored = recovery->retry();
        pendingSignal=recoveryState->pendingSignal;
        if (!restored) {
            TargetSyscallFailure failure(restored.error());
            failure.pendingSignal=pendingSignal;
            if (!recoveryState->done) failure.recovery = recovery;
            if (haveResult && rawResult < UINT64_MAX - 4094 &&
                (plan->resultWidth != 4 || static_cast<uint32_t>(rawResult) < 0xfffff001u))
                failure.completedValue = plan->resultWidth == 4 ? static_cast<uint32_t>(rawResult) : rawResult;
            return std::unexpected(std::move(failure));
        }
        // Diagnostics cannot discard a completed mmap if formatting runs out of
        // memory. The broker must receive its value to own or return the mapping.
        try {
            ce::log::debug(ce::log::Cat::Ptrace, "memory syscall tid={} nr={} raw={:#x} completed={} error={}",
                tid, plan->number, rawResult, haveResult, error.message());
        } catch (...) {}
        if (error) {
            TargetSyscallFailure failure(error);
            failure.pendingSignal=pendingSignal;
            if (haveResult && rawResult < UINT64_MAX - 4094 &&
                (plan->resultWidth != 4 || static_cast<uint32_t>(rawResult) < 0xfffff001u))
                failure.completedValue = plan->resultWidth == 4 ? static_cast<uint32_t>(rawResult) : rawResult;
            return std::unexpected(std::move(failure));
        }
        if (plan->resultWidth == 4) {
            uint32_t value=static_cast<uint32_t>(rawResult);
            if (value >= 0xfffff001u) return std::unexpected(std::error_code(-static_cast<int32_t>(value),std::system_category()));
            return value;
        }
        if (rawResult >= UINT64_MAX - 4094) return std::unexpected(std::error_code(-static_cast<int64_t>(rawResult),std::system_category()));
        return rawResult;
    };
    auto result=[&]() -> std::expected<uint64_t,TargetSyscallFailure> {
        try { return execute(); }
        catch (const std::bad_alloc&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
        catch (...) { return std::unexpected(std::make_error_code(std::errc::io_error)); }
    }();
    if (!result && recoveryState->seized && !recoveryState->done && !result.error().recovery) {
        auto restored=recovery->retry();
        if (!restored && !recoveryState->done) {
            result.error().code=restored.error();
            result.error().recovery=recovery;
            result.error().pendingSignal=recoveryState->pendingSignal;
        }
    }
    return result;
#else
    (void)tid; (void)host; (void)operation; (void)arguments; (void)expectedIdentity; (void)expectedImage;
    (void)alreadyStopped; (void)scratch; (void)existingOnly;
    return unsupported();
#endif
}

std::expected<void,TargetSyscallFailure> executeThreadInspection(
    const TargetProcessIdentity& identity,const TargetMachine& host,bool registerWrites,
    const std::function<std::expected<void,std::error_code>()>& callback) {
#if defined(__x86_64__) || defined(__aarch64__) || defined(__arm__)
    const auto native = nativeTargetMachine();
    if (host.architecture != native.architecture &&
        !(native.architecture == CpuArchitecture::X86_64 && host.architecture == CpuArchitecture::X86_32) &&
        !(native.architecture == CpuArchitecture::Arm64 && host.architecture == CpuArchitecture::Arm32))
        return unsupported();
    std::shared_ptr<TargetSyscallRecovery::State> state;
    std::shared_ptr<TargetSyscallRecovery> recovery;
    try {
        state = std::make_shared<TargetSyscallRecovery::State>();
        recovery = std::shared_ptr<TargetSyscallRecovery>(new TargetSyscallRecovery(state));
    } catch (const std::bad_alloc&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
    state->tid = identity.pid; state->startTime = identity.startTime;
    state->owner = static_cast<pid_t>(syscall(SYS_gettid));
    auto work = [&]() -> std::expected<void,TargetSyscallFailure> {
        auto stopped = state->seizeStopped(identity);
        if (!stopped) return std::unexpected(stopped.error());
        if (registerWrites) {
            auto original = getRegisters(identity.pid);
            if (!original) return std::unexpected(original.error());
            state->original = *original;
            std::string path = "/proc/" + std::to_string(identity.pid) + "/mem";
            state->memoryFd = open(path.c_str(),O_RDWR | O_CLOEXEC);
            if (state->memoryFd < 0) return std::unexpected(currentError());
            state->executableDevice = identity.executableDevice;
            state->executableInode = identity.executableInode;
            state->prepared = true;
            state->registersChanged = true;
        }
        auto result = callback();
        if (!result) return std::unexpected(result.error());
        // A successful edit is intentional. Retain it while releasing only the
        // stop; errors below this point must not replay an obsolete GP snapshot.
        state->prepared = false; state->registersChanged = false;
        auto released = recovery->retry();
        if (!released) return std::unexpected(released.error());
        return {};
    };
    auto result = [&]() -> std::expected<void,TargetSyscallFailure> {
        try { return work(); }
        catch (const std::bad_alloc&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
        catch (...) { return std::unexpected(std::make_error_code(std::errc::io_error)); }
    }();
    if (!result && state->seized && !state->done) {
        auto restored = recovery->retry();
        if (!restored && !state->done) {
            result.error().code = restored.error();
            result.error().recovery = recovery;
            result.error().pendingSignal = state->pendingSignal;
        }
    }
    return result;
#else
    (void)identity; (void)host; (void)registerWrites; (void)callback;
    return unsupported();
#endif
}

std::expected<uint64_t, TargetSyscallFailure> executeMemorySyscall(
    pid_t tid,const TargetMachine& host,MemorySyscall operation,std::array<uint64_t,6> arguments,
    const TargetProcessIdentity* expectedIdentity,const TargetSyscallRecovery* expectedImage,const NativeMemoryImage* savedImage) {
    return executeMemorySyscallInternal(tid,host,operation,arguments,expectedIdentity,expectedImage,false,0,false,savedImage);
}
std::expected<uint64_t, TargetSyscallFailure> executeStoppedMemorySyscall(
    pid_t tid,const TargetMachine& host,MemorySyscall operation,std::array<uint64_t,6> arguments,uintptr_t scratch) {
    if (!scratch) return std::unexpected(invalid());
    return executeMemorySyscallInternal(tid,host,operation,arguments,nullptr,nullptr,true,scratch,false,nullptr);
}
std::expected<uint64_t, TargetSyscallFailure> executeQuiescedMemorySyscall(
    pid_t tid,const TargetMachine& host,MemorySyscall operation,std::array<uint64_t,6> arguments) {
    return executeMemorySyscallInternal(tid,host,operation,arguments,nullptr,nullptr,true,0,false,nullptr);
}
std::expected<uint64_t,TargetSyscallFailure> executeOwnedMemorySyscall(
    pid_t tid,const TargetMachine& host,MemorySyscall operation,std::array<uint64_t,6> arguments) {
    return executeMemorySyscallInternal(tid,host,operation,arguments,nullptr,nullptr,true,0,true,nullptr);
}

std::expected<void,TargetSyscallFailure> verifyStoppedMemoryImage(
    pid_t tid,const TargetMachine& host,const NativeMemoryImage& image) {
    auto verified=executeMemorySyscallInternal(tid,host,MemorySyscall::Map,{},nullptr,nullptr,true,0,true,&image,true);
    if (!verified) return std::unexpected(std::move(verified.error()));
    return {};
}

std::expected<void,std::error_code> checkStoppedFunctionAbi(pid_t tid,const TargetMachine& host) {
#if defined(__x86_64__) || defined(__aarch64__)
    auto registers=getRegisters(tid);
    if (!registers) return std::unexpected(registers.error());
#if defined(__x86_64__)
    bool compat=mode(*registers)==InstructionMode::X86_32;
    if ((compat && host.abi!=TargetAbi::LinuxI386) ||
        (!compat && host.abi!=TargetAbi::LinuxX86_64 && host.abi!=TargetAbi::LinuxX32) || !host.isX86() ||
        registers->orig_rax!=UINT64_MAX) return unsupported();
#else
    if (registers->compat || host.architecture!=CpuArchitecture::Arm64 || host.abi!=TargetAbi::LinuxAarch64 || host.byteOrder!=ByteOrder::Little)
        return unsupported();
    if (registers->pc%4) return std::unexpected(invalid());
    int syscallNumber=-1; iovec io{&syscallNumber,sizeof(syscallNumber)};
    if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL),&io)<0)
        return std::unexpected(currentError());
    if (io.iov_len!=sizeof(syscallNumber) || syscallNumber!=-1) return unsupported();
    uintptr_t aligned=registers->pc&~uintptr_t(sizeof(long)-1);
    errno=0;
    long word=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(aligned),nullptr);
    if (word==-1 && errno) return std::unexpected(currentError());
    uint32_t instruction=0;
    std::memcpy(&instruction,reinterpret_cast<const uint8_t*>(&word)+(registers->pc-aligned),sizeof(instruction));
    if ((instruction&0xffe0001f)==0xd4000001) return unsupported(); // SVC #imm16.
#endif
    return {};
#else
    (void)tid; (void)host;
    return unsupported();
#endif
}

std::expected<uint64_t,TargetSyscallFailure> executeStoppedFunction(
    pid_t tid,const TargetMachine& host,uintptr_t function,std::array<uint64_t,8> arguments,
    uintptr_t code,uintptr_t stackTop,int timeoutMs) {
#if defined(__x86_64__) || defined(__aarch64__)
    if (!function || !code || code>UINTPTR_MAX-16 || stackTop<64 || stackTop%16 || timeoutMs<0 || timeoutMs>60000)
        return std::unexpected(invalid());
    std::shared_ptr<TargetSyscallRecovery::State> state;
    std::shared_ptr<TargetSyscallRecovery> recovery;
    try {
        state=std::make_shared<TargetSyscallRecovery::State>();
        recovery=std::shared_ptr<TargetSyscallRecovery>(new TargetSyscallRecovery(state));
    } catch (const std::bad_alloc&) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }
    state->tid=tid; state->owner=static_cast<pid_t>(syscall(SYS_gettid));
    state->detach=false; state->seized=true; state->stopped=true;
    auto execute=[&]() -> std::expected<uint64_t,TargetSyscallFailure> {
        auto identity=targetProcessIdentity(tid);
        if (!identity) return std::unexpected(identity.error());
        auto original=getRegisters(tid);
        if (!original) return std::unexpected(original.error());
        auto eligible=checkStoppedFunctionAbi(tid,host);
        if (!eligible) return std::unexpected(eligible.error());
        state->original=*original;
        state->startTime=identity->startTime;
        state->executableDevice=identity->executableDevice;
        state->executableInode=identity->executableInode;
        std::ifstream taskStatus("/proc/"+std::to_string(tid)+"/status");
        std::string line;
        while (std::getline(taskStatus,line)) if (line.starts_with("Tgid:")) {
            std::istringstream value(line.substr(5));value>>state->groupLeader;break;
        }
        if (!state->groupLeader) return std::unexpected(std::make_error_code(std::errc::no_such_process));
        auto groupBirth=taskStartTime(state->groupLeader);
        if (!groupBirth) return std::unexpected(groupBirth.error());
        state->groupBirth=*groupBirth;
        Registers injected=*original;
        std::array<uint8_t,16> instructions{};
        std::array<uint8_t,32> stackArguments{};
        size_t instructionSize=0,stackSize=0;
        uintptr_t callStack=stackTop;
        bool compat=false;
#if defined(__x86_64__)
        compat=mode(*original)==InstructionMode::X86_32;
        if ((compat && host.abi!=TargetAbi::LinuxI386) ||
            (!compat && host.abi!=TargetAbi::LinuxX86_64 && host.abi!=TargetAbi::LinuxX32) || !host.isX86())
            return unsupported();
        // A remote call must not disturb hidden restart_block state belonging
        // to an interrupted kernel wait. Its caller must obtain a user stop.
        if (original->orig_rax!=UINT64_MAX) return unsupported();
        if (compat || host.abi==TargetAbi::LinuxX32) {
            if (function>UINT32_MAX || code>UINT32_MAX-16 || stackTop>UINT32_MAX) return std::unexpected(invalid());
            // x32 retains the x86-64 integer calling convention, including
            // 64-bit scalar arguments and eight-byte stack argument slots.
            if (compat) for (auto argument : arguments) if (argument>UINT32_MAX) return std::unexpected(invalid());
        }
        injected.orig_rax=UINT64_MAX;
        injected.eflags&=~uint64_t(0x100|0x400|0x10000); // TF, DF and RF.
        if (compat) {
            instructions={0xff,0xd0,0xcc}; // call eax; int3
            instructionSize=3; stackSize=32; callStack-=stackSize;
            injected.rax=function;
            for (size_t i=0;i<arguments.size();++i) {
                uint32_t word=static_cast<uint32_t>(arguments[i]);
                std::memcpy(stackArguments.data()+i*sizeof(word),&word,sizeof(word));
            }
        } else {
            instructions={0x41,0xff,0xd3,0xcc}; // call r11; int3
            instructionSize=4; stackSize=16; callStack-=stackSize;
            injected.r11=function; injected.rax=0;
            injected.rdi=arguments[0]; injected.rsi=arguments[1]; injected.rdx=arguments[2];
            injected.rcx=arguments[3]; injected.r8=arguments[4]; injected.r9=arguments[5];
            std::memcpy(stackArguments.data(),arguments.data()+6,stackSize);
        }
        injected.rsp=callStack;
#else
        if (original->compat || host.architecture!=CpuArchitecture::Arm64 || host.abi!=TargetAbi::LinuxAarch64 ||
            host.byteOrder!=ByteOrder::Little || code%4 || function%4) return unsupported();
        iovec syscallIo{&state->oldSyscall,sizeof(state->oldSyscall)};
        if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL),&syscallIo)<0)
            return std::unexpected(currentError());
        if (syscallIo.iov_len!=sizeof(state->oldSyscall) || state->oldSyscall!=-1) return unsupported();
        injected.sp=callStack;
        injected.pstate&=~(uint64_t{1}<<21);
        injected.regs[16]=function;
        std::copy(arguments.begin(),arguments.end(),injected.regs);
#endif
        char memoryPath[64];
        std::snprintf(memoryPath,sizeof(memoryPath),"/proc/%ld/mem",static_cast<long>(tid));
#if defined(__aarch64__)
        state->memoryFd=open(memoryPath,O_RDWR|O_CLOEXEC);
        if (state->memoryFd<0)
#endif
        state->memoryFd=open(memoryPath,O_RDONLY|O_CLOEXEC);
        if (state->memoryFd<0) return std::unexpected(currentError());
        auto extended=captureNativeExtendedContext(tid);
        if (!extended) return std::unexpected(extended.error());
        state->extended=std::move(*extended);
        if (ptrace(PTRACE_GETSIGMASK,tid,reinterpret_cast<void*>(sizeof(state->originalMask)),&state->originalMask)<0)
            return std::unexpected(currentError());
        state->maskSaved=true;
#if defined(__aarch64__)
        bool streaming=false;
        for (const auto& regset : state->extended.regsets) if (regset.note==0x40b && regset.bytes.size()>=16) {
            uint16_t flags=0;
            std::memcpy(&flags,regset.bytes.data()+12,sizeof(flags));
            streaming=(flags&1)!=0;
        }
        std::array<uint32_t,3> words{0xd63f0200,0xd4200000,0}; // blr x16; brk #0
        instructionSize=8;
        if (streaming) {
            // Ordinary AAPCS64 callees execute outside streaming mode.
            words={0xd503427f,0xd63f0200,0xd4200000}; // smstop sm; blr x16; brk #0
            instructionSize=12;
        }
        std::memcpy(instructions.data(),words.data(),instructionSize);
        auto plan=targetSyscallPlan(host,InstructionMode::Aarch64,MemorySyscall::Map,{});
        if (!plan) return std::unexpected(plan.error());
        auto returnSite=existingSyscallInstruction(tid,state->memoryFd,*plan,InstructionMode::Aarch64,MemorySyscall::Map,{});
        if (!returnSite) return std::unexpected(returnSite.error());
        auto returned=Arm64VectorReturn::prepare(tid,state->memoryFd,*returnSite,*original,state->oldSyscall,
            state->extended,MemorySyscall::Map,{});
        if (!returned) return std::unexpected(returned.error());
        state->vectorReturn=std::move(*returned);
#endif
        state->function.emplace();
        auto& call=*state->function;
        call.stack=callStack; call.compat=compat; call.waitMilliseconds=timeoutMs;
        call.trap=code+instructionSize-
#if defined(__x86_64__)
            1;
#else
            4;
#endif
        state->prepared=true;
        auto writePrivate=[&](uintptr_t at,const uint8_t* bytes,size_t size) -> Result<void> {
            for (size_t offset=0;offset<size;) {
                uintptr_t address=at+offset,aligned=address&~uintptr_t(sizeof(long)-1);
                size_t first=address-aligned,count=std::min(size-offset,sizeof(long)-first);
                errno=0;
                long word=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(aligned),nullptr);
                if (word==-1 && errno) return std::unexpected(currentError());
                std::memcpy(reinterpret_cast<uint8_t*>(&word)+first,bytes+offset,count);
                // Ptrace also performs the architecture's instruction-cache
                // maintenance for the executable private page.
                if (ptrace(PTRACE_POKETEXT,tid,reinterpret_cast<void*>(aligned),reinterpret_cast<void*>(word))<0)
                    return std::unexpected(currentError());
                errno=0;
                long actual=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(aligned),nullptr);
                if ((actual==-1 && errno) || actual!=word) return std::unexpected(std::make_error_code(std::errc::io_error));
                offset+=count;
            }
            return {};
        };
        auto written=writePrivate(code,instructions.data(),instructionSize);
        if (!written) return std::unexpected(written.error());
        if (stackSize) {
            written=writePrivate(callStack,stackArguments.data(),stackSize);
            if (!written) return std::unexpected(written.error());
        }
        setPc(injected,code);
#if defined(__aarch64__)
        int noSyscall=-1; iovec io{&noSyscall,sizeof(noSyscall)};
        state->syscallChanged=true;
        if (ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL),&io)<0)
            return std::unexpected(currentError());
#endif
        state->registersChanged=true;
        if (!setRegisters(tid,injected)) return std::unexpected(currentError());
        call.started=true;
        auto restored=recovery->retry();
        call.waitMilliseconds=100;
        if (!restored) {
            TargetSyscallFailure failure(restored.error());
            if (!state->done) failure.recovery=recovery;
            failure.completedValue=call.value;
            failure.pendingSignal=call.awaitingSignal ? call.signal : state->pendingSignal;
            failure.pendingEvent=call.event;
            return std::unexpected(std::move(failure));
        }
        return *call.value;
    };
    auto value=[&]() -> std::expected<uint64_t,TargetSyscallFailure> {
        try { return execute(); }
        catch (const std::bad_alloc&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
        catch (...) { return std::unexpected(std::make_error_code(std::errc::io_error)); }
    }();
    if (!value && state->prepared && !state->done && !value.error().recovery) {
        auto restored=recovery->retry();
        if (!restored && !state->done) {
            value.error().recovery=recovery;
            value.error().code=restored.error();
            value.error().completedValue=recovery->functionResult();
        }
    }
    if (!value && state->replacementTask) {
        value.error().replacementTask=state->replacementTask;
        value.error().pendingEvent=PTRACE_EVENT_EXEC;
    }
    return value;
#else
    (void)tid; (void)host; (void)function; (void)arguments; (void)code; (void)stackTop; (void)timeoutMs;
    return unsupported();
#endif
}
} // namespace ce::os
