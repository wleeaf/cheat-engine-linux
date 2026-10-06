#include "arch/target_arch.hpp"
#include "core/target_capabilities.hpp"
#include "core/cpu_registers.hpp"
#include "arch/cpu_flags.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/stack_trace.hpp"
#include "debug/thread_inspection.hpp"
#include "core/value_io.hpp"
#include "core/local_target.hpp"
#include "core/expression.hpp"
#include "core/injection_gen.hpp"
#include "core/simple_hook.hpp"
#include "core/autoasm.hpp"
#include "scripting/lua_engine.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/thread_entry.hpp"
#include "scanner/pointer_scanner.hpp"
#include "analysis/mono_dissector.hpp"
#include "plugins/mono_protocol.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <arpa/inet.h>
#include <filesystem>
#include <limits>
#include <poll.h>
#include <stdexcept>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

using namespace ce;
static int failures = 0;
static void check(bool ok, const char* name) {
    std::printf("%s: %s\n", ok ? "OK" : "FAILED", name);
    failures += !ok;
}
static std::vector<uint8_t> elf(uint16_t machine, bool wide, bool big = false) {
    std::vector<uint8_t> h(64);
    h[0] = 0x7f; h[1] = 'E'; h[2] = 'L'; h[3] = 'F';
    h[EI_CLASS] = wide ? ELFCLASS64 : ELFCLASS32;
    h[EI_DATA] = big ? ELFDATA2MSB : ELFDATA2LSB;
    h[EI_VERSION] = EV_CURRENT;
    h[18] = big ? machine >> 8 : machine; h[19] = big ? machine : machine >> 8;
    return h;
}
static std::vector<uint8_t> pe(uint16_t machine, bool wide) {
    std::vector<uint8_t> h(0x200);
    h[0] = 'M'; h[1] = 'Z'; h[0x3c] = 0x80;
    h[0x80] = 'P'; h[0x81] = 'E';
    h[0x84] = machine; h[0x85] = machine >> 8;
    h[0x94] = 0xe0;
    h[0x98] = wide ? 0x0b : 0x0b; h[0x99] = wide ? 2 : 1;
    return h;
}

class TargetBuffer : public ProcessHandle {
public:
    static constexpr uintptr_t base = 0x10000;
    uintptr_t memoryBase=base;
    TargetDescription description = [] { TargetDescription d; d.transport = TargetTransport::Local; return d; }();
    std::vector<uint8_t> bytes = std::vector<uint8_t>(0x10000, 0xcc);
    std::atomic<int> reads{0};
    int writes = 0, allocations = 0, frees = 0;
    bool concurrentReads=false;
    bool supportsConcurrentReads() const override {return concurrentReads;}
    bool rejectWrites = false, rejectFree = false;
    std::optional<uintptr_t> failReadAfterWrite;
    bool shortWrites = false, shortReads = false;
    bool throwAfterWrite = false;
    MemProt protection = MemProt::ReadWrite;
    int rejectedProtectionChanges = 0;
    std::vector<ModuleInfo> extraModules;
    pid_t pid() const override { return getpid(); }
    bool is64bit() const override { return description.host.pointerWidth == 8; }
    bool runs32BitCode() override { return description.program.instructionMode == InstructionMode::X86_32; }
    TargetDescription targetDescription() override { return description; }
    Result<size_t> read(uintptr_t address, void* buffer, size_t n) override {
        ++reads;
        if (failReadAfterWrite==address && writes>0)
            return std::unexpected(std::make_error_code(std::errc::io_error));
        if (address < memoryBase || address - memoryBase > bytes.size() || n > bytes.size() - (address - memoryBase))
            return std::unexpected(std::make_error_code(std::errc::bad_address));
        std::memcpy(buffer, bytes.data() + address - memoryBase, n); return shortReads && n ? n-1 : n;
    }
    Result<size_t> write(uintptr_t address, const void* buffer, size_t n) override {
        ++writes;
        if (rejectWrites) return std::unexpected(std::make_error_code(std::errc::permission_denied));
        if (shortWrites && n) --n;
        if (address < memoryBase || address - memoryBase > bytes.size() || n > bytes.size() - (address - memoryBase))
            return std::unexpected(std::make_error_code(std::errc::bad_address));
        std::memcpy(bytes.data() + address - memoryBase, buffer, n);
        if (throwAfterWrite) {
            throwAfterWrite = false;
            throw std::runtime_error("injected post-mutation adapter exception");
        }
        return n;
    }
    std::vector<MemoryRegion> queryRegions() override {
        return {{memoryBase, bytes.size(), protection, MemType::Private, MemState::Committed, "fixture"}};
    }
    std::optional<MemoryRegion> queryRegion(uintptr_t address) override {
        return address >= memoryBase && address - memoryBase < bytes.size() ? std::optional(queryRegions()[0]) : std::nullopt;
    }
    Result<uintptr_t> allocate(size_t, MemProt, uintptr_t) override { ++allocations; return memoryBase + 0x8000; }
    Result<void> free(uintptr_t, size_t) override {
        ++frees;
        if (rejectFree) return std::unexpected(std::make_error_code(std::errc::permission_denied));
        return {};
    }
    Result<void> protect(uintptr_t, size_t, MemProt desired) override {
        if (rejectedProtectionChanges > 0) {
            --rejectedProtectionChanges;
            return std::unexpected(std::make_error_code(std::errc::permission_denied));
        }
        protection = desired;
        return {};
    }
    std::vector<ModuleInfo> modules() override {
        auto mods = extraModules;
        mods.push_back({memoryBase, bytes.size(), "fixture", "", description.program.pointerWidth == 8, description.program});
        return mods;
    }
    TargetMachine machineAt(uintptr_t address) override {
        for (const auto& m : extraModules)
            if (address >= m.base && address - m.base < m.size) return m.machine;
        return description.program;
    }
    std::vector<ThreadInfo> threads() override { return {}; }
};

static void machineTests() {
    auto x32 = parseElfTarget(elf(EM_X86_64, false));
    check(x32 && x32->architecture == CpuArchitecture::X86_64 && x32->pointerWidth == 4 &&
          x32->abi == TargetAbi::LinuxX32, "x32 uses x86-64 instructions and four-byte data pointers");
    auto rv32 = parseElfTarget(elf(EM_RISCV, false));
    auto rv64 = parseElfTarget(elf(EM_RISCV, true));
    check(rv32 && rv64 && rv32->architecture == CpuArchitecture::RiscV32 &&
          rv64->architecture == CpuArchitecture::RiscV64, "RISC-V class determines address width");
    auto be = parseElfTarget(elf(EM_PPC64, true, true));
    check(be && be->architecture == CpuArchitecture::PowerPC64 && be->byteOrder == ByteOrder::Big,
          "big-endian ELF machine fields are decoded in file byte order");
    auto bad = elf(EM_X86_64, true); bad[EI_DATA] = 0;
    check(!parseElfTarget(bad) && !parseElfTarget(elf(EM_386, true)) &&
          !parseElfTarget(elf(EM_X86_64, true, true)) && !parseElfTarget(std::span(bad).first(20)),
          "malformed and truncated ELF headers never default to x86-64");
    auto arm = elf(EM_ARM, false, true); arm[36] = 0x00; arm[37] = 0x80; // EF_ARM_BE8
    auto be8 = parseElfTarget(arm);
    check(be8 && be8->byteOrder == ByteOrder::Big && be8->instructionByteOrder == ByteOrder::Little,
          "ARM BE8 separates big-endian data from little-endian instructions");
    auto a64be = parseElfTarget(elf(EM_AARCH64, true, true));
    check(a64be && a64be->instructionByteOrder == ByteOrder::Little &&
          disassemblerArchFor(*a64be) == Arch::ARM64, "AArch64 data endianness does not swap instructions");
    auto p32 = parsePeTarget(pe(0x14c, false));
    auto p64 = parsePeTarget(pe(0x8664, true));
    auto hybrid = parsePeTarget(pe(0xa64e, true));
    check(p32 && p64 && p32->pointerWidth == 4 && p64->pointerWidth == 8 &&
          p32->abi == TargetAbi::WindowsI386 && p64->abi == TargetAbi::WindowsX64,
          "PE optional-header width and machine describe the Windows program ABI");
    check(hybrid && hybrid->architecture == CpuArchitecture::Arm64X && !disassemblerArchFor(*hybrid),
          "hybrid ARM64X modules require an explicit code-mode adapter");
    auto truncatedPe = pe(0x8664, true);
    check(!parsePeTarget(pe(0x14c, true)) && !parsePeTarget(std::span(truncatedPe).first(0x99)),
          "PE width mismatch and truncated optional headers are rejected");
    auto unknown = parseElfTarget(elf(0xbeef, true));
    check(unknown && unknown->architecture == CpuArchitecture::Other && !disassemblerArchFor(*unknown),
          "unimplemented architectures remain inspectable without selecting x86 code");
}

static void dataTests() {
    TargetBuffer buffer;
    buffer.description.host = *parseElfTarget(elf(EM_X86_64, true));
    buffer.description.program = *parsePeTarget(pe(0x14c, false));
    buffer.description.runtime = TargetRuntime::Wine;
    buffer.description.mixedCode = true;
    auto unknownAdapter = buffer.ProcessHandle::targetDescription();
    check(unknownAdapter.program.architecture == CpuArchitecture::Unknown && unknownAdapter.program.byteOrder == ByteOrder::Unknown,
          "bitness-only process adapters never guess their target ISA or byte order");
    auto pointer = writeTypedValue(buffer, buffer.base + 16, ValueType::Pointer, "0x10200");
    check(pointer && *pointer == 4 && buffer.bytes[20] == 0xcc &&
          readTypedValue(buffer, buffer.base + 16, ValueType::Pointer) == "0x10200" &&
          ExpressionParser(&buffer).parse("[0x10010]+4") == buffer.base + 0x204,
          "WoW64 typed pointers and expressions follow the program ABI instead of loader width");
    buffer.description.program = *parseElfTarget(elf(EM_PPC, false, true));
    auto value = writeTypedValue(buffer, buffer.base + 32, ValueType::Int32, "0x12345678");
    check(value && buffer.bytes[32] == 0x12 && buffer.bytes[35] == 0x78 &&
          readTypedValue(buffer, buffer.base + 32, ValueType::Int32) == "305419896",
          "typed integers default to the target's byte order");
    auto floating = writeTypedValue(buffer, buffer.base + 40, ValueType::Float, "2.5");
    check(floating && buffer.bytes[40] == 0x40 && buffer.bytes[41] == 0x20 &&
          readTypedValue(buffer, buffer.base + 40, ValueType::Float) == "2.5" &&
          compareTypedValue(buffer, buffer.base + 40, ValueType::Float, "3") == -1,
          "floating point encoding and directional comparisons honor target byte order");
    pointer = writeTypedValue(buffer, buffer.base + 16, ValueType::Pointer, "0x10200");
    check(pointer && buffer.bytes[16] == 0 && buffer.bytes[17] == 1 && buffer.bytes[18] == 2 &&
          ExpressionParser(&buffer).parse("[0x10010]+4") == buffer.base + 0x204,
          "big-endian pointer expressions decode all four bytes correctly");
    PointerPath path; path.module = "fixture"; path.baseOffset = 16; path.offsets = {4};
    check(PointerScanner::dereference(buffer, path) == buffer.base + 0x204,
          "pointer paths use target width and byte order");
    PointerScanConfig scan; scan.targetAddress = buffer.base + 0x204; scan.maxDepth = 1; scan.maxOffset = 8;
    PointerScanner scanner;
    auto paths = scanner.scan(buffer, scan);
    check(std::any_of(paths.begin(), paths.end(), [&](const auto& p) {
        return p.baseOffset == 16 && p.offsets == std::vector<int32_t>{4};
    }), "reverse pointer scanning finds big-endian four-byte pointers");
    ValueIoOptions little; little.byteOrder = ByteOrder::Little;
    auto override = writeTypedValue(buffer, buffer.base + 32, ValueType::Int32, "0x12345678", little);
    check(override && buffer.bytes[32] == 0x78 && buffer.bytes[35] == 0x12,
          "explicit byte order overrides target detection");
    buffer.description.program = {};
    auto before = buffer.writes;
    check(!writeTypedValue(buffer, buffer.base, ValueType::Pointer, "0x10000") && before == buffer.writes &&
          writeTypedValue(buffer, buffer.base, ValueType::ByteArray, "AA BB").has_value(),
          "unknown machine blocks pointer guesses while preserving raw-byte access");
}

static CapabilityState state(const TargetDescription& d, TargetFeature feature) {
    for (const auto& c : targetCapabilities(d)) if (c.feature == feature) return c.state;
    return CapabilityState::Unknown;
}
static void capabilityTests() {
    TargetBuffer buffer;
    buffer.description.host = buffer.description.program = *parseElfTarget(elf(EM_AARCH64, true));
    std::string error;
    check(generateInjectionScript(buffer, buffer.base, InjectionKind::Code, error).empty() &&
          !installSimpleHook(buffer, buffer.base, buffer.base + 16) && buffer.reads == 0 &&
          buffer.writes == 0 && buffer.allocations == 0,
          "unsupported hook backends fail before touching target state");
    buffer.description.host = *parseElfTarget(elf(EM_X86_64, true));
    buffer.description.program = *parsePeTarget(pe(0x14c, false));
    buffer.description.runtime = TargetRuntime::Wine;
    check(state(buffer.description, TargetFeature::HardwareWatchpoint) == CapabilityState::Partial &&
          state(buffer.description, TargetFeature::SoftwareWatchpoint) == CapabilityState::Unsupported &&
          state(buffer.description, TargetFeature::LibraryInjection) == CapabilityState::Unsupported,
          "Wine capabilities expose thread coverage and page-guard restrictions");
    buffer.description.tracerPid = std::numeric_limits<int>::max();
    check(state(buffer.description, TargetFeature::Debugger) == CapabilityState::Blocked &&
          state(buffer.description, TargetFeature::ReadMemory) == CapabilityState::Available,
          "another tracer blocks debugger operations independently of byte access");
    buffer.description.tracerPid = 0;
    buffer.description.transport = TargetTransport::CEServer;
    check(state(buffer.description, TargetFeature::LibraryInjection) == CapabilityState::Unsupported,
          "remote PIDs cannot select local library-injection helpers");
    buffer.description.live = false;
    check(state(buffer.description, TargetFeature::ReadMemory) == CapabilityState::Blocked,
          "exited target capabilities never remain available");
#if defined(__x86_64__)
    buffer.description={};buffer.description.live=true;
    buffer.description.transport=TargetTransport::Local;buffer.description.runtime=TargetRuntime::Native;
    buffer.description.host=buffer.description.program=*parseElfTarget(elf(EM_X86_64,false));
    check(state(buffer.description,TargetFeature::LibraryInjection)==CapabilityState::Partial &&
          state(buffer.description,TargetFeature::RemoteThread)==CapabilityState::Partial,
          "native x32 targets expose the supported loader and pthread backends");
    auto entry=os::nativeThreadEntry(buffer.description.host);
    auto control=os::nativeThreadControl(buffer.description.host,UINT32_MAX,UINT32_MAX);
    check(entry && entry->wordSize==4 && entry->suspendedStackBytes==24 && control &&
          control->size()==entry->dataSize() &&
          !os::nativeThreadControl(buffer.description.host,UINT64_C(0x100000000)) &&
          !os::nativeThreadControl(buffer.description.host,1,UINT64_C(0x100000000)),
          "x32 worker pointers remain four-byte values despite its 64-bit call stack");
#endif
}

static void instructionTests() {
    for (const auto& [arch,nop]:std::array<std::pair<Arch,std::vector<uint8_t>>,3>{
            {{Arch::ARM64,{0x1f,0x20,0x03,0xd5}}, {Arch::ARM32,{0,0xf0,0x20,0xe3}},
             {Arch::ARM32_BE,{0xe3,0x20,0xf0,0}}}}) {
        Disassembler dis(arch);std::vector<uint8_t> bytes(4,0xff);
        bytes.insert(bytes.end(),nop.begin(),nop.end());bytes.push_back(0xff);
        const auto decoded=dis.disassemble(0x1000,bytes,0,true);
        check(decoded.size()==3 && decoded[0].mnemonic=="db" && decoded[0].size==4 &&
              decoded[0].bytes==std::vector<uint8_t>(4,0xff) && decoded[1].mnemonic=="nop" &&
              decoded[1].address==0x1004 && decoded[2].size==1 && decoded[2].bytes==std::vector<uint8_t>{0xff},
              "invalid ARM words preserve the next instruction boundary and exact short trailing bytes");
    }
    for (const auto& [arch,bytes]:std::array<std::pair<Arch,std::vector<uint8_t>>,2>{
            {{Arch::ARMThumb,{0xff,0xff,0xff,0xff,0,0xbf,0xff}}, {Arch::ARMThumb_BE,{0xff,0xff,0xff,0xff,0xbf,0,0xff}}}}) {
        Disassembler dis(arch);const auto decoded=dis.disassemble(0x1000,bytes,0,true);
        check(decoded.size()==3 && decoded[0].mnemonic=="db" && decoded[0].size==4 &&
              decoded[1].mnemonic=="nop" && decoded[1].address==0x1004 && decoded[2].size==1,
              "invalid wide Thumb encodings do not decode their second halfword as another instruction");
    }
    {
        Disassembler dis(Arch::X86_64);const std::array<uint8_t,2> bytes{0x0f,0x90};
        const auto decoded=dis.disassemble(0x1000,bytes,0,true);
        check(decoded.size()==2 && decoded[0].mnemonic=="db" && decoded[0].size==1 && decoded[1].mnemonic=="nop",
              "x86 invalid-byte fallback still resumes at the next byte");
    }
    Assembler x64(AsmArch::X86_64);
    auto block = x64.assemble("entry:\nmov rcx,qword [0x402038]\nmov rdx,qword [rel 0x402030]\ncmp dword [0x402024],0\nret", 0x401000);
    Disassembler decoder(Arch::X86_64);
    auto decoded = block ? decoder.disassemble(0x401000, *block) : std::vector<Instruction>{};
    check(decoded.size() == 4 && decoded[0].ripTarget == 0x402038 && decoded[1].ripTarget == 0x402030 && decoded[2].ripTarget == 0x402024,
          "x64 absolute and relative memory operands retain their destinations in labeled assembly blocks");
    auto decimal = x64.assemble("mov rcx,qword [4202496]", 0x401000);
    auto decimalInstruction = decimal ? decoder.disassembleOne(0x401000, *decimal) : std::nullopt;
    check(decimalInstruction && decimalInstruction->ripTarget == 4202496,
          "bare numeric assembly operands preserve NASM decimal semantics");
    for (const auto& pair : std::array<std::pair<Arch, std::vector<uint8_t>>, 4>{
        {{Arch::ARM32, {0x00, 0xf0, 0x20, 0xe3}}, {Arch::ARM32_BE, {0xe3, 0x20, 0xf0, 0x00}},
         {Arch::ARMThumb, {0x00, 0xbf}}, {Arch::ARM64, {0x1f, 0x20, 0x03, 0xd5}}}}) {
        try {
            Disassembler dis(pair.first);
            auto insn = dis.disassembleOne(0x1000, pair.second);
            check(insn && insn->mnemonic == "nop" && insn->size == pair.second.size(),
                  "ARM/Thumb instruction decoding matches independent fixed bytes");
            Assembler assembler(assemblerArchFor(pair.first));
            auto encoded = assembler.assemble("nop", 0x1000);
            check(encoded && *encoded == pair.second, "ARM/Thumb assembly uses the selected instruction encoding");
        } catch (const std::exception& e) {
            std::printf("backend error: %s\n", e.what());
            check(false, "required ARM instruction backend is present");
        }
    }
}

static void luaTests() {
    TargetBuffer buffer;
    buffer.description.host = *parseElfTarget(elf(EM_X86_64, true));
    buffer.description.program = *parseElfTarget(elf(EM_PPC, false, true));
    LuaEngine lua; lua.setProcess(&buffer);
    check(lua.execute("assert(writeInteger(0x10010,0x12345678)); assert(readInteger(0x10010)==0x12345678); "
                      "assert(writePointer(0x10020,0x10200)); assert(readPointer(0x10020)==0x10200); "
                      "assert(getPointerSize()==4); assert(getTargetInfo().program.pointerWidth==4); "
                      "assert(getTargetCapabilities()['injection template / hook'].state=='unsupported')").empty() &&
          buffer.bytes[16] == 0x12 && buffer.bytes[19] == 0x78 && buffer.bytes[33] == 1,
          "Lua scalar and pointer APIs share target ABI and byte-order semantics");
    check(lua.execute("assert(writeValue(0x10010,'i32','0x12345678',{bigEndian=false})); "
                      "assert(readValue(0x10010,'i32',{bigEndian=false})=='305419896')").empty() && buffer.bytes[16] == 0x78,
          "Lua explicit little-endian selection overrides big-endian target data");
    check(localTargetPid(&buffer)==getpid(),"host-only operations retain an actual live local process PID");
    const std::string hostOnlyChecks="assert(unpause()==false); assert(pause()==false); assert(getProcessDir()==''); "
        "local result,err=branchMap(0); assert(result==nil and string.find(err,'local'))";
    for (auto transport:{TargetTransport::CEServer,TargetTransport::Gdb,TargetTransport::Unknown}) {
        buffer.description.transport=transport;
        check(!localTargetPid(&buffer) && lua.execute(hostOnlyChecks).empty(),
              "remote or unknown identifiers matching a real host PID cannot select host signals, proc paths or perf sampling");
    }
    buffer.description.transport=TargetTransport::Local;buffer.description.live=false;
    check(!localTargetPid(&buffer) && lua.execute(hostOnlyChecks).empty(),
          "an exited local target cannot select host signals, proc paths or perf sampling");
}

static void recoveryTests() {
    TargetBuffer buffer;
    buffer.description.host = buffer.description.program = *parseElfTarget(elf(EM_X86_64, true));
    AutoAssembler assembler;
    auto enabled = assembler.execute(buffer, "alloc(cave,100)\n0x10010:\ndb AA BB CC DD\n");
    check(enabled.success && buffer.bytes[16] == 0xaa, "recovery fixture activates a real patch");
    buffer.rejectWrites = true;
    auto disabled = assembler.disable(buffer, "", enabled.disableInfo);
    check(!disabled.success && !disabled.disableInfo.originals.empty() && buffer.frees == 0 &&
          buffer.bytes[16] == 0xaa, "failed byte restoration retains recovery state and keeps cave allocations alive");
    buffer.rejectWrites = false; buffer.shortWrites = true;
    disabled = assembler.disable(buffer, "", disabled.disableInfo);
    check(!disabled.success && buffer.bytes[19] == 0xdd && buffer.frees == 0,
          "short restoration writes cannot masquerade as successful cleanup");
    buffer.shortWrites = false; buffer.rejectFree = true;
    disabled = assembler.disable(buffer, "", disabled.disableInfo);
    check(!disabled.success && disabled.disableInfo.originals.empty() && disabled.disableInfo.allocs.size() == 1 &&
          buffer.bytes[16] == 0xcc && buffer.bytes[19] == 0xcc,
          "failed deallocation reports pending resources after verifying restored bytes");
    buffer.rejectFree = false;
    auto complete = assembler.disable(buffer, "", disabled.disableInfo);
    check(complete.success && complete.disableInfo.allocs.empty(), "partial cleanup can be retried to completion");
    auto overlap = assembler.execute(buffer, "0x10020:\ndb 11 22 33 44\n0x10022:\ndb AA BB\n");
    auto restored = assembler.disable(buffer, "", overlap.disableInfo);
    check(overlap.success && restored.success && buffer.bytes[32] == 0xcc && buffer.bytes[35] == 0xcc,
          "overlapping patches restore and verify the pre-enable image in reverse order");
    buffer.protection = MemProt::Read;
    auto access = assembler.execute(buffer, "FULLACCESS(0x10020,4)\nFULLACCESS(0x10030,4)\n0x10020:\ndb 11 22 33 44\n");
    check(access.success && access.disableInfo.protections.size() == 2,
          "FULLACCESS records original protections for every changed range");
    buffer.rejectedProtectionChanges = 1;
    auto partialProtection = assembler.disable(buffer, "", access.disableInfo);
    check(!partialProtection.success && buffer.bytes[32] == 0xcc && buffer.protection == MemProt::Read,
          "partial protection restoration retains retry state after restoring original bytes");
    buffer.rejectWrites = true;
    auto writesBeforeRetry = buffer.writes;
    auto protectionRetry = assembler.disable(buffer, "", partialProtection.disableInfo);
    check(protectionRetry.success && buffer.writes == writesBeforeRetry && buffer.protection == MemProt::Read,
          "cleanup retries already-restored read-only bytes without writing them again");
    buffer.rejectWrites = false;
    auto failedAccess = assembler.execute(buffer, "FULLACCESS(0x10020,4)\nassert(0x10020,11)\n");
    check(!failedAccess.success && failedAccess.disableInfo.protections.empty() && buffer.protection == MemProt::Read,
          "failed activation rolls back FULLACCESS page permissions");
    buffer.protection = MemProt::ReadWrite;
    buffer.description.program = *parseElfTarget(elf(EM_PPC, false, true));
    auto endian = assembler.execute(buffer, "0x10030:\ndd 12345678\n");
    check(endian.success && buffer.bytes[48] == 0x12 && buffer.bytes[51] == 0x78,
          "raw auto-assembler data directives honor non-x86 target byte order");
    check(assembler.disable(buffer, "", endian.disableInfo).success, "non-x86 data patches clean up without an instruction backend");
    buffer.description.program = *parsePeTarget(pe(0x14c, false));
    buffer.description.runtime = TargetRuntime::Wine;
    buffer.extraModules = {{buffer.base + 0x4000, 0x1000, "native.so", "", true, buffer.description.host}};
    auto mixed = assembler.execute(buffer, "alloc(cave,100,native.so)\ncave:\nmov rax,0x1122334455667788\n");
    check(mixed.success && buffer.bytes[0x8000] == 0x48 && buffer.bytes[0x8001] == 0xb8,
          "mixed-code caves inherit the preferred module's architecture instead of the program default");
    check(assembler.disable(buffer, "", mixed.disableInfo).success, "mixed-code cave cleanup succeeds");

    buffer.description.program = buffer.description.host;
    buffer.description.runtime = TargetRuntime::Native;
    buffer.protection = MemProt::ReadWrite;
    auto first = assembler.execute(buffer, "alloc(sharedcave,100)\nregistersymbol(sharedcave)\nsharedcave:\ndb 11 22\n");
    const auto saved = first.disableInfo;
    check(first.success && assembler.disable(buffer, "", saved).success,
          "an owned allocation and its symbols disable once");
    auto second = assembler.execute(buffer, "alloc(sharedcave,100)\nregistersymbol(sharedcave)\nsharedcave:\ndb 33 44\n");
    const auto writes = buffer.writes, frees = buffer.frees;
    auto replay = assembler.disable(buffer, "", saved);
    check(second.success && replay.success && buffer.writes == writes && buffer.frees == frees &&
          buffer.bytes[0x8000] == 0x33 && assembler.resolveSymbol("sharedcave") == buffer.base + 0x8000,
          "a completed undo copy cannot restore bytes, free a reused cave or remove its new symbol owner");
    check(assembler.disable(buffer, "", second.disableInfo).success,
          "the replacement allocation keeps its own usable undo lease");

    auto released = assembler.execute(buffer, "alloc(releasedcave,100)\nreleasedcave:\ndb 11 22\ndealloc(releasedcave)\n");
    buffer.bytes[0x8000] = 0x55;
    const auto beforeWrites = buffer.writes, beforeFrees = buffer.frees;
    auto releaseUndo = assembler.disable(buffer, "", released.disableInfo);
    check(released.success && releaseUndo.success && buffer.writes == beforeWrites && buffer.frees == beforeFrees &&
          buffer.bytes[0x8000] == 0x55,
          "same-script DEALLOC retains released ownership and never restores cave bytes into reused storage");

    auto deallocSource = assembler.execute(buffer, "alloc(dealloccave,100)\ndealloccave:\ndb 66\n");
    auto explicitFree = assembler.execute(buffer, "dealloc(dealloccave)\n");
    auto reused = assembler.execute(buffer, "alloc(dealloccave,100)\ndealloccave:\ndb 77\n");
    const auto freeWrites = buffer.writes, freeFrees = buffer.frees;
    check(deallocSource.success && explicitFree.success && reused.success &&
          assembler.disable(buffer, "", deallocSource.disableInfo).success &&
          buffer.writes == freeWrites && buffer.frees == freeFrees && buffer.bytes[0x8000] == 0x77,
          "cross-script DEALLOC shares its released lease with old undo while a reused allocation remains owned");
    check(assembler.disable(buffer, "", reused.disableInfo).success,
          "cross-script reuse cleans up through the new allocation lease");

    buffer.rejectFree = true;
    auto rejectedDealloc = assembler.execute(buffer, "alloc(failedcave,100)\nfailedcave:\ndb 12\ndealloc(failedcave)\n");
    check(!rejectedDealloc.success && rejectedDealloc.error.find("already in progress") == std::string::npos &&
          !rejectedDealloc.disableInfo.allocs.empty() && buffer.bytes[0x8000] == 0x66,
          "failed same-script DEALLOC releases its mutex before rolling back bytes and retains the failed free");
    buffer.rejectFree = false;
    check(assembler.disable(buffer, "", rejectedDealloc.disableInfo).success,
          "failed same-script DEALLOC can finish recovery on retry");

    auto owner = assembler.execute(buffer,"alloc(externalcave,100)\nregistersymbol(externalcave)\n");
    auto borrower = assembler.execute(buffer,"externalcave:\ndb 88\n");
    const bool freedOwner = assembler.disable(buffer,"",owner.disableInfo).success;
    buffer.bytes[0x8000] = 0x99;
    const auto borrowedWrites = buffer.writes;
    auto borrowerUndo = assembler.disable(buffer,"",borrower.disableInfo);
    const bool borrowedLifetime = owner.success && borrower.success && freedOwner && borrowerUndo.success &&
          buffer.bytes[0x8000]==0x99 && buffer.writes==borrowedWrites;
    if (!borrowedLifetime)
        std::printf("Borrowed cave: owner=%d (%s), borrower=%d (%s), freed=%d, undo=%d (%s), value=%02x, writes=%d/%d\n",
                    owner.success,owner.error.c_str(),borrower.success,borrower.error.c_str(),freedOwner,
                    borrowerUndo.success,borrowerUndo.error.c_str(),buffer.bytes[0x8000],borrowedWrites,buffer.writes);
    check(borrowedLifetime,
          "a patch in another script's cave shares allocation lifetime and never undoes into recycled storage");

    buffer.throwAfterWrite = true;
    const auto exceptionFrees = buffer.frees;
    auto exception = assembler.execute(buffer,"alloc(exceptioncave,100)\n0x10050:\ndb 12 34\n");
    check(!exception.success && exception.disableInfo.originals.empty() && exception.disableInfo.allocs.empty() &&
          buffer.bytes[80]==0xcc && buffer.bytes[81]==0xcc && buffer.frees==exceptionFrees+1,
          "an adapter exception after byte mutation still restores the original image and releases its saved allocation");

    buffer.protection = MemProt::Read | MemProt::Exec;
    auto ownedCode = assembler.execute(buffer, "0x10040:\ndb 11 22\n0x10041:\ndb 33\n");
    buffer.bytes[64] = 0x55;
    const auto conflictWrites = buffer.writes;
    auto conflictUndo = assembler.disable(buffer, "", ownedCode.disableInfo);
    check(ownedCode.success && !conflictUndo.success && buffer.writes == conflictWrites && buffer.bytes[64] == 0x55 &&
          !conflictUndo.disableInfo.originals.empty(),
          "changed executable bytes reject the entire undo before mutation and retain saved ownership");
    buffer.bytes[64] = 0x11;
    buffer.bytes[65] = 0x22;
    check(assembler.disable(buffer, "", conflictUndo.disableInfo).success && buffer.bytes[64] == 0xcc && buffer.bytes[65] == 0xcc,
          "owned intermediate overlapping code states remain recoverable after a partial undo");
    auto mutableStorage = assembler.execute(buffer,"0x10040:\nmov eax,0x11\n0x10060:\ndq 0\n");
    buffer.bytes[96] = 0x21;
    check(mutableStorage.success && assembler.disable(buffer,"",mutableStorage.disableInfo).success &&
          buffer.bytes[64]==0xcc && buffer.bytes[96]==0xcc,
          "mutable typed storage in an executable mapping does not block instruction and data undo");
}

static void stackFormatTests() {
    TargetBuffer buffer;
    const uintptr_t fp=buffer.base+0x100;
    auto word=[&](uintptr_t address,uint64_t value,unsigned width,ByteOrder order) {
        for (unsigned i=0;i<width;++i)
            buffer.bytes[address-buffer.base+i]=value>>(8*(order==ByteOrder::Big ? width-i-1 : i));
    };
    CpuContext context{};
    context.architecture=CpuArchitecture::Arm64;
    context.pc=buffer.base+0x20; context.sp=buffer.base+0x80; context.x[29]=fp;
    buffer.description.program=*parseElfTarget(elf(EM_AARCH64,true,true));
    word(fp,fp+0x20,8,ByteOrder::Big); word(fp+8,buffer.base+0x40,8,ByteOrder::Big);
    word(fp+0x20,0,8,ByteOrder::Big); word(fp+0x28,buffer.base+0x60,8,ByteOrder::Big);
    auto frames=buildStackTrace(buffer,context);
    check(frames.size()==3 && frames[0].instructionPointer==context.pc && frames[0].stackPointer==context.sp &&
          frames[1].instructionPointer==buffer.base+0x40 && frames[2].instructionPointer==buffer.base+0x60,
          "ARM64 frame chains use X29/PC/SP and decode target-endian saved registers");
    buffer.description.program=*parseElfTarget(elf(EM_X86_64,false));
    context={}; context.architecture=CpuArchitecture::X86_64;
    context.rip=buffer.base+0x20; context.rsp=buffer.base+0x80; context.rbp=fp;
    word(fp,fp+0x20,8,ByteOrder::Little); word(fp+8,0x1122334455,8,ByteOrder::Little);
    word(fp+0x20,0,8,ByteOrder::Little); word(fp+0x28,0x2233445566,8,ByteOrder::Little);
    frames=buildStackTrace(buffer,context);
    check(frames.size()==3 && frames[1].instructionPointer==0x1122334455 && frames[2].instructionPointer==0x2233445566,
          "x32 frame records retain 64-bit saved register slots despite 32-bit data pointers");
    buffer.description.program=*parseElfTarget(elf(EM_386,false));
    context.architecture=CpuArchitecture::X86_32;
    word(fp,0,4,ByteOrder::Little); word(fp+4,buffer.base+0x40,4,ByteOrder::Little);
    frames=buildStackTrace(buffer,context);
    check(frames.size()==2 && frames[1].instructionPointer==buffer.base+0x40,
          "i386 frame records use four-byte slots from the stopped instruction ISA");
    buffer.description.program.byteOrder=ByteOrder::Unknown;
    int reads=buffer.reads;
    frames=buildStackTrace(buffer,context);
    check(frames.size()==1 && buffer.reads==reads,"unknown stack byte order never becomes a host-endian guess");
    word(context.rsp,0x11223344,4,ByteOrder::Little);
    word(context.rsp+4,0x55667788,4,ByteOrder::Little);
    auto raw=readRawStack(buffer,context,ByteOrder::Little,2);
    check(raw.size()==2 && raw[0].available && raw[1].address==context.rsp+4 && raw[1].value==0x55667788,
          "i386 raw stack reads consecutive four-byte words");
    context.architecture=CpuArchitecture::X86_64;
    raw=readRawStack(buffer,context,ByteOrder::Little,1);
    check(raw.size()==1 && raw[0].width==8 && raw[0].value==0x5566778811223344ull,
          "x32 raw stack uses the register ISA width rather than its pointer ABI");
    context.architecture=CpuArchitecture::Arm64; context.sp=buffer.base+0x80;
    word(context.sp,0x0102030405060708ull,8,ByteOrder::Big);
    raw=readRawStack(buffer,context,ByteOrder::Big,1);
    check(raw.size()==1 && raw[0].value==0x0102030405060708ull,
          "ARM64 raw stack uses native SP and explicit target byte order");
    buffer.shortReads=true;
    raw=readRawStack(buffer,context,ByteOrder::Big,1);
    check(raw.size()==1 && !raw[0].available,"short raw stack reads never display partially initialized words");
    buffer.shortReads=false;
    context.sp=buffer.base+buffer.bytes.size()-4;
    raw=readRawStack(buffer,context,ByteOrder::Big,1);
    check(raw.size()==1 && !raw[0].available,"partial raw stack words are unavailable rather than zero values");
    context.sp=UINTPTR_MAX-7;
    raw=readRawStack(buffer,context,ByteOrder::Little,3);
    check(raw.size()==1,"raw stack address arithmetic never wraps to low memory");
    reads=buffer.reads;
    check(readRawStack(buffer,context,ByteOrder::Unknown).empty() &&
          readRawStack(buffer,context,ByteOrder::Little,4097).empty() && buffer.reads==reads,
          "raw stack rejects unknown byte order and excessive requests before reading");

}

static void registerTests() {
    Disassembler nativeDecoder;
    check(nativeDecoder.arch() == *disassemblerArchFor(nativeTargetMachine()),
          "unattached views initialize a decoder for the engine's native ISA");
    CpuContext ctx{};
    check(cpuRegisterValues(ctx).empty() && !setCpuRegisterValue(ctx, 0, 1),
          "unknown register ISA never invents an editable bank");
    ctx.architecture = CpuArchitecture::X86_32;
    ctx.rax = 0x100000005;
    auto regs = cpuRegisterValues(ctx);
    check(regs.size() == 10 && regs[0].name == "EIP" && regs[3].value == 5 && regs[3].bits == 32,
          "i386 register view uses architectural names and width");
    check(!setCpuRegisterValue(ctx, 3, 0x100000000) && ctx.rax == 0x100000005 &&
          !setCpuRegisterValue(ctx, 10, 1), "i386 edits reject overflow and nonexistent R8");
    check(setCpuRegisterValue(ctx, 3, 7) &&
          !evaluateBreakpointCondition("EAX == 8", ctx, 0) &&
          evaluateBreakpointCondition("EAX == 7 and ctx.eax == 7", ctx, 0),
          "i386 condition expressions see EAX in globals and context");
    ctx = {}; ctx.architecture = CpuArchitecture::X86_64;
    check(cpuRegisterValues(ctx).size() == 18 && setCpuRegisterValue(ctx, 17, UINT64_MAX) &&
          ctx.r15 == UINT64_MAX, "x86-64 exposes and edits the complete general register bank");
    ctx = {}; ctx.architecture = CpuArchitecture::Arm64;
    ctx.pc = 0x1000; ctx.sp = 0x2000; ctx.x[29] = 0x3000; ctx.x[30] = 0x4000;
    ctx.pstate = 0xb0000000;
    regs = cpuRegisterValues(ctx);
    bool arm = regs.size() == 34 && regs[0].name == "PC" && regs[1].name == "SP" &&
               regs[2].name == "X29" && regs[3].name == "X30" && regs[33].name == "PSTATE";
    for (size_t row = 0; row < regs.size(); ++row) {
        const uint64_t value = 0x1234000000000000 + row;
        arm = arm && setCpuRegisterValue(ctx, row, value) && cpuRegisterValues(ctx)[row].value == value;
    }
    check(arm && ctx.rip == 0 && ctx.rsp == 0 && !setCpuRegisterValue(ctx, 34, 1),
          "all ARM64 PC/SP/X0-X30/PSTATE edits use native fields, without x86 aliases");
    ctx.x[0] = 5; ctx.pstate = 0xb0000000;
    check(describeCpuStatusFlags(ctx) == "N=1 Z=0 C=1 V=1",
          "ARM64 flags decode NZCV from PSTATE");
    check(evaluateBreakpointCondition("X0 == 5 and x0 == ctx.x0 and PC == ctx.pc and FP == ctx.x29 and LR == ctx.x30", ctx, ctx.pc) &&
          !evaluateBreakpointCondition("X0 == 6", ctx, ctx.pc) &&
          evaluateBreakpointCondition("RAX == nil and ctx.rax == nil", ctx, ctx.pc),
          "ARM64 conditions expose real registers and never fabricate x86 values");
    ctx = {}; ctx.architecture = CpuArchitecture::Arm32;
    ctx.pc = 0x1000; ctx.sp = 0x2000; ctx.x[11] = 0x3000; ctx.x[14] = 0x4000;
    ctx.x[0] = 0x100000005; ctx.pstate = 0xa8000020;
    regs = cpuRegisterValues(ctx);
    check(regs.size() == 17 && regs[0].name == "PC" && regs[1].name == "SP" && regs[2].name == "R11" &&
          regs[3].name == "LR" && regs[4].name == "R0" && regs[4].value == 5 && regs[16].name == "CPSR" &&
          ctx.instructionPointer() == 0x1000 && ctx.stackPointer() == 0x2000 && ctx.framePointer() == 0x3000,
          "ARM32 register views expose native names, width and generic PC/SP/FP fields");
    check(setCpuRegisterValue(ctx, 3, 0xf1234567) && ctx.x[14] == 0xf1234567 &&
          setCpuRegisterValue(ctx, 15, 0x89abcdef) && ctx.x[12] == 0x89abcdef &&
          !setCpuRegisterValue(ctx, 15, UINT64_C(0x100000000)) && ctx.x[12] == 0x89abcdef &&
          !setCpuRegisterValue(ctx, 17, 1) && ctx.rip == 0 && ctx.rsp == 0,
          "ARM32 LR/R12 edits reject overflow and nonexistent rows without inventing x86 aliases");
    check(describeCpuStatusFlags(ctx) == "N=1 Z=0 C=1 V=0 Q=1 T=1 E=0",
          "ARM32 CPSR flags include Q, ARM/Thumb state and data endianness");
    check(evaluateBreakpointCondition("R0 == 5 and R13 == SP and R14 == LR and R15 == PC and FP == R11 and CPSR == ctx.cpsr and ctx.r14 == LR and RAX == nil and ctx.rax == nil", ctx, ctx.pc),
          "ARM32 Lua breakpoint conditions expose real registers and aliases without x86 values");
    CpuContext armModeChanged = ctx; armModeChanged.pstate ^= 0x20;
    std::vector<uint64_t> armValues; for (const auto& r : cpuRegisterValues(ctx)) armValues.push_back(r.value);
    check(!mergeCpuRegisterEdits(armModeChanged, ctx, armValues),
          "ARM32 edits reject a changed ARM/Thumb instruction state even with the same CPU architecture");
    for (auto architecture : {CpuArchitecture::X86_32,CpuArchitecture::X86_64,CpuArchitecture::Arm64,CpuArchitecture::Arm32}) {
        CpuContext displayed{}; displayed.architecture=architecture;
        displayed.rip=displayed.pc=0x1000; displayed.rsp=displayed.sp=0x2000;
        CpuContext live=displayed;
        live.rip=live.pc=0x3000; live.rsp=live.sp=0x4000; live.rflags=0x246;
        live.rbx=live.x[1]=0x9876; live.cs=0x33; live.dr7=0x400;
        std::vector<uint64_t> values;
        for (const auto& reg : cpuRegisterValues(displayed)) values.push_back(reg.value);
        const size_t row=displayed.hasArmRegisters() ? 4 : 3;
        values[row]=0x1234;
        auto merged=mergeCpuRegisterEdits(live,displayed,values);
        check(merged && merged->instructionPointer()==0x3000 && merged->stackPointer()==0x4000 &&
              merged->rflags==0x246 && merged->rbx==0x9876 && merged->x[1]==0x9876 &&
              merged->cs==0x33 && merged->dr7==0x400 && cpuRegisterValues(*merged)[row].value==0x1234,
              "register edits preserve fresh PC/SP and all unedited kernel registers in every supported ISA");
        values.pop_back();
        check(!mergeCpuRegisterEdits(live,displayed,values),"incomplete register snapshots cannot overwrite a thread");
        live.architecture=CpuArchitecture::Unknown;
        check(!mergeCpuRegisterEdits(live,displayed,values),"register edits reject a changed thread execution mode");
    }
    CpuContext narrow{}; narrow.architecture=CpuArchitecture::X86_32;
    std::vector<uint64_t> invalid(10); invalid[3]=0x100000000ull;
    check(!mergeCpuRegisterEdits(narrow,narrow,invalid) && narrow.rax==0,
          "overflowing register edits fail without altering the source context");
    bool conditions = true;
    for (unsigned nzcv = 0; nzcv < 16; ++nzcv) {
        bool n = nzcv & 8, z = nzcv & 4, c = nzcv & 2, v = nzcv & 1;
        const std::pair<const char*, bool> cases[] = {
            {"b.eq", z}, {"b.ne", !z}, {"b.hs", c}, {"b.lo", !c},
            {"b.mi", n}, {"b.pl", !n}, {"b.vs", v}, {"b.vc", !v},
            {"b.hi", c && !z}, {"b.ls", !c || z}, {"b.ge", n == v},
            {"b.lt", n != v}, {"b.gt", !z && n == v}, {"b.le", z || n != v},
            {"b.al", true}, {"b.nv", true}
        };
        for (const auto& [name, expected] : cases)
            conditions = conditions && conditionalArm64JumpTaken(name, uint64_t(nzcv) << 28) == expected;
    }
    check(conditions && !conditionalArm64JumpTaken("cbz", ctx.pstate).has_value(),
          "ARM64 branch hints cover every NZCV combination without guessing register-testing branches");
}

static void lifecycleTests() {
    os::LinuxProcessHandle self(getpid());
    auto d = self.targetDescription();
    check(d.live && d.program == d.host && d.host.architecture == nativeTargetMachine().architecture,
          "live process metadata comes from its actual executable");
    int pipefd[2];
    if (pipe(pipefd)) { check(false, "lifecycle pipe"); return; }
    pid_t child = fork();
    if (!child) { close(pipefd[1]); char c; (void)::read(pipefd[0], &c, 1); _exit(0); }
    close(pipefd[0]);
    if (child < 0) { close(pipefd[1]); check(false, "lifecycle child"); return; }
    os::LinuxProcessHandle process(child);
    check(process.targetDescription().live, "live child identity is inspectable");
    close(pipefd[1]); int status; waitpid(child, &status, 0);
    uint64_t value = 0;
    auto read = process.read(reinterpret_cast<uintptr_t>(&value), &value, sizeof(value));
    auto write = process.write(reinterpret_cast<uintptr_t>(&value), &value, sizeof(value));
    check(!read && !write && read.error() == std::errc::no_such_process &&
          !process.targetDescription().live, "old handles reject reads and writes after target exit");
}


#include "scanner_format_checks.inc"
#include "perf_ring_checks.inc"
#include "all_type_scan_checks.inc"
#include "all_type_number_checks.inc"
#include "floating_rounding_checks.inc"
#include "scanner_failure_checks.inc"
#include "value_format_override_checks.inc"
#include "aarch64_relocation_checks.inc"
#include "code_write_checks.inc"
#include "mono_lifecycle_checks.inc"

int main() {
    machineTests(); dataTests(); scannerFormatTests(); highAddressScanTests(); perfRingTests(); allTypeScanTests(); allTypeNumberTests(); floatingRoundingTests(); scannerFailureTests(); valueFormatOverrideTests(); aarch64RelocationTests(); codeWriteTests(); capabilityTests(); instructionTests(); luaTests(); recoveryTests(); stackFormatTests(); registerTests(); lifecycleTests(); monoLifecycleTests();
    std::printf("%d failed compatibility checks\n", failures);
    return failures ? 1 : 0;
}
