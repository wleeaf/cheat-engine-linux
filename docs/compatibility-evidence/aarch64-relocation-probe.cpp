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
#include "scanner/pointer_scanner.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <limits>
#include <sys/wait.h>
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

class TargetBuffer final : public ProcessHandle {
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
        std::memcpy(bytes.data() + address - memoryBase, buffer, n); return n;
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

int main() {
    TargetBuffer process;
    process.description.host=process.description.program=*parseElfTarget(elf(EM_AARCH64,true));
    const unsigned char nop[]={0x1f,0x20,0x03,0xd5};
    std::copy(std::begin(nop),std::end(nop),process.bytes.begin());
    const auto before=process.bytes;
    AutoAssembler assembler;
    auto result=assembler.execute(process,"[ENABLE]\nlabel(after)\n0x10000:\ndb 00 00 00 10\n0x11000:\ndd after\nreassemble(0x10000)\nafter:\ndb AB CD\n");
    std::printf("success=%d restored=%d error=%s destination=",result.success,process.bytes==before,result.error.c_str());
    for (size_t at=0x1000;at<0x1016;++at) std::printf("%02x",process.bytes[at]);
    std::puts("");
    return result.success ? 1 : 0;
}
