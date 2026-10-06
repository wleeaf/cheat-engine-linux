#include "core/cpu_registers.hpp"
#include "arch/cpu_flags.hpp"
#include <array>

namespace ce {
namespace {
using Member = uint64_t CpuContext::*;
constexpr std::array<Member, 18> x86Members{
    &CpuContext::rip, &CpuContext::rsp, &CpuContext::rbp,
    &CpuContext::rax, &CpuContext::rbx, &CpuContext::rcx,
    &CpuContext::rdx, &CpuContext::rsi, &CpuContext::rdi, &CpuContext::rflags,
    &CpuContext::r8, &CpuContext::r9, &CpuContext::r10, &CpuContext::r11,
    &CpuContext::r12, &CpuContext::r13, &CpuContext::r14, &CpuContext::r15
};
constexpr std::array<const char*, 18> x64Names{
    "RIP", "RSP", "RBP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RFLAGS",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"
};
constexpr std::array<const char*, 10> x32Names{
    "EIP", "ESP", "EBP", "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EFLAGS"
};
}

std::vector<CpuRegisterValue> cpuRegisterValues(const CpuContext& context) {
    std::vector<CpuRegisterValue> result;
    if (context.architecture == CpuArchitecture::Arm64) {
        result.reserve(34);
        result.push_back({"PC", context.pc, 64});
        result.push_back({"SP", context.sp, 64});
        result.push_back({"X29", context.x[29], 64});
        result.push_back({"X30", context.x[30], 64});
        for (size_t i = 0; i < 29; ++i)
            result.push_back({"X" + std::to_string(i), context.x[i], 64});
        result.push_back({"PSTATE", context.pstate, 64});
    } else if (context.architecture == CpuArchitecture::Arm32) {
        result.reserve(17);
        result.push_back({"PC", context.pc & UINT32_MAX, 32});
        result.push_back({"SP", context.sp & UINT32_MAX, 32});
        result.push_back({"R11", context.x[11] & UINT32_MAX, 32});
        result.push_back({"LR", context.x[14] & UINT32_MAX, 32});
        for (unsigned i = 0; i < 13; ++i) if (i != 11)
            result.push_back({"R" + std::to_string(i), context.x[i] & UINT32_MAX, 32});
        result.push_back({"CPSR", context.pstate & UINT32_MAX, 32});
    } else if (context.architecture == CpuArchitecture::X86_32 ||
               context.architecture == CpuArchitecture::X86_64) {
        bool narrow = context.architecture == CpuArchitecture::X86_32;
        size_t count = narrow ? x32Names.size() : x64Names.size();
        result.reserve(count);
        for (size_t i = 0; i < count; ++i)
            result.push_back({narrow ? x32Names[i] : x64Names[i],
                              context.*x86Members[i] & (narrow ? UINT32_MAX : UINT64_MAX),
                              narrow ? 32u : 64u});
    }
    return result;
}

bool setCpuRegisterValue(CpuContext& context, size_t row, uint64_t value) {
    if (context.architecture == CpuArchitecture::Arm32) {
        if (value > UINT32_MAX || row > 16) return false;
        if (row == 0) context.pc = value;
        else if (row == 1) context.sp = value;
        else if (row == 2) context.x[11] = value;
        else if (row == 3) context.x[14] = value;
        else if (row < 15) context.x[row - 4] = value;
        else if (row == 15) context.x[12] = value;
        else context.pstate = value;
        return true;
    }
    if (context.architecture == CpuArchitecture::Arm64) {
        if (row == 0) context.pc = value;
        else if (row == 1) context.sp = value;
        else if (row == 2) context.x[29] = value;
        else if (row == 3) context.x[30] = value;
        else if (row < 33) context.x[row - 4] = value;
        else if (row == 33) context.pstate = value;
        else return false;
        return true;
    }
    if (context.architecture != CpuArchitecture::X86_32 &&
        context.architecture != CpuArchitecture::X86_64) return false;
    if (context.architecture == CpuArchitecture::X86_32) {
        if (row >= x32Names.size() || value > UINT32_MAX) return false;
    } else if (row >= x64Names.size()) return false;
    context.*x86Members[row] = value;
    return true;
}

std::expected<CpuContext, std::string> mergeCpuRegisterEdits(
    const CpuContext& current, const CpuContext& displayed, std::span<const uint64_t> values) {
    if (current.architecture != displayed.architecture)
        return std::unexpected("Thread register mode changed; refresh before applying edits");
    if (current.architecture == CpuArchitecture::Arm32 && ((current.pstate ^ displayed.pstate) & 0x20))
        return std::unexpected("Thread ARM/Thumb mode changed; refresh before applying edits");
    auto registers = cpuRegisterValues(displayed);
    if (registers.empty() || registers.size() != values.size())
        return std::unexpected("Register snapshot is unavailable or incomplete");
    CpuContext merged = current;
    for (size_t row = 0; row < values.size(); ++row) {
        if (values[row] == registers[row].value) continue;
        if (!setCpuRegisterValue(merged, row, values[row]))
            return std::unexpected(registers[row].name + " requires a " + std::to_string(registers[row].bits) + "-bit value");
    }
    return merged;
}

std::string describeCpuStatusFlags(const CpuContext& context) {
    if (context.architecture == CpuArchitecture::Arm32) {
        std::string result;
        const char* names[] = {"N", "Z", "C", "V", "Q", "T", "E"};
        const unsigned bits[] = {31, 30, 29, 28, 27, 5, 9};
        for (unsigned i = 0; i < 7; ++i) {
            if (i) result += ' ';
            result += names[i]; result += '=';
            result += ((context.pstate >> bits[i]) & 1) ? '1' : '0';
        }
        return result;
    }
    if (context.architecture == CpuArchitecture::Arm64) {
        std::string result;
        const char* names[] = {"N", "Z", "C", "V"};
        for (unsigned i = 0; i < 4; ++i) {
            if (i) result += ' ';
            result += names[i]; result += '=';
            result += ((context.pstate >> (31 - i)) & 1) ? '1' : '0';
        }
        return result;
    }
    if (context.architecture == CpuArchitecture::X86_32 ||
        context.architecture == CpuArchitecture::X86_64)
        return describeEflagsVerbose(context.rflags);
    return {};
}
} // namespace ce
