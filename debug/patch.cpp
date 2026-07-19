#include "debug/patch.hpp"
#include "arch/disassembler.hpp"

namespace ce {

std::vector<uint8_t> nopInstruction(ProcessHandle& proc, uintptr_t address) {
    uint8_t buf[16];
    auto rr = proc.read(address, buf, sizeof(buf));
    if (!rr || *rr == 0) return {};

    Disassembler dis(proc.runs32BitCode() ? Arch::X86_32 : Arch::X86_64);
    auto insns = dis.disassemble(address, {buf, *rr}, 1);
    if (insns.empty() || insns[0].size == 0) return {};

    const size_t n = insns[0].size;
    std::vector<uint8_t> original(buf, buf + n);
    std::vector<uint8_t> nops(n, 0x90);
    auto wr = proc.write(address, nops.data(), n);
    if (!wr) return {};
    return original;
}

bool restoreBytes(ProcessHandle& proc, uintptr_t address,
                  const std::vector<uint8_t>& original) {
    if (original.empty()) return false;
    auto wr = proc.write(address, original.data(), original.size());
    return static_cast<bool>(wr);
}

} // namespace ce
