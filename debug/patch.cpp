#include "core/target_capabilities.hpp"
#include "arch/target_arch.hpp"
#include "debug/patch.hpp"
#include "arch/disassembler.hpp"
#include <algorithm>

namespace ce {

std::expected<std::vector<uint8_t>,std::string> nopBytesFor(
    ProcessHandle& proc,uintptr_t address,size_t size) {
    auto architecture=disassemblerArchFor(proc,address);
    if (!architecture) return std::unexpected(architecture.error());
    if (!size || size-1>UINTPTR_MAX-address) return std::unexpected("Empty or overflowing NOP range");
    if (*architecture==Arch::X86_32 || *architecture==Arch::X86_64)
        return std::vector<uint8_t>(size,0x90);
    if (*architecture==Arch::ARM64 && address%4==0 && size%4==0) {
        std::vector<uint8_t> bytes;bytes.reserve(size);
        for (size_t at=0;at<size;at+=4) bytes.insert(bytes.end(),{0x1f,0x20,0x03,0xd5});
        return bytes;
    }
    return std::unexpected("No verified NOP encoding for this instruction architecture/alignment");
}

std::expected<std::vector<uint8_t>,std::string> patchInstructionBytes(
    ProcessHandle& proc,uintptr_t address,std::span<const uint8_t> bytes) {
    if (bytes.empty() || bytes.size()-1>UINTPTR_MAX-address)
        return std::unexpected("Empty or overflowing code patch");
    std::vector<uint8_t> original(bytes.size()),actual(bytes.size());
    auto read=proc.read(address,original.data(),original.size());
    if (!read || *read!=original.size()) return std::unexpected("Cannot read complete original code bytes");
    auto written=proc.writeCode(address,bytes.data(),bytes.size());
    read=proc.read(address,actual.data(),actual.size());
    if (written && *written==bytes.size() && read && *read==actual.size() && std::equal(actual.begin(),actual.end(),bytes.begin()))
        return original;
    std::string detail=written ? "Code-write verification failed" : "Code write failed: "+written.error().message();
    if (!written && (written.error()==std::errc::operation_canceled || written.error()==std::errc::no_such_process))
        return std::unexpected(detail+"; the original process image retired, no undo bytes were replayed");
    if (!written && written.error()==std::errc::state_not_recoverable)
        return std::unexpected(detail+"; original-byte restoration is pending, retry native recovery before continuing");
    if (read && *read==actual.size() && actual==original)
        return std::unexpected(detail);
    auto restored=proc.writeCode(address,original.data(),original.size());
    read=proc.read(address,actual.data(),actual.size());
    const bool safe=restored && *restored==original.size() && read && *read==actual.size() && actual==original;
    if (!safe) detail+="; original-byte restoration is incomplete, retry native recovery before continuing";
    return std::unexpected(detail);
}

std::vector<uint8_t> nopInstruction(ProcessHandle& proc, uintptr_t address) {
    auto arch = disassemblerArchFor(proc, address);
    if (!arch) return {};
    uint8_t buf[16];
    auto rr = proc.read(address, buf, sizeof(buf));
    if (!rr || *rr == 0) return {};

    Disassembler dis(*arch);
    auto insns = dis.disassemble(address, {buf, *rr}, 1);
    if (insns.empty() || insns[0].size == 0) return {};

    const size_t n = insns[0].size;
    auto nops=nopBytesFor(proc,address,n);
    if (!nops) return {};
    auto patched=patchInstructionBytes(proc,address,*nops);
    return patched ? std::move(*patched) : std::vector<uint8_t>{};
}

bool restoreBytes(ProcessHandle& proc, uintptr_t address,
                  const std::vector<uint8_t>& original) {
    if (original.empty()) return false;
    auto wr = proc.writeCode(address, original.data(), original.size());
    return wr && *wr == original.size();
}

} // namespace ce
