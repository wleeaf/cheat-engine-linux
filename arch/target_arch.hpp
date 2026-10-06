#pragma once

#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "platform/process_api.hpp"
#include <expected>

namespace ce {

std::expected<Arch, std::string> disassemblerArchFor(const TargetMachine& machine);
std::expected<Arch, std::string> disassemblerArchFor(ProcessHandle& process, uintptr_t address = 0);
AsmArch assemblerArchFor(Arch arch);

} // namespace ce
