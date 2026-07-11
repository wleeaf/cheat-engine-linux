#pragma once
/// Code analysis — dissect modules for functions, strings, code caves.

#include "arch/assembler.hpp"
#include "platform/process_api.hpp"
#include "arch/disassembler.hpp"
#include "symbols/elf_symbols.hpp"
#include <vector>
#include <string>

namespace ce {

enum class RefType { Call, Jump, String, Function, RipRelative, AssemblyPattern };

struct CodeRef {
    uintptr_t address;      // Address of the instruction
    uintptr_t target;       // Target address (call/jump target, string address)
    RefType type;
    std::string text;       // Instruction text or string content
};

struct CodeCave {
    uintptr_t address;
    size_t size;
};

/// A static (i.e. module-relative or fixed) memory address referenced from
/// instructions inside the module's executable regions, with how many distinct
/// instructions read or write it. Distinct from RIP-relative scan results
/// which enumerate the instructions; find-statics groups by the target.
struct StaticAccess {
    uintptr_t address;   // Static address being read/written
    size_t    references;
};

struct FunctionInfo {
    uintptr_t address;
    size_t references;
};

struct CallGraphEdge {
    uintptr_t caller;
    uintptr_t callee;
    uintptr_t callSite;
};

class CodeAnalyzer {
public:
    /// Dissect a module — find all calls, jumps, string references.
    std::vector<CodeRef> dissectModule(ProcessHandle& proc, const ModuleInfo& module);

    /// Find referenced strings (LEA instructions pointing to readable data).
    std::vector<CodeRef> findReferencedStrings(ProcessHandle& proc, const ModuleInfo& module);

    /// Find direct call targets inside a module.
    std::vector<CodeRef> findReferencedFunctions(ProcessHandle& proc, const ModuleInfo& module);

    /// Enumerate functions by unique direct call targets.
    std::vector<FunctionInfo> enumerateFunctions(ProcessHandle& proc, const ModuleInfo& module);

    /// Build direct call graph edges from module call sites.
    std::vector<CallGraphEdge> buildCallGraph(ProcessHandle& proc, const ModuleInfo& module);

    /// Find direct conditional and unconditional jump targets inside a module.
    std::vector<CodeRef> findJumps(ProcessHandle& proc, const ModuleInfo& module);

    /// Find RIP-relative memory references inside executable module regions.
    std::vector<CodeRef> findRipRelativeInstructions(ProcessHandle& proc, const ModuleInfo& module);

    /// Assemble an instruction pattern and find exact byte matches in executable module regions.
    std::vector<CodeRef> findAssemblyPattern(ProcessHandle& proc, const ModuleInfo& module,
                                             const std::string& assembly);

    /// Find code caves (runs of 0x00 or 0xCC bytes).
    std::vector<CodeCave> findCodeCaves(ProcessHandle& proc, const ModuleInfo& module, size_t minSize = 16);

    /// Find static addresses (module-relative globals) referenced by code in
    /// the module. Aggregates RIP-relative references only (including the GOT
    /// slots reached by indirect PIC call/jmp), deduplicates by target address,
    /// sorts by reference count (highest first). Absolute-displacement memory
    /// operands ([imm] / [reg*scale + imm]) are NOT yet collected.
    std::vector<StaticAccess> findStatics(ProcessHandle& proc, const ModuleInfo& module);

    /// Find every instruction in `module` that references `target` — a call/jump
    /// to it, or a RIP-relative data access whose effective address is it. This
    /// is the disassembler's "find out what addresses reference this address".
    std::vector<CodeRef> findReferencesTo(ProcessHandle& proc, const ModuleInfo& module,
                                          uintptr_t target);

private:
    Disassembler disasm_{Arch::X86_64};
    Assembler assembler_{AsmArch::X86_64};
};

} // namespace ce
