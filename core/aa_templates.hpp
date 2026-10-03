#pragma once
/// Auto-assembler templates. Injection entries are generated from live code.

#include <cstdint>
#include <string>
#include <vector>

namespace ce {

enum class InjectionKind { None, Code, Aob, Full, Pointer };

struct AaTemplate {
    std::string name;        // Menu label
    std::string description; // One-line summary, shown as a tooltip
    std::string body;        // Static text for templates without an injection site
    InjectionKind injection = InjectionKind::None;
};

/// Returns the canonical template list, in CE's menu order.
const std::vector<AaTemplate>& builtinAaTemplates();

/// One disassembled instruction the injection will "steal" (relocate into the
/// cave). `text` is the ready-to-assemble mnemonic+operands (e.g. "mov [rax+8],ecx").
struct StolenInstruction {
    uintptr_t address = 0;
    std::string text;
    size_t size = 0;
    std::string label;       // Relocated destination for a branch inside the hook
};

/// Build a complete, ready-to-run code-injection AA script for `targetAddress`,
/// with the original instructions relocated into the cave and the original
/// bytes emitted as a `db` array for the [DISABLE] restore, the automatic
/// equivalent of CE's "Code injection" template. `originalBytes` must be the
/// exact bytes covered by `originalCode` (>= 5, so the 5-byte jmp fits); the
/// difference is padded with `nop`. A module name and offset make the hook
/// survive rebasing. This is pure string assembly (no process access) so it is
/// unit-testable.
std::string buildCodeInjectionScript(uintptr_t targetAddress,
                                     const std::vector<StolenInstruction>& originalCode,
                                     const std::vector<uint8_t>& originalBytes,
                                     const std::string& moduleLabel = "",
                                     uintptr_t moduleOffset = 0);

/// AOB-injection variant of the above: instead of a hard-coded address the hook
/// point is located with `aobscanmodule(INJECT, module, <signature>)` so the
/// script survives the module rebasing / game updates. `signature` is normally
/// the original bytes rendered as a hex AOB. Pure string assembly (testable).
/// `signatureOverride`, when non-empty, is used verbatim as the aobscanmodule
/// signature (e.g. a uniqueness-extended AOB from uniqueAobSignature); otherwise the
/// raw `originalBytes` are rendered as the signature.
std::string buildAobInjectionScript(const std::string& module,
                                    uintptr_t moduleOffset,
                                    const std::vector<StolenInstruction>& originalCode,
                                    const std::vector<uint8_t>& originalBytes,
                                    const std::string& signatureOverride = "");

} // namespace ce
