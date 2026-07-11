/// Built-in AA script templates. Mirrors Cheat Engine's "Code Templates"
/// menu (frmautoinjectunit / Ctrl+I) so users coming from CE find familiar
/// boilerplate.
///
/// Placeholder tokens (`<modulename>`, `<aob>`, `<address>`, `<original
/// bytes>`, etc.) are intentionally left for the user to replace — CE
/// itself paints them in for the user to fill in by hand.

#include "core/aa_templates.hpp"

#include <cstdio>
#include <sstream>

namespace ce {

std::string buildCodeInjectionScript(uintptr_t targetAddress,
                                     const std::vector<StolenInstruction>& originalCode,
                                     const std::vector<uint8_t>& originalBytes,
                                     const std::string& moduleLabel) {
    char addrBuf[32];
    std::snprintf(addrBuf, sizeof(addrBuf), "%llx",
                  static_cast<unsigned long long>(targetAddress));
    const std::string addr = addrBuf;

    // The hook overwrites the stolen bytes with a 5-byte `jmp newmem` plus
    // `nop` padding so the instruction boundary after the hook is preserved.
    size_t nopCount = originalBytes.size() > 5 ? originalBytes.size() - 5 : 0;

    // Original bytes as a db array for the DISABLE restore.
    std::string dbBytes;
    for (size_t i = 0; i < originalBytes.size(); ++i) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02X", originalBytes[i]);
        if (i) dbBytes += ' ';
        dbBytes += b;
    }

    std::ostringstream s;
    s << "{ Code injection auto-generated for 0x" << addr;
    if (!moduleLabel.empty()) s << "  (" << moduleLabel << ")";
    s << "\n  " << originalBytes.size() << " byte(s) stolen; original code and"
         " bytes captured below. }\n\n";

    s << "[ENABLE]\n";
    s << "alloc(newmem,$1000,0x" << addr << ")\n";
    s << "label(code)\n";
    s << "label(return)\n\n";
    s << "newmem:\n";
    s << "  // your code here\n\n";
    s << "code:\n";
    // Emit the stolen instructions as raw bytes (db) rather than re-assembled
    // mnemonics: the disassembler recognizes some instructions (e.g. endbr64)
    // that the assembler cannot round-trip, and stealing exact bytes is always
    // correct. The disassembly is kept as comments so the cave stays readable.
    for (const auto& insn : originalCode)
        s << "  // " << insn.text << "\n";
    s << "  db " << dbBytes << "\n";
    s << "  jmp return\n\n";
    s << "0x" << addr << ":\n";
    s << "  jmp newmem\n";
    for (size_t i = 0; i < nopCount; ++i)
        s << "  nop\n";
    s << "return:\n\n";

    s << "[DISABLE]\n";
    s << "0x" << addr << ":\n";
    s << "  db " << dbBytes << "\n\n";
    s << "dealloc(newmem)\n";
    return s.str();
}

std::string buildAobInjectionScript(const std::string& module,
                                    uintptr_t moduleOffset,
                                    const std::vector<StolenInstruction>& originalCode,
                                    const std::vector<uint8_t>& originalBytes) {
    size_t nopCount = originalBytes.size() > 5 ? originalBytes.size() - 5 : 0;

    std::string dbBytes;
    for (size_t i = 0; i < originalBytes.size(); ++i) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02X", originalBytes[i]);
        if (i) dbBytes += ' ';
        dbBytes += b;
    }
    // The original bytes double as the scan signature (space-separated hex). The
    // user can replace stable-but-not-unique bytes with `??` wildcards if needed.
    const std::string& signature = dbBytes;

    std::ostringstream s;
    s << "{ AOB injection auto-generated for " << module << "+0x" << std::hex << moduleOffset
      << std::dec << "\n  " << originalBytes.size()
      << " byte(s) stolen; original code and bytes captured below. Replace <sig>"
         " bytes with ?? if the pattern is not unique. }\n\n";

    s << "[ENABLE]\n";
    s << "aobscanmodule(INJECT," << module << "," << signature << ")\n";
    s << "alloc(newmem,$1000,INJECT)\n";
    s << "label(code)\n";
    s << "label(return)\n\n";
    s << "newmem:\n";
    s << "  // your code here\n\n";
    s << "code:\n";
    for (const auto& insn : originalCode)
        s << "  // " << insn.text << "\n";
    s << "  db " << dbBytes << "\n";
    s << "  jmp return\n\n";
    s << "INJECT:\n";
    s << "  jmp newmem\n";
    for (size_t i = 0; i < nopCount; ++i)
        s << "  nop\n";
    s << "return:\n";
    s << "registersymbol(INJECT)\n\n";

    s << "[DISABLE]\n";
    s << "INJECT:\n";
    s << "  db " << dbBytes << "\n\n";
    s << "unregistersymbol(INJECT)\n";
    s << "dealloc(newmem)\n";
    return s.str();
}

const std::vector<AaTemplate>& builtinAaTemplates() {
    static const std::vector<AaTemplate> templates = {
        {
            "Allocate memory",
            "Bare alloc + label scaffold; useful when you've found the address by hand.",
R"({ Allocate memory and run code from there.
  Replace <address> with the location you want to redirect, and write
  whatever you want the cave to do. }

[ENABLE]
alloc(newmem, $1000)
label(returnhere)

newmem:
  // your code here
  jmp returnhere

[DISABLE]
dealloc(newmem)
)"
        },

        {
            "Code injection (at address)",
            "Allocate a cave, jmp to it from a known address, run code, jmp back.",
R"({ Inject code at a fixed address.
  Replace <address> with the absolute address (or symbol+offset) of the
  instruction you're hooking. <original code> goes into the cave so the
  game's behaviour is preserved. The original-bytes line in [DISABLE]
  must be the same length as the jmp+nop padding in [ENABLE]. }

[ENABLE]
alloc(newmem, $1000, <address>)
label(code)
label(return)

newmem:

code:
  <original code>
  jmp return

<address>:
  jmp newmem
  // pad with nops if the original instruction was longer than 5 bytes
return:

[DISABLE]
<address>:
  db <original bytes>

dealloc(newmem)
)"
        },

        {
            "AOB injection",
            "Locate an instruction by an array-of-bytes pattern in a module, hook it, restore on disable.",
R"({ AOB injection — preferred over hard-coded addresses because it survives
  game updates as long as the byte pattern stays unique. Replace
  <modulename> with the binary's name (e.g. "mb_warband.exe"), <aob>
  with a unique signature for the instruction, and <original code> with
  the disassembly of the bytes you replace. }

[ENABLE]
aobscanmodule(INJECT,<modulename>,<aob>)  // should be unique
alloc(newmem, $1000, INJECT)

label(code)
label(return)

newmem:

code:
  <original code>
  jmp return

INJECT:
  jmp newmem
  // pad with nops if the original instruction was longer than 5 bytes
return:
registersymbol(INJECT)

[DISABLE]
INJECT:
  db <original bytes>

unregistersymbol(INJECT)
dealloc(newmem)
)"
        },

        {
            "Full code injection",
            "Alloc + full set of labels (originalcode, exit) — verbose AOB injection skeleton.",
R"({ Full AOB injection skeleton with explicit originalcode/exit labels.
  Use this when you want to keep the original instruction bytes inline
  in the cave for clarity, e.g. to compare against the patched version. }

[ENABLE]
aobscanmodule(INJECT,<modulename>,<aob>)  // should be unique
alloc(newmem, $1000, INJECT)

label(code)
label(originalcode)
label(exit)

newmem:

code:
  // your patched code
  jmp originalcode

originalcode:
  <original code>

exit:
  jmp return

INJECT:
  jmp newmem
  // pad with nops if the original instruction was longer than 5 bytes
return:
registersymbol(INJECT)

[DISABLE]
INJECT:
  db <original bytes>

unregistersymbol(INJECT)
dealloc(newmem)
)"
        },

        {
            "Pointer injection",
            "Alloc a slot, register it as a symbol, and capture a pointer (e.g. 'this' from a method) into it.",
R"({ Pointer-capture injection. Hook an instruction that touches the
  object you want, copy the pointer out of a register into a fixed
  symbol, run the original, jmp back. The symbol can then be used as
  a base for further memory records. }

[ENABLE]
aobscanmodule(INJECT,<modulename>,<aob>)  // should be unique
alloc(newmem, $1000, INJECT)
alloc(pPlayerBase, 8)

label(code)
label(return)

registersymbol(pPlayerBase)
registersymbol(INJECT)

newmem:
  mov [pPlayerBase], <register holding the pointer>

code:
  <original code>
  jmp return

INJECT:
  jmp newmem
  // pad with nops if the original instruction was longer than 5 bytes
return:

[DISABLE]
INJECT:
  db <original bytes>

unregistersymbol(INJECT)
unregistersymbol(pPlayerBase)
dealloc(pPlayerBase)
dealloc(newmem)
)"
        },

        {
            "Cheat table framework",
            "Lua skeleton for the cheat-table-level script — enable/disable callbacks + record helpers.",
R"({ Table-level Lua skeleton. Paste into the table's "Lua Script" entry
  (not into [ENABLE]/[DISABLE]) — runs once when the table loads. }

local addressList = getAddressList()

local function onMemoryRecordToggle(rec, active)
  if active then
    print("Activated: " .. tostring(rec.Description))
  else
    print("Deactivated: " .. tostring(rec.Description))
  end
end

-- Wire OnActivate for every existing record so the helper above runs.
for i = 0, addressList.Count - 1 do
  local rec = addressList:getMemoryRecord(i)
  if rec then
    rec.OnActivate = function(active) onMemoryRecordToggle(rec, active) end
  end
end
)"
        },

        {
            "Lua block inside AA",
            "Demo of {$lua} block expansion — Lua return value gets spliced into the AA stream.",
R"({ The {$lua} ... {$asm} block runs the embedded Lua chunk at preprocess
  time and substitutes its return value into the AA stream. Useful for
  conditional code generation. }

[ENABLE]
{$lua}
  if syntaxcheck then
    -- syntaxcheck is a global the host sets while running 'check()' — guard
    -- expensive lookups so the editor's syntax check stays fast.
    return ""
  end
  return "alloc(newmem, $100)\nlabel(here)\nhere:\n  mov rax, 1\n"
{$asm}

[DISABLE]
dealloc(newmem)
)"
        },
    };
    return templates;
}

} // namespace ce
