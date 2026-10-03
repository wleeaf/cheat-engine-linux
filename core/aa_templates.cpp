#include "core/aa_templates.hpp"

#include <cstdio>
#include <sstream>

namespace ce {

std::string buildCodeInjectionScript(uintptr_t targetAddress,
                                     const std::vector<StolenInstruction>& originalCode,
                                     const std::vector<uint8_t>& originalBytes,
                                     const std::string& moduleLabel,
                                     uintptr_t moduleOffset) {
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
    s << "define(INJECT,";
    if (moduleLabel.empty()) s << "0x" << addr;
    else s << '"' << moduleLabel << "\"+0x" << std::hex << moduleOffset << std::dec;
    s << ")\n";
    s << "assert(INJECT," << dbBytes << ")\n";
    s << "alloc(newmem,$1000," << (moduleLabel.empty() ? "0x" + addr : "INJECT") << ")\n";
    s << "label(code)\n";
    s << "label(return)\n\n";
    s << "newmem:\n";
    s << "  // your code here\n\n";
    s << "code:\n";
    for (const auto& insn : originalCode) {
        if (!insn.label.empty()) s << insn.label << ":\n";
        s << "  " << insn.text << "\n";
    }
    s << "  jmp return\n\n";
    s << "INJECT:\n";
    s << "  jmp near newmem\n";
    for (size_t i = 0; i < nopCount; ++i)
        s << "  nop\n";
    s << "return:\n\n";

    s << "[DISABLE]\n";
    if (moduleLabel.empty()) s << "0x" << addr << ":\n";
    else s << '"' << moduleLabel << "\"+0x" << std::hex << moduleOffset << std::dec << ":\n";
    s << "  db " << dbBytes << "\n\n";
    s << "dealloc(newmem)\n";
    return s.str();
}

std::string buildAobInjectionScript(const std::string& module,
                                    uintptr_t moduleOffset,
                                    const std::vector<StolenInstruction>& originalCode,
                                    const std::vector<uint8_t>& originalBytes,
                                    const std::string& signatureOverride) {
    size_t nopCount = originalBytes.size() > 5 ? originalBytes.size() - 5 : 0;

    std::string dbBytes;
    for (size_t i = 0; i < originalBytes.size(); ++i) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02X", originalBytes[i]);
        if (i) dbBytes += ' ';
        dbBytes += b;
    }
    // The live generator supplies a verified, unique signature.
    const std::string& signature = signatureOverride.empty() ? dbBytes : signatureOverride;

    std::ostringstream s;
    s << "{ AOB injection auto-generated for " << module << "+0x" << std::hex << moduleOffset
      << std::dec << "\n  " << originalBytes.size()
      << " byte(s) stolen; original code and bytes captured below. }\n\n";

    s << "[ENABLE]\n";
    s << "aobscanmodule(INJECT," << module << "," << signature << ")\n";
    s << "assert(INJECT," << dbBytes << ")\n";
    s << "alloc(newmem,$1000,INJECT)\n";
    s << "label(code)\n";
    s << "label(return)\n\n";
    s << "newmem:\n";
    s << "  // your code here\n\n";
    s << "code:\n";
    for (const auto& insn : originalCode) {
        if (!insn.label.empty()) s << insn.label << ":\n";
        s << "  " << insn.text << "\n";
    }
    s << "  jmp return\n\n";
    s << "INJECT:\n";
    s << "  jmp near newmem\n";
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
  Write code at newmem. Use a site-specific injection template to hook a location. }

[ENABLE]
alloc(newmem, $1000)

newmem:
  // your code here
  ret

[DISABLE]
dealloc(newmem)
)"
        },

        {
            "Code injection (at address)",
            "Allocate a cave, jmp to it from a known address, run code, jmp back.",
            "", InjectionKind::Code
        },

        {
            "AOB injection",
            "Locate an instruction by an array-of-bytes pattern in a module, hook it, restore on disable.",
            "", InjectionKind::Aob
        },

        {
            "Full code injection",
            "Generate an injection with originalcode and exit labels from the selected instructions.",
            "", InjectionKind::Full
        },

        {
            "Pointer injection",
            "Alloc a slot, register it as a symbol, and capture a pointer (e.g. 'this' from a method) into it.",
            "", InjectionKind::Pointer
        },

        {
            "Cheat table framework",
            "Lua skeleton for the cheat-table-level script: enable/disable callbacks + record helpers.",
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
            "Demo of {$lua} block expansion: Lua return value gets spliced into the AA stream.",
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
