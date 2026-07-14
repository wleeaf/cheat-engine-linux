#pragma once
/// .CT Cheat Table format — XML-based save/load compatible with CE format.

#include "core/types.hpp"
#include <string>
#include <vector>

namespace ce {

struct CheatEntry {
    int id = 0;
    std::string description;
    uintptr_t address = 0;
    std::string addressString;       // Original <Address> text (e.g. "game.exe+1C"); symbolic bases resolve at runtime
    std::vector<int64_t> offsets;    // Pointer-chain offsets (<Offsets>); empty = direct address
    ValueType type = ValueType::Int32;
    std::string value;
    bool active = false;
    bool showAsHex = false;     // Display the value as hexadecimal (CE <ShowAsHex>)
    FreezeMode freezeMode = FreezeMode::Normal;
    std::string autoAsmScript;  // [ENABLE]/[DISABLE] script
    std::string luaScript;      // Lua code
    int parentId = -1;          // -1 = root level
    std::vector<int> childIds;
    bool isGroup = false;       // True = group header, no address
    std::string color;          // Hex color for display
    std::string dropdownList;   // Semicolon-separated choices
    std::string hotkeyKeys;     // Hotkey binding
    std::string increaseHotkeyKeys;
    std::string decreaseHotkeyKeys;
    std::string setValueHotkeyKeys;    // hotkey that sets the value to setValueHotkeyValue
    std::string setValueHotkeyValue;   // target value for the set-value hotkey
    std::string hotkeyStep;
};

struct StructureField {
    std::string name;
    size_t offset = 0;
    ValueType type = ValueType::Int32;
    size_t size = 4;
    std::string displayMethod;
    std::string nestedStructure;
};

struct StructureDefinition {
    std::string name;
    size_t size = 0;
    std::vector<StructureField> fields;
};

/// A persisted disassembler annotation (comment and/or user label). The address is
/// stored as an EXPRESSION string (e.g. "libgame.so+0x1234" or "0x55...") so a
/// module-relative annotation survives the module rebasing under ASLR; it's
/// resolved via the ExpressionParser when applied to a live process.
struct DisassemblerComment {
    std::string address;   // address expression
    std::string comment;   // inline comment text (may be empty if only a label)
    std::string label;     // user-assigned symbol name for this address (may be empty)
};

/// On-disk cheat-table format, detected from file *contents* (not extension).
enum class TableFormat { Xml, Json, Protected, Unknown };

/// Sniff a table file's format by reading its leading bytes. Extension-agnostic:
/// CE tables are commonly `.CT` (uppercase) or extensionless when downloaded, and
/// case-sensitive extension checks reject them on Linux. `Protected` is returned
/// for a password-protected .CETRAINER payload (needs CheatTable::loadProtected).
TableFormat detectTableFormat(const std::string& path);

struct CheatTable {
    std::string gameName;
    std::string gameVersion;
    std::string author;
    std::string comment;
    std::string luaScript;      // Table-level Lua script
    std::vector<CheatEntry> entries;
    std::vector<DisassemblerComment> disassemblerComments;
    std::vector<StructureDefinition> structures;
    // Raw "<Forms>...</Forms>" block preserved verbatim across load/save. CE
    // embeds Delphi form designs here; we can't render them on Linux, but we must
    // not silently drop them when a user edits and re-saves a table that has them.
    std::string rawFormsXml;

    /// Save to .CT XML file.
    bool save(const std::string& path) const;

    /// Load from .CT XML file.
    bool load(const std::string& path);

    /// Load a table auto-detecting the on-disk format (CE XML .CT, our JSON, or a
    /// password-less protected payload) from the file *contents*, not its
    /// extension. Use this for any user-supplied path: CE tables are commonly
    /// `.CT` (uppercase) or have no extension, and case-sensitive extension checks
    /// silently reject them on Linux. Returns false if the format can't be loaded
    /// (e.g. a password-protected .CETRAINER, which needs loadProtected()).
    bool loadAuto(const std::string& path);

    /// Save to JSON (our native format).
    bool saveJson(const std::string& path) const;

    /// Load from JSON.
    bool loadJson(const std::string& path);

    /// Save/load a password-protected .CETRAINER payload.
    bool saveProtected(const std::string& path, const std::string& password) const;
    bool loadProtected(const std::string& path, const std::string& password);
};

/// Build a CE-style address expression from a (possibly symbolic) base and a
/// pointer offset chain, matching Cheat Engine's resolution
/// (deref(deref(...deref(base)+off[n-1]...)+off[1]) + off[0]). With no offsets it
/// returns the base unchanged. e.g. ("game.exe+1C", {0x10,0x8}) -> "[[game.exe+1C]+8]+10".
std::string buildPointerExpression(const std::string& base, const std::vector<int64_t>& offsets);

} // namespace ce
