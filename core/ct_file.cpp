#include <charconv>
#include "core/ct_file.hpp"
#include "core/ct_file_stream.hpp"
#include "core/log.hpp"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <unordered_map>
#include <functional>
#include <vector>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <string_view>
#include <unistd.h>

// Simple XML writer/reader (no external dependency)
namespace ce {

static constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
static constexpr uint64_t kFnvPrime = 1099511628211ULL;

static uint64_t fnv1a(const std::string& text) {
    uint64_t hash = kFnvOffset;
    for (unsigned char c : text) {
        hash ^= c;
        hash *= kFnvPrime;
    }
    return hash;
}

static uint64_t xorshift64(uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

// NOTE: xorCrypt/xorDecrypt provide light OBFUSCATION only, not confidentiality.
// The keystream is a non-cryptographic xorshift64 seeded by fnv1a(password) and is
// trivially recoverable from known plaintext (the JSON header is fixed), and the
// stored fnv1a(password) verifier (saveProtected) is brute-forceable offline. Do
// NOT rely on this to protect sensitive table contents.
// TODO(security): for real protection switch to an authenticated cipher
// (libsodium secretbox / AES-GCM) with a memory-hard KDF (argon2/scrypt), random
// salt+nonce, and stop storing any password-derived value in cleartext.
static std::vector<uint8_t> xorCrypt(const std::string& input, const std::string& password) {
    uint64_t state = fnv1a(password.empty() ? std::string("cecore") : password);
    std::vector<uint8_t> out(input.begin(), input.end());
    for (auto& byte : out)
        byte ^= static_cast<uint8_t>(xorshift64(state) & 0xff);
    return out;
}

static std::string xorDecrypt(const std::vector<uint8_t>& input, const std::string& password) {
    uint64_t state = fnv1a(password.empty() ? std::string("cecore") : password);
    std::string out(input.begin(), input.end());
    for (auto& byte : out)
        byte = static_cast<char>(static_cast<unsigned char>(byte) ^ static_cast<uint8_t>(xorshift64(state) & 0xff));
    return out;
}

// Create a fresh temp file (O_EXCL, mode 0600) in a trusted directory and
// return its path. Avoids the predictable "<path>.json.tmp" symlink/TOCTOU
// hazard when running as root. Returns "" on failure.
static std::string makeSecureTempFile() {
    std::error_code ec;
    auto dir = std::filesystem::temp_directory_path(ec);
    if (ec) dir = std::filesystem::path("/tmp");
    auto templ = (dir / "cecore-XXXXXX").string();
    std::vector<char> buf(templ.begin(), templ.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());  // creates with O_EXCL | 0600
    if (fd < 0) return "";
    close(fd);
    return std::string(buf.data());
}

// ── XML writing helpers ──
static std::string xmlEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            default:   out += c;
        }
    }
    return out;
}

static std::string typeToStr(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:    return "Byte";
        case ValueType::Int16:   return "2 Bytes";
        case ValueType::Int32:   return "4 Bytes";
        case ValueType::Int64:   return "8 Bytes";
        case ValueType::Float:   return "Float";
        case ValueType::Double:  return "Double";
        case ValueType::String:  return "String";
        case ValueType::UnicodeString: return "String";   // CE: String + <Unicode>1</Unicode>
        case ValueType::ByteArray: return "Array of byte";
        case ValueType::Binary:  return "Binary";
        case ValueType::Pointer: return "Pointer";
        case ValueType::Custom:  return "Custom";
        default: return "4 Bytes";
    }
}

static std::string normalizedTypeName(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c))
            out += static_cast<char>(std::tolower(c));
    }
    return out;
}

// Windows virtual-key code -> a Qt key-sequence token, for importing CE's
// <Hotkey><Keys><Key>vk</Key>...</Keys>. Unknown codes yield "" (dropped).
static std::string vkToKeyToken(int vk) {
    switch (vk) {
        case 16: return "Shift";  case 17: return "Ctrl";   case 18: return "Alt";
        case 91: case 92: return "Meta";
        case 8:  return "Backspace"; case 9: return "Tab";  case 13: return "Return";
        case 27: return "Esc";    case 32: return "Space";
        case 33: return "PgUp";   case 34: return "PgDown"; case 35: return "End";
        case 36: return "Home";   case 37: return "Left";   case 38: return "Up";
        case 39: return "Right";  case 40: return "Down";   case 45: return "Ins";
        case 46: return "Del";
        default: break;
    }
    if (vk >= 48 && vk <= 57)  return std::string(1, static_cast<char>('0' + (vk - 48)));  // 0-9
    if (vk >= 65 && vk <= 90)  return std::string(1, static_cast<char>('A' + (vk - 65)));  // A-Z
    if (vk >= 96 && vk <= 105) return std::string(1, static_cast<char>('0' + (vk - 96)));  // Numpad 0-9
    if (vk >= 112 && vk <= 123) return "F" + std::to_string(vk - 111);                      // F1-F12
    return {};
}

// A CE key list (VK codes) -> "Ctrl+Alt+Shift+<key>" in Qt's canonical order.
static std::string vksToKeyString(const std::vector<int>& vks) {
    bool ctrl = false, alt = false, shift = false, meta = false;
    std::string key;
    for (int vk : vks) {
        std::string tok = vkToKeyToken(vk);
        if (tok == "Ctrl") ctrl = true;
        else if (tok == "Alt") alt = true;
        else if (tok == "Shift") shift = true;
        else if (tok == "Meta") meta = true;
        else if (!tok.empty() && key.empty()) key = tok;
    }
    std::string out;
    if (ctrl)  out += "Ctrl+";
    if (alt)   out += "Alt+";
    if (shift) out += "Shift+";
    if (meta)  out += "Meta+";
    out += key;
    if (!out.empty() && out.back() == '+') out.pop_back();   // modifier-only (rare)
    return out;
}

// Inverse of vkToKeyToken: a Qt key token -> Windows VK code (0 if unknown), so we can
// write CE's <Hotkey><Keys> from our stored key-sequence strings.
static int keyTokenToVK(const std::string& t) {
    if (t == "Ctrl") return 17;  if (t == "Alt") return 18;   if (t == "Shift") return 16;
    if (t == "Meta") return 91;
    if (t == "Backspace") return 8;  if (t == "Tab") return 9;
    if (t == "Return" || t == "Enter") return 13;
    if (t == "Esc") return 27;   if (t == "Space") return 32;
    if (t == "PgUp") return 33;   if (t == "PgDown") return 34;
    if (t == "End") return 35;    if (t == "Home") return 36;
    if (t == "Left") return 37;   if (t == "Up") return 38;
    if (t == "Right") return 39;  if (t == "Down") return 40;
    if (t == "Ins") return 45;    if (t == "Del") return 46;
    if (t.size() == 1 && t[0] >= '0' && t[0] <= '9') return static_cast<unsigned char>(t[0]);  // 48-57
    if (t.size() == 1 && t[0] >= 'A' && t[0] <= 'Z') return static_cast<unsigned char>(t[0]);  // 65-90
    if (t.size() >= 2 && t[0] == 'F') {
        try { int n = std::stoi(t.substr(1)); if (n >= 1 && n <= 12) return 111 + n; } catch (...) {}
    }
    return 0;
}

// "Ctrl+Shift+F1" -> {17, 16, 112}. Unknown tokens are dropped.
static std::vector<int> keyStringToVKs(const std::string& s) {
    std::vector<int> vks;
    size_t start = 0;
    while (start <= s.size()) {
        size_t plus = s.find('+', start);
        std::string tok = s.substr(start, plus == std::string::npos ? std::string::npos : plus - start);
        while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
        while (!tok.empty() && tok.back() == ' ') tok.pop_back();
        if (int vk = keyTokenToVK(tok)) vks.push_back(vk);
        if (plus == std::string::npos) break;
        start = plus + 1;
    }
    return vks;
}

static ValueType strToType(const std::string& s) {
    bool numeric = !s.empty();
    for (unsigned char c : s) {
        if (!std::isdigit(c)) {
            numeric = false;
            break;
        }
    }
    if (numeric) {
        int v = std::atoi(s.c_str());
        switch (v) {
            case 0:  return ValueType::Byte;
            case 1:  return ValueType::Int16;
            case 2:  return ValueType::Int32;
            case 3:  return ValueType::Int64;
            case 4:  return ValueType::Float;
            case 5:  return ValueType::Double;
            case 6:  return ValueType::String;
            case 8:  return ValueType::ByteArray;
            case 9:  return ValueType::Binary;
            case 10: return ValueType::All;
            case 12: return ValueType::Custom;
            case 13: return ValueType::Pointer;
            default: return ValueType::Int32;
        }
    }

    auto type = normalizedTypeName(s);
    if (type == "byte" || type == "1byte") return ValueType::Byte;
    if (type == "2bytes" || type == "short") return ValueType::Int16;
    if (type == "4bytes" || type == "integer" || type == "int") return ValueType::Int32;
    if (type == "8bytes" || type == "long" || type == "int64") return ValueType::Int64;
    if (type == "float" || type == "single") return ValueType::Float;
    if (type == "double") return ValueType::Double;
    if (type == "string" || type == "text") return ValueType::String;
    if (type == "arrayofbyte" || type == "bytearray" || type == "aob") return ValueType::ByteArray;
    if (type == "binary" || type == "bits") return ValueType::Binary;
    if (type == "pointer") return ValueType::Pointer;
    if (type == "custom" || type == "customtype") return ValueType::Custom;
    return ValueType::Int32;
}

// ── Save as CE-compatible XML ──

static bool validRecordFormats(const std::vector<CheatEntry>& entries) {
    for (const auto& entry : entries)
        if ((entry.dataByteOrder != ByteOrder::Unknown && entry.dataByteOrder != ByteOrder::Little && entry.dataByteOrder != ByteOrder::Big) ||
            (entry.pointerWidth != 0 && entry.pointerWidth != 4 && entry.pointerWidth != 8)) return false;
    return true;
}

bool CheatTable::save(const std::string& path) const {
    if (!validRecordFormats(entries)) return false;
    std::ofstream f(path);
    if (!f) return false;
    bool success=writeTableXml(*this,f);
    f.flush();
    success=success && f.good();
    f.close();
    return success && !f.fail();
}

bool writeTableXml(const CheatTable& table,std::ostream& f) {
    const auto& entries=table.entries;
    const auto& gameName=table.gameName;
    const auto& gameVersion=table.gameVersion;
    const auto& author=table.author;
    const auto& comment=table.comment;
    const auto& luaScript=table.luaScript;
    const auto& structures=table.structures;
    const auto& disassemblerComments=table.disassemblerComments;
    const auto& rawFormsXml=table.rawFormsXml;
    if (!validRecordFormats(entries)) return false;

    f << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    f << "<CheatTable>\n";
    f << "  <CheatTableVersion>45</CheatTableVersion>\n";

    if (!gameName.empty())
        f << "  <GameName>" << xmlEscape(gameName) << "</GameName>\n";
    if (!gameVersion.empty())
        f << "  <GameVersion>" << xmlEscape(gameVersion) << "</GameVersion>\n";
    if (!author.empty())
        f << "  <Author>" << xmlEscape(author) << "</Author>\n";
    if (!comment.empty())
        f << "  <Comment>" << xmlEscape(comment) << "</Comment>\n";

    if (!luaScript.empty()) {
        f << "  <LuaScript>" << xmlEscape(luaScript) << "</LuaScript>\n";
    }

    if (!structures.empty()) {
        f << "  <Structures>\n";
        for (const auto& s : structures) {
            f << "    <Structure>\n";
            f << "      <Name>" << xmlEscape(s.name) << "</Name>\n";
            f << "      <Size>" << s.size << "</Size>\n";
            f << "      <Elements>\n";
            for (const auto& field : s.fields) {
                f << "        <Element>\n";
                f << "          <Name>" << xmlEscape(field.name) << "</Name>\n";
                f << "          <Offset>" << field.offset << "</Offset>\n";
                f << "          <Type>" << typeToStr(field.type) << "</Type>\n";
                f << "          <Size>" << field.size << "</Size>\n";
                if (!field.displayMethod.empty())
                    f << "          <DisplayMethod>" << xmlEscape(field.displayMethod) << "</DisplayMethod>\n";
                if (!field.nestedStructure.empty())
                    f << "          <NestedStructure>" << xmlEscape(field.nestedStructure) << "</NestedStructure>\n";
                f << "        </Element>\n";
            }
            f << "      </Elements>\n";
            f << "    </Structure>\n";
        }
        f << "  </Structures>\n";
    }

    if (!disassemblerComments.empty()) {
        f << "  <DisassemblerComments>\n";
        for (const auto& c : disassemblerComments) {
            f << "    <DisassemblerComment>\n";
            f << "      <Address>" << xmlEscape(c.address) << "</Address>\n";
            if (!c.comment.empty())
                f << "      <Comment>" << xmlEscape(c.comment) << "</Comment>\n";
            if (!c.label.empty())
                f << "      <Label>" << xmlEscape(c.label) << "</Label>\n";
            f << "    </DisassemblerComment>\n";
        }
        f << "  </DisassemblerComments>\n";
    }

    // Write the inner fields of one <CheatEntry> (everything but the enclosing
    // tags and any nested child list).
    auto writeEntryFields = [&](const CheatEntry& e) {
        f << "      <ID>" << e.id << "</ID>\n";
        // CE wraps the description in double quotes inside the tag; match that so
        // Cheat Engine (and our own quote-stripping loader) read it back cleanly.
        f << "      <Description>\"" << xmlEscape(e.description) << "\"</Description>\n";

        if (e.isGroup) {
            f << "      <GroupHeader>1</GroupHeader>\n";
            if (e.collapsed)
                f << "      <Collapsed>1</Collapsed>\n";
        } else if (!e.autoAsmScript.empty()) {
            // An entry carrying an AssemblerScript IS an "Auto Assembler Script"
            // record in CE (the two are equivalent). CE writes the type name and,
            // for the usual enable/disable script, no numeric <Address> (only a
            // symbolic one if the record defined an address). Writing a bogus
            // <Address>0</Address> + <VariableType>4 Bytes</VariableType> here made
            // re-saved AA tables diverge from the original.
            if (!e.addressString.empty())
                f << "      <Address>" << e.addressString << "</Address>\n";
            f << "      <VariableType>Auto Assembler Script</VariableType>\n";
        } else {
            // Data record. CE writes the address expression RAW (quotes and all);
            // matching that keeps a module-relative base like "ac_client.exe"+X
            // readable by CE and by our raw-reading loader. Escaping it (turning "
            // into &quot;) double-encoded on the next load.
            if (!e.addressString.empty()) {
                f << "      <Address>" << e.addressString << "</Address>\n";
            } else {
                char addr[32];
                snprintf(addr, sizeof(addr), "%lx", e.address);
                f << "      <Address>" << addr << "</Address>\n";
            }
            f << "      <VariableType>" << typeToStr(e.type) << "</VariableType>\n";
            // CE stores a string/AoB element length in <Length>, and marks wide strings
            // with <Unicode> (the VariableType stays "String").
            if (e.type == ValueType::String || e.type == ValueType::UnicodeString) {
                if (e.length > 0) f << "      <Length>" << e.length << "</Length>\n";
                f << "      <Unicode>" << (e.type == ValueType::UnicodeString ? 1 : 0) << "</Unicode>\n";
            } else if (e.type == ValueType::ByteArray && e.length > 0) {
                f << "      <Length>" << e.length << "</Length>\n";
            }
            if (!e.offsets.empty()) {
                f << "      <Offsets>\n";
                for (int64_t off : e.offsets) {
                    char ob[32];
                    // CE writes a negative offset as signed hex ("-60"). Emitting
                    // it as a 64-bit unsigned ("ffffffffffffffa0") overflowed the
                    // loader's stoll on reload and silently dropped the offset.
                    if (off < 0)
                        snprintf(ob, sizeof(ob), "-%llx", static_cast<unsigned long long>(-off));
                    else
                        snprintf(ob, sizeof(ob), "%llx", static_cast<unsigned long long>(off));
                    f << "        <Offset>" << ob << "</Offset>\n";
                }
                f << "      </Offsets>\n";
            }
            if (!e.value.empty())
                f << "      <Value>" << xmlEscape(e.value) << "</Value>\n";
        }

        if (e.active)
            f << "      <Activated>1</Activated>\n";
        if (e.showAsHex)
            f << "      <ShowAsHex>1</ShowAsHex>\n";   // CE-standard tag
        // Signed display defaults to on, so only the unsigned override needs writing
        // (CE reads <ShowAsSigned> and omits it at its default too).
        if (!e.showAsSigned)
            f << "      <ShowAsSigned>0</ShowAsSigned>\n";
        if (e.dataByteOrder != ByteOrder::Unknown)
            f << "      <LinuxDataByteOrder>" << (e.dataByteOrder == ByteOrder::Big ? "big" : "little") << "</LinuxDataByteOrder>\n";
        if (e.pointerWidth)
            f << "      <LinuxPointerWidth>" << static_cast<unsigned>(e.pointerWidth) << "</LinuxPointerWidth>\n";
        // Directional freeze (Allow Increase/Decrease etc.) — a custom tag CE
        // ignores but our loader restores, so it round-trips through CE XML too.
        if (e.freezeMode != FreezeMode::Normal)
            f << "      <freezeMode>" << (int)e.freezeMode << "</freezeMode>\n";

        if (!e.autoAsmScript.empty()) {
            f << "      <AssemblerScript>" << xmlEscape(e.autoAsmScript) << "</AssemblerScript>\n";
        }

        if (!e.luaScript.empty()) {
            f << "      <LuaScript>" << xmlEscape(e.luaScript) << "</LuaScript>\n";
        }

        if (!e.color.empty())
            f << "      <Color>" << e.color << "</Color>\n";

        // Preserve an imported CE record's <Options> element verbatim so flags we do
        // not model survive a load+save; otherwise synthesize one for a group whose
        // cascade defaults were changed away from "on".
        if (!e.optionsXml.empty())
            f << "      " << e.optionsXml << "\n";
        else if (e.isGroup && (!e.activateChildren || !e.deactivateChildren))
            f << "      <Options moActivateChildrenAsWell=\"" << (e.activateChildren ? 1 : 0)
              << "\" moDeactivateChildrenAsWell=\"" << (e.deactivateChildren ? 1 : 0) << "\"/>\n";

        if (!e.dropdownList.empty())
            f << "      <DropDownList>" << xmlEscape(e.dropdownList) << "</DropDownList>\n";

        // Hotkeys in CE's nested form so Cheat Engine can read them: one <Hotkey> per
        // binding with its mrh <Action>, a <Keys> list of VK codes, and an optional
        // <Value> (set-value target, or the step for increase/decrease).
        struct HkOut { int action; const std::string* keys; const std::string* value; };
        const std::string empty;
        std::vector<HkOut> hks;
        if (!e.hotkeyKeys.empty())          hks.push_back({0, &e.hotkeyKeys, &empty});               // Toggle
        if (!e.setValueHotkeyKeys.empty())  hks.push_back({5, &e.setValueHotkeyKeys, &e.setValueHotkeyValue});
        if (!e.increaseHotkeyKeys.empty())  hks.push_back({6, &e.increaseHotkeyKeys, &e.hotkeyStep});
        if (!e.decreaseHotkeyKeys.empty())  hks.push_back({7, &e.decreaseHotkeyKeys, &e.hotkeyStep});
        if (!hks.empty()) {
            f << "      <Hotkeys>\n";
            int hkId = 0;
            for (const auto& hk : hks) {
                f << "        <Hotkey>\n";
                f << "          <Action>" << hk.action << "</Action>\n";
                f << "          <Keys>\n";
                for (int vk : keyStringToVKs(*hk.keys))
                    f << "            <Key>" << vk << "</Key>\n";
                f << "          </Keys>\n";
                if (!hk.value->empty())
                    f << "          <Value>" << xmlEscape(*hk.value) << "</Value>\n";
                f << "          <ID>" << hkId++ << "</ID>\n";
                f << "        </Hotkey>\n";
            }
            f << "      </Hotkeys>\n";
        }
    };

    // Nest children inside their parent group's <CheatEntries> (CE's format), so
    // Cheat Engine reads the hierarchy and our own load restores parentId. Build
    // parent->children by id; write roots then recurse, index-based with a done[]
    // guard so cycles or duplicate ids can never drop or double-write an entry.
    std::unordered_map<int, int> idToIndex;
    for (size_t i = 0; i < entries.size(); ++i)
        idToIndex.emplace(entries[i].id, static_cast<int>(i));
    std::vector<std::vector<int>> children(entries.size());
    std::vector<char> isChild(entries.size(), 0);
    for (size_t i = 0; i < entries.size(); ++i) {
        int p = entries[i].parentId;
        if (p != -1) {
            auto it = idToIndex.find(p);
            if (it != idToIndex.end() && it->second != static_cast<int>(i)) {
                children[it->second].push_back(static_cast<int>(i));
                isChild[i] = 1;
            }
        }
    }
    std::vector<char> done(entries.size(), 0);
    std::function<void(int)> writeEntry = [&](int i) {
        if (done[i]) return;
        done[i] = 1;
        f << "    <CheatEntry>\n";
        writeEntryFields(entries[i]);
        if (!children[i].empty()) {
            f << "      <CheatEntries>\n";
            for (int c : children[i]) writeEntry(c);
            f << "      </CheatEntries>\n";
        }
        f << "    </CheatEntry>\n";
    };

    f << "  <CheatEntries>\n";
    for (size_t i = 0; i < entries.size(); ++i)
        if (!isChild[i]) writeEntry(static_cast<int>(i));
    for (size_t i = 0; i < entries.size(); ++i)   // orphan sweep (cycles)
        if (!done[i]) writeEntry(static_cast<int>(i));
    f << "  </CheatEntries>\n";
    if (!rawFormsXml.empty())
        f << "  <Forms>" << rawFormsXml << "</Forms>\n";
    f << "</CheatTable>\n";

    return f.good();
}

// ── Simple XML tag parser ──
static std::string getTag(const std::string& xml, const std::string& tag) {
    auto openTag = "<" + tag + ">";
    auto closeTag = "</" + tag + ">";
    auto start = xml.find(openTag);
    if (start == std::string::npos) return "";
    start += openTag.size();
    auto end = xml.find(closeTag, start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

static std::vector<std::string> getTagBlocks(const std::string& xml, const std::string& tag) {
    std::vector<std::string> blocks;
    auto openTag = "<" + tag + ">";
    auto closeTag = "</" + tag + ">";
    size_t pos = 0;
    while (true) {
        auto start = xml.find(openTag, pos);
        if (start == std::string::npos) break;
        auto end = xml.find(closeTag, start);
        if (end == std::string::npos) break;
        blocks.push_back(xml.substr(start, end - start + closeTag.size()));
        pos = end + closeTag.size();
    }
    return blocks;
}

static std::string xmlUnescape(const std::string& s);  // defined below

// Position of the "</tag>" that matches the "<tag>" opened at openPos, accounting
// for nested <tag> pairs. npos if unbalanced. Needed because Cheat Engine nests a
// group's children inside its own <CheatEntries>, so a naive find of the first
// close tag matches a child's close instead of the parent's.
static size_t findMatchingClose(const std::string& xml, size_t openPos, const std::string& tag) {
    std::string open = "<" + tag + ">";
    std::string close = "</" + tag + ">";
    size_t scan = openPos + open.size();
    int depth = 1;
    while (depth > 0) {
        auto nextOpen = xml.find(open, scan);
        auto nextClose = xml.find(close, scan);
        if (nextClose == std::string::npos) return std::string::npos;
        if (nextOpen != std::string::npos && nextOpen < nextClose) {
            ++depth;
            scan = nextOpen + open.size();
        } else {
            if (--depth == 0) return nextClose;
            scan = nextClose + close.size();
        }
    }
    return std::string::npos;
}

// Parse the <CheatEntry> blocks directly inside `entriesXml`, appending them (and,
// recursively, any nested children) to `entries` with parentId set for hierarchy.
static bool parseRecordDataFormat(const std::string& order, const std::string& width, CheatEntry& entry) {
    if (order.empty() || order == "auto") entry.dataByteOrder = ByteOrder::Unknown;
    else if (order == "little") entry.dataByteOrder = ByteOrder::Little;
    else if (order == "big") entry.dataByteOrder = ByteOrder::Big;
    else return false;
    if (width.empty() || width == "0") entry.pointerWidth = 0;
    else if (width == "4") entry.pointerWidth = 4;
    else if (width == "8") entry.pointerWidth = 8;
    else return false;
    return true;
}

static void parseCheatEntriesBlock(const std::string& entriesXml, int parentId,
                                   std::vector<CheatEntry>& entries, bool& validFormat) {
    static const std::string CE_CLOSE = "</CheatEntry>";
    size_t pos = 0;
    while (true) {
        auto entryStart = entriesXml.find("<CheatEntry>", pos);
        if (entryStart == std::string::npos) break;
        auto entryClose = findMatchingClose(entriesXml, entryStart, "CheatEntry");
        if (entryClose == std::string::npos) break;
        std::string entryXml = entriesXml.substr(entryStart, entryClose - entryStart + CE_CLOSE.size());
        pos = entryClose + CE_CLOSE.size();

        // Split this entry's own fields (before any nested child list) from the
        // nested <CheatEntries> so getTag() reads the parent's fields, not a child's.
        std::string ownXml = entryXml;
        std::string childListXml;
        auto nestedOpen = entryXml.find("<CheatEntries>");
        if (nestedOpen != std::string::npos) {
            ownXml = entryXml.substr(0, nestedOpen);
            auto nestedClose = findMatchingClose(entryXml, nestedOpen, "CheatEntries");
            if (nestedClose != std::string::npos) {
                size_t cs = nestedOpen + std::string("<CheatEntries>").size();
                childListXml = entryXml.substr(cs, nestedClose - cs);
            }
        }

        CheatEntry e;
        e.parentId = parentId;
        auto idStr = getTag(ownXml, "ID");
        if (!idStr.empty()) e.id = std::atoi(idStr.c_str());
        e.description = xmlUnescape(getTag(ownXml, "Description"));
        if (e.description.size() >= 2 && e.description.front() == '"' && e.description.back() == '"')
            e.description = e.description.substr(1, e.description.size() - 2);
        e.isGroup = (getTag(ownXml, "GroupHeader") == "1");
        e.collapsed = (getTag(ownXml, "Collapsed") == "1");
        if (!e.isGroup) {
            auto addrStr = getTag(ownXml, "Address");
            if (!addrStr.empty()) {
                e.addressString = addrStr;
                try { e.address = std::stoull(addrStr, nullptr, 16); } catch (...) { e.address = 0; }
            }
            auto offsetsXml = getTag(ownXml, "Offsets");
            for (const auto& offBlock : getTagBlocks(offsetsXml, "Offset")) {
                std::string offStr = getTag(offBlock, "Offset");
                try { e.offsets.push_back(static_cast<int64_t>(std::stoll(offStr, nullptr, 16))); }
                catch (...) {}
            }
            e.type = strToType(getTag(ownXml, "VariableType"));
            // CE String + <Unicode>1</Unicode> is our UnicodeString; <Length> is the
            // element byte length for String / Array-of-byte records.
            if (e.type == ValueType::String && getTag(ownXml, "Unicode") == "1")
                e.type = ValueType::UnicodeString;
            if (auto ln = getTag(ownXml, "Length"); !ln.empty()) {
                try { e.length = std::stoi(ln); } catch (...) {}
            }
            e.value = xmlUnescape(getTag(ownXml, "Value"));
        }
        e.active = (getTag(ownXml, "Activated") == "1");
        e.showAsHex = (getTag(ownXml, "ShowAsHex") == "1");
        if (!parseRecordDataFormat(getTag(ownXml, "LinuxDataByteOrder"), getTag(ownXml, "LinuxPointerWidth"), e)) validFormat = false;
        e.showAsSigned = (getTag(ownXml, "ShowAsSigned") != "0");  // absent -> signed default
        if (auto fm = getTag(ownXml, "freezeMode"); !fm.empty()) {
            try { e.freezeMode = (FreezeMode)std::stoi(fm); } catch (...) {}
        }
        e.autoAsmScript = xmlUnescape(getTag(ownXml, "AssemblerScript"));
        e.luaScript = xmlUnescape(getTag(ownXml, "LuaScript"));
        e.color = getTag(ownXml, "Color");
        // CE writes the PascalCase <DropDownList> (like every other tag); accept the
        // mis-cased <DropdownList> older builds of this port wrote as a fallback.
        e.dropdownList = xmlUnescape(getTag(ownXml, "DropDownList"));
        if (e.dropdownList.empty())
            e.dropdownList = xmlUnescape(getTag(ownXml, "DropdownList"));
        // CE group <Options .../> is a self-closing element with attributes; preserve it
        // verbatim and read the two cascade flags. Absent element -> keep our defaults
        // (cascade on); present element -> an absent attribute reads as off (CE convention).
        if (auto op = ownXml.find("<Options"); op != std::string::npos) {
            auto oe = ownXml.find('>', op);
            if (oe != std::string::npos) {
                e.optionsXml = ownXml.substr(op, oe - op + 1);
                e.activateChildren   = e.optionsXml.find("moActivateChildrenAsWell=\"1\"")   != std::string::npos;
                e.deactivateChildren = e.optionsXml.find("moDeactivateChildrenAsWell=\"1\"") != std::string::npos;
            }
        }
        // Hotkeys: CE uses a nested <Hotkeys><Hotkey><Action>N</Action><Keys><Key>vk
        // </Key>...</Keys><Value>..</Value></Hotkey>...</Hotkeys>; older builds of this
        // port wrote a flat "<Hotkeys>Ctrl+H</Hotkeys>" plus separate tags. Detect the
        // nested form by the inner <Hotkey and map each action to our slot; else read flat.
        auto hkXml = getTag(ownXml, "Hotkeys");
        if (hkXml.find("<Hotkey") != std::string::npos) {
            for (const auto& hk : getTagBlocks(hkXml, "Hotkey")) {
                int action = 0;
                if (auto a = getTag(hk, "Action"); !a.empty()) {
                    try { action = std::stoi(a); } catch (...) {}
                }
                std::vector<int> vks;
                for (const auto& kb : getTagBlocks(getTag(hk, "Keys"), "Key")) {
                    try { vks.push_back(std::stoi(getTag(kb, "Key"))); } catch (...) {}
                }
                std::string keyStr = vksToKeyString(vks);
                std::string val = xmlUnescape(getTag(hk, "Value"));
                switch (action) {   // CE mrh* action codes
                    case 5: e.setValueHotkeyKeys = keyStr; e.setValueHotkeyValue = val; break;  // SetValue
                    case 6: e.increaseHotkeyKeys = keyStr; if (!val.empty()) e.hotkeyStep = val; break;  // Increase
                    case 7: e.decreaseHotkeyKeys = keyStr; if (!val.empty()) e.hotkeyStep = val; break;  // Decrease
                    default: if (e.hotkeyKeys.empty()) e.hotkeyKeys = keyStr; break;            // Toggle (0-4)
                }
            }
        } else {
            e.hotkeyKeys = xmlUnescape(hkXml);
            e.increaseHotkeyKeys = xmlUnescape(getTag(ownXml, "IncreaseHotkey"));
            e.setValueHotkeyKeys = xmlUnescape(getTag(ownXml, "SetValueHotkey"));
            e.setValueHotkeyValue = xmlUnescape(getTag(ownXml, "SetValueHotkeyValue"));
            e.decreaseHotkeyKeys = xmlUnescape(getTag(ownXml, "DecreaseHotkey"));
            e.hotkeyStep = xmlUnescape(getTag(ownXml, "HotkeyStep"));
        }

        int myId = e.id;
        entries.push_back(std::move(e));
        if (!childListXml.empty())
            parseCheatEntriesBlock(childListXml, myId, entries, validFormat);
    }
}

static std::string xmlUnescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '&') {
            if (s.substr(i, 4) == "&lt;") { out += '<'; i += 3; }
            else if (s.substr(i, 4) == "&gt;") { out += '>'; i += 3; }
            else if (s.substr(i, 5) == "&amp;") { out += '&'; i += 4; }
            else if (s.substr(i, 6) == "&quot;") { out += '"'; i += 5; }
            else if (s.substr(i, 6) == "&apos;") { out += '\''; i += 5; }  // CE may escape apostrophes
            else out += s[i];
        } else {
            out += s[i];
        }
    }
    return out;
}

static std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (static_cast<unsigned char>(c)<0x20) {
                    constexpr char hex[]="0123456789abcdef";
                    out += "\\u00";
                    out += hex[static_cast<unsigned char>(c)>>4];
                    out += hex[static_cast<unsigned char>(c)&15];
                } else out += c;
                break;
        }
    }
    return out;
}

struct JsonValue {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolValue = false;
    // Keep number tokens exact: IEEE double cannot represent every 64-bit
    // address or signed pointer offset, even when the JSON integer is valid.
    std::string stringValue;
    std::vector<JsonValue> arrayValue;
    std::unordered_map<std::string, JsonValue> objectValue;
};

class JsonParser {
public:
    explicit JsonParser(const std::string& input) : input_(input) {
        if (input_.compare(0,3,"\xef\xbb\xbf")==0) pos_=3;
    }

    bool parse(JsonValue& out) {
        skipWs();
        if (!parseValue(out)) return false;
        skipWs();
        return pos_ == input_.size();
    }

private:
    void skipWs() {
        while (pos_<input_.size() && (input_[pos_]==' ' || input_[pos_]=='\t' || input_[pos_]=='\r' || input_[pos_]=='\n'))
            ++pos_;
    }

    bool consume(char expected) {
        skipWs();
        if (pos_ >= input_.size() || input_[pos_] != expected) return false;
        ++pos_;
        return true;
    }

    bool parseValue(JsonValue& out) {
        // Bound nesting so a hostile table (e.g. "[[[[[...]]]]]") can't exhaust
        // the stack through the parseValue/parseArray/parseObject recursion.
        struct DepthGuard {
            int& d;
            explicit DepthGuard(int& v) : d(v) { ++d; }
            ~DepthGuard() { --d; }
        } guard(depth_);
        if (depth_ > kMaxDepth) return false;
        skipWs();
        if (pos_ >= input_.size()) return false;
        char c = input_[pos_];
        if (c == '"') return parseString(out);
        if (c == '{') return parseObject(out);
        if (c == '[') return parseArray(out);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parseNumber(out);
        if (input_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            out.type = JsonValue::Type::Bool;
            out.boolValue = true;
            return true;
        }
        if (input_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            out.type = JsonValue::Type::Bool;
            out.boolValue = false;
            return true;
        }
        if (input_.compare(pos_, 4, "null") == 0) {
            pos_ += 4;
            out.type = JsonValue::Type::Null;
            return true;
        }
        return false;
    }

    bool parseString(JsonValue& out) {
        if (pos_ >= input_.size() || input_[pos_] != '"') return false;
        ++pos_;
        std::string value;
        while (pos_ < input_.size()) {
            char c = input_[pos_++];
            if (c == '"') {
                out.type = JsonValue::Type::String;
                out.stringValue = std::move(value);
                return true;
            }
            if (c != '\\') {
                if (static_cast<unsigned char>(c)<0x20) return false;
                value += c;
                continue;
            }
            if (pos_ >= input_.size()) return false;
            char esc = input_[pos_++];
            switch (esc) {
                case '"': value += '"'; break;
                case '\\': value += '\\'; break;
                case '/': value += '/'; break;
                case 'b': value += '\b'; break;
                case 'f': value += '\f'; break;
                case 'n': value += '\n'; break;
                case 'r': value += '\r'; break;
                case 't': value += '\t'; break;
                case 'u': {
                    auto unit=[&](uint32_t& code) {
                        if (input_.size()-pos_<4) return false;
                        code=0;
                        for (int i=0;i<4;++i) {
                            const char h=input_[pos_++];
                            const int digit=h>='0' && h<='9' ? h-'0' : h>='a' && h<='f' ? h-'a'+10 : h>='A' && h<='F' ? h-'A'+10 : -1;
                            if (digit<0) return false;
                            code=(code<<4)|static_cast<unsigned>(digit);
                        }
                        return true;
                    };
                    uint32_t code=0;
                    if (!unit(code)) return false;
                    if (code>=0xd800 && code<=0xdbff) {
                        if (input_.size()-pos_<2 || input_[pos_]!='\\' || input_[pos_+1]!='u') return false;
                        pos_+=2;uint32_t low=0;
                        if (!unit(low) || low<0xdc00 || low>0xdfff) return false;
                        code=0x10000+((code-0xd800)<<10)+(low-0xdc00);
                    } else if (code>=0xdc00 && code<=0xdfff) return false;
                    if (code<=0x7f) value+=static_cast<char>(code);
                    else {
                        if (code<=0x7ff) value+=static_cast<char>(0xc0|(code>>6));
                        else {
                            if (code<=0xffff) value+=static_cast<char>(0xe0|(code>>12));
                            else {
                                value+=static_cast<char>(0xf0|(code>>18));
                                value+=static_cast<char>(0x80|((code>>12)&63));
                            }
                            value+=static_cast<char>(0x80|((code>>6)&63));
                        }
                        value+=static_cast<char>(0x80|(code&63));
                    }
                    break;
                }
                default:
                    return false;
            }
        }
        return false;
    }

    bool parseNumber(JsonValue& out) {
        const size_t start=pos_;
        auto digit=[&] {return pos_<input_.size() && input_[pos_]>='0' && input_[pos_]<='9';};
        if (input_[pos_]=='-') ++pos_;
        if (!digit()) return false;
        if (input_[pos_]=='0') {++pos_;if (digit()) return false;}
        else while (digit()) ++pos_;
        if (pos_<input_.size() && input_[pos_]=='.') {
            ++pos_;if (!digit()) return false;
            while (digit()) ++pos_;
        }
        if (pos_<input_.size() && (input_[pos_]=='e' || input_[pos_]=='E')) {
            ++pos_;
            if (pos_<input_.size() && (input_[pos_]=='+' || input_[pos_]=='-')) ++pos_;
            if (!digit()) return false;
            while (digit()) ++pos_;
        }
        out.type = JsonValue::Type::Number;
        out.stringValue=input_.substr(start,pos_-start);
        return true;
    }

    bool parseArray(JsonValue& out) {
        if (!consume('[')) return false;
        out.type = JsonValue::Type::Array;
        skipWs();
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (true) {
            JsonValue item;
            if (!parseValue(item)) return false;
            out.arrayValue.push_back(std::move(item));
            skipWs();
            if (pos_ < input_.size() && input_[pos_] == ']') {
                ++pos_;
                return true;
            }
            if (!consume(',')) return false;
        }
    }

    bool parseObject(JsonValue& out) {
        if (!consume('{')) return false;
        out.type = JsonValue::Type::Object;
        skipWs();
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (true) {
            skipWs();
            JsonValue key;
            if (!parseString(key)) return false;
            if (!consume(':')) return false;
            JsonValue value;
            if (!parseValue(value)) return false;
            out.objectValue.insert_or_assign(std::move(key.stringValue), std::move(value));
            skipWs();
            if (pos_ < input_.size() && input_[pos_] == '}') {
                ++pos_;
                return true;
            }
            if (!consume(',')) return false;
        }
    }

    const std::string& input_;
    size_t pos_ = 0;
    int depth_ = 0;
    static constexpr int kMaxDepth = 128;
};

static const JsonValue* getField(const JsonValue& obj, const std::string& key) {
    if (obj.type != JsonValue::Type::Object) return nullptr;
    auto it = obj.objectValue.find(key);
    return it == obj.objectValue.end() ? nullptr : &it->second;
}

static std::string jsonStringField(const JsonValue& obj, const std::string& key) {
    auto* v = getField(obj, key);
    return (v && v->type == JsonValue::Type::String) ? v->stringValue : "";
}

static bool jsonBoolField(const JsonValue& obj, const std::string& key) {
    auto* v = getField(obj, key);
    if (!v) return false;
    if (v->type == JsonValue::Type::Bool) return v->boolValue;
    if (v->type == JsonValue::Type::Number) {
        for (char c:v->stringValue) {
            if (c=='e' || c=='E') break;
            if (c>='1' && c<='9') return true;
        }
        return false;
    }
    if (v->type == JsonValue::Type::String) return v->stringValue == "true" || v->stringValue == "1";
    return false;
}

template<class T> static std::optional<T> jsonInteger(const JsonValue& value) {
    static_assert(std::is_integral_v<T> && sizeof(T)<=sizeof(uint64_t));
    if (value.type!=JsonValue::Type::Number && value.type!=JsonValue::Type::String) return {};
    std::string_view token=value.stringValue;
    const bool quoted=value.type==JsonValue::Type::String;
    if (quoted) {
        while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front()))) token.remove_prefix(1);
        while (!token.empty() && std::isspace(static_cast<unsigned char>(token.back()))) token.remove_suffix(1);
    }
    if (token.empty()) return {};
    const bool negative=token.front()=='-';
    if (negative || (quoted && token.front()=='+')) token.remove_prefix(1);
    if (token.empty()) return {};
    uint64_t magnitude=0;
    if (quoted) {
        int base=10;
        if (token.size()>1 && token.front()=='0') {
            base=8;
            if (token[1]=='x' || token[1]=='X') {base=16;token.remove_prefix(2);}
        }
        if (token.empty()) return {};
        auto [end,error]=std::from_chars(token.data(),token.data()+token.size(),magnitude,base);
        if (error!=std::errc{} || end!=token.data()+token.size()) return {};
    } else {
        // Normalize the exact decimal coefficient/scale, including integral
        // exponent notation. This works when long double is only 64 bits too.
        std::string digits;size_t fractional=0,pos=0;bool afterPoint=false;
        for (;pos<token.size() && token[pos]!='e' && token[pos]!='E';++pos) {
            if (token[pos]=='.') {afterPoint=true;continue;}
            digits+=token[pos];if (afterPoint) ++fractional;
        }
        const auto first=digits.find_first_not_of('0');
        if (first==std::string::npos) return T{};
        digits.erase(0,first);
        size_t exponent=0;bool negativeExponent=false;
        if (pos<token.size()) {
            ++pos;negativeExponent=token[pos]=='-';
            if (token[pos]=='-' || token[pos]=='+') ++pos;
            // Beyond this magnitude a nonzero coefficient either overflows
            // every supported integer or has a nonzero fractional part.
            if (token.size()>SIZE_MAX-20) return {};
            const size_t bound=token.size()+20;
            for (;pos<token.size();++pos) {
                const unsigned digit=token[pos]-'0';
                if (exponent>(bound-digit)/10) return {};
                exponent=exponent*10+digit;
            }
        }
        size_t remove=0,append=0;
        if (negativeExponent) {
            if (exponent>digits.size() || fractional>digits.size()-exponent) return {};
            remove=fractional+exponent;
        } else if (exponent>=fractional) append=exponent-fractional;
        else remove=fractional-exponent;
        if (remove>digits.size() || append>20) return {};
        const size_t end=digits.size()-remove;
        for (size_t i=end;i<digits.size();++i) if (digits[i]!='0') return {};
        for (size_t i=0;i<end+append;++i) {
            const unsigned digit=i<end ? digits[i]-'0' : 0;
            if (magnitude>(UINT64_MAX-digit)/10) return {};
            magnitude=magnitude*10+digit;
        }
    }
    if constexpr (std::is_signed_v<T>) {
        const uint64_t maximum=static_cast<uint64_t>(std::numeric_limits<T>::max());
        if (magnitude>maximum+static_cast<unsigned>(negative)) return {};
        if (negative && magnitude==maximum+1) return std::numeric_limits<T>::min();
        const T result=static_cast<T>(magnitude);
        return negative ? -result : result;
    } else {
        if ((negative && magnitude!=0) || magnitude>std::numeric_limits<T>::max()) return {};
        return static_cast<T>(magnitude);
    }
}

template<class T> static T jsonIntegerField(const JsonValue& obj,const std::string& key,T defaultValue={}) {
    const auto* field=getField(obj,key);
    if (!field) return defaultValue;
    auto parsed=jsonInteger<T>(*field);
    if (!parsed) throw std::invalid_argument("Invalid table integer: "+key);
    return *parsed;
}
static int jsonIntField(const JsonValue& obj,const std::string& key,int fallback=0) {return jsonIntegerField<int>(obj,key,fallback);}
static size_t jsonSizeField(const JsonValue& obj,const std::string& key,size_t fallback=0) {return jsonIntegerField<size_t>(obj,key,fallback);}
static uintptr_t jsonAddressField(const JsonValue& obj,const std::string& key) {return jsonIntegerField<uintptr_t>(obj,key);}

static ValueType jsonValueTypeField(const JsonValue& obj) {
    auto* v = getField(obj, "type");
    if (!v) return ValueType::Int32;
    auto numericType=[&] {
        const auto type=jsonInteger<int>(*v);
        if (!type || *type<static_cast<int>(ValueType::Byte) || *type>static_cast<int>(ValueType::Pointer))
            throw std::invalid_argument("Invalid table value type");
        return static_cast<ValueType>(*type);
    };
    if (v->type==JsonValue::Type::Number) return numericType();
    if (v->type!=JsonValue::Type::String) throw std::invalid_argument("Invalid table value type");

    auto s = v->stringValue;
    if (s == "byte")   return ValueType::Byte;
    if (s == "i16")    return ValueType::Int16;
    if (s == "i32")    return ValueType::Int32;
    if (s == "i64")    return ValueType::Int64;
    if (s == "float")  return ValueType::Float;
    if (s == "double") return ValueType::Double;
    if (s == "string") return ValueType::String;
    if (s == "aob")    return ValueType::ByteArray;
    if (s == "pointer") return ValueType::Pointer;
    if (s == "unicode") return ValueType::UnicodeString;
    if (s == "binary") return ValueType::Binary;
    if (s == "grouped") return ValueType::Grouped;
    if (s == "custom") return ValueType::Custom;
    if (s == "all") return ValueType::All;
    return numericType();
}

TableFormat detectTableFormat(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return TableFormat::Unknown;
    char buf[512] = {0};
    f.read(buf, sizeof(buf) - 1);
    std::string head(buf, static_cast<size_t>(f.gcount()));

    // Password-protected .CETRAINER payloads lead with this magic line.
    if (head.rfind("CETRAINER1", 0) == 0) return TableFormat::Protected;

    // First meaningful byte after any BOM / leading whitespace decides XML vs JSON.
    size_t i = 0;
    if (head.size() >= 3 && (unsigned char)head[0] == 0xEF &&
        (unsigned char)head[1] == 0xBB && (unsigned char)head[2] == 0xBF)
        i = 3;  // UTF-8 BOM
    while (i < head.size() && (head[i] == ' ' || head[i] == '\t' ||
                              head[i] == '\r' || head[i] == '\n'))
        ++i;

    if ((i < head.size() && head[i] == '<') ||
        head.find("<CheatTable") != std::string::npos ||
        head.find("<CheatEntries") != std::string::npos)
        return TableFormat::Xml;
    if (i < head.size() && (head[i] == '{' || head[i] == '['))
        return TableFormat::Json;
    return TableFormat::Unknown;
}

bool CheatTable::loadAuto(const std::string& path) {
    TableFormat fmt = detectTableFormat(path);
    bool ok = false;
    switch (fmt) {
        case TableFormat::Xml:  ok = load(path); break;
        case TableFormat::Json: ok = loadJson(path); break;
        case TableFormat::Protected: ok = false; break;  // needs a password
        case TableFormat::Unknown:
            // Ambiguous: try both parsers, each self-validates and rejects a mismatch.
            ok = load(path) || loadJson(path); break;
    }
    const char* fmtName = fmt == TableFormat::Xml ? "xml" : fmt == TableFormat::Json ? "json"
                        : fmt == TableFormat::Protected ? "protected" : "unknown";
    if (ok)
        ce::log::info(ce::log::Cat::Ct, "loaded table '{}' (format={}, {} entries)",
                      path, fmtName, entries.size());
    else
        ce::log::warn(ce::log::Cat::Ct, "failed to load table '{}' (detected format={})",
                      path, fmtName);
    return ok;
}

bool CheatTable::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;

    std::string xml((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return loadFromString(xml);
}

bool CheatTable::loadFromString(const std::string& xml) {
    // Reject input that is not a cheat table so callers can distinguish a
    // valid (possibly empty) table from "not a CT at all".
    if (xml.find("<CheatTable") == std::string::npos &&
        xml.find("<CheatEntries>") == std::string::npos)
        return false;

    // Table-level tags (GameName, LuaScript, …) live OUTSIDE <CheatEntries>. CE
    // writes <LuaScript> AFTER the entries block, so searching only the part
    // before <CheatEntries> missed it entirely. Search everything outside the
    // entries block instead; per-entry <LuaScript> tags stay inside and are never
    // matched here.
    auto entriesStart = xml.find("<CheatEntries>");
    // Must be the matching close: a group nests its children in their own
    // <CheatEntries>, so the first close tag can be a child's, which would leave
    // later per-entry fields in the "outside" region and let getTag() pick up a
    // record's <LuaScript> as the table-level one.
    auto entriesClose = (entriesStart == std::string::npos)
        ? std::string::npos
        : findMatchingClose(xml, entriesStart, "CheatEntries");
    std::string headerXml;
    if (entriesStart != std::string::npos && entriesClose != std::string::npos) {
        headerXml = xml.substr(0, entriesStart);
        headerXml += xml.substr(entriesClose + std::string("</CheatEntries>").size());
    } else {
        headerXml = xml;
    }

    gameName = xmlUnescape(getTag(headerXml, "GameName"));
    gameVersion = xmlUnescape(getTag(headerXml, "GameVersion"));
    author = xmlUnescape(getTag(headerXml, "Author"));
    comment = xmlUnescape(getTag(headerXml, "Comment"));
    luaScript = xmlUnescape(getTag(headerXml, "LuaScript"));

    // Preserve the raw <Forms> block (Delphi form designs) verbatim so editing
    // and re-saving a table that has forms does not silently drop them.
    rawFormsXml = getTag(xml, "Forms");

    structures.clear();
    auto structuresXml = getTag(xml, "Structures");
    for (const auto& structureXml : getTagBlocks(structuresXml, "Structure")) {
        StructureDefinition structure;
        structure.name = xmlUnescape(getTag(structureXml, "Name"));
        auto sizeStr = getTag(structureXml, "Size");
        if (!sizeStr.empty()) {
            try { structure.size = std::stoull(sizeStr, nullptr, 0); } catch (...) {}
        }

        auto elementsXml = getTag(structureXml, "Elements");
        for (const auto& elementXml : getTagBlocks(elementsXml, "Element")) {
            StructureField field;
            field.name = xmlUnescape(getTag(elementXml, "Name"));
            auto offsetStr = getTag(elementXml, "Offset");
            auto fieldSizeStr = getTag(elementXml, "Size");
            if (!offsetStr.empty()) {
                try { field.offset = std::stoull(offsetStr, nullptr, 0); } catch (...) {}
            }
            if (!fieldSizeStr.empty()) {
                try { field.size = std::stoull(fieldSizeStr, nullptr, 0); } catch (...) {}
            }
            field.type = strToType(getTag(elementXml, "Type"));
            field.displayMethod = xmlUnescape(getTag(elementXml, "DisplayMethod"));
            field.nestedStructure = xmlUnescape(getTag(elementXml, "NestedStructure"));
            structure.fields.push_back(std::move(field));
        }

        if (!structure.name.empty() || !structure.fields.empty())
            structures.push_back(std::move(structure));
    }

    disassemblerComments.clear();
    auto commentsXml = getTag(xml, "DisassemblerComments");
    for (const auto& cXml : getTagBlocks(commentsXml, "DisassemblerComment")) {
        DisassemblerComment c;
        c.address = xmlUnescape(getTag(cXml, "Address"));
        c.comment = xmlUnescape(getTag(cXml, "Comment"));
        c.label   = xmlUnescape(getTag(cXml, "Label"));
        if (!c.address.empty() && (!c.comment.empty() || !c.label.empty()))
            disassemblerComments.push_back(std::move(c));
    }

    // Parse CheatEntries. CE nests a group's children inside the group's own
    // <CheatEntries>, so extract the outermost list depth-aware and recurse.
    entries.clear();
    auto topOpen = xml.find("<CheatEntries>");
    if (topOpen != std::string::npos) {
        auto topClose = findMatchingClose(xml, topOpen, "CheatEntries");
        if (topClose != std::string::npos) {
            size_t cs = topOpen + std::string("<CheatEntries>").size();
            bool validFormat = true;
            parseCheatEntriesBlock(xml.substr(cs, topClose - cs), -1, entries, validFormat);
            if (!validFormat) return false;
        }
    }

    return true;
}

std::string buildPointerExpression(const std::string& base, const std::vector<int64_t>& offsets) {
    if (offsets.empty()) return base;
    // Build inside-out from the deepest (last) offset to the shallowest (first):
    // each step dereferences the current expression and adds the offset.
    std::string expr = base;
    for (size_t i = offsets.size(); i-- > 0; ) {
        int64_t off = offsets[i];
        char buf[40];
        if (off >= 0) snprintf(buf, sizeof(buf), "]+%llx", static_cast<unsigned long long>(off));
        else          snprintf(buf, sizeof(buf), "]-%llx", static_cast<unsigned long long>(-off));
        expr = "[" + expr + buf;
    }
    return expr;
}

namespace {
std::string trimPtrExpr(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

// Parse "+1a" / "-4" / "0x1a" / "1a" (already trimmed) as a signed hex offset.
bool parseSignedHexOffset(const std::string& s, int64_t& out) {
    if (s.empty()) return false;
    size_t i = 0;
    bool neg = false;
    if (s[i] == '+' || s[i] == '-') { neg = (s[i] == '-'); ++i; }
    if (i + 1 < s.size() && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) i += 2;
    if (i >= s.size()) return false;
    uint64_t val = 0;
    for (; i < s.size(); ++i) {
        char c = s[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        val = val * 16 + static_cast<uint64_t>(d);
    }
    out = neg ? -static_cast<int64_t>(val) : static_cast<int64_t>(val);
    return true;
}
} // namespace

std::optional<PointerExpr> parsePointerExpression(const std::string& expr) {
    std::string e = trimPtrExpr(expr);
    if (e.empty() || e.front() != '[') return std::nullopt;   // a plain address, not a chain
    PointerExpr out;
    // Peel one bracket level at a time. The outermost '[' is closed by the LAST ']';
    // whatever trails it is this level's "+/-offset" (buildPointerExpression always
    // emits one, including +0). offsets accumulate outermost-first, matching the
    // vector order buildPointerExpression consumes.
    while (!e.empty() && e.front() == '[') {
        size_t rb = e.find_last_of(']');
        if (rb == std::string::npos) return std::nullopt;
        std::string tail = trimPtrExpr(e.substr(rb + 1));
        int64_t off = 0;
        if (!tail.empty() && !parseSignedHexOffset(tail, off)) return std::nullopt;
        out.offsets.push_back(off);
        e = trimPtrExpr(e.substr(1, rb - 1));
    }
    if (e.empty()) return std::nullopt;   // malformed: bracket chain with no base
    out.base = e;
    return out;
}

// ── JSON format (our native format, simpler) ──

bool CheatTable::saveJson(const std::string& path) const {
    if (!validRecordFormats(entries)) return false;
    std::ofstream f(path);
    if (!f) return false;
    bool success=writeTableJson(*this,f);
    f.flush();
    success=success && f.good();
    f.close();
    return success && !f.fail();
}

bool writeTableJson(const CheatTable& table,std::ostream& f) {
    const auto& entries=table.entries;
    const auto& gameName=table.gameName;
    const auto& gameVersion=table.gameVersion;
    const auto& author=table.author;
    const auto& comment=table.comment;
    const auto& luaScript=table.luaScript;
    const auto& structures=table.structures;
    const auto& disassemblerComments=table.disassemblerComments;
    const auto& rawFormsXml=table.rawFormsXml;
    if (!validRecordFormats(entries)) return false;

    f << "{\n";
    f << "  \"game\": \"" << jsonEscape(gameName) << "\",\n";
    f << "  \"version\": \"" << jsonEscape(gameVersion) << "\",\n";
    f << "  \"author\": \"" << jsonEscape(author) << "\",\n";
    f << "  \"comment\": \"" << jsonEscape(comment) << "\",\n";
    f << "  \"luaScript\": \"" << jsonEscape(luaScript) << "\",\n";
    f << "  \"rawFormsXml\": \"" << jsonEscape(rawFormsXml) << "\",\n";
    f << "  \"structures\": [\n";
    for (size_t i = 0; i < structures.size(); ++i) {
        const auto& s = structures[i];
        f << "    {\"name\":\"" << jsonEscape(s.name) << "\",\"size\":" << s.size << ",\"fields\":[";
        for (size_t fieldIndex = 0; fieldIndex < s.fields.size(); ++fieldIndex) {
            const auto& field = s.fields[fieldIndex];
            f << "{\"name\":\"" << jsonEscape(field.name) << "\"";
            f << ",\"offset\":" << field.offset;
            f << ",\"type\":" << (int)field.type;
            f << ",\"size\":" << field.size;
            if (!field.displayMethod.empty())
                f << ",\"display\":\"" << jsonEscape(field.displayMethod) << "\"";
            if (!field.nestedStructure.empty())
                f << ",\"nested\":\"" << jsonEscape(field.nestedStructure) << "\"";
            f << "}";
            if (fieldIndex + 1 < s.fields.size()) f << ",";
        }
        f << "]}";
        if (i + 1 < structures.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n";
    f << "  \"disassemblerComments\": [";
    for (size_t i = 0; i < disassemblerComments.size(); ++i) {
        const auto& c = disassemblerComments[i];
        f << (i ? "," : "") << "{\"address\":\"" << jsonEscape(c.address) << "\"";
        if (!c.comment.empty()) f << ",\"comment\":\"" << jsonEscape(c.comment) << "\"";
        if (!c.label.empty())   f << ",\"label\":\"" << jsonEscape(c.label) << "\"";
        f << "}";
    }
    f << "],\n";
    f << "  \"entries\": [\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        auto& e = entries[i];
        f << "    {";
        f << "\"id\":" << e.id;
        f << ",\"desc\":\"" << jsonEscape(e.description) << "\"";
        if (!e.isGroup) {
            char addr[32]; snprintf(addr, sizeof(addr), "0x%lx", e.address);
            f << ",\"addr\":\"" << addr << "\"";
            f << ",\"type\":" << (int)e.type;
            f << ",\"value\":\"" << jsonEscape(e.value) << "\"";
            // Persist the fields the XML path round-trips too; otherwise a
            // pointer chain / symbolic base / String-AoB length is lost through
            // saveJson+loadJson (i.e. every .CETRAINER save/load).
            if (!e.addressString.empty())
                f << ",\"addrString\":\"" << jsonEscape(e.addressString) << "\"";
            if (!e.offsets.empty()) {
                f << ",\"offsets\":[";
                for (size_t k = 0; k < e.offsets.size(); ++k)
                    f << (k ? "," : "") << e.offsets[k];
                f << "]";
            }
            if (e.length > 0) f << ",\"length\":" << e.length;
        }
        if (e.active) f << ",\"active\":true";
        if (e.showAsHex) f << ",\"showAsHex\":true";
        if (!e.showAsSigned) f << ",\"showAsSigned\":false";
        if (e.dataByteOrder != ByteOrder::Unknown) f << ",\"dataByteOrder\":\"" << (e.dataByteOrder == ByteOrder::Big ? "big" : "little") << "\"";
        if (e.pointerWidth) f << ",\"pointerWidth\":" << static_cast<unsigned>(e.pointerWidth);
        if (e.freezeMode != FreezeMode::Normal)
            f << ",\"freezeMode\":" << (int)e.freezeMode;
        if (e.isGroup) f << ",\"group\":true";
        if (e.collapsed) f << ",\"collapsed\":true";
        if (!e.autoAsmScript.empty()) f << ",\"asm\":\"" << jsonEscape(e.autoAsmScript) << "\"";
        if (!e.luaScript.empty()) f << ",\"lua\":\"" << jsonEscape(e.luaScript) << "\"";
        if (!e.optionsXml.empty()) f << ",\"options\":\"" << jsonEscape(e.optionsXml) << "\"";
        if (!e.activateChildren) f << ",\"activateChildren\":false";
        if (!e.deactivateChildren) f << ",\"deactivateChildren\":false";
        if (!e.color.empty()) f << ",\"color\":\"" << jsonEscape(e.color) << "\"";
        if (!e.dropdownList.empty()) f << ",\"dropdown\":\"" << jsonEscape(e.dropdownList) << "\"";
        if (!e.hotkeyKeys.empty()) f << ",\"hotkeys\":\"" << jsonEscape(e.hotkeyKeys) << "\"";
        if (!e.increaseHotkeyKeys.empty()) f << ",\"increaseHotkey\":\"" << jsonEscape(e.increaseHotkeyKeys) << "\"";
        if (!e.setValueHotkeyKeys.empty()) f << ",\"setValueHotkey\":\"" << jsonEscape(e.setValueHotkeyKeys) << "\"";
        if (!e.setValueHotkeyValue.empty()) f << ",\"setValueHotkeyValue\":\"" << jsonEscape(e.setValueHotkeyValue) << "\"";
        if (!e.decreaseHotkeyKeys.empty()) f << ",\"decreaseHotkey\":\"" << jsonEscape(e.decreaseHotkeyKeys) << "\"";
        if (!e.hotkeyStep.empty()) f << ",\"hotkeyStep\":\"" << jsonEscape(e.hotkeyStep) << "\"";
        if (e.parentId >= 0) f << ",\"parent\":" << e.parentId;
        f << "}";
        if (i + 1 < entries.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n}\n";
    return f.good();
}

static bool readTableJson(const JsonValue& root,CheatTable& table) {
    auto& gameName=table.gameName;
    auto& gameVersion=table.gameVersion;
    auto& author=table.author;
    auto& comment=table.comment;
    auto& luaScript=table.luaScript;
    auto& rawFormsXml=table.rawFormsXml;
    auto& structures=table.structures;
    auto& disassemblerComments=table.disassemblerComments;
    auto& entries=table.entries;
    gameName = jsonStringField(root, getField(root,"game") ? "game" : "process");
    gameVersion = jsonStringField(root, "version");
    author = jsonStringField(root, "author");
    comment = jsonStringField(root, "comment");
    luaScript = jsonStringField(root, "luaScript");
    rawFormsXml = jsonStringField(root, "rawFormsXml");

    structures.clear();
    auto* structuresValue = getField(root, "structures");
    if (structuresValue) {
        if (structuresValue->type!=JsonValue::Type::Array) return false;
        for (const auto& item : structuresValue->arrayValue) {
            if (item.type != JsonValue::Type::Object) return false;

            StructureDefinition structure;
            structure.name = jsonStringField(item, "name");
            structure.size = jsonSizeField(item, "size");

            auto* fieldsValue = getField(item, "fields");
            if (fieldsValue) {
                if (fieldsValue->type!=JsonValue::Type::Array) return false;
                for (const auto& fieldItem : fieldsValue->arrayValue) {
                    if (fieldItem.type != JsonValue::Type::Object) return false;
                    StructureField field;
                    field.name = jsonStringField(fieldItem, "name");
                    field.offset = jsonSizeField(fieldItem, "offset");
                    field.type = jsonValueTypeField(fieldItem);
                    field.size = jsonSizeField(fieldItem, "size", 4);
                    field.displayMethod = jsonStringField(fieldItem, "display");
                    field.nestedStructure = jsonStringField(fieldItem, "nested");
                    structure.fields.push_back(std::move(field));
                }
            }

            structures.push_back(std::move(structure));
        }
    }

    disassemblerComments.clear();
    auto* dcValue = getField(root, "disassemblerComments");
    if (dcValue) {
        if (dcValue->type!=JsonValue::Type::Array) return false;
        for (const auto& item : dcValue->arrayValue) {
            if (item.type != JsonValue::Type::Object) return false;
            DisassemblerComment c;
            c.address = jsonStringField(item, "address");
            c.comment = jsonStringField(item, "comment");
            c.label   = jsonStringField(item, "label");
            if (!c.address.empty()) disassemblerComments.push_back(std::move(c));
        }
    }

    entries.clear();
    auto* entriesValue = getField(root, "entries");
    if (!entriesValue) return true;
    if (entriesValue->type!=JsonValue::Type::Array) return false;

    for (const auto& item : entriesValue->arrayValue) {
        if (item.type != JsonValue::Type::Object) return false;

        CheatEntry e;
        e.id = jsonIntField(item, "id");
        e.description = jsonStringField(item, getField(item,"desc") ? "desc" : "description");
        e.address = jsonAddressField(item, getField(item,"addr") ? "addr" : "address");
        e.addressString = jsonStringField(item, getField(item,"addrString") ? "addrString" : "addressExpr");
        e.type = jsonValueTypeField(item);
        e.value = jsonStringField(item, "value");
        if (auto* offs = getField(item, "offsets")) {
            if (offs->type!=JsonValue::Type::Array) return false;
            for (const auto& ov : offs->arrayValue) {
                const auto offset=jsonInteger<int64_t>(ov);
                if (!offset) return false;
                e.offsets.push_back(*offset);
            }
        }
        e.length = jsonIntField(item, getField(item,"length") ? "length" : "byteCount", 0);
        if (e.length<0) return false;
        e.active = jsonBoolField(item, "active");
        e.showAsHex = jsonBoolField(item, "showAsHex");
        e.showAsSigned = getField(item, "showAsSigned") ? jsonBoolField(item, "showAsSigned") : true;
        if (auto* order = getField(item, "dataByteOrder"); order && order->type != JsonValue::Type::String) return false;
        if (auto* width = getField(item,"pointerWidth"); width && width->type!=JsonValue::Type::Number) return false;
        if (!parseRecordDataFormat(jsonStringField(item, "dataByteOrder"), std::to_string(jsonIntField(item, "pointerWidth", 0)), e)) return false;
        if (!getField(item, "dataByteOrder") && jsonBoolField(item, "bigEndian")) e.dataByteOrder = ByteOrder::Big;
        const int freezeMode=jsonIntField(item,"freezeMode",0);
        if (freezeMode<static_cast<int>(FreezeMode::Normal) || freezeMode>static_cast<int>(FreezeMode::NeverDecrease)) return false;
        e.freezeMode=static_cast<FreezeMode>(freezeMode);
        e.isGroup = jsonBoolField(item, "group");
        e.collapsed = jsonBoolField(item, "collapsed");
        e.autoAsmScript = jsonStringField(item, "asm");
        e.luaScript = jsonStringField(item, "lua");
        e.optionsXml = jsonStringField(item, getField(item,"options") ? "options" : "optionsXml");
        if (!e.optionsXml.empty()) {
            e.activateChildren   = e.optionsXml.find("moActivateChildrenAsWell=\"1\"")   != std::string::npos;
            e.deactivateChildren = e.optionsXml.find("moDeactivateChildrenAsWell=\"1\"") != std::string::npos;
        }
        if (getField(item,"activateChildren")) e.activateChildren=jsonBoolField(item,"activateChildren");
        if (getField(item,"deactivateChildren")) e.deactivateChildren=jsonBoolField(item,"deactivateChildren");
        e.color = jsonStringField(item, "color");
        e.dropdownList = jsonStringField(item, "dropdown");
        e.hotkeyKeys = jsonStringField(item, "hotkeys");
        e.increaseHotkeyKeys = jsonStringField(item, "increaseHotkey");
        e.setValueHotkeyKeys = jsonStringField(item, "setValueHotkey");
        e.setValueHotkeyValue = jsonStringField(item, "setValueHotkeyValue");
        e.decreaseHotkeyKeys = jsonStringField(item, "decreaseHotkey");
        e.hotkeyStep = jsonStringField(item, "hotkeyStep");
        e.parentId = jsonIntField(item, "parent", -1);
        // GUI JSON stores parent rows; native JSON stores stable parent IDs.
        if (getField(item,"description") && !getField(item,"desc") && e.parentId>=0 &&
            static_cast<size_t>(e.parentId)<entriesValue->arrayValue.size())
            e.parentId=jsonIntField(entriesValue->arrayValue[e.parentId],"id",e.parentId);
        entries.push_back(std::move(e));
    }

    return true;
}

bool CheatTable::loadJson(const std::string& path) {
    std::ifstream input(path);
    if (!input) return false;
    std::string json{std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
    if (input.bad()) return false;
    return loadJsonFromString(json);
}

bool CheatTable::loadJsonFromString(const std::string& json) {
    JsonValue root;
    if (!JsonParser(json).parse(root) || root.type!=JsonValue::Type::Object) return false;
    CheatTable pending;
    try {
        if (!readTableJson(root,pending)) return false;
    } catch (const std::invalid_argument&) {return false;}
    *this=std::move(pending);
    return true;
}

bool CheatTable::saveProtected(const std::string& path, const std::string& password) const {
    auto tempPath = makeSecureTempFile();
    if (tempPath.empty())
        return false;
    std::error_code ec;
    if (!saveJson(tempPath)) {
        std::filesystem::remove(tempPath, ec);
        return false;
    }

    std::ifstream in(tempPath, std::ios::binary);
    std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    std::filesystem::remove(tempPath, ec);
    if (json.empty())
        return false;

    auto encrypted = xorCrypt(json, password);
    std::ofstream out(path, std::ios::binary);
    if (!out)
        return false;

    out << "CETRAINER1\n";
    out << fnv1a(password) << "\n";
    out.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
    out.flush();
    bool success=out.good();
    out.close();
    return success && !out.fail();
}

bool CheatTable::loadProtected(const std::string& path, const std::string& password) {
    // .CETRAINER files are commonly shared/downloaded (untrusted). A real cheat
    // table is a few KB; reject an absurdly large one up front so a hostile file
    // can't drive the whole-payload read below into bad_alloc.
    std::error_code sizeEc;
    auto fsize = std::filesystem::file_size(path, sizeEc);
    if (!sizeEc && fsize > 64u * 1024 * 1024)
        return false;

    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;

    std::string magic;
    std::string hashLine;
    if (!std::getline(in, magic) || !std::getline(in, hashLine))
        return false;
    if (magic != "CETRAINER1")
        return false;

    uint64_t expectedHash = 0;
    try {
        expectedHash = std::stoull(hashLine);
    } catch (...) {
        return false;
    }
    if (expectedHash != fnv1a(password))
        return false;

    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(in)), {});
    auto json = xorDecrypt(encrypted, password);

    auto tempPath = makeSecureTempFile();
    if (tempPath.empty())
        return false;
    {
        std::ofstream out(tempPath, std::ios::binary);
        if (!out) {
            std::error_code ec;
            std::filesystem::remove(tempPath, ec);
            return false;
        }
        out.write(json.data(), static_cast<std::streamsize>(json.size()));
    }

    bool loaded = loadJson(tempPath);
    std::error_code ec;
    std::filesystem::remove(tempPath, ec);
    return loaded;
}

} // namespace ce
