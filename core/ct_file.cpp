#include "core/ct_file.hpp"
#include "core/ct_file_stream.hpp"
#include "core/json.hpp"
#include "core/log.hpp"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <charconv>
#include <set>
#include <filesystem>
#include <unordered_map>
#include <functional>
#include <vector>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <string_view>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// Simple XML writer/reader (no external dependency)
namespace ce {

// Groups nest this deep at most; a deeper table is refused rather than
// recursing without bound.
constexpr int kMaxEntryDepth = 64;


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

static bool writeAll(int fd, std::string_view bytes) {
    for (size_t done = 0; done < bytes.size();) {
        const ssize_t n = ::write(fd, bytes.data() + done, bytes.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

static bool pwriteAll(int fd, std::string_view bytes) {
    for (size_t done = 0; done < bytes.size();) {
        const ssize_t n = ::pwrite(fd, bytes.data() + done, bytes.size() - done, static_cast<off_t>(done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; return false; }
        done += static_cast<size_t>(n);
    }
    return true;
}

static bool preadAll(int fd, std::string& out, size_t size) {
    out.resize(size);
    for (size_t done = 0; done < size;) {
        const ssize_t n = ::pread(fd, out.data() + done, size - done, static_cast<off_t>(done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

// Rewrite the file itself: what a plain save does. It keeps the inode (owner,
// hard links, ACLs). The space is reserved before anything changes, the new
// bytes overwrite the old ones and the file is cut to size last; a write that
// fails partway (a full disk, an I/O error) puts the old bytes back, so the
// old table survives unless the process dies mid-write.
static bool writeFileInPlace(const std::filesystem::path& target, std::string_view bytes) {
    bool readable = true;
    int fd = ::open(target.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if (fd < 0 && errno == EACCES) {   // write-only for us: no copy to restore from
        readable = false;
        fd = ::open(target.c_str(), O_WRONLY | O_CLOEXEC);
    }
    if (fd < 0) return false;
    auto fail = [fd](int failure) { ::close(fd); errno = failure; return false; };
    struct stat st{};
    if (::fstat(fd, &st) != 0) return fail(errno);
    if (!S_ISREG(st.st_mode)) {   // a device or a pipe takes the bytes as a stream
        bool ok = writeAll(fd, bytes);
        ok = ::close(fd) == 0 && ok;
        return ok;
    }
    // The old table, kept to undo a failed rewrite (up to a size it is sane
    // to hold in memory).
    std::string old;
    const bool haveOld = readable && st.st_size >= 0 && static_cast<uint64_t>(st.st_size) <= (1ull << 30) &&
                         preadAll(fd, old, static_cast<size_t>(st.st_size));
    if (!bytes.empty()) {
        const int reserved = ::posix_fallocate(fd, 0, static_cast<off_t>(bytes.size()));
        if (reserved != 0 && reserved != EOPNOTSUPP && reserved != ENOSYS) {
            // posix_fallocate may have grown the file with zeros before failing.
            if (haveOld) (void)::ftruncate(fd, static_cast<off_t>(old.size()));
            return fail(reserved);
        }
    }
    bool ok = pwriteAll(fd, bytes);
    ok = ok && ::ftruncate(fd, static_cast<off_t>(bytes.size())) == 0;
    ok = ok && ::fsync(fd) == 0;
    if (!ok) {
        const int failure = errno;
        if (haveOld && pwriteAll(fd, old) && ::ftruncate(fd, static_cast<off_t>(old.size())) == 0)
            (void)::fsync(fd);
        return fail(failure);
    }
    return ::close(fd) == 0;
}

// Replace the file at path with bytes so that it is never left truncated or half
// written: write a temporary file in the same directory, flush it to disk and
// rename it over the old one. A symlink is followed when it resolves; a
// dangling one is refused rather than replaced by a regular file. A file the
// user may not write (a chmod 444 table) is refused, as an ordinary save
// would be. Where a rename would change the file's identity (another owner,
// more hard links, not a regular file) or cannot be done (an unwritable
// directory, a bind-mounted file), the file is rewritten in place instead.
static bool writeFileAtomically(const std::string& path, std::string_view bytes) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path target(path);
    if (fs::is_symlink(target, ec)) {
        auto real = fs::canonical(target, ec);
        if (ec) { errno = ENOENT; return false; }
        target = real;
    }
    const fs::path dir = target.has_parent_path() ? target.parent_path() : fs::path(".");
    struct stat old{};
    const bool existed = ::stat(target.c_str(), &old) == 0;
    if (existed) {
        if (::faccessat(AT_FDCWD, target.c_str(), W_OK, AT_EACCESS) != 0) return false;
        const bool root = ::geteuid() == 0;
        if (!S_ISREG(old.st_mode) || old.st_nlink > 1 || (!root && old.st_uid != ::geteuid()))
            return writeFileInPlace(target, bytes);
    }
    static std::atomic<unsigned> counter{0};
    std::string temp;
    int fd = -1;
    for (int attempt = 0; attempt < 100 && fd < 0; ++attempt) {
        temp = (dir / ("." + target.filename().string() + ".tmp" + std::to_string(getpid()) + "-" +
                       std::to_string(counter++))).string();
        // 0666 less the umask, like any new file; an existing table keeps its mode.
        fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
        if (fd >= 0 || errno == EEXIST) continue;
        // A directory we cannot add to (or a file we cannot rename over) still
        // lets us write a table that exists and is writable.
        if (existed && (errno == EACCES || errno == EPERM || errno == EROFS || errno == EXDEV || errno == EBUSY))
            return writeFileInPlace(target, bytes);
        return false;
    }
    if (fd < 0) return false;
    bool ok = true;
    if (existed) {
        // Root saving a user's table keeps it the user's. Otherwise only the
        // group can differ (we own the file); one we may not give the new
        // file is kept by rewriting the old one.
        if (::fchown(fd, ::geteuid() == 0 ? old.st_uid : static_cast<uid_t>(-1), old.st_gid) != 0) {
            if (::geteuid() == 0) ok = false;
            else {
                ::close(fd);
                ::unlink(temp.c_str());
                return writeFileInPlace(target, bytes);
            }
        }
        // After fchown, which may clear set-id bits.
        ok = ok && ::fchmod(fd, old.st_mode & 07777) == 0;
    }
    ok = ok && writeAll(fd, bytes);
    ok = ok && ::fsync(fd) == 0;
    ok = ::close(fd) == 0 && ok;
    if (ok && ::rename(temp.c_str(), target.c_str()) != 0) {
        const int failure = errno;
        ::unlink(temp.c_str());
        if (existed && (failure == EXDEV || failure == EBUSY)) return writeFileInPlace(target, bytes);
        errno = failure;
        return false;
    }
    if (!ok) {
        const int failure = errno;
        ::unlink(temp.c_str());
        errno = failure;
        return false;
    }
    // Make the rename itself durable.
    if (int dirFd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); dirFd >= 0) {
        ::fsync(dirFd);
        ::close(dirFd);
    }
    return true;
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

// Element text as Cheat Engine writes it: only what would break the markup
// is escaped, so an address keeps its quotes ("game.exe"+10) on disk.
static std::string xmlEscapeText(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            default:  out += c;
        }
    }
    return out;
}

// The tag parsers, defined with the loader below.
static std::string getTag(const std::string& xml, const std::string& tag);
static std::vector<std::string> getTagBlocks(const std::string& xml, const std::string& tag);

// One CE <Hotkey> element as the loader reads it.
struct ParsedHotkey {
    std::string block;   // the whole element, as written
    std::string keys;    // "Ctrl+H"
    std::string value;   // set-value target, or the increase/decrease step
    int action = 0;      // CE mrh* action code
    bool usable = false; // has keys and is not Active="0"
    // The loader marks a kept element that fills a record slot (LinuxSlot="1"),
    // and for increase and decrease records the record's step at load
    // (LinuxSlotStep). The marks live only in memory and the JSON forms; a
    // .CT never carries them.
    bool slotBound = false;
    std::string slotStep;
};
static std::vector<ParsedHotkey> parseHotkeyBlocks(const std::string& xml);
static std::string withoutSlotMarks(std::string block);

// The record slot a hotkey action binds: 0 toggle (Toggle Activation, its
// increase/decrease variants, Activate, Deactivate), 1 set value, 2 increase,
// 3 decrease.
static int hotkeySlot(int action) {
    return action <= 4 ? 0 : action - 4;
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

// Our <Structures> format has no <Unicode> flag beside the type, so a wide
// string field needs a name of its own.
static std::string fieldTypeToStr(ValueType vt) {
    return vt == ValueType::UnicodeString ? "Unicode String" : typeToStr(vt);
}

// CE's hotkey <Action> texts (MemRecHotkeyActionToText), indexed by its mrh* codes.
static const char* const kHotkeyActions[] = {
    "Toggle Activation", "Toggle Activation Allow Increase", "Toggle Activation Allow Decrease",
    "Activate", "Deactivate", "Set Value", "Increase Value", "Decrease Value"};

// An <Action> as CE writes it (text), or the numeric code older builds of this
// port wrote. Anything else is a toggle, as in CE's TextToMemRecHotkeyAction.
static int hotkeyActionFromText(const std::string& text) {
    for (int i = 0; i < 8; ++i)
        if (text == kHotkeyActions[i]) return i;
    int code = 0;
    const auto [stop, error] = std::from_chars(text.data(), text.data() + text.size(), code);
    return error == std::errc() && stop == text.data() + text.size() && code >= 0 && code < 8 ? code : 0;
}

// CE <Color> is a Delphi TColor in hex: $00BBGGRR. Values with any high byte set
// are system colors (clWindowText is 80000008) or clDefault/clNone: no color.
// A leading '#' marks the RGB text older builds of this port wrote.
static std::string colorFromCE(const std::string& text) {
    if (text.empty() || text[0] == '#') return text;
    uint32_t v = 0;
    const auto [stop, error] = std::from_chars(text.data(), text.data() + text.size(), v, 16);
    if (error != std::errc() || stop != text.data() + text.size() || (v & 0xFF000000u)) return {};
    char rgb[8];
    snprintf(rgb, sizeof(rgb), "%02X%02X%02X", v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF);
    return rgb;
}

// Inverse of colorFromCE for "RRGGBB", "#rrggbb" or "#aarrggbb"; "" if unreadable.
static std::string colorToCE(const std::string& color) {
    std::string_view hex = color;
    if (!hex.empty() && hex.front() == '#') hex.remove_prefix(1);
    if (hex.size() == 8) hex.remove_prefix(2);   // drop Qt's alpha
    uint32_t v = 0;
    const auto [stop, error] = std::from_chars(hex.data(), hex.data() + hex.size(), v, 16);
    if (hex.size() != 6 || error != std::errc() || stop != hex.data() + hex.size()) return {};
    char bgr[8];
    snprintf(bgr, sizeof(bgr), "%02X%02X%02X", v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF);
    return bgr;
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
    // The keypad is Qt's "Num" modifier on the same key, not the main digits.
    if (vk >= 96 && vk <= 105) return "Num+" + std::string(1, static_cast<char>('0' + (vk - 96)));
    switch (vk) {
        case 106: return "Num+*"; case 107: return "Num++"; case 109: return "Num+-";
        case 110: return "Num+."; case 111: return "Num+/";
        // US-layout punctuation (VK_OEM_*), as Qt names those keys.
        case 186: return ";"; case 187: return "="; case 188: return ","; case 189: return "-";
        case 190: return "."; case 191: return "/"; case 192: return "`"; case 219: return "[";
        case 220: return "\\"; case 221: return "]"; case 222: return "'";
        default: break;
    }
    if (vk >= 112 && vk <= 135) return "F" + std::to_string(vk - 111);                      // F1-F24
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
    if (key.empty() && !out.empty()) out.pop_back();   // modifier-only (rare): drop the last '+'
    out += key;
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
        try { int n = std::stoi(t.substr(1)); if (n >= 1 && n <= 24) return 111 + n; } catch (...) {}
    }
    if (t.size() == 1) {
        switch (t[0]) {
            case ';': return 186; case '=': case '+': return 187; case ',': return 188; case '-': return 189;
            case '.': return 190; case '/': return 191; case '`': return 192; case '[': return 219;
            case '\\': return 220; case ']': return 221; case '\'': return 222;
            default: break;
        }
    }
    return 0;
}

// A key with Qt's "Num" (keypad) modifier -> its keypad VK code, 0 if none.
static int keypadTokenToVK(const std::string& t) {
    if (t.size() != 1) return 0;
    if (t[0] >= '0' && t[0] <= '9') return 96 + (t[0] - '0');
    switch (t[0]) {
        case '*': return 106; case '+': return 107; case '-': return 109; case '.': return 110; case '/': return 111;
        default: return 0;
    }
}

// "Ctrl+Shift+F1" -> {17, 16, 112}; "Ctrl++" is Ctrl and the plus key, and
// "Num+5" the keypad 5. Unknown tokens are dropped.
static std::vector<int> keyStringToVKs(const std::string& s) {
    std::string rest = s;
    std::string plusKey;
    if (rest == "+") { rest.clear(); plusKey = "+"; }
    else if (rest.size() >= 2 && rest.compare(rest.size() - 2, 2, "++") == 0) { rest.resize(rest.size() - 2); plusKey = "+"; }
    std::vector<std::string> tokens;
    size_t start = 0;
    while (start <= rest.size()) {
        size_t plus = rest.find('+', start);
        std::string tok = rest.substr(start, plus == std::string::npos ? std::string::npos : plus - start);
        while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
        while (!tok.empty() && tok.back() == ' ') tok.pop_back();
        if (!tok.empty()) tokens.push_back(tok);
        if (plus == std::string::npos) break;
        start = plus + 1;
    }
    if (!plusKey.empty()) tokens.push_back(plusKey);
    std::vector<int> vks;
    bool keypad = false;
    for (const auto& tok : tokens) {
        if (tok == "Num") { keypad = true; continue; }
        int vk = keypad ? keypadTokenToVK(tok) : 0;
        if (!vk) vk = keyTokenToVK(tok);
        if (vk) vks.push_back(vk);
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
    if (type == "unicodestring" || type == "widestring") return ValueType::UnicodeString;
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
    std::ostringstream xml;
    return writeTableXml(*this, xml) && writeFileAtomically(path, xml.str());
}

// The end of the XML element whose '<' is at xml[at], past its close tag or
// "/>", searching no further than limit; npos if it does not close in time.
// Sets *name to the element's name.
static size_t elementEnd(const std::string& xml, size_t at, size_t limit, std::string* name = nullptr) {
    auto nameChar = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.' || c == ':';
    };
    size_t p = at + 1;
    while (p < limit && nameChar(xml[p])) ++p;
    if (p == at + 1 || p >= limit) return std::string::npos;
    const std::string tag = xml.substr(at + 1, p - at - 1);
    if (name) *name = tag;
    const size_t gt = xml.find('>', p);
    if (gt == std::string::npos || gt >= limit) return std::string::npos;
    if (xml[gt - 1] == '/') return gt + 1;
    const std::string open = "<" + tag, close = "</" + tag + ">";
    int depth = 1;
    size_t scan = gt + 1;
    while (true) {
        const size_t c = xml.find(close, scan);
        if (c == std::string::npos || c + close.size() > limit) return std::string::npos;
        size_t o = xml.find(open, scan);
        while (o != std::string::npos && o < c && o + open.size() < xml.size() && nameChar(xml[o + open.size()]))
            o = xml.find(open, o + 1);   // a longer name (<Offsets for <Offset)
        if (o != std::string::npos && o < c) {
            const size_t g = xml.find('>', o);
            if (g == std::string::npos || g >= c) return std::string::npos;
            if (xml[g - 1] != '/') ++depth;
            scan = g + 1;
        } else {
            if (--depth == 0) return c + close.size();
            scan = c + close.size();
        }
    }
}

// True when text is nothing but whole elements (and whitespace), only ones named
// onlyName if given, and none of them a record or record list. Raw XML kept from
// a table, or read from JSON, is written into the .CT as it is, so it must not
// be able to close or open records there.
static bool isElementSequence(const std::string& text, const char* onlyName = nullptr) {
    for (const char* bad : {"<CheatEntr", "</CheatEntr", "<CheatTable", "</CheatTable"})
        if (text.find(bad) != std::string::npos) return false;
    for (size_t p = 0;;) {
        p = text.find_first_not_of(" \t\r\n", p);
        if (p == std::string::npos) return true;
        std::string name;
        const size_t end = text[p] == '<' ? elementEnd(text, p, text.size(), &name) : std::string::npos;
        if (end == std::string::npos || (onlyName && name != onlyName)) return false;
        p = end;
    }
}

// A single self-closing <Options .../> element, as the loader keeps it.
static bool isOptionsElement(const std::string& s) {
    return s.rfind("<Options", 0) == 0 && s.size() >= 10 && s.compare(s.size() - 2, 2, "/>") == 0 &&
        s.find('<', 1) == std::string::npos && s.find('>') == s.size() - 1;
}

// Attribute text kept from a start tag (name="value" pairs): nothing that could
// end the tag early.
static bool isAttributeText(const std::string& s) {
    return s.find_first_of("<>") == std::string::npos && std::count(s.begin(), s.end(), '"') % 2 == 0;
}

static std::string trimmedXmlText(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}

// The record keeps the <Address>/<Offsets> texts we could not parse, and nothing
// has replaced the address since.
static bool keepsUnparsedPointer(const CheatEntry& e) {
    return !e.unparsedOffsets.empty() && e.offsets.empty() && e.addressString.rfind("(unsupported offset ", 0) == 0;
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
                f << "          <Type>" << fieldTypeToStr(field.type) << "</Type>\n";
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

    // <Address> and <Offsets> as CE writes them. The GUI and Lua keep a pointer
    // path as one expression ("[[game.exe+1C]+8]+10"); CE wants it as a base and
    // offsets, so one that is exactly what buildPointerExpression makes is split.
    auto writeAddressAndOffsets = [&](const CheatEntry& e, bool numericFallback) {
        if (keepsUnparsedPointer(e)) {
            f << "      <Address>" << xmlEscapeText(e.unparsedAddress) << "</Address>\n";
            f << "      <Offsets>\n";
            for (const auto& text : e.unparsedOffsets)
                f << "        <Offset>" << xmlEscapeText(text) << "</Offset>\n";
            f << "      </Offsets>\n";
            return;
        }
        std::string base = e.addressString;
        std::vector<int64_t> offsets = e.offsets;
        if (offsets.empty())
            if (auto chain = parsePointerExpression(base); chain && buildPointerExpression(chain->base, chain->offsets) == base) {
                base = chain->base;
                offsets = chain->offsets;
            }
        // Data record. CE writes the address expression RAW (quotes and all);
        // matching that keeps a module-relative base like "ac_client.exe"+X
        // readable by CE and by our raw-reading loader. Escaping it (turning "
        // into &quot;) double-encoded on the next load.
        if (!base.empty()) {
            f << "      <Address>" << xmlEscapeText(base) << "</Address>\n";
        } else if (numericFallback) {
            char addr[32];
            snprintf(addr, sizeof(addr), "%lx", e.address);
            f << "      <Address>" << addr << "</Address>\n";
        }
        if (!offsets.empty()) {
            f << "      <Offsets>\n";
            for (int64_t off : offsets) {
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
    };

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
            // CE's address group header: children whose address starts with + or -
            // are relative to it.
            if (!e.addressString.empty() || !e.offsets.empty() || keepsUnparsedPointer(e))
                writeAddressAndOffsets(e, false);
        } else if (!e.autoAsmScript.empty()) {
            // An entry carrying an AssemblerScript IS an "Auto Assembler Script"
            // record in CE (the two are equivalent). CE writes the type name and,
            // for the usual enable/disable script, no numeric <Address> (only a
            // symbolic one if the record defined an address). Writing a bogus
            // <Address>0</Address> + <VariableType>4 Bytes</VariableType> here made
            // re-saved AA tables diverge from the original.
            if (!e.addressString.empty())
                f << "      <Address>" << xmlEscapeText(e.addressString) << "</Address>\n";
            f << "      <VariableType>Auto Assembler Script</VariableType>\n";
        } else {
            writeAddressAndOffsets(e, true);
            f << "      <VariableType>" << typeToStr(e.type) << "</VariableType>\n";
            // CE stores a string length in <Length> and marks wide strings with
            // <Unicode> (the VariableType stays "String"); an array of byte has
            // <ByteLength>.
            if (e.type == ValueType::String || e.type == ValueType::UnicodeString) {
                if (e.length > 0) f << "      <Length>" << e.length << "</Length>\n";
                f << "      <Unicode>" << (e.type == ValueType::UnicodeString ? 1 : 0) << "</Unicode>\n";
            } else if (e.type == ValueType::ByteArray && e.length > 0) {
                f << "      <ByteLength>" << e.length << "</ByteLength>\n";
            } else if (e.type == ValueType::Custom && !e.customTypeName.empty()) {
                f << "      <CustomType>" << xmlEscapeText(e.customTypeName) << "</CustomType>\n";
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
            f << "      <AssemblerScript" << (e.asyncScript ? " Async=\"1\"" : "") << ">"
              << xmlEscape(e.autoAsmScript) << "</AssemblerScript>\n";
        }

        if (!e.luaScript.empty()) {
            f << "      <LuaScript>" << xmlEscape(e.luaScript) << "</LuaScript>\n";
        }

        if (auto color = colorToCE(e.color); !color.empty())
            f << "      <Color>" << color << "</Color>\n";

        // Preserve an imported CE record's <Options> element verbatim so flags we do
        // not model survive a load+save; otherwise synthesize one for a group whose
        // cascade defaults were changed away from "on".
        if (isOptionsElement(e.optionsXml))
            f << "      " << e.optionsXml << "\n";
        else if (e.isGroup && (!e.activateChildren || !e.deactivateChildren))
            f << "      <Options moActivateChildrenAsWell=\"" << (e.activateChildren ? 1 : 0)
              << "\" moDeactivateChildrenAsWell=\"" << (e.deactivateChildren ? 1 : 0) << "\"/>\n";

        if (!e.dropdownList.empty()) {
            f << "      <DropDownList";
            if (!e.dropdownAttributes.empty() && isAttributeText(e.dropdownAttributes))
                f << " " << e.dropdownAttributes;
            f << ">" << xmlEscape(e.dropdownList) << "</DropDownList>\n";
        }

        if (!e.extraXml.empty() && isElementSequence(e.extraXml))
            f << "      " << e.extraXml << "\n";

        // Hotkeys in CE's nested form so Cheat Engine can read them: one <Hotkey> per
        // binding with its <Action> text, a <Keys> list of VK codes, and an optional
        // <Value> (set-value target, or the step for increase/decrease).
        struct HkOut { int action; const std::string* keys; const std::string* value; };
        const std::string empty;
        // A slot the loader filled from a kept hotkey (an Activate key in the
        // toggle slot, a decrease key with its own step) is written by that
        // hotkey's original element, not again as the slot's own action, while
        // the slot still holds the keys (and value or step) it was loaded with.
        // Once the slot is cleared or changed the element is dropped, so the
        // old key does not come back on the next load. Other kept hotkeys are
        // always written.
        auto kept = !e.extraHotkeysXml.empty() && isElementSequence(e.extraHotkeysXml, "Hotkey")
                        ? parseHotkeyBlocks(e.extraHotkeysXml) : std::vector<ParsedHotkey>{};
        auto slotHolds = [&](const ParsedHotkey& h) {
            switch (hotkeySlot(h.action)) {
                case 0: return h.keys == e.hotkeyKeys;
                case 1: return h.keys == e.setValueHotkeyKeys && h.value == e.setValueHotkeyValue;
                case 2: return h.keys == e.increaseHotkeyKeys && h.slotStep == e.hotkeyStep;
                default: return h.keys == e.decreaseHotkeyKeys && h.slotStep == e.hotkeyStep;
            }
        };
        std::erase_if(kept, [&](const ParsedHotkey& h) { return h.slotBound && !(h.usable && slotHolds(h)); });
        std::string keptXml;
        for (const auto& h : kept) {
            if (!keptXml.empty()) keptXml += "\n        ";
            keptXml += h.slotBound ? withoutSlotMarks(h.block) : h.block;
        }
        const bool extraHotkeys = !keptXml.empty();
        auto keptBinds = [&](int action, const std::string& keys) {
            return std::any_of(kept.begin(), kept.end(), [&](const ParsedHotkey& h) {
                return h.usable && hotkeySlot(h.action) == hotkeySlot(action) && h.keys == keys;
            });
        };
        std::vector<HkOut> hks;
        auto add = [&](int action, const std::string& keys, const std::string& value) {
            if (!keys.empty() && !keptBinds(action, keys)) hks.push_back({action, &keys, &value});
        };
        add(0, e.hotkeyKeys, empty);   // Toggle
        add(5, e.setValueHotkeyKeys, e.setValueHotkeyValue);
        add(6, e.increaseHotkeyKeys, e.hotkeyStep);
        add(7, e.decreaseHotkeyKeys, e.hotkeyStep);
        if (!hks.empty() || extraHotkeys) {
            f << "      <Hotkeys>\n";
            // Hotkey IDs are unique in a record: number ours after the kept ones.
            int hkId = 0;
            if (extraHotkeys)
                for (const auto& block : getTagBlocks(keptXml, "ID")) {
                    const std::string text = getTag(block, "ID");
                    int id = -1;
                    std::from_chars(text.data(), text.data() + text.size(), id);
                    if (id >= hkId && id < std::numeric_limits<int>::max()) hkId = id + 1;
                }
            for (const auto& hk : hks) {
                f << "        <Hotkey>\n";
                f << "          <Action>" << kHotkeyActions[hk.action] << "</Action>\n";
                f << "          <Keys>\n";
                for (int vk : keyStringToVKs(*hk.keys))
                    f << "            <Key>" << vk << "</Key>\n";
                f << "          </Keys>\n";
                if (!hk.value->empty())
                    f << "          <Value>" << xmlEscape(*hk.value) << "</Value>\n";
                f << "          <ID>" << hkId++ << "</ID>\n";
                f << "        </Hotkey>\n";
            }
            if (extraHotkeys)
                f << "        " << keptXml << "\n";
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
    // Nesting stops at the depth the loader accepts; deeper children are
    // written further out (the loop below picks them up), not recursed into.
    std::function<void(int, int)> writeEntry = [&](int i, int depth) {
        if (done[i]) return;
        done[i] = 1;
        f << "    <CheatEntry>\n";
        writeEntryFields(entries[i]);
        if (!children[i].empty() && depth + 1 < kMaxEntryDepth) {
            f << "      <CheatEntries>\n";
            for (int c : children[i]) writeEntry(c, depth + 1);
            f << "      </CheatEntries>\n";
        }
        f << "    </CheatEntry>\n";
    };

    f << "  <CheatEntries>\n";
    for (size_t i = 0; i < entries.size(); ++i)
        if (!isChild[i]) writeEntry(static_cast<int>(i), 0);
    for (size_t i = 0; i < entries.size(); ++i)   // orphan sweep (cycles)
        if (!done[i]) writeEntry(static_cast<int>(i), 0);
    f << "  </CheatEntries>\n";
    if (!rawFormsXml.empty())
        f << "  <Forms>" << rawFormsXml << "</Forms>\n";
    f << table.rawSectionsXml;
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

// Every "<tag>...</tag>" or "<tag attr=...>...</tag>" block in xml, as
// [begin, end) ranges including both tags. An unclosed block runs to the end.
static std::vector<std::pair<size_t, size_t>> tagBlockRanges(const std::string& xml, const std::string& tag,
                                                             bool withAttributesOnly = false) {
    std::vector<std::pair<size_t, size_t>> ranges;
    const std::string open = "<" + tag, close = "</" + tag + ">";
    for (size_t at = xml.find(open); at != std::string::npos; at = xml.find(open, at + 1)) {
        const size_t after = at + open.size();
        if (after >= xml.size()) break;
        const char next = xml[after];
        if (next != '>' && next != ' ' && next != '\t' && next != '\n' && next != '\r' && next != '/') continue;
        if (withAttributesOnly && next == '>') continue;
        if (next == '/') {   // <tag/>
            const size_t end = xml.find('>', after);
            ranges.push_back({at, end == std::string::npos ? xml.size() : end + 1});
        } else {
            const size_t end = xml.find(close, after);
            ranges.push_back({at, end == std::string::npos ? xml.size() : end + close.size()});
        }
        at = ranges.back().second - 1;
    }
    return ranges;
}

// The text inside the first <tag> element of xml, which may carry attributes
// (CE 7 writes <AssemblerScript Async="1">, <DropDownList DisplayValueAsItem="1">).
// The attribute text, trimmed, goes to *attributes. "" when absent or <tag/>.
static std::string getTagWithAttributes(const std::string& xml, const std::string& tag, std::string* attributes) {
    if (attributes) attributes->clear();
    const auto ranges = tagBlockRanges(xml, tag);
    if (ranges.empty()) return {};
    const auto [begin, end] = ranges.front();
    const size_t gt = xml.find('>', begin);
    if (gt == std::string::npos || gt >= end) return {};
    const bool selfClosing = xml[gt - 1] == '/';
    if (attributes) *attributes = trimmedXmlText(xml.substr(begin + 1 + tag.size(), gt - begin - 1 - tag.size() - selfClosing));
    const std::string close = "</" + tag + ">";
    if (selfClosing || end < gt + 1 + close.size() || xml.compare(end - close.size(), close.size(), close) != 0) return {};
    return xml.substr(gt + 1, end - close.size() - gt - 1);
}

// The value of name="..." in a start tag's attribute text, "" if absent.
static std::string attributeValue(const std::string& attributes, const std::string& name) {
    for (size_t at = attributes.find(name); at != std::string::npos; at = attributes.find(name, at + 1)) {
        if (at > 0 && !std::isspace(static_cast<unsigned char>(attributes[at - 1]))) continue;
        size_t p = at + name.size();
        while (p < attributes.size() && std::isspace(static_cast<unsigned char>(attributes[p]))) ++p;
        if (p >= attributes.size() || attributes[p] != '=') continue;
        ++p;
        while (p < attributes.size() && std::isspace(static_cast<unsigned char>(attributes[p]))) ++p;
        if (p >= attributes.size() || (attributes[p] != '"' && attributes[p] != '\'')) continue;
        const size_t close = attributes.find(attributes[p], p + 1);
        if (close == std::string::npos) return {};
        return attributes.substr(p + 1, close - p - 1);
    }
    return {};
}

static std::vector<ParsedHotkey> parseHotkeyBlocks(const std::string& xml) {
    std::vector<ParsedHotkey> parsed;
    for (const auto& [begin, end] : tagBlockRanges(xml, "Hotkey")) {
        ParsedHotkey h;
        h.block = xml.substr(begin, end - begin);
        std::string attributes;
        const std::string hk = getTagWithAttributes(h.block, "Hotkey", &attributes);
        h.action = hotkeyActionFromText(trimmedXmlText(xmlUnescape(getTag(hk, "Action"))));
        std::vector<int> vks;
        for (const auto& kb : getTagBlocks(getTag(hk, "Keys"), "Key")) {
            try { vks.push_back(std::stoi(getTag(kb, "Key"))); } catch (...) {}
        }
        h.keys = vksToKeyString(vks);
        h.value = xmlUnescape(getTag(hk, "Value"));
        h.usable = !h.keys.empty() && attributeValue(attributes, "Active") != "0";
        h.slotBound = attributeValue(attributes, "LinuxSlot") == "1";
        h.slotStep = xmlUnescape(attributeValue(attributes, "LinuxSlotStep"));
        parsed.push_back(std::move(h));
    }
    return parsed;
}

// A kept <Hotkey> element without the loader's LinuxSlot and LinuxSlotStep
// attributes: for writing a .CT, and before the loader marks an element read
// from an untrusted file.
static std::string withoutSlotMarks(std::string block) {
    for (const std::string name : {"LinuxSlotStep", "LinuxSlot"}) {
        for (size_t at = block.find(name); at != std::string::npos && at < block.find('>'); at = block.find(name, at)) {
            size_t p = at + name.size();
            if (!std::isspace(static_cast<unsigned char>(block[at - 1])) || p >= block.size() || block[p] != '=' ||
                p + 1 >= block.size() || (block[p + 1] != '"' && block[p + 1] != '\'')) {
                ++at;
                continue;
            }
            const size_t close = block.find(block[p + 1], p + 2);
            if (close == std::string::npos) break;
            block.erase(at - 1, close + 1 - (at - 1));
            at -= 1;
        }
    }
    return block;
}

// Record elements the loader reads; anything else is kept verbatim in extraXml.
static const std::set<std::string, std::less<>> kRecordElements = {
    "ID", "Description", "Options", "DropDownList", "DropdownList", "ShowAsHex", "ShowAsSigned", "Color",
    "GroupHeader", "Collapsed", "CheatEntries", "VariableType", "CustomType", "Length", "ByteLength",
    "Unicode", "Address", "Offsets", "Hotkeys", "AssemblerScript", "LuaScript", "Value", "Activated",
    "freezeMode", "LinuxDataByteOrder", "LinuxPointerWidth", "IncreaseHotkey", "SetValueHotkey",
    "SetValueHotkeyValue", "DecreaseHotkey", "HotkeyStep"};

// The direct child elements of a record (its own part, from "<CheatEntry>") that
// kRecordElements does not name, joined for writing back as they were.
static std::string unknownRecordElements(const std::string& own) {
    std::string out;
    size_t p = own.find('>');
    if (p == std::string::npos) return out;
    for (++p; (p = own.find('<', p)) != std::string::npos;) {
        if (own.compare(p, 2, "</") == 0) break;   // </CheatEntry>
        if (own.compare(p, 4, "<!--") == 0) {
            p = own.find("-->", p);
            if (p == std::string::npos) break;
            continue;
        }
        std::string name;
        const size_t end = elementEnd(own, p, own.size(), &name);
        if (end == std::string::npos) break;
        if (!kRecordElements.count(name)) {
            if (!out.empty()) out += "\n      ";
            out += own.substr(p, end - p);
        }
        p = end;
    }
    return out;
}

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

// The <CheatEntry> blocks directly inside xml[begin, end). Children are parsed
// in place, by position, so a deep table is not copied once per level.
static void parseCheatEntriesBlock(const std::string& xml, size_t begin, size_t end, int parentId,
                                   std::vector<CheatEntry>& entries, bool& validFormat, std::set<int>& usedIds,
                                   int depth = 0) {
    static const std::string CE_CLOSE = "</CheatEntry>";
    static const std::string LIST_OPEN = "<CheatEntries>";
    if (depth >= kMaxEntryDepth) { validFormat = false; return; }
    size_t pos = begin;
    while (true) {
        auto entryStart = xml.find("<CheatEntry>", pos);
        if (entryStart == std::string::npos || entryStart >= end) break;
        auto entryClose = findMatchingClose(xml, entryStart, "CheatEntry");
        if (entryClose == std::string::npos || entryClose + CE_CLOSE.size() > end) break;
        pos = entryClose + CE_CLOSE.size();

        // Split this entry's own fields (before any nested child list) from the
        // nested <CheatEntries> so getTag() reads the parent's fields, not a child's.
        size_t ownEnd = pos;
        size_t childBegin = 0, childEnd = 0;
        // Search this record only: a search to the end of the file for every
        // record without children made loading quadratic.
        size_t nestedOpen = std::string_view(xml).substr(entryStart, entryClose - entryStart).find(LIST_OPEN);
        if (nestedOpen != std::string::npos) nestedOpen += entryStart;
        if (nestedOpen != std::string::npos && nestedOpen < entryClose) {
            ownEnd = nestedOpen;
            auto nestedClose = findMatchingClose(xml, nestedOpen, "CheatEntries");
            if (nestedClose != std::string::npos && nestedClose < entryClose) {
                childBegin = nestedOpen + LIST_OPEN.size();
                childEnd = nestedClose;
            }
        }
        const std::string hotkeysXml = xml.substr(entryStart, ownEnd - entryStart);
        // The record's own scalar fields, without its <Hotkeys>: a set-value
        // hotkey has a <Value> (and could have any other tag) of its own.
        std::string ownXml = hotkeysXml;
        if (auto h = ownXml.find("<Hotkeys>"); h != std::string::npos) {
            auto hEnd = ownXml.find("</Hotkeys>", h);
            ownXml.erase(h, hEnd == std::string::npos ? std::string::npos : hEnd + std::string("</Hotkeys>").size() - h);
        }

        CheatEntry e;
        e.parentId = parentId;
        auto idStr = getTag(ownXml, "ID");
        int parsedId = 0;
        const auto [idStop, idError] = std::from_chars(idStr.data(), idStr.data() + idStr.size(), parsedId);
        const bool hasId = !idStr.empty() && idError == std::errc() && idStop == idStr.data() + idStr.size() && parsedId >= 0;
        if (hasId) e.id = parsedId;
        e.description = xmlUnescape(getTag(ownXml, "Description"));
        if (e.description.size() >= 2 && e.description.front() == '"' && e.description.back() == '"')
            e.description = e.description.substr(1, e.description.size() - 2);
        e.isGroup = (getTag(ownXml, "GroupHeader") == "1");
        e.collapsed = (getTag(ownXml, "Collapsed") == "1");
        // A group can have an address too (CE's address group header): children
        // whose address starts with + or - are relative to it.
        auto addrStr = getTag(ownXml, "Address");
        if (!addrStr.empty()) {
            e.addressString = xmlUnescape(addrStr);
            // Only a plain hex address is one; "game.exe+10" must not read as 0xBA.
            uint64_t plain = 0;
            const auto [stop, error] = std::from_chars(addrStr.data(), addrStr.data() + addrStr.size(), plain, 16);
            e.address = error == std::errc() && stop == addrStr.data() + addrStr.size() ? plain : 0;
        }
        const auto offsetsXml = getTag(ownXml, "Offsets");
        std::vector<std::string> offsetTexts;
        bool offsetsParsed = true;
        // CE may give an offset attributes (<Offset Interval="100">); skipping
        // such an offset would follow a shorter chain to some other address.
        for (const auto& [offBegin, offEnd] : tagBlockRanges(offsetsXml, "Offset")) {
            const std::string offStr = trimmedXmlText(xmlUnescape(
                getTagWithAttributes(offsetsXml.substr(offBegin, offEnd - offBegin), "Offset", nullptr)));
            offsetTexts.push_back(offStr);
            // The whole text must be hex (64-bit values wrap, as pointer math
            // does). Anything else (a symbol, an expression) is kept as text and
            // the record keeps no address at all.
            const bool negative = !offStr.empty() && offStr[0] == '-';
            const std::string digits = offStr.substr(negative ? 1 : 0);
            uint64_t magnitude = 0;
            const auto [stop, error] = std::from_chars(digits.data(), digits.data() + digits.size(), magnitude, 16);
            const bool parsed = !digits.empty() && error == std::errc() && stop == digits.data() + digits.size();
            if (parsed) e.offsets.push_back(static_cast<int64_t>(negative ? 0 - magnitude : magnitude));
            else if (offsetsParsed) {
                offsetsParsed = false;
                e.addressString.swap(e.unparsedAddress);
                e.addressString = "(unsupported offset " + offStr + ")";
            }
        }
        if (!offsetsParsed) {
            e.offsets.clear();
            e.address = 0;
            e.unparsedOffsets = std::move(offsetTexts);
        }
        if (!e.isGroup) {
            e.type = strToType(getTag(ownXml, "VariableType"));
            // CE String + <Unicode>1</Unicode> is our UnicodeString. The element
            // length is <Length> for a string and <ByteLength> for an array of
            // byte; older builds of this port wrote <Length> for both.
            if (e.type == ValueType::String && getTag(ownXml, "Unicode") == "1")
                e.type = ValueType::UnicodeString;
            auto ln = getTag(ownXml, "ByteLength");
            if (ln.empty()) ln = getTag(ownXml, "Length");
            if (!ln.empty()) {
                // Read on every refresh: a huge length would read that much each time.
                try { e.length = std::clamp(std::stoi(ln), 0, 65536); } catch (...) {}
            }
            if (e.type == ValueType::Custom) e.customTypeName = xmlUnescape(getTag(ownXml, "CustomType"));
            e.value = xmlUnescape(getTag(ownXml, "Value"));
        }
        e.active = (getTag(ownXml, "Activated") == "1");
        e.showAsHex = (getTag(ownXml, "ShowAsHex") == "1");
        if (!parseRecordDataFormat(getTag(ownXml, "LinuxDataByteOrder"), getTag(ownXml, "LinuxPointerWidth"), e)) validFormat = false;
        e.showAsSigned = (getTag(ownXml, "ShowAsSigned") != "0");  // absent -> signed default
        if (auto fm = getTag(ownXml, "freezeMode"); !fm.empty()) {
            try {
                const int mode = std::stoi(fm);
                if (mode >= static_cast<int>(FreezeMode::Normal) && mode <= static_cast<int>(FreezeMode::NeverDecrease))
                    e.freezeMode = static_cast<FreezeMode>(mode);
            } catch (...) {}
        }
        // CE 7 writes <AssemblerScript Async="1"> for a script that runs in the background.
        std::string attributes;
        e.autoAsmScript = xmlUnescape(getTagWithAttributes(ownXml, "AssemblerScript", &attributes));
        e.asyncScript = attributeValue(attributes, "Async") == "1";
        e.luaScript = xmlUnescape(getTag(ownXml, "LuaScript"));
        e.color = colorFromCE(trimmedXmlText(xmlUnescape(getTag(ownXml, "Color"))));
        // CE writes the PascalCase <DropDownList>, one choice per line, with
        // attributes such as DisplayValueAsItem="1"; accept the mis-cased
        // <DropdownList> older builds of this port wrote as a fallback.
        e.dropdownList = xmlUnescape(getTagWithAttributes(ownXml, "DropDownList", &attributes));
        e.dropdownAttributes = attributes;
        if (e.dropdownList.empty())
            e.dropdownList = xmlUnescape(getTag(ownXml, "DropdownList"));
        e.dropdownList.erase(std::remove(e.dropdownList.begin(), e.dropdownList.end(), '\r'), e.dropdownList.end());
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
        e.extraXml = unknownRecordElements(ownXml);
        // Hotkeys: CE uses a nested <Hotkeys><Hotkey><Action>Set Value</Action><Keys>
        // <Key>vk</Key>...</Keys><Value>..</Value></Hotkey>...</Hotkeys>; older builds of
        // this port wrote numeric actions, and before that a flat "<Hotkeys>Ctrl+H
        // </Hotkeys>" plus separate tags. The first enabled hotkey of each kind fills
        // our toggle/set/increase/decrease slot; every other one is kept as written.
        // With no enabled plain toggle, the first Activate, Deactivate or toggle
        // that allows increase or decrease fills the toggle slot instead, so its
        // key still works. Increase and decrease share one step, the first one
        // given; a key with another step still binds, using that step.
        // A hotkey whose slot cannot say what it says (one of those actions, or
        // another step) is kept as written too, and so is one whose slot keys
        // another kept hotkey also has: the save writes the kept element in
        // place of the slot, so a load and save keeps every action and step.
        auto hkXml = getTag(hotkeysXml, "Hotkeys");
        if (hkXml.find("<Hotkey") != std::string::npos) {
            const auto parsed = parseHotkeyBlocks(hkXml);
            bool plainToggle = false;
            for (const auto& h : parsed) plainToggle |= h.usable && h.action == 0;
            bool stepTaken = false;
            std::vector<bool> keep(parsed.size(), true);
            std::array<int, 4> boundBy{-1, -1, -1, -1};   // per slot, the hotkey that fills it
            for (size_t index = 0; index < parsed.size(); ++index) {
                const auto& h = parsed[index];
                if (!h.usable) continue;
                bool bound = false;
                switch (h.action) {   // CE mrh* action codes
                    case 0:   // Toggle Activation
                        if ((bound = e.hotkeyKeys.empty())) e.hotkeyKeys = h.keys;
                        break;
                    case 1: case 2:   // Toggle Activation Allow Increase / Decrease
                    case 3: case 4:   // Activate, Deactivate
                        if ((bound = !plainToggle && e.hotkeyKeys.empty())) e.hotkeyKeys = h.keys;
                        break;
                    case 5:   // Set Value
                        if ((bound = e.setValueHotkeyKeys.empty())) { e.setValueHotkeyKeys = h.keys; e.setValueHotkeyValue = h.value; }
                        break;
                    case 6:
                    case 7: {
                        auto& slot = h.action == 6 ? e.increaseHotkeyKeys : e.decreaseHotkeyKeys;
                        if ((bound = slot.empty())) {
                            slot = h.keys;
                            if (!stepTaken && !h.value.empty()) { e.hotkeyStep = h.value; stepTaken = true; }
                        }
                        break;
                    }
                    default: break;
                }
                if (bound) { keep[index] = false; boundBy[hotkeySlot(h.action)] = static_cast<int>(index); }
            }
            for (int slot = 0; slot < 4; ++slot) {
                const int index = boundBy[slot];
                if (index < 0) continue;
                const auto& h = parsed[index];
                const bool otherAction = slot == 0 && h.action != 0;
                const bool otherStep = slot >= 2 && h.value != e.hotkeyStep;
                const bool shared = std::any_of(parsed.begin(), parsed.end(), [&](const ParsedHotkey& other) {
                    return keep[&other - parsed.data()] && other.usable && hotkeySlot(other.action) == slot && other.keys == h.keys;
                });
                if (otherAction || otherStep || shared) keep[index] = true;
            }
            // A kept element that fills a slot is marked, so the save can tell
            // whether the slot still holds what was loaded.
            for (size_t index = 0; index < parsed.size(); ++index) {
                if (!keep[index] || !isElementSequence(parsed[index].block, "Hotkey")) continue;
                std::string block = withoutSlotMarks(parsed[index].block);
                const int slot = hotkeySlot(parsed[index].action);
                if (boundBy[slot] == static_cast<int>(index) && block.starts_with("<Hotkey")) {
                    std::string mark = " LinuxSlot=\"1\"";
                    if (slot >= 2) mark += " LinuxSlotStep=\"" + xmlEscape(e.hotkeyStep) + "\"";
                    block.insert(7, mark);
                }
                if (!e.extraHotkeysXml.empty()) e.extraHotkeysXml += "\n        ";
                e.extraHotkeysXml += block;
            }
        } else {
            e.hotkeyKeys = xmlUnescape(hkXml);
            e.increaseHotkeyKeys = xmlUnescape(getTag(ownXml, "IncreaseHotkey"));
            e.setValueHotkeyKeys = xmlUnescape(getTag(ownXml, "SetValueHotkey"));
            e.setValueHotkeyValue = xmlUnescape(getTag(ownXml, "SetValueHotkeyValue"));
            e.decreaseHotkeyKeys = xmlUnescape(getTag(ownXml, "DecreaseHotkey"));
            e.hotkeyStep = xmlUnescape(getTag(ownXml, "HotkeyStep"));
        }

        // Children find their parent by id, so a record without one, or with
        // one already taken, gets a fresh id before its children are linked.
        if (!hasId || !usedIds.insert(e.id).second) {
            if (usedIds.empty()) e.id = 1;
            else if (*usedIds.rbegin() < std::numeric_limits<int>::max()) e.id = *usedIds.rbegin() + 1;
            else for (e.id = 1; usedIds.count(e.id); ++e.id) {}   // INT_MAX is taken: the first gap
            usedIds.insert(e.id);
        }
        int myId = e.id;
        entries.push_back(std::move(e));
        if (childEnd > childBegin)
            parseCheatEntriesBlock(xml, childBegin, childEnd, myId, entries, validFormat, usedIds, depth + 1);
    }
}

// A character reference (&#10; or &#x27;) at s[i] as UTF-8, advancing i to its
// ';'. False, leaving i, when it is not a valid one.
static bool appendCharacterReference(const std::string& s, size_t& i, std::string& out) {
    if (s.compare(i, 2, "&#") != 0) return false;
    const size_t semi = s.find(';', i);
    if (semi == std::string::npos || semi - i > 12) return false;
    const bool hex = i + 2 < s.size() && (s[i + 2] == 'x' || s[i + 2] == 'X');
    const char* first = s.data() + i + (hex ? 3 : 2);
    uint32_t cp = 0;
    const auto [stop, error] = std::from_chars(first, s.data() + semi, cp, hex ? 16 : 10);
    if (first == s.data() + semi || error != std::errc() || stop != s.data() + semi || cp == 0 || cp > 0x10FFFF ||
        (cp >= 0xD800 && cp <= 0xDFFF))
        return false;
    if (cp < 0x80) out += static_cast<char>(cp);
    else if (cp < 0x800) { out += static_cast<char>(0xC0 | (cp >> 6)); out += static_cast<char>(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
    i = semi;
    return true;
}

static std::string xmlUnescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        // A CDATA section is literal text: nothing in it is a reference.
        if (s.compare(i, 9, "<![CDATA[") == 0) {
            const size_t close = s.find("]]>", i + 9);
            out.append(s, i + 9, close == std::string::npos ? std::string::npos : close - i - 9);
            if (close == std::string::npos) break;
            i = close + 2;
            continue;
        }
        if (s[i] == '&') {
            if (appendCharacterReference(s, i, out)) {}
            else if (s.substr(i, 4) == "&lt;") { out += '<'; i += 3; }
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

// The JSON value and parser live in core/json; the names below keep this file's
// loader code unchanged.
using JsonValue = json::Value;
static std::string jsonEscape(const std::string& s) { return json::escape(s); }
class JsonParser {
public:
    explicit JsonParser(const std::string& input) : input_(input) {}
    bool parse(JsonValue& out) { return json::parse(input_, out); }
private:
    const std::string& input_;
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

    // The first byte decides before any search: a JSON table whose text
    // mentions "<CheatTable" is still JSON.
    if (i < head.size() && head[i] == '<') return TableFormat::Xml;
    if (i < head.size() && (head[i] == '{' || head[i] == '['))
        return TableFormat::Json;
    if (head.find("<CheatTable") != std::string::npos || head.find("<CheatEntries") != std::string::npos)
        return TableFormat::Xml;
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

    // Header fields only: nested sections have tags of the same names (each
    // disassembler comment has a <Comment>).
    for (const char* section : {"DisassemblerComments", "Structures", "Forms", "UserdefinedSymbols", "Files"}) {
        const auto ranges = tagBlockRanges(headerXml, section);
        for (auto it = ranges.rbegin(); it != ranges.rend(); ++it) headerXml.erase(it->first, it->second - it->first);
    }
    // Sections we do not model, kept as they are so a re-save does not drop
    // them. Only Cheat Engine's own structure format (with attributes); ours
    // is parsed below.
    rawSectionsXml.clear();
    for (const auto& [section, attributesOnly] : {std::pair{"UserdefinedSymbols", false}, std::pair{"Files", false},
                                                  std::pair{"Structures", true}})
        for (const auto& [begin, end] : tagBlockRanges(xml, section, attributesOnly))
            rawSectionsXml += "  " + xml.substr(begin, end - begin) + "\n";
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
            std::set<int> usedIds;
            parseCheatEntriesBlock(xml, cs, topClose, -1, entries, validFormat, usedIds);
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
    std::ostringstream json;
    return writeTableJson(*this, json) && writeFileAtomically(path, json.str());
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
    f << "  \"rawSectionsXml\": \"" << jsonEscape(table.rawSectionsXml) << "\",\n";
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
            if (e.length > 0) f << ",\"length\":" << e.length;
            if (!e.customTypeName.empty()) f << ",\"customType\":\"" << jsonEscape(e.customTypeName) << "\"";
        }
        // Persist the fields the XML path round-trips too; otherwise a pointer
        // chain / symbolic base is lost through saveJson+loadJson (i.e. every
        // .CETRAINER save/load). A group can have an address as well.
        if (!e.addressString.empty())
            f << ",\"addrString\":\"" << jsonEscape(e.addressString) << "\"";
        if (!e.offsets.empty()) {
            f << ",\"offsets\":[";
            for (size_t k = 0; k < e.offsets.size(); ++k)
                f << (k ? "," : "") << e.offsets[k];
            f << "]";
        }
        if (!e.unparsedOffsets.empty()) {
            f << ",\"unparsedAddress\":\"" << jsonEscape(e.unparsedAddress) << "\",\"unparsedOffsets\":[";
            for (size_t k = 0; k < e.unparsedOffsets.size(); ++k)
                f << (k ? "," : "") << "\"" << jsonEscape(e.unparsedOffsets[k]) << "\"";
            f << "]";
        }
        if (e.asyncScript) f << ",\"async\":true";
        if (!e.dropdownAttributes.empty()) f << ",\"dropdownAttributes\":\"" << jsonEscape(e.dropdownAttributes) << "\"";
        if (!e.extraHotkeysXml.empty()) f << ",\"extraHotkeys\":\"" << jsonEscape(e.extraHotkeysXml) << "\"";
        if (!e.extraXml.empty()) f << ",\"extraXml\":\"" << jsonEscape(e.extraXml) << "\"";
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
    table.rawSectionsXml = jsonStringField(root, "rawSectionsXml");

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
        e.length = std::min(jsonIntField(item, getField(item,"length") ? "length" : "byteCount", 0), 65536);   // as <Length>
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
        e.customTypeName = jsonStringField(item, "customType");
        e.asyncScript = jsonBoolField(item, "async");
        e.unparsedAddress = jsonStringField(item, "unparsedAddress");
        if (auto* texts = getField(item, "unparsedOffsets")) {
            if (texts->type != JsonValue::Type::Array) return false;
            for (const auto& text : texts->arrayValue) {
                if (text.type != JsonValue::Type::String) return false;
                e.unparsedOffsets.push_back(text.stringValue);
            }
        }
        e.extraHotkeysXml = jsonStringField(item, "extraHotkeys");
        e.extraXml = jsonStringField(item, "extraXml");
        e.dropdownAttributes = jsonStringField(item, "dropdownAttributes");
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
    std::ostringstream json;
    if (!writeTableJson(*this, json))
        return false;
    const auto encrypted = xorCrypt(json.str(), password);
    std::string bytes = "CETRAINER1\n" + std::to_string(fnv1a(password)) + "\n";
    bytes.append(encrypted.begin(), encrypted.end());
    return writeFileAtomically(path, bytes);
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
