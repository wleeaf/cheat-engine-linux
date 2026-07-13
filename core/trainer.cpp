#include <charconv>
#include <cmath>
#include "core/trainer.hpp"
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <climits>
#include <optional>
#include <filesystem>

namespace ce {
namespace {

std::string cString(const std::string& text) {
    std::string escaped;
    escaped.reserve(text.size() + 2);
    escaped.push_back('"');
    for (unsigned char c : text) {
        switch (c) {
            case '\\': escaped += "\\\\"; break;
            case '"': escaped += "\\\""; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (c < 0x20 || c >= 0x7f) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\x%02x", c);
                    escaped += buf;
                } else {
                    escaped.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    escaped.push_back('"');
    return escaped;
}

std::string shellQuote(const std::string& text) {
    std::string quoted = "'";
    for (char c : text) {
        if (c == '\'')
            quoted += "'\\''";
        else
            quoted.push_back(c);
    }
    quoted.push_back('\'');
    return quoted;
}

std::string lineCommentText(std::string text) {
    for (char& c : text) {
        if (c == '\r' || c == '\n')
            c = ' ';
    }
    return text;
}

// Build the C freeze-write body for an entry: a sanitized typed declaration plus
// the matching-width wpm() call. The CheatEntry::value comes from an untrusted
// .CT/.CETRAINER <Value> tag and MUST NOT be spliced into generated C verbatim
// (that is arbitrary code injection / RCE since the result is compiled with gcc).
// We strictly parse the value into a typed numeric, emit a canonical literal we
// produce ourselves, and pick the write size from the entry type instead of
// always writing 4 bytes. Returns nullopt to skip entries whose value is not a
// well-formed numeric literal or whose type is unsupported for freezing.
std::optional<std::string> freezeWriteBody(const CheatEntry& e) {
    std::ostringstream body;

    auto fullySigned = [&](long long& out) -> bool {
        if (e.value.empty()) return false;
        errno = 0;
        char* end = nullptr;
        long long v = std::strtoll(e.value.c_str(), &end, 0);
        if (errno != 0 || end == e.value.c_str() || *end != '\0') return false;
        out = v;
        return true;
    };
    auto inRange = [](long long v, long long lo, long long hi) {
        return v >= lo && v <= hi;
    };

    switch (e.type) {
        case ValueType::Byte: {
            long long v;
            if (!fullySigned(v) || !inRange(v, -128, 255)) return std::nullopt;
            body << "uint8_t v = " << static_cast<unsigned>(static_cast<uint8_t>(v))
                 << "u; wpm((void*)0x" << std::hex << e.address << std::dec << ", &v, 1);";
            return body.str();
        }
        case ValueType::Int16: {
            long long v;
            if (!fullySigned(v) || !inRange(v, -32768, 65535)) return std::nullopt;
            body << "int16_t v = " << static_cast<int16_t>(v)
                 << "; wpm((void*)0x" << std::hex << e.address << std::dec << ", &v, 2);";
            return body.str();
        }
        case ValueType::Int32: {
            long long v;
            if (!fullySigned(v) || !inRange(v, INT32_MIN, UINT32_MAX)) return std::nullopt;
            body << "int32_t v = " << static_cast<int32_t>(v)
                 << "; wpm((void*)0x" << std::hex << e.address << std::dec << ", &v, 4);";
            return body.str();
        }
        case ValueType::Int64:
        case ValueType::Pointer: {
            // strtoll covers the full signed 64-bit range; out-of-range sets errno.
            long long v;
            if (!fullySigned(v)) return std::nullopt;
            body << "int64_t v = " << static_cast<long long>(v)
                 << "LL; wpm((void*)0x" << std::hex << e.address << std::dec << ", &v, 8);";
            return body.str();
        }
        case ValueType::Float: {
            if (e.value.empty()) return std::nullopt;
            std::string norm = e.value;
            for (auto& c : norm) if (c == ',') c = '.';
            float v = 0;
            auto [ptr, ec] = std::from_chars(norm.data(), norm.data() + norm.size(), v);
            if (ec != std::errc() || ptr != norm.data() + norm.size()) return std::nullopt;
            if (!std::isfinite(v)) return std::nullopt;   // inf/nan is not a freezable target
            // Re-emit a canonical literal we generate (never the raw input string).
            // to_chars is locale-independent ('.'); snprintf("%g") would emit "3,14"
            // under Qt's comma-decimal C locale, producing invalid C in the trainer.
            char buf[64];
            auto fr = std::to_chars(buf, buf + sizeof(buf) - 1, v);
            *fr.ptr = '\0';
            std::string lit(buf);
            // to_chars emits the shortest round-trip form, so a whole number is
            // "9999" (no '.') — then "9999f" is an INVALID integer-with-f-suffix.
            // Ensure a fractional part so the 'f' attaches to a floating constant.
            if (lit.find_first_of(".eE") == std::string::npos) lit += ".0";
            body << "float v = " << lit << "f; wpm((void*)0x" << std::hex << e.address
                 << std::dec << ", &v, 4);";
            return body.str();
        }
        case ValueType::Double: {
            if (e.value.empty()) return std::nullopt;
            // Locale-independent parse: from_chars always uses '.', unlike strtod
            // which would honour Qt's comma-decimal C locale. Accept both ',' and '.'.
            std::string norm = e.value;
            for (auto& c : norm) if (c == ',') c = '.';
            double v = 0;
            auto [ptr, ec] = std::from_chars(norm.data(), norm.data() + norm.size(), v);
            if (ec != std::errc() || ptr != norm.data() + norm.size()) return std::nullopt;
            if (!std::isfinite(v)) return std::nullopt;   // inf/nan is not a freezable target
            char buf[64];
            auto dr = std::to_chars(buf, buf + sizeof(buf) - 1, v);
            *dr.ptr = '\0';
            // A whole-number double emits as "9999" — valid C (int->double), so no
            // fractional part is required here (unlike the float 'f'-suffix case).
            body << "double v = " << buf << "; wpm((void*)0x" << std::hex << e.address
                 << std::dec << ", &v, 8);";
            return body.str();
        }
        default:
            // String/ByteArray/Binary/Custom/etc.: no safe scalar freeze. Skip.
            // TODO(security): support freezing array/string types via a sanitized
            // byte buffer instead of a scalar write.
            return std::nullopt;
    }
}

} // namespace

std::string TrainerGenerator::generateSource(const CheatTable& table) const {
    std::ostringstream src;

    src << "// Auto-generated trainer for: " << lineCommentText(table.gameName) << "\n";
    src << "// Author: " << lineCommentText(table.author) << "\n";
    // process_vm_readv/writev are GNU extensions; without _GNU_SOURCE they are
    // implicitly declared (assumed to return int), truncating the 64-bit return on
    // x86-64. Define it before any include so the real ssize_t prototype is used.
    src << "#define _GNU_SOURCE\n";
    src << "#include <stdio.h>\n";
    src << "#include <stdlib.h>\n";
    src << "#include <string.h>\n";
    src << "#include <stdint.h>\n";
    src << "#include <ctype.h>\n";
    src << "#include <dirent.h>\n";
    src << "#include <unistd.h>\n";
    src << "#include <sys/uio.h>\n";
    src << "#include <sys/select.h>\n";
    src << "#include <signal.h>\n";
    src << "#include <termios.h>\n\n";

    src << "static int target_pid = 0;\n\n";
    src << "static const char* embedded_table_lua = " << cString(table.luaScript) << ";\n";
    src << "struct embedded_script_record { const char* description; const char* lua; const char* autoasm; };\n";
    src << "static const struct embedded_script_record embedded_scripts[] = {\n";
    for (const auto& e : table.entries) {
        if (e.luaScript.empty() && e.autoAsmScript.empty())
            continue;
        src << "    {" << cString(e.description) << ", " << cString(e.luaScript)
            << ", " << cString(e.autoAsmScript) << "},\n";
    }
    src << "};\n";
    src << "static const int embedded_script_count = sizeof(embedded_scripts) / sizeof(embedded_scripts[0]);\n\n";

    src << "static int is_numeric_name(const char* s) {\n";
    src << "    if (!s || !*s) return 0;\n";
    src << "    while (*s) { if (!isdigit((unsigned char)*s++)) return 0; }\n";
    src << "    return 1;\n";
    src << "}\n\n";

    src << "static int find_process_by_name(const char* name) {\n";
    src << "    DIR* dir = opendir(\"/proc\");\n";
    src << "    if (!dir) return 0;\n";
    src << "    struct dirent* ent;\n";
    src << "    while ((ent = readdir(dir)) != NULL) {\n";
    src << "        if (!is_numeric_name(ent->d_name)) continue;\n";
    src << "        char path[256];\n";
    src << "        snprintf(path, sizeof(path), \"/proc/%s/comm\", ent->d_name);\n";
    src << "        FILE* f = fopen(path, \"r\");\n";
    src << "        if (!f) continue;\n";
    src << "        char comm[256] = {0};\n";
    src << "        if (fgets(comm, sizeof(comm), f)) {\n";
    src << "            comm[strcspn(comm, \"\\r\\n\")] = 0;\n";
    src << "            if (strcmp(comm, name) == 0) {\n";
    src << "                fclose(f);\n";
    src << "                closedir(dir);\n";
    src << "                return atoi(ent->d_name);\n";
    src << "            }\n";
    src << "        }\n";
    src << "        fclose(f);\n";
    src << "    }\n";
    src << "    closedir(dir);\n";
    src << "    return 0;\n";
    src << "}\n\n";

    src << "static int hotkey_matches(int c, const char* spec, int fallback) {\n";
    src << "    if (!spec || !*spec) return c == fallback;\n";
    src << "    if (strlen(spec) == 1) return tolower((unsigned char)c) == tolower((unsigned char)spec[0]);\n";
    src << "    if (strncmp(spec, \"Ctrl+\", 5) == 0 && spec[5] && !spec[6]) {\n";
    src << "        return c == (tolower((unsigned char)spec[5]) & 0x1f);\n";
    src << "    }\n";
    src << "    if (strncmp(spec, \"Shift+\", 6) == 0 && spec[6] && !spec[7]) {\n";
    src << "        return c == toupper((unsigned char)spec[6]);\n";
    src << "    }\n";
    src << "    return c == fallback;\n";
    src << "}\n\n";

    src << "static int rpm(void* addr, void* buf, size_t sz) {\n";
    src << "    struct iovec l = {buf, sz}, r = {addr, sz};\n";
    src << "    return process_vm_readv(target_pid, &l, 1, &r, 1, 0) >= 0;\n";
    src << "}\n\n";

    src << "static int wpm(void* addr, void* buf, size_t sz) {\n";
    src << "    struct iovec l = {buf, sz}, r = {addr, sz};\n";
    src << "    return process_vm_writev(target_pid, &l, 1, &r, 1, 0) >= 0;\n";
    src << "}\n\n";

    // Generate toggle functions for each entry
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0) continue;

        src << "static int cheat_" << i << "_enabled = 0;\n";
        src << "static void toggle_cheat_" << i << "() {\n";
        src << "    cheat_" << i << "_enabled = !cheat_" << i << "_enabled;\n";
        src << "}\n\n";
    }

    src << "static void print_trainer_ui() {\n";
    src << "    printf(\"\\033[2J\\033[H\");\n";
    src << "    printf(\"Trainer for: %s\\n\", " << cString(table.gameName) << ");\n";
    src << "    printf(\"Target PID: %d\\n\\n\", target_pid);\n";
    src << "    if (*embedded_table_lua || embedded_script_count > 0) {\n";
    src << "        printf(\"Embedded scripts: table=%s entries=%d\\n\\n\", *embedded_table_lua ? \"yes\" : \"no\", embedded_script_count);\n";
    src << "    }\n";
    src << "    printf(\"Cheats:\\n\");\n";
    int keyIdx = 0;
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0) continue;
        auto fallbackKey = static_cast<char>('1' + keyIdx);
        auto hotkeyText = e.hotkeyKeys.empty() ? std::string(1, fallbackKey) : e.hotkeyKeys;
        src << "    printf(\"  [%c] %-12s %s\\n\", cheat_" << i << "_enabled ? 'x' : ' ', "
            << cString(hotkeyText) << ", " << cString(e.description) << ");\n";
        ++keyIdx;
    }
    src << "    printf(\"\\nPress listed hotkeys to toggle. Ctrl+C to exit.\\n\");\n";
    src << "    fflush(stdout);\n";
    src << "}\n\n";

    // Freeze loop
    src << "static volatile int running = 1;\n";
    src << "static void sighandler(int s) { running = 0; }\n\n";

    src << "static void freeze_loop() {\n";
    src << "    while (running) {\n";
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0 || e.value.empty()) continue;
        auto body = freezeWriteBody(e);
        if (!body) continue;
        src << "        if (cheat_" << i << "_enabled) {\n";
        src << "            " << *body << "\n";
        src << "        }\n";
    }
    src << "        usleep(100000);\n";
    src << "    }\n";
    src << "}\n\n";

    // Main
    src << "int main(int argc, char** argv) {\n";
    src << "    if (argc >= 2) target_pid = atoi(argv[1]);\n";
    src << "    else target_pid = find_process_by_name(" << cString(table.gameName) << ");\n";
    src << "    if (target_pid <= 0) {\n";
    src << "        printf(\"Usage: %s <pid>\\n\", argv[0]);\n";
    src << "        printf(\"Auto-detection did not find process: %s\\n\", " << cString(table.gameName) << ");\n";
    src << "        return 1;\n";
    src << "    }\n";
    src << "    signal(SIGINT, sighandler);\n";

    src << "    // Non-blocking terminal input\n";
    src << "    struct termios oldt, newt;\n";
    src << "    tcgetattr(0, &oldt);\n";
    src << "    newt = oldt;\n";
    src << "    newt.c_lflag &= ~(ICANON | ECHO);\n";
    src << "    tcsetattr(0, TCSANOW, &newt);\n\n";
    src << "    print_trainer_ui();\n\n";

    src << "    while (running) {\n";
    src << "        fd_set fds; FD_ZERO(&fds); FD_SET(0, &fds);\n";
    src << "        struct timeval tv = {0, 100000};\n";
    src << "        if (select(1, &fds, NULL, NULL, &tv) > 0) {\n";
    src << "            char c = getchar();\n";

    keyIdx = 0;
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0) continue;
        src << "            if (hotkey_matches((unsigned char)c, " << cString(e.hotkeyKeys)
            << ", '" << static_cast<char>('1' + keyIdx) << "')) { toggle_cheat_" << i << "(); print_trainer_ui(); }\n";
        ++keyIdx;
    }

    src << "        }\n";
    src << "        // Freeze active cheats\n";
    for (size_t i = 0; i < table.entries.size(); ++i) {
        auto& e = table.entries[i];
        if (e.isGroup || e.address == 0 || e.value.empty()) continue;
        auto body = freezeWriteBody(e);
        if (!body) continue;
        src << "        if (cheat_" << i << "_enabled) {\n";
        src << "            " << *body << "\n";
        src << "        }\n";
    }
    src << "    }\n\n";
    src << "    tcsetattr(0, TCSANOW, &oldt);\n";
    src << "    printf(\"\\nTrainer exited.\\n\");\n";
    src << "    return 0;\n";
    src << "}\n";

    return src.str();
}

std::string TrainerGenerator::generateBinary(const CheatTable& table, const std::string& outputPath) const {
    auto source = generateSource(table);
    auto srcPath = outputPath + ".c";

    std::ofstream f(srcPath);
    if (!f) return "Failed to write source file";
    f << source;
    f.close();

    auto cmd = "gcc -O2 -o " + shellQuote(outputPath) + " " + shellQuote(srcPath) + " 2>&1";
    auto* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "Failed to run gcc";

    char buf[256];
    std::string output;
    while (fgets(buf, sizeof(buf), pipe)) output += buf;
    int ret = pclose(pipe);

    std::filesystem::remove(srcPath);

    if (ret != 0) return "Compilation failed: " + output;
    return {};
}

} // namespace ce
