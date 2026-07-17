#include "analysis/mono_dissector.hpp"
#include "platform/linux/injector.hpp"
#include "core/log.hpp"

#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <unistd.h>

namespace ce {

size_t MonoDissection::classCount() const {
    size_t n = 0;
    for (const auto& img : images) n += img.classes.size();
    return n;
}

const MonoClassInfo* MonoDissection::findClass(const std::string& fullOrName) const {
    for (const auto& img : images)
        for (const auto& c : img.classes)
            if (c.fullName() == fullOrName || c.name == fullOrName)
                return &c;
    return nullptr;
}

MonoDissection parseMonoDump(const std::string& text) {
    MonoDissection out;
    std::istringstream in(text);
    std::string line;
    MonoImageInfo* curImage = nullptr;
    MonoClassInfo* curClass = nullptr;

    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (line[0] == '#') {
            // Status lines: "# ready …", "# done", "# error: …".
            if (line.rfind("# done", 0) == 0) out.ready = true;
            else if (line.rfind("# error:", 0) == 0)
                out.error = line.substr(std::string("# error:").size() + (line.size() > 8 && line[8] == ' ' ? 1 : 0));
            continue;
        }
        if (line.rfind("IMG ", 0) == 0) {
            out.images.push_back({line.substr(4), {}});
            curImage = &out.images.back();
            curClass = nullptr;
        } else if (line.rfind("CLS ", 0) == 0) {
            if (!curImage) continue;
            // "CLS <Namespace>.<Name>" — the agent always writes a leading dot when
            // the namespace is empty (".<Module>"), so split on the FIRST dot only
            // if a namespace is present.
            std::string full = line.substr(4);
            MonoClassInfo c;
            if (!full.empty() && full[0] == '.') {
                c.name = full.substr(1);            // empty namespace
            } else {
                auto dot = full.rfind('.');
                if (dot == std::string::npos) { c.name = full; }
                else { c.namespaceName = full.substr(0, dot); c.name = full.substr(dot + 1); }
            }
            curImage->classes.push_back(std::move(c));
            curClass = &curImage->classes.back();
        } else if (line.rfind("FLD ", 0) == 0) {
            if (!curClass) continue;
            // "FLD 0x<off> <S|-> <type-name> <field-name>"
            std::istringstream fs(line.substr(4));
            std::string offTok, staticTok, typeName, fieldName;
            fs >> offTok >> staticTok >> typeName;
            std::getline(fs, fieldName);           // remainder (field name; no spaces in practice)
            // trim leading space from getline remainder
            size_t s = fieldName.find_first_not_of(' ');
            fieldName = (s == std::string::npos) ? std::string() : fieldName.substr(s);
            MonoField f;
            f.offset = static_cast<uint32_t>(std::strtoul(offTok.c_str(), nullptr, 0));
            f.isStatic = (staticTok == "S");
            f.typeName = typeName;
            f.name = fieldName;
            curClass->fields.push_back(std::move(f));
        }
    }
    return out;
}

ManagedKind detectManagedKind(ProcessHandle& proc) {
    // Mono ships libmono*/mono-2.0; IL2CPP builds put the AOT code in
    // GameAssembly.so (Unity/Linux) and carry global-metadata.dat + il2cpp_* code.
    bool mono = false, il2cpp = false;
    for (const auto& m : proc.modules()) {
        std::string n = m.name;
        for (auto& ch : n) ch = static_cast<char>(std::tolower((unsigned char)ch));
        // Any "mono" module: libmono-2.0 / libmonosgen / libmonobdwgc /
        // libmono-native, or a statically-linked mono-sgen/mono executable.
        if (n.find("mono") != std::string::npos) mono = true;
        if (n.find("gameassembly") != std::string::npos || n.find("il2cpp") != std::string::npos)
            il2cpp = true;
    }
    if (mono) return ManagedKind::Mono;
    if (il2cpp) return ManagedKind::Il2Cpp;
    return ManagedKind::None;
}

std::string findMonoAgentPath() {
    namespace fs = std::filesystem;
    const char* kName = "libcecore_mono_agent.so";

    // Directory of the running executable (works for the build tree and installs).
    fs::path exeDir;
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; exeDir = fs::path(buf).parent_path(); }

    std::vector<fs::path> candidates;
    if (!exeDir.empty()) {
        candidates.push_back(exeDir / kName);                       // build tree (build/)
        candidates.push_back(exeDir / ".." / "lib" / kName);        // <prefix>/bin + <prefix>/lib
        candidates.push_back(exeDir / ".." / "lib" / "x86_64-linux-gnu" / kName);
    }
    candidates.push_back(fs::path("/usr/lib/x86_64-linux-gnu") / kName);
    candidates.push_back(fs::path("/usr/lib") / kName);
    candidates.push_back(fs::path("/lib/x86_64-linux-gnu") / kName);

    std::error_code ec;
    for (const auto& c : candidates)
        if (fs::exists(c, ec)) return fs::weakly_canonical(c, ec).string();
    return {};
}

std::optional<MonoDissection> dissectMono(ProcessHandle& proc, SymbolResolver& resolver,
                                          const std::string& agentSoPath, int timeoutMs) {
    const int pid = proc.pid();
    const std::string dumpPath = "/tmp/cecore_mono_" + std::to_string(pid) + ".txt";
    std::remove(dumpPath.c_str());   // clear any stale dump from a prior run

    ce::log::info(ce::log::Cat::General, "mono: injecting agent {} into pid {}", agentSoPath, pid);
    auto inj = os::injectLibrary(proc, resolver, agentSoPath);
    if (!inj) {
        ce::log::warn(ce::log::Cat::General, "mono: agent injection failed: {}", inj.error());
        return std::nullopt;
    }

    // The agent dumps on its own thread once the runtime is reachable; poll the
    // file for the terminal "# done"/"# error" marker.
    using namespace std::chrono;
    auto deadline = steady_clock::now() + milliseconds(timeoutMs);
    MonoDissection result;
    while (steady_clock::now() < deadline) {
        std::ifstream f(dumpPath, std::ios::binary);
        if (f) {
            std::stringstream ss; ss << f.rdbuf();
            result = parseMonoDump(ss.str());
            if (result.ready || !result.error.empty()) break;
        }
        std::this_thread::sleep_for(milliseconds(100));
    }
    ce::log::info(ce::log::Cat::General, "mono: dissection {}: {} images, {} classes{}",
                  result.ready ? "ready" : "incomplete", result.images.size(),
                  result.classCount(), result.error.empty() ? "" : (", error: " + result.error));
    return result;
}

uintptr_t findMonoFunction(ProcessHandle& proc, SymbolResolver& resolver,
                           const std::string& agentSoPath, const std::string& ns,
                           const std::string& className, const std::string& methodName,
                           int paramCount, int timeoutMs) {
    const int pid = proc.pid();
    const std::string reqPath  = "/tmp/cecore_mono_req_"  + std::to_string(pid) + ".txt";
    const std::string respPath = "/tmp/cecore_mono_resp_" + std::to_string(pid) + ".txt";
    const std::string dumpPath = "/tmp/cecore_mono_"      + std::to_string(pid) + ".txt";

    // Ensure the resident agent is present. dlopen of an already-loaded .so is a
    // harmless refcount bump (the agent's request loop keeps running from the
    // first injection), so this is safe to call every time.
    auto inj = os::injectLibrary(proc, resolver, agentSoPath);
    if (!inj) {
        ce::log::warn(ce::log::Cat::General, "findMonoFunction: agent injection failed: {}", inj.error());
        return 0;
    }

    std::remove(respPath.c_str());
    {
        std::ofstream rq(reqPath, std::ios::trunc);
        rq << ns << '|' << className << '|' << methodName << '|' << paramCount << '\n';
    }

    // On the first call the agent must finish its initial dump before it services
    // requests; wait for the dump marker OR the response, up to the timeout.
    using namespace std::chrono;
    auto deadline = steady_clock::now() + milliseconds(timeoutMs);
    while (steady_clock::now() < deadline) {
        std::ifstream rp(respPath);
        if (rp) {
            std::string hex; std::getline(rp, hex);
            std::remove(respPath.c_str());
            uintptr_t addr = 0;
            try { addr = static_cast<uintptr_t>(std::stoull(hex, nullptr, 16)); } catch (...) {}
            ce::log::info(ce::log::Cat::General, "findMonoFunction {}.{}::{} -> {:#x}",
                          ns, className, methodName, addr);
            return addr;
        }
        std::this_thread::sleep_for(milliseconds(80));
    }
    ce::log::warn(ce::log::Cat::General, "findMonoFunction {}.{}::{} timed out",
                  ns, className, methodName);
    (void)dumpPath;
    return 0;
}

} // namespace ce
