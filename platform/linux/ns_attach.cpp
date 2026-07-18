#include "core/ns_attach.hpp"

#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace ce {

std::string resolveProcPath(pid_t pid, const std::string& rawPath) {
    if (rawPath.empty() || rawPath[0] != '/')
        return rawPath;                       // [heap], [stack], anon, "" — nothing to open
    if (::access(rawPath.c_str(), F_OK) == 0)
        return rawPath;                       // openable from the host already (common case)
    // Try through the target's mount namespace root. Requires ptrace-level access to
    // traverse /proc/<pid>/root, which we hold when we can read the process at all.
    std::string viaRoot = "/proc/" + std::to_string(pid) + "/root" + rawPath;
    if (::access(viaRoot.c_str(), F_OK) == 0)
        return viaRoot;
    return rawPath;                           // neither exists; fail as before
}

// Parse the NSpid: line of /proc/<pid>/status into its whitespace-separated fields.
// Returns the fields in namespace order (outermost first, innermost last); empty on
// failure or when the field is absent (older kernels).
static std::vector<pid_t> nspidChain(pid_t pid) {
    std::vector<pid_t> out;
    std::ifstream st("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(st, line)) {
        if (line.rfind("NSpid:", 0) != 0) continue;
        std::istringstream iss(line.substr(6));
        pid_t v;
        while (iss >> v) out.push_back(v);
        break;
    }
    return out;
}

pid_t nsInnerPid(pid_t pid) {
    auto chain = nspidChain(pid);
    return chain.empty() ? pid : chain.back();
}

bool isPidNamespaced(pid_t pid) {
    return nspidChain(pid).size() > 1;
}

} // namespace ce
