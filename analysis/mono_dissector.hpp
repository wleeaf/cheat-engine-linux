#pragma once
/// Host side of the Mono dissector. Injects the in-process Mono agent
/// (plugins/mono_agent.c -> libcecore_mono_agent.so) into a Mono/Unity target,
/// then parses the ground-truth image/class/field dump it writes. See the agent
/// for why this must run in-process (only the runtime knows field offsets).

#include "platform/process_api.hpp"
#include "symbols/elf_symbols.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ce {

struct MonoField {
    std::string name;
    std::string typeName;   // e.g. "System.Int32", "Player"
    uint32_t offset = 0;    // field offset within the object (or static area)
    bool isStatic = false;
};

struct MonoClassInfo {
    std::string namespaceName;
    std::string name;
    std::vector<MonoField> fields;
    /// "Namespace.Name" (or just "Name" when the namespace is empty).
    std::string fullName() const {
        return namespaceName.empty() ? name : namespaceName + "." + name;
    }
};

struct MonoImageInfo {
    std::string name;                    // assembly image name, e.g. "Assembly-CSharp"
    std::vector<MonoClassInfo> classes;
};

struct MonoDissection {
    std::vector<MonoImageInfo> images;
    bool ready = false;                  // agent reached "# done"
    std::string error;                   // agent-reported error, if any

    size_t classCount() const;
    /// Find a class by "Namespace.Name" or bare "Name" (first match). nullptr if none.
    const MonoClassInfo* findClass(const std::string& fullOrName) const;
};

/// Parse the agent's dump text (IMG/CLS/FLD lines). Pure + testable; no process.
MonoDissection parseMonoDump(const std::string& text);

/// Inject the agent .so into `proc`, wait up to timeoutMs for its dump to
/// complete, and parse it. `agentSoPath` is the path to libcecore_mono_agent.so.
/// Returns nullopt if injection fails; on success the result's `ready`/`error`
/// reflect the agent's status. Requires ptrace permission on the target.
std::optional<MonoDissection> dissectMono(ProcessHandle& proc, SymbolResolver& resolver,
                                          const std::string& agentSoPath,
                                          int timeoutMs = 8000);

} // namespace ce
