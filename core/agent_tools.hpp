#pragma once
/// Tools an AI agent uses to drive Cheat Engine: attach to a process, scan and
/// narrow values, read and write memory, disassemble, and build a cheat table.
/// Qt-free, so the MCP server (`cescan mcp`) and a future GUI agent panel share
/// one implementation. Results are compact JSON summaries sized for a model's
/// context, never raw memory dumps.

#include "core/ct_file.hpp"
#include "core/json.hpp"

#include <memory>
#include <string>
#include <vector>

namespace ce {

struct AgentToolInfo {
    std::string name;
    std::string description;
    json::Value inputSchema;   // JSON Schema object for the arguments
};

struct AgentToolResult {
    bool isError = false;
    json::Value content;       // the result object, or {"error": "..."} on failure
};

struct AgentSessionOptions {
    // Writing to the game (write, freezing) changes its memory; off unless the
    // user starts the server with it enabled.
    bool allowWrites = false;
    // How often frozen records are rewritten.
    int freezeIntervalMs = 100;
};

class AgentSession {
public:
    explicit AgentSession(AgentSessionOptions options = {});
    ~AgentSession();
    AgentSession(const AgentSession&) = delete;
    AgentSession& operator=(const AgentSession&) = delete;

    /// Every tool, with descriptions written for the model.
    static std::vector<AgentToolInfo> tools();

    /// Run one tool. Unknown tools and bad arguments return isError with a reason.
    AgentToolResult call(const std::string& name, const json::Value& arguments);

    /// Text an MCP client shows the model about how to use the tools.
    static std::string instructions();

    /// Allow or refuse changes to the game from now on (the GUI's switch).
    void setAllowWrites(bool allow);
    /// The table the agent built, as save_table would write it: pointer
    /// records as base and offsets, frozen records active.
    std::vector<CheatEntry> tableEntries();

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace ce
