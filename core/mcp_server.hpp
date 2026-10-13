#pragma once
/// A Model Context Protocol server over newline-delimited JSON-RPC 2.0 (the MCP
/// stdio transport). It exposes AgentSession's tools to external agents such as
/// Claude Code: `cescan mcp` runs it on stdin/stdout.

#include "core/agent_tools.hpp"

#include <functional>
#include <iosfwd>
#include <string>

namespace ce {

/// Serve requests from `in` until end of input, `stop` returns true, or `out`
/// fails (the client went away), writing responses to `out`. Returns 0 on a
/// clean end of input.
int runMcpServer(std::istream& in, std::ostream& out, AgentSession& session, const std::string& version,
                 const std::function<bool()>& stop = {});

/// Handle one message or batch (exposed for tests). Returns the response line,
/// or an empty string for notifications, which get no response.
std::string handleMcpMessage(const std::string& line, AgentSession& session, const std::string& version);

} // namespace ce
