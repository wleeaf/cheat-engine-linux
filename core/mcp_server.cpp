#include "core/mcp_server.hpp"

#include <array>
#include <istream>
#include <ostream>

namespace ce {

namespace {

using json::Value;

constexpr std::array<const char*, 3> kProtocolVersions = {"2025-06-18", "2025-03-26", "2024-11-05"};

std::string response(const Value& id, Value result) {
    return json::dump(Value::object().set("jsonrpc", Value::string("2.0")).set("id", id).set("result", std::move(result)));
}

std::string errorResponse(const Value& id, int code, const std::string& message) {
    return json::dump(Value::object().set("jsonrpc", Value::string("2.0")).set("id", id)
        .set("error", Value::object().set("code", Value::number(code)).set("message", Value::string(message))));
}

} // namespace

std::string handleMcpMessage(const std::string& line, AgentSession& session, const std::string& version) {
    Value message;
    if (!json::parse(line, message)) return errorResponse(Value(), -32700, "parse error");
    if (!message.isObject()) return errorResponse(Value(), -32600, "invalid request");
    const Value* id = message.get("id");
    const auto method = message.getString("method");
    // Notifications (no id) and responses to our own requests get no reply.
    if (!id || !method) return {};
    if (!id->isNumber() && !id->isString()) return errorResponse(Value(), -32600, "invalid request id");
    const Value* params = message.get("params");
    static const Value empty = Value::object();
    if (!params) params = &empty;

    if (*method == "initialize") {
        std::string requested = params->getString("protocolVersion").value_or(kProtocolVersions[0]);
        std::string chosen = kProtocolVersions[0];
        for (const char* v : kProtocolVersions) if (requested == v) chosen = v;
        return response(*id, Value::object()
            .set("protocolVersion", Value::string(chosen))
            .set("capabilities", Value::object().set("tools", Value::object()))
            .set("serverInfo", Value::object().set("name", Value::string("cheat-engine-linux"))
                                              .set("version", Value::string(version)))
            .set("instructions", Value::string(AgentSession::instructions())));
    }
    if (*method == "ping") return response(*id, Value::object());
    if (*method == "tools/list") {
        Value tools = Value::array();
        for (const auto& tool : AgentSession::tools())
            tools.push(Value::object().set("name", Value::string(tool.name))
                                      .set("description", Value::string(tool.description))
                                      .set("inputSchema", tool.inputSchema));
        return response(*id, Value::object().set("tools", tools));
    }
    if (*method == "tools/call") {
        const auto name = params->getString("name");
        if (!name) return errorResponse(*id, -32602, "tools/call needs a tool name");
        const Value* arguments = params->get("arguments");
        const AgentToolResult result = session.call(*name, arguments ? *arguments : Value::object());
        Value content = Value::array();
        content.push(Value::object().set("type", Value::string("text"))
                                    .set("text", Value::string(json::dump(result.content))));
        return response(*id, Value::object().set("content", content).set("isError", Value::boolean(result.isError)));
    }
    return errorResponse(*id, -32601, "method not found: " + *method);
}

int runMcpServer(std::istream& in, std::ostream& out, AgentSession& session, const std::string& version) {
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find_first_not_of(" \t") == std::string::npos) continue;
        const std::string reply = handleMcpMessage(line, session, version);
        if (!reply.empty()) {
            out << reply << '\n';
            out.flush();
        }
    }
    return 0;
}

} // namespace ce
