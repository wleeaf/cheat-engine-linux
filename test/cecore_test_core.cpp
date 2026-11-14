// cecore_test: values, tables, agent tools, codecs, parsers, symbols and
// managed runtimes, clients of the remote protocols.
#include "test_target.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/mono_debugger_client.hpp"
#include "platform/linux/process_watcher.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/kernel_driver.hpp"
#include "platform/network_compression.hpp"
#include "platform/vulkan_overlay_injector.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/wine_memory.hpp"
#include "platform/linux/memory_image.hpp"
#ifdef CE_HAVE_VULKAN
#include <vulkan/vulkan.h>
#include <vulkan/vk_layer.h>
#include <dlfcn.h>
#endif
#include "scanner/pointer_scanner.hpp"
#include "scanner/snapshot.hpp"
#include "core/target_capabilities.hpp"
#include "core/value_io.hpp"
#include "core/autoasm.hpp"
#include "core/aa_templates.hpp"
#include "core/injection_gen.hpp"
#include "core/ct_file.hpp"
#include "analysis/mono_dissector.hpp"
#include "core/simple_hook.hpp"
#include "core/log.hpp"
#include "core/target_profile.hpp"
#include "core/guest_view.hpp"
#include "core/ns_attach.hpp"
#include "core/value_codec.hpp"
#include "core/value_transform.hpp"
#include "arch/disassembler.hpp"
#include "arch/cpu_flags.hpp"
#include "core/expression.hpp"
#include "core/memview_nav.hpp"
#include "core/trainer.hpp"
#include "analysis/code_analysis.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/il2cpp_metadata.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "analysis/signature.hpp"
#include "analysis/pe_exports.hpp"
#include "analysis/structure_tools.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/stack_trace.hpp"
#include "debug/tracer.hpp"
#include "debug/debug_session.hpp"
#include "debug/gdb_remote.hpp"
#include "debug/managed_breakpoint.hpp"
#include "debug/code_finder.hpp"
#include "debug/instruction_access.hpp"
#include "debug/patch.hpp"
#include "symbols/kernel_symbols.hpp"
#include "symbols/dwarf_symbols.hpp"
#include "scripting/lua_engine.hpp"
#include "core/address_list.hpp"
#include "core/simple_address_list.hpp"
#include "plugins/plugin_loader.hpp"

#include <cstdio>
#include <cstdlib>
#include "symbols/elf_symbols.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <csignal>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <cstdarg>
#include <stdexcept>
#include "core/mcp_server.hpp"
#include "core/agent_chat.hpp"
#include "arch/target_arch.hpp"
#include "core/json.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <csignal>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <poll.h>

#include "test/cecore_test.hpp"

void test_memory_access_problem() {
    printf("\n── Test: Unreadable target is reported, not scanned as empty ──\n");
    // Yama ptrace_scope >= 1 makes every read of a non-descendant fail with EPERM;
    // a scan must then say so instead of reporting zero results.
    struct DeniedProcessHandle : FakeProcessHandle {
        using FakeProcessHandle::FakeProcessHandle;
        Result<size_t> read(uintptr_t, void*, size_t) override {
            return std::unexpected(std::error_code(EPERM, std::system_category()));
        }
    };
    std::vector<uint8_t> data(64, 0x5a);
    FakeProcessHandle::Segment segment{{0x500000, data.size(), MemProt::ReadWrite, MemType::Private,
                                        MemState::Committed, ""}, data};
    FakeProcessHandle readable({segment}, {});
    DeniedProcessHandle denied({segment}, {});
    FakeProcessHandle empty({}, {});
    auto ok = ce::memoryAccessProblem(readable);
    auto problem = ce::memoryAccessProblem(denied);
    printf("  readable target -> no problem: %s\n", !ok ? "OK" : "FAILED");
    printf("  EPERM target -> explicit read error: %s (%s)\n",
           problem && problem->starts_with("read memory: ") ? "OK" : "FAILED",
           problem ? problem->c_str() : "none");
    printf("  no readable regions -> nothing to report: %s\n", !ce::memoryAccessProblem(empty) ? "OK" : "FAILED");
}

// The agent tools through the MCP server, against a real child process: the
// protocol handshake, tool listing, attach, scanning, write gating, freezing,
// and a saved table that loads back.
static volatile int g_agentHealth = 4711;

// The AI Assistant's conversation loop against a scripted model: both API
// formats, tool calls run in a real session, approval before changes, and
// errors that leave the conversation usable.
void test_agent_chat() {
    printf("\n── Test: AI Assistant conversation (scripted model) ──\n");
    int ready[2];
    if (pipe(ready) != 0) { printf("  pipe: FAILED\n"); return; }
    const pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        g_agentHealth = 4711;
        if (write(ready[1], "x", 1) != 1) _exit(1);
        for (;;) pause();
    }
    char byte = 0;
    if (read(ready[0], &byte, 1) != 1) printf("  child start: FAILED\n");
    close(ready[0]); close(ready[1]);
    char address[32];
    std::snprintf(address, sizeof address, "0x%lx", static_cast<unsigned long>(reinterpret_cast<uintptr_t>(&g_agentHealth)));
    const std::string pid = std::to_string(child);
    auto health = [&] {
        int32_t v = 0;
        (void)ce::os::LinuxProcessHandle(child).read(reinterpret_cast<uintptr_t>(&g_agentHealth), &v, sizeof v);
        return v;
    };

    // Anthropic: the model attaches, then asks to write; the user declines once, then allows.
    {
        ce::AgentSessionOptions options;
        options.allowWrites = true;
        ce::AgentSession session(options);
        std::vector<ce::ChatHttpRequest> seen;
        std::vector<std::string> replies = {
            R"({"content":[{"type":"tool_use","id":"t1","name":"attach","input":{"target":")" + pid + R"("}}],"stop_reason":"tool_use"})",
            R"({"content":[{"type":"text","text":"Setting health."},{"type":"tool_use","id":"t2","name":"write","input":{"address":")" +
                std::string(address) + R"(","type":"i32","value":"1234"}}],"stop_reason":"tool_use"})",
            R"({"content":[{"type":"text","text":"Left it as it was."}],"stop_reason":"end_turn"})",
            R"({"content":[{"type":"tool_use","id":"t3","name":"write","input":{"address":")" + std::string(address) +
                R"(","type":"i32","value":"1234"}}],"stop_reason":"tool_use"})",
            R"({"content":[{"type":"text","text":"Done."}],"stop_reason":"end_turn"})",
        };
        size_t next = 0;
        ce::AgentChat chat(session, {}, "sk-test", [&](const ce::ChatHttpRequest& request) {
            seen.push_back(request);
            return next < replies.size() ? ce::ChatHttpResponse{200, replies[next++], {}} : ce::ChatHttpResponse{500, "{}", {}};
        });
        std::vector<ce::ChatEvent> events;
        chat.setEventSink([&](const ce::ChatEvent& e) { events.push_back(e); });
        bool allow = false;
        int asked = 0;
        chat.setApprover([&](const std::string& tool, const ce::json::Value&) {
            if (tool == "attach") return true;   // the panel lets the opened process through
            ++asked;
            return tool == "write" && allow;
        });
        const bool first = chat.send("Set my health to 1234.");
        bool keyHeader = false, version = false;
        for (const auto& [name, value] : seen.front().headers) {
            keyHeader = keyHeader || (name == "x-api-key" && value == "sk-test");
            version = version || name == "anthropic-version";
        }
        printf("  Anthropic request: endpoint, key header, tools, model: %s\n",
               seen.front().url == "https://api.anthropic.com/v1/messages" && keyHeader && version &&
               seen.front().body.find("\"input_schema\"") != std::string::npos &&
               seen.front().body.find("claude-sonnet-5-5") != std::string::npos ? "OK" : "FAILED");
        printf("  tool results go back as tool_result blocks: %s\n",
               seen.size() >= 2 && seen[1].body.find("\"tool_result\"") != std::string::npos &&
               seen[1].body.find("\"tool_use_id\":\"t1\"") != std::string::npos ? "OK" : "FAILED");
        printf("  a declined change is not made and the model is told: %s\n",
               first && asked == 1 && health() == 4711 && seen.size() == 3 &&
               seen[2].body.find("declined") != std::string::npos ? "OK" : "FAILED");
        allow = true;
        const bool second = chat.send("Do it, I approve.");
        printf("  an approved change is made: %s (%d)\n", second && health() == 1234 ? "OK" : "FAILED", health());
        // A turn cut off after tool results: the next user text joins that user
        // turn, because Anthropic's turns must alternate.
        {
            std::vector<std::string> bodies;
            ce::AgentChat cut(session, {}, "k", [&](const ce::ChatHttpRequest& request) {
                bodies.push_back(request.body);
                return ce::ChatHttpResponse{200, R"({"content":[{"type":"tool_use","id":"t9","name":"target_info","input":{}}]})", {}};
            });
            cut.setMaxRounds(1);
            const bool stopped = !cut.send("Look around.");
            cut.send("Go on.");
            printf("  user and assistant turns alternate after a cut-off turn: %s\n",
                   stopped && bodies.size() == 2 &&
                   bodies[1].find("\"tool_use_id\":\"t9\"") < bodies[1].find("\"text\":\"Go on.\"") &&
                   bodies[1].find("\"role\":\"user\",\"content\":\"Go on.\"") == std::string::npos ? "OK" : "FAILED");
        }
        // An empty reply after tool results must not leave an empty assistant
        // turn behind (the API rejects every later request), and a failure after
        // tools ran keeps their results so the model knows what was done.
        {
            std::vector<std::string> bodies;
            std::vector<ce::ChatHttpResponse> answers = {
                {200, R"({"content":[{"type":"tool_use","id":"e1","name":"target_info","input":{}}]})", {}},
                {200, R"({"content":[],"stop_reason":"end_turn"})", {}},
                {200, R"({"content":[{"type":"tool_use","id":"e2","name":"target_info","input":{}}]})", {}},
                {529, R"({"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}})", {}},
                {200, R"({"content":[{"type":"text","text":"ok"}]})", {}},
            };
            size_t at = 0;
            ce::AgentChat empty(session, {}, "k", [&](const ce::ChatHttpRequest& request) {
                bodies.push_back(request.body);
                return at < answers.size() ? answers[at++] : ce::ChatHttpResponse{500, "{}", {}};
            });
            const bool firstOk = empty.send("Look.");
            const bool overloaded = !empty.send("Again.");
            const bool resumed = empty.send("Go on.");
            printf("  an empty reply leaves no empty assistant turn: %s\n",
                   firstOk && bodies.size() >= 3 && bodies[2].find("\"content\":[]") == std::string::npos ? "OK" : "FAILED");
            printf("  a failure after tools ran keeps their results: %s\n",
                   overloaded && resumed && bodies.size() == 5 && bodies[4].find("\"tool_use_id\":\"e2\"") != std::string::npos ? "OK" : "FAILED");
        }
        bool sawCall = false, sawText = false;
        for (const auto& e : events) {
            sawCall = sawCall || (e.type == ce::ChatEvent::Type::ToolCall && e.tool == "attach");
            sawText = sawText || (e.type == ce::ChatEvent::Type::AssistantText && e.text == "Done.");
        }
        printf("  events report tool calls and replies: %s\n", sawCall && sawText ? "OK" : "FAILED");

        // A refused key: an error, and the conversation is as it was.
        ce::AgentChat refused(session, {}, "bad", [](const ce::ChatHttpRequest&) {
            return ce::ChatHttpResponse{401, R"({"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}})", {}};
        });
        std::string error;
        refused.setEventSink([&](const ce::ChatEvent& e) { if (e.type == ce::ChatEvent::Type::Error) error = e.text; });
        const bool refusedSent = refused.send("hi");
        printf("  a refused key is reported: %s (%s)\n",
               !refusedSent && error.find("API key was refused") != std::string::npos &&
               error.find("invalid x-api-key") != std::string::npos && refused.messageCount() == 0 ? "OK" : "FAILED", error.c_str());
        ce::AgentChat offline(session, {}, "k", [](const ce::ChatHttpRequest&) { return ce::ChatHttpResponse{0, {}, "connection refused"}; });
        offline.setEventSink([&](const ce::ChatEvent& e) { if (e.type == ce::ChatEvent::Type::Error) error = e.text; });
        printf("  no connection is reported: %s\n", !offline.send("hi") && error.find("Could not reach") != std::string::npos ? "OK" : "FAILED");
    }

    // OpenAI-compatible: function calls with JSON-string arguments, role "tool" results.
    {
        ce::AgentSession session;
        ce::ChatProvider provider;
        provider.kind = ce::ChatProviderKind::OpenAiCompatible;
        provider.baseUrl = "http://localhost:11434/v1/";
        provider.model = "qwen3";
        std::vector<ce::ChatHttpRequest> seen;
        std::vector<std::string> replies = {
            R"({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"attach","arguments":"{\"target\":\")" +
                pid + R"(\"}"}}]},"finish_reason":"tool_calls"}]})",
            R"({"choices":[{"message":{"role":"assistant","content":"Attached."},"finish_reason":"stop"}]})",
        };
        size_t next = 0;
        ce::AgentChat chat(session, provider, "", [&](const ce::ChatHttpRequest& request) {
            seen.push_back(request);
            return next < replies.size() ? ce::ChatHttpResponse{200, replies[next++], {}} : ce::ChatHttpResponse{500, "{}", {}};
        });
        std::string reply;
        chat.setEventSink([&](const ce::ChatEvent& e) { if (e.type == ce::ChatEvent::Type::AssistantText) reply = e.text; });
        chat.setApprover([](const std::string& tool, const ce::json::Value&) { return tool == "attach"; });
        const bool ok = chat.send("Attach to my game.");
        bool auth = false;
        for (const auto& header : seen.front().headers) auth = auth || header.first == "authorization";
        printf("  OpenAI-compatible request: endpoint, functions, no key header without a key: %s\n",
               seen.front().url == "http://localhost:11434/v1/chat/completions" && !auth &&
               seen.front().body.find("\"parameters\"") != std::string::npos &&
               seen.front().body.find("\"role\":\"system\"") != std::string::npos ? "OK" : "FAILED");
        printf("  tool results go back as role tool messages: %s\n",
               ok && reply == "Attached." && seen.size() == 2 &&
               seen[1].body.find("\"role\":\"tool\",\"tool_call_id\":\"c1\"") != std::string::npos ? "OK" : "FAILED");
        // Some local servers send the arguments as an object, not a JSON string.
        std::vector<std::string> bodies;
        bool first = true;
        ce::AgentChat objects(session, provider, "", [&](const ce::ChatHttpRequest& request) {
            bodies.push_back(request.body);
            if (!first) return ce::ChatHttpResponse{200, R"({"choices":[{"message":{"role":"assistant","content":"ok"}}]})", {}};
            first = false;
            return ce::ChatHttpResponse{200, R"({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"o1","type":"function","function":{"name":"read","arguments":{"address":")" +
                std::string(address) + R"(","type":"i32"}}}]}}]})", {}};
        });
        printf("  object arguments are accepted: %s\n",
               objects.send("Read it.") && bodies.size() == 2 && bodies[1].find("arguments are not") == std::string::npos &&
               bodies[1].find(std::to_string(health())) != std::string::npos ? "OK" : "FAILED");
        // A tool call without a function gets no result, so it must not stay in
        // the conversation: the server would reject every later request.
        bodies.clear();
        bool firstCall = true;
        ce::AgentChat broken(session, provider, "", [&](const ce::ChatHttpRequest& request) {
            bodies.push_back(request.body);
            if (!firstCall) return ce::ChatHttpResponse{200, R"({"choices":[{"message":{"role":"assistant","content":"ok"}}]})", {}};
            firstCall = false;
            return ce::ChatHttpResponse{200, R"({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"x1","type":"function"},)"
                R"({"id":"x2","type":"function","function":{"name":"target_info","arguments":"{}"}}]}}]})", {}};
        });
        printf("  tool calls without a function are dropped: %s\n",
               broken.send("Look.") && bodies.size() == 2 && bodies[1].find("\"x1\"") == std::string::npos &&
               bodies[1].find("\"tool_call_id\":\"x2\"") != std::string::npos ? "OK" : "FAILED");
    }
    // At most 16 tool calls run from one reply; every call still gets a result.
    {
        ce::AgentSession session;
        std::string many = R"({"content":[)";
        for (int i = 0; i < 18; ++i) many += std::string(i ? "," : "") + R"({"type":"tool_use","id":"m)" + std::to_string(i) + R"(","name":"target_info","input":{}})";
        many += "]}";
        std::vector<std::string> bodies;
        ce::AgentChat chat(session, {}, "k", [&](const ce::ChatHttpRequest& request) {
            bodies.push_back(request.body);
            return ce::ChatHttpResponse{200, bodies.size() == 1 ? many : R"({"content":[{"type":"text","text":"ok"}]})", {}};
        });
        int ran = 0;
        chat.setEventSink([&](const ce::ChatEvent& e) { if (e.type == ce::ChatEvent::Type::ToolCall) ++ran; });
        size_t results = 0, refused = 0;
        const bool ok = chat.send("Look a lot.");
        if (bodies.size() == 2)
            for (size_t at = 0; (at = bodies[1].find("\"tool_result\"", at)) != std::string::npos; ++at) ++results;
        if (bodies.size() == 2)
            for (size_t at = 0; (at = bodies[1].find("only 16 tool calls", at)) != std::string::npos; ++at) ++refused;
        printf("  at most 16 tool calls run per reply: %s (%d ran, %zu results, %zu refused)\n",
               ok && ran == 16 && results == 18 && refused == 2 ? "OK" : "FAILED", ran, results, refused);
        std::string error;
        ce::AgentChat huge(session, {}, "k", [](const ce::ChatHttpRequest&) {
            ce::ChatHttpResponse response{200, "{}", {}};
            response.truncated = true;
            return response;
        });
        huge.setEventSink([&](const ce::ChatEvent& e) { if (e.type == ce::ChatEvent::Type::Error) error = e.text; });
        printf("  a reply that is too large is refused: %s\n",
               !huge.send("hi") && error.find("larger than 16 MiB") != std::string::npos && huge.messageCount() == 0 ? "OK" : "FAILED");
    }
    printf("  changes that need approval: %s\n",
           ce::AgentChat::needsApproval("write", ce::json::Value::object()) &&
           ce::AgentChat::needsApproval("aa_enable", ce::json::Value::object()) &&
           ce::AgentChat::needsApproval("aa_disable", ce::json::Value::object()) &&
           ce::AgentChat::needsApproval("find_accessed_addresses", ce::json::Value::object()) &&
           ce::AgentChat::needsApproval("save_table", ce::json::Value::object()) &&
           ce::AgentChat::needsApproval("attach", ce::json::Value::object()) &&
           ce::AgentChat::needsApproval("set_frozen", ce::json::Value::object().set("frozen", ce::json::Value::boolean(true))) &&
           !ce::AgentChat::needsApproval("set_frozen", ce::json::Value::object().set("frozen", ce::json::Value::boolean(false))) &&
           !ce::AgentChat::needsApproval("first_scan", ce::json::Value::object()) ? "OK" : "FAILED");
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
}

// A discarded scan removes its directory; the CLI keeps the ones it prints.
void test_scan_directory_cleanup() {
    printf("\n── Test: Scan results clean up after themselves ──\n");
    static volatile int32_t values[64];
    for (int i = 0; i < 64; ++i) values[i] = 0x5eed0000 + (i % 3);
    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner(1);
    ScanConfig config;
    config.valueType = ValueType::Int32;
    config.compareType = ScanCompare::Exact;
    config.intValue = 0x5eed0001;
    config.startAddress = reinterpret_cast<uintptr_t>(values);
    config.stopAddress = config.startAddress + sizeof values - 1;
    std::filesystem::path firstDir, nextDir, keptDir;
    {
        ScanResult first = scanner.firstScan(proc, config);
        firstDir = first.directory().parent_path();
        ScanResult next = scanner.nextScan(proc, config, first);
        nextDir = next.directory().parent_path();
        printf("  results exist while in use: %s\n",
               std::filesystem::exists(firstDir) && std::filesystem::exists(nextDir) && next.count() == 21 ? "OK" : "FAILED");
        ScanResult kept = scanner.firstScan(proc, config);
        kept.keepFiles();
        keptDir = kept.directory().parent_path();
    }
    printf("  discarded results remove their directories: %s\n",
           !std::filesystem::exists(firstDir) && !std::filesystem::exists(nextDir) ? "OK" : "FAILED");
    printf("  keepFiles leaves them for a later scan: %s\n", std::filesystem::exists(keptDir) ? "OK" : "FAILED");
    std::filesystem::remove_all(keptDir);
}

// Values that do not fit the type, float steps and an unaligned From address.
void test_scan_review_fixes() {
    printf("\n── Test: Scan values, float steps and From alignment ──\n");
    alignas(16) static volatile int32_t ints[16];
    for (auto& v : ints) v = 0;
    ints[4] = 0x13572468;
    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner(1);
    ScanConfig config;
    config.valueType = ValueType::Byte;
    config.compareType = ScanCompare::Exact;
    config.intValue = 300;   // cast to a byte this was 44
    config.startAddress = reinterpret_cast<uintptr_t>(ints);
    config.stopAddress = config.startAddress + sizeof ints - 1;
    auto refused = [&](const ScanConfig& c) {
        try { (void)scanner.firstScan(proc, c); } catch (const std::invalid_argument&) { return true; }
        return false;
    };
    ScanConfig between = config;
    between.compareType = ScanCompare::Between;
    between.intValue = -5;
    between.intValue2 = 5;
    ScanConfig bigger = config;
    bigger.valueType = ValueType::Int16;
    bigger.compareType = ScanCompare::Greater;
    bigger.intValue = 40000;
    ScanConfig unsignedExact = config;
    unsignedExact.valueType = ValueType::Int16;
    unsignedExact.intValue = 40000;   // the unsigned reading of the same bits is fine
    printf("  values that do not fit the type are refused: %s\n",
           refused(config) && refused(between) && refused(bigger) && !refused(unsignedExact) ? "OK" : "FAILED");

    config.valueType = ValueType::Int32;
    config.intValue = 0x13572468;
    config.alignment = 4;
    config.startAddress = reinterpret_cast<uintptr_t>(ints) + 2;   // off the grid
    ScanResult aligned = scanner.firstScan(proc, config);
    printf("  an unaligned From address keeps the alignment grid: %s\n",
           aligned.count() == 1 && aligned.address(0) == reinterpret_cast<uintptr_t>(&ints[4]) ? "OK" : "FAILED");

    alignas(16) static volatile float health[4] = {100.0f, 0, 0, 0};
    ScanConfig floats;
    floats.valueType = ValueType::Float;
    floats.compareType = ScanCompare::Unknown;
    floats.alignment = 4;
    floats.startAddress = reinterpret_cast<uintptr_t>(health);
    floats.stopAddress = floats.startAddress + sizeof health - 1;
    ScanResult before = scanner.firstScan(proc, floats);
    health[0] = 100.0f + 0.1f;   // stored as 100.0999985
    floats.compareType = ScanCompare::IncreasedBy;
    floats.floatValue = 0.1;
    ScanResult after = scanner.nextScan(proc, floats, before);
    printf("  float increased by 0.1 from 100 is found: %s\n",
           after.count() == 1 && after.address(0) == reinterpret_cast<uintptr_t>(&health[0]) ? "OK" : "FAILED");
}

// Two game objects and the pointer that picks one: the agent's pointer records
// must follow the pointer when the game switches objects.
static int32_t g_agentObjects[2][4] = {{1, 5, 40, 9}, {2, 5, 40, 9}};
static int32_t* volatile g_agentPointer = g_agentObjects[0];
static uintptr_t g_agentChain[2];   // a two-level pointer path to g_agentObjects[0][3]
void test_agent_mcp() {
    printf("\n── Test: Agent tools over MCP ──\n");
    g_agentChain[0] = reinterpret_cast<uintptr_t>(&g_agentChain[1]);
    g_agentChain[1] = reinterpret_cast<uintptr_t>(&g_agentObjects[0][3]);
    {
        // JSON text is UTF-8: raw bytes from game memory must not break it.
        const std::string escaped = ce::json::escape(std::string("ok \xc3\xa9 \xff \xe2\x82 \xed\xa0\x80 end"));
        printf("  JSON output replaces invalid UTF-8: %s (%s)\n",
               escaped == "ok \xc3\xa9 \\ufffd \\ufffd\\ufffd \\ufffd\\ufffd\\ufffd end" ? "OK" : "FAILED", escaped.c_str());
    }
    int ready[2];
    if (pipe(ready) != 0) { printf("  pipe: FAILED\n"); return; }
    const pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        g_agentHealth = 4711;
        if (write(ready[1], "x", 1) != 1) _exit(1);
        for (;;) pause();
    }
    char byte = 0;
    if (read(ready[0], &byte, 1) != 1) { printf("  child start: FAILED\n"); }
    close(ready[0]); close(ready[1]);
    auto rpc = [](ce::AgentSession& session, int id, const std::string& method, const std::string& params) {
        const std::string line = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(id) + ",\"method\":\"" + method +
                                 "\",\"params\":" + params + "}";
        ce::json::Value reply;
        ce::json::parse(ce::handleMcpMessage(line, session, "test"), reply);
        return reply;
    };
    // Call a tool and return its result object (the text content, parsed).
    auto tool = [&](ce::AgentSession& session, const std::string& name, const std::string& arguments, bool* isError = nullptr) {
        auto reply = rpc(session, 9, "tools/call", "{\"name\":\"" + name + "\",\"arguments\":" + arguments + "}");
        ce::json::Value content;
        const ce::json::Value* result = reply.get("result");
        if (isError) *isError = result && result->getBool("isError").value_or(true);
        if (result && result->get("content") && !result->get("content")->arrayValue.empty())
            ce::json::parse(result->get("content")->arrayValue[0].getString("text").value_or(""), content);
        return content;
    };
    const std::string pid = std::to_string(child);
    const uintptr_t address = reinterpret_cast<uintptr_t>(&g_agentHealth);
    char hexAddress[32];
    std::snprintf(hexAddress, sizeof hexAddress, "0x%lx", static_cast<unsigned long>(address));
    {
        ce::AgentSession readOnly;
        auto init = rpc(readOnly, 1, "initialize", "{\"protocolVersion\":\"2025-06-18\"}");
        const auto* initResult = init.get("result");
        printf("  initialize negotiates the protocol: %s\n",
               initResult && initResult->getString("protocolVersion") == "2025-06-18" ? "OK" : "FAILED");
        auto list = rpc(readOnly, 2, "tools/list", "{}");
        bool hasScan = false;
        if (const auto* r = list.get("result"); r && r->get("tools"))
            for (const auto& t : r->get("tools")->arrayValue) hasScan = hasScan || t.getString("name") == "first_scan";
        printf("  tools/list includes first_scan: %s\n", hasScan ? "OK" : "FAILED");
        printf("  notifications get no reply: %s\n",
               ce::handleMcpMessage("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}", readOnly, "t").empty() ? "OK" : "FAILED");
        auto unknown = rpc(readOnly, 3, "nope", "{}");
        printf("  unknown method -> error -32601: %s\n",
               unknown.get("error") && unknown.get("error")->getInt("code") == -32601 ? "OK" : "FAILED");
        {
            // A line over the 4 MiB cap is refused whole; the next message is still read.
            std::istringstream in(std::string((4u << 20) + 1, 'x') + "\n{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\"}\n");
            std::ostringstream out;
            ce::runMcpServer(in, out, readOnly, "test");
            const std::string text = out.str();
            const size_t newline = text.find('\n');
            ce::json::Value refusedLong, pong;
            const bool parsed = newline != std::string::npos && ce::json::parse(text.substr(0, newline), refusedLong) &&
                                ce::json::parse(text.substr(newline + 1), pong);
            printf("  an over-long MCP message gets -32600 and the next one an answer: %s\n",
                   parsed && refusedLong.get("error") && refusedLong.get("error")->getInt("code") == -32600 &&
                   pong.getInt("id") == 5 && pong.get("result") ? "OK" : "FAILED");
        }
        bool error = false;
        tool(readOnly, "first_scan", "{\"type\":\"i32\",\"value\":\"4711\"}", &error);
        printf("  tools need an attached process: %s\n", error ? "OK" : "FAILED");
        auto attached = tool(readOnly, "attach", "{\"target\":\"" + pid + "\"}", &error);
        printf("  attach by PID: %s\n", !error && attached.getInt("pid") == child ? "OK" : "FAILED");
        // A JSON number is a decimal address; the expression parser alone would read it as hex.
        auto byNumber = tool(readOnly, "read", "{\"address\":" + std::to_string(reinterpret_cast<uintptr_t>(&g_agentHealth)) +
                                               ",\"type\":\"i32\"}", &error);
        printf("  an address given as a JSON number is decimal: %s\n",
               !error && byNumber.getString("value") == "4711" ? "OK" : "FAILED");
        tool(readOnly, "first_scan", "{\"type\":\"string\",\"compare\":\"greater\",\"value\":\"abc\"}", &error);
        printf("  string scans refuse compares they cannot do: %s\n", error ? "OK" : "FAILED");
        tool(readOnly, "attach", "{\"target\":\"4294968296\"}", &error);
        printf("  attach refuses a PID out of range: %s\n", error ? "OK" : "FAILED");
        auto scan = tool(readOnly, "first_scan", "{\"type\":\"i32\",\"value\":\"4711\"}", &error);
        printf("  first_scan reports matches: %s (count %lld)\n", !error && scan.getInt("count").value_or(0) >= 1 ? "OK" : "FAILED",
               static_cast<long long>(scan.getInt("count").value_or(-1)));
        // Narrow like an agent does: the value changes in the game, then next_scan.
        // (A sanitizer build holds many stray copies of the first value.)
        {
            ce::os::LinuxProcessHandle process(child);
            const int32_t changed = 0x1d3c5b7;
            (void)process.write(address, &changed, sizeof changed);
        }
        auto narrowed = tool(readOnly, "next_scan", "{\"compare\":\"exact\",\"value\":\"30655927\"}", &error);
        bool found = false;
        if (const auto* candidates = narrowed.get("candidates"))
            for (const auto& c : candidates->arrayValue) found = found || c.getString("address") == hexAddress;
        printf("  next_scan narrows to the value: %s (count %lld)\n", !error && found ? "OK" : "FAILED",
               static_cast<long long>(narrowed.getInt("count").value_or(-1)));
        auto undone = tool(readOnly, "undo_scan", "{}", &error);
        printf("  undo_scan restores the first results: %s\n",
               !error && undone.getInt("count") == scan.getInt("count") ? "OK" : "FAILED");
        tool(readOnly, "write", "{\"address\":\"" + std::string(hexAddress) + "\",\"type\":\"i32\",\"value\":\"1\"}", &error);
        printf("  write is refused without --allow-writes: %s\n", error ? "OK" : "FAILED");
        {
            // Both change the game's code: restoring a script, or a breakpoint.
            bool disableRefused = false, watchRefused = false;
            auto disabled = tool(readOnly, "aa_disable", "{\"id\":1}", &disableRefused);
            auto watched = tool(readOnly, "find_accessed_addresses", "{\"address\":\"" + std::string(hexAddress) + "\"}", &watchRefused);
            printf("  aa_disable and find_accessed_addresses need --allow-writes: %s\n",
                   disableRefused && watchRefused &&
                   disabled.getString("error").value_or("").find("--allow-writes") != std::string::npos &&
                   watched.getString("error").value_or("").find("--allow-writes") != std::string::npos ? "OK" : "FAILED");
        }
        // Unknown value that changes by a known amount.
        {
            ce::os::LinuxProcessHandle process(child);
            const int32_t start = 0x2468ace;
            (void)process.write(address, &start, sizeof start);
            tool(readOnly, "first_scan", "{\"type\":\"i32\",\"value\":\"38177486\"}", &error);
            const int32_t raised = start + 7;
            (void)process.write(address, &raised, sizeof raised);
        }
        auto by = tool(readOnly, "next_scan", "{\"compare\":\"increased_by\",\"value\":\"7\"}", &error);
        bool foundBy = false;
        if (const auto* candidates = by.get("candidates"))
            for (const auto& c : candidates->arrayValue) foundBy = foundBy || c.getString("address") == hexAddress;
        printf("  next_scan increased_by finds the value: %s\n", !error && foundBy ? "OK" : "FAILED");
        tool(readOnly, "first_scan", "{\"type\":\"i32\",\"compare\":\"increased_by\",\"value\":\"7\"}", &error);
        printf("  increased_by needs an earlier scan: %s\n", error ? "OK" : "FAILED");
        char objects[2][32];
        for (int i = 0; i < 2; ++i)
            std::snprintf(objects[i], sizeof objects[i], "0x%lx", static_cast<unsigned long>(reinterpret_cast<uintptr_t>(g_agentObjects[i])));
        auto compared = tool(readOnly, "compare_structures", std::string("{\"group1\":[\"") + objects[0] + "\"],\"group2\":[\"" +
                             objects[1] + "\"],\"size\":16}", &error);
        const auto* differs = compared.get("differs_between_groups");
        printf("  compare_structures finds the field that differs: %s\n",
               !error && differs && differs->arrayValue.size() == 1 && differs->arrayValue[0].stringValue == "0x0" ? "OK" : "FAILED");
    }
    {
        ce::AgentSessionOptions options;
        options.allowWrites = true;
        options.freezeIntervalMs = 20;
        ce::AgentSession session(options);
        bool error = false;
        tool(session, "attach", "{\"target\":\"" + pid + "\"}", &error);
        auto written = tool(session, "write", "{\"address\":\"" + std::string(hexAddress) + "\",\"type\":\"i32\",\"value\":\"999\"}", &error);
        printf("  write changes the value: %s\n", !error && written.getString("value_now") == "999" ? "OK" : "FAILED");
        tool(session, "add_record", "{\"address\":\"" + std::string(hexAddress) + "\",\"type\":\"i32\",\"description\":\"Health\"}", &error);
        tool(session, "set_frozen", "{\"index\":0,\"frozen\":true,\"value\":\"500\"}", &error);
        // Something else changes the value; the freeze puts it back.
        ce::os::LinuxProcessHandle process(child);
        const int32_t other = 7;
        (void)process.write(address, &other, sizeof other);
        usleep(150000);
        int32_t now = 0;
        (void)process.read(address, &now, sizeof now);
        printf("  set_frozen keeps the value: %s (%d)\n", !error && now == 500 ? "OK" : "FAILED", now);
        const std::string path = (std::filesystem::temp_directory_path() / ("ce-agent-" + pid + ".CT")).string();
        std::filesystem::remove(path);
        auto saved = tool(session, "save_table", "{\"path\":\"" + path + "\"}", &error);
        ce::CheatTable table;
        const bool loaded = !error && table.loadAuto(path);
        printf("  save_table writes a loadable .CT: %s\n",
               loaded && table.entries.size() == 1 && table.entries[0].description == "Health" ? "OK" : "FAILED");
        tool(session, "save_table", "{\"path\":\"" + path + "\"}", &error);
        printf("  save_table will not overwrite by default: %s\n", error ? "OK" : "FAILED");
        tool(session, "save_table", "{\"path\":\"/tmp/x.sh\"}", &error);
        printf("  save_table only writes .CT or .json: %s\n", error ? "OK" : "FAILED");
        tool(session, "save_table", "{\"path\":\"/tmp/ce-agent-nul.sh\\u0000.json\",\"overwrite\":true}", &error);
        printf("  save_table refuses a NUL in the path: %s\n",
               error && !std::filesystem::exists("/tmp/ce-agent-nul.sh") ? "OK" : "FAILED");
        // Library loads, threads and file reads would happen for real even in
        // the dry run, so agent scripts may not use them, also when a {comment}
        // splits the name from its arguments or the internal form is written.
        bool refusedAll = true;
        for (const char* directive : {"loadlibrary(/tmp/x.so)", "LoadBinary(0,/etc/passwd)", "include(/etc/passwd)",
                                      "createthread(0)", "CREATETHREADANDWAIT(0)", "loadlibrary{}(/tmp/x.so)",
                                      "include{ x }(/etc/passwd)", "createthread{}(0)", "__LOADLIBRARY__:/tmp/x.so",
                                      "{$ccode}int x;{$endccode}"}) {
            auto checked = tool(session, "aa_check", std::string("{\"script\":\"[ENABLE]\\n") + directive + "\\n[DISABLE]\\n\"}", &error);
            const std::string message = checked.getString("error").value_or("");
            refusedAll = refusedAll && error && message.find("is not allowed") != std::string::npos &&
                         message.find("root:") == std::string::npos;
        }
        printf("  agent scripts cannot load files or start threads: %s\n", refusedAll ? "OK" : "FAILED");
        std::filesystem::remove(path);

        // A pointer record keeps following the pointer, frozen or not.
        char pointerPath[64];
        std::snprintf(pointerPath, sizeof pointerPath, "[0x%lx]+8",
                      static_cast<unsigned long>(reinterpret_cast<uintptr_t>(&g_agentPointer)));
        auto pointerRecord = tool(session, "add_record", std::string("{\"address\":\"") + pointerPath +
                                  "\",\"type\":\"i32\",\"description\":\"Moving value\"}", &error);
        printf("  add_record keeps a pointer path: %s\n",
               !error && pointerRecord.getBool("follows_pointer").value_or(false) ? "OK" : "FAILED");
        tool(session, "set_frozen", "{\"index\":1,\"frozen\":true,\"value\":\"321\"}", &error);
        int32_t* const moved = g_agentObjects[1];
        (void)process.write(reinterpret_cast<uintptr_t>(&g_agentPointer), &moved, sizeof moved);
        usleep(150000);
        int32_t followed = 0;
        (void)process.read(reinterpret_cast<uintptr_t>(&g_agentObjects[1][2]), &followed, sizeof followed);
        printf("  a frozen pointer record follows the pointer: %s (%d)\n", !error && followed == 321 ? "OK" : "FAILED", followed);
        std::filesystem::remove(path);
        tool(session, "save_table", "{\"path\":\"" + path + "\"}", &error);
        ce::CheatTable pointerTable;
        const bool pointerLoaded = !error && pointerTable.loadAuto(path);
        printf("  save_table stores the pointer as base and offsets: %s\n",
               pointerLoaded && pointerTable.entries.size() == 2 && pointerTable.entries[1].offsets == std::vector<int64_t>{8}
                   ? "OK" : "FAILED");
        std::filesystem::remove(path);

        // Unfreezing writes nothing, so it works after the path stops resolving.
        char chainPath[64];
        std::snprintf(chainPath, sizeof chainPath, "[[0x%lx]+0]+0",
                      static_cast<unsigned long>(reinterpret_cast<uintptr_t>(&g_agentChain[0])));
        tool(session, "add_record", std::string("{\"address\":\"") + chainPath + "\",\"type\":\"i32\",\"description\":\"Chain\"}", &error);
        bool chainError = error;
        tool(session, "set_frozen", "{\"index\":2,\"frozen\":true}", &error);
        chainError = chainError || error;
        const uintptr_t unmapped = 0x10;
        (void)process.write(reinterpret_cast<uintptr_t>(&g_agentChain[0]), &unmapped, sizeof unmapped);
        auto unfrozen = tool(session, "set_frozen", "{\"index\":2,\"frozen\":false}", &error);
        printf("  set_frozen false works when the path does not resolve: %s\n",
               !chainError && !error && unfrozen.getBool("frozen") == false ? "OK" : "FAILED");

        // A dry run sees the symbols that enabled scripts registered.
        char mark[32];
        std::snprintf(mark, sizeof mark, "%lx", static_cast<unsigned long>(reinterpret_cast<uintptr_t>(&g_agentObjects[0][3])));
        auto registering = tool(session, "aa_enable", std::string("{\"description\":\"Mark\",\"script\":\"[ENABLE]\\ndefine(agentmark,") +
                                mark + ")\\nregistersymbol(agentmark)\\n[DISABLE]\\nunregistersymbol(agentmark)\\n\"}", &error);
        const bool registerError = error;
        tool(session, "aa_check", "{\"script\":\"[ENABLE]\\nagentmark:\\ndd 9\\n[DISABLE]\\n\"}", &error);
        printf("  aa_check resolves a symbol an enabled script registered: %s\n", !registerError && !error ? "OK" : "FAILED");
        tool(session, "aa_disable", "{\"id\":" + std::to_string(registering.getInt("id").value_or(-1)) + "}", &error);

        // The dry run covers the [DISABLE] section, which aa_disable runs.
        char first[32], second[32];
        std::snprintf(first, sizeof first, "%lx", static_cast<unsigned long>(reinterpret_cast<uintptr_t>(&g_agentObjects[0][0])));
        std::snprintf(second, sizeof second, "%lx", static_cast<unsigned long>(reinterpret_cast<uintptr_t>(&g_agentObjects[0][1])));
        auto brokenDisable = tool(session, "aa_check", std::string("{\"script\":\"[ENABLE]\\n") + first +
                                  ":\\ndd 5\\n[DISABLE]\\n" + first + ":\\nnot_an_instruction\\n\"}", &error);
        printf("  aa_check dry-runs the [DISABLE] section: %s\n",
               error && brokenDisable.getString("error").value_or("").find("[DISABLE]") != std::string::npos ? "OK" : "FAILED");
        {
            // Detaching restores the saved bytes without the user's approval,
            // so it does not run the [DISABLE] section (here a write elsewhere).
            const int32_t before[2] = {11, 22};
            (void)process.write(reinterpret_cast<uintptr_t>(&g_agentObjects[0][0]), before, sizeof before);
            ce::AgentSession scripted(options);
            tool(scripted, "attach", "{\"target\":\"" + pid + "\"}", &error);
            const std::string script = std::string("[ENABLE]\\n") + first + ":\\ndd 5\\n[DISABLE]\\n" + second + ":\\ndd 6\\n";
            tool(scripted, "aa_enable", "{\"description\":\"Five\",\"script\":\"" + script + "\"}", &error);
            const bool enabledError = error;
            int32_t during[2] = {}, after[2] = {};
            (void)process.read(reinterpret_cast<uintptr_t>(&g_agentObjects[0][0]), during, sizeof during);
            const auto stuck = scripted.detach();
            (void)process.read(reinterpret_cast<uintptr_t>(&g_agentObjects[0][0]), after, sizeof after);
            printf("  detach restores saved bytes and skips [DISABLE]: %s (%d %d -> %d %d)\n",
                   !enabledError && stuck.empty() && during[0] == 5 && after[0] == 11 && after[1] == 22 ? "OK" : "FAILED",
                   during[0], during[1], after[0], after[1]);
        }

        // Turning writes off ends every freeze.
        session.setAllowWrites(false);
        auto records = tool(session, "list_records", "{}", &error);
        bool anyFrozen = false;
        if (const auto* list = records.get("records"))
            for (const auto& r : list->arrayValue) anyFrozen = anyFrozen || r.getBool("frozen").value_or(false);
        const int32_t changed = 77;
        (void)process.write(address, &changed, sizeof changed);
        usleep(150000);
        int32_t kept = 0;
        (void)process.read(address, &kept, sizeof kept);
        printf("  turning writes off ends freezes: %s (%d)\n", !error && !anyFrozen && kept == 77 ? "OK" : "FAILED", kept);
        session.setAllowWrites(true);

        // A debugger that cannot attach is an error, not "the instruction did
        // not run": here this test traces the child already.
        uintptr_t accessing = 0;
        {
            const auto code = reinterpret_cast<uintptr_t>(&test_scan_review_fixes);
            uint8_t bytes[256];
            auto arch = ce::disassemblerArchFor(process, code);
            auto got = process.read(code, bytes, sizeof bytes);
            if (arch && got && *got == sizeof bytes)
                for (const auto& insn : ce::Disassembler(*arch).disassemble(code, {bytes, sizeof bytes}, 64))
                    if (insn.memory.present) { accessing = insn.address; break; }
        }
        const bool seized = accessing && ptrace(PTRACE_SEIZE, child, nullptr, nullptr) == 0;
        char accessingHex[32];
        std::snprintf(accessingHex, sizeof accessingHex, "0x%lx", static_cast<unsigned long>(accessing));
        auto attachFailed = tool(session, "find_accessed_addresses",
                                 std::string("{\"address\":\"") + accessingHex + "\",\"seconds\":1}", &error);
        printf("  find_accessed_addresses reports a failed attach: %s\n",
               seized && error && attachFailed.getString("error").value_or("").find("could not watch") != std::string::npos
                   ? "OK" : "FAILED");
    }
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
}

void test_recover_store() {
    printf("\n── Test: Exact store recovery (find-what-writes) ──\n");
    // mov edx,[rax]; add edx,1; mov [rax],edx; mov edi,0x7d0
    //   8b 10 | 83 c2 01 | 89 10 | bf d0 07 00 00
    // A hardware watchpoint traps with rip AT the `mov edi` (offset 7). The writer is
    // the 2-byte `mov [rax],edx` at +5, but the longest decode that also ends at rip
    // starts at +1 (a 6-byte `adc`). Recovery must resolve to +5, not the +1 mis-decode.
    const uintptr_t base = 0x400000;
    std::vector<uint8_t> code = {0x8b,0x10, 0x83,0xc2,0x01, 0x89,0x10, 0xbf,0xd0,0x07,0x00,0x00};
    FakeProcessHandle proc({
        {{base, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, "test"}, code},
    }, {});
    SymbolResolver resolver;
    resolver.addUserSymbol(base, "func");   // enclosing-function anchor
    auto rec = ce::recoverStoreInstruction(proc, resolver, base + 7, /*is64*/true);
    bool ok = rec.ok && rec.address == base + 5
           && rec.text.find("mov") != std::string::npos
           && rec.text.find("[rax]") != std::string::npos;
    printf("  recovers 'mov [rax],edx' at +5 (not the +1 adc): %s (got +0x%lx '%s')\n",
           ok ? "OK" : "FAILED", (unsigned long)(rec.address - base), rec.text.c_str());

    // Empty/zero rip is a no-op (ok=false), so callers keep the original instruction.
    auto none = ce::recoverStoreInstruction(proc, resolver, 0, true);
    printf("  zero rip -> not recovered: %s\n", (!none.ok) ? "OK" : "FAILED");

    // A trap after a branch stops at its target, where the instruction before
    // did not run. caller: call callee (+0); mov [rax],edx (+5); int3 padding
    // up to callee at +0x10: push rbp.
    {
        const uintptr_t fn = 0x500000, stack = 0x7f0000;
        std::vector<uint8_t> text = {0xe8,0x0b,0x00,0x00,0x00, 0x89,0x10};
        text.resize(0x10, 0xcc);
        text.push_back(0x55);
        std::vector<uint8_t> top(16, 0);
        const uint64_t returnAddress = fn + 5;
        std::memcpy(top.data(), &returnAddress, sizeof returnAddress);
        FakeProcessHandle branchy({
            {{fn, text.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, "test"}, text},
            {{stack, top.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, ""}, top},
        }, {});
        SymbolResolver names;
        names.addUserSymbol(fn, "caller");
        CpuContext atCallee{};
        atCallee.architecture = CpuArchitecture::X86_64;
        atCallee.rip = fn + 0x10;   // the call pushed onto a watched stack slot
        atCallee.rsp = stack;
        auto padding = ce::recoverStoreInstruction(branchy, names, fn + 0x10, true);
        auto viaCall = ce::recoverHardwareAccess(branchy, names, atCallee);
        printf("  trap at a call target names the call, not the padding: %s (got +0x%lx '%s')\n",
               !padding.ok && viaCall.ok && viaCall.address == fn ? "OK" : "FAILED",
               (unsigned long)(viaCall.address - fn), viaCall.text.c_str());

        CpuContext afterReturn = atCallee;
        afterReturn.rip = fn + 5;      // a ret read a watched return address
        afterReturn.rsp = stack + 8;   // no call's return address on top
        auto viaRet = ce::recoverHardwareAccess(branchy, names, afterReturn);
        printf("  trap after a return is labelled, not blamed on the call: %s\n",
               !viaRet.ok && viaRet.branched && !ce::recoverStoreInstruction(branchy, names, fn + 5, true).ok
                   ? "OK" : "FAILED");

        CpuContext afterStore = atCallee;
        afterStore.rip = fn + 7;       // an ordinary store falls through
        auto store = ce::recoverHardwareAccess(branchy, names, afterStore);
        printf("  a store that falls through is kept: %s\n",
               store.ok && !store.branched && store.address == fn + 5 ? "OK" : "FAILED");
    }

    // Disassembler::setArch re-opens the decoder for a different architecture (used by
    // the CodeFinder/Tracer members once the target's bitness is known).
    ce::Disassembler d(ce::Arch::X86_64);
    d.setArch(ce::Arch::ARM64);
    const uint8_t arm[] = {0x20, 0x00, 0x80, 0xd2};   // movz x0, #1
    auto ai = d.disassemble(0x1000, {arm, sizeof(arm)}, 1);
    // Capstone >= 5 aliases "movz x0, #1" to "mov x0, #1"; Capstone 4 prints
    // "movz". Accept either so the fallback (pinned Capstone 5.0.1) and a system
    // Capstone 4 both pass. The arch() check below still distinguishes ARM64.
    bool armOk = !ai.empty() && (ai[0].mnemonic == "movz" || ai[0].mnemonic == "mov") &&
                 d.arch() == ce::Arch::ARM64;
    d.setArch(ce::Arch::X86_32);
    const uint8_t x86[] = {0xb8, 0x01, 0x00, 0x00, 0x00};   // mov eax, 1
    auto xi = d.disassemble(0x1000, {x86, sizeof(x86)}, 1);
    bool x86Ok = !xi.empty() && xi[0].mnemonic == "mov" && d.arch() == ce::Arch::X86_32;
    printf("  Disassembler::setArch re-opens (arm64 movz, then x86-32 mov): %s\n",
           (armOk && x86Ok) ? "OK" : "FAILED");
}

void test_value_codec() {
    printf("\n── Test: Value codecs (obfuscated values) ──\n");
    using C = ce::ValueCodec;

    // encode is the inverse of decode across every op and width.
    bool roundtrip = true;
    const uint64_t samples[] = {0, 1, 100, 1000, 0x7fff, 0xdead, 123456789ull, 0xffffffffull};
    struct { C::Op op; uint64_t key; } cases[] = {
        {C::Op::Xor, 0xDEADBEEFull}, {C::Op::Add, 100}, {C::Op::Add, 0xFFFF},
        {C::Op::Rol, 3}, {C::Op::Ror, 5}, {C::Op::Xor, 0xA5}, {C::Op::Rol, 13},
    };
    for (int bytes : {1, 2, 4, 8})
        for (auto& c : cases) {
            C codec{c.op, c.key};
            for (uint64_t s : samples) {
                uint64_t masked = s & C::maskFor(bytes);
                if (codec.decode(codec.encode(masked, bytes), bytes) != masked) roundtrip = false;
            }
        }
    printf("  encode/decode round-trip (all ops, widths 1/2/4/8): %s\n", roundtrip ? "OK" : "FAILED");

    // Concrete: money = 1000 stored as 1000 xor 0xDEADBEEF (i32). Scanning by 1000
    // means searching for the encoded needle; reading it back decodes to 1000.
    C x{C::Op::Xor, 0xDEADBEEFull};
    uint32_t stored = (uint32_t)x.encode(1000, 4);
    bool xorOk = stored == (uint32_t)(1000u ^ 0xDEADBEEFu) && x.decode(stored, 4) == 1000;
    printf("  xor i32 (1000 <-> stored 0x%x): %s\n", stored, xorOk ? "OK" : "FAILED");

    // ADD wraps within the type width (byte): 200 add 100 = 300 & 0xFF = 44.
    C add{C::Op::Add, 100};
    bool addWrap = add.encode(200, 1) == 44 && add.decode(44, 1) == 200;
    printf("  add byte wraparound (200 add 100 = 44): %s\n", addWrap ? "OK" : "FAILED");

    // ROL is width-local: rol 4 of 0x12 as a byte = 0x21, not smeared into 16 bits.
    C rol{C::Op::Rol, 4};
    bool rolOk = rol.encode(0x12, 1) == 0x21 && rol.decode(0x21, 1) == 0x12;
    printf("  rol byte width-local (0x12 rol 4 = 0x21): %s\n", rolOk ? "OK" : "FAILED");

    // Parsing: valid specs, and malformed ones rejected.
    auto pv = C::parse("xor:0xFF"); auto pa = C::parse("add:12");
    bool parseOk = pv && pv->op == C::Op::Xor && pv->key == 0xFF
                && pa && pa->op == C::Op::Add && pa->key == 12
                && !C::parse("xor") && !C::parse("bogus:1") && !C::parse("add:") && !C::parse("add:xyz");
    printf("  parse valid + reject malformed: %s\n", parseOk ? "OK" : "FAILED");

    // describe() -> parse() round-trips for every active codec. The GUI persists codecs
    // as their describe() spec string and reloads them via parse(), so this must hold.
    bool descRt = true;
    for (auto& c : cases) {
        C codec{c.op, c.key};
        auto back = C::parse(codec.describe());
        if (!back || back->op != codec.op || back->key != codec.key) descRt = false;
    }
    printf("  describe/parse round-trip (persistence): %s\n", descRt ? "OK" : "FAILED");
}

void test_value_transform() {
    printf("\n── Test: Scalar value transform (endianness + codec) ──\n");
    using ce::ValueType;
    using ce::ValueCodec;
    const ValueCodec none;
    const ValueCodec xr{ValueCodec::Op::Xor, 0xDEADBEEFull};

    // Round-trip: decode(encode(v)) == v for every combination of endianness and codec.
    bool rt = true;
    const uint64_t vals[] = {0, 1, 100, 1000, 0x7fffffffull, 0xdeadbeefull};
    for (auto type : {ValueType::Byte, ValueType::Int16, ValueType::Int32, ValueType::Int64})
        for (bool be : {false, true})
            for (const auto* codec : {&none, &xr}) {
                const int w = ce::scalarWidth(type);
                for (uint64_t v : vals) {
                    uint64_t masked = v & ce::ValueCodec::maskFor(w);
                    uint8_t stored[8] = {};
                    ce::encodeScalarBits(type, masked, be, *codec, stored);
                    if (ce::decodeScalarBits(type, stored, be, *codec) != masked) rt = false;
                }
            }
    printf("  decode(encode(v)) round-trips (all types/endian/codec): %s\n", rt ? "OK" : "FAILED");

    // Big-endian layout: i32 1000 stored big-endian is 00 00 03 e8.
    uint8_t be32[4] = {};
    ce::encodeScalarBits(ValueType::Int32, 1000, /*bigEndian*/true, none, be32);
    bool beOk = be32[0] == 0x00 && be32[1] == 0x00 && be32[2] == 0x03 && be32[3] == 0xe8
             && ce::decodeScalarBits(ValueType::Int32, be32, true, none) == 1000;
    printf("  big-endian i32 1000 = 00 00 03 e8: %s\n", beOk ? "OK" : "FAILED");

    // Codec wraps endianness: logical 1000 with xor, stored big-endian, decodes back.
    uint8_t bx[4] = {};
    ce::encodeScalarBits(ValueType::Int32, 1000, true, xr, bx);
    bool bxOk = ce::decodeScalarBits(ValueType::Int32, bx, true, xr) == 1000
             && ce::decodeScalarBits(ValueType::Int32, bx, true, none) != 1000;  // still encoded w/o codec
    printf("  big-endian + xor codec composes: %s\n", bxOk ? "OK" : "FAILED");

    // The codec never touches float/pointer; big-endian still byte-swaps them.
    uint8_t f[4] = {};
    float pi = 3.5f; memcpy(f, &pi, 4);
    uint64_t decoded = ce::decodeScalarBits(ValueType::Float, f, false, xr);  // codec ignored for float
    float back; memcpy(&back, &decoded, 4);
    printf("  codec skipped for float: %s\n", (back == pi) ? "OK" : "FAILED");

    // formatIntegerScalar: the CE ShowAsSigned flag decides signed vs unsigned decimal;
    // hex always shows the width-masked unsigned value.
    bool fmtOk =
        ce::formatIntegerScalar(200, 1, /*signed*/true,  false) == "-56"  &&
        ce::formatIntegerScalar(200, 1, /*signed*/false, false) == "200"  &&
        ce::formatIntegerScalar(0xFFFFFFFFull, 4, true,  false) == "-1"    &&
        ce::formatIntegerScalar(0xFFFFFFFFull, 4, false, false) == "4294967295" &&
        ce::formatIntegerScalar(0xFFFFull, 2, true, false) == "-1"         &&
        ce::formatIntegerScalar(0x1Full, 1, true, /*hex*/true) == "0x1f"   &&
        ce::formatIntegerScalar(0xFFFFFFFFull, 4, false, /*hex*/true) == "0xffffffff";
    printf("  formatIntegerScalar signed/unsigned/hex: %s\n", fmtOk ? "OK" : "FAILED");

    // parseIntegerScalar (the input side): in hex-display mode a bare token is hex; a
    // "0x" prefix is always hex; signs and decimal work; junk sets ok=false.
    bool pok = false;
    auto pv = [&pok](const char* s, bool hex) { return ce::parseIntegerScalar(s, hex, pok); };
    bool parseOk =
        (pv("1a", true) == 26 && pok) &&                 // bare hex in hex mode
        (pv("26", false) == 26 && pok) &&                // decimal in decimal mode
        (pv("0x1a", false) == 26 && pok) &&              // 0x forces hex even in decimal mode
        (pv("-56", false) == -56 && pok) &&              // signed decimal
        (uint8_t)pv("-56", false) == 200 &&              // ...casts to the byte the user meant
        (pv("ff", true) == 255 && pok);
    (void)pv("1a", false); bool rejectDecimal = !pok;    // "1a" is junk in decimal mode
    (void)pv("xyz", true); bool rejectJunk = !pok;
    printf("  parseIntegerScalar hex/decimal/signed: %s\n",
           (parseOk && rejectDecimal && rejectJunk) ? "OK" : "FAILED");

    // Round-trip: format(bits) -> string -> parse -> the same width-masked bytes, for the
    // signed and unsigned display and hex and decimal input. This ties the two halves of
    // the value pipeline together (the source of several fixed hex/signed bugs).
    bool rtInt = true;
    for (int w : {1, 2, 4, 8}) {
        uint64_t mask = (w >= 8) ? ~0ull : ((1ull << (w * 8)) - 1);
        const uint64_t samples[] = {0, 1, 127, 128, 200, 255, 0x7fff, 0x8000,
                                    0xdeadbeefu, 0x80000000u, 0xffffffffu, ~0ull};
        for (uint64_t raw : samples) {
            uint64_t bits = raw & mask;
            for (bool sgn : {false, true})
                for (bool hex : {false, true}) {
                    std::string s = ce::formatIntegerScalar(bits, w, sgn, hex);
                    bool ok = false;
                    int64_t v = ce::parseIntegerScalar(s, hex, ok);
                    if (!ok || (static_cast<uint64_t>(v) & mask) != bits) rtInt = false;
                }
        }
    }
    printf("  format<->parse integer round-trip (all widths/signs/bases): %s\n",
           rtInt ? "OK" : "FAILED");

    // Canonical type names match CE's wording (and the Change-address dialog), so the
    // Type column no longer says "Text"/"Array of Bytes" while the dialog says "String".
    bool nameOk =
        std::string(ce::valueTypeName(ValueType::Int32)) == "4 Bytes" &&
        std::string(ce::valueTypeName(ValueType::String)) == "String" &&
        std::string(ce::valueTypeName(ValueType::UnicodeString)) == "Unicode String" &&
        std::string(ce::valueTypeName(ValueType::ByteArray)) == "Array of byte";
    printf("  valueTypeName matches CE wording: %s\n", nameOk ? "OK" : "FAILED");

    // formatFloatScalar trims trailing zeros (CE), so a round float reads cleanly.
    bool floatFmtOk =
        ce::formatFloatScalar(100.0, false) == "100" &&
        ce::formatFloatScalar(99.5, false) == "99.5" &&
        ce::formatFloatScalar(0.0, true) == "0" &&
        ce::formatFloatScalar(-2.5, true) == "-2.5" &&
        ce::formatFloatScalar(std::nan(""), false) == "nan";
    printf("  formatFloatScalar trims trailing zeros: %s\n", floatFmtOk ? "OK" : "FAILED");
}

void test_ns_attach() {
    printf("\n── Test: Namespace-aware path resolution ──\n");
    const pid_t self = getpid();

    // Non-absolute pseudo-paths and empty are passed through untouched.
    bool passthrough = ce::resolveProcPath(self, "[heap]") == "[heap]"
                    && ce::resolveProcPath(self, "") == ""
                    && ce::resolveProcPath(self, "[stack]") == "[stack]";
    printf("  non-file paths passthrough: %s\n", passthrough ? "OK" : "FAILED");

    // The identical backing file is returned as-is for a normal process.
    bool hostPath = ce::resolveProcPath(self, "/proc/self/status") == "/proc/self/status";
    printf("  existing host path unchanged: %s\n", hostPath ? "OK" : "FAILED");

    // Missing target files remain scoped to the target, preventing host fallback.
    bool missing = ce::resolveProcPath(self, "/no/such/file/xyzzy") ==
        "/proc/"+std::to_string(self)+"/root/no/such/file/xyzzy";
    printf("  missing path stays target-scoped: %s\n", missing ? "OK" : "FAILED");
    bool inaccessible=ce::resolveProcPath(-1,"/proc/self/status")=="/proc/-1/root/proc/self/status";
    printf("  inaccessible target never uses an existing host file: %s\n",inaccessible ? "OK" : "FAILED");

    // We are not sandboxed, so the inner-namespace pid is our own and we report as
    // not namespaced.
    bool nsSelf = ce::nsInnerPid(self) == self && !ce::isPidNamespaced(self);
    printf("  self not namespaced: %s\n", nsSelf ? "OK" : "FAILED");

    // processDescendants: fork a child that waits, and confirm it shows up as our
    // descendant (the multi-process discovery primitive).
    pid_t child = fork();
    if (child == 0) { pause(); _exit(0); }   // child: block until killed
    bool found = false;
    for (int i = 0; i < 200 && !found; ++i) {
        auto d = ce::processDescendants(self);
        found = std::find(d.begin(), d.end(), child) != d.end();
        if (!found) usleep(500);
    }
    printf("  forked child seen as a descendant: %s\n", found ? "OK" : "FAILED");
    kill(child, SIGKILL);
    int status = 0; waitpid(child, &status, 0);
}

void test_dolphin_guest_ram() {
    printf("\n── Test: Dolphin guest-RAM adapter ──\n");
    const size_t MEM1 = 24u << 20, MEM2 = 64u << 20;
    // Child poses as Dolphin: a /dev/shm/dolphin-emu shm holding MEM1+MEM2, each mapped
    // twice (cached/uncached mirrors), plus an unrelated 32 MB anon region. The adapter
    // must return exactly the two DISTINCT shm regions (mirrors collapsed by offset) and
    // exclude the anon.
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_NAME, "dolphin-emu", 0, 0, 0);
        shm_unlink("/dolphin-emu-cetest");
        int fd = shm_open("/dolphin-emu-cetest", O_CREAT | O_RDWR, 0600);
        if (fd < 0 || ftruncate(fd, MEM1 + MEM2)) _exit(1);
        mmap(nullptr, MEM1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        mmap(nullptr, MEM1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        mmap(nullptr, MEM2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MEM1);
        mmap(nullptr, MEM2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MEM1);
        mmap(nullptr, 32u << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        for (;;) pause();
    }
    bool ok = false;
    for (int i = 0; i < 300 && !ok; ++i) {
        auto prof = ce::probeTarget(child);
        if (prof.emulator == "Dolphin" && prof.guestCandidates.size() == 2 &&
            prof.guestCandidates[0].size == MEM2 && prof.guestCandidates[1].size == MEM1 &&
            prof.guestCandidates[0].guestBase == 0x90000000u &&   // MEM2 console base
            prof.guestCandidates[1].guestBase == 0x80000000u)     // MEM1 console base
            ok = true;
        if (!ok) usleep(1000);
    }
    printf("  MEM1+MEM2 deduped from mirrors, anon excluded: %s\n", ok ? "OK" : "FAILED");
    kill(child, SIGKILL);
    int st = 0; waitpid(child, &st, 0);
    shm_unlink("/dolphin-emu-cetest");
}

void test_yuzu_guest_ram() {
    printf("\n── Test: yuzu/Citra guest-RAM adapter ──\n");
    // The yuzu/Citra family (suyu, sudachi, citron, Lime3DS, Azahar) backs guest RAM with
    // a memfd_create("HostMemory") mapped MAP_FIXED into a large virtual reservation, with
    // fastmem mirrors. In /proc/pid/maps that shows as "/memfd:HostMemory (deleted)". The
    // child poses as yuzu: a HostMemory memfd holding two guest regions, each mapped twice
    // (mirrors), plus an unrelated 32 MB anon region. Switch/3DS are little-endian with no
    // fixed console base, so the adapter must return the two DISTINCT regions (mirrors
    // collapsed by offset), guestBase 0, and exclude the anon.
    const size_t RA = 32u << 20, RB = 48u << 20;
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_NAME, "yuzu", 0, 0, 0);
        int fd = static_cast<int>(syscall(SYS_memfd_create, "HostMemory", 0u));
        if (fd < 0 || ftruncate(fd, RA + RB)) _exit(1);
        mmap(nullptr, RA, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        mmap(nullptr, RA, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        mmap(nullptr, RB, PROT_READ | PROT_WRITE, MAP_SHARED, fd, RA);
        mmap(nullptr, RB, PROT_READ | PROT_WRITE, MAP_SHARED, fd, RA);
        mmap(nullptr, 32u << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        for (;;) pause();
    }
    bool ok = false, memfdUnsupported = false;
    for (int i = 0; i < 300 && !ok; ++i) {
        auto prof = ce::probeTarget(child);
        if (prof.emulator == "yuzu" && prof.guestCandidates.size() == 2 &&
            prof.guestCandidates[0].size == RB && prof.guestCandidates[1].size == RA &&
            prof.guestCandidates[0].fileBacked && prof.guestCandidates[1].fileBacked &&
            prof.guestCandidates[0].guestBase == 0 && prof.guestCandidates[1].guestBase == 0)
            ok = true;
        // Detect a dead child early (e.g. SYS_memfd_create absent on an ancient kernel):
        // don't fail the suite for a missing kernel feature, just note it.
        if (!ok) { int s = 0; if (waitpid(child, &s, WNOHANG) == child) { memfdUnsupported = true; break; } usleep(1000); }
    }
    if (memfdUnsupported)
        printf("  HostMemory memfd (skipped: memfd_create unsupported here)\n");
    else
        printf("  HostMemory regions deduped from mirrors, anon excluded, guestBase 0: %s\n",
               ok ? "OK" : "FAILED");
    kill(child, SIGKILL);
    int st = 0; waitpid(child, &st, 0);
}

void test_rpcs3_mirror_dedup() {
    printf("\n── Test: RPCS3-style mirror dedup (generic path, by inode) ──\n");
#ifdef __SANITIZE_ADDRESS__
    // Skipped under ASan: this forks a child and has probeTarget introspect
    // /proc/<child>/maps. ASan gives the forked child a ~20 TB shadow reservation
    // plus extra allocator arenas that pollute the unnamed-memfd inode/anon heuristic,
    // so the guest-candidate counts come out unreliable. The normal (uninstrumented)
    // build job exercises the real path; the product code (inode-based mirror dedup)
    // is proven correct there. Named-memfd detection (test_yuzu_guest_ram) keys on the
    // name and is unaffected, so only this inode-keyed case needs the guard.
    printf("  (skipped under ASan: forked child's maps polluted by shadow/arenas)\n");
    return;
#endif
    // RPCS3 backs PS3 guest RAM with UNNAMED memfds (memfd_create("") / "2M"), mapped at
    // both g_base_addr and a g_sudo write-mirror -- one backing object, two virtual
    // addresses. With no named shm marker the generic path can't key on the name, so it
    // must collapse the mirror by the backing object's INODE. A distinct second memfd and
    // an anonymous arena (inode 0) must survive as separate regions. Sizes are odd so they
    // can't collide with any incidental region the forked child inherits.
    const size_t A = 33u << 20, B = 50u << 20;
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_NAME, "rpcs3", 0, 0, 0);
        int fa = static_cast<int>(syscall(SYS_memfd_create, "", 0u));   // unnamed, like RPCS3
        int fb = static_cast<int>(syscall(SYS_memfd_create, "", 0u));   // distinct object
        if (fa < 0 || fb < 0 || ftruncate(fa, A) || ftruncate(fb, B)) _exit(1);
        mmap(nullptr, A, PROT_READ | PROT_WRITE, MAP_SHARED, fa, 0);   // g_base view
        mmap(nullptr, A, PROT_READ | PROT_WRITE, MAP_SHARED, fa, 0);   // g_sudo mirror
        mmap(nullptr, B, PROT_READ | PROT_WRITE, MAP_SHARED, fb, 0);
        mmap(nullptr, 17u << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        for (;;) pause();
    }
    bool ok = false, unsupported = false;
    for (int i = 0; i < 300 && !ok; ++i) {
        auto prof = ce::probeTarget(child);
        if (prof.emulator == "RPCS3") {
            int nA = 0, nB = 0;
            for (const auto& g : prof.guestCandidates) { if (g.size == A) nA++; if (g.size == B) nB++; }
            // memfd A's two mirror views collapse to exactly one; distinct memfd B survives.
            if (nA == 1 && nB == 1) ok = true;
        }
        if (!ok) { int s = 0; if (waitpid(child, &s, WNOHANG) == child) { unsupported = true; break; } usleep(1000); }
    }
    if (unsupported)
        printf("  (skipped: memfd_create unsupported here)\n");
    else
        printf("  unnamed-memfd mirror collapsed by inode, distinct memfd kept: %s\n",
               ok ? "OK" : "FAILED");
    kill(child, SIGKILL);
    int st = 0; waitpid(child, &st, 0);
}

void test_parser_fuzz() {
    printf("\n── Test: untrusted-parser negative-input / mutation fuzz ──\n");
    // .CT/.CETRAINER tables and a target's ELF/PE modules are loaded from untrusted
    // sources (downloaded tables, the game's own binaries), so the hand-rolled parsers
    // must never crash on malformed input (AGENTS.md: treat these as untrusted,
    // bounds-checked). This is a deterministic, seeded mutation fuzz plus a hand-picked
    // pathological corpus; reaching the end without a SIGSEGV/abort is the pass, and
    // under the CI sanitizers (ASan/UBSan) job it additionally gates memory safety.
    // (Also validated out-of-band with 400k .CT + 300k ELF ASan/UBSan iterations
    //  incl. loadAuto/loadJson; this is the fast CI-friendly distillation of that.)
    uint64_t rs = 0x123456789abcdef0ull;
    auto rnd = [&]() -> uint32_t { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)(rs >> 32); };
    auto mutate = [&](std::string m) -> std::string {
        int n = 1 + rnd() % 12;
        for (int k = 0; k < n && !m.empty(); ++k) {
            switch (rnd() % 6) {
                case 0: m[rnd() % m.size()] = (char)(rnd() & 0xff); break;                       // byte flip
                case 1: m.erase(rnd() % m.size(), 1 + rnd() % 7); break;                         // delete run
                case 2: m.insert(rnd() % m.size(), std::string(1 + rnd() % 8, (char)(rnd() & 0xff))); break;
                case 3: m.resize(rnd() % (m.size() + 1)); break;                                 // truncate
                case 4: { static const char* big[] = {"999999999999", "-1", "0x7fffffffffffffff", "4294967296"};
                          m.insert(rnd() % m.size(), big[rnd() % 4]); break; }                   // huge count/offset
                case 5: if (m.size() >= 8) { size_t a = rnd() % (m.size() - 7); uint64_t v = ~0ull >> (8 * (rnd() % 8));
                          for (int b = 0; b < 8; ++b) m[a + b] = (char)(v >> (8 * b)); } break;  // smash a 64-bit field
            }
        }
        return m;
    };

    // --- .CT XML parser (loadFromString): pathological corpus + mutation fuzz ---
    static const char* kEvil[] = {
        "", "<", "<CheatTable", "<CheatTable>", "<CheatEntries>", "<CheatEntries",
        "<CheatTable><CheatEntries>", "<CheatEntries></CheatEntries>",
        "<CheatTable><CheatEntries><CheatEntry>",
        "<CheatEntries><CheatEntry><Offsets><Offset>",
        "<CheatEntries><CheatEntry><Address>game.exe+",
        "<CheatTable><Structures><Structure><Elements><Element Offset=\"",
        "<CheatEntries><CheatEntry><VariableType>String</VariableType><Length>999999999999</Length></CheatEntry></CheatEntries>",
        "<CheatEntries><CheatEntry><Description>\"</Description></CheatEntry></CheatEntries>",
    };
    for (const char* e : kEvil) { CheatTable t; t.loadFromString(e); }
    const std::string ctSeed =
        "<?xml version=\"1.0\"?><CheatTable><CheatEntries>"
        "<CheatEntry><ID>1</ID><Description>\"H\"</Description><VariableType>4 Bytes</VariableType>"
        "<Address>game.exe+1C</Address><Offsets><Offset>10</Offset><Offset>8</Offset></Offsets></CheatEntry>"
        "<CheatEntry><ID>2</ID><Description>\"S\"</Description><VariableType>String</VariableType>"
        "<Length>16</Length><Address>00401000</Address></CheatEntry>"
        "</CheatEntries><LuaScript>print(1)</LuaScript></CheatTable>";
    for (int i = 0; i < 6000; ++i) { CheatTable t; t.loadFromString(mutate(ctSeed)); }
    printf("  .CT XML parser: %zu pathological + 6000 mutations, no crash: OK\n",
           sizeof(kEvil) / sizeof(kEvil[0]));

    // --- ELF module parser (loadModule): seed from our own binary, corrupt + truncate ---
    std::ifstream exeIn("/proc/self/exe", std::ios::binary);
    std::string exe((std::istreambuf_iterator<char>(exeIn)), std::istreambuf_iterator<char>());
    if (!exe.empty()) {
        auto tmp = std::filesystem::temp_directory_path() / "ce_fuzz_elf.tmp";
        auto feed = [&](const std::string& bytes) {
            { std::ofstream o(tmp, std::ios::binary); o.write(bytes.data(), (std::streamsize)bytes.size()); }
            SymbolResolver r; r.loadModule(tmp.string(), "m", 0x400000);
        };
        // Truncations at boundary lengths (empty / partial header / partway / full).
        size_t lens[] = {0, 1, 4, 15, 16, 52, 63, 64, 120, 4096, exe.size() / 4, exe.size() / 2};
        for (size_t len : lens) feed(exe.substr(0, len > exe.size() ? exe.size() : len));
        // Structural mutations of a bounded prefix (keeps the per-iteration file small).
        std::string prefix = exe.substr(0, exe.size() < (64u << 10) ? exe.size() : (64u << 10));
        for (int i = 0; i < 1500; ++i) feed(mutate(prefix));
        std::error_code ec; std::filesystem::remove(tmp, ec);
        printf("  ELF module parser: %zu truncations + 1500 mutations, no crash: OK\n",
               sizeof(lens) / sizeof(lens[0]));
    } else {
        printf("  ELF module parser: (skipped: /proc/self/exe unreadable)\n");
    }
}

void test_target_profile() {
    printf("\n── Test: Target capability probe ──\n");
    // Probe ourselves: a valid x86-64 native process, not Wine, not an emulator,
    // and (normally) not traced by anyone else.
    auto self = ce::probeTarget(getpid());
    bool selfOk = self.valid
        && self.arch == ce::TargetProfile::Arch::X86_64
        && self.endianness == ce::TargetProfile::Endian::Little
        && !self.wine && self.emulator.empty()
        && !self.pidNamespaced && self.nsInnerPid == getpid()   // not sandboxed
        && self.guestCandidates.empty();   // only emulator targets get these
    printf("  probe self: %s (%s)\n", selfOk ? "OK" : "FAILED", self.summary().c_str());

    // A bogus pid probes as invalid with no notes.
    auto bad = ce::probeTarget(999999);
    printf("  probe bogus pid: %s\n",
           (!bad.valid && bad.notes.empty()) ? "OK" : "FAILED");

    // archName()/summary() are always non-empty for a valid target.
    printf("  arch/summary strings: %s\n",
           (!self.archName().empty() && !self.summary().empty()) ? "OK" : "FAILED");
}

void test_eflags_decode() {
    printf("\n── Test: EFLAGS decode ──\n");
    // Standard x86 status/control flag bits, decoded for the debugger's flags display.
    bool a = ce::describeEflags(0x246) == "PF ZF IF";   // typical "result was zero" flags
    bool b = ce::describeEflags(0x1)   == "CF";
    bool c = ce::describeEflags(0x0)   == "";
    bool d = ce::describeEflags(0xC0)  == "ZF SF";      // 0x40 | 0x80
    bool e = ce::describeEflags(0x8D5) == "CF PF AF ZF SF OF";
    printf("  0x246 -> \"PF ZF IF\": %s\n", a ? "OK" : "FAILED");
    printf("  0x1   -> \"CF\":       %s\n", b ? "OK" : "FAILED");
    printf("  0x0   -> \"\":         %s\n", c ? "OK" : "FAILED");
    printf("  0xC0  -> \"ZF SF\":    %s\n", d ? "OK" : "FAILED");
    printf("  0x8D5 -> full set:    %s\n", e ? "OK" : "FAILED");
}

void test_guest_view() {
    printf("\n── Test: Emulator guest view (endianness) ──\n");
    bool bs = ce::bswap32(0x12345678u) == 0x78563412u
           && ce::bswap16(0x1234) == 0x3412
           && ce::bswap64(0x1122334455667788ull) == 0x8877665544332211ull;
    printf("  byteswap primitives: %s\n", bs ? "OK" : "FAILED");

    // A guest view over our own memory (self process), guest = big-endian.
    uint8_t buffer[64] = {0};
    ce::os::LinuxProcessHandle self(getpid());
    ce::GuestView gv{ &self, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer), /*bigEndian=*/true };

    bool wrote = gv.write<uint32_t>(4, 0x11223344u);
    // The host bytes must be laid out big-endian: 11 22 33 44.
    bool rawOk = wrote && buffer[4] == 0x11 && buffer[5] == 0x22
              && buffer[6] == 0x33 && buffer[7] == 0x44;
    printf("  big-endian write layout: %s\n", rawOk ? "OK" : "FAILED");

    auto back = gv.read<uint32_t>(4);
    printf("  read-back round trip: %s\n", (back && *back == 0x11223344u) ? "OK" : "FAILED");

    // A read-only shared mapping of a regular file (an asset pack, an SQLite
    // database): a write that the page refuses must fail, never go through to
    // the file on disk.
    {
        const auto dataPath = std::filesystem::read_symlink("/proc/self/exe").parent_path() /
            ("cecore-shared-ro-" + std::to_string(getpid()) + ".bin");
        { std::ofstream out(dataPath, std::ios::binary); out << std::string(4096, 'A'); }
        int ready[2]; bool piped = ::pipe(ready) == 0;
        pid_t child = piped ? fork() : -1;
        if (child == 0) {
            int fd = ::open(dataPath.c_str(), O_RDONLY | O_CLOEXEC);
            void* view = fd >= 0 ? ::mmap(nullptr, 4096, PROT_READ, MAP_SHARED, fd, 0) : MAP_FAILED;
            uintptr_t at = view == MAP_FAILED ? 0 : reinterpret_cast<uintptr_t>(view);
            (void)!::write(ready[1], &at, sizeof(at));
            for (;;) pause();
        }
        uintptr_t at = 0;
        if (child > 0) (void)!::read(ready[0], &at, sizeof(at));
        bool refused = false;
        if (at) {
            ce::os::LinuxProcessHandle target(child);
            const char patch[4] = {'B', 'B', 'B', 'B'};
            auto w = target.write(at, patch, sizeof(patch));
            refused = !w || *w != sizeof(patch);
        }
        if (child > 0) { kill(child, SIGKILL); waitpid(child, nullptr, 0); }
        if (piped) { ::close(ready[0]); ::close(ready[1]); }
        std::ifstream in(dataPath, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), {});
        std::filesystem::remove(dataPath);
        printf("  a read-only shared file mapping is never written through to disk: %s\n",
               at && refused && content == std::string(4096, 'A') ? "OK" : "FAILED");
    }

    // A zero-initialised global past the executable's last file page lives in
    // an anonymous mapping; it is still part of the module (pointer-scan statics).
    {
        static volatile char bssProbe[1 << 16];
        bssProbe[sizeof(bssProbe) - 1] = 1;
        const auto probe = reinterpret_cast<uintptr_t>(&bssProbe[sizeof(bssProbe) - 1]);
        bool inside = false;
        for (const auto& m : self.modules())
            if (m.path.find("cecore_test") != std::string::npos && probe >= m.base && probe - m.base < m.size) inside = true;
        printf("  an executable's .bss counts as part of its module: %s\n", inside ? "OK" : "FAILED");
    }

    // Our own executable also mapped as data (a game reading its binary): the
    // module keeps the loaded image's base and extent, and appears once.
    {
        const int exeFd = ::open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
        void* view = exeFd >= 0 ? ::mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, exeFd, 0) : MAP_FAILED;
        const auto code = reinterpret_cast<uintptr_t>(&ce::bswap64);
        int images = 0;
        bool containsCode = false, viewIsModule = false;
        for (const auto& m : self.modules()) {
            if (code >= m.base && code - m.base < m.size) containsCode = m.size < (size_t(1) << 30);
            if (view != MAP_FAILED && reinterpret_cast<uintptr_t>(view) >= m.base &&
                reinterpret_cast<uintptr_t>(view) - m.base < m.size && m.path.find("cecore_test") != std::string::npos)
                viewIsModule = true;
            if (m.path.find("cecore_test") != std::string::npos) ++images;
        }
        printf("  a data view of the executable is not its module: %s\n",
               view != MAP_FAILED && containsCode && images == 1 && !viewIsModule ? "OK" : "FAILED");
        if (view != MAP_FAILED) ::munmap(view, 4096);
        if (exeFd >= 0) ::close(exeFd);
    }

    // Bounds: a read that runs off the end of the region fails, and toHost maps right.
    bool bounds = !gv.read<uint32_t>(62).has_value()
               && gv.toHost(8) == reinterpret_cast<uintptr_t>(buffer) + 8;
    printf("  bounds + address translation: %s\n", bounds ? "OK" : "FAILED");

    // Exact scan: place the same big-endian value at two aligned offsets, plus a
    // decoy at an unaligned one, and confirm the scan finds exactly the aligned two.
    uint8_t ram[256] = {0};
    ce::GuestView be{ &self, reinterpret_cast<uintptr_t>(ram), sizeof(ram), /*bigEndian=*/true };
    be.write<uint32_t>(0x10, 0xCAFEBABEu);
    be.write<uint32_t>(0x40, 0xCAFEBABEu);
    be.writeBytes(0x51, "\xCA\xFE\xBA\xBE", 4);           // unaligned decoy (offset 0x51)
    auto hits = ce::guestScanExact<uint32_t>(be, 0xCAFEBABEu, /*alignment=*/4);
    bool scanOk = hits.size() == 2 && hits[0] == 0x10 && hits[1] == 0x40;
    // Same value scanned little-endian should NOT match the big-endian bytes.
    ce::GuestView le = be; le.bigEndian = false;
    bool leOk = ce::guestScanExact<uint32_t>(le, 0xCAFEBABEu, 4).empty();
    printf("  exact guest scan (aligned, BE): %s\n", scanOk ? "OK" : "FAILED");
    printf("  endianness affects matches: %s\n", leOk ? "OK" : "FAILED");

    // Next scan: change one of the two matches, then narrow. Only the unchanged one
    // (0x40) still equals the value.
    be.write<uint32_t>(0x10, 0x00000001u);   // 0x10 no longer 0xCAFEBABE
    auto narrowed = ce::guestNextExact<uint32_t>(be, hits, 0xCAFEBABEu);
    bool nextOk = narrowed.size() == 1 && narrowed[0] == 0x40;
    printf("  guest next-scan narrows: %s\n", nextOk ? "OK" : "FAILED");

    // Comparison next-scan: two candidates (0x60=10, 0x64=20); bump one, drop the
    // other, then keep by increased / decreased.
    std::vector<std::pair<uint64_t, int32_t>> cand = {{0x60, 10}, {0x64, 20}};
    be.write<int32_t>(0x60, 15);   // increased
    be.write<int32_t>(0x64, 5);    // decreased
    auto inc = ce::guestNextCompare<int32_t>(be, cand, ce::GuestCompare::Increased);
    auto dec = ce::guestNextCompare<int32_t>(be, cand, ce::GuestCompare::Decreased);
    bool cmpOk = inc.size() == 1 && inc[0].first == 0x60 && inc[0].second == 15
              && dec.size() == 1 && dec[0].first == 0x64 && dec[0].second == 5;
    printf("  compare next-scan (increased/decreased): %s\n", cmpOk ? "OK" : "FAILED");

    // Unknown-value scan: snapshot the whole region, change some values, compare
    // buffers to narrow (here: which offsets increased).
    uint8_t r2[64] = {0};
    ce::GuestView lev{ &self, reinterpret_cast<uintptr_t>(r2), sizeof(r2), /*bigEndian=*/false };
    lev.write<int32_t>(0x08, 100);
    lev.write<int32_t>(0x0C, 100);
    auto snap = ce::guestReadRegion(lev);
    lev.write<int32_t>(0x08, 120);   // increased
    lev.write<int32_t>(0x0C, 80);    // decreased
    auto now = ce::guestReadRegion(lev);
    auto up = ce::guestCompareBuffers<int32_t>(snap, now, false, ce::GuestCompare::Increased, 4);
    bool unkOk = snap.size() == sizeof(r2) && up.size() == 1
              && up[0].first == 0x08 && up[0].second == 120;
    printf("  unknown-value scan (snapshot + compare): %s\n", unkOk ? "OK" : "FAILED");

    // An unreadable page inside guest RAM does not end the snapshot: offsets after
    // it are still compared, offsets in it never are. Caps bound the snapshot and
    // the hit lists.
    const size_t page = 4096;
    auto* ram3 = static_cast<uint8_t*>(::mmap(nullptr, 3 * page, PROT_READ | PROT_WRITE,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    bool gapOk = ram3 != MAP_FAILED;
    if (gapOk) {
        std::memset(ram3, 0, 3 * page);
        gapOk = ::mprotect(ram3 + page, page, PROT_NONE) == 0;
        ce::GuestView gap{ &self, reinterpret_cast<uintptr_t>(ram3), 3 * page, /*bigEndian=*/false };
        auto before = ce::guestSnapshotRegion(gap);
        int32_t raised = 7;
        std::memcpy(ram3 + 2 * page + 8, &raised, sizeof(raised));
        auto after = ce::guestSnapshotRegion(gap);
        auto inc = ce::guestCompareSnapshots<int32_t>(before, after, false, ce::GuestCompare::Increased, 4);
        auto same = ce::guestCompareSnapshots<int32_t>(before, after, false, ce::GuestCompare::Unchanged, 4);
        gapOk = gapOk && before.readable.size() == 2 && before.readableBytes() == 2 * page &&
                !before.truncated && inc.size() == 1 && inc[0].first == 2 * page + 8 &&
                same.size() == (2 * page) / 4 - 1;
        bool hitsCut = false, cmpCut = false;
        auto capped = ce::guestScanExact<int32_t>(gap, 0, 4, 3, &hitsCut);
        auto cappedCmp = ce::guestCompareSnapshots<int32_t>(before, after, false, ce::GuestCompare::Unchanged,
                                                            4, 5, &cmpCut);
        auto small = ce::guestSnapshotRegion(gap, page);
        gapOk = gapOk && capped.size() == 3 && hitsCut && cappedCmp.size() == 5 && cmpCut &&
                small.truncated && small.bytes.size() == page;
        ::munmap(ram3, 3 * page);
    }
    printf("  guest snapshot skips unreadable pages and caps its size and hits: %s\n", gapOk ? "OK" : "FAILED");
}

void test_cheat_table_json() {
    printf("\n── Test: CheatTable Round Trip ──\n");

    CheatTable table;
    table.gameName = "Example Game";
    table.gameVersion = "1.2.3";
    table.author = "cecore";
    table.comment = "Lua table metadata";
    table.luaScript = "print('table lua')\nreturn 7\n";

    CheatEntry entry;
    entry.id = 7;
    entry.description = "Health \"current\"";
    entry.address = 0x1234;
    entry.type = ValueType::Int32;
    entry.value = "100\n200";
    entry.active = true;
    // A data record (address + type) and an Auto Assembler record are mutually
    // exclusive in CE's format: a record with an <AssemblerScript> IS an "Auto
    // Assembler Script" record and carries no numeric address/type. Keep this
    // entry a pure data record; AA-record round-trip is covered by
    // test_ce_table_import's fidelity checks and the real-table corpus.
    entry.luaScript = "print('entry lua')\n";
    entry.color = "FF00AA";
    entry.dropdownList = "0:Off;1:On";
    entry.hotkeyKeys = "Ctrl+H";
    entry.increaseHotkeyKeys = "Ctrl+Up";
    entry.decreaseHotkeyKeys = "Ctrl+Down";
    entry.hotkeyStep = "5";
    entry.showAsSigned = false;   // non-default (CE <ShowAsSigned>0</ShowAsSigned>) must survive
    table.entries.push_back(entry);

    StructureDefinition structure;
    structure.name = "Player";
    structure.size = 16;
    structure.fields.push_back({"health", 0, ValueType::Int32, 4});
    structure.fields.push_back({"mana", 4, ValueType::Float, 4});
    structure.fields[0].displayMethod = "unsigned";
    structure.fields.push_back({"position", 8, ValueType::ByteArray, 8});
    structure.fields[2].nestedStructure = "Vector2";
    table.structures.push_back(structure);

    table.disassemblerComments.push_back({"libgame.so+0x1234", "loop start \"here\"", ""});
    table.disassemblerComments.push_back({"0x400500", "", "InitPlayer"});

    auto jsonPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".json");
    auto xmlPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".CT");
    auto protectedPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".CETRAINER");

    if (!table.saveJson(jsonPath.string()) || !table.save(xmlPath.string()) ||
        !table.saveProtected(protectedPath.string(), "secret")) {
        printf("  Save FAILED\n");
        return;
    }

    auto matchesTable = [&table, &entry](const CheatTable& loaded) {
        return loaded.gameName == table.gameName &&
            loaded.gameVersion == table.gameVersion &&
            loaded.author == table.author &&
            loaded.comment == table.comment &&
            loaded.luaScript == table.luaScript &&
            loaded.structures.size() == 1 &&
            loaded.structures[0].name == "Player" &&
            loaded.structures[0].size == 16 &&
            loaded.structures[0].fields.size() == 3 &&
            loaded.structures[0].fields[0].name == "health" &&
            loaded.structures[0].fields[0].offset == 0 &&
            loaded.structures[0].fields[0].type == ValueType::Int32 &&
            loaded.structures[0].fields[0].displayMethod == "unsigned" &&
            loaded.structures[0].fields[1].name == "mana" &&
            loaded.structures[0].fields[1].offset == 4 &&
            loaded.structures[0].fields[1].type == ValueType::Float &&
            loaded.structures[0].fields[2].name == "position" &&
            loaded.structures[0].fields[2].nestedStructure == "Vector2" &&
            loaded.entries.size() == 1 &&
            loaded.entries[0].id == entry.id &&
            loaded.entries[0].description == entry.description &&
            loaded.entries[0].address == entry.address &&
            loaded.entries[0].type == entry.type &&
            loaded.entries[0].value == entry.value &&
            loaded.entries[0].active == entry.active &&
            loaded.entries[0].showAsSigned == entry.showAsSigned &&
            loaded.entries[0].autoAsmScript == entry.autoAsmScript &&
            loaded.entries[0].luaScript == entry.luaScript &&
            loaded.entries[0].color == entry.color &&
            loaded.entries[0].dropdownList == entry.dropdownList &&
            loaded.entries[0].hotkeyKeys == entry.hotkeyKeys &&
            loaded.entries[0].increaseHotkeyKeys == entry.increaseHotkeyKeys &&
            loaded.entries[0].decreaseHotkeyKeys == entry.decreaseHotkeyKeys &&
            loaded.entries[0].hotkeyStep == entry.hotkeyStep &&
            loaded.disassemblerComments.size() == 2 &&
            loaded.disassemblerComments[0].address == "libgame.so+0x1234" &&
            loaded.disassemblerComments[0].comment == "loop start \"here\"" &&
            loaded.disassemblerComments[0].label.empty() &&
            loaded.disassemblerComments[1].address == "0x400500" &&
            loaded.disassemblerComments[1].comment.empty() &&
            loaded.disassemblerComments[1].label == "InitPlayer";
    };

    CheatTable jsonLoaded;
    bool jsonOk = jsonLoaded.loadJson(jsonPath.string()) && matchesTable(jsonLoaded);
    CheatTable xmlLoaded;
    bool xmlOk = xmlLoaded.load(xmlPath.string()) && matchesTable(xmlLoaded);
    std::ifstream xmlFile(xmlPath);
    std::string xmlText((std::istreambuf_iterator<char>(xmlFile)), {});
    bool xmlTypeNamesOk =
        xmlText.find("<VariableType>4 Bytes</VariableType>") != std::string::npos &&
        xmlText.find("<Type>4 Bytes</Type>") != std::string::npos &&
        xmlText.find("<Type>Float</Type>") != std::string::npos &&
        xmlText.find("<Type>Array of byte</Type>") != std::string::npos;

    // A CE .CT that omits <ShowAsSigned> loads as signed (our default); an explicit
    // <ShowAsSigned>0</ShowAsSigned> loads as unsigned.
    CheatTable absentTag;
    absentTag.loadFromString(
        "<CheatTable><CheatEntries><CheatEntry><ID>1</ID><Description>\"x\"</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400000</Address></CheatEntry>"
        "</CheatEntries></CheatTable>");
    CheatTable zeroTag;
    zeroTag.loadFromString(
        "<CheatTable><CheatEntries><CheatEntry><ID>1</ID><Description>\"x\"</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400000</Address>"
        "<ShowAsSigned>0</ShowAsSigned></CheatEntry></CheatEntries></CheatTable>");
    bool signedDefaultOk = absentTag.entries.size() == 1 && absentTag.entries[0].showAsSigned &&
                           zeroTag.entries.size() == 1 && !zeroTag.entries[0].showAsSigned;

    // Group collapse persists: <Collapsed>1</Collapsed> loads true (absent loads false),
    // and a collapsed group survives a save + reload round-trip.
    CheatTable collapseLoad;
    collapseLoad.loadFromString(
        "<CheatTable><CheatEntries>"
        "<CheatEntry><ID>1</ID><Description>\"g1\"</Description><GroupHeader>1</GroupHeader>"
        "<Collapsed>1</Collapsed></CheatEntry>"
        "<CheatEntry><ID>2</ID><Description>\"g2\"</Description><GroupHeader>1</GroupHeader>"
        "</CheatEntry></CheatEntries></CheatTable>");
    bool collapseOk = collapseLoad.entries.size() == 2 &&
                      collapseLoad.entries[0].collapsed && !collapseLoad.entries[1].collapsed;
    auto collapsePath = std::filesystem::temp_directory_path() /
        ("cecore-collapse-" + std::to_string(getpid()) + ".CT");
    CheatTable collapseReload;
    collapseOk = collapseOk && collapseLoad.save(collapsePath.string()) &&
                 collapseReload.load(collapsePath.string()) &&
                 collapseReload.entries.size() == 2 &&
                 collapseReload.entries[0].collapsed && !collapseReload.entries[1].collapsed;
    std::filesystem::remove(collapsePath);

    // CE writes the dropdown options as <DropDownList> (PascalCase, like every other
    // tag); a real CE file's options must import. The mis-cased <DropdownList> older
    // builds of this port wrote is still accepted as a fallback.
    CheatTable ddCE, ddOld;
    ddCE.loadFromString(
        "<CheatTable><CheatEntries><CheatEntry><ID>1</ID><Description>\"d\"</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400000</Address>"
        "<DropDownList>0:Off\n1:On</DropDownList></CheatEntry></CheatEntries></CheatTable>");
    ddOld.loadFromString(
        "<CheatTable><CheatEntries><CheatEntry><ID>1</ID><Description>\"d\"</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400000</Address>"
        "<DropdownList>0:Off\n1:On</DropdownList></CheatEntry></CheatEntries></CheatTable>");
    bool dropdownOk = ddCE.entries.size() == 1 && ddCE.entries[0].dropdownList == "0:Off\n1:On" &&
                      ddOld.entries.size() == 1 && ddOld.entries[0].dropdownList == "0:Off\n1:On";

    // CE group <Options>: parse the two cascade flags, and preserve the whole element
    // verbatim so unmodeled flags (moRecursiveSetValue, ...) survive a load + save.
    CheatTable optLoad;
    optLoad.loadFromString(
        "<CheatTable><CheatEntries><CheatEntry><ID>1</ID><Description>\"g\"</Description>"
        "<GroupHeader>1</GroupHeader>"
        "<Options moHideChildren=\"0\" moActivateChildrenAsWell=\"0\" "
        "moDeactivateChildrenAsWell=\"1\" moRecursiveSetValue=\"1\"/>"
        "</CheatEntry></CheatEntries></CheatTable>");
    bool optOk = optLoad.entries.size() == 1 &&
                 !optLoad.entries[0].activateChildren && optLoad.entries[0].deactivateChildren &&
                 optLoad.entries[0].optionsXml.find("moRecursiveSetValue=\"1\"") != std::string::npos;
    auto optPath = std::filesystem::temp_directory_path() /
        ("cecore-options-" + std::to_string(getpid()) + ".CT");
    CheatTable optReload;
    optOk = optOk && optLoad.save(optPath.string()) && optReload.load(optPath.string()) &&
            optReload.entries.size() == 1 &&
            !optReload.entries[0].activateChildren && optReload.entries[0].deactivateChildren &&
            optReload.entries[0].optionsXml.find("moRecursiveSetValue=\"1\"") != std::string::npos;
    std::filesystem::remove(optPath);

    // CE string/AoB <Length>, and <Unicode>1 on a "String" type -> our UnicodeString.
    // Type + length must survive a save+reload (UnicodeString writes as String+Unicode).
    CheatTable strCE;
    strCE.loadFromString(
        "<CheatTable><CheatEntries>"
        "<CheatEntry><ID>1</ID><Description>\"name\"</Description>"
        "<VariableType>String</VariableType><Length>10</Length><Unicode>1</Unicode>"
        "<Address>400000</Address></CheatEntry>"
        "<CheatEntry><ID>2</ID><Description>\"tag\"</Description>"
        "<VariableType>String</VariableType><Length>8</Length><Address>400010</Address></CheatEntry>"
        "<CheatEntry><ID>3</ID><Description>\"sig\"</Description>"
        "<VariableType>Array of byte</VariableType><Length>4</Length><Address>400020</Address></CheatEntry>"
        "</CheatEntries></CheatTable>");
    bool strOk = strCE.entries.size() == 3 &&
        strCE.entries[0].type == ValueType::UnicodeString && strCE.entries[0].length == 10 &&
        strCE.entries[1].type == ValueType::String && strCE.entries[1].length == 8 &&
        strCE.entries[2].type == ValueType::ByteArray && strCE.entries[2].length == 4;
    auto strPath = std::filesystem::temp_directory_path() /
        ("cecore-strlen-" + std::to_string(getpid()) + ".CT");
    CheatTable strReload;
    strOk = strOk && strCE.save(strPath.string()) && strReload.load(strPath.string()) &&
        strReload.entries.size() == 3 &&
        strReload.entries[0].type == ValueType::UnicodeString && strReload.entries[0].length == 10 &&
        strReload.entries[1].type == ValueType::String && strReload.entries[1].length == 8 &&
        strReload.entries[2].type == ValueType::ByteArray && strReload.entries[2].length == 4;
    std::filesystem::remove(strPath);

    // CE nested <Hotkeys>: each <Hotkey> has an mrh Action + VK <Key> codes (+ Value);
    // they map to our toggle/set/increase/decrease slots with Qt key-sequence strings.
    CheatTable hkCE;
    hkCE.loadFromString(
        "<CheatTable><CheatEntries><CheatEntry><ID>1</ID><Description>\"h\"</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400000</Address>"
        "<Hotkeys>"
        "<Hotkey><Action>0</Action><Keys><Key>17</Key><Key>72</Key></Keys><ID>0</ID></Hotkey>"
        "<Hotkey><Action>5</Action><Keys><Key>116</Key></Keys><Value>100</Value><ID>1</ID></Hotkey>"
        "<Hotkey><Action>6</Action><Keys><Key>17</Key><Key>38</Key></Keys><Value>10</Value></Hotkey>"
        "<Hotkey><Action>7</Action><Keys><Key>17</Key><Key>40</Key></Keys><Value>10</Value></Hotkey>"
        "</Hotkeys></CheatEntry></CheatEntries></CheatTable>");
    bool hkOk = hkCE.entries.size() == 1 &&
        hkCE.entries[0].hotkeyKeys == "Ctrl+H" &&
        hkCE.entries[0].setValueHotkeyKeys == "F5" && hkCE.entries[0].setValueHotkeyValue == "100" &&
        hkCE.entries[0].increaseHotkeyKeys == "Ctrl+Up" && hkCE.entries[0].hotkeyStep == "10" &&
        hkCE.entries[0].decreaseHotkeyKeys == "Ctrl+Down";
    // Our save now emits CE's nested <Hotkey> structure (VK codes), not the old flat tag.
    auto hkPath = std::filesystem::temp_directory_path() /
        ("cecore-hkw-" + std::to_string(getpid()) + ".CT");
    std::string savedXml;
    if (hkCE.save(hkPath.string())) {
        std::ifstream in(hkPath.string());
        savedXml.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::filesystem::remove(hkPath);
    hkOk = hkOk && savedXml.find("<Hotkey>") != std::string::npos &&
                   savedXml.find("<Action>Toggle Activation</Action>") != std::string::npos &&
                   savedXml.find("<Key>17</Key>") != std::string::npos &&
                   savedXml.find("<Key>72</Key>") != std::string::npos;

    // XML special characters in a description/value must escape and round-trip
    // losslessly, including the quote-wrapping CE puts around descriptions.
    CheatTable specialsSave, specialsLoad;
    {
        CheatEntry se;
        se.description = "HP & <max> \"cur\" it's here";
        se.type = ValueType::Int32;
        se.address = 0x9000;
        se.value = "a<b>&c\"d";
        specialsSave.entries.push_back(se);
    }
    auto spPath = std::filesystem::temp_directory_path() /
        ("cecore-specials-" + std::to_string(getpid()) + ".CT");
    bool specialsOk = specialsSave.save(spPath.string()) && specialsLoad.load(spPath.string()) &&
        specialsLoad.entries.size() == 1 &&
        specialsLoad.entries[0].description == "HP & <max> \"cur\" it's here" &&
        specialsLoad.entries[0].value == "a<b>&c\"d";
    std::filesystem::remove(spPath);

    CheatTable protectedLoaded;
    bool protectedOk = protectedLoaded.loadProtected(protectedPath.string(), "secret") &&
        matchesTable(protectedLoaded);
    CheatTable wrongPassword;
    bool wrongPasswordOk = !wrongPassword.loadProtected(protectedPath.string(), "wrong");
    std::filesystem::remove(jsonPath);
    std::filesystem::remove(xmlPath);
    std::filesystem::remove(protectedPath);

    printf("  JSON round trip: %s\n", jsonOk ? "OK" : "FAILED");
    printf("  CT XML round trip: %s\n", xmlOk ? "OK" : "FAILED");
    printf("  ShowAsSigned default/override: %s\n", signedDefaultOk ? "OK" : "FAILED");
    printf("  group Collapsed round-trips: %s\n", collapseOk ? "OK" : "FAILED");
    printf("  CE <DropDownList> import (+ old-cased fallback): %s\n", dropdownOk ? "OK" : "FAILED");
    printf("  CE group <Options> flags parse + verbatim round-trip: %s\n", optOk ? "OK" : "FAILED");
    printf("  CE String/AoB <Length> + <Unicode> import + round-trip: %s\n", strOk ? "OK" : "FAILED");
    printf("  CE nested <Hotkeys> (VK codes + actions) import: %s\n", hkOk ? "OK" : "FAILED");
    printf("  XML special chars (& < > \") in desc/value round-trip: %s\n", specialsOk ? "OK" : "FAILED");
    printf("  CT XML CE type names: %s\n", xmlTypeNamesOk ? "OK" : "FAILED");
    printf("  CETRAINER protected round trip: %s\n", (protectedOk && wrongPasswordOk) ? "OK" : "FAILED");
}

// A pointer-scan result added to the address list must go in AS its pointer
// expression, not the resolved numeric address, so it survives a restart. Verify
// PointerPath::toString() produces an expression ExpressionParser resolves back to the
// same target the scan found.
// Perf maps are written by the target (untrusted): malformed, oversized and
// unnamed lines are skipped, and a recompiled function's latest entry wins.
// W^X JIT layout (CoreCLR): one memfd page mapped twice, a writable view that
// is dropped after writing code and a read-only executable view that runs it.
// Forced remote writes refuse shared read-only mappings; writes and software
// breakpoints must land through the file behind both views.
void test_wx_double_mapped_code() {
    printf("\n── Test: W^X double-mapped JIT code ──\n");
    int commands[2], replies[2];
    if (pipe(commands) || pipe(replies)) { printf("  W^X code: FAILED (pipes)\n"); return; }
    pid_t child = fork();
    if (child == 0) {
        close(commands[1]); close(replies[0]);
        int fd = memfd_create("ce-wx-code", 0);
        if (fd < 0 || ftruncate(fd, 4096) < 0) _exit(1);
        auto* rw = static_cast<uint8_t*>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
        void* rx = mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
        if (rw == MAP_FAILED || rx == MAP_FAILED) _exit(2);
        const uint8_t code[] = {0xb8, 42, 0, 0, 0, 0xc3};   // mov eax, 42; ret
        std::memcpy(rw, code, sizeof(code));
        munmap(rw, 4096);   // only the read-only executable view remains
        // Shared memory the target can write but maps read-only and never runs.
        int dataFd = memfd_create("ce-wx-data", 0);
        if (dataFd < 0 || ftruncate(dataFd, 4096) < 0 || pwrite(dataFd, "D", 1, 0) != 1) _exit(5);
        void* data = mmap(nullptr, 4096, PROT_READ, MAP_SHARED, dataFd, 0);
        if (data == MAP_FAILED) _exit(6);
        uintptr_t address = reinterpret_cast<uintptr_t>(rx), dataAddress = reinterpret_cast<uintptr_t>(data);
        if (::write(replies[1], &address, sizeof(address)) != sizeof(address) ||
            ::write(replies[1], &dataAddress, sizeof(dataAddress)) != sizeof(dataAddress)) _exit(3);
        for (char command; ::read(commands[0], &command, 1) == 1;) {
            int result = reinterpret_cast<int (*)()>(rx)();
            if (::write(replies[1], &result, sizeof(result)) != sizeof(result)) _exit(4);
        }
        _exit(0);
    }
    close(commands[0]); close(replies[1]);
    uintptr_t rx = 0, data = 0;
    bool started = ::read(replies[0], &rx, sizeof(rx)) == sizeof(rx) &&
                   ::read(replies[0], &data, sizeof(data)) == sizeof(data);
    auto call = [&]() {
        int result = -1;
        char command = 'c';
        if (::write(commands[1], &command, 1) != 1 || ::read(replies[0], &result, sizeof(result)) != sizeof(result)) return -1;
        return result;
    };
    ce::os::LinuxProcessHandle proc(child);
    const uint8_t seven[] = {7, 0, 0, 0};
    auto written = started ? proc.write(rx + 1, seven, sizeof(seven)) : ce::Result<size_t>(std::unexpected(std::error_code()));
    bool writeOk = written && *written == sizeof(seven) && call() == 7;
    printf("  a write to the read-only shared code view lands through its backing file: %s\n", writeOk ? "OK" : "FAILED");

    std::atomic<uintptr_t> hit{0};
    ce::DebugSession session;
    session.setEventCallback([&](const ce::DebugEvent& event) {
        if (event.type == ce::DebugEventType::BreakpointHit) hit = event.address;
    });
    bool attached = started && session.attach(child, &proc);
    int id = attached ? session.setSoftwareBreakpoint(rx) : -1;
    if (attached) session.continueExecution();
    char command = 'c';
    bool sent = id >= 0 && ::write(commands[1], &command, 1) == 1;
    for (int i = 0; i < 500 && sent && !hit; ++i) usleep(10000);
    bool stopped = hit == rx;
    if (attached) { if (id >= 0) session.removeSoftwareBreakpoint(id); session.continueExecution(); }
    int result = -1;
    bool completed = sent && ::read(replies[0], &result, sizeof(result)) == sizeof(result) && result == 7;
    if (attached) session.detach();
    printf("  a software breakpoint in the read-only shared code view stops and the call completes: %s\n",
           stopped && completed ? "OK" : "FAILED");

    // /proc/PID/mem refuses the forced write with EIO, which must reach the
    // file fallback too: Auto Assembler patches go through writeCode().
    const uint8_t nine[] = {9, 0, 0, 0}, eleven[] = {11, 0, 0, 0};
    auto patched = started ? proc.writeCode(rx + 1, nine, sizeof(nine)) : ce::Result<size_t>(std::unexpected(std::error_code()));
    bool codeOk = patched && *patched == sizeof(nine) && call() == 9;
    auto image = ce::os::pinNativeMemoryImage(proc);
    auto imaged = image && *image ? (*image)->write(rx + 1, eleven, true) : ce::Result<size_t>(std::unexpected(std::error_code()));
    bool imageOk = imaged && *imaged == sizeof(eleven) && call() == 11;
    printf("  writeCode and a pinned image write the read-only shared code view: %s\n", codeOk && imageOk ? "OK" : "FAILED");

    // Read-only shared memory with no executable view is not code: its file stays untouched.
    const uint8_t edit = 'E';
    uint8_t seen = 0;
    bool refused = started && !proc.write(data, &edit, 1) && proc.read(data, &seen, 1) && seen == 'D';
    printf("  a read-only shared mapping that is never executable refuses writes: %s\n", refused ? "OK" : "FAILED");
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    close(commands[1]); close(replies[0]);
}

// Lua deAlloc(address) passes no size: free() releases the block that
// allocate() returned there, and refuses an address it did not allocate.
void test_free_without_size() {
    printf("\n── Test: free without a size ──\n");
    pid_t child = fork();
    if (child == 0) { for (;;) pause(); }
    ce::os::LinuxProcessHandle proc(child);
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto block = proc.allocate(3 * page, ce::MemProt::Read | ce::MemProt::Write);
    auto other = proc.allocate(page, ce::MemProt::Read | ce::MemProt::Write);
    bool freed = block && proc.free(*block, 0) && !proc.queryRegion(*block) && !proc.queryRegion(*block + 2 * page);
    bool again = block && !proc.free(*block, 0);
    bool unknown = block && !proc.free(*block + page, 0);
    bool sized = other && proc.free(*other, page) && !proc.queryRegion(*other) && !proc.free(*other, 0);
    printf("  free(address, 0) releases a whole allocated block once: %s\n", freed && again ? "OK" : "FAILED");
    printf("  free(address, 0) refuses an address it did not allocate; explicit sizes still work: %s\n",
           unknown && sized ? "OK" : "FAILED");
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
}

// The Wine memory helper's machine code is embedded (its file must build
// without Keystone); it has to stay the assembly of the source kept beside it.
void test_wine_memory_helper() {
    printf("\n── Test: Wine memory helper image ──\n");
    ce::Assembler assembler(ce::AsmArch::X86_64);
    auto assembled = assembler.assemble(std::string(ce::os::wineHelperSource()), 0x401000);
    const auto code = ce::os::wineHelperCode();
    bool same = assembled && assembled->size() == code.size() && std::equal(code.begin(), code.end(), assembled->begin());
    printf("  embedded helper code is the assembly of its source: %s\n", same ? "OK" : "FAILED");
    ce::os::WineHelperRequest request;
    request.operation = 1; request.windowsPid = 0x124; request.preferred = 0x400000; request.low = 0x10000;
    request.high = 0x7fff0000; request.size = 0x1000; request.protection = 0x40;
    auto image = ce::os::wineHelperImage(request);
    auto u32 = [&](size_t at) { uint32_t v = 0; std::memcpy(&v, image.data() + at, 4); return v; };
    auto u64 = [&](size_t at) { uint64_t v = 0; std::memcpy(&v, image.data() + at, 8); return v; };
    bool headers = image.size() == 0x1800 && image[0] == 'M' && image[1] == 'Z' && u32(0x3c) == 0x80 &&
        std::memcmp(image.data() + 0x80, "PE\0\0", 4) == 0 && u32(0x98 + 16) == 0x1000 && u64(0x98 + 24) == 0x400000;
    bool code0 = std::equal(code.begin(), code.end(), image.begin() + 0x400);
    bool data = u64(0x1400) == 1 && u64(0x1408) == 0x124 && u64(0x1410) == 0x400000 && u64(0x1428) == 0x1000 &&
        u64(0x1430) == 0x40 && std::memcmp(image.data() + 0x1440, "CEWINEAL", 8) == 0;
    // Import address table slot i must name the i-th function the code calls.
    const char* names[] = {"GetStdHandle", "WriteFile", "ExitProcess", "OpenProcess", "VirtualAllocEx", "VirtualFreeEx", "GetLastError"};
    bool imports = std::strcmp(reinterpret_cast<const char*>(image.data() + 0x1640), "kernel32.dll") == 0;
    for (size_t i = 0; i < std::size(names) && imports; ++i) {
        const uint64_t hint = u64(0x1600 + 0x140 + i * 8);
        imports = hint >= 0x3080 && hint < 0x3100 && u64(0x1600 + 0x100 + i * 8) == hint &&
            std::strcmp(reinterpret_cast<const char*>(image.data() + 0x1600 + (hint - 0x3000) + 2), names[i]) == 0;
    }
    imports = imports && u64(0x1600 + 0x140 + std::size(names) * 8) == 0;
    printf("  helper PE32+ headers, code, parameters and imports are laid out: %s\n",
           headers && code0 && data && imports ? "OK" : "FAILED");
}

void test_perf_map_symbols() {
    printf("\n── Test: JIT perf-map symbols ──\n");
    char path[] = "/tmp/ce-perfmap-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { printf("  perf map: FAILED (temp file)\n"); return; }
    std::string text =
        "7f0000001000 40 JS:*hotLoop game.js:3:1\n"
        "0x7f0000002000 0x20 Interpreter::ceJitWriter (I)I\n"
        "not-a-number 10 bogus\n"
        "7f0000003000 10\n"
        "7f0000004000 zz broken size\n"
        "7f0000001000 40 JS:*hotLoopRecompiled game.js:3:1\r\n" +
        std::string(5000, 'x') + "\n";
    bool written = write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    close(fd);
    ce::SymbolResolver resolver;
    resolver.loadPerfMap(path);
    unlink(path);
    bool ok = written && resolver.count() == 2 &&
        resolver.lookup("JS:*hotLoopRecompiled game.js:3:1") == 0x7f0000001000 &&
        resolver.lookup("Interpreter::ceJitWriter (I)I") == 0x7f0000002000 &&
        resolver.resolve(0x7f0000001010) == "[jit]!JS:*hotLoopRecompiled game.js:3:1+0x10" &&
        resolver.lookup("bogus") == 0;
    printf("  perf map entries, recompiled names and malformed lines: %s\n", ok ? "OK" : "FAILED");

    // Anyone can create the file: a FIFO there must not block the loader.
    char fifo[] = "/tmp/ce-perfmap-fifo-XXXXXX";
    if (int temp = mkstemp(fifo); temp >= 0) {
        close(temp);
        unlink(fifo);
        if (mkfifo(fifo, 0600) == 0) {
            auto loaded = std::async(std::launch::async, [&] { ce::SymbolResolver fifoResolver; fifoResolver.loadPerfMap(fifo); });
            const bool returned = loaded.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
            if (!returned) { int unblock = open(fifo, O_WRONLY | O_NONBLOCK); if (unblock >= 0) close(unblock); }
            printf("  a FIFO in place of the perf map does not block: %s\n", returned ? "OK" : "FAILED");
            loaded.wait();
            unlink(fifo);
        }
    }
}

// A mapped device (a GPU's /dev/dri node in a real game) is not a module: a
// blocking read on it would hang module enumeration.
void test_device_mapping_not_module() {
    printf("\n── Test: Mapped devices are not modules ──\n");
    int ready[2];
    if (pipe(ready) != 0) return;
    const pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        int fd = open("/dev/zero", O_RDWR);
        void* shared = fd >= 0 ? mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) : MAP_FAILED;
        if (write(ready[1], shared == MAP_FAILED ? "n" : "y", 1) != 1) _exit(1);
        for (;;) pause();
    }
    char byte = 'n';
    if (read(ready[0], &byte, 1) != 1) byte = 'n';
    close(ready[0]); close(ready[1]);
    if (byte == 'y') {
        ce::os::LinuxProcessHandle proc(child);
        bool deviceModule = false, deletedName = false;
        for (const auto& m : proc.modules()) {
            deviceModule = deviceModule || m.path.rfind("/dev/", 0) == 0;
            deletedName = deletedName || m.name.find(" (deleted)") != std::string::npos;
        }
        printf("  no module for a mapped device, no \"(deleted)\" in names: %s\n",
               !deviceModule && !deletedName ? "OK" : "FAILED");
    } else {
        printf("  no module for a mapped device: SKIPPED (no /dev/zero mapping)\n");
    }
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
}

void test_pointer_path_expression() {
    printf("\n── Test: PointerPath toString resolves via ExpressionParser ──\n");
    const uintptr_t moduleBase = 0x400000;
    const uintptr_t node1 = 0x500000;
    std::vector<uint8_t> module(0x100, 0), n1(0x100, 0);
    std::memcpy(module.data() + 0x10, &node1, sizeof(node1));   // [game+0x10] -> node1
    FakeProcessHandle proc({
        {{moduleBase, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game"}, module},
        {{node1, n1.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, n1},
    }, {
        {moduleBase, module.size(), "game", "/tmp/game", true},
    });

    PointerPath path;
    path.module = "game"; path.moduleBase = moduleBase; path.baseOffset = 0x10;
    path.offsets = {0x8};                    // final address = [game+0x10] + 0x8 = node1 + 0x8
    std::string expr = path.toString();
    ce::ExpressionParser parser(&proc, nullptr);
    auto resolved = parser.parse(expr);
    uintptr_t want = node1 + 0x8;
    bool ok = resolved && *resolved == want;
    printf("  '%s' resolves to the scanned target: %s (got 0x%lx want 0x%lx)\n",
           expr.c_str(), ok ? "OK" : "FAILED",
           (unsigned long)(resolved ? *resolved : 0), (unsigned long)want);

    // A module name with '+' (libstdc++.so.6) is quoted so the path parses back.
    FakeProcessHandle plusProc({
        {{moduleBase, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/libstdc++.so.6"}, module},
        {{node1, n1.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, n1},
    }, {
        {moduleBase, module.size(), "libstdc++.so.6", "/tmp/libstdc++.so.6", true},
    });
    PointerPath plusPath = path;
    plusPath.module = "libstdc++.so.6";
    const std::string plusExpr = plusPath.toString();
    auto plusResolved = ce::ExpressionParser(&plusProc, nullptr).parse(plusExpr);
    printf("  '%s' (a module name with '+') resolves: %s\n", plusExpr.c_str(),
           plusResolved && *plusResolved == want ? "OK" : "FAILED");
}

void test_ce_table_import() {
    printf("\n── Test: Real CE .CT import ──\n");
    // Exactly as Cheat Engine itself writes an entry: the Description is wrapped
    // in double quotes, the type is a name ("4 Bytes"), the address is bare hex.
    const char* ct =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<CheatTable>\n"
        "  <CheatEntries>\n"
        "    <CheatEntry>\n"
        "      <ID>1</ID>\n"
        "      <Description>\"Player Health\"</Description>\n"
        "      <VariableType>4 Bytes</VariableType>\n"
        "      <Address>00401000</Address>\n"
        "    </CheatEntry>\n"
        "    <CheatEntry>\n"
        "      <ID>2</ID>\n"
        "      <Description>\"Ammo (pointer)\"</Description>\n"
        "      <VariableType>4 Bytes</VariableType>\n"
        "      <Address>game.exe+1C</Address>\n"
        "      <Offsets>\n"
        "        <Offset>10</Offset>\n"
        "        <Offset>8</Offset>\n"
        "      </Offsets>\n"
        "    </CheatEntry>\n"
        "  </CheatEntries>\n"
        "</CheatTable>\n";
    auto path = std::filesystem::temp_directory_path() / "ce_import_test.CT";
    { std::ofstream o(path); o << ct; }
    CheatTable t;
    bool loaded = t.load(path.string());
    std::filesystem::remove(path);
    bool ok = loaded && t.entries.size() == 2 &&
        t.entries[0].description == "Player Health" &&      // CE's quotes stripped
        t.entries[0].type == ValueType::Int32 &&
        t.entries[0].address == 0x401000;
    // Pointer entry: symbolic base preserved, offsets parsed (hex).
    bool ptrOk = t.entries[1].description == "Ammo (pointer)" &&
        t.entries[1].addressString == "game.exe+1C" &&
        t.entries[1].offsets == std::vector<int64_t>({0x10, 0x8});
    printf("  loads CE-authored .CT (quoted desc, 4 Bytes, hex addr): %s\n", ok ? "OK" : "FAILED");
    printf("  loads CE pointer entry (symbolic base + offsets): %s\n", ptrOk ? "OK" : "FAILED");

    // Pointer expression built from base+offsets must match CE's resolution order.
    bool exprOk =
        ce::buildPointerExpression("game.exe+1C", {}) == "game.exe+1C" &&
        ce::buildPointerExpression("game.exe+1C", {0x10}) == "[game.exe+1C]+10" &&
        ce::buildPointerExpression("game.exe+1C", {0x10, 0x8}) == "[[game.exe+1C]+8]+10";
    printf("  pointer expression matches CE offset order: %s\n", exprOk ? "OK" : "FAILED");

    // parsePointerExpression is the exact inverse: it round-trips every built chain,
    // rejects a plain (non-bracketed) address, and reads negative offsets.
    auto roundtrips = [](const std::string& base, const std::vector<int64_t>& offs) {
        auto p = ce::parsePointerExpression(ce::buildPointerExpression(base, offs));
        return p && p->base == base && p->offsets == offs;
    };
    bool parseOk =
        roundtrips("game.exe+1C", {0x10}) &&
        roundtrips("game.exe+1C", {0x10, 0x8}) &&
        roundtrips("mono.dll", {0x0, 0x18, 0x4}) &&
        !ce::parsePointerExpression("game.exe+1C").has_value() &&   // plain addr, not a chain
        !ce::parsePointerExpression("00400000").has_value();
    // Negative offsets survive the round-trip.
    auto pn = ce::parsePointerExpression("[base]-8");
    bool negOk = pn && pn->base == "base" && pn->offsets.size() == 1 && pn->offsets[0] == -8;
    printf("  parsePointerExpression inverts buildPointerExpression: %s\n",
           (parseOk && negOk) ? "OK" : "FAILED");

    // CE nests child entries inside a group's <CheatEntries>. Loading a grouped
    // table must yield the group AND its child, with the child parented correctly.
    const char* grouped =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<CheatTable>\n"
        "  <CheatEntries>\n"
        "    <CheatEntry>\n"
        "      <ID>10</ID>\n"
        "      <Description>\"Cheats\"</Description>\n"
        "      <GroupHeader>1</GroupHeader>\n"
        "      <CheatEntries>\n"
        "        <CheatEntry>\n"
        "          <ID>11</ID>\n"
        "          <Description>\"God Mode\"</Description>\n"
        "          <VariableType>4 Bytes</VariableType>\n"
        "          <Address>00500000</Address>\n"
        "        </CheatEntry>\n"
        "      </CheatEntries>\n"
        "    </CheatEntry>\n"
        "  </CheatEntries>\n"
        "</CheatTable>\n";
    auto gpath = std::filesystem::temp_directory_path() / "ce_group_test.CT";
    { std::ofstream o(gpath); o << grouped; }
    CheatTable gt;
    bool gloaded = gt.load(gpath.string());
    std::filesystem::remove(gpath);
    bool groupOk = gloaded && gt.entries.size() == 2;
    // find the group and child
    if (groupOk) {
        const CheatEntry* grp = nullptr; const CheatEntry* child = nullptr;
        for (auto& e : gt.entries) {
            if (e.description == "Cheats") grp = &e;
            if (e.description == "God Mode") child = &e;
        }
        groupOk = grp && child && grp->isGroup && !child->isGroup &&
                  child->address == 0x500000 && child->parentId == grp->id;
    }
    printf("  loads nested CE group (parent+child hierarchy): %s\n", groupOk ? "OK" : "FAILED");

    // Save a grouped table and reload it: the parent/child hierarchy must survive
    // (saver must nest children, not write a flat list).
    CheatTable st;
    CheatEntry sg; sg.id = 1; sg.description = "Folder"; sg.isGroup = true; sg.parentId = -1;
    CheatEntry sc; sc.id = 2; sc.description = "Coins"; sc.parentId = 1;
    sc.address = 0x1000; sc.type = ValueType::Int32;
    st.entries = {sg, sc};
    auto spath = std::filesystem::temp_directory_path() / "ce_group_save.CT";
    bool saved = st.save(spath.string());
    CheatTable rt;
    bool reloaded = rt.load(spath.string());
    std::filesystem::remove(spath);
    bool saveHierOk = saved && reloaded && rt.entries.size() == 2;
    if (saveHierOk) {
        const CheatEntry* g = nullptr; const CheatEntry* c = nullptr;
        for (auto& e : rt.entries) { if (e.description == "Folder") g = &e; if (e.description == "Coins") c = &e; }
        saveHierOk = g && c && g->isGroup && c->parentId == g->id && c->address == 0x1000;
    }
    printf("  save/reload preserves group hierarchy: %s\n", saveHierOk ? "OK" : "FAILED");

    // Save an entry with a symbolic base + pointer offsets, reload: both must
    // survive (verifies the SAVE side emits <Address>text and <Offsets>).
    CheatTable pt;
    CheatEntry pe; pe.id = 1; pe.description = "Ptr"; pe.type = ValueType::Int32;
    pe.addressString = "game.exe+1C"; pe.offsets = {0x10, 0x8};
    pe.freezeMode = ce::FreezeMode::DecreaseOnly;  // directional freeze must persist
    pe.showAsHex = true;                          // show-as-hex flag must persist too
    pe.setValueHotkeyKeys = "Ctrl+H"; pe.setValueHotkeyValue = "999";  // set-value hotkey persists
    pt.entries = {pe};
    auto ppath = std::filesystem::temp_directory_path() / "ce_ptr_save.CT";
    bool psaved = pt.save(ppath.string());
    CheatTable pr;
    bool preloaded = pr.load(ppath.string());
    std::filesystem::remove(ppath);
    bool ptrSaveOk = psaved && preloaded && pr.entries.size() == 1 &&
        pr.entries[0].addressString == "game.exe+1C" &&
        pr.entries[0].freezeMode == ce::FreezeMode::DecreaseOnly &&  // freezeMode round-trips
        pr.entries[0].showAsHex == true &&  // showAsHex round-trips
        pr.entries[0].setValueHotkeyKeys == "Ctrl+H" && pr.entries[0].setValueHotkeyValue == "999" &&
        pr.entries[0].offsets == std::vector<int64_t>({0x10, 0x8});
    printf("  save/reload preserves symbolic base + offsets: %s\n", ptrSaveOk ? "OK" : "FAILED");

    // Round-trip fidelity bugs found against 14 real downloaded CE tables:
    //  1. a quoted module base ("ac_client.exe"+X) was XML-escaped on save, so the
    //     next load saw &quot; literally. CE writes the address RAW.
    //  2. an Auto Assembler record was re-saved as <Address>0</Address> +
    //     <VariableType>4 Bytes</VariableType> instead of "Auto Assembler Script".
    //  3. a negative pointer offset (-60) was saved as 64-bit unsigned hex, which
    //     overflowed the loader on reload and dropped the offset.
    CheatTable f;
    CheatEntry q; q.id = 1; q.description = "Quoted base";
    q.type = ValueType::Int32; q.addressString = "\"ac_client.exe\"+0x17E254";
    CheatEntry aa; aa.id = 2; aa.description = "God Mode";
    aa.autoAsmScript = "[ENABLE]\nnop\n[DISABLE]\ndb 89 01";   // no address -> AA record
    CheatEntry ng; ng.id = 3; ng.description = "Neg offset ptr";
    ng.type = ValueType::Float; ng.addressString = "EDF5.exe+125AB70";
    ng.offsets = {0x1F8, 0x0, -0x60};                         // trailing NEGATIVE offset
    f.entries = {q, aa, ng};
    auto fpath = std::filesystem::temp_directory_path() / "ce_fidelity.CT";
    bool fsaved = f.save(fpath.string());
    // The on-disk address must be raw (no &quot;) and the AA type name present.
    std::string disk; { std::ifstream in(fpath); disk.assign(
        std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()); }
    bool rawAddr = disk.find("&quot;") == std::string::npos &&
                   disk.find("\"ac_client.exe\"+0x17E254") != std::string::npos;
    bool aaType  = disk.find("Auto Assembler Script") != std::string::npos &&
                   disk.find("<Address>0</Address>") == std::string::npos;
    bool negHex  = disk.find("-60") != std::string::npos;
    CheatTable fr;
    bool freloaded = fr.load(fpath.string());
    std::filesystem::remove(fpath);
    bool fidelityOk = fsaved && freloaded && fr.entries.size() == 3 &&
        fr.entries[0].addressString == "\"ac_client.exe\"+0x17E254" &&   // raw quotes survive
        !fr.entries[1].autoAsmScript.empty() &&                          // AA script survives
        fr.entries[2].offsets == std::vector<int64_t>({0x1F8, 0x0, -0x60}); // negative offset survives
    printf("  saver: raw address (no over-escape): %s\n", rawAddr ? "OK" : "FAILED");
    printf("  saver: AA record keeps its type, no bogus address: %s\n", aaType ? "OK" : "FAILED");
    printf("  saver: negative offset survives round-trip: %s\n", (negHex && fidelityOk) ? "OK" : "FAILED");
}

// loadFromString parses .CT XML held in memory. The clipboard path relies on it
// accepting a bare <CheatEntries> fragment (what CE copies), not just a full
// <CheatTable> document.
// Fields of the same name in nested sections, odd offsets and ids, and a
// table nested too deep for the loader.
void test_ct_review_fixes() {
    printf("\n── Test: Cheat table fields, ids and nesting ──\n");
    const std::string table =
        "<CheatTable><CheatEntries>"
        "<CheatEntry><ID>1</ID><Description>\"Health\"</Description><VariableType>4 Bytes</VariableType>"
        "<Address>1000</Address><Length>268435456</Length><freezeMode>9</freezeMode>"
        "<Hotkeys><Hotkey><Action>5</Action><Keys><Key>112</Key></Keys><Value>999</Value></Hotkey></Hotkeys></CheatEntry>"
        "<CheatEntry><Description>\"Group\"</Description><GroupHeader>1</GroupHeader><CheatEntries>"
        "<CheatEntry><Description>\"A\"</Description><VariableType>4 Bytes</VariableType><Address>2000</Address></CheatEntry>"
        "<CheatEntry><Description>\"B\"</Description><VariableType>4 Bytes</VariableType><Address>3000</Address></CheatEntry>"
        "</CheatEntries></CheatEntry>"
        "<CheatEntry><ID>9</ID><Description>\"Ptr\"</Description><VariableType>4 Bytes</VariableType><Address>game+10</Address>"
        "<Offsets><Offset>10</Offset><Offset>player_ofs</Offset></Offsets></CheatEntry>"
        "</CheatEntries>"
        "<DisassemblerComments><DisassemblerComment><Address>401000</Address><Comment>not the table's</Comment>"
        "</DisassemblerComment></DisassemblerComments></CheatTable>";
    CheatTable t;
    const bool loaded = t.loadFromString(table);
    const bool fields = loaded && t.entries.size() == 5 && t.entries[0].value.empty() &&
        t.entries[0].setValueHotkeyValue == "999" && t.entries[0].length == 65536 &&
        t.entries[0].freezeMode == FreezeMode::Normal && t.comment.empty();
    printf("  a hotkey's Value and a disassembler Comment stay theirs: %s\n", fields ? "OK" : "FAILED");
    // The group and its children had no ids: each gets its own, and both
    // children hang off the group.
    const bool ids = loaded && t.entries.size() == 5 && t.entries[1].id != t.entries[2].id &&
        t.entries[2].id != t.entries[3].id && t.entries[2].parentId == t.entries[1].id &&
        t.entries[3].parentId == t.entries[1].id;
    printf("  records without ids keep their hierarchy: %s\n", ids ? "OK" : "FAILED");
    const bool offsets = loaded && t.entries.size() == 5 && t.entries[4].offsets.empty() && t.entries[4].address == 0 &&
        t.entries[4].addressString.find("unsupported offset player_ofs") != std::string::npos;
    printf("  an offset that cannot be read leaves no wrong address: %s\n", offsets ? "OK" : "FAILED");

    std::string deep = "<CheatTable><CheatEntries>";
    for (int i = 0; i < 5000; ++i) deep += "<CheatEntry><GroupHeader>1</GroupHeader><CheatEntries>";
    for (int i = 0; i < 5000; ++i) deep += "</CheatEntries></CheatEntry>";
    deep += "</CheatEntries></CheatTable>";
    CheatTable tooDeep;
    printf("  a table nested too deep is refused: %s\n", !tooDeep.loadFromString(deep) ? "OK" : "FAILED");

    // Markup characters in an address survive a save and load as text.
    CheatTable markup;
    CheatEntry odd;
    odd.id = 1;
    odd.addressString = "1<2&3";
    odd.type = ValueType::Int32;
    markup.entries = {odd};
    const auto path = std::filesystem::temp_directory_path() / "ce_markup.CT";
    CheatTable back;
    const bool roundTrip = markup.save(path.string()) && back.load(path.string()) && back.entries.size() == 1 &&
        back.entries[0].addressString == "1<2&3";
    std::filesystem::remove(path);
    printf("  markup in an address is escaped: %s\n", roundTrip ? "OK" : "FAILED");

    // Keypad, punctuation and the plus key survive a save and load, and so do
    // Cheat Engine sections we do not model.
    CheatTable keys;
    keys.rawSectionsXml = "  <UserdefinedSymbols><SymbolEntry><Name>player</Name><Address>1000</Address></SymbolEntry></UserdefinedSymbols>\n";
    // "Ctrl++" is the =/+ key (VK_OEM_PLUS), which reads back as "Ctrl+=".
    const std::vector<std::string> sequences = {"Ctrl+Num+0", "Ctrl+Num++", "Ctrl+-", "Ctrl+=", "Shift+F13", "Alt+;"};
    for (size_t i = 0; i < sequences.size(); ++i) {
        CheatEntry e;
        e.id = static_cast<int>(i) + 1;
        e.addressString = "1000";
        e.address = 0x1000;
        e.type = ValueType::Int32;
        e.hotkeyKeys = sequences[i] == "Ctrl+=" ? "Ctrl++" : sequences[i];
        keys.entries.push_back(e);
    }
    const auto keysPath = std::filesystem::temp_directory_path() / "ce_keys.CT";
    CheatTable keysBack;
    bool keysOk = keys.save(keysPath.string()) && keysBack.load(keysPath.string()) &&
                  keysBack.entries.size() == sequences.size();
    for (size_t i = 0; keysBack.entries.size() == sequences.size() && i < sequences.size(); ++i)
        if (keysBack.entries[i].hotkeyKeys != sequences[i]) {
            printf("    %s came back as %s\n", sequences[i].c_str(), keysBack.entries[i].hotkeyKeys.c_str());
            keysOk = false;
        }
    std::string keysDisk;
    { std::ifstream in(keysPath); keysDisk.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()); }
    std::filesystem::remove(keysPath);
    printf("  keypad and punctuation hotkeys round-trip: %s\n", keysOk ? "OK" : "FAILED");
    printf("  Cheat Engine sections we do not model are kept: %s\n",
           keysBack.rawSectionsXml.find("<SymbolEntry><Name>player</Name>") != std::string::npos &&
           keysDisk.find("<UserdefinedSymbols>") != std::string::npos ? "OK" : "FAILED");
}

void test_ct_load_from_string() {
    printf("\n── Test: CheatTable::loadFromString (clipboard fragment) ──\n");

    // A bare <CheatEntries> block, exactly as Cheat Engine puts on the clipboard
    // when you Ctrl+C selected records (no <?xml?> header, no <CheatTable> wrapper).
    const char* fragment =
        "<CheatEntries>\n"
        "  <CheatEntry>\n"
        "    <ID>7</ID>\n"
        "    <Description>\"Gold\"</Description>\n"
        "    <VariableType>4 Bytes</VariableType>\n"
        "    <Address>1234ABCD</Address>\n"
        "  </CheatEntry>\n"
        "  <CheatEntry>\n"
        "    <ID>8</ID>\n"
        "    <Description>\"Lives\"</Description>\n"
        "    <VariableType>2 Bytes</VariableType>\n"
        "    <Address>game.exe+20</Address>\n"
        "    <Offsets><Offset>4</Offset></Offsets>\n"
        "  </CheatEntry>\n"
        "</CheatEntries>\n";
    CheatTable frag;
    bool fragOk = frag.loadFromString(fragment) && frag.entries.size() == 2 &&
        frag.entries[0].description == "Gold" &&
        frag.entries[0].type == ValueType::Int32 &&
        frag.entries[0].address == 0x1234ABCD &&
        frag.entries[1].description == "Lives" &&
        frag.entries[1].type == ValueType::Int16 &&
        frag.entries[1].addressString == "game.exe+20" &&
        frag.entries[1].offsets == std::vector<int64_t>({0x4});
    printf("  parses a bare <CheatEntries> clipboard fragment: %s\n", fragOk ? "OK" : "FAILED");

    // A full <CheatTable> document still parses (the refactor kept load() working).
    CheatTable full;
    bool fullOk = full.loadFromString(
        "<CheatTable><CheatEntries><CheatEntry><ID>1</ID>"
        "<Description>\"HP\"</Description><VariableType>Float</VariableType>"
        "<Address>DEAD00</Address></CheatEntry></CheatEntries></CheatTable>") &&
        full.entries.size() == 1 && full.entries[0].type == ValueType::Float &&
        full.entries[0].address == 0xDEAD00;
    printf("  parses a full <CheatTable> document: %s\n", fullOk ? "OK" : "FAILED");

    // Non-table text is rejected (so the clipboard paste can fall back to JSON).
    bool rejectsOk = !CheatTable().loadFromString("just some text, not a table") &&
                     !CheatTable().loadFromString("[{\"address\":\"0x1000\"}]");
    printf("  rejects non-table text: %s\n", rejectsOk ? "OK" : "FAILED");
}

// The Mono dissector's dump parser (the in-process agent's IMG/CLS/FLD output ->
// a structured model). Pure + offline; the live inject path is validated by hand
// against a real mono process.
void test_mono_dissector_parse() {
    printf("\n── Test: Mono dissector dump parser ──\n");
    const char* dump =
        "# ready pid=123\n"
        "IMG Assembly-CSharp\n"
        "CLS .Player\n"
        "FLD 0x18 - System.Int32 health\n"
        "FLD 0x10 - System.String playerName\n"
        "FLD 0x0 S System.Int32 instanceCount\n"
        "CLS Game.Enemies.Boss\n"
        "FLD 0x20 - System.Single hp\n"
        "IMG mscorlib\n"
        "CLS System.String\n"
        "# done\n";
    auto d = ce::parseMonoDump(dump);
    bool structOk = d.ready && d.error.empty() && d.images.size() == 2 &&
        d.images[0].name == "Assembly-CSharp" && d.images[0].classes.size() == 2 &&
        d.classCount() == 3;
    const ce::MonoClassInfo* p = d.findClass("Player");
    bool fieldOk = p && p->fields.size() == 3 &&
        p->fields[0].name == "health" && p->fields[0].offset == 0x18 &&
        !p->fields[0].isStatic && p->fields[0].typeName == "System.Int32" &&
        p->fields[2].name == "instanceCount" && p->fields[2].isStatic &&
        p->fields[2].offset == 0;
    const ce::MonoClassInfo* boss = d.findClass("Game.Enemies.Boss");
    bool nsOk = boss && boss->namespaceName == "Game.Enemies" && boss->name == "Boss";
    printf("  parses images/classes/fields + ready marker: %s\n", structOk ? "OK" : "FAILED");
    printf("  field offset/type/static-flag parsed: %s\n", fieldOk ? "OK" : "FAILED");
    printf("  namespaced class name split: %s\n", nsOk ? "OK" : "FAILED");
}

// Conditional breakpoint evaluation (the interactive debugger auto-continues when
// a breakpoint's condition is false).
void test_breakpoint_condition() {
    printf("\n── Test: conditional breakpoint evaluation ──\n");
    ce::CpuContext ctx{};
    ctx.rax = 5; ctx.rbx = 10; ctx.rip = 0x1234;
    bool trueCond  = ce::evaluateBreakpointCondition("rax == 5", ctx, ctx.rip);
    bool falseCond = ce::evaluateBreakpointCondition("rax == 6", ctx, ctx.rip);
    bool upper     = ce::evaluateBreakpointCondition("RAX == 5 and RBX > 5", ctx, ctx.rip);
    bool empty     = ce::evaluateBreakpointCondition("", ctx, ctx.rip);
    bool malformed = ce::evaluateBreakpointCondition("$$ not lua", ctx, ctx.rip);
    printf("  register condition true/false: %s\n", (trueCond && !falseCond) ? "OK" : "FAILED");
    printf("  uppercase register names + logic: %s\n", upper ? "OK" : "FAILED");
    printf("  empty condition always breaks: %s\n", empty ? "OK" : "FAILED");
    printf("  malformed condition fails safe (breaks): %s\n", malformed ? "OK" : "FAILED");
}

// createSimpleHook / removeSimpleHook against a live forked child. noipa keeps the
// caller from constant-propagating the return, so the detour is observable.
static volatile int g_hooktest_result = 0;
__attribute__((noinline, noipa)) static int hooktest_getval() { return 5; }
void test_simple_hook() {
    printf("\n── Test: createSimpleHook / removeSimpleHook (live detour) ──\n");
    int fds[2];
    if (pipe(fds) != 0) { printf("  pipe FAILED\n"); return; }
    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        char c = 'x'; ssize_t w = write(fds[1], &c, 1); (void)w;
        for (;;) { g_hooktest_result = hooktest_getval(); usleep(3000); }
        _exit(0);
    }
    close(fds[1]);
    char c = 0; ssize_t r = read(fds[0], &c, 1); (void)r; close(fds[0]);
    usleep(60000);

    ce::os::LinuxProcessHandle proc(child);
    auto res = [&] { int v = 0; proc.read(reinterpret_cast<uintptr_t>(&g_hooktest_result), &v, 4); return v; };
    const uintptr_t fnAddr = reinterpret_cast<uintptr_t>(&hooktest_getval);
    int before = res(), hooked = -1, after = -1;
    bool fired = false, restored = false, refused_bad = false;

    auto cave = proc.allocate(16, ce::MemProt::Read | ce::MemProt::Write | ce::MemProt::Exec, fnAddr);
    if (cave) {
        unsigned char stub[6] = {0xB8, 0x63, 0x00, 0x00, 0x00, 0xC3};  // mov eax,99; ret
        proc.write(*cave, stub, sizeof(stub));
        if (auto h = ce::installSimpleHook(proc, fnAddr, *cave)) {
            usleep(60000); hooked = res(); fired = (hooked == 99);
            ce::removeSimpleHook(proc, *h);
            usleep(60000); after = res(); restored = (after == before && before == 5);
        }
    }
    // Safety: refuse to hook a location whose displaced instructions include a
    // relative branch (a jmp at the very entry) rather than corrupt it.
    unsigned char reljmp[8] = {0xEB, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    if (auto bad = proc.allocate(64, ce::MemProt::Read | ce::MemProt::Write | ce::MemProt::Exec, fnAddr)) {
        proc.write(*bad, reljmp, sizeof(reljmp));
        refused_bad = !ce::installSimpleHook(proc, *bad, fnAddr).has_value();
    }

    kill(child, SIGKILL); int st = 0; waitpid(child, &st, 0);
    printf("  detour fires (5 -> 99): %s (before=%d hooked=%d)\n", fired ? "OK" : "FAILED", before, hooked);
    printf("  remove restores (-> 5): %s (after=%d)\n", restored ? "OK" : "FAILED", after);
    printf("  refuses position-dependent displaced code: %s\n", refused_bad ? "OK" : "FAILED");
}

// CE stringlist object: add/count/get (0-based)/set/remove/destroy.
void test_lua_stringlist() {
    printf("\n── Test: Lua stringlist API ──\n");
    ce::LuaEngine eng;
    auto run = [&](const char* c) { return eng.evalToString(c); };
    eng.execute("sl=createStringlist(); stringlist_add(sl,'a'); stringlist_add(sl,'b'); stringlist_add(sl,'c')");
    int count = 0; if (auto v = run("return stringlist_getCount(sl)")) count = std::atoi(v->c_str());
    std::string first, last;
    if (auto v = run("return stringlist_getString(sl,0)")) first = *v;
    if (auto v = run("return stringlist_getString(sl,2)")) last = *v;
    bool basic = count == 3 && first == "a" && last == "c";
    eng.execute("stringlist_setString(sl,1,'B'); stringlist_remove(sl,0)");
    std::string afterEdit; int afterCount = 0;
    if (auto v = run("return stringlist_getString(sl,0)")) afterEdit = *v;
    if (auto v = run("return stringlist_getCount(sl)")) afterCount = std::atoi(v->c_str());
    bool edit = afterEdit == "B" && afterCount == 2;   // removed 'a', 'b'->'B'
    printf("  add/count/get (0-based): %s\n", basic ? "OK" : "FAILED");
    printf("  set/remove: %s\n", edit ? "OK" : "FAILED");
}

// CE timer API: createTimer/timer_onTimer fire from pumpTimers(); disable + destroy.
void test_lua_timers() {
    printf("\n── Test: Lua timer API (createTimer/timer_onTimer/pump) ──\n");
    ce::LuaEngine eng;
    eng.execute("count=0; t=createTimer(20); timer_onTimer(t, function() count=count+1 end)");
    for (int i = 0; i < 6; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        eng.pumpTimers();
    }
    int fired = 0;
    if (auto v = eng.evalToString("return count")) fired = std::atoi(v->c_str());
    printf("  timer fires from pump (%d ticks): %s\n", fired, fired >= 4 ? "OK" : "FAILED");

    eng.execute("timer_setEnabled(t, false)");
    int before = fired;
    for (int i = 0; i < 3; ++i) { std::this_thread::sleep_for(std::chrono::milliseconds(25)); eng.pumpTimers(); }
    int after = before;
    if (auto v = eng.evalToString("return count")) after = std::atoi(v->c_str());
    printf("  disabled timer stops firing: %s\n", after == before ? "OK" : "FAILED");

    eng.execute("object_destroy(t)");   // must not crash / must stop firing
    for (int i = 0; i < 2; ++i) { std::this_thread::sleep_for(std::chrono::milliseconds(25)); eng.pumpTimers(); }
    int afterDestroy = after;
    if (auto v = eng.evalToString("return count")) afterDestroy = std::atoi(v->c_str());
    printf("  object_destroy stops + frees the timer: %s\n", afterDestroy == after ? "OK" : "FAILED");
}

// The diagnostic logging facility: level parsing, per-category gating, Off.
void test_logging() {
    printf("\n── Test: diagnostic logging (ce::log) ──\n");
    namespace log = ce::log;

    log::Level lv;
    bool parseOk = log::parseLevel("debug", lv) && lv == log::Level::Debug &&
                   log::parseLevel("WARN", lv)  && lv == log::Level::Warn &&
                   log::parseLevel("Trace", lv) && lv == log::Level::Trace &&
                   !log::parseLevel("nonsense", lv);
    printf("  parseLevel (names, case-insensitive): %s\n", parseOk ? "OK" : "FAILED");

    // Raising one category must not affect another.
    log::setLevelAll(log::Level::Warn);
    log::setLevel(log::Cat::Ptrace, log::Level::Trace);
    bool gateOk =
        log::enabled(log::Cat::Ptrace, log::Level::Trace) &&   // raised -> trace passes
        log::enabled(log::Cat::Ptrace, log::Level::Debug) &&
        !log::enabled(log::Cat::Scan, log::Level::Info) &&     // untouched -> still Warn
        !log::enabled(log::Cat::Scan, log::Level::Debug) &&
        log::enabled(log::Cat::Scan, log::Level::Warn) &&
        log::enabled(log::Cat::Scan, log::Level::Error);       // errors pass at Warn
    printf("  per-category level gating: %s\n", gateOk ? "OK" : "FAILED");

    // Off silences even errors for that category.
    log::setLevel(log::Cat::Lua, log::Level::Off);
    bool offOk = !log::enabled(log::Cat::Lua, log::Level::Error);
    printf("  Off silences a category: %s\n", offOk ? "OK" : "FAILED");

    log::setLevelAll(log::Level::Warn);   // restore baseline for the rest of the suite
}

// Format detection must be driven by file CONTENT, not extension: downloaded CE
// tables are commonly `.CT` (uppercase) or carry a wrong/missing extension, and a
// case-sensitive ".ct" check silently rejected them on Linux (the real bug).
void test_ct_format_detection() {
    printf("\n── Test: table format auto-detection (content, not extension) ──\n");
    namespace fs = std::filesystem;
    const char* xml =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<CheatTable>\n  <CheatEntries>\n    <CheatEntry>\n"
        "      <ID>1</ID>\n      <Description>\"HP\"</Description>\n"
        "      <VariableType>4 Bytes</VariableType>\n      <Address>00401000</Address>\n"
        "    </CheatEntry>\n  </CheatEntries>\n</CheatTable>\n";

    // XML content behind a deliberately WRONG extension must still be detected +
    // loaded via loadAuto (the extension lies; the content doesn't).
    auto wrongExt = fs::temp_directory_path() / "table_but_named.json";
    { std::ofstream o(wrongExt); o << xml; }
    bool xmlByContent = ce::detectTableFormat(wrongExt.string()) == ce::TableFormat::Xml;
    CheatTable a; bool xmlAutoOk = a.loadAuto(wrongExt.string()) &&
        a.entries.size() == 1 && a.entries[0].description == "HP";
    fs::remove(wrongExt);

    // Uppercase .CT (exactly the scenario that returned nil before the fix).
    auto upper = fs::temp_directory_path() / "GAME.CT";
    { std::ofstream o(upper); o << xml; }
    CheatTable b; bool upperOk = b.loadAuto(upper.string()) && b.entries.size() == 1;
    fs::remove(upper);

    // JSON content is detected as JSON, not misparsed as XML.
    CheatTable j; CheatEntry je; je.id = 1; je.description = "Gold";
    je.type = ValueType::Int32; je.address = 0x1000; j.entries = {je};
    auto jpath = fs::temp_directory_path() / "native.json";
    bool jsonSaved = j.saveJson(jpath.string());
    bool jsonDetect = ce::detectTableFormat(jpath.string()) == ce::TableFormat::Json;
    CheatTable jr; bool jsonAutoOk = jr.loadAuto(jpath.string()) &&
        jr.entries.size() == 1 && jr.entries[0].description == "Gold";
    fs::remove(jpath);

    // A password-protected payload is detected as Protected (loadAuto declines it,
    // since it needs a password, rather than silently corrupting).
    CheatTable p; p.entries = {je};
    auto ppath = fs::temp_directory_path() / "secret.CETRAINER";
    bool protSaved = p.saveProtected(ppath.string(), "pw");
    bool protDetect = ce::detectTableFormat(ppath.string()) == ce::TableFormat::Protected;
    CheatTable pr; bool protDeclined = !pr.loadAuto(ppath.string());
    fs::remove(ppath);

    printf("  XML content behind .json extension detected+loaded: %s\n",
           (xmlByContent && xmlAutoOk) ? "OK" : "FAILED");
    printf("  uppercase GAME.CT loads via loadAuto: %s\n", upperOk ? "OK" : "FAILED");
    printf("  JSON detected + loaded (not misparsed): %s\n",
           (jsonSaved && jsonDetect && jsonAutoOk) ? "OK" : "FAILED");
    printf("  protected .CETRAINER detected, loadAuto declines: %s\n",
           (protSaved && protDetect && protDeclined) ? "OK" : "FAILED");
}

// A .CT with an embedded <Forms> block must survive load -> save -> load, so
// editing a table with Delphi forms doesn't silently drop them.
void test_ct_forms_roundtrip() {
    printf("\n── Test: .CT Forms preservation ──\n");
    namespace fs = std::filesystem;
    const std::string formsInner = "<Form><Name>frmMain</Name><Data>AABBCC</Data></Form>";
    auto inPath  = fs::temp_directory_path() / ("cecore-forms-"     + std::to_string(getpid()) + ".CT");
    auto outPath = fs::temp_directory_path() / ("cecore-forms-out-" + std::to_string(getpid()) + ".CT");
    {
        std::ofstream o(inPath);
        o << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<CheatTable>\n"
          << "  <CheatEntries>\n"
          << "    <CheatEntry><ID>1</ID><Description>\"x\"</Description>"
             "<VariableType>4 Bytes</VariableType><Address>400000</Address></CheatEntry>\n"
          << "  </CheatEntries>\n"
          << "  <Forms>" << formsInner << "</Forms>\n"
          << "</CheatTable>\n";
    }

    CheatTable t1;
    bool loaded    = t1.load(inPath.string());
    bool captured  = t1.rawFormsXml == formsInner;
    bool saved     = t1.save(outPath.string());
    CheatTable t2;
    bool reloaded  = t2.load(outPath.string());
    bool preserved = t2.rawFormsXml == formsInner;

    std::error_code ec; fs::remove(inPath, ec); fs::remove(outPath, ec);
    bool ok = loaded && captured && saved && reloaded && preserved && !t1.entries.empty();
    printf("  <Forms> survives load -> save -> load: %s (captured=%d preserved=%d)\n",
           ok ? "OK" : "FAILED", (int)captured, (int)preserved);
}

void test_trainer_generation() {
    printf("\n── Test: Trainer Generation ──\n");

    CheatTable table;
    table.gameName = "Trainer \"Smoke\"\nGame";
    table.author = "cecore";
    table.luaScript = "print('table trainer lua')\n";

    CheatEntry entry;
    entry.description = "Health \"current\"\nline";
    entry.address = 0x12345678;
    entry.type = ValueType::Int32;
    entry.value = "1337";
    entry.hotkeyKeys = "Ctrl+H";
    entry.luaScript = "print('entry trainer lua')\n";
    entry.autoAsmScript = "[ENABLE]\nnop\n";
    table.entries.push_back(entry);

    // Float/Double entries with COMMA-decimal input (as typed under tr_TR): the
    // generator must normalize ','->'.' and emit valid C literals ("2.5f", "1.25"),
    // never "2,5f" (which would fail to compile in generateBinary below).
    CheatEntry fe;
    fe.description = "Speed";
    fe.address = 0x2000;
    fe.type = ValueType::Float;
    fe.value = "2,5";
    table.entries.push_back(fe);

    CheatEntry de;
    de.description = "Gravity";
    de.address = 0x2008;
    de.type = ValueType::Double;
    de.value = "1,25";
    table.entries.push_back(de);

    // Whole-number float: to_chars emits "9999" (no '.'), so the generator must add
    // a fractional part before the 'f' suffix — "9999.0f", never "9999f" (an invalid
    // integer-with-f-suffix that fails to compile). Regression guard for that bug.
    CheatEntry we;
    we.description = "Score";
    we.address = 0x2010;
    we.type = ValueType::Float;
    we.value = "9999";
    table.entries.push_back(we);

    // A pointer-path record as the GUI exports it: the path in addressString,
    // no offsets, and `address` only where it resolved this session.
    CheatEntry ptr;
    ptr.description = "Ammo";
    ptr.address = 0x7f00dead0000;
    ptr.addressString = "[[game+1C]+8]+10";
    ptr.type = ValueType::Int32;
    ptr.value = "99";
    table.entries.push_back(ptr);

    // Data formats: a 32-bit pointer is 4 bytes, a big-endian record is
    // stored reversed, and a directional freeze compares before writing.
    CheatEntry p32; p32.description = "P32"; p32.address = 0x3000; p32.type = ValueType::Pointer;
    p32.pointerWidth = 4; p32.value = "4096"; table.entries.push_back(p32);
    CheatEntry be; be.description = "BE"; be.address = 0x3010; be.type = ValueType::Int32;
    be.dataByteOrder = ByteOrder::Big; be.value = "7"; table.entries.push_back(be);
    CheatEntry floorE; floorE.description = "Floor"; floorE.address = 0x3020; floorE.type = ValueType::Int32;
    floorE.freezeMode = ce::FreezeMode::IncreaseOnly; floorE.value = "50"; table.entries.push_back(floorE);

    TrainerGenerator generator;
    auto source = generator.generateSource(table);
    printf("  trainer honours pointer width, byte order and freeze direction: %s\n",
           source.find("uint32_t v = 4096u; wpm((void*)0x3000, &v, 4);") != std::string::npos &&
           source.find("wpm((void*)0x3010, b, 4);") != std::string::npos &&
           source.find("cur < v) wpm((void*)0x3020, &v, 4);") != std::string::npos ? "OK" : "FAILED");
    printf("  pointer-path records are not written at a fixed address: %s\n",
           source.find("7f00dead0000") == std::string::npos ? "OK" : "FAILED");
    bool floatOk = source.find("2.5f") != std::string::npos &&
                   source.find("1.25") != std::string::npos &&
                   source.find("2,5") == std::string::npos &&   // comma never leaks into C
                   source.find("9999.0f") != std::string::npos &&
                   source.find("9999f") == std::string::npos;   // no int-with-f-suffix
    bool sourceOk =
        source.find("Trainer \\\"Smoke\\\"\\nGame") != std::string::npos &&
        source.find("Health \\\"current\\\"\\nline") != std::string::npos &&
        source.find("#include <sys/select.h>") != std::string::npos &&
        source.find("find_process_by_name") != std::string::npos &&
        source.find("else target_pid = find_process_by_name") != std::string::npos &&
        source.find("hotkey_matches") != std::string::npos &&
        source.find("\"Ctrl+H\"") != std::string::npos &&
        source.find("print_trainer_ui") != std::string::npos &&
        source.find("[%c]") != std::string::npos &&
        source.find("embedded_table_lua") != std::string::npos &&
        source.find("entry trainer lua") != std::string::npos &&
        source.find("[ENABLE]\\nnop\\n") != std::string::npos;

    auto outputPath = std::filesystem::temp_directory_path() /
        ("cecore-trainer-" + std::to_string(getpid()));
    // The compiler input lives in a private directory: a user's own file
    // named like "<output>.c" is neither overwritten nor deleted.
    const auto userSource = outputPath.string() + ".c";
    { std::ofstream mine(userSource); mine << "user source\n"; }
    auto error = generator.generateBinary(table, outputPath.string());
    bool binaryOk = error.empty() && std::filesystem::exists(outputPath);
    std::string userText;
    { std::ifstream mine(userSource); std::getline(mine, userText); }
    bool keptUserSource = userText == "user source";

    std::filesystem::remove(outputPath);
    std::filesystem::remove(userSource);
    bool keyLoopOk = source.find("read(0, &c, 1)") != std::string::npos &&
                     source.find("getchar") == std::string::npos &&
                     source.find("if (got == 0 ||") != std::string::npos;

    printf("  source escaping: %s\n", sourceOk ? "OK" : "FAILED");
    printf("  float/double comma-decimal emits valid C: %s\n", floatOk ? "OK" : "FAILED");
    printf("  binary compile: %s\n", binaryOk ? "OK" : "FAILED");
    printf("  trainer build leaves <output>.c alone: %s\n", keptUserSource ? "OK" : "FAILED");
    printf("  trainer key loop reads unbuffered and stops at end of input: %s\n", keyLoopOk ? "OK" : "FAILED");
    if (!error.empty())
        printf("    error: %s\n", error.c_str());
}

void test_code_analysis_references() {
    printf("\n── Test: Code Analysis References ──\n");

    const uintptr_t codeBase = 0x1000;
    const uintptr_t stringBase = 0x2000;
    const uintptr_t callTarget = 0x3000;

    std::vector<uint8_t> code = {
        0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, // lea rax, [rip + 0xff9] -> 0x2000
        0xe8, 0xf4, 0x1f, 0x00, 0x00,             // call 0x3000
        0xeb, 0x01,                                     // jmp 0x100f
        0xc3                                            // ret
    };
    code.insert(code.end(), 20, 0x00);
    std::vector<uint8_t> text = {'h', 'e', 'l', 'l', 'o', ' ', 'c', 'e', 0};

    ModuleInfo module{codeBase, 0x1000, "fake.so", "/tmp/fake.so", true};
    FakeProcessHandle proc({
        {{codeBase, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, module.path}, code},
        {{stringBase, text.size(), MemProt::Read, MemType::Image, MemState::Committed, module.path}, text},
    }, {module});

    CodeAnalyzer analyzer;
    auto strings = analyzer.findReferencedStrings(proc, module);
    auto functions = analyzer.findReferencedFunctions(proc, module);
    auto functionSummary = analyzer.enumerateFunctions(proc, module);
    auto callGraph = analyzer.buildCallGraph(proc, module);
    auto jumps = analyzer.findJumps(proc, module);
    auto ripRelative = analyzer.findRipRelativeInstructions(proc, module);
    auto statics = analyzer.findStatics(proc, module);
    auto assembly = analyzer.findAssemblyPattern(proc, module, "ret");
    auto caves = analyzer.findCodeCaves(proc, module, 16);

    bool stringOk = strings.size() == 1 && strings[0].address == codeBase &&
        strings[0].target == stringBase && strings[0].text == "hello ce";
    bool functionOk = functions.size() == 1 && functions[0].address == codeBase + 7 &&
        functions[0].target == callTarget;
    bool functionSummaryOk = functionSummary.size() == 1 &&
        functionSummary[0].address == callTarget &&
        functionSummary[0].references == 1;
    bool callGraphOk = callGraph.size() == 1 &&
        callGraph[0].caller == codeBase &&
        callGraph[0].callee == callTarget &&
        callGraph[0].callSite == codeBase + 7;
    bool jumpsOk = jumps.size() == 1 && jumps[0].address == codeBase + 12 &&
        jumps[0].target == codeBase + 15;
    bool ripOk = ripRelative.size() == 1 && ripRelative[0].address == codeBase &&
        ripRelative[0].target == stringBase;
    bool assemblyOk = assembly.size() == 1 && assembly[0].address == codeBase + 14;
    bool cavesOk = caves.size() == 1 && caves[0].address == codeBase + 15 && caves[0].size == 20;

    // Relative branches match away from module.base, where the pattern was
    // assembled: the rel field must reach the same target from each candidate.
    auto callHits = analyzer.findAssemblyPattern(proc, module, "call 0x3000");
    auto jmpHits = analyzer.findAssemblyPattern(proc, module, "jmp 0x100f");
    auto wrongTarget = analyzer.findAssemblyPattern(proc, module, "call 0x3001");
    bool relativeOk = callHits.size() == 1 && callHits[0].address == codeBase + 7 &&
        jmpHits.size() == 1 && jmpHits[0].address == codeBase + 12 && wrongTarget.empty();
    printf("  assembly pattern matches relative branches by target: %s\n", relativeOk ? "OK" : "FAILED");

    // 32-bit code: mov eax,[0x80001000] carries a disp32 that Capstone
    // sign-extends; the reference must still resolve to the high address.
    {
        const uintptr_t hiBase = 0x80000000;
        std::vector<uint8_t> code32 = {0x8B, 0x05, 0x00, 0x10, 0x00, 0x80, 0xC3};
        ModuleInfo module32{hiBase, 0x2000, "game.exe", "/tmp/game.exe", false};
        FakeProcessHandle proc32({
            {{hiBase, code32.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, module32.path}, code32},
        }, {module32}, /*is64bit=*/false);
        CodeAnalyzer analyzer32(Arch::X86_32);
        auto refs32 = analyzer32.findRipRelativeInstructions(proc32, module32);
        bool highOk = refs32.size() == 1 && refs32[0].address == hiBase && refs32[0].target == hiBase + 0x1000;
        printf("  32-bit absolute reference above 2 GB resolves: %s\n", highOk ? "OK" : "FAILED");
    }

    // Disassembler resolves the RIP-relative operand to its absolute address and
    // records it in Instruction::ripTarget (the lea at codeBase points to stringBase).
    ce::Disassembler dis(ce::Arch::X86_64);
    auto insns = dis.disassemble(codeBase, {code.data(), code.size()}, 1);
    bool ripResolveOk = insns.size() == 1 &&
        insns[0].ripTarget == stringBase &&
        insns[0].operands.find("0x2000") != std::string::npos &&
        insns[0].operands.find("rip") == std::string::npos;

    printf("  Disassembler RIP resolution: %s\n", ripResolveOk ? "OK" : "FAILED");

    // An indirect branch through a RIP-relative pointer slot (a PLT stub) must
    // resolve ripTarget too, and its operand is a memory reference ('['). The
    // memory browser's "Follow operand" relies on both: parseImmediate bails on the
    // '[' (so it doesn't mistake the displacement 0x2ede for a target) and follows
    // ripTarget (the pointer slot) instead. ff 25 de 2e 00 00 = jmp qword [rip+0x2ede].
    uint8_t pltJmp[] = {0xff, 0x25, 0xde, 0x2e, 0x00, 0x00};
    uintptr_t pltAt = 0x555555000000;
    auto pj = dis.disassemble(pltAt, {pltJmp, sizeof(pltJmp)}, 1);
    bool pltOk = pj.size() == 1 && pj[0].mnemonic == "jmp" &&
        pj[0].ripTarget == pltAt + 6 + 0x2ede &&
        pj[0].operands.find('[') != std::string::npos;
    printf("  Disassembler resolves indirect jmp ripTarget (PLT follow): %s\n", pltOk ? "OK" : "FAILED");

    // Back-disassembly (previousInstruction): nop; nop; mov eax,1 (5B); ret.
    // Layout: c+0 nop, c+1 nop, c+2..c+6 mov, c+7 ret. The read callback refuses
    // out-of-buffer reads, emulating a region boundary (the old fixed-lookback
    // code read unmapped memory there and mis-reported the previous instruction).
    std::vector<uint8_t> backCode = {0x90, 0x90, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3};
    const uintptr_t bc = 0x400000;
    auto backRead = [&](uintptr_t a, uint8_t* buf, size_t n) {
        if (a < bc || a + n > bc + backCode.size()) return false;
        std::memcpy(buf, backCode.data() + (a - bc), n);
        return true;
    };
    bool backOk =
        dis.previousInstruction(bc + 7, backRead) == bc + 2 &&   // before ret -> mov start
        dis.previousInstruction(bc + 2, backRead) == bc + 1 &&   // before mov -> 2nd nop
        dis.previousInstruction(bc + 1, backRead) == bc + 0;     // before 2nd nop -> 1st nop
    printf("  Disassembler previousInstruction: %s\n", backOk ? "OK" : "FAILED");

    // emitDataBytes: an undecodable byte (0xFF at a spot Capstone can't start an
    // instruction) becomes "db" and disassembly continues instead of stopping.
    // nop(90); <bad>; nop(90). Without emitDataBytes it stops at the bad byte.
    // 0x0f without a following modrm is an incomplete/undecodable opcode here.
    std::vector<uint8_t> gapCode = {0x90, 0x0f, 0x90};
    auto strict = dis.disassemble(0x1000, {gapCode.data(), gapCode.size()}, 0, /*emitDataBytes=*/false);
    auto filled = dis.disassemble(0x1000, {gapCode.data(), gapCode.size()}, 0, /*emitDataBytes=*/true);
    // strict stops early (fewer than 3 entries, never reaches the trailing nop);
    // filled emits a db for the 0x0f and continues to the final nop at 0x1002.
    bool gapOk = filled.size() > strict.size() &&
                 std::any_of(filled.begin(), filled.end(),
                     [](const ce::Instruction& i){ return i.mnemonic == "db"; }) &&
                 filled.back().address == 0x1002 && filled.back().mnemonic == "nop";
    printf("  Disassembler emitDataBytes (db fallback): %s\n", gapOk ? "OK" : "FAILED");

    // Round-trip: a RIP-relative instruction is displayed with its operand
    // rewritten to [0x<abs>]. Re-assembling that resolved text at the same address
    // should reproduce the original bytes (so "Assemble" on such an insn is safe).
    {
        ce::Assembler rtAsm(ce::AsmArch::X86_64);
        const uintptr_t A = 0x401000;
        auto orig = rtAsm.assemble("lea rax, [rip+0x100]", A);
        bool rtOk = false;
        if (orig) {
            auto di = dis.disassemble(A, {orig->data(), orig->size()}, 1);
            if (!di.empty() && di[0].ripTarget != 0) {
                std::string text = di[0].mnemonic + " " + di[0].operands;  // lea rax, [0x401107]
                auto re = rtAsm.assemble(text, A);
                rtOk = re && *re == *orig;
            }
        }
        printf("  RIP-resolved operand re-assembles to same bytes: %s\n", rtOk ? "OK" : "FAILED");
    }

    // Relocation invariant — the crux of RIP-relative code injection. Because the
    // disassembler rewrites [rip+disp] to its absolute [0x<abs>], a stolen
    // RIP-relative instruction re-assembled at a DIFFERENT address (the cave)
    // still points at the SAME absolute target (Keystone recomputes the disp for
    // the new site). Without the absolute rewrite it would silently retarget.
    {
        ce::Assembler rtAsm(ce::AsmArch::X86_64);
        const uintptr_t A = 0x401000, B = 0x410000;  // cave within ±2GB of target
        auto orig = rtAsm.assemble("mov eax, dword ptr [rip+0x1234]", A);
        bool relocOk = false;
        if (orig) {
            auto dA = dis.disassemble(A, {orig->data(), orig->size()}, 1);
            if (!dA.empty() && dA[0].ripTarget != 0) {
                std::string text = dA[0].mnemonic + " " + dA[0].operands;  // [0x<abs>]
                auto atB = rtAsm.assemble(text, B);
                if (atB) {
                    auto dB = dis.disassemble(B, {atB->data(), atB->size()}, 1);
                    // The relocated insn must reference the SAME absolute target.
                    // Compare by the resolved address in the operand text, not
                    // ripTarget: Keystone may pick the moffs (absolute) encoding at
                    // the new site, which has no RIP base but still hits 0x<abs>.
                    char tgt[32];
                    std::snprintf(tgt, sizeof(tgt), "0x%llx",
                                  (unsigned long long)dA[0].ripTarget);
                    relocOk = !dB.empty() &&
                              dB[0].operands.find(tgt) != std::string::npos;
                }
            }
        }
        printf("  RIP-relative stolen insn keeps target when relocated to cave: %s\n",
               relocOk ? "OK" : "FAILED");
    }

    // A relative branch more than 2 GiB away is an error, not a wrapped
    // displacement that lands somewhere else.
    {
        ce::Assembler far(ce::AsmArch::X86_64);
        auto jumpFar = far.assemble("jmp 0x100000000000", 0x1000);
        auto callFar = far.assemble("call 0x100000000000", 0x1000);
        auto jumpNear = far.assemble("jmp 0x2000", 0x1000);
        printf("  a branch out of rel32 reach fails instead of wrapping: %s\n",
               !jumpFar && !callFar && jumpNear ? "OK" : "FAILED");
    }

    // Assemble<->disassemble round-trip idempotency for instructions common in
    // code injection. assemble(text) -> bytes -> disassemble -> text2 ->
    // assemble(text2) -> bytes2; bytes2 must equal bytes (the canonical
    // disassembly must re-assemble to the same encoding). Catches asm/disasm
    // encoding drift without depending on exact textual equality of the original.
    {
        ce::Assembler rt(ce::AsmArch::X86_64);
        ce::Disassembler rd(ce::Arch::X86_64);
        const uintptr_t A = 0x401000;
        const char* insns[] = {
            "push rbp", "pop rbp", "mov eax, 1", "xor eax, eax", "add rax, rbx",
            "sub rsp, 0x20", "ret", "nop", "lea rax, [rbx+rcx*4+0x10]",
            "mov [rax+8], rbx", "cmp rax, 0x10", "test eax, eax", "call 0x401234",
            "jmp 0x401500", "jne 0x401050", "movzx eax, byte ptr [rdx]",
            // SSE / float math (common in game code injection)
            "movss xmm0, dword ptr [rax]", "addss xmm0, xmm1", "mulss xmm0, dword ptr [rbx]",
            "movsd xmm0, qword ptr [rax]", "cvtsi2ss xmm0, eax", "comiss xmm0, xmm1",
            "subps xmm0, xmm1", "movaps xmm2, xmm3",
            // Prefixed instructions (appear throughout real code / injection sites)
            "lock inc dword ptr [rax]", "lock xadd qword ptr [rbx], rcx",
            "rep movsb", "rep stosd", "pause", "lock cmpxchg dword ptr [rdi], esi",
            // x64-specific: 64-bit immediates, bit ops, shifts, misc
            "movabs rax, 0x123456789abcdef0", "cqo", "cdqe", "rdtsc", "bswap eax",
            "bt rax, 5", "shld rax, rbx, 4", "imul rax, rbx, 0x10", "shl rax, cl",
            // Segment override + size specifier (stripPtrKeyword must not corrupt these)
            "mov qword ptr fs:[0x28], rax", "mov eax, dword ptr gs:[0x10]",
            // AVX / VEX-encoded (modern game code — 256-bit ymm and 3-operand forms)
            "vmovups ymm0, ymmword ptr [rax]", "vaddps ymm0, ymm1, ymm2",
            "vxorps xmm0, xmm0, xmm0", "vmovaps ymm5, ymm6", "vmulsd xmm0, xmm1, xmm2",
        };
        // Safety property: re-assembling the canonical disassembly must EITHER
        // reproduce the original bytes OR cleanly fail — never silently succeed
        // with wrong/empty bytes (which would let the GUI NOP-pad over real code).
        int match = 0, safeErr = 0, unsafe = 0;
        for (const char* ins : insns) {
            auto b1 = rt.assemble(ins, A);
            if (!b1) continue;                 // Keystone can't encode it -> skip
            auto d = rd.disassemble(A, {b1->data(), b1->size()}, 1);
            if (d.empty()) continue;
            std::string text = d[0].operands.empty() ? d[0].mnemonic
                                                      : d[0].mnemonic + " " + d[0].operands;
            auto b2 = rt.assemble(text, A);
            if (b2 && *b2 == *b1) ++match;
            else if (!b2)         ++safeErr;   // clean error -> GUI shows a message
            else                  ++unsafe;    // BAD: success with different/empty bytes
        }
        printf("  asm<->disasm round-trip safe (match=%d safeErr=%d unsafe=%d): %s\n",
               match, safeErr, unsafe, (unsafe == 0 && safeErr == 0) ? "OK" : "FAILED");

        // Direct exact-encoding check that the assembler uses the target address for
        // the rel32 (the memory-view "Assemble" path passes the instruction address):
        // jmp 0x401500 @ 0x401000 -> e9 <0x401500-(0x401000+5)=0x4fb> = e9 fb 04 00 00.
        auto jrel = rt.assemble("jmp 0x401500", 0x401000);
        bool jrelOk = jrel && jrel->size() == 5 &&
            (*jrel)[0] == 0xe9 && (*jrel)[1] == 0xfb && (*jrel)[2] == 0x04 &&
            (*jrel)[3] == 0x00 && (*jrel)[4] == 0x00;
        // Same instruction one page higher must encode a different rel32 (address is
        // actually consumed, not ignored): jmp 0x401500 @ 0x402000 -> negative rel.
        auto jrel2 = rt.assemble("jmp 0x401500", 0x402000);
        bool addrUsed = jrel2 && jrel2->size() == 5 && (*jrel2) != (*jrel);
        printf("  assembler uses branch address for rel32: %s\n",
               (jrelOk && addrUsed) ? "OK" : "FAILED");
    }
    printf("  Referenced strings: %s\n", stringOk ? "OK" : "FAILED");
    printf("  Referenced functions: %s\n", functionOk ? "OK" : "FAILED");
    printf("  Function enumeration: %s\n", functionSummaryOk ? "OK" : "FAILED");
    printf("  Call graph: %s\n", callGraphOk ? "OK" : "FAILED");
    printf("  Jump detection: %s\n", jumpsOk ? "OK" : "FAILED");
    printf("  RIP-relative instructions: %s\n", ripOk ? "OK" : "FAILED");

    // findStatics aggregates RIP-relative targets by reference count. Here the one
    // rip-relative insn (the lea) points at stringBase, referenced once.
    bool staticsOk = statics.size() == 1 && statics[0].address == stringBase &&
                     statics[0].references == 1;
    printf("  Find statics (referenced static addresses): %s\n", staticsOk ? "OK" : "FAILED");
    printf("  Assembly pattern scan: %s\n", assemblyOk ? "OK" : "FAILED");
    printf("  Code caves: %s\n", cavesOk ? "OK" : "FAILED");
}

// Static "find what references this address": a module with a rip-relative load
// and a call, both targeting the same data address. findReferencesTo must return
// both referencing instructions (no runtime execution).
void test_find_references_static() {
    printf("\n── Test: static find-references ──\n");
    const uintptr_t base = 0x400000, target = base + 0x800;
    std::vector<uint8_t> code(0x1000, 0x90);   // nop sled
    // @0x100: mov rax,[rip+disp] -> target. len 7; disp = target-(base+0x100+7).
    uint32_t disp = (uint32_t)(target - (base + 0x100 + 7));
    uint8_t rip[7] = {0x48, 0x8B, 0x05,
                      (uint8_t)disp, (uint8_t)(disp >> 8), (uint8_t)(disp >> 16), (uint8_t)(disp >> 24)};
    std::memcpy(code.data() + 0x100, rip, 7);
    // @0x200: call rel32 -> target. len 5; rel = target-(base+0x200+5).
    uint32_t rel = (uint32_t)(target - (base + 0x200 + 5));
    uint8_t call[5] = {0xE8, (uint8_t)rel, (uint8_t)(rel >> 8), (uint8_t)(rel >> 16), (uint8_t)(rel >> 24)};
    std::memcpy(code.data() + 0x200, call, 5);

    FakeProcessHandle proc({
        {{base, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, "/tmp/game"}, code},
    }, {
        {base, code.size(), "game", "/tmp/game", true},
    });

    ce::CodeAnalyzer an;
    ce::ModuleInfo mod{base, code.size(), "game", "/tmp/game", true};
    auto refs = an.findReferencesTo(proc, mod, target);
    bool hasRip = false, hasCall = false;
    for (const auto& r : refs) {
        if (r.address == base + 0x100) hasRip = true;
        if (r.address == base + 0x200) hasCall = true;
    }
    printf("  finds rip-relative + call references to a data address: %s (%zu refs)\n",
           (hasRip && hasCall) ? "OK" : "FAILED", refs.size());
}

// Decoding an instruction's memory operand + resolving the address it accesses
// from register state (the primitive behind "find what addresses this
// instruction accesses" and richer disassembly display).
// The disassembler is multi-arch (Capstone). Verify it decodes x86-32, ARM32,
// and ARM64 — the non-hardware, testable slices of #25 (ARM) and #26 (32-bit).
// Arches Capstone was built without are reported SKIPPED, not FAILED.
void test_disassembler_multiarch() {
    printf("\n── Test: multi-arch disassembly ──\n");
    auto tryOne = [](Arch arch, std::vector<uint8_t> bytes, const std::string& mnem) -> int {
        try {
            Disassembler dis(arch);
            auto insns = dis.disassemble(0x1000, {bytes.data(), bytes.size()}, 1);
            if (insns.empty()) return 0;
            return insns[0].mnemonic == mnem ? 1 : 0;
        } catch (const std::exception&) { return -1; }   // arch unsupported by Capstone
    };
    int x32 = tryOne(Arch::X86_32, {0xC3}, "ret");                     // ret
    int a32 = tryOne(Arch::ARM32,  {0x00, 0xF0, 0x20, 0xE3}, "nop");   // 0xE320F000
    int a64 = tryOne(Arch::ARM64,  {0x1F, 0x20, 0x03, 0xD5}, "nop");   // 0xD503201F
    auto s = [](int r) { return r == 1 ? "OK" : r == 0 ? "FAILED" : "SKIPPED"; };
    bool ok = x32 == 1 && a32 != 0 && a64 != 0;   // x86-32 must work; ARM OK or skipped
    printf("  x86-32/ARM32/ARM64 decode: %s (x32=%s arm32=%s arm64=%s)\n",
           ok ? "OK" : "FAILED", s(x32), s(a32), s(a64));
}

void test_effective_address() {
    printf("\n── Test: instruction effective-address ──\n");
    Disassembler dis(Arch::X86_64);

    // mov eax, [rbx + rcx*4 + 0x10]  ->  8B 44 8B 10
    uint8_t code1[] = {0x8B, 0x44, 0x8B, 0x10};
    auto i1 = dis.disassemble(0x1000, code1, 1);
    bool ok1 = false;
    if (!i1.empty()) {
        CpuContext ctx{}; ctx.rbx = 0x2000; ctx.rcx = 0x3;
        uintptr_t ea = computeEffectiveAddress(i1[0], ctx);
        ok1 = i1[0].memory.present && !i1[0].memory.ripRelative &&
              i1[0].memory.baseReg == "rbx" && i1[0].memory.indexReg == "rcx" &&
              i1[0].memory.scale == 4 &&
              ea == static_cast<uintptr_t>(0x2000 + 0x3 * 4 + 0x10);
    }
    printf("  base+index*scale+disp: %s\n", ok1 ? "OK" : "FAILED");

    // mov eax, [rip + 0x100]  ->  8B 05 00 01 00 00  (EA = next_rip + 0x100)
    uint8_t code2[] = {0x8B, 0x05, 0x00, 0x01, 0x00, 0x00};
    auto i2 = dis.disassemble(0x1000, code2, 1);
    bool ok2 = false;
    if (!i2.empty()) {
        uintptr_t ea = computeEffectiveAddress(i2[0], CpuContext{});
        ok2 = i2[0].memory.present && i2[0].memory.ripRelative &&
              ea == static_cast<uintptr_t>(0x1000 + i2[0].size + 0x100);
    }
    printf("  rip-relative: %s\n", ok2 ? "OK" : "FAILED");

    // nop  ->  90  (no memory operand)
    uint8_t code3[] = {0x90};
    auto i3 = dis.disassemble(0x1000, code3, 1);
    bool ok3 = !i3.empty() && !i3[0].memory.present &&
               computeEffectiveAddress(i3[0], CpuContext{}) == 0;
    printf("  no-memory instruction: %s\n", ok3 ? "OK" : "FAILED");

    // mov rax, fs:[0x28] -> 64 48 8B 04 25 28 00 00 00: thread-local, and the
    // context has no fs base, so no address rather than 0x28.
    uint8_t code4[] = {0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00};
    auto i4 = dis.disassemble(0x1000, code4, 1);
    CpuContext ctx4{}; ctx4.fs = 0x53;
    bool ok4 = !i4.empty() && i4[0].memory.present && i4[0].memory.segmentReg == "fs" &&
               computeEffectiveAddress(i4[0], ctx4) == 0;
    printf("  fs-relative operand reports no address: %s\n", ok4 ? "OK" : "FAILED");
}

void test_managed_runtime_detection() {
    printf("\n── Test: Managed runtime detection ──\n");

    FakeProcessHandle proc({}, {
        {0x100000, 0x20000, "libmonosgen-2.0.so", "/usr/lib/libmonosgen-2.0.so", true},
        {0x200000, 0x30000, "libclrjit.so", "/opt/dotnet/shared/Microsoft.NETCore.App/libclrjit.so", true},
        {0x300000, 0x10000, "libnative.so", "/tmp/libnative.so", true},
    });
    auto runtimes = detectManagedRuntimes(proc);

    FakeProcessHandle nativeOnly({}, {
        {0x400000, 0x10000, "libc.so.6", "/usr/lib/libc.so.6", true},
    });
    auto none = detectManagedRuntimes(nativeOnly);

    bool monoOk = std::any_of(runtimes.begin(), runtimes.end(), [](const ManagedRuntimeInfo& info) {
        return info.kind == ManagedRuntimeKind::Mono &&
            info.name == "Mono" &&
            info.moduleName == "libmonosgen-2.0.so";
    });
    bool coreClrOk = std::any_of(runtimes.begin(), runtimes.end(), [](const ManagedRuntimeInfo& info) {
        return info.kind == ManagedRuntimeKind::CoreCLR &&
            info.name == "CoreCLR" &&
            info.moduleName == "libclrjit.so";
    });

    printf("  Mono/CoreCLR modules: %s\n",
        (monoOk && coreClrOk && none.empty()) ? "OK" : "FAILED");
}

void test_managed_object_enumeration() {
    printf("\n── Test: Managed object enumeration ──\n");

    constexpr uintptr_t metadataBase = 0x500000;
    constexpr uintptr_t heapBase = 0x800000;
    std::vector<uint8_t> metadata(0x200, 0);
    std::vector<uint8_t> heap(0x200, 0);

    uintptr_t playerType = metadataBase + 0x40;
    uintptr_t inventoryType = metadataBase + 0x90;
    uintptr_t nativePointer = 0x12345678;
    std::memcpy(heap.data() + 0x20, &playerType, sizeof(playerType));
    std::memcpy(heap.data() + 0x80, &inventoryType, sizeof(inventoryType));
    std::memcpy(heap.data() + 0xc0, &nativePointer, sizeof(nativePointer));

    FakeProcessHandle proc({
        {{metadataBase, metadata.size(), MemProt::Read, MemType::Image, MemState::Committed, "/opt/dotnet/System.Private.CoreLib.dll"}, metadata},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[managed heap]"}, heap},
    }, {
        {metadataBase, metadata.size(), "System.Private.CoreLib.dll", "/opt/dotnet/System.Private.CoreLib.dll", true},
    });

    ManagedObjectEnumerationConfig config;
    config.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto objects = enumerateManagedObjects(proc, config);

    config.heapStart = heapBase + 0x70;
    config.heapEnd = heapBase + 0x100;
    config.maxObjects = 1;
    auto bounded = enumerateManagedObjects(proc, config);

    bool playerOk = std::any_of(objects.begin(), objects.end(), [&](const ManagedObjectInfo& object) {
        return object.address == heapBase + 0x20 &&
            object.typeHandle == playerType &&
            object.runtimeKind == ManagedRuntimeKind::CoreCLR &&
            object.regionPath == "[managed heap]";
    });
    bool inventoryOk = std::any_of(objects.begin(), objects.end(), [&](const ManagedObjectInfo& object) {
        return object.address == heapBase + 0x80 && object.typeHandle == inventoryType;
    });
    bool boundedOk = bounded.size() == 1 &&
        bounded.front().address == heapBase + 0x80 &&
        bounded.front().typeHandle == inventoryType;

    printf("  object headers: %s\n",
        (objects.size() == 2 && playerOk && inventoryOk && boundedOk) ? "OK" : "FAILED");
}

void test_managed_type_extraction() {
    printf("\n── Test: Managed type extraction ──\n");

    constexpr uintptr_t metadataBase = 0x510000;
    constexpr uintptr_t heapBase = 0x810000;
    std::vector<uint8_t> metadata(0x300, 0);
    std::vector<uint8_t> heap(0x200, 0);

    uintptr_t playerType = metadataBase + 0x40;
    uintptr_t inventoryType = metadataBase + 0x80;
    uintptr_t playerName = metadataBase + 0x140;
    uintptr_t playerNamespace = metadataBase + 0x180;
    uintptr_t inventoryName = metadataBase + 0x1c0;
    uintptr_t inventoryNamespace = metadataBase + 0x200;

    std::memcpy(metadata.data() + 0x40, &playerName, sizeof(playerName));
    std::memcpy(metadata.data() + 0x48, &playerNamespace, sizeof(playerNamespace));
    std::memcpy(metadata.data() + 0x80, &inventoryName, sizeof(inventoryName));
    std::memcpy(metadata.data() + 0x88, &inventoryNamespace, sizeof(inventoryNamespace));
    std::memcpy(metadata.data() + 0x140, "Player", sizeof("Player"));
    std::memcpy(metadata.data() + 0x180, "Game.Entities", sizeof("Game.Entities"));
    std::memcpy(metadata.data() + 0x1c0, "Inventory", sizeof("Inventory"));
    std::memcpy(metadata.data() + 0x200, "Game.Items", sizeof("Game.Items"));

    std::memcpy(heap.data() + 0x20, &playerType, sizeof(playerType));
    std::memcpy(heap.data() + 0x80, &inventoryType, sizeof(inventoryType));
    std::memcpy(heap.data() + 0xa0, &playerType, sizeof(playerType));

    FakeProcessHandle proc({
        {{metadataBase, metadata.size(), MemProt::Read, MemType::Image, MemState::Committed, "/opt/dotnet/System.Private.CoreLib.dll"}, metadata},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[managed heap]"}, heap},
    }, {
        {metadataBase, metadata.size(), "System.Private.CoreLib.dll", "/opt/dotnet/System.Private.CoreLib.dll", true},
    });

    ManagedObjectEnumerationConfig objectConfig;
    objectConfig.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto objects = enumerateManagedObjects(proc, objectConfig);

    ManagedTypeExtractionConfig typeConfig;
    typeConfig.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto types = extractManagedObjectTypes(proc, objects, typeConfig);

    bool playerOk = std::any_of(types.begin(), types.end(), [&](const ManagedTypeInfo& type) {
        return type.typeHandle == playerType &&
            type.name == "Player" &&
            type.namespaceName == "Game.Entities" &&
            type.runtimeKind == ManagedRuntimeKind::CoreCLR;
    });
    bool inventoryOk = std::any_of(types.begin(), types.end(), [&](const ManagedTypeInfo& type) {
        return type.typeHandle == inventoryType &&
            type.name == "Inventory" &&
            type.namespaceName == "Game.Items";
    });

    printf("  type names: %s\n",
        (objects.size() == 3 && types.size() == 2 && playerOk && inventoryOk) ? "OK" : "FAILED");
}

void test_gdb_remote_client() {
    printf("\n── Test: GDB remote client ──\n");

    auto checksum = [](const std::string& payload) {
        uint8_t sum = 0;
        for (unsigned char c : payload)
            sum = static_cast<uint8_t>(sum + c);
        return sum;
    };
    auto sendPacket = [&](int fd, const std::string& payload) {
        char suffix[4];
        std::snprintf(suffix, sizeof(suffix), "#%02x", checksum(payload));
        std::string packet = "$" + payload + suffix;
        ::send(fd, packet.data(), packet.size(), 0);
        char ack = 0;
        ::recv(fd, &ack, 1, MSG_WAITALL);
    };
    auto readPacket = [](int fd) {
        char c = 0;
        do {
            if (::recv(fd, &c, 1, MSG_WAITALL) != 1)
                return std::string{};
        } while (c != '$');

        std::string payload;
        while (::recv(fd, &c, 1, MSG_WAITALL) == 1 && c != '#')
            payload.push_back(c);
        char ignored[2] = {};
        ::recv(fd, ignored, 2, MSG_WAITALL);
        ::send(fd, "+", 1, 0);
        return payload;
    };

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool setupOk = server >= 0 &&
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(server, 1) == 0;
    socklen_t addrLen = sizeof(addr);
    if (setupOk)
        setupOk = ::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0;

    if (!setupOk) {
        if (server >= 0) ::close(server);
        printf("  packet exchange: FAILED\n");
        return;
    }

    bool serverOk = false;
    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0)
            return;

        auto first = readPacket(client);
        sendPacket(client, "01020304");
        auto second = readPacket(client);
        sendPacket(client, "11223344");
        // gdbserver run-length encodes 14 more zeros with the count '+'.
        auto third = readPacket(client);
        sendPacket(client, "10*+");

        serverOk = first == "g" && second == "m1000,4" && third == "m2000,8";
        ::close(client);
    });

    GdbRemoteClient client;
    std::string error;
    bool connected = client.connectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    std::expected<std::string, std::string> regs = std::unexpected(error);
    std::expected<std::vector<uint8_t>, std::string> mem = std::unexpected(error);
    std::expected<std::vector<uint8_t>, std::string> runLength = std::unexpected(error);
    if (connected) {
        regs = client.readRegisters();
        mem = client.readMemory(0x1000, 4);
        runLength = client.readMemory(0x2000, 8);
    }
    stub.join();
    bool disconnectOk = connected && !client.readRegisters() && !client.readRegisters();
    client.close();
    ::close(server);

    bool ok = connected &&
        regs && *regs == "01020304" &&
        mem && *mem == std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}) &&
        serverOk;
    printf("  packet exchange: %s\n", ok ? "OK" : "FAILED");
    printf("  run-length counts '+' and '-' as gdbserver sends them: %s\n",
           runLength && *runLength == std::vector<uint8_t>({0x10, 0, 0, 0, 0, 0, 0, 0}) ? "OK" : "FAILED");
    printf("  disconnected GDB peer returns errors without SIGPIPE: %s\n", disconnectOk ? "OK" : "FAILED");
}

// Only our own processes are opened, even with cap_sys_ptrace (the .deb sets
// it on the binaries to get past Yama).
void test_process_owner_check() {
    printf("\n── Test: Other users' processes are refused ──\n");
    const bool self = ce::processOwnedByCaller(getpid());
    bool foreign = true;
    if (getuid() != 0) {
        ce::os::LinuxProcessHandle init(1);   // root's
        uint8_t byte = 0;
        foreign = !ce::processOwnedByCaller(1) && init.targetDescription().otherOwner && !init.read(0x1000, &byte, 1) &&
                  ce::seizeIfOwned(1, 0) == -1 && errno == EPERM &&
                  ce::targetOperationError(init, ce::TargetFeature::ReadMemory).find("another user") != std::string::npos;
    }
    printf("  own processes allowed, another user's refused: %s\n", self && foreign ? "OK" : "FAILED");
}

void test_ceserver_client() {
    printf("\n── Test: ceserver TCP client ──\n");

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool setupOk = server >= 0 &&
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(server, 1) == 0;
    socklen_t addrLen = sizeof(addr);
    if (setupOk)
        setupOk = ::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0;

    if (!setupOk) {
        if (server >= 0) ::close(server);
        printf("  version handshake: FAILED\n");
        return;
    }

    bool serverOk = false;
    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0)
            return;

        uint8_t command = 0xff;
        ::recv(client, &command, sizeof(command), MSG_WAITALL);
        int32_t protocol = 6;
        const std::string version = "CHEATENGINE Network 2.3";
        uint8_t size = static_cast<uint8_t>(version.size());
        ::send(client, &protocol, sizeof(protocol), 0);
        ::send(client, &size, sizeof(size), 0);
        ::send(client, version.data(), version.size(), 0);
        serverOk = command == 0;
        ::close(client);
    });

    CEServerClient client;
    std::string error;
    bool connected = client.connectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    std::expected<CEServerVersionInfo, std::string> version = std::unexpected(error);
    if (connected)
        version = client.getVersion();
    stub.join();
    bool disconnectOk = connected && !client.getVersion() && !client.getVersion();
    client.close();
    ::close(server);

    bool ok = connected &&
        version &&
        version->protocolVersion == 6 &&
        version->versionString == "CHEATENGINE Network 2.3" &&
        serverOk;
    printf("  version handshake: %s\n", ok ? "OK" : "FAILED");
    printf("  disconnected ceserver peer returns errors without SIGPIPE: %s\n", disconnectOk ? "OK" : "FAILED");
}

// Exercises the Mono soft-debugger client against an in-process mock agent that
// speaks the real wire framing (13-byte handshake, then 11-byte packet headers).
// Verifies the handshake, VM/Version string+ints decode, VM/AllThreads id decode,
// empty-reply commands, and that a non-zero agent error code is surfaced rather
// than parsed as a body. It cannot prove the cmdset/cmd numbers match a real
// Mono runtime (that needs a live target), but it locks the framing + parsing.
void test_mono_debugger_client() {
    printf("\n── Test: Mono soft-debugger client ──\n");

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool setupOk = server >= 0 &&
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(server, 1) == 0;
    socklen_t addrLen = sizeof(addr);
    if (setupOk)
        setupOk = ::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0;
    if (!setupOk) {
        if (server >= 0) ::close(server);
        printf("  setup: FAILED\n");
        return;
    }

    bool handshakeSeen = false;
    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0) return;

        auto recvExact = [&](void* buf, size_t n) {
            size_t got = 0; auto* p = static_cast<uint8_t*>(buf);
            while (got < n) {
                ssize_t r = ::recv(client, p + got, n - got, MSG_WAITALL);
                if (r <= 0) return false;
                got += static_cast<size_t>(r);
            }
            return true;
        };
        auto be32 = [](std::vector<uint8_t>& v, uint32_t x) {
            v.push_back(static_cast<uint8_t>(x >> 24));
            v.push_back(static_cast<uint8_t>(x >> 16));
            v.push_back(static_cast<uint8_t>(x >> 8));
            v.push_back(static_cast<uint8_t>(x));
        };

        // Handshake: the client sends first, the agent echoes it back.
        char hs[13] = {0};
        if (!recvExact(hs, 13)) { ::close(client); return; }
        handshakeSeen = std::memcmp(hs, "DWP-Handshake", 13) == 0;
        ::send(client, "DWP-Handshake", 13, 0);

        for (;;) {
            uint8_t hdr[11];
            if (!recvExact(hdr, 11)) break;
            uint32_t len = static_cast<uint32_t>(hdr[0]) << 24 |
                           static_cast<uint32_t>(hdr[1]) << 16 |
                           static_cast<uint32_t>(hdr[2]) << 8  | hdr[3];
            int32_t id = static_cast<int32_t>(
                static_cast<uint32_t>(hdr[4]) << 24 | static_cast<uint32_t>(hdr[5]) << 16 |
                static_cast<uint32_t>(hdr[6]) << 8  | hdr[7]);
            uint8_t cmdset = hdr[9], cmd = hdr[10];
            std::vector<uint8_t> payload(len > 11 ? len - 11 : 0);
            if (!payload.empty() && !recvExact(payload.data(), payload.size())) break;

            std::vector<uint8_t> body;
            uint16_t error = 0;
            // Real mono CmdVM numbers: VERSION=1, ALL_THREADS=2, SUSPEND=3, RESUME=4.
            if (cmdset == 1 && cmd == 1) {              // VM/Version
                const std::string ver = "Mono mock 1.0";
                be32(body, static_cast<uint32_t>(ver.size()));
                body.insert(body.end(), ver.begin(), ver.end());
                be32(body, 2);   // major
                be32(body, 55);  // minor
            } else if (cmdset == 1 && cmd == 2) {       // VM/AllThreads
                be32(body, 2);
                be32(body, 0x1111u);   // 4-byte object ids (buffer_add_id)
                be32(body, 0x2222u);
            } else if (cmdset == 1 && (cmd == 3 || cmd == 4)) {
                // VM/Suspend, VM/Resume: success with an empty body.
            } else {
                error = 57;                              // unknown command
            }

            std::vector<uint8_t> reply;
            be32(reply, static_cast<uint32_t>(11 + body.size()));
            be32(reply, static_cast<uint32_t>(id));
            reply.push_back(0x80);                       // reply flag
            reply.push_back(static_cast<uint8_t>(error >> 8));
            reply.push_back(static_cast<uint8_t>(error));
            reply.insert(reply.end(), body.begin(), body.end());
            ::send(client, reply.data(), reply.size(), 0);
        }
        ::close(client);
    });

    ce::os::MonoDebuggerClient mono;
    bool connOk = mono.connectTcp("127.0.0.1", ntohs(addr.sin_port)).has_value();

    auto ver = mono.getVersion();
    bool verOk = ver && ver->vmVersion == "Mono mock 1.0" &&
        ver->majorVersion == 2 && ver->minorVersion == 55;

    auto threads = mono.vmAllThreads();
    bool threadsOk = threads && threads->size() == 2 &&
        (*threads)[0] == 0x1111 && (*threads)[1] == 0x2222;

    bool suspendOk = mono.vmSuspend().has_value() && mono.vmResume().has_value();

    // An unknown command must surface the agent's error code, not decode garbage.
    auto bad = mono.sendCommand(99, 99, {});
    bool errorOk = !bad.has_value() && bad.error().find("57") != std::string::npos;

    mono.close();
    stub.join();
    ::close(server);

    printf("  handshake + connect: %s\n", (connOk && handshakeSeen) ? "OK" : "FAILED");
    printf("  VM/Version parse: %s\n", verOk ? "OK" : "FAILED");
    printf("  VM/AllThreads parse: %s\n", threadsOk ? "OK" : "FAILED");
    printf("  suspend/resume: %s\n", suspendOk ? "OK" : "FAILED");
    printf("  agent error surfaced: %s\n", errorOk ? "OK" : "FAILED");
}

// ProcessWatcher polls /proc for a newly-appearing process whose comm matches a
// name. Testing it deterministically hinges on comm being inherited across fork:
// if the test process sets ITS OWN name to the target before forking, the child
// is born already matching, so the watcher's single read-on-first-sighting can
// never race a not-yet-renamed child. start() snapshots the baseline
// synchronously before spawning its thread, so a child forked after start()
// returns is guaranteed to be a NEW pid (not in the baseline) and must fire.
void test_process_watcher() {
    printf("\n── Test: process watcher ──\n");

    char original[16] = {0};
    prctl(PR_GET_NAME, original, 0, 0, 0);
    const char* target = "ceprocwatch";   // <= 15 chars (TASK_COMM_LEN limit)
    prctl(PR_SET_NAME, target, 0, 0, 0);

    ce::os::ProcessWatcher watcher;
    std::atomic<pid_t> firedPid{0};
    watcher.start(target, [&](pid_t pid, const std::string&) {
        pid_t expected = 0;
        firedPid.compare_exchange_strong(expected, pid);  // record the first hit
    }, /*pollIntervalMs=*/25);

    // Baseline is already captured; a child forked now inherits "ceprocwatch".
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);  // don't linger if the test process dies
        for (;;) pause();                  // hold the inherited comm until killed
        _exit(0);
    }
    prctl(PR_SET_NAME, original, 0, 0, 0); // restore ours; child keeps its copy

    bool detected = false;
    if (child > 0) {
        for (int i = 0; i < 500 && !detected; ++i) {
            if (firedPid.load() == child) detected = true;
            else usleep(10 * 1000);        // up to ~5s
        }
    }

    watcher.stop();
    if (child > 0) { kill(child, SIGKILL); waitpid(child, nullptr, 0); }

    printf("  detects a newly-launched matching process: %s\n", detected ? "OK" : "FAILED");

    // A program name longer than comm's 15 characters still matches, through
    // argv[0]. A copy of sleep under a long name stands in for the game.
    const auto program = std::filesystem::temp_directory_path() / "ce_a_rather_long_game_name";
    std::error_code ec;
    std::filesystem::copy_file("/bin/sleep", program, std::filesystem::copy_options::overwrite_existing, ec);
    if (!ec) {
        ce::os::ProcessWatcher longWatcher;
        std::atomic<pid_t> found{0};
        longWatcher.start("ce_a_rather_long_game_name", [&](pid_t pid, const std::string&) {
            pid_t expected = 0;
            found.compare_exchange_strong(expected, pid);
        }, 25);
        pid_t game = fork();
        if (game == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            execl(program.c_str(), program.c_str(), "30", (char*)nullptr);
            _exit(127);
        }
        bool longDetected = false;
        for (int i = 0; i < 500 && !longDetected && game > 0; ++i) {
            if (found.load() == game) longDetected = true;
            else usleep(10 * 1000);
        }
        longWatcher.stop();
        if (game > 0) { kill(game, SIGKILL); waitpid(game, nullptr, 0); }
        std::filesystem::remove(program, ec);
        printf("  matches a program name longer than 15 characters: %s\n", longDetected ? "OK" : "FAILED");
    }
}

// Validates MonoDebuggerClient against a REAL mono soft-debugger agent (not just
// the mock): compiles a tiny C# program, runs it under mono with
// --debugger-agent server=y,suspend=y, and confirms the client's handshake +
// VM/Version + VM/AllThreads framing decodes the genuine agent's replies. Proves
// the wire framing matches real mono, not only our own encoder. Skips without a
// mono runtime (e.g. in CI, which does not install mono).
void test_mono_debugger_real_agent() {
    printf("\n── Test: Mono soft-debugger client vs real mono agent ──\n");

    if (std::system("which mono mcs >/dev/null 2>&1") != 0) {
        printf("  real handshake + VM/Version + AllThreads: SKIPPED (no mono runtime)\n");
        return;
    }

    auto dir = std::filesystem::temp_directory_path();
    auto cs  = dir / "ce_mono_probe.cs";
    auto exe = dir / "ce_mono_probe.exe";
    {
        std::ofstream o(cs);
        o << "class CeMonoProbe { static void Main() {"
             " System.Threading.Thread.Sleep(60000); } }\n";
    }
    if (std::system(("mcs -out:'" + exe.string() + "' '" + cs.string() + "' 2>/dev/null").c_str()) != 0) {
        printf("  real handshake + VM/Version + AllThreads: SKIPPED (mcs compile failed)\n");
        std::filesystem::remove(cs);
        return;
    }

    // Reserve an ephemeral loopback port (bind then close) for the agent.
    int probe = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ::bind(probe, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    socklen_t al = sizeof(addr);
    ::getsockname(probe, reinterpret_cast<sockaddr*>(&addr), &al);
    uint16_t port = ntohs(addr.sin_port);
    ::close(probe);

    std::string agentArg = "--debugger-agent=transport=dt_socket,server=y,address=127.0.0.1:" +
        std::to_string(port) + ",suspend=y";
    pid_t mono = fork();
    if (mono == 0) {
        execlp("mono", "mono", agentArg.c_str(), exe.string().c_str(), (char*)nullptr);
        _exit(127);
    }

    bool ok = false;
    std::string detail;
    if (mono > 0) {
        ce::os::MonoDebuggerClient client;
        bool connected = false;
        for (int i = 0; i < 80 && !connected; ++i) {   // up to ~8s for the agent
            if (client.connectTcp("127.0.0.1", port)) connected = true;
            else usleep(100 * 1000);
        }
        if (connected) {
            auto ver = client.getVersion();
            auto threads = client.vmAllThreads();
            ok = ver.has_value() && !ver->vmVersion.empty() && ver->majorVersion >= 1 &&
                 threads.has_value() && !threads->empty();
            if (!ver) detail = "getVersion: " + ver.error();
            else if (!threads) detail = "vmAllThreads: " + threads.error();
            else detail = "version='" + ver->vmVersion + "' threads=" +
                          std::to_string(threads->size());
        } else {
            detail = "could not connect to agent";
        }
        client.close();
        kill(mono, SIGKILL);
        waitpid(mono, nullptr, 0);
    }

    printf("  real handshake + VM/Version + AllThreads: %s (%s)\n",
           ok ? "OK" : "FAILED", detail.c_str());

    std::filesystem::remove(cs);
    std::filesystem::remove(exe);
}
