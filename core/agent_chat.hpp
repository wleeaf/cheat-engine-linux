#pragma once
/// A conversation with a language model that uses the agent tools: the user's
/// message goes to the model's API, the tool calls it answers with run in an
/// AgentSession, their results go back, until the model replies in text. It
/// speaks Anthropic's Messages API and the OpenAI-compatible chat completions
/// API (OpenAI, and local servers such as Ollama or LM Studio).
///
/// Qt-free: the caller supplies the HTTP transport, so the GUI uses Qt Network
/// and the tests use a scripted model. Not thread-safe; run one send() at a
/// time (cancel() may be called from another thread).

#include "core/agent_tools.hpp"
#include "core/json.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace ce {

enum class ChatProviderKind { Anthropic, OpenAiCompatible };

struct ChatProvider {
    ChatProviderKind kind = ChatProviderKind::Anthropic;
    std::string baseUrl;   // empty: the provider's public API
    std::string model;     // empty: the provider's default (Anthropic only)
    int maxTokens = 4096;

    std::string endpoint() const;
    std::string modelName() const;
    static const char* defaultAnthropicModel() { return "claude-sonnet-5-5"; }
};

struct ChatHttpRequest {
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

/// The largest reply AgentChat reads. A transport should stop reading a
/// longer one and set `truncated`.
constexpr size_t kMaxReplyBytes = 16 * 1024 * 1024;

struct ChatHttpResponse {
    int status = 0;          // 0 when the request did not complete
    std::string body;
    std::string error;       // transport error (no connection, timeout, ...)
    bool truncated = false;  // the reply was larger than kMaxReplyBytes
    bool retryable = false;  // status 0 only: the connection dropped, so sending
                             // again may work (not a timeout, DNS, TLS or Stop)
};

using ChatTransport = std::function<ChatHttpResponse(const ChatHttpRequest&)>;

/// What happened during a turn, in order, for the transcript.
struct ChatEvent {
    enum class Type { AssistantText, ToolCall, ToolResult, Error };
    Type type = Type::AssistantText;
    std::string text;            // assistant text, or the error
    std::string tool;            // ToolCall / ToolResult
    json::Value arguments;       // ToolCall
    json::Value result;          // ToolResult
    bool isError = false;        // ToolResult
};

class AgentChat {
public:
    AgentChat(AgentSession& session, ChatProvider provider, std::string apiKey, ChatTransport transport);

    /// Extra system text, for example which process the user has open.
    void setContext(std::string context) { context_ = std::move(context); }
    /// Asked before every tool call that changes the game (write, freeze,
    /// enabling or disabling a script, a breakpoint in its code), saves a file
    /// or attaches; returning false refuses the call. Without an approver such
    /// calls are refused.
    void setApprover(std::function<bool(const std::string& tool, const json::Value& arguments)> approver) {
        approver_ = std::move(approver);
    }
    void setEventSink(std::function<void(const ChatEvent&)> sink) { sink_ = std::move(sink); }
    /// Most model round trips in one turn before stopping to ask the user.
    void setMaxRounds(int rounds) { maxRounds_ = rounds; }
    /// Tries a request again after a dropped connection (`retryable`), 408,
    /// 429, a 5xx or 529 (overloaded): `attempts` tries in all, the first wait
    /// `firstDelayMs` and each later one twice as long. 1 turns it off.
    void setRetry(int attempts, double firstDelayMs) { retryAttempts_ = attempts; retryDelayMs_ = firstDelayMs; }
    /// Most tool calls run from one reply; the rest are answered with an error.
    static constexpr size_t kMaxCallsPerReply = 16;

    /// Run one user turn to completion (blocking). False when it stopped on an
    /// error or was cancelled; the events say why.
    bool send(const std::string& userText);
    /// Stop the running turn after the current request or tool call. A wait
    /// before sending a request again ends at once.
    void cancel();
    /// Forget an earlier cancel. Call before handing a new turn to another
    /// thread, so a Stop pressed before send() starts is not lost.
    void clearCancel();
    /// Forget the conversation.
    void reset() { messages_.clear(); }
    size_t messageCount() const { return messages_.size(); }

    /// The request body for the current conversation (exposed for tests).
    std::string requestBody() const;

    /// Tool calls that need the user's approval: changes to the running
    /// program, files written to the user's disk, and attaching (the approver
    /// lets the process the user opened through without asking).
    static bool needsApproval(const std::string& tool, const json::Value& arguments);

private:
    struct ToolCall { std::string id, name; json::Value arguments; };
    ChatHttpResponse post(const ChatHttpRequest& request);
    bool waitUnlessCancelled(double ms);
    bool parseReply(const std::string& body, std::string& text, std::vector<ToolCall>& calls, std::string& error);
    void report(const ChatEvent& event) { if (sink_) sink_(event); }
    std::string systemPrompt() const;

    AgentSession& session_;
    ChatProvider provider_;
    std::string apiKey_;
    ChatTransport transport_;
    std::string context_;
    std::function<bool(const std::string&, const json::Value&)> approver_;
    std::function<void(const ChatEvent&)> sink_;
    std::vector<json::Value> messages_;   // in the provider's own message format
    int maxRounds_ = 40;
    int retryAttempts_ = 3;
    double retryDelayMs_ = 500;
    std::atomic<bool> cancelled_{false};
    std::mutex cancelMutex_;               // with cancelChanged_, ends a retry wait
    std::condition_variable cancelChanged_;
};

/// The provider's error message from an error response body, if it has one.
std::string chatErrorMessage(const std::string& body);

} // namespace ce
