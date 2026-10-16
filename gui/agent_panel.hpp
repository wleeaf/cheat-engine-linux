#pragma once
/// The AI Assistant: a chat panel where a language model of the user's choice
/// (their API key, or a local server) finds and changes values with the agent
/// tools. The conversation runs on a worker thread; every change to the game
/// waits for the user's Allow in the panel.

#include "core/agent_chat.hpp"

#include <QString>
#include <QWidget>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <sys/types.h>
#include <vector>

class QFrame;
class QLabel;
class QNetworkAccessManager;
class QPlainTextEdit;
class QPushButton;
class QTextBrowser;
class QThread;

namespace ce::gui {

/// The provider settings (Settings, AI Assistant).
struct AgentConfig {
    ChatProvider provider;
    QString account;   // the keyring entry for its key
    QString envVar;    // an environment variable that overrides the stored key
    QString name;      // for display
    QString keyOrigin; // the API address the stored key was saved for
};
AgentConfig loadAgentConfig();
/// Whether ANTHROPIC_API_KEY / OPENAI_API_KEY may be sent: only to that
/// provider's own API, never to another server the user points the panel at.
bool agentEnvKeyApplies(bool openAi, const QString& baseUrl);
/// The origin (scheme, host, port) requests go to with this API address.
QString agentOrigin(bool openAi, const QString& baseUrl);
/// Why a stored key may not be sent to this API address, or empty when it may:
/// it was saved for another origin (an empty keyOrigin is the provider's own
/// API), or the address is plain http to another computer.
QString agentKeyRefusal(bool openAi, const QString& baseUrl, const QString& keyOrigin);
/// The API key for the configured provider: the environment variable, else the
/// keyring. `source` says where it came from. A stored key that may not be
/// sent to the configured address is not read; `refused` says why.
std::optional<QString> agentApiKey(const AgentConfig& config, QString* source, QString* error, QString* refused = nullptr);

class AgentPanel : public QWidget {
    Q_OBJECT
public:
    explicit AgentPanel(QWidget* parent = nullptr);
    ~AgentPanel() override;

    /// The process the main window has open; the assistant attaches to it.
    /// pid 0 with a name is a target the tools cannot reach (ceserver, GDB).
    void setTarget(pid_t pid, const QString& name);
    /// Receives the assistant's table when the user adds it to the address list.
    void setTableSink(std::function<void(const std::vector<CheatEntry>&)> sink) { tableSink_ = std::move(sink); }
    /// Use this transport instead of the network (tests); no API key is needed.
    void setTransportForTesting(ChatTransport transport) { testTransport_ = std::move(transport); }

    void send(const QString& text);
    bool busy() const { return busy_; }
    bool approvalPending() const;
    /// Answer the pending change: allow it (and, with forChat, every later one
    /// in the same process; opening a process or replacing a file always asks).
    void answerApproval(bool allow, bool forChat = false);
    /// The question the pending approval shows.
    QString approvalText() const;
    QString transcriptText() const;
    /// The settings changed: the next message uses the new provider.
    void reloadSettings();
    /// Stop the turn in progress.
    void stop();

signals:
    void turnFinished(bool ok);
    void settingsRequested();

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void onEvent(const ChatEvent& event);
    void showApproval(const QString& description, const QString& detail, bool forChat);
    void finishTurn(bool ok);
    void addLine(const QString& html, int topMargin = 0);
    void addMarkdown(const QString& markdown);
    void updateState();
    ChatHttpResponse post(const ChatHttpRequest& request);
    bool approve(const std::string& tool, const json::Value& arguments);
    QString settingsSignature(const AgentConfig& config) const;
    void syncSession();

    QTextBrowser* transcript_;
    QPlainTextEdit* input_;
    QPushButton* send_;
    QPushButton* stop_;
    QPushButton* newChat_;
    QPushButton* addToTable_;
    QLabel* status_;
    QLabel* provider_;
    QFrame* approvalBar_;
    QLabel* approvalText_;
    QPlainTextEdit* approvalDetail_;
    QPushButton* allowForChatButton_;

    QThread* worker_;
    QObject* workerContext_;
    QNetworkAccessManager* network_ = nullptr;   // lives on the worker thread
    std::unique_ptr<AgentSession> session_;
    std::unique_ptr<AgentChat> chat_;
    ChatTransport testTransport_;
    std::function<void(const std::vector<CheatEntry>&)> tableSink_;

    pid_t targetPid_ = 0;
    QString targetName_;
    std::vector<pid_t> leftPids_;   // targets the main window closed, for syncSession
    pid_t turnPid_ = 0;     // the target when the turn started, for the worker
    QString turnName_;
    QString chatSignature_;   // the settings chat_ was made with
    QString pendingCall_;   // a tool call waiting for its result line
    bool busy_ = false;
    std::atomic<bool> stopping_{false};
    // "Allow for this chat" covers changes in this process only (0: none).
    std::atomic<pid_t> allowForChatPid_{0};
    mutable std::mutex approvalMutex_;
    std::condition_variable approvalChanged_;
    std::optional<bool> approvalAnswer_;
    bool approvalWaiting_ = false;
    pid_t approvalGrantPid_ = 0;   // what "Allow for this chat" would cover now (0: not offered)
    QString approvalQuestion_;
};

} // namespace ce::gui
