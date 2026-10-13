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
};
AgentConfig loadAgentConfig();
/// The API key for the configured provider: the environment variable, else the
/// keyring. `source` says where it came from.
std::optional<QString> agentApiKey(const AgentConfig& config, QString* source, QString* error);

class AgentPanel : public QWidget {
    Q_OBJECT
public:
    explicit AgentPanel(QWidget* parent = nullptr);
    ~AgentPanel() override;

    /// The process the main window has open; the assistant attaches to it.
    void setTarget(pid_t pid, const QString& name);
    /// Receives the assistant's table when the user adds it to the address list.
    void setTableSink(std::function<void(const std::vector<CheatEntry>&)> sink) { tableSink_ = std::move(sink); }
    /// Use this transport instead of the network (tests); no API key is needed.
    void setTransportForTesting(ChatTransport transport) { testTransport_ = std::move(transport); }

    void send(const QString& text);
    bool busy() const { return busy_; }
    bool approvalPending() const;
    /// Answer the pending change: allow it (and, with forChat, every later one).
    void answerApproval(bool allow, bool forChat = false);
    QString transcriptText() const;
    /// The settings changed: the next message uses the new provider.
    void reloadSettings();

signals:
    void turnFinished(bool ok);
    void settingsRequested();

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void onEvent(const ChatEvent& event);
    void showApproval(const QString& description, const QString& detail);
    void finishTurn(bool ok);
    void addLine(const QString& html, int topMargin = 0);
    void addMarkdown(const QString& markdown);
    void updateState();
    ChatHttpResponse post(const ChatHttpRequest& request);
    bool approve(const std::string& tool, const json::Value& arguments);

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

    QThread* worker_;
    QObject* workerContext_;
    QNetworkAccessManager* network_ = nullptr;   // lives on the worker thread
    std::unique_ptr<AgentSession> session_;
    std::unique_ptr<AgentChat> chat_;
    ChatTransport testTransport_;
    std::function<void(const std::vector<CheatEntry>&)> tableSink_;

    pid_t targetPid_ = 0;
    QString targetName_;
    QString pendingCall_;   // a tool call waiting for its result line
    pid_t attachedPid_ = 0;
    bool busy_ = false;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> allowForChat_{false};
    mutable std::mutex approvalMutex_;
    std::condition_variable approvalChanged_;
    std::optional<bool> approvalAnswer_;
    bool approvalWaiting_ = false;
};

} // namespace ce::gui
