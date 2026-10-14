#include "gui/agent_panel.hpp"
#include <QFile>

#include "gui/secret_store.hpp"

#include <QApplication>
#include <QEvent>
#include <QEventLoop>
#include <QFontDatabase>
#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QSettings>
#include <QTextBrowser>
#include <QTextBlockFormat>
#include <QTextCursor>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

namespace ce::gui {

namespace {

using json::Value;

QString text(const std::string& s) { return QString::fromStdString(s); }

QString scalar(const Value& v) {
    if (v.isString() || v.isNumber()) return text(v.stringValue);
    if (v.isBool()) return v.boolValue ? "true" : "false";
    return {};
}

// "first_scan type=i32 value=100", short enough for one line.
QString describeCall(const std::string& tool, const Value& arguments) {
    QString line = text(tool);
    if (arguments.isObject())
        for (const auto& key : arguments.objectOrder) {
            const Value& v = arguments.objectValue.at(key);
            QString shown;
            if (key == "script") shown = QString("(%1 lines)").arg(text(v.stringValue).count('\n') + 1);
            else if (v.isArray()) shown = QString("[%1]").arg(v.arrayValue.size());
            else shown = scalar(v);
            if (shown.size() > 40) shown = shown.left(37) + "...";
            line += QString(" %1=%2").arg(text(key), shown);
        }
    return line.size() > 120 ? line.left(117) + "..." : line;
}

QString describeResult(const Value& result, bool isError) {
    if (isError) return "refused: " + text(result.getString("error").value_or("error"));
    if (auto count = result.getInt("count")) return QString("%1 found").arg(*count);
    if (auto attached = result.getString("attached")) return "attached to " + text(*attached);
    if (const Value* list = result.get("instructions"); list && list->isArray()) return QString("%1 instruction(s)").arg(list->arrayValue.size());
    if (const Value* list = result.get("addresses"); list && list->isArray()) return QString("%1 address(es)").arg(list->arrayValue.size());
    if (auto saved = result.getString("saved")) return "saved to " + text(*saved);
    if (auto value = result.getString("value_now")) return "now " + text(*value);
    if (auto value = result.getString("value")) return "value " + text(*value);
    if (result.get("id")) return "enabled";
    return "done";
}

} // namespace

AgentConfig loadAgentConfig() {
    QSettings s;
    AgentConfig config;
    const bool openAi = s.value("agent/provider", 0).toInt() == 1;
    config.provider.kind = openAi ? ChatProviderKind::OpenAiCompatible : ChatProviderKind::Anthropic;
    config.account = openAi ? "openai-compatible" : "anthropic";
    config.envVar = openAi ? "OPENAI_API_KEY" : "ANTHROPIC_API_KEY";
    config.name = openAi ? "OpenAI-compatible server" : "Anthropic";
    config.provider.model = s.value("agent/" + config.account + "/model").toString().trimmed().toStdString();
    config.provider.baseUrl = s.value("agent/" + config.account + "/baseUrl").toString().trimmed().toStdString();
    return config;
}

bool agentEnvKeyApplies(bool openAi, const QString& baseUrl) {
    if (baseUrl.trimmed().isEmpty()) return true;
    const QUrl url(baseUrl.trimmed());
    return url.scheme() == "https" && url.host().compare(openAi ? "api.openai.com" : "api.anthropic.com", Qt::CaseInsensitive) == 0;
}

std::optional<QString> agentApiKey(const AgentConfig& config, QString* source, QString* error) {
    const QString fromEnvironment = qEnvironmentVariable(config.envVar.toUtf8().constData()).trimmed();
    const bool openAi = config.provider.kind == ChatProviderKind::OpenAiCompatible;
    if (!fromEnvironment.isEmpty() && agentEnvKeyApplies(openAi, QString::fromStdString(config.provider.baseUrl))) {
        if (source) *source = config.envVar;
        return fromEnvironment;
    }
    auto stored = SecretStore(config.account).lookup(error);
    if (stored && !stored->isEmpty()) {
        if (source) *source = "keyring";
        return stored;
    }
    return std::nullopt;
}

AgentPanel::AgentPanel(QWidget* parent) : QWidget(parent) {
    AgentSessionOptions options;
    options.allowWrites = true;   // every change still waits for the user's Allow
    // Stop (and closing the window, which waits for the worker) ends a long
    // tool such as a 30 s watch, not only the network request.
    options.stopRequested = [this] { return stopping_.load(); };
    session_ = std::make_unique<AgentSession>(options);

    provider_ = new QLabel;
    provider_->setProperty("secondary", true);
    provider_->setWordWrap(true);
    transcript_ = new QTextBrowser;
    transcript_->setOpenLinks(false);
    transcript_->setPlaceholderText("Describe what to change in the game, for example:\n\n"
                                    "My health shows 100. Find it and keep it at 100.");

    approvalBar_ = new QFrame;
    approvalBar_->setFrameShape(QFrame::StyledPanel);
    auto* approvalLayout = new QVBoxLayout(approvalBar_);
    approvalText_ = new QLabel;
    approvalText_->setWordWrap(true);
    approvalText_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto* allow = new QPushButton("Allow");
    allow->setProperty("primary", true);
    auto* allowAll = new QPushButton("Allow for this chat");
    auto* decline = new QPushButton("Decline");
    connect(allow, &QPushButton::clicked, this, [this] { answerApproval(true); });
    connect(allowAll, &QPushButton::clicked, this, [this] { answerApproval(true, true); });
    connect(decline, &QPushButton::clicked, this, [this] { answerApproval(false); });
    auto* approvalButtons = new QHBoxLayout;
    approvalButtons->addWidget(allow);
    approvalButtons->addWidget(allowAll);
    approvalButtons->addStretch(1);
    approvalButtons->addWidget(decline);
    // The whole script, scrollable: the user approves exactly what will run.
    approvalDetail_ = new QPlainTextEdit;
    approvalDetail_->setReadOnly(true);
    approvalDetail_->setLineWrapMode(QPlainTextEdit::NoWrap);
    approvalDetail_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    approvalDetail_->setMaximumHeight(approvalDetail_->fontMetrics().lineSpacing() * 12);
    approvalDetail_->hide();
    approvalLayout->addWidget(approvalText_);
    approvalLayout->addWidget(approvalDetail_);
    approvalLayout->addLayout(approvalButtons);
    approvalBar_->hide();

    input_ = new QPlainTextEdit;
    input_->setPlaceholderText("Message the assistant (Enter sends, Shift+Enter adds a line)");
    input_->setMaximumHeight(input_->fontMetrics().lineSpacing() * 5);
    input_->installEventFilter(this);

    send_ = new QPushButton("Send");
    send_->setProperty("primary", true);
    stop_ = new QPushButton("Stop");
    newChat_ = new QPushButton("New chat");
    addToTable_ = new QPushButton("Add to address list");
    addToTable_->setToolTip("Copy the values and scripts the assistant saved into the address list");
    auto* settings = new QPushButton("Settings...");
    connect(send_, &QPushButton::clicked, this, [this] { send(input_->toPlainText()); });
    connect(stop_, &QPushButton::clicked, this, &AgentPanel::stop);
    connect(newChat_, &QPushButton::clicked, this, [this] {
        if (busy_) return;
        chat_.reset();   // the next message starts with the current settings and key
        allowForChat_ = false;
        transcript_->clear();
    });
    connect(addToTable_, &QPushButton::clicked, this, [this] {
        if (!tableSink_) return;
        const auto entries = session_->tableEntries();
        tableSink_(entries);
        status_->setText(QString("Added %1 entr%2 to the address list.").arg(entries.size()).arg(entries.size() == 1 ? "y" : "ies"));
    });
    connect(settings, &QPushButton::clicked, this, &AgentPanel::settingsRequested);

    status_ = new QLabel;
    status_->setProperty("secondary", true);
    auto* buttons = new QHBoxLayout;
    buttons->addWidget(newChat_);
    buttons->addWidget(addToTable_);
    buttons->addStretch(1);
    buttons->addWidget(stop_);
    buttons->addWidget(send_);
    auto* footer = new QHBoxLayout;
    footer->addWidget(status_, 1);
    footer->addWidget(settings);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 6, 8, 8);
    layout->addWidget(provider_);
    layout->addWidget(transcript_, 1);
    layout->addWidget(approvalBar_);
    layout->addWidget(input_);
    layout->addLayout(buttons);
    layout->addLayout(footer);

    worker_ = new QThread(this);
    worker_->setObjectName("ai-assistant");
    workerContext_ = new QObject;
    workerContext_->moveToThread(worker_);
    connect(worker_, &QThread::finished, workerContext_, &QObject::deleteLater);
    worker_->start();
    // A child of workerContext_, so it is deleted on the worker thread when the
    // thread finishes, after any request in progress has returned.
    QMetaObject::invokeMethod(workerContext_, [this] { network_ = new QNetworkAccessManager(workerContext_); },
                              Qt::BlockingQueuedConnection);

    reloadSettings();
    updateState();
}

AgentPanel::~AgentPanel() {
    stop();
    // quit() also ends the event loop of a request waiting in post(); the turn
    // then sees the cancel and returns, and wait() lets it finish.
    worker_->quit();
    worker_->wait();
    chat_.reset();
    session_.reset();   // disables the scripts the assistant enabled
}

bool AgentPanel::eventFilter(QObject* watched, QEvent* event) {
    if (watched == input_ && event->type() == QEvent::KeyPress) {
        auto* key = static_cast<QKeyEvent*>(event);
        if ((key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter) && !(key->modifiers() & Qt::ShiftModifier)) {
            send(input_->toPlainText());
            return true;
        }
    }
    return QWidget::eventFilter(watched, event);
}

void AgentPanel::reloadSettings() {
    const AgentConfig config = loadAgentConfig();
    const QString model = text(config.provider.modelName());
    provider_->setText(QString("%1%2. Your messages and what the tools find in the game are sent there.")
                           .arg(config.name, model.isEmpty() ? QString() : ", " + model));
    // send() compares the settings with the ones the chat was made with, so a
    // change applies to the next message, even one sent while a turn runs.
}

QString AgentPanel::settingsSignature(const AgentConfig& config) const {
    return QString("%1|%2|%3|%4").arg(int(config.provider.kind)).arg(text(config.provider.model), text(config.provider.baseUrl))
        .arg(SecretStore::changeCount());
}

void AgentPanel::stop() {
    {
        std::lock_guard lock(approvalMutex_);   // so a waiting approve() cannot miss it
        stopping_ = true;
    }
    if (chat_) chat_->cancel();
    approvalChanged_.notify_all();
    if (busy_) status_->setText("Stopping...");
}

void AgentPanel::setTarget(pid_t pid, const QString& name) {
    if (pid == targetPid_ && name == targetName_) return;
    targetPid_ = pid;
    targetName_ = name;
    syncSession();
}

// Leave a process the main window no longer has open, so the assistant's
// scripts and freezes do not stay behind in it.
void AgentPanel::syncSession() {
    if (busy_) return;   // finishTurn calls this again
    const pid_t pid = targetPid_;
    QMetaObject::invokeMethod(workerContext_, [this, pid] {
        const pid_t attached = session_->attachedPid();
        if (attached && attached != pid) session_->detach();
        QMetaObject::invokeMethod(this, [this] { if (!busy_) updateState(); }, Qt::QueuedConnection);
    });
}

void AgentPanel::updateState() {
    send_->setEnabled(!busy_);
    stop_->setEnabled(busy_);
    newChat_->setEnabled(!busy_);
    input_->setReadOnly(busy_);
    if (!busy_) {
        const bool haveEntries = !session_->tableEntries().empty();
        addToTable_->setEnabled(haveEntries && bool(tableSink_));
    } else {
        addToTable_->setEnabled(false);
    }
}

void AgentPanel::addLine(const QString& html, int topMargin) {
    QTextCursor cursor(transcript_->document());
    cursor.movePosition(QTextCursor::End);
    QTextBlockFormat format;
    format.setTopMargin(topMargin);
    format.setBottomMargin(0);
    if (transcript_->document()->isEmpty()) cursor.setBlockFormat(format);
    else cursor.insertBlock(format, QTextCharFormat());
    cursor.insertHtml(html);
    transcript_->verticalScrollBar()->setValue(transcript_->verticalScrollBar()->maximum());
}

void AgentPanel::addMarkdown(const QString& markdown) {
    QTextCursor cursor(transcript_->document());
    cursor.movePosition(QTextCursor::End);
    QTextBlockFormat format;
    format.setTopMargin(8);
    if (!transcript_->document()->isEmpty()) cursor.insertBlock(format, QTextCharFormat());
    cursor.insertMarkdown(markdown);
    transcript_->verticalScrollBar()->setValue(transcript_->verticalScrollBar()->maximum());
}

QString AgentPanel::transcriptText() const { return transcript_->toPlainText(); }

void AgentPanel::send(const QString& message) {
    const QString trimmed = message.trimmed();
    if (busy_ || trimmed.isEmpty()) return;
    // Busy from here: reading the key may show the keyring's prompt, which runs
    // an event loop where another Enter must not start a second turn.
    busy_ = true;
    updateState();
    const AgentConfig config = loadAgentConfig();
    if (chat_ && settingsSignature(config) != chatSignature_) {
        chat_.reset();
        allowForChat_ = false;
        if (!transcript_->document()->isEmpty())
            addLine(QString("<span style='color:%1'>The AI Assistant settings changed, so this message starts a new "
                            "conversation.</span>").arg(palette().color(QPalette::PlaceholderText).name()), 16);
    }
    if (!chat_) {
        std::string key;
        ChatTransport transport = testTransport_;
        if (!transport) {
            QString source, error;
            auto found = agentApiKey(config, &source, &error);
            if (!found && config.provider.kind == ChatProviderKind::Anthropic) {
                addLine(QString("<span style='color:#d9534f'>Add your Anthropic API key in Settings, AI Assistant%1.</span>")
                            .arg(error.isEmpty() ? QString() : " (" + error.toHtmlEscaped() + ")"), 8);
                busy_ = false;
                updateState();
                emit settingsRequested();
                return;
            }
            key = found.value_or(QString()).toStdString();
            transport = [this](const ChatHttpRequest& request) { return post(request); };
        }
        chat_ = std::make_unique<AgentChat>(*session_, config.provider, key, transport);
        chatSignature_ = settingsSignature(config);
        chat_->setEventSink([this](const ChatEvent& event) {
            QMetaObject::invokeMethod(this, [this, event] { onEvent(event); }, Qt::QueuedConnection);
        });
        chat_->setApprover([this](const std::string& tool, const Value& arguments) { return approve(tool, arguments); });
    }

    addLine(QString("<b>You</b><br>%1").arg(trimmed.toHtmlEscaped().replace("\n", "<br>")), transcript_->document()->isEmpty() ? 0 : 16);
    input_->clear();
    {
        std::lock_guard lock(approvalMutex_);
        stopping_ = false;
    }
    chat_->clearCancel();   // before the worker starts, so an early Stop counts
    status_->setText("Working...");
    turnPid_ = targetPid_;
    turnName_ = targetName_;
    const pid_t pid = targetPid_;
    const QString name = targetName_;
    QMetaObject::invokeMethod(workerContext_, [this, trimmed, pid, name] {
        std::string context = "No process is open in Cheat Engine. Use list_processes and attach, or ask the user to "
                              "open the game with Ctrl+O.";
        if (!pid && !name.isEmpty())
            context = QString("Cheat Engine has \"%1\" open, a remote or emulator target that these tools cannot reach: "
                              "they work on processes on this computer only.").arg(name).toStdString();
        if (pid && !stopping_ && pid != session_->attachedPid()) {
            const auto attached = session_->call("attach", Value::object().set("target", Value::string(std::to_string(pid))));
            ChatEvent shown{ChatEvent::Type::ToolCall};
            shown.tool = "attach";
            shown.arguments = Value::object().set("target", Value::string(std::to_string(pid)));
            QMetaObject::invokeMethod(this, [this, shown] { onEvent(shown); }, Qt::QueuedConnection);
            ChatEvent result{ChatEvent::Type::ToolResult};
            result.tool = "attach";
            result.result = attached.content;
            result.isError = attached.isError;
            QMetaObject::invokeMethod(this, [this, result] { onEvent(result); }, Qt::QueuedConnection);
        }
        if (pid) {
            const QString opened = QString("The user has the process \"%1\" (PID %2) open in Cheat Engine").arg(name).arg(pid);
            context = (session_->attachedPid() == pid ? opened + ", and you are attached to it."
                                                      : opened + ", but attaching to it failed.").toStdString();
        }
        chat_->setContext(context);
        const bool ok = !stopping_ && chat_->send(trimmed.toStdString());
        QMetaObject::invokeMethod(this, [this, ok] { finishTurn(ok); }, Qt::QueuedConnection);
    });
}

void AgentPanel::onEvent(const ChatEvent& event) {
    const QString secondary = palette().color(QPalette::PlaceholderText).name();
    switch (event.type) {
    case ChatEvent::Type::AssistantText:
        addMarkdown(text(event.text));
        break;
    case ChatEvent::Type::ToolCall:
        pendingCall_ = describeCall(event.tool, event.arguments);   // shown with its result
        break;
    case ChatEvent::Type::ToolResult:
        addLine(QString("<span style='color:%1'>&#9656; %2 &#8594; </span><span style='color:%3'>%4</span>")
                    .arg(secondary, pendingCall_.toHtmlEscaped(), event.isError ? QString("#d9534f") : secondary,
                         describeResult(event.result, event.isError).toHtmlEscaped()), 4);
        pendingCall_.clear();
        break;
    case ChatEvent::Type::Error:
        addLine(QString("<span style='color:#d9534f'>%1</span>").arg(text(event.text).toHtmlEscaped()), 8);
        break;
    }
}

void AgentPanel::finishTurn(bool ok) {
    busy_ = false;
    approvalBar_->hide();
    // A failure is explained in the transcript; the status only marks a Stop.
    status_->setText(!ok && stopping_ ? QString("Stopped.") : QString());
    updateState();
    syncSession();
    input_->setFocus();
    emit turnFinished(ok);
}

// Runs on the worker thread: show the request in the panel and wait for the
// user's answer (or Stop, or the panel closing).
bool AgentPanel::approve(const std::string& tool, const Value& arguments) {
    // The process the user opened needs no question; any other one does, since
    // the assistant could then read its memory and send it to the provider.
    if (tool == "attach") {
        const std::string target = arguments.getString("target").value_or(scalar(arguments.get("target") ? *arguments.get("target") : Value()).toStdString());
        if (turnPid_ && (target == std::to_string(turnPid_) || QString::fromStdString(target) == turnName_)) return true;
    }
    if (allowForChat_) return true;
    QString description, detail;
    // Values and addresses may come as JSON numbers as well as strings.
    auto field = [&](const char* key) {
        const QString value = scalar(arguments.get(key) ? *arguments.get(key) : Value());
        return value.isEmpty() ? QString("?") : value;
    };
    if (tool == "write") {
        description = QString("Write %1 (%2) to %3?").arg(field("value"), field("type"), field("address"));
    } else if (tool == "save_table") {
        description = arguments.getBool("overwrite").value_or(false)
            ? QString("Save the table to %1, replacing that file if it exists?").arg(field("path"))
            : QString("Save the table to %1?").arg(field("path"));
    } else if (tool == "attach") {
        description = QString("Let the assistant open \"%1\"? It can then read that program's memory, and what it reads "
                              "is sent to the model's provider.").arg(field("target"));
    } else if (tool == "set_frozen") {
        const QString value = scalar(arguments.get("value") ? *arguments.get("value") : Value());
        QString record = field("index");
        if (auto index = arguments.getInt("index"); index && *index >= 0) {
            const auto entries = session_->tableEntries();   // the worker owns the session during a turn
            const auto at = static_cast<size_t>(*index);
            if (at < entries.size() && !entries[at].description.empty()) record = "\"" + text(entries[at].description) + "\"";
        }
        description = QString("Freeze %1 at %2?").arg(record, value.isEmpty() ? QString("its current value") : value);
    } else {
        description = QString("Enable the script \"%1\"?").arg(text(arguments.getString("description").value_or("")));
        detail = text(arguments.getString("script").value_or(""));
    }
    // Name the process the session is attached to now: the model may have
    // attached elsewhere since the turn began (with the user's approval).
    if (tool != "attach" && tool != "save_table" && description.endsWith('?')) {
        const pid_t pid = session_->attachedPid();   // the worker owns the session during a turn
        if (pid > 0) {
            QString name = pid == turnPid_ ? turnName_ : QString();
            if (name.isEmpty()) {
                QFile comm(QString("/proc/%1/comm").arg(pid));
                if (comm.open(QIODevice::ReadOnly)) name = QString::fromUtf8(comm.readAll()).trimmed();
            }
            description = description.chopped(1) + (name.isEmpty() ? QString(" in PID %1?").arg(pid)
                                                                    : QString(" in %1 (PID %2)?").arg(name).arg(pid));
        }
    }
    {
        std::lock_guard lock(approvalMutex_);
        if (stopping_) return false;
        approvalAnswer_.reset();
        approvalWaiting_ = true;
    }
    QMetaObject::invokeMethod(this, [this, description, detail] { showApproval(description, detail); }, Qt::QueuedConnection);
    std::unique_lock lock(approvalMutex_);
    approvalChanged_.wait(lock, [this] { return approvalAnswer_.has_value() || stopping_.load(); });
    approvalWaiting_ = false;
    const bool answer = approvalAnswer_.value_or(false);
    lock.unlock();
    QMetaObject::invokeMethod(this, [this] { approvalBar_->hide(); }, Qt::QueuedConnection);
    return answer;
}

void AgentPanel::showApproval(const QString& description, const QString& detail) {
    approvalText_->setText("<b>" + description.toHtmlEscaped() + "</b>");
    approvalDetail_->setPlainText(detail);
    approvalDetail_->setVisible(!detail.isEmpty());
    approvalBar_->show();
    status_->setText("Waiting for your answer...");
}

bool AgentPanel::approvalPending() const {
    std::lock_guard lock(approvalMutex_);
    return approvalWaiting_ && !approvalAnswer_.has_value();
}

void AgentPanel::answerApproval(bool allow, bool forChat) {
    {
        std::lock_guard lock(approvalMutex_);
        if (!approvalWaiting_) return;
        approvalAnswer_ = allow;
        if (allow && forChat) allowForChat_ = true;
    }
    approvalChanged_.notify_all();
    approvalBar_->hide();
    status_->setText("Working...");
}

// Runs on the worker thread.
ChatHttpResponse AgentPanel::post(const ChatHttpRequest& request) {
    ChatHttpResponse response;
    if (!network_) { response.error = "closing"; return response; }
    QNetworkRequest http(QUrl(QString::fromStdString(request.url)));
    // Never follow a redirect to another host: it would carry the API key there.
    http.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::SameOriginRedirectPolicy);
    for (const auto& [name, value] : request.headers) http.setRawHeader(QByteArray::fromStdString(name), QByteArray::fromStdString(value));
    http.setTransferTimeout(300000);
    QNetworkReply* reply = network_->post(http, QByteArray::fromStdString(request.body));
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QTimer poll;
    QObject::connect(&poll, &QTimer::timeout, &loop, [this, reply] { if (stopping_) reply->abort(); });
    poll.start(100);
    if (!reply->isFinished()) loop.exec();
    response.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    response.body = reply->readAll().toStdString();
    if (response.status == 0) response.error = stopping_ ? "stopped" : reply->errorString().toStdString();
    delete reply;
    return response;
}

} // namespace ce::gui
