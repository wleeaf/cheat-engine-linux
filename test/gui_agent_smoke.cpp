// The AI Assistant panel, offscreen, with a scripted model instead of an API:
// a turn that scans, asks to write (allowed) and saves a record; a change the
// user declines; Stop during a slow request; the table handed to the address
// list; what "Allow for this chat" covers; the questions the approvals ask;
// a process the model opened staying open; and which API addresses a saved
// key may go to. Pass --screenshot FILE to render the panel after the first turn.

#include "gui/agent_panel.hpp"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QPushButton>
#include <QThread>

#include <atomic>
#include <mutex>

#include <cstdio>
#include <cstring>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "platform/linux/linux_process.hpp"

static volatile int32_t g_health = 4711;
static int failures = 0;

static void check(const char* name, bool ok, const QString& detail = {}) {
    std::printf("  %s: %s%s\n", name, ok ? "OK" : "FAILED", ok || detail.isEmpty() ? "" : (" (" + detail.toStdString() + ")").c_str());
    if (!ok) ++failures;
}

static bool waitFor(const std::function<bool()>& condition, int ms = 10000) {
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < ms) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(5);
    }
    return condition();
}

int main(int argc, char** argv) {
    int ready[2];
    if (pipe(ready) != 0) return 1;
    const pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (write(ready[1], "x", 1) != 1) _exit(1);
        for (;;) pause();
    }
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 1;
    qputenv("QT_QPA_PLATFORM", qgetenv("QT_QPA_PLATFORM").isEmpty() ? "offscreen" : qgetenv("QT_QPA_PLATFORM"));
    QApplication app(argc, argv);
    QApplication::setOrganizationName("cheat-engine-linux-test");
    const char* screenshot = argc > 2 && !std::strcmp(argv[1], "--screenshot") ? argv[2] : nullptr;

    char address[32];
    std::snprintf(address, sizeof address, "0x%lx", static_cast<unsigned long>(reinterpret_cast<uintptr_t>(&g_health)));
    const std::string decimal = std::to_string(reinterpret_cast<uintptr_t>(&g_health));
    auto health = [&] {
        int32_t v = 0;
        (void)ce::os::LinuxProcessHandle(child).read(reinterpret_cast<uintptr_t>(&g_health), &v, sizeof v);
        return v;
    };

    std::printf("── AI Assistant panel (scripted model) ──\n");
    std::vector<std::string> replies = {
        R"({"content":[{"type":"text","text":"Looking for 4711."},{"type":"tool_use","id":"a","name":"first_scan","input":{"type":"i32","value":"4711"}}]})",
        R"({"content":[{"type":"tool_use","id":"b","name":"write","input":{"address":")" + std::string(address) + R"(","type":"i32","value":"999"}}]})",
        R"({"content":[{"type":"tool_use","id":"c","name":"add_record","input":{"address":")" + std::string(address) + R"(","type":"i32","description":"Health"}}]})",
        R"({"content":[{"type":"text","text":"Health is now **999**."}]})",
        R"({"content":[{"type":"tool_use","id":"d","name":"write","input":{"address":")" + std::string(address) + R"(","type":"i32","value":"5"}}]})",
        R"({"content":[{"type":"text","text":"Left it alone."}]})",
        R"({"content":[{"type":"tool_use","id":"e","name":"attach","input":{"target":")" + std::to_string(getpid()) + R"("}}]})",
        R"({"content":[{"type":"text","text":"Not opened."}]})",
        // "Allow for this chat": a write with the address as a JSON number, a
        // second write it covers, and an attach it does not.
        R"({"content":[{"type":"tool_use","id":"f","name":"write","input":{"address":)" + decimal + R"(,"type":"i32","value":"777"}}]})",
        R"({"content":[{"type":"tool_use","id":"g","name":"write","input":{"address":")" + std::string(address) + R"(","type":"i32","value":"778"}}]})",
        R"({"content":[{"type":"tool_use","id":"h","name":"attach","input":{"target":")" + std::to_string(getpid()) + R"("}}]})",
        R"({"content":[{"type":"text","text":"Done."}]})",
        // The questions: freeze, breakpoint, disabling a script, saving.
        R"({"content":[{"type":"tool_use","id":"i","name":"set_frozen","input":{"index":0,"frozen":true,"value":"5"}}]})",
        R"({"content":[{"type":"tool_use","id":"j","name":"find_accessed_addresses","input":{"address":")" + std::string(address) + R"("}}]})",
        R"({"content":[{"type":"tool_use","id":"k","name":"aa_disable","input":{"id":1}}]})",
        R"({"content":[{"type":"tool_use","id":"l","name":"save_table","input":{"path":"smoke-table.CT"}}]})",
        R"({"content":[{"type":"text","text":"Asked."}]})",
        // With no process open in the main window, the model opens one itself.
        R"({"content":[{"type":"tool_use","id":"m","name":"attach","input":{"target":")" + std::to_string(child) + R"("}}]})",
        R"({"content":[{"type":"text","text":"Attached."}]})",
        R"({"content":[{"type":"text","text":"Still attached."}]})",
    };
    std::atomic<size_t> next{0};
    std::atomic<bool> slow{false};
    std::vector<std::string> bodies;
    std::mutex bodiesLock;

    auto* panel = new ce::gui::AgentPanel;
    panel->resize(420, 640);
    panel->show();
    panel->setTarget(child, "agent-smoke-child");
    std::vector<ce::CheatEntry> handed;
    panel->setTableSink([&](const std::vector<ce::CheatEntry>& entries) { handed = entries; });
    panel->setTransportForTesting([&](const ce::ChatHttpRequest& request) {
        { std::lock_guard lock(bodiesLock); bodies.push_back(request.body); }
        if (slow) {   // a request that only ends when the user presses Stop
            for (int i = 0; i < 300 && slow; ++i) QThread::msleep(20);
            return ce::ChatHttpResponse{0, {}, "stopped"};
        }
        const size_t i = next++;
        return i < replies.size() ? ce::ChatHttpResponse{200, replies[i], {}} : ce::ChatHttpResponse{500, "{}", {}};
    });
    bool finished = false, finishedOk = false;
    QObject::connect(panel, &ce::gui::AgentPanel::turnFinished, [&](bool ok) { finished = true; finishedOk = ok; });

    panel->send("My health shows 4711. Set it to 999.");
    check("a change waits for the user's answer", waitFor([&] { return panel->approvalPending(); }) && health() == 4711);
    if (screenshot) {
        waitFor([] { return false; }, 200);   // let the approval bar show
        panel->grab().save(QString(screenshot).replace(".png", "-approval.png"));
    }
    check("the context names the open process", !bodies.empty() && bodies.front().find("agent-smoke-child") != std::string::npos);
    panel->answerApproval(true);
    check("the turn finishes", waitFor([&] { return finished; }) && finishedOk);
    check("the allowed write happened", health() == 999, QString::number(health()));
    const QString transcript = panel->transcriptText();
    check("the transcript shows replies, tool calls and results",
          transcript.contains("Looking for 4711.") && transcript.contains("Health is now 999") &&
          transcript.contains("first_scan type=i32 value=4711") && transcript.contains("attached to"), transcript.right(400));
    if (screenshot) panel->grab().save(screenshot);

    QPushButton* addButton = nullptr;
    for (auto* button : panel->findChildren<QPushButton*>()) if (button->text() == "Add to address list") addButton = button;
    check("Add to address list is offered", addButton && addButton->isEnabled());
    if (addButton) addButton->click();
    check("the address list receives the saved record", handed.size() == 1 && handed[0].description == "Health");

    finished = false;
    panel->send("Now set it to 5.");
    check("a second change asks again", waitFor([&] { return panel->approvalPending(); }));
    panel->answerApproval(false);
    check("a declined change is not made", waitFor([&] { return finished; }) && health() == 999);
    check("the model is told it was declined", bodies.size() >= 6 && bodies[5].find("declined") != std::string::npos);

    finished = false;
    slow = true;
    panel->send("Do something slow.");
    QThread::msleep(100);
    for (auto* button : panel->findChildren<QPushButton*>()) if (button->text() == "Stop") button->click();
    slow = false;
    check("Stop ends a turn", waitFor([&] { return finished; }) && !finishedOk);
    check("the panel takes a new message after Stop", !panel->busy());

    finished = false;
    panel->send("Open the other program.");
    check("opening another process asks first", waitFor([&] { return panel->approvalPending(); }));
    panel->answerApproval(false);
    check("a declined attach is not made", waitFor([&] { return finished; }) &&
          panel->transcriptText().contains("attach target=" + QString::number(getpid()) + " \u2192 refused"),
          panel->transcriptText().right(300));

    finished = false;
    panel->send("Set it to 777, then 778.");
    check("a write shows its address in 0x form", waitFor([&] { return panel->approvalPending(); }) &&
          panel->approvalText().contains(QString(address) + " in agent-smoke-child (PID ") &&
          !panel->approvalText().contains(QString::fromStdString(decimal)), panel->approvalText());
    panel->answerApproval(true, true);
    check("Allow for this chat covers the next write", waitFor([&] { return health() == 778; }), QString::number(health()));
    check("Allow for this chat does not cover opening a process", waitFor([&] { return panel->approvalPending(); }) &&
          panel->approvalText().contains("Let the assistant open"), panel->approvalText());
    panel->answerApproval(false);
    check("the turn with the grant finishes", waitFor([&] { return finished; }));

    // A new target (here a new name) ends the grant.
    panel->setTarget(child, "agent-smoke-renamed");
    finished = false;
    panel->send("Show me the questions.");
    const bool freezeAsked = waitFor([&] { return panel->approvalPending(); });
    const QString freeze = panel->approvalText();
    check("a freeze asks again after the target changed, naming the record, type and address",
          freezeAsked && freeze.startsWith("Freeze \"Health\" (4 Bytes at ") && freeze.contains(address) &&
          freeze.contains(") at 5 in agent-smoke-renamed (PID "), freeze);
    panel->answerApproval(false);
    check("a breakpoint asks first", waitFor([&] { return panel->approvalPending() && panel->approvalText().startsWith("Put a breakpoint"); }) &&
          panel->approvalText().contains(QString("Put a breakpoint at %1 in agent-smoke-renamed").arg(address)), panel->approvalText());
    panel->answerApproval(false);
    check("disabling a script asks first", waitFor([&] { return panel->approvalPending() && panel->approvalText().startsWith("Disable"); }) &&
          panel->approvalText().contains("Disable script #1 in agent-smoke-renamed"), panel->approvalText());
    panel->answerApproval(false);
    check("saving shows the absolute path", waitFor([&] { return panel->approvalPending() && panel->approvalText().startsWith("Save"); }) &&
          panel->approvalText().contains(QDir::currentPath() + "/smoke-table.CT"), panel->approvalText());
    panel->answerApproval(false);
    check("the questions turn finishes", waitFor([&] { return finished; }) && health() == 778);

    // Closing the process in the main window leaves it: the records go, so
    // there is nothing left to add to the address list.
    panel->setTarget(0, {});
    check("closing the process leaves it", waitFor([&] { return addButton && !addButton->isEnabled(); }));

    // A process the model opened (with the user's Allow) stays open after the turn.
    finished = false;
    panel->send("Open it again.");
    check("the model asks to open a process", waitFor([&] { return panel->approvalPending(); }));
    panel->answerApproval(true);
    check("the attach turn finishes", waitFor([&] { return finished; }) && finishedOk);
    finished = false;
    panel->send("Are you still attached?");
    check("the model's process stays open across turns", waitFor([&] { return finished; }) &&
          bodies.back().find("You are attached to PID " + std::to_string(child)) != std::string::npos);

    std::printf("── API key origins ──\n");
    using ce::gui::agentKeyRefusal;
    using ce::gui::agentOrigin;
    check("origins are normalized", agentOrigin(true, "HTTPS://API.OpenAI.com:443/v1/") == "https://api.openai.com" &&
          agentOrigin(false, "") == "https://api.anthropic.com" && agentOrigin(true, "http://localhost:11434/v1") == "http://localhost:11434",
          agentOrigin(true, "HTTPS://API.OpenAI.com:443/v1/"));
    check("a key saved before origins were kept goes to the provider's own API",
          agentKeyRefusal(false, "", "").isEmpty() && agentKeyRefusal(false, "https://api.anthropic.com/", "").isEmpty());
    check("a key is not sent to another address",
          agentKeyRefusal(false, "https://proxy.example.com", "").contains("is for https://api.anthropic.com") &&
          !agentKeyRefusal(true, "http://127.0.0.1:11434/v1", "http://localhost:11434").isEmpty());
    check("a key is not sent over plain http to another computer",
          agentKeyRefusal(true, "http://example.com/v1", "http://example.com").contains("https"));
    check("a key saved for a local server goes there",
          agentKeyRefusal(true, "http://localhost:11434/v1", agentOrigin(true, "http://localhost:11434/v1")).isEmpty() &&
          agentKeyRefusal(true, "http://[::1]:8080/v1", agentOrigin(true, "http://[::1]:8080")).isEmpty());

    delete panel;   // closes the worker thread cleanly
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    std::printf("GUI_AGENT_SMOKE_RESULT=%s failed=%d\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
