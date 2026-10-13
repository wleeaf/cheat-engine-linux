// The AI Assistant panel, offscreen, with a scripted model instead of an API:
// a turn that scans, asks to write (allowed) and saves a record; a change the
// user declines; Stop during a slow request; and the table handed to the
// address list. Pass --screenshot FILE to render the panel after the first turn.

#include "gui/agent_panel.hpp"

#include <QApplication>
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

    delete panel;   // closes the worker thread cleanly
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);
    std::printf("GUI_AGENT_SMOKE_RESULT=%s failed=%d\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
