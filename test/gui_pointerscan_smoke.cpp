// Offscreen smoke test for the pointer scan window: the scan runs on a worker,
// so the GUI thread keeps running (the main window's freeze timer depends on
// it), the result arrives, a rescan runs on the worker as well, and closing the
// window during a scan stops and joins the worker. Scans this process, so no fork/ptrace is needed.

#include "gui/pointerscan_dialog.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTimer>

#include <cstdio>
#include <functional>
#include <unistd.h>

static volatile int32_t g_value = 4711;
static volatile int32_t* volatile g_pointer = &g_value;   // a static pointer to it

static int failures = 0;
static void check(const char* name, bool ok) {
    std::printf("  %s: %s\n", name, ok ? "OK" : "FAILED");
    if (!ok) ++failures;
}

static bool waitFor(const std::function<bool()>& condition, int ms) {
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < ms) QApplication::processEvents(QEventLoop::AllEvents, 20);
    return condition();
}

static QPushButton* button(QWidget* parent, const QString& text) {
    for (auto* b : parent->findChildren<QPushButton*>()) if (b->text() == text) return b;
    return nullptr;
}

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    (void)g_pointer;
    ce::os::LinuxProcessHandle proc(getpid());
    std::printf("── Pointer scan window ──\n");

    int ticks = 0;
    QTimer heartbeat;   // stands in for the main window's freeze timer
    QObject::connect(&heartbeat, &QTimer::timeout, [&] { ++ticks; });
    heartbeat.start(10);

    {
        ce::gui::PointerScanDialog dialog(&proc);
        dialog.setTargetAddress(reinterpret_cast<uintptr_t>(&g_value));
        auto* scan = button(&dialog, "Scan");
        check("the window offers Scan", scan != nullptr);
        if (!scan) return 1;
        const int before = ticks;
        scan->click();
        check("Scan turns into Cancel while the scan runs", scan->text() == "Cancel");
        const bool finished = waitFor([&] { return scan->text() == "Scan"; }, 180000);
        auto* table = dialog.findChild<QTableWidget*>();
        check("the scan finishes and lists the static pointer", finished && table && table->rowCount() > 0);
        check("the GUI thread kept running during the scan", ticks > before);

        // Rescan runs on the worker too: Scan reads Cancel until it is done.
        auto statusText = [&] {
            for (auto* label : dialog.findChildren<QLabel*>())
                if (label->text().startsWith("Rescan")) return label->text();
            return QString();
        };
        dialog.rescanTo(reinterpret_cast<uintptr_t>(&g_value));
        check("Rescan turns Scan into Cancel while it runs", scan->text() == "Cancel");
        const bool rescanned = waitFor([&] { return scan->text() == "Scan"; }, 60000);
        check("a rescan to the same address keeps the paths",
              rescanned && table && table->rowCount() > 0 && statusText().startsWith("Rescan:"));
        dialog.rescanTo(reinterpret_cast<uintptr_t>(&g_value) + 0x100000);
        const bool moved = waitFor([&] { return scan->text() == "Scan"; }, 60000);
        check("a rescan to another address drops the paths", moved && table && table->rowCount() == 0);
    }

    {
        auto* dialog = new ce::gui::PointerScanDialog(&proc);
        dialog->setTargetAddress(reinterpret_cast<uintptr_t>(&g_value));
        for (auto* spin : dialog->findChildren<QSpinBox*>()) spin->setValue(spin->maximum());   // a long scan
        if (auto* scan = button(dialog, "Scan")) scan->click();
        QElapsedTimer timer;
        timer.start();
        delete dialog;   // cancels and joins the worker
        check("closing the window during a scan stops it", timer.elapsed() < 60000);
    }

    std::printf("GUI_POINTERSCAN_SMOKE_RESULT=%s failed=%d\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
