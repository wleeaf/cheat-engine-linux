// `gui_lifecycle_smoke --target PID VALUE WRITER`: drive the real main window
// and debugger window against any live process a gate launched (sandboxed,
// static, foreign libc, ...). VALUE is a 4-byte field holding 24681357 and
// WRITER a function that increments it. The debugger stage prints
// GUI_TARGET_ARMED and waits for the gate to make the program call WRITER.
#include "platform/linux/linux_process.hpp"
#include <cstdlib>

namespace gui_target_test {
static int failures = 0;
static void check(bool ok, const char* name) {
    std::printf("GUI_TARGET_CHECK %s: %s\n", ok ? "OK" : "FAILED", name);
    failures += !ok;
}
static bool run(pid_t pid, uintptr_t value, uintptr_t writer) {
    ce::gui::MainWindow main;
    main.attachToPid(pid, "target");
    auto* type = main.findChild<QComboBox*>("scanValueType");
    auto* scanValue = main.findChild<QLineEdit*>("scanValue");
    auto* first = main.findChild<QPushButton*>("primaryButton");
    auto* next = main.findChild<QPushButton*>("nextScanButton");
    auto* results = main.findChild<ce::gui::ScanResultsModel*>();
    auto* records = main.findChild<ce::gui::AddressListModel*>();
    if (!type || !scanValue || !first || !next || !results || !records) {
        check(false, "the main window exposes its scan and address-list controls");
        return false;
    }
    ce::os::LinuxProcessHandle process(pid);
    auto found = [&] {
        for (int row = 0; row < results->rowCount(); ++row)
            if (results->addressAt(row) == value) return true;
        return false;
    };
    // GUI first scan over the whole target, then a next scan after a change.
    type->setCurrentIndex(2);   // 4 Bytes
    scanValue->setText("24681357");
    first->click();
    check(found(), "a GUI first scan over the whole target finds the field");
    int32_t changed = 24681358;
    auto wrote = process.write(value, &changed, sizeof(changed));
    scanValue->setText("24681358");
    next->click();
    check(wrote && found(), "a GUI next scan keeps the field after its value changes");
    // Address list: add the field and edit its value as a user would.
    int id = records->addEntry(value, ce::ValueType::Int32, "target value");
    int row = records->rowOfId(id);
    bool edited = row >= 0 && records->setData(records->index(row, 4), "13579", Qt::EditRole);
    int32_t observed = 0;
    auto read = process.read(value, &observed, sizeof(observed));
    check(edited && read && observed == 13579, "editing the address-list value writes the target");
    // Debugger window: a breakpoint at the writer, hit by the program's own call.
    ce::gui::DebuggerWindow debugger(&process);
    for (int i = 0; i < 20; ++i) { QApplication::processEvents(); usleep(2000); }
    check(debugger.debugAttached(), "the debugger window attaches to the target");
    debugger.addBreakpointAt(writer);
    QMetaObject::invokeMethod(&debugger, "onContinue");
    QApplication::processEvents();
    std::printf("GUI_TARGET_ARMED\n");
    bool hit = false;
    for (int i = 0; i < 1000 && !hit; ++i) {
        QApplication::processEvents();
        usleep(10000);
        hit = debugger.debugStopped() && debugger.currentStopRip() == writer;
    }
    check(hit, "the debugger window stops at the writer when the program calls it");
    QMetaObject::invokeMethod(&debugger, "onDetach");
    QApplication::processEvents();
    check(!debugger.debugAttached(), "detaching the debugger window releases the target");
    std::printf("GUI_TARGET_RESULT=%s checks=6\n", failures ? "FAILED" : "PASSED");
    return failures == 0;
}
// `--ceserver-target PORT PID VALUE`: the same main-window scan and edit,
// with the target opened through a local ceserver (`cescan ceserver`).
static bool runCeserver(uint16_t port, pid_t pid, uintptr_t value) {
    ce::gui::MainWindow main;
    QString error;
    check(main.attachToCeserver("127.0.0.1", port, pid, &error), "the main window opens the target through ceserver");
    if (!error.isEmpty()) std::printf("ceserver attach error: %s\n", qPrintable(error));
    auto* type = main.findChild<QComboBox*>("scanValueType");
    auto* scanValue = main.findChild<QLineEdit*>("scanValue");
    auto* first = main.findChild<QPushButton*>("primaryButton");
    auto* next = main.findChild<QPushButton*>("nextScanButton");
    auto* results = main.findChild<ce::gui::ScanResultsModel*>();
    auto* records = main.findChild<ce::gui::AddressListModel*>();
    if (!type || !scanValue || !first || !next || !results || !records) return false;
    ce::os::LinuxProcessHandle local(pid);   // independent verification
    auto found = [&] {
        for (int row = 0; row < results->rowCount(); ++row)
            if (results->addressAt(row) == value) return true;
        return false;
    };
    type->setCurrentIndex(2);
    scanValue->setText("24681357");
    first->click();
    check(found(), "a GUI first scan over ceserver finds the field");
    int32_t changed = 24681358;
    auto wrote = local.write(value, &changed, sizeof(changed));
    scanValue->setText("24681358");
    next->click();
    check(wrote && found(), "a GUI next scan over ceserver keeps the field");
    int id = records->addEntry(value, ce::ValueType::Int32, "remote value");
    int row = records->rowOfId(id);
    bool edited = row >= 0 && records->setData(records->index(row, 4), "13579", Qt::EditRole);
    int32_t observed = 0;
    auto read = local.read(value, &observed, sizeof(observed));
    check(edited && read && observed == 13579, "an address-list edit over ceserver writes the target");
    std::printf("GUI_CESERVER_RESULT=%s checks=4\n", failures ? "FAILED" : "PASSED");
    return failures == 0;
}
} // namespace gui_target_test
