#include "gui/mainwindow.hpp"
#include "gui/memorybrowser.hpp"
#include "gui/codefinder.hpp"
#include "gui/graphicalmemoryview.hpp"
#include "gui/tracerwindow.hpp"
#include "gui/debuggerwindow.hpp"
#include "gui/scripteditor.hpp"
#include "core/expression.hpp"
#include <QInputDialog>
#include <QMessageBox>
#include <QTimer>
#include "core/value_io.hpp"

#include <QApplication>
#include <QAction>
#include <QTemporaryDir>
#include <QThread>
#include <QTextLayout>
#include <QTextBlock>
#include <QScrollBar>
#include <QScrollArea>
#include <cstring>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <cstdio>

alignas(8) static volatile int watched = 0;

static pid_t target() {
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        for (;;) { watched = watched + 1; usleep(1000); }
    }
    return child;
}

static bool trigger(QObject& window, const QString& text) {
    for (auto* action : window.findChildren<QAction*>()) {
        if (action->text() == text) { action->trigger(); return true; }
    }
    return false;
}

static bool usabilityChecks() {
    QTemporaryDir directory;
    ce::ScanResult result(directory.path().toStdString() + "/results");
    for (uint32_t i = 0; i < 25001; ++i) result.addResult(0x1000 + i * 4, &i, 4);
    result.finalize();
    ce::gui::ScanResultsModel results;
    results.setResult(&result, ce::ValueType::Int32, 4);
    bool incremental = results.rowCount() == 1000 && results.resultCount() == 25001;
    bool allValues = results.displayValueAt(25000, 1) == "25000";
    while (results.canFetchMore()) results.fetchMore();
    incremental = incremental && results.rowCount() == 25001 &&
        results.data(results.index(25000, 1), Qt::DisplayRole).toString() == "25000";
    incremental = incremental && results.rowCount(results.index(0, 0)) == 0 && !results.canFetchMore(results.index(0, 0));
    results.clear(); incremental = incremental && results.rowCount() == 0 && !results.canFetchMore();

    ce::ScanResult pointers(directory.path().toStdString() + "/pointers");
    uint32_t pointer = 0xFF123456;
    pointers.addResult(0x1000, &pointer, 4); pointers.finalize();
    results.setResult(&pointers, ce::ValueType::Pointer, 4);
    allValues = allValues && results.displayValueAt(0, 1) == "0xff123456";

    ce::ScanResult unicodeResults(directory.path().toStdString() + "/unicode");
    auto unicodeBytes = ce::encodeTypedValue(ce::ValueType::UnicodeString, "世界 😀");
    unicodeResults.addResult(0x1000, unicodeBytes->data(), unicodeBytes->size()); unicodeResults.finalize();
    results.setResult(&unicodeResults, ce::ValueType::UnicodeString, 40);
    allValues = allValues && results.displayValueAt(0, 1) == QString::fromUtf8("世界 😀");

    ce::os::LinuxProcessHandle process(getpid());
    ce::gui::AddressListModel records;
    records.setProcess(&process);
    bool errorReported = false;
    records.setActivationErrorCallback([&](const QString&, const QString&) { errorReported = true; });
    uint32_t number = 17;
    int scalar = records.rowCount();
    int scalarId = records.addEntry(reinterpret_cast<uintptr_t>(&number), ce::ValueType::Int32, "number");
    records.updateValues(&process);
    bool validation = !records.setData({}, "8", Qt::EditRole) && !records.setValue(scalarId, "17bad") && !records.setData(records.index(scalar, 4), "17bad", Qt::EditRole) &&
        number == 17 && records.entries()[scalar].currentValue == "17" && errorReported;
    char text[64] = "longer text";
    int string = records.rowCount();
    int stringId = records.addEntry(reinterpret_cast<uintptr_t>(text), ce::ValueType::String, "text");
    records.updateValues(&process);
    bool textWritten = records.setData(records.index(string, 4), QString::fromUtf8("世界"), Qt::EditRole);
    records.updateValues(&process);
    bool unicode = textWritten && records.entries()[string].currentValue == QString::fromUtf8("世界") && records.entries()[string].byteCount == 7 && text[6] == 0;
    bool cleared = records.setData(records.index(string, 4), "", Qt::EditRole) && text[0] == 0;
    records.updateValues(&process);
    cleared = cleared && records.entries()[string].currentValue.isEmpty();
    bool active = records.setActive(stringId, true);
    text[0] = 'X'; records.freezeWrite(&process);
    cleared = cleared && active && text[0] == 0;
    records.setActive(stringId, false);
    uint64_t large = 9007199254740993ULL;
    int largeRow = records.rowCount();
    int largeId = records.addEntry(reinterpret_cast<uintptr_t>(&large), ce::ValueType::Int64, "large");
    records.setSigned(largeId, false); records.updateValues(&process);
    records.setFreezeMode(largeRow, ce::FreezeMode::IncreaseOnly);
    bool largeFrozen = records.setActive(largeId, true);
    large = 9007199254740992ULL; records.freezeWrite(&process);
    validation = validation && largeFrozen && large == 9007199254740993ULL;
    records.setActive(largeId, false);
    unsigned char bytes[8] = {0xAA, 0xBB, 0xCC};
    int array = records.rowCount();
    records.addEntry(reinterpret_cast<uintptr_t>(bytes), ce::ValueType::ByteArray, "bytes", {}, 3);
    bool arrayValidation = !records.setData(records.index(array, 4), "90 XX 8B", Qt::EditRole) && bytes[0] == 0xAA;
    std::printf("gui usability: rows=%d export=%d validation=%d UTF8=%d clear=%d bytes=%d\n",
        incremental, allValues, validation, unicode, cleared, arrayValidation);
    return incremental && allValues && validation && unicode && cleared && arrayValidation;
}

static bool injectionTemplateChecks() {
    // This data has a valid x86 prologue and a distinct suffix for AOB uniqueness.
    alignas(16) static const uint8_t site[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10,
        0x90, 0x90, 0xc3, 0x57, 0xa8, 0x19, 0xd2, 0x45, 0x91, 0x3f, 0xb1, 0x16, 0xc5, 0xef,
        0x21, 0x42, 0x63, 0x84, 0x95, 0xb6, 0xc7, 0xd8, 0x59, 0x7a, 0x9b, 0xbc,
        0x11, 0x27, 0x39, 0x43, 0x58, 0x69, 0x70, 0x82, 0x9d, 0xa6, 0xb7, 0xc9,
        0xd4, 0xe5, 0xf1, 0x08, 0x14, 0x29, 0x32, 0x46, 0x5a, 0x67, 0x71, 0x8e,
        0x93, 0xa2, 0xb5, 0xc1, 0xde, 0xe9};
    ce::os::LinuxProcessHandle process(getpid());
    ce::AutoAssembler assembler;
    ce::gui::ScriptEditor editor(&process, &assembler);
    auto* input = editor.findChild<QPlainTextEdit*>();
    uintptr_t address = reinterpret_cast<uintptr_t>(site);
    editor.setInjectionAddress(address);
    bool ok = input;
    for (const auto& label : {"Code injection (at address)", "AOB injection", "Full code injection", "Pointer injection"}) {
        editor.setScript("");
        bool prefilled = false, prompted = false, unexpectedError = false;
        QTimer timer;
        timer.setInterval(5);
        QObject::connect(&timer, &QTimer::timeout, [&]() {
            if (auto* dialog = qobject_cast<QInputDialog*>(QApplication::activeModalWidget())) {
                if (dialog->windowTitle() == "Pointer injection") dialog->setTextValue("rdi");
                else {
                    prompted = true;
                    prefilled = ce::ExpressionParser(&process).parse(dialog->textValue().toStdString()) == address;
                }
                dialog->accept();
            } else if (auto* message = qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
                std::printf("template dialog error: %s\n", message->text().toUtf8().constData());
                unexpectedError = true; message->accept();
            }
        });
        timer.start();
        bool found = trigger(editor, label);
        timer.stop();
        QString script = input->toPlainText();
        bool generated = found && prompted && prefilled && !unexpectedError &&
            script.contains("assert(INJECT,55 48 89 E5 48 83 EC 10)") &&
            script.contains("  push rbp\n") && script.contains("  mov rbp, rsp\n") &&
            !script.contains("<address>") && !script.contains("<original");
        if (QString(label).startsWith("AOB")) generated = generated && script.contains("aobscanmodule(INJECT,");
        if (QString(label).startsWith("Pointer")) generated = generated && script.contains("mov [rel pPlayerBase], rdi");
        if (QString(label).startsWith("Full")) generated = generated && script.contains("originalcode:") && script.contains("exit:");
        std::printf("GUI template %s: %s\n", label, generated ? "OK" : "FAILED");
        ok = ok && generated;
    }
    return ok;
}

#include "test/gui_visual_review.hpp"

static bool visualInteractionChecks() {
    using namespace ce::gui;
    bool pickerOk = false, cancelOk = false, applyOk = false, fontOk = false, historyOk = false, syntaxOk = true;
    {
        ProcessListDialog picker;
        auto* list = picker.findChild<QListWidget*>();
        auto* filter = picker.findChild<QLineEdit*>();
        filter->setText("nonexistent_process_73acd");
        QMetaObject::invokeMethod(&picker, "onAccept", Qt::DirectConnection);
        pickerOk = picker.selectedPid() == 0 && picker.result() != QDialog::Accepted;
        for (auto* button : picker.findChildren<QPushButton*>())
            if (button->text() == "Open") pickerOk = pickerOk && !button->isEnabled();
        filter->clear();
        pickerOk = pickerOk && list->currentItem() && !list->currentItem()->isHidden();
        for (int i = 0; i < list->count(); ++i)
            if (list->item(i)->data(Qt::UserRole).toInt() == getpid()) list->setCurrentRow(i);
        int selected = list->currentItem()->data(Qt::UserRole).toInt();
        QMetaObject::invokeMethod(&picker, "refreshList", Qt::DirectConnection);
        pickerOk = pickerOk && list->currentItem()->data(Qt::UserRole).toInt() == selected;
    }
    QSettings().setValue("symbols/demangle", true);
    auto editDemangle = [](SettingsDialog& settings) {
        for (auto* box : settings.findChildren<QCheckBox*>())
            if (box->text() == "Demangle C++ symbol names") { box->setChecked(false); return true; }
        return false;
    };
    {
        SettingsDialog settings;
        cancelOk = editDemangle(settings) && QSettings().value("symbols/demangle").toBool();
        settings.reject();
        cancelOk = cancelOk && QSettings().value("symbols/demangle").toBool();
    }
    {
        MainWindow main;
        auto* settings = qobject_cast<SettingsDialog*>(main.openSettingsDialog("Display"));
        applyOk = editDemangle(*settings);
        settings->findChild<QSpinBox*>("displayFontSize")->setValue(14);
        QMetaObject::invokeMethod(settings, "onApply", Qt::DirectConnection);
        applyOk = applyOk && !QSettings().value("symbols/demangle").toBool();
        fontOk = true;
        for (auto* view : main.findChildren<QTableView*>())
            if (qobject_cast<AddressListModel*>(view->model()) || qobject_cast<ScanResultsModel*>(view->model()))
                fontOk = fontOk && view->font().pointSize() == 14;
        settings->close();
    }
    QSettings().setValue("display/fontSize", 10);
    applyTheme(false);
    bool canvasOk = false, fillOk = false, preferencesOk = false;
    {
        QSettings().remove("disasm/colorDefault");
        MemviewPreferences preferences;
        preferences.show();
        for (auto* button : preferences.findChildren<QPushButton*>())
            if (button->text() == "Apply") button->click();
        preferencesOk = preferences.isVisible() && !QSettings().contains("disasm/colorDefault");
        preferences.reject();
    }
    {
        FormDesigner designer;
        designer.resize(900, 640);
        designer.show();
        designer.findChildren<QSpinBox*>()[0]->setValue(4000);
        QApplication::processEvents();
        for (auto* scroll : designer.findChildren<QScrollArea*>())
            if (scroll->widget()->objectName() == "formDesignerCanvas") {
                canvasOk = designer.width() < 2000 && scroll->horizontalScrollBar()->maximum() > 0;
                applyTheme(true);
                canvasOk = canvasOk && scroll->widget()->styleSheet().contains(editorPalette().canvas.name());
            }
        canvasOk = canvasOk && designer.findChild<QPlainTextEdit*>()->toPlainText().contains("form.Width = 4000");
    }
    applyTheme(false);
    {
        ce::os::LinuxProcessHandle process(getpid());
        uint8_t byte = 0xA5;
        MemoryFillDialog fill(&process, reinterpret_cast<uintptr_t>(&byte));
        auto fields = fill.findChildren<QLineEdit*>();
        fields[1]->setText("1"); fields[2]->setText("100");
        bool warned = false;
        QTimer timer;
        QObject::connect(&timer, &QTimer::timeout, [&]() {
            if (auto* message = qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
                warned = message->text().contains("00 to FF");
                message->accept();
            }
        });
        timer.start(5);
        for (auto* button : fill.findChildren<QPushButton*>()) if (button->text() == "Fill") button->click();
        fillOk = warned && byte == 0xA5 && fill.result() != QDialog::Accepted;
    }
    {
        ce::AutoAssembler assembler;
        ScriptEditor editor(nullptr, &assembler);
        editor.setScript("{$if 1}\ndefine(name,\"//literal\") // actual comment\n");
        auto* input = editor.findChild<QPlainTextEdit*>();
        auto colorAt = [&](int line, int offset) {
            auto block = input->document()->findBlockByNumber(line);
            for (const auto& format : block.layout()->formats())
                if (offset >= format.start && offset < format.start + format.length)
                    return format.format.foreground().color();
            return QColor();
        };
        for (bool dark : {false, true}) {
            applyTheme(dark);
            QApplication::processEvents();
            syntaxOk = syntaxOk && colorAt(0, 5) == editorPalette().directive &&
                colorAt(1, 15) == editorPalette().string && colorAt(1, 28) == editorPalette().comment;
        }
        bool shortcut = false;
        for (auto* action : editor.actions())
            if (action->shortcut() == QKeySequence("Ctrl+I")) shortcut = true;
        syntaxOk = syntaxOk && shortcut && input->lineWrapMode() == QPlainTextEdit::NoWrap;
    }
    applyTheme(false);
    {
        ce::LuaEngine engine;
        LuaConsole console(&engine);
        console.runForTest("print('readable output')");
        auto* output = console.findChild<QPlainTextEdit*>();
        auto colorAtEnd = [&]() {
            QTextCursor cursor(output->document());
            cursor.movePosition(QTextCursor::End);
            cursor.movePosition(QTextCursor::PreviousCharacter, QTextCursor::KeepAnchor);
            return cursor.charFormat().foreground().color();
        };
        historyOk = colorAtEnd() == editorPalette().text;
        applyTheme(true);
        historyOk = historyOk && colorAtEnd() == editorPalette().text && output->toPlainText().contains("readable output");
        applyTheme(false);
        historyOk = historyOk && colorAtEnd() == editorPalette().text;
    }
    bool ok = pickerOk && cancelOk && applyOk && fontOk && historyOk && syntaxOk && canvasOk && fillOk && preferencesOk;
    std::printf("GUI visual interactions: %s (picker=%d cancel=%d apply=%d font=%d history=%d syntax=%d canvas=%d fill=%d preferences=%d)\n",
        ok ? "OK" : "FAILED", pickerOk, cancelOk, applyOk, fontOk, historyOk, syntaxOk, canvasOk, fillOk, preferencesOk);
    return ok;
}

int main(int argc, char** argv) {
    alarm(25);
    QTemporaryDir config;
    qputenv("XDG_CONFIG_HOME", config.path().toUtf8());
    qputenv("QT_QPA_PLATFORM", "offscreen");
    pid_t first = target(), second = target();
    if (first < 0 || second < 0) return 1;
    QApplication app(argc, argv);
    app.setOrganizationName("cecore-test");
    app.setApplicationName("gui-lifecycle");
    if (argc == 3 && QString::fromLocal8Bit(argv[1]) == "--screenshots") {
        alarm(90);
        int result = renderGuiReview(QString::fromLocal8Bit(argv[2]), first, reinterpret_cast<uintptr_t>(&watched));
        kill(first, SIGKILL); kill(second, SIGKILL);
        waitpid(first, nullptr, 0); waitpid(second, nullptr, 0);
        return result;
    }
    bool usability = usabilityChecks() && injectionTemplateChecks() && visualInteractionChecks();
    bool windowsReleased = false, traceReleased = false, debuggerReleased = false;
    {
        ce::gui::MainWindow main;
        main.attachToPid(first, "first");
        QPointer<ce::gui::MemoryBrowser> viewer = main.openMemoryView(reinterpret_cast<uintptr_t>(&watched));
        trigger(main, "Graphical memory view");
        QPointer<ce::gui::GraphicalMemoryView> pixels = main.findChild<ce::gui::GraphicalMemoryView*>();
        main.startFindWritesForTest(reinterpret_cast<uintptr_t>(&watched));
        QPointer<ce::gui::CodeFinderWindow> finder = main.findChild<ce::gui::CodeFinderWindow*>();
        QThread::msleep(40);
        bool hadWindows = pixels && finder && viewer;
        main.attachToPid(second, "second");
        app.processEvents();
        windowsReleased = hadWindows && !pixels && !finder && viewer;

        main.openMemoryView(reinterpret_cast<uintptr_t>(&watched));
        trigger(main, "Break and trace");
        QPointer<ce::gui::TracerWindow> tracer = main.findChild<ce::gui::TracerWindow*>();
        if (tracer) {
            tracer->findChildren<QLineEdit*>()[0]->setText("1");
            for (auto* button : tracer->findChildren<QPushButton*>())
                if (button->text() == "Start Trace") button->click();
            QThread::msleep(100);
            main.attachToPid(first, "first again");
            app.processEvents();
            traceReleased = !tracer;
        }
        main.openMemoryView(reinterpret_cast<uintptr_t>(&watched));
        trigger(main, "Full debugger");
        debuggerReleased = main.findChild<ce::gui::DebuggerWindow*>() != nullptr;
    }
    app.processEvents();
    int status = 0;
    bool targetsRunning = waitpid(first, &status, WNOHANG) == 0 && waitpid(second, &status, WNOHANG) == 0;
    kill(first, SIGKILL); kill(second, SIGKILL);
    waitpid(first, nullptr, 0); waitpid(second, nullptr, 0);
    bool ok = usability && windowsReleased && traceReleased && debuggerReleased && targetsRunning;
    std::printf("gui lifecycle smoke: %s (windows=%d trace=%d debugger=%d targets=%d)\n",
                ok ? "OK" : "FAILED", windowsReleased, traceReleased, debuggerReleased, targetsRunning);
    return ok ? 0 : 1;
}
