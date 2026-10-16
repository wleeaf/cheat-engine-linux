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
#include <QFile>
#include <QThread>
#include <QTextLayout>
#include <QTextBlock>
#include <QScrollBar>
#include <QScrollArea>
#include <QStatusBar>
#include <QSettings>
#include <QShortcut>
#include <QJsonArray>
#include <QJsonObject>
#include <cstring>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <cstdio>
#include <fstream>
#include <chrono>
#include <array>
#include <bit>

alignas(8) static volatile int watched = 0;

static pid_t target() {
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        for (;;) { watched = watched + 1; usleep(1000); }
    }
    return child;
}

static bool targetProgresses(pid_t pid) {
    // Verify that teardown released ptrace ownership and that the original
    // application continues making progress, in addition to checking exit status.
    std::ifstream status("/proc/"+std::to_string(pid)+"/status");
    std::string field;
    bool detached=false;
    while (status>>field) {
        if (field=="TracerPid:") { int tracer=-1; status>>tracer; detached=tracer==0; break; }
        std::string rest; std::getline(status,rest);
    }
    if (!detached) return false;
    ce::os::LinuxProcessHandle process(pid);
    int before=0,after=0;
    auto read=process.read(reinterpret_cast<uintptr_t>(&watched),&before,sizeof(before));
    if (!read || *read!=sizeof(before)) return false;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(1);
    while (std::chrono::steady_clock::now()<deadline) {
        usleep(1000);
        read=process.read(reinterpret_cast<uintptr_t>(&watched),&after,sizeof(after));
        if (!read || *read!=sizeof(after)) return false;
        if (after!=before) return true;
    }
    return false;
}

static bool trigger(QObject& window, const QString& text) {
    for (auto* action : window.findChildren<QAction*>()) {
        // A viewer frozen on an earlier target keeps its tools, disabled.
        if (action->text() == text && action->isEnabled()) { action->trigger(); return true; }
    }
    return false;
}

#include "gdb_gui_checks.inc"
#include "gui_injection_lifecycle_checks.inc"
#include "gui_editor_injection_checks.inc"

static bool allTypeModelChecks(const QString& screenshot = {}) {
    QTemporaryDir directory;
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto* memory = static_cast<uint8_t*>(mmap(nullptr, page * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (memory == MAP_FAILED) return false;
    const bool guarded = mprotect(memory + page, page, PROT_NONE) == 0;
    memory[page - 1] = 42;
    std::array<uint8_t,8> byteSample{42}, floatSample{};
    const float number = 2.5f;
    std::memcpy(floatSample.data(), &number, sizeof(number));
    ce::ScanResult result(directory.path().toStdString() + "/all");
    result.enableAllTypeCandidates();
    result.setDataFormat(std::endian::native == std::endian::big ? ce::ByteOrder::Big : ce::ByteOrder::Little, sizeof(uintptr_t));
    result.addAllTypeResult(reinterpret_cast<uintptr_t>(memory + page - 1), byteSample.data(), 1);
    result.addAllTypeResult(reinterpret_cast<uintptr_t>(floatSample.data()), floatSample.data(), 16);
    result.finalize();
    ce::os::LinuxProcessHandle process(getpid());
    ce::gui::ScanResultsModel model;
    model.setProcess(&process);
    model.setResult(&result, ce::ValueType::All, 8);
    ce::ValueIoOptions options;
    const auto expected = ce::decodeTypedValue(ce::ValueType::ByteArray, {floatSample.data(), 4}, options);
    bool saved = expected && model.displayValueAt(0, 2) == "2A" &&
        model.displayValueAt(1, 2) == QString::fromStdString(*expected);
    model.refreshRange(0, 1);
    bool live = model.displayValueAt(0, 1) == "2A" &&
        model.displayValueAt(1, 1) == model.displayValueAt(1, 2);
    floatSample[7] = 0xff;
    model.refreshRange(0, 1);
    bool padding = !model.data(model.index(1, 1), Qt::ForegroundRole).isValid() &&
        model.displayValueAt(1, 1) == model.displayValueAt(1, 2);
    memory[page - 1] = 43;
    model.refreshRange(0, 1);
    bool changed = model.displayValueAt(0, 1) == "2B" && model.displayValueAt(0, 2) == "2A" &&
        model.data(model.index(0, 1), Qt::ForegroundRole).isValid();
    bool rendered = true;
    if (!screenshot.isEmpty()) {
        QTableView view;
        view.setWindowTitle("All scan results");
        view.setModel(&model);
        view.resize(600, 220);
        view.resizeColumnsToContents();
        view.show();
        QApplication::processEvents();
        rendered = view.grab().save(screenshot);
    }
    munmap(memory, page * 2);
    std::printf("GUI All-type model: %s (guard=%d saved=%d live=%d padding=%d changed=%d screenshot=%d)\n",
        guarded && saved && live && padding && changed && rendered ? "OK" : "FAILED",
        guarded, saved, live, padding, changed, rendered);
    return guarded && saved && live && padding && changed && rendered;
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
    // Arrange keeps subtrees together: B moves above the whole group, and
    // indenting the group takes its child along.
    ce::gui::AddressListModel arranged;
    const int g = arranged.createGroup("G");
    const int a = arranged.createEntry(0x1000, ce::ValueType::Int32, "A");
    arranged.setIndent(a, 1);
    const int b = arranged.createEntry(0x2000, ce::ValueType::Int32, "B");
    const int moved = arranged.moveEntry(arranged.rowOfId(b), -1);
    bool arrange = moved == 0 && arranged.entries()[0].id == b && arranged.entries()[1].id == g &&
                   arranged.entries()[2].id == a;
    arranged.indentRows({arranged.rowOfId(g)});
    arrange = arrange && arranged.entries()[arranged.rowOfId(g)].indent == 1 &&
              arranged.entries()[arranged.rowOfId(a)].indent == 2;
    std::printf("gui usability: rows=%d export=%d validation=%d UTF8=%d clear=%d bytes=%d arrange=%d\n",
        incremental, allValues, validation, unicode, cleared, arrayValidation, arrange);
    return incremental && allValues && validation && unicode && cleared && arrayValidation && arrange;
}

static bool allTypeGuiScanChecks(const QString& screenshot = {}) {
    alignas(16) float number = 2.5f;
    ce::gui::MainWindow main;
    main.attachToPid(getpid(), "scan fixture");
    auto* type = main.findChild<QComboBox*>("scanValueType");
    auto* comparison = main.findChild<QComboBox*>("scanComparison");
    auto* lower = main.findChild<QLineEdit*>("scanValue");
    auto* upper = main.findChild<QLineEdit*>("scanValueUpper");
    auto* from = main.findChild<QLineEdit*>("scanFrom");
    auto* to = main.findChild<QLineEdit*>("scanTo");
    auto* first = main.findChild<QPushButton*>("primaryButton");
    auto* next = main.findChild<QPushButton*>("nextScanButton");
    auto* results = main.findChild<ce::gui::ScanResultsModel*>();
    auto* rounding = main.findChild<QComboBox*>("scanRounding");
    auto* tolerance = main.findChild<QLineEdit*>("scanTolerance");
    if (!type || !comparison || !lower || !upper || !from || !to || !first || !next || !results || !rounding || !tolerance) return false;
    const uintptr_t address = reinterpret_cast<uintptr_t>(&number);
    from->setText(QString("0x%1").arg(address, 0, 16));
    to->setText(QString("0x%1").arg(address + sizeof(number) - 1, 0, 16));
    type->setCurrentIndex(10);
    comparison->setCurrentIndex(3);
    lower->setText("2.0"); upper->setText("3.0");
    ce::ValueIoOptions options;
    auto expected = ce::decodeTypedValue(ce::ValueType::ByteArray,
        {reinterpret_cast<const uint8_t*>(&number), sizeof(number)}, options);
    first->click();
    bool firstBetween = expected && results->rowCount() == 1 &&
        results->displayValueAt(0, 2) == QString::fromStdString(*expected) && type->isEnabled();
    lower->setText("2.4"); upper->setText("2.6"); next->click();
    bool nextBetween = results->rowCount() == 1 &&
        results->displayValueAt(0, 2) == QString::fromStdString(*expected);
    int errors=0;
    QTimer dismiss;
    dismiss.setInterval(5);
    QObject::connect(&dismiss, &QTimer::timeout, [&] {
        if (auto* dialog=qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
            ++errors; dialog->accept();
        }
    });
    upper->setText("2.6oops"); dismiss.start(); next->click(); dismiss.stop();
    bool malformed=errors==1 && results->rowCount()==1 && results->displayValueAt(0,2)==QString::fromStdString(*expected);
    type->setCurrentIndex(4); comparison->setCurrentIndex(0); lower->setText("2.5"); next->click();
    bool selection = results->rowCount() == 1 && results->displayValueAt(0, 2) == "2.5" && !type->isEnabled();
    first->click(); // New Scan releases the old typed session.
    type->setCurrentIndex(10); lower->setText("3e-2"); number=0.0f; first->click();
    bool scientific=results->rowCount()==0;
    first->click();type->setCurrentIndex(4);number=0.0f;first->click();
    bool typedScientific=results->rowCount()==0;
    first->click();number=0.05f;lower->setText("0.1");first->click();
    bool rounded=results->rowCount()==1 && results->displayValueAt(0,2)=="0.05" &&
        main.statusBar()->currentMessage().startsWith("First scan complete.");
    lower->setText("1e-1");next->click();rounded=rounded && results->rowCount()==1 &&
        main.statusBar()->currentMessage().startsWith("Next scan complete.");
    lower->setText("0.1oops");dismiss.start();next->click();dismiss.stop();
    bool typedMalformed=errors==2 && results->rowCount()==1 && results->displayValueAt(0,2)=="0.05";
    lower->setText("0.1");rounding->setCurrentIndex(3);tolerance->setText("oops");
    dismiss.start();next->click();dismiss.stop();
    bool invalidTolerance=errors==3 && results->rowCount()==1;
    tolerance->setText("0.05");next->click();bool extreme=results->rowCount()==1;
    tolerance->setText("1e8");bool wideTolerance=tolerance->hasAcceptableInput();
    tolerance->setText("0.000000000001");wideTolerance=wideTolerance && tolerance->hasAcceptableInput();
    tolerance->setText("0.05");
    bool rendered=true;
    if(!screenshot.isEmpty()) {
        main.resize(1200,800);main.show();QApplication::processEvents();
        rendered=main.grab().save(screenshot);
    }
    bool ok=firstBetween && nextBetween && selection && malformed && scientific && typedScientific && rounded &&
        typedMalformed && invalidTolerance && extreme && wideTolerance && rendered;
    std::printf("GUI All scan controls: %s (first-between=%d next-between=%d selection=%d malformed=%d scientific=%d)\n",
        firstBetween && nextBetween && selection && malformed && scientific ? "OK" : "FAILED",
        firstBetween, nextBetween, selection, malformed, scientific);
    std::printf("GUI floating scan controls: %s (scientific=%d rounded=%d malformed=%d tolerance=%d extreme=%d wide=%d screenshot=%d)\n",
        ok ? "OK" : "FAILED",typedScientific,rounded,typedMalformed,invalidTolerance,extreme,wideTolerance,rendered);
    return ok;
}

#include "gui_scan_format_checks.inc"
#include "gui_table_save_checks.inc"

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

#include <QTreeWidget>
#include "test/gui_visual_review.hpp"

static bool visualInteractionChecks() {
    using namespace ce::gui;
    bool pickerOk = false, cancelOk = false, applyOk = false, fontOk = false, historyOk = false, syntaxOk = true;
    {
        ProcessListDialog picker;
        auto* list = picker.findChild<QTreeWidget*>();
        auto* filter = picker.findChild<QLineEdit*>();
        filter->setText("nonexistent_process_73acd");
        QMetaObject::invokeMethod(&picker, "onAccept", Qt::DirectConnection);
        pickerOk = picker.selectedPid() == 0 && picker.result() != QDialog::Accepted;
        for (auto* button : picker.findChildren<QPushButton*>())
            if (button->text() == "Open") pickerOk = pickerOk && !button->isEnabled();
        filter->clear();
        pickerOk = pickerOk && list->currentItem() && !list->currentItem()->isHidden();
        // Our own process is listed under its full name, owned by us, so it stays
        // visible with "Only my processes" on.
        bool ownListed = false;
        for (int i = 0; i < list->topLevelItemCount(); ++i)
            if (list->topLevelItem(i)->data(0, Qt::UserRole).toInt() == getpid()) {
                list->setCurrentItem(list->topLevelItem(i));
                ownListed = !list->topLevelItem(i)->isHidden();
            }
        pickerOk = pickerOk && ownListed;
        int selected = list->currentItem()->data(0, Qt::UserRole).toInt();
        QMetaObject::invokeMethod(&picker, "refreshList", Qt::DirectConnection);
        pickerOk = pickerOk && list->currentItem()->data(0, Qt::UserRole).toInt() == selected;
    }
    QSettings().setValue("display/hexUpper", true);
    auto editHexCase = [](SettingsDialog& settings) {
        for (auto* box : settings.findChildren<QCheckBox*>())
            if (box->text().startsWith("Uppercase hexadecimal")) { box->setChecked(false); return true; }
        return false;
    };
    {
        SettingsDialog settings;
        cancelOk = editHexCase(settings) && QSettings().value("display/hexUpper").toBool();
        settings.reject();
        cancelOk = cancelOk && QSettings().value("display/hexUpper").toBool();
    }
    {
        MainWindow main;
        auto* settings = qobject_cast<SettingsDialog*>(main.openSettingsDialog("Display"));
        applyOk = editHexCase(*settings);
        settings->findChild<QSpinBox*>("displayFontSize")->setValue(14);
        QMetaObject::invokeMethod(settings, "onApply", Qt::DirectConnection);
        applyOk = applyOk && !QSettings().value("display/hexUpper").toBool();
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

// Counts module list reads: a refresh or freeze pass reads it once, not once per record.
struct CountingProcess : ce::os::LinuxProcessHandle {
    using LinuxProcessHandle::LinuxProcessHandle;
    int moduleReads = 0;
    std::vector<ce::ModuleInfo> modules() override { ++moduleReads; return LinuxProcessHandle::modules(); }
};
alignas(8) static int32_t reviewValues[3] = {5, 6, 7};

// Main window runtime behaviour: one module list per pass, live values for
// frozen records, format changes that end a freeze, group toggles and their
// hotkeys, range removal, collapse after indenting, the display settings in
// the lists, and stale "Wait for process" hits.
static bool mainWindowRuntimeChecks(pid_t first, pid_t second) {
    using namespace ce::gui;
    CountingProcess process(getpid());
    AddressListModel records;
    records.setProcess(&process);
    const auto modules = process.modules();
    std::vector<int> ids;
    for (auto& value : reviewValues) {
        const auto where = ce::moduleOffsetString(modules, reinterpret_cast<uintptr_t>(&value));
        ids.push_back(records.addEntry(0, ce::ValueType::Int32, "value", QString::fromStdString(where)));
    }
    process.moduleReads = 0;
    records.updateValues(&process);
    bool oneRead = process.moduleReads == 1 && records.entries()[0].currentValue == "5" &&
        records.entries()[2].currentValue == "7";
    records.setFreezeMode(0, ce::FreezeMode::IncreaseOnly);
    for (int id : ids) oneRead = records.setActive(id, true) && oneRead;
    process.moduleReads = 0;
    records.freezeWrite(&process);
    oneRead = oneRead && process.moduleReads == 1;

    // An Increase Only record lets the value rise and shows it, but saves the frozen value.
    reviewValues[0] = 30;
    records.freezeWrite(&process);
    records.updateValues(&process);
    bool live = reviewValues[0] == 30 && records.entries()[0].currentValue == "30" &&
        records.entries()[0].frozenValue == "5" && records.toJson()[0].toObject()["value"].toString() == "5";

    // New byte order: the frozen text is not rewritten in it; the freeze ends.
    records.setEntryBigEndian(1, true);
    reviewValues[1] = 9;
    records.freezeWrite(&process);
    bool format = !records.entries()[1].active && reviewValues[1] == 9 && records.entries()[2].active;
    format = format && records.setActive(ids[1], true);
    records.setEntryBigEndian(1, true);   // unchanged order: the freeze stays
    format = format && records.entries()[1].active;

    // Toggling a group header reaches its children, as the check box does.
    AddressListModel tree;
    const int group = tree.createGroup("G");
    const int inner = tree.createGroup("H");
    tree.setIndent(inner, 1);
    tree.toggleActive(tree.rowOfId(group));
    bool groups = tree.entries()[0].active && tree.entries()[1].active;
    tree.toggleActive(tree.rowOfId(group));
    groups = groups && !tree.entries()[0].active && !tree.entries()[1].active;

    // A group and its subtree go in one removal.
    tree.createEntry(0x1000, ce::ValueType::Int32, "after");
    int removals = 0;
    QObject::connect(&tree, &QAbstractItemModel::rowsRemoved, [&] { ++removals; });
    bool removed = tree.removeEntries({0}) && tree.rowCount() == 1 && removals == 1;

    bool collapse = false, hotkeys = false, display = false, stale = false;
    {
        MainWindow main;
        QTableView* table = nullptr;
        for (auto* view : main.findChildren<QTableView*>())
            if (qobject_cast<AddressListModel*>(view->model())) table = view;
        auto* model = table ? qobject_cast<AddressListModel*>(table->model()) : nullptr;
        if (model) {
            const int g = model->createGroup("G");
            model->setHotkeyKeys(model->rowOfId(g), "Ctrl+Shift+F9");
            const int h = model->createGroup("H");
            model->setIndent(h, 1);
            const int r = model->createEntry(0xabc, ce::ValueType::Int32, "R");
            model->setValueHotkeys(model->rowOfId(r), "Ctrl+Shift+F10", {}, "1", {}, {});
            model->toggleGroupCollapse(model->rowOfId(g));
            QApplication::processEvents();   // the queued hotkey rebuild
            // Indenting into a collapsed group hides the row.
            model->indentRows({model->rowOfId(r)});
            collapse = table->isRowHidden(model->rowOfId(h)) && table->isRowHidden(model->rowOfId(r));
            model->outdentRows({model->rowOfId(r)});
            collapse = collapse && !table->isRowHidden(model->rowOfId(r));
            // The group's toggle hotkey is registered and fires once per press;
            // increase repeats while held.
            QApplication::processEvents();
            bool toggle = false, increase = false;
            for (auto* shortcut : main.findChildren<QShortcut*>()) {
                if (shortcut->key() == QKeySequence("Ctrl+Shift+F9") && !shortcut->autoRepeat()) {
                    emit shortcut->activated();
                    toggle = model->entries()[model->rowOfId(h)].active;
                }
                if (shortcut->key() == QKeySequence("Ctrl+Shift+F10")) increase = shortcut->autoRepeat();
            }
            hotkeys = toggle && increase;

            QSettings().setValue("display/hexUpper", true);
            QSettings().setValue("display/addressWidth", 0);
            auto* settings = qobject_cast<SettingsDialog*>(main.openSettingsDialog("Display"));
            QMetaObject::invokeMethod(settings, "onApply", Qt::DirectConnection);
            display = model->data(model->index(model->rowOfId(r), 2), Qt::DisplayRole).toString() == "0x00000ABC";
            settings->close();
            QApplication::processEvents();
            QSettings().setValue("display/hexUpper", false);
            QSettings().setValue("display/addressWidth", 1);
            settings = qobject_cast<SettingsDialog*>(main.openSettingsDialog("Display"));
            QMetaObject::invokeMethod(settings, "onApply", Qt::DirectConnection);
            display = display && model->data(model->index(model->rowOfId(r), 2), Qt::DisplayRole).toString() == "0x0000000000000abc";
            settings->close();
        }
        // A hit from a watch that a manual attach ended does not replace that target.
        const quint64 watch = main.processWatch_;
        main.attachToPid(first, "manual");
        main.autoAttach(second, "late", watch);
        QApplication::processEvents();
        stale = main.windowTitle().contains("manual") && !main.windowTitle().contains("late");
    }
    QApplication::processEvents();
    const bool ok = oneRead && live && format && groups && removed && collapse && hotkeys && display && stale;
    std::printf("GUI main window runtime: %s (modules=%d live=%d format=%d groups=%d removal=%d collapse=%d hotkeys=%d display=%d stale=%d)\n",
        ok ? "OK" : "FAILED", oneRead, live, format, groups, removed, collapse, hotkeys, display, stale);
    return ok;
}

#include "test/gui_target_checks.inc"

int main(int argc, char** argv) {
    // Keep the last completed stage visible if the deadline terminates a CI
    // run while stdout is redirected to a file.
    std::setvbuf(stdout,nullptr,_IOLBF,0);
    alarm(25);
    QTemporaryDir config;
    qputenv("XDG_CONFIG_HOME", config.path().toUtf8());
    qputenv("XDG_CACHE_HOME", config.path().toUtf8());
    qputenv("QT_QPA_PLATFORM", "offscreen");
    if (argc == 5 && QString::fromLocal8Bit(argv[1]) == "--ceserver-target") {
        alarm(90);
        QApplication app(argc, argv);
        app.setOrganizationName("cecore-test");
        app.setApplicationName("gui-ceserver-target");
        return gui_target_test::runCeserver(static_cast<uint16_t>(std::strtoul(argv[2], nullptr, 10)),
            static_cast<pid_t>(std::strtol(argv[3], nullptr, 10)), std::strtoull(argv[4], nullptr, 0)) ? 0 : 1;
    }
    if (argc == 5 && QString::fromLocal8Bit(argv[1]) == "--target") {
        alarm(60);
        QApplication app(argc, argv);
        app.setOrganizationName("cecore-test");
        app.setApplicationName("gui-target");
        return gui_target_test::run(static_cast<pid_t>(std::strtol(argv[2], nullptr, 10)),
            std::strtoull(argv[3], nullptr, 0), std::strtoull(argv[4], nullptr, 0)) ? 0 : 1;
    }
    if (argc == 4 && QString::fromLocal8Bit(argv[1]) == "--editor-injection-only") {
        alarm(45);
        signal(SIGPIPE, SIG_IGN);
        QApplication app(argc, argv);
        app.setOrganizationName("cecore-test");
        app.setApplicationName("gui-editor-injection");
        return gui_editor_injection_test::run(argv[2], argv[3]) ? 0 : 1;
    }
    if (argc == 4 && QString::fromLocal8Bit(argv[1]) == "--injection-lifecycle-only") {
        alarm(45);
        signal(SIGPIPE, SIG_IGN);
        QApplication app(argc, argv);
        app.setOrganizationName("cecore-test");
        app.setApplicationName("gui-injection");
        return gui_injection_test::run(argv[2], argv[3]) ? 0 : 1;
    }
    if (argc>=2 && QString::fromLocal8Bit(argv[1])=="--table-save-only") {
        QApplication app(argc,argv);
        app.setOrganizationName("cecore-test");
        app.setApplicationName("table-save");
        return guiTableSaveChecks() ? 0:1;
    }
    if (argc >= 2 && QString::fromLocal8Bit(argv[1]) == "--scan-model-only") {
        QApplication app(argc, argv);
        app.setOrganizationName("cecore-test");
        app.setApplicationName("scan-model");
        const QString shot=argc==3 ? QString::fromLocal8Bit(argv[2]) : QString{};
        return usabilityChecks() && allTypeModelChecks(shot) && allTypeGuiScanChecks(shot.isEmpty() ? QString{} : shot+".controls.png") && guiScanFormatChecks(shot.isEmpty() ? QString{} : shot+".format.png") ? 0 : 1;
    }
    if (argc==4 && (QString::fromLocal8Bit(argv[1]).startsWith("gdb-") || QString::fromLocal8Bit(argv[1])=="qemu-gui")) {
        alarm(40);
        QApplication app(argc,argv);
        app.setOrganizationName("cecore-test");app.setApplicationName("gdb-gui");
        return gdbGuiChecks(QString::fromLocal8Bit(argv[1]),QString::fromLocal8Bit(argv[2]),QString::fromLocal8Bit(argv[3]).toInt());
    }
    pid_t first = target(), second = target();
    if (first < 0 || second < 0) return 1;
    QApplication app(argc, argv);
    app.setOrganizationName("cecore-test");
    app.setApplicationName("gui-lifecycle");
    if (argc == 3 && QString::fromLocal8Bit(argv[1]) == "--screenshots") {
        alarm(300);
        int result = renderGuiReview(QString::fromLocal8Bit(argv[2]), first, reinterpret_cast<uintptr_t>(&watched));
        kill(first, SIGKILL); kill(second, SIGKILL);
        waitpid(first, nullptr, 0); waitpid(second, nullptr, 0);
        return result;
    }
    bool usability = usabilityChecks() && allTypeModelChecks() && allTypeGuiScanChecks() && guiScanFormatChecks() && guiTableSaveChecks() && injectionTemplateChecks() && visualInteractionChecks() &&
        mainWindowRuntimeChecks(first, second);
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
    int firstStatus=0,secondStatus=0;
    auto firstWait=waitpid(first,&firstStatus,WNOHANG);
    auto secondWait=waitpid(second,&secondStatus,WNOHANG);
    if (firstWait!=0 || secondWait!=0)
        std::printf("GUI target wait results: first=%ld status=0x%x second=%ld status=0x%x\n",
                    static_cast<long>(firstWait),firstStatus,static_cast<long>(secondWait),secondStatus);
    bool targetsRunning=firstWait>=0 && secondWait>=0 &&
        (firstWait==0 || WIFSTOPPED(firstStatus)) && (secondWait==0 || WIFSTOPPED(secondStatus)) &&
        targetProgresses(first) && targetProgresses(second);
    kill(first, SIGKILL); kill(second, SIGKILL);
    waitpid(first, nullptr, 0); waitpid(second, nullptr, 0);
    bool ok = usability && windowsReleased && traceReleased && debuggerReleased && targetsRunning;
    std::printf("gui lifecycle smoke: %s (windows=%d trace=%d debugger=%d targets=%d)\n",
                ok ? "OK" : "FAILED", windowsReleased, traceReleased, debuggerReleased, targetsRunning);
    return ok ? 0 : 1;
}
