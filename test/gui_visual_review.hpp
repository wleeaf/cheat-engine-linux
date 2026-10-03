#pragma once
// Render real widgets for repeatable visual inspection in an isolated settings store.
#include "gui/theme.hpp"
#include "gui/processlistdialog.hpp"
#include "gui/settingsdialog.hpp"
#include "gui/changeaddressdialog.hpp"
#include "gui/pointerscan_dialog.hpp"
#include "gui/scripteditor.hpp"
#include "gui/luaconsole.hpp"
#include "gui/structuredissector.hpp"
#include "gui/memoryregions.hpp"
#include "gui/modulelist.hpp"
#include "gui/threadlist.hpp"
#include "gui/monodissector.hpp"
#include "gui/advancedoptions.hpp"
#include "gui/branchmapper.hpp"
#include "gui/codereferences.hpp"
#include "gui/elfinspector.hpp"
#include "gui/filepatcher.hpp"
#include "gui/findstaticswindow.hpp"
#include "gui/formdesigner.hpp"
#include "gui/graphicalmemoryview.hpp"
#include "gui/guest_scan_dialog.hpp"
#include "gui/heapregions.hpp"
#include "gui/memoryfill.hpp"
#include "gui/memviewpreferences.hpp"
#include "gui/registereditor.hpp"
#include "gui/stackview.hpp"
#include "core/injection_gen.hpp"
#include <QDir>
#include <QSettings>
#include <QListWidget>
#include <QTabWidget>
#include <QHeaderView>
#include <QTextEdit>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QFile>

__attribute__((noinline)) static int visualReviewCode(int x) { volatile int n = x; return n * 3 + 7; }

static int renderGuiReview(const QString& directory, pid_t pid, uintptr_t valueAddress) {
    using namespace ce::gui;
    QDir().mkpath(directory);
    QJsonArray files;
    bool saved = true;
    auto capture = [&](QWidget& w, const QString& name, QSize size = {}) {
        if (size.isValid()) w.resize(size);
        w.show();
        for (int i = 0; i < 12; ++i) { QApplication::processEvents(); QThread::msleep(5); }
        QString file = name + ".png";
        saved = w.grab().save(directory + "/" + file) && saved;
        files.append(QJsonObject{{"file", file}, {"width", w.width()}, {"height", w.height()}});
        w.hide();
    };
    ce::os::LinuxProcessHandle process(pid);
    QTemporaryDir resultsDir;
    ce::ScanResult results(resultsDir.path().toStdString() + "/results");
    for (uint32_t i = 0; i < 24; ++i) results.addResult(valueAddress + i * 4, &i, 4);
    results.finalize();
    for (bool dark : {false, true}) {
        QSettings().setValue(kDarkThemeKey, dark);
        applyTheme(dark);
        QString prefix = dark ? "dark-" : "light-";
        {
            MainWindow main;
            capture(main, prefix + "main-empty", {920, 760});
            main.attachToPid(pid, "Example Game (64-bit)");
            auto* model = main.findChild<AddressListModel*>();
            model->addEntry(valueAddress, ce::ValueType::Int32, "Player health");
            model->addEntry(valueAddress, ce::ValueType::Float, "Movement speed");
            model->addEntry(valueAddress, ce::ValueType::Int32, "A descriptive cheat name that should remain readable when resizing");
            model->addGroup("Player settings");
            main.findChild<ScanResultsModel*>()->setResult(&results, ce::ValueType::Int32, 4);
            model->updateValues(&process);
            for (auto* label : main.findChildren<QLabel*>()) if (label->text() == "Found: 0") label->setText("Found: 24");
            capture(main, prefix + "main-populated", {1000, 780});
            capture(main, prefix + "main-compact", {760, 600});
            auto* settings = qobject_cast<SettingsDialog*>(main.openSettingsDialog("Display"));
            settings->findChild<QSpinBox*>("displayFontSize")->setValue(14);
            QMetaObject::invokeMethod(settings, "onApply", Qt::DirectConnection);
            settings->close();
            capture(main, prefix + "main-large-font", {1000, 820});
            QSettings().setValue("display/fontSize", 10);
        }
        {
            ProcessListDialog picker;
            capture(picker, prefix + "processes", {600, 500});
            picker.findChild<QLineEdit*>()->setText("nonexistent_process_73acd");
            capture(picker, prefix + "processes-empty", {460, 480});
        }
        {
            SettingsDialog settings;
            auto* nav = settings.findChild<QListWidget*>();
            for (int i = 0; i < nav->count(); ++i) {
                nav->setCurrentRow(i);
                capture(settings, prefix + "settings-" + QString::number(i), {720, 500});
            }
        }
        {
            MemoryBrowser browser(&process);
            browser.gotoAddress(reinterpret_cast<uintptr_t>(&visualReviewCode));
            capture(browser, prefix + "memory", {1000, 720});
        }
        {
            ce::AutoAssembler assembler;
            ScriptEditor editor(&process, &assembler);
            editor.setScript("[ENABLE]\n// Edit the code below\ndefine(INJECT,game.bin+0x100)\nalloc(newmem,$1000,INJECT)\nlabel(return)\nnewmem:\n  mov eax,[rel INJECT+0x40]\n  jmp return\nINJECT:\n  jmp near newmem\nreturn:\n[DISABLE]\nINJECT:\n  db 8B 05 3A 00 00 00\ndealloc(newmem)\n");
            auto* output = editor.findChild<QTextEdit*>();
            output->setTextColor(editorPalette().success); output->append("Script executed successfully.");
            output->setTextColor(editorPalette().error); output->append("Example error: the bytes at the injection site changed.");
            capture(editor, prefix + "assembler", {820, 580});
            capture(editor, prefix + "assembler-compact", {520, 400});
        }
        {
            ce::LuaEngine engine;
            LuaConsole console(&engine);
            console.runForTest("print('Player health:', 100)");
            console.runForTest("error('Example diagnostic')");
            capture(console, prefix + "lua", {760, 440});
        }
        {
            StructureDissector structure(&process, valueAddress);
            capture(structure, prefix + "structure", {1050, 620});
        }
        {
            PointerScanDialog pointers(&process);
            capture(pointers, prefix + "pointers", {820, 500});
        }
        {
            ChangeAddressDialog address("[game.bin+0x120]+0x20", ce::ValueType::Int32, false, 1, nullptr, true, &process);
            capture(address, prefix + "address", {520, 430});
        }
        {
            ModuleListWindow modules(&process);
            capture(modules, prefix + "modules", {900, 560});
            MemoryRegionsWindow regions(&process);
            capture(regions, prefix + "regions", {900, 560});
            ThreadListWindow threads(&process);
            capture(threads, prefix + "threads", {700, 420});
            DebuggerWindow debugger(&process);
            capture(debugger, prefix + "debugger", {1000, 720});
        }
        { AdvancedOptionsWindow window(&process); capture(window, prefix + "advanced"); }
        { BranchMapper window(&process); capture(window, prefix + "branches"); }
        { CodeReferencesWindow window(&process); capture(window, prefix + "references"); }
        { ElfInspector window(QCoreApplication::applicationFilePath()); capture(window, prefix + "elf"); }
        { FilePatcher window; capture(window, prefix + "file-patcher"); }
        { FindStaticsWindow window(&process); capture(window, prefix + "find-statics"); }
        {
            FormDesigner window;
            capture(window, prefix + "form-designer");
            window.findChildren<QSpinBox*>()[0]->setValue(2000);
            capture(window, prefix + "form-designer-large-canvas", {900, 640});
        }
        {
            GraphicalMemoryView window(&process);
            capture(window, prefix + "graphical-memory");
            window.gotoAddress(valueAddress);
            capture(window, prefix + "graphical-memory-populated");
        }
        { GuestScanDialog window(&process); capture(window, prefix + "guest-scan"); }
        { HeapRegionsWindow window(&process); capture(window, prefix + "heaps"); }
        { MemoryFillDialog window(&process, valueAddress); capture(window, prefix + "fill"); }
        { MemviewPreferences window; capture(window, prefix + "disasm-preferences"); }
        { RegisterEditorWindow window(&process); capture(window, prefix + "registers"); }
        { StackViewWindow window(&process); capture(window, prefix + "stack"); }
        { MonoDissectorWindow window(&process); capture(window, prefix + "mono"); }
    }
    QFile manifest(directory + "/screenshots.json");
    if (manifest.open(QIODevice::WriteOnly)) manifest.write(QJsonDocument(files).toJson());
    std::printf("GUI visual review: %lld screenshots, %s\n", static_cast<long long>(files.size()), saved ? "OK" : "FAILED");
    return saved ? 0 : 1;
}
