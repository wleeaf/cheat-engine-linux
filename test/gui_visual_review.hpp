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
#include <QMenuBar>
#include <QMenu>
#include <QElapsedTimer>
#include <QProgressBar>
#include <QComboBox>
#include <QTimer>
#include <functional>
#include <set>

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
        // Item views lay their rows out lazily; settle them before grabbing.
        for (auto* view : w.findChildren<QAbstractItemView*>()) view->doItemsLayout();
        QString file = name + ".png";
        saved = w.grab().save(directory + "/" + file) && saved;
        files.append(QJsonObject{{"file", file}, {"width", w.width()}, {"height", w.height()}});
        w.hide();
    };
    auto pump = [](int rounds = 12) { for (int i = 0; i < rounds; ++i) { QApplication::processEvents(); QThread::msleep(5); } };
    auto grabTo = [&](QWidget* w, const QString& name) {
        QString file = name + ".png";
        saved = w->grab().save(directory + "/" + file) && saved;
        files.append(QJsonObject{{"file", file}, {"width", w->width()}, {"height", w->height()}});
    };
    // Open something (a modal dialog, a window, a context menu), then capture and
    // close whatever new top-level widget appeared. Works for exec() and show().
    auto captureNew = [&](const std::function<void()>& open, const QString& name, QSize size = {}) {
        std::set<QWidget*> before;
        for (auto* w : QApplication::topLevelWidgets()) if (w->isVisible()) before.insert(w);
        bool done = false;
        auto take = [&]() {
            if (done) return;
            done = true;
            QWidget* found = nullptr;
            for (auto* w : QApplication::topLevelWidgets())
                if (w->isVisible() && !before.count(w)) found = w;
            if (!found) { std::printf("visual review: nothing opened for %s\n", qPrintable(name)); return; }
            if (size.isValid()) found->resize(size);
            pump();
            grabTo(found, name);
            if (auto* dialog = qobject_cast<QDialog*>(found)) dialog->reject();
            else found->close();
        };
        QTimer::singleShot(250, take);
        open();
        QElapsedTimer waited; waited.start();
        while (!done && waited.elapsed() < 2000) pump(1);
        take();
        pump();
    };
    // Open a context menu, pick one of its items, and capture the dialog it opens.
    auto captureMenuAction = [&](const std::function<void()>& openMenu, const QString& actionText, const QString& name) {
        std::set<QWidget*> before;
        for (auto* w : QApplication::topLevelWidgets()) if (w->isVisible()) before.insert(w);
        bool done = false;
        QTimer::singleShot(250, [&]() {
            auto* menu = qobject_cast<QMenu*>(QApplication::activePopupWidget());
            QAction* chosen = nullptr;
            if (menu) for (auto* a : menu->actions()) if (a->text() == actionText) chosen = a;
            if (menu) menu->close();
            if (!chosen) { std::printf("visual review: no menu item %s\n", qPrintable(actionText)); done = true; return; }
            QTimer::singleShot(actionText.startsWith("Find") ? 1500 : 300, [&]() {
                QWidget* found = nullptr;
                for (auto* w : QApplication::topLevelWidgets())
                    if (w->isVisible() && !before.count(w) && !qobject_cast<QMenu*>(w)) found = w;
                if (found) {
                    pump();
                    grabTo(found, name);
                    if (auto* dialog = qobject_cast<QDialog*>(found)) dialog->reject(); else found->close();
                } else std::printf("visual review: %s opened nothing\n", qPrintable(actionText));
                done = true;
            });
            chosen->trigger();
        });
        openMenu();
        QElapsedTimer waited; waited.start();
        while (!done && waited.elapsed() < 3000) pump(1);
        pump();
    };
    auto captureMenus = [&](QMainWindow& window, const QString& stem) {
        for (auto* action : window.menuBar()->actions()) {
            auto* menu = action->menu();
            if (!menu) continue;
            menu->popup(window.mapToGlobal(QPoint(0, 0)));
            pump();
            grabTo(menu, stem + "-" + action->text().remove('&').remove('.').toLower());
            menu->hide();
        }
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
            settings = qobject_cast<SettingsDialog*>(main.openSettingsDialog("Display"));
            settings->findChild<QSpinBox*>("displayFontSize")->setValue(10);
            QMetaObject::invokeMethod(settings, "onApply", Qt::DirectConnection);
            settings->close();

            main.resize(1000, 780);
            main.show();
            pump();
            captureMenus(main, prefix + "menu");
            // Scan-option states: float rounding + tolerance, a range scan, text.
            auto* valueType = main.findChild<QComboBox*>("scanValueType");
            auto* comparison = main.findChild<QComboBox*>("scanComparison");
            valueType->setCurrentText("Float");
            main.findChild<QComboBox*>("scanRounding")->setCurrentText("Extreme");
            comparison->setCurrentText("Value between...");
            capture(main, prefix + "main-float-between", {1000, 780});
            valueType->setCurrentText("String");
            comparison->setCurrentText("Exact Value");
            capture(main, prefix + "main-string", {1000, 780});
            valueType->setCurrentText("4 Bytes");
            auto* progress = main.findChild<QProgressBar*>();
            progress->setValue(42); progress->setVisible(true);
            capture(main, prefix + "main-scanning", {1000, 780});
            progress->setVisible(false);
            model->toggleActive(0);
            main.show();
            pump();
            auto* table = main.findChild<QTableView*>();
            for (auto* view : main.findChildren<QTableView*>())
                if (qobject_cast<AddressListModel*>(view->model())) table = view;
            table->selectRow(0);
            captureNew([&] { emit table->customContextMenuRequested(table->visualRect(model->index(0, 1)).center()); },
                       prefix + "menu-address-entry");
            auto entryMenu = [&] { emit table->customContextMenuRequested(table->visualRect(model->index(0, 1)).center()); };
            for (const auto& [action, name] : std::vector<std::pair<QString, QString>>{
                     {"Change address...", "entry-change-address"}, {"Set value...", "entry-set-value"},
                     {"Configure Hotkey...", "entry-hotkey"}, {"Configure Value Hotkeys...", "entry-value-hotkeys"},
                     {"Set value codec...", "entry-codec"}, {"Set/Change dropdown selection options...", "entry-dropdown"},
                     {"Add to new group...", "entry-group"}, {"Change Color...", "entry-color"},
                     {"Find what writes to this address", "entry-find-writes"},
                     {"Pointer scan for this address", "entry-pointer-scan"}})
                captureMenuAction(entryMenu, action, prefix + "dialog-" + name);
            // A real First Scan, so the results list and its menu show live data.
            main.findChild<QComboBox*>("scanValueType")->setCurrentText("4 Bytes");
            main.findChild<QComboBox*>("scanComparison")->setCurrentText("Exact Value");
            main.findChild<QLineEdit*>("scanValue")->setText("0");
            for (auto* button : main.findChildren<QPushButton*>())
                if (button->text() == "First Scan") button->click();
            pump(40);
            capture(main, prefix + "main-after-scan", {1000, 780});
            main.show();
            pump();
            for (auto* view : main.findChildren<QTableView*>())
                if (qobject_cast<ScanResultsModel*>(view->model())) {
                    view->selectRow(1);
                    captureNew([&] { emit view->customContextMenuRequested(view->visualRect(view->model()->index(1, 0)).center()); },
                               prefix + "menu-result");
                }
            auto openAction = [&](const QString& text) {
                return [&main, text] {
                    for (auto* action : main.findChildren<QAction*>())
                        if (action->text() == text) { action->trigger(); return; }
                    std::printf("visual review: no action %s\n", qPrintable(text));
                };
            };
            for (const auto& [action, name] : std::vector<std::pair<QString, QString>>{
                     {"About", "about"}, {"Process/System Info", "process-info"},
                     {"Speedhack...", "speedhack"}, {"Show Cheat Table Lua Script", "table-lua"},
                     {"Auto Assemble...", "auto-assemble"}, {"Connect to ceserver...", "ceserver"},
                     {"Connect to GDB / QEMU...", "gdb"}, {"Memory Allocations...", "allocations"},
                     {"Structure Spider...", "structure-spider"}, {"Group Scan Generator...", "group-scan"},
                     {"Wait for process...", "wait-process"}, {"Generate Trainer (executable)...", "trainer"},
                     {"Breakpoint list", "breakpoint-list"}, {"Lua Engine", "lua-engine"},
                     {"Create form", "create-form"}, {"Cheat Engine Help", "help"},
                     {"Settings...", "settings-from-menu"}})
                captureNew(openAction(action), prefix + "dialog-" + name);
            captureNew(openAction("Overlay..."), prefix + "dialog-overlay");
            // The Memory Viewer as the app opens it: its View/Debug menus are filled
            // by the main window.
            if (auto* viewer = main.openMemoryView(reinterpret_cast<uintptr_t>(&visualReviewCode))) {
                viewer->resize(1000, 720);
                pump();
                captureMenus(*viewer, prefix + "memory-menu");
                viewer->close();
                pump();
            }
            for (auto* button : main.findChildren<QPushButton*>()) {
                if (button->text() == "Add Address") captureNew([button] { button->click(); }, prefix + "dialog-add-address");
                if (button->text() == "Table Extras") captureNew([button] { button->click(); }, prefix + "dialog-comments");
                if (button->text() == "Advanced Options") captureNew([button] { button->click(); }, prefix + "dialog-advanced-options");
            }
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
            debugger.show();
            pump();
            captureNew([&] { QMetaObject::invokeMethod(&debugger, "onAddDataBreakpoint", Qt::DirectConnection); },
                       prefix + "dialog-data-breakpoint");
            debugger.hide();
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
