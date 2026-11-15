// MainWindow: the menu bar and the small windows it opens (help, comments,
// table Lua script, advanced options, overlay).
#include <bit>
#include "core/target_capabilities.hpp"
#include "arch/target_arch.hpp"
#include <csignal>
#include "gui/mainwindow.hpp"
#include "gui/code_editor.hpp"
#include "core/local_target.hpp"
#include "gui/gdbconnectiondialog.hpp"
#include "gui/theme.hpp"
#include "gui/i18n.hpp"
#include "core/expression.hpp"
#include "core/value_io.hpp"
#include "core/memview_nav.hpp"
#include "gui/processlistdialog.hpp"
#include "gui/registereditor.hpp"
#include "gui/debuggerwindow.hpp"
#include "gui/memorybrowser.hpp"
#include "gui/advancedoptions.hpp"
#include "gui/changeaddressdialog.hpp"
#include "gui/graphicalmemoryview.hpp"
#include "scanner/pointer_scanner.hpp"
#include "gui/scripteditor.hpp"
#include "gui/pointerscan_dialog.hpp"
#include "gui/guest_scan_dialog.hpp"
#include "gui/structuredissector.hpp"
#include "gui/monodissector.hpp"
#include "gui/luaconsole.hpp"
#include "gui/breakpointlist.hpp"
#include "gui/codefinder.hpp"
#include "debug/instruction_access.hpp"
#include "gui/codereferences.hpp"
#include "gui/heapregions.hpp"
#include "gui/memoryregions.hpp"
#include "gui/modulelist.hpp"
#include "gui/overlay.hpp"
#include "gui/stackview.hpp"
#include "gui/threadlist.hpp"
#include "gui/settingsdialog.hpp"
#include "gui/tracerwindow.hpp"
#include "gui/filepatcher.hpp"
#include "gui/branchmapper.hpp"
#include "gui/elfinspector.hpp"
#include "gui/formdesigner.hpp"
#include "gui/findstaticswindow.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "scripting/lua_gui.hpp"
#include "core/ct_file.hpp"
#include "core/ct_file_stream.hpp"
#include <streambuf>
#include <sstream>
#include <limits>
#include <unordered_set>
#include <stdexcept>
#include "core/target_profile.hpp"
#include "core/trainer.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/mono_dissector.hpp"
#include <dlfcn.h>

#include <QMenuBar>
#include <QApplication>
#include "gui/autoasmoperation.hpp"
#include <thread>
#include <sys/utsname.h>
#include <atomic>
#include <QCoreApplication>
#include <QTextBrowser>
#include <QDesktopServices>
#include <QUrl>
#include <fstream>
#include "platform/linux/injector.hpp"
#include <QClipboard>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QListWidget>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <QFile>
#include <QFileInfo>
#include <QProcess>

#include "gui/agent_panel.hpp"
#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <cerrno>
#include <QMenu>
#include <QInputDialog>
#include <QSettings>
#include <QFormLayout>
#include <QStatusBar>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <QFileDialog>
#include <cstdio>
#include <cstring>
#include <QStringList>
#include <cmath>
#include <charconv>
#include <exception>

#include "gui/mainwindow_internal.hpp"
#include "gui/aboutdialog.hpp"
#include <QItemSelectionModel>
#include <QAction>
namespace ce::gui {
using namespace mainwindow_detail;

void MainWindow::setupMenus() {
    // Menu bar follows Cheat Engine's MainUnit.MainMenu1 (captions, item order,
    // separators, shortcuts). CE items with no Linux backend are left out instead of
    // shown disabled, and Windows-only menus (D3D) are dropped. Our tools stay under
    // Tools, which CE leaves empty in the form and fills at runtime.

    // ── File ──
    auto* file = menuBar()->addMenu(tr("&File"));
    file->addAction(tr("Clear scan results"), this, [this]() {
        resultsModel_->clear(); lastResult_.reset(); undoResult_.reset(); updateScanButtons();
    });
    file->addAction(tr("Open Process..."), QKeySequence("Ctrl+O"), this, &MainWindow::onOpenProcess);
    file->addSeparator();
    file->addAction(tr("Save"), QKeySequence("Ctrl+S"), this, &MainWindow::onSaveTable);
    file->addAction(tr("Save As..."), QKeySequence("Ctrl+Shift+S"), this, &MainWindow::onSaveTableAs);
    file->addAction(tr("Load..."), QKeySequence("Ctrl+L"), this, &MainWindow::onLoadTable);
    recentMenu_ = file->addMenu(tr("Load Recent")); // populated from QSettings below
    recentMenu_->setToolTipsVisible(true);      // show the full path on hover
    rebuildRecentMenu();
    file->addSeparator();
    file->addAction(tr("Save scan results..."), QKeySequence("Alt+Shift+S"), this, &MainWindow::onSaveScanResults);
    file->addSeparator();
    file->addAction(tr("Generate Trainer Lua Script..."), this, &MainWindow::onCreateTrainer);
    file->addSeparator();
    file->addAction(tr("Connect to ceserver..."), this, &MainWindow::onConnectCeserver);  // Linux extra
    file->addAction(tr("Connect to GDB / QEMU..."), this, &MainWindow::onConnectGdb);
    file->addAction(tr("Disconnect target"), this, &MainWindow::onDisconnectProcess);
    file->addSeparator();
    file->addAction(tr("Quit"), QKeySequence("Ctrl+Q"), this, &QWidget::close);

    // ── Top-level menus in CE's order (D3D dropped — Windows-only, see below) ──
    // File · Edit · Process · Table · Tools · .Net · Network · Plugins ·
    // Languages · Help.
    auto* edit = menuBar()->addMenu(tr("&Edit"));
    auto* process = menuBar()->addMenu(tr("&Process"));
    auto* table = menuBar()->addMenu(tr("Table"));
    // CE's "D3D" menu (Direct3D overlay/hook) is Windows-only and every item is
    // permanently disabled on Linux, so it's dropped here rather than shown as a
    // dead top-level menu. Graphics hooking is out of scope (see docs/DEVELOPMENT).
    auto* tools = menuBar()->addMenu(tr("&Tools"));
    auto* dotnet = menuBar()->addMenu(tr(".Net"));
    // CE's .Net/Mono menu: dissect a Mono/IL2CPP runtime's classes and fields.
    dotnet->addAction(tr("Mono dissector..."), this, &MainWindow::openMonoDissector);
    // CE also has Network, Plugins and Languages menus. Their ceserver transfer
    // options, plugin loader and translations don't exist here, so the menus are
    // left out rather than shown full of disabled items (same call as D3D above).

    // ── Table (CE: Lua script + forms) ──
    table->addAction(tr("Show Cheat Table Lua Script"), QKeySequence("Ctrl+Alt+L"), this, &MainWindow::showTableLuaScript);
    table->addSeparator();
    table->addAction(tr("Create Form..."), this, [this]() {
        auto* fd = new FormDesigner(this); fd->setAttribute(Qt::WA_DeleteOnClose); fd->show();
    });

    // (D3D menu intentionally omitted on Linux — see note at the menu creation above.)

    // The Memory Viewer is the entry point; the memory/debug windows (Memory
    // Regions, Heap list, Module list, Referenced strings, Thread list, Stacktrace,
    // Registers, Breakpoint list, Debugger, Branch mapper, Break-and-trace, …) live
    // in ITS View/Debug menus — matching CE — populated by populateBrowserMenus().
    tools->addAction(tr("Memory Viewer..."), QKeySequence("Ctrl+M"), this, &MainWindow::onMemoryView);
    tools->addAction(tr("AI Assistant"), QKeySequence("Ctrl+Shift+I"), this, [this]() { showAgentPanel(); });
    tools->addSeparator();
    // Analysis panels (also in the Memory Viewer's Tools menu) — surfaced here so
    // they're findable from the main window without opening the viewer first.
    addAnalysisToolsMenu(tools);
    // Table > Auto Assemble... is the fuller version (it picks up the viewer's
    // selected instruction), so the Tools copy would only duplicate it.
    for (QAction* action : tools->actions())
        if (action->text() == tr("Auto Assemble...")) tools->removeAction(action);
    tools->addSeparator();
    // Table-wide edits (the entry context menu keeps to the entry under the cursor).
    for (auto* button : findChildren<QPushButton*>())
        if (button->text() == tr("Add Address"))
            edit->addAction(tr("Add Address..."), button, &QPushButton::click);
    edit->addAction(tr("Add Group"), this, [this]() { addressListModel_->addGroup(); });
    edit->addSeparator();
    edit->addAction(tr("Enable all entries"), this, [this]() { addressListModel_->setAllActive(true); });
    edit->addAction(tr("Disable all entries"), this, [this]() { addressListModel_->setAllActive(false); });
    edit->addSeparator();
    edit->addAction(tr("Settings..."), this, [this]() { openSettingsDialog(); });

    // ── Process menu ──
    process->addAction(tr("Open Process..."), this, &MainWindow::onOpenProcess);
    // CE formProcessInfo (Process/System Info) — Linux equivalents.
    // CE "Create Process" / frmopenfileasprocessdialogunit: launch an executable
    // and attach. As our own child it is ptrace-accessible under yama scope=1.
    process->addAction(tr("Create Process..."), this, [this]() {
        auto path = QFileDialog::getOpenFileName(this, tr("Open file as process"), "", tr("Executables (*)"));
        if (path.isEmpty()) return;
        std::string p = path.toStdString();
        pid_t pid = fork();
        if (pid == 0) {
            prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
            execl(p.c_str(), p.c_str(), (char*)nullptr);
            _exit(127);
        }
        if (pid < 0) { QMessageBox::warning(this, tr("Create Process"), tr("fork() failed.")); return; }
        usleep(120000);   // let it map its image
        // Through attachToPid so the old target's Debugger/views are torn down
        // before process_ is replaced (they hold a raw handle).
        attachToPid(pid, QFileInfo(path).fileName());
    });
    process->addAction(tr("Process/System Info"), this, [this]() {
        QDialog dialog(this);
        dialog.setWindowTitle(tr("Process and System Info"));
        auto* layout = new QVBoxLayout(&dialog);
        // One form for both sections so their label columns line up.
        auto* form = new QFormLayout;
        form->setHorizontalSpacing(16);
        form->setLabelAlignment(Qt::AlignLeft);
        layout->addLayout(form);
        auto section = [&](const QString& title) {
            auto* heading = new QLabel(title);
            heading->setObjectName("pageTitle");
            if (form->rowCount() > 0) heading->setContentsMargins(0, 10, 0, 0);
            form->addRow(heading);
            return form;
        };
        auto value = [](const QString& text) {
            auto* label = new QLabel(text);
            label->setTextInteractionFlags(Qt::TextSelectableByMouse);
            label->setWordWrap(true);
            return label;
        };
        auto* target = section(tr("Process"));
        if (!process_) {
            target->addRow(value(tr("No process is open. Use File > Open Process.")));
        } else {
            const auto modules = process_->modules();
            const auto description = process_->targetDescription();
            target->addRow(tr("Name:"), value(currentProcessName_));
            target->addRow(tr("PID:"), value(QString::number(currentPid_)));
            target->addRow(tr("Executable:"), value(modules.empty() ? QString(tr("(unknown)")) : QString::fromStdString(modules.front().path)));
            if (auto localPid = ce::localTargetPid(process_.get()))
                target->addRow(tr("Kind:"), value(targetSummaryText(ce::probeTarget(*localPid))));
            target->addRow(tr("Program:"), value(QString(tr("%1, %2-byte pointers, %3"))
                .arg(ce::cpuArchitectureName(description.program.architecture)).arg(description.program.pointerWidth)
                .arg(ce::byteOrderName(description.program.byteOrder))));
            target->addRow(tr("Modules:"), value(QString::number(modules.size())));
            target->addRow(tr("Threads:"), value(QString::number(process_->threads().size())));
        }
        auto* system = section(tr("System"));
        struct utsname uts{};
        if (::uname(&uts) == 0) system->addRow(tr("Kernel:"), value(QString("%1 %2 (%3)").arg(uts.sysname, uts.release, uts.machine)));
        system->addRow(tr("CPUs:"), value(QString::number(std::thread::hardware_concurrency())));
        QString scope = tr("not present (Yama disabled)");
        if (QFile f("/proc/sys/kernel/yama/ptrace_scope"); f.open(QIODevice::ReadOnly)) {
            const QString level = QString::fromUtf8(f.readAll()).trimmed();
            static const char* const meaning[] = {
                QT_TRANSLATE_NOOP("MainWindow", "any process of the same user"),
                QT_TRANSLATE_NOOP("MainWindow", "only child processes"),
                QT_TRANSLATE_NOOP("MainWindow", "administrators only"),
                QT_TRANSLATE_NOOP("MainWindow", "no attaching")};
            const int n = level.toInt();
            scope = n >= 0 && n <= 3 ? QString("%1: %2").arg(level,
                QCoreApplication::translate("MainWindow", meaning[n])) : level;
        }
        system->addRow(tr("ptrace scope:"), value(scope));
        system->addRow(tr("Qt:"), value(qVersion()));
        layout->addStretch();
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
        connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        layout->addWidget(buttons);
        dialog.resize(520, dialog.sizeHint().height());
        dialog.exec();
    });
    // "Pause the process" toggle (CE's pause-the-game) — SIGSTOP/SIGCONT the target.
    auto* pauseAct = process->addAction(tr("Pause the process"));
    pauseAct->setCheckable(true);
    pauseAction_ = pauseAct;
    connect(pauseAct, &QAction::toggled, this, [this, pauseAct](bool checked) {
        auto pid=ce::localTargetPid(process_.get());
        if (!pid) {
            pauseAct->setChecked(false);
            statusBar()->showMessage(tr("Pause requires a live local process target"),5000);return;
        }
        if (::kill(*pid, checked ? SIGSTOP : SIGCONT) != 0)
            pauseAct->setChecked(false);
    });
    // Optionally SIGSTOP the target for the duration of each scan (CE's "pause
    // while scanning") so values can't change mid-scan, then resume.
    auto* pauseScanAct = process->addAction(tr("Pause target while scanning"));
    pauseScanAct->setCheckable(true);
    pauseScanAct->setToolTip(tr("Suspend the target during each First/Next Scan so its "
                             "memory is a consistent snapshot, then resume it."));
    connect(pauseScanAct, &QAction::toggled, this, [this](bool on) { pauseWhileScanning_ = on; });
    // ── Table menu ──
    table->addAction(tr("Auto Assemble..."), QKeySequence("Ctrl+A"), this, [this]() {
        auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
        for (auto it = memoryViewers_.rbegin(); it != memoryViewers_.rend(); ++it) {
            if (*it && (*it)->isVisible()) {
                auto [address, size] = (*it)->injectionSelection();
                editor->setInjectionAddress(address, size);
                break;
            }
        }
        // With no target yet the editor belongs to none: keep it (and its
        // script) across the next attach and bind it then.
        if (process_) trackTargetWindow(editor);
        else unboundEditors_.push_back(editor);
        editor->setAttribute(Qt::WA_DeleteOnClose);
        editor->setAddToTable([this](const QString& d, const QString& s) {
            addressListModel_->addScriptEntry(d, s);
        });
        editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
        editor->show();
    });
    tools->addAction(tr("File Patcher..."), this, [this]() {
        auto* dlg = new FilePatcher(this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE frmSaveMemoryRegionUnit (Save memoryregion): dump a From..To range to a file.
    tools->addAction(tr("Save Memory Region..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("Save Memory Region"), tr("Open a process first.")); return; }
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(tr("Save Memory Region"));
        trackTargetWindow(dlg);   // closed when the target changes
        auto* v = new QVBoxLayout(dlg);
        auto* intro = new QLabel(tr("Save a range of the target's memory to a file (up to 64 MiB). "
                                 "Addresses are hexadecimal; To is exclusive."));
        intro->setWordWrap(true);
        intro->setProperty("secondary", true);
        v->addWidget(intro);
        auto* form = new QFormLayout;
        auto* fromEdit = new QLineEdit;
        auto* toEdit = new QLineEdit;
        for (auto* edit : {fromEdit, toEdit}) {
            edit->setFont(monospaceFont());
            edit->setMinimumWidth(240);
        }
        fromEdit->setPlaceholderText(tr("e.g. 7f3a00000000"));
        toEdit->setPlaceholderText(tr("e.g. 7f3a00001000"));
        form->addRow(tr("From:"), fromEdit);
        form->addRow(tr("To:"), toEdit);
        v->addLayout(form);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
        v->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, this, [this, dlg, fromEdit, toEdit]() {
            uintptr_t from = fromEdit->text().trimmed().toULongLong(nullptr, 16);
            uintptr_t to = toEdit->text().trimmed().toULongLong(nullptr, 16);
            if (to <= from) { QMessageBox::warning(dlg, tr("Save"), tr("\"To\" must be greater than \"From\".")); return; }
            // Cap like the Save Disassembly path: an unbounded range would throw
            // std::bad_alloc out of a Qt slot (terminate) and OOM.
            constexpr uintptr_t kMaxSave = 64ull * 1024 * 1024;  // 64 MiB
            if (to - from > kMaxSave) {
                QMessageBox::warning(dlg, tr("Save"), tr("Region too large (max 64 MiB)."));
                return;
            }
            auto path = QFileDialog::getSaveFileName(dlg, tr("Save memory region"), "region.bin");
            if (path.isEmpty()) return;
            // The process can have exited or been closed while this was open.
            if (!process_) { QMessageBox::warning(dlg, tr("Save"), tr("The process is no longer open.")); return; }
            std::vector<uint8_t> buf(to - from);
            auto r = process_->read(from, buf.data(), buf.size());
            if (!r || *r == 0) { QMessageBox::warning(dlg, tr("Save"), tr("Could not read that region.")); return; }
            std::ofstream f(path.toStdString(), std::ios::binary);
            f.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)*r);
            if (!f) { QMessageBox::warning(dlg, tr("Save"), QString(tr("Could not write %1.")).arg(path)); return; }
            QMessageBox::information(dlg, tr("Saved"), QString(tr("Wrote %1 to %2.")).arg(formatByteSize(*r), path));
            dlg->accept();
        });
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE frmMemoryAllocHandlerUnit (Memory Allocations): allocate + track blocks.
    tools->addAction(tr("Memory Allocations..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("Memory Allocations"), tr("Open a process first.")); return; }
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(tr("Memory Allocations"));
        trackTargetWindow(dlg);
        dlg->resize(420, 320);
        auto* v = new QVBoxLayout(dlg);
        auto* intro = new QLabel(tr("Memory reserved in the target from here (readable, writable and "
                                 "executable). Double-click a block to browse it."));
        intro->setWordWrap(true);
        intro->setProperty("secondary", true);
        v->addWidget(intro);
        auto* list = new QListWidget;
        list->setProperty("monospace", true);   // font from the theme sheet
        setEmptyHint(list, tr("No blocks allocated yet.\nClick Allocate to reserve memory in the target."));
        auto refill = [this, list]() {
            list->clear();
            for (const auto& a : allocations_)
                list->addItem(QString("0x%1   %2").arg(a.first, 0, 16).arg(formatByteSize(a.second)));
        };
        refill();
        v->addWidget(list);
        auto* row = new QHBoxLayout;
        auto* allocBtn = new QPushButton(tr("Allocate"));
        auto* freeBtn = new QPushButton(tr("Free"));
        freeBtn->setToolTip(tr("Free the selected block"));
        freeBtn->setEnabled(false);   // needs a selected block
        connect(list, &QListWidget::currentRowChanged, freeBtn, [freeBtn](int row) { freeBtn->setEnabled(row >= 0); });
        auto* closeBtn = new QPushButton(tr("Close"));
        row->addWidget(allocBtn); row->addWidget(freeBtn); row->addStretch(); row->addWidget(closeBtn);
        v->addLayout(row);
        connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
        connect(allocBtn, &QPushButton::clicked, this, [this, dlg, refill]() {
            bool ok = false;
            int size = QInputDialog::getInt(dlg, tr("Allocate"), tr("Size (bytes):"), 4096, 1, 1 << 30, 1, &ok);
            if (!ok) return;
            auto r = process_->allocate(size, ce::MemProt::All, 0);
            if (!r) {
                QMessageBox::warning(dlg, tr("Allocate"), QString(tr("Could not allocate %1 in the target: %2"))
                    .arg(formatByteSize(size), QString::fromStdString(r.error().message())));
                return;
            }
            allocations_.push_back({(qulonglong)*r, (qulonglong)size});
            refill();
        });
        connect(freeBtn, &QPushButton::clicked, this, [this, dlg, list, refill]() {
            int i = list->currentRow();
            if (i < 0 || i >= (int)allocations_.size()) return;
            if (auto freed = process_->free(allocations_[i].first, allocations_[i].second); !freed) {
                QMessageBox::warning(dlg, tr("Free"), QString(tr("Could not free the block: %1"))
                    .arg(QString::fromStdString(freed.error().message())));
                return;
            }
            allocations_.erase(allocations_.begin() + i);
            refill();
        });
        connect(list, &QListWidget::itemDoubleClicked, this, [this, list](QListWidgetItem*) {
            int i = list->currentRow();
            if (i >= 0 && i < (int)allocations_.size()) openMemoryView(allocations_[i].first);
        });
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE frmExeTrainerGeneratorUnit: compile a standalone trainer executable.
    tools->addAction(tr("Generate Trainer (executable)..."), this, [this]() {
        auto path = QFileDialog::getSaveFileName(this, tr("Generate Trainer executable"), "trainer");
        if (path.isEmpty()) return;
        try {
            ce::CheatTable table = buildCheatTable();
            ce::TrainerGenerator gen;
            std::string err = gen.generateBinary(table, path.toStdString());
            if (err.empty())
                statusBar()->showMessage(tr("Trainer executable written to %1").arg(path), 6000);
            else
                QMessageBox::critical(this, tr("Generate Trainer"), QString::fromStdString(err));
        } catch (const std::exception& ex) {
            QMessageBox::critical(this, tr("Generate Trainer"), ex.what());
        }
    });
    // CE frmStringPointerScanUnit (Structure spider): find pointer paths to a target
    // and dissect the structure there.
    tools->addAction(tr("Structure Spider..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("Structure Spider"), tr("Open a process first.")); return; }
        bool ok = false;
        // Start from the selected cheat-table entry, the usual thing to spider from.
        QString initial;
        if (auto rows = addressListView_->selectionModel()->selectedRows(); !rows.isEmpty()) {
            const auto& entries = addressListModel_->entries();
            if (int r = rows.first().row(); r >= 0 && r < (int)entries.size() && !entries[r].isGroup)
                initial = QString("0x%1").arg((qulonglong)entries[r].address, 0, 16);
        }
        QString ts = QInputDialog::getText(this, tr("Structure Spider"),
                                           tr("Address of the value to find pointer paths to (hex):"),
                                           QLineEdit::Normal, initial, &ok);
        if (!ok || ts.trimmed().isEmpty()) return;
        bool valid = false;
        uintptr_t target = ts.trimmed().toULongLong(&valid, 16);
        if (!valid || !target) {
            QMessageBox::warning(this, tr("Structure Spider"), QString(tr("\"%1\" is not a hexadecimal address.")).arg(ts.trimmed()));
            return;
        }
        if (!process_) { QMessageBox::warning(this, tr("Structure Spider"), tr("The process is no longer open.")); return; }
        // The scan runs on a worker so the GUI keeps running; the window shows
        // its progress. Closing the window, or a target change (which deletes
        // target windows), cancels the scan and joins the worker.
        struct SpiderJob : QObject {
            explicit SpiderJob(QObject* parent) : QObject(parent) {}
            ~SpiderJob() override { scanner.cancel(); if (worker.joinable()) worker.join(); }
            ce::PointerScanner scanner;
            std::thread worker;
            std::atomic<bool> done{false};
            std::vector<ce::PointerPath> paths;   // written by the worker, read after join
            std::string error;
        };
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(tr("Structure spider"));
        dlg->resize(520, 420);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        trackTargetWindow(dlg);
        auto* v = new QVBoxLayout(dlg);
        const QString targetText = QString("0x%1").arg((qulonglong)target, 0, 16);
        auto* status = new QLabel(QString(tr("Searching for pointer paths to %1...")).arg(targetText));
        status->setWordWrap(true);
        v->addWidget(status);
        auto* list = new QListWidget;
        v->addWidget(list);
        auto* job = new SpiderJob(dlg);
        ce::PointerScanConfig cfg;
        cfg.targetAddress = target; cfg.maxDepth = 2; cfg.maxOffset = 256; cfg.staticOnly = false;
        job->worker = std::thread([job, proc = process_.get(), cfg] {
            // buildPointerMap throws for a target of unknown pointer width, and
            // a huge target can run out of memory: report either in the window.
            try { job->paths = job->scanner.scan(*proc, cfg); }
            catch (const std::exception& e) { job->error = e.what(); }
            catch (...) { job->error = tr("unexpected error").toStdString(); }
            job->done = true;
        });
        connect(dlg, &QDialog::finished, job, [job]() { job->scanner.cancel(); });
        auto* row = new QHBoxLayout;
        auto* dissectBtn = new QPushButton(tr("Dissect structure at target"));
        connect(dissectBtn, &QPushButton::clicked, this, [this, target]() {
            if (!process_) return;
            auto* sd = new StructureDissector(process_.get(), target, this);
            sd->setAttribute(Qt::WA_DeleteOnClose);
            sd->setAddToListCallback([this](uintptr_t a, ce::ValueType t, const QString& d) {
                addressListModel_->addEntry(a, t, d);
            });
            trackStructDissector(sd);
            sd->show();
        });
        // Cancel while the scan runs, Close afterwards.
        auto* closeBtn = new QPushButton(tr("Cancel"));
        connect(closeBtn, &QPushButton::clicked, dlg, [dlg, job, status]() {
            if (job->done) { dlg->accept(); return; }
            job->scanner.cancel();
            status->setText(tr("Cancelling..."));
        });
        row->addWidget(dissectBtn); row->addStretch(); row->addWidget(closeBtn);
        v->addLayout(row);
        auto* poll = new QTimer(dlg);
        connect(poll, &QTimer::timeout, dlg, [poll, job, status, list, closeBtn, targetText]() {
            if (!job->done) {
                if (!job->scanner.wasCancelled())
                    status->setText(QString(tr("Searching for pointer paths to %1... %2%"))
                                        .arg(targetText).arg(int(job->scanner.progress() * 100)));
                return;
            }
            poll->stop();
            job->worker.join();
            closeBtn->setText(tr("Close"));
            if (!job->error.empty()) {
                status->setText(QString(tr("The pointer scan failed: %1")).arg(QString::fromStdString(job->error)));
                return;
            }
            if (job->scanner.wasCancelled()) { status->setText(tr("Cancelled.")); return; }
            QString text = QString(tr("%1 pointer path(s) to %2:")).arg(job->paths.size()).arg(targetText);
            if (job->scanner.truncated()) text += " " + tr("(the scan stopped at a limit, so some paths may be missing)");
            status->setText(text);
            for (const auto& p : job->paths) list->addItem(QString::fromStdString(p.toString()));
        });
        poll->start(100);
        dlg->show();
    });
    // CE frmgroupscanalgoritmgeneratorunit: build a grouped-scan pattern from the
    // selected scan results (offsets from the first, with each value), for finding
    // other instances of the same structure.
    tools->addAction(tr("Group Scan Generator..."), this, [this]() {
        if (!process_ || !lastResult_) { QMessageBox::warning(this, tr("Group Scan Generator"), tr("Run a scan and select results first.")); return; }
        auto sel = resultsView_->selectionModel()->selectedRows();
        if (sel.size() < 2) { QMessageBox::information(this, tr("Group Scan Generator"), tr("Select two or more addresses in the scan results first (Ctrl+click or Shift+click). The generator builds a pattern from their offsets and values.")); return; }
        std::vector<uintptr_t> addrs;
        for (const auto& idx : sel) addrs.push_back(resultsModel_->addressAt(idx.row()));
        std::sort(addrs.begin(), addrs.end());
        uintptr_t base = addrs.front();
        QStringList parts;
        for (auto a : addrs) {
            int32_t v = 0;
            if (auto got = process_->read(a, &v, sizeof(v)); !got || *got != sizeof(v)) {
                QMessageBox::warning(this, tr("Group Scan Generator"),
                                     tr("Could not read the value at %1.").arg(a, 0, 16));
                return;
            }
            parts << QString("%1:%2").arg(a - base).arg(v);   // offset:value (4 bytes)
        }
        QString pattern = parts.join(' ');
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(tr("Group Scan Generator"));
        auto* v = new QVBoxLayout(dlg);
        v->addWidget(new QLabel(tr("Grouped-scan pattern (offset:value, 4-byte):")));
        auto* edit = new QPlainTextEdit(pattern); edit->setReadOnly(true);
        v->addWidget(edit);
        auto* row = new QHBoxLayout;
        auto* copyBtn = new QPushButton(tr("Copy"));
        connect(copyBtn, &QPushButton::clicked, this, [pattern]() { QApplication::clipboard()->setText(pattern); });
        auto* closeBtn = new QPushButton(tr("Close"));
        connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
        row->addStretch(); row->addWidget(copyBtn); row->addWidget(closeBtn);
        v->addLayout(row);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE savedisassemblyfrm: disassemble a From..To range to a text file.
    tools->addAction(tr("Save Disassembly..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("Save Disassembly"), tr("Open a process first.")); return; }
        bool ok = false;
        QString fromS = QInputDialog::getText(this, tr("Save Disassembly"), tr("From (hex):"),
                                              QLineEdit::Normal, "0", &ok);
        if (!ok) return;
        QString toS = QInputDialog::getText(this, tr("Save Disassembly"), tr("To (hex):"),
                                            QLineEdit::Normal, "0", &ok);
        if (!ok) return;
        uintptr_t from = fromS.toULongLong(nullptr, 16), to = toS.toULongLong(nullptr, 16);
        if (to <= from || to - from > (64u << 20)) {
            QMessageBox::warning(this, tr("Save Disassembly"), tr("Invalid or too-large range.")); return;
        }
        if (!process_) { QMessageBox::warning(this, tr("Save Disassembly"), tr("The process is no longer open.")); return; }
        std::vector<uint8_t> buf(to - from);
        auto r = process_->read(from, buf.data(), buf.size());
        if (!r || *r == 0) { QMessageBox::warning(this, tr("Save Disassembly"), tr("Could not read that range.")); return; }
        auto architecture = ce::disassemblerArchFor(*process_, from);
        if (!architecture) {
            QMessageBox::warning(this, tr("Save Disassembly"), QString::fromStdString(architecture.error()));
            return;
        }
        ce::Disassembler dis(*architecture);
        auto insns = dis.disassemble(from, {buf.data(), *r}, 1000000, /*emitDataBytes=*/true);
        auto path = QFileDialog::getSaveFileName(this, tr("Save disassembly"), "disasm.asm");
        if (path.isEmpty()) return;
        std::ofstream f(path.toStdString());
        for (const auto& i : insns)
            f << std::hex << i.address << ": " << i.mnemonic
              << (i.operands.empty() ? "" : " ") << i.operands << "\n";
        QMessageBox::information(this, tr("Saved"), QString(tr("Wrote %1 instructions to %2."))
                                    .arg(insns.size()).arg(path));
    });
    // CE frmMemoryViewExUnit (Graphical Memory View): bytes as pixels.
    process->addAction(tr("Wait for process..."), this, [this]() {
        bool ok = false;
        auto name = QInputDialog::getText(this, tr("Wait for process"),
            tr("Name (or part of the name) of the program to wait for.\nCheat Engine opens it as soon as it starts:"),
            QLineEdit::Normal, "", &ok);
        if (!ok || name.isEmpty()) return;
        stopProcessWatch();
        processWatcher_ = std::make_unique<os::ProcessWatcher>();
        auto* status = statusBar();
        status->showMessage(QString(tr("Watching for '%1'…")).arg(name));
        const quint64 watch = processWatch_;
        processWatcher_->start(name.toStdString(),
            [this, watch](pid_t pid, const std::string& procName) {
                QMetaObject::invokeMethod(this, [this, pid, procName, watch]() {
                    autoAttach(pid, QString::fromStdString(procName), watch);
                }, Qt::QueuedConnection);
            });
    });
    auto* snapshotMenu = tools->addMenu(tr("Snapshot"));
    // Bounded so a large game cannot exhaust memory; a diff reads at most as
    // much again.
    static constexpr uint64_t kSnapshotBudget = uint64_t(1) << 30;
    snapshotMenu->addAction(tr("Capture writable regions"), this, [this]() {
        if (!process_) {
            QMessageBox::warning(this, tr("No process"), tr("Open a process before capturing a snapshot."));
            return;
        }
        ProcessHandle* proc = process_.get();
        std::shared_ptr<Snapshot> captured;
        try {
            runSnapshotTask([&] {
                captured = std::make_shared<Snapshot>(Snapshot::capture(*proc, kSnapshotBudget));
            });
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Snapshot failed"), QString::fromStdString(e.what()));
            return;
        }
        snapshot_ = std::move(captured);
        QString text = QString(tr("Captured %1 region(s), %2 total."))
            .arg(snapshot_->regionCount()).arg(formatByteSize(snapshot_->byteCount()));
        if (snapshot_->truncated())
            text += QString(tr("\n\nThe snapshot stopped at its %1 limit: writable memory "
                            "after that point is not included.")).arg(formatByteSize(kSnapshotBudget));
        QMessageBox::information(this, tr("Snapshot captured"), text);
    });
    snapshotMenu->addAction(tr("Diff against current"), this, [this]() {
        if (!process_ || !snapshot_) {
            QMessageBox::warning(this, tr("Need both"), tr("Capture a baseline snapshot first, then open a process."));
            return;
        }
        constexpr size_t kShown = 200;
        ProcessHandle* proc = process_.get();
        std::shared_ptr<const Snapshot> baseline = snapshot_;
        std::vector<Snapshot::ByteDiff> diffs;
        uint64_t changed = 0;
        try {
            runSnapshotTask([&] {
                const Snapshot now = baseline->recapture(*proc);
                diffs = baseline->diff(now, kShown, &changed);
            });
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Diff failed"), QString::fromStdString(e.what()));
            return;
        }
        if (changed == 0) {
            QMessageBox::information(this, tr("Diff"), tr("No byte-level differences detected."));
            return;
        }
        // Only the first kShown differences are kept; the count covers all.
        QString text;
        text += changed == 1 ? tr("1 byte changed since the baseline.\n\n")
                             : tr("%1 bytes changed since the baseline.\n\n").arg(changed);
        for (const auto& d : diffs) {
            text += QString("0x%1: 0x%2 -> 0x%3\n")
                .arg(d.address, 16, 16, QChar('0'))
                .arg(d.before, 2, 16, QChar('0'))
                .arg(d.after,  2, 16, QChar('0'));
        }
        if (changed > diffs.size())
            text += QString(tr("\n(%1 more not shown.)")).arg(changed - diffs.size());

        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(tr("Snapshot Diff"));
        dlg->resize(640, 480);
        auto* l = new QVBoxLayout(dlg);
        auto* edit = new QPlainTextEdit(text);
        edit->setReadOnly(true);
        edit->setFont(monospaceFont(-1));
        l->addWidget(edit);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
        connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::accept);
        l->addWidget(buttons);
        dlg->exec();
        dlg->deleteLater();
    });
    snapshotMenu->addAction(tr("Restore baseline"), this, [this]() {
        if (!process_ || !snapshot_) {
            QMessageBox::warning(this, tr("Need both"), tr("Capture a baseline snapshot first."));
            return;
        }
        auto answer = QMessageBox::question(this, tr("Restore?"),
            QString(tr("Write the baseline back into the process? This overwrites the "
                    "captured memory that is still mapped writable (%1 regions, %2)."))
                .arg(snapshot_->regionCount()).arg(formatByteSize(snapshot_->byteCount())));
        if (answer != QMessageBox::Yes) return;
        // Both go away if the process exits while the question is open.
        if (!process_ || !snapshot_) { QMessageBox::warning(this, tr("Restore"), tr("The process is no longer open.")); return; }
        ProcessHandle* proc = process_.get();
        std::shared_ptr<const Snapshot> baseline = snapshot_;
        uint64_t written = 0;
        try {
            runSnapshotTask([&] { written = baseline->restore(*proc); });
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Restore failed"), QString::fromStdString(e.what()));
            return;
        }
        QString text = QString(tr("Wrote %1 bytes back into the process.")).arg(written);
        if (written < baseline->byteCount())
            text += QString(tr("\n\n%1 bytes were skipped: that memory is no longer mapped, "
                            "or is now read-only or executable.")).arg(baseline->byteCount() - written);
        QMessageBox::information(this, tr("Restored"), text);
    });
    snapshotMenu->addAction(tr("Save to file..."), this, [this]() {
        if (!snapshot_) {
            QMessageBox::warning(this, tr("No snapshot"), tr("Capture a snapshot first."));
            return;
        }
        auto path = QFileDialog::getSaveFileName(this, tr("Save snapshot"), "snapshot.cesnap",
            tr("Snapshot (*.cesnap);;All (*)"));
        if (path.isEmpty()) return;
        if (!snapshot_->save(path.toStdString())) {
            QMessageBox::warning(this, tr("Save failed"), tr("Could not write %1").arg(path));
        }
    });
    snapshotMenu->addAction(tr("Load from file..."), this, [this]() {
        auto path = QFileDialog::getOpenFileName(this, tr("Load snapshot"), "",
            tr("Snapshot (*.cesnap);;All (*)"));
        if (path.isEmpty()) return;
        auto loaded = std::make_shared<Snapshot>();
        std::string err;
        if (!loaded->load(path.toStdString(), &err)) {
            QMessageBox::warning(this, tr("Load failed"), QString::fromStdString(err));
            return;
        }
        snapshot_ = std::move(loaded);
        QMessageBox::information(this, tr("Snapshot loaded"),
            QString(tr("Loaded %1 region(s), %2 bytes."))
                .arg(snapshot_->regionCount()).arg(snapshot_->byteCount()));
    });
    tools->addSeparator();
    tools->addAction(tr("Overlay..."), this, &MainWindow::showOverlayDialog);
    tools->addAction(tr("Speedhack..."), this, [this]() {
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(tr("Speedhack"));
        auto* layout = new QVBoxLayout(dlg);
        layout->setSpacing(10);
        auto* intro = new QLabel(tr("Scales the time the game sees. Apply loads the speedhack "
                                 "library into the process the first time."));
        intro->setWordWrap(true);
        intro->setProperty("secondary", true);
        auto* speedRow = new QHBoxLayout;
        speedRow->addWidget(new QLabel(tr("Speed")));
        speedRow->addStretch();
        auto* speedValue = new QLabel("1.0×");
        speedValue->setStyleSheet(QString("font-size: %1pt; font-weight: 600;")
            .arg(QApplication::font().pointSizeF() * 1.4, 0, 'f', 1));
        speedRow->addWidget(speedValue);
        auto* slider = new QSlider(Qt::Horizontal);
        slider->setRange(1, 100);  // 0.1x to 10.0x
        slider->setValue(10);      // 1.0x default
        connect(slider, &QSlider::valueChanged, [speedValue](int v) {
            speedValue->setText(QString("%1×").arg(v / 10.0, 0, 'f', 1));
        });
        auto* presets = new QHBoxLayout;
        for (double preset : {0.5, 1.0, 2.0, 5.0}) {
            auto* b = new QPushButton(QString("%1×").arg(preset, 0, 'g', 2));
            connect(b, &QPushButton::clicked, slider, [slider, preset]() { slider->setValue(int(preset * 10)); });
            presets->addWidget(b);
        }
        // Status of the last Apply: injection errors or the speed now in effect.
        auto* label = new QLabel(process_ ? tr("Not applied yet.") : tr("Open a process first."));
        label->setProperty("secondary", true);
        label->setWordWrap(true);
        auto* applyBtn = new QPushButton(tr("Apply"));
        applyBtn->setProperty("primary", true);
        applyBtn->setEnabled(process_ != nullptr);
        connect(applyBtn, &QPushButton::clicked, [this, slider, label]() {
            double speed = slider->value() / 10.0;
            // Inject the speedhack library into the running target the first time,
            // so it works without relaunching the game under LD_PRELOAD (CE-style).
            if (process_) {
                // The speedhack is injected locally and speaks through this
                // machine's /dev/shm: a remote PID names some other process here.
                const auto localPid = ce::localTargetPid(process_.get());
                if (!localPid) { label->setText(tr("The speedhack works on local processes only.")); return; }
                pid_t pid = *localPid;
                bool loaded = false;
                std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
                std::string line;
                while (std::getline(maps, line))
                    if (line.find("libspeedhack.so") != std::string::npos) { loaded = true; break; }
                if (!loaded) {
                    // injectLibrary needs the target's libc symbols (dlopen); the
                    // resolver is otherwise only populated lazily on Lua use.
                    if (luaResolver_.count() == 0) luaResolver_.loadProcess(*process_);
                    // Installed beside libcecore (lib, lib64 or a multiarch
                    // directory), or next to the binary in a build tree.
                    const std::string so = ce::findCompanionLibrary("libspeedhack.so");
                    if (so.empty()) {
                        label->setText(tr("Inject failed: libspeedhack.so is not installed next to Cheat Engine."));
                        return;
                    }
                    // A containerised game (Flatpak, Steam runtime) may see
                    // this file under another name; dlopen runs in its view.
                    std::string targetSo = so;
                    if (auto task = ce::os::processMemoryTask(pid)) targetSo = ce::os::targetVisiblePath(*task, so);
                    auto r = ce::os::injectLibrary(*process_, luaResolver_, targetSo);
                    if (!r) {
                        label->setText(QString(tr("Inject failed: %1"))
                                           .arg(QString::fromStdString(r.error())));
                        return;  // don't set a speed the plugin can't read
                    }
                }
                label->setText(QString(tr("Active: the game runs at %1×.")).arg(speed, 0, 'f', 1));
            }
            // Match the plugin side (plugins/speedhack.c): O_NOFOLLOW refuses a
            // symlink-swapped /dev/shm entry and mode 0600 keeps the channel
            // same-user only. Do NOT add O_EXCL/unlink: the file is a persistent
            // shared channel the injected plugin mmaps, so it must be opened in
            // place (a new inode would orphan the plugin's existing mapping).
            int shmfd = ::open("/dev/shm/ce_speedhack", O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
            if (shmfd >= 0) {
                // Confirm we opened a real regular file, not a fifo/device an
                // attacker pre-created at the predictable path.
                struct stat st{};
                if (::fstat(shmfd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid() && !(st.st_mode & 077) &&
                    ::ftruncate(shmfd, sizeof(double)) == 0) {
                    void* mem = ::mmap(nullptr, sizeof(double), PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, 0);
                    if (mem != MAP_FAILED) { *(double*)mem = speed; ::munmap(mem, sizeof(double)); }
                }
                ::close(shmfd);
            }
        });
        layout->addWidget(intro);
        layout->addLayout(speedRow);
        layout->addWidget(slider);
        layout->addLayout(presets);
        auto* applyRow = new QHBoxLayout;
        applyRow->addWidget(label, 1);
        applyRow->addWidget(applyBtn);
        layout->addLayout(applyRow);
        dlg->resize(380, dlg->sizeHint().height());
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });

    // ── Help (CE verbatim) ──
    auto* help = menuBar()->addMenu(tr("&Help"));
    help->addAction(tr("Cheat Engine Help"), this, [this]() {
        openHelpDoc("README.md", tr("Cheat Engine for Linux: Help"),
                    "https://github.com/wleeaf/cheat-engine-linux#readme");
    });
    help->addAction(tr("Lua documentation"), this, [this]() {
        openHelpDoc("docs/SCRIPTING.md", tr("Lua / Scripting documentation"),
                    "https://github.com/wleeaf/cheat-engine-linux/blob/main/docs/SCRIPTING.md");
    });
    help->addSeparator();
    // The tutorial games are installed next to cheatengine.
    auto launchTutorial = [this](const QString& program) {
        const QString path = QCoreApplication::applicationDirPath() + "/" + program;
        if (!QProcess::startDetached(path, {}))
            QMessageBox::warning(this, tr("Tutorial not found"),
                QString(tr("Could not start %1. It is installed next to cheatengine.")).arg(path));
    };
    help->addAction(tr("Cheat Engine Tutorial..."), this, [launchTutorial]() { launchTutorial("cetutorial"); });
    help->addAction(tr("Graphical Tutorial..."), this, [launchTutorial]() { launchTutorial("cegtutorial"); });
    help->addSeparator();
    help->addAction(tr("About"), this, [this]() {
        auto* dialog = new AboutDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    });
}

// Locate a shipped doc next to the binary (dev build or installed layout).
// Returns an empty string when not found (caller falls back to the online copy).
static QString findDocFile(const QString& rel) {
    const QString exeDir = QCoreApplication::applicationDirPath();
    const QString base = QFileInfo(rel).fileName();
    const QStringList candidates = {
        exeDir + "/" + rel,                                          // next to the binary
        exeDir + "/../" + rel,                                       // dev build: build/../<rel>
        exeDir + "/../share/doc/cheat-engine-linux/" + base,         // installed
        "/usr/share/doc/cheat-engine-linux/" + base,
    };
    for (const auto& c : candidates)
        if (QFileInfo::exists(c)) return QFileInfo(c).absoluteFilePath();
    return {};
}

void MainWindow::openHelpDoc(const QString& relPath, const QString& title, const QString& url) {
    QString path = findDocFile(relPath);
    QFile f(path);
    if (path.isEmpty() || !f.open(QIODevice::ReadOnly)) {
        // No local copy (e.g. a minimal install): open the online doc instead.
        QDesktopServices::openUrl(QUrl(url));
        return;
    }
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle(title);
    dlg->resize(780, 640);
    auto* v = new QVBoxLayout(dlg);
    auto* view = new QTextBrowser;
    view->setOpenExternalLinks(true);
    view->setMarkdown(QString::fromUtf8(f.readAll()));   // render the Markdown
    view->document()->setDocumentMargin(12);
    v->addWidget(view);
    auto* row = new QHBoxLayout;
    auto* online = new QPushButton(tr("Open on GitHub"));
    connect(online, &QPushButton::clicked, this, [url]() { QDesktopServices::openUrl(QUrl(url)); });
    row->addWidget(online);
    row->addStretch();
    auto* closeBtn = new QPushButton(tr("Close"));
    row->addWidget(closeBtn);
    v->addLayout(row);
    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

// Table "Comments" window — CE's CommentsUnit: a PageControl with a Comments tab
// holding a free-text memo, plus Close. The text is the cheat table's comment,
// persisted via buildCheatTable()/onLoadTable().
void MainWindow::showComments() {
    auto* dlg = new QDialog(this);
    tableTextWindows_.push_back(dlg);   // closed when another table loads
    dlg->setWindowTitle(tr("Table Comments"));
    dlg->resize(520, 400);
    auto* v = new QVBoxLayout(dlg);
    auto* memo = new QPlainTextEdit;                   // CE Memo1
    memo->setPlainText(tableComment_);
    memo->setPlaceholderText(tr("Notes about this cheat table: how to use it, what each entry does, "
                             "which game version it was made for. They are saved with the table."));
    memo->document()->setDocumentMargin(6);
    v->addWidget(memo);
    auto* row = new QHBoxLayout;                        // CE Panel1
    row->addStretch();
    auto* closeBtn = new QPushButton(tr("Close"));         // CE Button1
    row->addWidget(closeBtn);
    v->addLayout(row);
    connect(memo, &QPlainTextEdit::textChanged, this,
            [this, memo]() { tableComment_ = memo->toPlainText(); });
    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

// CE's "Show Cheat Table Lua Script": view/edit the table-level Lua that runs on
// load and is saved with the table (buildCheatTable). Kept editable here so a
// table author can add trainer logic, not only import a script that already runs.
void MainWindow::showTableLuaScript() {
    auto* dlg = new QDialog(this);
    tableTextWindows_.push_back(dlg);   // closed when another table loads
    dlg->setWindowTitle(tr("Cheat Table Lua Script"));
    dlg->resize(640, 460);
    auto* v = new QVBoxLayout(dlg);
    auto* memo = new CodeEditor;
    memo->setPlainText(tableLuaScript_);
    memo->setPlaceholderText(tr("-- Lua that runs when this table is opened; saved with the table."));
    v->addWidget(memo);

    auto* row = new QHBoxLayout;
    auto* execBtn = new QPushButton(tr("Execute script"));
    execBtn->setProperty("primary", true);
    row->addWidget(execBtn);
    auto* result = new QLabel;
    result->setWordWrap(true);
    row->addWidget(result, 1);
    auto* closeBtn = new QPushButton(tr("Close"));
    row->addWidget(closeBtn);
    v->addLayout(row);

    // Edits are captured live so Close (or saving the table) keeps them.
    connect(memo, &QPlainTextEdit::textChanged, this,
            [this, memo]() { tableLuaScript_ = memo->toPlainText(); });
    // Run it now, through the same engine and against the current process/list as
    // the load-time run. No extra trust prompt: the user typed/edited this here.
    connect(execBtn, &QPushButton::clicked, this, [this, memo, result]() {
        luaEngine_.setProcess(process_.get());
        luaEngine_.setAddressList(addressListModel_);
        auto res = luaEngine_.evalToString(memo->toPlainText().toStdString());
        const auto pal = editorPalette();
        result->setStyleSheet(QString("color: %1;").arg((res.has_value() ? pal.success : pal.error).name()));
        result->setText(res.has_value() ? tr("Script executed.")
                                        : QString(tr("Error: %1")).arg(QString::fromStdString(res.error())));
    });
    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

// Advanced Options — CE's "Code list" window. Kept as a single instance so the
// list survives reopening; double-click / "Open the disassembler" navigates the
// memory browser to the code address.
void MainWindow::showAdvancedOptions() {
    if (!advancedOptions_) {
        advancedOptions_ = new ce::gui::AdvancedOptionsWindow(process_.get(), this);
        connect(advancedOptions_, &ce::gui::AdvancedOptionsWindow::navigateTo, this,
                [this](uintptr_t addr) { openMemoryView(addr); });  // full-featured viewer
    }
    advancedOptions_->setProcess(process_.get());
    advancedOptions_->show();
    advancedOptions_->raise();
    advancedOptions_->activateWindow();
}

void MainWindow::showOverlayDialog() {
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Overlay"));
    auto* layout = new QVBoxLayout(&dialog);
    layout->setSpacing(10);
    auto* intro = new QLabel(tr("A transparent, click-through layer drawn over the whole screen, "
                             "for use with a game in borderless or windowed mode."));
    intro->setWordWrap(true);
    intro->setProperty("secondary", true);
    layout->addWidget(intro);
    auto* osdCheck = new QCheckBox(tr("Status text (process, active cheats, frame rate)"));
    auto* crosshairCheck = new QCheckBox(tr("Crosshair in the centre of the screen"));
    auto* showButton = new QPushButton(tr("Show Overlay"));
    showButton->setProperty("primary", true);
    auto* hideButton = new QPushButton(tr("Hide Overlay"));
    auto* closeButton = new QPushButton(tr("Close"));

    osdCheck->setChecked(!overlayWindow_ || overlayWindow_->osdEnabled());
    crosshairCheck->setChecked(!overlayWindow_ || overlayWindow_->crosshairEnabled());

    layout->addWidget(osdCheck);
    layout->addWidget(crosshairCheck);
    layout->addSpacing(4);
    auto* buttons = new QHBoxLayout;
    buttons->addWidget(showButton);
    buttons->addWidget(hideButton);
    buttons->addStretch();
    buttons->addWidget(closeButton);
    layout->addLayout(buttons);
    dialog.resize(440, dialog.sizeHint().height());

    auto ensureOverlay = [this]() {
        if (overlayWindow_)
            return;

        overlayWindow_ = new OverlayWindow;
        overlayWindow_->setAttribute(Qt::WA_DeleteOnClose);
        connect(overlayWindow_, &QObject::destroyed, this, [this]() {
            overlayWindow_ = nullptr;
        });

        auto* statusTimer = new QTimer(overlayWindow_);
        connect(statusTimer, &QTimer::timeout, this, &MainWindow::updateOverlayStatus);
        statusTimer->start(500);
    };

    connect(showButton, &QPushButton::clicked, this, [this, ensureOverlay, osdCheck, crosshairCheck]() {
        ensureOverlay();
        overlayWindow_->setOsdEnabled(osdCheck->isChecked());
        overlayWindow_->setCrosshairEnabled(crosshairCheck->isChecked());
        updateOverlayStatus();
        overlayWindow_->showFullScreen();
    });
    connect(hideButton, &QPushButton::clicked, this, [this]() {
        if (overlayWindow_)
            overlayWindow_->close();
    });
    connect(osdCheck, &QCheckBox::toggled, this, [this](bool enabled) {
        if (overlayWindow_)
            overlayWindow_->setOsdEnabled(enabled);
    });
    connect(crosshairCheck, &QCheckBox::toggled, this, [this](bool enabled) {
        if (overlayWindow_)
            overlayWindow_->setCrosshairEnabled(enabled);
    });
    connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);

    dialog.exec();
}

void MainWindow::updateOverlayStatus() {
    if (!overlayWindow_)
        return;

    int total = 0;
    int active = 0;
    for (const auto& entry : addressListModel_->entries()) {
        if (entry.isGroup)
            continue;
        ++total;
        if (entry.active)
            ++active;
    }

    overlayWindow_->setStatusText(QString(tr("%1 | Records %2/%3 active"))
        .arg(processLabel_->text())
        .arg(active)
        .arg(total));
}
} // namespace ce::gui
