#include <csignal>
#include "gui/mainwindow.hpp"
#include "core/expression.hpp"
#include "gui/processlistdialog.hpp"
#include "gui/registereditor.hpp"
#include "gui/debuggerwindow.hpp"
#include "gui/memorybrowser.hpp"
#include "gui/scripteditor.hpp"
#include "gui/pointerscan_dialog.hpp"
#include "gui/structuredissector.hpp"
#include "gui/luaconsole.hpp"
#include "gui/breakpointlist.hpp"
#include "gui/codefinder.hpp"
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
#include "core/trainer.hpp"
#include "analysis/managed_runtime.hpp"

#include <QMenuBar>
#include <QApplication>
#include <QEventLoop>
#include <thread>
#include <atomic>
#include <QCoreApplication>
#include <fstream>
#include "platform/linux/injector.hpp"
#include <QClipboard>
#include <QPixmap>
#include <QPainter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QFile>
#include <QDialog>
#include <QDialogButtonBox>
#include <QLabel>
#include <QKeySequenceEdit>
#include <QPushButton>
#include <QTimer>
#include <QFileInfo>
#include <cerrno>
#include <QBrush>
#include <QFont>
#include <QMenu>
#include <QShortcut>
#include <QInputDialog>
#include <QSettings>
#include <QFormLayout>
#include <QStatusBar>
#include <QColor>
#include <QDoubleValidator>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <QMap>
#include <cmath>
#include <cstring>
#include <exception>

namespace ce::gui {
// Accepts "," or "." decimals (Turkish comma-locale); defined lower down.
static double parseUserDouble(const QString& s, bool* ok = nullptr);

// Forward declarations of static helpers
static ScanCompare mapScanType(int index);
static ValueType mapValueType(int index);
static void warnIfMemoryUnreadable(QWidget* parent, ce::ProcessHandle* p,
                                   pid_t pid, const QString& name);

// ═══════════════════════════════════════════════════════════════
// MainWindow
// ═══════════════════════════════════════════════════════════════

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setupUi();
    setupMenus();
    setWindowTitle("Cheat Engine");
    resize(760, 560);

    // Lua-evaluated AA blocks: {$lua}return "..."{$asm} substitutes the result
    // into the AA stream at preprocess time.
    autoAsm_.setLuaEvaluator([this](const std::string& code) {
        return luaEngine_.evalToString(code);
    });

    // Refresh address list values periodically (skip if user is editing)
    valueRefreshTimer_ = new QTimer(this);
    auto* timer = valueRefreshTimer_;
    connect(timer, &QTimer::timeout, this, [this]() {
        if (!process_) return;
        // Detect target death: once the pid is gone, stop polling and clear state
        // so the UI doesn't keep showing stale values against a dead process.
        if (currentPid_ > 0 && ::kill(currentPid_, 0) != 0 && errno == ESRCH) {
            processLabel_->setText(QString("Process %1 has exited").arg(currentPid_));
            statusBar()->showMessage("Target process exited", 5000);
            process_.reset();
            currentPid_ = 0;
            addressListModel_->setProcess(nullptr);
            resultsModel_->setProcess(nullptr);
            updateScanButtons();
            return;
        }
        // Skip the refresh only while a cell editor is open: the item delegate
        // editor is a separate widget parented under the view's viewport, so the
        // old indexWidget() guard never fired. Plain view focus (the user just
        // watching live values) is NOT editing, so check for a focused
        // descendant editor rather than mere focus on the view itself.
        QWidget* fw = QApplication::focusWidget();
        bool editing = fw && fw != addressListView_ &&
                       fw != addressListView_->viewport() &&
                       addressListView_->isAncestorOf(fw);
        if (!editing)
            addressListModel_->updateValues(process_.get());

        // Live-refresh the scan-results list too, but only the rows currently
        // visible (result sets can be millions of rows).
        if (resultsModel_ && resultsView_ && resultsModel_->rowCount() > 0) {
            QModelIndex topIdx = resultsView_->indexAt(QPoint(2, 2));
            QModelIndex botIdx = resultsView_->indexAt(
                QPoint(2, resultsView_->viewport()->height() - 2));
            int first = topIdx.isValid() ? topIdx.row() : 0;
            int last  = botIdx.isValid() ? botIdx.row()
                                         : std::min(resultsModel_->rowCount() - 1, first + 100);
            resultsModel_->refreshRange(first, last);
        }
    });
    timer->start(QSettings().value("memview/refreshMs", 500).toInt());

    // Freeze timer — writes frozen values at 100ms intervals
    auto* freezeTimer = new QTimer(this);
    connect(freezeTimer, &QTimer::timeout, this, &MainWindow::onFreezeTimer);
    freezeTimer->start(100);

    // F5 forces an immediate value refresh (CE-style manual refresh).
    auto* refreshSc = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(refreshSc, &QShortcut::activated, this, [this]() {
        if (!process_) return;
        addressListModel_->updateValues(process_.get());
        if (resultsModel_ && resultsView_ && resultsModel_->rowCount() > 0) {
            QModelIndex topIdx = resultsView_->indexAt(QPoint(2, 2));
            QModelIndex botIdx = resultsView_->indexAt(
                QPoint(2, resultsView_->viewport()->height() - 2));
            int first = topIdx.isValid() ? topIdx.row() : 0;
            int last  = botIdx.isValid() ? botIdx.row()
                                         : std::min(resultsModel_->rowCount() - 1, first + 100);
            resultsModel_->refreshRange(first, last);
        }
    });
}

void MainWindow::setupMenus() {
    auto* file = menuBar()->addMenu("&File");
    file->addAction("Open Process...", this, &MainWindow::onOpenProcess, QKeySequence("Ctrl+O"));
    file->addAction("Connect to ceserver...", this, &MainWindow::onConnectCeserver);
    file->addSeparator();
    file->addAction("Save Table...", this, &MainWindow::onSaveTable, QKeySequence("Ctrl+S"));
    file->addAction("Load Table...", this, &MainWindow::onLoadTable, QKeySequence("Ctrl+L"));
    file->addAction("Create Trainer (C source)...", this, &MainWindow::onCreateTrainer);
    file->addSeparator();
    file->addAction("Quit", this, &QWidget::close, QKeySequence("Ctrl+Q"));

    // Cheat Engine's top-level menu structure: File / Edit / Process / Table /
    // Tools / Help. (Created here in order so the menu bar reads like CE.)
    auto* edit = menuBar()->addMenu("&Edit");
    auto* process = menuBar()->addMenu("&Process");
    auto* table = menuBar()->addMenu("&Table");
    auto* tools = menuBar()->addMenu("&Tools");
    tools->addAction("Memory Browser", this, &MainWindow::onMemoryView, QKeySequence("Ctrl+M"));
    tools->addAction("Breakpoint List", this, [this]() {
        auto* w = new BreakpointListWindow(&bpManager_, this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    }, QKeySequence("Ctrl+B"));
    tools->addAction("Memory Regions", this, [this]() {
        if (!process_) return;
        auto* w = new MemoryRegionsWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &MemoryRegionsWindow::navigateTo, this, [this](uintptr_t addr) {
            auto* browser = new MemoryBrowser(process_.get(), this);
            browser->setAttribute(Qt::WA_DeleteOnClose);
            wireBrowserAnnotations(browser);
            browser->gotoAddress(addr);
            browser->show();
        });
        w->show();
    });
    tools->addAction("Heap Regions", this, [this]() {
        if (!process_) return;
        auto* w = new HeapRegionsWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &HeapRegionsWindow::navigateTo, this, [this](uintptr_t addr) {
            auto* browser = new MemoryBrowser(process_.get(), this);
            browser->setAttribute(Qt::WA_DeleteOnClose);
            wireBrowserAnnotations(browser);
            browser->gotoAddress(addr);
            browser->show();
        });
        w->show();
    });
    tools->addAction("Module List", this, [this]() {
        if (!process_) return;
        auto* w = new ModuleListWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &ModuleListWindow::navigateTo, this, [this](uintptr_t addr) {
            auto* browser = new MemoryBrowser(process_.get(), this);
            browser->setAttribute(Qt::WA_DeleteOnClose);
            wireBrowserAnnotations(browser);
            browser->gotoAddress(addr);
            browser->show();
        });
        w->show();
    });
    tools->addAction("Code References", this, [this]() {
        if (!process_) return;
        auto* w = new CodeReferencesWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &CodeReferencesWindow::navigateTo, this, [this](uintptr_t addr) {
            auto* browser = new MemoryBrowser(process_.get(), this);
            browser->setAttribute(Qt::WA_DeleteOnClose);
            wireBrowserAnnotations(browser);
            browser->gotoAddress(addr);
            browser->show();
        });
        w->show();
    });
    tools->addAction("Thread List", this, [this]() {
        if (!process_) return;
        auto* w = new ThreadListWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    tools->addAction("Stack View", this, [this]() {
        if (!process_) return;
        auto* w = new StackViewWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    tools->addAction("Register Editor", this, [this]() {
        if (!process_) return;
        auto* w = new RegisterEditorWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    tools->addAction("Debugger", this, [this]() {
        if (!process_) return;
        auto* w = new ce::gui::DebuggerWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    tools->addSeparator();
    edit->addAction("Settings...", this, [this]() {
        SettingsDialog dlg(this);
        dlg.exec();
        // Apply the (possibly changed) auto-refresh interval live (restart to
        // guarantee the new interval takes effect immediately).
        if (valueRefreshTimer_)
            valueRefreshTimer_->start(QSettings().value("memview/refreshMs", 500).toInt());
    });

    // ── Process menu ──
    process->addAction("Open Process...", this, &MainWindow::onOpenProcess);
    // "Pause the process" toggle (CE's pause-the-game) — SIGSTOP/SIGCONT the target.
    auto* pauseAct = process->addAction("Pause the process");
    pauseAct->setCheckable(true);
    connect(pauseAct, &QAction::toggled, this, [this, pauseAct](bool checked) {
        if (!process_ || currentPid_ <= 0) { pauseAct->setChecked(false); return; }
        if (::kill(currentPid_, checked ? SIGSTOP : SIGCONT) != 0)
            pauseAct->setChecked(false);
    });
    // ── Table menu ──
    table->addAction("Auto Assemble...", this, [this]() {
        auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
        editor->setAttribute(Qt::WA_DeleteOnClose);
        editor->setAddToTable([this](const QString& d, const QString& s) {
            addressListModel_->addScriptEntry(d, s);
        });
        editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
        editor->show();
    }, QKeySequence("Ctrl+A"));
    tools->addAction("Pointer Scanner...", this, [this]() {
        if (!process_) return;
        auto* dlg = new PointerScanDialog(process_.get(), this);
        connect(dlg, &PointerScanDialog::addressSelected, this, [this](uintptr_t addr, const QString& desc) {
            addressListModel_->addEntry(addr, ce::ValueType::Int32, desc);
        });
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }, QKeySequence("Ctrl+P"));
    tools->addAction("Structure Dissector...", this, [this]() {
        if (!process_) return;
        bool ok;
        auto text = QInputDialog::getText(this, "Structure Dissector", "Base address (hex):",
            QLineEdit::Normal, "0", &ok);
        uintptr_t addr = ok ? text.toULongLong(nullptr, 16) : 0;
        auto* sd = new StructureDissector(process_.get(), addr, this);
        sd->setAttribute(Qt::WA_DeleteOnClose);
        sd->setAddToListCallback([this](uintptr_t a, ce::ValueType t, const QString& d) {
            addressListModel_->addEntry(a, t, d);
        });
        sd->show();
    });
    tools->addAction("File Patcher...", this, [this]() {
        auto* dlg = new FilePatcher(this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    tools->addAction("Find Statics...", this, [this]() {
        if (!process_) {
            QMessageBox::warning(this, "No process", "Open a process first.");
            return;
        }
        auto* w = new FindStaticsWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        w->show();
    });
    table->addAction("Form Designer...", this, [this]() {
        auto* fd = new FormDesigner(this);
        fd->setAttribute(Qt::WA_DeleteOnClose);
        fd->show();
    });
    tools->addAction("ELF Inspector...", this, [this]() {
        QString initial;
        if (process_) {
            auto mods = process_->modules();
            if (!mods.empty()) initial = QString::fromStdString(mods.front().path);
        }
        auto* dlg = new ElfInspector(initial, this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    process->addAction("Wait for process...", this, [this]() {
        bool ok = false;
        auto name = QInputDialog::getText(this, "Wait for process",
            "Process name substring (will auto-attach when seen):",
            QLineEdit::Normal, "", &ok);
        if (!ok || name.isEmpty()) return;
        if (processWatcher_) processWatcher_->stop();
        processWatcher_ = std::make_unique<os::ProcessWatcher>();
        auto* status = statusBar();
        status->showMessage(QString("Watching for '%1'…").arg(name));
        processWatcher_->start(name.toStdString(),
            [this, status](pid_t pid, const std::string& procName) {
                QMetaObject::invokeMethod(this, [this, pid, procName, status]() {
                    status->showMessage(
                        QString("Auto-attached to %1 (pid %2)")
                            .arg(QString::fromStdString(procName)).arg(pid),
                        4000);
                    currentPid_ = pid;
                    ceserverClient_.reset();
                    process_ = std::make_unique<os::LinuxProcessHandle>(pid);
                    processLabel_->setText(QString("PID: %1 — %2 (auto-attached)")
                        .arg(pid).arg(QString::fromStdString(procName)));
                    warnIfMemoryUnreadable(this, process_.get(), pid,
                                           QString::fromStdString(procName));
                    addressListModel_->setProcess(process_.get());
                    resultsModel_->setProcess(process_.get());
                    firstScanBtn_->setEnabled(true);
                    updateScanButtons();
                    if (processWatcher_) processWatcher_->stop();
                }, Qt::QueuedConnection);
            });
    });
    auto* snapshotMenu = tools->addMenu("Snapshot");
    snapshotMenu->addAction("Capture writable regions", this, [this]() {
        if (!process_) {
            QMessageBox::warning(this, "No process", "Open a process before capturing a snapshot.");
            return;
        }
        snapshot_ = std::make_unique<Snapshot>(Snapshot::capture(*process_));
        QMessageBox::information(this, "Snapshot captured",
            QString("Captured %1 region(s), %2 bytes total.")
                .arg(snapshot_->regionCount()).arg(snapshot_->byteCount()));
    });
    snapshotMenu->addAction("Diff against current", this, [this]() {
        if (!process_ || !snapshot_) {
            QMessageBox::warning(this, "Need both", "Capture a baseline snapshot first, then open a process.");
            return;
        }
        Snapshot now = Snapshot::capture(*process_);
        auto diffs = snapshot_->diff(now);
        if (diffs.empty()) {
            QMessageBox::information(this, "Diff", "No byte-level differences detected.");
            return;
        }
        // Show the first 200 diffs in a simple dialog; full list can be saved.
        QString text;
        text += QString("%1 byte%2 changed since the baseline.\n\n")
            .arg(diffs.size()).arg(diffs.size() == 1 ? "" : "s");
        int shown = (int)std::min<size_t>(200, diffs.size());
        for (int i = 0; i < shown; ++i) {
            text += QString("0x%1: 0x%2 -> 0x%3\n")
                .arg(diffs[i].address, 16, 16, QChar('0'))
                .arg(diffs[i].before, 2, 16, QChar('0'))
                .arg(diffs[i].after,  2, 16, QChar('0'));
        }
        if ((int)diffs.size() > shown)
            text += QString("\n(%1 more not shown — use Save to dump full list.)").arg(diffs.size() - shown);

        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Snapshot diff");
        dlg->resize(640, 480);
        auto* l = new QVBoxLayout(dlg);
        auto* edit = new QPlainTextEdit(text);
        edit->setReadOnly(true);
        edit->setFont(QFont("Monospace", 9));
        l->addWidget(edit);
        auto* btn = new QPushButton("Close");
        connect(btn, &QPushButton::clicked, dlg, &QDialog::accept);
        l->addWidget(btn);
        dlg->exec();
        dlg->deleteLater();
    });
    snapshotMenu->addAction("Restore baseline", this, [this]() {
        if (!process_ || !snapshot_) {
            QMessageBox::warning(this, "Need both", "Capture a baseline snapshot first.");
            return;
        }
        auto answer = QMessageBox::question(this, "Restore?",
            QString("Write the baseline back into the process? This overwrites every "
                    "writable region captured (%1 regions, %2 bytes).")
                .arg(snapshot_->regionCount()).arg(snapshot_->byteCount()));
        if (answer != QMessageBox::Yes) return;
        auto written = snapshot_->restore(*process_);
        QMessageBox::information(this, "Restored",
            QString("Wrote %1 bytes back into the process.").arg(written));
    });
    snapshotMenu->addAction("Save to file...", this, [this]() {
        if (!snapshot_) {
            QMessageBox::warning(this, "No snapshot", "Capture a snapshot first.");
            return;
        }
        auto path = QFileDialog::getSaveFileName(this, "Save snapshot", "snapshot.cesnap",
            "Snapshot (*.cesnap);;All (*)");
        if (path.isEmpty()) return;
        if (!snapshot_->save(path.toStdString())) {
            QMessageBox::warning(this, "Save failed", "Could not write " + path);
        }
    });
    snapshotMenu->addAction("Load from file...", this, [this]() {
        auto path = QFileDialog::getOpenFileName(this, "Load snapshot", "",
            "Snapshot (*.cesnap);;All (*)");
        if (path.isEmpty()) return;
        auto loaded = std::make_unique<Snapshot>();
        std::string err;
        if (!loaded->load(path.toStdString(), &err)) {
            QMessageBox::warning(this, "Load failed", QString::fromStdString(err));
            return;
        }
        snapshot_ = std::move(loaded);
        QMessageBox::information(this, "Snapshot loaded",
            QString("Loaded %1 region(s), %2 bytes.")
                .arg(snapshot_->regionCount()).arg(snapshot_->byteCount()));
    });
    tools->addAction("Branch Mapper (LBR)...", this, [this]() {
        if (!process_) {
            QMessageBox::warning(this, "No process", "Open a process first.");
            return;
        }
        auto* bm = new BranchMapper(process_.get(), this);
        bm->setAttribute(Qt::WA_DeleteOnClose);
        bm->show();
    });
    tools->addAction("Break and Trace...", this, [this]() {
        if (!process_) {
            QMessageBox::warning(this, "No process", "Open a process before tracing.");
            return;
        }
        auto* tw = new TracerWindow(process_.get(),
            [this]() { return createDebuggerForCurrentProcess(); }, this);
        tw->setAttribute(Qt::WA_DeleteOnClose);
        tw->show();
    });
    tools->addSeparator();
    tools->addAction("Lua Console...", this, [this]() {
        luaEngine_.setProcess(process_.get());
        // Give Lua a populated symbol resolver so getAddressFromName(),
        // registerSymbol(), and expression parsing actually resolve names.
        if (process_) {
            luaResolver_.loadProcess(*process_);
            luaEngine_.setResolver(&luaResolver_);
        }
        auto* console = new LuaConsole(&luaEngine_, this);
        console->setAttribute(Qt::WA_DeleteOnClose);
        console->show();
    }, QKeySequence("Ctrl+Shift+L"));
    tools->addSeparator();
    tools->addAction("Overlay...", this, &MainWindow::showOverlayDialog);
    tools->addAction("Detect Mono/.NET Runtime", this, [this]() {
        if (!process_) {
            QMessageBox::warning(this, "Managed Runtime", "Open a process first.");
            return;
        }
        auto runtimes = ce::detectManagedRuntimes(*process_);
        if (runtimes.empty()) {
            QMessageBox::information(this, "Managed Runtime",
                "No Mono or .NET (CoreCLR) runtime detected — this looks like a native process.");
            return;
        }
        QString text = "Detected managed runtime(s):\n\n";
        for (const auto& r : runtimes) {
            text += QString("- %1 - module %2\n   base 0x%3\n   %4\n\n")
                .arg(r.kind == ce::ManagedRuntimeKind::Mono ? ".NET/Mono" : ".NET (CoreCLR)")
                .arg(QString::fromStdString(r.moduleName))
                .arg(r.base, 0, 16)
                .arg(QString::fromStdString(r.modulePath));
        }
        QMessageBox::information(this, "Managed Runtime", text.trimmed());
    });
    tools->addSeparator();
    tools->addAction("Speedhack...", this, [this]() {
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Speedhack");
        dlg->resize(300, 120);
        auto* layout = new QVBoxLayout(dlg);
        auto* label = new QLabel("Speed: 1.0x");
        auto* slider = new QSlider(Qt::Horizontal);
        slider->setRange(1, 100);  // 0.1x to 10.0x
        slider->setValue(10);      // 1.0x default
        connect(slider, &QSlider::valueChanged, [label](int v) {
            double speed = v / 10.0;
            label->setText(QString("Speed: %1x").arg(speed, 0, 'f', 1));
        });
        auto* applyBtn = new QPushButton("Apply (inject speedhack + set speed)");
        connect(applyBtn, &QPushButton::clicked, [this, slider, label]() {
            double speed = slider->value() / 10.0;
            // Inject the speedhack library into the running target the first time,
            // so it works without relaunching the game under LD_PRELOAD (CE-style).
            if (process_) {
                pid_t pid = process_->pid();
                bool loaded = false;
                std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
                std::string line;
                while (std::getline(maps, line))
                    if (line.find("libspeedhack.so") != std::string::npos) { loaded = true; break; }
                if (!loaded) {
                    // injectLibrary needs the target's libc symbols (dlopen); the
                    // resolver is otherwise only populated lazily on Lua use.
                    if (luaResolver_.count() == 0) luaResolver_.loadProcess(*process_);
                    std::string so = (QCoreApplication::applicationDirPath() +
                                      "/libspeedhack.so").toStdString();
                    auto r = ce::os::injectLibrary(*process_, luaResolver_, so);
                    if (!r) {
                        label->setText(QString("Inject failed: %1")
                                           .arg(QString::fromStdString(r.error())));
                        return;  // don't set a speed the plugin can't read
                    }
                }
                label->setText(QString("Active — Speed: %1x").arg(speed, 0, 'f', 1));
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
                if (::fstat(shmfd, &st) == 0 && S_ISREG(st.st_mode) &&
                    ::ftruncate(shmfd, sizeof(double)) == 0) {
                    void* mem = ::mmap(nullptr, sizeof(double), PROT_READ|PROT_WRITE, MAP_SHARED, shmfd, 0);
                    if (mem != MAP_FAILED) { *(double*)mem = speed; ::munmap(mem, sizeof(double)); }
                }
                ::close(shmfd);
            }
        });
        layout->addWidget(label);
        layout->addWidget(slider);
        layout->addWidget(applyBtn);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });

    auto* help = menuBar()->addMenu("&Help");
    help->addAction("About", this, [this]() {
        QMessageBox::about(this, "Cheat Engine for Linux",
            "<h2>Cheat Engine for Linux</h2>"
            "<p>Memory scanner, debugger, and code injection tool</p>"
            "<p>C++23 / Qt6 / Capstone / Keystone / Lua 5.3</p>"
            "<p>9,120 lines of code</p>"
            "<p><a href='https://github.com/wleeaf/cheat-engine-linux'>GitHub</a></p>");
    });
}

void MainWindow::showOverlayDialog() {
    QDialog dialog(this);
    dialog.setWindowTitle("Overlay");
    auto* layout = new QVBoxLayout(&dialog);
    auto* osdCheck = new QCheckBox("OSD text");
    auto* crosshairCheck = new QCheckBox("Crosshair");
    auto* showButton = new QPushButton("Show Overlay");
    auto* hideButton = new QPushButton("Hide Overlay");
    auto* closeButton = new QPushButton("Close");

    osdCheck->setChecked(!overlayWindow_ || overlayWindow_->osdEnabled());
    crosshairCheck->setChecked(!overlayWindow_ || overlayWindow_->crosshairEnabled());

    layout->addWidget(osdCheck);
    layout->addWidget(crosshairCheck);
    layout->addWidget(showButton);
    layout->addWidget(hideButton);
    layout->addWidget(closeButton);

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

    overlayWindow_->setStatusText(QString("%1 | Records %2/%3 active")
        .arg(processLabel_->text())
        .arg(active)
        .arg(total));
}

void MainWindow::setupUi() {
    auto* central = new QWidget;
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(4, 4, 4, 4);
    mainLayout->setSpacing(4);

    // ── Process bar ──
    auto* processBar = new QHBoxLayout;
    auto* openBtn = new QPushButton;
    openBtn->setFixedSize(38, 38);
    openBtn->setToolTip("Open process");
    // Remove the default button padding so the icon fills the button instead of
    // being clipped by the frame.
    openBtn->setStyleSheet("QPushButton { padding: 0px; }");
    // Prefer the bundled app icon; if it isn't available, draw a crosshair
    // target (thematic for a scanner) instead of falling back to plain text.
    QPixmap btnIcon(":/icon.png");
    if (btnIcon.isNull()) {
        btnIcon = QPixmap(64, 64);
        btnIcon.fill(Qt::transparent);
        QPainter p(&btnIcon);
        p.setRenderHint(QPainter::Antialiasing);
        QPen pen(QColor(0x8a, 0xad, 0xf4)); // soft blue accent
        pen.setWidth(5);
        pen.setCapStyle(Qt::RoundCap);
        p.setPen(pen);
        p.drawEllipse(QPoint(32, 32), 20, 20);   // outer ring
        p.drawLine(32, 4,  32, 16);              // top tick
        p.drawLine(32, 48, 32, 60);              // bottom tick
        p.drawLine(4,  32, 16, 32);              // left tick
        p.drawLine(48, 32, 60, 32);              // right tick
        p.setBrush(pen.color());
        p.drawEllipse(QPoint(32, 32), 4, 4);     // center dot
        p.end();
    }
    openBtn->setIcon(QIcon(btnIcon.scaled(22, 22, Qt::KeepAspectRatio, Qt::SmoothTransformation)));
    openBtn->setIconSize(QSize(22, 22));
    connect(openBtn, &QPushButton::clicked, this, &MainWindow::onOpenProcess);
    processLabel_ = new QLabel("No process selected");
    processLabel_->setStyleSheet("font-weight: bold;");
    processBar->addWidget(openBtn);
    processBar->addWidget(processLabel_, 1);
    mainLayout->addLayout(processBar);

    // ── Top area: results + scan controls ──
    auto* topSplitter = new QSplitter(Qt::Horizontal);

    // Left: scan results
    auto* leftPanel = new QWidget;
    auto* leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(0, 0, 0, 0);

    resultsModel_ = new ScanResultsModel(this);
    resultsView_ = new QTableView;
    resultsView_->setModel(resultsModel_);
    resultsView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsView_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    resultsView_->setFont(QFont("Monospace", 9));
    resultsView_->verticalHeader()->setVisible(false);
    resultsView_->horizontalHeader()->setStretchLastSection(true);
    connect(resultsView_, &QTableView::doubleClicked, this, &MainWindow::onResultDoubleClicked);
    // Enter adds all selected results to the address list (complements the
    // context menu's "Add N selected").
    auto* addSelSc = new QShortcut(QKeySequence(Qt::Key_Return), resultsView_);
    addSelSc->setContext(Qt::WidgetShortcut);
    connect(addSelSc, &QShortcut::activated, this, [this]() {
        if (!lastResult_) return;
        auto sel = resultsView_->selectionModel()->selectedRows();
        for (auto& idx : sel)
            addressListModel_->addEntry(resultsModel_->addressAt(idx.row()), lastResultType_);
    });
    resultsView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(resultsView_, &QTableView::customContextMenuRequested, this, [this](const QPoint& pos) {
        if (!lastResult_) return;
        auto sel = resultsView_->selectionModel()->selectedRows();
        if (sel.isEmpty()) return;
        QMenu menu(this);
        auto* addAct = menu.addAction(sel.size() > 1
            ? QString("Add %1 selected to address list").arg(sel.size())
            : QString("Add to address list"));
        auto* browseAct = menu.addAction("Browse this memory region");
        auto* copyAct = menu.addAction("Copy address(es)");
        QAction* picked = menu.exec(resultsView_->viewport()->mapToGlobal(pos));
        if (!picked) return;
        if (picked == addAct) {
            for (auto& idx : sel)
                addressListModel_->addEntry(resultsModel_->addressAt(idx.row()), lastResultType_);
        } else if (picked == browseAct) {
            onMemoryView();
        } else if (picked == copyAct) {
            QStringList addrs;
            for (auto& idx : sel)
                addrs << QString("0x%1").arg(resultsModel_->addressAt(idx.row()), 0, 16);
            QApplication::clipboard()->setText(addrs.join('\n'));
        }
    });
    // Ctrl+C copies the selected result addresses (the "Copy address(es)" menu
    // action), matching the address list's copy shortcut.
    auto* resultsCopySc = new QShortcut(QKeySequence::Copy, resultsView_);
    connect(resultsCopySc, &QShortcut::activated, this, [this]() {
        if (!lastResult_) return;
        const auto sel = resultsView_->selectionModel()->selectedRows();
        QStringList addrs;
        for (const auto& idx : sel)
            addrs << QString("0x%1").arg(resultsModel_->addressAt(idx.row()), 0, 16);
        if (!addrs.isEmpty()) QApplication::clipboard()->setText(addrs.join('\n'));
    });
    leftLayout->addWidget(resultsView_);

    auto* foundRow = new QHBoxLayout;
    foundLabel_ = new QLabel("Found: 0");
    foundRow->addWidget(foundLabel_);
    foundRow->addStretch();
    auto* resHexCheck = new QCheckBox("Hex");
    resHexCheck->setToolTip("Show result values in hexadecimal");
    connect(resHexCheck, &QCheckBox::toggled, this, [this](bool on) { resultsModel_->setDisplayHex(on); });
    foundRow->addWidget(resHexCheck);
    leftLayout->addLayout(foundRow);

    auto* leftBtns = new QHBoxLayout;
    auto* memViewBtn = new QPushButton("Memory View");
    connect(memViewBtn, &QPushButton::clicked, this, &MainWindow::onMemoryView);
    auto* addAddrBtn = new QPushButton("Add Address");
    connect(addAddrBtn, &QPushButton::clicked, this, [this]() {
        bool ok = false;
        auto text = QInputDialog::getText(this, "Add Address",
            "Address, symbol, module+offset, or [pointer]+off:", QLineEdit::Normal, "", &ok);
        if (!ok || text.trimmed().isEmpty()) return;
        auto addr = parseAddressExpr(text);
        if (addr) {
            // Keep the address EXPRESSION (not just the resolved absolute) whenever
            // it isn't a plain hex literal, so pointer chains ("[base]+8"),
            // module+offset ("game.exe+1C"), and symbols re-resolve every refresh
            // AND survive save/reload across ASLR. A bare hex address is static.
            auto trimmed = text.trimmed();
            auto hexBody = trimmed;
            if (hexBody.startsWith("0x") || hexBody.startsWith("0X")) hexBody = hexBody.mid(2);
            bool plainHex = !hexBody.isEmpty() &&
                std::all_of(hexBody.begin(), hexBody.end(),
                            [](QChar c){ return std::isxdigit(c.toLatin1()); });
            QString expr = plainHex ? QString() : trimmed;
            addressListModel_->addEntry(*addr, mapValueType(valueTypeCombo_->currentIndex()),
                                        "Manual entry", expr);
        } else
            QMessageBox::warning(this, "Add Address", QString("Could not resolve \"%1\".").arg(text.trimmed()));
    });
    leftBtns->addWidget(memViewBtn);
    leftBtns->addWidget(addAddrBtn);
    leftBtns->addStretch();
    leftLayout->addLayout(leftBtns);

    // Right: scan controls
    auto* rightPanel = new QWidget;
    auto* rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(4, 0, 0, 0);

    // Value input
    auto* valueLayout = new QHBoxLayout;
    valueLayout->addWidget(new QLabel("Value:"));
    scanValueEdit_ = new QLineEdit;
    valueLayout->addWidget(scanValueEdit_);
    // Second bound, only shown for "Value between..." scans.
    betweenAndLabel_ = new QLabel("and");
    betweenAndLabel_->setVisible(false);
    valueLayout->addWidget(betweenAndLabel_);
    scanValue2Edit_ = new QLineEdit;
    scanValue2Edit_->setVisible(false);
    valueLayout->addWidget(scanValue2Edit_);
    hexCheck_ = new QCheckBox("Hex");
    hexCheck_->setToolTip("Interpret integer scan values as hexadecimal");
    valueLayout->addWidget(hexCheck_);
    rightLayout->addLayout(valueLayout);

    // Scan type
    scanTypeCombo_ = new QComboBox;
    scanTypeCombo_->addItems({"Exact Value", "Bigger than...", "Smaller than...",
        "Value between...", "Unknown initial value", "Increased value",
        "Decreased value", "Changed value", "Unchanged value", "Same as first scan",
        "Increased value by...", "Decreased value by..."});
    rightLayout->addWidget(scanTypeCombo_);

    // Reveal the second value box only for a "Value between..." scan.
    auto updateBetweenUi = [this]() {
        bool between = mapScanType(scanTypeCombo_->currentIndex()) == ScanCompare::Between;
        betweenAndLabel_->setVisible(between);
        scanValue2Edit_->setVisible(between);
    };
    connect(scanTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updateBetweenUi](int) { updateBetweenUi(); });
    updateBetweenUi();

    // Value type
    valueTypeCombo_ = new QComboBox;
    valueTypeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "Text", "Unicode Text", "Array of Bytes", "Binary", "All Types", "Pointer", "Grouped", "Custom"});
    valueTypeCombo_->setCurrentIndex(2); // 4 Bytes default
    rightLayout->addWidget(valueTypeCombo_);

    auto* floatLayout = new QHBoxLayout;
    floatRoundingCombo_ = new QComboBox;
    floatRoundingCombo_->addItems({"Exact", "Rounded", "Truncated", "Extreme"});
    floatRoundingCombo_->setCurrentIndex(1);  // CE defaults float scans to Rounded
    floatToleranceEdit_ = new QLineEdit;
    floatToleranceEdit_->setPlaceholderText("Tolerance");
    floatToleranceEdit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 8, floatToleranceEdit_));
    floatLayout->addWidget(floatRoundingCombo_);
    floatLayout->addWidget(floatToleranceEdit_);
    rightLayout->addLayout(floatLayout);
    auto updateFloatOptions = [this]() {
        auto vt = mapValueType(valueTypeCombo_->currentIndex());
        bool isFloat = vt == ValueType::Float || vt == ValueType::Double;
        floatRoundingCombo_->setEnabled(isFloat);
        floatToleranceEdit_->setEnabled(isFloat && floatRoundingCombo_->currentIndex() == 3);
    };
    connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions](int) { updateFloatOptions(); });
    connect(floatRoundingCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions](int) { updateFloatOptions(); });
    updateFloatOptions();

    // Buttons
    auto* btnLayout = new QHBoxLayout;
    firstScanBtn_ = new QPushButton("First Scan");
    firstScanBtn_->setStyleSheet("font-weight: bold;");
    nextScanBtn_ = new QPushButton("Next Scan");
    nextScanBtn_->setEnabled(false);
    undoScanBtn_ = new QPushButton("Undo Scan");
    undoScanBtn_->setEnabled(false);
    connect(firstScanBtn_, &QPushButton::clicked, this, &MainWindow::onFirstScan);
    connect(nextScanBtn_, &QPushButton::clicked, this, &MainWindow::onNextScan);
    connect(undoScanBtn_, &QPushButton::clicked, this, &MainWindow::onUndoScan);
    btnLayout->addWidget(firstScanBtn_);
    btnLayout->addWidget(nextScanBtn_);
    rightLayout->addLayout(btnLayout);
    rightLayout->addWidget(undoScanBtn_);

    // Scan options group
    auto* optGroup = new QGroupBox("Memory Scan Options");
    auto* optLayout = new QGridLayout(optGroup);
    optLayout->addWidget(new QLabel("From:"), 0, 0);
    fromAddressEdit_ = new QLineEdit("0000000000");
    fromAddressEdit_->setFont(QFont("Monospace", 9));
    optLayout->addWidget(fromAddressEdit_, 0, 1);
    optLayout->addWidget(new QLabel("To:"), 1, 0);
    toAddressEdit_ = new QLineEdit("7fffffffffff");
    toAddressEdit_->setFont(QFont("Monospace", 9));
    optLayout->addWidget(toAddressEdit_, 1, 1);
    writableCheck_ = new QCheckBox("Writable");
    writableCheck_->setChecked(true);
    optLayout->addWidget(writableCheck_, 2, 0, 1, 2);
    executableCheck_ = new QCheckBox("Executable");
    optLayout->addWidget(executableCheck_, 3, 0, 1, 2);
    fastScanCheck_ = new QCheckBox("Fast Scan");
    fastScanCheck_->setChecked(true);
    optLayout->addWidget(fastScanCheck_, 4, 0);
    alignEdit_ = new QLineEdit("4");
    alignEdit_->setFixedWidth(42);
    optLayout->addWidget(alignEdit_, 4, 1);
    // The alignment field only applies when Fast Scan is on; grey it out otherwise.
    connect(fastScanCheck_, &QCheckBox::toggled, alignEdit_, &QLineEdit::setEnabled);

    percentCheck_ = new QCheckBox("Compare by %");
    optLayout->addWidget(percentCheck_, 5, 0);
    percentValueEdit_ = new QLineEdit("10");
    percentValueEdit_->setFixedWidth(68);
    percentValueEdit_->setEnabled(false);
    percentValueEdit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 4, percentValueEdit_));
    optLayout->addWidget(percentValueEdit_, 5, 1);

    auto* percent2Label = new QLabel("Percent max:");
    optLayout->addWidget(percent2Label, 6, 0);
    percentValue2Edit_ = new QLineEdit("20");
    percentValue2Edit_->setFixedWidth(68);
    percentValue2Edit_->setEnabled(false);
    percentValue2Edit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 4, percentValue2Edit_));
    optLayout->addWidget(percentValue2Edit_, 6, 1);

    caseSensitiveCheck_ = new QCheckBox("Case sensitive (text)");
    caseSensitiveCheck_->setChecked(true);   // string scans default to case-sensitive
    optLayout->addWidget(caseSensitiveCheck_, 8, 0, 1, 2);

    optLayout->addWidget(new QLabel("Text encoding:"), 7, 0);
    stringEncodingCombo_ = new QComboBox;
    stringEncodingCombo_->addItems({"UTF-8", "ISO-8859-1", "CP1252"});
    optLayout->addWidget(stringEncodingCombo_, 7, 1);

    auto updatePercentUi = [this, percent2Label]() {
        bool enabled = percentCheck_->isChecked();
        bool needsUpper = enabled && mapScanType(scanTypeCombo_->currentIndex()) == ScanCompare::Between;
        percentValueEdit_->setEnabled(enabled);
        percent2Label->setEnabled(needsUpper);
        percentValue2Edit_->setEnabled(needsUpper);
    };
    connect(percentCheck_, &QCheckBox::toggled, this, [updatePercentUi](bool) { updatePercentUi(); });
    connect(scanTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updatePercentUi](int) { updatePercentUi(); });
    updatePercentUi();
    rightLayout->addWidget(optGroup);

    progressBar_ = new QProgressBar;
    progressBar_->setMaximum(100);
    progressBar_->setValue(0);
    progressBar_->setVisible(false);
    rightLayout->addWidget(progressBar_);

    rightLayout->addStretch();

    topSplitter->addWidget(leftPanel);
    topSplitter->addWidget(rightPanel);
    topSplitter->setStretchFactor(0, 2);
    topSplitter->setStretchFactor(1, 1);

    // ── Bottom: address list ──
    addressListModel_ = new AddressListModel(this);
    addressListModel_->setAutoAssembler(&autoAsm_);
    addressListModel_->setBeforeAaExecute([this]() { stopCodeFindersForInjection(); });
    // Let inline Address-column edits accept the full expression syntax.
    addressListModel_->setAddressResolver([this](const QString& t) { return parseAddressExpr(t); });
    addressListModel_->setActivationErrorCallback([this](const QString& title, const QString& message) {
        QMessageBox::warning(this, title, message);
    });
    luaEngine_.setAddressList(addressListModel_);
    registerLuaGuiBindings(luaEngine_.state());
    setLuaMainForm(this);
    addressListView_ = new QTableView;
    addressListView_->setModel(addressListModel_);
    // System-wide hotkeys (X11): fire while the game is focused, like CE. The
    // dispatch map is keyed by the id we hand registerHotkey in rebuildValueHotkeys.
    globalHotkeys_ = new GlobalHotkeyManager(this);
    connect(globalHotkeys_, &GlobalHotkeyManager::activated, this, [this](int id) {
        auto it = hotkeyActions_.find(id);
        if (it != hotkeyActions_.end()) (it.value())();
    });

    connect(addressListModel_, &QAbstractItemModel::modelReset, this, &MainWindow::rebuildValueHotkeys);
    connect(addressListModel_, &QAbstractItemModel::rowsInserted, this, &MainWindow::rebuildValueHotkeys);
    connect(addressListModel_, &QAbstractItemModel::rowsRemoved, this, &MainWindow::rebuildValueHotkeys);
    addressListView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    addressListView_->setFont(QFont("Monospace", 9));
    addressListView_->verticalHeader()->setVisible(false);
    addressListView_->horizontalHeader()->setStretchLastSection(true);
    addressListView_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    // Double-clicking a script entry's Address/Type/Value cell (which carry no
    // editable data for a script) opens the auto-assembler editor for it. The
    // Description cell still edits inline.
    connect(addressListView_, &QAbstractItemView::doubleClicked, this,
            [this](const QModelIndex& idx) {
        if (idx.isValid() && idx.column() != 1 && addressListModel_->isScriptEntry(idx.row()))
            editScriptEntry(idx.row());
    });
    addressListView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(addressListView_, &QWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        QMenu menu;
        auto selected = addressListView_->selectionModel()->selectedRows();

        if (!selected.isEmpty()) {
            int firstRow = selected.first().row();
            const auto& ents0 = addressListModel_->entries();
            // "Edit script..." for a single auto-assembler entry — it has no
            // address to edit, so this opens the script in the AA editor.
            if (selected.size() == 1 && addressListModel_->isScriptEntry(firstRow)) {
                menu.addAction("Edit script...", [this, firstRow]() { editScriptEntry(firstRow); });
                menu.addSeparator();
            }

            menu.addAction("Copy", this, &MainWindow::onCopyAddresses, QKeySequence::Copy);
            // Copy an individual field of the first selected entry to the clipboard.
            if (firstRow >= 0 && firstRow < (int)ents0.size()) {
                const auto& fe = ents0[firstRow];
                auto* copyMenu = menu.addMenu("Copy field");
                copyMenu->addAction("Description", [fe]() {
                    QApplication::clipboard()->setText(fe.description);
                });
                if (!fe.isGroup && fe.autoAsmScript.isEmpty()) {
                    copyMenu->addAction("Address", [fe]() {
                        QApplication::clipboard()->setText(
                            fe.addressExpr.isEmpty() ? QString("0x%1").arg(fe.address, 0, 16)
                                                     : fe.addressExpr);
                    });
                    copyMenu->addAction("Value", [fe]() {
                        QApplication::clipboard()->setText(fe.currentValue);
                    });
                }
                if (!fe.autoAsmScript.isEmpty())
                    copyMenu->addAction("Script", [fe]() {
                        QApplication::clipboard()->setText(fe.autoAsmScript);
                    });
            }
            menu.addAction("Delete", this, &MainWindow::onDeleteAddresses, QKeySequence::Delete);

            menu.addSeparator();
            menu.addAction("Indent", [this, selected]() {
                QList<int> rows;
                for (const auto& idx : selected) rows.append(idx.row());
                addressListModel_->indentRows(rows);
            });
            menu.addAction("Outdent", [this, selected]() {
                QList<int> rows;
                for (const auto& idx : selected) rows.append(idx.row());
                addressListModel_->outdentRows(rows);
            });

            menu.addSeparator();
            // Set the value of ALL selected entries at once (CE's batch set value).
            menu.addAction("Set value...", [this, selected]() {
                bool ok = false;
                QString v = QInputDialog::getText(this, "Set value",
                    QString("New value for %1 selected entr%2:")
                        .arg(selected.size()).arg(selected.size() == 1 ? "y" : "ies"),
                    QLineEdit::Normal, QString(), &ok);
                if (!ok) return;
                for (const auto& idx : selected)
                    addressListModel_->setEntryValueTo(idx.row(), v);
            });

            menu.addSeparator();
            auto* freezeMenu = menu.addMenu("Freeze Mode");
            freezeMenu->addAction("Normal", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::Normal);
            });
            freezeMenu->addAction("Increase Only", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::IncreaseOnly);
            });
            freezeMenu->addAction("Decrease Only", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::DecreaseOnly);
            });
            freezeMenu->addAction("Never Increase", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::NeverIncrease);
            });
            freezeMenu->addAction("Never Decrease", [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::NeverDecrease);
            });

            menu.addSeparator();
            auto* typeMenu = menu.addMenu("Change type");
            const std::pair<const char*, ValueType> typeChoices[] = {
                {"Byte", ValueType::Byte}, {"2 Bytes", ValueType::Int16},
                {"4 Bytes", ValueType::Int32}, {"8 Bytes", ValueType::Int64},
                {"Float", ValueType::Float}, {"Double", ValueType::Double},
                {"Pointer", ValueType::Pointer},
            };
            for (const auto& [label, vt] : typeChoices) {
                typeMenu->addAction(label, [this, selected, vt]() {
                    for (auto& idx : selected) addressListModel_->setEntryType(idx.row(), vt);
                });
            }

            menu.addSeparator();
            // Toggle hex display: reflect the first selected row's current state.
            const auto& ents = addressListModel_->entries();
            bool firstHex = !selected.isEmpty() && selected.first().row() < (int)ents.size()
                            && ents[selected.first().row()].showAsHex;
            auto* hexAct = menu.addAction("Show as hexadecimal");
            hexAct->setCheckable(true);
            hexAct->setChecked(firstHex);
            connect(hexAct, &QAction::triggered, this, [this, selected, firstHex]() {
                for (auto& idx : selected) addressListModel_->setShowAsHex(idx.row(), !firstHex);
            });

            // Open the memory browser at this entry's exact address (CE's
            // "Browse this memory region"). Skipped for script/group rows, which
            // have no address.
            if (firstRow >= 0 && firstRow < (int)ents0.size()
                && !ents0[firstRow].isGroup && ents0[firstRow].autoAsmScript.isEmpty()) {
                menu.addAction("Browse this memory region", [this, selected]() {
                    if (!process_ || selected.isEmpty()) return;
                    auto& entries = addressListModel_->entries();
                    int row = selected.first().row();
                    if (row < (int)entries.size()) {
                        auto* browser = new MemoryBrowser(process_.get(), this);
                        browser->setAttribute(Qt::WA_DeleteOnClose);
                        wireBrowserAnnotations(browser);
                        browser->gotoAddress(entries[row].address);
                        browser->show();
                    }
                });
            }
            menu.addAction("Find what accesses this address", [this, selected]() {
                if (!selected.isEmpty())
                    startCodeFinder(selected.first().row(), false);
            });
            menu.addAction("Find what writes to this address", [this, selected]() {
                if (!selected.isEmpty())
                    startCodeFinder(selected.first().row(), true);
            });
            if (selected.size() == 1) {
                menu.addSeparator();
                menu.addAction("Configure Hotkey...", [this, selected]() {
                    int row = selected.first().row();
                    const auto& entries = addressListModel_->entries();
                    if (row < 0 || row >= (int)entries.size()) return;

                    QDialog dialog(this);
                    dialog.setWindowTitle("Configure Hotkey");
                    auto* layout = new QVBoxLayout(&dialog);
                    auto* label = new QLabel(entries[row].description, &dialog);
                    auto* editor = new QKeySequenceEdit(QKeySequence(entries[row].hotkeyKeys), &dialog);
                    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
                    auto* clearButton = buttons->addButton("Clear", QDialogButtonBox::ResetRole);

                    layout->addWidget(label);
                    layout->addWidget(editor);
                    layout->addWidget(buttons);
                    connect(clearButton, &QPushButton::clicked, editor, &QKeySequenceEdit::clear);
                    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
                    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

                    if (dialog.exec() == QDialog::Accepted) {
                        addressListModel_->setHotkeyKeys(row,
                            editor->keySequence().toString(QKeySequence::PortableText));
                    }
                });
                menu.addAction("Configure Value Hotkeys...", [this, selected]() {
                    int row = selected.first().row();
                    const auto& entries = addressListModel_->entries();
                    if (row < 0 || row >= (int)entries.size()) return;

                    QDialog dialog(this);
                    dialog.setWindowTitle("Configure Value Hotkeys");
                    auto* layout = new QGridLayout(&dialog);
                    auto* label = new QLabel(entries[row].description, &dialog);
                    auto* increaseEditor = new QKeySequenceEdit(QKeySequence(entries[row].increaseHotkeyKeys), &dialog);
                    auto* decreaseEditor = new QKeySequenceEdit(QKeySequence(entries[row].decreaseHotkeyKeys), &dialog);
                    auto* stepEdit = new QLineEdit(entries[row].hotkeyStep, &dialog);
                    stepEdit->setValidator(new QDoubleValidator(stepEdit));
                    auto* setEditor = new QKeySequenceEdit(QKeySequence(entries[row].setValueHotkeyKeys), &dialog);
                    auto* setValueEdit = new QLineEdit(entries[row].setValueHotkeyValue, &dialog);
                    setValueEdit->setPlaceholderText("value to set");
                    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);

                    layout->addWidget(label, 0, 0, 1, 2);
                    layout->addWidget(new QLabel("Increase", &dialog), 1, 0);
                    layout->addWidget(increaseEditor, 1, 1);
                    layout->addWidget(new QLabel("Decrease", &dialog), 2, 0);
                    layout->addWidget(decreaseEditor, 2, 1);
                    layout->addWidget(new QLabel("Step", &dialog), 3, 0);
                    layout->addWidget(stepEdit, 3, 1);
                    layout->addWidget(new QLabel("Set value hotkey", &dialog), 4, 0);
                    layout->addWidget(setEditor, 4, 1);
                    layout->addWidget(new QLabel("Set to value", &dialog), 5, 0);
                    layout->addWidget(setValueEdit, 5, 1);
                    layout->addWidget(buttons, 6, 0, 1, 2);
                    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
                    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

                    if (dialog.exec() == QDialog::Accepted) {
                        addressListModel_->setValueHotkeys(row,
                            increaseEditor->keySequence().toString(QKeySequence::PortableText),
                            decreaseEditor->keySequence().toString(QKeySequence::PortableText),
                            stepEdit->text().isEmpty() ? "1" : stepEdit->text(),
                            setEditor->keySequence().toString(QKeySequence::PortableText),
                            setValueEdit->text());
                        rebuildValueHotkeys();
                    }
                });
            }
        }

        menu.addSeparator();
        menu.addAction("Add Address Manually...", [this]() {
            bool ok;
            auto text = QInputDialog::getText(this, "Add Address",
                "Address, symbol, module+offset, or [pointer]+off:", QLineEdit::Normal, "", &ok);
            if (ok && !text.trimmed().isEmpty()) {
                auto addr = parseAddressExpr(text);
                if (addr) {
                    // A '[' means a pointer deref — store the expression so the entry
                    // re-resolves and follows the pointer chain each refresh.
                    QString expr = text.contains('[') ? text.trimmed() : QString();
                    addressListModel_->addEntry(*addr, mapValueType(valueTypeCombo_->currentIndex()),
                                                "Manual entry", expr);
                }
            }
        });
        menu.addAction("Add Group", [this]() {
            addressListModel_->addGroup();
        });
        menu.addAction("Paste", this, &MainWindow::onPasteAddresses, QKeySequence::Paste);

        menu.addSeparator();
        menu.addAction("Enable all", [this]() { addressListModel_->setAllActive(true); });
        menu.addAction("Disable all", [this]() { addressListModel_->setAllActive(false); });

        menu.exec(addressListView_->viewport()->mapToGlobal(pos));
    });
    // Delete key shortcut
    auto* delShortcut = new QShortcut(QKeySequence::Delete, addressListView_);
    connect(delShortcut, &QShortcut::activated, this, &MainWindow::onDeleteAddresses);
    auto* copyShortcut = new QShortcut(QKeySequence::Copy, addressListView_);
    connect(copyShortcut, &QShortcut::activated, this, &MainWindow::onCopyAddresses);
    auto* pasteShortcut = new QShortcut(QKeySequence::Paste, addressListView_);
    connect(pasteShortcut, &QShortcut::activated, this, &MainWindow::onPasteAddresses);
    // Space toggles the active/frozen state of ALL selected entries (CE-style),
    // regardless of the focused column. WidgetShortcut so it doesn't fire while a
    // cell editor is open (there Space types a space). Intercepts before the
    // table's default single-cell checkbox toggle, so there is no double-toggle.
    auto* spaceShortcut = new QShortcut(QKeySequence(Qt::Key_Space), addressListView_);
    spaceShortcut->setContext(Qt::WidgetShortcut);
    connect(spaceShortcut, &QShortcut::activated, this, [this]() {
        const auto sel = addressListView_->selectionModel()->selectedRows();
        for (const auto& idx : sel) addressListModel_->toggleActive(idx.row());
    });

    // ── Cheat-Engine-faithful layout ──
    // All widgets above are created and wired; here we discard the interim
    // splitter layout and reposition them into Cheat Engine's exact main-window
    // arrangement (coordinates transcribed from CE's MainUnit.lfm): a scan panel
    // on top (process bar + found list on the left, scan controls on the right),
    // the cheat table below, and an Advanced Options / Table Extras bar at the
    // bottom.
    auto* scanPanel = new QWidget;
    auto* sv = new QVBoxLayout(scanPanel);
    sv->setContentsMargins(2, 2, 2, 2);
    sv->setSpacing(3);

    // Process bar (spans the width): open-process button, process name (stretches),
    // and the scan progress bar (shown only while scanning).
    openBtn->setMinimumSize(0, 0);
    openBtn->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
    openBtn->setFixedSize(32, 32);
    auto* procRow = new QHBoxLayout;
    procRow->addWidget(openBtn);
    procRow->addWidget(processLabel_, 1);
    progressBar_->setFixedWidth(220);
    procRow->addWidget(progressBar_);
    sv->addLayout(procRow);

    // "Found: N" count row.
    auto* foundRow2 = new QHBoxLayout;
    foundRow2->addWidget(foundLabel_);
    foundRow2->addStretch();
    foundRow2->addWidget(resHexCheck);
    sv->addLayout(foundRow2);

    // Main row: found-results list on the left (stretches with the window), and
    // the scan controls in a fixed-width block on the right (Cheat Engine's shape).
    auto* mainRow = new QHBoxLayout;
    auto* foundBlock = new QVBoxLayout;
    foundBlock->addWidget(resultsView_, 1);
    auto* foundBtns = new QHBoxLayout;
    foundBtns->addWidget(memViewBtn);
    foundBtns->addStretch();
    foundBtns->addWidget(addAddrBtn);
    foundBlock->addLayout(foundBtns);
    mainRow->addLayout(foundBlock, 1);

    auto* controls = new QWidget;
    controls->setFixedWidth(410);
    controls->setMinimumHeight(404);
    auto cplace = [controls](QWidget* w, int x, int y, int cw, int ch) {
        w->setMinimumSize(0, 0);
        w->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
        w->setParent(controls);
        w->setGeometry(x, y, cw, ch);
        w->show();
    };
    auto clabel = [controls](const QString& t, int x, int y, int cw, int ch) {
        auto* l = new QLabel(t, controls);
        l->setGeometry(x, y, cw, ch);
        l->show();
        return l;
    };
    // Scan buttons: First / Next / Undo.
    cplace(firstScanBtn_, 66, 0, 88, 25);
    cplace(nextScanBtn_, 160, 0, 84, 25);
    cplace(undoScanBtn_, 250, 0, 90, 25);
    // Scan value + Hex + the second ("and") value box for between-scans. The
    // field column starts at x=74 so the right-aligned Scan/Value Type labels to
    // its left have room (they were bumping into the combos).
    clabel("Scan Value", 74, 33, 120, 15);
    cplace(scanValueEdit_, 74, 48, 214, 23);
    cplace(hexCheck_, 6, 50, 60, 19);
    cplace(betweenAndLabel_, 292, 52, 25, 15);
    cplace(scanValue2Edit_, 320, 48, 74, 23);
    // Scan Type / Value Type dropdowns (labels right-aligned against the combos).
    clabel("Scan Type", 0, 82, 68, 15)->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    cplace(scanTypeCombo_, 74, 78, 200, 23);
    clabel("Value Type", 0, 107, 68, 15)->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    cplace(valueTypeCombo_, 74, 103, 200, 23);
    // Float rounding (CE puts radios here; we keep our combo + tolerance).
    cplace(floatRoundingCombo_, 74, 132, 120, 23);
    cplace(floatToleranceEdit_, 200, 132, 90, 23);
    // Memory Scan Options group (From/To, Writable/Executable, Fast Scan, etc.).
    cplace(optGroup, 66, 156, 246, 244);
    mainRow->addWidget(controls);
    sv->addLayout(mainRow, 1);

    // cplace() force-shows each widget; restore the ones that must start hidden
    // (their visibility is driven by scan state, not the layout).
    progressBar_->setVisible(false);
    betweenAndLabel_->setVisible(false);
    scanValue2Edit_->setVisible(false);

    // ── Assemble: scan panel (top) / cheat table (bottom) / actions bar ──
    auto* newCentral = new QWidget;
    auto* v = new QVBoxLayout(newCentral);
    v->setContentsMargins(2, 2, 2, 2);
    v->setSpacing(2);

    auto* vsplit = new QSplitter(Qt::Vertical);
    vsplit->addWidget(scanPanel);
    vsplit->addWidget(addressListView_);
    vsplit->setStretchFactor(0, 0);
    vsplit->setStretchFactor(1, 1);
    vsplit->setSizes({440, 220});
    v->addWidget(vsplit, 1);
    addressListView_->setMinimumHeight(90);

    auto* bottomBar = new QHBoxLayout;
    auto* advBtn = new QPushButton("Advanced Options");
    connect(advBtn, &QPushButton::clicked, this, &MainWindow::onMemoryView);
    auto* extrasBtn = new QPushButton("Table Extras");
    connect(extrasBtn, &QPushButton::clicked, this, [this, extrasBtn]() {
        QMenu m(this);
        m.addAction("Save Table...", this, &MainWindow::onSaveTable);
        m.addAction("Load Table...", this, &MainWindow::onLoadTable);
        m.exec(extrasBtn->mapToGlobal(QPoint(0, extrasBtn->height())));
    });
    bottomBar->addWidget(advBtn);
    bottomBar->addStretch();
    bottomBar->addWidget(extrasBtn);
    v->addLayout(bottomBar);

    // Discard the interim splitter tree; its roots own only the helper widgets we
    // did not reposition (the ones we use were reparented onto scanPanel above).
    delete topSplitter;
    delete central;
    setCentralWidget(newCentral);
    resize(760, 600);
}

// Probe whether we can actually read the target's memory. Under the default
// kernel.yama.ptrace_scope=1, process_vm_readv is DENIED for any process we can't
// ptrace — i.e. anything Cheat Engine didn't spawn — so scanning, memory browsing
// and debugging all silently fail (empty results, blank disassembler). Detect that
// the moment a process is opened and tell the user exactly how to fix it, instead
// of leaving them to wonder why "browse memory" shows nothing for some processes.
static void warnIfMemoryUnreadable(QWidget* parent, ce::ProcessHandle* p,
                                   pid_t pid, const QString& name) {
    if (!p) return;
    bool sawReadable = false;
    for (auto& r : p->queryRegions()) {
        if (!(r.protection & ce::MemProt::Read)) continue;
        sawReadable = true;
        uint8_t b = 0;
        auto res = p->read(r.base, &b, 1);
        if (res && *res >= 1) return;   // memory is readable — nothing to warn about
        break;                          // first readable region failed → diagnose below
    }
    if (!sawReadable) return;           // couldn't enumerate regions — don't guess

    QString scope = QStringLiteral("1");
    if (QFile f(QStringLiteral("/proc/sys/kernel/yama/ptrace_scope")); f.open(QIODevice::ReadOnly))
        scope = QString::fromUtf8(f.readAll()).trimmed();

    QMessageBox::warning(parent, QObject::tr("Process memory not readable"),
        QObject::tr(
            "Cannot read the memory of PID %1 (%2).\n\n"
            "Linux only lets a program read another process's memory if it is "
            "allowed to ptrace it. With kernel.yama.ptrace_scope = %3, that means "
            "the target must be a child of Cheat Engine, or Cheat Engine must run "
            "with elevated rights. Scanning, memory browsing and debugging this "
            "process will not work until you do ONE of:\n\n"
            "  • Grant Cheat Engine ptrace rights (persists for the binary):\n"
            "        sudo setcap cap_sys_ptrace+ep %4\n"
            "  • Run Cheat Engine as root (sudo).\n"
            "  • Lower the system policy until reboot:\n"
            "        sudo sysctl kernel.yama.ptrace_scope=0")
            .arg(pid).arg(name).arg(scope).arg(QCoreApplication::applicationFilePath()));
}

void MainWindow::onOpenProcess() {
    ProcessListDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        currentPid_ = dlg.selectedPid();
        ceserverClient_.reset();
        process_ = std::make_unique<os::LinuxProcessHandle>(currentPid_);
        processLabel_->setText(QString("PID: %1 — %2").arg(currentPid_).arg(dlg.selectedName()));
        warnIfMemoryUnreadable(this, process_.get(), currentPid_, dlg.selectedName());
        addressListModel_->setProcess(process_.get());
                    resultsModel_->setProcess(process_.get());
        firstScanBtn_->setEnabled(true);
        resultsModel_->clear();
        lastResult_.reset();
        undoResult_.reset();
        lastResultType_ = ValueType::Int32;
        undoResultType_ = ValueType::Int32;
        lastResultValueSize_ = 0;
        undoResultValueSize_ = 0;
        updateScanButtons();
    }
}

void MainWindow::onConnectCeserver() {
    QSettings settings;
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("Connect to ceserver");
    auto* form = new QFormLayout(dlg);

    auto* hostEdit = new QLineEdit(settings.value("network/ceserverHost", "127.0.0.1").toString());
    form->addRow("Host:", hostEdit);

    auto* portSpin = new QSpinBox;
    portSpin->setRange(1, 65535);
    portSpin->setValue(settings.value("network/ceserverPort", 52736).toInt());
    form->addRow("Port:", portSpin);

    auto* pidEdit = new QLineEdit;
    pidEdit->setPlaceholderText("Remote PID");
    form->addRow("PID:", pidEdit);

    auto* statusLabel = new QLabel;
    statusLabel->setWordWrap(true);
    form->addRow(statusLabel);

    auto* btnRow = new QHBoxLayout;
    auto* connectBtn = new QPushButton("Connect");
    auto* cancelBtn = new QPushButton("Cancel");
    btnRow->addStretch();
    btnRow->addWidget(connectBtn);
    btnRow->addWidget(cancelBtn);
    form->addRow(btnRow);

    connect(cancelBtn, &QPushButton::clicked, dlg, &QDialog::reject);
    connect(connectBtn, &QPushButton::clicked, this, [&]() {
        bool ok = false;
        pid_t pid = pidEdit->text().toInt(&ok);
        if (!ok || pid <= 0) {
            statusLabel->setText("Enter a valid remote PID.");
            return;
        }
        auto client = std::make_unique<ce::os::CEServerClient>();
        std::string err;
        if (!client->connectTcp(hostEdit->text().toStdString(),
                                static_cast<uint16_t>(portSpin->value()), err)) {
            statusLabel->setText(QString("Connect failed: %1").arg(QString::fromStdString(err)));
            return;
        }
        auto version = client->getVersion();
        if (!version) {
            statusLabel->setText(QString("Handshake failed: %1").arg(QString::fromStdString(version.error())));
            return;
        }
        auto handle = ce::os::RemoteProcessHandle::open(*client, pid);
        if (!handle) {
            statusLabel->setText(QString("Server refused PID %1").arg((int)pid));
            return;
        }

        ceserverClient_ = std::move(client);
        process_ = std::move(handle);
        currentPid_ = pid;
        processLabel_->setText(QString("REMOTE PID: %1 @ %2:%3 (%4)")
            .arg((int)pid).arg(hostEdit->text()).arg(portSpin->value())
            .arg(QString::fromStdString(version->versionString)));
        addressListModel_->setProcess(process_.get());
                    resultsModel_->setProcess(process_.get());
        firstScanBtn_->setEnabled(true);
        resultsModel_->clear();
        lastResult_.reset();
        undoResult_.reset();
        lastResultType_ = ValueType::Int32;
        undoResultType_ = ValueType::Int32;
        lastResultValueSize_ = 0;
        undoResultValueSize_ = 0;
        updateScanButtons();

        settings.setValue("network/ceserverHost", hostEdit->text());
        settings.setValue("network/ceserverPort", portSpin->value());
        dlg->accept();
    });

    dlg->exec();
    dlg->deleteLater();
}

static ScanCompare mapScanType(int index) {
    switch (index) {
        case 0: return ScanCompare::Exact;
        case 1: return ScanCompare::Greater;
        case 2: return ScanCompare::Less;
        case 3: return ScanCompare::Between;
        case 4: return ScanCompare::Unknown;
        case 5: return ScanCompare::Increased;
        case 6: return ScanCompare::Decreased;
        case 7: return ScanCompare::Changed;
        case 8: return ScanCompare::Unchanged;
        case 9: return ScanCompare::SameAsFirst;
        case 10: return ScanCompare::IncreasedBy;
        case 11: return ScanCompare::DecreasedBy;
        default: return ScanCompare::Exact;
    }
}

static ValueType mapValueType(int index) {
    switch (index) {
        case 0: return ValueType::Byte;
        case 1: return ValueType::Int16;
        case 2: return ValueType::Int32;
        case 3: return ValueType::Int64;
        case 4: return ValueType::Float;
        case 5: return ValueType::Double;
        case 6: return ValueType::String;
        case 7: return ValueType::UnicodeString;
        case 8: return ValueType::ByteArray;
        case 9: return ValueType::Binary;
        case 10: return ValueType::All;
        case 11: return ValueType::Pointer;
        case 12: return ValueType::Grouped;
        case 13: return ValueType::Custom;
        default: return ValueType::Int32;
    }
}

static void applyFloatOptions(ScanConfig& config, QComboBox* roundingCombo,
                              QLineEdit* toleranceEdit, const QString& valueText) {
    if (config.valueType != ValueType::Float &&
        config.valueType != ValueType::Double) {
        return;
    }
    config.roundingType = roundingCombo->currentIndex();
    // parseUserDouble accepts ',' or '.' (Turkish comma-decimal locale).
    double tolerance = parseUserDouble(toleranceEdit->text());
    if (tolerance > 0.0)
        config.floatTolerance = tolerance;

    // Count the decimal places the user typed (either '.' or ',' separator) so
    // "Rounded" matches at that precision (CE's Rounded-default). No separator = 0.
    QString t = valueText.trimmed();
    int sep = t.indexOf('.');
    if (sep < 0) sep = t.indexOf(',');
    int decimals = 0;
    if (sep >= 0)
        for (int i = sep + 1; i < t.size() && t[i].isDigit(); ++i) ++decimals;
    config.floatDecimals = decimals;
}

static size_t resultValueSizeForConfig(const ScanConfig& config) {
    switch (config.valueType) {
        case ValueType::Byte:
            return 1;
        case ValueType::Int16:
            return 2;
        case ValueType::Int32:
        case ValueType::Float:
            return 4;
        case ValueType::Int64:
        case ValueType::Double:
        case ValueType::Pointer:
            return 8;
        case ValueType::String:
            return std::max<size_t>(1, config.stringValueSize());
        case ValueType::UnicodeString:
            return std::max<size_t>(2, config.stringValue.size() * 2);
        case ValueType::ByteArray:
        case ValueType::Binary:
            return std::max<size_t>(1, config.byteArray.size());
        case ValueType::Grouped:
            return std::max<size_t>(1, config.groupedValueSize());
        case ValueType::Custom:
            return std::max<size_t>(1, config.customValueSize);
        case ValueType::All:
        default:
            return 8;
    }
}


std::unique_ptr<ScanResult> MainWindow::runScanWithProgress(
    const std::function<ScanResult()>& scanFn) {
    // Pause the live-value refresh so it doesn't fight the scan for the target,
    // and show the progress bar.
    if (valueRefreshTimer_) valueRefreshTimer_->stop();
    progressBar_->setValue(0);
    progressBar_->setVisible(true);

    std::unique_ptr<ScanResult> result;
    std::exception_ptr err;
    std::atomic<bool> done{false};
    std::thread worker([&] {
        try { result = std::make_unique<ScanResult>(scanFn()); }
        catch (...) { err = std::current_exception(); }
        done.store(true, std::memory_order_release);
    });

    // Drive the bar on the UI thread. ExcludeUserInputEvents keeps paints flowing
    // (so the bar animates) while blocking clicks (no re-entrant scan).
    while (!done.load(std::memory_order_acquire)) {
        progressBar_->setValue((int)(scanner_.progress() * 100.0f));
        QApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 25);
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    worker.join();

    progressBar_->setValue(100);
    progressBar_->setVisible(false);
    if (valueRefreshTimer_)
        valueRefreshTimer_->start(QSettings().value("memview/refreshMs", 500).toInt());

    if (err) std::rethrow_exception(err);
    return result;
}

void MainWindow::onFirstScan() {
    if (!process_) return;

    ScanConfig config;
    config.valueType = mapValueType(valueTypeCombo_->currentIndex());
    config.compareType = mapScanType(scanTypeCombo_->currentIndex());
    // Fast Scan pins the scan to `alignment`-aligned addresses (much faster);
    // unchecking it scans every byte offset so misaligned values are found too.
    // Without this the Fast Scan checkbox did nothing.
    config.alignment = fastScanCheck_->isChecked() ? alignEdit_->text().toInt() : 1;
    if (config.alignment < 1) config.alignment = 1;
    auto fromExpr = parseAddressExpr(fromAddressEdit_->text());
    auto toExpr = parseAddressExpr(toAddressEdit_->text());
    if (!fromExpr || !toExpr) {
        QMessageBox::warning(this, "Scan range",
            "From/To must be a hex address, symbol, or module+offset (e.g. target2, target2+0x5000).");
        return;
    }
    config.startAddress = *fromExpr;
    config.stopAddress = *toExpr;
    if (config.startAddress > config.stopAddress) {
        QMessageBox::warning(this, "Scan range",
            "The From address must not be greater than the To address.");
        return;
    }
    config.scanWritableOnly = writableCheck_->isChecked();
    config.scanExecutableOnly = executableCheck_->isChecked();

    auto text = scanValueEdit_->text();
    int intBase = (hexCheck_ && hexCheck_->isChecked()) ? 16 : 10;
    if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
        config.stringValue = text.toStdString();
        if (config.valueType == ValueType::String)
            config.stringEncoding = stringEncodingCombo_->currentText().toStdString();
            config.caseSensitive = !caseSensitiveCheck_ || caseSensitiveCheck_->isChecked();
        config.alignment = 1;
    } else if (config.valueType == ValueType::ByteArray) {
        // parseAOB returns false for an empty pattern OR a token that isn't hex
        // or a wildcard (a typo like "8Z") — reject both instead of scanning wrong.
        if (!config.parseAOB(text.toStdString())) {
            QMessageBox::warning(this, "Array of byte scan", "Enter a valid AOB pattern (e.g. \"7F 45 ?? 46\").");
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Binary) {
        config.parseBinary(text.toStdString());
        // parseBinary returns void; an empty pattern means nothing was parsed.
        if (config.byteArray.empty()) {
            QMessageBox::warning(this, "Binary scan", "Enter a valid binary pattern (e.g. \"0110??01\").");
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Grouped) {
        std::string error;
        if (!config.parseGrouped(text.toStdString(), &error)) {
            QMessageBox::warning(this, "Grouped scan", QString::fromStdString(error));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Custom) {
        config.customFormula = text.toStdString();
        config.customValueSize = std::max<size_t>(1, static_cast<size_t>(config.alignment));
        config.alignment = 1;
    } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
        config.floatValue = parseUserDouble(text);
    } else if (config.valueType == ValueType::Pointer) {
        config.intValue = static_cast<int64_t>(text.toULongLong(nullptr, 0));
    } else if (config.valueType == ValueType::All) {
        config.intValue = text.toLongLong(nullptr, intBase);
        config.floatValue = parseUserDouble(text);
    } else {
        config.intValue = text.toLongLong(nullptr, intBase);
    }
    // "Value between..." needs a second (upper) bound from its own box.
    if (config.compareType == ScanCompare::Between) {
        auto text2 = scanValue2Edit_->text();
        if (config.valueType == ValueType::Float || config.valueType == ValueType::Double)
            config.floatValue2 = parseUserDouble(text2);
        else
            config.intValue2 = text2.toLongLong(nullptr, intBase);
    }
    applyFloatOptions(config, floatRoundingCombo_, floatToleranceEdit_, text);
    size_t resultValueSize = resultValueSizeForConfig(config);

    firstScanBtn_->setEnabled(false);
    // Scan on a worker thread with a live progress bar (keeps the UI responsive).
    std::unique_ptr<ScanResult> result;
    try {
        result = runScanWithProgress([&] { return scanner_.firstScan(*process_, config); });
    } catch (const std::exception& e) {
        // A huge target (e.g. an emulator mapping many GB of guest RAM) can
        // exhaust memory during the scan/merge. Report it instead of letting
        // the exception escape the Qt event handler and std::terminate.
        firstScanBtn_->setEnabled(true);
        QMessageBox::warning(this, "Scan failed",
            QString("The scan could not complete: %1\n\n"
                    "Try narrowing the From/To range, enabling Fast Scan, or "
                    "choosing a more specific value type.").arg(e.what()));
        return;
    }
    firstScanBtn_->setEnabled(true);

    foundLabel_->setText(QString("Found: %1").arg(result->count()));
    if (result->hasWriteError())
        QMessageBox::warning(this, "Scan results truncated",
            "A scan-result file could not be fully written (the disk may be full). "
            "Some results are unreliable; free space and scan again.");
    resultsModel_->setResult(result.get(), config.valueType, resultValueSize);

    undoResult_ = std::move(lastResult_);
    undoResultType_ = lastResultType_;
    undoResultValueSize_ = lastResultValueSize_;
    lastResult_ = std::move(result);
    lastResultType_ = config.valueType;
    lastResultValueSize_ = resultValueSize;
    updateScanButtons();
}

void MainWindow::onNextScan() {
    if (!process_ || !lastResult_) return;

    ScanConfig config;
    // A Next Scan MUST reuse the first scan's value type. The previous results
    // are stored at that type's size, so honoring a mid-session combo change would
    // reinterpret them at the wrong stride and corrupt the narrowing. (CE locks
    // the type combo after the first scan; we simply pin it here.)
    config.valueType = lastResultType_;
    config.compareType = mapScanType(scanTypeCombo_->currentIndex());
    config.alignment = alignEdit_->text().toInt();

    auto text = scanValueEdit_->text();
    int intBase = (hexCheck_ && hexCheck_->isChecked()) ? 16 : 10;
    if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
        config.stringValue = text.toStdString();
        if (config.valueType == ValueType::String)
            config.stringEncoding = stringEncodingCombo_->currentText().toStdString();
            config.caseSensitive = !caseSensitiveCheck_ || caseSensitiveCheck_->isChecked();
        config.alignment = 1;
    } else if (config.valueType == ValueType::ByteArray) {
        // parseAOB returns false for an empty pattern OR a token that isn't hex
        // or a wildcard (a typo like "8Z") — reject both instead of scanning wrong.
        if (!config.parseAOB(text.toStdString())) {
            QMessageBox::warning(this, "Array of byte scan", "Enter a valid AOB pattern (e.g. \"7F 45 ?? 46\").");
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Binary) {
        config.parseBinary(text.toStdString());
        // parseBinary returns void; an empty pattern means nothing was parsed.
        if (config.byteArray.empty()) {
            QMessageBox::warning(this, "Binary scan", "Enter a valid binary pattern (e.g. \"0110??01\").");
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Grouped) {
        std::string error;
        if (!config.parseGrouped(text.toStdString(), &error)) {
            QMessageBox::warning(this, "Grouped scan", QString::fromStdString(error));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Custom) {
        config.customFormula = text.toStdString();
        config.customValueSize = std::max<size_t>(1, static_cast<size_t>(config.alignment));
        config.alignment = 1;
    } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
        config.floatValue = parseUserDouble(text);
    } else if (config.valueType == ValueType::Pointer) {
        config.intValue = static_cast<int64_t>(text.toULongLong(nullptr, 0));
    } else if (config.valueType == ValueType::All) {
        config.intValue = text.toLongLong(nullptr, intBase);
        config.floatValue = parseUserDouble(text);
    } else {
        config.intValue = text.toLongLong(nullptr, intBase);
    }
    if (config.compareType == ScanCompare::Between) {
        auto text2 = scanValue2Edit_->text();
        if (config.valueType == ValueType::Float || config.valueType == ValueType::Double)
            config.floatValue2 = parseUserDouble(text2);
        else
            config.intValue2 = text2.toLongLong(nullptr, intBase);
    }
    applyFloatOptions(config, floatRoundingCombo_, floatToleranceEdit_, text);

    if (percentCheck_->isChecked()) {
        config.percentageScan = true;
        // parseUserDouble accepts ',' or '.' (Turkish comma-decimal locale).
        config.percentageValue = parseUserDouble(percentValueEdit_->text());
        auto percent2Text = percentValue2Edit_->text().trimmed();
        config.percentageValue2 = percent2Text.isEmpty()
            ? config.percentageValue
            : parseUserDouble(percent2Text);
    }
    size_t resultValueSize = resultValueSizeForConfig(config);

    nextScanBtn_->setEnabled(false);
    // Scan on a worker thread with a live progress bar (see onFirstScan).
    std::unique_ptr<ScanResult> result;
    try {
        result = runScanWithProgress(
            [&] { return scanner_.nextScan(*process_, config, *lastResult_); });
    } catch (const std::exception& e) {
        // Guard the same way as onFirstScan: a bad_alloc (or a rejected
        // next-scan, e.g. a changed value-size stride) must not terminate.
        nextScanBtn_->setEnabled(true);
        QMessageBox::warning(this, "Scan failed",
            QString("The next scan could not complete: %1").arg(e.what()));
        return;
    }
    nextScanBtn_->setEnabled(true);

    foundLabel_->setText(QString("Found: %1").arg(result->count()));
    if (result->hasWriteError())
        QMessageBox::warning(this, "Scan results truncated",
            "A scan-result file could not be fully written (the disk may be full). "
            "Some results are unreliable; free space and scan again.");
    resultsModel_->setResult(result.get(), config.valueType, resultValueSize);

    undoResult_ = std::move(lastResult_);
    undoResultType_ = lastResultType_;
    undoResultValueSize_ = lastResultValueSize_;
    lastResult_ = std::move(result);
    lastResultType_ = config.valueType;
    lastResultValueSize_ = resultValueSize;
    updateScanButtons();
}

void MainWindow::onUndoScan() {
    if (!undoResult_) return;
    lastResult_ = std::move(undoResult_);
    lastResultType_ = undoResultType_;
    lastResultValueSize_ = undoResultValueSize_;
    undoResultType_ = ValueType::Int32;
    undoResultValueSize_ = 0;
    resultsModel_->setResult(lastResult_.get(), lastResultType_, lastResultValueSize_);
    foundLabel_->setText(QString("Found: %1").arg(lastResult_->count()));
    updateScanButtons();
}

void MainWindow::onResultDoubleClicked(const QModelIndex& index) {
    if (!lastResult_) return;
    auto addr = resultsModel_->addressAt(index.row());
    addressListModel_->addEntry(addr, lastResultType_);
}

void MainWindow::onDeleteAddresses() {
    auto selected = addressListView_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;
    QList<int> rows;
    for (auto& idx : selected) rows.append(idx.row());
    addressListModel_->removeEntries(rows);
}

void MainWindow::onCopyAddresses() {
    auto selected = addressListView_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;

    std::sort(selected.begin(), selected.end(), [](const QModelIndex& a, const QModelIndex& b) {
        return a.row() < b.row();
    });

    auto allEntries = addressListModel_->toJson();
    QJsonArray copied;
    for (const auto& idx : selected) {
        if (idx.row() >= 0 && idx.row() < allEntries.size())
            copied.append(allEntries[idx.row()].toObject());
    }

    QApplication::clipboard()->setText(
        QString::fromUtf8(QJsonDocument(copied).toJson(QJsonDocument::Compact)));
}

void MainWindow::onPasteAddresses() {
    auto text = QApplication::clipboard()->text().toUtf8();
    QJsonParseError error{};
    auto doc = QJsonDocument::fromJson(text, &error);
    if (error.error != QJsonParseError::NoError)
        return;

    QJsonArray pasted;
    if (doc.isArray()) {
        pasted = doc.array();
    } else if (doc.isObject()) {
        pasted = doc.object()["entries"].toArray();
    }
    if (pasted.isEmpty())
        return;

    auto entries = addressListModel_->toJson();
    for (auto value : pasted) {
        auto obj = value.toObject();
        if (obj.isEmpty())
            continue;
        obj["active"] = false;
        // Drop the copied id so fromJson allocates a fresh unique one — otherwise
        // pasting into a table that already holds that id yields duplicate ids,
        // which make getMemoryRecordByID / byId / Lua references ambiguous. (The
        // row/indent-based hierarchy is unaffected — it doesn't key on id.)
        obj.remove("id");
        entries.append(obj);
    }
    addressListModel_->fromJson(entries);
}

void MainWindow::onFreezeTimer() {
    if (process_)
        addressListModel_->freezeWrite(process_.get());
}

MainWindow::~MainWindow() {
    // Drop Lua GUI callback bindings before luaEngine_ (and its lua_State) is
    // destroyed with this window's members, so a stray Qt timer/widget callback
    // can't fire into a freed lua_State.
    ce::shutdownLuaGuiBindings();
}

// Build a ce::CheatTable from the current address list (shared by Save Table and
// Create Trainer). Mirrors the JSON field mapping the .CT saver expects.
void MainWindow::wireBrowserAnnotations(MemoryBrowser* browser) {
    // Seed the browser with the stored comments and have it push changes back to
    // the MainWindow-owned store (which is serialized with the cheat table).
    browser->setAnnotationStore(disasmAnnotations_,
        [this](std::vector<ce::DisassemblerComment> v) { disasmAnnotations_ = std::move(v); });
    // "Auto Assemble > Create code/AOB injection here" opens a script editor
    // pre-filled with the generated template.
    browser->setAutoAssembleOpener([this](const QString& script) {
        auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
        editor->setAttribute(Qt::WA_DeleteOnClose);
        editor->setAddToTable([this](const QString& d, const QString& s) {
            addressListModel_->addScriptEntry(d, s);
        });
        editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
        editor->setScript(script.toStdString());
        editor->show();
    });
}

void MainWindow::editScriptEntry(int row) {
    const auto& entries = addressListModel_->entries();
    if (row < 0 || row >= (int)entries.size() || entries[row].autoAsmScript.isEmpty())
        return;
    int id = entries[row].id;
    QString desc = entries[row].description;
    QString script = entries[row].autoAsmScript;

    auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
    editor->setAttribute(Qt::WA_DeleteOnClose);
    editor->setWindowTitle("Auto Assembler — " + desc);
    editor->setDefaultDescription(desc);
    editor->setTableButtonText("Save to Table");
    editor->setScript(script.toStdString());
    // Save back to THIS entry (found by stable id, so it survives reordering)
    // instead of appending a duplicate row.
    editor->setAddToTable([this, id](const QString& d, const QString& s) {
        addressListModel_->updateScriptEntryById(id, d, s);
    });
    editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
    editor->show();
}

ce::CheatTable MainWindow::buildCheatTable() const {
    ce::CheatTable table;
    table.gameName = processLabel_->text().toStdString();
    auto json = addressListModel_->toJson();
    int saveIdx = 0;
    for (auto val : json) {
        auto obj = val.toObject();
        ce::CheatEntry e;
        // toJson emits "parent" as the parent row's index; use the row index as
        // the id too so the saver links children to parents to nest groups.
        e.id = saveIdx++;
        e.description = obj["description"].toString().toStdString();
        e.address = obj["address"].toString().toULongLong(nullptr, 16);
        auto exprStr = obj["addressExpr"].toString();
        if (!exprStr.isEmpty()) e.addressString = exprStr.toStdString();
        auto typeStr = obj["type"].toString().toStdString();
        if (typeStr == "byte") e.type = ce::ValueType::Byte;
        else if (typeStr == "i16") e.type = ce::ValueType::Int16;
        else if (typeStr == "i32") e.type = ce::ValueType::Int32;
        else if (typeStr == "i64") e.type = ce::ValueType::Int64;
        else if (typeStr == "pointer") e.type = ce::ValueType::Pointer;
        else if (typeStr == "float") e.type = ce::ValueType::Float;
        else if (typeStr == "double") e.type = ce::ValueType::Double;
        else e.type = ce::ValueType::Int32;
        e.value = obj["value"].toString().toStdString();
        e.active = obj["active"].toBool();
        e.showAsHex = obj["showAsHex"].toBool();
        e.freezeMode = (ce::FreezeMode)obj["freezeMode"].toInt();
        e.autoAsmScript = obj["asm"].toString().toStdString();
        e.color = obj["color"].toString().toStdString();
        e.dropdownList = obj["dropdown"].toString().toStdString();
        e.hotkeyKeys = obj["hotkeys"].toString().toStdString();
        e.increaseHotkeyKeys = obj["increaseHotkey"].toString().toStdString();
        e.setValueHotkeyKeys = obj["setValueHotkey"].toString().toStdString();
        e.setValueHotkeyValue = obj["setValueHotkeyValue"].toString().toStdString();
        e.decreaseHotkeyKeys = obj["decreaseHotkey"].toString().toStdString();
        e.hotkeyStep = obj["hotkeyStep"].toString().toStdString();
        e.isGroup = obj["group"].toBool();
        e.parentId = obj["parent"].toInt(-1);
        table.entries.push_back(e);
    }
    table.disassemblerComments = disasmAnnotations_;
    return table;
}

void MainWindow::onCreateTrainer() {
    auto path = QFileDialog::getSaveFileName(this, "Create Trainer (C source)",
        "trainer.c", "C source (*.c);;All Files (*)");
    if (path.isEmpty()) return;
    try {
        ce::CheatTable table = buildCheatTable();
        ce::TrainerGenerator gen;
        std::string src = gen.generateSource(table);
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(this, "Create Trainer", "Could not write the trainer source file.");
            return;
        }
        f.write(src.data(), (qint64)src.size());
        statusBar()->showMessage(
            QString("Trainer C source written to %1 (compile with gcc)").arg(path), 6000);
    } catch (const std::exception& ex) {
        QMessageBox::critical(this, "Create Trainer",
            QString("Trainer generation failed:\n%1").arg(ex.what()));
    }
}

std::optional<uintptr_t> MainWindow::parseAddressExpr(const QString& text) {
    QString t = text.trimmed();
    if (t.isEmpty()) return std::nullopt;
    // Lazily load module/symbol info so "target2+0x100" and symbols resolve.
    if (process_ && luaResolver_.count() == 0) luaResolver_.loadProcess(*process_);
    ce::ExpressionParser parser(process_.get(), &luaResolver_);
    if (auto a = parser.parse(t.toStdString()); a) return a;
    bool ok = false;
    uintptr_t v = t.toULongLong(&ok, 16);
    return ok ? std::optional<uintptr_t>(v) : std::nullopt;
}

void MainWindow::rebuildValueHotkeys() {
    for (auto* shortcut : valueHotkeyShortcuts_)
        shortcut->deleteLater();
    valueHotkeyShortcuts_.clear();
    if (globalHotkeys_) globalHotkeys_->clear();
    hotkeyActions_.clear();
    int nextId = 1;

    const auto& entries = addressListModel_->entries();
    for (int row = 0; row < (int)entries.size(); ++row) {
        const auto& entry = entries[row];
        if (entry.isGroup)
            continue;

        bool ok = false;
        double step = entry.hotkeyStep.toDouble(&ok);
        if (!ok || step == 0.0)
            step = 1.0;

        // Register a hotkey system-wide (X11) so it fires while the game is
        // focused; if that fails (non-X11 / unmappable key), fall back to a
        // Qt::ApplicationShortcut that only works when cheatengine is focused.
        auto addHotkey = [&](const QString& keys, std::function<void()> action) {
            QKeySequence sequence(keys);
            if (sequence.isEmpty())
                return;
            int id = nextId++;
            if (globalHotkeys_ && globalHotkeys_->registerHotkey(id, sequence)) {
                hotkeyActions_.insert(id, std::move(action));
                return;
            }
            auto* shortcut = new QShortcut(sequence, this);
            shortcut->setContext(Qt::ApplicationShortcut);
            connect(shortcut, &QShortcut::activated, this, action);
            valueHotkeyShortcuts_.push_back(shortcut);
        };

        // Toggle-active hotkey (previously configured + saved but never wired,
        // so it did nothing): flip the entry's active state.
        addHotkey(entry.hotkeyKeys, [this, row]() {
            addressListModel_->toggleActive(row);
        });
        addHotkey(entry.increaseHotkeyKeys, [this, row, step]() {
            if (!addressListModel_->adjustEntryValue(row, step * 1.0))
                QApplication::beep();
        });
        addHotkey(entry.decreaseHotkeyKeys, [this, row, step]() {
            if (!addressListModel_->adjustEntryValue(row, step * -1.0))
                QApplication::beep();
        });
        // Set-value hotkey: write a fixed value (e.g. bind a key to "health = 999").
        addHotkey(entry.setValueHotkeyKeys, [this, row, val = entry.setValueHotkeyValue]() {
            addressListModel_->setEntryValueTo(row, val);
        });
    }
}

void MainWindow::onSaveTable() {
    auto path = QFileDialog::getSaveFileName(this, "Save Cheat Table", "",
        "Cheat Tables (*.ct);;JSON Tables (*.json);;All Files (*)");
    if (path.isEmpty()) return;

  try {
    if (path.endsWith(".ct")) {
        // Save as CE-compatible XML .CT format
        CheatTable table = buildCheatTable();
        table.save(path.toStdString());
    } else {
        // Save as JSON
        QJsonObject root;
        root["process"] = processLabel_->text();
        root["entries"] = addressListModel_->toJson();
        QJsonArray dc;
        for (const auto& c : disasmAnnotations_) {
            QJsonObject o;
            o["address"] = QString::fromStdString(c.address);
            if (!c.comment.empty()) o["comment"] = QString::fromStdString(c.comment);
            if (!c.label.empty())   o["label"]   = QString::fromStdString(c.label);
            dc.append(o);
        }
        root["disassemblerComments"] = dc;
        QFile f(path);
        if (f.open(QIODevice::WriteOnly))
            f.write(QJsonDocument(root).toJson());
    }
  } catch (const std::exception& ex) {
    // A serialize/save path may throw; never let it escape the slot into
    // std::terminate.
    QMessageBox::critical(this, "Save Cheat Table",
        QString("Failed to save table:\n%1").arg(ex.what()));
  } catch (...) {
    QMessageBox::critical(this, "Save Cheat Table", "Failed to save table (unknown error).");
  }
}

void MainWindow::onLoadTable() {
    auto path = QFileDialog::getOpenFileName(this, "Load Cheat Table", "",
        "Cheat Tables (*.ct);;JSON Tables (*.json);;All Files (*)");
    if (path.isEmpty()) return;
    loadTableFromPath(path);
}

// Load a cheat table from a path (no dialog). Shared by onLoadTable and the
// command-line "cheatengine <table.ct>" entry point.
void MainWindow::loadTableFromPath(const QString& path) {
    // Show the loaded table's file name in the title bar, like CE.
    setWindowTitle(QString("Cheat Engine - %1").arg(QFileInfo(path).fileName()));
  try {
    if (path.endsWith(".ct")) {
        // Load CE XML .CT format
        CheatTable table;
        if (!table.load(path.toStdString())) return;
        QJsonArray arr;
        // Compute each entry's nesting level from the parentId tree (entries are in
        // document order, parents before children) so imported groups indent in the
        // address list, which tracks hierarchy by indent depth.
        std::unordered_map<int, int> indentById;
        for (auto& e : table.entries) {
            QJsonObject obj;
            int indent = 0;
            if (e.parentId != -1) {
                auto it = indentById.find(e.parentId);
                if (it != indentById.end()) indent = it->second + 1;
            }
            indentById[e.id] = indent;
            obj["indent"] = indent;
            obj["description"] = QString::fromStdString(e.description);
            obj["address"] = QString("0x%1").arg(e.address, 0, 16);
            // Preserve CE symbolic bases ("game.exe+1C") and pointer offset chains
            // as an address expression that is re-evaluated each refresh.
            if (!e.addressString.empty() || !e.offsets.empty()) {
                std::string base = e.addressString.empty()
                    ? "0x" + QString::number(e.address, 16).toStdString()
                    : e.addressString;
                obj["addressExpr"] = QString::fromStdString(ce::buildPointerExpression(base, e.offsets));
            }
            obj["type"] = QString::number((int)e.type);
            obj["value"] = QString::fromStdString(e.value);
            obj["active"] = e.active;
            obj["showAsHex"] = e.showAsHex;
            obj["freezeMode"] = (int)e.freezeMode;
            obj["asm"] = QString::fromStdString(e.autoAsmScript);
            obj["color"] = QString::fromStdString(e.color);
            obj["dropdown"] = QString::fromStdString(e.dropdownList);
            obj["hotkeys"] = QString::fromStdString(e.hotkeyKeys);
            obj["increaseHotkey"] = QString::fromStdString(e.increaseHotkeyKeys);
            obj["setValueHotkey"] = QString::fromStdString(e.setValueHotkeyKeys);
            obj["setValueHotkeyValue"] = QString::fromStdString(e.setValueHotkeyValue);
            obj["decreaseHotkey"] = QString::fromStdString(e.decreaseHotkeyKeys);
            obj["hotkeyStep"] = QString::fromStdString(e.hotkeyStep);
            obj["group"] = e.isGroup;
            obj["parent"] = e.parentId;
            arr.append(obj);
        }
        loadAddressEntries(arr);
        // Run the table-level Lua script (CE's <LuaScript>) after the records are
        // loaded, so it can define trainer functions/hooks and reference records.
        // Previously this was parsed but never executed, silently breaking any
        // table that relied on its framework code.
        if (!table.luaScript.empty()) {
            luaEngine_.setProcess(process_.get());
            luaEngine_.setAddressList(addressListModel_);
            auto res = luaEngine_.evalToString(table.luaScript);
            if (!res.has_value())
                statusBar()->showMessage(
                    QString("Table Lua error: %1").arg(QString::fromStdString(res.error())), 8000);
        }
        disasmAnnotations_ = table.disassemblerComments;
    } else {
        // Load JSON
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return;
        auto doc = QJsonDocument::fromJson(f.readAll());
        if (!doc.isObject()) return;
        loadAddressEntries(doc.object()["entries"].toArray());
        // Persistent disassembler comments (module-relative address expressions).
        disasmAnnotations_.clear();
        for (const auto& v : doc.object()["disassemblerComments"].toArray()) {
            auto o = v.toObject();
            ce::DisassemblerComment c;
            c.address = o["address"].toString().toStdString();
            c.comment = o["comment"].toString().toStdString();
            c.label   = o["label"].toString().toStdString();
            if (!c.address.empty()) disasmAnnotations_.push_back(std::move(c));
        }
    }
  } catch (const std::exception& ex) {
    // A parse/load path (e.g. ct_file) may throw; never let it escape the slot
    // into std::terminate.
    QMessageBox::critical(this, "Load Cheat Table",
        QString("Failed to load table:\n%1").arg(ex.what()));
  } catch (...) {
    QMessageBox::critical(this, "Load Cheat Table", "Failed to load table (unknown error).");
  }
}

void MainWindow::loadAddressEntries(const QJsonArray& entries) {
    QJsonArray normalized = entries;
    QStringList failures;
    bool skippedForMissingProcess = false;

    for (int i = 0; i < normalized.size(); ++i) {
        auto obj = normalized[i].toObject();
        auto script = obj["asm"].toString();
        if (!obj["active"].toBool() || script.isEmpty())
            continue;

        if (!process_) {
            obj["active"] = false;
            skippedForMissingProcess = true;
            normalized.replace(i, obj);
            continue;
        }

        auto result = autoAsm_.execute(*process_, script.toStdString());
        if (!result.success) {
            obj["active"] = false;
            normalized.replace(i, obj);
            auto desc = obj["description"].toString("Unnamed entry");
            failures << QString("%1: %2").arg(desc, QString::fromStdString(result.error));
        }
    }

    addressListModel_->fromJson(normalized);

    if (skippedForMissingProcess) {
        QMessageBox::warning(this, "Process required",
            "Some active auto-assembler records were loaded inactive because no process is open.");
    }
    if (!failures.isEmpty()) {
        QMessageBox::warning(this, "Auto-assembler activation failed",
            failures.join('\n'));
    }
}

void MainWindow::startCodeFinder(int row, bool writesOnly) {
    if (!process_) return;
    const auto& entries = addressListModel_->entries();
    if (row < 0 || row >= (int)entries.size()) return;
    const auto& entry = entries[row];
    if (entry.isGroup) return;
    startCodeFinderForAddress(entry.address, writesOnly);
}

void MainWindow::stopCodeFindersForInjection() {
    // A target can have only one ptrace tracer. If a "find what accesses/writes"
    // monitor is running, it holds that trace, so an injection's attach fails
    // (surfacing as a mmap "Cannot allocate memory"). Stop the monitors, which
    // detach, freeing the target for the injection.
    for (auto& f : codeFinders_)
        if (f) f->stop();
}

std::unique_ptr<Debugger> MainWindow::createDebuggerForCurrentProcess() {
    if (!process_) return nullptr;
    if (auto* remote = dynamic_cast<os::RemoteProcessHandle*>(process_.get())) {
        if (!ceserverClient_) return nullptr;
        return std::make_unique<os::RemoteDebugger>(*ceserverClient_, remote->serverHandle());
    }
    return std::make_unique<os::LinuxDebugger>();
}

void MainWindow::startCodeFinderForAddress(uintptr_t addr, bool writesOnly) {
    if (!process_) return;

    auto debugger = createDebuggerForCurrentProcess();
    if (!debugger) return;
    auto finder = std::make_unique<CodeFinder>();
    if (!finder->start(*process_, *debugger, addr, writesOnly)) {
        QMessageBox::warning(this, "Code finder unavailable",
            "Could not start hardware watchpoint monitoring for this address.");
        return;
    }

    auto* finderPtr = finder.get();
    codeFinderDebuggers_.push_back(std::move(debugger));
    codeFinders_.push_back(std::move(finder));

    auto title = writesOnly ? "Find what writes" : "Find what accesses";
    auto* window = new CodeFinderWindow(finderPtr,
        QString("%1 0x%2").arg(title).arg(addr, 0, 16), this);
    window->setAttribute(Qt::WA_DeleteOnClose);
    // Let the user save the found code locations into the address list.
    window->setAddToList([this](uintptr_t a, const QString& desc) {
        addressListModel_->addEntry(a, ce::ValueType::Int32,
            desc.isEmpty() ? QString("code 0x%1").arg(a, 0, 16) : desc);
    });
    window->show();
}

void MainWindow::onMemoryView() {
    if (!process_) return;
    auto* browser = new MemoryBrowser(process_.get(), this);
    browser->setAttribute(Qt::WA_DeleteOnClose);
    wireBrowserAnnotations(browser);

    // Hook breakpoint actions through MainWindow's BpManager.
    browser->setBreakpointSetter([this](uintptr_t addr, bool hardware) {
        Breakpoint bp;
        bp.address = addr;
        bp.type = BpType::Execute;
        bp.method = hardware ? BpMethod::Hardware : BpMethod::Software;
        bp.size = 1;
        bp.enabled = true;
        bp.description = QString("BP @ 0x%1").arg(addr, 0, 16).toStdString();
        bpManager_.add(bp);
    });
    browser->setBreakpointRemover([this](uintptr_t addr) {
        for (const auto& bp : bpManager_.list()) {
            if (bp.address == addr) bpManager_.remove(bp.id);
        }
    });
    browser->setBreakpointQuery([this]() {
        std::set<uintptr_t> out;
        for (const auto& bp : bpManager_.list())
            if (bp.enabled) out.insert(bp.address);
        return out;
    });
    browser->setCodeFinderLauncher([this](uintptr_t addr, bool writesOnly) {
        startCodeFinderForAddress(addr, writesOnly);
    });

    // If a scan result is selected, open the browser at that address.
    if (lastResult_) {
        auto sel = resultsView_->selectionModel()->selectedRows();
        if (!sel.isEmpty())
            browser->gotoAddress(resultsModel_->addressAt(sel.first().row()));
    }

    browser->show();
}

void MainWindow::updateScanButtons() {
    bool hasProcess = (process_ != nullptr);
    bool hasResults = (lastResult_ != nullptr && lastResult_->count() > 0);
    firstScanBtn_->setEnabled(hasProcess);
    nextScanBtn_->setEnabled(hasResults);
    undoScanBtn_->setEnabled(undoResult_ != nullptr);
}

// ═══════════════════════════════════════════════════════════════
// ScanResultsModel
// ═══════════════════════════════════════════════════════════════

ScanResultsModel::ScanResultsModel(QObject* parent) : QAbstractTableModel(parent) {}

size_t ScanResultsModel::valueSizeBytes() const {
    switch (valueType_) {
        case ValueType::Byte:    return 1;
        case ValueType::Int16:   return 2;
        case ValueType::Int32:   return 4;
        case ValueType::Int64:   return 8;
        case ValueType::Pointer: return sizeof(uintptr_t);
        case ValueType::Float:   return 4;
        case ValueType::Double:  return 8;
        case ValueType::Grouped:
        case ValueType::Custom:  return std::max<size_t>(1, valueSize_);
        default:                 return 4;
    }
}

void ScanResultsModel::refreshRange(int firstRow, int lastRow) {
    if (!result_ || !proc_) return;
    int n = rowCount();
    if (n == 0) return;
    firstRow = std::max(0, firstRow);
    lastRow  = std::min(n - 1, lastRow);
    if (firstRow > lastRow) return;

    size_t vs = valueSizeBytes();
    // Bound the cache to what's on screen — drop rows outside the window.
    for (auto it = liveValues_.begin(); it != liveValues_.end(); ) {
        if (it->first < firstRow || it->first > lastRow) {
            changed_.erase(it->first);
            it = liveValues_.erase(it);
        } else ++it;
    }
    for (int row = firstRow; row <= lastRow; ++row) {
        std::vector<uint8_t> buf(vs);
        auto r = proc_->read(result_->address(row), buf.data(), vs);
        std::vector<uint8_t> nv = (r && *r >= vs) ? std::move(buf) : std::vector<uint8_t>{};
        // Flag rows whose value changed since the previous refresh (CE-style
        // red highlight for live-changing values).
        auto it = liveValues_.find(row);
        changed_[row] = (it != liveValues_.end()) && !it->second.empty()
                        && !nv.empty() && it->second != nv;
        liveValues_[row] = std::move(nv);
    }
    emit dataChanged(index(firstRow, 1), index(lastRow, 1), {Qt::DisplayRole, Qt::ForegroundRole});
}

void ScanResultsModel::setResult(ScanResult* result, ValueType vt, size_t valueSize) {
    beginResetModel();
    result_ = result;
    valueType_ = vt;
    valueSize_ = valueSize;
    liveValues_.clear();
    changed_.clear();
    endResetModel();
}

void ScanResultsModel::clear() {
    beginResetModel();
    result_ = nullptr;
    valueSize_ = 0;
    liveValues_.clear();
    changed_.clear();
    endResetModel();
}

int ScanResultsModel::rowCount(const QModelIndex&) const {
    return result_ ? std::min(result_->count(), size_t(10000)) : 0;
}

int ScanResultsModel::columnCount(const QModelIndex&) const { return 2; }

QVariant ScanResultsModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    return section == 0 ? "Address" : "Value";
}

QVariant ScanResultsModel::data(const QModelIndex& index, int role) const {
    if (!result_) return {};
    // Red foreground on the Value column when it changed since the last refresh.
    if (role == Qt::ForegroundRole) {
        if (index.column() == 1) {
            auto it = changed_.find(index.row());
            if (it != changed_.end() && it->second) return QBrush(QColor(0xf3, 0x8b, 0xa8));
        }
        return {};
    }
    if (role != Qt::DisplayRole) return {};

    if (index.column() == 0) {
        return QString("0x%1").arg(result_->address(index.row()), 0, 16);
    } else {
        size_t vs = valueSizeBytes();
        std::vector<uint8_t> buf(vs);
        // Prefer the live re-read for on-screen rows; fall back to the scan-time
        // value for rows not currently refreshed.
        auto it = liveValues_.find(index.row());
        if (it != liveValues_.end()) {
            if (it->second.size() == vs) buf = it->second;
            else return QStringLiteral("??");   // unreadable this refresh
        } else {
            result_->value(index.row(), buf.data(), vs);
        }

        switch (valueType_) {
            case ValueType::Byte:   return displayHex_ ? QString("0x%1").arg(buf[0], 0, 16) : QString::number(buf[0]);
            case ValueType::Int16:  { uint16_t v; memcpy(&v, buf.data(), 2); return displayHex_ ? QString("0x%1").arg(v, 0, 16) : QString::number((int16_t)v); }
            case ValueType::Int32:  { uint32_t v; memcpy(&v, buf.data(), 4); return displayHex_ ? QString("0x%1").arg(v, 0, 16) : QString::number((int32_t)v); }
            case ValueType::Int64:  { uint64_t v; memcpy(&v, buf.data(), 8); return displayHex_ ? QString("0x%1").arg((qulonglong)v, 0, 16) : QString::number((int64_t)v); }
            case ValueType::Pointer:{ uintptr_t v; memcpy(&v, buf.data(), sizeof(v)); return QString("0x%1").arg(v, 0, 16); }
            case ValueType::Float:  { float v; memcpy(&v, buf.data(), 4); return QString::number(v, 'f', 4); }
            case ValueType::Double: { double v; memcpy(&v, buf.data(), 8); return QString::number(v, 'f', 6); }
            case ValueType::Grouped:
            case ValueType::Custom: {
                QString hex;
                hex.reserve(static_cast<int>(vs * 2));
                for (size_t i = 0; i < vs; ++i)
                    hex += QString("%1").arg(buf[i], 2, 16, QChar('0'));
                return hex;
            }
            default: return "?";
        }
    }
}

uintptr_t ScanResultsModel::addressAt(int row) const {
    return result_ ? result_->address(row) : 0;
}

// ═══════════════════════════════════════════════════════════════
// AddressListModel
// ═══════════════════════════════════════════════════════════════

AddressListModel::AddressListModel(QObject* parent) : QAbstractTableModel(parent) {}

void AddressListModel::addEntry(uintptr_t addr, ValueType type, const QString& desc,
                                const QString& addressExpr) {
    beginInsertRows({}, entries_.size(), entries_.size());
    AddressEntry entry;
    entry.id = allocId();
    entry.description = desc;
    entry.address = addr;
    entry.addressExpr = addressExpr;  // non-empty => pointer record, re-resolved live
    entry.type = type;
    entry.currentValue = "?";
    entries_.push_back(std::move(entry));
    endInsertRows();
}

void AddressListModel::addScriptEntry(const QString& desc, const QString& script) {
    beginInsertRows({}, entries_.size(), entries_.size());
    AddressEntry entry;
    entry.id = allocId();
    entry.description = desc.isEmpty() ? "Auto Assembler script" : desc;
    entry.autoAsmScript = script;   // toggling the checkbox runs [ENABLE]/[DISABLE]
    entry.type = ValueType::Int32;
    entry.currentValue = "(Auto Assembler script)";
    entries_.push_back(std::move(entry));
    endInsertRows();
}

bool AddressListModel::isScriptEntry(int row) const {
    return row >= 0 && row < (int)entries_.size() && !entries_[row].autoAsmScript.isEmpty();
}

void AddressListModel::updateScriptEntryById(int id, const QString& desc, const QString& script) {
    int row = rowOfId(id);
    if (row < 0) return;
    auto& e = entries_[row];
    e.autoAsmScript = script;
    if (!desc.isEmpty()) e.description = desc;
    // The script changed; if it is currently enabled its saved DisableInfo is
    // stale, so drop it (the user should re-toggle to re-apply the new script).
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

void AddressListModel::setEntryAddress(int row, uintptr_t addr, const QString& expr) {
    if (row < 0 || row >= (int)entries_.size()) return;
    auto& e = entries_[row];
    if (e.isGroup || !e.autoAsmScript.isEmpty()) return;  // not addressable
    e.address = addr;
    e.addressExpr = expr;      // pointer expression re-resolves each refresh
    e.currentValue.clear();    // force a re-read at the new address
    emit dataChanged(index(row, 2), index(row, columnCount() - 1),
                     {Qt::DisplayRole, Qt::EditRole});
}

void AddressListModel::setEntryDescription(int row, const QString& desc) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].description = desc;
    emit dataChanged(index(row, 1), index(row, 1), {Qt::DisplayRole, Qt::EditRole});
}

void AddressListModel::addGroup(const QString& desc) {
    beginInsertRows({}, entries_.size(), entries_.size());
    AddressEntry entry;
    entry.id = allocId();
    entry.description = desc;
    entry.currentValue.clear();
    entry.isGroup = true;
    entries_.push_back(std::move(entry));
    endInsertRows();
}

static const char* typeToStr(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:   return "byte";
        case ValueType::Int16:  return "i16";
        case ValueType::Int32:  return "i32";
        case ValueType::Int64:  return "i64";
        case ValueType::Pointer: return "pointer";
        case ValueType::Float:  return "float";
        case ValueType::Double: return "double";
        default: return "i32";
    }
}

static ValueType strToType(const QString& s) {
    if (s == "byte")   return ValueType::Byte;
    if (s == "i16")    return ValueType::Int16;
    if (s == "i32")    return ValueType::Int32;
    if (s == "i64")    return ValueType::Int64;
    if (s == "pointer") return ValueType::Pointer;
    if (s == "float")  return ValueType::Float;
    if (s == "double") return ValueType::Double;
    bool ok = false;
    int raw = s.toInt(&ok);
    if (ok) {
        switch (raw) {
            case 0: return ValueType::Byte;
            case 1: return ValueType::Int16;
            case 2: return ValueType::Int32;
            case 3: return ValueType::Int64;
            case 4: return ValueType::Float;
            case 5: return ValueType::Double;
            case 6: return ValueType::String;
            case 8: return ValueType::ByteArray;
            case 9: return ValueType::Binary;
            case 10: return ValueType::All;
            case 13: return ValueType::Pointer;
            case 11: return ValueType::Grouped;
            case 12: return ValueType::Custom;
            default: break;
        }
    }
    return ValueType::Int32;
}

static QMap<QString, QString> parseDropdownList(const QString& dropdownList) {
    QMap<QString, QString> choices;
    for (const auto& rawItem : dropdownList.split(';', Qt::SkipEmptyParts)) {
        auto item = rawItem.trimmed();
        auto sep = item.indexOf(':');
        if (sep <= 0) continue;
        auto value = item.left(sep).trimmed();
        auto label = item.mid(sep + 1).trimmed();
        if (!value.isEmpty())
            choices[value] = label.isEmpty() ? value : label;
    }
    return choices;
}

static QString displayDropdownValue(const QString& value, const QString& dropdownList) {
    auto choices = parseDropdownList(dropdownList);
    auto it = choices.find(value.trimmed());
    return it == choices.end() ? value : QString("%1 (%2)").arg(it.value(), it.key());
}

static QString resolveDropdownInput(const QString& input, const QString& dropdownList) {
    auto choices = parseDropdownList(dropdownList);
    auto trimmed = input.trimmed();
    if (choices.contains(trimmed))
        return trimmed;
    for (auto it = choices.begin(); it != choices.end(); ++it) {
        if (QString::compare(it.value(), trimmed, Qt::CaseInsensitive) == 0)
            return it.key();
    }
    return input;
}

static QVariant entryForeground(const QString& color) {
    if (color.isEmpty())
        return {};
    auto name = color.startsWith('#') ? color : "#" + color;
    QColor parsed(name);
    return parsed.isValid() ? QVariant(parsed) : QVariant();
}

static size_t vtSize(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:   return 1;
        case ValueType::Int16:  return 2;
        case ValueType::Int32:  return 4;
        case ValueType::Int64:  return 8;
        case ValueType::Pointer: return sizeof(uintptr_t);
        case ValueType::Float:  return 4;
        case ValueType::Double: return 8;
        default: return 4;
    }
}

// Parse a user-entered decimal accepting either '.' or ',' as the separator.
// QString::toDouble is C-locale ('.') only; comma-locale users type "2,5".
static double parseUserDouble(const QString& s, bool* ok) {
    return QString(s).replace(',', '.').toDouble(ok);
}

// Parse an integer value field tolerantly: accept a leading '-', an optional 0x
// hex prefix, and both signed and full-width-unsigned magnitudes. Returns a wide
// value the caller truncates to the target width — so "-1" -> byte 0xFF and
// "40000" -> int16 fits, matching how CE accepts either sign for a fixed width.
static long long parseIntField(const QString& valStr) {
    QString t = valStr.trimmed();
    bool neg = t.startsWith('-');
    if (neg || t.startsWith('+')) t = t.mid(1);
    bool ok = false;
    long long v = 0;
    if (t.startsWith("0x", Qt::CaseInsensitive))
        v = static_cast<long long>(t.mid(2).toULongLong(&ok, 16));
    else
        v = static_cast<long long>(t.toULongLong(&ok, 10));
    if (!ok) return 0;
    return neg ? -v : v;
}

static void writeValueToProcess(ProcessHandle* proc, uintptr_t addr, ValueType type, const QString& valStr) {
    // Variable-length types: write the raw bytes directly (length = the value's).
    if (type == ValueType::String) {
        auto bytes = valStr.toUtf8();
        if (!bytes.isEmpty()) proc->write(addr, bytes.constData(), (size_t)bytes.size());
        return;
    }
    if (type == ValueType::UnicodeString) {
        std::vector<uint8_t> u16;                  // UTF-16LE
        for (QChar c : valStr) { char16_t u = c.unicode(); u16.push_back(u & 0xFF); u16.push_back((u >> 8) & 0xFF); }
        if (!u16.empty()) proc->write(addr, u16.data(), u16.size());
        return;
    }
    if (type == ValueType::ByteArray) {
        std::vector<uint8_t> bytes;                // parse space-separated hex ("90 90 48 8b")
        for (const QString& tok : valStr.split(' ', Qt::SkipEmptyParts)) {
            bool ok = false; uint b = tok.toUInt(&ok, 16);
            if (ok && b <= 0xFF) bytes.push_back(static_cast<uint8_t>(b));
        }
        if (!bytes.empty()) proc->write(addr, bytes.data(), bytes.size());
        return;
    }

    uint8_t buf[8] = {};
    size_t vs = vtSize(type);
    switch (type) {
        case ValueType::Byte:   { uint8_t v = (uint8_t)parseIntField(valStr); memcpy(buf, &v, 1); break; }
        case ValueType::Int16:  { uint16_t v = (uint16_t)parseIntField(valStr); memcpy(buf, &v, 2); break; }
        case ValueType::Int32:  { uint32_t v = (uint32_t)parseIntField(valStr); memcpy(buf, &v, 4); break; }
        case ValueType::Int64:  { uint64_t v = (uint64_t)parseIntField(valStr); memcpy(buf, &v, 8); break; }
        case ValueType::Pointer:{ uintptr_t v = valStr.toULongLong(nullptr, 0); memcpy(buf, &v, sizeof(v)); break; }
        // Accept either '.' or ',' as the decimal separator: QString::toFloat is
        // C-locale ('.') only, so a comma-locale user typing "2,5" would otherwise
        // get 0. Value entry never has thousands separators, so this is safe.
        case ValueType::Float:  { float v = QString(valStr).replace(',', '.').toFloat(); memcpy(buf, &v, 4); break; }
        case ValueType::Double: { double v = QString(valStr).replace(',', '.').toDouble(); memcpy(buf, &v, 8); break; }
        // Non-scalar types (String/UnicodeString/ByteArray/All/Grouped/Custom)
        // have no scalar encoding here; vtSize() falls back to 4, so writing the
        // zero-filled buffer would silently clobber 4 bytes as Int32. Refuse
        // instead of corrupting target memory.
        // TODO(security): implement proper per-type read/format/write for
        // String/UnicodeString/ByteArray address-list entries.
        default: return;
    }
    proc->write(addr, buf, vs);
}

static bool readComparableValue(ProcessHandle* proc, uintptr_t addr, ValueType type, double& value) {
    uint8_t buf[8] = {};
    size_t vs = vtSize(type);
    auto r = proc->read(addr, buf, vs);
    if (!r || *r < vs) return false;

    switch (type) {
        case ValueType::Byte: {
            uint8_t v; memcpy(&v, buf, 1); value = v; return true;
        }
        case ValueType::Int16: {
            int16_t v; memcpy(&v, buf, 2); value = v; return true;
        }
        case ValueType::Int32: {
            int32_t v; memcpy(&v, buf, 4); value = v; return true;
        }
        case ValueType::Int64: {
            int64_t v; memcpy(&v, buf, 8); value = static_cast<double>(v); return true;
        }
        case ValueType::Pointer: {
            uintptr_t v; memcpy(&v, buf, sizeof(v)); value = static_cast<double>(v); return true;
        }
        case ValueType::Float: {
            float v; memcpy(&v, buf, 4); value = v; return true;
        }
        case ValueType::Double: {
            double v; memcpy(&v, buf, 8); value = v; return true;
        }
        default:
            return false;
    }
}

static bool parseComparableValue(ValueType type, const QString& valStr, double& value) {
    bool ok = false;
    switch (type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64:
            value = valStr.toLongLong(&ok);
            return ok;
        case ValueType::Pointer:
            value = static_cast<double>(valStr.toULongLong(&ok, 0));
            return ok;
        case ValueType::Float:
        case ValueType::Double:
            // Accept ',' or '.' as the decimal separator, matching
            // writeValueToProcess — otherwise a comma-locale frozen value would
            // silently degrade a directional freeze to an unconditional write.
            value = QString(valStr).replace(',', '.').toDouble(&ok);
            return ok;
        default:
            return false;
    }
}

void AddressListModel::freezeWrite(ProcessHandle* proc) {
    for (auto& e : entries_) {
        if (e.isGroup) continue;
        if (!e.active || e.frozenValue.isEmpty()) continue;

        if (e.freezeMode == FreezeMode::Normal) {
            writeValueToProcess(proc, e.address, e.type, e.frozenValue);
            continue;
        }

        // Read current value to compare for directional freeze.
        double current = 0;
        double frozen = 0;
        if (!readComparableValue(proc, e.address, e.type, current) ||
            !parseComparableValue(e.type, e.frozenValue, frozen)) {
            writeValueToProcess(proc, e.address, e.type, e.frozenValue);
            continue;
        }

        if (ce::freezeShouldWrite(e.freezeMode, current, frozen))
            writeValueToProcess(proc, e.address, e.type, e.frozenValue);
    }
}

QJsonArray AddressListModel::toJson() const {
    QJsonArray arr;
    std::vector<int> lastRowAtIndent;
    for (int row = 0; row < (int)entries_.size(); ++row) {
        const auto& e = entries_[row];
        QJsonObject obj;
        obj["id"] = e.id;
        obj["description"] = e.description;
        obj["address"] = QString("0x%1").arg(e.address, 0, 16);
        if (!e.addressExpr.isEmpty()) obj["addressExpr"] = e.addressExpr;
        obj["type"] = typeToStr(e.type);
        obj["value"] = e.currentValue;
        obj["active"] = e.active;
        obj["asm"] = e.autoAsmScript;
        obj["color"] = e.color;
        obj["dropdown"] = e.dropdownList;
        obj["hotkeys"] = e.hotkeyKeys;
        obj["increaseHotkey"] = e.increaseHotkeyKeys;
        obj["setValueHotkey"] = e.setValueHotkeyKeys;
        obj["setValueHotkeyValue"] = e.setValueHotkeyValue;
        obj["decreaseHotkey"] = e.decreaseHotkeyKeys;
        obj["hotkeyStep"] = e.hotkeyStep;
        obj["indent"] = e.indent;
        obj["group"] = e.isGroup;
        obj["showAsHex"] = e.showAsHex;
        obj["freezeMode"] = (int)e.freezeMode;
        if (e.indent > 0 && e.indent - 1 < (int)lastRowAtIndent.size())
            obj["parent"] = lastRowAtIndent[e.indent - 1];
        arr.append(obj);

        if (e.indent >= (int)lastRowAtIndent.size())
            lastRowAtIndent.resize(e.indent + 1, -1);
        lastRowAtIndent[e.indent] = row;
        if ((int)lastRowAtIndent.size() > e.indent + 1)
            lastRowAtIndent.resize(e.indent + 1);
    }
    return arr;
}

void AddressListModel::fromJson(const QJsonArray& arr) {
    beginResetModel();
    entries_.clear();
    std::vector<int> parentIndentById;
    for (auto val : arr) {
        auto obj = val.toObject();
        AddressEntry e;
        e.id = obj.contains("id") ? obj["id"].toInt() : allocId();
        if (e.id >= nextId_) nextId_ = e.id + 1;
        e.description = obj["description"].toString();
        e.address = obj["address"].toString().toULongLong(nullptr, 16);
        e.addressExpr = obj["addressExpr"].toString();
        e.type = strToType(obj["type"].toString());
        e.currentValue = obj["value"].toString();
        e.active = obj["active"].toBool();
        e.autoAsmScript = obj["asm"].toString();
        e.color = obj["color"].toString();
        e.dropdownList = obj["dropdown"].toString();
        e.hotkeyKeys = obj["hotkeys"].toString();
        e.increaseHotkeyKeys = obj["increaseHotkey"].toString();
        e.setValueHotkeyKeys = obj["setValueHotkey"].toString();
        e.setValueHotkeyValue = obj["setValueHotkeyValue"].toString();
        e.decreaseHotkeyKeys = obj["decreaseHotkey"].toString();
        e.hotkeyStep = obj["hotkeyStep"].toString("1");
        e.indent = std::max(0, obj.contains("indent")
            ? obj["indent"].toInt()
            : (obj["parent"].toInt(-1) >= 0 && obj["parent"].toInt(-1) < (int)parentIndentById.size()
                ? parentIndentById[obj["parent"].toInt()] + 1
                : 0));
        e.isGroup = obj["group"].toBool();
        e.showAsHex = obj["showAsHex"].toBool();
        if (obj.contains("freezeMode"))
            e.freezeMode = (ce::FreezeMode)obj["freezeMode"].toInt();
        if (e.isGroup) {
            e.address = 0;
            e.currentValue.clear();
            e.frozenValue.clear();
        }
        if (e.active) e.frozenValue = e.currentValue;
        parentIndentById.push_back(e.indent);
        entries_.push_back(e);
    }
    endResetModel();
}

void AddressListModel::setFreezeMode(int row, FreezeMode mode) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].freezeMode = mode;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

void AddressListModel::setShowAsHex(int row, bool hex) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].showAsHex = hex;
    emit dataChanged(index(row, 4), index(row, 4));
}

void AddressListModel::setEntryType(int row, ValueType t) {
    if (row < 0 || row >= (int)entries_.size()) return;
    if (entries_[row].isGroup) return;
    entries_[row].type = t;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

void AddressListModel::setHotkeyKeys(int row, const QString& keys) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].hotkeyKeys = keys;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

void AddressListModel::setValueHotkeys(int row, const QString& increaseKeys, const QString& decreaseKeys,
                                       const QString& step, const QString& setKeys, const QString& setValue) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].increaseHotkeyKeys = increaseKeys;
    entries_[row].decreaseHotkeyKeys = decreaseKeys;
    entries_[row].hotkeyStep = step.isEmpty() ? "1" : step;
    entries_[row].setValueHotkeyKeys = setKeys;
    entries_[row].setValueHotkeyValue = setValue;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
}

bool AddressListModel::adjustEntryValue(int row, double delta) {
    if (row < 0 || row >= (int)entries_.size() || !proc_) return false;
    auto& e = entries_[row];
    if (e.isGroup) return false;

    // Re-resolve pointer/expression records NOW so a hotkey acts on the current
    // target address, not the up-to-500ms-stale cached one (a moved pointer would
    // otherwise write to the wrong — possibly unrelated — memory).
    if (!e.addressExpr.isEmpty()) {
        ExpressionParser parser(proc_, nullptr);
        if (auto v = parser.parse(e.addressExpr.toStdString())) e.address = *v;
    }

    double current = 0;
    if (!readComparableValue(proc_, e.address, e.type, current) &&
        !parseComparableValue(e.type, e.currentValue, current)) {
        return false;
    }

    double next = current + delta;
    QString nextText;
    switch (e.type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64:
            nextText = QString::number(static_cast<qlonglong>(std::llround(next)));
            break;
        case ValueType::Pointer:
            nextText = QString("0x%1").arg(static_cast<qulonglong>(std::llround(next)), 0, 16);
            break;
        case ValueType::Float:
            nextText = QString::number(next, 'f', 4);
            break;
        case ValueType::Double:
            nextText = QString::number(next, 'f', 6);
            break;
        default:
            return false;
    }

    writeValueToProcess(proc_, e.address, e.type, nextText);
    e.currentValue = nextText;
    if (e.active) e.frozenValue = nextText;
    emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
    return true;
}

void AddressListModel::indentRows(QList<int> rows) {
    if (rows.isEmpty()) return;
    std::sort(rows.begin(), rows.end());
    for (int row : rows) {
        if (row <= 0 || row >= (int)entries_.size()) continue;
        int maxIndent = entries_[row - 1].indent + 1;
        entries_[row].indent = std::min(entries_[row].indent + 1, maxIndent);
    }
    emit dataChanged(index(rows.first(), 0), index(rows.last(), columnCount() - 1));
}

void AddressListModel::outdentRows(QList<int> rows) {
    if (rows.isEmpty()) return;
    std::sort(rows.begin(), rows.end());
    for (int row : rows) {
        if (row < 0 || row >= (int)entries_.size()) continue;
        entries_[row].indent = std::max(0, entries_[row].indent - 1);
    }
    emit dataChanged(index(rows.first(), 0), index(rows.last(), columnCount() - 1));
}

void AddressListModel::reportActivationError(const QString& title, const QString& message) {
    if (activationErrorCb_)
        activationErrorCb_(title, message);
}

void AddressListModel::setAllActive(bool active) {
    for (int i = 0; i < (int)entries_.size(); ++i)
        if (!entries_[i].isGroup) setEntryActive(i, active);
    if (!entries_.empty())
        emit dataChanged(index(0, 0), index((int)entries_.size() - 1, columnCount() - 1));
}

void AddressListModel::toggleActive(int row) {
    if (row < 0 || row >= (int)entries_.size() || entries_[row].isGroup) return;
    setEntryActive(row, !entries_[row].active);
}

void AddressListModel::setEntryValueTo(int row, const QString& value) {
    if (row < 0 || row >= (int)entries_.size() || !proc_) return;
    auto& e = entries_[row];
    if (e.isGroup || value.isEmpty()) return;
    // Re-resolve pointer records so the write lands on the current target.
    if (!e.addressExpr.isEmpty()) {
        ExpressionParser parser(proc_, nullptr);
        if (auto v = parser.parse(e.addressExpr.toStdString())) e.address = *v;
    }
    writeValueToProcess(proc_, e.address, e.type, value);
    e.currentValue = value;
    if (e.active) e.frozenValue = value;
    emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
}

bool AddressListModel::setEntryActive(int row, bool active) {
    if (row < 0 || row >= (int)entries_.size()) return false;

    auto& e = entries_[row];
    if (e.active == active) return true;

    if (!e.autoAsmScript.isEmpty()) {
        if (!proc_ || !autoAsm_) {
            reportActivationError("Process required",
                "Open a process before activating this auto-assembler record.");
            return false;
        }

        // Code injection needs to ptrace-attach the target, which fails if this
        // program already traces it (e.g. an open "find what accesses" window).
        // Release those traces first.
        if (beforeAaExecute_) beforeAaExecute_();

        if (active) {
            auto result = autoAsm_->execute(*proc_, e.autoAsmScript.toStdString());
            if (!result.success) {
                reportActivationError("Auto-assembler activation failed",
                    QString::fromStdString(result.error));
                return false;
            }
            e.autoAsmDisableInfo = std::move(result.disableInfo);
        } else {
            auto result = autoAsm_->disable(*proc_, e.autoAsmScript.toStdString(), e.autoAsmDisableInfo);
            if (!result.success) {
                reportActivationError("Auto-assembler deactivation failed",
                    QString::fromStdString(result.error));
                return false;
            }
            e.autoAsmDisableInfo = {};
        }
    }

    e.active = active;
    if (e.active)
        e.frozenValue = e.currentValue;
    else
        e.frozenValue.clear();
    if (activationCb_)
        activationCb_(e.id, active);
    return true;
}

void AddressListModel::removeEntry(int row) {
    if (row < 0 || row >= (int)entries_.size()) return;
    beginRemoveRows({}, row, row);
    entries_.erase(entries_.begin() + row);
    endRemoveRows();
}

void AddressListModel::removeEntries(QList<int> rows) {
    std::sort(rows.begin(), rows.end(), std::greater<int>());
    for (int row : rows)
        removeEntry(row);
}

// Read+format a variable-length value (String/UnicodeString/ByteArray) for display.
// nullopt if `type` isn't variable-length; "??" on read failure. Shared by the
// address-list refresh and the Lua mr.Value read so both agree.
static std::optional<QString> formatVariableLengthValue(ProcessHandle* proc, uintptr_t addr, ValueType type) {
    if (type != ValueType::String && type != ValueType::UnicodeString && type != ValueType::ByteArray)
        return std::nullopt;
    uint8_t sbuf[64] = {};
    auto sr = proc->read(addr, sbuf, sizeof(sbuf));
    if (!sr || *sr == 0) return QString("??");
    size_t n = *sr;
    QString s;
    if (type == ValueType::String) {
        for (size_t k = 0; k < n && sbuf[k]; ++k) {
            if (sbuf[k] < 32 || sbuf[k] > 126) break;
            s += QChar(sbuf[k]);
        }
    } else if (type == ValueType::UnicodeString) {
        for (size_t k = 0; k + 1 < n; k += 2) {
            char16_t u = sbuf[k] | (char16_t(sbuf[k + 1]) << 8);
            if (u == 0 || u < 32) break;
            s += QChar(u);
        }
    } else {  // ByteArray
        for (size_t k = 0; k < n && k < 16; ++k)
            s += QString("%1 ").arg(sbuf[k], 2, 16, QChar('0'));
        s = s.trimmed();
    }
    return s;
}

void AddressListModel::updateValues(ProcessHandle* proc) {
    for (size_t i = 0; i < entries_.size(); ++i) {
        auto& e = entries_[i];
        if (e.isGroup) continue;
        if (e.active) continue; // Don't overwrite display for frozen entries

        // Pointer records: re-evaluate the address expression so a moving pointer
        // chain is followed live (CE re-resolves every refresh).
        if (!e.addressExpr.isEmpty()) {
            ExpressionParser parser(proc, nullptr);
            if (auto v = parser.parse(e.addressExpr.toStdString())) e.address = *v;
        }

        // Variable-length types: read a window and format for display.
        if (auto fv = formatVariableLengthValue(proc, e.address, e.type)) {
            e.currentValue = *fv;
            continue;
        }

        uint8_t buf[8] = {};
        size_t vs = vtSize(e.type);
        auto r = proc->read(e.address, buf, vs);
        if (r && *r >= vs) {
            switch (e.type) {
                case ValueType::Byte:   { uint8_t v; memcpy(&v, buf, 1); e.currentValue = e.showAsHex ? QString("0x%1").arg(v, 0, 16) : QString::number(v); break; }
                case ValueType::Int16:  { int16_t v; memcpy(&v, buf, 2); e.currentValue = e.showAsHex ? QString("0x%1").arg((uint16_t)v, 0, 16) : QString::number(v); break; }
                case ValueType::Int32:  { int32_t v; memcpy(&v, buf, 4); e.currentValue = e.showAsHex ? QString("0x%1").arg((uint32_t)v, 0, 16) : QString::number(v); break; }
                case ValueType::Int64:  { int64_t v; memcpy(&v, buf, 8); e.currentValue = e.showAsHex ? QString("0x%1").arg((quint64)(uint64_t)v, 0, 16) : QString::number(v); break; }
                case ValueType::Pointer:{ uintptr_t v; memcpy(&v, buf, sizeof(v)); e.currentValue = QString("0x%1").arg(v, 0, 16); break; }
                case ValueType::Float:  { float v; memcpy(&v, buf, 4); e.currentValue = QString::number(v, 'f', 4); break; }
                case ValueType::Double: { double v; memcpy(&v, buf, 8); e.currentValue = QString::number(v, 'f', 6); break; }
                default: e.currentValue = "?"; break;
            }
        } else {
            e.currentValue = "??";
        }
    }
    if (!entries_.empty())
        emit dataChanged(index(0, 4), index(entries_.size() - 1, 4));
}

std::string AddressListModel::liveValue(int id) {
    int row = rowOfId(id);
    if (row < 0 || !proc_) return {};
    auto& e = entries_[row];
    if (e.isGroup) return {};
    // Re-resolve pointer expressions and read the process now (CE's mr.Value does a
    // live read on access, not a cached refresh value).
    if (!e.addressExpr.isEmpty()) {
        ExpressionParser parser(proc_, nullptr);
        if (auto v = parser.parse(e.addressExpr.toStdString())) e.address = *v;
    }
    if (auto fv = formatVariableLengthValue(proc_, e.address, e.type))
        return fv->toStdString();

    uint8_t buf[8] = {};
    size_t vs = vtSize(e.type);
    auto r = proc_->read(e.address, buf, vs);
    if (!r || *r < vs) return "??";
    QString out;
    switch (e.type) {
        case ValueType::Byte:   { uint8_t v; memcpy(&v, buf, 1); out = e.showAsHex ? QString("0x%1").arg(v, 0, 16) : QString::number(v); break; }
        case ValueType::Int16:  { int16_t v; memcpy(&v, buf, 2); out = e.showAsHex ? QString("0x%1").arg((uint16_t)v, 0, 16) : QString::number(v); break; }
        case ValueType::Int32:  { int32_t v; memcpy(&v, buf, 4); out = e.showAsHex ? QString("0x%1").arg((uint32_t)v, 0, 16) : QString::number(v); break; }
        case ValueType::Int64:  { int64_t v; memcpy(&v, buf, 8); out = e.showAsHex ? QString("0x%1").arg((quint64)(uint64_t)v, 0, 16) : QString::number(v); break; }
        case ValueType::Pointer:{ uintptr_t v; memcpy(&v, buf, sizeof(v)); out = QString("0x%1").arg(v, 0, 16); break; }
        case ValueType::Float:  { float v; memcpy(&v, buf, 4); out = QString::number(v, 'f', 4); break; }
        case ValueType::Double: { double v; memcpy(&v, buf, 8); out = QString::number(v, 'f', 6); break; }
        default: return "?";
    }
    return out.toStdString();
}

int AddressListModel::rowCount(const QModelIndex&) const { return entries_.size(); }
int AddressListModel::columnCount(const QModelIndex&) const { return 5; }

QVariant AddressListModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (section) {
        case 0: return "Active";
        case 1: return "Description";
        case 2: return "Address";
        case 3: return "Type";
        case 4: return "Value";
        default: return {};
    }
}

QVariant AddressListModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)entries_.size())
        return {};
    if (role == Qt::CheckStateRole && index.column() == 0)
        return entries_[index.row()].active ? Qt::Checked : Qt::Unchecked;

    auto& e = entries_[index.row()];
    if (role == Qt::ForegroundRole)
        return entryForeground(e.color);
    if (role == Qt::EditRole) {
        if (index.column() == 1) return e.description;
        // Pre-fill the address editor with the pointer expression if it is a
        // pointer record, otherwise the plain hex address.
        if (index.column() == 2)
            return e.addressExpr.isEmpty()
                ? QString("0x%1").arg(e.address, 0, 16) : e.addressExpr;
        if (index.column() == 4) return e.currentValue;
        return {};
    }
    if (role != Qt::DisplayRole) return {};

    switch (index.column()) {
        case 1: {
            QString prefix;
            for (int i = 0; i < e.indent; ++i) prefix += "  ";
            return prefix + e.description;
        }
        case 2:
            if (e.isGroup) return QString("");
            // Pointer records show a "P->" prefix (CE convention) so they read as
            // a dereferenced address rather than a static one.
            return (e.addressExpr.isEmpty() ? QString("0x%1") : QString("P->0x%1"))
                       .arg(e.address, 0, 16);
        case 3: {
            if (e.isGroup) return "";
            switch (e.type) {
                case ValueType::Byte:   return "Byte";
                case ValueType::Int16:  return "2 Bytes";
                case ValueType::Int32:  return "4 Bytes";
                case ValueType::Int64:  return "8 Bytes";
                case ValueType::Pointer: return "Pointer";
                case ValueType::Float:  return "Float";
                case ValueType::Double: return "Double";
                case ValueType::String: return "Text";
                case ValueType::UnicodeString: return "Unicode Text";
                case ValueType::ByteArray: return "Array of Bytes";
                default: return "?";
            }
        }
        case 4: return e.isGroup ? QString("") : e.dropdownList.isEmpty()
            ? e.currentValue
            : displayDropdownValue(e.currentValue, e.dropdownList);
        default: return {};
    }
}

Qt::ItemFlags AddressListModel::flags(const QModelIndex& index) const {
    auto f = QAbstractTableModel::flags(index);
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)entries_.size())
        return f;
    const auto& e = entries_[index.row()];
    bool isScript = !e.autoAsmScript.isEmpty();
    if (index.column() == 0) f |= Qt::ItemIsUserCheckable;
    // Description is always editable. Address/Type/Value are editable for real
    // (non-group, non-script) entries — a script entry has no meaningful address,
    // type, or value; edit its script via the context menu / double-click.
    if (index.column() == 1)
        f |= Qt::ItemIsEditable;
    else if (!e.isGroup && !isScript &&
             (index.column() == 2 || index.column() == 3 || index.column() == 4))
        f |= Qt::ItemIsEditable;
    return f;
}

// Parse a Type-column display name ("4 Bytes", "Text", "Array of Bytes", ...) back
// to a ValueType, tolerant of common synonyms. Falls back to Int32.
static ValueType valueTypeFromDisplayName(const QString& s) {
    QString n = s.trimmed().toLower();
    if (n == "byte") return ValueType::Byte;
    if (n == "2 bytes" || n == "word" || n == "short") return ValueType::Int16;
    if (n == "4 bytes" || n == "dword" || n == "int") return ValueType::Int32;
    if (n == "8 bytes" || n == "qword" || n == "long" || n == "int64") return ValueType::Int64;
    if (n == "float") return ValueType::Float;
    if (n == "double") return ValueType::Double;
    if (n == "text" || n == "string") return ValueType::String;
    if (n == "unicode text" || n == "unicode" || n == "utf-16") return ValueType::UnicodeString;
    if (n == "array of bytes" || n == "array of byte" || n == "aob" || n == "bytes")
        return ValueType::ByteArray;
    if (n == "binary") return ValueType::Binary;
    if (n == "pointer") return ValueType::Pointer;
    return ValueType::Int32;
}

bool AddressListModel::setData(const QModelIndex& index, const QVariant& value, int role) {
    if (role == Qt::CheckStateRole && index.column() == 0) {
        auto& e = entries_[index.row()];
        bool requestedActive = (value.toInt() == Qt::Checked);
        if (!setEntryActive(index.row(), requestedActive))
            return false;
        emit dataChanged(index, index);

        // Cascade to children if this is a group
        if (e.isGroup) {
            int parentIndent = e.indent;
            int lastChangedRow = index.row();
            for (int i = index.row() + 1; i < (int)entries_.size(); ++i) {
                if (entries_[i].indent <= parentIndent) break;
                setEntryActive(i, requestedActive);
                lastChangedRow = i;
            }
            // Repaint exactly the rows that were cascaded (the old fixed +50
            // window left the 51st+ children desynced from the model).
            if (lastChangedRow > index.row())
                emit dataChanged(this->index(index.row() + 1, 0),
                    this->index(lastChangedRow, columnCount() - 1));
        }
        return true;
    }
    if (role == Qt::EditRole) {
        if (index.column() == 1) {
            entries_[index.row()].description = value.toString();
            emit dataChanged(index, index, {Qt::DisplayRole, Qt::EditRole});
            return true;
        }
        if (index.column() == 2) {   // Address
            auto& e = entries_[index.row()];
            if (e.isGroup || !e.autoAsmScript.isEmpty()) return false;
            QString text = value.toString().trimmed();
            if (text.isEmpty()) return false;
            std::optional<uintptr_t> addr;
            if (addressResolver_) addr = addressResolver_(text);
            if (!addr) {   // fall back to a bare hex address if no resolver
                bool ok = false;
                QString h = text;
                if (h.startsWith("0x") || h.startsWith("0X")) h = h.mid(2);
                uintptr_t v = h.toULongLong(&ok, 16);
                if (ok) addr = v;
            }
            if (!addr) return false;
            // A '[' means a pointer deref — keep the expression so the entry
            // re-resolves and follows the chain each refresh (CE convention).
            setEntryAddress(index.row(), *addr, text.contains('[') ? text : QString());
            return true;
        }
        if (index.column() == 3) {   // Type
            auto& e = entries_[index.row()];
            if (e.isGroup) return false;
            e.type = valueTypeFromDisplayName(value.toString());
            e.currentValue.clear();  // force a re-read/reformat with the new type
            emit dataChanged(this->index(index.row(), 3), this->index(index.row(), 4),
                             {Qt::DisplayRole, Qt::EditRole});
            return true;
        }
        if (index.column() == 4) {
            auto& e = entries_[index.row()];
            if (e.isGroup) return false;
            auto rawValue = e.dropdownList.isEmpty()
                ? value.toString()
                : resolveDropdownInput(value.toString(), e.dropdownList);
            // When the entry displays in hex, the user types hex; convert it to a
            // decimal string for the (base-10) writer.
            QString writeStr = rawValue;
            if (e.showAsHex) {
                QString h = rawValue.trimmed();
                if (h.startsWith("0x") || h.startsWith("0X")) h = h.mid(2);
                bool okh = false;
                qulonglong hv = h.toULongLong(&okh, 16);
                if (okh) {
                    writeStr = QString::number((qlonglong)hv);
                    rawValue = "0x" + QString::number(hv, 16);
                }
            }
            e.currentValue = rawValue;
            if (e.active) e.frozenValue = writeStr;
            if (proc_)
                writeValueToProcess(proc_, e.address, e.type, writeStr);
            emit dataChanged(index, index);
            return true;
        }
    }
    return false;
}

// ── ce::IAddressList implementation ──

int AddressListModel::rowOfId(int id) const {
    for (size_t i = 0; i < entries_.size(); ++i)
        if (entries_[i].id == id) return (int)i;
    return -1;
}

int AddressListModel::count() const { return (int)entries_.size(); }

static AddressEntrySnapshot snapshotOf(const AddressEntry& e) {
    AddressEntrySnapshot s;
    s.id = e.id;
    s.description = e.description.toStdString();
    s.address = e.address;
    s.type = e.type;
    s.value = e.currentValue.toStdString();
    s.color = e.color.toStdString();
    s.script = e.autoAsmScript.toStdString();
    s.hotkeyKeys = e.hotkeyKeys.toStdString();
    s.active = e.active;
    s.isGroup = e.isGroup;
    s.showAsHex = e.showAsHex;
    s.indent = e.indent;
    return s;
}

bool AddressListModel::setHexView(int id, bool hex) {
    int row = rowOfId(id);
    if (row < 0) return false;
    setShowAsHex(row, hex);   // existing row-based method: updates + emits dataChanged
    return true;
}

bool AddressListModel::setIndent(int id, int indent) {
    int row = rowOfId(id);
    if (row < 0 || row >= (int)entries_.size()) return false;
    entries_[row].indent = indent < 0 ? 0 : indent;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return true;
}

std::optional<AddressEntrySnapshot> AddressListModel::at(int index) const {
    if (index < 0 || index >= (int)entries_.size()) return std::nullopt;
    return snapshotOf(entries_[index]);
}

std::optional<AddressEntrySnapshot> AddressListModel::byId(int id) const {
    int row = rowOfId(id);
    if (row < 0) return std::nullopt;
    return snapshotOf(entries_[row]);
}

int AddressListModel::findIdByDescription(const std::string& desc) const {
    QString q = QString::fromStdString(desc);
    for (const auto& e : entries_)
        if (e.description == q) return e.id;
    return -1;
}

std::vector<int> AddressListModel::ids() const {
    std::vector<int> out;
    out.reserve(entries_.size());
    for (const auto& e : entries_) out.push_back(e.id);
    return out;
}

int AddressListModel::createEntry(uintptr_t addr, ValueType type, const std::string& description) {
    addEntry(addr, type, QString::fromStdString(description));
    return entries_.empty() ? -1 : entries_.back().id;
}

int AddressListModel::createGroup(const std::string& description) {
    addGroup(QString::fromStdString(description));
    return entries_.empty() ? -1 : entries_.back().id;
}

bool AddressListModel::deleteById(int id) {
    int row = rowOfId(id);
    if (row < 0) return false;
    removeEntry(row);
    return true;
}

bool AddressListModel::disableAllWithoutExecute() {
    bool any = false;
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].active && !entries_[i].isGroup) {
            entries_[i].active = false;
            entries_[i].frozenValue.clear();
            any = true;
        }
    }
    if (any)
        emit dataChanged(index(0, 0), index((int)entries_.size() - 1, columnCount() - 1));
    return any;
}

bool AddressListModel::setDescription(int id, const std::string& desc) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].description = QString::fromStdString(desc);
    emit dataChanged(index(row, 1), index(row, 1));
    return true;
}

bool AddressListModel::setAddress(int id, uintptr_t addr) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].address = addr;
    entries_[row].addressExpr.clear();   // a plain address clears any pointer expr
    emit dataChanged(index(row, 2), index(row, 2));
    return true;
}

bool AddressListModel::setAddressExpression(int id, const std::string& expr) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].addressExpr = QString::fromStdString(expr);
    // Resolve once now so the address column is populated immediately.
    ExpressionParser parser(proc_, nullptr);
    if (auto v = parser.parse(expr)) entries_[row].address = *v;
    emit dataChanged(index(row, 2), index(row, 2));
    return true;
}

bool AddressListModel::setType(int id, ValueType t) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].type = t;
    emit dataChanged(index(row, 3), index(row, 4));
    return true;
}

bool AddressListModel::setValue(int id, const std::string& valStr) {
    int row = rowOfId(id);
    if (row < 0) return false;
    auto& e = entries_[row];
    if (e.isGroup) return false;
    e.currentValue = QString::fromStdString(valStr);
    if (e.active) e.frozenValue = e.currentValue;
    if (proc_)
        writeValueToProcess(proc_, e.address, e.type, e.currentValue);
    emit dataChanged(index(row, 4), index(row, 4));
    return true;
}

bool AddressListModel::setActive(int id, bool active) {
    int row = rowOfId(id);
    if (row < 0) return false;
    bool ok = setEntryActive(row, active);
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return ok;
}

bool AddressListModel::setColor(int id, const std::string& color) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].color = QString::fromStdString(color);
    emit dataChanged(index(row, 1), index(row, columnCount() - 1));
    return true;
}

bool AddressListModel::setScript(int id, const std::string& script) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].autoAsmScript = QString::fromStdString(script);
    return true;
}

bool AddressListModel::setFreezeMode(int id, int mode) {
    int row = rowOfId(id);
    if (row < 0 || mode < 0 || mode > 4) return false;
    entries_[row].freezeMode = static_cast<ce::FreezeMode>(mode);
    return true;
}

} // namespace ce::gui
