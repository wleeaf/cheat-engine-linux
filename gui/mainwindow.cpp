#include <csignal>
#include "gui/mainwindow.hpp"
#include "gui/theme.hpp"
#include "core/expression.hpp"
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
#include "core/target_profile.hpp"
#include "core/trainer.hpp"
#include "analysis/managed_runtime.hpp"

#include <QMenuBar>
#include <QApplication>
#include <QEventLoop>
#include <thread>
#include <atomic>
#include <QCoreApplication>
#include <QTextBrowser>
#include <QDesktopServices>
#include <QUrl>
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
#include <QTabWidget>
#include <QColorDialog>
#include <QListWidget>
#include <sys/prctl.h>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QStandardPaths>
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
#include <QTextStream>
#include <QLocale>
#include <cstdio>
#include <cstring>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <QMap>
#include <cmath>
#include <cstring>
#include <exception>

namespace ce::gui {
// The scan-results table renders at most this many rows (keeping a million-hit
// first scan responsive). The true hit count is always shown in the label, with
// a "(showing first N)" note when it exceeds the cap so the list never looks
// silently truncated.
static constexpr size_t kResultDisplayCap = 10000;

static QString foundLabelText(size_t count) {
    QString s = QString("Found: %1").arg(QLocale().toString((qulonglong)count));
    if (count > kResultDisplayCap)
        s += QString("  (showing first %1)").arg(QLocale().toString((qulonglong)kResultDisplayCap));
    return s;
}

// Accepts "," or "." decimals (Turkish comma-locale); defined lower down.
static double parseUserDouble(const QString& s, bool* ok = nullptr);

// Forward declarations of static helpers
static QJsonArray cheatEntriesToJson(const ce::CheatTable& table);
static QFont settingsMonospaceFont();
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
    // Restore the last window size/position and splitter layout (no-ops on the
    // first run, leaving the defaults above). Saved back in closeEvent().
    {
        QSettings s;
        if (auto g = s.value("mainwindow/geometry").toByteArray(); !g.isEmpty())
            restoreGeometry(g);
        for (auto* sp : findChildren<QSplitter*>())
            if (!sp->objectName().isEmpty())
                if (auto st = s.value("mainwindow/splitter/" + sp->objectName()).toByteArray();
                    !st.isEmpty())
                    sp->restoreState(st);
    }

    // Drive CE Lua timers (createTimer/timer_onTimer): trainer scripts rely on a
    // periodic pump on the Lua thread. 30ms matches CE's default timer resolution.
    auto* luaTimerPump = new QTimer(this);
    connect(luaTimerPump, &QTimer::timeout, this, [this]() { luaEngine_.pumpTimers(); });
    luaTimerPump->start(30);

    // selectFilePath(sender, setting) in a table's Lua opens a real file chooser.
    luaEngine_.setFilePicker([this](const std::string& setting) -> std::string {
        QString title = setting.empty() ? QString("Select file")
                                        : QString("Select file for %1").arg(QString::fromStdString(setting));
        return QFileDialog::getOpenFileName(this, title).toStdString();
    });

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
            // Sever every raw pointer into process_ BEFORE it is destroyed: open
            // Memory Viewers (their refresh timer would read a freed handle) and
            // the shared Lua engine (a table timer/script would do the same).
            for (auto& mv : memoryViewers_) if (mv) mv->detachFromTarget();
            for (auto& sd : structDissectors_) if (sd) sd->detachFromTarget();
            luaEngine_.setProcess(nullptr);
            process_.reset();
            currentPid_ = 0;
            setWindowTitle("Cheat Engine");
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

        // Refresh the module cache (module+offset address display) on a slower
        // cadence than the value poll, so modules mapped after attach show up
        // without re-parsing /proc/pid/maps every tick.
        if (++moduleCacheTick_ >= 10) {
            moduleCacheTick_ = 0;
            addressListModel_->refreshModuleCache();
        }

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
    // Menu bar reproduces Cheat Engine's MainUnit.MainMenu1 verbatim (captions,
    // item order, separators, shortcuts, and .lfm Visible flags). CE items we have
    // no backend for yet are present but disabled (see `stub`); Windows-only menus
    // (D3D/.Net) are present but inert on Linux. Our tools stay under Tools, which
    // CE leaves empty in the form and fills at runtime.
    auto stub = [](QMenu* m, const QString& text) {
        auto* a = m->addAction(text);
        a->setEnabled(false);
        a->setToolTip("Not yet implemented");
        return a;
    };

    // ── File ──
    auto* file = menuBar()->addMenu("&File");
    stub(file, "Add scan tab")->setShortcut(QKeySequence("Ctrl+T"));
    file->addAction("Clear list", this, [this]() {
        resultsModel_->clear(); lastResult_.reset(); undoResult_.reset(); updateScanButtons();
    });
    file->addAction("Open Process", this, &MainWindow::onOpenProcess, QKeySequence("Ctrl+O"));
    stub(file, "Open File")->setShortcut(QKeySequence("Ctrl+Shift+O"));
    { auto* a = stub(file, "Save File"); a->setShortcut(QKeySequence("Ctrl+Shift+S")); a->setVisible(false); }
    file->addSeparator();
    file->addAction("Save", this, &MainWindow::onSaveTable, QKeySequence("Ctrl+S"));
    file->addAction("Save As...", this, &MainWindow::onSaveTable);
    file->addAction("Load", this, &MainWindow::onLoadTable, QKeySequence("Ctrl+L"));
    recentMenu_ = file->addMenu("Load Recent"); // populated from QSettings below
    recentMenu_->setToolTipsVisible(true);      // show the full path on hover
    rebuildRecentMenu();
    stub(file, "Sign table");
    file->addSeparator();
    file->addAction("Save current scanresults", this, &MainWindow::onSaveScanResults,
                    QKeySequence("Alt+Shift+S"));
    stub(file, "Delete scanresult");
    file->addSeparator();
    file->addAction("Generate generic trainer lua script from table", this, &MainWindow::onCreateTrainer);
    file->addSeparator();
    file->addAction("Connect to ceserver...", this, &MainWindow::onConnectCeserver);  // Linux extra
    file->addSeparator();
    file->addAction("Quit", this, &QWidget::close, QKeySequence("Ctrl+Q"));

    // ── Top-level menus in CE's order (D3D dropped — Windows-only, see below) ──
    // File · Edit · Process · Table · Tools · .Net · Network · Plugins ·
    // Languages · Help.
    auto* edit = menuBar()->addMenu("&Edit");
    auto* process = menuBar()->addMenu("&Process");
    auto* table = menuBar()->addMenu("Table");
    // CE's "D3D" menu (Direct3D overlay/hook) is Windows-only and every item is
    // permanently disabled on Linux, so it's dropped here rather than shown as a
    // dead top-level menu. Graphics hooking is out of scope (see docs/DEVELOPMENT).
    auto* tools = menuBar()->addMenu("&Tools");
    auto* dotnet = menuBar()->addMenu(".Net");
    // CE's .Net/Mono menu: dissect a Mono/IL2CPP runtime's classes and fields.
    dotnet->addAction("Mono dissector...", this, &MainWindow::openMonoDissector);
    auto* network = menuBar()->addMenu("Network");
    // CE also has Plugins and Languages menus, but this build has no plugin loader
    // and ships English-only, so they are dropped rather than shown as empty dropdowns
    // (same call the D3D menu got above).

    // ── Table (CE: Lua script + forms) ──
    table->addAction("Show Cheat Table Lua Script", this, &MainWindow::showTableLuaScript,
                     QKeySequence("Ctrl+Alt+L"));
    table->addSeparator();
    table->addAction("Create form", this, [this]() {
        auto* fd = new FormDesigner(this); fd->setAttribute(Qt::WA_DeleteOnClose); fd->show();
    });
    stub(table, "Resynchronize forms with Lua");
    table->addSeparator();
    stub(table, "Add file");

    // (D3D menu intentionally omitted on Linux — see note at the menu creation above.)

    // ── .Net (Windows-only) ──
    stub(dotnet, "Get object list");

    // ── Network (ceserver client options) ──
    stub(network, "Compression");
    stub(network, "Scan changed regions only");
    stub(network, "Scan paged (physical) memory only");
    auto* netRead = network->addMenu("Memory read method");
    stub(netRead, "0: /proc/pid/mem"); stub(netRead, "1: ptrace peek"); stub(netRead, "2: process_vm_readv");
    auto* netWrite = network->addMenu("Memory write method");
    stub(netWrite, "0: /proc/pid/mem"); stub(netWrite, "1: ptrace poke"); stub(netWrite, "2: process_vm_writev");
    // The Memory Viewer is the entry point; the memory/debug windows (Memory
    // Regions, Heap list, Module list, Referenced strings, Thread list, Stacktrace,
    // Registers, Breakpoint list, Debugger, Branch mapper, Break-and-trace, …) live
    // in ITS View/Debug menus — matching CE — populated by populateBrowserMenus().
    tools->addAction("Memory Browser", this, &MainWindow::onMemoryView, QKeySequence("Ctrl+M"));
    tools->addSeparator();
    // Analysis panels (also in the Memory Viewer's Tools menu) — surfaced here so
    // they're findable from the main window without opening the viewer first.
    addAnalysisToolsMenu(tools);
    tools->addSeparator();
    edit->addAction("Settings...", this, [this]() { openSettingsDialog(); });

    // ── Process menu ──
    process->addAction("Open Process...", this, &MainWindow::onOpenProcess);
    // CE formProcessInfo (Process/System Info) — Linux equivalents.
    // CE "Create Process" / frmopenfileasprocessdialogunit: launch an executable
    // and attach. As our own child it is ptrace-accessible under yama scope=1.
    process->addAction("Create Process...", this, [this]() {
        auto path = QFileDialog::getOpenFileName(this, "Open file as process", "", "Executables (*)");
        if (path.isEmpty()) return;
        std::string p = path.toStdString();
        pid_t pid = fork();
        if (pid == 0) {
            prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
            execl(p.c_str(), p.c_str(), (char*)nullptr);
            _exit(127);
        }
        if (pid < 0) { QMessageBox::warning(this, "Create Process", "fork() failed."); return; }
        usleep(120000);   // let it map its image
        currentPid_ = pid;
        ceserverClient_.reset();
        process_ = std::make_unique<os::LinuxProcessHandle>(pid);
        processLabel_->setText(QString("PID: %1 - %2 (created)").arg(pid).arg(QFileInfo(path).fileName()));
        setWindowTitle(QString("Cheat Engine - %1 (%2)").arg(QFileInfo(path).fileName()).arg(pid));
        addressListModel_->setProcess(process_.get());
        resultsModel_->setProcess(process_.get());
        firstScanBtn_->setEnabled(true);
        updateScanButtons();
    });
    process->addAction("Process/System Info", this, [this]() {
        if (!process_) { QMessageBox::information(this, "Process Info", "No process opened."); return; }
        auto mods = process_->modules();
        auto threads = process_->threads();
        QString path = mods.empty() ? QString() : QString::fromStdString(mods.front().path);
        QString info = QString(
            "PID:\t%1\n"
            "Name:\t%2\n"
            "Path:\t%3\n"
            "Architecture:\t%4\n"
            "Modules:\t%5\n"
            "Threads:\t%6")
            .arg(currentPid_)
            .arg(processLabel_->text())
            .arg(path.isEmpty() ? "(unknown)" : path)
            .arg(process_->is64bit() ? "64-bit" : "32-bit")
            .arg(mods.size())
            .arg(threads.size());
        QMessageBox::information(this, "Process/System Info", info);
    });
    // "Pause the process" toggle (CE's pause-the-game) — SIGSTOP/SIGCONT the target.
    auto* pauseAct = process->addAction("Pause the process");
    pauseAct->setCheckable(true);
    connect(pauseAct, &QAction::toggled, this, [this, pauseAct](bool checked) {
        if (!process_ || currentPid_ <= 0) { pauseAct->setChecked(false); return; }
        if (::kill(currentPid_, checked ? SIGSTOP : SIGCONT) != 0)
            pauseAct->setChecked(false);
    });
    // Optionally SIGSTOP the target for the duration of each scan (CE's "pause
    // while scanning") so values can't change mid-scan, then resume.
    auto* pauseScanAct = process->addAction("Pause target while scanning");
    pauseScanAct->setCheckable(true);
    pauseScanAct->setToolTip("Suspend the target during each First/Next Scan so its "
                             "memory is a consistent snapshot, then resume it.");
    connect(pauseScanAct, &QAction::toggled, this, [this](bool on) { pauseWhileScanning_ = on; });
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
    tools->addAction("File Patcher...", this, [this]() {
        auto* dlg = new FilePatcher(this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE frmSaveMemoryRegionUnit (Save memoryregion): dump a From..To range to a file.
    tools->addAction("Save Memory Region...", this, [this]() {
        if (!process_) { QMessageBox::warning(this, "Save Memory Region", "Open a process first."); return; }
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Save memoryregion");
        auto* v = new QVBoxLayout(dlg);
        v->addWidget(new QLabel("Add the region of memory you want to save"));
        auto* form = new QFormLayout;
        auto* fromEdit = new QLineEdit("0");
        auto* toEdit = new QLineEdit("0");
        form->addRow("From", fromEdit);
        form->addRow("To", toEdit);
        v->addLayout(form);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
        v->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, this, [this, dlg, fromEdit, toEdit]() {
            uintptr_t from = fromEdit->text().toULongLong(nullptr, 16);
            uintptr_t to = toEdit->text().toULongLong(nullptr, 16);
            if (to <= from) { QMessageBox::warning(dlg, "Save", "\"To\" must be greater than \"From\"."); return; }
            auto path = QFileDialog::getSaveFileName(dlg, "Save memory region", "region.bin");
            if (path.isEmpty()) return;
            std::vector<uint8_t> buf(to - from);
            auto r = process_->read(from, buf.data(), buf.size());
            if (!r || *r == 0) { QMessageBox::warning(dlg, "Save", "Could not read that region."); return; }
            std::ofstream f(path.toStdString(), std::ios::binary);
            f.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)*r);
            QMessageBox::information(dlg, "Saved", QString("Wrote %1 bytes to %2.").arg(*r).arg(path));
            dlg->accept();
        });
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE frmMemoryAllocHandlerUnit (Memory Allocations): allocate + track blocks.
    tools->addAction("Memory Allocations...", this, [this]() {
        if (!process_) { QMessageBox::warning(this, "Memory Allocations", "Open a process first."); return; }
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Memory Allocations");
        dlg->resize(360, 300);
        auto* v = new QVBoxLayout(dlg);
        auto* list = new QListWidget;
        auto refill = [this, list]() {
            list->clear();
            for (const auto& a : allocations_)
                list->addItem(QString("0x%1  (%2 bytes)").arg(a.first, 0, 16).arg(a.second));
        };
        refill();
        v->addWidget(list);
        auto* row = new QHBoxLayout;
        auto* allocBtn = new QPushButton("Allocate");
        auto* freeBtn = new QPushButton("Free");
        auto* closeBtn = new QPushButton("Close");
        row->addWidget(allocBtn); row->addWidget(freeBtn); row->addStretch(); row->addWidget(closeBtn);
        v->addLayout(row);
        connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
        connect(allocBtn, &QPushButton::clicked, this, [this, dlg, refill]() {
            bool ok = false;
            int size = QInputDialog::getInt(dlg, "Allocate", "Size (bytes):", 4096, 1, 1 << 30, 1, &ok);
            if (!ok) return;
            auto r = process_->allocate(size, ce::MemProt::All, 0);
            if (!r) { QMessageBox::warning(dlg, "Allocate", "Allocation failed."); return; }
            allocations_.push_back({(qulonglong)*r, (qulonglong)size});
            refill();
        });
        connect(freeBtn, &QPushButton::clicked, this, [this, list, refill]() {
            int i = list->currentRow();
            if (i < 0 || i >= (int)allocations_.size()) return;
            process_->free(allocations_[i].first, allocations_[i].second);
            allocations_.erase(allocations_.begin() + i);
            refill();
        });
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE frmExeTrainerGeneratorUnit: compile a standalone trainer executable.
    tools->addAction("Generate Trainer (executable)...", this, [this]() {
        auto path = QFileDialog::getSaveFileName(this, "Generate Trainer executable", "trainer");
        if (path.isEmpty()) return;
        try {
            ce::CheatTable table = buildCheatTable();
            ce::TrainerGenerator gen;
            std::string err = gen.generateBinary(table, path.toStdString());
            if (err.empty())
                statusBar()->showMessage("Trainer executable written to " + path, 6000);
            else
                QMessageBox::critical(this, "Generate Trainer", QString::fromStdString(err));
        } catch (const std::exception& ex) {
            QMessageBox::critical(this, "Generate Trainer", ex.what());
        }
    });
    // CE frmStringPointerScanUnit (Structure spider): find pointer paths to a target
    // and dissect the structure there.
    tools->addAction("Structure Spider...", this, [this]() {
        if (!process_) { QMessageBox::warning(this, "Structure Spider", "Open a process first."); return; }
        bool ok = false;
        QString ts = QInputDialog::getText(this, "Structure Spider", "Target address (hex):",
                                           QLineEdit::Normal, "0", &ok);
        if (!ok) return;
        uintptr_t target = ts.toULongLong(nullptr, 16);
        QApplication::setOverrideCursor(Qt::WaitCursor);
        ce::PointerScanner scanner;
        ce::PointerScanConfig cfg;
        cfg.targetAddress = target; cfg.maxDepth = 2; cfg.maxOffset = 256; cfg.staticOnly = false;
        auto paths = scanner.scan(*process_, cfg);
        QApplication::restoreOverrideCursor();
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Structure spider");
        dlg->resize(520, 420);
        auto* v = new QVBoxLayout(dlg);
        v->addWidget(new QLabel(QString("%1 pointer path(s) to 0x%2:")
                                    .arg(paths.size()).arg((qulonglong)target, 0, 16)));
        auto* list = new QListWidget;
        for (const auto& p : paths) list->addItem(QString::fromStdString(p.toString()));
        v->addWidget(list);
        auto* row = new QHBoxLayout;
        auto* dissectBtn = new QPushButton("Dissect structure at target");
        connect(dissectBtn, &QPushButton::clicked, this, [this, target]() {
            auto* sd = new StructureDissector(process_.get(), target, this);
            sd->setAttribute(Qt::WA_DeleteOnClose);
            sd->setAddToListCallback([this](uintptr_t a, ce::ValueType t, const QString& d) {
                addressListModel_->addEntry(a, t, d);
            });
            trackStructDissector(sd);
            sd->show();
        });
        auto* closeBtn = new QPushButton("Close");
        connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
        row->addWidget(dissectBtn); row->addStretch(); row->addWidget(closeBtn);
        v->addLayout(row);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE frmgroupscanalgoritmgeneratorunit: build a grouped-scan pattern from the
    // selected scan results (offsets from the first, with each value), for finding
    // other instances of the same structure.
    tools->addAction("Group Scan Generator...", this, [this]() {
        if (!process_ || !lastResult_) { QMessageBox::warning(this, "Group Scan Generator", "Run a scan and select results first."); return; }
        auto sel = resultsView_->selectionModel()->selectedRows();
        if (sel.size() < 2) { QMessageBox::warning(this, "Group Scan Generator", "Select at least two results."); return; }
        std::vector<uintptr_t> addrs;
        for (const auto& idx : sel) addrs.push_back(resultsModel_->addressAt(idx.row()));
        std::sort(addrs.begin(), addrs.end());
        uintptr_t base = addrs.front();
        QStringList parts;
        for (auto a : addrs) {
            int32_t v = 0;
            process_->read(a, &v, sizeof(v));
            parts << QString("%1:%2").arg(a - base).arg(v);   // offset:value (4 bytes)
        }
        QString pattern = parts.join(' ');
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle("Group Scan Generator");
        auto* v = new QVBoxLayout(dlg);
        v->addWidget(new QLabel("Grouped-scan pattern (offset:value, 4-byte):"));
        auto* edit = new QPlainTextEdit(pattern); edit->setReadOnly(true);
        v->addWidget(edit);
        auto* row = new QHBoxLayout;
        auto* copyBtn = new QPushButton("Copy");
        connect(copyBtn, &QPushButton::clicked, this, [pattern]() { QApplication::clipboard()->setText(pattern); });
        auto* closeBtn = new QPushButton("Close");
        connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
        row->addStretch(); row->addWidget(copyBtn); row->addWidget(closeBtn);
        v->addLayout(row);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    // CE savedisassemblyfrm: disassemble a From..To range to a text file.
    tools->addAction("Save Disassembly...", this, [this]() {
        if (!process_) { QMessageBox::warning(this, "Save Disassembly", "Open a process first."); return; }
        bool ok = false;
        QString fromS = QInputDialog::getText(this, "Save Disassembly", "From (hex):",
                                              QLineEdit::Normal, "0", &ok);
        if (!ok) return;
        QString toS = QInputDialog::getText(this, "Save Disassembly", "To (hex):",
                                            QLineEdit::Normal, "0", &ok);
        if (!ok) return;
        uintptr_t from = fromS.toULongLong(nullptr, 16), to = toS.toULongLong(nullptr, 16);
        if (to <= from || to - from > (64u << 20)) {
            QMessageBox::warning(this, "Save Disassembly", "Invalid or too-large range."); return;
        }
        std::vector<uint8_t> buf(to - from);
        auto r = process_->read(from, buf.data(), buf.size());
        if (!r || *r == 0) { QMessageBox::warning(this, "Save Disassembly", "Could not read that range."); return; }
        ce::Disassembler dis(process_->is64bit() ? ce::Arch::X86_64 : ce::Arch::X86_32);
        auto insns = dis.disassemble(from, {buf.data(), *r}, 1000000, /*emitDataBytes=*/true);
        auto path = QFileDialog::getSaveFileName(this, "Save disassembly", "disasm.asm");
        if (path.isEmpty()) return;
        std::ofstream f(path.toStdString());
        for (const auto& i : insns)
            f << std::hex << i.address << ": " << i.mnemonic
              << (i.operands.empty() ? "" : " ") << i.operands << "\n";
        QMessageBox::information(this, "Saved", QString("Wrote %1 instructions to %2.")
                                    .arg(insns.size()).arg(path));
    });
    // CE frmMemoryViewExUnit (Graphical Memory View): bytes as pixels.
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
                    processLabel_->setText(QString("PID: %1 - %2 (auto-attached)")
                        .arg(pid).arg(QString::fromStdString(procName)));
                    setWindowTitle(QString("Cheat Engine - %1 (%2)")
                        .arg(QString::fromStdString(procName)).arg(pid));
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
            text += QString("\n(%1 more not shown; use Save to dump full list.)").arg(diffs.size() - shown);

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
    tools->addSeparator();
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
                label->setText(QString("Active, Speed: %1x").arg(speed, 0, 'f', 1));
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

    // ── Help (CE verbatim) ──
    auto* help = menuBar()->addMenu("&Help");
    help->addAction("Cheat Engine Help", this, [this]() {
        openHelpDoc("README.md", "Cheat Engine for Linux: Help",
                    "https://github.com/wleeaf/cheat-engine-linux#readme");
    });
    help->addAction("Lua documentation", this, [this]() {
        openHelpDoc("docs/SCRIPTING.md", "Lua / Scripting documentation",
                    "https://github.com/wleeaf/cheat-engine-linux/blob/main/docs/SCRIPTING.md");
    });
    stub(help, "Cheat Engine Tutorial");
    stub(help, "Cheat Engine Tutorial (x86_64)");
    { auto* a = stub(help, "Cheat Engine Tutorial (AArch64)"); a->setVisible(false); }
    stub(help, "Cheat Engine Tutorial Games");
    { auto* a = stub(help, "Generate errorlogs"); a->setVisible(false); }
    { auto* a = stub(help, "Test access violation"); a->setVisible(false); }
    { auto* a = stub(help, "Test access violation in thread"); a->setVisible(false); }
    help->addSeparator();
    help->addAction("About", this, [this]() {
        QMessageBox::about(this, "Cheat Engine for Linux",
            "<h2>Cheat Engine for Linux</h2>"
            "<p>Memory scanner, debugger, and code injection tool</p>"
            "<p>C++23 / Qt6 / Capstone / Keystone / Lua 5.3</p>"
            "<p><a href='https://github.com/wleeaf/cheat-engine-linux'>GitHub</a></p>");
    });
}

// Table "Comments" window — CE's CommentsUnit: a PageControl with a Comments tab
// holding a free-text memo, plus Close. The text is the cheat table's comment,
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
    v->addWidget(view);
    auto* row = new QHBoxLayout;
    auto* online = new QPushButton("Open on GitHub");
    connect(online, &QPushButton::clicked, this, [url]() { QDesktopServices::openUrl(QUrl(url)); });
    row->addWidget(online);
    row->addStretch();
    auto* closeBtn = new QPushButton("Close");
    row->addWidget(closeBtn);
    v->addLayout(row);
    connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

// persisted via buildCheatTable()/onLoadTable().
void MainWindow::showComments() {
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle("Comments");
    dlg->resize(500, 400);
    auto* v = new QVBoxLayout(dlg);
    auto* tabs = new QTabWidget;                       // CE PageControl1
    auto* memo = new QPlainTextEdit;                   // CE Memo1
    memo->setPlainText(tableComment_);
    tabs->addTab(memo, "Comments");                    // CE tsComment
    v->addWidget(tabs);
    auto* row = new QHBoxLayout;                        // CE Panel1
    row->addStretch();
    auto* closeBtn = new QPushButton("Close");         // CE Button1
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
    dlg->setWindowTitle("Cheat Table Lua Script");
    dlg->resize(640, 460);
    auto* v = new QVBoxLayout(dlg);
    auto* memo = new QPlainTextEdit;
    memo->setFont(settingsMonospaceFont());
    memo->setPlainText(tableLuaScript_);
    memo->setPlaceholderText("-- Lua that runs when this table is opened; saved with the table.");
    v->addWidget(memo);

    auto* row = new QHBoxLayout;
    auto* execBtn = new QPushButton("Execute script");
    row->addWidget(execBtn);
    row->addStretch();
    auto* closeBtn = new QPushButton("Close");
    row->addWidget(closeBtn);
    v->addLayout(row);

    // Edits are captured live so Close (or saving the table) keeps them.
    connect(memo, &QPlainTextEdit::textChanged, this,
            [this, memo]() { tableLuaScript_ = memo->toPlainText(); });
    // Run it now, through the same engine and against the current process/list as
    // the load-time run. No extra trust prompt: the user typed/edited this here.
    connect(execBtn, &QPushButton::clicked, this, [this, memo]() {
        luaEngine_.setProcess(process_.get());
        luaEngine_.setAddressList(addressListModel_);
        auto res = luaEngine_.evalToString(memo->toPlainText().toStdString());
        statusBar()->showMessage(
            res.has_value() ? "Table Lua executed."
                            : QString("Table Lua error: %1").arg(QString::fromStdString(res.error())),
            8000);
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

// The monospace font from the Settings dialog (display/fontFamily + fontSize),
// used for the results / cheat-table views. Falls back to "Monospace" 9.
static QFont settingsMonospaceFont() {
    QSettings s;
    return QFont(s.value("display/fontFamily", "Monospace").toString(),
                 s.value("display/fontSize", 9).toInt());
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
    // A crisp, purpose-drawn "find process" magnifying glass (drawn at 4x and
    // downscaled) rather than the scaled app logo, so it reads cleanly at button
    // size. The accent blue is legible on both the light and dark process bar.
    QPixmap btnIcon(88, 88);
    btnIcon.setDevicePixelRatio(1.0);
    btnIcon.fill(Qt::transparent);
    {
        QPainter p(&btnIcon);
        p.setRenderHint(QPainter::Antialiasing);
        QPen pen(QColor(0x3f, 0x77, 0xe6));   // accent blue
        pen.setWidthF(8);
        pen.setCapStyle(Qt::RoundCap);
        p.setPen(pen);
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(QPointF(36, 36), 22, 22);      // lens
        p.drawLine(QPointF(52, 52), QPointF(74, 74)); // handle
    }
    openBtn->setIcon(QIcon(btnIcon.scaled(24, 24, Qt::KeepAspectRatio, Qt::SmoothTransformation)));
    openBtn->setIconSize(QSize(24, 24));
    connect(openBtn, &QPushButton::clicked, this, &MainWindow::onOpenProcess);
    processLabel_ = new QLabel("No process selected");
    processLabel_->setStyleSheet("font-weight: bold;");
    processBar->addWidget(openBtn);
    processBar->addWidget(processLabel_, 1);
    mainLayout->addLayout(processBar);

    // ── Top area: results + scan controls ──
    auto* topSplitter = new QSplitter(Qt::Horizontal);
    topSplitter->setObjectName("topSplitter");   // persisted across runs

    // Left: scan results
    auto* leftPanel = new QWidget;
    auto* leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(0, 0, 0, 0);

    resultsModel_ = new ScanResultsModel(this);
    resultsView_ = new QTableView;
    resultsView_->setModel(resultsModel_);
    resultsView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsView_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    resultsView_->setAlternatingRowColors(true);   // activates the theme's zebra rows
    resultsView_->setFont(settingsMonospaceFont());
    resultsView_->verticalHeader()->setVisible(false);
    resultsView_->horizontalHeader()->setStretchLastSection(true);
    // Address sized to its content; Value and Previous share the rest evenly.
    resultsView_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    resultsView_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    resultsView_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    // A centered hint shown over the empty result list so the pane isn't a blank
    // grid before the first scan (a "finished app" touch).
    resultsEmptyHint_ = new QLabel(
        tr("No results yet.\n\nEnter a value and press First Scan,\n"
           "or open a process with Ctrl+O."),
        resultsView_->viewport());
    resultsEmptyHint_->setAlignment(Qt::AlignCenter);
    resultsEmptyHint_->setStyleSheet("color: gray; background: transparent;");
    resultsEmptyHint_->setAttribute(Qt::WA_TransparentForMouseEvents);
    resultsView_->viewport()->installEventFilter(this);
    auto updateResultsHint = [this]() {
        if (!resultsEmptyHint_) return;
        const bool empty = resultsModel_->rowCount() == 0;
        resultsEmptyHint_->setGeometry(resultsView_->viewport()->rect());
        resultsEmptyHint_->setVisible(empty);
    };
    connect(resultsModel_, &QAbstractItemModel::modelReset, this, updateResultsHint);
    connect(resultsModel_, &QAbstractItemModel::rowsInserted, this, updateResultsHint);
    connect(resultsModel_, &QAbstractItemModel::rowsRemoved, this, updateResultsHint);
    updateResultsHint();

    connect(resultsView_, &QTableView::doubleClicked, this, &MainWindow::onResultDoubleClicked);
    // Enter adds all selected results to the address list (complements the
    // context menu's "Add N selected").
    auto* addSelSc = new QShortcut(QKeySequence(Qt::Key_Return), resultsView_);
    addSelSc->setContext(Qt::WidgetShortcut);
    connect(addSelSc, &QShortcut::activated, this, [this]() {
        if (!lastResult_) return;
        auto sel = resultsView_->selectionModel()->selectedRows();
        for (auto& idx : sel)
            addressListModel_->addEntry(resultsModel_->addressAt(idx.row()), lastResultType_,
                                        "No description", "", lastResultValueSize_);
    });
    resultsView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(resultsView_, &QTableView::customContextMenuRequested, this, [this](const QPoint& pos) {
        if (!lastResult_) return;
        auto sel = resultsView_->selectionModel()->selectedRows();
        if (sel.isEmpty()) return;
        QMenu menu(this);
        // CE foundlistpopup order.
        auto* addAct = menu.addAction(sel.size() > 1
            ? QString("Add %1 selected addresses to the addresslist").arg(sel.size())
            : QString("Add selected addresses to the addresslist"));
        auto* browseAct = menu.addAction("Browse this memory region");
        auto* disasmAct = menu.addAction("Disassemble this memory region");
        auto* copyAct = menu.addAction("Copy selected addresses");
        menu.addSeparator();
        auto* accAct = menu.addAction("Find out what accesses this address");
        auto* wrAct  = menu.addAction("Find out what writes to this address");
        QAction* picked = menu.exec(resultsView_->viewport()->mapToGlobal(pos));
        if (!picked) return;
        const uintptr_t firstAddr = resultsModel_->addressAt(sel.first().row());
        if (picked == addAct) {
            for (auto& idx : sel)
                addressListModel_->addEntry(resultsModel_->addressAt(idx.row()), lastResultType_,
                                        "No description", "", lastResultValueSize_);
        } else if (picked == browseAct || picked == disasmAct) {
            // Full-featured viewer (breakpoints, add-to-list, Tools/Debug menus),
            // the same one the Memory View button opens, not a stripped-down clone.
            openMemoryView(firstAddr);
        } else if (picked == copyAct) {
            QStringList addrs;
            for (auto& idx : sel)
                addrs << QString("0x%1").arg(resultsModel_->addressAt(idx.row()), 0, 16);
            QApplication::clipboard()->setText(addrs.join('\n'));
        } else if (picked == accAct) {
            startCodeFinderForAddress(firstAddr, /*writesOnly=*/false);
        } else if (picked == wrAct) {
            startCodeFinderForAddress(firstAddr, /*writesOnly=*/true);
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
        // CE uses formAddressChange for both add and edit.
        ce::gui::ChangeAddressDialog dlg("", mapValueType(valueTypeCombo_->currentIndex()),
                                         false, 1, this);
        dlg.setWindowTitle("Add address");
        if (dlg.exec() != QDialog::Accepted) return;
        auto text = dlg.address();
        if (text.isEmpty()) return;
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
            addressListModel_->addEntry(*addr, dlg.valueType(), "Manual entry", expr);
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

    // Reveal the second value box only for a "Value between..." scan, and grey out
    // the value field(s) for compares that take no value (Unknown/Changed/
    // Unchanged/Increased/Decreased/Same-as-first) so it's clear there is nothing
    // to type, CE-style.
    auto updateBetweenUi = [this]() {
        ScanCompare cmp = mapScanType(scanTypeCombo_->currentIndex());
        bool between = cmp == ScanCompare::Between;
        betweenAndLabel_->setVisible(between);
        scanValue2Edit_->setVisible(between);
        bool takesValue = cmp == ScanCompare::Exact || cmp == ScanCompare::Greater ||
                          cmp == ScanCompare::Less || cmp == ScanCompare::Between ||
                          cmp == ScanCompare::IncreasedBy || cmp == ScanCompare::DecreasedBy;
        scanValueEdit_->setEnabled(takesValue);
        scanValue2Edit_->setEnabled(takesValue);
        hexCheck_->setEnabled(takesValue);
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
        // Hide (not just disable) the float-only rounding/tolerance controls for
        // integer/text scans so the row collapses instead of leaving greyed
        // clutter. Tolerance appears only for the "Extreme" rounding mode.
        floatRoundingCombo_->setVisible(isFloat);
        floatToleranceEdit_->setVisible(isFloat && floatRoundingCombo_->currentIndex() == 3);
        // Type-aware placeholder to guide what to type (AOB wildcards, etc.).
        const char* ph = "e.g. 100";
        switch (vt) {
            case ValueType::Float:
            case ValueType::Double:        ph = "e.g. 3.14"; break;
            case ValueType::String:
            case ValueType::UnicodeString: ph = "text to find"; break;
            case ValueType::ByteArray:     ph = "e.g. 48 8B ?? 05"; break;
            case ValueType::Binary:        ph = "e.g. 0110??01"; break;
            case ValueType::Pointer:       ph = "e.g. 0x7fabc000"; break;
            default:                       ph = "e.g. 100"; break;
        }
        scanValueEdit_->setPlaceholderText(ph);
    };
    connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions](int) { updateFloatOptions(); });
    connect(floatRoundingCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions](int) { updateFloatOptions(); });
    updateFloatOptions();

    // Buttons
    auto* btnLayout = new QHBoxLayout;
    firstScanBtn_ = new QPushButton("First Scan");
    // Accent "primary action" styling comes from the theme (QPushButton#primaryButton).
    firstScanBtn_->setObjectName("primaryButton");
    nextScanBtn_ = new QPushButton("Next Scan");
    nextScanBtn_->setEnabled(false);
    undoScanBtn_ = new QPushButton("Undo Scan");
    undoScanBtn_->setEnabled(false);
    connect(firstScanBtn_, &QPushButton::clicked, this, &MainWindow::onFirstScan);
    connect(nextScanBtn_, &QPushButton::clicked, this, &MainWindow::onNextScan);
    connect(undoScanBtn_, &QPushButton::clicked, this, &MainWindow::onUndoScan);
    // Enter in the value field scans (CE-style): Next Scan when one is in progress,
    // otherwise First Scan. Same for the second ("between") value box.
    auto scanOnEnter = [this]() {
        if (nextScanBtn_->isEnabled()) onNextScan();
        else if (firstScanBtn_->isEnabled()) onFirstScan();
    };
    connect(scanValueEdit_, &QLineEdit::returnPressed, this, scanOnEnter);
    connect(scanValue2Edit_, &QLineEdit::returnPressed, this, scanOnEnter);
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
    // Tri-state like CE: checked = must have the protection, unchecked = must NOT,
    // partial (grey) = don't care. Writable defaults to "must" (values live in
    // writable memory); Executable defaults to "don't care".
    writableCheck_ = new QCheckBox("Writable");
    writableCheck_->setTristate(true);
    writableCheck_->setCheckState(Qt::Checked);
    writableCheck_->setToolTip("Checked: only writable regions. Unchecked: only "
                               "non-writable. Grey: any (don't care).");
    optLayout->addWidget(writableCheck_, 2, 0, 1, 2);
    executableCheck_ = new QCheckBox("Executable");
    executableCheck_->setTristate(true);
    executableCheck_->setCheckState(Qt::PartiallyChecked);
    executableCheck_->setToolTip("Checked: only executable regions. Unchecked: only "
                                 "non-executable. Grey: any (don't care).");
    optLayout->addWidget(executableCheck_, 3, 0, 1, 2);
    fastScanCheck_ = new QCheckBox("Fast Scan");
    fastScanCheck_->setChecked(true);
    optLayout->addWidget(fastScanCheck_, 4, 0);
    alignEdit_ = new QLineEdit("4");
    alignEdit_->setFixedWidth(42);
    optLayout->addWidget(alignEdit_, 4, 1);
    // The alignment field only applies when Fast Scan is on; grey it out otherwise.
    connect(fastScanCheck_, &QCheckBox::toggled, alignEdit_, &QLineEdit::setEnabled);

    // Apply the persisted scan defaults from the Settings dialog (previously these
    // were saved but never used). Writable/Executable store a bool "only-<prot>":
    // true -> require it (checked), false -> don't care (grey); the tri-state's
    // "exclude" (unchecked) isn't a default the settings can express.
    {
        QSettings s;
        writableCheck_->setCheckState(s.value("scan/writable", true).toBool()
                                      ? Qt::Checked : Qt::PartiallyChecked);
        executableCheck_->setCheckState(s.value("scan/executable", false).toBool()
                                        ? Qt::Checked : Qt::PartiallyChecked);
        fastScanCheck_->setChecked(s.value("scan/fast", true).toBool());
        alignEdit_->setText(QString::number(s.value("scan/alignment", 4).toInt()));
        alignEdit_->setEnabled(fastScanCheck_->isChecked());
        int dvt = s.value("scan/defaultValueType", 2).toInt();
        if (dvt >= 0 && dvt < valueTypeCombo_->count()) valueTypeCombo_->setCurrentIndex(dvt);
    }

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
        // Hide (not just grey) the percent value fields until "Compare by %" is on,
        // and the "Percent max" row until the scan is a "between" compare, so the
        // options group collapses instead of showing dead controls. Keep enabled
        // in sync with visible (the fields start disabled).
        percentValueEdit_->setVisible(enabled);
        percentValueEdit_->setEnabled(enabled);
        percent2Label->setVisible(needsUpper);
        percentValue2Edit_->setVisible(needsUpper);
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
    addressListView_->setAlternatingRowColors(true);   // activates the theme's zebra rows
    // Centered hint over the empty cheat table (matches the results-list hint).
    tableEmptyHint_ = new QLabel(
        tr("No saved addresses.\n\nDouble-click a scan result to add it here,\n"
           "or use Add Address."),
        addressListView_->viewport());
    tableEmptyHint_->setAlignment(Qt::AlignCenter);
    tableEmptyHint_->setStyleSheet("color: gray; background: transparent;");
    tableEmptyHint_->setAttribute(Qt::WA_TransparentForMouseEvents);
    addressListView_->viewport()->installEventFilter(this);
    auto updateTableHint = [this]() {
        if (!tableEmptyHint_) return;
        tableEmptyHint_->setGeometry(addressListView_->viewport()->rect());
        tableEmptyHint_->setVisible(addressListModel_->rowCount() == 0);
    };
    connect(addressListModel_, &QAbstractItemModel::modelReset, this, updateTableHint);
    connect(addressListModel_, &QAbstractItemModel::rowsInserted, this, updateTableHint);
    connect(addressListModel_, &QAbstractItemModel::rowsRemoved, this, updateTableHint);
    // Row visibility (collapsed groups) is a view property that a model reset or a
    // structural change clears, so re-hide the collapsed children whenever that happens.
    connect(addressListModel_, &QAbstractItemModel::modelReset, this, &MainWindow::reapplyGroupCollapse);
    connect(addressListModel_, &QAbstractItemModel::rowsInserted, this, &MainWindow::reapplyGroupCollapse);
    connect(addressListModel_, &QAbstractItemModel::rowsRemoved, this, &MainWindow::reapplyGroupCollapse);
    connect(addressListModel_, &QAbstractItemModel::layoutChanged, this, &MainWindow::reapplyGroupCollapse);
    // Surface a reverted (protected) manual edit as a status-bar hint toward
    // find-what-writes, so "my edit doesn't stick" has an explanation.
    connect(addressListModel_, &AddressListModel::valueReverted, this,
        [this](uintptr_t addr, const QString& wrote, const QString& now) {
            statusBar()->showMessage(
                QString("Value at 0x%1 was reverted (wrote %2, now %3). It looks protected: "
                        "right-click the entry and choose \"Find what writes\" to locate the "
                        "code that overwrites it.").arg(addr, 0, 16).arg(wrote).arg(now), 9000);
        });
    updateTableHint();
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
    addressListView_->setFont(settingsMonospaceFont());
    addressListView_->verticalHeader()->setVisible(false);
    addressListView_->horizontalHeader()->setStretchLastSection(true);
    addressListView_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    // Double-clicking a script entry's Address/Type/Value cell (which carry no
    // editable data for a script) opens the auto-assembler editor for it. The
    // Description cell still edits inline.
    connect(addressListView_, &QAbstractItemView::doubleClicked, this,
            [this](const QModelIndex& idx) {
        if (!idx.isValid()) return;
        // Double-clicking a group header (outside its editable Description) collapses or
        // expands it, hiding/showing its children like a CE tree node.
        if (idx.column() != 1 && addressListModel_->toggleGroupCollapse(idx.row())) {
            reapplyGroupCollapse();
            return;
        }
        if (idx.column() != 1 && addressListModel_->isScriptEntry(idx.row())) {
            editScriptEntry(idx.row());
            return;
        }
        // CE: double-clicking the Address cell browses that address in the Memory
        // Viewer, focusing the disassembler for code or the hex dump for data
        // (Shift forces the disassembler, Ctrl forces the hex dump).
        if (idx.column() == 2) {
            const int row = idx.row();
            const auto& ents = addressListModel_->entries();
            if (row < 0 || row >= (int)ents.size()) return;
            const auto& e = ents[row];
            if (e.isGroup || addressListModel_->isScriptEntry(row) || e.address == 0) return;
            auto* mv = openMemoryView(e.address);
            if (!mv) return;
            bool exec = false;
            if (process_) {
                if (auto rg = process_->queryRegion(e.address))
                    exec = (rg->protection & ce::MemProt::Exec);
            }
            const auto mods = QApplication::keyboardModifiers();
            const auto pane = ce::chooseMemViewPane(exec, mods & Qt::ShiftModifier,
                                                    mods & Qt::ControlModifier);
            mv->focusPane(pane == ce::MemViewPane::Disassembler
                              ? MemoryBrowser::Pane::Disassembler
                              : MemoryBrowser::Pane::HexDump);
        }
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
            } else if (selected.size() == 1 && firstRow < (int)addressListModel_->entries().size()
                       && !addressListModel_->entries()[firstRow].isGroup) {
                // CE "Change address" (formAddressChangeUnit): edit address/type/flags.
                menu.addAction("Change address...", [this, firstRow]() {
                    const auto& e = addressListModel_->entries()[firstRow];
                    QString addrStr = !e.addressExpr.isEmpty()
                        ? e.addressExpr : QString("%1").arg((qulonglong)e.address, 0, 16);
                    ce::gui::ChangeAddressDialog dlg(addrStr, e.type, e.showAsHex,
                                                     (int)e.byteCount, this, e.showAsSigned);
                    if (dlg.exec() != QDialog::Accepted) return;
                    const int id = e.id;
                    const QString a = dlg.address();
                    bool numeric = false;
                    qulonglong v = a.toULongLong(&numeric, 16);
                    if (numeric && !a.contains('[') && !a.contains('+') && !a.contains(' '))
                        addressListModel_->setAddress(id, (uintptr_t)v);
                    else
                        addressListModel_->setAddressExpression(id, a.toStdString());
                    const ce::ValueType nt = dlg.valueType();
                    addressListModel_->setType(id, nt);
                    addressListModel_->setHexView(id, dlg.showHex());
                    addressListModel_->setSigned(id, dlg.isSigned());
                    // Length applies to String / Array of byte (and Unicode strings).
                    if (nt == ce::ValueType::String || nt == ce::ValueType::UnicodeString ||
                        nt == ce::ValueType::ByteArray)
                        addressListModel_->setByteCount(id, (std::size_t)dlg.length());
                });
                menu.addSeparator();
            }

            // CE PopupMenu2: Cut / Copy / Paste (PasteTableentryFRM).
            menu.addAction("Cut", this, [this]() { onCopyAddresses(); onDeleteAddresses(); }, QKeySequence::Cut);
            menu.addAction("Copy", this, &MainWindow::onCopyAddresses, QKeySequence::Copy);
            menu.addAction("Paste", this, [this]() {
                auto doc = QJsonDocument::fromJson(QApplication::clipboard()->text().toUtf8());
                if (!doc.isArray()) return;
                for (auto v : doc.array()) {
                    auto o = v.toObject();
                    uintptr_t addr = o["address"].toString().toULongLong(nullptr, 16);
                    QString expr = o["addressExpr"].toString();
                    QString ts = o["type"].toString();
                    ce::ValueType t = ts == "byte"    ? ce::ValueType::Byte
                                    : ts == "i16"     ? ce::ValueType::Int16
                                    : ts == "i64"     ? ce::ValueType::Int64
                                    : ts == "float"   ? ce::ValueType::Float
                                    : ts == "double"  ? ce::ValueType::Double
                                    : ts == "pointer" ? ce::ValueType::Pointer
                                                      : ce::ValueType::Int32;
                    addressListModel_->addEntry(addr, t, o["description"].toString(), expr);
                }
            }, QKeySequence::Paste);
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
            if (selected.size() == 1) {
                int row = selected.first().row();
                auto* up = menu.addAction("Move Up", [this, row]() { moveSelectedEntry(row, -1); });
                up->setShortcut(QKeySequence("Ctrl+Up"));
                auto* down = menu.addAction("Move Down", [this, row]() { moveSelectedEntry(row, +1); });
                down->setShortcut(QKeySequence("Ctrl+Down"));
            }

            menu.addSeparator();
            // Set the value of ALL selected entries at once (CE's batch set value).
            menu.addAction("Set value...", [this, selected]() {
                // Pre-fill with the first selected entry's current value (in its display
                // format), like CE, so the user edits from the existing value not a blank.
                QString initial;
                const auto& ents = addressListModel_->entries();
                for (const auto& idx : selected) {
                    int r = idx.row();
                    if (r >= 0 && r < (int)ents.size() && !ents[r].isGroup) {
                        const QString& cv = ents[r].currentValue;
                        if (cv != "?" && cv != "??") initial = cv;
                        break;
                    }
                }
                bool ok = false;
                QString v = QInputDialog::getText(this, "Set value",
                    QString("New value for %1 selected entr%2:")
                        .arg(selected.size()).arg(selected.size() == 1 ? "y" : "ies"),
                    QLineEdit::Normal, initial, &ok);
                if (!ok) return;
                // A group header has no value of its own, so setting a group applies the
                // value to its child entries recursively (CE moRecursiveSetValue). A set
                // dedupes when a group and its child are both selected.
                std::vector<int> indents;
                indents.reserve(ents.size());
                for (const auto& e : ents) indents.push_back(e.indent);
                std::set<int> targets;
                for (const auto& idx : selected) {
                    int r = idx.row();
                    if (r < 0 || r >= (int)ents.size()) continue;
                    if (ents[r].isGroup) {
                        auto [b, en] = ce::descendantRange(indents, (size_t)r);
                        for (size_t i = b; i < en; ++i)
                            if (!ents[i].isGroup) targets.insert((int)i);
                    } else {
                        targets.insert(r);
                    }
                }
                for (int r : targets)
                    addressListModel_->setEntryValueTo(r, v);
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

            // Obfuscated values: declare a codec so the value is displayed decoded and
            // edited/frozen by its logical value (block 6). Reuses ce::ValueCodec::parse.
            menu.addAction("Set value codec...", [this, selected]() {
                if (selected.isEmpty()) return;
                QString cur = QString::fromStdString(
                    addressListModel_->entryCodecSpec(selected.first().row()));
                bool ok = false;
                QString spec = QInputDialog::getText(this, "Value codec",
                    "Obfuscation codec for the stored value:\n"
                    "  none | xor:0xKEY | add:N | rol:N | ror:N\n"
                    "(stored as encode(logical); display decodes, edit/freeze encode)",
                    QLineEdit::Normal, cur, &ok);
                if (!ok) return;
                spec = spec.trimmed();
                ce::ValueCodec codec;   // default: none
                if (!spec.isEmpty() && spec.compare("none", Qt::CaseInsensitive) != 0) {
                    auto c = ce::ValueCodec::parse(spec.toStdString());
                    if (!c) {
                        QMessageBox::warning(this, "Invalid codec",
                            "Use none, xor:0xKEY, add:N, rol:N, or ror:N.");
                        return;
                    }
                    codec = *c;
                }
                for (auto& idx : selected) addressListModel_->setEntryCodec(idx.row(), codec);
            });

            // Big-endian value (emulated PS3 / Wii / GameCube): display byte-swaps to
            // host order and edits swap back. Guest-scan results set this automatically.
            auto* beAction = menu.addAction("Big-endian value");
            beAction->setCheckable(true);
            beAction->setChecked(addressListModel_->entryBigEndian(selected.first().row()));
            connect(beAction, &QAction::toggled, this, [this, selected](bool on) {
                for (auto& idx : selected) addressListModel_->setEntryBigEndian(idx.row(), on);
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
                    if (row < (int)entries.size())
                        openMemoryView(entries[row].address);   // full-featured viewer
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
            // CE "Pointer scan for this address".
            if (firstRow >= 0 && firstRow < (int)ents0.size()
                && !ents0[firstRow].isGroup && ents0[firstRow].autoAsmScript.isEmpty()) {
                menu.addAction("Pointer scan for this address", [this, selected]() {
                    if (!process_ || selected.isEmpty()) return;
                    auto* dlg = new PointerScanDialog(process_.get(), this);
                    dlg->setAttribute(Qt::WA_DeleteOnClose);
                    connect(dlg, &PointerScanDialog::addressSelected, this,
                            [this](uintptr_t addr, const QString& desc) {
                                addressListModel_->addEntry(addr, ce::ValueType::Int32, desc);
                            });
                    dlg->show();
                });
            }
            // CE "Change Color" — per-record display color.
            menu.addAction("Change Color...", [this, selected]() {
                const auto& entries = addressListModel_->entries();
                if (selected.isEmpty()) return;
                int row = selected.first().row();
                QColor initial = (row < (int)entries.size() && !entries[row].color.isEmpty())
                    ? QColor(entries[row].color) : QColor(Qt::black);
                QColor c = QColorDialog::getColor(initial, this, "Change record color");
                if (!c.isValid()) return;
                for (const auto& idx : selected)
                    if (idx.row() < (int)entries.size())
                        addressListModel_->setColor(entries[idx.row()].id, c.name().toStdString());
            });
            // CE "Set/Change dropdown selection options".
            if (selected.size() == 1) {
                menu.addAction("Set/Change dropdown selection options...", [this, firstRow]() {
                    const auto& entries = addressListModel_->entries();
                    if (firstRow >= (int)entries.size()) return;
                    bool ok = false;
                    QString v = QInputDialog::getMultiLineText(this, "Dropdown options",
                        "One \"value:label\" per line (or value alone):",
                        addressListModel_->dropdownList(firstRow).split(';').join('\n'), &ok);
                    if (ok)
                        addressListModel_->setDropdownList(entries[firstRow].id,
                                                           v.split('\n', Qt::SkipEmptyParts).join(';'));
                });
            }
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
            // CE's "Add Address Manually" opens the same formAddressChangeUnit as
            // "Change address", so a new entry gets its type, flags, length, and an
            // optional structured pointer in one dialog.
            ce::gui::ChangeAddressDialog dlg("", mapValueType(valueTypeCombo_->currentIndex()),
                                             false, 0, this);
            if (dlg.exec() != QDialog::Accepted) return;
            const QString a = dlg.address();
            if (a.trimmed().isEmpty()) return;
            bool numeric = false;
            qulonglong v = a.toULongLong(&numeric, 16);
            int id;
            if (numeric && !a.contains('[') && !a.contains('+') && !a.contains(' ')) {
                id = addressListModel_->addEntry((uintptr_t)v, dlg.valueType(),
                                                 "No description", QString(), (size_t)dlg.length());
            } else {
                // Symbolic / module+offset / pointer chain: store the expression so it
                // re-resolves live, seeding the initial numeric address if resolvable.
                uintptr_t addr0 = 0;
                if (auto r = parseAddressExpr(a)) addr0 = *r;
                id = addressListModel_->addEntry(addr0, dlg.valueType(),
                                                 "No description", a, (size_t)dlg.length());
            }
            addressListModel_->setHexView(id, dlg.showHex());
            addressListModel_->setSigned(id, dlg.isSigned());
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
    // Ctrl+Up / Ctrl+Down reorder the selected cheat-table entry (CE-style).
    auto moveSel = [this](int delta) {
        auto sel = addressListView_->selectionModel()->selectedRows();
        if (sel.size() == 1) moveSelectedEntry(sel.first().row(), delta);
    };
    auto* moveUpSc = new QShortcut(QKeySequence("Ctrl+Up"), addressListView_);
    moveUpSc->setContext(Qt::WidgetShortcut);
    connect(moveUpSc, &QShortcut::activated, this, [moveSel]() { moveSel(-1); });
    auto* moveDownSc = new QShortcut(QKeySequence("Ctrl+Down"), addressListView_);
    moveDownSc->setContext(Qt::WidgetShortcut);
    connect(moveDownSc, &QShortcut::activated, this, [moveSel]() { moveSel(+1); });
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

    // Scan controls, laid out with real Qt layouts (no fixed pixel coordinates,
    // so it scales with font size / DPI and leaves no dead space): a button row,
    // a right-aligned label/field form, and the Memory Scan Options group.
    auto* controls = new QWidget;
    controls->setMaximumWidth(440);
    auto* cv = new QVBoxLayout(controls);
    cv->setContentsMargins(6, 0, 0, 0);
    cv->setSpacing(6);

    auto* scanBtnRow = new QHBoxLayout;
    scanBtnRow->setSpacing(4);
    scanBtnRow->addWidget(firstScanBtn_);
    scanBtnRow->addWidget(nextScanBtn_);
    scanBtnRow->addWidget(undoScanBtn_);
    cv->addLayout(scanBtnRow);

    auto* scanForm = new QGridLayout;
    scanForm->setHorizontalSpacing(6);
    scanForm->setVerticalSpacing(6);
    scanForm->setColumnStretch(1, 1);
    scanForm->addWidget(new QLabel("Scan Value"), 0, 0, Qt::AlignRight | Qt::AlignVCenter);
    auto* valRow = new QHBoxLayout;
    valRow->setSpacing(4);
    valRow->addWidget(scanValueEdit_, 1);
    valRow->addWidget(betweenAndLabel_);
    valRow->addWidget(scanValue2Edit_, 1);
    valRow->addWidget(hexCheck_);
    scanForm->addLayout(valRow, 0, 1);
    scanForm->addWidget(new QLabel("Scan Type"), 1, 0, Qt::AlignRight | Qt::AlignVCenter);
    scanForm->addWidget(scanTypeCombo_, 1, 1);
    scanForm->addWidget(new QLabel("Value Type"), 2, 0, Qt::AlignRight | Qt::AlignVCenter);
    scanForm->addWidget(valueTypeCombo_, 2, 1);
    auto* floatRow2 = new QHBoxLayout;
    floatRow2->setSpacing(4);
    floatRow2->addWidget(floatRoundingCombo_);
    floatRow2->addWidget(floatToleranceEdit_);
    floatRow2->addStretch();
    scanForm->addLayout(floatRow2, 3, 1);
    cv->addLayout(scanForm);

    // Memory Scan Options group (From/To, Writable/Executable, Fast Scan, etc.).
    cv->addWidget(optGroup);
    cv->addStretch(1);
    mainRow->addWidget(controls);
    sv->addLayout(mainRow, 1);

    // These start hidden; their visibility is driven by scan state, not the layout
    // (progress bar shows while scanning; the "and"/second-value box only for a
    // "Value between..." scan).
    progressBar_->setVisible(false);
    betweenAndLabel_->setVisible(false);
    scanValue2Edit_->setVisible(false);

    // ── Assemble: scan panel (top) / cheat table (bottom) / actions bar ──
    auto* newCentral = new QWidget;
    auto* v = new QVBoxLayout(newCentral);
    v->setContentsMargins(2, 2, 2, 2);
    v->setSpacing(2);

    auto* vsplit = new QSplitter(Qt::Vertical);
    vsplit->setObjectName("vsplit");   // persisted across runs
    vsplit->addWidget(scanPanel);
    vsplit->addWidget(addressListView_);
    vsplit->setStretchFactor(0, 0);
    vsplit->setStretchFactor(1, 1);
    vsplit->setSizes({440, 220});
    v->addWidget(vsplit, 1);
    addressListView_->setMinimumHeight(90);

    auto* bottomBar = new QHBoxLayout;
    auto* advBtn = new QPushButton("Advanced Options");
    // CE "Advanced Options" = the Code list (AdvancedOptionsUnit): a persistent
    // list of code addresses from find-what-writes, with disassemble/NOP/restore.
    connect(advBtn, &QPushButton::clicked, this, &MainWindow::showAdvancedOptions);
    auto* extrasBtn = new QPushButton("Table Extras");
    // CE "Table Extras" opens the table notes (Comments) — a free-text memo saved
    // with the table. (Save/Load now live in the File menu.)
    connect(extrasBtn, &QPushButton::clicked, this, &MainWindow::showComments);
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

// One-click elevation: use pkexec (graphical polkit prompt) to grant memory-read
// access. For a real installed/dev binary that means setcap cap_sys_ptrace+ep on it
// (persistent, targeted, effective after a restart). For an AppImage the capability
// can't persist on the read-only temp mount, so lower kernel.yama.ptrace_scope
// instead (effective immediately, resets on reboot — the .deb sets it up permanently).
static void grantPtraceAccess(QWidget* parent) {
    const QString bin = QCoreApplication::applicationFilePath();
    const bool isAppImage = qEnvironmentVariableIsSet("APPIMAGE") || bin.contains("/.mount_");

    QStringList args;
    QString followup;
    if (isAppImage) {
        args = {QStringLiteral("/bin/sh"), QStringLiteral("-c"),
                QStringLiteral("echo 0 > /proc/sys/kernel/yama/ptrace_scope")};
        followup = QObject::tr("Access granted for this session; re-open the process.\n"
                               "(This resets on reboot. Install the .deb, or re-run the "
                               "command, to make it permanent.)");
    } else {
        const QString cescan = QFileInfo(bin).absolutePath() + QStringLiteral("/cescan");
        args = {QStringLiteral("/bin/sh"), QStringLiteral("-c"),
                QStringLiteral("setcap cap_sys_ptrace+ep \"$1\"; "
                               "[ -x \"$2\" ] && setcap cap_sys_ptrace+ep \"$2\" || true"),
                QStringLiteral("sh"), bin, cescan};
        followup = QObject::tr("Access granted. Restart Cheat Engine for it to take effect.");
    }

    int rc = QProcess::execute(QStringLiteral("pkexec"), args);
    if (rc == 0)
        QMessageBox::information(parent, QObject::tr("Access granted"), followup);
    else
        QMessageBox::warning(parent, QObject::tr("Could not grant access"),
            QObject::tr("The privileged command was cancelled or failed (pkexec exit %1). "
                        "You can still grant access manually from a terminal.").arg(rc));
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

    QMessageBox box(parent);
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle(QObject::tr("Process memory not readable"));
    box.setText(QObject::tr(
        "Cannot read the memory of PID %1 (%2).\n\n"
        "Linux only lets a program read another process's memory if it is allowed "
        "to ptrace it. With kernel.yama.ptrace_scope = %3, that means the target "
        "must be a child of Cheat Engine, or Cheat Engine must run with elevated "
        "rights. Scanning, memory browsing and debugging this process will not work "
        "until that is granted.").arg(pid).arg(name).arg(scope));
    box.setInformativeText(QObject::tr(
        "\"Grant access\" will ask for your password (via pkexec) and set it up for "
        "you. Or do it manually:\n"
        "  • Persistent, per-binary:  sudo setcap cap_sys_ptrace+ep %1\n"
        "  • Whole system, until reboot:  sudo sysctl kernel.yama.ptrace_scope=0")
        .arg(QCoreApplication::applicationFilePath()));

    // Offer one-click elevation only when pkexec (polkit) is actually available.
    QPushButton* grantBtn = nullptr;
    const bool havePkexec = !QStandardPaths::findExecutable(QStringLiteral("pkexec")).isEmpty();
    if (havePkexec)
        grantBtn = box.addButton(QObject::tr("Grant access…"), QMessageBox::AcceptRole);
    box.addButton(QMessageBox::Close);
    box.exec();

    if (grantBtn && box.clickedButton() == grantBtn)
        grantPtraceAccess(parent);
}

void MainWindow::attachToPid(pid_t pid, const QString& name) {
    currentPid_ = pid;
    // A Debugger window from a previous target holds a ptrace attachment and a
    // pointer to the ProcessHandle we are about to replace. Tear it down
    // synchronously (not close(), which defers deletion past the reset below) so
    // its detach runs against the still-valid handle and frees ptrace for the new
    // attach.
    if (debuggerWindow_) delete debuggerWindow_;
    // Freeze any Memory Viewers on the previous target for the same reason: the
    // handle they point at is replaced (destroyed) on the next line.
    for (auto& mv : memoryViewers_) if (mv) mv->detachFromTarget();
    memoryViewers_.clear();
    for (auto& sd : structDissectors_) if (sd) sd->detachFromTarget();
    structDissectors_.clear();
    ceserverClient_.reset();
    process_ = std::make_unique<os::LinuxProcessHandle>(pid);
    // Resolve a readable name so the header isn't "PID: 1234 - 1234" when we were
    // handed a bare pid (--pid, or a caller that didn't know the name): read the
    // process's own /proc/<pid>/comm (e.g. "sleep"), falling back to the number.
    QString label = name;
    if (label.isEmpty()) {
        QFile comm(QString("/proc/%1/comm").arg(pid));
        if (comm.open(QIODevice::ReadOnly))
            label = QString::fromUtf8(comm.readAll()).trimmed();
        if (label.isEmpty()) label = QString::number(pid);
    }
    processLabel_->setText(QString("PID: %1 - %2").arg(pid).arg(label));
    setWindowTitle(QString("Cheat Engine - %1 (%2)").arg(label).arg(pid));
    warnIfMemoryUnreadable(this, process_.get(), pid, label);
    addressListModel_->setProcess(process_.get());
    resultsModel_->setProcess(process_.get());
    // Keep the shared Lua engine pointed at the current target, so scripts (and an
    // already-open Lua Engine console) operate on this process after a re-attach,
    // not a stale one. The address list model is persistent; bind it too.
    luaEngine_.setProcess(process_.get());
    luaEngine_.setAddressList(addressListModel_);
    firstScanBtn_->setEnabled(true);
    resultsModel_->clear();
    lastResult_.reset();
    undoResult_.reset();
    lastResultType_ = ValueType::Int32;
    undoResultType_ = ValueType::Int32;
    lastResultValueSize_ = 0;
    undoResultValueSize_ = 0;
    updateScanButtons();

    // Honest reporting: tell the user up-front what kind of target this is (Wine,
    // emulator, managed runtime, sandboxed, already-traced) so any limitation is an
    // explicit note, not a silent surprise later. See docs/CHALLENGING_TARGETS.md.
    {
        ce::TargetProfile prof = ce::probeTarget(pid);
        statusBar()->showMessage(
            QString("Attached to %1: %2").arg(label, QString::fromStdString(prof.summary())), 8000);
        // The summary + every note live on the process label's tooltip (persistent,
        // non-intrusive; hover to read).
        QString tip = QString::fromStdString(prof.summary());
        for (const auto& n : prof.notes) tip += "\n\n• " + QString::fromStdString(n);
        processLabel_->setToolTip(tip);
        // The one note that means nothing will work at all (attach/watch/inject all
        // fail) is worth an explicit dialog: the target is already being traced.
        if (prof.tracerPid != 0 && !prof.notes.empty())
            QMessageBox::warning(this, "Target already being traced",
                QString::fromStdString(prof.notes.front()));
    }
}

void MainWindow::onOpenProcess() {
    ProcessListDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted)
        attachToPid(dlg.selectedPid(), dlg.selectedName());
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


namespace {
// The scheduler state char from /proc/<pid>/stat ('R','S','T',…), or '?'.
char processStateChar(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return '?';
    char buf[512];
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = '\0';
    // comm (field 2) is parenthesised and may contain spaces; state follows the
    // last ')'.
    char* rp = std::strrchr(buf, ')');
    if (!rp) return '?';
    ++rp;
    while (*rp == ' ') ++rp;
    return *rp ? *rp : '?';
}

// SIGSTOP the target on construction, SIGCONT on destruction (best-effort), to
// freeze it for a scan ("Pause while scanning"). Does nothing if the target is
// already stopped (e.g. manually paused) so we never resume a process we didn't
// suspend.
struct ScopedSigstop {
    pid_t pid; bool active;
    ScopedSigstop(pid_t p, bool a) : pid(p), active(false) {
        if (!a || p <= 0 || processStateChar(p) == 'T') return;
        active = true;
        ::kill(pid, SIGSTOP);
    }
    ~ScopedSigstop() { if (active) ::kill(pid, SIGCONT); }
    ScopedSigstop(const ScopedSigstop&) = delete;
    ScopedSigstop& operator=(const ScopedSigstop&) = delete;
};
} // namespace

std::unique_ptr<ScanResult> MainWindow::runScanWithProgress(
    const std::function<ScanResult()>& scanFn) {
    // Optionally freeze the target for the whole scan so it's a consistent snapshot.
    ScopedSigstop pause(currentPid_, pauseWhileScanning_);
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

bool MainWindow::eventFilter(QObject* obj, QEvent* ev) {
    if (ev->type() == QEvent::Resize) {
        if (resultsEmptyHint_ && resultsView_ && obj == resultsView_->viewport())
            resultsEmptyHint_->setGeometry(resultsView_->viewport()->rect());
        if (tableEmptyHint_ && addressListView_ && obj == addressListView_->viewport())
            tableEmptyHint_->setGeometry(addressListView_->viewport()->rect());
    }
    return QMainWindow::eventFilter(obj, ev);
}

void MainWindow::onFirstScan() {
    // "New Scan" mode: a scan session is open, so this click resets to the
    // pre-scan state (clears results, unlocks the value type) rather than
    // scanning. The next click then runs a fresh First Scan.
    if (lastResult_ != nullptr) {
        resultsModel_->clear();
        lastResult_.reset();
        undoResult_.reset();
        foundLabel_->setText("Found: 0");
        statusBar()->showMessage("New scan: pick a value type and value, then First Scan.", 4000);
        updateScanButtons();
        return;
    }
    if (!process_) {
        statusBar()->showMessage("No process attached; open one first (Ctrl+O) to scan.", 4000);
        return;
    }

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
    auto toMatch = [](Qt::CheckState s) {
        return s == Qt::Checked   ? ce::ProtMatch::Yes
             : s == Qt::Unchecked ? ce::ProtMatch::No
                                  : ce::ProtMatch::Any;   // PartiallyChecked
    };
    config.writableMatch   = toMatch(writableCheck_->checkState());
    config.executableMatch = toMatch(executableCheck_->checkState());

    auto text = scanValueEdit_->text();
    int intBase = (hexCheck_ && hexCheck_->isChecked()) ? 16 : 10;
    if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
        config.stringValue = text.toStdString();
        if (config.valueType == ValueType::String)
            config.stringEncoding = stringEncodingCombo_->currentText().toStdString();
        // Case sensitivity applies to both Text and Unicode Text (set unconditionally).
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

    foundLabel_->setText(foundLabelText(result->count()));
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
    if (!process_) {
        statusBar()->showMessage("No process attached; open one first (Ctrl+O) to scan.", 4000);
        return;
    }
    if (!lastResult_) {
        statusBar()->showMessage("Run a First Scan before a Next Scan.", 4000);
        return;
    }

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
        // Case sensitivity applies to both Text and Unicode Text (set unconditionally).
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

    foundLabel_->setText(foundLabelText(result->count()));
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
    foundLabel_->setText(foundLabelText(lastResult_->count()));
    updateScanButtons();
}

void MainWindow::onResultDoubleClicked(const QModelIndex& index) {
    if (!lastResult_) return;
    auto addr = resultsModel_->addressAt(index.row());
    addressListModel_->addEntry(addr, lastResultType_, "No description", "", lastResultValueSize_);
}

void MainWindow::onDeleteAddresses() {
    auto selected = addressListView_->selectionModel()->selectedRows();
    if (selected.isEmpty()) return;
    QList<int> rows;
    for (auto& idx : selected) rows.append(idx.row());
    addressListModel_->removeEntries(rows);
}

void MainWindow::moveSelectedEntry(int row, int delta) {
    int nr = addressListModel_->moveEntry(row, delta);
    if (nr != row) addressListView_->selectRow(nr);
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
    const QString clip = QApplication::clipboard()->text();
    QJsonArray pasted;
    // Cheat Engine copies records as a <CheatEntries> XML fragment; accept that too
    // so entries can be pasted straight from a CE session (or a shared table
    // snippet), not only from our own JSON copy.
    if (clip.contains(QLatin1String("<CheatEntry"))) {
        ce::CheatTable t;
        if (t.loadFromString(clip.toStdString()))
            pasted = cheatEntriesToJson(t);
    } else {
        QJsonParseError error{};
        auto doc = QJsonDocument::fromJson(clip.toUtf8(), &error);
        if (error.error != QJsonParseError::NoError)
            return;
        if (doc.isArray())
            pasted = doc.array();
        else if (doc.isObject())
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

void MainWindow::closeEvent(QCloseEvent* ev) {
    // Remember where the user put the window and how they sized the panels, so
    // the next launch comes up the same (restored in the constructor).
    QSettings s;
    s.setValue("mainwindow/geometry", saveGeometry());
    for (auto* sp : findChildren<QSplitter*>())
        if (!sp->objectName().isEmpty())
            s.setValue("mainwindow/splitter/" + sp->objectName(), sp->saveState());
    QMainWindow::closeEvent(ev);
}

MainWindow::~MainWindow() {
    // Stop every "find what writes/accesses" monitor (joining its background thread)
    // BEFORE any members are destroyed. Each monitor thread uses process_ and its
    // ce::Debugger, and member destruction runs in reverse declaration order (the
    // Debuggers would otherwise be freed while a monitor thread is still calling
    // dbg_->getContext() on a live hit — a use-after-free crash at exit).
    for (auto& f : codeFinders_)
        if (f) f->stop();
    codeFinders_.clear();
    codeFinderDebuggers_.clear();

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
    // The browser's step buttons open the full Debugger (which owns the debug
    // session and does real single-stepping).
    browser->setDebuggerLauncher([this](uintptr_t /*addr*/) { showDebugger(); });
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
    // Tools > Dissect data/structures opens a Structure Dissector at the address.
    browser->setDissectOpener([this](uintptr_t addr) {
        if (!process_) return;
        auto* sd = new StructureDissector(process_.get(), addr, this);
        sd->setAttribute(Qt::WA_DeleteOnClose);
        sd->setAddToListCallback([this](uintptr_t a, ce::ValueType t, const QString& d) {
            addressListModel_->addEntry(a, t, d);
        });
        trackStructDissector(sd);
        sd->show();
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
    editor->setWindowTitle("Auto Assembler: " + desc);
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
    table.comment = tableComment_.toStdString();   // table notes (Comments window)
    table.luaScript = tableLuaScript_.toStdString();  // table-level Lua (CE <LuaScript>)
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
        e.showAsSigned = obj["showAsSigned"].toBool(true);
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
        e.collapsed = obj["collapsed"].toBool();
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

void MainWindow::onSaveScanResults() {
    const int rows = resultsModel_ ? resultsModel_->rowCount() : 0;
    if (rows == 0) {
        statusBar()->showMessage("No scan results to save.", 4000);
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, "Save current scan results",
        "scanresults.txt", "Text (*.txt);;CSV (*.csv);;All files (*)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        statusBar()->showMessage("Could not open the file for writing.", 4000);
        return;
    }
    // Tab-separated by default; comma when the user picks a .csv name. Values come
    // through the model's own formatter, so they match exactly what's on screen.
    const bool csv = path.endsWith(".csv", Qt::CaseInsensitive);
    const QChar sep = csv ? QChar(',') : QChar('\t');
    QTextStream out(&f);
    out << "Address" << sep << "Value" << '\n';
    for (int r = 0; r < rows; ++r) {
        const QString addr = resultsModel_->data(resultsModel_->index(r, 0), Qt::DisplayRole).toString();
        const QString val  = resultsModel_->data(resultsModel_->index(r, 1), Qt::DisplayRole).toString();
        out << addr << sep << val << '\n';
    }
    QString msg = QString("Saved %1 results to %2").arg(rows).arg(QFileInfo(path).fileName());
    if (lastResult_ && lastResult_->count() > static_cast<size_t>(rows))
        msg += QString(" (list capped at %1 of %2 found)").arg(rows).arg(lastResult_->count());
    statusBar()->showMessage(msg, 6000);
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
        addRecentTable(path);
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
        if (f.open(QIODevice::WriteOnly)) {
            f.write(QJsonDocument(root).toJson());
            addRecentTable(path);
        }
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
// Convert a parsed CheatTable's records into the address-list JSON schema
// (the same shape AddressListModel::toJson emits), computing each record's indent
// from the parentId tree. Shared by full-table load (replace) and clipboard paste
// of CE XML (append).
static QJsonArray cheatEntriesToJson(const ce::CheatTable& table) {
    QJsonArray arr;
    // Compute each entry's nesting level from the parentId tree (entries are in
    // document order, parents before children) so imported groups indent in the
    // address list, which tracks hierarchy by indent depth.
    std::unordered_map<int, int> indentById;
    for (const auto& e : table.entries) {
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
        obj["showAsSigned"] = e.showAsSigned;
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
        obj["collapsed"] = e.collapsed;
        obj["parent"] = e.parentId;
        arr.append(obj);
    }
    return arr;
}

// Populate the address list (and table comment / disassembler annotations / table
// Lua) from a parsed CheatTable. Shared by every load path that yields a
// CheatTable model (CE XML .CT and password-protected .CETRAINER), so they behave
// identically. JSON goes through its own reader below.
void MainWindow::loadCheatTableModel(const ce::CheatTable& table) {
    tableComment_ = QString::fromStdString(table.comment);   // table notes
    QJsonArray arr = cheatEntriesToJson(table);
    loadAddressEntries(arr);
    // Retain the table-level Lua script so it can be viewed/edited (Table > Show
    // Cheat Table Lua Script) and re-saved, not just run once on load.
    tableLuaScript_ = QString::fromStdString(table.luaScript);
    // Run the table-level Lua script (CE's <LuaScript>) after the records are
    // loaded, so it can define trainer functions/hooks and reference records.
    if (!table.luaScript.empty()) {
        // CE asktorunluascript: never auto-run an untrusted table's Lua, ask first.
        auto answer = QMessageBox::question(this, "Execute this lua script?",
            "This cheat table contains a Lua script.\n\n"
            "Only execute scripts from tables you trust, a table's Lua can hook "
            "and manipulate the target. Execute it?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer == QMessageBox::Yes) {
            luaEngine_.setProcess(process_.get());
            luaEngine_.setAddressList(addressListModel_);
            auto res = luaEngine_.evalToString(table.luaScript);
            if (!res.has_value())
                statusBar()->showMessage(
                    QString("Table Lua error: %1").arg(QString::fromStdString(res.error())), 8000);
        }
    }
    disasmAnnotations_ = table.disassemblerComments;
}

void MainWindow::addRecentTable(const QString& path) {
    QString abs = QFileInfo(path).absoluteFilePath();
    if (abs.isEmpty()) return;
    QSettings s;
    QStringList recent = s.value("recentTables").toStringList();
    recent.removeAll(abs);        // de-dup, then promote to the front (most recent)
    recent.prepend(abs);
    while (recent.size() > 10) recent.removeLast();
    s.setValue("recentTables", recent);
    rebuildRecentMenu();
}

void MainWindow::rebuildRecentMenu() {
    if (!recentMenu_) return;
    recentMenu_->clear();
    const QStringList recent = QSettings().value("recentTables").toStringList();
    if (recent.isEmpty()) {
        recentMenu_->addAction("(no recent tables)")->setEnabled(false);
        return;
    }
    for (const QString& p : recent) {
        // Basename in the menu, full path in the tooltip; a missing file is greyed
        // (it stays listed so the user can see what went away, like CE).
        const bool exists = QFileInfo::exists(p);
        auto* a = recentMenu_->addAction(QFileInfo(p).fileName());
        a->setToolTip(exists ? p : p + "  (missing)");
        a->setEnabled(exists);
        if (exists) connect(a, &QAction::triggered, this, [this, p]() { loadTableFromPath(p); });
    }
    recentMenu_->addSeparator();
    connect(recentMenu_->addAction("Clear list"), &QAction::triggered, this, [this]() {
        QSettings().remove("recentTables");
        rebuildRecentMenu();
    });
}

void MainWindow::loadTableFromPath(const QString& path) {
    // Show the loaded table's file name in the title bar, like CE.
    setWindowTitle(QString("Cheat Engine - %1").arg(QFileInfo(path).fileName()));
  try {
    // Detect the format from the file's contents, not its extension: CE tables are
    // commonly `.CT` (uppercase) or extensionless when downloaded, which a
    // case-sensitive ".ct" check silently rejected.
    const ce::TableFormat fmt = ce::detectTableFormat(path.toStdString());
    if (fmt == ce::TableFormat::Protected) {
        bool ok = false;
        QString pw = QInputDialog::getText(this, "Protected Cheat Table",
            "This table is password-protected (.CETRAINER).\nEnter its password:",
            QLineEdit::Password, QString(), &ok);
        if (!ok) return;
        CheatTable table;
        if (!table.loadProtected(path.toStdString(), pw.toStdString())) {
            QMessageBox::warning(this, "Load Cheat Table",
                "Could not decrypt the table (wrong password or corrupt file).");
            return;
        }
        loadCheatTableModel(table);
        addRecentTable(path);
        return;
    }
    if (fmt != ce::TableFormat::Json) {
        // CE XML .CT format (Xml, or Unknown which load() self-validates).
        CheatTable table;
        if (!table.load(path.toStdString())) return;
        loadCheatTableModel(table);
        addRecentTable(path);
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
        addRecentTable(path);
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

// A Wine/Proton target runs a Windows .exe, and /proc/PID/cmdline carries that
// .exe path (Steam/Proton, PortProton, Lutris, Heroic and Bottles all keep it
// there). Used to warn before arming a hardware watchpoint, which Wine's own
// debug-register handling often turns into a game crash.
static bool targetLooksLikeWine(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (!f) return false;
    std::string cmd;
    char buf[4096];
    while (f.read(buf, sizeof(buf)) || f.gcount())
        cmd.append(buf, static_cast<size_t>(f.gcount()));
    for (auto& c : cmd) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return cmd.find(".exe") != std::string::npos;
}

void MainWindow::startCodeFinderForAddress(uintptr_t addr, bool writesOnly) {
    if (!process_) return;

    // A previous "find what writes/accesses" monitor still holds the target thread
    // ptrace-traced. A new one's PTRACE_SEIZE of the same thread would then fail, so
    // the second attempt would silently find nothing. Stop finished finders first to
    // release the trace (and the debug register).
    for (auto& f : codeFinders_)
        if (f) f->stop();

    // Watchpoint backend selection. On a Wine/Proton game we must NOT seize the
    // whole thread group (that deadlocks the game against wineserver / esync-fsync /
    // GPU threads) and must NOT use the software page-guard (its mprotect fights
    // Proton's kernel write-watch/userfaultfd and freezes the game). So for Wine we
    // arm a HARDWARE watchpoint on the MAIN thread only — the game-logic thread that
    // writes gameplay values. Native Linux keeps the full all-thread hardware watch.
    const bool wine = targetLooksLikeWine(process_->pid());
    bool software = QSettings().value("codefinder/forceSoftware", false).toBool();
    bool singleThread = wine && !software;
    // Test override: CE_CODEFINDER_MODE = hw (all-thread hardware) | sw (software) |
    // st (single-thread hardware).
    const QByteArray modeOverride = qgetenv("CE_CODEFINDER_MODE");
    if (modeOverride == "hw") { software = false; singleThread = false; }
    else if (modeOverride == "sw") { software = true;  singleThread = false; }
    else if (modeOverride == "st") { software = false; singleThread = true;  }

    if (wine && !codeFinderNoPrompt_ && !software) {
        auto r = QMessageBox::information(this, "Wine / Proton game",
            "This is a Wine/Proton (Windows) game. Cheat Engine will watch the game's "
            "main thread for writes, which is where gameplay values (money, HP, …) are "
            "usually changed.\n\n"
            "If nothing shows up, the value may be written by a background thread; "
            "tell me and it can be widened. Start monitoring?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (r != QMessageBox::Yes) return;
    }

    auto debugger = createDebuggerForCurrentProcess();
    if (!debugger) return;
    auto finder = std::make_unique<CodeFinder>();
    // Honour the configured hardware-watchpoint size (was ignored -> always 4).
    int watchSize = QSettings().value("codefinder/watchSize", "4").toInt();
    if (watchSize != 1 && watchSize != 2 && watchSize != 4 && watchSize != 8) watchSize = 4;
    if (!finder->start(*process_, *debugger, addr, writesOnly, watchSize, software, singleThread)) {
        QMessageBox::warning(this, "Code finder unavailable",
            software ? "Could not start software watchpoint monitoring for this address."
                     : "Could not start hardware watchpoint monitoring for this address.");
        return;
    }

    auto* finderPtr = finder.get();
    codeFinderDebuggers_.push_back(std::move(debugger));
    codeFinders_.push_back(std::move(finder));

    auto title = writesOnly ? "Find what writes" : "Find what accesses";
    auto* window = new CodeFinderWindow(finderPtr,
        QString("%1 0x%2").arg(title).arg(addr, 0, 16), process_.get(), this);
    window->setAttribute(Qt::WA_DeleteOnClose);
    // Closing the window stops the monitor so it releases the traced thread / debug
    // register (otherwise a later find-what-writes could not seize it). `this`
    // context makes the connection auto-drop if the main window goes away first.
    connect(window, &QObject::destroyed, this, [finderPtr]() { finderPtr->stop(); });
    // CE: "Add to the code list" sends the found opcodes to Advanced Options
    // (the Code list), where they can be disassembled / NOP'd / restored.
    window->setAddToList([this](uintptr_t a, const QString& desc) {
        showAdvancedOptions();
        advancedOptions_->addCode(a, desc.isEmpty() ? QString("code 0x%1").arg(a, 0, 16) : desc);
    });
    window->show();
}

void MainWindow::onMemoryView() {
    if (!process_) {
        statusBar()->showMessage("No process attached; open one first (Ctrl+O) to view memory.", 4000);
        return;
    }
    openMemoryView(0);
}

void MainWindow::showDebugger() {
    if (!process_) { QMessageBox::warning(this, "No process", "Open a process first."); return; }
    // Reuse the existing window: it holds the ptrace attachment, so a second one
    // would fail to attach. Just raise it if it is already open.
    if (debuggerWindow_) {
        debuggerWindow_->show();
        debuggerWindow_->raise();
        debuggerWindow_->activateWindow();
        return;
    }
    auto* w = new ce::gui::DebuggerWindow(process_.get(), this);
    w->setAttribute(Qt::WA_DeleteOnClose);
    debuggerWindow_ = w;   // QPointer auto-nulls on close
    // Drive the current-instruction highlight in open Memory Viewers from the
    // debugger's stops, like CE. The first viewer follows execution (scrolls to the
    // current line); the rest just light the line up where it is already visible.
    connect(w, &ce::gui::DebuggerWindow::stopped, this, [this](uintptr_t rip) {
        bool first = true;
        for (auto& mv : memoryViewers_)
            if (mv) { mv->showCurrentInstruction(rip, first); first = false; }
    });
    connect(w, &ce::gui::DebuggerWindow::resumed, this, [this]() {
        for (auto& mv : memoryViewers_) if (mv) mv->clearCurrentInstruction();
    });
    w->show();
}

void MainWindow::trackStructDissector(StructureDissector* sd) {
    std::erase_if(structDissectors_, [](const QPointer<StructureDissector>& p) { return p.isNull(); });
    structDissectors_.push_back(sd);
}

void MainWindow::openMonoDissector() {
    if (!process_) { QMessageBox::warning(this, "No process", "Open a process first."); return; }
    auto* w = new ce::gui::MonoDissectorWindow(process_.get(), this);
    w->setAttribute(Qt::WA_DeleteOnClose);
    // Double-clicking a field asks for the object's base address, then adds
    // base+offset to the address list with the field's mapped type.
    connect(w, &ce::gui::MonoDissectorWindow::addFieldRequested, this,
            [this](quint32 offset, int valueType, const QString& label) {
        bool ok = false;
        QString base = QInputDialog::getText(this, "Add Mono field",
            QString("Object base address for '%1' (field at +0x%2):")
                .arg(label).arg(offset, 0, 16),
            QLineEdit::Normal, "", &ok);
        if (!ok || base.trimmed().isEmpty()) return;
        QString expr = QString("%1+0x%2").arg(base.trimmed()).arg(offset, 0, 16);
        // Resolve now for the initial address; keep the expression so it
        // re-evaluates each refresh (the base may be a pointer/symbol).
        ce::ExpressionParser parser(process_.get(), &luaResolver_);
        auto addr = parser.parse(expr.toStdString());
        addressListModel_->addEntry(addr.value_or(0),
            static_cast<ce::ValueType>(valueType), label, expr);
    });
    w->show();
}

void MainWindow::reapplyGroupCollapse() {
    const auto& ents = addressListModel_->entries();
    std::vector<int> indents;
    std::vector<bool> collapsed;
    indents.reserve(ents.size());
    collapsed.reserve(ents.size());
    for (const auto& e : ents) {
        indents.push_back(e.indent);
        collapsed.push_back(e.isGroup && e.collapsed);
    }
    const auto hidden = ce::hiddenByCollapse(indents, collapsed);
    for (int r = 0; r < (int)hidden.size(); ++r)
        addressListView_->setRowHidden(r, hidden[r]);
}

QWidget* MainWindow::openPanelByName(const QString& name) {
    auto tryIn = [this, &name](QWidget* host) -> QWidget* {
        QSet<QWidget*> before;
        for (auto* w : QApplication::topLevelWidgets()) before.insert(w);
        bool matched = false;
        for (QAction* a : host->findChildren<QAction*>()) {
            if (a->menu() || a->isSeparator()) continue;
            QString t = a->text(); t.remove('&');
            if (t.contains(name, Qt::CaseInsensitive)) { a->trigger(); matched = true; break; }
        }
        if (!matched) return nullptr;
        QApplication::processEvents();
        for (auto* w : QApplication::topLevelWidgets())
            if (!before.contains(w) && w->isWindow() && w != this) return w;
        return nullptr;
    };
    if (auto* w = tryIn(menuBar())) return w;
    // Many analysis panels live in the Memory Viewer's own menus; open it and look.
    if (auto* mv = openMemoryView(0))
        if (auto* w = tryIn(mv)) return w;
    return nullptr;
}

QDialog* MainWindow::openSettingsDialog(const QString& page) {
    auto* dlg = new SettingsDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    // Apply the (possibly changed) auto-refresh interval live when it closes.
    connect(dlg, &QDialog::finished, this, [this](int) {
        if (valueRefreshTimer_)
            valueRefreshTimer_->start(QSettings().value("memview/refreshMs", 500).toInt());
    });
    // Optionally jump straight to a named category (used by the UI screenshot
    // harness, and handy for deep-linking to a settings page).
    if (!page.isEmpty()) {
        if (auto* nav = dlg->findChild<QListWidget*>("settingsNav")) {
            auto matches = nav->findItems(page, Qt::MatchContains);
            if (!matches.isEmpty()) nav->setCurrentItem(matches.first());
        }
    }
    dlg->show();
    dlg->raise();
    return dlg;
}

MemoryBrowser* MainWindow::openMemoryView(uintptr_t addr) {
    if (!process_) return nullptr;
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
    browser->setAddToList([this](uintptr_t addr, ce::ValueType type) {
        addressListModel_->addEntry(addr, type);
        statusBar()->showMessage(QString("Added 0x%1 to the cheat table").arg(addr, 0, 16), 3000);
    });

    // An explicit address wins; otherwise open at a selected scan result.
    if (addr) {
        browser->gotoAddress(addr);
    } else if (lastResult_) {
        auto sel = resultsView_->selectionModel()->selectedRows();
        if (!sel.isEmpty())
            browser->gotoAddress(resultsModel_->addressAt(sel.first().row()));
    }

    populateBrowserMenus(browser);   // add the CE Memory-Viewer tools to its menu bar
    browser->show();
    // Track it so a target exit can freeze it before its process handle is freed.
    // Drop any stale (already-closed) entries while we are here.
    std::erase_if(memoryViewers_, [](const QPointer<MemoryBrowser>& p) { return p.isNull(); });
    memoryViewers_.push_back(browser);
    // If the debugger is already paused, light up the current line in this new viewer
    // too (highlight only, without yanking it away from the address it opened at).
    if (debuggerWindow_ && debuggerWindow_->debugStopped())
        browser->showCurrentInstruction(debuggerWindow_->currentStopRip(), false);
    return browser;
}

// Fill a Memory Viewer's View/Tools/Debug menus with the tools that CE keeps in
// that window (they need MainWindow's process + address list).
void MainWindow::populateBrowserMenus(MemoryBrowser* b) {
    QMenu* view = b->viewMenu();
    QMenu* tools = b->toolsMenu();
    if (!view || !tools) return;

    // Navigating from these info windows opens the same full-featured viewer as
    // the Memory View button (breakpoints, add-to-list, Tools/Debug menus), not a
    // stripped-down clone. openMemoryView() no-ops safely when no process is open.
    auto openAt = [this](uintptr_t addr) { openMemoryView(addr); };
    auto needProc = [this]() { return process_ != nullptr; };

    // ── View: navigable info windows ──
    view->addAction("Memory Regions", this, [this, openAt]() {
        if (!process_) return;
        auto* w = new MemoryRegionsWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &MemoryRegionsWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction("Heap list", this, [this, openAt]() {
        if (!process_) return;
        auto* w = new HeapRegionsWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &HeapRegionsWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction("Module list", this, [this, openAt]() {
        if (!process_) return;
        auto* w = new ModuleListWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &ModuleListWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction("Referenced strings / functions", this, [this, openAt]() {
        if (!process_) return;
        auto* w = new CodeReferencesWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &CodeReferencesWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction("Thread list", this, [this]() {
        if (!process_) return;
        auto* w = new ThreadListWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });
    view->addAction("Stacktrace", this, [this]() {
        if (!process_) return;
        auto* w = new StackViewWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });
    view->addAction("Graphical memory view", this, [this]() {
        if (!process_) return;
        auto* w = new ce::gui::GraphicalMemoryView(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });

    // ── Debug ──
    QMenu* dbg = b->debugMenu();
    if (dbg) {
        dbg->addSeparator();
        dbg->addAction("Registers", this, [this]() {
            if (!process_) return;
            auto* w = new RegisterEditorWindow(process_.get(), this);
            w->setAttribute(Qt::WA_DeleteOnClose); w->show();
        });
        dbg->addAction("Breakpoint list", this, [this]() {
            auto* w = new BreakpointListWindow(&bpManager_, this);
            w->setAttribute(Qt::WA_DeleteOnClose); w->show();
        });
        dbg->addAction("Full debugger", this, [this]() { showDebugger(); });
        dbg->addAction("Break and trace", this, [this]() {
            if (!process_) return;
            auto* tw = new TracerWindow(process_.get(),
                [this]() { return createDebuggerForCurrentProcess(); }, this);
            tw->setAttribute(Qt::WA_DeleteOnClose); tw->show();
        });
        dbg->addAction("Branch mapper (LBR)", this, [this]() {
            if (!process_) return;
            auto* bm = new BranchMapper(process_.get(), this);
            bm->setAttribute(Qt::WA_DeleteOnClose); bm->show();
        });
    }

    // Analysis tools (shared with the main window Tools menu).
    addAnalysisToolsMenu(tools);
    (void)needProc;
}

void MainWindow::addAnalysisToolsMenu(QMenu* tools) {
    tools->addAction("Auto Assemble", this, [this]() {
        auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
        editor->setAttribute(Qt::WA_DeleteOnClose);
        editor->setAddToTable([this](const QString& d, const QString& s) { addressListModel_->addScriptEntry(d, s); });
        editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
        editor->show();
    });
    tools->addAction("Pointer scan", this, [this]() {
        if (!process_) return;
        auto* dlg = new PointerScanDialog(process_.get(), this);
        connect(dlg, &PointerScanDialog::addressSelected, this,
                [this](uintptr_t a, const QString& d) { addressListModel_->addEntry(a, ce::ValueType::Int32, d); });
        dlg->setAttribute(Qt::WA_DeleteOnClose); dlg->show();
    });
    tools->addAction("Emulator guest scan", this, [this]() {
        if (!process_) { QMessageBox::warning(this, "No process", "Open a process first."); return; }
        auto* dlg = new GuestScanDialog(process_.get(), this);
        connect(dlg, &GuestScanDialog::addressSelected, this,
                [this](uintptr_t a, ce::ValueType t, bool be, const QString& d) {
                    addressListModel_->addEntry(a, t, d);
                    if (be) addressListModel_->setEntryBigEndian(addressListModel_->rowCount() - 1, true);
                });
        dlg->setAttribute(Qt::WA_DeleteOnClose); dlg->show();
    });
    tools->addAction("Dissect data/structures", this, [this]() {
        if (!process_) return;
        auto* sd = new StructureDissector(process_.get(), 0, this);
        sd->setAttribute(Qt::WA_DeleteOnClose);
        sd->setAddToListCallback([this](uintptr_t a, ce::ValueType t, const QString& d) { addressListModel_->addEntry(a, t, d); });
        trackStructDissector(sd);
        sd->show();
    });
    tools->addAction("Find static addresses", this, [this]() {
        if (!process_) { QMessageBox::warning(this, "No process", "Open a process first."); return; }
        auto* w = new FindStaticsWindow(process_.get(), this);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });
    tools->addAction("Mono dissector...", this, &MainWindow::openMonoDissector);
    tools->addAction("Lua Engine", this, [this]() {
        luaEngine_.setProcess(process_.get());
        luaEngine_.setAddressList(addressListModel_);   // so getMemoryRecord etc. work
        if (process_) { luaResolver_.loadProcess(*process_); luaEngine_.setResolver(&luaResolver_); }
        auto* console = new LuaConsole(&luaEngine_, this);
        console->setAttribute(Qt::WA_DeleteOnClose); console->show();
    });
    tools->addAction("Find Statics / ELF Inspector", this, [this]() {
        QString initial;
        if (process_) { auto mods = process_->modules(); if (!mods.empty()) initial = QString::fromStdString(mods.front().path); }
        auto* dlg = new ElfInspector(initial, this);
        dlg->setAttribute(Qt::WA_DeleteOnClose); dlg->show();
    });
}

void MainWindow::updateScanButtons() {
    bool hasProcess = (process_ != nullptr);
    bool scanActive = (lastResult_ != nullptr);   // a First Scan has been run
    bool hasResults = (scanActive && lastResult_->count() > 0);
    firstScanBtn_->setEnabled(hasProcess);
    // CE-style: once a scan session is open, "First Scan" becomes "New Scan" (a
    // reset), the value type is locked (Next Scan must reuse it), and Next Scan
    // is available. A fresh state shows "First Scan" with an editable value type.
    firstScanBtn_->setText(scanActive ? "New Scan" : "First Scan");
    nextScanBtn_->setEnabled(hasResults);
    undoScanBtn_->setEnabled(undoResult_ != nullptr);
    if (valueTypeCombo_) valueTypeCombo_->setEnabled(!scanActive);
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
        // Variable-width types carry their byte length in valueSize_ (set at scan
        // time from the pattern / string length). Without this, AOB and string
        // results read only 4 bytes and rendered as "?".
        case ValueType::Grouped:
        case ValueType::Custom:
        case ValueType::ByteArray:
        case ValueType::Binary:
        case ValueType::String:
        case ValueType::UnicodeString: return std::max<size_t>(1, valueSize_);
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
    // Cache the module map so the Address column can flag "static" results (those
    // inside a loaded module) in green — CE's cue for pointer-stable addresses
    // that survive a restart, the ones worth turning into a pointer path.
    modules_ = proc_ ? proc_->modules() : std::vector<ce::ModuleInfo>{};
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
    return result_ ? std::min(result_->count(), kResultDisplayCap) : 0;
}

int ScanResultsModel::columnCount(const QModelIndex&) const { return 3; }

QVariant ScanResultsModel::headerData(int section, Qt::Orientation o, int role) const {
    if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
    switch (section) {
        case 0:  return "Address";
        case 1:  return "Value";       // current (live) value
        default: return "Previous";    // value captured at scan time
    }
}

// Format `vs` bytes at `buf` as `vt` (shared by the live Value and the scan-time
// Previous columns).
static QString formatScanValue(ValueType vt, bool displayHex, const uint8_t* buf, size_t vs) {
    switch (vt) {
        // Integers render through the same shared helper as the cheat table (signed by
        // default, hex width-masked), so a value reads identically in the results and
        // after "Add to the address list".
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64: {
            int w = ce::scalarWidth(vt);
            uint64_t bits = 0; memcpy(&bits, buf, static_cast<size_t>(w));
            return QString::fromStdString(ce::formatIntegerScalar(bits, w, /*isSigned=*/true, displayHex));
        }
        case ValueType::Pointer:{ uintptr_t v; memcpy(&v, buf, sizeof(v)); return QString("0x%1").arg(v, 0, 16); }
        case ValueType::Float:  { float v; memcpy(&v, buf, 4); return QString::fromStdString(ce::formatFloatScalar(v, false)); }
        case ValueType::Double: { double v; memcpy(&v, buf, 8); return QString::fromStdString(ce::formatFloatScalar(v, true)); }
        case ValueType::String: {
            size_t len = strnlen(reinterpret_cast<const char*>(buf), vs);
            return QString::fromUtf8(reinterpret_cast<const char*>(buf), static_cast<int>(len));
        }
        case ValueType::UnicodeString: {
            const char16_t* u = reinterpret_cast<const char16_t*>(buf);
            size_t maxch = vs / 2, len = 0;
            while (len < maxch && u[len] != u'\0') ++len;
            return QString::fromUtf16(u, static_cast<int>(len));
        }
        case ValueType::ByteArray:
        case ValueType::Binary:
        case ValueType::Grouped:
        case ValueType::Custom: {
            QString hex; hex.reserve(static_cast<int>(vs * 3));
            for (size_t i = 0; i < vs; ++i)
                hex += QString("%1 ").arg(buf[i], 2, 16, QChar('0'));
            return hex.trimmed().toUpper();
        }
        default: return "?";
    }
}

QVariant ScanResultsModel::data(const QModelIndex& index, int role) const {
    if (!result_) return {};
    // Red foreground on the Value column when it changed since the last refresh.
    if (role == Qt::ForegroundRole) {
        if (index.column() == 1) {
            auto it = changed_.find(index.row());
            if (it != changed_.end() && it->second)
                return QBrush(ce::gui::editorPalette().error);  // theme-aware red (was low-contrast pink on white)
        } else if (index.column() == 0 && !modules_.empty()) {
            // Green address = "static": lives inside a loaded module, so it keeps
            // the same module+offset across restarts (CE's green cue).
            if (!ce::moduleOffsetString(modules_, result_->address(index.row())).empty())
                return QBrush(ce::gui::editorPalette().success);  // theme-aware green
        }
        return {};
    }
    // Hovering a static address reveals its module+offset (the durable identity).
    if (role == Qt::ToolTipRole && index.column() == 0 && !modules_.empty()) {
        std::string modOff = ce::moduleOffsetString(modules_, result_->address(index.row()));
        if (!modOff.empty()) return QString::fromStdString(modOff);
        return {};
    }
    if (role != Qt::DisplayRole) return {};

    if (index.column() == 0) {
        return QString("0x%1").arg(result_->address(index.row()), 0, 16);
    }

    const size_t vs = valueSizeBytes();
    std::vector<uint8_t> buf(vs);
    if (index.column() == 2) {
        // Previous: always the value captured at scan time.
        result_->value(index.row(), buf.data(), vs);
        return formatScanValue(valueType_, displayHex_, buf.data(), vs);
    }
    // Value: prefer the live re-read for on-screen rows; fall back to the
    // scan-time value for rows not currently refreshed.
    auto it = liveValues_.find(index.row());
    if (it != liveValues_.end()) {
        if (it->second.size() == vs) buf = it->second;
        else return QStringLiteral("??");   // unreadable this refresh
    } else {
        result_->value(index.row(), buf.data(), vs);
    }
    return formatScanValue(valueType_, displayHex_, buf.data(), vs);
}

uintptr_t ScanResultsModel::addressAt(int row) const {
    return result_ ? result_->address(row) : 0;
}

// ═══════════════════════════════════════════════════════════════
// AddressListModel
// ═══════════════════════════════════════════════════════════════

AddressListModel::AddressListModel(QObject* parent) : QAbstractTableModel(parent) {}

int AddressListModel::addEntry(uintptr_t addr, ValueType type, const QString& desc,
                               const QString& addressExpr, size_t byteCount) {
    beginInsertRows({}, entries_.size(), entries_.size());
    AddressEntry entry;
    entry.id = allocId();
    entry.description = desc;
    entry.address = addr;
    entry.addressExpr = addressExpr;  // non-empty => pointer record, re-resolved live
    entry.type = type;
    entry.byteCount = byteCount;       // element length for AOB/string (0 = unknown)
    entry.currentValue = "?";
    int id = entry.id;
    entries_.push_back(std::move(entry));
    endInsertRows();
    return id;
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
        case ValueType::String: return "string";
        case ValueType::UnicodeString: return "unicode";
        case ValueType::ByteArray: return "aob";
        case ValueType::Binary: return "binary";
        case ValueType::Grouped: return "grouped";
        case ValueType::Custom: return "custom";
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
    if (s == "string") return ValueType::String;
    if (s == "unicode") return ValueType::UnicodeString;
    if (s == "aob")    return ValueType::ByteArray;
    if (s == "binary") return ValueType::Binary;
    if (s == "grouped") return ValueType::Grouped;
    if (s == "custom") return ValueType::Custom;
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
static long long parseIntField(const QString& valStr, bool hex = false) {
    // In hex-display mode a bare token is hex (CE); a "0x" prefix is always hex.
    bool ok = false;
    long long v = ce::parseIntegerScalar(valStr.toStdString(), hex, ok);
    return ok ? v : 0;
}

// Format a fixed-width scalar exactly as the cheat table displays it (decimal or hex,
// float precision). The byte-swap (big-endian) + codec decode is the shared cecore
// transform (ce::decodeScalarBits); this only formats the resulting logical value.
// Returns empty for non-scalar types.
static QString formatScalarValue(ValueType type, const uint8_t* raw, bool showHex,
                                 const ce::ValueCodec& codec, bool bigEndian, bool isSigned) {
    const uint64_t bits = ce::decodeScalarBits(type, raw, bigEndian, codec);
    switch (type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64:
            // CE ShowAsSigned decides signed vs unsigned decimal (hex is width-masked).
            return QString::fromStdString(
                ce::formatIntegerScalar(bits, ce::scalarWidth(type), isSigned, showHex));
        case ValueType::Pointer:{ return QString("0x%1").arg((qulonglong)bits, 0, 16); }
        case ValueType::Float:  { float  v; memcpy(&v, &bits, 4);
                                  return QString::fromStdString(ce::formatFloatScalar(v, false)); }
        case ValueType::Double: { double v; memcpy(&v, &bits, 8);
                                  return QString::fromStdString(ce::formatFloatScalar(v, true)); }
        default: return QString();
    }
}

static void writeValueToProcess(ProcessHandle* proc, uintptr_t addr, ValueType type,
                                const QString& valStr, const ce::ValueCodec& codec = {},
                                bool bigEndian = false, bool showHex = false) {
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
        case ValueType::Byte:   { uint8_t v = (uint8_t)parseIntField(valStr, showHex); memcpy(buf, &v, 1); break; }
        case ValueType::Int16:  { uint16_t v = (uint16_t)parseIntField(valStr, showHex); memcpy(buf, &v, 2); break; }
        case ValueType::Int32:  { uint32_t v = (uint32_t)parseIntField(valStr, showHex); memcpy(buf, &v, 4); break; }
        case ValueType::Int64:  { uint64_t v = (uint64_t)parseIntField(valStr, showHex); memcpy(buf, &v, 8); break; }
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
    // Encode into the stored form (obfuscation codec + target byte order) so the user
    // edits by the logical value. Shared cecore transform; `buf` holds the logical
    // little-endian value at this point.
    { uint64_t bits = 0; memcpy(&bits, buf, vs); ce::encodeScalarBits(type, bits, bigEndian, codec, buf); }
    proc->write(addr, buf, vs);
}

static bool readComparableValue(ProcessHandle* proc, uintptr_t addr, ValueType type,
                                double& value, const ce::ValueCodec& codec = {},
                                bool bigEndian = false) {
    uint8_t buf[8] = {};
    size_t vs = vtSize(type);
    auto r = proc->read(addr, buf, vs);
    if (!r || *r < vs) return false;

    // Shared cecore transform: reverse big-endian to host order, then codec-decode
    // (integer types), so directional freeze, the adjust hotkey and edit-verify all
    // compare the LOGICAL value.
    const uint64_t bits = ce::decodeScalarBits(type, buf, bigEndian, codec);
    switch (type) {
        case ValueType::Byte:    value = (uint8_t)bits;                    return true;
        case ValueType::Int16:   value = (int16_t)bits;                   return true;
        case ValueType::Int32:   value = (int32_t)bits;                   return true;
        case ValueType::Int64:   value = static_cast<double>((int64_t)bits); return true;
        case ValueType::Pointer: value = static_cast<double>((uintptr_t)bits); return true;
        case ValueType::Float:  { float  v; memcpy(&v, &bits, 4); value = v; return true; }
        case ValueType::Double: { double v; memcpy(&v, &bits, 8); value = v; return true; }
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
            writeValueToProcess(proc, e.address, e.type, e.frozenValue, e.codec, e.bigEndian, e.showAsHex);
            continue;
        }

        // Read current value to compare for directional freeze.
        double current = 0;
        double frozen = 0;
        if (!readComparableValue(proc, e.address, e.type, current, e.codec, e.bigEndian) ||
            !parseComparableValue(e.type, e.frozenValue, frozen)) {
            writeValueToProcess(proc, e.address, e.type, e.frozenValue, e.codec, e.bigEndian, e.showAsHex);
            continue;
        }

        if (ce::freezeShouldWrite(e.freezeMode, current, frozen))
            writeValueToProcess(proc, e.address, e.type, e.frozenValue, e.codec, e.bigEndian, e.showAsHex);
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
        if (e.byteCount > 0) obj["byteCount"] = (int)e.byteCount;   // AOB/string length
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
        obj["collapsed"] = e.collapsed;
        obj["showAsHex"] = e.showAsHex;
        obj["showAsSigned"] = e.showAsSigned;
        obj["freezeMode"] = (int)e.freezeMode;
        if (e.codec.active())   // obfuscation codec, as its round-trippable spec string
            obj["codec"] = QString::fromStdString(e.codec.describe());
        if (e.bigEndian) obj["bigEndian"] = true;
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
        e.byteCount = (size_t)obj["byteCount"].toInt(0);   // AOB/string length (0 if absent)
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
        e.collapsed = obj["collapsed"].toBool();
        e.showAsHex = obj["showAsHex"].toBool();
        e.showAsSigned = obj["showAsSigned"].toBool(true);
        if (obj.contains("freezeMode"))
            e.freezeMode = (ce::FreezeMode)obj["freezeMode"].toInt();
        if (obj.contains("codec")) {
            if (auto c = ce::ValueCodec::parse(obj["codec"].toString().toStdString()))
                e.codec = *c;
        }
        e.bigEndian = obj["bigEndian"].toBool();
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

void AddressListModel::setEntryCodec(int row, ce::ValueCodec codec) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].codec = codec;
    entries_[row].currentValue.clear();   // force a re-read/reformat through the codec
    emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
}

std::string AddressListModel::entryCodecSpec(int row) const {
    if (row < 0 || row >= (int)entries_.size()) return "none";
    return entries_[row].codec.describe();
}

void AddressListModel::setEntryBigEndian(int row, bool bigEndian) {
    if (row < 0 || row >= (int)entries_.size()) return;
    entries_[row].bigEndian = bigEndian;
    entries_[row].currentValue.clear();   // re-read/reformat in the new byte order
    emit dataChanged(index(row, 4), index(row, 4), {Qt::DisplayRole, Qt::EditRole});
}

bool AddressListModel::entryBigEndian(int row) const {
    return (row >= 0 && row < (int)entries_.size()) && entries_[row].bigEndian;
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
    if (!readComparableValue(proc_, e.address, e.type, current, e.codec, e.bigEndian) &&
        !parseComparableValue(e.type, e.currentValue, current)) {
        return false;
    }

    double next = current + delta;
    QString nextText;
    switch (e.type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64: {
            // Render in the record's display format (hex/signed). This is both what the
            // column shows until the next refresh AND what writeValueToProcess parses
            // back: a hex record must NOT receive a bare decimal, which its hex-aware
            // parse would misread (e.g. "256" as 0x256).
            uint64_t bits = static_cast<uint64_t>(static_cast<int64_t>(std::llround(next)));
            nextText = QString::fromStdString(
                ce::formatIntegerScalar(bits, ce::scalarWidth(e.type), e.showAsSigned, e.showAsHex));
            break;
        }
        case ValueType::Pointer:
            nextText = QString("0x%1").arg(static_cast<qulonglong>(std::llround(next)), 0, 16);
            break;
        case ValueType::Float:
            nextText = QString::fromStdString(ce::formatFloatScalar(next, false));
            break;
        case ValueType::Double:
            nextText = QString::fromStdString(ce::formatFloatScalar(next, true));
            break;
        default:
            return false;
    }

    writeValueToProcess(proc_, e.address, e.type, nextText, e.codec, e.bigEndian, e.showAsHex);
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

bool AddressListModel::toggleGroupCollapse(int row) {
    if (row < 0 || row >= (int)entries_.size() || !entries_[row].isGroup) return false;
    entries_[row].collapsed = !entries_[row].collapsed;
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));  // refresh the ▸/▾ marker
    return true;
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
    writeValueToProcess(proc_, e.address, e.type, value, e.codec, e.bigEndian, e.showAsHex);
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

int AddressListModel::moveEntry(int row, int delta) {
    int target = row + delta;
    if (row < 0 || row >= (int)entries_.size() ||
        target < 0 || target >= (int)entries_.size())
        return row;
    std::swap(entries_[row], entries_[target]);
    emit dataChanged(index(std::min(row, target), 0),
                     index(std::max(row, target), columnCount() - 1));
    return target;
}

// Read+format a variable-length value (String/UnicodeString/ByteArray) for display.
// nullopt if `type` isn't variable-length; "??" on read failure. Shared by the
// address-list refresh and the Lua mr.Value read so both agree.
static std::optional<QString> formatVariableLengthValue(ProcessHandle* proc, uintptr_t addr,
                                                        ValueType type, size_t byteCount) {
    if (type != ValueType::String && type != ValueType::UnicodeString && type != ValueType::ByteArray)
        return std::nullopt;
    // Read exactly the known element length (AOB pattern / string length) when we
    // have it, else a reasonable window.
    const size_t want = byteCount > 0 ? std::min<size_t>(byteCount, 4096) : 64;
    std::vector<uint8_t> sbuf(want);
    auto sr = proc->read(addr, sbuf.data(), want);
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
    } else {  // ByteArray: show the exact pattern length when known, else cap at 16.
        const size_t cap = byteCount > 0 ? n : std::min<size_t>(n, 16);
        for (size_t k = 0; k < cap; ++k)
            s += QString("%1 ").arg(sbuf[k], 2, 16, QChar('0'));
        s = s.trimmed().toUpper();
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

        // Variable-length types: read the element (exact length if known) and format.
        if (auto fv = formatVariableLengthValue(proc, e.address, e.type, e.byteCount)) {
            e.currentValue = *fv;
            continue;
        }

        uint8_t buf[8] = {};
        size_t vs = vtSize(e.type);
        auto r = proc->read(e.address, buf, vs);
        if (r && *r >= vs) {
            QString s = formatScalarValue(e.type, buf, e.showAsHex, e.codec, e.bigEndian, e.showAsSigned);
            e.currentValue = s.isEmpty() ? "?" : s;
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
    if (auto fv = formatVariableLengthValue(proc_, e.address, e.type, e.byteCount))
        return fv->toStdString();

    uint8_t buf[8] = {};
    size_t vs = vtSize(e.type);
    auto r = proc_->read(e.address, buf, vs);
    if (!r || *r < vs) return "??";
    QString out = formatScalarValue(e.type, buf, e.showAsHex, e.codec, e.bigEndian, e.showAsSigned);
    return out.isEmpty() ? std::string("?") : out.toStdString();
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

void AddressListModel::refreshModuleCache() {
    moduleCache_ = proc_ ? proc_->modules() : std::vector<ce::ModuleInfo>{};
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
            // A group shows a collapse indicator (CE tree node): open vs collapsed.
            if (e.isGroup) prefix += e.collapsed ? QString::fromUtf8("▸ ")
                                                 : QString::fromUtf8("▾ ");
            return prefix + e.description;
        }
        case 2: {
            if (e.isGroup) return QString("");
            // Show the address relative to its module ("game.bin+0x1234") when it
            // falls inside one -- CE's convention, and stable across restarts.
            // Otherwise a plain hex address. Pointer records keep the "P->" prefix.
            std::string modOff = ce::moduleOffsetString(moduleCache_, e.address);
            QString addrStr = modOff.empty()
                ? QString("0x%1").arg(e.address, 0, 16)
                : QString::fromStdString(modOff);
            return e.addressExpr.isEmpty() ? addrStr : ("P->" + addrStr);
        }
        case 3: {
            if (e.isGroup) return "";
            // CE-canonical name; String/Array records also show their element length
            // in brackets (e.g. "String[10]", "Array of byte[8]"), like Cheat Engine.
            QString name = ce::valueTypeName(e.type);
            if ((e.type == ValueType::String || e.type == ValueType::UnicodeString ||
                 e.type == ValueType::ByteArray) && e.byteCount > 0)
                name += QString("[%1]").arg(e.byteCount);
            return name;
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
            if (proc_) {
                writeValueToProcess(proc_, e.address, e.type, writeStr, e.codec, e.bigEndian, e.showAsHex);
                // A non-frozen value that snaps back is protected: warn and point the
                // user at find-what-writes. A frozen entry is intentionally held, so
                // the freeze timer, not this, owns its persistence.
                if (!e.active) scheduleEditVerify(e.address, e.type, writeStr, e.codec, e.bigEndian);
            }
            emit dataChanged(index, index);
            return true;
        }
    }
    return false;
}

void AddressListModel::scheduleEditVerify(uintptr_t addr, ce::ValueType type,
                                          const QString& wroteStr, const ce::ValueCodec& codec,
                                          bool bigEndian) {
    if (!proc_) return;
    bool okNum = false;
    const double target = QString(wroteStr).replace(',', '.').toDouble(&okNum);
    if (!okNum) return;   // non-numeric types (string/byte array): no revert check
    // `this` as the timer context: the callback is skipped if the model is destroyed.
    QTimer::singleShot(250, this, [this, addr, type, wroteStr, target, codec, bigEndian]() {
        if (!proc_) return;
        double now = 0;
        if (!readComparableValue(proc_, addr, type, now, codec, bigEndian)) return;
        const double tol = (type == ce::ValueType::Float || type == ce::ValueType::Double)
                         ? std::abs(target) * 1e-5 + 1e-6 : 0.5;
        if (std::abs(now - target) > tol)
            emit valueReverted(addr, wroteStr, QString::number(now, 'g', 10));
    });
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

bool AddressListModel::setByteCount(int id, std::size_t count) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].byteCount = count;   // element length for String / Array of byte
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
    return true;
}

bool AddressListModel::setSigned(int id, bool isSigned) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].showAsSigned = isSigned;   // CE ShowAsSigned: re-render the value column
    emit dataChanged(index(row, 0), index(row, columnCount() - 1));
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
        writeValueToProcess(proc_, e.address, e.type, e.currentValue, e.codec, e.bigEndian, e.showAsHex);
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

bool AddressListModel::setDropdownList(int id, const QString& list) {
    int row = rowOfId(id);
    if (row < 0) return false;
    entries_[row].dropdownList = list;
    emit dataChanged(index(row, 1), index(row, columnCount() - 1));
    return true;
}

QString AddressListModel::dropdownList(int row) const {
    return (row >= 0 && row < (int)entries_.size()) ? entries_[row].dropdownList : QString();
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
