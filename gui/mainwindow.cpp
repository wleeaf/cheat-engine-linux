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
#include <QScrollArea>
#include <QFontMetrics>
#include <thread>
#include <sys/utsname.h>
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
#include <QColorDialog>
#include <QListWidget>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <QSignalBlocker>
#include <QFile>
#include <QDockWidget>

#include "gui/agent_panel.hpp"
#include <QStandardPaths>
#include <QDir>
#include <QDialog>
#include <QDialogButtonBox>
#include <QScreen>
#include <QGuiApplication>
#include <QLabel>
#include <QKeySequenceEdit>
#include <QPushButton>
#include <QTimer>
#include <cerrno>
#include <QFont>
#include <QMenu>
#include <QShortcut>
#include <QInputDialog>
#include <QSettings>
#include <QStatusBar>
#include <QColor>
#include <QDoubleValidator>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <QFileDialog>
#include <QLocale>
#include <cstdio>
#include <cstring>
#include <QJsonDocument>
#include <QJsonArray>
#include <QStringList>
#include <cmath>
#include <charconv>
#include <exception>
#include "gui/mainwindow_internal.hpp"
#include "gui/hotkeysdialog.hpp"
#include "gui/changedaddresses.hpp"
#include "gui/codefilter.hpp"
#include "gui/peinfo.hpp"
#include "gui/structurecompare.hpp"
#include "gui/structuredissectorconfig.hpp"
#include <QItemSelectionModel>
#include <QAction>

namespace ce::gui {
using namespace mainwindow_detail;

namespace mainwindow_detail {
QString foundLabelText(size_t count) {
    return QString(QCoreApplication::translate("MainWindow", "Found: %1")).arg(QLocale().toString((qulonglong)count));
}
} // namespace mainwindow_detail

// Settings > Display "Uppercase hexadecimal" and "Address width", read like
// the Memory Viewer reads them, for the address list and the scan results.
struct AddressDisplay { bool upper = false; int digits = 16; };
static AddressDisplay loadAddressDisplay() {
    QSettings s;
    return {s.value("display/hexUpper", false).toBool(), s.value("display/addressWidth", 1).toInt() == 0 ? 8 : 16};
}
static AddressDisplay& addressDisplay() {
    static AddressDisplay display = loadAddressDisplay();
    return display;
}
namespace mainwindow_detail {
QString formatListAddress(uintptr_t address) {
    const auto& display = addressDisplay();
    const QString digits = QString("%1").arg(address, display.digits, 16, QChar('0'));
    return "0x" + (display.upper ? digits.toUpper() : digits);
}
} // namespace mainwindow_detail
static QFont settingsMonospaceFont();

// ═══════════════════════════════════════════════════════════════
// MainWindow
// ═══════════════════════════════════════════════════════════════

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    scannerThreads_ = QSettings().value("scan/threads", 0).toInt();
    scanner_ = std::make_unique<MemoryScanner>(scannerThreads_);
    setupUi();
    setupMenus();
    updateScanButtons();
    setWindowTitle("Cheat Engine");
    {
        // The default size grows with the text size, within the screen.
        const double textScale = std::max(1.0, fontMetrics().height() / 17.0);
        QSize size(int(960 * textScale), int(760 * textScale));
        if (auto* screen = QGuiApplication::primaryScreen())
            size = size.boundedTo(screen->availableGeometry().size() * 0.92);
        resize(size);
    }
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
        QString title = setting.empty() ? QString(tr("Select file"))
                                        : QString(tr("Select file for %1")).arg(QString::fromStdString(setting));
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
        // Releasing a dead target deletes its windows. A modal dialog or menu
        // open in one of them is a nested event loop on its stack (often a
        // stack object parented to the window), so deleting under it crashes:
        // wait until it closes, this timer comes back.
        const bool nestedLoop = QApplication::activeModalWidget() || QApplication::activePopupWidget();
        if (dynamic_cast<ce::GdbProcessHandle*>(process_.get()) && !process_->targetDescription().live) {
            if (nestedLoop) return;
            onDisconnectProcess();
            processLabel_->setText(tr("GDB target disconnected or exited"));
            processDetail_->clear();
            statusBar()->showMessage(tr("GDB target disconnected or exited"),5000);
            return;
        }
        // A ceserver connection closes on any error or timeout and never comes
        // back: say so, instead of showing "??" values against a dead link.
        // Ask the client directly: targetDescription() is a network round trip
        // on the GUI thread for every tick.
        if (ceserverClient_ && !ceserverClient_->isConnected()) {
            if (nestedLoop) return;
            onDisconnectProcess();
            processLabel_->setText(tr("ceserver connection lost"));
            processDetail_->setText(tr("Connect again with File > Connect to ceserver."));
            statusBar()->showMessage(tr("ceserver connection lost"),5000);
            return;
        }
        // Detect target death: once the pid is gone, stop polling and clear state
        // so the UI doesn't keep showing stale values against a dead process.
        // A process we started (Create Process) stays a zombie until reaped, and
        // kill(pid, 0) still succeeds on a zombie. waitid with WNOWAIT only looks
        // at exits, so it never takes a ptrace stop from the debugger's thread.
        siginfo_t exitInfo{};
        const bool exitedChild = !ceserverClient_ && currentPid_ > 0 &&
            ::waitid(P_PID, static_cast<id_t>(currentPid_), &exitInfo, WEXITED | WNOHANG | WNOWAIT) == 0 &&
            exitInfo.si_pid == currentPid_;
        if (exitedChild || (!ceserverClient_ && currentPid_ > 0 && ::kill(currentPid_, 0) != 0 && errno == ESRCH)) {
            if (nestedLoop) return;
            processLabel_->setText(QString(tr("Process %1 has exited")).arg(currentPid_));
            processDetail_->setText(tr("Open another process with Ctrl+O."));
            statusBar()->showMessage(tr("Target process exited"), 5000);
            if (!releaseTargetUsers()) return;
            if (exitedChild) (void)::waitpid(currentPid_, nullptr, WNOHANG);   // reap it now that nothing traces it
            process_.reset();
            currentPid_ = 0;
            updateWindowTitle();
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
    timer->start(kValueRefreshMs);

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

// The monospace font from the Settings dialog (display/fontFamily + fontSize),
// used for the results / cheat-table views. Defaults to the desktop's monospace font.
static QFont settingsMonospaceFont() {
    QSettings s;
    return QFont(s.value("display/fontFamily", defaultMonospaceFamily()).toString(),
                 s.value("display/fontSize", defaultMonospaceSize()).toInt());
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
    openBtn->setToolTip(tr("Open process"));
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
    processLabel_ = new QLabel(tr("No process selected"));
    processLabel_->setObjectName("processLabel");
    processLabel_->setStyleSheet(QString("font-weight: 600; font-size: %1pt;")
        .arg(QApplication::font().pointSizeF() * 1.1, 0, 'f', 1));
    processDetail_ = new QLabel(tr("Press Ctrl+O or click the magnifier to choose a process."));
    processDetail_->setObjectName("processDetail");
    processDetail_->setProperty("secondary", true);
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
    // Headers align with their (left-aligned) cells, as in every other table.
    resultsView_->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    resultsView_->horizontalHeader()->setHighlightSections(false);
    resultsView_->setShowGrid(false);
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
    resultsEmptyHint_->setProperty("secondary", true);
    resultsEmptyHint_->setWordWrap(true);
    resultsEmptyHint_->setAttribute(Qt::WA_TransparentForMouseEvents);
    resultsView_->viewport()->installEventFilter(this);
    auto updateResultsHint = [this]() {
        if (!resultsEmptyHint_) return;
        const bool empty = resultsModel_->rowCount() == 0;
        // Only point at Open Process while there is no process to scan.
        resultsEmptyHint_->setText(process_
            ? tr("No results yet.\n\nEnter a value and press First Scan.")
            : tr("No results yet.\n\nOpen a process with Ctrl+O,\nthen enter a value and press First Scan."));
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
            onResultDoubleClicked(idx);   // the same record a double-click adds
    });
    resultsView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(resultsView_, &QTableView::customContextMenuRequested, this, [this](const QPoint& pos) {
        if (!lastResult_) return;
        auto sel = resultsView_->selectionModel()->selectedRows();
        if (sel.isEmpty()) return;
        QMenu menu(this);
        // CE foundlistpopup order.
        auto* addAct = menu.addAction(sel.size() > 1
            ? QString(tr("Add %1 selected addresses to the address list")).arg(sel.size())
            : QString(tr("Add selected address to the address list")));
        auto* browseAct = menu.addAction(tr("Browse this memory region"));
        auto* disasmAct = menu.addAction(tr("Disassemble this memory region"));
        auto* copyAct = menu.addAction(sel.size() > 1 ? QString(tr("Copy %1 addresses")).arg(sel.size())
                                                      : QString(tr("Copy address")));
        copyAct->setShortcut(QKeySequence::Copy);
        auto* removeAct = menu.addAction(sel.size() > 1
            ? QString(tr("Remove %1 selected addresses from the results")).arg(sel.size())
            : QString(tr("Remove selected address from the results")));
        menu.addSeparator();
        auto* accAct = menu.addAction(tr("Find out what accesses this address"));
        auto* wrAct  = menu.addAction(tr("Find out what writes to this address"));
        menu.addSeparator();
        auto* customizeAct = menu.addAction(tr("Change Foundlist settings..."));
        QAction* picked = menu.exec(resultsView_->viewport()->mapToGlobal(pos));
        if (!picked) return;
        if (picked == customizeAct) {
            FoundListPreferencesDialog dialog(this);
            if (dialog.exec() == QDialog::Accepted) resultsModel_->reloadPreferences();
            return;
        }
        const uintptr_t firstAddr = resultsModel_->addressAt(sel.first().row());
        if (picked == addAct) {
            for (auto& idx : sel)
                onResultDoubleClicked(idx);   // the same record a double-click adds
        } else if (picked == browseAct || picked == disasmAct) {
            // Full-featured viewer (breakpoints, add-to-list, Tools/Debug menus),
            // the same one the Memory View button opens, not a stripped-down clone.
            openMemoryView(firstAddr);
        } else if (picked == copyAct) {
            QStringList addrs;
            for (auto& idx : sel)
                addrs << QString("0x%1").arg(resultsModel_->addressAt(idx.row()), 0, 16);
            QApplication::clipboard()->setText(addrs.join('\n'));
        } else if (picked == removeAct) {
            // Swap in a pruned copy of the result so the removal persists into a later
            // Next Scan (CE "remove selected addresses from the list"). The pre-prune set
            // becomes the undo state, so "Undo scan" brings the removed rows back.
            std::vector<bool> mask(lastResult_->count(), false);
            for (auto& idx : sel) {
                int r = idx.row();
                if (r >= 0 && r < (int)mask.size()) mask[r] = true;
            }
            // A failure (incomplete result files, a full disk) must not escape
            // the slot: that would terminate Cheat Engine.
            std::unique_ptr<ce::ScanResult> pruned;
            try { pruned = ce::pruneScanResult(*lastResult_, lastResultValueSize_, mask); }
            catch (const std::exception& error) {
                QMessageBox::warning(this, tr("Remove from results"), QString::fromStdString(error.what()));
                return;
            }
            resultsModel_->setResult(pruned.get(), lastResultType_, lastResultValueSize_, resultsModel_->stringEncoding());
            undoResult_ = std::move(lastResult_);
            undoResultType_ = lastResultType_;
            undoResultValueSize_ = lastResultValueSize_;
            lastResult_ = std::move(pruned);
            foundLabel_->setText(foundLabelText(lastResult_->count()));
            updateScanButtons();
        } else if (picked == accAct) {
            startCodeFinderForAddress(firstAddr, /*writesOnly=*/false);
        } else if (picked == wrAct) {
            startCodeFinderForAddress(firstAddr, /*writesOnly=*/true);
        }
    });
    // Ctrl+C copies the selected result addresses (the "Copy address(es)" menu
    // action), matching the address list's copy shortcut.
    auto* resultsCopySc = new QShortcut(QKeySequence::Copy, resultsView_);
    // Scoped to its list: two window-wide Ctrl+C shortcuts are ambiguous to
    // Qt, which then fires neither.
    resultsCopySc->setContext(Qt::WidgetShortcut);
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
    foundLabel_ = new QLabel(tr("Found: 0"));
    foundRow->addWidget(foundLabel_);
    foundRow->addStretch();
    auto* resHexCheck = new QCheckBox(tr("Hex"));
    resHexCheck->setToolTip(tr("Show result values in hexadecimal"));
    connect(resHexCheck, &QCheckBox::toggled, this, [this](bool on) { resultsModel_->setDisplayHex(on); });
    foundRow->addWidget(resHexCheck);
    leftLayout->addLayout(foundRow);

    auto* leftBtns = new QHBoxLayout;
    auto* memViewBtn = new QPushButton(tr("Memory View"));
    memViewBtn->setObjectName("memoryViewButton");
    memViewBtn->setToolTip(tr("Browse the selected process's memory"));
    connect(memViewBtn, &QPushButton::clicked, this, &MainWindow::onMemoryView);
    auto* addAddrBtn = new QPushButton(tr("Add Address"));
    connect(addAddrBtn, &QPushButton::clicked, this, [this]() {
        // CE uses formAddressChange for both add and edit.
        ce::gui::ChangeAddressDialog dlg("", mapValueType(valueTypeCombo_->currentIndex()),
                                         false, 1, this, /*showSigned=*/true, process_.get());
        openAddressDialog_ = &dlg;
        dlg.setWindowTitle(tr("Add address"));
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
            // Every field of the dialog, as Add Address Manually applies them.
            const int id = addressListModel_->addEntry(*addr, dlg.valueType(), tr("Manual entry"), expr, (size_t)dlg.length());
            addressListModel_->setHexView(id, dlg.showHex());
            addressListModel_->setSigned(id, dlg.isSigned());
        } else
            QMessageBox::warning(this, tr("Add Address"), QString(tr("Could not resolve \"%1\".")).arg(text.trimmed()));
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
    valueLayout->addWidget(new QLabel(tr("Value:")));
    scanValueEdit_ = new QLineEdit;
    scanValueEdit_->setObjectName("scanValue");
    valueLayout->addWidget(scanValueEdit_);
    // Second bound, only shown for "Value between..." scans.
    betweenAndLabel_ = new QLabel(tr("and"));
    betweenAndLabel_->setVisible(false);
    valueLayout->addWidget(betweenAndLabel_);
    scanValue2Edit_ = new QLineEdit;
    scanValue2Edit_->setObjectName("scanValueUpper");
    scanValue2Edit_->setVisible(false);
    valueLayout->addWidget(scanValue2Edit_);
    hexCheck_ = new QCheckBox(tr("Hex"));
    hexCheck_->setToolTip(tr("Interpret integer scan values as hexadecimal"));
    valueLayout->addWidget(hexCheck_);
    rightLayout->addLayout(valueLayout);

    // Scan type
    scanTypeCombo_ = new QComboBox;
    scanTypeCombo_->setObjectName("scanComparison");
    scanTypeCombo_->addItems({tr("Exact Value"), tr("Bigger than..."), tr("Smaller than..."),
        tr("Value between..."), tr("Unknown initial value"), tr("Increased value"),
        tr("Decreased value"), tr("Changed value"), tr("Unchanged value"), tr("Same as first scan"),
        tr("Increased value by..."), tr("Decreased value by...")});
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
        // Hex input only means something for integer-like values.
        bool hexApplies = true;
        if (valueTypeCombo_) {
            const auto vt = mapValueType(valueTypeCombo_->currentIndex());
            hexApplies = vt != ValueType::Float && vt != ValueType::Double && vt != ValueType::String &&
                         vt != ValueType::UnicodeString && vt != ValueType::ByteArray && vt != ValueType::Binary;
        }
        hexCheck_->setEnabled(takesValue && hexApplies);
    };
    connect(scanTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updateBetweenUi](int) { updateBetweenUi(); });
    updateBetweenUi();

    // Value type
    valueTypeCombo_ = new QComboBox;
    valueTypeCombo_->setObjectName("scanValueType");
    // Names match the cheat-table Type column / Change-address dialog (ce::valueTypeName)
    // and CE, so a type reads the same in the scanner and the address list. mapValueType
    // keys on the index, not the text, so the labels are free to be canonical.
    valueTypeCombo_->addItems({tr("Byte"), tr("2 Bytes"), tr("4 Bytes"), tr("8 Bytes"), tr("Float"), tr("Double"), tr("String"), tr("Unicode String"), tr("Array of byte"), tr("Binary"), tr("All"), tr("Pointer"), tr("Grouped"), tr("Custom")});
    valueTypeCombo_->setCurrentIndex(2); // 4 Bytes default
    rightLayout->addWidget(valueTypeCombo_);

    auto* floatLayout = new QHBoxLayout;
    floatRoundingCombo_ = new QComboBox;
    floatRoundingCombo_->setObjectName("scanRounding");
    floatRoundingCombo_->setToolTip(tr("Exact uses stored precision. Rounded uses the precision of your input. Truncated compares integer parts. Extreme uses a tolerance."));
    floatRoundingCombo_->addItems({tr("Exact"), tr("Rounded"), tr("Truncated"), tr("Extreme")});
    floatRoundingCombo_->setCurrentIndex(1);  // CE defaults float scans to Rounded
    floatToleranceEdit_ = new QLineEdit;
    floatToleranceEdit_->setObjectName("scanTolerance");
    floatToleranceEdit_->setToolTip(tr("Absolute difference allowed in Extreme mode. Leave blank or use 0 for automatic tolerance."));
    floatToleranceEdit_->setPlaceholderText(tr("Tolerance"));
    floatToleranceEdit_->setValidator(new QDoubleValidator(0.0, std::numeric_limits<double>::max(), 4096, floatToleranceEdit_));
    if (double tolerance = QSettings().value("scan/floatTolerance", 0.0).toDouble(); tolerance > 0)
        floatToleranceEdit_->setText(QString::number(tolerance, 'g', 12));
    floatLayout->addWidget(floatRoundingCombo_);
    floatLayout->addWidget(floatToleranceEdit_);
    rightLayout->addLayout(floatLayout);
    auto updateFloatOptions = [this]() {
        auto vt = mapValueType(valueTypeCombo_->currentIndex());
        bool isFloat = vt == ValueType::Float || vt == ValueType::Double || vt == ValueType::All;
        // Hide (not just disable) the float-only rounding/tolerance controls for
        // integer/text scans so the row collapses instead of leaving greyed
        // clutter. Tolerance appears only for the "Extreme" rounding mode.
        floatRoundingCombo_->setVisible(isFloat);
        floatToleranceEdit_->setVisible(isFloat && floatRoundingCombo_->currentIndex() == 3);
        // Type-aware placeholder to guide what to type (AOB wildcards, etc.).
        QString ph = tr("e.g. 100");
        switch (vt) {
            case ValueType::Float:
            case ValueType::Double:        ph = tr("e.g. 3.14"); break;
            case ValueType::String:
            case ValueType::UnicodeString: ph = tr("text to find"); break;
            case ValueType::ByteArray:     ph = tr("e.g. 48 8B ?? 05"); break;
            case ValueType::Binary:        ph = tr("e.g. 0110??01"); break;
            case ValueType::Pointer:       ph = tr("e.g. 0x7fabc000"); break;
            default:                       ph = tr("e.g. 100"); break;
        }
        scanValueEdit_->setPlaceholderText(ph);
    };
    connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions, updateBetweenUi](int) { updateFloatOptions(); updateBetweenUi(); });
    connect(floatRoundingCombo_, &QComboBox::currentIndexChanged, this,
        [updateFloatOptions](int) { updateFloatOptions(); });
    updateFloatOptions();

    // Buttons
    auto* btnLayout = new QHBoxLayout;
    firstScanBtn_ = new QPushButton(tr("First Scan"));
    // Accent "primary action" styling comes from the theme (QPushButton#primaryButton).
    firstScanBtn_->setObjectName("primaryButton");
    nextScanBtn_ = new QPushButton(tr("Next Scan"));
    nextScanBtn_->setObjectName("nextScanButton");
    nextScanBtn_->setEnabled(false);
    undoScanBtn_ = new QPushButton(tr("Undo Scan"));
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
    auto* optGroup = new QGroupBox(tr("Memory Scan Options"));
    auto* optLayout = new QGridLayout(optGroup);
    optLayout->addWidget(new QLabel(tr("From:")), 0, 0);
    fromAddressEdit_ = new QLineEdit("0000000000");
    fromAddressEdit_->setObjectName("scanFrom");
    fromAddressEdit_->setFont(monospaceFont());
    optLayout->addWidget(fromAddressEdit_, 0, 1);
    optLayout->addWidget(new QLabel(tr("To:")), 1, 0);
    toAddressEdit_ = new QLineEdit(QString::number(UINTPTR_MAX,16));
    toAddressEdit_->setObjectName("scanTo");
    toAddressEdit_->setFont(monospaceFont());
    optLayout->addWidget(toAddressEdit_, 1, 1);
    // Tri-state like CE: checked = must have the protection, unchecked = must NOT,
    // partial (grey) = don't care. Writable defaults to "must" (values live in
    // writable memory); Executable defaults to "don't care".
    writableCheck_ = new QCheckBox(tr("Writable"));
    writableCheck_->setTristate(true);
    writableCheck_->setCheckState(Qt::Checked);
    writableCheck_->setToolTip(tr("Checked: only writable regions. Unchecked: only "
                               "non-writable. Grey: any (don't care)."));
    optLayout->addWidget(writableCheck_, 2, 0, 1, 2);
    executableCheck_ = new QCheckBox(tr("Executable"));
    executableCheck_->setTristate(true);
    executableCheck_->setCheckState(Qt::PartiallyChecked);
    executableCheck_->setToolTip(tr("Checked: only executable regions. Unchecked: only "
                                 "non-executable. Grey: any (don't care)."));
    optLayout->addWidget(executableCheck_, 3, 0, 1, 2);
    fastScanCheck_ = new QCheckBox(tr("Fast Scan"));
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
        // The Settings dialog's default-type combo is shorter than the scanner's
        // (it omits Unicode String/Binary/All/Grouped/Custom), so its index must
        // be mapped, not applied raw: e.g. its "Array of byte" (7) and "Pointer"
        // (8) are scanner indices 8 and 11.
        int dvt = s.value("scan/defaultValueType", 2).toInt();
        static const int kSettingsToScanner[] = {0, 1, 2, 3, 4, 5, 6, 8, 11};
        constexpr int kMapSize = (int)(sizeof(kSettingsToScanner) / sizeof(kSettingsToScanner[0]));
        if (dvt >= 0 && dvt < kMapSize && kSettingsToScanner[dvt] < valueTypeCombo_->count())
            valueTypeCombo_->setCurrentIndex(kSettingsToScanner[dvt]);
    }

    percentCheck_ = new QCheckBox(tr("Compare by %"));
    optLayout->addWidget(percentCheck_, 5, 0);
    percentValueEdit_ = new QLineEdit("10");
    percentValueEdit_->setFixedWidth(68);
    percentValueEdit_->setEnabled(false);
    percentValueEdit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 4, percentValueEdit_));
    optLayout->addWidget(percentValueEdit_, 5, 1);

    auto* percent2Label = new QLabel(tr("Percent max:"));
    optLayout->addWidget(percent2Label, 6, 0);
    percentValue2Edit_ = new QLineEdit("20");
    percentValue2Edit_->setFixedWidth(68);
    percentValue2Edit_->setEnabled(false);
    percentValue2Edit_->setValidator(new QDoubleValidator(0.0, 1000000.0, 4, percentValue2Edit_));
    optLayout->addWidget(percentValue2Edit_, 6, 1);

    caseSensitiveCheck_ = new QCheckBox(tr("Case sensitive (text)"));
    caseSensitiveCheck_->setChecked(true);   // string scans default to case-sensitive
    optLayout->addWidget(caseSensitiveCheck_, 8, 0, 1, 2);

    // Region-type filters (CE's "Memory Scan Options": MEM_PRIVATE / MEM_IMAGE /
    // MEM_MAPPED). All on = scan everything (the default). Turning one off skips that
    // class of memory: Private = anonymous heap/stack, Image = loaded ELF modules,
    // Mapped = other file-backed maps. Backed by ScanConfig::scan{Private,Image,Mapped}.
    {
        QSettings s;
        auto* memRow = new QWidget;
        auto* memLayout = new QHBoxLayout(memRow);
        memLayout->setContentsMargins(0, 0, 0, 0);
        memPrivateCheck_ = new QCheckBox(tr("Private"));
        memPrivateCheck_->setToolTip(tr("Scan MEM_PRIVATE regions (anonymous heap, stack, private maps)"));
        memPrivateCheck_->setChecked(s.value("scan/memPrivate", true).toBool());
        memImageCheck_ = new QCheckBox(tr("Image"));
        memImageCheck_->setToolTip(tr("Scan MEM_IMAGE regions (loaded executable modules)"));
        memImageCheck_->setChecked(s.value("scan/memImage", true).toBool());
        memMappedCheck_ = new QCheckBox(tr("Mapped"));
        memMappedCheck_->setToolTip(tr("Scan MEM_MAPPED regions (other file-backed maps)"));
        memMappedCheck_->setChecked(s.value("scan/memMapped", true).toBool());
        memLayout->addWidget(memPrivateCheck_);
        memLayout->addWidget(memImageCheck_);
        memLayout->addWidget(memMappedCheck_);
        memLayout->addStretch();
        optLayout->addWidget(memRow, 9, 0, 1, 2);
        // Persist each toggle so the filter survives a restart (session preference).
        auto persist = [](const char* key, QCheckBox* box) {
            connect(box, &QCheckBox::toggled, box, [key](bool on) {
                QSettings s; s.setValue(key, on);
            });
        };
        persist("scan/memPrivate", memPrivateCheck_);
        persist("scan/memImage", memImageCheck_);
        persist("scan/memMapped", memMappedCheck_);
    }

    auto* textEncodingLabel = new QLabel(tr("Text encoding:"));
    optLayout->addWidget(textEncodingLabel, 7, 0);
    stringEncodingCombo_ = new QComboBox;
    stringEncodingCombo_->addItems({"UTF-8", "ISO-8859-1", "CP1252"});
    optLayout->addWidget(stringEncodingCombo_, 7, 1);

    auto* orderLabel = new QLabel(tr("Data order:"));
    scanByteOrderCombo_ = new QComboBox;
    scanByteOrderCombo_->setObjectName("scanByteOrder");
    scanByteOrderCombo_->addItem(tr("Auto (target)"), static_cast<int>(ce::ByteOrder::Unknown));
    scanByteOrderCombo_->addItem(tr("Little-endian"), static_cast<int>(ce::ByteOrder::Little));
    scanByteOrderCombo_->addItem(tr("Big-endian"), static_cast<int>(ce::ByteOrder::Big));
    scanByteOrderCombo_->setToolTip(tr("Choose the encoding of the data being scanned. Auto uses the selected target's data order."));
    orderLabel->setBuddy(scanByteOrderCombo_);
    optLayout->addWidget(orderLabel, 10, 0);
    optLayout->addWidget(scanByteOrderCombo_, 10, 1);
    auto* widthLabel = new QLabel(tr("Pointer size:"));
    scanPointerWidthCombo_ = new QComboBox;
    scanPointerWidthCombo_->setObjectName("scanPointerWidth");
    scanPointerWidthCombo_->addItem(tr("Auto (target)"), 0);
    scanPointerWidthCombo_->addItem(tr("4 bytes"), 4);
    scanPointerWidthCombo_->addItem(tr("8 bytes"), 8);
    scanPointerWidthCombo_->setToolTip(tr("Size of encoded pointers for Pointer, Grouped and Custom scans. A different saved record size requires a New Scan."));
    widthLabel->setBuddy(scanPointerWidthCombo_);
    optLayout->addWidget(widthLabel, 11, 0);
    optLayout->addWidget(scanPointerWidthCombo_, 11, 1);
    auto updateDataFormatUi = [this, orderLabel, widthLabel] {
        const auto type = mapValueType(valueTypeCombo_->currentIndex());
        const bool order = type != ValueType::Byte && type != ValueType::String &&
            type != ValueType::ByteArray && type != ValueType::Binary;
        const bool width = type == ValueType::Pointer || type == ValueType::Grouped || type == ValueType::Custom;
        orderLabel->setVisible(order); scanByteOrderCombo_->setVisible(order);
        widthLabel->setVisible(width); scanPointerWidthCombo_->setVisible(width);
    };
    connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this,
        [updateDataFormatUi](int) { updateDataFormatUi(); });
    updateDataFormatUi();

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
    // Resolve record address expressions through the app-wide symbol table, so a label
    // set in the Memory Viewer (or a module export) works as a record address.
    addressListModel_->setSymbolResolver(&luaResolver_);
    addressListModel_->setBeforeAaExecute([this]() { stopCodeFindersForInjection(); });
    // Let inline Address-column edits accept the full expression syntax.
    addressListModel_->setAddressResolver([this](const QString& t) { return parseAddressExpr(t); });
    addressListModel_->setActivationErrorCallback([this](const QString& title, const QString& message) {
        QMessageBox::warning(this, title, message);
    });
    luaEngine_.setAddressList(addressListModel_);
    registerLuaGuiBindings(luaEngine_.state());
    setLuaMainForm(this);
    // Run the user's autorun/ Lua scripts (CE autorun/) once the window is fully up.
    QTimer::singleShot(0, this, [this]() { runAutorunScripts(); });
    addressListView_ = new QTableView;
    addressListView_->setModel(addressListModel_);
    addressListView_->setAlternatingRowColors(true);   // activates the theme's zebra rows
    // Centered hint over the empty cheat table (matches the results-list hint).
    tableEmptyHint_ = new QLabel(
        tr("No saved addresses.\nDouble-click a result or use Add Address."),
        addressListView_->viewport());
    tableEmptyHint_->setAlignment(Qt::AlignCenter);
    tableEmptyHint_->setProperty("secondary", true);
    tableEmptyHint_->setWordWrap(true);
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
    // Inserts and removals rebuild it once per burst (scheduleAddressListRefresh).
    connect(addressListModel_, &QAbstractItemModel::modelReset, this, &MainWindow::reapplyGroupCollapse);
    connect(addressListModel_, &QAbstractItemModel::layoutChanged, this, &MainWindow::reapplyGroupCollapse);
    // Surface a reverted (protected) manual edit as a status-bar hint toward
    // find-what-writes, so "my edit doesn't stick" has an explanation.
    connect(addressListModel_, &AddressListModel::valueReverted, this,
        [this](uintptr_t addr, const QString& wrote, const QString& now) {
            statusBar()->showMessage(
                QString(tr("Value at 0x%1 was reverted (wrote %2, now %3). It looks protected: "
                        "right-click the entry and choose \"Find what writes\" to locate the "
                        "code that overwrites it.")).arg(addr, 0, 16).arg(wrote).arg(now), 9000);
        });
    updateTableHint();
    // System-wide hotkeys (X11): fire while the game is focused, like CE. The
    // dispatch map is keyed by the id we hand registerHotkey in rebuildValueHotkeys.
    globalHotkeys_ = new GlobalHotkeyManager(this);
    connect(globalHotkeys_, &GlobalHotkeyManager::activated, this, [this](int id, bool autoRepeat) {
        auto it = hotkeyActions_.find(id);
        if (it == hotkeyActions_.end() || (autoRepeat && !it->repeats)) return;
        const auto run = it->run;   // the action may rebuild the hotkeys
        run();
    });

    connect(addressListModel_, &QAbstractItemModel::modelReset, this, &MainWindow::rebuildValueHotkeys);
    connect(addressListModel_, &QAbstractItemModel::rowsInserted, this, &MainWindow::scheduleAddressListRefresh);
    connect(addressListModel_, &QAbstractItemModel::rowsRemoved, this, &MainWindow::scheduleAddressListRefresh);
    addressListView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    addressListView_->setFont(settingsMonospaceFont());
    addressListView_->verticalHeader()->setVisible(false);
    auto* addressHeader = addressListView_->horizontalHeader();
    addressHeader->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    addressHeader->setHighlightSections(false);
    addressListView_->setShowGrid(false);
    addressHeader->setMinimumSectionSize(48);
    addressHeader->setSectionResizeMode(0, QHeaderView::Fixed);
    addressHeader->resizeSection(0, 62);
    addressHeader->setSectionResizeMode(1, QHeaderView::Stretch);
    addressHeader->setSectionResizeMode(2, QHeaderView::Interactive);
    addressHeader->resizeSection(2, QFontMetrics(addressListView_->font()).horizontalAdvance("GameAssembly.so+0x123456") + 18);
    addressHeader->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    addressHeader->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    addressListView_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    // Drag-and-drop reordering (CE): drag an entry to move it; the model's dropMimeData
    // does the reorder (a group header carries its children) and the view must not do
    // its own row removal, so the model returns false from dropMimeData.
    addressListView_->setDragEnabled(true);
    addressListView_->setAcceptDrops(true);
    addressListView_->setDropIndicatorShown(true);
    addressListView_->setDragDropMode(QAbstractItemView::InternalMove);
    addressListView_->setDefaultDropAction(Qt::MoveAction);
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
        // Persistent indexes: the menu and the dialogs its actions open run
        // event loops in which table scripts and timers can add, remove or
        // move records. A persistent index follows its record (or becomes
        // invalid, row -1), so an action never lands on another record.
        QList<QPersistentModelIndex> selected;
        for (const auto& index : addressListView_->selectionModel()->selectedRows()) selected.push_back(index);

        if (!selected.isEmpty()) {
            const QPersistentModelIndex first = selected.first();
            int firstRow = first.row();
            const auto& ents0 = addressListModel_->entries();
            // "Edit script..." for a single auto-assembler entry — it has no
            // address to edit, so this opens the script in the AA editor.
            if (selected.size() == 1 && addressListModel_->isScriptEntry(firstRow)) {
                menu.addAction(tr("Edit script..."), [this, first]() { if (first.row() >= 0) editScriptEntry(first.row()); });
                menu.addSeparator();
            } else if (selected.size() == 1 && firstRow < (int)addressListModel_->entries().size()
                       && !addressListModel_->entries()[firstRow].isGroup) {
                // CE "Change address" (formAddressChangeUnit): edit address/type/flags.
                menu.addAction(tr("Change address..."), [this, first]() {
                    const int firstRow = first.row();
                    if (firstRow < 0 || firstRow >= (int)addressListModel_->entries().size()) return;
                    // The dialog's event loop runs table scripts that can add or
                    // remove records: take the ID now, never a reference or row.
                    const auto& e = addressListModel_->entries()[firstRow];
                    const int id = e.id;
                    QString addrStr = !e.addressExpr.isEmpty()
                        ? e.addressExpr : QString("0x%1").arg((qulonglong)e.address, 0, 16);
                    ce::gui::ChangeAddressDialog dlg(addrStr, e.type, e.showAsHex,
                                                     (int)e.byteCount, this, e.showAsSigned,
                                                     process_.get());
                    openAddressDialog_ = &dlg;
                    if (dlg.exec() != QDialog::Accepted) return;
                    if (addressListModel_->rowOfId(id) < 0) return;   // deleted meanwhile
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
            menu.addAction(tr("Cut"), QKeySequence::Cut, this, [this]() { onCopyAddresses(); onDeleteAddresses(); });
            menu.addAction(tr("Copy"), QKeySequence::Copy, this, &MainWindow::onCopyAddresses);
            // The same paste as Ctrl+V: every field, groups, scripts and CE XML.
            menu.addAction(tr("Paste"), QKeySequence::Paste, this, &MainWindow::onPasteAddresses);
            // Copy an individual field of the first selected entry to the clipboard.
            if (firstRow >= 0 && firstRow < (int)ents0.size()) {
                const auto& fe = ents0[firstRow];
                auto* copyMenu = menu.addMenu(tr("Copy field"));
                copyMenu->addAction(tr("Description"), [fe]() {
                    QApplication::clipboard()->setText(fe.description);
                });
                if (!fe.isGroup && fe.autoAsmScript.isEmpty()) {
                    copyMenu->addAction(tr("Address"), [fe]() {
                        QApplication::clipboard()->setText(
                            fe.addressExpr.isEmpty() ? QString("0x%1").arg(fe.address, 0, 16)
                                                     : fe.addressExpr);
                    });
                    copyMenu->addAction(tr("Value"), [fe]() {
                        QApplication::clipboard()->setText(fe.currentValue);
                    });
                }
                if (!fe.autoAsmScript.isEmpty())
                    copyMenu->addAction(tr("Script"), [fe]() {
                        QApplication::clipboard()->setText(fe.autoAsmScript);
                    });
            }
            menu.addAction(tr("Delete"), QKeySequence::Delete, this, &MainWindow::onDeleteAddresses);

            menu.addSeparator();
            // Rarely used items sit in submenus so the menu stays one column at
            // large text sizes (it wrapped into two at 130 DPI).
            QMenu* arrangeMenu = menu.addMenu(tr("Arrange"));
            arrangeMenu->addAction(tr("Indent"), [this, selected]() {
                QList<int> rows;
                for (const auto& idx : selected) if (idx.row() >= 0) rows.append(idx.row());
                addressListModel_->indentRows(rows);
            });
            arrangeMenu->addAction(tr("Outdent"), [this, selected]() {
                QList<int> rows;
                for (const auto& idx : selected) if (idx.row() >= 0) rows.append(idx.row());
                addressListModel_->outdentRows(rows);
            });
            // CE "Add the selected records to a new group": wrap the selection under a
            // fresh group header (prompts for its name, like CE's group description).
            arrangeMenu->addAction(tr("Add to new group..."), [this, selected]() {
                QList<int> rows;
                for (const auto& idx : selected) if (idx.row() >= 0) rows.append(idx.row());
                if (rows.isEmpty()) return;
                bool ok = false;
                QString name = QInputDialog::getText(this, tr("New group"),
                    tr("Group name:"), QLineEdit::Normal, tr("New group"), &ok);
                if (!ok) return;
                if (name.isEmpty()) name = tr("New group");
                addressListModel_->groupSelectedRows(rows, name);
            });
            if (selected.size() == 1) {
                auto* up = arrangeMenu->addAction(tr("Move Up"), [this, first]() { if (first.row() >= 0) moveSelectedEntry(first.row(), -1); });
                up->setShortcut(QKeySequence("Ctrl+Up"));
                auto* down = arrangeMenu->addAction(tr("Move Down"), [this, first]() { if (first.row() >= 0) moveSelectedEntry(first.row(), +1); });
                down->setShortcut(QKeySequence("Ctrl+Down"));
            }

            menu.addSeparator();
            // Set the value of ALL selected entries at once (CE's batch set value).
            menu.addAction(tr("Set value..."), [this, selected]() {
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
                const QString valuePrompt = selected.size() == 1
                    ? tr("New value for 1 selected entry:")
                    : tr("New value for %1 selected entries:").arg(selected.size());
                QString v = QInputDialog::getText(this, tr("Set value"), valuePrompt,
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
            auto* freezeMenu = menu.addMenu(tr("Freeze Mode"));
            freezeMenu->addAction(tr("Normal"), [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::Normal);
            });
            freezeMenu->addAction(tr("Increase Only"), [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::IncreaseOnly);
            });
            freezeMenu->addAction(tr("Decrease Only"), [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::DecreaseOnly);
            });
            freezeMenu->addAction(tr("Never Increase"), [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::NeverIncrease);
            });
            freezeMenu->addAction(tr("Never Decrease"), [this, selected]() {
                for (auto& idx : selected) addressListModel_->setFreezeMode(idx.row(), FreezeMode::NeverDecrease);
            });

            // Obfuscated values: declare a codec so the value is displayed decoded and
            // edited/frozen by its logical value (block 6). Reuses ce::ValueCodec::parse.
            // How the entry is shown and decoded: format, colour, dropdown, codec.
            QMenu* encodingMenu = menu.addMenu(tr("Display"));
            encodingMenu->addAction(tr("Set value codec..."), [this, selected]() {
                if (selected.isEmpty() || selected.first().row() < 0) return;
                QString cur = QString::fromStdString(
                    addressListModel_->entryCodecSpec(selected.first().row()));
                bool ok = false;
                QString spec = QInputDialog::getText(this, tr("Value codec"),
                    tr("How the game obfuscates this value in memory:\n"
                    "none, xor:0xKEY, add:N, rol:N or ror:N (e.g. xor:0x5A).\n\n"
                    "The list shows the decoded value; edits and freezes are encoded back."),
                    QLineEdit::Normal, cur, &ok);
                if (!ok) return;
                spec = spec.trimmed();
                ce::ValueCodec codec;   // default: none
                if (!spec.isEmpty() && spec.compare("none", Qt::CaseInsensitive) != 0) {
                    auto c = ce::ValueCodec::parse(spec.toStdString());
                    if (!c) {
                        QMessageBox::warning(this, tr("Invalid codec"),
                            tr("Use none, xor:0xKEY, add:N, rol:N, or ror:N."));
                        return;
                    }
                    codec = *c;
                }
                for (auto& idx : selected) addressListModel_->setEntryCodec(idx.row(), codec);
            });

            auto* orderMenu = encodingMenu->addMenu(tr("Data order"));
            for (const auto& choice : {std::pair{tr("Auto (target)"), ByteOrder::Unknown},
                                std::pair{tr("Little-endian"), ByteOrder::Little},
                                std::pair{tr("Big-endian"), ByteOrder::Big}}) {
                auto* action = orderMenu->addAction(choice.first);
                action->setCheckable(true);
                const auto& entry = addressListModel_->entries()[selected.first().row()];
                action->setChecked(entry.dataByteOrder == choice.second);
                connect(action, &QAction::triggered, this, [this, selected, order=choice.second] {
                    for (auto& index : selected) {
                        if (index.row() < 0) continue;
                        const auto width = addressListModel_->entries()[index.row()].pointerWidth;
                        addressListModel_->setEntryDataFormat(index.row(), order, width);
                    }
                });
            }
            auto* widthMenu = encodingMenu->addMenu(tr("Pointer size"));
            for (const auto& choice : {std::pair{tr("Auto (target)"), 0}, std::pair{tr("4 bytes"), 4}, std::pair{tr("8 bytes"), 8}}) {
                auto* action = widthMenu->addAction(choice.first); action->setCheckable(true);
                action->setChecked(addressListModel_->entries()[selected.first().row()].pointerWidth == choice.second);
                connect(action, &QAction::triggered, this, [this, selected, width=choice.second] {
                    for (auto& index : selected) {
                        if (index.row() < 0) continue;
                        const auto order = addressListModel_->entries()[index.row()].dataByteOrder;
                        addressListModel_->setEntryDataFormat(index.row(), order, width);
                    }
                });
            }

            menu.addSeparator();
            auto* typeMenu = menu.addMenu(tr("Change type"));
            const std::pair<QString, ValueType> typeChoices[] = {
                {tr("Byte"), ValueType::Byte}, {tr("2 Bytes"), ValueType::Int16},
                {tr("4 Bytes"), ValueType::Int32}, {tr("8 Bytes"), ValueType::Int64},
                {tr("Float"), ValueType::Float}, {tr("Double"), ValueType::Double},
                {tr("Pointer"), ValueType::Pointer},
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
            encodingMenu->addSeparator();
            auto* hexAct = encodingMenu->addAction(tr("Show as hexadecimal"));
            hexAct->setCheckable(true);
            hexAct->setChecked(firstHex);
            connect(hexAct, &QAction::triggered, this, [this, selected, firstHex]() {
                for (auto& idx : selected) addressListModel_->setShowAsHex(idx.row(), !firstHex);
            });

            // Static-address durability: rewrite a raw scanned address as
            // "module+0xoffset" so a saved table survives the module rebasing
            // (PIE/ASLR) on the next launch. Only meaningful with a process attached
            // (module bases known); leaves pointer/expression records untouched.
            if (process_) {
                menu.addAction(tr("Convert to module+offset"), [this, selected]() {
                    if (!process_) return;
                    const auto modules = process_->modules();   // by value: hold it, don't dangle
                    const auto& entries = addressListModel_->entries();
                    int converted = 0, skipped = 0;
                    for (const auto& idx : selected) {
                        int row = idx.row();
                        if (row < 0 || row >= (int)entries.size()) continue;
                        const auto& e = entries[row];
                        if (e.isGroup || !e.autoAsmScript.isEmpty()) continue;
                        if (!e.addressExpr.isEmpty()) { ++skipped; continue; } // already symbolic
                        std::string expr = ce::moduleOffsetString(modules, e.address);
                        if (expr.empty()) { ++skipped; continue; }             // not inside a module
                        addressListModel_->setAddressExpression(e.id, expr);
                        ++converted;
                    }
                    const QString skippedText = skipped ? QString(" ") + tr("(%1 skipped)").arg(skipped) : QString();
                    const QString convertedText = converted == 1
                        ? tr("Converted 1 address to module+offset%1").arg(skippedText)
                        : tr("Converted %1 addresses to module+offset%2").arg(converted).arg(skippedText);
                    statusBar()->showMessage(convertedText, 4000);
                });
            }

            // Open the memory browser at this entry's exact address (CE's
            // "Browse this memory region"). Skipped for script/group rows, which
            // have no address.
            if (firstRow >= 0 && firstRow < (int)ents0.size()
                && !ents0[firstRow].isGroup && ents0[firstRow].autoAsmScript.isEmpty()) {
                menu.addAction(tr("Browse this memory region"), [this, selected]() {
                    if (!process_ || selected.isEmpty()) return;
                    auto& entries = addressListModel_->entries();
                    int row = selected.first().row();
                    if (row >= 0 && row < (int)entries.size())
                        openMemoryView(entries[row].address);   // full-featured viewer
                });
            }
            menu.addAction(tr("Find what accesses this address"), [this, selected]() {
                if (!selected.isEmpty())
                    startCodeFinder(selected.first().row(), false);
            });
            menu.addAction(tr("Find what writes to this address"), [this, selected]() {
                if (!selected.isEmpty())
                    startCodeFinder(selected.first().row(), true);
            });
            // CE "Pointer scan for this address".
            if (firstRow >= 0 && firstRow < (int)ents0.size()
                && !ents0[firstRow].isGroup && ents0[firstRow].autoAsmScript.isEmpty()) {
                menu.addAction(tr("Pointer scan for this address"), [this, selected]() {
                    if (!process_ || selected.isEmpty()) return;
                    const int row = selected.first().row();
                    const auto& entries = addressListModel_->entries();
                    if (row < 0 || row >= (int)entries.size()) return;
                    const auto type = entries[row].type;
                    auto* dlg = new PointerScanDialog(process_.get(), this);
                    trackTargetWindow(dlg);
                    dlg->setAttribute(Qt::WA_DeleteOnClose);
                    dlg->setTargetAddress(entries[row].address);
                    connect(dlg, &PointerScanDialog::addressSelected, this,
                            [this, type](uintptr_t addr, const QString& expr) {
                                // The path string is a resolvable pointer expression; store it
                                // AS the address so the record re-resolves each refresh and
                                // survives the module rebasing on restart (the point of a scan).
                                // The record keeps the scanned entry's value type.
                                addressListModel_->addEntry(addr, type, expr, expr);
                            });
                    dlg->show();
                });
            }
            // CE "Change Color" — per-record display color.
            encodingMenu->addAction(tr("Change Color..."), [this, selected]() {
                if (selected.isEmpty()) return;
                // The dialog runs an event loop in which table scripts may add or
                // remove records: keep IDs, not rows or a reference into the list.
                std::vector<int> ids;
                QColor initial = addressListView_->palette().color(QPalette::Text);
                {
                    const auto& entries = addressListModel_->entries();
                    const int row = selected.first().row();
                    if (row >= 0 && row < (int)entries.size() && !entries[row].color.isEmpty()) initial = QColor(entries[row].color);
                    for (const auto& idx : selected)
                        if (idx.row() >= 0 && idx.row() < (int)entries.size()) ids.push_back(entries[idx.row()].id);
                }
                QColor c = QColorDialog::getColor(initial, this, tr("Change record color"));
                if (!c.isValid()) return;
                for (int id : ids) addressListModel_->setColor(id, c.name().toStdString());
            });
            // CE "Set/Change dropdown selection options".
            if (selected.size() == 1) {
                encodingMenu->addAction(tr("Dropdown options..."), [this, first]() {
                    const int firstRow = first.row();
                    if (firstRow < 0 || firstRow >= (int)addressListModel_->entries().size()) return;
                    const int id = addressListModel_->entries()[firstRow].id;   // rows can move during the dialog
                    bool ok = false;
                    QString v = QInputDialog::getMultiLineText(this, tr("Dropdown options"),
                        tr("The values this entry can be set to from a dropdown, one per line,\n"
                        "as value:label or just value. For example:\n0:Off\n1:On"),
                        addressListModel_->dropdownList(firstRow), &ok);
                    if (ok)
                        addressListModel_->setDropdownList(id, v.remove('\r').split('\n', Qt::SkipEmptyParts).join('\n'));
                });
            }
            if (selected.size() == 1) {
                menu.addSeparator();
                // Cheat Engine's Set/Change hotkey window: every hotkey of the
                // record, each with its action, value and description.
                menu.addAction(tr("Set/Change hotkeys..."), [this, selected]() {
                    int row = selected.first().row();
                    const auto& entries = addressListModel_->entries();
                    if (row < 0 || row >= (int)entries.size()) return;
                    QList<HotkeyBinding> bindings;
                    for (const auto& hotkey : addressListModel_->hotkeysOf(row))
                        bindings.push_back({hotkey.action, QString::fromStdString(hotkey.keys),
                                            QString::fromStdString(hotkey.value), QString::fromStdString(hotkey.description)});
                    const int id = entries[row].id;   // rows can move during the dialog
                    HotkeysDialog dialog(entries[row].description, bindings, this);
                    if (dialog.exec() != QDialog::Accepted) return;
                    row = addressListModel_->rowOfId(id);
                    if (row < 0) return;
                    std::vector<ce::CheatHotkey> hotkeys;
                    for (const auto& binding : dialog.hotkeys())
                        hotkeys.push_back({binding.action, binding.keys.toStdString(), binding.value.toStdString(),
                                           binding.description.toStdString()});
                    addressListModel_->setHotkeys(row, hotkeys);
                    rebuildValueHotkeys();   // grab the new keys (and release cleared ones) now
                });
            }
        }

        menu.addSeparator();
        menu.addAction(tr("Add Address Manually..."), [this]() {
            // CE's "Add Address Manually" opens the same formAddressChangeUnit as
            // "Change address", so a new entry gets its type, flags, length, and an
            // optional structured pointer in one dialog.
            ce::gui::ChangeAddressDialog dlg("", mapValueType(valueTypeCombo_->currentIndex()),
                                             false, 0, this, /*showSigned=*/true, process_.get());
            openAddressDialog_ = &dlg;
            if (dlg.exec() != QDialog::Accepted) return;
            const QString a = dlg.address();
            if (a.trimmed().isEmpty()) return;
            bool numeric = false;
            qulonglong v = a.toULongLong(&numeric, 16);
            int id;
            if (numeric && !a.contains('[') && !a.contains('+') && !a.contains(' ')) {
                id = addressListModel_->addEntry((uintptr_t)v, dlg.valueType(),
                                                 tr("No description"), QString(), (size_t)dlg.length());
            } else {
                // Symbolic / module+offset / pointer chain: store the expression so it
                // re-resolves live, seeding the initial numeric address if resolvable.
                uintptr_t addr0 = 0;
                if (auto r = parseAddressExpr(a)) addr0 = *r;
                id = addressListModel_->addEntry(addr0, dlg.valueType(),
                                                 tr("No description"), a, (size_t)dlg.length());
            }
            addressListModel_->setHexView(id, dlg.showHex());
            addressListModel_->setSigned(id, dlg.isSigned());
        });
        menu.addAction(tr("Add Group"), [this]() {
            addressListModel_->addGroup();
        });
        // With entries selected, Paste is already in the edit group above.
        if (selected.isEmpty()) menu.addAction(tr("Paste"), QKeySequence::Paste, this, &MainWindow::onPasteAddresses);

        menu.addSeparator();
        // Whole-table actions only on empty space: with an entry under the cursor the
        // menu is about that entry, and it has to fit one column on a 1080p screen.
        if (selected.isEmpty()) {
            menu.addAction(tr("Enable all"), [this]() { addressListModel_->setAllActive(true); });
            menu.addAction(tr("Disable all"), [this]() { addressListModel_->setAllActive(false); });
        }

        menu.exec(addressListView_->viewport()->mapToGlobal(pos));
    });
    // Delete key shortcut
    auto* delShortcut = new QShortcut(QKeySequence::Delete, addressListView_);
    // Only in the address list: window-wide, Delete in the scan results
    // deleted the cheat table's selected records.
    delShortcut->setContext(Qt::WidgetShortcut);
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
    copyShortcut->setContext(Qt::WidgetShortcut);
    connect(copyShortcut, &QShortcut::activated, this, &MainWindow::onCopyAddresses);
    auto* pasteShortcut = new QShortcut(QKeySequence::Paste, addressListView_);
    pasteShortcut->setContext(Qt::WidgetShortcut);
    connect(pasteShortcut, &QShortcut::activated, this, &MainWindow::onPasteAddresses);
    // Space toggles the active/frozen state of ALL selected entries (CE-style),
    // regardless of the focused column. WidgetShortcut so it doesn't fire while a
    // cell editor is open (there Space types a space). Intercepts before the
    // table's default single-cell checkbox toggle, so there is no double-toggle.
    auto* spaceShortcut = new QShortcut(QKeySequence(Qt::Key_Space), addressListView_);
    spaceShortcut->setContext(Qt::WidgetShortcut);
    // Like CE, every selected record takes the opposite of the current one's
    // state: toggling each in turn would undo a group's cascade on a selected
    // child. Rows are taken by id, since an activation can add or move records.
    connect(spaceShortcut, &QShortcut::activated, this, [this]() {
        const auto sel = addressListView_->selectionModel()->selectedRows();
        if (sel.isEmpty()) return;
        const auto& ents = addressListModel_->entries();
        int lead = addressListView_->currentIndex().row();
        if (!addressListView_->selectionModel()->isRowSelected(lead, {})) lead = sel.first().row();
        if (lead < 0 || lead >= (int)ents.size()) return;
        const auto state = ents[lead].active ? Qt::Unchecked : Qt::Checked;
        std::vector<int> ids;
        for (const auto& idx : sel)
            if (idx.row() >= 0 && idx.row() < (int)ents.size()) ids.push_back(ents[idx.row()].id);
        for (int id : ids) {
            const int row = addressListModel_->rowOfId(id);
            if (row >= 0) addressListModel_->setData(addressListModel_->index(row, 0), state, Qt::CheckStateRole);
        }
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
    procRow->addSpacing(4);
    procRow->addWidget(processLabel_);
    procRow->addSpacing(10);
    procRow->addWidget(processDetail_, 1);
    progressBar_->setFixedWidth(220);
    procRow->addWidget(progressBar_);
    sv->addLayout(procRow);

    // Main row: found-results list on the left (stretches with the window), and
    // the scan controls in a fixed-width block on the right (Cheat Engine's shape).
    // The "Found: N" count and the results' Hex toggle head the results column, so
    // that Hex box sits on the list it formats rather than above the scan buttons
    // (where it read as a second copy of the scan value's Hex box).
    auto* mainRow = new QHBoxLayout;
    auto* foundBlock = new QVBoxLayout;
    auto* foundRow2 = new QHBoxLayout;
    foundRow2->addWidget(foundLabel_);
    foundRow2->addStretch();
    foundRow2->addWidget(resHexCheck);
    foundBlock->addLayout(foundRow2);
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
    scanForm->addWidget(new QLabel(tr("Scan Value")), 0, 0, Qt::AlignRight | Qt::AlignVCenter);
    auto* valRow = new QHBoxLayout;
    valRow->setSpacing(4);
    valRow->addWidget(scanValueEdit_, 1);
    valRow->addWidget(betweenAndLabel_);
    valRow->addWidget(scanValue2Edit_, 1);
    valRow->addWidget(hexCheck_);
    scanForm->addLayout(valRow, 0, 1);
    scanForm->addWidget(new QLabel(tr("Scan Type")), 1, 0, Qt::AlignRight | Qt::AlignVCenter);
    scanForm->addWidget(scanTypeCombo_, 1, 1);
    scanForm->addWidget(new QLabel(tr("Value Type")), 2, 0, Qt::AlignRight | Qt::AlignVCenter);
    scanForm->addWidget(valueTypeCombo_, 2, 1);
    auto* floatRow2 = new QHBoxLayout;
    floatRow2->setSpacing(4);
    floatRow2->addWidget(floatRoundingCombo_);
    floatRow2->addWidget(floatToleranceEdit_);
    floatRow2->addStretch();
    auto* roundingLabel = new QLabel(tr("Rounding"));
    roundingLabel->setBuddy(floatRoundingCombo_);
    scanForm->addWidget(roundingLabel, 3, 0, Qt::AlignRight | Qt::AlignVCenter);
    scanForm->addLayout(floatRow2, 3, 1);
    auto updateRoundingLabel = [this, roundingLabel]() {
        const auto vt = mapValueType(valueTypeCombo_->currentIndex());
        roundingLabel->setVisible(vt == ValueType::Float || vt == ValueType::Double || vt == ValueType::All);
    };
    connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this, [updateRoundingLabel](int) { updateRoundingLabel(); });
    updateRoundingLabel();
    cv->addLayout(scanForm);

    // Memory Scan Options group (From/To, Writable/Executable, Fast Scan, etc.).
    cv->addWidget(optGroup);
    auto updateTextOptions = [this, textEncodingLabel]() {
        auto type = mapValueType(valueTypeCombo_->currentIndex());
        bool text = type == ValueType::String || type == ValueType::UnicodeString;
        caseSensitiveCheck_->setVisible(text);
        stringEncodingCombo_->setVisible(type == ValueType::String);
        textEncodingLabel->setVisible(type == ValueType::String);
    };
    connect(valueTypeCombo_, &QComboBox::currentIndexChanged, this, [updateTextOptions]() { updateTextOptions(); });
    updateTextOptions();
    cv->addStretch(1);
    auto* controlsScroll = new QScrollArea;
    controlsScroll->setObjectName("scanControlsScroll");
    controlsScroll->setFrameShape(QFrame::NoFrame);
    controlsScroll->setWidgetResizable(true);
    controlsScroll->setWidget(controls);
    controlsScroll->setMinimumWidth(controls->minimumSizeHint().width() + 18);
    controlsScroll->setMaximumWidth(controls->minimumSizeHint().width() + 36);
    controlsScroll->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Expanding);
    mainRow->addWidget(controlsScroll);
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
    vsplit->setChildrenCollapsible(false);
    // Sizes for a 10 pt font at 96 DPI, scaled up for larger text (GNOME's text
    // scaling, bigger fonts) so the scan options fit without scrolling.
    const double textScale = std::max(1.0, fontMetrics().height() / 17.0);
    vsplit->setSizes({int(480 * textScale), int(220 * textScale)});
    v->addWidget(vsplit, 1);
    addressListView_->setMinimumHeight(140);

    auto* bottomBar = new QHBoxLayout;
    auto* advBtn = new QPushButton(tr("Advanced Options"));
    // CE "Advanced Options" = the Code list (AdvancedOptionsUnit): a persistent
    // list of code addresses from find-what-writes, with disassemble/NOP/restore.
    connect(advBtn, &QPushButton::clicked, this, &MainWindow::showAdvancedOptions);
    auto* extrasBtn = new QPushButton(tr("Table Extras"));
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
    // A group comes with its subtree, as Delete (and so Cut) takes it: a cut
    // group pasted back must not be an empty header.
    std::vector<int> indents;
    for (const auto& e : addressListModel_->entries()) indents.push_back(e.indent);
    std::vector<std::size_t> rows;
    for (const auto& idx : selected)
        if (idx.row() >= 0 && idx.row() < (int)indents.size()) rows.push_back(static_cast<std::size_t>(idx.row()));
    QJsonArray copied;
    for (auto row : ce::expandGroupDeletion(indents, rows))
        if ((qsizetype)row < allEntries.size()) copied.append(allEntries[(qsizetype)row].toObject());

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
    addressListModel_->fromJson(entries, true);
}

void MainWindow::onFreezeTimer() {
    if (process_)
        addressListModel_->freezeWrite(process_.get());
}

// What a save writes, without what changes on its own: live values, on/off
// state, group folding, and the resolved address of a pointer record.
QByteArray MainWindow::tableFingerprint() const {
    QJsonArray entries;
    for (const auto& value : addressListModel_->toJson()) {
        auto record = value.toObject();
        record.remove("value"); record.remove("active"); record.remove("collapsed");
        if (!record.value("addressExpr").toString().isEmpty()) record.remove("address");
        entries.append(record);
    }
    QByteArray print = QJsonDocument(entries).toJson(QJsonDocument::Compact);
    print += '\0'; print += tableComment_.toUtf8();
    print += '\0'; print += tableLuaScript_.toUtf8();
    for (const auto& c : disasmAnnotations_) {
        print += '\0'; print += QByteArray::fromStdString(c.address + '\x1f' + c.comment + '\x1f' + c.label);
    }
    return print;
}

void MainWindow::markTableSaved() { savedTableFingerprint_ = tableFingerprint(); }

void MainWindow::restartAfterLanguageChange() {
    // closeEvent() offers to save the table and releases the target users
    // (breakpoints, injected code) before the process goes away. Start the new
    // instance only after that close was accepted, so a cancelled save prompt
    // does not leave two instances behind and the release is never skipped.
    if (!close()) return;
    if (!ce::gui::launchRestart())
        QMessageBox::warning(nullptr, tr("Language"),
            tr("Cheat Engine could not restart itself. Start it again to apply the language."));
    QCoreApplication::quit();
}

// Before the table is replaced or the window closes: Save, Discard or Cancel
// when it has changes no file holds. Nothing tracked this, so edits were
// dropped without a word.
bool MainWindow::maybeSaveTable() {
    // Headless (the offscreen test platform): nobody can answer a prompt.
    const auto platform = QGuiApplication::platformName();
    if (platform == "offscreen" || platform == "minimal") return true;
    // Nothing loaded or saved yet: only content is a change.
    if (savedTableFingerprint_.isNull() && addressListModel_->rowCount() == 0 && tableComment_.isEmpty() &&
        tableLuaScript_.isEmpty() && disasmAnnotations_.empty())
        return true;
    if (tableFingerprint() == savedTableFingerprint_) return true;
    const auto answer = QMessageBox::question(this, tr("Unsaved changes"),
        tr("The cheat table has changes that are not saved. Save them?"),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Save);
    if (answer == QMessageBox::Discard) return true;
    if (answer != QMessageBox::Save) return false;
    onSaveTable();
    return tableFingerprint() == savedTableFingerprint_;   // saved (not cancelled or failed)
}

void MainWindow::closeEvent(QCloseEvent* ev) {
    if (!maybeSaveTable()) { ev->ignore(); return; }
    if (!releaseTargetUsers()) { ev->ignore(); return; }
    // Remember where the user put the window and how they sized the panels, so
    // the next launch comes up the same (restored in the constructor).
    QSettings s;
    s.setValue("mainwindow/geometry", saveGeometry());
    for (auto* sp : findChildren<QSplitter*>())
        if (!sp->objectName().isEmpty())
            s.setValue("mainwindow/splitter/" + sp->objectName(), sp->saveState());
    QMainWindow::closeEvent(ev);
}

bool MainWindow::releaseTargetUsers(bool force) {
    // A scan worker is reading process_: the target cannot change under it.
    // Callers retry (the exit check runs again, attachToPid re-queues).
    if (scanInProgress_ && !force) return false;
    const bool released = releaseTargetUsersOnce(force);
    // The models stop using the old process at once: the caller may open a
    // dialog (an event loop with timers and hotkeys) before it hands them the
    // new one, and the old handle is about to be freed.
    if (released || force) {
        if (addressListModel_) addressListModel_->setProcess(nullptr);
        if (resultsModel_) resultsModel_->setProcess(nullptr);
    }
    return released;
}

bool MainWindow::releaseTargetUsersOnce(bool force) {
    AutoAsmUiOperation retirement(&autoAsm_, AutoAsmUiOperation::Purpose::Retire);
    if (!retirement && !force) return false;
    // Release debugger traces before restoring injected code. Editors must keep
    // their original dependencies and recovery UI until cleanup succeeds.
    if (debuggerWindow_) delete debuggerWindow_;
    for (auto& finder : codeFinders_) if (finder) finder->stop();
    const auto windows = targetWindows_;
    for (const auto& window : windows)
        if (window && !qobject_cast<ScriptEditor*>(window.data())) delete window.data();
    struct Owner { uint64_t order; int id; QPointer<ScriptEditor> editor; };
    std::vector<Owner> owners;
    for (const auto& window : targetWindows_)
        if (auto* editor = qobject_cast<ScriptEditor*>(window.data()); editor && editor->injectionOrder())
            owners.push_back({editor->injectionOrder(), -1, editor});
    if (addressListModel_) for (const auto& entry : addressListModel_->entries())
        if (entry.autoAsmOrder) owners.push_back({entry.autoAsmOrder, entry.id, {}});
    std::stable_sort(owners.begin(), owners.end(), [](const Owner& a, const Owner& b) { return a.order > b.order; });
    bool cleaned = true;
    for (const auto& owner : owners) {
        if (owner.editor) {
            if (!owner.editor->cleanupInjection(!force)) {
                cleaned = false;
                if (!force) { owner.editor->show(); owner.editor->raise(); return false; }
            }
        } else if (owner.id >= 0 && addressListModel_->byId(owner.id) && !addressListModel_->setActive(owner.id, false)) {
            cleaned = false;
            if (!force) return false;
        }
    }
    if (addressListModel_ && !addressListModel_->deactivateAll()) cleaned = false;
    if (!cleaned && !force) return false;
    // Delete windows while their target, finders and Lua engine still exist.
    // QPointer also covers nested windows deleted with one of their parents.
    while (!targetWindows_.empty()) {
        const auto window = targetWindows_.back();
        targetWindows_.pop_back();
        if (window) delete window.data();
    }
    // Finder-window destruction callbacks and refresh timers borrow these.
    codeFinders_.clear();
    codeFinderDebuggers_.clear();
    // Saved undo belongs to the current address space. Keep its process handle
    // and records available if restoration fails, so the user can repair/retry.
    if (scanByteOrderCombo_) scanByteOrderCombo_->setCurrentIndex(0);
    if (scanPointerWidthCombo_) scanPointerWidthCombo_->setCurrentIndex(0);
    for (auto& viewer : memoryViewers_) if (viewer) viewer->detachFromTarget();
    memoryViewers_.clear();
    for (auto& dissector : structDissectors_) if (dissector) dissector->detachFromTarget();
    structDissectors_.clear();
    if (advancedOptions_) advancedOptions_->setProcess(nullptr);
    if (openAddressDialog_) openAddressDialog_->detachFromTarget();
    // A paused target must not stay frozen once we leave it.
    if (pauseAction_ && pauseAction_->isChecked()) {
        if (auto pid = ce::localTargetPid(process_.get())) ::kill(*pid, SIGCONT);
        QSignalBlocker quiet(pauseAction_);
        pauseAction_->setChecked(false);
    }
    snapshot_.reset();
    allocations_.clear();
    luaEngine_.setProcess(nullptr);
    luaResolver_.clear();
    return cleaned;
}

MainWindow::~MainWindow() {
    // Normal close can be refused on cleanup failure. Forced destruction still
    // attempts cleanup while these borrowed dependencies are alive, without a
    // modal dialog entering an event loop during object destruction.
    if (addressListModel_) {
        addressListModel_->setActivationErrorCallback({});
        addressListModel_->setActivationCallback({});
    }
    releaseTargetUsers(true);

    // Drop Lua GUI callback bindings before luaEngine_ (and its lua_State) is
    // destroyed with this window's members, so a stray Qt timer/widget callback
    // can't fire into a freed lua_State.
    ce::shutdownLuaGuiBindings();
}

// Build a ce::CheatTable from the current address list (shared by Save Table and
// Create Trainer). Mirrors the JSON field mapping the .CT saver expects.
void MainWindow::wireBrowserAnnotations(MemoryBrowser* browser) {
    // Seed the browser with the stored comments and have it push each edit back to
    // the MainWindow-owned store (which is serialized with the cheat table). Edits
    // merge one at a time, so two viewers never overwrite each other's comments.
    browser->setAnnotationStore(disasmAnnotations_,
        [this](const MemoryBrowser::AnnotationChange& change) {
            // A loaded table may spell the same address differently ("game+1234"),
            // so match an entry by its key or by where it resolves.
            ce::ExpressionParser parser(process_.get(), &luaResolver_);
            auto sameAddress = [&](const ce::DisassemblerComment& c) {
                if (c.address == change.expression) return true;
                if (!process_ || !change.address) return false;
                auto resolved = parser.parse(c.address);
                return resolved && *resolved == change.address;
            };
            auto it = std::find_if(disasmAnnotations_.begin(), disasmAnnotations_.end(), sameAddress);
            if (it == disasmAnnotations_.end() && !change.text.empty())
                it = disasmAnnotations_.insert(disasmAnnotations_.end(), {change.expression, {}, {}});
            if (it != disasmAnnotations_.end()) {
                (change.label ? it->label : it->comment) = change.text;
                if (it->comment.empty() && it->label.empty()) disasmAnnotations_.erase(it);
            }
            // Labels reach the other viewers through setUserSymbol; comments here.
            if (!change.label)
                for (const auto& viewer : memoryViewers_)
                    if (viewer) viewer->setComment(change.address, change.text);
            rebuildDebuggerComments();   // keep an open debugger's inline comments in sync
        });
    // The browser's step buttons open the full Debugger (which owns the debug
    // session and does real single-stepping).
    browser->setDebuggerLauncher([this](uintptr_t /*addr*/) { showDebugger(); });
    // In-Memory-Viewer stepping (CE parity): F7/F8/F9 in the viewer drive the debug
    // session hosted in the Debugger window. Each is a no-op unless a target is
    // paused; the onStep*/onContinue slots run on the debugger and re-emit stopped(),
    // which this window forwards to open viewers to advance the highlighted line.
    browser->setStepControls(
        [this]() { if (debuggerWindow_ && debuggerWindow_->debugStopped())
                       QMetaObject::invokeMethod(debuggerWindow_, "onStepInto"); },
        [this]() { if (debuggerWindow_ && debuggerWindow_->debugStopped())
                       QMetaObject::invokeMethod(debuggerWindow_, "onStepOver"); },
        [this]() { if (debuggerWindow_ && debuggerWindow_->debugStopped())
                       QMetaObject::invokeMethod(debuggerWindow_, "onContinue"); });
    browser->setStepOut([this]() {
        if (debuggerWindow_ && debuggerWindow_->debugStopped())
            QMetaObject::invokeMethod(debuggerWindow_, "onStepOut");
    });
    // Run to cursor (F4): run to the viewer's own selected line, not the Debugger's.
    browser->setRunToCursor([this](uintptr_t addr) {
        if (addr && debuggerWindow_ && debuggerWindow_->debugStopped())
            debuggerWindow_->runToAddress(addr);
    });
    // "Auto Assemble > Create code/AOB injection here" opens a script editor
    // pre-filled with the generated template.
    browser->setAutoAssembleOpener([this](const QString& script, uintptr_t address, size_t size) {
        auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
        trackTargetWindow(editor);
        editor->setAttribute(Qt::WA_DeleteOnClose);
        editor->setAddToTable([this](const QString& d, const QString& s) {
            addressListModel_->addScriptEntry(d, s);
        });
        editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
        editor->setScript(script.toStdString());
        editor->setInjectionAddress(address, size);
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
    // File > New window: open through openMemoryView so the new viewer is tracked
    // (and frozen on target exit), not left holding a stale ProcessHandle.
    browser->setNewWindowOpener([this](uintptr_t addr) { openMemoryView(addr); });
}

void MainWindow::editScriptEntry(int row) {
    const auto& entries = addressListModel_->entries();
    if (row < 0 || row >= (int)entries.size() || entries[row].autoAsmScript.isEmpty())
        return;
    int id = entries[row].id;
    QString desc = entries[row].description;
    QString script = entries[row].autoAsmScript;

    auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
    trackTargetWindow(editor);
    editor->setAttribute(Qt::WA_DeleteOnClose);
    editor->setWindowTitle(tr("Auto Assembler: %1").arg(desc));
    editor->setDefaultDescription(desc);
    editor->setTableButtonText(tr("Save to Table"));
    editor->setScript(script.toStdString());
    // Save back to THIS entry (found by stable id, so it survives reordering)
    // instead of appending a duplicate row.
    editor->setAddToTable([this, id](const QString& d, const QString& s) {
        addressListModel_->updateScriptEntryById(id, d, s);
    });
    editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
    editor->show();
}

void MainWindow::onCreateTrainer() {
    auto path = QFileDialog::getSaveFileName(this, tr("Create Trainer (C source)"),
        "trainer.c", tr("C source (*.c);;All Files (*)"));
    if (path.isEmpty()) return;
    try {
        ce::CheatTable table = buildCheatTable();
        ce::TrainerGenerator gen;
        std::string src = gen.generateSource(table);
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(this, tr("Create Trainer"), tr("Could not write the trainer source file."));
            return;
        }
        f.write(src.data(), (qint64)src.size());
        statusBar()->showMessage(
            QString(tr("Trainer C source written to %1 (compile with gcc)")).arg(path), 6000);
    } catch (const std::exception& ex) {
        QMessageBox::critical(this, tr("Create Trainer"),
            QString(tr("Trainer generation failed:\n%1")).arg(ex.what()));
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

        bool ok = false;
        // Accept a comma decimal separator like every other value field, so a "0,5"
        // step in a comma-locale isn't silently dropped to the default (QString::
        // toDouble is C-locale only).
        double step = QString(entry.hotkeyStep).replace(',', '.').toDouble(&ok);
        if (!ok || step == 0.0)
            step = 1.0;

        // Register a hotkey system-wide (X11) so it fires while the game is
        // focused; if that fails (non-X11 / unmappable key), fall back to a
        // Qt::ApplicationShortcut that only works when cheatengine is focused.
        // Toggle and set-value act once per press; increase and decrease repeat
        // while the key is held, as in CE. The portal name comes from the
        // record id, not the row, so a desktop's binding stays with its record.
        auto addHotkey = [&](const QString& keys, const char* slot, bool repeats, std::function<void()> action) {
            QKeySequence sequence(keys);
            if (sequence.isEmpty())
                return;
            int id = nextId++;
            const QString name = QStringLiteral("ce_%1_%2").arg(entry.id).arg(QLatin1String(slot));
            const QString description = QStringLiteral("%1 (%2)").arg(entry.description, QLatin1String(slot));
            if (globalHotkeys_ && globalHotkeys_->registerHotkey(id, sequence, name, description)) {
                hotkeyActions_.insert(id, {std::move(action), repeats});
                return;
            }
            auto* shortcut = new QShortcut(sequence, this);
            shortcut->setContext(Qt::ApplicationShortcut);
            shortcut->setAutoRepeat(repeats);
            connect(shortcut, &QShortcut::activated, this, action);
            valueHotkeyShortcuts_.push_back(shortcut);
        };

        // Capture the entry's stable id, not its row: a reorder (Move Up/Down, drag) or
        // a delete shifts row indices, but these hotkeys are only rebuilt on insert/
        // remove/reset, so a row-based capture would fire on the wrong entry. Resolve the
        // current row from the id each time the key is pressed.
        const int id = entry.id;
        // Every hotkey of the record, with Cheat Engine's actions. The first of
        // each slot keeps the slot's portal name, so a desktop's binding stays.
        int extra = 0;
        QSet<QString> named;
        for (const auto& hotkey : addressListModel_->hotkeysOf(row)) {
            const int action = hotkey.action;
            if (entry.isGroup && action > 4) continue;   // a group header has no value
            static const char* const slotNames[] = {"toggle", "toggle", "toggle", "toggle", "toggle", "set", "increase", "decrease"};
            QString slot = QLatin1String(slotNames[action]);
            if (named.contains(slot)) slot = QStringLiteral("hotkey%1").arg(++extra);
            named.insert(slot);
            const QByteArray slotName = slot.toLatin1();
            const QString keys = QString::fromStdString(hotkey.keys);
            const QString value = QString::fromStdString(hotkey.value);
            switch (action) {
                case 0: case 1: case 2:   // toggle; 1 and 2 freeze allowing an increase / a decrease
                    addHotkey(keys, slotName.constData(), false, [this, id, action]() {
                        int r = addressListModel_->rowOfId(id);
                        if (r < 0) return;
                        if (action != 0 && !addressListModel_->entries()[r].active)
                            addressListModel_->setFreezeMode(r, action == 1 ? ce::FreezeMode::IncreaseOnly
                                                                            : ce::FreezeMode::DecreaseOnly);
                        addressListModel_->toggleActive(r);
                    });
                    break;
                case 3: case 4:           // activate, deactivate
                    addHotkey(keys, slotName.constData(), false, [this, id, on = action == 3]() {
                        int r = addressListModel_->rowOfId(id);
                        if (r >= 0 && addressListModel_->entries()[r].active != on) addressListModel_->setActive(id, on);
                    });
                    break;
                case 5:                   // set value
                    addHotkey(keys, slotName.constData(), false, [this, id, value]() {
                        int r = addressListModel_->rowOfId(id);
                        if (r >= 0) addressListModel_->setEntryValueTo(r, value);
                    });
                    break;
                default: {                // 6 increase, 7 decrease: repeat while held, as in CE
                    bool ok = false;
                    double amount = QString(value).replace(',', '.').toDouble(&ok);
                    if (!ok || amount == 0.0) amount = step;
                    const double delta = action == 6 ? amount : -amount;
                    addHotkey(keys, slotName.constData(), true, [this, id, delta]() {
                        int r = addressListModel_->rowOfId(id);
                        if (r < 0 || !addressListModel_->adjustEntryValue(r, delta)) QApplication::beep();
                    });
                    break;
                }
            }
        }
    }
}

void MainWindow::startCodeFinder(int row, bool writesOnly) {
    if (!process_) return;
    const auto& entries = addressListModel_->entries();
    if (row < 0 || row >= (int)entries.size()) return;
    const auto& entry = entries[row];
    if (entry.isGroup) return;
    // Size the watchpoint to the record's type (Byte -> 1, Qword -> 8, ...); scalarWidth
    // returns 0 for String/AoB, which falls back to the configured default.
    size_t size = ce::scalarWidth(entry.type);
    if (entry.type == ValueType::Pointer)
        size = entry.pointerWidth ? entry.pointerWidth : process_ ? process_->pointerWidth(entry.address) : 0;
    else if (entry.type == ValueType::ByteArray) size = entry.byteCount;
    startCodeFinderForAddress(entry.address, writesOnly, static_cast<int>(std::min<size_t>(size, 8)));
}

void MainWindow::stopCodeFindersForInjection() {
    // A target can have only one ptrace tracer. If a "find what accesses/writes"
    // monitor is running, it holds that trace, so an injection's attach fails
    // (surfacing as a mmap "Cannot allocate memory"). Stop the monitors, which
    // detach, freeing the target for the injection.
    releaseTraceHolders();
}

void MainWindow::releaseTraceHolders() {
    for (auto& f : codeFinders_)
        if (f) f->stop();
    for (auto& monitor : accessMonitors_)
        if (monitor) monitor->stop();
    for (auto& filter : codeFilters_)
        if (filter) filter->stop();
}

std::unique_ptr<Debugger> MainWindow::createDebuggerForCurrentProcess() {
    if (AutoAsmUiOperation::retiring(&autoAsm_)) return nullptr;
    if (!process_) return nullptr;
    if (process_->targetDescription().transport==ce::TargetTransport::Gdb) return nullptr;
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

void MainWindow::showInstructionAccesses(uintptr_t instructionAddr) {
    if (!process_) return;
    // Release any active monitor first: it holds the target thread ptrace-traced,
    // and the instruction-access monitor's SEIZE would then fail.
    releaseTraceHolders();
    // Cheat Engine's Changed Addresses: a live list until Stop, with the value
    // and hit count of every address the instruction touches.
    auto* window = new ChangedAddressesWindow(process_.get(), instructionAddr, this);
    trackTargetWindow(window);
    std::erase_if(accessMonitors_, [](const QPointer<ChangedAddressesWindow>& p) { return p.isNull(); });
    accessMonitors_.push_back(window);
    connect(window, &ChangedAddressesWindow::browseRequested, this, [this](quint64 address) {
        openMemoryView(static_cast<uintptr_t>(address));
    });
    connect(window, &ChangedAddressesWindow::dissectRequested, this, [this](QList<quint64> addresses) {
        if (!process_ || addresses.isEmpty()) return;
        auto* sd = new StructureDissector(process_.get(), static_cast<uintptr_t>(addresses.front()), this);
        sd->setAttribute(Qt::WA_DeleteOnClose);
        trackStructDissector(sd);
        std::vector<uintptr_t> others;
        for (qsizetype i = 1; i < addresses.size(); ++i) others.push_back(static_cast<uintptr_t>(addresses[i]));
        if (!others.empty()) sd->setCompareAddresses(others);
        sd->show();
    });
    connect(window, &ChangedAddressesWindow::addToAddressListRequested, this, [this](quint64 address, int type) {
        addressListModel_->addEntry(static_cast<uintptr_t>(address), static_cast<ce::ValueType>(type),
                                    tr("Accessed address"));
    });
    window->show();
    statusBar()->showMessage(QString(tr("Monitoring the instruction at 0x%1…")).arg(instructionAddr, 0, 16), 5000);
}

int MainWindow::runAutorunScripts() {
    // CE runs every .lua in its autorun/ folder at startup. Ours lives under the user's
    // config dir and is opt-in (only runs if the user creates it). These are the user's
    // own scripts (like a shell rc file), and they run in the same sandboxed engine as
    // any Lua, so shellExecute and file writes stay gated behind CECORE_LUA_ALLOW_UNSAFE.
    QDir d(QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/autorun");
    if (!d.exists()) return 0;
    const QStringList files = d.entryList(QStringList{"*.lua", "*.LUA"}, QDir::Files, QDir::Name);
    int ran = 0, failed = 0;
    for (const QString& f : files) {
        QFile file(d.filePath(f));
        if (!file.open(QIODevice::ReadOnly)) continue;
        const QString code = QString::fromUtf8(file.readAll());
        file.close();
        const auto err = luaEngine_.execute(code.toStdString());
        ++ran;
        if (!err.empty()) {
            ++failed;
            statusBar()->showMessage(QString(tr("autorun %1: %2")).arg(f, QString::fromStdString(err)), 8000);
        }
    }
    if (ran > 0 && failed == 0)
        statusBar()->showMessage(QString(tr("Ran %1 autorun script(s).")).arg(ran), 4000);
    return ran;
}

void MainWindow::startCodeFinderForAddress(uintptr_t addr, bool writesOnly, int watchSize) {
    if (!process_) return;

    // A previous "find what writes/accesses" monitor still holds the target thread
    // ptrace-traced. A new one's PTRACE_SEIZE of the same thread would then fail, so
    // the second attempt would silently find nothing. Stop finished finders first to
    // release the trace (and the debug register).
    releaseTraceHolders();

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
        auto r = QMessageBox::information(this, tr("Wine / Proton game"),
            tr("This is a Wine/Proton (Windows) game. Cheat Engine will watch the game's "
            "main thread for writes, which is where gameplay values (money, HP, …) are "
            "usually changed.\n\n"
            "If nothing shows up, the value may be written by a background thread; "
            "tell me and it can be widened. Start monitoring?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
        if (r != QMessageBox::Yes) return;
    }

    auto debugger = createDebuggerForCurrentProcess();
    if (!debugger) return;
    auto finder = std::make_unique<CodeFinder>();
    // Use the caller's type-derived watch size when valid (e.g. a Byte record watches 1
    // byte); otherwise fall back to the configured default.
    if (watchSize != 1 && watchSize != 2 && watchSize != 4 && watchSize != 8)
        watchSize = QSettings().value("codefinder/watchSize", "4").toInt();
    if (watchSize != 1 && watchSize != 2 && watchSize != 4 && watchSize != 8) watchSize = 4;
    if (!finder->start(*process_, *debugger, addr, writesOnly, watchSize, software, singleThread)) {
        QMessageBox::warning(this, tr("Code finder unavailable"), QString::fromStdString(ce::targetOperationError(*process_,
            software ? ce::TargetFeature::SoftwareWatchpoint : ce::TargetFeature::HardwareWatchpoint, finder->lastError())));
        return;
    }

    auto* finderPtr = finder.get();
    codeFinderDebuggers_.push_back(std::move(debugger));
    codeFinders_.push_back(std::move(finder));

    auto title = writesOnly ? tr("Find what writes") : tr("Find what accesses");
    auto* window = new CodeFinderWindow(finderPtr,
        QString("%1 0x%2").arg(title).arg(addr, 0, 16), process_.get(), this);
    trackTargetWindow(window);
    window->setAttribute(Qt::WA_DeleteOnClose);
    // Closing the window stops the monitor so it releases the traced thread / debug
    // register (otherwise a later find-what-writes could not seize it). `this`
    // context makes the connection auto-drop if the main window goes away first.
    connect(window, &QObject::destroyed, this, [finderPtr]() { finderPtr->stop(); });
    // CE: "Add to the code list" sends the found opcodes to Advanced Options
    // (the Code list), where they can be disassembled / NOP'd / restored.
    window->setAddToList([this](uintptr_t a, const QString& desc) {
        showAdvancedOptions();
        advancedOptions_->addCode(a, desc.isEmpty() ? QString(tr("code 0x%1")).arg(a, 0, 16) : desc);
    });
    // CE: "Show this address in the disassembler" jumps the Memory Viewer to the
    // writing/accessing instruction (the found row's recovered address).
    window->setShowInDisassembler([this](uintptr_t a) { openMemoryView(a); });
    window->setFindWhatCodeAccesses([this](uintptr_t a) { showInstructionAccesses(a); });
    window->show();
}

void MainWindow::onMemoryView() {
    if (!process_) {
        statusBar()->showMessage(tr("No process attached; open one first (Ctrl+O) to view memory."), 4000);
        return;
    }
    openMemoryView(0);
}

void MainWindow::showDebugger() {
    if (AutoAsmUiOperation::retiring(&autoAsm_)) return;
    if (!process_) { QMessageBox::warning(this, tr("No process"), tr("Open a process first.")); return; }
    // Reuse the existing window: it holds the ptrace attachment, so a second one
    // would fail to attach. Just raise it if it is already open.
    if (debuggerWindow_) {
        debuggerWindow_->show();
        debuggerWindow_->raise();
        debuggerWindow_->activateWindow();
        return;
    }
    releaseTraceHolders();   // the Debugger attaches as it opens
    auto* w = new ce::gui::DebuggerWindow(process_.get(), this);
    w->setAttribute(Qt::WA_DeleteOnClose);
    debuggerWindow_ = w;   // QPointer auto-nulls on close
    // Drive the current-instruction highlight in open Memory Viewers from the
    // debugger's stops, like CE. The first viewer follows execution (scrolls to the
    // current line); the rest just light the line up where it is already visible.
    connect(w, &ce::gui::DebuggerWindow::stopped, this, [this, w](uintptr_t rip) {
        bool first = true;
        const ce::CpuContext& ctx = w->currentStopContext();
        for (auto& mv : memoryViewers_)
            if (mv) { mv->showCurrentInstruction(rip, first, ctx); first = false; }
    });
    connect(w, &ce::gui::DebuggerWindow::resumed, this, [this]() {
        for (auto& mv : memoryViewers_) if (mv) mv->clearCurrentInstruction();
    });
    rebuildDebuggerComments();   // show the same inline comments as the Memory Viewer
    w->show();
}

void MainWindow::trackStructDissector(StructureDissector* sd) {
    // Fields go to the address list in hexadecimal when Dissect Data Config says so.
    sd->setAddToListCallback([this](uintptr_t a, ce::ValueType t, const QString& d) {
        const int id = addressListModel_->addEntry(a, t, d);
        if (StructureDissectorOptions::load().hexFields && (ce::isIntegerScalar(t) || t == ce::ValueType::Pointer))
            addressListModel_->setHexView(id, true);
    });
    std::erase_if(structDissectors_, [](const QPointer<StructureDissector>& p) { return p.isNull(); });
    structDissectors_.push_back(sd);
}

void MainWindow::openMonoDissector() {
    if (!process_) { QMessageBox::warning(this, tr("No process"), tr("Open a process first.")); return; }
    auto* w = new ce::gui::MonoDissectorWindow(process_.get(), this);
    trackTargetWindow(w);
    w->setAttribute(Qt::WA_DeleteOnClose);
    // Double-clicking a field asks for the object's base address, then adds
    // base+offset to the address list with the field's mapped type.
    connect(w, &ce::gui::MonoDissectorWindow::addFieldRequested, this,
            [this](quint32 offset, int valueType, const QString& label, bool isStatic, const QString& chosen) {
        bool ok = false;
        // A static field's offset is into the class's static data, not an object.
        // The default is the object chosen from Find instances.
        QString base = QInputDialog::getText(this, tr("Add Mono field"),
            QString(tr("%1 for '%2' (field at +0x%3):"))
                .arg(isStatic ? tr("Static data address of the class") : tr("Object base address"))
                .arg(label).arg(offset, 0, 16),
            QLineEdit::Normal, chosen, &ok);
        if (!ok || base.trimmed().isEmpty()) return;
        QString expr = QString("%1+0x%2").arg(base.trimmed()).arg(offset, 0, 16);
        // Resolve now for the initial address; keep the expression so it
        // re-evaluates each refresh (the base may be a pointer/symbol).
        ce::ExpressionParser parser(process_.get(), &luaResolver_);
        auto addr = parser.parse(expr.toStdString());
        addressListModel_->addEntry(addr.value_or(0),
            static_cast<ce::ValueType>(valueType), label, expr);
    });
    connect(w, &ce::gui::MonoDissectorWindow::instanceActivated, this,
            [this](quint64 address) { openMemoryView(static_cast<uintptr_t>(address)); });
    w->show();
}

void MainWindow::scheduleAddressListRefresh() {
    if (addressListRefreshQueued_) return;
    addressListRefreshQueued_ = true;
    QTimer::singleShot(0, this, [this] {
        addressListRefreshQueued_ = false;
        reapplyGroupCollapse();
        rebuildValueHotkeys();
    });
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

void MainWindow::rebuildDebuggerComments() {
    if (!debuggerWindow_ || !process_) return;
    // Resolve each annotation's symbolic address ("libgame.so+0x1234") to a number so the
    // debugger can show the same inline comments the Memory Viewer does.
    std::map<uintptr_t, std::string> m;
    ce::ExpressionParser parser(process_.get(), &luaResolver_);
    for (const auto& c : disasmAnnotations_) {
        if (c.comment.empty()) continue;
        if (auto a = parser.parse(c.address); a && *a) m[*a] = c.comment;
    }
    debuggerWindow_->setComments(std::move(m));
}

QWidget* MainWindow::openPanelByName(const QString& name) {
    auto tryIn = [this, &name](QWidget* host) -> QWidget* {
        // The --panel argument is an English menu name; with a translation
        // catalogue installed the actions carry the translated text.
        QStringList candidates{name};
        const QString translated = QCoreApplication::translate("ce::gui::MainWindow", name.toUtf8().constData());
        if (!translated.isEmpty() && translated != name) candidates << translated;
        QSet<QWidget*> before;
        for (auto* w : QApplication::topLevelWidgets()) before.insert(w);
        bool matched = false;
        for (QAction* a : host->findChildren<QAction*>()) {
            if (a->menu() || a->isSeparator()) continue;
            QString t = a->text(); t.remove('&');
            bool hit = false;
            for (const QString& candidate : candidates)
                if (t.contains(candidate, Qt::CaseInsensitive)) { hit = true; break; }
            if (hit) { a->trigger(); matched = true; break; }
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

AgentPanel* MainWindow::showAgentPanel() {
    if (!agentPanel_) {
        agentDock_ = new QDockWidget(tr("AI Assistant"), this);
        agentDock_->setObjectName("aiAssistantDock");
        agentPanel_ = new AgentPanel(agentDock_);
        agentDock_->setWidget(agentPanel_);
        agentDock_->setMinimumWidth(340);
        addDockWidget(Qt::RightDockWidgetArea, agentDock_);
        agentPanel_->setTableSink([this](const std::vector<ce::CheatEntry>& entries) { addTableEntries(entries); });
        connect(agentPanel_, &AgentPanel::settingsRequested, this, [this]() { openSettingsDialog("AI Assistant"); });
        syncAgentTarget();
    }
    agentDock_->show();
    agentDock_->raise();
    return agentPanel_;
}

void MainWindow::addTableEntries(const std::vector<ce::CheatEntry>& entries) {
    ce::CheatTable table;
    table.entries = entries;
    auto list = addressListModel_->toJson();
    for (auto value : cheatEntriesToJson(table)) {
        auto obj = value.toObject();
        obj["active"] = false;   // the user turns them on
        obj.remove("id");        // fresh ids, as when pasting
        list.append(obj);
    }
    addressListModel_->fromJson(list, true);
}

QDialog* MainWindow::openSettingsDialog(const QString& page) {
    // One dialog: a second one opened earlier would write back, on OK, the
    // values it read when it opened, reverting changes made meanwhile.
    auto selectPage = [](QDialog* dialog, const QString& name) {
        if (name.isEmpty()) return;
        if (auto* nav = dialog->findChild<QListWidget*>("settingsNav")) {
            auto matches = nav->findItems(name, Qt::MatchContains);
            // Nav labels are translated; page names stay English identifiers, so
            // fall back to the translated label when the English one does not match.
            if (matches.isEmpty())
                matches = nav->findItems(QCoreApplication::translate("ce::gui::SettingsDialog",
                    name.toUtf8().constData()), Qt::MatchContains);
            if (!matches.isEmpty()) nav->setCurrentItem(matches.first());
        }
    };
    if (settingsDialog_) {
        selectPage(settingsDialog_, page);
        settingsDialog_->show();
        settingsDialog_->raise();
        settingsDialog_->activateWindow();
        return settingsDialog_;
    }
    auto* dlg = new SettingsDialog(this);
    settingsDialog_ = dlg;
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    connect(dlg, &SettingsDialog::restartRequested, this, &MainWindow::restartAfterLanguageChange);
    connect(dlg, &SettingsDialog::settingsApplied, this, [this]() {
        if (agentPanel_) agentPanel_->reloadSettings();
        // A scan blocks user input, so Apply can't land mid-scan; the scanner is idle.
        if (int threads = QSettings().value("scan/threads", 0).toInt(); threads != scannerThreads_) {
            scannerThreads_ = threads;
            scanner_ = std::make_unique<MemoryScanner>(threads);
        }
        if (valueRefreshTimer_)
            valueRefreshTimer_->start(kValueRefreshMs);
        addressDisplay() = loadAddressDisplay();   // repainted below
        const QFont font = settingsMonospaceFont();
        resultsView_->setFont(font);
        addressListView_->setFont(font);
        addressListView_->setColumnWidth(2, QFontMetrics(font).horizontalAdvance("GameAssembly.so+0x123456") + 18);
        resultsView_->viewport()->update();
        addressListView_->viewport()->update();
    });
    // Optionally jump straight to a named category (used by the UI screenshot
    // harness, and handy for deep-linking to a settings page).
    selectPage(dlg, page);
    dlg->show();
    dlg->raise();
    return dlg;
}

MemoryBrowser* MainWindow::openMemoryView(uintptr_t addr) {
    if (!process_) return nullptr;
    auto* browser = new MemoryBrowser(process_.get(), this);
    browser->setAttribute(Qt::WA_DeleteOnClose);
    wireBrowserAnnotations(browser);

    // Breakpoints are armed by the debugger window, which holds the ptrace
    // session: open it (attaching) on first use, then plant through it.
    browser->setBreakpointSetter([this](uintptr_t addr, bool hardware) {
        if (!debuggerWindow_) showDebugger();
        if (!debuggerWindow_ || !debuggerWindow_->debugAttached()) {
            statusBar()->showMessage(tr("The debugger could not attach; no breakpoint was set."), 5000);
            return;
        }
        if (!debuggerWindow_->debugStopped()) {
            statusBar()->showMessage(tr("Pause the target in the debugger to set a breakpoint."), 5000);
            return;
        }
        debuggerWindow_->addBreakpointAt(addr);
        if (hardware)
            statusBar()->showMessage(tr("Execute breakpoints are software breakpoints in this debugger."), 5000);
    });
    browser->setBreakpointRemover([this](uintptr_t addr) {
        if (debuggerWindow_ && !debuggerWindow_->removeBreakpointAt(addr))
            statusBar()->showMessage(tr("Could not remove the breakpoint; see the debugger window."), 5000);
    });
    browser->setBreakpointQuery([this]() {
        return debuggerWindow_ ? debuggerWindow_->breakpointAddresses() : std::set<uintptr_t>{};
    });
    browser->setCodeFinderLauncher([this](uintptr_t addr, bool writesOnly) {
        startCodeFinderForAddress(addr, writesOnly);
    });
    browser->setInstructionAccessLauncher([this](uintptr_t addr) {
        showInstructionAccesses(addr);
    });
    browser->setChangeRegistersLauncher([this](uintptr_t addr) {
        showDebugger();   // the Debugger owns the session the breakpoint lives in
        if (debuggerWindow_) debuggerWindow_->changeRegistersAt(addr);
    });
    browser->setAddToList([this](uintptr_t addr, ce::ValueType type) {
        addressListModel_->addEntry(addr, type);
        statusBar()->showMessage(QString(tr("Added 0x%1 to the cheat table")).arg(addr, 0, 16), 3000);
    });
    // Global user-defined symbols: a label set in one Memory Viewer must resolve
    // everywhere (records, Lua, other views). Seed this view with the app-wide labels,
    // and mirror any new label back into the shared resolver the address list uses.
    browser->addUserSymbols(luaResolver_.userSymbols());
    browser->setUserSymbolCallback([this](uintptr_t addr, const std::string& name) {
        if (name.empty()) luaResolver_.removeUserSymbol(addr);
        else              luaResolver_.addUserSymbol(addr, name);
        // Re-point any record addressed by that label at the new resolution immediately.
        if (process_) addressListModel_->updateValues(process_.get());
        // Fan the label out to every other open Memory Viewer so they display it too.
        for (const auto& mv : memoryViewers_)
            if (mv) mv->setUserSymbol(addr, name);
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
        browser->showCurrentInstruction(debuggerWindow_->currentStopRip(), false,
                                        debuggerWindow_->currentStopContext());
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
    view->addAction(tr("Memory Regions"), this, [this, openAt]() {
        if (!process_) return;
        auto* w = new MemoryRegionsWindow(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &MemoryRegionsWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction(tr("Heap list"), this, [this, openAt]() {
        if (!process_) return;
        auto* w = new HeapRegionsWindow(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &HeapRegionsWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction(tr("Module list"), this, [this, openAt]() {
        if (!process_) return;
        auto* w = new ModuleListWindow(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &ModuleListWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction(tr("Referenced strings / functions"), this, [this, openAt]() {
        if (!process_) return;
        auto* w = new CodeReferencesWindow(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose);
        connect(w, &CodeReferencesWindow::navigateTo, this, [openAt](uintptr_t a){ openAt(a); });
        w->show();
    });
    view->addAction(tr("Thread list"), this, [this]() {
        if (!process_) return;
        auto* w = new ThreadListWindow(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });
    view->addAction(tr("Stacktrace"), this, [this]() {
        if (!process_) return;
        auto* w = new StackViewWindow(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });
    view->addAction(tr("Graphical memory view"), this, [this]() {
        if (!process_) return;
        auto* w = new ce::gui::GraphicalMemoryView(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });

    // ── Debug ──
    QMenu* dbg = b->debugMenu();
    if (dbg) {
        dbg->addSeparator();
        dbg->addAction(tr("Registers"), this, [this]() {
            if (!process_) return;
            auto* w = new RegisterEditorWindow(process_.get(), this);
            trackTargetWindow(w);
            w->setAttribute(Qt::WA_DeleteOnClose); w->show();
        });
        // The debugger window holds the breakpoints that are actually armed
        // (set there, or from the Memory Viewer); its list is the real one.
        dbg->addAction(tr("Breakpoint list"), this, [this]() { showDebugger(); });
        dbg->addAction(tr("Full debugger"), this, [this]() { showDebugger(); });
        dbg->addAction(tr("Break and trace"), this, [this]() {
            if (!process_) return;
            releaseTraceHolders();   // the trace attaches when it starts
            auto* tw = new TracerWindow(process_.get(),
                [this]() { return createDebuggerForCurrentProcess(); }, this);
            trackTargetWindow(tw);
            tw->setAttribute(Qt::WA_DeleteOnClose); tw->show();
        });
        dbg->addAction(tr("Branch mapper (LBR)"), this, [this]() {
            if (!process_) return;
            auto* bm = new BranchMapper(process_.get(), this);
            trackTargetWindow(bm);
            bm->setAttribute(Qt::WA_DeleteOnClose); bm->show();
        });
    }

    // Analysis tools (shared with the main window Tools menu). The viewer already
    // has address-aware Auto Assemble and Dissect entries, so drop the generic copies.
    tools->addSeparator();
    const auto own = tools->actions();
    addAnalysisToolsMenu(tools);
    for (QAction* action : tools->actions())
        if (!own.contains(action) &&
            (action->text() == tr("Auto Assemble...") || action->text() == tr("Dissect data/structures...")))
            tools->removeAction(action);
    (void)needProc;
}

void MainWindow::addAnalysisToolsMenu(QMenu* tools) {
    tools->addAction(tr("Auto Assemble..."), this, [this]() {
        auto* editor = new ScriptEditor(process_.get(), &autoAsm_, this);
        trackTargetWindow(editor);
        editor->setAttribute(Qt::WA_DeleteOnClose);
        editor->setAddToTable([this](const QString& d, const QString& s) { addressListModel_->addScriptEntry(d, s); });
        editor->setBeforeExecute([this]() { stopCodeFindersForInjection(); });
        editor->show();
    });
    tools->addAction(tr("Pointer scan..."), this, [this]() {
        if (!process_) return;
        auto* dlg = new PointerScanDialog(process_.get(), this);
        trackTargetWindow(dlg);
        connect(dlg, &PointerScanDialog::addressSelected, this,
                [this](uintptr_t a, const QString& expr) {
                    // Add the pointer path AS the address expression so it re-resolves live.
                    addressListModel_->addEntry(a, ce::ValueType::Int32, expr, expr);
                });
        dlg->setAttribute(Qt::WA_DeleteOnClose); dlg->show();
    });
    tools->addAction(tr("Emulator guest scan..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("No process"), tr("Open a process first.")); return; }
        auto* dlg = new GuestScanDialog(process_.get(), this);
        trackTargetWindow(dlg);
        connect(dlg, &GuestScanDialog::addressSelected, this,
                [this](uintptr_t a, ce::ValueType t, bool be, const QString& d) {
                    addressListModel_->addEntry(a, t, d);
                    if (be) addressListModel_->setEntryBigEndian(addressListModel_->rowCount() - 1, true);
                });
        dlg->setAttribute(Qt::WA_DeleteOnClose); dlg->show();
    });
    tools->addAction(tr("Dissect data/structures..."), this, [this]() {
        if (!process_) return;
        auto* sd = new StructureDissector(process_.get(), 0, this);
        sd->setAttribute(Qt::WA_DeleteOnClose);
        sd->setAddToListCallback([this](uintptr_t a, ce::ValueType t, const QString& d) { addressListModel_->addEntry(a, t, d); });
        trackStructDissector(sd);
        sd->show();
    });
    tools->addAction(tr("Find static addresses..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("No process"), tr("Open a process first.")); return; }
        auto* w = new FindStaticsWindow(process_.get(), this);
        trackTargetWindow(w);
        w->setAttribute(Qt::WA_DeleteOnClose); w->show();
    });
    tools->addAction(tr("Mono dissector..."), this, &MainWindow::openMonoDissector);
    tools->addAction(tr("Lua Engine..."), this, [this]() {
        luaEngine_.setProcess(process_.get());
        luaEngine_.setAddressList(addressListModel_);   // so getMemoryRecord etc. work
        if (process_) { luaResolver_.loadProcess(*process_); luaEngine_.setResolver(&luaResolver_); }
        // One console: the engine has a single output callback, which each
        // new console took over, so print() in an older one went to a closed one.
        if (luaConsole_) { luaConsole_->show(); luaConsole_->raise(); luaConsole_->activateWindow(); return; }
        auto* console = new LuaConsole(&luaEngine_, this);
        luaConsole_ = console;
        console->setAttribute(Qt::WA_DeleteOnClose); console->show();
    });
    tools->addAction(tr("Structure Compare..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("No process"), tr("Open a process first.")); return; }
        auto* w = new StructureCompareWindow(process_.get(), this);
        trackTargetWindow(w);
        w->show();
    });
    tools->addAction(tr("Code Filter..."), this, [this]() {
        if (!process_) { QMessageBox::warning(this, tr("No process"), tr("Open a process first.")); return; }
        auto* w = new CodeFilterWindow(process_.get(), this);
        trackTargetWindow(w);
        std::erase_if(codeFilters_, [](const QPointer<CodeFilterWindow>& p) { return p.isNull(); });
        codeFilters_.push_back(w);
        w->setBeforeStart([this]() { releaseTraceHolders(); });
        connect(w, &CodeFilterWindow::showInDisassembler, this, [this](quint64 address) {
            openMemoryView(static_cast<uintptr_t>(address));
        });
        w->show();
    });
    tools->addAction(tr("PE Info..."), this, [this]() {
        auto* w = new PEInfoWindow(process_.get(), this);
        if (process_) trackTargetWindow(w);
        w->show();
    });
    tools->addAction(tr("ELF Inspector..."), this, [this]() {
        QString initial;
        // Only a local target's module path names a file readelf can open here
        // (modules() already maps a sandboxed target's paths through /proc).
        if (process_ && process_->targetDescription().transport == ce::TargetTransport::Local) {
            auto mods = process_->modules();
            if (!mods.empty()) initial = QString::fromStdString(mods.front().path);
        }
        auto* dlg = new ElfInspector(initial, this);
        dlg->setAttribute(Qt::WA_DeleteOnClose); dlg->show();
    });
}

} // namespace ce::gui
