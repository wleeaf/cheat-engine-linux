#include "gui/debuggerwindow.hpp"
#include "core/local_target.hpp"
#include <QSettings>
#include <QDialogButtonBox>
#include <QFormLayout>
#include "core/target_capabilities.hpp"
#include "arch/cpu_flags.hpp"
#include "core/types.hpp"   // moduleOffsetString
#include "core/cpu_registers.hpp"
#include "gui/theme.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/patch.hpp"

#include <QWidget>
#include <QMenu>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QToolButton>
#include <QLabel>
#include <QPlainTextEdit>
#include <QTextEdit>   // QTextEdit::ExtraSelection for the current-line highlight
#include <QTextBlock>
#include <QShortcut>
#include <QTableWidget>
#include <QHeaderView>
#include <QComboBox>
#include <QLineEdit>
#include <QInputDialog>
#include <QListWidget>
#include <QGroupBox>
#include <QSplitter>
#include <QFont>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QTextCursor>
#include <QSignalBlocker>
#include <bit>
#include <csignal>
#include <algorithm>

namespace ce::gui {

static QString hex(uintptr_t v) { return QStringLiteral("0x%1").arg(v, 0, 16); }

DebuggerWindow::DebuggerWindow(ce::ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc), session_(std::make_unique<ce::DebugSession>()) {
    setWindowTitle("Debugger");
    resize(1080, 720);

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);

    // ── control row ──
    auto* controls = new QHBoxLayout();
    contBtn_   = new QPushButton("Continue");     contBtn_->setShortcut(Qt::Key_F9);
    intoBtn_   = new QPushButton("Step Into");    intoBtn_->setShortcut(Qt::Key_F7);
    overBtn_   = new QPushButton("Step Over");    overBtn_->setShortcut(Qt::Key_F8);
    outBtn_    = new QPushButton("Step Out");
    rtcBtn_    = new QPushButton("Run to Cursor"); rtcBtn_->setShortcut(Qt::Key_F4);
    detachBtn_ = new QPushButton("Detach");
    for (auto* b : {contBtn_, intoBtn_, overBtn_, outBtn_, rtcBtn_, detachBtn_})
        controls->addWidget(b);

    // Break on exceptions (CE's exception breakpoints): a checkable menu of the
    // common CPU-trap signals. Toggling one arms/disarms addExceptionBreakpoint.
    auto* excBtn = new QToolButton();
    excBtn->setText("Break on exceptions");
    excBtn->setPopupMode(QToolButton::InstantPopup);
    auto* excMenu = new QMenu(excBtn);
    struct SigEntry { const char* name; int sig; };
    static const SigEntry kSigs[] = {
        {"SIGSEGV (segfault)", SIGSEGV}, {"SIGILL (illegal instruction)", SIGILL},
        {"SIGFPE (FP / divide-by-zero)", SIGFPE}, {"SIGBUS (bus error)", SIGBUS},
        {"SIGABRT (abort)", SIGABRT}, {"SIGTRAP", SIGTRAP},
    };
    for (const auto& s : kSigs) {
        auto* a = excMenu->addAction(s.name);
        a->setCheckable(true);
        int sig = s.sig;
        connect(a, &QAction::toggled, this, [this, sig](bool on) {
            if (!session_->isAttached()) return;
            if (on) session_->addExceptionBreakpoint(sig);
            else    session_->removeExceptionBreakpoint(sig);
        });
    }
    excBtn->setMenu(excMenu);
    controls->addWidget(excBtn);

    controls->addStretch();
    root->addLayout(controls);

    statusLabel_ = new QLabel("Not attached");
    root->addWidget(statusLabel_);

    const QFont mono = monospaceFont();

    // ── main split: [disasm / stack] | [registers / breakpoints] ──
    auto* split = new QSplitter(Qt::Horizontal);

    auto* leftSplit = new QSplitter(Qt::Vertical);
    disasmView_ = new QPlainTextEdit();
    disasmView_->setReadOnly(true);
    disasmView_->setFont(mono);
    disasmView_->setLineWrapMode(QPlainTextEdit::NoWrap);
    disasmView_->setPlaceholderText("The disassembly around the stopped thread's instruction pointer appears here.");
    disasmView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(disasmView_, &QPlainTextEdit::customContextMenuRequested,
            this, &DebuggerWindow::onDisasmContextMenu);
    leftSplit->addWidget(disasmView_);
    stackView_ = new QPlainTextEdit();
    stackView_->setReadOnly(true);
    stackView_->setFont(mono);
    stackView_->setLineWrapMode(QPlainTextEdit::NoWrap);
    stackView_->setPlaceholderText("Stack of the stopped thread");
    leftSplit->addWidget(stackView_);

    auto* memWidget = new QWidget();
    auto* memLayout = new QVBoxLayout(memWidget);
    memLayout->setContentsMargins(0, 0, 0, 0);
    memAddrInput_ = new QLineEdit();
    memAddrInput_->setPlaceholderText("memory address (hex), then Enter");
    memLayout->addWidget(memAddrInput_);
    memView_ = new QTextEdit();
    memView_->setReadOnly(true);
    memView_->setFont(mono);
    memView_->setLineWrapMode(QTextEdit::NoWrap);
    // A read-only QTextEdit does not paint its placeholder, so start with a dim hint
    // that the first dump replaces.
    memView_->setHtml(QString("<span style=\"color:%1\">Type an address above and press Enter "
                              "to dump memory here.</span>").arg(ce::gui::editorPalette().dim.name()));
    memLayout->addWidget(memView_);
    leftSplit->addWidget(memWidget);

    leftSplit->setStretchFactor(0, 3);
    leftSplit->setStretchFactor(1, 1);
    leftSplit->setStretchFactor(2, 1);
    split->addWidget(leftSplit);

    auto* right = new QWidget();
    auto* rl = new QVBoxLayout(right);
    auto* threadRow = new QHBoxLayout();
    threadRow->addWidget(new QLabel("Thread:"));
    threadCombo_ = new QComboBox();
    threadRow->addWidget(threadCombo_, 1);
    rl->addLayout(threadRow);
    regTable_ = new QTableWidget(0, 1);
    regTable_->setObjectName("debuggerRegisters");
    regTable_->setProperty("monospace", true);   // font from the theme sheet
    regTable_->horizontalHeader()->setVisible(false);
    regTable_->horizontalHeader()->setStretchLastSection(true);
    regTable_->verticalHeader()->setVisible(true);   // register names
    regTable_->verticalHeader()->setDefaultSectionSize(QFontMetrics(mono).height() + 8);
    regTable_->setShowGrid(false);
    regTable_->setAlternatingRowColors(true);
    regTable_->setToolTip("Double-click a value to edit the register while the thread is stopped");
    rl->addWidget(regTable_, 3);

    // Decoded CPU flags under the register table (RFLAGS shows only the raw hex).
    flagsLabel_ = new QLabel(QStringLiteral("Flags:"));
    flagsLabel_->setFont(mono);
    flagsLabel_->setToolTip("Status flags of the currently stopped thread");
    rl->addWidget(flagsLabel_);

    auto* bpGroup = new QGroupBox("Breakpoints");
    auto* bl = new QVBoxLayout(bpGroup);
    auto* addRow = new QHBoxLayout();
    bpInput_ = new QLineEdit();
    bpInput_->setPlaceholderText("address (hex), then Add");
    auto* addBtn = new QPushButton("Add");
    auto* dataBpBtn = new QPushButton("Data BP...");
    dataBpBtn->setToolTip("Hardware watchpoint: break when an address is written or accessed");
    addRow->addWidget(bpInput_);
    addRow->addWidget(addBtn);
    addRow->addWidget(dataBpBtn);
    bl->addLayout(addRow);
    bpList_ = new QListWidget();
    bpList_->setToolTip("Check to enable/disable · double-click to set/edit its condition");
    connect(bpList_, &QListWidget::itemDoubleClicked, this,
            [this](QListWidgetItem*) { editBreakpointCondition(); });
    // Checkbox toggles enable/disable: unchecking removes the planted breakpoint
    // but keeps the list entry so it can be re-armed.
    connect(bpList_, &QListWidget::itemChanged, this, [this](QListWidgetItem* it) {
        int row = bpList_->row(it);
        if (row < 0 || row >= static_cast<int>(bps_.size())) return;
        bool wantEnabled = (it->checkState() == Qt::Checked);
        if (wantEnabled == bps_[row].enabled) return;   // programmatic text change, not a toggle
        if (!session_->isAttached() || !paused()) {
            QSignalBlocker block(bpList_);
            it->setCheckState(bps_[row].enabled ? Qt::Checked : Qt::Unchecked);
            statusLabel_->setText("Stop the target to enable/disable breakpoints");
            return;
        }
        if (wantEnabled) {
            int id = bps_[row].hardware
                ? session_->setHardwareBreakpoint(bps_[row].addr, bps_[row].hwType, bps_[row].hwSize)
                : session_->setSoftwareBreakpoint(bps_[row].addr);
            if (id <= 0) {
                QSignalBlocker block(bpList_);
                it->setCheckState(Qt::Unchecked);
                statusLabel_->setText("Could not enable breakpoint");
                return;
            }
            bps_[row].id = id;
            bps_[row].enabled = true;
        } else {
            bool removed=bps_[row].hardware ? session_->removeHardwareBreakpoint(bps_[row].id) :
                                             session_->removeSoftwareBreakpoint(bps_[row].id);
            if (!removed) {
                QSignalBlocker block(bpList_);
                it->setCheckState(Qt::Checked);
                statusLabel_->setText("Breakpoint cleanup pending: "+QString::fromStdString(session_->lastError().message()));
                return;
            }
            bps_[row].enabled = false;
        }
        if (paused()) updateDisassembly(session_->getStopContext());
    });
    setEmptyHint(bpList_, "No breakpoints yet.\nAdd one above, or press F5\non a line of code.");
    bl->addWidget(bpList_);
    auto* rmRow = new QHBoxLayout();
    rmRow->addStretch();
    rmBtn_ = new QPushButton("Remove");
    rmBtn_->setToolTip("Remove the selected breakpoint");
    rmBtn_->setEnabled(false);
    connect(bpList_, &QListWidget::currentRowChanged, rmBtn_, [this](int row) { rmBtn_->setEnabled(row >= 0 && !stepping_); });
    rmRow->addWidget(rmBtn_);
    bl->addLayout(rmRow);
    rl->addWidget(bpGroup, 2);
    split->addWidget(right);
    // The register panel needs about "RFLAGS  0x0000000000000000"; anything wider
    // only leaves its value column empty, so the disassembly gets the rest.
    right->setMaximumWidth(QFontMetrics(mono).horizontalAdvance(QString(36, QLatin1Char('0'))) + 80);
    split->setStretchFactor(0, 1);
    split->setStretchFactor(1, 0);
    root->addWidget(split, 1);

    setCentralWidget(central);

    connect(contBtn_,   &QPushButton::clicked, this, &DebuggerWindow::onContinue);
    connect(intoBtn_,   &QPushButton::clicked, this, &DebuggerWindow::onStepInto);
    connect(overBtn_,   &QPushButton::clicked, this, &DebuggerWindow::onStepOver);
    connect(outBtn_,    &QPushButton::clicked, this, &DebuggerWindow::onStepOut);
    connect(rtcBtn_,    &QPushButton::clicked, this, &DebuggerWindow::onRunToCursor);
    connect(detachBtn_, &QPushButton::clicked, this, &DebuggerWindow::onDetach);
    connect(addBtn,     &QPushButton::clicked, this, &DebuggerWindow::onAddBreakpoint);
    connect(dataBpBtn,  &QPushButton::clicked, this, &DebuggerWindow::onAddDataBreakpoint);
    connect(rmBtn_,     &QPushButton::clicked, this, &DebuggerWindow::onRemoveBreakpoint);
    connect(bpInput_,   &QLineEdit::returnPressed, this, &DebuggerWindow::onAddBreakpoint);
    // F5 toggles a breakpoint at the disassembly cursor (matching CE's debugger, which
    // already binds F7 step-into, F8 step-over, and F9 continue on the buttons above).
    auto* bpToggleSc = new QShortcut(QKeySequence(Qt::Key_F5), this);
    connect(bpToggleSc, &QShortcut::activated, this, &DebuggerWindow::toggleBreakpointAtCursor);
    connect(regTable_,  &QTableWidget::itemChanged, this, &DebuggerWindow::onRegisterEdited);
    connect(threadCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &DebuggerWindow::onThreadSelected);
    connect(memAddrInput_, &QLineEdit::returnPressed, this, &DebuggerWindow::onMemAddrEntered);

    // Debug events fire on the tracer thread; publish the event and marshal a
    // refresh onto the UI thread.
    session_->setEventCallback([this](const ce::DebugEvent& e) {
        lastEvtAddr_.store(e.address);
        lastEvtTid_.store(e.tid);
        int t = static_cast<int>(e.type);
        QMetaObject::invokeMethod(this, [this, t] { onDebugEvent(t); }, Qt::QueuedConnection);
    });

    if (proc_ && session_->attach(proc_->pid(), proc_)) {
        prevGp_.clear(); prevVectors_ = {}; shownGp_.clear(); shownVectors_ = {};   // fresh session: don't flag the first stop's registers
        refreshStopped();   // target is all-stopped right after attach
    } else {
        statusLabel_->setText(proc_ ? "Attach failed: " + QString::fromStdString(
            ce::targetOperationError(*proc_, ce::TargetFeature::Debugger, session_->lastError())) : "No process attached");
        setRunningUi(false, true);
    }
}

QString DebuggerWindow::statusTextForTest() const { return statusLabel_->text(); }

DebuggerWindow::~DebuggerWindow() {
    if (session_ && session_->isAttached())
        session_->detach();   // restores breakpoint bytes, resumes the target; ends a step
    if (stepThread_.joinable()) stepThread_.join();
}

void DebuggerWindow::setRunningUi(bool running, bool exited) {
    bool stopped = !running && !exited;
    for (auto* b : {contBtn_, intoBtn_, overBtn_, outBtn_, rtcBtn_})
        b->setEnabled(stopped);
    detachBtn_->setEnabled(!exited);
    threadCombo_->setEnabled(stopped && threadCombo_->count() > 0);
    bpInput_->setEnabled(stopped);
    regTable_->setEnabled(stopped);
    // Removal works while running, but not during a step (see removeBreakpointRow).
    rmBtn_->setEnabled(!stepping_ && bpList_->currentRow() >= 0);
    if (!stopped) emit resumed();   // running or exited: drop the current-line marker
}

void DebuggerWindow::onContinue() {
    if (!session_->isAttached() || stepping_) return;
    statusLabel_->setText("Running...");
    setRunningUi(true);
    // Continue can leave the target stopped without reporting a stop: show
    // it as stopped, with the reason, instead of "Running...".
    if (!session_->continueExecution() && session_->isAttached() && session_->isStopped()) {
        refreshStopped();
        statusLabel_->setText("Continue failed, still stopped: "+QString::fromStdString(session_->lastError().message()));
    }
}

void DebuggerWindow::onStepInto() { runStep(ce::StepMode::Into); }
void DebuggerWindow::onStepOver() { runStep(ce::StepMode::Over); }
void DebuggerWindow::onStepOut()  { runStep(ce::StepMode::Out); }

void DebuggerWindow::runStep(ce::StepMode mode) {
    if (!session_->isAttached() || !paused()) return;
    if (stepThread_.joinable()) stepThread_.join();   // a finished step not yet collected
    stepping_ = true;
    setRunningUi(true);
    statusLabel_->setText("Stepping... (Detach ends a step that does not return)");
    stepThread_ = std::thread([this, mode] {
        try { session_->step(mode); } catch (...) {}   // a detach can abandon the command
        QMetaObject::invokeMethod(this, [this] { finishStep(); }, Qt::QueuedConnection);
    });
}

void DebuggerWindow::finishStep() {
    if (stepThread_.joinable()) stepThread_.join();
    stepping_ = false;
    rmBtn_->setEnabled(bpList_->currentRow() >= 0);
    if (session_->isAttached() && session_->isStopped()) refreshStopped();
}

void DebuggerWindow::onRunToCursor() {
    runToAddress(currentCursorAddress());
}

void DebuggerWindow::runToAddress(uintptr_t addr) {
    if (!session_->isAttached() || !paused()) return;
    if (!addr) return;
    // One run-to-cursor at a time: a previous one that stopped short is dropped.
    if (!clearRunToCursor()) {
        statusLabel_->setText("Run-to-cursor cleanup pending: "+QString::fromStdString(session_->lastError().message()));
        return;
    }
    // If an armed user breakpoint already sits there, just continue to it.
    bool existing = false;
    for (auto& b : bps_) if (!b.hardware && b.enabled && b.addr == addr) existing = true;
    if (!existing) {
        pendingRtcId_ = session_->setSoftwareBreakpoint(addr);
        pendingRtcAddr_ = addr;
    }
    onContinue();
}

void DebuggerWindow::onDetach() {
    if (session_->isAttached()) session_->detach();
    statusLabel_->setText("Detached");
    setRunningUi(false, true);
}

void DebuggerWindow::onAddBreakpoint() {
    QString text = bpInput_->text().trimmed();
    if (text.startsWith("0x") || text.startsWith("0X")) text = text.mid(2);
    bool ok = false;
    uintptr_t addr = text.toULongLong(&ok, 16);
    if (!ok || !addr) { statusLabel_->setText("Invalid breakpoint address"); return; }
    addBreakpointAt(addr);
    bpInput_->clear();
}

void DebuggerWindow::addBreakpointAt(uintptr_t addr, const QString& condition) {
    if (!session_->isAttached() || !paused()) {
        statusLabel_->setText("Stop the target before setting a breakpoint");
        return;
    }
    for (size_t i = 0; i < bps_.size(); ++i) if (bps_[i].addr == addr) {  // already set — update condition
        bps_[i].condition = condition.toStdString();
        refreshBpRow(static_cast<int>(i));
        return;
    }
    // ARM64 replaces a full instruction, while x86 replaces a single byte.
    std::vector<uint8_t> original(session_->getStopContext().architecture == ce::CpuArchitecture::Arm64 ? 4 : 1);
    auto read = proc_ ? proc_->read(addr, original.data(), original.size()) : ce::Result<size_t>{std::unexpected(std::make_error_code(std::errc::bad_address))};
    if (!read || *read != original.size()) original.clear();
    int id = session_->setSoftwareBreakpoint(addr);
    if (id <= 0) { statusLabel_->setText("Failed to set breakpoint at " + hex(addr)); return; }
    Bp bp; bp.id = id; bp.addr = addr; bp.condition = condition.toStdString();
    bp.original = std::move(original);
    bps_.push_back(bp);
    bpList_->addItem(new QListWidgetItem());
    refreshBpRow(static_cast<int>(bps_.size()) - 1);
    if (paused()) updateDisassembly(session_->getStopContext());
}

QString DebuggerWindow::bpLabel(uintptr_t addr, const QString& condition) {
    return condition.isEmpty() ? hex(addr) : hex(addr) + "  if " + condition;
}

QString DebuggerWindow::bpRowText(const Bp& b) const {
    QString base = b.hardware ? bpDataLabel(b.addr, b.hwType, b.hwSize)
                              : bpLabel(b.addr, QString::fromStdString(b.condition));
    if (b.hitCount > 0) base += QStringLiteral("  (hits: %1)").arg(b.hitCount);
    return base;
}

// Rewrite one list row from bps_[index]. Signals are blocked so this programmatic
// update isn't seen as a user check-toggle by the itemChanged handler.
void DebuggerWindow::refreshBpRow(int index) {
    if (index < 0 || index >= static_cast<int>(bps_.size()) || index >= bpList_->count()) return;
    QSignalBlocker block(bpList_);
    auto* it = bpList_->item(index);
    it->setText(bpRowText(bps_[index]));
    it->setFlags(it->flags() | Qt::ItemIsUserCheckable);
    it->setCheckState(bps_[index].enabled ? Qt::Checked : Qt::Unchecked);
}

void DebuggerWindow::setConditionalBreakpointAtCursor() {
    uintptr_t addr = currentCursorAddress();
    if (!addr) return;
    bool ok = false;
    const auto architecture = session_->getStopContext().architecture;
    const QString example = architecture == ce::CpuArchitecture::Arm64 ? "X0 == 5" :
                            architecture == ce::CpuArchitecture::X86_32 ? "EAX == 5" : "RAX == 5";
    QString cond = QInputDialog::getText(this, "Conditional breakpoint",
        "Break only when this expression is true\n"
        "(Lua; register names accept either case, also available in ctx, e.g. \"" + example + "\"):",
        QLineEdit::Normal, QString(), &ok);
    if (!ok) return;
    addBreakpointAt(addr, cond.trimmed());
}

void DebuggerWindow::editBreakpointCondition() {
    int row = bpList_->currentRow();
    if (row < 0 || row >= static_cast<int>(bps_.size())) return;
    // The dialog runs an event loop: a queued debug event (an exec) can clear or
    // reorder bps_ meanwhile, so find the breakpoint again afterwards.
    const uintptr_t addr = bps_[row].addr;
    const bool hardware = bps_[row].hardware;
    bool ok = false;
    QString cur = QString::fromStdString(bps_[row].condition);
    QString cond = QInputDialog::getText(this, "Edit breakpoint condition",
        "Break only when this expression is true (empty = unconditional):",
        QLineEdit::Normal, cur, &ok);
    if (!ok) return;
    auto it = std::find_if(bps_.begin(), bps_.end(),
                           [&](const Bp& b) { return b.addr == addr && b.hardware == hardware; });
    if (it == bps_.end()) { statusLabel_->setText("The breakpoint was removed while editing"); return; }
    it->condition = cond.trimmed().toStdString();
    refreshBpRow(static_cast<int>(it - bps_.begin()));
}

void DebuggerWindow::onRemoveBreakpoint() {
    removeBreakpointRow(bpList_->currentRow());
}

bool DebuggerWindow::removeBreakpointRow(int row) {
    if (row < 0 || row >= static_cast<int>(bps_.size())) return false;
    // A step runs on the tracer thread until it returns, and a removal queued
    // behind it would block this thread for as long (forever for a call that
    // never returns). Removal while running is fine: the session stops the
    // target for it.
    if (stepping_) {
        statusLabel_->setText("Wait for the step to finish (or Detach) before removing a breakpoint");
        return false;
    }
    if (bps_[row].enabled) {
        bool removed=bps_[row].hardware ? session_->removeHardwareBreakpoint(bps_[row].id) :
                                         session_->removeSoftwareBreakpoint(bps_[row].id);
        if (!removed) {
            statusLabel_->setText("Breakpoint cleanup pending: "+QString::fromStdString(session_->lastError().message()));
            return false;
        }
    }
    bps_.erase(bps_.begin() + row);
    delete bpList_->takeItem(row);
    if (paused()) updateDisassembly(session_->getStopContext());
    return true;
}

bool DebuggerWindow::removeBreakpointAt(uintptr_t addr) {
    for (size_t i = 0; i < bps_.size(); ++i)
        if (!bps_[i].hardware && bps_[i].addr == addr) return removeBreakpointRow(static_cast<int>(i));
    return false;
}

std::set<uintptr_t> DebuggerWindow::breakpointAddresses() const {
    std::set<uintptr_t> out;
    for (const auto& b : bps_) if (!b.hardware && b.enabled) out.insert(b.addr);
    return out;
}

QString DebuggerWindow::bpDataLabel(uintptr_t addr, int type, int size) {
    return hex(addr) + QStringLiteral("  [%1%2]").arg(type == 3 ? "rw" : "w").arg(size);
}

void DebuggerWindow::onAddDataBreakpoint() {
    if (!session_->isAttached() || !paused()) {
        statusLabel_->setText("Stop the target before setting a breakpoint");
        return;
    }
    // One dialog for the whole watchpoint: address, trigger and size.
    QDialog dialog(this);
    dialog.setWindowTitle("Data breakpoint");
    auto* form = new QFormLayout(&dialog);
    auto* addrEdit = new QLineEdit(bpInput_->text().trimmed(), &dialog);
    addrEdit->setPlaceholderText("address (hex)");
    addrEdit->setMinimumWidth(220);
    auto* typeCombo = new QComboBox(&dialog);
    typeCombo->addItem("Writes", 1);
    typeCombo->addItem("Reads or writes", 3);
    auto* sizeCombo = new QComboBox(&dialog);
    for (int size : {1, 2, 4, 8}) sizeCombo->addItem(QString("%1 %2").arg(size).arg(size == 1 ? "byte" : "bytes"), size);
    sizeCombo->setCurrentIndex(std::max(0, sizeCombo->findData(QSettings().value("debug/bpSize", "4").toInt())));
    form->addRow("Address:", addrEdit);
    form->addRow("Break on:", typeCombo);
    form->addRow("Size:", sizeCombo);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    buttons->button(QDialogButtonBox::Ok)->setText("Set");
    form->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() != QDialog::Accepted) return;

    bool ok = false;
    const QString addrStr = addrEdit->text().trimmed();
    uintptr_t addr = addrStr.startsWith("0x", Qt::CaseInsensitive)
        ? addrStr.mid(2).toULongLong(&ok, 16)
        : addrStr.toULongLong(&ok, 16);
    if (!ok || !addr) { statusLabel_->setText("Invalid address"); return; }
    const int type = typeCombo->currentData().toInt();   // 1=write, 3=access
    const int size = sizeCombo->currentData().toInt();

    for (auto& b : bps_) if (b.hardware && b.addr == addr) return;   // already watched
    int id = session_->setHardwareBreakpoint(addr, type, size);
    if (id <= 0) {
        statusLabel_->setText("No free debug register (max 4 hardware breakpoints)");
        return;
    }
    Bp bp; bp.id = id; bp.addr = addr; bp.hardware = true; bp.hwType = type; bp.hwSize = size;
    bps_.push_back(bp);
    bpList_->addItem(new QListWidgetItem());
    refreshBpRow(static_cast<int>(bps_.size()) - 1);
}

void DebuggerWindow::onDebugEvent(int type) {
    if (type == static_cast<int>(ce::DebugEventType::ThreadExiting)) {
        refreshStopped();
        statusLabel_->setText(QStringLiteral("Thread is exiting; stopped on tid %1")
                                 .arg(static_cast<int>(session_->activeThread())));
        return;
    }
    if (type == static_cast<int>(ce::DebugEventType::ProcessExecuted)) {
        bps_.clear();
        bpList_->clear();
        pendingRtcId_=-1; pendingRtcAddr_=0;
        prevGp_.clear(); prevVectors_={}; shownGp_.clear(); shownVectors_={};
        refreshStopped();
        statusLabel_->setText("Process executed a new program; previous breakpoints cleared");
        return;
    }
    if (type == static_cast<int>(ce::DebugEventType::ProcessExited)) {
        statusLabel_->setText("Process exited");
        setRunningUi(false, true);
        return;
    }
    // Conditional breakpoints: if the breakpoint that stopped us carries a
    // condition and it evaluates false for the current register state, resume
    // silently instead of surfacing the stop (CE's "condition" field).
    if (type == static_cast<int>(ce::DebugEventType::BreakpointHit)) {
        auto ctx = session_->getStopContext();
        // A code breakpoint stops at its address; a data breakpoint's event
        // carries the watched address, while RIP is wherever the access was.
        const uintptr_t eventAddr = lastEvtAddr_.load();
        for (size_t i = 0; i < bps_.size(); ++i) {
            if (bps_[i].addr != (bps_[i].hardware ? eventAddr : ctx.instructionPointer())) continue;
            // False condition => resume silently, don't count it as a hit.
            if (!bps_[i].condition.empty() &&
                !ce::evaluateBreakpointCondition(bps_[i].condition, ctx, ctx.instructionPointer())) {
                setRunningUi(true);
                if (!session_->continueExecution() && session_->isAttached() && session_->isStopped()) {
                    refreshStopped();
                    statusLabel_->setText("Continue failed, still stopped: "+
                                          QString::fromStdString(session_->lastError().message()));
                }
                return;
            }
            bps_[i].hitCount++;
            refreshBpRow(static_cast<int>(i));
            break;
        }
    }
    // The run-to-cursor breakpoint is one-shot: clear it on the stop at its
    // target, and also on a stop anywhere else, so it never fires later.
    if (!clearRunToCursor()) {
        refreshStopped();
        statusLabel_->setText("Run-to-cursor cleanup pending: "+QString::fromStdString(session_->lastError().message()));
        return;
    }
    refreshStopped();
}

bool DebuggerWindow::clearRunToCursor() {
    if (pendingRtcId_ <= 0) return true;
    if (!session_->removeSoftwareBreakpoint(pendingRtcId_)) return false;
    pendingRtcId_ = -1; pendingRtcAddr_ = 0;
    return true;
}

void DebuggerWindow::refreshStopped() {
    if (!session_->isAttached()) return;
    updateThreadList();
    auto ctx = session_->getStopContext();
    lastStopRip_ = ctx.instructionPointer();
    lastStopRflags_ = ctx.architecture == ce::CpuArchitecture::Arm64 ? ctx.pstate : ctx.rflags;
    lastStopContext_ = ctx;
    updateRegisters(ctx);
    updateDisassembly(ctx);
    updateStack(ctx);
    if (lastMemAddr_) updateMemoryView(lastMemAddr_);   // keep the hex pane current
    statusLabel_->setText(QStringLiteral("Stopped at %1 (tid %2)")
                              .arg(hex(ctx.instructionPointer())).arg(static_cast<int>(session_->activeThread())));
    setRunningUi(false);
    emit stopped(ctx.instructionPointer());
}

void DebuggerWindow::updateThreadList() {
    if (!threadCombo_) return;
    auto tids = session_->stoppedThreads();
    pid_t active = session_->activeThread();
    // The initial attach can supply a context before the stopped-thread list is populated.
    if (active > 0 && std::find(tids.begin(), tids.end(), active) == tids.end())
        tids.push_back(active);
    // Block signals: repopulating must not be seen as a user thread switch.
    threadCombo_->blockSignals(true);
    threadCombo_->clear();
    int sel = 0;
    for (size_t i = 0; i < tids.size(); ++i) {
        threadCombo_->addItem(threadLabel(ce::localTargetPid(proc_).value_or(0), static_cast<int>(tids[i])),
                              static_cast<int>(tids[i]));
        if (tids[i] == active) sel = static_cast<int>(i);
    }
    if (threadCombo_->count() > 0) threadCombo_->setCurrentIndex(sel);
    threadCombo_->blockSignals(false);
}

void DebuggerWindow::onThreadSelected(int index) {
    if (!session_ || index < 0 || !paused()) return;
    bool okv = false;
    pid_t tid = static_cast<pid_t>(threadCombo_->itemData(index).toInt(&okv));
    if (okv && session_->selectThread(tid))
        refreshStopped();   // re-render registers/disasm/stack for the new thread
}

int DebuggerWindow::threadCount() const {
    return threadCombo_ ? threadCombo_->count() : 0;
}

bool DebuggerWindow::switchToOtherThreadForTest() {
    if (!threadCombo_ || !session_) return false;
    pid_t cur = session_->activeThread();
    for (int i = 0; i < threadCombo_->count(); ++i) {
        bool okv = false;
        pid_t tid = static_cast<pid_t>(threadCombo_->itemData(i).toInt(&okv));
        if (okv && tid != cur) {
            threadCombo_->setCurrentIndex(i);   // fires onThreadSelected -> selectThread
            return session_->activeThread() == tid;
        }
    }
    return false;
}

void DebuggerWindow::updateMemoryView(uintptr_t addr) {
    if (!memView_ || !proc_) return;
    lastMemAddr_ = addr;
    uint8_t buf[128];
    auto r = proc_->read(addr, buf, sizeof(buf));
    size_t n = (r && *r) ? *r : 0;
    if (n == 0) { memView_->setPlainText("  <unreadable at " + hex(addr) + ">"); memChanged_.clear(); return; }

    // Flag bytes that changed since the previous dump at the SAME address, so stepping
    // shows what the code just wrote (like the standalone hex pane). A new address resets.
    memChanged_.assign(n, 0);
    if (prevMemAddr_ == addr && prevMem_.size() >= n)
        for (size_t i = 0; i < n; ++i) memChanged_[i] = (buf[i] != prevMem_[i]) ? 1 : 0;
    prevMem_.assign(buf, buf + n);
    prevMemAddr_ = addr;

    const QString changedCol = ce::gui::editorPalette().error.name();  // theme-aware red
    QString html = QStringLiteral("<pre style=\"margin:0\">");
    for (size_t row = 0; row < n; row += 16) {
        html += hex(addr + row) + "  ";
        QString ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (row + i < n) {
                uint8_t b = buf[row + i];
                QString bs = QString::asprintf("%02x ", b);
                html += memChanged_[row + i]
                    ? QStringLiteral("<span style=\"color:%1\">%2</span>").arg(changedCol, bs)
                    : bs;
                ascii += (b >= 0x20 && b < 0x7f) ? QChar(b) : QChar('.');
            } else {
                html += QStringLiteral("   ");
            }
        }
        html += " " + ascii.toHtmlEscaped() + "\n";
    }
    html += QStringLiteral("</pre>");
    memView_->setHtml(html);
}

bool DebuggerWindow::memViewChangeHighlightForTest(uintptr_t addr) {
    if (!proc_) return false;
    uint8_t orig = 0;
    auto r0 = proc_->read(addr, &orig, 1);
    if (!r0 || *r0 != 1) return false;
    updateMemoryView(addr);                                  // baseline
    const int base = memViewChangedByteCountForTest();
    const uint8_t nb = static_cast<uint8_t>(orig ^ 0xFF);
    if (auto w = proc_->write(addr, &nb, 1); !w || *w < 1) return false;
    updateMemoryView(addr);                                  // one byte changed
    const int after = memViewChangedByteCountForTest();
    proc_->write(addr, &orig, 1);                            // restore
    updateMemoryView(addr);
    return base == 0 && after == 1;
}

void DebuggerWindow::onMemAddrEntered() {
    QString t = memAddrInput_->text().trimmed();
    if (t.startsWith("0x") || t.startsWith("0X")) t = t.mid(2);
    bool okv = false;
    const qulonglong addr = t.toULongLong(&okv, 16);
    if (okv) updateMemoryView(static_cast<uintptr_t>(addr));
}

bool DebuggerWindow::memoryViewShowsForTest(uintptr_t addr) {
    if (!proc_) return false;
    updateMemoryView(addr);
    uint8_t buf[4];
    auto r = proc_->read(addr, buf, sizeof(buf));
    if (!r || *r < 4) return false;
    QString expect;
    for (int i = 0; i < 4; ++i) expect += QString::asprintf("%02x ", buf[i]);
    const QString text = memView_->toPlainText();
    return text.contains(hex(addr)) && text.contains(expect.trimmed());
}

bool DebuggerWindow::xmm0ShowsForTest(uint64_t lo) {
    return vectorRegisterShowsForTest(0, lo);
}

bool DebuggerWindow::vectorRegisterShowsForTest(unsigned index, uint64_t lo) {
    if (!regTable_ || !session_) return false;
    auto vectors = session_->getVectorRegisters();
    if (index >= vectors.count) return false;
    auto* it = regTable_->item(static_cast<int>(ce::cpuRegisterValues(session_->getStopContext()).size() + index), 0);
    if (!it) return false;
    return it->text().contains(QString::asprintf("%016llx", static_cast<unsigned long long>(lo)));
}

void DebuggerWindow::updateRegisters(const ce::CpuContext& c) {
    auto registers = ce::cpuRegisterValues(c);
    const int kGp = static_cast<int>(registers.size());
    const bool arm = c.architecture == ce::CpuArchitecture::Arm64;
    const int vectorCount = arm ? 32 : c.architecture == ce::CpuArchitecture::X86_64 ? 16
                                   : c.architecture == ce::CpuArchitecture::X86_32 ? 8 : 0;
    const int controls = arm ? 2 : vectorCount ? 1 : 0;
    auto vectors = session_->getVectorRegisters();
    // Flag registers the last instruction changed, like CE: red when the value
    // differs from the previous stop, default colour otherwise. Skipped on the
    // first stop of a session (prevGp_ empty), so nothing lights up spuriously.
    const bool sameArchitecture = registerArchitecture_ == c.architecture;
    // A stop is rendered more than once (its debug event, then the command
    // that caused it). Compare against the previous distinct stop, not the
    // last render, or the second render clears every highlight.
    std::vector<uint64_t> values;
    for (const auto& value : registers) values.push_back(value.value);
    auto sameVectors = [](const auto& a, const auto& b) {
        return a.count == b.count && a.control == b.control && a.status == b.status && a.registers == b.registers;
    };
    if (!sameArchitecture || values != shownGp_ || !sameVectors(vectors, shownVectors_)) {
        prevGp_ = sameArchitecture ? shownGp_ : std::vector<uint64_t>{};
        prevVectors_ = shownVectors_;
        shownGp_ = values;
        shownVectors_ = vectors;
    }
    const bool hasPrev = sameArchitecture && prevGp_.size() == registers.size();
    const QBrush changedFg(ce::gui::editorPalette().error);   // theme-aware red
    const QBrush normalFg = regTable_->palette().text();
    // Update items IN PLACE (never setItem here): this runs from within
    // onRegisterEdited (itemChanged), where replacing an item would delete the
    // one whose setText is still on the stack (use-after-free). Block signals so
    // these programmatic fills aren't re-interpreted as user edits.
    const QSignalBlocker blocker(regTable_);
    if (!sameArchitecture || regTable_->rowCount() != kGp + vectorCount + controls) {
        regTable_->setRowCount(kGp + vectorCount + controls);
        for (int i = 0; i < kGp; ++i) {
            QString name = QString::fromStdString(registers[i].name);
            if (arm && name == "X29") name += " (FP)";
            if (arm && name == "X30") name += " (LR)";
            regTable_->setVerticalHeaderItem(i, new QTableWidgetItem(name));
        }
        for (int i = 0; i < vectorCount; ++i)
            regTable_->setVerticalHeaderItem(kGp + i, new QTableWidgetItem(QString(arm ? "V%1" : "XMM%1").arg(i)));
        if (controls) regTable_->setVerticalHeaderItem(kGp + vectorCount, new QTableWidgetItem(arm ? "FPCR" : "MXCSR"));
        if (arm) regTable_->setVerticalHeaderItem(kGp + vectorCount + 1, new QTableWidgetItem("FPSR"));
    }
    auto cell = [&](int row, bool editable) {
        auto* item = regTable_->item(row, 0);
        if (!item) { item = new QTableWidgetItem(); regTable_->setItem(row, 0, item); }
        item->setFlags(editable ? item->flags() | Qt::ItemIsEditable : item->flags() & ~Qt::ItemIsEditable);
        return item;
    };
    for (int i = 0; i < kGp; ++i) {
        auto* it = cell(i, true);
        it->setText(QStringLiteral("0x%1").arg(registers[i].value, registers[i].bits / 4, 16, QLatin1Char('0')));
        it->setForeground(hasPrev && prevGp_[i] != registers[i].value ? changedFg : normalFg);
    }
    if (flagsLabel_) {
        // Show every status flag's 0/1 state (CE-style), not just the set ones, so a
        // clear flag next to a conditional jump is still readable.
        flagsLabel_->setText(QStringLiteral("Flags: ") +
                             (kGp ? QString::fromStdString(ce::describeCpuStatusFlags(c)) : QStringLiteral("Unavailable")));
    }
    // Show all architectural SIMD registers, preserving unavailable reads.
    for (int r = 0; r < vectorCount; ++r) {
        auto* it = cell(kGp + r, false);
        QString s;
        if (r < static_cast<int>(vectors.count)) {
            for (int b = 0; b < 16; ++b) {
                int byte = std::endian::native == std::endian::little ? 15 - b : b;
                s += QString::asprintf("%02x", vectors.registers[r][byte]);
            }
        } else s = "Unavailable";
        it->setText(s);
        it->setForeground(hasPrev && r < static_cast<int>(vectors.count) &&
                          r < static_cast<int>(prevVectors_.count) && vectors.registers[r] != prevVectors_.registers[r] ? changedFg : normalFg);
    }
    for (int i = 0; i < controls; ++i) {
        auto* it = cell(kGp + vectorCount + i, false);
        uint32_t value = i ? vectors.status : vectors.control;
        uint32_t previous = i ? prevVectors_.status : prevVectors_.control;
        it->setText(vectors.count ? QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')) : QStringLiteral("Unavailable"));
        it->setForeground(hasPrev && vectors.count && prevVectors_.count && value != previous ? changedFg : normalFg);
    }
    registerArchitecture_ = c.architecture;
}

bool DebuggerWindow::anyRegisterChangedHighlightForTest() const {
    if (!regTable_) return false;
    const QColor red = ce::gui::editorPalette().error;
    for (int i = 0; i < static_cast<int>(prevGp_.size()); ++i)
        if (auto* it = regTable_->item(i, 0); it && it->foreground().color() == red)
            return true;
    return false;
}

QString DebuggerWindow::flagsTextForTest() const {
    return flagsLabel_ ? flagsLabel_->text() : QString();
}

// The register value column is editable; committing a cell writes the parsed
// value back to the stopped thread via DebugSession::setStopContext, then
// re-renders from the canonical post-write context (which also reverts bad hex).
void DebuggerWindow::onRegisterEdited(QTableWidgetItem* item) {
    if (!session_ || !item || item->column() != 0) return;
    if (!session_->isAttached() || !paused()) return;

    QString t = item->text().trimmed();
    if (t.startsWith("0x") || t.startsWith("0X")) t = t.mid(2);
    bool okParse = false;
    const qulonglong v = t.toULongLong(&okParse, 16);
    if (okParse) {
        ce::CpuContext ctx = session_->getStopContext();
        auto registers = ce::cpuRegisterValues(ctx);
        if (item->row() < 0 || item->row() >= static_cast<int>(registers.size())) return;
        if (!ce::setCpuRegisterValue(ctx, item->row(), v)) {
            statusLabel_->setText(QStringLiteral("%1 needs a %2-bit hexadecimal value")
                                 .arg(QString::fromStdString(registers[item->row()].name)).arg(registers[item->row()].bits));
        } else if (session_->setStopContext(ctx)) {
            refreshStopped();
            return;
        } else {
            statusLabel_->setText("Register edit failed: " + QString::fromStdString(session_->lastError().message()));
        }
    } else statusLabel_->setText("Invalid hexadecimal register value");
    updateRegisters(session_->getStopContext());
}

bool DebuggerWindow::pokeRegisterForTest(int row, uint64_t value) {
    if (!regTable_ || !session_ || !paused()) return false;
    auto before = ce::cpuRegisterValues(session_->getStopContext());
    if (row < 0 || row >= static_cast<int>(before.size())) return false;
    auto* it = regTable_->item(row, 0);
    if (!it) return false;
    it->setText(hex(value));   // fires itemChanged -> onRegisterEdited -> setStopContext
    auto after = ce::cpuRegisterValues(session_->getStopContext());
    return row < static_cast<int>(after.size()) && after[row].value == value;
}

void DebuggerWindow::setComments(std::map<uintptr_t, std::string> comments) {
    comments_ = std::move(comments);
    // Re-render the paused disassembly so a comment added mid-session appears at once.
    if (paused())
        updateDisassembly(session_->getStopContext());
}

void DebuggerWindow::updateDisassembly(const ce::CpuContext& c) {
    // Remember which instruction the caret was on, so re-rendering (a breakpoint toggle,
    // a step, an auto-refresh) keeps it there instead of jerking it to the top.
    uintptr_t caretAddr = 0;
    if (int blk = disasmView_->textCursor().blockNumber();
        blk >= 0 && blk < static_cast<int>(disasmLineAddrs_.size()))
        caretAddr = disasmLineAddrs_[blk];
    disasmLineAddrs_.clear();
    const uintptr_t ip = c.instructionPointer();
    if (c.architecture == ce::CpuArchitecture::Arm64) disasm_.setArch(ce::Arch::ARM64);
    else if (c.architecture == ce::CpuArchitecture::X86_32) disasm_.setArch(ce::Arch::X86_32);
    else if (c.architecture == ce::CpuArchitecture::X86_64) disasm_.setArch(ce::Arch::X86_64);
    else {
        disasmView_->setPlainText("  <instruction architecture unavailable>");
        disasmView_->setExtraSelections({});
        return;
    }
    if (proc_ && !symbolsLoaded_) { resolver_.loadProcess(*proc_); symbolsLoaded_ = true; }
    if (modules_.empty() && proc_) modules_ = proc_->modules();   // for data-operand annotations
    uint8_t buf[128];
    auto rr = proc_->read(ip, buf, sizeof(buf));
    QString out;
    int currentLineBlock = -1;   // text block index of the "=>" line, for the highlight
    if (rr && *rr > 0) {
        // Restore the complete saved instruction bytes for x86 INT3 or ARM64 BRK.
        const size_t nread = *rr;
        for (const auto& b : bps_) {
            if (b.hardware || b.addr < ip || b.addr - ip >= nread) continue;
            const size_t offset = b.addr - ip;
            std::copy_n(b.original.begin(), std::min(b.original.size(), nread - offset), buf + offset);
        }
        auto insns = disasm_.disassemble(ip, {buf, *rr}, 24);
        for (auto& in : insns) {
            if (in.address == ip) currentLineBlock = static_cast<int>(disasmLineAddrs_.size());
            bool isBp = false;
            for (auto& b : bps_) if (b.addr == in.address) isBp = true;
            QString marker = (in.address == ip) ? "=> " : "   ";
            QString bpMark = isBp ? "*" : " ";
            // Symbol annotation (CE-style), inline so it never shifts the line/address
            // mapping: a direct call/jmp shows its target's symbol; the current line
            // shows the function it is stopped in.
            std::string sym;
            const bool branch = in.isCall || in.mnemonic == "jmp" ||
                                (in.mnemonic.size() > 1 && in.mnemonic[0] == 'j') ||
                                in.mnemonic == "b" || in.mnemonic.starts_with("b.") ||
                                in.mnemonic == "cbz" || in.mnemonic == "cbnz" ||
                                in.mnemonic == "tbz" || in.mnemonic == "tbnz";
            if (branch && in.operands.find('[') == std::string::npos) {
                if (auto pos = in.operands.find("0x"); pos != std::string::npos) {
                    try {
                        auto t = static_cast<uintptr_t>(std::stoull(in.operands.substr(pos + 2), nullptr, 16));
                        sym = resolver_.resolve(t);
                    } catch (...) {}
                }
            }
            if (sym.empty() && in.address == ip) sym = resolver_.resolve(in.address);
            QString anno = sym.empty() ? QString() : QStringLiteral("   ; %1").arg(QString::fromStdString(sym));
            // Data reference: annotate a memory operand's effective address with the
            // symbol / module+offset it points at and the value there, so you can see
            // which memory the paused code touches. RIP-relative uses the pre-resolved
            // ripTarget; for the current instruction a register-relative operand
            // ([rax+8], [rbx+rcx*4+10]) is resolved from the live registers.
            uintptr_t eff = in.ripTarget;
            if (!eff && !branch && in.address == ip)
                eff = ce::computeEffectiveAddress(in, c);
            if (anno.isEmpty() && !branch && eff) {
                std::string es = resolver_.resolve(eff);
                if (es.empty()) es = ce::moduleOffsetString(modules_, eff);
                QString valPart;
                if (proc_) {
                    uint8_t vb[24] = {};
                    if (auto r = proc_->read(eff, vb, sizeof(vb)); r && *r > 0) {
                        const size_t n = *r;
                        size_t printable = 0;
                        for (size_t k = 0; k < n && vb[k]; ++k) {
                            if (vb[k] >= 0x20 && vb[k] < 0x7f) ++printable; else break;
                        }
                        if (printable >= 3 && (printable == n || vb[printable] == 0)) {
                            valPart = QStringLiteral(" \"%1\"").arg(QString::fromLatin1(
                                reinterpret_cast<const char*>(vb), static_cast<int>(printable)));
                        }
                    }
                }
                if (valPart.isEmpty() && proc_) {
                    // Not a string: show the sized integer (from the operand's ptr prefix).
                    const int sz = in.operands.find("qword") != std::string::npos ? 8
                                 : in.operands.find("dword") != std::string::npos ? 4
                                 : in.operands.find("word")  != std::string::npos ? 2
                                 : in.operands.find("byte")  != std::string::npos ? 1 : 0;
                    uint64_t v = 0;
                    if (sz) {
                        auto r = proc_->read(eff, &v, sz);
                        if (r && *r == static_cast<size_t>(sz)) {
                            int64_t sv = sz == 1 ? static_cast<int8_t>(v)
                                       : sz == 2 ? static_cast<int16_t>(v)
                                       : sz == 4 ? static_cast<int32_t>(v)
                                                 : static_cast<int64_t>(v);
                            valPart = QStringLiteral(" = %1").arg(static_cast<qlonglong>(sv));
                        }
                    }
                }
                if (!es.empty())
                    anno = QStringLiteral("   ; -> %1%2").arg(QString::fromStdString(es), valPart);
                else if (!valPart.isEmpty())
                    anno = QStringLiteral("   ; ->%1").arg(valPart);
            }
            // For the paused instruction, show whether a conditional branch will be
            // taken given the live flags (CE-style), so the path is visible before you
            // step. Unconditional jmp needs no hint.
            if (in.address == ip && in.mnemonic != "jmp" && in.mnemonic != "b") {
                const auto jt = c.architecture == ce::CpuArchitecture::Arm64 ?
                    ce::conditionalArm64JumpTaken(in.mnemonic, c.pstate) :
                    ce::conditionalJumpTaken(in.mnemonic, c.rflags);
                if (jt)
                    anno += *jt ? QStringLiteral("   (will jump)") : QStringLiteral("   (no jump)");
            }
            // User comment (set in the Memory Viewer): show it inline too, so annotated
            // code reads the same while debugging.
            if (auto ci = comments_.find(in.address); ci != comments_.end())
                anno += QStringLiteral("   // %1").arg(QString::fromStdString(ci->second));
            out += QStringLiteral("%1%2%3  %4 %5%6\n")
                       .arg(marker, bpMark, hex(in.address),
                            QString::fromStdString(in.mnemonic),
                            QString::fromStdString(in.operands), anno);
            disasmLineAddrs_.push_back(in.address);
        }
    } else {
        out = "  <unable to read code at " + hex(ip) + ">";
    }
    disasmView_->setPlainText(out);

    // Restore the caret to the same instruction it was on before the re-render.
    if (caretAddr) {
        for (size_t i = 0; i < disasmLineAddrs_.size(); ++i)
            if (disasmLineAddrs_[i] == caretAddr) {
                disasmView_->setTextCursor(QTextCursor(disasmView_->document()->findBlockByNumber(static_cast<int>(i))));
                break;
            }
    }

    // Highlight the current (=>) line with a full-width background, CE-style, so the
    // stopped location stands out beyond the "=> " text marker.
    if (currentLineBlock >= 0) {
        QTextEdit::ExtraSelection sel;
        sel.cursor = QTextCursor(disasmView_->document()->findBlockByNumber(currentLineBlock));
        sel.format.setBackground(ce::gui::isDarkTheme() ? QColor(0x33, 0x53, 0x3a)
                                                        : QColor(0xcf, 0xef, 0xd0));
        sel.format.setProperty(QTextFormat::FullWidthSelection, true);
        disasmView_->setExtraSelections({sel});
    } else {
        disasmView_->setExtraSelections({});
    }
}

void DebuggerWindow::updateStack(const ce::CpuContext& c) {
    // Resolve stack values that point into code (return addresses) so the raw stack
    // reads as a call stack (CE-style): prefer the function name ("func+0xNN" from the
    // symbol table), falling back to "module+offset" when there is no symbol. Symbols
    // and the module list are loaded once per session (both rarely change while stopped).
    if (proc_ && !symbolsLoaded_) { resolver_.loadProcess(*proc_); symbolsLoaded_ = true; }
    if (modules_.empty() && proc_) modules_ = proc_->modules();
    QString out;
    const size_t width = c.architecture == ce::CpuArchitecture::X86_32 ? 4 :
                         c.architecture == ce::CpuArchitecture::X86_64 ||
                         c.architecture == ce::CpuArchitecture::Arm64 ? 8 : 0;
    const auto order = c.architecture == ce::CpuArchitecture::Arm64 ?
        proc_->targetDescription().host.byteOrder : ce::ByteOrder::Little;
    if (!width || order == ce::ByteOrder::Unknown) {
        stackView_->setPlainText("  <stack register format unavailable>");
        return;
    }
    for (int i = 0; i < 16; ++i) {
        const uintptr_t offset = static_cast<uintptr_t>(i) * width;
        if (c.stackPointer() > UINTPTR_MAX - offset) break;
        uintptr_t slotAddr = c.stackPointer() + offset;
        uint8_t bytes[8]{};
        auto rr = proc_->read(slotAddr, bytes, width);
        if (rr && *rr == width) {
            const uint64_t val = *ce::decodeTargetUnsigned({bytes, width}, order);
            std::string anno = val ? resolver_.resolve(static_cast<uintptr_t>(val)) : std::string();
            if (val && anno.empty()) anno = ce::moduleOffsetString(modules_, static_cast<uintptr_t>(val));
            if (!anno.empty())
                out += QStringLiteral("%1: %2  %3\n")
                           .arg(hex(slotAddr), hex(val), QString::fromStdString(anno));
            else
                out += QStringLiteral("%1: %2\n").arg(hex(slotAddr), hex(val));
        } else {
            out += QStringLiteral("%1: ??\n").arg(hex(slotAddr));
        }
    }
    stackView_->setPlainText(out);
}

QString DebuggerWindow::stackTextForTest() const {
    return stackView_ ? stackView_->toPlainText() : QString();
}

QString DebuggerWindow::disasmTextForTest() const {
    return disasmView_ ? disasmView_->toPlainText() : QString();
}

bool DebuggerWindow::disasmCurrentLineHighlightedForTest() const {
    if (!disasmView_) return false;
    const auto sels = disasmView_->extraSelections();
    return !sels.isEmpty() && sels.first().cursor.block().text().contains("=>");
}

uintptr_t DebuggerWindow::currentCursorAddress() const {
    int block = disasmView_->textCursor().blockNumber();
    if (block >= 0 && block < static_cast<int>(disasmLineAddrs_.size()))
        return disasmLineAddrs_[block];
    return lastStopRip_;
}

void DebuggerWindow::setBreakpointAtCursor() {
    addBreakpointAt(currentCursorAddress());
}

void DebuggerWindow::toggleBreakpointAtCursor() {
    uintptr_t addr = currentCursorAddress();
    // F5: if a breakpoint is already planted here, remove it; otherwise add one.
    for (size_t i = 0; i < bps_.size(); ++i) {
        if (bps_[i].addr == addr) {
            bpList_->setCurrentRow(static_cast<int>(i));
            onRemoveBreakpoint();
            return;
        }
    }
    addBreakpointAt(addr);
}

bool DebuggerWindow::toggleBreakpointAtCursorForTest(int lineIndex) {
    // Seat the caret once; the caret is preserved across the toggle's re-render, so the
    // second toggle acts on the same line without re-seating.
    QTextCursor c = disasmView_->textCursor();
    c.movePosition(QTextCursor::Start);
    c.movePosition(QTextCursor::Down, QTextCursor::MoveAnchor, lineIndex);
    disasmView_->setTextCursor(c);
    uintptr_t addr = currentCursorAddress();
    auto has = [&] { for (auto& b : bps_) if (b.addr == addr) return true; return false; };
    const bool startedWithBp = has();
    const int before = static_cast<int>(bps_.size());
    const int delta = startedWithBp ? -1 : +1;
    toggleBreakpointAtCursor();                                 // flip
    const bool flipped = (has() != startedWithBp) && static_cast<int>(bps_.size()) == before + delta;
    const bool caretKept = currentCursorAddress() == addr;     // preserved across the re-render
    toggleBreakpointAtCursor();                                 // flip back
    const bool restored = (has() == startedWithBp) && static_cast<int>(bps_.size()) == before;
    return flipped && caretKept && restored;
}

void DebuggerWindow::nopInstructionAtCursor() {
    if (!proc_ || !paused()) return;
    const uintptr_t addr = currentCursorAddress();
    // A planted breakpoint reads as a trap byte: the instruction would decode as
    // one byte, and removing the breakpoint later writes the saved original back
    // over the NOP. Decode the real instruction and refuse while a breakpoint
    // sits inside it.
    uint8_t buf[16];
    auto rr = proc_->read(addr, buf, sizeof(buf));
    if (!rr || *rr == 0) { statusLabel_->setText("Cannot read the instruction at " + hex(addr)); return; }
    for (const auto& b : bps_) {
        if (b.hardware || b.addr < addr || b.addr - addr >= *rr) continue;
        const size_t offset = b.addr - addr;
        std::copy_n(b.original.begin(), std::min(b.original.size(), *rr - offset), buf + offset);
    }
    auto insns = disasm_.disassemble(addr, {buf, *rr}, 1);
    if (insns.empty() || insns[0].size == 0) { statusLabel_->setText("No instruction at " + hex(addr)); return; }
    for (const auto& b : bps_)
        if (!b.hardware && b.enabled && b.addr >= addr && b.addr - addr < insns[0].size) {
            statusLabel_->setText("Remove the breakpoint on this instruction before replacing it with NOPs");
            return;
        }
    if (ce::nopInstruction(*proc_, addr).empty())
        statusLabel_->setText("Could not replace the instruction at " + hex(addr) + " with NOPs");
    updateDisassembly(session_->getStopContext());   // show the NOPs
}

void DebuggerWindow::onDisasmContextMenu(const QPoint& pos) {
    // Move the caret to the clicked line so currentCursorAddress() targets it.
    disasmView_->setTextCursor(disasmView_->cursorForPosition(pos));
    // Below the last instruction (or on an empty view) there is no line, and
    // currentCursorAddress() would fall back to RIP: offer nothing to act on.
    const int block = disasmView_->textCursor().blockNumber();
    const bool onLine = block >= 0 && block < static_cast<int>(disasmLineAddrs_.size());
    QMenu menu(this);
    for (QAction* a : {menu.addAction("Set breakpoint here", this, &DebuggerWindow::setBreakpointAtCursor),
                       menu.addAction("Set conditional breakpoint...", this, &DebuggerWindow::setConditionalBreakpointAtCursor),
                       menu.addAction("Replace with NOPs",  this, &DebuggerWindow::nopInstructionAtCursor)})
        a->setEnabled(onLine);
    menu.addSeparator();
    // Run to this line (CE's F4): only meaningful while the target is paused.
    QAction* rtc = menu.addAction("Run to cursor", this, &DebuggerWindow::onRunToCursor);
    rtc->setEnabled(onLine && paused());
    menu.exec(disasmView_->viewport()->mapToGlobal(pos));
}

bool DebuggerWindow::disasmSetBreakpointForTest(int lineIndex) {
    QTextCursor c = disasmView_->textCursor();
    c.movePosition(QTextCursor::Start);
    c.movePosition(QTextCursor::Down, QTextCursor::MoveAnchor, lineIndex);
    disasmView_->setTextCursor(c);
    uintptr_t addr = currentCursorAddress();
    setBreakpointAtCursor();
    for (auto& b : bps_) if (b.addr == addr) return true;
    return false;
}

} // namespace ce::gui
