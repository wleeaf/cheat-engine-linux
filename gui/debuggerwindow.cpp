#include "gui/debuggerwindow.hpp"
#include "arch/cpu_flags.hpp"
#include "core/types.hpp"   // moduleOffsetString
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
#include <QTextCursor>
#include <csignal>

namespace ce::gui {

static QString hex(uintptr_t v) { return QStringLiteral("0x%1").arg(v, 0, 16); }

DebuggerWindow::DebuggerWindow(ce::ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc), session_(std::make_unique<ce::DebugSession>()) {
    setWindowTitle("Debugger");
    resize(920, 640);

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
    excBtn->setText("Break on exceptions ▾");
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

    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);

    // ── main split: [disasm / stack] | [registers / breakpoints] ──
    auto* split = new QSplitter(Qt::Horizontal);

    auto* leftSplit = new QSplitter(Qt::Vertical);
    disasmView_ = new QPlainTextEdit();
    disasmView_->setReadOnly(true);
    disasmView_->setFont(mono);
    disasmView_->setLineWrapMode(QPlainTextEdit::NoWrap);
    disasmView_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(disasmView_, &QPlainTextEdit::customContextMenuRequested,
            this, &DebuggerWindow::onDisasmContextMenu);
    leftSplit->addWidget(disasmView_);
    stackView_ = new QPlainTextEdit();
    stackView_->setReadOnly(true);
    stackView_->setFont(mono);
    stackView_->setLineWrapMode(QPlainTextEdit::NoWrap);
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
    regTable_ = new QTableWidget(26, 1);   // 10 GP/flags + 16 XMM
    regTable_->setFont(mono);
    regTable_->horizontalHeader()->setVisible(false);
    regTable_->horizontalHeader()->setStretchLastSection(true);
    regTable_->verticalHeader()->setVisible(true);
    static const char* rnames[] = {"RIP","RSP","RBP","RAX","RBX","RCX","RDX","RSI","RDI","RFLAGS",
        "XMM0","XMM1","XMM2","XMM3","XMM4","XMM5","XMM6","XMM7",
        "XMM8","XMM9","XMM10","XMM11","XMM12","XMM13","XMM14","XMM15"};
    for (int i = 0; i < 26; ++i)
        regTable_->setVerticalHeaderItem(i, new QTableWidgetItem(rnames[i]));
    rl->addWidget(regTable_, 3);

    // Decoded CPU flags under the register table (RFLAGS shows only the raw hex).
    flagsLabel_ = new QLabel(QStringLiteral("Flags:"));
    flagsLabel_->setFont(mono);
    flagsLabel_->setToolTip("Status/control flags set in RFLAGS at the current stop");
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
        if (!session_->isAttached() || !session_->isStopped()) {
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
            if (bps_[row].hardware) session_->removeHardwareBreakpoint(bps_[row].id);
            else                    session_->removeSoftwareBreakpoint(bps_[row].id);
            bps_[row].enabled = false;
        }
        if (session_->isStopped()) updateDisassembly(session_->getStopContext());
    });
    bl->addWidget(bpList_);
    auto* rmBtn = new QPushButton("Remove selected");
    bl->addWidget(rmBtn);
    rl->addWidget(bpGroup, 2);
    split->addWidget(right);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
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
    connect(rmBtn,      &QPushButton::clicked, this, &DebuggerWindow::onRemoveBreakpoint);
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
        prevGp_.clear(); prevXmm_ = {};   // fresh session: don't flag the first stop's registers
        refreshStopped();   // target is all-stopped right after attach
    } else {
        statusLabel_->setText("Attach failed (need ptrace permission?)");
        setRunningUi(false, true);
    }
}

DebuggerWindow::~DebuggerWindow() {
    if (session_ && session_->isAttached())
        session_->detach();   // restores breakpoint bytes, resumes the target
}

void DebuggerWindow::setRunningUi(bool running, bool exited) {
    bool stopped = !running && !exited;
    for (auto* b : {contBtn_, intoBtn_, overBtn_, outBtn_, rtcBtn_})
        b->setEnabled(stopped);
    detachBtn_->setEnabled(!exited);
    bpInput_->setEnabled(stopped);
    if (!stopped) emit resumed();   // running or exited: drop the current-line marker
}

void DebuggerWindow::onContinue() {
    if (!session_->isAttached()) return;
    statusLabel_->setText("Running...");
    setRunningUi(true);
    session_->continueExecution();
}

void DebuggerWindow::onStepInto() {
    if (!session_->isAttached() || !session_->isStopped()) return;
    session_->step(ce::StepMode::Into);
    refreshStopped();
}

void DebuggerWindow::onStepOver() {
    if (!session_->isAttached() || !session_->isStopped()) return;
    session_->step(ce::StepMode::Over);
    refreshStopped();
}

void DebuggerWindow::onStepOut() {
    if (!session_->isAttached() || !session_->isStopped()) return;
    session_->step(ce::StepMode::Out);
    refreshStopped();
}

void DebuggerWindow::onRunToCursor() {
    if (!session_->isAttached() || !session_->isStopped()) return;
    uintptr_t addr = currentCursorAddress();
    if (!addr) return;
    // If a user breakpoint already sits there, just continue to it.
    bool existing = false;
    for (auto& b : bps_) if (b.addr == addr) existing = true;
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
    if (!session_->isAttached() || !session_->isStopped()) {
        statusLabel_->setText("Stop the target before setting a breakpoint");
        return;
    }
    for (size_t i = 0; i < bps_.size(); ++i) if (bps_[i].addr == addr) {  // already set — update condition
        bps_[i].condition = condition.toStdString();
        refreshBpRow(static_cast<int>(i));
        return;
    }
    // Capture the original byte BEFORE planting 0xCC, so the disassembly can un-mask it
    // and show the real instruction while stopped here (not int3).
    uint8_t orig = 0; bool hasOrig = false;
    if (proc_) { uint8_t b = 0; auto rb = proc_->read(addr, &b, 1); if (rb && *rb == 1) { orig = b; hasOrig = true; } }
    int id = session_->setSoftwareBreakpoint(addr);
    if (id <= 0) { statusLabel_->setText("Failed to set breakpoint at " + hex(addr)); return; }
    Bp bp; bp.id = id; bp.addr = addr; bp.condition = condition.toStdString();
    bp.origByte = orig; bp.hasOrig = hasOrig;
    bps_.push_back(bp);
    bpList_->addItem(new QListWidgetItem());
    refreshBpRow(static_cast<int>(bps_.size()) - 1);
    if (session_->isStopped()) updateDisassembly(session_->getStopContext());
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
    QString cond = QInputDialog::getText(this, "Conditional breakpoint",
        "Break only when this expression is true\n"
        "(Lua; reads registers RAX/rax, RIP, ... and the ctx table, e.g. \"RAX == 5\"):",
        QLineEdit::Normal, QString(), &ok);
    if (!ok) return;
    addBreakpointAt(addr, cond.trimmed());
}

void DebuggerWindow::editBreakpointCondition() {
    int row = bpList_->currentRow();
    if (row < 0 || row >= static_cast<int>(bps_.size())) return;
    bool ok = false;
    QString cur = QString::fromStdString(bps_[row].condition);
    QString cond = QInputDialog::getText(this, "Edit breakpoint condition",
        "Break only when this expression is true (empty = unconditional):",
        QLineEdit::Normal, cur, &ok);
    if (!ok) return;
    bps_[row].condition = cond.trimmed().toStdString();
    refreshBpRow(row);
}

void DebuggerWindow::onRemoveBreakpoint() {
    int row = bpList_->currentRow();
    if (row < 0 || row >= static_cast<int>(bps_.size())) return;
    if (bps_[row].hardware) session_->removeHardwareBreakpoint(bps_[row].id);
    else                    session_->removeSoftwareBreakpoint(bps_[row].id);
    bps_.erase(bps_.begin() + row);
    delete bpList_->takeItem(row);
    if (session_->isStopped()) updateDisassembly(session_->getStopContext());
}

QString DebuggerWindow::bpDataLabel(uintptr_t addr, int type, int size) {
    return hex(addr) + QStringLiteral("  [%1%2]").arg(type == 3 ? "rw" : "w").arg(size);
}

void DebuggerWindow::onAddDataBreakpoint() {
    if (!session_->isAttached() || !session_->isStopped()) {
        statusLabel_->setText("Stop the target before setting a breakpoint");
        return;
    }
    bool ok = false;
    QString addrStr = QInputDialog::getText(this, "Data breakpoint",
        "Address to watch (hex):", QLineEdit::Normal,
        bpInput_->text().isEmpty() ? QString() : bpInput_->text(), &ok);
    if (!ok) return;
    uintptr_t addr = addrStr.trimmed().startsWith("0x")
        ? addrStr.trimmed().mid(2).toULongLong(&ok, 16)
        : addrStr.trimmed().toULongLong(&ok, 16);
    if (!ok || !addr) { statusLabel_->setText("Invalid address"); return; }

    QStringList types = {"On write", "On read/write (access)"};
    QString typeSel = QInputDialog::getItem(this, "Data breakpoint", "Break:", types, 0, false, &ok);
    if (!ok) return;
    int type = (types.indexOf(typeSel) == 1) ? 3 : 1;   // 1=write, 3=access

    QStringList sizes = {"1", "2", "4", "8"};
    QString sizeSel = QInputDialog::getItem(this, "Data breakpoint", "Size (bytes):", sizes, 2, false, &ok);
    if (!ok) return;
    int size = sizeSel.toInt();

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
    if (type == static_cast<int>(ce::DebugEventType::ProcessExited)) {
        statusLabel_->setText("Process exited");
        setRunningUi(false, true);
        return;
    }
    // Auto-clear a run-to-cursor temp breakpoint when its target is hit.
    if (type == static_cast<int>(ce::DebugEventType::BreakpointHit) &&
        pendingRtcId_ > 0 && lastEvtAddr_.load() == pendingRtcAddr_) {
        session_->removeSoftwareBreakpoint(pendingRtcId_);
        pendingRtcId_ = -1;
        pendingRtcAddr_ = 0;
    }
    // Conditional breakpoints: if the breakpoint that stopped us carries a
    // condition and it evaluates false for the current register state, resume
    // silently instead of surfacing the stop (CE's "condition" field).
    if (type == static_cast<int>(ce::DebugEventType::BreakpointHit)) {
        auto ctx = session_->getStopContext();
        for (size_t i = 0; i < bps_.size(); ++i) {
            if (bps_[i].addr != ctx.rip) continue;
            // False condition => resume silently, don't count it as a hit.
            if (!bps_[i].condition.empty() &&
                !ce::evaluateBreakpointCondition(bps_[i].condition, ctx, ctx.rip)) {
                setRunningUi(true);
                session_->continueExecution();
                return;
            }
            bps_[i].hitCount++;
            refreshBpRow(static_cast<int>(i));
            break;
        }
    }
    refreshStopped();
}

void DebuggerWindow::refreshStopped() {
    if (!session_->isAttached()) return;
    updateThreadList();
    auto ctx = session_->getStopContext();
    lastStopRip_ = ctx.rip;
    lastStopRflags_ = ctx.rflags;
    updateRegisters(ctx);
    updateDisassembly(ctx);
    updateStack(ctx);
    if (lastMemAddr_) updateMemoryView(lastMemAddr_);   // keep the hex pane current
    statusLabel_->setText(QStringLiteral("Stopped at %1 (tid %2)")
                              .arg(hex(ctx.rip)).arg(static_cast<int>(session_->activeThread())));
    setRunningUi(false);
    emit stopped(ctx.rip);
}

void DebuggerWindow::updateThreadList() {
    if (!threadCombo_) return;
    auto tids = session_->stoppedThreads();
    pid_t active = session_->activeThread();
    // Block signals: repopulating must not be seen as a user thread switch.
    threadCombo_->blockSignals(true);
    threadCombo_->clear();
    int sel = 0;
    for (size_t i = 0; i < tids.size(); ++i) {
        threadCombo_->addItem(QStringLiteral("tid %1").arg(static_cast<int>(tids[i])),
                              static_cast<int>(tids[i]));
        if (tids[i] == active) sel = static_cast<int>(i);
    }
    if (threadCombo_->count() > 0) threadCombo_->setCurrentIndex(sel);
    threadCombo_->blockSignals(false);
}

void DebuggerWindow::onThreadSelected(int index) {
    if (!session_ || index < 0 || !session_->isStopped()) return;
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
    if (!regTable_) return false;
    auto* it = regTable_->item(10, 0);   // XMM0 row
    if (!it) return false;
    return it->text().contains(QString::asprintf("%016llx", static_cast<unsigned long long>(lo)));
}

void DebuggerWindow::updateRegisters(const ce::CpuContext& c) {
    const uintptr_t vals[] = {c.rip, c.rsp, c.rbp, c.rax, c.rbx, c.rcx, c.rdx, c.rsi, c.rdi, c.rflags};
    constexpr int kGp = 10;
    // Flag registers the last instruction changed, like CE: red when the value
    // differs from the previous stop, default colour otherwise. Skipped on the
    // first stop of a session (prevGp_ empty), so nothing lights up spuriously.
    const bool hasPrev = prevGp_.size() == kGp;
    const QBrush changedFg(ce::gui::editorPalette().error);   // theme-aware red
    const QBrush normalFg = regTable_->palette().text();
    // Update items IN PLACE (never setItem here): this runs from within
    // onRegisterEdited (itemChanged), where replacing an item would delete the
    // one whose setText is still on the stack (use-after-free). Block signals so
    // these programmatic fills aren't re-interpreted as user edits.
    regTable_->blockSignals(true);
    for (int i = 0; i < kGp; ++i) {
        auto* it = regTable_->item(i, 0);
        if (!it) {
            it = new QTableWidgetItem();
            it->setFlags(it->flags() | Qt::ItemIsEditable);
            regTable_->setItem(i, 0, it);
        }
        it->setText(hex(vals[i]));
        it->setForeground(hasPrev && prevGp_[i] != vals[i] ? changedFg : normalFg);
    }
    prevGp_.assign(vals, vals + kGp);
    if (flagsLabel_) {
        // Show every status flag's 0/1 state (CE-style), not just the set ones, so a
        // clear flag next to a conditional jump is still readable.
        flagsLabel_->setText(QStringLiteral("Flags: ") +
                             QString::fromStdString(ce::describeEflagsVerbose(c.rflags)));
    }
    // XMM0-15, view-only, shown as the 128-bit value (most-significant byte first).
    // Same change highlight as the GP regs (a movss/paddd etc. lights up its dest).
    auto xmm = session_->getXmmRegisters();
    for (int r = 0; r < 16; ++r) {
        auto* it = regTable_->item(10 + r, 0);
        if (!it) {
            it = new QTableWidgetItem();
            it->setFlags(it->flags() & ~Qt::ItemIsEditable);
            regTable_->setItem(10 + r, 0, it);
        }
        QString s;
        for (int b = 15; b >= 0; --b) s += QString::asprintf("%02x", xmm[r][b]);
        it->setText(s);
        it->setForeground(hasPrev && xmm[r] != prevXmm_[r] ? changedFg : normalFg);
    }
    prevXmm_ = xmm;
    regTable_->blockSignals(false);
}

bool DebuggerWindow::anyRegisterChangedHighlightForTest() const {
    if (!regTable_) return false;
    const QColor red = ce::gui::editorPalette().error;
    for (int i = 0; i < 10; ++i)
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
    if (!session_->isAttached() || !session_->isStopped()) return;

    QString t = item->text().trimmed();
    if (t.startsWith("0x") || t.startsWith("0X")) t = t.mid(2);
    bool okParse = false;
    const qulonglong v = t.toULongLong(&okParse, 16);
    if (okParse) {
        ce::CpuContext ctx = session_->getStopContext();
        switch (item->row()) {
            case 0: ctx.rip = v; break;
            case 1: ctx.rsp = v; break;
            case 2: ctx.rbp = v; break;
            case 3: ctx.rax = v; break;
            case 4: ctx.rbx = v; break;
            case 5: ctx.rcx = v; break;
            case 6: ctx.rdx = v; break;
            case 7: ctx.rsi = v; break;
            case 8: ctx.rdi = v; break;
            case 9: ctx.rflags = v; break;
            default: return;
        }
        session_->setStopContext(ctx);
    }
    updateRegisters(session_->getStopContext());
}

bool DebuggerWindow::pokeRegisterForTest(int row, uint64_t value) {
    if (!regTable_ || !session_ || !session_->isStopped()) return false;
    if (row < 0 || row >= 10) return false;
    auto* it = regTable_->item(row, 0);
    if (!it) return false;
    it->setText(hex(value));   // fires itemChanged -> onRegisterEdited -> setStopContext
    const ce::CpuContext c = session_->getStopContext();
    const uint64_t got[] = {c.rip, c.rsp, c.rbp, c.rax, c.rbx,
                            c.rcx, c.rdx, c.rsi, c.rdi, c.rflags};
    return got[row] == value;
}

void DebuggerWindow::updateDisassembly(const ce::CpuContext& c) {
    // Remember which instruction the caret was on, so re-rendering (a breakpoint toggle,
    // a step, an auto-refresh) keeps it there instead of jerking it to the top.
    uintptr_t caretAddr = 0;
    if (int blk = disasmView_->textCursor().blockNumber();
        blk >= 0 && blk < static_cast<int>(disasmLineAddrs_.size()))
        caretAddr = disasmLineAddrs_[blk];
    disasmLineAddrs_.clear();
    if (proc_ && !symbolsLoaded_) { resolver_.loadProcess(*proc_); symbolsLoaded_ = true; }
    if (modules_.empty() && proc_) modules_ = proc_->modules();   // for data-operand annotations
    uint8_t buf[128];
    auto rr = proc_->read(c.rip, buf, sizeof(buf));
    QString out;
    int currentLineBlock = -1;   // text block index of the "=>" line, for the highlight
    if (rr && *rr > 0) {
        // Un-mask any planted software breakpoints in this window so the paused code
        // disassembles as its real instructions instead of int3 (0xCC) — otherwise the
        // 0xCC replacing an instruction's first byte desyncs the whole disassembly.
        const size_t nread = *rr;
        for (const auto& b : bps_)
            if (!b.hardware && b.hasOrig && b.addr >= c.rip && b.addr < c.rip + nread)
                buf[b.addr - c.rip] = b.origByte;
        auto insns = disasm_.disassemble(c.rip, {buf, *rr}, 24);
        for (auto& in : insns) {
            if (in.address == c.rip) currentLineBlock = static_cast<int>(disasmLineAddrs_.size());
            bool isBp = false;
            for (auto& b : bps_) if (b.addr == in.address) isBp = true;
            QString marker = (in.address == c.rip) ? "=> " : "   ";
            QString bpMark = isBp ? "*" : " ";
            // Symbol annotation (CE-style), inline so it never shifts the line/address
            // mapping: a direct call/jmp shows its target's symbol; the current line
            // shows the function it is stopped in.
            std::string sym;
            const bool branch = in.mnemonic == "call" || in.mnemonic == "jmp" ||
                                (in.mnemonic.size() > 1 && in.mnemonic[0] == 'j');
            if (branch && in.operands.find('[') == std::string::npos) {
                if (auto pos = in.operands.find("0x"); pos != std::string::npos) {
                    try {
                        auto t = static_cast<uintptr_t>(std::stoull(in.operands.substr(pos + 2), nullptr, 16));
                        sym = resolver_.resolve(t);
                    } catch (...) {}
                }
            }
            if (sym.empty() && in.address == c.rip) sym = resolver_.resolve(in.address);
            QString anno = sym.empty() ? QString() : QStringLiteral("   ; %1").arg(QString::fromStdString(sym));
            // Data reference: the disassembler resolves a memory operand to its effective
            // address (in.ripTarget). Annotate it with the symbol / module+offset it points
            // at and the value there, so you can see which global the paused code touches
            // and what it holds (a printable target shows as a string).
            if (anno.isEmpty() && !branch && in.ripTarget) {
                const uintptr_t eff = in.ripTarget;
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
            if (in.address == c.rip && in.mnemonic != "jmp") {
                if (auto jt = ce::conditionalJumpTaken(in.mnemonic, c.rflags))
                    anno += *jt ? QStringLiteral("   (will jump)") : QStringLiteral("   (no jump)");
            }
            out += QStringLiteral("%1%2%3  %4 %5%6\n")
                       .arg(marker, bpMark, hex(in.address),
                            QString::fromStdString(in.mnemonic),
                            QString::fromStdString(in.operands), anno);
            disasmLineAddrs_.push_back(in.address);
        }
    } else {
        out = "  <unable to read code at " + hex(c.rip) + ">";
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
    for (int i = 0; i < 16; ++i) {
        uintptr_t slotAddr = c.rsp + static_cast<uintptr_t>(i) * 8;
        uint64_t val = 0;
        auto rr = proc_->read(slotAddr, &val, sizeof(val));
        if (rr && *rr == sizeof(val)) {
            std::string anno = resolver_.resolve(static_cast<uintptr_t>(val));
            if (anno.empty()) anno = ce::moduleOffsetString(modules_, static_cast<uintptr_t>(val));
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
            if (bps_[i].hardware) session_->removeHardwareBreakpoint(bps_[i].id);
            else                  session_->removeSoftwareBreakpoint(bps_[i].id);
            bps_.erase(bps_.begin() + i);
            delete bpList_->takeItem(static_cast<int>(i));
            if (session_->isStopped()) updateDisassembly(session_->getStopContext());
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
    if (!proc_ || !session_->isStopped()) return;
    ce::nopInstruction(*proc_, currentCursorAddress());
    updateDisassembly(session_->getStopContext());   // show the NOPs
}

void DebuggerWindow::onDisasmContextMenu(const QPoint& pos) {
    // Move the caret to the clicked line so currentCursorAddress() targets it.
    disasmView_->setTextCursor(disasmView_->cursorForPosition(pos));
    QMenu menu(this);
    menu.addAction("Set breakpoint here", this, &DebuggerWindow::setBreakpointAtCursor);
    menu.addAction("Set conditional breakpoint...", this, &DebuggerWindow::setConditionalBreakpointAtCursor);
    menu.addAction("Replace with NOPs",  this, &DebuggerWindow::nopInstructionAtCursor);
    menu.addSeparator();
    // Run to this line (CE's F4): only meaningful while the target is paused.
    QAction* rtc = menu.addAction("Run to cursor", this, &DebuggerWindow::onRunToCursor);
    rtc->setEnabled(session_ && session_->isStopped());
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
