#include "gui/debuggerwindow.hpp"

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QHeaderView>
#include <QLineEdit>
#include <QListWidget>
#include <QGroupBox>
#include <QSplitter>
#include <QFont>
#include <QFontDatabase>
#include <QTextCursor>

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
    rtcBtn_    = new QPushButton("Run to Cursor");
    detachBtn_ = new QPushButton("Detach");
    for (auto* b : {contBtn_, intoBtn_, overBtn_, outBtn_, rtcBtn_, detachBtn_})
        controls->addWidget(b);
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
    leftSplit->addWidget(disasmView_);
    stackView_ = new QPlainTextEdit();
    stackView_->setReadOnly(true);
    stackView_->setFont(mono);
    stackView_->setLineWrapMode(QPlainTextEdit::NoWrap);
    leftSplit->addWidget(stackView_);
    leftSplit->setStretchFactor(0, 3);
    leftSplit->setStretchFactor(1, 1);
    split->addWidget(leftSplit);

    auto* right = new QWidget();
    auto* rl = new QVBoxLayout(right);
    regTable_ = new QTableWidget(10, 1);
    regTable_->setFont(mono);
    regTable_->horizontalHeader()->setVisible(false);
    regTable_->horizontalHeader()->setStretchLastSection(true);
    regTable_->verticalHeader()->setVisible(true);
    static const char* rnames[] = {"RIP","RSP","RBP","RAX","RBX","RCX","RDX","RSI","RDI","RFLAGS"};
    for (int i = 0; i < 10; ++i)
        regTable_->setVerticalHeaderItem(i, new QTableWidgetItem(rnames[i]));
    rl->addWidget(regTable_, 3);

    auto* bpGroup = new QGroupBox("Breakpoints");
    auto* bl = new QVBoxLayout(bpGroup);
    auto* addRow = new QHBoxLayout();
    bpInput_ = new QLineEdit();
    bpInput_->setPlaceholderText("address (hex), then Add");
    auto* addBtn = new QPushButton("Add");
    addRow->addWidget(bpInput_);
    addRow->addWidget(addBtn);
    bl->addLayout(addRow);
    bpList_ = new QListWidget();
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
    connect(rmBtn,      &QPushButton::clicked, this, &DebuggerWindow::onRemoveBreakpoint);
    connect(bpInput_,   &QLineEdit::returnPressed, this, &DebuggerWindow::onAddBreakpoint);

    // Debug events fire on the tracer thread; publish the event and marshal a
    // refresh onto the UI thread.
    session_->setEventCallback([this](const ce::DebugEvent& e) {
        lastEvtAddr_.store(e.address);
        lastEvtTid_.store(e.tid);
        int t = static_cast<int>(e.type);
        QMetaObject::invokeMethod(this, [this, t] { onDebugEvent(t); }, Qt::QueuedConnection);
    });

    if (proc_ && session_->attach(proc_->pid(), proc_)) {
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

void DebuggerWindow::addBreakpointAt(uintptr_t addr) {
    if (!session_->isAttached() || !session_->isStopped()) {
        statusLabel_->setText("Stop the target before setting a breakpoint");
        return;
    }
    for (auto& b : bps_) if (b.addr == addr) return;   // already set
    int id = session_->setSoftwareBreakpoint(addr);
    if (id <= 0) { statusLabel_->setText("Failed to set breakpoint at " + hex(addr)); return; }
    bps_.push_back({id, addr});
    bpList_->addItem(hex(addr));
    if (session_->isStopped()) updateDisassembly(session_->getStopContext());
}

void DebuggerWindow::onRemoveBreakpoint() {
    int row = bpList_->currentRow();
    if (row < 0 || row >= static_cast<int>(bps_.size())) return;
    session_->removeSoftwareBreakpoint(bps_[row].id);
    bps_.erase(bps_.begin() + row);
    delete bpList_->takeItem(row);
    if (session_->isStopped()) updateDisassembly(session_->getStopContext());
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
    refreshStopped();
}

void DebuggerWindow::refreshStopped() {
    if (!session_->isAttached()) return;
    auto ctx = session_->getStopContext();
    lastStopRip_ = ctx.rip;
    updateRegisters(ctx);
    updateDisassembly(ctx);
    updateStack(ctx);
    statusLabel_->setText(QStringLiteral("Stopped at %1 (tid %2)")
                              .arg(hex(ctx.rip)).arg(static_cast<int>(lastEvtTid_.load())));
    setRunningUi(false);
}

void DebuggerWindow::updateRegisters(const ce::CpuContext& c) {
    const uintptr_t vals[] = {c.rip, c.rsp, c.rbp, c.rax, c.rbx, c.rcx, c.rdx, c.rsi, c.rdi, c.rflags};
    for (int i = 0; i < 10; ++i)
        regTable_->setItem(i, 0, new QTableWidgetItem(hex(vals[i])));
}

void DebuggerWindow::updateDisassembly(const ce::CpuContext& c) {
    disasmLineAddrs_.clear();
    uint8_t buf[128];
    auto rr = proc_->read(c.rip, buf, sizeof(buf));
    QString out;
    if (rr && *rr > 0) {
        auto insns = disasm_.disassemble(c.rip, {buf, *rr}, 24);
        for (auto& in : insns) {
            bool isBp = false;
            for (auto& b : bps_) if (b.addr == in.address) isBp = true;
            QString marker = (in.address == c.rip) ? "=> " : "   ";
            QString bpMark = isBp ? "*" : " ";
            out += QStringLiteral("%1%2%3  %4 %5\n")
                       .arg(marker, bpMark, hex(in.address),
                            QString::fromStdString(in.mnemonic),
                            QString::fromStdString(in.operands));
            disasmLineAddrs_.push_back(in.address);
        }
    } else {
        out = "  <unable to read code at " + hex(c.rip) + ">";
    }
    disasmView_->setPlainText(out);
}

void DebuggerWindow::updateStack(const ce::CpuContext& c) {
    QString out;
    for (int i = 0; i < 16; ++i) {
        uintptr_t slotAddr = c.rsp + static_cast<uintptr_t>(i) * 8;
        uint64_t val = 0;
        auto rr = proc_->read(slotAddr, &val, sizeof(val));
        if (rr && *rr == sizeof(val))
            out += QStringLiteral("%1: %2\n").arg(hex(slotAddr), hex(val));
        else
            out += QStringLiteral("%1: ??\n").arg(hex(slotAddr));
    }
    stackView_->setPlainText(out);
}

uintptr_t DebuggerWindow::currentCursorAddress() const {
    int block = disasmView_->textCursor().blockNumber();
    if (block >= 0 && block < static_cast<int>(disasmLineAddrs_.size()))
        return disasmLineAddrs_[block];
    return lastStopRip_;
}

} // namespace ce::gui
