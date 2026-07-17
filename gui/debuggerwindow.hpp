#pragma once
// Interactive step-debugger window: attach, software breakpoints, and
// continue/step-into/over/out/run-to-cursor over a live (multi-threaded) target,
// driven by ce::DebugSession (all-stop). Debug events fire on the tracer thread
// and are marshalled to the UI thread via a queued invocation.

#include "debug/debug_session.hpp"
#include "arch/disassembler.hpp"
#include "platform/process_api.hpp"
#include <QMainWindow>
#include <memory>
#include <vector>
#include <array>
#include <atomic>

class QLineEdit;
class QPlainTextEdit;
class QTableWidget;
class QTableWidgetItem;
class QComboBox;
class QLabel;
class QListWidget;
class QPushButton;

namespace ce::gui {

class DebuggerWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit DebuggerWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);
    ~DebuggerWindow() override;

    /// Plant a software breakpoint at `addr` (e.g. from the disassembler's
    /// "set breakpoint" action). No-op if not attached.
    void addBreakpointAt(uintptr_t addr, const QString& condition = QString());

    // Accessors for automation/smoke tests.
    bool debugAttached() const { return session_ && session_->isAttached(); }
    bool debugStopped() const { return session_ && session_->isStopped(); }
    uintptr_t currentStopRip() const { return lastStopRip_; }
    // Type `value` into register row `row`'s cell exactly as the UI would (routes
    // through onRegisterEdited -> setStopContext) and report whether the stopped
    // thread's register now holds it. Row order matches the table:
    // 0=RIP 1=RSP 2=RBP 3=RAX 4=RBX 5=RCX 6=RDX 7=RSI 8=RDI 9=RFLAGS.
    bool pokeRegisterForTest(int row, uint64_t value);
    // Thread switcher automation: number of threads in the dropdown, and a helper
    // that picks a different one via the combo (as the user would) and reports
    // whether the session's active thread followed.
    int  threadCount() const;
    bool switchToOtherThreadForTest();
    // Point the memory/hex pane at `addr` and report whether it rendered the
    // bytes actually there (verifies the pane against a fresh read).
    bool memoryViewShowsForTest(uintptr_t addr);
    // Whether the XMM0 register row displays a value whose low 64 bits are `lo`.
    bool xmm0ShowsForTest(uint64_t lo);
    // Move the caret to disasm line `lineIndex` and set a breakpoint there via the
    // same path the right-click menu uses; report whether it was planted.
    bool disasmSetBreakpointForTest(int lineIndex);
    // True if any GP register row currently paints in the "changed" (red) colour,
    // i.e. the last stop's step highlight fired.
    bool anyRegisterChangedHighlightForTest() const;

private slots:
    void onContinue();
    void onStepInto();
    void onStepOver();
    void onStepOut();
    void onRunToCursor();
    void onDetach();
    void onAddBreakpoint();
    void onAddDataBreakpoint();   // hardware watchpoint (break on write/access)
    void onRemoveBreakpoint();
    void onRegisterEdited(QTableWidgetItem* item);  // edit a GP register in place
    void onThreadSelected(int index);               // switch the active thread
    void onMemAddrEntered();                         // point the hex pane at an address
    void onDisasmContextMenu(const QPoint& pos);     // right-click the disassembly
    void onDebugEvent(int type);   // marshalled from the tracer thread

private:
    void refreshStopped();
    void updateThreadList();   // repopulate the thread dropdown at a stop
    void updateMemoryView(uintptr_t addr);   // hex-dump bytes at addr
    void setBreakpointAtCursor();            // disasm menu action
    void setConditionalBreakpointAtCursor(); // disasm menu action (prompts for expr)
    void editBreakpointCondition();          // breakpoint-list action (edit condition)
    void nopInstructionAtCursor();           // disasm menu action
    void updateRegisters(const ce::CpuContext& ctx);
    void updateDisassembly(const ce::CpuContext& ctx);
    void updateStack(const ce::CpuContext& ctx);
    void setRunningUi(bool running, bool exited = false);
    uintptr_t currentCursorAddress() const;   // selected disasm line, else RIP

    ce::ProcessHandle* proc_;
    std::unique_ptr<ce::DebugSession> session_;
    ce::Disassembler disasm_{ce::Arch::X86_64};

    QLabel* statusLabel_ = nullptr;
    QPlainTextEdit* disasmView_ = nullptr;
    QComboBox* threadCombo_ = nullptr;
    QTableWidget* regTable_ = nullptr;
    std::vector<uintptr_t> prevGp_;   // last stop's GP regs, to red-flag changes on step
    std::array<std::array<uint8_t, 16>, 16> prevXmm_{};   // ditto for XMM0-15
    QPlainTextEdit* stackView_ = nullptr;
    QLineEdit* memAddrInput_ = nullptr;
    QPlainTextEdit* memView_ = nullptr;
    uintptr_t lastMemAddr_ = 0;   // address the hex pane is following (0 = none)
    QLineEdit* bpInput_ = nullptr;
    QListWidget* bpList_ = nullptr;
    QPushButton* contBtn_ = nullptr;
    QPushButton* intoBtn_ = nullptr;
    QPushButton* overBtn_ = nullptr;
    QPushButton* outBtn_ = nullptr;
    QPushButton* rtcBtn_ = nullptr;
    QPushButton* detachBtn_ = nullptr;

    struct Bp {
        int id; uintptr_t addr; std::string condition;
        bool hardware = false;   // true = hardware data watchpoint (DR0-3)
        int hwType = 0;          // 1=write, 3=access (data breakpoints only)
        int hwSize = 0;          // 1/2/4/8 bytes
        int hitCount = 0;
        bool enabled = true;
    };
    std::vector<Bp> bps_;
    QString bpRowText(const Bp& b) const;      // list text incl. condition + hit count
    void refreshBpRow(int index);              // rewrite one list row from bps_[index]
    static QString bpLabel(uintptr_t addr, const QString& condition);   // execute-bp list text
    static QString bpDataLabel(uintptr_t addr, int type, int size);     // data-bp list text
    std::vector<uintptr_t> disasmLineAddrs_;   // address per rendered disasm line
    uintptr_t lastStopRip_ = 0;

    // Latest event, published by the tracer-thread callback and read on the UI
    // thread after a queued invocation.
    std::atomic<uintptr_t> lastEvtAddr_{0};
    std::atomic<pid_t> lastEvtTid_{0};
    // Run-to-cursor is a GUI-level temp breakpoint + continue (non-blocking),
    // auto-removed when its address is hit.
    uintptr_t pendingRtcAddr_ = 0;
    int pendingRtcId_ = -1;
};

} // namespace ce::gui
