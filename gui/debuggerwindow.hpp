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
#include <atomic>

class QLineEdit;
class QPlainTextEdit;
class QTableWidget;
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
    void addBreakpointAt(uintptr_t addr);

    // Accessors for automation/smoke tests.
    bool debugAttached() const { return session_ && session_->isAttached(); }
    bool debugStopped() const { return session_ && session_->isStopped(); }
    uintptr_t currentStopRip() const { return lastStopRip_; }

private slots:
    void onContinue();
    void onStepInto();
    void onStepOver();
    void onStepOut();
    void onRunToCursor();
    void onDetach();
    void onAddBreakpoint();
    void onRemoveBreakpoint();
    void onDebugEvent(int type);   // marshalled from the tracer thread

private:
    void refreshStopped();
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
    QTableWidget* regTable_ = nullptr;
    QPlainTextEdit* stackView_ = nullptr;
    QLineEdit* bpInput_ = nullptr;
    QListWidget* bpList_ = nullptr;
    QPushButton* contBtn_ = nullptr;
    QPushButton* intoBtn_ = nullptr;
    QPushButton* overBtn_ = nullptr;
    QPushButton* outBtn_ = nullptr;
    QPushButton* rtcBtn_ = nullptr;
    QPushButton* detachBtn_ = nullptr;

    struct Bp { int id; uintptr_t addr; };
    std::vector<Bp> bps_;
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
