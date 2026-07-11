#pragma once
/// Break-and-trace window — wraps debug/tracer.{cpp,hpp} in a Qt UI.

#include "debug/tracer.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/process_api.hpp"

#include <QMainWindow>
#include <QTableWidget>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <functional>
#include <thread>
#include <atomic>

namespace ce::gui {

class TracerWindow : public QMainWindow {
    Q_OBJECT
public:
    using DebuggerFactory = std::function<std::unique_ptr<ce::Debugger>()>;

    /// `factory` builds a fresh Debugger each time the user starts a trace.
    /// MainWindow returns LinuxDebugger for local processes and
    /// RemoteDebugger when a ceserver target is attached.
    explicit TracerWindow(ce::ProcessHandle* proc,
                          DebuggerFactory factory,
                          QWidget* parent = nullptr);
    ~TracerWindow() override;

private slots:
    void onStart();
    void onCancel();
    void onSave();
    void onTraceFinished();

private:
    void buildUi();
    static QString hexQ(uint64_t v);

    ce::ProcessHandle* proc_;
    DebuggerFactory debuggerFactory_;
    ce::Tracer tracer_;
    std::unique_ptr<ce::Debugger> debugger_;
    std::thread worker_;
    std::vector<ce::TraceEntry> entries_;

    // Inputs
    QLineEdit* startAddressEdit_;
    QSpinBox* maxStepsSpin_;
    QCheckBox* stepOverCheck_;
    QCheckBox* stayInModuleCheck_;
    QLineEdit* moduleStartEdit_;
    QLineEdit* moduleEndEdit_;
    QLineEdit* stopAddressEdit_;

    // Controls
    QPushButton* startBtn_;
    QPushButton* cancelBtn_;
    QPushButton* saveBtn_;
    QProgressBar* progressBar_;
    QLabel* statusLabel_;

    QTableWidget* table_;
};

} // namespace ce::gui
