#pragma once
/// Break-and-trace window — wraps debug/tracer.{cpp,hpp} in a Qt UI.

#include "debug/tracer.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/process_api.hpp"

#include <QMainWindow>
#include <QTableView>
#include <QAbstractTableModel>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QPushButton>
#include <QProgressBar>
#include <QLabel>
#include <functional>
#include <climits>
#include <algorithm>
#include <thread>
#include <atomic>
#include <memory>
#include <string>

extern "C" { struct lua_State; }

namespace ce::gui {

// The steps of a trace, read straight from the entries: a million-step trace
// must not become eight million table items built on the GUI thread.
class TraceTableModel : public QAbstractTableModel {
public:
    explicit TraceTableModel(const std::vector<ce::TraceEntry>* entries, QObject* parent = nullptr)
        : QAbstractTableModel(parent), entries_(entries) {}
    int rowCount(const QModelIndex& parent = {}) const override {
        return parent.isValid() ? 0 : static_cast<int>(std::min<size_t>(entries_->size(), INT_MAX));
    }
    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 8; }
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    void reload() { beginResetModel(); endResetModel(); }

private:
    const std::vector<ce::TraceEntry>* entries_;
};

/// A Lua expression on the registers (RAX, EAX, RIP, X0, ...), as Cheat
/// Engine's trace conditions are written: "RAX == 5 and RCX > 0x100".
/// Evaluated on one thread at a time; its own Lua state, nothing else in it.
class RegisterCondition {
public:
    RegisterCondition() = default;
    RegisterCondition(const RegisterCondition&) = delete;
    RegisterCondition& operator=(const RegisterCondition&) = delete;
    ~RegisterCondition();
    /// Compiles `expression`; returns the error text, or an empty string.
    std::string compile(const std::string& expression);
    /// True when the expression is true for `context` (an error counts as false).
    bool operator()(const ce::CpuContext& context);

private:
    lua_State* lua_ = nullptr;
    int function_ = -1;
};

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
    friend class TraceTableModel;
    void buildUi();
    static QString hexQ(uint64_t v);

    ce::ProcessHandle* proc_;
    DebuggerFactory debuggerFactory_;
    ce::Tracer tracer_;
    std::unique_ptr<ce::Debugger> debugger_;
    std::thread worker_;
    std::vector<ce::TraceEntry> entries_;
    std::shared_ptr<RegisterCondition> startCondition_, stopCondition_;

    // Inputs
    QLineEdit* startAddressEdit_;
    QSpinBox* maxStepsSpin_;
    QCheckBox* stepOverCheck_;
    QCheckBox* stayInModuleCheck_;
    QLineEdit* moduleStartEdit_;
    QLineEdit* moduleEndEdit_;
    QLineEdit* stopAddressEdit_;
    QLineEdit* startConditionEdit_;
    QLineEdit* stopConditionEdit_;
    QCheckBox* stepOverRepCheck_;
    QCheckBox* skipSystemCheck_;
    QCheckBox* dereferenceCheck_;
    QCheckBox* saveStackCheck_;

    // Controls
    QPushButton* startBtn_;
    QPushButton* cancelBtn_;
    QPushButton* saveBtn_;
    QProgressBar* progressBar_;
    QLabel* statusLabel_;

    QTableView* table_;
    TraceTableModel* model_ = nullptr;
};

} // namespace ce::gui
