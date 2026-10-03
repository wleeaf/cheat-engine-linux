#pragma once

#include "core/autoasm.hpp"
#include "core/aa_templates.hpp"
#include "platform/process_api.hpp"

#include <QMainWindow>
#include <QPlainTextEdit>
#include <functional>
#include <QTextEdit>
#include <QAction>

namespace ce::gui {

class ScriptEditor : public QMainWindow {
    Q_OBJECT
public:
    explicit ScriptEditor(ce::ProcessHandle* proc, ce::AutoAssembler* autoAsm, QWidget* parent = nullptr);

    void setScript(const std::string& script);
    void setInjectionAddress(uintptr_t address, size_t size = 5) { injectionAddress_ = address; injectionSize_ = size; }
    /// Hook to add the current script to the cheat table as a toggleable entry
    /// (MainWindow owns the address list).
    void setAddToTable(std::function<void(const QString& desc, const QString& script)> fn) {
        addToTable_ = std::move(fn);
        if (addTableBtn_) addTableBtn_->setEnabled(static_cast<bool>(addToTable_));
    }
    /// Pre-fill the description prompt shown by "Add to Cheat Table" (defaults to
    /// "Auto Assembler script"). When editing an existing entry, pass its name.
    void setDefaultDescription(const QString& d) { defaultDescription_ = d; }
    /// Relabel the add/save button (e.g. "Save to Table" when editing in place).
    void setTableButtonText(const QString& t);
    /// Called just before Execute/Disable so the owner can release debugger traces
    /// that would block the injection's ptrace attach.
    void setBeforeExecute(std::function<void()> fn) { beforeExecute_ = std::move(fn); }

private slots:
    void onExecute();
    void onDisable();
    void onCheck();
    void onGenerateCodeInjection();
    void onAddToTable();

private:
    void onGenerateInjection(ce::InjectionKind kind);
    uintptr_t injectionAddress_ = 0;
    size_t injectionSize_ = 5;
    ce::ProcessHandle* proc_;
    ce::AutoAssembler* autoAsm_;
    QPlainTextEdit* editor_;
    QTextEdit* output_;
    QAction* executeBtn_;
    QAction* disableBtn_;
    QAction* addTableBtn_ = nullptr;
    ce::DisableInfo lastDisableInfo_;
    bool enabled_ = false;
    QString defaultDescription_ = "Auto Assembler script";
    std::function<void(const QString&, const QString&)> addToTable_;
    std::function<void()> beforeExecute_;
};

} // namespace ce::gui
