#pragma once
#include "debug/code_finder.hpp"
#include "symbols/elf_symbols.hpp"
#include <QMainWindow>
#include <QTableWidget>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <functional>

namespace ce::gui {

class CodeFinderWindow : public QMainWindow {
    Q_OBJECT
public:
    // `proc` (optional) lets the window recover the exact store instruction for a
    // hardware watchpoint (whose trap fires one instruction past the writer).
    explicit CodeFinderWindow(ce::CodeFinder* finder, const QString& title,
                              ce::ProcessHandle* proc = nullptr, QWidget* parent = nullptr);

    /// Hook to add a found instruction address (with a description) to the main
    /// address list, so the user can keep the code locations that touch an address.
    using AddToListFn = std::function<void(uintptr_t addr, const QString& desc)>;
    void setAddToList(AddToListFn fn) { addToList_ = std::move(fn); }

private slots:
    void refresh();
    void onStop();

private:
    void onAddToList();       // add selected (or all) rows to the address list
    void onExportToFile();    // write the findings to a text report

    ce::CodeFinder* finder_;
    ce::ProcessHandle* proc_ = nullptr;   // for exact-store recovery (may be null)
    ce::SymbolResolver symbols_;          // enclosing-function anchor for recovery
    QTableWidget* table_;
    QLabel* statusLabel_;
    QPushButton* stopBtn_;
    QPushButton* saveBtn_;
    QTimer* refreshTimer_;
    AddToListFn addToList_;
};

} // namespace ce::gui
