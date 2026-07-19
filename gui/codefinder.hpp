#pragma once
#include "debug/code_finder.hpp"
#include "symbols/elf_symbols.hpp"
#include <QMainWindow>
#include <QTableWidget>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <functional>
#include <map>
#include <vector>
#include <cstdint>

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

    /// Hook to open the Memory Viewer's disassembler at an instruction address (CE's
    /// "Show this address in the disassembler"). MainWindow wires it to openMemoryView.
    using ShowFn = std::function<void(uintptr_t addr)>;
    void setShowInDisassembler(ShowFn fn) { showInDisasm_ = std::move(fn); }

    // Test hooks (headless): NOP the instruction at `addr` (returns true if patched);
    // restore its original bytes; fire the show hook; read a row's displayed address.
    bool nopInstructionForTest(uintptr_t addr) { return nopInstructionAt(addr); }
    bool restoreInstructionForTest(uintptr_t addr) { return restoreInstructionAt(addr); }
    void showInDisassemblerForTest(uintptr_t addr) { if (showInDisasm_) showInDisasm_(addr); }
    uintptr_t rowAddressForTest(int row) const { return addressOfRow(row); }

private slots:
    void refresh();
    void onStop();

private:
    void onAddToList();       // add selected (or all) rows to the address list
    void onExportToFile();    // write the findings to a text report
    void onContextMenu(const QPoint& pos);   // per-result right-click actions
    uintptr_t addressOfRow(int row) const;   // the (recovered) address shown in column 0
    bool nopInstructionAt(uintptr_t addr);   // overwrite the instruction with NOPs
    bool restoreInstructionAt(uintptr_t addr);   // write the saved original bytes back

    ce::CodeFinder* finder_;
    ce::ProcessHandle* proc_ = nullptr;   // for exact-store recovery (may be null)
    ce::SymbolResolver symbols_;          // enclosing-function anchor for recovery
    QTableWidget* table_;
    QLabel* statusLabel_;
    QPushButton* stopBtn_;
    QPushButton* saveBtn_;
    QTimer* refreshTimer_;
    AddToListFn addToList_;
    ShowFn showInDisasm_;
    std::map<uintptr_t, std::vector<uint8_t>> noppedOriginals_;  // NOPped addr -> original bytes
};

} // namespace ce::gui
