#pragma once
// Advanced Options — Cheat Engine's AdvancedOptionsUnit ("Code list/Pause"): a
// persistent list of code addresses (from "find what writes/accesses", or added
// by hand) with a context menu to disassemble / NOP / restore / rename / remove.

#include "platform/process_api.hpp"
#include <QMainWindow>
#include <QTableWidget>
#include <cstdint>
#include <map>
#include <vector>

namespace ce::gui {

class AdvancedOptionsWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit AdvancedOptionsWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

    void setProcess(ce::ProcessHandle* proc) { proc_ = proc; }
    /// Add a code address to the list (deduped). Used by find-what-writes results.
    void addCode(uintptr_t addr, const QString& name);

signals:
    void navigateTo(uintptr_t addr);   // "Open the disassembler at this location"

private:
    void showContextMenu(const QPoint& pos);
    uintptr_t addressAtRow(int row) const;
    int selectedRow() const;

    ce::ProcessHandle* proc_;
    QTableWidget* table_;
    std::map<uintptr_t, std::vector<uint8_t>> nopOriginals_;  // for "Restore original code"
};

}  // namespace ce::gui
