#pragma once
/// Find Statics window — runs CodeAnalyzer::findStatics on a chosen module
/// and presents the most-referenced static addresses in a sortable table.
/// Equivalent of CE's frmFindstaticsUnit.

#include "platform/process_api.hpp"
#include "analysis/code_analysis.hpp"
#include "symbols/elf_symbols.hpp"

#include <QMainWindow>
#include <QTableWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>

namespace ce::gui {

class FindStaticsWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit FindStaticsWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

private slots:
    void onScan();

private:
    ce::ProcessHandle* proc_;
    ce::CodeAnalyzer analyzer_;
    ce::SymbolResolver resolver_;
    bool symbolsLoaded_ = false;

    QComboBox*    moduleCombo_;
    QPushButton*  scanBtn_;
    QLabel*       statusLabel_;
    QTableWidget* table_;
};

} // namespace ce::gui
