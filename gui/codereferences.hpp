#pragma once

#include "analysis/code_analysis.hpp"
#include "platform/process_api.hpp"
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QSpinBox>
#include <QTableWidget>

namespace ce::gui {

class CodeReferencesWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit CodeReferencesWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

signals:
    void navigateTo(uintptr_t addr);

private:
    void analyzeSelectedModule();
    void fillTable(QTableWidget* table, const std::vector<ce::CodeRef>& refs);
    void fillFunctionsTable(const std::vector<ce::FunctionInfo>& functions);
    void fillCallGraphTable(const std::vector<ce::CallGraphEdge>& graph);
    void fillCavesTable(const std::vector<ce::CodeCave>& caves);
    ce::ModuleInfo selectedModule() const;

    ce::ProcessHandle* proc_;
    std::vector<ce::ModuleInfo> modules_;
    QComboBox* moduleCombo_;
    QLabel* statusLabel_;
    QSpinBox* minCaveSizeSpin_;
    QLineEdit* assemblyPatternEdit_;
    QTableWidget* stringsTable_;
    QTableWidget* functionsTable_;
    QTableWidget* functionSummaryTable_;
    QTableWidget* callGraphTable_;
    QTableWidget* jumpsTable_;
    QTableWidget* ripRelativeTable_;
    QTableWidget* assemblyTable_;
    QTableWidget* cavesTable_;
};

} // namespace ce::gui
