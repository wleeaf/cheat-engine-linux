#pragma once
#include "scanner/pointer_scanner.hpp"
#include "platform/process_api.hpp"
#include <QDialog>
#include <QTableWidget>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>

namespace ce::gui {

class PointerScanDialog : public QDialog {
    Q_OBJECT
public:
    explicit PointerScanDialog(ce::ProcessHandle* proc, QWidget* parent = nullptr);

signals:
    void addressSelected(uintptr_t addr, const QString& description);

private slots:
    void onScan();
    void onRescan();
    void onSave();
    void onLoad();
    void onResultDoubleClicked(int row, int col);

private:
    void populateResults();

    ce::ProcessHandle* proc_;
    QLineEdit* targetEdit_;
    QSpinBox* depthSpin_;
    QSpinBox* offsetSpin_;
    QPushButton* scanBtn_;
    QPushButton* rescanBtn_;
    QPushButton* saveBtn_;
    QPushButton* loadBtn_;
    QLabel* statusLabel_;
    QTableWidget* resultsTable_;
    std::vector<ce::PointerPath> results_;
};

} // namespace ce::gui
