#pragma once
#include "scanner/pointer_scanner.hpp"
#include "platform/process_api.hpp"
#include <QDialog>
#include <QTableWidget>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QTimer>

#include <atomic>
#include <memory>
#include <thread>

namespace ce::gui {

class PointerScanDialog : public QDialog {
    Q_OBJECT
public:
    explicit PointerScanDialog(ce::ProcessHandle* proc, QWidget* parent = nullptr);
    ~PointerScanDialog() override;
    /// Pre-fill the address to find pointer paths to (e.g. a cheat table entry's).
    void setTargetAddress(uintptr_t address) {
        targetEdit_->setText(QString("0x%1").arg(static_cast<qulonglong>(address), 0, 16));
    }

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
    void finishScan();

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
    // The scan runs on a worker so the window (and the main window's freeze
    // timer) keeps running; Scan becomes Cancel meanwhile.
    std::unique_ptr<ce::PointerScanner> scanner_;
    std::thread worker_;
    std::atomic<bool> scanDone_{false};
    std::vector<ce::PointerPath> scanned_;
    QTimer* scanPoll_ = nullptr;
};

} // namespace ce::gui
