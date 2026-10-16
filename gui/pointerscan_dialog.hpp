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
#include <functional>
#include <memory>
#include <string>
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
    /// Keep only the paths that now lead to `newTarget`. Runs on the worker like
    /// a scan; Rescan asks for the address and calls this.
    void rescanTo(uintptr_t newTarget);

signals:
    void addressSelected(uintptr_t addr, const QString& description);

private slots:
    void onScan();
    void onRescan();
    void onSave();
    void onLoad();
    void onResultDoubleClicked(int row, int col);

private:
    enum class Job { None, Scan, Rescan };
    void startJob(Job job, std::function<void()> work);
    void finishJob();
    void finishScan();
    void finishRescan();
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
    // Scans and rescans run on a worker so the window (and the main window's
    // freeze timer) keeps running; Scan becomes Cancel meanwhile.
    Job job_ = Job::None;
    std::unique_ptr<ce::PointerScanner> scanner_;
    std::thread worker_;
    std::atomic<bool> scanDone_{false};
    std::string jobError_;                  // set by the worker, read after join
    std::vector<ce::PointerPath> scanned_;
    std::atomic<bool> rescanCancel_{false};
    std::atomic<float> rescanProgress_{0};
    std::vector<ce::PointerPath> rescanned_;
    uintptr_t rescanTarget_ = 0;
    QTimer* scanPoll_ = nullptr;
};

} // namespace ce::gui
