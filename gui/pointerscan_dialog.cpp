#include "gui/pointerscan_dialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFont>
#include <QInputDialog>
#include <QFileDialog>
#include <QMessageBox>

namespace ce::gui {

PointerScanDialog::PointerScanDialog(ProcessHandle* proc, QWidget* parent)
    : QDialog(parent), proc_(proc) {
    setWindowTitle("Pointer Scanner");
    resize(700, 500);

    auto* layout = new QVBoxLayout(this);

    // Config row
    auto* configRow = new QHBoxLayout;
    configRow->addWidget(new QLabel("Target Address:"));
    targetEdit_ = new QLineEdit;
    targetEdit_->setFont(QFont("Monospace", 10));
    targetEdit_->setPlaceholderText("0x7f1234");
    configRow->addWidget(targetEdit_);

    configRow->addWidget(new QLabel("Depth:"));
    depthSpin_ = new QSpinBox;
    depthSpin_->setRange(1, 7);
    depthSpin_->setValue(4);
    configRow->addWidget(depthSpin_);

    configRow->addWidget(new QLabel("Max Offset:"));
    offsetSpin_ = new QSpinBox;
    offsetSpin_->setRange(64, 65536);
    offsetSpin_->setValue(2048);
    offsetSpin_->setSingleStep(256);
    configRow->addWidget(offsetSpin_);

    scanBtn_ = new QPushButton("Scan");
    scanBtn_->setStyleSheet("font-weight: bold;");
    connect(scanBtn_, &QPushButton::clicked, this, &PointerScanDialog::onScan);
    configRow->addWidget(scanBtn_);

    // Rescan filters the current paths against a new target address (after the
    // dynamic value has moved) — the key to finding a stable pointer path.
    rescanBtn_ = new QPushButton("Rescan…");
    rescanBtn_->setToolTip("Filter current paths to those that still point at a new target address");
    rescanBtn_->setEnabled(false);
    connect(rescanBtn_, &QPushButton::clicked, this, &PointerScanDialog::onRescan);
    configRow->addWidget(rescanBtn_);

    saveBtn_ = new QPushButton("Save…");
    saveBtn_->setEnabled(false);
    connect(saveBtn_, &QPushButton::clicked, this, &PointerScanDialog::onSave);
    configRow->addWidget(saveBtn_);

    loadBtn_ = new QPushButton("Load…");
    connect(loadBtn_, &QPushButton::clicked, this, &PointerScanDialog::onLoad);
    configRow->addWidget(loadBtn_);
    layout->addLayout(configRow);

    statusLabel_ = new QLabel("Ready");
    layout->addWidget(statusLabel_);

    // Results table
    resultsTable_ = new QTableWidget;
    resultsTable_->setColumnCount(3);
    resultsTable_->setHorizontalHeaderLabels({"Path", "Current Address", "Value"});
    resultsTable_->horizontalHeader()->setStretchLastSection(true);
    resultsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable_->setFont(QFont("Monospace", 9));
    resultsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(resultsTable_, &QTableWidget::cellDoubleClicked, this, &PointerScanDialog::onResultDoubleClicked);
    layout->addWidget(resultsTable_);
}

void PointerScanDialog::onScan() {
    if (!proc_) return;

    bool ok;
    uintptr_t target = targetEdit_->text().toULongLong(&ok, 16);
    if (!ok) { statusLabel_->setText("Invalid address"); return; }

    scanBtn_->setEnabled(false);
    statusLabel_->setText("Scanning...");
    resultsTable_->setRowCount(0);

    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = depthSpin_->value();
    config.maxOffset = offsetSpin_->value();

    PointerScanner scanner;
    results_ = scanner.scan(*proc_, config);

    populateResults();
    statusLabel_->setText(QString("Found %1 paths").arg(results_.size()));
    scanBtn_->setEnabled(true);
}

void PointerScanDialog::populateResults() {
    size_t shown = std::min(results_.size(), size_t(1000));
    resultsTable_->setRowCount((int)shown);
    for (size_t i = 0; i < shown; ++i) {
        auto& p = results_[i];
        resultsTable_->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(p.toString())));
        auto addr = PointerScanner::dereference(*proc_, p);
        resultsTable_->setItem(i, 1, new QTableWidgetItem(
            addr ? QString("0x%1").arg(addr, 0, 16) : "??"));
        if (addr) {
            int32_t val = 0;
            auto vr = proc_->read(addr, &val, 4);
            resultsTable_->setItem(i, 2, new QTableWidgetItem(
                (vr && *vr == 4) ? QString::number(val) : QStringLiteral("??")));
        }
    }
    bool have = !results_.empty();
    rescanBtn_->setEnabled(have);
    saveBtn_->setEnabled(have);
}

void PointerScanDialog::onRescan() {
    if (!proc_ || results_.empty()) return;
    bool ok = false;
    QString text = QInputDialog::getText(this, "Rescan pointer paths",
        "New target address (hex) the paths should now resolve to:",
        QLineEdit::Normal, targetEdit_->text(), &ok);
    if (!ok) return;
    uintptr_t newTarget = text.toULongLong(&ok, 16);
    if (!ok || !newTarget) { statusLabel_->setText("Invalid address"); return; }

    size_t before = results_.size();
    results_ = ce::rescanPointerPaths(*proc_, results_, newTarget);
    targetEdit_->setText(QString("0x%1").arg(newTarget, 0, 16));
    populateResults();
    statusLabel_->setText(QString("Rescan: %1 → %2 paths still reach 0x%3")
        .arg(before).arg(results_.size()).arg(newTarget, 0, 16));
}

void PointerScanDialog::onSave() {
    if (results_.empty()) return;
    auto path = QFileDialog::getSaveFileName(this, "Save pointer paths", "pointers.ptr",
        "Pointer scan (*.ptr);;All (*)");
    if (path.isEmpty()) return;
    if (!ce::savePointerPaths(path.toStdString(), results_))
        QMessageBox::warning(this, "Save failed", "Could not write the pointer paths.");
    else
        statusLabel_->setText(QString("Saved %1 paths").arg(results_.size()));
}

void PointerScanDialog::onLoad() {
    auto path = QFileDialog::getOpenFileName(this, "Load pointer paths", "",
        "Pointer scan (*.ptr);;All (*)");
    if (path.isEmpty()) return;
    std::string err;
    auto loaded = ce::loadPointerPaths(path.toStdString(), &err);
    if (loaded.empty() && !err.empty()) {
        QMessageBox::warning(this, "Load failed", QString::fromStdString(err));
        return;
    }
    results_ = std::move(loaded);
    populateResults();
    statusLabel_->setText(QString("Loaded %1 paths").arg(results_.size()));
}

void PointerScanDialog::onResultDoubleClicked(int row, int) {
    if (row < 0 || row >= (int)results_.size()) return;
    auto addr = PointerScanner::dereference(*proc_, results_[row]);
    if (addr)
        emit addressSelected(addr, QString::fromStdString(results_[row].toString()));
}

} // namespace ce::gui
