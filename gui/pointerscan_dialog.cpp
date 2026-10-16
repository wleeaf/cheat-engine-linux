#include "gui/pointerscan_dialog.hpp"
#include <cstring>
#include "gui/theme.hpp"
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
    resize(820, 500);

    auto* layout = new QVBoxLayout(this);

    // Give address expressions a full row; keep options and actions together below.
    auto* configRow = new QHBoxLayout;
    configRow->addWidget(new QLabel("Target Address:"));
    targetEdit_ = new QLineEdit;
    targetEdit_->setFont(monospaceFont());
    targetEdit_->setPlaceholderText("0x7f1234");
    configRow->addWidget(targetEdit_, 1);
    layout->addLayout(configRow);
    auto* optionsRow = new QHBoxLayout;

    optionsRow->addWidget(new QLabel("Depth:"));
    depthSpin_ = new QSpinBox;
    depthSpin_->setRange(1, 7);
    depthSpin_->setValue(4);
    optionsRow->addWidget(depthSpin_);

    optionsRow->addWidget(new QLabel("Max Offset:"));
    offsetSpin_ = new QSpinBox;
    offsetSpin_->setRange(64, 65536);
    offsetSpin_->setValue(2048);
    offsetSpin_->setSingleStep(256);
    optionsRow->addWidget(offsetSpin_);
    optionsRow->addStretch();

    scanBtn_ = new QPushButton("Scan");
    scanBtn_->setObjectName("primaryButton");
    connect(scanBtn_, &QPushButton::clicked, this, &PointerScanDialog::onScan);
    optionsRow->addWidget(scanBtn_);

    // Rescan filters the current paths against a new target address (after the
    // dynamic value has moved) — the key to finding a stable pointer path.
    rescanBtn_ = new QPushButton("Rescan…");
    rescanBtn_->setToolTip("Filter current paths to those that still point at a new target address");
    rescanBtn_->setEnabled(false);
    connect(rescanBtn_, &QPushButton::clicked, this, &PointerScanDialog::onRescan);
    optionsRow->addWidget(rescanBtn_);

    saveBtn_ = new QPushButton("Save…");
    saveBtn_->setEnabled(false);
    connect(saveBtn_, &QPushButton::clicked, this, &PointerScanDialog::onSave);
    optionsRow->addWidget(saveBtn_);

    loadBtn_ = new QPushButton("Load…");
    connect(loadBtn_, &QPushButton::clicked, this, &PointerScanDialog::onLoad);
    optionsRow->addWidget(loadBtn_);
    layout->addLayout(optionsRow);

    statusLabel_ = new QLabel("Ready");
    layout->addWidget(statusLabel_);

    // Results table
    resultsTable_ = new QTableWidget;
    resultsTable_->setColumnCount(3);
    resultsTable_->setHorizontalHeaderLabels({"Path", "Current Address", "Value"});
    // The pointer path is the long, variable-length column, so let it absorb the
    // slack. Size the address/value columns to their contents (and never narrower
    // than the header text, so "Current Address" isn't clipped to "Current Addres").
    auto* hh = resultsTable_->horizontalHeader();
    hh->setStretchLastSection(false);
    hh->setSectionResizeMode(0, QHeaderView::Stretch);
    hh->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    hh->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    hh->setMinimumSectionSize(48);
    resultsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable_->setProperty("monospace", true);   // font from the theme sheet
    styleDataTable(resultsTable_);
    setEmptyHint(resultsTable_, "Enter the address of a value and click Scan to find pointer paths that lead to it.");
    connect(resultsTable_, &QTableWidget::cellDoubleClicked, this, &PointerScanDialog::onResultDoubleClicked);
    layout->addWidget(resultsTable_);
}

PointerScanDialog::~PointerScanDialog() {
    // The process handle outlives this window (it is closed first on a
    // target change), but not this worker: stop and join it here.
    if (scanner_) scanner_->cancel();
    if (worker_.joinable()) worker_.join();
}

void PointerScanDialog::onScan() {
    if (worker_.joinable()) {   // the button reads Cancel while a scan runs
        scanner_->cancel();
        statusLabel_->setText("Cancelling...");
        return;
    }
    if (!proc_) return;

    bool ok;
    uintptr_t target = targetEdit_->text().toULongLong(&ok, 16);
    if (!ok) { statusLabel_->setText("Invalid address"); return; }

    statusLabel_->setText("Scanning...");
    resultsTable_->setRowCount(0);
    rescanBtn_->setEnabled(false);
    saveBtn_->setEnabled(false);
    loadBtn_->setEnabled(false);
    scanBtn_->setText("Cancel");

    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = depthSpin_->value();
    config.maxOffset = offsetSpin_->value();

    scanner_ = std::make_unique<PointerScanner>();
    scanDone_ = false;
    scanned_.clear();
    worker_ = std::thread([this, config] {
        try { scanned_ = scanner_->scan(*proc_, config); } catch (...) { scanned_.clear(); }
        scanDone_ = true;
    });
    if (!scanPoll_) {
        scanPoll_ = new QTimer(this);
        connect(scanPoll_, &QTimer::timeout, this, [this] {
            if (!scanDone_) {
                statusLabel_->setText(QString("Scanning... %1%").arg(int(scanner_->progress() * 100)));
                return;
            }
            scanPoll_->stop();
            finishScan();
        });
    }
    scanPoll_->start(100);
}

void PointerScanDialog::finishScan() {
    worker_.join();
    const bool cancelled = scanner_->wasCancelled();
    results_ = std::move(scanned_);
    populateResults();
    QString status = results_.size() > 1000 ? QString("Found %1 paths (showing first 1000)").arg(results_.size())
                                            : QString("Found %1 paths").arg(results_.size());
    if (cancelled)
        status = QString("Cancelled; %1 paths found so far").arg(results_.size());
    else if (scanner_->truncated())
        status += ". The scan stopped at its path limit, so longer paths may be missing: lower Max offset and scan again.";
    statusLabel_->setText(status);
    scanBtn_->setText("Scan");
    loadBtn_->setEnabled(true);
}

void PointerScanDialog::populateResults() {
    size_t shown = std::min(results_.size(), size_t(1000));
    resultsTable_->setRowCount((int)shown);
    for (size_t i = 0; i < shown; ++i) {
        auto& p = results_[i];
        resultsTable_->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(p.toString())));
        resultsTable_->item(i, 0)->setToolTip(resultsTable_->item(i, 0)->text());
        auto addr = PointerScanner::dereference(*proc_, p);
        resultsTable_->setItem(i, 1, new QTableWidgetItem(
            addr ? QString("0x%1").arg(addr, 0, 16) : "??"));
        if (addr) {
            uint8_t bytes[4] = {};
            auto vr = proc_->read(addr, bytes, 4);
            // In the target's byte order: a big-endian guest's value read in host
            // order showed byte-swapped.
            uint32_t raw = 0;
            if (proc_->byteOrder() == ce::ByteOrder::Big)
                raw = (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) | (uint32_t(bytes[2]) << 8) | bytes[3];
            else
                std::memcpy(&raw, bytes, 4);
            resultsTable_->setItem(i, 2, new QTableWidgetItem(
                (vr && *vr == 4) ? QString::number(static_cast<int32_t>(raw)) : QStringLiteral("??")));
        } else {
            // Rows are reused: an unresolved path must not keep the previous scan's value.
            resultsTable_->setItem(i, 2, new QTableWidgetItem());
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
