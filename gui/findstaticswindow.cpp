/// Find Statics window — list static addresses referenced from a module
/// sorted by reference count.

#include "gui/findstaticswindow.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFont>
#include <QApplication>

namespace ce::gui {

FindStaticsWindow::FindStaticsWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Find Statics");
    resize(720, 540);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    auto* row = new QHBoxLayout;
    row->addWidget(new QLabel("Module:"));
    moduleCombo_ = new QComboBox;
    if (proc_) {
        for (const auto& m : proc_->modules()) {
            moduleCombo_->addItem(
                QString("%1  @ 0x%2").arg(QString::fromStdString(m.name)).arg(m.base, 0, 16));
        }
    }
    row->addWidget(moduleCombo_, 1);
    scanBtn_ = new QPushButton("Scan");
    connect(scanBtn_, &QPushButton::clicked, this, &FindStaticsWindow::onScan);
    row->addWidget(scanBtn_);
    layout->addLayout(row);

    statusLabel_ = new QLabel("Pick a module and click Scan.");
    layout->addWidget(statusLabel_);

    table_ = new QTableWidget;
    table_->setColumnCount(3);
    table_->setHorizontalHeaderLabels({"Static address", "Symbol", "References"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setFont(QFont("Monospace", 9));
    layout->addWidget(table_, 1);

    setCentralWidget(central);
}

void FindStaticsWindow::onScan() {
    if (!proc_) return;
    int idx = moduleCombo_->currentIndex();
    auto mods = proc_->modules();
    if (idx < 0 || idx >= (int)mods.size()) return;

    statusLabel_->setText("Scanning…");
    scanBtn_->setEnabled(false);
    QApplication::processEvents();

    if (!symbolsLoaded_) {
        resolver_.loadProcess(*proc_);
        symbolsLoaded_ = true;
    }
    auto statics = analyzer_.findStatics(*proc_, mods[idx]);

    table_->setRowCount((int)statics.size());
    for (size_t i = 0; i < statics.size(); ++i) {
        const auto& s = statics[i];
        table_->setItem((int)i, 0, new QTableWidgetItem(
            QString("0x%1").arg(s.address, 16, 16, QChar('0'))));
        QString sym;
        if (symbolsLoaded_) {
            auto resolved = resolver_.resolve(s.address);
            if (!resolved.empty()) sym = QString::fromStdString(resolved);
        }
        table_->setItem((int)i, 1, new QTableWidgetItem(sym));
        table_->setItem((int)i, 2, new QTableWidgetItem(QString::number(s.references)));
    }
    statusLabel_->setText(QString("Done — %1 static addresses found.").arg(statics.size()));
    scanBtn_->setEnabled(true);
}

} // namespace ce::gui
