#include "gui/memoryregions.hpp"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QFont>

namespace ce::gui {

MemoryRegionsWindow::MemoryRegionsWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Memory Regions");
    resize(800, 500);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    table_ = new QTableWidget;
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"Start", "End", "Size", "Perm", "Path"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setFont(QFont("Monospace", 9));
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        bool ok;
        uintptr_t addr = table_->item(row, 0)->text().toULongLong(&ok, 16);
        if (ok) emit navigateTo(addr);
    });
    layout->addWidget(table_);
    setCentralWidget(central);
    populate();
}

void MemoryRegionsWindow::populate() {
    if (!proc_) return;
    auto regions = proc_->queryRegions();
    table_->setRowCount(regions.size());
    size_t totalReadable = 0;
    for (size_t i = 0; i < regions.size(); ++i) {
        auto& r = regions[i];
        table_->setItem(i, 0, new QTableWidgetItem(QString("%1").arg(r.base, 16, 16, QChar('0'))));
        table_->setItem(i, 1, new QTableWidgetItem(QString("%1").arg(r.base + r.size, 16, 16, QChar('0'))));
        table_->setItem(i, 2, new QTableWidgetItem(QString::number(r.size)));
        char perms[4] = "---";
        if (r.protection & MemProt::Read) perms[0] = 'r';
        if (r.protection & MemProt::Write) perms[1] = 'w';
        if (r.protection & MemProt::Exec) perms[2] = 'x';
        table_->setItem(i, 3, new QTableWidgetItem(perms));
        table_->setItem(i, 4, new QTableWidgetItem(QString::fromStdString(r.path)));
        if (r.protection & MemProt::Read) totalReadable += r.size;
    }
    setWindowTitle(QString("Memory Regions — %1 regions, %2 MB readable")
        .arg(regions.size()).arg(totalReadable / 1048576));
}

} // namespace ce::gui
