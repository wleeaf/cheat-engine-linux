#include "gui/heapregions.hpp"
#include "gui/theme.hpp"

#include <QFont>
#include <QHeaderView>
#include <QVBoxLayout>

namespace ce::gui {

namespace {

QString permsFor(const MemoryRegion& region) {
    char perms[4] = "---";
    if (region.protection & MemProt::Read) perms[0] = 'r';
    if (region.protection & MemProt::Write) perms[1] = 'w';
    if (region.protection & MemProt::Exec) perms[2] = 'x';
    return perms;
}

bool isHeapLike(const MemoryRegion& region) {
    if (!(region.protection & MemProt::Read) || !(region.protection & MemProt::Write))
        return false;
    if (region.protection & MemProt::Exec)
        return false;
    if (region.path.find("[heap]") != std::string::npos)
        return true;
    return region.path.empty() && region.type == MemType::Private;
}

QString heapKind(const MemoryRegion& region) {
    if (region.path.find("[heap]") != std::string::npos)
        return "brk heap";
    return "anonymous private";
}

} // namespace

HeapRegionsWindow::HeapRegionsWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Heap Regions");
    resize(760, 480);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    table_ = new QTableWidget;
    table_->setColumnCount(6);
    table_->setHorizontalHeaderLabels({"Start", "End", "Size", "Perm", "Kind", "Path"});
    // Fit the fixed-width columns to content (16-digit hex addresses were clipped)
    // and let Path (variable) take the remaining width.
    auto* hh = table_->horizontalHeader();
    hh->setStretchLastSection(true);
    for (int c = 0; c < 5; ++c)
        hh->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    styleDataTable(table_);
    table_->setToolTip("Double-click a region to browse it");
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        bool ok = false;
        uintptr_t addr = table_->item(row, 0)->text().toULongLong(&ok, 16);
        if (ok) emit navigateTo(addr);
    });

    layout->addWidget(table_);
    setCentralWidget(central);
    populate();
}

void HeapRegionsWindow::populate() {
    if (!proc_) return;

    std::vector<MemoryRegion> heaps;
    for (const auto& region : proc_->queryRegions()) {
        if (isHeapLike(region))
            heaps.push_back(region);
    }

    table_->setRowCount((int)heaps.size());
    size_t total = 0;
    for (int row = 0; row < (int)heaps.size(); ++row) {
        const auto& region = heaps[row];
        table_->setItem(row, 0, new QTableWidgetItem(QString("%1").arg(region.base, 16, 16, QChar('0'))));
        table_->setItem(row, 1, new QTableWidgetItem(QString("%1").arg(region.base + region.size, 16, 16, QChar('0'))));
        table_->setItem(row, 2, new QTableWidgetItem(formatByteSize(region.size)));
        table_->item(row, 2)->setToolTip(QString("%1 bytes (0x%2)").arg(region.size).arg(region.size, 0, 16));
        table_->item(row, 2)->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        table_->setItem(row, 3, new QTableWidgetItem(permsFor(region)));
        table_->setItem(row, 4, new QTableWidgetItem(heapKind(region)));
        table_->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(region.path)));
        total += region.size;
    }

    setWindowTitle(QString("Heap Regions: %1 regions, %2")
        .arg(heaps.size())
        .arg(formatByteSize(total)));
}

} // namespace ce::gui
