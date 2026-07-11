#include "gui/modulelist.hpp"

#include <QFont>
#include <QHeaderView>
#include <QVBoxLayout>

namespace ce::gui {

ModuleListWindow::ModuleListWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Module List");
    resize(850, 500);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    table_ = new QTableWidget;
    table_->setColumnCount(4);
    table_->setHorizontalHeaderLabels({"Base", "Size", "Name", "Path"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setFont(QFont("Monospace", 9));
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        bool ok = false;
        auto addr = table_->item(row, 0)->text().toULongLong(&ok, 16);
        if (ok) emit navigateTo(addr);
    });

    layout->addWidget(table_);
    setCentralWidget(central);
    populate();
}

void ModuleListWindow::populate() {
    if (!proc_) return;

    auto modules = proc_->modules();
    table_->setRowCount((int)modules.size());
    for (int i = 0; i < (int)modules.size(); ++i) {
        const auto& module = modules[i];
        table_->setItem(i, 0, new QTableWidgetItem(QString("%1").arg(module.base, 16, 16, QChar('0'))));
        table_->setItem(i, 1, new QTableWidgetItem(QString::number(module.size)));
        table_->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(module.name)));
        table_->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(module.path)));
    }
    setWindowTitle(QString("Module List - %1 modules").arg(modules.size()));
}

} // namespace ce::gui
