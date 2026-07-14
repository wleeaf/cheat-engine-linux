#include "gui/advancedoptions.hpp"

#include "debug/patch.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QHeaderView>
#include <QMenu>
#include <QInputDialog>
#include <QMessageBox>

namespace ce::gui {

AdvancedOptionsWindow::AdvancedOptionsWindow(ce::ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Code list/Pause");   // CE AdvancedOptionsUnit caption

    auto* central = new QWidget;
    setCentralWidget(central);
    auto* v = new QVBoxLayout(central);

    v->addWidget(new QLabel("Code list:"));       // CE Label

    table_ = new QTableWidget(0, 2);               // CE lvCodelist (Address, Name)
    table_->setHorizontalHeaderLabels({"Address", "Name"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(table_, &QWidget::customContextMenuRequested,
            this, &AdvancedOptionsWindow::showContextMenu);
    connect(table_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* it) {
        if (it) emit navigateTo(addressAtRow(it->row()));
    });
    v->addWidget(table_);

    auto* row = new QHBoxLayout;                    // CE Panel1
    row->addStretch();
    auto* ok = new QPushButton("OK");               // CE Button1
    connect(ok, &QPushButton::clicked, this, &QWidget::close);
    row->addWidget(ok);
    v->addLayout(row);

    resize(500, 400);
}

uintptr_t AdvancedOptionsWindow::addressAtRow(int row) const {
    auto* it = (row >= 0) ? table_->item(row, 0) : nullptr;
    return it ? (uintptr_t)it->data(Qt::UserRole).toULongLong() : 0;
}

int AdvancedOptionsWindow::selectedRow() const {
    auto sel = table_->selectionModel()->selectedRows();
    return sel.isEmpty() ? -1 : sel.first().row();
}

void AdvancedOptionsWindow::addCode(uintptr_t addr, const QString& name) {
    for (int r = 0; r < table_->rowCount(); ++r)
        if (addressAtRow(r) == addr) return;   // dedupe
    int r = table_->rowCount();
    table_->insertRow(r);
    auto* a = new QTableWidgetItem(QString("0x%1").arg((qulonglong)addr, 0, 16));
    a->setData(Qt::UserRole, (qulonglong)addr);
    table_->setItem(r, 0, a);
    table_->setItem(r, 1, new QTableWidgetItem(name));
}

void AdvancedOptionsWindow::showContextMenu(const QPoint& pos) {
    const int row = selectedRow();
    const uintptr_t addr = addressAtRow(row);

    QMenu m(this);
    auto* openAct    = m.addAction("Open the disassembler at this location");
    m.addSeparator();
    auto* nopAct     = m.addAction("Replace with code that does nothing");
    auto* restoreAct = m.addAction("Restore with original code");
    m.addSeparator();
    auto* renameAct  = m.addAction("Rename");
    auto* removeAct  = m.addAction("Remove from list");

    const bool have = (addr != 0);
    for (auto* a : {openAct, nopAct, renameAct, removeAct}) a->setEnabled(have);
    restoreAct->setEnabled(have && nopOriginals_.count(addr) > 0);

    auto* chosen = m.exec(table_->viewport()->mapToGlobal(pos));
    if (!chosen) return;

    if (chosen == openAct) {
        emit navigateTo(addr);
    } else if (chosen == nopAct && proc_) {
        auto orig = ce::nopInstruction(*proc_, addr);
        if (!orig.empty()) nopOriginals_[addr] = orig;
        else QMessageBox::warning(this, "NOP", "Could not read/patch the instruction.");
    } else if (chosen == restoreAct && proc_) {
        auto it = nopOriginals_.find(addr);
        if (it != nopOriginals_.end() && ce::restoreBytes(*proc_, addr, it->second))
            nopOriginals_.erase(it);
    } else if (chosen == renameAct && row >= 0) {
        bool ok = false;
        QString cur = table_->item(row, 1) ? table_->item(row, 1)->text() : QString();
        auto name = QInputDialog::getText(this, "Rename", "Name:", QLineEdit::Normal, cur, &ok);
        if (ok) table_->setItem(row, 1, new QTableWidgetItem(name));
    } else if (chosen == removeAct && row >= 0) {
        table_->removeRow(row);
    }
}

}  // namespace ce::gui
