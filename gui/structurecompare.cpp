#include "gui/structurecompare.hpp"

#include "analysis/structure_tools.hpp"
#include "platform/process_api.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QVBoxLayout>

namespace ce::gui {

namespace {
constexpr int kAddressRole = Qt::UserRole + 1;
QString hex(uint64_t value) { return QString::number(static_cast<qulonglong>(value), 16).toUpper(); }
}

StructureCompareWindow::StructureCompareWindow(ProcessHandle* process, QWidget* parent)
    : QMainWindow(parent), process_(process) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(tr("Structure Compare"));
    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);

    auto* groupsRow = new QHBoxLayout;
    for (int group = 0; group < 2; ++group) {
        auto* box = new QGroupBox(group == 0 ? tr("Group 1") : tr("Group 2"), central);
        auto* boxLayout = new QVBoxLayout(box);
        groups_[group] = new QListWidget(box);
        groups_[group]->setSelectionMode(QAbstractItemView::ExtendedSelection);
        groups_[group]->setContextMenuPolicy(Qt::CustomContextMenu);
        boxLayout->addWidget(groups_[group]);
        auto* add = new QPushButton(tr("Add Address"), box);
        boxLayout->addWidget(add);
        connect(add, &QPushButton::clicked, this, [this, group]() { addAddressPrompt(group); });
        connect(groups_[group], &QWidget::customContextMenuRequested, this, [this, group](const QPoint& pos) {
            QMenu menu(this);
            menu.addAction(tr("Delete"), [this, group]() { qDeleteAll(groups_[group]->selectedItems()); });
            menu.exec(groups_[group]->viewport()->mapToGlobal(pos));
        });
        groupsRow->addWidget(box);
    }
    layout->addLayout(groupsRow);

    auto* options = new QHBoxLayout;
    auto* form = new QFormLayout;
    sizeSpin_ = new QSpinBox(central);
    sizeSpin_->setRange(8, 65536);
    sizeSpin_->setValue(4096);
    form->addRow(tr("Structsize"), sizeSpin_);
    elementCombo_ = new QComboBox(central);
    for (int size : {1, 2, 4, 8}) elementCombo_->addItem(QString::number(size), size);
    elementCombo_->setCurrentIndex(2);
    form->addRow(tr("element compare size"), elementCombo_);
    levelSpin_ = new QSpinBox(central);
    levelSpin_->setRange(0, 4);
    levelSpin_->setValue(2);
    form->addRow(tr("Max Level"), levelSpin_);
    options->addLayout(form);
    auto* checks = new QVBoxLayout;
    sameOnly_ = new QCheckBox(tr("Only find matching groups"), central);
    sameOnly_->setToolTip(tr("Group 1 must hold one and the same value; otherwise its values only have to differ "
                             "from every group 2 value"));
    sameOnly_->setChecked(true);
    hex_ = new QCheckBox(tr("Hexadecimal"), central);
    hex_->setChecked(true);
    auto* scanButton = new QPushButton(tr("Scan"), central);
    checks->addWidget(sameOnly_);
    checks->addWidget(hex_);
    checks->addWidget(scanButton);
    checks->addStretch();
    options->addLayout(checks);
    layout->addLayout(options);

    info_ = new QLabel(tr("Add the structures to compare, then Scan."), central);
    layout->addWidget(info_);
    results_ = new QTableWidget(0, 3, central);
    results_->setHorizontalHeaderLabels({tr("Offset"), tr("Group 1"), tr("Group 2")});
    results_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    results_->setSelectionBehavior(QAbstractItemView::SelectRows);
    results_->verticalHeader()->hide();
    results_->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(results_, 1);
    setCentralWidget(central);
    resize(640, 560);

    connect(scanButton, &QPushButton::clicked, this, [this]() { scan(); });
    connect(hex_, &QCheckBox::toggled, this, [this]() { scan(); });
}

void StructureCompareWindow::addAddressPrompt(int group) {
    bool ok = false;
    const QString text = QInputDialog::getText(this, tr("Add Address"), tr("Address of a structure (hex):"),
                                               QLineEdit::Normal, QString(), &ok);
    if (!ok) return;
    QString digits = text.trimmed();
    if (digits.startsWith("0x", Qt::CaseInsensitive)) digits.remove(0, 2);
    const uintptr_t address = digits.toULongLong(&ok, 16);
    if (ok) addToGroup(group, address);
}

void StructureCompareWindow::addToGroup(int group, uintptr_t address) {
    if (group < 0 || group > 1) return;
    auto* item = new QListWidgetItem(hex(address), groups_[group]);
    item->setData(kAddressRole, static_cast<qulonglong>(address));
}

std::vector<uintptr_t> StructureCompareWindow::groupAddresses(int group) const {
    std::vector<uintptr_t> out;
    out.reserve(static_cast<size_t>(groups_[group]->count()));
    for (int i = 0; i < groups_[group]->count(); ++i)
        out.push_back(static_cast<uintptr_t>(groups_[group]->item(i)->data(kAddressRole).toULongLong()));
    return out;
}

int StructureCompareWindow::scan() {
    results_->setRowCount(0);
    const auto group1 = groupAddresses(0), group2 = groupAddresses(1);
    if (!process_ || group1.empty()) {
        info_->setText(tr("Add at least one structure to group 1."));
        return 0;
    }
    if (group2.empty() && group1.size() < 2) {
        info_->setText(tr("Add a group 2 structure, or a second group 1 structure."));
        return 0;
    }
    StructureCompareOptions options;
    options.structSize = static_cast<size_t>(sizeSpin_->value());
    options.elementSize = static_cast<size_t>(elementCombo_->currentData().toInt());
    options.maxLevel = levelSpin_->value();
    options.sameOnly = sameOnly_->isChecked();
    QApplication::setOverrideCursor(Qt::WaitCursor);
    const auto matches = compareStructureGroups(*process_, group1, group2, options);
    QApplication::restoreOverrideCursor();
    auto values = [this](const std::vector<uint64_t>& list) {
        QStringList out;
        for (uint64_t v : list) out << (hex_->isChecked() ? hex(v) : QString::number(static_cast<qlonglong>(v)));
        return out.join(", ");
    };
    results_->setRowCount(static_cast<int>(matches.size()));
    for (int row = 0; row < static_cast<int>(matches.size()); ++row) {
        const auto& match = matches[static_cast<size_t>(row)];
        results_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(formatStructureComparePath(match.offsets))));
        results_->setItem(row, 1, new QTableWidgetItem(values(match.group1Values)));
        results_->setItem(row, 2, new QTableWidgetItem(values(match.group2Values)));
    }
    info_->setText(matches.size() >= options.maxResults
                       ? tr("%1 offsets found (the first %1; narrow the groups to see others)").arg(matches.size())
                       : tr("%1 offsets found").arg(matches.size()));
    return static_cast<int>(matches.size());
}

QStringList StructureCompareWindow::resultPathsForTest() const {
    QStringList out;
    for (int row = 0; row < results_->rowCount(); ++row) out << results_->item(row, 0)->text();
    return out;
}

} // namespace ce::gui
