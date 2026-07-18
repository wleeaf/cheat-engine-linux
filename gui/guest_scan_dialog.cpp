#include "gui/guest_scan_dialog.hpp"
#include "core/guest_view.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QComboBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QHeaderView>

#include <algorithm>
#include <type_traits>

namespace ce::gui {

using ce::ValueType;

namespace {

// Run a generic lambda instantiated for the scalar C++ type matching `t`.
template <class F>
auto dispatchType(ValueType t, F&& f) {
    switch (t) {
        case ValueType::Byte:   return f.template operator()<int8_t>();
        case ValueType::Int16:  return f.template operator()<int16_t>();
        case ValueType::Int64:  return f.template operator()<int64_t>();
        case ValueType::Float:  return f.template operator()<float>();
        case ValueType::Double: return f.template operator()<double>();
        case ValueType::Int32:
        default:                return f.template operator()<int32_t>();
    }
}

template <class T>
T parseValueT(const QString& s) {
    if constexpr (std::is_floating_point_v<T>) {
        return static_cast<T>(QString(s).replace(',', '.').toDouble());
    } else {
        bool ok = false;
        long long v = s.trimmed().toLongLong(&ok, 0);
        return static_cast<T>(v);
    }
}

template <class T>
QString formatValueT(const ce::GuestView& gv, uint64_t guestAddr) {
    auto v = gv.read<T>(guestAddr);
    if (!v) return "??";
    if constexpr (std::is_floating_point_v<T>) return QString::number(*v, 'g', 7);
    else if constexpr (std::is_signed_v<T>)    return QString::number((long long)*v);
    else                                       return QString::number((unsigned long long)*v);
}

} // namespace

GuestScanDialog::GuestScanDialog(ce::ProcessHandle* proc, QWidget* parent)
    : QDialog(parent), proc_(proc) {
    setWindowTitle("Emulator guest scan");
    resize(560, 480);
    if (proc_) profile_ = ce::probeTarget(proc_->pid());

    auto* layout = new QVBoxLayout(this);

    QString emu = QString::fromStdString(profile_.emulator);
    auto* header = new QLabel(profile_.guestCandidates.empty()
        ? QString("<b>No emulator guest RAM detected.</b> Attach to a recognized "
                  "emulator (Dolphin, PCSX2, RPCS3, DuckStation, …) first.")
        : QString("<b>%1</b> guest memory. Scan by the value the game shows; enable "
                  "big-endian for PS3 / Wii / GameCube.").arg(emu.isEmpty() ? "Emulator" : emu));
    header->setWordWrap(true);
    layout->addWidget(header);

    auto* form = new QFormLayout;
    regionCombo_ = new QComboBox;
    for (const auto& g : profile_.guestCandidates)
        regionCombo_->addItem(QString("0x%1  (%2 MB)").arg(g.base, 0, 16).arg(g.size >> 20));
    form->addRow("Guest RAM region:", regionCombo_);

    typeCombo_ = new QComboBox;
    typeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double"});
    typeCombo_->setCurrentIndex(2);   // 4 Bytes
    form->addRow("Value type:", typeCombo_);

    valueEdit_ = new QLineEdit;
    valueEdit_->setPlaceholderText("value to find (decimal or 0x…)");
    form->addRow("Value:", valueEdit_);

    bigEndianCheck_ = new QCheckBox("Big-endian (PS3 / Wii / GameCube)");
    form->addRow("", bigEndianCheck_);
    layout->addLayout(form);

    auto* btnRow = new QHBoxLayout;
    firstBtn_ = new QPushButton("First Scan");
    nextBtn_  = new QPushButton("Next Scan");
    newBtn_   = new QPushButton("New Scan");
    nextBtn_->setEnabled(false);
    btnRow->addWidget(firstBtn_);
    btnRow->addWidget(nextBtn_);
    btnRow->addWidget(newBtn_);
    btnRow->addStretch();
    auto* addBtn = new QPushButton("Add to Address List");
    btnRow->addWidget(addBtn);
    layout->addLayout(btnRow);

    statusLabel_ = new QLabel("Ready.");
    layout->addWidget(statusLabel_);

    resultsTable_ = new QTableWidget(0, 3);
    resultsTable_->setHorizontalHeaderLabels({"Guest address", "Host address", "Value"});
    resultsTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTable_->horizontalHeader()->setStretchLastSection(true);
    resultsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(resultsTable_);

    const bool canScan = !profile_.guestCandidates.empty();
    firstBtn_->setEnabled(canScan);
    newBtn_->setEnabled(canScan);
    addBtn->setEnabled(canScan);
    valueEdit_->setEnabled(canScan);

    connect(firstBtn_, &QPushButton::clicked, this, &GuestScanDialog::onFirstScan);
    connect(nextBtn_,  &QPushButton::clicked, this, &GuestScanDialog::onNextScan);
    connect(newBtn_,   &QPushButton::clicked, this, &GuestScanDialog::onNewScan);
    connect(addBtn,    &QPushButton::clicked, this, &GuestScanDialog::onAddToList);
    connect(valueEdit_, &QLineEdit::returnPressed, this,
            [this]() { haveScan_ ? onNextScan() : onFirstScan(); });
}

ValueType GuestScanDialog::selectedType() const {
    switch (typeCombo_->currentIndex()) {
        case 0: return ValueType::Byte;
        case 1: return ValueType::Int16;
        case 3: return ValueType::Int64;
        case 4: return ValueType::Float;
        case 5: return ValueType::Double;
        case 2:
        default: return ValueType::Int32;
    }
}

void GuestScanDialog::onFirstScan() {
    if (profile_.guestCandidates.empty()) return;
    int ri = std::clamp(regionCombo_->currentIndex(), 0, (int)profile_.guestCandidates.size() - 1);
    const auto& region = profile_.guestCandidates[ri];
    scanType_ = selectedType();
    scanBigEndian_ = bigEndianCheck_->isChecked();
    regionBase_ = region.base;
    regionSize_ = region.size;

    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    const QString valStr = valueEdit_->text();
    candidates_ = dispatchType(scanType_, [&]<class T>() {
        return ce::guestScanExact<T>(gv, parseValueT<T>(valStr), sizeof(T));
    });
    haveScan_ = true;
    typeCombo_->setEnabled(false);       // type/endian are frozen for narrowing
    bigEndianCheck_->setEnabled(false);
    regionCombo_->setEnabled(false);
    refreshResults();
}

void GuestScanDialog::onNextScan() {
    if (!haveScan_) return;
    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    const QString valStr = valueEdit_->text();
    candidates_ = dispatchType(scanType_, [&]<class T>() {
        return ce::guestNextExact<T>(gv, candidates_, parseValueT<T>(valStr));
    });
    refreshResults();
}

void GuestScanDialog::onNewScan() {
    candidates_.clear();
    haveScan_ = false;
    resultsTable_->setRowCount(0);
    nextBtn_->setEnabled(false);
    typeCombo_->setEnabled(true);
    bigEndianCheck_->setEnabled(true);
    regionCombo_->setEnabled(true);
    statusLabel_->setText("Ready.");
}

void GuestScanDialog::refreshResults() {
    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    const size_t shown = std::min<size_t>(candidates_.size(), 2000);
    resultsTable_->setRowCount((int)shown);
    dispatchType(scanType_, [&]<class T>() {
        for (size_t i = 0; i < shown; ++i) {
            const uint64_t g = candidates_[i];
            resultsTable_->setItem((int)i, 0, new QTableWidgetItem(QString("0x%1").arg(g, 0, 16)));
            resultsTable_->setItem((int)i, 1, new QTableWidgetItem(
                QString("0x%1").arg((qulonglong)gv.toHost(g), 0, 16)));
            resultsTable_->setItem((int)i, 2, new QTableWidgetItem(formatValueT<T>(gv, g)));
        }
    });
    statusLabel_->setText(QString("%1 result(s)%2").arg(candidates_.size())
        .arg(candidates_.size() > shown ? QString(" (showing first %1)").arg(shown) : QString()));
    nextBtn_->setEnabled(haveScan_);
}

void GuestScanDialog::onAddToList() {
    if (candidates_.empty()) return;
    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    QList<int> rows;
    const auto sel = resultsTable_->selectionModel()->selectedRows();
    if (sel.isEmpty()) {
        if (resultsTable_->currentRow() >= 0) rows << resultsTable_->currentRow();
    } else {
        for (const auto& idx : sel) rows << idx.row();
    }
    for (int row : rows) {
        if (row < 0 || row >= (int)candidates_.size()) continue;
        const uint64_t g = candidates_[row];
        emit addressSelected(gv.toHost(g), scanType_, QString("guest 0x%1").arg(g, 0, 16));
    }
}

} // namespace ce::gui
