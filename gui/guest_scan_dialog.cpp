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
#include <cstring>
#include <type_traits>
#include <utility>

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

template <class T> uint64_t valBits(T v) { uint64_t b = 0; std::memcpy(&b, &v, sizeof(T)); return b; }
template <class T> T bitsVal(uint64_t b) { T v; std::memcpy(&v, &b, sizeof(T)); return v; }

template <class T>
QString fmtBits(uint64_t b) {
    const T v = bitsVal<T>(b);
    if constexpr (std::is_floating_point_v<T>) return QString::number(v, 'g', 7);
    else if constexpr (std::is_signed_v<T>)    return QString::number((long long)v);
    else                                       return QString::number((unsigned long long)v);
}

template <class T>
T parseValueT(const QString& s) {
    if constexpr (std::is_floating_point_v<T>) {
        return static_cast<T>(QString(s).replace(',', '.').toDouble());
    } else {
        bool ok = false;
        return static_cast<T>(s.trimmed().toLongLong(&ok, 0));
    }
}

} // namespace

GuestScanDialog::GuestScanDialog(ce::ProcessHandle* proc, QWidget* parent)
    : QDialog(parent), proc_(proc) {
    setWindowTitle("Emulator guest scan");
    resize(600, 520);
    if (proc_) profile_ = ce::probeTarget(proc_->pid());

    auto* layout = new QVBoxLayout(this);

    QString emu = QString::fromStdString(profile_.emulator);
    auto* header = new QLabel(profile_.guestCandidates.empty()
        ? QString("<b>No emulator guest RAM detected.</b> Attach to a recognized "
                  "emulator (Dolphin, PCSX2, RPCS3, DuckStation, …) first.")
        : QString("<b>%1</b> guest memory. Scan by value, or Unknown Scan then narrow by "
                  "how the value changed. Enable big-endian for PS3 / Wii / GameCube.")
              .arg(emu.isEmpty() ? "Emulator" : emu));
    header->setWordWrap(true);
    layout->addWidget(header);

    auto* form = new QFormLayout;
    regionCombo_ = new QComboBox;
    for (const auto& g : profile_.guestCandidates)
        regionCombo_->addItem(QString("0x%1  (%2 MB)").arg(g.base, 0, 16).arg(g.size >> 20));
    form->addRow("Guest RAM region:", regionCombo_);

    typeCombo_ = new QComboBox;
    typeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double"});
    typeCombo_->setCurrentIndex(2);
    form->addRow("Value type:", typeCombo_);

    valueEdit_ = new QLineEdit;
    valueEdit_->setPlaceholderText("value to find (decimal or 0x…)");
    form->addRow("Value:", valueEdit_);

    bigEndianCheck_ = new QCheckBox("Big-endian (PS3 / Wii / GameCube)");
    form->addRow("", bigEndianCheck_);
    layout->addLayout(form);

    auto* btnRow = new QHBoxLayout;
    firstBtn_   = new QPushButton("First Scan");
    unknownBtn_ = new QPushButton("Unknown Scan");
    nextBtn_    = new QPushButton("Next Scan");
    newBtn_     = new QPushButton("New Scan");
    for (auto* b : {firstBtn_, unknownBtn_, nextBtn_, newBtn_}) btnRow->addWidget(b);
    layout->addLayout(btnRow);

    auto* cmpRow = new QHBoxLayout;
    changedBtn_   = new QPushButton("Changed");
    unchangedBtn_ = new QPushButton("Unchanged");
    increasedBtn_ = new QPushButton("Increased");
    decreasedBtn_ = new QPushButton("Decreased");
    for (auto* b : {changedBtn_, unchangedBtn_, increasedBtn_, decreasedBtn_}) cmpRow->addWidget(b);
    cmpRow->addStretch();
    auto* addBtn = new QPushButton("Add to Address List");
    cmpRow->addWidget(addBtn);
    layout->addLayout(cmpRow);

    statusLabel_ = new QLabel("Ready.");
    layout->addWidget(statusLabel_);

    resultsTable_ = new QTableWidget(0, 3);
    resultsTable_->setHorizontalHeaderLabels({"Guest address", "Host address", "Value"});
    resultsTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    resultsTable_->horizontalHeader()->setStretchLastSection(true);
    resultsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(resultsTable_);

    connect(firstBtn_,   &QPushButton::clicked, this, &GuestScanDialog::onFirstScan);
    connect(unknownBtn_, &QPushButton::clicked, this, &GuestScanDialog::onUnknownScan);
    connect(nextBtn_,    &QPushButton::clicked, this, &GuestScanDialog::onNextScan);
    connect(newBtn_,     &QPushButton::clicked, this, &GuestScanDialog::onNewScan);
    connect(addBtn,      &QPushButton::clicked, this, &GuestScanDialog::onAddToList);
    connect(changedBtn_,   &QPushButton::clicked, this, [this]() { narrowCompare((int)ce::GuestCompare::Changed); });
    connect(unchangedBtn_, &QPushButton::clicked, this, [this]() { narrowCompare((int)ce::GuestCompare::Unchanged); });
    connect(increasedBtn_, &QPushButton::clicked, this, [this]() { narrowCompare((int)ce::GuestCompare::Increased); });
    connect(decreasedBtn_, &QPushButton::clicked, this, [this]() { narrowCompare((int)ce::GuestCompare::Decreased); });
    connect(valueEdit_, &QLineEdit::returnPressed, this,
            [this]() { haveScan_ ? onNextScan() : onFirstScan(); });

    onNewScan();   // sets the initial (not-yet-scanning) button states
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

void GuestScanDialog::beginScan() {
    const int ri = std::clamp(regionCombo_->currentIndex(), 0,
                              (int)profile_.guestCandidates.size() - 1);
    const auto& region = profile_.guestCandidates[ri];
    scanType_ = selectedType();
    scanBigEndian_ = bigEndianCheck_->isChecked();
    regionBase_ = region.base;
    regionGuestBase_ = region.guestBase;
    regionSize_ = region.size;
    haveScan_ = true;
    typeCombo_->setEnabled(false);
    bigEndianCheck_->setEnabled(false);
    regionCombo_->setEnabled(false);
}

void GuestScanDialog::onFirstScan() {
    if (profile_.guestCandidates.empty()) return;
    beginScan();
    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    const QString valStr = valueEdit_->text();
    candidates_ = dispatchType(scanType_, [&]<class T>() {
        const uint64_t vb = valBits<T>(parseValueT<T>(valStr));
        std::vector<std::pair<uint64_t, uint64_t>> out;
        for (uint64_t a : ce::guestScanExact<T>(gv, parseValueT<T>(valStr), sizeof(T)))
            out.emplace_back(a, vb);
        return out;
    });
    unknownMode_ = false;
    refreshResults();
}

void GuestScanDialog::onUnknownScan() {
    if (profile_.guestCandidates.empty()) return;
    beginScan();
    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    snapshot_ = ce::guestReadRegion(gv);
    candidates_.clear();
    unknownMode_ = true;
    refreshResults();
}

void GuestScanDialog::onNextScan() {
    if (!haveScan_ || unknownMode_) return;
    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    const QString valStr = valueEdit_->text();
    candidates_ = dispatchType(scanType_, [&]<class T>() {
        const T val = parseValueT<T>(valStr);
        std::vector<uint64_t> addrs;
        addrs.reserve(candidates_.size());
        for (auto& [a, _] : candidates_) addrs.push_back(a);
        const uint64_t vb = valBits<T>(val);
        std::vector<std::pair<uint64_t, uint64_t>> out;
        for (uint64_t a : ce::guestNextExact<T>(gv, addrs, val)) out.emplace_back(a, vb);
        return out;
    });
    refreshResults();
}

void GuestScanDialog::narrowCompare(int opInt) {
    if (!haveScan_) return;
    const auto op = static_cast<ce::GuestCompare>(opInt);
    ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
    const size_t align = 0;  // default = sizeof(T)
    candidates_ = dispatchType(scanType_, [&]<class T>() {
        std::vector<std::pair<uint64_t, uint64_t>> out;
        if (unknownMode_) {
            const auto live = ce::guestReadRegion(gv);
            for (auto& [off, nv] : ce::guestCompareBuffers<T>(snapshot_, live, scanBigEndian_, op,
                                                              align ? align : sizeof(T)))
                out.emplace_back(off, valBits<T>(nv));
        } else {
            std::vector<std::pair<uint64_t, T>> pairs;
            pairs.reserve(candidates_.size());
            for (auto& [a, b] : candidates_) pairs.emplace_back(a, bitsVal<T>(b));
            for (auto& [a, nv] : ce::guestNextCompare<T>(gv, pairs, op))
                out.emplace_back(a, valBits<T>(nv));
        }
        return out;
    });
    if (unknownMode_) { unknownMode_ = false; snapshot_.clear(); }  // now an explicit set
    refreshResults();
}

void GuestScanDialog::onNewScan() {
    candidates_.clear();
    snapshot_.clear();
    haveScan_ = false;
    unknownMode_ = false;
    resultsTable_->setRowCount(0);
    statusLabel_->setText("Ready.");
    refreshResults();
}

void GuestScanDialog::refreshResults() {
    if (haveScan_ && !unknownMode_) {
        const size_t shown = std::min<size_t>(candidates_.size(), 2000);
        ce::GuestView gv{ proc_, regionBase_, regionSize_, scanBigEndian_ };
        resultsTable_->setRowCount((int)shown);
        dispatchType(scanType_, [&]<class T>() {
            for (size_t i = 0; i < shown; ++i) {
                const uint64_t g = candidates_[i].first;
                resultsTable_->setItem((int)i, 0, new QTableWidgetItem(
                    QString("0x%1").arg(regionGuestBase_ + g, 0, 16)));
                resultsTable_->setItem((int)i, 1, new QTableWidgetItem(
                    QString("0x%1").arg((qulonglong)gv.toHost(g), 0, 16)));
                resultsTable_->setItem((int)i, 2, new QTableWidgetItem(fmtBits<T>(candidates_[i].second)));
            }
        });
        statusLabel_->setText(QString("%1 result(s)%2").arg(candidates_.size())
            .arg(candidates_.size() > shown ? QString(" (showing first %1)").arg(shown) : QString()));
    } else if (unknownMode_) {
        resultsTable_->setRowCount(0);
        statusLabel_->setText(QString("Snapshot taken (%1 MB). Change the value in-game, then "
                                      "narrow with Changed / Increased / Decreased / Unchanged.")
                                  .arg(snapshot_.size() >> 20));
    }

    // Button states for the current phase.
    const bool idle = !haveScan_;
    const bool canStart = idle && !profile_.guestCandidates.empty();
    firstBtn_->setEnabled(canStart);
    unknownBtn_->setEnabled(canStart);
    valueEdit_->setEnabled(!profile_.guestCandidates.empty());
    nextBtn_->setEnabled(haveScan_ && !unknownMode_ && !candidates_.empty());
    for (auto* b : {changedBtn_, unchangedBtn_, increasedBtn_, decreasedBtn_})
        b->setEnabled(haveScan_);
    typeCombo_->setEnabled(idle);
    bigEndianCheck_->setEnabled(idle);
    regionCombo_->setEnabled(idle && regionCombo_->count() > 0);
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
        const uint64_t g = candidates_[row].first;
        emit addressSelected(gv.toHost(g), scanType_, scanBigEndian_,
                             QString("guest 0x%1").arg(regionGuestBase_ + g, 0, 16));
    }
}

} // namespace ce::gui
