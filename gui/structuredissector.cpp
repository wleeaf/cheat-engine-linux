#include "gui/structuredissector.hpp"
#include "gui/theme.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QClipboard>
#include <QApplication>
#include <QMessageBox>
#include "analysis/structure_tools.hpp"
#include <QLabel>
#include <QHeaderView>
#include <QMenu>
#include <QColor>
#include <QInputDialog>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMessageBox>
#include <QFileDialog>
#include <QFont>
#include <QRegularExpression>
#include <cstring>
#include <cmath>
#include <algorithm>

namespace ce::gui {

StructureDissector::StructureDissector(ProcessHandle* proc, uintptr_t baseAddr, QWidget* parent)
    : QMainWindow(parent), proc_(proc), baseAddr_(baseAddr) {

    setWindowTitle("Structure Dissector");
    resize(750, 600);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    // Address bar
    auto* addrRow = new QHBoxLayout;
    addrRow->addWidget(new QLabel("Base Address:"));
    addressEdit_ = new QLineEdit(QString("0x%1").arg(baseAddr, 0, 16));
    addressEdit_->setFont(QFont("Monospace", 10));
    connect(addressEdit_, &QLineEdit::returnPressed, this, &StructureDissector::onGotoAddress);
    addrRow->addWidget(addressEdit_);
    auto* goBtn = new QPushButton("Go");
    connect(goBtn, &QPushButton::clicked, this, &StructureDissector::onGotoAddress);
    addrRow->addWidget(goBtn);

    addrRow->addWidget(new QLabel("Bytes:"));
    sizeSpin_ = new QSpinBox;
    sizeSpin_->setRange(8, 8192);
    sizeSpin_->setSingleStep(64);
    sizeSpin_->setValue(structSize_);
    connect(sizeSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int v) {
        structSize_ = (v / 8) * 8;   // keep a multiple of 8 (one row per 8 bytes)
        if (baseAddr_) populateTable();
    });
    addrRow->addWidget(sizeSpin_);

    // Compare: one or more struct addresses; rows whose 8 bytes differ from the
    // base in ANY instance are highlighted. With one address this is CE's
    // "compare two structures"; with several it is the N-instance dissector,
    // surfacing the fields that discriminate between instances (e.g. team id).
    addrRow->addWidget(new QLabel("Compare:"));
    compareEdit_ = new QLineEdit;
    compareEdit_->setFont(QFont("Monospace", 10));
    compareEdit_->setPlaceholderText("0x…, 0x… (optional, comma/space separated)");
    connect(compareEdit_, &QLineEdit::returnPressed, this, [this]() {
        compareAddrs_.clear();
        const auto tokens = compareEdit_->text().split(
            QRegularExpression("[\\s,]+"), Qt::SkipEmptyParts);
        for (const QString& token : tokens) {
            bool ok = false;
            uintptr_t addr = token.trimmed().toULongLong(&ok, 16);
            if (ok && addr) compareAddrs_.push_back(addr);
        }
        populateTable();
    });
    addrRow->addWidget(compareEdit_);

    auto* saveBtn = new QPushButton("Save Def…");
    saveBtn->setToolTip("Save this structure definition (named fields + size)");
    connect(saveBtn, &QPushButton::clicked, this, &StructureDissector::onSaveDefinition);
    addrRow->addWidget(saveBtn);
    auto* loadBtn = new QPushButton("Load Def…");
    connect(loadBtn, &QPushButton::clicked, this, &StructureDissector::onLoadDefinition);
    addrRow->addWidget(loadBtn);
    auto* cppBtn = new QPushButton("Copy as C++");
    connect(cppBtn, &QPushButton::clicked, this, &StructureDissector::onCopyAsCpp);
    addrRow->addWidget(cppBtn);
    auto* il2cppBtn = new QPushButton("Type as IL2CPP…");
    il2cppBtn->setToolTip("Label these bytes with a Unity IL2CPP class's fields "
                          "(names + offsets from global-metadata.dat + GameAssembly)");
    connect(il2cppBtn, &QPushButton::clicked, this, &StructureDissector::onTypeAsIl2Cpp);
    addrRow->addWidget(il2cppBtn);
    auto* cstructBtn = new QPushButton("Type as C struct…");
    cstructBtn->setToolTip("Label these bytes with a native struct from the target's DWARF debug info");
    connect(cstructBtn, &QPushButton::clicked, this, &StructureDissector::onTypeAsCStruct);
    addrRow->addWidget(cstructBtn);
    layout->addLayout(addrRow);

    // Table
    table_ = new QTableWidget;
    table_->setColumnCount(7);
    table_->setHorizontalHeaderLabels({"Offset", "Name", "Hex", "Int8", "Int32", "Float", "Pointer?"});
    // Fit the numeric/offset columns to content and let the field Name take the
    // slack, so every value column stays readable instead of all-but-last squeezing.
    auto* hh = table_->horizontalHeader();
    hh->setStretchLastSection(false);
    for (int c = 0; c < 7; ++c)
        hh->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    hh->setSectionResizeMode(1, QHeaderView::Stretch);  // Name
    table_->setFont(QFont("Monospace", 9));
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->verticalHeader()->setVisible(false);
    table_->setAlternatingRowColors(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(table_, &QTableWidget::customContextMenuRequested,
            this, &StructureDissector::onContextMenu);
    // Double-click a row to name that field (stored by offset; blank clears).
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        int off = row * 8;
        bool ok = false;
        QString cur = fieldNames_.count(off) ? fieldNames_[off] : QString();
        QString name = QInputDialog::getText(this, "Name field",
            QString("Name for offset +0x%1:").arg(off, 0, 16), QLineEdit::Normal, cur, &ok);
        if (!ok) return;
        if (name.trimmed().isEmpty()) fieldNames_.erase(off);
        else                          fieldNames_[off] = name.trimmed();
        populateTable();
    });
    layout->addWidget(table_);

    setCentralWidget(central);

    // Auto-refresh
    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &StructureDissector::onRefresh);
    refreshTimer_->start(1000);

    if (baseAddr_) populateTable();
}

void StructureDissector::onGotoAddress() {
    bool ok;
    baseAddr_ = addressEdit_->text().toULongLong(&ok, 16);
    if (ok) populateTable();
}

void StructureDissector::onRefresh() {
    if (baseAddr_ && proc_) populateTable();
}

void StructureDissector::detachFromTarget() {
    if (refreshTimer_) refreshTimer_->stop();
    proc_ = nullptr;   // populateTable()/onRefresh() both bail on a null proc_
    setWindowTitle("Structure Dissector (target exited)");
}

QString StructureDissector::formatValue(const uint8_t* data, int offset, const QString& type) const {
    if (offset + 8 > validBytes_) return "??";

    if (type == "hex") {
        return QString("%1 %2 %3 %4 %5 %6 %7 %8")
            .arg(data[0], 2, 16, QChar('0')).arg(data[1], 2, 16, QChar('0'))
            .arg(data[2], 2, 16, QChar('0')).arg(data[3], 2, 16, QChar('0'))
            .arg(data[4], 2, 16, QChar('0')).arg(data[5], 2, 16, QChar('0'))
            .arg(data[6], 2, 16, QChar('0')).arg(data[7], 2, 16, QChar('0'));
    }
    if (type == "int8") return QString::number((int8_t)data[0]);
    if (type == "int32") {
        int32_t v; memcpy(&v, data, 4);
        return QString::number(v);
    }
    if (type == "float") {
        float v; memcpy(&v, data, 4);
        if (std::isnan(v) || std::isinf(v)) return "NaN";
        if (v == 0.0f) return "0";
        if (std::abs(v) < 1e-20 || std::abs(v) > 1e20) return "-";
        return QString::number(v, 'f', 4);
    }
    if (type == "ptr") {
        uintptr_t v; memcpy(&v, data, 8);
        if (looksLikePointer(v))
            return QString("-> 0x%1").arg(v, 0, 16);
        return "-";
    }
    return "?";
}

// Heuristically guess the most likely type of the 8 bytes at `offset`:
//   - a plausible userspace pointer  -> Pointer
//   - a sane non-integer float       -> Float
//   - otherwise                      -> Int32
bool StructureDissector::looksLikePointer(uintptr_t p) const {
    // A range check alone treats any 8-byte value in userspace range as a
    // pointer; require that it actually points to readable memory.
    if (p <= 0x10000 || p >= 0x7fffffffffffULL || !proc_) return false;
    uint8_t probe;
    return (bool)proc_->read(p, &probe, 1);
}

ce::ValueType StructureDissector::guessType(const uint8_t* data, int offset) const {
    if (offset + 8 > validBytes_) return ce::ValueType::Int32;
    uintptr_t p; std::memcpy(&p, data, 8);
    if (looksLikePointer(p)) return ce::ValueType::Pointer;
    float f; std::memcpy(&f, data, 4);
    if (!std::isnan(f) && !std::isinf(f) && f != 0.0f &&
        std::abs(f) >= 1e-3f && std::abs(f) <= 1e7f &&
        f != std::floor(f))          // has a fractional part -> looks like a float
        return ce::ValueType::Float;
    return ce::ValueType::Int32;
}

void StructureDissector::onContextMenu(const QPoint& pos) {
    int row = table_->rowAt(pos.y());
    if (row < 0) return;
    int off = row * 8;
    uintptr_t addr = baseAddr_ + off;
    ce::ValueType guessed = guessType(cache_.data() + off, off);
    auto typeName = [](ce::ValueType t) {
        switch (t) {
            case ce::ValueType::Pointer: return "Pointer";
            case ce::ValueType::Float:   return "Float";
            case ce::ValueType::Int64:   return "8 Bytes";
            default:                     return "4 Bytes";
        }
    };

    QMenu menu(this);
    menu.addAction(QString("Offset +0x%1  (0x%2)").arg(off, 2, 16, QChar('0')).arg(addr, 0, 16))
        ->setEnabled(false);
    menu.addSeparator();
    auto* addGuess = menu.addAction(QString("Add to address list as %1 (auto)").arg(typeName(guessed)));
    auto* add4  = menu.addAction("Add as 4 Bytes");
    auto* add8  = menu.addAction("Add as 8 Bytes");
    auto* addF  = menu.addAction("Add as Float");
    auto* addP  = menu.addAction("Add as Pointer");

    QAction* picked = menu.exec(table_->viewport()->mapToGlobal(pos));
    if (!picked || !addToListCb_) return;

    ce::ValueType t = guessed;
    if (picked == add4) t = ce::ValueType::Int32;
    else if (picked == add8) t = ce::ValueType::Int64;
    else if (picked == addF) t = ce::ValueType::Float;
    else if (picked == addP) t = ce::ValueType::Pointer;
    else if (picked != addGuess) return;

    addToListCb_(addr, t, QString("Dissect +0x%1").arg(off, 0, 16));
}

void StructureDissector::onSaveDefinition() {
    auto path = QFileDialog::getSaveFileName(this, "Save structure definition",
        "structure.json", "Structure def (*.json);;All (*)");
    if (path.isEmpty()) return;
    QJsonObject root;
    root["size"] = structSize_;
    QJsonArray fields;
    for (const auto& [off, name] : fieldNames_) {
        QJsonObject f;
        f["offset"] = off;
        f["name"] = name;
        fields.append(f);
    }
    root["fields"] = fields;
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Save failed", "Could not write the definition file.");
        return;
    }
    file.write(QJsonDocument(root).toJson());
}

void StructureDissector::onLoadDefinition() {
    auto path = QFileDialog::getOpenFileName(this, "Load structure definition",
        "", "Structure def (*.json);;All (*)");
    if (path.isEmpty()) return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Load failed", "Could not read the definition file.");
        return;
    }
    auto doc = QJsonDocument::fromJson(file.readAll());
    if (!doc.isObject()) {
        QMessageBox::warning(this, "Load failed", "Not a valid structure definition.");
        return;
    }
    auto root = doc.object();
    fieldNames_.clear();
    for (const auto& v : root["fields"].toArray()) {
        auto f = v.toObject();
        fieldNames_[f["offset"].toInt()] = f["name"].toString();
    }
    int sz = root["size"].toInt(structSize_);
    if (sz >= 8 && sz <= 8192) { structSize_ = (sz / 8) * 8; sizeSpin_->setValue(structSize_); }
    if (baseAddr_) populateTable();
}

void StructureDissector::onTypeAsIl2Cpp() {
    if (!proc_) { QMessageBox::information(this, "IL2CPP", "No target process."); return; }
    bool ok = false;
    QString cls = QInputDialog::getText(this, "Type as IL2CPP class",
        "Class name (e.g. UnityEngine.Vector3 or Player):", QLineEdit::Normal, "", &ok);
    if (!ok || cls.trimmed().isEmpty()) return;

    QApplication::setOverrideCursor(Qt::WaitCursor);
    auto layout = ce::resolveIl2CppForProcess(*proc_);
    QApplication::restoreOverrideCursor();
    if (!layout.ok) {
        QMessageBox::warning(this, "IL2CPP", QString::fromStdString(layout.error));
        return;
    }
    const std::string want = cls.trimmed().toStdString();
    const ce::Il2CppClassLayout* found = nullptr;
    for (const auto& c : layout.classes) if (c.fullName() == want) { found = &c; break; }
    if (!found)
        for (const auto& c : layout.classes) if (c.name == want) { found = &c; break; }
    if (!found) {
        QMessageBox::warning(this, "IL2CPP", "Class not found: " + cls);
        return;
    }

    // Lay the class's instance fields over the struct: names at their offsets,
    // size from the class. Copy-as-C++ / Save capture the full field set; the live
    // 8-byte-row view labels the fields that land on a row start.
    ce::StructureDefinition def = ce::il2cppClassToStructure(*found);
    fieldNames_.clear();
    for (const auto& f : def.fields)
        fieldNames_[static_cast<int>(f.offset)] = QString::fromStdString(f.name);
    if (def.size > 0) {
        structSize_ = std::max(8, (static_cast<int>(def.size) + 7) / 8 * 8);
        if (sizeSpin_) sizeSpin_->setValue(structSize_);
    }
    if (baseAddr_) populateTable();
}

void StructureDissector::onTypeAsCStruct() {
    if (!proc_) { QMessageBox::information(this, "DWARF", "No target process."); return; }
    if (!ce::DwarfInfo::available()) {
        QMessageBox::information(this, "DWARF", "This build has no libdw (DWARF) support.");
        return;
    }
    bool ok = false;
    QString name = QInputDialog::getText(this, "Type as C struct",
        "Struct name (from the target's debug info):", QLineEdit::Normal, "", &ok);
    if (!ok || name.trimmed().isEmpty()) return;

    QApplication::setOverrideCursor(Qt::WaitCursor);
    ce::DwarfRegistry reg;
    reg.loadFromProcess(*proc_);
    auto st = reg.structByName(name.trimmed().toStdString());
    QApplication::restoreOverrideCursor();
    if (!st) {
        QMessageBox::warning(this, "DWARF", "Struct not found (needs debug info): " + name);
        return;
    }
    ce::StructureDefinition def = ce::dwarfStructToStructure(*st);
    fieldNames_.clear();
    for (const auto& f : def.fields)
        fieldNames_[static_cast<int>(f.offset)] = QString::fromStdString(f.name);
    if (def.size > 0) {
        structSize_ = std::max(8, (static_cast<int>(def.size) + 7) / 8 * 8);
        if (sizeSpin_) sizeSpin_->setValue(structSize_);
    }
    if (baseAddr_) populateTable();
}

void StructureDissector::populateTable() {
    if (!proc_) return;

    cache_.resize(structSize_);
    auto r = proc_->read(baseAddr_, cache_.data(), structSize_);
    if (!r) return;
    // read() may report a partial count when the struct straddles an unmapped
    // page; only bytes [0, validBytes_) are real, the rest may be stale.
    validBytes_ = (int)std::min<size_t>(*r, (size_t)structSize_);

    // Compare mode: read every compare instance so we can flag rows that vary
    // across the set. Each instance tracks how many bytes are real: a partial
    // read (the struct straddles an unmapped page) leaves stale bytes past *cr,
    // which must not drive the row-diff highlight.
    compareCaches_.assign(compareAddrs_.size(), {});
    std::vector<int> compareValid(compareAddrs_.size(), 0);
    for (size_t k = 0; k < compareAddrs_.size(); ++k) {
        compareCaches_[k].resize(structSize_);
        auto cr = proc_->read(compareAddrs_[k], compareCaches_[k].data(), structSize_);
        compareValid[k] = cr ? (int)std::min<size_t>(*cr, (size_t)structSize_) : 0;
    }

    int rows = structSize_ / 8; // Show every 8 bytes
    table_->setRowCount(rows);

    for (int i = 0; i < rows; ++i) {
        int off = i * 8;
        const uint8_t* d = cache_.data() + off;

        table_->setItem(i, 0, new QTableWidgetItem(QString("+0x%1").arg(off, 2, 16, QChar('0'))));
        auto nit = fieldNames_.find(off);
        auto* nameItem = new QTableWidgetItem(nit != fieldNames_.end() ? nit->second : QString());
        nameItem->setForeground(ce::gui::editorPalette().label);  // theme-aware (was fixed green, invisible on white)
        table_->setItem(i, 1, nameItem);
        table_->setItem(i, 2, new QTableWidgetItem(formatValue(d, off, "hex")));
        table_->setItem(i, 3, new QTableWidgetItem(formatValue(d, off, "int8")));
        table_->setItem(i, 4, new QTableWidgetItem(formatValue(d, off, "int32")));
        table_->setItem(i, 5, new QTableWidgetItem(formatValue(d, off, "float")));
        table_->setItem(i, 6, new QTableWidgetItem(formatValue(d, off, "ptr")));

        // Highlight rows that differ from the base in any compare instance (only
        // where BOTH snapshots have real bytes, so stale tail bytes can't fake a
        // diff). This is the per-row form of the N-instance field detector.
        bool rowVaries = false;
        if (off + 8 <= validBytes_) {
            for (size_t k = 0; k < compareCaches_.size() && !rowVaries; ++k)
                rowVaries = off + 8 <= compareValid[k] &&
                    std::memcmp(d, compareCaches_[k].data() + off, 8) != 0;
        }
        if (rowVaries) {
            // "Changed since base" highlight: a deep red on dark, a soft red on
            // light, so the default (theme) text stays readable on top of it.
            const QColor changedBg = ce::gui::isDarkTheme()
                ? QColor(0x5c, 0x25, 0x25) : QColor(0xff, 0xd6, 0xd6);
            for (int c = 0; c < table_->columnCount(); ++c)
                if (auto* it = table_->item(i, c))
                    it->setBackground(changedBg);
        }
    }
}


void StructureDissector::onCopyAsCpp() {
    if (fieldNames_.empty()) {
        QMessageBox::information(this, "Copy as C++",
            "Name some fields first (double-click a row to name the offset).");
        return;
    }
    ce::StructureDefinition def;
    def.name = "DissectedStruct";
    def.size = cache_.size();
    for (const auto& [off, name] : fieldNames_) {
        ce::StructureField f;
        f.name = name.toStdString();
        f.offset = (size_t)off;
        f.type = (off >= 0 && off < (int)cache_.size())
            ? guessType(cache_.data() + off, off) : ce::ValueType::Int32;
        switch (f.type) {
            case ce::ValueType::Byte:  f.size = 1; break;
            case ce::ValueType::Int16: f.size = 2; break;
            case ce::ValueType::Int64:
            case ce::ValueType::Double:
            case ce::ValueType::Pointer: f.size = 8; break;
            default: f.size = 4; break;
        }
        def.fields.push_back(f);
    }
    QString cpp = QString::fromStdString(ce::generateCppStruct(def));
    QApplication::clipboard()->setText(cpp);
    QMessageBox::information(this, "Copy as C++",
        "C++ struct copied to clipboard:\n\n" + cpp);
}

} // namespace ce::gui
