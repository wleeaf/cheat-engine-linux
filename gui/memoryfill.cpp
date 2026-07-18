#include "gui/memoryfill.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QFont>
#include <QMessageBox>
#include <cstring>

namespace ce::gui {

MemoryFillDialog::MemoryFillDialog(ProcessHandle* proc, uintptr_t startAddr, QWidget* parent)
    : QDialog(parent), proc_(proc) {
    setWindowTitle("Fill Memory");
    resize(350, 150);

    auto* layout = new QVBoxLayout(this);

    // A form layout keeps the three labels in one aligned column (the previous
    // per-row HBoxes left the fields at ragged left edges).
    auto* form = new QFormLayout;
    addrEdit_ = new QLineEdit(QString("0x%1").arg(startAddr, 0, 16));
    addrEdit_->setFont(QFont("Monospace", 10));
    form->addRow("Start address:", addrEdit_);

    sizeEdit_ = new QLineEdit("256");
    form->addRow("Size (bytes):", sizeEdit_);

    valueEdit_ = new QLineEdit("00");
    valueEdit_->setFont(QFont("Monospace", 10));
    form->addRow("Fill byte (hex):", valueEdit_);
    layout->addLayout(form);

    auto* btnRow = new QHBoxLayout;
    auto* fillBtn = new QPushButton("Fill");
    connect(fillBtn, &QPushButton::clicked, this, &MemoryFillDialog::onFill);
    auto* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    btnRow->addStretch();
    btnRow->addWidget(fillBtn);
    btnRow->addWidget(cancelBtn);
    layout->addLayout(btnRow);
}

void MemoryFillDialog::onFill() {
    if (!proc_) return;
    bool ok;
    uintptr_t addr = addrEdit_->text().toULongLong(&ok, 16);
    if (!ok) return;
    size_t size = sizeEdit_->text().toULongLong(&ok, 0);
    if (!ok || size == 0) return;
    constexpr size_t kMaxFillSize = 1u << 28; // 256 MiB, matches saveRegionToFile cap
    if (size > kMaxFillSize) {
        QMessageBox::warning(this, "Fill Memory",
            QString("Fill size too large (max %1 bytes).").arg(kMaxFillSize));
        return;
    }
    uint8_t fillByte = (uint8_t)valueEdit_->text().toUInt(&ok, 16);
    if (!ok) fillByte = 0;

    std::vector<uint8_t> buf(size, fillByte);
    auto r = proc_->write(addr, buf.data(), buf.size());
    if (r)
        QMessageBox::information(this, "Fill Memory", QString("Filled %1 bytes at 0x%2 with 0x%3")
            .arg(size).arg(addr, 0, 16).arg(fillByte, 2, 16, QChar('0')));
    else
        QMessageBox::warning(this, "Fill Memory", "Write failed");
    accept();
}

} // namespace ce::gui
