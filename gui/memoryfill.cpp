#include "gui/memoryfill.hpp"
#include "gui/theme.hpp"
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
    setWindowTitle(tr("Fill Memory"));
    resize(350, 150);

    auto* layout = new QVBoxLayout(this);

    // A form layout keeps the three labels in one aligned column (the previous
    // per-row HBoxes left the fields at ragged left edges).
    auto* form = new QFormLayout;
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    addrEdit_ = new QLineEdit(QString("0x%1").arg(startAddr, 0, 16));
    addrEdit_->setFont(monospaceFont());
    form->addRow(tr("Start address:"), addrEdit_);

    sizeEdit_ = new QLineEdit("256");
    form->addRow(tr("Size (bytes):"), sizeEdit_);

    valueEdit_ = new QLineEdit("00");
    valueEdit_->setFont(monospaceFont());
    form->addRow(tr("Fill byte (hex):"), valueEdit_);
    layout->addLayout(form);

    auto* btnRow = new QHBoxLayout;
    auto* fillBtn = new QPushButton(tr("Fill"));
    fillBtn->setObjectName("primaryButton");
    connect(fillBtn, &QPushButton::clicked, this, &MemoryFillDialog::onFill);
    auto* cancelBtn = new QPushButton(tr("Cancel"));
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
    if (!ok) { QMessageBox::warning(this, tr("Fill Memory"), tr("Enter a valid hexadecimal start address.")); return; }
    size_t size = sizeEdit_->text().toULongLong(&ok, 0);
    if (!ok || size == 0) { QMessageBox::warning(this, tr("Fill Memory"), tr("Enter a positive size in bytes.")); return; }
    constexpr size_t kMaxFillSize = 1u << 28; // 256 MiB, matches saveRegionToFile cap
    if (size > kMaxFillSize) {
        QMessageBox::warning(this, tr("Fill Memory"),
            tr("Fill size too large (max %1 bytes).").arg(kMaxFillSize));
        return;
    }
    unsigned int parsedByte = valueEdit_->text().toUInt(&ok, 16);
    if (!ok || parsedByte > 0xff) {
        QMessageBox::warning(this, tr("Fill Memory"), tr("Enter a hexadecimal byte from 00 to FF."));
        valueEdit_->setFocus(); valueEdit_->selectAll();
        return;
    }
    uint8_t fillByte = static_cast<uint8_t>(parsedByte);

    std::vector<uint8_t> buf(size, fillByte);
    auto r = proc_->write(addr, buf.data(), buf.size());
    if (r && *r == buf.size()) {
        QMessageBox::information(this, tr("Fill Memory"), tr("Filled %1 bytes at 0x%2 with 0x%3")
            .arg(size).arg(addr, 0, 16).arg(fillByte, 2, 16, QChar('0')));
        accept();
    } else
        QMessageBox::warning(this, tr("Fill Memory"), r ? tr("Only %1 of %2 bytes were written.").arg(*r).arg(size)
                                                   : tr("Write failed."));
}

} // namespace ce::gui
