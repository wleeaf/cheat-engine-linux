#include "gui/changeaddressdialog.hpp"

#include <QFormLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QDialogButtonBox>

namespace ce::gui {

// CE cbvarType order (formAddressChangeUnit).
static const struct { const char* label; ce::ValueType type; } kTypes[] = {
    {"Byte", ce::ValueType::Byte},
    {"2 Bytes", ce::ValueType::Int16},
    {"4 Bytes", ce::ValueType::Int32},
    {"8 Bytes", ce::ValueType::Int64},
    {"Float", ce::ValueType::Float},
    {"Double", ce::ValueType::Double},
    {"String", ce::ValueType::String},
    {"Array of byte", ce::ValueType::ByteArray},
    {"Pointer", ce::ValueType::Pointer},
};

ChangeAddressDialog::ChangeAddressDialog(const QString& address, ce::ValueType type,
                                         bool showHex, int length, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle("Change address");

    auto* v = new QVBoxLayout(this);
    auto* form = new QFormLayout;

    addrEdit_ = new QLineEdit(address);          // CE editAddress
    addrEdit_->setMinimumWidth(240);
    form->addRow("Address:", addrEdit_);

    typeCombo_ = new QComboBox;                   // CE cbvarType
    int sel = 2;                                  // default 4 Bytes
    for (int i = 0; i < (int)(sizeof(kTypes) / sizeof(kTypes[0])); ++i) {
        typeCombo_->addItem(kTypes[i].label);
        if (kTypes[i].type == type) sel = i;
    }
    typeCombo_->setCurrentIndex(sel);
    form->addRow("Type:", typeCombo_);

    lengthEdit_ = new QLineEdit(QString::number(length > 0 ? length : 1));  // CE edtSize
    form->addRow("Length:", lengthEdit_);          // CE lengthlabel — for String/Array
    v->addLayout(form);

    auto* flags = new QHBoxLayout;
    pointerCheck_ = new QCheckBox("Pointer");      // CE cbPointer
    hexCheck_     = new QCheckBox("Hexadecimal");  // CE cbHex
    hexCheck_->setChecked(showHex);
    signedCheck_  = new QCheckBox("Signed");       // CE cbSigned
    unicodeCheck_ = new QCheckBox("Unicode");      // CE cbunicode
    flags->addWidget(pointerCheck_);
    flags->addWidget(hexCheck_);
    flags->addWidget(signedCheck_);
    flags->addWidget(unicodeCheck_);
    flags->addStretch();
    v->addLayout(flags);

    // Length only applies to String / Array of byte (like CE, which shows edtSize
    // for those types); enable it accordingly.
    auto syncLength = [this]() {
        auto t = valueType();
        lengthEdit_->setEnabled(t == ce::ValueType::String || t == ce::ValueType::ByteArray);
    };
    connect(typeCombo_, &QComboBox::currentIndexChanged, this, [syncLength](int) { syncLength(); });
    syncLength();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

QString ChangeAddressDialog::address() const { return addrEdit_->text().trimmed(); }
ce::ValueType ChangeAddressDialog::valueType() const {
    int i = typeCombo_->currentIndex();
    return (i >= 0 && i < (int)(sizeof(kTypes) / sizeof(kTypes[0]))) ? kTypes[i].type
                                                                     : ce::ValueType::Int32;
}
bool ChangeAddressDialog::showHex() const { return hexCheck_->isChecked(); }
int ChangeAddressDialog::length() const { return lengthEdit_->text().toInt(); }

}  // namespace ce::gui
