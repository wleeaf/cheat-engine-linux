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
    // CE has no separate "Unicode String" type: a Unicode string is the String type
    // with the Unicode box ticked, so map an incoming UnicodeString onto String+box.
    bool startUnicode = (type == ce::ValueType::UnicodeString);
    if (startUnicode)
        for (int i = 0; i < (int)(sizeof(kTypes) / sizeof(kTypes[0])); ++i)
            if (kTypes[i].type == ce::ValueType::String) { sel = i; break; }
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
    unicodeCheck_->setChecked(startUnicode);
    flags->addWidget(pointerCheck_);
    flags->addWidget(hexCheck_);
    flags->addWidget(signedCheck_);
    flags->addWidget(unicodeCheck_);
    flags->addStretch();
    v->addLayout(flags);

    // The Length field and the Unicode box only apply to certain types (CE shows
    // edtSize for String/Array and cbunicode only for String); keep them in sync.
    connect(typeCombo_, &QComboBox::currentIndexChanged, this, [this](int) { syncFlagState(); });
    syncFlagState();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

QString ChangeAddressDialog::address() const { return addrEdit_->text().trimmed(); }
ce::ValueType ChangeAddressDialog::valueType() const {
    int i = typeCombo_->currentIndex();
    ce::ValueType t = (i >= 0 && i < (int)(sizeof(kTypes) / sizeof(kTypes[0])))
                          ? kTypes[i].type : ce::ValueType::Int32;
    // Unicode is a modifier on the String type (CE cbunicode), not its own entry.
    if (t == ce::ValueType::String && unicodeCheck_->isChecked())
        return ce::ValueType::UnicodeString;
    return t;
}
bool ChangeAddressDialog::showHex() const { return hexCheck_->isChecked(); }
bool ChangeAddressDialog::isUnicode() const { return unicodeCheck_->isChecked(); }
bool ChangeAddressDialog::isPointer() const { return pointerCheck_->isChecked(); }
bool ChangeAddressDialog::isSigned() const { return signedCheck_->isChecked(); }
int ChangeAddressDialog::length() const { return lengthEdit_->text().toInt(); }

void ChangeAddressDialog::syncFlagState() {
    int i = typeCombo_->currentIndex();
    ce::ValueType base = (i >= 0 && i < (int)(sizeof(kTypes) / sizeof(kTypes[0])))
                             ? kTypes[i].type : ce::ValueType::Int32;
    bool isString = (base == ce::ValueType::String);
    lengthEdit_->setEnabled(isString || base == ce::ValueType::ByteArray);
    unicodeCheck_->setEnabled(isString);   // CE only offers Unicode for String
}

void ChangeAddressDialog::setTypeIndexForTest(int i) { typeCombo_->setCurrentIndex(i); }
void ChangeAddressDialog::setUnicodeForTest(bool on) { unicodeCheck_->setChecked(on); }
void ChangeAddressDialog::setLengthForTest(int n) { lengthEdit_->setText(QString::number(n)); }
bool ChangeAddressDialog::unicodeCheckedForTest() const { return unicodeCheck_->isChecked(); }
bool ChangeAddressDialog::unicodeEnabledForTest() const { return unicodeCheck_->isEnabled(); }

}  // namespace ce::gui
