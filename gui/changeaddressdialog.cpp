#include "gui/changeaddressdialog.hpp"
#include "core/ct_file.hpp"
#include "core/value_transform.hpp"
#include "core/expression.hpp"
#include "platform/process_api.hpp"

#include <QFormLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QSignalBlocker>

#include <algorithm>

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
                                         bool showHex, int length, QWidget* parent,
                                         bool showSigned, ce::ProcessHandle* proc)
    : QDialog(parent), proc_(proc) {
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
    signedCheck_->setChecked(showSigned);
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

    // Pointer editor (CE cbPointer): a base address plus an offset chain. Hidden until
    // "Pointer" is ticked; the address field then shows the composed [[base]+..] chain.
    pointerBox_ = new QWidget;
    auto* pv = new QVBoxLayout(pointerBox_);
    pv->setContentsMargins(0, 0, 0, 0);
    auto* baseRow = new QHBoxLayout;
    baseRow->addWidget(new QLabel("Base:"));
    pointerBaseEdit_ = new QLineEdit;
    baseRow->addWidget(pointerBaseEdit_);
    pv->addLayout(baseRow);
    offsetsLayout_ = new QVBoxLayout;
    pv->addLayout(offsetsLayout_);
    auto* addOffBtn = new QPushButton("Add offset");
    pv->addWidget(addOffBtn, 0, Qt::AlignLeft);
    // Live resolution of the chain (CE shows the pointer resolving as you edit it).
    previewLabel_ = new QLabel;
    previewLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    pv->addWidget(previewLabel_);
    v->addWidget(pointerBox_);
    pointerBox_->setVisible(false);

    connect(addOffBtn, &QPushButton::clicked, this, [this]() { addOffsetRow(0); });
    connect(pointerBaseEdit_, &QLineEdit::textChanged, this, [this](const QString&) { recomposeAddress(); });
    connect(pointerCheck_, &QCheckBox::toggled, this, [this](bool on) { setPointerMode(on); });

    // If the incoming address is already a pointer chain, open in pointer mode with the
    // base and offsets populated (round-trips buildPointerExpression); otherwise seed the
    // base field so ticking "Pointer" starts from the current address.
    if (auto pp = ce::parsePointerExpression(address.toStdString())) {
        pointerBaseEdit_->setText(QString::fromStdString(pp->base));
        for (int64_t off : pp->offsets) addOffsetRow(off);
        setPointerMode(true);
    } else {
        pointerBaseEdit_->setText(address);
    }

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

QString ChangeAddressDialog::address() const {
    if (pointerCheck_->isChecked())
        return QString::fromStdString(
            ce::buildPointerExpression(pointerBaseEdit_->text().trimmed().toStdString(),
                                       collectOffsets()));
    return addrEdit_->text().trimmed();
}

std::vector<int64_t> ChangeAddressDialog::collectOffsets() const {
    std::vector<int64_t> offs;
    offs.reserve(offsetEdits_.size());
    for (auto* e : offsetEdits_) {
        QString q = e->text().trimmed();
        bool neg = false;
        if (q.startsWith('-')) { neg = true; q = q.mid(1); }
        else if (q.startsWith('+')) q = q.mid(1);
        if (q.startsWith("0x") || q.startsWith("0X")) q = q.mid(2);
        bool ok = false;
        qulonglong val = q.toULongLong(&ok, 16);
        offs.push_back(ok ? (neg ? -static_cast<int64_t>(val) : static_cast<int64_t>(val)) : 0);
    }
    return offs;
}

void ChangeAddressDialog::recomposeAddress() {
    if (!pointerCheck_->isChecked()) return;
    addrEdit_->setText(QString::fromStdString(
        ce::buildPointerExpression(pointerBaseEdit_->text().trimmed().toStdString(),
                                   collectOffsets())));
    updatePreview();
}

void ChangeAddressDialog::updatePreview() {
    if (!previewLabel_) return;
    if (!proc_ || !pointerCheck_->isChecked() ||
        pointerBaseEdit_->text().trimmed().isEmpty()) {
        previewLabel_->clear();
        return;
    }
    // Resolve the composed [[base]+..] chain live so the user sees whether it lands on
    // valid memory (CE resolves the pointer as you build it). A failed deref shows "??".
    std::string expr = ce::buildPointerExpression(
        pointerBaseEdit_->text().trimmed().toStdString(), collectOffsets());
    ce::ExpressionParser parser(proc_, nullptr);
    auto addr = parser.parse(expr);
    if (!addr || !*addr) {
        previewLabel_->setText(QStringLiteral("→ ?? (does not resolve)"));
        return;
    }
    QString txt = QStringLiteral("→ 0x%1").arg(*addr, 0, 16);
    // Also show the value the pointer lands on for fixed-width numeric types, so you
    // can confirm the chain reaches the value you expect (CE shows this too).
    QString valStr = previewValueAt(*addr);
    if (!valStr.isEmpty()) txt += " = " + valStr;
    previewLabel_->setText(txt);
}

QString ChangeAddressDialog::previewValueAt(unsigned long long addr) {
    ce::ValueType vt = valueType();
    switch (vt) {
        case ce::ValueType::Byte: case ce::ValueType::Int16:
        case ce::ValueType::Int32: case ce::ValueType::Int64: {
            int w = ce::scalarWidth(vt);
            uint64_t raw = 0;
            auto r = proc_->read((uintptr_t)addr, &raw, (size_t)w);
            if (!r || *r < (size_t)w) return {};
            return QString::fromStdString(ce::formatIntegerScalar(raw, w, isSigned(), showHex()));
        }
        case ce::ValueType::Float: {
            float f = 0; auto r = proc_->read((uintptr_t)addr, &f, 4);
            if (!r || *r < 4) return {};
            return QString::fromStdString(ce::formatFloatScalar(f, false));
        }
        case ce::ValueType::Double: {
            double d = 0; auto r = proc_->read((uintptr_t)addr, &d, 8);
            if (!r || *r < 8) return {};
            return QString::fromStdString(ce::formatFloatScalar(d, true));
        }
        case ce::ValueType::Pointer: {
            uint64_t p = 0; auto r = proc_->read((uintptr_t)addr, &p, 8);
            if (!r || *r < 8) return {};
            return QStringLiteral("0x%1").arg(p, 0, 16);
        }
        default: return {};   // String / Array of byte / etc: address only
    }
}

QString ChangeAddressDialog::previewTextForTest() const {
    return previewLabel_ ? previewLabel_->text() : QString();
}

void ChangeAddressDialog::addOffsetRow(long long value) {
    auto* row = new QWidget;
    auto* h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->addWidget(new QLabel("Offset:"));
    auto* edit = new QLineEdit;
    edit->setText(value < 0 ? "-" + QString::number(-value, 16) : QString::number(value, 16));
    h->addWidget(edit);
    auto* rm = new QPushButton("−");
    rm->setFixedWidth(28);
    h->addWidget(rm);
    offsetsLayout_->addWidget(row);
    offsetEdits_.push_back(edit);

    connect(edit, &QLineEdit::textChanged, this, [this](const QString&) { recomposeAddress(); });
    connect(rm, &QPushButton::clicked, this, [this, row, edit]() {
        offsetEdits_.erase(std::remove(offsetEdits_.begin(), offsetEdits_.end(), edit),
                           offsetEdits_.end());
        offsetsLayout_->removeWidget(row);
        row->deleteLater();
        recomposeAddress();
    });
    recomposeAddress();
}

void ChangeAddressDialog::setPointerMode(bool on) {
    { QSignalBlocker b(pointerCheck_); pointerCheck_->setChecked(on); }
    pointerBox_->setVisible(on);
    addrEdit_->setReadOnly(on);   // in pointer mode the address is composed, not typed
    if (on) recomposeAddress();
    updatePreview();              // clears the preview when leaving pointer mode
}
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
    signedCheck_->setEnabled(ce::isIntegerScalar(base));  // signed only for integer types
}

void ChangeAddressDialog::setTypeIndexForTest(int i) { typeCombo_->setCurrentIndex(i); }
void ChangeAddressDialog::setUnicodeForTest(bool on) { unicodeCheck_->setChecked(on); }
void ChangeAddressDialog::setLengthForTest(int n) { lengthEdit_->setText(QString::number(n)); }
bool ChangeAddressDialog::unicodeCheckedForTest() const { return unicodeCheck_->isChecked(); }
bool ChangeAddressDialog::unicodeEnabledForTest() const { return unicodeCheck_->isEnabled(); }
bool ChangeAddressDialog::signedEnabledForTest() const { return signedCheck_->isEnabled(); }
void ChangeAddressDialog::setPointerModeForTest(bool on) { setPointerMode(on); }
void ChangeAddressDialog::setPointerBaseForTest(const QString& base) {
    pointerBaseEdit_->setText(base); recomposeAddress();
}
void ChangeAddressDialog::addOffsetForTest(long long value) { addOffsetRow(value); }
int ChangeAddressDialog::offsetRowCountForTest() const { return (int)offsetEdits_.size(); }

}  // namespace ce::gui
