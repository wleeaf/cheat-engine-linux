#include "gui/memviewpreferences.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QColorDialog>
#include <QFontDialog>
#include <QSettings>

namespace ce::gui {

// A color swatch button bound to a QSettings key (defaults match the current
// disassembler palette). Clicking picks a new color; the swatch updates and the
// value is written on Apply (the button carries the pending color in a property).
QPushButton* MemviewPreferences::colorButton(const QString& key, const QColor& def) {
    QSettings s;
    QColor cur = QColor(s.value("disasm/" + key, def.name()).toString());
    auto* btn = new QPushButton;
    btn->setProperty("prefKey", key);
    btn->setProperty("color", cur);
    auto paint = [btn]() {
        QColor c = btn->property("color").value<QColor>();
        btn->setStyleSheet(QString("background:%1; min-width:44px;").arg(c.name()));
    };
    paint();
    connect(btn, &QPushButton::clicked, this, [this, btn, paint]() {
        QColor c = QColorDialog::getColor(btn->property("color").value<QColor>(), this);
        if (c.isValid()) { btn->setProperty("color", c); paint(); }
    });
    return btn;
}

MemviewPreferences::MemviewPreferences(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Disassembler Preferences");
    QSettings s;
    font_.fromString(s.value("disasm/font", QFont("Monospace", 10).toString()).toString());

    auto* v = new QVBoxLayout(this);

    // GroupBox2 "Disassembler": font + color group selector.
    auto* gbDisasm = new QGroupBox("Disassembler");
    auto* dl = new QFormLayout(gbDisasm);
    fontBtn_ = new QPushButton("Change disassembler font");
    connect(fontBtn_, &QPushButton::clicked, this, [this]() {
        bool ok = false;
        QFont f = QFontDialog::getFont(&ok, font_, this);
        if (ok) font_ = f;
    });
    dl->addRow(fontBtn_);
    colorGroup_ = new QComboBox;
    colorGroup_->addItems({"Normal"});
    dl->addRow("Color group:", colorGroup_);
    v->addWidget(gbDisasm);

    // GroupBox1 "Normal": text colors.
    auto* gbNormal = new QGroupBox("Normal");
    auto* nl = new QFormLayout(gbNormal);
    nl->addRow("Default color", colorButton("colorDefault", QColor(0xcd, 0xd6, 0xf4)));
    nl->addRow("Register color", colorButton("colorRegister", QColor(0xa6, 0xe3, 0xa1)));
    nl->addRow("Symbol color", colorButton("colorSymbol", QColor(0xf9, 0xe2, 0xaf)));
    nl->addRow("Hexadecimal color", colorButton("colorHex", QColor(0x89, 0xb4, 0xfa)));
    v->addWidget(gbNormal);

    // GroupBox4 "Jumplines".
    auto* gbJump = new QGroupBox("Jumplines");
    auto* jl = new QFormLayout(gbJump);
    jl->addRow("Conditional jump color", colorButton("colorCondJump", QColor(0xfa, 0xb3, 0x87)));
    jl->addRow("Unconditional jump color", colorButton("colorJump", QColor(0x89, 0xb4, 0xfa)));
    jl->addRow("Call color", colorButton("colorCall", QColor(0xcb, 0xa6, 0xf7)));
    jlThickness_ = new QLineEdit(s.value("disasm/jlThickness", 1).toString());
    jl->addRow("Thickness", jlThickness_);
    jlSpacing_ = new QLineEdit(s.value("disasm/jlSpacing", 4).toString());
    jl->addRow("Spacing", jlSpacing_);
    v->addWidget(gbJump);

    // GroupBox5 "Space between lines".
    auto* gbSpace = new QGroupBox("Space between lines");
    auto* sl = new QFormLayout(gbSpace);
    spaceAbove_ = new QLineEdit(s.value("disasm/spaceAbove", 0).toString());
    sl->addRow("Above", spaceAbove_);
    spaceBelow_ = new QLineEdit(s.value("disasm/spaceBelow", 0).toString());
    sl->addRow("Below", spaceBelow_);
    v->addWidget(gbSpace);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Apply | QDialogButtonBox::Cancel);
    connect(buttons->button(QDialogButtonBox::Apply), &QPushButton::clicked, this, [this]() {
        apply();
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    v->addWidget(buttons);
}

void MemviewPreferences::apply() {
    QSettings s;
    s.setValue("disasm/font", font_.toString());
    for (auto* btn : findChildren<QPushButton*>()) {
        auto key = btn->property("prefKey").toString();
        if (!key.isEmpty())
            s.setValue("disasm/" + key, btn->property("color").value<QColor>().name());
    }
    s.setValue("disasm/jlThickness", jlThickness_->text().toInt());
    s.setValue("disasm/jlSpacing", jlSpacing_->text().toInt());
    s.setValue("disasm/spaceAbove", spaceAbove_->text().toInt());
    s.setValue("disasm/spaceBelow", spaceBelow_->text().toInt());
    emit applied();
}

}  // namespace ce::gui
