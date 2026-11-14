#include "gui/structuredissectorconfig.hpp"

#include "gui/theme.hpp"

#include <QCheckBox>
#include <QColorDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QVBoxLayout>

#include <algorithm>

namespace ce::gui {

StructureDissectorOptions StructureDissectorOptions::load() {
    StructureDissectorOptions options;
    QSettings settings;
    // The defaults are the colours the dissector always used.
    const QColor differentDefault = isDarkTheme() ? QColor(0xf3, 0x8b, 0xa8) : QColor(0xc0, 0x00, 0x00);
    options.different = settings.value("structdissect/differentColor", differentDefault).value<QColor>();
    options.equal = settings.value("structdissect/equalColor", QColor()).value<QColor>();
    options.defaultSize = std::clamp(settings.value("structdissect/defaultSize", 256).toInt(), 8, 8192);
    options.hexFields = settings.value("structdissect/hexFields", false).toBool();
    return options;
}

void StructureDissectorOptions::save() const {
    QSettings settings;
    settings.setValue("structdissect/differentColor", different);
    settings.setValue("structdissect/equalColor", equal);
    settings.setValue("structdissect/defaultSize", defaultSize);
    settings.setValue("structdissect/hexFields", hexFields);
}

StructureDissectorConfigDialog::StructureDissectorConfigDialog(QWidget* parent)
    : QDialog(parent), options_(StructureDissectorOptions::load()) {
    setWindowTitle(tr("Dissect Data Config"));
    auto* layout = new QVBoxLayout(this);

    auto* colors = new QGroupBox(tr("Colors"), this);
    auto* colorForm = new QFormLayout(colors);
    equalButton_ = new QPushButton(colors);
    differentButton_ = new QPushButton(colors);
    colorForm->addRow(tr("Equal:"), equalButton_);
    colorForm->addRow(tr("Different:"), differentButton_);
    auto* clearEqual = new QPushButton(tr("No colour for equal values"), colors);
    colorForm->addRow(QString(), clearEqual);
    showColor(equalButton_, options_.equal);
    showColor(differentButton_, options_.different);
    connect(equalButton_, &QPushButton::clicked, this, [this]() { pickColor(options_.equal, equalButton_); });
    connect(differentButton_, &QPushButton::clicked, this, [this]() { pickColor(options_.different, differentButton_); });
    connect(clearEqual, &QPushButton::clicked, this, [this]() {
        options_.equal = QColor();
        showColor(equalButton_, options_.equal);
    });
    layout->addWidget(colors);

    auto* defaults = new QGroupBox(tr("Default options for new structures"), this);
    auto* defaultForm = new QFormLayout(defaults);
    sizeSpin_ = new QSpinBox(defaults);
    sizeSpin_->setRange(8, 8192);
    sizeSpin_->setSingleStep(8);
    sizeSpin_->setValue(options_.defaultSize);
    defaultForm->addRow(tr("Structure size:"), sizeSpin_);
    hexCheck_ = new QCheckBox(tr("Default to hexadecimal for new integer entries"), defaults);
    hexCheck_->setChecked(options_.hexFields);
    defaultForm->addRow(hexCheck_);
    layout->addWidget(defaults);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        options_.defaultSize = sizeSpin_->value() / 8 * 8;
        options_.hexFields = hexCheck_->isChecked();
        options_.save();
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

void StructureDissectorConfigDialog::pickColor(QColor& color, QPushButton* button) {
    const QColor chosen = QColorDialog::getColor(color.isValid() ? color : Qt::white, this);
    if (!chosen.isValid()) return;
    color = chosen;
    showColor(button, color);
}

void StructureDissectorConfigDialog::showColor(QPushButton* button, const QColor& color) {
    if (!color.isValid()) {
        button->setText(tr("(none)"));
        button->setStyleSheet({});
        return;
    }
    button->setText(color.name());
    button->setStyleSheet(QString("color: %1;").arg(color.name()));
}

} // namespace ce::gui
