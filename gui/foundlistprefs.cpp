#include "gui/foundlistprefs.hpp"

#include "gui/theme.hpp"

#include <QCheckBox>
#include <QColorDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QVBoxLayout>

#include <algorithm>

namespace ce::gui {

FoundListOptions FoundListOptions::load() {
    QSettings settings;
    FoundListOptions options;
    const auto palette = editorPalette();
    options.normal = settings.value("foundlist/normalColor", QColor()).value<QColor>();
    options.changed = settings.value("foundlist/changedColor", palette.error).value<QColor>();
    options.staticAddress = settings.value("foundlist/staticColor", palette.success).value<QColor>();
    options.dynamicAddress = settings.value("foundlist/dynamicColor", QColor()).value<QColor>();
    options.background = settings.value("foundlist/backgroundColor", QColor()).value<QColor>();
    options.fontSize = std::clamp(settings.value("foundlist/fontSize", 0).toInt(), 0, 72);
    options.staticNotation = settings.value("foundlist/staticNotation", false).toBool();
    return options;
}

void FoundListOptions::save() const {
    QSettings settings;
    settings.setValue("foundlist/normalColor", normal);
    settings.setValue("foundlist/changedColor", changed);
    settings.setValue("foundlist/staticColor", staticAddress);
    settings.setValue("foundlist/dynamicColor", dynamicAddress);
    settings.setValue("foundlist/backgroundColor", background);
    settings.setValue("foundlist/fontSize", fontSize);
    settings.setValue("foundlist/staticNotation", staticNotation);
}

FoundListPreferencesDialog::FoundListPreferencesDialog(QWidget* parent)
    : QDialog(parent), options_(FoundListOptions::load()) {
    setWindowTitle(tr("Foundlist Customizer"));
    auto* layout = new QVBoxLayout(this);
    auto* form = new QFormLayout;
    addColorRow(form, tr("Normal value"), options_.normal, true);
    addColorRow(form, tr("Changed value"), options_.changed, false);
    addColorRow(form, tr("Static"), options_.staticAddress, false);
    addColorRow(form, tr("Dynamic"), options_.dynamicAddress, true);
    addColorRow(form, tr("Background color"), options_.background, true);
    fontSize_ = new QSpinBox(this);
    fontSize_->setRange(0, 72);
    fontSize_->setSpecialValueText(tr("(list font)"));
    fontSize_->setValue(options_.fontSize);
    form->addRow(tr("Override font size"), fontSize_);
    layout->addLayout(form);
    staticNotation_ = new QCheckBox(tr("Show static addresses using their static notation"), this);
    staticNotation_->setChecked(options_.staticNotation);
    layout->addWidget(staticNotation_);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        options_.fontSize = fontSize_->value();
        options_.staticNotation = staticNotation_->isChecked();
        options_.save();
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

void FoundListPreferencesDialog::addColorRow(QFormLayout* form, const QString& label, QColor& color, bool clearable) {
    auto* row = new QHBoxLayout;
    auto* button = new QPushButton(this);
    auto show = [button](const QColor& c) {
        button->setText(c.isValid() ? c.name() : tr("(theme)"));
        button->setStyleSheet(c.isValid() ? QString("color: %1;").arg(c.name()) : QString());
    };
    show(color);
    connect(button, &QPushButton::clicked, this, [this, &color, show]() {
        const QColor chosen = QColorDialog::getColor(color.isValid() ? color : Qt::white, this);
        if (chosen.isValid()) { color = chosen; show(color); }
    });
    row->addWidget(button, 1);
    if (clearable) {
        auto* clear = new QPushButton(tr("Theme"), this);
        connect(clear, &QPushButton::clicked, this, [&color, show]() { color = QColor(); show(color); });
        row->addWidget(clear);
    }
    form->addRow(label, row);
}

} // namespace ce::gui
