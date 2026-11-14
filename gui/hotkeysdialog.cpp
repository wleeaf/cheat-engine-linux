#include "gui/hotkeysdialog.hpp"

#include <QComboBox>
#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QKeySequenceEdit>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace ce::gui {

QString HotkeyBinding::actionName(int action) {
    static const char* const names[] = {
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Toggle freeze"),
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Toggle freeze and allow increase"),
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Toggle freeze and allow decrease"),
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Freeze"),
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Unfreeze"),
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Set value to:"),
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Increase value with:"),
        QT_TRANSLATE_NOOP("ce::gui::HotkeysDialog", "Decrease value with:"),
    };
    return action >= 0 && action < 8 ? QCoreApplication::translate("ce::gui::HotkeysDialog", names[action]) : QString();
}

HotkeysDialog::HotkeysDialog(const QString& record, QList<HotkeyBinding> hotkeys, QWidget* parent)
    : QDialog(parent), hotkeys_(std::move(hotkeys)) {
    setWindowTitle(tr("Set/Change hotkey"));
    auto* layout = new QVBoxLayout(this);
    auto* title = new QLabel(record, this);
    title->setObjectName("pageTitle");
    layout->addWidget(title);

    table_ = new QTableWidget(0, 4, this);
    table_->setHorizontalHeaderLabels({tr("Hotkey"), tr("Action"), tr("Value"), tr("Description")});
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setStretchLastSection(true);
    layout->addWidget(table_, 1);

    auto* editor = new QFormLayout;
    keysEdit_ = new QKeySequenceEdit(this);
    auto* keysRow = new QHBoxLayout;
    keysRow->addWidget(keysEdit_, 1);
    auto* clearKeys = new QPushButton(tr("Clear"), this);
    keysRow->addWidget(clearKeys);
    editor->addRow(tr("Type the keys you want to set the hotkey to"), keysRow);
    actionCombo_ = new QComboBox(this);
    for (int action = 0; action < 8; ++action) actionCombo_->addItem(HotkeyBinding::actionName(action));
    valueEdit_ = new QLineEdit(this);
    auto* actionRow = new QHBoxLayout;
    actionRow->addWidget(actionCombo_);
    actionRow->addWidget(valueEdit_, 1);
    editor->addRow(tr("Action"), actionRow);
    descriptionEdit_ = new QLineEdit(this);
    descriptionEdit_->setPlaceholderText(tr("Used as the description when a trainer is generated"));
    editor->addRow(tr("Description (Optional)"), descriptionEdit_);
    layout->addLayout(editor);

    auto* rowButtons = new QHBoxLayout;
    auto* newButton = new QPushButton(tr("Create hotkey"), this);
    applyButton_ = new QPushButton(tr("Apply"), this);
    deleteButton_ = new QPushButton(tr("Delete"), this);
    rowButtons->addWidget(newButton);
    rowButtons->addWidget(applyButton_);
    rowButtons->addWidget(deleteButton_);
    rowButtons->addStretch();
    layout->addLayout(rowButtons);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    layout->addWidget(buttons);

    connect(clearKeys, &QPushButton::clicked, keysEdit_, &QKeySequenceEdit::clear);
    connect(actionCombo_, &QComboBox::currentIndexChanged, this, [this](int action) {
        valueEdit_->setEnabled(HotkeyBinding::takesValue(action));
    });
    connect(table_, &QTableWidget::currentCellChanged, this, [this](int row) { loadEditor(row); });
    connect(newButton, &QPushButton::clicked, this, [this]() {
        table_->clearSelection();
        loadEditor(-1);
        keysEdit_->setFocus();
    });
    connect(applyButton_, &QPushButton::clicked, this, &HotkeysDialog::storeEditor);
    connect(deleteButton_, &QPushButton::clicked, this, [this]() {
        if (editing_ < 0 || editing_ >= hotkeys_.size()) return;
        hotkeys_.removeAt(editing_);
        refreshTable();
        loadEditor(-1);
    });
    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        // A hotkey typed but not applied yet still counts, as in Cheat Engine.
        if (!keysEdit_->keySequence().isEmpty()) storeEditor();
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    refreshTable();
    loadEditor(hotkeys_.isEmpty() ? -1 : 0);
    resize(560, 380);
}

void HotkeysDialog::refreshTable() {
    table_->setRowCount(static_cast<int>(hotkeys_.size()));
    for (int row = 0; row < hotkeys_.size(); ++row) {
        const auto& hotkey = hotkeys_[row];
        table_->setItem(row, 0, new QTableWidgetItem(QKeySequence(hotkey.keys).toString(QKeySequence::NativeText)));
        table_->setItem(row, 1, new QTableWidgetItem(HotkeyBinding::actionName(hotkey.action)));
        table_->setItem(row, 2, new QTableWidgetItem(HotkeyBinding::takesValue(hotkey.action) ? hotkey.value : QString()));
        table_->setItem(row, 3, new QTableWidgetItem(hotkey.description));
    }
    table_->resizeColumnsToContents();
}

void HotkeysDialog::loadEditor(int row) {
    editing_ = row >= 0 && row < hotkeys_.size() ? row : -1;
    const HotkeyBinding hotkey = editing_ >= 0 ? hotkeys_[editing_] : HotkeyBinding{};
    keysEdit_->setKeySequence(QKeySequence(hotkey.keys));
    actionCombo_->setCurrentIndex(hotkey.action);
    valueEdit_->setText(hotkey.value);
    valueEdit_->setEnabled(HotkeyBinding::takesValue(hotkey.action));
    descriptionEdit_->setText(hotkey.description);
    applyButton_->setText(editing_ >= 0 ? tr("Apply") : tr("Add"));
    deleteButton_->setEnabled(editing_ >= 0);
}

void HotkeysDialog::storeEditor() {
    HotkeyBinding hotkey;
    hotkey.keys = keysEdit_->keySequence().toString(QKeySequence::PortableText);
    if (hotkey.keys.isEmpty()) return;
    hotkey.action = actionCombo_->currentIndex();
    hotkey.value = HotkeyBinding::takesValue(hotkey.action) ? valueEdit_->text().trimmed() : QString();
    hotkey.description = descriptionEdit_->text().trimmed();
    if (editing_ >= 0) hotkeys_[editing_] = hotkey;
    else hotkeys_.push_back(hotkey);
    const int row = editing_ >= 0 ? editing_ : static_cast<int>(hotkeys_.size()) - 1;
    refreshTable();
    table_->selectRow(row);
    loadEditor(row);
}

} // namespace ce::gui
