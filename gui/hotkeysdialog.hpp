#pragma once
/// Set/Change hotkeys of one address list record (Cheat Engine's HotKeyForm):
/// any number of hotkeys, each with an action (toggle, activate, deactivate,
/// set, increase or decrease the value), a value where the action takes one,
/// and an optional description.

#include <QDialog>
#include <QList>
#include <QString>

class QComboBox;
class QKeySequenceEdit;
class QLineEdit;
class QPushButton;
class QTableWidget;

namespace ce::gui {

struct HotkeyBinding {
    // Cheat Engine's action codes (mrh*), as cheat tables store them.
    enum Action {
        ToggleActivation = 0,
        ToggleActivationAllowIncrease = 1,
        ToggleActivationAllowDecrease = 2,
        Activate = 3,
        Deactivate = 4,
        SetValue = 5,
        IncreaseValue = 6,
        DecreaseValue = 7,
    };
    int action = ToggleActivation;
    QString keys;          // QKeySequence portable text
    QString value;         // the value to set, or the step to increase/decrease by
    QString description;

    static QString actionName(int action);
    static bool takesValue(int action) { return action >= SetValue; }
    bool operator==(const HotkeyBinding&) const = default;
};

class HotkeysDialog : public QDialog {
    Q_OBJECT
public:
    HotkeysDialog(const QString& record, QList<HotkeyBinding> hotkeys, QWidget* parent = nullptr);
    QList<HotkeyBinding> hotkeys() const { return hotkeys_; }

private:
    void refreshTable();
    void loadEditor(int row);
    void storeEditor();

    QList<HotkeyBinding> hotkeys_;
    QTableWidget* table_ = nullptr;
    QComboBox* actionCombo_ = nullptr;
    QKeySequenceEdit* keysEdit_ = nullptr;
    QLineEdit* valueEdit_ = nullptr;
    QLineEdit* descriptionEdit_ = nullptr;
    QPushButton* applyButton_ = nullptr;
    QPushButton* deleteButton_ = nullptr;
    int editing_ = -1;   // row being edited, -1 for a new hotkey
};

} // namespace ce::gui
