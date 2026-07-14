#pragma once
// Change address — Cheat Engine's formAddressChangeUnit: edit an address-list
// entry's address (or pointer expression), value type, and display flags.

#include "core/types.hpp"

#include <QDialog>
#include <QString>

class QLineEdit;
class QComboBox;
class QCheckBox;
class QLabel;

namespace ce::gui {

class ChangeAddressDialog : public QDialog {
    Q_OBJECT
public:
    ChangeAddressDialog(const QString& address, ce::ValueType type, bool showHex,
                        int length, QWidget* parent = nullptr);

    QString address() const;
    ce::ValueType valueType() const;
    bool showHex() const;
    int length() const;      // for String / Array of byte

private:
    QLineEdit* addrEdit_;
    QComboBox* typeCombo_;
    QCheckBox* hexCheck_;
    QCheckBox* signedCheck_;
    QCheckBox* unicodeCheck_;
    QCheckBox* pointerCheck_;
    QLineEdit* lengthEdit_;
};

}  // namespace ce::gui
