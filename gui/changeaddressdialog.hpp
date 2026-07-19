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
    ce::ValueType valueType() const;   // folds the Unicode box into String -> UnicodeString
    bool showHex() const;
    bool isUnicode() const;
    bool isPointer() const;
    bool isSigned() const;
    int length() const;      // for String / Array of byte

    // Test hooks (offscreen smoke): drive the flag/type state and read it back.
    void setTypeIndexForTest(int i);
    void setUnicodeForTest(bool on);
    void setLengthForTest(int n);
    bool unicodeCheckedForTest() const;
    bool unicodeEnabledForTest() const;

private:
    void syncFlagState();    // enable Unicode only for String; length only for String/Array
    QLineEdit* addrEdit_;
    QComboBox* typeCombo_;
    QCheckBox* hexCheck_;
    QCheckBox* signedCheck_;
    QCheckBox* unicodeCheck_;
    QCheckBox* pointerCheck_;
    QLineEdit* lengthEdit_;
};

}  // namespace ce::gui
