#pragma once
// Change address — Cheat Engine's formAddressChangeUnit: edit an address-list
// entry's address (or pointer expression), value type, and display flags.

#include "core/types.hpp"

#include <QDialog>
#include <QString>

#include <cstdint>
#include <vector>

class QLineEdit;
class QComboBox;
class QCheckBox;
class QLabel;
class QWidget;
class QVBoxLayout;

namespace ce { class ProcessHandle; }

namespace ce::gui {

class ChangeAddressDialog : public QDialog {
    Q_OBJECT
public:
    ChangeAddressDialog(const QString& address, ce::ValueType type, bool showHex,
                        int length, QWidget* parent = nullptr, bool showSigned = true,
                        ce::ProcessHandle* proc = nullptr);

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
    bool signedEnabledForTest() const;
    void setPointerModeForTest(bool on);
    void setPointerBaseForTest(const QString& base);
    void addOffsetForTest(long long value);
    int  offsetRowCountForTest() const;
    QString previewTextForTest() const;

private:
    void syncFlagState();    // enable Unicode only for String; length only for String/Array
    void updatePreview();    // resolve the pointer chain live and show the target address
    QString previewValueAt(unsigned long long addr);   // formatted value at a resolved address
    void setPointerMode(bool on);              // CE cbPointer: reveal the base+offsets editor
    void addOffsetRow(long long value);        // append one offset row (hex, signed)
    void recomposeAddress();                   // rebuild the address field from base+offsets
    std::vector<int64_t> collectOffsets() const;
    QLineEdit* addrEdit_;
    QComboBox* typeCombo_;
    QCheckBox* hexCheck_;
    QCheckBox* signedCheck_;
    QCheckBox* unicodeCheck_;
    QCheckBox* pointerCheck_;
    QLineEdit* lengthEdit_;

    // Pointer editor (hidden unless "Pointer" is ticked): a base + an offset chain.
    QWidget* pointerBox_ = nullptr;
    QLineEdit* pointerBaseEdit_ = nullptr;
    QVBoxLayout* offsetsLayout_ = nullptr;
    std::vector<QLineEdit*> offsetEdits_;
    QLabel* previewLabel_ = nullptr;           // live "-> 0x...." of the resolved chain
    ce::ProcessHandle* proc_ = nullptr;        // for the live pointer resolution (may be null)
};

}  // namespace ce::gui
