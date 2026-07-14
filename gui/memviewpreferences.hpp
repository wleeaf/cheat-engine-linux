#pragma once
// Disassembler Preferences — Cheat Engine's frmMemviewPreferencesUnit: font +
// color scheme + jumpline appearance for the disassembler. Persists to QSettings
// under "disasm/"; the Memory Browser's disassembler reads them back.

#include <QDialog>
#include <QColor>
#include <QFont>

class QLineEdit;
class QPushButton;
class QComboBox;

namespace ce::gui {

class MemviewPreferences : public QDialog {
    Q_OBJECT
public:
    explicit MemviewPreferences(QWidget* parent = nullptr);

signals:
    void applied();   // settings written — the disassembler should reload

private:
    QPushButton* colorButton(const QString& key, const QColor& def);
    void apply();

    QFont font_;
    QPushButton* fontBtn_;
    QComboBox* colorGroup_;
    QLineEdit* jlThickness_;
    QLineEdit* jlSpacing_;
    QLineEdit* spaceAbove_;
    QLineEdit* spaceBelow_;
};

}  // namespace ce::gui
