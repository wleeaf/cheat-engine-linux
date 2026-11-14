#pragma once
/// Structure Dissector options (Cheat Engine's "Dissect Data Config"): the
/// colours of compared values and the defaults of a new structure. Kept in
/// QSettings under "structdissect/".

#include <QColor>
#include <QDialog>

class QCheckBox;
class QPushButton;
class QSpinBox;

namespace ce::gui {

struct StructureDissectorOptions {
    QColor equal;            // a compared value equal in every instance (invalid: no colour)
    QColor different;        // a compared value that differs between instances
    int defaultSize = 256;   // bytes shown for a new structure
    bool hexFields = false;  // fields added to the address list show hexadecimal

    /// The saved options, with theme-aware default colours.
    static StructureDissectorOptions load();
    void save() const;
};

class StructureDissectorConfigDialog : public QDialog {
    Q_OBJECT
public:
    explicit StructureDissectorConfigDialog(QWidget* parent = nullptr);
    /// The options as edited (saved when the dialog is accepted).
    StructureDissectorOptions options() const { return options_; }

private:
    void pickColor(QColor& color, QPushButton* button);
    static void showColor(QPushButton* button, const QColor& color);

    StructureDissectorOptions options_;
    QPushButton* equalButton_ = nullptr;
    QPushButton* differentButton_ = nullptr;
    QSpinBox* sizeSpin_ = nullptr;
    QCheckBox* hexCheck_ = nullptr;
};

} // namespace ce::gui
