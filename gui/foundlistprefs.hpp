#pragma once
/// The scan result list's look (Cheat Engine's Foundlist Customizer): the
/// colours of normal, changed, static and dynamic entries, a background, a
/// font size, and whether a static address shows as module+offset. Kept in
/// QSettings under "foundlist/".

#include <QColor>
#include <QDialog>

class QCheckBox;
class QFormLayout;
class QPushButton;
class QSpinBox;

namespace ce::gui {

struct FoundListOptions {
    QColor normal;        // a value that did not change (invalid: the theme's text colour)
    QColor changed;       // a value that changed since the last refresh
    QColor staticAddress; // an address inside a module
    QColor dynamicAddress;// any other address (invalid: the theme's text colour)
    QColor background;    // invalid: the theme's background
    int fontSize = 0;     // points; 0 keeps the list font
    bool staticNotation = false;   // show module+offset for a static address

    /// The saved options; unset colours fall back to the theme's.
    static FoundListOptions load();
    void save() const;
};

class FoundListPreferencesDialog : public QDialog {
    Q_OBJECT
public:
    explicit FoundListPreferencesDialog(QWidget* parent = nullptr);
    FoundListOptions options() const { return options_; }

private:
    void addColorRow(QFormLayout* form, const QString& label, QColor& color, bool clearable);

    FoundListOptions options_;
    QSpinBox* fontSize_ = nullptr;
    QCheckBox* staticNotation_ = nullptr;
};

} // namespace ce::gui
