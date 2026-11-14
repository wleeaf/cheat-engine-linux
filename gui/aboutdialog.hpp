#pragma once
/// Help > About: the version, the credits and the licenses of the components
/// the program is built from (Cheat Engine's About window is the model).

#include <QDialog>

class QTabWidget;

namespace ce::gui {

class AboutDialog : public QDialog {
    Q_OBJECT
public:
    explicit AboutDialog(QWidget* parent = nullptr);

    /// The text of the Credits tab, for tests.
    QString creditsTextForTest() const;

private:
    QTabWidget* tabs_ = nullptr;
    QString credits_;
};

} // namespace ce::gui
