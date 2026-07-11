#pragma once

#include <QDialog>
#include <QListWidget>
#include <QLineEdit>
#include <QTabWidget>

namespace ce::gui {

class ProcessListDialog : public QDialog {
    Q_OBJECT
public:
    explicit ProcessListDialog(QWidget* parent = nullptr);

    pid_t selectedPid() const { return selectedPid_; }
    QString selectedName() const { return selectedName_; }

private slots:
    void refreshList();
    void onAccept();
    void onFilter(const QString& text);

private:
    QTabWidget* tabs_;
    QListWidget* processList_;
    QLineEdit* filterEdit_;
    pid_t selectedPid_ = 0;
    QString selectedName_;
};

} // namespace ce::gui
