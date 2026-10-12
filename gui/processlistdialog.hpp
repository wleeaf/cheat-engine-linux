#pragma once

#include <QDialog>
#include <QTreeWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QCheckBox>
#include <QLabel>

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
    QTreeWidget* processList_;
    QLineEdit* filterEdit_;
    QCheckBox* mineOnly_;
    QPushButton* openBtn_;
    QLabel* statusLabel_;
    pid_t selectedPid_ = 0;
    QString selectedName_;
};

} // namespace ce::gui
