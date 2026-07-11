#pragma once
#include "platform/process_api.hpp"
#include <QDialog>
#include <QLineEdit>

namespace ce::gui {

class MemoryFillDialog : public QDialog {
    Q_OBJECT
public:
    explicit MemoryFillDialog(ce::ProcessHandle* proc, uintptr_t startAddr = 0, QWidget* parent = nullptr);
private slots:
    void onFill();
private:
    ce::ProcessHandle* proc_;
    QLineEdit* addrEdit_;
    QLineEdit* sizeEdit_;
    QLineEdit* valueEdit_;
};

} // namespace ce::gui
