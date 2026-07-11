#pragma once

#include "platform/process_api.hpp"
#include <QComboBox>
#include <QLabel>
#include <QMainWindow>
#include <QTableWidget>

namespace ce::gui {

class RegisterEditorWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit RegisterEditorWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

private:
    void populateThreads();
    void refreshRegisters();
    void refreshFloatingPointRegisters(pid_t tid);
    void applyRegisters();

    ce::ProcessHandle* proc_;
    QComboBox* threadCombo_;
    QLabel* statusLabel_;
    QTableWidget* table_;
    QTableWidget* fpTable_;
    ce::CpuContext context_{};
};

} // namespace ce::gui
