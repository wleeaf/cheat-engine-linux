#pragma once

#include "platform/process_api.hpp"
#include <QComboBox>
#include <QLabel>
#include <QMainWindow>
#include <QTableWidget>
#include <QTabWidget>

namespace ce::gui {

class StackViewWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit StackViewWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

private:
    void populateThreads();
    void refreshStack();

    ce::ProcessHandle* proc_;
    QComboBox* threadCombo_;
    QLabel* statusLabel_;
    QTabWidget* tabs_;
    QTableWidget* stackTable_;
    QTableWidget* traceTable_;
};

} // namespace ce::gui
