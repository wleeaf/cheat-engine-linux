#pragma once
#include "platform/process_api.hpp"
#include <QMainWindow>
#include <QTableWidget>

namespace ce::gui {

class ThreadListWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit ThreadListWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);
private:
    void populate();
    ce::ProcessHandle* proc_;
    QTableWidget* table_;
};

} // namespace ce::gui
