#pragma once
#include "debug/breakpoint_manager.hpp"
#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QTimer>

namespace ce::gui {

class BreakpointListWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit BreakpointListWindow(ce::BreakpointManager* mgr, QWidget* parent = nullptr);

private slots:
    void refresh();
    void onRemove();
    void onToggle();

private:
    ce::BreakpointManager* mgr_;
    QTableWidget* table_;
    QTimer* refreshTimer_;
};

} // namespace ce::gui
