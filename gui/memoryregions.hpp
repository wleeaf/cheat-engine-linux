#pragma once
#include "platform/process_api.hpp"
#include <QMainWindow>
#include <QTableWidget>

namespace ce::gui {

class MemoryRegionsWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MemoryRegionsWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);
signals:
    void navigateTo(uintptr_t addr);
private:
    void populate();
    ce::ProcessHandle* proc_;
    QTableWidget* table_;
};

} // namespace ce::gui
