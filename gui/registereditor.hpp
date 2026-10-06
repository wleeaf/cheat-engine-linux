#pragma once

#include "debug/thread_inspection.hpp"
#include <optional>
#include <QComboBox>
#include <QLabel>
#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>

namespace ce::gui {

class RegisterEditorWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit RegisterEditorWindow(ce::ProcessHandle* proc, QWidget* parent = nullptr);

private:
    void populateThreads();
    void refreshRegisters();
    void displaySnapshot(ce::ThreadSnapshot snapshot);
    void applyRegisters();
    void refreshGdbRegisters();
    void applyGdbRegisters();

    ce::ProcessHandle* proc_;
    QComboBox* threadCombo_;
    QLabel* statusLabel_;
    QTableWidget* table_;
    QTableWidget* fpTable_;
    QPushButton* applyButton_;
    std::optional<ce::ThreadSnapshot> snapshot_;
};

} // namespace ce::gui
