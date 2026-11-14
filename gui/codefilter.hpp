#pragma once
/// Code Filter window (Cheat Engine's frmCodeFilter): load code addresses
/// (the CALLs or every instruction of a module, or a file of addresses), let
/// the game run with a one-shot breakpoint on each, then keep the ones that
/// did or did not execute.

#include "debug/code_filter.hpp"

#include <QMainWindow>

class QLabel;
class QListWidget;
class QPushButton;
class QTimer;

namespace ce::gui {

class CodeFilterWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit CodeFilterWindow(ProcessHandle* process, QWidget* parent = nullptr);
    ~CodeFilterWindow() override;

    /// For tests and scripts: load addresses directly.
    void setAddresses(const std::vector<uintptr_t>& addresses);
    std::vector<uintptr_t> addressesForTest() const { return filter_.addresses(); }

signals:
    void showInDisassembler(quint64 address);

private:
    void loadFromModule();
    void loadFromFile();
    void startFiltering();
    void stopFiltering();
    void keep(bool executed);
    void refreshList();
    void updateStatus();

    ProcessHandle* process_;
    CodeFilter filter_;
    QListWidget* list_ = nullptr;
    QLabel* status_ = nullptr;
    QLabel* executedLabel_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QPushButton* executedButton_ = nullptr;
    QPushButton* notExecutedButton_ = nullptr;
    QTimer* timer_ = nullptr;
};

} // namespace ce::gui
