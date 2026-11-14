#pragma once
/// Structure Compare (Cheat Engine's frmStructureCompare): two groups of
/// structure addresses, and the offsets (following pointers) whose element is
/// the same in every group 1 structure and different in every group 2 one,
/// for finding what tells, say, the player from the other characters.

#include <QMainWindow>

#include <cstdint>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QListWidget;
class QSpinBox;
class QTableWidget;

namespace ce { class ProcessHandle; }

namespace ce::gui {

class StructureCompareWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit StructureCompareWindow(ProcessHandle* process, QWidget* parent = nullptr);

    void addToGroup(int group, uintptr_t address);
    /// Run the comparison; returns the number of matches.
    int scan();
    QStringList resultPathsForTest() const;

private:
    std::vector<uintptr_t> groupAddresses(int group) const;
    void addAddressPrompt(int group);

    ProcessHandle* process_;
    QListWidget* groups_[2] = {nullptr, nullptr};
    QSpinBox* sizeSpin_ = nullptr;
    QComboBox* elementCombo_ = nullptr;
    QSpinBox* levelSpin_ = nullptr;
    QCheckBox* sameOnly_ = nullptr;
    QCheckBox* hex_ = nullptr;
    QLabel* info_ = nullptr;
    QTableWidget* results_ = nullptr;
};

} // namespace ce::gui
