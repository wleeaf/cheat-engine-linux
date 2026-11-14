#pragma once
/// "Find out what addresses this instruction accesses" (Cheat Engine's Changed
/// Addresses window): a live list of the data addresses one instruction
/// touches, with a hit count and the current value of each, until Stop.
/// Includes the Commonality scanner, which compares the registers seen at two
/// groups of those addresses.

#include "core/types.hpp"
#include "debug/instruction_access.hpp"

#include <QList>
#include <QMainWindow>
#include <QSet>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTimer;

namespace ce { class ProcessHandle; }

namespace ce::gui {

class ChangedAddressesWindow : public QMainWindow {
    Q_OBJECT
public:
    ChangedAddressesWindow(ProcessHandle* process, uintptr_t instruction, QWidget* parent = nullptr);
    ~ChangedAddressesWindow() override;

    /// Stop monitoring and release the target (also on close).
    void stop();
    bool monitoring() const { return worker_.joinable() && !stopping_.load(); }

    /// For tests: wait until `count` addresses are listed (or the timeout).
    bool waitForAddressesForTest(int count, int timeoutMs);
    int rowCountForTest() const;
    QString valueTextForTest(int row) const;
    /// Registers equal within group 1 and different in group 2 (the scanner's rows).
    QStringList commonalitiesForTest(const QList<uintptr_t>& group1, const QList<uintptr_t>& group2) const;

signals:
    void browseRequested(quint64 address);
    void dissectRequested(QList<quint64> addresses);
    void addToAddressListRequested(quint64 address, int valueType);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    struct Record {
        int hits = 0;
        CpuContext context{};
    };
    void refresh();
    void showContextMenu(const QPoint& pos);
    QList<uintptr_t> selectedAddresses() const;
    ValueType displayType() const;
    QString valueText(uintptr_t address) const;
    void showRegisters(uintptr_t address);
    void changeValue(const QList<uintptr_t>& addresses);
    void scanForCommonalities();

    ProcessHandle* process_;
    uintptr_t instruction_;
    QLineEdit* codeAddress_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QComboBox* typeCombo_ = nullptr;
    QLabel* info_ = nullptr;
    QTableWidget* table_ = nullptr;
    QTimer* timer_ = nullptr;
    QString filter_;
    bool hex_ = false;
    bool signed_ = true;
    QSet<uintptr_t> group1_, group2_;

    mutable std::mutex mutex_;
    std::map<uintptr_t, Record> records_;   // guarded by mutex_
    std::string error_;                     // guarded by mutex_
    bool finished_ = false;                 // guarded by mutex_
    std::atomic<bool> stopping_{false};
    std::thread worker_;
};

} // namespace ce::gui
