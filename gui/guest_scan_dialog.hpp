#pragma once
/// Emulator guest-RAM scanner (docs/CHALLENGING_TARGETS.md block 2). When attached to a
/// recognized emulator, this scans the console game's guest memory in guest-address
/// space, with correct byte order for big-endian consoles. It reuses the same
/// core/guest_view.hpp primitives as `cescan guest-scan`, so the scan logic is shared
/// and already tested; this is just the GUI front end.

#include "platform/process_api.hpp"
#include "core/target_profile.hpp"
#include "core/types.hpp"

#include <QDialog>
#include <cstdint>
#include <vector>

class QComboBox;
class QLineEdit;
class QCheckBox;
class QPushButton;
class QLabel;
class QTableWidget;

namespace ce::gui {

class GuestScanDialog : public QDialog {
    Q_OBJECT
public:
    explicit GuestScanDialog(ce::ProcessHandle* proc, QWidget* parent = nullptr);

signals:
    // A guest result added to the cheat table, as its HOST address (base + guest), the
    // scan's value type, and whether the guest is big-endian.
    void addressSelected(uintptr_t hostAddr, ce::ValueType type, bool bigEndian,
                         const QString& description);

private slots:
    void onFirstScan();
    void onUnknownScan();
    void onNextScan();
    void onNewScan();
    void onAddToList();

private:
    void refreshResults();
    void beginScan();                 // freeze region/type/endian from the UI
    void narrowCompare(int op);       // op = ce::GuestCompare value
    ce::ValueType selectedType() const;

    ce::ProcessHandle* proc_;
    ce::TargetProfile profile_;

    QComboBox*    regionCombo_;
    QComboBox*    typeCombo_;
    QLineEdit*    valueEdit_;
    QCheckBox*    bigEndianCheck_;
    QPushButton*  firstBtn_;
    QPushButton*  unknownBtn_;
    QPushButton*  nextBtn_;
    QPushButton*  newBtn_;
    QPushButton*  changedBtn_;
    QPushButton*  unchangedBtn_;
    QPushButton*  increasedBtn_;
    QPushButton*  decreasedBtn_;
    QLabel*       statusLabel_;
    QTableWidget* resultsTable_;

    // Frozen once a scan starts, so narrowing uses the same view.
    std::vector<std::pair<uint64_t, uint64_t>> candidates_;  // (guest addr, value bits at last scan)
    std::vector<uint8_t> snapshot_;   // whole-region snapshot for an unknown-value scan
    bool      unknownMode_ = false;   // snapshot taken, no explicit candidates yet
    uintptr_t regionBase_ = 0;
    uintptr_t regionGuestBase_ = 0;   // console address of the region start (Dolphin), else 0
    uint64_t  regionSize_ = 0;
    ce::ValueType scanType_ = ce::ValueType::Int32;
    bool      scanBigEndian_ = false;
    bool      haveScan_ = false;
};

} // namespace ce::gui
