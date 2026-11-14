#pragma once
/// "Change register at this location" (Cheat Engine's Modify register(s)
/// window): the registers and flags a breakpoint sets each time execution
/// reaches an address, then lets the program run on. A blank field or a
/// partially checked flag leaves that register or flag as it is.

#include "core/types.hpp"

#include <QDialog>
#include <QList>

#include <array>
#include <string>
#include <utility>
#include <vector>

class QCheckBox;
class QLineEdit;

namespace ce::gui {

struct RegisterChanges {
    std::vector<std::pair<std::string, uint64_t>> registers;   // name (as cpuRegisterValues names it), value
    std::array<int8_t, 6> flags{-1, -1, -1, -1, -1, -1};      // CF PF AF ZF SF OF: -1 keep, 0 clear, 1 set
    bool empty() const;
    /// Apply to `context`; returns false when a named register is unknown there.
    bool applyTo(CpuContext& context) const;
    /// "RAX=5, ZF=1" for the breakpoint list.
    QString summary() const;
};

class ChangeRegistersDialog : public QDialog {
    Q_OBJECT
public:
    /// `sample` gives the register set (its architecture); `current` prefills nothing.
    ChangeRegistersDialog(uintptr_t address, const CpuContext& sample, const RegisterChanges& current,
                          QWidget* parent = nullptr);
    RegisterChanges changes() const;

private:
    QList<QPair<QString, QLineEdit*>> fields_;
    std::array<QCheckBox*, 6> flags_{};
};

} // namespace ce::gui
