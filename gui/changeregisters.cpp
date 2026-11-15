#include "gui/changeregisters.hpp"
#include "gui/hexformat.hpp"

#include "core/cpu_registers.hpp"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QVBoxLayout>

namespace ce::gui {

namespace {
// The arithmetic flags of x86 RFLAGS/EFLAGS, in Cheat Engine's order.
constexpr std::array<const char*, 6> kFlagNames{"CF", "PF", "AF", "ZF", "SF", "OF"};
constexpr std::array<int, 6> kFlagBits{0, 2, 4, 6, 7, 11};

bool isX86(const CpuContext& context) {
    return context.architecture == CpuArchitecture::X86_64 || context.architecture == CpuArchitecture::X86_32;
}
} // namespace

bool RegisterChanges::empty() const {
    return registers.empty() && std::all_of(flags.begin(), flags.end(), [](int8_t f) { return f < 0; });
}

bool RegisterChanges::applyTo(CpuContext& context) const {
    bool known = true;
    for (const auto& [name, value] : registers) {
        const auto list = cpuRegisterValues(context);
        size_t row = 0;
        while (row < list.size() && list[row].name != name) ++row;
        if (row == list.size() || !setCpuRegisterValue(context, row, value)) known = false;
    }
    if (isX86(context))
        for (size_t i = 0; i < flags.size(); ++i) {
            if (flags[i] < 0) continue;
            const uint64_t bit = uint64_t(1) << kFlagBits[i];
            context.rflags = flags[i] ? (context.rflags | bit) : (context.rflags & ~bit);
        }
    return known;
}

QString RegisterChanges::summary() const {
    QStringList parts;
    for (const auto& [name, value] : registers)
        parts << QString("%1=%2").arg(QString::fromStdString(name)).arg(static_cast<qulonglong>(value), 0, 16);
    for (size_t i = 0; i < flags.size(); ++i)
        if (flags[i] >= 0) parts << QString("%1=%2").arg(QLatin1String(kFlagNames[i])).arg(flags[i]);
    return parts.join(", ");
}

ChangeRegistersDialog::ChangeRegistersDialog(uintptr_t address, const CpuContext& sample,
                                             const RegisterChanges& current, QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("Modify register(s) at %1").arg(static_cast<qulonglong>(address), 0, 16));
    auto* layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel(tr("Leave blank if you don't want to edit the register or flag"), this));
    auto* registers = new QGridLayout;
    int index = 0;
    for (const auto& reg : cpuRegisterValues(sample)) {
        // Segment and debug registers are not worth changing on every hit.
        if (reg.name.size() == 2 && reg.name[1] == 'S' && reg.name != "SP") continue;
        if (reg.name.starts_with("DR") || reg.name == "RFLAGS" || reg.name == "EFLAGS" || reg.name == "PSTATE") continue;
        auto* edit = new QLineEdit(this);
        edit->setPlaceholderText(tr("unchanged"));
        for (const auto& [name, value] : current.registers)
            if (name == reg.name) edit->setText(upperHex(value));
        const QString name = QString::fromStdString(reg.name);
        registers->addWidget(new QLabel(name, this), index / 3, (index % 3) * 2);
        registers->addWidget(edit, index / 3, (index % 3) * 2 + 1);
        fields_.push_back({name, edit});
        ++index;
    }
    layout->addLayout(registers);
    if (isX86(sample)) {
        auto* flagBox = new QGroupBox(tr("Flags"), this);
        auto* flagRow = new QHBoxLayout(flagBox);
        for (size_t i = 0; i < kFlagNames.size(); ++i) {
            flags_[i] = new QCheckBox(QLatin1String(kFlagNames[i]), flagBox);
            flags_[i]->setTristate(true);
            flags_[i]->setCheckState(current.flags[i] < 0 ? Qt::PartiallyChecked
                                     : current.flags[i] ? Qt::Checked : Qt::Unchecked);
            flags_[i]->setToolTip(tr("Checked sets the flag, unchecked clears it, partly checked leaves it"));
            flagRow->addWidget(flags_[i]);
        }
        layout->addWidget(flagBox);
    }
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        for (const auto& [name, edit] : fields_) {
            QString text = edit->text().trimmed();
            if (text.isEmpty()) continue;
            if (text.startsWith("0x", Qt::CaseInsensitive)) text.remove(0, 2);
            bool ok = false;
            text.toULongLong(&ok, 16);
            if (!ok) {
                QMessageBox::warning(this, windowTitle(), tr("%1 is not a hexadecimal value").arg(name));
                edit->setFocus();
                return;
            }
        }
        accept();
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    layout->addWidget(buttons);
}

RegisterChanges ChangeRegistersDialog::changes() const {
    RegisterChanges out;
    for (const auto& [name, edit] : fields_) {
        QString text = edit->text().trimmed();
        if (text.isEmpty()) continue;
        if (text.startsWith("0x", Qt::CaseInsensitive)) text.remove(0, 2);
        out.registers.emplace_back(name.toStdString(), text.toULongLong(nullptr, 16));
    }
    for (size_t i = 0; i < flags_.size(); ++i)
        if (flags_[i] && flags_[i]->checkState() != Qt::PartiallyChecked)
            out.flags[i] = flags_[i]->checkState() == Qt::Checked ? 1 : 0;
    return out;
}

} // namespace ce::gui
