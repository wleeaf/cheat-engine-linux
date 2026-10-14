#include "gui/processlistdialog.hpp"
#include "platform/linux/linux_process.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <unistd.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFont>
#include <QHeaderView>
#include <QKeySequence>
#include <sys/stat.h>
#include "gui/theme.hpp"

namespace ce::gui {

namespace {

enum Column { NameColumn, PidColumn, MemoryColumn, CommandColumn };
enum Role { PidRole = Qt::UserRole, NameRole, FilterRole, SortRole, MineRole, StartRole };

// Numeric columns sort by their number, not their text ("9 MiB" < "10 MiB").
class ProcessItem : public QTreeWidgetItem {
public:
    using QTreeWidgetItem::QTreeWidgetItem;
    bool operator<(const QTreeWidgetItem& other) const override {
        const int column = treeWidget() ? treeWidget()->sortColumn() : NameColumn;
        if (column == PidColumn || column == MemoryColumn)
            return data(column, SortRole).toULongLong() < other.data(column, SortRole).toULongLong();
        const int byName = text(column).compare(other.text(column), Qt::CaseInsensitive);
        if (byName != 0 || column != NameColumn) return byName < 0;
        // Same name (a game's many Wine helpers): the biggest, likely the game, first.
        return data(MemoryColumn, SortRole).toULongLong() > other.data(MemoryColumn, SortRole).toULongLong();
    }
};

} // namespace

ProcessListDialog::ProcessListDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Open Process");
    resize(720, 520);
    setMinimumSize(560, 360);   // narrower clips the columns behind a horizontal scrollbar

    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(8);

    // Filter, plus the owner toggle: other users' processes and kernel threads
    // cannot be opened without elevated rights, so they are hidden by default.
    auto* filterRow = new QHBoxLayout;
    filterEdit_ = new QLineEdit;
    filterEdit_->setPlaceholderText("Filter by process name, PID, or command");
    filterEdit_->setAccessibleName("Filter processes");
    filterEdit_->setClearButtonEnabled(true);
    connect(filterEdit_, &QLineEdit::textChanged, this, &ProcessListDialog::onFilter);
    filterRow->addWidget(filterEdit_, 1);
    mineOnly_ = new QCheckBox("Only my processes");
    mineOnly_->setToolTip("Hide kernel threads and processes owned by other users");
    mineOnly_->setChecked(geteuid() != 0);
    connect(mineOnly_, &QCheckBox::toggled, this, [this]() { onFilter(filterEdit_->text()); });
    filterRow->addWidget(mineOnly_);
    layout->addLayout(filterRow);
    filterEdit_->setFocus();   // type the game name immediately

    processList_ = new QTreeWidget;
    processList_->setColumnCount(4);
    processList_->setHeaderLabels({"Name", "PID", "Memory", "Command"});
    processList_->setRootIsDecorated(false);
    processList_->setUniformRowHeights(true);
    processList_->setAlternatingRowColors(true);
    processList_->setTextElideMode(Qt::ElideMiddle);
    processList_->setAllColumnsShowFocus(true);
    processList_->setSortingEnabled(true);
    processList_->sortByColumn(NameColumn, Qt::AscendingOrder);
    auto* header = processList_->header();
    header->setStretchLastSection(true);
    header->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    header->resizeSection(NameColumn, 210);
    header->resizeSection(PidColumn, 72);
    header->resizeSection(MemoryColumn, 88);
    processList_->headerItem()->setTextAlignment(PidColumn, Qt::AlignRight | Qt::AlignVCenter);
    processList_->headerItem()->setTextAlignment(MemoryColumn, Qt::AlignRight | Qt::AlignVCenter);
    connect(processList_, &QTreeWidget::itemDoubleClicked, this, &ProcessListDialog::onAccept);
    layout->addWidget(processList_, 1);

    statusLabel_ = new QLabel;
    statusLabel_->setProperty("secondary", true);

    // Buttons: Refresh is a list action (left); Open/Cancel are the dialog actions (right).
    auto* btnLayout = new QHBoxLayout;
    auto* openBtn = new QPushButton("Open");
    openBtn_ = openBtn;
    openBtn_->setObjectName("primaryButton");
    openBtn->setDefault(true);
    auto* cancelBtn = new QPushButton("Cancel");
    auto* refreshBtn = new QPushButton("Refresh");
    refreshBtn->setShortcut(QKeySequence::Refresh);
    connect(openBtn, &QPushButton::clicked, this, &ProcessListDialog::onAccept);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    connect(refreshBtn, &QPushButton::clicked, this, &ProcessListDialog::refreshList);
    btnLayout->addWidget(refreshBtn);
    btnLayout->addSpacing(8);
    btnLayout->addWidget(statusLabel_);
    btnLayout->addStretch();
    btnLayout->addWidget(openBtn);
    btnLayout->addWidget(cancelBtn);
    layout->addLayout(btnLayout);
    connect(processList_, &QTreeWidget::currentItemChanged, this, [this]() {
        auto* current = processList_->currentItem();
        openBtn_->setEnabled(current && !current->isHidden());
    });

    refreshList();
}

// A process's start time (/proc/PID/stat field 22), which a reused PID does not share.
static QString processStartTime(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/stat");
    std::string text((std::istreambuf_iterator<char>(f)), {});
    const auto close = text.rfind(')');
    if (close == std::string::npos) return {};
    std::istringstream fields(text.substr(close + 2));
    std::string field;
    for (int i = 3; i <= 22 && fields >> field; ++i) {}
    return QString::fromStdString(field);
}

// Resident memory (RSS) in bytes from /proc/PID/statm, or 0 if unavailable.
static uint64_t residentBytes(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/statm");
    unsigned long size = 0, resident = 0;
    if (f >> size >> resident)
        return (uint64_t)resident * (uint64_t)sysconf(_SC_PAGESIZE);
    return 0;
}

void ProcessListDialog::refreshList() {
    auto* selected = processList_->currentItem();
    qlonglong previousPid = selected ? selected->data(NameColumn, PidRole).toLongLong() : 0;
    processList_->setSortingEnabled(false);
    processList_->clear();
    os::LinuxProcessEnumerator enumerator;
    const uid_t me = geteuid();
    QTreeWidgetItem* reselect = nullptr;
    for (const auto& p : enumerator.list()) {
        const uint64_t rss = residentBytes(p.pid);
        struct stat st{};
        const bool known = ::stat(("/proc/" + std::to_string(p.pid)).c_str(), &st) == 0;
        // Kernel threads have no command line and no memory of their own.
        const bool kernelThread = p.path.empty() && rss == 0;
        const bool mine = known && st.st_uid == me && !kernelThread;

        const QString name = QString::fromStdString(p.name);
        const QString command = QString::fromStdString(p.path);
        auto* item = new ProcessItem;
        item->setText(NameColumn, p.sandboxed ? name + QStringLiteral("  [sandboxed]") : name);
        item->setText(PidColumn, QString::number(p.pid));
        item->setText(MemoryColumn, rss ? formatByteSize(rss) : QStringLiteral("-"));
        item->setText(CommandColumn, command);
        item->setTextAlignment(PidColumn, Qt::AlignRight | Qt::AlignVCenter);
        item->setTextAlignment(MemoryColumn, Qt::AlignRight | Qt::AlignVCenter);
        item->setData(PidColumn, SortRole, QVariant::fromValue<qulonglong>(p.pid));
        item->setData(MemoryColumn, SortRole, QVariant::fromValue<qulonglong>(rss));
        item->setData(NameColumn, PidRole, QVariant::fromValue((qlonglong)p.pid));
        item->setData(NameColumn, NameRole, name);
        item->setData(NameColumn, MineRole, mine);
        item->setData(NameColumn, StartRole, processStartTime(p.pid));
        // The filter matches the name, PID and command; "sandboxed" finds those.
        item->setData(NameColumn, FilterRole, QStringList{name, QString::number(p.pid), command,
            p.sandboxed ? QStringLiteral("sandboxed") : QString()}.join('\n'));
        QString tip = command.isEmpty() ? name : command;
        if (p.sandboxed)
            tip += QStringLiteral("\nSandboxed (Flatpak/Snap/container): attaching reaches into "
                                  "its namespace; scan, edit and symbols work.");
        for (int column = 0; column < processList_->columnCount(); ++column) item->setToolTip(column, tip);
        if (kernelThread || !known)
            for (int column = 0; column < processList_->columnCount(); ++column)
                item->setForeground(column, palette().color(QPalette::Disabled, QPalette::Text));
        processList_->addTopLevelItem(item);
        if (p.pid == previousPid) reselect = item;
    }
    processList_->setSortingEnabled(true);
    if (reselect) processList_->setCurrentItem(reselect);
    onFilter(filterEdit_->text());
}

void ProcessListDialog::onAccept() {
    auto* item = processList_->currentItem();
    if (!item || item->isHidden()) return;
    // The list is a snapshot: the process may have exited and its PID gone to
    // another one since. Opening that would attach to it under the old name.
    const pid_t pid = static_cast<pid_t>(item->data(NameColumn, PidRole).toLongLong());
    if (processStartTime(pid) != item->data(NameColumn, StartRole).toString()) {
        refreshList();
        statusLabel_->setText("That process has exited; the list was refreshed.");
        return;
    }
    selectedPid_ = item->data(NameColumn, PidRole).toLongLong();
    selectedName_ = item->data(NameColumn, NameRole).toString();
    accept();
}

void ProcessListDialog::onFilter(const QString& text) {
    const QString needle = text.trimmed();
    const bool mineOnly = mineOnly_->isChecked();
    QTreeWidgetItem* first = nullptr;
    int visible = 0;
    for (int i = 0; i < processList_->topLevelItemCount(); ++i) {
        auto* item = processList_->topLevelItem(i);
        bool match = needle.isEmpty() ||
            item->data(NameColumn, FilterRole).toString().contains(needle, Qt::CaseInsensitive);
        if (mineOnly && !item->data(NameColumn, MineRole).toBool()) match = false;
        item->setHidden(!match);
        if (match) { ++visible; if (!first) first = item; }
    }
    auto* current = processList_->currentItem();
    if (!current || current->isHidden()) processList_->setCurrentItem(first);
    openBtn_->setEnabled(visible > 0 && processList_->currentItem());
    statusLabel_->setText(visible ? QString("%1 %2").arg(visible).arg(visible == 1 ? "process" : "processes")
                                : "No processes match this filter.");
    if (auto* item = processList_->currentItem()) processList_->scrollToItem(item);
}

} // namespace ce::gui
