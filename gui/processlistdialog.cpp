#include "gui/processlistdialog.hpp"
#include "platform/linux/linux_process.hpp"
#include <algorithm>
#include <fstream>
#include <unistd.h>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFont>

namespace ce::gui {

ProcessListDialog::ProcessListDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Open Process");
    resize(400, 500);

    auto* layout = new QVBoxLayout(this);

    // Filter
    filterEdit_ = new QLineEdit;
    filterEdit_->setPlaceholderText("Type to filter by name (e.g. warband)...");
    connect(filterEdit_, &QLineEdit::textChanged, this, &ProcessListDialog::onFilter);
    layout->addWidget(filterEdit_);
    filterEdit_->setFocus();   // type the game name immediately

    // Tabs
    tabs_ = new QTabWidget;
    processList_ = new QListWidget;
    processList_->setFont(QFont("Monospace", 9));
    connect(processList_, &QListWidget::itemDoubleClicked, this, &ProcessListDialog::onAccept);

    tabs_->addTab(processList_, "Processes");
    layout->addWidget(tabs_);

    // Buttons
    auto* btnLayout = new QHBoxLayout;
    auto* openBtn = new QPushButton("Open");
    openBtn->setDefault(true);
    auto* cancelBtn = new QPushButton("Cancel");
    auto* refreshBtn = new QPushButton("Refresh");
    connect(openBtn, &QPushButton::clicked, this, &ProcessListDialog::onAccept);
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    connect(refreshBtn, &QPushButton::clicked, this, &ProcessListDialog::refreshList);
    btnLayout->addStretch();
    btnLayout->addWidget(openBtn);
    btnLayout->addWidget(cancelBtn);
    btnLayout->addWidget(refreshBtn);
    layout->addLayout(btnLayout);

    refreshList();
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
    processList_->clear();
    os::LinuxProcessEnumerator enumerator;
    auto procs = enumerator.list();

    // Attach resident memory to each process, then sort by name (grouping the
    // many wine helper processes of a game together) and, within a name, by
    // memory descending so the actual game (largest RSS) is the first match.
    struct Row { ce::ProcessInfo info; uint64_t rss; };
    std::vector<Row> rows;
    rows.reserve(procs.size());
    for (auto& p : procs) rows.push_back({p, residentBytes(p.pid)});
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        int n = QString::fromStdString(a.info.name)
                    .compare(QString::fromStdString(b.info.name), Qt::CaseInsensitive);
        if (n != 0) return n < 0;
        return a.rss > b.rss;  // biggest (likely the game) first within a name
    });

    for (auto& r : rows) {
        const auto& p = r.info;
        QString mem = r.rss >= (1u << 20)
            ? QString("%1 MB").arg(r.rss / (1024.0 * 1024.0), 0, 'f', 1)
            : QString("%1 KB").arg(r.rss / 1024.0, 0, 'f', 0);
        // Name first (readable), then pid + memory so duplicates are distinguishable.
        auto text = QString("%1   (pid %2, %3)")
                        .arg(QString::fromStdString(p.name)).arg(p.pid).arg(mem);
        auto* item = new QListWidgetItem(text);
        item->setData(Qt::UserRole, QVariant::fromValue((qlonglong)p.pid));
        item->setData(Qt::UserRole + 1, QString::fromStdString(p.name));
        // Stash the full path / cmdline so the filter can match against it
        // (Wine-wrapped processes keep their .exe name in cmdline even when
        // /proc/PID/comm reads "Main Thread" or "wine64-preloader").
        item->setData(Qt::UserRole + 2, QString::fromStdString(p.path));
        if (!p.path.empty())
            item->setToolTip(QString::fromStdString(p.path));
        processList_->addItem(item);
    }
}

void ProcessListDialog::onAccept() {
    auto* item = processList_->currentItem();
    if (!item) return;
    selectedPid_ = item->data(Qt::UserRole).toLongLong();
    selectedName_ = item->data(Qt::UserRole + 1).toString();
    accept();
}

void ProcessListDialog::onFilter(const QString& text) {
    for (int i = 0; i < processList_->count(); ++i) {
        auto* item = processList_->item(i);
        if (text.isEmpty()) { item->setHidden(false); continue; }
        bool match = item->text().contains(text, Qt::CaseInsensitive);
        if (!match) {
            auto path = item->data(Qt::UserRole + 2).toString();
            match = path.contains(text, Qt::CaseInsensitive);
        }
        item->setHidden(!match);
    }
}

} // namespace ce::gui
