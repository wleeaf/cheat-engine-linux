#include "gui/exceptionlists.hpp"
#include "gui/hexformat.hpp"

#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPushButton>
#include <QTextStream>
#include <QVBoxLayout>

#include <algorithm>
#include <csignal>
#include <cstring>

namespace ce::gui {

namespace {
struct NamedSignal { const char* name; int number; };
const NamedSignal kSignals[] = {
    {"SIGHUP", SIGHUP}, {"SIGINT", SIGINT}, {"SIGQUIT", SIGQUIT}, {"SIGILL", SIGILL}, {"SIGTRAP", SIGTRAP},
    {"SIGABRT", SIGABRT}, {"SIGBUS", SIGBUS}, {"SIGFPE", SIGFPE}, {"SIGUSR1", SIGUSR1}, {"SIGSEGV", SIGSEGV},
    {"SIGUSR2", SIGUSR2}, {"SIGPIPE", SIGPIPE}, {"SIGALRM", SIGALRM}, {"SIGTERM", SIGTERM},
    {"SIGSTKFLT", SIGSTKFLT}, {"SIGCHLD", SIGCHLD}, {"SIGCONT", SIGCONT}, {"SIGTSTP", SIGTSTP},
    {"SIGTTIN", SIGTTIN}, {"SIGTTOU", SIGTTOU}, {"SIGURG", SIGURG}, {"SIGXCPU", SIGXCPU},
    {"SIGXFSZ", SIGXFSZ}, {"SIGVTALRM", SIGVTALRM}, {"SIGPROF", SIGPROF}, {"SIGWINCH", SIGWINCH},
    {"SIGIO", SIGIO}, {"SIGPWR", SIGPWR}, {"SIGSYS", SIGSYS},
};
bool parseHex(QString text, quint64& value) {
    text = text.trimmed();
    if (text.startsWith("0x", Qt::CaseInsensitive)) text.remove(0, 2);
    bool ok = false;
    value = text.toULongLong(&ok, 16);
    return ok;
}
} // namespace

QString signalName(int signal) {
    for (const auto& named : kSignals)
        if (named.number == signal) return QString::fromLatin1(named.name);
    return QString("SIG%1").arg(signal);
}

int parseSignal(const QString& text) {
    QString upper = text.trimmed().toUpper();
    bool numeric = false;
    const int number = upper.toInt(&numeric);
    if (numeric) return number > 0 && number <= SIGRTMAX ? number : 0;
    if (!upper.startsWith("SIG")) upper.prepend("SIG");
    for (const auto& named : kSignals)
        if (upper == QLatin1String(named.name)) return named.number;
    return 0;
}

QList<int> breakableSignals() {
    QList<int> out;
    // SIGKILL and SIGSTOP never reach a tracer; SIGTRAP is the debugger's own.
    for (int signal = 1; signal <= SIGRTMAX; ++signal)
        if (signal != SIGKILL && signal != SIGSTOP && signal != SIGTRAP) out << signal;
    return out;
}

QSet<int> defaultIgnoredSignals() {
    return {SIGCHLD, SIGALRM, SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGURG, SIGCONT, SIGPIPE};
}

ExceptionRegionListDialog::ExceptionRegionListDialog(QList<AddressRange> regions, QWidget* parent)
    : QDialog(parent), regions_(std::move(regions)) {
    setWindowTitle(tr("Exception region list"));
    auto* layout = new QVBoxLayout(this);
    auto* menu = new QMenuBar(this);
    auto* file = menu->addMenu(tr("File"));
    layout->setMenuBar(menu);
    auto* note = new QLabel(tr("The following regions will cause a debugger break when an unhandled exception "
                               "happens inside them. With none, every break-on-signal stops."), this);
    note->setWordWrap(true);
    layout->addWidget(note);
    list_ = new QListWidget(this);
    list_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    layout->addWidget(list_, 1);
    auto* grid = new QGridLayout;
    grid->addWidget(new QLabel(tr("Start address"), this), 0, 0);
    grid->addWidget(new QLabel(tr("End address"), this), 0, 1);
    start_ = new QLineEdit(this);
    stop_ = new QLineEdit(this);
    grid->addWidget(start_, 1, 0);
    grid->addWidget(stop_, 1, 1);
    auto* add = new QPushButton(tr("Add"), this);
    auto* remove = new QPushButton(tr("Delete"), this);
    grid->addWidget(add, 1, 2);
    grid->addWidget(remove, 1, 3);
    layout->addLayout(grid);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    layout->addWidget(buttons);

    file->addAction(tr("Clear"), this, [this]() { regions_.clear(); refresh(); });
    file->addAction(tr("Open..."), this, [this]() {
        const QString path = QFileDialog::getOpenFileName(this, tr("Open region list"), QString(),
                                                          tr("Text files (*.txt);;All files (*)"));
        QFile f(path);
        if (path.isEmpty() || !f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
        QTextStream in(&f);
        while (!in.atEnd()) {
            const QStringList parts = in.readLine().split('-', Qt::SkipEmptyParts);
            quint64 from = 0, to = 0;
            if (parts.size() == 2 && parseHex(parts[0], from) && parseHex(parts[1], to) && from <= to)
                regions_.push_back({from, to});
        }
        refresh();
    });
    file->addAction(tr("Save..."), this, [this]() {
        const QString path = QFileDialog::getSaveFileName(this, tr("Save region list"), "regions.txt",
                                                          tr("Text files (*.txt);;All files (*)"));
        QFile f(path);
        if (path.isEmpty() || !f.open(QIODevice::WriteOnly | QIODevice::Text)) return;
        QTextStream out(&f);
        for (const auto& [from, to] : regions_) out << upperHex(from) << '-' << upperHex(to) << '\n';
    });
    connect(add, &QPushButton::clicked, this, [this]() {
        quint64 from = 0, to = 0;
        if (!parseHex(start_->text(), from) || !parseHex(stop_->text(), to) || to < from) {
            QMessageBox::warning(this, windowTitle(), tr("Enter a start and an end address (hexadecimal, end not below start)."));
            return;
        }
        regions_.push_back({from, to});
        start_->clear();
        stop_->clear();
        refresh();
    });
    connect(remove, &QPushButton::clicked, this, [this]() {
        QList<int> rows;
        for (auto* item : list_->selectedItems()) rows << list_->row(item);
        std::sort(rows.rbegin(), rows.rend());
        for (int row : rows) regions_.removeAt(row);
        refresh();
    });
    connect(list_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem* item) {
        const auto& [from, to] = regions_[list_->row(item)];
        start_->setText(upperHex(from));
        stop_->setText(upperHex(to));
    });
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    refresh();
    resize(460, 360);
}

void ExceptionRegionListDialog::refresh() {
    list_->clear();
    for (const auto& [from, to] : regions_) list_->addItem(QString("%1 - %2").arg(upperHex(from), upperHex(to)));
}

ExceptionIgnoreListDialog::ExceptionIgnoreListDialog(QSet<int> ignored, QWidget* parent)
    : QDialog(parent), ignored_(std::move(ignored)) {
    setWindowTitle(tr("Exception ignore list"));
    auto* layout = new QVBoxLayout(this);
    auto* note = new QLabel(tr("The following signals will be ignored: with Break on all signals they are passed "
                               "to the program without stopping."), this);
    note->setWordWrap(true);
    layout->addWidget(note);
    list_ = new QListWidget(this);
    list_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    list_->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(list_, 1);
    auto* row = new QGridLayout;
    row->addWidget(new QLabel(tr("Signal"), this), 0, 0);
    edit_ = new QLineEdit(this);
    edit_->setPlaceholderText(tr("SIGUSR1 or 10"));
    row->addWidget(edit_, 0, 1);
    auto* add = new QPushButton(tr("Add Signal"), this);
    row->addWidget(add, 0, 2);
    layout->addLayout(row);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    auto* defaults = buttons->addButton(tr("Defaults"), QDialogButtonBox::ResetRole);
    layout->addWidget(buttons);

    connect(add, &QPushButton::clicked, this, [this]() {
        const int signal = parseSignal(edit_->text());
        if (!signal) {
            QMessageBox::warning(this, windowTitle(), tr("Unknown signal: %1").arg(edit_->text()));
            return;
        }
        ignored_.insert(signal);
        edit_->clear();
        refresh();
    });
    auto removeSelected = [this]() {
        for (auto* item : list_->selectedItems()) ignored_.remove(item->data(Qt::UserRole).toInt());
        refresh();
    };
    connect(list_, &QListWidget::itemDoubleClicked, this, removeSelected);
    connect(list_, &QWidget::customContextMenuRequested, this, [this, removeSelected](const QPoint& pos) {
        QMenu menu(this);
        menu.addAction(tr("Delete"), removeSelected);
        menu.exec(list_->viewport()->mapToGlobal(pos));
    });
    connect(defaults, &QPushButton::clicked, this, [this]() { ignored_ = defaultIgnoredSignals(); refresh(); });
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    refresh();
    resize(360, 360);
}

void ExceptionIgnoreListDialog::refresh() {
    list_->clear();
    QList<int> sorted(ignored_.begin(), ignored_.end());
    std::sort(sorted.begin(), sorted.end());
    for (int signal : sorted) {
        auto* item = new QListWidgetItem(QString("%1 (%2)").arg(signalName(signal)).arg(signal), list_);
        item->setData(Qt::UserRole, signal);
    }
}

} // namespace ce::gui
