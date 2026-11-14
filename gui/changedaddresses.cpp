#include "gui/changedaddresses.hpp"

#include "core/cpu_registers.hpp"
#include "core/value_io.hpp"
#include "platform/process_api.hpp"

#include <QApplication>
#include <QClipboard>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QSet>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <chrono>
#include <thread>

namespace ce::gui {

namespace {
struct DisplayChoice { const char* label; ValueType type; };
// Cheat Engine's display types for this window.
const DisplayChoice kDisplayChoices[] = {
    {QT_TRANSLATE_NOOP("ce::gui::ChangedAddressesWindow", "Byte"), ValueType::Byte},
    {QT_TRANSLATE_NOOP("ce::gui::ChangedAddressesWindow", "2 Bytes"), ValueType::Int16},
    {QT_TRANSLATE_NOOP("ce::gui::ChangedAddressesWindow", "4 Bytes"), ValueType::Int32},
    {QT_TRANSLATE_NOOP("ce::gui::ChangedAddressesWindow", "8 Bytes"), ValueType::Int64},
    {QT_TRANSLATE_NOOP("ce::gui::ChangedAddressesWindow", "Float"), ValueType::Float},
    {QT_TRANSLATE_NOOP("ce::gui::ChangedAddressesWindow", "Double"), ValueType::Double},
    {QT_TRANSLATE_NOOP("ce::gui::ChangedAddressesWindow", "Pointer"), ValueType::Pointer},
};
constexpr int kAddressRole = Qt::UserRole + 1;

QString hexAddress(uintptr_t address) { return QString::number(static_cast<qulonglong>(address), 16).toUpper(); }

// Registers whose value is the same at every group-1 address and differs from
// all of group 2 (or, with group 2 empty, from every other address).
QStringList commonRegisters(const std::map<uintptr_t, std::vector<CpuRegisterValue>>& registers,
                            const QList<uintptr_t>& group1, const QList<uintptr_t>& group2) {
    QStringList out;
    if (group1.isEmpty()) return out;
    auto first = registers.find(group1.front());
    if (first == registers.end()) return out;
    QList<uintptr_t> others = group2;
    if (others.isEmpty())
        for (const auto& [address, unused] : registers)
            if (!group1.contains(address)) others.push_back(address);
    for (size_t index = 0; index < first->second.size(); ++index) {
        const auto& reference = first->second[index];
        auto valueAt = [&](uintptr_t address) -> std::optional<uint64_t> {
            auto it = registers.find(address);
            if (it == registers.end() || index >= it->second.size() || it->second[index].name != reference.name)
                return std::nullopt;
            return it->second[index].value;
        };
        bool same = std::all_of(group1.begin(), group1.end(),
                                [&](uintptr_t a) { return valueAt(a) == reference.value; });
        bool differs = !others.isEmpty() && std::all_of(others.begin(), others.end(), [&](uintptr_t a) {
            auto value = valueAt(a);
            return value && *value != reference.value;
        });
        if (same && differs)
            out << QString("%1 = %2").arg(QString::fromStdString(reference.name), hexAddress(reference.value));
    }
    return out;
}
} // namespace

ChangedAddressesWindow::ChangedAddressesWindow(ProcessHandle* process, uintptr_t instruction, QWidget* parent)
    : QMainWindow(parent), process_(process), instruction_(instruction) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(tr("Changed Addresses"));
    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);

    auto* top = new QHBoxLayout;
    top->addWidget(new QLabel(tr("Code Address"), central));
    codeAddress_ = new QLineEdit(central);
    codeAddress_->setReadOnly(true);
    QString where = hexAddress(instruction);
    if (process_) {
        const std::string module = moduleOffsetString(process_->modules(), instruction);
        if (!module.empty()) where = QString::fromStdString(module) + "  (" + where + ")";
    }
    codeAddress_->setText(where);
    top->addWidget(codeAddress_, 1);
    typeCombo_ = new QComboBox(central);
    for (const auto& choice : kDisplayChoices) typeCombo_->addItem(tr(choice.label));
    typeCombo_->setCurrentIndex(2);   // 4 Bytes, as in Cheat Engine
    top->addWidget(typeCombo_);
    stopButton_ = new QPushButton(tr("Stop"), central);
    top->addWidget(stopButton_);
    layout->addLayout(top);

    info_ = new QLabel(tr("The following addresses have been accessed by the code you selected"), central);
    info_->setWordWrap(true);
    layout->addWidget(info_);

    table_ = new QTableWidget(0, 3, central);
    table_->setHorizontalHeaderLabels({tr("Address"), tr("Value"), tr("Count")});
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table_->verticalHeader()->hide();
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    layout->addWidget(table_, 1);
    setCentralWidget(central);
    resize(520, 420);

    connect(stopButton_, &QPushButton::clicked, this, [this]() {
        if (monitoring()) stop();
        else close();
    });
    connect(typeCombo_, &QComboBox::currentIndexChanged, this, [this]() { refresh(); });
    connect(table_, &QWidget::customContextMenuRequested, this, &ChangedAddressesWindow::showContextMenu);
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (auto* item = table_->item(row, 0))
            emit addToAddressListRequested(item->data(kAddressRole).toULongLong(), static_cast<int>(displayType()));
    });
    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &ChangedAddressesWindow::refresh);
    timer_->start(250);

    if (!process_) return;
    worker_ = std::thread([this]() {
        std::string error;
        findInstructionAccesses(*process_, instruction_, 0, 0, [this]() { return stopping_.load(); }, &error,
            [this](const InstructionAccess& access) {
                std::lock_guard lock(mutex_);
                auto [it, added] = records_.try_emplace(access.address);
                if (added) it->second.context = access.firstContext;
                ++it->second.hits;
            });
        std::lock_guard lock(mutex_);
        error_ = std::move(error);
        finished_ = true;
    });
}

ChangedAddressesWindow::~ChangedAddressesWindow() { stop(); }

void ChangedAddressesWindow::stop() {
    stopping_ = true;
    if (worker_.joinable()) worker_.join();
    if (stopButton_) stopButton_->setText(tr("Close"));
}

void ChangedAddressesWindow::closeEvent(QCloseEvent* event) {
    stop();
    QMainWindow::closeEvent(event);
}

ValueType ChangedAddressesWindow::displayType() const {
    const int index = typeCombo_ ? typeCombo_->currentIndex() : 2;
    return kDisplayChoices[std::clamp(index, 0, static_cast<int>(std::size(kDisplayChoices)) - 1)].type;
}

QString ChangedAddressesWindow::valueText(uintptr_t address) const {
    if (!process_) return QStringLiteral("??");
    ValueIoOptions options;
    options.hex = hex_;
    options.isSigned = signed_;
    auto value = readTypedValue(*process_, address, displayType(), options);
    return value ? QString::fromStdString(*value) : QStringLiteral("??");
}

void ChangedAddressesWindow::refresh() {
    std::vector<std::pair<uintptr_t, int>> rows;
    QString error;
    bool finished = false;
    {
        std::lock_guard lock(mutex_);
        rows.reserve(records_.size());
        for (const auto& [address, record] : records_) rows.emplace_back(address, record.hits);
        error = QString::fromStdString(error_);
        finished = finished_;
    }
    if (finished && stopButton_->text() != tr("Close")) stopButton_->setText(tr("Close"));
    if (!error.isEmpty()) info_->setText(QString(tr("Monitoring failed: %1")).arg(error));

    // Update the rows in place, matched by address, so the selection and the
    // scroll position survive; a new address gets a new row.
    QHash<uintptr_t, int> rowOf;
    for (int row = 0; row < table_->rowCount(); ++row)
        if (auto* item = table_->item(row, 0)) rowOf.insert(item->data(kAddressRole).toULongLong(), row);
    QSet<uintptr_t> present;
    for (const auto& [address, hits] : rows) {
        present.insert(address);
        int row = rowOf.value(address, -1);
        if (row < 0) {
            row = table_->rowCount();
            table_->insertRow(row);
            auto* item = new QTableWidgetItem;
            item->setData(kAddressRole, static_cast<qulonglong>(address));
            table_->setItem(row, 0, item);
            table_->setItem(row, 1, new QTableWidgetItem);
            table_->setItem(row, 2, new QTableWidgetItem);
            rowOf.insert(address, row);
        }
        const QString value = valueText(address);
        QString label = hexAddress(address);
        const bool shown = filter_.isEmpty() || label.contains(filter_, Qt::CaseInsensitive) ||
                           value.contains(filter_, Qt::CaseInsensitive);
        if (group1_.contains(address)) label += "  [1]";
        else if (group2_.contains(address)) label += "  [2]";
        auto set = [&](int column, const QString& text) {
            if (table_->item(row, column)->text() != text) table_->item(row, column)->setText(text);
        };
        set(0, label);
        set(1, value);
        set(2, QString::number(hits));
        table_->setRowHidden(row, !shown);
    }
    // Rows whose address was deleted go (from the bottom, so indexes hold).
    for (int row = table_->rowCount() - 1; row >= 0; --row)
        if (auto* item = table_->item(row, 0); !item || !present.contains(item->data(kAddressRole).toULongLong()))
            table_->removeRow(row);
}

QList<uintptr_t> ChangedAddressesWindow::selectedAddresses() const {
    QList<uintptr_t> out;
    if (!table_ || !table_->selectionModel()) return out;
    for (const auto& index : table_->selectionModel()->selectedRows())
        if (auto* item = table_->item(index.row(), 0)) out << item->data(kAddressRole).toULongLong();
    return out;
}

void ChangedAddressesWindow::showRegisters(uintptr_t address) {
    CpuContext context{};
    {
        std::lock_guard lock(mutex_);
        auto it = records_.find(address);
        if (it == records_.end()) return;
        context = it->second.context;
    }
    QStringList lines;
    for (const auto& reg : cpuRegisterValues(context))
        lines << QString("%1 = %2").arg(QString::fromStdString(reg.name), -6).arg(hexAddress(reg.value));
    const std::string flags = describeCpuStatusFlags(context);
    if (!flags.empty()) lines << QString::fromStdString(flags);
    QMessageBox box(QMessageBox::NoIcon, QString(tr("Register states at %1")).arg(hexAddress(address)),
                    lines.join('\n'), QMessageBox::Close, this);
    box.setTextInteractionFlags(Qt::TextSelectableByMouse);
    box.exec();
}

void ChangedAddressesWindow::changeValue(const QList<uintptr_t>& addresses) {
    if (!process_ || addresses.isEmpty()) return;
    bool ok = false;
    const QString value = QInputDialog::getText(this, tr("Change value"), tr("New value:"), QLineEdit::Normal,
                                                valueText(addresses.front()), &ok);
    if (!ok) return;
    ValueIoOptions options;
    options.hex = hex_;
    options.isSigned = signed_;
    QStringList failed;
    for (uintptr_t address : addresses)
        if (auto written = writeTypedValue(*process_, address, displayType(), value.toStdString(), options); !written)
            failed << QString("%1: %2").arg(hexAddress(address), QString::fromStdString(written.error()));
    if (!failed.isEmpty()) QMessageBox::warning(this, tr("Change value"), failed.join('\n'));
    refresh();
}

QStringList ChangedAddressesWindow::commonalitiesForTest(const QList<uintptr_t>& group1,
                                                         const QList<uintptr_t>& group2) const {
    std::map<uintptr_t, std::vector<CpuRegisterValue>> registers;
    std::lock_guard lock(mutex_);
    for (const auto& [address, record] : records_) registers[address] = cpuRegisterValues(record.context);
    return commonRegisters(registers, group1, group2);
}

void ChangedAddressesWindow::scanForCommonalities() {
    const QList<uintptr_t> group1(group1_.begin(), group1_.end());
    const QList<uintptr_t> group2(group2_.begin(), group2_.end());
    if (group1.isEmpty()) {
        QMessageBox::information(this, tr("Commonality scanner"),
                                 tr("Mark at least one address as group 1 first."));
        return;
    }
    const QStringList rows = commonalitiesForTest(group1, group2);
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Commonality scanner"));
    auto* layout = new QVBoxLayout(&dialog);
    layout->addWidget(new QLabel(group2.isEmpty()
        ? tr("Registers with the same value at every group 1 address and a different one at every other address:")
        : tr("Registers with the same value at every group 1 address and a different one at every group 2 address:"),
        &dialog));
    auto* list = new QTableWidget(rows.size(), 1, &dialog);
    list->horizontalHeader()->hide();
    list->verticalHeader()->hide();
    list->horizontalHeader()->setStretchLastSection(true);
    list->setEditTriggers(QAbstractItemView::NoEditTriggers);
    for (int i = 0; i < rows.size(); ++i) list->setItem(i, 0, new QTableWidgetItem(rows[i]));
    if (rows.isEmpty()) layout->addWidget(new QLabel(tr("No register tells the groups apart."), &dialog));
    layout->addWidget(list);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);
    dialog.resize(380, 300);
    dialog.exec();
}

void ChangedAddressesWindow::showContextMenu(const QPoint& pos) {
    const QList<uintptr_t> selected = selectedAddresses();
    const bool any = !selected.isEmpty();
    QMenu menu(this);
    auto* registers = menu.addAction(tr("Show register states"), [this, selected]() { showRegisters(selected.front()); });
    registers->setEnabled(selected.size() == 1);
    menu.addAction(tr("Change value"), [this, selected]() { changeValue(selected); })->setEnabled(any);
    menu.addAction(tr("Browse this memory region"), [this, selected]() {
        emit browseRequested(selected.front());
    })->setEnabled(any);
    menu.addAction(tr("Open dissect data with selected addresses"), [this, selected]() {
        QList<quint64> addresses;
        for (uintptr_t address : selected) addresses << address;
        emit dissectRequested(addresses);
    })->setEnabled(any);
    auto* common = menu.addMenu(tr("Find commonalities between addresses"));
    common->addAction(tr("Mark selection as group 1"), [this, selected]() {
        for (uintptr_t address : selected) { group2_.remove(address); group1_.insert(address); }
        refresh();
    })->setEnabled(any);
    common->addAction(tr("Mark selection as group 2 (Nothing means everything else)"), [this, selected]() {
        for (uintptr_t address : selected) { group1_.remove(address); group2_.insert(address); }
        refresh();
    })->setEnabled(any);
    common->addSeparator();
    common->addAction(tr("Clear Selection"), [this]() { group1_.clear(); group2_.clear(); refresh(); });
    common->addSeparator();
    common->addAction(tr("Scan for commonalities"), this, &ChangedAddressesWindow::scanForCommonalities);
    auto* hex = menu.addAction(tr("Show as hexadecimal"), [this]() { hex_ = !hex_; refresh(); });
    hex->setCheckable(true);
    hex->setChecked(hex_);
    auto* isSigned = menu.addAction(tr("Show as signed"), [this]() { signed_ = !signed_; refresh(); });
    isSigned->setCheckable(true);
    isSigned->setChecked(signed_);
    menu.addAction(tr("Copy address to clipboard"), [selected]() {
        QStringList lines;
        for (uintptr_t address : selected) lines << hexAddress(address);
        QApplication::clipboard()->setText(lines.join('\n'));
    })->setEnabled(any);
    menu.addAction(tr("Copy value to clipboard"), [this, selected]() {
        QStringList lines;
        for (uintptr_t address : selected) lines << valueText(address);
        QApplication::clipboard()->setText(lines.join('\n'));
    })->setEnabled(any);
    menu.addAction(tr("Copy selected addresses to addresslist"), [this, selected]() {
        for (uintptr_t address : selected) emit addToAddressListRequested(address, static_cast<int>(displayType()));
    })->setEnabled(any);
    menu.addSeparator();
    menu.addAction(tr("Delete selected entries"), [this, selected]() {
        std::lock_guard lock(mutex_);
        for (uintptr_t address : selected) records_.erase(address);
    })->setEnabled(any);
    menu.addAction(tr("Reset count"), [this]() {
        std::lock_guard lock(mutex_);
        for (auto& [address, record] : records_) record.hits = 0;
    });
    menu.addSeparator();
    menu.addAction(tr("Filter..."), [this]() {
        bool ok = false;
        const QString text = QInputDialog::getText(this, tr("Filter"),
            tr("Show only the rows whose address or value contains this text (empty shows all):"),
            QLineEdit::Normal, filter_, &ok);
        if (ok) { filter_ = text.trimmed(); refresh(); }
    });
    menu.exec(table_->viewport()->mapToGlobal(pos));
    refresh();
}

bool ChangedAddressesWindow::waitForAddressesForTest(int count, int timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard lock(mutex_);
            if (static_cast<int>(records_.size()) >= count) break;
        }
        QApplication::processEvents();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    refresh();
    std::lock_guard lock(mutex_);
    return static_cast<int>(records_.size()) >= count;
}

int ChangedAddressesWindow::rowCountForTest() const {
    int shown = 0;
    for (int row = 0; row < table_->rowCount(); ++row) shown += !table_->isRowHidden(row);
    return shown;
}

void ChangedAddressesWindow::selectAllForTest() { table_->selectAll(); }
int ChangedAddressesWindow::selectedCountForTest() const { return static_cast<int>(selectedAddresses().size()); }

QString ChangedAddressesWindow::valueTextForTest(int row) const {
    auto* item = table_->item(row, 1);
    return item ? item->text() : QString();
}

} // namespace ce::gui
