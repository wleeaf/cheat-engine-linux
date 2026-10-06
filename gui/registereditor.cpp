#include "gui/registereditor.hpp"

#include "core/cpu_registers.hpp"
#include "platform/gdb_process.hpp"
#include <QByteArray>
#include <algorithm>
#include <QAbstractItemView>
#include <QFont>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QPushButton>
#include <QVBoxLayout>
#include <QSignalBlocker>

namespace ce::gui {
namespace {

QString hexValue(uint64_t value, unsigned bits = 64) {
    return QString("%1").arg(value, bits / 4, 16, QChar('0'));
}

QString bytesToHex(const uint8_t* data, size_t size) {
    QString out;
    out.reserve((int)size * 2);
    for (size_t i = 0; i < size; ++i)
        out += QString("%1").arg(data[i], 2, 16, QChar('0'));
    return out;
}

} // namespace

RegisterEditorWindow::RegisterEditorWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Register Editor");
    resize(820, 680);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    threadCombo_ = new QComboBox;
    threadCombo_->setObjectName("registerEditorThreads");
    layout->addWidget(threadCombo_);

    auto* buttons = new QHBoxLayout;
    auto* refreshButton = new QPushButton("Refresh");
    refreshButton->setObjectName("registerEditorRefresh");
    applyButton_ = new QPushButton("Apply changes");
    applyButton_->setObjectName("registerEditorApply");
    applyButton_->setToolTip("Apply only edited values to the thread’s current register state");
    buttons->addWidget(refreshButton);
    buttons->addWidget(applyButton_);
    layout->addLayout(buttons);
    connect(refreshButton, &QPushButton::clicked, this, &RegisterEditorWindow::refreshRegisters);
    connect(applyButton_, &QPushButton::clicked, this, &RegisterEditorWindow::applyRegisters);

    statusLabel_ = new QLabel;
    statusLabel_->setObjectName("registerEditorStatus");
    statusLabel_->setWordWrap(true);
    layout->addWidget(statusLabel_);

    table_ = new QTableWidget;
    table_->setColumnCount(2);
    table_->setHorizontalHeaderLabels({"Register", "Value"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setFont(QFont("Monospace", 9));
    table_->setObjectName("registerEditorGeneral");
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    layout->addWidget(table_);

    auto* fpLabel = new QLabel("Floating point / SIMD registers");
    fpLabel->setObjectName("registerEditorVectorLabel");
    layout->addWidget(fpLabel);

    fpTable_ = new QTableWidget;
    fpTable_->setColumnCount(3);
    fpTable_->setHorizontalHeaderLabels({"Register", "XMM low 128", "YMM high 128"});
    // Fit both 128-bit value columns so YMM values remain accessible when narrowed.
    fpTable_->horizontalHeader()->setStretchLastSection(false);
    fpTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    fpTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    fpTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    fpTable_->setFont(QFont("Monospace", 9));
    fpTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fpTable_->setObjectName("registerEditorVectors");
    layout->addWidget(fpTable_);

    setCentralWidget(central);
    if (auto* guest=dynamic_cast<GdbProcessHandle*>(proc_)) {
        setWindowTitle("GDB Register Editor");
        threadCombo_->addItem("CPU selected by the GDB stub");threadCombo_->setEnabled(false);
        fpLabel->hide();fpTable_->hide();table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table_->setHorizontalHeaderLabels({"XML register", "Target-order hexadecimal bytes"});
        table_->setRowCount(static_cast<int>(guest->registerDescription().registers.size()));
        for (size_t row=0;row<guest->registerDescription().registers.size();++row) {
            const auto& reg=guest->registerDescription().registers[row];
            auto* name=new QTableWidgetItem(QString::fromStdString(reg.name));
            name->setFlags(name->flags() & ~Qt::ItemIsEditable);
            name->setToolTip(QString("%1 bits; register %2; %3").arg(reg.bits).arg(reg.number).arg(QString::fromStdString(reg.type)));
            auto* value=new QTableWidgetItem("Select this row and press Refresh");
            value->setFlags(value->flags() & ~Qt::ItemIsEditable);
            table_->setItem(static_cast<int>(row),0,name);table_->setItem(static_cast<int>(row),1,value);
        }
        applyButton_->setToolTip("Write only edited XML registers; values are raw bytes in the target's register order");
        if (table_->rowCount()) table_->selectRow(0);
        refreshGdbRegisters();return;
    }
    populateThreads();
    connect(threadCombo_, &QComboBox::currentIndexChanged, this, &RegisterEditorWindow::refreshRegisters);
    refreshRegisters();
}

void RegisterEditorWindow::populateThreads() {
    const QSignalBlocker blocker(threadCombo_);
    const auto selected = threadCombo_->currentData();
    threadCombo_->clear();
    if (!proc_) return;

    for (const auto& thread : proc_->threads())
        threadCombo_->addItem(QString::number(thread.tid), QVariant::fromValue((qlonglong)thread.tid));
    const auto previous = threadCombo_->findData(selected);
    if (previous >= 0) threadCombo_->setCurrentIndex(previous);
}

void RegisterEditorWindow::refreshRegisters() {
    if (dynamic_cast<GdbProcessHandle*>(proc_)) {refreshGdbRegisters();return;}
    populateThreads();
    snapshot_.reset();
    table_->setRowCount(0);
    fpTable_->setRowCount(0);
    table_->setEnabled(false);
    applyButton_->setEnabled(false);
    if (!proc_ || threadCombo_->currentIndex() < 0) {
        statusLabel_->setText("No thread selected");
        return;
    }
    const auto tid = static_cast<pid_t>(threadCombo_->currentData().toLongLong());
    auto snapshot = ce::inspectThread(*proc_, tid);
    if (!snapshot) { statusLabel_->setText(QString::fromStdString(snapshot.error())); return; }
    displaySnapshot(std::move(*snapshot));
    statusLabel_->setText(QString("Loaded TID %1").arg(tid));
}

void RegisterEditorWindow::displaySnapshot(ThreadSnapshot snapshot) {
    snapshot_ = std::move(snapshot);
    const auto registers = cpuRegisterValues(snapshot_->context);
    table_->setRowCount(static_cast<int>(registers.size()));
    for (size_t row = 0; row < registers.size(); ++row) {
        auto* name = new QTableWidgetItem(QString::fromStdString(registers[row].name));
        name->setFlags(name->flags() & ~Qt::ItemIsEditable);
        table_->setItem(row, 0, name);
        table_->setItem(row, 1, new QTableWidgetItem(hexValue(registers[row].value, registers[row].bits)));
    }
    table_->setEnabled(true);
    applyButton_->setEnabled(true);
    const bool arm = snapshot_->context.architecture == CpuArchitecture::Arm64;
    const unsigned count = arm ? 32 : snapshot_->context.architecture == CpuArchitecture::X86_32 ? 8 : 16;
    fpTable_->setColumnHidden(2, arm);
    fpTable_->setHorizontalHeaderLabels({"Register", arm ? "128-bit value" : "XMM low 128", "YMM high 128"});
    fpTable_->setRowCount(count + (arm ? 2 : 1));
    const QString unavailable = snapshot_->vectorError ?
        QString("unavailable: %1").arg(QString::fromStdString(snapshot_->vectorError.message())) : "unavailable";
    for (unsigned row = 0; row < count; ++row) {
        fpTable_->setItem(row, 0, new QTableWidgetItem(QString(arm ? "V%1" : "XMM%1/YMM%1").arg(row)));
        fpTable_->setItem(row, 1, new QTableWidgetItem(row < snapshot_->vectors.count ?
            bytesToHex(snapshot_->vectors.registers[row].data(), 16) : unavailable));
        fpTable_->setItem(row, 2, new QTableWidgetItem(row < snapshot_->ymmCount ?
            bytesToHex(snapshot_->ymmHigh[row].data(), 16) : "unavailable"));
    }
    for (unsigned row = count; row < static_cast<unsigned>(fpTable_->rowCount()); ++row) {
        const bool control = !arm || row == count;
        fpTable_->setItem(row, 0, new QTableWidgetItem(arm ? (control ? "FPCR" : "FPSR") : "MXCSR"));
        fpTable_->setItem(row, 1, new QTableWidgetItem(snapshot_->vectors.count ?
            hexValue(control ? snapshot_->vectors.control : snapshot_->vectors.status, 32) : unavailable));
        fpTable_->setItem(row, 2, new QTableWidgetItem);
    }
}

void RegisterEditorWindow::applyRegisters() {
    if (dynamic_cast<GdbProcessHandle*>(proc_)) {applyGdbRegisters();return;}
    if (!proc_ || !snapshot_ || threadCombo_->currentIndex() < 0) return;
    const auto tid = static_cast<pid_t>(threadCombo_->currentData().toLongLong());
    if (tid != snapshot_->identity.pid) { refreshRegisters(); return; }
    const auto registers = cpuRegisterValues(snapshot_->context);
    std::vector<uint64_t> values;
    bool changed = false;
    for (size_t row = 0; row < registers.size(); ++row) {
        bool ok = false;
        const auto value = table_->item(row, 1)->text().toULongLong(&ok, 16);
        if (!ok) { statusLabel_->setText(QString("Invalid %1 value").arg(QString::fromStdString(registers[row].name))); return; }
        values.push_back(value);
        changed |= value != registers[row].value;
    }
    auto valid = mergeCpuRegisterEdits(snapshot_->context, snapshot_->context, values);
    if (!valid) { statusLabel_->setText(QString::fromStdString(valid.error())); return; }
    if (!changed) { statusLabel_->setText("No register values changed"); return; }
    auto applied = ce::inspectThread(*proc_, tid, false, &*snapshot_, values);
    if (!applied) {
        statusLabel_->setText(QString::fromStdString(applied.error()));
        snapshot_.reset(); table_->setEnabled(false); applyButton_->setEnabled(false);
        return;
    }
    displaySnapshot(std::move(*applied));
    statusLabel_->setText(QString("Applied changes to TID %1").arg(tid));
}

void RegisterEditorWindow::refreshGdbRegisters() {
    auto* guest=dynamic_cast<GdbProcessHandle*>(proc_);if (!guest) return;
    if (!guest->targetDescription().live) {
        statusLabel_->setText("GDB target is disconnected or exited");table_->setEnabled(false);applyButton_->setEnabled(false);return;
    }
    table_->setEnabled(true);
    auto rows=table_->selectionModel()->selectedRows();
    if (rows.empty() && table_->rowCount()) rows.push_back(table_->model()->index(0,0));
    unsigned count=0;QString lastError;
    for (const auto& row:rows) {
        auto* value=table_->item(row.row(),1);
        auto bytes=guest->readRegister(guest->registerDescription().registers[row.row()].name);
        if (!bytes) {
            lastError=QString::fromStdString(bytes.error());value->setText("Unavailable: "+lastError);
            value->setData(Qt::UserRole,{});value->setFlags(value->flags() & ~Qt::ItemIsEditable);
            if (!guest->targetDescription().live) {table_->setEnabled(false);break;}
        } else {
            value->setText(bytesToHex(bytes->data(),bytes->size()));
            value->setData(Qt::UserRole,QByteArray(reinterpret_cast<const char*>(bytes->data()),static_cast<qsizetype>(bytes->size())));
            value->setFlags(value->flags() | Qt::ItemIsEditable);++count;
        }
    }
    applyButton_->setEnabled(table_->isEnabled());
    statusLabel_->setText(lastError.isEmpty() ? QString("Read %1 selected register(s). Select other rows and Refresh to read them.").arg(count) : lastError);
}
void RegisterEditorWindow::applyGdbRegisters() {
    auto* guest=dynamic_cast<GdbProcessHandle*>(proc_);if (!guest) return;
    struct Edit {int row;QByteArray bytes;};std::vector<Edit> edits;
    for (int row=0;row<table_->rowCount();++row) {
        auto* item=table_->item(row,1);if (!item->data(Qt::UserRole).isValid()) continue;
        const auto text=item->text().trimmed().toLatin1();const auto original=item->data(Qt::UserRole).toByteArray();
        if (text.size()!=original.size()*2 || !std::all_of(text.begin(),text.end(),[](unsigned char c){return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');})) {
            statusLabel_->setText(QString("%1 requires %2 hexadecimal byte pairs").arg(table_->item(row,0)->text()).arg(original.size()));return;
        }
        auto bytes=QByteArray::fromHex(text);if (bytes!=original) edits.push_back({row,std::move(bytes)});
    }
    if (edits.empty()) {statusLabel_->setText("No register values changed");return;}
    if (!guest->targetDescription().live) {table_->setEnabled(false);applyButton_->setEnabled(false);statusLabel_->setText("GDB target is disconnected or exited");return;}
    size_t completed=0;
    for (const auto& edit:edits) {
        const auto& reg=guest->registerDescription().registers[edit.row];
        auto result=guest->writeRegister(reg.name,{reinterpret_cast<const uint8_t*>(edit.bytes.constData()),static_cast<size_t>(edit.bytes.size())});
        if (!result) {
            statusLabel_->setText(QString("Applied %1 of %2 register edits. %3: %4. Refresh before retrying.").arg(completed).arg(edits.size()).arg(QString::fromStdString(reg.name),QString::fromStdString(result.error())));
            applyButton_->setEnabled(false);return;
        }
        table_->item(edit.row,1)->setData(Qt::UserRole,edit.bytes);++completed;
    }
    statusLabel_->setText(QString("Applied %1 register edit(s)").arg(completed));
}

} // namespace ce::gui
