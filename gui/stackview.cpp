#include "gui/stackview.hpp"

#include "debug/stack_trace.hpp"
#include "debug/thread_inspection.hpp"
#include "symbols/elf_symbols.hpp"

#include <QFont>
#include <QHeaderView>
#include <QPushButton>
#include <QVBoxLayout>
#include <QSignalBlocker>

namespace ce::gui {

StackViewWindow::StackViewWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Stack Trace");
    resize(850, 560);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    threadCombo_ = new QComboBox;
    threadCombo_->setObjectName("stackViewThreads");
    layout->addWidget(threadCombo_);

    auto* refreshButton = new QPushButton("Refresh");
    connect(refreshButton, &QPushButton::clicked, this, &StackViewWindow::refreshStack);
    layout->addWidget(refreshButton);

    statusLabel_ = new QLabel;
    statusLabel_->setObjectName("stackViewStatus");
    statusLabel_->setWordWrap(true);
    layout->addWidget(statusLabel_);

    tabs_ = new QTabWidget;

    stackTable_ = new QTableWidget;
    stackTable_->setObjectName("stackViewRaw");
    stackTable_->setColumnCount(3);
    stackTable_->setHorizontalHeaderLabels({"Address", "Value", "Offset"});
    // Address and Value are 16-digit hex; fit them so they aren't clipped, let
    // the Offset column take the slack.
    stackTable_->horizontalHeader()->setStretchLastSection(true);
    stackTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    stackTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    stackTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    stackTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    stackTable_->setFont(QFont("Monospace", 9));
    tabs_->addTab(stackTable_, "Raw Stack");

    traceTable_ = new QTableWidget;
    traceTable_->setObjectName("stackViewFrames");
    traceTable_->setColumnCount(5);
    traceTable_->setHorizontalHeaderLabels({"Frame", "Instruction", "Return", "Frame Pointer", "Symbol"});
    // Fit the frame/address columns to content; Symbol (last) takes the slack.
    traceTable_->horizontalHeader()->setStretchLastSection(true);
    for (int c = 0; c < 4; ++c)
        traceTable_->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    traceTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    traceTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    traceTable_->setFont(QFont("Monospace", 9));
    tabs_->addTab(traceTable_, "Stack Trace");

    layout->addWidget(tabs_);

    setCentralWidget(central);
    populateThreads();
    connect(threadCombo_, &QComboBox::currentIndexChanged, this, &StackViewWindow::refreshStack);
    refreshStack();
}

void StackViewWindow::populateThreads() {
    const QSignalBlocker blocker(threadCombo_);
    const auto selected = threadCombo_->currentData();
    threadCombo_->clear();
    if (!proc_) return;

    for (const auto& thread : proc_->threads())
        threadCombo_->addItem(QString::number(thread.tid), QVariant::fromValue((qlonglong)thread.tid));
    const auto previous = threadCombo_->findData(selected);
    if (previous >= 0) threadCombo_->setCurrentIndex(previous);
}

void StackViewWindow::refreshStack() {
    populateThreads();
    stackTable_->setRowCount(0);
    traceTable_->setRowCount(0);
    if (!proc_ || threadCombo_->currentIndex() < 0) {
        statusLabel_->setText("No thread selected");
        return;
    }

    auto tid = (pid_t)threadCombo_->currentData().toLongLong();

    auto snapshot = ce::inspectThread(*proc_, tid, true);
    if (!snapshot) { statusLabel_->setText(QString::fromStdString(snapshot.error())); return; }
    const auto& context = snapshot->context;
    const unsigned digits = context.architecture == CpuArchitecture::X86_32 ? 8 : 16;
    stackTable_->setRowCount(static_cast<int>(snapshot->stack.size()));
    for (size_t row = 0; row < snapshot->stack.size(); ++row) {
        const auto& value = snapshot->stack[row];
        stackTable_->setItem(row, 0, new QTableWidgetItem(QString("%1").arg(value.address, digits, 16, QChar('0'))));
        stackTable_->setItem(row, 1, new QTableWidgetItem(value.available ?
            QString("%1").arg(value.value, value.width * 2, 16, QChar('0')) : "??"));
        stackTable_->setItem(row, 2, new QTableWidgetItem(QString("+0x%1").arg(value.address - context.stackPointer(), 0, 16)));
    }

    // Resolve symbols after releasing the stop; parsing debug files can be slow.
    SymbolResolver symbols;
    symbols.loadProcess(*proc_);
    auto& frames = snapshot->frames;
    for (auto& frame : frames)
        if (frame.instructionPointer) frame.symbol = symbols.resolve(frame.instructionPointer);
    traceTable_->setRowCount((int)frames.size());
    for (int row = 0; row < (int)frames.size(); ++row) {
        const auto& frame = frames[(size_t)row];
        traceTable_->setItem(row, 0, new QTableWidgetItem(QString::number(frame.index)));
        traceTable_->setItem(row, 1, new QTableWidgetItem(QString("%1").arg(frame.instructionPointer, digits, 16, QChar('0'))));
        traceTable_->setItem(row, 2, new QTableWidgetItem(frame.returnAddress
            ? QString("%1").arg(frame.returnAddress, digits, 16, QChar('0'))
            : QString()));
        traceTable_->setItem(row, 3, new QTableWidgetItem(QString("%1").arg(frame.framePointer, digits, 16, QChar('0'))));
        traceTable_->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(frame.symbol)));
    }

    statusLabel_->setText(QString("TID %1 %2=0x%3 %4=0x%5 Frames=%6")
        .arg(tid)
        .arg(context.architecture == CpuArchitecture::Arm64 ? "SP" : digits == 8 ? "ESP" : "RSP")
        .arg(context.stackPointer(), 0, 16)
        .arg(context.architecture == CpuArchitecture::Arm64 ? "X29" : digits == 8 ? "EBP" : "RBP")
        .arg(context.framePointer(), 0, 16)
        .arg(frames.size()));
}

} // namespace ce::gui
