#include "gui/stackview.hpp"

#include "debug/stack_trace.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "symbols/elf_symbols.hpp"

#include <QFont>
#include <QHeaderView>
#include <QPushButton>
#include <QVBoxLayout>

namespace ce::gui {

StackViewWindow::StackViewWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Stack Trace");
    resize(850, 560);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    threadCombo_ = new QComboBox;
    layout->addWidget(threadCombo_);

    auto* refreshButton = new QPushButton("Refresh");
    connect(refreshButton, &QPushButton::clicked, this, &StackViewWindow::refreshStack);
    layout->addWidget(refreshButton);

    statusLabel_ = new QLabel;
    layout->addWidget(statusLabel_);

    tabs_ = new QTabWidget;

    stackTable_ = new QTableWidget;
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
    refreshStack();
}

void StackViewWindow::populateThreads() {
    threadCombo_->clear();
    if (!proc_) return;

    for (const auto& thread : proc_->threads())
        threadCombo_->addItem(QString::number(thread.tid), QVariant::fromValue((qlonglong)thread.tid));
}

void StackViewWindow::refreshStack() {
    stackTable_->setRowCount(0);
    traceTable_->setRowCount(0);
    if (!proc_ || threadCombo_->currentIndex() < 0) return;

    auto tid = (pid_t)threadCombo_->currentData().toLongLong();

    os::LinuxDebugger debugger;
    auto attached = debugger.attach(tid);
    if (!attached) {
        statusLabel_->setText("Could not attach to thread for stack context.");
        return;
    }

    auto context = debugger.getContext(tid);
    debugger.detach();
    if (!context) {
        statusLabel_->setText("Could not read thread context.");
        return;
    }

    constexpr int rows = 32;
    stackTable_->setRowCount(rows);
    for (int i = 0; i < rows; ++i) {
        auto address = context->rsp + (uintptr_t)i * sizeof(uintptr_t);
        uintptr_t value = 0;
        auto read = proc_->read(address, &value, sizeof(value));

        stackTable_->setItem(i, 0, new QTableWidgetItem(QString("%1").arg(address, 16, 16, QChar('0'))));
        bool fullRead = read && *read == sizeof(value);
        stackTable_->setItem(i, 1, new QTableWidgetItem(fullRead ? QString("%1").arg(value, 16, 16, QChar('0')) : "??"));
        stackTable_->setItem(i, 2, new QTableWidgetItem(QString("+0x%1").arg(i * (int)sizeof(uintptr_t), 0, 16)));
    }

    SymbolResolver symbols;
    symbols.loadProcess(*proc_);
    auto frames = buildStackTrace(*proc_, *context, 64, &symbols);
    traceTable_->setRowCount((int)frames.size());
    for (int row = 0; row < (int)frames.size(); ++row) {
        const auto& frame = frames[(size_t)row];
        traceTable_->setItem(row, 0, new QTableWidgetItem(QString::number(frame.index)));
        traceTable_->setItem(row, 1, new QTableWidgetItem(QString("%1").arg(frame.instructionPointer, 16, 16, QChar('0'))));
        traceTable_->setItem(row, 2, new QTableWidgetItem(frame.returnAddress
            ? QString("%1").arg(frame.returnAddress, 16, 16, QChar('0'))
            : QString()));
        traceTable_->setItem(row, 3, new QTableWidgetItem(QString("%1").arg(frame.framePointer, 16, 16, QChar('0'))));
        traceTable_->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(frame.symbol)));
    }

    statusLabel_->setText(QString("TID %1 RSP=0x%2 RBP=0x%3 Frames=%4")
        .arg(tid)
        .arg(context->rsp, 0, 16)
        .arg(context->rbp, 0, 16)
        .arg(frames.size()));
}

} // namespace ce::gui
