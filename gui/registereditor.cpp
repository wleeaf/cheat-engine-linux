#include "gui/registereditor.hpp"

#include "platform/linux/ptrace_wrapper.hpp"

#include <QAbstractItemView>
#include <QFont>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QPushButton>
#include <QVBoxLayout>
#include <array>
#include <cerrno>
#include <cstring>
#include <elf.h>
#include <iterator>
#include <sys/ptrace.h>
#include <sys/uio.h>

namespace ce::gui {
namespace {

#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif

struct RegisterField {
    const char* name;
    uint64_t CpuContext::*member;
};

constexpr RegisterField kRegisters[] = {
    {"RAX", &CpuContext::rax}, {"RBX", &CpuContext::rbx}, {"RCX", &CpuContext::rcx},
    {"RDX", &CpuContext::rdx}, {"RSI", &CpuContext::rsi}, {"RDI", &CpuContext::rdi},
    {"RBP", &CpuContext::rbp}, {"RSP", &CpuContext::rsp}, {"RIP", &CpuContext::rip},
    {"R8", &CpuContext::r8},   {"R9", &CpuContext::r9},   {"R10", &CpuContext::r10},
    {"R11", &CpuContext::r11}, {"R12", &CpuContext::r12}, {"R13", &CpuContext::r13},
    {"R14", &CpuContext::r14}, {"R15", &CpuContext::r15}, {"RFLAGS", &CpuContext::rflags},
};

QString hexValue(uint64_t value) {
    return QString("%1").arg(value, 16, 16, QChar('0'));
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
    resize(420, 620);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    threadCombo_ = new QComboBox;
    layout->addWidget(threadCombo_);

    auto* buttons = new QHBoxLayout;
    auto* refreshButton = new QPushButton("Refresh");
    auto* applyButton = new QPushButton("Apply");
    buttons->addWidget(refreshButton);
    buttons->addWidget(applyButton);
    layout->addLayout(buttons);
    connect(refreshButton, &QPushButton::clicked, this, &RegisterEditorWindow::refreshRegisters);
    connect(applyButton, &QPushButton::clicked, this, &RegisterEditorWindow::applyRegisters);

    statusLabel_ = new QLabel;
    layout->addWidget(statusLabel_);

    table_ = new QTableWidget;
    table_->setColumnCount(2);
    table_->setHorizontalHeaderLabels({"Register", "Value"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setFont(QFont("Monospace", 9));
    table_->setRowCount((int)std::size(kRegisters));
    for (int row = 0; row < (int)std::size(kRegisters); ++row) {
        auto* name = new QTableWidgetItem(kRegisters[row].name);
        name->setFlags(name->flags() & ~Qt::ItemIsEditable);
        table_->setItem(row, 0, name);
        table_->setItem(row, 1, new QTableWidgetItem("0"));
    }
    layout->addWidget(table_);

    auto* fpLabel = new QLabel("Floating point / SIMD registers");
    layout->addWidget(fpLabel);

    fpTable_ = new QTableWidget;
    fpTable_->setColumnCount(3);
    fpTable_->setHorizontalHeaderLabels({"Register", "XMM low 128", "YMM high 128"});
    // The 128-bit hex value columns are 32 chars wide and clipped at the 100px
    // default; fit the register name and XMM column, YMM (last) stretches.
    fpTable_->horizontalHeader()->setStretchLastSection(true);
    fpTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    fpTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    fpTable_->setFont(QFont("Monospace", 9));
    fpTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fpTable_->setRowCount(16);
    for (int row = 0; row < 16; ++row) {
        fpTable_->setItem(row, 0, new QTableWidgetItem(QString("XMM%1/YMM%1").arg(row)));
        fpTable_->setItem(row, 1, new QTableWidgetItem("unavailable"));
        fpTable_->setItem(row, 2, new QTableWidgetItem("unavailable"));
    }
    layout->addWidget(fpTable_);

    setCentralWidget(central);
    populateThreads();
    refreshRegisters();
}

void RegisterEditorWindow::populateThreads() {
    threadCombo_->clear();
    if (!proc_) return;

    for (const auto& thread : proc_->threads())
        threadCombo_->addItem(QString::number(thread.tid), QVariant::fromValue((qlonglong)thread.tid));
}

void RegisterEditorWindow::refreshRegisters() {
    if (!proc_ || threadCombo_->currentIndex() < 0) return;

    auto tid = (pid_t)threadCombo_->currentData().toLongLong();
    os::LinuxDebugger debugger;
    auto attached = debugger.attach(tid);
    if (!attached) {
        statusLabel_->setText("Could not attach to thread.");
        return;
    }

    auto context = debugger.getContext(tid);
    if (!context) {
        debugger.detach();
        statusLabel_->setText("Could not read thread context.");
        return;
    }

    context_ = *context;
    for (int row = 0; row < (int)std::size(kRegisters); ++row)
        table_->item(row, 1)->setText(hexValue(context_.*(kRegisters[row].member)));
    refreshFloatingPointRegisters(tid);
    debugger.detach();
    statusLabel_->setText(QString("Loaded TID %1").arg(tid));
}

void RegisterEditorWindow::refreshFloatingPointRegisters(pid_t tid) {
    std::array<uint8_t, 4096> xstate{};
    iovec iov{ xstate.data(), xstate.size() };
    if (ptrace(PTRACE_GETREGSET, tid, (void*)NT_X86_XSTATE, &iov) < 0) {
        auto error = QString("unavailable: %1").arg(strerror(errno));
        for (int row = 0; row < fpTable_->rowCount(); ++row) {
            fpTable_->item(row, 1)->setText(error);
            fpTable_->item(row, 2)->setText(error);
        }
        return;
    }

    constexpr size_t fxsaveXmmOffset = 160;
    constexpr size_t xsaveHeaderOffset = 512;
    constexpr size_t ymmHighOffset = 576;
    uint64_t xstateMask = 0;
    if (iov.iov_len >= xsaveHeaderOffset + sizeof(xstateMask))
        std::memcpy(&xstateMask, xstate.data() + xsaveHeaderOffset, sizeof(xstateMask));
    bool hasYmm = (xstateMask & (1ULL << 2)) != 0 && iov.iov_len >= ymmHighOffset + 16 * 16;

    for (int row = 0; row < fpTable_->rowCount(); ++row) {
        auto xmmOffset = fxsaveXmmOffset + (size_t)row * 16;
        if (iov.iov_len >= xmmOffset + 16)
            fpTable_->item(row, 1)->setText(bytesToHex(xstate.data() + xmmOffset, 16));
        else
            fpTable_->item(row, 1)->setText("unavailable");

        if (hasYmm)
            fpTable_->item(row, 2)->setText(bytesToHex(xstate.data() + ymmHighOffset + (size_t)row * 16, 16));
        else
            fpTable_->item(row, 2)->setText("unavailable");
    }
}

void RegisterEditorWindow::applyRegisters() {
    if (!proc_ || threadCombo_->currentIndex() < 0) return;

    CpuContext updated = context_;
    for (int row = 0; row < (int)std::size(kRegisters); ++row) {
        bool ok = false;
        auto value = table_->item(row, 1)->text().toULongLong(&ok, 16);
        if (!ok) {
            statusLabel_->setText(QString("Invalid %1 value.").arg(kRegisters[row].name));
            return;
        }
        updated.*(kRegisters[row].member) = value;
    }

    auto tid = (pid_t)threadCombo_->currentData().toLongLong();
    os::LinuxDebugger debugger;
    auto attached = debugger.attach(tid);
    if (!attached) {
        statusLabel_->setText("Could not attach to thread.");
        return;
    }

    auto applied = debugger.setContext(tid, updated);
    debugger.detach();
    if (!applied) {
        statusLabel_->setText("Could not apply register context.");
        return;
    }

    context_ = updated;
    statusLabel_->setText(QString("Applied TID %1").arg(tid));
}

} // namespace ce::gui
