/// Break-and-trace window — runs a Tracer on a worker thread, displays decoded steps.

#include "gui/tracerwindow.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QFont>
#include <QDialog>
#include <QPlainTextEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QTimer>

namespace ce::gui {

QString TracerWindow::hexQ(uint64_t v) { return QString("0x%1").arg(v, 0, 16); }

static QString fullRegisterDump(const ce::CpuContext& c) {
    auto h = [](uint64_t v) { return QString("0x%1").arg(v, 0, 16); };
    QString s;
    s += QString("rax = %1   rbx = %2\n").arg(h(c.rax), h(c.rbx));
    s += QString("rcx = %1   rdx = %2\n").arg(h(c.rcx), h(c.rdx));
    s += QString("rsi = %1   rdi = %2\n").arg(h(c.rsi), h(c.rdi));
    s += QString("rbp = %1   rsp = %2\n").arg(h(c.rbp), h(c.rsp));
    s += QString("r8  = %1   r9  = %2\n").arg(h(c.r8),  h(c.r9));
    s += QString("r10 = %1   r11 = %2\n").arg(h(c.r10), h(c.r11));
    s += QString("r12 = %1   r13 = %2\n").arg(h(c.r12), h(c.r13));
    s += QString("r14 = %1   r15 = %2\n").arg(h(c.r14), h(c.r15));
    s += QString("rip = %1\n").arg(h(c.rip));
    s += QString("rflags = %1\n").arg(h(c.rflags));
    return s;
}

TracerWindow::TracerWindow(ProcessHandle* proc, DebuggerFactory factory, QWidget* parent)
    : QMainWindow(parent), proc_(proc), debuggerFactory_(std::move(factory)) {
    setWindowTitle("Break and Trace");
    resize(1100, 600);
    buildUi();
}

TracerWindow::~TracerWindow() {
    if (worker_.joinable()) {
        tracer_.cancel();
        worker_.join();
    }
}

void TracerWindow::buildUi() {
    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    // Inputs grid
    auto* form = new QGridLayout;
    int row = 0;

    form->addWidget(new QLabel("Start address (hex):"), row, 0);
    startAddressEdit_ = new QLineEdit;
    startAddressEdit_->setPlaceholderText("0x0000000000000000, leave blank to start at RIP");
    form->addWidget(startAddressEdit_, row, 1, 1, 3);
    ++row;

    form->addWidget(new QLabel("Max steps:"), row, 0);
    maxStepsSpin_ = new QSpinBox;
    maxStepsSpin_->setRange(1, 1'000'000);
    maxStepsSpin_->setValue(1000);
    form->addWidget(maxStepsSpin_, row, 1);

    stepOverCheck_ = new QCheckBox("Step over calls");
    form->addWidget(stepOverCheck_, row, 2);

    stayInModuleCheck_ = new QCheckBox("Stay in module");
    form->addWidget(stayInModuleCheck_, row, 3);
    ++row;

    form->addWidget(new QLabel("Module start (hex):"), row, 0);
    moduleStartEdit_ = new QLineEdit;
    moduleStartEdit_->setPlaceholderText("0x... (only if Stay in module)");
    form->addWidget(moduleStartEdit_, row, 1);
    form->addWidget(new QLabel("end:"), row, 2);
    moduleEndEdit_ = new QLineEdit;
    form->addWidget(moduleEndEdit_, row, 3);
    ++row;

    form->addWidget(new QLabel("Stop address (hex, optional):"), row, 0);
    stopAddressEdit_ = new QLineEdit;
    stopAddressEdit_->setPlaceholderText("Trace stops when this address is reached");
    form->addWidget(stopAddressEdit_, row, 1, 1, 3);
    ++row;

    layout->addLayout(form);

    // Buttons + progress
    auto* btnRow = new QHBoxLayout;
    startBtn_ = new QPushButton("Start Trace");
    cancelBtn_ = new QPushButton("Cancel");
    cancelBtn_->setEnabled(false);
    saveBtn_ = new QPushButton("Save…");
    saveBtn_->setEnabled(false);
    progressBar_ = new QProgressBar;
    progressBar_->setRange(0, 100);
    statusLabel_ = new QLabel("Idle");
    btnRow->addWidget(startBtn_);
    btnRow->addWidget(cancelBtn_);
    btnRow->addWidget(saveBtn_);
    btnRow->addWidget(progressBar_, 1);
    btnRow->addWidget(statusLabel_);
    layout->addLayout(btnRow);

    // Results table
    table_ = new QTableWidget;
    table_->setColumnCount(8);
    table_->setHorizontalHeaderLabels({"#", "Address", "Instruction", "RAX", "RBX", "RCX", "RDX", "RIP"});
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setFont(QFont("Monospace", 9));
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(table_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item) {
        if (!item || item->row() < 0 || item->row() >= (int)entries_.size()) return;
        const auto& e = entries_[item->row()];
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(QString("Step %1 @ 0x%2").arg(item->row()).arg(e.address, 0, 16));
        dlg->resize(500, 320);
        auto* dl = new QVBoxLayout(dlg);
        auto* hdr = new QLabel(QString("<b>%1</b>").arg(QString::fromStdString(e.instruction)));
        dl->addWidget(hdr);
        auto* dump = new QPlainTextEdit(fullRegisterDump(e.context));
        dump->setReadOnly(true);
        dump->setFont(QFont("Monospace", 9));
        dl->addWidget(dump);
        auto* close = new QPushButton("Close");
        connect(close, &QPushButton::clicked, dlg, &QDialog::accept);
        dl->addWidget(close);
        dlg->exec();
        dlg->deleteLater();
    });
    layout->addWidget(table_);

    setCentralWidget(central);

    connect(startBtn_, &QPushButton::clicked, this, &TracerWindow::onStart);
    connect(cancelBtn_, &QPushButton::clicked, this, &TracerWindow::onCancel);
    connect(saveBtn_, &QPushButton::clicked, this, &TracerWindow::onSave);

    // Periodic progress updater while a trace is running.
    auto* poll = new QTimer(this);
    connect(poll, &QTimer::timeout, this, [this]() {
        if (!worker_.joinable()) return;
        progressBar_->setValue((int)(tracer_.progress() * 100.0f));
    });
    poll->start(100);
}

void TracerWindow::onStart() {
    if (!proc_) {
        QMessageBox::warning(this, "No process", "Open a process before tracing.");
        return;
    }
    if (worker_.joinable()) return;

    TraceConfig cfg;
    bool ok = false;
    cfg.startAddress = startAddressEdit_->text().trimmed().isEmpty()
        ? 0
        : (uintptr_t)startAddressEdit_->text().toULongLong(&ok, 16);
    cfg.maxSteps = maxStepsSpin_->value();
    cfg.stepOverCalls = stepOverCheck_->isChecked();
    cfg.stayInModule = stayInModuleCheck_->isChecked();
    cfg.moduleBase = moduleStartEdit_->text().trimmed().isEmpty()
        ? 0
        : (uintptr_t)moduleStartEdit_->text().toULongLong(&ok, 16);
    cfg.moduleEnd = moduleEndEdit_->text().trimmed().isEmpty()
        ? 0
        : (uintptr_t)moduleEndEdit_->text().toULongLong(&ok, 16);
    cfg.stopAddress = stopAddressEdit_->text().trimmed().isEmpty()
        ? 0
        : (uintptr_t)stopAddressEdit_->text().toULongLong(&ok, 16);

    debugger_ = debuggerFactory_ ? debuggerFactory_() : std::make_unique<os::LinuxDebugger>();
    if (!debugger_) {
        QMessageBox::warning(this, "No debugger",
            "No debugger could be constructed for the attached process.");
        return;
    }
    entries_.clear();
    table_->setRowCount(0);
    progressBar_->setValue(0);
    statusLabel_->setText("Tracing…");
    startBtn_->setEnabled(false);
    cancelBtn_->setEnabled(true);
    saveBtn_->setEnabled(false);

    worker_ = std::thread([this, cfg]() {
        auto results = tracer_.trace(*proc_, *debugger_, cfg);
        QMetaObject::invokeMethod(this, [this, results = std::move(results)]() mutable {
            entries_ = std::move(results);
            onTraceFinished();
        }, Qt::QueuedConnection);
    });
}

void TracerWindow::onCancel() {
    tracer_.cancel();
    statusLabel_->setText("Cancelling…");
}

void TracerWindow::onTraceFinished() {
    if (worker_.joinable()) worker_.join();

    table_->setRowCount(entries_.size());
    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& e = entries_[i];
        const auto& c = e.context;
        table_->setItem(i, 0, new QTableWidgetItem(QString::number(i)));
        table_->setItem(i, 1, new QTableWidgetItem(hexQ(e.address)));
        table_->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(e.instruction)));
        table_->setItem(i, 3, new QTableWidgetItem(hexQ(c.rax)));
        table_->setItem(i, 4, new QTableWidgetItem(hexQ(c.rbx)));
        table_->setItem(i, 5, new QTableWidgetItem(hexQ(c.rcx)));
        table_->setItem(i, 6, new QTableWidgetItem(hexQ(c.rdx)));
        table_->setItem(i, 7, new QTableWidgetItem(hexQ(c.rip)));
    }
    progressBar_->setValue(100);
    statusLabel_->setText(QString("%1 steps recorded%2")
        .arg(entries_.size())
        .arg(entries_.size() == 0 ? " (check start address / module range)" : ""));
    startBtn_->setEnabled(true);
    cancelBtn_->setEnabled(false);
    saveBtn_->setEnabled(!entries_.empty());
}

void TracerWindow::onSave() {
    auto path = QFileDialog::getSaveFileName(this, "Save trace", "trace.txt", "Text (*.txt)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Save failed", f.errorString());
        return;
    }
    QTextStream out(&f);
    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& e = entries_[i];
        out << QString("%1\t").arg(i) << hexQ(e.address) << '\t'
            << QString::fromStdString(e.instruction) << '\t'
            << "rax=" << hexQ(e.context.rax) << " rbx=" << hexQ(e.context.rbx)
            << " rcx=" << hexQ(e.context.rcx) << " rdx=" << hexQ(e.context.rdx)
            << " rip=" << hexQ(e.context.rip) << '\n';
    }
}

} // namespace ce::gui
