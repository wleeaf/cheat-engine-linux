#include "gui/codefinder.hpp"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QFont>
#include <QDialog>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QTextStream>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>

namespace ce::gui {

static QString hexQ(uint64_t v) { return QString("0x%1").arg(v, 0, 16); }

static QString fullRegisterDump(const ce::CpuContext& ctx) {
    QString s;
    s += QString("rax = %1   rbx = %2\n").arg(hexQ(ctx.rax), hexQ(ctx.rbx));
    s += QString("rcx = %1   rdx = %2\n").arg(hexQ(ctx.rcx), hexQ(ctx.rdx));
    s += QString("rsi = %1   rdi = %2\n").arg(hexQ(ctx.rsi), hexQ(ctx.rdi));
    s += QString("rbp = %1   rsp = %2\n").arg(hexQ(ctx.rbp), hexQ(ctx.rsp));
    s += QString("r8  = %1   r9  = %2\n").arg(hexQ(ctx.r8),  hexQ(ctx.r9));
    s += QString("r10 = %1   r11 = %2\n").arg(hexQ(ctx.r10), hexQ(ctx.r11));
    s += QString("r12 = %1   r13 = %2\n").arg(hexQ(ctx.r12), hexQ(ctx.r13));
    s += QString("r14 = %1   r15 = %2\n").arg(hexQ(ctx.r14), hexQ(ctx.r15));
    s += QString("rip = %1\n").arg(hexQ(ctx.rip));
    s += QString("rflags = %1\n").arg(hexQ(ctx.rflags));
    s += QString("cs=%1 ss=%2 ds=%3 es=%4 fs=%5 gs=%6\n")
            .arg(hexQ(ctx.cs)).arg(hexQ(ctx.ss)).arg(hexQ(ctx.ds))
            .arg(hexQ(ctx.es)).arg(hexQ(ctx.fs)).arg(hexQ(ctx.gs));
    s += QString("dr0=%1 dr1=%2 dr2=%3 dr3=%4 dr6=%5 dr7=%6\n")
            .arg(hexQ(ctx.dr0)).arg(hexQ(ctx.dr1)).arg(hexQ(ctx.dr2))
            .arg(hexQ(ctx.dr3)).arg(hexQ(ctx.dr6)).arg(hexQ(ctx.dr7));
    return s;
}

CodeFinderWindow::CodeFinderWindow(CodeFinder* finder, const QString& title, QWidget* parent)
    : QMainWindow(parent), finder_(finder) {
    setWindowTitle(title);
    resize(1100, 500);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    statusLabel_ = new QLabel("Monitoring...");
    layout->addWidget(statusLabel_);

    table_ = new QTableWidget;
    table_->setColumnCount(8);
    table_->setHorizontalHeaderLabels({"Address", "Instruction", "Hits", "RAX", "RBX", "RCX", "RDX", "RIP"});
    table_->horizontalHeader()->setStretchLastSection(false);
    // Fit the address, hit count and 64-bit register columns to content (they
    // clipped at the 100px default); the disassembly text takes the slack.
    for (int c = 0; c < 8; ++c)
        table_->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setFont(QFont("Monospace", 9));
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(table_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item) {
        if (!item) return;
        int row = item->row();
        auto results = finder_->results();
        if (row < 0 || row >= (int)results.size()) return;

        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(QString("Hit context @ 0x%1").arg(results[row].instructionAddress, 0, 16));
        dlg->resize(520, 360);
        auto* dlgLayout = new QVBoxLayout(dlg);
        auto* hdr = new QLabel(QString("<b>%1</b>  hits=%2")
            .arg(QString::fromStdString(results[row].instructionText))
            .arg(results[row].hitCount));
        dlgLayout->addWidget(hdr);

        auto* firstLabel = new QLabel("<b>First hit:</b>");
        dlgLayout->addWidget(firstLabel);
        auto* firstDump = new QPlainTextEdit(fullRegisterDump(results[row].firstContext));
        firstDump->setReadOnly(true);
        firstDump->setFont(QFont("Monospace", 9));
        dlgLayout->addWidget(firstDump);

        auto* lastLabel = new QLabel("<b>Last hit:</b>");
        dlgLayout->addWidget(lastLabel);
        auto* lastDump = new QPlainTextEdit(fullRegisterDump(results[row].lastContext));
        lastDump->setReadOnly(true);
        lastDump->setFont(QFont("Monospace", 9));
        dlgLayout->addWidget(lastDump);

        auto* btn = new QPushButton("Close");
        connect(btn, &QPushButton::clicked, dlg, &QDialog::accept);
        dlgLayout->addWidget(btn);
        dlg->exec();
        dlg->deleteLater();
    });
    layout->addWidget(table_);

    auto* btnRow = new QHBoxLayout;
    stopBtn_ = new QPushButton("Stop");
    connect(stopBtn_, &QPushButton::clicked, this, &CodeFinderWindow::onStop);
    btnRow->addWidget(stopBtn_);
    btnRow->addStretch();
    auto* addBtn = new QPushButton("Add to Address List");
    addBtn->setToolTip("Add the selected instructions (or all, if none selected) to the address list.");
    connect(addBtn, &QPushButton::clicked, this, &CodeFinderWindow::onAddToList);
    btnRow->addWidget(addBtn);
    saveBtn_ = new QPushButton("Save to File...");
    saveBtn_->setToolTip("Export the found instructions, hit counts, and registers to a text file.");
    connect(saveBtn_, &QPushButton::clicked, this, &CodeFinderWindow::onExportToFile);
    btnRow->addWidget(saveBtn_);
    layout->addLayout(btnRow);

    setCentralWidget(central);

    refreshTimer_ = new QTimer(this);
    connect(refreshTimer_, &QTimer::timeout, this, &CodeFinderWindow::refresh);
    refreshTimer_->start(500);
}

void CodeFinderWindow::refresh() {
    auto results = finder_->results();
    statusLabel_->setText(finder_->running()
        ? QString("Monitoring... %1 unique instructions found (double-click a row for full register state)").arg(results.size())
        : QString("Stopped. %1 unique instructions found").arg(results.size()));

    table_->setRowCount(results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        auto& r = results[i];
        const auto& c = r.lastContext;
        table_->setItem(i, 0, new QTableWidgetItem(hexQ(r.instructionAddress)));
        table_->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(r.instructionText)));
        table_->setItem(i, 2, new QTableWidgetItem(QString::number(r.hitCount)));
        table_->setItem(i, 3, new QTableWidgetItem(hexQ(c.rax)));
        table_->setItem(i, 4, new QTableWidgetItem(hexQ(c.rbx)));
        table_->setItem(i, 5, new QTableWidgetItem(hexQ(c.rcx)));
        table_->setItem(i, 6, new QTableWidgetItem(hexQ(c.rdx)));
        table_->setItem(i, 7, new QTableWidgetItem(hexQ(c.rip)));
    }
}

void CodeFinderWindow::onStop() {
    finder_->stop();
    stopBtn_->setEnabled(false);
    statusLabel_->setText(QString("Stopped. %1 unique instructions found").arg(finder_->results().size()));
}

void CodeFinderWindow::onAddToList() {
    if (!addToList_) return;
    auto results = finder_->results();
    // Use the selected rows, or all rows if the user selected none.
    std::vector<int> rows;
    for (const auto& idx : table_->selectionModel()->selectedRows())
        rows.push_back(idx.row());
    if (rows.empty())
        for (int i = 0; i < (int)results.size(); ++i) rows.push_back(i);

    int added = 0;
    for (int row : rows) {
        if (row < 0 || row >= (int)results.size()) continue;
        const auto& r = results[row];
        addToList_(r.instructionAddress, QString::fromStdString(r.instructionText));
        ++added;
    }
    statusLabel_->setText(QString("Added %1 instruction(s) to the address list.").arg(added));
}

void CodeFinderWindow::onExportToFile() {
    auto results = finder_->results();
    QString path = QFileDialog::getSaveFileName(this, "Save findings",
        "code-finder.txt", "Text files (*.txt);;All files (*)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Save failed", f.errorString());
        return;
    }
    QTextStream out(&f);
    out << windowTitle() << "\n";
    out << QString("%1 unique instruction(s)\n\n").arg(results.size());
    for (const auto& r : results) {
        out << QString("0x%1  hits=%2  %3\n")
                   .arg(r.instructionAddress, 0, 16)
                   .arg(r.hitCount)
                   .arg(QString::fromStdString(r.instructionText));
        const auto& c = r.firstContext;
        out << QString("    rax=%1 rbx=%2 rcx=%3 rdx=%4 rsi=%5 rdi=%6 rip=%7\n")
                   .arg(c.rax,0,16).arg(c.rbx,0,16).arg(c.rcx,0,16).arg(c.rdx,0,16)
                   .arg(c.rsi,0,16).arg(c.rdi,0,16).arg(c.rip,0,16);
    }
    statusLabel_->setText(QString("Saved %1 instruction(s) to %2").arg(results.size()).arg(path));
}

} // namespace ce::gui
