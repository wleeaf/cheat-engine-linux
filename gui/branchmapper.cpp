/// Branch Mapper window — LBR sample collector + frequency view.

#include "gui/branchmapper.hpp"
#include <limits>
#include "core/local_target.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QHeaderView>
#include <QFont>
#include <QMessageBox>

namespace ce::gui {

BranchMapper::BranchMapper(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Branch Mapper (LBR)");
    resize(900, 600);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    auto* form = new QFormLayout;
    tidSpin_ = new QSpinBox;
    tidSpin_->setObjectName("branchMapperThread");
    tidSpin_->setRange(1,std::numeric_limits<pid_t>::max());
    if (proc_) {
        auto threads = proc_->threads();
        if (!threads.empty()) tidSpin_->setValue(threads.front().tid);
        else if (auto pid=ce::localTargetPid(proc_)) tidSpin_->setValue(*pid);
    }
    form->addRow("Thread ID:", tidSpin_);

    auto* btnRow = new QHBoxLayout;
    startBtn_ = new QPushButton("Start sampling");
    startBtn_->setObjectName("branchMapperStart");
    stopBtn_  = new QPushButton("Stop");
    stopBtn_->setEnabled(false);
    clearBtn_ = new QPushButton("Clear");
    const bool local=ce::localTargetPid(proc_).has_value();
    statusLabel_ = new QLabel(!local ? "Branch sampling requires a live local process target" :
        LbrTracer::available() ? "Idle" :
        "Branch-stack sampling unavailable; requires kernel perf permission and a supported CPU/PMU.");
    statusLabel_->setObjectName("branchMapperStatus");statusLabel_->setWordWrap(true);
    if (!local) {startBtn_->setEnabled(false);tidSpin_->setEnabled(false);}
    btnRow->addWidget(startBtn_);
    btnRow->addWidget(stopBtn_);
    btnRow->addWidget(clearBtn_);
    btnRow->addStretch();
    btnRow->addWidget(statusLabel_, 1);

    layout->addLayout(form);
    layout->addLayout(btnRow);

    table_ = new QTableWidget;
    table_->setColumnCount(6);
    table_->setHorizontalHeaderLabels({"From", "From symbol", "To", "To symbol", "Hits", "% of total"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setFont(QFont("Monospace", 9));
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table_);

    setCentralWidget(central);

    connect(startBtn_, &QPushButton::clicked, this, &BranchMapper::onStart);
    connect(stopBtn_,  &QPushButton::clicked, this, &BranchMapper::onStop);
    connect(clearBtn_, &QPushButton::clicked, this, &BranchMapper::onClear);

    pollTimer_ = new QTimer(this);
    connect(pollTimer_, &QTimer::timeout, this, &BranchMapper::onPoll);
}

BranchMapper::~BranchMapper() {
    tracer_.stop();
}

void BranchMapper::onStart() {
    if (!ce::localTargetPid(proc_)) {
        statusLabel_->setText("Branch sampling requires a live local process target");
        startBtn_->setEnabled(false);tidSpin_->setEnabled(false);return;
    }
    pid_t tid = (pid_t)tidSpin_->value();
    if (!tracer_.start(tid)) {
        QMessageBox::warning(this, "Start failed",
            QString::fromStdString(tracer_.lastError()));
        return;
    }
    // One-shot symbol load so the table can show fn names alongside addrs.
    if (proc_ && !symbolsLoaded_) {
        resolver_.loadProcess(*proc_);
        symbolsLoaded_ = true;
    }
    startBtn_->setEnabled(false);
    stopBtn_->setEnabled(true);
    tidSpin_->setEnabled(false);
    statusLabel_->setText("Sampling…");
    pollTimer_->start(250);
}

void BranchMapper::onStop() {
    pollTimer_->stop();
    tracer_.stop();
    const bool local=ce::localTargetPid(proc_).has_value();
    startBtn_->setEnabled(local);
    stopBtn_->setEnabled(false);
    tidSpin_->setEnabled(local);
    statusLabel_->setText(QString("Stopped. %1 samples total.").arg(totalSamples_));
}

void BranchMapper::onClear() {
    counts_.clear();
    totalSamples_ = 0;
    table_->setRowCount(0);
    statusLabel_->setText(ce::localTargetPid(proc_) ? "Cleared." : "Branch sampling requires a live local process target");
}

void BranchMapper::onPoll() {
    auto entries = tracer_.drain();
    if (entries.empty()) return;
    for (const auto& e : entries) {
        counts_[e.from][e.to] += 1;
        ++totalSamples_;
    }

    // Flatten for display, sorted by hit count descending. Cap to top 500
    // to keep the table responsive.
    struct Row { uint64_t from; uint64_t to; size_t hits; };
    std::vector<Row> flat;
    flat.reserve(256);
    for (const auto& [from, tos] : counts_)
        for (const auto& [to, n] : tos)
            flat.push_back({from, to, n});
    std::sort(flat.begin(), flat.end(),
        [](const Row& a, const Row& b) { return a.hits > b.hits; });
    if (flat.size() > 500) flat.resize(500);

    auto sym = [&](uint64_t addr) {
        if (!symbolsLoaded_) return QString();
        auto s = resolver_.resolve(addr);
        return s.empty() ? QString() : QString::fromStdString(s);
    };
    table_->setRowCount((int)flat.size());
    for (size_t i = 0; i < flat.size(); ++i) {
        const auto& r = flat[i];
        table_->setItem((int)i, 0, new QTableWidgetItem(QString("0x%1").arg(r.from, 16, 16, QChar('0'))));
        table_->setItem((int)i, 1, new QTableWidgetItem(sym(r.from)));
        table_->setItem((int)i, 2, new QTableWidgetItem(QString("0x%1").arg(r.to,   16, 16, QChar('0'))));
        table_->setItem((int)i, 3, new QTableWidgetItem(sym(r.to)));
        table_->setItem((int)i, 4, new QTableWidgetItem(QString::number(r.hits)));
        double pct = totalSamples_ ? (100.0 * r.hits / totalSamples_) : 0.0;
        table_->setItem((int)i, 5, new QTableWidgetItem(QString::number(pct, 'f', 2) + "%"));
    }
    statusLabel_->setText(QString("Sampling… %1 total / %2 unique pairs")
        .arg(totalSamples_).arg(flat.size()));
}

} // namespace ce::gui
