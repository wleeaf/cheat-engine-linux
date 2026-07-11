#pragma once
/// Branch Mapper — visualises hardware LBR (last-branch-record) samples for
/// a chosen thread. Equivalent of CE's frmbranchmapper. Backed by
/// ce::LbrTracer; falls back to a disabled state when perf_event_open
/// can't be set up on the runner.

#include "debug/lbr_tracer.hpp"
#include "platform/process_api.hpp"
#include "symbols/elf_symbols.hpp"

#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QSpinBox>
#include <QTimer>
#include <unordered_map>

namespace ce::gui {

class BranchMapper : public QMainWindow {
    Q_OBJECT
public:
    explicit BranchMapper(ce::ProcessHandle* proc, QWidget* parent = nullptr);
    ~BranchMapper() override;

private slots:
    void onStart();
    void onStop();
    void onClear();
    void onPoll();

private:
    ce::ProcessHandle* proc_;
    ce::LbrTracer tracer_;
    ce::SymbolResolver resolver_;
    bool symbolsLoaded_ = false;

    QSpinBox*    tidSpin_;
    QPushButton* startBtn_;
    QPushButton* stopBtn_;
    QPushButton* clearBtn_;
    QLabel*      statusLabel_;
    QTableWidget* table_;
    QTimer*      pollTimer_;

    // (from, to) → hit count
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, size_t>> counts_;
    size_t totalSamples_ = 0;
};

} // namespace ce::gui
