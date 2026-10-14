#include "gui/threadlist.hpp"
#include "gui/theme.hpp"
#include "core/local_target.hpp"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QFont>
#include <fstream>
#include <cctype>

namespace ce::gui {

ThreadListWindow::ThreadListWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Thread List");
    resize(520, 360);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    table_ = new QTableWidget;
    table_->setColumnCount(3);
    table_->setHorizontalHeaderLabels({"TID", "Name", "State"});
    // TID and State are short and fixed; let the thread Name column take the slack.
    auto* hh = table_->horizontalHeader();
    hh->setStretchLastSection(false);
    hh->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    hh->setSectionResizeMode(1, QHeaderView::Stretch);
    hh->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    styleDataTable(table_);
    layout->addWidget(table_);
    setCentralWidget(central);
    populate();
}

void ThreadListWindow::populate() {
    if (!proc_) return;
    auto threads = proc_->threads();
    table_->setRowCount(threads.size());
    // Once per refresh: for a remote target each call is a network round trip.
    const auto localPid = ce::localTargetPid(proc_);
    for (size_t i = 0; i < threads.size(); ++i) {
        auto& t = threads[i];
        table_->setItem(i, 0, new QTableWidgetItem(QString::number(t.tid)));

        table_->setItem(i, 1, new QTableWidgetItem(threadName(localPid.value_or(0), t.tid)));

        // Read state from /proc/pid/task/tid/status
        std::string state = "?";
        // Only a local target's tasks are under this machine's /proc: a remote
        // PID would name an unrelated local process.
        std::ifstream status;
        if (localPid) status.open("/proc/" + std::to_string(*localPid) + "/task/" + std::to_string(t.tid) + "/status");
        std::string line;
        while (status && std::getline(status, line)) {
            if (line.substr(0, 6) == "State:") {
                // substr(6) is safe even if the line is exactly "State:" (empty value);
                // trim the leading tab/space that follows the field name.
                state = line.substr(6);
                size_t nonWs = state.find_first_not_of(" \t");
                state = (nonWs == std::string::npos) ? "" : state.substr(nonWs);
                // "S (sleeping)" -> "Sleeping": the word, capitalised, without the code letter.
                if (auto open = state.find('('), close = state.rfind(')');
                    open != std::string::npos && close != std::string::npos && close > open + 1) {
                    state = state.substr(open + 1, close - open - 1);
                    state[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(state[0])));
                }
                break;
            }
        }
        table_->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(state)));
    }
    setWindowTitle(QString("Thread List: %1 threads").arg(threads.size()));
}

} // namespace ce::gui
