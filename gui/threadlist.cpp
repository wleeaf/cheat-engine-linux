#include "gui/threadlist.hpp"
#include <QVBoxLayout>
#include <QHeaderView>
#include <QFont>
#include <fstream>

namespace ce::gui {

ThreadListWindow::ThreadListWindow(ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Thread List");
    resize(400, 300);

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
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setFont(QFont("Monospace", 9));
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table_);
    setCentralWidget(central);
    populate();
}

void ThreadListWindow::populate() {
    if (!proc_) return;
    auto threads = proc_->threads();
    table_->setRowCount(threads.size());
    for (size_t i = 0; i < threads.size(); ++i) {
        auto& t = threads[i];
        table_->setItem(i, 0, new QTableWidgetItem(QString::number(t.tid)));

        // Read thread name from /proc/pid/task/tid/comm
        std::string name;
        std::ifstream comm("/proc/" + std::to_string(proc_->pid()) + "/task/" + std::to_string(t.tid) + "/comm");
        if (comm) std::getline(comm, name);
        table_->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(name)));

        // Read state from /proc/pid/task/tid/status
        std::string state = "?";
        std::ifstream status("/proc/" + std::to_string(proc_->pid()) + "/task/" + std::to_string(t.tid) + "/status");
        std::string line;
        while (status && std::getline(status, line)) {
            if (line.substr(0, 6) == "State:") {
                // substr(6) is safe even if the line is exactly "State:" (empty value);
                // trim the leading tab/space that follows the field name.
                state = line.substr(6);
                size_t nonWs = state.find_first_not_of(" \t");
                state = (nonWs == std::string::npos) ? "" : state.substr(nonWs);
                break;
            }
        }
        table_->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(state)));
    }
}

} // namespace ce::gui
