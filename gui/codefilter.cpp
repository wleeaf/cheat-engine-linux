#include "gui/codefilter.hpp"

#include <QApplication>
#include <QFile>
#include <QFileDialog>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>

namespace ce::gui {

namespace {
constexpr int kAddressRole = Qt::UserRole + 1;
constexpr int kShownRows = 20000;   // the list shows this many; the filter keeps all
}

CodeFilterWindow::CodeFilterWindow(ProcessHandle* process, QWidget* parent) : QMainWindow(parent), process_(process) {
    setAttribute(Qt::WA_DeleteOnClose);
    setWindowTitle(tr("Code Filter"));
    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);
    auto* intro = new QLabel(tr("This places software breakpoints (int3) on many locations of interest (usually "
                                "CALLs) and then tracks which of them execute. Filter between game actions to find "
                                "the code behind one of them."), central);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto* body = new QHBoxLayout;
    auto* left = new QVBoxLayout;
    left->addWidget(new QLabel(tr("Address List"), central));
    list_ = new QListWidget(central);
    list_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    list_->setContextMenuPolicy(Qt::CustomContextMenu);
    left->addWidget(list_, 1);
    body->addLayout(left, 1);

    auto* right = new QVBoxLayout;
    auto* load = new QGroupBox(tr("Load address list"), central);
    auto* loadLayout = new QVBoxLayout(load);
    auto* fromModule = new QPushButton(tr("From Disassembler"), load);
    auto* fromFile = new QPushButton(tr("From File"), load);
    loadLayout->addWidget(fromModule);
    loadLayout->addWidget(fromFile);
    right->addWidget(load);
    startButton_ = new QPushButton(tr("Start"), central);
    stopButton_ = new QPushButton(tr("Stop"), central);
    right->addWidget(startButton_);
    right->addWidget(stopButton_);
    auto* filters = new QGroupBox(tr("Filter out"), central);
    auto* filterLayout = new QVBoxLayout(filters);
    executedButton_ = new QPushButton(tr("Has been executed"), filters);
    executedButton_->setToolTip(tr("Keep only the addresses that executed since Start"));
    notExecutedButton_ = new QPushButton(tr("Has not been executed"), filters);
    notExecutedButton_->setToolTip(tr("Keep only the addresses that did not execute since Start"));
    filterLayout->addWidget(executedButton_);
    filterLayout->addWidget(notExecutedButton_);
    right->addWidget(filters);
    executedLabel_ = new QLabel(central);
    executedLabel_->setWordWrap(true);
    right->addWidget(executedLabel_);
    right->addStretch();
    body->addLayout(right);
    layout->addLayout(body, 1);
    status_ = new QLabel(central);
    layout->addWidget(status_);
    setCentralWidget(central);
    resize(640, 480);

    connect(fromModule, &QPushButton::clicked, this, &CodeFilterWindow::loadFromModule);
    connect(fromFile, &QPushButton::clicked, this, &CodeFilterWindow::loadFromFile);
    connect(startButton_, &QPushButton::clicked, this, &CodeFilterWindow::startFiltering);
    connect(stopButton_, &QPushButton::clicked, this, &CodeFilterWindow::stopFiltering);
    connect(executedButton_, &QPushButton::clicked, this, [this]() { keep(true); });
    connect(notExecutedButton_, &QPushButton::clicked, this, [this]() { keep(false); });
    connect(list_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem* item) {
        emit showInDisassembler(item->data(kAddressRole).toULongLong());
    });
    connect(list_, &QWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        QMenu menu(this);
        menu.addAction(tr("Save addresslist"), [this]() {
            const QString path = QFileDialog::getSaveFileName(this, tr("Save addresslist"), "codefilter.txt",
                                                              tr("Text files (*.txt);;All files (*)"));
            if (path.isEmpty()) return;
            QFile file(path);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
                QMessageBox::warning(this, tr("Save failed"), file.errorString());
                return;
            }
            QTextStream out(&file);
            for (uintptr_t address : filter_.addresses()) out << QString::number(address, 16).toUpper() << '\n';
        });
        menu.addSeparator();
        menu.addAction(tr("Clear list"), [this]() { setAddresses({}); });
        menu.addAction(tr("Delete selected addresses"), [this]() {
            std::vector<uintptr_t> kept = filter_.addresses();
            for (auto* item : list_->selectedItems()) std::erase(kept, item->data(kAddressRole).toULongLong());
            setAddresses(kept);
        });
        menu.exec(list_->viewport()->mapToGlobal(pos));
    });
    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &CodeFilterWindow::updateStatus);
    timer_->start(250);
    updateStatus();
}

CodeFilterWindow::~CodeFilterWindow() { filter_.stop(); }

void CodeFilterWindow::setAddresses(const std::vector<uintptr_t>& addresses) {
    filter_.stop();
    filter_.setAddresses(addresses);
    refreshList();
    updateStatus();
}

void CodeFilterWindow::loadFromModule() {
    if (!process_) return;
    QStringList names;
    const auto modules = process_->modules();
    for (const auto& module : modules) names << QString::fromStdString(module.name);
    if (names.isEmpty()) return;
    bool ok = false;
    const QString chosen = QInputDialog::getItem(this, tr("From Disassembler"), tr("Module:"), names, 0, false, &ok);
    if (!ok) return;
    const auto& module = modules[static_cast<size_t>(names.indexOf(chosen))];
    // Cheat Engine's "Load all instructions into the list or just the CALL's?"
    QMessageBox question(QMessageBox::Question, tr("Code Filter"),
                         tr("Load all instructions into the list or just the CALL's?"), QMessageBox::NoButton, this);
    auto* all = question.addButton(tr("All"), QMessageBox::AcceptRole);
    auto* calls = question.addButton(tr("Call's only"), QMessageBox::AcceptRole);
    question.addButton(QMessageBox::Cancel);
    question.setDefaultButton(calls);
    question.exec();
    if (question.clickedButton() != all && question.clickedButton() != calls) return;
    status_->setText(tr("Disassembling %1...").arg(chosen));
    QApplication::setOverrideCursor(Qt::WaitCursor);
    auto addresses = CodeFilter::codeAddresses(*process_, module.base, module.size, question.clickedButton() == calls);
    QApplication::restoreOverrideCursor();
    setAddresses(addresses);
}

void CodeFilterWindow::loadFromFile() {
    const QString path = QFileDialog::getOpenFileName(this, tr("Load addresslist"), QString(),
                                                      tr("Text files (*.txt);;All files (*)"));
    if (path.isEmpty()) return;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Load failed"), file.errorString());
        return;
    }
    std::vector<uintptr_t> addresses;
    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.startsWith("0x", Qt::CaseInsensitive)) line.remove(0, 2);
        bool ok = false;
        const uintptr_t address = line.toULongLong(&ok, 16);
        if (ok && address) addresses.push_back(address);
    }
    setAddresses(addresses);
}

void CodeFilterWindow::startFiltering() {
    if (!process_) return;
    if (beforeStart_) beforeStart_();
    auto planted = filter_.start(*process_);
    if (!planted) {
        QMessageBox::warning(this, tr("Code Filter"), QString::fromStdString(planted.error()));
        return;
    }
    status_->setText(tr("%1 breakpoints set. Do something in the game, then Stop.").arg(*planted));
    updateStatus();
}

void CodeFilterWindow::stopFiltering() {
    filter_.stop();
    updateStatus();
}

void CodeFilterWindow::keep(bool executed) {
    filter_.stop();
    filter_.filter(executed);
    refreshList();
    updateStatus();
}

void CodeFilterWindow::refreshList() {
    list_->clear();
    const auto addresses = filter_.addresses();
    for (size_t i = 0; i < addresses.size() && i < static_cast<size_t>(kShownRows); ++i) {
        QString label = QString::number(addresses[i], 16).toUpper();
        if (process_) {
            const std::string module = moduleOffsetString(process_->modules(), addresses[i]);
            if (!module.empty()) label += "  (" + QString::fromStdString(module) + ")";
        }
        auto* item = new QListWidgetItem(label, list_);
        item->setData(kAddressRole, static_cast<qulonglong>(addresses[i]));
    }
}

void CodeFilterWindow::updateStatus() {
    const bool running = filter_.running();
    const size_t count = filter_.addresses().size();
    startButton_->setEnabled(!running && count && process_);
    stopButton_->setEnabled(running);
    executedButton_->setEnabled(count);
    notExecutedButton_->setEnabled(count);
    executedLabel_->setText(tr("Addresses executed since last filter operation: %1").arg(filter_.executedCount()));
    if (!running) status_->setText(tr("%1 addresses in the list").arg(count));
}

} // namespace ce::gui
