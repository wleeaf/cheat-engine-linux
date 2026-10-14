/// ELF inspector — thin wrapper over binutils' readelf. Tabbed view.

#include "gui/elfinspector.hpp"
#include <memory>
#include <QTimer>
#include <QPointer>
#include "gui/theme.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QFont>
#include <QProcess>
#include <QStandardPaths>

namespace ce::gui {

ElfInspector::ElfInspector(const QString& initialPath, QWidget* parent) : QDialog(parent) {
    setWindowTitle("ELF Inspector");
    resize(900, 640);

    auto* root = new QVBoxLayout(this);

    auto* row = new QHBoxLayout;
    row->addWidget(new QLabel("ELF file:"));
    pathEdit_ = new QLineEdit;
    pathEdit_->setText(initialPath);
    row->addWidget(pathEdit_, /*stretch=*/1);
    auto* browseBtn = new QPushButton("Browse…");
    auto* loadBtn   = new QPushButton("Load");
    row->addWidget(browseBtn);
    row->addWidget(loadBtn);
    root->addLayout(row);

    connect(browseBtn, &QPushButton::clicked, this, &ElfInspector::onBrowse);
    connect(loadBtn,   &QPushButton::clicked, this, &ElfInspector::onLoad);

    tabs_ = new QTabWidget;
    auto makePane = [&](const char* title) {
        auto* edit = new QPlainTextEdit;
        edit->setReadOnly(true);
        edit->setFont(monospaceFont(-1));
        edit->setLineWrapMode(QPlainTextEdit::NoWrap);   // keep readelf's columns intact
        tabs_->addTab(edit, title);
        return edit;
    };
    headerView_  = makePane("Header");
    sectionView_ = makePane("Sections");
    programView_ = makePane("Segments");
    dynamicView_ = makePane("Dynamic");
    symbolView_  = makePane("Symbols");
    notesView_   = makePane("Notes");

    root->addWidget(tabs_, 1);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    auto* closeBtn = new QPushButton("Close");
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);

    if (!initialPath.isEmpty()) onLoad();
}

void ElfInspector::onBrowse() {
    auto path = QFileDialog::getOpenFileName(this, "Choose ELF file",
        pathEdit_->text(), "All Files (*)");
    if (!path.isEmpty()) pathEdit_->setText(path);
}

void ElfInspector::runReadelf(QPlainTextEdit* sink, const QStringList& args) {
    // Resolve readelf to a trusted absolute path once, so a poisoned $PATH
    // (cecore commonly runs as root) cannot substitute a malicious binary.
    static const QString readelfPath = QStandardPaths::findExecutable("readelf");
    if (readelfPath.isEmpty()) {
        sink->setPlainText("readelf not found in PATH (install binutils).");
        return;
    }
    // Asynchronous: six runs on a large library took up to a minute on the GUI
    // thread. Output of a load that a newer one replaced is dropped.
    sink->setPlainText("Running readelf...");
    const int generation = loadGeneration_;
    auto* process = new QProcess(this);
    QPointer<QPlainTextEdit> out(sink);
    auto timedOut = std::make_shared<bool>(false);
    connect(process, &QProcess::finished, this, [this, process, out, generation, timedOut]() {
        process->deleteLater();
        if (!out || generation != loadGeneration_) return;
        if (*timedOut) { out->setPlainText("readelf took longer than 60 seconds and was stopped."); return; }
        QString text = QString::fromUtf8(process->readAllStandardOutput());
        const QByteArray err = process->readAllStandardError();
        if (!err.isEmpty()) text += "\n--- stderr ---\n" + QString::fromUtf8(err);
        out->setPlainText(text.isEmpty() ? QStringLiteral("(readelf produced no output)") : text);
    });
    connect(process, &QProcess::errorOccurred, this, [this, process, out, generation](QProcess::ProcessError error) {
        if (error != QProcess::FailedToStart) return;   // a crash or kill still emits finished
        process->deleteLater();
        if (out && generation == loadGeneration_) out->setPlainText("readelf could not be started.");
    });
    QTimer::singleShot(60'000, process, [process, timedOut]() { *timedOut = true; process->kill(); });
    process->start(readelfPath, args);
}

void ElfInspector::onLoad() {
    auto path = pathEdit_->text();
    if (path.isEmpty()) return;
    ++loadGeneration_;
    // "--": a file name starting with '-' is not an option.
    runReadelf(headerView_,  {"-hW", "--", path});
    runReadelf(sectionView_, {"-SW", "--", path});
    runReadelf(programView_, {"-lW", "--", path});
    runReadelf(dynamicView_, {"-dW", "--", path});
    runReadelf(symbolView_,  {"-sW", "--", path});
    runReadelf(notesView_,   {"-nW", "--", path});
}

} // namespace ce::gui
