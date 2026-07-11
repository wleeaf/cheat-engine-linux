/// File patcher dialog — overwrite a chunk of an on-disk file with user-supplied
/// hex bytes. Mirrors CE's frmFilePatcher: pick file, set offset, paste hex,
/// click Apply.

#include "gui/filepatcher.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QLabel>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QFont>
#include <QRegularExpression>

namespace ce::gui {

FilePatcher::FilePatcher(QWidget* parent) : QDialog(parent) {
    setWindowTitle("File Patcher");
    resize(540, 420);

    auto* root = new QVBoxLayout(this);

    auto* form = new QFormLayout;

    auto* pathRow = new QHBoxLayout;
    pathEdit_ = new QLineEdit;
    pathEdit_->setPlaceholderText("/path/to/file.exe");
    auto* browseBtn = new QPushButton("Browse…");
    connect(browseBtn, &QPushButton::clicked, this, &FilePatcher::onChooseFile);
    pathRow->addWidget(pathEdit_);
    pathRow->addWidget(browseBtn);
    form->addRow("File:", pathRow);

    offsetEdit_ = new QLineEdit;
    offsetEdit_->setPlaceholderText("0x0 (hex with 0x prefix, decimal otherwise)");
    form->addRow("Offset:", offsetEdit_);

    auto* readRow = new QHBoxLayout;
    readSizeSpin_ = new QSpinBox;
    readSizeSpin_->setRange(1, 1024);
    readSizeSpin_->setValue(16);
    auto* readBtn = new QPushButton("Read current bytes");
    connect(readBtn, &QPushButton::clicked, this, &FilePatcher::onReadBytes);
    readRow->addWidget(readSizeSpin_);
    readRow->addWidget(readBtn);
    readRow->addStretch();
    form->addRow("Inspect:", readRow);

    root->addLayout(form);

    root->addWidget(new QLabel("Hex bytes to write (whitespace ignored):"));
    hexEdit_ = new QPlainTextEdit;
    hexEdit_->setFont(QFont("Monospace", 10));
    hexEdit_->setPlaceholderText("DE AD BE EF\n90 90 90");
    root->addWidget(hexEdit_, /*stretch=*/1);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    auto* applyBtn = new QPushButton("Apply Patch");
    auto* closeBtn = new QPushButton("Close");
    connect(applyBtn, &QPushButton::clicked, this, &FilePatcher::onApply);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnRow->addWidget(applyBtn);
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);
}

void FilePatcher::onChooseFile() {
    auto path = QFileDialog::getOpenFileName(this, "Choose file to patch",
        pathEdit_->text(), "All Files (*)");
    if (!path.isEmpty()) pathEdit_->setText(path);
}

static QByteArray parseHexBytes(const QString& text, QString* err) {
    QString clean = text;
    clean.replace(QRegularExpression(R"(\s+)"), "");
    if (clean.size() % 2 != 0) {
        if (err) *err = "Hex byte sequence has odd length.";
        return {};
    }
    QByteArray out;
    out.reserve(clean.size() / 2);
    for (int i = 0; i < clean.size(); i += 2) {
        bool ok = false;
        uint8_t b = (uint8_t)QStringView(clean).mid(i, 2).toUInt(&ok, 16);
        if (!ok) {
            if (err) *err = QString("Not a hex byte: '%1'").arg(clean.mid(i, 2));
            return {};
        }
        out.append((char)b);
    }
    return out;
}

void FilePatcher::onReadBytes() {
    if (pathEdit_->text().isEmpty()) {
        QMessageBox::warning(this, "Pick a file", "Choose a file first.");
        return;
    }
    bool ok = false;
    qint64 offset = offsetEdit_->text().toLongLong(&ok, 0);
    if (!ok) {
        QMessageBox::warning(this, "Bad offset", "Offset doesn't parse.");
        return;
    }
    QFile f(pathEdit_->text());
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Open failed", f.errorString());
        return;
    }
    if (!f.seek(offset)) {
        QMessageBox::warning(this, "Seek failed", "Offset is past end of file.");
        return;
    }
    QByteArray buf = f.read(readSizeSpin_->value());
    QString hex;
    for (int i = 0; i < buf.size(); ++i) {
        if (i) hex += ' ';
        hex += QString("%1").arg((uint8_t)buf[i], 2, 16, QChar('0')).toUpper();
    }
    hexEdit_->setPlainText(hex);
}

void FilePatcher::onApply() {
    if (pathEdit_->text().isEmpty()) {
        QMessageBox::warning(this, "Pick a file", "Choose a file first.");
        return;
    }
    bool ok = false;
    qint64 offset = offsetEdit_->text().toLongLong(&ok, 0);
    if (!ok) {
        QMessageBox::warning(this, "Bad offset", "Offset doesn't parse.");
        return;
    }
    QString err;
    auto bytes = parseHexBytes(hexEdit_->toPlainText(), &err);
    if (bytes.isEmpty()) {
        QMessageBox::warning(this, "Bad hex", err.isEmpty() ? "Provide at least one hex byte." : err);
        return;
    }
    auto answer = QMessageBox::question(this, "Confirm patch",
        QString("Write %1 byte%2 to %3 at offset 0x%4?\nThis modifies the file in place.")
            .arg(bytes.size()).arg(bytes.size() == 1 ? "" : "s")
            .arg(pathEdit_->text()).arg(offset, 0, 16));
    if (answer != QMessageBox::Yes) return;

    QFile f(pathEdit_->text());
    if (!f.open(QIODevice::ReadWrite)) {
        QMessageBox::warning(this, "Open failed", f.errorString());
        return;
    }
    // ReadWrite seek-past-EOF succeeds and would grow the file (sparse hole)
    // rather than patch in place; confirm before extending.
    if (offset + (qint64)bytes.size() > f.size()) {
        auto extend = QMessageBox::question(this, "Extend file?",
            QString("The patch ends at offset 0x%1 but the file is only 0x%2 bytes.\n"
                    "Applying it will grow the file (zero-filling the gap). Continue?")
                .arg(offset + (qint64)bytes.size(), 0, 16).arg(f.size(), 0, 16));
        if (extend != QMessageBox::Yes) return;
    }
    if (!f.seek(offset)) {
        QMessageBox::warning(this, "Seek failed", "Offset is past end of file.");
        return;
    }
    qint64 written = f.write(bytes);
    if (written != bytes.size()) {
        QMessageBox::warning(this, "Write failed", f.errorString());
        return;
    }
    QMessageBox::information(this, "Patched",
        QString("Wrote %1 bytes at 0x%2.").arg(written).arg(offset, 0, 16));
}

} // namespace ce::gui
