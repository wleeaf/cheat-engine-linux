/// File patcher dialog — overwrite a chunk of an on-disk file with user-supplied
/// hex bytes. Mirrors CE's frmFilePatcher: pick file, set offset, paste hex,
/// click Apply.

#include "gui/filepatcher.hpp"
#include "gui/theme.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QLabel>
#include <QCoreApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QFont>
#include <QRegularExpression>

namespace ce::gui {

FilePatcher::FilePatcher(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("File Patcher"));
    resize(540, 420);

    auto* root = new QVBoxLayout(this);

    auto* form = new QFormLayout;

    auto* pathRow = new QHBoxLayout;
    pathEdit_ = new QLineEdit;
    pathEdit_->setPlaceholderText(tr("/path/to/file"));
    auto* browseBtn = new QPushButton(tr("Browse…"));
    connect(browseBtn, &QPushButton::clicked, this, &FilePatcher::onChooseFile);
    pathRow->addWidget(pathEdit_);
    pathRow->addWidget(browseBtn);
    form->addRow(tr("File:"), pathRow);

    offsetEdit_ = new QLineEdit;
    offsetEdit_->setPlaceholderText(tr("0x0 (hex with 0x prefix, decimal otherwise)"));
    form->addRow(tr("Offset:"), offsetEdit_);

    auto* readRow = new QHBoxLayout;
    readSizeSpin_ = new QSpinBox;
    readSizeSpin_->setRange(1, 1024);
    readSizeSpin_->setValue(16);
    auto* readBtn = new QPushButton(tr("Read current bytes"));
    connect(readBtn, &QPushButton::clicked, this, &FilePatcher::onReadBytes);
    readRow->addWidget(readSizeSpin_);
    readRow->addWidget(readBtn);
    readRow->addStretch();
    form->addRow(tr("Inspect:"), readRow);

    root->addLayout(form);

    root->addWidget(new QLabel(tr("Hex bytes to write (whitespace ignored):")));
    hexEdit_ = new QPlainTextEdit;
    hexEdit_->setFont(monospaceFont());
    hexEdit_->setPlaceholderText("DE AD BE EF\n90 90 90");
    root->addWidget(hexEdit_, /*stretch=*/1);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    auto* applyBtn = new QPushButton(tr("Apply Patch"));
    applyBtn->setProperty("primary", true);
    auto* closeBtn = new QPushButton(tr("Close"));
    connect(applyBtn, &QPushButton::clicked, this, &FilePatcher::onApply);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    btnRow->addWidget(applyBtn);
    btnRow->addWidget(closeBtn);
    root->addLayout(btnRow);
}

void FilePatcher::onChooseFile() {
    auto path = QFileDialog::getOpenFileName(this, tr("Choose file to patch"),
        pathEdit_->text(), tr("All Files (*)"));
    if (!path.isEmpty()) pathEdit_->setText(path);
}

static QByteArray parseHexBytes(const QString& text, QString* err) {
    QString clean = text;
    clean.replace(QRegularExpression(R"(\s+)"), "");
    if (clean.size() % 2 != 0) {
        if (err) *err = QCoreApplication::translate("FilePatcher", "Hex byte sequence has odd length.");
        return {};
    }
    QByteArray out;
    out.reserve(clean.size() / 2);
    for (int i = 0; i < clean.size(); i += 2) {
        bool ok = false;
        uint8_t b = (uint8_t)QStringView(clean).mid(i, 2).toUInt(&ok, 16);
        if (!ok) {
            if (err) *err = QCoreApplication::translate("FilePatcher", "Not a hex byte: '%1'").arg(clean.mid(i, 2));
            return {};
        }
        out.append((char)b);
    }
    return out;
}

// "0x" hex or decimal, as the field says; a leading zero is not octal (010 is
// ten, not eight) and a negative offset is refused.
static bool parseFileOffset(const QString& text, qint64& offset) {
    QString s = text.trimmed();
    bool ok = false;
    if (s.startsWith("0x", Qt::CaseInsensitive)) offset = s.mid(2).toLongLong(&ok, 16);
    else offset = s.toLongLong(&ok, 10);
    return ok && offset >= 0;
}

void FilePatcher::onReadBytes() {
    if (pathEdit_->text().isEmpty()) {
        QMessageBox::warning(this, tr("Pick a file"), tr("Choose a file first."));
        return;
    }
    qint64 offset = 0;
    if (!parseFileOffset(offsetEdit_->text(), offset)) {
        QMessageBox::warning(this, tr("Bad offset"), tr("Enter a non-negative offset: 0x-prefixed hex or decimal."));
        return;
    }
    QFile f(pathEdit_->text());
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Open failed"), f.errorString());
        return;
    }
    if (!f.seek(offset)) {
        QMessageBox::warning(this, tr("Seek failed"), tr("Offset is past end of file."));
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
        QMessageBox::warning(this, tr("Pick a file"), tr("Choose a file first."));
        return;
    }
    qint64 offset = 0;
    if (!parseFileOffset(offsetEdit_->text(), offset)) {
        QMessageBox::warning(this, tr("Bad offset"), tr("Enter a non-negative offset: 0x-prefixed hex or decimal."));
        return;
    }
    QString err;
    auto bytes = parseHexBytes(hexEdit_->toPlainText(), &err);
    if (bytes.isEmpty()) {
        QMessageBox::warning(this, tr("Bad hex"), err.isEmpty() ? tr("Provide at least one hex byte.") : err);
        return;
    }
    const QString question = bytes.size() == 1
        ? tr("Write %1 byte to %2 at offset 0x%3?\nThis modifies the file in place.")
        : tr("Write %1 bytes to %2 at offset 0x%3?\nThis modifies the file in place.");
    auto answer = QMessageBox::question(this, tr("Confirm patch"),
        question.arg(bytes.size()).arg(pathEdit_->text()).arg(offset, 0, 16));
    if (answer != QMessageBox::Yes) return;

    QFile f(pathEdit_->text());
    if (!f.open(QIODevice::ReadWrite)) {
        QMessageBox::warning(this, tr("Open failed"), f.errorString());
        return;
    }
    // ReadWrite seek-past-EOF succeeds and would grow the file (sparse hole)
    // rather than patch in place; confirm before extending.
    if (offset + (qint64)bytes.size() > f.size()) {
        auto extend = QMessageBox::question(this, tr("Extend file?"),
            tr("The patch ends at offset 0x%1 but the file is only 0x%2 bytes.\n"
               "Applying it will grow the file (zero-filling the gap). Continue?")
                .arg(offset + (qint64)bytes.size(), 0, 16).arg(f.size(), 0, 16));
        if (extend != QMessageBox::Yes) return;
    }
    if (!f.seek(offset)) {
        QMessageBox::warning(this, tr("Seek failed"), tr("Offset is past end of file."));
        return;
    }
    qint64 written = f.write(bytes);
    if (written != bytes.size()) {
        QMessageBox::warning(this, tr("Write failed"), f.errorString());
        return;
    }
    QMessageBox::information(this, tr("Patched"),
        tr("Wrote %1 bytes at 0x%2.").arg(written).arg(offset, 0, 16));
}

} // namespace ce::gui
