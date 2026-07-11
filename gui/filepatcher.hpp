#pragma once
/// File patcher dialog — write hex bytes into a binary file at a given offset.
/// Useful for patching `.exe` / `.so` files on disk (e.g. DRM removal, static
/// constant overrides) without going through a running process.

#include <QDialog>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QSpinBox>

namespace ce::gui {

class FilePatcher : public QDialog {
    Q_OBJECT
public:
    explicit FilePatcher(QWidget* parent = nullptr);

private slots:
    void onChooseFile();
    void onApply();
    void onReadBytes();

private:
    QLineEdit*       pathEdit_;
    QLineEdit*       offsetEdit_;
    QPlainTextEdit*  hexEdit_;     // "DE AD BE EF"
    QSpinBox*        readSizeSpin_;
};

} // namespace ce::gui
