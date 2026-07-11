#pragma once
/// ELF Inspector — shows readelf-style header / section / segment / dynamic
/// info for any ELF file. Shells out to binutils' `readelf` and presents
/// the output in tabbed panes. CE's PEInfo equivalent for Linux.

#include <QDialog>
#include <QTabWidget>
#include <QPlainTextEdit>
#include <QLineEdit>

namespace ce::gui {

class ElfInspector : public QDialog {
    Q_OBJECT
public:
    /// Construct optionally pre-filled with a path (e.g. the attached
    /// process's first module).
    explicit ElfInspector(const QString& initialPath = "", QWidget* parent = nullptr);

private slots:
    void onBrowse();
    void onLoad();

private:
    void runReadelf(QPlainTextEdit* sink, const QStringList& args);

    QLineEdit*   pathEdit_;
    QTabWidget*  tabs_;
    QPlainTextEdit* headerView_;
    QPlainTextEdit* sectionView_;
    QPlainTextEdit* programView_;
    QPlainTextEdit* dynamicView_;
    QPlainTextEdit* symbolView_;
    QPlainTextEdit* notesView_;
};

} // namespace ce::gui
