#pragma once
/// Portable Executable (PE) Info (Cheat Engine's PEInfo window): the headers,
/// sections, data directories, imports, exports and base relocations of a
/// Windows module, read from its file or, for a loaded module, from memory.

#include <QMainWindow>

#include <cstdint>

class QLabel;
class QLineEdit;
class QListWidget;
class QRadioButton;
class QTabWidget;
class QTreeWidget;

namespace ce { class ProcessHandle; }

namespace ce::gui {

class PEInfoWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit PEInfoWindow(ProcessHandle* process, QWidget* parent = nullptr);

    /// Show the PE at `path` (File mode).
    bool showFile(const QString& path);
    /// Show the module loaded at `base` (Memory mode for the headers; imports,
    /// exports and relocations come from `path` when it is a readable file).
    bool showMemory(uintptr_t base, const QString& path);
    /// For tests: the text of every tab, as "Copy everything" puts it.
    QString allTextForTest() const;

private:
    void loadModules();
    void showInfo(const QByteArray& header, const QString& path, const QString& title);
    QString tabText(int tab) const;

    ProcessHandle* process_;
    QRadioButton* fileMode_ = nullptr;
    QRadioButton* memoryMode_ = nullptr;
    QListWidget* modules_ = nullptr;
    QLineEdit* address_ = nullptr;
    QLabel* status_ = nullptr;
    QTabWidget* tabs_ = nullptr;
    QTreeWidget* all_ = nullptr;
    QListWidget* imports_ = nullptr;
    QListWidget* exports_ = nullptr;
    QListWidget* relocations_ = nullptr;
};

} // namespace ce::gui
