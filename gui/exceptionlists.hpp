#pragma once
/// The debugger's exception lists (Cheat Engine's Exception region list and
/// Exception ignore list), for Linux signals:
/// - regions: a break on a signal only stops when the instruction that
///   raised it lies in one of them;
/// - ignored signals: with "Break on all signals" these are passed to the
///   program without stopping.

#include <QDialog>
#include <QList>
#include <QPair>
#include <QSet>

#include <cstdint>

class QCheckBox;
class QLineEdit;
class QListWidget;

namespace ce::gui {

using AddressRange = QPair<quint64, quint64>;   // first..second, inclusive

/// "SIGSEGV" for 11; "SIG42" for a number without a name.
QString signalName(int signal);
/// "SIGSEGV", "segv", "11" -> 11; 0 when unknown.
int parseSignal(const QString& text);
/// Every signal the debugger can break on (1..SIGRTMAX), for "Break on all".
QList<int> breakableSignals();
/// The signals a program uses for timers and job control, ignored by default.
QSet<int> defaultIgnoredSignals();

class ExceptionRegionListDialog : public QDialog {
    Q_OBJECT
public:
    ExceptionRegionListDialog(QList<AddressRange> regions, QWidget* parent = nullptr);
    QList<AddressRange> regions() const { return regions_; }

private:
    void refresh();
    QList<AddressRange> regions_;
    QListWidget* list_ = nullptr;
    QLineEdit* start_ = nullptr;
    QLineEdit* stop_ = nullptr;
};

class ExceptionIgnoreListDialog : public QDialog {
    Q_OBJECT
public:
    ExceptionIgnoreListDialog(QSet<int> ignored, QWidget* parent = nullptr);
    QSet<int> ignored() const { return ignored_; }

private:
    void refresh();
    QSet<int> ignored_;
    QListWidget* list_ = nullptr;
    QLineEdit* edit_ = nullptr;
};

} // namespace ce::gui
