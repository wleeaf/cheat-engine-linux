// MainWindow: first, next and undo scans, and saving scan results.
#include <bit>
#include "core/target_capabilities.hpp"
#include "arch/target_arch.hpp"
#include <csignal>
#include "gui/mainwindow.hpp"
#include "gui/code_editor.hpp"
#include "core/local_target.hpp"
#include "gui/gdbconnectiondialog.hpp"
#include "gui/theme.hpp"
#include "gui/i18n.hpp"
#include "core/expression.hpp"
#include "core/value_io.hpp"
#include "core/memview_nav.hpp"
#include "gui/processlistdialog.hpp"
#include "gui/registereditor.hpp"
#include "gui/debuggerwindow.hpp"
#include "gui/memorybrowser.hpp"
#include "gui/advancedoptions.hpp"
#include "gui/changeaddressdialog.hpp"
#include "gui/graphicalmemoryview.hpp"
#include "scanner/pointer_scanner.hpp"
#include "gui/scripteditor.hpp"
#include "gui/pointerscan_dialog.hpp"
#include "gui/guest_scan_dialog.hpp"
#include "gui/structuredissector.hpp"
#include "gui/monodissector.hpp"
#include "gui/luaconsole.hpp"
#include "gui/breakpointlist.hpp"
#include "gui/codefinder.hpp"
#include "debug/instruction_access.hpp"
#include "gui/codereferences.hpp"
#include "gui/heapregions.hpp"
#include "gui/memoryregions.hpp"
#include "gui/modulelist.hpp"
#include "gui/overlay.hpp"
#include "gui/stackview.hpp"
#include "gui/threadlist.hpp"
#include "gui/settingsdialog.hpp"
#include "gui/tracerwindow.hpp"
#include "gui/filepatcher.hpp"
#include "gui/branchmapper.hpp"
#include "gui/elfinspector.hpp"
#include "gui/formdesigner.hpp"
#include "gui/findstaticswindow.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "scripting/lua_gui.hpp"
#include "core/ct_file.hpp"
#include "core/ct_file_stream.hpp"
#include <QSaveFile>
#include <streambuf>
#include <sstream>
#include <limits>
#include <unordered_set>
#include <stdexcept>
#include "core/target_profile.hpp"
#include "core/trainer.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/mono_dissector.hpp"
#include <dlfcn.h>

#include <QApplication>
#include <QScopedValueRollback>
#include "gui/autoasmoperation.hpp"
#include <QEventLoop>
#include <thread>
#include <sys/utsname.h>
#include <atomic>
#include <QCoreApplication>
#include <fstream>
#include "platform/linux/injector.hpp"
#include <QMessageBox>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <QProgressDialog>
#include <QFileInfo>

#include "gui/agent_panel.hpp"
#include <QPushButton>
#include <cerrno>
#include <QStatusBar>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <QFileDialog>
#include <QTextStream>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <charconv>
#include <exception>

#include "gui/mainwindow_internal.hpp"
namespace ce::gui {
using namespace mainwindow_detail;

// The warning for a scan whose result files are unreliable. Name what failed:
// "the disk may be full" was the only explanation shown, also when a read of
// the previous results or a file open failed for another reason.
static QString scanWriteErrorText(const ScanResult& result) {
    const auto& reason = result.writeErrorReason();
    QString text = reason.empty()
        ? QCoreApplication::translate("MainWindow", "A scan-result file could not be fully written or read.")
        : QCoreApplication::translate("MainWindow",
              "A scan-result file could not be fully written or read: %1.").arg(QString::fromStdString(reason));
    if (reason.find(std::strerror(ENOSPC)) != std::string::npos || reason.find(std::strerror(EDQUOT)) != std::string::npos)
        text += QCoreApplication::translate("MainWindow",
                    " The disk holding %1 is full; free space there or set CE_SCAN_DIR to a larger disk.")
                    .arg(QString::fromStdString(result.directory().parent_path().parent_path().string()));
    return text + QCoreApplication::translate("MainWindow", " Some results are unreliable; scan again.");
}

// Accepts "," or "." decimals (Turkish comma-locale); defined lower down.
static double parseUserDouble(const QString& s, bool* ok = nullptr);
static std::optional<long long> scanIntegerInput(const QString& text, bool hex, bool pointer = false);
static bool scanTakesValue(ScanCompare compare);
static void warnBadScanValue(QWidget* parent, const QString& text);

// Compares that only a next scan can do: they need the previous scan's values.
static bool scanNeedsPreviousResult(ScanCompare compare) {
    switch (compare) {
        case ScanCompare::Changed: case ScanCompare::Unchanged: case ScanCompare::Increased:
        case ScanCompare::Decreased: case ScanCompare::IncreasedBy: case ScanCompare::DecreasedBy:
        case ScanCompare::SameAsFirst:
            return true;
        default:
            return false;
    }
}

namespace mainwindow_detail {
ScanCompare mapScanType(int index) {
    switch (index) {
        case 0: return ScanCompare::Exact;
        case 1: return ScanCompare::Greater;
        case 2: return ScanCompare::Less;
        case 3: return ScanCompare::Between;
        case 4: return ScanCompare::Unknown;
        case 5: return ScanCompare::Increased;
        case 6: return ScanCompare::Decreased;
        case 7: return ScanCompare::Changed;
        case 8: return ScanCompare::Unchanged;
        case 9: return ScanCompare::SameAsFirst;
        case 10: return ScanCompare::IncreasedBy;
        case 11: return ScanCompare::DecreasedBy;
        default: return ScanCompare::Exact;
    }
}
} // namespace mainwindow_detail

namespace mainwindow_detail {
ValueType mapValueType(int index) {
    switch (index) {
        case 0: return ValueType::Byte;
        case 1: return ValueType::Int16;
        case 2: return ValueType::Int32;
        case 3: return ValueType::Int64;
        case 4: return ValueType::Float;
        case 5: return ValueType::Double;
        case 6: return ValueType::String;
        case 7: return ValueType::UnicodeString;
        case 8: return ValueType::ByteArray;
        case 9: return ValueType::Binary;
        case 10: return ValueType::All;
        case 11: return ValueType::Pointer;
        case 12: return ValueType::Grouped;
        case 13: return ValueType::Custom;
        default: return ValueType::Int32;
    }
}
} // namespace mainwindow_detail

static bool applyFloatOptions(ScanConfig& config, QComboBox* roundingCombo,
                              QLineEdit* toleranceEdit) {
    if (config.valueType != ValueType::Float &&
        config.valueType != ValueType::Double && config.valueType != ValueType::All) {
        return true;
    }
    config.roundingType = roundingCombo->currentIndex();
    if (config.roundingType==3 && !toleranceEdit->text().trimmed().isEmpty()) {
        ScanConfig tolerance;
        if (!tolerance.parseFloatingValues(toleranceEdit->text().toStdString()) ||
            !std::isfinite(tolerance.floatValue) || tolerance.floatValue<0) return false;
        config.floatTolerance=tolerance.floatValue;
    }
    return true;

}

static size_t resultValueSizeForConfig(const ScanConfig& config) {
    switch (config.valueType) {
        case ValueType::Byte:
            return 1;
        case ValueType::Int16:
            return 2;
        case ValueType::Int32:
        case ValueType::Float:
            return 4;
        case ValueType::Int64:
        case ValueType::Double:
        case ValueType::Pointer:
            return 8;
        case ValueType::String:
            return std::max<size_t>(1, config.stringValueSize());
        case ValueType::UnicodeString:
            return std::max<size_t>(2, ce::encodeStringBytes(config.stringValue, "UTF-16LE").size());
        case ValueType::ByteArray:
        case ValueType::Binary:
            return std::max<size_t>(1, config.byteArray.size());
        case ValueType::Grouped:
            return std::max<size_t>(1, config.groupedValueSize());
        case ValueType::Custom:
            return std::max<size_t>(1, config.customValueSize);
        case ValueType::All:
        default:
            return 8;
    }
}

namespace {
// The scheduler state char from /proc/<pid>/stat ('R','S','T',…), or '?'.
char processStateChar(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return '?';
    char buf[512];
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = '\0';
    // comm (field 2) is parenthesised and may contain spaces; state follows the
    // last ')'.
    char* rp = std::strrchr(buf, ')');
    if (!rp) return '?';
    ++rp;
    while (*rp == ' ') ++rp;
    return *rp ? *rp : '?';
}

// SIGSTOP the target on construction, SIGCONT on destruction (best-effort), to
// freeze it for a scan ("Pause while scanning"). Does nothing if the target is
// already stopped (e.g. manually paused) so we never resume a process we didn't
// suspend.
struct ScopedSigstop {
    pid_t pid; bool active;
    ScopedSigstop(pid_t p, bool a) : pid(p), active(false) {
        if (!a || p <= 0 || processStateChar(p) == 'T') return;
        active = true;
        ::kill(pid, SIGSTOP);
    }
    ~ScopedSigstop() { if (active) ::kill(pid, SIGCONT); }
    ScopedSigstop(const ScopedSigstop&) = delete;
    ScopedSigstop& operator=(const ScopedSigstop&) = delete;
};

// Discards mouse and keyboard input while installed. A scan's progress loop
// used ExcludeUserInputEvents, which only defers input: Qt queued the clicks
// and keys and replayed them after the scan (a second First Scan click wiped
// the results it had just produced).
class ScopedInputBlocker : public QObject {
public:
    ScopedInputBlocker() { qApp->installEventFilter(this); }
    ~ScopedInputBlocker() override { qApp->removeEventFilter(this); }
protected:
    bool eventFilter(QObject*, QEvent* event) override {
        switch (event->type()) {
            case QEvent::MouseButtonPress: case QEvent::MouseButtonRelease:
            case QEvent::MouseButtonDblClick: case QEvent::KeyPress: case QEvent::KeyRelease:
            case QEvent::Wheel: case QEvent::Shortcut: case QEvent::ShortcutOverride:
            case QEvent::TouchBegin: case QEvent::TouchUpdate: case QEvent::TouchEnd:
                return true;
            default:
                return false;
        }
    }
};
} // namespace

std::unique_ptr<ScanResult> MainWindow::runScanWithProgress(
    const std::function<ScanResult()>& scanFn) {
    // Optionally freeze the target for the whole scan so it's a consistent snapshot.
    const auto pausePid=pauseWhileScanning_ ? ce::localTargetPid(process_.get()) : std::optional<pid_t>{};
    ScopedSigstop pause(pausePid.value_or(0), pauseWhileScanning_);
    // Pause the live-value refresh so it doesn't fight the scan for the target,
    // and show the progress bar.
    if (valueRefreshTimer_) valueRefreshTimer_->stop();
    progressBar_->setValue(0);
    progressBar_->setVisible(true);

    std::unique_ptr<ScanResult> result;
    std::exception_ptr err;
    std::atomic<bool> done{false};
    QScopedValueRollback scanning(scanInProgress_, true);
    std::thread worker([&] {
        try { result = std::make_unique<ScanResult>(scanFn()); }
        catch (...) { err = std::current_exception(); }
        done.store(true, std::memory_order_release);
    });

    // Drive the bar on the UI thread. Paints keep flowing (the bar animates);
    // user input is dropped, not deferred, so no re-entrant or replayed scan.
    {
        ScopedInputBlocker blocker;
        while (!done.load(std::memory_order_acquire)) {
            progressBar_->setValue((int)(scanner_->progress() * 100.0f));
            QApplication::processEvents(QEventLoop::AllEvents, 25);
            std::this_thread::sleep_for(std::chrono::milliseconds(16));
        }
    }
    worker.join();

    progressBar_->setValue(100);
    progressBar_->setVisible(false);
    if (valueRefreshTimer_)
        valueRefreshTimer_->start(kValueRefreshMs);

    if (err) std::rethrow_exception(err);
    return result;
}

void MainWindow::runSnapshotTask(const std::function<void()>& task) {
    if (valueRefreshTimer_) valueRefreshTimer_->stop();
    progressBar_->setRange(0, 0);   // busy: a capture reports no progress
    progressBar_->setVisible(true);

    std::exception_ptr err;
    std::atomic<bool> done{false};
    QScopedValueRollback scanning(scanInProgress_, true);
    std::thread worker([&] {
        try { task(); }
        catch (...) { err = std::current_exception(); }
        done.store(true, std::memory_order_release);
    });
    {
        ScopedInputBlocker blocker;
        while (!done.load(std::memory_order_acquire)) {
            QApplication::processEvents(QEventLoop::AllEvents, 25);
            std::this_thread::sleep_for(std::chrono::milliseconds(16));
        }
    }
    worker.join();

    progressBar_->setRange(0, 100);
    progressBar_->setVisible(false);
    if (valueRefreshTimer_)
        valueRefreshTimer_->start(kValueRefreshMs);
    if (err) std::rethrow_exception(err);
}

bool MainWindow::eventFilter(QObject* obj, QEvent* ev) {
    if (ev->type() == QEvent::Resize) {
        if (resultsEmptyHint_ && resultsView_ && obj == resultsView_->viewport())
            resultsEmptyHint_->setGeometry(resultsView_->viewport()->rect());
        if (tableEmptyHint_ && addressListView_ && obj == addressListView_->viewport())
            tableEmptyHint_->setGeometry(addressListView_->viewport()->rect());
    }
    return QMainWindow::eventFilter(obj, ev);
}

void MainWindow::onFirstScan() {
    // "New Scan" mode: a scan session is open, so this click resets to the
    // pre-scan state (clears results, unlocks the value type) rather than
    // scanning. The next click then runs a fresh First Scan.
    if (lastResult_ != nullptr) {
        resultsModel_->clear();
        lastResult_.reset();
        undoResult_.reset();
        foundLabel_->setText(tr("Found: 0"));
        // Changed, Increased and the like compare with a previous scan, which
        // a first scan does not have: start again from Exact Value, as CE does.
        if (scanNeedsPreviousResult(mapScanType(scanTypeCombo_->currentIndex())))
            scanTypeCombo_->setCurrentIndex(0);
        statusBar()->showMessage(tr("New scan: pick a value type and value, then First Scan."), 4000);
        updateScanButtons();
        return;
    }
    if (!process_) {
        statusBar()->showMessage(tr("No process attached; open one first (Ctrl+O) to scan."), 4000);
        return;
    }
    if (auto problem = ce::memoryAccessProblem(*process_)) {
        QMessageBox::warning(this, tr("Cannot read the process"), QString::fromStdString(*problem));
        return;
    }

    ScanConfig config;
    applyScanDataFormat(config);
    config.valueType = mapValueType(valueTypeCombo_->currentIndex());
    config.compareType = mapScanType(scanTypeCombo_->currentIndex());
    // Fast Scan pins the scan to `alignment`-aligned addresses (much faster);
    // unchecking it scans every byte offset so misaligned values are found too.
    // Without this the Fast Scan checkbox did nothing.
    config.alignment = fastScanCheck_->isChecked() ? alignEdit_->text().toInt() : 1;
    if (config.alignment < 1) config.alignment = 1;
    auto fromExpr = parseAddressExpr(fromAddressEdit_->text());
    auto toExpr = parseAddressExpr(toAddressEdit_->text());
    if (!fromExpr || !toExpr) {
        QMessageBox::warning(this, tr("Scan range"),
            tr("From/To must be a hex address, symbol, or module+offset (e.g. target2, target2+0x5000)."));
        return;
    }
    config.startAddress = *fromExpr;
    config.stopAddress = *toExpr;
    if (config.startAddress > config.stopAddress) {
        QMessageBox::warning(this, tr("Scan range"),
            tr("The From address must not be greater than the To address."));
        return;
    }
    auto toMatch = [](Qt::CheckState s) {
        return s == Qt::Checked   ? ce::ProtMatch::Yes
             : s == Qt::Unchecked ? ce::ProtMatch::No
                                  : ce::ProtMatch::Any;   // PartiallyChecked
    };
    config.writableMatch   = toMatch(writableCheck_->checkState());
    config.executableMatch = toMatch(executableCheck_->checkState());
    // CE Memory Scan Options: which region classes to scan (all on by default).
    if (memPrivateCheck_) config.scanPrivate = memPrivateCheck_->isChecked();
    if (memImageCheck_)   config.scanImage   = memImageCheck_->isChecked();
    if (memMappedCheck_)  config.scanMapped  = memMappedCheck_->isChecked();

    auto text = scanValueEdit_->text();
    int intBase = (hexCheck_ && hexCheck_->isEnabled() && hexCheck_->isChecked()) ? 16 : 10;
    if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
        config.stringValue = text.toStdString();
        if (config.valueType == ValueType::String)
            config.stringEncoding = stringEncodingCombo_->currentText().toStdString();
        // Case sensitivity applies to both Text and Unicode Text (set unconditionally).
        config.caseSensitive = !caseSensitiveCheck_ || caseSensitiveCheck_->isChecked();
        config.alignment = 1;
    } else if (config.valueType == ValueType::ByteArray) {
        // parseAOB returns false for an empty pattern OR a token that isn't hex
        // or a wildcard (a typo like "8Z") — reject both instead of scanning wrong.
        if (!config.parseAOB(text.toStdString())) {
            QMessageBox::warning(this, tr("Array of byte scan"), tr("Enter a valid AOB pattern (e.g. \"7F 45 ?? 46\")."));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Binary) {
        config.parseBinary(text.toStdString());
        // parseBinary returns void; an empty pattern means nothing was parsed.
        if (config.byteArray.empty()) {
            QMessageBox::warning(this, tr("Binary scan"), tr("Enter a valid binary pattern (e.g. \"0110??01\")."));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Grouped) {
        std::string error;
        if (!config.parseGrouped(text.toStdString(), &error)) {
            QMessageBox::warning(this, tr("Grouped scan"), QString::fromStdString(error));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Custom) {
        config.customFormula = text.toStdString();
        config.customValueSize = std::max<size_t>(1, static_cast<size_t>(config.alignment));
        config.alignment = 1;
    } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
        if (!config.parseFloatingValues(text.toStdString(), scanValue2Edit_->text().toStdString())) {
            QMessageBox::warning(this, tr("Floating scan"), tr("Enter valid numeric values for the selected comparison."));return;
        }
    } else if (config.valueType == ValueType::Pointer) {
        auto value = scanIntegerInput(text, intBase == 16, /*pointer=*/true);
        if (!value && scanTakesValue(config.compareType)) { warnBadScanValue(this, text); return; }
        config.intValue = value.value_or(0);
    } else if (config.valueType == ValueType::All) {
        if (!config.parseAllValues(text.toStdString(), scanValue2Edit_->text().toStdString(), intBase == 16)) {
            QMessageBox::warning(this, tr("All scan"), tr("Enter valid numeric values for the selected comparison."));return;
        }
    } else {
        auto value = scanIntegerInput(text, intBase == 16);
        if (!value && scanTakesValue(config.compareType)) { warnBadScanValue(this, text); return; }
        config.intValue = value.value_or(0);
    }
    // "Value between..." needs a second (upper) bound from its own box.
    if (config.compareType == ScanCompare::Between && config.valueType != ValueType::All &&
        config.valueType != ValueType::Float && config.valueType != ValueType::Double) {
        auto text2 = scanValue2Edit_->text();
        if (config.valueType == ValueType::Float || config.valueType == ValueType::Double || config.valueType == ValueType::All)
            config.floatValue2 = parseUserDouble(text2);
        if (config.valueType != ValueType::Float && config.valueType != ValueType::Double) {
            auto value = scanIntegerInput(text2, intBase == 16, config.valueType == ValueType::Pointer);
            if (!value) { warnBadScanValue(this, text2); return; }
            config.intValue2 = *value;
        }
    }
    if (!applyFloatOptions(config, floatRoundingCombo_, floatToleranceEdit_)) {
        QMessageBox::warning(this, tr("Floating tolerance"), tr("Enter a finite nonnegative tolerance."));return;
    }
    size_t resultValueSize = resultValueSizeForConfig(config);

    firstScanBtn_->setEnabled(false);
    // Scan on a worker thread with a live progress bar (keeps the UI responsive).
    std::unique_ptr<ScanResult> result;
    try {
        result = runScanWithProgress([&] { return scanner_->firstScan(*process_, config); });
    } catch (const std::invalid_argument& e) {
        // The scanner refused these settings and says why; the advice below
        // is about running out of memory and does not apply.
        firstScanBtn_->setEnabled(true);
        QMessageBox::warning(this, tr("Scan failed"), QString(tr("The scan could not start: %1")).arg(e.what()));
        return;
    } catch (const std::exception& e) {
        // A huge target (e.g. an emulator mapping many GB of guest RAM) can
        // exhaust memory during the scan/merge. Report it instead of letting
        // the exception escape the Qt event handler and std::terminate.
        firstScanBtn_->setEnabled(true);
        QMessageBox::warning(this, tr("Scan failed"),
            QString(tr("The scan could not complete: %1\n\n"
                    "Try narrowing the From/To range, enabling Fast Scan, or "
                    "choosing a more specific value type.")).arg(e.what()));
        return;
    }
    firstScanBtn_->setEnabled(true);

    foundLabel_->setText(foundLabelText(result->count()));
    if (result->hasWriteError())
        QMessageBox::warning(this, tr("Scan results truncated"), scanWriteErrorText(*result));
    if (result->valueSize()) resultValueSize = result->valueSize();
    resultsModel_->setResult(result.get(), config.valueType, resultValueSize, config.stringEncoding);

    undoResult_ = std::move(lastResult_);
    undoResultType_ = lastResultType_;
    undoResultValueSize_ = lastResultValueSize_;
    lastResult_ = std::move(result);
    lastResultType_ = config.valueType;
    lastResultValueSize_ = resultValueSize;
    updateScanButtons();
    statusBar()->showMessage(lastResult_->hasWriteError() ? tr("Scan results are incomplete.") :
        tr("First scan complete. %1").arg(foundLabelText(lastResult_->count())), 4000);
}

void MainWindow::onNextScan() {
    if (!process_) {
        statusBar()->showMessage(tr("No process attached; open one first (Ctrl+O) to scan."), 4000);
        return;
    }
    if (!lastResult_) {
        statusBar()->showMessage(tr("Run a First Scan before a Next Scan."), 4000);
        return;
    }

    ScanConfig config;
    applyScanDataFormat(config);
    // Ordinary typed samples keep their original stride. All samples carry
    // candidate metadata, so the backend can select a concrete surviving type.
    config.valueType = lastResultType_ == ValueType::All ? mapValueType(valueTypeCombo_->currentIndex()) : lastResultType_;
    config.compareType = mapScanType(scanTypeCombo_->currentIndex());
    config.alignment = alignEdit_->text().toInt();

    auto text = scanValueEdit_->text();
    int intBase = (hexCheck_ && hexCheck_->isEnabled() && hexCheck_->isChecked()) ? 16 : 10;
    if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
        config.stringValue = text.toStdString();
        if (config.valueType == ValueType::String)
            config.stringEncoding = stringEncodingCombo_->currentText().toStdString();
        // Case sensitivity applies to both Text and Unicode Text (set unconditionally).
        config.caseSensitive = !caseSensitiveCheck_ || caseSensitiveCheck_->isChecked();
        config.alignment = 1;
    } else if (config.valueType == ValueType::ByteArray) {
        // parseAOB returns false for an empty pattern OR a token that isn't hex
        // or a wildcard (a typo like "8Z") — reject both instead of scanning wrong.
        if (!config.parseAOB(text.toStdString())) {
            QMessageBox::warning(this, tr("Array of byte scan"), tr("Enter a valid AOB pattern (e.g. \"7F 45 ?? 46\")."));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Binary) {
        config.parseBinary(text.toStdString());
        // parseBinary returns void; an empty pattern means nothing was parsed.
        if (config.byteArray.empty()) {
            QMessageBox::warning(this, tr("Binary scan"), tr("Enter a valid binary pattern (e.g. \"0110??01\")."));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Grouped) {
        std::string error;
        if (!config.parseGrouped(text.toStdString(), &error)) {
            QMessageBox::warning(this, tr("Grouped scan"), QString::fromStdString(error));
            return;
        }
        config.alignment = 1;
    } else if (config.valueType == ValueType::Custom) {
        config.customFormula = text.toStdString();
        // The first scan fixed the size (it depends on Fast Scan then, not now).
        config.customValueSize = lastResultValueSize_ ? lastResultValueSize_ : std::max<size_t>(1, static_cast<size_t>(config.alignment));
        config.alignment = 1;
    } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
        if (!config.parseFloatingValues(text.toStdString(), scanValue2Edit_->text().toStdString())) {
            QMessageBox::warning(this, tr("Floating scan"), tr("Enter valid numeric values for the selected comparison."));return;
        }
    } else if (config.valueType == ValueType::Pointer) {
        auto value = scanIntegerInput(text, intBase == 16, /*pointer=*/true);
        if (!value && scanTakesValue(config.compareType)) { warnBadScanValue(this, text); return; }
        config.intValue = value.value_or(0);
    } else if (config.valueType == ValueType::All) {
        if (!config.parseAllValues(text.toStdString(), scanValue2Edit_->text().toStdString(), intBase == 16)) {
            QMessageBox::warning(this, tr("All scan"), tr("Enter valid numeric values for the selected comparison."));return;
        }
    } else {
        auto value = scanIntegerInput(text, intBase == 16);
        if (!value && scanTakesValue(config.compareType)) { warnBadScanValue(this, text); return; }
        config.intValue = value.value_or(0);
    }
    if (config.compareType == ScanCompare::Between && config.valueType != ValueType::All &&
        config.valueType != ValueType::Float && config.valueType != ValueType::Double) {
        auto text2 = scanValue2Edit_->text();
        if (config.valueType == ValueType::Float || config.valueType == ValueType::Double || config.valueType == ValueType::All)
            config.floatValue2 = parseUserDouble(text2);
        if (config.valueType != ValueType::Float && config.valueType != ValueType::Double) {
            auto value = scanIntegerInput(text2, intBase == 16, config.valueType == ValueType::Pointer);
            if (!value) { warnBadScanValue(this, text2); return; }
            config.intValue2 = *value;
        }
    }
    if (!applyFloatOptions(config, floatRoundingCombo_, floatToleranceEdit_)) {
        QMessageBox::warning(this, tr("Floating tolerance"), tr("Enter a finite nonnegative tolerance."));return;
    }

    if (percentCheck_->isChecked()) {
        config.percentageScan = true;
        // parseUserDouble accepts ',' or '.' (Turkish comma-decimal locale).
        // An empty or junk box was 0%, which also matches unchanged values.
        bool ok = false;
        config.percentageValue = parseUserDouble(percentValueEdit_->text(), &ok);
        if (!ok || !std::isfinite(config.percentageValue)) { warnBadScanValue(this, percentValueEdit_->text()); return; }
        auto percent2Text = percentValue2Edit_->text().trimmed();
        config.percentageValue2 = config.percentageValue;
        if (!percent2Text.isEmpty()) {
            config.percentageValue2 = parseUserDouble(percent2Text, &ok);
            if (!ok || !std::isfinite(config.percentageValue2)) { warnBadScanValue(this, percent2Text); return; }
        }
    }
    size_t resultValueSize = resultValueSizeForConfig(config);

    nextScanBtn_->setEnabled(false);
    // Scan on a worker thread with a live progress bar (see onFirstScan).
    std::unique_ptr<ScanResult> result;
    try {
        result = runScanWithProgress(
            [&] { return scanner_->nextScan(*process_, config, *lastResult_); });
    } catch (const std::exception& e) {
        // Guard the same way as onFirstScan: a bad_alloc (or a rejected
        // next-scan, e.g. a changed value-size stride) must not terminate.
        nextScanBtn_->setEnabled(true);
        QMessageBox::warning(this, tr("Scan failed"),
            QString(tr("The next scan could not complete: %1")).arg(e.what()));
        return;
    }
    nextScanBtn_->setEnabled(true);

    foundLabel_->setText(foundLabelText(result->count()));
    if (result->hasWriteError())
        QMessageBox::warning(this, tr("Scan results truncated"), scanWriteErrorText(*result));
    if (result->valueSize()) resultValueSize = result->valueSize();
    resultsModel_->setResult(result.get(), config.valueType, resultValueSize, config.stringEncoding);

    undoResult_ = std::move(lastResult_);
    undoResultType_ = lastResultType_;
    undoResultValueSize_ = lastResultValueSize_;
    lastResult_ = std::move(result);
    lastResultType_ = config.valueType;
    lastResultValueSize_ = resultValueSize;
    updateScanButtons();
    statusBar()->showMessage(lastResult_->hasWriteError() ? tr("Scan results are incomplete.") :
        tr("Next scan complete. %1").arg(foundLabelText(lastResult_->count())), 4000);
}

void MainWindow::onUndoScan() {
    if (!undoResult_) return;
    lastResult_ = std::move(undoResult_);
    lastResultType_ = undoResultType_;
    lastResultValueSize_ = undoResultValueSize_;
    undoResultType_ = ValueType::Int32;
    undoResultValueSize_ = 0;
    resultsModel_->setResult(lastResult_.get(), lastResultType_, lastResultValueSize_, resultsModel_->stringEncoding());
    foundLabel_->setText(foundLabelText(lastResult_->count()));
    updateScanButtons();
}

void MainWindow::onResultDoubleClicked(const QModelIndex& index) {
    if (!lastResult_ || !index.isValid() || index.row() < 0 || static_cast<size_t>(index.row()) >= lastResult_->count()) return;
    auto addr = resultsModel_->addressAt(index.row());
    auto type = lastResultType_;
    size_t size = type == ValueType::All ? lastResult_->allTypeValueSize(index.row()) : lastResultValueSize_;
    if (type == ValueType::All || type == ValueType::Grouped || type == ValueType::Custom || type == ValueType::Binary)
        type = ValueType::ByteArray;
    int id = addressListModel_->addEntry(addr, type, tr("No description"), "", size);
    if (lastResult_->hasDataFormat())
        addressListModel_->setEntryDataFormat(addressListModel_->rowOfId(id), lastResult_->byteOrder(), lastResult_->pointerWidth());
}

void MainWindow::onSaveScanResults() {
    if (!resultsModel_ || !resultsModel_->resultCount()) { statusBar()->showMessage(tr("No scan results to save."), 4000); return; }
    const QString path = QFileDialog::getSaveFileName(this, tr("Save all current scan results"),
        "scanresults.txt", tr("Text (*.txt);;CSV (*.csv);;All files (*)"));
    if (path.isEmpty()) return;
    const size_t rows = resultsModel_->resultCount();
    if (!rows) { statusBar()->showMessage(tr("No scan results to save."), 4000); return; }
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        statusBar()->showMessage(file.errorString(), 4000); return;
    }
    const bool csv = path.endsWith(".csv", Qt::CaseInsensitive);
    const QChar separator = csv ? QChar(',') : QChar('\t');
    auto field = [csv](QString text) {
        if (csv) return QString('"') + text.replace("\"", "\"\"") + '"';
        return text.replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n");
    };
    QProgressDialog progress(tr("Saving all scan results..."), tr("Cancel"), 0, 1000, this);
    progress.setWindowModality(Qt::WindowModal);
    bool changed = false;
    connect(resultsModel_, &QAbstractItemModel::modelReset, &progress, [&] { changed = true; });
    QTextStream output(&file);
    output << "Address" << separator << "Value" << '\n';
    for (size_t row = 0; row < rows; ++row) {
        if (row % 1000 == 0) {
            progress.setValue(static_cast<int>(static_cast<long double>(row) / rows * 1000));
            QCoreApplication::processEvents();
            if (changed || progress.wasCanceled()) {
                file.cancelWriting();
                statusBar()->showMessage(changed ? tr("Scan results changed; export canceled.") : tr("Export canceled."), 4000);
                return;
            }
        }
        output << field(resultsModel_->displayValueAt(row, 0)) << separator
               << field(resultsModel_->displayValueAt(row, 1)) << '\n';
    }
    output.flush();
    if (output.status() != QTextStream::Ok || !file.flush() || !file.commit()) {
        statusBar()->showMessage(tr("Could not save scan results: %1").arg(file.errorString()), 6000); return;
    }
    statusBar()->showMessage(QString(tr("Saved %1 results to %2")).arg(qulonglong(rows)).arg(QFileInfo(path).fileName()), 6000);
}

void MainWindow::applyScanDataFormat(ScanConfig& config) const {
    config.byteOrder = static_cast<ByteOrder>(scanByteOrderCombo_->currentData().toInt());
    config.pointerWidth = static_cast<uint8_t>(scanPointerWidthCombo_->currentData().toInt());
}

void MainWindow::updateScanButtons() {
    bool hasProcess = (process_ != nullptr);
    bool scanActive = (lastResult_ != nullptr);   // a First Scan has been run
    bool hasResults = (scanActive && lastResult_->count() > 0);
    firstScanBtn_->setEnabled(hasProcess);
    if (auto* button = findChild<QPushButton*>("memoryViewButton")) button->setEnabled(hasProcess);
    // CE-style: once a scan session is open, "First Scan" becomes "New Scan" (a
    // reset). Ordinary typed scans lock the value type; All scans permit
    // selection of a surviving numeric type. A fresh state allows any type.
    firstScanBtn_->setText(scanActive ? tr("New Scan") : tr("First Scan"));
    nextScanBtn_->setEnabled(hasResults);
    undoScanBtn_->setEnabled(undoResult_ != nullptr);
    if (valueTypeCombo_) valueTypeCombo_->setEnabled(!scanActive || lastResultType_ == ValueType::All);
}

// Parse a user-entered decimal accepting either '.' or ',' as the separator.
// QString::toDouble is C-locale ('.') only; comma-locale users type "2,5".
static double parseUserDouble(const QString& s, bool* ok) {
    return QString(s).replace(',', '.').toDouble(ok);
}

// Parse an integer value field tolerantly: accept a leading '-', an optional 0x
// hex prefix, and both signed and full-width-unsigned magnitudes. Returns a wide
// value the caller truncates to the target width — so "-1" -> byte 0xFF and
// An integer scan value, or nullopt when the text is not one: scanning for 0
// instead would quietly find the wrong thing. Pointers are unsigned.
static std::optional<long long> scanIntegerInput(const QString& text, bool hex, bool pointer) {
    if (pointer) {
        bool ok = false;
        const QString trimmed = text.trimmed();
        const bool prefixed = trimmed.startsWith("0x", Qt::CaseInsensitive);
        const qulonglong value = (prefixed ? trimmed.mid(2) : trimmed).toULongLong(&ok, hex || prefixed ? 16 : 10);
        return ok ? std::optional<long long>(static_cast<long long>(value)) : std::nullopt;
    }
    bool ok = false;
    const long long value = ce::parseIntegerScalar(text.toStdString(), hex, ok);
    return ok ? std::optional<long long>(value) : std::nullopt;
}

static bool scanTakesValue(ScanCompare compare) {
    return compare == ScanCompare::Exact || compare == ScanCompare::Greater || compare == ScanCompare::Less ||
           compare == ScanCompare::Between || compare == ScanCompare::IncreasedBy || compare == ScanCompare::DecreasedBy;
}

static void warnBadScanValue(QWidget* parent, const QString& text) {
    QMessageBox::warning(parent, QCoreApplication::translate("MainWindow", "Scan value"), text.trimmed().isEmpty()
        ? QString(QCoreApplication::translate("MainWindow", "Enter a value for this scan."))
        : QString(QCoreApplication::translate("MainWindow", "\"%1\" is not a number (or does not fit in 64 bits).")).arg(text.trimmed()));
}
} // namespace ce::gui
