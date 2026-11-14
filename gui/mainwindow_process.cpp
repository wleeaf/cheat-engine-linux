// MainWindow: opening, attaching to and disconnecting from a target (local
// process, GDB stub, ceserver).
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
#include <streambuf>
#include <sstream>
#include <limits>
#include <unordered_set>
#include <stdexcept>
#include "core/target_profile.hpp"
#include "core/trainer.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/mono_dissector.hpp"
#include <QRegularExpression>
#include <dlfcn.h>

#include <QApplication>
#include "gui/autoasmoperation.hpp"
#include <thread>
#include <sys/utsname.h>
#include <atomic>
#include <QCoreApplication>
#include <fstream>
#include "platform/linux/injector.hpp"
#include <QHBoxLayout>
#include <QMessageBox>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <QFile>
#include <QFileInfo>
#include <QProcess>

#include "gui/agent_panel.hpp"
#include <QStandardPaths>
#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <cerrno>
#include <QSettings>
#include <QFormLayout>
#include <QStatusBar>
#include <QIntValidator>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <QStringList>
#include <cmath>
#include <charconv>
#include <exception>

#include "gui/mainwindow_internal.hpp"
namespace ce::gui {
using namespace mainwindow_detail;
static void warnIfMemoryUnreadable(QWidget* parent, ce::ProcessHandle* p,
                                   pid_t pid, const QString& name);

// One-click elevation: use pkexec (graphical polkit prompt) to grant memory-read
// access. For a real installed/dev binary that means setcap cap_sys_ptrace+ep on it
// (persistent, targeted, effective after a restart). For an AppImage the capability
// can't persist on the read-only temp mount, so lower kernel.yama.ptrace_scope
// instead (effective immediately, resets on reboot — the .deb sets it up permanently).
// A binary with file capabilities runs in secure-execution mode, where the
// loader ignores $ORIGIN in its run path. An install outside the system library
// directories (~/.local, /opt) finds libcecore only through $ORIGIN, so a
// capability would stop Cheat Engine from starting. The build tree uses
// absolute run paths and keeps working.
static bool capabilityKeepsLibrariesLoadable() {
    Dl_info info{};
    if (!dladdr(reinterpret_cast<void*>(&ce::findCompanionLibrary), &info) || !info.dli_fname) return false;
    const QString library = QFileInfo(QString::fromLocal8Bit(info.dli_fname)).canonicalFilePath();
    const QString exe = QFileInfo(QCoreApplication::applicationFilePath()).canonicalFilePath();
    if (library.isEmpty() || library == exe) return true;   // engine linked into the executable
    const QString dir = QFileInfo(library).absolutePath();
    if (dir == QFileInfo(exe).absolutePath()) return true;  // build tree: absolute run path
    static const QRegularExpression systemDir(
        QStringLiteral("^/(usr/)?lib(64|32)?(/[a-z0-9_]+-linux-gnu[a-z0-9_]*)?$"));
    return systemDir.match(dir).hasMatch();
}

static void grantPtraceAccess(QWidget* parent) {
    const QString bin = QCoreApplication::applicationFilePath();
    const bool isAppImage = qEnvironmentVariableIsSet("APPIMAGE") || bin.contains("/.mount_");
    const bool capabilityUsable = !isAppImage && capabilityKeepsLibrariesLoadable();

    QStringList args;
    QString followup;
    if (!capabilityUsable) {
        args = {QStringLiteral("/bin/sh"), QStringLiteral("-c"),
                QStringLiteral("echo 0 > /proc/sys/kernel/yama/ptrace_scope")};
        followup = isAppImage
            ? QCoreApplication::translate("MainWindow", "Access granted for this session; re-open the process.\n"
                          "(This resets on reboot. Install the .deb, or re-run the "
                          "command, to make it permanent.)")
            : QCoreApplication::translate("MainWindow", "Access granted for this session; re-open the process.\n"
                          "(This resets on reboot. A capability on this install would "
                          "stop it from finding its libraries, because it is outside the "
                          "system library directories.)");
    } else {
        const QString cescan = QFileInfo(bin).absolutePath() + QStringLiteral("/cescan");
        // Fail when either setcap fails (no xattr support, nosuid mount), so
        // the result below is not "granted" for nothing.
        args = {QStringLiteral("/bin/sh"), QStringLiteral("-c"),
                QStringLiteral("setcap cap_sys_ptrace+ep \"$1\" || exit 1; "
                               "if [ -x \"$2\" ]; then setcap cap_sys_ptrace+ep \"$2\" || exit 1; fi"),
                QStringLiteral("sh"), bin, cescan};
        followup = QCoreApplication::translate("MainWindow", "Access granted. Restart Cheat Engine for it to take effect.");
    }

    int rc = QProcess::execute(QStringLiteral("pkexec"), args);
    if (rc == 0)
        QMessageBox::information(parent, QCoreApplication::translate("MainWindow", "Access granted"), followup);
    else
        QMessageBox::warning(parent, QCoreApplication::translate("MainWindow", "Could not grant access"),
            QCoreApplication::translate("MainWindow", "The privileged command was cancelled or failed (pkexec exit %1). "
                        "You can still grant access manually from a terminal.").arg(rc));
}

// Probe whether we can actually read the target's memory. Under the default
// kernel.yama.ptrace_scope=1, process_vm_readv is DENIED for any process we can't
// ptrace — i.e. anything Cheat Engine didn't spawn — so scanning, memory browsing
// and debugging all silently fail (empty results, blank disassembler). Detect that
// the moment a process is opened and tell the user exactly how to fix it, instead
// of leaving them to wonder why "browse memory" shows nothing for some processes.
static void warnIfMemoryUnreadable(QWidget* parent, ce::ProcessHandle* p,
                                   pid_t pid, const QString& name) {
    if (!p) return;
    bool sawReadable = false;
    for (auto& r : p->queryRegions()) {
        if (!(r.protection & ce::MemProt::Read)) continue;
        sawReadable = true;
        uint8_t b = 0;
        auto res = p->read(r.base, &b, 1);
        if (res && *res >= 1) return;   // memory is readable — nothing to warn about
        break;                          // first readable region failed → diagnose below
    }
    if (!sawReadable) return;           // couldn't enumerate regions — don't guess

    QString scope = QStringLiteral("1");
    if (QFile f(QStringLiteral("/proc/sys/kernel/yama/ptrace_scope")); f.open(QIODevice::ReadOnly))
        scope = QString::fromUtf8(f.readAll()).trimmed();

    QMessageBox box(parent);
    box.setIcon(QMessageBox::Warning);
    box.setWindowTitle(QCoreApplication::translate("MainWindow", "Process memory not readable"));
    box.setText(QCoreApplication::translate("MainWindow",
        "Cannot read the memory of PID %1 (%2).\n\n"
        "Linux only lets a program read another process's memory if it is allowed "
        "to ptrace it. With kernel.yama.ptrace_scope = %3, that means the target "
        "must be a child of Cheat Engine, or Cheat Engine must run with elevated "
        "rights. Scanning, memory browsing and debugging this process will not work "
        "until that is granted.").arg(pid).arg(name).arg(scope));
    box.setInformativeText(QCoreApplication::translate("MainWindow",
        "\"Grant access\" will ask for your password (via pkexec) and set it up for "
        "you. Or do it manually:\n"
        "  • Persistent, per-binary:  sudo setcap cap_sys_ptrace+ep %1\n"
        "  • Whole system, until reboot:  sudo sysctl kernel.yama.ptrace_scope=0")
        .arg(QCoreApplication::applicationFilePath()));

    // Offer one-click elevation only when pkexec (polkit) is actually available.
    QPushButton* grantBtn = nullptr;
    const bool havePkexec = !QStandardPaths::findExecutable(QStringLiteral("pkexec")).isEmpty();
    if (havePkexec)
        grantBtn = box.addButton(QCoreApplication::translate("MainWindow", "Grant access…"), QMessageBox::AcceptRole);
    box.addButton(QMessageBox::Close);
    box.exec();

    if (grantBtn && box.clickedButton() == grantBtn)
        grantPtraceAccess(parent);
}

// "Wait for process" found its program. Attaching replaces the target and
// deletes its windows, which must not happen under a dialog or menu still on
// the stack (a queued call runs inside their event loops): try again once it
// has closed. Report success only when the attach happened.
// A hit from a watch that has since ended (another attach, a new watch, an
// earlier hit that attached) is dropped, also while it waits for a dialog.
void MainWindow::autoAttach(pid_t pid, const QString& name, quint64 watch) {
    if (watch != processWatch_) return;
    if (::kill(pid, 0) != 0 && errno == ESRCH) return;   // gone before we got to it
    // A running scan also waits here, not in attachToPid, so the retry is checked too.
    if (QApplication::activeModalWidget() || QApplication::activePopupWidget() || scanInProgress_) {
        QTimer::singleShot(250, this, [this, pid, name, watch]() { autoAttach(pid, name, watch); });
        return;
    }
    // Through attachToPid so the old target's Debugger/views are torn down
    // before process_ is replaced (they hold a raw handle).
    attachToPid(pid, name);
    if (process_ && currentPid_ == pid) {
        statusBar()->showMessage(QString(tr("Auto-attached to %1 (pid %2)")).arg(name).arg(pid), 4000);
        stopProcessWatch();
    } else {
        statusBar()->showMessage(QString(tr("Found %1 (pid %2) but could not open it")).arg(name).arg(pid), 8000);
    }
}

void MainWindow::stopProcessWatch() {
    if (processWatcher_) processWatcher_->stop();
    ++processWatch_;
}

void MainWindow::attachToPid(pid_t pid, const QString& name) {
    if (scanInProgress_) {   // queued while a scan runs ("Wait for process"): attach after it
        QTimer::singleShot(200, this, [this, pid, name] { attachToPid(pid, name); });
        return;
    }
    if (!releaseTargetUsers()) return;
    currentPid_ = pid;
    process_.reset();
    ceserverClient_.reset();
    process_ = std::make_unique<os::LinuxProcessHandle>(pid);
    // A target chosen now ends a pending "Wait for process": it would otherwise
    // switch to the next match whenever one starts, hours later.
    stopProcessWatch();
    // Resolve a readable name so the header isn't "PID: 1234 - 1234" when we were
    // handed a bare pid (--pid, or a caller that didn't know the name): read the
    // process's own /proc/<pid>/comm (e.g. "sleep"), falling back to the number.
    QString label = name;
    if (label.isEmpty()) {
        QFile comm(QString("/proc/%1/comm").arg(pid));
        if (comm.open(QIODevice::ReadOnly))
            label = QString::fromUtf8(comm.readAll()).trimmed();
        if (label.isEmpty()) label = QString::number(pid);
    }
    processLabel_->setText(label);
    processDetail_->setText(QString("PID %1").arg(pid));
    currentProcessName_ = label;
    updateWindowTitle();
    warnIfMemoryUnreadable(this, process_.get(), pid, label);
    addressListModel_->setProcess(process_.get());
    resultsModel_->setProcess(process_.get());
    // Keep the shared Lua engine pointed at the current target, so scripts (and an
    // already-open Lua Engine console) operate on this process after a re-attach,
    // not a stale one. The address list model is persistent; bind it too.
    luaEngine_.setProcess(process_.get());
    luaEngine_.setAddressList(addressListModel_);
    firstScanBtn_->setEnabled(true);
    resultsModel_->clear();
    lastResult_.reset();
    undoResult_.reset();
    lastResultType_ = ValueType::Int32;
    undoResultType_ = ValueType::Int32;
    lastResultValueSize_ = 0;
    undoResultValueSize_ = 0;
    resetGuestScanSetup();
    updateScanButtons();

    // Honest reporting: tell the user up-front what kind of target this is (Wine,
    // emulator, managed runtime, sandboxed, already-traced) so any limitation is an
    // explicit note, not a silent surprise later. See docs/CHALLENGING_TARGETS.md.
    {
        ce::TargetProfile prof = ce::probeTarget(pid);
        processDetail_->setText(QString("PID %1  ·  %2").arg(pid).arg(QString::fromStdString(prof.summary())));
        statusBar()->showMessage(
            QString(tr("Attached to %1: %2")).arg(label, QString::fromStdString(prof.summary())), 8000);
        // The summary + every note live on the process label's tooltip (persistent,
        // non-intrusive; hover to read).
        QString tip = QString::fromStdString(prof.summary());
        for (const auto& n : prof.notes) tip += "\n\n• " + QString::fromStdString(n);
        auto target = process_->targetDescription();
        tip += QString(tr("\n\nProgram: %1, %2-byte pointers, %3\nHost ABI: %4"))
            .arg(ce::cpuArchitectureName(target.program.architecture)).arg(target.program.pointerWidth)
            .arg(ce::byteOrderName(target.program.byteOrder)).arg(ce::targetAbiName(target.host.abi));
        for (const auto& c : ce::targetCapabilities(target))
            if (c.state != ce::CapabilityState::Available)
                tip += QString("\n%1: %2. %3").arg(ce::targetFeatureName(c.feature),
                    ce::capabilityStateName(c.state), QString::fromStdString(c.reason));
        processLabel_->setToolTip(tip);
        // The one note that means nothing will work at all (attach/watch/inject all
        // fail) is worth an explicit dialog: the target is already being traced.
        if (prof.tracerPid != 0 && !prof.notes.empty())
            QMessageBox::warning(this, tr("Target already being traced"),
                QString::fromStdString(prof.notes.front()));
    }
}

void MainWindow::onOpenProcess() {
    ProcessListDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted)
        attachToPid(dlg.selectedPid(), dlg.selectedName());
}

bool MainWindow::attachToGdb(std::unique_ptr<ce::GdbProcessHandle> process,const QString& endpoint) {
    if (!process) return false;
    const auto description=process->targetDescription();
    if (!description.live) {statusBar()->showMessage(QString::fromStdString(process->lastTransportError()),5000);return false;}
    const auto architecture=QString::fromStdString(process->registerDescription().architecture);
    if (!releaseTargetUsers()) return false;
    process_.reset();ceserverClient_.reset();
    process_=std::move(process);currentPid_=0;
    stopProcessWatch();   // see attachToPid
    luaEngine_.setProcess(process_.get());luaEngine_.setAddressList(addressListModel_);
    addressListModel_->setProcess(process_.get());resultsModel_->setProcess(process_.get());
    resultsModel_->clear();lastResult_.reset();undoResult_.reset();
    lastResultType_=undoResultType_=ValueType::Int32;lastResultValueSize_=undoResultValueSize_=0;
    foundLabel_->setText(tr("Found: 0"));
    const QString dataOrder=description.program.byteOrder==ce::ByteOrder::Unknown
        ? tr("data order unknown") : QString(tr("%1 data")).arg(ce::byteOrderName(description.program.byteOrder));
    const QString pointers=description.program.pointerWidth
        ? QString(tr("%1-bit pointers")).arg(description.program.pointerWidth*8) : tr("pointer width unknown");
    processLabel_->setText(QString(tr("GDB: %1")).arg(endpoint));
    processDetail_->setText(QString("%1  ·  %2  ·  %3").arg(architecture,dataOrder,pointers));
    QString tip=QString(tr("Guest CPU: %1\nData order: %2\nProgram pointers: %3\nTransport: GDB"))
        .arg(architecture).arg(ce::byteOrderName(description.program.byteOrder)).arg(pointers);
    for (const auto& capability:ce::targetCapabilities(description))
        if (capability.state!=ce::CapabilityState::Available)
            tip+=QString("\n%1: %2. %3").arg(ce::targetFeatureName(capability.feature),ce::capabilityStateName(capability.state),QString::fromStdString(capability.reason));
    processLabel_->setToolTip(tip);currentProcessName_="GDB "+endpoint;updateWindowTitle();
    const auto regions=process_->queryRegions();
    if (!regions.empty()) {
        fromAddressEdit_->setText(QString("0x%1").arg(regions.front().base,0,16));
        toAddressEdit_->setText(QString("0x%1").arg(regions.back().base+regions.back().size-1,0,16));
    }
    // Raw byte patterns work even when the stub cannot identify data byte order.
    valueTypeCombo_->setCurrentIndex(8); // ByteArray, see mapValueType.
    guestScanSetup_ = true;
    updateScanButtons();
    statusBar()->showMessage(regions.empty() ? tr("Connected to GDB; no memory map. Reconnect with a known scan range.") : tr("Connected to GDB target"),8000);
    return true;
}
void MainWindow::onConnectGdb() {
    GdbConnectionDialog dialog(this);
    if (dialog.exec()==QDialog::Accepted) attachToGdb(dialog.takeProcess(),dialog.endpoint());
}
// A GDB guest narrows the scan to its memory and Array of byte; the next
// target must not inherit that (First Scan on a native process searched only
// the old guest range and found nothing).
void MainWindow::resetGuestScanSetup() {
    if (foundLabel_) foundLabel_->setText(tr("Found: 0"));
    if (!guestScanSetup_) return;
    guestScanSetup_ = false;
    fromAddressEdit_->setText("0000000000");
    toAddressEdit_->setText(QString::number(UINTPTR_MAX, 16));
    const int dvt = QSettings().value("scan/defaultValueType", 2).toInt();
    static const int kSettingsToScanner[] = {0, 1, 2, 3, 4, 5, 6, 8, 11};
    if (dvt >= 0 && dvt < 9 && kSettingsToScanner[dvt] < valueTypeCombo_->count())
        valueTypeCombo_->setCurrentIndex(kSettingsToScanner[dvt]);
}

void MainWindow::onDisconnectProcess() {
    if (!releaseTargetUsers()) return;
    stopProcessWatch();
    resetGuestScanSetup();
    process_.reset();ceserverClient_.reset();currentPid_=0;
    addressListModel_->setProcess(nullptr);resultsModel_->setProcess(nullptr);resultsModel_->clear();
    lastResult_.reset();undoResult_.reset();lastResultType_=undoResultType_=ValueType::Int32;
    lastResultValueSize_=undoResultValueSize_=0;foundLabel_->setText(tr("Found: 0"));
    processLabel_->setText(tr("No process selected"));processLabel_->setToolTip({});processDetail_->setText(tr("Press Ctrl+O or click the magnifier to choose a process."));currentProcessName_.clear();updateWindowTitle();updateScanButtons();
}

// The network half of attaching to a ceserver target: no GUI state, so the
// Connect dialog can run it on a worker thread (each step can wait 5 s, and
// resolving a host name has no limit at all).
MainWindow::CeserverConnection MainWindow::connectCeserver(const QString& host, uint16_t port, pid_t pid) {
    CeserverConnection c;
    c.client = std::make_unique<ce::os::CEServerClient>();
    std::string err;
    if (!c.client->connectTcp(host.toStdString(), port, err)) {
        c.error = QString(tr("Connect failed: %1")).arg(QString::fromStdString(err));
        return c;
    }
    auto version = c.client->getVersion();
    if (!version) {
        c.error = QString(tr("Handshake failed: %1")).arg(QString::fromStdString(version.error()));
        return c;
    }
    c.version = QString::fromStdString(version->versionString);
    c.handle = ce::os::RemoteProcessHandle::open(*c.client, pid);
    if (!c.handle) c.error = QString(tr("Server refused PID %1")).arg((int)pid);
    return c;
}

bool MainWindow::attachToCeserver(const QString& host, uint16_t port, pid_t pid, QString* error) {
    auto connection = connectCeserver(host, port, pid);
    return adoptCeserver(std::move(connection), host, port, pid, error);
}

bool MainWindow::adoptCeserver(CeserverConnection connection, const QString& host, uint16_t port, pid_t pid, QString* error) {
    auto fail = [&](const QString& message) { if (error) *error = message; return false; };
    if (!connection.handle) return fail(connection.error);
    auto client = std::move(connection.client);
    auto handle = std::move(connection.handle);
    if (!releaseTargetUsers())
        return fail(tr("The current target is still in use: wait for the scan to finish or disable its scripts, then connect again."));
    process_.reset();
    ceserverClient_ = std::move(client);
    process_ = std::move(handle);
    stopProcessWatch();   // see attachToPid
    luaEngine_.setProcess(process_.get());
    currentPid_ = pid;
    processLabel_->setText(QString(tr("Remote process %1")).arg((int)pid));
    processDetail_->setText(QString("ceserver %1:%2  ·  %3").arg(host).arg(port).arg(connection.version));
    currentProcessName_ = QString("ceserver %1:%2").arg(host).arg(port);
    updateWindowTitle();
    addressListModel_->setProcess(process_.get());
    resultsModel_->setProcess(process_.get());
    firstScanBtn_->setEnabled(true);
    resultsModel_->clear();
    lastResult_.reset();
    undoResult_.reset();
    lastResultType_ = ValueType::Int32;
    undoResultType_ = ValueType::Int32;
    lastResultValueSize_ = 0;
    undoResultValueSize_ = 0;
    resetGuestScanSetup();
    updateScanButtons();
    return true;
}

void MainWindow::onConnectCeserver() {
    QSettings settings;
    auto* dlg = new QDialog(this);
    dlg->setWindowTitle(tr("Connect to ceserver"));
    auto* form = new QFormLayout(dlg);
    auto* intro = new QLabel(tr("Attach to a process on another machine (or in a container) "
                             "through a running ceserver."));
    intro->setWordWrap(true);
    intro->setProperty("secondary", true);
    form->addRow(intro);

    auto* hostEdit = new QLineEdit(settings.value("network/ceserverHost", "127.0.0.1").toString());
    form->addRow(tr("Host:"), hostEdit);

    auto* portSpin = new QSpinBox;
    portSpin->setRange(1, 65535);
    portSpin->setValue(settings.value("network/ceserverPort", 52736).toInt());
    form->addRow(tr("Port:"), portSpin);

    auto* pidEdit = new QLineEdit;
    pidEdit->setPlaceholderText(tr("process ID on the remote machine"));
    pidEdit->setValidator(new QIntValidator(1, std::numeric_limits<int>::max(), pidEdit));
    portSpin->setGroupSeparatorShown(false);
    hostEdit->setMinimumWidth(240);
    form->addRow(tr("PID:"), pidEdit);

    auto* statusLabel = new QLabel;
    statusLabel->setWordWrap(true);
    form->addRow(statusLabel);

    auto* btnRow = new QHBoxLayout;
    auto* connectBtn = new QPushButton(tr("Connect"));
    connectBtn->setProperty("primary", true);
    connectBtn->setDefault(true);
    auto* cancelBtn = new QPushButton(tr("Cancel"));
    btnRow->addStretch();
    btnRow->addWidget(connectBtn);
    btnRow->addWidget(cancelBtn);
    form->addRow(btnRow);

    connect(cancelBtn, &QPushButton::clicked, dlg, &QDialog::reject);
    QPointer<QDialog> guard(dlg);
    connect(connectBtn, &QPushButton::clicked, this, [this, guard, dlg, hostEdit, portSpin, pidEdit, statusLabel, connectBtn]() {
        bool ok = false;
        pid_t pid = pidEdit->text().toInt(&ok);
        if (!ok || pid <= 0) {
            statusLabel->setText(tr("Enter a valid remote PID."));
            return;
        }
        const QString host = hostEdit->text();
        const auto port = static_cast<uint16_t>(portSpin->value());
        statusLabel->setText(QString(tr("Connecting to %1:%2...")).arg(host).arg(port));
        connectBtn->setEnabled(false);
        // Off the GUI thread; Cancel closes the dialog and the late result is
        // dropped (its connection closes with it).
        std::thread([this, guard, dlg, host, port, pid, statusLabel, connectBtn]() {
            auto connection = std::make_shared<CeserverConnection>(connectCeserver(host, port, pid));
            // Posted to the application, not this window: the window may be
            // gone by now. The dialog (its child) being alive says it is not.
            QMetaObject::invokeMethod(qApp, [this, guard, dlg, host, port, pid, statusLabel, connectBtn, connection]() {
                if (!guard || !dlg->isVisible()) return;   // cancelled meanwhile
                connectBtn->setEnabled(true);
                QString error;
                if (!adoptCeserver(std::move(*connection), host, port, pid, &error)) {
                    if (!error.isEmpty()) statusLabel->setText(error);
                    return;
                }
                QSettings settings;
                settings.setValue("network/ceserverHost", host);
                settings.setValue("network/ceserverPort", port);
                dlg->accept();
            }, Qt::QueuedConnection);
        }).detach();
    });

    dlg->exec();
    dlg->deleteLater();
}
} // namespace ce::gui
