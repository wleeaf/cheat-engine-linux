/// Break-and-trace window — runs a Tracer on a worker thread, displays decoded steps.

#include "gui/tracerwindow.hpp"
#include "gui/theme.hpp"
#include <QDialogButtonBox>
#include <QCoreApplication>
#include "core/target_capabilities.hpp"
#include "core/cpu_registers.hpp"
#include <cctype>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QFont>
#include <QDialog>
#include <QPlainTextEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QTimer>

namespace ce::gui {

RegisterCondition::~RegisterCondition() {
    if (lua_) lua_close(lua_);
}

std::string RegisterCondition::compile(const std::string& expression) {
    if (lua_) lua_close(lua_);
    lua_ = luaL_newstate();
    if (!lua_) return "out of memory";
    // Only the math and string libraries: a condition reads registers, nothing more.
    luaL_requiref(lua_, "_G", luaopen_base, 1);
    luaL_requiref(lua_, LUA_MATHLIBNAME, luaopen_math, 1);
    luaL_requiref(lua_, LUA_STRLIBNAME, luaopen_string, 1);
    lua_settop(lua_, 0);
    for (const char* unsafe : {"dofile", "loadfile", "load", "require", "collectgarbage"}) {
        lua_pushnil(lua_);
        lua_setglobal(lua_, unsafe);
    }
    const std::string chunk = "return (" + expression + ")";
    if (luaL_loadstring(lua_, chunk.c_str()) != LUA_OK) {
        std::string message = lua_tostring(lua_, -1);
        lua_close(lua_);
        lua_ = nullptr;
        return message;
    }
    function_ = luaL_ref(lua_, LUA_REGISTRYINDEX);
    return {};
}

bool RegisterCondition::operator()(const ce::CpuContext& context) {
    if (!lua_) return false;
    for (const auto& reg : ce::cpuRegisterValues(context)) {
        lua_pushinteger(lua_, static_cast<lua_Integer>(reg.value));
        lua_setglobal(lua_, reg.name.c_str());
        // A 64-bit register also answers to its 32-bit name (RAX and EAX).
        if (reg.name.size() == 3 && reg.name[0] == 'R' && std::isalpha(static_cast<unsigned char>(reg.name[1])) &&
            reg.bits == 64) {
            std::string low = "E" + reg.name.substr(1);
            lua_pushinteger(lua_, static_cast<lua_Integer>(reg.value & 0xffffffffu));
            lua_setglobal(lua_, low.c_str());
        }
    }
    lua_rawgeti(lua_, LUA_REGISTRYINDEX, function_);
    if (lua_pcall(lua_, 0, 1, 0) != LUA_OK) { lua_pop(lua_, 1); return false; }
    const bool result = lua_toboolean(lua_, -1);
    lua_pop(lua_, 1);
    return result;
}

QString TracerWindow::hexQ(uint64_t v) { return QString("0x%1").arg(v, 0, 16); }

QVariant TraceTableModel::data(const QModelIndex& index, int role) const {
    if (role != Qt::DisplayRole || !index.isValid() || static_cast<size_t>(index.row()) >= entries_->size())
        return {};
    const auto& e = (*entries_)[static_cast<size_t>(index.row())];
    const auto& c = e.context;
    const bool arm = c.architecture == ce::CpuArchitecture::Arm64;
    switch (index.column()) {
        case 0: return QString::number(index.row());
        case 1: return TracerWindow::hexQ(e.address);
        case 2: return e.memoryNote.empty() ? QString::fromStdString(e.instruction)
                                            : QString::fromStdString(e.instruction + "   ; " + e.memoryNote);
        case 3: return TracerWindow::hexQ(arm ? c.x[0] : c.rax);
        case 4: return TracerWindow::hexQ(arm ? c.x[1] : c.rbx);
        case 5: return TracerWindow::hexQ(arm ? c.x[2] : c.rcx);
        case 6: return TracerWindow::hexQ(arm ? c.x[3] : c.rdx);
        case 7: return TracerWindow::hexQ(c.instructionPointer());
    }
    return {};
}

QVariant TraceTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0 || section >= 8) return {};
    const auto architecture = entries_->empty() ? ce::CpuArchitecture::Unknown : entries_->front().context.architecture;
    // "Address" and "Instruction" are column headers; the per-architecture
    // register mnemonics are technical names and stay untranslated.
    static const char* x64[] = {"#", QT_TRANSLATE_NOOP("TraceTableModel", "Address"),
                                QT_TRANSLATE_NOOP("TraceTableModel", "Instruction"),
                                "RAX", "RBX", "RCX", "RDX", "RIP"};
    static const char* x86[] = {"#", QT_TRANSLATE_NOOP("TraceTableModel", "Address"),
                                QT_TRANSLATE_NOOP("TraceTableModel", "Instruction"),
                                "EAX", "EBX", "ECX", "EDX", "EIP"};
    static const char* a64[] = {"#", QT_TRANSLATE_NOOP("TraceTableModel", "Address"),
                                QT_TRANSLATE_NOOP("TraceTableModel", "Instruction"),
                                "X0", "X1", "X2", "X3", "PC"};
    const char** names = architecture == ce::CpuArchitecture::Arm64 ? a64
                       : architecture == ce::CpuArchitecture::X86_32 ? x86 : x64;
    return QCoreApplication::translate("TraceTableModel", names[section]);
}

static QString fullRegisterDump(const ce::CpuContext& c) {
    auto h = [](uint64_t v) { return QString("0x%1").arg(v, 0, 16); };
    QString s;
    if (c.architecture==ce::CpuArchitecture::Arm64) {
        for (size_t i=0;i<c.x.size();++i)
            s+=QString("x%1 = %2\n").arg(i).arg(h(c.x[i]));
        s+=QString("sp = %1\npc = %2\npstate = %3\n").arg(h(c.sp),h(c.pc),h(c.pstate));
        return s;
    }
    if (c.architecture==ce::CpuArchitecture::X86_32) {
        s+=QString("eax = %1   ebx = %2\necx = %3   edx = %4\n")
            .arg(h(c.rax),h(c.rbx),h(c.rcx),h(c.rdx));
        s+=QString("esi = %1   edi = %2\nebp = %3   esp = %4\n")
            .arg(h(c.rsi),h(c.rdi),h(c.rbp),h(c.rsp));
        s+=QString("eip = %1\neflags = %2\n").arg(h(c.rip),h(c.rflags));
        return s;
    }
    s += QString("rax = %1   rbx = %2\n").arg(h(c.rax), h(c.rbx));
    s += QString("rcx = %1   rdx = %2\n").arg(h(c.rcx), h(c.rdx));
    s += QString("rsi = %1   rdi = %2\n").arg(h(c.rsi), h(c.rdi));
    s += QString("rbp = %1   rsp = %2\n").arg(h(c.rbp), h(c.rsp));
    s += QString("r8  = %1   r9  = %2\n").arg(h(c.r8),  h(c.r9));
    s += QString("r10 = %1   r11 = %2\n").arg(h(c.r10), h(c.r11));
    s += QString("r12 = %1   r13 = %2\n").arg(h(c.r12), h(c.r13));
    s += QString("r14 = %1   r15 = %2\n").arg(h(c.r14), h(c.r15));
    s += QString("rip = %1\n").arg(h(c.rip));
    s += QString("rflags = %1\n").arg(h(c.rflags));
    return s;
}

TracerWindow::TracerWindow(ProcessHandle* proc, DebuggerFactory factory, QWidget* parent)
    : QMainWindow(parent), proc_(proc), debuggerFactory_(std::move(factory)) {
    setWindowTitle(tr("Break and Trace"));
    resize(1100, 600);
    buildUi();
}

TracerWindow::~TracerWindow() {
    if (worker_.joinable()) {
        tracer_.cancel();
        worker_.join();
    }
}

void TracerWindow::buildUi() {
    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    // Inputs grid
    auto* form = new QGridLayout;
    int row = 0;

    form->addWidget(new QLabel(tr("Start address (hex):")), row, 0);
    startAddressEdit_ = new QLineEdit;
    startAddressEdit_->setPlaceholderText(tr("0x0000000000000000, leave blank to start at the instruction pointer"));
    form->addWidget(startAddressEdit_, row, 1, 1, 3);
    ++row;

    form->addWidget(new QLabel(tr("Max steps:")), row, 0);
    maxStepsSpin_ = new QSpinBox;
    maxStepsSpin_->setRange(1, 1'000'000);
    maxStepsSpin_->setValue(1000);
    form->addWidget(maxStepsSpin_, row, 1);

    stepOverCheck_ = new QCheckBox(tr("Step over calls"));
    form->addWidget(stepOverCheck_, row, 2);

    stayInModuleCheck_ = new QCheckBox(tr("Stay in module"));
    form->addWidget(stayInModuleCheck_, row, 3);
    ++row;

    form->addWidget(new QLabel(tr("Module start (hex):")), row, 0);
    moduleStartEdit_ = new QLineEdit;
    moduleStartEdit_->setPlaceholderText(tr("0x... (only if Stay in module)"));
    form->addWidget(moduleStartEdit_, row, 1);
    form->addWidget(new QLabel(tr("end:")), row, 2);
    moduleEndEdit_ = new QLineEdit;
    form->addWidget(moduleEndEdit_, row, 3);
    ++row;

    form->addWidget(new QLabel(tr("Stop address (hex, optional):")), row, 0);
    stopAddressEdit_ = new QLineEdit;
    stopAddressEdit_->setPlaceholderText(tr("Trace stops when this address is reached"));
    form->addWidget(stopAddressEdit_, row, 1, 1, 3);
    ++row;

    form->addWidget(new QLabel(tr("Start condition (optional, Lua):")), row, 0);
    startConditionEdit_ = new QLineEdit;
    startConditionEdit_->setPlaceholderText(tr("e.g. RCX == 0x10; the trace starts at the first hit where it is true (x86)"));
    form->addWidget(startConditionEdit_, row, 1, 1, 3);
    ++row;

    form->addWidget(new QLabel(tr("Stop condition (optional, Lua):")), row, 0);
    stopConditionEdit_ = new QLineEdit;
    stopConditionEdit_->setPlaceholderText(tr("e.g. RAX == 0; the trace ends at the first step where it is true"));
    form->addWidget(stopConditionEdit_, row, 1, 1, 3);
    ++row;

    stepOverRepCheck_ = new QCheckBox(tr("Step over rep instructions"));
    form->addWidget(stepOverRepCheck_, row, 0);
    skipSystemCheck_ = new QCheckBox(tr("Skip system modules"));
    skipSystemCheck_->setToolTip(tr("Step over calls into system libraries (the C library, Wine's DLLs)"));
    form->addWidget(skipSystemCheck_, row, 1);
    dereferenceCheck_ = new QCheckBox(tr("Dereference Addresses (Slows down)"));
    form->addWidget(dereferenceCheck_, row, 2);
    saveStackCheck_ = new QCheckBox(tr("Save stack snapshots (Eats memory)"));
    form->addWidget(saveStackCheck_, row, 3);
    ++row;

    layout->addLayout(form);

    // Buttons + progress
    auto* btnRow = new QHBoxLayout;
    startBtn_ = new QPushButton(tr("Start Trace"));
    cancelBtn_ = new QPushButton(tr("Cancel"));
    cancelBtn_->setEnabled(false);
    saveBtn_ = new QPushButton(tr("Save…"));
    saveBtn_->setEnabled(false);
    progressBar_ = new QProgressBar;
    progressBar_->setRange(0, 100);
    statusLabel_ = new QLabel(tr("Idle"));
    btnRow->addWidget(startBtn_);
    btnRow->addWidget(cancelBtn_);
    btnRow->addWidget(saveBtn_);
    btnRow->addWidget(progressBar_, 1);
    btnRow->addWidget(statusLabel_);
    layout->addLayout(btnRow);

    // Results table
    table_ = new QTableView;
    model_ = new TraceTableModel(&entries_, table_);
    table_->setModel(model_);
    // Fit the index, address and 64-bit register columns to content (they clipped
    // at the 100px default); the disassembly text column takes the slack.
    for (int c = 0; c < 8; ++c)
        table_->horizontalHeader()->setSectionResizeMode(c, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setProperty("monospace", true);   // font from the theme sheet
    styleDataTable(table_);
    setEmptyHint(table_, tr("Traced instructions appear here."));
    connect(table_, &QTableView::doubleClicked, this, [this](const QModelIndex& index) {
        if (!index.isValid() || index.row() >= (int)entries_.size()) return;
        const auto& e = entries_[index.row()];
        auto* dlg = new QDialog(this);
        dlg->setWindowTitle(tr("Step %1 @ 0x%2").arg(index.row()).arg(e.address, 0, 16));
        dlg->resize(500, 320);
        auto* dl = new QVBoxLayout(dlg);
        auto* hdr = new QLabel(QString("<b>%1</b>").arg(QString::fromStdString(e.instruction)));
        dl->addWidget(hdr);
        QString details = fullRegisterDump(e.context);
        if (!e.memoryNote.empty()) details += "\n" + QString::fromStdString(e.memoryNote) + "\n";
        if (!e.stack.empty()) {
            details += "\n" + tr("Stack:") + "\n";
            for (size_t offset = 0; offset < e.stack.size(); offset += 16) {
                QStringList bytes;
                for (size_t i = offset; i < std::min(offset + 16, e.stack.size()); ++i)
                    bytes << QString("%1").arg(e.stack[i], 2, 16, QChar('0'));
                details += QString("+%1  %2\n").arg(offset, 3, 16, QChar('0')).arg(bytes.join(' '));
            }
        }
        auto* dump = new QPlainTextEdit(details);
        dump->setReadOnly(true);
        dump->setFont(monospaceFont(-1));
        dl->addWidget(dump);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
        connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::accept);
        dl->addWidget(buttons);
        dlg->exec();
        dlg->deleteLater();
    });
    layout->addWidget(table_);

    setCentralWidget(central);

    connect(startBtn_, &QPushButton::clicked, this, &TracerWindow::onStart);
    connect(cancelBtn_, &QPushButton::clicked, this, &TracerWindow::onCancel);
    connect(saveBtn_, &QPushButton::clicked, this, &TracerWindow::onSave);

    // Periodic progress updater while a trace is running.
    auto* poll = new QTimer(this);
    connect(poll, &QTimer::timeout, this, [this]() {
        if (!worker_.joinable()) return;
        progressBar_->setValue((int)(tracer_.progress() * 100.0f));
    });
    poll->start(100);
}

void TracerWindow::onStart() {
    if (!proc_) {
        QMessageBox::warning(this, tr("No process"), tr("Open a process before tracing."));
        return;
    }
    if (worker_.joinable()) return;

    TraceConfig cfg;
    auto address=[this](QLineEdit* edit,uintptr_t& result) {
        auto text=edit->text().trimmed();
        if (text.isEmpty()) { result=0; return true; }
        bool ok=false;
        auto value=text.toULongLong(&ok,16);
        if (!ok || value>UINTPTR_MAX) {
            statusLabel_->setText(tr("Invalid hexadecimal address"));
            edit->setFocus(); edit->selectAll(); return false;
        }
        result=static_cast<uintptr_t>(value); return true;
    };
    if (!address(startAddressEdit_,cfg.startAddress) || !address(stopAddressEdit_,cfg.stopAddress)) return;
    cfg.maxSteps = maxStepsSpin_->value();
    cfg.stepOverCalls = stepOverCheck_->isChecked();
    cfg.stayInModule = stayInModuleCheck_->isChecked();
    if (cfg.stayInModule) {
        if (!address(moduleStartEdit_,cfg.moduleBase) || !address(moduleEndEdit_,cfg.moduleEnd)) return;
        if (!cfg.moduleEnd || cfg.moduleEnd<=cfg.moduleBase) {
            statusLabel_->setText(tr("Module end must be greater than its start")); return;
        }
    }

    cfg.stepOverRep = stepOverRepCheck_->isChecked();
    cfg.skipSystemModules = skipSystemCheck_->isChecked();
    cfg.dereferenceAddresses = dereferenceCheck_->isChecked();
    cfg.stackBytes = saveStackCheck_->isChecked() ? 256 : 0;
    // Each condition gets its own Lua state, used only on the trace thread.
    auto condition = [this](QLineEdit* edit, std::shared_ptr<RegisterCondition>& slot) {
        slot.reset();
        const QString text = edit->text().trimmed();
        if (text.isEmpty()) return true;
        auto compiled = std::make_shared<RegisterCondition>();
        if (const std::string error = compiled->compile(text.toStdString()); !error.empty()) {
            statusLabel_->setText(tr("Invalid condition: %1").arg(QString::fromStdString(error)));
            edit->setFocus();
            return false;
        }
        slot = std::move(compiled);
        return true;
    };
    if (!condition(startConditionEdit_, startCondition_) || !condition(stopConditionEdit_, stopCondition_)) return;
    if (startCondition_ && !cfg.startAddress) {
        statusLabel_->setText(tr("A start condition needs a start address"));
        return;
    }
    if (startCondition_) cfg.startCondition = [c = startCondition_](const ce::CpuContext& ctx) { return (*c)(ctx); };
    if (stopCondition_) cfg.stopCondition = [c = stopCondition_](const ce::CpuContext& ctx) { return (*c)(ctx); };

    debugger_ = debuggerFactory_ ? debuggerFactory_() : std::make_unique<os::LinuxDebugger>();
    if (!debugger_) {
        QMessageBox::warning(this, tr("No debugger"),
            tr("No debugger could be constructed for the attached process."));
        return;
    }
    entries_.clear();
    model_->reload();
    progressBar_->setValue(0);
    statusLabel_->setText(tr("Tracing…"));
    startBtn_->setEnabled(false);
    cancelBtn_->setEnabled(true);
    saveBtn_->setEnabled(false);

    tracer_.prepare();   // a Cancel or close from now on reaches the worker
    worker_ = std::thread([this, cfg]() {
        auto results = tracer_.trace(*proc_, *debugger_, cfg);
        QMetaObject::invokeMethod(this, [this, results = std::move(results)]() mutable {
            entries_ = std::move(results);
            onTraceFinished();
        }, Qt::QueuedConnection);
    });
}

void TracerWindow::onCancel() {
    tracer_.cancel();
    statusLabel_->setText(tr("Cancelling…"));
}

void TracerWindow::onTraceFinished() {
    if (worker_.joinable()) worker_.join();

    model_->reload();   // headers follow the trace's architecture
    progressBar_->setValue(100);
    if (entries_.empty())
        statusLabel_->setText(tr("%1 steps recorded (check start address / module range)")
                                  .arg(entries_.size()));
    else
        statusLabel_->setText(tr("%1 steps recorded").arg(entries_.size()));
    if (auto error=tracer_.lastError())
        statusLabel_->setText(tr("%1 steps recorded: %2").arg(entries_.size()).arg(QString::fromStdString(
            proc_ ? ce::targetOperationError(*proc_, ce::TargetFeature::Trace, error) : error.message())));
    startBtn_->setEnabled(true);
    cancelBtn_->setEnabled(false);
    saveBtn_->setEnabled(!entries_.empty());
}

void TracerWindow::onSave() {
    auto path = QFileDialog::getSaveFileName(this, tr("Save trace"), "trace.txt", tr("Text (*.txt)"));
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Save failed"), f.errorString());
        return;
    }
    QTextStream out(&f);
    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& e = entries_[i];
        out << QString("%1\t").arg(i) << hexQ(e.address) << '\t'
            << QString::fromStdString(e.instruction);
        if (!e.memoryNote.empty()) out << "\t; " << QString::fromStdString(e.memoryNote);
        out << '\n' << fullRegisterDump(e.context) << '\n';
    }
}

} // namespace ce::gui
