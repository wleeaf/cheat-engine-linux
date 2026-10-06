#include <QClipboard>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QFile>
#include <QSettings>
#include <poll.h>
#include <sstream>

namespace gui_injection_test {
struct Fixture {
    pid_t pid = -1;
    int input = -1, output = -1;
    explicit Fixture(const char* executable) {
        int in[2], out[2];
        if (pipe(in)) return;
        if (pipe(out)) { close(in[0]); close(in[1]); return; }
        pid = fork();
        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            dup2(in[0], 0); dup2(out[1], 1);
            close(in[0]); close(in[1]); close(out[0]); close(out[1]);
            execl(executable, executable, nullptr);
            _exit(127);
        }
        close(in[0]); close(out[1]);
        input = in[1]; output = out[0];
    }
    bool command(char c) { return ::write(input, &c, 1) == 1; }
    std::string line() {
        std::string result;
        while (result.size() < 4096) {
            pollfd fd{output, POLLIN, 0};
            if (poll(&fd, 1, 3000) <= 0) return {};
            char c;
            if (::read(output, &c, 1) != 1) return {};
            if (c == '\n') return result;
            result += c;
        }
        return {};
    }
    bool finish() {
        if (!command('q')) return false;
        int status = 0;
        const auto result = waitpid(pid, &status, 0);
        if (result == pid) pid = -1;
        return result > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    ~Fixture() {
        if (pid > 0) { kill(pid, SIGKILL); int status; while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {} }
        if (input >= 0) close(input);
        if (output >= 0) close(output);
    }
};
struct Ready { unsigned width = 0; uintptr_t value = 0, code = 0; };
Ready ready(Fixture& fixture) {
    Ready r; uintptr_t pointer = 0; pid_t pid = 0; std::string magic;
    std::istringstream stream(fixture.line());
    stream >> magic >> pid >> r.width >> std::hex >> r.value >> pointer >> r.code;
    return stream && magic == "CE_TARGET" && pid == fixture.pid ? r : Ready{};
}
bool saved(const ce::DisableInfo& info) {
    return info.ownership || info.image || !info.originals.empty() || !info.allocs.empty() ||
        !info.protections.empty() || !info.symbols.empty();
}
struct Checks {
    unsigned width, count = 0, failures = 0;
    void operator()(bool ok, const char* name) {
        ++count; failures += !ok;
        std::printf("GUI_INJECTION %u %s: %s\n", width, ok ? "OK" : "FAILED", name);
    }
};
bool profile(const char* path, unsigned width) {
    Checks check{width};
    Fixture fixture(path); auto r = ready(fixture);
    check(r.width == width, "owned fixture starts with the required ABI");
    if (r.width != width) return false;
    ce::os::LinuxProcessHandle proc(fixture.pid);
    uint8_t original = 0;
    auto read = proc.read(r.code, &original, 1);
    auto scratch = proc.allocate(4096, ce::MemProt::ReadWrite);
    check(read && *read == 1 && scratch.has_value(), "real executable byte and scratch allocation available");
    if (!read || !scratch) return false;
    auto zero = [&] { uint64_t value = 0; return proc.write(*scratch, &value, width).has_value(); };
    auto block = [&] { uint64_t value = 0; auto result = proc.read(*scratch, &value, width); return result && *result == width ? uintptr_t(value) : 0; };
    auto valueIs = [&](const char* value) { return ce::readTypedValue(proc, r.value, ce::ValueType::Int32) == value; };
    auto codeIs = [&](uint8_t byte) { uint8_t value = 0; auto result = proc.read(r.code, &value, 1); return result && *result == 1 && value == byte; };
    QTemporaryDir directory;
    QStringList errors;
    QTimer dismiss; dismiss.setInterval(5);
    QObject::connect(&dismiss, &QTimer::timeout, [&] {
        if (auto* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) {
            errors.append(box->text());
            std::printf("GUI_INJECTION_DIALOG %u: %s\n", width, box->text().toUtf8().constData());
            box->done(QMessageBox::No);
        }
    });
    dismiss.start();
    for (int scenario = 0; scenario < 14; ++scenario) {
        zero();
        const QString symbol = QString("gui_lifecycle_%1_%2").arg(width).arg(scenario);
        QString script = QString("[ENABLE]\nalloc(%1,4096)\nregistersymbol(%1)\n%2:\n%3 %1\n%4:\ndd #777\n%5:\ndb 90\n[DISABLE]\ndealloc(%1)\n")
            .arg(symbol).arg(*scratch, 0, 16).arg(width == 4 ? "dd" : "dq").arg(r.value, 0, 16).arg(r.code, 0, 16);
        if (scenario == 11) script.replace("[ENABLE]\n", "[ENABLE]\n{$lua}for i=1,256 do createMemoryRecord() end return ''{$asm}\n");
        ce::CheatTable table; ce::CheatEntry entry;
        entry.id = 41; entry.description = "Injection"; entry.autoAsmScript = script.toStdString();
        entry.active = scenario == 0; table.entries.push_back(entry);
        if (scenario == 10) {
            ce::CheatEntry group; group.id = 40; group.isGroup = true; group.description = "Group";
            table.entries[0].parentId = 40; table.entries.insert(table.entries.begin(), group);
        }
        const auto file = directory.filePath(QString("case%1.json").arg(scenario));
        if (!table.saveJson(file.toStdString())) return false;
        uintptr_t allocated = 0;
        {
            ce::gui::MainWindow main;
            main.attachToPid(fixture.pid, "injection fixture");
            main.loadTableFromPath(file);
            auto* model = main.findChild<ce::gui::AddressListModel*>();
            if (!model || !model->byId(41)) return false;
            if (scenario != 0) check(model->setActive(41, true), "manual enable succeeds");
            allocated = block();
            check(allocated && valueIs("777") && codeIs(0x90), "live target confirms the patch and mapped allocation");
            if (scenario == 0) {
                check(saved(model->entries()[0].autoAsmDisableInfo), "imported activation retains its undo ownership");
                check(model->setActive(41, false), "imported script can be disabled");
            } else if (scenario == 1) {
                QApplication::clipboard()->setText("[{\"description\":\"Pasted\",\"address\":\"0\",\"type\":\"i32\"}]");
                QMetaObject::invokeMethod(&main, "onPasteAddresses", Qt::DirectConnection);
                check(model->rowCount() == 2 && saved(model->entries()[0].autoAsmDisableInfo), "paste preserves existing injection ownership");
                check(model->setActive(41, false), "pasted table disables the existing script");
            } else if (scenario == 2) {
                check(model->deleteById(41) && !model->byId(41), "delete removes a successfully cleaned script");
            } else if (scenario == 3) {
                model->disableAllWithoutExecute();
                check(!model->byId(41)->active && saved(model->entries()[0].autoAsmDisableInfo), "flag-only disable retains pending undo");
                check(model->setActive(41, false), "inactive record still runs pending cleanup");
            } else if (scenario == 4) {
                ce::CheatTable empty; const auto replacement = directory.filePath("replacement.json");
                empty.saveJson(replacement.toStdString()); main.loadTableFromPath(replacement);
                check(model->rowCount() == 0, "replacement commits after cleaning the previous table");
            } else if (scenario == 5) {
                model->updateScriptEntryById(41, "Edited", "[ENABLE]\n[DISABLE]\n");
                check(!model->byId(41)->active && !saved(model->entries()[0].autoAsmDisableInfo), "script editing cleans the old injection first");
            } else if (scenario == 6) {
                QMetaObject::invokeMethod(&main, "onDisconnectProcess", Qt::DirectConnection);
                check(!model->byId(41)->active && !saved(model->entries()[0].autoAsmDisableInfo), "disconnect retires the old injection ownership");
            } else if (scenario == 7) {
                main.show(); check(main.close(), "normal close accepts after cleanup");
            } else if (scenario == 8) {
                Fixture other(path); auto otherReady = ready(other);
                const auto title = main.windowTitle(); const uint8_t conflict = 0xcc;
                check(proc.writeCode(r.code, &conflict, 1).has_value(), "external executable modification creates an ownership conflict");
                const auto recent = QSettings().value("recentTables");
                ce::CheatTable empty; const auto replacement = directory.filePath("conflict.json");
                empty.saveJson(replacement.toStdString()); main.loadTableFromPath(replacement);
                check(model->byId(41) && saved(model->entries()[0].autoAsmDisableInfo) && main.windowTitle() == title && QSettings().value("recentTables") == recent,
                    "failed replacement preserves the original table title recent list and undo");
                check(!model->deleteById(41) && model->byId(41).has_value(), "failed deletion preserves the record for retry");
                model->updateScriptEntryById(41, "Changed", "[ENABLE]\n[DISABLE]\n");
                check(model->byId(41) && model->entries()[0].autoAsmScript == script, "failed cleanup refuses script replacement");
                main.attachToPid(other.pid, "replacement target");
                check(main.windowTitle() == title && model->byId(41).has_value(), "failed cleanup refuses a process switch");
                main.show(); check(!main.close(), "failed cleanup refuses window close");
                const uint8_t expected = 0x90;
                check(proc.writeCode(r.code, &expected, 1).has_value(), "conflicting byte repaired on the original target");
                check(model->setActive(41, false), "repairing the conflicting byte allows cleanup retry");
                ce::os::LinuxProcessHandle otherProc(other.pid);
                check(otherReady.width == width && ce::readTypedValue(otherProc, otherReady.value, ce::ValueType::Int32) == "123456789" && other.finish(),
                    "replacement target stays untouched and exits normally");
            } else if (scenario == 9) {
                Fixture other(path); auto otherReady = ready(other);
                main.attachToPid(other.pid, "replacement target");
                check(otherReady.width == width && !model->byId(41)->active && !saved(model->entries()[0].autoAsmDisableInfo), "successful process switch cleans before rebinding");
                QMetaObject::invokeMethod(&main, "onDisconnectProcess", Qt::DirectConnection);
                check(other.finish(), "replacement process exits normally after disconnect");
            } else if (scenario == 10) {
                check(model->deleteById(40) && model->rowCount() == 0, "group deletion cleans its injected descendants");
            } else if (scenario == 11) {
                check(model->rowCount() == 257 && saved(model->entries()[model->rowOfId(41)].autoAsmDisableInfo), "actual Lua appends retain the executing record ownership");
                check(model->setActive(41, false), "Lua-expanded table can disable its script");
            } else if (scenario == 12) {
                const auto old = model->entries()[model->rowOfId(41)].autoAsmDisableInfo;
                model->disableAllWithoutExecute();
                check(model->setActive(41, true) && !old.allocs.empty() && old.allocs[0].released && old.allocs[0].released->load() &&
                    model->entries()[model->rowOfId(41)].autoAsmDisableInfo.ownership != old.ownership,
                    "flag-only disable cleans the old allocation before re-enabling");
                allocated = block();
                check(allocated && valueIs("777") && model->setActive(41, false), "re-enabled script owns one usable injection and can be disabled");
            }
            if (scenario != 13) check(valueIs("123456789") && codeIs(original) && block() == 0 && allocated && !proc.queryRegion(allocated),
                    "cleanup restores exact target bytes and releases the injected mapping");
            // Recover the deliberately broken baseline too, so each scenario is
            // independent and only these owned fixtures are ever modified.
            if (scenario != 13) {
                (void)proc.writeCode(r.code, &original, 1);
                (void)ce::writeTypedValue(proc, r.value, ce::ValueType::Int32, "123456789");
                if (model->byId(41)) model->setActive(41, false);
            }
        }
        if (scenario == 13) check(valueIs("123456789") && codeIs(original) && block() == 0 && allocated && !proc.queryRegion(allocated),
            "window destruction cleans while its borrowed process and assembler are alive");
        if (allocated && proc.queryRegion(allocated)) (void)proc.free(allocated, 4096);
        (void)proc.writeCode(r.code, &original, 1);
        (void)ce::writeTypedValue(proc, r.value, ce::ValueType::Int32, "123456789");
        zero();
    }
    {
        ce::AutoAssembler assembler;
        ce::gui::AddressListModel model; model.setProcess(&proc); model.setAutoAssembler(&assembler);
        model.addScriptEntry("Callback", QString("[ENABLE]\n%1:\ndd #777\n[DISABLE]\n").arg(r.value, 0, 16));
        const int id = model.entries()[0].id;
        bool guarded = true;
        model.setBeforeAaExecute([&] {
            guarded = guarded && !model.deleteById(id) && !model.fromJson({}) &&
                !model.setScript(id, "[ENABLE]\n[DISABLE]\n") && !model.setProcess(nullptr) && !model.setActive(id, true);
            for (int i = 0; i < 256; ++i) model.addEntry(0, ce::ValueType::Byte, "Callback appended");
        });
        check(model.setActive(id, true) && model.byId(id)->active && saved(model.entries()[model.rowOfId(id)].autoAsmDisableInfo),
            "callback appends cannot invalidate the executing record");
        check(model.setActive(id, false) && valueIs("123456789"), "callback-driven vector growth still retains usable undo");
        check(guarded, "reentrant callbacks cannot delete reset edit retarget or execute the current script");
    }
    {
        ce::AutoAssembler assembler;
        ce::gui::AddressListModel model; model.setProcess(&proc); model.setAutoAssembler(&assembler);
        auto record = [&](int id, int value, bool active) {
            return QJsonObject{{"id", id}, {"description", "Callback record"}, {"active", active},
                {"asm", QString("[ENABLE]\n%1:\ndd #%2\n[DISABLE]\n").arg(r.value, 0, 16).arg(value)}};
        };
        bool replaced = false;
        model.setActivationCallback([&](int id, bool active) {
            if (id == 1 && active) replaced = model.fromJson(QJsonArray{record(2, 888, false)});
        });
        const bool imported = model.fromJson(QJsonArray{record(1, 777, true), record(2, 888, true)});
        check(imported && replaced && model.rowCount() == 1 && model.byId(2) && !model.byId(2)->active && valueIs("123456789"),
            "activation callbacks replacing a table cannot activate reused IDs from the earlier import");
        model.setActivationCallback([&](int id, bool active) { if (active) model.deleteById(id); });
        check(model.setData(model.index(0, 0), Qt::Checked, Qt::CheckStateRole) && model.rowCount() == 0 && valueIs("123456789"),
            "checkbox callbacks can delete the completed script without stale row references");
    }
    check(proc.free(*scratch, 4096).has_value(), "fixture scratch allocation released");
    fixture.command('r'); check(fixture.line() == "123456789", "original application observes restored data");
    check(fixture.finish(), "original application exits normally after all operations");
    std::printf("GUI_INJECTION_RESULT width=%u checks=%u failures=%u\n", width, check.count, check.failures);
    return check.failures == 0;
}
bool run(const char* native64, const char* native32) {
    const bool x64 = profile(native64, 8);
    const bool x86 = profile(native32, 4);
    return x64 && x86;
}
} // namespace gui_injection_test
