#include "gui/scripteditor.hpp"
#include "gui/codefinder.hpp"
#include <QAction>
#include <QPointer>

namespace gui_editor_injection_test {
using gui_injection_test::Fixture;
using gui_injection_test::ready;
struct Checks {
    unsigned width, count = 0, failures = 0;
    void operator()(bool ok, const char* name) {
        ++count; failures += !ok;
        std::printf("GUI_EDITOR_INJECTION %u %s: %s\n", width, ok ? "OK" : "FAILED", name);
    }
};
bool invoke(QObject& object, const char* method) {
    return QMetaObject::invokeMethod(&object, method, Qt::DirectConnection);
}
QAction* action(QObject& editor, const QString& name) {
    for (auto* candidate : editor.findChildren<QAction*>()) if (candidate->text() == name) return candidate;
    return nullptr;
}
bool profile(const char* path, unsigned width) {
    Checks check{width}; Fixture fixture(path); const auto r = ready(fixture);
    check(r.width == width, "owned editor fixture starts with the required ABI");
    if (r.width != width) return false;
    ce::os::LinuxProcessHandle proc(fixture.pid); ce::AutoAssembler assembler;
    uint8_t original = 0;
    const auto read = proc.read(r.code, &original, 1);
    const auto scratch = proc.allocate(4096, ce::MemProt::ReadWrite);
    check(read && *read == 1 && scratch.has_value(), "editor fixture has real code and owned scratch memory");
    if (!read || !scratch) return false;
    auto block = [&] { uint64_t value = 0; const auto result = proc.read(*scratch, &value, width); return result && *result == width ? uintptr_t(value) : 0; };
    auto codeIs = [&](uint8_t expected) { uint8_t value = 0; const auto result = proc.read(r.code, &value, 1); return result && *result == 1 && value == expected; };
    auto valueIs = [&](const char* value) { return ce::readTypedValue(proc, r.value, ce::ValueType::Int32) == value; };
    auto restored = [&](uintptr_t allocation) { return allocation && valueIs("123456789") && codeIs(original) && block() == 0 && !proc.queryRegion(allocation); };
    for (int scenario = 0; scenario < 11; ++scenario) {
        const uint64_t zero = 0; (void)proc.write(*scratch, &zero, width);
        const QString symbol = QString("gui_editor_%1_%2").arg(width).arg(scenario);
        std::string script = QString("[ENABLE]\nalloc(%1,4096)\nregistersymbol(%1)\n%2:\n%3 %1\n%4:\ndd #777\n%5:\ndb 90\n[DISABLE]\ndealloc(%1)\n")
            .arg(symbol).arg(*scratch, 0, 16).arg(width == 4 ? "dd" : "dq").arg(r.value, 0, 16).arg(r.code, 0, 16).toStdString();
        QPointer<ce::gui::ScriptEditor> editor;
        std::unique_ptr<ce::gui::MainWindow> main;
        if (scenario >= 4) {
            main = std::make_unique<ce::gui::MainWindow>(); main->attachToPid(fixture.pid, "editor fixture");
            for (auto* item : main->findChildren<QAction*>()) if (item->text() == "Auto Assemble...") { item->trigger(); break; }
            editor = main->findChild<ce::gui::ScriptEditor*>();
        } else editor = new ce::gui::ScriptEditor(&proc, &assembler);
        check(!editor.isNull(), "editor opens with its original process context");
        if (!editor) return false;
        std::unique_ptr<Fixture> alternate;
        bool switchRefused = false, nestedRefused = false;
        ce::gui::AddressListModel* nestedModel = nullptr;
        if (scenario == 9) {
            alternate = std::make_unique<Fixture>(path);
            check(ready(*alternate).width == width, "reentrant replacement target starts");
            nestedModel = main->findChild<ce::gui::AddressListModel*>();
            nestedModel->addScriptEntry("Nested", QString("[ENABLE]\n%1:\ndd #888\n[DISABLE]\n").arg(r.value, 0, 16));
            const auto title = main->windowTitle();
            bool* nestedResult = &nestedRefused;
            editor->setBeforeExecute([&, title, nestedResult] {
                if (!switchRefused) {
                    main->attachToPid(alternate->pid, "refused reentrant replacement");
                    switchRefused = editor && main->windowTitle() == title;
                    *nestedResult = !nestedModel->setActive(nestedModel->entries()[0].id, true);
                }
            });
            script.insert(script.find('\n') + 1,
                "{$lua}local m=getAddressList():getMemoryRecord(0); m.Active=true; assert(not m.Active,'nested assembly must remain inactive'); return ''{$asm}\n");
        }
        editor->setScript(script); invoke(*editor, "onExecute");
        uintptr_t allocation = block();
        check(allocation && valueIs("777") && codeIs(0x90), "the live target confirms editor injection bytes and allocation");
        if (scenario == 0) {
            check(editor->close(), "editor close accepts after successful cleanup");
            check(restored(allocation), "editor close restores bytes and frees its mapping");
        } else if (scenario == 1) {
            invoke(*editor, "onExecute");
            check(block() == allocation && proc.queryRegion(allocation).has_value(), "repeated direct execute preserves the existing owner instead of allocating twice");
            invoke(*editor, "onDisable");
            check(restored(allocation), "disable after repeated execute still restores the original target");
        } else if (scenario == 2) {
            editor->setScript("[ENABLE]\nbreak edited script must not run\n[DISABLE]\n");
            invoke(*editor, "onDisable");
            check(restored(allocation), "editing displayed text retains usable undo for the original script");
            check(editor->close(), "edited inactive editor closes normally");
        } else if (scenario == 3) {
            const uint8_t conflict = 0xcc; (void)proc.writeCode(r.code, &conflict, 1);
            editor->show(); check(!editor->close(), "code ownership conflict refuses editor close");
            auto* disable = action(*editor, "Disable"); auto* execute = action(*editor, "Execute");
            check(disable && disable->isEnabled() && execute && !execute->isEnabled() && codeIs(conflict), "failed close retains an enabled cleanup action and the conflicting byte");
            const uint8_t expected = 0x90; (void)proc.writeCode(r.code, &expected, 1);
            check(editor->close() && restored(allocation), "repair permits editor close and complete cleanup");
        } else if (scenario == 4) {
            Fixture other(path); const auto otherReady = ready(other);
            main->attachToPid(other.pid, "editor replacement");
            check(editor.isNull() && restored(allocation), "process switch cleans an editor before retiring its process handle");
            ce::os::LinuxProcessHandle otherProc(other.pid);
            check(otherReady.width == width && ce::readTypedValue(otherProc, otherReady.value, ce::ValueType::Int32) == "123456789", "replacement process receives no old editor cleanup writes");
            invoke(*main, "onDisconnectProcess"); check(other.finish(), "replacement process exits normally after successful switch");
        } else if (scenario == 5) {
            const auto title = main->windowTitle(); const uint8_t conflict = 0xcc;
            (void)proc.writeCode(r.code, &conflict, 1);
            Fixture other(path); const auto otherReady = ready(other);
            main->attachToPid(other.pid, "refused editor replacement");
            check(editor && main->windowTitle() == title && codeIs(conflict), "failed editor cleanup preserves its window and original process on switch");
            if (editor) invoke(*editor, "onExecute");
            check(block() == allocation, "pending editor recovery cannot be overwritten by another execute");
            const uint8_t expected = 0x90; (void)proc.writeCode(r.code, &expected, 1);
            invoke(*main, "onDisconnectProcess");
            check(editor.isNull() && restored(allocation), "repair permits disconnect and editor cleanup against the original target");
            check(otherReady.width == width && other.finish(), "refused replacement target still exits normally");
        } else if (scenario == 6) {
            invoke(*main, "onDisconnectProcess");
            check(editor.isNull() && restored(allocation), "disconnect restores editor code and frees allocation before deleting the editor");
        } else if (scenario == 7) {
            const uint8_t conflict = 0xcc; (void)proc.writeCode(r.code, &conflict, 1);
            main->show(); check(!main->close() && editor, "failed editor cleanup refuses main-window close");
            const uint8_t expected = 0x90; (void)proc.writeCode(r.code, &expected, 1);
            check(main->close() && editor.isNull() && restored(allocation), "repair permits main-window close and editor retirement");
        } else if (scenario == 8) {
            main.reset(); check(editor.isNull() && restored(allocation), "main-window destruction cleans editor undo while dependencies remain alive");
        } else if (scenario == 9) {
            check(switchRefused && nestedRefused && nestedModel && !nestedModel->entries()[0].active,
                "shared GUI assembler rejects reentrant target changes and nested record execution from hooks and actual Lua");
            check(main->close() && editor.isNull() && restored(allocation), "guarded editor execution retains its original process and complete undo");
            check(alternate->finish(), "reentrant replacement target remains live and exits normally");
        } else {
            const uint8_t conflict = 0xcc; (void)proc.writeCode(r.code, &conflict, 1);
            main->startFindWritesForTest(r.value);
            QPointer<ce::gui::CodeFinderWindow> monitor = main->findChild<ce::gui::CodeFinderWindow*>();
            check(!monitor.isNull(), "real CodeFinder monitor opens alongside an active editor injection");
            const auto title = main->windowTitle();
            Fixture other(path); const auto otherReady = ready(other);
            main->attachToPid(other.pid, "refused monitored replacement");
            check(editor && monitor.isNull() && main->windowTitle() == title && codeIs(conflict),
                "failed cleanup stops and destroys monitor windows while their borrowed finder remains alive");
            const uint8_t expected = 0x90; (void)proc.writeCode(r.code, &expected, 1);
            check(main->close() && editor.isNull() && restored(allocation), "monitor retirement and repaired editor cleanup release both target owners");
            check(otherReady.width == width && other.finish(), "monitored replacement target exits normally without receiving cleanup writes");
        }
        // Recover the old implementation too, keeping scenarios independent.
        if (editor) {
            const uint8_t expected = 0x90;
            if (!restored(allocation)) (void)proc.writeCode(r.code, &expected, 1);
            invoke(*editor, "onDisable"); delete editor.data();
        }
        main.reset();
        if (allocation && proc.queryRegion(allocation)) (void)proc.free(allocation, 4096);
        const auto latest = block();
        if (latest && latest != allocation && proc.queryRegion(latest)) (void)proc.free(latest, 4096);
        (void)proc.writeCode(r.code, &original, 1);
        (void)ce::writeTypedValue(proc, r.value, ce::ValueType::Int32, "123456789");
        (void)proc.write(*scratch, &zero, width);
    }
    {
        ce::gui::ScriptEditor editor(&proc, &assembler);
        ce::gui::ScriptEditor other(&proc, &assembler);
        const auto script = QString("[ENABLE]\n%1:\ndd #777\n[DISABLE]\n").arg(r.value, 0, 16).toStdString();
        bool refusedClose = false, nestedAttempted = false, otherRefused = false;
        other.setScript(script);
        editor.setBeforeExecute([&] {
            if (!nestedAttempted) {
                nestedAttempted = true; refusedClose = !editor.close(); invoke(editor, "onExecute");
                invoke(other, "onExecute"); invoke(other, "onCheck");
                const auto* console = other.findChild<QTextEdit*>();
                otherRefused = console && console->toPlainText().isEmpty();
            }
        });
        editor.setScript(script); invoke(editor, "onExecute");
        check(nestedAttempted && refusedClose && otherRefused && valueIs("777"), "before-execute callback cannot close or recursively execute its own or another editor");
        invoke(editor, "onDisable"); check(valueIs("123456789"), "guarded callback execution retains correct cleanup ownership");
    }
    for (int scenario = 0; scenario < 7; ++scenario) {
        const uint64_t zero = 0;
        (void)proc.write(*scratch, &zero, 8); (void)proc.write(*scratch + 16, &zero, 8);
        ce::gui::MainWindow main; main.attachToPid(fixture.pid, "stacked editor fixture");
        auto* model = main.findChild<ce::gui::AddressListModel*>();
        auto makeScript = [&](int layer) {
            const QString name = QString("gui_stack_%1_%2_%3").arg(width).arg(scenario).arg(layer);
            return QString("[ENABLE]\nalloc(%1,4096)\nregistersymbol(%1)\n%2:\n%3 %1\n%4:\ndd #%5\n%6:\ndb %7\n[DISABLE]\ndealloc(%1)\n")
                .arg(name).arg(*scratch + layer * 16, 0, 16).arg(width == 4 ? "dd" : "dq").arg(r.value, 0, 16)
                .arg(layer ? 888 : 777).arg(r.code, 0, 16).arg(layer ? "91" : "90");
        };
        auto createEditor = [&] {
            for (auto* item : main.findChildren<QAction*>()) if (item->text() == "Auto Assemble...") { item->trigger(); break; }
            const auto editors = main.findChildren<ce::gui::ScriptEditor*>();
            return QPointer<ce::gui::ScriptEditor>(editors.isEmpty() ? nullptr : editors.back());
        };
        auto readSlot = [&](int slot) { uint64_t value = 0; const auto result = proc.read(*scratch + slot * 16, &value, width); return result && *result == width ? uintptr_t(value) : 0; };
        QPointer<ce::gui::ScriptEditor> first, second;
        int firstId = -1, secondId = -1, groupId = -1;
        if (scenario == 0) {
            first = createEditor(); first->setScript(makeScript(0).toStdString()); invoke(*first, "onExecute");
            model->addScriptEntry("Second record", makeScript(1)); secondId = model->entries().back().id;
        } else if (scenario == 1) {
            model->addScriptEntry("First record", makeScript(0)); firstId = model->entries().back().id;
            model->setActive(firstId, true);
            second = createEditor(); second->setScript(makeScript(1).toStdString());
        } else if (scenario == 2) {
            second = createEditor(); first = createEditor();
            first->setScript(makeScript(0).toStdString()); second->setScript(makeScript(1).toStdString());
            invoke(*first, "onExecute");
        } else {
            if (scenario == 4) { groupId = model->createGroup("Injected children"); model->setActive(groupId, true); }
            model->addScriptEntry("First record", makeScript(0)); firstId = model->entries().back().id;
            model->addScriptEntry("Second record", makeScript(1)); secondId = model->entries().back().id;
            if (scenario == 4) { model->setIndent(firstId, 1); model->setIndent(secondId, 1); }
            model->setActive(firstId, true);
        }
        const auto firstAllocation = readSlot(0);
        if (second) invoke(*second, "onExecute"); else model->setActive(secondId, true);
        const auto secondAllocation = readSlot(1);
        check(firstAllocation && secondAllocation && firstAllocation != secondAllocation && valueIs("888") && codeIs(0x91),
            "two independent owners patch the same executable byte and own distinct mappings");
        if (scenario == 3) {
            model->moveEntryBlock(model->rowOfId(secondId), 0);
            model->setAllActive(false);
        } else if (scenario == 4) {
            check(model->setData(model->index(model->rowOfId(groupId), 0), Qt::Unchecked, Qt::CheckStateRole),
                "group deactivation unwinds overlapping children before clearing the group flag");
        } else if (scenario == 5) {
            check(model->removeEntries({model->rowOfId(firstId), model->rowOfId(secondId)}) && model->rowCount() == 0,
                "multi-row deletion unwinds overlapping records in reverse activation order");
        } else if (scenario == 6) {
            check(model->fromJson({}) && model->rowCount() == 0, "table replacement unwinds overlapping owners before committing empty rows");
        } else invoke(main, "onDisconnectProcess");
        check(valueIs("123456789") && codeIs(original) && readSlot(0) == 0 && readSlot(1) == 0 &&
            !proc.queryRegion(firstAllocation) && !proc.queryRegion(secondAllocation),
            "cleanup order follows activation ownership across editors records and row reordering");
        invoke(main, "onDisconnectProcess");
    }
    {
        Fixture exiting(path); const auto old = ready(exiting);
        ce::gui::MainWindow main; main.attachToPid(exiting.pid, "exiting editor fixture");
        for (auto* item : main.findChildren<QAction*>()) if (item->text() == "Auto Assemble...") { item->trigger(); break; }
        QPointer<ce::gui::ScriptEditor> editor = main.findChild<ce::gui::ScriptEditor*>();
        if (!editor) return false;
        editor->setScript(QString("[ENABLE]\n%1:\ndd #777\n[DISABLE]\n").arg(old.value, 0, 16).toStdString());
        invoke(*editor, "onExecute");
        ce::os::LinuxProcessHandle oldProc(exiting.pid);
        check(old.width == width && ce::readTypedValue(oldProc, old.value, ce::ValueType::Int32) == "777" && exiting.finish(),
            "an injected original process can exit normally before editor cleanup");
        Fixture replacement(path); const auto next = ready(replacement);
        main.attachToPid(replacement.pid, "after exiting editor fixture");
        ce::os::LinuxProcessHandle replacementProc(replacement.pid);
        check(editor.isNull() && next.width == width && ce::readTypedValue(replacementProc, next.value, ce::ValueType::Int32) == "123456789",
            "retired editor undo cannot write into the replacement application's reused virtual addresses");
        invoke(main, "onDisconnectProcess"); check(replacement.finish(), "replacement remains live and exits normally after retiring dead-target undo");
    }
    check(proc.free(*scratch, 4096).has_value(), "editor fixture scratch mapping is released");
    fixture.command('r'); check(fixture.line() == "123456789", "the original program observes restored data after editor operations");
    check(fixture.finish(), "the original program exits normally after editor operations");
    std::printf("GUI_EDITOR_INJECTION_RESULT width=%u checks=%u failures=%u\n", width, check.count, check.failures);
    return check.failures == 0;
}
bool run(const char* native64, const char* native32) {
    const bool x64 = profile(native64, 8); const bool x86 = profile(native32, 4);
    return x64 && x86;
}
} // namespace gui_editor_injection_test
