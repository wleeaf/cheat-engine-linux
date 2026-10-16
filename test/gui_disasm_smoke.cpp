// Headless (offscreen Qt) smoke test for the disassembler's multi-instruction range
// selection (CE-style: Shift+Up/Down and Shift+click select a range). Decodes this
// process's own code and drives real key events. Exit 0 on success.

#include "gui/memorybrowser.hpp"
#include "arch/disassembler.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <QKeyEvent>
#include <QClipboard>
#include <QScrollBar>
#include <QSettings>
#include <QTemporaryDir>
#include <cstdio>
#include <cstdint>
#include <unistd.h>

// A function with several instructions to disassemble (kept out-of-line and doing
// real work so the compiler emits a decodable body, not a single ret).
__attribute__((noinline)) static int decodeTarget(int x) {
    volatile int a = x + 1;
    a = a * 3;
    a = a ^ 0x55;
    a = a - 7;
    a = a | 0x10;
    return a + x;
}

static void sendKey(QObject* w, int key, Qt::KeyboardModifiers mods) {
    QKeyEvent e(QEvent::KeyPress, key, mods);
    QApplication::sendEvent(w, &e);
}

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    // Preferences are written below; keep them out of the user's settings.
    QTemporaryDir config;
    if (config.isValid()) qputenv("XDG_CONFIG_HOME", config.path().toLocal8Bit());
    QApplication app(argc, argv);
    app.setOrganizationName("cecore-smoke");

    ce::os::LinuxProcessHandle proc(getpid());
    ce::gui::DisasmView dv;
    dv.setProcess(&proc);
    dv.setArch(ce::Arch::X86_64);
    dv.resize(900, 600);
    dv.show();
    app.processEvents();
    dv.setAddress(reinterpret_cast<uintptr_t>(&decodeTarget) & ~0xFULL);
    app.processEvents();

    sendKey(&dv, Qt::Key_Down, Qt::NoModifier);      // select row 0 (single)
    int single = dv.selectionCountForTest();
    uintptr_t selectionStart = dv.selectedAddress();

    sendKey(&dv, Qt::Key_Down, Qt::ShiftModifier);   // extend to row 1
    sendKey(&dv, Qt::Key_Down, Qt::ShiftModifier);   // extend to row 2
    int rangeThree = dv.selectionCountForTest();
    auto injectionRange = dv.injectionSelection();
    bool injectionSelection = injectionRange.first == selectionStart &&
        injectionRange.second == dv.selectedAddress() + dv.selectedSize() - selectionStart;

    // Ctrl+C copies every selected line as a block (3 lines -> 2 newlines).
    QApplication::clipboard()->clear();
    sendKey(&dv, Qt::Key_C, Qt::ControlModifier);
    QString clip = QApplication::clipboard()->text();
    int copiedLines = clip.isEmpty() ? 0 : clip.count('\n') + 1;

    sendKey(&dv, Qt::Key_Up, Qt::ShiftModifier);     // shrink back to rows 0..1
    int rangeTwo = dv.selectionCountForTest();

    sendKey(&dv, Qt::Key_Down, Qt::NoModifier);      // plain move collapses the range
    int collapsed = dv.selectionCountForTest();

    // Ctrl+A selects every visible instruction (more than the manual 3-line range).
    sendKey(&dv, Qt::Key_A, Qt::ControlModifier);
    int selectAll = dv.selectionCountForTest();

    // Home collapses to the first line; Shift+End extends to the last; Escape collapses.
    sendKey(&dv, Qt::Key_Home, Qt::NoModifier);
    int homeSel = dv.selectionCountForTest();          // single line
    sendKey(&dv, Qt::Key_End, Qt::ShiftModifier);
    int shiftEndSel = dv.selectionCountForTest();       // whole visible range
    sendKey(&dv, Qt::Key_Escape, Qt::NoModifier);
    int escSel = dv.selectionCountForTest();            // collapsed back to one

    // Double-click / activate a plain instruction opens the assembler on it (CE edits an
    // instruction in place). decodeTarget's body is branch-free, so activating a row
    // emits requestAssemble (rather than following a branch/data target).
    dv.setAddress(reinterpret_cast<uintptr_t>(&decodeTarget) & ~0xFULL);
    app.processEvents();
    uintptr_t asmAddr = 0; int asmSize = 0;
    QObject::connect(&dv, &ce::gui::DisasmView::requestAssemble,
        [&](uintptr_t a, int sz, const QString&) { asmAddr = a; asmSize = sz; });
    dv.activateRowForTest(2);
    bool dblAssemble = (asmAddr != 0 && asmSize > 0 && asmSize <= 15);

    // Selection stays anchored to its instruction address across a scroll (CE-style):
    // select an instruction, scroll down, and the same address stays selected until it
    // leaves the view, at which point the selection clears.
    dv.setAddress(reinterpret_cast<uintptr_t>(&decodeTarget) & ~0xFULL);
    app.processEvents();
    sendKey(&dv, Qt::Key_Home, Qt::NoModifier);   // cursor to row 0
    sendKey(&dv, Qt::Key_Down, Qt::NoModifier);   // row 1
    sendKey(&dv, Qt::Key_Down, Qt::NoModifier);   // row 2
    uintptr_t selAddrBefore = dv.selectedAddress();
    dv.scrollRowsForTest(2);                        // scroll down 2 instructions
    bool scrollAnchored = (selAddrBefore != 0 && dv.selectedAddress() == selAddrBefore
                           && dv.selectionCountForTest() == 1);
    dv.scrollRowsForTest(100);                       // push the selection well off the top
    bool scrollCleared = (dv.selectionCountForTest() == 0);
    bool disasmSticky = scrollAnchored && scrollCleared;
    dv.setAddress(reinterpret_cast<uintptr_t>(&decodeTarget));
    dv.setComment(dv.currentAddress(), std::string(300, 'X'));
    for (int i = 0; i < 4; ++i) { dv.viewport()->repaint(); app.processEvents(); }
    bool horizontal = dv.horizontalScrollBar()->maximum() > 0;
    std::printf("GUI disassembly horizontal scrolling: %s\n", horizontal ? "OK" : "FAILED");

    // Space between lines (Disassembler Preferences) makes every row taller,
    // so fewer instructions fit the same view.
    bool spacing = false;
    if (config.isValid()) {
        { QSettings s; s.setValue("disasm/spaceAbove", 6); s.setValue("disasm/spaceBelow", 6); }
        dv.setAddress(reinterpret_cast<uintptr_t>(&decodeTarget) & ~0xFULL);
        dv.reloadPreferences();
        app.processEvents();
        sendKey(&dv, Qt::Key_A, Qt::ControlModifier);
        const int spacedAll = dv.selectionCountForTest();
        spacing = spacedAll > 0 && spacedAll < selectAll;
        std::printf("GUI disassembly line spacing preference: %s (%d rows, %d before)\n",
                    spacing ? "OK" : "FAILED", spacedAll, selectAll);
    }

    // PageDown with no whole row visible must not index before the first instruction.
    // The view asks for 8 rows, but the viewer's splitter can collapse it below that.
    dv.setMinimumHeight(0);
    dv.resize(900, 1);
    app.processEvents();
    const uintptr_t beforePage = dv.currentAddress();
    sendKey(&dv, Qt::Key_PageDown, Qt::NoModifier);
    bool pageDownEmpty = dv.currentAddress() == beforePage;
    std::printf("GUI disassembly PageDown with no visible rows: %s (viewport %d px)\n",
                pageDownEmpty ? "OK" : "FAILED", dv.viewport()->height());

    // Comments reach the owner's store one edit at a time (two viewers share it), and
    // a viewer whose target went away saves nothing and no longer reaches the owner's
    // breakpoint or run controls, which would act on the next target.
    bool annotations = false;
    {
        ce::gui::MemoryBrowser mb(&proc);
        std::vector<ce::gui::MemoryBrowser::AnnotationChange> changes;
        mb.setAnnotationStore({}, [&](const ce::gui::MemoryBrowser::AnnotationChange& c) { changes.push_back(c); });
        const uintptr_t at = reinterpret_cast<uintptr_t>(&decodeTarget);
        mb.gotoAddress(at);
        mb.setCommentForTest(at, "first");
        const bool oneEdit = changes.size() == 1 && changes[0].address == at && !changes[0].label &&
                             changes[0].text == "first" && changes[0].expression.find('+') != std::string::npos;
        int bpSets = 0, runs = 0;
        mb.setBreakpointSetter([&](uintptr_t, bool) { ++bpSets; });
        mb.setStepControls([] {}, [] {}, [&] { ++runs; });
        mb.triggerDebugActionForTest("Toggle breakpoint");
        const bool wiredBefore = bpSets == 1;
        mb.detachFromTarget();
        mb.setCommentForTest(at, "after exit");
        mb.triggerDebugActionForTest("Toggle breakpoint");
        mb.triggerDebugActionForTest("Run");
        annotations = oneEdit && wiredBefore && changes.size() == 1 && bpSets == 1 && runs == 0;
        std::printf("GUI memory viewer single-edit comments and detach: %s (edit=%d wired=%d changes=%zu bp=%d run=%d)\n",
                    annotations ? "OK" : "FAILED", oneEdit, wiredBefore, changes.size(), bpSets, runs);
    }

    bool ok = annotations && pageDownEmpty && spacing && horizontal && injectionSelection && single == 1 && rangeThree == 3 && rangeTwo == 2 && collapsed == 1
           && copiedLines == 3 && selectAll > 3
           && homeSel == 1 && shiftEndSel == selectAll && escSel == 1 && dblAssemble && disasmSticky;
    printf("gui disasm smoke: %s (single=%d range3=%d range2=%d collapsed=%d copiedLines=%d "
           "selectAll=%d home=%d shiftEnd=%d esc=%d dblAssemble=%d disasmSticky=%d)\n",
           ok ? "OK" : "FAILED", single, rangeThree, rangeTwo, collapsed, copiedLines,
           selectAll, homeSel, shiftEndSel, escSel, (int)dblAssemble, (int)disasmSticky);
    return ok ? 0 : 1;
}
