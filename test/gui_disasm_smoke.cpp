// Headless (offscreen Qt) smoke test for the disassembler's multi-instruction range
// selection (CE-style: Shift+Up/Down and Shift+click select a range). Decodes this
// process's own code and drives real key events. Exit 0 on success.

#include "gui/memorybrowser.hpp"
#include "arch/disassembler.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <QKeyEvent>
#include <QClipboard>
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
    QApplication app(argc, argv);

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

    sendKey(&dv, Qt::Key_Down, Qt::ShiftModifier);   // extend to row 1
    sendKey(&dv, Qt::Key_Down, Qt::ShiftModifier);   // extend to row 2
    int rangeThree = dv.selectionCountForTest();

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

    bool ok = single == 1 && rangeThree == 3 && rangeTwo == 2 && collapsed == 1
           && copiedLines == 3 && selectAll > 3
           && homeSel == 1 && shiftEndSel == selectAll && escSel == 1 && dblAssemble && disasmSticky;
    printf("gui disasm smoke: %s (single=%d range3=%d range2=%d collapsed=%d copiedLines=%d "
           "selectAll=%d home=%d shiftEnd=%d esc=%d dblAssemble=%d disasmSticky=%d)\n",
           ok ? "OK" : "FAILED", single, rangeThree, rangeTwo, collapsed, copiedLines,
           selectAll, homeSel, shiftEndSel, escSel, (int)dblAssemble, (int)disasmSticky);
    return ok ? 0 : 1;
}
