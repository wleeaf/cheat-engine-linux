// Headless (offscreen Qt) smoke test for the disassembler's multi-instruction range
// selection (CE-style: Shift+Up/Down and Shift+click select a range). Decodes this
// process's own code and drives real key events. Exit 0 on success.

#include "gui/memorybrowser.hpp"
#include "arch/disassembler.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <QKeyEvent>
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

    sendKey(&dv, Qt::Key_Up, Qt::ShiftModifier);     // shrink back to rows 0..1
    int rangeTwo = dv.selectionCountForTest();

    sendKey(&dv, Qt::Key_Down, Qt::NoModifier);      // plain move collapses the range
    int collapsed = dv.selectionCountForTest();

    bool ok = single == 1 && rangeThree == 3 && rangeTwo == 2 && collapsed == 1;
    printf("gui disasm smoke: %s (single=%d range3=%d range2=%d collapsed=%d)\n",
           ok ? "OK" : "FAILED", single, rangeThree, rangeTwo, collapsed);
    return ok ? 0 : 1;
}
