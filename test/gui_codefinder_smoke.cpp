// Headless (offscreen Qt) smoke test for the find-what-writes/accesses results window
// (CodeFinderWindow). Exercises the two CE per-result actions added to it: "Show in the
// disassembler" (fires the hook with the row's address) and "Replace with code that does
// nothing (NOP)" (overwrites the instruction with 0x90). Operates on this process's own
// memory, so no fork/ptrace is needed. Exit 0 on success.

#include "gui/codefinder.hpp"
#include "debug/code_finder.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <unistd.h>

// A decodable instruction to patch: `mov eax, 1` (B8 01 00 00 00, 5 bytes), then filler.
alignas(16) static uint8_t g_code[32];

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    std::memset(g_code, 0xCC, sizeof g_code);
    g_code[0] = 0xB8; g_code[1] = 0x01; g_code[2] = 0x00; g_code[3] = 0x00; g_code[4] = 0x00;

    QApplication app(argc, argv);
    ce::os::LinuxProcessHandle proc(getpid());
    ce::CodeFinder finder;                       // empty results; we drive the actions directly
    ce::gui::CodeFinderWindow win(&finder, "find what writes", &proc);
    win.resize(800, 400);
    win.show();
    app.processEvents();

    uintptr_t codeAddr = reinterpret_cast<uintptr_t>(g_code);

    // "Show in the disassembler" fires the hook with the row's instruction address.
    uintptr_t shown = 0;
    win.setShowInDisassembler([&](uintptr_t a) { shown = a; });
    win.showInDisassemblerForTest(codeAddr);
    bool showOk = (shown == codeAddr);

    // "Replace with code that does nothing (NOP)": mov eax,1 (5 bytes) -> five 0x90,
    // leaving the following byte (0xCC) untouched.
    bool nopped = win.nopInstructionForTest(codeAddr);
    bool nopBytes = (g_code[0] == 0x90 && g_code[1] == 0x90 && g_code[2] == 0x90 &&
                     g_code[3] == 0x90 && g_code[4] == 0x90 && g_code[5] == 0xCC);
    bool nopOk = nopped && nopBytes;

    bool ok = showOk && nopOk;
    printf("gui codefinder smoke: %s (show=%d nopped=%d nopBytes=%d)\n",
           ok ? "OK" : "FAILED", (int)showOk, (int)nopped, (int)nopBytes);
    return ok ? 0 : 1;
}
