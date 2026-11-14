// Headless (offscreen Qt) smoke test for the find-what-writes/accesses results window
// (CodeFinderWindow). Exercises the two CE per-result actions added to it: "Show in the
// disassembler" (fires the hook with the row's address) and "Replace with code that does
// nothing (NOP)" (overwrites the instruction with 0x90). Operates on this process's own
// memory, so no fork/ptrace is needed. Exit 0 on success.

#include "gui/codefinder.hpp"
#include "gui/changedaddresses.hpp"
#include "debug/code_finder.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <QRegularExpression>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <csignal>
#include <sys/wait.h>

#ifdef __x86_64__
// One instruction with a memory operand at a known address: the Changed
// Addresses window watches it touch three different integers.
extern "C" void cf_touch(volatile int* p);
asm(".text\n.globl cf_touch\n.type cf_touch,@function\ncf_touch:\n  addl $1, (%rdi)\n  ret\n");
static volatile int g_touched[3];
#endif

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

    // "Restore with original code": writes the saved original bytes back over the NOPs.
    bool restored = win.restoreInstructionForTest(codeAddr);
    bool restoreBytes = (g_code[0] == 0xB8 && g_code[1] == 0x01 && g_code[2] == 0x00 &&
                         g_code[3] == 0x00 && g_code[4] == 0x00 && g_code[5] == 0xCC);
    bool restoreOk = restored && restoreBytes;

    // Changed Addresses: a child runs cf_touch on three integers; the window
    // lists all three with their values, and the Commonality scanner finds the
    // register (RDI) that tells one of them from another.
    bool changedOk = true;
#ifdef __x86_64__
    {
        const pid_t child = fork();
        if (child == 0) {
            for (unsigned i = 0;; ++i) { cf_touch(&g_touched[i % 3]); usleep(2000); }
        }
        ce::os::LinuxProcessHandle target(child);
        const auto instruction = reinterpret_cast<uintptr_t>(&cf_touch);
        auto* changed = new ce::gui::ChangedAddressesWindow(&target, instruction);
        const bool listed = changed->waitForAddressesForTest(3, 8000);
        const bool rows = changed->rowCountForTest() == 3;
        bool values = rows;
        for (int row = 0; values && row < 3; ++row) {
            bool number = false;
            changed->valueTextForTest(row).toLongLong(&number);
            values = number;
        }
        const auto a = reinterpret_cast<uintptr_t>(&g_touched[0]);
        const auto b = reinterpret_cast<uintptr_t>(&g_touched[1]);
        const QStringList common = changed->commonalitiesForTest({a}, {b});
        const bool commonality = common.filter(QRegularExpression("^RDI ")).size() == 1;
        changed->stop();
        delete changed;
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        changedOk = listed && rows && values && commonality;
        printf("gui changed addresses: %s (listed=%d rows=%d values=%d commonality=%d [%s])\n",
               changedOk ? "OK" : "FAILED", listed, rows, values, commonality,
               common.join(", ").toUtf8().constData());
    }
#endif

    bool ok = showOk && nopOk && restoreOk && changedOk;
    printf("gui codefinder smoke: %s (show=%d nopped=%d nopBytes=%d restored=%d restoreBytes=%d changed=%d)\n",
           ok ? "OK" : "FAILED", (int)showOk, (int)nopped, (int)nopBytes,
           (int)restored, (int)restoreBytes, (int)changedOk);
    return ok ? 0 : 1;
}
