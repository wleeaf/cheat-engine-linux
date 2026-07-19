// Headless (offscreen Qt) smoke test for the Structure Dissector's compare mode
// (CE Dissect Data side-by-side): two structs identical except at one offset must
// produce one value column per instance, with the differing cell coloured and the
// equal cells not. Reads this process's own memory, so no fork/ptrace is needed.
// Exit 0 on success.

#include "gui/structuredissector.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <unistd.h>

static uint8_t g_a[64];
static uint8_t g_b[64];

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");

    // Two "structs" identical except for the int32 field at offset 0x10.
    std::memset(g_a, 0, sizeof g_a);
    std::memset(g_b, 0, sizeof g_b);
    uint32_t va = 0x11111111u, vb = 0x22222222u;
    std::memcpy(g_a + 16, &va, 4);
    std::memcpy(g_b + 16, &vb, 4);
    uint32_t equalField = 7;                 // offset 0x28: same in both
    std::memcpy(g_a + 40, &equalField, 4);
    std::memcpy(g_b + 40, &equalField, 4);

    QApplication app(argc, argv);
    ce::os::LinuxProcessHandle proc(getpid());
    ce::gui::StructureDissector diss(&proc, reinterpret_cast<uintptr_t>(g_a));
    diss.resize(800, 600);
    diss.show();
    app.processEvents();

    // Single-struct mode: a value that changes between refreshes is flagged (live-change
    // highlight). Flip the field at offset 0x18 (row 3), refresh, and check only it lit.
    g_a[24] ^= 0xFFu;
    diss.refreshNowForTest();
    bool changedRow3 = diss.rowValueChangedForTest(3);
    bool changedRow0 = diss.rowValueChangedForTest(0);

    // Enter compare mode against the second struct.
    diss.setCompareAddressesForTest({ reinterpret_cast<uintptr_t>(g_b) });
    app.processEvents();

    int cols = diss.columnCountForTest();          // Offset, Name, Base, 0x<g_b>
    bool diffAt0x10 = diss.cellDiffColoredForTest(2, 3);   // row 2 = offset 0x10 differs
    bool sameAt0x00 = diss.cellDiffColoredForTest(0, 3);   // row 0 = offset 0x00 equal
    bool sameAt0x28 = diss.cellDiffColoredForTest(5, 3);   // row 5 = offset 0x28 equal

    bool ok = cols == 4 && diffAt0x10 && !sameAt0x00 && !sameAt0x28
           && changedRow3 && !changedRow0;
    printf("gui structdissect smoke: %s (cols=%d diff@0x10=%d same@0x00=%d same@0x28=%d "
           "changed@0x18=%d changed@0x00=%d)\n",
           ok ? "OK" : "FAILED", cols, diffAt0x10, sameAt0x00, sameAt0x28, changedRow3, changedRow0);
    return ok ? 0 : 1;
}
