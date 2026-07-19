// Headless (offscreen Qt) smoke test for the Memory Viewer hex pane's changed-byte
// highlight (CE-style: bytes that change between refreshes paint red). Reads this
// process's own memory; mutates one byte between two refreshes and checks exactly
// that byte is flagged changed. Exit 0 on success.

#include "gui/memorybrowser.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <unistd.h>

alignas(16) static uint8_t g_buf[512];

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    std::memset(g_buf, 0xA5, sizeof g_buf);

    QApplication app(argc, argv);
    ce::os::LinuxProcessHandle proc(getpid());
    ce::gui::HexView hv;
    hv.setProcess(&proc);
    hv.resize(700, 400);
    hv.show();
    app.processEvents();

    hv.setAddress(reinterpret_cast<uintptr_t>(g_buf));   // refresh #1 (baseline)
    hv.refresh();                                        // baseline, same address
    int baseline = hv.changedByteCountForTest();         // must be 0 (nothing changed yet)

    g_buf[8] = 0x5A;                                     // flip one byte
    hv.refresh();                                        // refresh #2: byte 8 differs
    int afterOne = hv.changedByteCountForTest();

    // Navigating to a different address must reset the baseline (no false "changed").
    alignas(16) static uint8_t other[64];
    std::memset(other, 0, sizeof other);
    hv.setAddress(reinterpret_cast<uintptr_t>(other));
    int afterNav = hv.changedByteCountForTest();

    // Paste an AOB with a wildcard: patch g_buf at the cursor; "??" leaves that byte.
    hv.setAddress(reinterpret_cast<uintptr_t>(g_buf));
    g_buf[0] = 0x11; g_buf[1] = 0x22; g_buf[2] = 0x33;
    int wrote = hv.pasteBytes("aa ?? cc");
    bool pasteOk = (wrote == 2 && g_buf[0] == 0xaa && g_buf[1] == 0x22 && g_buf[2] == 0xcc);

    bool ok = baseline == 0 && afterOne == 1 && afterNav == 0 && pasteOk;
    printf("gui hexview smoke: %s (baseline=%d afterOneFlip=%d afterNav=%d pasteWrote=%d pasteOk=%d)\n",
           ok ? "OK" : "FAILED", baseline, afterOne, afterNav, wrote, pasteOk);
    return ok ? 0 : 1;
}
