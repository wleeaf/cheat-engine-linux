// Headless (offscreen Qt) smoke test for the Memory Viewer's wildcard AOB search:
// a "??" wildcard in the pattern matches any byte, an exact pattern does not.
// Searches this process's own memory. Exit 0 on success.

#include "gui/memorybrowser.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <unistd.h>

// A distinctive 6-byte needle unlikely to occur elsewhere.
static volatile uint8_t g_needle[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);

    ce::os::LinuxProcessHandle proc(getpid());
    ce::gui::MemoryBrowser browser(&proc);
    const uintptr_t at = reinterpret_cast<uintptr_t>(const_cast<uint8_t*>(g_needle));

    // Wildcard at index 1 (the 0xAD byte) still matches g_needle.
    std::vector<uint8_t> wpat = {0xDE, 0x00, 0xBE, 0xEF, 0xCA, 0xFE};
    std::vector<char>    wmask = {1, 0, 1, 1, 1, 1};
    uintptr_t wildHit = browser.searchMemoryForTest(wpat, wmask, at);

    // The same pattern as an EXACT match (byte 1 must be 0x00) must not match here.
    std::vector<char> exactMask = {1, 1, 1, 1, 1, 1};
    uintptr_t exactHit = browser.searchMemoryForTest(wpat, exactMask, at);

    // A fully-exact correct pattern matches at the needle.
    std::vector<uint8_t> full = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    uintptr_t fullHit = browser.searchMemoryForTest(full, exactMask, at);

    bool ok = (wildHit == at) && (exactHit != at) && (fullHit == at);
    printf("gui search smoke: %s (wild@needle=%d exactMismatch=%d full@needle=%d)\n",
           ok ? "OK" : "FAILED", (int)(wildHit == at), (int)(exactHit != at), (int)(fullHit == at));
    return ok ? 0 : 1;
}
