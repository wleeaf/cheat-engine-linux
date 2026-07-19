// Headless (offscreen Qt) smoke test for the Memory Viewer hex pane's changed-byte
// highlight (CE-style: bytes that change between refreshes paint red). Reads this
// process's own memory; mutates one byte between two refreshes and checks exactly
// that byte is flagged changed. Exit 0 on success.

#include "gui/memorybrowser.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <QKeyEvent>
#include <QClipboard>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <unistd.h>

alignas(16) static uint8_t g_buf[512];

static void sendKey(QObject* w, int key, Qt::KeyboardModifiers mods) {
    QKeyEvent e(QEvent::KeyPress, key, mods);
    QApplication::sendEvent(w, &e);
}

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

    // Keyboard Ctrl+V pastes the clipboard AOB into memory at the cursor.
    hv.setSelectionForTest(0, 0);
    std::memset(g_buf, 0, 8);
    QApplication::clipboard()->setText("de ad be ef");
    sendKey(&hv, Qt::Key_V, Qt::ControlModifier);
    bool ctrlV = (g_buf[0] == 0xde && g_buf[1] == 0xad && g_buf[2] == 0xbe && g_buf[3] == 0xef);

    // Keyboard Ctrl+C copies the selected bytes back out as an AOB.
    g_buf[0] = 0x01; g_buf[1] = 0x02; g_buf[2] = 0x03;
    hv.refresh();                         // cache_ picks up the new bytes
    hv.setSelectionForTest(0, 2);
    QApplication::clipboard()->clear();
    sendKey(&hv, Qt::Key_C, Qt::ControlModifier);
    bool ctrlC = QApplication::clipboard()->text().contains("01 02 03");

    // Fill selection: write 0x90 across bytes [4,7], leaving the neighbours untouched.
    std::memset(g_buf, 0x00, 16);
    hv.setSelectionForTest(4, 7);
    int filled = hv.fillSelection(0x90);
    bool fillOk = (filled == 4 && g_buf[3] == 0x00 && g_buf[4] == 0x90 && g_buf[5] == 0x90 &&
                   g_buf[6] == 0x90 && g_buf[7] == 0x90 && g_buf[8] == 0x00);

    // "Add to list" uses the current display type: float display -> Float, qword -> 8 bytes.
    hv.setDisplayType(ce::gui::HexView::DisplayType::Float);
    bool typeFloat = hv.valueTypeForDisplay() == ce::ValueType::Float;
    hv.setDisplayType(ce::gui::HexView::DisplayType::Qword);
    bool typeQword = hv.valueTypeForDisplay() == ce::ValueType::Int64;
    hv.setDisplayType(ce::gui::HexView::DisplayType::Byte);
    bool typeByte = hv.valueTypeForDisplay() == ce::ValueType::Byte;
    bool typeMap = typeFloat && typeQword && typeByte;

    // selectBytes highlights a range at an absolute address (used to mark a search hit).
    hv.setAddress(reinterpret_cast<uintptr_t>(g_buf));
    hv.selectBytes(reinterpret_cast<uintptr_t>(g_buf) + 4, 3);
    bool selBytes = (hv.selectionStartForTest() == 4 && hv.selectionSizeForTest() == 3);

    // pointerAt reads a target-sized pointer (8 bytes on this 64-bit process).
    uintptr_t ptrTarget = reinterpret_cast<uintptr_t>(g_buf) + 128;
    std::memcpy(g_buf, &ptrTarget, sizeof(ptrTarget));
    bool ptrOk = (hv.pointerAt(reinterpret_cast<uintptr_t>(g_buf)) == ptrTarget);

    // Shift+Right extends the byte selection from a single cursor; a plain move collapses it.
    hv.setSelectionForTest(5, 5);
    sendKey(&hv, Qt::Key_Right, Qt::ShiftModifier);
    sendKey(&hv, Qt::Key_Right, Qt::ShiftModifier);
    bool shiftSel = (hv.selectionStartForTest() == 5 && hv.selectionSizeForTest() == 3);
    sendKey(&hv, Qt::Key_Left, Qt::NoModifier);   // plain move collapses to one byte
    bool shiftCollapse = (hv.selectionSizeForTest() == 1);

    bool ok = baseline == 0 && afterOne == 1 && afterNav == 0 && pasteOk && ctrlV && ctrlC && fillOk && typeMap && selBytes && ptrOk && shiftSel && shiftCollapse;
    printf("gui hexview smoke: %s (baseline=%d afterOneFlip=%d afterNav=%d pasteWrote=%d pasteOk=%d "
           "ctrlV=%d ctrlC=%d filled=%d fillOk=%d typeMap=%d selBytes=%d ptrOk=%d shiftSel=%d shiftCollapse=%d)\n",
           ok ? "OK" : "FAILED", baseline, afterOne, afterNav, wrote, pasteOk, ctrlV, ctrlC, filled, fillOk, typeMap, selBytes, ptrOk, shiftSel, shiftCollapse);
    return ok ? 0 : 1;
}
