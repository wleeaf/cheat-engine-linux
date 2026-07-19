// Headless (offscreen Qt) smoke test for the Lua Console's command history (Up/Down
// recall, like any REPL and CE's console). Runs a few lines, then walks history with
// the arrow-key recall hooks and checks the input field. Exit 0 on success.

#include "gui/luaconsole.hpp"
#include "scripting/lua_engine.hpp"

#include <QApplication>
#include <cstdio>

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);

    ce::LuaEngine engine;
    ce::gui::LuaConsole console(&engine);
    console.show();
    app.processEvents();

    console.runForTest("print(1)");
    console.runForTest("print(2)");
    console.runForTest("print(3)");
    console.runForTest("print(3)");   // an immediate repeat is not stored twice

    // Up recalls newest-first and clamps at the oldest.
    console.recallForTest(true);  bool up1 = console.inputTextForTest() == "print(3)";
    console.recallForTest(true);  bool up2 = console.inputTextForTest() == "print(2)";
    console.recallForTest(true);  bool up3 = console.inputTextForTest() == "print(1)";
    console.recallForTest(true);  bool upClamp = console.inputTextForTest() == "print(1)";

    // Down walks forward and ends on an empty new line (dedup means only 3 entries, so
    // from the oldest: 1 -> 2 -> 3 -> empty).
    console.recallForTest(false); bool down1 = console.inputTextForTest() == "print(2)";
    console.recallForTest(false); bool down2 = console.inputTextForTest() == "print(3)";
    console.recallForTest(false); bool downEmpty = console.inputTextForTest().isEmpty();

    bool ok = up1 && up2 && up3 && upClamp && down1 && down2 && downEmpty;
    printf("gui luaconsole smoke: %s (up=%d%d%d clamp=%d down=%d%d empty=%d)\n",
           ok ? "OK" : "FAILED", (int)up1, (int)up2, (int)up3, (int)upClamp,
           (int)down1, (int)down2, (int)downEmpty);
    return ok ? 0 : 1;
}
