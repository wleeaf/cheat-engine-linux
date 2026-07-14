// Offscreen render of the Auto Assembler window (ScriptEditor). Fills the editor
// with a representative script and writes a couple of console lines, then grabs
// the widget so the syntax highlighting AND the output console can be checked in
// light or dark without a window manager. `gui_script_shot <out.png> [dark]`.

#include "gui/scripteditor.hpp"
#include "gui/theme.hpp"
#include "core/autoasm.hpp"

#include <QApplication>
#include <QSettings>
#include <QPlainTextEdit>
#include <QTextEdit>
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <out.png> [dark]\n", argv[0]); return 2; }
    const char* out = argv[1];
    const bool dark = argc > 2 && std::string(argv[2]) == "dark";
    qputenv("QT_QPA_PLATFORM", "offscreen");

    QApplication app(argc, argv);
    // Use a throwaway settings store (not the user's real prefs) and set the theme
    // flag there, so editorPalette()/isDarkTheme() agree with applyTheme() below.
    app.setOrganizationName("cecore-uitest");
    app.setApplicationName("gui_script_shot");
    QSettings().setValue(ce::gui::kDarkThemeKey, dark);
    ce::gui::applyTheme(dark);

    ce::AutoAssembler aa;
    ce::gui::ScriptEditor ed(nullptr, &aa);
    ed.resize(760, 560);

    // Populate the editor (exercises every highlight rule) + the console.
    if (auto* editor = ed.findChild<QPlainTextEdit*>()) {
        editor->setPlainText(
            "[ENABLE]\n"
            "// enable god mode\n"
            "aobscanmodule(inj, game.so, 89 01 8B 41 10)\n"
            "alloc(newmem, 0x100)\n"
            "label(return)\n"
            "newmem:\n"
            "  mov [rcx], eax   // write health\n"
            "  jmp return\n"
            "inj:\n"
            "  jmp newmem\n"
            "return:\n"
            "registersymbol(inj)\n"
            "\n"
            "[DISABLE]\n"
            "dealloc(newmem)\n");
    }
    if (auto* console = ed.findChild<QTextEdit*>()) {
        console->setTextColor(ce::gui::editorPalette().success);
        console->append("Script executed successfully.");
        console->setTextColor(ce::gui::editorPalette().error);
        console->append("Warning: symbol 'inj' already registered.");
        console->setTextColor(ce::gui::editorPalette().text);
        console->append("Ready.");
    }

    ed.show();
    for (int i = 0; i < 40; ++i) { app.processEvents(); }

    const bool ok = ed.grab().save(QString::fromLocal8Bit(out));
    std::printf("gui script shot: %s (%s) -> %s\n", ok ? "OK" : "FAILED",
                dark ? "dark" : "light", out);
    return ok ? 0 : 1;
}
