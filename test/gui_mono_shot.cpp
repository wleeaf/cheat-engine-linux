// Offscreen render of the Mono dissector window, populated from a parsed dump
// (no live process needed). `gui_mono_shot <out.png> [dark]`.
#include "gui/monodissector.hpp"
#include "gui/theme.hpp"
#include "analysis/mono_dissector.hpp"
#include <QApplication>
#include <QSettings>
#include <QTreeWidget>
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    const bool dark = argc > 2 && std::string(argv[2]) == "dark";
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    app.setOrganizationName("cecore-uitest"); app.setApplicationName("gui_mono_shot");
    QSettings().setValue(ce::gui::kDarkThemeKey, dark);
    ce::gui::applyTheme(dark);

    const char* dump =
        "# ready\n"
        "IMG Assembly-CSharp\n"
        "CLS .Player\n"
        "FLD 0x18 - System.Int32 health\n"
        "FLD 0x1c - System.Single stamina\n"
        "FLD 0x10 - System.String playerName\n"
        "FLD 0x0 S System.Int32 instanceCount\n"
        "FLD 0x20 - Vector3 position\n"
        "CLS Game.Enemies.Boss\n"
        "FLD 0x18 - System.Int32 hp\n"
        "FLD 0x20 - System.Single rage\n"
        "IMG mscorlib\n"
        "CLS System.String\n"
        "FLD 0x10 - System.Int32 m_stringLength\n"
        "# done\n";
    ce::gui::MonoDissectorWindow w(nullptr);
    w.resize(760, 620);
    w.setDissection(ce::parseMonoDump(dump));
    // expand the tree so the render shows the layout
    if (auto* tree = w.findChild<QTreeWidget*>()) tree->expandAll();
    w.show();
    for (int i = 0; i < 30; ++i) app.processEvents();
    bool ok = w.grab().save(QString::fromLocal8Bit(argv[1]));
    printf("gui mono shot: %s (%s)\n", ok?"OK":"FAILED", dark?"dark":"light");
    return ok?0:1;
}
