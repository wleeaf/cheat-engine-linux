// Hotkeys at run time, end to end: a Cheat Engine table whose record has one
// hotkey of every action (and two Set Value ones) is loaded into the main
// window, and each key press is checked against the memory it changes.
// Offscreen there is no system-wide hotkey grab, so every hotkey is the
// window's own shortcut, which is what a press fires.
static bool guiHotkeyRuntimeChecks() {
    static volatile int32_t value = 10;
    value = 10;
    QTemporaryDir directory;
    if (!directory.isValid()) return false;
    const QString path = directory.filePath("hotkeys.CT");
    {
        // Ctrl+Shift+F1..F9; VK 17 Ctrl, 16 Shift, 112 F1.
        struct Key { const char* action; int f; const char* value; };
        const Key keys[] = {
            {"Set Value", 1, "42"}, {"Set Value", 2, "7"}, {"Increase Value", 3, "5"},
            {"Decrease Value", 4, "2"}, {"Activate", 5, nullptr}, {"Deactivate", 6, nullptr},
            {"Toggle Activation", 7, nullptr}, {"Toggle Activation Allow Increase", 8, nullptr},
            {"Toggle Activation Allow Decrease", 9, nullptr},
        };
        std::ofstream out(path.toStdString());
        out << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<CheatTable CheatEngineTableVersion=\"45\">\n"
               "  <CheatEntries>\n    <CheatEntry>\n      <ID>1</ID>\n      <Description>\"hotkeyed\"</Description>\n"
               "      <VariableType>4 Bytes</VariableType>\n      <Address>"
            << std::hex << reinterpret_cast<uintptr_t>(&value) << std::dec << "</Address>\n      <Hotkeys>\n";
        int id = 0;
        for (const auto& key : keys) {
            out << "        <Hotkey>\n          <Action>" << key.action << "</Action>\n          <Keys>\n"
                   "            <Key>17</Key>\n            <Key>16</Key>\n            <Key>" << 111 + key.f << "</Key>\n"
                   "          </Keys>\n";
            if (key.value) out << "          <Value>" << key.value << "</Value>\n";
            out << "          <ID>" << id++ << "</ID>\n        </Hotkey>\n";
        }
        out << "      </Hotkeys>\n    </CheatEntry>\n  </CheatEntries>\n</CheatTable>\n";
    }

    ce::gui::MainWindow main;
    main.attachToPid(getpid(), "hotkey fixture");
    QTimer dismiss;
    dismiss.setInterval(5);
    QObject::connect(&dismiss, &QTimer::timeout, [] {
        if (auto* box = qobject_cast<QMessageBox*>(QApplication::activeModalWidget())) box->accept();
    });
    dismiss.start();
    main.loadTableFromPath(path);
    dismiss.stop();
    QApplication::processEvents();
    auto* model = main.findChild<ce::gui::AddressListModel*>();
    if (!model || model->entries().size() != 1) {
        std::printf("gui hotkeys: FAILED (the table did not load)\n");
        return false;
    }
    const int recordId = model->entries()[0].id;
    auto entry = [&]() -> const ce::gui::AddressEntry& { return model->entries()[model->rowOfId(recordId)]; };
    // Every hotkey of the record survived the load.
    const bool loaded = model->hotkeysOf(0).size() == 9;

    auto press = [&](int f) {
        const QKeySequence sequence(QStringLiteral("Ctrl+Shift+F%1").arg(f));
        int fired = 0;
        for (auto* shortcut : main.findChildren<QShortcut*>())
            if (shortcut->key() == sequence) { emit shortcut->activated(); ++fired; }
        QApplication::processEvents();
        return fired == 1;
    };
    bool pressed = true;
    auto pressed1 = [&](int f) { pressed = press(f) && pressed; };

    // Set Value, both of them, and Increase/Decrease by their own steps.
    pressed1(1);
    const bool setFirst = value == 42;
    pressed1(2);
    const bool setSecond = value == 7;
    pressed1(3);
    const bool increase = value == 12;
    pressed1(4);
    const bool decrease = value == 10;
    // Increase and decrease repeat while held; the others act once per press.
    bool repeats = true;
    for (auto* shortcut : main.findChildren<QShortcut*>()) {
        const QString text = shortcut->key().toString();
        if (!text.startsWith("Ctrl+Shift+F")) continue;
        const bool held = text == "Ctrl+Shift+F3" || text == "Ctrl+Shift+F4";
        repeats = repeats && shortcut->autoRepeat() == held;
    }

    // Activate and Deactivate set the state, whatever it was.
    pressed1(5);
    bool activate = entry().active;
    pressed1(5);
    activate = activate && entry().active;
    pressed1(6);
    bool deactivate = !entry().active;
    pressed1(6);
    deactivate = deactivate && !entry().active;
    // The frozen value holds while active: a write by the game is undone.
    pressed1(5);
    value = 99;
    for (int i = 0; i < 200 && value != 10; ++i) { QThread::msleep(5); QApplication::processEvents(); }
    const bool frozen = value == 10;
    pressed1(6);

    // Toggle flips it; the "allow" toggles also choose the freeze mode.
    pressed1(7);
    bool toggle = entry().active && entry().freezeMode == ce::FreezeMode::Normal;
    pressed1(7);
    toggle = toggle && !entry().active;
    pressed1(8);
    bool allowIncrease = entry().active && entry().freezeMode == ce::FreezeMode::IncreaseOnly;
    pressed1(8);
    allowIncrease = allowIncrease && !entry().active;
    pressed1(9);
    bool allowDecrease = entry().active && entry().freezeMode == ce::FreezeMode::DecreaseOnly;
    pressed1(9);
    allowDecrease = allowDecrease && !entry().active;

    const bool ok = loaded && pressed && setFirst && setSecond && increase && decrease && repeats && activate &&
                    deactivate && frozen && toggle && allowIncrease && allowDecrease;
    std::printf("gui hotkeys: %s (loaded=%d pressed=%d set=%d,%d inc=%d dec=%d repeat=%d activate=%d deactivate=%d "
                "frozen=%d toggle=%d allowinc=%d allowdec=%d value=%d)\n",
                ok ? "OK" : "FAILED", loaded, pressed, setFirst, setSecond, increase, decrease, repeats, activate,
                deactivate, frozen, toggle, allowIncrease, allowDecrease, static_cast<int>(value));
    return ok;
}
