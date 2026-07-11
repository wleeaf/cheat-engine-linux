#include "gui/luaconsole.hpp"
#include "scripting/lua_gui.hpp"
#include <QVBoxLayout>
#include <QFont>

namespace ce::gui {

LuaConsole::LuaConsole(LuaEngine* engine, QWidget* parent)
    : QMainWindow(parent), engine_(engine) {

    setWindowTitle("Lua Console");
    resize(600, 400);

    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);

    output_ = new QPlainTextEdit;
    output_->setReadOnly(true);
    output_->setFont(QFont("Monospace", 10));
    output_->appendPlainText("-- Cheat Engine Lua Console --");
    output_->appendPlainText("-- Functions: readInteger(addr), writeInteger(addr, val), getModuleBase(name), ...");
    layout->addWidget(output_);

    input_ = new QLineEdit;
    input_->setFont(QFont("Monospace", 10));
    input_->setPlaceholderText("Enter Lua code...");
    connect(input_, &QLineEdit::returnPressed, this, &LuaConsole::onExecute);
    layout->addWidget(input_);

    setCentralWidget(central);

    // Set output callback
    engine_->setOutputCallback([this](const std::string& msg) {
        output_->appendPlainText(QString::fromStdString(msg));
    });

    // Register GUI bindings (needs Qt, so done here not in engine)
    registerLuaGuiBindings(engine_->state());
}

void LuaConsole::onExecute() {
    auto code = input_->text();
    if (code.isEmpty()) return;

    output_->appendPlainText("> " + code);
    input_->clear();

    auto err = engine_->execute(code.toStdString());
    if (!err.empty())
        output_->appendPlainText("ERROR: " + QString::fromStdString(err));
}

} // namespace ce::gui
