#include "gui/luaconsole.hpp"
#include "scripting/lua_gui.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFont>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QColor>

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

    // Input row: the code field plus explicit Run / Clear buttons, so the actions
    // are visible instead of relying on the user guessing to press Enter.
    auto* inputRow = new QHBoxLayout;
    input_ = new QLineEdit;
    input_->setFont(QFont("Monospace", 10));
    input_->setPlaceholderText("Enter Lua code, then press Run or Enter…");
    connect(input_, &QLineEdit::returnPressed, this, &LuaConsole::onExecute);
    inputRow->addWidget(input_, 1);

    auto* runBtn = new QPushButton("Run");
    runBtn->setToolTip("Execute the Lua code (Enter)");
    connect(runBtn, &QPushButton::clicked, this, &LuaConsole::onExecute);
    inputRow->addWidget(runBtn);

    auto* clearBtn = new QPushButton("Clear");
    clearBtn->setToolTip("Clear the console output");
    connect(clearBtn, &QPushButton::clicked, this, [this]() {
        output_->clear();
        output_->appendPlainText("-- Cheat Engine Lua Console --");
    });
    inputRow->addWidget(clearBtn);
    layout->addLayout(inputRow);

    setCentralWidget(central);

    // Set output callback
    engine_->setOutputCallback([this](const std::string& msg) {
        output_->appendPlainText(QString::fromStdString(msg));
    });

    // Register GUI bindings (needs Qt, so done here not in engine)
    registerLuaGuiBindings(engine_->state());
}

// Append one line to the console in a specific colour. QPlainTextEdit's
// appendPlainText can't colour a line, so insert through a cursor with a format.
static void appendColored(QPlainTextEdit* out, const QString& text, const QColor& color) {
    QTextCharFormat fmt;
    fmt.setForeground(color);
    QTextCursor cur(out->document());
    cur.movePosition(QTextCursor::End);
    if (!out->document()->isEmpty())
        cur.insertBlock();
    cur.insertText(text, fmt);
    out->setTextCursor(cur);
    out->ensureCursorVisible();
}

void LuaConsole::onExecute() {
    auto code = input_->text();
    if (code.isEmpty()) return;

    // Echo the command dimmed so it reads as input, not output.
    appendColored(output_, "> " + code, QColor(0x80, 0x86, 0x94));
    input_->clear();

    auto err = engine_->execute(code.toStdString());
    if (!err.empty())
        // Errors in red (legible on both the light and dark themes).
        appendColored(output_, "ERROR: " + QString::fromStdString(err), QColor(0xd6, 0x2b, 0x2b));
}

} // namespace ce::gui
