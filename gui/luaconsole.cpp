#include "gui/luaconsole.hpp"
#include "scripting/lua_gui.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QFont>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QColor>
#include <QEvent>
#include <QKeyEvent>

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
    input_->installEventFilter(this);   // Up/Down recall previous commands (REPL history)
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

    // Remember the command for Up/Down recall (skip an immediate repeat), and reset the
    // browse position to the new (empty) line.
    if (history_.isEmpty() || history_.last() != code)
        history_.append(code);
    historyIndex_ = history_.size();

    // Echo the command dimmed so it reads as input, not output.
    appendColored(output_, "> " + code, QColor(0x80, 0x86, 0x94));
    input_->clear();

    auto err = engine_->execute(code.toStdString());
    if (!err.empty())
        // Errors in red (legible on both the light and dark themes).
        appendColored(output_, "ERROR: " + QString::fromStdString(err), QColor(0xd6, 0x2b, 0x2b));
}

void LuaConsole::recallHistory(bool previous) {
    if (history_.isEmpty()) return;
    if (previous) {
        if (historyIndex_ > 0) --historyIndex_;
        input_->setText(history_[historyIndex_]);
    } else {
        if (historyIndex_ < history_.size() - 1) {
            ++historyIndex_;
            input_->setText(history_[historyIndex_]);
        } else {                       // past the newest -> back to an empty new line
            historyIndex_ = history_.size();
            input_->clear();
        }
    }
}

bool LuaConsole::eventFilter(QObject* obj, QEvent* ev) {
    if (obj == input_ && ev->type() == QEvent::KeyPress) {
        auto* key = static_cast<QKeyEvent*>(ev);
        if (key->key() == Qt::Key_Up)   { recallHistory(true);  return true; }
        if (key->key() == Qt::Key_Down) { recallHistory(false); return true; }
    }
    return QMainWindow::eventFilter(obj, ev);
}

} // namespace ce::gui
