#pragma once
#include "scripting/lua_engine.hpp"
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QLineEdit>

namespace ce::gui {

class LuaConsole : public QMainWindow {
    Q_OBJECT
public:
    explicit LuaConsole(ce::LuaEngine* engine, QWidget* parent = nullptr);

private slots:
    void onExecute();

private:
    ce::LuaEngine* engine_;
    QPlainTextEdit* output_;
    QLineEdit* input_;
};

} // namespace ce::gui
