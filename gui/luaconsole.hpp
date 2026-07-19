#pragma once
#include "scripting/lua_engine.hpp"
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QStringList>

namespace ce::gui {

class LuaConsole : public QMainWindow {
    Q_OBJECT
public:
    explicit LuaConsole(ce::LuaEngine* engine, QWidget* parent = nullptr);

    // Test hooks (offscreen): run a line (adds to history), step through history, and
    // read the input field.
    void runForTest(const QString& code) { input_->setText(code); onExecute(); }
    void recallForTest(bool previous) { recallHistory(previous); }
    QString inputTextForTest() const { return input_->text(); }

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override;

private slots:
    void onExecute();

private:
    void recallHistory(bool previous);   // Up (previous) / Down (next) command recall

    ce::LuaEngine* engine_;
    QPlainTextEdit* output_;
    QLineEdit* input_;
    QStringList history_;        // executed commands, oldest first
    int historyIndex_ = 0;       // browse position; == history_.size() means the new line
};

} // namespace ce::gui
