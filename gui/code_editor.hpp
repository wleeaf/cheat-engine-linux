#pragma once
/// A plain-text code editor with a line-number gutter and a soft highlight on
/// the cursor line, used by the Auto Assembler and Lua script editors. Colours
/// follow the active theme through editorPalette().

#include "gui/theme.hpp"
#include <QApplication>
#include <QPainter>
#include <QPlainTextEdit>
#include <QTextBlock>

namespace ce::gui {

class CodeEditor : public QPlainTextEdit {
public:
    explicit CodeEditor(QWidget* parent = nullptr) : QPlainTextEdit(parent), gutter_(new Gutter(this)) {
        setLineWrapMode(QPlainTextEdit::NoWrap);
        setFont(monospaceFont());
        document()->setDocumentMargin(6);
        connect(this, &QPlainTextEdit::blockCountChanged, this, [this]() { updateGutterWidth(); });
        connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect& rect, int dy) {
            if (dy) gutter_->scroll(0, dy);
            else gutter_->update(0, rect.y(), gutter_->width(), rect.height());
        });
        connect(this, &QPlainTextEdit::cursorPositionChanged, this, [this]() { highlightCurrentLine(); });
        connect(qApp, &QApplication::paletteChanged, this, [this]() { highlightCurrentLine(); gutter_->update(); });
        updateGutterWidth();
        highlightCurrentLine();
    }

    int gutterWidth() const {
        int digits = QString::number(std::max(1, blockCount())).size();
        return 14 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * std::max(2, digits);
    }

protected:
    void resizeEvent(QResizeEvent* event) override {
        QPlainTextEdit::resizeEvent(event);
        const QRect area = contentsRect();
        gutter_->setGeometry(QRect(area.left(), area.top(), gutterWidth(), area.height()));
    }
    void changeEvent(QEvent* event) override {
        QPlainTextEdit::changeEvent(event);
        if (event->type() == QEvent::FontChange) updateGutterWidth();
    }

private:
    class Gutter : public QWidget {
    public:
        explicit Gutter(CodeEditor* editor) : QWidget(editor), editor_(editor) {}
        QSize sizeHint() const override { return {editor_->gutterWidth(), 0}; }
    protected:
        void paintEvent(QPaintEvent* event) override { editor_->paintGutter(event); }
    private:
        CodeEditor* editor_;
    };

    void updateGutterWidth() { setViewportMargins(gutterWidth(), 0, 0, 0); }

    void highlightCurrentLine() {
        if (isReadOnly()) { setExtraSelections({}); return; }
        QTextEdit::ExtraSelection line;
        QColor tint = palette().color(QPalette::Highlight);
        tint.setAlpha(isDarkTheme() ? 70 : 90);
        line.format.setBackground(tint);
        line.format.setProperty(QTextFormat::FullWidthSelection, true);
        line.cursor = textCursor();
        line.cursor.clearSelection();
        setExtraSelections({line});
    }

    void paintGutter(QPaintEvent* event) {
        QPainter painter(gutter_);
        const EditorPalette pal = editorPalette();
        QColor background = pal.background;
        background = isDarkTheme() ? background.darker(112) : background.darker(103);
        painter.fillRect(event->rect(), background);
        painter.setFont(font());
        const int current = textCursor().blockNumber();
        QTextBlock block = firstVisibleBlock();
        int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
        int bottom = top + qRound(blockBoundingRect(block).height());
        while (block.isValid() && top <= event->rect().bottom()) {
            if (block.isVisible() && bottom >= event->rect().top()) {
                painter.setPen(block.blockNumber() == current ? pal.text : pal.dim);
                painter.drawText(0, top, gutter_->width() - 8, fontMetrics().height(),
                                 Qt::AlignRight | Qt::AlignVCenter, QString::number(block.blockNumber() + 1));
            }
            block = block.next();
            top = bottom;
            bottom = top + qRound(blockBoundingRect(block).height());
        }
    }

    Gutter* gutter_;
};

} // namespace ce::gui
