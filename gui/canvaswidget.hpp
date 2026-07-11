#pragma once
/// CanvasWidget — a drawable QWidget that holds an offscreen QImage and
/// re-paints it on every paintEvent. Lua's createCanvas() returns one of
/// these wrapped in a userdata; the Lua-side drawing methods (drawLine,
/// fillRect, drawText, etc.) operate on the QImage and request a repaint.
///
/// CE-style canvas API: cheap immediate-mode drawing for trainer HUDs.

#include <QWidget>
#include <QImage>
#include <QColor>
#include <QFont>
#include <QPen>
#include <QBrush>

namespace ce::gui {

class CanvasWidget : public QWidget {
    Q_OBJECT
public:
    explicit CanvasWidget(QWidget* parent = nullptr);

    void setPenColor(const QColor& c);
    void setPenWidth(int w);
    void setBrushColor(const QColor& c);
    void setFontPointSize(int pt);
    void setFontFamily(const QString& family);

    void drawLine(int x1, int y1, int x2, int y2);
    void drawRect(int x, int y, int w, int h);
    void fillRect(int x, int y, int w, int h);
    void drawText(int x, int y, const QString& text);
    void drawPixel(int x, int y, const QColor& c);
    void drawEllipse(int x, int y, int w, int h);
    void clear();

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    QImage image_;
    QPen   pen_;
    QBrush brush_;
    QFont  font_;
    void ensureImageSize();
};

} // namespace ce::gui
