/// CanvasWidget — QImage-backed drawing surface for Lua-driven HUDs.

#include "gui/canvaswidget.hpp"

#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>

namespace ce::gui {

CanvasWidget::CanvasWidget(QWidget* parent) : QWidget(parent) {
    pen_   = QPen(QColor(255, 255, 255));
    brush_ = QBrush(QColor(0, 0, 0));
    font_  = QFont("Monospace", 10);
    setAttribute(Qt::WA_OpaquePaintEvent, false);
    setAutoFillBackground(false);
    resize(200, 100);
    ensureImageSize();
    image_.fill(Qt::transparent);
}

void CanvasWidget::ensureImageSize() {
    QSize sz = size();
    if (sz.width() <= 0 || sz.height() <= 0) return;
    if (image_.size() != sz) {
        QImage fresh(sz, QImage::Format_ARGB32_Premultiplied);
        fresh.fill(Qt::transparent);
        if (!image_.isNull()) {
            QPainter p(&fresh);
            p.drawImage(0, 0, image_);
        }
        image_ = std::move(fresh);
    }
}

void CanvasWidget::setPenColor(const QColor& c)        { pen_.setColor(c); }
void CanvasWidget::setPenWidth(int w)                  { pen_.setWidth(std::max(1, w)); }
void CanvasWidget::setBrushColor(const QColor& c)      { brush_.setColor(c); brush_.setStyle(Qt::SolidPattern); }
void CanvasWidget::setFontPointSize(int pt)            { font_.setPointSize(std::max(1, pt)); }
void CanvasWidget::setFontFamily(const QString& fam)   { font_.setFamily(fam); }

void CanvasWidget::drawLine(int x1, int y1, int x2, int y2) {
    ensureImageSize();
    QPainter p(&image_);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(pen_);
    p.drawLine(x1, y1, x2, y2);
    update();
}

void CanvasWidget::drawRect(int x, int y, int w, int h) {
    ensureImageSize();
    QPainter p(&image_);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(pen_);
    p.setBrush(Qt::NoBrush);
    p.drawRect(x, y, w, h);
    update();
}

void CanvasWidget::fillRect(int x, int y, int w, int h) {
    ensureImageSize();
    QPainter p(&image_);
    p.fillRect(x, y, w, h, brush_);
    update();
}

void CanvasWidget::drawText(int x, int y, const QString& text) {
    ensureImageSize();
    QPainter p(&image_);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(pen_);
    p.setFont(font_);
    p.drawText(x, y, text);
    update();
}

void CanvasWidget::drawPixel(int x, int y, const QColor& c) {
    ensureImageSize();
    if (x < 0 || y < 0 || x >= image_.width() || y >= image_.height()) return;
    image_.setPixelColor(x, y, c);
    update();
}

void CanvasWidget::drawEllipse(int x, int y, int w, int h) {
    ensureImageSize();
    QPainter p(&image_);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setPen(pen_);
    p.setBrush(brush_);
    p.drawEllipse(x, y, w, h);
    update();
}

void CanvasWidget::clear() {
    ensureImageSize();
    image_.fill(Qt::transparent);
    update();
}

void CanvasWidget::paintEvent(QPaintEvent* /*ev*/) {
    QPainter p(this);
    if (!image_.isNull())
        p.drawImage(0, 0, image_);
}

void CanvasWidget::resizeEvent(QResizeEvent* ev) {
    QWidget::resizeEvent(ev);
    ensureImageSize();
}

} // namespace ce::gui
