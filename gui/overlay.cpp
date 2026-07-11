#include "gui/overlay.hpp"

#include <QApplication>
#include <QGuiApplication>
#include <QPainter>
#include <QScreen>
#include <QTimer>

namespace ce::gui {

OverlayWindow::OverlayWindow(QWidget* parent) : QWidget(parent) {
    setWindowTitle("CE Overlay");
    setWindowFlags(Qt::Tool | Qt::FramelessWindowHint |
        Qt::WindowStaysOnTopHint | Qt::BypassWindowManagerHint |
        Qt::WindowTransparentForInput);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_NoSystemBackground);
    setAttribute(Qt::WA_TransparentForMouseEvents);
    setFocusPolicy(Qt::NoFocus);

    if (auto* screen = QGuiApplication::primaryScreen())
        setGeometry(screen->geometry());

    fpsTimer_.start();
    auto* repaintTimer = new QTimer(this);
    connect(repaintTimer, &QTimer::timeout, this, QOverload<>::of(&OverlayWindow::update));
    repaintTimer->start(16);
}

void OverlayWindow::setStatusText(const QString& text) {
    statusText_ = text;
    update();
}

void OverlayWindow::setOsdEnabled(bool enabled) {
    osdEnabled_ = enabled;
    update();
}

void OverlayWindow::setCrosshairEnabled(bool enabled) {
    crosshairEnabled_ = enabled;
    update();
}

void OverlayWindow::updateFpsCounter() {
    ++frameCounter_;
    if (fpsTimer_.elapsed() >= 1000) {
        fps_ = frameCounter_;
        frameCounter_ = 0;
        fpsTimer_.restart();
    }
}

void OverlayWindow::paintEvent(QPaintEvent*) {
    updateFpsCounter();

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    if (osdEnabled_) {
        QFont font = painter.font();
        font.setPointSize(11);
        font.setBold(true);
        painter.setFont(font);

        QStringList lines;
        lines << QString("CE Linux  FPS %1").arg(fps_);
        lines << statusText_;

        const QFontMetrics metrics(font);
        int width = 0;
        for (const auto& line : lines)
            width = std::max(width, metrics.horizontalAdvance(line));

        QRect panel(18, 18, width + 24, metrics.height() * lines.size() + 18);
        painter.setPen(QColor(17, 17, 27, 210));
        painter.setBrush(QColor(17, 17, 27, 160));
        painter.drawRoundedRect(panel, 6, 6);

        painter.setPen(QColor(205, 214, 244));
        int y = panel.top() + 10 + metrics.ascent();
        for (const auto& line : lines) {
            painter.drawText(panel.left() + 12, y, line);
            y += metrics.height();
        }
    }

    if (crosshairEnabled_) {
        const QPoint center(width() / 2, height() / 2);
        const int gap = 5;
        const int length = 18;

        QPen shadow(QColor(17, 17, 27, 180), 4, Qt::SolidLine, Qt::RoundCap);
        painter.setPen(shadow);
        painter.drawLine(center.x() - length, center.y(), center.x() - gap, center.y());
        painter.drawLine(center.x() + gap, center.y(), center.x() + length, center.y());
        painter.drawLine(center.x(), center.y() - length, center.x(), center.y() - gap);
        painter.drawLine(center.x(), center.y() + gap, center.x(), center.y() + length);

        QPen line(QColor(166, 227, 161), 2, Qt::SolidLine, Qt::RoundCap);
        painter.setPen(line);
        painter.drawLine(center.x() - length, center.y(), center.x() - gap, center.y());
        painter.drawLine(center.x() + gap, center.y(), center.x() + length, center.y());
        painter.drawLine(center.x(), center.y() - length, center.x(), center.y() - gap);
        painter.drawLine(center.x(), center.y() + gap, center.x(), center.y() + length);
    }
}

} // namespace ce::gui
