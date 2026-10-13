#include "tutorial/graphical/window.hpp"

#include "tutorial/graphical/game.h"

#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QPainter>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>

namespace {

QRectF toScreen(const GtRect& r) { return {r.x, r.y, r.w, r.h}; }

void drawBar(QPainter& p, const QRectF& area, float fraction, const QColor& fill, const QString& label) {
    p.setPen(Qt::NoPen);
    p.setBrush(QColor(255, 255, 255, 40));
    p.drawRoundedRect(area, 3, 3);
    p.setBrush(fill);
    p.drawRoundedRect(QRectF(area.x(), area.y(), area.width() * fraction, area.height()), 3, 3);
    if (!label.isEmpty()) {
        p.setPen(QColor(230, 236, 245));
        p.drawText(area.adjusted(0, -18, 0, -area.height()), Qt::AlignLeft | Qt::AlignBottom, label);
    }
}

} // namespace

GameCanvas::GameCanvas(QWidget* parent) : QWidget(parent) {
    setFocusPolicy(Qt::StrongFocus);
    setMinimumSize(480, 270);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

void GameCanvas::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.fillRect(rect(), QColor(14, 20, 33));
    // Fit the 640x360 world, centred, keeping its shape.
    const double scale = std::min(width() / double(GT_WIDTH), height() / double(GT_HEIGHT));
    p.translate((width() - double(GT_WIDTH) * scale) / 2, (height() - double(GT_HEIGHT) * scale) / 2);
    p.scale(scale, scale);
    p.fillRect(QRectF(0, 0, GT_WIDTH, GT_HEIGHT), QColor(22, 31, 51));

    GtView view;
    gt_view(&view);
    p.setPen(Qt::NoPen);
    for (int i = 0; i < view.ground_count; ++i) {
        p.setBrush(QColor(52, 68, 96));
        p.drawRect(toScreen(view.ground[i]));
        p.setBrush(QColor(92, 196, 126));
        p.drawRect(QRectF(view.ground[i].x, view.ground[i].y, view.ground[i].w, 4));
    }
    if (view.show_door) {
        p.setBrush(QColor(240, 196, 64));
        p.drawRoundedRect(toScreen(view.door), 4, 4);
        p.setPen(QColor(230, 236, 245));
        p.drawText(QRectF(16, 16, 300, 20), Qt::AlignLeft, QString("Jump power %1").arg(view.jump_power, 0, 'f', 0));
        p.setPen(Qt::NoPen);
    }
    if (view.show_target) {
        const QRectF t = toScreen(view.target);
        if (gt_level() == 2) {   // the fortress
            p.setBrush(QColor(150, 112, 226));
            p.drawRoundedRect(t.adjusted(-10, 0, 10, 0), 6, 6);
            p.setBrush(QColor(22, 31, 51));
            p.drawRect(QRectF(t.center().x() - 5, t.bottom() - 18, 10, 18));
        } else {
            p.setBrush(view.target_health > 0 ? QColor(226, 84, 84) : QColor(90, 90, 90));
            p.drawEllipse(t);
            p.setBrush(QColor(255, 255, 255, 200));
            p.drawEllipse(t.center(), t.width() / 6, t.height() / 6);
        }
        drawBar(p, QRectF(t.x() - 25, t.bottom() + 10, t.width() + 50, 8), view.target_health, QColor(226, 84, 84), QString());
    }
    if (view.show_heat)
        drawBar(p, QRectF(16, 36, 160, 10), view.heat, view.jammed ? QColor(226, 84, 84) : QColor(240, 150, 64),
                view.jammed ? "Heat (jammed)" : "Heat");
    p.setBrush(QColor(236, 240, 246));
    for (int i = 0; i < view.bullet_count; ++i) p.drawRect(toScreen(view.bullets[i]));
    p.setBrush(QColor(86, 182, 242));
    p.drawRoundedRect(toScreen(view.player), 4, 4);
}

static int keyBit(int key) {
    switch (key) {
    case Qt::Key_Left: case Qt::Key_A: return GT_LEFT;
    case Qt::Key_Right: case Qt::Key_D: return GT_RIGHT;
    case Qt::Key_Up: case Qt::Key_W: return GT_JUMP;
    case Qt::Key_Space: return gt_level() == 3 ? GT_JUMP : GT_FIRE;
    default: return 0;
    }
}

void GameCanvas::keyPressEvent(QKeyEvent* event) {
    const int bit = keyBit(event->key());
    if (!bit) { QWidget::keyPressEvent(event); return; }
    held_ |= bit;
    gt_keys(held_);
}

void GameCanvas::keyReleaseEvent(QKeyEvent* event) {
    if (event->isAutoRepeat()) return;
    held_ &= ~keyBit(event->key());
    gt_keys(held_);
}

void GameCanvas::focusOutEvent(QFocusEvent* event) {
    held_ = 0;
    gt_keys(0);
    QWidget::focusOutEvent(event);
}

GraphicalWindow::GraphicalWindow(unsigned seed, int level, QWidget* parent) : QWidget(parent) {
    gt_init(seed);
    if (level > 1) gt_goto(level);
    setWindowTitle("Cheat Engine Graphical Tutorial");

    canvas_ = new GameCanvas;
    stepLabel_ = new QLabel;
    QFont small = stepLabel_->font();
    small.setCapitalization(QFont::AllUppercase);
    stepLabel_->setFont(small);
    stepLabel_->setForegroundRole(QPalette::PlaceholderText);
    titleLabel_ = new QLabel;
    QFont title = titleLabel_->font();
    title.setPointSizeF(title.pointSizeF() * 1.35);
    title.setBold(true);
    titleLabel_->setFont(title);
    text_ = new QLabel;
    text_->setWordWrap(true);
    text_->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    status_ = new QLabel;
    next_ = new QPushButton("Next");
    next_->setFocusPolicy(Qt::NoFocus);
    connect(next_, &QPushButton::clicked, this, [this] {
        if (gt_finished()) { close(); return; }
        if (gt_next()) showLevel();
        canvas_->setFocus();
    });

    auto* footer = new QHBoxLayout;
    footer->addWidget(status_, 1);
    footer->addWidget(next_);
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 14);
    layout->setSpacing(8);
    layout->addWidget(canvas_, 1);
    auto* panel = new QVBoxLayout;
    panel->setContentsMargins(18, 4, 18, 0);
    panel->setSpacing(6);
    panel->addWidget(stepLabel_);
    panel->addWidget(titleLabel_);
    panel->addWidget(text_);
    panel->addLayout(footer);
    layout->addLayout(panel);

    clock_.start();
    timer_ = new QTimer(this);
    timer_->setTimerType(Qt::PreciseTimer);
    connect(timer_, &QTimer::timeout, this, &GraphicalWindow::tick);
    timer_->start(16);
    resize(760, 680);
    showLevel();
    canvas_->setFocus();
}

void GraphicalWindow::openLevel(int level) {
    gt_init(1);
    gt_goto(level);
    showLevel();
}

void GraphicalWindow::showLevel() {
    shownLevel_ = gt_level();
    shownDone_ = gt_done();
    if (gt_finished()) {
        stepLabel_->setText("Tutorial complete");
        titleLabel_->setText("Well done");
        text_->setText(gt_finished_text());
        status_->clear();
        next_->setText("Close");
        next_->setEnabled(true);
        canvas_->update();
        return;
    }
    stepLabel_->setText(QString("Level %1 of %2").arg(gt_level()).arg(GT_LEVELS));
    titleLabel_->setText(gt_title(gt_level()));
    QString text = QString::fromUtf8(gt_text(gt_level()));
    text.replace("\n\n", "<br><br>");
    text_->setText(text);
    status_->setText(gt_level() == 3 ? "Arrow keys run, Up jumps." : "Space shoots.");
    next_->setText(gt_level() == GT_LEVELS ? "Finish" : "Next");
    next_->setEnabled(gt_done());
    canvas_->update();
}

void GraphicalWindow::tick() {
    const qint64 now = clock_.elapsed();
    const float dt = std::min(0.05f, (now - lastMs_) / 1000.0f);
    lastMs_ = now;
    char message[160];
    if (gt_tick(dt, message, sizeof message)) status_->setText(message);
    if (gt_level() != shownLevel_) showLevel();
    if (gt_done() && !shownDone_) {
        shownDone_ = true;
        status_->setText(QString("%1 Press %2.").arg(message).arg(gt_level() == GT_LEVELS ? "Finish" : "Next"));
        next_->setEnabled(true);
    }
    canvas_->update();
}
