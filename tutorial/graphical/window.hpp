#pragma once

#include <QElapsedTimer>
#include <QWidget>

class QLabel;
class QPushButton;
class QTimer;

/// Draws the game world, scaled to fit, and turns held keys into game input.
class GameCanvas : public QWidget {
    Q_OBJECT
public:
    explicit GameCanvas(QWidget* parent = nullptr);
    QSize sizeHint() const override { return {640, 360}; }

protected:
    void paintEvent(QPaintEvent*) override;
    void keyPressEvent(QKeyEvent* event) override;
    void keyReleaseEvent(QKeyEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;

private:
    int held_ = 0;
};

/// The graphical tutorial window: the game above, the level's lesson below.
class GraphicalWindow : public QWidget {
    Q_OBJECT
public:
    GraphicalWindow(unsigned seed, int level, QWidget* parent = nullptr);
    /// Start a level directly (for screenshots).
    void openLevel(int level);

private:
    void showLevel();
    void tick();

    GameCanvas* canvas_;
    QLabel* stepLabel_;
    QLabel* titleLabel_;
    QLabel* text_;
    QLabel* status_;
    QPushButton* next_;
    QTimer* timer_;
    QElapsedTimer clock_;
    qint64 lastMs_ = 0;
    int shownLevel_ = 0;
    bool shownDone_ = false;
};
