#pragma once

#include <QElapsedTimer>
#include <QWidget>

class QBoxLayout;
class QFormLayout;
class QGroupBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QTextBrowser;
class QTimer;

/// The tutorial window: the step's instructions, the game's values and
/// buttons, and Next. All game state lives in game.c.
class TutorialWindow : public QWidget {
    Q_OBJECT
public:
    explicit TutorialWindow(unsigned seed, QWidget* parent = nullptr);
    /// Start over at a step, as its password would (for screenshots).
    void openStep(int step);

private:
    void showStep();
    void refreshValues();
    void log(const QString& message);
    void tick();
    void runAction(int index);
    void unlock();

    QLabel* stepLabel_;
    QLabel* titleLabel_;
    QTextBrowser* text_;
    QGroupBox* game_;
    QFormLayout* fields_;
    QBoxLayout* buttons_;
    QListWidget* log_;
    QWidget* passwordRow_;
    QLineEdit* password_;
    QLabel* passwordHint_;
    QLabel* status_;
    QPushButton* next_;
    QTimer* timer_;
    QElapsedTimer clock_;
    QList<QLabel*> values_;
    int shownStep_ = 0;
    bool shownDone_ = false;
};
