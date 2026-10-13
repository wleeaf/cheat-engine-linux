#include "tutorial/window.hpp"

#include "tutorial/game.h"

#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QTextBrowser>
#include <QTimer>
#include <QVBoxLayout>

namespace {

QString paragraphsToHtml(const char* text) {
    QString html;
    for (const QString& paragraph : QString::fromUtf8(text).split("\n\n"))
        html += "<p>" + paragraph.toHtmlEscaped() + "</p>";
    return html;
}

void clearLayout(QLayout* layout) {
    while (QLayoutItem* item = layout->takeAt(0)) {
        if (QWidget* widget = item->widget()) { widget->hide(); widget->deleteLater(); }
        delete item;
    }
}

} // namespace

TutorialWindow::TutorialWindow(unsigned seed, QWidget* parent) : QWidget(parent) {
    tut_init(seed);
    setWindowTitle("Cheat Engine Tutorial");

    stepLabel_ = new QLabel;
    QFont small = stepLabel_->font();
    small.setCapitalization(QFont::AllUppercase);
    small.setLetterSpacing(QFont::PercentageSpacing, 108);
    stepLabel_->setFont(small);
    stepLabel_->setForegroundRole(QPalette::PlaceholderText);

    titleLabel_ = new QLabel;
    QFont title = titleLabel_->font();
    title.setPointSizeF(title.pointSizeF() * 1.5);
    title.setBold(true);
    titleLabel_->setFont(title);

    text_ = new QTextBrowser;
    text_->setOpenLinks(false);
    text_->setFrameShape(QFrame::NoFrame);
    text_->viewport()->setAutoFillBackground(false);
    text_->setMinimumHeight(160);

    // Step 1: a password opens a later step.
    passwordRow_ = new QWidget;
    auto* passwordLayout = new QHBoxLayout(passwordRow_);
    passwordLayout->setContentsMargins(0, 0, 0, 0);
    password_ = new QLineEdit;
    password_->setPlaceholderText("Password");
    password_->setMaxLength(12);
    auto* go = new QPushButton("Go to step");
    passwordHint_ = new QLabel;
    passwordHint_->setForegroundRole(QPalette::PlaceholderText);
    passwordLayout->addWidget(password_);
    passwordLayout->addWidget(go);
    passwordLayout->addWidget(passwordHint_, 1);
    connect(go, &QPushButton::clicked, this, &TutorialWindow::unlock);
    connect(password_, &QLineEdit::returnPressed, this, &TutorialWindow::unlock);

    game_ = new QGroupBox("Game");
    auto* gameLayout = new QVBoxLayout(game_);
    fields_ = new QFormLayout;
    fields_->setLabelAlignment(Qt::AlignLeft);
    buttons_ = new QHBoxLayout;
    log_ = new QListWidget;
    log_->setSelectionMode(QAbstractItemView::NoSelection);
    log_->setFocusPolicy(Qt::NoFocus);
    log_->setMinimumHeight(90);
    gameLayout->addLayout(fields_);
    gameLayout->addLayout(buttons_);
    gameLayout->addWidget(log_, 1);

    status_ = new QLabel;
    status_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    next_ = new QPushButton("Next");
    next_->setDefault(true);
    connect(next_, &QPushButton::clicked, this, [this] {
        if (tut_finished()) { close(); return; }
        if (tut_next()) showStep();
    });
    auto* footer = new QHBoxLayout;
    footer->addWidget(status_, 1);
    footer->addWidget(next_);

    auto* layout = new QVBoxLayout(this);
    layout->setSpacing(10);
    layout->setContentsMargins(18, 16, 18, 16);
    layout->addWidget(stepLabel_);
    layout->addWidget(titleLabel_);
    layout->addWidget(text_, 1);
    layout->addWidget(passwordRow_);
    layout->addWidget(game_, 1);
    layout->addLayout(footer);

    clock_.start();
    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &TutorialWindow::tick);
    timer_->start(50);

    resize(720, 640);
    showStep();
}

void TutorialWindow::showStep() {
    const int step = tut_step();
    shownStep_ = step;
    shownDone_ = tut_done();
    clearLayout(fields_);
    clearLayout(buttons_);
    values_.clear();
    log_->clear();

    if (tut_finished()) {
        stepLabel_->setText("Tutorial complete");
        titleLabel_->setText("Well done");
        text_->setHtml(paragraphsToHtml(tut_finished_text()));
        passwordRow_->hide();
        game_->hide();
        status_->clear();
        next_->setText("Close");
        next_->setEnabled(true);
        return;
    }

    stepLabel_->setText(QString("Step %1 of %2").arg(step).arg(TUT_STEPS));
    titleLabel_->setText(tut_title(step));
    text_->setHtml(paragraphsToHtml(tut_text(step)));
    passwordRow_->setVisible(step == 1);
    passwordHint_->clear();
    game_->setVisible(step > 1);

    const QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    for (int i = 0; i < tut_field_count(); ++i) {
        auto* value = new QLabel;
        QFont font = mono;
        font.setPointSizeF(font.pointSizeF() * 1.25);
        value->setFont(font);
        values_.append(value);
        fields_->addRow(QString(tut_field_label(i)) + ":", value);
    }
    for (int i = 0; i < tut_action_count(); ++i) {
        auto* button = new QPushButton(tut_action_label(i));
        connect(button, &QPushButton::clicked, this, [this, i] { runAction(i); });
        buttons_->addWidget(button);
    }
    buttons_->addStretch(1);

    status_->setText(step > 1 ? QString("Password for this step: <b>%1</b>").arg(tut_password(step)) : QString());
    next_->setText(step == TUT_STEPS ? "Finish" : "Next");
    next_->setEnabled(tut_done());
    refreshValues();
}

void TutorialWindow::openStep(int step) {
    tut_init(1);
    if (step > 1) tut_unlock(tut_password(step));
    showStep();
}

void TutorialWindow::refreshValues() {
    char value[64];
    for (int i = 0; i < values_.size(); ++i) {
        tut_field_value(i, value, sizeof value);
        values_[i]->setText(value);
    }
}

void TutorialWindow::log(const QString& message) {
    if (message.isEmpty()) return;
    log_->addItem(message);
    while (log_->count() > 200) delete log_->takeItem(0);
    log_->scrollToBottom();
}

void TutorialWindow::runAction(int index) {
    char message[256];
    tut_action(index, message, sizeof message);
    log(message);
    tick();
}

void TutorialWindow::tick() {
    if (tut_finished()) return;
    char message[256];
    if (tut_tick(clock_.elapsed(), message, sizeof message)) log(message);
    if (tut_step() != shownStep_) { showStep(); return; }
    refreshValues();
    if (tut_done() && !shownDone_) {
        shownDone_ = true;
        log(QString("Step %1 complete. Press %2.").arg(tut_step()).arg(tut_step() == TUT_STEPS ? "Finish" : "Next"));
        next_->setEnabled(true);
        next_->setFocus();
    }
}

void TutorialWindow::unlock() {
    const int step = tut_unlock(password_->text().trimmed().toUpper().toUtf8().constData());
    if (!step) {
        passwordHint_->setText("That password does not open a step.");
        return;
    }
    password_->clear();
    showStep();
}
