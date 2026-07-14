#include "gui/graphicalmemoryview.hpp"

#include <QPainter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QScrollArea>
#include <QImage>

namespace ce::gui {

QSize MemPixelView::sizeHint() const {
    int rows = data_.empty() ? 1 : (int)((data_.size() + perLine_ - 1) / perLine_);
    return QSize(perLine_ * scale_, rows * scale_);
}

void MemPixelView::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.fillRect(rect(), Qt::black);
    if (data_.empty()) return;
    // One byte -> one greyscale pixel; upscale by `scale_`. Build an QImage once
    // (fast) then blit scaled.
    int rows = (int)((data_.size() + perLine_ - 1) / perLine_);
    QImage img(perLine_, rows, QImage::Format_RGB32);
    img.fill(Qt::black);
    for (size_t i = 0; i < data_.size(); ++i) {
        int x = (int)(i % perLine_), y = (int)(i / perLine_);
        uint8_t b = data_[i];
        img.setPixel(x, y, qRgb(b, b, b));
    }
    p.drawImage(QRect(0, 0, perLine_ * scale_, rows * scale_), img);
}

GraphicalMemoryView::GraphicalMemoryView(ce::ProcessHandle* proc, QWidget* parent)
    : QMainWindow(parent), proc_(proc) {
    setWindowTitle("Graphical Memory View");
    resize(560, 620);

    auto* central = new QWidget;
    setCentralWidget(central);
    auto* v = new QVBoxLayout(central);

    auto* controls = new QHBoxLayout;
    controls->addWidget(new QLabel("Address:"));
    addrEdit_ = new QLineEdit("0");
    controls->addWidget(addrEdit_);
    controls->addWidget(new QLabel("Pixels per line:"));
    perLineSpin_ = new QSpinBox;
    perLineSpin_->setRange(1, 4096);
    perLineSpin_->setValue(256);
    controls->addWidget(perLineSpin_);
    controls->addWidget(new QLabel("Rows:"));
    rowsSpin_ = new QSpinBox;
    rowsSpin_->setRange(1, 4096);
    rowsSpin_->setValue(256);
    controls->addWidget(rowsSpin_);
    auto* fetchBtn = new QPushButton("Fetch memory map");
    controls->addWidget(fetchBtn);
    v->addLayout(controls);

    view_ = new MemPixelView;
    auto* scroll = new QScrollArea;
    scroll->setWidget(view_);
    scroll->setWidgetResizable(false);
    v->addWidget(scroll, 1);

    connect(fetchBtn, &QPushButton::clicked, this, &GraphicalMemoryView::fetch);
    connect(perLineSpin_, &QSpinBox::valueChanged, this, [this](int n) { view_->setPerLine(n); });
    view_->setPerLine(256);
}

void GraphicalMemoryView::gotoAddress(uintptr_t addr) {
    addrEdit_->setText(QString("0x%1").arg((qulonglong)addr, 0, 16));
    fetch();
}

void GraphicalMemoryView::fetch() {
    if (!proc_) return;
    uintptr_t addr = addrEdit_->text().toULongLong(nullptr, 16);
    int perLine = perLineSpin_->value();
    size_t count = (size_t)perLine * rowsSpin_->value();
    std::vector<uint8_t> buf(count);
    auto r = proc_->read(addr, buf.data(), buf.size());
    size_t got = (r && *r > 0) ? *r : 0;
    buf.resize(got);
    view_->setPerLine(perLine);
    view_->setData(std::move(buf));
    view_->resize(view_->sizeHint());
}

}  // namespace ce::gui
