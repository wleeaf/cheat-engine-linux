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
    if (data_.empty()) return QSize(360, 160);
    int rows = (int)((data_.size() + perLine_ - 1) / perLine_);
    return QSize(perLine_ * scale_, rows * scale_);
}

void MemPixelView::paintEvent(QPaintEvent*) {
    QPainter p(this);
    if (data_.empty()) {
        p.fillRect(rect(), palette().color(QPalette::Window));
        p.setPen(palette().color(QPalette::Text));
        p.drawText(rect().adjusted(16, 16, -16, -16), Qt::AlignCenter | Qt::TextWordWrap,
                   "Enter an address and press Fetch to visualize memory.");
        return;
    }
    p.fillRect(rect(), Qt::black);
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
    resize(680, 620);

    auto* central = new QWidget;
    setCentralWidget(central);
    auto* v = new QVBoxLayout(central);

    auto* controls = new QHBoxLayout;
    controls->addWidget(new QLabel("Address:"));
    addrEdit_ = new QLineEdit("0");
    addrEdit_->setMinimumWidth(220);
    controls->addWidget(addrEdit_, 1);
    auto* fetchBtn = new QPushButton("Fetch");
    fetchBtn->setObjectName("primaryButton");
    fetchBtn->setToolTip("Read and visualize memory at this address");
    controls->addWidget(fetchBtn);
    v->addLayout(controls);
    auto* dimensions = new QHBoxLayout;
    dimensions->addWidget(new QLabel("Pixels per line:"));
    perLineSpin_ = new QSpinBox;
    perLineSpin_->setRange(1, 4096);
    perLineSpin_->setValue(256);
    dimensions->addWidget(perLineSpin_);
    dimensions->addWidget(new QLabel("Rows:"));
    rowsSpin_ = new QSpinBox;
    rowsSpin_->setRange(1, 4096);
    rowsSpin_->setValue(256);
    dimensions->addWidget(rowsSpin_);
    dimensions->addStretch();
    v->addLayout(dimensions);
    statusLabel_ = new QLabel("No memory loaded.");
    statusLabel_->setProperty("secondary", true);
    statusLabel_->setWordWrap(true);
    v->addWidget(statusLabel_);

    view_ = new MemPixelView;
    auto* scroll = new QScrollArea;
    scroll->setWidget(view_);
    scroll->setWidgetResizable(false);
    v->addWidget(scroll, 1);

    connect(fetchBtn, &QPushButton::clicked, this, &GraphicalMemoryView::fetch);
    connect(addrEdit_, &QLineEdit::returnPressed, this, &GraphicalMemoryView::fetch);
    // Changing pixels-per-line or rows re-reads and re-lays-out the image (which
    // also refreshes the scroll range); previously perLine only repainted at the
    // old size and rows did nothing, leaving the scrollbar stale.
    connect(perLineSpin_, &QSpinBox::valueChanged, this, &GraphicalMemoryView::fetch);
    connect(rowsSpin_, &QSpinBox::valueChanged, this, &GraphicalMemoryView::fetch);
    view_->setPerLine(256);
}

void GraphicalMemoryView::gotoAddress(uintptr_t addr) {
    addrEdit_->setText(QString("0x%1").arg((qulonglong)addr, 0, 16));
    fetch();
}

void GraphicalMemoryView::fetch() {
    if (!proc_) return;
    bool valid = false;
    uintptr_t addr = addrEdit_->text().trimmed().toULongLong(&valid, 16);
    if (!valid) {
        statusLabel_->setText("Enter a valid hexadecimal address.");
        addrEdit_->setFocus(); addrEdit_->selectAll();
        return;
    }
    int perLine = perLineSpin_->value();
    size_t count = (size_t)perLine * rowsSpin_->value();
    std::vector<uint8_t> buf(count);
    auto r = proc_->read(addr, buf.data(), buf.size());
    size_t got = (r && *r > 0) ? *r : 0;
    statusLabel_->setText(got ? QString("Read %1 of %2 bytes at 0x%3.").arg(got).arg(count).arg(addr, 0, 16)
                             : QString("Could not read memory at 0x%1.").arg(addr, 0, 16));
    buf.resize(got);
    view_->setPerLine(perLine);
    view_->setData(std::move(buf));
    view_->resize(view_->sizeHint());
}

}  // namespace ce::gui
