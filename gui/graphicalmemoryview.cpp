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
#include <QPaintEvent>
#include <algorithm>
#include <cstring>

namespace ce::gui {

QSize MemPixelView::sizeHint() const {
    if (data_.empty()) return QSize(360, 160);
    int rows = (int)((data_.size() + perLine_ - 1) / perLine_);
    return QSize(perLine_ * scale_, rows * scale_);
}

void MemPixelView::paintEvent(QPaintEvent* event) {
    QPainter p(this);
    if (data_.empty()) {
        p.fillRect(rect(), palette().color(QPalette::Window));
        p.setPen(palette().color(QPalette::Text));
        p.drawText(rect().adjusted(16, 16, -16, -16), Qt::AlignCenter | Qt::TextWordWrap,
                   "Enter an address and press Fetch to visualize memory.");
        return;
    }
    p.fillRect(event->rect(), Qt::black);
    // One byte -> one greyscale pixel; upscale by `scale_`. The image is built
    // once per fetch (row copies, not a setPixel per byte), and a paint scales
    // only the part that is exposed: scrolling a 4096x4096 view stays cheap.
    const int rows = (int)((data_.size() + perLine_ - 1) / perLine_);
    if (image_.isNull()) {
        image_ = QImage(perLine_, rows, QImage::Format_Grayscale8);
        image_.fill(0);
        for (int y = 0; y < rows; ++y) {
            const size_t start = static_cast<size_t>(y) * perLine_;
            std::memcpy(image_.scanLine(y), data_.data() + start, std::min<size_t>(perLine_, data_.size() - start));
        }
    }
    const QRect exposed = event->rect().intersected(QRect(0, 0, perLine_ * scale_, rows * scale_));
    if (exposed.isEmpty()) return;
    const QRect source(exposed.x() / scale_, exposed.y() / scale_,
                       (exposed.width() + scale_ - 1) / scale_ + 1, (exposed.height() + scale_ - 1) / scale_ + 1);
    const QRect clipped = source.intersected(image_.rect());
    p.drawImage(QRect(clipped.x() * scale_, clipped.y() * scale_, clipped.width() * scale_, clipped.height() * scale_),
                image_, clipped);
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
    addrEdit_ = new QLineEdit;
    addrEdit_->setPlaceholderText("address (hex)");
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
    scroll->setAlignment(Qt::AlignCenter);   // the hint, and small images, sit in the middle
    v->addWidget(scroll, 1);

    connect(fetchBtn, &QPushButton::clicked, this, &GraphicalMemoryView::fetch);
    connect(addrEdit_, &QLineEdit::returnPressed, this, &GraphicalMemoryView::fetch);
    // Changing pixels-per-line or rows re-reads and re-lays-out the image (which
    // also refreshes the scroll range); previously perLine only repainted at the
    // old size and rows did nothing, leaving the scrollbar stale.
    // Typing "4096" must not fetch for 4, 40 and 409 on the way.
    perLineSpin_->setKeyboardTracking(false);
    rowsSpin_->setKeyboardTracking(false);
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
    // One byte per pixel, darker = smaller value. Say when the readable memory
    // ended early, so a short image isn't mistaken for a rendering fault.
    if (!got)
        statusLabel_->setText(QString("Could not read memory at 0x%1.").arg(addr, 0, 16));
    else if (got < count)
        statusLabel_->setText(QString("Showing %1 bytes from 0x%2; the memory after 0x%3 is not readable.")
            .arg(got).arg(addr, 0, 16).arg(addr + got, 0, 16));
    else
        statusLabel_->setText(QString("Showing %1 bytes from 0x%2, one byte per pixel (black = 00, white = FF).")
            .arg(got).arg(addr, 0, 16));
    buf.resize(got);
    view_->setPerLine(perLine);
    view_->setData(std::move(buf));
    view_->resize(view_->sizeHint());
}

}  // namespace ce::gui
