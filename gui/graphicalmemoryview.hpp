#pragma once
// Graphical Memory View — Cheat Engine's frmMemoryViewExUnit: renders a block of
// target memory as a grid of pixels (one byte = one pixel, greyscale by value),
// with a configurable pixels-per-line, so structures / patterns stand out.

#include "platform/process_api.hpp"

#include <QMainWindow>
#include <QWidget>
#include <cstdint>
#include <vector>

class QLineEdit;
class QSpinBox;

namespace ce::gui {

// The paint surface: draws `data_` as scale×scale pixels, `perLine_` per row.
class MemPixelView : public QWidget {
public:
    using QWidget::QWidget;
    void setData(std::vector<uint8_t> d) { data_ = std::move(d); update(); }
    void setPerLine(int n) { perLine_ = n > 0 ? n : 1; updateGeometry(); update(); }
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;

private:
    std::vector<uint8_t> data_;
    int perLine_ = 256;
    int scale_ = 2;
};

class GraphicalMemoryView : public QMainWindow {
    Q_OBJECT
public:
    explicit GraphicalMemoryView(ce::ProcessHandle* proc, QWidget* parent = nullptr);
    void gotoAddress(uintptr_t addr);

private:
    void fetch();

    ce::ProcessHandle* proc_;
    MemPixelView* view_;
    QLineEdit* addrEdit_;
    QSpinBox* perLineSpin_;
    QSpinBox* rowsSpin_;
};

}  // namespace ce::gui
