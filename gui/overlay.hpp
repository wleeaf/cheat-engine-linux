#pragma once

#include <QElapsedTimer>
#include <QWidget>

namespace ce::gui {

class OverlayWindow : public QWidget {
    Q_OBJECT
public:
    explicit OverlayWindow(QWidget* parent = nullptr);

    void setStatusText(const QString& text);
    void setOsdEnabled(bool enabled);
    void setCrosshairEnabled(bool enabled);
    bool osdEnabled() const { return osdEnabled_; }
    bool crosshairEnabled() const { return crosshairEnabled_; }

protected:
    void paintEvent(QPaintEvent* event) override;

private:
    void updateFpsCounter();

    QString statusText_ = "No process";
    bool osdEnabled_ = true;
    bool crosshairEnabled_ = true;
    int fps_ = 0;
    int frameCounter_ = 0;
    QElapsedTimer fpsTimer_;
};

} // namespace ce::gui
