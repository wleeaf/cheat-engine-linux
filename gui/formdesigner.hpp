#pragma once
/// Form designer — visual builder for Lua trainer UIs.
///
/// Canvas supports click-to-select and drag-to-move on placed widgets.
/// Sizing is via the right-pane spinboxes (drag-resize handles are a
/// future enhancement).

#include <QMainWindow>
#include <QListWidget>
#include <QSpinBox>
#include <QLineEdit>
#include <QComboBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QPoint>
#include <vector>
#include <memory>

namespace ce::gui {

struct FormItem {
    QString type;     // "Button", "Label", "Edit", "CheckBox", "Memo", "GroupBox"
    QString name;     // Lua-side identifier
    QString caption;
    int x = 10, y = 10, w = 100, h = 24;
};

class FormDesigner : public QMainWindow {
    Q_OBJECT
public:
    explicit FormDesigner(QWidget* parent = nullptr);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void onAddWidget();
    void onItemSelected();
    void onPropertyChanged();
    void onSave();
    void onLoad();
    void onGenerateLua();
    void onDelete();

private:
    void redrawCanvas();
    void syncPropertiesFromSelection();

    // Layout
    QListWidget* paletteList_;
    QListWidget* itemList_;
    QWidget*     canvas_;
    QSpinBox*    xSpin_;
    QSpinBox*    ySpin_;
    QSpinBox*    wSpin_;
    QSpinBox*    hSpin_;
    QLineEdit*   nameEdit_;
    QLineEdit*   captionEdit_;
    QPlainTextEdit* luaPreview_;

    // Model
    std::vector<FormItem> items_;
    int selected_ = -1;
    int formWidth_ = 400, formHeight_ = 300;

    // Drag state
    enum class DragMode { None, Move, Resize };
    DragMode dragMode_ = DragMode::None;
    QPoint   dragStartMouse_;     // global mouse pos at drag start
    int      dragStartItemX_ = 0;
    int      dragStartItemY_ = 0;
    int      dragStartItemW_ = 0;
    int      dragStartItemH_ = 0;
};

} // namespace ce::gui
