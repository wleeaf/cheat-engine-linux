/// Form designer — three-pane layout (palette, canvas, properties).

#include "gui/formdesigner.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QFormLayout>
#include <QPushButton>
#include <QFrame>
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QPainter>
#include <QPaintEvent>
#include <QMouseEvent>
#include <QEvent>
#include <QShortcut>
#include <QKeySequence>
#include <QApplication>
#include <QClipboard>
#include <QCheckBox>
#include <QGroupBox>
#include <QPushButton>

namespace ce::gui {

FormDesigner::FormDesigner(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("Form Designer");
    resize(1100, 720);

    auto* central = new QWidget;
    auto* root = new QHBoxLayout(central);

    // ── Palette pane (left) ──
    auto* paletteCol = new QVBoxLayout;
    paletteCol->addWidget(new QLabel("<b>Palette</b>"));
    paletteList_ = new QListWidget;
    paletteList_->addItems({"Button", "Label", "Edit", "CheckBox", "Memo", "GroupBox", "Panel"});
    paletteList_->setCurrentRow(0);
    paletteCol->addWidget(paletteList_);
    auto* addBtn = new QPushButton("Add to form");
    connect(addBtn, &QPushButton::clicked, this, &FormDesigner::onAddWidget);
    paletteCol->addWidget(addBtn);

    paletteCol->addWidget(new QLabel("<b>Items</b>"));
    itemList_ = new QListWidget;
    paletteCol->addWidget(itemList_, 1);
    auto* delBtn = new QPushButton("Delete");
    connect(delBtn, &QPushButton::clicked, this, &FormDesigner::onDelete);
    paletteCol->addWidget(delBtn);
    connect(itemList_, &QListWidget::currentRowChanged, this, &FormDesigner::onItemSelected);

    auto* paletteWidget = new QWidget;
    paletteWidget->setLayout(paletteCol);
    paletteWidget->setFixedWidth(220);
    root->addWidget(paletteWidget);

    // ── Canvas + Lua preview (center, vertical split) ──
    auto* centerSplit = new QSplitter(Qt::Vertical);

    canvas_ = new QWidget;
    canvas_->setStyleSheet("background-color: #313244; border: 1px dashed #6c7086;");
    canvas_->setFixedSize(formWidth_, formHeight_);
    auto* canvasWrap = new QWidget;
    auto* canvasLayout = new QVBoxLayout(canvasWrap);
    canvasLayout->addWidget(new QLabel("<b>Canvas</b> — click a widget on the canvas or in the Items list to select it"));
    canvasLayout->addWidget(canvas_);
    canvasLayout->addStretch();
    centerSplit->addWidget(canvasWrap);

    auto* luaWrap = new QWidget;
    auto* luaLayout = new QVBoxLayout(luaWrap);
    auto* luaHeader = new QHBoxLayout;
    luaHeader->addWidget(new QLabel("<b>Generated Lua</b>"));
    auto* regenBtn = new QPushButton("Refresh");
    connect(regenBtn, &QPushButton::clicked, this, &FormDesigner::onGenerateLua);
    luaHeader->addStretch();
    luaHeader->addWidget(regenBtn);
    luaLayout->addLayout(luaHeader);
    luaPreview_ = new QPlainTextEdit;
    luaPreview_->setReadOnly(true);
    luaPreview_->setFont(QFont("Monospace", 9));
    luaLayout->addWidget(luaPreview_);
    centerSplit->addWidget(luaWrap);
    centerSplit->setStretchFactor(0, 3);
    centerSplit->setStretchFactor(1, 2);
    root->addWidget(centerSplit, 1);

    // ── Properties pane (right) ──
    auto* propsCol = new QVBoxLayout;
    propsCol->addWidget(new QLabel("<b>Form</b>"));
    {
        auto* form = new QFormLayout;
        auto* fw = new QSpinBox; fw->setRange(50, 4000); fw->setValue(formWidth_);
        auto* fh = new QSpinBox; fh->setRange(50, 4000); fh->setValue(formHeight_);
        connect(fw, qOverload<int>(&QSpinBox::valueChanged), this, [this, fw](int v) {
            formWidth_ = v; canvas_->setFixedSize(formWidth_, formHeight_); redrawCanvas();
        });
        connect(fh, qOverload<int>(&QSpinBox::valueChanged), this, [this, fh](int v) {
            formHeight_ = v; canvas_->setFixedSize(formWidth_, formHeight_); redrawCanvas();
        });
        form->addRow("Width:", fw);
        form->addRow("Height:", fh);
        propsCol->addLayout(form);
    }

    propsCol->addWidget(new QLabel("<b>Selected widget</b>"));
    auto* propForm = new QFormLayout;
    nameEdit_ = new QLineEdit;
    captionEdit_ = new QLineEdit;
    xSpin_ = new QSpinBox; xSpin_->setRange(0, 4000);
    ySpin_ = new QSpinBox; ySpin_->setRange(0, 4000);
    wSpin_ = new QSpinBox; wSpin_->setRange(1, 4000); wSpin_->setValue(100);
    hSpin_ = new QSpinBox; hSpin_->setRange(1, 4000); hSpin_->setValue(24);
    propForm->addRow("Name:",    nameEdit_);
    propForm->addRow("Caption:", captionEdit_);
    propForm->addRow("X:",       xSpin_);
    propForm->addRow("Y:",       ySpin_);
    propForm->addRow("Width:",   wSpin_);
    propForm->addRow("Height:",  hSpin_);
    propsCol->addLayout(propForm);

    for (auto* w : std::vector<QWidget*>{nameEdit_, captionEdit_, xSpin_, ySpin_, wSpin_, hSpin_}) {
        auto* le = qobject_cast<QLineEdit*>(w);
        auto* sb = qobject_cast<QSpinBox*>(w);
        if (le) connect(le, &QLineEdit::editingFinished, this, &FormDesigner::onPropertyChanged);
        if (sb) connect(sb, qOverload<int>(&QSpinBox::valueChanged), this,
            [this](int) { onPropertyChanged(); });
    }

    propsCol->addStretch();
    auto* saveBtn = new QPushButton("Save layout (.json)…");
    auto* loadBtn = new QPushButton("Load layout (.json)…");
    auto* exportBtn = new QPushButton("Copy Lua to clipboard");
    connect(saveBtn, &QPushButton::clicked, this, &FormDesigner::onSave);
    connect(loadBtn, &QPushButton::clicked, this, &FormDesigner::onLoad);
    connect(exportBtn, &QPushButton::clicked, this, [this]() {
        onGenerateLua();
        QApplication::clipboard()->setText(luaPreview_->toPlainText());
    });
    propsCol->addWidget(saveBtn);
    propsCol->addWidget(loadBtn);
    propsCol->addWidget(exportBtn);

    auto* propsWidget = new QWidget;
    propsWidget->setLayout(propsCol);
    propsWidget->setFixedWidth(280);
    root->addWidget(propsWidget);

    setCentralWidget(central);

    // Delete key removes the selected widget. WindowShortcut scope so the
    // shortcut fires regardless of which inner widget has focus.
    auto* delShortcut = new QShortcut(QKeySequence(Qt::Key_Delete), this);
    delShortcut->setContext(Qt::WindowShortcut);
    connect(delShortcut, &QShortcut::activated, this, &FormDesigner::onDelete);

    redrawCanvas();
    onGenerateLua();
}

void FormDesigner::redrawCanvas() {
    // Drop existing child widgets — we rebuild from items_.
    for (auto* c : canvas_->findChildren<QWidget*>())
        c->deleteLater();

    for (size_t i = 0; i < items_.size(); ++i) {
        const auto& it = items_[i];
        QWidget* w = nullptr;
        // Concrete previews — using the lightest matching Qt widget so the
        // canvas LOOKS roughly like the runtime form.
        if (it.type == "Button") {
            auto* b = new QPushButton(it.caption.isEmpty() ? it.name : it.caption, canvas_);
            w = b;
        } else if (it.type == "Label") {
            w = new QLabel(it.caption, canvas_);
        } else if (it.type == "Edit") {
            auto* e = new QLineEdit(canvas_);
            e->setText(it.caption);
            w = e;
        } else if (it.type == "CheckBox") {
            auto* c = new QCheckBox(it.caption, canvas_);
            w = c;
        } else if (it.type == "Memo") {
            auto* m = new QPlainTextEdit(canvas_);
            m->setPlainText(it.caption);
            w = m;
        } else if (it.type == "GroupBox") {
            auto* g = new QGroupBox(it.caption, canvas_);
            w = g;
        } else if (it.type == "Panel") {
            auto* f = new QFrame(canvas_);
            f->setFrameShape(QFrame::Panel);
            f->setFrameShadow(QFrame::Raised);
            w = f;
        }
        if (!w) continue;
        w->setGeometry(it.x, it.y, it.w, it.h);
        if ((int)i == selected_)
            w->setStyleSheet(w->styleSheet() + " border: 2px solid #f9e2af;");
        // Stash the item index on the widget and install our event filter
        // so a click on it selects + a drag moves it.
        w->setProperty("ce_form_item_index", (int)i);
        w->setMouseTracking(true);
        w->installEventFilter(this);
        // Disable the widget's own input semantics so a click drives the
        // designer's drag logic rather than e.g. activating a button.
        w->setAttribute(Qt::WA_TransparentForMouseEvents, false);
        w->setEnabled(true);
        if (auto* btn = qobject_cast<QPushButton*>(w))      btn->setEnabled(false);
        else if (auto* ed = qobject_cast<QLineEdit*>(w))     ed->setReadOnly(true);
        else if (auto* cb = qobject_cast<QCheckBox*>(w))     cb->setEnabled(false);
        else if (auto* mm = qobject_cast<QPlainTextEdit*>(w)) mm->setReadOnly(true);
        w->show();
    }
}

bool FormDesigner::eventFilter(QObject* watched, QEvent* event) {
    auto* w = qobject_cast<QWidget*>(watched);
    if (!w || w->parent() != canvas_) return QMainWindow::eventFilter(watched, event);

    bool indexValid = false;
    int index = w->property("ce_form_item_index").toInt(&indexValid);
    if (!indexValid || index < 0 || index >= (int)items_.size())
        return QMainWindow::eventFilter(watched, event);

    // Bottom-right 10×10 px area is the resize handle.
    auto isResizeZone = [&](const QPoint& localPos) {
        constexpr int handle = 10;
        return localPos.x() >= w->width() - handle &&
               localPos.y() >= w->height() - handle;
    };

    if (event->type() == QEvent::MouseMove && dragMode_ == DragMode::None) {
        auto* me = static_cast<QMouseEvent*>(event);
        w->setCursor(isResizeZone(me->position().toPoint())
                     ? Qt::SizeFDiagCursor
                     : Qt::SizeAllCursor);
    }

    if (event->type() == QEvent::MouseButtonPress) {
        auto* me = static_cast<QMouseEvent*>(event);
        if (me->button() == Qt::LeftButton) {
            selected_ = index;
            itemList_->setCurrentRow(index);
            syncPropertiesFromSelection();
            dragMode_ = isResizeZone(me->position().toPoint())
                        ? DragMode::Resize
                        : DragMode::Move;
            dragStartMouse_ = me->globalPosition().toPoint();
            dragStartItemX_ = items_[index].x;
            dragStartItemY_ = items_[index].y;
            dragStartItemW_ = items_[index].w;
            dragStartItemH_ = items_[index].h;
            return true;
        }
    } else if (event->type() == QEvent::MouseMove) {
        if (dragMode_ != DragMode::None) {
            auto* me = static_cast<QMouseEvent*>(event);
            QPoint delta = me->globalPosition().toPoint() - dragStartMouse_;
            auto& it = items_[index];
            if (dragMode_ == DragMode::Move) {
                it.x = std::max(0, dragStartItemX_ + delta.x());
                it.y = std::max(0, dragStartItemY_ + delta.y());
                w->move(it.x, it.y);
                QSignalBlocker bx(xSpin_), by(ySpin_);
                xSpin_->setValue(it.x);
                ySpin_->setValue(it.y);
            } else {
                it.w = std::max(1, dragStartItemW_ + delta.x());
                it.h = std::max(1, dragStartItemH_ + delta.y());
                w->resize(it.w, it.h);
                QSignalBlocker bw(wSpin_), bh(hSpin_);
                wSpin_->setValue(it.w);
                hSpin_->setValue(it.h);
            }
            return true;
        }
    } else if (event->type() == QEvent::MouseButtonRelease) {
        if (dragMode_ != DragMode::None) {
            dragMode_ = DragMode::None;
            onGenerateLua();
            redrawCanvas();
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void FormDesigner::onAddWidget() {
    auto* sel = paletteList_->currentItem();
    if (!sel) return;
    FormItem it;
    it.type = sel->text();
    it.name = QString("%1%2").arg(it.type.toLower()).arg(items_.size() + 1);
    it.caption = it.name;
    if (it.type == "Memo")    { it.w = 200; it.h = 100; }
    if (it.type == "GroupBox") { it.w = 200; it.h = 100; }
    if (it.type == "Panel")   { it.w = 200; it.h = 100; }
    items_.push_back(it);
    itemList_->addItem(QString("%1 — %2").arg(it.type).arg(it.name));
    itemList_->setCurrentRow(itemList_->count() - 1);
    redrawCanvas();
    onGenerateLua();
}

void FormDesigner::onDelete() {
    if (selected_ < 0 || selected_ >= (int)items_.size()) return;
    items_.erase(items_.begin() + selected_);
    delete itemList_->takeItem(selected_);
    selected_ = -1;
    redrawCanvas();
    onGenerateLua();
}

void FormDesigner::onItemSelected() {
    selected_ = itemList_->currentRow();
    syncPropertiesFromSelection();
    redrawCanvas();
}

void FormDesigner::syncPropertiesFromSelection() {
    if (selected_ < 0 || selected_ >= (int)items_.size()) {
        nameEdit_->setText(""); captionEdit_->setText("");
        xSpin_->setValue(0); ySpin_->setValue(0);
        wSpin_->setValue(100); hSpin_->setValue(24);
        return;
    }
    const auto& it = items_[selected_];
    QSignalBlocker b1(nameEdit_), b2(captionEdit_), b3(xSpin_), b4(ySpin_), b5(wSpin_), b6(hSpin_);
    nameEdit_->setText(it.name);
    captionEdit_->setText(it.caption);
    xSpin_->setValue(it.x);
    ySpin_->setValue(it.y);
    wSpin_->setValue(it.w);
    hSpin_->setValue(it.h);
}

void FormDesigner::onPropertyChanged() {
    if (selected_ < 0 || selected_ >= (int)items_.size()) return;
    auto& it = items_[selected_];
    it.name    = nameEdit_->text();
    it.caption = captionEdit_->text();
    it.x = xSpin_->value(); it.y = ySpin_->value();
    it.w = wSpin_->value(); it.h = hSpin_->value();
    itemList_->item(selected_)->setText(QString("%1 — %2").arg(it.type).arg(it.name));
    redrawCanvas();
    onGenerateLua();
}

void FormDesigner::onSave() {
    auto path = QFileDialog::getSaveFileName(this, "Save form layout", "form.json", "JSON (*.json)");
    if (path.isEmpty()) return;
    QJsonObject root;
    root["formWidth"] = formWidth_;
    root["formHeight"] = formHeight_;
    QJsonArray arr;
    for (const auto& it : items_) {
        QJsonObject o;
        o["type"]    = it.type;
        o["name"]    = it.name;
        o["caption"] = it.caption;
        o["x"] = it.x; o["y"] = it.y;
        o["w"] = it.w; o["h"] = it.h;
        arr.append(o);
    }
    root["items"] = arr;
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Save failed", f.errorString());
        return;
    }
    f.write(QJsonDocument(root).toJson());
}

void FormDesigner::onLoad() {
    auto path = QFileDialog::getOpenFileName(this, "Load form layout", "", "JSON (*.json)");
    if (path.isEmpty()) return;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Load failed", f.errorString());
        return;
    }
    auto doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) {
        QMessageBox::warning(this, "Load failed", "Not a valid form layout file.");
        return;
    }
    auto root = doc.object();
    formWidth_  = root.value("formWidth").toInt(400);
    formHeight_ = root.value("formHeight").toInt(300);
    canvas_->setFixedSize(formWidth_, formHeight_);
    items_.clear();
    itemList_->clear();
    selected_ = -1;
    for (const auto& v : root.value("items").toArray()) {
        auto o = v.toObject();
        FormItem it;
        it.type    = o.value("type").toString();
        it.name    = o.value("name").toString();
        it.caption = o.value("caption").toString();
        it.x = o.value("x").toInt(); it.y = o.value("y").toInt();
        it.w = o.value("w").toInt(100); it.h = o.value("h").toInt(24);
        items_.push_back(it);
        itemList_->addItem(QString("%1 — %2").arg(it.type).arg(it.name));
    }
    redrawCanvas();
    onGenerateLua();
}

void FormDesigner::onGenerateLua() {
    QString out;
    out += "-- Generated by cecore Form Designer\n";
    out += QString("local form = createForm(true)\n");
    out += QString("form.Caption = \"Form\"\n");
    out += QString("form.Width = %1\n").arg(formWidth_);
    out += QString("form.Height = %1\n").arg(formHeight_);
    for (const auto& it : items_) {
        QString creator;
        if      (it.type == "Button")   creator = "createButton";
        else if (it.type == "Label")    creator = "createLabel";
        else if (it.type == "Edit")     creator = "createEdit";
        else if (it.type == "CheckBox") creator = "createCheckBox";
        else if (it.type == "Memo")     creator = "createMemo";
        else if (it.type == "GroupBox") creator = "createGroupBox";
        else if (it.type == "Panel")    creator = "createPanel";
        else continue;
        out += QString("local %1 = %2(form)\n").arg(it.name).arg(creator);
        QString safeCaption = it.caption;
        safeCaption.replace('\\', "\\\\"); // escape backslash first
        safeCaption.replace('"', "\\\"");
        out += QString("%1.Caption = \"%2\"\n").arg(it.name).arg(safeCaption);
        out += QString("%1.Left = %2\n").arg(it.name).arg(it.x);
        out += QString("%1.Top = %2\n").arg(it.name).arg(it.y);
        out += QString("%1.Width = %2\n").arg(it.name).arg(it.w);
        out += QString("%1.Height = %2\n").arg(it.name).arg(it.h);
    }
    out += "form:show()\n";
    luaPreview_->setPlainText(out);
}

} // namespace ce::gui
