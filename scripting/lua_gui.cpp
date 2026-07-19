/// Lua GUI bindings — create Qt6 widgets from Lua.
/// Supports: createForm, createButton, createLabel, createEdit, createCheckBox, createListView,
///           createMemo, createPanel, createGroupBox, createTimer, getMainForm.
/// Property access via __index/__newindex metamethods. Font is a sub-object; ws.Font.Size = 14
/// reads/writes the widget's current QFont.

#include "scripting/lua_gui.hpp"
#include "gui/canvaswidget.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <QWidget>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QAction>
#include <QDialog>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QFrame>
#include <QGroupBox>
#include <QCheckBox>
#include <QListWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QApplication>
#include <QMetaObject>
#include <QEvent>
#include <QFont>
#include <QPalette>
#include <QColor>
#include <QStringList>
#include <QPointer>
#include <QScreen>
#include <cstdio>
#include <cstring>
#include <new>
#include <unordered_map>
#include <string>

namespace ce {

struct CallbackBinding {
    int ref = LUA_NOREF;
    QMetaObject::Connection connection;
};

// Store Lua callback references per Qt object.
// INVARIANT: these maps are only touched from the GUI thread (the single Lua
// state lives there). Keys are raw QObject* but each entry is erased
// synchronously by QObject::destroyed (see trackDestroyed / the OnClose lambda)
// before the object's address can be recycled, so stale-key collisions cannot
// occur as long as that single-thread invariant holds.
// TODO(security): move the callback ref into the widget userdata (now that it
// has __gc) to eliminate the global raw-pointer-keyed maps entirely.
static std::unordered_map<QObject*, CallbackBinding> clickCallbacks;
static std::unordered_map<QObject*, CallbackBinding> changeCallbacks;
static std::unordered_map<QObject*, CallbackBinding> closeCallbacks;
static std::unordered_map<QObject*, CallbackBinding> timerCallbacks;
static lua_State* guiLuaState = nullptr;
static QPointer<QMainWindow> guiMainForm;

// ── Widget userdata wrapper ──

struct LuaWidget {
    QPointer<QWidget> widget;
    QPointer<QTimer> timer; // Non-null only for timer objects
};

static const char* WIDGET_MT = "CEWidget";
static const char* WIDGETFONT_MT = "CEWidgetFont";

struct LuaWidgetFont {
    QPointer<QWidget> widget;
};

static LuaWidget* checkWidget(lua_State* L, int idx) {
    return (LuaWidget*)luaL_checkudata(L, idx, WIDGET_MT);
}

// Fetch the live QWidget* from a widget userdata, raising a Lua error if the
// underlying Qt object has already been destroyed (e.g. WA_DeleteOnClose form
// closed, or a parent form took its children down). Guards against UAF.
static QWidget* liveWidget(lua_State* L, int idx) {
    auto* lw = checkWidget(L, idx);
    if (!lw->widget) {
        luaL_error(L, "widget has been destroyed");
        return nullptr; // unreachable; luaL_error does a longjmp
    }
    return lw->widget.data();
}

static void pushWidget(lua_State* L, QWidget* w, QTimer* t = nullptr) {
    auto* lw = (LuaWidget*)lua_newuserdata(L, sizeof(LuaWidget));
    new (lw) LuaWidget();
    lw->widget = w;
    lw->timer = t;
    luaL_setmetatable(L, WIDGET_MT);
}

static int widget_gc(lua_State* L) {
    auto* lw = checkWidget(L, 1);
    lw->~LuaWidget();
    return 0;
}

static void pushWidgetFont(lua_State* L, QWidget* w) {
    auto* f = (LuaWidgetFont*)lua_newuserdata(L, sizeof(LuaWidgetFont));
    new (f) LuaWidgetFont();
    f->widget = w;
    luaL_setmetatable(L, WIDGETFONT_MT);
}

// Parse 0x00BBGGRR (CE's TColor convention) or "#RRGGBB" / "RRGGBB" / Qt color name.
static QColor parseLuaColor(lua_State* L, int idx) {
    if (lua_type(L, idx) == LUA_TNUMBER) {
        unsigned int v = (unsigned int)lua_tointeger(L, idx);
        // CE TColor packs as 0x00BBGGRR — swap to RGB.
        int r = v & 0xFF;
        int g = (v >> 8) & 0xFF;
        int b = (v >> 16) & 0xFF;
        return QColor(r, g, b);
    }
    return QColor(QString::fromUtf8(luaL_checkstring(L, idx)));
}

// Pack QColor as CE-style TColor int 0x00BBGGRR.
static lua_Integer colorToTColor(QColor c) {
    return (lua_Integer)((c.blue() << 16) | (c.green() << 8) | c.red());
}

static void unrefCallback(int ref) {
    if (guiLuaState && ref != LUA_NOREF && ref != LUA_REFNIL)
        luaL_unref(guiLuaState, LUA_REGISTRYINDEX, ref);
}

static void clearCallback(QObject* object, std::unordered_map<QObject*, CallbackBinding>& callbacks) {
    auto it = callbacks.find(object);
    if (it == callbacks.end())
        return;
    QObject::disconnect(it->second.connection);
    unrefCallback(it->second.ref);
    callbacks.erase(it);
}

static int storeCallback(lua_State* L, int index) {
    lua_pushvalue(L, index);
    return luaL_ref(L, LUA_REGISTRYINDEX);
}

static void invokeLuaCallback(int ref, QWidget* widget, QTimer* timer = nullptr) {
    if (!guiLuaState)
        return;

    lua_rawgeti(guiLuaState, LUA_REGISTRYINDEX, ref);
    if (widget)
        pushWidget(guiLuaState, widget, timer);
    else
        lua_pushnil(guiLuaState);
    if (lua_pcall(guiLuaState, 1, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(guiLuaState, -1);
        std::fprintf(stderr, "[CE Lua GUI] callback error: %s\n", err ? err : "unknown error");
        lua_pop(guiLuaState, 1);
    }
}

static void trackDestroyed(QObject* object) {
    QObject::connect(object, &QObject::destroyed, [object]() {
        clearCallback(object, clickCallbacks);
        clearCallback(object, changeCallbacks);
        clearCallback(object, timerCallbacks);
    });
}

// ── Font sub-object ──
static int widgetfont_index(lua_State* L) {
    auto* f = (LuaWidgetFont*)luaL_checkudata(L, 1, WIDGETFONT_MT);
    const char* key = luaL_checkstring(L, 2);
    if (!f->widget) { lua_pushnil(L); return 1; }
    QFont qf = f->widget->font();
    if (!strcmp(key, "Name")) { lua_pushstring(L, qf.family().toUtf8()); return 1; }
    if (!strcmp(key, "Size")) {
        int s = qf.pointSize();
        if (s <= 0) s = qf.pixelSize();
        lua_pushinteger(L, s > 0 ? s : 0); return 1;
    }
    if (!strcmp(key, "Bold")) { lua_pushboolean(L, qf.bold()); return 1; }
    if (!strcmp(key, "Italic")) { lua_pushboolean(L, qf.italic()); return 1; }
    if (!strcmp(key, "Color")) {
        QColor c = f->widget->palette().color(QPalette::WindowText);
        lua_pushinteger(L, colorToTColor(c)); return 1;
    }
    lua_pushnil(L);
    return 1;
}
static int widgetfont_newindex(lua_State* L) {
    auto* f = (LuaWidgetFont*)luaL_checkudata(L, 1, WIDGETFONT_MT);
    if (!f->widget) return 0;
    const char* key = luaL_checkstring(L, 2);
    QFont qf = f->widget->font();
    if (!strcmp(key, "Name"))   { qf.setFamily(luaL_checkstring(L, 3)); f->widget->setFont(qf); return 0; }
    if (!strcmp(key, "Size"))   { qf.setPointSize((int)luaL_checkinteger(L, 3)); f->widget->setFont(qf); return 0; }
    if (!strcmp(key, "Bold"))   { qf.setBold(lua_toboolean(L, 3));   f->widget->setFont(qf); return 0; }
    if (!strcmp(key, "Italic")) { qf.setItalic(lua_toboolean(L, 3)); f->widget->setFont(qf); return 0; }
    if (!strcmp(key, "Color"))  {
        QPalette pal = f->widget->palette();
        pal.setColor(QPalette::WindowText, parseLuaColor(L, 3));
        pal.setColor(QPalette::Text, parseLuaColor(L, 3));
        f->widget->setPalette(pal);
        return 0;
    }
    return 0;
}
static int widgetfont_gc(lua_State* L) {
    auto* f = (LuaWidgetFont*)luaL_checkudata(L, 1, WIDGETFONT_MT);
    f->~LuaWidgetFont();
    return 0;
}

// ── Property get ──
static int widget_index(lua_State* L) {
    auto* lw = checkWidget(L, 1);
    const char* key = luaL_checkstring(L, 2);
    auto* w = liveWidget(L, 1);

    if (!strcmp(key, "Caption") || !strcmp(key, "Text")) {
        if (auto* btn = qobject_cast<QPushButton*>(w)) { lua_pushstring(L, btn->text().toUtf8()); return 1; }
        if (auto* lbl = qobject_cast<QLabel*>(w)) { lua_pushstring(L, lbl->text().toUtf8()); return 1; }
        if (auto* ed = qobject_cast<QLineEdit*>(w)) { lua_pushstring(L, ed->text().toUtf8()); return 1; }
        if (auto* memo = qobject_cast<QPlainTextEdit*>(w)) { lua_pushstring(L, memo->toPlainText().toUtf8()); return 1; }
        if (auto* gb = qobject_cast<QGroupBox*>(w)) { lua_pushstring(L, gb->title().toUtf8()); return 1; }
        if (auto* list = qobject_cast<QListWidget*>(w)) {
            auto* item = list->currentItem();
            lua_pushstring(L, item ? item->text().toUtf8().constData() : "");
            return 1;
        }
        lua_pushstring(L, w->windowTitle().toUtf8()); return 1;
    }
    if (!strcmp(key, "Title")) {
        if (auto* gb = qobject_cast<QGroupBox*>(w)) { lua_pushstring(L, gb->title().toUtf8()); return 1; }
        lua_pushstring(L, w->windowTitle().toUtf8()); return 1;
    }
    if (!strcmp(key, "Width"))  { lua_pushinteger(L, w->width());  return 1; }
    if (!strcmp(key, "Height")) { lua_pushinteger(L, w->height()); return 1; }
    if (!strcmp(key, "Top"))    { lua_pushinteger(L, w->y()); return 1; }
    if (!strcmp(key, "Left"))   { lua_pushinteger(L, w->x()); return 1; }
    if (!strcmp(key, "Visible")) { lua_pushboolean(L, w->isVisible()); return 1; }
    if (!strcmp(key, "Enabled")) {
        lua_pushboolean(L, lw->timer ? lw->timer->isActive() : w->isEnabled());
        return 1;
    }
    if (!strcmp(key, "Hint"))   { lua_pushstring(L, w->toolTip().toUtf8()); return 1; }
    if (!strcmp(key, "Color"))  {
        QColor c = w->palette().color(QPalette::Window);
        lua_pushinteger(L, colorToTColor(c)); return 1;
    }
    if (!strcmp(key, "Font"))   { pushWidgetFont(L, w); return 1; }
    if (!strcmp(key, "Checked")) {
        if (auto* cb = qobject_cast<QCheckBox*>(w)) { lua_pushboolean(L, cb->isChecked()); return 1; }
    }
    if (!strcmp(key, "Count")) {
        if (auto* list = qobject_cast<QListWidget*>(w)) { lua_pushinteger(L, list->count()); return 1; }
    }
    if (!strcmp(key, "Interval") && lw->timer) { lua_pushinteger(L, lw->timer->interval()); return 1; }

    if (!strcmp(key, "Lines")) {
        if (auto* memo = qobject_cast<QPlainTextEdit*>(w)) {
            QStringList ls = memo->toPlainText().split('\n');
            lua_newtable(L);
            for (int i = 0; i < ls.size(); ++i) {
                lua_pushstring(L, ls[i].toUtf8());
                lua_rawseti(L, -2, i + 1);
            }
            return 1;
        }
    }

    // Method: show, close
    if (!strcmp(key, "show")) {
        lua_pushcfunction(L, [](lua_State* L) -> int { liveWidget(L, 1)->show(); return 0; });
        return 1;
    }
    if (!strcmp(key, "hide")) {
        lua_pushcfunction(L, [](lua_State* L) -> int { liveWidget(L, 1)->hide(); return 0; });
        return 1;
    }
    if (!strcmp(key, "close")) {
        lua_pushcfunction(L, [](lua_State* L) -> int { liveWidget(L, 1)->close(); return 0; });
        return 1;
    }
    if (!strcmp(key, "centerScreen") || !strcmp(key, "Centered")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = liveWidget(L, 1);
            if (auto* screen = w->screen()) {
                QRect avail = screen->availableGeometry();
                w->move(avail.center() - w->rect().center());
            }
            return 0;
        });
        return 1;
    }
    if (!strcmp(key, "showModal")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = liveWidget(L, 1);
            if (auto* dlg = qobject_cast<QDialog*>(w)) dlg->exec();
            else w->show();
            return 0;
        });
        return 1;
    }
    if (!strcmp(key, "addItem")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = liveWidget(L, 1);
            auto* list = qobject_cast<QListWidget*>(w);
            if (list) list->addItem(luaL_checkstring(L, 2));
            return 0;
        });
        return 1;
    }
    if (!strcmp(key, "addLine")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = liveWidget(L, 1);
            const char* line = luaL_checkstring(L, 2);
            if (auto* memo = qobject_cast<QPlainTextEdit*>(w)) memo->appendPlainText(line);
            return 0;
        });
        return 1;
    }
    if (!strcmp(key, "clear")) {
        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* w = liveWidget(L, 1);
            if (auto* list = qobject_cast<QListWidget*>(w)) list->clear();
            else if (auto* memo = qobject_cast<QPlainTextEdit*>(w)) memo->clear();
            else if (auto* ed = qobject_cast<QLineEdit*>(w)) ed->clear();
            return 0;
        });
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

// ── Property set ──
static int widget_newindex(lua_State* L) {
    auto* lw = checkWidget(L, 1);
    const char* key = luaL_checkstring(L, 2);
    auto* w = liveWidget(L, 1);

    if (!strcmp(key, "Caption") || !strcmp(key, "Text")) {
        const char* val = luaL_checkstring(L, 3);
        if (auto* btn = qobject_cast<QPushButton*>(w)) btn->setText(val);
        else if (auto* lbl = qobject_cast<QLabel*>(w)) lbl->setText(val);
        else if (auto* ed = qobject_cast<QLineEdit*>(w)) ed->setText(val);
        else if (auto* memo = qobject_cast<QPlainTextEdit*>(w)) memo->setPlainText(val);
        else if (auto* gb = qobject_cast<QGroupBox*>(w)) gb->setTitle(val);
        else if (auto* list = qobject_cast<QListWidget*>(w)) {
            if (auto* item = list->currentItem()) item->setText(val);
        }
        else w->setWindowTitle(val);
        return 0;
    }
    if (!strcmp(key, "Title")) {
        const char* val = luaL_checkstring(L, 3);
        if (auto* gb = qobject_cast<QGroupBox*>(w)) gb->setTitle(val);
        else w->setWindowTitle(val);
        return 0;
    }
    if (!strcmp(key, "Width"))  { w->resize((int)luaL_checkinteger(L, 3), w->height()); return 0; }
    if (!strcmp(key, "Height")) { w->resize(w->width(), (int)luaL_checkinteger(L, 3)); return 0; }
    if (!strcmp(key, "Top"))    { w->move(w->x(), (int)luaL_checkinteger(L, 3)); return 0; }
    if (!strcmp(key, "Left"))   { w->move((int)luaL_checkinteger(L, 3), w->y()); return 0; }
    if (!strcmp(key, "Hint"))   { w->setToolTip(luaL_checkstring(L, 3)); return 0; }
    if (!strcmp(key, "Color"))  {
        QPalette pal = w->palette();
        pal.setColor(QPalette::Window, parseLuaColor(L, 3));
        pal.setColor(QPalette::Base,   parseLuaColor(L, 3));
        w->setAutoFillBackground(true);
        w->setPalette(pal);
        return 0;
    }
    if (!strcmp(key, "Lines")) {
        if (auto* memo = qobject_cast<QPlainTextEdit*>(w)) {
            luaL_checktype(L, 3, LUA_TTABLE);
            QStringList ls;
            int n = (int)lua_rawlen(L, 3);
            for (int i = 1; i <= n; ++i) {
                lua_rawgeti(L, 3, i);
                ls << QString::fromUtf8(luaL_optstring(L, -1, ""));
                lua_pop(L, 1);
            }
            memo->setPlainText(ls.join('\n'));
            return 0;
        }
        return 0;
    }
    if (!strcmp(key, "Visible")) { w->setVisible(lua_toboolean(L, 3)); return 0; }
    if (!strcmp(key, "Enabled")) {
        if (lw->timer) {
            if (lua_toboolean(L, 3)) lw->timer->start();
            else lw->timer->stop();
        } else {
            w->setEnabled(lua_toboolean(L, 3));
        }
        return 0;
    }
    if (!strcmp(key, "Checked")) {
        if (auto* cb = qobject_cast<QCheckBox*>(w)) cb->setChecked(lua_toboolean(L, 3));
        return 0;
    }
    if (!strcmp(key, "Interval") && lw->timer) { lw->timer->setInterval(luaL_checkinteger(L, 3)); return 0; }

    // Event handlers
    if (!strcmp(key, "OnClick")) {
        clearCallback(w, clickCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        if (auto* btn = qobject_cast<QPushButton*>(w)) {
            binding.connection = QObject::connect(btn, &QPushButton::clicked, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            clickCallbacks[w] = binding;
            return 0;
        } else if (auto* cb = qobject_cast<QCheckBox*>(w)) {
            binding.connection = QObject::connect(cb, &QCheckBox::toggled, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            clickCallbacks[w] = binding;
            return 0;
        }
        unrefCallback(ref);
        return 0;
    }
    if (!strcmp(key, "OnChange")) {
        clearCallback(w, changeCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        if (auto* ed = qobject_cast<QLineEdit*>(w)) {
            binding.connection = QObject::connect(ed, &QLineEdit::textChanged, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            changeCallbacks[w] = binding;
            return 0;
        } else if (auto* cb = qobject_cast<QCheckBox*>(w)) {
            binding.connection = QObject::connect(cb, &QCheckBox::toggled, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            changeCallbacks[w] = binding;
            return 0;
        } else if (auto* list = qobject_cast<QListWidget*>(w)) {
            binding.connection = QObject::connect(list, &QListWidget::currentRowChanged, [ref, w]() {
                invokeLuaCallback(ref, w);
            });
            changeCallbacks[w] = binding;
            return 0;
        }
        unrefCallback(ref);
        return 0;
    }
    if (!strcmp(key, "OnClose")) {
        clearCallback(w, closeCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        binding.connection = QObject::connect(w, &QObject::destroyed, [ref, w]() {
            invokeLuaCallback(ref, nullptr);
            unrefCallback(ref);
            closeCallbacks.erase(w);
        });
        closeCallbacks[w] = binding;
        return 0;
    }
    if (!strcmp(key, "OnTimer") && lw->timer) {
        QTimer* tmr = lw->timer.data();
        clearCallback(tmr, timerCallbacks);
        if (lua_isnil(L, 3))
            return 0;
        luaL_checktype(L, 3, LUA_TFUNCTION);
        int ref = storeCallback(L, 3);
        CallbackBinding binding;
        binding.ref = ref;
        binding.connection = QObject::connect(tmr, &QTimer::timeout, [ref, w, timer = tmr]() {
            invokeLuaCallback(ref, w, timer);
        });
        timerCallbacks[tmr] = binding;
        return 0;
    }

    return 0;
}

// ── Widget creation functions ──

static QWidget* getParentWidget(lua_State* L, int idx) {
    if (lua_isuserdata(L, idx)) {
        auto* lw = (LuaWidget*)luaL_testudata(L, idx, WIDGET_MT);
        if (lw) return lw->widget;
    }
    return nullptr;
}

static int l_createForm(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* w = new QWidget(parent);
    w->setWindowTitle("Form");
    w->resize(400, 300);
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->setLayout(new QVBoxLayout);
    trackDestroyed(w);
    pushWidget(L, w);
    return 1;
}

static int l_createButton(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* btn = new QPushButton("Button", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(btn);
    trackDestroyed(btn);
    pushWidget(L, btn);
    return 1;
}

static int l_createLabel(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* lbl = new QLabel("Label", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(lbl);
    trackDestroyed(lbl);
    pushWidget(L, lbl);
    return 1;
}

static int l_createEdit(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* ed = new QLineEdit(parent);
    if (parent && parent->layout()) parent->layout()->addWidget(ed);
    trackDestroyed(ed);
    pushWidget(L, ed);
    return 1;
}

static int l_createCheckBox(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* cb = new QCheckBox("CheckBox", parent);
    if (parent && parent->layout()) parent->layout()->addWidget(cb);
    trackDestroyed(cb);
    pushWidget(L, cb);
    return 1;
}

static int l_createListView(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* list = new QListWidget(parent);
    if (parent && parent->layout()) parent->layout()->addWidget(list);
    trackDestroyed(list);
    pushWidget(L, list);
    return 1;
}

static int l_createMemo(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* memo = new QPlainTextEdit(parent);
    if (parent && parent->layout()) parent->layout()->addWidget(memo);
    trackDestroyed(memo);
    pushWidget(L, memo);
    return 1;
}

static int l_createPanel(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* panel = new QFrame(parent);
    panel->setFrameShape(QFrame::StyledPanel);
    panel->setLayout(new QVBoxLayout);
    if (parent && parent->layout()) parent->layout()->addWidget(panel);
    trackDestroyed(panel);
    pushWidget(L, panel);
    return 1;
}

static int l_createGroupBox(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* gb = new QGroupBox(parent);
    gb->setTitle("Group");
    gb->setLayout(new QVBoxLayout);
    if (parent && parent->layout()) parent->layout()->addWidget(gb);
    trackDestroyed(gb);
    pushWidget(L, gb);
    return 1;
}

static int l_getMainForm(lua_State* L) {
    if (!guiMainForm) { lua_pushnil(L); return 1; }
    pushWidget(L, guiMainForm.data());
    return 1;
}

// A "Scripts" menu on the main form, created lazily, that Lua (typically an autorun
// script) populates with tools.
static QPointer<QMenu> guiScriptsMenu;

// addMainMenuItem(caption, onclick) -> boolean. Adds an item to the main window's
// "Scripts" menu that calls the Lua function `onclick` when clicked. Lets an autorun /
// extension script surface a tool in the UI. Returns false if there is no main form.
static int l_addMainMenuItem(lua_State* L) {
    const char* caption = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (!guiMainForm) { lua_pushboolean(L, false); return 1; }
    if (!guiScriptsMenu)
        guiScriptsMenu = guiMainForm->menuBar()->addMenu(QStringLiteral("Scripts"));
    int ref = storeCallback(L, 2);   // the menu item lives for the session; ref persists
    QAction* act = guiScriptsMenu->addAction(QString::fromUtf8(caption));
    QObject::connect(act, &QAction::triggered, act, [ref]() { invokeLuaCallback(ref, nullptr); });
    lua_pushboolean(L, true);
    return 1;
}

// ── Canvas — drawing surface backed by CanvasWidget (QImage) ──

static const char* CANVAS_MT = "CECanvas";

struct LuaCanvas {
    QPointer<ce::gui::CanvasWidget> widget;
};

static LuaCanvas* checkCanvas(lua_State* L, int idx) {
    return (LuaCanvas*)luaL_checkudata(L, idx, CANVAS_MT);
}

// Fetch the live CanvasWidget*, raising a Lua error if it was destroyed.
static ce::gui::CanvasWidget* liveCanvas(lua_State* L, int idx) {
    auto* c = checkCanvas(L, idx);
    if (!c->widget) {
        luaL_error(L, "canvas has been destroyed");
        return nullptr; // unreachable; luaL_error does a longjmp
    }
    return c->widget.data();
}

static int canvas_gc(lua_State* L) {
    auto* c = checkCanvas(L, 1);
    c->~LuaCanvas();
    return 0;
}

static QColor parseCanvasColor(lua_State* L, int idx) {
    if (lua_type(L, idx) == LUA_TNUMBER) {
        unsigned int v = (unsigned int)lua_tointeger(L, idx);
        // CE TColor: 0x00BBGGRR. Match the rest of our bindings.
        return QColor(v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF);
    }
    return QColor(QString::fromUtf8(luaL_checkstring(L, idx)));
}

static int l_canvas_setPenColor(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->setPenColor(parseCanvasColor(L, 2));
    return 0;
}
static int l_canvas_setPenWidth(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->setPenWidth((int)luaL_checkinteger(L, 2));
    return 0;
}
static int l_canvas_setBrushColor(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->setBrushColor(parseCanvasColor(L, 2));
    return 0;
}
static int l_canvas_setFontSize(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->setFontPointSize((int)luaL_checkinteger(L, 2));
    return 0;
}
static int l_canvas_setFontFamily(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->setFontFamily(QString::fromUtf8(luaL_checkstring(L, 2)));
    return 0;
}
static int l_canvas_line(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->drawLine((int)luaL_checkinteger(L, 2),
                        (int)luaL_checkinteger(L, 3),
                        (int)luaL_checkinteger(L, 4),
                        (int)luaL_checkinteger(L, 5));
    return 0;
}
static int l_canvas_rect(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->drawRect((int)luaL_checkinteger(L, 2),
                        (int)luaL_checkinteger(L, 3),
                        (int)luaL_checkinteger(L, 4),
                        (int)luaL_checkinteger(L, 5));
    return 0;
}
static int l_canvas_fillRect(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->fillRect((int)luaL_checkinteger(L, 2),
                        (int)luaL_checkinteger(L, 3),
                        (int)luaL_checkinteger(L, 4),
                        (int)luaL_checkinteger(L, 5));
    return 0;
}
static int l_canvas_text(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->drawText((int)luaL_checkinteger(L, 2),
                        (int)luaL_checkinteger(L, 3),
                        QString::fromUtf8(luaL_checkstring(L, 4)));
    return 0;
}
static int l_canvas_pixel(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->drawPixel((int)luaL_checkinteger(L, 2),
                         (int)luaL_checkinteger(L, 3),
                         parseCanvasColor(L, 4));
    return 0;
}
static int l_canvas_ellipse(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->drawEllipse((int)luaL_checkinteger(L, 2),
                           (int)luaL_checkinteger(L, 3),
                           (int)luaL_checkinteger(L, 4),
                           (int)luaL_checkinteger(L, 5));
    return 0;
}
static int l_canvas_clear(lua_State* L) {
    auto* cw = liveCanvas(L, 1);
    cw->clear();
    return 0;
}

static int l_canvas__index(lua_State* L) {
    luaL_checkudata(L, 1, CANVAS_MT);
    luaL_getmetatable(L, CANVAS_MT);
    lua_pushvalue(L, 2);
    lua_rawget(L, -2);
    return 1;
}

static int l_createCanvas(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    auto* canvas = new ce::gui::CanvasWidget(parent);
    if (parent) {
        canvas->setGeometry(0, 0, parent->width(), parent->height());
        if (parent->layout()) parent->layout()->addWidget(canvas);
        canvas->show();
        canvas->raise();
    }
    trackDestroyed(canvas);
    auto* lc = (LuaCanvas*)lua_newuserdata(L, sizeof(LuaCanvas));
    new (lc) LuaCanvas();
    lc->widget = canvas;
    luaL_setmetatable(L, CANVAS_MT);
    return 1;
}

static int l_createTimer(lua_State* L) {
    auto* parent = getParentWidget(L, 1);
    int enabledIndex = 1;
    if (lua_isuserdata(L, 1) || lua_isnil(L, 1))
        enabledIndex = 2;
    // CE defaults a created timer to enabled=true; only an explicit false disables
    // it. (Previously defaulted to false, so createTimer() never ticked.)
    bool enabled = lua_isnoneornil(L, enabledIndex) ? true : lua_toboolean(L, enabledIndex);

    auto* timer = new QTimer(parent);
    timer->setInterval(1000);
    // Timer doesn't have a visual widget, but we wrap it as one for property access
    auto* dummy = new QWidget(parent); // Hidden
    dummy->hide();
    trackDestroyed(dummy);
    trackDestroyed(timer);
    if (enabled)
        timer->start();
    pushWidget(L, dummy, timer);
    return 1;
}

static int l_getProperty(lua_State* L) {
    return widget_index(L);
}

static int l_setProperty(lua_State* L) {
    return widget_newindex(L);
}

// ── Registration ──

void shutdownLuaGuiBindings() {
    // Null the state FIRST so any Qt callback firing during teardown early-outs
    // in invokeLuaCallback (which checks guiLuaState) instead of touching the
    // about-to-be-freed lua_State; then drop the binding maps. The registry refs
    // they hold are released by the imminent lua_close, so no explicit unref here.
    guiLuaState = nullptr;
    clickCallbacks.clear();
    changeCallbacks.clear();
    closeCallbacks.clear();
    timerCallbacks.clear();
}

void registerLuaGuiBindings(lua_State* L) {
    guiLuaState = L;

    // Create the CEWidget metatable
    luaL_newmetatable(L, WIDGET_MT);
    lua_pushcfunction(L, widget_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, widget_newindex);
    lua_setfield(L, -2, "__newindex");
    lua_pushcfunction(L, widget_gc);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);

    // Create the WidgetFont sub-object metatable
    luaL_newmetatable(L, WIDGETFONT_MT);
    lua_pushcfunction(L, widgetfont_index);    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, widgetfont_newindex); lua_setfield(L, -2, "__newindex");
    lua_pushcfunction(L, widgetfont_gc);       lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);

    // Canvas metatable — drawing methods stored in the metatable itself.
    luaL_newmetatable(L, CANVAS_MT);
    static const luaL_Reg canvasMethods[] = {
        {"setPenColor",   l_canvas_setPenColor},
        {"setPenWidth",   l_canvas_setPenWidth},
        {"setBrushColor", l_canvas_setBrushColor},
        {"setFontSize",   l_canvas_setFontSize},
        {"setFontFamily", l_canvas_setFontFamily},
        {"line",          l_canvas_line},
        {"rect",          l_canvas_rect},
        {"fillRect",      l_canvas_fillRect},
        {"text",          l_canvas_text},
        {"pixel",         l_canvas_pixel},
        {"ellipse",       l_canvas_ellipse},
        {"clear",         l_canvas_clear},
        {nullptr, nullptr},
    };
    luaL_setfuncs(L, canvasMethods, 0);
    lua_pushcfunction(L, l_canvas__index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, canvas_gc);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);

    // Bitmap userdata + createBitmap / loadBitmap globals
    extern void registerBitmapBindings(lua_State* L);
    registerBitmapBindings(L);

    // Register creation functions
    lua_register(L, "createForm", l_createForm);
    lua_register(L, "createButton", l_createButton);
    lua_register(L, "createLabel", l_createLabel);
    lua_register(L, "createEdit", l_createEdit);
    lua_register(L, "createCheckBox", l_createCheckBox);
    lua_register(L, "createListView", l_createListView);
    lua_register(L, "createCanvas", l_createCanvas);
    lua_register(L, "createMemo", l_createMemo);
    lua_register(L, "createPanel", l_createPanel);
    lua_register(L, "createGroupBox", l_createGroupBox);
    lua_register(L, "createTimer", l_createTimer);
    lua_register(L, "getMainForm", l_getMainForm);
    lua_register(L, "addMainMenuItem", l_addMainMenuItem);
    lua_register(L, "getProperty", l_getProperty);
    lua_register(L, "setProperty", l_setProperty);
}

void setLuaMainForm(QMainWindow* w) {
    guiMainForm = w;
}

} // namespace ce
