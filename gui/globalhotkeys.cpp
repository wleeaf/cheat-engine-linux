#include "gui/globalhotkeys.hpp"

#ifndef CECORE_HAVE_X11_HOTKEYS

// Non-X11 build: global hotkeys unavailable; registerHotkey reports failure so
// callers fall back to Qt::ApplicationShortcut.
GlobalHotkeyManager::GlobalHotkeyManager(QObject* parent) : QObject(parent) {}
GlobalHotkeyManager::~GlobalHotkeyManager() {}
bool GlobalHotkeyManager::registerHotkey(int, const QKeySequence&) { return false; }
void GlobalHotkeyManager::unregisterHotkey(int) {}
void GlobalHotkeyManager::clear() {}
void GlobalHotkeyManager::ungrabOne(const Grab&) {}
bool GlobalHotkeyManager::nativeEventFilter(const QByteArray&, void*, qintptr*) { return false; }

#else

#include <QGuiApplication>
#include <QList>

// Qt's X11 native interface (display() = Xlib Display*, connection() = xcb).
#include <QtGui/qguiapplication_platform.h>

// xcb, for decoding the KeyPress events Qt hands us via nativeEventFilter.
#include <xcb/xcb.h>

// Xlib, for XGrabKey / XKeysymToKeycode — simpler than the xcb equivalents and it
// shares Qt's connection. Include LAST and immediately scrub the macros it defines
// (KeyPress, None, Bool, …) that collide with Qt identifiers used elsewhere.
#include <X11/Xlib.h>
#include <X11/keysym.h>
#undef KeyPress
#undef KeyRelease
#undef FocusIn
#undef FocusOut
#undef None
#undef Bool
#undef Status
#undef Unsorted
#undef CursorShape

namespace {

// The X11 lock modifiers (CapsLock, NumLock and their combination) are part of the
// key state, so a grab must be registered for every combination or the hotkey
// silently fails whenever CapsLock/NumLock happens to be on.
constexpr unsigned kLockMasks[] = {
    0,
    LockMask,             // CapsLock
    Mod2Mask,             // NumLock
    LockMask | Mod2Mask,
};

Display* x11Display() {
    if (auto* x11 = qGuiApp->nativeInterface<QNativeInterface::QX11Application>())
        return x11->display();
    return nullptr;
}

unsigned long qtKeyToKeysym(int key) {
    if (key >= Qt::Key_A && key <= Qt::Key_Z) return XK_a + (key - Qt::Key_A);
    if (key >= Qt::Key_0 && key <= Qt::Key_9) return XK_0 + (key - Qt::Key_0);
    if (key >= Qt::Key_F1 && key <= Qt::Key_F35) return XK_F1 + (key - Qt::Key_F1);
    switch (key) {
        case Qt::Key_Space:     return XK_space;
        case Qt::Key_Insert:    return XK_Insert;
        case Qt::Key_Delete:    return XK_Delete;
        case Qt::Key_Home:      return XK_Home;
        case Qt::Key_End:       return XK_End;
        case Qt::Key_PageUp:    return XK_Prior;
        case Qt::Key_PageDown:  return XK_Next;
        case Qt::Key_Left:      return XK_Left;
        case Qt::Key_Right:     return XK_Right;
        case Qt::Key_Up:        return XK_Up;
        case Qt::Key_Down:      return XK_Down;
        case Qt::Key_Return:    return XK_Return;
        case Qt::Key_Enter:     return XK_KP_Enter;
        case Qt::Key_Tab:       return XK_Tab;
        case Qt::Key_Escape:    return XK_Escape;
        case Qt::Key_Backspace: return XK_BackSpace;
        case Qt::Key_Minus:     return XK_minus;
        case Qt::Key_Equal:     return XK_equal;
        case Qt::Key_Plus:      return XK_plus;
        case Qt::Key_Comma:     return XK_comma;
        case Qt::Key_Period:    return XK_period;
        case Qt::Key_Slash:     return XK_slash;
        case Qt::Key_Semicolon: return XK_semicolon;
        default:                return NoSymbol;
    }
}

unsigned qtModsToX11(Qt::KeyboardModifiers mods) {
    unsigned m = 0;
    if (mods & Qt::ShiftModifier)   m |= ShiftMask;
    if (mods & Qt::ControlModifier) m |= ControlMask;
    if (mods & Qt::AltModifier)     m |= Mod1Mask;
    if (mods & Qt::MetaModifier)    m |= Mod4Mask;   // Super/Windows
    return m;
}

} // namespace

GlobalHotkeyManager::GlobalHotkeyManager(QObject* parent) : QObject(parent) {
    if (x11Display())
        qGuiApp->installNativeEventFilter(this);
}

GlobalHotkeyManager::~GlobalHotkeyManager() {
    clear();
    if (x11Display())
        qGuiApp->removeNativeEventFilter(this);
}

bool GlobalHotkeyManager::registerHotkey(int id, const QKeySequence& seq) {
    unregisterHotkey(id);
    Display* dpy = x11Display();
    if (!dpy || seq.isEmpty()) return false;

    // Use the first chord of the sequence (CE hotkeys are single chords).
    const QKeyCombination combo = seq[0];
    unsigned long keysym = qtKeyToKeysym(combo.key());
    if (keysym == NoSymbol) return false;
    KeyCode keycode = XKeysymToKeycode(dpy, keysym);
    if (keycode == 0) return false;

    unsigned mod = qtModsToX11(combo.keyboardModifiers());
    Window root = DefaultRootWindow(dpy);
    for (unsigned lock : kLockMasks)
        XGrabKey(dpy, keycode, mod | lock, root, /*owner_events*/ True,
                 GrabModeAsync, GrabModeAsync);
    XSync(dpy, False);

    grabs_.insert(id, Grab{(quint32)keycode, (quint32)mod});
    return true;
}

void GlobalHotkeyManager::ungrabOne(const Grab& g) {
    Display* dpy = x11Display();
    if (!dpy) return;
    Window root = DefaultRootWindow(dpy);
    for (unsigned lock : kLockMasks)
        XUngrabKey(dpy, (KeyCode)g.keycode, g.modmask | lock, root);
    XSync(dpy, False);
}

void GlobalHotkeyManager::unregisterHotkey(int id) {
    auto it = grabs_.find(id);
    if (it == grabs_.end()) return;
    ungrabOne(it.value());
    grabs_.erase(it);
}

void GlobalHotkeyManager::clear() {
    for (const auto& g : grabs_) ungrabOne(g);
    grabs_.clear();
}

bool GlobalHotkeyManager::nativeEventFilter(const QByteArray& eventType,
                                            void* message, qintptr*) {
    if (eventType != "xcb_generic_event_t") return false;
    auto* ev = static_cast<xcb_generic_event_t*>(message);
    if ((ev->response_type & ~0x80) != XCB_KEY_PRESS) return false;

    auto* ke = reinterpret_cast<xcb_key_press_event_t*>(ev);
    // Strip the lock bits from the reported state before comparing.
    quint32 state = ke->state & (ShiftMask | ControlMask | Mod1Mask | Mod4Mask);
    for (auto it = grabs_.constBegin(); it != grabs_.constEnd(); ++it) {
        if (ke->detail == it.value().keycode && state == it.value().modmask) {
            emit activated(it.key());
            return true;   // consume
        }
    }
    return false;
}

#endif // CECORE_HAVE_X11_HOTKEYS
