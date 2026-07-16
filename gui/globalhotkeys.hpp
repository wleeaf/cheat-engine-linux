#pragma once
/// System-wide (global) hotkeys via X11 XGrabKey. Unlike Qt::ApplicationShortcut,
/// these fire even while the *game* window is focused — which is how Cheat Engine
/// hotkeys are meant to work (toggle a cheat mid-play). Falls back gracefully
/// (registerHotkey returns false) when the platform isn't X11.

#include <QObject>
#include <QAbstractNativeEventFilter>
#include <QKeySequence>
#include <QHash>

#ifdef CECORE_HAVE_WAYLAND_HOTKEYS
namespace ce::gui { class WaylandGlobalShortcuts; }
#endif

class GlobalHotkeyManager : public QObject, public QAbstractNativeEventFilter {
    Q_OBJECT
public:
    explicit GlobalHotkeyManager(QObject* parent = nullptr);
    ~GlobalHotkeyManager() override;

    /// Grab `seq` system-wide and associate it with `id` (replacing any prior
    /// grab for `id`). Returns false if not on X11 or the key can't be mapped.
    bool registerHotkey(int id, const QKeySequence& seq);
    void unregisterHotkey(int id);
    void clear();

    bool nativeEventFilter(const QByteArray& eventType, void* message,
                           qintptr* result) override;

signals:
    void activated(int id);

private:
    struct Grab { quint32 keycode = 0; quint32 modmask = 0; };
    QHash<int, Grab> grabs_;   // id -> grab
    void ungrabOne(const Grab& g);

#ifdef CECORE_HAVE_WAYLAND_HOTKEYS
    // Wayland path: under a Wayland session there is no XGrabKey, so hotkeys go
    // through the xdg-desktop-portal GlobalShortcuts client. Both register and
    // clear feed this, and the portal's activated(name) is funnelled back into
    // the same activated(int) signal so callers are unaffected by the platform.
    ce::gui::WaylandGlobalShortcuts* wayland_ = nullptr;   // null unless on Wayland
    bool waylandReady_ = false;      // portal session established
    bool rebindQueued_ = false;      // a coalesced rebind is already scheduled
    QHash<int, QString> waylandTriggers_;   // id -> "CTRL+SHIFT+G"
    void initWayland();
    bool tryRegisterWayland(int id, const QKeySequence& seq);
    void scheduleWaylandRebind();
    void rebindWayland();
#endif
};
