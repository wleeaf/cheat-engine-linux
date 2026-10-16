#pragma once
/// System-wide (global) hotkeys via X11 XGrabKey. Unlike Qt::ApplicationShortcut,
/// these fire even while the *game* window is focused — which is how Cheat Engine
/// hotkeys are meant to work (toggle a cheat mid-play). Falls back gracefully
/// (registerHotkey returns false) when the platform isn't X11.

#include <QObject>
#include <QAbstractNativeEventFilter>
#include <QKeySequence>
#include <QHash>
#include <QSet>

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
    /// `name` is the stable portal shortcut id on Wayland (letters, digits and
    /// '_'; "ce_hotkey_<id>" when empty), `description` what the desktop shows.
    bool registerHotkey(int id, const QKeySequence& seq, const QString& name = {},
                        const QString& description = {});
    void unregisterHotkey(int id);
    void clear();

    bool nativeEventFilter(const QByteArray& eventType, void* message,
                           qintptr* result) override;

signals:
    /// `autoRepeat`: the key is held and this is a repeat of the press.
    void activated(int id, bool autoRepeat);

private:
    struct Grab { quint32 keycode = 0; quint32 modmask = 0; };
    QHash<int, Grab> grabs_;   // id -> grab
    void ungrabOne(const Grab& g);
    // X11 autorepeat: keys pressed and not yet released, and the last release.
    // Without detectable autorepeat, X sends a release and a press with the
    // same timestamp for each repeat.
    QSet<quint32> held_;
    QHash<quint32, quint32> lastRelease_;   // keycode -> time

#ifdef CECORE_HAVE_WAYLAND_HOTKEYS
    // Wayland path: under a Wayland session there is no XGrabKey, so hotkeys go
    // through the xdg-desktop-portal GlobalShortcuts client. Both register and
    // clear feed this, and the portal's activated(name) is funnelled back into
    // the same activated(int) signal so callers are unaffected by the platform.
    ce::gui::WaylandGlobalShortcuts* wayland_ = nullptr;   // null unless on Wayland
    bool waylandReady_ = false;      // portal session established
    bool rebindQueued_ = false;      // a coalesced rebind is already scheduled
    bool waylandBound_ = false;      // the session holds shortcuts from a bind
    QHash<int, QString> waylandTriggers_;   // id -> "CTRL+SHIFT+G"
    struct WaylandName { QString name, description; };
    QHash<int, WaylandName> waylandNames_;   // id -> portal shortcut id and text
    void initWayland();
    QString waylandShortcutId(int id) const;
    bool tryRegisterWayland(int id, const QKeySequence& seq, const QString& name, const QString& description);
    void scheduleWaylandRebind();
    void rebindWayland();
#endif
};
