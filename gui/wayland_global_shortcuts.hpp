#pragma once
/// Wayland global hotkeys via the XDG Desktop Portal GlobalShortcuts interface
/// (org.freedesktop.portal.GlobalShortcuts). Under Wayland a client cannot grab
/// keys directly (no XGrabKey), so the compositor-mediated portal is the only
/// way to get shortcuts that fire while the *game* is focused. This mirrors the
/// X11 `GlobalHotkeyManager` role for the Wayland path.
///
/// The portal uses the async Request pattern: each method returns a Request
/// object path and the real result arrives on that object's Response signal.
/// This class drives that pattern with QtDBus and emits activated() when the
/// portal reports a bound shortcut fired.
///
/// The method/signal signatures here are matched to the authoritative
/// org.freedesktop.portal.GlobalShortcuts XML. Behaviour against a real portal
/// still needs a live Wayland session to validate end to end; the accompanying
/// test exercises the call format + signal decode against a mock portal.

#include <QObject>
#include <QDBusConnection>
#include <QDBusArgument>
#include <QDBusMessage>
#include <QString>
#include <QVariantMap>
#include <QList>
#include <QKeySequence>

// Portal shortcut entry: the (s a{sv}) struct inside BindShortcuts' `a(sa{sv})`
// array — a shortcut id plus a metadata dict (description, preferred_trigger).
// Shared with the mock-portal test so both marshal the exact same wire type.
struct CePortalShortcut {
    QString id;
    QVariantMap meta;
};
Q_DECLARE_METATYPE(CePortalShortcut)
Q_DECLARE_METATYPE(QList<CePortalShortcut>)

QDBusArgument& operator<<(QDBusArgument& arg, const CePortalShortcut& s);
const QDBusArgument& operator>>(const QDBusArgument& arg, CePortalShortcut& s);

namespace ce::gui {

class WaylandGlobalShortcuts : public QObject {
    Q_OBJECT
public:
    /// `connection` is the bus to talk on (defaults to the session bus) and
    /// `service` the portal service name; both are injectable so a test can point
    /// the client at a mock portal on a private bus.
    explicit WaylandGlobalShortcuts(
        QDBusConnection connection = QDBusConnection::sessionBus(),
        QString service = QStringLiteral("org.freedesktop.portal.Desktop"),
        QObject* parent = nullptr);

    /// True when the portal service owns a name on the bus (i.e. a portal is
    /// reachable). On X11-only systems this is false and the caller should keep
    /// using the X11 path.
    bool portalAvailable() const;

    /// Begin a GlobalShortcuts session. Emits sessionReady() (or sessionFailed())
    /// when the portal answers the CreateSession Request.
    void createSession();

    /// Bind one shortcut id with a human description and a preferred trigger
    /// (e.g. "CTRL+SHIFT+F1"). Valid after sessionReady(). Emits shortcutsBound()
    /// when the BindShortcuts Request answers.
    void bindShortcut(const QString& id, const QString& description,
                      const QString& preferredTrigger);

    /// Bind a whole set of shortcuts in one BindShortcuts call. The portal binds
    /// the session's shortcuts as a set, so callers with several hotkeys should
    /// prefer this over repeated bindShortcut() calls. Emits shortcutsBound().
    void bindShortcuts(const QList<CePortalShortcut>& shortcuts);

    QString sessionHandle() const { return sessionHandle_; }

signals:
    void sessionReady();
    void sessionFailed(const QString& reason);
    void shortcutsBound();
    void activated(const QString& shortcutId);

private slots:
    void onCreateSessionResponse(uint response, const QVariantMap& results);
    void onBindResponse(uint response, const QVariantMap& results);
    // Connected with a raw-message slot: QtDBus rejects a typed multi-arg slot for
    // this signal's (osta{sv}) signature, and the raw form is robust.
    void onActivated(const QDBusMessage& message);

private:
    QString newToken(const QString& prefix);
    QString requestPathFor(const QString& token) const;

    QDBusConnection bus_;
    QString service_;
    QString sessionHandle_;
    int tokenCounter_ = 0;
};

/// Convert a Qt key sequence to an XDG portal "preferred_trigger" string, e.g.
/// QKeySequence("Ctrl+Shift+G") -> "CTRL+SHIFT+G". Modifiers are emitted in the
/// fixed order CTRL, ALT, SHIFT, LOGO (super) followed by the key name, matching
/// the trigger syntax the GlobalShortcuts portal expects. Returns an empty string
/// if the sequence carries no key. Only the first chord is used (CE hotkeys are
/// single chords). This is a best-effort *preferred* trigger; the compositor may
/// present its own rebinding UI and choose a different one.
QString keySequenceToPortalTrigger(const QKeySequence& seq);

} // namespace ce::gui
