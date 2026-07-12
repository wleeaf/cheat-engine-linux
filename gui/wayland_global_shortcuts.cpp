#include "gui/wayland_global_shortcuts.hpp"

#include <QDBusArgument>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDBusMetaType>
#include <QVariant>

// CePortalShortcut and its metatype declarations live in the header (shared with
// the mock-portal test); the marshalling operators are defined here.
QDBusArgument& operator<<(QDBusArgument& arg, const CePortalShortcut& s) {
    arg.beginStructure();
    arg << s.id << s.meta;
    arg.endStructure();
    return arg;
}
const QDBusArgument& operator>>(const QDBusArgument& arg, CePortalShortcut& s) {
    arg.beginStructure();
    arg >> s.id >> s.meta;
    arg.endStructure();
    return arg;
}

namespace ce::gui {

namespace {
constexpr const char* kPortalPath = "/org/freedesktop/portal/desktop";
constexpr const char* kShortcutsIface = "org.freedesktop.portal.GlobalShortcuts";
constexpr const char* kRequestIface = "org.freedesktop.portal.Request";
} // namespace

WaylandGlobalShortcuts::WaylandGlobalShortcuts(QDBusConnection connection,
                                               QString service, QObject* parent)
    : QObject(parent), bus_(std::move(connection)), service_(std::move(service)) {
    qDBusRegisterMetaType<CePortalShortcut>();
    qDBusRegisterMetaType<QList<CePortalShortcut>>();

    // Subscribe to the Activated signal up front so a shortcut firing after a
    // bind always reaches us, regardless of when the session was created.
    bus_.connect(service_, kPortalPath, kShortcutsIface, QStringLiteral("Activated"),
                 this, SLOT(onActivated(QDBusMessage)));
}

bool WaylandGlobalShortcuts::portalAvailable() const {
    auto* iface = bus_.interface();
    return iface && iface->isServiceRegistered(service_).value();
}

QString WaylandGlobalShortcuts::newToken(const QString& prefix) {
    return prefix + QString::number(++tokenCounter_);
}

QString WaylandGlobalShortcuts::requestPathFor(const QString& token) const {
    // The portal derives the Request object path from the caller's unique bus
    // name (":1.42" -> "1_42") and the handle_token. Predicting it lets us
    // subscribe to Response before issuing the call, avoiding a race.
    QString unique = bus_.baseService();
    if (unique.startsWith(':')) unique.remove(0, 1);
    unique.replace('.', '_');
    return QStringLiteral("/org/freedesktop/portal/desktop/request/") + unique +
           QStringLiteral("/") + token;
}

void WaylandGlobalShortcuts::createSession() {
    const QString token = newToken(QStringLiteral("ce_session"));
    const QString reqPath = requestPathFor(token);
    bus_.connect(service_, reqPath, kRequestIface, QStringLiteral("Response"),
                 this, SLOT(onCreateSessionResponse(uint, QVariantMap)));

    QDBusMessage msg = QDBusMessage::createMethodCall(
        service_, kPortalPath, kShortcutsIface, QStringLiteral("CreateSession"));
    QVariantMap options;
    options[QStringLiteral("handle_token")] = token;
    options[QStringLiteral("session_handle_token")] = token;
    msg << options;   // a{sv}
    bus_.asyncCall(msg);
}

void WaylandGlobalShortcuts::onCreateSessionResponse(uint response,
                                                     const QVariantMap& results) {
    if (response != 0) {
        emit sessionFailed(QStringLiteral("CreateSession response %1").arg(response));
        return;
    }
    sessionHandle_ = results.value(QStringLiteral("session_handle")).toString();
    if (sessionHandle_.isEmpty()) {
        emit sessionFailed(QStringLiteral("no session_handle in response"));
        return;
    }
    emit sessionReady();
}

void WaylandGlobalShortcuts::bindShortcut(const QString& id, const QString& description,
                                          const QString& preferredTrigger) {
    const QString token = newToken(QStringLiteral("ce_bind"));
    const QString reqPath = requestPathFor(token);
    bus_.connect(service_, reqPath, kRequestIface, QStringLiteral("Response"),
                 this, SLOT(onBindResponse(uint, QVariantMap)));

    CePortalShortcut shortcut;
    shortcut.id = id;
    shortcut.meta[QStringLiteral("description")] = description;
    shortcut.meta[QStringLiteral("preferred_trigger")] = preferredTrigger;

    QDBusMessage msg = QDBusMessage::createMethodCall(
        service_, kPortalPath, kShortcutsIface, QStringLiteral("BindShortcuts"));
    QVariantMap options;
    options[QStringLiteral("handle_token")] = token;
    msg << QVariant::fromValue(QDBusObjectPath(sessionHandle_))          // o
        << QVariant::fromValue(QList<CePortalShortcut>{shortcut})        // a(sa{sv})
        << QString()                                                     // s parent_window
        << options;                                                      // a{sv}
    bus_.asyncCall(msg);
}

void WaylandGlobalShortcuts::onBindResponse(uint response, const QVariantMap&) {
    if (response == 0)
        emit shortcutsBound();
    else
        emit sessionFailed(QStringLiteral("BindShortcuts response %1").arg(response));
}

void WaylandGlobalShortcuts::onActivated(const QDBusMessage& message) {
    // Activated(o session_handle, s shortcut_id, t timestamp, a{sv} options).
    const QList<QVariant> args = message.arguments();
    if (args.size() >= 2)
        emit activated(args.at(1).toString());
}

} // namespace ce::gui
