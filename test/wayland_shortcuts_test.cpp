/// Validates WaylandGlobalShortcuts against a mock XDG GlobalShortcuts portal.
///
/// The mock implements the authoritative org.freedesktop.portal.GlobalShortcuts
/// interface (CreateSession / BindShortcuts + the async Request/Response pattern
/// + the Activated signal). Because the client and mock share one bus connection,
/// the mock derives the Request object path the same way the client predicts it.
///
/// This exercises the message FORMAT (a{sv} options, the a(sa{sv}) shortcuts
/// marshalling, the Activated signal signature) against the real interface shape,
/// and the request round-trip + signal decode against the mock's behaviour.
/// End-to-end behaviour against a real compositor's portal still needs a live
/// Wayland session; this is the most that is verifiable headlessly. Skips when no
/// session bus is available (e.g. plain CI without dbus-run-session).

#include "gui/wayland_global_shortcuts.hpp"

#include <QCoreApplication>
#include <QDBusAbstractAdaptor>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDBusMetaType>
#include <QEventLoop>
#include <QTimer>
#include <QVariantMap>

#include <cstdio>
#include <functional>

using ce::gui::WaylandGlobalShortcuts;

namespace {
constexpr const char* kMockService = "org.cheatengine.MockPortal";
constexpr const char* kPortalPath = "/org/freedesktop/portal/desktop";
constexpr const char* kRequestIface = "org.freedesktop.portal.Request";
constexpr const char* kShortcutsIface = "org.freedesktop.portal.GlobalShortcuts";

QString requestPath(QDBusConnection& bus, const QString& token) {
    QString unique = bus.baseService();
    if (unique.startsWith(':')) unique.remove(0, 1);
    unique.replace('.', '_');
    return QStringLiteral("/org/freedesktop/portal/desktop/request/") + unique +
           QStringLiteral("/") + token;
}

// Spin the event loop until `done` is true or `ms` elapses.
bool waitFor(const std::function<bool()>& done, int ms) {
    QEventLoop loop;
    QTimer timer;
    timer.setInterval(10);
    QObject::connect(&timer, &QTimer::timeout, &loop, [&] {
        if (done()) loop.quit();
    });
    QTimer::singleShot(ms, &loop, [&] { loop.quit(); });
    timer.start();
    if (!done()) loop.exec();
    return done();
}
} // namespace

// Mock portal state + async response driver.
class MockPortal : public QObject {
    Q_OBJECT
public:
    MockPortal(QDBusConnection conn, QObject* parent = nullptr)
        : QObject(parent), conn_(conn) {}

    QDBusObjectPath onCreateSession(const QVariantMap& options) {
        createSessionSeen = true;
        const QString token = options.value(QStringLiteral("handle_token")).toString();
        const QString sessTok = options.value(QStringLiteral("session_handle_token")).toString();
        QString base = conn_.baseService();
        if (base.startsWith(':')) base.remove(0, 1);
        base.replace('.', '_');
        const QString sessionPath =
            QStringLiteral("/org/freedesktop/portal/desktop/session/") + base +
            QStringLiteral("/") + sessTok;
        const QString reqPath = requestPath(conn_, token);
        // Answer asynchronously, like the real portal.
        QTimer::singleShot(0, this, [this, reqPath, sessionPath] {
            QVariantMap results;
            results[QStringLiteral("session_handle")] = sessionPath;
            QDBusMessage sig = QDBusMessage::createSignal(reqPath, kRequestIface,
                                                          QStringLiteral("Response"));
            sig << uint(0) << results;
            conn_.send(sig);
        });
        return QDBusObjectPath(reqPath);
    }

    QDBusObjectPath onBindShortcuts(const QDBusObjectPath&,
                                    const QList<CePortalShortcut>& shortcuts,
                                    const QString&, const QVariantMap& options) {
        bindSeen = true;
        if (!shortcuts.isEmpty()) {
            boundId = shortcuts.first().id;
            boundDescription = shortcuts.first().meta.value(QStringLiteral("description")).toString();
            boundTrigger = shortcuts.first().meta.value(QStringLiteral("preferred_trigger")).toString();
        }
        const QString token = options.value(QStringLiteral("handle_token")).toString();
        const QString reqPath = requestPath(conn_, token);
        QTimer::singleShot(0, this, [this, reqPath] {
            QDBusMessage sig = QDBusMessage::createSignal(reqPath, kRequestIface,
                                                          QStringLiteral("Response"));
            sig << uint(0) << QVariantMap();
            conn_.send(sig);
        });
        return QDBusObjectPath(reqPath);
    }

    void emitActivated(const QString& sessionHandle, const QString& id) {
        QDBusMessage sig = QDBusMessage::createSignal(kPortalPath, kShortcutsIface,
                                                      QStringLiteral("Activated"));
        sig << QDBusObjectPath(sessionHandle) << id << qulonglong(0) << QVariantMap();
        conn_.send(sig);
    }

    bool createSessionSeen = false;
    bool bindSeen = false;
    QString boundId, boundDescription, boundTrigger;

private:
    QDBusConnection conn_;
};

// D-Bus adaptor exposing the GlobalShortcuts interface, forwarding to MockPortal.
class GlobalShortcutsAdaptor : public QDBusAbstractAdaptor {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.portal.GlobalShortcuts")
public:
    explicit GlobalShortcutsAdaptor(MockPortal* portal)
        : QDBusAbstractAdaptor(portal), portal_(portal) {}

public slots:
    QDBusObjectPath CreateSession(const QVariantMap& options) {
        return portal_->onCreateSession(options);
    }
    QDBusObjectPath BindShortcuts(const QDBusObjectPath& session,
                                  const QList<CePortalShortcut>& shortcuts,
                                  const QString& parentWindow, const QVariantMap& options) {
        return portal_->onBindShortcuts(session, shortcuts, parentWindow, options);
    }

private:
    MockPortal* portal_;
};

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    printf("\n── Test: Wayland GlobalShortcuts portal client ──\n");

    qDBusRegisterMetaType<CePortalShortcut>();
    qDBusRegisterMetaType<QList<CePortalShortcut>>();

    // Pure-function check of the QKeySequence -> portal trigger mapping. Needs no
    // bus, so it gates the exit code even where the session bus is unavailable.
    using ce::gui::keySequenceToPortalTrigger;
    const bool triggerOk =
        keySequenceToPortalTrigger(QKeySequence(QStringLiteral("Ctrl+Shift+G")))
            == QLatin1String("CTRL+SHIFT+G") &&
        keySequenceToPortalTrigger(QKeySequence(QStringLiteral("F1")))
            == QLatin1String("F1") &&
        keySequenceToPortalTrigger(QKeySequence(QStringLiteral("Alt+Meta+Space")))
            == QLatin1String("ALT+LOGO+SPACE") &&
        keySequenceToPortalTrigger(QKeySequence()).isEmpty();
    printf("  keySequenceToPortalTrigger mapping: %s\n", triggerOk ? "OK" : "FAILED");

    QDBusConnection bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) {
        printf("  portal client round-trip: SKIPPED (no session bus)\n");
        return triggerOk ? 0 : 1;
    }
    if (!bus.registerService(QString::fromLatin1(kMockService))) {
        printf("  portal client round-trip: SKIPPED (cannot own mock service)\n");
        return triggerOk ? 0 : 1;
    }

    MockPortal mock(bus);
    new GlobalShortcutsAdaptor(&mock);
    bus.registerObject(QString::fromLatin1(kPortalPath), &mock);

    WaylandGlobalShortcuts client(bus, QString::fromLatin1(kMockService));

    const bool availOk = client.portalAvailable();

    bool ready = false;
    QString handle;
    QObject::connect(&client, &WaylandGlobalShortcuts::sessionReady, &app, [&] {
        ready = true;
        handle = client.sessionHandle();
    });
    client.createSession();
    waitFor([&] { return ready; }, 3000);
    const bool sessionOk = ready && mock.createSessionSeen && !handle.isEmpty();

    bool bound = false;
    QObject::connect(&client, &WaylandGlobalShortcuts::shortcutsBound, &app, [&] { bound = true; });
    client.bindShortcut(QStringLiteral("toggle_god"), QStringLiteral("Toggle god mode"),
                        QStringLiteral("CTRL+SHIFT+G"));
    waitFor([&] { return bound; }, 3000);
    const bool bindOk = bound && mock.bindSeen &&
        mock.boundId == QLatin1String("toggle_god") &&
        mock.boundDescription == QLatin1String("Toggle god mode") &&
        mock.boundTrigger == QLatin1String("CTRL+SHIFT+G");

    QString fired;
    QObject::connect(&client, &WaylandGlobalShortcuts::activated, &app,
                     [&](const QString& id) { fired = id; });
    mock.emitActivated(handle, QStringLiteral("toggle_god"));
    waitFor([&] { return !fired.isEmpty(); }, 3000);
    const bool activatedOk = fired == QLatin1String("toggle_god");

    printf("  portal available: %s\n", availOk ? "OK" : "FAILED");
    printf("  CreateSession round-trip: %s\n", sessionOk ? "OK" : "FAILED");
    printf("  BindShortcuts a(sa{sv}) marshalling: %s\n", bindOk ? "OK" : "FAILED");
    printf("  Activated signal decode: %s\n", activatedOk ? "OK" : "FAILED");

    const int failures = int(!triggerOk) + int(!availOk) + int(!sessionOk) +
                         int(!bindOk) + int(!activatedOk);
    return failures ? 1 : 0;
}

#include "wayland_shortcuts_test.moc"
