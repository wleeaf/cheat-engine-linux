#include "gui/secret_store.hpp"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDBusVariant>
#include <QEventLoop>
#include <QHash>
#include <QMutex>
#include <QTimer>

// The Secret Service D-Bus API (freedesktop.org), with a "plain" session: the
// secret crosses the user's own session bus unencrypted, as with libsecret's
// default, and is stored encrypted by the keyring.

namespace ce::gui::secret {

struct Secret {
    QDBusObjectPath session;
    QByteArray parameters;
    QByteArray value;
    QString contentType;
};

QDBusArgument& operator<<(QDBusArgument& arg, const Secret& s) {
    arg.beginStructure();
    arg << s.session << s.parameters << s.value << s.contentType;
    arg.endStructure();
    return arg;
}

const QDBusArgument& operator>>(const QDBusArgument& arg, Secret& s) {
    arg.beginStructure();
    arg >> s.session >> s.parameters >> s.value >> s.contentType;
    arg.endStructure();
    return arg;
}

class PromptWaiter : public QObject {
    Q_OBJECT
public:
    bool dismissed = true;
    bool done = false;
signals:
    void finished();
public slots:
    void completed(bool wasDismissed, const QDBusVariant&) {
        dismissed = wasDismissed;
        done = true;
        emit finished();
    }
};

} // namespace ce::gui::secret

Q_DECLARE_METATYPE(ce::gui::secret::Secret)

namespace ce::gui {

namespace {

using secret::Secret;
using Attributes = QMap<QString, QString>;

const QString kService = "org.freedesktop.secrets";
const QString kPath = "/org/freedesktop/secrets";
const QString kServiceInterface = "org.freedesktop.Secret.Service";
const QString kItemInterface = "org.freedesktop.Secret.Item";
const QString kPromptInterface = "org.freedesktop.Secret.Prompt";

QMutex memoryLock;
QHash<QString, QString>& memory() {
    static QHash<QString, QString> secrets;
    return secrets;
}

void registerTypes() {
    static const bool done = [] {
        qDBusRegisterMetaType<Secret>();
        qDBusRegisterMetaType<Attributes>();
        return true;
    }();
    (void)done;
}

Attributes attributesFor(const QString& account) {
    return {{"application", "cheat-engine-linux"}, {"account", account}};
}

QDBusMessage call(const QString& path, const QString& interface, const QString& method,
                  const QList<QVariant>& arguments, QString* error) {
    registerTypes();
    auto message = QDBusMessage::createMethodCall(kService, path, interface, method);
    message.setArguments(arguments);
    auto reply = QDBusConnection::sessionBus().call(message, QDBus::Block, 25000);
    if (reply.type() == QDBusMessage::ErrorMessage && error)
        *error = reply.errorMessage().isEmpty() ? reply.errorName() : reply.errorMessage();
    return reply;
}

bool failed(const QDBusMessage& reply, int arguments) {
    return reply.type() != QDBusMessage::ReplyMessage || reply.arguments().size() < arguments;
}

QList<QDBusObjectPath> paths(const QVariant& value) {
    return qdbus_cast<QList<QDBusObjectPath>>(value.value<QDBusArgument>());
}

// Unlock and create calls may hand back a prompt for the user (the keyring's
// password dialog). Run it and wait for the answer.
bool runPrompt(const QDBusObjectPath& prompt, QString* error) {
    if (prompt.path().isEmpty() || prompt.path() == "/") return true;
    secret::PromptWaiter waiter;
    QEventLoop loop;
    auto bus = QDBusConnection::sessionBus();
    bus.connect(kService, prompt.path(), kPromptInterface, "Completed", &waiter, SLOT(completed(bool,QDBusVariant)));
    QObject::connect(&waiter, &secret::PromptWaiter::finished, &loop, &QEventLoop::quit);
    QTimer::singleShot(120000, &loop, &QEventLoop::quit);
    if (failed(call(prompt.path(), kPromptInterface, "Prompt", {QString()}, error), 0)) return false;
    if (!waiter.done) loop.exec();
    bus.disconnect(kService, prompt.path(), kPromptInterface, "Completed", &waiter, SLOT(completed(bool,QDBusVariant)));
    if (!waiter.done) { if (error) *error = "the keyring did not answer"; return false; }
    if (waiter.dismissed) { if (error) *error = "the keyring prompt was dismissed"; return false; }
    return true;
}

std::optional<QDBusObjectPath> openSession(QString* error) {
    auto reply = call(kPath, kServiceInterface, "OpenSession", {QString("plain"), QVariant::fromValue(QDBusVariant(QString()))}, error);
    if (failed(reply, 2)) return std::nullopt;
    return reply.arguments().at(1).value<QDBusObjectPath>();
}

// Unlock objects if they are locked (may prompt).
bool unlock(const QList<QDBusObjectPath>& objects, QString* error) {
    auto reply = call(kPath, kServiceInterface, "Unlock", {QVariant::fromValue(objects)}, error);
    if (failed(reply, 2)) return false;
    return runPrompt(reply.arguments().at(1).value<QDBusObjectPath>(), error);
}

std::optional<QList<QDBusObjectPath>> search(const QString& account, bool unlockLocked, QString* error) {
    auto reply = call(kPath, kServiceInterface, "SearchItems", {QVariant::fromValue(attributesFor(account))}, error);
    if (failed(reply, 2)) return std::nullopt;
    auto unlocked = paths(reply.arguments().at(0));
    const auto locked = paths(reply.arguments().at(1));
    if (!locked.isEmpty() && unlockLocked) {
        if (!unlock(locked, error)) return std::nullopt;
        unlocked += locked;
    } else if (unlocked.isEmpty() && !locked.isEmpty()) {
        unlocked = locked;   // deletion works on locked items too
    }
    return unlocked;
}

} // namespace

SecretStore::SecretStore(QString account) : account_(std::move(account)) {}

bool SecretStore::available() {
    auto* bus = QDBusConnection::sessionBus().interface();
    if (!bus) return false;
    if (bus->isServiceRegistered(kService)) return true;
    const auto activatable = bus->activatableServiceNames();
    return activatable.isValid() && activatable.value().contains(kService);
}

bool SecretStore::store(const QString& value, QString* error) {
    {
        QMutexLocker lock(&memoryLock);
        memory()[account_] = value;
    }
    persisted_ = false;
    if (!available()) { if (error) *error = "no keyring service is running"; return false; }
    auto session = openSession(error);
    if (!session) return false;
    auto alias = call(kPath, kServiceInterface, "ReadAlias", {QString("default")}, error);
    if (failed(alias, 1)) return false;
    const auto collection = alias.arguments().at(0).value<QDBusObjectPath>();
    if (collection.path().isEmpty() || collection.path() == "/") {
        if (error) *error = "the keyring has no default collection";
        return false;
    }
    if (!unlock({collection}, error)) return false;
    QVariantMap properties;
    properties["org.freedesktop.Secret.Item.Label"] = QString("Cheat Engine for Linux: %1 API key").arg(account_);
    properties["org.freedesktop.Secret.Item.Attributes"] = QVariant::fromValue(attributesFor(account_));
    const Secret secret{*session, {}, value.toUtf8(), "text/plain"};
    auto created = call(collection.path(), "org.freedesktop.Secret.Collection", "CreateItem",
                        {properties, QVariant::fromValue(secret), true}, error);
    if (failed(created, 2)) return false;
    if (!runPrompt(created.arguments().at(1).value<QDBusObjectPath>(), error)) return false;
    persisted_ = true;
    return true;
}

std::optional<QString> SecretStore::lookup(QString* error) {
    {
        QMutexLocker lock(&memoryLock);
        if (memory().contains(account_)) return memory().value(account_);
    }
    if (!available()) return std::nullopt;
    auto session = openSession(error);
    if (!session) return std::nullopt;
    auto items = search(account_, true, error);
    if (!items || items->isEmpty()) return std::nullopt;
    auto reply = call(items->first().path(), kItemInterface, "GetSecret", {QVariant::fromValue(*session)}, error);
    if (failed(reply, 1)) return std::nullopt;
    const auto secret = qdbus_cast<Secret>(reply.arguments().at(0).value<QDBusArgument>());
    const QString value = QString::fromUtf8(secret.value);
    QMutexLocker lock(&memoryLock);
    memory()[account_] = value;
    return value;
}

bool SecretStore::remove(QString* error) {
    {
        QMutexLocker lock(&memoryLock);
        memory().remove(account_);
    }
    persisted_ = false;
    if (!available()) return true;
    auto items = search(account_, false, error);
    if (!items) return false;
    for (const auto& item : *items) {
        auto reply = call(item.path(), kItemInterface, "Delete", {}, error);
        if (failed(reply, 1) || !runPrompt(reply.arguments().at(0).value<QDBusObjectPath>(), error)) return false;
    }
    return true;
}

} // namespace ce::gui

#include "secret_store.moc"
