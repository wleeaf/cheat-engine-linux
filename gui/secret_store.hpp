#pragma once
/// API keys in the desktop's keyring (GNOME Keyring, KWallet, KeePassXC: any
/// Secret Service), never in Cheat Engine's own settings file. When no keyring
/// is running, a key is kept in memory until Cheat Engine closes.

#include <QString>

#include <optional>

namespace ce::gui {

class SecretStore {
public:
    /// One stored secret, named by `account` (for example "anthropic").
    explicit SecretStore(QString account);

    /// A Secret Service answers on the session bus (or can be started).
    static bool available();
    /// Goes up whenever any key is stored or removed in this run.
    static int changeCount();

    /// Save the secret. May show the keyring's unlock prompt. On failure the
    /// secret is still kept in memory for this run, and `error` says why.
    bool store(const QString& secret, QString* error = nullptr);
    /// The stored secret: from memory, else from the keyring (which may prompt).
    std::optional<QString> lookup(QString* error = nullptr);
    /// Remove it from the keyring and from memory.
    bool remove(QString* error = nullptr);
    /// A copy is held in memory for this run (stored, or read from the keyring).
    bool inMemory() const;
    /// Whether the last store() reached the keyring.
    bool persisted() const { return persisted_; }

private:
    QString account_;
    bool persisted_ = false;
};

} // namespace ce::gui
