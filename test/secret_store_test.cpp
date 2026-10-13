// Drives gui/secret_store.cpp for test/secret_store_gate.py, one action per run
// so a lookup really goes to the keyring (the in-memory copy dies with the run).
//   secret_store_test available | store KEY | lookup | remove | memory KEY

#include "gui/secret_store.hpp"

#include <QCoreApplication>

#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    if (argc < 2) return 2;
    ce::gui::SecretStore store("test-account");
    QString error;
    const char* action = argv[1];
    if (!std::strcmp(action, "available")) {
        std::printf("AVAILABLE %d\n", ce::gui::SecretStore::available() ? 1 : 0);
    } else if (!std::strcmp(action, "store") && argc > 2) {
        const bool ok = store.store(argv[2], &error);
        std::printf("STORED ok=%d persisted=%d error=%s\n", ok, store.persisted(), qPrintable(error));
    } else if (!std::strcmp(action, "lookup")) {
        auto found = store.lookup(&error);
        if (found) std::printf("FOUND %s\n", qPrintable(*found));
        else std::printf("NONE error=%s\n", qPrintable(error));
    } else if (!std::strcmp(action, "remove")) {
        std::printf("REMOVED ok=%d error=%s\n", store.remove(&error), qPrintable(error));
    } else if (!std::strcmp(action, "memory") && argc > 2) {
        // Without a keyring the key still lasts for this run.
        store.store(argv[2], &error);
        auto found = store.lookup();
        std::printf("FOUND %s persisted=%d\n", found ? qPrintable(*found) : "", store.persisted());
    } else {
        return 2;
    }
    return 0;
}
