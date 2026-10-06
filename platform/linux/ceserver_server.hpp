#pragma once
/// Minimal ceserver-protocol SERVER: exposes local process memory over TCP so a
/// remote CEServerClient (or Cheat Engine itself) can attach and read/write. This
/// is the "be a server, not just a client" side (P2 #24). It implements the core
/// commands (GETVERSION / OPENPROCESS / CLOSEHANDLE / READ- / WRITEPROCESSMEMORY);
/// Process handles retain the opened Linux target identity for one connection.

#include <cstdint>
#include <thread>
#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

namespace ce::os {

class CeserverServer {
public:
    CeserverServer();
    ~CeserverServer();
    CeserverServer(const CeserverServer&) = delete;
    CeserverServer& operator=(const CeserverServer&) = delete;

    /// Bind to `port` on localhost and start serving on a background thread.
    /// Returns the bound port (>0), or 0 on failure. Pass 0 for an ephemeral port.
    uint16_t start(uint16_t port);
    void stop();
    bool running() const { return running_.load(); }
    uint16_t port() const { return port_.load(); }

private:
    struct ClientState;
    void acceptLoop(int listener, int wakeFd);
    void serveClient(ClientState& client);
    void interruptClients();

    int listenFd_ = -1;
    int wakeFd_ = -1;
    // Serialize start/stop, including their complete thread ownership changes.
    std::mutex lifecycleMutex_;
    // Each worker closes its socket under this lock. Shutdown and worker
    // reaping therefore cannot act on a descriptor reused by another client.
    std::mutex socketMutex_;
    std::vector<std::unique_ptr<ClientState>> clients_;
    std::atomic<uint16_t> port_{0};
    std::thread thread_;
    std::atomic<bool> running_{false};
};

} // namespace ce::os
