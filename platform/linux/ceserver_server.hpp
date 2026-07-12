#pragma once
/// Minimal ceserver-protocol SERVER: exposes local process memory over TCP so a
/// remote CEServerClient (or Cheat Engine itself) can attach and read/write. This
/// is the "be a server, not just a client" side (P2 #24). It implements the core
/// commands (GETVERSION / OPENPROCESS / CLOSEHANDLE / READ- / WRITEPROCESSMEMORY);
/// the process handle is the pid.

#include <cstdint>
#include <thread>
#include <atomic>

namespace ce::os {

class CeserverServer {
public:
    CeserverServer() = default;
    ~CeserverServer();
    CeserverServer(const CeserverServer&) = delete;
    CeserverServer& operator=(const CeserverServer&) = delete;

    /// Bind to `port` on localhost and start serving on a background thread.
    /// Returns the bound port (>0), or 0 on failure. Pass 0 for an ephemeral port.
    uint16_t start(uint16_t port);
    void stop();
    bool running() const { return running_.load(); }
    uint16_t port() const { return port_; }

private:
    void acceptLoop();
    void serveClient(int fd);

    int listenFd_ = -1;
    uint16_t port_ = 0;
    std::thread thread_;
    std::atomic<bool> running_{false};
};

} // namespace ce::os
