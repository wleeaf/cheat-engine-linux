#pragma once
/// Minimal ceserver-protocol SERVER: exposes local process memory over TCP so a
/// remote CEServerClient (or Cheat Engine itself) can attach and read/write. This
/// is the "be a server, not just a client" side (P2 #24). It implements the core
/// commands (GETVERSION / OPENPROCESS / CLOSEHANDLE / READ- / WRITEPROCESSMEMORY);
/// the process handle is the pid.

#include <cstdint>
#include <thread>
#include <atomic>
#include <memory>
#include <deque>
#include <mutex>
#include <condition_variable>

namespace ce { class DebugSession; class ProcessHandle; }

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

    // Remote debug state (one active DebugSession per served client). The
    // session's tracer-thread callback only enqueues events; WAITFORDEBUGEVENT
    // drains them on the serve thread. dbg_ is declared LAST so it is destroyed
    // first — its destructor joins the tracer thread, which touches the members
    // above, so they must still be alive during that join.
    struct DebugEventRec { int32_t debugevent = 0; int64_t tid = 0; uint64_t address = 0; };
    std::mutex dbgMutex_;
    std::condition_variable dbgCv_;
    std::deque<DebugEventRec> dbgQueue_;
    std::unique_ptr<ce::ProcessHandle> dbgProc_;
    std::unique_ptr<ce::DebugSession> dbg_;
};

} // namespace ce::os
