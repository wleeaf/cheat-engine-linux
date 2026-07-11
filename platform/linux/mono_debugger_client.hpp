#pragma once
/// Mono soft-debugger protocol client. Speaks the wire protocol used by
/// the Mono runtime's debug agent (`--debugger-agent=transport=dt_socket,
/// server=y,address=0.0.0.0:PORT`). This first cut covers the handshake
/// and VM/Version query; further command sets (VM, Thread, Method,
/// AppDomain, Assembly, etc.) follow the same packet shape and can be
/// added incrementally.
///
/// Protocol summary (Mono debugger-agent.c):
///   - 13-byte ASCII handshake "DWP-Handshake" exchanged after TCP connect.
///   - Each command/reply packet: 4-byte big-endian length + 4-byte
///     packet id + 1 byte flags (0=cmd, 0x80=reply) + 2 bytes cmd set / cmd
///     (cmd packets) OR 2 bytes error code (reply packets) + payload.
///
/// Reference: mono/mini/debugger-agent.h in the Mono source tree.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace ce::os {

struct MonoVmVersion {
    std::string vmVersion;      // "Mono 6.12.0 (...)"
    int32_t majorVersion = 0;
    int32_t minorVersion = 0;
};

class MonoDebuggerClient {
public:
    MonoDebuggerClient() = default;
    ~MonoDebuggerClient();

    MonoDebuggerClient(const MonoDebuggerClient&) = delete;
    MonoDebuggerClient& operator=(const MonoDebuggerClient&) = delete;

    /// Connect + exchange the handshake. Returns the protocol-major
    /// reported by the agent on success.
    std::expected<int32_t, std::string>
    connectTcp(const std::string& host, uint16_t port);

    void close();
    bool isConnected() const { return fd_ >= 0; }

    /// Send VM/Version (cmdset=1, cmd=1) and parse the reply.
    std::expected<MonoVmVersion, std::string> getVersion();

    /// VM/Suspend (cmdset=1, cmd=2) — suspend every Mono thread until
    /// resumed. Idempotent: nested suspend calls each need a matching
    /// resume.
    std::expected<void, std::string> vmSuspend();

    /// VM/Resume (cmdset=1, cmd=3) — resume after a matching suspend.
    std::expected<void, std::string> vmResume();

    /// VM/Exit (cmdset=1, cmd=4) — terminate the target with the given
    /// exit code. Irreversible.
    std::expected<void, std::string> vmExit(int32_t exitCode);

    /// VM/AllThreads (cmdset=1, cmd=6) — list every Mono thread's object
    /// id. Mono uses 8-byte object ids in modern protocol versions; this
    /// implementation reads them as 8-byte big-endian by default.
    std::expected<std::vector<int64_t>, std::string> vmAllThreads();

    /// VM/Dispose (cmdset=1, cmd=5) — detach without exiting the target.
    std::expected<void, std::string> vmDispose();

    /// Generic packet-level send. Cmdset/cmd identify the command; payload
    /// is the command-specific bytes. Returns the reply payload on success.
    std::expected<std::vector<uint8_t>, std::string>
    sendCommand(uint8_t cmdset, uint8_t cmd, const std::vector<uint8_t>& payload);

private:
    int  fd_ = -1;
    int32_t nextPacketId_ = 1;

    bool sendAll(const void* data, size_t n, std::string& err);
    bool recvAll(void* data, size_t n, std::string& err);
};

} // namespace ce::os
