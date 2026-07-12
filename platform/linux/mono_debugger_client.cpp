/// Mono soft-debugger protocol client — TCP handshake + framed packets.

#include "platform/linux/mono_debugger_client.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace ce::os {

namespace {
constexpr const char* kHandshake = "DWP-Handshake";
constexpr size_t kHandshakeLen = 13;
// Upper bound on a single Mono debug-agent reply frame (untrusted input).
// Caps the body allocation derived from the on-wire length header.
constexpr uint32_t kMaxMonoReply = 1u << 28; // 256 MiB

std::string errnoString(const char* prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

uint32_t loadBe32(const uint8_t* p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8  | (uint32_t)p[3];
}
void storeBe32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
uint16_t loadBe16(const uint8_t* p) {
    return (uint16_t)p[0] << 8 | (uint16_t)p[1];
}

} // namespace

MonoDebuggerClient::~MonoDebuggerClient() { close(); }

bool MonoDebuggerClient::sendAll(const void* data, size_t n, std::string& err) {
    auto* p = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = ::send(fd_, p + sent, n - sent, 0);
        if (r < 0 && errno == EINTR) continue; // retry on signal interruption
        if (r <= 0) { err = errnoString("send"); return false; }
        sent += (size_t)r;
    }
    return true;
}

bool MonoDebuggerClient::recvAll(void* data, size_t n, std::string& err) {
    auto* p = static_cast<uint8_t*>(data);
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::recv(fd_, p + got, n - got, MSG_WAITALL);
        if (r < 0 && errno == EINTR) continue; // retry on signal interruption
        if (r <= 0) { err = errnoString("recv"); return false; }
        got += (size_t)r;
    }
    return true;
}

std::expected<int32_t, std::string>
MonoDebuggerClient::connectTcp(const std::string& host, uint16_t port) {
    close();

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    auto portStr = std::to_string(port);
    addrinfo* res = nullptr;
    int gai = ::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (gai != 0) return std::unexpected(::gai_strerror(gai));

    int cfd = -1;
    for (auto* a = res; a; a = a->ai_next) {
        cfd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (cfd < 0) continue;
        if (::connect(cfd, a->ai_addr, a->ai_addrlen) == 0) {
            fd_ = cfd;
            break;
        }
        ::close(cfd);
        cfd = -1;
    }
    ::freeaddrinfo(res);
    if (fd_ < 0) return std::unexpected(errnoString("connect"));

    // Exchange 13-byte handshake — Mono's debug agent expects the client
    // to send first, then echoes it back. Some agent versions reverse the
    // order; recvAll first then sendAll also works on those, but the
    // documented order is send-first.
    std::string err;
    if (!sendAll(kHandshake, kHandshakeLen, err)) {
        close();
        return std::unexpected("handshake send: " + err);
    }
    char incoming[kHandshakeLen] = {0};
    if (!recvAll(incoming, kHandshakeLen, err)) {
        close();
        return std::unexpected("handshake recv: " + err);
    }
    if (std::memcmp(incoming, kHandshake, kHandshakeLen) != 0) {
        close();
        return std::unexpected("handshake mismatch — peer is not a Mono debug agent");
    }
    // Return protocol-major heuristically as the byte after the handshake
    // — the upstream agent doesn't actually expose this in the handshake,
    // so callers should follow up with VM/Version. We return 0 to mean
    // "handshake completed, protocol unknown — query VM/Version".
    return 0;
}

void MonoDebuggerClient::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    nextPacketId_ = 1;
}

std::expected<std::vector<uint8_t>, std::string>
MonoDebuggerClient::sendCommand(uint8_t cmdset, uint8_t cmd,
                                 const std::vector<uint8_t>& payload) {
    if (fd_ < 0) return std::unexpected("not connected");
    std::string err;

    // Packet: [len(4)][id(4)][flags(1)][cmdset(1)][cmd(1)][payload...]
    uint32_t totalLen = (uint32_t)(11 + payload.size());
    int32_t  id = nextPacketId_++;
    std::vector<uint8_t> packet(totalLen);
    storeBe32(packet.data(), totalLen);
    storeBe32(packet.data() + 4, (uint32_t)id);
    packet[8] = 0;        // flags = command
    packet[9] = cmdset;
    packet[10] = cmd;
    if (!payload.empty())
        std::memcpy(packet.data() + 11, payload.data(), payload.size());

    if (!sendAll(packet.data(), packet.size(), err))
        return std::unexpected("send: " + err);

    // The agent interleaves asynchronous EVENT packets (command packets it sends
    // us, flags bit 0x80 clear -- e.g. VM_START / THREAD_START on suspend) with
    // the reply to our command. Read framed packets until we see the reply whose
    // id matches ours; drain and discard any event packets in between. Bounded so
    // a peer that never sends our reply can't loop forever.
    // Reply frame:   [len(4)][id(4)][flags=0x80][error(2)][payload...]
    // Event frame:   [len(4)][id(4)][flags=0x00][cmdset(1)][cmd(1)][payload...]
    for (int guard = 0; guard < 4096; ++guard) {
        uint8_t hdr[11] = {0};
        if (!recvAll(hdr, sizeof(hdr), err))
            return std::unexpected("recv hdr: " + err);
        uint32_t replyLen = loadBe32(hdr);
        int32_t  replyId  = (int32_t)loadBe32(hdr + 4);
        uint8_t  flags    = hdr[8];
        uint16_t errCode  = loadBe16(hdr + 9);
        if (replyLen < 11 || replyLen > kMaxMonoReply)
            return std::unexpected("reply length out of range");

        std::vector<uint8_t> body(replyLen - 11);
        if (!body.empty() && !recvAll(body.data(), body.size(), err))
            return std::unexpected("recv body: " + err);

        // An event packet (or a reply to a different command) is not ours: drop
        // it and keep reading.
        if (!(flags & 0x80) || replyId != id)
            continue;

        if (errCode != 0)
            return std::unexpected("mono agent error " + std::to_string(errCode));
        return body;
    }
    return std::unexpected("no matching reply after draining agent events");
}

namespace {

std::vector<uint8_t> int32Payload(int32_t v) {
    std::vector<uint8_t> out(4);
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
    return out;
}

} // namespace

// Mono debugger-agent CmdVM numbers (mono/mini/debugger-agent.h):
//   VERSION=1, ALL_THREADS=2, SUSPEND=3, RESUME=4, EXIT=5, DISPOSE=6.
std::expected<void, std::string> MonoDebuggerClient::vmSuspend() {
    auto r = sendCommand(/*cmdset=*/1, /*cmd=*/3, {});
    if (!r) return std::unexpected(r.error());
    return {};
}

std::expected<void, std::string> MonoDebuggerClient::vmResume() {
    auto r = sendCommand(/*cmdset=*/1, /*cmd=*/4, {});
    if (!r) return std::unexpected(r.error());
    return {};
}

std::expected<void, std::string> MonoDebuggerClient::vmExit(int32_t exitCode) {
    auto r = sendCommand(/*cmdset=*/1, /*cmd=*/5, int32Payload(exitCode));
    if (!r) return std::unexpected(r.error());
    return {};
}

std::expected<void, std::string> MonoDebuggerClient::vmDispose() {
    auto r = sendCommand(/*cmdset=*/1, /*cmd=*/6, {});
    if (!r) return std::unexpected(r.error());
    return {};
}

std::expected<std::vector<int64_t>, std::string> MonoDebuggerClient::vmAllThreads() {
    auto body = sendCommand(/*cmdset=*/1, /*cmd=*/2, {});   // CMD_VM_ALL_THREADS
    if (!body) return std::unexpected(body.error());
    if (body->size() < 4) return std::unexpected("AllThreads reply too short");
    uint32_t count = loadBe32(body->data());
    if (count > (1u << 24)) return std::unexpected("AllThreads count out of range");
    // Mono encodes object ids with buffer_add_id -> buffer_add_int, i.e. a 4-byte
    // big-endian id (an index into the agent's id table), not an 8-byte pointer.
    if (body->size() < 4 + (size_t)count * 4)
        return std::unexpected("AllThreads payload truncated");
    std::vector<int64_t> out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i)
        out.push_back((int64_t)(int32_t)loadBe32(body->data() + 4 + i * 4));
    return out;
}

std::expected<MonoVmVersion, std::string> MonoDebuggerClient::getVersion() {
    auto body = sendCommand(/*cmdset=*/1, /*cmd=*/1, {});
    if (!body) return std::unexpected(body.error());

    // Reply layout for VM/Version: string vm_version, int major, int minor.
    // Mono's wire strings are big-endian uint32 length followed by UTF-8.
    if (body->size() < 4) return std::unexpected("version reply too short");
    uint32_t strLen = loadBe32(body->data());
    if (strLen > body->size() - 4) return std::unexpected("version string overrun");
    MonoVmVersion v;
    v.vmVersion.assign((const char*)body->data() + 4, strLen);
    size_t pos = 4 + strLen;
    if (body->size() >= pos + 8) {
        v.majorVersion = (int32_t)loadBe32(body->data() + pos);
        v.minorVersion = (int32_t)loadBe32(body->data() + pos + 4);
    }
    return v;
}

} // namespace ce::os
