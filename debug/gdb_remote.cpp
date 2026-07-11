#include "debug/gdb_remote.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace ce {
namespace {

uint8_t packetChecksum(const std::string& payload) {
    uint8_t sum = 0;
    for (unsigned char c : payload)
        sum = static_cast<uint8_t>(sum + c);
    return sum;
}

int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string errnoString(const char* prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

} // namespace

GdbRemoteClient::~GdbRemoteClient() {
    close();
}

bool GdbRemoteClient::connectTcp(const std::string& host, uint16_t port, std::string& error) {
    close();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    auto portText = std::to_string(port);
    addrinfo* results = nullptr;
    int gai = getaddrinfo(host.c_str(), portText.c_str(), &hints, &results);
    if (gai != 0) {
        error = gai_strerror(gai);
        return false;
    }

    for (auto* addr = results; addr; addr = addr->ai_next) {
        int candidate = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (candidate < 0)
            continue;

        if (::connect(candidate, addr->ai_addr, addr->ai_addrlen) == 0) {
            fd_ = candidate;
            freeaddrinfo(results);
            return true;
        }

        ::close(candidate);
    }

    error = errnoString("connect");
    freeaddrinfo(results);
    return false;
}

void GdbRemoteClient::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool GdbRemoteClient::sendAll(const std::string& data, std::string& error) {
    size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd_, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) {
            error = errnoString("send");
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

std::expected<std::string, std::string> GdbRemoteClient::readPacket() {
    // Cap the raw payload accepted from the (untrusted) stub so a hostile or
    // buggy peer cannot drive unbounded allocation. Decoded RLE can expand by
    // up to ~98x per run, so the decoded result is bounded separately below.
    constexpr size_t kMaxRawPayload = 1u << 20;   // 1 MiB of on-wire payload
    constexpr size_t kMaxDecoded    = 16u << 20;  // 16 MiB after RLE expansion

    char c = 0;
    do {
        ssize_t n = ::recv(fd_, &c, 1, 0);
        if (n <= 0)
            return std::unexpected(errnoString("recv"));
    } while (c != '$');

    std::string raw;
    while (true) {
        ssize_t n = ::recv(fd_, &c, 1, 0);
        if (n <= 0)
            return std::unexpected(errnoString("recv"));
        if (c == '#')
            break;
        if (raw.size() >= kMaxRawPayload)
            return std::unexpected("packet exceeds maximum size");
        raw.push_back(c);
    }

    char checksumText[2] = {};
    if (::recv(fd_, checksumText, 2, MSG_WAITALL) != 2)
        return std::unexpected(errnoString("recv checksum"));

    int hi = hexValue(checksumText[0]);
    int lo = hexValue(checksumText[1]);
    if (hi < 0 || lo < 0)
        return std::unexpected("invalid packet checksum");

    // RSP checksum is computed over the raw (still-encoded) payload bytes.
    uint8_t expected = static_cast<uint8_t>((hi << 4) | lo);
    if (expected != packetChecksum(raw))
        return std::unexpected("packet checksum mismatch");

    // Decode RSP transforms: '}' escape (next byte XOR 0x20) and '*' run-length
    // encoding (repeat the previous decoded char count = next_byte - 29 times).
    std::string payload;
    for (size_t i = 0; i < raw.size(); ++i) {
        char ch = raw[i];
        if (ch == '}') {
            if (i + 1 >= raw.size())
                return std::unexpected("truncated escape in packet");
            ch = static_cast<char>(raw[++i] ^ 0x20);
            if (payload.size() >= kMaxDecoded)
                return std::unexpected("decoded packet exceeds maximum size");
            payload.push_back(ch);
        } else if (ch == '*') {
            if (payload.empty() || i + 1 >= raw.size())
                return std::unexpected("invalid run-length encoding in packet");
            int repeat = static_cast<unsigned char>(raw[++i]) - 29;
            if (repeat < 0)
                return std::unexpected("invalid run-length count in packet");
            char prev = payload.back();
            if (payload.size() + static_cast<size_t>(repeat) > kMaxDecoded)
                return std::unexpected("decoded packet exceeds maximum size");
            payload.append(static_cast<size_t>(repeat), prev);
        } else {
            if (payload.size() >= kMaxDecoded)
                return std::unexpected("decoded packet exceeds maximum size");
            payload.push_back(ch);
        }
    }

    std::string error;
    if (!sendAll("+", error))
        return std::unexpected(error);

    return payload;
}

std::expected<std::string, std::string> GdbRemoteClient::sendPacket(const std::string& payload) {
    if (fd_ < 0)
        return std::unexpected("not connected");

    char suffix[4];
    std::snprintf(suffix, sizeof(suffix), "#%02x", packetChecksum(payload));
    std::string packet = "$" + payload + suffix;

    std::string error;
    if (!sendAll(packet, error))
        return std::unexpected(error);

    char ack = 0;
    ssize_t n = ::recv(fd_, &ack, 1, MSG_WAITALL);
    if (n != 1)
        return std::unexpected(errnoString("recv ack"));
    if (ack != '+')
        return std::unexpected("GDB stub did not acknowledge packet");

    auto response = readPacket();
    if (!response)
        return response;
    if (response->size() >= 1 && (*response)[0] == 'E')
        return std::unexpected("GDB error response: " + *response);
    return response;
}

std::expected<std::string, std::string> GdbRemoteClient::readRegisters() {
    return sendPacket("g");
}

std::expected<std::vector<uint8_t>, std::string> GdbRemoteClient::readMemory(uintptr_t address, size_t size) {
    char command[64];
    std::snprintf(command, sizeof(command), "m%lx,%zx",
        static_cast<unsigned long>(address), size);

    auto response = sendPacket(command);
    if (!response)
        return std::unexpected(response.error());
    if (response->size() % 2 != 0)
        return std::unexpected("memory response has odd hex length");

    std::vector<uint8_t> bytes;
    bytes.reserve(response->size() / 2);
    for (size_t i = 0; i < response->size(); i += 2) {
        int hi = hexValue((*response)[i]);
        int lo = hexValue((*response)[i + 1]);
        if (hi < 0 || lo < 0)
            return std::unexpected("memory response contains non-hex data");
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

} // namespace ce
