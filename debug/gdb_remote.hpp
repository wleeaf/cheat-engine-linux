#pragma once
/// Minimal GDB remote serial protocol client for GDB-compatible stubs.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace ce {

class GdbRemoteClient {
public:
    GdbRemoteClient() = default;
    ~GdbRemoteClient();

    GdbRemoteClient(const GdbRemoteClient&) = delete;
    GdbRemoteClient& operator=(const GdbRemoteClient&) = delete;

    bool connectTcp(const std::string& host, uint16_t port, std::string& error);
    void close();
    bool isConnected() const { return fd_ >= 0; }

    std::expected<std::string, std::string> sendPacket(const std::string& payload);
    std::expected<std::string, std::string> readRegisters();
    std::expected<std::vector<uint8_t>, std::string> readMemory(uintptr_t address, size_t size);

private:
    bool sendAll(const std::string& data, std::string& error);
    std::expected<std::string, std::string> readPacket();

    int fd_ = -1;
};

} // namespace ce
