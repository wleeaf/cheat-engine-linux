#pragma once
/// Bounded all-stop GDB remote protocol client. No local ptrace or host ISA assumptions.

#include "core/target_machine.hpp"
#include <chrono>
#include <cstdint>
#include <expected>
#include <mutex>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

namespace ce {

struct GdbRegisterDescription {
    std::string name;
    uint32_t number=0;
    uint32_t bits=0;
    std::string type;
};
struct GdbTargetDescription {
    std::string architecture;
    std::string osAbi;
    TargetMachine machine;
    std::vector<GdbRegisterDescription> registers;
};

class GdbRemoteClient {
public:
    GdbRemoteClient() = default;
    ~GdbRemoteClient();

    GdbRemoteClient(const GdbRemoteClient&) = delete;
    GdbRemoteClient& operator=(const GdbRemoteClient&) = delete;

    bool connectTcp(const std::string& host, uint16_t port, std::string& error);
    void close();
    bool isConnected() const { std::lock_guard lock(mutex_); return fd_ >= 0; }
    void setTimeout(std::chrono::milliseconds timeout);
    void setCancellation(std::stop_token token);

    std::expected<std::string, std::string> sendPacket(const std::string& payload);
    std::expected<void, std::string> negotiate();
    bool supports(const std::string& feature) const;
    std::expected<std::string, std::string> readObject(const std::string& object, const std::string& annex);
    std::expected<GdbTargetDescription, std::string> describeTarget();
    std::expected<std::string, std::string> readRegisters();
    std::expected<std::vector<uint8_t>, std::string> readRegister(const GdbRegisterDescription& reg);
    std::expected<void, std::string> writeRegister(const GdbRegisterDescription& reg, std::span<const uint8_t> bytes);
    std::expected<std::vector<uint8_t>, std::string> readMemory(uintptr_t address, size_t size);
    std::expected<size_t, std::string> writeMemory(uintptr_t address, std::span<const uint8_t> bytes);

private:
    bool sendAll(const std::string& data, std::string& error);
    bool waitReady(short events, std::string& error);
    std::expected<char, std::string> readByte();
    std::expected<std::string, std::string> readPacket();
    struct RegisterBank {
        std::string data;
        size_t offset=0;
        size_t width=0;
    };
    std::expected<RegisterBank, std::string> readRegisterBank(const GdbRegisterDescription& reg);

    mutable std::recursive_mutex mutex_;
    int fd_ = -1;
    bool noAck_=false;
    size_t packetSize_=1024;
    std::vector<std::string> features_;
    std::vector<GdbRegisterDescription> registerLayout_;
    bool individualReads_=true;
    bool individualWrites_=true;
    std::chrono::milliseconds timeout_{2000};
    std::chrono::steady_clock::time_point deadline_;
    std::stop_token cancellation_;
};

} // namespace ce
