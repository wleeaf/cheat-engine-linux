#pragma once
#include "platform/process_api.hpp"
#include "debug/gdb_remote.hpp"
#include <mutex>

namespace ce {
struct GdbProcessOptions {
    ByteOrder byteOrder=ByteOrder::Unknown;
    uint8_t pointerWidth=0;
    TargetRuntime runtime=TargetRuntime::Unknown;
    std::chrono::milliseconds timeout{2000};
    std::stop_token cancellation;
    // Explicit guest address ranges, not host /proc mappings or translated PIDs.
    std::vector<MemoryRegion> regions;
};

class GdbProcessHandle final : public ProcessHandle {
public:
    using ProcessHandle::read;
    using ProcessHandle::write;
    ~GdbProcessHandle() override;
    static std::expected<std::unique_ptr<GdbProcessHandle>,std::string>
        connect(const std::string& host,uint16_t port,const GdbProcessOptions& options={});
    pid_t pid() const override {return 0;} // No local Linux process identity.
    bool is64bit() const override {return target_.machine.pointerWidth==8;}
    bool runs32BitCode() override {return target_.machine.instructionMode==InstructionMode::X86_32;}
    TargetDescription targetDescription() override;
    TargetMachine machineAt(uintptr_t) override {return target_.machine;}
    Result<size_t> read(uintptr_t address,void* buffer,size_t size) override;
    Result<size_t> write(uintptr_t address,const void* buffer,size_t size) override;
    std::vector<MemoryRegion> queryRegions() override;
    std::optional<MemoryRegion> queryRegion(uintptr_t address) override;
    Result<uintptr_t> allocate(size_t,MemProt,uintptr_t=0) override;
    Result<void> free(uintptr_t,size_t) override;
    Result<void> protect(uintptr_t,size_t,MemProt) override;
    std::vector<ModuleInfo> modules() override {return {};}
    std::vector<ThreadInfo> threads() override {return {};}
    const GdbTargetDescription& registerDescription() const {return target_;}
    std::expected<std::vector<uint8_t>,std::string> readRegister(const std::string& name);
    std::expected<void,std::string> writeRegister(const std::string& name,std::span<const uint8_t> bytes);
    std::string lastTransportError() const;
    // RSP operations for guest execution/control, kept distinct from local ptrace.
    std::expected<std::string,std::string> remoteCommand(const std::string& command);
    void disconnect();
    std::expected<void,std::string> detach();
private:
    GdbProcessHandle()=default;
    mutable std::mutex mutex_;
    GdbRemoteClient client_;
    GdbTargetDescription target_;
    TargetRuntime runtime_=TargetRuntime::Unknown;
    std::vector<MemoryRegion> regions_;
    std::string error_;
    bool ownsSession_=false;
};
}
