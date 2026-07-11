#pragma once
/// Minimal TCP client for Cheat Engine ceserver-compatible endpoints.
///
/// Wire format follows ceserver/ceserver.h (#pragma pack(1), little-endian).
/// All operations field-by-field to keep compiler packing rules out of the
/// equation.

#include <cstdint>
#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace ce::os {

struct CEServerVersionInfo {
    int32_t protocolVersion = 0;
    std::string versionString;
};

/// CE-style page protection (Windows convention) returned by VirtualQueryEx.
/// Bit values defined in CE: PAGE_READONLY=2, PAGE_READWRITE=4, PAGE_EXECUTE=0x10,
/// PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40, ...
enum class CeRegionProtection : uint32_t {
    NoAccess           = 0x01,
    ReadOnly           = 0x02,
    ReadWrite          = 0x04,
    WriteCopy          = 0x08,
    Execute            = 0x10,
    ExecuteRead        = 0x20,
    ExecuteReadWrite   = 0x40,
    ExecuteWriteCopy   = 0x80,
    Guard              = 0x100,
};

/// CE-style memory type bits (Windows convention) returned by VirtualQueryEx.
enum class CeRegionType : uint32_t {
    Private = 0x20000,
    Mapped  = 0x40000,
    Image   = 0x1000000,
};

struct CeRegion {
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    uint32_t protection = 0; // bitfield of CeRegionProtection
    uint32_t type = 0;       // bitfield of CeRegionType
};

struct CeModuleInfo {
    uint64_t baseAddress = 0;
    int32_t  moduleSize = 0;
    int32_t  modulePart = 0;
    uint32_t fileOffset = 0;
    std::string name;
};

enum class CeArchitecture : uint8_t {
    X86    = 0,
    X86_64 = 1,
    ARM32  = 2,
    ARM64  = 3,
    Unknown = 0xff,
};

/// A debug event delivered by CMD_WAITFORDEBUGEVENT. Wire size = 20 bytes
/// (4 + 8 + 8, pragma-packed).
struct CeDebugEvent {
    int32_t  debugEvent = 0;     // Linux signal number for trap, or special codes
    int64_t  threadId = 0;
    uint64_t address = 0;        // For SIGTRAP: faulting/breakpoint address
};

class CEServerClient {
public:
    CEServerClient() = default;
    ~CEServerClient();

    CEServerClient(const CEServerClient&) = delete;
    CEServerClient& operator=(const CEServerClient&) = delete;

    bool connectTcp(const std::string& host, uint16_t port, std::string& error);
    void close();
    bool isConnected() const { return fd_ >= 0; }

    std::expected<CEServerVersionInfo, std::string> getVersion();

    /// CMD_OPENPROCESS — returns ceserver-side handle (non-zero on success).
    std::expected<int32_t, std::string> openProcess(int32_t pid);

    /// CMD_CLOSEHANDLE — succeeds whenever the server acks (always 1).
    std::expected<void, std::string> closeHandle(int32_t handle);

    /// CMD_VIRTUALQUERYEX — region containing baseAddress.
    /// Returns std::nullopt when the server reports `result==0`.
    std::expected<std::optional<CeRegion>, std::string>
    virtualQueryEx(int32_t handle, uint64_t baseAddress);

    /// CMD_VIRTUALQUERYEXFULL — full region list.
    /// `flags` mirrors upstream: bit 0 = include image regions, bit 1 = sub-regions.
    std::expected<std::vector<CeRegion>, std::string>
    virtualQueryExFull(int32_t handle, uint8_t flags = 0);

    /// CMD_READPROCESSMEMORY — uncompressed read.
    /// Returns the actual byte count read (may be less than `size` near unmapped
    /// pages); the buffer is pre-allocated by the caller.
    std::expected<int32_t, std::string>
    readProcessMemory(int32_t handle, uint64_t address, void* buffer, uint32_t size);

    /// CMD_WRITEPROCESSMEMORY.
    std::expected<int32_t, std::string>
    writeProcessMemory(int32_t handle, uint64_t address, const void* buffer, int32_t size);

    /// CMD_GETARCHITECTURE — handle's process bitness/arch.
    std::expected<CeArchitecture, std::string> getArchitecture(int32_t handle);

    /// CMD_CREATETOOLHELP32SNAPSHOTEX with TH32CS_SNAPMODULE.
    std::expected<std::vector<CeModuleInfo>, std::string> enumModules(int32_t pid);

    /// CMD_CREATETOOLHELP32SNAPSHOTEX with TH32CS_SNAPTHREAD.
    std::expected<std::vector<int32_t>, std::string> enumThreads(int32_t pid);

    /// CMD_ALLOC. Returns 0 on failure.
    std::expected<uint64_t, std::string>
    allocateMemory(int32_t handle, uint64_t preferredBase, uint32_t size, uint32_t windowsProtection);

    /// CMD_FREE.
    std::expected<uint32_t, std::string>
    freeMemory(int32_t handle, uint64_t address, uint32_t size);

    struct ProtectionResult { uint32_t result; uint32_t oldProtection; };
    /// CMD_CHANGEMEMORYPROTECTION.
    std::expected<ProtectionResult, std::string>
    changeMemoryProtection(int32_t handle, uint64_t address, uint32_t size, uint32_t windowsProtection);

    // ── Debugger control ──

    /// CMD_STARTDEBUG — non-zero on success.
    std::expected<int32_t, std::string> startDebug(int32_t handle);

    /// CMD_STOPDEBUG.
    std::expected<int32_t, std::string> stopDebug(int32_t handle);

    /// CMD_WAITFORDEBUGEVENT — blocks up to `timeoutMs` (0 = poll).
    /// Returns std::nullopt when no event was queued within the timeout.
    std::expected<std::optional<CeDebugEvent>, std::string>
    waitForDebugEvent(int32_t handle, int32_t timeoutMs);

    /// CMD_CONTINUEFROMDEBUGEVENT.
    std::expected<int32_t, std::string>
    continueFromDebugEvent(int32_t handle, int32_t tid, int32_t signalToForward);

    /// CMD_SETBREAKPOINT — bptype mirrors the upstream encoding: 0=execute,
    /// 1=write, 2=reserved, 3=read/write. bpsize=0 is treated as 1.
    std::expected<int32_t, std::string>
    setRemoteBreakpoint(int32_t handle, int32_t tid, int32_t debugReg,
                        uint64_t address, int32_t bpType, int32_t bpSize);

    /// CMD_REMOVEBREAKPOINT.
    std::expected<int32_t, std::string>
    removeRemoteBreakpoint(int32_t handle, uint32_t tid, uint32_t debugReg, uint32_t wasWatchpoint);

    /// CMD_SUSPENDTHREAD / CMD_RESUMETHREAD.
    std::expected<int32_t, std::string> suspendThread(int32_t handle, int32_t tid);
    std::expected<int32_t, std::string> resumeThread(int32_t handle, int32_t tid);

    /// CMD_GETTHREADCONTEXT — returns the raw architecture-specific CONTEXT
    /// blob plus its size (the first uint32 inside the blob is also `structsize`).
    /// The caller is responsible for reinterpreting based on the target arch.
    std::expected<std::vector<uint8_t>, std::string>
    getThreadContext(int32_t handle, uint32_t tid);

    /// CMD_SETTHREADCONTEXT — sends the raw CONTEXT blob back. Returns 1 on
    /// success.
    std::expected<uint32_t, std::string>
    setThreadContext(int32_t handle, uint32_t tid, const void* contextBlob, uint32_t blobSize);

    /// CMD_SPEEDHACK_SETSPEED — multiplier for time-related calls in the
    /// remote process.
    std::expected<uint32_t, std::string>
    speedhackSetSpeed(int32_t handle, float speed);

    /// CMD_GETSYMBOLLISTFROMFILE — fetch a CE-compressed symbol payload for
    /// the named file on the remote system. The returned blob is the full
    /// server-side buffer (including its 8-byte header where bytes [4..7]
    /// hold the size). Returns std::nullopt when the server has no symbols
    /// for the requested file. Decoding the payload into individual symbols
    /// is left to the caller — the wire format is CE-specific and intended
    /// to be fed back to CE-format consumers verbatim.
    std::expected<std::optional<std::vector<uint8_t>>, std::string>
    getSymbolListFromFile(const std::string& symbolPath, uint32_t fileOffset = 0);

private:
    bool sendAll(const void* data, size_t size, std::string& error);
    bool recvAll(void* data, size_t size, std::string& error);
    bool sendCmd(uint8_t cmd, std::string& error);

    int fd_ = -1;
};

} // namespace ce::os
