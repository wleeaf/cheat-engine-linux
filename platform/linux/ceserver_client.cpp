#include "platform/linux/ceserver_client.hpp"

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <algorithm>
#include <limits>

#include <cerrno>
#include <cstring>
#include <optional>
#include <vector>

namespace ce::os {
namespace {

constexpr uint8_t CMD_GETVERSION                  = 0;
constexpr uint8_t CMD_OPENPROCESS                 = 3;
constexpr uint8_t CMD_CLOSEHANDLE                 = 7;
constexpr uint8_t CMD_VIRTUALQUERYEX              = 8;
constexpr uint8_t CMD_READPROCESSMEMORY           = 9;
constexpr uint8_t CMD_WRITEPROCESSMEMORY          = 10;
constexpr uint8_t CMD_STARTDEBUG                  = 11;
constexpr uint8_t CMD_STOPDEBUG                   = 12;
constexpr uint8_t CMD_WAITFORDEBUGEVENT           = 13;
constexpr uint8_t CMD_CONTINUEFROMDEBUGEVENT      = 14;
constexpr uint8_t CMD_SETBREAKPOINT               = 15;
constexpr uint8_t CMD_REMOVEBREAKPOINT            = 16;
constexpr uint8_t CMD_SUSPENDTHREAD               = 17;
constexpr uint8_t CMD_RESUMETHREAD                = 18;
constexpr uint8_t CMD_GETTHREADCONTEXT            = 19;
constexpr uint8_t CMD_SETTHREADCONTEXT            = 20;
constexpr uint8_t CMD_GETARCHITECTURE             = 21;
constexpr uint8_t CMD_ALLOC                       = 26;
constexpr uint8_t CMD_SPEEDHACK_SETSPEED          = 30;
constexpr uint8_t CMD_GETSYMBOLLISTFROMFILE       = 24;
constexpr uint8_t CMD_FREE                        = 27;
constexpr uint8_t CMD_VIRTUALQUERYEXFULL          = 31;
constexpr uint8_t CMD_CREATETOOLHELP32SNAPSHOTEX  = 35;
constexpr uint8_t CMD_CHANGEMEMORYPROTECTION      = 36;

// Snapshot flags (Win32-style, mirrored by ceserver).
constexpr uint32_t TH32CS_SNAPTHREAD = 0x4;
constexpr uint32_t TH32CS_SNAPMODULE = 0x8;

std::string errnoString(const char* prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

} // namespace

CEServerClient::~CEServerClient() {
    close();
}

bool CEServerClient::isConnected() const {
    std::lock_guard lock(stateMutex_);
    return fd_>=0 && !closing_;
}
uint64_t CEServerClient::connectionGeneration() const {
    std::lock_guard lock(stateMutex_);
    return generation_;
}
bool CEServerClient::setTimeoutMs(int timeoutMs) {
    auto operation=lockConnection();
    if (timeoutMs<=0) return false;
    timeoutMs_=timeoutMs;
    return true;
}
void CEServerClient::beginRequest(int extraWaitMs) {
    deadline_=std::chrono::steady_clock::now()+
        std::chrono::milliseconds(int64_t(timeoutMs_)+std::max(extraWaitMs,0));
}
void CEServerClient::retireConnection() {
    std::lock_guard lock(stateMutex_);
    if (fd_>=0) ::close(fd_);
    fd_=-1;closing_=false;++generation_;
}
void CEServerClient::close() {
    uint64_t cancellation;
    {
        std::lock_guard lock(stateMutex_);
        // Wake an in-flight recv/send without closing a descriptor still used
        // by that transaction. A reconnect cannot reuse it until the lock ends.
        closing_=true;cancellation=++generation_;
        if (fd_>=0) ::shutdown(fd_,SHUT_RDWR);
    }
    auto operation=lockConnection();
    std::lock_guard lock(stateMutex_);
    // A newer close or connection may have won the transaction lock first.
    if (generation_!=cancellation) return;
    if (fd_>=0) ::close(fd_);
    fd_=-1;closing_=false;
}
bool CEServerClient::waitSocket(int fd,short events,std::string& error) {
    for (;;) {
        auto now=std::chrono::steady_clock::now();
        if (now>=deadline_) { error="ceserver request timed out";return false; }
        auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline_-now).count();
        pollfd p{fd,events,0};
        int result=::poll(&p,1,static_cast<int>(std::clamp<int64_t>(remaining,1,INT32_MAX)));
        if (result<0 && errno==EINTR) continue;
        if (result<0) { error=errnoString("poll");return false; }
        if (result>0) return true;
    }
}
bool CEServerClient::connectTcp(const std::string& host,uint16_t port,std::string& error) {
    // Cancel the old operation before waiting for its transaction lock.
    close();
    auto operation=lockConnection();
    retireConnection();beginRequest();error.clear();
    const auto generation=connectionGeneration();
    addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
    auto portText=std::to_string(port);
    addrinfo* results=nullptr;
    int gai=getaddrinfo(host.c_str(),portText.c_str(),&hints,&results);
    if (gai!=0) { error=gai_strerror(gai);return false; }
    for (auto* addr=results;addr;addr=addr->ai_next) {
        if (connectionGeneration()!=generation) { error="ceserver connection cancelled";break; }
        if (std::chrono::steady_clock::now()>=deadline_) { error="ceserver connect timed out";break; }
        int candidate=::socket(addr->ai_family,addr->ai_socktype|SOCK_NONBLOCK|SOCK_CLOEXEC,addr->ai_protocol);
        if (candidate<0) { error=errnoString("socket");continue; }
        bool connected=::connect(candidate,addr->ai_addr,addr->ai_addrlen)==0;
        if (!connected && (errno==EINPROGRESS || errno==EINTR)) {
            while (connectionGeneration()==generation && std::chrono::steady_clock::now()<deadline_) {
                pollfd p{candidate,POLLOUT,0};
                auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline_-std::chrono::steady_clock::now()).count();
                int ready=::poll(&p,1,static_cast<int>(std::clamp<int64_t>(remaining,1,50)));
                if (ready<0 && errno==EINTR) continue;
                if (ready<0) { error=errnoString("connect poll");break; }
                if (!ready) continue;
                int result=0;socklen_t size=sizeof(result);
                if (getsockopt(candidate,SOL_SOCKET,SO_ERROR,&result,&size)<0)
                    error=errnoString("connect status");
                else if (!result) connected=true;
                else { errno=result;error=errnoString("connect"); }
                break;
            }
        } else if (!connected) error=errnoString("connect");
        {
            std::lock_guard lock(stateMutex_);
            if (connected && generation_==generation && !closing_) {
                fd_=candidate;++generation_;freeaddrinfo(results);return true;
            }
        }
        ::close(candidate);
    }
    freeaddrinfo(results);
    if (connectionGeneration()!=generation) error="ceserver connection cancelled";
    else if (std::chrono::steady_clock::now()>=deadline_) error="ceserver connect timed out";
    else if (error.empty()) error="ceserver connection failed";
    return false;
}
bool CEServerClient::sendAll(const void* data,size_t size,std::string& error) {
    auto* bytes=static_cast<const uint8_t*>(data);
    size_t sent=0;
    while (sent<size) {
        if (!waitSocket(fd_,POLLOUT,error)) { retireConnection();return false; }
        ssize_t n=::send(fd_,bytes+sent,size-sent,MSG_NOSIGNAL|MSG_DONTWAIT);
        if (n<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        if (n<=0) { error=errnoString("send");retireConnection();return false; }
        sent+=static_cast<size_t>(n);
    }
    return true;
}
bool CEServerClient::recvAll(void* data,size_t size,std::string& error) {
    auto* bytes=static_cast<uint8_t*>(data);
    size_t received=0;
    while (received<size) {
        if (!waitSocket(fd_,POLLIN,error)) { retireConnection();return false; }
        ssize_t n=::recv(fd_,bytes+received,size-received,MSG_DONTWAIT);
        if (n<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        if (n<=0) {
            error=n==0 ? "ceserver connection closed" : errnoString("recv");
            retireConnection();return false;
        }
        received+=static_cast<size_t>(n);
    }
    return true;
}

bool CEServerClient::sendCmd(uint8_t cmd, std::string& error) {
    return sendAll(&cmd, sizeof(cmd), error);
}

std::expected<CEServerVersionInfo, std::string> CEServerClient::getVersion() {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0)
        return std::unexpected("not connected");

    std::string error;
    if (!sendCmd(CMD_GETVERSION, error))
        return std::unexpected(error);

    int32_t protocolVersion = 0;
    uint8_t stringSize = 0;
    if (!recvAll(&protocolVersion, sizeof(protocolVersion), error) ||
        !recvAll(&stringSize, sizeof(stringSize), error)) {
        return std::unexpected(error);
    }

    std::string versionString(stringSize, '\0');
    if (stringSize > 0 && !recvAll(versionString.data(), stringSize, error))
        return std::unexpected(error);

    return CEServerVersionInfo{protocolVersion, versionString};
}

std::expected<int32_t, std::string> CEServerClient::openProcess(int32_t pid) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_OPENPROCESS, error) ||
        !sendAll(&pid, sizeof(pid), error))
        return std::unexpected(error);

    int32_t handle = 0;
    if (!recvAll(&handle, sizeof(handle), error))
        return std::unexpected(error);
    return handle;
}

std::expected<void, std::string> CEServerClient::closeHandle(int32_t handle) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_CLOSEHANDLE, error) ||
        !sendAll(&handle, sizeof(handle), error))
        return std::unexpected(error);

    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error))
        return std::unexpected(error);
    if (!result) return std::unexpected("ceserver could not close the handle");
    return {};
}

std::expected<std::optional<CeRegion>, std::string>
CEServerClient::virtualQueryEx(int32_t handle, uint64_t baseAddress) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    // Wire: { int32_t handle; uint64_t baseaddress }
    if (!sendCmd(CMD_VIRTUALQUERYEX, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&baseAddress, sizeof(baseAddress), error))
        return std::unexpected(error);

    // Wire: { uint8_t result; uint32_t protection; uint32_t type; uint64_t base; uint64_t size }
    uint8_t result = 0;
    uint32_t protection = 0, type = 0;
    uint64_t base = 0, size = 0;
    if (!recvAll(&result, sizeof(result), error) ||
        !recvAll(&protection, sizeof(protection), error) ||
        !recvAll(&type, sizeof(type), error) ||
        !recvAll(&base, sizeof(base), error) ||
        !recvAll(&size, sizeof(size), error))
        return std::unexpected(error);

    if (!result) return std::optional<CeRegion>{};
    return std::optional<CeRegion>{CeRegion{base, size, protection, type}};
}

std::expected<std::vector<CeRegion>, std::string>
CEServerClient::virtualQueryExFull(int32_t handle, uint8_t flags) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_VIRTUALQUERYEXFULL, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&flags, sizeof(flags), error))
        return std::unexpected(error);

    int32_t count = 0;
    if (!recvAll(&count, sizeof(count), error))
        return std::unexpected(error);
    if (count < 0 || count > (1 << 20)) {
        retireConnection();
        return std::unexpected("ceserver returned invalid region count");
    }

    std::vector<CeRegion> regions;
    regions.reserve(static_cast<size_t>(count));
    for (int32_t i = 0; i < count; ++i) {
        uint32_t protection = 0, type = 0;
        uint64_t base = 0, size = 0;
        if (!recvAll(&protection, sizeof(protection), error) ||
            !recvAll(&type, sizeof(type), error) ||
            !recvAll(&base, sizeof(base), error) ||
            !recvAll(&size, sizeof(size), error))
            return std::unexpected(error);
        regions.push_back(CeRegion{base, size, protection, type});
    }
    return regions;
}

std::expected<int32_t, std::string>
CEServerClient::readProcessMemory(int32_t handle, uint64_t address, void* buffer, uint32_t size) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    uint32_t handleField = static_cast<uint32_t>(handle);
    uint8_t compress = 0;
    if (!sendCmd(CMD_READPROCESSMEMORY, error) ||
        !sendAll(&handleField, sizeof(handleField), error) ||
        !sendAll(&address, sizeof(address), error) ||
        !sendAll(&size, sizeof(size), error) ||
        !sendAll(&compress, sizeof(compress), error))
        return std::unexpected(error);

    int32_t read = 0;
    if (!recvAll(&read, sizeof(read), error))
        return std::unexpected(error);
    if (read < 0 || static_cast<uint32_t>(read) > size) {
        retireConnection();
        return std::unexpected("ceserver returned invalid read length");
    }
    if (read > 0 && !recvAll(buffer, static_cast<size_t>(read), error))
        return std::unexpected(error);
    return read;
}

std::expected<CeArchitecture, std::string>
CEServerClient::getArchitecture(int32_t handle) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_GETARCHITECTURE, error) ||
        !sendAll(&handle, sizeof(handle), error))
        return std::unexpected(error);
    uint8_t arch = 0xff;
    if (!recvAll(&arch, sizeof(arch), error))
        return std::unexpected(error);
    return static_cast<CeArchitecture>(arch);
}

std::expected<std::vector<CeModuleInfo>, std::string>
CEServerClient::enumModules(int32_t pid) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    uint32_t flags = TH32CS_SNAPMODULE;
    uint32_t pidField = static_cast<uint32_t>(pid);
    if (!sendCmd(CMD_CREATETOOLHELP32SNAPSHOTEX, error) ||
        !sendAll(&flags, sizeof(flags), error) ||
        !sendAll(&pidField, sizeof(pidField), error))
        return std::unexpected(error);

    // Stream of CeModuleEntry { int32_t result; int64_t modulebase; int32_t modulepart;
    //                            int32_t modulesize; uint32_t modulefileoffset;
    //                            int32_t modulenamesize; } + namesize bytes.
    // result==0 marks end of list.
    std::vector<CeModuleInfo> modules;
    while (true) {
        int32_t result = 0;
        int64_t base = 0;
        int32_t part = 0;
        int32_t modSize = 0;
        uint32_t fileOff = 0;
        int32_t nameSize = 0;
        if (!recvAll(&result, sizeof(result), error) ||
            !recvAll(&base, sizeof(base), error) ||
            !recvAll(&part, sizeof(part), error) ||
            !recvAll(&modSize, sizeof(modSize), error) ||
            !recvAll(&fileOff, sizeof(fileOff), error) ||
            !recvAll(&nameSize, sizeof(nameSize), error))
            return std::unexpected(error);
        if (nameSize < 0 || nameSize > (1 << 20)) {
            retireConnection();
            return std::unexpected("ceserver returned invalid module name size");
        }
        std::string name(static_cast<size_t>(nameSize), '\0');
        if (nameSize > 0 && !recvAll(name.data(), nameSize, error))
            return std::unexpected(error);
        if (result == 0) break;
        modules.push_back(CeModuleInfo{static_cast<uint64_t>(base), modSize, part, fileOff, std::move(name)});
        // A malicious/buggy server that never sends the result==0 terminator
        // must not grow this vector without bound.
        if (modules.size() > (1u << 20)) {
            retireConnection();
            return std::unexpected("ceserver returned too many modules");
        }
    }
    return modules;
}

std::expected<std::vector<int32_t>, std::string>
CEServerClient::enumThreads(int32_t pid) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    uint32_t flags = TH32CS_SNAPTHREAD;
    uint32_t pidField = static_cast<uint32_t>(pid);
    if (!sendCmd(CMD_CREATETOOLHELP32SNAPSHOTEX, error) ||
        !sendAll(&flags, sizeof(flags), error) ||
        !sendAll(&pidField, sizeof(pidField), error))
        return std::unexpected(error);

    int32_t count = 0;
    if (!recvAll(&count, sizeof(count), error))
        return std::unexpected(error);
    if (count < 0 || count > (1 << 20)) {
        retireConnection();
        return std::unexpected("ceserver returned invalid thread count");
    }
    std::vector<int32_t> tids(static_cast<size_t>(count), 0);
    if (count > 0 && !recvAll(tids.data(), static_cast<size_t>(count) * sizeof(int32_t), error))
        return std::unexpected(error);
    return tids;
}

std::expected<uint64_t, std::string>
CEServerClient::allocateMemory(int32_t handle, uint64_t preferredBase, uint32_t size, uint32_t windowsProtection) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_ALLOC, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&preferredBase, sizeof(preferredBase), error) ||
        !sendAll(&size, sizeof(size), error) ||
        !sendAll(&windowsProtection, sizeof(windowsProtection), error))
        return std::unexpected(error);
    uint64_t address = 0;
    if (!recvAll(&address, sizeof(address), error))
        return std::unexpected(error);
    return address;
}

std::expected<uint32_t, std::string>
CEServerClient::freeMemory(int32_t handle, uint64_t address, uint32_t size) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_FREE, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&address, sizeof(address), error) ||
        !sendAll(&size, sizeof(size), error))
        return std::unexpected(error);
    uint32_t result = 0;
    if (!recvAll(&result, sizeof(result), error))
        return std::unexpected(error);
    return result;
}

std::expected<CEServerClient::ProtectionResult, std::string>
CEServerClient::changeMemoryProtection(int32_t handle, uint64_t address, uint32_t size, uint32_t windowsProtection) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_CHANGEMEMORYPROTECTION, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&address, sizeof(address), error) ||
        !sendAll(&size, sizeof(size), error) ||
        !sendAll(&windowsProtection, sizeof(windowsProtection), error))
        return std::unexpected(error);
    ProtectionResult out{};
    if (!recvAll(&out.result, sizeof(out.result), error) ||
        !recvAll(&out.oldProtection, sizeof(out.oldProtection), error))
        return std::unexpected(error);
    return out;
}

std::expected<int32_t, std::string> CEServerClient::startDebug(int32_t handle) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_STARTDEBUG, error) || !sendAll(&handle, sizeof(handle), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<int32_t, std::string> CEServerClient::stopDebug(int32_t handle) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_STOPDEBUG, error) || !sendAll(&handle, sizeof(handle), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<std::optional<CeDebugEvent>, std::string>
CEServerClient::waitForDebugEvent(int32_t handle, int32_t timeoutMs) {
    auto operation=lockConnection();
    beginRequest(timeoutMs);
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_WAITFORDEBUGEVENT, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&timeoutMs, sizeof(timeoutMs), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    if (result == 0) return std::optional<CeDebugEvent>{};

    // DebugEvent wire layout (#pragma pack(1)): int32 + int64 + uint64 = 20 bytes.
    int32_t debugevent = 0;
    int64_t threadid = 0;
    uint64_t address = 0;
    if (!recvAll(&debugevent, sizeof(debugevent), error) ||
        !recvAll(&threadid, sizeof(threadid), error) ||
        !recvAll(&address, sizeof(address), error))
        return std::unexpected(error);
    return std::optional<CeDebugEvent>{CeDebugEvent{debugevent, threadid, address}};
}

std::expected<int32_t, std::string>
CEServerClient::continueFromDebugEvent(int32_t handle, int32_t tid, int32_t signalToForward) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_CONTINUEFROMDEBUGEVENT, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&tid, sizeof(tid), error) ||
        !sendAll(&signalToForward, sizeof(signalToForward), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<int32_t, std::string>
CEServerClient::setRemoteBreakpoint(int32_t handle, int32_t tid, int32_t debugReg,
                                    uint64_t address, int32_t bpType, int32_t bpSize) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    // CeSetBreapointInput layout: handle, tid, debugreg, address, bptype, bpsize.
    if (!sendCmd(CMD_SETBREAKPOINT, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&tid, sizeof(tid), error) ||
        !sendAll(&debugReg, sizeof(debugReg), error) ||
        !sendAll(&address, sizeof(address), error) ||
        !sendAll(&bpType, sizeof(bpType), error) ||
        !sendAll(&bpSize, sizeof(bpSize), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<int32_t, std::string>
CEServerClient::removeRemoteBreakpoint(int32_t handle, uint32_t tid, uint32_t debugReg, uint32_t wasWatchpoint) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_REMOVEBREAKPOINT, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&tid, sizeof(tid), error) ||
        !sendAll(&debugReg, sizeof(debugReg), error) ||
        !sendAll(&wasWatchpoint, sizeof(wasWatchpoint), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<int32_t, std::string> CEServerClient::suspendThread(int32_t handle, int32_t tid) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_SUSPENDTHREAD, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&tid, sizeof(tid), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<int32_t, std::string> CEServerClient::resumeThread(int32_t handle, int32_t tid) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_RESUMETHREAD, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&tid, sizeof(tid), error))
        return std::unexpected(error);
    int32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<std::vector<uint8_t>, std::string>
CEServerClient::getThreadContext(int32_t handle, uint32_t tid) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_GETTHREADCONTEXT, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&tid, sizeof(tid), error))
        return std::unexpected(error);

    uint32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    if (!result) return std::vector<uint8_t>{};

    uint32_t structSize = 0;
    if (!recvAll(&structSize, sizeof(structSize), error)) return std::unexpected(error);
    if (structSize == 0 || structSize > (1u << 20)) {
        retireConnection();
        return std::unexpected("ceserver returned invalid context size");
    }
    std::vector<uint8_t> blob(structSize);
    if (!recvAll(blob.data(), structSize, error)) return std::unexpected(error);
    return blob;
}

std::expected<uint32_t, std::string>
CEServerClient::setThreadContext(int32_t handle, uint32_t tid, const void* contextBlob, uint32_t blobSize) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    if (blobSize == 0) return std::unexpected("setThreadContext requires a non-empty blob");
    std::string error;
    if (!sendCmd(CMD_SETTHREADCONTEXT, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&tid, sizeof(tid), error) ||
        !sendAll(&blobSize, sizeof(blobSize), error) ||
        !sendAll(contextBlob, blobSize, error))
        return std::unexpected(error);
    uint32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<uint32_t, std::string>
CEServerClient::speedhackSetSpeed(int32_t handle, float speed) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    if (!sendCmd(CMD_SPEEDHACK_SETSPEED, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&speed, sizeof(speed), error))
        return std::unexpected(error);
    uint32_t result = 0;
    if (!recvAll(&result, sizeof(result), error)) return std::unexpected(error);
    return result;
}

std::expected<std::optional<std::vector<uint8_t>>, std::string>
CEServerClient::getSymbolListFromFile(const std::string& symbolPath, uint32_t fileOffset) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    std::string error;
    uint32_t pathSize = static_cast<uint32_t>(symbolPath.size());
    if (!sendCmd(CMD_GETSYMBOLLISTFROMFILE, error) ||
        !sendAll(&fileOffset, sizeof(fileOffset), error) ||
        !sendAll(&pathSize, sizeof(pathSize), error))
        return std::unexpected(error);
    if (pathSize > 0 && !sendAll(symbolPath.data(), pathSize, error))
        return std::unexpected(error);

    // Read the 8-byte header. bytes[4..7] = total payload size (including the
    // header itself). All-zero bytes signal "no symbols available".
    uint8_t header[8] = {};
    if (!recvAll(header, sizeof(header), error)) return std::unexpected(error);
    uint32_t totalSize = 0;
    std::memcpy(&totalSize, header + 4, 4);
    if (totalSize == 0) return std::optional<std::vector<uint8_t>>{};
    if (totalSize < 8 || totalSize > (1u << 28)) {
        retireConnection();
        return std::unexpected("ceserver returned implausible symbol payload size");
    }

    std::vector<uint8_t> blob(totalSize);
    std::memcpy(blob.data(), header, 8);
    size_t remaining = totalSize - 8;
    if (remaining > 0 && !recvAll(blob.data() + 8, remaining, error))
        return std::unexpected(error);
    return std::optional<std::vector<uint8_t>>{std::move(blob)};
}

std::expected<int32_t, std::string>
CEServerClient::writeProcessMemory(int32_t handle, uint64_t address, const void* buffer, int32_t size) {
    auto operation=lockConnection();
    beginRequest();
    if (fd_ < 0) return std::unexpected("not connected");
    if (size < 0) return std::unexpected("negative write size");
    std::string error;
    int64_t addressField = static_cast<int64_t>(address);
    if (!sendCmd(CMD_WRITEPROCESSMEMORY, error) ||
        !sendAll(&handle, sizeof(handle), error) ||
        !sendAll(&addressField, sizeof(addressField), error) ||
        !sendAll(&size, sizeof(size), error))
        return std::unexpected(error);
    if (size > 0 && !sendAll(buffer, static_cast<size_t>(size), error))
        return std::unexpected(error);

    int32_t written = 0;
    if (!recvAll(&written, sizeof(written), error))
        return std::unexpected(error);
    if (written < 0 || written > size) {
        retireConnection();
        return std::unexpected("ceserver returned invalid write length");
    }
    return written;
}

} // namespace ce::os
