#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/linux_process.hpp"
#include "debug/debug_session.hpp"

#include <sys/socket.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <condition_variable>
#include <deque>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <limits>
#include <array>
#include <cerrno>

namespace ce::os {
namespace {

// Opcodes must match platform/linux/ceserver_client.cpp (CE's ceserver protocol).
constexpr uint8_t CMD_GETVERSION         = 0;
constexpr uint8_t CMD_OPENPROCESS        = 3;
constexpr uint8_t CMD_CLOSEHANDLE        = 7;
constexpr uint8_t CMD_VIRTUALQUERYEX      = 8;
constexpr uint8_t CMD_CHANGEMEMORYPROTECTION = 36;
constexpr uint8_t CMD_READPROCESSMEMORY  = 9;
constexpr uint8_t CMD_WRITEPROCESSMEMORY = 10;
constexpr uint8_t CMD_STARTDEBUG              = 11;
constexpr uint8_t CMD_STOPDEBUG               = 12;
constexpr uint8_t CMD_WAITFORDEBUGEVENT       = 13;
constexpr uint8_t CMD_CONTINUEFROMDEBUGEVENT  = 14;
constexpr uint8_t CMD_SETBREAKPOINT           = 15;
constexpr uint8_t CMD_REMOVEBREAKPOINT        = 16;
constexpr uint8_t CMD_GETARCHITECTURE    = 21;
constexpr uint8_t CMD_ALLOC              = 26;
constexpr uint8_t CMD_FREE               = 27;
constexpr uint8_t CMD_VIRTUALQUERYEXFULL = 31;
constexpr uint8_t CMD_CREATETOOLHELP32SNAPSHOTEX = 35;
constexpr uint32_t TH32CS_SNAPTHREAD = 0x4;
constexpr uint32_t TH32CS_SNAPMODULE = 0x8;

// Cap a single client read/write so a hostile/corrupt size can't OOM the server
// (a negative int32 write size cast to size_t is ~2^64) or drive a huge vector.
constexpr uint32_t kMaxTransfer = 64u * 1024 * 1024;  // 64 MB

void notifyAccept(int fd) {
    uint64_t value=1;
    ssize_t result;
    do { result=::write(fd,&value,sizeof(value)); } while (result<0 && errno==EINTR);
    // EAGAIN means the event counter is already full and the accept owner is
    // already wakeable. The fd remains owned until all workers have joined.
}

bool recvAll(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    while (n > 0) {
        ssize_t r = ::recv(fd, p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}
bool sendAll(int fd, const void* buf, size_t n) {
    auto* p = static_cast<const uint8_t*>(buf);
    while (n > 0) {
        ssize_t r = ::send(fd, p, n, MSG_NOSIGNAL);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return false;
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}

// Protocol protection/type fields use Windows values, independently of the
// engine's Linux rwx bits and enum ordinals.
uint32_t wireProtection(MemProt p) {
    if (p & MemProt::Exec) {
        if (p & MemProt::Write) return 0x40;
        return p & MemProt::Read ? 0x20 : 0x10;
    }
    if (p & MemProt::Write) return 0x04;
    return p & MemProt::Read ? 0x02 : 0x01;
}
std::optional<MemProt> nativeProtection(uint32_t p) {
    switch (p) {
        case 0x01: return MemProt::None;
        case 0x02: return MemProt::Read;
        case 0x04: case 0x08: return MemProt::ReadWrite;
        case 0x10: return MemProt::Exec;
        case 0x20: return MemProt::ReadExec;
        case 0x40: case 0x80: return MemProt::All;
        default: return std::nullopt;
    }
}
uint32_t wireType(MemType t) {
    switch (t) {
        case MemType::Image: return 0x1000000;
        case MemType::Mapped: return 0x40000;
        default: return 0x20000;
    }
}

} // namespace

// Connection objects stay at a stable address until their worker has joined.
// Destroy the debug session first: its callback uses the queue and mutex.
struct CeserverServer::ClientState {
    explicit ClientState(int socket) : fd(socket) {}
    int fd;
    std::thread thread;
    std::atomic<bool> finished{false};
    struct DebugEventRec { int32_t debugevent=0;int64_t tid=0;uint64_t address=0; };
    std::mutex dbgMutex;
    std::condition_variable dbgCv;
    std::deque<DebugEventRec> dbgQueue;
    std::shared_ptr<ce::ProcessHandle> dbgProc;
    std::unique_ptr<ce::DebugSession> dbg;
};

CeserverServer::CeserverServer() = default;
CeserverServer::~CeserverServer() { stop(); }

uint16_t CeserverServer::start(uint16_t port) {
    std::lock_guard lifecycle(lifecycleMutex_);
    if (running_.load() || thread_.joinable()) return 0;
    int listener=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (listener<0) return 0;
    int one=1;
    setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    sockaddr_in addr{};addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons(port);
    socklen_t len=sizeof(addr);
    if (::bind(listener,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))<0 ||
        ::listen(listener,SOMAXCONN)<0 ||
        getsockname(listener,reinterpret_cast<sockaddr*>(&addr),&len)<0) {
        ::close(listener);return 0;
    }
    int wake=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    if (wake<0) { ::close(listener);return 0; }
    listenFd_=listener;wakeFd_=wake;port_=ntohs(addr.sin_port);running_=true;
    try { thread_=std::thread(&CeserverServer::acceptLoop,this,listener,wake); }
    catch (...) {
        running_=false;port_=0;::close(listener);::close(wake);listenFd_=-1;wakeFd_=-1;
        return 0;
    }
    return port_.load();
}

void CeserverServer::interruptClients() {
    std::lock_guard sockets(socketMutex_);
    for (auto& client:clients_) {
        if (client->fd>=0) ::shutdown(client->fd,SHUT_RDWR);
        // Synchronize with wait_for's predicate-to-wait transition. Notifying
        // without this mutex could lose shutdown between the two operations.
        std::lock_guard events(client->dbgMutex);
        client->dbgCv.notify_all();
    }
}

void CeserverServer::stop() {
    std::lock_guard lifecycle(lifecycleMutex_);
    running_=false;
    if (listenFd_>=0) ::shutdown(listenFd_,SHUT_RDWR);
    if (wakeFd_>=0) notifyAccept(wakeFd_);
    interruptClients();
    if (thread_.joinable()) thread_.join();
    // Accept is gone; the collection is stable. Join without the socket mutex
    // so each worker can close its own descriptor and publish completion.
    for (auto& client:clients_) if (client->thread.joinable()) client->thread.join();
    clients_.clear();
    if (listenFd_>=0) { ::close(listenFd_);listenFd_=-1; }
    if (wakeFd_>=0) { ::close(wakeFd_);wakeFd_=-1; }
    port_=0;
}

void CeserverServer::acceptLoop(int listener,int wakeFd) {
    while (running_.load()) {
        {
            std::lock_guard sockets(socketMutex_);
            for (auto it=clients_.begin();it!=clients_.end();) {
                if ((*it)->finished.load()) {
                    (*it)->thread.join();it=clients_.erase(it);
                } else ++it;
            }
        }
        pollfd fds[]={{listener,POLLIN,0},{wakeFd,POLLIN,0}};
        int ready=::poll(fds,2,-1);
        if (ready<0 && errno==EINTR) continue;
        if (ready<0) break;
        if (fds[1].revents&POLLIN) {
            uint64_t value;ssize_t result;
            do { result=::read(wakeFd,&value,sizeof(value)); } while (result<0 && errno==EINTR);
        }
        if (!running_.load()) break;
        if (!(fds[0].revents&POLLIN)) {
            if (fds[0].revents&(POLLERR|POLLHUP|POLLNVAL)) break;
            continue;
        }
        int fd=::accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);
        if (fd<0 && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK)) continue;
        if (fd<0) {
            if (errno==ECONNABORTED || errno==EPROTO) continue;
            if (errno==EMFILE || errno==ENFILE || errno==ENOBUFS || errno==ENOMEM) {
                // Keep existing clients alive and avoid spinning on a readable
                // backlog while the kernel cannot allocate another socket.
                pollfd wake{wakeFd,POLLIN,0};(void)::poll(&wake,1,100);
                continue;
            }
            break;
        }
        std::lock_guard sockets(socketMutex_);
        if (!running_.load()) { ::close(fd);break; }
        // Resource exhaustion affects this connection, not the accept owner or
        // existing clients. There is no fixed application-level client limit.
        try {
            auto state=std::make_unique<ClientState>(fd);
            clients_.push_back(std::move(state));
            auto* client=clients_.back().get();
            try {
                client->thread=std::thread([this,client,wakeFd] {
                    try { serveClient(*client); } catch (...) { /* close only this connection */ }
                    client->dbg.reset();client->dbgProc.reset();
                    {
                        std::lock_guard sockets(socketMutex_);
                        ::close(client->fd);client->fd=-1;client->finished=true;
                    }
                    notifyAccept(wakeFd);
                });
            } catch (...) { clients_.pop_back();throw; }
        } catch (...) { ::close(fd); }
    }
    running_=false;
    interruptClients();
}

void CeserverServer::serveClient(ClientState& client) {
    const int fd=client.fd;
    std::unordered_map<int32_t,std::shared_ptr<LinuxProcessHandle>> processes;
    int32_t nextHandle=1, debugHandle=0;
    std::array<int,4> breakpointIds{};
    std::array<bool,4> hardwareBreakpoints{};
    auto removeSlot=[&](unsigned slot) {
        if (!breakpointIds[slot]) return false;
        bool removed=hardwareBreakpoints[slot]
            ? client.dbg->removeHardwareBreakpoint(breakpointIds[slot])
            : client.dbg->removeSoftwareBreakpoint(breakpointIds[slot]);
        if (removed) breakpointIds[slot]=0;
        return removed;
    };
    auto process=[&](int32_t handle) -> std::shared_ptr<LinuxProcessHandle> {
        auto found=processes.find(handle);
        return found==processes.end() ? nullptr : found->second;
    };
    auto stopDebug=[&] {
        client.dbg.reset();client.dbgProc.reset();debugHandle=0;breakpointIds.fill(0);
        std::lock_guard<std::mutex> lk(client.dbgMutex);client.dbgQueue.clear();
    };
    while (running_.load()) {
        uint8_t cmd = 0;
        if (!recvAll(fd, &cmd, 1)) return;
        switch (cmd) {
            case CMD_GETVERSION: {
                int32_t proto = 1;
                const char* ver = "cecore ceserver";
                uint8_t vlen = static_cast<uint8_t>(std::strlen(ver));
                if (!sendAll(fd, &proto, 4) || !sendAll(fd, &vlen, 1) || !sendAll(fd, ver, vlen))
                    return;
                break;
            }
            case CMD_OPENPROCESS: {
                int32_t pid = 0;
                if (!recvAll(fd, &pid, 4)) return;
                int32_t handle=0;
                if (pid>0 && nextHandle<std::numeric_limits<int32_t>::max()) {
                    auto opened=std::make_shared<LinuxProcessHandle>(static_cast<pid_t>(pid));
                    if (opened->targetDescription().live) {
                        handle=nextHandle++;
                        processes.emplace(handle,std::move(opened));
                    }
                }
                if (!sendAll(fd, &handle, 4)) return;
                break;
            }
            case CMD_CLOSEHANDLE: {
                int32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                if (handle==debugHandle) stopDebug();
                int32_t result = processes.erase(handle) ? 1 : 0;
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_READPROCESSMEMORY: {
                uint32_t handle = 0, size = 0; uint64_t address = 0; uint8_t compress = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &address, 8) ||
                    !recvAll(fd, &size, 4) || !recvAll(fd, &compress, 1)) return;
                if (size > kMaxTransfer) { int32_t got = 0; if (!sendAll(fd, &got, 4)) return; break; }
                std::vector<uint8_t> buf(size);
                auto proc=process(static_cast<int32_t>(handle));
                int32_t got=0;
                if (proc) {
                    auto r=proc->read(static_cast<uintptr_t>(address),buf.data(),size);
                    got=r ? static_cast<int32_t>(*r) : 0;
                }
                if (!sendAll(fd, &got, 4)) return;
                if (got > 0 && !sendAll(fd, buf.data(), static_cast<size_t>(got))) return;
                break;
            }
            case CMD_WRITEPROCESSMEMORY: {
                int32_t handle = 0, size = 0; int64_t address = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &address, 8) ||
                    !recvAll(fd, &size, 4)) return;
                // Reject a bad size by dropping the connection: the announced
                // bytes were not read, so the stream can no longer be trusted.
                if (size < 0 || static_cast<uint32_t>(size) > kMaxTransfer) return;
                std::vector<uint8_t> buf(static_cast<size_t>(size));
                if (size > 0 && !recvAll(fd, buf.data(), static_cast<size_t>(size))) return;
                auto proc=process(handle);
                int32_t written=0;
                if (proc) {
                    auto r=proc->write(static_cast<uintptr_t>(address),buf.data(),static_cast<size_t>(size));
                    written=r ? static_cast<int32_t>(*r) : 0;
                }
                if (!sendAll(fd, &written, 4)) return;
                break;
            }
            case CMD_GETARCHITECTURE: {
                int32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                uint8_t arch=0xff;
                auto proc=process(handle);
                if (proc) {
                    auto description=proc->targetDescription();
                    if (description.live) switch (description.program.architecture) {
                        case CpuArchitecture::X86_32: arch=0;break;
                        case CpuArchitecture::X86_64: arch=1;break;
                        case CpuArchitecture::Arm32: arch=2;break;
                        case CpuArchitecture::Arm64: arch=3;break;
                        default: break;
                    }
                }
                if (!sendAll(fd, &arch, 1)) return;
                break;
            }
            case CMD_VIRTUALQUERYEX: {
                int32_t handle=0;uint64_t address=0;
                if (!recvAll(fd,&handle,4) || !recvAll(fd,&address,8)) return;
                auto proc=process(handle);
                auto region=proc ? proc->queryRegion(static_cast<uintptr_t>(address)) : std::nullopt;
                uint8_t result=region ? 1 : 0;
                uint32_t protection=region ? wireProtection(region->protection) : 0;
                uint32_t type=region ? wireType(region->type) : 0;
                uint64_t base=region ? region->base : 0,size=region ? region->size : 0;
                if (!sendAll(fd,&result,1) || !sendAll(fd,&protection,4) ||
                    !sendAll(fd,&type,4) || !sendAll(fd,&base,8) || !sendAll(fd,&size,8)) return;
                break;
            }
            case CMD_CHANGEMEMORYPROTECTION: {
                int32_t handle=0;uint64_t address=0;uint32_t size=0,prot=0;
                if (!recvAll(fd,&handle,4) || !recvAll(fd,&address,8) ||
                    !recvAll(fd,&size,4) || !recvAll(fd,&prot,4)) return;
                auto proc=process(handle);auto protection=nativeProtection(prot);
                uint32_t result=0,oldProtection=0;
                if (proc && protection) {
                    auto old=proc->queryRegion(static_cast<uintptr_t>(address));
                    if (old && proc->protect(static_cast<uintptr_t>(address),size,*protection)) {
                        result=1;oldProtection=wireProtection(old->protection);
                    }
                }
                if (!sendAll(fd,&result,4) || !sendAll(fd,&oldProtection,4)) return;
                break;
            }
            case CMD_VIRTUALQUERYEXFULL: {
                int32_t handle = 0; uint8_t flags = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &flags, 1)) return;
                auto proc=process(handle);
                auto regions=proc ? proc->queryRegions() : std::vector<MemoryRegion>{};
                int32_t count = static_cast<int32_t>(regions.size());
                if (!sendAll(fd, &count, 4)) return;
                for (auto& reg : regions) {
                    uint32_t protection = wireProtection(reg.protection);
                    uint32_t type = wireType(reg.type);
                    uint64_t base = reg.base, size = reg.size;
                    if (!sendAll(fd, &protection, 4) || !sendAll(fd, &type, 4) ||
                        !sendAll(fd, &base, 8) || !sendAll(fd, &size, 8)) return;
                }
                break;
            }
            case CMD_CREATETOOLHELP32SNAPSHOTEX: {
                uint32_t flags = 0, pid = 0;
                if (!recvAll(fd, &flags, 4) || !recvAll(fd, &pid, 4)) return;
                LinuxProcessHandle proc(static_cast<pid_t>(pid));
                if (flags & TH32CS_SNAPTHREAD) {
                    auto threads = proc.threads();
                    int32_t count = static_cast<int32_t>(threads.size());
                    if (!sendAll(fd, &count, 4)) return;
                    for (auto& t : threads) {
                        int32_t tid = t.tid;
                        if (!sendAll(fd, &tid, 4)) return;
                    }
                } else if (flags & TH32CS_SNAPMODULE) {
                    // Streamed CeModuleEntry list, terminated by a result==0 entry.
                    auto modules = proc.modules();
                    auto sendEntry = [&](int32_t result, uint64_t base, int32_t modSize,
                                         const std::string& name) -> bool {
                        int64_t base64 = static_cast<int64_t>(base);
                        int32_t part = 0, nameSize = static_cast<int32_t>(name.size());
                        uint32_t fileOff = 0;
                        if (!sendAll(fd, &result, 4) || !sendAll(fd, &base64, 8) ||
                            !sendAll(fd, &part, 4) || !sendAll(fd, &modSize, 4) ||
                            !sendAll(fd, &fileOff, 4) || !sendAll(fd, &nameSize, 4)) return false;
                        if (nameSize > 0 && !sendAll(fd, name.data(), static_cast<size_t>(nameSize)))
                            return false;
                        return true;
                    };
                    for (auto& m : modules)
                        if (!sendEntry(1, m.base, static_cast<int32_t>(m.size),
                                       m.name.empty() ? m.path : m.name)) return;
                    if (!sendEntry(0, 0, 0, std::string())) return;   // terminator
                } else {
                    int32_t count = 0;
                    if (!sendAll(fd, &count, 4)) return;   // unknown snapshot flags
                }
                break;
            }
            case CMD_ALLOC: {
                int32_t handle = 0; uint64_t preferredBase = 0; uint32_t size = 0, prot = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &preferredBase, 8) ||
                    !recvAll(fd, &size, 4) || !recvAll(fd, &prot, 4)) return;
                auto proc=process(handle);
                auto protection=nativeProtection(prot);
                uint64_t address=0;
                if (proc && protection) {
                    auto r=proc->allocate(size,*protection,static_cast<uintptr_t>(preferredBase));
                    if (r) address=*r;
                }
                if (!sendAll(fd, &address, 8)) return;
                break;
            }
            case CMD_FREE: {
                int32_t handle = 0; uint64_t address = 0; uint32_t size = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &address, 8) ||
                    !recvAll(fd, &size, 4)) return;
                auto proc=process(handle);
                uint32_t result=proc && proc->free(static_cast<uintptr_t>(address),size) ? 1 : 0;
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_STARTDEBUG: {
                int32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                stopDebug();
                auto proc=process(handle);
                if (!proc || !proc->targetDescription().live) {
                    int32_t result=0;
                    if (!sendAll(fd,&result,4)) return;
                    break;
                }
                client.dbgProc=proc;
                debugHandle=handle;
                client.dbg = std::make_unique<ce::DebugSession>();
                client.dbg->setEventCallback([&client](const ce::DebugEvent& e) {
                    // Tracer thread — enqueue only, never block on the socket.
                    int32_t ev = (e.type == ce::DebugEventType::BreakpointHit ||
                                  e.type == ce::DebugEventType::ExceptionBreakpointHit) ? 5 : 1;
                    { std::lock_guard<std::mutex> lk(client.dbgMutex);
                      client.dbgQueue.push_back({ev, static_cast<int64_t>(e.tid),
                                           static_cast<uint64_t>(e.address)}); }
                    client.dbgCv.notify_all();
                });
                int32_t result = client.dbg->attach(proc->pid(), client.dbgProc.get()) ? 1 : 0;
                if (!result) stopDebug();
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_STOPDEBUG: {
                int32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                int32_t result=client.dbg && handle==debugHandle ? 1 : 0;
                if (result) stopDebug();
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_SETBREAKPOINT: {
                int32_t handle = 0, tid = 0, debugReg = 0, bpType = 0, bpSize = 0;
                uint64_t address = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &tid, 4) ||
                    !recvAll(fd, &debugReg, 4) || !recvAll(fd, &address, 8) ||
                    !recvAll(fd, &bpType, 4) || !recvAll(fd, &bpSize, 4)) return;
                int32_t result = 0;
                if (client.dbg && handle==debugHandle && debugReg>=0 && debugReg<4) {
                    if (breakpointIds[debugReg] && !removeSlot(debugReg)) {
                        if (!sendAll(fd,&result,4)) return;
                        break;
                    }
                    int id = (bpType == 0)
                        ? client.dbg->setSoftwareBreakpoint(static_cast<uintptr_t>(address))
                        : client.dbg->setHardwareBreakpoint(static_cast<uintptr_t>(address), bpType, bpSize);
                    result = (id > 0) ? 1 : 0;
                    breakpointIds[debugReg]=id>0 ? id : 0;
                    hardwareBreakpoints[debugReg]=bpType!=0;
                    client.dbg->continueExecution();
                }
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_REMOVEBREAKPOINT: {
                int32_t handle = 0, tid = 0, debugReg = 0, wasWatchpoint = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &tid, 4) ||
                    !recvAll(fd, &debugReg, 4) || !recvAll(fd, &wasWatchpoint, 4)) return;
                int32_t result=0;
                if (client.dbg && handle==debugHandle && debugReg>=0 && debugReg<4 && breakpointIds[debugReg]) {
                    result=removeSlot(debugReg) ? 1 : 0;
                }
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_WAITFORDEBUGEVENT: {
                int32_t handle = 0, timeoutMs = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &timeoutMs, 4)) return;
                ClientState::DebugEventRec rec{};
                bool have = false;
                {
                    std::unique_lock<std::mutex> lk(client.dbgMutex);
                    if (client.dbg && handle==debugHandle)
                        have = client.dbgCv.wait_for(lk, std::chrono::milliseconds(timeoutMs < 0 ? 0 : timeoutMs),
                            [this,&client] { return !client.dbgQueue.empty() || !running_.load(); });
                    have=have && !client.dbgQueue.empty();
                    if (have) { rec = client.dbgQueue.front(); client.dbgQueue.pop_front(); }
                }
                int32_t result = have ? 1 : 0;
                if (!sendAll(fd, &result, 4)) return;
                if (have && (!sendAll(fd, &rec.debugevent, 4) || !sendAll(fd, &rec.tid, 8) ||
                             !sendAll(fd, &rec.address, 8))) return;
                break;
            }
            case CMD_CONTINUEFROMDEBUGEVENT: {
                int32_t handle = 0, tid = 0, sig = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &tid, 4) || !recvAll(fd, &sig, 4)) return;
                int32_t result=client.dbg && handle==debugHandle ? 1 : 0;
                if (result) client.dbg->continueExecution();
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            default:
                return;   // unsupported command -> drop the connection
        }
    }
}

} // namespace ce::os
