#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/linux_process.hpp"
#include "debug/debug_session.hpp"
#include "platform/network_compression.hpp"

#include <sys/socket.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <condition_variable>
#include <deque>
#include <netinet/in.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <limits>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <optional>
#include <sstream>

namespace ce::os {
namespace {

// Opcodes must match platform/linux/ceserver_client.cpp (CE's ceserver protocol).
constexpr uint8_t CMD_GETVERSION         = 0;
constexpr uint8_t CMD_CLOSECONNECTION    = 1;
constexpr uint8_t CMD_TERMINATESERVER    = 2;
constexpr uint8_t CMD_OPENPROCESS        = 3;
constexpr uint8_t CMD_CREATETOOLHELP32SNAPSHOT = 4;
constexpr uint8_t CMD_PROCESS32FIRST     = 5;
constexpr uint8_t CMD_PROCESS32NEXT      = 6;
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
constexpr uint8_t CMD_SUSPENDTHREAD           = 17;
constexpr uint8_t CMD_RESUMETHREAD            = 18;
constexpr uint8_t CMD_GETTHREADCONTEXT        = 19;
constexpr uint8_t CMD_SETTHREADCONTEXT        = 20;
constexpr uint8_t CMD_GETARCHITECTURE    = 21;
constexpr uint8_t CMD_MODULE32FIRST      = 22;
constexpr uint8_t CMD_MODULE32NEXT       = 23;
constexpr uint8_t CMD_GETSYMBOLLISTFROMFILE = 24;
constexpr uint8_t CMD_LOADEXTENSION      = 25;
constexpr uint8_t CMD_ALLOC              = 26;
constexpr uint8_t CMD_FREE               = 27;
constexpr uint8_t CMD_CREATETHREAD       = 28;
constexpr uint8_t CMD_SPEEDHACK_SETSPEED = 30;
constexpr uint8_t CMD_VIRTUALQUERYEXFULL = 31;
constexpr uint8_t CMD_GETREGIONINFO      = 32;
constexpr uint8_t CMD_GETABI             = 33;
constexpr uint8_t CMD_SET_CONNECTION_NAME = 34;
constexpr uint8_t CMD_CREATETOOLHELP32SNAPSHOTEX = 35;
constexpr uint8_t CMD_GETOPTIONS         = 37;
constexpr uint8_t CMD_GETOPTIONVALUE     = 38;
constexpr uint8_t CMD_SETOPTIONVALUE     = 39;
constexpr uint8_t CMD_GETCESERVERPATH    = 44;
constexpr uint8_t CMD_ISANDROID          = 45;
constexpr uint32_t TH32CS_SNAPPROCESS = 0x2;
constexpr uint32_t TH32CS_SNAPTHREAD = 0x4;
constexpr uint32_t TH32CS_SNAPMODULE = 0x8;
constexpr uint32_t PAGE_NOACCESS = 0x01;

// Cap a single client read/write so a hostile/corrupt size can't OOM the server
// (a negative int32 write size cast to size_t is ~2^64) or drive a huge vector.
constexpr uint32_t kMaxTransfer = 64u * 1024 * 1024;  // 64 MB
// Upstream clients keep only the low 24 bits of a handle (the top byte tags
// it as a network handle), so process and snapshot handles stay below 2^24.
constexpr int32_t kMaxHandle = 0xffffff;
// Bound on length-prefixed strings and blobs this server reads and discards.
constexpr uint32_t kMaxDiscard = 64u * 1024;

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
bool discardAll(int fd, size_t n) {
    char scratch[4096];
    while (n > 0) {
        const size_t part = std::min(n, sizeof scratch);
        if (!recvAll(fd, scratch, part)) return false;
        n -= part;
    }
    return true;
}
// Upstream string16: a uint16 length, then that many bytes.
bool discardString16(int fd) {
    uint16_t length = 0;
    return recvAll(fd, &length, 2) && discardAll(fd, length);
}
bool sendString16(int fd, const std::string& text) {
    const uint16_t length = static_cast<uint16_t>(std::min<size_t>(text.size(), UINT16_MAX));
    return sendAll(fd, &length, 2) && (!length || sendAll(fd, text.data(), length));
}

// True once the client has hung up or reset. A command that waits must not
// keep a target stopped and traced for a peer that is gone.
bool peerGone(int fd) {
    pollfd p{fd, POLLIN | POLLRDHUP, 0};
    int ready;
    do { ready = ::poll(&p, 1, 0); } while (ready < 0 && errno == EINTR);
    if (ready < 0) return true;
    if (!ready) return false;
    if (p.revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)) return true;
    // Readable: either the next command was sent early or the stream ended.
    char byte;
    ssize_t n;
    do { n = ::recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT); } while (n < 0 && errno == EINTR);
    return n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
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

// The uid owning the client end of an accepted loopback connection, from
// /proc/net/tcp (tableFd, re-read from the start each time): the client's
// socket has the peer address as its local end and ours as its remote end.
static std::optional<uid_t> loopbackPeerUid(int fd, int tableFd) {
    sockaddr_in peer{}, self{};
    socklen_t peerLength = sizeof peer, selfLength = sizeof self;
    if (getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &peerLength) != 0 || peer.sin_family != AF_INET ||
        getsockname(fd, reinterpret_cast<sockaddr*>(&self), &selfLength) != 0)
        return std::nullopt;
    // /proc/net/tcp prints the address as the raw 32-bit value in host order.
    char wantLocal[32], wantRemote[32];
    std::snprintf(wantLocal, sizeof wantLocal, "%08X:%04X", peer.sin_addr.s_addr, ntohs(peer.sin_port));
    std::snprintf(wantRemote, sizeof wantRemote, "%08X:%04X", self.sin_addr.s_addr, ntohs(self.sin_port));
    std::string contents;
    char buffer[16384];
    for (off_t offset = 0;;) {
        const ssize_t got = ::pread(tableFd, buffer, sizeof buffer, offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        contents.append(buffer, static_cast<size_t>(got));
        offset += got;
    }
    std::istringstream table(contents);
    std::string line;
    std::getline(table, line);   // header
    while (std::getline(table, line)) {
        std::istringstream fields(line);
        std::string slot, local, remote, state, queues, timer, retransmits;
        unsigned long uid = 0;
        if (!(fields >> slot >> local >> remote >> state >> queues >> timer >> retransmits >> uid)) continue;
        if (local == wantLocal && remote == wantRemote) return static_cast<uid_t>(uid);
    }
    return std::nullopt;
}

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
    const int tcpTable=::open("/proc/net/tcp",O_RDONLY|O_CLOEXEC);
    if (tcpTable<0) { ::close(listener);::close(wake);return 0; }
    tcpTableFd_=tcpTable;
    listenFd_=listener;wakeFd_=wake;port_=ntohs(addr.sin_port);running_=true;
    try { thread_=std::thread(&CeserverServer::acceptLoop,this,listener,wake); }
    catch (...) {
        running_=false;port_=0;::close(listener);::close(wake);listenFd_=-1;wakeFd_=-1;::close(tcpTableFd_);tcpTableFd_=-1;
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
    if (tcpTableFd_>=0) { ::close(tcpTableFd_);tcpTableFd_=-1; }
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
        // The protocol has no authentication and grants full access to this
        // user's processes, so only this user's own programs may connect.
        if (auto owner = loopbackPeerUid(fd, tcpTableFd_); !owner || *owner != getuid()) { ::close(fd); continue; }
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
    // Toolhelp snapshots for PROCESS32FIRST/NEXT and MODULE32FIRST/NEXT. They
    // share the handle space with processes, as upstream handles do.
    struct Snapshot {
        struct Entry { int32_t pid=0; uint64_t base=0; uint64_t size=0; std::string name; };
        bool modules=false;
        std::vector<Entry> entries;
        size_t next=0;
    };
    std::unordered_map<int32_t,Snapshot> snapshots;
    int32_t nextHandle=1, debugHandle=0;
    // The thread of the stop last handed to the client by WAITFORDEBUGEVENT
    // and not yet continued. A continue must acknowledge exactly that stop.
    std::optional<int64_t> deliveredStop;
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
        client.dbg.reset();client.dbgProc.reset();debugHandle=0;breakpointIds.fill(0);deliveredStop.reset();
        std::lock_guard<std::mutex> lk(client.dbgMutex);client.dbgQueue.clear();
    };
    auto takeHandle=[&]() -> int32_t {
        // Each process handle holds a pidfd: a bounded number per connection.
        if (nextHandle>kMaxHandle || processes.size()+snapshots.size()>=256) return 0;
        return nextHandle++;
    };
    auto snapshot=[&](uint32_t flags,uint32_t pid) -> int32_t {
        Snapshot taken;
        if (flags & TH32CS_SNAPPROCESS) {
            for (auto& p : LinuxProcessEnumerator().list())
                taken.entries.push_back({static_cast<int32_t>(p.pid),0,0,p.path.empty() ? p.name : p.path});
        } else if (flags & TH32CS_SNAPMODULE) {
            taken.modules=true;
            for (auto& m : LinuxProcessHandle(static_cast<pid_t>(pid)).modules())
                taken.entries.push_back({0,m.base,m.size,m.path.empty() ? m.name : m.path});
        } else return 0;
        const int32_t handle=takeHandle();
        if (handle) snapshots.emplace(handle,std::move(taken));
        return handle;
    };
    // Upstream CeModuleEntry: result, base, part, size, file offset, name size, name.
    auto sendModuleEntry=[&](int32_t result,uint64_t base,uint64_t size,const std::string& name) {
        int64_t base64=static_cast<int64_t>(base);
        int32_t part=0,moduleSize=static_cast<int32_t>(static_cast<uint32_t>(std::min<uint64_t>(size,UINT32_MAX)));
        int32_t nameSize=static_cast<int32_t>(name.size());
        uint32_t fileOffset=0;
        return sendAll(fd,&result,4) && sendAll(fd,&base64,8) && sendAll(fd,&part,4) &&
               sendAll(fd,&moduleSize,4) && sendAll(fd,&fileOffset,4) && sendAll(fd,&nameSize,4) &&
               (!nameSize || sendAll(fd,name.data(),static_cast<size_t>(nameSize)));
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
            // TERMINATESERVER ends only this connection: the server belongs to
            // the application that started it, not to a client.
            case CMD_CLOSECONNECTION:
            case CMD_TERMINATESERVER:
                return;
            case CMD_GETABI: {
                uint8_t abi = 1;   // upstream: 0 Windows, 1 everything else
                if (!sendAll(fd, &abi, 1)) return;
                break;
            }
            case CMD_ISANDROID: {
                uint8_t android = 0;
                if (!sendAll(fd, &android, 1)) return;
                break;
            }
            case CMD_SET_CONNECTION_NAME: {
                // A label for upstream's server log; no reply.
                uint32_t length = 0;
                if (!recvAll(fd, &length, 4) || length > kMaxDiscard || !discardAll(fd, length)) return;
                break;
            }
            case CMD_GETOPTIONS: {
                uint16_t count = 0;   // no server options
                if (!sendAll(fd, &count, 2)) return;
                break;
            }
            case CMD_GETOPTIONVALUE: {
                if (!discardString16(fd) || !sendString16(fd, {})) return;
                break;
            }
            case CMD_SETOPTIONVALUE: {
                if (!discardString16(fd) || !discardString16(fd)) return;
                break;
            }
            case CMD_GETCESERVERPATH: {
                if (!sendString16(fd, {})) return;
                break;
            }
            case CMD_OPENPROCESS: {
                int32_t pid = 0;
                if (!recvAll(fd, &pid, 4)) return;
                int32_t handle=0;
                if (pid>0) {
                    auto opened=std::make_shared<LinuxProcessHandle>(static_cast<pid_t>(pid));
                    if (opened->targetDescription().live && (handle=takeHandle()))
                        processes.emplace(handle,std::move(opened));
                }
                if (!sendAll(fd, &handle, 4)) return;
                break;
            }
            case CMD_CLOSEHANDLE: {
                int32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                if (handle==debugHandle) stopDebug();
                int32_t result = processes.erase(handle) || snapshots.erase(handle) ? 1 : 0;
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_CREATETOOLHELP32SNAPSHOT: {
                uint32_t flags = 0, pid = 0;
                if (!recvAll(fd, &flags, 4) || !recvAll(fd, &pid, 4)) return;
                int32_t handle = snapshot(flags, pid);
                if (!sendAll(fd, &handle, 4)) return;
                break;
            }
            case CMD_PROCESS32FIRST:
            case CMD_PROCESS32NEXT: {
                uint32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                auto found = snapshots.find(static_cast<int32_t>(handle));
                const Snapshot::Entry* entry = nullptr;
                if (found != snapshots.end() && !found->second.modules) {
                    auto& list = found->second;
                    if (cmd == CMD_PROCESS32FIRST) list.next = 0;
                    if (list.next < list.entries.size()) entry = &list.entries[list.next++];
                }
                // Upstream CeProcessEntry: result, pid, name size, name.
                int32_t header[3] = {entry ? 1 : 0, entry ? entry->pid : 0,
                                     entry ? static_cast<int32_t>(std::min<size_t>(entry->name.size(), 4096)) : 0};
                if (!sendAll(fd, header, sizeof header) ||
                    (header[2] && !sendAll(fd, entry->name.data(), static_cast<size_t>(header[2])))) return;
                break;
            }
            case CMD_MODULE32FIRST:
            case CMD_MODULE32NEXT: {
                uint32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                auto found = snapshots.find(static_cast<int32_t>(handle));
                const Snapshot::Entry* entry = nullptr;
                if (found != snapshots.end() && found->second.modules) {
                    auto& list = found->second;
                    if (cmd == CMD_MODULE32FIRST) list.next = 0;
                    if (list.next < list.entries.size()) entry = &list.entries[list.next++];
                }
                if (!(entry ? sendModuleEntry(1, entry->base, entry->size, entry->name)
                            : sendModuleEntry(0, 0, 0, std::string()))) return;
                break;
            }
            case CMD_READPROCESSMEMORY: {
                uint32_t handle = 0, size = 0; uint64_t address = 0; uint8_t compress = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &address, 8) ||
                    !recvAll(fd, &size, 4) || !recvAll(fd, &compress, 1)) return;
                std::vector<uint8_t> buf;
                int32_t got=0;
                auto proc=process(static_cast<int32_t>(handle));
                if (proc && size <= kMaxTransfer) {
                    buf.resize(size);
                    auto r=proc->read(static_cast<uintptr_t>(address),buf.data(),size);
                    got=r ? static_cast<int32_t>(*r) : 0;
                }
                buf.resize(static_cast<size_t>(got));
                if (compress) {
                    // Upstream answers a compressed request with the read size,
                    // the zlib stream size and the stream (deflate level = compress).
                    auto packed=ce::net::compressPayload(buf, std::clamp<int>(compress, 1, 9));
                    uint32_t sizes[2] = {packed ? static_cast<uint32_t>(got) : 0u,
                                         packed ? static_cast<uint32_t>(packed->size()) : 0u};
                    if (!sendAll(fd, sizes, sizeof sizes) || (sizes[1] && !sendAll(fd, packed->data(), sizes[1]))) return;
                    break;
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
            case CMD_VIRTUALQUERYEX:
            case CMD_GETREGIONINFO: {
                int32_t handle=0;uint64_t address=0;
                if (!recvAll(fd,&handle,4) || !recvAll(fd,&address,8)) return;
                auto proc=process(handle);
                uint8_t result=0;
                uint32_t protection=0,type=0;
                uint64_t base=0,size=0;
                // An address between mappings is answered as upstream does: a
                // PAGE_NOACCESS gap of type 0 up to the next mapping.
                for (auto& region : proc ? proc->queryRegions() : std::vector<MemoryRegion>{}) {
                    if (region.base+region.size<=address) continue;
                    result=1;
                    if (address>=region.base) {
                        protection=wireProtection(region.protection);type=wireType(region.type);
                        base=region.base;size=region.size;
                    } else {
                        protection=PAGE_NOACCESS;
                        base=address & ~uint64_t(0xfff);size=region.base-base;
                    }
                    break;
                }
                if (!sendAll(fd,&result,1) || !sendAll(fd,&protection,4) ||
                    !sendAll(fd,&type,4) || !sendAll(fd,&base,8) || !sendAll(fd,&size,8)) return;
                // GETREGIONINFO appends the maps line (string8); none is sent.
                uint8_t lineSize=0;
                if (cmd==CMD_GETREGIONINFO && !sendAll(fd,&lineSize,1)) return;
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
                // Upstream RegionInfo, sent raw: base, size, protection, type.
                for (auto& reg : regions) {
                    uint64_t base = reg.base, size = reg.size;
                    uint32_t protection = wireProtection(reg.protection);
                    uint32_t type = wireType(reg.type);
                    if (!sendAll(fd, &base, 8) || !sendAll(fd, &size, 8) ||
                        !sendAll(fd, &protection, 4) || !sendAll(fd, &type, 4)) return;
                }
                break;
            }
            case CMD_CREATETOOLHELP32SNAPSHOTEX: {
                uint32_t flags = 0, pid = 0;
                if (!recvAll(fd, &flags, 4) || !recvAll(fd, &pid, 4)) return;
                if (flags & TH32CS_SNAPTHREAD) {
                    auto threads = LinuxProcessHandle(static_cast<pid_t>(pid)).threads();
                    int32_t count = static_cast<int32_t>(threads.size());
                    if (!sendAll(fd, &count, 4)) return;
                    for (auto& t : threads) {
                        int32_t tid = t.tid;
                        if (!sendAll(fd, &tid, 4)) return;
                    }
                } else if (flags & TH32CS_SNAPMODULE) {
                    // Streamed CeModuleEntry list, terminated by a result==0 entry.
                    // The name is the full path, as upstream sends it.
                    for (auto& m : LinuxProcessHandle(static_cast<pid_t>(pid)).modules())
                        if (!sendModuleEntry(1, m.base, m.size, m.path.empty() ? m.name : m.path)) return;
                    if (!sendModuleEntry(0, 0, 0, std::string())) return;   // terminator
                } else {
                    // Anything else returns a snapshot handle (0 on failure),
                    // read with PROCESS32FIRST/NEXT.
                    int32_t handle = snapshot(flags, pid);
                    if (!sendAll(fd, &handle, 4)) return;
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
            // Recognized but not provided here: read the whole request and
            // answer with upstream's failure value, so the client keeps its
            // connection and falls back.
            case CMD_SUSPENDTHREAD:
            case CMD_RESUMETHREAD:
            case CMD_GETTHREADCONTEXT: {
                int32_t request[2] = {};   // handle, tid
                int32_t result = 0;
                if (!recvAll(fd, request, sizeof request) || !sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_SETTHREADCONTEXT: {
                uint32_t request[3] = {};   // handle, tid, context size
                uint32_t result = 0;
                if (!recvAll(fd, request, sizeof request) || request[2] > kMaxDiscard ||
                    !discardAll(fd, request[2]) || !sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_SPEEDHACK_SETSPEED:
            case CMD_LOADEXTENSION: {
                uint32_t request[2] = {};   // handle, then the speed (float) for SETSPEED
                uint32_t result = 0;
                if (!recvAll(fd, request, cmd == CMD_LOADEXTENSION ? 4 : 8) || !sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_CREATETHREAD: {
                uint8_t request[20] = {};   // handle, start address, parameter
                int32_t threadHandle = 0;
                if (!recvAll(fd, request, sizeof request) || !sendAll(fd, &threadHandle, 4)) return;
                break;
            }
            case CMD_GETSYMBOLLISTFROMFILE: {
                uint32_t request[2] = {};   // file offset, path size
                uint64_t none = 0;          // upstream's "no symbols" reply
                if (!recvAll(fd, request, sizeof request) || request[1] > kMaxDiscard ||
                    !discardAll(fd, request[1]) || !sendAll(fd, &none, 8)) return;
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
                    // Tracer thread: enqueue only, never block on the socket.
                    // Only stops are forwarded: each one leaves the target
                    // stopped until the client continues it. Thread exits are
                    // reported inside a stop already delivered, and a process
                    // exit has nothing to continue.
                    if (e.type == ce::DebugEventType::ThreadExiting ||
                        e.type == ce::DebugEventType::ProcessExited) return;
                    int32_t ev = (e.type == ce::DebugEventType::BreakpointHit ||
                                  e.type == ce::DebugEventType::ExceptionBreakpointHit) ? 5 : 1;
                    { std::lock_guard<std::mutex> lk(client.dbgMutex);
                      client.dbgQueue.push_back({ev, static_cast<int64_t>(e.tid),
                                           static_cast<uint64_t>(e.address)}); }
                    client.dbgCv.notify_all();
                });
                int32_t result = client.dbg->attach(proc->pid(), client.dbgProc.get()) ? 1 : 0;
                // The seize leaves every thread stopped, and no attach event is
                // queued for the client to continue from: let the target run.
                // Setting a breakpoint must not resume it later (that would
                // release a thread the client is still inspecting at a hit).
                if (result) client.dbg->continueExecution();
                else stopDebug();
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
                    // Wait in short slices and look at the socket between them:
                    // a client that dies during a long wait must not leave its
                    // target traced until the timeout. Returning tears the
                    // session down as any disconnect does.
                    constexpr auto kSlice = std::chrono::milliseconds(100);
                    const auto deadline = std::chrono::steady_clock::now() +
                                          std::chrono::milliseconds(timeoutMs < 0 ? 0 : timeoutMs);
                    auto ready = [this,&client] { return !client.dbgQueue.empty() || !running_.load(); };
                    std::unique_lock<std::mutex> lk(client.dbgMutex);
                    while (client.dbg && handle==debugHandle && !ready()) {
                        const auto now = std::chrono::steady_clock::now();
                        if (now >= deadline) break;
                        client.dbgCv.wait_for(lk, std::min<std::chrono::steady_clock::duration>(deadline - now, kSlice), ready);
                        if (ready()) break;
                        lk.unlock();
                        const bool gone = peerGone(fd);
                        lk.lock();
                        if (gone) return;
                    }
                    have = client.dbg && handle==debugHandle && !client.dbgQueue.empty();
                    if (have) { rec = client.dbgQueue.front(); client.dbgQueue.pop_front(); }
                }
                if (have) deliveredStop = rec.tid;
                int32_t result = have ? 1 : 0;
                if (!sendAll(fd, &result, 4)) return;
                if (have && (!sendAll(fd, &rec.debugevent, 4) || !sendAll(fd, &rec.tid, 8) ||
                             !sendAll(fd, &rec.address, 8))) return;
                break;
            }
            case CMD_CONTINUEFROMDEBUGEVENT: {
                int32_t handle = 0, tid = 0, sig = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &tid, 4) || !recvAll(fd, &sig, 4)) return;
                // Only the delivered, not yet continued stop can be continued:
                // a repeated or stale continue must not resume a newer stop
                // the client has not seen.
                int32_t result=0;
                if (client.dbg && handle==debugHandle && deliveredStop && *deliveredStop==tid) {
                    deliveredStop.reset();
                    client.dbg->continueExecution();
                    result=1;
                }
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            default:
                // Unimplemented commands carry variable-length payloads this
                // server cannot skip safely: drop the connection.
                return;
        }
    }
}

} // namespace ce::os
