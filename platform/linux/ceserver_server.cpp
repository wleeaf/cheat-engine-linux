#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/linux_process.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <vector>

namespace ce::os {
namespace {

// Opcodes must match platform/linux/ceserver_client.cpp (CE's ceserver protocol).
constexpr uint8_t CMD_GETVERSION         = 0;
constexpr uint8_t CMD_OPENPROCESS        = 3;
constexpr uint8_t CMD_CLOSEHANDLE        = 7;
constexpr uint8_t CMD_READPROCESSMEMORY  = 9;
constexpr uint8_t CMD_WRITEPROCESSMEMORY = 10;
constexpr uint8_t CMD_GETARCHITECTURE    = 21;
constexpr uint8_t CMD_VIRTUALQUERYEXFULL = 31;

bool recvAll(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    while (n > 0) {
        ssize_t r = ::recv(fd, p, n, 0);
        if (r <= 0) return false;
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}
bool sendAll(int fd, const void* buf, size_t n) {
    auto* p = static_cast<const uint8_t*>(buf);
    while (n > 0) {
        ssize_t r = ::send(fd, p, n, MSG_NOSIGNAL);
        if (r <= 0) return false;
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}

} // namespace

CeserverServer::~CeserverServer() { stop(); }

uint16_t CeserverServer::start(uint16_t port) {
    listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd_ < 0) return 0;
    int one = 1;
    setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
        ::listen(listenFd_, 4) < 0) {
        ::close(listenFd_); listenFd_ = -1; return 0;
    }
    socklen_t len = sizeof(addr);
    if (getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len) == 0)
        port_ = ntohs(addr.sin_port);

    running_ = true;
    thread_ = std::thread(&CeserverServer::acceptLoop, this);
    return port_;
}

void CeserverServer::stop() {
    if (!running_.exchange(false)) return;
    if (listenFd_ >= 0) { ::shutdown(listenFd_, SHUT_RDWR); ::close(listenFd_); listenFd_ = -1; }
    if (thread_.joinable()) thread_.join();
}

void CeserverServer::acceptLoop() {
    while (running_.load()) {
        int fd = ::accept(listenFd_, nullptr, nullptr);
        if (fd < 0) break;
        serveClient(fd);   // one client at a time (minimal)
        ::close(fd);
    }
}

void CeserverServer::serveClient(int fd) {
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
                int32_t handle = pid;   // handle == pid
                if (!sendAll(fd, &handle, 4)) return;
                break;
            }
            case CMD_CLOSEHANDLE: {
                int32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                int32_t result = 1;
                if (!sendAll(fd, &result, 4)) return;
                break;
            }
            case CMD_READPROCESSMEMORY: {
                uint32_t handle = 0, size = 0; uint64_t address = 0; uint8_t compress = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &address, 8) ||
                    !recvAll(fd, &size, 4) || !recvAll(fd, &compress, 1)) return;
                std::vector<uint8_t> buf(size);
                LinuxProcessHandle proc(static_cast<pid_t>(handle));
                auto r = proc.read(static_cast<uintptr_t>(address), buf.data(), size);
                int32_t got = (r && *r > 0) ? static_cast<int32_t>(*r) : 0;
                if (!sendAll(fd, &got, 4)) return;
                if (got > 0 && !sendAll(fd, buf.data(), static_cast<size_t>(got))) return;
                break;
            }
            case CMD_WRITEPROCESSMEMORY: {
                int32_t handle = 0, size = 0; int64_t address = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &address, 8) ||
                    !recvAll(fd, &size, 4)) return;
                std::vector<uint8_t> buf(size > 0 ? static_cast<size_t>(size) : 0);
                if (size > 0 && !recvAll(fd, buf.data(), static_cast<size_t>(size))) return;
                LinuxProcessHandle proc(static_cast<pid_t>(handle));
                auto r = proc.write(static_cast<uintptr_t>(address), buf.data(),
                                    static_cast<size_t>(size));
                int32_t written = (r && *r > 0) ? static_cast<int32_t>(*r) : 0;
                if (!sendAll(fd, &written, 4)) return;
                break;
            }
            case CMD_GETARCHITECTURE: {
                int32_t handle = 0;
                if (!recvAll(fd, &handle, 4)) return;
                uint8_t arch = 1;   // CeArchitecture::X86_64 (cecore is x86-64)
                if (!sendAll(fd, &arch, 1)) return;
                break;
            }
            case CMD_VIRTUALQUERYEXFULL: {
                int32_t handle = 0; uint8_t flags = 0;
                if (!recvAll(fd, &handle, 4) || !recvAll(fd, &flags, 1)) return;
                LinuxProcessHandle proc(static_cast<pid_t>(handle));
                auto regions = proc.queryRegions();
                int32_t count = static_cast<int32_t>(regions.size());
                if (!sendAll(fd, &count, 4)) return;
                for (auto& reg : regions) {
                    uint32_t protection = static_cast<uint32_t>(reg.protection);
                    uint32_t type = static_cast<uint32_t>(reg.type);
                    uint64_t base = reg.base, size = reg.size;
                    if (!sendAll(fd, &protection, 4) || !sendAll(fd, &type, 4) ||
                        !sendAll(fd, &base, 8) || !sendAll(fd, &size, 8)) return;
                }
                break;
            }
            default:
                return;   // unsupported command -> drop the connection
        }
    }
}

} // namespace ce::os
