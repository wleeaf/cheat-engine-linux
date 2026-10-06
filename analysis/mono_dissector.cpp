#include "analysis/mono_dissector.hpp"
#include "platform/linux/injector.hpp"
#include "core/log.hpp"
#include "core/ns_attach.hpp"
#include "platform/linux/target_syscall.hpp"
#include "plugins/mono_protocol.h"
#include <arpa/inet.h>
#include <cerrno>
#include <climits>
#include <charconv>
#include <cstring>
#include <dlfcn.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <limits>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <unistd.h>

namespace ce {

size_t MonoDissection::classCount() const {
    size_t n = 0;
    for (const auto& img : images) n += img.classes.size();
    return n;
}

const MonoClassInfo* MonoDissection::findClass(const std::string& fullOrName) const {
    for (const auto& img : images)
        for (const auto& c : img.classes)
            if (c.fullName() == fullOrName || c.name == fullOrName)
                return &c;
    return nullptr;
}

MonoDissection parseMonoDump(const std::string& text) {
    MonoDissection out;
    std::istringstream in(text);
    std::string line;
    MonoImageInfo* curImage = nullptr;
    MonoClassInfo* curClass = nullptr;

    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (line[0] == '#') {
            // Status lines: "# ready …", "# done", "# error: …".
            if (line.rfind("# done", 0) == 0) out.ready = true;
            else if (line.rfind("# error:", 0) == 0)
                out.error = line.substr(std::string("# error:").size() + (line.size() > 8 && line[8] == ' ' ? 1 : 0));
            continue;
        }
        if (line.rfind("IMG ", 0) == 0) {
            out.images.push_back({line.substr(4), {}});
            curImage = &out.images.back();
            curClass = nullptr;
        } else if (line.rfind("CLS ", 0) == 0) {
            if (!curImage) continue;
            // "CLS <Namespace>.<Name>" — the agent always writes a leading dot when
            // the namespace is empty (".<Module>"), so split on the FIRST dot only
            // if a namespace is present.
            std::string full = line.substr(4);
            MonoClassInfo c;
            if (!full.empty() && full[0] == '.') {
                c.name = full.substr(1);            // empty namespace
            } else {
                auto dot = full.rfind('.');
                if (dot == std::string::npos) { c.name = full; }
                else { c.namespaceName = full.substr(0, dot); c.name = full.substr(dot + 1); }
            }
            curImage->classes.push_back(std::move(c));
            curClass = &curImage->classes.back();
        } else if (line.rfind("FLD ", 0) == 0) {
            if (!curClass) continue;
            // "FLD 0x<off> <S|-> <type-name> <field-name>"
            std::istringstream fs(line.substr(4));
            std::string offTok, staticTok, typeName, fieldName;
            fs >> offTok >> staticTok >> typeName;
            std::getline(fs, fieldName);           // remainder (field name; no spaces in practice)
            // trim leading space from getline remainder
            size_t s = fieldName.find_first_not_of(' ');
            fieldName = (s == std::string::npos) ? std::string() : fieldName.substr(s);
            MonoField f;
            f.offset = static_cast<uint32_t>(std::strtoul(offTok.c_str(), nullptr, 0));
            f.isStatic = (staticTok == "S");
            f.typeName = typeName;
            f.name = fieldName;
            curClass->fields.push_back(std::move(f));
        }
    }
    return out;
}

ManagedKind detectManagedKind(ProcessHandle& proc) {
    // Mono ships libmono*/mono-2.0; IL2CPP builds put the AOT code in
    // GameAssembly.so (Unity/Linux) and carry global-metadata.dat + il2cpp_* code.
    bool mono = false, il2cpp = false;
    for (const auto& m : proc.modules()) {
        std::string n = m.name;
        for (auto& ch : n) ch = static_cast<char>(std::tolower((unsigned char)ch));
        // Any "mono" module: libmono-2.0 / libmonosgen / libmonobdwgc /
        // libmono-native, or a statically-linked mono-sgen/mono executable.
        if (n.find("mono") != std::string::npos) mono = true;
        if (n.find("gameassembly") != std::string::npos || n.find("il2cpp") != std::string::npos)
            il2cpp = true;
    }
    if (mono) return ManagedKind::Mono;
    if (il2cpp) return ManagedKind::Il2Cpp;
    return ManagedKind::None;
}

std::string findMonoAgentPath() {
    namespace fs = std::filesystem;
    const char* kName = "libcecore_mono_agent.so";

    // Directory of the running executable (works for the build tree and installs).
    fs::path exeDir;
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) { buf[n] = '\0'; exeDir = fs::path(buf).parent_path(); }

    std::vector<fs::path> candidates;
    // Embedders and distro packages can load cecore from lib64, a multiarch
    // directory or a custom library directory. Follow the actual engine first.
    Dl_info library{};
    if (dladdr(reinterpret_cast<void*>(&findMonoAgentPath),&library) && library.dli_fname)
        candidates.push_back(fs::path(library.dli_fname).parent_path() / kName);
    if (!exeDir.empty()) {
        candidates.push_back(exeDir / kName);                       // build tree (build/)
        candidates.push_back(exeDir / ".." / "lib" / kName);        // <prefix>/bin + <prefix>/lib
        candidates.push_back(exeDir / ".." / "lib64" / kName);
        candidates.push_back(exeDir / ".." / "lib" / "x86_64-linux-gnu" / kName);
    }
    candidates.push_back(fs::path("/usr/lib/x86_64-linux-gnu") / kName);
    candidates.push_back(fs::path("/usr/lib") / kName);
    candidates.push_back(fs::path("/usr/lib64") / kName);
    candidates.push_back(fs::path("/lib/x86_64-linux-gnu") / kName);

    std::error_code ec;
    for (const auto& c : candidates) {
        if (!fs::is_regular_file(c, ec)) continue;
        auto resolved=fs::weakly_canonical(c, ec);
        if (!ec) return resolved.string();
    }
    return {};
}

namespace {
using Deadline=std::chrono::steady_clock::time_point;
struct AgentSocket {
    int fd=-1;
    ~AgentSocket() { if (fd>=0) close(fd); }
};
bool readySocket(int fd,short event,Deadline deadline) {
    for (;;) {
        auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        if (left<=0) { errno=ETIMEDOUT;return false; }
        pollfd poller{fd,event,0};
        int result=poll(&poller,1,static_cast<int>(std::min<int64_t>(left,INT_MAX)));
        if (result<0 && errno==EINTR) continue;
        if (!result) errno=ETIMEDOUT;
        return result>0;
    }
}
bool transfer(int fd,void* data,size_t size,bool sending,Deadline deadline) {
    size_t done=0;
    while (done<size) {
        if (!readySocket(fd,sending ? POLLOUT : POLLIN,deadline)) return false;
        ssize_t count=sending ? send(fd,static_cast<char*>(data)+done,size-done,MSG_NOSIGNAL) :
            recv(fd,static_cast<char*>(data)+done,size-done,0);
        if (count<0 && (errno==EINTR || errno==EAGAIN)) continue;
        if (count<=0) { if (!count) errno=ECONNRESET;return false; }
        done+=static_cast<size_t>(count);
    }
    return true;
}
bool connectAgent(AgentSocket& socket,const std::string& path,pid_t pid,Deadline deadline) {
    if (socket.fd>=0) { close(socket.fd);socket.fd=-1; }
    sockaddr_un address{};address.sun_family=AF_UNIX;
    if (path.size()>=sizeof(address.sun_path)) { errno=ENAMETOOLONG;return false; }
    std::memcpy(address.sun_path,path.c_str(),path.size()+1);
    socket.fd=::socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (socket.fd<0) return false;
    if (connect(socket.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))<0) {
        if (errno!=EINPROGRESS && errno!=EAGAIN && errno!=EINTR) return false;
        if (!readySocket(socket.fd,POLLOUT,deadline)) return false;
        int error=0;socklen_t size=sizeof(error);
        if (getsockopt(socket.fd,SOL_SOCKET,SO_ERROR,&error,&size)<0) return false;
        if (error) { errno=error;return false; }
    }
    ucred peer{};socklen_t size=sizeof(peer);
    if (getsockopt(socket.fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)<0) return false;
    if (peer.pid!=pid) { errno=ESTALE;return false; }
    return true;
}
// Resolve a host agent exposed through a bind mount without changing namespaces.
// Mount metadata is only a candidate generator; device/inode identity is proof.
std::string targetAgentPath(pid_t task,const std::string& path) {
    struct stat source{};
    if (stat(path.c_str(),&source)<0 || !S_ISREG(source.st_mode)) return path;
    const std::string root="/proc/"+std::to_string(task)+"/root";
    auto matches=[&](const std::string& candidate) {
        struct stat target{};
        return stat((root+candidate).c_str(),&target)==0 && target.st_dev==source.st_dev && target.st_ino==source.st_ino;
    };
    if (path.empty() || path[0]!='/' || matches(path)) return path;
    const auto decode=[](std::string text) {
        std::string result;
        for (size_t i=0;i<text.size();++i) {
            if (text[i]=='\\' && i+3<text.size() && text[i+1]>='0' && text[i+1]<='7' &&
                text[i+2]>='0' && text[i+2]<='7' && text[i+3]>='0' && text[i+3]<='7') {
                result+=char((text[i+1]-'0')*64+(text[i+2]-'0')*8+text[i+3]-'0');i+=3;
            } else result+=text[i];
        }
        return result;
    };
    std::ifstream mounts("/proc/"+std::to_string(task)+"/mountinfo");std::string line;
    while (std::getline(mounts,line)) {
        std::istringstream fields(line);std::string id,parent,device,mountRoot,mountPoint;
        if (!(fields>>id>>parent>>device>>mountRoot>>mountPoint)) continue;
        mountRoot=decode(mountRoot);mountPoint=decode(mountPoint);
        if (mountRoot=="/") continue;
        if (path.size()<=mountRoot.size() || path.compare(0,mountRoot.size(),mountRoot)!=0 || path[mountRoot.size()]!='/') continue;
        std::string candidate=(mountPoint=="/" ? std::string{} : mountPoint)+path.substr(mountRoot.size());
        if (matches(candidate)) return candidate;
    }
    return path;
}
std::expected<std::string,std::string> requestMono(ProcessHandle& proc,SymbolResolver& resolver,
    const std::string& agentPath,unsigned command,const std::string& ns,const std::string& cls,
    const std::string& method,int count,int timeoutMs) {
    if (timeoutMs<=0) return std::unexpected("Mono request timeout must be positive");
    auto target=proc.targetDescription();
    if (target.transport!=TargetTransport::Local)
        return std::unexpected("Mono agent requires a local target filesystem and process");
    if (!target.live) return std::unexpected("Mono target process has exited");
    uint64_t length=uint64_t(ns.size())+cls.size()+method.size();
    if (length>CE_MONO_MAX_REQUEST || ns.find('\0')!=std::string::npos || cls.find('\0')!=std::string::npos ||
        method.find('\0')!=std::string::npos || count < -1)
        return std::unexpected("Invalid or oversized Mono method request");
    auto task=os::processMemoryTask(proc.pid());
    if (!task) return std::unexpected("Mono target has no live task: "+task.error().message());
    auto inner=nsInnerPid(proc.pid());
    std::string path="/proc/"+std::to_string(*task)+"/root/tmp/cecore_mono_"+std::to_string(inner)+"/agent.sock";
    auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeoutMs);
    AgentSocket socket;
    if (!connectAgent(socket,path,proc.pid(),deadline)) {
        if (errno!=ENOENT && errno!=ECONNREFUSED)
            return std::unexpected("Mono agent connection: "+std::string(std::strerror(errno)));
        auto injected=os::injectLibrary(proc,resolver,targetAgentPath(*task,agentPath));
        if (!injected) return std::unexpected("Mono agent injection: "+injected.error());
        while (!connectAgent(socket,path,proc.pid(),deadline)) {
            if (errno!=ENOENT && errno!=ECONNREFUSED)
                return std::unexpected("Mono agent connection: "+std::string(std::strerror(errno)));
            if (std::chrono::steady_clock::now()>=deadline)
                return std::unexpected("Mono agent connection timed out");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    // A reachable socket and matching numeric PID do not prove that this is
    // still the process owned by the caller's handle. Check before dispatch.
    if (!proc.targetDescription().live) return std::unexpected("Mono target exited before the request");
    uint32_t header[]={htonl(CE_MONO_MAGIC),htonl(command),htonl(static_cast<uint32_t>(ns.size())),
        htonl(static_cast<uint32_t>(cls.size())),htonl(static_cast<uint32_t>(method.size())),
        htonl(static_cast<uint32_t>(count))};
    if (!transfer(socket.fd,header,sizeof(header),true,deadline))
        return std::unexpected("Mono agent request: "+std::string(std::strerror(errno)));
    for (const auto* part : {&ns,&cls,&method})
        if (!transfer(socket.fd,const_cast<char*>(part->data()),part->size(),true,deadline))
            return std::unexpected("Mono agent request: "+std::string(std::strerror(errno)));
    uint32_t response[3];
    if (!transfer(socket.fd,response,sizeof(response),false,deadline))
        return std::unexpected("Mono agent response: "+std::string(std::strerror(errno)));
    for (auto& word : response) word=ntohl(word);
    if (response[0]!=CE_MONO_MAGIC || response[1]>CE_MONO_ERROR || response[2]>CE_MONO_MAX_RESPONSE)
        return std::unexpected("Invalid Mono agent response header");
    std::string payload(response[2],'\0');
    if (!transfer(socket.fd,payload.data(),payload.size(),false,deadline))
        return std::unexpected("Mono agent response: "+std::string(std::strerror(errno)));
    if (response[1]!=CE_MONO_OK) return std::unexpected("Mono runtime: "+payload);
    if (!proc.targetDescription().live) return std::unexpected("Mono target exited during the request");
    return payload;
}
} // namespace

std::optional<MonoDissection> dissectMono(ProcessHandle& proc, SymbolResolver& resolver,
                                          const std::string& agentSoPath, int timeoutMs) {
    auto response=requestMono(proc,resolver,agentSoPath,CE_MONO_DUMP,{},{},{},-1,timeoutMs);
    if (!response) {
        MonoDissection result;result.error=response.error();return result;
    }
    return parseMonoDump(*response);
}

uintptr_t findMonoFunction(ProcessHandle& proc, SymbolResolver& resolver,
                           const std::string& agentSoPath, const std::string& ns,
                           const std::string& className, const std::string& methodName,
                           int paramCount, int timeoutMs) {
    auto response=requestMono(proc,resolver,agentSoPath,CE_MONO_METHOD,ns,className,methodName,paramCount,timeoutMs);
    if (!response) {
        ce::log::warn(ce::log::Cat::General,"Mono method lookup: {}",response.error());return 0;
    }
    std::string_view hex=*response;
    if (!hex.empty() && hex.back()=='\n') hex.remove_suffix(1);
    uintptr_t address=0;
    auto parsed=std::from_chars(hex.data(),hex.data()+hex.size(),address,16);
    if (parsed.ec!=std::errc{} || parsed.ptr!=hex.data()+hex.size()) return 0;
    return address;
}

} // namespace ce
