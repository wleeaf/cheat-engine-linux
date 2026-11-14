#include "platform/linux/wine_memory.hpp"
#include "platform/linux/target_syscall.hpp"
#include "core/log.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <map>
#include <mutex>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ce::os {
namespace {

// The helper runs at the PE's preferred base with no relocations: .text at
// 0x401000, its parameters and result at 0x402000, the import table at
// 0x403000 with the address table at 0x403140 (GetStdHandle, WriteFile,
// ExitProcess, OpenProcess, VirtualAllocEx, VirtualFreeEx, GetLastError).
// The assembler reads bare numbers as hexadecimal.
constexpr char kHelperSource[] =
    "sub rsp,0x58\n"
    "mov ecx,0x1fffff\n"
    "xor edx,edx\n"
    "mov r8,qword [0x402008]\n"
    "call qword [0x403158]\n"
    "test rax,rax\n"
    "jz failed\n"
    "mov qword [0x402058],rax\n"
    "cmp qword [0x402000],2\n"
    "je release\n"
    "mov rbx,qword [0x402010]\n"
    "test rbx,rbx\n"
    "jnz search\n"
    "xor edx,edx\n"
    "call attempt\n"
    "test rax,rax\n"
    "jnz allocated\n"
    "jmp failed\n"
    "search:\n"
    "xor esi,esi\n"
    "search_loop:\n"
    "mov rdx,rbx\n"
    "add rdx,rsi\n"
    "jc backward\n"
    "cmp rdx,qword [0x402020]\n"
    "ja backward\n"
    "cmp rdx,qword [0x402018]\n"
    "jb backward\n"
    "call attempt\n"
    "test rax,rax\n"
    "jnz allocated\n"
    "backward:\n"
    "test rsi,rsi\n"
    "jz advance\n"
    "mov rdx,rbx\n"
    "sub rdx,rsi\n"
    "jb advance\n"
    "cmp rdx,qword [0x402018]\n"
    "jb advance\n"
    "cmp rdx,qword [0x402020]\n"
    "ja advance\n"
    "call attempt\n"
    "test rax,rax\n"
    "jnz allocated\n"
    "advance:\n"
    "add rsi,0x10000\n"
    "mov rax,rbx\n"
    "add rax,rsi\n"
    "jc check_low\n"
    "cmp rax,qword [0x402020]\n"
    "jbe search_loop\n"
    "check_low:\n"
    "cmp rsi,rbx\n"
    "ja failed\n"
    "mov rax,rbx\n"
    "sub rax,rsi\n"
    "cmp rax,qword [0x402018]\n"
    "jae search_loop\n"
    "jmp failed\n"
    "allocated:\n"
    "mov qword [0x402048],rax\n"
    "mov dword [0x402054],1\n"
    "jmp report\n"
    "release:\n"
    "mov rcx,qword [0x402058]\n"
    "mov rdx,qword [0x402038]\n"
    "xor r8d,r8d\n"
    "mov r9d,0x8000\n"
    "call qword [0x403168]\n"
    "test eax,eax\n"
    "jz failed\n"
    "mov dword [0x402054],1\n"
    "jmp report\n"
    "failed:\n"
    "call qword [0x403170]\n"
    "mov dword [0x402050],eax\n"
    "report:\n"
    "mov ecx,0xfffffff5\n"
    "call qword [0x403140]\n"
    "mov rcx,rax\n"
    "mov edx,0x402040\n"
    "mov r8d,0x18\n"
    "mov r9d,0x402060\n"
    "mov qword [rsp+0x20],0\n"
    "call qword [0x403148]\n"
    "xor ecx,ecx\n"
    "call qword [0x403150]\n"
    "int3\n"
    "attempt:\n"
    "sub rsp,0x38\n"
    "mov rcx,qword [0x402058]\n"
    "mov r8,qword [0x402028]\n"
    "mov r9d,0x3000\n"
    "mov rax,qword [0x402030]\n"
    "mov qword [rsp+0x20],rax\n"
    "call qword [0x403160]\n"
    "add rsp,0x38\n"
    "ret\n";

constexpr uint8_t kHelperCode[] = {
    0x48,0x83,0xec,0x58,0xb9,0xff,0xff,0x1f,0x00,0x31,0xd2,0x4c,0x8b,0x05,0xf6,0x0f,
    0x00,0x00,0xff,0x15,0x40,0x21,0x00,0x00,0x48,0x85,0xc0,0x0f,0x84,0xf9,0x00,0x00,
    0x00,0x48,0xa3,0x58,0x20,0x40,0x00,0x00,0x00,0x00,0x00,0x48,0x83,0x3d,0xcd,0x0f,
    0x00,0x00,0x02,0x0f,0x84,0xb4,0x00,0x00,0x00,0x48,0x8b,0x1d,0xd0,0x0f,0x00,0x00,
    0x48,0x85,0xdb,0x75,0x15,0x31,0xd2,0xe8,0x14,0x01,0x00,0x00,0x48,0x85,0xc0,0x0f,
    0x85,0x82,0x00,0x00,0x00,0xe9,0xc0,0x00,0x00,0x00,0x31,0xf6,0x48,0x89,0xda,0x48,
    0x01,0xf2,0x72,0x1c,0x48,0x3b,0x15,0xb5,0x0f,0x00,0x00,0x77,0x13,0x48,0x3b,0x15,
    0xa4,0x0f,0x00,0x00,0x72,0x0a,0xe8,0xe5,0x00,0x00,0x00,0x48,0x85,0xc0,0x75,0x57,
    0x48,0x85,0xf6,0x74,0x24,0x48,0x89,0xda,0x48,0x29,0xf2,0x72,0x1c,0x48,0x3b,0x15,
    0x84,0x0f,0x00,0x00,0x72,0x13,0x48,0x3b,0x15,0x83,0x0f,0x00,0x00,0x77,0x0a,0xe8,
    0xbc,0x00,0x00,0x00,0x48,0x85,0xc0,0x75,0x2e,0x48,0x81,0xc6,0x00,0x00,0x01,0x00,
    0x48,0x89,0xd8,0x48,0x01,0xf0,0x72,0x09,0x48,0x3b,0x05,0x61,0x0f,0x00,0x00,0x76,
    0x9b,0x48,0x39,0xde,0x77,0x54,0x48,0x89,0xd8,0x48,0x29,0xf0,0x48,0x3b,0x05,0x45,
    0x0f,0x00,0x00,0x73,0x87,0xeb,0x43,0x48,0xa3,0x48,0x20,0x40,0x00,0x00,0x00,0x00,
    0x00,0xc7,0x05,0x69,0x0f,0x00,0x00,0x01,0x00,0x00,0x00,0xeb,0x3c,0x48,0x8b,0x0d,
    0x64,0x0f,0x00,0x00,0x48,0x8b,0x15,0x3d,0x0f,0x00,0x00,0x45,0x31,0xc0,0x41,0xb9,
    0x00,0x80,0x00,0x00,0xff,0x15,0x5e,0x20,0x00,0x00,0x85,0xc0,0x74,0x0c,0xc7,0x05,
    0x3c,0x0f,0x00,0x00,0x01,0x00,0x00,0x00,0xeb,0x0f,0xff,0x15,0x50,0x20,0x00,0x00,
    0xa3,0x50,0x20,0x40,0x00,0x00,0x00,0x00,0x00,0xb9,0xf5,0xff,0xff,0xff,0xff,0x15,
    0x0c,0x20,0x00,0x00,0x48,0x89,0xc1,0xba,0x40,0x20,0x40,0x00,0x41,0xb8,0x18,0x00,
    0x00,0x00,0x41,0xb9,0x60,0x20,0x40,0x00,0x48,0xc7,0x44,0x24,0x20,0x00,0x00,0x00,
    0x00,0xff,0x15,0xf1,0x1f,0x00,0x00,0x31,0xc9,0xff,0x15,0xf1,0x1f,0x00,0x00,0xcc,
    0x48,0x83,0xec,0x38,0x48,0x8b,0x0d,0xed,0x0e,0x00,0x00,0x4c,0x8b,0x05,0xb6,0x0e,
    0x00,0x00,0x41,0xb9,0x00,0x30,0x00,0x00,0x48,0xa1,0x30,0x20,0x40,0x00,0x00,0x00,
    0x00,0x00,0x48,0x89,0x44,0x24,0x20,0xff,0x15,0xd3,0x1f,0x00,0x00,0x48,0x83,0xc4,
    0x38,0xc3,
};

constexpr uint64_t kImageBase = 0x400000;
constexpr char kResultMagic[8] = {'C', 'E', 'W', 'I', 'N', 'E', 'A', 'L'};

template<typename T>
void put(std::vector<uint8_t>& bytes, size_t at, T value) {
    std::memcpy(bytes.data() + at, &value, sizeof(value));
}

std::error_code error(std::errc code) { return std::make_error_code(code); }

// Windows error codes the helper reports, mapped to the closest errno.
std::error_code windowsError(uint32_t code) {
    switch (code) {
    case 5: return error(std::errc::permission_denied);          // ERROR_ACCESS_DENIED
    case 8: case 487: return error(std::errc::not_enough_memory); // NOT_ENOUGH_MEMORY, INVALID_ADDRESS
    case 87: return error(std::errc::invalid_argument);            // ERROR_INVALID_PARAMETER
    default: return error(std::errc::io_error);
    }
}

uint32_t windowsProtection(MemProt protection) {
    const bool read = protection & MemProt::Read, write = protection & MemProt::Write, exec = protection & MemProt::Exec;
    if (exec) return write ? 0x40 : read ? 0x20 : 0x10;   // EXECUTE_READWRITE, EXECUTE_READ, EXECUTE
    if (write) return 0x04;                                // READWRITE
    return read ? 0x02 : 0x01;                             // READONLY, NOACCESS
}

struct Launch {
    std::string loader;
    std::vector<std::string> environment;
    std::optional<std::pair<uid_t, gid_t>> switchTo;   // when running as root for another user
};

std::optional<std::pair<uid_t, gid_t>> processOwner(pid_t pid) {
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    std::optional<uid_t> uid;
    std::optional<gid_t> gid;
    while (std::getline(status, line)) {
        unsigned long value = 0;
        if (line.rfind("Uid:", 0) == 0 && std::sscanf(line.c_str() + 4, "%lu", &value) == 1) uid = static_cast<uid_t>(value);
        if (line.rfind("Gid:", 0) == 0 && std::sscanf(line.c_str() + 4, "%lu", &value) == 1) gid = static_cast<gid_t>(value);
    }
    if (!uid || !gid) return std::nullopt;
    return std::pair{*uid, *gid};
}

// How to start the helper the way the target was started: its Wine loader,
// its environment (prefix, home, server directory) and its user.
std::expected<Launch, std::error_code> launchFor(pid_t pid) {
    const std::string proc = "/proc/" + std::to_string(pid);
    struct stat ours{}, theirs{};
    if (::stat("/proc/self/ns/mnt", &ours) || ::stat((proc + "/ns/mnt").c_str(), &theirs))
        return std::unexpected(error(std::errc::not_supported));
    // A Proton or Flatpak container sees other files at the same paths.
    if (ours.st_ino != theirs.st_ino || ours.st_dev != theirs.st_dev)
        return std::unexpected(error(std::errc::not_supported));

    Launch launch;
    auto owner = processOwner(pid);
    if (!owner) return std::unexpected(error(std::errc::no_such_process));
    if (owner->first != ::getuid()) {
        // Running another user's Wine as ourselves would use our prefix and
        // server, not the target's.
        if (::geteuid() != 0) return std::unexpected(error(std::errc::not_supported));
        launch.switchTo = owner;
    }

    std::error_code ec;
    const std::filesystem::path exe = std::filesystem::read_symlink(proc + "/exe", ec);
    if (ec) return std::unexpected(ec);
    // wine-preloader and wine64-preloader map the program; the loader beside
    // them (wine, wine64) starts a new one.
    std::string name = exe.filename().string();
    if (const std::string suffix = "-preloader"; name.size() > suffix.size() && name.ends_with(suffix))
        name.resize(name.size() - suffix.size());
    const auto loader = exe.parent_path() / name;
    if (::access(loader.c_str(), X_OK)) return std::unexpected(error(std::errc::not_supported));
    launch.loader = loader.string();

    std::ifstream environ(proc + "/environ", std::ios::binary);
    if (!environ) return std::unexpected(error(std::errc::permission_denied));
    std::string entry;
    while (std::getline(environ, entry, '\0')) {
        // Per-process Wine internals (an inherited server socket descriptor,
        // the preloader's reservation) and preloaded overlays stay behind.
        static constexpr std::string_view dropped[] = {"WINESERVERSOCKET=", "WINELOADERNOEXEC=", "WINEPRELOADRESERVE=",
                                                       "WINEDEBUG=", "LD_PRELOAD="};
        if (std::any_of(std::begin(dropped), std::end(dropped), [&](std::string_view key) { return entry.starts_with(key); }))
            continue;
        if (!entry.empty()) launch.environment.push_back(entry);
    }
    launch.environment.push_back("WINEDEBUG=-all");
    return launch;
}

// Wine carries out VirtualAllocEx/VirtualFreeEx on a thread of the target
// itself. When every thread is stopped (a SIGSTOP, or an all-stop debugger
// session) nothing can, and the helper would wait for its whole timeout.
bool everyThreadStopped(pid_t pid) {
    std::error_code ec;
    bool any = false;
    for (const auto& task : std::filesystem::directory_iterator("/proc/" + std::to_string(pid) + "/task", ec)) {
        std::ifstream stat(task.path() / "stat");
        std::string text;
        std::getline(stat, text);
        const auto close = text.rfind(')');
        if (close == std::string::npos || close + 2 >= text.size()) continue;
        any = true;
        const char state = text[close + 2];
        if (state != 'T' && state != 't') return false;
    }
    return any;
}

// The Windows process id, found once per process (the TEB search reads every
// page of the small private regions).
std::expected<uint32_t, std::error_code> cachedWindowsProcessId(pid_t pid) {
    static std::mutex mutex;
    static std::map<std::pair<pid_t, uint64_t>, uint32_t> ids;
    auto identity = targetProcessIdentity(pid);
    if (!identity) return std::unexpected(identity.error());
    const std::pair key{pid, identity->startTime};
    {
        std::lock_guard lock(mutex);
        if (auto found = ids.find(key); found != ids.end()) return found->second;
    }
    auto id = wineWindowsProcessId(pid);
    if (!id) return id;
    std::lock_guard lock(mutex);
    std::erase_if(ids, [&](const auto& entry) { return entry.first.first == pid; });
    ids[key] = *id;
    return id;
}

// Starts the helper image and returns its 24-byte result.
std::expected<std::array<uint8_t, 24>, std::error_code> runHelper(pid_t pid, const std::vector<uint8_t>& image) {
    auto launch = launchFor(pid);
    if (!launch) return std::unexpected(launch.error());
    if (everyThreadStopped(pid)) return std::unexpected(error(std::errc::resource_unavailable_try_again));

    // Readable by the target's user when the helper runs as that user.
    std::string directory = "/tmp";
    if (!launch->switchTo)
        if (const char* runtime = std::getenv("XDG_RUNTIME_DIR"); runtime && *runtime == '/') directory = runtime;
    std::string path = directory + "/ce-wine-memory-XXXXXX.exe";
    const int file = ::mkstemps(path.data(), 4);
    if (file < 0) return std::unexpected(std::error_code(errno, std::generic_category()));
    struct Remove { const std::string& path; ~Remove() { ::unlink(path.c_str()); } } remove{path};
    const bool written = ::fchmod(file, 0644) == 0 &&
        ::write(file, image.data(), image.size()) == static_cast<ssize_t>(image.size());
    ::close(file);
    if (!written) return std::unexpected(error(std::errc::io_error));

    // Everything the child needs is built before fork: after it, only
    // async-signal-safe calls.
    std::vector<char*> argv{launch->loader.data(), path.data(), nullptr};
    std::vector<char*> envp;
    for (auto& variable : launch->environment) envp.push_back(variable.data());
    envp.push_back(nullptr);
    int output[2];
    if (::pipe2(output, O_CLOEXEC)) return std::unexpected(std::error_code(errno, std::generic_category()));
    const int null = ::open("/dev/null", O_RDWR | O_CLOEXEC);
    const pid_t child = ::fork();
    if (child == 0) {
        if (null >= 0) { ::dup2(null, STDIN_FILENO); ::dup2(null, STDERR_FILENO); }
        ::dup2(output[1], STDOUT_FILENO);
        if (launch->switchTo &&
            (::setgroups(0, nullptr) || ::setgid(launch->switchTo->second) || ::setuid(launch->switchTo->first)))
            ::_exit(126);
        ::execve(argv[0], argv.data(), envp.data());
        ::_exit(127);
    }
    if (null >= 0) ::close(null);
    ::close(output[1]);
    if (child < 0) { ::close(output[0]); return std::unexpected(std::error_code(errno, std::generic_category())); }

    // Starting Wine in a prefix whose server already runs takes well under a
    // second; a near search can take a few seconds more. A target thread
    // stopped while it holds the request delays it without limit.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    std::string bytes;
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) break;
        pollfd ready{output[0], POLLIN, 0};
        const int polled = ::poll(&ready, 1, static_cast<int>(std::min<long long>(left, 1000)));
        if (polled < 0 && errno != EINTR) break;
        if (polled <= 0) continue;
        char chunk[256];
        const ssize_t n = ::read(output[0], chunk, sizeof(chunk));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        bytes.append(chunk, static_cast<size_t>(n));
    }
    ::close(output[0]);
    int status = 0;
    if (::waitpid(child, &status, WNOHANG) == 0) {
        ::kill(child, SIGKILL);
        ::waitpid(child, &status, 0);
    }
    const auto magic = bytes.find(std::string_view(kResultMagic, sizeof(kResultMagic)));
    if (magic == std::string::npos || bytes.size() - magic < 24) {
        ce::log::warn(ce::log::Cat::Memory, "Wine memory helper for pid {} gave no result (status {:#x})", pid, status);
        return std::unexpected(error(std::errc::io_error));
    }
    std::array<uint8_t, 24> result{};
    std::memcpy(result.data(), bytes.data() + magic, result.size());
    return result;
}

} // namespace

std::span<const uint8_t> wineHelperCode() { return kHelperCode; }
std::string_view wineHelperSource() { return {kHelperSource, sizeof(kHelperSource) - 1}; }

std::vector<uint8_t> wineHelperImage(const WineHelperRequest& request) {
    // Headers 0x400, .text 0x1000 at RVA 0x1000, .data 0x200 at RVA 0x2000,
    // .idata 0x200 at RVA 0x3000: the layout of test/wine_fixture.py's PE32+.
    std::vector<uint8_t> image(0x400 + 0x1000 + 0x200 + 0x200);
    image[0] = 'M'; image[1] = 'Z';
    put<uint32_t>(image, 0x3c, 0x80);
    std::memcpy(image.data() + 0x80, "PE\0\0", 4);
    constexpr size_t optional = 0x98, optionalSize = 0xf0;
    put<uint16_t>(image, 0x84, 0x8664);                 // x86-64
    put<uint16_t>(image, 0x86, 3);                      // sections
    put<uint16_t>(image, 0x94, optionalSize);
    put<uint16_t>(image, 0x96, 0x23);                   // relocations stripped, executable, large addresses
    put<uint16_t>(image, optional, 0x20b);              // PE32+
    put<uint32_t>(image, optional + 4, 0x1000);         // size of code
    put<uint32_t>(image, optional + 8, 0x400);          // size of initialized data
    put<uint32_t>(image, optional + 16, 0x1000);        // entry point
    put<uint32_t>(image, optional + 20, 0x1000);        // base of code
    put<uint64_t>(image, optional + 24, kImageBase);
    put<uint32_t>(image, optional + 32, 0x1000);        // section alignment
    put<uint32_t>(image, optional + 36, 0x200);         // file alignment
    put<uint16_t>(image, optional + 40, 6);             // operating system version
    put<uint16_t>(image, optional + 48, 6);             // subsystem version
    put<uint32_t>(image, optional + 56, 0x4000);        // size of image
    put<uint32_t>(image, optional + 60, 0x400);         // size of headers
    put<uint16_t>(image, optional + 68, 3);             // console subsystem
    put<uint16_t>(image, optional + 70, 0x100);         // NX compatible
    put<uint64_t>(image, optional + 72, 0x100000);      // stack reserve
    put<uint64_t>(image, optional + 80, 0x1000);        // stack commit
    put<uint64_t>(image, optional + 88, 0x100000);      // heap reserve
    put<uint64_t>(image, optional + 96, 0x1000);        // heap commit
    put<uint32_t>(image, optional + 108, 16);           // data directories
    constexpr size_t directories = optional + 112;
    put<uint32_t>(image, directories + 8, 0x3000);      // import directory
    put<uint32_t>(image, directories + 12, 40);
    put<uint32_t>(image, directories + 12 * 8, 0x3140); // import address table
    put<uint32_t>(image, directories + 12 * 8 + 4, 8 * 8);
    struct Section { const char* name; uint32_t rva, rawSize, rawOffset, flags; };
    constexpr Section sections[] = {
        {".text", 0x1000, 0x1000, 0x400, 0x60000020},
        {".data", 0x2000, 0x200, 0x1400, 0xc0000040},
        {".idata", 0x3000, 0x200, 0x1600, 0xc0000040},
    };
    for (size_t index = 0; index < std::size(sections); ++index) {
        const size_t header = optional + optionalSize + index * 40;
        std::memcpy(image.data() + header, sections[index].name, std::strlen(sections[index].name));
        put<uint32_t>(image, header + 8, sections[index].rawSize);
        put<uint32_t>(image, header + 12, sections[index].rva);
        put<uint32_t>(image, header + 16, sections[index].rawSize);
        put<uint32_t>(image, header + 20, sections[index].rawOffset);
        put<uint32_t>(image, header + 36, sections[index].flags);
    }
    std::memcpy(image.data() + 0x400, kHelperCode, sizeof(kHelperCode));

    constexpr size_t data = 0x1400;
    put<uint64_t>(image, data + 0x00, request.operation);
    put<uint64_t>(image, data + 0x08, request.windowsPid);
    put<uint64_t>(image, data + 0x10, request.preferred);
    put<uint64_t>(image, data + 0x18, request.low);
    put<uint64_t>(image, data + 0x20, request.high);
    put<uint64_t>(image, data + 0x28, request.size);
    put<uint64_t>(image, data + 0x30, request.protection);
    put<uint64_t>(image, data + 0x38, request.address);
    std::memcpy(image.data() + data + 0x40, kResultMagic, sizeof(kResultMagic));

    constexpr size_t imports = 0x1600;
    put<uint32_t>(image, imports + 0, 0x3100);          // lookup table
    put<uint32_t>(image, imports + 12, 0x3040);         // DLL name
    put<uint32_t>(image, imports + 16, 0x3140);         // address table
    std::memcpy(image.data() + imports + 0x40, "kernel32.dll", 13);
    size_t offset = 0x80;
    constexpr const char* names[] = {"GetStdHandle", "WriteFile", "ExitProcess", "OpenProcess",
                                     "VirtualAllocEx", "VirtualFreeEx", "GetLastError"};
    for (size_t index = 0; index < std::size(names); ++index) {
        const size_t length = std::strlen(names[index]);
        std::memcpy(image.data() + imports + offset + 2, names[index], length + 1);
        put<uint64_t>(image, imports + 0x100 + index * 8, 0x3000 + offset);
        put<uint64_t>(image, imports + 0x140 + index * 8, 0x3000 + offset);
        offset = (offset + 2 + length + 1 + 1) & ~size_t(1);
    }
    return image;
}

std::expected<uint32_t, std::error_code> wineWindowsProcessId(pid_t pid) {
    auto task = processMemoryTask(pid);
    if (!task) return std::unexpected(task.error());
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps) return std::unexpected(error(std::errc::no_such_process));
    std::optional<uint32_t> found;
    std::string line;
    while (std::getline(maps, line)) {
        unsigned long long start = 0, end = 0;
        char perms[5] = {};
        int pathAt = 0;
        if (std::sscanf(line.c_str(), "%llx-%llx %4s %*s %*s %*s %n", &start, &end, perms, &pathAt) < 3) continue;
        // TEBs are small private writable allocations; skip file mappings and
        // large heaps.
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p' || end - start > (64u << 20) ||
            (pathAt > 0 && static_cast<size_t>(pathAt) < line.size() && line[static_cast<size_t>(pathAt)] != '['))
            continue;
        for (unsigned long long page = start; page < end; page += 0x1000) {
            // +0x30 NtTib.Self, +0x38 EnvironmentPointer, +0x40 and +0x48
            // ClientId (process, thread).
            uint64_t words[4] = {};
            iovec local{words, sizeof(words)}, remote{reinterpret_cast<void*>(page + 0x30), sizeof(words)};
            if (::process_vm_readv(*task, &local, 1, &remote, 1, 0) != static_cast<ssize_t>(sizeof(words))) continue;
            // Windows ids are nonzero multiples of four.
            const uint64_t process = words[2], thread = words[3];
            if (words[0] != page || !process || process > UINT32_MAX || process % 4 || !thread || thread % 4) continue;
            if (found && *found != process) return std::unexpected(error(std::errc::invalid_argument));
            found = static_cast<uint32_t>(process);
        }
    }
    if (!found) return std::unexpected(error(std::errc::no_such_process));
    return *found;
}

std::expected<uintptr_t, std::error_code> wineVirtualAlloc(pid_t pid, size_t size, MemProt protection,
                                                           uintptr_t preferred, uintptr_t low, uintptr_t high) {
    constexpr uint64_t granularity = 0x10000;
    WineHelperRequest request;
    request.operation = 1;
    request.size = size;
    request.protection = windowsProtection(protection);
    request.low = std::max<uint64_t>((low + granularity - 1) & ~(granularity - 1), granularity);
    request.high = high & ~(granularity - 1);
    if (!size || request.low > request.high) return std::unexpected(error(std::errc::invalid_argument));
    // Nothing preferred: search the window from its start.
    request.preferred = std::clamp<uint64_t>(preferred ? preferred & ~(granularity - 1) : request.low, request.low, request.high);
    auto windowsPid = cachedWindowsProcessId(pid);
    if (!windowsPid) return std::unexpected(windowsPid.error());
    request.windowsPid = *windowsPid;
    auto result = runHelper(pid, wineHelperImage(request));
    if (!result) return std::unexpected(result.error());
    uint64_t address = 0;
    uint32_t lastError = 0, status = 0;
    std::memcpy(&address, result->data() + 8, 8);
    std::memcpy(&lastError, result->data() + 16, 4);
    std::memcpy(&status, result->data() + 20, 4);
    if (status != 1 || !address) return std::unexpected(windowsError(lastError));
    if (address < request.low || address > request.high) {
        (void)wineVirtualFree(pid, static_cast<uintptr_t>(address));
        return std::unexpected(error(std::errc::not_enough_memory));
    }
    return static_cast<uintptr_t>(address);
}

std::expected<void, std::error_code> wineVirtualFree(pid_t pid, uintptr_t address) {
    WineHelperRequest request;
    request.operation = 2;
    request.address = address;
    auto windowsPid = cachedWindowsProcessId(pid);
    if (!windowsPid) return std::unexpected(windowsPid.error());
    request.windowsPid = *windowsPid;
    auto result = runHelper(pid, wineHelperImage(request));
    if (!result) return std::unexpected(result.error());
    uint32_t lastError = 0, status = 0;
    std::memcpy(&lastError, result->data() + 16, 4);
    std::memcpy(&status, result->data() + 20, 4);
    if (status != 1) return std::unexpected(windowsError(lastError));
    return {};
}

} // namespace ce::os
