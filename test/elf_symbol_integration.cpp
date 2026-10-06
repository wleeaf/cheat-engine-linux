#include "symbols/elf_symbols.hpp"
#include "platform/linux/linux_process.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

// Read foreign ELF files without executing their code. The gate obtains the
// reference value from the toolchain's nm output, independently of our parser.
int main(int argc, char** argv) {
    if (argc != 5) return 2;
    char* end = nullptr;
    auto expected = std::strtoull(argv[4], &end, 0);
    if (!end || end == argv[4] || *end) return 2;
    ce::SymbolResolver resolver;
    uintptr_t actual = 0;
    if (std::strcmp(argv[1], "--process") == 0) {
        auto pid = std::strtoull(argv[2], &end, 0);
        if (!end || end == argv[2] || *end || !pid || pid > std::numeric_limits<pid_t>::max()) return 2;
        ce::os::LinuxProcessHandle process(static_cast<pid_t>(pid));
        resolver.loadProcess(process);
        actual = resolver.lookup(argv[3]);
    } else {
        auto base = std::strtoull(argv[3], &end, 0);
        if (!end || end == argv[3] || *end) return 2;
        resolver.loadModule(argv[1], "fixture", base);
        actual = resolver.lookup(argv[2]);
    }
    std::printf("ELF_SYMBOL_RESULT=%s expected=%llu actual=%llu\n",
                actual == expected ? "PASSED" : "FAILED", expected,
                static_cast<unsigned long long>(actual));
    return actual == expected ? 0 : 1;
}
