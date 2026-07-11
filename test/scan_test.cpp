#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"
#include "arch/disassembler.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>

using namespace ce;
using namespace ce::os;

// ── Test target: child process with a known value in shared memory ──
static volatile int32_t* shared_value = nullptr;
static pid_t child_pid = 0;

static void spawn_target() {
    // Create shared memory so we can modify the child's value
    shared_value = (volatile int32_t*)mmap(nullptr, 4096,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *shared_value = 12345;

    child_pid = fork();
    if (child_pid == 0) {
        // Child: just spin reading the shared value
        volatile int32_t* val = shared_value;
        while (true) {
            (void)*val; // keep it in memory
            usleep(100000);
        }
        _exit(0);
    }
    usleep(200000); // let child start
    printf("Target PID: %d, value at %p = %d\n\n", child_pid, (void*)shared_value, *shared_value);
}

static void kill_target() {
    if (child_pid > 0) {
        kill(child_pid, SIGTERM);
        waitpid(child_pid, nullptr, 0);
        printf("\nKilled target %d\n", child_pid);
    }
    if (shared_value)
        munmap((void*)shared_value, 4096);
}

// ── Disassembler test ──
static void test_disassembler() {
    printf("── Test: Disassembler (Capstone) ──\n");
    Disassembler dis(Arch::X86_64);

    // x86-64: push rbp; mov rbp, rsp; sub rsp, 0x20; nop; ret
    uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x90, 0xc3};
    auto insns = dis.disassemble(0x400000, {code, sizeof(code)});

    printf("  Disassembled %zu instructions:\n", insns.size());
    for (auto& i : insns)
        printf("  %s\n", i.toString().c_str());
    printf("\n");
}

// ── First scan test ──
static void test_first_scan() {
    printf("── Test: First Scan (exact int32 = 12345) ──\n");
    LinuxProcessHandle proc(child_pid);
    MemoryScanner scanner;

    ScanConfig config;
    config.valueType = ValueType::Int32;
    config.compareType = ScanCompare::Exact;
    config.intValue = 12345;
    config.alignment = 4;

    auto result = scanner.firstScan(proc, config);
    printf("  Found %zu results\n", result.count());

    if (result.count() > 0 && result.count() <= 20) {
        for (size_t i = 0; i < result.count(); ++i) {
            uintptr_t addr = result.address(i);
            int32_t val;
            result.value(i, &val, sizeof(val));
            printf("  [%zu] addr=0x%lx value=%d\n", i, addr, val);
        }
    } else if (result.count() > 20) {
        printf("  (showing first 5)\n");
        for (size_t i = 0; i < 5; ++i) {
            uintptr_t addr = result.address(i);
            int32_t val;
            result.value(i, &val, sizeof(val));
            printf("  [%zu] addr=0x%lx value=%d\n", i, addr, val);
        }
    }
    printf("\n");
}

// ── Next scan test ──
static void test_next_scan() {
    printf("── Test: Full Scan Workflow ──\n");
    LinuxProcessHandle proc(child_pid);
    MemoryScanner scanner;

    // Step 1: First scan for 12345
    ScanConfig config;
    config.valueType = ValueType::Int32;
    config.compareType = ScanCompare::Exact;
    config.intValue = 12345;
    config.alignment = 4;

    printf("  Step 1: Scan for int32 = 12345\n");
    auto result1 = scanner.firstScan(proc, config);
    printf("  Found %zu results\n", result1.count());

    // Step 2: Change the value
    printf("  Step 2: Changing value to 99999\n");
    *shared_value = 99999;
    usleep(50000);

    // Step 3: Next scan for "changed"
    printf("  Step 3: Next scan for 'changed'\n");
    ScanConfig config2;
    config2.valueType = ValueType::Int32;
    config2.compareType = ScanCompare::Changed;
    config2.alignment = 4;

    auto result2 = scanner.nextScan(proc, config2, result1);
    printf("  Narrowed to %zu results\n", result2.count());

    // Step 4: Next scan for exact 99999
    printf("  Step 4: Next scan for exact 99999\n");
    ScanConfig config3;
    config3.valueType = ValueType::Int32;
    config3.compareType = ScanCompare::Exact;
    config3.intValue = 99999;
    config3.alignment = 4;

    auto result3 = scanner.nextScan(proc, config3, result2);
    printf("  Final: %zu results\n", result3.count());

    if (result3.count() > 0 && result3.count() <= 10) {
        for (size_t i = 0; i < result3.count(); ++i) {
            uintptr_t addr = result3.address(i);
            int32_t val;
            result3.value(i, &val, sizeof(val));
            printf("  [%zu] addr=0x%lx value=%d\n", i, addr, val);
        }
    }

    // Verify we can write to the found address
    if (result3.count() > 0) {
        uintptr_t addr = result3.address(0);
        int32_t newVal = 42;
        auto wr = proc.write(addr, &newVal, sizeof(newVal));
        if (wr) {
            printf("\n  Wrote 42 to 0x%lx\n", addr);
            printf("  Shared value is now: %d %s\n", *shared_value,
                   *shared_value == 42 ? "(CORRECT!)" : "(wrong address)");
        }
    }
    printf("\n");
}

int main() {
    if (getuid() != 0) {
        fprintf(stderr, "Run as root: sudo ./scan_test\n");
        return 1;
    }

    spawn_target();
    test_disassembler();
    test_first_scan();
    test_next_scan();
    kill_target();

    printf("All tests complete.\n");
    return 0;
}
