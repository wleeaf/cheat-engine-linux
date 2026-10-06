#include <condition_variable>
#include <chrono>
#include <map>
#include <mutex>
#include <thread>

// Throw controlled exceptions instead of exhausting the host's memory. The
// synchronized mode holds a second worker inside a read until the first fails.
class ScanFaultProcess final : public ProcessHandle {
public:
    enum class Fault { None, Allocation, Transport, Unknown };
    TargetBuffer buffer;
    Fault fault = Fault::None;
    bool synchronized = false;
    std::atomic<int> active{0}, entered{0}, slowFinished{0};
    std::atomic<bool> slowUsed{false};
    std::mutex mutex;
    std::condition_variable condition;
    bool secondEntered = false, failureReady = false, timedOut = false;
    ScanFaultProcess() {
        buffer.description.host = buffer.description.program = nativeTargetMachine();
        buffer.bytes.assign(70000, 42);
        buffer.concurrentReads = true;
    }
    void arm(Fault kind, bool sync = false) {
        fault = kind; synchronized = sync;
        entered = 0; slowFinished = 0; slowUsed = false;
        secondEntered = failureReady = timedOut = false;
    }
    pid_t pid() const override { return buffer.pid(); }
    bool is64bit() const override { return buffer.is64bit(); }
    bool supportsConcurrentReads() const override { return true; }
    TargetDescription targetDescription() override { return buffer.targetDescription(); }
    Result<size_t> read(uintptr_t address, void* destination, size_t size) override {
        struct ActiveRead {
            std::atomic<int>& count;
            explicit ActiveRead(std::atomic<int>& value) : count(value) { ++count; }
            ~ActiveRead() { --count; }
        } readOwner(active);
        if (fault == Fault::None) return buffer.read(address, destination, size);
        ++entered;
        if (synchronized && address >= buffer.memoryBase + buffer.bytes.size()/2) {
            if (!slowUsed.exchange(true)) {
                std::unique_lock lock(mutex);
                secondEntered = true; condition.notify_all();
                if (!condition.wait_for(lock, std::chrono::seconds(2), [&] { return failureReady; })) timedOut = true;
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
                ++slowFinished;
            }
            return buffer.read(address, destination, size);
        }
        if (synchronized) {
            std::unique_lock lock(mutex);
            if (!condition.wait_for(lock, std::chrono::seconds(2), [&] { return secondEntered; })) timedOut = true;
            failureReady = true; condition.notify_all();
        }
        if (fault == Fault::Allocation) throw std::bad_alloc();
        if (fault == Fault::Transport)
            throw std::system_error(std::make_error_code(std::errc::connection_reset), "controlled scan read failure");
        throw 42;
    }
    Result<size_t> write(uintptr_t address, const void* source, size_t size) override { return buffer.write(address, source, size); }
    std::vector<MemoryRegion> queryRegions() override { return buffer.queryRegions(); }
    std::optional<MemoryRegion> queryRegion(uintptr_t address) override { return buffer.queryRegion(address); }
    Result<uintptr_t> allocate(size_t size, MemProt protection, uintptr_t preferred) override { return buffer.allocate(size, protection, preferred); }
    Result<void> free(uintptr_t address, size_t size) override { return buffer.free(address, size); }
    Result<void> protect(uintptr_t address, size_t size, MemProt protection) override { return buffer.protect(address, size, protection); }
    std::vector<ModuleInfo> modules() override { return buffer.modules(); }
    std::vector<ThreadInfo> threads() override { return buffer.threads(); }
};

struct ScanFaultEnvironment {
    std::filesystem::path directory;
    std::optional<std::string> temporary, chunk;
    ScanFaultEnvironment() {
        if (const char* value = getenv("TMPDIR")) temporary = value;
        if (const char* value = getenv("CE_SCAN_CHUNK_KB")) chunk = value;
        std::string pattern = (std::filesystem::temp_directory_path()/"scan-fault-check-XXXXXX").string();
        if (!mkdtemp(pattern.data())) throw std::runtime_error("create scan fault test directory");
        directory = pattern;
        setenv("TMPDIR", directory.c_str(), 1); setenv("CE_SCAN_CHUNK_KB", "1", 1);
    }
    ~ScanFaultEnvironment() {
        if (temporary) setenv("TMPDIR", temporary->c_str(), 1); else unsetenv("TMPDIR");
        if (chunk) setenv("CE_SCAN_CHUNK_KB", chunk->c_str(), 1); else unsetenv("CE_SCAN_CHUNK_KB");
        std::error_code ignored; std::filesystem::remove_all(directory, ignored);
    }
};

static void scannerFailureTests() {
    ScanFaultEnvironment environment;
    ScanFaultProcess process;
    ScanConfig config; config.valueType = ValueType::Byte; config.compareType = ScanCompare::Unknown;
    config.alignment = 1; config.startAddress = process.buffer.memoryBase;
    config.stopAddress = config.startAddress + process.buffer.bytes.size() - 1;
    ScanResult bytePrevious(environment.directory/"byte"), allPrevious(environment.directory/"all");
    const std::array<uint8_t,8> sample{42}; allPrevious.enableAllTypeCandidates();
    for (size_t i=0; i<process.buffer.bytes.size(); ++i) {
        bytePrevious.addResult(config.startAddress+i, sample.data(), 1);
        allPrevious.addAllTypeResult(config.startAddress+i, sample.data(), 1);
    }
    bytePrevious.finalize(); allPrevious.finalize();
    auto snapshots = [&] {
        size_t count = 0;
        for (const auto& entry : std::filesystem::directory_iterator(environment.directory))
            count += entry.path().filename().string().starts_with("ce-scan-");
        return count;
    };
    auto descriptors = [] {
        return std::distance(std::filesystem::directory_iterator("/proc/self/fd"), std::filesystem::directory_iterator{});
    };
    auto originalFiles = [&] {
        std::map<std::filesystem::path, uint64_t> hashes;
        for (const auto& dir : {bytePrevious.directory(), allPrevious.directory()})
            for (const auto& file : std::filesystem::directory_iterator(dir)) {
                std::ifstream input(file.path(), std::ios::binary); uint64_t hash = 14695981039346656037ULL;
                char byte;
                while (input.get(byte)) { hash ^= static_cast<uint8_t>(byte); hash *= 1099511628211ULL; }
                hashes.emplace(file.path(), hash);
            }
        return hashes;
    };
    const auto savedFiles = originalFiles();
    bool cleaned = true;
    auto failsAsExpected = [&](auto&& operation, ScanFaultProcess::Fault fault) {
        const auto filesBefore = snapshots(); const auto fdsBefore = descriptors(); bool caught = false;
        try { operation(); }
        catch (const std::bad_alloc&) { caught = fault == ScanFaultProcess::Fault::Allocation; }
        catch (const std::system_error& error) { caught = fault == ScanFaultProcess::Fault::Transport && error.code() == std::errc::connection_reset; }
        catch (const std::runtime_error& error) { caught = fault == ScanFaultProcess::Fault::Unknown && std::string(error.what()).find("unknown exception") != std::string::npos; }
        catch (...) {}
        cleaned = cleaned && snapshots() == filesBefore && descriptors() == fdsBefore;
        return caught && process.active == 0;
    };
    bool first = true, next = true;
    for (int workers : {1,2}) for (ValueType type : {ValueType::Byte,ValueType::All}) {
        MemoryScanner scanner(workers); config.valueType = type;
        for (auto fault : {ScanFaultProcess::Fault::Allocation,ScanFaultProcess::Fault::Transport,ScanFaultProcess::Fault::Unknown}) {
            process.arm(fault);
            first = failsAsExpected([&] { scanner.firstScan(process, config); }, fault) && first;
            process.arm(fault);
            const auto& previous = type == ValueType::Byte ? bytePrevious : allPrevious;
            next = failsAsExpected([&] { scanner.nextScan(process, config, previous); }, fault) && next;
        }
    }
    check(first,"First scan reports allocation, transport and unknown worker exceptions instead of returning false success");
    check(next,"Single and parallel next scans report worker exceptions without terminating the engine or replacing saved samples");
    MemoryScanner scanner(2); config.valueType = ValueType::Byte;
    bool joined = true;
    for (bool narrowing : {false,true}) {
        process.arm(ScanFaultProcess::Fault::Allocation, true);
        bool propagated = failsAsExpected([&] {
            if (narrowing) scanner.nextScan(process, config, bytePrevious);
            else scanner.firstScan(process, config);
        }, ScanFaultProcess::Fault::Allocation);
        joined = joined && propagated && process.entered >= 2 && process.slowFinished == 1 && !process.timedOut;
    }
    check(joined,"Failed scans join an independently blocked sibling before reporting the original error");
    check(cleaned,"Failed first/next scans remove partial snapshot directories and release every file descriptor");
    process.arm(ScanFaultProcess::Fault::None);
    auto retryFirst = scanner.firstScan(process, config), retryNext = scanner.nextScan(process, config, bytePrevious);
    ScanResult reloaded(bytePrevious.directory()); uint8_t value = 0; reloaded.value(69999, &value, 1);
    check(retryFirst.count() == 70000 && retryNext.count() == 70000 && retryNext.shardLayout().size() == 2 &&
        originalFiles() == savedFiles && reloaded.count() == 70000 && reloaded.address(69999) == config.startAddress+69999 && value == 42 && process.buffer.writes == 0,
        "The same scanner succeeds after worker failure with original persisted samples and target memory unchanged");
    LuaEngine lua; lua.setProcess(&process);
    bool luaOk = lua.execute(R"lua(
        scanFailure=createMemScan()
        assert(scanFailure:firstScan(0,0,"42",0x10000,0x10003,1))
        assert(scanFailure:getFoundCount()==4 and scanFailure:getValue(0)=="42")
    )lua").empty();
    process.arm(ScanFaultProcess::Fault::Allocation);
    luaOk = lua.execute(R"lua(
        local ok,err=scanFailure:firstScan(0,0,"42",0x10000,0x10003,1)
        assert(not ok and type(err)=="string")
        assert(scanFailure:getFoundCount()==4 and scanFailure:getValue(0)=="42")
        ok,err=scanFailure:nextScan(0,0,"42",0x10000,0x10003,1)
        assert(not ok and type(err)=="string")
        assert(scanFailure:getFoundCount()==4 and scanFailure:getAddress(3)==0x10003)
    )lua").empty() && luaOk;
    process.arm(ScanFaultProcess::Fault::None);
    luaOk = lua.execute("assert(scanFailure:nextScan(0,0,'42',0x10000,0x10003,1) and scanFailure:getFoundCount()==4)").empty() && luaOk;
    check(luaOk,"Lua retains the last successful scan after allocation failure and can retry on the same scan object");
}
