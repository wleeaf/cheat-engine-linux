#pragma once
/// Multi-threaded memory scanner.
/// Ports the core algorithm from CE's memscan.pas.

#include "core/types.hpp"
#include "platform/process_api.hpp"
#include <functional>
#include <atomic>
#include <filesystem>

namespace ce {

/// Configuration for a memory scan.
struct ScanConfig {
    struct GroupedTerm {
        ValueType valueType = ValueType::Int32;
        size_t offset = 0;
        int64_t intValue = 0;
        double floatValue = 0.0;
        std::string stringValue;
        std::vector<uint8_t> byteArray;
        std::vector<uint8_t> byteArrayMask;
        std::vector<uint8_t> byteMask;
    };

    ValueType   valueType    = ValueType::Int32;
    ScanCompare compareType  = ScanCompare::Exact;
    size_t      alignment    = 4;        // Scan alignment (1=unaligned, 2, 4, 8)
    uintptr_t   startAddress = 0;
    uintptr_t   stopAddress  = 0x7FFFFFFFFFFF;
    bool        scanWritableOnly   = false;
    bool        scanExecutableOnly = false;
    bool        scanPrivate = true;
    bool        scanImage   = true;
    bool        scanMapped  = true;
    int         roundingType       = 0;   // 0=exact, 1=rounded, 2=truncated, 3=extreme
    int         floatDecimals      = -1;  // decimal places in the search value (-1=unknown);
                                          // roundingType 1 matches within half the last place
    double      floatTolerance     = 0.0; // Override tolerance for extreme comparisons
    bool        percentageScan     = false;
    double      percentageValue    = 0.0;
    double      percentageValue2   = 0.0; // For percentage "between" comparisons

    // Search values (interpretation depends on valueType + compareType)
    int64_t     intValue     = 0;
    int64_t     intValue2    = 0;  // For "between" comparisons
    double      floatValue   = 0;
    double      floatValue2  = 0;
    std::string stringValue;
    std::string stringEncoding;      // Empty/UTF-8 = raw UTF-8 bytes, otherwise iconv target encoding
    bool        caseSensitive = true; // String/Text scans: false = case-insensitive (ASCII fold)
    std::vector<uint8_t> byteArray;
    std::vector<uint8_t> byteArrayMask; // per-byte AND-mask (0xFF match, 0x00 wildcard, 0xF0/0x0F nibble)
    std::vector<uint8_t> byteMask;   // Bit mask for binary scans: 1 bits must match
    std::string binaryString;        // Binary pattern: "0110??01" (? = wildcard bit)
    std::vector<GroupedTerm> groupedTerms;
    std::string groupedExpression;
    std::string customFormula;
    size_t customValueSize = 4;

    /// Parse an AOB pattern like "7F 45 ?? 46" into byteArray + byteArrayMask
    /// Parse an AOB pattern ("48 8B ?? 05"). Returns false if the pattern is
    /// empty or contains a token that is neither hex nor a wildcard (?/*), so
    /// callers can reject typos instead of silently scanning a wrong pattern.
    bool parseAOB(const std::string& pattern);

    /// Parse a binary pattern like "0110??01" into byteArray + mask
    void parseBinary(const std::string& pattern);

    /// Encoded byte length of stringValue for ValueType::String scans.
    size_t stringValueSize() const;

    /// Parse grouped expressions like "i32:100@0;float:1.5@4;byte:7@8".
    bool parseGrouped(const std::string& expression, std::string* error = nullptr);

    /// Size in bytes of one grouped result block.
    size_t groupedValueSize() const;
};

/// Holds scan results on disk. Supports iteration without loading all into memory.
class ScanResult {
public:
    ScanResult() = default;
    explicit ScanResult(const std::filesystem::path& dir);

    size_t count() const { return count_; }
    /// Byte stride of each persisted value record (0 if empty).
    size_t valueSize() const { return valueSize_; }
    bool empty() const { return count_ == 0; }
    /// True if a backing-file write was short/failed (e.g. ENOSPC): the result is
    /// then truncated and trailing entries read back as zeroes, so consumers should
    /// treat it as unreliable and warn the user.
    bool hasWriteError() const { return writeError_; }
    /// Mark the result truncated/unreliable (used by the merge path when a
    /// concatenation write was short).
    void markWriteError() { writeError_ = true; }

    /// Read address at index i.
    uintptr_t address(size_t i) const;

    /// Read value bytes at index i.
    void value(size_t i, void* buf, size_t valueSize) const;

    /// Read original first-scan value bytes at index i.
    void firstValue(size_t i, void* buf, size_t valueSize) const;

    /// Iterate all results.
    void forEach(std::function<void(uintptr_t addr, const void* value, size_t valueSize)> callback, size_t valueSize) const;

    const std::filesystem::path& directory() const { return dir_; }

    /// Each backing shard's directory and record count, in address order. A scan
    /// splits its output across worker shards and the result references them in
    /// place (via a shards.txt manifest) instead of concatenating into one file,
    /// so there is no merge copy. Consumers that stream the raw record files
    /// (nextScan) iterate these; a single-file result reports one shard.
    struct ShardInfo { std::filesystem::path dir; size_t count; };
    std::vector<ShardInfo> shardLayout() const;

    /// Byte stride of one persisted value record, derived from a shard's
    /// values.bin size (0 if empty/unknown). Lets a next scan detect a
    /// value-size change without trusting the in-memory valueSize_, which is 0
    /// for a result reconstructed from files.
    size_t recordStride() const;

    /// Add a result (used during scanning).
    void addResult(uintptr_t addr, const void* value, size_t valueSize);
    void addResult(uintptr_t addr, const void* value, const void* firstValue, size_t valueSize);

    /// Flush buffered results to disk.
    void flush();

    /// Finalize (close files, update count).
    void finalize();

private:
    std::filesystem::path dir_;
    size_t count_ = 0;
    size_t valueSize_ = 0;

    bool writeError_ = false;   // a backing-file write was short/failed
    // Write buffers
    std::vector<uintptr_t> addrBuf_;
    std::vector<uint8_t> valueBuf_;
    std::vector<uint8_t> firstValueBuf_;
    int addrFd_ = -1;
    int valueFd_ = -1;
    int firstValueFd_ = -1;

    // Read-side shard layout. A finalized write result and a legacy
    // single-directory result are one implicit shard (dir_); a scan output
    // assembled from workers lists each worker directory here (loaded from a
    // shards.txt manifest), so reads span the shards without a physical merge.
    struct Shard { std::filesystem::path dir; size_t count; size_t cum; };
    std::vector<Shard> shards_;
    void loadShards();                     // populate shards_ + count_ from dir_
    const Shard* shardAt(size_t i) const;  // shard holding global index i (or null)
};

/// The memory scanner engine.
class MemoryScanner {
public:
    explicit MemoryScanner(int threadCount = 0); // 0 = auto (CPU count)

    /// First scan — searches all readable memory regions for the value.
    ScanResult firstScan(ProcessHandle& proc, const ScanConfig& config);

    /// Next scan — narrows previous results.
    ScanResult nextScan(ProcessHandle& proc, const ScanConfig& config, const ScanResult& previous);

    /// Progress (0.0 to 1.0).
    float progress() const { return progress_.load(std::memory_order_relaxed); }

    /// Cancel a running scan.
    void cancel() { cancelled_.store(true, std::memory_order_relaxed); }

private:
    int threadCount_;
    std::atomic<float> progress_{0};
    std::atomic<bool> cancelled_{false};

    static size_t valueSizeFor(ValueType vt);
};

} // namespace ce
