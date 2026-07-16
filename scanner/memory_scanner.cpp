#include <charconv>
#include "scanner/memory_scanner.hpp"

#include <thread>
#include <mutex>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <type_traits>
#include <stdexcept>
#include <cctype>
#include <cerrno>
#include <limits>
#include <optional>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <iconv.h>
#if defined(__x86_64__)
#include <immintrin.h>   // SIMD exact-match scanning (SSE2 baseline + runtime AVX2)
#endif

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

namespace ce {

// ── Value size lookup ──

size_t MemoryScanner::valueSizeFor(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:    return 1;
        case ValueType::Int16:   return 2;
        case ValueType::Int32:   return 4;
        case ValueType::Int64:   return 8;
        case ValueType::Pointer: return sizeof(uintptr_t);
        case ValueType::Float:   return 4;
        case ValueType::Double:  return 8;
        case ValueType::String:  return 1;
        case ValueType::UnicodeString: return 2;
        default:                 return 4;
    }
}

// ── Comparison functions ──

namespace {

std::string trimCopy(const std::string& value) {
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start])))
        ++start;
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])))
        --end;
    return value.substr(start, end - start);
}

std::string lowerCopy(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::string unquoteCopy(const std::string& value) {
    auto trimmed = trimCopy(value);
    if (trimmed.size() >= 2) {
        char first = trimmed.front();
        char last = trimmed.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
            return trimmed.substr(1, trimmed.size() - 2);
    }
    return trimmed;
}

bool parseInt64Token(const std::string& text, int64_t& out) {
    auto token = trimCopy(text);
    if (token.empty()) return false;
    errno = 0;
    char* end = nullptr;
    long long parsed = std::strtoll(token.c_str(), &end, 0);
    if (errno != 0 || end == token.c_str() || *end != '\0')
        return false;
    out = static_cast<int64_t>(parsed);
    return true;
}

bool parseDoubleToken(const std::string& text, double& out) {
    auto token = trimCopy(text);
    if (token.empty()) return false;
    // Parse locale-independently: std::strtod honours the C locale, which Qt sets
    // to comma-decimal, so "3.14" would parse as 3. Accept both '.' and ',' and
    // parse with '.' via std::from_chars (always locale-independent).
    for (auto& c : token) if (c == ',') c = '.';
    // from_chars accepts a leading '-' but NOT a leading '+' (unlike strtoll, which
    // parseInt64Token uses), so skip one so "+3.14" parses like "+100" does.
    size_t begin = (!token.empty() && token[0] == '+') ? 1 : 0;
    double parsed = 0;
    auto [ptr, ec] = std::from_chars(token.data() + begin, token.data() + token.size(), parsed);
    if (ec != std::errc() || ptr != token.data() + token.size())
        return false;
    out = parsed;
    return true;
}

bool parseSizeToken(const std::string& text, size_t& out) {
    auto token = trimCopy(text);
    if (token.empty()) return false;
    errno = 0;
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(token.c_str(), &end, 0);
    if (errno != 0 || end == token.c_str() || *end != '\0')
        return false;
    if (parsed > std::numeric_limits<size_t>::max())
        return false;
    out = static_cast<size_t>(parsed);
    return true;
}

bool isUtf8Encoding(const std::string& encoding) {
    auto normalized = lowerCopy(trimCopy(encoding));
    return normalized.empty() || normalized == "utf8" || normalized == "utf-8";
}

std::vector<uint8_t> encodeStringBytes(const std::string& text, const std::string& encoding) {
    if (isUtf8Encoding(encoding))
        return {text.begin(), text.end()};

    iconv_t cd = iconv_open(encoding.c_str(), "UTF-8");
    if (cd == reinterpret_cast<iconv_t>(-1))
        throw std::invalid_argument("unsupported string encoding: " + encoding);

    size_t inLeft = text.size();
    char* inPtr = const_cast<char*>(text.data());
    std::vector<uint8_t> out(std::max<size_t>(16, text.size() * 4 + 8));
    char* outPtr = reinterpret_cast<char*>(out.data());
    size_t outLeft = out.size();

    while (true) {
        size_t converted = iconv(cd, &inPtr, &inLeft, &outPtr, &outLeft);
        if (converted != static_cast<size_t>(-1))
            break;
        if (errno != E2BIG) {
            iconv_close(cd);
            throw std::invalid_argument("string encoding conversion failed for " + encoding);
        }

        size_t used = out.size() - outLeft;
        out.resize(out.size() * 2);
        outPtr = reinterpret_cast<char*>(out.data() + used);
        outLeft = out.size() - used;
    }

    out.resize(out.size() - outLeft);
    iconv_close(cd);
    return out;
}

template<typename T>
using CompareFn = bool(*)(T current, T scanVal, T scanVal2);

template<typename T> bool cmpExact(T c, T v, T)          { return c == v; }
template<typename T> bool cmpGreater(T c, T v, T)        { return c > v; }
template<typename T> bool cmpLess(T c, T v, T)           { return c < v; }
// Auto-order the bounds so "between 200 and 100" means the same as "between 100
// and 200" (a value between min and max is unambiguous); otherwise reversed input
// silently finds nothing.
template<typename T> bool cmpBetween(T c, T v, T v2)     { return v <= v2 ? (c >= v && c <= v2)
                                                                          : (c >= v2 && c <= v); }
template<typename T> bool cmpChanged(T c, T v, T)        { return c != v; }
template<typename T> bool cmpUnchanged(T c, T v, T)      { return c == v; }
template<typename T> bool cmpIncreased(T c, T v, T)      { return c > v; }
template<typename T> bool cmpDecreased(T c, T v, T)      { return c < v; }
template<typename T> bool cmpUnknown(T, T, T)             { return true; }

template<typename T>
CompareFn<T> getCompare(ScanCompare cmp) {
    switch (cmp) {
        case ScanCompare::Exact:     return cmpExact<T>;
        case ScanCompare::Greater:   return cmpGreater<T>;
        case ScanCompare::Less:      return cmpLess<T>;
        case ScanCompare::Between:   return cmpBetween<T>;
        case ScanCompare::Changed:   return cmpChanged<T>;
        case ScanCompare::Unchanged: return cmpUnchanged<T>;
        case ScanCompare::Increased: return cmpIncreased<T>;
        case ScanCompare::Decreased: return cmpDecreased<T>;
        case ScanCompare::SameAsFirst: return cmpUnchanged<T>;
        case ScanCompare::Unknown:   return cmpUnknown<T>;
        default:                     return cmpExact<T>;
    }
}

template<typename T>
bool compareFloatingExact(const ScanConfig& config, T current, T scanVal) {
    if (!std::isfinite(static_cast<double>(current))) return false;

    switch (config.roundingType) {
        case 1: {
            double c = static_cast<double>(current);
            double s = static_cast<double>(scanVal);
            // CE "Rounded (default)": a memory value matches when it rounds to the
            // same value at the search value's decimal precision, i.e. it's within
            // half of the last decimal place. E.g. "3.14" (2 dp) matches [3.135,
            // 3.145); "100" (0 dp) matches [99.5, 100.5).
            if (config.floatDecimals >= 0) {
                double half = 0.5 * std::pow(10.0, -config.floatDecimals);
                return std::abs(c - s) <= half;
            }
            // No precision hint (non-GUI caller): fall back to integer rounding.
            // std::llround is UB when the rounded value doesn't fit in long long
            // (|v| > ~9.2e18), so round as doubles for out-of-range operands.
            constexpr double kLLMax = 9.2e18; // < LLONG_MAX, safe margin
            if (std::abs(c) > kLLMax || std::abs(s) > kLLMax)
                return std::round(c) == std::round(s);
            return std::llround(c) == std::llround(s);
        }
        case 2:
            return std::trunc(current) == std::trunc(scanVal);
        case 3: {
            double tolerance = config.floatTolerance > 0.0
                ? config.floatTolerance
                : std::max(1e-6, std::abs(static_cast<double>(scanVal)) * 1e-6);
            return std::abs(static_cast<double>(current) - static_cast<double>(scanVal)) <= tolerance;
        }
        default:
            return current == scanVal;
    }
}

template<typename T>
bool compareFloating(const ScanConfig& config, T current, T scanVal, T scanVal2) {
    if (config.compareType == ScanCompare::Exact)
        return compareFloatingExact(config, current, scanVal);
    return getCompare<T>(config.compareType)(current, scanVal, scanVal2);
}

bool supportsPercentageCompare(ScanCompare cmp) {
    switch (cmp) {
        case ScanCompare::Greater:
        case ScanCompare::Less:
        case ScanCompare::Between:
        case ScanCompare::Increased:
        case ScanCompare::Decreased:
            return true;
        default:
            return false;
    }
}

template<typename T>
bool comparePercentage(const ScanConfig& config, T current, T old) {
    double base = std::abs(static_cast<double>(old));
    if (base == 0.0) return false;

    double deltaPct = ((static_cast<double>(current) - static_cast<double>(old)) / base) * 100.0;
    switch (config.compareType) {
        case ScanCompare::Increased:
        case ScanCompare::Greater:
            return deltaPct >= config.percentageValue;
        case ScanCompare::Decreased:
        case ScanCompare::Less:
            return deltaPct <= -config.percentageValue;
        case ScanCompare::Between: {
            double lo = std::min(config.percentageValue, config.percentageValue2);
            double hi = std::max(config.percentageValue, config.percentageValue2);
            return deltaPct >= lo && deltaPct <= hi;
        }
        default:
            return false;
    }
}

template<typename T>
void scanBufferFloating(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                        size_t alignment, const ScanConfig& config, ScanResult& result)
{
    if (bufSize < sizeof(T)) return;
    if (alignment == 0) alignment = 1; // never let a 0 stride spin forever
    size_t limit = bufSize - sizeof(T) + 1;

    T scanVal = static_cast<T>(config.floatValue);
    T scanVal2 = static_cast<T>(config.floatValue2);
    for (size_t offset = 0; offset < limit; offset += alignment) {
        T current;
        std::memcpy(&current, buf + offset, sizeof(T));
        if (compareFloating(config, current, scanVal, scanVal2))
            result.addResult(baseAddr + offset, &current, sizeof(T));
    }
}

// ── Fast integer scanning ──
// The dominant scan by far is an exact integer value over an aligned buffer.
// A vectorised equality search makes the common "no match in this vector" case
// cost one compare + one movemask, so the scan runs near memory-bandwidth speed
// instead of a branch (previously an indirect call) per element. AVX2 is chosen
// at runtime; SSE2 is the guaranteed x86_64 baseline; every other case
// (non-x86, 8-byte lanes without AVX2, unaligned strides, relational compares)
// uses an inlined scalar loop, still element-wise but with no function-pointer
// indirection, so the compiler can keep the comparison in registers.

template<typename T>
inline void emitAt(const uint8_t* buf, size_t off, uintptr_t base, ScanResult& res) {
    res.addResult(base + off, buf + off, sizeof(T));
}

// Which vector path exact-integer scans take. Decided once from the CPU, with
// an override for portability testing/benchmarking: CE_SCAN_SIMD=off|sse2|avx2
// (consistent with the project's other runtime CE_* diagnostics).
enum class SimdMode { Scalar, SSE2, AVX2 };
inline SimdMode simdMode() {
    static const SimdMode m = [] {
#if defined(__x86_64__)
        if (const char* e = std::getenv("CE_SCAN_SIMD")) {
            if (!std::strcmp(e, "off") || !std::strcmp(e, "0") || !std::strcmp(e, "scalar"))
                return SimdMode::Scalar;
            if (!std::strcmp(e, "sse2")) return SimdMode::SSE2;
            if (!std::strcmp(e, "avx2"))
                return __builtin_cpu_supports("avx2") ? SimdMode::AVX2 : SimdMode::SSE2;
        }
        if (__builtin_cpu_supports("avx2")) return SimdMode::AVX2;
        return SimdMode::SSE2; // SSE2 is the x86_64 baseline
#else
        return SimdMode::Scalar;
#endif
    }();
    return m;
}

#if defined(__x86_64__)

// Emit every lane in a movemask where the lane's low bit is set. cmpeq sets all
// L bytes of a matching lane, so the low bit at lane*L reliably marks a hit.
template<typename T, size_t W>
inline void emitMaskLanes(const uint8_t* buf, size_t firstLane, unsigned mask,
                          uintptr_t base, ScanResult& res) {
    constexpr size_t L = sizeof(T);
    for (size_t lane = 0; lane < W; ++lane)
        if (mask & (1u << (lane * L)))
            emitAt<T>(buf, (firstLane + lane) * L, base, res);
}

template<typename T>
__attribute__((target("avx2")))
void scanExactAVX2(const uint8_t* buf, size_t nLanes, uintptr_t base, T needle, ScanResult& res) {
    constexpr size_t L = sizeof(T);
    constexpr size_t W = 32 / L;
    __m256i n;
    if constexpr (L == 1)      n = _mm256_set1_epi8(static_cast<char>(needle));
    else if constexpr (L == 2) n = _mm256_set1_epi16(static_cast<short>(needle));
    else if constexpr (L == 4) n = _mm256_set1_epi32(static_cast<int>(needle));
    else                       n = _mm256_set1_epi64x(static_cast<long long>(needle));

    size_t i = 0;
    for (; i + W <= nLanes; i += W) {
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(buf + i * L));
        __m256i eq;
        if constexpr (L == 1)      eq = _mm256_cmpeq_epi8(v, n);
        else if constexpr (L == 2) eq = _mm256_cmpeq_epi16(v, n);
        else if constexpr (L == 4) eq = _mm256_cmpeq_epi32(v, n);
        else                       eq = _mm256_cmpeq_epi64(v, n);
        unsigned mask = static_cast<unsigned>(_mm256_movemask_epi8(eq));
        if (mask) emitMaskLanes<T, W>(buf, i, mask, base, res);
    }
    for (; i < nLanes; ++i) {
        T cur; std::memcpy(&cur, buf + i * L, L);
        if (cur == needle) emitAt<T>(buf, i * L, base, res);
    }
}

// SSE2 is unconditionally available on x86_64. It lacks a 64-bit integer
// compare, so this handles 1/2/4-byte lanes; 8-byte falls through to scalar.
template<typename T>
void scanExactSSE2(const uint8_t* buf, size_t nLanes, uintptr_t base, T needle, ScanResult& res) {
    constexpr size_t L = sizeof(T);
    static_assert(L == 1 || L == 2 || L == 4, "SSE2 exact scan handles 1/2/4-byte lanes");
    constexpr size_t W = 16 / L;
    __m128i n;
    if constexpr (L == 1)      n = _mm_set1_epi8(static_cast<char>(needle));
    else if constexpr (L == 2) n = _mm_set1_epi16(static_cast<short>(needle));
    else                       n = _mm_set1_epi32(static_cast<int>(needle));

    size_t i = 0;
    for (; i + W <= nLanes; i += W) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buf + i * L));
        __m128i eq;
        if constexpr (L == 1)      eq = _mm_cmpeq_epi8(v, n);
        else if constexpr (L == 2) eq = _mm_cmpeq_epi16(v, n);
        else                       eq = _mm_cmpeq_epi32(v, n);
        unsigned mask = static_cast<unsigned>(_mm_movemask_epi8(eq));
        if (mask) emitMaskLanes<T, W>(buf, i, mask, base, res);
    }
    for (; i < nLanes; ++i) {
        T cur; std::memcpy(&cur, buf + i * L, L);
        if (cur == needle) emitAt<T>(buf, i * L, base, res);
    }
}
#endif // __x86_64__

// Exact integer scan. For an aligned scan (stride == sizeof(T)) the candidate
// offsets are exactly the T-lanes, so we can vectorise. nLanes is chosen so the
// last lane's read stays within bufSize (nLanes*sizeof(T) <= bufSize).
template<typename T>
void scanExactInteger(const uint8_t* buf, size_t bufSize, uintptr_t base,
                      size_t alignment, T needle, ScanResult& res) {
    if (bufSize < sizeof(T)) return;
    if (alignment == 0) alignment = 1;
    if (alignment == sizeof(T)) {
        size_t nLanes = (bufSize - sizeof(T)) / sizeof(T) + 1;
#if defined(__x86_64__)
        SimdMode mode = simdMode();
        if (mode == SimdMode::AVX2) { scanExactAVX2<T>(buf, nLanes, base, needle, res); return; }
        if (mode == SimdMode::SSE2) {
            if constexpr (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4) {
                scanExactSSE2<T>(buf, nLanes, base, needle, res);
                return;
            }
            // 8-byte lanes have no SSE2 integer compare → fall through to scalar.
        }
#endif
        for (size_t i = 0; i < nLanes; ++i) {
            T cur; std::memcpy(&cur, buf + i * sizeof(T), sizeof(T));
            if (cur == needle) emitAt<T>(buf, i * sizeof(T), base, res);
        }
        return;
    }
    // Unaligned exact scan: inlined scalar, arbitrary stride.
    size_t limit = bufSize - sizeof(T) + 1;
    for (size_t off = 0; off < limit; off += alignment) {
        T cur; std::memcpy(&cur, buf + off, sizeof(T));
        if (cur == needle) emitAt<T>(buf, off, base, res);
    }
}

// Relational / first-scan comparisons other than Exact. The predicate is a
// stateless lambda selected once outside the loop, so it inlines (no CompareFn
// function pointer).
template<typename T>
void scanRelational(const uint8_t* buf, size_t bufSize, uintptr_t base,
                    size_t alignment, T v, T v2, ScanCompare cmp, ScanResult& res) {
    if (bufSize < sizeof(T)) return;
    if (alignment == 0) alignment = 1;
    size_t limit = bufSize - sizeof(T) + 1;
    auto run = [&](auto pred) {
        for (size_t off = 0; off < limit; off += alignment) {
            T cur; std::memcpy(&cur, buf + off, sizeof(T));
            if (pred(cur)) emitAt<T>(buf, off, base, res);
        }
    };
    switch (cmp) {
        case ScanCompare::Greater:     run([&](T c){ return c > v; }); break;
        case ScanCompare::Less:        run([&](T c){ return c < v; }); break;
        case ScanCompare::Between:     run([&](T c){ return v <= v2 ? (c >= v && c <= v2)
                                                                    : (c >= v2 && c <= v); }); break;
        case ScanCompare::Changed:     run([&](T c){ return c != v; }); break;
        case ScanCompare::Unchanged:   run([&](T c){ return c == v; }); break;
        case ScanCompare::Increased:   run([&](T c){ return c > v; }); break;
        case ScanCompare::Decreased:   run([&](T c){ return c < v; }); break;
        case ScanCompare::SameAsFirst: run([&](T c){ return c == v; }); break;
        case ScanCompare::Unknown:     run([&](T){ return true; }); break;
        default:                       run([&](T c){ return c == v; }); break;
    }
}

// Dispatch a first-scan integer comparison: exact goes through the SIMD path,
// everything else through the inlined scalar predicate.
template<typename T>
void scanIntegerFast(const uint8_t* buf, size_t bufSize, uintptr_t base,
                     size_t alignment, T v, T v2, ScanCompare cmp, ScanResult& res) {
    if (cmp == ScanCompare::Exact)
        scanExactInteger<T>(buf, bufSize, base, alignment, v, res);
    else
        scanRelational<T>(buf, bufSize, base, alignment, v, v2, cmp, res);
}

// ── Fast float scanning ──
// A float/double exact scan uses the SIMD ordered-equality compare (_CMP_EQ_OQ /
// cmpeq_p*), which matches C++ float == exactly: NaN never matches, and -0.0
// equals 0.0. This is only equivalent to the scalar compareFloatingExact when
// there is no rounding (roundingType 0) and the search value is finite, so the
// caller only routes those cases here; rounded/tolerant/inf searches keep the
// scalar path. Lane emission and bounds mirror the integer SIMD scanners.
#if defined(__x86_64__)
template<typename T>
__attribute__((target("avx2")))
void scanExactFloatAVX(const uint8_t* buf, size_t nLanes, uintptr_t base, T needle, ScanResult& res) {
    if constexpr (sizeof(T) == 4) {
        constexpr size_t L = 4, W = 8;
        __m256 n = _mm256_set1_ps(needle);
        size_t i = 0;
        for (; i + W <= nLanes; i += W) {
            __m256 v = _mm256_loadu_ps(reinterpret_cast<const float*>(buf + i * L));
            unsigned mask = (unsigned)_mm256_movemask_ps(_mm256_cmp_ps(v, n, _CMP_EQ_OQ));
            if (mask) for (size_t lane = 0; lane < W; ++lane)
                if (mask & (1u << lane)) emitAt<T>(buf, (i + lane) * L, base, res);
        }
        for (; i < nLanes; ++i) { T c; std::memcpy(&c, buf + i * L, L); if (c == needle) emitAt<T>(buf, i * L, base, res); }
    } else {
        constexpr size_t L = 8, W = 4;
        __m256d n = _mm256_set1_pd(needle);
        size_t i = 0;
        for (; i + W <= nLanes; i += W) {
            __m256d v = _mm256_loadu_pd(reinterpret_cast<const double*>(buf + i * L));
            unsigned mask = (unsigned)_mm256_movemask_pd(_mm256_cmp_pd(v, n, _CMP_EQ_OQ));
            if (mask) for (size_t lane = 0; lane < W; ++lane)
                if (mask & (1u << lane)) emitAt<T>(buf, (i + lane) * L, base, res);
        }
        for (; i < nLanes; ++i) { T c; std::memcpy(&c, buf + i * L, L); if (c == needle) emitAt<T>(buf, i * L, base, res); }
    }
}

template<typename T>
void scanExactFloatSSE(const uint8_t* buf, size_t nLanes, uintptr_t base, T needle, ScanResult& res) {
    if constexpr (sizeof(T) == 4) {
        constexpr size_t L = 4, W = 4;
        __m128 n = _mm_set1_ps(needle);
        size_t i = 0;
        for (; i + W <= nLanes; i += W) {
            __m128 v = _mm_loadu_ps(reinterpret_cast<const float*>(buf + i * L));
            unsigned mask = (unsigned)_mm_movemask_ps(_mm_cmpeq_ps(v, n));
            if (mask) for (size_t lane = 0; lane < W; ++lane)
                if (mask & (1u << lane)) emitAt<T>(buf, (i + lane) * L, base, res);
        }
        for (; i < nLanes; ++i) { T c; std::memcpy(&c, buf + i * L, L); if (c == needle) emitAt<T>(buf, i * L, base, res); }
    } else {
        constexpr size_t L = 8, W = 2;
        __m128d n = _mm_set1_pd(needle);
        size_t i = 0;
        for (; i + W <= nLanes; i += W) {
            __m128d v = _mm_loadu_pd(reinterpret_cast<const double*>(buf + i * L));
            unsigned mask = (unsigned)_mm_movemask_pd(_mm_cmpeq_pd(v, n));
            if (mask) for (size_t lane = 0; lane < W; ++lane)
                if (mask & (1u << lane)) emitAt<T>(buf, (i + lane) * L, base, res);
        }
        for (; i < nLanes; ++i) { T c; std::memcpy(&c, buf + i * L, L); if (c == needle) emitAt<T>(buf, i * L, base, res); }
    }
}
#endif // __x86_64__

// If this float scan is a plain finite-value exact search on an aligned buffer,
// run the SIMD equality path and return true; otherwise return false so the
// caller falls back to scanBufferFloating (which handles rounding, tolerance,
// relational and non-finite comparisons).
template<typename T>
bool tryScanExactFloat(const uint8_t* buf, size_t bufSize, uintptr_t base,
                       size_t alignment, const ScanConfig& config, ScanResult& res) {
    if (config.compareType != ScanCompare::Exact) return false;
    if (config.roundingType != 0) return false;
    if (alignment != sizeof(T)) return false;
    if (bufSize < sizeof(T)) return false;
    T needle = static_cast<T>(config.floatValue);
    if (!std::isfinite(needle)) return false;

    size_t nLanes = (bufSize - sizeof(T)) / sizeof(T) + 1;
#if defined(__x86_64__)
    switch (simdMode()) {
        case SimdMode::AVX2: scanExactFloatAVX<T>(buf, nLanes, base, needle, res); return true;
        case SimdMode::SSE2: scanExactFloatSSE<T>(buf, nLanes, base, needle, res); return true;
        default: break;
    }
#endif
    for (size_t i = 0; i < nLanes; ++i) {
        T c; std::memcpy(&c, buf + i * sizeof(T), sizeof(T));
        if (c == needle) emitAt<T>(buf, i * sizeof(T), base, res);
    }
    return true;
}

/// Scan buffer for a string (exact substring match).
void scanBufferString(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                      const std::vector<uint8_t>& needle, ScanResult& result,
                      bool caseInsensitive = false)
{
    if (needle.empty() || bufSize < needle.size()) return;
    size_t nLen = needle.size();
    size_t limit = bufSize - nLen + 1;

    for (size_t offset = 0; offset < limit; ++offset) {
        bool match;
        if (!caseInsensitive) {
            match = std::memcmp(buf + offset, needle.data(), nLen) == 0;
        } else {
            // ASCII case fold per byte (handles UTF-8/ASCII; multibyte letters
            // outside ASCII compare exactly, as CE's case-insensitive does).
            match = true;
            for (size_t i = 0; i < nLen; ++i) {
                if (std::tolower(buf[offset + i]) != std::tolower(needle[i])) { match = false; break; }
            }
        }
        if (match) result.addResult(baseAddr + offset, buf + offset, nLen);
    }
}

std::vector<uint8_t> utf16LeBytes(const std::string& text);

/// Scan buffer for a UTF-16LE string.
void scanBufferUnicode(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                       const std::string& needle, ScanResult& result,
                       bool caseInsensitive = false)
{
    // Encode the needle with the same explicit little-endian encoder used by
    // the next-scan / grouped paths so both agree regardless of host
    // endianness. (Still ASCII→UTF-16LE only; see TODO.)
    // TODO(portability): decode a real UTF-8 needle to UTF-16LE (e.g. via
    // iconv, like encodeStringBytes) so non-ASCII unicode searches are correct.
    std::vector<uint8_t> n = utf16LeBytes(needle);
    size_t nBytes = n.size();
    if (nBytes == 0 || bufSize < nBytes) return;

    size_t limit = bufSize - nBytes + 1;

    for (size_t offset = 0; offset < limit; offset += 2) {
        bool match;
        if (!caseInsensitive) {
            match = std::memcmp(buf + offset, n.data(), nBytes) == 0;
        } else {
            // UTF-16LE code unit = [low, high]. ASCII-fold the low byte, compare
            // the high byte exactly (non-ASCII units then compare exactly).
            match = true;
            for (size_t i = 0; i + 1 < nBytes; i += 2) {
                if (std::tolower(buf[offset + i]) != std::tolower(n[i]) ||
                    buf[offset + i + 1] != n[i + 1]) { match = false; break; }
            }
        }
        if (match) result.addResult(baseAddr + offset, buf + offset, nBytes);
    }
}

/// Scan buffer for an array of bytes with wildcard mask.
void scanBufferAOB(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                   const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask,
                   ScanResult& result)
{
    if (pattern.empty() || mask.size() != pattern.size() || bufSize < pattern.size()) return;
    size_t pLen = pattern.size();
    size_t limit = bufSize - pLen + 1;

    for (size_t offset = 0; offset < limit; ++offset) {
        bool match = true;
        for (size_t j = 0; j < pLen; ++j) {
            // Per-byte AND-mask (full 0xFF, wildcard 0x00, nibble 0xF0/0x0F).
            if ((buf[offset + j] & mask[j]) != (pattern[j] & mask[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            result.addResult(baseAddr + offset, buf + offset, pLen);
        }
    }
}

/// Scan buffer for binary pattern with bitmask wildcards.
/// Pattern bytes and mask bytes: mask bit 1 = must match, 0 = wildcard.
void scanBufferBinary(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                      const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask,
                      size_t alignment, ScanResult& result)
{
    if (pattern.empty() || mask.size() != pattern.size() || bufSize < pattern.size()) return;
    if (alignment == 0) alignment = 1; // never let a 0 stride spin forever
    size_t pLen = pattern.size();
    size_t limit = bufSize - pLen + 1;

    for (size_t offset = 0; offset < limit; offset += alignment) {
        bool match = true;
        for (size_t j = 0; j < pLen; ++j) {
            if ((buf[offset + j] & mask[j]) != (pattern[j] & mask[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            result.addResult(baseAddr + offset, buf + offset, pLen);
        }
    }
}

/// "All Types" scan — scan for byte, int16, int32, int64, float, double simultaneously.
// emitLimit bounds the start offsets this call may emit (the window's "owned"
// length); the sub-type reads may still look ahead up to bufSize (the overlap),
// so a match starting at the last owned offset completes without the next
// window re-emitting it. When there is no overlap, pass emitLimit == bufSize.
void scanBufferAllTypes(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                        size_t alignment, int64_t intVal, double floatVal,
                        ScanCompare cmp, ScanResult& result, size_t emitLimit)
{
    auto cmpI8  = getCompare<int8_t>(cmp);
    auto cmpI16 = getCompare<int16_t>(cmp);
    auto cmpI32 = getCompare<int32_t>(cmp);
    auto cmpI64 = getCompare<int64_t>(cmp);
    auto cmpF32 = getCompare<float>(cmp);
    auto cmpF64 = getCompare<double>(cmp);

    if (alignment == 0) alignment = 1; // never let a 0 stride spin forever
    if (emitLimit > bufSize) emitLimit = bufSize;
    // ValueType::All stores a UNIFORM 8-byte record per match — the memory window
    // at the match offset, zero-padded at the region tail. A narrow per-type width
    // (1/2/4) would desync the value stream from the address list under the fixed
    // i*valueSize stride used by value(i)/firstValue(i) and the GUI (which reads
    // All-results at size 8), producing garbage values and a nextScan stride throw.
    auto addAll = [&](size_t off) {
        uint8_t w[8] = {0};
        std::memcpy(w, buf + off, std::min<size_t>(8, bufSize - off));
        result.addResult(baseAddr + off, w, 8);
    };
    for (size_t offset = 0; offset < emitLimit; offset += alignment) {
        // Byte
        if (offset < bufSize) {
            int8_t v; std::memcpy(&v, buf + offset, 1);
            if (cmpI8(v, (int8_t)intVal, 0))
                addAll(offset);
        }
        // Int16
        if (offset + 2 <= bufSize) {
            int16_t v; std::memcpy(&v, buf + offset, 2);
            if (cmpI16(v, (int16_t)intVal, 0))
                addAll(offset);
        }
        // Int32
        if (offset + 4 <= bufSize) {
            int32_t v; std::memcpy(&v, buf + offset, 4);
            if (cmpI32(v, (int32_t)intVal, 0))
                addAll(offset);
        }
        // Int64
        if (offset + 8 <= bufSize) {
            int64_t v; std::memcpy(&v, buf + offset, 8);
            if (cmpI64(v, intVal, 0))
                addAll(offset);
        }
        // Float
        if (offset + 4 <= bufSize) {
            float v; std::memcpy(&v, buf + offset, 4);
            // The magnitude squelch (drop tiny/huge floats as implausible) is a
            // heuristic that only makes sense for Unknown/initial scans — it
            // must not gate an exact/relational search, where 0.0 and small
            // magnitudes are legitimate matches. Always require finiteness.
            bool plausible = (cmp != ScanCompare::Unknown) ||
                             (v == 0.0f) ||
                             (std::abs(v) < 1e15f && std::abs(v) > 1e-15f);
            if (!std::isnan(v) && !std::isinf(v) && plausible)
                if (cmpF32(v, (float)floatVal, 0))
                    addAll(offset);
        }
        // Double
        if (offset + 8 <= bufSize) {
            double v; std::memcpy(&v, buf + offset, 8);
            bool plausible = (cmp != ScanCompare::Unknown) ||
                             (v == 0.0) ||
                             (std::abs(v) < 1e100 && std::abs(v) > 1e-100);
            if (!std::isnan(v) && !std::isinf(v) && plausible)
                if (cmpF64(v, floatVal, 0))
                    addAll(offset);
        }
    }
}

std::vector<uint8_t> utf16LeBytes(const std::string& text) {
    std::vector<uint8_t> bytes;
    bytes.reserve(text.size() * 2);
    for (char c : text) {
        bytes.push_back(static_cast<uint8_t>(c));
        bytes.push_back(0);
    }
    return bytes;
}

bool compareMaskedBytes(const uint8_t* currentVal,
                        const std::vector<uint8_t>& pattern,
                        const std::vector<uint8_t>& mask);

size_t groupedTermValueSize(const ScanConfig::GroupedTerm& term) {
    switch (term.valueType) {
        case ValueType::Byte:
            return 1;
        case ValueType::Int16:
            return 2;
        case ValueType::Int32:
        case ValueType::Float:
            return 4;
        case ValueType::Int64:
        case ValueType::Pointer:
        case ValueType::Double:
            return 8;
        case ValueType::String:
            return std::max<size_t>(1, term.stringValue.size());
        case ValueType::UnicodeString:
            return std::max<size_t>(2, term.stringValue.size() * 2);
        case ValueType::ByteArray:
        case ValueType::Binary:
            return std::max<size_t>(1, term.byteArray.size());
        default:
            return 0;
    }
}

bool groupedTermMatches(const uint8_t* value, const ScanConfig::GroupedTerm& term, const ScanConfig& config) {
    switch (term.valueType) {
        case ValueType::Byte: {
            uint8_t current = value[0];
            return current == static_cast<uint8_t>(term.intValue);
        }
        case ValueType::Int16: {
            int16_t current{};
            std::memcpy(&current, value, sizeof(current));
            return current == static_cast<int16_t>(term.intValue);
        }
        case ValueType::Int32: {
            int32_t current{};
            std::memcpy(&current, value, sizeof(current));
            return current == static_cast<int32_t>(term.intValue);
        }
        case ValueType::Int64: {
            int64_t current{};
            std::memcpy(&current, value, sizeof(current));
            return current == term.intValue;
        }
        case ValueType::Pointer: {
            uintptr_t current{};
            std::memcpy(&current, value, sizeof(current));
            return current == static_cast<uintptr_t>(term.intValue);
        }
        case ValueType::Float: {
            float current{};
            std::memcpy(&current, value, sizeof(current));
            return compareFloatingExact(config, current, static_cast<float>(term.floatValue));
        }
        case ValueType::Double: {
            double current{};
            std::memcpy(&current, value, sizeof(current));
            return compareFloatingExact(config, current, term.floatValue);
        }
        case ValueType::String:
            return std::memcmp(value, term.stringValue.data(), term.stringValue.size()) == 0;
        case ValueType::UnicodeString: {
            auto needle = utf16LeBytes(term.stringValue);
            return std::memcmp(value, needle.data(), needle.size()) == 0;
        }
        case ValueType::ByteArray:
            return compareMaskedBytes(value, term.byteArray, term.byteArrayMask);
        case ValueType::Binary: {
            if (term.byteMask.size() != term.byteArray.size())
                return false;
            for (size_t i = 0; i < term.byteArray.size(); ++i) {
                if ((value[i] & term.byteMask[i]) != (term.byteArray[i] & term.byteMask[i]))
                    return false;
            }
            return true;
        }
        default:
            return false;
    }
}

bool groupedBlockMatches(const uint8_t* block, size_t blockSize, const ScanConfig& config) {
    for (const auto& term : config.groupedTerms) {
        size_t termSize = groupedTermValueSize(term);
        if (termSize == 0 || term.offset > blockSize - termSize)
            return false;
        if (!groupedTermMatches(block + term.offset, term, config))
            return false;
    }
    return true;
}

void scanBufferUnknown(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                       size_t alignment, size_t valueSize, ScanResult& result) {
    if (valueSize == 0 || bufSize < valueSize) return;
    if (alignment == 0) alignment = 1;

    size_t limit = bufSize - valueSize + 1;
    for (size_t offset = 0; offset < limit; offset += alignment)
        result.addResult(baseAddr + offset, buf + offset, valueSize);
}

void scanBufferGrouped(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                       size_t alignment, const ScanConfig& config, ScanResult& result) {
    if (config.groupedTerms.empty()) return;
    size_t blockSize = config.groupedValueSize();
    if (blockSize == 0 || bufSize < blockSize) return;
    if (alignment == 0) alignment = 1;

    size_t limit = bufSize - blockSize + 1;
    for (size_t offset = 0; offset < limit; offset += alignment) {
        if (groupedBlockMatches(buf + offset, blockSize, config))
            result.addResult(baseAddr + offset, buf + offset, blockSize);
    }
}

size_t valueSizeForConfig(const ScanConfig& config) {
    switch (config.valueType) {
        case ValueType::String:
            return std::max<size_t>(1, config.stringValueSize());
        case ValueType::UnicodeString:
            return std::max<size_t>(2, config.stringValue.size() * 2);
        case ValueType::ByteArray:
        case ValueType::Binary:
            return std::max<size_t>(1, config.byteArray.size());
        case ValueType::All:
            return 8;
        case ValueType::Grouped:
            return std::max<size_t>(1, config.groupedValueSize());
        case ValueType::Custom:
            return std::max<size_t>(1, config.customValueSize);
        case ValueType::Byte:
            return 1;
        case ValueType::Int16:
            return 2;
        case ValueType::Int32:
        case ValueType::Float:
            return 4;
        case ValueType::Int64:
        case ValueType::Pointer:
        case ValueType::Double:
            return 8;
        default:
            return 4;
    }
}

template<typename T>
bool compareNextNumeric(const ScanConfig& config, const uint8_t* currentVal, const uint8_t* oldVal) {
    T cur{};
    T old{};
    std::memcpy(&cur, currentVal, sizeof(T));
    std::memcpy(&old, oldVal, sizeof(T));

    if (config.percentageScan && supportsPercentageCompare(config.compareType))
        return comparePercentage(config, cur, old);

    if (config.compareType == ScanCompare::SameAsFirst)
        return cur == old;

    // "Increased/Decreased value by N": delta comparison. Integers compare the
    // delta exactly; floats use a relative tolerance because the true delta is
    // rarely exactly representable (e.g. 0.3f-0.1f != 0.2f), so an exact == would
    // silently miss legitimate matches.
    if (config.compareType == ScanCompare::IncreasedBy ||
        config.compareType == ScanCompare::DecreasedBy) {
        if constexpr (std::is_floating_point_v<T>) {
            double d = static_cast<double>(config.floatValue);
            double actual = config.compareType == ScanCompare::IncreasedBy
                ? static_cast<double>(cur) - static_cast<double>(old)
                : static_cast<double>(old) - static_cast<double>(cur);
            double tol = std::max(1e-6, std::abs(d) * 1e-5);
            bool dir = config.compareType == ScanCompare::IncreasedBy ? (cur > old) : (cur < old);
            return dir && std::abs(actual - d) <= tol;
        } else {
            T delta = static_cast<T>(config.intValue);
            if (config.compareType == ScanCompare::IncreasedBy)
                return cur > old && static_cast<T>(cur - old) == delta;
            return cur < old && static_cast<T>(old - cur) == delta;
        }
    }

    auto cmp = getCompare<T>(config.compareType);
    if (config.compareType >= ScanCompare::Changed)
        return cmp(cur, old, T{});

    if constexpr (std::is_floating_point_v<T>) {
        T v1 = static_cast<T>(config.floatValue);
        T v2 = static_cast<T>(config.floatValue2);
        return compareFloating(config, cur, v1, v2);
    } else {
        return cmp(cur, static_cast<T>(config.intValue), static_cast<T>(config.intValue2));
    }
}

bool compareMaskedBytes(const uint8_t* currentVal,
                        const std::vector<uint8_t>& pattern,
                        const std::vector<uint8_t>& mask) {
    if (pattern.empty()) return false;
    for (size_t i = 0; i < pattern.size(); ++i) {
        // Per-byte AND-mask: only the set bits must match (supports full-byte and
        // nibble wildcards for AOB, and per-bit masks for binary patterns).
        uint8_t m = i < mask.size() ? mask[i] : 0xFF;
        if ((currentVal[i] & m) != (pattern[i] & m)) return false;
    }
    return true;
}

// Read exactly `n` bytes from `fd` into `buf`, retrying on EINTR and short
// reads. Returns true only if the full count was satisfied; a genuine EOF or
// hard error before `n` bytes yields false so callers can treat the result
// file as truncated rather than scanning stale/garbage buffer contents.
bool readFull(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0)
            return false; // EOF before satisfying the request → truncated
        got += static_cast<size_t>(r);
    }
    return true;
}

// pread exactly `n` bytes at `offset`, retrying on EINTR/short reads. Returns
// true only if the full count was satisfied.
bool preadFull(int fd, void* buf, size_t n, off_t offset) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::pread(fd, p + got, n - got, offset + static_cast<off_t>(got));
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0)
            return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

bool memoryTypeAllowed(const ScanConfig& config, MemType type) {
    switch (type) {
        case MemType::Private: return config.scanPrivate;
        case MemType::Image:   return config.scanImage;
        case MemType::Mapped:  return config.scanMapped;
    }
    return false;
}

// Reusable evaluator for ValueType::Custom formula scans. Standing up and
// tearing down a full Lua VM per candidate offset (the previous behaviour) was
// pathologically slow; this keeps ONE lua_State for the lifetime of the scan
// (or per worker thread, since lua_State is not thread-safe) and compiles the
// formula once into a reusable chunk. Each candidate only resets the
// current/old/hasOld/valueSize globals and re-calls the precompiled function.
// Only base/math/string libraries are loaded — a numeric match predicate has
// no need for os/io (which would also be a sandbox-escape vector).
class CustomFormulaEvaluator {
public:
    explicit CustomFormulaEvaluator(std::string formula)
        : formula_(std::move(formula)) {}

    ~CustomFormulaEvaluator() {
        if (L_) lua_close(L_);
    }

    CustomFormulaEvaluator(const CustomFormulaEvaluator&) = delete;
    CustomFormulaEvaluator& operator=(const CustomFormulaEvaluator&) = delete;

    // Returns true if the formula evaluated to a usable boolean/number result;
    // matchOut holds the predicate outcome. Returns false on compile/runtime
    // error or non-bool/number result (treated as "no match" by callers).
    bool eval(const uint8_t* currentVal, const uint8_t* oldVal,
              size_t valueSize, bool hasOld, bool& matchOut) {
        matchOut = false;
        if (formula_.empty())
            return false;
        if (!ensureCompiled())
            return false;

        lua_pushlstring(L_, reinterpret_cast<const char*>(currentVal), valueSize);
        lua_setglobal(L_, "current");
        lua_pushlstring(L_, reinterpret_cast<const char*>(oldVal), valueSize);
        lua_setglobal(L_, "old");
        lua_pushboolean(L_, hasOld ? 1 : 0);
        lua_setglobal(L_, "hasOld");
        lua_pushinteger(L_, static_cast<lua_Integer>(valueSize));
        lua_setglobal(L_, "valueSize");

        // Push a fresh copy of the precompiled chunk (registry ref) to call.
        lua_rawgeti(L_, LUA_REGISTRYINDEX, chunkRef_);
        bool ok = false;
        if (lua_pcall(L_, 0, 1, 0) == LUA_OK) {
            if (lua_isboolean(L_, -1)) {
                matchOut = lua_toboolean(L_, -1) != 0;
                ok = true;
            } else if (lua_isnumber(L_, -1)) {
                matchOut = lua_tonumber(L_, -1) != 0.0;
                ok = true;
            }
        }
        lua_pop(L_, 1); // result or error message
        return ok;
    }

private:
    bool ensureCompiled() {
        if (compiled_)
            return chunkRef_ != LUA_NOREF;
        compiled_ = true;
        L_ = luaL_newstate();
        if (!L_)
            return false;
        // Restricted library set: arithmetic only, no os/io.
        luaL_requiref(L_, "_G", luaopen_base, 1);   lua_pop(L_, 1);
        luaL_requiref(L_, "math", luaopen_math, 1);  lua_pop(L_, 1);
        luaL_requiref(L_, "string", luaopen_string, 1); lua_pop(L_, 1);

        if (luaL_loadstring(L_, formula_.c_str()) != LUA_OK) {
            lua_pop(L_, 1);
            chunkRef_ = LUA_NOREF;
            return false;
        }
        chunkRef_ = luaL_ref(L_, LUA_REGISTRYINDEX);
        return chunkRef_ != LUA_NOREF;
    }

    std::string formula_;
    lua_State* L_ = nullptr;
    int chunkRef_ = LUA_NOREF;
    bool compiled_ = false;
};

} // anonymous namespace

// ── AOB pattern parser ──

bool ScanConfig::parseAOB(const std::string& pattern) {
    byteArray.clear();
    byteArrayMask.clear();
    bool valid = true;
    auto nib = [&](char c, uint8_t& val, uint8_t& mask) {
        if (c == '?' || c == '*') { val = 0; mask = 0x0; }
        else if (c >= '0' && c <= '9') { val = c - '0';        mask = 0xF; }
        else if (c >= 'a' && c <= 'f') { val = c - 'a' + 10;   mask = 0xF; }
        else if (c >= 'A' && c <= 'F') { val = c - 'A' + 10;   mask = 0xF; }
        else { val = 0; mask = 0x0; valid = false; }   // not hex and not a wildcard
    };
    auto isHex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    std::istringstream ss(pattern);
    std::string token;
    while (ss >> token) {
        if (token == "??" || token == "?" || token == "*") {
            byteArray.push_back(0);
            byteArrayMask.push_back(0x00);           // full-byte wildcard
        } else if (token.size() == 2) {
            // Per-nibble: supports "48" (full), "4?"/"?8" (nibble wildcards).
            uint8_t hv, hm, lv, lm;
            nib(token[0], hv, hm); nib(token[1], lv, lm);
            byteArray.push_back((uint8_t)((hv << 4) | lv));
            byteArrayMask.push_back((uint8_t)((hm << 4) | lm));
        } else {
            // A single hex digit or an over-long token: accept only if all-hex.
            for (char c : token) if (!isHex(c)) valid = false;
            byteArray.push_back((uint8_t)strtoul(token.c_str(), nullptr, 16));
            byteArrayMask.push_back(0xFF);
        }
    }
    return valid && !byteArray.empty();
}

void ScanConfig::parseBinary(const std::string& pattern) {
    // Parse binary string like "0110??01" into bytes + mask
    // Every 8 bits = 1 byte. ? = wildcard bit.
    byteArray.clear();
    byteArrayMask.clear();
    byteMask.clear();

    uint8_t currentByte = 0, currentMask = 0;
    int bitCount = 0;

    for (char c : pattern) {
        if (c == ' ') continue;
        if (c == '0' || c == '1' || c == '?' || c == '*') {
            currentByte <<= 1;
            currentMask <<= 1;
            if (c == '1') { currentByte |= 1; currentMask |= 1; }
            else if (c == '0') { currentMask |= 1; }
            // '?' and '*' leave both as 0 (wildcard)
            bitCount++;
            if (bitCount == 8) {
                byteArray.push_back(currentByte);
                byteMask.push_back(currentMask);
                currentByte = 0;
                currentMask = 0;
                bitCount = 0;
            }
        }
    }
    // Handle partial last byte
    if (bitCount > 0) {
        currentByte <<= (8 - bitCount);
        currentMask <<= (8 - bitCount);
        byteArray.push_back(currentByte);
        byteMask.push_back(currentMask);
    }
    binaryString = pattern; // Keep original for reference
    byteArrayMask.resize(byteMask.size());
    for (size_t i = 0; i < byteMask.size(); ++i)
        byteArrayMask[i] = byteMask[i];
}

size_t ScanConfig::stringValueSize() const {
    return encodeStringBytes(stringValue, stringEncoding).size();
}

bool ScanConfig::parseGrouped(const std::string& expression, std::string* error) {
    groupedTerms.clear();
    groupedExpression = expression;

    auto fail = [&](const std::string& message) {
        if (error)
            *error = message;
        groupedTerms.clear();
        return false;
    };

    auto expr = trimCopy(expression);
    if (expr.empty())
        return fail("grouped expression is empty");

    std::stringstream ss(expr);
    std::string rawTerm;
    size_t termIndex = 0;
    while (std::getline(ss, rawTerm, ';')) {
        auto termText = trimCopy(rawTerm);
        if (termText.empty())
            continue;
        ++termIndex;

        auto atPos = termText.rfind('@');
        if (atPos == std::string::npos)
            return fail("missing @offset in grouped term " + std::to_string(termIndex));

        auto lhs = trimCopy(termText.substr(0, atPos));
        auto offsetToken = trimCopy(termText.substr(atPos + 1));
        size_t offset = 0;
        if (!parseSizeToken(offsetToken, offset))
            return fail("invalid offset in grouped term " + std::to_string(termIndex));

        auto colonPos = lhs.find(':');
        if (colonPos == std::string::npos)
            return fail("missing type:value in grouped term " + std::to_string(termIndex));

        auto typeToken = lowerCopy(trimCopy(lhs.substr(0, colonPos)));
        auto valueToken = trimCopy(lhs.substr(colonPos + 1));
        if (valueToken.empty())
            return fail("missing value in grouped term " + std::to_string(termIndex));

        GroupedTerm term;
        term.offset = offset;

        if (typeToken == "byte" || typeToken == "i8" || typeToken == "int8" || typeToken == "1") {
            term.valueType = ValueType::Byte;
            if (!parseInt64Token(valueToken, term.intValue))
                return fail("invalid byte value in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "i16" || typeToken == "int16" || typeToken == "short" || typeToken == "word" || typeToken == "2") {
            term.valueType = ValueType::Int16;
            if (!parseInt64Token(valueToken, term.intValue))
                return fail("invalid i16 value in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "i32" || typeToken == "int32" || typeToken == "dword" || typeToken == "int" || typeToken == "4") {
            term.valueType = ValueType::Int32;
            if (!parseInt64Token(valueToken, term.intValue))
                return fail("invalid i32 value in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "i64" || typeToken == "int64" || typeToken == "long" || typeToken == "qword" || typeToken == "8") {
            term.valueType = ValueType::Int64;
            if (!parseInt64Token(valueToken, term.intValue))
                return fail("invalid i64 value in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "pointer" || typeToken == "ptr") {
            term.valueType = ValueType::Pointer;
            if (!parseInt64Token(valueToken, term.intValue))
                return fail("invalid pointer value in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "float" || typeToken == "single") {
            term.valueType = ValueType::Float;
            if (!parseDoubleToken(valueToken, term.floatValue))
                return fail("invalid float value in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "double") {
            term.valueType = ValueType::Double;
            if (!parseDoubleToken(valueToken, term.floatValue))
                return fail("invalid double value in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "string" || typeToken == "str") {
            term.valueType = ValueType::String;
            term.stringValue = unquoteCopy(valueToken);
            if (term.stringValue.empty())
                return fail("empty string in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "unicode" || typeToken == "utf16" || typeToken == "wstring") {
            term.valueType = ValueType::UnicodeString;
            term.stringValue = unquoteCopy(valueToken);
            if (term.stringValue.empty())
                return fail("empty unicode string in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "aob" || typeToken == "bytearray") {
            term.valueType = ValueType::ByteArray;
            ScanConfig temp;
            temp.parseAOB(valueToken);
            term.byteArray = std::move(temp.byteArray);
            term.byteArrayMask = std::move(temp.byteArrayMask);
            if (term.byteArray.empty())
                return fail("empty AOB pattern in grouped term " + std::to_string(termIndex));
        } else if (typeToken == "binary" || typeToken == "bin") {
            term.valueType = ValueType::Binary;
            ScanConfig temp;
            temp.parseBinary(valueToken);
            term.byteArray = std::move(temp.byteArray);
            term.byteMask = std::move(temp.byteMask);
            term.byteArrayMask = std::move(temp.byteArrayMask);
            if (term.byteArray.empty())
                return fail("empty binary pattern in grouped term " + std::to_string(termIndex));
        } else {
            return fail("unknown grouped value type '" + typeToken + "' in term " + std::to_string(termIndex));
        }

        size_t termSize = groupedTermValueSize(term);
        if (termSize == 0)
            return fail("unsupported grouped value type in term " + std::to_string(termIndex));
        if (term.offset > std::numeric_limits<size_t>::max() - termSize)
            return fail("offset overflow in grouped term " + std::to_string(termIndex));

        groupedTerms.push_back(std::move(term));
    }

    if (groupedTerms.empty())
        return fail("grouped expression produced no terms");

    if (error)
        error->clear();
    return true;
}

size_t ScanConfig::groupedValueSize() const {
    size_t blockSize = 0;
    for (const auto& term : groupedTerms) {
        size_t termSize = groupedTermValueSize(term);
        if (termSize == 0) continue;
        if (term.offset > std::numeric_limits<size_t>::max() - termSize)
            return 0;
        blockSize = std::max(blockSize, term.offset + termSize);
    }
    return blockSize;
}

// ── ScanResult ──

ScanResult::ScanResult(const std::filesystem::path& dir) : dir_(dir) {
    auto addrPath = dir / "addresses.bin";
    auto valPath  = dir / "values.bin";
    auto firstValPath = dir / "first_values.bin";

    if (std::filesystem::exists(dir / "shards.txt") || std::filesystem::exists(addrPath)) {
        // Loading existing scan results (read-only mode): either a shards.txt
        // manifest of worker directories, or a single record file.
        loadShards();
        addrFd_ = -1;
        valueFd_ = -1;
        firstValueFd_ = -1;
    } else {
        // Creating new scan results (write mode)
        std::filesystem::create_directories(dir);
        addrFd_ = open(addrPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        valueFd_ = open(valPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        firstValueFd_ = open(firstValPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        addrBuf_.reserve(8192);
        valueBuf_.reserve(8192 * 8);
        firstValueBuf_.reserve(8192 * 8);
    }
}

void ScanResult::loadShards() {
    shards_.clear();
    count_ = 0;
    std::error_code ec;
    auto manifestPath = dir_ / "shards.txt";
    if (std::filesystem::exists(manifestPath, ec)) {
        // Manifest lines: "<count> <shard directory>". The shard directories
        // hold the actual addresses/values/first_values files (written once by
        // the scan workers — never copied into a merged file).
        std::ifstream in(manifestPath);
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            size_t sp = line.find(' ');
            if (sp == std::string::npos) continue;
            size_t c = 0;
            try { c = std::stoull(line.substr(0, sp)); } catch (...) { continue; }
            shards_.push_back({ std::filesystem::path(line.substr(sp + 1)), c, count_ });
            count_ += c;
        }
    } else {
        // Single-file result: this directory is the one shard.
        auto addrPath = dir_ / "addresses.bin";
        if (std::filesystem::exists(addrPath, ec)) {
            size_t bytes = std::filesystem::file_size(addrPath, ec);
            size_t c = ec ? 0 : bytes / sizeof(uintptr_t);
            shards_.push_back({ dir_, c, 0 });
            count_ = c;
        }
    }
}

const ScanResult::Shard* ScanResult::shardAt(size_t i) const {
    // Few shards (one per scan worker), so a linear walk is fine.
    for (const auto& s : shards_)
        if (i >= s.cum && i < s.cum + s.count) return &s;
    return nullptr;
}

std::vector<ScanResult::ShardInfo> ScanResult::shardLayout() const {
    std::vector<ShardInfo> out;
    if (!shards_.empty()) {
        out.reserve(shards_.size());
        for (const auto& s : shards_) out.push_back({ s.dir, s.count });
    } else if (count_ > 0) {
        // A write-mode result read before finalize (not expected in practice).
        out.push_back({ dir_, count_ });
    }
    return out;
}

size_t ScanResult::recordStride() const {
    auto strideOf = [](const std::filesystem::path& d, size_t cnt) -> size_t {
        if (cnt == 0) return 0;
        std::error_code ec;
        auto vb = std::filesystem::file_size(d / "values.bin", ec);
        return (ec || vb == 0) ? 0 : vb / cnt;
    };
    for (const auto& s : shards_)
        if (size_t st = strideOf(s.dir, s.count)) return st;
    if (shards_.empty())
        return strideOf(dir_, count_);
    return 0;
}

void ScanResult::addResult(uintptr_t addr, const void* value, size_t valueSize) {
    addResult(addr, value, value, valueSize);
}

void ScanResult::addResult(uintptr_t addr, const void* value, const void* firstValue, size_t valueSize) {
    addrBuf_.push_back(addr);
    // insert() copies the bytes once; resize()+memcpy would first zero-fill the
    // new region and then overwrite it, a wasted write per matched byte, which
    // adds up for dense scans emitting millions of results.
    const auto* v  = static_cast<const uint8_t*>(value);
    const auto* fv = static_cast<const uint8_t*>(firstValue);
    valueBuf_.insert(valueBuf_.end(), v, v + valueSize);
    firstValueBuf_.insert(firstValueBuf_.end(), fv, fv + valueSize);
    valueSize_ = valueSize;
    ++count_;

    if (addrBuf_.size() >= 8192)
        flush();
}

// Write all `len` bytes, retrying on EINTR and short writes. A bare ::write can
// return fewer bytes than requested (signal, nearly-full disk); if that happened
// on the addresses file but not the values file, the two would end at mismatched
// lengths and every result past that point would pair the wrong address+value.
static bool writeAll(int fd, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    while (len > 0) {
        ssize_t n = ::write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return false; }
        if (n == 0) return false;
        p += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

// Assemble a sharded result: write a shards.txt manifest under `mergedDir`
// referencing each worker's directory in worker order (which is address order,
// since each worker owns a contiguous ascending slice), WITHOUT copying the
// record files. The old design concatenated every worker file into one merged
// file, doubling result-data disk traffic; here the worker files ARE the result.
// Any worker's write-error flag is propagated. Shared by firstScan/nextScan.
static ScanResult assembleShardedResult(const std::filesystem::path& mergedDir,
                                        std::vector<ScanResult>& parts) {
    std::filesystem::create_directories(mergedDir);
    int fd = open((mergedDir / "shards.txt").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    bool writeError = (fd < 0);
    if (fd >= 0) {
        for (auto& tr : parts) {
            if (tr.hasWriteError()) writeError = true;
            std::string line = std::to_string(tr.count()) + " " + tr.directory().string() + "\n";
            if (!writeAll(fd, line.data(), line.size())) writeError = true;
        }
        close(fd);
    }
    ScanResult merged(mergedDir); // loads the manifest (read mode)
    if (writeError) merged.markWriteError();
    return merged;
}

// Reads a global record range from a (possibly sharded) previous result. Each
// nextScan worker builds its own so positional reads don't share a file offset.
// Holds every shard's three files open (few shards → few fds).
struct ShardReader {
    struct S { int afd = -1, vfd = -1, ffd = -1; size_t count = 0, cum = 0; };
    std::vector<S> shards;
    bool ok = true;

    explicit ShardReader(const std::vector<ScanResult::ShardInfo>& layout) {
        size_t cum = 0;
        for (const auto& si : layout) {
            S s;
            s.count = si.count;
            s.cum = cum;
            cum += si.count;
            s.afd = open((si.dir / "addresses.bin").c_str(), O_RDONLY);
            s.vfd = open((si.dir / "values.bin").c_str(), O_RDONLY);
            s.ffd = open((si.dir / "first_values.bin").c_str(), O_RDONLY);
            if (s.afd < 0 || s.vfd < 0) ok = false;
            shards.push_back(s);
        }
    }
    ~ShardReader() {
        for (auto& s : shards) {
            if (s.afd >= 0) close(s.afd);
            if (s.vfd >= 0) close(s.vfd);
            if (s.ffd >= 0) close(s.ffd);
        }
    }
    ShardReader(const ShardReader&) = delete;
    ShardReader& operator=(const ShardReader&) = delete;

    // Read n records at global [begin, begin+n) into the buffers (addresses +
    // old values + first values), spanning shard boundaries as needed. Where a
    // shard has no first_values.bin, first values fall back to the old values.
    // Returns true iff every read succeeded.
    bool read(size_t begin, size_t n, uintptr_t* addrs, uint8_t* oldVals,
              uint8_t* firstVals, size_t valueSize) {
        size_t got = 0;
        while (got < n) {
            size_t gi = begin + got;
            S* sh = nullptr;
            for (auto& s : shards)
                if (gi >= s.cum && gi < s.cum + s.count) { sh = &s; break; }
            if (!sh) return false;
            size_t local = gi - sh->cum;
            size_t take = std::min(sh->count - local, n - got);
            if (!preadFull(sh->afd, addrs + got, take * sizeof(uintptr_t),
                           (off_t)(local * sizeof(uintptr_t))))
                return false;
            if (!preadFull(sh->vfd, oldVals + got * valueSize, take * valueSize,
                           (off_t)(local * valueSize)))
                return false;
            if (sh->ffd < 0 ||
                !preadFull(sh->ffd, firstVals + got * valueSize, take * valueSize,
                           (off_t)(local * valueSize)))
                std::memcpy(firstVals + got * valueSize, oldVals + got * valueSize, take * valueSize);
            got += take;
        }
        return true;
    }
};

// One next-scan predicate for one address: does the freshly-read `currentVal`
// still match, given the previous scan's `oldVal` and the first scan's
// `firstVal`? Pulled out of nextScan so the single- and multi-threaded paths
// share exactly one copy of the comparison logic. Needles are precomputed once
// by the caller; `customEval` is per-thread (lua_State is not thread-safe).
static bool nextScanCompare(const ScanConfig& config, size_t valueSize,
                            const uint8_t* currentVal, const uint8_t* oldVal,
                            const uint8_t* firstVal,
                            const std::vector<uint8_t>& stringNeedle,
                            const std::vector<uint8_t>& unicodeNeedle,
                            CustomFormulaEvaluator& customEval) {
    const uint8_t* compareVal =
        config.compareType == ScanCompare::SameAsFirst ? firstVal : oldVal;
    bool match = false;
    switch (config.valueType) {
        case ValueType::Byte:
            match = compareNextNumeric<uint8_t>(config, currentVal, compareVal); break;
        case ValueType::Int16:
            match = compareNextNumeric<int16_t>(config, currentVal, compareVal); break;
        case ValueType::Int32:
            match = compareNextNumeric<int32_t>(config, currentVal, compareVal); break;
        case ValueType::Int64:
            match = compareNextNumeric<int64_t>(config, currentVal, compareVal); break;
        case ValueType::Pointer:
            match = compareNextNumeric<uintptr_t>(config, currentVal, compareVal); break;
        case ValueType::Float:
            match = compareNextNumeric<float>(config, currentVal, compareVal); break;
        case ValueType::Double:
            match = compareNextNumeric<double>(config, currentVal, compareVal); break;
        case ValueType::String: {
            if (config.compareType == ScanCompare::SameAsFirst)
                match = std::memcmp(currentVal, firstVal, valueSize) == 0;
            else if (config.compareType >= ScanCompare::Changed)
                match = (std::memcmp(currentVal, oldVal, valueSize) != 0) ==
                        (config.compareType == ScanCompare::Changed ||
                         config.compareType == ScanCompare::Increased ||
                         config.compareType == ScanCompare::Decreased);
            else if (config.compareType == ScanCompare::Exact)
                match = stringNeedle.size() == valueSize &&
                        std::memcmp(currentVal, stringNeedle.data(), valueSize) == 0;
            else if (config.compareType == ScanCompare::Unknown)
                match = true;
            break;
        }
        case ValueType::UnicodeString: {
            if (config.compareType == ScanCompare::SameAsFirst)
                match = std::memcmp(currentVal, firstVal, valueSize) == 0;
            else if (config.compareType >= ScanCompare::Changed)
                match = (std::memcmp(currentVal, oldVal, valueSize) != 0) ==
                        (config.compareType == ScanCompare::Changed ||
                         config.compareType == ScanCompare::Increased ||
                         config.compareType == ScanCompare::Decreased);
            else if (config.compareType == ScanCompare::Exact)
                match = unicodeNeedle.size() == valueSize &&
                        std::memcmp(currentVal, unicodeNeedle.data(), valueSize) == 0;
            else if (config.compareType == ScanCompare::Unknown)
                match = true;
            break;
        }
        case ValueType::ByteArray:
            if (config.compareType == ScanCompare::SameAsFirst)
                match = std::memcmp(currentVal, firstVal, valueSize) == 0;
            else if (config.compareType >= ScanCompare::Changed)
                match = (std::memcmp(currentVal, oldVal, valueSize) != 0) ==
                        (config.compareType == ScanCompare::Changed ||
                         config.compareType == ScanCompare::Increased ||
                         config.compareType == ScanCompare::Decreased);
            else if (config.compareType == ScanCompare::Exact)
                match = compareMaskedBytes(currentVal, config.byteArray, config.byteArrayMask);
            else if (config.compareType == ScanCompare::Unknown)
                match = true;
            break;
        case ValueType::Binary:
            if (config.compareType == ScanCompare::SameAsFirst)
                match = std::memcmp(currentVal, firstVal, valueSize) == 0;
            else if (config.compareType >= ScanCompare::Changed)
                match = (std::memcmp(currentVal, oldVal, valueSize) != 0) ==
                        (config.compareType == ScanCompare::Changed ||
                         config.compareType == ScanCompare::Increased ||
                         config.compareType == ScanCompare::Decreased);
            else if (config.compareType == ScanCompare::Exact) {
                match = !config.byteArray.empty() &&
                        config.byteMask.size() == config.byteArray.size();
                for (size_t j = 0; match && j < config.byteArray.size(); ++j)
                    if ((currentVal[j] & config.byteMask[j]) !=
                        (config.byteArray[j] & config.byteMask[j]))
                        match = false;
            } else if (config.compareType == ScanCompare::Unknown)
                match = true;
            break;
        case ValueType::Grouped:
            if (config.compareType == ScanCompare::Unknown)
                match = true;
            else if (config.compareType == ScanCompare::Changed)
                match = std::memcmp(currentVal, oldVal, valueSize) != 0;
            else if (config.compareType == ScanCompare::Unchanged ||
                     config.compareType == ScanCompare::SameAsFirst)
                match = std::memcmp(currentVal, compareVal, valueSize) == 0;
            else if (config.compareType == ScanCompare::Exact)
                match = groupedBlockMatches(currentVal, valueSize, config);
            break;
        case ValueType::Custom:
            if (config.compareType == ScanCompare::Unknown)
                match = true;
            else if (config.compareType == ScanCompare::Changed)
                match = std::memcmp(currentVal, oldVal, valueSize) != 0;
            else if (config.compareType == ScanCompare::Unchanged ||
                     config.compareType == ScanCompare::SameAsFirst)
                match = std::memcmp(currentVal, compareVal, valueSize) == 0;
            else if (config.compareType == ScanCompare::Exact)
                customEval.eval(currentVal, compareVal, valueSize, true, match);
            break;
        default:
            if (config.compareType == ScanCompare::SameAsFirst)
                match = std::memcmp(currentVal, firstVal, valueSize) == 0;
            else
                match = (std::memcmp(currentVal, oldVal, valueSize) != 0) ==
                        (config.compareType == ScanCompare::Changed);
            break;
    }
    return match;
}

void ScanResult::flush() {
    if (addrBuf_.empty()) return;
    // A short/failed write (e.g. ENOSPC) truncates the backing file below count_,
    // so mark the result unreliable rather than silently reading back zeroes later.
    if (addrFd_ >= 0 && !writeAll(addrFd_, addrBuf_.data(), addrBuf_.size() * sizeof(uintptr_t)))
        writeError_ = true;
    if (valueFd_ >= 0 && !writeAll(valueFd_, valueBuf_.data(), valueBuf_.size()))
        writeError_ = true;
    if (firstValueFd_ >= 0 && !writeAll(firstValueFd_, firstValueBuf_.data(), firstValueBuf_.size()))
        writeError_ = true;
    addrBuf_.clear();
    valueBuf_.clear();
    firstValueBuf_.clear();
}

void ScanResult::finalize() {
    flush();
    if (addrFd_ >= 0) { close(addrFd_); addrFd_ = -1; }
    if (valueFd_ >= 0) { close(valueFd_); valueFd_ = -1; }
    if (firstValueFd_ >= 0) { close(firstValueFd_); firstValueFd_ = -1; }
    // A written result is a single implicit shard (its own directory), so the
    // read paths below work the same whether it came straight from a scan or was
    // reconstructed from disk.
    shards_.assign(1, Shard{ dir_, count_, 0 });
}

uintptr_t ScanResult::address(size_t i) const {
    const Shard* s = shardAt(i);
    if (!s) return 0;
    uintptr_t addr = 0;
    int fd = open((s->dir / "addresses.bin").c_str(), O_RDONLY);
    if (fd < 0) return 0;
    if (!preadFull(fd, &addr, sizeof(addr), (i - s->cum) * sizeof(uintptr_t)))
        addr = 0;
    close(fd);
    return addr;
}

void ScanResult::value(size_t i, void* buf, size_t valueSize) const {
    const Shard* s = shardAt(i);
    if (!s) return;
    int fd = open((s->dir / "values.bin").c_str(), O_RDONLY);
    if (fd < 0) return;
    if (!preadFull(fd, buf, valueSize, (i - s->cum) * valueSize))
        std::memset(buf, 0, valueSize);
    close(fd);
}

void ScanResult::firstValue(size_t i, void* buf, size_t valueSize) const {
    const Shard* s = shardAt(i);
    if (!s) return;
    int fd = open((s->dir / "first_values.bin").c_str(), O_RDONLY);
    if (fd < 0) {
        value(i, buf, valueSize);
        return;
    }
    if (!preadFull(fd, buf, valueSize, (i - s->cum) * valueSize))
        std::memset(buf, 0, valueSize);
    close(fd);
}

void ScanResult::forEach(std::function<void(uintptr_t, const void*, size_t)> callback, size_t valueSize) const {
    constexpr size_t BATCH = 4096;
    std::vector<uintptr_t> addrs(BATCH);
    std::vector<uint8_t> vals(BATCH * valueSize);

    // Stream each shard in address order.
    for (const auto& s : shards_) {
        if (s.count == 0) continue;
        int afd = open((s.dir / "addresses.bin").c_str(), O_RDONLY);
        int vfd = open((s.dir / "values.bin").c_str(), O_RDONLY);
        if (afd < 0 || vfd < 0) {
            if (afd >= 0) close(afd);
            if (vfd >= 0) close(vfd);
            continue; // skip an unreadable shard rather than aborting the rest
        }
        size_t remaining = s.count;
        while (remaining > 0) {
            size_t n = std::min(remaining, BATCH);
            // A short/truncated read here would pair addresses with the wrong
            // values; treat this shard's files as truncated and stop it.
            if (!readFull(afd, addrs.data(), n * sizeof(uintptr_t)) ||
                !readFull(vfd, vals.data(), n * valueSize))
                break;
            for (size_t i = 0; i < n; ++i)
                callback(addrs[i], vals.data() + i * valueSize, valueSize);
            remaining -= n;
        }
        close(afd);
        close(vfd);
    }
}

// ── MemoryScanner ──

MemoryScanner::MemoryScanner(int threadCount)
    : threadCount_(threadCount > 0 ? threadCount : std::thread::hardware_concurrency())
{
    if (threadCount_ < 1) threadCount_ = 1;
}

static std::atomic<uint64_t> scanCounter{0};

static std::filesystem::path makeScanDir() {
    return std::filesystem::temp_directory_path() / "ce-scan" /
           ("scan-" + std::to_string(getpid()) + "-" + std::to_string(scanCounter.fetch_add(1)));
}

ScanResult MemoryScanner::firstScan(ProcessHandle& proc, const ScanConfig& config) {
    cancelled_.store(false);
    progress_.store(0);

    if (config.valueType == ValueType::Grouped) {
        if (config.groupedTerms.empty())
            throw std::invalid_argument("ValueType::Grouped requires grouped terms (use parseGrouped)");
        if (config.groupedValueSize() == 0)
            throw std::invalid_argument("ValueType::Grouped has invalid grouped terms");
        if (config.compareType != ScanCompare::Exact && config.compareType != ScanCompare::Unknown)
            throw std::invalid_argument("ValueType::Grouped first scan supports only Exact or Unknown compare");
    }

    if (config.valueType == ValueType::Custom) {
        if (config.customValueSize == 0)
            throw std::invalid_argument("ValueType::Custom requires customValueSize > 0");
        if (config.compareType == ScanCompare::Exact && config.customFormula.empty())
            throw std::invalid_argument("ValueType::Custom exact scan requires customFormula");
        if (config.compareType != ScanCompare::Exact && config.compareType != ScanCompare::Unknown)
            throw std::invalid_argument("ValueType::Custom first scan supports only Exact or Unknown compare");
    }

    // Get memory regions
    auto regions = proc.queryRegions();

    // Filter regions
    std::vector<MemoryRegion> scanRegions;
    for (auto& r : regions) {
        if (r.state != MemState::Committed) continue;
        if (!(r.protection & MemProt::Read)) continue;
        if (config.scanWritableOnly && !(r.protection & MemProt::Write)) continue;
        if (config.scanExecutableOnly && !(r.protection & MemProt::Exec)) continue;
        if (!memoryTypeAllowed(config, r.type)) continue;

        uintptr_t regionEnd = std::numeric_limits<uintptr_t>::max() - r.base < r.size
            ? std::numeric_limits<uintptr_t>::max()
            : r.base + r.size;
        uintptr_t scanStart = std::max(r.base, config.startAddress);
        uintptr_t scanEnd = std::min(regionEnd, config.stopAddress);
        if (scanEnd <= scanStart) continue;

        MemoryRegion clipped = r;
        clipped.base = scanStart;
        clipped.size = scanEnd - scanStart;
        scanRegions.push_back(clipped);
    }

    auto resultDir = makeScanDir();

    size_t totalMem = 0;
    for (auto& r : scanRegions) totalMem += r.size;
    if (totalMem == 0) { ScanResult empty(resultDir / "results"); empty.finalize(); return empty; }

    // Scan dispatch lambda (reused by each thread). `customEval` is a
    // per-thread evaluator for ValueType::Custom (null for other types).
    auto scanRegion = [&](const uint8_t* buf, size_t bytesRead, uintptr_t base,
                          ScanResult& res, CustomFormulaEvaluator* customEval,
                          size_t emitLimit) {
        switch (config.valueType) {
            case ValueType::Byte:
                scanIntegerFast<uint8_t>(buf, bytesRead, base, config.alignment,
                    (uint8_t)config.intValue, (uint8_t)config.intValue2, config.compareType, res); break;
            case ValueType::Int16:
                scanIntegerFast<int16_t>(buf, bytesRead, base, config.alignment,
                    (int16_t)config.intValue, (int16_t)config.intValue2, config.compareType, res); break;
            case ValueType::Int32:
                scanIntegerFast<int32_t>(buf, bytesRead, base, config.alignment,
                    (int32_t)config.intValue, (int32_t)config.intValue2, config.compareType, res); break;
            case ValueType::Int64:
                scanIntegerFast<int64_t>(buf, bytesRead, base, config.alignment,
                    config.intValue, config.intValue2, config.compareType, res); break;
            case ValueType::Pointer:
                scanIntegerFast<uintptr_t>(buf, bytesRead, base, config.alignment,
                    static_cast<uintptr_t>(config.intValue), static_cast<uintptr_t>(config.intValue2),
                    config.compareType, res); break;
            case ValueType::Float:
                if (!tryScanExactFloat<float>(buf, bytesRead, base, config.alignment, config, res))
                    scanBufferFloating<float>(buf, bytesRead, base, config.alignment, config, res);
                break;
            case ValueType::Double:
                if (!tryScanExactFloat<double>(buf, bytesRead, base, config.alignment, config, res))
                    scanBufferFloating<double>(buf, bytesRead, base, config.alignment, config, res);
                break;
            case ValueType::String:
                scanBufferString(buf, bytesRead, base,
                    encodeStringBytes(config.stringValue, config.stringEncoding), res,
                    !config.caseSensitive); break;
            case ValueType::UnicodeString:
                scanBufferUnicode(buf, bytesRead, base, config.stringValue, res,
                    !config.caseSensitive); break;
            case ValueType::ByteArray:
                scanBufferAOB(buf, bytesRead, base, config.byteArray, config.byteArrayMask, res); break;
            case ValueType::Binary: {
                scanBufferBinary(buf, bytesRead, base, config.byteArray, config.byteMask, config.alignment, res);
                break;
            }
            case ValueType::All:
                scanBufferAllTypes(buf, bytesRead, base, config.alignment,
                    config.intValue, config.floatValue, config.compareType, res, emitLimit); break;
            case ValueType::Grouped:
                if (config.compareType == ScanCompare::Unknown)
                    scanBufferUnknown(buf, bytesRead, base, config.alignment, config.groupedValueSize(), res);
                else
                    scanBufferGrouped(buf, bytesRead, base, config.alignment, config, res);
                break;
            case ValueType::Custom: {
                size_t customSize = std::max<size_t>(1, config.customValueSize);
                if (bytesRead < customSize) break;
                size_t limit = bytesRead - customSize + 1;
                size_t alignment = std::max<size_t>(1, config.alignment);
                for (size_t offset = 0; offset < limit; offset += alignment) {
                    if (config.compareType == ScanCompare::Unknown) {
                        res.addResult(base + offset, buf + offset, customSize);
                        continue;
                    }
                    bool match = false;
                    if (customEval &&
                        customEval->eval(buf + offset, buf + offset, customSize, false, match) && match)
                        res.addResult(base + offset, buf + offset, customSize);
                }
                break;
            }
            default: break;
        }
    };

    // Split every region into fixed-size chunks, then hand each thread a
    // contiguous run of chunks. Splitting means one huge region (a common case:
    // a game's main heap can be the bulk of scanned memory) is shared across all
    // threads instead of pinning a single core (the old per-region split left a
    // process with one big region single-threaded). A contiguous run per thread
    // keeps each thread's output address-ordered, so concatenating thread files
    // in order still yields a globally sorted result (nextScan relies on nothing
    // here, but the GUI shows results in address order).
    //
    // Each chunk "owns" `owned` start positions and reads an extra `overlap`
    // (maxMatchSize-1) lookahead bytes so a value straddling the chunk boundary
    // is fully readable and is emitted exactly once (by the chunk that owns its
    // start). `owned` is a multiple of alignment so the scan stride grid is
    // preserved across boundaries, so there are no duplicates and no gaps.
    constexpr size_t kChunkBytes = 8u * 1024 * 1024; // per-chunk owned span
    size_t alignment = std::max<size_t>(1, config.alignment);
    size_t maxMatchSize = std::max<size_t>(1, valueSizeForConfig(config));
    size_t overlap = maxMatchSize - 1;
    size_t ownedLen = (kChunkBytes / alignment) * alignment;
    if (ownedLen == 0) ownedLen = alignment;

    struct Chunk { uintptr_t base; size_t owned; size_t readLen; };
    std::vector<Chunk> chunks;
    chunks.reserve(totalMem / ownedLen + scanRegions.size());
    for (const auto& region : scanRegions) {
        for (size_t ws = 0; ws < region.size; ws += ownedLen) {
            size_t owned   = std::min(ownedLen, region.size - ws);
            size_t readLen = std::min(ownedLen + overlap, region.size - ws);
            chunks.push_back({ region.base + ws, owned, readLen });
        }
    }

    // Only fan out across cores when the handle tolerates concurrent reads
    // (process_vm_readv does; a socket-backed ceserver handle does not).
    int maxThreads = proc.supportsConcurrentReads() ? threadCount_ : 1;
    int nThreads = std::min(maxThreads, std::max<int>(1, (int)chunks.size()));

    // Partition chunk indices into nThreads contiguous runs of ~equal owned
    // bytes (chunks are uniform except region tails, so this balances well).
    std::vector<size_t> chunkBegin(nThreads), chunkEnd(nThreads);
    {
        size_t perThread = (totalMem + nThreads - 1) / nThreads; // ceil
        if (perThread == 0) perThread = 1;
        size_t ci = 0;
        for (int t = 0; t < nThreads; ++t) {
            chunkBegin[t] = ci;
            size_t acc = 0;
            while (ci < chunks.size() && (acc < perThread || t == nThreads - 1)) {
                acc += chunks[ci].owned;
                ++ci;
            }
            chunkEnd[t] = ci;
        }
    }

    // Launch threads; each writes to its own ScanResult
    std::vector<ScanResult> threadResults;
    threadResults.reserve(nThreads);
    for (int t = 0; t < nThreads; ++t)
        threadResults.emplace_back(resultDir / ("t" + std::to_string(t)));

    std::atomic<size_t> scannedBytes{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < nThreads; ++t) {
        threads.emplace_back([&, t]() {
            auto& res = threadResults[t];
            try {
                std::vector<uint8_t> buf;
                // One Lua evaluator per worker (lua_State is not thread-safe);
                // the formula is compiled once and reused across all offsets.
                CustomFormulaEvaluator customEval(config.valueType == ValueType::Custom
                                                  ? config.customFormula : std::string{});
                for (size_t ci = chunkBegin[t];
                     ci < chunkEnd[t] && !cancelled_.load(std::memory_order_relaxed); ++ci) {
                    const Chunk& c = chunks[ci];
                    buf.resize(c.readLen);
                    auto readResult = proc.read(c.base, buf.data(), c.readLen);
                    size_t bytesRead = (readResult && *readResult > 0) ? *readResult : 0;
                    if (bytesRead == 0) continue;
                    // Owned start positions: everything up to `owned`; the
                    // trailing bytes are overlap lookahead only.
                    size_t emitLimit = std::min<size_t>(bytesRead, c.owned);
                    scanRegion(buf.data(), bytesRead, c.base, res, &customEval, emitLimit);
                    // Don't double-count the overlap lookahead in progress.
                    scannedBytes.fetch_add(std::min(bytesRead, c.owned), std::memory_order_relaxed);
                    progress_.store((float)scannedBytes.load(std::memory_order_relaxed) / totalMem, std::memory_order_relaxed);
                }
            } catch (...) {
                // A failed worker (e.g. bad_alloc on an unexpectedly large
                // window) must not escape the thread function (that calls
                // std::terminate); degrade gracefully and let other threads
                // finish. TODO(security): surface per-worker read/alloc errors
                // to the caller instead of silently producing a partial result.
                (void)0;
            }
            res.finalize();
        });
    }

    for (auto& t : threads) t.join();
    progress_.store(1.0f);

    // Reference the worker files in place (in address order) — no merge copy.
    return assembleShardedResult(resultDir / "results", threadResults);
}

ScanResult MemoryScanner::nextScan(ProcessHandle& proc, const ScanConfig& config, const ScanResult& previous) {
    cancelled_.store(false);
    progress_.store(0);

    if (config.valueType == ValueType::Grouped) {
        if (config.groupedTerms.empty())
            throw std::invalid_argument("ValueType::Grouped requires grouped terms (use parseGrouped)");
        if (config.groupedValueSize() == 0)
            throw std::invalid_argument("ValueType::Grouped has invalid grouped terms");
        if (config.compareType != ScanCompare::Exact &&
            config.compareType != ScanCompare::Changed &&
            config.compareType != ScanCompare::Unchanged &&
            config.compareType != ScanCompare::SameAsFirst &&
            config.compareType != ScanCompare::Unknown) {
            throw std::invalid_argument("ValueType::Grouped next scan supports exact/changed/unchanged/samefirst/unknown");
        }
    }

    if (config.valueType == ValueType::Custom) {
        if (config.customValueSize == 0)
            throw std::invalid_argument("ValueType::Custom requires customValueSize > 0");
        if (config.compareType == ScanCompare::Exact && config.customFormula.empty())
            throw std::invalid_argument("ValueType::Custom exact next scan requires customFormula");
        if (config.compareType != ScanCompare::Exact &&
            config.compareType != ScanCompare::Changed &&
            config.compareType != ScanCompare::Unchanged &&
            config.compareType != ScanCompare::SameAsFirst &&
            config.compareType != ScanCompare::Unknown) {
            throw std::invalid_argument("ValueType::Custom next scan supports exact/changed/unchanged/samefirst/unknown");
        }
    }

    size_t valueSize = valueSizeForConfig(config);
    // The persisted addresses/values/first-values streams were written at the
    // previous scan's record size. If the current config yields a different
    // size (e.g. a variable-length string re-scan with a changed length), the
    // valueSize stride would desync the value streams and pair addresses with
    // the wrong bytes. Reject rather than silently produce wrong matches.
    // (For fixed-width types the two sizes always agree, so this never fires.)
    //
    // Derive the previous stride from a shard's actual values.bin size rather
    // than ScanResult::valueSize(): a scan returns a result reconstructed from
    // files, so its in-memory valueSize_ is 0 and can't be trusted here.
    if (previous.count() > 0) {
        size_t prevStride = previous.recordStride();
        if (prevStride != 0 && prevStride != valueSize) {
            throw std::invalid_argument(
                "next scan value size differs from the previous scan; "
                "the search length must stay constant across scans");
        }
    }
    // Precompute the exact-match needles once for the whole scan (not per address).
    std::vector<uint8_t> stringNeedle;
    if (config.valueType == ValueType::String && config.compareType == ScanCompare::Exact)
        stringNeedle = encodeStringBytes(config.stringValue, config.stringEncoding);
    std::vector<uint8_t> unicodeNeedle;
    if (config.valueType == ValueType::UnicodeString)
        unicodeNeedle = utf16LeBytes(config.stringValue);

    auto resultDir = makeScanDir();
    size_t total = previous.count();
    if (total == 0) {
        ScanResult empty(resultDir / "results");
        empty.finalize();
        return empty;
    }

    // The previous result may be split across worker shards; the reader hides
    // that and serves any global index range (see ShardReader).
    auto layout = previous.shardLayout();

    constexpr size_t BATCH = 4096;
    // Small result sets stay single-threaded: once reads are batched, spinning
    // up per-worker result files costs more than the scan. Big sets fan out:
    // each worker owns a contiguous, ascending index slice read positionally
    // (pread) with no shared file offset, and referencing worker files in order
    // keeps the output sorted.
    constexpr size_t kMTFloor = 1u << 16; // 65536 results
    int nThreads = (total < kMTFloor || !proc.supportsConcurrentReads())
                       ? 1 : std::max(1, threadCount_);
    nThreads = std::min<int>(nThreads, std::max<size_t>(1, total / BATCH));
    if (nThreads < 1) nThreads = 1;

    std::atomic<size_t> processed{0};

    // Scan one previous-result index range [begin,end); write matches to `res`
    // (a per-worker ScanResult, so the hot path needs no locking).
    auto worker = [&](size_t begin, size_t end, ScanResult& res) {
        ShardReader reader(layout); // own fds → positional reads don't collide
        if (!reader.ok) {
            res.finalize();
            return;
        }
        // One Lua evaluator per worker (lua_State is not thread-safe).
        CustomFormulaEvaluator customEval(config.valueType == ValueType::Custom
                                          ? config.customFormula : std::string{});
        std::vector<uintptr_t> addrs(BATCH);
        std::vector<uint8_t> oldVals(BATCH * valueSize);
        std::vector<uint8_t> firstVals(BATCH * valueSize);
        // Batched current-value reads: one process_vm_readv per batch (see
        // ProcessHandle::readMany) instead of a syscall per address, into a
        // reused buffer instead of a per-address heap allocation.
        std::vector<uint8_t> curVals(BATCH * valueSize);
        std::vector<uint8_t> okFlags(BATCH);

        for (size_t idx = begin; idx < end && !cancelled_.load(std::memory_order_relaxed); ) {
            size_t n = std::min(BATCH, end - idx);
            // Read this slice's addresses/old-values/first-values across shards.
            // A short/interrupted read would desync the streams or feed garbage
            // addresses into readMany; on truncation stop rather than emit wrong
            // matches.
            if (!reader.read(idx, n, addrs.data(), oldVals.data(), firstVals.data(), valueSize))
                break;

            proc.readMany(addrs.data(), n, valueSize, curVals.data(), okFlags.data());

            for (size_t i = 0; i < n; ++i) {
                if (!okFlags[i]) continue; // address unreadable this pass -> drop it
                const uint8_t* currentVal = curVals.data() + i * valueSize;
                const uint8_t* oldVal     = oldVals.data() + i * valueSize;
                const uint8_t* firstVal   = firstVals.data() + i * valueSize;
                if (nextScanCompare(config, valueSize, currentVal, oldVal, firstVal,
                                    stringNeedle, unicodeNeedle, customEval))
                    res.addResult(addrs[i], currentVal, firstVal, valueSize);
            }

            idx += n;
            size_t done = processed.fetch_add(n, std::memory_order_relaxed) + n;
            progress_.store((float)done / total, std::memory_order_relaxed);
        }

        res.finalize();
    };

    if (nThreads == 1) {
        ScanResult result(resultDir / "results");
        worker(0, total, result);
        return result;
    }

    // Fan out over contiguous, ascending index slices.
    std::vector<ScanResult> parts;
    parts.reserve(nThreads);
    for (int t = 0; t < nThreads; ++t)
        parts.emplace_back(resultDir / ("t" + std::to_string(t)));

    std::vector<std::thread> threads;
    threads.reserve(nThreads);
    size_t per = (total + nThreads - 1) / nThreads; // ceil
    for (int t = 0; t < nThreads; ++t) {
        size_t begin = std::min(total, (size_t)t * per);
        size_t end   = std::min(total, begin + per);
        threads.emplace_back([&, begin, end, t]() { worker(begin, end, parts[t]); });
    }
    for (auto& th : threads) th.join();

    // Reference the worker files in place (in address order) — no merge copy.
    return assembleShardedResult(resultDir / "results", parts);
}

} // namespace ce
