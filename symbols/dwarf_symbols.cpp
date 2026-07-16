/// DWARF line-table reader. libdw-backed when CECORE_HAVE_DWARF is defined,
/// stub-only otherwise.
///
/// The libdw path uses dwarf_addrdie() to find the compile unit, then
/// dwarf_getsrc_die() to map the address into a Dwarf_Line whose file/lineno
/// we extract. We open the ELF read-only via libdw's `dwarf_begin` (which
/// pulls debug info via libelf internally).
///
/// Note: addresses are passed in runtime form (i.e. moduleBase + offset). We
/// subtract the supplied loadBase before consulting libdw, which deals in
/// link-time addresses for ET_EXEC binaries and offsets for ET_DYN.

#include <elf.h>
#include "symbols/dwarf_symbols.hpp"
#include "platform/process_api.hpp"

#include <functional>
#include <set>

#ifdef CECORE_HAVE_DWARF
extern "C" {
#include <elfutils/libdw.h>
#include <dwarf.h>
#include <fcntl.h>
#include <unistd.h>
}
#include <cstring>
#endif

namespace ce {

#ifdef CECORE_HAVE_DWARF

struct DwarfInfo::Impl {
    int fd = -1;
    Dwarf* dwarf = nullptr;
    uintptr_t loadBase = 0;

    ~Impl() { closeAll(); }

    void closeAll() {
        if (dwarf) { dwarf_end(dwarf); dwarf = nullptr; }
        if (fd >= 0) { ::close(fd); fd = -1; }
    }
};

DwarfInfo::DwarfInfo() : impl_(std::make_unique<Impl>()) {}
DwarfInfo::~DwarfInfo() = default;
DwarfInfo::DwarfInfo(DwarfInfo&&) noexcept = default;
DwarfInfo& DwarfInfo::operator=(DwarfInfo&&) noexcept = default;

bool DwarfInfo::available() { return true; }

bool DwarfInfo::load(const std::string& elfPath, uintptr_t loadBase) {
    impl_->closeAll();
    impl_->fd = ::open(elfPath.c_str(), O_RDONLY);
    if (impl_->fd < 0) return false;
    impl_->dwarf = dwarf_begin(impl_->fd, DWARF_C_READ);
    if (!impl_->dwarf) {
        ::close(impl_->fd);
        impl_->fd = -1;
        return false;
    }
    // dwarf_begin succeeds for any readable ELF, even one without .debug_*
    // sections (split-debug / stripped modules). Without this probe we would
    // pin an fd for every mapped module — tens to hundreds in a real process —
    // risking RLIMIT_NOFILE exhaustion. Confirm at least one compile unit
    // exists before retaining the handle; modules with no DWARF return false
    // (they would have produced zero results anyway via empty CU iteration).
    {
        Dwarf_Off next = 0;
        size_t hsize = 0;
        Dwarf_Off abbrev = 0;
        uint8_t addrsz = 0, offsz = 0;
        if (dwarf_nextcu(impl_->dwarf, 0, &next, &hsize, &abbrev, &addrsz, &offsz) != 0) {
            impl_->closeAll();
            return false;
        }
    }
    // Bias handling depends on the ELF type. For ET_DYN (PIE / shared library)
    // DWARF addresses are link-base-relative (link base 0), so lookup subtracts
    // the runtime load base. For ET_EXEC (-no-pie / classic executables) DWARF
    // addresses are ABSOLUTE and the module loads at its fixed vaddr, so the bias
    // must be 0 — otherwise every lookup subtracts the base and misses. e_type is
    // a 2-byte field at offset 16 in both ELF32 and ELF64 headers.
    uint16_t etype = 0;
    if (::pread(impl_->fd, &etype, sizeof(etype), 16) == (ssize_t)sizeof(etype) &&
        etype == ET_EXEC)
        impl_->loadBase = 0;
    else
        impl_->loadBase = loadBase;
    return true;
}

bool DwarfInfo::isLoaded() const { return impl_ && impl_->dwarf != nullptr; }

void DwarfInfo::close() { if (impl_) impl_->closeAll(); }

std::optional<DwarfSourceLocation> DwarfInfo::lookup(uintptr_t runtimeAddress) const {
    if (!impl_ || !impl_->dwarf) return std::nullopt;
    Dwarf_Addr linkAddr = (runtimeAddress >= impl_->loadBase)
        ? (Dwarf_Addr)(runtimeAddress - impl_->loadBase)
        : (Dwarf_Addr)runtimeAddress;

    Dwarf_Die cuDie;
    if (dwarf_addrdie(impl_->dwarf, linkAddr, &cuDie) == nullptr)
        return std::nullopt;

    Dwarf_Line* line = dwarf_getsrc_die(&cuDie, linkAddr);
    if (!line) return std::nullopt;

    DwarfSourceLocation loc;
    int lineNo = 0, col = 0;
    const char* file = dwarf_linesrc(line, nullptr, nullptr);
    if (file) loc.file = file;
    if (dwarf_lineno(line, &lineNo) == 0) loc.line = lineNo;
    if (dwarf_linecol(line, &col) == 0) loc.column = col;
    // libdw doesn't expose a portable is_stmt accessor; keep the default
    // true. Callers shouldn't rely on this distinction yet.
    return loc;
}

// Walk the CU's children looking for a DW_TAG_subprogram whose PC range
// contains `addr`. Recurses into nested scopes so inline functions get
// matched too. Returns the innermost match.
// TODO(security): convert this recursive walk to an explicit work-list/stack
// to fully bound it against hostile DWARF; for now a depth cap stops runaway
// recursion exhausting the stack on pathologically nested DIE trees.
static constexpr int kMaxDwarfDepth = 256;
static bool findSubprogramName(Dwarf_Die* parent, Dwarf_Addr addr, std::string& nameOut, int depth = 0) {
    if (depth >= kMaxDwarfDepth) return false;
    Dwarf_Die child;
    if (dwarf_child(parent, &child) != 0) return false;
    bool foundAny = false;
    do {
        int tag = dwarf_tag(&child);
        if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine) {
            if (dwarf_haspc(&child, addr) > 0) {
                const char* n = dwarf_diename(&child);
                if (n) { nameOut = n; foundAny = true; }
                // Recurse for an even more specific (inlined) match.
                std::string deeper;
                if (findSubprogramName(&child, addr, deeper, depth + 1) && !deeper.empty())
                    nameOut = deeper;
            }
        } else if (tag == DW_TAG_lexical_block) {
            // Mutually exclusive with the subprogram branch above so a
            // subprogram subtree is never walked twice.
            std::string deeper;
            if (findSubprogramName(&child, addr, deeper, depth + 1) && !deeper.empty()) {
                nameOut = deeper;
                foundAny = true;
            }
        }
    } while (dwarf_siblingof(&child, &child) == 0);
    return foundAny;
}

std::optional<std::string> DwarfInfo::functionName(uintptr_t runtimeAddress) const {
    if (!impl_ || !impl_->dwarf) return std::nullopt;
    Dwarf_Addr linkAddr = (runtimeAddress >= impl_->loadBase)
        ? (Dwarf_Addr)(runtimeAddress - impl_->loadBase)
        : (Dwarf_Addr)runtimeAddress;
    Dwarf_Die cuDie;
    if (dwarf_addrdie(impl_->dwarf, linkAddr, &cuDie) == nullptr)
        return std::nullopt;
    std::string name;
    if (findSubprogramName(&cuDie, linkAddr, name) && !name.empty())
        return name;
    return std::nullopt;
}

// ── Type description (structs / members) ──

// Resolve a type DIE to a readable name and, via out params, its byte size and
// whether it is a float / pointer. Follows typedef/const/volatile and pointer
// chains; bounded by kMaxDwarfDepth against hostile debug info.
static std::string dwarfTypeName(Dwarf_Die* type, uint64_t& sizeOut,
                                 bool& isFloat, bool& isPointer, int depth = 0) {
    if (!type || depth >= kMaxDwarfDepth) return "?";
    int tag = dwarf_tag(type);

    auto followType = [&](Dwarf_Die* out) -> bool {
        Dwarf_Attribute at;
        if (!dwarf_attr_integrate(type, DW_AT_type, &at)) return false;
        return dwarf_formref_die(&at, out) != nullptr;
    };

    switch (tag) {
        case DW_TAG_base_type: {
            const char* n = dwarf_diename(type);
            Dwarf_Word bs = 0; Dwarf_Attribute a;
            if (dwarf_attr_integrate(type, DW_AT_byte_size, &a) && dwarf_formudata(&a, &bs) == 0)
                sizeOut = bs;
            Dwarf_Word enc = 0;
            if (dwarf_attr_integrate(type, DW_AT_encoding, &a) && dwarf_formudata(&a, &enc) == 0)
                isFloat = (enc == DW_ATE_float);
            return n ? n : "?";
        }
        case DW_TAG_pointer_type: {
            isPointer = true;
            sizeOut = 8;
            Dwarf_Die inner;
            if (followType(&inner)) {
                uint64_t s2 = 0; bool f2 = false, p2 = false;
                return dwarfTypeName(&inner, s2, f2, p2, depth + 1) + "*";
            }
            return "void*";
        }
        case DW_TAG_typedef: {
            // Keep the typedef name for readability, but resolve size/flags from
            // the underlying type.
            const char* n = dwarf_diename(type);
            Dwarf_Die inner;
            if (followType(&inner)) {
                std::string uname = dwarfTypeName(&inner, sizeOut, isFloat, isPointer, depth + 1);
                return n ? n : uname;
            }
            return n ? n : "?";
        }
        case DW_TAG_const_type:
        case DW_TAG_volatile_type:
        case DW_TAG_restrict_type: {
            Dwarf_Die inner;
            if (followType(&inner))
                return dwarfTypeName(&inner, sizeOut, isFloat, isPointer, depth + 1);
            return "void";
        }
        case DW_TAG_structure_type:
        case DW_TAG_class_type:
        case DW_TAG_union_type:
        case DW_TAG_enumeration_type: {
            Dwarf_Word bs = 0; Dwarf_Attribute a;
            if (dwarf_attr_integrate(type, DW_AT_byte_size, &a) && dwarf_formudata(&a, &bs) == 0)
                sizeOut = bs;
            const char* n = dwarf_diename(type);
            const char* kw = (tag == DW_TAG_union_type) ? "union "
                           : (tag == DW_TAG_enumeration_type) ? "enum " : "struct ";
            return n ? (std::string(kw) + n) : (std::string(kw) + "<anon>");
        }
        case DW_TAG_array_type: {
            Dwarf_Die elem;
            std::string en = "?";
            uint64_t elemSize = 0; bool f2 = false, p2 = false;
            if (followType(&elem)) en = dwarfTypeName(&elem, elemSize, f2, p2, depth + 1);
            // Array length via the DW_TAG_subrange_type child's upper bound + 1.
            uint64_t count = 0;
            Dwarf_Die sub;
            if (dwarf_child(type, &sub) == 0) {
                do {
                    if (dwarf_tag(&sub) == DW_TAG_subrange_type) {
                        Dwarf_Word ub = 0; Dwarf_Attribute a;
                        if (dwarf_attr_integrate(&sub, DW_AT_upper_bound, &a) &&
                            dwarf_formudata(&a, &ub) == 0)
                            count = ub + 1;
                        else if (dwarf_attr_integrate(&sub, DW_AT_count, &a) &&
                                 dwarf_formudata(&a, &ub) == 0)
                            count = ub;
                        break;
                    }
                } while (dwarf_siblingof(&sub, &sub) == 0);
            }
            sizeOut = elemSize * count;
            return en + "[" + (count ? std::to_string(count) : std::string()) + "]";
        }
        default: {
            const char* n = dwarf_diename(type);
            return n ? n : "?";
        }
    }
}

// Fill a DwarfStruct from a struct/union/class DIE (must already be the match).
static void readStructMembers(Dwarf_Die* structDie, DwarfStruct& out) {
    Dwarf_Word bs = 0; Dwarf_Attribute a;
    if (dwarf_attr_integrate(structDie, DW_AT_byte_size, &a) && dwarf_formudata(&a, &bs) == 0)
        out.size = bs;

    Dwarf_Die child;
    if (dwarf_child(structDie, &child) != 0) return;
    do {
        if (dwarf_tag(&child) != DW_TAG_member) continue;
        DwarfMember m;
        const char* n = dwarf_diename(&child);
        m.name = n ? n : "";
        Dwarf_Attribute at;
        if (dwarf_attr_integrate(&child, DW_AT_data_member_location, &at)) {
            Dwarf_Word off = 0;
            if (dwarf_formudata(&at, &off) == 0) m.offset = off;
        }
        Dwarf_Die typeDie;
        if (dwarf_attr_integrate(&child, DW_AT_type, &at) &&
            dwarf_formref_die(&at, &typeDie) != nullptr) {
            m.typeName = dwarfTypeName(&typeDie, m.size, m.isFloat, m.isPointer);
        }
        out.members.push_back(std::move(m));
    } while (dwarf_siblingof(&child, &child) == 0);
}

// Walk a DIE subtree, invoking `visit` for each aggregate-type DIE. Bounded.
static void walkAggregates(Dwarf_Die* parent,
                           const std::function<void(Dwarf_Die*)>& visit, int depth = 0) {
    if (depth >= kMaxDwarfDepth) return;
    Dwarf_Die child;
    if (dwarf_child(parent, &child) != 0) return;
    do {
        int tag = dwarf_tag(&child);
        if (tag == DW_TAG_structure_type || tag == DW_TAG_class_type ||
            tag == DW_TAG_union_type)
            visit(&child);
        // Types can nest (namespaces, nested classes); recurse.
        walkAggregates(&child, visit, depth + 1);
    } while (dwarf_siblingof(&child, &child) == 0);
}

// Iterate every compile unit's DIE tree, calling `visit` for each aggregate type.
template <typename Fn>
static void forEachAggregate(Dwarf* dwarf, Fn&& visit) {
    Dwarf_Off off = 0, next = 0;
    size_t hsize = 0;
    Dwarf_Off abbrev = 0;
    uint8_t addrsz = 0, offsz = 0;
    std::function<void(Dwarf_Die*)> v = visit;
    while (dwarf_nextcu(dwarf, off, &next, &hsize, &abbrev, &addrsz, &offsz) == 0) {
        Dwarf_Die cu;
        if (dwarf_offdie(dwarf, off + hsize, &cu) != nullptr)
            walkAggregates(&cu, v);
        off = next;
    }
}

std::vector<std::string> DwarfInfo::structNames() const {
    std::vector<std::string> names;
    if (!impl_ || !impl_->dwarf) return names;
    std::set<std::string> seen;
    forEachAggregate(impl_->dwarf, [&](Dwarf_Die* d) {
        const char* n = dwarf_diename(d);
        if (n && *n && seen.insert(n).second) names.push_back(n);
    });
    return names;
}

std::optional<DwarfStruct> DwarfInfo::structByName(const std::string& name) const {
    if (!impl_ || !impl_->dwarf) return std::nullopt;
    std::optional<DwarfStruct> result;
    forEachAggregate(impl_->dwarf, [&](Dwarf_Die* d) {
        if (result) return;                        // first match wins
        const char* n = dwarf_diename(d);
        if (!n || name != n) return;
        // Prefer a definition (has members) over a forward declaration.
        Dwarf_Attribute a;
        if (dwarf_attr_integrate(d, DW_AT_declaration, &a)) return;
        DwarfStruct s;
        s.name = n;
        readStructMembers(d, s);
        result = std::move(s);
    });
    return result;
}

#else // CECORE_HAVE_DWARF

struct DwarfInfo::Impl { /* empty stub */ };

DwarfInfo::DwarfInfo() : impl_(std::make_unique<Impl>()) {}
DwarfInfo::~DwarfInfo() = default;
DwarfInfo::DwarfInfo(DwarfInfo&&) noexcept = default;
DwarfInfo& DwarfInfo::operator=(DwarfInfo&&) noexcept = default;

bool DwarfInfo::available() { return false; }
bool DwarfInfo::load(const std::string&, uintptr_t) { return false; }
bool DwarfInfo::isLoaded() const { return false; }
void DwarfInfo::close() {}
std::optional<DwarfSourceLocation> DwarfInfo::lookup(uintptr_t) const { return std::nullopt; }
std::optional<std::string>         DwarfInfo::functionName(uintptr_t) const { return std::nullopt; }
std::vector<std::string>           DwarfInfo::structNames() const { return {}; }
std::optional<DwarfStruct>         DwarfInfo::structByName(const std::string&) const { return std::nullopt; }

#endif // CECORE_HAVE_DWARF

// ── DwarfRegistry ──

DwarfRegistry::DwarfRegistry() = default;
DwarfRegistry::~DwarfRegistry() = default;

int DwarfRegistry::loadFromProcess(ProcessHandle& proc) {
    clear();
    if (!DwarfInfo::available()) return 0;
    auto mods = proc.modules();
    int loaded = 0;
    for (const auto& m : mods) {
        if (m.path.empty()) continue;
        auto info = std::make_unique<DwarfInfo>();
        if (info->load(m.path, m.base)) {
            modules_.push_back(Module{m.base, m.size, std::move(info)});
            ++loaded;
        }
    }
    return loaded;
}

std::optional<DwarfSourceLocation> DwarfRegistry::lookup(uintptr_t runtimeAddress) const {
    for (const auto& m : modules_) {
        if (runtimeAddress >= m.base && runtimeAddress < m.base + m.size) {
            return m.info->lookup(runtimeAddress);
        }
    }
    return std::nullopt;
}

std::optional<std::string> DwarfRegistry::functionName(uintptr_t runtimeAddress) const {
    for (const auto& m : modules_) {
        if (runtimeAddress >= m.base && runtimeAddress < m.base + m.size) {
            return m.info->functionName(runtimeAddress);
        }
    }
    return std::nullopt;
}

std::vector<std::string> DwarfRegistry::structNames() const {
    std::vector<std::string> all;
    std::set<std::string> seen;
    for (const auto& m : modules_)
        for (auto& n : m.info->structNames())
            if (seen.insert(n).second) all.push_back(std::move(n));
    return all;
}

std::optional<DwarfStruct> DwarfRegistry::structByName(const std::string& name) const {
    for (const auto& m : modules_)
        if (auto s = m.info->structByName(name)) return s;
    return std::nullopt;
}

void DwarfRegistry::clear() { modules_.clear(); }

} // namespace ce
