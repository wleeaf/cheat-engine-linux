#include <cxxabi.h>
#include <cstdlib>
#include "symbols/elf_symbols.hpp"
#include "analysis/pe_exports.hpp"

#include <fstream>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <algorithm>

namespace ce {

void SymbolResolver::clear() {
    symbols_.clear();
    addrIndex_.clear();
    nameIndex_.clear();
}

void SymbolResolver::loadProcess(ProcessHandle& proc) {
    clear();
    auto modules = proc.modules();
    for (auto& m : modules) {
        if (m.path.empty() || m.path[0] != '/') continue;
        if (!std::filesystem::exists(m.path)) continue;
        parseElfSymbols(m.path, m.name, m.base);
    }
}

void SymbolResolver::loadModule(const std::string& path, const std::string& moduleName, uintptr_t baseAddr) {
    // Wine/Proton modules are PE images (MZ magic); their symbols live in the PE
    // export table, not an ELF symtab. Dispatch on the file magic.
    std::ifstream probe(path, std::ios::binary);
    char magic[2] = {};
    if (probe.read(magic, 2) && magic[0] == 'M' && magic[1] == 'Z') {
        parsePeExports(path, moduleName, baseAddr);
        return;
    }
    parseElfSymbols(path, moduleName, baseAddr);
}

void SymbolResolver::parsePeExports(const std::string& path, const std::string& moduleName,
                                    uintptr_t baseAddr) {
    for (const auto& e : ce::parsePEExports(path)) {
        if (e.name.empty() || e.rva == 0) continue;   // skip ordinal-only / forwarders
        uintptr_t addr = baseAddr + e.rva;
        if (addrIndex_.count(addr)) continue;          // first name at an address wins
        size_t idx = symbols_.size();
        symbols_.push_back(Symbol{e.name, addr, 0, moduleName});
        addrIndex_[addr] = idx;
        if (!nameIndex_.count(e.name)) nameIndex_[e.name] = addr;
    }
}

// Locate a stripped binary's separate debug file: build-id first
// (/usr/lib/debug/.build-id/<xx>/<rest>.debug), then .gnu_debuglink (next to the
// binary, in a .debug/ subdir, or under /usr/lib/debug). Returns "" if none.
static std::string findSeparateDebugFile(const std::vector<Elf64_Shdr>& shdrs,
                                         const Elf64_Ehdr& ehdr, std::ifstream& f,
                                         uintmax_t fileSize, const std::string& origPath) {
    namespace fs = std::filesystem;
    std::error_code ec;

    // 1) build-id note (most reliable; keyed lookup under /usr/lib/debug/.build-id).
    for (const auto& sh : shdrs) {
        if (sh.sh_type != SHT_NOTE) continue;
        if (sh.sh_offset > fileSize || sh.sh_size > fileSize - sh.sh_offset) continue;
        if (sh.sh_size < sizeof(Elf64_Nhdr) || sh.sh_size > (1u << 20)) continue;
        std::vector<char> buf(sh.sh_size);
        f.clear(); f.seekg(sh.sh_offset); f.read(buf.data(), sh.sh_size);
        if (!f) continue;
        size_t off = 0;
        while (off + sizeof(Elf64_Nhdr) <= buf.size()) {
            Elf64_Nhdr nh;
            std::memcpy(&nh, buf.data() + off, sizeof(nh));
            size_t nameOff = off + sizeof(Elf64_Nhdr);
            size_t descOff = nameOff + ((nh.n_namesz + 3u) & ~3u);
            size_t descPad = (nh.n_descsz + 3u) & ~3u;
            if (descOff > buf.size() || nh.n_descsz > buf.size() - descOff) break;
            if (nh.n_type == NT_GNU_BUILD_ID && nh.n_namesz >= 3 && nh.n_descsz >= 2 &&
                std::memcmp(buf.data() + nameOff, "GNU", 3) == 0) {
                static const char* hx = "0123456789abcdef";
                std::string id;
                for (uint32_t i = 0; i < nh.n_descsz; ++i) {
                    unsigned char b = static_cast<unsigned char>(buf[descOff + i]);
                    id.push_back(hx[b >> 4]); id.push_back(hx[b & 0xf]);
                }
                std::string p = "/usr/lib/debug/.build-id/" + id.substr(0, 2) + "/" +
                                id.substr(2) + ".debug";
                if (fs::exists(p, ec)) return p;
            }
            size_t next = descOff + descPad;
            if (next <= off) break;   // never stall
            off = next;
        }
    }

    // 2) .gnu_debuglink section (filename + CRC; CRC not verified here).
    if (ehdr.e_shstrndx < shdrs.size()) {
        const Elf64_Shdr& shstr = shdrs[ehdr.e_shstrndx];
        if (shstr.sh_offset <= fileSize && shstr.sh_size <= fileSize - shstr.sh_offset &&
            shstr.sh_size > 0 && shstr.sh_size < (1u << 20)) {
            std::vector<char> names(shstr.sh_size);
            f.clear(); f.seekg(shstr.sh_offset); f.read(names.data(), shstr.sh_size);
            if (f) {
                names.back() = '\0';
                for (const auto& sh : shdrs) {
                    if (sh.sh_name >= names.size()) continue;
                    if (std::strcmp(names.data() + sh.sh_name, ".gnu_debuglink") != 0) continue;
                    if (sh.sh_offset > fileSize || sh.sh_size > fileSize - sh.sh_offset ||
                        sh.sh_size < 5 || sh.sh_size > 4096) break;
                    std::vector<char> dl(sh.sh_size);
                    f.clear(); f.seekg(sh.sh_offset); f.read(dl.data(), sh.sh_size);
                    if (!f) break;
                    dl.back() = '\0';
                    std::string debugName = dl.data();
                    if (debugName.empty()) break;
                    fs::path dir = fs::path(origPath).parent_path();
                    for (const fs::path& cand : { dir / debugName,
                                                  dir / ".debug" / debugName,
                                                  fs::path("/usr/lib/debug") / dir.relative_path() / debugName }) {
                        if (fs::exists(cand, ec)) return cand.string();
                    }
                    break;
                }
            }
        }
    }
    return "";
}

void SymbolResolver::parseElfSymbols(const std::string& path, const std::string& moduleName,
                                     uintptr_t baseAddr, bool followDebugLink) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return;

    // Actual on-disk size. Every section offset/size taken from the (untrusted)
    // ELF is bounded against this before any allocation or read, so a hostile
    // header can't drive a giant allocation or an out-of-file read.
    std::error_code fsEc;
    uintmax_t fileSize = std::filesystem::file_size(path, fsEc);
    if (fsEc) return;

    // Read ELF header
    Elf64_Ehdr ehdr;
    f.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!f) return;

    // Verify ELF magic
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return;

    // 32-bit (i386) ELFs go through the parallel Elf32 symbol path; the rest of
    // this function is Elf64-typed.
    if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
        parseElf32Symbols(path, moduleName, baseAddr);
        return;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return;

    // Read section headers
    if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0) return;

    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);
    f.clear();  // reset any prior failbit so this section read is independent
    f.seekg(ehdr.e_shoff);
    f.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!f) return;

    // Determine if this is a position-independent executable (PIE/shared lib)
    // If ET_DYN, symbol addresses are relative to base and we need to add baseAddr
    // If ET_EXEC, symbol addresses are absolute
    bool isPIE = (ehdr.e_type == ET_DYN);

    // Find symbol tables (.dynsym and .symtab) and their string tables
    auto processSymtab = [&](const Elf64_Shdr& symShdr, const Elf64_Shdr& strShdr) {
        // The symbol read below sizes its buffer from sh_entsize but must read
        // exactly that many bytes per entry; only sizeof(Elf64_Sym) entries are
        // safe. (A larger sh_entsize would otherwise read more bytes than the
        // buffer holds — a heap overflow.) Real ELFCLASS64 symtabs use 24.
        if (symShdr.sh_entsize != sizeof(Elf64_Sym)) return;

        // Bound each section's [offset, offset+size) against the actual file
        // size. Written so neither term can wrap a 64-bit add past UINT64_MAX.
        if (strShdr.sh_offset > fileSize || strShdr.sh_size > fileSize - strShdr.sh_offset) return;
        if (symShdr.sh_offset > fileSize || symShdr.sh_size > fileSize - symShdr.sh_offset) return;

        // Read string table
        std::vector<char> strtab(strShdr.sh_size);
        f.clear();  // reset any prior failbit so this section read is independent
        f.seekg(strShdr.sh_offset);
        f.read(strtab.data(), strShdr.sh_size);
        if (!f) return;
        // Guarantee NUL-termination: symbol names below are read as C strings,
        // and a valid strtab already ends in NUL, so this is a no-op on good
        // files but caps the strlen scan on hostile ones.
        if (!strtab.empty()) strtab.back() = '\0';

        // Read symbol entries — exactly numSyms * sizeof(Elf64_Sym) bytes, never
        // sh_size, so the destination buffer and the read length always match.
        size_t numSyms = symShdr.sh_size / sizeof(Elf64_Sym);
        std::vector<Elf64_Sym> syms(numSyms);
        f.clear();  // reset any prior failbit so this section read is independent
        f.seekg(symShdr.sh_offset);
        f.read(reinterpret_cast<char*>(syms.data()), numSyms * sizeof(Elf64_Sym));
        if (!f) return;

        for (auto& sym : syms) {
            // Skip undefined, no-name, and non-function/object symbols
            if (sym.st_name == 0) continue;
            if (sym.st_shndx == SHN_UNDEF) continue;
            if (sym.st_name >= strShdr.sh_size) continue;

            uint8_t type = ELF64_ST_TYPE(sym.st_info);
            if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE) continue;

            const char* name = strtab.data() + sym.st_name;
            if (name[0] == '\0') continue;

            uintptr_t addr = sym.st_value;
            if (isPIE) addr += baseAddr;

            Symbol s;
            s.name = name;
            // Demangle Itanium C++ names ("_Z...") for readability, like CE shows
            // "Foo::bar()" rather than "_ZN3Foo3barEv". Keep the raw name on failure.
            if (name[0] == '_' && name[1] == 'Z') {
                int status = 0;
                char* dem = abi::__cxa_demangle(name, nullptr, nullptr, &status);
                if (status == 0 && dem) s.name = dem;
                std::free(dem);
            }
            s.address = addr;
            s.size = sym.st_size;
            s.module = moduleName;

            size_t idx = symbols_.size();
            symbols_.push_back(std::move(s));
            addrIndex_[addr] = idx;
            if (!nameIndex_.count(name))
                nameIndex_[std::string(name)] = addr;
        }
    };

    bool hasSymtab = false;
    for (size_t i = 0; i < shdrs.size(); ++i) {
        if ((shdrs[i].sh_type == SHT_DYNSYM || shdrs[i].sh_type == SHT_SYMTAB) &&
            shdrs[i].sh_link < shdrs.size()) {
            if (shdrs[i].sh_type == SHT_SYMTAB) hasSymtab = true;
            processSymtab(shdrs[i], shdrs[shdrs[i].sh_link]);
        }
    }

    // Stripped binary (only .dynsym): pull the full symbols from its separate
    // debug file (build-id / .gnu_debuglink), as CE-on-Linux and gdb do. Most
    // system libraries and release game binaries keep symbols in /usr/lib/debug.
    if (!hasSymtab && followDebugLink) {
        std::string dbg = findSeparateDebugFile(shdrs, ehdr, f, fileSize, path);
        if (!dbg.empty() && dbg != path)
            parseElfSymbols(dbg, moduleName, baseAddr, /*followDebugLink=*/false);
    }

    // Second pass: PLT/GOT relocations (.rela.plt / .rela.dyn) name the import
    // slots. Each RELA r_offset is a GOT slot; ELF64_R_SYM(r_info) indexes the
    // linked symtab. Naming the slot "<func>@got" lets a PLT stub's "jmp [got]"
    // resolve to the imported function instead of "_GLOBAL_OFFSET_TABLE_+off".
    // GOT slot file-vaddr -> imported function name, built by the reloc pass and
    // consumed by the PLT pass to name stubs. Keyed by the unrelocated r_offset.
    std::map<uintptr_t, std::string> gotSlotName;
    auto processRelocations = [&](const Elf64_Shdr& relShdr) {
        if (relShdr.sh_entsize != sizeof(Elf64_Rela)) return;
        if (relShdr.sh_link >= shdrs.size()) return;
        const Elf64_Shdr& symShdr = shdrs[relShdr.sh_link];
        if (symShdr.sh_entsize != sizeof(Elf64_Sym) || symShdr.sh_link >= shdrs.size()) return;
        const Elf64_Shdr& strShdr = shdrs[symShdr.sh_link];

        // Bound every section against the real file size (untrusted headers).
        if (relShdr.sh_offset > fileSize || relShdr.sh_size > fileSize - relShdr.sh_offset) return;
        if (symShdr.sh_offset > fileSize || symShdr.sh_size > fileSize - symShdr.sh_offset) return;
        if (strShdr.sh_offset > fileSize || strShdr.sh_size > fileSize - strShdr.sh_offset) return;

        std::vector<char> strtab(strShdr.sh_size);
        f.clear();  // reset any prior failbit so this section read is independent
        f.seekg(strShdr.sh_offset);
        f.read(strtab.data(), strShdr.sh_size);
        if (!f) return;
        if (!strtab.empty()) strtab.back() = '\0';

        size_t numSyms = symShdr.sh_size / sizeof(Elf64_Sym);
        std::vector<Elf64_Sym> syms(numSyms);
        f.clear();  // reset any prior failbit so this section read is independent
        f.seekg(symShdr.sh_offset);
        f.read(reinterpret_cast<char*>(syms.data()), numSyms * sizeof(Elf64_Sym));
        if (!f) return;

        size_t numRel = relShdr.sh_size / sizeof(Elf64_Rela);
        std::vector<Elf64_Rela> rels(numRel);
        f.clear();  // reset any prior failbit so this section read is independent
        f.seekg(relShdr.sh_offset);
        f.read(reinterpret_cast<char*>(rels.data()), numRel * sizeof(Elf64_Rela));
        if (!f) return;

        for (auto& rel : rels) {
            uint32_t symIdx = ELF64_R_SYM(rel.r_info);
            if (symIdx == 0 || symIdx >= numSyms) continue;
            const Elf64_Sym& sym = syms[symIdx];
            if (sym.st_name == 0 || sym.st_name >= strShdr.sh_size) continue;
            const char* name = strtab.data() + sym.st_name;
            if (name[0] == '\0') continue;

            std::string base = name;
            if (name[0] == '_' && name[1] == 'Z') {
                int status = 0;
                char* dem = abi::__cxa_demangle(name, nullptr, nullptr, &status);
                if (status == 0 && dem) base = dem;
                std::free(dem);
            }
            gotSlotName[rel.r_offset] = base;   // for PLT-stub matching (file vaddr key)

            uintptr_t slot = rel.r_offset;
            if (isPIE) slot += baseAddr;
            if (addrIndex_.count(slot)) continue;   // don't shadow a real symbol

            Symbol s;
            s.name = base + "@got";
            s.address = slot;
            s.size = sizeof(uintptr_t);   // a GOT slot is one pointer wide
            s.module = moduleName;
            size_t idx = symbols_.size();
            if (!nameIndex_.count(s.name)) nameIndex_[s.name] = slot;  // navigable by name
            symbols_.push_back(std::move(s));
            addrIndex_[slot] = idx;
        }
    };

    for (size_t i = 0; i < shdrs.size(); ++i) {
        if (shdrs[i].sh_type == SHT_RELA)
            processRelocations(shdrs[i]);
    }

    // Third pass: name PLT stubs "<func>@plt" so `call <stub>` resolves to the
    // imported function (CE shows "call printf"). Each stub holds an indirect jmp
    // (ff 25 disp32) to a GOT slot we just named; match by that target. The stub's
    // entry start (= the call target) is sh_entsize-aligned within the PLT section.
    if (ehdr.e_shstrndx < shdrs.size() && !gotSlotName.empty()) {
        const Elf64_Shdr& shstr = shdrs[ehdr.e_shstrndx];
        if (shstr.sh_offset <= fileSize && shstr.sh_size <= fileSize - shstr.sh_offset) {
            std::vector<char> secNames(shstr.sh_size);
            f.clear();  // reset any prior failbit so this section read is independent
            f.seekg(shstr.sh_offset);
            f.read(secNames.data(), shstr.sh_size);
            if (f && !secNames.empty()) {
                secNames.back() = '\0';
                for (const auto& sh : shdrs) {
                    if (sh.sh_type != SHT_PROGBITS || sh.sh_name >= shstr.sh_size) continue;
                    std::string sname = secNames.data() + sh.sh_name;
                    if (sname.rfind(".plt", 0) != 0) continue;   // .plt / .plt.sec / .plt.got
                    if (sh.sh_offset > fileSize || sh.sh_size > fileSize - sh.sh_offset) continue;
                    size_t entsz = sh.sh_entsize >= 8 ? sh.sh_entsize : 16;

                    std::vector<uint8_t> code(sh.sh_size);
                    f.clear();  // reset any prior failbit so this section read is independent
                    f.seekg(sh.sh_offset);
                    f.read(reinterpret_cast<char*>(code.data()), sh.sh_size);
                    if (!f) continue;

                    for (size_t off = 0; off + entsz <= code.size(); off += entsz) {
                        for (size_t j = 0; j + 6 <= entsz; ++j) {   // find the indirect jmp
                            if (code[off + j] != 0xff || code[off + j + 1] != 0x25) continue;
                            int32_t disp;
                            std::memcpy(&disp, &code[off + j + 2], 4);
                            uintptr_t jmpVaddr = sh.sh_addr + off + j;              // file vaddr
                            uintptr_t target   = jmpVaddr + 6 + (int64_t)disp;      // GOT slot
                            auto it = gotSlotName.find(target);
                            if (it != gotSlotName.end()) {
                                uintptr_t stub = sh.sh_addr + off;                  // entry start
                                if (isPIE) stub += baseAddr;
                                if (!addrIndex_.count(stub)) {
                                    Symbol s;
                                    s.name = it->second + "@plt";
                                    s.address = stub;
                                    s.size = entsz;
                                    s.module = moduleName;
                                    size_t idx = symbols_.size();
                                    if (!nameIndex_.count(s.name)) nameIndex_[s.name] = stub;
                                    symbols_.push_back(std::move(s));
                                    addrIndex_[stub] = idx;
                                }
                            }
                            break;   // one jmp per entry
                        }
                    }
                }
            }
        }
    }
}

void SymbolResolver::parseElf32Symbols(const std::string& path, const std::string& moduleName,
                                       uintptr_t baseAddr) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return;

    std::error_code fsEc;
    uintmax_t fileSize = std::filesystem::file_size(path, fsEc);
    if (fsEc) return;

    Elf32_Ehdr ehdr;
    f.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!f) return;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return;
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS32) return;
    if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0) return;

    std::vector<Elf32_Shdr> shdrs(ehdr.e_shnum);
    f.clear();
    f.seekg(ehdr.e_shoff);
    f.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf32_Shdr));
    if (!f) return;

    const bool isPIE = (ehdr.e_type == ET_DYN);

    // Mirror the Elf64 processSymtab, with 16-byte Elf32_Sym entries. Every
    // section [offset, offset+size) is bounded against the real file size first.
    auto processSymtab = [&](const Elf32_Shdr& symShdr, const Elf32_Shdr& strShdr) {
        if (symShdr.sh_entsize != sizeof(Elf32_Sym)) return;
        if (strShdr.sh_offset > fileSize || strShdr.sh_size > fileSize - strShdr.sh_offset) return;
        if (symShdr.sh_offset > fileSize || symShdr.sh_size > fileSize - symShdr.sh_offset) return;

        std::vector<char> strtab(strShdr.sh_size);
        f.clear();
        f.seekg(strShdr.sh_offset);
        f.read(strtab.data(), strShdr.sh_size);
        if (!f) return;
        if (!strtab.empty()) strtab.back() = '\0';

        size_t numSyms = symShdr.sh_size / sizeof(Elf32_Sym);
        std::vector<Elf32_Sym> syms(numSyms);
        f.clear();
        f.seekg(symShdr.sh_offset);
        f.read(reinterpret_cast<char*>(syms.data()), numSyms * sizeof(Elf32_Sym));
        if (!f) return;

        for (auto& sym : syms) {
            if (sym.st_name == 0 || sym.st_shndx == SHN_UNDEF) continue;
            if (sym.st_name >= strShdr.sh_size) continue;

            uint8_t type = ELF32_ST_TYPE(sym.st_info);
            if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE) continue;

            const char* name = strtab.data() + sym.st_name;
            if (name[0] == '\0') continue;

            uintptr_t addr = sym.st_value;
            if (isPIE) addr += baseAddr;

            Symbol s;
            s.name = name;
            if (name[0] == '_' && name[1] == 'Z') {
                int status = 0;
                char* dem = abi::__cxa_demangle(name, nullptr, nullptr, &status);
                if (status == 0 && dem) s.name = dem;
                std::free(dem);
            }
            s.address = addr;
            s.size = sym.st_size;
            s.module = moduleName;

            size_t idx = symbols_.size();
            symbols_.push_back(std::move(s));
            addrIndex_[addr] = idx;
            if (!nameIndex_.count(name))
                nameIndex_[std::string(name)] = addr;
        }
    };

    for (size_t i = 0; i < shdrs.size(); ++i) {
        if ((shdrs[i].sh_type == SHT_DYNSYM || shdrs[i].sh_type == SHT_SYMTAB) &&
            shdrs[i].sh_link < shdrs.size()) {
            processSymtab(shdrs[i], shdrs[shdrs[i].sh_link]);
        }
    }
}

void SymbolResolver::addUserSymbol(uintptr_t address, const std::string& name) {
    userSymbols_[address] = name;
    nameIndex_[name] = address;
}

void SymbolResolver::removeUserSymbol(uintptr_t address) {
    auto it = userSymbols_.find(address);
    if (it != userSymbols_.end()) {
        nameIndex_.erase(it->second);
        userSymbols_.erase(it);
    }
}

std::string SymbolResolver::resolve(uintptr_t address) const {
    // User-defined labels take priority over module symbols.
    if (!userSymbols_.empty()) {
        auto it = userSymbols_.upper_bound(address);
        if (it != userSymbols_.begin()) {
            --it;
            uintptr_t off = address - it->first;
            if (off == 0) return it->second;
            if (off <= 0x1000) {
                char buf[32];
                snprintf(buf, sizeof(buf), "+0x%lx", off);
                return it->second + buf;
            }
        }
    }
    if (addrIndex_.empty()) return {};

    // Find the symbol at or before this address
    auto it = addrIndex_.upper_bound(address);
    if (it == addrIndex_.begin()) return {};
    --it;

    auto& sym = symbols_[it->second];

    // Check if address is within the symbol's range (or within a reasonable
    // distance). Past the symbol's known extent, only attribute the address to it
    // within a 4KB grace window (likely still in the same function). Size-0
    // symbols (hand-written asm, many NOTYPE entries) have unknown extent, so the
    // grace window is measured from the symbol start — otherwise one size-0 symbol
    // would claim every address after it, up to megabytes away.
    uintptr_t offset = address - sym.address;
    uintptr_t extent = sym.size > 0 ? sym.size : 0;
    if (offset >= extent && offset > 0x1000) return {};

    if (offset == 0)
        return sym.module + "!" + sym.name;
    else {
        char buf[32];
        snprintf(buf, sizeof(buf), "+0x%lx", offset);
        return sym.module + "!" + sym.name + buf;
    }
}

uintptr_t SymbolResolver::lookup(const std::string& name) const {
    auto it = nameIndex_.find(name);
    return it != nameIndex_.end() ? it->second : 0;
}

} // namespace ce
