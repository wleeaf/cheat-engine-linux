/// Lua bindings: memory scans, pointer scans and structure dissection.
#include "core/target_capabilities.hpp"
#include "core/local_target.hpp"
#include "core/module_files.hpp"
#include "arch/target_arch.hpp"
/// Extended Lua API bindings — CE-compatible function set.
#include <charconv>
#include <bit>
#include <array>
#include <csignal>
#include "scripting/lua_engine.hpp"
#include "scripting/lua_safe.hpp"
#include "core/ct_file.hpp"
#include "core/trainer.hpp"
#include "core/address_list.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/mono_dissector.hpp"
#include "analysis/il2cpp_metadata.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "analysis/signature.hpp"
#include "analysis/pe_exports.hpp"
#include "symbols/dwarf_symbols.hpp"
#include "core/simple_hook.hpp"
#include "analysis/structure_tools.hpp"
#include "analysis/code_analysis.hpp"
#include "scripting/lua_memrec.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "core/autoasm.hpp"
#include "core/value_io.hpp"
#include "core/value_transform.hpp"
#include "core/expression.hpp"
#include "core/injection_gen.hpp"
#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "debug/patch.hpp"
#include "debug/debug_session.hpp"
#include "debug/code_finder.hpp"
#include "debug/tracer.hpp"
#include "debug/lbr_tracer.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "symbols/elf_symbols.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/target_syscall.hpp"
#include <climits>
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/gdb_process.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstring>
#include <sys/uio.h>
#include <cerrno>
#include <iconv.h>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/input.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <filesystem>
#include <limits>
#include <cmath>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <cctype>

#undef lua_pushcfunction
#define lua_pushcfunction(L, f) ce::pushSafeLuaFunction((L), (f))

#include "scripting/lua_bindings_internal.hpp"
namespace ce::lua_detail {

// ── Scanning from Lua ──

struct LuaScanData {
    ValueType valueType=ValueType::Int32;
    std::string encoding;
    MemoryScanner scanner;
    std::unique_ptr<ScanResult> result;
};

struct LuaScanRef { LuaScanData* data; };

static LuaScanData* checkScan(lua_State* L, int index) {
    auto* ref = static_cast<LuaScanRef*>(luaL_checkudata(L, index, "MemScan"));
    if (!ref->data) luaL_error(L, "scan is destroyed");
    return ref->data;
}

static ValueType mapLuaValueType(int raw) {
    switch (raw) {
        case 0: return ValueType::Byte;
        case 1: return ValueType::Int16;
        case 2: return ValueType::Int32;
        case 3: return ValueType::Int64;
        case 4: return ValueType::Float;
        case 5: return ValueType::Double;
        case 6: return ValueType::String;
        case 7: return ValueType::UnicodeString;
        case 8: return ValueType::ByteArray;
        case 9: return ValueType::Binary;
        case 10: return ValueType::All;
        case 11: return ValueType::Grouped;
        case 12: return ValueType::Custom;
        case 13: return ValueType::Pointer;
        default:
            return static_cast<ValueType>(raw);
    }
}

static size_t luaValueTypeSize(ValueType vt) {
    switch (vt) {
        case ValueType::Byte: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32:
        case ValueType::Float: return 4;
        case ValueType::Int64:
        case ValueType::Pointer:
        case ValueType::Double: return 8;
        default: return 4;
    }
}

static ScanCompare mapLuaScanType(int raw, bool& customFormula) {
    customFormula = false;
    switch (raw) {
        case 0: return ScanCompare::Exact;
        case 1: return ScanCompare::Between;
        case 2: return ScanCompare::Greater;
        case 3: return ScanCompare::Less;
        case 4: return ScanCompare::Unknown;
        case 5: return ScanCompare::Increased;
        case 6: return ScanCompare::Decreased;
        case 7: return ScanCompare::Changed;
        case 8: return ScanCompare::Unchanged;
        case 9: return ScanCompare::SameAsFirst;
        case 10:
            customFormula = true;
            return ScanCompare::Exact;
        default:
            return static_cast<ScanCompare>(raw);
    }
}

static ScanConfig luaScanConfig(lua_State* L, int scanTypeIndex, int valueTypeIndex, int valueIndex) {
    int scanType = (int)luaL_checkinteger(L, scanTypeIndex);
    int valueTypeRaw = (int)luaL_checkinteger(L, valueTypeIndex);
    size_t valueLength = 0;
    const char* value = luaL_checklstring(L, valueIndex, &valueLength);

    // Validate Lua arguments before constructing C++ objects so a type error
    // cannot longjmp past their destructors.
    const auto start=luaL_optinteger(L,valueIndex+1,0);
    const auto stop=luaL_optinteger(L,valueIndex+2,static_cast<lua_Integer>(UINTPTR_MAX));
    const auto alignment=luaL_optinteger(L,valueIndex+3,4);
    ScanConfig cfg;
    std::string upperValue;
    bool customFormula = false;
    cfg.compareType = mapLuaScanType(scanType, customFormula);
    cfg.valueType = mapLuaValueType(valueTypeRaw);
    cfg.alignment=static_cast<size_t>(std::max<lua_Integer>(1,alignment));
    cfg.startAddress=static_cast<uintptr_t>(start);cfg.stopAddress=static_cast<uintptr_t>(stop);
    if (lua_isstring(L, valueIndex + 4))
        cfg.stringEncoding = lua_tostring(L, valueIndex + 4);

    const int options=valueIndex+5;
    if (!lua_isnoneornil(L,options)) {
        if (!lua_istable(L,options)) throw std::invalid_argument("Scan format options must be a table");
        auto field=[&](const char* name) {
            auto result=gdbOptionField(L,options,name);
            if (!result) throw std::invalid_argument(result.error());
        };
        field("byteOrder");
        if (!lua_isnil(L,-1)) {
            if (lua_type(L,-1)!=LUA_TSTRING) {lua_pop(L,1);throw std::invalid_argument("Scan byte order must be auto, little or big");}
            const std::string order=lua_tostring(L,-1);lua_pop(L,1);
            if (order=="little") cfg.byteOrder=ByteOrder::Little;
            else if (order=="big") cfg.byteOrder=ByteOrder::Big;
            else if (order!="auto") throw std::invalid_argument("Scan byte order must be auto, little or big");
        } else lua_pop(L,1);
        field("pointerWidth");
        if (!lua_isnil(L,-1)) {
            int integer=0;const auto width=lua_tointegerx(L,-1,&integer);lua_pop(L,1);
            if (!integer || (width!=4 && width!=8)) throw std::invalid_argument("Scan pointer width must be 4 or 8");
            cfg.pointerWidth=static_cast<uint8_t>(width);
        } else lua_pop(L,1);
        const bool floating=cfg.valueType==ValueType::All || cfg.valueType==ValueType::Float || cfg.valueType==ValueType::Double;
        if (floating) {
            field("rounding");
            if (!lua_isnil(L,-1)) {
                if (lua_type(L,-1)!=LUA_TSTRING) {lua_pop(L,1);throw std::invalid_argument("Scan rounding must be exact, rounded, truncated or extreme");}
                const std::string mode=lua_tostring(L,-1);lua_pop(L,1);
                if (mode=="exact") cfg.roundingType=0;
                else if (mode=="rounded") cfg.roundingType=1;
                else if (mode=="truncated") cfg.roundingType=2;
                else if (mode=="extreme") cfg.roundingType=3;
                else throw std::invalid_argument("Scan rounding must be exact, rounded, truncated or extreme");
            } else lua_pop(L,1);
            field("tolerance");
            if (!lua_isnil(L,-1)) {
                int number=0;const auto tolerance=lua_tonumberx(L,-1,&number);lua_pop(L,1);
                if (!number || !std::isfinite(tolerance) || tolerance<0) throw std::invalid_argument("Scan tolerance must be a finite nonnegative number");
                cfg.floatTolerance=tolerance;
            } else lua_pop(L,1);
        }
        const bool integer=cfg.valueType==ValueType::Byte || cfg.valueType==ValueType::Int16 || cfg.valueType==ValueType::Int32 ||
            cfg.valueType==ValueType::Int64 || cfg.valueType==ValueType::Pointer;
        if ((floating || integer) && cfg.compareType==ScanCompare::Between) {
            field("value2");
            if (!lua_isnil(L,-1)) {
                if (!lua_isstring(L,-1)) {lua_pop(L,1);throw std::invalid_argument("Scan upper value must be a number or string");}
                size_t length=0;const char* upper=lua_tolstring(L,-1,&length);
                upperValue.assign(upper,length);lua_pop(L,1);
            } else lua_pop(L,1);
        }
    }
    if (customFormula)
        cfg.valueType = ValueType::Custom;

    auto integerValue=[&]() {
        bool valid=false;const auto parsed=parseIntegerScalar(value,false,valid);
        if (!valid) throw std::invalid_argument("Invalid scan integer or pointer");
        return parsed;
    };
    auto upperInteger=[&]() {
        bool valid=false;const auto parsed=parseIntegerScalar(upperValue,false,valid);
        if (!valid) throw std::invalid_argument("Invalid scan integer or pointer upper bound (format.value2)");
        return parsed;
    };
    switch (cfg.valueType) {
        case ValueType::String:
        case ValueType::UnicodeString:
            cfg.stringValue = value;
            cfg.alignment = 1;
            break;
        case ValueType::ByteArray:
            if (!cfg.parseAOB(value)) throw std::invalid_argument("Invalid scan byte pattern");
            cfg.alignment = 1;
            break;
        case ValueType::Binary:
            cfg.parseBinary(value);
            cfg.alignment = 1;
            break;
        case ValueType::Float:
        case ValueType::Double:
            if (!cfg.parseFloatingValues(std::string_view(value,valueLength),upperValue))
                throw std::invalid_argument("Invalid floating scan value or Between upper bound (format.value2)");
            break;
        case ValueType::Pointer:
            cfg.intValue = integerValue();
            if (cfg.compareType==ScanCompare::Between) cfg.intValue2=upperInteger();
            break;
        case ValueType::All:
            if (!cfg.parseAllValues(std::string_view(value,valueLength),upperValue))
                throw std::invalid_argument("Invalid All scan value or Between upper bound (format.value2)");
            break;
        case ValueType::Grouped: {
            std::string error;
            if (!cfg.parseGrouped(value, &error))
                throw std::invalid_argument("Invalid grouped scan expression: " + error);
            cfg.alignment = 1;
            break;
        }
        case ValueType::Custom:
            cfg.customFormula = value;
            if (mapLuaValueType(valueTypeRaw)==ValueType::Pointer) {
                auto* process=getProc(L);
                const auto width=cfg.pointerWidth ? cfg.pointerWidth : process ? process->targetDescription().program.pointerWidth : 0;
                if (width!=4 && width!=8) throw std::invalid_argument("Custom pointer scan requires a known program pointer width");
                cfg.customValueSize=width;
            } else cfg.customValueSize=luaValueTypeSize(mapLuaValueType(valueTypeRaw));
            cfg.alignment = 1;
            break;
        default:
            cfg.intValue = integerValue();
            if (cfg.compareType==ScanCompare::Between) cfg.intValue2=upperInteger();
            break;
    }

    return cfg;
}

int l_createMemScan(lua_State* L) {
    auto* ref = static_cast<LuaScanRef*>(lua_newuserdata(L, sizeof(LuaScanRef)));
    ref->data = nullptr;
    luaL_getmetatable(L, "MemScan");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        luaL_newmetatable(L, "MemScan");
        lua_pushvalue(L, -1); lua_setfield(L, -2, "__index");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* ref = static_cast<LuaScanRef*>(luaL_checkudata(L, 1, "MemScan"));
            delete ref->data;
            ref->data = nullptr;
            return 0;
        });
        lua_setfield(L, -2, "__gc");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            checkScan(L, 1);
            // The options can run Lua (metatables) that frees this scan or the
            // process: read them before taking either pointer.
            ScanConfig cfg;
            try { cfg = luaScanConfig(L, 2, 3, 4); }
            catch (const std::exception& ex) { lua_pushboolean(L, 0); lua_pushstring(L, ex.what()); return 2; }
            auto* sd = checkScan(L, 1);
            auto* p = getProc(L);
            if (!p) { lua_pushboolean(L, 0); return 1; }
            try {
                auto result=std::make_unique<ScanResult>(sd->scanner.firstScan(*p, cfg));
                if (result->hasWriteError()) throw std::runtime_error("Incomplete scan result files: " + result->writeErrorReason());
                sd->encoding=cfg.stringEncoding;sd->valueType=cfg.valueType;sd->result=std::move(result);
                lua_pushboolean(L, 1);
                lua_pushnil(L);
            } catch (const std::exception& ex) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, ex.what());
            } catch (...) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, "scan failed");
            }
            return 2;
        });
        lua_setfield(L, -2, "firstScan");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            checkScan(L, 1);
            ScanConfig cfg;   // read first: the options can run Lua (see firstScan)
            try { cfg = luaScanConfig(L, 2, 3, 4); }
            catch (const std::exception& ex) { lua_pushboolean(L, 0); lua_pushstring(L, ex.what()); return 2; }
            auto* sd = checkScan(L, 1);
            auto* p = getProc(L);
            if (!p || !sd->result) { lua_pushboolean(L, 0); return 1; }
            try {
                auto result=std::make_unique<ScanResult>(sd->scanner.nextScan(*p, cfg, *sd->result));
                if (result->hasWriteError()) throw std::runtime_error("Incomplete scan result files: " + result->writeErrorReason());
                sd->encoding=cfg.stringEncoding;sd->valueType=cfg.valueType;sd->result=std::move(result);
                lua_pushboolean(L, 1);
                lua_pushnil(L);
            } catch (const std::exception& ex) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, ex.what());
            } catch (...) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, "scan failed");
            }
            return 2;
        });
        lua_setfield(L, -2, "nextScan");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = checkScan(L, 1);
            lua_pushinteger(L, sd->result ? sd->result->count() : 0);
            return 1;
        });
        lua_setfield(L, -2, "getFoundCount");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = checkScan(L, 1);
            lua_Integer idx = luaL_checkinteger(L, 2);
            if (!sd->result || idx < 0 || static_cast<uint64_t>(idx) >= sd->result->count()) { lua_pushnil(L); return 1; }
            lua_pushinteger(L, (lua_Integer)sd->result->address(idx));
            return 1;
        });
        lua_setfield(L, -2, "getAddress");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd=checkScan(L,1);
            const auto index=luaL_checkinteger(L,2);
            const bool first=lua_toboolean(L,3);
            const auto selectedType=luaL_optinteger(L,4,-1);
            if (!sd->result || index<0 || static_cast<uint64_t>(index)>=sd->result->count()) {lua_pushnil(L);return 1;}
            if (sd->result->hasWriteError() || sd->result->recordStride()!=sd->result->valueSize()) {
                lua_pushnil(L);lua_pushliteral(L,"Invalid scan result files");return 2;
            }
            std::vector<uint8_t> bytes(sd->result->valueSize());
            if (first) sd->result->firstValue(index,bytes.data(),bytes.size());
            else sd->result->value(index,bytes.data(),bytes.size());
            auto type=sd->valueType;
            if (selectedType!=-1) {
                if (!sd->result->hasAllTypeCandidates() || selectedType<0 || selectedType>5 ||
                    !(sd->result->allTypeCandidates(index)&(1u<<selectedType))) {
                    lua_pushnil(L);lua_pushliteral(L,"Select a surviving All-type numeric candidate");return 2;
                }
                type=mapLuaValueType(selectedType);
                bytes.resize(luaValueTypeSize(type));
            } else if (sd->result->hasAllTypeCandidates()) {
                const size_t size=sd->result->allTypeValueSize(index);
                if (!size) {lua_pushnil(L);lua_pushliteral(L,"Invalid All-type candidate metadata");return 2;}
                bytes.resize(size);
            }
            if (type==ValueType::Binary || type==ValueType::Grouped || type==ValueType::Custom || type==ValueType::All) type=ValueType::ByteArray;
            ValueIoOptions options;options.byteOrder=sd->result->byteOrder();options.pointerWidth=sd->result->pointerWidth();options.encoding=sd->encoding;
            auto value=decodeTypedValue(type,bytes,options);
            if (!value) {lua_pushnil(L);lua_pushlstring(L,value.error().data(),value.error().size());return 2;}
            lua_pushlstring(L,value->data(),value->size());return 1;
        });
        lua_setfield(L,-2,"getValue");
        lua_pushcfunction(L,[](lua_State* L) -> int {
            auto* sd=checkScan(L,1);const auto index=luaL_checkinteger(L,2);
            if (!sd->result || index<0 || static_cast<uint64_t>(index)>=sd->result->count()) {lua_pushnil(L);return 1;}
            const auto mask=sd->result->allTypeCandidates(index);
            if (sd->result->hasWriteError() || !mask) {lua_pushnil(L);lua_pushliteral(L,"No valid All-type candidate metadata");return 2;}
            lua_newtable(L);int slot=1;
            for (int type=0;type<6;++type) if (mask&(1u<<type)) {lua_pushinteger(L,type);lua_rawseti(L,-2,slot++);}
            return 1;
        });
        lua_setfield(L,-2,"getValueTypes");
    }
    lua_setmetatable(L, -2);
    ref->data = new LuaScanData();
    return 1;
}

// ── Pointer scanner ──
// pointerScan(target [, maxDepth [, maxOffset [, {negativeOffsets,staticOnly,alignedOnly}]]])
//   -> array of { path, module, baseOffset, moduleBase, offsets={...} }
int l_pointerScan(lua_State* L) {
    // Read every argument first: an option's __index can run Lua that closes
    // the process (freeing the handle), and a raise must not skip the
    // destructors of the C++ objects below.
    const auto target = (uintptr_t)luaL_checkinteger(L, 1);
    std::optional<int> maxDepth, maxOffset;
    std::optional<bool> negativeOffsets, staticOnly, alignedOnly;
    // The work grows as fanout^depth and the scan cannot be interrupted from
    // Lua, so out-of-range limits are an error rather than a hang.
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
        const lua_Integer depth = luaL_checkinteger(L, 2);
        luaL_argcheck(L, depth >= 1 && depth <= ce::kPointerScanMaxDepth, 2, "maxDepth must be 1 to 7");
        maxDepth = static_cast<int>(depth);
    }
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        const lua_Integer offset = luaL_checkinteger(L, 3);
        luaL_argcheck(L, offset >= 0 && offset <= ce::kPointerScanMaxOffset, 3, "maxOffset must be 0 to 1048576");
        maxOffset = static_cast<int>(offset);
    }
    if (lua_istable(L, 4)) {
        lua_getfield(L, 4, "negativeOffsets"); if (lua_isboolean(L, -1)) negativeOffsets = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 4, "staticOnly");      if (lua_isboolean(L, -1)) staticOnly      = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 4, "alignedOnly");     if (lua_isboolean(L, -1)) alignedOnly     = lua_toboolean(L, -1); lua_pop(L, 1);
    }
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    ce::PointerScanConfig cfg;
    cfg.targetAddress = target;
    if (maxDepth) cfg.maxDepth = *maxDepth;
    if (maxOffset) cfg.maxOffset = *maxOffset;
    if (negativeOffsets) cfg.negativeOffsets = *negativeOffsets;
    if (staticOnly) cfg.staticOnly = *staticOnly;
    if (alignedOnly) cfg.alignedOnly = *alignedOnly;
    ce::PointerScanner scanner;
    auto paths = scanner.scan(*p, cfg);
    lua_newtable(L);
    for (size_t i = 0; i < paths.size(); ++i) {
        const auto& pp = paths[i];
        lua_newtable(L);
        lua_pushstring(L, pp.toString().c_str());       lua_setfield(L, -2, "path");
        lua_pushstring(L, pp.module.c_str());           lua_setfield(L, -2, "module");
        lua_pushinteger(L, (lua_Integer)pp.baseOffset); lua_setfield(L, -2, "baseOffset");
        lua_pushinteger(L, (lua_Integer)pp.moduleBase); lua_setfield(L, -2, "moduleBase");
        lua_newtable(L);
        for (size_t j = 0; j < pp.offsets.size(); ++j) {
            lua_pushinteger(L, pp.offsets[j]);
            lua_rawseti(L, -2, (int)j + 1);
        }
        lua_setfield(L, -2, "offsets");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// ── Structure dissect (discriminating-field detector across N instances) ──
static const char* structFieldTypeName(ce::ValueType t) {
    switch (t) {
        case ce::ValueType::Byte:          return "Byte";
        case ce::ValueType::Int16:         return "2 Bytes";
        case ce::ValueType::Int32:         return "4 Bytes";
        case ce::ValueType::Int64:         return "8 Bytes";
        case ce::ValueType::Float:         return "Float";
        case ce::ValueType::Double:        return "Double";
        case ce::ValueType::String:        return "String";
        case ce::ValueType::UnicodeString: return "Unicode String";
        case ce::ValueType::Pointer:       return "Pointer";
        default:                           return "Array of byte";
    }
}
// dissectStructure(address | {addresses...}, size)
//   -> array of { offset, size, changed, type }
// One address: shows the layout. N addresses: flags fields that differ across
// instances (the discriminating-field detector).
int l_dissectStructure(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    // Check every argument before any C++ container exists (a raise longjmps
    // past destructors), and bound the work: a size per address is read.
    const lua_Integer requested = luaL_checkinteger(L, 2);
    luaL_argcheck(L, requested >= 0 && requested <= (lua_Integer(1) << 20), 2, "size must be 0..1MB");
    const bool many = lua_istable(L, 1);
    const lua_Integer count = many ? (lua_Integer)lua_rawlen(L, 1) : 1;
    luaL_argcheck(L, count <= 256, 1, "at most 256 addresses");
    if (many)
        for (lua_Integer i = 1; i <= count; ++i) {
            lua_rawgeti(L, 1, i);
            if (!lua_isinteger(L, -1)) return luaL_error(L, "address %d is not an integer", (int)i);
            lua_pop(L, 1);
        }
    else luaL_checkinteger(L, 1);
    const size_t size = static_cast<size_t>(requested);
    std::vector<uintptr_t> addrs;
    for (lua_Integer i = 1; i <= count; ++i) {
        if (many) { lua_rawgeti(L, 1, i); addrs.push_back((uintptr_t)lua_tointeger(L, -1)); lua_pop(L, 1); }
        else addrs.push_back((uintptr_t)lua_tointeger(L, 1));
    }
    if (addrs.empty() || size == 0) { lua_pushnil(L); return 1; }
    std::vector<std::vector<uint8_t>> snapshots;
    for (auto a : addrs) {
        std::vector<uint8_t> buf(size);
        // A short read would present the unread zeros as fields.
        if (!readExact(p, a, buf.data(), size)) { lua_pushnil(L); lua_pushstring(L, "read failed"); return 2; }
        snapshots.push_back(std::move(buf));
    }
    auto fields = ce::autoDetectStructureFieldsMulti(snapshots);
    lua_newtable(L);
    for (size_t i = 0; i < fields.size(); ++i) {
        const auto& f = fields[i];
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)f.offset);         lua_setfield(L, -2, "offset");
        lua_pushinteger(L, (lua_Integer)f.size);           lua_setfield(L, -2, "size");
        lua_pushboolean(L, f.changed);                     lua_setfield(L, -2, "changed");
        lua_pushstring(L, structFieldTypeName(f.suggestedType)); lua_setfield(L, -2, "type");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}
} // namespace ce::lua_detail
