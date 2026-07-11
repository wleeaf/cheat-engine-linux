/// Lua Stream and StringList userdata.
///
/// Stream: byte-oriented sequential access. Backed by an in-memory buffer
/// (createMemoryStream) or an on-disk file (createFileStream). Methods
/// mirror CE's TMemoryStream / TFileStream surface enough that table
/// scripts reading config blobs, saving state, etc. just work.
///
/// StringList: TStringList-style ordered string list. add/delete/get/set,
/// getText/setText to serialise as \n-joined text, saveToFile/loadFromFile.

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <new>
#include <sstream>
#include <string>
#include <vector>

#include <sys/stat.h>

namespace ce {

namespace {

constexpr const char* STREAM_MT     = "ce.Stream";
constexpr const char* STRINGLIST_MT = "ce.StringList";

// cecore commonly runs as root, so a trojaned table's saveToFile/createFileStream
// could clobber an arbitrary file through a planted symlink (e.g. a symlink named
// "save.dat" pointing at /etc/shadow). Refuse to open a *write* target that is an
// existing symlink. This is a defensive subset; it does not close the broader
// trust boundary or the TOCTOU window.
// TODO(security): gate filesystem bindings behind a script-trust setting and open
// write targets with O_NOFOLLOW via a fd-backed stream to also cover races.
bool isExistingSymlink(const char* path) {
    struct stat st;
    return path && lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
}

// ── Stream ──

enum class StreamKind { Memory, File };

// Upper bound on a memory stream / loaded file buffer. Caps allocations driven
// by a script-controlled seek+write or an oversized/unseekable file so the
// std::vector allocation can't throw bad_alloc/length_error out of a
// lua_CFunction (which would unwind through liblua's C frames = UB/terminate).
constexpr size_t kMaxStreamBytes = 512u * 1024 * 1024; // 512 MB

struct LuaStream {
    StreamKind kind;
    // Memory backing.
    std::vector<uint8_t>* mem;
    size_t memPos;
    // File backing.
    std::fstream* file;
    bool readOnly;
};

LuaStream* checkStream(lua_State* L, int idx) {
    return static_cast<LuaStream*>(luaL_checkudata(L, idx, STREAM_MT));
}

void pushMemoryStream(lua_State* L) {
    auto* s = static_cast<LuaStream*>(lua_newuserdata(L, sizeof(LuaStream)));
    s->kind = StreamKind::Memory;
    s->mem = new std::vector<uint8_t>();
    s->memPos = 0;
    s->file = nullptr;
    s->readOnly = false;
    luaL_setmetatable(L, STREAM_MT);
}

void pushFileStream(lua_State* L, const std::string& path, const std::string& mode) {
    auto openMode = std::ios::binary | std::ios::in;
    bool readOnly = true;
    if (mode.find('w') != std::string::npos) {
        openMode |= std::ios::out;
        readOnly = false;
    }
    if (mode.find('+') != std::string::npos || mode == "rw") {
        openMode |= std::ios::out;
        readOnly = false;
    }
    if (!readOnly && isExistingSymlink(path.c_str())) {
        lua_pushnil(L);
        return;
    }
    auto* fs = new std::fstream(path, openMode);
    if (!fs->is_open()) {
        delete fs;
        lua_pushnil(L);
        return;
    }
    auto* s = static_cast<LuaStream*>(lua_newuserdata(L, sizeof(LuaStream)));
    s->kind = StreamKind::File;
    s->mem = nullptr;
    s->memPos = 0;
    s->file = fs;
    s->readOnly = readOnly;
    luaL_setmetatable(L, STREAM_MT);
}

int l_stream_read(lua_State* L) {
    auto* s = checkStream(L, 1);
    lua_Integer n = luaL_checkinteger(L, 2);
    if (n <= 0) { lua_pushstring(L, ""); return 1; }
    // Clamp the request to the bytes actually available BEFORE allocating, so a
    // script asking for read(0x7fffffffffff) on a tiny/empty stream cannot force
    // a multi-terabyte allocation (bad_alloc / OOM-kill).
    size_t want = (size_t)n;
    if (s->kind == StreamKind::Memory) {
        size_t avail = s->mem->size() > s->memPos ? s->mem->size() - s->memPos : 0;
        want = std::min<size_t>(want, avail);
    } else {
        // File: clamp to remaining bytes (size - current read position).
        std::streampos cur = s->file->tellg();
        s->file->seekg(0, std::ios::end);
        std::streampos end = s->file->tellg();
        s->file->clear();
        s->file->seekg(cur);
        size_t remaining = (cur >= 0 && end >= cur)
                               ? (size_t)(end - cur)
                               : (size_t)0;
        want = std::min<size_t>(want, remaining);
    }
    std::string buf;
    buf.resize(want);
    size_t got = 0;
    if (s->kind == StreamKind::Memory) {
        if (want > 0) std::memcpy(buf.data(), s->mem->data() + s->memPos, want);
        s->memPos += want;
        got = want;
    } else {
        // At EOF want==0; skip the read entirely. gcount() is NOT reset by a
        // skipped read, so reading it here would return the previous read's
        // count and yield stale NUL bytes (breaking `while #chunk>0` loops).
        if (want > 0) {
            s->file->read(buf.data(), (std::streamsize)want);
            got = (size_t)s->file->gcount();
        }
    }
    buf.resize(got);
    lua_pushlstring(L, buf.data(), buf.size());
    return 1;
}

int l_stream_write(lua_State* L) {
    auto* s = checkStream(L, 1);
    size_t len = 0;
    const char* data = luaL_checklstring(L, 2, &len);
    if (s->kind == StreamKind::Memory) {
        // Overwrite at current position, extending the buffer if needed.
        // Reject a script-controlled position/length that would force an
        // unbounded (throwing) allocation.
        if (s->memPos > kMaxStreamBytes || len > kMaxStreamBytes - s->memPos)
            return luaL_error(L, "stream write exceeds maximum size");
        if (s->memPos + len > s->mem->size())
            s->mem->resize(s->memPos + len);
        std::memcpy(s->mem->data() + s->memPos, data, len);
        s->memPos += len;
    } else {
        if (s->readOnly) return luaL_error(L, "stream is read-only");
        s->file->write(data, (std::streamsize)len);
    }
    lua_pushinteger(L, (lua_Integer)len);
    return 1;
}

int l_stream_seek(lua_State* L) {
    auto* s = checkStream(L, 1);
    lua_Integer pos = luaL_checkinteger(L, 2);
    if (pos < 0) pos = 0;
    if (s->kind == StreamKind::Memory) {
        s->memPos = (size_t)pos;
    } else {
        s->file->clear();
        s->file->seekg(pos);
        s->file->seekp(pos);
    }
    lua_pushinteger(L, pos);
    return 1;
}

int l_stream_position(lua_State* L) {
    auto* s = checkStream(L, 1);
    if (s->kind == StreamKind::Memory)
        lua_pushinteger(L, (lua_Integer)s->memPos);
    else
        lua_pushinteger(L, (lua_Integer)s->file->tellg());
    return 1;
}

int l_stream_size(lua_State* L) {
    auto* s = checkStream(L, 1);
    if (s->kind == StreamKind::Memory) {
        lua_pushinteger(L, (lua_Integer)s->mem->size());
    } else {
        auto cur = s->file->tellg();
        s->file->seekg(0, std::ios::end);
        auto end = s->file->tellg();
        s->file->seekg(cur);
        lua_pushinteger(L, (lua_Integer)end);
    }
    return 1;
}

int l_stream_saveToFile(lua_State* L) {
    auto* s = checkStream(L, 1);
    const char* path = luaL_checkstring(L, 2);
    if (isExistingSymlink(path)) { lua_pushboolean(L, 0); return 1; }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        lua_pushboolean(L, 0);
        return 1;
    }
    if (s->kind == StreamKind::Memory) {
        out.write(reinterpret_cast<const char*>(s->mem->data()), (std::streamsize)s->mem->size());
    } else {
        auto cur = s->file->tellg();
        s->file->seekg(0);
        std::vector<char> buf(4096);
        while (s->file->read(buf.data(), buf.size()) || s->file->gcount() > 0)
            out.write(buf.data(), s->file->gcount());
        s->file->clear();
        s->file->seekg(cur);
    }
    lua_pushboolean(L, 1);
    return 1;
}

int l_stream_loadFromFile(lua_State* L) {
    auto* s = checkStream(L, 1);
    const char* path = luaL_checkstring(L, 2);
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) { lua_pushboolean(L, 0); return 1; }
    std::streamoff rawSz = in.tellg();
    // tellg() returns -1 for unseekable/special files; reject that and any file
    // larger than the cap before allocating so the vector ctor can't throw.
    if (rawSz < 0) { lua_pushboolean(L, 0); return 1; }
    size_t sz = static_cast<size_t>(rawSz);
    if (sz > kMaxStreamBytes)
        return luaL_error(L, "file too large to load into stream");
    in.seekg(0);
    std::vector<uint8_t> buf(sz);
    in.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)sz);
    if (s->kind == StreamKind::Memory) {
        *s->mem = std::move(buf);
        s->memPos = 0;
    } else {
        if (s->readOnly) return luaL_error(L, "stream is read-only");
        s->file->clear();
        s->file->seekp(0);
        s->file->write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)buf.size());
    }
    lua_pushboolean(L, 1);
    return 1;
}

int l_stream_clear(lua_State* L) {
    auto* s = checkStream(L, 1);
    if (s->kind == StreamKind::Memory) {
        s->mem->clear();
        s->memPos = 0;
    } else {
        return luaL_error(L, "clear() is only valid on memory streams");
    }
    return 0;
}

int l_stream_close(lua_State* L) {
    auto* s = checkStream(L, 1);
    if (s->kind == StreamKind::File && s->file) {
        s->file->close();
    }
    return 0;
}

int l_stream__gc(lua_State* L) {
    auto* s = checkStream(L, 1);
    if (s->kind == StreamKind::Memory) {
        delete s->mem;
        s->mem = nullptr;
    } else if (s->file) {
        s->file->close();
        delete s->file;
        s->file = nullptr;
    }
    return 0;
}

int l_stream__index(lua_State* L) {
    luaL_checkudata(L, 1, STREAM_MT);
    const char* key = luaL_checkstring(L, 2);
    luaL_getmetatable(L, STREAM_MT);
    lua_getfield(L, -1, "__methods");
    lua_getfield(L, -1, key);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 3);
    // Property accessors
    if (!std::strcmp(key, "Position")) return l_stream_position(L);
    if (!std::strcmp(key, "Size"))     return l_stream_size(L);
    lua_pushnil(L);
    return 1;
}

void buildStreamMetatable(lua_State* L) {
    luaL_newmetatable(L, STREAM_MT);
    lua_newtable(L);
    static const luaL_Reg methods[] = {
        {"read",         l_stream_read},
        {"write",        l_stream_write},
        {"seek",         l_stream_seek},
        {"getPosition",  l_stream_position},
        {"getSize",      l_stream_size},
        {"saveToFile",   l_stream_saveToFile},
        {"loadFromFile", l_stream_loadFromFile},
        {"clear",        l_stream_clear},
        {"close",        l_stream_close},
        {nullptr, nullptr},
    };
    luaL_setfuncs(L, methods, 0);
    lua_setfield(L, -2, "__methods");

    lua_pushcfunction(L, l_stream__index); lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_stream__gc);    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);
}

int l_createMemoryStream(lua_State* L) {
    pushMemoryStream(L);
    return 1;
}

int l_createFileStream(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* mode = luaL_optstring(L, 2, "rw");
    pushFileStream(L, path, mode);
    return 1;
}

// ── StringList ──

struct LuaStringList {
    std::vector<std::string>* items;
};

LuaStringList* checkSL(lua_State* L, int idx) {
    return static_cast<LuaStringList*>(luaL_checkudata(L, idx, STRINGLIST_MT));
}

void pushStringList(lua_State* L) {
    auto* sl = static_cast<LuaStringList*>(lua_newuserdata(L, sizeof(LuaStringList)));
    sl->items = new std::vector<std::string>();
    luaL_setmetatable(L, STRINGLIST_MT);
}

int l_sl_add(lua_State* L) {
    auto* sl = checkSL(L, 1);
    size_t n = 0;
    const char* s = luaL_checklstring(L, 2, &n);
    sl->items->emplace_back(s, n);
    lua_pushinteger(L, (lua_Integer)sl->items->size() - 1);
    return 1;
}

int l_sl_delete(lua_State* L) {
    auto* sl = checkSL(L, 1);
    int i = (int)luaL_checkinteger(L, 2);
    if (i < 0 || i >= (int)sl->items->size()) return 0;
    sl->items->erase(sl->items->begin() + i);
    return 0;
}

int l_sl_clear(lua_State* L) {
    auto* sl = checkSL(L, 1);
    sl->items->clear();
    return 0;
}

int l_sl_getCount(lua_State* L) {
    auto* sl = checkSL(L, 1);
    lua_pushinteger(L, (lua_Integer)sl->items->size());
    return 1;
}

int l_sl_get(lua_State* L) {
    auto* sl = checkSL(L, 1);
    int i = (int)luaL_checkinteger(L, 2);
    if (i < 0 || i >= (int)sl->items->size()) { lua_pushnil(L); return 1; }
    const auto& s = (*sl->items)[i];
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

int l_sl_set(lua_State* L) {
    auto* sl = checkSL(L, 1);
    int i = (int)luaL_checkinteger(L, 2);
    size_t n = 0;
    const char* v = luaL_checklstring(L, 3, &n);
    if (i < 0 || i >= (int)sl->items->size()) return 0;
    (*sl->items)[i].assign(v, n);
    return 0;
}

int l_sl_getText(lua_State* L) {
    auto* sl = checkSL(L, 1);
    std::string out;
    for (size_t i = 0; i < sl->items->size(); ++i) {
        if (i) out.push_back('\n');
        out += (*sl->items)[i];
    }
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}

int l_sl_setText(lua_State* L) {
    auto* sl = checkSL(L, 1);
    size_t n = 0;
    const char* s = luaL_checklstring(L, 2, &n);
    sl->items->clear();
    std::string current;
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if (c == '\n') { sl->items->push_back(std::move(current)); current.clear(); }
        else current.push_back(c);
    }
    if (!current.empty()) sl->items->push_back(std::move(current));
    return 0;
}

int l_sl_indexOf(lua_State* L) {
    auto* sl = checkSL(L, 1);
    size_t n = 0;
    const char* needle = luaL_checklstring(L, 2, &n);
    std::string target(needle, n);
    for (size_t i = 0; i < sl->items->size(); ++i)
        if ((*sl->items)[i] == target) { lua_pushinteger(L, (lua_Integer)i); return 1; }
    lua_pushinteger(L, -1);
    return 1;
}

int l_sl_saveToFile(lua_State* L) {
    auto* sl = checkSL(L, 1);
    const char* path = luaL_checkstring(L, 2);
    if (isExistingSymlink(path)) { lua_pushboolean(L, 0); return 1; }
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) { lua_pushboolean(L, 0); return 1; }
    for (size_t i = 0; i < sl->items->size(); ++i) {
        out << (*sl->items)[i] << '\n';
    }
    lua_pushboolean(L, 1);
    return 1;
}

int l_sl_loadFromFile(lua_State* L) {
    auto* sl = checkSL(L, 1);
    const char* path = luaL_checkstring(L, 2);
    std::ifstream in(path);
    if (!in.is_open()) { lua_pushboolean(L, 0); return 1; }
    sl->items->clear();
    std::string line;
    while (std::getline(in, line)) sl->items->push_back(std::move(line));
    lua_pushboolean(L, 1);
    return 1;
}

int l_sl__gc(lua_State* L) {
    auto* sl = checkSL(L, 1);
    delete sl->items;
    sl->items = nullptr;
    return 0;
}

int l_sl__len(lua_State* L) {
    auto* sl = checkSL(L, 1);
    lua_pushinteger(L, (lua_Integer)sl->items->size());
    return 1;
}

int l_sl__index(lua_State* L) {
    luaL_checkudata(L, 1, STRINGLIST_MT);
    // Numeric index → get(i).
    if (lua_type(L, 2) == LUA_TNUMBER) return l_sl_get(L);
    const char* key = luaL_checkstring(L, 2);
    luaL_getmetatable(L, STRINGLIST_MT);
    lua_getfield(L, -1, "__methods");
    lua_getfield(L, -1, key);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 3);
    if (!std::strcmp(key, "Count")) return l_sl_getCount(L);
    if (!std::strcmp(key, "Text"))  return l_sl_getText(L);
    lua_pushnil(L);
    return 1;
}

int l_sl__newindex(lua_State* L) {
    luaL_checkudata(L, 1, STRINGLIST_MT);
    if (lua_type(L, 2) == LUA_TSTRING) {
        const char* key = lua_tostring(L, 2);
        if (!std::strcmp(key, "Text")) {
            lua_remove(L, 2);
            return l_sl_setText(L);
        }
    }
    return luaL_error(L, "StringList: write-only property is not supported");
}

void buildStringListMetatable(lua_State* L) {
    luaL_newmetatable(L, STRINGLIST_MT);
    lua_newtable(L);
    static const luaL_Reg methods[] = {
        {"add",          l_sl_add},
        {"delete",       l_sl_delete},
        {"clear",        l_sl_clear},
        {"getCount",     l_sl_getCount},
        {"getString",    l_sl_get},
        {"setString",    l_sl_set},
        {"getText",      l_sl_getText},
        {"setText",      l_sl_setText},
        {"indexOf",      l_sl_indexOf},
        {"saveToFile",   l_sl_saveToFile},
        {"loadFromFile", l_sl_loadFromFile},
        {nullptr, nullptr},
    };
    luaL_setfuncs(L, methods, 0);
    lua_setfield(L, -2, "__methods");

    lua_pushcfunction(L, l_sl__index);    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_sl__newindex); lua_setfield(L, -2, "__newindex");
    lua_pushcfunction(L, l_sl__len);      lua_setfield(L, -2, "__len");
    lua_pushcfunction(L, l_sl__gc);       lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);
}

int l_createStringList(lua_State* L) {
    pushStringList(L);
    return 1;
}

} // anonymous namespace

void registerStreamBindings(lua_State* L) {
    buildStreamMetatable(L);
    buildStringListMetatable(L);
    lua_register(L, "createMemoryStream", l_createMemoryStream);
    lua_register(L, "createFileStream",   l_createFileStream);
    lua_register(L, "createStringList",   l_createStringList);
}

} // namespace ce
