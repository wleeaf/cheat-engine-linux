/// Lua Bitmap userdata — thin wrapper around QImage. Use case: trainer
/// HUDs that load PNG/JPG assets and draw them via Canvas, or generate
/// bitmaps procedurally and save them to disk.

#include "gui/canvaswidget.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <QImage>
#include <QColor>
#include <QString>
#include <new>
#include <cstring>

namespace ce {

namespace {

constexpr const char* BITMAP_MT = "ce.Bitmap";

struct LuaBitmap {
    QImage* image;
};

LuaBitmap* checkBmp(lua_State* L, int idx) {
    return (LuaBitmap*)luaL_checkudata(L, idx, BITMAP_MT);
}

QColor parseBmpColor(lua_State* L, int idx) {
    if (lua_type(L, idx) == LUA_TNUMBER) {
        unsigned int v = (unsigned int)lua_tointeger(L, idx);
        return QColor(v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF);
    }
    return QColor(QString::fromUtf8(luaL_checkstring(L, idx)));
}

int l_bmp__gc(lua_State* L) {
    auto* b = checkBmp(L, 1);
    delete b->image;
    b->image = nullptr;
    return 0;
}

int l_bmp_loadFromFile(lua_State* L) {
    auto* b = checkBmp(L, 1);
    const char* path = luaL_checkstring(L, 2);
    QImage loaded;
    bool ok = loaded.load(QString::fromUtf8(path));
    if (ok) *b->image = std::move(loaded);
    lua_pushboolean(L, ok);
    return 1;
}

int l_bmp_saveToFile(lua_State* L) {
    auto* b = checkBmp(L, 1);
    const char* path = luaL_checkstring(L, 2);
    const char* fmt = luaL_optstring(L, 3, nullptr);
    lua_pushboolean(L, b->image && b->image->save(QString::fromUtf8(path), fmt));
    return 1;
}

int l_bmp_width(lua_State* L) {
    auto* b = checkBmp(L, 1);
    lua_pushinteger(L, b->image ? b->image->width() : 0);
    return 1;
}

int l_bmp_height(lua_State* L) {
    auto* b = checkBmp(L, 1);
    lua_pushinteger(L, b->image ? b->image->height() : 0);
    return 1;
}

int l_bmp_resize(lua_State* L) {
    auto* b = checkBmp(L, 1);
    int w = (int)luaL_checkinteger(L, 2);
    int h = (int)luaL_checkinteger(L, 3);
    if (b->image) *b->image = b->image->scaled(w, h);
    return 0;
}

int l_bmp_setPixel(lua_State* L) {
    auto* b = checkBmp(L, 1);
    int x = (int)luaL_checkinteger(L, 2);
    int y = (int)luaL_checkinteger(L, 3);
    QColor c = parseBmpColor(L, 4);
    if (b->image && x >= 0 && y >= 0 && x < b->image->width() && y < b->image->height())
        b->image->setPixelColor(x, y, c);
    return 0;
}

int l_bmp_getPixel(lua_State* L) {
    auto* b = checkBmp(L, 1);
    int x = (int)luaL_checkinteger(L, 2);
    int y = (int)luaL_checkinteger(L, 3);
    if (!b->image || x < 0 || y < 0 || x >= b->image->width() || y >= b->image->height()) {
        lua_pushnil(L); return 1;
    }
    auto px = b->image->pixelColor(x, y);
    // Return as CE-style 0x00BBGGRR.
    uint32_t packed = (px.blue() << 16) | (px.green() << 8) | px.red();
    lua_pushinteger(L, (lua_Integer)packed);
    return 1;
}

int l_bmp__index(lua_State* L) {
    luaL_checkudata(L, 1, BITMAP_MT);
    const char* key = luaL_checkstring(L, 2);
    if (!std::strcmp(key, "Width"))  return l_bmp_width(L);
    if (!std::strcmp(key, "Height")) return l_bmp_height(L);
    luaL_getmetatable(L, BITMAP_MT);
    lua_pushvalue(L, 2);
    lua_rawget(L, -2);
    return 1;
}

void pushBitmap(lua_State* L, QImage* img) {
    auto* b = (LuaBitmap*)lua_newuserdata(L, sizeof(LuaBitmap));
    b->image = img;
    luaL_setmetatable(L, BITMAP_MT);
}

int l_createBitmap(lua_State* L) {
    int w = (int)luaL_optinteger(L, 1, 32);
    int h = (int)luaL_optinteger(L, 2, 32);
    auto* img = new QImage(w, h, QImage::Format_ARGB32_Premultiplied);
    img->fill(Qt::transparent);
    pushBitmap(L, img);
    return 1;
}

int l_loadBitmap(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    auto* img = new QImage;
    if (!img->load(QString::fromUtf8(path))) {
        delete img;
        lua_pushnil(L);
        return 1;
    }
    pushBitmap(L, img);
    return 1;
}

void buildBitmapMetatable(lua_State* L) {
    luaL_newmetatable(L, BITMAP_MT);
    static const luaL_Reg methods[] = {
        {"loadFromFile", l_bmp_loadFromFile},
        {"saveToFile",   l_bmp_saveToFile},
        {"getWidth",     l_bmp_width},
        {"getHeight",    l_bmp_height},
        {"resize",       l_bmp_resize},
        {"setPixel",     l_bmp_setPixel},
        {"getPixel",     l_bmp_getPixel},
        {nullptr, nullptr},
    };
    luaL_setfuncs(L, methods, 0);
    lua_pushcfunction(L, l_bmp__index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_bmp__gc);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);
}

} // anonymous namespace

void registerBitmapBindings(lua_State* L) {
    buildBitmapMetatable(L);
    lua_register(L, "createBitmap", l_createBitmap);
    lua_register(L, "loadBitmap",   l_loadBitmap);
}

} // namespace ce
