module;
#include "luaconf.h"
#undef LUA_API
#define LUA_API extern "C"
#include "lua.h"
#include "lauxlib.h"

export module grid.api;

export namespace grid::api {
extern const luaL_Reg functions[];
}
namespace grid::api {
namespace {
int afk(lua_State* L) {
    lua_pushstring(L, "hello");
    return 1;
}
}
const luaL_Reg functions[] = {
    { "AFK", afk },
    { nullptr, nullptr },
};
}
