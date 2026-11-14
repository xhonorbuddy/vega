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
int print_here(lua_State* L) {
    lua_pushstring(L, "here");
    return 1;
}
int print_there(lua_State* L) {
    lua_pushstring(L, "there");
    return 1;
}
}
const luaL_Reg functions[] = {
    { "PrintHere", print_here },
    { "PrintThere", print_there },
    { nullptr, nullptr },
};
}
