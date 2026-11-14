module;
#include <cstddef>
#include <cstdint>
#include <limits>
#include "luaconf.h"
#undef LUA_API
#define LUA_API extern "C"
#include "lua.h"
#include "lauxlib.h"

export module grid.lua_registration;
import grid.breakpoint;

export namespace grid::lua_registration {
// Like luaL_register: null-terminated entries; leaves the library table on top.
// Resolve the breakpoint pool first. Call on the game thread.
// Returns false before changing Lua if the pool cannot fit the whole API.
bool register_api(lua_State* L, const char* library, const luaL_Reg* api);
}

namespace grid::lua_registration {
bool register_api(lua_State* L,const char* library,const luaL_Reg* api) {
    if (!L || !api || (!library && !lua_istable(L,-1))) return false;
    std::uintptr_t pending[breakpoint::capacity]{};
    std::size_t required=0,entries=0;
    for (const auto* entry=api;entry->name;++entry) {
        if (!entry->func) return false;
        ++entries;
        const auto callback=reinterpret_cast<std::uintptr_t>(entry->func);
        if (breakpoint::contains(callback)) continue;
        bool duplicate=false;
        for (std::size_t i=0;i<required;++i) if (pending[i]==callback) duplicate=true;
        if (duplicate) continue;
        if (required==breakpoint::capacity) return false;
        pending[required++]=callback;
    }
    if (required>breakpoint::available() ||
        entries>std::numeric_limits<std::size_t>::max()/sizeof(luaL_Reg)-1) return false;
    if (!lua_checkstack(L,3)) return false;
    // Lua owns the temporary registrations across its nonlocal error/unwind paths.
    // No callback-local C++ container destructor may cross luaL_register.
    auto* bridged=static_cast<luaL_Reg*>(lua_newuserdata(L,(entries+1)*sizeof(luaL_Reg)));
    const auto scratch=lua_gettop(L);
    for (std::size_t i=0;i<entries;++i) {
        const auto trap=breakpoint::bind(reinterpret_cast<std::uintptr_t>(api[i].func));
        bridged[i]={api[i].name,reinterpret_cast<lua_CFunction>(trap)};
    }
    bridged[entries]={nullptr,nullptr};
    if (!library) lua_pushvalue(L,scratch-1);
    luaL_register(L,library,bridged);
    if (!library) lua_pop(L,1);
    lua_remove(L,scratch);
    return true;
}
}
