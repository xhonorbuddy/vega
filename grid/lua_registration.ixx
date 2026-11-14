module;
#include <cstdint>
#include <vector>
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
bool register_api(lua_State* L, const char* library, const luaL_Reg* api) {
    if (!L || !api) return false;
    std::vector<std::uintptr_t> new_callbacks;
    for (auto* entry = api; entry->name; ++entry) {
        if (!entry->func) return false;
        const auto callback = reinterpret_cast<std::uintptr_t>(entry->func);
        if (breakpoint::contains(callback)) continue;
        bool duplicate = false;
        for (const auto pending : new_callbacks) if (pending == callback) duplicate = true;
        if (!duplicate) new_callbacks.push_back(callback);
    }
    if (new_callbacks.size() > breakpoint::available()) return false;
    std::vector<luaL_Reg> bridged;
    for (auto* entry = api; entry->name; ++entry) {
        const auto trap = breakpoint::bind(reinterpret_cast<std::uintptr_t>(entry->func));
        if (!trap) return false;
        bridged.push_back({entry->name, reinterpret_cast<lua_CFunction>(trap)});
    }
    bridged.push_back({nullptr, nullptr});
    luaL_register(L, library, bridged.data());
    return true;
}
}
