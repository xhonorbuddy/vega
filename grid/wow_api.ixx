module;
#include <windows.h>
#include <cstdint>
// Lua 5.1 has no C++ linkage wrapper. Keep the global module fragment
// preprocessor-only while giving its public API C linkage for the static lib.
#include "luaconf.h"
#undef LUA_API
#define LUA_API extern "C"
#include "lua.h"
#include "lauxlib.h"
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>

export module grid.wow_api;
import grid.wow;

export namespace grid::wow_api {
    extern const luaL_Reg functions[];
    void set_game_thread(DWORD thread_id);
}

namespace grid::wow_api {
namespace {
    namespace state = wow::client_state_70888;
    DWORD game_thread = 0;
    const char* const type_names[] = {
        "Object", "Item", "Container", "AzeriteEmpoweredItem", "AzeriteItem",
        "Unit", "Player", "ActivePlayer", "GameObject", "DynamicObject",
        "Corpse", "AreaTrigger", "SceneObject", "Conversation", "MeshObject"
    };

    int memory_fault_filter(DWORD code) {
        return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
    }

    bool supported_build() {
        const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        if (!base) return false;
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE &&
            nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
            nt->FileHeader.TimeDateStamp == state::image_timestamp &&
            nt->OptionalHeader.SizeOfImage == state::image_size;
    }

    const char* phase_name(state::phase phase) {
        switch (phase) {
        case state::phase::in_world: return "in_world";
        case state::phase::loading: return "loading";
        case state::phase::outside_world: return "outside_world";
        default: return "unavailable";
        }
    }

    bool read_world(state::snapshot& result) {
        __try { result = state::read(); return true; }
        __except (memory_fault_filter(GetExceptionCode())) { result = {}; return false; }
    }

    void boolean(lua_State* L, const char* key, bool value) {
        lua_pushboolean(L, value); lua_setfield(L, -2, key);
    }
    void number(lua_State* L, const char* key, lua_Number value) {
        lua_pushnumber(L, value); lua_setfield(L, -2, key);
    }
    void string(lua_State* L, const char* key, const char* value) {
        lua_pushstring(L, value); lua_setfield(L, -2, key);
    }
    void push_guid(lua_State* L, wow::guid value) {
        if (!value.low && !value.high) { lua_pushnil(L); return; }
        char buffer[35]{};
        std::snprintf(buffer, sizeof(buffer), "0x%016llX%016llX",
            static_cast<unsigned long long>(value.high), static_cast<unsigned long long>(value.low));
        lua_pushstring(L, buffer);
    }
    void guid_field(lua_State* L, const char* key, wow::guid value) {
        push_guid(L, value); lua_setfield(L, -2, key);
    }
    void push_vector(lua_State* L, wow::vector3 value) {
        lua_createtable(L, 0, 3);
        number(L, "x", value.x); number(L, "y", value.y); number(L, "z", value.z);
    }
    int failure(lua_State* L, const char* reason, bool validity = false) {
        if (validity) lua_pushboolean(L, 0); else lua_pushnil(L);
        lua_pushstring(L, reason);
        return 2;
    }

    uintptr_t object_address(lua_State* L) {
        if (lua_type(L, 1) == LUA_TLIGHTUSERDATA)
            return reinterpret_cast<uintptr_t>(lua_touserdata(L, 1));
        if (lua_type(L, 1) == LUA_TNUMBER) {
            const double n = lua_tonumber(L, 1);
            if (std::isfinite(n) && n >= 0 && n <= 9007199254740991.0 && std::floor(n) == n)
                return static_cast<uintptr_t>(n);
        }
        if (lua_type(L, 1) == LUA_TSTRING) {
            size_t length = 0;
            const char* text = lua_tolstring(L, 1, &length);
            uintptr_t result = 0;
            if (length > 2 && length <= 18 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
                const auto parsed = std::from_chars(text + 2, text + length, result, 16);
                if (parsed.ec == std::errc{} && parsed.ptr == text + length) return result;
            }
        }
        luaL_error(L, "expected an object lightuserdata, hex address, or exact integer address");
        return 0;
    }

    enum class query { info, valid, type, id, owner, target, health, power, flags, flags3,
        name, position, plate, facing, dead, ghost, animation, bite };
    struct object_result {
        bool valid{}, unit{}, dead{}, ghost{}, bite{};
        uint8_t type{};
        wow::guid id{}, owner{}, target{};
        int64_t health{};
        int power{}, subtype{-1}, network_state{-1};
        uint32_t flags{}, flags3{}, animation{};
        float facing{};
        wow::vector3 position{}, plate{};
        char name[512]{};
    };

    // No Lua calls or C++ objects requiring unwinding inside this fault boundary.
    bool inspect(uintptr_t address, query kind, int power_type, object_result& r) {
        __try {
            if (!address) return false;
            auto* object = reinterpret_cast<wow::entity*>(address);
            if (!object->active()) return false;
            r.valid = true;
            r.type = static_cast<uint8_t>(object->type());
            r.unit = object->isUnit();
            const bool all = kind == query::info;
            if (all || kind == query::id) r.id = object->id();
            if (all || kind == query::owner) r.owner = object->owner();
            if (all || kind == query::target) r.target = object->target();
            if (all || kind == query::health) r.health = object->health();
            if (all || kind == query::power) r.power = object->power(power_type);
            if (all || kind == query::flags) r.flags = object->flags();
            if (all || kind == query::flags3) r.flags3 = object->flags3();
            if (all || kind == query::name) {
                const char* name = object->rawName();
                if (name) for (size_t i = 0; i + 1 < sizeof(r.name); ++i) {
                    r.name[i] = name[i];
                    if (!name[i]) break;
                }
            }
            if (all || kind == query::position) r.position = object->location();
            if (all || kind == query::plate) r.plate = object->plateLocation();
            if (all || kind == query::facing) r.facing = object->facing();
            if (all || kind == query::dead) r.dead = object->dead() != 0;
            if (all || kind == query::ghost) r.ghost = object->deadOrGhost();
            if (all || kind == query::animation) r.animation = object->animation();
            if (all || kind == query::bite) r.bite = object->fishingBiteAnimationActive();
            if (all) {
                r.subtype = object->gameObjectSubtype();
                r.network_state = object->gameObjectState();
            }
            return true;
        }
        __except (memory_fault_filter(GetExceptionCode())) { r = {}; return false; }
    }

    bool unit_query(query kind) {
        return kind == query::target || kind == query::health || kind == query::power ||
            kind == query::flags || kind == query::flags3 || kind == query::dead || kind == query::ghost;
    }

    int object_query(lua_State* L, query kind) {
        const uintptr_t address = object_address(L);
        const bool validity = kind == query::valid;
        if (!supported_build()) return failure(L, "unsupported client build; expected 1.60.1.70888", validity);
        if (!game_thread || GetCurrentThreadId() != game_thread)
            return failure(L, "object queries must run on the registered game thread", validity);
        state::snapshot world{};
        if (!read_world(world) || world.state() != state::phase::in_world)
            return failure(L, "game world is not ready", validity);
        int power_type = -1;
        if (kind == query::power && !lua_isnoneornil(L, 2)) {
            const lua_Number value = luaL_checknumber(L, 2);
            if (!std::isfinite(value) || std::floor(value) != value || value < -1 || value >= 30)
                return luaL_error(L, "power type must be -1 or an integer from 0 to 29");
            power_type = static_cast<int>(value);
        }
        object_result r{};
        if (!inspect(address, kind, power_type, r)) return failure(L, "object is invalid or unreadable", validity);
        if (unit_query(kind) && !r.unit) return failure(L, "property requires a Unit, Player, or ActivePlayer");
        switch (kind) {
        case query::valid: lua_pushboolean(L, 1); return 1;
        case query::type:
            lua_pushinteger(L, r.type); lua_pushstring(L, type_names[r.type]); return 2;
        case query::id: push_guid(L, r.id); return 1;
        case query::owner: push_guid(L, r.owner); return 1;
        case query::target: push_guid(L, r.target); return 1;
        case query::health: {
            char exact[24]{};
            std::snprintf(exact, sizeof(exact), "%lld", static_cast<long long>(r.health));
            lua_pushnumber(L, static_cast<lua_Number>(r.health)); lua_pushstring(L, exact); return 2;
        }
        case query::power: lua_pushinteger(L, r.power); return 1;
        case query::flags: lua_pushnumber(L, r.flags); return 1;
        case query::flags3: lua_pushnumber(L, r.flags3); return 1;
        case query::name: lua_pushstring(L, r.name[0] ? r.name : "UNKNOWN"); return 1;
        case query::position: push_vector(L, r.position); return 1;
        case query::plate: push_vector(L, r.plate); return 1;
        case query::facing: lua_pushnumber(L, r.facing); return 1;
        case query::dead: lua_pushboolean(L, r.dead); return 1;
        case query::ghost: lua_pushboolean(L, r.ghost); return 1;
        case query::animation: lua_pushinteger(L, r.animation); return 1;
        case query::bite: lua_pushboolean(L, r.bite); return 1;
        default: break;
        }
        lua_createtable(L, 0, 20);
        lua_pushlightuserdata(L, reinterpret_cast<void*>(address)); lua_setfield(L, -2, "address");
        number(L, "type", r.type); string(L, "typeName", type_names[r.type]);
        guid_field(L, "guid", r.id); guid_field(L, "owner", r.owner);
        string(L, "name", r.name[0] ? r.name : "UNKNOWN");
        push_vector(L, r.position); lua_setfield(L, -2, "position");
        push_vector(L, r.plate); lua_setfield(L, -2, "platePosition");
        number(L, "facing", r.facing);
        if (r.unit) {
            char exact[24]{};
            std::snprintf(exact, sizeof(exact), "%lld", static_cast<long long>(r.health));
            number(L, "health", static_cast<lua_Number>(r.health)); string(L, "healthExact", exact);
            number(L, "power", r.power); number(L, "flags", r.flags); number(L, "flags3", r.flags3);
            boolean(L, "dead", r.dead); boolean(L, "deadOrGhost", r.ghost);
            guid_field(L, "target", r.target);
        }
        if (r.type == wow::GAMEOBJECT) {
            number(L, "subtype", r.subtype); number(L, "gameObjectState", r.network_state);
            number(L, "animationFlags", r.animation); boolean(L, "biteAnimationActive", r.bite);
        }
        return 1;
    }

    int world_state(lua_State* L) {
        state::snapshot world{};
        read_world(world);
        lua_createtable(L, 0, 8);
        string(L, "build", "1.60.1.70888"); string(L, "state", phase_name(world.state()));
        boolean(L, "available", world.available); boolean(L, "buildSupported", supported_build());
        boolean(L, "inWorld", world.state() == state::phase::in_world);
        boolean(L, "loading", world.state() == state::phase::loading);
        boolean(L, "playerInWorldFlag", world.playerInWorld());
        if (world.available) {
            number(L, "loadingRequests", world.loading_requests);
            boolean(L, "loadingScreenLayer", world.loading_screen_layer);
        }
        return 1;
    }
    int in_world(lua_State* L) {
        state::snapshot s{}; read_world(s); lua_pushboolean(L, s.state() == state::phase::in_world); return 1;
    }
    int loading(lua_State* L) {
        state::snapshot s{}; read_world(s); lua_pushboolean(L, s.state() == state::phase::loading); return 1;
    }
    int object_types(lua_State* L) {
        lua_createtable(L, 15, 0);
        for (int i = 0; i < 15; ++i) {
            lua_createtable(L, 0, 3);
            number(L, "id", i); string(L, "name", type_names[i]);
            number(L, "hierarchyMask", wow::entity_layout_70888::hierarchy_masks[i]);
            lua_rawseti(L, -2, i + 1);
        }
        return 1;
    }
    template<query Kind> int get(lua_State* L) { return object_query(L, Kind); }
}

void set_game_thread(DWORD thread_id) { game_thread = thread_id; }
const luaL_Reg functions[] = {
    {"WorldState", world_state}, {"IsInWorld", in_world}, {"IsLoading", loading},
    {"ObjectTypes", object_types}, {"ObjectInfo", get<query::info>},
    {"ObjectValid", get<query::valid>}, {"ObjectType", get<query::type>},
    {"ObjectGUID", get<query::id>}, {"ObjectOwner", get<query::owner>},
    {"ObjectTarget", get<query::target>}, {"ObjectHealth", get<query::health>},
    {"ObjectPower", get<query::power>}, {"ObjectFlags", get<query::flags>},
    {"ObjectFlags3", get<query::flags3>}, {"ObjectName", get<query::name>},
    {"ObjectPosition", get<query::position>}, {"ObjectPlatePosition", get<query::plate>},
    {"ObjectFacing", get<query::facing>}, {"ObjectDead", get<query::dead>},
    {"ObjectDeadOrGhost", get<query::ghost>}, {"ObjectAnimationFlags", get<query::animation>},
    {"Animating", get<query::bite>}, {"FishingBiteAnimationActive", get<query::bite>},
    {nullptr, nullptr}
};
} // namespace grid::wow_api
