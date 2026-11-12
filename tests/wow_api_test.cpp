#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <new>
#include <stdexcept>
#include <windows.h>
extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}
import grid.wow;
import grid.wow_api;

template<class T, size_t N>
void put(std::array<std::byte, N>& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}
void check(bool value) {
    if (!value) throw std::runtime_error("WoW entity/API regression");
}
int hello(lua_State* L) { lua_pushliteral(L, "hello"); return 1; }

int main() {
    using namespace grid::wow;
    namespace state = client_state_70888;
    static_assert(sizeof(guid) == 16 && sizeof(vector3) == 12);
    static_assert(offsetof(ctm, type) == 0x1C);
    static_assert(offsetof(mouseClick, type) == 0x2D0);
    static_assert(offsetof(mouseClick, GUID) == 0x2D8);
    static_assert(offsetof(mouseClick, position) == 0x2E8);
    static_assert(state::snapshot{true, 0x10, 0, false}.state() == state::phase::in_world);
    static_assert(state::snapshot{true, 0x10, 1, false}.state() == state::phase::loading);
    static_assert(state::snapshot{true, 0x10, 0, true}.state() == state::phase::loading);
    check(state::read().state() == state::phase::unavailable);

    alignas(16) std::array<std::byte, 0x2300> bytes{};
    auto* object = ::new (bytes.data()) entity;
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    for (uint8_t type = 0; type < 15; ++type) {
        put(bytes, 0, base + entity_layout_70888::primary_vtable_rvas[type]);
        put(bytes, 0x24, type); put(bytes, 0x25, type);
        check(object->active() && object->isA(ENTITY) && object->isA(static_cast<gameobject>(type)));
        check(object->isA(UNIT) == (type >= 5 && type <= 7));
        check(object->isA(ITEM) == (type >= 1 && type <= 4));
        if (type >= 1 && type <= 4) {
            put(bytes, 0x150, guid{17, uint64_t{2} << 58});
            check(object->owner().low == 17);
        }
    }
    put(bytes, 0, base + entity_layout_70888::primary_vtable_rvas[UNIT]);
    put(bytes, 0x24, uint8_t{UNIT}); put(bytes, 0x25, uint8_t{UNIT});
    put(bytes, 0x10, guid{0x1122334455667788, 0x2233445566778899});
    put(bytes, 0x1E28, int64_t{5000000000});
    put(bytes, 0x1E58, uint32_t{0x80000000}); put(bytes, 0x1E60, uint32_t{0x123});
    put(bytes, 0x1DB8, guid{11, uint64_t{2} << 58});
    put(bytes, 0x1D88, guid{7, uint64_t{2} << 58});
    check(object->id().low == 0x1122334455667788 && object->id().high == 0x2233445566778899);
    check(object->health() == 5000000000 && object->flags() == 0x80000000 && object->flags3() == 0x123);
    check(!object->dead() && object->target().low == 11 && object->owner().low == 7);
    put(bytes, 0x1D68, guid{9, uint64_t{2} << 58}); check(object->owner().low == 9);
    put(bytes, 0x25, uint8_t{0x12});
    check(!object->active() && object->health() == 0 && object->owner().high == 0);
    const auto pos = object->location();
    check(pos.x == 0 && pos.y == 0 && pos.z == 0 && object->facing() == 0);
    put(bytes, 0, base + entity_layout_70888::primary_vtable_rvas[GAMEOBJECT]);
    put(bytes, 0x24, uint8_t{GAMEOBJECT}); put(bytes, 0x25, uint8_t{GAMEOBJECT});
    put(bytes, 0x188, guid{15, uint64_t{2} << 58});
    put(bytes, 0x1C9, uint8_t{17}); put(bytes, 0x1C8, uint8_t{1});
    check(object->owner().low == 15 && object->health() == 0);
    // Captured live sequence. Extra flags and adjacent bytes must be preserved.
    put(bytes, 0x114, uint32_t{0xAABBCC11});
    check(!object->fishingBiteAnimationActive() && object->animation() == 0x11);
    put(bytes, 0x114, uint8_t{0x13}); check(object->fishingBiteAnimationActive());
    put(bytes, 0x114, uint8_t{0x11}); check(!object->fishingBiteAnimationActive());
    put(bytes, 0x114, uint8_t{5}); check(!object->fishingBiteAnimationActive());
    put(bytes, 0x114, uint8_t{7}); check(!object->fishingBiteAnimationActive());
    put(bytes, 0x1C9, uint8_t{3}); check(!object->fishingBiteAnimationActive());
    put(bytes, 0, base + entity_layout_70888::primary_vtable_rvas[CORPSE]);
    put(bytes, 0x24, uint8_t{CORPSE}); put(bytes, 0x25, uint8_t{CORPSE});
    put(bytes, 0x110, guid{13, uint64_t{2} << 58});
    check(object->corpseOwner().low == 13 && object->owner().low == 13);

    lua_State* L = luaL_newstate();
    check(L != nullptr);
    luaL_openlibs(L);
    grid::wow_api::set_game_thread(GetCurrentThreadId());
    const luaL_Reg existing[] = {{"AFK", hello}, {nullptr, nullptr}};
    luaL_register(L, "C", existing);
    luaL_register(L, nullptr, grid::wow_api::functions);
    for (const luaL_Reg* entry = grid::wow_api::functions; entry->name; ++entry) {
        lua_getfield(L, -1, entry->name); check(lua_isfunction(L, -1)); lua_pop(L, 1);
    }
    const char* script = R"lua(
        assert(C.AFK() == 'hello')
        local types = C.ObjectTypes()
        assert(#types == 15 and types[1].id == 0 and types[1].name == 'Object')
        assert(types[15].id == 14 and types[15].name == 'MeshObject')
        assert(types[7].hierarchyMask == 0x61)
        local world = C.WorldState()
        assert(world.state == 'unavailable' and world.available == false)
        assert(world.buildSupported == false and world.build == '1.60.1.70888')
        assert(C.IsInWorld() == false and C.IsLoading() == false)
        local ok, err = C.ObjectValid('0xFFFFFFFFFFFFFFFF')
        assert(ok == false and string.find(err, 'unsupported client build', 1, true))
        local object, reason = C.ObjectInfo(0)
        assert(object == nil and string.find(reason, 'unsupported client build', 1, true))
        for _, bad in ipairs({'0x1garbage', '0x0\000bad', -1, 0.5, 9007199254740992}) do
            local success = pcall(C.ObjectValid, bad)
            assert(not success, 'invalid pointer argument accepted')
        end
        collectgarbage('collect')
        assert(C.WorldState().state == 'unavailable')
    )lua";
    const int result = luaL_dostring(L, script);
    if (result != 0) std::fprintf(stderr, "%s\n", lua_tostring(L, -1));
    lua_close(L);
    check(result == 0);
    std::puts("WoW 70888 entity layouts and grid Lua API tests passed");
    return 0;
}
