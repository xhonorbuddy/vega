module;
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "lua.h"

export module grid.client_lua;
import grid.signature;

export namespace grid::client_lua {
bool resolve();
lua_State* state();
}

namespace grid::client_lua {
namespace {
lua_State** state_slot{};
}
bool resolve() {
    const auto image = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    // Verified unique in the open Wow 1.60.1.70938 executable (image base 0).
    // RVAs are evidence only; runtime addresses always come from IDA patterns.
    const auto reference = signature::find(image,
        "48 8B 0D ?? ?? ?? ?? 48 8B DA E8 ?? ?? ?? ?? 48 83 38 00 74 0C 33 C9 E8 ?? ?? ?? ??"); // 0x339862
    state_slot = nullptr;
    if (reference) {
        std::int32_t displacement{};
        std::memcpy(&displacement, reinterpret_cast<void*>(reference + 3), sizeof(displacement));
        state_slot = reinterpret_cast<lua_State**>(reference + 7 + displacement); // 0x6B46468
    }
    return state_slot != nullptr;
}
lua_State* state() { return state_slot ? *state_slot : nullptr; }
}
