module;
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "lua.h"

export module grid.client_lua;
import grid.signature;

// Opaque internal library entry point; the host Node is never dereferenced here.
extern "C" void luaH_set_dummynode(void* node);

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
    // luaH_free compares node identity before passing the hash allocation to
    // the client allocator. A DLL-local dummy would be freed as a real node.
    const auto dummy_reference = signature::find(image,
        "48 8D 05 ?? ?? ?? ?? 48 8B 52 28 48 8B F9 48 3B D0 74 1C 0F B6 4B 13"); // 0x39ECA5D
    if (!reference || !dummy_reference) return false;
    std::int32_t dummy_displacement{};
    std::memcpy(&dummy_displacement,reinterpret_cast<void*>(dummy_reference+3),sizeof(dummy_displacement));
    const auto dummy=dummy_reference+7+dummy_displacement; // 0x3BFF000
    MEMORY_BASIC_INFORMATION page{};
    if (!VirtualQuery(reinterpret_cast<void*>(dummy),&page,sizeof(page)) ||
        page.State!=MEM_COMMIT || (page.Protect&PAGE_GUARD) ||
        (page.Protect&0xff)==PAGE_NOACCESS ||
        dummy+56>reinterpret_cast<std::uintptr_t>(page.BaseAddress)+page.RegionSize) return false;
    const unsigned char empty_node[56]{};
    if (std::memcmp(reinterpret_cast<void*>(dummy),empty_node,sizeof(empty_node))) return false;
    luaH_set_dummynode(reinterpret_cast<void*>(dummy));
    if (reference) {
        std::int32_t displacement{};
        std::memcpy(&displacement, reinterpret_cast<void*>(reference + 3), sizeof(displacement));
        state_slot = reinterpret_cast<lua_State**>(reference + 7 + displacement); // 0x6B46468
    }
    return state_slot != nullptr;
}
lua_State* state() { return state_slot ? *state_slot : nullptr; }
}
