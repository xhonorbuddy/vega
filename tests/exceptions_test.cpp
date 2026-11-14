#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
extern "C" {
#include "lua.h"
#include "lauxlib.h"
}
import grid.exceptions;
import grid.breakpoint;
import grid.lua_registration;
import grid.api;

bool raise_and_catch(DWORD code, DWORD count = 0, const ULONG_PTR* arguments = nullptr) {
    __try { RaiseException(code, 0, count, arguments); }
    __except (GetExceptionCode() == code ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
    return false;
}
int main() {
    using namespace grid::exceptions;
    if (!start() || !start()) return 1;
    OutputDebugStringA("[grid test] debugger notification\n");
    if (observed_count() != 0) return 2;
    if (!raise_and_catch(0xE0420001) || observed_count() != 1) return 3;
    const ULONG_PTR access[] = {1, 0x1234};
    if (!raise_and_catch(EXCEPTION_ACCESS_VIOLATION, 2, access) || observed_count() != 2) return 4;
    stop();
    stop();
    if (!raise_and_catch(0xE0420001) || observed_count() != 2) return 5;
    if (!start() || observed_count() != 0) return 6;
    if (!raise_and_catch(0xE0420001) || observed_count() != 1) return 7;
    // Unrelated breakpoints must still reach SEH rather than the Lua callback.
    if (!raise_and_catch(EXCEPTION_BREAKPOINT) || observed_count() != 2) return 8;
    auto* image = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!image) return 9;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x100;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image + 0x100);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.SizeOfImage = 0x2000;
    auto* section = IMAGE_FIRST_SECTION(nt);
    section->Characteristics = IMAGE_SCN_MEM_EXECUTE;
    section->VirtualAddress = 0x1000;
    section->Misc.VirtualSize = 0x1000;
    const unsigned char fixture[] = {0xC3,0xCC,0xCC,0xCC,0xCC,0x48};
    for (unsigned i = 0; i < 19; ++i) std::memcpy(image + 0x1000 + 16*i, fixture, sizeof(fixture));
    DWORD old{};
    if (!VirtualProtect(image + 0x1000, 0x1000, PAGE_EXECUTE_READ, &old)) return 10;
    const auto base = reinterpret_cast<std::uintptr_t>(image);
    if (grid::breakpoint::resolve(base)) return 11; // Require at least 20.
    if (!VirtualProtect(image + 0x1000, 0x1000, PAGE_READWRITE, &old)) return 12;
    for (unsigned i = 19; i < 101; ++i) std::memcpy(image + 0x1000 + 16*i, fixture, sizeof(fixture));
    if (!VirtualProtect(image + 0x1000, 0x1000, PAGE_EXECUTE_READ, &old)) return 13;
    FlushInstructionCache(GetCurrentProcess(), image + 0x1000, 0x1000);
    if (!grid::breakpoint::resolve(base) || grid::breakpoint::size() != 100) return 14;
    lua_State* L = luaL_newstate();
    if (!L) return 15;
    if (!grid::lua_registration::register_api(L, "C", grid::api::functions)) return 16;
    lua_pop(L, 1);
    if (grid::breakpoint::available() != 98) return 17;
    if (!grid::lua_registration::register_api(L, "C", grid::api::functions)) return 18;
    lua_pop(L, 1);
    if (grid::breakpoint::available() != 98) return 19; // Cached mappings reused.
    for (int i = 0; i < 100; ++i) {
        if (luaL_dostring(L, "return C.PrintHere(), C.PrintThere()") ||
            std::strcmp(lua_tostring(L, -2), "here") || std::strcmp(lua_tostring(L, -1), "there")) return 20;
        lua_pop(L, 2);
    }
    // Fill the remaining slots without executing these synthetic callbacks.
    for (unsigned i = 0; i < 98; ++i)
        if (!grid::breakpoint::bind(0x10000 + i)) return 21;
    const luaL_Reg extra[] = {{"Extra", reinterpret_cast<lua_CFunction>(0x20000)}, {nullptr,nullptr}};
    const auto top = lua_gettop(L);
    if (grid::lua_registration::register_api(L, "Overflow", extra) || lua_gettop(L) != top) return 22;
    lua_getglobal(L, "Overflow");
    if (!lua_isnil(L, -1)) return 23;
    lua_pop(L, 1);
    if (!grid::lua_registration::register_api(L, "Alias", grid::api::functions)) return 24;
    lua_pop(L, 1);
    if (luaL_dostring(L, "return Alias.PrintThere()") || std::strcmp(lua_tostring(L, -1), "there")) return 25;
    lua_pop(L, 1);
    if (observed_count() != 2) return 14;
    lua_close(L);
    stop();
    VirtualFree(image, 0, MEM_RELEASE);
    std::puts("Exception tests passed (monitor lifecycle, unrelated breakpoints, pool limits, cached registration, exhaustion, two Lua callbacks)");
}
