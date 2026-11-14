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
    const unsigned char fixture[] = {0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0x48,0x83,0xEC,0x28,0x48,0x8B,0xD1,0x48,0x85,0xC9,0x75,0x07,0xC6,0x44,0x24,0x30,0x63,0xEB,0x2F};
    std::memcpy(image + 0x1000, fixture, sizeof(fixture));
    DWORD old{};
    if (!VirtualProtect(image + 0x1000, 0x1000, PAGE_EXECUTE_READ, &old)) return 10;
    FlushInstructionCache(GetCurrentProcess(), image + 0x1000, sizeof(fixture));
    const auto base = reinterpret_cast<std::uintptr_t>(image);
    if (!grid::breakpoint::resolve(base) || grid::breakpoint::address() != base + 0x1001) return 11;
    lua_State* L = luaL_newstate();
    if (!L) return 12;
    lua_register(L, "C", reinterpret_cast<lua_CFunction>(grid::breakpoint::address()));
    for (int i = 0; i < 100; ++i) {
        if (luaL_dostring(L, "return C()") || std::strcmp(lua_tostring(L, -1), "here")) return 13;
        lua_pop(L, 1);
    }
    if (observed_count() != 2) return 14;
    lua_close(L);
    stop();
    VirtualFree(image, 0, MEM_RELEASE);
    std::puts("Exception tests passed (monitor lifecycle, unrelated breakpoints, 100 Lua INT3 hops)");
}
