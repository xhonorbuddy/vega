// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lobject.h"
#include "lstate.h"
}

import grid.patch;

#pragma comment(lib, "lua-5.1.lib")

// The state slot is only meaningful once the client has created its Lua state.
// Reading a stale or half-initialised slot made luaL_register walk a bogus
// globals table (crash at luaH_get), so validate it before touching it.
namespace {

    // Lua objects live on the heap; modules and decoded client code live far
    // above this. 0x7ff6a14ce2b0 (a client code pointer) was accepted by an
    // earlier check because it sits in a private decoded page.
    constexpr uintptr_t kMaxHeapAddress = 0x00007ff000000000ull;

    bool readable_private(const void* pointer)
    {
        if (pointer == nullptr) {
            return false;
        }

        const auto address = reinterpret_cast<uintptr_t>(pointer);

        if (address >= kMaxHeapAddress) {
            return false;
        }

        MEMORY_BASIC_INFORMATION info{};

        if (VirtualQuery(pointer, &info, sizeof(info)) == 0) {
            return false;
        }

        if (info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
            return false;
        }

        return info.Type == MEM_PRIVATE;
    }

    bool plausible_lua_state(lua_State* L)
    {
        if (L == nullptr || (reinterpret_cast<uintptr_t>(L) & (alignof(void*) - 1)) != 0) {
            return false;
        }

        if (!readable_private(L)) {
            return false;
        }

        // A live thread state carries a small Lua status value.
        if (L->status > LUA_ERRERR) {
            return false;
        }

        // Its global state must be a heap object as well.
        if (!readable_private(L->l_G)) {
            return false;
        }

        // The globals table must exist and be a real table, not a code pointer.
        if (!ttistable(&L->l_gt)) {
            return false;
        }

        const Table* globals = hvalue(&L->l_gt);

        if (!readable_private(globals)) {
            return false;
        }

        // Table fields the hash walk depends on: a sane node size and, when the
        // table has a hash part, a readable node array.
        if (globals->lsizenode > 30) {
            return false;
        }

        if (globals->lsizenode != 0 && !readable_private(globals->node)) {
            return false;
        }

        return true;
    }

} // namespace

// Appends one line to %TEMP%\grid_lua.log. Used because a manually mapped DLL
// has no console and OutputDebugString needs a viewer attached.
static void log_line(const char* text)
{
    char path[MAX_PATH]{};
    char line[512]{};

    const DWORD length = GetTempPathA(MAX_PATH, path);

    if (length == 0 || length >= MAX_PATH) {
        return;
    }

    lstrcatA(path, "grid_lua.log");

    wsprintfA(line, "%s\r\n", text);

    HANDLE file = CreateFileA(
        path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD written = 0;
    static_cast<void>(WriteFile(file, line, lstrlenA(line), &written, nullptr));
    static_cast<void>(CloseHandle(file));
}

static void log_lua_state_rejected(const lua_State* L)
{
    char message[200]{};

    if (L == nullptr) {
        wsprintfA(message, "[grid] lua_State slot is null; registration skipped\n");
        OutputDebugStringA(message);
        return;
    }

    // Only read fields when the page is actually mapped: a rejected pointer is
    // exactly the case where dereferencing it is unsafe.
    if (!readable_private(L)) {
        wsprintfA(
            message,
            "[grid] lua_State %p is not a mapped heap object; registration skipped",
            static_cast<const void*>(L)
        );
        OutputDebugStringA(message);
        log_line(message);
        return;
    }

    const auto gt_value = reinterpret_cast<uintptr_t>(L->l_gt.value.gc);

    Table* globals = ttistable(&L->l_gt) ? hvalue(&L->l_gt) : nullptr;
    const unsigned lsizenode =
        readable_private(globals) ? static_cast<unsigned>(globals->lsizenode) : 0u;

    wsprintfA(
        message,
        "[grid] lua_State %p rejected (status 0x%02x, l_gt tt %d val %p, lsizenode %u)",
        static_cast<const void*>(L),
        static_cast<unsigned>(L->status),
        static_cast<int>(L->l_gt.tt),
        reinterpret_cast<const void*>(gt_value),
        lsizenode
    );

    OutputDebugStringA(message);
    log_line(message);
}

int test(lua_State* L)
{
    MessageBoxA(nullptr, "MB", "OOK", MB_OK);
    lua_pushstring(L, "hello");
    return 1;
}

luaL_Reg api[] =
{
    { "AFK",					test },
    { NULL, NULL },
};

// EXCEPTION HANDLER
LONG NTAPI veh(EXCEPTION_POINTERS* e) {
    if (e->ExceptionRecord->ExceptionAddress == (PVOID)((uintptr_t)GetModuleHandle(nullptr) + 0x4FD2BB)) {
        e->ContextRecord->Rip = (uintptr_t)test;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Registration can run before the client has finished creating its Lua state
// (lua_newstate allocates the block and the engine stores L only afterwards).
// In that case keep checking for a bounded window instead of giving up.
static volatile LONG g_stop_retry = 0;

static bool try_register_once(lua_State** slot)
{
    MEMORY_BASIC_INFORMATION info{};

    if (VirtualQuery(slot, &info, sizeof(info)) == 0 ||
        info.State != MEM_COMMIT ||
        (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }

    lua_State* L = *slot;

    if (!plausible_lua_state(L)) {
        return false;
    }

    luaL_register(L, "C", api);

    char message[256]{};
    wsprintfA(
        message,
        "[grid] registered; L=%p status=0x%02x l_gt=%p tt=%d",
        static_cast<const void*>(L),
        static_cast<unsigned>(L->status),
        static_cast<const void*>(L->l_gt.value.gc),
        static_cast<int>(L->l_gt.tt)
    );
    log_line(message);
    return true;
}

static DWORD WINAPI retry_register_thread(LPVOID parameter)
{
    auto* slot = static_cast<lua_State**>(parameter);

    for (int attempt = 0; attempt < 150; ++attempt) {
        if (InterlockedCompareExchange(&g_stop_retry, 0, 0) != 0) {
            return 0;
        }

        if (try_register_once(slot)) {
            return 0;
        }

        Sleep(100);
    }

    log_line("[grid] registration retry window expired");
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        AddVectoredExceptionHandler(1, veh);

        // Disable the client function this build targets (base + 0x1E6B40 -> ret).
        const auto patchesApplied = grid::patch::install_client_patches();

        if (patchesApplied == 0) {
            OutputDebugStringA("[grid] client patch was not applied\n");
        }

        const auto wowBase =
            reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

        auto* luaStateSlot =
            reinterpret_cast<lua_State**>(wowBase + 0x6A320E8);

        // Dereferencing the slot itself is only safe when that page is mapped:
        // in a process other than the client it usually is not.
        MEMORY_BASIC_INFORMATION slotInfo{};

        const bool slotReadable =
            VirtualQuery(luaStateSlot, &slotInfo, sizeof(slotInfo)) != 0 &&
            slotInfo.State == MEM_COMMIT &&
            (slotInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;

        if (!slotReadable)
        {
            log_line("[grid] lua_State slot is not mapped; registration skipped");
            break;
        }

        // Immediate attempt first; if the client is still bringing Lua up, keep
        // polling for a bounded window on a worker thread.
        if (!try_register_once(luaStateSlot)) {
            lua_State* L = *luaStateSlot;
            log_lua_state_rejected(L);

            HANDLE thread = CreateThread(
                nullptr,
                0,
                retry_register_thread,
                luaStateSlot,
                0,
                nullptr
            );

            if (thread != nullptr) {
                CloseHandle(thread);
                log_line("[grid] lua_State not ready; retrying in the background");
            }
        }

        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        if (ul_reason_for_call == DLL_PROCESS_DETACH) {
            InterlockedExchange(&g_stop_retry, 1);
            Sleep(200);
        }
        break;
    }
    return TRUE;
}

