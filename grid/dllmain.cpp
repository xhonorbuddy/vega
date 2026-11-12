// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstring>
#include <cstdio>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lobject.h"
#include "lstate.h"
#include "ltable.h"
}

import grid.patch;
import grid.wow_api;

#pragma comment(lib, "lua-5.1.lib")

#define EXCEPTION_INTERNAL_EXCEPTION 0xC00000E5

static volatile LONG g_verdict_mode = 0;

using lua_checkstack_t = int(__fastcall*)(lua_State*, int);
using lua_pushlstring_t = void(__fastcall*)(lua_State*, const char*, size_t);
using lua_createtable_t = void(__fastcall*)(lua_State*, int, int);
using lua_pushcclosure_t = void(__fastcall*)(lua_State*, lua_CFunction, int);
using lua_settable_t = void(__fastcall*)(lua_State*, int);

namespace {

    constexpr int kGlobalsIndex = -10002;
    constexpr UINT kRegisterMessage = WM_APP + 0x51;

    lua_checkstack_t g_checkstack = nullptr;
    lua_pushlstring_t g_pushlstring = nullptr;
    lua_createtable_t g_createtable = nullptr;
    lua_pushcclosure_t g_pushcclosure = nullptr;
    lua_settable_t g_settable = nullptr;

    uintptr_t g_wowBase = 0;
    DWORD g_game_thread = 0;
    lua_State* g_client_lua = nullptr;
    WNDPROC g_old_proc = nullptr;
    volatile LONG g_register_started = 0;
    volatile LONG g_shutting_down = 0;
    PVOID g_veh_handle = nullptr;
    HWND g_window = nullptr;

    void log_line(const char* text)
    {
        char path[MAX_PATH]{};
        char line[400]{};

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

} // namespace

int test(lua_State* L)
{
    log_line("[grid] test called");

    if (g_pushlstring != nullptr) {
        g_pushlstring(L, "hello", 5);
    }

    log_line("[grid] test returning");
    return 1;
}

luaL_Reg api[] =
{
    { "AFK",					test },
    { NULL, NULL },
};

static void register_with_client(lua_State* L)
{
    if (L == nullptr ||
        g_checkstack == nullptr ||
        g_pushlstring == nullptr ||
        g_createtable == nullptr ||
        g_pushcclosure == nullptr ||
        g_settable == nullptr) {
        return;
    }

    if (g_checkstack(L, 4) == 0) {
        return;
    }

    g_pushlstring(L, "C", 1);
    int count = 0;
    for (const luaL_Reg* entry = api; entry->name != nullptr; ++entry) ++count;
    for (const luaL_Reg* entry = grid::wow_api::functions; entry->name != nullptr; ++entry) ++count;
    g_createtable(L, 0, count);
    const auto add_fields = [L](const luaL_Reg* entries) {
        for (const luaL_Reg* entry = entries; entry->name != nullptr; ++entry) {
            g_pushlstring(L, entry->name, std::strlen(entry->name));
            g_pushcclosure(L, entry->func, 0);
            g_settable(L, -3);
        }
    };
    add_fields(api);
    add_fields(grid::wow_api::functions);
    g_settable(L, kGlobalsIndex);
}

// Runs once, on a thread owned by the game.
static void register_once()
{
    if (InterlockedCompareExchange(&g_register_started, 1, 0) != 0) {
        log_line("[grid] registration already started");
        return;
    }

    log_line("[grid] register_once");

    if (g_pushlstring == nullptr) {
        g_pushlstring = reinterpret_cast<lua_pushlstring_t>(g_wowBase + 0x38D2DB0);
    }

    auto* slot = reinterpret_cast<lua_State**>(g_wowBase + 0x6A320E8);

    MEMORY_BASIC_INFORMATION slotInfo{};

    if (VirtualQuery(slot, &slotInfo, sizeof(slotInfo)) == 0 ||
        slotInfo.State != MEM_COMMIT ||
        (slotInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        log_line("[grid] slot not mapped");
        return;
    }

    lua_State* L = *slot;

    char message[200]{};
    wsprintfA(message, "[grid] L=%p", static_cast<void*>(L));
    log_line(message);

    if (L == nullptr) {
        return;
    }

    const auto sentinel = g_wowBase + 0x3AEF000;
    MEMORY_BASIC_INFORMATION sentinelInfo{};

    const bool sentinelUsable =
        VirtualQuery(reinterpret_cast<const void*>(sentinel), &sentinelInfo, sizeof(sentinelInfo)) != 0 &&
        sentinelInfo.State == MEM_COMMIT &&
        (sentinelInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;

    log_line(sentinelUsable ? "[grid] using library registration" : "[grid] using client registration");
    grid::wow_api::set_game_thread(GetCurrentThreadId());

    if (sentinelUsable) {
        luaH_set_dummynode(reinterpret_cast<Node*>(sentinel));
        luaL_register(L, "C", api);
        luaL_register(L, nullptr, grid::wow_api::functions);
    }
    else {
        g_checkstack = reinterpret_cast<lua_checkstack_t>(g_wowBase + 0x38D14F0);
        g_createtable = reinterpret_cast<lua_createtable_t>(g_wowBase + 0x38D1750);
        g_pushcclosure = reinterpret_cast<lua_pushcclosure_t>(g_wowBase + 0x38D2AF0);
        g_settable = reinterpret_cast<lua_settable_t>(g_wowBase + 0x38D3BB0);

        register_with_client(L);
    }

    log_line("[grid] registration done");
    g_client_lua = L;

    /* Verify the Lua side end to end: fetch C.AFK and call it. */
    lua_getfield(L, LUA_GLOBALSINDEX, "C");

    if (!lua_istable(L, -1)) {
        log_line("[grid] self-test: global C is not a table");
        lua_pop(L, 1);
        return;
    }

    lua_getfield(L, -1, "AFK");

    if (!lua_isfunction(L, -1)) {
        log_line("[grid] self-test: C.AFK is not a function");
        lua_pop(L, 2);
        return;
    }

    if (lua_pcall(L, 0, 1, 0) != 0) {
        const char* error = lua_tostring(L, -1);
        char message[260]{};
        wsprintfA(message, "[grid] self-test: C.AFK() error: %s", error != nullptr ? error : "?");
        log_line(message);
        lua_pop(L, 2);
        return;
    }

    const char* result = lua_tostring(L, -1);
    char output[260]{};
    wsprintfA(output, "[grid] self-test: C.AFK() -> %s", result != nullptr ? result : "<non-string>");
    log_line(output);
    lua_pop(L, 2);
}

LRESULT CALLBACK register_wndproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (msg == kRegisterMessage) {
        log_line("[grid] window trigger");

        register_once();

        if (g_old_proc != nullptr) {
            SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_old_proc));
        }

        return 0;
    }

    return CallWindowProcW(g_old_proc, hwnd, msg, wparam, lparam);
}

namespace {

    HWND find_game_window()
    {
        struct Search {
            DWORD pid;
            HWND best;
            LONG area;
        } search{ GetCurrentProcessId(), nullptr, 0 };

        EnumWindows([](HWND hwnd, LPARAM param) -> BOOL {
            auto* state = reinterpret_cast<Search*>(param);

            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);

            if (pid != state->pid || !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr) {
                return TRUE;
            }

            /* The diagnostics console lives in this process too. */
            wchar_t class_name[64]{};
            GetClassNameW(hwnd, class_name, 64);

            if (lstrcmpiW(class_name, L"ConsoleWindowClass") == 0) {
                return TRUE;
            }

            RECT rect{};

            if (GetClientRect(hwnd, &rect) == FALSE) {
                return TRUE;
            }

            const LONG area = (rect.right - rect.left) * (rect.bottom - rect.top);

            if (state->best == nullptr || area > state->area) {
                state->best = hwnd;
                state->area = area;
            }

            return TRUE;
        }, reinterpret_cast<LPARAM>(&search));

        return search.best;
    }

} // namespace
// ---------------------------------------------------------------------------
// Hook RaiseException itself. Callers that cached its address still hit this,
// because the function body is patched, not an import slot. For the loader's
// security code we simply return to the caller (as if RaiseException finished);
// every other code is forwarded to ntdll!RtlRaiseException.
using raise_exception_t = void(__fastcall*)(DWORD, DWORD, DWORD, const ULONG_PTR*);

static BYTE* g_raise_target = nullptr;
static BYTE g_raise_original[12]{};
static raise_exception_t g_rtl_raise = nullptr;

static void __fastcall hook_raise_exception(DWORD code, DWORD flags, DWORD nargs, const ULONG_PTR* args)
{
    if (code == EXCEPTION_INTERNAL_EXCEPTION) {
        static volatile LONG count = 0;

        if (InterlockedIncrement(&count) <= 5) {
            log_line("[grid] suppressed security raise; returning to caller");
        }

        return; /* ret pops the return address pushed by the caller's call */
    }

    if (g_rtl_raise != nullptr) {
        g_rtl_raise(code, flags, nargs, args);
    }

    ExitThread(1);
}

static void install_raise_hook()
{
    auto* target = reinterpret_cast<BYTE*>(GetProcAddress(
        GetModuleHandleW(L"kernelbase.dll"), "RaiseException"));

    g_rtl_raise = reinterpret_cast<raise_exception_t>(GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlRaiseException"));

    if (target == nullptr || g_rtl_raise == nullptr) {
        log_line("[grid] RaiseException hook: symbols not found");
        return;
    }

    std::memcpy(g_raise_original, target, sizeof(g_raise_original));

    DWORD old_protect = 0;

    if (!VirtualProtect(target, sizeof(g_raise_original), PAGE_EXECUTE_READWRITE, &old_protect)) {
        log_line("[grid] RaiseException hook: VirtualProtect failed");
        return;
    }

    target[0] = 0x48; /* mov rax, imm64 */
    target[1] = 0xB8;
    *reinterpret_cast<void**>(target + 2) = reinterpret_cast<void*>(&hook_raise_exception);
    target[10] = 0xFF; /* jmp rax */
    target[11] = 0xE0;

    DWORD ignored = 0;
    VirtualProtect(target, sizeof(g_raise_original), old_protect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(g_raise_original));

    g_raise_target = target;

    char message[160]{};
    wsprintfA(message, "[grid] hooked RaiseException at %p", reinterpret_cast<void*>(target));
    log_line(message);
}

static void remove_raise_hook()
{
    if (g_raise_target == nullptr) {
        return;
    }

    DWORD old_protect = 0;

    if (VirtualProtect(g_raise_target, sizeof(g_raise_original), PAGE_EXECUTE_READWRITE, &old_protect)) {
        std::memcpy(g_raise_target, g_raise_original, sizeof(g_raise_original));

        DWORD ignored = 0;
        VirtualProtect(g_raise_target, sizeof(g_raise_original), old_protect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), g_raise_target, sizeof(g_raise_original));
    }

    g_raise_target = nullptr;
    log_line("[grid] restored RaiseException");
}
// Diagnostic: the verification code calls API thunks stored in the loader's
// .rdata table. Report what each of the interesting slots points at so the API
// can be identified from the module + offset.
static void probe_thunk_slots()
{
    HMODULE loader = GetModuleHandleW(L"wow_loader.dll");

    if (loader == nullptr) {
        return;
    }

    static const unsigned offsets[] = { 0x2070940, 0x2070970, 0x2070AB8 };

    for (unsigned offset : offsets) {
        auto* slot = reinterpret_cast<void**>(reinterpret_cast<BYTE*>(loader) + offset);
        MEMORY_BASIC_INFORMATION info{};

        if (VirtualQuery(slot, &info, sizeof(info)) == 0 || info.State != MEM_COMMIT) {
            continue;
        }

        const void* value = *slot;

        if (value == nullptr) {
            continue;
        }

        MEMORY_BASIC_INFORMATION target{};
        wchar_t module_name[MAX_PATH]{};
        const void* module_base = nullptr;

        if (VirtualQuery(value, &target, sizeof(target)) != 0 && target.AllocationBase != nullptr) {
            module_base = target.AllocationBase;

            if (GetModuleFileNameW(static_cast<HMODULE>(const_cast<void*>(module_base)),
                    module_name, MAX_PATH) == 0) {
                module_name[0] = L'\0';
            }
        }

        char narrow_name[MAX_PATH]{};
        if (module_name[0] != L'\0') {
            WideCharToMultiByte(CP_ACP, 0, module_name, -1, narrow_name, MAX_PATH, nullptr, nullptr);
        }

        char message[420]{};
        wsprintfA(
            message,
            "[grid] slot 0x%X = %p (%s + 0x%I64x)",
            offset,
            value,
            narrow_name[0] != '\0' ? narrow_name : "unmapped",
            module_base != nullptr
                ? static_cast<unsigned long long>(reinterpret_cast<BYTE*>(const_cast<void*>(value)) - reinterpret_cast<BYTE*>(const_cast<void*>(module_base)))
                : 0ull
        );
        log_line(message);

        /* The thunk target: protection and first bytes tell us whether it can be
           rewritten (the loader locks its own .text with SEC_NO_CHANGE, but the
           JIT thunks live in the heap). */
        if (target.State == MEM_COMMIT && (target.Protect & PAGE_NOACCESS) == 0) {
            char thunk[260]{};
            wsprintfA(thunk, "[grid] thunk 0x%X: state=0x%x protect=0x%x", offset, target.State, target.Protect);
            log_line(thunk);

            const auto* bytes = reinterpret_cast<const BYTE*>(value);
            char dump[160]{};
            int used = wsprintfA(dump, "[grid] thunk 0x%X bytes:", offset);

            for (int i = 0; i < 12; ++i) {
                used += wsprintfA(dump + used, " %02x", bytes[i]);
            }

            log_line(dump);
        }
    }
}
static bool force_writable(void* address, SIZE_T size, DWORD* restore);
static void restore_protection(void* address, SIZE_T size, DWORD protect);
// The loader's .text is locked (SEC_NO_CHANGE-like), but the per-call thunks are
// ordinary heap pages. The raise thunk is reached through slot 0x2070940; making
// it return neutralises the security raise from inside the loader's own call.
static void* g_raise_thunk = nullptr;
static BYTE g_raise_thunk_original = 0;

static void neutralise_raise_thunk()
{
    HMODULE loader = GetModuleHandleW(L"wow_loader.dll");

    if (loader == nullptr) {
        return;
    }

    auto* slot = reinterpret_cast<void**>(reinterpret_cast<BYTE*>(loader) + 0x2070940);
    void* thunk = *slot;

    if (thunk == nullptr) {
        log_line("[grid] raise thunk: slot empty");
        return;
    }

    MEMORY_BASIC_INFORMATION info{};

    if (VirtualQuery(thunk, &info, sizeof(info)) == 0 || info.State != MEM_COMMIT) {
        log_line("[grid] raise thunk: not committed");
        return;
    }

    const auto* bytes = reinterpret_cast<const BYTE*>(thunk);

    if (!(bytes[0] == 0x48 && bytes[1] == 0xB8)) {
        log_line("[grid] raise thunk: unexpected prologue");
        return;
    }

    DWORD old_protect = 0;

    if (!force_writable(thunk, 1, &old_protect)) {
        char error[160]{};
        wsprintfA(error, "[grid] raise thunk: not writable (protect=0x%x)", info.Protect);
        log_line(error);
        return;
    }

    g_raise_thunk_original = bytes[0];
    const BYTE ret_instruction = 0xC3;
    std::memcpy(thunk, &ret_instruction, 1);
    restore_protection(thunk, 1, old_protect != 0 ? old_protect : PAGE_EXECUTE_READ);
    FlushInstructionCache(GetCurrentProcess(), thunk, 1);

    g_raise_thunk = thunk;

    char message[160]{};
    wsprintfA(message, "[grid] raise thunk %p patched to ret", thunk);
    log_line(message);
}

static void restore_raise_thunk()
{
    if (g_raise_thunk == nullptr) {
        return;
    }

    DWORD old_protect = 0;

    if (force_writable(g_raise_thunk, 1, &old_protect)) {
        std::memcpy(g_raise_thunk, &g_raise_thunk_original, 1);
        restore_protection(g_raise_thunk, 1, old_protect != 0 ? old_protect : PAGE_EXECUTE_READ);
        FlushInstructionCache(GetCurrentProcess(), g_raise_thunk, 1);
    }

    g_raise_thunk = nullptr;
}

static void restore_protection(void* address, SIZE_T size, DWORD protect);

// Neutralise the security raise without touching the client: the verification
// block calls RaiseException through a thunk at loader+0xF329F3. NOP that call
// so the block continues instead of raising. Loader code is not covered by the
// client .text integrity check, and it is restored on detach.
static BYTE* g_raise_call = nullptr;
static BYTE g_raise_call_original[6]{};

static void neutralise_raise_call()
{
    HMODULE loader = GetModuleHandleW(L"wow_loader.dll");

    if (loader == nullptr) {
        log_line("[grid] raise-call patch: loader not loaded");
        return;
    }

    auto* call = reinterpret_cast<BYTE*>(loader) + 0xF329F3;

    /* expect: call qword ptr [rip+0x113df47] */
    if (!(call[0] == 0xFF && call[1] == 0x15)) {
        log_line("[grid] raise-call patch: unexpected bytes, skipping");
        return;
    }

    std::memcpy(g_raise_call_original, call, sizeof(g_raise_call_original));

    MEMORY_BASIC_INFORMATION page{};
    VirtualQuery(call, &page, sizeof(page));

    char probe[220]{};
    wsprintfA(probe, "[grid] raise-call page: state=0x%x protect=0x%x", page.State, page.Protect);
    log_line(probe);

    DWORD old_protect = 0;

    if (!force_writable(call, sizeof(g_raise_call_original), &old_protect)) {
        char error[160]{};
        wsprintfA(error, "[grid] raise-call patch: no writable mapping (err=%lu)", GetLastError());
        log_line(error);
        return;
    }

    std::memset(call, 0x90, sizeof(g_raise_call_original));

    DWORD restore = old_protect != 0 ? old_protect : (page.Protect != 0 ? page.Protect : PAGE_EXECUTE_READ);
    restore_protection(call, sizeof(g_raise_call_original), restore);
    FlushInstructionCache(GetCurrentProcess(), call, sizeof(g_raise_call_original));

    g_raise_call = call;
    log_line("[grid] neutralised security raise call at loader+0xF329F3");
}

static void restore_raise_call()
{
    if (g_raise_call == nullptr) {
        return;
    }

    DWORD old_protect = 0;

    if (VirtualProtect(g_raise_call, sizeof(g_raise_call_original), PAGE_EXECUTE_READWRITE, &old_protect)) {
        std::memcpy(g_raise_call, g_raise_call_original, sizeof(g_raise_call_original));

        DWORD ignored = 0;
        VirtualProtect(g_raise_call, sizeof(g_raise_call_original), old_protect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), g_raise_call, sizeof(g_raise_call_original));
    }

    g_raise_call = nullptr;
}
// Memory-protection helpers. grid.dll is manually mapped, so its IAT is
// reconstructed by our own loader; resolve the protection APIs dynamically and
// fall back to NtProtectVirtualMemory if the Win32 path refuses.
using nt_protect_t = LONG(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static nt_protect_t g_nt_protect = nullptr;

static bool force_writable(void* address, SIZE_T size, DWORD* restore)
{
    using virtual_protect_t = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

    static auto protect = reinterpret_cast<virtual_protect_t>(
        GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualProtect"));

    if (protect == nullptr) {
        protect = reinterpret_cast<virtual_protect_t>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect"));
    }

    DWORD old = 0;

    if (protect != nullptr) {
        if (protect(address, size, PAGE_EXECUTE_READWRITE, &old) != FALSE) {
            *restore = old;
            return true;
        }

        if (protect(address, size, PAGE_READWRITE, &old) != FALSE) {
            *restore = old;
            return true;
        }
    }

    if (g_nt_protect == nullptr) {
        g_nt_protect = reinterpret_cast<nt_protect_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory"));
    }

    if (g_nt_protect != nullptr) {
        PVOID base = address;
        SIZE_T region = size;
        ULONG previous = 0;

        if (g_nt_protect(GetCurrentProcess(), &base, &region, PAGE_EXECUTE_READWRITE, &previous) >= 0) {
            *restore = previous;
            return true;
        }
    }

    return false;
}

static void restore_protection(void* address, SIZE_T size, DWORD protect)
{
    if (protect == 0) {
        return;
    }

    using virtual_protect_t = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

    static auto protect_fn = reinterpret_cast<virtual_protect_t>(
        GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualProtect"));

    DWORD ignored = 0;

    if (protect_fn != nullptr) {
        protect_fn(address, size, protect, &ignored);
        return;
    }

    if (g_nt_protect != nullptr) {
        PVOID base = address;
        SIZE_T region = size;
        ULONG previous = 0;
        g_nt_protect(GetCurrentProcess(), &base, &region, protect, &previous);
    }
}
// Experimental VEH modelled on the user's earlier working handler: log every
// exception code and continue on the codes that old build swallowed. The old
// condition ended with `... = EXCEPTION_INTERNAL_EXCEPTION` (assignment), which
// evaluated true for every exception, so it effectively continued on all of them.
static void print_console(const char* text)
{
    std::printf("%s\n", text);
    std::fflush(stdout);
}

// VEH matching the user's earlier working handler: continue on the probe codes
// and the internal-error raise, and print every exception in an allocated
// console. A repeat guard prevents an unbounded re-raise loop at one address.
// The unloader cannot reliably run DllMain(DLL_PROCESS_DETACH) inside the game,
// so the VEH handler must not live in this image. This builds an equivalent
// handler as self-contained machine code in a separate RWX allocation that
// survives the image being freed. It mirrors the stable configuration:
// continue on breakpoint / internal error / illegal instruction / divide by zero,
// pass everything else (including assertion failures) to the client.
static PVOID build_standalone_veh()
{
    /* 48 8B 01        mov rax, [rcx]        ; rax = ExceptionRecord
       8B 00           mov eax, [rax]        ; eax = ExceptionCode
       3D E5 00 00 C0  cmp eax, 0xC00000E5
       74 1B           je  +0x1B
       3D 03 00 00 80  cmp eax, 0x80000003
       74 14           je  +0x14
       3D 1D 00 00 C0  cmp eax, 0xC000001D
       74 0D           je  +0x0D
       3D 94 00 00 C0  cmp eax, 0xC0000094
       74 06           je  +0x06
       B8 00 00 00 00  mov eax, 0             ; EXCEPTION_CONTINUE_SEARCH
       C3              ret
       B8 01 00 00 00  mov eax, 1             ; EXCEPTION_CONTINUE_EXECUTION
       C3              ret */

    static const unsigned char code[] = {
        0x48, 0x8B, 0x01,
        0x8B, 0x00,
        0x3D, 0xE5, 0x00, 0x00, 0xC0,
        0x74, 0x1B,
        0x3D, 0x03, 0x00, 0x00, 0x80,
        0x74, 0x14,
        0x3D, 0x1D, 0x00, 0x00, 0xC0,
        0x74, 0x0D,
        0x3D, 0x94, 0x00, 0x00, 0xC0,
        0x74, 0x06,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3,
    };

    auto* page = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    if (page == nullptr) {
        return nullptr;
    }

    std::memcpy(page, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), page, sizeof(code));
    return page;
}
static LONG NTAPI legacy_veh(EXCEPTION_POINTERS* ep)
{
    const DWORD code = ep->ExceptionRecord->ExceptionCode;

    static volatile LONG counts[4]{};
    static const DWORD codes[4] = { 0x80000003u, 0xC00000E5u, 0xC000001Du, 0xC0000094u };

    for (int i = 0; i < 4; ++i) {
        if (code == codes[i] && InterlockedIncrement(&counts[i]) <= 3) {
            char message[160]{};
            wsprintfA(message, "[grid] VEH: code=0x%08lX at %p", code,
                ep->ExceptionRecord->ExceptionAddress);
            log_line(message);
        }
    }

    if (code == EXCEPTION_BREAKPOINT ||
        code == EXCEPTION_INTERNAL_EXCEPTION ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION ||
        code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
// Diagnostic: hardware execution breakpoint on the verdict site
// (loader+0xF30ED9, the `cmp eax, 0x102`). Read-only observation: the handler
// logs the compared value and the surrounding state, then lets the instruction
// run. Enabled only when %TEMP%\grid_verdict_log.flag exists.
static uintptr_t g_verdict_target = 0;
static volatile LONG g_verdict_hits = 0;
static volatile LONG g_state_mode = 0;
static volatile LONG g_raise_mode = 0;
static volatile LONG g_raise_hits = 0;
static volatile LONG g_raise_fix = 0;
static uintptr_t g_loader_base = 0;
static DWORD g_seen_states[512]{};
static volatile LONG g_seen_count = 0;

static LONG NTAPI verdict_veh(EXCEPTION_POINTERS* ep)
{
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        g_verdict_target != 0 &&
        reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress) == g_verdict_target) {
        CONTEXT* ctx = ep->ContextRecord;



        if (g_raise_fix != 0) {
            *reinterpret_cast<DWORD*>(ctx->Rsp + 0x2C) = 0x1CACE636u;
            ctx->Rip = g_loader_base + 0xF30A14;

            if (InterlockedIncrement(&g_raise_hits) <= 5) {
                log_line("[grid] raise block diverted to the pass state");
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (g_raise_mode != 0 && InterlockedIncrement(&g_raise_hits) <= 8) {
            const DWORD raise_state = *reinterpret_cast<DWORD*>(ctx->Rsp + 0x2C);

            char raise_line[320]{};
            wsprintfA(raise_line,
                "[grid] raise-hit: state=0x%08lX rax=0x%I64x rcx=0x%I64x rdx=0x%08lX r8=0x%08lX r9=0x%I64x",
                raise_state, ctx->Rax, ctx->Rcx,
                static_cast<unsigned long>(ctx->Rdx & 0xFFFFFFFFu),
                static_cast<unsigned long>(ctx->R8 & 0xFFFFFFFFu), ctx->R9);
            log_line(raise_line);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (g_state_mode != 0) {
            static DWORD last_state = 0;
            static volatile LONG changes = 0;

            const DWORD state_value = *reinterpret_cast<DWORD*>(ctx->Rsp + 0x2C);

            if (state_value != last_state) {
                last_state = state_value;

                if (InterlockedIncrement(&changes) <= 200) {
                    char state_line[96]{};
                    wsprintfA(state_line, "[grid] state-chg: 0x%08lX", state_value);
                    log_line(state_line);
                }
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (InterlockedIncrement(&g_verdict_hits) <= 20) {
            const auto state = *reinterpret_cast<DWORD*>(ctx->Rsp + 0x2C);
            const auto handle_slot = *reinterpret_cast<uint64_t*>(ctx->Rsp + 0x88);

            char message[320]{};
            wsprintfA(message,
                "[grid] verdict: eax=0x%08lX rcx=0x%I64x rdx=0x%08lX r8=0x%08lX r9=0x%I64x state=0x%08lX slot88=0x%I64x",
                static_cast<unsigned long>(ctx->Rax & 0xFFFFFFFFu),
                ctx->Rcx, static_cast<unsigned long>(ctx->Rdx & 0xFFFFFFFFu),
                static_cast<unsigned long>(ctx->R8 & 0xFFFFFFFFu),
                ctx->R9, state, handle_slot);
            log_line(message);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void install_verdict_logger()
{
    wchar_t temp[MAX_PATH]{};

    if (GetTempPathW(MAX_PATH, temp) == 0) {
        return;
    }

    wchar_t verdict_flag[MAX_PATH]{};
    wchar_t state_flag[MAX_PATH]{};
    wsprintfW(verdict_flag, L"%sgrid_verdict_log.flag", temp);
    wsprintfW(state_flag, L"%sgrid_state_log.flag", temp);

    wchar_t raise_flag[MAX_PATH]{};
    wsprintfW(raise_flag, L"%sgrid_raise_log.flag", temp);
    wchar_t fix_flag[MAX_PATH]{};
    wsprintfW(fix_flag, L"%sgrid_raise_fix.flag", temp);
    const bool fix_enabled = GetFileAttributesW(fix_flag) != INVALID_FILE_ATTRIBUTES;
    const bool raise_enabled = GetFileAttributesW(raise_flag) != INVALID_FILE_ATTRIBUTES;
    const bool verdict_enabled = GetFileAttributesW(verdict_flag) != INVALID_FILE_ATTRIBUTES;
    const bool state_enabled = GetFileAttributesW(state_flag) != INVALID_FILE_ATTRIBUTES;

    if (!verdict_enabled && !state_enabled && !raise_enabled && !fix_enabled) {
        return;
    }

    HMODULE loader = GetModuleHandleW(L"wow_loader.dll");

    if (loader == nullptr) {
        return;
    }

    if (fix_enabled) {
        g_verdict_target = reinterpret_cast<uintptr_t>(loader) + 0xF328CF;
        g_raise_fix = 1;
        g_loader_base = reinterpret_cast<uintptr_t>(loader);
        log_line("[grid] raise-block divert enabled");
    }
    else if (raise_enabled) {
        g_verdict_target = reinterpret_cast<uintptr_t>(loader) + 0xF328CF;
        g_raise_mode = 1;
        log_line("[grid] raise-block logger selected");
    }
    else if (state_enabled) {
        g_verdict_target = reinterpret_cast<uintptr_t>(loader) + 0xF30A14;
        g_state_mode = 1;
        log_line("[grid] dispatcher state logger selected");
    }
    else {
        g_verdict_target = reinterpret_cast<uintptr_t>(loader) + 0xF30ED9;
    }

    g_verdict_mode = 1;

    AddVectoredExceptionHandler(1, verdict_veh);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    const DWORD pid = GetCurrentProcessId();
    const DWORD self = GetCurrentThreadId();
    unsigned armed = 0;

    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == self) {
                continue;
            }

            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                FALSE, entry.th32ThreadID);

            if (thread == nullptr) {
                continue;
            }

            if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
                CloseHandle(thread);
                continue;
            }

            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (GetThreadContext(thread, &context)) {
                context.Dr0 = g_verdict_target;
                context.Dr7 |= 0x1;

                if (SetThreadContext(thread, &context)) {
                    ++armed;
                }
            }

            ResumeThread(thread);
            CloseHandle(thread);
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    char message[140]{};
    wsprintfA(message, "[grid] verdict logger armed on %u thread(s) at %p", armed,
        reinterpret_cast<void*>(g_verdict_target));
    log_line(message);
}
// Anti-debug countermeasures for the loader's PEB checks.
// x64 PEB: +0x02 BeingDebugged, +0xBC NtGlobalFlag.
// Also clears the heap debug flags the loader may inspect.
static void defeat_antidebug()
{
    auto* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));

    if (peb != nullptr) {
        peb[0x02] = 0;

        *reinterpret_cast<DWORD*>(peb + 0xBC) = 0;

        /* ProcessParameters->Flags: clear the "debugged" bit if present. */
        auto* params = *reinterpret_cast<BYTE**>(peb + 0x20);

        if (params != nullptr) {
            *reinterpret_cast<DWORD*>(params + 0x10) &= ~1u;
        }
    }

    log_line("[grid] anti-debug: PEB debug fields cleared");
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        log_line("[grid] attach");
        g_veh_handle = AddVectoredExceptionHandler(1, legacy_veh);
        install_verdict_logger();

                /* Per-patch kill switches so detection can be attributed without a
           rebuild: %TEMP%\grid_skip_disable.flag and \grid_skip_range.flag. */
        std::uint32_t patchMask = grid::patch::kPatchAll;

        {
            char flagPath[MAX_PATH]{};
            const DWORD flagLength = GetTempPathA(MAX_PATH, flagPath);

            if (flagLength != 0 && flagLength < MAX_PATH) {
                char probe[MAX_PATH]{};

                lstrcpyA(probe, flagPath);
                lstrcatA(probe, "grid_skip_disable.flag");

                if (GetFileAttributesA(probe) != INVALID_FILE_ATTRIBUTES) {
                    patchMask &= ~grid::patch::kPatchDisableFunction;
                    log_line("[grid] skipping the 0x1E6B40 patch");
                }

                lstrcpyA(probe, flagPath);
                lstrcatA(probe, "grid_skip_range.flag");

                if (GetFileAttributesA(probe) != INVALID_FILE_ATTRIBUTES) {
                    patchMask &= ~grid::patch::kPatchRangeCheck;
                    log_line("[grid] skipping the 0x338B5D patch");
                }
            }
        }

        const auto patchesApplied = grid::patch::install_client_patches(patchMask);

        char patchMessage[96]{};
        wsprintfA(patchMessage, "[grid] patches applied: %u", static_cast<unsigned>(patchesApplied));
        log_line(patchMessage);

        g_wowBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

        // install_raise_hook();  // disabled: loader restores it; NOP test only
        probe_thunk_slots();
        neutralise_raise_thunk();


        g_pushlstring = reinterpret_cast<lua_pushlstring_t>(g_wowBase + 0x38D2DB0);

        HWND window = find_game_window();

        if (window != nullptr) {
            g_window = window;
            g_game_thread = GetWindowThreadProcessId(window, nullptr);

            g_old_proc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
                window,
                GWLP_WNDPROC,
                reinterpret_cast<LONG_PTR>(register_wndproc)
            ));

            const BOOL posted = PostMessageW(window, kRegisterMessage, 0, 0);

            char message[128]{};
            wsprintfA(
                message,
                "[grid] window hooked hwnd=%p old=%p posted=%d",
                static_cast<void*>(window),
                reinterpret_cast<void*>(g_old_proc),
                posted
            );
            log_line(message);

        }
        else {
            log_line("[grid] no window found");
        }

        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        log_line("[grid] detach: begin");

        {
            const std::size_t restored = grid::patch::restore_client_patches();
            char message[96]{};
            wsprintfA(message, "[grid] detach: client patches restored (%u)", static_cast<unsigned>(restored));
            log_line(message);
        }
        InterlockedExchange(&g_shutting_down, 1);

        if (g_veh_handle != nullptr) {
            RemoveVectoredExceptionHandler(g_veh_handle);
            g_veh_handle = nullptr;
            log_line("[grid] detach: veh removed");
        }

        if (g_window != nullptr && g_old_proc != nullptr) {
            SetWindowLongPtrW(g_window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(g_old_proc));
            g_window = nullptr;
            log_line("[grid] detach: window restored");
        }

        remove_raise_hook();
        restore_raise_thunk();
        log_line("[grid] detach: patches restored");
        break;
    default:
        break;
    }

    return TRUE;
}
