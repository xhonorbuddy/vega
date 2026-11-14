module;
#include <windows.h>
#include <cstdint>
#include "luaconf.h"
#undef LUA_API
#define LUA_API extern "C"
#include "lua.h"
#include "lauxlib.h"

export module grid.registration;
import grid.client_lua;
import grid.api;
import grid.breakpoint;
import grid.lua_registration;

export namespace grid::registration {
bool start();
void stop();
}
namespace grid::registration {
namespace {
HWND window{};
WNDPROC previous{};
UINT message{};
LRESULT CALLBACK dispatch(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    const auto original = previous;
    if (msg != message) return CallWindowProcW(original, hwnd, msg, wparam, lparam);
    // Restore before entering Lua: this is a one-shot game-thread dispatch.
    stop();
    if (!breakpoint::resolve(reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)))) {
        OutputDebugStringA("[grid] fewer than 20 executable INT3 candidates found; registration skipped.\n");
        return 0;
    }
    if (!client_lua::resolve()) {
        OutputDebugStringA("[grid] Lua state signature missing, ambiguous, or unreadable; registration skipped.\n");
        return 0;
    }
    if (auto* L = client_lua::state()) {
        if (!lua_registration::register_api(L, "C", api::functions)) {
            OutputDebugStringA("[grid] insufficient INT3 slots or invalid API; registration skipped.\n");
            return 0;
        }
        lua_pop(L, 1);
    } else {
        OutputDebugStringA("[grid] Lua state is not available; registration skipped.\n");
    }
    return 0;
}
}
bool start() {
    struct Search { HWND best{}; LONG area{}; } search;
    EnumWindows([](HWND hwnd, LPARAM parameter) -> BOOL {
        auto& result = *reinterpret_cast<Search*>(parameter);
        DWORD pid{};
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid != GetCurrentProcessId() || !IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER)) return TRUE;
        wchar_t name[64]{};
        GetClassNameW(hwnd, name, 64);
        if (lstrcmpiW(name, L"ConsoleWindowClass") == 0) return TRUE;
        RECT rect{};
        if (!GetClientRect(hwnd, &rect)) return TRUE;
        const auto area = (rect.right - rect.left) * (rect.bottom - rect.top);
        if (!result.best || area > result.area) { result.best = hwnd; result.area = area; }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&search));
    if (!search.best) return false;
    message = RegisterWindowMessageW(L"grid.register.lua.api");
    if (!message) return false;
    window = search.best;
    previous = reinterpret_cast<WNDPROC>(GetWindowLongPtrW(window, GWLP_WNDPROC));
    if (!previous) { window = nullptr; return false; }
    if (!SetWindowLongPtrW(window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(dispatch))) {
        window = nullptr;
        previous = nullptr;
        return false;
    }
    if (!PostMessageW(window, message, 0, 0)) { stop(); return false; }
    return true;
}
void stop() {
    if (window && previous && reinterpret_cast<WNDPROC>(GetWindowLongPtrW(window, GWLP_WNDPROC)) == dispatch)
        SetWindowLongPtrW(window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(previous));
    window = nullptr;
    // Keep previous valid for a dispatch already in flight during detach.
}
}
