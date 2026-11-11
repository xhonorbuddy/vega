// Payload whose DllMain blocks, the way grid.dll does with MessageBoxA.
// Used to check that a blocked entry point does not destroy the target and
// that the module can still be unloaded once the call returns.

#include <windows.h>

#include <cstring>
#include <cstdio>

namespace {

    void log_line(const char* text) noexcept {
        char path[MAX_PATH]{};
        const DWORD length = GetEnvironmentVariableA("VEGA_TEST_LOG", path, MAX_PATH);

        if (length == 0 || length >= MAX_PATH) {
            return;
        }

        const HANDLE file = CreateFileA(
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
        WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
        CloseHandle(file);
    }

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    static_cast<void>(module);
    static_cast<void>(reserved);

    if (reason == DLL_PROCESS_ATTACH) {
        log_line("blocking:attach:begin");
        Sleep(6000);
        log_line("blocking:attach:end");
    }
    else if (reason == DLL_PROCESS_DETACH) {
        log_line("blocking:detach");
    }

    return TRUE;
}
