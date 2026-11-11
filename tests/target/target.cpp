// Minimal target process used by the end-to-end mapper test.
// It stays alive until it is killed so the loader has something to map into.
// GetSystemMetrics makes sure user32.dll is loaded, so the sample DLL can
// delay-load from it instead of forcing the mapper to map user32 itself.

#include <windows.h>

#include <cstdio>

int main() {
    std::printf(
        "target.exe running, pid %lu, screen width %d\n",
        GetCurrentProcessId(),
        GetSystemMetrics(SM_CXSCREEN)
    );

    std::fflush(stdout);

    for (;;) {
        Sleep(200);
    }
}
