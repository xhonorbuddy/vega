#include <windows.h>
import grid.registration;
import grid.exceptions;

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        if (!grid::exceptions::start()) return FALSE;
        if (grid::registration::start()) return TRUE;
        grid::exceptions::stop();
        return FALSE;
    }
    if (reason == DLL_PROCESS_DETACH) {
        grid::registration::stop();
        grid::exceptions::stop();
    }
    return TRUE;
}
