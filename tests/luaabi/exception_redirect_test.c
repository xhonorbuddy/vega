/* Replicates grid.dll's EXCEPTION_INTERNAL_ERROR handling in isolation:
   a worker thread raises 0xC00000E5, the VEH redirects that thread to an exit
   stub, and the process must continue instead of spinning or dying. */

#include <windows.h>
#include <stdio.h>

#define EXCEPTION_INTERNAL_EXCEPTION 0xC00000E5

static volatile LONG g_redirected = 0;

static LONG NTAPI veh(EXCEPTION_POINTERS* info)
{
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_INTERNAL_EXCEPTION) {
        /* Mirror the loader's non-continuable raise: CONTINUE_EXECUTION is
           rejected, so the handler must end the thread itself. */
        InterlockedIncrement(&g_redirected);
        ExitThread(0);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI raiser(LPVOID param)
{
    (void)param;
    RaiseException(EXCEPTION_INTERNAL_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
    return 1; /* not reached */
}

int main(void)
{
    AddVectoredExceptionHandler(1, veh);

    HANDLE thread = CreateThread(NULL, 0, raiser, NULL, 0, NULL);
    if (thread == NULL) {
        printf("CreateThread failed\n");
        return 1;
    }

    const DWORD wait = WaitForSingleObject(thread, 5000);
    CloseHandle(thread);

    printf("wait=%lu redirected=%ld\n", wait, (long)g_redirected);
    printf("RESULT: %s\n", (wait == WAIT_OBJECT_0 && g_redirected == 1) ? "PASS" : "FAIL");
    return (wait == WAIT_OBJECT_0 && g_redirected == 1) ? 0 : 1;
}
