/* Verifies the inline RaiseException hook: patching the function body with
   `mov rax, hook; jmp rax` and returning from the hook must resume the caller
   as if RaiseException had returned. */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define EXCEPTION_INTERNAL_EXCEPTION 0xC00000E5

typedef void(__fastcall* raise_exception_t)(DWORD, DWORD, DWORD, const ULONG_PTR*);

static BYTE* g_target = NULL;
static BYTE g_original[12];
static raise_exception_t g_rtl_raise = NULL;
static volatile LONG g_caught = 0;

static void __fastcall hook_raise_exception(DWORD code, DWORD flags, DWORD nargs, const ULONG_PTR* args)
{
    if (code == EXCEPTION_INTERNAL_EXCEPTION) {
        InterlockedIncrement(&g_caught);
        return; /* resume the caller */
    }

    if (g_rtl_raise != NULL) {
        g_rtl_raise(code, flags, nargs, args);
    }

    ExitThread(1);
}

static int install_hook(void)
{
    g_target = (BYTE*)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "RaiseException");
    g_rtl_raise = (raise_exception_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlRaiseException");

    if (g_target == NULL || g_rtl_raise == NULL) {
        return 0;
    }

    memcpy(g_original, g_target, sizeof(g_original));

    DWORD old_protect = 0;
    if (!VirtualProtect(g_target, sizeof(g_original), PAGE_EXECUTE_READWRITE, &old_protect)) {
        return 0;
    }

    g_target[0] = 0x48;
    g_target[1] = 0xB8;
    *(void**)(g_target + 2) = (void*)&hook_raise_exception;
    g_target[10] = 0xFF;
    g_target[11] = 0xE0;

    DWORD ignored = 0;
    VirtualProtect(g_target, sizeof(g_original), old_protect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), g_target, sizeof(g_original));
    return 1;
}

static void remove_hook(void)
{
    if (g_target == NULL) {
        return;
    }

    DWORD old_protect = 0;
    if (VirtualProtect(g_target, sizeof(g_original), PAGE_EXECUTE_READWRITE, &old_protect)) {
        memcpy(g_target, g_original, sizeof(g_original));
        DWORD ignored = 0;
        VirtualProtect(g_target, sizeof(g_original), old_protect, &ignored);
        FlushInstructionCache(GetCurrentProcess(), g_target, sizeof(g_original));
    }
}

int main(void)
{
    if (!install_hook()) {
        printf("install failed\n");
        return 1;
    }

    const DWORD before = GetTickCount();

    /* Would raise a non-continuable security exception without the hook. */
    RaiseException(EXCEPTION_INTERNAL_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);

    const DWORD after = GetTickCount();

    remove_hook();

    printf("returned=1 caught=%ld elapsed_ms=%lu\n",
        (long)g_caught, (unsigned long)(after - before));
    printf("RESULT: %s\n", (after >= before && g_caught == 1) ? "PASS" : "FAIL");
    return (g_caught == 1) ? 0 : 1;
}
