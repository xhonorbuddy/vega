module;
#include <windows.h>

export module grid.exceptions;

export namespace grid::exceptions {
bool start() noexcept;
void stop() noexcept;
LONG observed_count() noexcept;
}

namespace grid::exceptions {
namespace {
PVOID handler{};
volatile LONG observed{};
volatile LONG reporting{};

LONG CALLBACK monitor(EXCEPTION_POINTERS* info) noexcept {
    if (!info || !info->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const auto& record = *info->ExceptionRecord;
    // Bypass fake raise
    if (record.ExceptionCode == 0xC00000E5)
        return EXCEPTION_CONTINUE_EXECUTION;
    // OutputDebugString can itself raise these notifications.
    if (record.ExceptionCode == 0x40010006 || record.ExceptionCode == 0x4001000A)
        return EXCEPTION_CONTINUE_SEARCH;
    const LONG count = InterlockedIncrement(&observed);
    // Avoid recursive logging and locks/allocations in an exception callback.
    if (InterlockedCompareExchange(&reporting, 1, 0) != 0)
        return EXCEPTION_CONTINUE_SEARCH;
    char line[512]{};
    wsprintfA(line,
        "[grid] exception #%ld thread=%lu code=0x%08lX flags=0x%08lX address=%p rip=%p\n",
        count, GetCurrentThreadId(), record.ExceptionCode, record.ExceptionFlags,
        record.ExceptionAddress,
        info->ContextRecord ? reinterpret_cast<void*>(info->ContextRecord->Rip) : nullptr);
    OutputDebugStringA(line);
    if ((record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
         record.ExceptionCode == EXCEPTION_IN_PAGE_ERROR) && record.NumberParameters >= 2) {
        const auto access = record.ExceptionInformation[0];
        const char* operation = access == 0 ? "read" : access == 1 ? "write" :
                                access == 8 ? "execute" : "unknown";
        wsprintfA(line, "[grid] memory fault operation=%s target=%p\n", operation,
            reinterpret_cast<void*>(record.ExceptionInformation[1]));
        OutputDebugStringA(line);
    }
    InterlockedExchange(&reporting, 0);
    // Monitoring only: preserve the original exception and its context.
    return EXCEPTION_CONTINUE_SEARCH;
}
}

bool start() noexcept {
    if (handler) return true;
    InterlockedExchange(&observed, 0);
    handler = AddVectoredExceptionHandler(1, monitor);
    return handler != nullptr;
}
void stop() noexcept {
    if (handler && RemoveVectoredExceptionHandler(handler)) handler = nullptr;
}
LONG observed_count() noexcept { return InterlockedCompareExchange(&observed, 0, 0); }
}
