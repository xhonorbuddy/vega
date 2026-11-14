#include <windows.h>
#include <cstdio>
import grid.exceptions;

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
    stop();
    std::puts("Exception monitor tests passed (SEH propagation, counting, removal, restart)");
}
