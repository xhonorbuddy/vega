/* Minimal memory dumper: ReadProcessMemory a range into a file. */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int wmain(int argc, wchar_t** argv)
{
    if (argc != 5) {
        wprintf(L"usage: dumper <pid> <base-hex> <size-hex> <out>\n");
        return 1;
    }

    const DWORD pid = (DWORD)wcstoul(argv[1], NULL, 10);
    const ULONGLONG base = wcstoull(argv[2], NULL, 16);
    const ULONGLONG size = wcstoull(argv[3], NULL, 16);

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (process == NULL) {
        wprintf(L"OpenProcess failed %lu\n", GetLastError());
        return 1;
    }

    FILE* file = _wfopen(argv[4], L"wb");
    if (file == NULL) {
        wprintf(L"cannot open output\n");
        CloseHandle(process);
        return 1;
    }

    const SIZE_T chunk = 0x100000;
    BYTE* buffer = (BYTE*)malloc(chunk);
    ULONGLONG done = 0;

    while (done < size) {
        SIZE_T want = (SIZE_T)((size - done) < chunk ? (size - done) : chunk);
        SIZE_T got = 0;

        if (ReadProcessMemory(process, (BYTE*)(ULONG_PTR)(base + done), buffer, want, &got) && got > 0) {
            fwrite(buffer, 1, got, file);
        }
        else {
            /* unreadable page: write zeros to keep offsets aligned */
            memset(buffer, 0, want);
            fwrite(buffer, 1, want, file);
        }

        done += want;
    }

    free(buffer);
    fclose(file);
    CloseHandle(process);
    wprintf(L"dumped 0x%llx bytes to %s\n", size, argv[4]);
    return 0;
}
