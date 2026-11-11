// Test payload for the Vega manual mapper.
//
// Everything this DLL reports is written to the file named by VEGA_TEST_LOG so
// the test harness can assert on behaviour that only happens inside the target
// process:
//
//   tls:attach / tls:detach           - TLS callbacks actually executed
//   dllmain:attach / dllmain:detach   - entry point called with the right reason
//   dllmain:exception:<what>          - C++ exceptions unwind (.pdata registered)
//   dllmain:delay:<value>             - delay-loaded import reconstructed
//
// The DLL is linked with a base address that collides with the target image so
// the mapper must relocate it.

#include <windows.h>
#include <delayimp.h>

#include <cstdio>
#include <cstring>
#include <stdexcept>

#pragma comment(lib, "delayimp")

// Delay-loaded: resolved by the mapper's delay-import pass, not by delayimp.
extern "C" __declspec(dllimport) int __stdcall GetSystemMetrics(int index);

// A TLS variable forces the linker to emit a TLS directory, which is what makes
// the .CRT$XLB callback below reachable. It is never read at runtime; reading it
// requires loader-allocated TLS slots, which manual mapping does not provide.
__declspec(thread) int g_tls_canary = 0x1234;

extern "C" __declspec(dllexport) int vega_test_marker() noexcept;

// Provided by the linker; the image's own base address.
extern "C" IMAGE_DOS_HEADER __ImageBase;

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

    void log_value(const char* prefix, int value) noexcept {
        char buffer[128]{};
        std::snprintf(buffer, sizeof(buffer), "%s:%d", prefix, value);
        log_line(buffer);
    }

    void NTAPI tls_callback(PVOID, DWORD reason, PVOID) noexcept {
        if (reason == DLL_PROCESS_ATTACH) {
            log_line("tls:attach");
        }
        else if (reason == DLL_PROCESS_DETACH) {
            log_line("tls:detach");
        }
    }

    [[nodiscard]] bool env_flag_set(const char* name) noexcept {
        char value[8]{};
        return GetEnvironmentVariableA(name, value, sizeof(value)) != 0;
    }

    // Kept out of DllMain: a function with C++ objects in scope cannot also use
    // __try/__except under /EHsc.
    void run_seh_test() noexcept {
        log_line("seh:begin");

        __try {
            RaiseException(0x1234, 0, 0, nullptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            log_line("seh:caught");
        }
    }

    LONG CALLBACK vectored_handler(EXCEPTION_POINTERS* info) noexcept {
        const auto* record = info->ExceptionRecord;

        const auto image_base = reinterpret_cast<std::uintptr_t>(&__ImageBase);
        const auto address = reinterpret_cast<std::uintptr_t>(record->ExceptionAddress);

        char buffer[256]{};
        std::snprintf(
            buffer,
            sizeof(buffer),
            "veh:code:%08lx:addr:%llx:in-image:%d",
            record->ExceptionCode,
            static_cast<unsigned long long>(address),
            (address >= image_base && address < image_base + 0x100000) ? 1 : 0
        );
        log_line(buffer);

        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Reports whether the target's unwinder can see this image's .pdata, which
    // is what makes C++ exceptions work inside a manually mapped DLL.
    void probe_unwind_tables() noexcept {
        const HMODULE ntdll = GetModuleHandleA("ntdll.dll");

        if (ntdll == nullptr) {
            log_line("unwind:no-ntdll");
            return;
        }

        using LookupFn = PRUNTIME_FUNCTION(NTAPI*)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
        using AddFn = BOOLEAN(NTAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);

        const auto lookup = reinterpret_cast<LookupFn>(
            GetProcAddress(ntdll, "RtlLookupFunctionEntry")
            );

        const auto add = reinterpret_cast<AddFn>(
            GetProcAddress(ntdll, "RtlAddFunctionTable")
            );

        if (lookup == nullptr) {
            log_line("unwind:no-lookup");
            return;
        }

        auto report = [&](const char* label) noexcept {
            DWORD64 image_base = 0;
            const PRUNTIME_FUNCTION entry = lookup(
                reinterpret_cast<DWORD64>(&probe_unwind_tables),
                &image_base,
                nullptr
            );

            char buffer[160]{};
            std::snprintf(
                buffer,
                sizeof(buffer),
                "%s:found:%d:base:%llx",
                label,
                entry != nullptr ? 1 : 0,
                static_cast<unsigned long long>(image_base)
            );
            log_line(buffer);
            };

        report("unwind:before-add");

        if (add != nullptr) {
            const auto* base = reinterpret_cast<const IMAGE_DOS_HEADER*>(&__ImageBase);
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                reinterpret_cast<const char*>(&__ImageBase) + base->e_lfanew
                );

            const IMAGE_DATA_DIRECTORY& directory =
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

            if (directory.VirtualAddress != 0 && directory.Size != 0) {
                auto* table = reinterpret_cast<PRUNTIME_FUNCTION>(
                    const_cast<char*>(reinterpret_cast<const char*>(&__ImageBase)) + directory.VirtualAddress
                    );

                const BOOLEAN added = add(
                    table,
                    directory.Size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION)),
                    reinterpret_cast<DWORD64>(&__ImageBase)
                );

                char buffer[128]{};
                std::snprintf(buffer, sizeof(buffer), "unwind:self-add:%d", added != 0 ? 1 : 0);
                log_line(buffer);
            }
        }

        report("unwind:after-add");

        using PcToFileHeaderFn = PVOID(NTAPI*)(PVOID, PVOID*);

        const auto pc_to_file_header = reinterpret_cast<PcToFileHeaderFn>(
            GetProcAddress(ntdll, "RtlPcToFileHeader")
            );

        if (pc_to_file_header != nullptr) {
            PVOID resolved_base = nullptr;
            const PVOID result = pc_to_file_header(
                const_cast<IMAGE_DOS_HEADER*>(&__ImageBase),
                &resolved_base
            );

            char buffer[160]{};
            std::snprintf(
                buffer,
                sizeof(buffer),
                "pctofileheader:found:%d:base:%llx",
                result != nullptr ? 1 : 0,
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(resolved_base)
                    )
            );
            log_line(buffer);
        }

        // Control: an address inside a normally loaded module must resolve.
        if (pc_to_file_header != nullptr) {
            PVOID control_base = nullptr;
            const HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
            const FARPROC sleep_address = kernel32
                ? GetProcAddress(kernel32, "Sleep")
                : nullptr;

            const PVOID control = sleep_address
                ? pc_to_file_header(reinterpret_cast<PVOID>(sleep_address), &control_base)
                : nullptr;

            char buffer[160]{};
            std::snprintf(
                buffer,
                sizeof(buffer),
                "pctofileheader-control:found:%d:base:%llx",
                control != nullptr ? 1 : 0,
                static_cast<unsigned long long>(
                    reinterpret_cast<std::uintptr_t>(control_base)
                    )
            );
            log_line(buffer);
        }

        HMODULE by_address = nullptr;
        const BOOL via_address = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(&__ImageBase),
            &by_address
        );

        HMODULE by_name = GetModuleHandleW(L"sample.dll");

        char buffer[160]{};
        std::snprintf(
            buffer,
            sizeof(buffer),
            "getmodule:byaddress:%d:byname:%d",
            via_address != FALSE ? 1 : 0,
            by_name != nullptr ? 1 : 0
        );
        log_line(buffer);
    }

} // namespace

#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_tls_entry = tls_callback;

extern "C" __declspec(dllexport) int vega_test_marker() noexcept {
    return 0x56454741;
}

// Exported so the TLS variable is not dropped, but never called: thread-local
// storage needs loader cooperation that manual mapping cannot provide.
extern "C" __declspec(dllexport) int vega_tls_probe() noexcept {
    return g_tls_canary;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    static_cast<void>(module);
    static_cast<void>(reserved);

    if (reason == DLL_PROCESS_ATTACH) {
        log_line("dllmain:attach");
        AddVectoredExceptionHandler(1, vectored_handler);
        probe_unwind_tables();
        run_seh_test();

        if (env_flag_set("VEGA_TEST_THROW")) {
            log_line("throw:int:begin");

            try {
                throw 42;
            }
            catch (int value) {
                log_value("throw:int:caught", value);
            }

            log_line("throw:std:begin");

            try {
                throw std::runtime_error("boom");
            }
            catch (const std::exception& error) {
                char buffer[128]{};
                std::snprintf(buffer, sizeof(buffer), "dllmain:exception:%s", error.what());
                log_line(buffer);
            }
        }
        else {
            log_line("dllmain:exception:skipped");
        }

        log_value("dllmain:delay", GetSystemMetrics(SM_CXSCREEN));
        log_value("dllmain:marker", vega_test_marker());
    }
    else if (reason == DLL_PROCESS_DETACH) {
        log_line("dllmain:detach");
    }

    return TRUE;
}
