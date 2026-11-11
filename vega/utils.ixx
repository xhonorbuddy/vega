module;

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <winternl.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

export module manualmap.utils;

import manualmap.apiset;
import manualmap.peb;

export namespace manualmap {

    inline constexpr std::string_view VIRTUAL_DLL_PREFIX = "api-ms";

    class utils final {
    public:
        utils() = delete;

        static void sleep(float milliseconds) {
            initialize_timer_resolution();

            LARGE_INTEGER interval{};
            interval.QuadPart = -static_cast<LONGLONG>(milliseconds * 10'000.0f);

            if (nt_delay_execution()) {
                nt_delay_execution()(FALSE, &interval);
                return;
            }

            Sleep(static_cast<DWORD>(milliseconds));
        }

        static std::string get_dll_name_from_api_set_map(const std::string& api_set) {
            const std::wstring api_set_wide = widen_utf8(api_set);

            const auto* peb = reinterpret_cast<ntapi::PEB*>(
                NtCurrentTeb()->ProcessEnvironmentBlock
                );

            if (!peb || !peb->ApiSetMap) {
                return {};
            }

            const auto* api_set_map = static_cast<API_SET_NAMESPACE*>(peb->ApiSetMap);
            const auto map_base = reinterpret_cast<ULONG_PTR>(api_set_map);

            auto* namespace_entry = reinterpret_cast<API_SET_NAMESPACE_ENTRY*>(
                map_base + api_set_map->EntryOffset
                );

            for (ULONG i = 0; i < api_set_map->Count; ++i, ++namespace_entry) {
                const std::wstring current_name =
                    read_api_set_string(map_base, namespace_entry->NameOffset, namespace_entry->NameLength) +
                    L".dll";

                if (_wcsicmp(api_set_wide.c_str(), current_name.c_str()) != 0) {
                    continue;
                }

                if (namespace_entry->ValueCount == 0) {
                    return {};
                }

                const auto* value_entry = reinterpret_cast<API_SET_VALUE_ENTRY*>(
                    map_base + namespace_entry->ValueOffset
                    );

                const std::wstring resolved_name = read_api_set_string(
                    map_base,
                    value_entry->ValueOffset,
                    value_entry->ValueLength
                );

                return narrow_utf8(resolved_name);
            }

            return {};
        }

        static std::wstring get_wstring_from_char(const char* text) {
            if (!text || *text == '\0') {
                return {};
            }

            return widen_utf8(text);
        }

        static std::wstring get_wstring_from_char(const std::string& text) {
            return get_wstring_from_char(text.c_str());
        }

        static std::wstring widen_utf8(std::string_view text) {
            if (text.empty()) {
                return {};
            }

            const int required_size = MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                text.data(),
                static_cast<int>(text.size()),
                nullptr,
                0
            );

            if (required_size <= 0) {
                return widen_ansi(text);
            }

            std::wstring result(static_cast<std::size_t>(required_size), L'\0');

            MultiByteToWideChar(
                CP_UTF8,
                MB_ERR_INVALID_CHARS,
                text.data(),
                static_cast<int>(text.size()),
                result.data(),
                required_size
            );

            return result;
        }

        static std::string narrow_utf8(std::wstring_view text) {
            if (text.empty()) {
                return {};
            }

            const int required_size = WideCharToMultiByte(
                CP_UTF8,
                0,
                text.data(),
                static_cast<int>(text.size()),
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (required_size <= 0) {
                return {};
            }

            std::string result(static_cast<std::size_t>(required_size), '\0');

            WideCharToMultiByte(
                CP_UTF8,
                0,
                text.data(),
                static_cast<int>(text.size()),
                result.data(),
                required_size,
                nullptr,
                nullptr
            );

            return result;
        }

        static void print_and_exit(const char* format, ...) {
            std::printf("Error: ");

            va_list args;
            va_start(args, format);
            std::vprintf(format, args);
            va_end(args);

            std::printf("\n");
            std::exit(EXIT_FAILURE);
        }

    private:
        using NtDelayExecutionFn = NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER);
        using ZwSetTimerResolutionFn = NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG);

        static HMODULE ntdll_module() {
            static HMODULE module = GetModuleHandleW(L"ntdll.dll");
            return module;
        }

        static NtDelayExecutionFn nt_delay_execution() {
            static auto function = reinterpret_cast<NtDelayExecutionFn>(
                GetProcAddress(ntdll_module(), "NtDelayExecution")
                );

            return function;
        }

        static ZwSetTimerResolutionFn zw_set_timer_resolution() {
            static auto function = reinterpret_cast<ZwSetTimerResolutionFn>(
                GetProcAddress(ntdll_module(), "ZwSetTimerResolution")
                );

            return function;
        }

        static void initialize_timer_resolution() {
            static bool initialized = [] {
                if (auto function = zw_set_timer_resolution()) {
                    ULONG actual_resolution{};
                    function(1, TRUE, &actual_resolution);
                }

                return true;
                }();

            static_cast<void>(initialized);
        }

        static std::wstring widen_ansi(std::string_view text) {
            const int required_size = MultiByteToWideChar(
                CP_ACP,
                0,
                text.data(),
                static_cast<int>(text.size()),
                nullptr,
                0
            );

            if (required_size <= 0) {
                return {};
            }

            std::wstring result(static_cast<std::size_t>(required_size), L'\0');

            MultiByteToWideChar(
                CP_ACP,
                0,
                text.data(),
                static_cast<int>(text.size()),
                result.data(),
                required_size
            );

            return result;
        }

        static std::wstring read_api_set_string(
            ULONG_PTR map_base,
            ULONG offset,
            ULONG byte_length
        ) {
            const auto* buffer = reinterpret_cast<const wchar_t*>(map_base + offset);
            return std::wstring(buffer, byte_length / sizeof(wchar_t));
        }
    };

} // namespace manualmap