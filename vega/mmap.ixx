module;

#pragma comment(lib, "ntdll")

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <delayimp.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

export module manualmap.mmap;

import manualmap.memory;
import manualmap.utils;

export namespace manualmap {

    // Options that control a single mapping operation.
    struct MapOptions {
        int print_padding = 0;
        bool verbose = true;
        bool call_tls_callbacks = true;
        bool register_exception_table = true;
        bool resolve_delay_imports = true;
        bool prefer_preferred_base = true;
        bool call_entry_point = true;
        bool register_loader_entry = false;
        bool thread_hijack = false;
        bool force = false;
        bool erase_headers = true;
        bool keep_image = false;
        std::uint32_t ddag_state = 9;
        DWORD call_timeout_ms = 60'000;
    };

    // Result of a successful map.
    struct MappedModule {
        std::uintptr_t base = 0;
        std::size_t image_size = 0;
        std::uintptr_t entry_point = 0;
        std::uintptr_t record = 0;
        std::string name;
    };

    class MapError : public std::runtime_error {
    public:
        explicit MapError(const std::string& message)
            : std::runtime_error(message) {
        }
    };

    inline constexpr std::uint64_t VEGA_MODULE_MAGIC = 0x56454741'4D4F4401ULL;
    inline constexpr std::uint32_t VEGA_MODULE_RECORD_VERSION = 2;

    // Control block written next to every mapped image. A later run of the tool
    // scans the target for this magic so a module can be unloaded without any
    // external bookkeeping.
    struct ModuleRecord {
        std::uint64_t magic = 0;
        std::uint32_t version = 0;
        std::uint32_t image_size = 0;
        std::uint64_t image_base = 0;
        std::uint64_t entry_point = 0;
        std::uint64_t exception_table = 0;
        std::uint32_t exception_count = 0;
        std::uint32_t flags = 0;
        std::uint64_t ldr_entry = 0;
        wchar_t module_name[64] = {};
    };

    class Mmap {
    public:
        Mmap() = default;

        [[nodiscard]] MappedModule map_dll(
            const std::string& process,
            const std::string& dll_path,
            const MapOptions& options = {}
        );

        [[nodiscard]] std::size_t unload_module(
            const std::string& process,
            const std::string& module_name,
            const MapOptions& options = {}
        );

        [[nodiscard]] std::vector<MappedModule> list_modules(const std::string& process);

    private:
        struct PeImage {
            std::vector<char> file;
            std::vector<char> image;
            std::size_t image_size = 0;
            std::size_t size_of_headers = 0;
            std::size_t nt_offset = 0;
            std::uintptr_t preferred_base = 0;
            IMAGE_NT_HEADERS* nt = nullptr;
            IMAGE_SECTION_HEADER* sections = nullptr;
            std::uint16_t section_count = 0;
            std::string name;
        };

        struct FoundRecord {
            std::uintptr_t address = 0;
            ModuleRecord record;
        };

        [[nodiscard]] PeImage read_pe_file(const std::string& path);
        void build_image(PeImage& pe);

        void apply_relocations(
            PeImage& pe,
            std::uintptr_t remote_base,
            const MapOptions& options
        );

        void resolve_imports(
            const std::string& process,
            PeImage& pe,
            const MapOptions& options,
            int depth
        );

        void resolve_delay_imports(
            const std::string& process,
            PeImage& pe,
            const MapOptions& options,
            int depth
        );

        void resolve_thunk_table(
            const std::string& process,
            PeImage& pe,
            HMODULE local_module,
            const std::string& module_name,
            IMAGE_THUNK_DATA* lookup_table,
            IMAGE_THUNK_DATA* address_table,
            const MapOptions& options,
            int depth
        );

        [[nodiscard]] std::uintptr_t resolve_target_module(
            const std::string& process,
            const std::string& module_name,
            const MapOptions& options,
            int depth
        );

        [[nodiscard]] std::uintptr_t resolve_export_remote(
            const std::string& process,
            HMODULE local_module,
            std::uint32_t export_rva,
            const MapOptions& options,
            int depth
        );

        [[nodiscard]] std::uintptr_t resolve_target_export(
            const std::string& module_name,
            const char* function_name
        );

        void write_image(
            const PeImage& pe,
            std::uintptr_t remote_base,
            const MapOptions& options
        );

        [[nodiscard]] bool register_exception_table(
            std::uintptr_t remote_base,
            const PeImage& pe,
            const MapOptions& options,
            ModuleRecord& record
        );

        // Adds the image to ntdll's KiUserInvertedFunctionTable, which is what
        // RtlPcToFileHeader (and therefore MSVC's C++ exception handler) uses to
        // map a code address back to its image base. The table is a sorted array
        // of 24-byte entries living in ntdll's read-only image data, so it is
        // briefly made writable while the entry is spliced in.
        [[nodiscard]] bool register_loader_index(
            std::uintptr_t remote_base,
            std::size_t image_size,
            const MapOptions& options
        );

        [[nodiscard]] bool unregister_loader_index(
            std::uintptr_t remote_base,
            const MapOptions& options
        );

        [[nodiscard]] bool image_is_in_loader_index(
            std::uintptr_t table,
            std::uintptr_t image_base
        );

        void run_tls_callbacks(
            std::uintptr_t remote_base,
            DWORD reason,
            const MapOptions& options
        );

        [[nodiscard]] std::uint32_t call_entry_point(
            std::uintptr_t remote_base,
            std::size_t entry_point_rva,
            DWORD reason,
            const MapOptions& options
        );

        [[nodiscard]] std::uintptr_t write_record(const ModuleRecord& record);
        [[nodiscard]] std::vector<FoundRecord> find_records(const std::string& module_name);

        [[nodiscard]] static std::string normalize_module_name(const std::string& module_name);
        [[nodiscard]] static std::string module_basename(HMODULE module);
        [[nodiscard]] static std::string module_full_path(HMODULE module);
        [[nodiscard]] static const IMAGE_NT_HEADERS* local_nt_headers(HMODULE module);
        [[nodiscard]] static std::optional<std::uint32_t> export_rva_by_name(
            HMODULE module,
            std::string_view name
        );
        [[nodiscard]] static std::optional<std::uint32_t> export_rva_by_ordinal(
            HMODULE module,
            WORD ordinal
        );
        [[nodiscard]] static std::string read_cstring(
            const PeImage& pe,
            std::size_t offset,
            std::size_t limit = 1024
        );
        [[nodiscard]] static DWORD section_protection(const IMAGE_SECTION_HEADER& section);
        [[nodiscard]] static std::string indent(int count);

        static void log(const MapOptions& options, const std::string& message);

    private:
        Memory memory_;
    };

} // namespace manualmap

namespace manualmap {

    namespace {

        constexpr std::size_t kMaxImageSize = 512ull * 1024ull * 1024ull;
        constexpr std::size_t kMaxSections = 96;
        constexpr std::size_t kMaxTlsCallbacks = 256;
        constexpr std::size_t kMaxImportDepth = 16;
        constexpr std::size_t kMaxExportHops = 16;
        constexpr std::size_t kRecordSize = 0x1000;
        constexpr std::uintptr_t kMaxUserAddress = 0x00007FFF'FFFE'FFFFull;

        // KiUserInvertedFunctionTable: a ULONG count at +0x00, a ULONG capacity at
        // +0x04, and a sorted array of 24-byte entries from +0x10. Each entry is
        // {PVOID exception_table; PVOID image_base; ULONG image_size; ULONG flags}
        // and the array is what RtlPcToFileHeader binary-searches by address.
        constexpr std::size_t kInvertedTableHeaderSize = 0x10;
        constexpr std::size_t kInvertedTableCountOffset = 0x00;
        constexpr std::size_t kInvertedTableCapacityOffset = 0x04;

        struct InvertedTableEntry {
            std::uint64_t exception_table;
            std::uint64_t image_base;
            std::uint32_t image_size;
            std::uint32_t flags;
        };

        static_assert(sizeof(InvertedTableEntry) == 24);

        constexpr std::uint32_t kModuleFlagLoaderIndex = 0x1;
        constexpr std::uint32_t kModuleFlagEntryPointRunning = 0x2;

        // Loader PC index registration goes through the loader's own insertion
        // routine (it locks, keeps the array sorted and grows it if needed). The
        // RVA is checked against the expected prologue before it is called so a
        // different ntdll build degrades instead of corrupting the loader.
        constexpr std::size_t kLoaderIndexInsertRva = 0x5AEA4;

        constexpr std::array<BYTE, 16> kLoaderIndexInsertPrologue{
            0x48, 0x8B, 0xC4,               // mov rax, rsp
            0x48, 0x89, 0x58, 0x08,         // mov [rax+8], rbx
            0x48, 0x89, 0x68, 0x10,         // mov [rax+10h], rbp
            0x48, 0x89, 0x70, 0x20,         // mov [rax+20h], rsi
            0x57                            // push rdi
        };

        [[nodiscard]] bool range_within(
            std::size_t offset,
            std::size_t length,
            std::size_t total
        ) noexcept {
            return offset <= total && length <= total - offset;
        }

        [[nodiscard]] bool has_data_directory(
            const IMAGE_NT_HEADERS* nt_headers,
            std::size_t index
        ) noexcept {
            return nt_headers != nullptr &&
                index < nt_headers->OptionalHeader.NumberOfRvaAndSizes &&
                nt_headers->OptionalHeader.DataDirectory[index].VirtualAddress != 0 &&
                nt_headers->OptionalHeader.DataDirectory[index].Size != 0;
        }

        [[nodiscard]] std::string hex(std::uint64_t value) {
            char buffer[32]{};
            std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
            return buffer;
        }

    } // namespace

    void Mmap::log(const MapOptions& options, const std::string& message) {
        if (!options.verbose) {
            return;
        }

        const std::string padding = indent(options.print_padding);
        std::printf("%s%s\n", padding.c_str(), message.c_str());
    }

    MappedModule Mmap::map_dll(
        const std::string& process,
        const std::string& dll_path,
        const MapOptions& options
    ) {
        if (process.empty()) {
            throw MapError("Target process name is empty");
        }

        if (dll_path.empty()) {
            throw MapError("DLL path is empty");
        }

        if (!memory_.has_handle()) {
            if (!memory_.open_handle(utils::get_wstring_from_char(process))) {
                throw MapError(
                    "Failed to open process '" + process + "' (Win32 error " +
                    std::to_string(memory_.last_error()) +
                    "; is it running, and are you elevated?)"
                );
            }

            log(options, "[*] Target: " + process +
                " (PID " + std::to_string(memory_.process_id()) + ")");
        }

        memory_.set_prefer_thread_hijack(options.thread_hijack);

        PeImage pe = read_pe_file(dll_path);
        pe.name = std::filesystem::path(dll_path).filename().string();

        log(options, "Mapping: " + dll_path);

        // Prefer the image's own base so relocations become a no-op and any
        // absolute address baked into the DLL stays correct.
        std::uintptr_t remote_base = 0;

        if (options.prefer_preferred_base) {
            remote_base = memory_.virtual_alloc_ex(
                pe.preferred_base,
                pe.image_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE
            );
        }

        if (remote_base == 0) {
            remote_base = memory_.virtual_alloc_ex(
                0,
                pe.image_size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE
            );
        }

        if (remote_base == 0) {
            throw MapError(
                "Failed to allocate " + std::to_string(pe.image_size) +
                " bytes in the target process"
            );
        }

        log(options, "[+] DLL base: " + hex(remote_base));

        std::uintptr_t ldr_entry = 0;
        bool index_registered = false;
        bool record_written = false;
        bool entry_point_invoked = false;
        bool entry_call_incomplete = false;
        std::uintptr_t record_address = 0;
        ModuleRecord record{};

        try {
            build_image(pe);

            apply_relocations(pe, remote_base, options);
            log(options, "[+] Applied relocations");

            resolve_imports(process, pe, options, 0);

            if (options.resolve_delay_imports) {
                resolve_delay_imports(process, pe, options, 0);
            }

            log(options, "[+] Reconstructed imports");

            write_image(pe, remote_base, options);

            if (options.erase_headers && pe.size_of_headers != 0) {
                std::vector<char> zeros(pe.size_of_headers, 0);

                if (memory_.write_memory_with_size(remote_base, zeros.data(), zeros.size())) {
                    log(options, "[+] Erased PE headers");
                }
                else {
                    log(options, "[!] Could not erase the PE headers");
                }
            }
            log(options, "[+] Wrote image into target");

            record.magic = VEGA_MODULE_MAGIC;
            record.version = VEGA_MODULE_RECORD_VERSION;
            record.image_size = static_cast<std::uint32_t>(pe.image_size);
            record.image_base = remote_base;
            record.entry_point =
                remote_base + pe.nt->OptionalHeader.AddressOfEntryPoint;
            record.exception_table = 0;
            record.exception_count = 0;
            record.flags = 0;
            record.ldr_entry = 0;

            const std::wstring wide_name = utils::get_wstring_from_char(pe.name);
            wcsncpy_s(record.module_name, wide_name.c_str(), _TRUNCATE);

            // Make the image reachable from an address lookup before anything
            // runs inside it: that is what lets the C++ exception runtime find
            // the image base for a frame in the mapped DLL.
            if (options.register_exception_table &&
                register_loader_index(remote_base, pe.image_size, options)) {
                record.flags |= kModuleFlagLoaderIndex;
                index_registered = true;
                log(options, "[+] Registered image in the loader PC index");
            }
            else if (options.register_exception_table && !options.thread_hijack) {
                // Some protected targets neutralise newly created threads, so
                // the call above can return without doing anything. Retry on an
                // existing thread and keep that mode for the rest of the map.
                memory_.set_prefer_thread_hijack(true);

                if (register_loader_index(remote_base, pe.image_size, options)) {
                    record.flags |= kModuleFlagLoaderIndex;
                    index_registered = true;
                    log(options, "[+] Registered image in the loader PC index "
                        "(existing-thread mode)");
                }
            }

            // Register the image with the loader list before anything runs inside
            // it: the unwinder, GetModuleHandle and module enumeration all look
            // there, and C++ exception dispatch inside the DLL depends on it.
            if (options.register_loader_entry) {
                ldr_entry = memory_.insert_loader_module(
                    remote_base,
                    pe.image_size,
                    static_cast<std::uintptr_t>(record.entry_point),
                    static_cast<std::uint32_t>(pe.nt->FileHeader.TimeDateStamp),
                    utils::get_wstring_from_char(dll_path),
                    wide_name,
                    options.ddag_state
                );

                if (ldr_entry == 0) {
                    throw MapError("Failed to add the image to the target loader list");
                }

                record.ldr_entry = ldr_entry;
                log(options, "[+] Registered loader entry");
            }

            // With a loader entry in place the unwinder finds .pdata through the
            // loader itself; a dynamic function table would be a duplicate, and
            // ntdll rejects it for addresses covered by a loaded module.
            // With a loader PC index entry in place the unwinder finds .pdata
            // through that entry; a dynamic function table would be a second,
            // conflicting description of the same address range.
            if (options.register_exception_table && ldr_entry == 0 &&
                register_exception_table(remote_base, pe, options, record)) {
                log(options, "[+] Registered exception table (" +
                    std::to_string(record.exception_count) + " entries)");
            }

            // The record goes in before anything executes, so the image stays
            // discoverable (and unloadable) even if the entry point fails later.
            record_address = write_record(record);
            record_written = true;

            if (options.call_tls_callbacks) {
                run_tls_callbacks(remote_base, DLL_PROCESS_ATTACH, options);
                log(options, "[+] Called TLS callbacks");
            }

            entry_point_invoked = options.call_entry_point;

            std::uint32_t dll_main_result = 1;

            if (options.call_entry_point) {
                try {
                    dll_main_result = call_entry_point(
                        remote_base,
                        pe.nt->OptionalHeader.AddressOfEntryPoint,
                        DLL_PROCESS_ATTACH,
                        options
                    );
                }
                catch (...) {
                    // A timed-out call may still be running on a target thread.
                    entry_call_incomplete = memory_.last_call_timed_out();
                    throw;
                }
            }

            if (dll_main_result == 0) {
                std::uint8_t probe = 0;
                const bool reachable = memory_.read_memory_with_size(
                    remote_base,
                    &probe,
                    sizeof(probe)
                );

                throw MapError(
                    std::string("DllMain returned FALSE (DLL_PROCESS_ATTACH)") +
                    (reachable ? "" : "; the target no longer responds")
                );
            }

            if (options.call_entry_point) {
                log(options, "[+] Called DllMain (DLL_PROCESS_ATTACH)");
            }

            MappedModule module;
            module.base = remote_base;
            module.image_size = pe.image_size;
            module.entry_point = record.entry_point;
            module.record = record_address;
            module.name = pe.name;

            log(options, "[+] Module ready for unload");

            return module;
        }
        catch (...) {
            // An entry point that timed out is still running on a target thread
            // (a modal dialog, for example). Freeing the image underneath it
            // would crash the target when that call returns, so record the state
            // and leave everything mapped for a later unload.
            if (entry_call_incomplete && record_address != 0) {
                record.flags |= kModuleFlagEntryPointRunning;
                static_cast<void>(memory_.write_memory_with_size(
                    record_address,
                    &record,
                    sizeof(record)
                ));

                log(options, "[!] The DLL entry point is still running on a target "
                    "thread; leaving the image mapped. Close any dialog and unload "
                    "it, or pass --force to override the check.");

                throw;
            }

            // Never free memory that a live thread is still executing: an entry
            // point that blocked (a modal dialog, for example) leaves the DLL on
            // that thread's stack. Keeping the image and its record lets the user
            // unload it later instead of crashing the target.
            bool threads_inside = false;

            if (entry_point_invoked) {
                const auto busy = memory_.find_threads_in_range(
                    remote_base,
                    pe.image_size
                );

                threads_inside = !busy.empty();
                log(options, "[*] Threads using the image before cleanup: " +
                    std::to_string(busy.size()));
            }

            if (threads_inside) {
                log(options, "[!] A thread is still executing inside the image; "
                    "leaving it mapped so the target stays alive");
                throw;
            }

            if (record_written) {
                // The record is freed with the image below; nothing to unlink.
            }

            if (index_registered) {
                static_cast<void>(unregister_loader_index(remote_base, options));
            }

            if (ldr_entry != 0) {
                static_cast<void>(memory_.remove_loader_module(ldr_entry));
                static_cast<void>(memory_.virtual_free_ex(ldr_entry, MEM_RELEASE));
            }

            static_cast<void>(memory_.virtual_free_ex(remote_base, MEM_RELEASE));
            throw;
        }
    }

    std::size_t Mmap::unload_module(
        const std::string& process,
        const std::string& module_name,
        const MapOptions& options
    ) {
        if (!memory_.has_handle()) {
            if (!memory_.open_handle(utils::get_wstring_from_char(process))) {
                throw MapError(
                    "Failed to open process '" + process + "' (Win32 error " +
                    std::to_string(memory_.last_error()) +
                    "; is it running, and are you elevated?)"
                );
            }
        }

        /* Protected targets kill threads whose start is not module-backed,
           so created-thread stubs never run; use the hijack path. */
        memory_.set_prefer_thread_hijack(true);

        const auto records = find_records(module_name);

        if (records.empty()) {
            return 0;
        }

        std::size_t unloaded = 0;

        for (const auto& found : records) {
            const ModuleRecord& record = found.record;
            const std::uintptr_t base = static_cast<std::uintptr_t>(record.image_base);

            log(options, "Unloading: " + utils::narrow_utf8(record.module_name));

            if ((record.flags & kModuleFlagEntryPointRunning) != 0) {
                log(options, "[!] This image was recorded with a still-running entry "
                    "point; dismiss any dialog before it is freed");
            }

            if (!options.force) {
                const auto busy = memory_.find_threads_in_range(
                    base,
                    record.image_size
                );

                if (!busy.empty()) {
                    std::string ids;

                    for (const DWORD id : busy) {
                        ids += (ids.empty() ? "" : ", ") + std::to_string(id);
                    }

                    throw MapError(
                        "Refusing to unload " +
                        utils::narrow_utf8(record.module_name) +
                        ": thread(s) " + ids + " are still executing inside the "
                        "image. Close any dialog or wait for it to return, or "
                        "retry with --force"
                    );
                }
            }

            if (options.keep_image) {
                /* Never touch the target's threads in keep mode: the remote call
                   corrupts a hijacked thread on this client. */
                log(options, "[+] Kept the image mapped by request (safe unload)");

                const std::uint64_t cleared_magic = 0;

                static_cast<void>(memory_.write_memory_with_size(
                    found.address,
                    &cleared_magic,
                    sizeof(cleared_magic)
                ));

                ++unloaded;
                continue;
            }
            /* Diagnostic: does remote_call execute at all in this target?
               A trivial export with no arguments distinguishes a broken hijack
               from a DllMain that simply does not run. */
            {
                const std::uintptr_t tick = resolve_target_export("kernel32.dll", "GetTickCount");

                if (tick != 0) {
                    const auto probe = memory_.remote_call(tick, 0, 0, 0, 5000);

                    if (probe.has_value()) {
                        log(options, "[diag] remote GetTickCount -> " + std::to_string(probe.value()));
                    }
                    else {
                        log(options, "[diag] remote GetTickCount did NOT run");
                    }
                }
            }

            // Mirror the loader: DllMain sees DLL_PROCESS_DETACH first, then the
            // TLS detach callbacks run.
            if (record.entry_point != 0) {
                const auto result = memory_.remote_call(
                    static_cast<std::uintptr_t>(record.entry_point),
                    base,
                    DLL_PROCESS_DETACH,
                    0,
                    options.call_timeout_ms
                );

                if (result.has_value()) {
                    log(options, "[diag] DllMain(DLL_PROCESS_DETACH) returned " + std::to_string(result.value()));
                }

                if (!result.has_value()) {
                    /* The in-image VEH must stay valid, so the image cannot be
                       freed when its DllMain never ran. Leave it mapped, mark
                       the record as handled, and move on. */
                    log(options, options.keep_image
                        ? "[+] Kept the image mapped by request (safe unload)"
                        : "[!] DllMain(DLL_PROCESS_DETACH) did not run; "
                          "leaving the image mapped so registered handlers stay valid");

                    const std::uint64_t cleared_magic = 0;

                    static_cast<void>(memory_.write_memory_with_size(
                        found.address,
                        &cleared_magic,
                        sizeof(cleared_magic)
                    ));

                    ++unloaded;
                    continue;
                }
            }

            try {
                run_tls_callbacks(base, DLL_PROCESS_DETACH, options);
            }
            catch (const std::exception& error) {
                log(options, std::string("[!] TLS detach callback failed: ") + error.what());
            }

            if (record.exception_table != 0 && record.exception_count != 0) {
                const std::uintptr_t delete_table =
                    resolve_target_export("ntdll.dll", "RtlDeleteFunctionTable");

                if (delete_table != 0) {
                    const auto result = memory_.remote_call(
                        delete_table,
                        static_cast<std::uintptr_t>(record.exception_table),
                        0,
                        0,
                        options.call_timeout_ms
                    );

                    if (!result.has_value()) {
                        log(options, "[!] RtlDeleteFunctionTable did not run");
                    }
                }
            }

            if (!memory_.virtual_free_ex(found.address, MEM_RELEASE)) {
                log(options, "[!] Failed to release the module record");
            }

            if ((record.flags & kModuleFlagLoaderIndex) != 0) {
                if (unregister_loader_index(base, options)) {
                    log(options, "[+] Removed image from the loader PC index");
                }
                else {
                    log(options, "[!] Could not remove the image from the loader PC index");
                }
            }

            if (record.ldr_entry != 0) {
                if (!memory_.remove_loader_module(
                    static_cast<std::uintptr_t>(record.ldr_entry)
                )) {
                    log(options, "[!] Failed to unlink the loader entry");
                }

                static_cast<void>(memory_.virtual_free_ex(
                    static_cast<std::uintptr_t>(record.ldr_entry),
                    MEM_RELEASE
                ));
            }

            if (!memory_.virtual_free_ex(base, MEM_RELEASE)) {
                log(options, "[!] Failed to release the mapped image");
            }
            else {
                ++unloaded;
                log(options, "[+] Unloaded " + hex(base));
            }
        }

        return unloaded;
    }

    std::vector<MappedModule> Mmap::list_modules(const std::string& process) {
        if (!memory_.has_handle()) {
            if (!memory_.open_handle(utils::get_wstring_from_char(process))) {
                throw MapError("Failed to open process '" + process + "'");
            }
        }

        std::vector<MappedModule> modules;

        for (const auto& found : find_records({})) {
            MappedModule module;
            module.base = static_cast<std::uintptr_t>(found.record.image_base);
            module.image_size = found.record.image_size;
            module.entry_point = static_cast<std::uintptr_t>(found.record.entry_point);
            module.record = found.address;
            module.name = utils::narrow_utf8(found.record.module_name);
            modules.push_back(std::move(module));
        }

        return modules;
    }

    Mmap::PeImage Mmap::read_pe_file(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);

        if (!file.is_open()) {
            throw MapError("Cannot open DLL: " + path);
        }

        const std::streamsize file_size = file.tellg();

        if (file_size <= 0) {
            throw MapError("DLL file is empty: " + path);
        }

        if (static_cast<std::uint64_t>(file_size) > kMaxImageSize) {
            throw MapError("DLL is implausibly large: " + path);
        }

        file.seekg(0, std::ios::beg);

        PeImage pe;
        pe.file.resize(static_cast<std::size_t>(file_size));

        if (!file.read(pe.file.data(), file_size)) {
            throw MapError("Failed to read DLL: " + path);
        }

        const std::size_t size = pe.file.size();

        if (size < sizeof(IMAGE_DOS_HEADER)) {
            throw MapError("Invalid PE: file is smaller than a DOS header");
        }

        const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe.file.data());

        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            throw MapError("Invalid DOS signature");
        }

        if (dos_header->e_lfanew <= 0) {
            throw MapError("Invalid NT header offset");
        }

        const std::size_t nt_offset = static_cast<std::size_t>(dos_header->e_lfanew);

        if (!range_within(nt_offset, sizeof(IMAGE_NT_HEADERS), size)) {
            throw MapError("NT headers fall outside the file");
        }

        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            pe.file.data() + nt_offset
            );

        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            throw MapError("Invalid NT signature");
        }

        if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            throw MapError("Only x64 images are supported (machine type " +
                hex(nt_headers->FileHeader.Machine) + ")");
        }

        if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            throw MapError("Only PE32+ images are supported");
        }

        const std::size_t image_size = nt_headers->OptionalHeader.SizeOfImage;

        if (image_size == 0 || image_size > kMaxImageSize) {
            throw MapError("Invalid SizeOfImage");
        }

        const std::uint16_t section_count = nt_headers->FileHeader.NumberOfSections;

        if (section_count == 0 || section_count > kMaxSections) {
            throw MapError("Invalid section count");
        }

        const std::size_t sections_offset = nt_offset + sizeof(IMAGE_NT_HEADERS);

        if (!range_within(
            sections_offset,
            static_cast<std::size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER),
            size
        )) {
            throw MapError("Section table falls outside the file");
        }

        const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            pe.file.data() + sections_offset
            );

        for (std::uint16_t index = 0; index < section_count; ++index) {
            const IMAGE_SECTION_HEADER& section = sections[index];
            const std::size_t extent = (std::max)(
                static_cast<std::size_t>(section.Misc.VirtualSize),
                static_cast<std::size_t>(section.SizeOfRawData)
                );

            if (!range_within(section.VirtualAddress, extent, image_size)) {
                throw MapError("Section '" + std::string(
                    reinterpret_cast<const char*>(section.Name),
                    strnlen_s(reinterpret_cast<const char*>(section.Name), IMAGE_SIZEOF_SHORT_NAME)
                ) + "' exceeds SizeOfImage");
            }

            if (section.SizeOfRawData != 0 &&
                !range_within(section.PointerToRawData, section.SizeOfRawData, size)) {
                throw MapError("Section raw data falls outside the file");
            }
        }

        pe.image_size = image_size;
        pe.size_of_headers = (std::min)(
            static_cast<std::size_t>(nt_headers->OptionalHeader.SizeOfHeaders),
            image_size
        );
        pe.nt_offset = nt_offset;
        pe.preferred_base = static_cast<std::uintptr_t>(
            nt_headers->OptionalHeader.ImageBase
            );
        pe.section_count = section_count;

        return pe;
    }

    void Mmap::build_image(PeImage& pe) {
        pe.image.assign(pe.image_size, 0);

        const std::size_t headers_to_copy = (std::min)(pe.size_of_headers, pe.file.size());

        if (headers_to_copy != 0) {
            std::memcpy(pe.image.data(), pe.file.data(), headers_to_copy);
        }

        auto* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
            pe.image.data() + pe.nt_offset
            );

        auto* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            pe.image.data() + pe.nt_offset + sizeof(IMAGE_NT_HEADERS)
            );

        for (std::uint16_t index = 0; index < pe.section_count; ++index) {
            const IMAGE_SECTION_HEADER& section = sections[index];

            if (section.SizeOfRawData == 0 || section.PointerToRawData >= pe.file.size()) {
                continue;
            }

            std::size_t to_copy = (std::min)(
                static_cast<std::size_t>(section.SizeOfRawData),
                pe.image_size - section.VirtualAddress
                );

            to_copy = (std::min)(to_copy, pe.file.size() - section.PointerToRawData);

            if (to_copy != 0) {
                std::memcpy(
                    pe.image.data() + section.VirtualAddress,
                    pe.file.data() + section.PointerToRawData,
                    to_copy
                );
            }
        }

        pe.nt = nt_headers;
        pe.sections = sections;

        pe.file.clear();
        pe.file.shrink_to_fit();
    }

    void Mmap::apply_relocations(
        PeImage& pe,
        std::uintptr_t remote_base,
        const MapOptions& options
    ) {
        if (!has_data_directory(pe.nt, IMAGE_DIRECTORY_ENTRY_BASERELOC)) {
            if (remote_base != pe.preferred_base) {
                log(options, "[!] Image has no relocations and could not be placed at its preferred base");
            }

            return;
        }

        const IMAGE_DATA_DIRECTORY directory =
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (directory.Size < sizeof(IMAGE_BASE_RELOCATION)) {
            return;
        }

        if (!range_within(directory.VirtualAddress, directory.Size, pe.image_size)) {
            throw MapError("Relocation table falls outside the image");
        }

        const auto delta = static_cast<std::int64_t>(
            static_cast<std::int64_t>(remote_base) -
            static_cast<std::int64_t>(pe.preferred_base)
            );

        std::size_t block_offset = 0;
        std::size_t skipped = 0;

        while (block_offset + sizeof(IMAGE_BASE_RELOCATION) <= directory.Size) {
            auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                pe.image.data() + directory.VirtualAddress + block_offset
                );

            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                break;
            }

            if (block_offset + block->SizeOfBlock > directory.Size) {
                throw MapError("Malformed relocation block");
            }

            const std::size_t entry_count =
                (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            const auto* entries = reinterpret_cast<const WORD*>(
                reinterpret_cast<const char*>(block) + sizeof(IMAGE_BASE_RELOCATION)
                );

            for (std::size_t index = 0; index < entry_count; ++index) {
                const BYTE type = static_cast<BYTE>(entries[index] >> 12);
                const WORD page_offset = static_cast<WORD>(entries[index] & 0x0FFF);
                const std::size_t target = static_cast<std::size_t>(block->VirtualAddress) + page_offset;

                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;

                case IMAGE_REL_BASED_HIGH: {
                    if (!range_within(target, sizeof(std::uint16_t), pe.image_size)) {
                        throw MapError("Relocation target outside image");
                    }

                    std::uint16_t value = 0;
                    std::memcpy(&value, pe.image.data() + target, sizeof(value));
                    value = static_cast<std::uint16_t>(value + static_cast<std::uint16_t>((delta >> 16) & 0xFFFF));
                    std::memcpy(pe.image.data() + target, &value, sizeof(value));
                    break;
                }

                case IMAGE_REL_BASED_LOW: {
                    if (!range_within(target, sizeof(std::uint16_t), pe.image_size)) {
                        throw MapError("Relocation target outside image");
                    }

                    std::uint16_t value = 0;
                    std::memcpy(&value, pe.image.data() + target, sizeof(value));
                    value = static_cast<std::uint16_t>(value + static_cast<std::uint16_t>(delta & 0xFFFF));
                    std::memcpy(pe.image.data() + target, &value, sizeof(value));
                    break;
                }

                case IMAGE_REL_BASED_HIGHLOW: {
                    if (!range_within(target, sizeof(std::uint32_t), pe.image_size)) {
                        throw MapError("Relocation target outside image");
                    }

                    std::uint32_t value = 0;
                    std::memcpy(&value, pe.image.data() + target, sizeof(value));
                    value = static_cast<std::uint32_t>(value + static_cast<std::uint32_t>(delta));
                    std::memcpy(pe.image.data() + target, &value, sizeof(value));
                    break;
                }

                case IMAGE_REL_BASED_DIR64: {
                    if (!range_within(target, sizeof(std::uint64_t), pe.image_size)) {
                        throw MapError("Relocation target outside image");
                    }

                    std::uint64_t value = 0;
                    std::memcpy(&value, pe.image.data() + target, sizeof(value));
                    value = static_cast<std::uint64_t>(value + static_cast<std::uint64_t>(delta));
                    std::memcpy(pe.image.data() + target, &value, sizeof(value));
                    break;
                }

                case IMAGE_REL_BASED_HIGHADJ:
                    // Consumes the following entry; x64 images do not use it.
                    ++index;
                    ++skipped;
                    break;

                default:
                    ++skipped;
                    break;
                }
            }

            block_offset += block->SizeOfBlock;
        }

        if (skipped != 0) {
            log(options, "[!] Skipped " + std::to_string(skipped) + " unsupported relocation entries");
        }
    }

    void Mmap::resolve_imports(
        const std::string& process,
        PeImage& pe,
        const MapOptions& options,
        int depth
    ) {
        if (!has_data_directory(pe.nt, IMAGE_DIRECTORY_ENTRY_IMPORT)) {
            return;
        }

        const IMAGE_DATA_DIRECTORY directory =
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (!range_within(directory.VirtualAddress, directory.Size, pe.image_size)) {
            throw MapError("Import table falls outside the image");
        }

        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            pe.image.data() + directory.VirtualAddress
            );

        const auto* descriptor_end = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            pe.image.data() + directory.VirtualAddress + directory.Size
            );

        for (; descriptor < descriptor_end && descriptor->Name != 0; ++descriptor) {
            const std::string module_name = normalize_module_name(
                read_cstring(pe, descriptor->Name)
            );

            HMODULE local_module = LoadLibraryA(module_name.c_str());

            if (local_module == nullptr) {
                throw MapError("Failed to load dependency '" + module_name +
                    "' (Win32 error " + std::to_string(GetLastError()) + ")");
            }

            if (!range_within(descriptor->FirstThunk, sizeof(IMAGE_THUNK_DATA), pe.image_size)) {
                throw MapError("Import address table outside image for " + module_name);
            }

            auto* address_table = reinterpret_cast<IMAGE_THUNK_DATA*>(
                pe.image.data() + descriptor->FirstThunk
                );

            auto* lookup_table = address_table;

            if (descriptor->OriginalFirstThunk != 0) {
                if (!range_within(descriptor->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA), pe.image_size)) {
                    throw MapError("Import lookup table outside image for " + module_name);
                }

                lookup_table = reinterpret_cast<IMAGE_THUNK_DATA*>(
                    pe.image.data() + descriptor->OriginalFirstThunk
                    );
            }

            resolve_thunk_table(
                process,
                pe,
                local_module,
                module_name,
                lookup_table,
                address_table,
                options,
                depth
            );

            // A non-zero timestamp marks the image as bound; clearing it keeps
            // the loader from trusting stale pre-computed addresses.
            descriptor->TimeDateStamp = 0;
        }
    }

    void Mmap::resolve_delay_imports(
        const std::string& process,
        PeImage& pe,
        const MapOptions& options,
        int depth
    ) {
        if (!has_data_directory(pe.nt, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)) {
            return;
        }

        const IMAGE_DATA_DIRECTORY directory =
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

        if (directory.Size < sizeof(ImgDelayDescr) ||
            !range_within(directory.VirtualAddress, directory.Size, pe.image_size)) {
            return;
        }

        auto* descriptor = reinterpret_cast<ImgDelayDescr*>(
            pe.image.data() + directory.VirtualAddress
            );

        const std::size_t descriptor_count = directory.Size / sizeof(ImgDelayDescr);

        for (std::size_t index = 0; index < descriptor_count; ++index, ++descriptor) {
            if (descriptor->rvaDLLName == 0) {
                break;
            }

            const bool rva_based = (descriptor->grAttrs & dlattrRva) != 0;

            auto to_offset = [&](DWORD value) -> std::size_t {
                if (rva_based) {
                    return value;
                }

                const auto as_va = static_cast<std::uintptr_t>(value);

                if (as_va < pe.preferred_base) {
                    throw MapError("Invalid delay-import address");
                }

                return static_cast<std::size_t>(as_va - pe.preferred_base);
                };

            const std::string module_name = normalize_module_name(
                read_cstring(pe, to_offset(descriptor->rvaDLLName))
            );

            HMODULE local_module = LoadLibraryA(module_name.c_str());

            if (local_module == nullptr) {
                throw MapError("Failed to load delay-load dependency '" + module_name + "'");
            }

            const std::size_t iat_offset = to_offset(descriptor->rvaIAT);

            if (!range_within(iat_offset, sizeof(IMAGE_THUNK_DATA), pe.image_size)) {
                throw MapError("Delay import address table outside image for " + module_name);
            }

            auto* address_table = reinterpret_cast<IMAGE_THUNK_DATA*>(
                pe.image.data() + iat_offset
                );

            auto* lookup_table = address_table;

            if (descriptor->rvaINT != 0) {
                const std::size_t int_offset = to_offset(descriptor->rvaINT);

                if (!range_within(int_offset, sizeof(IMAGE_THUNK_DATA), pe.image_size)) {
                    throw MapError("Delay import name table outside image for " + module_name);
                }

                lookup_table = reinterpret_cast<IMAGE_THUNK_DATA*>(
                    pe.image.data() + int_offset
                    );
            }

            resolve_thunk_table(
                process,
                pe,
                local_module,
                module_name,
                lookup_table,
                address_table,
                options,
                depth
            );

            descriptor->dwTimeStamp = 0;
        }
    }

    void Mmap::resolve_thunk_table(
        const std::string& process,
        PeImage& pe,
        HMODULE local_module,
        const std::string& module_name,
        IMAGE_THUNK_DATA* lookup_table,
        IMAGE_THUNK_DATA* address_table,
        const MapOptions& options,
        int depth
    ) {
        const std::uintptr_t remote_module = resolve_target_module(
            process,
            module_name,
            options,
            depth
        );

        if (remote_module == 0) {
            throw MapError("Failed to resolve target module for " + module_name);
        }

        for (; lookup_table->u1.AddressOfData != 0; ++lookup_table, ++address_table) {            std::optional<std::uint32_t> export_rva;

            if ((lookup_table->u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0) {
                export_rva = export_rva_by_ordinal(
                    local_module,
                    static_cast<WORD>(IMAGE_ORDINAL64(lookup_table->u1.Ordinal))
                );
            }
            else {
                const std::size_t name_offset = static_cast<std::size_t>(
                    lookup_table->u1.AddressOfData
                    );

                if (!range_within(name_offset, sizeof(WORD) + 1, pe.image_size)) {
                    throw MapError("Import-by-name record outside image for " + module_name);
                }

                export_rva = export_rva_by_name(
                    local_module,
                    read_cstring(pe, name_offset + sizeof(WORD))
                );
            }

            if (!export_rva.has_value()) {
                throw MapError("Unresolved import from " + module_name +
                    " (ordinal/name not found in the local copy)");
            }

            const std::uintptr_t remote_function = resolve_export_remote(
                process,
                local_module,
                *export_rva,
                options,
                depth
            );

            if (remote_function == 0) {
                throw MapError("Failed to compute remote address for an export of " + module_name);
            }

            address_table->u1.Function = remote_function;
        }

        static_cast<void>(remote_module);
    }

    std::uintptr_t Mmap::resolve_target_module(
        const std::string& process,
        const std::string& module_name,
        const MapOptions& options,
        int depth
    ) {
        if (module_name.empty()) {
            throw MapError("Empty import module name");
        }

        const std::wstring wide_name = utils::get_wstring_from_char(module_name);

        if (HMODULE loaded = memory_.get_module(wide_name).hModule) {
            return reinterpret_cast<std::uintptr_t>(loaded);
        }

        // A module we mapped earlier is not visible to the loader's module list,
        // so consult our own records before mapping a duplicate.
        const auto records = find_records(module_name);

        if (!records.empty()) {
            return static_cast<std::uintptr_t>(records.front().record.image_base);
        }

        if (depth >= kMaxImportDepth) {
            throw MapError("Import dependency chain is too deep at " + module_name);
        }

        HMODULE local_module = LoadLibraryA(module_name.c_str());

        if (local_module == nullptr) {
            throw MapError("Failed to locate dependency '" + module_name +
                "' (Win32 error " + std::to_string(GetLastError()) + ")");
        }

        const std::string path = module_full_path(local_module);

        MapOptions nested = options;
        nested.print_padding = options.print_padding + 2;

        log(options, "[*] Mapping dependency: " + module_name);

        return map_dll(process, path, nested).base;
    }

    std::uintptr_t Mmap::resolve_export_remote(
        const std::string& process,
        HMODULE local_module,
        std::uint32_t export_rva,
        const MapOptions& options,
        int depth
    ) {
        for (std::size_t hop = 0; hop < kMaxExportHops; ++hop) {
            const IMAGE_NT_HEADERS* nt_headers = local_nt_headers(local_module);

            if (nt_headers == nullptr) {
                throw MapError("Cannot read export table of a dependency");
            }

            if (IMAGE_DIRECTORY_ENTRY_EXPORT >= nt_headers->OptionalHeader.NumberOfRvaAndSizes) {
                throw MapError("Dependency has no export directory");
            }

            const IMAGE_DATA_DIRECTORY export_directory =
                nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            const auto local_base = reinterpret_cast<std::uintptr_t>(local_module);
            const bool forwarded =
                export_directory.VirtualAddress != 0 &&
                export_rva >= export_directory.VirtualAddress &&
                export_rva < export_directory.VirtualAddress + export_directory.Size;

            if (!forwarded) {
                const std::string name = module_basename(local_module);
                const std::uintptr_t remote_base = resolve_target_module(
                    process,
                    name,
                    options,
                    depth
                );

                return remote_base + export_rva;
            }

            const char* forwarder = reinterpret_cast<const char*>(
                local_base + export_rva
                );

            const std::string text = forwarder;
            const std::size_t dot = text.rfind('.');

            if (dot == std::string::npos || dot == 0 || dot + 1 >= text.size()) {
                throw MapError("Malformed export forwarder: " + text);
            }

            std::string forward_module = text.substr(0, dot);
            const std::string forward_function = text.substr(dot + 1);

            if (!forward_module.ends_with(".dll")) {
                forward_module += ".dll";
            }

            HMODULE next_module = LoadLibraryA(forward_module.c_str());

            if (next_module == nullptr) {
                throw MapError("Failed to load forwarder target " + forward_module);
            }

            std::optional<std::uint32_t> next_rva;

            if (!forward_function.empty() && forward_function.front() == '#') {
                next_rva = export_rva_by_ordinal(
                    next_module,
                    static_cast<WORD>(std::strtoul(forward_function.c_str() + 1, nullptr, 10))
                );
            }
            else {
                next_rva = export_rva_by_name(next_module, forward_function);
            }

            if (!next_rva.has_value()) {
                throw MapError("Forwarder target not found: " + text);
            }

            local_module = next_module;
            export_rva = *next_rva;
        }

        throw MapError("Export forwarder chain is too deep");
    }

    std::uintptr_t Mmap::resolve_target_export(
        const std::string& module_name,
        const char* function_name
    ) {
        HMODULE local_module = GetModuleHandleA(module_name.c_str());

        if (local_module == nullptr) {
            local_module = LoadLibraryA(module_name.c_str());
        }

        if (local_module == nullptr) {
            return 0;
        }

        const FARPROC function = GetProcAddress(local_module, function_name);

        if (function == nullptr) {
            return 0;
        }

        const auto rva = reinterpret_cast<std::uintptr_t>(function) -
            reinterpret_cast<std::uintptr_t>(local_module);

        HMODULE remote_module = memory_.get_module(
            utils::get_wstring_from_char(module_name)
        ).hModule;

        if (remote_module == nullptr) {
            return 0;
        }

        return reinterpret_cast<std::uintptr_t>(remote_module) + rva;
    }

    void Mmap::write_image(
        const PeImage& pe,
        std::uintptr_t remote_base,
        const MapOptions& options
    ) {
        if (!memory_.write_memory_with_size(
            remote_base,
            pe.image.data(),
            pe.image.size()
        )) {
            throw MapError("Failed to write the image into the target process");
        }

        DWORD old_protection = 0;

        if (pe.size_of_headers != 0) {
            static_cast<void>(memory_.virtual_protect_ex(
                remote_base,
                pe.size_of_headers,
                PAGE_READONLY,
                &old_protection
            ));
        }

        for (std::uint16_t index = 0; index < pe.section_count; ++index) {
            const IMAGE_SECTION_HEADER& section = pe.sections[index];

            const std::size_t size = (std::max)(
                static_cast<std::size_t>(section.Misc.VirtualSize),
                static_cast<std::size_t>(section.SizeOfRawData)
                );

            if (size == 0) {
                continue;
            }

            const DWORD protection = section_protection(section);

            if (!memory_.virtual_protect_ex(
                remote_base + section.VirtualAddress,
                size,
                protection,
                &old_protection
            )) {
                log(options, "[!] Failed to set protection on section " +
                    std::string(
                        reinterpret_cast<const char*>(section.Name),
                        strnlen_s(reinterpret_cast<const char*>(section.Name), IMAGE_SIZEOF_SHORT_NAME)
                    ));
            }
        }
    }

    bool Mmap::register_loader_index(
        std::uintptr_t remote_base,
        std::size_t image_size,
        const MapOptions& options
    ) {
        const auto ntdll = reinterpret_cast<std::uintptr_t>(
            memory_.get_module(L"ntdll.dll").hModule
            );

        if (ntdll == 0) {
            return false;
        }

        const std::uintptr_t insert_function = ntdll + kLoaderIndexInsertRva;

        std::array<BYTE, kLoaderIndexInsertPrologue.size()> prologue{};

        if (!memory_.read_memory_with_size(
            insert_function,
            prologue.data(),
            prologue.size()
        ) || prologue != kLoaderIndexInsertPrologue) {
            log(options, "[!] Unsupported ntdll build: loader PC index helper "
                "signature mismatch (C++ exceptions inside the DLL will not work)");
            return false;
        }

        const std::uintptr_t table = resolve_target_export(
            "ntdll.dll",
            "KiUserInvertedFunctionTable"
        );

        // A previous attempt may have left an entry behind (a map that failed
        // after registration, for example). Replace it so retries stay clean.
        if (table != 0 && image_is_in_loader_index(table, remote_base)) {
            log(options, "[*] Replacing stale loader PC index entry");
            static_cast<void>(unregister_loader_index(remote_base, options));
        }

        const auto result = memory_.remote_call(
            insert_function,
            remote_base,
            image_size,
            0,
            options.call_timeout_ms
        );

        if (!result.has_value()) {
            log(options, "[!] Loader PC index registration call failed");
            return false;
        }

        {
            std::array<std::uint32_t, 2> header{};

            if (table != 0) {
                static_cast<void>(memory_.read_memory_with_size(
                    table,
                    header.data(),
                    sizeof(header)
                ));
            }

            log(options, "[*] PC index: table " + hex(table) +
                ", count " + std::to_string(header[0]) +
                ", capacity " + std::to_string(header[1]) +
                ", insert returned " + hex(*result));
        }

        // Verify by looking the image up in the table rather than by comparing
        // counts: a busy target can load or unload modules between the two reads,
        // and the loader may grow (relocate) the array while inserting.
        if (!image_is_in_loader_index(table, remote_base)) {
            std::uint32_t count = 0;

            if (table != 0) {
                static_cast<void>(memory_.read_memory_with_size(
                    table,
                    &count,
                    sizeof(count)
                ));
            }

            log(options, "[!] Loader PC index did not accept the image (table " +
                hex(table) + ", count " + std::to_string(count) + ")");
            return false;
        }

        return true;
    }

    bool Mmap::image_is_in_loader_index(
        std::uintptr_t table,
        std::uintptr_t image_base
    ) {
        if (table == 0) {
            return false;
        }

        std::uint32_t count = 0;

        if (!memory_.read_memory_with_size(table, &count, sizeof(count)) ||
            count == 0 || count > 4096) {
            return false;
        }

        std::vector<InvertedTableEntry> entries(count);

        if (!memory_.read_memory_with_size(
            table + kInvertedTableHeaderSize,
            entries.data(),
            entries.size() * sizeof(InvertedTableEntry)
        )) {
            return false;
        }

        return std::any_of(
            entries.begin(),
            entries.end(),
            [image_base](const InvertedTableEntry& entry) {
                return entry.image_base == image_base;
            }
        );
    }

    bool Mmap::unregister_loader_index(
        std::uintptr_t remote_base,
        const MapOptions& options
    ) {        const std::uintptr_t table = resolve_target_export(
            "ntdll.dll",
            "KiUserInvertedFunctionTable"
        );

        if (table == 0) {
            return false;
        }

        std::uint32_t count = 0;

        if (!memory_.read_memory_with_size(table, &count, sizeof(count)) ||
            count == 0 || count > 1024) {
            return false;
        }

        std::vector<InvertedTableEntry> entries(count);

        if (!memory_.read_memory_with_size(
            table + kInvertedTableHeaderSize,
            entries.data(),
            entries.size() * sizeof(InvertedTableEntry)
        )) {
            return false;
        }

        const auto match = std::find_if(
            entries.begin(),
            entries.end(),
            [remote_base](const InvertedTableEntry& candidate) {
                return candidate.image_base == remote_base;
            }
        );

        if (match == entries.end()) {
            log(options, "[!] Image is not present in the loader PC index");
            return false;
        }

        entries.erase(match);

        const std::size_t bytes = kInvertedTableHeaderSize +
            (entries.size() + 1) * sizeof(InvertedTableEntry);

        DWORD old_protection = 0;

        if (!memory_.virtual_protect_ex(table, bytes, PAGE_READWRITE, &old_protection)) {
            return false;
        }

        const std::uint32_t new_count = count - 1;

        bool wrote = true;

        if (!entries.empty()) {
            wrote = memory_.write_memory_with_size(
                table + kInvertedTableHeaderSize,
                entries.data(),
                entries.size() * sizeof(InvertedTableEntry)
            );
        }

        wrote = wrote && memory_.write_memory_with_size(
            table + kInvertedTableCountOffset,
            &new_count,
            sizeof(new_count)
        );

        DWORD ignored = 0;
        static_cast<void>(memory_.virtual_protect_ex(table, bytes, old_protection, &ignored));

        return wrote;
    }

    bool Mmap::register_exception_table(
        std::uintptr_t remote_base,
        const PeImage& pe,
        const MapOptions& options,
        ModuleRecord& record
    ) {
        if (!has_data_directory(pe.nt, IMAGE_DIRECTORY_ENTRY_EXCEPTION)) {
            return false;
        }

        const IMAGE_DATA_DIRECTORY directory =
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        if (!range_within(directory.VirtualAddress, directory.Size, pe.image_size)) {
            throw MapError("Exception table falls outside the image");
        }

        const std::size_t entry_count = directory.Size / sizeof(RUNTIME_FUNCTION);

        if (entry_count == 0) {
            return false;
        }

        const std::uintptr_t add_function_table =
            resolve_target_export("ntdll.dll", "RtlAddFunctionTable");

        if (add_function_table == 0) {
            throw MapError("RtlAddFunctionTable is not available in the target");
        }

        const std::uintptr_t table = remote_base + directory.VirtualAddress;

        const auto result = memory_.remote_call(
            add_function_table,
            table,
            entry_count,
            remote_base,
            options.call_timeout_ms
        );

        if (!result.has_value()) {
            throw MapError("RtlAddFunctionTable call failed");
        }

        if ((*result & 0xFF) == 0) {
            // The loader already knows this range - typically because the PC
            // index entry went in first - and refuses a second description of
            // the same address range. That is not a mapping failure.
            log(options, "[!] RtlAddFunctionTable declined the table "
                "(range already described by the loader)");
            return false;
        }

        record.exception_table = table;
        record.exception_count = static_cast<std::uint32_t>(entry_count);

        return true;
    }

    void Mmap::run_tls_callbacks(
        std::uintptr_t remote_base,
        DWORD reason,
        const MapOptions& options
    ) {
        IMAGE_DOS_HEADER dos_header{};

        if (!memory_.read_memory_with_size(remote_base, &dos_header, sizeof(dos_header)) ||
            dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
            return;
        }

        IMAGE_NT_HEADERS nt_headers{};

        if (!memory_.read_memory_with_size(
            remote_base + dos_header.e_lfanew,
            &nt_headers,
            sizeof(nt_headers)
        )) {
            return;
        }

        if (nt_headers.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS) {
            return;
        }

        const IMAGE_DATA_DIRECTORY directory =
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

        if (directory.VirtualAddress == 0 ||
            directory.Size < sizeof(IMAGE_TLS_DIRECTORY)) {
            return;
        }

        IMAGE_TLS_DIRECTORY tls_directory{};

        if (!memory_.read_memory_with_size(
            remote_base + directory.VirtualAddress,
            &tls_directory,
            sizeof(tls_directory)
        )) {
            return;
        }

        if (tls_directory.AddressOfCallBacks == 0) {
            return;
        }

        for (std::size_t index = 0; index < kMaxTlsCallbacks; ++index) {
            std::uint64_t callback = 0;

            if (!memory_.read_memory_with_size(
                static_cast<std::uintptr_t>(tls_directory.AddressOfCallBacks) + index * sizeof(callback),
                &callback,
                sizeof(callback)
            )) {
                break;
            }

            if (callback == 0) {
                break;
            }

            const auto result = memory_.remote_call(
                callback,
                remote_base,
                reason,
                0,
                options.call_timeout_ms
            );

            if (!result.has_value()) {
                throw MapError("TLS callback " + hex(callback) + " failed to execute");
            }
        }
    }

    std::uint32_t Mmap::call_entry_point(
        std::uintptr_t remote_base,
        std::size_t entry_point_rva,
        DWORD reason,
        const MapOptions& options
    ) {
        if (entry_point_rva == 0) {
            return 1;
        }

        const auto result = memory_.remote_call(
            remote_base + entry_point_rva,
            remote_base,
            reason,
            0,
            options.call_timeout_ms
        );

        if (!result.has_value()) {
            throw MapError("Failed to execute the DLL entry point");
        }

        return static_cast<std::uint32_t>(*result & 0xFFFFFFFFu);
    }

    std::uintptr_t Mmap::write_record(const ModuleRecord& record) {
        const std::uintptr_t address = memory_.virtual_alloc_ex(
            0,
            kRecordSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (address == 0) {
            throw MapError("Failed to allocate the module record");
        }

        if (!memory_.write_memory_with_size(address, &record, sizeof(record))) {
            static_cast<void>(memory_.virtual_free_ex(address, MEM_RELEASE));
            throw MapError("Failed to write the module record");
        }

        return address;
    }

    std::vector<Mmap::FoundRecord> Mmap::find_records(const std::string& module_name) {
        std::vector<FoundRecord> found;
        const std::wstring filter = utils::get_wstring_from_char(module_name);

        std::uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION info{};

        while (address < kMaxUserAddress && memory_.virtual_query(address, info)) {
            const auto region_base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
            const auto region_size = static_cast<std::size_t>(info.RegionSize);

            if (region_size == 0) {
                break;
            }

            const bool candidate =
                info.State == MEM_COMMIT &&
                info.Type == MEM_PRIVATE &&
                (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
                (info.Protect == PAGE_READWRITE || info.Protect == PAGE_EXECUTE_READWRITE) &&
                region_size >= sizeof(ModuleRecord);

            if (candidate) {
                ModuleRecord record{};

                if (memory_.read_memory_with_size(region_base, &record, sizeof(record)) &&
                    record.magic == VEGA_MODULE_MAGIC &&
                    record.version == VEGA_MODULE_RECORD_VERSION) {
                    const std::filesystem::path stored_path(record.module_name);
                    const std::filesystem::path filter_path(filter);

                    const bool name_matches = filter.empty() ||
                        _wcsicmp(stored_path.filename().c_str(), filter_path.filename().c_str()) == 0;

                    if (name_matches) {
                        FoundRecord entry;
                        entry.address = region_base;
                        entry.record = record;
                        found.push_back(entry);
                    }
                }
            }

            address = region_base + region_size;
        }

        return found;
    }

    std::string Mmap::normalize_module_name(const std::string& module_name) {
        if (module_name.find(VIRTUAL_DLL_PREFIX) == std::string::npos) {
            return module_name;
        }

        // The loader itself understands API set names, so letting it resolve the
        // name gives us the real host module that the target's loader list
        // contains (api-ms-win-* -> kernelbase.dll, ntdll.dll, ...).
        if (const HMODULE module = LoadLibraryA(module_name.c_str())) {
            std::array<char, MAX_PATH> path{};

            if (GetModuleFileNameA(module, path.data(), static_cast<DWORD>(path.size())) != 0) {
                return std::filesystem::path(path.data()).filename().string();
            }
        }

        const std::string resolved = utils::get_dll_name_from_api_set_map(module_name);

        if (resolved.empty()) {
            throw MapError("Failed to resolve API set import '" + module_name + "'");
        }

        return resolved;
    }

    std::string Mmap::module_basename(HMODULE module) {
        return std::filesystem::path(module_full_path(module)).filename().string();
    }

    std::string Mmap::module_full_path(HMODULE module) {
        std::array<char, MAX_PATH> path{};

        if (GetModuleFileNameA(module, path.data(), static_cast<DWORD>(path.size())) == 0) {
            throw MapError("GetModuleFileName failed for a dependency");
        }

        return path.data();
    }

    const IMAGE_NT_HEADERS* Mmap::local_nt_headers(HMODULE module) {
        if (module == nullptr) {
            return nullptr;
        }

        const auto* base = reinterpret_cast<const char*>(module);
        const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }

        const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            base + dos_header->e_lfanew
            );

        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        return nt_headers;
    }

    std::optional<std::uint32_t> Mmap::export_rva_by_name(
        HMODULE module,
        std::string_view name
    ) {
        const IMAGE_NT_HEADERS* nt_headers = local_nt_headers(module);

        if (nt_headers == nullptr ||
            IMAGE_DIRECTORY_ENTRY_EXPORT >= nt_headers->OptionalHeader.NumberOfRvaAndSizes) {
            return std::nullopt;
        }

        const IMAGE_DATA_DIRECTORY directory =
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (directory.VirtualAddress == 0 ||
            directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            return std::nullopt;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(module);
        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            base + directory.VirtualAddress
            );

        const auto* names = reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
        const auto* ordinals = reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
        const auto* functions = reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);

        for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
            const char* candidate = reinterpret_cast<const char*>(base + names[index]);

            if (name != candidate) {
                continue;
            }

            const WORD ordinal = ordinals[index];

            if (ordinal >= exports->NumberOfFunctions) {
                return std::nullopt;
            }

            return functions[ordinal];
        }

        return std::nullopt;
    }

    std::optional<std::uint32_t> Mmap::export_rva_by_ordinal(
        HMODULE module,
        WORD ordinal
    ) {
        const IMAGE_NT_HEADERS* nt_headers = local_nt_headers(module);

        if (nt_headers == nullptr ||
            IMAGE_DIRECTORY_ENTRY_EXPORT >= nt_headers->OptionalHeader.NumberOfRvaAndSizes) {
            return std::nullopt;
        }

        const IMAGE_DATA_DIRECTORY directory =
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (directory.VirtualAddress == 0 ||
            directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            return std::nullopt;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(module);
        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            base + directory.VirtualAddress
            );

        if (ordinal < exports->Base) {
            return std::nullopt;
        }

        const DWORD index = ordinal - exports->Base;

        if (index >= exports->NumberOfFunctions) {
            return std::nullopt;
        }

        const auto* functions = reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);

        return functions[index];
    }

    std::string Mmap::read_cstring(
        const PeImage& pe,
        std::size_t offset,
        std::size_t limit
    ) {
        if (offset >= pe.image_size) {
            throw MapError("String offset falls outside the image");
        }

        const char* start = pe.image.data() + offset;
        const std::size_t max_length = (std::min)(limit, pe.image_size - offset);

        const void* terminator = std::memchr(start, 0, max_length);

        if (terminator == nullptr) {
            throw MapError("Unterminated string in the image");
        }

        return std::string(
            start,
            static_cast<std::size_t>(static_cast<const char*>(terminator) - start)
        );
    }

    DWORD Mmap::section_protection(const IMAGE_SECTION_HEADER& section) {
        const bool executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool readable = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        const bool writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (executable) {
            if (writable) {
                return PAGE_EXECUTE_READWRITE;
            }

            if (readable) {
                return PAGE_EXECUTE_READ;
            }

            return PAGE_EXECUTE;
        }

        if (writable) {
            return PAGE_READWRITE;
        }

        if (readable) {
            return PAGE_READONLY;
        }

        if ((section.Characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0) {
            return PAGE_NOCACHE;
        }

        return PAGE_NOACCESS;
    }

    std::string Mmap::indent(int count) {
        return std::string(static_cast<std::size_t>((std::max)(0, count)), ' ');
    }

} // namespace manualmap
