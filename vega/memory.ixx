module;

#pragma comment(lib, "ntdll")

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

export module manualmap.memory;

import manualmap.peb;
import manualmap.utils;

export namespace manualmap {

    inline constexpr BYTE FLAG_HIJACK_THREAD_FINISHED = 0x1;

    inline constexpr DWORD PAGE_READABLE =
        PAGE_READONLY |
        PAGE_READWRITE |
        PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE;

    inline bool is_valid_handle(HANDLE handle) noexcept {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }

    class Memory {
    public:
        Memory() = default;
        ~Memory();

        Memory(const Memory&) = delete;
        Memory& operator=(const Memory&) = delete;

        Memory(Memory&& other) noexcept;
        Memory& operator=(Memory&& other) noexcept;

        [[nodiscard]] bool open_handle(const std::wstring& process_name);
        [[nodiscard]] bool open_handle_by_pid(DWORD process_id);

        [[nodiscard]] DWORD last_error() const noexcept {
            return last_error_;
        }

        // Force every remote call onto an existing thread instead of a new one.
        // New threads receive DLL_THREAD_ATTACH for every loader-list module, so
        // a mapped image must not be called through a fresh thread before its
        // own entry point has initialized its runtime.
        void set_prefer_thread_hijack(bool value) noexcept {
            prefer_thread_hijack_ = value;
        }

        // True when the most recent call timed out and may still be running on a
        // target thread (a blocked DllMain, for example).
        [[nodiscard]] bool last_call_timed_out() const noexcept {
            return last_call_timed_out_;
        }

        [[nodiscard]] DWORD process_id() const noexcept {
            return process_id_;
        }

        [[nodiscard]] bool has_handle() const noexcept {
            return is_valid_handle(handle_);
        }

        [[nodiscard]] bool virtual_query(
            std::uintptr_t address,
            MEMORY_BASIC_INFORMATION& info
        );

        // Executes `function` inside the target process with the given register
        // arguments (rcx, rdx, r8) and returns the value left in rax.
        //
        // The call is performed on a freshly created remote thread so no existing
        // thread state is disturbed; if remote thread creation is unavailable the
        // call falls back to hijacking a running thread. A timeout kills the
        // remote thread and reports failure instead of hanging the loader.
        [[nodiscard]] std::optional<std::uint64_t> remote_call(
            std::uintptr_t function,
            std::uint64_t arg0,
            std::uint64_t arg1,
            std::uint64_t arg2,
            DWORD timeout_ms = 30'000
        );

        // Executes the call on an existing thread instead of creating one.
        // Protected targets routinely kill threads whose start address is not
        // backed by a module, which makes CreateRemoteThread silently useless.
        // The chosen thread is suspended, given a private stack and the stub as
        // its instruction pointer, then restored to its original context.
        [[nodiscard]] std::optional<std::uint64_t> hijack_call(
            std::uintptr_t function,
            std::uint64_t arg0,
            std::uint64_t arg1,
            std::uint64_t arg2,
            DWORD timeout_ms = 30'000
        );

        // Links a manually mapped image into the target's PEB loader list. The
        // unwinder, GetModuleHandle and module enumeration all consult that list,
        // so registering the image is what makes C++ exceptions and self-lookups
        // work inside the mapped DLL. Returns the remote LDR entry address.
        [[nodiscard]] std::uintptr_t insert_loader_module(
            std::uintptr_t image_base,
            std::size_t image_size,
            std::uintptr_t entry_point,
            std::uint32_t time_date_stamp,
            const std::wstring& full_path,
            const std::wstring& base_name,
            std::uint32_t ddag_state = 9
        );

        [[nodiscard]] bool remove_loader_module(std::uintptr_t ldr_entry);

        // Threads whose instruction pointer currently lies inside the given
        // image range. Unloading or freeing an image while any of them is still
        // executing there would make that thread resume into unmapped memory.
        [[nodiscard]] std::vector<DWORD> find_threads_in_range(
            std::uintptr_t base,
            std::size_t size
        );

        [[nodiscard]] std::uintptr_t get_proc_image_base_addr();
        [[nodiscard]] MODULEENTRY32W get_module(const std::wstring& module_name);

        [[nodiscard]] std::uintptr_t find_pattern(
            std::uintptr_t base,
            std::size_t size,
            const char* signature,
            const char* mask,
            int offset = 0
        );

        [[nodiscard]] std::uintptr_t find_codecave(
            std::uintptr_t start,
            std::uintptr_t end,
            std::size_t size,
            DWORD protection_flags
        );

        [[nodiscard]] bool hijack_thread_and_execute_shellcode(
            const BYTE* shellcode,
            std::size_t shellcode_size
        );

        template <typename Type>
        [[nodiscard]] Type read_memory(std::uintptr_t address) {
            require_process_handle();

            Type out{};
            if (!ReadProcessMemory(
                handle_,
                reinterpret_cast<LPCVOID>(address),
                &out,
                sizeof(Type),
                nullptr
            )) {
                return {};
            }

            return out;
        }

        [[nodiscard]] bool read_memory_with_size(
            std::uintptr_t address,
            void* out,
            std::size_t size
        ) {
            require_process_handle();

            return ReadProcessMemory(
                handle_,
                reinterpret_cast<LPCVOID>(address),
                out,
                size,
                nullptr
            ) != FALSE;
        }

        template <typename Type>
        [[nodiscard]] bool write_memory(std::uintptr_t destination, const Type& data) {
            require_process_handle();

            return WriteProcessMemory(
                handle_,
                reinterpret_cast<LPVOID>(destination),
                &data,
                sizeof(Type),
                nullptr
            ) != FALSE;
        }

        [[nodiscard]] bool write_memory_with_size(
            std::uintptr_t destination,
            const void* data,
            std::size_t size
        ) {
            require_process_handle();

            return WriteProcessMemory(
                handle_,
                reinterpret_cast<LPVOID>(destination),
                data,
                size,
                nullptr
            ) != FALSE;
        }

        [[nodiscard]] std::uintptr_t virtual_alloc_ex(
            std::uintptr_t address,
            std::size_t size,
            DWORD allocation_type,
            DWORD protection
        ) {
            require_process_handle();

            return reinterpret_cast<std::uintptr_t>(
                VirtualAllocEx(
                    handle_,
                    reinterpret_cast<LPVOID>(address),
                    size,
                    allocation_type,
                    protection
                )
                );
        }

        [[nodiscard]] bool virtual_protect_ex(
            std::uintptr_t address,
            std::size_t size,
            DWORD new_protection,
            DWORD* old_protection
        ) {
            require_process_handle();

            return VirtualProtectEx(
                handle_,
                reinterpret_cast<LPVOID>(address),
                size,
                new_protection,
                old_protection
            ) != FALSE;
        }

        [[nodiscard]] bool virtual_free_ex(
            std::uintptr_t address,
            DWORD free_type,
            std::size_t size = 0
        ) {
            require_process_handle();

            return VirtualFreeEx(
                handle_,
                reinterpret_cast<LPVOID>(address),
                size,
                free_type
            ) != FALSE;
        }

        [[nodiscard]] bool query_information_process(
            PROCESSINFOCLASS process_info_class,
            void* out,
            std::size_t out_size
        ) {
            require_process_handle();

            const NTSTATUS status = NtQueryInformationProcess(
                handle_,
                process_info_class,
                out,
                static_cast<ULONG>(out_size),
                nullptr
            );

            return NT_SUCCESS(status);
        }

        [[nodiscard]] bool zero_out_memory(std::uintptr_t start, std::size_t size) {
            require_process_handle();

            auto zeros = std::make_unique<BYTE[]>(size);
            std::memset(zeros.get(), 0x00, size);

            return write_memory_with_size(start, zeros.get(), size);
        }

    private:
        class UniqueHandle {
        public:
            UniqueHandle() = default;

            explicit UniqueHandle(HANDLE handle) noexcept
                : handle_(handle) {
            }

            ~UniqueHandle() {
                reset();
            }

            UniqueHandle(const UniqueHandle&) = delete;
            UniqueHandle& operator=(const UniqueHandle&) = delete;

            UniqueHandle(UniqueHandle&& other) noexcept
                : handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)) {
            }

            UniqueHandle& operator=(UniqueHandle&& other) noexcept {
                if (this != &other) {
                    reset(std::exchange(other.handle_, INVALID_HANDLE_VALUE));
                }
                return *this;
            }

            [[nodiscard]] HANDLE get() const noexcept {
                return handle_;
            }

            [[nodiscard]] bool valid() const noexcept {
                return is_valid_handle(handle_);
            }

            HANDLE release() noexcept {
                return std::exchange(handle_, INVALID_HANDLE_VALUE);
            }

            void reset(HANDLE handle = INVALID_HANDLE_VALUE) noexcept {
                if (is_valid_handle(handle_)) {
                    CloseHandle(handle_);
                }

                handle_ = handle;
            }

        private:
            HANDLE handle_ = INVALID_HANDLE_VALUE;
        };

        void close() noexcept;
        void require_process_handle() const;

        // Requests the widest useful access mask the target will grant. Full
        // PROCESS_ALL_ACCESS is often denied to restricted or non-elevated
        // callers even for same-user targets, so the rights are degraded in
        // steps instead of failing outright.
        [[nodiscard]] bool open_with_best_access(DWORD pid);

        struct RemoteModuleInfo {
            std::uintptr_t base = 0;
            std::size_t size = 0;
            std::wstring name;
        };

        // x64 LDR_DATA_TABLE_ENTRY fields that matter here. Only the load-order
        // links, image base, size and base name are read.
        struct ModuleListEntry {
            LIST_ENTRY in_load_order_links;   // 0x00
            std::byte reserved_0010[0x20];    // 0x10
            PVOID dll_base;                   // 0x30
            PVOID entry_point;                // 0x38
            ULONG size_of_image;              // 0x40
            std::byte reserved_0044[0x04];    // 0x44
            UNICODE_STRING full_dll_name;     // 0x48
            UNICODE_STRING base_dll_name;     // 0x58
        };

        static_assert(offsetof(ModuleListEntry, dll_base) == 0x30);
        static_assert(offsetof(ModuleListEntry, base_dll_name) == 0x58);

        // The x64 LDR_DATA_TABLE_ENTRY prefix written for mapped images.
        struct LoaderEntryLayout {
            LIST_ENTRY in_load_order_links;            // 0x00
            LIST_ENTRY in_memory_order_links;          // 0x10
            LIST_ENTRY in_initialization_order_links;  // 0x20
            PVOID dll_base;                            // 0x30
            PVOID entry_point;                         // 0x38
            ULONG size_of_image;                       // 0x40
            UNICODE_STRING full_dll_name;              // 0x48
            UNICODE_STRING base_dll_name;              // 0x58
            ULONG flags;                               // 0x68
            USHORT obsolete_load_count;                // 0x6C
            USHORT tls_index;                          // 0x6E
            LIST_ENTRY hash_links;                     // 0x70
            ULONG time_date_stamp;                     // 0x80
            PVOID entry_point_activation_context;      // 0x88
            PVOID lock;                                // 0x90
            PVOID ddag_node;                           // 0x98
            LIST_ENTRY node_module_link;               // 0xA0
        };

        static_assert(offsetof(LoaderEntryLayout, dll_base) == 0x30);
        static_assert(offsetof(LoaderEntryLayout, entry_point) == 0x38);
        static_assert(offsetof(LoaderEntryLayout, size_of_image) == 0x40);
        static_assert(offsetof(LoaderEntryLayout, full_dll_name) == 0x48);
        static_assert(offsetof(LoaderEntryLayout, base_dll_name) == 0x58);
        static_assert(offsetof(LoaderEntryLayout, hash_links) == 0x70);
        static_assert(offsetof(LoaderEntryLayout, time_date_stamp) == 0x80);
        static_assert(offsetof(LoaderEntryLayout, ddag_node) == 0x98);

        [[nodiscard]] std::optional<RemoteModuleInfo> find_module_in_peb(
            const std::wstring& module_name
        );

        [[nodiscard]] bool try_execute_on_thread(
            DWORD thread_id,
            std::uintptr_t shellcode_address,
            const BYTE* shellcode,
            std::size_t shellcode_size,
            const BYTE* prologue,
            std::size_t prologue_size,
            BYTE* epilogue,
            std::size_t epilogue_size,
            std::size_t complete_shellcode_size
        );

        [[nodiscard]] static std::vector<BYTE> build_call_stub(
            std::uintptr_t function,
            std::uint64_t arg0,
            std::uint64_t arg1,
            std::uint64_t arg2,
            std::uintptr_t result_slot,
            bool create_remote_thread_entry
        );

    private:
        DWORD process_id_ = 0;
        HANDLE handle_ = INVALID_HANDLE_VALUE;
        ntapi::PEB process_peb_{};
        DWORD last_error_ = 0;
        ACCESS_MASK granted_access_ = 0;
        bool prefer_thread_hijack_ = false;
        bool last_call_timed_out_ = false;
    };

} // namespace manualmap

namespace manualmap {

    namespace {

        constexpr std::size_t kCallBlockSize = 0x1000;
        constexpr std::size_t kCallStubOffset = 0x000;
        constexpr std::size_t kCallResultOffset = 0x100;
        constexpr std::size_t kHijackFlagOffset = 0x300;
        constexpr std::size_t kHijackRspOffset = 0x308;
        constexpr std::size_t kHijackOriginalRspOffset = 0x310;
        constexpr std::size_t kHijackTrailerOffset = 0x400;
        constexpr std::size_t kHijackStackSize = 0x40000;

        constexpr std::size_t kLdrEntrySize = 0x100;
        constexpr std::size_t kLdrDdagNodeOffset = 0x100;
        constexpr std::size_t kLdrDdagNodeSize = 0x200;
        constexpr std::size_t kLdrFullNameOffset = 0x300;
        constexpr std::size_t kLdrBaseNameOffset = 0x500;
        constexpr std::size_t kLdrBlockSize = 0x800;

        void append_imm64(std::vector<BYTE>& out, std::uint64_t value) {
            for (int index = 0; index < 8; ++index) {
                out.push_back(static_cast<BYTE>((value >> (index * 8)) & 0xFF));
            }
        }

        [[nodiscard]] bool is_readable_region(const MEMORY_BASIC_INFORMATION& mbi) noexcept {
            return mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                (mbi.Protect & PAGE_READABLE);
        }

        [[nodiscard]] bool region_has_protection(
            const MEMORY_BASIC_INFORMATION& mbi,
            DWORD protection
        ) noexcept {
            return mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                (mbi.Protect & protection);
        }

    } // namespace

    Memory::~Memory() {
        close();
    }

    Memory::Memory(Memory&& other) noexcept
        : process_id_(std::exchange(other.process_id_, 0)),
        handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE)),
        process_peb_(std::exchange(other.process_peb_, {})),
        last_error_(std::exchange(other.last_error_, 0)),
        granted_access_(std::exchange(other.granted_access_, 0)) {
    }

    Memory& Memory::operator=(Memory&& other) noexcept {
        if (this != &other) {
            close();

            process_id_ = std::exchange(other.process_id_, 0);
            handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE);
            process_peb_ = std::exchange(other.process_peb_, {});
            last_error_ = std::exchange(other.last_error_, 0);
            granted_access_ = std::exchange(other.granted_access_, 0);
        }

        return *this;
    }

    void Memory::close() noexcept {
        if (is_valid_handle(handle_)) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }

        process_id_ = 0;
        process_peb_ = {};
        granted_access_ = 0;
        last_error_ = 0;
    }

    void Memory::require_process_handle() const {
        if (!is_valid_handle(handle_)) {
            throw std::runtime_error("No valid process handle");
        }
    }

    bool Memory::open_handle(const std::wstring& process_name) {
        close();

        UniqueHandle snapshot{
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        };

        if (!snapshot.valid()) {
            last_error_ = GetLastError();
            return false;
        }

        PROCESSENTRY32W process_entry{};
        process_entry.dwSize = sizeof(process_entry);

        if (!Process32FirstW(snapshot.get(), &process_entry)) {
            last_error_ = GetLastError();
            return false;
        }

        do {
            if (_wcsicmp(process_entry.szExeFile, process_name.c_str()) != 0) {
                continue;
            }

            return open_with_best_access(process_entry.th32ProcessID);
        } while (Process32NextW(snapshot.get(), &process_entry));

        last_error_ = process_name.empty() ? ERROR_INVALID_PARAMETER : ERROR_NOT_FOUND;
        return false;
    }

    bool Memory::open_handle_by_pid(DWORD process_id) {
        close();

        if (process_id == 0) {
            last_error_ = ERROR_INVALID_PARAMETER;
            return false;
        }

        return open_with_best_access(process_id);
    }

    bool Memory::open_with_best_access(DWORD pid) {
        constexpr ACCESS_MASK kFullAccess =
            PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ |
            PROCESS_SUSPEND_RESUME;

        constexpr ACCESS_MASK kNoHijackAccess =
            PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ;

        constexpr ACCESS_MASK kMinimalAccess =
            PROCESS_CREATE_THREAD |
            PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ;

        const ACCESS_MASK candidates[] = {
            PROCESS_ALL_ACCESS,
            kFullAccess,
            kNoHijackAccess,
            kMinimalAccess
        };

        last_error_ = 0;

        for (const ACCESS_MASK rights : candidates) {
            const HANDLE handle = OpenProcess(rights, FALSE, pid);

            if (is_valid_handle(handle)) {
                process_id_ = pid;
                handle_ = handle;
                granted_access_ = rights;
                return true;
            }

            last_error_ = GetLastError();
        }

        return false;
    }

    bool Memory::virtual_query(
        std::uintptr_t address,
        MEMORY_BASIC_INFORMATION& info
    ) {
        require_process_handle();

        info = {};

        return VirtualQueryEx(
            handle_,
            reinterpret_cast<LPCVOID>(address),
            &info,
            sizeof(info)
        ) == sizeof(info);
    }

    std::vector<BYTE> Memory::build_call_stub(
        std::uintptr_t function,
        std::uint64_t arg0,
        std::uint64_t arg1,
        std::uint64_t arg2,
        std::uintptr_t result_slot,
        bool create_remote_thread_entry
    ) {
        std::vector<BYTE> stub;
        stub.reserve(96);

        // mov rcx, arg0
        stub.push_back(0x48); stub.push_back(0xB9); append_imm64(stub, arg0);
        // mov rdx, arg1
        stub.push_back(0x48); stub.push_back(0xBA); append_imm64(stub, arg1);
        // mov r8, arg2
        stub.push_back(0x49); stub.push_back(0xB8); append_imm64(stub, arg2);
        // mov r9, 0
        stub.push_back(0x49); stub.push_back(0xB9); append_imm64(stub, 0);

        if (create_remote_thread_entry) {
            // A remote thread starts with rsp = 8 (mod 16); reserve shadow space.
            stub.insert(stub.end(), { 0x48, 0x83, 0xEC, 0x28 });
        }

        // mov rax, function
        stub.push_back(0x48); stub.push_back(0xB8); append_imm64(stub, function);
        // call rax
        stub.push_back(0xFF); stub.push_back(0xD0);

        if (create_remote_thread_entry) {
            stub.insert(stub.end(), { 0x48, 0x83, 0xC4, 0x28 });
        }

        // mov [result_slot], rax
        stub.push_back(0x48); stub.push_back(0xA3); append_imm64(stub, result_slot);

        if (create_remote_thread_entry) {
            // ret
            stub.push_back(0xC3);
        }

        return stub;
    }

    std::optional<std::uint64_t> Memory::remote_call(
        std::uintptr_t function,
        std::uint64_t arg0,
        std::uint64_t arg1,
        std::uint64_t arg2,
        DWORD timeout_ms
    ) {
        require_process_handle();

        last_call_timed_out_ = false;

        if (function == 0) {
            return std::nullopt;
        }

        if (prefer_thread_hijack_) {
            return hijack_call(function, arg0, arg1, arg2, timeout_ms);
        }

        const std::uintptr_t block = virtual_alloc_ex(
            0,
            kCallBlockSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (block == 0) {
            return std::nullopt;
        }

        auto release_block = [&]() noexcept {
            auto result = virtual_free_ex(block, MEM_RELEASE);
        };

        const std::uintptr_t stub_address = block + kCallStubOffset;
        const std::uintptr_t result_slot = block + kCallResultOffset;

        const std::uint64_t zero = 0;

        if (!write_memory_with_size(result_slot, &zero, sizeof(zero))) {
            release_block();
            return std::nullopt;
        }

        const auto stub = build_call_stub(
            function,
            arg0,
            arg1,
            arg2,
            result_slot,
            true
        );

        if (!write_memory_with_size(stub_address, stub.data(), stub.size())) {
            release_block();
            return std::nullopt;
        }

        UniqueHandle thread{
            CreateRemoteThread(
                handle_,
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(stub_address),
                nullptr,
                0,
                nullptr
            )
        };

        if (!thread.valid()) {
            release_block();
            return hijack_call(function, arg0, arg1, arg2, timeout_ms);
        }

        const DWORD wait_result = WaitForSingleObject(thread.get(), timeout_ms);

        if (wait_result != WAIT_OBJECT_0) {
            TerminateThread(thread.get(), 0);
            WaitForSingleObject(thread.get(), 5'000);
            release_block();
            return std::nullopt;
        }

        std::uint64_t result = 0;
        const bool read_ok = read_memory_with_size(result_slot, &result, sizeof(result));

        release_block();

        if (!read_ok) {
            return std::nullopt;
        }

        return result;
    }

    std::optional<std::uint64_t> Memory::hijack_call(
        std::uintptr_t function,
        std::uint64_t arg0,
        std::uint64_t arg1,
        std::uint64_t arg2,
        DWORD timeout_ms
    ) {
        require_process_handle();

        last_call_timed_out_ = false;

        if (function == 0) {
            return std::nullopt;
        }

        const std::uintptr_t block = virtual_alloc_ex(
            0,
            kCallBlockSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (block == 0) {
            return std::nullopt;
        }

        auto release_block = [&]() noexcept {
            auto result = virtual_free_ex(block, MEM_RELEASE);
        };

        const std::uintptr_t result_slot = block + kCallResultOffset;
        const std::uintptr_t flag_slot = block + kHijackFlagOffset;
        const std::uintptr_t saved_rsp_slot = block + kHijackRspOffset;
        const std::uintptr_t original_rsp_slot = block + kHijackOriginalRspOffset;
        const std::uintptr_t jump_target = block + kHijackTrailerOffset;

        const std::uint64_t zero = 0;
        const BYTE zero_byte = 0;

        if (!write_memory_with_size(result_slot, &zero, sizeof(zero)) ||
            !write_memory_with_size(flag_slot, &zero_byte, sizeof(zero_byte)) ||
            !write_memory_with_size(saved_rsp_slot, &zero, sizeof(zero)) ||
            !write_memory_with_size(original_rsp_slot, &zero, sizeof(zero))) {
            release_block();
            return std::nullopt;
        }

        UniqueHandle snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process_id_) };

        if (!snapshot.valid()) {
            release_block();
            return std::nullopt;
        }

        THREADENTRY32 thread_entry{};
        thread_entry.dwSize = sizeof(thread_entry);

        if (!Thread32First(snapshot.get(), &thread_entry)) {
            release_block();
            return std::nullopt;
        }

        do {
            if (thread_entry.th32OwnerProcessID != process_id_) {
                continue;
            }

            UniqueHandle thread{
                OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID)
            };

            if (!thread.valid()) {
                thread.reset(OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                    FALSE,
                    thread_entry.th32ThreadID
                ));
            }

            if (!thread.valid()) {
                continue;
            }

            if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) {
                continue;
            }

            CONTEXT saved{};
            saved.ContextFlags = CONTEXT_FULL;

            if (!GetThreadContext(thread.get(), &saved) || saved.Rip == 0) {
                ResumeThread(thread.get());
                continue;
            }

            // The stub restores the interrupted context itself, so a call that
            // blocks (a modal dialog in DllMain) simply stays blocked on this
            // thread instead of being torn off its stack by a context restore.
            if (!write_memory_with_size(jump_target, &saved.Rip, sizeof(saved.Rip)) ||
                !write_memory_with_size(
                    original_rsp_slot,
                    &saved.Rsp,
                    sizeof(saved.Rsp)
                )) {
                ResumeThread(thread.get());
                break;
            }

            std::vector<BYTE> stub;
            stub.reserve(160);

            stub.push_back(0x9C);                                   // pushfq
            stub.push_back(0x50);                                   // push rax
            stub.push_back(0x51);                                   // push rcx
            stub.push_back(0x52);                                   // push rdx
            stub.insert(stub.end(), { 0x41, 0x50 });                // push r8
            stub.insert(stub.end(), { 0x41, 0x51 });                // push r9
            stub.insert(stub.end(), { 0x41, 0x52 });                // push r10
            stub.insert(stub.end(), { 0x41, 0x53 });                // push r11
            stub.push_back(0x49); stub.push_back(0xBB); append_imm64(stub, saved_rsp_slot);
            stub.insert(stub.end(), { 0x49, 0x89, 0x23 });          // mov [r11], rsp
            stub.push_back(0x48); stub.push_back(0xB9); append_imm64(stub, arg0);
            stub.push_back(0x48); stub.push_back(0xBA); append_imm64(stub, arg1);
            stub.push_back(0x49); stub.push_back(0xB8); append_imm64(stub, arg2);
            stub.insert(stub.end(), { 0x48, 0x83, 0xE4, 0xF0 });    // and rsp, -16
            stub.insert(stub.end(), { 0x48, 0x83, 0xEC, 0x20 });    // sub rsp, 20h (aligned)
            stub.push_back(0x48); stub.push_back(0xB8); append_imm64(stub, function);
            stub.push_back(0xFF); stub.push_back(0xD0);             // call rax
            stub.push_back(0x48); stub.push_back(0xA3); append_imm64(stub, result_slot);
            stub.push_back(0x49); stub.push_back(0xBB); append_imm64(stub, flag_slot);
            stub.insert(stub.end(), { 0x41, 0xC6, 0x03, 0x01 });    // mov byte [r11], 1
            stub.push_back(0x49); stub.push_back(0xBB); append_imm64(stub, saved_rsp_slot);
            stub.insert(stub.end(), { 0x49, 0x8B, 0x23 });          // mov rsp, [r11]
            stub.insert(stub.end(), { 0x41, 0x5B });                // pop r11
            stub.insert(stub.end(), { 0x41, 0x5A });                // pop r10
            stub.insert(stub.end(), { 0x41, 0x59 });                // pop r9
            stub.insert(stub.end(), { 0x41, 0x58 });                // pop r8
            stub.push_back(0x5A);                                   // pop rdx
            stub.push_back(0x59);                                   // pop rcx
            stub.push_back(0x58);                                   // pop rax
            stub.push_back(0x9D);                                   // popfq
            stub.push_back(0x49); stub.push_back(0xBB);
            append_imm64(stub, original_rsp_slot);
            stub.insert(stub.end(), { 0x49, 0x8B, 0x23 });          // mov rsp, [r11]
            stub.insert(stub.end(), { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 });

            std::array<BYTE, 8> target_bytes{};
            std::memcpy(target_bytes.data(), &saved.Rip, sizeof(saved.Rip));
            stub.insert(stub.end(), target_bytes.begin(), target_bytes.end());

            if (!write_memory_with_size(block, stub.data(), stub.size())) {
                ResumeThread(thread.get());
                break;
            }

            FlushInstructionCache(handle_, reinterpret_cast<LPCVOID>(block), stub.size());

            CONTEXT hijacked = saved;
            hijacked.Rip = block;

            // Rsp is left untouched: the stub explicitly aligns a frame and
            // restores the original Rsp when it returns, and keeping the real
            // thread stack keeps SEH dispatch and stack-limit checks valid.

            if (!SetThreadContext(thread.get(), &hijacked)) {
                ResumeThread(thread.get());
                break;
            }

            ResumeThread(thread.get());

            bool finished = false;
            const ULONGLONG deadline = GetTickCount64() + timeout_ms;

            while (GetTickCount64() < deadline) {
                BYTE flag = 0;

                if (read_memory_with_size(flag_slot, &flag, sizeof(flag)) && flag == 1) {
                    finished = true;
                    break;
                }

                Sleep(5);
            }

            if (!finished) {
                // The call is still running (a modal dialog, for example). Leave
                // the thread and its stub alone: the call may still return
                // through the stub, and unmapping the page under it would crash
                // the target. Leaking one page is the safe outcome.
                last_call_timed_out_ = true;
                return std::nullopt;
            }

            std::uint64_t result = 0;
            const bool read_ok = read_memory_with_size(result_slot, &result, sizeof(result));

            // Wait for the thread to leave the stub before unmapping it.
            for (int attempt = 0; attempt < 20; ++attempt) {
                Sleep(5);
                static_cast<void>(SuspendThread(thread.get()));

                CONTEXT current{};
                current.ContextFlags = CONTEXT_CONTROL;
                const bool outside = GetThreadContext(thread.get(), &current) &&
                    !(current.Rip >= block && current.Rip < block + stub.size());

                ResumeThread(thread.get());

                if (outside) {
                    release_block();
                    return read_ok ? std::optional<std::uint64_t>(result) : std::nullopt;
                }
            }

            // Could not prove the thread left the stub; leaking a page is safer
            // than unmapping code that may still be executing.
            return read_ok ? std::optional<std::uint64_t>(result) : std::nullopt;
        } while (Thread32Next(snapshot.get(), &thread_entry));

        release_block();
        return std::nullopt;
    }

    std::uintptr_t Memory::get_proc_image_base_addr() {
        require_process_handle();

        if (process_peb_.ImageBaseAddress != nullptr) {
            return reinterpret_cast<std::uintptr_t>(process_peb_.ImageBaseAddress);
        }

        PROCESS_BASIC_INFORMATION process_basic_info{};

        if (!query_information_process(
            ProcessBasicInformation,
            &process_basic_info,
            sizeof(process_basic_info)
        )) {
            return 0;
        }

        ntapi::PEB target_peb{};

        if (!read_memory_with_size(
            reinterpret_cast<std::uintptr_t>(process_basic_info.PebBaseAddress),
            &target_peb,
            sizeof(target_peb)
        )) {
            return 0;
        }

        process_peb_ = target_peb;

        return reinterpret_cast<std::uintptr_t>(process_peb_.ImageBaseAddress);
    }

    MODULEENTRY32W Memory::get_module(const std::wstring& module_name) {
        require_process_handle();

        if (module_name.empty()) {
            return {};
        }

        // The PEB loader list is authoritative and only needs PROCESS_VM_READ,
        // so prefer it over the Toolhelp snapshot, which is denied for callers
        // that only hold limited query rights.
        if (const auto loaded = find_module_in_peb(module_name); loaded.has_value()) {
            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);
            entry.th32ProcessID = process_id_;
            entry.modBaseAddr = reinterpret_cast<BYTE*>(loaded->base);
            entry.modBaseSize = static_cast<DWORD>(loaded->size);
            entry.hModule = reinterpret_cast<HMODULE>(loaded->base);
            wcsncpy_s(entry.szModule, loaded->name.c_str(), _TRUNCATE);
            return entry;
        }

        UniqueHandle snapshot{
            CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                process_id_
            )
        };

        if (!snapshot.valid()) {
            return {};
        }

        MODULEENTRY32W module_entry{};
        module_entry.dwSize = sizeof(module_entry);

        if (!Module32FirstW(snapshot.get(), &module_entry)) {
            return {};
        }

        do {
            if (_wcsicmp(module_name.c_str(), module_entry.szModule) == 0) {
                return module_entry;
            }
        } while (Module32NextW(snapshot.get(), &module_entry));

        return {};
    }

    std::optional<Memory::RemoteModuleInfo> Memory::find_module_in_peb(
        const std::wstring& module_name
    ) {
        PROCESS_BASIC_INFORMATION basic_info{};

        if (!query_information_process(
            ProcessBasicInformation,
            &basic_info,
            sizeof(basic_info)
        )) {
            return std::nullopt;
        }

        const auto peb = reinterpret_cast<std::uintptr_t>(basic_info.PebBaseAddress);

        if (peb == 0) {
            return std::nullopt;
        }

        std::uintptr_t ldr = 0;

        if (!read_memory_with_size(peb + 0x18, &ldr, sizeof(ldr)) || ldr == 0) {
            return std::nullopt;
        }

        // PEB_LDR_DATA::InLoadOrderModuleList is at offset 0x10 on x64.
        const std::uintptr_t list_head = ldr + 0x10;
        std::uintptr_t flink = 0;

        if (!read_memory_with_size(list_head, &flink, sizeof(flink)) || flink == 0) {
            return std::nullopt;
        }

        std::uintptr_t entry_address = flink;

        for (std::size_t guard = 0; guard < 1024; ++guard) {
            if (entry_address == 0 || entry_address == list_head) {
                break;
            }

            ModuleListEntry entry{};

            if (!read_memory_with_size(entry_address, &entry, sizeof(entry))) {
                break;
            }

            std::wstring name;

            if (entry.base_dll_name.Length != 0 && entry.base_dll_name.Buffer != nullptr) {
                const std::size_t byte_length = entry.base_dll_name.Length;
                std::wstring buffer(byte_length / sizeof(wchar_t), L'\0');

                if (read_memory_with_size(
                    reinterpret_cast<std::uintptr_t>(entry.base_dll_name.Buffer),
                    buffer.data(),
                    byte_length
                )) {
                    name = std::move(buffer);
                }
            }

            if (entry.dll_base != nullptr && _wcsicmp(name.c_str(), module_name.c_str()) == 0) {
                RemoteModuleInfo info;
                info.base = reinterpret_cast<std::uintptr_t>(entry.dll_base);
                info.size = entry.size_of_image;
                info.name = std::move(name);
                return info;
            }

            flink = reinterpret_cast<std::uintptr_t>(entry.in_load_order_links.Flink);
            entry_address = flink;
        }

        return std::nullopt;
    }

    std::uintptr_t Memory::insert_loader_module(
        std::uintptr_t image_base,
        std::size_t image_size,
        std::uintptr_t entry_point,
        std::uint32_t time_date_stamp,
        const std::wstring& full_path,
        const std::wstring& base_name,
        std::uint32_t ddag_state
    ) {
        require_process_handle();

        PROCESS_BASIC_INFORMATION basic_info{};

        if (!query_information_process(ProcessBasicInformation, &basic_info, sizeof(basic_info))) {
            return 0;
        }

        const auto peb = reinterpret_cast<std::uintptr_t>(basic_info.PebBaseAddress);

        if (peb == 0) {
            return 0;
        }

        std::uintptr_t ldr = 0;

        if (!read_memory_with_size(peb + 0x18, &ldr, sizeof(ldr)) || ldr == 0) {
            return 0;
        }

        const std::uintptr_t block = virtual_alloc_ex(
            0,
            kLdrBlockSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (block == 0) {
            return 0;
        }

        auto release = [&]() noexcept {
            auto result = virtual_free_ex(block, MEM_RELEASE);
        };

        const std::uintptr_t base_name_address = block + kLdrBaseNameOffset;
        const std::uintptr_t full_name_address = block + kLdrFullNameOffset;

        auto write_wide_string = [&](std::uintptr_t destination, const std::wstring& text) -> std::uint16_t {
            const auto bytes = static_cast<std::uint16_t>(
                (text.size() + 1) * sizeof(wchar_t)
                );

            if (!write_memory_with_size(destination, text.c_str(), bytes)) {
                return 0;
            }

            return bytes;
            };

        const std::uint16_t base_length = write_wide_string(base_name_address, base_name);
        const std::uint16_t full_length = write_wide_string(full_name_address, full_path);

        if (base_length == 0 || full_length == 0) {
            release();
            return 0;
        }

        std::array<std::byte, kLdrEntrySize> buffer{};
        auto* entry = reinterpret_cast<LoaderEntryLayout*>(buffer.data());

        entry->dll_base = reinterpret_cast<PVOID>(image_base);
        entry->entry_point = reinterpret_cast<PVOID>(entry_point);
        entry->size_of_image = static_cast<ULONG>(image_size);
        entry->base_dll_name = {
            base_length,
            base_length,
            reinterpret_cast<PWSTR>(base_name_address)
        };
        entry->full_dll_name = {
            full_length,
            full_length,
            reinterpret_cast<PWSTR>(full_name_address)
        };
        entry->time_date_stamp = static_cast<ULONG>(time_date_stamp);

        // 0xFFFF is the loader's "this module has no TLS slot" sentinel. Leaving
        // it zero makes ntdll index TEB->TlsSlots[0], which belongs to some other
        // module and is null for us, crashing thread initialization.
        entry->tls_index = 0xFFFF;

        // The loader dereferences LDR_DATA_TABLE_ENTRY::DdagNode (offset 0x98)
        // while walking modules for thread initialization. Give it a zeroed node
        // whose state field is set to the "loaded" value it expects.
        const std::uintptr_t ddag_node = block + kLdrDdagNodeOffset;
        entry->ddag_node = reinterpret_cast<PVOID>(ddag_node);

        // Mirror the flags of a real loaded *DLL* (the newest load-order entry):
        // some loader paths branch on LDRP_PROCESS_ATTACH_CALLED / LDRP_IMAGE_DLL
        // and misbehave on zeros or on the process image's flag set.
        std::uintptr_t reference_entry = 0;

        {
            const std::uintptr_t load_order_tail_address = ldr + 0x10 + sizeof(std::uintptr_t);

            if (read_memory_with_size(
                load_order_tail_address,
                &reference_entry,
                sizeof(reference_entry)
            ) && reference_entry != 0 && reference_entry != ldr + 0x10) {
                ULONG reference_flags = 0;

                if (read_memory_with_size(
                    reference_entry + 0x68,
                    &reference_flags,
                    sizeof(reference_flags)
                )) {
                    entry->flags = reference_flags;
                }

                USHORT reference_load_count = 0;

                if (read_memory_with_size(
                    reference_entry + 0x6C,
                    &reference_load_count,
                    sizeof(reference_load_count)
                )) {
                    entry->obsolete_load_count = reference_load_count;
                }
            }
        }


        if (!write_memory_with_size(block, buffer.data(), buffer.size())) {
            release();
            return 0;
        }

        std::array<std::byte, kLdrDdagNodeSize> ddag_node_buffer{};
        constexpr std::size_t kDdagStateOffset = 0x38;
        std::memcpy(
            ddag_node_buffer.data() + kDdagStateOffset,
            &ddag_state,
            sizeof(ddag_state)
        );

        if (!write_memory_with_size(
            ddag_node,
            ddag_node_buffer.data(),
            ddag_node_buffer.size()
        )) {
            release();
            return 0;
        }

        // Insert into the load-order and memory-order lists. Address lookups
        // (RtlPcToFileHeader, the unwinder) and name lookups each walk one of
        // them. The initialization-order list is left alone: it is what ntdll
        // walks to deliver DLL_THREAD_ATTACH, which a mapped image cannot
        // service before its own entry point has run.
        const std::array<std::size_t, 2> link_offsets{ 0x00, 0x10 };
        const std::array<std::size_t, 2> head_offsets{ 0x10, 0x20 };

        for (std::size_t index = 0; index < link_offsets.size(); ++index) {
            const std::uintptr_t head = ldr + head_offsets[index];
            const std::uintptr_t self = block + link_offsets[index];
            const std::uintptr_t self_blink = self + sizeof(std::uintptr_t);

            std::uintptr_t last = 0;

            if (!read_memory_with_size(head + sizeof(std::uintptr_t), &last, sizeof(last))) {
                release();
                return 0;
            }

            // Append before the head, which is the tail of the circular list.
            if (!write_memory_with_size(self, &head, sizeof(head)) ||
                !write_memory_with_size(self_blink, &last, sizeof(last))) {
                release();
                return 0;
            }

            if (!write_memory_with_size(last, &self, sizeof(self)) ||
                !write_memory_with_size(head + sizeof(std::uintptr_t), &self, sizeof(self))) {
                release();
                return 0;
            }
        }

        return block;
    }

    bool Memory::remove_loader_module(std::uintptr_t ldr_entry) {
        require_process_handle();

        if (ldr_entry == 0) {
            return false;
        }

        bool removed = true;

        const std::array<std::size_t, 2> link_offsets{ 0x00, 0x10 };

        for (const std::size_t link_offset : link_offsets) {
            const std::uintptr_t self = ldr_entry + link_offset;

            std::uintptr_t flink = 0;
            std::uintptr_t blink = 0;

            if (!read_memory_with_size(self, &flink, sizeof(flink)) ||
                !read_memory_with_size(self + sizeof(std::uintptr_t), &blink, sizeof(blink)) ||
                flink == 0 || blink == 0) {
                removed = false;
                continue;
            }

            if (!write_memory_with_size(blink, &flink, sizeof(flink))) {
                removed = false;
            }

            const std::uintptr_t flink_blink = flink + sizeof(std::uintptr_t);

            if (!write_memory_with_size(flink_blink, &blink, sizeof(blink))) {
                removed = false;
            }
        }

        return removed;
    }

    std::vector<DWORD> Memory::find_threads_in_range(
        std::uintptr_t base,
        std::size_t size
    ) {
        std::vector<DWORD> threads;

        if (base == 0 || size == 0) {
            return threads;
        }

        require_process_handle();

        UniqueHandle snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process_id_) };

        if (!snapshot.valid()) {
            return threads;
        }

        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);

        if (!Thread32First(snapshot.get(), &entry)) {
            return threads;
        }

        do {
            if (entry.th32OwnerProcessID != process_id_) {
                continue;
            }

            UniqueHandle thread{ OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                FALSE,
                entry.th32ThreadID
            ) };

            if (!thread.valid()) {
                continue;
            }

            const bool suspended =
                SuspendThread(thread.get()) != static_cast<DWORD>(-1);

            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL;

            const bool got = GetThreadContext(thread.get(), &context) != FALSE;

            if (suspended) {
                ResumeThread(thread.get());
            }

            if (!got) {
                continue;
            }

            const auto rip = static_cast<std::uintptr_t>(context.Rip);

            bool uses_image = rip >= base && rip < base + size;

            if (!uses_image) {
                // A thread blocked inside a call made from the image has the
                // image's return addresses on its stack even though Rip points
                // into ntdll (Sleep, MessageBox, ...). Scan the stack for them.
                const auto stack_pointer = static_cast<std::uintptr_t>(context.Rsp);
                constexpr std::size_t kChunkSize = 0x1000;
                constexpr std::size_t kMaxStackScan = 0x40000;

                std::array<BYTE, kChunkSize> buffer{};

                for (std::size_t offset = 0; offset < kMaxStackScan; offset += kChunkSize) {
                    if (!read_memory_with_size(
                        stack_pointer + offset,
                        buffer.data(),
                        buffer.size()
                    )) {
                        break;
                    }

                    for (std::size_t index = 0;
                        index + sizeof(std::uintptr_t) <= buffer.size();
                        index += sizeof(std::uintptr_t)) {
                        std::uintptr_t value = 0;
                        std::memcpy(&value, buffer.data() + index, sizeof(value));

                        if (value >= base && value < base + size) {
                            uses_image = true;
                            break;
                        }
                    }

                    if (uses_image) {
                        break;
                    }
                }
            }

            if (uses_image) {
                threads.push_back(entry.th32ThreadID);
            }
        } while (Thread32Next(snapshot.get(), &entry));

        return threads;
    }

    std::uintptr_t Memory::find_pattern(
        std::uintptr_t base,
        std::size_t size,
        const char* signature,
        const char* mask,
        int offset
    ) {
        require_process_handle();

        if (signature == nullptr || mask == nullptr) {
            return 0;
        }

        const std::size_t mask_length = std::strlen(mask);
        if (mask_length == 0 || size < mask_length) {
            return 0;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        std::uintptr_t current = base;
        const std::uintptr_t end = base + size;

        while (current < end &&
            VirtualQueryEx(
                handle_,
                reinterpret_cast<LPCVOID>(current),
                &mbi,
                sizeof(mbi)
            )) {
            const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto region_size = static_cast<std::size_t>(mbi.RegionSize);

            if (is_readable_region(mbi)) {
                auto buffer = std::make_unique<char[]>(region_size);

                if (read_memory_with_size(region_base, buffer.get(), region_size)) {
                    for (std::size_t byte_index = 0;
                        byte_index + mask_length <= region_size;
                        ++byte_index) {
                        bool matched = true;

                        for (std::size_t mask_index = 0;
                            mask_index < mask_length;
                            ++mask_index) {
                            if (mask[mask_index] != '?' &&
                                buffer[byte_index + mask_index] != signature[mask_index]) {
                                matched = false;
                                break;
                            }
                        }

                        if (matched) {
                            return region_base + byte_index + offset;
                        }
                    }
                }
            }

            current = region_base + region_size;
        }

        return 0;
    }

    std::uintptr_t Memory::find_codecave(
        std::uintptr_t start,
        std::uintptr_t end,
        std::size_t size,
        DWORD protection
    ) {
        require_process_handle();

        if (size == 0 || start >= end) {
            return 0;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        std::uintptr_t current = start;

        while (current < end&&
            VirtualQueryEx(
                handle_,
                reinterpret_cast<LPCVOID>(current),
                &mbi,
                sizeof(mbi)
            )) {
            const auto region_base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto region_size = static_cast<std::size_t>(mbi.RegionSize);

            if (region_has_protection(mbi, protection) && region_size >= size) {
                auto page = std::make_unique<BYTE[]>(region_size);

                if (!read_memory_with_size(region_base, page.get(), region_size)) {
                    current = region_base + region_size;
                    continue;
                }

                std::size_t run_length = 0;

                for (std::size_t i = region_size; i > 0; --i) {
                    const std::size_t index = i - 1;

                    if (page[index] == 0x00) {
                        ++run_length;

                        if (run_length >= size) {
                            return region_base + index;
                        }
                    }
                    else {
                        run_length = 0;
                    }
                }
            }

            current = region_base + region_size;
        }

        return 0;
    }

    bool Memory::try_execute_on_thread(
        DWORD thread_id,
        std::uintptr_t shellcode_address,
        const BYTE* shellcode,
        std::size_t shellcode_size,
        const BYTE* prologue,
        std::size_t prologue_size,
        BYTE* epilogue,
        std::size_t epilogue_size,
        std::size_t complete_shellcode_size
    ) {
        UniqueHandle thread{
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                FALSE,
                thread_id
            )
        };

        if (!thread.valid()) {
            return false;
        }

        if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) {
            return false;
        }

        bool should_resume = true;

        auto resume_thread = [&]() noexcept {
            if (should_resume) {
                ResumeThread(thread.get());
                should_resume = false;
            }
            };

        CONTEXT context{};
        context.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(thread.get(), &context)) {
            resume_thread();
            return false;
        }

        std::memcpy(&epilogue[2], &shellcode_address, sizeof(std::uintptr_t));
        std::memcpy(&epilogue[42], &context.Rip, sizeof(std::uintptr_t));

        context.Rip = shellcode_address;

        auto complete_shellcode = std::make_unique<BYTE[]>(complete_shellcode_size);

        std::memcpy(
            complete_shellcode.get(),
            prologue,
            prologue_size
        );

        std::memcpy(
            complete_shellcode.get() + prologue_size,
            shellcode,
            shellcode_size
        );

        std::memcpy(
            complete_shellcode.get() + prologue_size + shellcode_size,
            epilogue,
            epilogue_size
        );

        if (!write_memory_with_size(
            shellcode_address,
            complete_shellcode.get(),
            complete_shellcode_size
        )) {
            resume_thread();
            return false;
        }

        if (!SetThreadContext(thread.get(), &context)) {
            resume_thread();
            return false;
        }

        resume_thread();

        // Prevent an infinite wait if the remote shellcode never reaches the completion flag.
        constexpr int max_wait_iterations = 1000;

        for (int i = 0; i < max_wait_iterations; ++i) {
            if (read_memory<BYTE>(shellcode_address) == FLAG_HIJACK_THREAD_FINISHED) {
                return true;
            }

            utils::sleep(10);
        }

        return false;
    }

    bool Memory::hijack_thread_and_execute_shellcode(
        const BYTE* shellcode,
        std::size_t shellcode_size
    ) {
        require_process_handle();

        if (shellcode == nullptr || shellcode_size == 0) {
            return false;
        }

        std::array<BYTE, 26> prologue{
            0x9C,
            0x50,
            0x57,
            0x56,
            0x52,
            0x51,
            0x41, 0x50,
            0x41, 0x51,
            0x41, 0x52,
            0x41, 0x53,
            0x54,
            0xFF, 0x34, 0x24,
            0x48, 0x83, 0xE4, 0xF0,
            0x48, 0x83, 0xEC, 0x20
        };

        std::array<BYTE, 50> epilogue{
            0x48, 0xB8,
            0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,
            0xC6, 0x00, 0x01,
            0x48, 0x83, 0xC4, 0x20,
            0x48, 0x8B, 0x64, 0x24, 0x08,
            0x41, 0x5B,
            0x41, 0x5A,
            0x41, 0x59,
            0x41, 0x58,
            0x59,
            0x5A,
            0x5E,
            0x5F,
            0x58,
            0x9D,
            0xFF, 0x25,
            0x00, 0x00, 0x00, 0x00,
            0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE
        };

        const std::size_t complete_shellcode_size =
            prologue.size() +
            shellcode_size +
            epilogue.size();

        std::uintptr_t shellcode_address = find_codecave(
            0,
            UINT64_MAX,
            complete_shellcode_size,
            PAGE_EXECUTE_READWRITE
        );

        bool allocated = false;

        if (shellcode_address == 0) {
            shellcode_address = virtual_alloc_ex(
                0,
                complete_shellcode_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if (shellcode_address == 0) {
                return false;
            }

            allocated = true;
        }

        auto cleanup_shellcode = [&]() {
            if (allocated) {
                auto result = virtual_free_ex(shellcode_address, MEM_RELEASE);
            }
            else {
                auto result = zero_out_memory(shellcode_address, complete_shellcode_size);
            }
            };

        UniqueHandle snapshot{
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process_id_)
        };

        if (!snapshot.valid()) {
            cleanup_shellcode();
            return false;
        }

        THREADENTRY32 thread_entry{};
        thread_entry.dwSize = sizeof(thread_entry);

        if (!Thread32First(snapshot.get(), &thread_entry)) {
            cleanup_shellcode();
            return false;
        }

        bool success = false;

        do {
            if (thread_entry.th32OwnerProcessID != process_id_) {
                continue;
            }

            success = try_execute_on_thread(
                thread_entry.th32ThreadID,
                shellcode_address,
                shellcode,
                shellcode_size,
                prologue.data(),
                prologue.size(),
                epilogue.data(),
                epilogue.size(),
                complete_shellcode_size
            );

            if (success) {
                break;
            }

        } while (Thread32Next(snapshot.get(), &thread_entry));

        cleanup_shellcode();

        return success;
    }

} // namespace manualmap
