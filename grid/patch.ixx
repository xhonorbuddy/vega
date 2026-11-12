// Client patching, exposed as a module so DllMain and any future feature can
// apply patches against the host process image (the game client).

module;

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>

export module grid.patch;

export namespace grid::patch {

    // x64 `ret`.
    inline constexpr std::uint8_t kRetByte = 0xC3;

    // Function in the client image that this build wants to disable.
    inline constexpr std::uintptr_t kDisabledFunctionOffset = 0x1E6B40;

    // sub_338AD0 checks that a Lua C function pointer lives inside the client's
    // own module range. A manually mapped DLL is outside that range, so the
    // check falls into a deliberate `movzx eax,[0]` and kills the process.
    // 0x338B5D holds `jne +6` (0x75); making it `jmp +6` (0xEB) skips only that
    // fatal branch and returns the same value an in-range address would.
    inline constexpr std::uintptr_t kCFunctionRangeCheckOffset = 0x338B5D;
    inline constexpr std::uint8_t kJneOpcode = 0x75;
    inline constexpr std::uint8_t kJmpOpcode = 0xEB;

    struct PatchEntry {
        std::uintptr_t offset;
        std::uint8_t value;
        // Byte the client must currently have at that offset, or 0 to accept any
        // value. Set this from the disassembly to make a patch fail closed after
        // a client update instead of writing into an unrelated function.
        std::uint8_t expected;
    };

    inline constexpr PatchEntry kClientPatches[]{
        { kDisabledFunctionOffset, kRetByte, 0x00 },
        { kCFunctionRangeCheckOffset, kJmpOpcode, kJneOpcode },
    };

    // Base address of the host executable (the client), not of this DLL.
    [[nodiscard]] inline std::uintptr_t client_base() noexcept {
        return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    }

    [[nodiscard]] inline std::size_t client_image_size(std::uintptr_t base) noexcept {
        if (base == 0) {
            return 0;
        }

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            base + static_cast<std::uintptr_t>(dos->e_lfanew)
            );

        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        return nt->OptionalHeader.SizeOfImage;
    }

    // Writes one byte into executable memory: makes the page writable, stores,
    // flushes the instruction cache and restores the previous protection.
    [[nodiscard]] inline bool write_byte(
        std::uintptr_t address,
        std::uint8_t value
    ) noexcept {
        MEMORY_BASIC_INFORMATION info{};

        if (VirtualQuery(
            reinterpret_cast<LPCVOID>(address),
            &info,
            sizeof(info)
        ) == 0 || info.State != MEM_COMMIT) {
            return false;
        }

        DWORD old_protection = 0;

        if (!VirtualProtect(
            reinterpret_cast<LPVOID>(address),
            1,
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )) {
            return false;
        }

        *reinterpret_cast<std::uint8_t*>(address) = value;
        FlushInstructionCache(
            GetCurrentProcess(),
            reinterpret_cast<LPCVOID>(address),
            1
        );

        DWORD ignored = 0;
        static_cast<void>(VirtualProtect(
            reinterpret_cast<LPVOID>(address),
            1,
            old_protection,
            &ignored
        ));

        return true;
    }

    inline void save_original(std::size_t index, std::uint8_t value) noexcept;

    // Applies one entry. Returns true when the byte already had the wanted
    // value (idempotent) or was written successfully.
    [[nodiscard]] inline bool apply(const PatchEntry& entry) noexcept {
        const std::uintptr_t base = client_base();

        if (base == 0) {
            OutputDebugStringA("[grid.patch] client base is null\n");
            return false;
        }

        const std::size_t image_size = client_image_size(base);

        if (image_size == 0) {
            OutputDebugStringA("[grid.patch] cannot read the client PE headers\n");
            return false;
        }

        if (entry.offset >= image_size) {
            OutputDebugStringA("[grid.patch] patch offset is outside the client image\n");
            return false;
        }

        const std::uintptr_t address = base + entry.offset;

        std::uint8_t current = 0;
        std::memcpy(&current, reinterpret_cast<const void*>(address), 1);

        if (current == entry.value) {
            return true;
        }

        if (entry.expected != 0 && current != entry.expected) {
            OutputDebugStringA(
                "[grid.patch] unexpected byte at the patch offset; client build changed?\n"
            );
            return false;
        }

        std::size_t patch_index = 0;
        for (const PatchEntry& candidate : kClientPatches) {
            if (&candidate == &entry) {
                break;
            }
            ++patch_index;
        }

        save_original(patch_index, current);

        if (!write_byte(address, entry.value)) {
            OutputDebugStringA("[grid.patch] write failed\n");
            return false;
        }

        return true;
    }

    // Original bytes, persisted outside the module so a reload can still restore
    // them after the first copy is unloaded. The client .text is encrypted on
    // disk, so the only source of truth is the byte read before the first write.
    struct OriginalBytes {
        std::uint32_t magic;
        std::uint8_t bytes[sizeof(kClientPatches)];
    };

    inline constexpr std::uint32_t kOriginalMagic = 0x47524450u; // 'GRDP'

    inline void original_path(wchar_t* buffer, std::size_t count) noexcept {
        wchar_t temp[MAX_PATH]{};

        if (GetTempPathW(MAX_PATH, temp) == 0) {
            buffer[0] = L'\0';
            return;
        }

        swprintf_s(buffer, count, L"%sgrid_originals.bin", temp);
    }

    [[nodiscard]] inline bool load_originals(OriginalBytes& out) noexcept {
        wchar_t path[MAX_PATH]{};
        original_path(path, MAX_PATH);

        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (file == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD read = 0;
        const BOOL ok = ReadFile(file, &out, sizeof(out), &read, nullptr);
        CloseHandle(file);

        return ok != FALSE && read == sizeof(out) && out.magic == kOriginalMagic;
    }

    inline void save_original(std::size_t index, std::uint8_t value) noexcept {
        OriginalBytes data{ kOriginalMagic, {} };

        load_originals(data);
        data.magic = kOriginalMagic;

        if (index < sizeof(data.bytes)) {
            data.bytes[index] = value;
        }

        wchar_t path[MAX_PATH]{};
        original_path(path, MAX_PATH);

        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);

        if (file == INVALID_HANDLE_VALUE) {
            return;
        }

        DWORD written = 0;
        static_cast<void>(WriteFile(file, &data, sizeof(data), &written, nullptr));
        CloseHandle(file);
    }

    // Restores every recorded original byte (used before the image is freed).
    [[nodiscard]] inline std::size_t restore_client_patches() noexcept {
        OriginalBytes data{};

        if (!load_originals(data)) {
            return 0;
        }

        const std::uintptr_t base = client_base();

        if (base == 0) {
            return 0;
        }

        std::size_t restored = 0;
        std::size_t index = 0;

        for (const PatchEntry& entry : kClientPatches) {
            if (index < sizeof(data.bytes)) {
                const std::uintptr_t address = base + entry.offset;

                if (write_byte(address, data.bytes[index])) {
                    ++restored;
                }
            }

            ++index;
        }

        return restored;
    }
    // Bit i selects kClientPatches[i]. Defaults to everything.
    inline constexpr std::uint32_t kPatchDisableFunction = 1u << 0;
    inline constexpr std::uint32_t kPatchRangeCheck = 1u << 1;
    inline constexpr std::uint32_t kPatchAll =
        kPatchDisableFunction | kPatchRangeCheck;

    // Applies the selected patches; returns how many are in place.
    [[nodiscard]] inline std::size_t install_client_patches(
        std::uint32_t mask = kPatchAll
    ) noexcept {
        std::size_t applied = 0;
        std::uint32_t index = 0;

        for (const PatchEntry& entry : kClientPatches) {
            if ((mask & (1u << index)) != 0 && apply(entry)) {
                ++applied;
            }

            ++index;
        }

        return applied;
    }

} // namespace grid::patch
