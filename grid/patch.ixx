// Client patching, exposed as a module so DllMain and any future feature can
// apply patches against the host process image (the game client).

module;

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

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

        if (!write_byte(address, entry.value)) {
            OutputDebugStringA("[grid.patch] write failed\n");
            return false;
        }

        return true;
    }

    // Applies every patch in the table; returns how many are in place.
    [[nodiscard]] inline std::size_t install_client_patches() noexcept {
        std::size_t applied = 0;

        for (const PatchEntry& entry : kClientPatches) {
            if (apply(entry)) {
                ++applied;
            }
        }

        return applied;
    }

} // namespace grid::patch
