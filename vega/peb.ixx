module;

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <winternl.h>
#include <cstddef>
#include <cstdint>

export module manualmap.peb;

export namespace manualmap::ntapi {

    // Minimal PEB layout used by this project.
    //
    // This intentionally avoids carrying a full reverse-engineered PEB definition.
    // The mapper currently needs only:
    //   - ImageBaseAddress
    //   - ApiSetMap
    //
    // These offsets are for x64 Windows. If you build x86, use a separate 32-bit
    // layout instead of relying on this structure.
    struct PEB64 {
        std::byte reserved_0000[0x10];
        PVOID ImageBaseAddress;       // 0x10

        std::byte reserved_0018[0x50];
        PVOID ApiSetMap;              // 0x68
    };

#ifdef _WIN64
    using PEB = PEB64;

    static_assert(offsetof(PEB, ImageBaseAddress) == 0x10);
    static_assert(offsetof(PEB, ApiSetMap) == 0x68);
#else
#error "manualmap::ntapi::PEB currently defines only the x64 PEB layout."
#endif

} // namespace manualmap::ntapi
