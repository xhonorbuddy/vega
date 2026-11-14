module;
#include <windows.h>
#include <array>
#include <cstdint>
#include <cstring>

export module grid.entity_client;
import grid.signature;
import grid.entity_index;

export namespace grid::entity_client {
struct bindings {
    std::array<std::uintptr_t,15> vtables{};
    std::uintptr_t enumerate{}, lookup{}, position{}, facing{}, power{}, death{};
    std::uintptr_t flags{}, counter{}, layer{}, manager{}, visible{};
};
bool initialize();
bool supported() noexcept;
const bindings& get() noexcept;
bool accept_vtable(unsigned type, std::uintptr_t table, std::uintptr_t object) noexcept;
std::uintptr_t object_for_guid(const void* id) noexcept;
#ifdef GRID_ENTITY_TESTING
void configure_for_tests(const bindings& value) noexcept;
#endif
}
namespace grid::entity_client {
namespace {
bindings addresses{};
bool ready{};
std::uintptr_t rip(std::uintptr_t instruction, unsigned offset, unsigned length) {
    if (!instruction) return 0;
    std::int32_t displacement{};
    std::memcpy(&displacement,reinterpret_cast<void*>(instruction+offset),4);
    return instruction+length+displacement;
}
}
const bindings& get() noexcept { return addresses; }
std::uintptr_t object_for_guid(const void* id) noexcept {
    return ready ? entity_index::find(addresses.visible,id) : 0;
}

bool accept_vtable(unsigned type,std::uintptr_t table,std::uintptr_t object) noexcept {
    if (type>=15 || !table) return false;
    if (addresses.vtables[type]) return table==addresses.vtables[type];
    if (!ready) return false;
    __try {
        if (*reinterpret_cast<const unsigned char*>(object+0x24)!=type ||
            *reinterpret_cast<const unsigned char*>(object+0x25)!=type) return false;
        if (object_for_guid(reinterpret_cast<const void*>(object+0x10))!=object) return false;
        addresses.vtables[type]=table;
        return true;
    } __except(GetExceptionCode()==EXCEPTION_ACCESS_VIOLATION || GetExceptionCode()==EXCEPTION_IN_PAGE_ERROR
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return false; }
}

bool supported() noexcept { return ready; }
#ifdef GRID_ENTITY_TESTING
void configure_for_tests(const bindings& value) noexcept { addresses=value; ready=value.vtables[0]!=0; }
#endif
bool initialize() {
    if (ready) return true;
    const auto image=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (!image || dos->e_magic!=IMAGE_DOS_SIGNATURE) return false;
    const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(image+dos->e_lfanew);
    if (nt->Signature!=IMAGE_NT_SIGNATURE || nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 ||
        nt->FileHeader.TimeDateStamp!=0x6AF601DA || nt->OptionalHeader.SizeOfImage<0x7000000) return false;
    bindings result{};
    result.enumerate = signature::find(image,"48 89 5C 24 08 48 89 74 24 18 48 89 7C 24 20 48 89 54 24 10 55 41 54 41 55 41 56 41 57 48 8D 6C 24 80 48 81 EC 80 01 00 00"); // Verified 70938 RVA 0x1a10210
    if (!result.enumerate) return false;
    result.lookup = signature::find(image,"48 89 5C 24 08 48 89 74 24 10 44 89 4C 24 20 57 48 83 EC 20 4C 8B 0D ?? ?? ?? ??"); // Verified 70938 RVA 0x1a11c90
    result.position = signature::find(image,"40 53 48 83 EC 40 45 33 C9 48 8D 41 08 48 85 C9 48 8B DA 49 0F 44 C1 4C 8B 00 49 83 E0 FE 74 ?? 4D 8B 50 08 41 8B 4A 30"); // Verified 70938 RVA 0x1f61d0
    if (!result.position) return false;
    result.facing = signature::find(image,"48 83 EC 48 45 33 C9 48 8D 41 08 48 85 C9 49 0F 44 C1 4C 8B 00 49 83 E0 FE 74 77 4D 8B 50 08 41 8B 4A 30 85 C9 79 2E 83 F9 FF 75 05 41 8B C1 EB 28 41 8B 40 10 0F BA F1 1F 48 8D 14 40 49 8B 82 48 04 00 00 48 03 D2 48 03 C9 48 8B 44 D0 18 48 8B 04 C8 EB 04 49 8D 04 08 48 85 C0 74 34 48 89 44 24 28 48 8B 05 26 9E B3 06 4C 89 44 24 20 C6 44 24 30 01 48 85 C0 74 04 4C 8B 48 10 41 B0 01 48 8D 54 24 20 49 8B C9 E8 23 69 78 03 48 83 C4 48 C3 0F 57 C0 48 83 C4 48 C3 CC CC CC CC CC CC"); // Verified 70938 RVA 0x20eef0
    if (!result.facing) return false;
    result.power = signature::find(image,"0F B6 41 24 4C 8D 05 ?? ?? ?? ?? 41 F6 84 80 80 5E DF 03 40 74 ?? 0F BE 81 1D 1E 00 00"); // Verified 70938 RVA 0x20c3050
    if (!result.power) return false;
    result.death = signature::find(image,"48 89 5C 24 08 57 48 83 EC 20 48 8D 79 10 E8 ?? ?? ?? ?? 48 8B 0F 48 39 08"); // Verified 70938 RVA 0x1fad740
    if (!result.death) return false;
    result.vtables[0] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 77 30 48 8D 8F A0 00 00 00 48 89 77 38 BA F0 04 00 00"), 3, 7); // Verified 70938 RVA 0x420c778
    result.vtables[1] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 4C 89 59 30 4C 8B D1 4C 89 59 38 4C 89 59 40 48 89 01"), 3, 7); // Verified 70938 RVA 0x4208768
    result.vtables[2] = rip(signature::find(image,"4C 8D 0D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 89 0F 48 8D 9F 88 04 00 00"), 3, 7); // Verified 70938 RVA 0x4208f08
    result.vtables[3] = rip(signature::find(image,"4C 8D 0D ?? ?? ?? ?? 48 89 47 28 48 8D 05 ?? ?? ?? ?? 48 89 87 A0 00 00 00"), 3, 7); // Verified 70938 RVA 0x4208c30
    result.vtables[4] = rip(signature::find(image,"4C 8D 0D ?? ?? ?? ?? 4C 89 0F 48 8D 05 ?? ?? ?? ?? 48 89 87 A0 00 00 00"), 3, 7); // Verified 70938 RVA 0x42089c8
    result.vtables[5] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 49 89 06 48 8D 05 ?? ?? ?? ?? 49 C7 86 C0 00 00 00 01 00 00 00"), 3, 7); // Verified 70938 RVA 0x420c0d8
    result.vtables[6] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? B9 13 00 00 00 49 89 06 33 ED 48 8D 05 ?? ?? ?? ??"), 3, 7); // Verified 70938 RVA 0x41fa328
    result.vtables[7] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 9F 90 67 00 00 48 8D 05 ?? ?? ?? ??"), 3, 7); // Verified 70938 RVA 0x41f8070
    result.vtables[8] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 8F 50 01 00 00 48 89 B7 F0 00 00 00"), 3, 7); // Verified 70938 RVA 0x41fff48
    result.vtables[9] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 07 0F 57 C0 48 8D 05 ?? ?? ?? ?? 48 89 47 28 48 89 B7 DC 00 00 00 48 89 B7 E4 00 00 00 48 89 B7 30 01 00 00"), 3, 7); // Verified 70938 RVA 0x4209680
    result.vtables[10] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 07 0F 57 C0 48 8D 05 ?? ?? ?? ?? 48 89 47 28 48 8D 87 78 01 00 00 48 89 B7 E0 00 00 00 48 C7 87 E8 00 00 00 00 00 80 3F"), 3, 7); // Verified 70938 RVA 0x42093c0
    result.vtables[11] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 07 48 8D 8F A0 01 00 00 48 89 B7 E8 00 00 00"), 3, 7); // Verified 70938 RVA 0x420cd68
    result.vtables[12] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 07 0F 57 C0 48 89 B7 D8 00 00 00 48 8D 05 ?? ?? ?? ??"), 3, 7); // Verified 70938 RVA 0x420d008
    result.vtables[13] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 77 30 49 81 C0 F8 07 00 00 48 89 77 38 48 B9 01 00 00 00 00 00 00 80"), 3, 7); // Verified 70938 RVA 0x41f9d20
    result.vtables[14] = rip(signature::find(image,"48 8D 05 ?? ?? ?? ?? 48 89 77 30 48 89 77 38 48 89 77 40 48 89 07 48 8D 05 ?? ?? ?? ??"), 3, 7); // Verified 70938 RVA 0x420ec60
    result.flags = rip(signature::find(image,"0F B6 05 ?? ?? ?? ?? 48 8B D9 C0 E8 04 24 01 C6 45 C0 00 88 45 20 C7 45 C4 FF FF FF FF"), 3, 7); // Verified 70938 RVA 0x4dea0e8
    if (!result.flags) result.flags=rip(signature::find(image,"0F B7 05 ?? ?? ?? ?? 0F BA E0 09 72 ?? 0F B6 05 ?? ?? ?? ?? 84 C0 74 ?? 0F B6 0D ?? ?? ?? ?? 84 C9 75 ?? 38 0D ?? ?? ?? ?? 75 ?? 84 C0 74 ?? 84 C9 75 ?? 38 0D ?? ?? ?? ?? EB ?? A9 00 01 00 00 75 ?? 48 8B 53 30 48 8B CB E8 ?? ?? ?? ?? 48 8B CB 48 83 C4 20 5B E9 ?? ?? ?? ?? CC CC 48 89 5C 24 08"), 3, 7);
    if (!result.flags) result.flags=rip(signature::find(image,"0F B7 05 ?? ?? ?? ?? 0F BA E0 09 72 ?? 0F B6 05 ?? ?? ?? ?? 84 C0 74 ?? 0F B6 0D ?? ?? ?? ?? 84 C9 75 ?? 38 0D ?? ?? ?? ?? 75 ?? 84 C0 74 ?? 84 C9 75 ?? 38 0D ?? ?? ?? ?? EB ?? A9 00 01 00 00 75 ?? 48 8B 97 90 00 00 00 48 8B CF E8 ?? ?? ?? ?? 48 8D 9F A0 00 00 00 48 8B 03 48 3B C3 74 ??"), 3, 7);
    if (!result.flags) result.flags=rip(signature::find(image,"0F B7 05 ?? ?? ?? ?? 0F BA E0 09 73 ?? A9 00 01 00 00 EB ?? 0F B6 05 ?? ?? ?? ??"), 3, 7);
    if (!result.flags) result.flags=rip(signature::find(image,"0F B7 05 ?? ?? ?? ?? 0F BA E0 09 73 ?? B1 02 66 C7 44 24 30 02 01 EB ?? 80 3D ?? ?? ?? ?? 00 74 ?? 80 3D ?? ?? ?? ?? 00"), 3, 7);
    if (!result.flags) result.flags=rip(signature::find(image,"0F B7 05 ?? ?? ?? ?? B9 05 00 00 00 66 0F AB C8 8B 0D ?? ?? ?? ?? 83 C9 40"), 3, 7);
    if (!result.flags) return false;
    result.counter = rip(signature::find(image,"48 8B 0D ?? ?? ?? ?? B2 01 41 0F B6 D8 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ??"), 3, 7); // Verified 70938 RVA 0x6af8b40
    if (!result.counter) return false;
    result.layer = rip(signature::find(image,"48 89 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 3D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? FF FF FF FF"), 3, 7); // Verified 70938 RVA 0x6af8ba8
    if (!result.layer) return false;
    result.manager = rip(signature::find(image,"48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 33 C9 48 89 4C 24 38 48 89 4C 24 40"), 3, 7); // Verified 70938 RVA 0x6d48cf8
    if (!result.manager) return false;
    result.visible = rip(signature::find(image,"48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 8B 5C 24 58 48 8B 6C 24 60"), 3, 7); // Verified 70938 RVA 0x6d48d78
    if (!result.visible) return false;
    addresses=result;
    ready=true;
    return true;
}
}
