#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
import grid.signature;

void check(bool pass, const char* label) {
    if (!pass) { std::fprintf(stderr, "FAIL: %s\n", label); std::exit(1); }
}
int main() {
    auto* memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, 0x5000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    check(memory != nullptr, "allocation");
    const auto base = reinterpret_cast<std::uintptr_t>(memory);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(memory);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x100;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(memory + 0x100);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.SizeOfImage = 0x5000;
    auto* section = IMAGE_FIRST_SECTION(nt);
    section->Characteristics = IMAGE_SCN_MEM_EXECUTE;
    section->VirtualAddress = 0x1000;
    section->Misc.VirtualSize = 0x4000;
    const unsigned char code[] = {0x48, 0x8b, 0x0d, 0x01, 0x23, 0x45, 0x67, 0xc3};
    std::memcpy(memory + 0x1ffc, code, sizeof(code));
    DWORD old{};
    VirtualProtect(memory + 0x1000, 0x1000, PAGE_EXECUTE_READ, &old);
    check(grid::signature::find(base, "48 8B 0D ?? ?? ?? ?? C3") == base + 0x1ffc, "match crossing protection regions");
    std::memcpy(memory + 0x3000, code, sizeof(code));
    check(grid::signature::find(base, "48 8B 0D ? ? ? ? C3") == 0, "reject ambiguity");
    VirtualProtect(memory + 0x3000, 0x1000, PAGE_NOACCESS, &old);
    check(grid::signature::find(base, "48 8B 0D ?? ?? ?? ?? C3") == base + 0x1ffc, "skip inaccessible pages");
    VirtualProtect(memory + 0x2000, 0x1000, PAGE_NOACCESS, &old);
    check(grid::signature::find(base, "48 8B 0D ?? ?? ?? ?? C3") == 0, "reject crossing inaccessible page");
    const char* invalid_patterns[] = {"", "?? ??", "4", "GG", "48ZZ", "48 ?A"};
    for (const auto* invalid : invalid_patterns)
        check(grid::signature::find(base, invalid) == 0, "reject malformed pattern");
    check(grid::signature::find(base, "FE ED FA CE") == 0, "missing pattern");
    VirtualFree(memory, 0, MEM_RELEASE);
    std::puts("Signature scanner tests passed");
}
