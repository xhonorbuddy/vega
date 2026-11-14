#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
import grid.patch;

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
    const unsigned char code[] = {0x40, 0x53, 0x48, 0x83, 0xec, 0x20};
    std::memcpy(memory + 0x1000, code, sizeof(code));
    DWORD old{};
    check(VirtualProtect(memory + 0x1000, 0x1000, PAGE_EXECUTE_READ, &old) != FALSE, "protect fixture");
    grid::patch::byte_patch patch("40 53 48 83 EC 20", 0x40, 0xC3);
    check(patch.apply(base), "apply patch");
    check(memory[0x1000] == 0xc3 && memory[0x1001] == 0x53, "only first byte changed");
    MEMORY_BASIC_INFORMATION page{};
    VirtualQuery(memory + 0x1000, &page, sizeof(page));
    check(page.Protect == PAGE_EXECUTE_READ, "protection restored");
    check(patch.apply(base), "idempotent apply");
    check(patch.restore() && memory[0x1000] == 0x40, "original restored");
    check(patch.restore(), "idempotent restore");
    grid::patch::byte_patch wrong("40 53 48 83 EC 20", 0x48, 0xc3);
    check(!wrong.apply(base) && memory[0x1000] == 0x40, "expected byte mismatch rejected");
    std::memcpy(memory + 0x2000, code, sizeof(code));
    check(!patch.apply(base) && memory[0x1000] == 0x40 && memory[0x2000] == 0x40, "ambiguous pattern rejected");
    grid::patch::byte_patch missing("FE ED FA CE", 0xfe, 0xc3);
    check(!missing.apply(base), "missing pattern rejected");
    VirtualFree(memory, 0, MEM_RELEASE);
    std::puts("Pattern patch tests passed");
}
