module;
#include <windows.h>
#include <cstdint>
#include <vector>

export module grid.signature;
export namespace grid::signature {
std::uintptr_t find(std::uintptr_t image, const char* ida);
}

namespace grid::signature {
namespace {
int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
bool readable(std::uintptr_t address, std::size_t size) {
    const auto end = address + size;
    while (address < end) {
        MEMORY_BASIC_INFORMATION page{};
        if (!VirtualQuery(reinterpret_cast<void*>(address), &page, sizeof(page))) return false;
        const auto protection = page.Protect & 0xff;
        if (page.State != MEM_COMMIT || (page.Protect & PAGE_GUARD) ||
            !(protection == PAGE_READONLY || protection == PAGE_READWRITE ||
              protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
              protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY)) return false;
        const auto next = reinterpret_cast<std::uintptr_t>(page.BaseAddress) + page.RegionSize;
        if (next <= address) return false;
        address = next;
    }
    return true;
}
}

// IDA byte patterns with ?/?? wildcards. Missing and ambiguous matches fail closed.
std::uintptr_t find(std::uintptr_t image, const char* ida) {
    if (!image || !ida) return 0;
    std::vector<int> bytes;
    bool anchored = false;
    while (*ida) {
        if (*ida == ' ') { ++ida; continue; }
        if (*ida == '?') {
            ++ida;
            if (*ida == '?') ++ida;
            bytes.push_back(-1);
        } else {
            const int high = hex(*ida++);
            if (!*ida) return 0;
            const int low = hex(*ida++);
            if (high < 0 || low < 0) return 0;
            bytes.push_back(high * 16 + low);
            anchored = true;
        }
        if (*ida && *ida != ' ') return 0;
    }
    if (bytes.empty() || !anchored) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return 0;
    const auto* section = IMAGE_FIRST_SECTION(nt);
    std::uintptr_t result = 0;
    for (unsigned s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
        if (!(section[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        const auto size = section[s].Misc.VirtualSize;
        const auto rva = section[s].VirtualAddress;
        if (rva > nt->OptionalHeader.SizeOfImage || size > nt->OptionalHeader.SizeOfImage - rva) return 0;
        const auto begin = image + rva;
        const auto end = begin + size;
        for (auto cursor = begin; cursor < end;) {
            MEMORY_BASIC_INFORMATION page{};
            if (!VirtualQuery(reinterpret_cast<void*>(cursor), &page, sizeof(page))) return 0;
            const auto page_end = reinterpret_cast<std::uintptr_t>(page.BaseAddress) + page.RegionSize;
            if (page_end <= cursor) return 0;
            const auto limit = (page_end < end) ? page_end : end;
            if (readable(cursor, limit - cursor)) {
                for (auto p = cursor; p < limit && bytes.size() <= end - p; ++p) {
                    const auto* data = reinterpret_cast<const unsigned char*>(p);
                    if (bytes[0] >= 0 && data[0] != bytes[0]) continue;
                    if (bytes.size() > limit - p && !readable(p, bytes.size())) continue;
                    std::size_t i = 0;
                    while (i < bytes.size() && (bytes[i] < 0 || data[i] == bytes[i])) ++i;
                    if (i != bytes.size()) continue;
                    if (result) return 0;
                    result = p;
                }
            }
            cursor = limit;
        }
    }
    return result;
}
}
