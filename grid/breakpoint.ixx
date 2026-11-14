module;
#include <cstdint>

export module grid.breakpoint;
import grid.signature;

export namespace grid::breakpoint {
bool resolve(std::uintptr_t image);
std::uintptr_t address() noexcept;
}

namespace grid::breakpoint {
namespace {
std::uintptr_t entry{};
}
bool resolve(std::uintptr_t image) {
    // Existing INT3 padding followed by a distinctive function prologue.
    // 70938: match at 0x339DC9, second CC at 0x339DCA (the former hardcoded hop).
    const auto match = signature::find(image,
        "CC CC CC CC CC CC CC 48 83 EC 28 48 8B D1 48 85 C9 75 07 C6 44 24 30 63 EB 2F");
    entry = match ? match + 1 : 0;
    return entry != 0;
}
std::uintptr_t address() noexcept { return entry; }
}
