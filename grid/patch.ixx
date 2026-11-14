module;
#include <windows.h>
#include <cstdint>

export module grid.patch;
import grid.signature;

export namespace grid::patch {
// One-byte patches resolve uniquely from IDA patterns and remember their original byte.
class byte_patch {
public:
    byte_patch(const char* pattern, std::uint8_t expected, std::uint8_t replacement)
        : pattern_(pattern), expected_(expected), replacement_(replacement) {}
    bool apply(std::uintptr_t image);
    bool restore();
private:
    const char* pattern_;
    std::uint8_t expected_;
    std::uint8_t replacement_;
    std::uintptr_t address_{};
    std::uint8_t original_{};
    bool active_{};
};
bool install();
void stop();
}

namespace grid::patch {
namespace {
bool write(std::uintptr_t address, std::uint8_t expected, std::uint8_t replacement,
           bool& changed) {
    changed = false;
    DWORD original_protection{};
    auto* target = reinterpret_cast<std::uint8_t*>(address);
    if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &original_protection)) return false;
    bool success = *target == expected;
    if (success) {
        *target = replacement;
        changed = true;
        success = FlushInstructionCache(GetCurrentProcess(), target, 1) != FALSE;
        if (!success) {
            *target = expected;
            changed = false;
            FlushInstructionCache(GetCurrentProcess(), target, 1);
        }
    }
    DWORD ignored{};
    const bool restored = VirtualProtect(target, 1, original_protection, &ignored) != FALSE;
    if (!restored) OutputDebugStringA("[grid.patch] failed to restore page protection\n");
    return success && restored;
}

// Wow 1.60.1.70938: sub_1E6B80 starts with 40 53 (push rbx).
// Entry bytes checked in the open IDB; pattern unique in the matching executable.
// The RVA documents verification only and is never used to locate the patch.
byte_patch disable_function{
    "48 83 EC 28 48 8B D1 48 85 C9 75 ? C6 44 24",
    0x48, 0xC3
};
}

bool byte_patch::apply(std::uintptr_t image) {
    if (active_) return *reinterpret_cast<const std::uint8_t*>(address_) == replacement_;
    const auto address = signature::find(image, pattern_);
    if (!address) {
        OutputDebugStringA("[grid.patch] signature missing, ambiguous, or unreadable\n");
        return false;
    }
    bool changed{};
    const bool success = write(address, expected_, replacement_, changed);
    if (changed) {
        address_ = address;
        original_ = expected_;
        active_ = true;
    }
    return success;
}

bool byte_patch::restore() {
    if (!active_) return true;
    bool changed{};
    const bool success = write(address_, replacement_, original_, changed);
    if (changed) { active_ = false; address_ = 0; }
    return success;
}

bool install() {
    const bool success = disable_function.apply(
        reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)));
    OutputDebugStringA(success ? "[grid.patch] sub_1E6B80 patched to C3\n" :
                                 "[grid.patch] sub_1E6B80 patch failed\n");
    return success;
}
void stop() {
    if (!disable_function.restore()) OutputDebugStringA("[grid.patch] failed to restore sub_1E6B80\n");
}
}
