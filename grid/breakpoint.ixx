module;
#include <windows.h>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

export module grid.breakpoint;
import grid.signature;

export namespace grid::breakpoint {
inline constexpr std::size_t capacity = 100;
inline constexpr std::size_t minimum = 20;
// Initialize and bind on the game thread. Once published, mappings stay stable.
bool resolve(std::uintptr_t image);
std::uintptr_t bind(std::uintptr_t callback) noexcept;
std::uintptr_t target(std::uintptr_t trap) noexcept;
std::size_t available() noexcept;
std::size_t size() noexcept;
bool contains(std::uintptr_t callback) noexcept;
}

namespace grid::breakpoint {
namespace {
struct slot {
    std::uintptr_t trap{};
    std::atomic<std::uintptr_t> callback{};
};
static_assert(std::atomic<std::uintptr_t>::is_always_lock_free);
std::array<slot, capacity> slots{};
std::atomic<std::size_t> published{};
std::uintptr_t source{};
}
bool resolve(std::uintptr_t image) {
    if (published.load(std::memory_order_acquire)) return source == image;
    const auto matches = signature::find_all(image, "C3 CC CC CC CC 48", capacity);
    std::size_t count = 0;
    for (const auto match : matches) {
        MEMORY_BASIC_INFORMATION page{};
        if (!VirtualQuery(reinterpret_cast<void*>(match + 1), &page, sizeof(page))) continue;
        const DWORD protection = page.Protect & 0xff;
        if ((page.Protect & PAGE_GUARD) ||
            !(protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE ||
              protection == PAGE_EXECUTE_WRITECOPY)) continue;
        slots[count++].trap = match + 1; // First existing INT3 after RET.
    }
    if (count < minimum) return false;
    source = image;
    published.store(count, std::memory_order_release);
    char message[96]{};
    wsprintfA(message, "[grid] cached %u executable INT3 slots\n", static_cast<unsigned>(count));
    OutputDebugStringA(message);
    return true;
}
std::size_t size() noexcept { return published.load(std::memory_order_acquire); }
bool contains(std::uintptr_t callback) noexcept {
    if (!callback) return false;
    const auto count = size();
    for (std::size_t i = 0; i < count; ++i)
        if (slots[i].callback.load(std::memory_order_acquire) == callback) return true;
    return false;
}
std::size_t available() noexcept {
    std::size_t free = 0;
    const auto count = size();
    for (std::size_t i = 0; i < count; ++i)
        if (!slots[i].callback.load(std::memory_order_acquire)) ++free;
    return free;
}
std::uintptr_t bind(std::uintptr_t callback) noexcept {
    if (!callback) return 0;
    const auto count = size();
    for (std::size_t i = 0; i < count; ++i)
        if (slots[i].callback.load(std::memory_order_acquire) == callback) return slots[i].trap;
    for (std::size_t i = 0; i < count; ++i) {
        if (slots[i].callback.load(std::memory_order_relaxed)) continue;
        slots[i].callback.store(callback, std::memory_order_release);
        return slots[i].trap;
    }
    return 0;
}
std::uintptr_t target(std::uintptr_t trap) noexcept {
    const auto count = size();
    for (std::size_t i = 0; i < count; ++i)
        if (slots[i].trap == trap) return slots[i].callback.load(std::memory_order_acquire);
    return 0;
}
}
