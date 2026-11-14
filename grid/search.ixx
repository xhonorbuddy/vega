// IDA-style signature scanning for the client image.
//
// Patterns use IDA syntax: whitespace-separated bytes, "?" (or "??") for a
// wildcard byte, and nibble wildcards such as "4?" or "?5".
//
// Scanning strategy (fastest practical without SIMD intrinsics):
//   * compile every pattern to bytes + mask once,
//   * pick the longest run of fully concrete bytes as the anchor,
//   * locate candidates with memchr (SIMD-accelerated in the CRT),
//   * verify the anchor run with memcmp, then the remaining bytes with a masked
//     compare. Random data almost never reaches the masked compare.
//
// Every resolved address is cached, so repeated lookups are a hash-map hit.
// Signatures that do not match are collected and reported once, by name.

module;

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

export module grid.search;

export namespace grid::search {

enum class Kind : std::uint8_t {
    Address,    // the matched location itself
    RipTarget,  // [rip+disp32] at disp_offset -> absolute target address
    Pointer,    // RipTarget, then read a pointer at that target (one deref)
    Deref,      // the matched address itself holds a pointer (data slots)
};

struct Signature {
    const char* name;
    const char* pattern;
    Kind kind = Kind::Address;
    int disp_offset = 0; // offset of the disp32 inside the match (rip kinds)
};

using report_fn = void (*)(const char* text);

struct Range {
    std::uintptr_t start = 0;
    std::size_t size = 0;
};

void set_reporter(report_fn fn) noexcept;

// Scans the executable sections of the image at module_base for every
// signature. Results are cached; unmatched names are reported.
void resolve_all_data(std::uintptr_t module_base, std::size_t module_size,
                       const Signature* signatures, std::size_t count) noexcept;

void resolve_all(std::uintptr_t module_base, std::size_t module_size,
                 const Signature* signatures, std::size_t count) noexcept;

// Scans an explicit range instead of the PE executable sections.
void resolve_all_in_ranges(const Range* ranges, std::size_t range_count,
                           const Signature* signatures, std::size_t count) noexcept;

// Cached lookups. Return 0 when unknown or when the signature did not match.
[[nodiscard]] std::uintptr_t get(const char* name) noexcept;
[[nodiscard]] bool has(const char* name) noexcept;

// Names that failed to resolve in the last resolve_all call.
[[nodiscard]] std::vector<std::string> unresolved();

// Convenience: executable section ranges of the image at base.
[[nodiscard]] std::vector<Range> executable_ranges(std::uintptr_t base) noexcept;
[[nodiscard]] std::vector<Range> data_ranges(std::uintptr_t base) noexcept;

} // namespace grid::search

namespace grid::search::detail {

struct compiled {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> mask;
    std::size_t anchor_offset = 0;
    std::size_t anchor_length = 0;
    bool valid = false;
};

inline int hex_digit(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline compiled compile(const char* pattern) noexcept {
    compiled out;
    const char* p = pattern;

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '\0') break;

        const char* token = p;
        while (*p != '\0' && *p != ' ' && *p != '\t') ++p;
        const std::size_t length = static_cast<std::size_t>(p - token);

        if (length == 1 && token[0] == '?') {
            out.bytes.push_back(0);
            out.mask.push_back(0x00);
            continue;
        }

        if (length == 2 && token[0] == '?' && token[1] == '?') {
            out.bytes.push_back(0);
            out.mask.push_back(0x00);
            continue;
        }

        if (length != 2) {
            out.valid = false;
            return out;
        }

        std::uint8_t byte = 0;
        std::uint8_t mask = 0;

        const int hi = hex_digit(token[0]);
        const int lo = hex_digit(token[1]);

        if (token[0] == '?') {
            byte |= 0x00;
            mask |= 0x0F;
        }
        else if (hi >= 0) {
            byte |= static_cast<std::uint8_t>(hi << 4);
            mask |= 0xF0;
        }
        else {
            out.valid = false;
            return out;
        }

        if (token[1] == '?') {
            byte |= 0x00;
            mask |= 0xF0;
        }
        else if (lo >= 0) {
            byte |= static_cast<std::uint8_t>(lo);
            mask |= 0x0F;
        }
        else {
            out.valid = false;
            return out;
        }

        out.bytes.push_back(byte);
        out.mask.push_back(mask);
    }

    // Longest fully-concrete run becomes the memchr anchor.
    std::size_t best_start = 0;
    std::size_t best_len = 0;
    std::size_t run_start = 0;
    std::size_t run_len = 0;

    for (std::size_t i = 0; i < out.mask.size(); ++i) {
        if (out.mask[i] == 0xFF) {
            if (run_len == 0) run_start = i;
            ++run_len;

            if (run_len > best_len) {
                best_len = run_len;
                best_start = run_start;
            }
        }
        else {
            run_len = 0;
        }
    }

    out.anchor_offset = best_start;
    out.anchor_length = best_len;
    out.valid = !out.bytes.empty() && best_len != 0;
    return out;
}

inline bool masked_equal(const std::uint8_t* data, const compiled& c) noexcept {
    for (std::size_t i = 0; i < c.bytes.size(); ++i) {
        if (static_cast<std::uint8_t>(data[i] & c.mask[i]) !=
            static_cast<std::uint8_t>(c.bytes[i] & c.mask[i])) {
            return false;
        }
    }

    return true;
}

inline std::uintptr_t scan_range(const Range& range, const compiled& c) noexcept {
    if (!c.valid || range.size < c.bytes.size()) {
        return 0;
    }

    const auto* base = reinterpret_cast<const std::uint8_t*>(range.start);
    const std::uint8_t anchor = c.bytes[c.anchor_offset];
    const std::size_t last = range.size - c.bytes.size();

    std::size_t offset = 0;

    while (offset <= last) {
        const auto* haystack = base + offset + c.anchor_offset;
        const std::size_t haystack_len = range.size - offset - c.anchor_offset;

        const void* hit = std::memchr(haystack, anchor, haystack_len);

        if (hit == nullptr) {
            return 0;
        }

        const std::size_t candidate = static_cast<std::size_t>(
            static_cast<const std::uint8_t*>(hit) - base) - c.anchor_offset;

        if (candidate > last) {
            return 0;
        }

        const std::uint8_t* data = base + candidate;

        if (c.anchor_length == 0 ||
            std::memcmp(data + c.anchor_offset,
                        c.bytes.data() + c.anchor_offset,
                        c.anchor_length) == 0) {
            if (masked_equal(data, c)) {
                return range.start + candidate;
            }
        }

        offset = candidate + 1;
    }

    return 0;
}

inline void report(const char* text) noexcept {
    static report_fn reporter = nullptr;

    if (reporter != nullptr) {
        reporter(text);
    }
    else {
        OutputDebugStringA(text);
        OutputDebugStringA("\n");
    }
}

} // namespace grid::search::detail

namespace grid::search {

namespace {

SRWLOCK g_lock = SRWLOCK_INIT;
std::unordered_map<std::string, std::uintptr_t> g_cache;
std::vector<std::string> g_unresolved;
report_fn g_reporter = nullptr;

void lock_exclusive() noexcept { AcquireSRWLockExclusive(&g_lock); }
void unlock_exclusive() noexcept { ReleaseSRWLockExclusive(&g_lock); }
void lock_shared() noexcept { AcquireSRWLockShared(&g_lock); }
void unlock_shared() noexcept { ReleaseSRWLockShared(&g_lock); }

void cache_store(const char* name, std::uintptr_t value) noexcept {
    g_cache[std::string(name)] = value;
}

std::uintptr_t cache_load(const char* name) noexcept {
    const auto it = g_cache.find(std::string(name));
    return it == g_cache.end() ? 0 : it->second;
}

} // namespace

void set_reporter(report_fn fn) noexcept {
    g_reporter = fn;
}

std::vector<Range> executable_ranges(std::uintptr_t base) noexcept {
    std::vector<Range> ranges;

    if (base == 0) {
        return ranges;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return ranges;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        base + static_cast<std::uintptr_t>(dos->e_lfanew));

    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return ranges;
    }

    const auto* section = IMAGE_FIRST_SECTION(nt);

    for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }

        const std::size_t size = section->Misc.VirtualSize != 0
            ? section->Misc.VirtualSize
            : section->SizeOfRawData;

        if (size != 0) {
            ranges.push_back({ base + section->VirtualAddress, size });
        }
    }

    return ranges;
}

std::vector<Range> data_ranges(std::uintptr_t base) noexcept {
    std::vector<Range> ranges;

    if (base == 0) {
        return ranges;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return ranges;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + static_cast<std::uintptr_t>(dos->e_lfanew));

    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return ranges;
    }

    const auto* section = IMAGE_FIRST_SECTION(nt);

    for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
            (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == 0) {
            continue;
        }

        const std::size_t size = section->Misc.VirtualSize != 0
            ? section->Misc.VirtualSize
            : section->SizeOfRawData;

        if (size != 0) {
            ranges.push_back({ base + section->VirtualAddress, size });
        }
    }

    return ranges;
}

void resolve_all_in_ranges(const Range* ranges, std::size_t range_count,
                           const Signature* signatures, std::size_t count) noexcept {
    if (ranges == nullptr || signatures == nullptr) {
        return;
    }

    lock_exclusive();
    g_unresolved.clear();

    if (g_reporter == nullptr) {
        g_reporter = nullptr; // the detail::report fallback handles it
    }

    for (std::size_t i = 0; i < count; ++i) {
        const Signature& signature = signatures[i];

        if (signature.name == nullptr || signature.pattern == nullptr) {
            continue;
        }

        detail::compiled compiled = detail::compile(signature.pattern);
        std::uintptr_t found = 0;

        if (compiled.valid) {
            for (std::size_t r = 0; r < range_count && found == 0; ++r) {
                /* Client code pages may be PAGE_NOACCESS (decrypted on demand),
                   so make the range readable for the scan and restore after. */
                DWORD old_protect = 0;
                const bool made_readable = VirtualProtect(
                    reinterpret_cast<void*>(ranges[r].start),
                    ranges[r].size,
                    PAGE_READONLY,
                    &old_protect
                ) != FALSE;

                if (made_readable) {
                    found = detail::scan_range(ranges[r], compiled);

                    DWORD ignored = 0;
                    static_cast<void>(VirtualProtect(
                        reinterpret_cast<void*>(ranges[r].start),
                        ranges[r].size,
                        old_protect,
                        &ignored
                    ));
                }
                else {
                    found = detail::scan_range(ranges[r], compiled);
                }
            }
        }

        if (found != 0 && signature.kind == Kind::Deref) {
            std::uintptr_t pointer = 0;
            std::memcpy(&pointer, reinterpret_cast<const void*>(found), sizeof(pointer));
            found = pointer;
        }
        if (found != 0 && signature.kind != Kind::Address) {
            int32_t displacement = 0;
            std::memcpy(&displacement,
                        reinterpret_cast<const void*>(found + signature.disp_offset),
                        sizeof(displacement));

            const std::uintptr_t target =
                found + signature.disp_offset + sizeof(displacement) + displacement;

            if (signature.kind == Kind::RipTarget) {
                found = target;
            }
            else {
                std::uintptr_t pointer = 0;
                std::memcpy(&pointer, reinterpret_cast<const void*>(target), sizeof(pointer));
                found = pointer;
            }
        }

        cache_store(signature.name, found);

        if (found == 0) {
            g_unresolved.emplace_back(signature.name);

            char message[256]{};
            _snprintf_s(message, sizeof(message), _TRUNCATE,
                        "[search] not found: %s  (%s)", signature.name, signature.pattern);

            if (g_reporter != nullptr) {
                g_reporter(message);
            }
            else {
                OutputDebugStringA(message);
                OutputDebugStringA("\n");
            }
        }
    }

    unlock_exclusive();
}

void resolve_all(std::uintptr_t module_base, std::size_t module_size,
                 const Signature* signatures, std::size_t count) noexcept {
    (void)module_size;

    const std::vector<Range> ranges = executable_ranges(module_base);

    if (ranges.empty()) {
        lock_exclusive();
        g_unresolved.clear();

        for (std::size_t i = 0; i < count; ++i) {
            if (signatures[i].name != nullptr) {
                g_unresolved.emplace_back(signatures[i].name);
            }
        }

        unlock_exclusive();
        return;
    }

    resolve_all_in_ranges(ranges.data(), ranges.size(), signatures, count);
}

void resolve_all_data(std::uintptr_t module_base, std::size_t module_size,
                      const Signature* signatures, std::size_t count) noexcept {
    (void)module_size;

    const std::vector<Range> ranges = data_ranges(module_base);

    if (ranges.empty()) {
        return;
    }

    resolve_all_in_ranges(ranges.data(), ranges.size(), signatures, count);
}
std::uintptr_t get(const char* name) noexcept {
    if (name == nullptr) {
        return 0;
    }

    lock_shared();
    const std::uintptr_t value = cache_load(name);
    unlock_shared();

    return value;
}

bool has(const char* name) noexcept {
    return get(name) != 0;
}

std::vector<std::string> unresolved() {
    lock_shared();
    std::vector<std::string> copy = g_unresolved;
    unlock_shared();

    return copy;
}

} // namespace grid::search
