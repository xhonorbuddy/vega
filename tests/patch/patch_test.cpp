// Scratch harness for grid.patch: exercises the byte writer against a local
// function and checks that a bad offset is rejected instead of written.

#include <Windows.h>

#include <cstdint>
#include <cstdio>

import grid.patch;

namespace {

    void dummy_function() noexcept {
    }

} // namespace

int main() {
    const auto address = reinterpret_cast<std::uintptr_t>(&dummy_function);
    const std::uint8_t before = *reinterpret_cast<const std::uint8_t*>(address);

    const bool written = grid::patch::write_byte(address, grid::patch::kRetByte);
    const std::uint8_t after = *reinterpret_cast<const std::uint8_t*>(address);

    const bool restored = grid::patch::write_byte(address, before);
    const std::uint8_t final_byte = *reinterpret_cast<const std::uint8_t*>(address);

    std::printf(
        "write=%d before=0x%02x after=0x%02x restored=%d final=0x%02x\n",
        written ? 1 : 0,
        before,
        after,
        restored ? 1 : 0,
        final_byte
    );

    std::printf("client_base=0x%llx image_size=0x%zx\n",
        static_cast<unsigned long long>(grid::patch::client_base()),
        grid::patch::client_image_size(grid::patch::client_base()));

    // The configured offset is far outside this harness image, so the guard must
    // reject it and apply nothing.
    const std::size_t applied = grid::patch::install_client_patches();
    std::printf("install_client_patches=%zu (expected 0)\n", applied);

    const bool ok =
        written &&
        after == grid::patch::kRetByte &&
        restored &&
        final_byte == before &&
        applied == 0;

    std::printf("RESULT: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
