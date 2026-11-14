module;
#include <windows.h>
#include <cstdint>

export module grid.entity_index;
export namespace grid::entity_index {
// Read-only lookup of the CGObject component in the verified 70938 index.
std::uintptr_t find(std::uintptr_t index_slot,const void* id) noexcept;
}
namespace grid::entity_index {
std::uintptr_t find(std::uintptr_t index_slot,const void* id) noexcept {
    if (!id || !index_slot) return 0;
    // 70938 ObjectMgr index: +8 entry array, +0x10 slot count, 16-byte entries.
    // Metadata +0x34 describes the CGObject* component. Negative offsets select
    // the out-of-line bank at metadata+0x448 (48-byte banks, +0x18 values).
    struct entry { std::uint32_t state, reserved; std::uintptr_t entity; };
    static_assert(sizeof(entry)==16);
    __try {
        const auto* wanted=static_cast<const std::uint64_t*>(id);
        const auto index=*reinterpret_cast<const std::uintptr_t*>(index_slot);
        if (!index) return 0;
        const auto* entries=*reinterpret_cast<const entry* const*>(index+8);
        const auto count=*reinterpret_cast<const std::uint64_t*>(index+0x10);
        if (!entries || count>65536) return 0;
        for (std::uint64_t i=0;i<count;++i) {
            const auto cell=entries[i];
            if (!cell.entity || !(cell.state&0x80000000u) || (cell.state&0x3fffffffu)==0x3fffffffu) continue;
            const auto metadata=*reinterpret_cast<const std::uintptr_t*>(cell.entity+8);
            if (!metadata) continue;
            const auto offset=*reinterpret_cast<const std::int32_t*>(metadata+0x34);
            if (offset==-1) continue;
            std::uintptr_t object{};
            if (offset>=0) object=*reinterpret_cast<const std::uintptr_t*>(cell.entity+offset);
            else {
                const auto bank=*reinterpret_cast<const std::uint32_t*>(cell.entity+0x10);
                if (bank>=65536) continue;
                const auto banks=*reinterpret_cast<const std::uintptr_t*>(metadata+0x448);
                if (!banks) continue;
                const auto values=*reinterpret_cast<const std::uintptr_t*>(banks+48ull*bank+0x18);
                if (!values) continue;
                object=*reinterpret_cast<const std::uintptr_t*>(values+16ull*(static_cast<std::uint32_t>(offset)&0x7fffffffu));
            }
            if (!object) continue;
            const auto* actual=reinterpret_cast<const std::uint64_t*>(object+0x10);
            if (actual[0]==wanted[0] && actual[1]==wanted[1]) return object;
        }
    } __except(GetExceptionCode()==EXCEPTION_ACCESS_VIOLATION || GetExceptionCode()==EXCEPTION_IN_PAGE_ERROR
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return 0; }
    return 0;
}
}
