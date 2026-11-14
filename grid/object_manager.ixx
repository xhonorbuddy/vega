module;
#include <windows.h>
#include <cstdint>
#include <algorithm>
#include <cstring>

export module grid.object_manager;
import grid.entity_client;
import grid.wow;

export namespace grid::object_manager {
inline constexpr char metatable_name[]="grid.entity";
struct handle { wow::guid id; };
struct statistics { std::size_t enumerated{}, unique{}, lookups{}, missing{}, invalid{}, mismatched{}; };
statistics last_statistics() noexcept;
void set_game_thread(DWORD thread) noexcept;
const char* ready_reason() noexcept;
wow::entity* lookup(wow::guid id) noexcept;
bool name_is(wow::entity* object,const char* text,std::size_t length) noexcept;
// Produces GUIDs, never borrowed pointers. Enumeration is synchronous and game-thread only.
inline constexpr std::size_t max_objects=65536;
bool enumerate(wow::guid* result,std::size_t capacity,std::size_t& count,const char*& error);
}

namespace grid::object_manager {
namespace {
DWORD game_thread{};
wow::guid* capture{};
std::size_t captured{};
std::size_t capture_capacity{};
bool overflow{};
statistics stats{};
int fault_filter(DWORD code) {
    return code==EXCEPTION_ACCESS_VIOLATION || code==EXCEPTION_IN_PAGE_ERROR
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
bool read_world(wow::client_state_70938::snapshot& state) noexcept {
    __try { state=wow::client_state_70938::read(); return true; }
    __except(fault_filter(GetExceptionCode())) { return false; }
}
unsigned int collect(const wow::guid* id, std::uintptr_t) noexcept {
    if (!capture || !id || !(id->low || id->high)) return 1;
    if (captured==capture_capacity) { overflow=true; return 0; }
    capture[captured++]=*id;
    return 1;
}
bool native_enumerate() noexcept {
    using callback=unsigned int (*)(const wow::guid*,std::uintptr_t);
    using function=bool (*)(callback);
    __try { return reinterpret_cast<function>(entity_client::get().enumerate)(collect); }
    __except(fault_filter(GetExceptionCode())) { return false; }
}
}
statistics last_statistics() noexcept { return stats; }
void set_game_thread(DWORD thread) noexcept { game_thread=thread; }
const char* ready_reason() noexcept {
    if (!entity_client::supported()) return "unsupported client build or unresolved entity signatures";
    if (!game_thread || GetCurrentThreadId()!=game_thread) return "object access requires the game thread";
    wow::client_state_70938::snapshot world{};
    if (!read_world(world) || world.state()!=wow::client_state_70938::phase::in_world)
        return "game world is not ready";
    const auto& b=entity_client::get();
    __try {
        if (!*reinterpret_cast<const std::uintptr_t*>(b.manager) ||
            !*reinterpret_cast<const std::uintptr_t*>(b.visible)) return "object manager is unavailable";
    } __except(fault_filter(GetExceptionCode())) { return "object manager is unreadable"; }
    return nullptr;
}
wow::entity* lookup(wow::guid id) noexcept {
    if (ready_reason() || !(id.high>>58)) return nullptr;
    ++stats.lookups;
    __try {
        auto* object=reinterpret_cast<wow::entity*>(entity_client::object_for_guid(&id));
        if (!object) { ++stats.missing; return nullptr; }
        if (!object->active()) { ++stats.invalid; return nullptr; }
        if (!(object->id()==id)) { ++stats.mismatched; return nullptr; }
        return object;
    } __except(fault_filter(GetExceptionCode())) { ++stats.invalid; return nullptr; }
}
bool name_is(wow::entity* object,const char* text,std::size_t length) noexcept {
    if (!object || length>=512) return false;
    __try {
        const auto* name=object->rawName();
        if (!name) return false;
        for (std::size_t i=0;i<length;++i) if (!name[i] || name[i]!=text[i]) return false;
        return name[length]==0;
    } __except(fault_filter(GetExceptionCode())) { return false; }
}
bool enumerate(wow::guid* result,std::size_t capacity,std::size_t& count,const char*& error) {
    count=0;
    stats={};
    error=ready_reason();
    if (error) return false;
    if (!result || !capacity || capacity>max_objects) { error="invalid snapshot buffer"; return false; }
    if (capture) { error="object enumeration is already active"; return false; }
    capture=result; capture_capacity=capacity; captured=0; overflow=false;
    const bool success=native_enumerate();
    capture=nullptr;
    stats.enumerated=captured;
    if (!success || overflow) {
        error=overflow ? "object enumeration limit exceeded" : "object enumeration failed";
        return false;
    }
    std::sort(result,result+captured,[](wow::guid a,wow::guid b) {
        return a.high<b.high || (a.high==b.high && a.low<b.low);
    });
    count=static_cast<std::size_t>(std::unique(result,result+captured)-result);
    stats.unique=count;
    return true;
}
}
