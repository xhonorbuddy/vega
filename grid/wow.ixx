module;
// WoW 1.60.1.70938: port of the constructor/API-verified entities and clientState
// modules. Source research: binary analysis/entities-70888; migration evidence in
// entity-verification-70938.json and WOW_API.md.
// These are non-owning views. Call on the game thread while objects are live.
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

export module grid.wow;
import grid.entity_client;

export namespace grid::wow {
struct vector3 {
    float x{}, y{}, z{};
    constexpr vector3() = default;
    constexpr vector3(float a, float b, float c) : x(a), y(b), z(c) {}
};
static_assert(sizeof(void*) == 8, "WoW 70938 requires x64");
#pragma pack(push, 1)

// OBJECT TYPES
enum gameobject : uint8_t {
    ENTITY = 0,
    ITEM = 1,
    CONTAINER = 2,
    AZERITEEMPOWEREDITEM = 3,
    AZERITEEMPORTEDITEM = AZERITEEMPOWEREDITEM, // Compatibility with older callers.
    AZERITEITEM = 4,
    UNIT = 5,
    PLAYER = 6,
    ACTIVEPLAYER = 7,
    GAMEOBJECT = 8,
    DYNAMICOBJECT = 9,
    CORPSE = 10,
    AREATRIGGER = 11,
    SCENE = 12,
    CONVERSATION = 13,
    MESHOBJECT = 14,
};

// Verified primary address points from build 1.60.1.70938 constructors.
namespace entity_layout_70938 {
    inline constexpr uintptr_t primary_vtable_rvas[] = {
        0x420C778,0x4208768,0x4208F08,0x4208C30,0x42089C8,
        0x420C0D8,0x41FA328,0x41F8070,0x41FFF48,0x4209680,
        0x42093C0,0x420CD68,0x420D008,0x41F9D20,0x420EC60,
    }; // Verification evidence; runtime vtables are signature-resolved.
    inline constexpr size_t name_slot = 52;
    inline constexpr size_t dead_or_ghost_slot = 75;
    inline constexpr size_t name_position_slot = 15;
    inline constexpr uint32_t hierarchy_masks[] = {
        0x1, 0x3, 0x7, 0xB, 0x13, 0x21, 0x61, 0xE1,
        0x101, 0x201, 0x401, 0x801, 0x1001, 0x2001, 0x4001,
    };
}

// Legacy flag vocabulary. PLAYER_CONTROLLED, IN_COMBAT, ON_TAXI, and
// POSSESSED are independently confirmed by this build's script APIs.
// The other names are retained for compatibility, not newly verified here.
inline const std::unordered_map<std::string, unsigned int> unitflags = {
    {"SERVER_CONTROLLED", 0x00000001},                  // set only when unit movement is controlled by server
    {"NON_ATTACKABLE", 0x00000002},                     // not attackable, set when creature starts to cast spells
    {"REMOVE_CLIENT_CONTROL", 0x00000004},              // legacy flag to disable client movement control
    {"PLAYER_CONTROLLED", 0x00000008},                  // controlled by player
    {"RENAME", 0x00000010},
    {"PREPARATION", 0x00000020},                        // don't take reagents for certain spells
    {"UNK_6", 0x00000040},
    {"NOT_ATTACKABLE_1", 0x00000080},                   // part of NON_PVP_ATTACKABLE
    {"IMMUNE_TO_PC", 0x00000100},                       // disables combat with PlayerCharacters
    {"IMMUNE_TO_NPC", 0x00000200},                      // disables combat with NonPlayerCharacters
    {"LOOTING", 0x00000400},                            // loot animation
    {"PET_IN_COMBAT", 0x00000800},                      // pet combat status
    {"PVP_ENABLING", 0x00001000},
    {"SILENCED", 0x00002000},                           // silenced
    {"CANT_SWIM", 0x00004000},                          // Can't Swim
    {"CAN_SWIM", 0x00008000},                           // Can Swim
    {"NON_ATTACKABLE_2", 0x00010000},                   // removes attackable icon
    {"PACIFIED", 0x00020000},
    {"STUNNED", 0x00040000},
    {"IN_COMBAT", 0x00080000},
    {"ON_TAXI", 0x00100000},                            // disable casting during taxi flight
    {"DISARMED", 0x00200000},                           // disable melee spell casting
    {"CONFUSED", 0x00400000},
    {"FLEEING", 0x00800000},
    {"POSSESSED", 0x01000000},                          // under direct client control
    {"UNINTERACTIBLE", 0x02000000},
    {"SKINNABLE", 0x04000000},
    {"MOUNT", 0x08000000},
    {"UNK_28", 0x10000000},
    {"PREVENT_EMOTES_FROM_CHAT_TEXT", 0x20000000},      // prevent auto-emotes from chat
    {"SHEATHE", 0x40000000},
    {"IMMUNE", 0x80000000},                             // Immune to damage
};

// ANIMATION STATUS
enum animation {
    IDLE = 1,
    ACTIVE = 3,
    RETIRED = 5,
};

// GUID STRUCTURE
struct guid {
    // WOWGUID stores the low word first; the high word carries the GUID kind.
    uint64_t low;
    uint64_t high;

    bool operator==(const guid& rhs) const {
        return (low == rhs.low && high == rhs.high);
    }
};
static_assert(sizeof(guid) == 0x10);
static_assert(offsetof(guid, low) == 0 && offsetof(guid, high) == 8);
static_assert(sizeof(vector3) == 0xC);

// Verified common prefix only; this is not the complete size of any entity class.
struct entity_header {
    uintptr_t vtable;
    uintptr_t component_handle;
    guid id;
    std::byte unknown20[4];
    gameobject type;
    uint8_t constructed_type;
    std::byte unknown26[2];
};
static_assert(sizeof(entity_header)==0x28);
static_assert(offsetof(entity_header,id)==0x10 && offsetof(entity_header,type)==0x24 &&
              offsetof(entity_header,constructed_type)==0x25);

// CLICK TO MOVE
struct ctm {
    guid GUID{};					// 0x0
    vector3 location;				// 0x10
    unsigned int type{};			// 0x1C
};
static_assert(offsetof(ctm, location) == 0x10 && offsetof(ctm, type) == 0x1C);

// MOUSE CLICK
struct mouseClick {
    char unk1[0x2D0];
    unsigned int type;				// 0x2D0
    char unk2[0x4];
    guid GUID;						// 0x2D8
    vector3 position;				// 0x2E8
};
static_assert(offsetof(mouseClick, type) == 0x2D0);
static_assert(offsetof(mouseClick, GUID) == 0x2D8 && offsetof(mouseClick, position) == 0x2E8);

// GAME ENTITY
class entity {
    template <typename T>
    const T& field(ptrdiff_t offset) const {
        return *reinterpret_cast<const T*>(reinterpret_cast<const char*>(this) + offset);
    }

    // VIRTUAL METHODS
    template <typename T, typename... ARGS>
    T vmtMethod(void* instance, size_t index, ARGS... args) {
        using VMT = T(*)(void*, ARGS...);

        auto vmt = *reinterpret_cast<uintptr_t**>(instance);
        auto method = reinterpret_cast<VMT>(vmt[index]);

        return method(instance, args...);
    }
public:

    // Requires an otherwise live object pointer, just like the field accessors.
    bool matchesVtable() const {
        const auto object_type = static_cast<uint8_t>(type());
        if (object_type >= 15)
            return false;

        return entity_client::accept_vtable(object_type,field<uintptr_t>(0),
            reinterpret_cast<uintptr_t>(this));
    }

    uintptr_t base() const {
        return uintptr_t(this);
    }

    bool active() const {
        // Constructors set +0x25 to the completed class ID; base teardown sets
        // it to 0x12. This checks construction state, not pointer lifetime.
        return matchesVtable() &&
            field<uint8_t>(0x25) == static_cast<uint8_t>(type());
    }

    bool isUnit() const {
        const auto object_type = type();
        return object_type == UNIT || object_type == PLAYER || object_type == ACTIVEPLAYER;
    }

    bool isA(gameobject base_type) const {
        const auto object_type = static_cast<uint8_t>(type());
        const auto base_id = static_cast<uint8_t>(base_type);
        return object_type < 15 && base_id < 15 &&
            (entity_layout_70938::hierarchy_masks[object_type] & (1u << base_id)) != 0;
    }

    gameobject type() const {
        // 1.60.1.70938: independently read by object lookup and unit predicates.
        return field<gameobject>(0x24);
    }

    guid id() const {
        // 1.60.1.70938: passed to the GUID formatter in object activation.
        return field<guid>(0x10);
    }

    int64_t movement() const {
        // Unit construction copies its movement pointer from +0xA8 to +0xE0.
        return active() && isUnit() ? field<int64_t>(0xE0) : 0;
    }

    float facing() const {
        if (!active())
            return 0.0f;
        // GetPlayerFacing uses this component-aware, transport-aware getter.
        using GetFacing = float (*)(const entity*);
        return reinterpret_cast<GetFacing>(entity_client::get().facing)(this);
    }

    int dead() const {
        if (!active() || !isUnit())
            return 0;
        if (health() <= 0)
            return 1;
        if ((flags3() & 0x2000u) == 0)
            return 0;

        // The live-object branch of UnitIsDead uses this additional check.
        using StateCheck = bool (*)(const entity*);
        return !reinterpret_cast<StateCheck>(entity_client::get().death)(this);
    }

    bool deadOrGhost() {
        return active() && isUnit() &&
            vmtMethod<bool>(this, entity_layout_70938::dead_or_ghost_slot);
    }

    guid corpseOwner() const {
        // Corpse display resolves this GUID as a player; party membership
        // checks use the same GUID when deciding whether to keep the corpse.
        return active() && type() == CORPSE ? field<guid>(0x110) : guid{};
    }

    int gameObjectSubtype() const {
        return active() && type() == GAMEOBJECT ? field<uint8_t>(0x1C9) : -1;
    }

    int gameObjectState() const {
        // Raw network state, separate from cached display state at +0x110.
        return active() && type() == GAMEOBJECT ? field<uint8_t>(0x1C8) : -1;
    }

    bool isFishingBobber() const {
        return gameObjectSubtype() == 17;
    }

    bool fishingBiteAnimationActive() const {
        // Reports the splash animation window, not a persistent loot-ready
        // latch. Exclude a bobber playing its retirement animation.
        const auto status = animation();
        return isFishingBobber() && (status & ACTIVE) == ACTIVE && (status & 4u) == 0;
    }

    unsigned int animation() const {
        // Game-object local flags: bit 0 initialized, bit 1 animation update
        // lock (1EB9900 / 1ED0650), bit 2 despawn animation (1EB7FA0).
        // Only the byte at +0x114 belongs to these flags.
        return active() && type() == GAMEOBJECT ? field<uint8_t>(0x114) : 0;
    }

    guid owner() const {
        if (!active())
            return {};
        if (type() == CORPSE)
            return corpseOwner();
        if (type() == GAMEOBJECT)
            return field<guid>(0x188);
        if (isA(ITEM))
            // Item creation/destruction resolves this GUID as its player
            // owner and adjusts that player's live item count.
            return field<guid>(0x150);
        if (!isUnit())
            return {};
        // UnitOwnerGUID prefers the charmer when its GUID kind is nonzero.
        const auto charmer = field<guid>(0x1D68);
        return (charmer.high >> 58) != 0 ? charmer : field<guid>(0x1D88);
    }

    int64_t health() const {
        // Raw current health. The script API can additionally scale this value.
        return active() && isUnit() ? field<int64_t>(0x1E28) : 0;
    }

    int manaPower() const {
        return power();
    }

    int power(int power_type = -1) const {
        if (!active() || !isUnit())
            return 0;
        if (power_type == -1)
            power_type = field<uint8_t>(0x1E21);
        if (power_type < 0 || power_type >= 30)
            return 0;

        using PowerSlot = int (*)(const entity*, int8_t);
        const auto slot = reinterpret_cast<PowerSlot>(entity_client::get().power)(this, static_cast<int8_t>(power_type));
        // Constructor storage spans 0x1BC0..0x1BE7 (ten int32 slots),
        // followed by the corresponding maximum-power array at 0x1BE8.
        return slot >= 0 && slot < 10 ? field<int32_t>(0x1BC0 + slot * 4) : 0;
    }

    guid target() const {
        // The unit-token resolver's "target" suffix reads this 16-byte GUID.
        return active() && isUnit() ? field<guid>(0x1DB8) : guid{};
    }

    uint32_t flags() const {
        // UnitAffectingCombat / UnitPlayerControlled / UnitOnTaxi /
        // UnitIsPossessed all test this primary flags word.
        return active() && isUnit() ? field<uint32_t>(0x1E58) : 0;
    }

    uint32_t flags3() const {
        // Separate flags word used by UnitIsFeignDeath / UnitIsDead.
        return active() && isUnit() ? field<uint32_t>(0x1E60) : 0;
    }

    vector3 location() {
        vector3 result(0.0f, 0.0f, 0.0f);
        if (!active())
            return result;
        // The current client resolves position through the object's component
        // handle. The output is three floats, passed by pointer in RDX.
        using GetPosition = vector3* (*)(const entity*, vector3*);
        reinterpret_cast<GetPosition>(entity_client::get().position)(this, &result);
        return result;
    }

    vector3 plateLocation() {
        vector3 v(0.0f, 0.0f, 0.0f);

        if (!active())
            return v;
        // The inherited implementation forwards to the model; the game-object
        // override can calculate its name position without a model.
        if (type() != GAMEOBJECT && field<uintptr_t>(0x30) == 0)
            return v;
        vmtMethod<vector3*>(this, entity_layout_70938::name_position_slot, &v);

        return v;
    }

    const char* rawName() {
        return active() ? vmtMethod<const char*>(this, entity_layout_70938::name_slot) : nullptr;
    }

    std::string name() {
        if (!active())
            return "UNKNOWN";

        const char* name = vmtMethod<const char*>(this, entity_layout_70938::name_slot);

        if (name != nullptr && name[0] != '\0') {
            return std::string(name);
        }

        return "UNKNOWN";
    }
};

#pragma pack(pop)

namespace client_state_70938 {
    enum class phase { unavailable, outside_world, loading, in_world };

    struct snapshot {
        bool available{};
        uint16_t game_ui_flags{};
        int32_t loading_requests{};
        bool loading_screen_layer{};

        constexpr bool playerInWorld() const {
            return available && (game_ui_flags & 0x10) != 0;
        }

        constexpr phase state() const {
            if (!available)
                return phase::unavailable;
            // The screen can still exist after the last request is released.
            if (loading_requests > 0 || loading_screen_layer)
                return phase::loading;
            return playerInWorld() ? phase::in_world : phase::outside_world;
        }
    };

    inline snapshot read() {
        if (!entity_client::supported()) return {};
        const auto& addresses=entity_client::get();
        const auto counter=*reinterpret_cast<const volatile uintptr_t*>(addresses.counter);
        if (!counter)
            return {};
        snapshot result{};
        result.game_ui_flags = *reinterpret_cast<const volatile uint16_t*>(addresses.flags);
        result.loading_requests = *reinterpret_cast<const volatile int32_t*>(counter);
        result.loading_screen_layer = *reinterpret_cast<const volatile uintptr_t*>(addresses.layer) != 0;
        result.available = true;
        return result;
    }
}

} // namespace grid::wow
