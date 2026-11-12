# WoW 1.60.1.70888 queries in grid.dll

The verified entity and client-state layouts are ported into the `grid.wow`
module in `wow.ixx`. Lua registration and queries are in `grid.wow_api`,
defined by `wow_api.ixx`.
The Lua functions below are added to the existing global `C` table by both
registration paths. `C.AFK` is preserved.

```lua
local state = C.WorldState()
print(state.state) -- in_world, loading, outside_world, unavailable
print(C.IsInWorld(), C.IsLoading())

-- An existing live client object pointer, as lightuserdata or a hex address:
local info, err = C.ObjectInfo(objectPointer)
if info then
    print(info.typeName, info.guid, info.name)
    print(info.position.x, info.position.y, info.position.z)
end
```

Object queries run on the thread that registered the API, require the expected
executable PE fingerprint, and require an in-world state without an active
loading screen. A missing/unsupported state or an invalid object returns
`nil, reason`; `ObjectValid` returns `false, reason`. Access violations and
in-page memory faults are contained. Callers must still supply live objects: the type/tag/vtable
checks cannot establish the lifetime of a pointer whose memory has been reused.

No object enumerator or GUID-to-pointer resolver is inferred from the old
Tetra signatures. These queries consume pointers obtained by the caller.
Pointers can be lightuserdata, a complete `0x...` hexadecimal string, or an
exact nonnegative Lua number no greater than 2^53-1. Hexadecimal strings preserve
all address bits.

## Available functions

| Function | Result |
|---|---|
| `WorldState()` | State table, build support, availability, loading flags/count |
| `IsInWorld()` / `IsLoading()` | Boolean, including loading-screen precedence |
| `ObjectTypes()` | 15 records: id, name, inheritance mask |
| `ObjectInfo(pointer)` | Combined identity, name, position/facing, class-specific fields |
| `ObjectValid(pointer)` | Constructed-class tag and expected primary vtable match |
| `ObjectType(pointer)` | Numeric type ID, class name |
| `ObjectGUID(pointer)` | Full high/low GUID as a 32-digit hex string prefixed with 0x |
| `ObjectOwner(pointer)` | Verified Item/Unit/GameObject/Corpse relationship, or nil |
| `ObjectTarget(pointer)` | Unit target GUID or nil |
| `ObjectHealth(pointer)` | Raw 64-bit health as a number plus an exact decimal string |
| `ObjectPower(pointer[, type])` | Displayed resource; use type 0 for mana |
| `ObjectFlags(pointer)` / `ObjectFlags3(pointer)` | Separate primary/death-related words |
| `ObjectName(pointer)` | Object name, or UNKNOWN |
| `ObjectPosition(pointer)` / `ObjectPlatePosition(pointer)` | Table with x, y, z |
| `ObjectFacing(pointer)` | Component/transport-aware facing |
| `ObjectDead(pointer)` / `ObjectDeadOrGhost(pointer)` | Unit-class Boolean |
| `ObjectAnimationFlags(pointer)` | Game-object local flags byte at +0x114 |
| `Animating(pointer)` / `FishingBiteAnimationActive(pointer)` | Fishing-node splash window |

Unit-only queries reject other classes. `ObjectInfo` omits fields that do not
apply to that class. Its `healthExact` field avoids Lua-number precision loss
for health values exceeding 2^53. Empty GUIDs are represented as nil.

`Animating` checks subtype 17 and the local animation status, excluding the
despawn bit. The confirmed cast transitioned 0x11 -> 0x13 -> 0x11 -> 0x05,
while raw network GO state stayed 1. The splash window lasted about 1.31 seconds.
It is a transient bite-animation indication, not a persistent loot-ready latch.

The world-state helper uses the packed flags word at RVA 0x4CD5D78 (in-world
bit 0x10), the signed counter pointed to at RVA 0x69E47C0, and the screen-layer
handle at RVA 0x69E4828. The three-float vector is 12 bytes; the mouse overlay
uses type/GUID/position offsets 0x2D0/0x2D8/0x2E8.

The C++ module exposes the complete migrated entity accessors, type hierarchy,
primary vtable mapping, GUID, terrain-click and mouse layouts. The Lua adapter
uses the native name pointer directly and makes a bounded copy instead of
allocating a C++ string inside its Windows fault boundary.

## Verification

`tests/wow_api_test.vcxproj` builds a standalone host against the same port and
Lua adapter. It checks all 15 type guards, GUID order, large health, distinct
flag words, ownership/target gating, captured splash flags, input layout,
world-state precedence, preservation of existing C.AFK registration, every new
function registration, unsupported-client rejection, and malformed addresses.
It does not inject the DLL or invoke version-specific client RVAs in the host.

The existing loader, exception/protection handling, and Lua ABI changes in the
working tree were preserved. This update adds the query layer and registration
entries; it does not alter those mechanisms.
