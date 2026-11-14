# Entities and object manager: 1.60.1.70938

The `entities-70888` research is migrated into the current DLL and checked against
the latest saved 70938 IDB, using a separate headless snapshot. The user's open
IDA windows were not controlled or modified. `entity-verification-70938.json`
records the verified fields, ABI, signatures, and addresses.

```lua
local objects, err = C.Objects()
if not objects then print(err); return end
for _, object in ipairs(objects) do
    local x, y, z = object:Position()
    print(object:GUID(), object:Type(), object:Name(), x, y, z)
end

local units = C.Objects(5, true)       -- Unit + Player + ActivePlayer
local exactUnits = C.ObjectsFiltered(5) -- Unit only
local bobber = C.Objects("Exact Name") -- first matching visible name
local same = C.Object(objects[1]:GUID())
print(same == objects[1])              -- GUID identity
```

`C.Objects()` enumerates the client's visible-object index. It returns a table,
including an empty table when nothing matches. Numeric arguments filter by type;
`true` as the second argument includes derived classes. A name or full GUID string
returns one object, following Tetra's identifier-search convention. `C.Object`
also resolves an exact name or a `0x`-prefixed 32-hex-digit GUID. No unit-token
parser is implied. Failures return `nil, reason`.

Each result is full userdata containing a 16-byte GUID, with the protected
`grid.entity` metatable. It owns no client object. Every live-property query
resolves the GUID again through the read-only object index, validates type/construction state and vtable, and runs
on the registration thread while the world is ready. A retained handle therefore
does not retain a stale raw pointer. `Valid()` returns false after removal or
while loading; `GUID()` and `tostring()` still report the stored identity.

| Object method | Result |
| --- | --- |
| `Valid()` / `IsA(type)` | Validity / inheritance check |
| `GUID()` / `Base()` | Exact GUID / current pointer as hexadecimal strings |
| `Type()` | Numeric type and class name |
| `Name()` / `Info()` | Bounded name / complete property table |
| `Position()` / `PlatePosition()` | Three numbers: x, y, z |
| `Facing()` | Radians as a number |
| `Owner()` / `Target()` / `TargetGUID()` | GUID, or nil when empty |
| `Health()` | Number plus exact decimal string for int64 precision |
| `Power([type])` / `ManaPower()` | Resource value; default is displayed resource |
| `Flags()` / `Flags3()` | Separate unsigned unit flag words |
| `IsDead()` / `DeadOrGhost()` | Unit-only predicates |
| `AnimationFlags()` / `Animating()` | Game-object local flags / fishing splash window |

Unit-only properties reject other classes. Unsupported ownership relationships
return nil. The splash predicate follows the verified 70888 capture; the relevant
70938 field locations are unchanged, but a fresh in-game splash was not sampled.
Tetra's mutation/input methods (Click, SetFacing, etc.) are not migrated here.

The existing flat queries remain available: `C.WorldState`, `C.IsInWorld`,
`C.IsLoading`, `C.ObjectTypes`, `C.ObjectInfo`, `C.ObjectValid`, `C.ObjectType`,
`C.ObjectGUID`, `C.ObjectOwner`, `C.ObjectTarget`, `C.ObjectHealth`, `C.ObjectPower`,
`C.ObjectFlags`, `C.ObjectFlags3`, `C.ObjectName`, `C.ObjectPosition`,
`C.ObjectPlatePosition`, `C.ObjectFacing`, `C.ObjectDead`, `C.ObjectDeadOrGhost`,
`C.ObjectAnimationFlags`, `C.Animating`, and `C.FishingBiteAnimationActive`.
They accept entity handles as well as the original lightuserdata/hex-pointer
inputs. Flat position queries return vector tables. The two print tests remain.

## Verified migration

All 15 class IDs, inheritance masks, construction tag +0x25, type +0x24, and
low/high GUID at +0x10 agree with the new class factory at `0x1A13480` and
class constructors. Vtable name/plate/dead-or-ghost slots are 52/15/75. Health
remains signed int64 +0x1E28; flags +0x1E58 and +0x1E60 remain separate. Power
storage, target/owner GUIDs, game-object state/subtype, and local animation byte
were checked against current instructions and constructors.

`entity_client.ixx` resolves 31 native functions, globals, and class-table
references from unique IDA patterns. Runtime support requires AMD64 timestamp
`0x6AF601DA`. The exported IDB image reports size `0x7428A00`; the live client
reports `0x7422000`, so support does not require those two sizes to be equal.
All needed addresses are inside the live image.

| Binding | Verified RVA |
| --- | --- |
| Visible enumeration | `0x1A10210` |
| Script-facing GUID lookup (reference only) | `0x1A11C90` |
| Position / facing | `0x1F61D0` / `0x20EEF0` |
| Power-slot / death helper | `0x20C3050` / `0x1FAD740` |
| World flags / loading pointer / layer | `0x4DEA0E8` / `0x6AF8B40` / `0x6AF8BA8` |

The enumeration callback receives a GUID pointer and a zero context argument,
not an entity pointer. The manager collects GUIDs synchronously, deduplicates
results, and resolves their CGObject components through the current object index. It bounds snapshots at
65,536 entries and rejects reentrant enumeration.

Some constructor pages are inaccessible even in-world. Class-table references
are optional at initialization: a missing class table is cached only after the
read-only index lookup independently returns that exact live
object with the expected type/tag. There is no fixed-RVA fallback and no change
to client code or memory protections. Existing VEH behavior is unchanged.

Lua userdata was checked against native `lua_newuserdata` (`0x39E20C0`) and its
allocator (`0x39EE960`): header/payload offset 0x30, metatable +0x18, environment
+0x20, length +0x28. The integration test asserts the vendored layout and forces
collection of these userdata.

## Validation

- Debug/Release x64 DLL builds.
- `tests/verify_entity_bindings.py <70938-export.exe>` checks all 31 unique
  signatures/RIP targets and all 15 masks against the PE export.
- `tests/wow_api_test.vcxproj` tests all 15 class guards and accessor layouts.
- `tests/object_manager_test.vcxproj` exercises real Lua userdata/metatables and
  INT3/VEH registration with synthetic native providers: enumeration, GUID/name
  lookup, inheritance filters, methods, identity, stale handles, construction
  tags, loading precedence, wrong-thread rejection, contained read faults,
  snapshot overflow, cold-vtable confirmation, registration errors, repeated
  GC cycles, and recovery.
- A read-only check of the running 70938 client confirmed native signatures and
  world/loading globals: flags 0x211, zero requests, no loading layer. Alternate flag references handle
  changing code-page readability.

The first live test captured 28 GUIDs but the script-facing lookup exposed none.
The resolver now walks the verified index: entries +0x8, count +0x10, 16-byte
cells, CGObject component descriptor at metadata +0x34, including external banks.
A read-only walk found 63 correctly typed objects and confirmed matching GUIDs.
This updated resolver still needs to be exercised by loading the rebuilt DLL.
`C.ObjectManagerStats()` reports the last enumeration and subsequent lookup counts:
`enumerated`, `unique`, `lookups`, `missing`, `invalid`, and `mismatched`.

Native enumeration and userdata use inside the live client have not been
executed by the assistant as part of these checks. No DLL was injected, no remote function was
called, and no client protection was changed. Keep the DLL/VEH loaded while Lua
holds registered callbacks or entity userdata. Live gameplay stability remains
to be validated by loading the built DLL in the intended session.
