# Grid Lua registration

Build `grid/grid.vcxproj` for x64 (Debug or Release). The DLL installs a one-shot
window dispatch so registration runs on the game's window thread, then restores
the original window procedure. `DllMain` starts and stops the dispatch and
exception monitor. On the window thread, it patches the client before registering
the Lua API.

- `api.ixx`: the null-terminated API table; currently `C.AFK()` returns `hello`.
- `patch.ixx`: reusable signature-based byte patches, original-byte checks, instruction
  cache flushing, page-protection restoration, and restoration on DLL detach.
  The initial patch changes the entry of `sub_1E6B80` to `C3`; patch failure skips
  Lua registration.
- `client_lua.ixx`: IDA signature resolution for the client Lua-state slot.
- `signature.ixx`: unique-match scanning of readable executable pages.
- `exceptions.ixx`: vectored exception monitoring through `OutputDebugStringA`: count,
  thread ID, code, flags, exception address, RIP, and memory access details.
  It always returns `EXCEPTION_CONTINUE_SEARCH` and never changes the context.
  Debug-print notifications are ignored; recursive/concurrent logging is skipped.
  The handler is removed on detach and if registration startup fails.
- `registration.ixx`: game-thread dispatch, `luaL_register(L, "C", api)`, and
  removal of the table left on the stack.

Registration, string pushes, and stack cleanup use the vendored `lua-5.1.lib`
through `luaL_register`, `lua_pushstring`, and `lua_pop`. The project reference
builds and links that library automatically. The existing client Lua state is
read from the signature-resolved slot; no separate Lua state is created.

Entry bytes checked in the open 70938 IDB; unique patterns checked against the
matching `Wow 1.60.1.70938.exe` on 2026-11-13:

| Pattern | Unique match RVA | Resolution |
| --- | --- | --- |
| `sub_1E6B80` | `0x1E6B80` | Entry byte `40` replaced with `C3` |
| Lua state reference | `0x339862` | RIP-relative operand at +3, next instruction +7; slot `0x6B46468` |

RVAs document the IDB verification only. Runtime resolution uses the patterns,
rejects missing or duplicate matches, and skips registration when the state is
null. Inaccessible pages are skipped without changing their protection.

The former diagnostic, entity, and world API modules
are excluded from this DLL's build. Their source is retained for separate use.
The active API table previously registered only AFK; the unused world API table
is not added implicitly.

Validation: x64 Debug and Release builds; unique state match and RIP target verified
in the open IDB; `tests/signature_test.vcxproj` exercises wildcard matching,
ambiguity, protection boundaries, unreadable pages, and malformed patterns.
`tests/patch_test.vcxproj` verifies patch application, original-byte checks,
restoration, protection preservation, and ambiguous/missing pattern rejection.
Live patching and registration have not been run. The former callback-range bypass is absent;
this change does not establish that the client will accept external callbacks.
Keep the DLL mapped while Lua holds its registered callbacks.
