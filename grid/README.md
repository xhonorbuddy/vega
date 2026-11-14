# Grid Lua registration

Build `grid/grid.vcxproj` for x64 (Debug or Release). On the game window thread,
the DLL resolves the existing Lua state, caches a pool of existing INT3 locations,
and registers the API table using the vendored `lua-5.1.lib`.

```lua
print(C.PrintHere())  -- here
print(C.PrintThere()) -- there
```

Define callbacks and their null-terminated `luaL_Reg` table in `api.ixx`.
`grid::lua_registration::register_api(L, "C", api::functions)` assigns the next
available pool slot to each distinct callback and calls `luaL_register` with
the resulting table. It leaves the library table on the stack, just like
`luaL_register`; the caller removes it with `lua_pop(L, 1)`. A null library name
supports adding entries to a table already on the stack.

- `signature.ixx`: unique-match scanning plus bounded multi-match scanning.
- `breakpoint.ixx`: scans `C3 CC CC CC CC 48`, selecting the first existing `CC`
  after each `RET`. Requires at least 20 executable candidates and caches up to
  100. The 70938 executable has 3,128 raw matches for this broad pattern.
- `lua_registration.ixx`: checks capacity for the entire API before changing Lua;
  reuses cached mappings for repeated callbacks or registration under another name.
- `api.ixx`: `PrintHere` and `PrintThere` return their respective strings.
- `exceptions.ixx`: resolves only assigned pool entries to their callbacks using
  a lock-free lookup. Unassigned and unrelated breakpoints follow normal handling.
  Existing fake-raise behavior and monitoring are retained.
- `client_lua.ixx`: resolves and dereferences the client Lua-state slot.
- `registration.ixx`: one-shot game-window dispatch and API registration.

Initialize the pool and register APIs on the game thread. Published mappings
remain fixed for the DLL lifetime so existing Lua closures keep their targets.
An exhausted pool rejects new callbacks; cached callbacks remain usable.
No client code bytes or page protections are changed. Inaccessible pages are
skipped. A broad byte pattern identifies candidates, not a guarantee of client
stability or executable instruction boundaries in every future build.

Validation includes Debug/Release builds, scanner boundary tests, and exception
integration tests covering the 20-candidate minimum, 100-slot cap, two callbacks,
repeat-registration cache reuse, exhaustion without Lua changes, and unrelated
breakpoints. Live client stability has not been tested. Keep the DLL and its
handler loaded while Lua holds registered callbacks.
