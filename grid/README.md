# Grid Lua registration

Build `grid/grid.vcxproj` for x64 (Debug or Release). The DLL registers its VEH
and posts a one-shot window message. On the window thread it resolves the Lua
state and breakpoint, then registers the existing global `C()` callback using
`lua-5.1.lib`. The window procedure is restored before registration.

- `breakpoint.ixx`: resolves an existing INT3 in executable padding using an
  IDA-style byte pattern; no client bytes or page protections are changed.
- `signature.ixx`: scans readable executable pages and rejects ambiguous matches.
- `client_lua.ixx`: resolves and dereferences the client Lua-state slot.
- `registration.ixx`: registers `C` with the resolved breakpoint as its callback.
- `exceptions.ixx`: redirects only that breakpoint to the existing Lua callback,
  which returns `here`. Existing fake-raise handling and monitoring remain.
- `api.ixx`: retains the separate AFK table for later use; current registration
  follows the existing `C()` hop instead of registering that table.

The patcher and its tests have been removed. There are no client patch calls.

The short pattern `C3 CC CC CC CC 48` has thousands of matches in build 70938.
The longer padding/prologue pattern in `breakpoint.ixx` matches uniquely at RVA
`0x339DC9`; its second `CC`, RVA `0x339DCA`, is the original working hop location.
These addresses document verification against `Wow 1.60.1.70938.exe` only;
runtime resolution uses the signature. Missing, ambiguous, or unreadable
patterns skip registration. The Lua-state pattern resolves slot `0x6B46468`.

Validation: x64 Debug/Release builds; unique hop pattern checked against the
70938 executable; exception tests cover handler lifecycle, unrelated breakpoint
propagation, and 100 Lua calls through an executable fixture's resolved INT3.
Live client stability has not been tested. Keep the DLL and its handler loaded
while Lua retains the callback.
