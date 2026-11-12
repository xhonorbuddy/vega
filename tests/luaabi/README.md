# WoW 1.60.1.70888 Lua 5.1.4 ABI notes

The vendored `lua-5.1` is compiled against the client's object layout. Every
offset below was read out of the client's own Lua functions in
`binary analysis\Wow 1.60.1.70888.exe.i64` (headless IDA, exported symbols), so
these are facts about the shipped client rather than assumptions.

`tests/luaabi/luaabi.c` prints the compiler's layout; the static asserts at the
bottom of `lua-5.1/lstate.h` fail the build if it drifts.

## Confirmed layout

| Object | Field | Offset | Evidence in the client |
| --- | --- | --- | --- |
| TValue | value / tt / taint | 0x00 / 0x08 / 0x10 | `lua_gettop` divides by 24; `index2adr` writes env taint at +0x10 |
| TValue | size | 0x18 | `lua_gettop`, `index2adr` |
| GC header | tt / marked | 0x10 / 0x11 | `luaD_call` (`closure+0x12` is `isC`), `index2adr` |
| Table | flags / lsizenode | 0x12 / 0x13 | `luaH_get`, `luaV_settable` |
| Table | metatable / array / node | 0x18 / 0x20 / 0x28 | `luaH_get` reads `[table+40]`, `luaV_settable` reads `[table+24]` |
| Node | size / key / key.tt / next | 0x38 / 0x18 / 0x20 / 0x30 | `luaH_get`: `56 * index`, `[node+24]`, `[node+32]`, `[node+48]` |
| TString | tsv.hash / tsv.len | 0x14 / 0x18 | `luaH_get` reads `[key+20]` as the hash |
| CClosure | env / nupvalues | 0x20 / 0x13 | `index2adr` (environ branch) |
| CClosure | f | 0x30 | `luaD_call`: `*( *(ci->func) + 48 )` |
| CClosure | upvalue[0] | 0x38 | `index2adr` pseudo-index arithmetic |
| LClosure | p / upvals | 0x30 / 0x38 | same closure header |
| CallInfo | size | 0x38 | `(ci - base_ci) / 56` in `luaE_resetthread`, `luaD_callhook` |
| CallInfo | base / func / top / savedpc | 0x00 / 0x08 / 0x10 / 0x18 | `luaD_call`, `luaD_poscall` |
| CallInfo | nresults / tailcalls | 0x2C / 0x30 | `luaD_call`, `luaD_pcall` |
| lua_State | status / top / base / l_G / ci | 0x20 / 0x28 / 0x30 / 0x38 / 0x40 | `lua_gettop`, `index2adr`, `luaD_call` |
| lua_State | savedpc / stack_last / stack | 0x48 / 0x50 / 0x58 | `luaD_call`, `luaD_callhook` |
| lua_State | end_ci / base_ci | 0x60 / 0x68 | `luaE_resetthread`, `luaD_call` |
| lua_State | stacksize / size_ci | 0x70 / 0x74 | `luaD_call`, `luaE_resetthread` |
| lua_State | nCcalls / baseCcalls | 0x78 / 0x7A | `luaE_resetthread` |
| lua_State | hookmask / allowhook / hook | 0x7D / 0x7E / 0x88 | `luaD_callhook` |
| lua_State | **l_gt** | **0x90** | `index2adr` returns `L+144` for `LUA_GLOBALSINDEX` |
| lua_State | env / errorJmp / errfunc | 0xA8 / 0xD0 / 0xD8 | `index2adr`, `luaE_resetthread` |
| lua_State | sidecar pointer | 0xE0 | `sub_38D1020` = `*(L+0xE0)`, used across the engine |
| global_State | panic / l_registry | 0xB0 / 0xB8 | `index2adr`: registry is `*(L->l_G) + 184` |
| global_State | mainthread / uvhead / mt / tmname | 0xD0 / 0xD8 / 0x110 / 0x158 | struct arithmetic, `TM_N = 17` → size 0x1E0 |

## Consequences that explained earlier crashes

- The client calls a C function through `closure + 0x30`. The older header put
  `f` at 0x28, so the client read `upvalue[0].value` (zero) and called address
  `0` — the `#1 [C]: in function 'C'` / `call 0` crashes.
- The client's `CallInfo` is 56 bytes, not 40. The old layout made `nresults`
  and `tailcalls` land in the middle of the client's fields.
- The `lua_State` tail beyond 0xE0 is larger in the client (its `lua_newstate`
  allocates a 0x300 block and returns `block + 0x38`); everything the vendored
  Lua touches is at or below 0xE0, so 0xF0 remains sufficient.

## Re-running the checks

```
cl /TC /std:c17 /I lua-5.1 tests\luaabi\luaabi.c /link /SUBSYSTEM:CONSOLE
cl /TC /std:c17 /I lua-5.1 tests\luaabi\lua_call_test.c lua-5.1\*.c
```

`luaabi` prints the offset table; `lua_call_test` registers `C.AFK` through
`luaL_register` and runs `print(C.AFK())`, printing `hello` on success.
