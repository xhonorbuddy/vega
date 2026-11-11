# vega

An x64 manual mapper: it loads a DLL from disk into an already-running process
without going through `LoadLibrary`, and it can take that DLL back out again.

The mapped image is rebuilt in the target's memory, so the module never appears
in the target's module list, the file is never touched by the target's linker,
and imports are reconstructed by hand.

## Build

```
msbuild vega\vega.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `vega\x64\Release\vega.exe`.

## Usage

```
vega --process <name> --dll <path> [options]        map a DLL
vega --process <name> --unload [--module <name>]    unload a mapped DLL
vega --process <name> --list                        list mapped modules
```

Examples:

```
vega -p game.exe -d C:\mods\grid.dll
vega -p game.exe --unload --module grid.dll
vega -p game.exe --list
```

| Option | Meaning |
| --- | --- |
| `-p`, `--process <name>` | Target process image name, e.g. `game.exe` |
| `-d`, `--dll <path>` | DLL to map |
| `-u`, `--unload` | Unload instead of map |
| `-m`, `--module <name>` | Module name for `--unload` (default: DLL file name) |
| `--list` | List modules this tool mapped into the process |
| `--pid <pid>` | Target by PID instead of name |
| `--wait <seconds>` | Wait for the process to appear |
| `--timeout <ms>` | Timeout per in-target call (default 60000) |
| `--no-tls` | Skip TLS callbacks |
| `--no-exceptions` | Skip unwind table registration |
| `--no-preferred` | Ignore the DLL's preferred base (force relocation) |
| `--no-entry` | Map without calling `DllMain` (debugging aid) |
| `--force` | Unload even if a thread is still executing inside the image |
| `-q`, `--quiet` | Errors only |
| `-h`, `--help` | Help |

Experimental diagnostics: `--loader-entry` (link the image into `PEB->Ldr`),
`--ddag-state <n>` (Ddag node state for that entry), `--hijack` (run in-target
calls on an existing thread instead of a new one).

Exit codes: `0` success, `1` usage, `2` mapping failed, `3` unload failed.

## What the loader does

1. **Validate** the PE: DOS/NT signatures, x64 machine, `SizeOfImage`,
   section table, and that every section lies inside the file and the image.
2. **Allocate** `SizeOfImage` in the target at the DLL's preferred base when
   possible; otherwise anywhere and relocations are applied.
3. **Build the image** in a local buffer: headers plus each section, zeroed
   gaps, bounded by both `SizeOfRawData` and `VirtualSize`.
4. **Relocate**: `ABSOLUTE`, `HIGH`, `LOW`, `HIGHLOW`, `DIR64`; `HIGHADJ` and
   unknown types are skipped rather than thrown on.
5. **Reconstruct imports** by resolving each thunk's export *RVA* against the
   local copy of the dependency and adding the target's module base. This
   handles forwarded exports (followed recursively), ordinal imports, API set
   names (`api-ms-win-*`), and delay-load descriptors. Import timestamps are
   cleared so stale bound addresses are not trusted.
6. **Write** the whole image, then set each section's protection from its
   characteristics; headers become read-only.
7. **Register exception handling**: the image is spliced into ntdll's
   `KiUserInvertedFunctionTable` (the table `RtlPcToFileHeader` binary-searches)
   through the loader's own insertion routine, and a dynamic function table is
   registered with `RtlAddFunctionTable`. Together those make `RtlPcToFileHeader`
   and `RtlLookupFunctionEntry` resolve frames in the mapped DLL, so both SEH
   (`__try`/`__except`) and C++ `throw`/`catch` work. Both are verified
   end-to-end by the test suite.
8. **Run TLS callbacks** with `(hinstDLL, DLL_PROCESS_ATTACH, nullptr)`.
9. **Call `DllMain`** through the entry point and fail the map if it returns
   `FALSE`.
10. **Record** a control block next to the image so a later run can find and
    unload the module without external state.

Unload reverses it: `DllMain(DLL_PROCESS_DETACH)`, TLS detach callbacks,
`RtlDeleteFunctionTable`, removal from the loader PC index, then release the
image and the record.

## How C++ exceptions are made to work

MSVC's C++ handler resolves a code address to its image base with
`RtlPcToFileHeader`, and that function ignores the `PEB->Ldr` lists — it
binary-searches `ntdll!KiUserInvertedFunctionTable`, a sorted array of
`{exception_table, image_base, size, flags}` entries living in ntdll's
read-only image data. A manually mapped image is not in it, so `throw` inside
the DLL used to terminate the process even though unwind data was registered.

Vega adds the image to that table by calling the loader's own insertion routine
(`ntdll+0x5AEA4` on this build), which takes `(ImageBase, SizeOfImage)` and
handles locking, sorting and capacity growth. The RVA is verified against the
routine's prologue before the call; on an unknown ntdll build the tool logs a
warning and continues with SEH only instead of corrupting the loader. Unload
splices the entry back out and restores the array's count.

Note: `GetModuleHandle` by name still returns null for a mapped image (that is
a different loader index); use the base reported by the tool.

## Robustness notes

- All PE parsing is bounds-checked before it is trusted.
- A mapping that fails part-way frees everything it allocated; nothing is left
  behind in the target. The exception is a failure while the entry point is
  still running on a thread (a modal dialog in `DllMain`, for example): the
  image is deliberately left mapped, with its record, so the target is not
  destroyed and the module can be unloaded once that thread returns.
- Unload checks every target thread before touching anything: if one is
  executing inside the image, or has the image's return address on its stack
  (a call blocked in `Sleep`/`MessageBox` looks like that), it refuses with a
  clear message instead of freeing memory out from under a live stack
  (`--force` overrides).
- A `DllMain` that blocks is not torn off its stack. In-target calls run through
  a self-restoring stub, so a timed-out call (a modal dialog) keeps running on
  its thread and returns normally when dismissed; the image is left mapped and
  recorded, and can be unloaded afterwards. The one cost is that a timed-out
  call leaks its single page of stub memory rather than risk freeing code that
  may still execute.
- In-target calls time out on a real clock (`GetTickCount64`), not on a count of
  `Sleep(5)` iterations.
- In-target calls run on a new thread, with a per-call timeout. A hung call is
  aborted instead of hanging the loader.
- `OpenProcess` degrades from `PROCESS_ALL_ACCESS` through the minimal rights
  set the target will grant, instead of failing on access-denied.
- Module lookup walks the target's PEB loader list first and only falls back to
  a Toolhelp snapshot, so it still works with limited query rights.
- Dependencies that are not loaded in the target are mapped recursively, with
  depth and cycle protection.

## Known limitations

- **`thread_local` / `__declspec(thread)` storage is not supported.** Loading
  a TLS slot needs loader cooperation. TLS *callbacks* are supported.
- `GetModuleHandle` by name returns null for the mapped module, and
  `GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)` does not see it;
  `RtlPcToFileHeader` and C++ exception dispatch do. Use the base reported by
  the tool when the DLL needs its own module handle.
- **`--loader-entry` is experimental.** Linking the image into the target's
  `PEB->Ldr` lists (load order + memory order, with a fabricated Ddag node so
  ntdll's thread initialization stops dereferencing a null graph node) keeps the
  process stable, but Windows 11 name/address lookups are served from a separate
  loader index, so it buys nothing beyond what the PC index registration in
  step 7 already provides. It is off by default.
- The loader PC index helper is an ntdll internal at a fixed RVA on this build
  (verified by prologue). If a future Windows build moves it, C++ exceptions
  degrade to "not working" with a warning; SEH keeps working.
- x64 only, and the loader must be able to write into the target
  (same-user or elevated, depending on the target).
- Mapping system DLLs (kernel32, user32, ...) is supported only as a dependency
  fallback and is a bad idea in general; the test harness keeps to modules that
  are already loaded.

## Tests

```
powershell -ExecutionPolicy Bypass -File tests\run_tests.ps1
```

The suite builds `tests/target` (a long-running process), maps
`tests/sample` (TLS callback, delay-load import, ordinary imports), asserts on
what the payload wrote from inside the target, then unloads it and asserts on
the detach path. `tests/minimal` is a CRT-light payload used to isolate loader
bugs from payload bugs.
