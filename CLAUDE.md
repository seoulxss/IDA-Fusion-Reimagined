# IDA-Fusion

IDA Pro 9.x plugin (C++17, Windows/MSVC): creates unique byte signatures from code, outputs them as IDA/CODE style
or as hashes (FNV-1a, CRC-32, XXH32/64/128), and searches the database for patterns. Built and checked against the
IDA 9.5 SDK.

## Layout

| File | What |
|---|---|
| `main.cpp` | plugin (`plugmod_t`), actions, context menu, dialog handling, snapshot cache |
| `dialog_form.h` | `ask_form()` format string, no IDA includes so the tests can check it |
| `fusion.h` | declarations of everything below (one header for both .cpp files) |
| `fusion.cpp` | signature generation, wildcards, capture of the database, clipboard (calls IDA) |
| `pattern.cpp` | parser, formatter, hashes, memory scanner (**no IDA calls**, testable on its own) |
| `third_party/xxhash/` | vendored xxHash 0.8.3, header only |
| `tests/` | `test_fusion.cpp` (logic), `bench.cpp` (scan speed), `headless.cpp` (idalib, real database) |

## Build and test

SDK: the IDA SDK checkout (tag `v9.5.0-release` of https://github.com/HexRaysSA/ida-sdk); set `IDASDK` to its folder.
MSVC comes with Visual Studio 18 Community; CMake/Ninja are not installed system wide (`pip install cmake ninja`).
The CMake file finds MSVC itself, no developer prompt needed.

```
set IDASDK=...\ida-sdk-9.5
set IDABIN=%TEMP%\fusion_bin
cmake -B %TEMP%\fusion_build -G Ninja -DFUSION_BUILD_TESTS=ON
cmake --build %TEMP%\fusion_build
```

- Logic tests (no IDA): compile `tests/test_fusion.cpp` + `pattern.cpp` with `cl`, include path = SDK `src/include`,
  defines `__NT__ __EA64__ __X64__`.
- Real database, headless: `fusion_headless.exe <binary> <max_functions>` with `IDADIR` and `PATH` containing the
  IDA install directory. Use a **copy** of the binary in a scratch directory (idalib writes an `.i64` next to it).
  Expected on `notepad.exe`: 0 mismatches.
- The plugin has to be built with MSVC. A MinGW/clang-mingw build links but is not ABI compatible with IDA.
- Do not run GUI `ida.exe` from here: it asks for elevation, nobody answers, and the process hangs.

## Rules learned the hard way

- **`ask_form()` fails silently.** A label must not contain `:` or `#`. `tests/test_fusion.cpp` checks every item of
  `DIALOG_FORM` for that; keep the test green when you touch the dialog.
- **No `%/` form callback together with `BUTTON NO`.** IDA 9.5 crashed after the dialog closed (a jump through a
  dangling stack object, visible in the crash dump: no `fusion.dll` frame, call target below RSP). The dialog is
  plain radio and checkbox groups on purpose. Crash dumps are in `%LOCALAPPDATA%\CrashDumps` and can be read with
  the `minidump` Python package.
- **`pro.h` poisons libc functions** (`snprintf`, `getenv`, ...). Code in `pattern.cpp` must stay free of IDA
  includes' replacements; use plain C++ there, `qsnprintf`/`qgetenv` only in IDA-facing files.
- `get_bytes()` is slow (about 50 MB/s) and not thread safe. That is why the snapshot is cached between runs and
  dropped on `byte_patched` / segment events (`idb_watch_t` in `main.cpp`).
- Radio and checkbox groups take `ushort*`, not `int*`.
- Hashes cover the signature bytes with wildcards hashed as `00` (stable between builds). A hash cannot be searched.

## Shell gotcha

Backslashes in Python or bash heredocs passed through the tool layer get eaten or turned into real control
characters (`\n` became a newline in a C++ string, `\x` vanished, `\f` / `\t` / `\b` appeared in the README). For
files with `\n`, `\x...` or Windows paths use the Edit/Write tools, or write a script file first.

## Conventions

- Commit messages end with the `Co-Authored-By` line given by the harness. Branch is `main`, remote is `origin`.
- The project is called **IDA-Fusion** (plugin name "Fusion"), not "Enhanced". The folder name still says
  `IDA-Fusion-Enhanced-main`; renaming it is up to the user.
- Based on senator715/IDA-Fusion (the first commit is the original 2022 release); Apache-2.0.
