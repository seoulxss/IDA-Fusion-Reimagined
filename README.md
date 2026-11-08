# IDA-Fusion

Fast signature creator and scanner plugin for **IDA Pro 9.x** (built and checked against the 9.5 SDK).

Based on [senator715/IDA-Fusion](https://github.com/senator715/IDA-Fusion).

## Usage

Press **Ctrl-Alt-S** (or use *Edit > Plugins > Fusion*) in the disassembly view, or right-click and pick one of the
entries in the **Fusion** submenu.

The dialog has a checkbox per output: **Signature (IDA style)**, **Signature (CODE style)** and the hashes
**FNV-1a (32 bit)**, **CRC-32**, **XXH32**, **XXH64**, **XXH128**. Only what is ticked is printed and copied (one
output as is, several one per line with their name). The choice is remembered. **Run** creates, **Search pattern...**
searches (see below). The entries of the context menu create a single output each.

| Output | Example |
|---|---|
| IDA style | `48 8B ? ? ? 89 5C 24 08` |
| CODE style | `\x48\x8B\x00\x00\x00\x89\x5C\x24\x08` |
| Hashes | `0xBB86B11C`, `0x8CB841DB40E6AE83`, ... over the signature bytes. Wildcards are hashed as `00`, so the value stays the same between builds. |

### Search pattern

The button in the dialog (or *Fusion > Search for signature...* in the context menu) asks for a pattern, scans the
whole database, lists every match in the output window and jumps to the first one. Accepted notations:

- IDA style: `48 8B ? ? 05` or `48 8B ?? ?? 05`
- CODE style: `\x48\x8B\x00\x00\x05`, optionally with a mask: `\x48\x8B\x00\x00\x05 xx??x`
- plain hex: `488B000005` or `0x48, 0x8B, 0x00`; also pasted C arrays (`{ 0x48, 0x8B };`) and Python `b"..."`

A hash cannot be searched for (it is one way).

With a **selection**, the signature covers exactly the selected instructions and reports whether it is unique.

Wildcards: relative calls/jumps (rel32), RIP-relative and absolute addresses, offset operands, and (optional)
32 bit displacements and immediates. Without a mask, a `\x00` in a CODE style signature is a wildcard.

## How it works

All loaded segments are read into memory once per run. A search is then a plain memory scan, and generation scans
once for the first instruction and afterwards only re-checks the remaining candidates for each newly added
instruction, so it does not call IDA's binary search per instruction.

## Build

Requirements: CMake 3.25+, Visual Studio 2022 Build Tools (MSVC), and the
[IDA SDK](https://github.com/HexRaysSA/ida-sdk) (tag `v9.5.0-release` or newer).

```bat
git clone --branch v9.5.0-release https://github.com/HexRaysSA/ida-sdk.git C:\ida-sdk
set IDASDK=C:\ida-sdk
cmake -B build -G Ninja
cmake --build build
```

The plugin (`fusion.dll`) ends up in `%IDASDK%\src\bin\plugins`. Copy it to
`%APPDATA%\Hex-Rays\IDA Pro\plugins`. Set `IDABIN` to choose another output directory.

The plugin has to be built with MSVC; MinGW builds are not ABI compatible with IDA.

## Tests

- `tests/test_fusion.cpp`: parser, formatter and scanner, no IDA needed (compile with `pattern.cpp`).
- `tests/headless.cpp`: opens a real binary with idalib, generates a signature for every function and checks with an
  independent scan that each "unique" signature matches exactly its function.

```bat
cmake -B build -G Ninja -DFUSION_BUILD_TESTS=ON
cmake --build build
set IDADIR=C:\Program Files\IDA Professional 9.5
set PATH=%IDADIR%;%PATH%
%IDABIN%\fusion_headless.exe C:\path\to\binary.exe 1000
```

(`fusion_headless.exe` is written to `%IDABIN%`, by default `%IDASDK%\src\bin`.)

## License

Apache-2.0, see [LICENSE](LICENSE). Bundles [xxHash](https://github.com/Cyan4973/xxHash) 0.8.3 (BSD-2-Clause, `third_party/xxhash`).
