# IDA-Fusion

Fast signature creator and scanner plugin for **IDA Pro 9.x** (built and checked against the 9.5 SDK, Windows x64).

Based on [senator715/IDA-Fusion](https://github.com/senator715/IDA-Fusion).

A **signature** is a short run of bytes taken from code, with the bytes that change between builds (addresses, offsets)
replaced by wildcards, e.g. `48 89 5C 24 10 55 57 41 56 48 8B EC`. If it matches exactly one place in the program, you
can find that place again in the next version of the program, in a loader, or in another tool. This plugin creates such
signatures, searches for them, and can print them in several formats.

Contents: [Quick start](#quick-start) · [The dialog](#the-dialog) · [Create a signature](#create-a-signature) ·
[Output formats](#output-formats) · [XREF signatures](#xref-signatures-when-the-function-itself-has-no-unique-start) ·
[Search a pattern](#search-a-pattern) · [How it works](#how-it-works) · [Build](#build) · [Tests](#tests)

---

## Quick start

1. Put the cursor on the first instruction of a function in the disassembly view.
2. Press **Ctrl-Alt-S** (or *Edit > Plugins > Fusion*), keep **Create** and tick the outputs you want, press **Run**.
3. The signature appears in the Output window and is copied to the clipboard.

Right-click in the disassembly view also gives a **Fusion** submenu with the same actions, one output each.

## The dialog

Everything you choose is remembered between IDA sessions.

**Action** (pick one)

| Action | What it does |
|---|---|
| Create | Signature for the instruction under the cursor, or for the selected instructions. |
| Search for a pattern in the database | Asks for a pattern and finds every place that matches it. |
| Signatures for the XREFs to this function (call sites) | One signature per place that calls this function. See [XREF signatures](#xref-signatures-when-the-function-itself-has-no-unique-start). |

**Outputs** (tick any number; only what is ticked is printed and copied)

Signature (IDA style), Signature (CODE style), and the hashes FNV-1a (32 bit), CRC-32, XXH32, XXH64, XXH128.
One ticked output is copied as it is; several are copied one per line with their name in front.

**Options**

| Option | Meaning |
|---|---|
| Wildcard 32 bit displacements | `[reg+disp32]` offsets (struct member offsets) become wildcards. On by default. |
| Wildcard 32/64 bit immediates | Large constants in instructions become wildcards. Off by default. |
| Only scan executable segments (faster) | Data segments are not read and not searched. See [How it works](#how-it-works). |
| Stay inside the function | A signature is never extended past the end of its function. On by default: a signature that runs into the next function breaks as soon as the compiler reorders functions. |
| IDA style - use ?? as wildcard | Write `??` instead of `?`. |
| CODE style - always append the mask | Always add the `xx??` mask to CODE style signatures. |

## Create a signature

Starting at the cursor, instructions are added one by one until the bytes occur **nowhere else** in the scanned
segments. The result tells you what you got:

```
[Fusion] Signature for 0x180001008 (12 bytes, 5 instructions, 0.023s)
[Fusion] IDA   : 48 89 5C 24 10 55 57 41 56 48 8B EC
[Fusion] Unique
```

- **Unique**: it matches only this address. This is checked against everything the plugin scanned (all segments, or the
  executable ones with the option above).
- **NOT unique: N other matches**: the signature could not be made unique (identical stubs, or it hit the end of the
  function with *Stay inside the function*). Do not use it without checking.
- **Selection**: with instructions selected, the signature covers exactly those instructions and nothing is trimmed,
  because you picked the bytes. It reports whether it is unique.

**Which bytes become wildcards:** the 32 bit offset of calls and jumps, RIP-relative and absolute addresses, offset
operands, and optionally displacements and immediates (see Options). Short 8 bit jumps and small constants stay fixed.

## Output formats

| Format | Example | Notes |
|---|---|---|
| IDA style | `48 8B ? ? ? 89 5C 24 08` | `?` marks a wildcard byte (`??` with the option). Paste into IDA's binary search. |
| CODE style | `\x48\x8B\x00\x00\x00\x89\x5C\x24\x08` | `\x00` stands for a wildcard. If the signature contains a **real** `00` byte, the mask is added automatically (`... xx???xxxx`), otherwise that `00` would be read as a wildcard. |
| FNV-1a, CRC-32, XXH32 | `0xBB86B11C` | 32 bit hash over the signature bytes. |
| XXH64 | `0x8CB841DB40E6AE83` | 64 bit hash. |
| XXH128 | `0xDA472186EE4A7E1309A05FDB3337A36E` | 128 bit hash. |

Wildcards are hashed as `00`, so a hash stays the same when only addresses change between builds. A hash **cannot be
searched for**; it is one way and has no bytes in it.

## XREF signatures: when the function itself has no unique start

Some functions begin with bytes that occur all over the program (`push rbx; sub rsp, 20h`), so no signature of the
function start is unique. Then use a place that **calls** the function instead.

Choose **Signatures for the XREFs to this function** with the cursor anywhere in the function. Every call or jump to
it gets a signature that starts at the call instruction and is extended until it is unique:

```
[Fusion] 1 XREF(s) to 0x180001008
[Fusion] XREF 1  call site 0x18011AEC8 in LdrpInitializeExecutionOptions
[Fusion]   signature: E8 ? ? ? ? 85 C0 78 17 44 39 64 24 50
[Fusion]   resolve: target = match + 5 + int32 at (match + 1)   -> 0x180001008 (checked, this is the function)
[Fusion]   C++: const std::uintptr_t target = match + 5 + static_cast<std::uintptr_t>(*reinterpret_cast<const std::int32_t*>(match + 1));
```

The list is sorted shortest first; the shortest is copied.

**Important: the signature finds the call site, not the function.** `E8 ? ? ? ?` is a `call` whose four wildcard bytes
hold the distance to the function. To get the function you do one more step after the scan:

```
function = match + instruction_size + (signed 32 bit value at match + rel_offset)
```

`instruction_size` and `rel_offset` are in the `resolve:` line (for `E8` call and `E9` jump: 5 and 1).

Worked example with the numbers above. The scan finds the call site `match = 0x18011AEC8`. Behind the `E8` the
four bytes are `3B 61 EE FF`, which is the signed value `0xFFEE613B = -0x119EC5`:

```
0x18011AEC8 + 5 + (-0x119EC5) = 0x180001008      <- the function
```

In C++ the plugin prints the step as a line you can paste (`C++:` in the output). `match` is the address your own
pattern scanner returned, as a `std::uintptr_t`:

```cpp
const std::uintptr_t match  = find_pattern(module_base, "E8 ? ? ? ? 85 C0 78 17 44 39 64 24 50");
const std::uintptr_t target = match + 5 + static_cast<std::uintptr_t>(*reinterpret_cast<const std::int32_t*>(match + 1));
```

The address stays an integer; only the read of the 32 bit distance goes through a pointer. A negative distance
becomes a large unsigned number, and adding it wraps around to the right address, so backward calls work too.
There are no C style casts. The line is checked by compiling it with `/W4 /WX` and running it on a backward and a forward call.

In IDAPython:

```python
import ida_bytes

def resolve(match, insn_size=5, rel_offset=1):
    rel = ida_bytes.get_dword(match + rel_offset)
    if rel & 0x80000000:
        rel -= 1 << 32            # the value is signed
    return match + insn_size + rel
```

Things to know:

- **Direct calls and jumps only.** Calls through a pointer (`call [rip+x]`) have no encoded distance; the plugin says
  "cannot be resolved this way" for those. A function that is only called through a **vtable** has no code XREFs at all;
  the plugin reports the data references instead (sign the vtable entry or a direct caller).
- **Other instruction forms** have other numbers. A near conditional jump (`0F 8x`) is size 6 with the value at +2.
  Always take `instruction_size` and `rel_offset` from the `resolve:` line.
- **The caller has to survive updates.** The signature stays valid only as long as the code around the call stays the
  same. Pick a caller that is unlikely to change.
- The signature is created with *Stay inside the function*: it only uses bytes of the calling function.

## Search a pattern

*Search for a pattern in the database* (dialog) or *Fusion > Search for signature...* (right-click menu) asks for a
pattern, scans the database and lists every match in the Output window. With **exactly one** match it jumps there;
with several it stays where it is.

Accepted notations:

- IDA style: `48 8B ? ? 05` or `48 8B ?? ?? 05`
- CODE style: `\x48\x8B\x00\x00\x05`, optionally with a mask: `\x48\x8B\x00\x00\x05 xx??x`
  (without a mask, `\x00` is a wildcard)
- plain hex: `488B000005`, or `0x48, 0x8B, 0x00`; also pasted C arrays (`{ 0x48, 0x8B };`) and Python `b"..."`

## How it works

The loaded segments are read into memory once and **kept**, so the second search or signature does not read the
database again. Anything that changes bytes or segments (patching, rebasing, new or removed segments) throws the copy
away; a database above 512 MB is not kept. A search is then a plain memory scan: it anchors on the least common byte
of the pattern, and large images are scanned by several threads. Creating a signature scans once for the first
instruction and afterwards only re-checks the remaining candidates for each added instruction.

Reading the database through IDA (`get_bytes`) is the slow part (roughly 50 MB/s, not parallelisable), so use
**Only scan executable segments** when you only look for code.

## Build

Requirements: CMake 3.25+, Visual Studio 2022 or newer with the C++ tools (MSVC), and the
[IDA SDK](https://github.com/HexRaysSA/ida-sdk) (tag `v9.5.0-release` or newer).

```bat
git clone --branch v9.5.0-release https://github.com/HexRaysSA/ida-sdk.git C:\ida-sdk
set IDASDK=C:\ida-sdk
cmake -B build -G Ninja
cmake --build build
```

The plugin (`fusion.dll`) ends up in `%IDASDK%\src\bin\plugins`; set `IDABIN` to choose another folder. Copy it to
`%APPDATA%\Hex-Rays\IDA Pro\plugins` (or the `plugins` folder of your IDA installation) while IDA is closed.

The plugin has to be built with MSVC; MinGW builds are not ABI compatible with IDA.

## Tests

- `tests/test_fusion.cpp`: parser, formatter, hashes, scanner and the dialog string (no IDA needed; compile it together
  with `pattern.cpp` and the SDK include path).
- `tests/bench.cpp`: scan speed on a large real binary (no IDA needed): 333 MB in 5 to 26 ms per pattern.
- `tests/headless.cpp`: opens a real binary with idalib, creates a signature for every function, checks with an
  independent scan that each "unique" signature matches exactly its function, and does the same for the XREF
  signatures including the `resolve` formula above.

```bat
cmake -B build -G Ninja -DFUSION_BUILD_TESTS=ON
cmake --build build
set IDADIR=C:\Program Files\IDA Professional 9.5
set PATH=%IDADIR%;%PATH%
%IDABIN%\fusion_headless.exe C:\path\to\binary.exe 1000
```

(`fusion_headless.exe` is written to `%IDABIN%`, by default `%IDASDK%\src\bin`.)

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 seoulxss. Based on
[senator715/IDA-Fusion](https://github.com/senator715/IDA-Fusion) (Apache-2.0). Bundles
[xxHash](https://github.com/Cyan4973/xxHash) 0.8.3 (BSD-2-Clause, `third_party/xxhash`).
