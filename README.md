# Starburst UDRL-VS

User-Defined Reflective Loader development kit for Starburst, built on the [Stardust](https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/) PIC shellcode framework.

## Structure

```
Starburst.UDRL-VS/
├── Starburst.UDRL-VS.sln      VS2026 solution
├── Makefile                    Top-level build orchestrator
├── common/                     Shared headers (NT internals, beacon API, macros)
│   └── include/
├── tests/                      Unit tests and debug tools
│   ├── Makefile                Builds and runs all tests (gcc)
│   ├── include/
│   │   ├── test.h              Minimal test assertion framework
│   │   └── mock_pe.h           PE structures + Win32 mocks for Linux
│   ├── test_helpers.c          SectionToProtect, FindTextSection, GenerateRc4Key
│   ├── test_pe_ops.c           PE parsing, mapping, relocs, userdata
│   ├── test_mask_ops.c         XOR, dispatch, full cycle, erase, multi-region
│   └── debug/
│       ├── debug.h             Debug instrumentation macros (UDRL_LOG, hexdump, etc.)
│       ├── loader_validate.c   Post-load PE validation tool (7 checks)
│       └── mask_validate.c     Mask roundtrip validation tool (6 tests)
├── loader/                     Reflective DLL loader (PIC shellcode)
│   ├── loader.vcxproj          VS2026 project
│   ├── makefile                MinGW cross-compilation
│   ├── asm/x64/Stardust.asm    NASM entry point
│   ├── include/                Loader headers
│   ├── scripts/                Linker script, shellcode extractor
│   └── src/                    Loader source (Main.c = reflective loader)
├── mask/                       Sleepmask-VS (BOF/COFF object)
│   ├── mask.vcxproj            VS2026 project
│   ├── Makefile                MinGW cross-compilation
│   ├── include/                Sleepmask headers + Beacon Gate
│   └── src/main.c              Sleepmask implementation
└── examples/                   Drop-in replacement examples
    ├── loader-stomp/Main.c     Module-stomping loader
    ├── loader-headerless/Main.c  Headerless loader (no PE headers in memory)
    ├── mask-timer/main.c       Timer-based sleep mask
    └── mask-erase/main.c       Erase mask (zero + restore from backup)
```

## Prerequisites

- **NASM**: assembler for the x64 entry point
- **MinGW-w64**: `x86_64-w64-mingw32-g++` / `x86_64-w64-mingw32-gcc`
- **Python 3** with `pefile`: shellcode extraction (`pip install pefile`)
- **Visual Studio 2026** (optional): IDE, IntelliSense, debugging

## Building

### Command Line (WSL / Linux / MSYS2)

```bash
# Build both loader and sleepmask (release)
make

# Build with debug symbols
make debug

# Clean all artifacts
make clean
```

### Visual Studio

Open `Starburst.UDRL-VS.sln`. Both projects are configured as Makefile projects that invoke the MinGW toolchain. Select **Debug|x64** or **Release|x64** and build (Ctrl+B).

## Components

### Loader (`loader/`)

Position-independent reflective DLL loader built with the Stardust framework. The entry flow is:

1. **`Stardust.asm`**: `Start` saves registers, aligns stack, calls `PreMain`
2. **`PreMain.c`**: resolves ntdll from PEB, allocates heap for the `INSTANCE` struct, patches the global pointer
3. **`Main.c`**: the reflective loader:
   - Resolves kernel32 + ntdll APIs via PEB walking + custom hashing
   - Allocates `CUSTOM_DATA` for stomp region tracking (beacon + sleepmask + BOF)
   - Parses PE headers, maps sections into a single contiguous allocation
   - Resolves IAT via `ResolveIAT()` (ordinal + name imports, `LdrLoadDll`-based)
   - Processes relocations via `ProcessRelocations()` (DIR64 bitfield-based)
   - Sets `.text` executable via `NtProtectVirtualMemory`
   - Populates `USER_DATA` with version, `CUSTOM_DATA` pointer, and `ALLOCATED_MEMORY` regions
   - Three-call DllMain: `DLL_BEACON_USER_DATA` → `DLL_PROCESS_ATTACH` → `DLL_BEACON_START`

#### Configuration (compile-time defines in `makefile`)

| Define | Default | Description |
|--------|---------|-------------|
| `LOAD_MODE` | `0` | `0` = VirtualAlloc, `1` = Module Stomp |
| `STOMP_DLL` | `L"dbghelp.dll"` | Sacrificial DLL for module stomping |
| `FREE_LOADER` | `1` | Free the loader's initial allocation after loading |

### Sleepmask (`mask/`)

Compiled as a COFF object (`.o`) loaded by the Starburst agent at init. Called each sleep cycle to encrypt/decrypt the agent image in memory.

- **Beacon Gate path** (`bMask = FALSE`): dispatches the queued API call directly
- **Sleep mask path** (`bMask = TRUE`): XOR-encrypts all beacon memory regions, executes the queued sleep call, then XOR-decrypts to restore

### UDRL_USER_DATA

The `UDRL_USER_DATA` struct (defined in `loader/include/UserData.h`) bridges the loader and the agent:

| Field | Purpose |
|-------|---------|
| `magic` | `0x5442525354` ("STRBT"), validation sentinel |
| `version` | Starburst version (`STARBURST_VERSION`, currently `0x010400` = 1.4.0) |
| `load_type` | How the agent was loaded (VirtualAlloc / Module Stomp) |
| `agent_base` / `agent_size` | Location of the reflectively loaded agent image |
| `loader_base` / `loader_size` | Location of the loader shellcode allocation |
| `stomped_module` | Handle to the sacrificial DLL (module stomp only) |
| `stomped_text_base` / `stomped_text_size` | Stomped `.text` section location (module stomp only) |
| `regions[]` | Up to 8 `UDRL_REGION` entries (see below) |
| `region_count` | Number of populated entries in `regions[]` |
| `rc4_key[16]` | RDTSC-derived key for sleep-time encryption |
| `custom[32]` | Opaque scratch space; stores a `PCUSTOM_DATA` pointer for stomp region tracking |

#### UDRL_REGION / UDRL_SECTION

Each `UDRL_REGION` describes a top-level memory allocation with up to 4 nested `UDRL_SECTION` entries for granular per-section control (mirrors CS `ALLOCATED_MEMORY_REGION` / `ALLOCATED_MEMORY_SECTION`):

```
UDRL_REGION
├── purpose        UDRL_PURPOSE_AGENT_IMAGE / _SLEEPMASK_MEMORY / _BOF_MEMORY
├── alloc_base     Base of the allocation
├── region_size    Total size
├── section_count  Number of populated sections
└── sections[4]
    ├── label      UDRL_LABEL_TEXT / _DATA / _RDATA / _BUFFER / _NONE
    ├── base       Section base address
    ├── size       Section size
    └── protect    Current memory protection (PAGE_*)
```

The default loader populates 3 regions: the agent image (with `.text` and `.data` sections), sleepmask buffer, and BOF buffer. Users can add more regions/sections for finer sleep mask control.

## Integration with Starburst Builder

The kit produces artifacts compatible with the Starburst builder's UDRL-VS flow:

1. ZIP the entire `Starburst.UDRL-VS/` directory
2. In the Mythic payload builder, set `loader_type = udrl-vs`
3. Upload the ZIP as `udrl_vs_file`
4. The builder compiles `loader/` to produce PIC shellcode, compiles `mask/` for the sleepmask COFF, then concatenates the loader with the wrapped agent DLL

The final binary layout is: `[loader shellcode] + [4-byte DLL length] + [DLL bytes]`. For a Crystal Palace-based UDRL, use the separate `Starburst.CrystalKit` [project](https://github.com/Whispergate/Starburst.CrystalKit).

When `loader_type = udrl-vs` is selected, the sleep mask option is hidden. The builder automatically compiles and embeds the mask from the kit's `mask/` directory.

## Stardust Framework Reference

### API Resolution

APIs are resolved at runtime via PEB module walking + custom hashing (`key=7759, shift=6`):

```c
Instance.Win32.pVirtualAlloc = LdrFunction( Instance.Modules.Kernel32, HASH_STR("VirtualAlloc") );
```

### Compile-time Hashing

Use `HASH_STR()` from `Constexpr.h` for compile-time hashes:

```c
#define H_MODULE_NTDLL      0xc2ba439d
#define H_MODULE_KERNEL32   0xf232005a
```

### Adding New APIs

1. Add `API_ENTRY( FunctionName, ModuleName )` to `API_LIST` in `common/include/Shared.h`
2. If the module isn't `Ntdll` or `Kernel32`, add `DLL_ENTRY( ModuleName )` to `DLL_LIST`
3. The X-macro pattern auto-generates the `INSTANCE` struct fields and resolution in `ResolveApis()`
4. Use `API( FunctionName )` to call it anywhere with `STARDUST_INSTANCE` in scope

## Examples

The `examples/` directory contains drop-in replacements for the base loader and mask. Copy the example source file over the corresponding base file to use it.

### loader-stomp

Module-stomping reflective loader. Loads the agent DLL by stomping over a legitimate system DLL's `.text` section rather than allocating fresh executable memory. The sacrificial DLL defaults to `amsi.dll` (configurable via `STOMP_DLL`). Populates two UDRL_USER_DATA regions: the stomped `.text` and the user data allocation.

**Usage:** Copy `examples/loader-stomp/Main.c` to `loader/src/Main.c`.

### loader-headerless

Headerless reflective loader. Maps PE sections at their normal virtual addresses but never writes the DOS/NT headers into the allocation. The header region stays zeroed (from VirtualAlloc) and is marked PAGE_NOACCESS. Memory scanners walking allocation bases for MZ/PE signatures will not find this image.

**Usage:** Copy `examples/loader-headerless/Main.c` to `loader/src/Main.c`.

### mask-timer

Timer-based sleep mask. Instead of dispatching the queued WaitForSingleObject/Sleep call directly, creates a waitable timer set to the same duration and blocks on it. The thread waits on a timer object rather than a thread handle, producing a different call stack for anyone inspecting NtWaitForSingleObject hooks.

**Usage:** Copy `examples/mask-timer/main.c` to `mask/src/main.c`.

### mask-erase

Erase sleep mask. During sleep, backs up each beacon memory region to a heap allocation, zeros the original memory byte-by-byte, executes the sleep call, then restores from the backup. During sleep there is no beacon code in the original memory regions, only zeroes.

**Usage:** Copy `examples/mask-erase/main.c` to `mask/src/main.c`.

## Testing

The `tests/` directory contains unit tests and debug tools that validate the loader and mask logic without needing a Windows target or Mythic server.

### Unit Tests

Tests compile natively on Linux with `gcc`. They use `mock_pe.h` to provide PE structures and mock Win32 APIs (`VirtualAlloc` → `calloc`, `VirtualProtect` → no-op, `__rdtsc` → deterministic counter).

```bash
cd tests
make test    # compile and run all 57 tests
make clean   # remove binaries
```

Three test binaries:

| Binary | Tests | Coverage |
|--------|-------|----------|
| `test_helpers` | 18 | SectionToProtect (all 8 flag combos), FindTextSection (valid/invalid PE, multi-section), GenerateRc4Key (nonzero, byte order, uniqueness) |
| `test_pe_ops` | 22 | PE header parsing, section mapping, DIR64 relocations, zero-delta no-op, UDRL_USER_DATA population (VirtualAlloc + module stomp), headerless variant, full load cycle |
| `test_mask_ops` | 17 | XOR roundtrip, zero-key identity, key wrapping, dispatch (0-arg, 2-arg, NULL), full sleep mask cycle, beacon gate path, erase mask, multi-region, RC4 key usage |

### Debug Tools

Debug tools cross-compile with MinGW for Windows. Include `debug.h` with `-DUDRL_DEBUG` to instrument your loader or mask.

**`debug.h`** - drop-in instrumentation header:
- `UDRL_LOG`, `UDRL_LOG_OK`, `UDRL_LOG_ERR`, `UDRL_LOG_INFO` macros
- `udrl_hexdump()` - hex dump with ASCII column (capped at 256 bytes)
- `udrl_validate_pe()` - checks DOS/NT signatures, logs section count and entry RVA
- `udrl_validate_userdata()` - validates magic, load_type, regions, rc4_key
- `udrl_log_sections()`, `udrl_log_relocs()`, `udrl_log_imports()` - trace loader operations
- All compile to no-ops when `UDRL_DEBUG` is not defined

**`loader_validate.c`** - post-load validation tool (7 checks):
```bash
x86_64-w64-mingw32-gcc -DUDRL_DEBUG -o loader_validate.exe debug/loader_validate.c
loader_validate.exe 0x<agent_base_hex>
```
Checks: UDRL_USER_DATA fields, PE header integrity, section protections (`VirtualQuery`), IAT resolution, relocations, region bounds, module stomp consistency.

**`mask_validate.c`** - mask roundtrip validation tool (6 tests):
```bash
x86_64-w64-mingw32-gcc -DUDRL_DEBUG -o mask_validate.exe debug/mask_validate.c
mask_validate.exe
```
Runs 6 roundtrip tests (16-byte, 4096-byte, multi-region, all-zero, all-0xFF, 1-byte guard) with 32-byte guard zones on each buffer for overflow detection. Accepts a custom mask function pointer via `udrl_mask_validate()`.

## Development Workflow

1. Open the VS2026 solution for IntelliSense and code navigation
2. Edit `loader/src/Main.c` for loader logic, `mask/src/main.c` for sleep mask behavior
3. Run `make test` in `tests/` to validate changes
4. Build via `make` or VS2026's Build command
5. ZIP and upload to Mythic as a custom UDRL for end-to-end testing
