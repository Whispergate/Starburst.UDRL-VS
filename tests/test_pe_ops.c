/*
 * Unit tests for UDRL PE operations: LdrpImageHeader, LdrFunction,
 * section mapping, relocation processing, section protections,
 * UDRL_USER_DATA population, headerless loader variant, and full load cycle.
 *
 * Core logic is copied verbatim from loader/src/\*.
 * Tests use synthetic PEs from mock_pe.h.
 */

#include "test.h"
#include "mock_pe.h"

#define FUNC  /* PIC marker - no-op in test builds */

/* ========================================================================
 * Functions under test
 * ====================================================================== */

/* From loader/src/Utils.c */
FUNC static ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash = { 0 };
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Hash = H_MAGIC_KEY;
    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}

/* From loader/include/Constexpr.h */
CONSTEXPR ULONG ExprHashStringA(
    _In_ PCHAR String
) {
    ULONG Hash = { 0 };
    CHAR  Char = { 0 };

    Hash = H_MAGIC_KEY;

    if ( ! String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

#define HASH_STR( x ) ExprHashStringA( ( x ) )

/* From loader/src/Main.c */
FUNC static DWORD SectionToProtect( DWORD ch ) {
    BOOL x = !!( ch & IMAGE_SCN_MEM_EXECUTE );
    BOOL r = !!( ch & IMAGE_SCN_MEM_READ    );
    BOOL w = !!( ch & IMAGE_SCN_MEM_WRITE   );

    if ( x && w && r ) return PAGE_EXECUTE_READWRITE;
    if ( x && r      ) return PAGE_EXECUTE_READ;
    if ( x && w      ) return PAGE_EXECUTE_WRITECOPY;
    if ( x           ) return PAGE_EXECUTE;
    if ( w && r      ) return PAGE_READWRITE;
    if ( r           ) return PAGE_READONLY;
    if ( w           ) return PAGE_WRITECOPY;
    return PAGE_NOACCESS;
}

FUNC static VOID GenerateRc4Key( PBYTE Key ) {
    for ( int i = 0; i < 16; i += 4 ) {
        DWORD tick;
        tick = (DWORD)__rdtsc();
        Key[i]     = (BYTE)( tick );
        Key[i + 1] = (BYTE)( tick >> 8 );
        Key[i + 2] = (BYTE)( tick >> 16 );
        Key[i + 3] = (BYTE)( tick >> 24 );
        for ( volatile int j = 0; j < 100; j++ ) {}
    }
}

/* From loader/src/Ldr.c */
FUNC static PIMAGE_NT_HEADERS LdrpImageHeader(
    _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = C_PTR( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

/* From loader/src/Ldr.c */
FUNC static PVOID LdrFunction(
    _In_ PVOID Library,
    _In_ ULONG Function
) {
    PVOID                   Address    = { 0 };
    PIMAGE_NT_HEADERS       NtHeader   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
    SIZE_T                  ExpDirSize = { 0 };
    PDWORD                  AddrNames  = { 0 };
    PDWORD                  AddrFuncs  = { 0 };
    PWORD                   AddrOrdns  = { 0 };
    PCHAR                   FuncName   = { 0 };

    if ( ! Library || ! Function ) {
        return NULL;
    }

    if ( ! ( NtHeader = LdrpImageHeader( Library ) ) ) {
        return NULL;
    }

    ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
    AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
    AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {
        FuncName = C_PTR( U_PTR( Library ) + AddrNames[ i ] );

        if ( HashString( FuncName, 0 ) != Function ) {
            continue;
        }

        Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize )
        ) {
            __debugbreak();
        }

        break;
    }

    return Address;
}

/* ========================================================================
 * Helper: map a synthetic PE into a "mapped" buffer the way the loader does.
 * ====================================================================== */

static PBYTE map_test_pe(PBYTE raw, PIMAGE_NT_HEADERS *nt_out) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);

    DWORD image_size   = nt->OptionalHeader.SizeOfImage;
    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;
    WORD  num_sections = nt->FileHeader.NumberOfSections;

    PBYTE mapped = (PBYTE)calloc(1, image_size);
    if (!mapped) return NULL;

    MmCopy(mapped, raw, headers_size);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < num_sections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        MmCopy(
            mapped + sec[i].VirtualAddress,
            raw    + sec[i].PointerToRawData,
            sec[i].SizeOfRawData
        );
    }

    PIMAGE_DOS_HEADER mdos = (PIMAGE_DOS_HEADER)mapped;
    *nt_out = (PIMAGE_NT_HEADERS)(mapped + mdos->e_lfanew);

    return mapped;
}

/* ========================================================================
 * Helper: apply relocations the way the loader does (verbatim from Main.c).
 * ====================================================================== */

static void apply_relocations(PBYTE mapped, PIMAGE_NT_HEADERS nt, LONGLONG delta) {
    if (delta == 0) return;

    DWORD reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (!reloc_rva || !reloc_size) return;

    PIMAGE_BASE_RELOCATION reloc = C_PTR(mapped + reloc_rva);
    PBYTE reloc_end = (PBYTE)reloc + reloc_size;

    while ((PBYTE)reloc < reloc_end && reloc->SizeOfBlock) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < count; i++) {
            WORD type   = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;
            PBYTE patch = mapped + reloc->VirtualAddress + offset;

            switch (type) {
                case IMAGE_REL_BASED_DIR64:
                    *(PULONGLONG)patch += delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(PDWORD)patch += (DWORD)delta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(PWORD)patch += (WORD)(delta >> 16);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(PWORD)patch += (WORD)delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
            }
        }
        reloc = C_PTR((PBYTE)reloc + reloc->SizeOfBlock);
    }
}

/* ========================================================================
 * LdrpImageHeader tests
 * ====================================================================== */

static void test_ldr_image_header_valid(void) {
    TEST("LdrpImageHeader: valid PE returns correct NT headers");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_NT_HEADERS nt = LdrpImageHeader(pe);
    ASSERT_NOT_NULL(nt);
    ASSERT_EQ(nt->Signature, IMAGE_NT_SIGNATURE);
    ASSERT_EQ(nt->FileHeader.Machine, IMAGE_FILE_MACHINE_AMD64);
    ASSERT_EQ(nt->FileHeader.NumberOfSections, 2);

    free(pe);
    PASS();
}

static void test_ldr_image_header_bad_dos(void) {
    TEST("LdrpImageHeader: invalid DOS magic returns NULL");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    ((PIMAGE_DOS_HEADER)pe)->e_magic = 0xBEEF;
    ASSERT_NULL(LdrpImageHeader(pe));

    free(pe);
    PASS();
}

static void test_ldr_image_header_bad_nt(void) {
    TEST("LdrpImageHeader: invalid NT signature returns NULL");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    nt->Signature = 0xDEADDEAD;
    ASSERT_NULL(LdrpImageHeader(pe));

    free(pe);
    PASS();
}

/* ========================================================================
 * LdrFunction tests
 * ====================================================================== */

static void test_ldr_function_resolve_alpha(void) {
    TEST("LdrFunction: resolves FuncAlpha by hash");
    DWORD sz;
    PBYTE pe = build_test_pe_with_exports(&sz);
    ASSERT_NOT_NULL(pe);

    ULONG hash = HASH_STR("FuncAlpha");
    PVOID addr = LdrFunction(pe, hash);

    ASSERT_NOT_NULL(addr);
    ASSERT_EQ((ULONG_PTR)addr, (ULONG_PTR)pe + 0x1000);

    free(pe);
    PASS();
}

static void test_ldr_function_resolve_beta(void) {
    TEST("LdrFunction: resolves FuncBeta by hash");
    DWORD sz;
    PBYTE pe = build_test_pe_with_exports(&sz);
    ASSERT_NOT_NULL(pe);

    ULONG hash = HASH_STR("FuncBeta");
    PVOID addr = LdrFunction(pe, hash);

    ASSERT_NOT_NULL(addr);
    ASSERT_EQ((ULONG_PTR)addr, (ULONG_PTR)pe + 0x1020);

    free(pe);
    PASS();
}

static void test_ldr_function_unknown_hash(void) {
    TEST("LdrFunction: unknown hash returns NULL");
    DWORD sz;
    PBYTE pe = build_test_pe_with_exports(&sz);
    ASSERT_NOT_NULL(pe);

    PVOID addr = LdrFunction(pe, 0xDEADBEEF);
    ASSERT_NULL(addr);

    free(pe);
    PASS();
}

static void test_ldr_function_null_library(void) {
    TEST("LdrFunction: NULL library returns NULL");
    ASSERT_NULL(LdrFunction(NULL, 0x12345678));
    PASS();
}

static void test_ldr_function_zero_hash(void) {
    TEST("LdrFunction: zero hash returns NULL");
    DWORD sz;
    PBYTE pe = build_test_pe_with_exports(&sz);
    ASSERT_NOT_NULL(pe);

    ASSERT_NULL(LdrFunction(pe, 0));

    free(pe);
    PASS();
}

/* ========================================================================
 * PE header parsing tests
 * ====================================================================== */

static void test_pe_dos_valid(void) {
    TEST("PE parsing: valid DOS signature");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    ASSERT_EQ(dos->e_magic, IMAGE_DOS_SIGNATURE);

    free(pe);
    PASS();
}

static void test_pe_nt_valid(void) {
    TEST("PE parsing: valid NT signature");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    ASSERT_EQ(nt->Signature, IMAGE_NT_SIGNATURE);

    free(pe);
    PASS();
}

static void test_pe_section_count(void) {
    TEST("PE parsing: 2 sections");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    ASSERT_EQ(nt->FileHeader.NumberOfSections, 2);

    free(pe);
    PASS();
}

static void test_pe_image_base(void) {
    TEST("PE parsing: ImageBase = 0x180000000");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    ASSERT_EQ(nt->OptionalHeader.ImageBase, 0x180000000ULL);

    free(pe);
    PASS();
}

static void test_pe_size_of_image(void) {
    TEST("PE parsing: SizeOfImage = 0x3000");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    ASSERT_EQ(nt->OptionalHeader.SizeOfImage, 0x3000);

    free(pe);
    PASS();
}

static void test_pe_section_headers_readable(void) {
    TEST("PE parsing: section headers have correct names");
    DWORD sz;
    PBYTE pe = build_test_pe(&sz);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    ASSERT_TRUE(memcmp(sec[0].Name, ".text", 5) == 0);
    ASSERT_TRUE(memcmp(sec[1].Name, ".data", 5) == 0);

    free(pe);
    PASS();
}

/* ========================================================================
 * Section mapping tests
 * ====================================================================== */

static void test_map_headers_copied(void) {
    TEST("Section mapping: headers copied to mapped base");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped;
    ASSERT_EQ(dos->e_magic, IMAGE_DOS_SIGNATURE);

    PIMAGE_NT_HEADERS mnt = (PIMAGE_NT_HEADERS)(mapped + dos->e_lfanew);
    ASSERT_EQ(mnt->Signature, IMAGE_NT_SIGNATURE);

    free(mapped);
    free(raw);
    PASS();
}

static void test_map_text_section(void) {
    TEST("Section mapping: .text at VA 0x1000, filled with 0xCC");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    for (int i = 0; i < 16; i++) {
        ASSERT_EQ(mapped[0x1000 + i], 0xCC);
    }

    free(mapped);
    free(raw);
    PASS();
}

static void test_map_data_section(void) {
    TEST("Section mapping: .data at VA 0x2000, filled with 0xAA");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    for (int i = 0; i < 16; i++) {
        ASSERT_EQ(mapped[0x2000 + i], 0xAA);
    }

    free(mapped);
    free(raw);
    PASS();
}

static void test_map_zero_gap(void) {
    TEST("Section mapping: gap between headers and .text is zero-filled");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    for (int i = 0x200; i < 0x1000; i++) {
        ASSERT_EQ(mapped[i], 0);
    }

    free(mapped);
    free(raw);
    PASS();
}

/* ========================================================================
 * Relocation tests
 * ====================================================================== */

static void test_reloc_dir64_applied(void) {
    TEST("Relocations: DIR64 entry patched with delta");
    DWORD sz;
    PBYTE raw = build_test_pe_with_relocs(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    ULONGLONG orig = *(PULONGLONG)(mapped + 0x1010);
    ASSERT_EQ(orig, 0x180000000ULL + 0x2000);

    LONGLONG delta = (LONGLONG)((ULONGLONG)mapped - 0x180000000ULL);

    apply_relocations(mapped, nt, delta);

    ULONGLONG relocated = *(PULONGLONG)(mapped + 0x1010);
    ULONGLONG expected  = 0x180000000ULL + 0x2000 + delta;
    ASSERT_EQ(relocated, expected);

    free(mapped);
    free(raw);
    PASS();
}

static void test_reloc_zero_delta(void) {
    TEST("Relocations: zero delta is a no-op");
    DWORD sz;
    PBYTE raw = build_test_pe_with_relocs(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    ULONGLONG before = *(PULONGLONG)(mapped + 0x1010);

    apply_relocations(mapped, nt, 0);

    ULONGLONG after = *(PULONGLONG)(mapped + 0x1010);
    ASSERT_EQ(before, after);

    free(mapped);
    free(raw);
    PASS();
}

static void test_reloc_no_reloc_table(void) {
    TEST("Relocations: PE without relocs does not crash");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    LONGLONG delta = 0x100000;
    apply_relocations(mapped, nt, delta);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped;
    ASSERT_EQ(dos->e_magic, IMAGE_DOS_SIGNATURE);

    free(mapped);
    free(raw);
    PASS();
}

static void test_reloc_absolute_ignored(void) {
    TEST("Relocations: ABSOLUTE entry does not modify data");
    DWORD sz;
    PBYTE raw = build_test_pe_with_relocs(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    BYTE before = mapped[0x1000];
    LONGLONG delta = 0x50000;
    apply_relocations(mapped, nt, delta);
    BYTE after = mapped[0x1000];
    ASSERT_EQ(before, after);

    free(mapped);
    free(raw);
    PASS();
}

/* ========================================================================
 * Section protection tests
 * ====================================================================== */

static void test_section_protections(void) {
    TEST("Section protections: correct for .text and .data");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    DWORD text_prot = SectionToProtect(sec[0].Characteristics);
    DWORD data_prot = SectionToProtect(sec[1].Characteristics);

    ASSERT_EQ(text_prot, PAGE_EXECUTE_READ);
    ASSERT_EQ(data_prot, PAGE_READWRITE);

    free(mapped);
    free(raw);
    PASS();
}

/* ========================================================================
 * USER_DATA + ALLOCATED_MEMORY population tests (CS beacon.h 4.12)
 * ====================================================================== */

static void test_userdata_version(void) {
    TEST("USER_DATA: version set correctly");
    USER_DATA ud;
    MmZero(&ud, sizeof(ud));
    ud.version = STARBURST_VERSION;

    ASSERT_EQ(ud.version, 0x010400);
    PASS();
}

static void test_userdata_virtual_alloc(void) {
    TEST("USER_DATA: VirtualAlloc beacon memory region");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    USER_DATA ud;
    ALLOCATED_MEMORY allocMem;
    MmZero(&ud, sizeof(ud));
    MmZero(&allocMem, sizeof(allocMem));

    ud.version         = STARBURST_VERSION;
    ud.allocatedMemory = &allocMem;

    /* Region 0: Beacon memory */
    allocMem.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
    allocMem.AllocatedMemoryRegions[0].AllocationBase = mapped;
    allocMem.AllocatedMemoryRegions[0].RegionSize     = nt->OptionalHeader.SizeOfImage;

    allocMem.AllocatedMemoryRegions[0].Sections[0].Label       = LABEL_TEXT;
    allocMem.AllocatedMemoryRegions[0].Sections[0].BaseAddress = mapped;
    allocMem.AllocatedMemoryRegions[0].Sections[0].VirtualSize = nt->OptionalHeader.SizeOfImage;
    allocMem.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
    allocMem.AllocatedMemoryRegions[0].Sections[0].MaskSection = TRUE;

    ASSERT_EQ(ud.version, STARBURST_VERSION);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].Purpose, PURPOSE_BEACON_MEMORY);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].AllocationBase, mapped);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].RegionSize, 0x3000);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].Sections[0].BaseAddress, mapped);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].Sections[0].VirtualSize, 0x3000);
    ASSERT_TRUE(allocMem.AllocatedMemoryRegions[0].Sections[0].MaskSection);

    free(mapped);
    free(raw);
    PASS();
}

static void test_userdata_module_stomp(void) {
    TEST("USER_DATA: module stomp region with cleanup info");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    USER_DATA ud;
    ALLOCATED_MEMORY allocMem;
    MmZero(&ud, sizeof(ud));
    MmZero(&allocMem, sizeof(allocMem));

    ud.version         = STARBURST_VERSION;
    ud.allocatedMemory = &allocMem;

    /* Region 0: Beacon memory via module stomp */
    allocMem.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
    allocMem.AllocatedMemoryRegions[0].AllocationBase = mapped;
    allocMem.AllocatedMemoryRegions[0].RegionSize     = nt->OptionalHeader.SizeOfImage;

    allocMem.AllocatedMemoryRegions[0].CleanupInformation.AllocationMethod = METHOD_MODULESTOMP;
    allocMem.AllocatedMemoryRegions[0].CleanupInformation.AdditionalCleanupInformation.ModuleStompInfo.ModuleHandle = (HMODULE)mapped;

    allocMem.AllocatedMemoryRegions[0].Sections[0].Label       = LABEL_TEXT;
    allocMem.AllocatedMemoryRegions[0].Sections[0].BaseAddress = mapped + 0x1000;
    allocMem.AllocatedMemoryRegions[0].Sections[0].VirtualSize = 0x1000;
    allocMem.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
    allocMem.AllocatedMemoryRegions[0].Sections[0].MaskSection = TRUE;

    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].CleanupInformation.AllocationMethod, METHOD_MODULESTOMP);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].CleanupInformation.AdditionalCleanupInformation.ModuleStompInfo.ModuleHandle, (HMODULE)mapped);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].Sections[0].BaseAddress, mapped + 0x1000);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].Sections[0].VirtualSize, 0x1000);

    free(mapped);
    free(raw);
    PASS();
}

/* ========================================================================
 * Headerless loader variant tests
 * ====================================================================== */

static void test_headerless_no_headers(void) {
    TEST("Headerless: headers not present at mapped base");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);

    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    WORD  num_sec    = nt->FileHeader.NumberOfSections;

    PBYTE mapped = (PBYTE)calloc(1, image_size);
    ASSERT_NOT_NULL(mapped);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < num_sec; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        MmCopy(
            mapped + sec[i].VirtualAddress,
            raw    + sec[i].PointerToRawData,
            sec[i].SizeOfRawData
        );
    }

    PIMAGE_DOS_HEADER mdos = (PIMAGE_DOS_HEADER)mapped;
    ASSERT_NE(mdos->e_magic, IMAGE_DOS_SIGNATURE);

    ASSERT_EQ(mapped[0x1000], 0xCC);
    ASSERT_EQ(mapped[0x2000], 0xAA);

    free(mapped);
    free(raw);
    PASS();
}

static void test_headerless_entry_from_saved_rva(void) {
    TEST("Headerless: entry point from saved RVA");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);

    DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    ASSERT_EQ(entry_rva, 0x1000);

    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    PBYTE mapped = (PBYTE)calloc(1, image_size);
    ASSERT_NOT_NULL(mapped);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        MmCopy(
            mapped + sec[i].VirtualAddress,
            raw    + sec[i].PointerToRawData,
            sec[i].SizeOfRawData
        );
    }

    PBYTE entry = mapped + entry_rva;
    ASSERT_EQ(entry, mapped + 0x1000);
    ASSERT_EQ(*entry, 0xCC);

    free(mapped);
    free(raw);
    PASS();
}

static void test_headerless_relocs_from_raw(void) {
    TEST("Headerless: relocations applied using saved RVA from raw");
    DWORD sz;
    PBYTE raw = build_test_pe_with_relocs(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);

    DWORD reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    ULONGLONG preferred_base = nt->OptionalHeader.ImageBase;

    ASSERT_NE(reloc_rva, 0);
    ASSERT_NE(reloc_size, 0);

    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    PBYTE mapped = (PBYTE)calloc(1, image_size);
    ASSERT_NOT_NULL(mapped);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        MmCopy(
            mapped + sec[i].VirtualAddress,
            raw    + sec[i].PointerToRawData,
            sec[i].SizeOfRawData
        );
    }

    LONGLONG delta = (LONGLONG)((ULONGLONG)mapped - preferred_base);

    if (delta != 0 && reloc_rva && reloc_size) {
        PIMAGE_BASE_RELOCATION reloc = C_PTR(mapped + reloc_rva);
        PBYTE reloc_end = (PBYTE)reloc + reloc_size;

        while ((PBYTE)reloc < reloc_end && reloc->SizeOfBlock) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; i++) {
                WORD type   = entries[i] >> 12;
                WORD offset = entries[i] & 0xFFF;
                PBYTE patch = mapped + reloc->VirtualAddress + offset;
                if (type == IMAGE_REL_BASED_DIR64)
                    *(PULONGLONG)patch += delta;
            }
            reloc = C_PTR((PBYTE)reloc + reloc->SizeOfBlock);
        }
    }

    ULONGLONG relocated = *(PULONGLONG)(mapped + 0x1010);
    ULONGLONG expected  = preferred_base + 0x2000 + delta;
    ASSERT_EQ(relocated, expected);

    free(mapped);
    free(raw);
    PASS();
}

/* ========================================================================
 * Full load simulation test
 * ====================================================================== */

static void test_full_load_cycle(void) {
    TEST("Full cycle: parse -> map -> relocate -> protect -> populate userdata");
    DWORD sz;
    PBYTE raw = build_test_pe_with_relocs(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    ASSERT_EQ(dos->e_magic, IMAGE_DOS_SIGNATURE);

    PIMAGE_NT_HEADERS raw_nt = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);
    ASSERT_EQ(raw_nt->Signature, IMAGE_NT_SIGNATURE);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    LONGLONG delta = (LONGLONG)((ULONGLONG)mapped - nt->OptionalHeader.ImageBase);
    apply_relocations(mapped, nt, delta);

    ULONGLONG relocated = *(PULONGLONG)(mapped + 0x1010);
    ULONGLONG expected  = nt->OptionalHeader.ImageBase + 0x2000 + delta;
    ASSERT_EQ(relocated, expected);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Misc.VirtualSize == 0) continue;
        DWORD prot = SectionToProtect(sec[i].Characteristics);
        DWORD old;
        mock_VirtualProtect(
            mapped + sec[i].VirtualAddress,
            sec[i].Misc.VirtualSize,
            prot, &old);
    }

    USER_DATA ud;
    ALLOCATED_MEMORY allocMem;
    MmZero(&ud, sizeof(ud));
    MmZero(&allocMem, sizeof(allocMem));

    ud.version         = STARBURST_VERSION;
    ud.allocatedMemory = &allocMem;

    /* Region 0: Beacon memory */
    allocMem.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
    allocMem.AllocatedMemoryRegions[0].AllocationBase = mapped;
    allocMem.AllocatedMemoryRegions[0].RegionSize     = nt->OptionalHeader.SizeOfImage;

    allocMem.AllocatedMemoryRegions[0].Sections[0].Label       = LABEL_TEXT;
    allocMem.AllocatedMemoryRegions[0].Sections[0].BaseAddress = mapped;
    allocMem.AllocatedMemoryRegions[0].Sections[0].VirtualSize = nt->OptionalHeader.SizeOfImage;
    allocMem.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
    allocMem.AllocatedMemoryRegions[0].Sections[0].MaskSection = TRUE;

    ASSERT_EQ(ud.version, STARBURST_VERSION);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].AllocationBase, mapped);
    ASSERT_EQ(allocMem.AllocatedMemoryRegions[0].RegionSize, 0x3000);
    ASSERT_TRUE(allocMem.AllocatedMemoryRegions[0].Sections[0].MaskSection);

    DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    PBYTE entry = mapped + entry_rva;
    ASSERT_EQ(*entry, 0xCC);

    free(mapped);
    free(raw);
    PASS();
}

/* ========================================================================
 * main
 * ====================================================================== */

int main(void) {
    TEST_SUITE("LdrpImageHeader");
    test_ldr_image_header_valid();
    test_ldr_image_header_bad_dos();
    test_ldr_image_header_bad_nt();

    TEST_SUITE("LdrFunction");
    test_ldr_function_resolve_alpha();
    test_ldr_function_resolve_beta();
    test_ldr_function_unknown_hash();
    test_ldr_function_null_library();
    test_ldr_function_zero_hash();

    TEST_SUITE("PE Header Parsing");
    test_pe_dos_valid();
    test_pe_nt_valid();
    test_pe_section_count();
    test_pe_image_base();
    test_pe_size_of_image();
    test_pe_section_headers_readable();

    TEST_SUITE("Section Mapping");
    test_map_headers_copied();
    test_map_text_section();
    test_map_data_section();
    test_map_zero_gap();

    TEST_SUITE("Relocations");
    test_reloc_dir64_applied();
    test_reloc_zero_delta();
    test_reloc_no_reloc_table();
    test_reloc_absolute_ignored();

    TEST_SUITE("Section Protections");
    test_section_protections();

    TEST_SUITE("USER_DATA + ALLOCATED_MEMORY Population");
    test_userdata_version();
    test_userdata_virtual_alloc();
    test_userdata_module_stomp();

    TEST_SUITE("Headerless Loader Variant");
    test_headerless_no_headers();
    test_headerless_entry_from_saved_rva();
    test_headerless_relocs_from_raw();

    TEST_SUITE("Full Load Cycle");
    test_full_load_cycle();

    return TEST_SUMMARY();
}
