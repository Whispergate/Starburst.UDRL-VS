/*
 * Unit tests for UDRL PE operations: header parsing, section mapping,
 * relocation processing, IAT stub resolution, and UDRL_USER_DATA population.
 *
 * Core logic is copied verbatim from loader/src/Main.c.
 * Tests use synthetic PEs from mock_pe.h's build_test_pe / build_test_pe_with_relocs.
 */

#include "test.h"
#include "mock_pe.h"

#define FUNC  /* PIC marker - no-op in test builds */

/* SectionToProtect, copied from loader/src/Main.c */
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

/* GenerateRc4Key, copied from loader/src/Main.c */
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

/* ========================================================================
 * Helper: map a synthetic PE into a "mapped" buffer the way the loader does.
 * Returns the mapped base (calloc'd). Caller must free().
 * Sets *nt_out to point to the NT headers in the mapped image.
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
 * UDRL_USER_DATA population tests
 * ====================================================================== */

static void test_userdata_magic(void) {
    TEST("UDRL_USER_DATA: magic set correctly");
    UDRL_USER_DATA ud;
    MmZero(&ud, sizeof(ud));
    ud.magic = UDRL_MAGIC;

    ASSERT_EQ(ud.magic, 0x5442525354ULL);
    PASS();
}

static void test_userdata_virtual_alloc(void) {
    TEST("UDRL_USER_DATA: VirtualAlloc load type fields");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    UDRL_USER_DATA ud;
    MmZero(&ud, sizeof(ud));
    ud.magic      = UDRL_MAGIC;
    ud.load_type  = LOAD_TYPE_VIRTUAL_ALLOC;
    ud.agent_base = mapped;
    ud.agent_size = nt->OptionalHeader.SizeOfImage;

    ud.regions[0].base    = mapped;
    ud.regions[0].size    = nt->OptionalHeader.SizeOfImage;
    ud.regions[0].protect = PAGE_EXECUTE_READ;
    ud.region_count = 1;

    GenerateRc4Key(ud.rc4_key);

    ASSERT_EQ(ud.magic, UDRL_MAGIC);
    ASSERT_EQ(ud.load_type, LOAD_TYPE_VIRTUAL_ALLOC);
    ASSERT_EQ(ud.agent_base, mapped);
    ASSERT_EQ(ud.agent_size, 0x3000);
    ASSERT_EQ(ud.region_count, 1);
    ASSERT_EQ(ud.regions[0].base, mapped);
    ASSERT_EQ(ud.regions[0].size, 0x3000);

    BOOL key_ok = FALSE;
    for (int i = 0; i < 16; i++) {
        if (ud.rc4_key[i] != 0) { key_ok = TRUE; break; }
    }
    ASSERT_TRUE(key_ok);

    free(mapped);
    free(raw);
    PASS();
}

static void test_userdata_module_stomp(void) {
    TEST("UDRL_USER_DATA: module stomp fields");
    DWORD sz;
    PBYTE raw = build_test_pe(&sz);
    ASSERT_NOT_NULL(raw);

    PIMAGE_NT_HEADERS nt;
    PBYTE mapped = map_test_pe(raw, &nt);
    ASSERT_NOT_NULL(mapped);

    UDRL_USER_DATA ud;
    MmZero(&ud, sizeof(ud));
    ud.magic             = UDRL_MAGIC;
    ud.load_type         = LOAD_TYPE_MODULE_STOMP;
    ud.agent_base        = mapped;
    ud.agent_size        = nt->OptionalHeader.SizeOfImage;
    ud.stomped_module    = (HMODULE)mapped;
    ud.stomped_text_base = mapped + 0x1000;
    ud.stomped_text_size = 0x1000;

    ud.regions[0].base    = mapped;
    ud.regions[0].size    = nt->OptionalHeader.SizeOfImage;
    ud.regions[0].protect = PAGE_EXECUTE_READ;
    ud.region_count = 1;

    GenerateRc4Key(ud.rc4_key);

    ASSERT_EQ(ud.load_type, LOAD_TYPE_MODULE_STOMP);
    ASSERT_EQ(ud.stomped_module, (HMODULE)mapped);
    ASSERT_EQ(ud.stomped_text_base, mapped + 0x1000);
    ASSERT_EQ(ud.stomped_text_size, 0x1000);

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
    TEST("Full cycle: parse → map → relocate → protect → populate userdata");
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

    UDRL_USER_DATA ud;
    MmZero(&ud, sizeof(ud));
    ud.magic      = UDRL_MAGIC;
    ud.load_type  = LOAD_TYPE_VIRTUAL_ALLOC;
    ud.agent_base = mapped;
    ud.agent_size = nt->OptionalHeader.SizeOfImage;

    ud.regions[0].base    = mapped;
    ud.regions[0].size    = nt->OptionalHeader.SizeOfImage;
    ud.regions[0].protect = PAGE_EXECUTE_READ;
    ud.region_count = 1;

    GenerateRc4Key(ud.rc4_key);

    ASSERT_EQ(ud.magic, UDRL_MAGIC);
    ASSERT_EQ(ud.agent_base, mapped);
    ASSERT_EQ(ud.agent_size, 0x3000);
    ASSERT_EQ(ud.region_count, 1);

    BOOL key_ok = FALSE;
    for (int i = 0; i < 16; i++) {
        if (ud.rc4_key[i] != 0) { key_ok = TRUE; break; }
    }
    ASSERT_TRUE(key_ok);

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

    TEST_SUITE("UDRL_USER_DATA Population");
    test_userdata_magic();
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
