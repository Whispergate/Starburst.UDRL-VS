/*
 * Unit tests for UDRL helper functions: SectionToProtect, FindTextSection,
 * GenerateRc4Key. Functions are copied verbatim from loader/src/Main.c
 * since they are static PIC functions that cannot be linked directly.
 */

#include "test.h"
#include "mock_pe.h"

#define FUNC  /* PIC marker - no-op in test builds */

/* ========================================================================
 * Functions under test - verbatim from loader/src/Main.c
 * ====================================================================== */

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

FUNC static BOOL FindTextSection( PBYTE Base, PVOID *Addr, PDWORD Size ) {
    PIMAGE_DOS_HEADER Dos = C_PTR( Base );
    if ( Dos->e_magic != IMAGE_DOS_SIGNATURE ) return FALSE;

    PIMAGE_NT_HEADERS Nt = C_PTR( Base + Dos->e_lfanew );
    if ( Nt->Signature != IMAGE_NT_SIGNATURE ) return FALSE;

    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
    for ( WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        if ( ( Sec[i].Characteristics & IMAGE_SCN_CNT_CODE ) &&
             ( Sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) {
            *Addr = Base + Sec[i].VirtualAddress;
            *Size = Sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

FUNC static VOID GenerateRc4Key( PBYTE Key ) {
    for ( int i = 0; i < 16; i += 4 ) {
        DWORD tick;
#ifdef _WIN64
        tick = (DWORD)__rdtsc();
#else
        tick = (DWORD)__rdtsc();
#endif
        Key[i]     = (BYTE)( tick );
        Key[i + 1] = (BYTE)( tick >> 8 );
        Key[i + 2] = (BYTE)( tick >> 16 );
        Key[i + 3] = (BYTE)( tick >> 24 );
        for ( volatile int j = 0; j < 100; j++ ) {}
    }
}

/* ========================================================================
 * SectionToProtect tests
 * ====================================================================== */

static void test_stp_xrw(void) {
    TEST("SectionToProtect: X+R+W → PAGE_EXECUTE_READWRITE");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE_READWRITE);
    PASS();
}

static void test_stp_xr(void) {
    TEST("SectionToProtect: X+R → PAGE_EXECUTE_READ");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE_READ);
    PASS();
}

static void test_stp_xw(void) {
    TEST("SectionToProtect: X+W → PAGE_EXECUTE_WRITECOPY");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE_WRITECOPY);
    PASS();
}

static void test_stp_x(void) {
    TEST("SectionToProtect: X → PAGE_EXECUTE");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE);
    PASS();
}

static void test_stp_rw(void) {
    TEST("SectionToProtect: R+W → PAGE_READWRITE");
    DWORD ch = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_READWRITE);
    PASS();
}

static void test_stp_r(void) {
    TEST("SectionToProtect: R → PAGE_READONLY");
    DWORD ch = IMAGE_SCN_MEM_READ;
    ASSERT_EQ(SectionToProtect(ch), PAGE_READONLY);
    PASS();
}

static void test_stp_w(void) {
    TEST("SectionToProtect: W → PAGE_WRITECOPY");
    DWORD ch = IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_WRITECOPY);
    PASS();
}

static void test_stp_none(void) {
    TEST("SectionToProtect: no flags → PAGE_NOACCESS");
    ASSERT_EQ(SectionToProtect(0), PAGE_NOACCESS);
    PASS();
}

static void test_stp_with_content_flags(void) {
    TEST("SectionToProtect: non-memory flags ignored");
    DWORD ch = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    ASSERT_EQ(SectionToProtect(ch), PAGE_READONLY);
    PASS();
}

/* ========================================================================
 * FindTextSection tests
 * ====================================================================== */

static void test_fts_finds_text(void) {
    TEST("FindTextSection: finds .text in valid PE");
    DWORD pe_size;
    PBYTE pe = build_test_pe(&pe_size);
    ASSERT_NOT_NULL(pe);

    PVOID addr = NULL;
    DWORD size = 0;
    BOOL ret = FindTextSection(pe, &addr, &size);

    ASSERT_TRUE(ret);
    ASSERT_EQ(addr, pe + 0x1000);
    ASSERT_EQ(size, 0x1000);

    free(pe);
    PASS();
}

static void test_fts_no_code_section(void) {
    TEST("FindTextSection: returns FALSE when no code section");
    DWORD pe_size;
    PBYTE pe = build_test_pe(&pe_size);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    sec[0].Characteristics = IMAGE_SCN_MEM_READ;

    PVOID addr = NULL;
    DWORD size = 0;
    ASSERT_FALSE(FindTextSection(pe, &addr, &size));

    free(pe);
    PASS();
}

static void test_fts_bad_dos(void) {
    TEST("FindTextSection: returns FALSE on bad DOS signature");
    BYTE buf[512];
    memset(buf, 0, sizeof(buf));

    PVOID addr = NULL;
    DWORD size = 0;
    ASSERT_FALSE(FindTextSection(buf, &addr, &size));
    PASS();
}

static void test_fts_bad_nt(void) {
    TEST("FindTextSection: returns FALSE on bad NT signature");
    DWORD pe_size;
    PBYTE pe = build_test_pe(&pe_size);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    nt->Signature = 0xDEADBEEF;

    PVOID addr = NULL;
    DWORD size = 0;
    ASSERT_FALSE(FindTextSection(pe, &addr, &size));

    free(pe);
    PASS();
}

static void test_fts_second_section_is_code(void) {
    TEST("FindTextSection: finds code section even if not first");
    DWORD pe_size;
    PBYTE pe = build_test_pe(&pe_size);
    ASSERT_NOT_NULL(pe);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    sec[0].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    sec[1].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    PVOID addr = NULL;
    DWORD size = 0;
    BOOL ret = FindTextSection(pe, &addr, &size);

    ASSERT_TRUE(ret);
    ASSERT_EQ(addr, pe + sec[1].VirtualAddress);
    ASSERT_EQ(size, sec[1].Misc.VirtualSize);

    free(pe);
    PASS();
}

/* ========================================================================
 * GenerateRc4Key tests
 * ====================================================================== */

static void test_rc4key_nonzero(void) {
    TEST("GenerateRc4Key: produces non-zero key");
    BYTE key[16];
    memset(key, 0, 16);

    GenerateRc4Key(key);

    BOOL all_zero = TRUE;
    for (int i = 0; i < 16; i++) {
        if (key[i] != 0) { all_zero = FALSE; break; }
    }
    ASSERT_FALSE(all_zero);
    PASS();
}

static void test_rc4key_fills_all_bytes(void) {
    TEST("GenerateRc4Key: all 4 groups populated");
    BYTE key[16];
    memset(key, 0, 16);

    GenerateRc4Key(key);

    for (int g = 0; g < 4; g++) {
        BOOL group_nonzero = FALSE;
        for (int i = 0; i < 4; i++) {
            if (key[g * 4 + i] != 0) { group_nonzero = TRUE; break; }
        }
        ASSERT_TRUE(group_nonzero);
    }
    PASS();
}

static void test_rc4key_different_each_call(void) {
    TEST("GenerateRc4Key: consecutive calls produce different keys");
    BYTE key1[16], key2[16];

    GenerateRc4Key(key1);
    GenerateRc4Key(key2);

    BOOL differ = (memcmp(key1, key2, 16) != 0);
    ASSERT_TRUE(differ);
    PASS();
}

static void test_rc4key_byte_extraction(void) {
    TEST("GenerateRc4Key: bytes extracted in correct order");
    _mock_rdtsc_counter = 0;

    BYTE key[16];
    GenerateRc4Key(key);

    /* First __rdtsc: counter 0 + 0x1234 = 0x1234
       Key[0] = 0x34, Key[1] = 0x12, Key[2] = 0x00, Key[3] = 0x00 */
    ASSERT_EQ(key[0], 0x34);
    ASSERT_EQ(key[1], 0x12);
    ASSERT_EQ(key[2], 0x00);
    ASSERT_EQ(key[3], 0x00);

    PASS();
}

/* ========================================================================
 * main
 * ====================================================================== */

int main(void) {
    TEST_SUITE("SectionToProtect");
    test_stp_xrw();
    test_stp_xr();
    test_stp_xw();
    test_stp_x();
    test_stp_rw();
    test_stp_r();
    test_stp_w();
    test_stp_none();
    test_stp_with_content_flags();

    TEST_SUITE("FindTextSection");
    test_fts_finds_text();
    test_fts_no_code_section();
    test_fts_bad_dos();
    test_fts_bad_nt();
    test_fts_second_section_is_code();

    TEST_SUITE("GenerateRc4Key");
    test_rc4key_nonzero();
    test_rc4key_fills_all_bytes();
    test_rc4key_different_each_call();
    test_rc4key_byte_extraction();

    return TEST_SUMMARY();
}
