/*
 * Unit tests for UDRL helper functions: HashString, ExprHashStringA,
 * SectionToProtect, FindTextSection, GenerateRc4Key.
 * Functions are copied verbatim from loader sources since they are
 * static PIC functions that cannot be linked directly.
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
        tick = (DWORD)__rdtsc();
        Key[i]     = (BYTE)( tick );
        Key[i + 1] = (BYTE)( tick >> 8 );
        Key[i + 2] = (BYTE)( tick >> 16 );
        Key[i + 3] = (BYTE)( tick >> 24 );
        for ( volatile int j = 0; j < 100; j++ ) {}
    }
}

/* ========================================================================
 * HashString tests
 * ====================================================================== */

static void test_hash_null_returns_zero(void) {
    TEST("HashString: NULL input returns 0");
    ASSERT_EQ(HashString(NULL, 0), 0);
    ASSERT_EQ(HashString(NULL, 10), 0);
    PASS();
}

static void test_hash_empty_string(void) {
    TEST("HashString: empty string returns H_MAGIC_KEY");
    ASSERT_EQ(HashString("", 0), (ULONG)H_MAGIC_KEY);
    PASS();
}

static void test_hash_case_insensitive(void) {
    TEST("HashString: case insensitive for ASCII");
    ULONG h1 = HashString("Hello", 0);
    ULONG h2 = HashString("HELLO", 0);
    ULONG h3 = HashString("hELLO", 0);
    ASSERT_EQ(h1, h2);
    ASSERT_EQ(h2, h3);
    PASS();
}

static void test_hash_different_strings_differ(void) {
    TEST("HashString: different strings produce different hashes");
    ULONG h1 = HashString("AAA", 0);
    ULONG h2 = HashString("BBB", 0);
    ULONG h3 = HashString("AAAA", 0);
    ASSERT_NE(h1, h2);
    ASSERT_NE(h1, h3);
    PASS();
}

static void test_hash_single_char(void) {
    TEST("HashString: single character 'A' matches manual computation");
    ULONG hash = HashString("A", 0);
    ULONG expected = ((H_MAGIC_KEY << H_MAGIC_SEED) + H_MAGIC_KEY) + 'A';
    ASSERT_EQ(hash, expected);
    PASS();
}

static void test_hash_wide_ntdll(void) {
    TEST("HashString: wide \"ntdll.dll\" matches H_MODULE_NTDLL");
    unsigned char ntdll_wide[] = {
        'n', 0, 't', 0, 'd', 0, 'l', 0, 'l', 0,
        '.', 0, 'd', 0, 'l', 0, 'l', 0
    };
    ULONG hash = HashString(ntdll_wide, sizeof(ntdll_wide));
    ASSERT_EQ(hash, H_MODULE_NTDLL);
    PASS();
}

static void test_hash_wide_kernel32(void) {
    TEST("HashString: wide \"kernel32.dll\" matches H_MODULE_KERNEL32");
    unsigned char k32_wide[] = {
        'k', 0, 'e', 0, 'r', 0, 'n', 0, 'e', 0, 'l', 0,
        '3', 0, '2', 0, '.', 0, 'd', 0, 'l', 0, 'l', 0
    };
    ULONG hash = HashString(k32_wide, sizeof(k32_wide));
    ASSERT_EQ(hash, H_MODULE_KERNEL32);
    PASS();
}

/* ========================================================================
 * ExprHashStringA consistency tests
 * ====================================================================== */

static void test_expr_null_returns_zero(void) {
    TEST("ExprHashStringA: NULL returns 0");
    ASSERT_EQ(ExprHashStringA(NULL), 0);
    PASS();
}

static void test_expr_matches_runtime(void) {
    TEST("ExprHashStringA matches HashString for narrow strings");
    ULONG ct1 = HASH_STR("LoadLibraryA");
    ULONG rt1 = HashString("LoadLibraryA", 0);
    ASSERT_EQ(ct1, rt1);

    ULONG ct2 = HASH_STR("VirtualAlloc");
    ULONG rt2 = HashString("VirtualAlloc", 0);
    ASSERT_EQ(ct2, rt2);

    ULONG ct3 = HASH_STR("NtAllocateVirtualMemory");
    ULONG rt3 = HashString("NtAllocateVirtualMemory", 0);
    ASSERT_EQ(ct3, rt3);
    PASS();
}

static void test_expr_case_insensitive(void) {
    TEST("ExprHashStringA: case insensitive");
    ASSERT_EQ(HASH_STR("kernel32.dll"), HASH_STR("KERNEL32.DLL"));
    PASS();
}

/* ========================================================================
 * SectionToProtect tests
 * ====================================================================== */

static void test_stp_xrw(void) {
    TEST("SectionToProtect: X+R+W -> PAGE_EXECUTE_READWRITE");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE_READWRITE);
    PASS();
}

static void test_stp_xr(void) {
    TEST("SectionToProtect: X+R -> PAGE_EXECUTE_READ");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE_READ);
    PASS();
}

static void test_stp_xw(void) {
    TEST("SectionToProtect: X+W -> PAGE_EXECUTE_WRITECOPY");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE_WRITECOPY);
    PASS();
}

static void test_stp_x(void) {
    TEST("SectionToProtect: X -> PAGE_EXECUTE");
    DWORD ch = IMAGE_SCN_MEM_EXECUTE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_EXECUTE);
    PASS();
}

static void test_stp_rw(void) {
    TEST("SectionToProtect: R+W -> PAGE_READWRITE");
    DWORD ch = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_READWRITE);
    PASS();
}

static void test_stp_r(void) {
    TEST("SectionToProtect: R -> PAGE_READONLY");
    DWORD ch = IMAGE_SCN_MEM_READ;
    ASSERT_EQ(SectionToProtect(ch), PAGE_READONLY);
    PASS();
}

static void test_stp_w(void) {
    TEST("SectionToProtect: W -> PAGE_WRITECOPY");
    DWORD ch = IMAGE_SCN_MEM_WRITE;
    ASSERT_EQ(SectionToProtect(ch), PAGE_WRITECOPY);
    PASS();
}

static void test_stp_none(void) {
    TEST("SectionToProtect: no flags -> PAGE_NOACCESS");
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
    TEST_SUITE("HashString");
    test_hash_null_returns_zero();
    test_hash_empty_string();
    test_hash_case_insensitive();
    test_hash_different_strings_differ();
    test_hash_single_char();
    test_hash_wide_ntdll();
    test_hash_wide_kernel32();

    TEST_SUITE("ExprHashStringA");
    test_expr_null_returns_zero();
    test_expr_matches_runtime();
    test_expr_case_insensitive();

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
