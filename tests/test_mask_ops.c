#include "test.h"
#include "mock_pe.h"

/* ------------------------------------------------------------------ */
/* Functions under test, copied from the mask sources.                */
/* ------------------------------------------------------------------ */

/* From mask/src/main.c */
static void xor_region( unsigned char *buf, unsigned int len, unsigned char *key, unsigned int key_len ) {
    for ( unsigned int i = 0; i < len; i++ ) {
        buf[i] ^= key[i % key_len];
    }
}

/* From mask/src/main.c */
static ULONG_PTR dispatch_call( PFUNCTION_CALL fc ) {
    ULONG_PTR ret = 0;

    switch ( fc->numOfArgs ) {
        case 0:  ret = ((BEACON_GATE_00) fc->functionPtr)(); break;
        case 1:  ret = ((BEACON_GATE_01) fc->functionPtr)( fc->args[0] ); break;
        case 2:  ret = ((BEACON_GATE_02) fc->functionPtr)( fc->args[0], fc->args[1] ); break;
        case 3:  ret = ((BEACON_GATE_03) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2] ); break;
        case 4:  ret = ((BEACON_GATE_04) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3] ); break;
        case 5:  ret = ((BEACON_GATE_05) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4] ); break;
        case 6:  ret = ((BEACON_GATE_06) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5] ); break;
        case 7:  ret = ((BEACON_GATE_07) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6] ); break;
        case 8:  ret = ((BEACON_GATE_08) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6], fc->args[7] ); break;
        case 9:  ret = ((BEACON_GATE_09) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6], fc->args[7], fc->args[8] ); break;
        case 10: ret = ((BEACON_GATE_10) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6], fc->args[7], fc->args[8], fc->args[9] ); break;
    }

    return ret;
}

/* From mask/src/main.c: sleep_mask using CS BEACON_INFO (section-level XOR) */
static VOID sleep_mask( PBEACON_INFO beaconInfo, PFUNCTION_CALL functionCall ) {

    if ( ! functionCall )
        return;

    if ( ! functionCall->bMask ) {
        functionCall->retValue = dispatch_call( functionCall );
        return;
    }

    unsigned char *key     = (unsigned char *) beaconInfo->mask;
    unsigned int   key_len = MASK_SIZE;

    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;
        for ( int s = 0; s < 8; s++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;
            xor_region(
                (unsigned char *) sec->BaseAddress,
                (unsigned int) sec->VirtualSize,
                key, key_len
            );
        }
    }

    functionCall->retValue = dispatch_call( functionCall );

    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;
        for ( int s = 0; s < 8; s++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;
            xor_region(
                (unsigned char *) sec->BaseAddress,
                (unsigned int) sec->VirtualSize,
                key, key_len
            );
        }
    }
}

/* From examples/mask-erase/main.c: erase mask (adapted for CS BEACON_INFO) */
static VOID sleep_mask_erase( PBEACON_INFO beaconInfo, PFUNCTION_CALL functionCall ) {

    if ( ! functionCall )
        return;

    if ( ! functionCall->bMask ) {
        functionCall->retValue = dispatch_call( functionCall );
        return;
    }

    /* Back up each maskable section, then zero it */
    PVOID sec_backups[6 * 8] = { 0 };
    DWORD oldProtect = 0;
    int idx = 0;

    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 ) {
            idx += 8;
            continue;
        }
        for ( int s = 0; s < 8; s++, idx++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 || ! sec->MaskSection )
                continue;

            DWORD size = (DWORD) sec->VirtualSize;
            sec_backups[idx] = mock_VirtualAlloc( NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if ( ! sec_backups[idx] )
                continue;

            for ( DWORD j = 0; j < size; j++ )
                ((PBYTE) sec_backups[idx])[j] = ((PBYTE) sec->BaseAddress)[j];

            mock_VirtualProtect( sec->BaseAddress, size, PAGE_READWRITE, &oldProtect );

            for ( DWORD j = 0; j < size; j++ )
                ((PBYTE) sec->BaseAddress)[j] = 0;
        }
    }

    functionCall->retValue = dispatch_call( functionCall );

    /* Restore each section from its backup */
    idx = 0;
    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 ) {
            idx += 8;
            continue;
        }
        for ( int s = 0; s < 8; s++, idx++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 || ! sec_backups[idx] )
                continue;

            DWORD size = (DWORD) sec->VirtualSize;
            mock_VirtualProtect( sec->BaseAddress, size, PAGE_READWRITE, &oldProtect );

            for ( DWORD j = 0; j < size; j++ )
                ((PBYTE) sec->BaseAddress)[j] = ((PBYTE) sec_backups[idx])[j];

            mock_VirtualProtect( sec->BaseAddress, size, sec->CurrentProtect, &oldProtect );

            mock_VirtualFree( sec_backups[idx], 0, MEM_RELEASE );
        }
    }
}

/* From mask/src/main.c: production sleep_mask (CS BEACON_INFO, same as sleep_mask above) */
static VOID sleep_mask_prod( PBEACON_INFO beaconInfo, PFUNCTION_CALL functionCall ) {

    if ( ! functionCall )
        return;

    if ( ! functionCall->bMask ) {
        functionCall->retValue = dispatch_call( functionCall );
        return;
    }

    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;

        for ( int s = 0; s < 8; s++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;

            xor_region(
                (unsigned char *) sec->BaseAddress,
                (unsigned int) sec->VirtualSize,
                (unsigned char *) beaconInfo->mask,
                MASK_SIZE
            );
        }
    }

    functionCall->retValue = dispatch_call( functionCall );

    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;

        for ( int s = 0; s < 8; s++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;

            xor_region(
                (unsigned char *) sec->BaseAddress,
                (unsigned int) sec->VirtualSize,
                (unsigned char *) beaconInfo->mask,
                MASK_SIZE
            );
        }
    }
}

/* ------------------------------------------------------------------ */
/* Test helper functions                                              */
/* ------------------------------------------------------------------ */

static ULONG_PTR test_func_0( void ) {
    return 0x42;
}

static ULONG_PTR test_func_1( ULONG_PTR a ) {
    return a * 2;
}

static ULONG_PTR test_func_2( ULONG_PTR a, ULONG_PTR b ) {
    return a + b;
}

static ULONG_PTR test_func_3( ULONG_PTR a, ULONG_PTR b, ULONG_PTR c ) {
    return a + b + c;
}

static ULONG_PTR test_func_10( ULONG_PTR a, ULONG_PTR b, ULONG_PTR c, ULONG_PTR d, ULONG_PTR e,
                                ULONG_PTR f, ULONG_PTR g, ULONG_PTR h, ULONG_PTR i, ULONG_PTR j ) {
    return a + b + c + d + e + f + g + h + i + j;
}

static ULONG_PTR noop_func( void ) {
    return 0xBEEF;
}

static ULONG_PTR gate_test_func( void ) {
    return 0x1337;
}

static void fill_pattern( unsigned char *buf, unsigned int len, const char *pat ) {
    unsigned int pat_len = (unsigned int) strlen( pat );
    for ( unsigned int i = 0; i < len; i++ ) {
        buf[i] = (unsigned char) pat[i % pat_len];
    }
}

/* ================================================================== */
/*                      XOR REGION SYMMETRY                           */
/* ================================================================== */

static void test_xor_roundtrip( void ) {
    TEST( "xor_region: XOR then XOR again restores original data" );

    unsigned char buf[32];
    unsigned char orig[32];
    unsigned char key[4] = { 0xAA, 0xBB, 0xCC, 0xDD };

    fill_pattern( buf, 32, "DEADBEEF" );
    memcpy( orig, buf, 32 );

    xor_region( buf, 32, key, 4 );
    ASSERT_TRUE( memcmp( buf, orig, 32 ) != 0 );

    xor_region( buf, 32, key, 4 );
    ASSERT_MEM_EQ( buf, orig, 32 );

    PASS();
}

static void test_xor_zero_key_identity( void ) {
    TEST( "xor_region: all-zero key is identity" );

    unsigned char buf[16];
    unsigned char orig[16];
    unsigned char key[4] = { 0, 0, 0, 0 };

    fill_pattern( buf, 16, "TESTDATA" );
    memcpy( orig, buf, 16 );

    xor_region( buf, 16, key, 4 );
    ASSERT_MEM_EQ( buf, orig, 16 );

    PASS();
}

static void test_xor_single_byte_key( void ) {
    TEST( "xor_region: single-byte key applies uniformly" );

    unsigned char buf[8] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    unsigned char key[1] = { 0xFF };

    xor_region( buf, 8, key, 1 );

    ASSERT_EQ( buf[0], 0x10 ^ 0xFF );
    ASSERT_EQ( buf[1], 0x20 ^ 0xFF );
    ASSERT_EQ( buf[2], 0x30 ^ 0xFF );
    ASSERT_EQ( buf[7], 0x80 ^ 0xFF );

    PASS();
}

static void test_xor_16byte_key_wraps( void ) {
    TEST( "xor_region: 16-byte key wraps correctly on buffer > 16 bytes" );

    unsigned char buf[32];
    unsigned char orig[32];
    unsigned char key[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    memset( buf, 0x41, 32 );
    memcpy( orig, buf, 32 );

    xor_region( buf, 32, key, 16 );

    ASSERT_EQ( buf[0], 0x41 ^ key[0] );
    ASSERT_EQ( buf[16], 0x41 ^ key[0] );
    ASSERT_EQ( buf[1], 0x41 ^ key[1] );
    ASSERT_EQ( buf[17], 0x41 ^ key[1] );

    xor_region( buf, 32, key, 16 );
    ASSERT_MEM_EQ( buf, orig, 32 );

    PASS();
}

static void test_xor_empty_buffer( void ) {
    TEST( "xor_region: empty buffer (len=0) does not crash" );

    unsigned char buf[1] = { 0x42 };
    unsigned char key[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    xor_region( buf, 0, key, 4 );
    ASSERT_EQ( buf[0], 0x42 );

    PASS();
}

static void test_xor_large_buffer( void ) {
    TEST( "xor_region: 4096-byte buffer roundtrips correctly" );

    unsigned char *buf  = (unsigned char *) malloc( 4096 );
    unsigned char *orig = (unsigned char *) malloc( 4096 );
    unsigned char key[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    ASSERT_NOT_NULL( buf );
    ASSERT_NOT_NULL( orig );

    fill_pattern( buf, 4096, "LARGEBUFFER_TEST" );
    memcpy( orig, buf, 4096 );

    xor_region( buf, 4096, key, 16 );
    ASSERT_TRUE( memcmp( buf, orig, 4096 ) != 0 );

    xor_region( buf, 4096, key, 16 );
    ASSERT_MEM_EQ( buf, orig, 4096 );

    free( buf );
    free( orig );

    PASS();
}

static void test_xor_guard_bytes( void ) {
    TEST( "xor_region: does not write beyond buffer bounds" );

    unsigned char mem[40];
    memset( mem, 0xAA, sizeof( mem ) );

    unsigned char key[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    /* XOR only the middle 32 bytes, leaving 4 guard bytes on each side */
    xor_region( mem + 4, 32, key, 4 );

    /* Guard bytes should be untouched */
    ASSERT_EQ( mem[0], 0xAA );
    ASSERT_EQ( mem[1], 0xAA );
    ASSERT_EQ( mem[2], 0xAA );
    ASSERT_EQ( mem[3], 0xAA );
    ASSERT_EQ( mem[36], 0xAA );
    ASSERT_EQ( mem[37], 0xAA );
    ASSERT_EQ( mem[38], 0xAA );
    ASSERT_EQ( mem[39], 0xAA );

    /* Middle bytes should be modified (0xAA ^ 0xFF = 0x55) */
    ASSERT_EQ( mem[4], 0x55 );
    ASSERT_EQ( mem[35], 0x55 );

    PASS();
}

/* ================================================================== */
/*                        DISPATCH CALL                               */
/* ================================================================== */

static void test_dispatch_0arg( void ) {
    TEST( "dispatch_call: 0-arg function returns constant" );

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) test_func_0;
    fc.numOfArgs   = 0;

    ULONG_PTR ret = dispatch_call( &fc );
    ASSERT_EQ( ret, 0x42 );

    PASS();
}

static void test_dispatch_1arg( void ) {
    TEST( "dispatch_call: 1-arg function doubles value" );

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) test_func_1;
    fc.numOfArgs   = 1;
    fc.args[0]     = 21;

    ULONG_PTR ret = dispatch_call( &fc );
    ASSERT_EQ( ret, 42 );

    PASS();
}

static void test_dispatch_2arg( void ) {
    TEST( "dispatch_call: 2-arg function adds arguments" );

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) test_func_2;
    fc.numOfArgs   = 2;
    fc.args[0]     = 100;
    fc.args[1]     = 200;

    ULONG_PTR ret = dispatch_call( &fc );
    ASSERT_EQ( ret, 300 );

    PASS();
}

static void test_dispatch_3arg( void ) {
    TEST( "dispatch_call: 3-arg function sums arguments" );

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) test_func_3;
    fc.numOfArgs   = 3;
    fc.args[0]     = 10;
    fc.args[1]     = 20;
    fc.args[2]     = 30;

    ULONG_PTR ret = dispatch_call( &fc );
    ASSERT_EQ( ret, 60 );

    PASS();
}

static void test_dispatch_10arg( void ) {
    TEST( "dispatch_call: 10-arg (max) function sums all arguments" );

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) test_func_10;
    fc.numOfArgs   = 10;
    for ( int i = 0; i < 10; i++ )
        fc.args[i] = (ULONG_PTR)( i + 1 );

    ULONG_PTR ret = dispatch_call( &fc );
    ASSERT_EQ( ret, 55 ); /* 1+2+...+10 */

    PASS();
}

static void test_dispatch_null_function( void ) {
    TEST( "dispatch_call: NULL functionPtr with invalid numOfArgs returns 0" );

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = NULL;
    fc.numOfArgs   = -1;

    ULONG_PTR ret = dispatch_call( &fc );
    ASSERT_EQ( ret, 0 );

    PASS();
}

/* ================================================================== */
/*                SLEEP MASK FULL CYCLE (BASE XOR)                    */
/* ================================================================== */

static void test_sleep_mask_full_cycle( void ) {
    TEST( "sleep_mask: full cycle masks then restores data" );

    unsigned char data[64];
    unsigned char orig[64];
    fill_pattern( data, 64, "HELLO WORLD " );
    memcpy( orig, data, 64 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );
    bi.beacon_ptr = (char *) data;

    char mask_key[MASK_SIZE] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD
    };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg->AllocationBase = data;
    reg->RegionSize     = 64;
    reg->Sections[0].BaseAddress = data;
    reg->Sections[0].VirtualSize = 64;
    reg->Sections[0].MaskSection = TRUE;
    reg->Sections[0].CurrentProtect = PAGE_EXECUTE_READWRITE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask( &bi, &fc );

    ASSERT_MEM_EQ( data, orig, 64 );
    ASSERT_EQ( fc.retValue, 0xBEEF );

    PASS();
}

static void test_sleep_mask_null_call( void ) {
    TEST( "sleep_mask: NULL functionCall does not crash" );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    sleep_mask( &bi, NULL );

    PASS();
}

/* ================================================================== */
/*                      BEACON GATE PATH                              */
/* ================================================================== */

static void test_beacon_gate_path( void ) {
    TEST( "sleep_mask: beacon gate path (bMask=FALSE) executes without masking" );

    unsigned char data[32];
    unsigned char orig[32];
    fill_pattern( data, 32, "GATEDATA" );
    memcpy( orig, data, 32 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );
    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg->AllocationBase = data;
    reg->RegionSize     = 32;
    reg->Sections[0].BaseAddress    = data;
    reg->Sections[0].VirtualSize    = 32;
    reg->Sections[0].MaskSection    = TRUE;
    reg->Sections[0].CurrentProtect = PAGE_READWRITE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) gate_test_func;
    fc.numOfArgs   = 0;
    fc.bMask       = FALSE;

    sleep_mask( &bi, &fc );

    ASSERT_EQ( fc.retValue, 0x1337 );
    ASSERT_MEM_EQ( data, orig, 32 );

    PASS();
}

/* ================================================================== */
/*                     ERASE MASK ALGORITHM                           */
/* ================================================================== */

static void test_erase_mask_backup_restore( void ) {
    TEST( "erase mask: backup, zero, restore cycle preserves data" );

    unsigned char *data = (unsigned char *) malloc( 128 );
    unsigned char *orig = (unsigned char *) malloc( 128 );
    ASSERT_NOT_NULL( data );
    ASSERT_NOT_NULL( orig );

    fill_pattern( data, 128, "ERASEPATTERN" );
    memcpy( orig, data, 128 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );
    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg->AllocationBase = data;
    reg->RegionSize     = 128;
    reg->Sections[0].BaseAddress    = data;
    reg->Sections[0].VirtualSize    = 128;
    reg->Sections[0].MaskSection    = TRUE;
    reg->Sections[0].CurrentProtect = PAGE_EXECUTE_READWRITE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask_erase( &bi, &fc );

    ASSERT_MEM_EQ( data, orig, 128 );
    ASSERT_EQ( fc.retValue, 0xBEEF );

    free( data );
    free( orig );

    PASS();
}

static void test_erase_mask_zeros_during_sleep( void ) {
    TEST( "erase mask: original memory is zeroed during the sleep call" );

    unsigned char data[64];
    fill_pattern( data, 64, "CHECKZERO" );

    unsigned char *backup = (unsigned char *) malloc( 64 );
    ASSERT_NOT_NULL( backup );

    for ( unsigned int j = 0; j < 64; j++ )
        backup[j] = data[j];

    for ( unsigned int j = 0; j < 64; j++ )
        data[j] = 0;

    for ( unsigned int j = 0; j < 64; j++ ) {
        ASSERT_EQ( data[j], 0 );
    }

    for ( unsigned int j = 0; j < 64; j++ )
        data[j] = backup[j];

    unsigned char expected[64];
    fill_pattern( expected, 64, "CHECKZERO" );
    ASSERT_MEM_EQ( data, expected, 64 );

    free( backup );

    PASS();
}

static void test_erase_mask_multi_region( void ) {
    TEST( "erase mask: multi-region backup/restore cycle" );

    unsigned char *r1 = (unsigned char *) malloc( 64 );
    unsigned char *r2 = (unsigned char *) malloc( 96 );
    unsigned char o1[64], o2[96];

    ASSERT_NOT_NULL( r1 );
    ASSERT_NOT_NULL( r2 );

    fill_pattern( r1, 64, "REGION_A" );
    fill_pattern( r2, 96, "REGION_B" );
    memcpy( o1, r1, 64 );
    memcpy( o2, r2, 96 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    ALLOCATED_MEMORY_REGION *reg0 = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg0->AllocationBase = r1;
    reg0->RegionSize     = 64;
    reg0->Sections[0].BaseAddress    = r1;
    reg0->Sections[0].VirtualSize    = 64;
    reg0->Sections[0].MaskSection    = TRUE;
    reg0->Sections[0].CurrentProtect = PAGE_EXECUTE_READWRITE;

    ALLOCATED_MEMORY_REGION *reg1 = &bi.allocatedMemory.AllocatedMemoryRegions[1];
    reg1->AllocationBase = r2;
    reg1->RegionSize     = 96;
    reg1->Sections[0].BaseAddress    = r2;
    reg1->Sections[0].VirtualSize    = 96;
    reg1->Sections[0].MaskSection    = TRUE;
    reg1->Sections[0].CurrentProtect = PAGE_READWRITE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask_erase( &bi, &fc );

    ASSERT_MEM_EQ( r1, o1, 64 );
    ASSERT_MEM_EQ( r2, o2, 96 );

    free( r1 );
    free( r2 );

    PASS();
}

/* ================================================================== */
/*                    MULTI-REGION HANDLING                           */
/* ================================================================== */

static void test_multi_region_xor( void ) {
    TEST( "multi-region: XOR mask encrypts and restores 3 regions" );

    unsigned char r1[32], r2[48], r3[16];
    unsigned char o1[32], o2[48], o3[16];

    fill_pattern( r1, 32, "REGION_ONE" );
    fill_pattern( r2, 48, "REGION_TWO" );
    fill_pattern( r3, 16, "REGION_THREE" );
    memcpy( o1, r1, 32 );
    memcpy( o2, r2, 48 );
    memcpy( o3, r3, 16 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    char mask_key[MASK_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    /* Region 0: r1 */
    ALLOCATED_MEMORY_REGION *reg0 = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg0->AllocationBase = r1;
    reg0->RegionSize     = 32;
    reg0->Sections[0].BaseAddress    = r1;
    reg0->Sections[0].VirtualSize    = 32;
    reg0->Sections[0].MaskSection    = TRUE;
    reg0->Sections[0].CurrentProtect = PAGE_READWRITE;

    /* Region 1: r2 */
    ALLOCATED_MEMORY_REGION *reg1 = &bi.allocatedMemory.AllocatedMemoryRegions[1];
    reg1->AllocationBase = r2;
    reg1->RegionSize     = 48;
    reg1->Sections[0].BaseAddress    = r2;
    reg1->Sections[0].VirtualSize    = 48;
    reg1->Sections[0].MaskSection    = TRUE;
    reg1->Sections[0].CurrentProtect = PAGE_READWRITE;

    /* Region 2: r3 */
    ALLOCATED_MEMORY_REGION *reg2 = &bi.allocatedMemory.AllocatedMemoryRegions[2];
    reg2->AllocationBase = r3;
    reg2->RegionSize     = 16;
    reg2->Sections[0].BaseAddress    = r3;
    reg2->Sections[0].VirtualSize    = 16;
    reg2->Sections[0].MaskSection    = TRUE;
    reg2->Sections[0].CurrentProtect = PAGE_READWRITE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask( &bi, &fc );

    ASSERT_MEM_EQ( r1, o1, 32 );
    ASSERT_MEM_EQ( r2, o2, 48 );
    ASSERT_MEM_EQ( r3, o3, 16 );

    PASS();
}

static void test_multi_region_null_base( void ) {
    TEST( "multi-region: NULL AllocationBase region is skipped without crash" );

    unsigned char data[16];
    unsigned char orig[16];
    fill_pattern( data, 16, "SAFE" );
    memcpy( orig, data, 16 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    char mask_key[MASK_SIZE] = { 0x42 };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    /* Region 0: NULL base, should be skipped */
    bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = NULL;
    bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 32;

    /* Region 1: valid, with maskable section */
    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[1];
    reg->AllocationBase = data;
    reg->RegionSize     = 16;
    reg->Sections[0].BaseAddress    = data;
    reg->Sections[0].VirtualSize    = 16;
    reg->Sections[0].MaskSection    = TRUE;
    reg->Sections[0].CurrentProtect = PAGE_READWRITE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask( &bi, &fc );

    ASSERT_MEM_EQ( data, orig, 16 );

    PASS();
}

static void test_multi_region_zero_size( void ) {
    TEST( "multi-region: zero-size region is skipped without crash" );

    unsigned char data[16];
    unsigned char orig[16];
    fill_pattern( data, 16, "SKIP" );
    memcpy( orig, data, 16 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    char mask_key[MASK_SIZE] = { 0x42 };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    /* Region 0: zero RegionSize, should be skipped */
    bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = data;
    bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 0;

    /* Region 1: valid, with maskable section */
    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[1];
    reg->AllocationBase = data;
    reg->RegionSize     = 16;
    reg->Sections[0].BaseAddress    = data;
    reg->Sections[0].VirtualSize    = 16;
    reg->Sections[0].MaskSection    = TRUE;
    reg->Sections[0].CurrentProtect = PAGE_READWRITE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask( &bi, &fc );

    ASSERT_MEM_EQ( data, orig, 16 );

    PASS();
}

/* ================================================================== */
/*                       RC4 KEY USAGE                                */
/* ================================================================== */

static void test_rc4_key_all_16_bytes( void ) {
    TEST( "rc4 key: XOR uses all 16 bytes with correct wrapping" );

    unsigned char buf[32];
    unsigned char key[16] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01
    };

    memset( buf, 0, 32 );

    xor_region( buf, 32, key, 16 );

    for ( int i = 0; i < 16; i++ ) {
        ASSERT_EQ( buf[i], key[i] );
    }

    ASSERT_EQ( buf[0], buf[16] );
    ASSERT_EQ( buf[1], buf[17] );
    ASSERT_EQ( buf[15], buf[31] );

    for ( int i = 0; i < 16; i++ ) {
        ASSERT_EQ( buf[16 + i], key[i] );
    }

    PASS();
}

/* ================================================================== */
/*           PRODUCTION SLEEP MASK (NESTED STRUCT LAYOUT)             */
/* ================================================================== */

static void test_prod_mask_section_cycle( void ) {
    TEST( "prod sleep_mask: section-level XOR encrypt/decrypt cycle" );

    unsigned char data[64];
    unsigned char orig[64];
    fill_pattern( data, 64, "PROD_SECTION" );
    memcpy( orig, data, 64 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    char mask_key[MASK_SIZE] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD
    };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg->AllocationBase = data;
    reg->RegionSize     = 64;
    reg->Sections[0].BaseAddress  = data;
    reg->Sections[0].VirtualSize  = 64;
    reg->Sections[0].MaskSection  = TRUE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask_prod( &bi, &fc );

    ASSERT_MEM_EQ( data, orig, 64 );
    ASSERT_EQ( fc.retValue, 0xBEEF );

    PASS();
}

static void test_prod_mask_section_skip( void ) {
    TEST( "prod sleep_mask: MaskSection=FALSE sections are not encrypted" );

    unsigned char masked_data[32];
    unsigned char unmasked_data[32];
    unsigned char masked_orig[32];
    unsigned char unmasked_orig[32];

    fill_pattern( masked_data, 32, "MASKED" );
    fill_pattern( unmasked_data, 32, "NOMASK" );
    memcpy( masked_orig, masked_data, 32 );
    memcpy( unmasked_orig, unmasked_data, 32 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    char mask_key[MASK_SIZE] = {
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9,
        0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3
    };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg->AllocationBase = masked_data;
    reg->RegionSize     = 64;

    reg->Sections[0].BaseAddress = masked_data;
    reg->Sections[0].VirtualSize = 32;
    reg->Sections[0].MaskSection = TRUE;

    reg->Sections[1].BaseAddress = unmasked_data;
    reg->Sections[1].VirtualSize = 32;
    reg->Sections[1].MaskSection = FALSE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask_prod( &bi, &fc );

    /* Masked section should be restored after full cycle */
    ASSERT_MEM_EQ( masked_data, masked_orig, 32 );

    /* Unmasked section should never have been touched */
    ASSERT_MEM_EQ( unmasked_data, unmasked_orig, 32 );

    PASS();
}

static void test_prod_mask_empty_region( void ) {
    TEST( "prod sleep_mask: NULL AllocationBase region is skipped" );

    unsigned char data[16];
    unsigned char orig[16];
    fill_pattern( data, 16, "SAFE" );
    memcpy( orig, data, 16 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    char mask_key[MASK_SIZE] = { 0x42 };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    /* Region 0: NULL base, should be skipped */
    bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = NULL;
    bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 100;

    /* Region 1: valid, with maskable section */
    ALLOCATED_MEMORY_REGION *reg = &bi.allocatedMemory.AllocatedMemoryRegions[1];
    reg->AllocationBase = data;
    reg->RegionSize     = 16;
    reg->Sections[0].BaseAddress = data;
    reg->Sections[0].VirtualSize = 16;
    reg->Sections[0].MaskSection = TRUE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask_prod( &bi, &fc );

    ASSERT_MEM_EQ( data, orig, 16 );

    PASS();
}

static void test_prod_mask_multi_region_multi_section( void ) {
    TEST( "prod sleep_mask: 2 regions, multiple sections each" );

    unsigned char r1s1[32], r1s2[16], r2s1[48];
    unsigned char o1s1[32], o1s2[16], o2s1[48];

    fill_pattern( r1s1, 32, "R1SEC1" );
    fill_pattern( r1s2, 16, "R1SEC2" );
    fill_pattern( r2s1, 48, "R2SEC1" );
    memcpy( o1s1, r1s1, 32 );
    memcpy( o1s2, r1s2, 16 );
    memcpy( o2s1, r2s1, 48 );

    BEACON_INFO bi;
    memset( &bi, 0, sizeof( bi ) );

    char mask_key[MASK_SIZE] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA,
        0xBE, 0x01, 0x23, 0x45, 0x67, 0x89
    };
    memcpy( bi.mask, mask_key, MASK_SIZE );

    /* Region 0: 2 sections */
    ALLOCATED_MEMORY_REGION *reg0 = &bi.allocatedMemory.AllocatedMemoryRegions[0];
    reg0->AllocationBase = r1s1;
    reg0->RegionSize     = 48;
    reg0->Sections[0].BaseAddress = r1s1;
    reg0->Sections[0].VirtualSize = 32;
    reg0->Sections[0].MaskSection = TRUE;
    reg0->Sections[1].BaseAddress = r1s2;
    reg0->Sections[1].VirtualSize = 16;
    reg0->Sections[1].MaskSection = TRUE;

    /* Region 1: 1 section */
    ALLOCATED_MEMORY_REGION *reg1 = &bi.allocatedMemory.AllocatedMemoryRegions[1];
    reg1->AllocationBase = r2s1;
    reg1->RegionSize     = 48;
    reg1->Sections[0].BaseAddress = r2s1;
    reg1->Sections[0].VirtualSize = 48;
    reg1->Sections[0].MaskSection = TRUE;

    FUNCTION_CALL fc;
    memset( &fc, 0, sizeof( fc ) );
    fc.functionPtr = (PVOID) noop_func;
    fc.numOfArgs   = 0;
    fc.bMask       = TRUE;

    sleep_mask_prod( &bi, &fc );

    ASSERT_MEM_EQ( r1s1, o1s1, 32 );
    ASSERT_MEM_EQ( r1s2, o1s2, 16 );
    ASSERT_MEM_EQ( r2s1, o2s1, 48 );

    PASS();
}

/* ================================================================== */
/*                             MAIN                                   */
/* ================================================================== */

int main( void ) {
    TEST_SUITE( "Mask Operations" );

    /* XOR region symmetry */
    test_xor_roundtrip();
    test_xor_zero_key_identity();
    test_xor_single_byte_key();
    test_xor_16byte_key_wraps();
    test_xor_empty_buffer();
    test_xor_large_buffer();
    test_xor_guard_bytes();

    /* Dispatch call */
    test_dispatch_0arg();
    test_dispatch_1arg();
    test_dispatch_2arg();
    test_dispatch_3arg();
    test_dispatch_10arg();
    test_dispatch_null_function();

    /* Sleep mask full cycle */
    test_sleep_mask_full_cycle();
    test_sleep_mask_null_call();

    /* Beacon gate path */
    test_beacon_gate_path();

    /* Erase mask algorithm */
    test_erase_mask_backup_restore();
    test_erase_mask_zeros_during_sleep();
    test_erase_mask_multi_region();

    /* Multi-region handling */
    test_multi_region_xor();
    test_multi_region_null_base();
    test_multi_region_zero_size();

    /* RC4 key usage */
    test_rc4_key_all_16_bytes();

    /* Production mask (nested struct layout) */
    test_prod_mask_section_cycle();
    test_prod_mask_section_skip();
    test_prod_mask_empty_region();
    test_prod_mask_multi_region_multi_section();

    return TEST_SUMMARY();
}
