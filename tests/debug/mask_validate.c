/*
 * UDRL Mask Roundtrip Validation Tool
 *
 * Validates that a sleep mask implementation correctly encrypts and decrypts
 * beacon memory regions without corruption or overflow.
 *
 * Build (MinGW):
 *   x86_64-w64-mingw32-gcc -DUDRL_DEBUG -o mask_validate.exe mask_validate.c
 *
 * Usage:
 *   mask_validate.exe
 *
 * Or call udrl_mask_validate() from your own code with a function pointer
 * to your mask entry point.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* SM_BEACON_INFO / SM_REGION / FUNCTION_CALL definitions.
 * Uses the project headers when available. */
#ifndef SM_MAX_REGIONS
#define SM_MAX_REGIONS  8

typedef struct _SM_REGION {
    PVOID  base;
    DWORD  size;
    DWORD  protect;
} SM_REGION;

typedef struct _SM_BEACON_INFO {
    PVOID           beacon_base;
    DWORD           beacon_size;
    SM_REGION       regions[SM_MAX_REGIONS];
    int             region_count;
    unsigned char   rc4_key[16];
} SM_BEACON_INFO, *PSM_BEACON_INFO;
#endif

#ifndef MAX_BEACON_GATE_ARGUMENTS
#define MAX_BEACON_GATE_ARGUMENTS 10

typedef enum _WinApi {
    INTERNETOPENA, INTERNETCONNECTA,
    VIRTUALALLOC, VIRTUALALLOCEX,
    VIRTUALPROTECT, VIRTUALPROTECTEX, VIRTUALFREE,
    GETTHREADCONTEXT, SETTHREADCONTEXT,
    RESUMETHREAD, CREATETHREAD, CREATEREMOTETHREAD,
    OPENPROCESS, OPENTHREAD, CLOSEHANDLE,
    CREATEFILEMAPPING, MAPVIEWOFFILE, UNMAPVIEWOFFILE,
    VIRTUALQUERY, DUPLICATEHANDLE,
    READPROCESSMEMORY, WRITEPROCESSMEMORY,
    EXITTHREAD, VIRTUALFREEEX, VIRTUALQUERYEX,
    WAITFORSINGLEOBJECT, SLEEP
} WinApi;

typedef struct {
    PVOID     functionPtr;
    WinApi    function;
    int       numOfArgs;
    ULONG_PTR args[MAX_BEACON_GATE_ARGUMENTS];
    BOOL      bMask;
    ULONG_PTR retValue;
} FUNCTION_CALL, *PFUNCTION_CALL;
#endif

/* Provide a minimal UDRL_USER_DATA stub so debug.h compiles.
 * The mask validator only uses SM_BEACON_INFO, not UDRL_USER_DATA. */
#ifndef UDRL_MAGIC
#define UDRL_MAGIC              0x5442525354ULL
#define LOAD_TYPE_VIRTUAL_ALLOC 0
#define LOAD_TYPE_MODULE_STOMP  1
#define MAX_UDRL_REGIONS        8

typedef struct _UDRL_REGION {
    PVOID  base;
    DWORD  size;
    DWORD  protect;
} UDRL_REGION;

typedef struct _UDRL_USER_DATA {
    UINT64        magic;
    DWORD         load_type;
    PVOID         agent_base;
    DWORD         agent_size;
    PVOID         loader_base;
    DWORD         loader_size;
    HMODULE       stomped_module;
    PVOID         stomped_text_base;
    DWORD         stomped_text_size;
    UDRL_REGION   regions[MAX_UDRL_REGIONS];
    DWORD         region_count;
    BYTE          rc4_key[16];
    BYTE          reserved[64];
} UDRL_USER_DATA;
#endif

#define UDRL_DEBUG
#include "debug.h"

/* Guard byte used to detect buffer overflow/underflow */
#define GUARD_BYTE  0xCD
#define GUARD_SIZE  32

/* Mask function signature matching sleep_mask() */
typedef void (*MASK_FUNC)(PSM_BEACON_INFO, PFUNCTION_CALL);

/* No-op sleep function for the FUNCTION_CALL dispatch */
static ULONG_PTR __stdcall noop_sleep(ULONG_PTR handle, ULONG_PTR ms) {
    (void)handle; (void)ms;
    Sleep(1);
    return 0;
}

/* Allocate a test buffer with guard zones on both sides.
 * Returns the usable region pointer. The caller must free
 * the returned pointer minus GUARD_SIZE. */
static BYTE *alloc_guarded(DWORD size) {
    BYTE *raw = (BYTE *)malloc(GUARD_SIZE + size + GUARD_SIZE);
    if (!raw) return NULL;
    memset(raw, GUARD_BYTE, GUARD_SIZE);
    memset(raw + GUARD_SIZE + size, GUARD_BYTE, GUARD_SIZE);
    return raw + GUARD_SIZE;
}

/* Free a buffer allocated with alloc_guarded */
static void free_guarded(BYTE *buf) {
    if (buf) free(buf - GUARD_SIZE);
}

/* Check that guard bytes are intact around a region */
static BOOL check_guards(const char *label, BYTE *buf, DWORD size) {
    BYTE *before = buf - GUARD_SIZE;
    BYTE *after  = buf + size;

    for (DWORD i = 0; i < GUARD_SIZE; i++) {
        if (before[i] != GUARD_BYTE) {
            UDRL_LOG_ERR("%s: guard underflow at offset -%d (0x%02x, expected 0x%02x)",
                label, (int)(GUARD_SIZE - i), before[i], GUARD_BYTE);
            return FALSE;
        }
        if (after[i] != GUARD_BYTE) {
            UDRL_LOG_ERR("%s: guard overflow at offset +%d (0x%02x, expected 0x%02x)",
                label, (int)(size + i), after[i], GUARD_BYTE);
            return FALSE;
        }
    }
    return TRUE;
}

/* Fill a buffer with a repeating pattern for roundtrip comparison */
static void fill_pattern(BYTE *buf, DWORD size) {
    for (DWORD i = 0; i < size; i++) {
        buf[i] = (BYTE)(i & 0xFF);
    }
}

/* Set up a FUNCTION_CALL for the mask path (bMask=TRUE, calls noop_sleep) */
static void setup_mask_call(FUNCTION_CALL *fc) {
    memset(fc, 0, sizeof(*fc));
    fc->functionPtr = (PVOID)noop_sleep;
    fc->function    = WAITFORSINGLEOBJECT;
    fc->numOfArgs   = 2;
    fc->args[0]     = (ULONG_PTR)GetCurrentThread();
    fc->args[1]     = 1;
    fc->bMask       = TRUE;
}

/* Set up SM_BEACON_INFO with the given test key */
static void setup_beacon_info(SM_BEACON_INFO *bi, unsigned char *key) {
    memset(bi, 0, sizeof(*bi));
    memcpy(bi->rc4_key, key, 16);
}

/*
 * Run a single roundtrip test:
 *   1. Save original buffer contents
 *   2. Call mask with bMask=TRUE (mask encrypts, executes sleep, then decrypts)
 *   3. Compare buffer to original
 *   4. Check guard bytes
 */
static int run_roundtrip(const char *name, MASK_FUNC mask_fn,
                         SM_BEACON_INFO *bi, BYTE **originals) {
    int fail = 0;

    /* Save copies of all region data */
    for (int i = 0; i < bi->region_count; i++) {
        memcpy(originals[i], bi->regions[i].base, bi->regions[i].size);
    }

    /* Call the mask (encrypt, sleep, decrypt) */
    FUNCTION_CALL fc;
    setup_mask_call(&fc);
    mask_fn(bi, &fc);

    /* Verify roundtrip: data should match original */
    for (int i = 0; i < bi->region_count; i++) {
        if (memcmp(bi->regions[i].base, originals[i], bi->regions[i].size) != 0) {
            UDRL_LOG_ERR("%s: region[%d] data corrupted after roundtrip", name, i);
            /* Show first mismatch */
            BYTE *cur = (BYTE *)bi->regions[i].base;
            for (DWORD j = 0; j < bi->regions[i].size; j++) {
                if (cur[j] != originals[i][j]) {
                    UDRL_LOG_ERR("  first mismatch at offset %d: got 0x%02x, expected 0x%02x",
                        (int)j, cur[j], originals[i][j]);
                    break;
                }
            }
            fail++;
        } else {
            UDRL_LOG_OK("%s: region[%d] (%d bytes) roundtrip OK", name, i, bi->regions[i].size);
        }

        /* Check guard bytes */
        char label[128];
        snprintf(label, sizeof(label), "%s region[%d]", name, i);
        if (!check_guards(label, (BYTE *)bi->regions[i].base, bi->regions[i].size)) {
            fail++;
        }
    }

    return fail;
}

/*
 * udrl_mask_validate
 *
 * Runs a suite of roundtrip tests against a mask implementation.
 * Returns 0 if all tests pass, or the number of failures.
 */
int udrl_mask_validate(MASK_FUNC mask_fn) {
    int pass = 0;
    int fail = 0;
    int test_num = 0;

    /* Test key (non-zero, known pattern) */
    unsigned char key[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    UDRL_LOG_INFO("=== UDRL Mask Roundtrip Validation ===");

    /* ---- Test 1: Small buffer (16 bytes) ---- */
    {
        test_num++;
        const char *name = "Test 1: 16-byte buffer";
        UDRL_LOG_INFO("--- %s ---", name);

        BYTE *buf = alloc_guarded(16);
        BYTE orig[16];
        BYTE *originals[1] = { orig };

        fill_pattern(buf, 16);

        SM_BEACON_INFO bi;
        setup_beacon_info(&bi, key);
        bi.beacon_base  = buf;
        bi.beacon_size  = 16;
        bi.regions[0].base    = buf;
        bi.regions[0].size    = 16;
        bi.regions[0].protect = PAGE_EXECUTE_READ;
        bi.region_count = 1;

        int f = run_roundtrip(name, mask_fn, &bi, originals);
        fail += f;
        if (f == 0) pass++;

        free_guarded(buf);
    }

    /* ---- Test 2: Page-sized buffer (4096 bytes) ---- */
    {
        test_num++;
        const char *name = "Test 2: 4096-byte buffer";
        UDRL_LOG_INFO("--- %s ---", name);

        BYTE *buf = alloc_guarded(4096);
        BYTE *orig = (BYTE *)malloc(4096);
        BYTE *originals[1] = { orig };

        fill_pattern(buf, 4096);

        SM_BEACON_INFO bi;
        setup_beacon_info(&bi, key);
        bi.beacon_base  = buf;
        bi.beacon_size  = 4096;
        bi.regions[0].base    = buf;
        bi.regions[0].size    = 4096;
        bi.regions[0].protect = PAGE_EXECUTE_READ;
        bi.region_count = 1;

        int f = run_roundtrip(name, mask_fn, &bi, originals);
        fail += f;
        if (f == 0) pass++;

        free(orig);
        free_guarded(buf);
    }

    /* ---- Test 3: Multiple regions (3 regions of different sizes) ---- */
    {
        test_num++;
        const char *name = "Test 3: 3 regions";
        UDRL_LOG_INFO("--- %s ---", name);

        DWORD sizes[3] = { 64, 512, 2048 };
        BYTE *bufs[3];
        BYTE *origs[3];

        for (int i = 0; i < 3; i++) {
            bufs[i]  = alloc_guarded(sizes[i]);
            origs[i] = (BYTE *)malloc(sizes[i]);
            fill_pattern(bufs[i], sizes[i]);
        }

        SM_BEACON_INFO bi;
        setup_beacon_info(&bi, key);
        bi.beacon_base  = bufs[0];
        bi.beacon_size  = sizes[0];
        bi.region_count = 3;

        for (int i = 0; i < 3; i++) {
            bi.regions[i].base    = bufs[i];
            bi.regions[i].size    = sizes[i];
            bi.regions[i].protect = PAGE_EXECUTE_READ;
        }

        int f = run_roundtrip(name, mask_fn, &bi, origs);
        fail += f;
        if (f == 0) pass++;

        for (int i = 0; i < 3; i++) {
            free(origs[i]);
            free_guarded(bufs[i]);
        }
    }

    /* ---- Test 4: All-zero buffer ---- */
    {
        test_num++;
        const char *name = "Test 4: all-zero buffer";
        UDRL_LOG_INFO("--- %s ---", name);

        BYTE *buf = alloc_guarded(256);
        BYTE *orig = (BYTE *)malloc(256);
        BYTE *originals[1] = { orig };

        memset(buf, 0x00, 256);

        SM_BEACON_INFO bi;
        setup_beacon_info(&bi, key);
        bi.beacon_base  = buf;
        bi.beacon_size  = 256;
        bi.regions[0].base    = buf;
        bi.regions[0].size    = 256;
        bi.regions[0].protect = PAGE_EXECUTE_READ;
        bi.region_count = 1;

        int f = run_roundtrip(name, mask_fn, &bi, originals);
        fail += f;
        if (f == 0) pass++;

        free(orig);
        free_guarded(buf);
    }

    /* ---- Test 5: All-0xFF buffer ---- */
    {
        test_num++;
        const char *name = "Test 5: all-0xFF buffer";
        UDRL_LOG_INFO("--- %s ---", name);

        BYTE *buf = alloc_guarded(256);
        BYTE *orig = (BYTE *)malloc(256);
        BYTE *originals[1] = { orig };

        memset(buf, 0xFF, 256);

        SM_BEACON_INFO bi;
        setup_beacon_info(&bi, key);
        bi.beacon_base  = buf;
        bi.beacon_size  = 256;
        bi.regions[0].base    = buf;
        bi.regions[0].size    = 256;
        bi.regions[0].protect = PAGE_EXECUTE_READ;
        bi.region_count = 1;

        int f = run_roundtrip(name, mask_fn, &bi, originals);
        fail += f;
        if (f == 0) pass++;

        free(orig);
        free_guarded(buf);
    }

    /* ---- Test 6: Verify guard bytes (overflow detection) ---- */
    {
        test_num++;
        const char *name = "Test 6: guard byte integrity";
        UDRL_LOG_INFO("--- %s ---", name);

        /* This test uses a 1-byte region, which stresses alignment edge cases */
        BYTE *buf = alloc_guarded(1);
        BYTE orig[1];
        BYTE *originals[1] = { orig };

        buf[0] = 0x42;

        SM_BEACON_INFO bi;
        setup_beacon_info(&bi, key);
        bi.beacon_base  = buf;
        bi.beacon_size  = 1;
        bi.regions[0].base    = buf;
        bi.regions[0].size    = 1;
        bi.regions[0].protect = PAGE_EXECUTE_READ;
        bi.region_count = 1;

        int f = run_roundtrip(name, mask_fn, &bi, originals);
        fail += f;
        if (f == 0) pass++;

        free_guarded(buf);
    }

    /* ---- Summary ---- */
    UDRL_LOG_INFO("=================================");
    UDRL_LOG_INFO("Results: %d/%d tests passed, %d failed", pass, test_num, fail);
    if (fail == 0) {
        UDRL_LOG_OK("All mask validation tests passed.");
    } else {
        UDRL_LOG_ERR("%d test(s) failed.", fail);
    }

    return fail;
}

/* ---- Built-in reference mask for demonstration ---- */

/* XOR mask matching the template in mask/src/main.c */
static void xor_region(unsigned char *buf, unsigned int len,
                       unsigned char *key, unsigned int key_len) {
    for (unsigned int i = 0; i < len; i++) {
        buf[i] ^= key[i % key_len];
    }
}

/* Reference mask implementation: XOR encrypt, dispatch call, XOR decrypt */
static void reference_mask(PSM_BEACON_INFO bi, PFUNCTION_CALL fc) {
    if (!fc) return;

    if (!fc->bMask) {
        /* Beacon Gate path: no masking */
        fc->retValue = ((ULONG_PTR (__stdcall *)(ULONG_PTR, ULONG_PTR))fc->functionPtr)(
            fc->args[0], fc->args[1]);
        return;
    }

    unsigned char *key     = bi->rc4_key;
    unsigned int   key_len = 16;

    /* Encrypt */
    for (int i = 0; i < bi->region_count; i++) {
        if (bi->regions[i].base && bi->regions[i].size) {
            xor_region((unsigned char *)bi->regions[i].base,
                       bi->regions[i].size, key, key_len);
        }
    }

    /* Execute queued call */
    fc->retValue = ((ULONG_PTR (__stdcall *)(ULONG_PTR, ULONG_PTR))fc->functionPtr)(
        fc->args[0], fc->args[1]);

    /* Decrypt */
    for (int i = 0; i < bi->region_count; i++) {
        if (bi->regions[i].base && bi->regions[i].size) {
            xor_region((unsigned char *)bi->regions[i].base,
                       bi->regions[i].size, key, key_len);
        }
    }
}

int main(void) {
    printf("[UDRL] Mask roundtrip validation using built-in reference mask\n\n");
    int result = udrl_mask_validate(reference_mask);
    return result;
}
