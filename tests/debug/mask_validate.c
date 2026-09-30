/*
 * UDRL Mask Roundtrip Validation Tool
 *
 * Validates that a sleep mask implementation correctly encrypts and decrypts
 * beacon memory sections (CS BEACON_INFO) without corruption or overflow.
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

/* CS beacon.h 4.12 types: BEACON_INFO / ALLOCATED_MEMORY / FUNCTION_CALL.
 * Uses the project headers when available. */
#ifndef STARBURST_VERSION
#define STARBURST_VERSION  0x010400

typedef struct { char *ptr; size_t size; } HEAP_RECORD;
#define MASK_SIZE 13

typedef enum {
    PURPOSE_EMPTY, PURPOSE_GENERIC_BUFFER, PURPOSE_BEACON_MEMORY,
    PURPOSE_SLEEPMASK_MEMORY, PURPOSE_BOF_MEMORY, PURPOSE_UDC2_MEMORY,
    PURPOSE_USER_DEFINED_MEMORY = 1000
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
    LABEL_EMPTY, LABEL_BUFFER, LABEL_PEHEADER, LABEL_TEXT, LABEL_RDATA,
    LABEL_DATA, LABEL_PDATA, LABEL_RELOC, LABEL_USER_DEFINED = 1000
} ALLOCATED_MEMORY_LABEL;

typedef enum {
    METHOD_UNKNOWN, METHOD_VIRTUALALLOC, METHOD_HEAPALLOC,
    METHOD_MODULESTOMP, METHOD_NTMAPVIEW, METHOD_USER_DEFINED = 1000
} ALLOCATED_MEMORY_ALLOCATION_METHOD;

typedef struct _HEAPALLOC_INFO { PVOID HeapHandle; BOOL DestroyHeap; } HEAPALLOC_INFO;
typedef struct _MODULESTOMP_INFO { HMODULE ModuleHandle; } MODULESTOMP_INFO;

typedef union _ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
    HEAPALLOC_INFO   HeapAllocInfo;
    MODULESTOMP_INFO ModuleStompInfo;
    PVOID            Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_CLEANUP_INFORMATION {
    BOOL Cleanup;
    ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
    ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_SECTION {
    ALLOCATED_MEMORY_LABEL Label;
    PVOID  BaseAddress;
    SIZE_T VirtualSize;
    DWORD  CurrentProtect;
    DWORD  PreviousProtect;
    BOOL   MaskSection;
    DWORD  DripLoadPageSize;
} ALLOCATED_MEMORY_SECTION, *PALLOCATED_MEMORY_SECTION;

typedef struct _ALLOCATED_MEMORY_REGION {
    ALLOCATED_MEMORY_PURPOSE Purpose;
    PVOID  AllocationBase;
    SIZE_T RegionSize;
    DWORD  Type;
    DWORD  DripLoadAllocationGranularity;
    ALLOCATED_MEMORY_SECTION Sections[8];
    ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation;
} ALLOCATED_MEMORY_REGION, *PALLOCATED_MEMORY_REGION;

typedef struct {
    ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY, *PALLOCATED_MEMORY;

typedef struct {
    ALLOCATED_MEMORY allocatedMemory;
    unsigned char    mask[MASK_SIZE];
    HEAP_RECORD     *heap_records;
    int              num_heap_records;
} BEACON_INFO, *PBEACON_INFO;

#define DLL_BEACON_USER_DATA        0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32

typedef struct {
    unsigned int       version;
    PVOID              syscalls;
    char               custom[BEACON_USER_DATA_CUSTOM_SIZE];
    PVOID              rtls;
    PALLOCATED_MEMORY  allocatedMemory;
} USER_DATA, *PUSER_DATA;
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

#define UDRL_DEBUG
#include "debug.h"

/* Guard byte used to detect buffer overflow/underflow */
#define GUARD_BYTE  0xCD
#define GUARD_SIZE  32

/* Mask function signature matching sleep_mask() */
typedef void (*MASK_FUNC)(PBEACON_INFO, PFUNCTION_CALL);

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

/* Set up BEACON_INFO with the given mask key */
static void setup_beacon_info(BEACON_INFO *bi, unsigned char *key, unsigned int key_len) {
    memset(bi, 0, sizeof(*bi));
    unsigned int copy_len = key_len < MASK_SIZE ? key_len : MASK_SIZE;
    memcpy(bi->mask, key, copy_len);
}

/*
 * Run a single roundtrip test:
 *   1. Save original buffer contents for all maskable sections
 *   2. Call mask with bMask=TRUE (mask encrypts, executes sleep, then decrypts)
 *   3. Compare buffer to original
 *   4. Check guard bytes
 *
 * originals/sizes/count: parallel arrays of saved data for each maskable section.
 * sec_bufs: the actual section BaseAddress pointers (for guard check).
 */
static int run_roundtrip(const char *name, MASK_FUNC mask_fn,
                         BEACON_INFO *bi,
                         BYTE **originals, DWORD *sizes, BYTE **sec_bufs,
                         int sec_count) {
    int fail = 0;

    /* Save copies of all maskable section data */
    for (int i = 0; i < sec_count; i++) {
        memcpy(originals[i], sec_bufs[i], sizes[i]);
    }

    /* Call the mask (encrypt, sleep, decrypt) */
    FUNCTION_CALL fc;
    setup_mask_call(&fc);
    mask_fn(bi, &fc);

    /* Verify roundtrip: data should match original */
    for (int i = 0; i < sec_count; i++) {
        if (memcmp(sec_bufs[i], originals[i], sizes[i]) != 0) {
            UDRL_LOG_ERR("%s: section[%d] data corrupted after roundtrip", name, i);
            BYTE *cur = sec_bufs[i];
            for (DWORD j = 0; j < sizes[i]; j++) {
                if (cur[j] != originals[i][j]) {
                    UDRL_LOG_ERR("  first mismatch at offset %d: got 0x%02x, expected 0x%02x",
                        (int)j, cur[j], originals[i][j]);
                    break;
                }
            }
            fail++;
        } else {
            UDRL_LOG_OK("%s: section[%d] (%d bytes) roundtrip OK", name, i, (int)sizes[i]);
        }

        /* Check guard bytes */
        char label[128];
        snprintf(label, sizeof(label), "%s section[%d]", name, i);
        if (!check_guards(label, sec_bufs[i], sizes[i])) {
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

    /* Test key (non-zero, known pattern, MASK_SIZE bytes) */
    unsigned char key[MASK_SIZE] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89
    };

    UDRL_LOG_INFO("=== UDRL Mask Roundtrip Validation ===");

    /* ---- Test 1: Small buffer (16 bytes), one region one section ---- */
    {
        test_num++;
        const char *name = "Test 1: 16-byte buffer";
        UDRL_LOG_INFO("--- %s ---", name);

        BYTE *buf = alloc_guarded(16);
        BYTE orig[16];
        BYTE *originals[1] = { orig };
        BYTE *sec_bufs[1]  = { buf };
        DWORD sizes[1]     = { 16 };

        fill_pattern(buf, 16);

        BEACON_INFO bi;
        setup_beacon_info(&bi, key, MASK_SIZE);
        bi.allocatedMemory.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
        bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 16;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].Label          = LABEL_TEXT;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].BaseAddress    = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].VirtualSize    = 16;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].MaskSection    = TRUE;

        int f = run_roundtrip(name, mask_fn, &bi, originals, sizes, sec_bufs, 1);
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
        BYTE *sec_bufs[1]  = { buf };
        DWORD sizes[1]     = { 4096 };

        fill_pattern(buf, 4096);

        BEACON_INFO bi;
        setup_beacon_info(&bi, key, MASK_SIZE);
        bi.allocatedMemory.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
        bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 4096;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].Label          = LABEL_TEXT;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].BaseAddress    = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].VirtualSize    = 4096;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].MaskSection    = TRUE;

        int f = run_roundtrip(name, mask_fn, &bi, originals, sizes, sec_bufs, 1);
        fail += f;
        if (f == 0) pass++;

        free(orig);
        free_guarded(buf);
    }

    /* ---- Test 3: Multiple regions (3 regions, each with one section) ---- */
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

        BEACON_INFO bi;
        setup_beacon_info(&bi, key, MASK_SIZE);

        for (int i = 0; i < 3; i++) {
            bi.allocatedMemory.AllocatedMemoryRegions[i].Purpose       = PURPOSE_BEACON_MEMORY;
            bi.allocatedMemory.AllocatedMemoryRegions[i].AllocationBase = bufs[i];
            bi.allocatedMemory.AllocatedMemoryRegions[i].RegionSize     = sizes[i];
            bi.allocatedMemory.AllocatedMemoryRegions[i].Sections[0].Label          = LABEL_TEXT;
            bi.allocatedMemory.AllocatedMemoryRegions[i].Sections[0].BaseAddress    = bufs[i];
            bi.allocatedMemory.AllocatedMemoryRegions[i].Sections[0].VirtualSize    = sizes[i];
            bi.allocatedMemory.AllocatedMemoryRegions[i].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
            bi.allocatedMemory.AllocatedMemoryRegions[i].Sections[0].MaskSection    = TRUE;
        }

        int f = run_roundtrip(name, mask_fn, &bi, origs, sizes, bufs, 3);
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
        BYTE *sec_bufs[1]  = { buf };
        DWORD sizes[1]     = { 256 };

        memset(buf, 0x00, 256);

        BEACON_INFO bi;
        setup_beacon_info(&bi, key, MASK_SIZE);
        bi.allocatedMemory.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
        bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 256;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].Label          = LABEL_TEXT;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].BaseAddress    = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].VirtualSize    = 256;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].MaskSection    = TRUE;

        int f = run_roundtrip(name, mask_fn, &bi, originals, sizes, sec_bufs, 1);
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
        BYTE *sec_bufs[1]  = { buf };
        DWORD sizes[1]     = { 256 };

        memset(buf, 0xFF, 256);

        BEACON_INFO bi;
        setup_beacon_info(&bi, key, MASK_SIZE);
        bi.allocatedMemory.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
        bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 256;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].Label          = LABEL_TEXT;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].BaseAddress    = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].VirtualSize    = 256;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].MaskSection    = TRUE;

        int f = run_roundtrip(name, mask_fn, &bi, originals, sizes, sec_bufs, 1);
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

        /* This test uses a 1-byte section, which stresses alignment edge cases */
        BYTE *buf = alloc_guarded(1);
        BYTE orig[1];
        BYTE *originals[1] = { orig };
        BYTE *sec_bufs[1]  = { buf };
        DWORD sizes[1]     = { 1 };

        buf[0] = 0x42;

        BEACON_INFO bi;
        setup_beacon_info(&bi, key, MASK_SIZE);
        bi.allocatedMemory.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
        bi.allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].RegionSize     = 1;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].Label          = LABEL_TEXT;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].BaseAddress    = buf;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].VirtualSize    = 1;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
        bi.allocatedMemory.AllocatedMemoryRegions[0].Sections[0].MaskSection    = TRUE;

        int f = run_roundtrip(name, mask_fn, &bi, originals, sizes, sec_bufs, 1);
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

/* Reference mask implementation: XOR encrypt, dispatch call, XOR decrypt
 * Uses CS BEACON_INFO with nested region/section iteration. */
static void reference_mask(PBEACON_INFO bi, PFUNCTION_CALL fc) {
    if (!fc) return;

    if (!fc->bMask) {
        /* Beacon Gate path: no masking */
        fc->retValue = ((ULONG_PTR (__stdcall *)(ULONG_PTR, ULONG_PTR))fc->functionPtr)(
            fc->args[0], fc->args[1]);
        return;
    }

    unsigned char *key     = bi->mask;
    unsigned int   key_len = MASK_SIZE;

    /* Encrypt: iterate regions then sections */
    for (int r = 0; r < 6; r++) {
        ALLOCATED_MEMORY_REGION *reg = &bi->allocatedMemory.AllocatedMemoryRegions[r];
        if (!reg->AllocationBase || reg->RegionSize == 0)
            continue;
        for (int s = 0; s < 8; s++) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if (!sec->BaseAddress || sec->VirtualSize == 0 || !sec->MaskSection)
                continue;
            xor_region((unsigned char *)sec->BaseAddress,
                       (unsigned int)sec->VirtualSize, key, key_len);
        }
    }

    /* Execute queued call */
    fc->retValue = ((ULONG_PTR (__stdcall *)(ULONG_PTR, ULONG_PTR))fc->functionPtr)(
        fc->args[0], fc->args[1]);

    /* Decrypt: iterate regions then sections */
    for (int r = 0; r < 6; r++) {
        ALLOCATED_MEMORY_REGION *reg = &bi->allocatedMemory.AllocatedMemoryRegions[r];
        if (!reg->AllocationBase || reg->RegionSize == 0)
            continue;
        for (int s = 0; s < 8; s++) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if (!sec->BaseAddress || sec->VirtualSize == 0 || !sec->MaskSection)
                continue;
            xor_region((unsigned char *)sec->BaseAddress,
                       (unsigned int)sec->VirtualSize, key, key_len);
        }
    }
}

int main(void) {
    printf("[UDRL] Mask roundtrip validation using built-in reference mask\n\n");
    int result = udrl_mask_validate(reference_mask);
    return result;
}
