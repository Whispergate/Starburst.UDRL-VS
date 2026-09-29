#ifndef _SLEEPMASK_H_
#define _SLEEPMASK_H_

#include <windows.h>
#include "common.h"
#include "beacon_gate.h"

/*
 * BEACON_INFO - Passed by the Starburst agent to the sleep mask.
 *
 * Describes the beacon image location and memory regions that need to be
 * encrypted during sleep. The structure layout must match what the agent
 * populates in evasion_sleepmask_vs_sleep().
 */

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

typedef void (* SLEEPMASK_FUNC)( PSM_BEACON_INFO, PFUNCTION_CALL );

#endif
