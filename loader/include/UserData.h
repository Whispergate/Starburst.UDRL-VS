#ifndef UDRL_USER_DATA_H
#define UDRL_USER_DATA_H

#include <windows.h>

/*
 * UDRL_USER_DATA - Bridge between the UDRL loader and the Starburst agent.
 *
 * The UDRL populates this structure before transferring execution to the
 * agent's DllMain. It describes how and where the agent was loaded so the
 * sleep mask can properly encrypt/decrypt the correct memory regions.
 *
 * The pointer is passed as lpvReserved in DllMain(DLL_PROCESS_ATTACH, ...).
 */

#define UDRL_MAGIC  0x5442525354ULL   /* "STRBT" */

#define LOAD_TYPE_VIRTUAL_ALLOC   0
#define LOAD_TYPE_MODULE_STOMP    1

typedef struct _UDRL_REGION {
    PVOID  base;
    DWORD  size;
    DWORD  protect;
} UDRL_REGION;

#define MAX_UDRL_REGIONS  8

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
