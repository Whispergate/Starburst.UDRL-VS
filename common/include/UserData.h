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

#define STARBURST_VERSION  0x010400   /* 1.4.0  (0xMMmmPP like CS convention) */

#define LOAD_TYPE_VIRTUAL_ALLOC   0
#define LOAD_TYPE_MODULE_STOMP    1

#define UDRL_CUSTOM_SIZE  32

/* Region purpose constants (mirrors CS PURPOSE_* from beacon.h) */
#define UDRL_PURPOSE_AGENT_IMAGE        0
#define UDRL_PURPOSE_SLEEPMASK_MEMORY   1
#define UDRL_PURPOSE_BOF_MEMORY         2

/* Section label constants (mirrors CS LABEL_* from beacon.h) */
#define UDRL_LABEL_NONE       0
#define UDRL_LABEL_BUFFER     1
#define UDRL_LABEL_TEXT       2
#define UDRL_LABEL_RDATA      3
#define UDRL_LABEL_DATA       4

#define MAX_UDRL_SECTIONS  4
#define MAX_UDRL_REGIONS   8

typedef struct _UDRL_SECTION {
    DWORD   label;
    PVOID   base;
    SIZE_T  size;
    DWORD   protect;
} UDRL_SECTION;

typedef struct _UDRL_REGION {
    DWORD         purpose;
    PVOID         alloc_base;
    SIZE_T        region_size;
    UDRL_SECTION  sections[MAX_UDRL_SECTIONS];
    DWORD         section_count;
} UDRL_REGION;

typedef struct _UDRL_USER_DATA {
    UINT64        magic;
    DWORD         version;
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
    char          custom[UDRL_CUSTOM_SIZE];
} UDRL_USER_DATA;

#endif
