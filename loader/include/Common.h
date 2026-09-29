#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

#include <windows.h>
#include <Native.h>
#include <Macros.h>
#include <Ldr.h>
#include <Defs.h>
#include <Utils.h>

EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef struct _INSTANCE {

    BUFFER Base;

    struct {
        /* ntdll.dll */
        D_API( RtlAllocateHeap        )
        D_API( NtProtectVirtualMemory  )
        D_API( NtFlushInstructionCache )

        /* kernel32.dll */
        D_API( LoadLibraryA   )
        D_API( LoadLibraryExW )
        D_API( GetProcAddress )
        D_API( VirtualAlloc   )
        D_API( VirtualProtect )
        D_API( VirtualFree    )

    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
    } Modules;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Main(
    _In_ PVOID Param
);

#endif
