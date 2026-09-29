#pragma once
#include <windows.h>
#include <beacon.h>
#include <Native.h>
#include <Macros.h>
#include <stdio.h>

// Define all of the DLLs that we require beyond Ntdll and Kernel32
#define DLL_LIST \
    DLL_ENTRY( User32 ) \
    DLL_ENTRY( Msvcrt )

#define API_LIST \
    \
    /* ntdll.dll */\
    \
    API_ENTRY( RtlAllocateHeap, Ntdll ) \
    API_ENTRY( NtProtectVirtualMemory, Ntdll ) \
    API_ENTRY( NtFlushInstructionCache, Ntdll ) \
    \
    /* Kernel32.dll */\
    \
    API_ENTRY( LoadLibraryA, Kernel32 ) \
    API_ENTRY( LoadLibraryW, Kernel32 ) \
    API_ENTRY( LoadLibraryExW, Kernel32 ) \
    API_ENTRY( GetProcAddress, Kernel32 ) \
    API_ENTRY( VirtualAlloc, Kernel32 ) \
    API_ENTRY( VirtualProtect, Kernel32 ) \
    API_ENTRY( VirtualFree, Kernel32 ) \
    API_ENTRY( AllocConsole, Kernel32 ) \
    API_ENTRY( GetConsoleWindow, Kernel32 ) \
    \
    /* Msvcrt.dll */\
    \
    API_ENTRY( freopen, Msvcrt ) \
    API_ENTRY( __iob_func, Msvcrt ) \
    API_ENTRY( printf, Msvcrt ) \
    API_ENTRY( _snprintf, Msvcrt ) \
    API_ENTRY( vprintf, Msvcrt ) \
    API_ENTRY( getchar, Msvcrt ) \
    \
    /* User32.dll */\
    \
    API_ENTRY( ShowWindow, User32 ) \
    API_ENTRY( SetForegroundWindow, User32 ) \
    API_ENTRY( UpdateWindow, User32 ) \
    API_ENTRY( MessageBoxW, User32 )

    EXTERN_C VOID PrintMsg(const char*, BOOL, const char*, ...);