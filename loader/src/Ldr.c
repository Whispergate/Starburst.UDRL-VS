#include <Common.h>
#include <Constexpr.h>

/*!
 * @brief
 *  resolve module from peb
 *
 * @param Buffer
 *  Buffer: either string or hash
 *
 * @param Hashed
 *  is the Buffer a hash value
 *
 * @return
 *  module base pointer
 */
FUNC PVOID LdrModulePeb(
    _In_ ULONG Hash
) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );

        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash ) {
            return Data->DllBase;
        }
    }

    return NULL;
}

/*!
 * @brief
 *  retrieve image header
 *
 * @param Image
 *  image base pointer to retrieve header from
 *
 * @return
 *  pointer to Nt Header
 */
FUNC PIMAGE_NT_HEADERS LdrpImageHeader(
        _In_ PVOID Image
) {
    PIMAGE_DOS_HEADER DosHeader = { 0 };
    PIMAGE_NT_HEADERS NtHeader  = { 0 };

    DosHeader = C_PTR( Image );

    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return NULL;
    }

    NtHeader = C_PTR( U_PTR( Image ) + DosHeader->e_lfanew );

    if ( NtHeader->Signature != IMAGE_NT_SIGNATURE ) {
        return NULL;
    }

    return NtHeader;
}

FUNC PVOID LdrFunction(
    _In_ PVOID Library,
    _In_ ULONG Function
) {
    PVOID                   Address    = { 0 };
    PIMAGE_NT_HEADERS       NtHeader   = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir     = { 0 };
    SIZE_T                  ExpDirSize = { 0 };
    PDWORD                  AddrNames  = { 0 };
    PDWORD                  AddrFuncs  = { 0 };
    PWORD                   AddrOrdns  = { 0 };
    PCHAR                   FuncName   = { 0 };
    CHAR                    FwdLibrary [ MAX_PATH ] = { 0 };
    CHAR                    FwdFunction[ MAX_PATH ] = { 0 };    
    PVOID                   FwdLibraryBase = { 0 };
    UINT32                  Index = { 0 };
    ANSI_STRING             AnsiString = { 0 };
    STARDUST_INSTANCE

    //
    // sanity check arguments
    //
    if ( ! Library || ! Function ) {
        return NULL;
    }

    //
    // retrieve header of library
    //
    if ( ! ( NtHeader = LdrpImageHeader( Library ) ) ) {
        return NULL;
    }

    //
    // parse the header export address table
    //
    ExpDir     = C_PTR( Library + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSize = NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;
    AddrNames  = C_PTR( Library + ExpDir->AddressOfNames );
    AddrFuncs  = C_PTR( Library + ExpDir->AddressOfFunctions );
    AddrOrdns  = C_PTR( Library + ExpDir->AddressOfNameOrdinals );

    //
    // iterate over export address table director
    //
    for ( DWORD i = 0; i < ExpDir->NumberOfNames; i++ ) {
        //
        // retrieve function name
        //
        FuncName = C_PTR( U_PTR( Library ) + AddrNames[ i ] );

        //
        // hash function name from Iat and
        // check the function name is what we are searching for.
        // if not found keep searching.
        //
        if ( HashString( FuncName, 0 ) != Function ) {
            continue;
        }

        //
        // resolve function pointer
        //
        Address = C_PTR( U_PTR( Library ) + AddrFuncs[ AddrOrdns[ i ] ] );

        //
        // check if function is a forwarded function
        //
        if ( ( U_PTR( Address ) >= U_PTR( ExpDir ) ) &&
             ( U_PTR( Address ) <  U_PTR( ExpDir ) + ExpDirSize )
        ) {
            // where is the dot
            Index = CopyDotStr( Address );

            // Copy the library from our string
            MmCopy( FwdLibrary,  Address, Index );

            // Copy the function from our string
            MmCopy( FwdFunction, C_PTR( Address + Index + 1 ), KStringLengthA( C_PTR( Address + Index + 1 ) ) );

            //
            // check if this is an API set function
            //

            // Hash first four characters of FwdFunction
            ULONG FwdLibraryStart = HashString(FwdLibrary, 4);

            // Check if it matches either "ext-" or "api-", indicating API set function
            if ( FwdLibraryStart == HASH_STR( "ext-" ) || FwdLibraryStart == HASH_STR( "api-" ) )
            {
                AnsiString.Length        = KStringLengthA( FuncName );
                AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
                AnsiString.Buffer        = FuncName;

                // Use LdrGetProcedureAddress to resolve addr, as API set forwarding is complicated
                if ( !NT_SUCCESS( API( LdrGetProcedureAddress )( Library, &AnsiString, 0, &Address ) ) )
                    Address = NULL;
            }
            else
            {
                // Otherwise load library and recurse into this function to resolve address
                FwdLibraryBase = KLoadLibrary( FwdLibrary );
                Address  = LdrFunction( FwdLibraryBase, HashString( FwdFunction, 0 ) );
            }
        }

        break;
    }

    return Address;
}

FUNC UINT32 CopyDotStr( PCHAR String )
{
    for ( UINT32 i = 0; i < KStringLengthA( String ); i++ )
    {
        if ( String[ i ] == '.' )
            return i;
    }
}

FUNC PVOID KLoadLibrary( LPSTR ModuleName )
{
    STARDUST_INSTANCE
    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    DWORD           dwModuleNameSize        = KStringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    KCharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW )
    {
        USHORT DestSize             = KStringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( NT_SUCCESS( API( LdrLoadDll )( NULL, 0, &UnicodeString, &Module ) ) )
        return Module;
    else
        return NULL;
}

FUNC SIZE_T KStringLengthA( LPCSTR String )
{
    LPCSTR String2 = String;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

FUNC SIZE_T KStringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

FUNC SIZE_T KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

FUNC VOID ResolveIAT( LPVOID ImageBase, LPVOID IatDir )
{
    STARDUST_INSTANCE

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    PCHAR                    ImportModuleName  = NULL;
    HMODULE                  ImportModule      = NULL;
    PIMAGE_THUNK_DATA        ILT               = NULL;
    PIMAGE_THUNK_DATA        IAT               = NULL;
    PCHAR                    pImportByName     = NULL;
    LPVOID                   Function          = NULL;

    for ( pImportDescriptor = IatDir; pImportDescriptor->Name != 0; ++pImportDescriptor )
    {
        ImportModuleName = PADD( ImageBase, pImportDescriptor->Name );
        ImportModule     = KLoadLibrary( ImportModuleName );

        ILT              = PADD( ImageBase, pImportDescriptor->OriginalFirstThunk );
        IAT              = PADD( ImageBase, pImportDescriptor->FirstThunk );

        for ( ; ILT->u1.AddressOfData != 0 ; ++ILT, ++IAT )
        {
            if ( IMAGE_SNAP_BY_ORDINAL( ILT->u1.Ordinal ) )
            {
                if ( NT_SUCCESS( API( LdrGetProcedureAddress )(ImportModule, NULL, IMAGE_ORDINAL( ILT->u1.Ordinal ), &Function) ) )
                    IAT->u1.Function = Function;
                else
                    PRINT("Failed!");
            }
            else
            {
                pImportByName       = ( ( PIMAGE_IMPORT_BY_NAME )( PADD( ImageBase, ILT->u1.AddressOfData ) ) )->Name;
                Function            = LdrFunction(ImportModule, HashString( pImportByName, 0 ) );
                if ( Function != NULL )
                    IAT->u1.Function = Function;
                else
                    PRINT("Failed!");
            }
        }
    }
}

FUNC VOID ProcessRelocations( LPVOID ActualBase, LPVOID PreferredBase, LPVOID RelocDir )
{
    STARDUST_INSTANCE
    PIMAGE_BASE_RELOCATION  RelocBlock  = RelocDir;
    PIMAGE_RELOC            RelocEntry  = NULL;
    LPVOID                  RelocOffset = PSUB( ActualBase, PreferredBase );

    while ( RelocBlock->VirtualAddress != 0 )
    {
        RelocEntry = ( PIMAGE_RELOC )( RelocBlock + 1 );
        while ( C_PTR( RelocEntry ) != PADD( RelocBlock, RelocBlock->SizeOfBlock ) )
        {
            if ( RelocEntry->type == IMAGE_REL_BASED_DIR64 )
            {
                C_DEF64( PADD( ActualBase, RelocBlock->VirtualAddress, RelocEntry->offset ) ) += U_PTR( RelocOffset );
            }
            else if ( RelocEntry->type == 0 )
                ;
            else
                PRINT( "Unsupported relocation type: %u", RelocEntry->type );

            RelocEntry++;
        }

        RelocBlock = ( PIMAGE_BASE_RELOCATION ) RelocEntry;
    }
}