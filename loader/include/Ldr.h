#ifndef STARDUST_LDR_H
#define STARDUST_LDR_H

#include <Common.h>

PVOID LdrModulePeb(
    _In_ ULONG Hash
);

PVOID LdrFunction(
    _In_ PVOID Module,
    _In_ ULONG Function
);

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

PVOID   KLoadLibrary( LPSTR Module );
UINT32  CopyDotStr( PCHAR String );
SIZE_T  KStringLengthA( LPCSTR String );
SIZE_T  KStringLengthW( LPCWSTR String );
SIZE_T  KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
VOID    ResolveIAT( LPVOID ImageBase, LPVOID IatDir );
VOID    ProcessRelocations( LPVOID ActualBase, LPVOID PreferredBase, LPVOID RelocDir );

#endif //STARDUST_LDR_H
