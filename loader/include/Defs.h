#ifndef STARDUST_DEFS_H
#define STARDUST_DEFS_H

#include <Common.h>

typedef struct _BUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, *PBUFFER;

//
// Hashing defines
//
#define H_MAGIC_KEY       7759
#define H_MAGIC_SEED      6
#define H_MODULE_NTDLL    0xc2ba439d
#define H_MODULE_KERNEL32 0xf232005a


#endif //STARDUST_DEFS_H
