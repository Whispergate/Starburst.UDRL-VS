#ifndef _MOCK_PE_H
#define _MOCK_PE_H

/*
 * Mock PE structures and Win32 types for compiling loader/mask logic on Linux.
 * Provides everything <windows.h> would normally supply, plus synthetic PE
 * builders for unit testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ========================================================================
 * Basic Windows types
 * ====================================================================== */

typedef unsigned char       BYTE,  *PBYTE, *LPBYTE;
typedef unsigned short      WORD,  *PWORD;
typedef unsigned int        DWORD, *PDWORD, *LPDWORD;
typedef unsigned long long  ULONGLONG, *PULONGLONG;
typedef unsigned long long  UINT64;
typedef long long           LONGLONG;
typedef int                 LONG;
typedef int                 BOOL;
typedef void               *PVOID, *LPVOID;
typedef void               *HANDLE, *HMODULE, *HINSTANCE;
typedef uint32_t            ULONG;
typedef ULONG              *PULONG;
typedef uint64_t            ULONG_PTR;
typedef uintptr_t           UINT_PTR;
typedef size_t              SIZE_T;
typedef int               (*FARPROC)();
typedef const char         *LPCSTR;
typedef char               *PCHAR;
typedef const wchar_t      *LPCWSTR;
typedef wchar_t            *PWCHAR;
typedef void               *LPSECURITY_ATTRIBUTES;
typedef LONGLONG           *PLARGE_INTEGER;
typedef unsigned char       UCHAR;
typedef unsigned short      USHORT;
typedef uint8_t             UINT8;
typedef uint16_t            UINT16;
typedef uint32_t            UINT32;
typedef uint64_t            ULONG64;

#define TRUE  1
#define FALSE 0

#define VOID    void
#define WINAPI
#define NTAPI
#define __stdcall

/* SAL annotations (no-ops) */
#define _In_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _Inout_

#define INFINITE            0xFFFFFFFF
#define DLL_PROCESS_ATTACH  1
#define DLL_PROCESS_DETACH  0
#define DLL_THREAD_ATTACH   2
#define DLL_THREAD_DETACH   3
#define EXTERN_C            extern

/* ========================================================================
 * PE constants
 * ====================================================================== */

#define IMAGE_DOS_SIGNATURE         0x5A4D
#define IMAGE_NT_SIGNATURE          0x00004550

/* Section characteristics */
#define IMAGE_SCN_CNT_CODE              0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#define IMAGE_SCN_MEM_EXECUTE           0x20000000
#define IMAGE_SCN_MEM_READ              0x40000000
#define IMAGE_SCN_MEM_WRITE             0x80000000

/* Page protections */
#define PAGE_NOACCESS           0x01
#define PAGE_READONLY           0x02
#define PAGE_READWRITE          0x04
#define PAGE_WRITECOPY          0x08
#define PAGE_EXECUTE            0x10
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_EXECUTE_WRITECOPY  0x80

/* Memory allocation types */
#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_RELEASE             0x00008000

/* Relocation types */
#define IMAGE_REL_BASED_ABSOLUTE    0
#define IMAGE_REL_BASED_HIGH        1
#define IMAGE_REL_BASED_LOW         2
#define IMAGE_REL_BASED_HIGHLOW     3
#define IMAGE_REL_BASED_DIR64       10

/* Data directory indices */
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE  2
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

/* Ordinal flags */
#define IMAGE_ORDINAL_FLAG64    0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG32    0x80000000UL

/* Load library flags */
#define DONT_RESOLVE_DLL_REFERENCES 0x00000001

/* Optional header magic */
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x020B

/* Machine types */
#define IMAGE_FILE_MACHINE_AMD64    0x8664

/* ========================================================================
 * PE structures (packed to match Windows layout)
 * ====================================================================== */

#pragma pack(push, 1)

typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    LONG  e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS {
    DWORD                 Signature;
    IMAGE_FILE_HEADER     FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA, *PIMAGE_THUNK_DATA;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    char Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#pragma pack(pop)

/* IMAGE_FIRST_SECTION: pointer to first section header from NT headers */
#define IMAGE_FIRST_SECTION(nt) \
    ((PIMAGE_SECTION_HEADER)((PBYTE)&(nt)->OptionalHeader + (nt)->FileHeader.SizeOfOptionalHeader))

/* ========================================================================
 * Mock Win32 API implementations (static inline, use malloc/free)
 * ====================================================================== */

static inline PVOID mock_VirtualAlloc(PVOID addr, SIZE_T size, DWORD type, DWORD protect) {
    (void)addr; (void)type; (void)protect;
    void *p = calloc(1, size);
    return p;
}

static inline BOOL mock_VirtualProtect(PVOID addr, SIZE_T size, DWORD newProtect, PDWORD oldProtect) {
    (void)addr; (void)size; (void)newProtect;
    if (oldProtect) *oldProtect = PAGE_READWRITE;
    return TRUE;
}

static inline BOOL mock_VirtualFree(PVOID addr, SIZE_T size, DWORD type) {
    (void)size; (void)type;
    free(addr);
    return TRUE;
}

/* Mock RDTSC: returns incrementing values for GenerateRc4Key testing */
static unsigned long long _mock_rdtsc_counter = 0x12345678ABCDEF01ULL;

static inline unsigned long long mock_rdtsc(void) {
    _mock_rdtsc_counter += 0x1234;
    return _mock_rdtsc_counter;
}

#define __rdtsc() mock_rdtsc()

/* ========================================================================
 * Sleepmask types (matching sleepmask.h and beacon_gate.h)
 * ====================================================================== */

#define SM_MAX_REGIONS  8

typedef struct _SM_REGION {
    PVOID  base;
    DWORD  size;
    DWORD  protect;
} SM_REGION;

typedef struct _SM_BEACON_INFO {
    PVOID           beacon_base;
    DWORD           beacon_size;
    SM_REGION       regions[SM_MAX_REGIONS];
    int             region_count;
    unsigned char   rc4_key[16];
} SM_BEACON_INFO, *PSM_BEACON_INFO;

typedef enum _WinApi {
    INTERNETOPENA,
    INTERNETCONNECTA,
    VIRTUALALLOC,
    VIRTUALALLOCEX,
    VIRTUALPROTECT,
    VIRTUALPROTECTEX,
    VIRTUALFREE,
    GETTHREADCONTEXT,
    SETTHREADCONTEXT,
    RESUMETHREAD,
    CREATETHREAD,
    CREATEREMOTETHREAD,
    OPENPROCESS,
    OPENTHREAD,
    CLOSEHANDLE,
    CREATEFILEMAPPING,
    MAPVIEWOFFILE,
    UNMAPVIEWOFFILE,
    VIRTUALQUERY,
    DUPLICATEHANDLE,
    READPROCESSMEMORY,
    WRITEPROCESSMEMORY,
    EXITTHREAD,
    VIRTUALFREEEX,
    VIRTUALQUERYEX,
    WAITFORSINGLEOBJECT,
    SLEEP
} WinApi;

#define MAX_BEACON_GATE_ARGUMENTS 10

typedef struct {
    PVOID       functionPtr;
    WinApi      function;
    int         numOfArgs;
    ULONG_PTR   args[MAX_BEACON_GATE_ARGUMENTS];
    BOOL        bMask;
    ULONG_PTR   retValue;
} FUNCTION_CALL, *PFUNCTION_CALL;

typedef ULONG_PTR (*BEACON_GATE_00)(void);
typedef ULONG_PTR (*BEACON_GATE_01)(ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_02)(ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_03)(ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_04)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_05)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_06)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_07)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_08)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_09)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);
typedef ULONG_PTR (*BEACON_GATE_10)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

/* ========================================================================
 * UDRL_USER_DATA (matching UserData.h)
 * ====================================================================== */

#define UDRL_MAGIC              0x5442525354ULL  /* "STRBT" */
#define LOAD_TYPE_VIRTUAL_ALLOC 0
#define LOAD_TYPE_MODULE_STOMP  1
#define MAX_UDRL_REGIONS        8

typedef struct _UDRL_REGION {
    PVOID  base;
    DWORD  size;
    DWORD  protect;
} UDRL_REGION;

typedef struct _UDRL_USER_DATA {
    UINT64        magic;
    DWORD         load_type;

    PVOID         agent_base;
    DWORD         agent_size;

    PVOID         loader_base;
    DWORD         loader_size;

    HMODULE       stomped_module;
    PVOID         stomped_text_base;
    DWORD         stomped_text_size;

    UDRL_REGION   regions[MAX_UDRL_REGIONS];
    DWORD         region_count;

    BYTE          rc4_key[16];
    BYTE          reserved[64];
} UDRL_USER_DATA;

/* ========================================================================
 * Utility macros (matching Stardust framework Macros.h)
 * ====================================================================== */

#define C_PTR(x)    ((PVOID)(x))
#define U_PTR(x)    ((ULONG_PTR)(x))
#define MmCopy(dst, src, n)  memcpy((dst), (src), (n))
#define MmZero(dst, n)       memset((dst), 0, (n))

/* ========================================================================
 * Synthetic PE builders for testing
 * ====================================================================== */

/*
 * build_test_pe: creates a minimal valid PE in a malloc'd buffer.
 *   - Valid DOS header (e_magic=MZ, e_lfanew pointing to NT headers)
 *   - Valid NT headers (Signature=PE, Machine=0x8664, 2 sections)
 *   - .text section: 0x1000 bytes, executable, filled with 0xCC
 *   - .data section: 0x1000 bytes, read/write, filled with 0xAA
 *   - No relocations, no imports
 *   - SizeOfImage=0x3000, SizeOfHeaders=0x200, ImageBase=0x180000000
 *   - Returns pointer to buffer, sets *out_size to total buffer size.
 *   - Caller must free() the returned pointer.
 */
static inline PBYTE build_test_pe(DWORD *out_size) {
    DWORD total = 0x3000;
    PBYTE buf = (PBYTE)calloc(1, total);
    if (!buf) return NULL;

    /* DOS header at offset 0 */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    /* NT headers at offset 0x80 */
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;

    nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections     = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    nt->FileHeader.Characteristics      = 0x0022; /* EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE */

    nt->OptionalHeader.Magic                = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint  = 0x1000;
    nt->OptionalHeader.BaseOfCode           = 0x1000;
    nt->OptionalHeader.ImageBase            = 0x180000000ULL;
    nt->OptionalHeader.SectionAlignment     = 0x1000;
    nt->OptionalHeader.FileAlignment        = 0x200;
    nt->OptionalHeader.SizeOfImage          = 0x3000;
    nt->OptionalHeader.SizeOfHeaders        = 0x200;
    nt->OptionalHeader.NumberOfRvaAndSizes  = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* Section headers follow the optional header */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    /* .text section */
    memcpy(sec[0].Name, ".text\0\0\0", 8);
    sec[0].Misc.VirtualSize  = 0x1000;
    sec[0].VirtualAddress    = 0x1000;
    sec[0].SizeOfRawData     = 0x1000;
    sec[0].PointerToRawData  = 0x1000;
    sec[0].Characteristics   = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    /* .data section */
    memcpy(sec[1].Name, ".data\0\0\0", 8);
    sec[1].Misc.VirtualSize  = 0x1000;
    sec[1].VirtualAddress    = 0x2000;
    sec[1].SizeOfRawData     = 0x1000;
    sec[1].PointerToRawData  = 0x2000;
    sec[1].Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    /* Fill .text with INT3 (0xCC) */
    memset(buf + 0x1000, 0xCC, 0x1000);

    /* Fill .data with 0xAA */
    memset(buf + 0x2000, 0xAA, 0x1000);

    if (out_size) *out_size = total;
    return buf;
}

/*
 * build_test_pe_with_relocs: same as build_test_pe but adds a single
 * IMAGE_REL_BASED_DIR64 relocation entry pointing at offset 0x10 in .text
 * (RVA 0x1010). The relocation block is placed at file offset 0x1F00.
 *
 * A 64-bit value at .text+0x10 is set to (ImageBase + 0x2000) so a loader
 * applying the relocation delta can be verified.
 */
static inline PBYTE build_test_pe_with_relocs(DWORD *out_size) {
    DWORD total = 0x3000;
    PBYTE buf = (PBYTE)calloc(1, total);
    if (!buf) return NULL;

    /* DOS header */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    /* NT headers */
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buf + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;

    nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections     = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    nt->FileHeader.Characteristics      = 0x0022;

    nt->OptionalHeader.Magic                = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint  = 0x1000;
    nt->OptionalHeader.BaseOfCode           = 0x1000;
    nt->OptionalHeader.ImageBase            = 0x180000000ULL;
    nt->OptionalHeader.SectionAlignment     = 0x1000;
    nt->OptionalHeader.FileAlignment        = 0x200;
    nt->OptionalHeader.SizeOfImage          = 0x3000;
    nt->OptionalHeader.SizeOfHeaders        = 0x200;
    nt->OptionalHeader.NumberOfRvaAndSizes  = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* Sections */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    memcpy(sec[0].Name, ".text\0\0\0", 8);
    sec[0].Misc.VirtualSize  = 0x1000;
    sec[0].VirtualAddress    = 0x1000;
    sec[0].SizeOfRawData     = 0x1000;
    sec[0].PointerToRawData  = 0x1000;
    sec[0].Characteristics   = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    memcpy(sec[1].Name, ".data\0\0\0", 8);
    sec[1].Misc.VirtualSize  = 0x1000;
    sec[1].VirtualAddress    = 0x2000;
    sec[1].SizeOfRawData     = 0x1000;
    sec[1].PointerToRawData  = 0x2000;
    sec[1].Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    /* Fill sections */
    memset(buf + 0x1000, 0xCC, 0x1000);
    memset(buf + 0x2000, 0xAA, 0x1000);

    /*
     * Plant a 64-bit pointer at .text+0x10 (file offset 0x1010).
     * Value = ImageBase + 0x2000 (pointing into .data).
     */
    ULONGLONG orig_ptr = 0x180000000ULL + 0x2000;
    memcpy(buf + 0x1010, &orig_ptr, sizeof(orig_ptr));

    /*
     * Build relocation block at file offset 0x1F00 (RVA 0x1F00).
     *   Header: VirtualAddress=0x1000, SizeOfBlock=12
     *   Entry 0: (DIR64 << 12) | 0x0010  => apply at RVA 0x1010
     *   Entry 1: (ABSOLUTE << 12)        => padding
     */
    DWORD reloc_rva     = 0x1F00;
    DWORD reloc_fileoff = 0x1F00;

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(buf + reloc_fileoff);
    reloc->VirtualAddress = 0x1000;
    reloc->SizeOfBlock    = sizeof(IMAGE_BASE_RELOCATION) + 2 * sizeof(WORD);

    PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
    entries[0] = (WORD)((IMAGE_REL_BASED_DIR64 << 12) | 0x0010);
    entries[1] = (WORD)((IMAGE_REL_BASED_ABSOLUTE << 12) | 0x0000);

    /* Point data directory at the relocation block */
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_rva;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = reloc->SizeOfBlock;

    if (out_size) *out_size = total;
    return buf;
}

/* ========================================================================
 * Additional types for test compilation
 * ====================================================================== */

typedef unsigned char  *PUCHAR;
typedef char            CHAR;

#ifndef CONSTEXPR
#define CONSTEXPR static inline
#endif

#if !defined(_MSC_VER) && !defined(__debugbreak)
#define __debugbreak() abort()
#endif

/* ========================================================================
 * Hash constants (from loader/include/Defs.h)
 * ====================================================================== */

#define H_MAGIC_KEY       7759
#define H_MAGIC_SEED      6
#define H_MODULE_NTDLL    0xc2ba439d
#define H_MODULE_KERNEL32 0xf232005a

/* ========================================================================
 * Production sleepmask types (from mask/include/sleepmask.h)
 * Suffixed _PROD to coexist with the simplified test versions above.
 * ====================================================================== */

#define SM_MASK_SIZE_PROD      13
#define SM_MAX_SECTIONS_PROD   8
#define SM_MAX_REGIONS_PROD    6

typedef struct _SM_HEAP_RECORD_PROD {
    char*    ptr;
    size_t   size;
} SM_HEAP_RECORD_PROD;

typedef struct _SM_ALLOC_SECTION_PROD {
    int      Label;
    PVOID    BaseAddress;
    SIZE_T   VirtualSize;
    DWORD    CurrentProtect;
    DWORD    PreviousProtect;
    BOOL     MaskSection;
    DWORD    DripLoadPageSize;
} SM_ALLOC_SECTION_PROD;

typedef struct _SM_ALLOC_CLEANUP_PROD {
    BOOL     Cleanup;
    int      AllocationMethod;
    UINT8    AdditionalInfo[16];
} SM_ALLOC_CLEANUP_PROD;

typedef struct _SM_ALLOC_REGION_PROD {
    int      Purpose;
    PVOID    AllocationBase;
    SIZE_T   RegionSize;
    DWORD    Type;
    DWORD    DripLoadAllocationGranularity;
    SM_ALLOC_SECTION_PROD Sections[SM_MAX_SECTIONS_PROD];
    SM_ALLOC_CLEANUP_PROD CleanupInformation;
} SM_ALLOC_REGION_PROD;

typedef struct _SM_ALLOC_MEMORY_PROD {
    SM_ALLOC_REGION_PROD AllocatedMemoryRegions[SM_MAX_REGIONS_PROD];
} SM_ALLOC_MEMORY_PROD;

typedef struct _SM_BEACON_INFO_PROD {
    unsigned int         version;
    char*                sleep_mask_ptr;
    DWORD                sleep_mask_text_size;
    DWORD                sleep_mask_total_size;
    char*                beacon_ptr;
    SM_HEAP_RECORD_PROD* heap_records;
    char                 mask[SM_MASK_SIZE_PROD];
    SM_ALLOC_MEMORY_PROD allocatedMemory;
} SM_BEACON_INFO_PROD, *PSM_BEACON_INFO_PROD;

/* ========================================================================
 * Synthetic PE with export directory (for testing LdrFunction)
 *
 * Layout:
 *   0x0000  DOS header
 *   0x0080  NT headers (3 sections: .text, .data, .edata)
 *   0x1000  .text section (0x1000 bytes, 0xCC fill)
 *   0x2000  .data section (0x1000 bytes, 0xAA fill)
 *   0x3000  .edata section (export directory + tables)
 *
 * Exports two functions: "FuncAlpha" at RVA 0x1000, "FuncBeta" at RVA 0x1020.
 * ====================================================================== */

static inline PBYTE build_test_pe_with_exports(DWORD *out_size) {
    DWORD total = 0x4000;
    PBYTE buf = (PBYTE)calloc(1, total);
    if (!buf) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
    dos->e_magic  = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buf + 0x80);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections     = 3;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    nt->FileHeader.Characteristics      = 0x0022;

    nt->OptionalHeader.Magic               = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.ImageBase           = 0x180000000ULL;
    nt->OptionalHeader.SectionAlignment    = 0x1000;
    nt->OptionalHeader.FileAlignment       = 0x200;
    nt->OptionalHeader.SizeOfImage         = 0x4000;
    nt->OptionalHeader.SizeOfHeaders       = 0x200;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x3000;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size           = 0x200;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    memcpy(sec[0].Name, ".text\0\0\0", 8);
    sec[0].Misc.VirtualSize = 0x1000;
    sec[0].VirtualAddress   = 0x1000;
    sec[0].SizeOfRawData    = 0x1000;
    sec[0].PointerToRawData = 0x1000;
    sec[0].Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    memcpy(sec[1].Name, ".data\0\0\0", 8);
    sec[1].Misc.VirtualSize = 0x1000;
    sec[1].VirtualAddress   = 0x2000;
    sec[1].SizeOfRawData    = 0x1000;
    sec[1].PointerToRawData = 0x2000;
    sec[1].Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    memcpy(sec[2].Name, ".edata\0\0", 8);
    sec[2].Misc.VirtualSize = 0x1000;
    sec[2].VirtualAddress   = 0x3000;
    sec[2].SizeOfRawData    = 0x1000;
    sec[2].PointerToRawData = 0x3000;
    sec[2].Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    memset(buf + 0x1000, 0xCC, 0x1000);
    memset(buf + 0x2000, 0xAA, 0x1000);

    PIMAGE_EXPORT_DIRECTORY expdir = (PIMAGE_EXPORT_DIRECTORY)(buf + 0x3000);
    expdir->Name                  = 0x3090;
    expdir->Base                  = 1;
    expdir->NumberOfFunctions     = 2;
    expdir->NumberOfNames         = 2;
    expdir->AddressOfFunctions    = 0x3040;
    expdir->AddressOfNames        = 0x3050;
    expdir->AddressOfNameOrdinals = 0x3060;

    PDWORD funcRvas = (PDWORD)(buf + 0x3040);
    funcRvas[0] = 0x1000;
    funcRvas[1] = 0x1020;

    PDWORD nameRvas = (PDWORD)(buf + 0x3050);
    nameRvas[0] = 0x3070;
    nameRvas[1] = 0x3080;

    PWORD ordinals = (PWORD)(buf + 0x3060);
    ordinals[0] = 0;
    ordinals[1] = 1;

    memcpy(buf + 0x3070, "FuncAlpha", 10);
    memcpy(buf + 0x3080, "FuncBeta", 9);
    memcpy(buf + 0x3090, "testmod.dll", 12);

    if (out_size) *out_size = total;
    return buf;
}

#endif /* _MOCK_PE_H */
