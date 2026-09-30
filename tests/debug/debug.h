/*
 * UDRL Debug Instrumentation Header
 *
 * Include this in your loader or mask source when debugging.
 * Define UDRL_DEBUG before including to activate all instrumentation.
 * All functions compile to no-ops when UDRL_DEBUG is not defined.
 *
 * Requires: windows.h, UserData.h (or define STARBURST_VERSION before including)
 */

#ifndef _UDRL_DEBUG_H
#define _UDRL_DEBUG_H

#include <stdio.h>
#include <windows.h>

/* Pull in UserData.h for CS USER_DATA / ALLOCATED_MEMORY if not already defined */
#ifndef STARBURST_VERSION
#include "UserData.h"
#endif

#ifdef UDRL_DEBUG

/* ---- Logging macros ---- */

#define UDRL_LOG(fmt, ...) \
    printf("[UDRL] %s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define UDRL_LOG_OK(fmt, ...) \
    printf("[UDRL][+] " fmt "\n", ##__VA_ARGS__)

#define UDRL_LOG_ERR(fmt, ...) \
    printf("[UDRL][-] " fmt "\n", ##__VA_ARGS__)

#define UDRL_LOG_INFO(fmt, ...) \
    printf("[UDRL][*] " fmt "\n", ##__VA_ARGS__)

/* Assert with logging. Does not abort, only prints. */
#define UDRL_ASSERT(expr) do { \
    if (!(expr)) { \
        UDRL_LOG_ERR("ASSERT FAILED: %s", #expr); \
    } \
} while(0)

/* ---- Hex dump ---- */

static inline void udrl_hexdump(const char *label, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    printf("[UDRL] %s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len && i < 256; i++) {
        if (i % 16 == 0) printf("  %04zx: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15 || i == len - 1) {
            for (size_t pad = i % 16; pad < 15; pad++) printf("   ");
            printf(" |");
            size_t start = i - (i % 16);
            for (size_t j = start; j <= i; j++)
                printf("%c", (p[j] >= 0x20 && p[j] < 0x7f) ? p[j] : '.');
            printf("|\n");
        }
    }
    if (len > 256) printf("  ... (%zu more bytes)\n", len - 256);
}

/* ---- PE validation ---- */

static inline BOOL udrl_validate_pe(const char *label, PBYTE base) {
    if (!base) {
        UDRL_LOG_ERR("%s: base pointer is NULL", label);
        return FALSE;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        UDRL_LOG_ERR("%s: Bad DOS signature: 0x%04x (expected 0x5A4D)", label, dos->e_magic);
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        UDRL_LOG_ERR("%s: Bad NT signature: 0x%08x (expected 0x00004550)", label, (unsigned)nt->Signature);
        return FALSE;
    }

    UDRL_LOG_OK("%s: Valid PE, %d sections, ImageSize=0x%x, EntryRVA=0x%x",
        label, nt->FileHeader.NumberOfSections,
        nt->OptionalHeader.SizeOfImage,
        nt->OptionalHeader.AddressOfEntryPoint);
    return TRUE;
}

/* ---- CS USER_DATA + ALLOCATED_MEMORY validation ---- */

static inline BOOL udrl_validate_userdata(const USER_DATA *ud) {
    if (!ud) {
        UDRL_LOG_ERR("UserData is NULL");
        return FALSE;
    }
    if (ud->version == 0) {
        UDRL_LOG_ERR("UserData version is 0 (expected non-zero, e.g. 0x%x)", STARBURST_VERSION);
        return FALSE;
    }

    UDRL_LOG_OK("UserData: version=0x%x", ud->version);

    if (!ud->allocatedMemory) {
        UDRL_LOG_ERR("  allocatedMemory pointer is NULL");
        return FALSE;
    }

    UDRL_LOG_INFO("  allocatedMemory=%p", (void *)ud->allocatedMemory);

    for (int r = 0; r < 6; r++) {
        const ALLOCATED_MEMORY_REGION *reg = &ud->allocatedMemory->AllocatedMemoryRegions[r];
        if (!reg->AllocationBase || reg->RegionSize == 0)
            continue;

        UDRL_LOG_INFO("  region[%d]: purpose=%d base=%p size=0x%zx",
            r, (int)reg->Purpose, reg->AllocationBase, reg->RegionSize);

        for (int s = 0; s < 8; s++) {
            const ALLOCATED_MEMORY_SECTION *sec = &reg->Sections[s];
            if (!sec->BaseAddress || sec->VirtualSize == 0)
                continue;
            UDRL_LOG_INFO("    section[%d]: label=%d base=%p vsize=0x%zx prot=0x%x mask=%d",
                s, (int)sec->Label, sec->BaseAddress, sec->VirtualSize,
                (unsigned)sec->CurrentProtect, (int)sec->MaskSection);
        }
    }

    return TRUE;
}

/* ---- Section mapping log ---- */

static inline void udrl_log_sections(PBYTE mapped_base, PBYTE raw, PIMAGE_NT_HEADERS nt) {
    (void)raw;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        UDRL_LOG_INFO("Section[%d] '%.8s': VA=0x%x Size=0x%x -> %p (raw @ 0x%x, rawsz=0x%x)",
            (int)i, sec[i].Name,
            (unsigned)sec[i].VirtualAddress,
            (unsigned)sec[i].Misc.VirtualSize,
            mapped_base + sec[i].VirtualAddress,
            (unsigned)sec[i].PointerToRawData,
            (unsigned)sec[i].SizeOfRawData);
    }
}

/* ---- Relocation log ---- */

static inline void udrl_log_relocs(PBYTE base, DWORD reloc_rva, DWORD reloc_size, LONGLONG delta) {
    UDRL_LOG_INFO("Relocations: RVA=0x%x Size=0x%x Delta=0x%llx",
        (unsigned)reloc_rva, (unsigned)reloc_size, (long long)delta);

    if (!reloc_rva || !reloc_size) {
        UDRL_LOG_INFO("  No relocations to process");
        return;
    }

    PIMAGE_BASE_RELOCATION r = (PIMAGE_BASE_RELOCATION)(base + reloc_rva);
    DWORD count = 0;
    while ((PBYTE)r < (PBYTE)(base + reloc_rva + reloc_size) && r->SizeOfBlock) {
        DWORD n = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        count += n;
        r = (PIMAGE_BASE_RELOCATION)((PBYTE)r + r->SizeOfBlock);
    }
    UDRL_LOG_INFO("  Total relocation entries: %d", (int)count);
}

/* ---- Import log ---- */

static inline void udrl_log_imports(PBYTE base, DWORD import_rva) {
    if (!import_rva) {
        UDRL_LOG_INFO("Imports: none");
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + import_rva);
    int mod_count = 0;
    while (imp->Name) {
        UDRL_LOG_INFO("  Import[%d]: %s (OFT=0x%x FT=0x%x)",
            mod_count, (char *)(base + imp->Name),
            (unsigned)imp->OriginalFirstThunk,
            (unsigned)imp->FirstThunk);
        mod_count++;
        imp++;
    }
    UDRL_LOG_INFO("Imports: %d modules", mod_count);
}

#else /* UDRL_DEBUG not defined */

#define UDRL_LOG(fmt, ...)
#define UDRL_LOG_OK(fmt, ...)
#define UDRL_LOG_ERR(fmt, ...)
#define UDRL_LOG_INFO(fmt, ...)
#define UDRL_ASSERT(expr)

static inline void udrl_hexdump(const char *l, const void *d, size_t n) {
    (void)l; (void)d; (void)n;
}

static inline BOOL udrl_validate_pe(const char *l, PBYTE b) {
    (void)l; (void)b; return TRUE;
}

static inline BOOL udrl_validate_userdata(const USER_DATA *u) {
    (void)u; return TRUE;
}

static inline void udrl_log_sections(PBYTE m, PBYTE r, PIMAGE_NT_HEADERS n) {
    (void)m; (void)r; (void)n;
}

static inline void udrl_log_relocs(PBYTE b, DWORD rv, DWORD rs, LONGLONG d) {
    (void)b; (void)rv; (void)rs; (void)d;
}

static inline void udrl_log_imports(PBYTE b, DWORD rv) {
    (void)b; (void)rv;
}

#endif /* UDRL_DEBUG */

#endif /* _UDRL_DEBUG_H */
