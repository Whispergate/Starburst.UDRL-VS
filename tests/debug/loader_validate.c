/*
 * UDRL Post-Load Validation Tool
 *
 * Validates that the UDRL loader correctly mapped a PE, resolved imports,
 * applied relocations, and populated UDRL_USER_DATA.
 *
 * Build (MinGW):
 *   x86_64-w64-mingw32-gcc -DUDRL_DEBUG -o loader_validate.exe loader_validate.c
 *
 * Usage:
 *   loader_validate.exe <hex_address_of_UDRL_USER_DATA>
 *   loader_validate.exe 0x7FFE12340000
 *
 * Or call udrl_post_load_validate() from your own code after the loader runs.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* UDRL_USER_DATA definition. Uses the project header when available. */
#ifndef UDRL_MAGIC
#define UDRL_MAGIC              0x5442525354ULL
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
#endif

#define UDRL_DEBUG
#include "debug.h"

/* PE section characteristics to expected memory protection.
 * Mirrors SectionToProtect() in the loader. */
static DWORD section_to_protect(DWORD ch) {
    BOOL x = !!(ch & IMAGE_SCN_MEM_EXECUTE);
    BOOL r = !!(ch & IMAGE_SCN_MEM_READ);
    BOOL w = !!(ch & IMAGE_SCN_MEM_WRITE);

    if (x && w && r) return PAGE_EXECUTE_READWRITE;
    if (x && r)      return PAGE_EXECUTE_READ;
    if (x && w)      return PAGE_EXECUTE_WRITECOPY;
    if (x)           return PAGE_EXECUTE;
    if (w && r)      return PAGE_READWRITE;
    if (r)           return PAGE_READONLY;
    if (w)           return PAGE_WRITECOPY;
    return PAGE_NOACCESS;
}

/* Return readable name for a memory protection constant */
static const char *prot_name(DWORD p) {
    switch (p) {
        case PAGE_NOACCESS:          return "PAGE_NOACCESS";
        case PAGE_READONLY:          return "PAGE_READONLY";
        case PAGE_READWRITE:         return "PAGE_READWRITE";
        case PAGE_WRITECOPY:         return "PAGE_WRITECOPY";
        case PAGE_EXECUTE:           return "PAGE_EXECUTE";
        case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
        default:                     return "UNKNOWN";
    }
}

/*
 * udrl_post_load_validate
 *
 * Comprehensive post-load validation of the UDRL loader's work.
 * Returns 0 if all checks pass, or the number of failures.
 */
int udrl_post_load_validate(UDRL_USER_DATA *ud) {
    int pass = 0;
    int fail = 0;

    UDRL_LOG_INFO("=== UDRL Post-Load Validation ===");

    /* ---- 1. UDRL_USER_DATA validation ---- */
    UDRL_LOG_INFO("--- Check 1: UDRL_USER_DATA ---");

    if (!ud) {
        UDRL_LOG_ERR("UDRL_USER_DATA pointer is NULL");
        fail++;
        return fail;
    }

    if (ud->magic != UDRL_MAGIC) {
        UDRL_LOG_ERR("Bad magic: 0x%llx (expected 0x%llx)",
            (unsigned long long)ud->magic, (unsigned long long)UDRL_MAGIC);
        fail++;
    } else {
        UDRL_LOG_OK("Magic: OK");
        pass++;
    }

    if (ud->load_type != LOAD_TYPE_VIRTUAL_ALLOC &&
        ud->load_type != LOAD_TYPE_MODULE_STOMP) {
        UDRL_LOG_ERR("Unknown load_type: %d", (int)ud->load_type);
        fail++;
    } else {
        UDRL_LOG_OK("load_type: %d (%s)", (int)ud->load_type,
            ud->load_type == LOAD_TYPE_VIRTUAL_ALLOC ? "VirtualAlloc" : "ModuleStomp");
        pass++;
    }

    if (!ud->agent_base) {
        UDRL_LOG_ERR("agent_base is NULL");
        fail++;
    } else {
        UDRL_LOG_OK("agent_base: %p", ud->agent_base);
        pass++;
    }

    if (ud->agent_size == 0) {
        UDRL_LOG_ERR("agent_size is 0");
        fail++;
    } else {
        UDRL_LOG_OK("agent_size: 0x%x", (unsigned)ud->agent_size);
        pass++;
    }

    if (ud->region_count == 0 || ud->region_count > MAX_UDRL_REGIONS) {
        UDRL_LOG_ERR("region_count out of bounds: %d (expected 1..%d)",
            (int)ud->region_count, MAX_UDRL_REGIONS);
        fail++;
    } else {
        UDRL_LOG_OK("region_count: %d", (int)ud->region_count);
        pass++;
    }

    /* rc4_key check */
    {
        BOOL key_ok = FALSE;
        for (int i = 0; i < 16; i++) {
            if (ud->rc4_key[i] != 0) { key_ok = TRUE; break; }
        }
        if (!key_ok) {
            UDRL_LOG_ERR("rc4_key is all zeros");
            fail++;
        } else {
            printf("[UDRL][+] rc4_key: ");
            for (int i = 0; i < 16; i++) printf("%02x", ud->rc4_key[i]);
            printf("\n");
            pass++;
        }
    }

    /* ---- 2. PE header check at agent_base ---- */
    UDRL_LOG_INFO("--- Check 2: PE Headers ---");

    PBYTE base = (PBYTE)ud->agent_base;
    if (!base) {
        UDRL_LOG_ERR("Cannot check PE: agent_base is NULL");
        fail++;
        goto skip_pe_checks;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        UDRL_LOG_ERR("Bad DOS signature at agent_base: 0x%04x", dos->e_magic);
        fail++;
        goto skip_pe_checks;
    } else {
        UDRL_LOG_OK("DOS signature: OK (0x5A4D)");
        pass++;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        UDRL_LOG_ERR("Bad NT signature: 0x%08x", (unsigned)nt->Signature);
        fail++;
        goto skip_pe_checks;
    } else {
        UDRL_LOG_OK("NT signature: OK (0x00004550)");
        pass++;
    }

    if (nt->FileHeader.NumberOfSections == 0) {
        UDRL_LOG_ERR("PE has 0 sections");
        fail++;
    } else {
        UDRL_LOG_OK("Sections: %d", nt->FileHeader.NumberOfSections);
        pass++;
    }

    /* ---- 3. Section protection verification ---- */
    UDRL_LOG_INFO("--- Check 3: Section Protections ---");
    {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (sec[i].Misc.VirtualSize == 0) continue;

            PVOID sec_addr = base + sec[i].VirtualAddress;
            DWORD expected = section_to_protect(sec[i].Characteristics);

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(sec_addr, &mbi, sizeof(mbi)) == 0) {
                UDRL_LOG_ERR("Section '%.8s': VirtualQuery failed (error %d)",
                    sec[i].Name, (int)GetLastError());
                fail++;
                continue;
            }

            /* Mask off guard/nocache/writecombine flags for comparison */
            DWORD actual = mbi.Protect & 0xFF;

            if (actual != expected) {
                UDRL_LOG_ERR("Section '%.8s': protection mismatch: actual=%s (0x%x), expected=%s (0x%x)",
                    sec[i].Name,
                    prot_name(actual), (unsigned)actual,
                    prot_name(expected), (unsigned)expected);
                fail++;
            } else {
                UDRL_LOG_OK("Section '%.8s': protection OK (%s)",
                    sec[i].Name, prot_name(actual));
                pass++;
            }
        }
    }

    /* ---- 4. IAT verification ---- */
    UDRL_LOG_INFO("--- Check 4: Import Address Table ---");
    {
        DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!import_rva) {
            UDRL_LOG_INFO("No import directory");
        } else {
            PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + import_rva);
            int mod_ok = 0;
            int mod_fail = 0;
            int func_ok = 0;
            int func_fail = 0;

            while (imp->Name) {
                const char *mod_name = (const char *)(base + imp->Name);
                HMODULE hmod = GetModuleHandleA(mod_name);
                if (!hmod) {
                    UDRL_LOG_ERR("Import module not loaded: %s", mod_name);
                    mod_fail++;
                    imp++;
                    continue;
                }
                mod_ok++;

                /* Walk the IAT (FirstThunk) and verify entries */
                if (imp->FirstThunk) {
                    PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
                    int idx = 0;
                    while (iat->u1.Function) {
                        MEMORY_BASIC_INFORMATION mbi;
                        PVOID func_ptr = (PVOID)iat->u1.Function;
                        if (VirtualQuery(func_ptr, &mbi, sizeof(mbi)) == 0) {
                            UDRL_LOG_ERR("  %s: IAT[%d] -> %p: VirtualQuery failed",
                                mod_name, idx, func_ptr);
                            func_fail++;
                        } else if (mbi.State != MEM_COMMIT) {
                            UDRL_LOG_ERR("  %s: IAT[%d] -> %p: not MEM_COMMIT (state=0x%x)",
                                mod_name, idx, func_ptr, (unsigned)mbi.State);
                            func_fail++;
                        } else {
                            func_ok++;
                        }
                        iat++;
                        idx++;
                    }
                }
                imp++;
            }
            UDRL_LOG_OK("Imports: %d modules loaded (%d failed), %d IAT entries valid (%d failed)",
                mod_ok, mod_fail, func_ok, func_fail);
            if (mod_fail || func_fail) fail++;
            else pass++;
        }
    }

    /* ---- 5. Relocation verification ---- */
    UDRL_LOG_INFO("--- Check 5: Relocations ---");
    {
        ULONGLONG mapped_base_addr = (ULONGLONG)base;
        ULONGLONG preferred_base = nt->OptionalHeader.ImageBase;

        /* After relocation, the mapped NT headers' ImageBase is updated
         * by some loaders. The true test: did we load at preferred? */
        if (mapped_base_addr == preferred_base) {
            UDRL_LOG_OK("Loaded at preferred base 0x%llx, no relocations needed",
                (unsigned long long)preferred_base);
            pass++;
        } else {
            UDRL_LOG_INFO("Loaded at 0x%llx (preferred 0x%llx), delta=0x%llx",
                (unsigned long long)mapped_base_addr,
                (unsigned long long)preferred_base,
                (unsigned long long)(mapped_base_addr - preferred_base));

            /* Verify relocation directory exists */
            DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            if (!reloc_rva || !reloc_size) {
                UDRL_LOG_ERR("Image rebased but no relocation directory present");
                fail++;
            } else {
                UDRL_LOG_OK("Relocation directory present: RVA=0x%x Size=0x%x",
                    (unsigned)reloc_rva, (unsigned)reloc_size);
                pass++;
            }
        }
    }

    /* ---- 6. Region bounds checking ---- */
    UDRL_LOG_INFO("--- Check 6: Region Memory State ---");
    {
        DWORD valid_regions = ud->region_count;
        if (valid_regions > MAX_UDRL_REGIONS) valid_regions = MAX_UDRL_REGIONS;

        for (DWORD i = 0; i < valid_regions; i++) {
            if (!ud->regions[i].base) {
                UDRL_LOG_ERR("region[%d]: base is NULL", (int)i);
                fail++;
                continue;
            }
            if (ud->regions[i].size == 0) {
                UDRL_LOG_ERR("region[%d]: size is 0", (int)i);
                fail++;
                continue;
            }

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(ud->regions[i].base, &mbi, sizeof(mbi)) == 0) {
                UDRL_LOG_ERR("region[%d]: VirtualQuery failed at %p (error %d)",
                    (int)i, ud->regions[i].base, (int)GetLastError());
                fail++;
            } else if (mbi.State != MEM_COMMIT) {
                UDRL_LOG_ERR("region[%d]: %p not MEM_COMMIT (state=0x%x)",
                    (int)i, ud->regions[i].base, (unsigned)mbi.State);
                fail++;
            } else {
                UDRL_LOG_OK("region[%d]: %p (0x%x bytes) is MEM_COMMIT",
                    (int)i, ud->regions[i].base, (unsigned)ud->regions[i].size);
                pass++;
            }
        }
    }

    /* ---- 7. Module stomp specific checks ---- */
    UDRL_LOG_INFO("--- Check 7: Module Stomp ---");
    if (ud->load_type == LOAD_TYPE_MODULE_STOMP) {
        if (!ud->stomped_module) {
            UDRL_LOG_ERR("load_type is MODULE_STOMP but stomped_module is NULL");
            fail++;
        } else {
            char mod_path[MAX_PATH];
            DWORD len = GetModuleFileNameA(ud->stomped_module, mod_path, MAX_PATH);
            if (len == 0) {
                UDRL_LOG_ERR("GetModuleFileName failed for stomped_module %p (error %d)",
                    (void *)ud->stomped_module, (int)GetLastError());
                fail++;
            } else {
                UDRL_LOG_OK("Stomped module: %s", mod_path);
                pass++;
            }
        }

        if (!ud->stomped_text_base || ud->stomped_text_size == 0) {
            UDRL_LOG_ERR("stomped_text_base=%p stomped_text_size=0x%x (expected non-zero)",
                ud->stomped_text_base, (unsigned)ud->stomped_text_size);
            fail++;
        } else {
            UDRL_LOG_OK("Stomped .text: base=%p size=0x%x",
                ud->stomped_text_base, (unsigned)ud->stomped_text_size);
            pass++;
        }
    } else {
        UDRL_LOG_INFO("load_type is VirtualAlloc, skipping module stomp checks");
    }

skip_pe_checks:

    /* ---- Summary ---- */
    UDRL_LOG_INFO("=================================");
    UDRL_LOG_INFO("Results: %d passed, %d failed", pass, fail);
    if (fail == 0) {
        UDRL_LOG_OK("All validation checks passed.");
    } else {
        UDRL_LOG_ERR("%d check(s) failed.", fail);
    }

    return fail;
}

/*
 * main: standalone entry point.
 * Pass the UDRL_USER_DATA address as a hex argument.
 */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <hex_address_of_UDRL_USER_DATA>\n", argv[0]);
        printf("Example: %s 0x7FFE12340000\n", argv[0]);
        return 1;
    }

    UDRL_USER_DATA *ud = (UDRL_USER_DATA *)(uintptr_t)strtoull(argv[1], NULL, 16);
    if (!ud) {
        printf("Error: invalid address '%s'\n", argv[1]);
        return 1;
    }

    printf("[UDRL] Validating UDRL_USER_DATA at %p\n", (void *)ud);
    int result = udrl_post_load_validate(ud);
    return result;
}
