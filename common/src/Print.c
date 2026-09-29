#ifdef DEBUG

#ifdef PIC
    #include <Common.h>
#else
    #include <common.h>
    #define FUNC
    #define STARDUST_INSTANCE
    #define API( x ) x
#endif

FUNC VOID PrintMsg(const char* function, BOOL block, const char* format, ...)
{
    STARDUST_INSTANCE

    // Assemble buffer containing calling functions name followed by passed string
    CHAR pFull[512] = {0};
#ifdef PIC
    API( _snprintf )(pFull, sizeof(pFull), "[DEBUG] UDRL::%s | %s\n", function, format);
#else
    API( _snprintf )(pFull, sizeof(pFull), "[DEBUG] Sleepmask::%s | %s\n", function, format);
#endif

    // Print
    va_list args;
    va_start(args, format);
    API( vprintf )(pFull, args);
    va_end(args);

    // If block is TRUE, call getchar and require user to manually continue
    if (block)
    {
        API( printf )("[DEBUG] Return address: %p | Press any key to continue...", __builtin_return_address(0));
        API( getchar )();
    }

    return;
}

#endif
