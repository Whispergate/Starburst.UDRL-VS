#ifndef _TEST_H
#define _TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ANSI color codes. Disabled on Windows cmd by default. */
#ifdef _WIN32
#define _CLR_RED   ""
#define _CLR_GRN   ""
#define _CLR_CYN   ""
#define _CLR_RST   ""
#else
#define _CLR_RED   "\033[31m"
#define _CLR_GRN   "\033[32m"
#define _CLR_CYN   "\033[36m"
#define _CLR_RST   "\033[0m"
#endif

static int _test_pass  = 0;
static int _test_fail  = 0;
static int _test_total = 0;
static const char *_test_current = NULL;

#define TEST_SUITE(name) \
    printf("\n=== %s ===\n", (name))

#define TEST(name) \
    do { \
        _test_current = (name); \
        _test_total++; \
        printf("  %s[RUN]%s  %s\n", _CLR_CYN, _CLR_RST, _test_current); \
    } while (0)

#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            printf("  %s[FAIL]%s %s  (%s:%d: %s)\n", \
                   _CLR_RED, _CLR_RST, _test_current, __FILE__, __LINE__, #expr); \
            _test_fail++; \
            return; \
        } \
    } while (0)

#define ASSERT_FALSE(expr) \
    do { \
        if ((expr)) { \
            printf("  %s[FAIL]%s %s  (%s:%d: expected false: %s)\n", \
                   _CLR_RED, _CLR_RST, _test_current, __FILE__, __LINE__, #expr); \
            _test_fail++; \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        long long _a = (long long)(a); \
        long long _b = (long long)(b); \
        if (_a != _b) { \
            printf("  %s[FAIL]%s %s  (%s:%d: %s == %s, got %lld != %lld)\n", \
                   _CLR_RED, _CLR_RST, _test_current, __FILE__, __LINE__, #a, #b, _a, _b); \
            _test_fail++; \
            return; \
        } \
    } while (0)

#define ASSERT_NE(a, b) \
    do { \
        long long _a = (long long)(a); \
        long long _b = (long long)(b); \
        if (_a == _b) { \
            printf("  %s[FAIL]%s %s  (%s:%d: %s != %s, both %lld)\n", \
                   _CLR_RED, _CLR_RST, _test_current, __FILE__, __LINE__, #a, #b, _a); \
            _test_fail++; \
            return; \
        } \
    } while (0)

#define ASSERT_NULL(ptr) \
    do { \
        if ((ptr) != NULL) { \
            printf("  %s[FAIL]%s %s  (%s:%d: expected NULL: %s)\n", \
                   _CLR_RED, _CLR_RST, _test_current, __FILE__, __LINE__, #ptr); \
            _test_fail++; \
            return; \
        } \
    } while (0)

#define ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            printf("  %s[FAIL]%s %s  (%s:%d: expected non-NULL: %s)\n", \
                   _CLR_RED, _CLR_RST, _test_current, __FILE__, __LINE__, #ptr); \
            _test_fail++; \
            return; \
        } \
    } while (0)

#define ASSERT_MEM_EQ(a, b, n) \
    do { \
        if (memcmp((a), (b), (n)) != 0) { \
            printf("  %s[FAIL]%s %s  (%s:%d: memcmp(%s, %s, %d) != 0)\n", \
                   _CLR_RED, _CLR_RST, _test_current, __FILE__, __LINE__, #a, #b, (int)(n)); \
            _test_fail++; \
            return; \
        } \
    } while (0)

#define PASS() \
    do { \
        printf("  %s[PASS]%s %s\n", _CLR_GRN, _CLR_RST, _test_current); \
        _test_pass++; \
    } while (0)

#define TEST_SUMMARY() \
    ( \
        printf("\n--- Results: %d total, %d passed, %d failed ---\n", \
               _test_total, _test_pass, _test_fail), \
        (_test_fail > 0) ? 1 : 0 \
    )

#endif /* _TEST_H */
