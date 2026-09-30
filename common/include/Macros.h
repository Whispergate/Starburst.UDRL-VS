#ifndef STARDUST_MACROS_H
#define STARDUST_MACROS_H

//
// instance related macros
//
#define InstanceOffset()  ( U_PTR( & __Instance_offset ) )
#define InstancePtr()     ( ( PINSTANCE ) C_DEF( C_PTR( U_PTR( StRipStart() ) + InstanceOffset() ) ) )
#define Instance()        ( ( PINSTANCE ) __LocalInstance )
#define STARDUST_INSTANCE PINSTANCE __LocalInstance = InstancePtr();
#define CDATA             PCUSTOM_DATA cData = Instance()->cData;

//
// utils macros
//
#define D_API( x )  __typeof__( x ) * x;
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC        D_SEC( B )
#define ST_GLOBAL   __attribute__( ( section( ".global" ) ) )
#define ST_READONLY __attribute__( ( section( ".rdata" ) ) )
#define MOD( x ) Instance()->Modules.x
#define API( x ) Instance()->Win32.x
#define RESOLVE( x, y ) API( x ) = (__typeof__( x )*)LdrFunction( MOD( y ), HASH_STR( #x ) )

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

//
// Pointer arithmetic macros 
//

// These determine the number of arguments passed
#define NARGS_IMPL(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,N,...) N
#define NARGS(...) NARGS_IMPL(__VA_ARGS__,10,9,8,7,6,5,4,3,2,1,0)

// Helpers
#define CONCAT(a,b) a##b
#define EXPAND_AND_CONCAT(a,b) CONCAT(a,b)

// Addition macros
#define ADD1(a) U_PTR(a)
#define ADD2(a,b) U_PTR(a) + U_PTR(b)
#define ADD3(a,b,c) U_PTR(a) + U_PTR(b) + U_PTR(c)
#define ADD4(a,b,c,d) U_PTR(a) + U_PTR(b) + U_PTR(c) + U_PTR(d)
#define ADD5(a,b,c,d,e) U_PTR(a) + U_PTR(b) + U_PTR(c) + U_PTR(d) + U_PTR(e)
#define ADD6(a,b,c,d,e,f) ADD5(a,b,c,d,e) + U_PTR(f)
#define ADD7(a,b,c,d,e,f,g) ADD6(a,b,c,d,e,f) + U_PTR(g)
#define ADD8(a,b,c,d,e,f,g,h) ADD7(a,b,c,d,e,f,g) + U_PTR(h)
#define ADD9(a,b,c,d,e,f,g,h,i) ADD8(a,b,c,d,e,f,g,h) + U_PTR(i)
#define ADD10(a,b,c,d,e,f,g,h,i,j) ADD9(a,b,c,d,e,f,g,h,i) + U_PTR(j)
#define ADD_DISPATCH(N, ...) EXPAND_AND_CONCAT(ADD, N)(__VA_ARGS__)
#define PADD(...) ((PVOID)(ADD_DISPATCH(NARGS(__VA_ARGS__), __VA_ARGS__)))

// Subtraction macros
#define SUB1(a) U_PTR(a)
#define SUB2(a,b) U_PTR(a) - U_PTR(b)
#define SUB3(a,b,c) SUB2(a,b) - U_PTR(c)
#define SUB4(a,b,c,d) SUB3(a,b,c) - U_PTR(d)
#define SUB5(a,b,c,d,e) SUB4(a,b,c,d) - U_PTR(e)
#define SUB6(a,b,c,d,e,f) SUB5(a,b,c,d,e) - U_PTR(f)
#define SUB7(a,b,c,d,e,f,g) SUB6(a,b,c,d,e,f) - U_PTR(g)
#define SUB8(a,b,c,d,e,f,g,h) SUB7(a,b,c,d,e,f,g) - U_PTR(h)
#define SUB9(a,b,c,d,e,f,g,h,i) SUB8(a,b,c,d,e,f,g,h) - U_PTR(i)
#define SUB10(a,b,c,d,e,f,g,h,i,j) SUB9(a,b,c,d,e,f,g,h,i) - U_PTR(j)
#define SUB_DISPATCH(N, ...) EXPAND_AND_CONCAT(SUB, N)(__VA_ARGS__)
#define PSUB(...) ((PVOID)(SUB_DISPATCH(NARGS(__VA_ARGS__), __VA_ARGS__)))

//
// memory related macros
//
#define MmCopy __builtin_memcpy
#define MmSet  __stosb
#define MmZero RtlSecureZeroMemory

/* Clion IDE hacks */
#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#define TEMPLATE_TYPENAME template <typename T>
#define INLINE            inline
#else
#define CONSTEXPR
#define TEMPLATE_TYPENAME
#define INLINE
#endif

#endif //STARDUST_MACROS_H
