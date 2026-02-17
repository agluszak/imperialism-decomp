#pragma once

typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned short undefined2;
typedef unsigned int undefined4;

#if defined(_MSC_VER) && (_MSC_VER < 1300)
typedef unsigned __int64 undefined8;
#else
typedef unsigned long long undefined8;
#endif

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
#if defined(_MSC_VER) && (_MSC_VER < 1300)
typedef __int64 s64;
#else
typedef signed long long s64;
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
#if defined(_MSC_VER) && (_MSC_VER < 1300)
typedef unsigned __int64 u64;
#else
typedef unsigned long long u64;
#endif

#ifndef _MSC_VER
#ifndef __cdecl
#define __cdecl
#endif
#ifndef __stdcall
#define __stdcall
#endif
#ifndef __thiscall
#define __thiscall
#endif
#endif
