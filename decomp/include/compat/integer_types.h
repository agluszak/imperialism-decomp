#pragma once

// Exact-width aliases and temporary decompiler placeholders. Keep placeholders here so
// handwritten game code has one narrow, removable compatibility dependency.
typedef unsigned char byte;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#if defined(_MSC_VER) && (_MSC_VER < 1300)
typedef __int64 s64;
typedef unsigned __int64 u64;
typedef unsigned __int64 undefined8;
typedef unsigned __int64 qword;
#else
typedef signed long long s64;
typedef unsigned long long u64;
typedef unsigned long long undefined8;
typedef unsigned long long qword;
#endif

typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;

// Legacy compatibility aliases. New code should prefer the exact-width names above.
typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long ulong;
