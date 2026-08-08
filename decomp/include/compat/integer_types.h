#pragma once

// Exact-width aliases and decompiler placeholders used by recovered source.
typedef unsigned char byte;
typedef signed short s16;

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

typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned short ushort;
