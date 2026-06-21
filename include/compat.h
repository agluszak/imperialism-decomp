#ifndef COMPAT_H
#define COMPAT_H

// Various macros to enable compiling with other/newer compilers.

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER >= 1100)
#define COMPAT_MODE
#endif

// Disable "identifier was truncated to '255' characters" warning.
// Impossible to avoid this if using STL map or set.
// This removes most (but not all) occurrences of the warning.
#pragma warning(disable : 4786)

#define MSVC420_VERSION 1020

// Ghidra placeholder integer types. Mirrored here (decomp_types.h also defines
// them and includes this header) so a generated game-class header — which only
// includes its immediate base header — always sees `undefined` even before
// decomp_types.h is pulled in. Identical typedefs are a no-op redefinition when
// both headers are included.
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
#if defined(_MSC_VER) && (_MSC_VER < 1300)
typedef unsigned __int64 undefined8;
#else
typedef unsigned long long undefined8;
#endif
typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long ulong;
#if defined(_MSC_VER) && (_MSC_VER < 1300)
typedef unsigned __int64 qword;
#else
typedef unsigned long long qword;
#endif

// We use `override` so newer compilers can tell us our vtables are valid,
// however this keyword was added in C++11, so we define it as empty for
// compatibility with older compilers. Also define `nullptr` as `0`.
#if __cplusplus < 201103L
#define override
#define nullptr 0

// Pre-C++11 `static_assert` polyfill. C++11's static_assert does not exist on
// MSVC 5.0, so emulate it with the classic negative-size-array trick: a failing
// condition yields an array of size -1, which is a hard compile error. The
// `msg` argument is accepted for source compatibility but unused. We build a
// unique typedef name from __LINE__ so multiple asserts can share a scope.
#define COMPAT_ASSERT_CONCAT_(a, b) a##b
#define COMPAT_ASSERT_CONCAT(a, b) COMPAT_ASSERT_CONCAT_(a, b)
#define static_assert(expr, msg)                                                                   \
  typedef char COMPAT_ASSERT_CONCAT(compat_static_assert_, __LINE__)[(expr) ? 1 : -1]
#endif

// Assert that a class/struct has an exact byte size. Works on both modern
// compilers (real static_assert) and MSVC 5.0 (polyfill above). Use this to pin
// recovered class layouts to their original sizes.
#define ASSERT_SIZE(type, size)                                                                    \
  static_assert(sizeof(type) == (size), #type " must be " #size " bytes")

#endif // COMPAT_H