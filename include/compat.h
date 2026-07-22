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

// Suppress -Wnon-virtual-dtor around a class whose *original* vtable is verified
// (Ghidra disassembly, or COM ABI convention) to have no destructor slot at all.
// MSVC 5.0 never warned about this; adding a real destructor here would insert a
// vtable slot the original binary doesn't have and corrupt the modeled layout.
#if defined(__clang__)
#define IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR                                             \
  _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wnon-virtual-dtor\"")
#define IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR _Pragma("clang diagnostic pop")
#else
#define IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
#define IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
#endif

// Suppress Clang's exact-type delete warning only at call sites where the recovered
// class deliberately has a non-virtual destructor. This is narrower than disabling
// -Wdelete-non-abstract-non-virtual-dtor for the whole lint build: every use must sit
// beside evidence that the original vtable has no destructor slot and that the delete
// expression names the concrete type.
// clang-format off
#if defined(__clang__)
#define IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE                                       \
  _Pragma("clang diagnostic push")                                                                 \
      _Pragma("clang diagnostic ignored \"-Wdelete-non-abstract-non-virtual-dtor\"")
#define IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE _Pragma("clang diagnostic pop")
#else
#define IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
#define IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
#endif

// Preserve listing-proven reads of genuinely uninitialized retail stack slots. Keep
// this scoped to the exact function; new uninitialized reads remain lint failures.
#if defined(__clang__)
#define IMPERIALISM_BEGIN_RETAIL_UNINITIALIZED_READ                                                \
  _Pragma("clang diagnostic push")                                                                 \
  _Pragma("clang diagnostic ignored \"-Wsometimes-uninitialized\"")
#define IMPERIALISM_END_RETAIL_UNINITIALIZED_READ _Pragma("clang diagnostic pop")
#else
#define IMPERIALISM_BEGIN_RETAIL_UNINITIALIZED_READ
#define IMPERIALISM_END_RETAIL_UNINITIALIZED_READ
#endif

// Preserve the few retail methods which explicitly test a possibly-null `this` before
// accessing fields. Such calls are undefined in standard C++, but removing the test
// changes the original behavior and code shape.
#if defined(__clang__)
#define IMPERIALISM_BEGIN_RETAIL_NULL_THIS_CHECK                                                   \
  _Pragma("clang diagnostic push")                                                                 \
      _Pragma("clang diagnostic ignored \"-Wundefined-bool-conversion\"")
#define IMPERIALISM_END_RETAIL_NULL_THIS_CHECK _Pragma("clang diagnostic pop")
#else
#define IMPERIALISM_BEGIN_RETAIL_NULL_THIS_CHECK
#define IMPERIALISM_END_RETAIL_NULL_THIS_CHECK
#endif

// Preserve listing-proven whole-object byte copies performed by the retail binary.
// These copies include the vptr and are not ordinary C++ assignment; keep the warning
// active everywhere else so a new polymorphic memcpy is investigated.
#if defined(__clang__)
#define IMPERIALISM_BEGIN_RETAIL_POLYMORPHIC_BYTE_COPY                                             \
  _Pragma("clang diagnostic push")                                                                 \
  _Pragma("clang diagnostic ignored \"-Wdynamic-class-memaccess\"")
#define IMPERIALISM_END_RETAIL_POLYMORPHIC_BYTE_COPY _Pragma("clang diagnostic pop")
#else
#define IMPERIALISM_BEGIN_RETAIL_POLYMORPHIC_BYTE_COPY
#define IMPERIALISM_END_RETAIL_POLYMORPHIC_BYTE_COPY
#endif
// clang-format on

#endif // COMPAT_H
