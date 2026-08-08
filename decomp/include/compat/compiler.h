#pragma once

// Compiler and language-version compatibility only.

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER >= 1100)
#define COMPAT_MODE
#endif

#pragma warning(disable : 4786)

#define MSVC420_VERSION 1020

#if __cplusplus < 201103L
#define override
#define nullptr 0

#define COMPAT_ASSERT_CONCAT_(a, b) a##b
#define COMPAT_ASSERT_CONCAT(a, b) COMPAT_ASSERT_CONCAT_(a, b)
#define static_assert(expr, msg)                                                                   \
  typedef char COMPAT_ASSERT_CONCAT(compat_static_assert_, __LINE__)[(expr) ? 1 : -1]
#endif
