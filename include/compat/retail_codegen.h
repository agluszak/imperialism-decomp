#pragma once

#include "compat/compiler.h"

// Preserve listing-proven VC5 inlining decisions in the rare large matching bodies where
// automatic expansion changes call emission. MSVC accepts inline_depth only as a raw
// #pragma (not through __pragma), so the scoped markers deliberately surround that directive.
#define IMPERIALISM_BEGIN_DISABLE_AUTOMATIC_INLINING
#define IMPERIALISM_END_DISABLE_AUTOMATIC_INLINING

// Suppress Clang diagnostics only at listing-proven retail behaviors.
// clang-format off
#if defined(__clang__)
#define IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR                                             \
  _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wnon-virtual-dtor\"")
#define IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR _Pragma("clang diagnostic pop")
#define IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE                                       \
  _Pragma("clang diagnostic push")                                                                 \
      _Pragma("clang diagnostic ignored \"-Wdelete-non-abstract-non-virtual-dtor\"")
#define IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE _Pragma("clang diagnostic pop")
#define IMPERIALISM_BEGIN_RETAIL_UNINITIALIZED_READ                                                \
  _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wsometimes-uninitialized\"")
#define IMPERIALISM_END_RETAIL_UNINITIALIZED_READ _Pragma("clang diagnostic pop")
#define IMPERIALISM_BEGIN_RETAIL_NULL_THIS_CHECK                                                   \
  _Pragma("clang diagnostic push")                                                                 \
      _Pragma("clang diagnostic ignored \"-Wundefined-bool-conversion\"")
#define IMPERIALISM_END_RETAIL_NULL_THIS_CHECK _Pragma("clang diagnostic pop")
#define IMPERIALISM_BEGIN_RETAIL_POLYMORPHIC_BYTE_COPY                                             \
  _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wdynamic-class-memaccess\"")
#define IMPERIALISM_END_RETAIL_POLYMORPHIC_BYTE_COPY _Pragma("clang diagnostic pop")
#else
#define IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
#define IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR
#define IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
#define IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
#define IMPERIALISM_BEGIN_RETAIL_UNINITIALIZED_READ
#define IMPERIALISM_END_RETAIL_UNINITIALIZED_READ
#define IMPERIALISM_BEGIN_RETAIL_NULL_THIS_CHECK
#define IMPERIALISM_END_RETAIL_NULL_THIS_CHECK
#define IMPERIALISM_BEGIN_RETAIL_POLYMORPHIC_BYTE_COPY
#define IMPERIALISM_END_RETAIL_POLYMORPHIC_BYTE_COPY
#endif
// clang-format on
