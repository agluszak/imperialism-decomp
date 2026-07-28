#pragma once

#include <stddef.h>

#include "compat/compiler.h"

// Compile-time layout contracts for recovered records.
#define ASSERT_SIZE(type, size)                                                                    \
  static_assert(sizeof(type) == (size), #type " must be " #size " bytes")

#define ASSERT_OFFSET(type, field, offset)                                                         \
  static_assert(offsetof(type, field) == (offset), #type "::" #field " has wrong offset")
