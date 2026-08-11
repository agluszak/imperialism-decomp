#ifndef IMPERIALISM_NATIVE_CASES_H
#define IMPERIALISM_NATIVE_CASES_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error NativeCases is test-only and must not be included in the production build
#endif

#include "NativeTransition.h"

struct NativeCase {
  const char* name;
  RuntimeActionResult (*run)(NativeTransition&);
};

const NativeCase* FindNativeCase(const char* name);

#endif
