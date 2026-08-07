#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeExceptionCapture is test-only and must not be included in the production build
#endif

#include "RuntimeDebuggerTrap.h"

class RuntimeRun;
class RuntimeScenario;
struct _EXCEPTION_POINTERS;

namespace RuntimeExceptionCapture {

void Install(RuntimeRun& run, RuntimeScenario& scenario);
void Trap(RuntimeRun& run, RuntimeScenario& scenario, RuntimeDebugReason reason,
          const char* failureJson, _EXCEPTION_POINTERS* exception);

} // namespace RuntimeExceptionCapture
