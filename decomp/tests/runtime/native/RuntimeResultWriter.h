#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeResultWriter is test-only and must not be included in the production build
#endif

class RuntimeRun;
class RuntimeScenario;

bool WriteRuntimeResult(RuntimeRun& run, RuntimeScenario& scenario, const char* status,
                        const char* failureJson);
