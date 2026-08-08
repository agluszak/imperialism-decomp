#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeResultWriter is test-only and must not be included in the production build
#endif

class RuntimeRun;

bool WriteRuntimeResult(RuntimeRun& run, const char* status);
