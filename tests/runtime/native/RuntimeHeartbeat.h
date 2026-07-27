#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeHeartbeat is test-only and must not be included in the production build
#endif

class RuntimeRun;

void WriteRuntimeHeartbeat(RuntimeRun& run);
