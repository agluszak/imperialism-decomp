#ifndef IMPERIALISM_RUNTIME_MAP_GENERATION_CAPTURE_H
#define IMPERIALISM_RUNTIME_MAP_GENERATION_CAPTURE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeMapGenerationCapture is test-only and must not be included in the production build
#endif

class RuntimeRun;

void CaptureRuntimeMapGeneration(RuntimeRun& run);

#endif
