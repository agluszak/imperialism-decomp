#ifndef IMPERIALISM_RUNTIME_GENERATED_WORLD_SNAPSHOT_H
#define IMPERIALISM_RUNTIME_GENERATED_WORLD_SNAPSHOT_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeGeneratedWorldSnapshot is test-only and must not be included in the production build
#endif

class RuntimeRun;
class CString;

bool BuildRuntimeGeneratedWorldSnapshot(const RuntimeRun& run, CString& snapshotJson);
void CaptureRuntimeGeneratedWorldSnapshot(RuntimeRun& run);

#endif
