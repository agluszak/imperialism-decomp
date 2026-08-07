#ifndef IMPERIALISM_RUNTIME_GAME_SNAPSHOT_H
#define IMPERIALISM_RUNTIME_GAME_SNAPSHOT_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeGameSnapshot is test-only and must not be included in the production build
#endif

class RuntimeRun;

void CaptureRuntimeGameSnapshot(RuntimeRun& run);

#endif
