#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeRegistry is test-only and must not be included in the production build
#endif

class RuntimeTestCase;

enum RuntimeCaptureFlags {
  kRuntimeCaptureNone = 0,
  kRuntimeCaptureUiTree = 1,
  kRuntimeCaptureMapState = 2,
  kRuntimeCaptureGameState = 4,
  kRuntimeCaptureCoarseMapGeneration = 8,
  kRuntimeCaptureRandomMapTerrain = 16,
  kRuntimeCaptureRandomGameSetup = 32
};

struct RuntimeTestDescriptor {
  const char* name;
  RuntimeTestCase* testCase;
  unsigned int captureFlags;
  const char* evidenceKind;
  // Harness policy, from the catalog rather than from a virtual override in the scenario.
  bool recordsGameFlow;
  const int* uiSnapshotEvents;
  int uiSnapshotEventCount;
};

class RuntimeRegistry {
public:
  static const RuntimeTestDescriptor* Find(const char* name);
  static const RuntimeTestDescriptor* Descriptors();
  static int DescriptorCount();
};
