#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeRegistry is test-only and must not be included in the production build
#endif

class RuntimeTestCase;

struct RuntimeTestDescriptor {
  const char* name;
  RuntimeTestCase* testCase;
};

class RuntimeRegistry {
public:
  static const RuntimeTestDescriptor* Find(const char* name);
  static const RuntimeTestDescriptor* Descriptors();
  static int DescriptorCount();
};
