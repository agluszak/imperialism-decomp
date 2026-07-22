#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeTestDriver is test-only and must not be included in the production build
#endif

class RuntimeTestDriver {
public:
  static void OnIdle();
};
