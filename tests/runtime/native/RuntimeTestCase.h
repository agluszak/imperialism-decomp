#pragma once

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeTestCase is test-only and must not be included in the production build
#endif

#include "compat.h"

class RuntimeContext;
class TView;

class RuntimeTestCase {
public:
  virtual ~RuntimeTestCase() {}
  virtual void Start(RuntimeContext& context) = 0;
  virtual void Tick(RuntimeContext& context) = 0;
  virtual void ObserveTurnEvent(RuntimeContext&, int) {}
  virtual void ObserveBuiltUiTree(RuntimeContext&, int, TView*) {}
  virtual void Pulse(RuntimeContext&) {}
  virtual unsigned int RandomSeed(RuntimeContext& context) = 0;
  virtual void FailHarness(RuntimeContext& context, const char* failure) = 0;
};
