#pragma once

#ifndef IMPERIALISM_RUNTIME_TEST_FACTORY_H
#define IMPERIALISM_RUNTIME_TEST_FACTORY_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error RuntimeTestFactory is test-only and must not be included in the production build
#endif

#include "RuntimeTestCase.h"

// Registration boilerplate for one runtime test.
//
// Adding a test used to touch four places: the .cpp, a hand-maintained declaration in
// RuntimeScenarios.h, the catalog entry in tools/runtime/catalog.py, and a file-static
// instance plus factory function at the bottom of the .cpp. Nothing checked that the
// catalog's `native_factory` string and the header's declaration agreed -- the link step was
// the only verification, and a typo surfaced as an unresolved symbol.
//
// Now the declarations are generated from the catalog (RuntimeScenarioFactories.inc), so the
// catalog is the single source of truth for the name, and this macro supplies the definition:
//
//     RUNTIME_TEST_FACTORY(PlayerBuyOnlyTradeTestCase, PlayerBuyOnlyTradeTest)
//
// The scenario is a file-static singleton, matching every existing test: the harness resolves
// one test case per process and never reconstructs it, so a scenario's mutable state is reset
// by its start-point hook rather than by a constructor.
#define RUNTIME_TEST_FACTORY(CaseClass, FactoryName)                                               \
  namespace {                                                                                      \
  CaseClass g_runtimeTestCaseInstance;                                                             \
  }                                                                                                \
  RuntimeTestCase* FactoryName() {                                                                 \
    return &g_runtimeTestCaseInstance;                                                             \
  }

#endif
