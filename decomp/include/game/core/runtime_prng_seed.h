#pragma once

// Retail seeds several PRNGs from the wall clock, and production builds keep time(0).
// Under the runtime-test profile the scenario supplies the seed so maps are reproducible.

#include <time.h>

#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeTestDriver.h"
#endif

#ifdef IMPERIALISM_RUNTIME_TESTS
#define ClockDerivedPrngSeed() static_cast<int>(RuntimeTestDriver::RandomSeed())
#else
#define ClockDerivedPrngSeed() static_cast<int>(time(0))
#endif
