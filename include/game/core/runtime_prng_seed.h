#pragma once

// The retail game deliberately seeds several PRNG families from the wall clock: the CRT
// rand() stream, map generation, zone/status-code generation, and technology priorities.
// That is faithful to the original and production builds must keep it exactly.
//
// It also means one seed does not imply one map, which made every map-oracle runtime
// test flaky: three different maps were observed for seed 1 (representative tiles 1360,
// 4061 and 1998) with nothing changed but wall-clock time (imperialism-decomp-nhot).
// Under the runtime-test profile every clock-derived PRNG seed therefore comes from the
// scenario.
//
// The substitution is compile-time: production builds expand to plain time(0) and are
// unaffected.

#include <time.h>

#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeTestDriver.h"
#endif

static __inline int ClockDerivedPrngSeed(void) {
#ifdef IMPERIALISM_RUNTIME_TESTS
  return static_cast<int>(RuntimeTestDriver::RandomSeed());
#else
  return static_cast<int>(time(0));
#endif
}
