#pragma once

// The retail game deliberately reseeds its zone/status-code PRNG from the wall clock
// at several points during map setup -- TMapMgr::RebuildMapContextAndGlobalMapState and
// TMapMgr's province-naming tail both do it unconditionally, and TMapMaker falls back to
// it when the tuning-string hash comes out zero. That is faithful to the original and
// production builds must keep it exactly.
//
// It also means one seed does not imply one map, which made every map-oracle runtime
// test flaky: three different maps were observed for seed 1 (representative tiles 1360,
// 4061 and 1998) with nothing changed but wall-clock time
// (imperialism-decomp-nhot). Under the runtime-test profile the seed therefore comes
// from the scenario instead, the same way TSimMgr::ReinitializeRandomSeed already
// substitutes RuntimeTestDriver::RandomSeed() for its own time(0) call.
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
