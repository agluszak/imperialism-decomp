#pragma once

#ifndef IMPERIALISM_UNIT_CHAIN_PROBE_H
#define IMPERIALISM_UNIT_CHAIN_PROBE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error UnitChainProbe is test-only and must not be included in the production build
#endif

#include "screens/RuntimeActionResult.h"

// The map's two unit chains: each province's stationed military units
// (Province::stationedUnitChain98) and each tile's civilian orders
// (TTerrainStateRecord::firstCivilianOrder20), both threaded through
// TUnit::previousAtLocation10/nextAtLocation14.
//
// Walking a corrupt chain is a page fault, not a test failure -- the crash lands inside
// TMilitaryUnit::MoveTo with no scenario context, and under the debugger it does not reproduce. So
// this checks each link *before* following it: a node has to be pointer-shaped, and a chain has to
// terminate. That turns "the process died somewhere in a load" into "manager N left province P's
// chain holding 0xd".
//
// It deliberately does not dereference a node it has already rejected. A cheap plausibility test on
// the pointer value is the whole point: the values this catches (small integers written into a
// pointer slot) are not addresses at all.
class UnitChainProbe {
public:
  // Both chain families are walkable and terminate. `stage` names what just ran, so the failure
  // says which step left them broken.
  static RuntimeActionResult VerifyChainsAreWalkable(const char* stage);
};

#endif
