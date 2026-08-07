#pragma once

#ifndef IMPERIALISM_STARTING_CIVILIANS_PROBE_H
#define IMPERIALISM_STARTING_CIVILIANS_PROBE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error StartingCiviliansProbe is test-only and must not be included in the production build
#endif

#include "screens/RuntimeActionResult.h"

class TCivUnit;

// The civilians a nation starts an Introductory game with.
//
// A probe rather than a screen: nothing here is on screen. What it checks is the shape of the
// nation's tracked-object list -- that it really is the sorted list of civilian units the rest of
// the game assumes, rather than a list that merely behaves like one until something walks it with
// the wrong element type.
class StartingCiviliansProbe {
public:
  // The list exists, is the expected collection class, holds only placed civilians, and holds at
  // least the five an Introductory game grants.
  static RuntimeActionResult VerifyForNation(short nationSlot);

  // The nth civilian (1-based, as the list itself is indexed), or 0.
  static TCivUnit* CivilianForNation(short nationSlot, int ordinal);
};

#endif
