#pragma once

#ifndef IMPERIALISM_CIVILIAN_PROBE_H
#define IMPERIALISM_CIVILIAN_PROBE_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error CivilianProbe is test-only and must not be included in the production build
#endif

#include "screens/RuntimeActionResult.h"

class TAnimation;
class TCivUnit;

// The civilians a nation has produced, and the sprites the map animates them with.
//
// Finding "the one just recruited" means walking the nation's tracked-object list and matching the
// persistent unit id the simulation had just allocated -- which needs the list's element type, and
// so belongs on this side of the boundary rather than repeated in a scenario three times.
class CivilianProbe {
public:
  // The civilian carrying `persistentUnitId`, or 0. The simulation allocates ids in sequence, so a
  // caller that recorded the id before producing knows which one to ask for.
  static TCivUnit* CivilianWithPersistentId(short nationSlot, int persistentUnitId);

  // How many civilians the nation's tracked-object list holds.
  static int CivilianCount(short nationSlot);

  // The animation is the civilian sprite animation, not some other registered animation that
  // happens to share its tag.
  static bool IsCivilianSpriteAnimation(TAnimation* animation);
};

#endif
