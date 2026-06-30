#pragma once

// Shared inline helpers for trade cluster UI controls.
// Used by TIndustryCluster and TRailCluster.

#include "game/TAmtBar.h"

static __inline short ReadControlValueFieldPlus4(TAmtBar* control) {
  return *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 4);
}
