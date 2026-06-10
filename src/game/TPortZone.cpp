#include "game/TPortZone.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

TPortZone::TPortZone() : TZone() {
  field48 = -1;
}

// FUNCTION: IMPERIALISM 0x00561660
bool TPortZone::QueryZoneCapabilityFlagA() {
  return true;
}

// FUNCTION: IMPERIALISM 0x00561680
bool TPortZone::QueryPortZoneCapability() {
  return true;
}

// FUNCTION: IMPERIALISM 0x005616a0
bool TPortZone::QueryZoneCapabilityFlagC() {
  return false;
}
