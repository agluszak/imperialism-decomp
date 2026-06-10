#pragma once

#include "game/TZone.h"

// Port-zone map-action node; overrides capability virtual slots 0x34/0x38/0x3c.
// VTABLE: IMPERIALISM 0x0065c758
class TPortZone : public TZone {
public:
  TPortZone();

  bool QueryZoneCapabilityFlagA();
  bool QueryPortZoneCapability();
  bool QueryZoneCapabilityFlagC();
};
