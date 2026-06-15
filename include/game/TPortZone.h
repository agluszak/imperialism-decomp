#pragma once

#include "compat.h"
#include "game/TZone.h"

// Port-zone map-action node; overrides capability virtual slots 0x34/0x38/0x3c.
// VTABLE: IMPERIALISM 0x0065c758
class TPortZone : public TZone {
public:
  static TPortZone* CreateTPortZone();

  TPortZone();

  CRuntimeClass* GetRuntimeClass() const override;

  bool QueryZoneCapabilityFlagA() override;
  bool QueryPortZoneCapability() override;
  bool QueryZoneCapabilityFlagC() override;
};
