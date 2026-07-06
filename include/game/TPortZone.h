#pragma once

#include "compat.h"
#include "game/TZone.h"

// Port-zone map-action node; overrides capability virtual slots 0x34/0x38/0x3c.
// VTABLE: IMPERIALISM 0x0065c758
class TPortZone : public TZone {
public:
  static TPortZone* CreateTPortZone();

  TPortZone();
  ~TPortZone() override; // slot 0x01 scalar deleting destructor 0x5616c0

  // TPortZone overrides TZone vtable slots (table ends at slot 0x16, same as TZone).
  // The PortZone-specific body addresses are given per slot.
  DECLARE_DYNCREATE(TPortZone)
  void WriteTo(TStream* stream) override;  // slot 0x05 0x561820
  void ReadFrom(TStream* stream) override; // slot 0x06 0x5617f0
  void Free() override;                    // slot 0x07 0x561a70
  void
  GenerateMapActionContextDisplayNameAndHeadline(void* usedCityFlags,
                                                 void* overrideName) override; // slot 0x0a 0x5618b0
  bool QueryZoneCapabilityFlagA() override;                                    // slot 0x0d 0x561660
  bool QueryPortZoneCapability() override;                                     // slot 0x0e 0x561680
  bool QueryZoneCapabilityFlagC() override;                                    // slot 0x0f 0x5616a0
  bool QueryZoneCapabilityFlagD(int unused) override;                          // slot 0x10 0x561b10
  bool QueryZoneCapabilityFlagE(int unused) override;                          // slot 0x11 0x561b50
  bool HasZoneActiveChildCount(int unused) override;                           // slot 0x12 0x561dc0
  short FindNearestActiveSeaContextTileFromOffset216() override;               // slot 0x13 0x561e40

  int field48; // +0x48 selected/coastal tile index
};

ASSERT_SIZE(TPortZone, 0x4c);

