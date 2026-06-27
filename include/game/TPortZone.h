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
  void WriteTo(TStream* stream) override;                                   // slot 0x05 0x561820
  void ReadFrom(TStream* stream) override;                                  // slot 0x06 0x5617f0
  void Free() override;                                                     // slot 0x07 0x561a70
  void GenerateMapActionContextDisplayNameAndHeadline(int arg1, void* arg2) override; // slot 0x0a 0x5618b0
  bool QueryZoneCapabilityFlagA() override;                                 // slot 0x0d 0x561660
  bool QueryPortZoneCapability() override;                                  // slot 0x0e 0x561680
  bool QueryZoneCapabilityFlagC() override;                                 // slot 0x0f 0x5616a0
  bool QueryZoneCapabilityFlagD(int unused) override;                       // slot 0x10 0x561b10
  bool QueryZoneCapabilityFlagE(int unused) override;                       // slot 0x11 0x561b50
  bool HasZoneActiveChildCount(int unused) override;                        // slot 0x12 0x561dc0
  short FindNearestActiveSeaContextTileFromOffset216() override;            // slot 0x13 0x561e40
};

// === BEGIN GENERATED (TPortZone) — refreshed by `just gen-class TPortZone`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c7e4 (3 slots), object size 0x4c, base TZone
//   slot 0x00  byte 0x00  0x005621e0  override  DispatchNationPendingActionEventCodes
//   slot 0x01  byte 0x04  0x004798d0  override  ShallowClone
//   slot 0x02  byte 0x08  0x00415ce0  override  ShallowFree
// object size 0x4c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TPortZone) ===
