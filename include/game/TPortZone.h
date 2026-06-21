#pragma once

#include "compat.h"
#include "game/TZone.h"

// Port-zone map-action node; overrides capability virtual slots 0x34/0x38/0x3c.
// VTABLE: IMPERIALISM 0x0065c758
class TPortZone : public TZone {
public:
// === BEGIN GENERATED DECLS (TPortZone) — refreshed by recover-class; do not hand-edit ===
  virtual ~TPortZone(); // slot 0x01 (scalar deleting destructor)
  virtual void Serialize(CArchive& archive) override; // slot 0x02 0x415ce0
// === END GENERATED DECLS (TPortZone) ===
  static TPortZone* CreateTPortZone();

  TPortZone();

  CRuntimeClass* GetRuntimeClass() const override;

  bool QueryZoneCapabilityFlagA() override;
  bool QueryPortZoneCapability() override;
  bool QueryZoneCapabilityFlagC() override;
};

// === BEGIN GENERATED (TPortZone) — refreshed by `just gen-class TPortZone`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c7e4 (3 slots), object size 0x4c, base TZone
//   slot 0x00  byte 0x00  0x005621e0  override  DispatchNationPendingActionEventCodes
//   slot 0x01  byte 0x04  0x004798d0  override  DeserializeCityProductionQueueCommand
//   slot 0x02  byte 0x08  0x00415ce0  override  OrphanRetStub_0059add0
// object size 0x4c (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TPortZone) ===
