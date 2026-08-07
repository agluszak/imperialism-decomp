#pragma once

#include "compat.h"
#include "game/map/TZone.h"

// Port-zone map-action node; overrides capability virtual slots 0x34/0x38/0x3c.
// VTABLE: IMPERIALISM 0x0065c758
class TPortZone : public TZone {
public:
  // The original inlines this at every `new TPortZone()` call site instead of emitting
  // a standalone out-of-line copy (see the ctors-dtors-eh skill's trivial-ctor-factory
  // note); define it inline here so it inlines the same way, not as a real CALL.
  TPortZone() : TZone() {
    portTileIndex48 = -1;
  }
  ~TPortZone() override; // slot 0x01 scalar deleting destructor 0x5616c0

  // TPortZone overrides TZone vtable slots (table ends at slot 0x16, same as TZone).
  // The PortZone-specific body addresses are given per slot.
  DECLARE_DYNCREATE(TPortZone)
  void WriteTo(TStream* stream) override;  // slot 0x05 0x561820
  void ReadFrom(TStream* stream) override; // slot 0x06 0x5617f0
  void Free() override;                    // slot 0x07 0x561a70
  void GenerateMapActionContextDisplayNameAndHeadline(
      unsigned char* usedCityFlags,
      const char* overrideName) override;                        // slot 0x0a 0x5618b0
  bool QueryZoneCapabilityFlagA() override;                      // slot 0x0d 0x561660
  bool QueryPortZoneCapability() override;                       // slot 0x0e 0x561680
  bool QueryZoneCapabilityFlagC() override;                      // slot 0x0f 0x5616a0
  bool QueryZoneCapabilityFlagD(NationSlot nationSlot) override; // slot 0x10 0x561b10
  bool QueryZoneCapabilityFlagE(NationSlot nationSlot) override; // slot 0x11 0x561b50
  short GetPortTileFormerOwnerNationSlot();
  TPortZone* FindPreviousPortZone();                             // 0x561bc0
  bool HasZoneActiveChildCount(TTaskForce* force) override;      // slot 0x12 0x561dc0
  short FindNearestActiveSeaContextTileFromOffset216() override; // slot 0x13 0x561e40

  // +0x48 selected/coastal tile index. Genuinely a short: every original reader
  // is a `movsx word` (0x55f157, 0x562e15, ...).
  short portTileIndex48;
  unsigned char pad4a[2]; // +0x4a
};

ASSERT_SIZE(TPortZone, 0x4c);

TPortZone* FindLastPortZoneInMapActionContextList();
