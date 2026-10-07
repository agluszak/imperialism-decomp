#pragma once

#include "compat.h"
#include "game/map/TZone.h"

// Port-zone map-action node; overrides capability virtual slots 0x34/0x38/0x3c.
// VTABLE: IMPERIALISM 0x0065c758
class TPortZone : public TZone {
public:
  TPortZone() : TZone() {
    portTileIndex = -1;
  }
  ~TPortZone() override; // slot 0x01 scalar deleting destructor 0x5616c0

  DECLARE_DYNCREATE(TPortZone)
  void WriteTo(TStream* stream) override;  // slot 0x05 0x561820
  void ReadFrom(TStream* stream) override; // slot 0x06 0x5617f0
  void Free() override;                    // slot 0x07 0x561a70
  void NameThyself(unsigned char* usedCityFlags,
                   const char* overrideName) override; // slot 0x0a 0x5618b0
  bool IsSeaZone() override;                           // slot 0x0d 0x561660
  bool IsPortZone() override;                          // slot 0x0e 0x561680
  bool IsProvincial() override;                        // slot 0x0f 0x5616a0
  bool IsFriendlyWith(NationSlot nationSlot) override; // slot 0x10 0x561b10
  bool IsEnemyOf(NationSlot nationSlot) override;      // slot 0x11 0x561b50
  short GetOriginalOwner();
  TPortZone* GetPrevPort();                       // 0x561bc0
  bool CanBeTargetOf(TTaskForce* force) override; // slot 0x12 0x561dc0
  short PickPennantIngotTile() override;          // slot 0x13 0x561e40

  short portTileIndex;
  unsigned char pad4a[2]; // +0x4a
};

ASSERT_SIZE(TPortZone, 0x4c);

TPortZone* FindLastPortZoneInMapActionContextList();
