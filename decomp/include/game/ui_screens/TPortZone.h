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
  ~TPortZone() override;

  DECLARE_DYNCREATE(TPortZone)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;
  void NameThyself(unsigned char* usedCityFlags, const char* overrideName) override;
  bool IsSeaZone() override;
  bool IsPortZone() override;
  bool IsProvincial() override;
  bool IsFriendlyWith(NationSlot nationSlot) override;
  bool IsEnemyOf(NationSlot nationSlot) override;
  short GetOriginalOwner();
  TPortZone* GetPrevPort();
  bool CanBeTargetOf(TTaskForce* force) override;
  short PickPennantIngotTile() override;

  short portTileIndex;
  unsigned char pad4a[2];
};

ASSERT_SIZE(TPortZone, 0x4c);

TPortZone* FindLastPortZoneInMapActionContextList();
