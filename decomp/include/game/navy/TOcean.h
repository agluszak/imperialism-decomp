#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/app/TObject.h"
#include "game/core/TStream.h"
#include "game/map/TZone.h"

class TCity;
class TTaskForce;

// VTABLE: IMPERIALISM 0x0065c7c8
class TOcean : public TObject {
public:
  TOcean()
      : nationCount(0), contextArray(0), routeNodeCount(0), routeSegments(0), selectedTaskForce(0) {
  }
  DECLARE_DYNCREATE(TOcean)
  virtual ~TOcean() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  short nationCount;
  TZone* contextArray;
  short routeNodeCount; // +0x0c number of route records in routeSegments
  char pad0e[2];
  CRect* routeSegments; // +0x10 heap buffer of routeNodeCount map-route line segments
  TTaskForce* selectedTaskForce;

  // Reallocate routeSegments to hold `count` 0x10-byte route records.
  void SetNumSeaZones(short count);

  // Map-action context (TZone, stride 0x48) at the given index in contextArray.
  TZone* Seath(short index);

  void BuildPort(short nTileIndex);

  void NukePort(short nTileIndex);

  TZone* GetPortZone(short nationSlot);

  TZone* GetSeaZoneAdjacentTo(int cityRecordIndex);

  int GetAverageSeaZoneValue();

  void CreateZones(int nationCountArg);

  void UpdateOccupants();

  TZone* Sea(short nationCode);

  // Resolves port-zone or per-nation map-action context for a sea/coastal tile.
  TZone* GetZoneAt(short seaTileIndex);

  TZone* FindPortZoneBySelectedTile(TCity* city);

  void CommitForce(TTaskForce* entry);

  void ForgetForce(TTaskForce* entry);

  TTaskForce* AssembleUIForce(TZone* pMapOrderContextZone);
};

ASSERT_SIZE(TOcean, 0x18);

// Map-action-context maintenance passes (bodies in TZone.cpp).
void LinkPortZones();
void RefreshPortLinks();
void RegenerateZoneCodes();

TTaskForce* GetActiveMapOrderEntry();
