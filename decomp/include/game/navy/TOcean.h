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
      : TObject(), nationCount(0), contextArray(0), routeNodeCount(0), routeSegments(0),
        selectedTaskForce(0) {}
  DECLARE_DYNCREATE(TOcean)
  virtual ~TOcean() override;                      // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5628f0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x562340
  virtual void Free() override;                    // slot 0x07 0x5621e0
  short nationCount;                               // +0x04
  TZone* contextArray;                             // +0x08
  short routeNodeCount;                            // +0x0c number of route records in routeSegments
  char pad0e[2];                                   // +0x0e
  CRect* routeSegments;          // +0x10 heap buffer of routeNodeCount map-route line segments
  TTaskForce* selectedTaskForce; // +0x14

  // Reallocate routeSegments to hold `count` 0x10-byte route records. 0x0052e7b0.
  void SetNumSeaZones(short count);

  // Map-action context (TZone, stride 0x48) at the given index in contextArray. 0x00563330.
  TZone* Seath(short index);

  void BuildPort(short nTileIndex);

  void NukePort(short nTileIndex);

  TZone* FindFirstPortZoneContextByNation(short nationSlot);

  TZone* GetSeaZoneAdjacentTo(int cityRecordIndex);

  int GetAverageSeaZoneValue();

  void InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg);

  void UpdateOccupants();

  TZone* Sea(short nationCode);

  // Resolves port-zone or per-nation map-action context for a sea/coastal tile. 0x5633b0.
  TZone* GetZoneAt(short seaTileIndex);

  TZone* FindPortZoneBySelectedTile(TCity* city);

  void CommitForce(TTaskForce* entry); // 0x5642e0

  void ForgetForce(TTaskForce* entry); // 0x564400

  TTaskForce* AssembleUIForce(TZone* pMapOrderContextZone);
};

ASSERT_SIZE(TOcean, 0x18);

// Map-action-context maintenance passes (bodies in TZone.cpp).
void PopulatePortZoneAdjacencyToNearbyCityContexts();   // 0x00563da0
void RefreshPortZoneNeighborContextLinksAndFallbacks(); // 0x00563f50
void RegenerateAllMapActionContextStatusCodes();        // 0x00563220

TTaskForce* GetActiveMapOrderEntry();
