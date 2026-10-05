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
        selectedTaskForce14(0) {}
  DECLARE_DYNCREATE(TOcean)
  virtual ~TOcean() override;                      // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5628f0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x562340
  virtual void Free() override;                    // slot 0x07 0x5621e0
  short nationCount;                               // +0x04
  TZone* contextArray;                             // +0x08
  short routeNodeCount;                            // +0x0c number of route records in routeSegments
  char pad0e[2];                                   // +0x0e
  CRect* routeSegments; // +0x10 heap buffer of routeNodeCount map-route line segments
  TTaskForce* selectedTaskForce14; // +0x14

  // Reallocate routeSegments to hold `count` 0x10-byte route records. 0x0052e7b0.
  void AllocateRouteNodeStateBufferByCount(short count);

  // Map-action context (TZone, stride 0x48) at the given index in contextArray. 0x00563330.
  TZone* GetMapActionContextEntryByIndex(short index);

  void EnsurePortZoneForTile(short nTileIndex);

  void RemovePortZoneByTile(short nTileIndex);

  TZone* FindFirstPortZoneContextByNation(short nationSlot);

  TZone* FindMapActionContextContainingNodeByIndex(int cityRecordIndex);

  int ComputeGlobalMapActionContextNodeValueAverage();

  void InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg);

  void RefreshMapActionContextNationOverlaysAndOrderRanks();

  TZone* GetMapActionContextEntryByNationCodeOffset17(short nationCode);

  // Resolves port-zone or per-nation map-action context for a sea/coastal tile. 0x5633b0.
  TZone* GetLinkedZoneForSeaTile(short seaTileIndex);

  // 0x005634a0 — walks g_pMapActionContextListHead for TPortZone tile-id match.
  TZone* FindPortZoneBySelectedTile(TCity* city);

  void FinalizeQueuedMapOrderEntry(TTaskForce* entry); // 0x5642e0

  void ForgetForce(TTaskForce* entry); // 0x564400

  TTaskForce* EnsureSelectedTaskForceForOrderOwnerAndRefresh(TZone* pMapOrderContextZone);
};

ASSERT_SIZE(TOcean, 0x18);

// Map-action-context maintenance passes (bodies in TZone.cpp).
void PopulatePortZoneAdjacencyToNearbyCityContexts();   // 0x00563da0
void RefreshPortZoneNeighborContextLinksAndFallbacks(); // 0x00563f50
void RegenerateAllMapActionContextStatusCodes();        // 0x00563220

TTaskForce* GetActiveMapOrderEntry();
