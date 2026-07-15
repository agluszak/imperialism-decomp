#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"
#include "game/TStream.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

class TCity;
class TTaskForce;

// TOcean map-order runtime singleton (g_pActiveMapOrderContext @ 0x6a3fbc).
// Ghidra historically labeled this InputState for container-level methods.
// Polymorphic MFC object (vtable 0x0065c7c8, 10 slots — TObject's own Free/
// ShallowClone/ShallowFree slots 0x07-0x09 included: TOcean overrides Free,
// inherits ShallowClone/ShallowFree unchanged); per-zone nodes use TZone vtable
// 0x0065c6d8.
// VTABLE: IMPERIALISM 0x0065c7c8
class TOcean : public TObject {
public:
  TOcean();
  // === BEGIN GENERATED DECLS (TOcean) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TOcean)
  virtual ~TOcean() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5628f0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x562340
  virtual void Free() override;                    // slot 0x07 0x5621e0
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // === END GENERATED DECLS (TOcean) ===
  short nationCount;     // +0x04
  TZone* contextArray;   // +0x08
  short routeNodeCount;  // +0x0c number of route-node records in routeNodeBuffer
  char pad0e[2];         // +0x0e
  void* routeNodeBuffer; // +0x10 heap buffer of routeNodeCount 0x10-byte route records
  // +0x14: the currently-selected task force cached for the active map-order entry
  // (maintained by EnsureSelectedTaskForceForOrderOwnerAndRefresh); zeroed in the ctor.
  TTaskForce* selectedTaskForce14; // +0x14

  // Reallocate routeNodeBuffer to hold `count` 0x10-byte route records. 0x0052e7b0.
  void AllocateRouteNodeStateBufferByCount(short count);

  // Map-action context (TZone, stride 0x48) at the given index in contextArray. 0x00563330.
  TZone* GetMapActionContextEntryByIndex(short index);

  // 0x00563540 — walk g_pMapActionContextListHead for TPortZone contexts owned by
  // nationSlot. Real __thiscall on the TOcean singleton (ret 4; callers load
  // g_pActiveMapOrderContext into ecx); `this` is unused by the body.
  TZone* FindFirstPortZoneContextByNation(short nationSlot);

  void InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg);

  // 0x562f20 - refresh every map-action context's nation overlays and per-nation order
  // ranks after an order-list resync (turn-event-0x2E receive path calls it right after
  // TNavyMgr::DeserializeNavyOrderListsByNation).
  void RefreshMapActionContextNationOverlaysAndOrderRanks();

  // __inline: the original inlines this pointer calc at its call sites (e.g.
  // TZone::ResolvePortZoneOwnerContextAndDispatch) while keeping the standalone copy
  // at 0x00563300, so it must be inline-visible to match.
  // FUNCTION: IMPERIALISM 0x00563300
  __inline TZone* GetMapActionContextEntryByNationCodeOffset17(short nationCode) {
    return &this->contextArray[nationCode - 0x17];
  }

  // Resolves port-zone or per-nation map-action context for a sea/coastal tile. 0x5633b0.
  TZone* GetLinkedZoneForSeaTile(short seaTileIndex);

  // 0x005634a0 — walks g_pMapActionContextListHead for TPortZone tile-id match.
  TZone* FindPortZoneBySelectedTile(TCity* city);

  // bd 1uj.16: final step of TTaskForce::SetMapOrderType9AndQueue /
  // PromoteMapOrderChainAndQueue (0x552f80 / 0x5533f0). Not yet recovered --
  // body is a documented placeholder; see bd 1uj.16 follow-up notes.
  void FinalizeQueuedMapOrderEntry(TTaskForce* entry); // 0x5642e0

  // Frees the previously-tracked task force if the new map-order context zone is null,
  // or resolves/caches one for it via GetActiveNationId(); returns the (possibly
  // updated) cached task force. The map-order "entry" is the selected context TZone
  // (its CreateTaskForceFromNavyOrders... factory produces the task force). 0x00564600.
  TTaskForce* EnsureSelectedTaskForceForOrderOwnerAndRefresh(TZone* pMapOrderContextZone);
};

ASSERT_SIZE(TOcean, 0x18);

void NotifyMapUberPictureTileMarker(short tileIndex);

// Map-action-context maintenance passes (bodies in TZone.cpp).
void PopulatePortZoneAdjacencyToNearbyCityContexts(); // 0x00563da0
void RegenerateAllMapActionContextStatusCodes();      // 0x00563220

void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte);
int ComputeGlobalMapActionContextNodeValueAverage(void);

// Returns the currently active map-order entry (g_pActiveMapOrderContext->
// selectedTaskForce14). Ghidra labels this __thiscall, but the real call sites (e.g.
// TToolBarCluster::TryHandleMapContextAction's case-10 branch) pass an unrelated
// TMapUberPicture receiver in ecx and the body never touches `this` -- it reads the
// TOcean global directly, so the thiscall attribution is spurious. 0x005979f0.
TTaskForce* GetActiveMapOrderEntry();
