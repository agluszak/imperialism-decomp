#pragma once

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/CString.h"
#include "game/TObject.h"
#include "game/stretch.h"
#include "game/global_data_tables.h"

struct CRuntimeClass;
struct TGlobalMapCityScoreRecord;
class TStream;
class TZone;
class TTaskForce;
class TAdmiral;
struct TZonePrimaryNeighborTag;
struct TZoneSecondaryNeighborTag;

// Mac symbols expose a project-local stretch<T> family. Windows TZone embeds two
// stretch-like secondary subobjects whose vfptrs point into the TZone vtable group.
IMPERIALISM_BEGIN_INTENTIONAL_NON_VIRTUAL_DTOR
// VTABLE: IMPERIALISM 0x0065c74c
class TZonePrimaryNeighborStretch : public stretch<TZone*, TZonePrimaryNeighborTag> {
public:
  // Linear scan for `value`; returns the matching slot or null. Mirrors
  // TZoneSecondaryNeighborStretch::FindEntry (ground truth:
  // RefreshPortZoneNeighborContextLinksAndFallbacks, 0x00563f50, which pre-checks
  // membership before calling GetOrAppendUnique).
  TZone** FindEntry(TZone* value) {
    unsigned int count = Count();
    for (unsigned int index = 0; index < count; ++index) {
      if (Data()[index] == value) {
        return &Data()[index];
      }
    }
    return 0;
  }
  bool ContainsEntry(TZone* value) {
    return FindEntry(value) != 0;
  }

  TZone** GetOrAppendUnique(TZone* zone) override; // 0x55e8e0
  // Not a vtable slot (see stretch.h); called only on the concrete type.
  void Add(TZone* zone); // 0x55ead0
  // Grows `data`/`capacity` to hold at least `count` elements (doubling capacity,
  // clamped to INT_MAX, with a same-size fallback realloc if the doubled request
  // fails). Only this one instantiation (primary neighbors) is evidenced; do not
  // assume TZoneSecondaryNeighborStretch shares the address.
  void EnsureCapacityAtLeast(int count); // 0x561300
  // 0x558860. Grow-on-access accessor: ensures `data`/`capacity` can hold `index`
  // (same doubling/fallback realloc as EnsureCapacityAtLeast), bumps `count` to
  // cover it, and returns a pointer to the element slot. Called on TZone::primaryNeighbors.
  TZone** EnsureSlotAllocatedAndReturnPointer(unsigned int index);
};

// City/province records adjacent to a map-action context. Every reader treats each entry
// as a TGlobalMapCityScoreRecord*, and both map-generation writers append that type.
// EnsurePortZoneForTile (0x005635e0) links a newly founded port to its owning context via
// the PRIMARY stretch at +0x24 in both directions; writing the port into this +0x34 stretch
// is a receiver-offset error and corrupts the city-record index calculation at 0x0055f23a.
// VTABLE: IMPERIALISM 0x0065c748
class TZoneSecondaryNeighborStretch
    : public stretch<TGlobalMapCityScoreRecord*, TZoneSecondaryNeighborTag> {
public:
  // Linear scan for `value`; returns the matching slot or null. Always inlined
  // (ground truth: TOcean::FindMapActionContextContainingNodeByIndex, 0x00564570,
  // where the index/count comparisons are unsigned and the hit materializes as a
  // slot pointer). Lives here rather than on stretch<> because MSVC500 eagerly
  // instantiates template members for element types without operator==.
  TGlobalMapCityScoreRecord** FindEntry(TGlobalMapCityScoreRecord* value) {
    unsigned int count = Count();
    for (unsigned int index = 0; index < count; ++index) {
      if (Data()[index] == value) {
        return &Data()[index];
      }
    }
    return 0;
  }
  bool ContainsEntry(TGlobalMapCityScoreRecord* value) {
    return FindEntry(value) != 0;
  }

public:
  TGlobalMapCityScoreRecord**
  GetOrAppendUnique(TGlobalMapCityScoreRecord* entry) override; // 0x55e9c0
  // Not a vtable slot (see stretch.h); called only on the concrete type. The orig
  // vtable at 0x0065c748 is confirmed exactly 1 slot long (GetOrAppendUnique only).
  void Add(TGlobalMapCityScoreRecord* entry); // 0x55eba0
  // Unconditionally reallocate `data` to hold `count` entries (double-or-exact grow),
  // updating capacity. 0x55fae0.
  void ResizePointerArrayCapacityByRequestedCount(int count);
};
IMPERIALISM_END_INTENTIONAL_NON_VIRTUAL_DTOR

// Map zone / map-action context node (Mac: TZone, TPortZone, TOcean hierarchy).
// Per-nation seed contexts in TOcean use the first 0x48 bytes of this layout.
//
// The original TZone vtable (0x0065c6d8) is 32 slots, but slots 0x17..0x1b are
// literal NULL and only slots 0x1c..0x1f follow them. MSVC500 has no way to emit a
// mid-table NULL (a `= 0` pure virtual emits _purecall, any decl emits a concrete
// addr), so we deliberately model TZone's vtable as ending at its last reachable
// real slot (0x16). The handful of bodies the original placed at slots 0x1c..0x1f
// are kept as ordinary non-virtual methods (paired by address marker, not slot).
// VTABLE: IMPERIALISM 0x0065c6d8
class TZone : public TObject {
public:
  // vtable 0x0065c6d8 — slots 0x00..0x16. Slots 0x02..0x04 (Serialize/AssertValid/
  // Dump) and 0x08..0x09 (ShallowClone/ShallowFree) come from TObject/CObject.
  DECLARE_DYNCREATE(TZone)
  ~TZone() override;                       // slot 0x01 vector dtor 0x562880
  void WriteTo(TStream* stream) override;  // slot 0x05 0x55eff0
  void ReadFrom(TStream* stream) override; // slot 0x06 0x55ed20
  void Free() override;                    // slot 0x07 0x55ec60
  virtual void
  GenerateMapActionContextDisplayNameAndHeadline(void* usedCityFlags,
                                                 void* overrideName);     // slot 0x0a 0x55f780
  virtual void AssignZoneDisplayNameToOutputRef(CString* outputRef);      // slot 0x0b 0x55f070
  virtual void AssignZoneDisplayNameAliasToOutputRef(CString* outputRef); // slot 0x0c 0x55f090
  virtual bool QueryZoneCapabilityFlagA();                                // slot 0x0d 0x55e820
  virtual bool QueryPortZoneCapability();                                 // slot 0x0e 0x55e840
  virtual bool QueryZoneCapabilityFlagC();                                // slot 0x0f 0x55e860
  virtual bool QueryZoneCapabilityFlagD(int unused);                      // slot 0x10 0x55e880
  virtual bool QueryZoneCapabilityFlagE(int unused);                      // slot 0x11 0x55e8a0
  virtual bool HasZoneActiveChildCount(int unused);                       // slot 0x12 0x55e8c0
  virtual short FindNearestActiveSeaContextTileFromOffset216();           // slot 0x13 0x55fe60
  virtual short GetActiveNationSlotTile();                                // slot 0x14 0x55fef0
  virtual short
  FindBestCoastalTileForContextAndCityStateByHeuristic(int contextCityState); // slot 0x15 0x560150
  virtual void SetMapOrderUiFlag(int flag);                                   // slot 0x16 0x560580
  // --- vtable ends at slot 0x16 (orig 0x17..0x1b are NULL; see note above) ---

  // The original table group continues with two embedded stretch<TZone*> member vtables
  // at +0x24/+0x34, then TPortZone. Those stretch bodies are implemented in TZone.cpp.
  // Non-virtual helpers (real bodies in TZone.cpp; not TZone vtable slots).
  // 0x55f0b0 — null-tolerant: the original calls this on possibly-null TZone*
  // (mov ecx, zone; test ecx,ecx inside), so keep the `this == 0` guard.
  short GetContextOrdinalOrInvalid();
  void GenerateZoneStatusCodeIfUnset(); // 0x55f5c0
  // 0x55f300 — find-or-append `zone` to primaryNeighbors via the stretch's virtual
  // GetOrAppendUnique (Ghidra: DispatchMapActionContextCallbackViaField24).
  void AppendUniquePrimaryNeighbor(TZone* zone);
  // Picks the primaryNeighbors entry most at war with nationSlot: a neighbor qualifies
  // if it isn't a port zone or `nationSlot` doesn't hold flag D there, then scores it by
  // how many of the (up to 7) g_apTerrainTypeDescriptorTable nations it lists in
  // nationKeyMask10 (its key mask) are currently at war with nationSlot per
  // TDiplomacyMgr::IsNationPairAtWar. Returns the highest-scoring neighbor, or null if
  // none qualify. 0x560e70.
  TZone* SelectBestPrimaryNeighborForNationDiplomacyMask(int nationSlot);
  // BFS relaxation step over primaryNeighbors, writing shortest known distance
  // (in "hops") into distanceLevel44. level == -1 means "start a fresh search": resets
  // every zone's distanceLevel44 to the 0x29a sentinel first, then reseeds at level 0.
  // Recurses onto each neighbor with level+1 while that improves its distanceLevel44.
  void PropagateMapActionContextDistanceLevelsRecursive(short level); // 0x560f80
  // Zone-graph BFS distance from `this` to `other`, cached in a lazily-(re)built
  // g_pMapActionContextDistanceCache[thisOrd][otherOrd] byte matrix sized by
  // g_nMapActionContextCount; a cache miss (0xff sentinel) triggers a fresh BFS
  // via PropagateMapActionContextDistanceLevelsRecursive and repopulates every
  // (this, node) pair (both directions -- distance is symmetric).
  short GetCachedMapActionContextDistanceOrRecompute(TZone* other); // 0x5610b0
  // 0x0055f4d0 — true when any adjacent city record's ownerNationCode00 == nationTag.
  char HasSecondaryNeighborWithNationTag(short nationTag);
  // 0x0055f540 — true when key's bit is set in nationKeyMask10's low byte, or any
  // secondaryNeighbors entry has ownerNationCode00 == key.
  char IsZoneMaskOrArrayEntryPresentForKey(short key);
  // 0x0055f440 — true when any secondaryNeighbors entry points at
  // &g_pGlobalMapState->cityScoreTable[cityIndex].
  char ContainsCityStatePointerInZoneArrayByCityIndex(short cityIndex);
  // 0x560b00: whether this map-order context has a displayable primary navy order for
  // `nation` (-1 = active nation): nationKeyMask10 bit set and a g_pNavyPrimaryOrderListHead
  // ship with field08 == this, matching owner, field0c == 0 (and field34 == 0 unless
  // skipField34Check). Ghidra's TCivToolbar attribution is junk.
  char CanDisplayMapOrderEntryInCurrentContext(short nation, char skipField34Check);
  // RefreshMapOrderEntryPanel's reachability expansion. A higher remaining depth wins;
  // eligible primary neighbors recurse with depth-1, while the initial call also marks
  // this context's adjacent city records as actionable for TNavyMgr.
  void ExpandTaskForceTraversalDepthAndMarkDeferredNodes(int remainingDepth,
                                                         char markAdjacentCities); // 0x560ba0
  // Naval-intelligence helpers used by TMapUberPicture::NavalIntelligenceDialog.
  // They fold the primary ship list for this zone/nation using the same preference
  // rule as the order UI, then expose its reporting admiral/source label.
  TAdmiral* FindReportingAdmiralForNation(short nation);
  void BuildNavalIntelligenceSourceDescription(CString* out, short nation);
  void InvokeObjectVtableMethod24();
  void* HandleTurnEventVtableSlot24CopyPayloadBuffer();
  // 0x0055f140 — average node value of this context. Port zones (QueryPortZone-
  // Capability true) refresh via AssertValid, then return the home-region city score
  // of the terrain-table owner nation under the port tile (0 if that nation isn't
  // eligible); other contexts average cityScoreValue over the secondaryNeighbors
  // entries (TGlobalMapCityScoreRecord* stretch pun).
  int ComputeMapActionContextNodeValueAverage();

  // statusCode04: -1 sentinel means unset; GenerateZoneStatusCodeIfUnset (0x55f5c0) rolls a
  // PRNG-selected value on first read, then GenerateMapActionContextDisplayNameAndHeadline
  // (0x55f780) uses it as the GetString(0x275a, ...) headline-template index.
  short statusCode04;                           // +0x04
  char pad06[2];                                // +0x06
  CString displayName;                          // +0x08
  int tileOrTerrainId0c;                        // +0x0c tile / terrain id storage
  unsigned short nationKeyMask10;               // +0x10 (key mask in nation context slices)
  short seedNationId12;                         // +0x12 seed nation id arg
  short contextOrdinal14;                       // +0x14 context ordinal
  char pad16[2];                                // +0x16
  TZone* prev18;                                // +0x18 older in g_pMapActionContextListHead chain
  TZone* next1c;                                // +0x1c newer link
  short activeTileIndex20;                      // +0x20 active tile index
  char pad22[2];                                // +0x22
  TZonePrimaryNeighborStretch primaryNeighbors; // +0x24
  TZoneSecondaryNeighborStretch secondaryNeighbors; // +0x34
  // distanceLevel44: BFS "hops" distance written by
  // PropagateMapActionContextDistanceLevelsRecursive; 0x29a is the "unreached" sentinel.
  short distanceLevel44; // +0x44

  TZone();
  void SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex);

  // 0x0055ff70 — coastal-tile affinity heuristic (cdecl; used by FindBestCoastalTile).
  static int ScoreCoastalTileForContextAndCityStateAffinity(int tileIndex, TZone* contextZone,
                                                            int contextCityState);

  // 0x0055fc40 — Ghidra labeled InputState::; dispatches through TZone vtable 0x50/0x58.
  void HandleKeyDown(int key_id);

  static TZone* GetFirstPortZone();
  TZone* GetNextPortZone();
  static TZone* FindPortZoneByTile(short nTileIndex);

  // 0x00561490 / 0x00561400. Build a bitmask of nations that currently have an active
  // (non-eliminated) type-3 or type-4 map order whose ship sits in this zone; the
  // "IncludingNation" variant also sets `nation`'s own bit.
  unsigned int BuildNationBitmaskForActiveType3Or4Orders();
  unsigned int BuildNationBitmaskForActiveType3Or4OrdersIncludingNation(unsigned char nation);
  // 0x00561510. True if any nation in that active-order mask (excluding `nation`
  // itself) is diplomatically related to `nation` (per g_pDiplomacyTurnStateManager).
  unsigned int HasDiplomaticallyRelatedNationInActiveType3Or4OrderMask(int nation);

  // 0x00561b90. This port zone's owning nation code -- terrainStateTable[stylePayload48]'s
  // ownerNationTag04. (Reads the TPortZone-derived stylePayload48; only valid on a TPortZone.)
  short GetPortZoneOwnerNationCodeFromMissionField48();

  // 0x005619e0. Bidirectionally links this zone with its owning nation's map-order
  // context: resolves the owner nation (terrainStateTable at the zone's active tile),
  // finds that nation's context in g_pActiveMapOrderContext->contextArray, and adds
  // each to the other's primaryNeighbors (GetOrAppendUnique).
  void ResolvePortZoneOwnerContextAndDispatch();

  // 0x005609e0. If `nation` has this map-order context zone flagged (nationKeyMask10 bit) and a
  // matching primary-order ship, builds and returns a new TTaskForce order entry for it
  // (via the TTaskForce(contextAnchor, requiredCount) ctor); otherwise returns null.
  // `nation` == -1 resolves the active nation. Called by
  // TOcean::EnsureSelectedTaskForceForOrderOwnerAndRefresh.
  TTaskForce* CreateTaskForceFromNavyOrdersForNationIfEligible(short nation);

  TZone**& PrimaryZoneHeapData() {
    return primaryNeighbors.Data();
  }
  int& PrimaryZoneHeapCapacity() {
    return primaryNeighbors.Capacity();
  }
  int& PrimaryZoneHeapSize() {
    return primaryNeighbors.Count();
  }
};

ASSERT_SIZE(TZonePrimaryNeighborStretch, 0x10);
ASSERT_SIZE(TZoneSecondaryNeighborStretch, 0x10);
ASSERT_SIZE(TZone, 0x48);

// Walks g_pMapActionContextListHead (via prev18) for the zone whose contextOrdinal14
// context ordinal matches nodeId; -1 and misses return 0. Used by mission deserialization.
TZone* FindMapActionContextByNodeId(short nodeId); // 0x55f100

// Clears the traversal level on every live map-action context and the transient navy-order
// reachability marker on all 0x180 city records before RefreshMapOrderEntryPanel expands it.
void ResetMapActionContextActivityAndNationFlags(); // 0x560e20

// 0x564570 moved to TOcean::FindMapActionContextContainingNodeByIndex — every original
// callsite loads ecx = g_pActiveMapOrderContext before the call (thiscall, this unused).
