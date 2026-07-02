#pragma once

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/CString.h"
#include "game/TObject.h"
#include "game/stretch.h"
#include "game/global_data_tables.h"

struct CRuntimeClass;
class TStream;
class TZone;
struct TZonePrimaryNeighborTag;
struct TZoneSecondaryNeighborTag;

// Mac symbols expose a project-local stretch<T> family. Windows TZone embeds two
// stretch-like secondary subobjects whose vfptrs point into the TZone vtable group.
// VTABLE: IMPERIALISM 0x0065c74c
class TZonePrimaryNeighborStretch : public stretch<TZone*, TZonePrimaryNeighborTag> {
public:
  TZone** GetOrAppendUnique(TZone* zone) override; // 0x55e8e0
  // Not a vtable slot (see stretch.h); called only on the concrete type.
  void Add(TZone* zone); // 0x55ead0
  // Grows `data`/`capacity` to hold at least `count` elements (doubling capacity,
  // clamped to INT_MAX, with a same-size fallback realloc if the doubled request
  // fails). Only this one instantiation (primary neighbors) is evidenced; do not
  // assume TZoneSecondaryNeighborStretch shares the address.
  void EnsureCapacityAtLeast(int count); // 0x561300
};

// VTABLE: IMPERIALISM 0x0065c748
class TZoneSecondaryNeighborStretch : public stretch<TZone*, TZoneSecondaryNeighborTag> {
public:
  TZone** GetOrAppendUnique(TZone* zone) override; // 0x55e9c0
  // Not a vtable slot (see stretch.h); called only on the concrete type. The orig
  // vtable at 0x0065c748 is confirmed exactly 1 slot long (GetOrAppendUnique only).
  void Add(TZone* zone); // 0x55eba0
};

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
  virtual void GenerateMapActionContextDisplayNameAndHeadline(int arg1,
                                                              void* arg2); // slot 0x0a 0x55f780
  virtual void AssignZoneDisplayNameToOutputRef(void* outputRef);          // slot 0x0b 0x55f070
  virtual void AssignZoneDisplayNameAliasToOutputRef(void* outputRef);     // slot 0x0c 0x55f090
  virtual bool QueryZoneCapabilityFlagA();                                 // slot 0x0d 0x55e820
  virtual bool QueryPortZoneCapability();                                  // slot 0x0e 0x55e840
  virtual bool QueryZoneCapabilityFlagC();                                 // slot 0x0f 0x55e860
  virtual bool QueryZoneCapabilityFlagD(int unused);                       // slot 0x10 0x55e880
  virtual bool QueryZoneCapabilityFlagE(int unused);                       // slot 0x11 0x55e8a0
  virtual bool HasZoneActiveChildCount(int unused);                        // slot 0x12 0x55e8c0
  virtual short FindNearestActiveSeaContextTileFromOffset216();            // slot 0x13 0x55fe60
  virtual short GetActiveNationSlotTile();                                 // slot 0x14 0x55fef0
  virtual short
  FindBestCoastalTileForContextAndCityStateByHeuristic(int contextCityState); // slot 0x15 0x560150
  virtual void SetMapOrderUiFlag(int flag);                                   // slot 0x16 0x560580
  // --- vtable ends at slot 0x16 (orig 0x17..0x1b are NULL; see note above) ---

  // The original table group continues with two embedded stretch<TZone*> member vtables
  // at +0x24/+0x34, then TPortZone. Those stretch bodies are implemented in TZone.cpp.
  void AppendZonePointerToPrimaryArray(TZone* zone) {
    primaryNeighbors.Add(zone);
  }
  void AppendZonePointerToSecondaryArray(TZone* zone) {
    secondaryNeighbors.Add(zone);
  }

  // Non-virtual helpers (real bodies in TZone.cpp; not TZone vtable slots).
  // 0x55f0b0 — null-tolerant: the original calls this on possibly-null TZone*
  // (mov ecx, zone; test ecx,ecx inside), so keep the `this == 0` guard.
  short GetContextOrdinalOrInvalid();
  void GenerateZoneStatusCodeIfUnset(); // 0x55f5c0
  // BFS relaxation step over primaryNeighbors, writing shortest known distance
  // (in "hops") into field44. level == -1 means "start a fresh search": resets
  // every zone's field44 to the 0x29a sentinel first, then reseeds at level 0.
  // Recurses onto each neighbor with level+1 while that improves its field44.
  void PropagateMapActionContextDistanceLevelsRecursive(short level); // 0x560f80
  // Zone-graph BFS distance from `this` to `other`, cached in a lazily-(re)built
  // g_pMapActionContextDistanceCache[thisOrd][otherOrd] byte matrix sized by
  // g_nMapActionContextCount; a cache miss (0xff sentinel) triggers a fresh BFS
  // via PropagateMapActionContextDistanceLevelsRecursive and repopulates every
  // (this, node) pair (both directions -- distance is symmetric).
  short GetCachedMapActionContextDistanceOrRecompute(TZone* other); // 0x5610b0
  void InvokeObjectVtableMethod24();
  void* HandleTurnEventVtableSlot24CopyPayloadBuffer();

  short field04;                                // +0x04
  char pad06[2];                                // +0x06
  CString displayName;                          // +0x08
  int field0c;                                  // +0x0c tile / terrain id storage
  unsigned short field10;                       // +0x10 (key mask in nation context slices)
  short field12;                                // +0x12 seed nation id arg
  short field14;                                // +0x14 context ordinal
  char pad16[2];                                // +0x16
  TZone* prev18;                                // +0x18 older in g_pMapActionContextListHead chain
  TZone* next1c;                                // +0x1c newer link
  short field20;                                // +0x20 active tile index
  char pad22[2];                                // +0x22
  TZonePrimaryNeighborStretch primaryNeighbors; // +0x24
  TZoneSecondaryNeighborStretch secondaryNeighbors; // +0x34
  short field44;                                    // +0x44

  TZone();
  void SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex);

  // 0x0055ff70 — coastal-tile affinity heuristic (cdecl; used by FindBestCoastalTile).
  static int ScoreCoastalTileForContextAndCityStateAffinity(int tileIndex, TZone* contextZone,
                                                            int contextCityState);

  // 0x0055fc40 — Ghidra labeled InputState::; dispatches through TZone vtable 0x50/0x58.
  void HandleKeyDown(int key_id);

  static TZone* FindFirstPortZoneContextByNation(short nationSlot);
  static TZone* GetFirstPortZone();
  TZone* GetNextPortZone();
  static TZone* FindPortZoneByTile(short nTileIndex);

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

// Walks g_pMapActionContextListHead (via prev18) for the zone whose field14 context
// ordinal matches nodeId; -1 and misses return 0. Used by mission deserialization.
TZone* FindMapActionContextByNodeId(short nodeId); // 0x55f100

// === BEGIN GENERATED (TZone) — refreshed by `just gen-class TZone`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c6d8 (55 slots), object size 0x48, base TObject
//   slot 0x00  byte 0x00  0x0055e6e0  new       DispatchNationPendingActionEventCodes
//   slot 0x01  byte 0x04  0x00562880  new       SetNationPendingActionStateAndPayload
//   slot 0x02  byte 0x08  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x0055eff0  new       ExecuteNationPendingActionStateMachine
//   slot 0x06  byte 0x18  0x0055ed20  new       HasQueuedCivWorkOrderType7
//   slot 0x07  byte 0x1c  0x0055ec60  new       GetTCountryClassNamePointer
//   slot 0x08  byte 0x20  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x0055f780  new       OrphanRetStub_0059add0
//   slot 0x0b  byte 0x2c  0x0055f070  new       GetTEventHandlerClassNamePointer
//   slot 0x0c  byte 0x30  0x0055f090  new       HandleCityDialogHintClusterUpdate
//   slot 0x0d  byte 0x34  0x0055e820  new       DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x0e  byte 0x38  0x0055e840  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x0f  byte 0x3c  0x0055e860  new       GetTEventHandlerClassNamePointer
//   slot 0x10  byte 0x40  0x0055e880  new       VTableSlot10
//   slot 0x11  byte 0x44  0x0055e8a0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x12  byte 0x48  0x0055e8c0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x13  byte 0x4c  0x0055fe60  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x14  byte 0x50  0x0055fef0  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x15  byte 0x54  0x00560150  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x16  byte 0x58  0x00560580  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x17  byte 0x5c  0x00000000  null      (null)
//   slot 0x18  byte 0x60  0x00000000  null      (null)
//   slot 0x19  byte 0x64  0x00000000  null      (null)
//   slot 0x1a  byte 0x68  0x00000000  null      (null)
//   slot 0x1b  byte 0x6c  0x00000000  null      (null)
//   slot 0x1c  byte 0x70  0x0055e9c0  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x1d  byte 0x74  0x0055e8e0  new       GetOrAppendUniqueZonePointerInPrimaryArray
//   slot 0x1e  byte 0x78  0x0055ead0  new       AppendZonePointerToPrimaryArray
//   slot 0x1f  byte 0x7c  0x0055eba0  new       AppendZonePointerToSecondaryArray
//   slot 0x20  byte 0x80  0x005617d0  new       GetTPortZoneClassNamePointer
//   slot 0x21  byte 0x84  0x005616c0  new       DestroyTPortZone
//   slot 0x22  byte 0x88  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x23  byte 0x8c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x24  byte 0x90  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x25  byte 0x94  0x00561820  new       SerializeTPortZoneToBinaryStream
//   slot 0x26  byte 0x98  0x005617f0  new       DeserializeTPortZoneFromBinaryStream
//   slot 0x27  byte 0x9c  0x00561a70  new       DestroyTPortZoneAndClearOverlayMarkers
//   slot 0x28  byte 0xa0  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x29  byte 0xa4  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0x2a  byte 0xa8  0x005618b0  new       RefreshTPortZoneDisplayNameFromLocalization
//   slot 0x2b  byte 0xac  0x0055f070  new       GetTEventHandlerClassNamePointer
//   slot 0x2c  byte 0xb0  0x0055f090  new       HandleCityDialogHintClusterUpdate
//   slot 0x2d  byte 0xb4  0x00561660  new       ReturnTrueForPortZoneCapabilityFlagA
//   slot 0x2e  byte 0xb8  0x00561680  new       ReturnTrueForPortZoneCapabilityFlagB
//   slot 0x2f  byte 0xbc  0x005616a0  new       ReturnFalseForPortZoneCapabilityFlagC
//   slot 0x30  byte 0xc0  0x00561b10  new       IsPortZoneOwnerNationEqual
//   slot 0x31  byte 0xc4  0x00561b50  new       NotifyDiplomacyManagerForPortZoneOwnerNation
//   slot 0x32  byte 0xc8  0x00561dc0  new       CanPortZoneInteractWithNationUnderDiplomacyRules
//   slot 0x33  byte 0xcc  0x00561e40  new       FindNearestValidPortZoneOrCityContextTile
//   slot 0x34  byte 0xd0  0x0055fef0  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x35  byte 0xd4  0x00560150  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x36  byte 0xd8  0x00560580  new       ApplyJoinEmpireMode1TargetTransition
// object size 0x48 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TZone) ===
