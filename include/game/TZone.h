#pragma once

#include "decomp_types.h"

#include "game/mfc.h"
#include "game/CString.h"

struct CRuntimeClass;

// Map zone / map-action context node (Mac: TZone, TPortZone, TOcean hierarchy).
// Per-nation seed contexts in TOcean use the first 0x48 bytes of this layout.
// VTABLE: IMPERIALISM 0x0065c6d8
class TZone {
public:
// === BEGIN GENERATED DECLS (TZone) — refreshed by recover-class; do not hand-edit ===
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x55eff0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x55ed20
  virtual void Free() override; // slot 0x07 0x55ec60
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined AssignZoneDisplayNameToOutputRef_0b(); // slot 0x0b 0x55f070
  virtual undefined AssignZoneDisplayNameAliasToOutputRef_0c(); // slot 0x0c 0x55f090
  virtual undefined ReturnTrueForZoneCapabilityFlagA(); // slot 0x0d 0x55e820
  virtual undefined ReturnFalseForZoneCapabilityFlagB(); // slot 0x0e 0x55e840
  virtual undefined ReturnFalseForZoneCapabilityFlagC(); // slot 0x0f 0x55e860
  virtual undefined ReturnFalseForZoneCapabilityFlagD(); // slot 0x10 0x55e880
  virtual undefined ReturnFalseForZoneCapabilityFlagE(); // slot 0x11 0x55e8a0
  virtual undefined GetActiveNationSlotTile_14(); // slot 0x14 0x55fef0
  virtual undefined FindBestCoastalTileForContextAndCityStateByHeuristic_15(); // slot 0x15 0x560150
  virtual undefined SetMapOrderUiFlag_16(); // slot 0x16 0x560580
  virtual undefined GetOrAppendUniqueZonePointerInSecondaryArray(); // slot 0x1c 0x55e9c0
  virtual undefined GetOrAppendUniqueZonePointerInPrimaryArray(); // slot 0x1d 0x55e8e0
  virtual undefined AppendZonePointerToPrimaryArray(); // slot 0x1e 0x55ead0
  virtual undefined AppendZonePointerToSecondaryArray(); // slot 0x1f 0x55eba0
  virtual undefined GetTPortZoneClassNamePointer(); // slot 0x20 0x5617d0
  virtual undefined DestroyTPortZone(); // slot 0x21 0x5616c0
  virtual void Serialize(CArchive& archive); // slot 0x22 0x485e90
  virtual undefined SerializeTPortZoneToBinaryStream(); // slot 0x25 0x561820
  virtual undefined DeserializeTPortZoneFromBinaryStream(); // slot 0x26 0x5617f0
  virtual undefined DestroyTPortZoneAndClearOverlayMarkers(); // slot 0x27 0x561a70
  virtual TObject* ShallowFree(); // slot 0x29 0x415ce0
  virtual undefined RefreshTPortZoneDisplayNameFromLocalization(); // slot 0x2a 0x5618b0
  virtual undefined AssignZoneDisplayNameToOutputRef_2b(); // slot 0x2b 0x55f070
  virtual undefined AssignZoneDisplayNameAliasToOutputRef_2c(); // slot 0x2c 0x55f090
  virtual undefined ReturnTrueForPortZoneCapabilityFlagA(); // slot 0x2d 0x561660
  virtual undefined ReturnTrueForPortZoneCapabilityFlagB(); // slot 0x2e 0x561680
  virtual undefined ReturnFalseForPortZoneCapabilityFlagC(); // slot 0x2f 0x5616a0
  virtual undefined IsPortZoneOwnerNationEqual(); // slot 0x30 0x561b10
  virtual undefined NotifyDiplomacyManagerForPortZoneOwnerNation(); // slot 0x31 0x561b50
  virtual undefined CanPortZoneInteractWithNationUnderDiplomacyRules(); // slot 0x32 0x561dc0
  virtual undefined FindNearestValidPortZoneOrCityContextTile(); // slot 0x33 0x561e40
  virtual undefined GetActiveNationSlotTile_34(); // slot 0x34 0x55fef0
  virtual undefined FindBestCoastalTileForContextAndCityStateByHeuristic_35(); // slot 0x35 0x560150
  virtual undefined SetMapOrderUiFlag_36(); // slot 0x36 0x560580
// === END GENERATED DECLS (TZone) ===
  // vtable 0x0065c6d8 slots 0x00..0x58
  virtual CRuntimeClass* GetRuntimeClass() const;
  // slot 0x04 — scalar deleting destructor @ 0x562880 (SYNTHETIC; see TZone.cpp)
  virtual void HandleTurnEventVtableSlot08(int arg1);
  virtual void AssertValid() const;
  virtual void Dump(CDumpContext& unused) const;
  virtual void SerializeZoneToBinaryStream(void* streamState);
  virtual void DeserializeZoneFromBinaryStream(int streamState);
  virtual void RemoveZoneFromGlobalListAndRelease();
  virtual void InvokeObjectVtableMethod24();
  virtual void* HandleTurnEventVtableSlot24CopyPayloadBuffer();
  virtual void GenerateMapActionContextDisplayNameAndHeadline(int arg1, void* arg2);
  virtual void AssignZoneDisplayNameToOutputRef(void* outputRef);
  virtual void AssignZoneDisplayNameAliasToOutputRef(void* outputRef);
  virtual bool QueryZoneCapabilityFlagA();
  virtual bool QueryPortZoneCapability();
  virtual bool QueryZoneCapabilityFlagC();
  virtual bool QueryZoneCapabilityFlagD(int unused);
  virtual bool QueryZoneCapabilityFlagE(int unused);
  virtual bool HasZoneActiveChildCount(int unused);
  virtual short FindNearestActiveSeaContextTileFromOffset216();
  virtual short MapActionVtableSlot4C();
  virtual short GetActiveNationSlotTile();
  virtual short FindBestCoastalTileForContextAndCityStateByHeuristic(int contextCityState);
  virtual void SetMapOrderUiFlag(int flag);

  short field04;                  // +0x04
  char pad06[6];                  // +0x06
  int field0c;                    // +0x0c tile / terrain id storage
  unsigned short field10;         // +0x10 (key mask in nation context slices)
  short field12;                  // +0x12 seed nation id arg
  short field14;                  // +0x14 context ordinal
  char pad16[2];                  // +0x16
  TZone* prev18;                  // +0x18 older in g_pMapActionContextListHead chain
  TZone* next1c;                  // +0x1c newer link
  short field20;                  // +0x20 active tile index
  char pad22[2];                  // +0x22
  void* field24;                  // +0x24 primary array thunk ptr
  int* portZoneEntries28;         // +0x28 — per-nation port-zone entry vector (0x004dbf00 path)
  int portZoneEntryCount2c;       // +0x2c
  int portZoneActiveEntryCount30; // +0x30
  void* field34;                  // +0x34 secondary array thunk ptr
  void* field38;                  // +0x38 slot-table pointer in HandleKeyDown paths
  int field3c;                    // +0x3c
  int field40;                    // +0x40 slot-table count in HandleKeyDown paths
  int field44;                    // +0x44
  int field48;                    // +0x48 map tile index (also used as short in some paths)
  CString displayName;            // EH member; ctor initializes via empty shared-string ref

  TZone();
  virtual ~TZone();
  void SetMapActionContextTargetTileAndRefreshMarkers(int nationSeedId, int tileIndex);

  // 0x0055ff70 — coastal-tile affinity heuristic (cdecl; used by FindBestCoastalTile).
  static int ScoreCoastalTileForContextAndCityStateAffinity(int tileIndex, TZone* contextZone,
                                                            int contextCityState);

  // 0x0055fc40 — Ghidra labeled InputState::; dispatches through TZone vtable 0x50/0x58.
  void HandleKeyDown(int key_id);

  static TZone* FindFirstPortZoneContextByNation(short nationSlot);
};

extern TZone* g_pMapActionContextListHead;

// Nation-sized map-action context embedded in TOcean::contextArray (stride 0x48).
struct TMapNationActionContext {
  char storage[0x48];
};

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
