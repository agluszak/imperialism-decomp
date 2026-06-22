#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/nation_domain_types.h"
#include "game/TObject.h"
#include "game/TPtrList.h"

class TStream;

enum { kTerrainTypeDescriptorTableCount = 23 };

// Intermediate base between TObject and TGreatPower (Ghidra: TCountry). Owns the nation
// identity strings, the nation-slot metrics, the military-unit list and the owned-region
// list, and serializes that sub-object via WriteTo (0x004d6e60) / ReadFrom (0x004d6bf0).
// Its own vtable (0x00653868) is a 52-slot prefix of TGreatPower's 0x00653938; only the
// TObject stream-lifecycle overrides are modeled here, so the vtable is intentionally
// left partial (the 0x0a..0x29 nation virtuals are still declared on TGreatPower).
// VTABLE: IMPERIALISM 0x00653868
class TCountry : public TObject {
public:
  CRuntimeClass* GetRuntimeClass() const override;
  ~TCountry() override;

  // slots 0x05–0x07 — TObject stream lifecycle (Mac: WriteTo / ReadFrom / Free).
  void WriteTo(TStream* stream) override;  // body 0x004d6e60
  void ReadFrom(TStream* stream) override; // body 0x004d6bf0
  void Free() override;                    // body 0x004d6ba0

  // slots 0x0a-0x29 — concrete TCountry prefix. Slots 0x2a-0x33 are NULL in the
  // original base table and remain undeclared; pure virtuals would emit _purecall.
  virtual void WriteCoreFieldsToStream(TStream* stream);
  virtual void ReadCoreFieldsFromStream(TStream* stream, int unusedArg);
  virtual void SeedInitialMilitaryAndNavyOrdersForOwnedRegions(void);
  virtual void CreateMilitaryRecruitOrderForNode(int nodeContext);
  virtual void AddToNationMetricAtField10(int amount);
  virtual void AssignDisplayNamesToUnnamedMilitaryUnits(void);
  virtual int GetHomeRegionCityRecordIndex(void);
  virtual void QueueRecruitOrdersForUndergarrisonedRegions(void);
  virtual void ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel);
  virtual void ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode);
  virtual void SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot);
  virtual void ApplyJoinEmpireMode1TargetTransition(int targetNationSlot);
  virtual void ApplyJoinEmpireMode2FinalizeNationNameState(void);
  virtual char IsEncodedNationSlotMinus200Equal(int nationCode);
  virtual void RemoveRegionIdFromNationOwnedRegionList(int regionId);
  virtual void AddRegionIdToNationOwnedRegionList(int regionId);
  virtual void SetNationPercentFieldByModeAndDescriptorLinks(int targetNationSlot, int policyCode);
  virtual void DecrementDiplomacyCounterA2ByValue(int delta);
  virtual int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot);
  virtual short GetDiplomacyCounterA2(void);
  virtual short GetDiplomacyExternalStateB6ByTarget(short nationSlot);
  virtual short QueryNationMetricBySlot7C(short metricSlot);
  virtual void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                              int multiplier);
  virtual bool IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot);
  virtual char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                             int arg4);
  virtual void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId);
  virtual char ReturnFalseNationStateCapabilityFlag90(int arg);
  virtual void NotifyActionSlot94(int sourceNation, int actionCode);
  virtual char ReturnFalseNationStateCapabilityFlag98(void);
  virtual char ReturnFalseNationStateCapabilityFlag9C(void);
  virtual char ShouldDispatchImmediatelySlot28(void);
  virtual void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2);

  int SumWeightedNeighborLinkScoreForLinkedNodes(void);

  // Diplomacy / nation-state helpers (bodies may access TGreatPower tail via `this`).
  void DeserializeDiplomacyNationStateFromStream(TStream* stream);
  void SerializeDiplomacyNationStateToStream(TStream* stream);
  char IsDiplomacyPolicyAllowedForTargetClassState(short policyCode, short targetNationSlot);
  void SetNationTradePolicyValueForTargetAndNotify(short targetNationSlot, short policyValue);
  void ApplyNationStateCode200AndQueueEvent1B(int targetNationSlot);

  CString identitySharedString0;
  CString identitySharedString1;
  short nationSlot;
  short encodedNationSlot;
  int treasuryValue10;
  short needLevelByNation[0x17];
  short field42;
  // 0x44 — military unit list; entries carry a unit-type short at +4 indexing
  // g_Classify_Nation_Military_LookupTable_00695CD4 power weights.
  TPtrList* militaryUnitList44;
  // 0x48 — per-unit-type counter of names already issued (slot 0x0f increments the
  // type's entry after assigning "<ordinal> <type name>").
  short unitNameOrdinalByType[0x1e];
  short unitNameCounter84; // 0x84 — monotonically increasing name tag (stored at +0x1a)
  short pad_86;
  short ownerNationSlot;
  short pad_8a;
  // 0x8c — serialized as a 4-byte block by slots 0x0a/0x0b together with the
  // 4 bytes at 0x88 (ownerNationSlot + pad).
  int serializedField8c;
  TPtrList* ownedRegionList;

  // Defined inline so MSVC inlines the two CString-member constructions (and the
  // resulting EH frame) into derived ctors, matching the original TGreatPower ctor
  // which inlines the TCountry base construction rather than calling 0x004d67d0.
  TCountry() {}
};

// Nation terrain rows: major slots hold TGreatPower*, minor slots hold TMinor*.
// GLOBAL: IMPERIALISM 0x006a4310
extern TCountry* g_apTerrainTypeDescriptorTable[kTerrainTypeDescriptorTableCount];

// Nation-slot decode and linked-node scoring helpers (terrain table rows are TCountry*).
int DecodeTerrainNationSlotFromDescriptor(const TCountry* terrain, short encodedNationSlot);
int ResolveTerrainNationSlotFromTarget(int targetNationSlot);
int ComputeWeightedNeighborLinkScoreForNode(int nodeIndex);
int ComputeWeightedNeighborLinkScoreForNodeIndex(short nodeIndex);

ASSERT_SIZE(TCountry, 0x94);

// === BEGIN GENERATED (TCountry) — refreshed by `just gen-class TCountry`; do not hand-edit ===
// clang-format off
// vtable @ 0x00653868 (42 slots), object size 0x94, base TObject
//   slot 0x00  byte 0x00  0x004d67b0  new       GetTCountryClassNamePointer
//   slot 0x01  byte 0x04  0x004d6850  new       VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004d6e60  new       WrapperFor_HandleCityDialogNoOpSlot14_At004d6e60
//   slot 0x06  byte 0x18  0x004d6bf0  new       DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x07  byte 0x1c  0x004d6ba0  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x08  byte 0x20  0x004798d0  new       DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  new       OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004d70e0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x0b  byte 0x2c  0x004d7070  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x0c  byte 0x30  0x004d71b0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0d  byte 0x34  0x004d7770  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x0e  byte 0x38  0x004d7ae0  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x0f  byte 0x3c  0x004d8000  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x10  byte 0x40  0x004d87b0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x11  byte 0x44  0x004d87e0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x12  byte 0x48  0x004d8920  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x13  byte 0x4c  0x004d7b20  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x14  byte 0x50  0x004d7c00  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x15  byte 0x54  0x004d7c90  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x16  byte 0x58  0x004d7d50  new       ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x17  byte 0x5c  0x004d7d20  new       IsDiplomacyTargetClassCode200Match
//   slot 0x18  byte 0x60  0x004d7d70  new       RemoveRegionIdFromNationOwnedRegionList
//   slot 0x19  byte 0x64  0x004d7da0  new       AddRegionIdToNationOwnedRegionList
//   slot 0x1a  byte 0x68  0x004d7dd0  new       SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x1b  byte 0x6c  0x004d7e90  new       OrphanRetStub_004d7e90
//   slot 0x1c  byte 0x70  0x004d7ee0  new       OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x1d  byte 0x74  0x004d7f00  new       OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x1e  byte 0x78  0x004d7f20  new       OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x1f  byte 0x7c  0x004d7f40  new       OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x20  byte 0x80  0x004d7fa0  new       OrphanRetStub_004d7fa0
//   slot 0x21  byte 0x84  0x004d7fc0  new       OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x22  byte 0x88  0x004d7b00  new       ReturnFalseNationStateActionStub
//   slot 0x23  byte 0x8c  0x004d7fe0  new       OrphanRetStub_004d7fe0
//   slot 0x24  byte 0x90  0x004d7f60  new       ReturnFalseNationStateCapabilityFlag90
//   slot 0x25  byte 0x94  0x004d7f80  new       OrphanRetStub_004d7f80
//   slot 0x26  byte 0x98  0x004d6730  new       ReturnFalseNationStateCapabilityFlag98
//   slot 0x27  byte 0x9c  0x004d6750  new       ReturnFalseNationStateCapabilityFlag9C
//   slot 0x28  byte 0xa0  0x004d6770  new       ReturnFalseNationStateCapabilityFlagA0
//   slot 0x29  byte 0xa4  0x004d6790  new       NoOpNationSelectedRegionAndMapCellLabelHook
// object size 0x94 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TCountry) ===
