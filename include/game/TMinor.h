#pragma once

#include "game/TCountry.h"

// Minor-power nation row (g_apTerrainTypeDescriptorTable[7..], g_apSecondaryNationStateSlots).
// Inherits the TCountry prefix (0x94) and extends with minor-only tail state to 0x2cc.
// VTABLE: IMPERIALISM 0x00653c90
class TMinor : public TCountry {
public:
  TMinor();

  static void* CreateTMinorInstance();
  static void* GetTMinorClassNamePointer();

  CRuntimeClass* GetRuntimeClass() const override;

  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;

  void ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) override;
  void SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) override;
  void ApplyJoinEmpireMode1TargetTransition(int targetNationSlot) override;
  void ApplyJoinEmpireMode2FinalizeNationNameState(void) override;
  void RemoveRegionIdFromNationOwnedRegionList(int regionId) override;
  void AddRegionIdToNationOwnedRegionList(int regionId) override;
  int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) override;
  short GetDiplomacyExternalStateB6ByTarget(short nationSlot) override;
  short QueryNationMetricBySlot7C(short metricSlot) override;
  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  bool IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) override;
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                     int arg4) override;
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) override;
  char ReturnFalseNationStateCapabilityFlag90(int arg) override;
  void NotifyActionSlot94(int sourceNation, int actionCode) override;

  void RebuildDiplomacyEconomicPressureFromMapState(void);
  void SeedRandomDiplomacyPolicyThresholds(void);
  char CanInitiateJoinEmpireProposalToTarget(short targetNationSlot, short proposalCode);
  void HandleNetworkPortConstructionOrder(int nationId);
  void SetNationRowDisplayValueByDiplomacyPredicate(short targetNationSlot,
                                                            short predicateCode);
  void ClearTileActivityOverlayByProvinceId(int provinceId);
  void QueueInterNationEvent17ForState300AffectedNations(void);
  void ApplyDiplomacyRelationMaskToProvinceLinkedObjects(short provinceId);

  void ReassignUnitOrdersForCountryTargetChange(short provinceId, char includeAllPolicyTargets);
  void ReassignTileObjectOwnerAndNotifyForSelectedCells(int priorOwnerNationSlot);
  void RelinkTileUnitsToCountryOrderManager(int destinationNationSlot);

  void SetDiplomacyStandingSlot48(int targetNation, int standing);
  char HasMinorStandingLinkSlot5C(int sourceNation);
  void ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation, int packedRelationCode);
  char HasStandingPropagationBridgeSlot90(int targetNation);
  void NotifyNationAuxRuntimeFinalizeSlotC0(void);
  void ClearNationAuxRuntimeGrantSlotC4(int grantValue);

private:
  short needCurrentByType[0x17];
  short diplomacyPolicyByNation[0x17];
  short diplomacyGrantByNation[0x17];
  short diplomacyRandomThreshold11e;
  short diplomacyRandomThreshold120;
  short diplomacyRandomThreshold122;
  short diplomacyRandomThreshold124;
  short diplomacyRandomThreshold126;
  short diplomacyRandomThreshold128;
  short diplomacyRandomThreshold12a;
  short diplomacyPolicyPredicateCode12c;
  short diplomacyPolicyPredicateCode12e;
  short diplomacyPolicyGate130;
  short diplomacyPolicyGate132;
  unsigned char minorTailPad134[0x16a - 0x134];
  short recurringGrantByResource[0x17];
  short relationGrantLinkMatrix[7][7];
  unsigned char minorTailPad1fa[0x2cc - 0x1fa];

protected:
  ~TMinor();
};

ASSERT_SIZE(TMinor, 0x2cc);

// === BEGIN GENERATED (TMinor) — refreshed by `just gen-class TMinor`; do not hand-edit ===
// clang-format off
// vtable @ 0x00653c90 (53 slots), object size 0x2dc, base TCountry
//   slot 0x00  byte 0x00  0x004e36f0  override  GetTCountryClassNamePointer
//   slot 0x01  byte 0x04  0x004e3790  override  ApplyJoinEmpireModeForTargetNation
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004e4390  override  SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x06  byte 0x18  0x004e41c0  override  DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x07  byte 0x1c  0x004d6ba0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004d70e0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x0b  byte 0x2c  0x004d7070  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x0c  byte 0x30  0x004d71b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0d  byte 0x34  0x004d7770  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x0e  byte 0x38  0x004d7ae0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x0f  byte 0x3c  0x004d8000  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x10  byte 0x40  0x004d87b0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x11  byte 0x44  0x004d87e0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x12  byte 0x48  0x004e4fa0  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x13  byte 0x4c  0x004d7b20  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x14  byte 0x50  0x004e5340  override  SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x15  byte 0x54  0x004e5840  override  ApplyJoinEmpireMode1TargetTransition
//   slot 0x16  byte 0x58  0x004e59d0  override  ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x17  byte 0x5c  0x004d7d20  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x18  byte 0x60  0x004e64a0  override  RemoveRegionIdFromNationOwnedRegionList
//   slot 0x19  byte 0x64  0x004e64f0  override  AddRegionIdToNationOwnedRegionList
//   slot 0x1a  byte 0x68  0x004d7dd0  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x1b  byte 0x6c  0x004d7e90  inherited OrphanRetStub_004d7e90
//   slot 0x1c  byte 0x70  0x004e4630  override  OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x1d  byte 0x74  0x004d7f00  inherited OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x1e  byte 0x78  0x004e4660  override  OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x1f  byte 0x7c  0x004e4680  override  OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x20  byte 0x80  0x004e49b0  override  OrphanRetStub_004d7fa0
//   slot 0x21  byte 0x84  0x004e4ee0  override  OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x22  byte 0x88  0x004e4f50  override  ReturnFalseNationStateActionStub
//   slot 0x23  byte 0x8c  0x004e50d0  override  OrphanRetStub_004d7fe0
//   slot 0x24  byte 0x90  0x004e45f0  override  ReturnFalseNationStateCapabilityFlag90
//   slot 0x25  byte 0x94  0x004e5300  override  OrphanRetStub_004d7f80
//   slot 0x26  byte 0x98  0x004d6730  inherited ReturnFalseNationStateCapabilityFlag98
//   slot 0x27  byte 0x9c  0x004d6750  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x28  byte 0xa0  0x004d6770  inherited ReturnFalseNationStateCapabilityFlagA0
//   slot 0x29  byte 0xa4  0x004d6790  inherited NoOpNationSelectedRegionAndMapCellLabelHook
//   slot 0x2a  byte 0xa8  0x004e46a0  new       RebuildDiplomacyEconomicPressureFromMapState
//   slot 0x2b  byte 0xac  0x004e4bd0  new       Helper_Uses_GenerateThreadLocalRandom15_At004e4bd0
//   slot 0x2c  byte 0xb0  0x004e4ff0  new       CanInitiateJoinEmpireProposalToTarget
//   slot 0x2d  byte 0xb4  0x004e5730  new       HandleNetworkPortConstructionOrder
//   slot 0x2e  byte 0xb8  0x004e5a40  new       SetNationRowDisplayValueByDiplomacyPredicate
//   slot 0x2f  byte 0xbc  0x004e5ac0  new       ClearTileActivityOverlayByProvinceId
//   slot 0x30  byte 0xc0  0x004e5be0  new       QueueInterNationEvent17ForState300AffectedNations
//   slot 0x31  byte 0xc4  0x004e5d90  new       ApplyDiplomacyRelationMaskToProvinceLinkedObjects
//   slot 0x32  byte 0xc8  0x004e6150  new       ReassignUnitOrdersForCountryTargetChange
//   slot 0x33  byte 0xcc  0x004e6040  new       ReassignTileObjectOwnerAndNotifyForSelectedCells
//   slot 0x34  byte 0xd0  0x004e6520  new       GetTCountryClassNamePointer
// object size 0x2dc (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TMinor) ===
