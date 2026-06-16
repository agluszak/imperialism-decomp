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
  CString* GetIdentitySharedString1Slot58(void) override;
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

  void RebuildDiplomacyEconomicPressureFromMapState() override;
  void SeedRandomDiplomacyPolicyThresholds() override;
  char CanInitiateJoinEmpireProposalToTarget(short targetNationSlot, short proposalCode) override;
  void HandleNetworkPortConstructionOrder(int nationId) override;
  void SetNationRowDisplayValueByDiplomacyPredicate(short targetNationSlot,
                                                      short predicateCode) override;
  void ClearTileActivityOverlayByProvinceId(int provinceId) override;
  void QueueInterNationEvent17ForState300AffectedNations() override;
  void ApplyDiplomacyRelationMaskToProvinceLinkedObjects(short provinceId) override;

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
  ~TMinor() {}
};

ASSERT_SIZE(TMinor, 0x2cc);
