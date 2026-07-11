#pragma once

#include "game/TCountry.h"

// Minor-power nation row (g_apTerrainTypeDescriptorTable[7..], g_apSecondaryNationStateSlots).
// Inherits the TCountry prefix (0x94) and extends with minor-only tail state to 0x2cc.
// VTABLE: IMPERIALISM 0x00653c90
class TMinor : public TCountry {
public:
  TMinor();

  // Decode the owning great-power slot from encodedNationSlot: >= 200 -> tag - 200,
  // 100..199 -> tag - 100, else this nation's own slot. Header-inline: the original
  // bodies open-code this decode at each site.
  short DecodeOwnerNationSlot() const {
    short ownerNationSlot = encodedNationSlot;
    if (ownerNationSlot < 200) {
      if (ownerNationSlot < 100) {
        ownerNationSlot = nationSlot;
      } else {
        ownerNationSlot = static_cast<short>(ownerNationSlot - 100);
      }
    } else {
      ownerNationSlot = static_cast<short>(ownerNationSlot - 200);
    }
    return ownerNationSlot;
  }

  static void* GetTMinorClassNamePointer();

  DECLARE_DYNCREATE(TMinor)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;

  void ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) override;
  void SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) override;
  void ApplyJoinEmpireMode1TargetTransition(int targetNationSlot) override;
  void ApplyJoinEmpireMode2FinalizeNationNameState(void) override;
  void RemoveRegionIdFromNationOwnedRegionList(int regionId) override;
  void AddRegionIdToNationOwnedRegionList(int regionId) override;
  int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) override;
  short GetDiplomacyExternalStateByTarget(short nationSlot) override;
  short QueryNationMetricBySlot7C(short metricSlot) override;
  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  bool IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) override;
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                     int arg4) override;
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) override;
  char ReturnFalseNationStateCapabilityFlag90(int arg) override;
  void NotifyActionSlot94(int sourceNation, int actionCode) override;

  // slot 0x2a (+0xa8), TMinor's first new virtual — vtable 0x653c90+0xa8 -> 0x4e46a0,
  // dispatched virtually by HandleTurnResumeStateTelemetry (0x5434 0e region).
  virtual void RebuildDiplomacyEconomicPressureFromMapState(void);
  void SeedRandomDiplomacyPolicyThresholds(void);
  char CanInitiateJoinEmpireProposalToTarget(short targetNationSlot, short proposalCode);
  void HandleNetworkPortConstructionOrder(int nationId);
  void SetNationRowDisplayValueByDiplomacyPredicate(short targetNationSlot, short predicateCode);
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
  void InitializeTMinorDefaults(int slotIndex);

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
  // Serialized as a unit by ReadFrom/WriteTo (byte-order swapped via
  // SwapAdjacentBytesInShortArray on load); diplomacySaveExt13c is only present when
  // g_nSaveFormatVersion > 0x39 (a later save-format addition). Same 0x17-short size as
  // the sibling diplomacyGrantByNation/recurringGrantByResource tables, but the indexed
  // dimension (nation vs. resource) is not yet confirmed.
  short diplomacySaveFields134[4]; // 0x134
public:
  short diplomacySaveExt13c[0x17]; // 0x13c
private:
  short recurringGrantByResource[0x17];
  short relationGrantLinkMatrix[7][7];
  unsigned char minorTailPad1fa[0x2cc - 0x1fa];

protected:
  ~TMinor() override;
};

ASSERT_SIZE(TMinor, 0x2cc);
