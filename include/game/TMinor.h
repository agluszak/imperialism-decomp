#pragma once

#include "game/TCountry.h"

// Minor-power nation row (g_apTerrainTypeDescriptorTable[7..], g_apSecondaryNationStateSlots).
// Inherits the TCountry prefix (0x94) and extends with minor-only tail state to 0x2dc.
// VTABLE: IMPERIALISM 0x00653c90
struct TMinorRuntimeStatusEntry {
  short fields[7];
};

ASSERT_SIZE(TMinorRuntimeStatusEntry, 0x0e);

class TMinor : public TCountry {
public:
  TMinor();

  static void* GetTMinorClassNamePointer();

  DECLARE_DYNCREATE(TMinor)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;

  void SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) override;
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
  char ReturnFalseNationStateCapabilityFlag90(short arg) override;
  void NotifyActionSlot94(int sourceNation, int actionCode) override;

  // slot 0x2a (+0xa8), TMinor's first new virtual — vtable 0x653c90+0xa8 -> 0x4e46a0,
  // dispatched virtually by HandleTurnResumeStateTelemetry (0x5434 0e region).
  virtual void RebuildDiplomacyEconomicPressureFromMapState(void);
  void SeedRandomDiplomacyPolicyThresholds(void);
  char CanInitiateJoinEmpireProposalToTarget(short targetNationSlot, short proposalCode);
  void HandleNetworkPortConstructionOrder(int nationId);
  void SetNationRowDisplayValueByDiplomacyPredicate(short targetNationSlot);
  void ClearTileActivityOverlayByProvinceId(int provinceId);
  void QueueInterNationEvent17ForState300AffectedNations(void);
  void ApplyDiplomacyRelationMaskToProvinceLinkedObjects(short provinceId);
  short GetDiplomacyRandomThreshold124() const {
    return diplomacyRandomThreshold124;
  }

  void ReassignUnitOrdersForCountryTargetChange(short provinceId, char includeAllPolicyTargets);
  void ReassignTileObjectOwnerAndNotifyForSelectedCells(int priorOwnerNationSlot);
  void RelinkTileUnitsToCountryOrderManager(int destinationNationSlot);

  void SetDiplomacyStandingSlot48(int targetNation, int standing);
  char HasMinorStandingLinkSlot5C(int sourceNation);
  void ApplyTerrainDiplomacyRelationFlagSlot8c(int sourceNation, int packedRelationCode);
  char HasStandingPropagationBridgeSlot90(int targetNation);
  void NotifyNationAuxRuntimeFinalizeSlotC0(void);
  void ClearNationAuxRuntimeGrantSlotC4(int grantValue);
  // Full (re)initialization of a minor nation's per-session state: nation identity +
  // owned-region list, diplomacy policy defaults, the five per-resource/per-nation
  // short tables and all 23 status rows cleared, need counters recounted from owned
  // map tiles, home tile selected (flagged tile, else a random valid candidate) with
  // its port zone ensured, and the per-slot diplomacy random thresholds and save
  // fields set from the 16-way nation-slot table. 0x4e3830, __thiscall, RET 4.
  void InitializeSecondaryNationStateAndSelectHomeTile(short nationSlot);

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
  // +0x198. 23 rows of seven shorts, cleared row-by-row (as one 0x0e-byte memset per
  // row) by the same 0x17-iteration loop that clears the five short tables above
  // (0x4e3830). Rows 0..6 form the relation/grant/link matrix indexed
  // [relationSlot][majorNationSlot]; the individual meanings of rows 7..22 are not
  // yet recovered.
  TMinorRuntimeStatusEntry statusRows[0x17];
  short runtimeStatusTail2da;

protected:
  // Inline so network minor subclasses reproduce the original direct CString teardown.
  // FUNCTION: IMPERIALISM 0x004e37c0
  ~TMinor() override {}
};

ASSERT_SIZE(TMinor, 0x2dc);
