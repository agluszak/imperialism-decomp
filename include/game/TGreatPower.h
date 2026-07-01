#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/nation_domain_types.h"
#include "game/TCountry.h"
#include "game/TSortedList.h"

struct CRuntimeClass;
class TStream;

class TMinister;
class TForeignMinister;
class TDefenseMinister;
class TCityInteriorMinister;
class TQueueObject;
class TCity;
class TZone;

// Nation object: inherits the intermediate base TCountry (identity strings, nation-slot
// metrics, military-unit + owned-region lists), itself a TObject.
// VTABLE: IMPERIALISM 0x00653938
class TGreatPower : public TCountry {
public:
  // ---- identity / serialization ----
  // slot 0x00 — body 0x004d89d0: returns TGreatPower CRuntimeClass descriptor.
  DECLARE_DYNCREATE(TGreatPower)
  // 0x004d8c50 tears down the two identity CStrings.
  ~TGreatPower() override;
  // slots 0x05–0x07 — TObject stream lifecycle (Mac: WriteTo / ReadFrom / Free).
  void WriteTo(TStream* stream) override;  // body 0x004d9c70
  void ReadFrom(TStream* stream) override; // body 0x004d92e0
  // Releases every owned member object then `delete this`. TAutoGreatPower overrides
  // (0x004e7230) to drain missionQueue first.
  void Free() override; // body 0x004d9160
  // slot 0x0a — body 0x004da500: writes core scalars (0x0e/0x10/0x88/0x8c) then the
  // tracked-order list and each tracked order to the stream.
  void WriteCoreFieldsToStream(TStream* stream) override;
  void ReadCoreFieldsFromStream(TStream* stream, int unusedArg) override;

  // ---- diplomacy grants / policies / proposal queue ----
  void ResetDiplomacyLevelForNationSlot12(NationSlot nationSlot, int resetLevel) override;
  // index 0x13 / vtable+0x04c. Evidence: 0x004df010 calls this on `this`
  // with (targetNationSlot, 1); return value ignored.
  void ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode) override;
  void
  SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) override; // slot 0x14
  // slot 0x18 — body 0x004e2270: drop regionId from ownedRegionList then fire the
  // slot 0x298 hook. TAutoGreatPower overrides it (0x004ea1c0) to also drop the
  // matching mission from missionQueue and clear mapNodeStateFlags.
  void RemoveRegionIdFromNationOwnedRegionList(int regionId) override;
  void AddRegionIdToNationOwnedRegionList(int regionId) override;
  void SetNationPercentFieldByModeAndDescriptorLinks(int targetNationSlot, int policyCode) override;
  void DecrementDiplomacyCounterA2ByValue(int delta) override;
  int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) override; // slot 0x1c
  short GetDiplomacyCounterA2(void) override;                                  // slot 0x1d
  short GetDiplomacyExternalStateByTarget(short nationSlot) override;          // slot 0x1e
  short QueryNationMetricBySlot7C(short metricSlot) override;                  // slot 0x1f
  // index 0x20 / vtable+0x080. Evidence: base TGreatPower vtable entry
  // 0x00407392 thunks to body 0x004ddc30; TAutoGreatPower overrides this slot.
  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  bool
  IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot) override; // slot 0x21
  // slot 0x22 — TAutoGreatPower override 0x004e79d0 either forwards to the foreign
  // minister (slot 0x98) or appends a kind-1 tracked-slot entry; returns 0.
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                     int arg4) override;
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId) override;
  void NotifyActionSlot94(int sourceNation, int actionCode) override; // slot 0x94
  virtual void NoOpNationPendingActionHook(void);

  // ---- tracked orders / pending action state ----
  // slot 0x2b — body 0x004da860: marks status flag 5 handled when the city-order
  // capability byte (+0x277 row) is active.
  virtual void MarkStatusFlag5HandledIfCapabilityActive(void);
  // slot 0x2c — body 0x004da8a0: sweeps serializedStatusFlags, advancing every
  // pending ('2') flag to its handled state.
  virtual void MarkAllPendingStatusFlagsHandled(void);
  // slot 0x2d — body 0x004da5e0: dispatches one UI turn-status prompt per pending
  // flag via g_pUiRuntimeContext slot 0x3c.
  virtual void DispatchPendingStatusPrompts(void);
  virtual void SetNationPendingActionStateAndPayload(int index, short payload); // slot 0x2e
  // slot 0x2f — body 0x004daa50: appends a node to missionNodeQueue.
  virtual void AddNodeToMissionNodeQueue(void* node);
  // slot 0x30 — body 0x004daa80: invokes [vt+0x28] on every mission node, then
  // clears missionNodeQueue.
  virtual void DispatchMissionNodeCallbacksAndClearQueue(void);
  virtual void NoOpNationQueuedOrderHook(void);
  // index 0x32 / vtable+0x0c8. Per-nation pending-action state machine that
  // constructs queued land/navy/civ order objects (body 0x004dab20).
  virtual void ExecuteNationPendingActionStateMachine(void);
  void RefreshNationCivilianWorkOrdersForTurn(CString param_2, char* param_3);
  // slot 0x33 — body 0x004dae70: scans trackedObjectList for an order with
  // orderType == 7.
  virtual char HasTrackedOrderOfType7(void);
  // slot 0x34 — body 0x004db7d0: builds the 0x1950-byte transport-influence region map
  // (flood-filled from the home region via slot 0x35, extended through transport-linked
  // town markers), updates each marker's transportLinkedFlag4c, and hands the map to the
  // caller through outInfluenceMap (or frees it when outInfluenceMap is null).
  virtual void BuildTransportLinkedInfluenceMap(char** outInfluenceMap);
  // slot 0x35 — body 0x004dbac0: marks regionMap[id]=1 for every region connected to
  // regionId through same-owner neighbors (self-recursive through this slot, with the
  // first eligible neighbor tail-iterated).
  virtual void MarkConnectedOwnedRegionsFrom(unsigned char* regionMap, short regionId);

  // ---- turn-event message dispatch ----
  virtual void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
  virtual void NotifyCitySlot2C(void);
  virtual void OrphanRetStub_004dcc30(void);
  // slot 0x39 — body 0x004df810: loads the scenario-level preset row (table 0x653570)
  // into the city stock relation deltas, maxes six production-order entries to
  // 999, notifies the manager's 0x1d8 sink, then spawns the Frog City marker through
  // slot 0x3a or 0x3b.
  virtual void ApplyScenarioRelationPresetAndSpawnFrogCity(class TCity* mgr);
  // slot 0x3a — body 0x004dfa20: creates the "Frog City" town marker, hands it to
  // the receiver's slot 0x44 and appends it to townMarkerList.
  virtual void CreateFrogCityTownMarkerAndAttach(void* receiver);
  // slot 0x3b — body 0x004dfae0: resolves the nation's home region (minister slot 0xc0,
  // or a terrain-table scan when flag 0x114 is set, reporting "GP#<n> is missing capitol
  // site" on failure), stores it at +0x88, creates the "FrogCity" marker, attaches it to
  // the receiver and the global map, and notifies the interior minister.
  virtual void CreateFrogCityAtHomeRegionAndAttach(void* receiver);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel2(void);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel1(void);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel0(void);
  // slot 0xfc — placeholder in the original table; city callers use the direct helper
  // below (`AbsorbCityNeedVectorSlotFC`), not virtual dispatch.
  virtual void OrphanRetStub_004dca80(void);
  // slot 0x40 — body 0x004dcaa0: effective diplomacyCounterA2 for a proposal code,
  // reduced by 2 when the interaction manager maps the code into an active minister
  // capability category (4/5/3), or by 1 for the code-3 special case.
  virtual unsigned int GetEffectiveDiplomacyCounterA2ForCode(int proposalCode);
  virtual void ApplyDiplomacyState222ToCityStockAndClear(void);      // slot 0x41
  virtual void ApplyRelationDeltaToCityStockAndUpdateState1f4(void); // slot 0x42

  // ---- resource needs / aid allocation ----
  virtual void ApplyNationResourceNeedTargetsToOrderState(void);
  virtual void SetNationResourceNeedCurrentByType(int needType, int currentValue);
  virtual void UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value); // slot 0x45
  virtual bool IsNeedTargetEqualCurrent(short needIndex);                          // slot 0x46
  virtual short GetNeedTargetByType(short needIndex);                              // slot 0x47
  virtual void TryIncrementNationResourceNeedTargetTowardCurrent(int needType);
  virtual void IsNationResourceNeedCurrentSumExceedingCapA6(void);
  virtual short TryDecayRelationNeedScores9AndB(void); // slot 0x4a
  virtual short TryDecayRelationNeedScores9And8(void); // slot 0x4b
  // slot 0x4c — body 0x004e0220: invokes [vt+0x2c] on every tracked order.
  virtual void DispatchTrackedOrderSlot2CCallbacks(void); // slot 0x4c
  virtual void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
  virtual void AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents(void);
  virtual char AnyNeedCurrentExceedsTargetWhenCapMismatch(void); // slot 0x4f
  // slot 0x50 — body 0x004dc440: true when any city commodity record 8..0xc has its
  // control value below the record's step value (gated on scenario cap >= 2).
  virtual char HasAnyCommodityRecordBelowStepValue(void);
  // slot 0x51 — body 0x004dc4c0: status prompt code 0x25 (counter 0 at tick 3) or
  // 0x27 (counter ahead of tick by >4 with treasury >= 10000), else 0.
  virtual short ComputeTreasuryStatusPromptCode(void);
  // slot 0x52 — 0x004e1c20 dispatches it on the target nation with mode 0/1.
  virtual char CompareMissionScoreVariantsByMode(int mode);
  virtual void BuildGreatPowerMapContextTriggeredNationEventMessages(void);
  virtual void BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void);
  // slot 0x55 — body 0x004e0290: selection-sorts trackedObjectList ascending by the
  // per-order-type priority table at 0x6966d0.
  virtual void SortTrackedOrdersByTypePriority(void);
  // slot 0x56 — body 0x004e03a0: runs slot 0x4c then the slot 0x55 sort.
  virtual void RunSlot4CThenSortTrackedOrders(void);
  // slot 0x57 — body 0x004e03d0: field900 = needCapA6 / 5.
  virtual void ResetField900FromNeedCapA6(void);
  virtual void SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(int targetNationSlot,
                                                                            int isBoycottEnabled);
  virtual void RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void);
  virtual void ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  virtual void RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  virtual void ReleaseDiplomacyTrackedObjectSlots850(void); // slot 0x5c
  virtual void AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex,
                                                          short rowIndex);
  virtual int SumAidAllocationMatrixColumnForTarget(short targetNationId);
  virtual int SumAidAllocationMatrixAllCells(void); // slot 0x5f
  virtual int ComputeRemainingDiplomacyAidBudget(void);
  virtual void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void);
  virtual void AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void);
  virtual void SetCityStockCounterAndRefresh(short targetSlot, short value);   // slot 0x63
  virtual void AddToCityStockCounterAndRefresh(short targetSlot, short value); // slot 0x64
  // slot 0x65 — body 0x004dd7f0: per-order-kind production metric (city building
  // production doubled per kind; kind 7 sums the city summary record minus four
  // city stock counters, clamped at 0).
  virtual unsigned int ComputeProductionMetricForOrderKind(short orderKind);
  virtual void DecrementDiplomacyCounterA2Slot66(int delta);                          // slot 0x66
  virtual void AssignNeedSlotFromSourceSlot19C(short needSlot, short sourceNation);   // slot 0x19c
  virtual char AreDiplomacyState1c6Slots13To16AllNonPositive(void);                   // slot 0x68
  virtual void SetDiplomacyState1c6ClampedToCounterA4(short targetSlot, short value); // slot 0x69
  virtual void SnapshotDiplomacyState1c6Into250(void);                                // slot 0x6a
  // slot 0x6b / 0x1ac — body 0x004ddd20: clears diplomacyState1c6[targetSlot].
  virtual void ClearDiplomacyState1c6ForTarget(short targetSlot);
  // slot 0x6c — body 0x004ddd90: packs {kind, targetNation, value, eligibility,
  // payload} and appends it to diplomacyTrackedSlots[slotIndex] via [vt+0x38];
  // eligibility = kind==1, or kind==0 and manager slot 0x84 reports no flag.
  virtual void AppendTrackedSlotEntry(short kind, int targetNation, short value, short slotIndex,
                                      int payload);
  virtual short GetTrackedSlotEntryCountLow(short targetSlot);     // slot 0x6d
  virtual char AnyTrackedSlotEntryHasZeroField4(short targetSlot); // slot 0x6e
  // slot 0x6f — body 0x004ddeb0: unpacks tracked-slot entry fields (+0/+2/+4/+8).
  virtual void ReadTrackedSlotEntryFields(short slotIndex, short ordinal, short* outKind,
                                          short* outValue, short* outTargetNation, int* outPayload);
  virtual void AssignPayloadToTrackedSlotEntryMatchingField2(int targetSlot, int matchKey,
                                                             int payload);           // slot 0x70
  virtual void ClearDiplomacyState1c6Block(void);                                    // index 113
  virtual void BeginTurnDiplomacyPrePassSlot1c8();                                   // index 114
  virtual void ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void);     // index 115
  virtual bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2); // index 116
  virtual bool SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2); // index 117
  virtual void
  RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(int sourceNation); // index 118
  virtual bool
  CanAffordDiplomacyGrantEntryForTarget(short targetNationId,
                                        unsigned short proposedGrantEntry); // index 119
  virtual void ApplyTurnDiplomacyStateSlot1e0();                 // index 120 — body 0x004de7e0
  virtual void DecrementNeedLevelByNationStep(short nationSlot); // index 121
  virtual bool CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost); // index 122
  virtual void ApplyAcceptedDiplomacyProposalCode(short proposalIndex);                // index 123
  virtual void
  QueueInterNationEventForProposalCode12D_130(unsigned short proposalQueueIndex); // index 124
  // slot 0x7d — body 0x004df4b0: whether eventCode may target the nation given the
  // current relation tier (tiers 2..6 progressively restrict 0x12e-0x130).
  virtual char IsEventCodeAllowedForRelationTier(short eventCode, int targetNation);
  virtual void ResetNationDiplomacyProposalQueue(void);
  virtual void ReleaseProposalQueueSlot7F(void);
  virtual void DispatchTurnEvent2103WithNationFromRecord(void);
  virtual void ProcessPendingDiplomacyProposalQueue(void);
  // slot 0x82 — body 0x004e2880: ranks this nation's summed building production against
  // the mean/stddev across all eligible nations; returns tier 0..4.
  virtual int ClassifyNationProductionTierVsPeers(void);

  // ---- map-action mission scoring ----
  // slot 0x20c — base no-op; TAutoGreatPower override 0x004e9f10 prunes
  // candidateNationFlags and reports whether any candidate remains active.
  virtual char HasActiveCandidateNationSlots(void);
  // index 132 / vtable+0x210. Evidence: 0x004e9ed0 calls this on `this`
  // with one target-nation argument; return value ignored.
  virtual void SetCandidateNationFlagAndPortZoneState(int targetNation); // body 0x004e0420
  virtual void NotifyAllianceSlot214(int targetNation); // index 133 — body 0x004e0440
  // slot 0x86 — body 0x004e0500; navy order priority weights summed for this nation.
  virtual int SumNavyOrderPriorityForNationSlot86(void);
  virtual int CountMapActionContextNodesWithNationBit(void);       // slot 0x87
  virtual double ComputeMinisterSkillFloatSlot88(void);            // slot 0x88
  virtual double ComputeMinisterSkillFloatSlot89(void);            // slot 0x89
  virtual double ComputeMinisterSkillFloatSlot8A(void);            // slot 0x8a
  virtual double ComputeMinisterSkillFloatSlot8B(void);            // slot 0x8b
  virtual double ComputeMinisterSkillFloatSlot8C(void);            // slot 0x8c
  virtual int GetCityBuildingProductionSlot8D(short buildingSlot); // slot 0x8d

  // ---- relative military/naval power scoring ----
  // Relative military/naval power score family (bodies 0x004e07b0..0x004e1c20).
  // slot 0x8e — min(production-capped army commit budget, metric 0x10, armyPower/2).
  virtual int ComputeArmyCommitBudgetSlot8E(void);
  // slot 0x8f — army strength score: armyPower + commit budget + min(prod(3), power/4).
  virtual float GetScoreFactorSlot23C(void);
  // slot 0x90 — navy strength score from ship production, navy order priority and fleet power.
  virtual float GetScoreFactorSlot240(void);
  virtual float ComputeArmyScoreRatioVsNation(int targetNation);         // slot 0x91
  virtual float ComputeArmyScoreStandingRatioVsNation(int targetNation); // slot 0x92
  virtual float ComputeNavyScoreRatioVsNation(int targetNation);         // slot 0x93
  virtual float ComputeNavyScoreStandingRatioVsNation(int targetNation); // slot 0x94
  virtual float ComputeArmyScoreRatioVsNationWithSecondary(int targetNation,
                                                           int secondarySlot); // slot 0x95
  virtual float ComputeArmyScoreStandingRatioVsNationPair(int targetNation,
                                                          int partnerNation); // slot 0x96
  virtual float ComputeNavyScoreRatioVsNationWithSecondary(int targetNation,
                                                           int secondarySlot); // slot 0x97
  virtual float ComputeNavyScoreStandingRatioVsNationPair(int targetNation,
                                                          int partnerNation); // slot 0x98
  virtual float ComputeArmyScoreRatioForNationPair(int nationA, int nationB,
                                                   char swapRoles); // slot 0x99
  virtual float ComputeArmyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                           char swapRoles); // slot 0x9a
  virtual float ComputeNavyScoreRatioForNationPair(int nationA, int nationB,
                                                   char swapRoles); // slot 0x9b
  virtual float ComputeNavyScoreStandingRatioForNationPair(int nationA, int nationB,
                                                           char swapRoles); // slot 0x9c
  virtual char ReturnZeroSlot9D(int targetNation);                          // body 0x004e1c00
  // slot 0x9e — joins a war against targetNation when minister skill beats the war
  // threshold; propagates relation code 4 to tier-2 partners and queues event 0x1c.
  virtual char EvaluateJoinWarAgainstNationAndQueueEvent(int targetNation);
  virtual int CheckTransitionSlot27C(int targetNation, int sourceNation); // slot 0x27c
  virtual int PropagateWarTransitionSlot280(int targetNation, int sourceNation,
                                            int mode); // slot 0x280
  // index 0xa1 / vtable+0x284 — body 0x004e27f0 (vtable holds ILT thunk 0x00406fe1).
  // Queues a nation-pair war transition and notifies the third-party minor nation
  // when the policy code is 1 or 0x132.
  virtual void ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot,
                                                                    int policyCode,
                                                                    int sourceNationSlot);
  virtual void NoOpSlotA2(void); // body 0x004e1f20
  // slot 0xa3 — body 0x004e1f40 (not yet ported); war-commitment threshold consumed by
  // slot 0x9e (compared against ComputeMinisterSkillFloatSlot8C).
  virtual float ComputeWarThresholdSlotA3(int targetNation);
  virtual void PruneInvalidTrackedEntriesAndNotifyOwner(); // slot 0xa4 — body 0x004e2190
  virtual void NotifyWarResetSlotA5(void);
  // slot 0x298 — fired by RemoveRegionIdAndRunTrackedObjectCleanup (0x004e2270).
  virtual void NotifyRegionEventSlot298(int regionId);
  // slot 0x29c — body 0x004e25c0: reset diplomacy level/grants for targetNation and
  // fire slot 0x2a0 for every nation with an active policy link.
  virtual void ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation);
  virtual void CallSlotA8(int targetNation);
  virtual void CallSlotA9(int targetNation);
  // slot 0x2a8 — body 0x004e27b0: mode-dispatched diplomacy slot action (mode 6 ->
  // slot 0xa8, etc.). TDiplomacyMgr notifies relation-code changes here.
  virtual void DispatchNationDiplomacySlotActionByMode(int targetNationSlot, int mode);
  // slot 0x2ac — base body is the 0x0040389b thunk: dispatch turn event 0x11f8 with no
  // payload. TAutoGreatPower overrides it (0x004e7510) with the 'lost' game-state event.
  virtual void DispatchTurnEvent11F8NoPayloadSlot2AC(void);
  // slot 0xac — body 0x004e06d0: sums the accumulated value (+0x44) of city
  // commodity records 8..0xc.
  virtual int SumCommodityRecordAccumulatedValues(void);
  virtual void NoOpTailStateHookSlot2B4(void);
  virtual void NoOpTailStateHookSlot2B8(int arg);
  virtual void UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
  virtual void DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags);
  virtual void BuildGreatPowerTurnMessageSummaryAndDispatch(void);

  void LoadNationDisplayNameSharedRefFromField8(CString* destString);

  // 0x04..0x90 (identity strings, nation-slot metrics, militaryUnitList44,
  // unitNameOrdinalByType, ownedRegionList) now live on the TCountry base.
  TForeignMinister* foreignMinister;
  TCityInteriorMinister* interiorMinister;
  TDefenseMinister* defenseMinister;
  unsigned char diplomacyEligibilityA0;
  unsigned char pad_a1;
  short diplomacyCounterA2;
  short tradeCapacity;
  short needCapA6;
  short needsOverCapFlag;
  unsigned char pad_aa[2];
  int grantTotalCost;
  short diplomacyCounterB0;
  short diplomacyPolicyByNation[0x17];
  short diplomacyGrantByNation[0x17];
  short needCurrentByType[0x17];
  short needTargetByType[0x17];
  short relationDeltaCurrent[0x17];
  short relationDeltaSnapshot[0x17];
  short diplomacyState1c6[0x17];
  short diplomacyState1f4[0x17];
  short diplomacyState222[0x17];
  short diplomacyState250[0x17];
  int aidAllocationMatrix[0x170];
  int budgetPoolBase;
  int budgetPoolDelta;
  TQueueObject* turnEventQueue;
  TQueueObject* proposalQueue;
  TQueueObject* diplomacyTrackedSlots[0x11];
  // 0x894 — city production state; same object used as TCity in diplomacy paths.
  TCity* city;
  TSortedList* townMarkerList;
  TSortedList* trackedObjectList;
  unsigned char candidateNationFlags[0x17];
  unsigned char scenarioInitFlag;
  unsigned char pad_8b8[0x8c8 - 0x8b8];
  // 0x8c8 — pending-action status flag block. The serialization block is 0x0D bytes
  // (0x8c8..0x8d4) and slot 0x2c/0x2d sweep indices 0..0xc, so indices 8..0xc
  // address the named bytes that follow (expansionAlertCounter..expansionEventGate).
  unsigned char serializedStatusFlags[8];
  signed char expansionAlertCounter;
  unsigned char field8d1;
  unsigned char field8d2;
  unsigned char field8d3;
  unsigned char expansionEventGate;
  unsigned char field8d5;
  short field8d6[0x0d];
  int diplomacyBudgetBase;
  signed char escalationCounter;
  unsigned char pad_8f5[3];
  int pendingCommitmentCost;
  signed char pressureCounter;
  unsigned char pad_8fd[3];
  int field900;
  unsigned char field904;
  unsigned char pad_905[3];
  TQueueObject* turnSummaryQueue;
  TSortedList* missionNodeQueue;
  int field910;
  int aidAllocationTotal;
  unsigned char colonyBoycottFlags[0x17];
  unsigned char pad_92f[0x960 - 0x92f];
  int pendingAidTotal;
  // Provisional tail promoted from mixed-method imports beyond the core 0x964 block.
  short actionMetricByQuarter[6];
  unsigned char mapNodeStateFlags[0x180];
  unsigned char portZoneStateFlags[0x70];
  TSortedList* missionQueue;
  float floatB64;
  float floatB68;

  // (All thunk_*_At0040xxxx member wrappers retired: those addresses are pure ILT
  // `jmp` stubs from incremental linking, not real functions. Callsites now call the
  // real methods/virtuals directly; reccmp auto-detects the orig-side thunks.)

  // Semantic C++ wrappers:
  // - constructor behavior maps to 0x004D8CC0 InitializeNationStateRuntimeSubsystems
  // - TObject::Free override at 0x004D9160 releases owned members then deletes self
  TGreatPower();
  TGreatPower(int arg1, int arg2);

  static void* CreateTGreatPowerInstance(void);
  void CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
  void QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, TZone* portZoneContext,
                                                      int arg4);
  void ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass);
  bool ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2);
  void AbsorbCityNeedVectorSlotFC(short* needVector);
  void RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1);
  int GetMultiplierSlot21C(void);
  float ComputeMapActionContextCompositeScoreForNation(int nodeType);
  unsigned int ComputeMapActionContextNodeValueAverage(void);
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                      int relationTargetNation,
                                                      int selectedNationSlot);
  char ContainsPointerArrayEntryMatchingByteKey(short nationSlotKey);
  void InitializeNationStateRuntimeSubsystems(int arg1, int arg2);
  void HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw);
  void QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                       short sourceNationSlot);

  TCity* GetCityState(void) {
    return city;
  }
};

// === BEGIN GENERATED (TGreatPower) — refreshed by `just gen-class TGreatPower`; do not hand-edit
// ===
// clang-format off
// vtable @ 0x00653938 (178 slots), object size 0x964, base TCountry
//   slot 0x00  byte 0x00  0x004d89d0  override  GetTCountryClassNamePointer
//   slot 0x01  byte 0x04  0x004d8c20  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004d9c70  override  HandleCityDialogHintClusterUpdate
//   slot 0x06  byte 0x18  0x004d92e0  override  DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x07  byte 0x1c  0x004d9160  override  ApplyJoinEmpireModeForTargetNation
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004da500  override  OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x0b  byte 0x2c  0x004da3e0  override  SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x0c  byte 0x30  0x004d71b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0d  byte 0x34  0x004d7770  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x0e  byte 0x38  0x004d7ae0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x0f  byte 0x3c  0x004d8000  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x10  byte 0x40  0x004d87b0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x11  byte 0x44  0x004d87e0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x12  byte 0x48  0x004dd040  override  OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x13  byte 0x4c  0x004e21b0  override  ApplyJoinEmpireModeForTargetNation
//   slot 0x14  byte 0x50  0x004de860  override  SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x15  byte 0x54  0x004d7c90  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x16  byte 0x58  0x004d7d50  inherited ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x17  byte 0x5c  0x004d7d20  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x18  byte 0x60  0x004e2270  override  RemoveRegionIdFromNationOwnedRegionList
//   slot 0x19  byte 0x64  0x004e22b0  override  AddRegionIdToNationOwnedRegionList
//   slot 0x1a  byte 0x68  0x004e2330  override  SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x1b  byte 0x6c  0x004dda20  override  OrphanRetStub_004d7e90
//   slot 0x1c  byte 0x70  0x004dda60  override  OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x1d  byte 0x74  0x004d8c00  override  OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x1e  byte 0x78  0x004dd740  override  GetDiplomacyExternalStateByTarget
//   slot 0x1f  byte 0x7c  0x004ddb20  override  OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x20  byte 0x80  0x004ddc30  override  OrphanRetStub_004d7fa0
//   slot 0x21  byte 0x84  0x004ddd50  override  OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x22  byte 0x88  0x004ddbb0  override  ReturnFalseNationStateActionStub
//   slot 0x23  byte 0x8c  0x004defd0  override  OrphanRetStub_004d7fe0
//   slot 0x24  byte 0x90  0x004d7f60  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x25  byte 0x94  0x004dedf0  override  OrphanRetStub_004d7f80
//   slot 0x26  byte 0x98  0x004d6730  inherited ReturnFalseNationStateCapabilityFlag98
//   slot 0x27  byte 0x9c  0x004d6750  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x28  byte 0xa0  0x004d6770  inherited ReturnFalseNationStateCapabilityFlagA0
//   slot 0x29  byte 0xa4  0x004d6790  inherited NoOpNationSelectedRegionAndMapCellLabelHook
//   slot 0x2a  byte 0xa8  0x004da5c0  new       NoOpNationPendingActionHook
//   slot 0x2b  byte 0xac  0x004da860  new       PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x2c  byte 0xb0  0x004da8a0  new       AdvanceNationPendingActionStateMachine
//   slot 0x2d  byte 0xb4  0x004da5e0  new       DispatchNationPendingActionEventCodes
//   slot 0x2e  byte 0xb8  0x004daa10  new       SetNationPendingActionStateAndPayload
//   slot 0x2f  byte 0xbc  0x004daa50  new       QueueNationOrderManagerPayloadObject
//   slot 0x30  byte 0xc0  0x004daa80  new       ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x31  byte 0xc4  0x004dab00  new       NoOpNationQueuedOrderHook
//   slot 0x32  byte 0xc8  0x004dab20  new       ExecuteNationPendingActionStateMachine
//   slot 0x33  byte 0xcc  0x004dae70  new       HasQueuedCivWorkOrderType7
//   slot 0x34  byte 0xd0  0x004db7d0  new       GetTCountryClassNamePointer
//   slot 0x35  byte 0xd4  0x004dbac0  new       VTableSlot35
//   slot 0x36  byte 0xd8  0x004dc9f0  new       DispatchNationStateEventCode10
//   slot 0x37  byte 0xdc  0x004dca60  new       OrphanRetStub_0059add0
//   slot 0x38  byte 0xe0  0x004dcc30  new       GetTEventHandlerClassNamePointer
//   slot 0x39  byte 0xe4  0x004df810  new       HandleCityDialogHintClusterUpdate
//   slot 0x3a  byte 0xe8  0x004dfa20  new       DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x3b  byte 0xec  0x004dfae0  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x3c  byte 0xf0  0x004e00d0  new       GetTEventHandlerClassNamePointer
//   slot 0x3d  byte 0xf4  0x004e0140  new       VTableSlot3D
//   slot 0x3e  byte 0xf8  0x004e01b0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x3f  byte 0xfc  0x004dca80  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x40  byte 0x100  0x004dcaa0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x41  byte 0x104  0x004dcc50  new       ApplyDiplomacyState222ToCityStockAndClear
//   slot 0x42  byte 0x108  0x004dcca0  new       ApplyRelationDeltaToCityStockAndUpdateState1f4
//   slot 0x43  byte 0x10c  0x004dcd10  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x44  byte 0x110  0x004dce10  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x45  byte 0x114  0x004dcdd0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x46  byte 0x118  0x004dce40  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x47  byte 0x11c  0x004dce70  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x48  byte 0x120  0x004dce90  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x49  byte 0x124  0x004dcf10  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x4a  byte 0x128  0x004dcf60  new       ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x4b  byte 0x12c  0x004dcfd0  new       IsDiplomacyTargetClassCode200Match
//   slot 0x4c  byte 0x130  0x004e0220  new       RemoveRegionIdFromNationOwnedRegionList
//   slot 0x4d  byte 0x134  0x004dbd20  new       AddRegionIdToNationOwnedRegionList
//   slot 0x4e  byte 0x138  0x004dbf00  new       SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x4f  byte 0x13c  0x004dc3f0  new       OrphanRetStub_004d7e90
//   slot 0x50  byte 0x140  0x004dc440  new       OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x51  byte 0x144  0x004dc4c0  new       OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x52  byte 0x148  0x004dc540  new       OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x53  byte 0x14c  0x004dc660  new       OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x54  byte 0x150  0x004dc840  new       OrphanRetStub_004d7fa0
//   slot 0x55  byte 0x154  0x004e0290  new       OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x56  byte 0x158  0x004e03a0  new       ReturnFalseNationStateActionStub
//   slot 0x57  byte 0x15c  0x004e03d0  new       OrphanRetStub_004d7fe0
//   slot 0x58  byte 0x160  0x004dd0c0  new       ReturnFalseNationStateCapabilityFlag90
//   slot 0x59  byte 0x164  0x004dd140  new       OrphanRetStub_004d7f80
//   slot 0x5a  byte 0x168  0x004dd1b0  new       ReturnFalseNationStateCapabilityFlag98
//   slot 0x5b  byte 0x16c  0x004dd270  new       ReturnFalseNationStateCapabilityFlag9C
//   slot 0x5c  byte 0x170  0x004dd310  new       ReturnFalseNationStateCapabilityFlagA0
//   slot 0x5d  byte 0x174  0x004dd340  new       AddAmountToAidAllocationMatrixCellAndTotal
//   slot 0x5e  byte 0x178  0x004dd3b0  new       SumAidAllocationMatrixColumnForTarget
//   slot 0x5f  byte 0x17c  0x004dd3f0  new       PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x60  byte 0x180  0x004dd430  new       AdvanceNationPendingActionStateMachine
//   slot 0x61  byte 0x184  0x004dd470  new       DispatchNationPendingActionEventCodes
//   slot 0x62  byte 0x188  0x004dd4e0  new       SetNationPendingActionStateAndPayload
//   slot 0x63  byte 0x18c  0x004dd770  new       SetCityStockCounterAndRefresh
//   slot 0x64  byte 0x190  0x004dd7b0  new       AddToCityStockCounterAndRefresh
//   slot 0x65  byte 0x194  0x004dd7f0  new       OrphanCallChain_C1_I42_004dd7f0
//   slot 0x66  byte 0x198  0x004dda40  new       ExecuteNationPendingActionStateMachine
//   slot 0x67  byte 0x19c  0x004dda90  new       HasQueuedCivWorkOrderType7
//   slot 0x68  byte 0x1a0  0x004ddad0  new       GetTCountryClassNamePointer
//   slot 0x69  byte 0x1a4  0x004ddb40  new       VTableSlot69
//   slot 0x6a  byte 0x1a8  0x004ddb80  new       DispatchNationStateEventCode10
//   slot 0x6b  byte 0x1ac  0x004ddd20  new       OrphanRetStub_0059add0
//   slot 0x6c  byte 0x1b0  0x004ddd90  new       GetTEventHandlerClassNamePointer
//   slot 0x6d  byte 0x1b4  0x004dde80  new       HandleCityDialogHintClusterUpdate
//   slot 0x6e  byte 0x1b8  0x004dde30  new       DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x6f  byte 0x1bc  0x004ddeb0  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x70  byte 0x1c0  0x004ddf20  new       GetTEventHandlerClassNamePointer
//   slot 0x71  byte 0x1c4  0x004ddf90  new       VTableSlot71
//   slot 0x72  byte 0x1c8  0x004de2b0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x73  byte 0x1cc  0x004de2d0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x74  byte 0x1d0  0x004ddfc0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x75  byte 0x1d4  0x004de340  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x76  byte 0x1d8  0x004de5e0  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x77  byte 0x1dc  0x004de700  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x78  byte 0x1e0  0x004de7e0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x79  byte 0x1e4  0x004deca0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x7a  byte 0x1e8  0x004de790  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x7b  byte 0x1ec  0x004df010  new       ApplyJoinEmpireModeForTargetNation
//   slot 0x7c  byte 0x1f0  0x004df370  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x7d  byte 0x1f4  0x004df4b0  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0x7e  byte 0x1f8  0x004df580  new       ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x7f  byte 0x1fc  0x004df5a0  new       IsDiplomacyTargetClassCode200Match
//   slot 0x80  byte 0x200  0x004df5c0  new       RemoveRegionIdFromNationOwnedRegionList
//   slot 0x81  byte 0x204  0x004df5f0  new       AddRegionIdToNationOwnedRegionList
//   slot 0x82  byte 0x208  0x004e2880  new       SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x83  byte 0x20c  0x004e0400  new       OrphanRetStub_004d7e90
//   slot 0x84  byte 0x210  0x004e0420  new       OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x85  byte 0x214  0x004e0440  new       OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x86  byte 0x218  0x004e0500  new       OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x87  byte 0x21c  0x004e0550  new       OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x88  byte 0x220  0x004e0590  new       OrphanRetStub_004d7fa0
//   slot 0x89  byte 0x224  0x004e05d0  new       OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x8a  byte 0x228  0x004e0610  new       ReturnFalseNationStateActionStub
//   slot 0x8b  byte 0x22c  0x004e0650  new       OrphanRetStub_004d7fe0
//   slot 0x8c  byte 0x230  0x004e0690  new       ReturnFalseNationStateCapabilityFlag90
//   slot 0x8d  byte 0x234  0x004e0740  new       OrphanRetStub_004d7f80
//   slot 0x8e  byte 0x238  0x004e07b0  new       ReturnFalseNationStateCapabilityFlag98
//   slot 0x8f  byte 0x23c  0x004e0890  new       ReturnFalseNationStateCapabilityFlag9C
//   slot 0x90  byte 0x240  0x004e09a0  new       ReturnFalseNationStateCapabilityFlagA0
//   slot 0x91  byte 0x244  0x004e0b20  new       AddAmountToAidAllocationMatrixCellAndTotal
//   slot 0x92  byte 0x248  0x004e0c10  new       SumAidAllocationMatrixColumnForTarget
//   slot 0x93  byte 0x24c  0x004e0d80  new       PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x94  byte 0x250  0x004e0e70  new       AdvanceNationPendingActionStateMachine
//   slot 0x95  byte 0x254  0x004e0fe0  new       DispatchNationPendingActionEventCodes
//   slot 0x96  byte 0x258  0x004e1170  new       SetNationPendingActionStateAndPayload
//   slot 0x97  byte 0x25c  0x004e1300  new       QueueNationOrderManagerPayloadObject
//   slot 0x98  byte 0x260  0x004e1490  new       ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x99  byte 0x264  0x004e1620  new       OrphanCallChain_C1_I42_004dd7f0
//   slot 0x9a  byte 0x268  0x004e1750  new       ExecuteNationPendingActionStateMachine
//   slot 0x9b  byte 0x26c  0x004e1910  new       HasQueuedCivWorkOrderType7
//   slot 0x9c  byte 0x270  0x004e1a40  new       GetTCountryClassNamePointer
//   slot 0x9d  byte 0x274  0x004e1c00  new       VTableSlot9D
//   slot 0x9e  byte 0x278  0x004e1c20  new       DispatchNationStateEventCode10
//   slot 0x9f  byte 0x27c  0x004e1d50  new       OrphanRetStub_0059add0
//   slot 0xa0  byte 0x280  0x004e1e40  new       GetTEventHandlerClassNamePointer
//   slot 0xa1  byte 0x284  0x004e27f0  new       HandleCityDialogHintClusterUpdate
//   slot 0xa2  byte 0x288  0x004e1f20  new       DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0xa3  byte 0x28c  0x004e1f40  new       ApplyJoinEmpireModeForTargetNation
//   slot 0xa4  byte 0x290  0x004e2190  new       GetTEventHandlerClassNamePointer
//   slot 0xa5  byte 0x294  0x004de810  new       VTableSlotA5
//   slot 0xa6  byte 0x298  0x004e2500  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xa7  byte 0x29c  0x004e25c0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0xa8  byte 0x2a0  0x004e2630  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xa9  byte 0x2a4  0x004e2720  new       ApplyJoinEmpireModeForTargetNation
//   slot 0xaa  byte 0x2a8  0x004e27b0  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0xab  byte 0x2ac  0x004daf00  new       ApplyJoinEmpireMode1TargetTransition
//   slot 0xac  byte 0x2b0  0x004e06d0  new       OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xad  byte 0x2b4  0x004d8bc0  new       SelectCandidateTilesWithLowGroundUnitCount
//   slot 0xae  byte 0x2b8  0x004d8be0  new       OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xaf  byte 0x2bc  0x004db380  new       ApplyJoinEmpireModeForTargetNation
//   slot 0xb0  byte 0x2c0  0x004e2b00  new       SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0xb1  byte 0x2c4  0x004e2b70  new       ApplyJoinEmpireMode1TargetTransition
// object size 0x964 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TGreatPower) ===
