#pragma once

#include "compat.h"

#include "decomp_types.h"
#include "game/ui_screens/CString.h"
#include "game/nation_domain_types.h"
#include "game/city_ui/TCountry.h"
#include "game/map/TMission.h" // eMissionType
#include "game/ui_core/TSortedList.h"

struct CRuntimeClass;
class TStream;

class TMinister;
class TForeignMinister;
class TDefenseMinister;
class TCityInteriorMinister;
class TSortedByRelationshipList;
class TCity;
class TZone;
class TTurnStartEvent;

// 16-bit discriminator stored in each diplomacy tracked-slot record.
enum eTrackedSlotEntryKind { kTrackedSlotAcceptEntry = 0, kTrackedSlotOfferEntry = 1 };

// Nation object: inherits the intermediate base TCountry (identity strings, nation-slot
// metrics, military-unit + owned-region lists), itself a TObject.
// VTABLE: IMPERIALISM 0x00653938
class TGreatPower : public TCountry {
public:
  // ---- identity / serialization ----
  // slot 0x00 — body 0x004d89d0: returns TGreatPower CRuntimeClass descriptor.
  DECLARE_DYNCREATE(TGreatPower)
  // Inline so every derived nation class reproduces the original direct teardown of
  // TCountry's two identity CStrings.
  // FUNCTION: IMPERIALISM 0x004d8c50
  ~TGreatPower() override {}
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
  void SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) override;
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
  short SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot) override; // slot 0x1c
  short GetDiplomacyCounterA2(void) override;                                    // slot 0x1d
  short GetDiplomacyExternalStateByTarget(short nationSlot) override;            // slot 0x1e
  short QueryNationMetricBySlot7C(short metricSlot) override;                    // slot 0x1f
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
  void QueueDiplomacyProposalCodeForTargetNation(DiplomacyProposalCodeStorage proposalCode,
                                                 NationSlot targetNationSlot) override;
  // Reads the pending-policy pairs in field8d6, so it belongs here and not on TCountry:
  // TMinor also derives from TCountry and is only 0x2dc bytes, while field8d6 sits at
  // +0x8d6 inside TGreatPower's 0x964.
  char IsDiplomacyPolicyAllowedForTargetClassState(short policyCode, short targetNationSlot);
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
  // slot 0x2f — Mac oracle: AddTurnStartEvent(TTurnStartEvent*); the base queues it.
  virtual void AddTurnStartEvent(TTurnStartEvent* event);
  // slot 0x30 — body 0x004daa80: invokes [vt+0x28] on every mission node, then
  // clears missionNodeQueue.
  virtual void DispatchMissionNodeCallbacksAndClearQueue(void);
  virtual void NoOpNationQueuedOrderHook(void);
  // index 0x32 / vtable+0x0c8. Per-nation pending-action state machine that
  // constructs queued land/navy/civ order objects (body 0x004dab20).
  virtual void ExecuteNationPendingActionStateMachine(void);
  // 0x4dfd30 — update the capital-city record: homeTileIndex != -1 restamps the city's
  // tile ordinal, cityName != 0 reassigns its display name (renamed from the misleading
  // Ghidra 'RefreshNationCivilianWorkOrdersForTurn'; body walks this->city subobject).
  void SetHomeCityTileAndDisplayName(short homeTileIndex, char* cityName);
  // slot 0x33 — body 0x004dae70: scans trackedObjectList for an order with
  // orderType == 7.
  virtual char HasDeveloper(void);
  // slot 0x34 — body 0x004db7d0: builds the 0x1950-byte transport-influence region map
  // (flood-filled from the home region via slot 0x35, extended through transport-linked
  // town markers), updates each marker's transportLinkedFlag4c, and hands the map to the
  // caller through outInfluenceMap (or frees it when outInfluenceMap is null).
  virtual void BuildTransportLinkedInfluenceMap(char** outInfluenceMap);
  // slot 0x35 — body 0x004dbac0: marks regionMap[id]=1 for every region connected to
  // regionId through same-owner neighbors (self-recursive through this slot, with the
  // first eligible neighbor tail-iterated).
  virtual void MarkConnectedOwnedRegionsFrom(unsigned char* regionMap, short regionId);

  // Builds a per-tile strength map around transport-linked towns. The caller owns the
  // returned 0x1950-byte allocation. 0x4dbbb0.
  char* BuildCityInfluenceLevelMap();

  // ---- turn-event message dispatch ----
  virtual void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
  virtual void NotifyCitySlot2C(void);
  virtual void FillInteriorMinisterOrders(void);
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
  // Slots 0x3c-0x3e — each dispatches *message via A13A0 (overlayMode 2/1/0)
  // when the quarter gate (economicTurn / 4) is open.
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel2(CString* message);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel1(CString* message);
  virtual void DispatchGreatPowerQuarterlyStatusMessageLevel0(CString* message);
  // slot 0x3f / vtable offset 0xfc — TCity::PredictedNeeds passes its 23-entry
  // city-stock vector here. The base implementation is a bare `ret 4`.
  virtual void AbsorbCityNeedVectorSlotFC(short* needVector);
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
  // Ground truth leaves the just-stored needsOverCapFlag value in AL at return (the
  // ternary's SETcc result); TInteriorMinister::Call54 (0x4be5b0) reads it as bool.
  virtual bool IsNationResourceNeedCurrentSumExceedingCapA6(void);
  virtual short TryDecayRelationNeedScores9AndB(void); // slot 0x4a
  virtual short TryDecayRelationNeedScores9And8(void); // slot 0x4b
  // slot 0x4c — body 0x004e0220: invokes [vt+0x2c] on every tracked order.
  virtual void DispatchTrackedOrderSlot2CCallbacks(void); // slot 0x4c
  virtual void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
  virtual void AdvanceOwnedRegionDevelopmentCountersAndHandleEvents(void);
  virtual char AnyNeedCurrentExceedsTargetWhenCapMismatch(void); // slot 0x4f
  // slot 0x50 — body 0x004dc440: true when any city commodity record 8..0xc has its
  // control value below the record's step value (gated on scenario cap >= 2).
  virtual char HasAnyCommodityRecordBelowStepValue(void);
  // slot 0x51 — body 0x004dc4c0: status prompt code 0x25 (counter 0 at tick 3) or
  // 0x27 (counter ahead of tick by >4 with treasury >= 10000), else 0.
  virtual short ComputeTreasuryStatusPromptCode(void);
  // slot 0x52 — 0x004e1c20 dispatches it on the target nation with mode 0/1.
  virtual char CompareMissionScoreVariantsByMode(int mode);
  // slots 0x53/0x54 — both take the advisory message accumulator by pointer and
  // append "\n     <name>" lines for each qualifying zone/town, returning nonzero
  // when anything was appended (RET 4 + AL read at the 0x501270 call sites).
  virtual char BuildGreatPowerMapContextTriggeredNationEventMessages(CString* outMessageText);
  virtual char BuildGreatPowerEligibleNationEventMessagesFromLinkedList(CString* outMessageText);
  // slot 0x55 — body 0x004e0290: selection-sorts trackedObjectList ascending by the
  // per-order-type priority table at 0x6966d0.
  virtual void SortTrackedOrdersByTypePriority(void);
  // slot 0x56 — body 0x004e03a0: runs slot 0x4c then the slot 0x55 sort.
  virtual void MoveCivilians(void); // Mac oracle
  // slot 0x57 — body 0x004e03d0: field900 = needCapA6 / 5.
  virtual void MoveArmy(void); // Mac oracle
  virtual void SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(int targetNationSlot,
                                                                            int isBoycottEnabled);
  virtual void RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void);
  virtual void ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  virtual void RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  virtual void ReleaseDiplomacyTrackedObjectSlots850(void); // slot 0x5c
  virtual void AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex,
                                                          short rowIndex);
  virtual int SumAidAllocationMatrixColumnForTarget(NationSlot targetNationSlot);
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
  virtual void SetTradeOffersFor(short resourceKind, short offerContext);             // slot 0x19c
  virtual char AreDiplomacyState1c6Slots13To16AllNonPositive(void);                   // slot 0x68
  virtual void SetDiplomacyState1c6ClampedToCounterA4(short targetSlot, short value); // slot 0x69
  virtual void SnapshotDiplomacyState1c6Into250(void);                                // slot 0x6a
  // slot 0x6b / 0x1ac — body 0x004ddd20: clears diplomacyState1c6[targetSlot].
  virtual void ClearDiplomacyState1c6ForTarget(short targetSlot);
  // slot 0x6c — body 0x004ddd90: packs {kind, targetNation, value, eligibility,
  // payload} and appends it to diplomacyTrackedSlots[slotIndex] via [vt+0x38];
  // Offer entries are always eligible; accept entries are eligible for minor nations.
  virtual void AppendTrackedSlotEntry(short kind, int targetNation, short value, short slotIndex,
                                      int payload);
  virtual short GetTrackedSlotEntryCountLow(short targetSlot);     // slot 0x6d
  virtual char AnyTrackedSlotEntryHasZeroField4(short targetSlot); // slot 0x6e
  // slot 0x6f — body 0x004ddeb0: unpacks tracked-slot entry fields (+0/+2/+4/+8).
  virtual void ReadTrackedSlotEntryFields(short slotIndex, short ordinal, short* outKind,
                                          short* outValue, short* outTargetNation, int* outPayload);
  virtual void AssignPayloadToTrackedSlotEntryMatchingField2(int targetSlot, int matchKey,
                                                             int payload);       // slot 0x70
  virtual void ClearDiplomacyState1c6Block(void);                                // index 113
  virtual void BeginTurnDiplomacyPrePassSlot1c8();                               // index 114
  virtual void ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void); // index 115
  virtual bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(short targetClass,
                                                                short policyCode);   // index 116
  virtual bool SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2); // index 117
  virtual void
  RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(int sourceNation); // index 118
  virtual char
  CanAffordDiplomacyGrantEntryForTarget(NationSlot targetNationSlot,
                                        unsigned short proposedGrantEntry); // index 119
  virtual void ApplyTurnDiplomacyStateSlot1e0();                      // index 120 — body 0x004de7e0
  virtual void DecrementNeedLevelByNationStep(NationSlot nationSlot); // index 121
  virtual char CanAffordAdditionalDiplomacyCostAfterCommitments(short additionalCost); // index 122
  virtual void AcceptOffer(short proposalIndex);                                       // index 123
  virtual void RejectOffer(unsigned short proposalQueueIndex);                         // index 124
  // slot 0x7d — body 0x004df4b0: whether the proposal may target the nation given the
  // current relationship (alliance through war progressively restricts treaty offers).
  virtual char IsDiplomacyProposalAllowedForRelationship(DiplomacyProposalCodeStorage proposalCode,
                                                         int targetNation);
  virtual void ResetNationDiplomacyProposalQueue(void);
  virtual void ReleaseProposalQueueSlot7F(void);
  virtual void DispatchTurnEvent2103WithNationFromRecord(void);
  virtual void ReplyToDiplomacyOffers(void);
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
  virtual char PassesDiplomacyStrengthThresholdForTarget(int targetNation); // body 0x004e1c00
  // slot 0x9e — joins a war against targetNation when minister skill beats the war
  // threshold; propagates relation code 4 to tier-2 partners and queues event 0x1c.
  virtual char EvaluateJoinWarAgainstNationAndQueueEvent(int targetNation);
  virtual int HandleWarTransitionRequest(int targetNation, int sourceNation); // slot 0x27c
  virtual int HandleWarTransitionRequestWithRoleSwap(int targetNation, int sourceNation,
                                                     char swapRoles); // slot 0x280
  // index 0xa1 / vtable+0x284 — body 0x004e27f0 (vtable holds ILT thunk 0x00406fe1).
  // Queues a nation-pair war transition and notifies the third-party minor nation
  // for the direct-transition mode or a join-empire offer with war entanglements.
  virtual void QueueWarTransitionAndNotifyThirdPartyIfNeeded(int targetNationSlot,
                                                             int transitionMode,
                                                             int sourceNationSlot);
  // slot 0xa2 — base body 0x004e1f20 is an empty hook; TAutoGreatPower's override
  // (0x004e9a50) selects and queues the case-16 advisory map missions.
  virtual void SelectAndQueueAdvisoryMapMissionsCase16(void); // body 0x004e1f20
  // slot 0xa3 — body 0x004e1f40; war-commitment threshold consumed by
  // slot 0x9e (compared against ComputeMinisterSkillFloatSlot8C).
  virtual float ComputeWarThresholdSlotA3(int targetNation);
  virtual void PruneInvalidTrackedEntriesAndNotifyOwner(); // slot 0xa4 — body 0x004e2190
  virtual void NotifyWarResetSlotA5(void);
  // slot 0x298 — fired by RemoveRegionIdAndRunTrackedObjectCleanup (0x004e2270).
  virtual void NotifyRegionEventSlot298(int regionId);
  // slot 0x29c — body 0x004e25c0: reset diplomacy level/grants for targetNation and
  // fire slot 0x2a0 for every nation with an active policy link.
  virtual void ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation);
  virtual void DeclareWarOnTargetForAlignedMinors(int targetNation);
  virtual void MakePeaceWithTargetForAlignedMinors(int targetNation);
  // slot 0x2a8 — body 0x004e27b0: mode-dispatched diplomacy slot action (mode 6 ->
  // slot 0xa8, etc.). TDiplomacyMgr notifies relation-code changes here.
  virtual void DispatchNationDiplomacySlotActionByMode(int targetNationSlot,
                                                       DiplomacyRelationship relationship);
  // slot 0x2ac — handles this nation leaving play. The base dispatches turn event
  // 0x11f8; network and AI nation types override the transition behavior.
  virtual void SorryYouLose(void);
  // slot 0xac — body 0x004e06d0: sums the accumulated value (+0x44) of city
  // commodity records 8..0xc.
  virtual int SumCommodityRecordAccumulatedValues(void);
  virtual void RecomputeAiExpansionAndMissionPressureScores(void);
  virtual void RefreshTrackedEntriesAndReplanAiDevelopment(int unused);
  // slot 0xaf — body 0x004db380 returns a char (1 on the hard-alert dispatch path,
  // 0 otherwise); the case-0xb join-empire loop tests that result.
  virtual char UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
  virtual void DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags);
  virtual void BuildGreatPowerTurnMessageSummaryAndDispatch(void);

  // LoadNationDisplayNameSharedRefFromField8 moved to TCountry (its field's owner).

  // 0x004e3060 — army units weighted by g_anWeightedNeighborUnitScoreByType and quality
  // percent, plus this nation's navy primary orders against a local per-type table.
  int ComputeNationNavyOrderWeightedMovementScore();
  // 0x004e3220 — average bilateral relation-standing score vs every other live slot.
  int RecomputeNationComparativePowerMetrics_Impl();

  // 0x004ddcf0. Adds `delta` to relationDeltaSnapshot[index] (the +0x198 per-nation
  // short counter array). Called from
  // TNavyMgr::ProcessNationMapOrderInteractionsAndApplyOutcomes.
  void AddShortDeltaToNationCounterAtOffset198(short index, short delta);

  // Clamped diplomacy budget (treasury + base/100, floored at 0). Header-inline:
  // the original inlines this exact clamp into both CanAfford* bodies (0x004de700 /
  // 0x004de790), flowing the value through the eax return slot.
  int ComputeAvailableDiplomacyBudget() const {
    int availableBudget = treasuryValue10 + diplomacyBudgetBase / 100;
    return availableBudget & (static_cast<int>(availableBudget <= 0) - 1);
  }

  // 0x04..0x94 (identity strings, nation-slot metrics, militaryUnitList44,
  // unitNameOrdinalByType, ownedRegionList) now live on the TCountry base (ASSERT_SIZE 0x94).
  TForeignMinister* foreignMinister;       // +0x94
  TCityInteriorMinister* interiorMinister; // +0x98
  TDefenseMinister* defenseMinister;       // +0x9c
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
  // Turn/proposal/diplomacy queues are TSortedByRelationshipList instances
  // (constructed via TSortedByRelationshipList::CreateObject in 0x004d8cc0).
  TSortedByRelationshipList* turnEventQueue;
  TSortedByRelationshipList* proposalQueue;
  TSortedByRelationshipList* diplomacyTrackedSlots[0x11];
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
  // Compared signed (setge vs 0x33) by the region-list growth check (0x4e22b0).
  signed char serializedStatusFlags[8];
  signed char expansionAlertCounter;
  signed char field8d1;
  unsigned char field8d2;
  unsigned char field8d3;
  signed char expansionEventGate;
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
  TSortedByRelationshipList* turnSummaryQueue;
  TSortedList* missionNodeQueue;
  int field910;
  int aidAllocationTotal;
  unsigned char colonyBoycottFlags[0x17];
  unsigned char pad_92f;
  // 0x930..0x95c — the twelve rows displayed by TGameScorePicture. GenerateGameScore
  // rebuilds the block wholesale before the score screen reads it by row index.
  union {
    struct {
      int gameScoreLabor930;
      int gameScoreTransport934;
      int gameScoreIndustry938;
      int gameScoreProvinces93c;
      int gameScoreMilitary940;
      int gameScoreNavy944;
      int gameScoreDiplomacy948;
      int gameScoreMerchantMarine94c;
      int gameScoreYear950;
      int gameScoreSubtotal954;
      int gameScoreDifficultyPercent958;
      int gameScoreTotal95c;
    };
    int gameScoreRows930[12];
  };
  // Mac PayForMilitary writes this turn's army+navy maintenance charge here before
  // deducting it from treasury. The trade totals / remaining-budget views present the
  // same charge as an expense; the old pendingAidTotal name was misleading.
  int militaryExpenses960;
  // Object ends here at 0x964 (== CRuntimeClass::m_nObjectSize for TGreatPower and
  // for TProxyGreatPower/TClientGreatPower/TRemoteGreatPower; THostGreatPower adds one
  // more dword). The AI-only tail block (actionMetricByQuarter/mapNodeStateFlags/
  // portZoneStateFlags/missionQueue/floatB64/floatB68) that used to be declared here
  // moved to TAutoGreatPower (RTTI size 0xb70) -- see TSimMgr::RebuildPrimaryNationState
  // ForSlot (0x57cda0): every non-Auto concrete subclass allocates exactly its own
  // RTTI-reported size with no room for that block, and the one "bare TGreatPower"-
  // looking construction (TSimMgr.cpp, scenario mode 2) is proven by its
  // operator_new(0xb70) + TAutoGreatPower::TAutoGreatPower() ctor call (thunk 0x407a31
  // -> 0x4e6b50) to actually construct a TAutoGreatPower, not a bare TGreatPower.

  // (All thunk_*_At0040xxxx member wrappers retired: those addresses are pure ILT
  // `jmp` stubs from incremental linking, not real functions. Callsites now call the
  // real methods/virtuals directly; reccmp auto-detects the orig-side thunks.)

  // Semantic C++ wrappers:
  // - constructor behavior maps to 0x004D8CC0 InitializeNationStateRuntimeSubsystems
  // - TObject::Free override at 0x004D9160 releases owned members then deletes self
  // 0x4e0770 — city population summary metric: productionSlots14 bucket words folded
  // ((w8*2+w6)*2+w4) plus extraAt1e; 0 when the nation has no city. Curated name kept
  // from symbols.csv (advisory case-6 metric); exact game meaning still tentative.
  short ComputeNationRuntimeAdvisoryMetricCase6();

  // 0x4d84b0 — classifies this nation's military power (sum of
  // g_aUnitOrderCostProfileByAbilityId[unitType][2] over militaryUnitList44, plus
  // SumNavyOrderPriorityForNationSlot86() plus 4) against the mean/stddev of the same
  // metric across every eligible nation: 4 (> mean+2*sd), 3 (> mean+sd), 2 (<= mean-sd,
  // or fewer than 2 eligible nations to compare against), 1 (>= mean-2*sd), else 0.
  int ClassifyNationMilitaryPowerBandAgainstGlobalMean();

  TGreatPower();
  TGreatPower(int arg1, int arg2);

  void CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
  void ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass);
  bool TryHandleWarTransitionRequest(int targetNation, int sourceNation);
  void RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1);
  // 0x004e3620 — sums the encoded diplomacyGrantByNation entries (masking off the
  // top 2 flag bits), skipping the 0xffff "no grant" sentinel. Used by the grants/aid
  // screen's "Total" row (TGrantsView::Draw).
  int SumDiplomacyGrantEntriesMaskedToValueBits();
  // 0x004e9060 — composite advisory score for the nation selected from
  // candidateNationFlags (or from the diplomacy standing list when no flag is set):
  // product of metric factors 5*7*2*4 for (zone, selected nation). `zone` is the
  // map-action context the caller resolved for the scored node; it flows unchanged
  // into metric 4 (navy-order zone match) and metric 7 (zone value average).
  float ComputeMapActionContextCompositeScoreForNation(TZone* zone);
  // 0x004e8750 — one metric factor for the advisory map-node scoring family.
  // metricCase 1/2: eligible-nation army/navy strength share for selectedNationSlot;
  // 3: owned-region-weighted neighbor-link ratio (cityIndex node, selectedNationSlot
  // country); 4: navy-order priority share for `zone` (major slots only); 5: 100 /
  // diplomacy standing(this nation -> selectedNationSlot); 6: node city-score ratio
  // (1.5x when a claimed-but-not-owned node's owner is at war with us); 7: zone value
  // average vs global average.
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex, TZone* zone,
                                                      int selectedNationSlot);
  // 0x004e8c50 — composite advisory score for one map node: metric-factor product
  // keyed off the node's owner (primary nations square the product; mode 0 = plain
  // node, mode 1 = link pair with linkCityRecordIndex, other = zone-context form).
  float ComputeAdvisoryMapNodeCompositeScoreByMode(int cityRecordIndex, int mode,
                                                   int linkCityRecordIndex);
  // 0x004e8c20 — two-arg convenience wrapper (linkCityRecordIndex = -1).
  float ComputeAdvisoryMapNodeCompositeScore(int cityRecordIndex, int mode);
  // 0x004e0460 / 0x004e04b0 — sum GetStudliness over the
  // g_pNavyPrimaryOrderListHead chain entries owned by this nation (optionally only
  // those targeting `zone`). Real __thiscall methods: both bodies compare the ship's
  // owner tag against [this+0xc] (ret 4 / ret).
  int SumNavyOrderPriorityForNationAndNodeType(TZone* zone);
  int SumNavyOrderPriorityForNation();
  void InitializeNationStateRuntimeSubsystems(int arg1, int arg2);

  // Mac oracle: GenerateGameScore. Rebuilds the gameScoreRows930 snapshot wholesale:
  // population
  // baseline, summed city building types, owned-region score (this nation plus any
  // minor nation whose encoded slot matches), militaryUnitList44 order-cost sum, navy
  // order priority, average diplomatic relation standing, trade capacity, and a
  // season-weighted countdown total. Called once per turn to refresh the cached
  // metrics consumed elsewhere (advisory scoring, UI summaries).
  void GenerateGameScore(void); // 0x004e32a0

  // Mac oracle: PayForMilitary. Computes the army and navy maintenance charge using the
  // current scenario multiplier, stores it in militaryExpenses960, and deducts it from
  // treasury. 0x004e3560.
  void PayForMilitary();

  TCity* GetCityState(void) {
    return city;
  }
};
ASSERT_SIZE(TGreatPower, 0x964);
