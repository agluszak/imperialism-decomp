#pragma once

#include "decomp_types.h"
#include "game/CString.h"
#include "game/TPtrList.h"

class TMinister;
class NationCityTradeState;
class TQueueObject;
class TCity;

#define TGREATPOWER_VTABLE_SLOT(n)                                                                 \
  virtual void VTableIndex##n##_Provisional(void) {}

// VTABLE: IMPERIALISM 0x00653938
class TGreatPower {
public:
  TGREATPOWER_VTABLE_SLOT(00);
  // slot 0x01 — scalar deleting destructor 0x004d8c20 (SYNTHETIC); real dtor body
  // 0x004d8c50 releases the two identity CStrings then restores the base vtable.
  virtual ~TGreatPower();
  TGREATPOWER_VTABLE_SLOT(02);
  TGREATPOWER_VTABLE_SLOT(03);
  TGREATPOWER_VTABLE_SLOT(04);
  TGREATPOWER_VTABLE_SLOT(05);
  TGREATPOWER_VTABLE_SLOT(06);
  // slot 0x07 — body 0x004d9160: releases every owned member object then `delete this`.
  // TAutoGreatPower overrides it (0x004e7230) to drain autoTrackedListB60 first.
  virtual void ReleaseOwnedGreatPowerObjectsAndDeleteSelf(void);
  TGREATPOWER_VTABLE_SLOT(08);
  TGREATPOWER_VTABLE_SLOT(09);
  // slot 0x0a — body 0x004da500: writes core scalars (0x0e/0x10/0x88/0x8c) then the
  // tracked-order list and each tracked order to the stream.
  virtual void WriteCoreStateAndTrackedOrdersToStream(void* stream);
  // slot 0x0b — body 0x004da3e0 (RET 0x8): reads the same scalar block, clears the
  // tracked-order list, then recreates one TCivWorkOrderState per stream count entry.
  virtual void ReadCoreStateAndRecreateCivOrdersFromStream(void* stream, int unusedArg);
  // slot 0x0c — body 0x004d71b0: scenario-start order seeding. For every owned region
  // with an active terrain record, queues land recruit orders (kinds 2/2/7, plus 6/5 and
  // a navy order at scenario level 4), then three slot-0x0d recruit orders per region,
  // and finally assigns display names via slot 0x0f.
  virtual void SeedInitialMilitaryAndNavyOrdersForOwnedRegions(void);
  // slot 0x0d — body 0x004d7770: creates a military recruit order for nodeContext
  // with a capability bonus from the city-order table (+0x3a5/+0x39d rows).
  virtual void CreateMilitaryRecruitOrderForNode(int nodeContext);
  virtual void AddToNationMetricAtField10(int amount); // slot 0x0e
  // slot 0x0f — body 0x004d8000: gives every unnamed military unit (nameTag1a == 0) a
  // display name: "<ordinal> <unit-type string 0x2717>" for types < 0x1b, or a flavor
  // name from table 0x2744 for types >= 0x1b.
  virtual void AssignDisplayNamesToUnnamedMilitaryUnits(void);
  // slot 0x10 — body 0x004d87b0: cityRecordIndex of the nation's home region.
  virtual int GetHomeRegionCityRecordIndex(void);
  // slot 0x11 — body 0x004d87e0: on quarter ticks (tick/4 odd, tick%4 == 2), queue a
  // recruit order (slot 0x0d) for each owned region garrisoned below threshold.
  virtual void QueueRecruitOrdersForUndergarrisonedRegions(void);
  virtual void ResetDiplomacyLevelForNationSlot12_Provisional(int nationSlot, int resetLevel);
  // index 0x13 / vtable+0x04c. Evidence: 0x004df010 calls this on `this`
  // with (targetNationSlot, 1); return value ignored.
  virtual void ApplyJoinEmpireAcceptanceSideEffectsForTargetNation(int targetNationSlot, int mode);
  virtual void ApplyJoinEmpireMode0GlobalDiplomacyReset(int targetNationSlot); // slot 0x14
  virtual void ApplyJoinEmpireMode1TargetTransition(int targetNationSlot);     // slot 0x15
  virtual CString* GetIdentitySharedString1Slot58(void);                       // slot 0x16
  // slot 0x17 — body 0x004d7d20: encodedNationSlot - 200 == nationCode.
  virtual char IsEncodedNationSlotMinus200Equal(int nationCode);
  // slot 0x18 — body 0x004e2270: drop regionId from ownedRegionList then fire the
  // slot 0x298 hook. TAutoGreatPower overrides it (0x004ea1c0) to also drop the
  // matching mission from missionQueue and clear mapNodeStateFlags.
  virtual void RemoveRegionIdAndRunTrackedObjectCleanup(int regionId);
  TGREATPOWER_VTABLE_SLOT(25);
  TGREATPOWER_VTABLE_SLOT(26);
  TGREATPOWER_VTABLE_SLOT(27);
  virtual int SumDiplomacyState1c6AndRelationDeltaSnapshot(short nationSlot); // slot 0x1c
  virtual short GetDiplomacyCounterA2(void);                                  // slot 0x1d
  // index 0x1e / vtable+0x078. Evidence: 0x004dd1b0 and 0x004dd270 call this
  // for each nation while recomputing diplomacy need baselines; returns AX.
  virtual short QueryNationMetricBySlot78(short metricSlot); // slot 0x78
  virtual short QueryNationMetricBySlot7C(short metricSlot); // slot 0x7c
  // index 0x20 / vtable+0x080. Evidence: base TGreatPower vtable entry
  // 0x00407392 thunks to body 0x004ddc30; TAutoGreatPower overrides this slot.
  virtual void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                              int multiplier);
  virtual bool
  IsDiplomacyState1C6UnsetAndCounterPositiveForTarget(short targetNationSlot); // slot 0x21
  // slot 0x22 — TAutoGreatPower override 0x004e79d0 either forwards to the foreign
  // minister (slot 0x98) or appends a kind-1 tracked-slot entry; returns 0.
  virtual char DispatchOrQueueDiplomacyRequestSlot88_Provisional(int targetNation, int arg2,
                                                                 int arg3, int slotIndex) {
    (void)targetNation;
    (void)arg2;
    (void)arg3;
    (void)slotIndex;
    return 0;
  }
  TGREATPOWER_VTABLE_SLOT(35);
  TGREATPOWER_VTABLE_SLOT(36);
  virtual void NotifyActionSlot94(int sourceNation, int actionCode); // slot 0x94
  TGREATPOWER_VTABLE_SLOT(38);
  TGREATPOWER_VTABLE_SLOT(39);
  virtual char ShouldDispatchImmediatelySlot28_Provisional(void);
  TGREATPOWER_VTABLE_SLOT(41);
  virtual void VTableIndex42_Provisional(void) {} // slot 0x2a
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
  TGREATPOWER_VTABLE_SLOT(49);
  // index 0x32 / vtable+0x0c8. Per-nation pending-action state machine that
  // constructs queued land/navy/civ order objects (body 0x004dab20).
  virtual void ExecuteNationPendingActionStateMachine(void);
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
  TGREATPOWER_VTABLE_SLOT(54);
  // slot 0x37 — body 0x004dca60: forwards to relationManager slot 0x2c when present.
  virtual void NotifyRelationManagerSlot2C(void);
  TGREATPOWER_VTABLE_SLOT(56);
  // slot 0x39 — body 0x004df810: loads the scenario-level preset row (table 0x653570)
  // into the manager's fieldB6 relation deltas, maxes six production-order entries to
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
  TGREATPOWER_VTABLE_SLOT(60);
  TGREATPOWER_VTABLE_SLOT(61);
  TGREATPOWER_VTABLE_SLOT(62);
  // slot 0xfc — TCity::Call2C (0x004b3de0) pushes the city's fieldB6 need vector here.
  virtual void AbsorbCityNeedVectorSlotFC_Provisional(short* needVector) {
    (void)needVector;
  }
  // slot 0x40 — body 0x004dcaa0: effective diplomacyCounterA2 for a proposal code,
  // reduced by 2 when the interaction manager maps the code into an active minister
  // capability category (4/5/3), or by 1 for the code-3 special case.
  virtual unsigned int GetEffectiveDiplomacyCounterA2ForCode(int proposalCode);
  virtual void ApplyDiplomacyState222ToRelationManagerAndClear(void);      // slot 0x41
  virtual void ApplyRelationDeltaToRelationManagerAndUpdateState1f4(void); // slot 0x42
  virtual void VTableIndex67_Provisional(void) {}                          // slot 0x43
  TGREATPOWER_VTABLE_SLOT(68);
  virtual void UpdateNeedTargetAndAccumulateOverCap(short needIndex, short value); // slot 0x45
  virtual bool IsNeedTargetEqualCurrent(short needIndex);                          // slot 0x46
  virtual short GetNeedTargetByType(short needIndex);                              // slot 0x47
  TGREATPOWER_VTABLE_SLOT(72);
  TGREATPOWER_VTABLE_SLOT(73);
  virtual short TryDecayRelationNeedScores9AndB(void); // slot 0x4a
  virtual short TryDecayRelationNeedScores9And8(void); // slot 0x4b
  // slot 0x4c — body 0x004e0220: invokes [vt+0x2c] on every tracked order.
  virtual void DispatchTrackedOrderSlot2CCallbacks(void);        // slot 0x4c
  virtual void VTableIndex77_Provisional(void) {}                // slot 0x4d
  virtual void VTableIndex78_Provisional(void) {}                // slot 0x4e
  virtual char AnyNeedCurrentExceedsTargetWhenCapMismatch(void); // slot 0x4f
  // slot 0x50 — body 0x004dc440: true when any city commodity record 8..0xc has its
  // control value below the record's step value (gated on scenario cap >= 2).
  virtual char HasAnyCommodityRecordBelowStepValue(void);
  // slot 0x51 — body 0x004dc4c0: status prompt code 0x25 (counter 0 at tick 3) or
  // 0x27 (counter ahead of tick by >4 with treasury >= 10000), else 0.
  virtual short ComputeTreasuryStatusPromptCode(void);
  // slot 0x52 — 0x004e1c20 dispatches it on the target nation with mode 0/1.
  virtual char CompareMissionScoreVariantsByMode(int mode);
  TGREATPOWER_VTABLE_SLOT(83);
  TGREATPOWER_VTABLE_SLOT(84);
  // slot 0x55 — body 0x004e0290: selection-sorts trackedObjectList ascending by the
  // per-order-type priority table at 0x6966d0.
  virtual void SortTrackedOrdersByTypePriority(void);
  // slot 0x56 — body 0x004e03a0: runs slot 0x4c then the slot 0x55 sort.
  virtual void RunSlot4CThenSortTrackedOrders(void);
  // slot 0x57 — body 0x004e03d0: field900 = needCapA6 / 5.
  virtual void ResetField900FromNeedCapA6(void);
  TGREATPOWER_VTABLE_SLOT(88);
  // index 0x59 / vtable+0x164. Evidence: 0x004dd1b0 invokes this before
  // resetting diplomacy aid budget state; implementation at 0x004dd140.
  virtual void RecomputeDiplomacyAidBudgetScoreFromResourceWeights(void);
  TGREATPOWER_VTABLE_SLOT(90);
  TGREATPOWER_VTABLE_SLOT(91);
  virtual void ReleaseDiplomacyTrackedObjectSlots850(void); // slot 0x5c
  TGREATPOWER_VTABLE_SLOT(93);
  TGREATPOWER_VTABLE_SLOT(94);
  virtual int SumAidAllocationMatrixAllCells(void); // slot 0x5f
  TGREATPOWER_VTABLE_SLOT(96);
  TGREATPOWER_VTABLE_SLOT(97);
  TGREATPOWER_VTABLE_SLOT(98);
  virtual void SetRelationManagerFieldB6AndRefresh(short targetSlot, short value);   // slot 0x63
  virtual void AddToRelationManagerFieldB6AndRefresh(short targetSlot, short value); // slot 0x64
  // slot 0x65 — body 0x004dd7f0: per-order-kind production metric (city building
  // production doubled per kind; kind 7 sums the city summary record minus four
  // relation-manager counters, clamped at 0).
  virtual unsigned int ComputeProductionMetricForOrderKind(short orderKind);
  virtual void DecrementDiplomacyCounterA2Slot66(int delta);                          // slot 0x66
  virtual void AssignNeedSlotFromSourceSlot19C(int needSlot, int sourceNation) {}     // slot 0x19c
  virtual char AreDiplomacyState1c6Slots13To16AllNonPositive(void);                   // slot 0x68
  virtual void SetDiplomacyState1c6ClampedToCounterA4(short targetSlot, short value); // slot 0x69
  virtual void SnapshotDiplomacyState1c6Into250(void);                                // slot 0x6a
  TGREATPOWER_VTABLE_SLOT(107);
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
  virtual void BeginTurnDiplomacyPrePassSlot1c8() {}                                 // index 114
  virtual void ResetDiplomacyPolicyAndGrantEntriesPreserveRecurringGrants(void);     // index 115
  virtual bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2); // index 116
  virtual bool SetDiplomacyGrantEntryForTargetAndUpdateTreasury(int arg1, int arg2); // index 117
  virtual void RevokeDiplomacyGrantForTargetAndAdjustInfluenceSlot1d8(int sourceNation) {
  } // index 118
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
  TGREATPOWER_VTABLE_SLOT(126);
  // slot 0x7f — body 0x004df5a0: releases the proposal queue (slot 0x1c).
  virtual void ReleaseProposalQueueSlot7F(void);
  TGREATPOWER_VTABLE_SLOT(128);
  TGREATPOWER_VTABLE_SLOT(129);
  // slot 0x82 — body 0x004e2880: ranks this nation's summed building production against
  // the mean/stddev across all eligible nations; returns tier 0..4.
  virtual int ClassifyNationProductionTierVsPeers(void);
  // slot 0x20c — base is a no-op; TAutoGreatPower override 0x004e9f10 prunes
  // candidateNationFlags and reports whether any candidate remains active.
  virtual char VTableSlot20C_Provisional(void) {
    return 0;
  }
  // index 132 / vtable+0x210. Evidence: 0x004e9ed0 calls this on `this`
  // with one target-nation argument; return value ignored.
  virtual void VTableSlot84_Provisional(int targetNation); // body 0x004e0420
  virtual void NotifyAllianceSlot214(int targetNation);    // index 133 — body 0x004e0440
  // slot 0x86 — body 0x004e0500; navy order priority weights summed for this nation.
  virtual int SumNavyOrderPriorityForNationSlot86(void);
  virtual int CountMapActionContextNodesWithNationBit(void);                         // slot 0x87
  virtual double ComputeMinisterSkillFloatSlot88(void);                              // slot 0x88
  virtual double ComputeMinisterSkillFloatSlot89(void);                              // slot 0x89
  virtual double ComputeMinisterSkillFloatSlot8A(void);                              // slot 0x8a
  virtual double ComputeMinisterSkillFloatSlot8B(void);                              // slot 0x8b
  virtual double ComputeMinisterSkillFloatSlot8C(void);                              // slot 0x8c
  virtual int GetCityBuildingProductionViaRelationManagerSlot8D(short buildingSlot); // slot 0x8d
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
  virtual int CheckTransitionSlot27C(int targetNation, int sourceNation) {
    return 0;
  } // slot 0x27c
  virtual int PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) {
    return 0;
  } // slot 0x280
  // index 0xa1 / vtable+0x284 — body 0x004e27f0 (vtable holds ILT thunk 0x00406fe1).
  // Queues a nation-pair war transition and notifies the third-party minor nation
  // when the policy code is 1 or 0x132.
  virtual void ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot,
                                                                    int policyCode,
                                                                    int sourceNationSlot);
  virtual void NoOpSlotA2(void); // body 0x004e1f20
  // slot 0xa3 — body 0x004e1f40 (not yet ported); war-commitment threshold consumed by
  // slot 0x9e (compared against ComputeMinisterSkillFloatSlot8C).
  virtual float ComputeWarThresholdSlotA3_Provisional(int targetNation);
  virtual void NotifyWarResetSlot290(); // slot 0x290 — body 0x004e2190
  virtual void CallSlotA5_Provisional(void);
  // slot 0x298 — fired by RemoveRegionIdAndRunTrackedObjectCleanup (0x004e2270).
  virtual void NotifyRegionEventSlot298_Provisional(int regionId) {
    (void)regionId;
  }
  // slot 0x29c — body 0x004e25c0: reset diplomacy level/grants for targetNation and
  // fire slot 0x2a0 for every nation with an active policy link.
  virtual void ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation);
  virtual void CallSlotA8_Provisional(int targetNation);
  virtual void CallSlotA9_Provisional(int targetNation);
  // slot 0x2a8 — body 0x004e27b0: mode-dispatched diplomacy slot action (mode 6 ->
  // slot 0xa8, etc.). TDiplomacyTurnStateManager notifies relation-code changes here.
  virtual void DispatchNationDiplomacySlotActionByMode(int targetNationSlot, int mode);
  // slot 0x2ac — base body is the 0x0040389b thunk: dispatch turn event 0x11f8 with no
  // payload. TAutoGreatPower overrides it (0x004e7510) with the 'lost' game-state event.
  virtual void DispatchTurnEvent11F8NoPayloadSlot2AC(void);
  // slot 0xac — body 0x004e06d0: sums the accumulated value (+0x44) of city
  // commodity records 8..0xc.
  virtual int SumCommodityRecordAccumulatedValues(void);
  TGREATPOWER_VTABLE_SLOT(173);
  TGREATPOWER_VTABLE_SLOT(174);
  // slot 0x2bc — body 0x004db380; TAutoGreatPower stubs it out (0x004e6b10).
  virtual void UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void);
  // index 0xb0 / vtable+0x2c0. Dispatches a queued turn-order action via the active
  // map order context (body 0x004e2b00, RET 0xc -> three short args). Called from
  // slot 0x32 to enqueue land/navy/civ orders.
  virtual void DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags);
  TGREATPOWER_VTABLE_SLOT(177);
  // slot 0x2c8 — escalation hook invoked by TAutoGreatPower::AssignNeedSlotFromSourceSlot19C
  // (0x004e7680) when the random relation-score check passes.
  virtual void EscalateNeedSlot2C8_Provisional(int needSlot) {}
  virtual void CallSlotB3_Provisional(void) {}

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
  TMinister* foreignMinister;
  TMinister* interiorMinister;
  TMinister* defenseMinister;
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
  TCity* relationManager;
  TPtrList* townMarkerList;
  TPtrList* trackedObjectList;
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
  TPtrList* missionNodeQueue;
  int field910;
  int aidAllocationTotal;
  unsigned char colonyBoycottFlags[0x17];
  unsigned char pad_92f[0x960 - 0x92f];
  int pendingAidTotal;
  // Provisional tail promoted from mixed-method imports beyond the core 0x964 block.
  short actionMetricByQuarter[6];
  unsigned char mapNodeStateFlags[0x180];
  unsigned char portZoneStateFlags[0x70];
  TPtrList* missionQueue;

  // (All thunk_*_At0040xxxx member wrappers retired: those addresses are pure ILT
  // `jmp` stubs from incremental linking, not real functions. Callsites now call the
  // real methods/virtuals directly; reccmp auto-detects the orig-side thunks.)

  // Semantic C++ wrappers:
  // - constructor behavior maps to 0x004D8CC0 InitializeNationStateRuntimeSubsystems
  // - deleting destructor behavior maps to 0x004D9160 ReleaseOwnedGreatPowerObjectsAndDeleteSelf
  TGreatPower();
  TGreatPower(int arg1, int arg2);

  static void* CreateTGreatPowerInstance(void);
  static void* GetTGreatPowerClassNamePointer(void);
  void InitializeGreatPowerMinisterRosterAndScenarioState(int arg1);
  void CompileGreatPowerRelationshipDeltaLinesAndDispatchMessage(void);
  void IsNationResourceNeedCurrentSumExceedingCapA6(void);
  void QueueMapActionMissionFromCandidateAndMarkState(int arg1, int arg2, int arg3, int arg4);
  void AddRegionIdToNationOwnedRegionListAndTriggerExpansionActionIfThresholdMet(void);
  void ApplyDiplomacyTargetTransitionAndClearGrantEntry(int targetNationSlot, int policyCode);
  void ReleaseTrackedObjectsByMapOwnerAndUnassignedEntries(int ownerClass);
  void BuildGreatPowerMapContextTriggeredNationEventMessages(void);
  void BuildGreatPowerEligibleNationEventMessagesFromLinkedList(void);
  void ApplyNationResourceNeedTargetsToOrderState(void);
  bool ExecuteAdvisoryPromptAndApplyActionType1(int arg1, int arg2);
  void AssignFallbackNationsToUnfilledDiplomacyNeedSlots(void);
  void ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  void RefreshDiplomacyNeedScoresAndClearAidAllocationMatrix(void);
  void RevokeDiplomacyGrantForTargetAndAdjustInfluence(int arg1);
  void SetNationResourceNeedCurrentByType(int needType, int currentValue);
  void TryIncrementNationResourceNeedTargetTowardCurrent(int needType);
  int GetMultiplierSlot21C(void);
  void AddAmountToAidAllocationMatrixCellAndTotal(int amount, short columnIndex, short rowIndex);
  int SumAidAllocationMatrixColumnForTarget(short targetNationId);
  int ComputeRemainingDiplomacyAidBudget(void);
  short GetDiplomacyExternalStateB6ByTarget(short targetNationSlot);
  void DecrementDiplomacyCounterA2ByValue(int delta);
  void ResetNationDiplomacyProposalQueue(void);
  void SetDiplomacyColonyBoycottFlagForTargetAndRefreshMinorNations(int targetNationSlot,
                                                                    int isBoycottEnabled);
  void OrphanVtableAssignStub_004ddd20(void);
  void RebuildNationResourceYieldsAndRollField134Into136(void);
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void);
  void InitializeMapActionCandidateStateAndQueueMission(int arg1);
  void SelectAndQueueAdvisoryMapMissionsCase16(void);
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void);
  float ComputeMapActionContextCompositeScoreForNation(int nodeType);
  unsigned int ComputeMapActionContextNodeValueAverage(void);
  float ComputeAdvisoryMapNodeScoreFactorByCaseMetric(int metricCase, int cityIndex,
                                                      int relationTargetNation,
                                                      int selectedNationSlot);
  void ProcessPendingDiplomacyProposalQueue(void);
  void InitializeNationStateRuntimeSubsystems(int arg1, int arg2);
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode, short targetNationId);
  void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void);
  void DispatchTurnEvent2103WithNationFromRecord(void);
  void ApplyJoinEmpireModeForTargetNation(int targetNationSlot, int mode);
  void AdvanceOwnedRegionDevelopmentCountersAndDispatchEvents(void);
  void WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0(void* pMessage);
  void QueueDiplomacyProposalCodeWithAllianceGuards(int arg1, int arg2);
  void WrapperFor_TGreatPower_VtblSlot32_At004e7630(int arg1, int arg2, int arg3);
  void ForwardApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2);
  void ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook(int arg1, int arg2);
  void QueueWarTransitionFromAdvisoryAction(int arg1, int arg2, int arg3);
  void ApplyJoinEmpireResetAndClearDiplomacyCaches(int arg1);
  void AddRegionToNationAndQueueMapActionMission(int arg1);
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3, int arg4);
  void QueueDiplomacyProposalCodeForTargetNationAndDispatchTurnEvent16(int proposalCode,
                                                                       int targetNationId);
  void TryDispatchNationActionViaUiThenTurnEvent(int arg1, int arg2, int arg3, int arg4);
  void ProcessPendingDiplomacyThenDispatchTurnEvent29A(void);
  void ApplyClientGreatPowerCommand69AndEmitTurnEvent1E(int arg1, int arg2);
  void CommitCityRecruitmentOrderDelta(void);
  void HandleTurnInstruction_Civi_DeserializeAndCreateWorkOrder(void* pInstructionRaw);
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void);
  void QueueInterNationEventType0FForNationPairContext(short targetNationSlot,
                                                       short sourceNationSlot);
  void ConstructTurnOrderNavigationWindowEntryViewportAdaptive(void);
  void DispatchNationField98CallbackD4(void);
  void DispatchNationField9CCallback4C(void);
  void DispatchNationField94Callbacks90And94(void);

  NationCityTradeState* GetCityState(void) {
    return reinterpret_cast<NationCityTradeState*>(relationManager);
  }
};

#undef TGREATPOWER_VTABLE_SLOT
