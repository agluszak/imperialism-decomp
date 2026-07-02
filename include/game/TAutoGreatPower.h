#pragma once

#include "game/TGreatPower.h"

// VTABLE: IMPERIALISM 0x00654088
class TAutoGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TAutoGreatPower)
  // `missionQueue` (the whole 0x964+ tail block is TAutoGreatPower-only data that is
  // still declared on TGreatPower; see worklog 2026-06-10).

  TAutoGreatPower();
  ~TAutoGreatPower();
  // Destructor real body 0x004e6bb0; scalar deleting destructor 0x004e6b80
  // (both paired via symbols.csv names).

  // Overrides of TGreatPower virtuals:
  // slots 0x05/0x06 — 0x004e73f0/0x004e72c0: AI tail-state stream I/O.
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  // slot 0x07 — 0x004e7230: drain missionQueue then run the base Free().
  void Free() override;
  // slot 0x14 — 0x004ea150: join-empire reset plus clearing map-action caches.
  void SetNationTransferTargetCodeAndNotifyEligiblePeers(int targetNationSlot) override;
  // slot 0x19 — 0x004ea290: add region and queue a map-action mission.
  void AddRegionIdToNationOwnedRegionList(int regionId) override;
  // slot 0x20 — 0x004e7630: resource delta with need clamp before base totals.
  void ApplyIndexedResourceDeltaAndAdjustNationTotals(int resourceIndex, int delta,
                                                      int multiplier) override;
  // slot 0x23 — 0x004e7b50: proposal queue with alliance guards.
  void QueueDiplomacyProposalCodeForTargetNation(short proposalCode,
                                                  short targetNationId) override;
  // slot 0x25 — 0x004e7c50: policy side effects before slot 0x94 dispatch.
  void NotifyActionSlot94(int sourceNation, int actionCode) override;
  // slot 0x4d — 0x004ea470: rebuild yields and roll field 0x134 into 0x136.
  void RebuildNationResourceYieldCountersAndDevelopmentTargets(void) override;
  // slots 0x56/0x57 — 0x004e78d0/0x004e78f0: minister callbacks when city exists.
  void RunSlot4CThenSortTrackedOrders(void) override;
  void ResetField900FromNeedCapA6(void) override;
  // slot 0x5a — 0x004e7810: recompute aid budget and clear need matrix.
  void ResetDiplomacyNeedScoresAndClearAidAllocationMatrix(void) override;
  // slot 0x61 — 0x004e7990: foreign-minister slots 0x90/0x94.
  void ResetDiplomacyNeedSlots7012AndRefreshIfModeGateMatches(void) override;
  // slot 0x74 — 0x004e7b20: forward to base policy apply with cost checks.
  bool ApplyDiplomacyPolicyStateForTargetWithCostChecks(int arg1, int arg2) override;
  // slot 0x81 — 0x004e7be0: replay proposal rows then reset policy state.
  void ProcessPendingDiplomacyProposalQueue(void) override;
  // slot 0xa1 — 0x004e9ed0: war-transition propagation from advisory action.
  void ApplyDiplomacyRelationCodeAndNotifyThirdPartySlot284(int targetNationSlot, int policyCode,
                                                            int sourceNationSlot) override;
  // slot 0xa2 — 0x004e9a50: select and queue advisory map missions (case 16).
  void NoOpSlotA2(void) override;
  // slot 0xa4 — 0x004eb0d0: prune invalid missionQueue entries.
  void PruneInvalidTrackedEntriesAndNotifyOwner(void) override;
  // slots 0xad/0xae — 0x004eaa20/0x004eae70: AI turn tail hooks.
  void NoOpTailStateHookSlot2B4(void) override;
  void NoOpTailStateHookSlot2B8(int arg) override;
  // slot 0x36 — 0x004e7550: forward to slots 0x4d/0x4e when city exists.
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) override;
  // slot 0x67 — 0x004e7680: need assignment with capability caps / escalation roll.
  void AssignNeedSlotFromSourceSlot19C(short needSlot, short sourceNation) override;
  // slot 0x9f — 0x004e7cc0: war-transition propagation across eligible allied nations.
  int CheckTransitionSlot27C(int targetNation, int sourceNation) override;
  // slot 0xab — 0x004e7510: 'lost' game-state event when redraw is enabled.
  void DispatchTurnEvent11F8NoPayloadSlot2AC(void) override;
  // slot 0x18 — 0x004ea1c0: also drop the matching mission and map-node flag.
  void RemoveRegionIdFromNationOwnedRegionList(int regionId) override;
  // slot 0x22 — 0x004e79d0: forward to the foreign minister or queue a tracked entry.
  char TryDispatchNationActionViaUiContextOrFallback(int targetNation, int arg2, int arg3,
                                                     int slotIndex) override;
  // slot 0x38 — 0x004e7590: interior-minister slot 0x54 when city exists.
  void OrphanRetStub_004dcc30(void) override;
  // slot 0x71 — 0x004e7a50: flush actionMetricByQuarter into city stock.
  void ClearDiplomacyState1c6Block(void) override;
  // slot 0x72 — 0x004e7af0: foreign-minister slot 0x58 when city exists.
  void BeginTurnDiplomacyPrePassSlot1c8() override;
  // slot 0x83 — 0x004e9f10: prune candidateNationFlags; true while any stays active.
  char HasActiveCandidateNationSlots(void) override;
  // slot 0x84 — 0x004e9ff0: mark a candidate nation (and its port zone) active.
  void SetCandidateNationFlagAndPortZoneState(int targetNation) override;
  // slot 0x85 — 0x004ea0e0: clear a candidate nation (and its port zone).
  void NotifyAllianceSlot214(int targetNation) override;
  // slot 0xa0 — 0x004e7ec0: war-transition propagation for a nation pair.
  int PropagateWarTransitionSlot280(int targetNation, int sourceNation, int mode) override;
  // slot 0xaf — 0x004e6b10: pressure update stubbed out for AI nations.
  void UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  // slot 0x9d — 0x004e8040: alliance-aware strength evaluation against the strongest
  // peer; true when minister skill (slot 0x8a) clears the combined score.
  char ReturnZeroSlot9D(int targetNation) override;
  // slot 0xa7 — 0x004ea300: base reset plus marking every owned region / the port
  // zone of targetNation as action candidates.
  void ResetNationDiplomacySlotsAndMarkRelatedNations(int targetNation) override;
  // slots 0xb0/0xb1 — 0x004ea430/0x004ea450: no-op overrides for AI nations.
  void DispatchTurnOrderActionSlotB0(short orderKind, short payload, short flags) override;
  void BuildGreatPowerTurnMessageSummaryAndDispatch(void) override;

  // Quarterly / nation-state event stubs the AI nation leaves empty.
  // slots 0x3c/0x3d/0x3e — 0x004e7910/0x004e7930/0x004e7950.
  void DispatchGreatPowerQuarterlyStatusMessageLevel2() override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel1() override;
  void DispatchGreatPowerQuarterlyStatusMessageLevel0() override;
  // slot 0x6a — 0x004e7970: AI leaves the base 1c6→250 snapshot empty.
  void SnapshotDiplomacyState1c6Into250(void) override;
  // slot 0x80 — 0x004e7ca0.
  void DispatchTurnEvent2103WithNationFromRecord() override;
  // slots 0x2c8/0x2cc — base vtable NULL; TAutoGreatPower fills these entries.
  // slot 0xb2 — 0x004e75c0.
  virtual undefined OrphanCallChain_C4_I28_004e75c0(int needSlot);
  // slot 0xb3 — 0x004ea990.
  virtual undefined IterateLinkedListCursorAndRelinkNodeOwners_004ea990();

};


// === BEGIN GENERATED (TAutoGreatPower) — refreshed by `just gen-class TAutoGreatPower`; do not hand-edit ===
// clang-format off
// vtable @ 0x00654088 (180 slots), object size 0xb70, base TGreatPower
//   slot 0x00  byte 0x00  0x004e6b30  override  GetTAutoGreatPowerClassNamePointer
//   slot 0x01  byte 0x04  0x004e6b80  override  VTableSlot01
//   slot 0x02  byte 0x08  0x00485e90  inherited GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  inherited ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  inherited GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x004e73f0  override  WrapperFor_HandleCityDialogHintClusterUpdate_At004e73f0
//   slot 0x06  byte 0x18  0x004e72c0  override  InitializeMapActionCandidateStateAndQueueMission
//   slot 0x07  byte 0x1c  0x004e7230  override  ReleaseOwnedGreatPowerObjectsAndDeleteSelf
//   slot 0x08  byte 0x20  0x004798d0  inherited DeserializeCityProductionQueueCommand
//   slot 0x09  byte 0x24  0x00415ce0  inherited OrphanRetStub_0059add0
//   slot 0x0a  byte 0x28  0x004da500  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x0b  byte 0x2c  0x004da3e0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x0c  byte 0x30  0x004d71b0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x0d  byte 0x34  0x004d7770  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x0e  byte 0x38  0x004d7ae0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x0f  byte 0x3c  0x004d8000  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x10  byte 0x40  0x004d87b0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x11  byte 0x44  0x004d87e0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x12  byte 0x48  0x004dd040  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x13  byte 0x4c  0x004e21b0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x14  byte 0x50  0x004ea150  override  ApplyJoinEmpireResetAndClearDiplomacyCaches
//   slot 0x15  byte 0x54  0x004d7c90  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x16  byte 0x58  0x004d7d50  inherited ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x17  byte 0x5c  0x004d7d20  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x18  byte 0x60  0x004ea1c0  override  RemoveRegionIdAndRunTrackedObjectCleanup
//   slot 0x19  byte 0x64  0x004ea290  override  AddRegionToNationAndQueueMapActionMission
//   slot 0x1a  byte 0x68  0x004e2330  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x1b  byte 0x6c  0x004dda20  inherited OrphanRetStub_004d7e90
//   slot 0x1c  byte 0x70  0x004dda60  inherited OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x1d  byte 0x74  0x004d8c00  inherited OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x1e  byte 0x78  0x004dd740  inherited OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x1f  byte 0x7c  0x004ddb20  inherited OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x20  byte 0x80  0x004e7630  override  WrapperFor_TGreatPower_VtblSlot32_At004e7630
//   slot 0x21  byte 0x84  0x004ddd50  inherited OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x22  byte 0x88  0x004e79d0  override  OrphanCallChain_C3_I38_004e79d0
//   slot 0x23  byte 0x8c  0x004e7b50  override  QueueDiplomacyProposalCodeWithAllianceGuards
//   slot 0x24  byte 0x90  0x004d7f60  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x25  byte 0x94  0x004e7c50  override  ApplyImmediateDiplomacyPolicySideEffectsWithSelectionHook
//   slot 0x26  byte 0x98  0x004d6730  inherited ReturnFalseNationStateCapabilityFlag98
//   slot 0x27  byte 0x9c  0x004d6750  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x28  byte 0xa0  0x004d6770  inherited ReturnFalseNationStateCapabilityFlagA0
//   slot 0x29  byte 0xa4  0x004d6790  inherited NoOpNationSelectedRegionAndMapCellLabelHook
//   slot 0x2a  byte 0xa8  0x004da5c0  inherited NoOpNationPendingActionHook
//   slot 0x2b  byte 0xac  0x004da860  inherited PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x2c  byte 0xb0  0x004da8a0  inherited AdvanceNationPendingActionStateMachine
//   slot 0x2d  byte 0xb4  0x004da5e0  inherited DispatchNationPendingActionEventCodes
//   slot 0x2e  byte 0xb8  0x004daa10  inherited SetNationPendingActionStateAndPayload
//   slot 0x2f  byte 0xbc  0x004daa50  inherited QueueNationOrderManagerPayloadObject
//   slot 0x30  byte 0xc0  0x004daa80  inherited ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x31  byte 0xc4  0x004dab00  inherited NoOpNationQueuedOrderHook
//   slot 0x32  byte 0xc8  0x004dab20  inherited ExecuteNationPendingActionStateMachine
//   slot 0x33  byte 0xcc  0x004dae70  inherited HasQueuedCivWorkOrderType7
//   slot 0x34  byte 0xd0  0x004db7d0  inherited GetTCountryClassNamePointer
//   slot 0x35  byte 0xd4  0x004dbac0  inherited VTableSlot35
//   slot 0x36  byte 0xd8  0x004e7550  override  VTableIndex54_Provisional
//   slot 0x37  byte 0xdc  0x004dca60  inherited OrphanRetStub_0059add0
//   slot 0x38  byte 0xe0  0x004e7590  override  OrphanLeaf_NoCall_Ins07_004e7590
//   slot 0x39  byte 0xe4  0x004df810  inherited HandleCityDialogHintClusterUpdate
//   slot 0x3a  byte 0xe8  0x004dfa20  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x3b  byte 0xec  0x004dfae0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x3c  byte 0xf0  0x004e7910  override  OrphanRetStub_004e7910
//   slot 0x3d  byte 0xf4  0x004e7930  override  OrphanRetStub_004e7930
//   slot 0x3e  byte 0xf8  0x004e7950  override  OrphanRetStub_004e7950
//   slot 0x3f  byte 0xfc  0x004dca80  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x40  byte 0x100  0x004dcaa0  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x41  byte 0x104  0x004dcc50  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x42  byte 0x108  0x004dcca0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x43  byte 0x10c  0x004dcd10  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x44  byte 0x110  0x004dce10  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x45  byte 0x114  0x004dcdd0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x46  byte 0x118  0x004dce40  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x47  byte 0x11c  0x004dce70  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x48  byte 0x120  0x004dce90  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x49  byte 0x124  0x004dcf10  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x4a  byte 0x128  0x004dcf60  inherited ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x4b  byte 0x12c  0x004dcfd0  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x4c  byte 0x130  0x004e0220  inherited RemoveRegionIdFromNationOwnedRegionList
//   slot 0x4d  byte 0x134  0x004ea470  override  RebuildNationResourceYieldsAndRollField134Into136
//   slot 0x4e  byte 0x138  0x004dbf00  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x4f  byte 0x13c  0x004dc3f0  inherited OrphanRetStub_004d7e90
//   slot 0x50  byte 0x140  0x004dc440  inherited OrphanLeaf_NoCall_Ins02_004d7ee0
//   slot 0x51  byte 0x144  0x004dc4c0  inherited OrphanLeaf_NoCall_Ins02_004d7f00
//   slot 0x52  byte 0x148  0x004dc540  inherited OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x53  byte 0x14c  0x004dc660  inherited OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x54  byte 0x150  0x004dc840  inherited OrphanRetStub_004d7fa0
//   slot 0x55  byte 0x154  0x004e0290  inherited OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x56  byte 0x158  0x004e78d0  override  DispatchNationField98CallbackD4
//   slot 0x57  byte 0x15c  0x004e78f0  override  DispatchNationField9CCallback4C
//   slot 0x58  byte 0x160  0x004dd0c0  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x59  byte 0x164  0x004dd140  inherited OrphanRetStub_004d7f80
//   slot 0x5a  byte 0x168  0x004e7810  override  RecomputeDiplomacyAidBudgetAndResetNeedScoresAndMatrix
//   slot 0x5b  byte 0x16c  0x004dd270  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x5c  byte 0x170  0x004dd310  inherited ReturnFalseNationStateCapabilityFlagA0
//   slot 0x5d  byte 0x174  0x004dd340  inherited AddAmountToAidAllocationMatrixCellAndTotal
//   slot 0x5e  byte 0x178  0x004dd3b0  inherited SumAidAllocationMatrixColumnForTarget
//   slot 0x5f  byte 0x17c  0x004dd3f0  inherited PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x60  byte 0x180  0x004dd430  inherited AdvanceNationPendingActionStateMachine
//   slot 0x61  byte 0x184  0x004e7990  override  DispatchNationField94Callbacks90And94
//   slot 0x62  byte 0x188  0x004dd4e0  inherited SetNationPendingActionStateAndPayload
//   slot 0x63  byte 0x18c  0x004dd770  inherited QueueNationOrderManagerPayloadObject
//   slot 0x64  byte 0x190  0x004dd7b0  inherited ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x65  byte 0x194  0x004dd7f0  inherited OrphanCallChain_C1_I42_004dd7f0
//   slot 0x66  byte 0x198  0x004dda40  inherited ExecuteNationPendingActionStateMachine
//   slot 0x67  byte 0x19c  0x004e7680  override  AssignNeedSlotFromSourceSlot19C
//   slot 0x68  byte 0x1a0  0x004ddad0  inherited GetTCountryClassNamePointer
//   slot 0x69  byte 0x1a4  0x004ddb40  inherited VTableSlot69
//   slot 0x6a  byte 0x1a8  0x004e7970  override  OrphanRetStub_004e7970
//   slot 0x6b  byte 0x1ac  0x004ddd20  inherited OrphanRetStub_0059add0
//   slot 0x6c  byte 0x1b0  0x004ddd90  inherited GetTEventHandlerClassNamePointer
//   slot 0x6d  byte 0x1b4  0x004dde80  inherited HandleCityDialogHintClusterUpdate
//   slot 0x6e  byte 0x1b8  0x004dde30  inherited DeserializeRecruitScenarioAndInstantiateOrders
//   slot 0x6f  byte 0x1bc  0x004ddeb0  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x70  byte 0x1c0  0x004ddf20  inherited GetTEventHandlerClassNamePointer
//   slot 0x71  byte 0x1c4  0x004e7a50  override  ClearDiplomacyState1c6Block
//   slot 0x72  byte 0x1c8  0x004e7af0  override  OrphanLeaf_NoCall_Ins07_004e7af0
//   slot 0x73  byte 0x1cc  0x004de2d0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x74  byte 0x1d0  0x004e7b20  override  ForwardApplyDiplomacyPolicyStateForTargetWithCostChecks
//   slot 0x75  byte 0x1d4  0x004de340  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x76  byte 0x1d8  0x004de5e0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x77  byte 0x1dc  0x004de700  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x78  byte 0x1e0  0x004de7e0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0x79  byte 0x1e4  0x004deca0  inherited SelectCandidateTilesWithLowGroundUnitCount
//   slot 0x7a  byte 0x1e8  0x004de790  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0x7b  byte 0x1ec  0x004df010  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0x7c  byte 0x1f0  0x004df370  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0x7d  byte 0x1f4  0x004df4b0  inherited ApplyJoinEmpireMode1TargetTransition
//   slot 0x7e  byte 0x1f8  0x004df580  inherited ApplyJoinEmpireMode2FinalizeNationNameState
//   slot 0x7f  byte 0x1fc  0x004df5a0  inherited IsDiplomacyTargetClassCode200Match
//   slot 0x80  byte 0x200  0x004e7ca0  override  OrphanRetStub_004e7ca0
//   slot 0x81  byte 0x204  0x004e7be0  override  ReplayQueuedDiplomacyProposalRowsAndProcessQueue
//   slot 0x82  byte 0x208  0x004e2880  inherited SetNationPercentFieldByModeAndDescriptorLinks
//   slot 0x83  byte 0x20c  0x004e9f10  override  VTableSlot20C_Provisional
//   slot 0x84  byte 0x210  0x004e9ff0  override  VTableSlot84_Provisional
//   slot 0x85  byte 0x214  0x004ea0e0  override  NotifyAllianceSlot214
//   slot 0x86  byte 0x218  0x004e0500  inherited OrphanLeaf_NoCall_Ins02_004d7f20
//   slot 0x87  byte 0x21c  0x004e0550  inherited OrphanLeaf_NoCall_Ins02_004d7f40
//   slot 0x88  byte 0x220  0x004e0590  inherited OrphanRetStub_004d7fa0
//   slot 0x89  byte 0x224  0x004e05d0  inherited OrphanLeaf_NoCall_Ins02_004d7fc0
//   slot 0x8a  byte 0x228  0x004e0610  inherited ReturnFalseNationStateActionStub
//   slot 0x8b  byte 0x22c  0x004e0650  inherited OrphanRetStub_004d7fe0
//   slot 0x8c  byte 0x230  0x004e0690  inherited ReturnFalseNationStateCapabilityFlag90
//   slot 0x8d  byte 0x234  0x004e0740  inherited OrphanRetStub_004d7f80
//   slot 0x8e  byte 0x238  0x004e07b0  inherited ReturnFalseNationStateCapabilityFlag98
//   slot 0x8f  byte 0x23c  0x004e0890  inherited ReturnFalseNationStateCapabilityFlag9C
//   slot 0x90  byte 0x240  0x004e09a0  inherited ReturnFalseNationStateCapabilityFlagA0
//   slot 0x91  byte 0x244  0x004e0b20  inherited AddAmountToAidAllocationMatrixCellAndTotal
//   slot 0x92  byte 0x248  0x004e0c10  inherited SumAidAllocationMatrixColumnForTarget
//   slot 0x93  byte 0x24c  0x004e0d80  inherited PromoteNationPendingActionSlot5IfCapabilityActive
//   slot 0x94  byte 0x250  0x004e0e70  inherited AdvanceNationPendingActionStateMachine
//   slot 0x95  byte 0x254  0x004e0fe0  inherited DispatchNationPendingActionEventCodes
//   slot 0x96  byte 0x258  0x004e1170  inherited SetNationPendingActionStateAndPayload
//   slot 0x97  byte 0x25c  0x004e1300  inherited QueueNationOrderManagerPayloadObject
//   slot 0x98  byte 0x260  0x004e1490  inherited ClearQueuedNationOrdersAndResetOrderManager
//   slot 0x99  byte 0x264  0x004e1620  inherited OrphanCallChain_C1_I42_004dd7f0
//   slot 0x9a  byte 0x268  0x004e1750  inherited ExecuteNationPendingActionStateMachine
//   slot 0x9b  byte 0x26c  0x004e1910  inherited HasQueuedCivWorkOrderType7
//   slot 0x9c  byte 0x270  0x004e1a40  inherited GetTCountryClassNamePointer
//   slot 0x9d  byte 0x274  0x004e8040  override  ReturnZeroSlot9D
//   slot 0x9e  byte 0x278  0x004e1c20  inherited DispatchNationStateEventCode10
//   slot 0x9f  byte 0x27c  0x004e7cc0  override  CheckTransitionSlot27C
//   slot 0xa0  byte 0x280  0x004e7ec0  override  PropagateWarTransitionSlot280
//   slot 0xa1  byte 0x284  0x004e9ed0  override  QueueWarTransitionFromAdvisoryAction
//   slot 0xa2  byte 0x288  0x004e9a50  override  SelectAndQueueAdvisoryMapMissionsCase16
//   slot 0xa3  byte 0x28c  0x004e1f40  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0xa4  byte 0x290  0x004eb0d0  override  PruneInvalidTrackedEntriesAndNotifyOwner
//   slot 0xa5  byte 0x294  0x004de810  inherited VTableSlotA5
//   slot 0xa6  byte 0x298  0x004e2500  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xa7  byte 0x29c  0x004ea300  override  ResetNationDiplomacySlotsAndMarkRelatedNations
//   slot 0xa8  byte 0x2a0  0x004e2630  inherited OrphanLeaf_NoCall_Ins07_004d8920
//   slot 0xa9  byte 0x2a4  0x004e2720  inherited ApplyJoinEmpireModeForTargetNation
//   slot 0xaa  byte 0x2a8  0x004e27b0  inherited SetNationTransferTargetCodeAndNotifyEligiblePeers
//   slot 0xab  byte 0x2ac  0x004e7510  override  DispatchTurnEvent11F8NoPayloadSlot2AC
//   slot 0xac  byte 0x2b0  0x004e06d0  inherited OrphanLeaf_NoCall_Ins06_004d87b0
//   slot 0xad  byte 0x2b4  0x004eaa20  override  RecomputeNationTerrainCompatibilityAndDiplomacyMetrics
//   slot 0xae  byte 0x2b8  0x004eae70  override  RefreshTrackedEntriesAndReplanAiDevelopment
//   slot 0xaf  byte 0x2bc  0x004e6b10  override  CreateTAutoGreatPowerInstance
//   slot 0xb0  byte 0x2c0  0x004ea430  override  DispatchTurnOrderActionSlotB0
//   slot 0xb1  byte 0x2c4  0x004ea450  override  VTableIndex177_Provisional
//   slot 0xb2  byte 0x2c8  0x004e75c0  new       OrphanCallChain_C4_I28_004e75c0
//   slot 0xb3  byte 0x2cc  0x004ea990  new       IterateLinkedListCursorAndRelinkNodeOwners_004ea990
// object size 0xb70 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TAutoGreatPower) ===
