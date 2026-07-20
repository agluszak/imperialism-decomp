#pragma once

#include "game/TGreatPower.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065ba80
class TRemoteGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TRemoteGreatPower)
  ~TRemoteGreatPower() override;

  char ShouldDispatchImmediatelySlot28(void) override;
  void NoOpNationSelectedRegionAndMapCellLabelHook(int arg1, int arg2) override;
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) override;
  void NotifyCitySlot2C(void) override;
  void OrphanRetStub_004dcc30(void) override;
  void SortTrackedOrdersByTypePriority(void) override;
  void ClearDiplomacyState1c6ForTarget(short targetSlot) override;
  void ClearDiplomacyState1c6Block(void) override;
  void BeginTurnDiplomacyPrePassSlot1c8(void) override;
  void ApplyTurnDiplomacyStateSlot1e0(void) override;
  void ResetNationDiplomacyProposalQueue(void) override;
  void ReleaseProposalQueueSlot7F(void) override;
  void ProcessPendingDiplomacyProposalQueue(void) override;
  void SetCandidateNationFlagAndPortZoneState(int targetNation) override;
  void CallSlotA8(int targetNation) override;
  void DispatchTurnEvent11F8NoPayloadSlot2AC(void) override;
  void RecomputeAiExpansionAndMissionPressureScores(void) override;
  void RefreshTrackedEntriesAndReplanAiDevelopment(int unused) override;
  char UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  virtual void OrphanRetStub_005418e0(void);

  TRemoteGreatPower();
};
