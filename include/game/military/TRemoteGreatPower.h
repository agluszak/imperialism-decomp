#pragma once

#include "compat.h"

#include "game/nation/TGreatPower.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065ba80
class TRemoteGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TRemoteGreatPower)
  ~TRemoteGreatPower() override;

  bool IsRemote(void) const override;
  void PlopDownCity(short selectedRegion, const char* mapCellLabel) override;
  void RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary(void) override;
  void CalculatePotentials(void) override;
  void FillInteriorMinisterOrders(void) override;
  void SortTrackedOrdersByTypePriority(void) override;
  void ClearTradeOfferForResource(short targetSlot) override;
  void ClearTradeOffers(void) override;
  void SetDiplomacyPolicies(void) override;
  void FinishDiplomacyPhase(void) override;
  void InitializeDiplomacyOffers(void) override;
  void InitializeDiplomacyNotices(void) override;
  void ReplyToDiplomacyOffers(void) override;
  void SetEnemy(int targetNation) override;
  void DeclareWarOnTargetForAlignedMinors(int targetNation) override;
  void SorryYouLose(void) override;
  void RecomputeAiExpansionAndMissionPressureScores(void) override;
  void RefreshTrackedEntriesAndReplanAiDevelopment(int unused) override;
  char UpdateGreatPowerPressureStateAndDispatchEscalationMessage(void) override;
  // Remote-only vtable slot 0x2c8; Mac symbol oracle: DoMovePhase().
  virtual void DoMovePhase(void);

  TRemoteGreatPower() : TGreatPower() {}
};
ASSERT_SIZE(TRemoteGreatPower, 0x964);
