#pragma once

#include "compat.h"

#include "game/nation/TGreatPower.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065b078
class TProxyGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TProxyGreatPower)
  virtual ~TProxyGreatPower() override;
  virtual void AddToTreasury(int amount) override;
  void SetTradePolicyTo(NationSlot nationSlot, short tradePolicy) override;
  bool ReplyToTradeOffer(NationSlot targetNationSlot, short amount, short price,
                         ResourceKindStorage resourceKind) override;
  void AddOfferFrom(NationSlot sourceNationSlot,
                    DiplomacyProposalCodeStorage proposalCode) override;
  virtual bool IsClient() const override;
  bool IsRemote(void) const override;
  void AddTurnStartEvent(TTurnStartEvent* event) override;
  virtual void FinishCityPhase() override;
  virtual void ShowNewspaperForRecordNation() override;
  virtual void ReplyToDiplomacyOffers() override;
  int ConsiderWarOfIntervention(int targetNation, int sourceNation) override;
  int ConsiderWarOfAlliance(int targetNation, int sourceNation, char swapRoles) override;
  virtual void SorryYouLose() override;
  virtual bool UpdateGreatPowerPressureStateAndDispatchEscalationMessage() override;

  TProxyGreatPower() : TGreatPower() {}
};
ASSERT_SIZE(TProxyGreatPower, 0x964);
