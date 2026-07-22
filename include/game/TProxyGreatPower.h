#pragma once

#include "game/TGreatPower.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0065b078
class TProxyGreatPower : public TGreatPower {
public:
  DECLARE_DYNCREATE(TProxyGreatPower)
  virtual ~TProxyGreatPower() override;            // slot 0x01 (scalar deleting destructor)
  virtual void AddToTreasury(int amount) override; // slot 0x0e 0x540a00
  void SetTradePolicyTo(NationSlot nationSlot,
                        short tradePolicy) override; // slot 0x12 0x540c20
  char TryDispatchNationActionViaUiContextOrFallback(int arg1, int arg2, int arg3,
                                                     int arg4) override; // slot 0x22 0x540ba0
  void QueueDiplomacyProposalCodeForTargetNation(
      ProposalCode proposalCode,
      NationSlot targetNationSlot) override;               // slot 0x23 0x540ac0
  virtual bool IsClient() override;                        // slot 0x26 0x5408c0
  bool IsRemote(void) override;                            // slot 0x28 0x5408e0
  void AddTurnStartEvent(TTurnStartEvent* event) override; // slot 0x2f 0x540c70
  virtual void
  RefreshGreatPowerRelationPanelsAndDispatchDeltaSummary() override;           // slot 0x36 0x540b80
  virtual void DispatchTurnEvent2103WithNationFromRecord() override;           // slot 0x80 0x540aa0
  virtual void ReplyToDiplomacyOffers() override;                              // slot 0x81 0x540900
  int HandleWarTransitionRequest(int targetNation, int sourceNation) override; // slot 0x9f 0x540cf0
  int HandleWarTransitionRequestWithRoleSwap(int targetNation, int sourceNation,
                                             char swapRoles) override; // slot 0xa0 0x540dc0
  virtual void SorryYouLose() override;                                // slot 0xab 0x540cb0
  virtual char
  UpdateGreatPowerPressureStateAndDispatchEscalationMessage() override; // slot 0xaf 0x540920

  TProxyGreatPower() : TGreatPower() {}
};
