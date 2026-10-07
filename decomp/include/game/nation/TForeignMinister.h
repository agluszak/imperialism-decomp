#pragma once

#include "game/nation_domain_types.h"
#include "game/map/TMinister.h"

class TGreatPower;
class TStream;
class TCity;

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  // FUNCTION: IMPERIALISM 0x0052f110
  ~TForeignMinister() override {}
  TForeignMinister();
  void IForeignMinister(TGreatPower* owner);

  DECLARE_DYNCREATE(TForeignMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short GetRankingCriterionForGP(short nationSlot) override;
  virtual void InitializeTradeStatus();
  virtual void PleaseBuy(short index, short delta);
  virtual void PriceCheck();
  virtual void SetInteriorMinisterBid(short primary, short secondary);

  virtual void SetDiplomacyPolicies();
  virtual void DoDevelopmentGrants();
  virtual void DoFirstTurnDiplomacy();
  virtual void DoSecondTurnDiplomacy();
  virtual void GoodsMatchShipping();
  virtual void SetEmpirePolicies();
  virtual bool DeservesToBeEnemy(int nationCode);
  virtual void DoSelectEnemy();
  virtual void DoProposeTreaties();
  virtual void ReplyToDiplomacyOffers(short queueIndex);
  virtual void FinishDiplomacyPhase();
  virtual void SetBuyPriorities();
  virtual int WeNeedMoney();
  virtual void ArrangeMaterialsOffers();
  virtual void SetTradeBids();
  virtual void DoUsualSubsidyRule();
  virtual void ReplyToTradeOffer(short targetNation, short amount, short maximumAmount,
                                 short resourceCode);
  virtual void EndTradePhase();

  short interiorBidResource;              // +0x10 — SetInteriorMinisterBid resource code
  short interiorBidAmount;                // +0x12 — SetInteriorMinisterBid amount
  short priceCheckPending;                // +0x14
  short specialOfferQuota;                // +0x16
  short diplomacyPhaseCounter;            // +0x18 — reset after SetTradeBids
  short tradeBidRefreshInterval;          // +0x1a — turns before forced trade-bid refresh
  short interiorOrderKind;                // +0x1c — passed to TInteriorMinister slot 0x1a
  short purchasePriorityByResource[0x11]; // +0x1e..0x3f — per-resource demand
  short preferredResourceSlots[4];        // +0x40..0x47 — top four resource codes

  unsigned char field48;                            // +0x48 — cleared by the constructor
  unsigned char tradePartnerEnabled[7];             // +0x49..0x4f — per-major-nation trade status
  short developmentGrantByNation[kNationSlotCount]; // +0x50..0x7d — serialized grant accumulation
  unsigned char pad7e[2];
};

ASSERT_SIZE(TForeignMinister, 0x80);
