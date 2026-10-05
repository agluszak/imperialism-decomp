#pragma once

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
  // slot 0x13 (0x0052f4f0) — counters1e[index] += delta.
  virtual void PleaseBuy(short index, short delta);
  // slot 0x14 (0x0052f520) — set capability flag 0x14.
  virtual void PriceCheck();
  // slot 0x15 (0x0052f540) — store primary/secondary targets at 0x10/0x12.
  virtual void SetInteriorMinisterBid(short primary, short secondary);

  // slot 0x16 (0x0052fd10) — refresh minister sub-state gated on the sim-mode getter.
  virtual void SetDiplomacyPolicies();
  virtual void DoDevelopmentGrants();
  virtual void DoFirstTurnDiplomacy();
  virtual void DoSecondTurnDiplomacy();
  virtual void GoodsMatchShipping();
  virtual void SetEmpirePolicies();
  // slot 0x1c (body 0x005308b0) — difficulty-indexed army/navy score-threshold predicate.
  virtual char DeservesToBeEnemy(int nationCode);
  virtual void DoSelectEnemy();
  // slot 0x1e (0x00530200) — proposes treaty/policy actions from ranked relationships.
  virtual void DoProposeTreaties();
  // slot 0x1f (0x00530fa0) — validate a queued proposal row and dispatch accept/queue.
  virtual void ReplyToDiplomacyOffers(short queueIndex);
  virtual void FinishDiplomacyPhase();
  virtual void SetBuyPriorities();
  virtual int WeNeedMoney();
  virtual void ArrangeMaterialsOffers();
  virtual void SetTradeBids();
  virtual void DoUsualSubsidyRule();
  virtual void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode);
  virtual void EndTradePhase();

  short interiorBidResource10;              // +0x10 — SetInteriorMinisterBid resource code
  short interiorBidAmount;                  // +0x12 — SetInteriorMinisterBid amount
  short capabilityFlag14;                   // +0x14
  short capabilityFlag16;                   // +0x16
  short diplomacyPhaseCounter;              // +0x18 — reset after SetTradeBids
  short tradeBidRefreshInterval;            // +0x1a — turns before forced trade-bid refresh
  short interiorOrderKind1c;                // +0x1c — passed to TInteriorMinister slot 0x1a
  short purchasePriorityByResource1e[0x11]; // +0x1e..0x3f — per-resource demand
  short preferredResourceSlots[4];          // +0x40..0x47 — top four resource codes

  unsigned char field48;                  // +0x48 — cleared by the constructor
  unsigned char tradePartnerEnabled49[7]; // +0x49..0x4f — per-major-nation trade status
  short developmentGrantByNation[0x17];   // +0x50..0x7d — serialized grant accumulation
  unsigned char pad7e[2];
};

ASSERT_SIZE(TForeignMinister, 0x80);
