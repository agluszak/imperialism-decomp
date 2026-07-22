#pragma once

#include "game/TMinister.h"

class TGreatPower;
class TStream;
class TCity;

// VTABLE: IMPERIALISM 0x00659cb0
class TForeignMinister : public TMinister {
public:
  TForeignMinister();
  void InitializeStateAndCounters(TGreatPower* owner);

  DECLARE_DYNCREATE(TForeignMinister)
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  short GetRankingCriterionForGP(short nationSlot) override;
  // slot 0x12 (body 0x0052f4b0) — seed the foreign-minister state bytes (0x49-0x4f)
  // and capability flags; sets flag 0x14 when the owner's treasury is negative.
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
  // slot 0x1a (0x0052fdc0) — set per-nation interaction enable flags from a terrain
  // class-200 scan and relation-standing threshold. void (ret 0); SetTradeBids pushes an
  // ignored short at its call site.
  virtual void GoodsMatchShipping();
  virtual void SetEmpirePolicies();
  // slot 0x1c (body 0x005308b0) — difficulty-indexed army/navy score-threshold predicate.
  virtual char DeservesToBeEnemy(int nationCode);
  // slot 0x1d (body 0x00530b30) — mark the first eligible nation as an action
  // candidate, but only while no candidate is active yet.
  virtual void DoSelectEnemy();
  // slot 0x1e (0x00530200) — proposes treaty/policy actions from ranked relationships.
  virtual void DoProposeTreaties();
  // slot 0x1f (0x00530fa0) — validate a queued proposal row and dispatch accept/queue.
  virtual void ReplyToDiplomacyOffers(short queueIndex);
  virtual void FinishDiplomacyPhase();
  virtual void SetBuyPriorities();
  // slot 0x22 (0x0052f730) — true if any diplomacy option (0xd/0xe/0xf) meets the
  // owner's trade-capacity threshold.
  virtual int WeNeedMoney();
  virtual void ArrangeMaterialsOffers();
  virtual void SetTradeBids();
  virtual void DoUsualSubsidyRule();
  virtual void ReplyToTradeOffer(short arg1, short arg2, short arg3, short resourceCode);
  virtual void EndTradePhase();

  // Own fields at +0x10..+0x48 (moved from TMinister -- RTTI m_nObjectSize proves this
  // block is TForeignMinister-only, not shared base state; see TMinister.h).
  short interiorBidResource10;              // +0x10 — SetInteriorMinisterBid resource code
  short interiorBidAmount12;                // +0x12 — SetInteriorMinisterBid amount
  short capabilityFlag14;                   // +0x14
  short capabilityFlag16;                   // +0x16
  short diplomacyPhaseCounter18;            // +0x18 — reset after SetTradeBids
  short field1a;                            // +0x1a — ctor seeds 5 (0x52f070)
  short field1c;                            // +0x1c — ctor seeds 2 (0x52f070)
  short purchasePriorityByResource1e[0x11]; // +0x1e..0x3f — per-resource demand
  short preferredResourceSlots40[4];        // +0x40..0x47 — top four resource codes

  unsigned char field48;                  // +0x48 — cleared by the constructor
  unsigned char tradePartnerEnabled49[7]; // +0x49..0x4f — per-major-nation trade status
  short developmentGrantByNation50[0x17]; // +0x50..0x7d — serialized grant accumulation
  unsigned char pad7e[2];
};

ASSERT_SIZE(TForeignMinister, 0x80);
