#pragma once

#include "decomp_types.h"
#include "game/app/TObject.h"
#include "game/mfc.h"
#include "game/resource_domain_types.h"
#include "game/ui_widgets/TradeDealEntry.h"

class TStream;
#include "game/nation_domain_types.h"

class TDealList;
class TLongintList;

// VTABLE: IMPERIALISM 0x0066d990
class TTradeMgr : public TObject {
public:
  DECLARE_DYNCREATE(TTradeMgr)
  virtual ~TTradeMgr() override;
  void WriteTo(TStream* stream) override;
  void ReadFrom(TStream* stream) override;
  void Free() override;

  virtual void ResetTradeRows();
  virtual void CalculateDealOrder();
  virtual void CalculateNewWorldPrices();
  virtual void CalculateNewItemPrice(short item);
  virtual double GetAdjNumOffers(short item);
  virtual short GetAmtOffered(short item);
  virtual int GetDealPrice(short sourceSlot, short targetSlot, short scoreA, short scoreB);
  virtual short GetNumOffers(short item);
  virtual short GetNumRequests(short item);
  virtual short GetPrice(short item);
  virtual short GetBasePrice(short item);
  virtual void OfferItemDeals(short item);
  virtual void StartDeals();
  virtual void OfferTradeDeals();
  // ORACLE: Mac SetDealResults takes five shorts and two unsigned chars.
  virtual void SetDealResults(NationSlot sourceNation, NationSlot targetNation, short amount,
                              short maximumAmount, ResourceKindStorage commodityType,
                              unsigned char shortfallFlag, bool remoteReplay);
  virtual void UpdatePrice(short item, short value);
  virtual void StartTradePhase();
  virtual void SetMinorsTradeBids();
  virtual void TallyMinorsTradeBids();
  virtual void TallyTradeBids();
  virtual bool DidBidOn(int item, int nationSlot);
  virtual bool DidOffer(int item, int nationSlot);
  virtual TLongintList* GetBidderList(int item, int nationSlot);
  virtual short WhoTradesFirst(short proposalCode, short category);
  virtual double Power(double base, short exponent);

  TTradeMgr();
  void ITradeMgr();
  void NextTradeDeal();
  // Clamps each category row's turn history to the running max; the scan deliberately runs
  // past the logical row into the next one.
  void EndTradeOffers();
  int GetMarketChange();

#pragma pack(push, 4)
  struct NationMetricCategoryRow {
    short dealCategoryOrderIndex;
    short dealEntryOrdinal;
    short previousPrice;
    short price;
    short numRequests;
    short numOffers;
    double adjustedNumOffers;
    short amountOffered;
    short basePrice;
    short tradeOfferCells[(0xa0 - 0x18) / 2];
  };
#pragma pack(pop)

  NationMetricCategoryRow categoryRows[17];
  unsigned char paddingAA4[0xaa8 - 0xaa4];
  TDealList* categoryRankLists[17]; // .. 0xaeb
  unsigned char paddingAEC[0xaf0 - 0xaec];
};

ASSERT_SIZE(TTradeMgr::NationMetricCategoryRow, 0xa0);
ASSERT_SIZE(TTradeMgr, 0xaf0);
