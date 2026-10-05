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
  virtual ~TTradeMgr() override;           // slot 0x01 (scalar deleting destructor, 0x5b7a40)
  void WriteTo(TStream* stream) override;  // slot 0x05 0x5b7d90
  void ReadFrom(TStream* stream) override; // slot 0x06 0x5b7c10
  void Free() override;                    // slot 0x07 0x5b7bc0

  virtual void ResetNationMetricRowsAndClearCategoryRankLists(); // 0x0a 0x5b7fc0
  // ORACLE: Mac TTradeMgr names for the recovered Windows trade-price/deal operations.
  virtual void CalculateDealOrder();              // 0x0b 0x5b8080
  virtual void CalculateNewWorldPrices();         // 0x0c 0x5b8aa0
  virtual void CalculateNewItemPrice(short item); // 0x0d 0x5b8ad0
  virtual double GetAdjNumOffers(short item);     // 0x0e 0x5b8d40
  virtual short GetAmtOffered(short item);        // 0x0f 0x5b8d70
  virtual int GetDealPrice(short sourceSlot, short targetSlot, short scoreA,
                           short scoreB);   // 0x10 0x5b8da0
  virtual short GetNumOffers(short item);   // 0x11 0x5b8f80
  virtual short GetNumRequests(short item); // 0x12 0x5b8fb0
  virtual short GetPrice(short item);       // 0x13 0x5b8fe0
  virtual short GetBasePrice(short item);   // 0x14 0x5b9030
  virtual void OfferItemDeals(short item);  // 0x15 0x5b9060
  virtual void StartDeals();                // 0x16 0x5b9190
  virtual void OfferTradeDeals();           // 0x17 0x5b9410
  // ORACLE: Mac names this SetDealResults and declares five shorts plus two unsigned chars.
  virtual void SetDealResults(NationSlot sourceNation, NationSlot targetNation, short amount,
                              short maximumAmount, ResourceKindStorage commodityType,
                              unsigned char shortfallFlag,
                              bool remoteReplay);                   // 0x18 0x5b94d0
  virtual void UpdatePrice(short item, short value);                // 0x19 0x5b9790
  virtual void RunNationUpdatePassesAndResetTransitionFlags();      // 0x1a 0x5b97c0
  virtual void SetMinorsTradeBids();                                // 0x1b 0x5b9890
  virtual void TallyMinorsTradeBids();                              // 0x1c 0x5b9b30
  virtual void TallyTradeBids();                                    // 0x1d 0x5b98d0
  virtual char DidBidOn(int item, int nationSlot);                  // 0x1e 0x5b9f70
  virtual char DidOffer(int item, int nationSlot);                  // 0x1f 0x5b9fa0
  virtual TLongintList* GetBidderList(int item, int nationSlot);    // 0x20 0x5b9fd0
  virtual short WhoTradesFirst(short proposalCode, short category); // 0x21 0x5ba090
  // Mac oracle: Power(double, short).
  virtual double Power(double base, short exponent); // 0x22 0x5b9f30

  TTradeMgr();
  // ORACLE: Mac TTradeMgr::ITradeMgr().
  void ITradeMgr();
  // Non-virtual impl invoked by the slot-0x16 wrapper.
  // ORACLE: Mac TTradeMgr::NextTradeDeal().
  void NextTradeDeal(); // 0x5b91e0
  // Clears every live TGreatPower's trade offers, clamps each category row's
  // tradeOfferCells turn-history cells to the running max seen 23 cells earlier (the scan
  // deliberately runs past the logical sub-row into the next contiguous row), then advances
  // the host turn event or local simulation phase.
  // ORACLE: Mac TTradeMgr::EndTradeOffers().
  void EndTradeOffers(); // 0x5b9370
  // Average, across all 17 category rows, of (price - previousPrice).
  // Called from TNewspaperView::StuffValues
  // (0x55d200) while building the advisor-dialog inter-nation event summary rows.
  // ORACLE: Mac TTradeMgr::GetMarketChange().
  int GetMarketChange(); // 0x5ba0e0

#pragma pack(push, 4)
  struct NationMetricCategoryRow {
    short dealCategoryOrderIndex; // struct 0x00
    short dealEntryOrdinal;       // struct 0x02
    short previousPrice;          // struct 0x04
    short price;                  // struct 0x06
    short numRequests;            // struct 0x08
    short numOffers;              // struct 0x0a
    double adjustedNumOffers;     // struct 0x0c
    short amountOffered;          // struct 0x14
    short basePrice;              // struct 0x16
    short tradeOfferCells[(0xa0 - 0x18) / 2]; // struct 0x18..0x9f
  };
#pragma pack(pop)

  NationMetricCategoryRow categoryRows[0x11]; // 0x04 .. 0xaa3
  unsigned char paddingAA4[0xaa8 - 0xaa4];    // 0xaa4 .. 0xaa7
  TDealList* categoryRankLists[0x11];         // 0xaa8 .. 0xaeb (TDealList: vtable 0x66da38)
  unsigned char paddingAEC[0xaf0 - 0xaec];    // 0xaec .. 0xaef
};

ASSERT_SIZE(TTradeMgr::NationMetricCategoryRow, 0xa0);
ASSERT_SIZE(TTradeMgr, 0xaf0);
