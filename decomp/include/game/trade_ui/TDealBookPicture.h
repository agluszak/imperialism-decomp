#pragma once

#include "compat.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TPicture.h"
#include "game/mfc.h"

class TTradePageBuyView;
class TTradePageSellView;

// VTABLE: IMPERIALISM 0x0066dfc0
class TDealBookPicture : public TPicture {
public:
  DECLARE_DYNCREATE(TDealBookPicture)
  virtual ~TDealBookPicture() override; // slot 0x01 (scalar deleting destructor)
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler,
                       TEvent* event) override; // slot 0x0f 0x005bbc30
  virtual void ShowPage(int pageIndex, short nationId); // slot 0x73 0x5baf70
  virtual void CalculatePages();                        // slot 0x74 0x5bb2e0
  short selectedNationSlot; // +0x90 initialized to 8; indexes g_apNationStates in CalculatePages
  // +0x92 -- last page needed by either page list: max(page counts) - 1.
  short lastPageIndex;
  short currentPageIndex;     // +0x94 -- selected zero-based page, written by ShowPage
  unsigned char padding96[2]; // +0x96..0x97
  TTradePageBuyView* boughtTradesView;
  TTradePageSellView* soldTradesView;
  TTradePageBuyView* buyPageView;   // +0xa0, tag 'tbou'
  TTradePageSellView* sellPageView; // +0xa4, tag 'tsol'
  TTradePageSellView* cachedSellPageView;
  TTradePageBuyView* cachedBuyPageView;
  bool tradeListEmpty; // +0xb0 -- CalculatePages starts true and clears it when a row exists
  bool alternatePageMode;
  unsigned char deadByteB2;
  unsigned char paddingB3; // +0xb3

  TDealBookPicture();
  void SwitchPages();
  void Startup(short startupValue);
};

ASSERT_SIZE(TDealBookPicture, 0xb4);
