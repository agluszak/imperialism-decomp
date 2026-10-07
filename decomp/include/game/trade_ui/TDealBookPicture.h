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
  virtual ~TDealBookPicture() override;
  virtual void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  virtual void ShowPage(int pageIndex, short nationId);
  virtual void CalculatePages();
  short selectedNationSlot; // +0x90 initialized to 8; indexes g_apNationStates in CalculatePages
  // +0x92 -- last page needed by either page list: max(page counts) - 1.
  short lastPageIndex;
  short currentPageIndex; // selected zero-based page, written by ShowPage
  unsigned char padding96[2];
  TTradePageBuyView* boughtTradesView;
  TTradePageSellView* soldTradesView;
  TTradePageBuyView* buyPageView;   // tag 'tbou'
  TTradePageSellView* sellPageView; // tag 'tsol'
  TTradePageSellView* cachedSellPageView;
  TTradePageBuyView* cachedBuyPageView;
  bool tradeListEmpty; // CalculatePages starts true and clears it when a row exists
  bool alternatePageMode;
  unsigned char deadByteB2;

  TDealBookPicture();
  void SwitchPages();
  void Startup(short startupValue);
};

ASSERT_SIZE(TDealBookPicture, 0xb4);
