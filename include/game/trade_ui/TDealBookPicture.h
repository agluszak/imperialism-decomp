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
  // Mac name oracle: ShowPage(short, short). The Windows body reads the first argument as
  // a dword and the second as a word, so the recovered Windows signature remains (int, short).
  virtual void ShowPage(int pageIndex, short nationId); // slot 0x73 0x5baf70
  virtual void CalculatePages();                        // slot 0x74 0x5bb2e0
  // TPicture's slice ends at 0x90; RTTI oracle confirms sizeof(TDealBookPicture) == 0xb4.
  // The ctor (0x5babc0) writes selectedNationSlot (= 8) and unresolvedByteB2 (= 0); the intervening region and
  // the 0xb3 byte are unconfirmed padding. Fields 0x92-0xb1 (formerly a pad92[0x20] blob)
  // recovered from SwitchPages (0x5bc0d0).
  short selectedNationSlot; // +0x90 initialized to 8; indexes g_apNationStates in CalculatePages
  // +0x92 -- last page needed by either page list: max(page counts) - 1.
  short lastPageIndex;
  short currentPageIndex;     // +0x94 -- selected zero-based page, written by ShowPage
  unsigned char padding96[2]; // +0x96..0x97
  // +0x98/+0x9c -- 'boug'/'sold' controls. Startup copies them into the typed page slots
  // at +0xac/+0xa8, proving their concrete page-view types on Windows.
  TTradePageBuyView* boughtTradesView;
  TTradePageSellView* soldTradesView;
  TTradePageBuyView* buyPageView;   // +0xa0, tag 'tbou'
  TTradePageSellView* sellPageView; // +0xa4, tag 'tsol'
  // +0xa8/+0xac -- re-cached sell/buy page pointers set at the end of SwitchPages right
  // after the four Locate calls. lastPageIndex is computed from these copies.
  TTradePageSellView* cachedSellPageView;
  TTradePageBuyView* cachedBuyPageView;
  bool tradeListEmpty; // +0xb0 -- CalculatePages starts true and clears it when a row exists
  // +0xb1 -- "already initialized" flag; flipped (via `!=0`) at the end of
  // SwitchPages each time it runs.
  bool alternatePageMode;
  // +0xb2 has only the constructor's zero byte write so far; its meaning remains unresolved.
  unsigned char unresolvedByteB2;
  unsigned char paddingB3; // +0xb3

  TDealBookPicture();
  // 0x5bc0d0 -- on first call (alternatePageMode == false), sets the 'mark' state, builds the
  // "<season> <year>" header text for 'rtil' and loads the tab-strip's shared message.
  // On subsequent calls, resets both trade pages to their unselected state (-1), refreshes
  // 'titL'/'rtil"'s labels from the string table, resets 'mark', and reloads the tab strip.
  // Either way, ends by capturing 4 subviews' layouts, re-caching the sell view pointer,
  // recomputing lastPageIndex from the smaller page count, reapplying the
  // dialog's own picture resource, and flipping the "already initialized" flag.
  void SwitchPages();
  // 0x5bac50 -- re-caches the six commodity sub-controls (guob/dlos/uobt/lost) into
  // boughtTradesView..cachedBuyPageView, resets the 'mark'/'tabs' labels and the page-mode flag, refreshes
  // the nation title ('loot'), reapplies this dialog's slot-0x73 theme, plays the refresh
  // sfx, and rebuilds the 'titL'/'rtil' title/subtitle labels + 'rocl'/'rocr' buttons.
  // (Ghidra mis-attributed this to TControl; it is contiguous with this class's methods
  // and uses its exact field layout + slot 0x73.)
  void Startup(short startupValue);
};

ASSERT_SIZE(TDealBookPicture, 0xb4);
