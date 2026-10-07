#include "game/trade_ui/TDealBookPicture.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include "game/trade_ui/TCommodityLine.h"
#include "game/trade_ui/TDealLine.h"
#include "game/trade_ui/TDealTabControl.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TPageView.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TTextLine.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TToolBarCluster.h"
#include "game/trade_ui/TTradePageBuyView.h"
#include "game/trade_ui/TTradePageSellView.h"
#include "game/trade_ui/TTradeTotalsLine.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TDealBookPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005babc0
TDealBookPicture::TDealBookPicture() : TPicture(), selectedNationSlot(8), deadByteB2(0) {}

// FUNCTION: IMPERIALISM 0x005bac30
TDealBookPicture::~TDealBookPicture() {}

// FUNCTION: IMPERIALISM 0x005bac50
void TDealBookPicture::Startup(short startupValue) {
  TToolBarCluster* toolControl = static_cast<TToolBarCluster*>(FindSubView(kControlTagTool));
  toolControl->AssertValid();
  toolControl->AddInfoBehaviors();
  toolControl->SetReadouts(g_pSimMgr->GetPlayerCountry());
  toolControl->RefreshControl();

  // Re-cache the six commodity sub-controls.
  boughtTradesView = static_cast<TTradePageBuyView*>(FindSubView(kControlTagBoug)); // 'boug'
  soldTradesView = static_cast<TTradePageSellView*>(FindSubView(kControlTagSold));  // 'sold'
  buyPageView = static_cast<TTradePageBuyView*>(FindSubView(kControlTagTbou));      // 'tbou'
  sellPageView = static_cast<TTradePageSellView*>(FindSubView(kControlTagTsol));    // 'tsol'
  cachedBuyPageView = boughtTradesView;
  cachedSellPageView = soldTradesView;

  // 'mark' toggle + label reload.
  TView* markControl = FindSubView(kControlTagMark); // 'mark'
  if (markControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x129);
  }
  markControl->ViewEnable(1, 0);
  SetControlString(0x2741, 6, FindSubView(kControlTagMark));
  markControl->ViewEnable(0, 0);
  TView* tabsControl = FindSubView(kControlTagTabs);
  SetControlString(0x2741, 7, tabsControl);

  alternatePageMode = false;
  ShowPage(0, startupValue);
  g_pSfxPlaybackSystem->PlaySoundEffect(0x13ee, 0, 1);

  // 'titL' title label.
  TStaticText* titLControl = static_cast<TStaticText*>(FindSubView(kControlTagTitL));
  titLControl->AssertValid();
  titLControl->SetTextWithStrListID(0x2740, 0x19, false);
  CRect titLBounds;
  titLControl->GetFrame(&titLBounds);
  RECT titLInval;
  CopyRect(&titLInval, &titLBounds);
  InvalidateCityDialogRectRegion(&titLInval, 1);

  // 'rtil' subtitle label.
  TDropShadowText* rtilControl = static_cast<TDropShadowText*>(FindSubView(kControlTagRtil));
  rtilControl->AssertValid();
  rtilControl->SetTextWithStrListID(0x2740, 0x1a, false);
  CRect rtilBounds;
  rtilControl->GetFrame(&rtilBounds);
  RECT rtilInval;
  CopyRect(&rtilInval, &rtilBounds);
  InvalidateCityDialogRectRegion(&rtilInval, 1);
  rtilControl->Show(1, 1);
  ApplyUiTextStyleAndThemeFlags(rtilControl, 0, 0x12, 0x2b6b, 0x2b6c);

  // 'rocl'/'rocr' resource buttons.
  SetTaggedStringAndApply(0x2730, 0xc, kControlTagLcor); // 'rocl'
  SetTaggedStringAndApply(0x2730, 0xb, kControlTagRcor); // 'rocr'
}

// FUNCTION: IMPERIALISM 0x005baf70
void TDealBookPicture::ShowPage(int pageIndex, short nationId) {
  CString label;

  if (nationId != selectedNationSlot) {
    selectedNationSlot = nationId;
    CalculatePages();
  }

  int idx = pageIndex;
  currentPageIndex = static_cast<short>(idx);
  ++idx;

  TTradePageBuyView* buyCopy = cachedBuyPageView;
  if (static_cast<short>(idx) > buyCopy->pageCount) {
    buyCopy->Show(0, 1);
  } else {
    buyCopy->ShowPage(static_cast<short>(idx));
    buyCopy->Show(1, 0);
  }

  TTradePageSellView* sellCopy = cachedSellPageView;
  if (static_cast<short>(idx) > sellCopy->pageCount) {
    sellCopy->Show(0, 1);
  } else {
    sellCopy->ShowPage(static_cast<short>(idx));
    sellCopy->Show(1, 0);
  }

  TView* leftCtrl = FindSubView(kControlTagLcor);
  if (leftCtrl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x16e);
  }
  TView* rightCtrl = FindSubView(kControlTagRcor);
  if (rightCtrl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x170);
  }

  if (currentPageIndex != 0) {
    leftCtrl->Show(1, 1);
    leftCtrl->ViewEnable(1, 1);
    g_pSimMgr->GetString(0x2730, 0xb, &label);
  } else {
    leftCtrl->Show(0, 1);
    leftCtrl->ViewEnable(0, 1);
    label = g_szEmptyString;
  }
  SetControlHoverHelpTextAltEntry(label, leftCtrl);

  short refRow = lastPageIndex;
  if (currentPageIndex != refRow && refRow != 0) {
    rightCtrl->Show(1, 1);
    rightCtrl->ViewEnable(1, 1);
    g_pSimMgr->GetString(0x2730, 0xa, &label);
  } else {
    rightCtrl->Show(0, 1);
    rightCtrl->ViewEnable(0, 1);
    label = g_szEmptyString;
  }
  SetControlHoverHelpTextAltEntry(label, rightCtrl);
}

// FUNCTION: IMPERIALISM 0x005bb2e0
void TDealBookPicture::CalculatePages() {
  tradeListEmpty = true;
  TGreatPower* nation = g_apNationStates[selectedNationSlot];
  if (nation->pressureCounter > 0 || nation->ComputeRemainingDiplomacyAidBudget() != 0) {
    tradeListEmpty = false;
  }

  int buyRow = 0;
  int sellRow = 0;
  for (short commoditySlot = 0; commoditySlot < 17; ++commoditySlot) {
    short entryCount = nation->GetNumDealsIn(commoditySlot);
    if (entryCount == 0) {
      continue;
    }

    tradeListEmpty = false;
    short kind = 0;
    short value = 0;
    short targetNation = 0;
    int payload = 0;
    nation->GetDealInfo(commoditySlot, 1, &kind, &value, &targetNation, &payload);

    TPageView* page;
    int* row;
    if (kind == kTrackedSlotOfferEntry) {
      page = boughtTradesView;
      row = &buyRow;
    } else {
      page = soldTradesView;
      row = &sellRow;
    }
    ++*row;

    int headerBounds[2] = {200, 30};
    TCommodityLine* header = new TCommodityLine();
    header->ILineData(0, 30, headerBounds);
    header->commoditySlot = commoditySlot;
    page->AddOptionEntry(header);

    for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int lineBounds[2] = {200, 30};
      TDealLine* line = new TDealLine();
      line->ILineData(static_cast<short>(*row), 0, lineBounds);
      line->commoditySlot = commoditySlot;
      line->ownerNationSlot = selectedNationSlot;
      line->entryOrdinal = ordinal;
      page->AddOrderedEntry(line);
    }
  }

  if (nation->GetTotalOverseasProfits() != 0) {
    CString aidHeading;
    tradeListEmpty = false;

    int headingBounds[2] = {200, 30};
    TTextLine* heading = new TTextLine();
    heading->ITextLine(0, 60, headingBounds, -1, 0);
    g_pSimMgr->GetString(0x2741, 7, &aidHeading);
    heading->SetCaptionText(&aidHeading);

    TextStyle headingStyle;
    BuildUiTextStyleDescriptor(&headingStyle, 0, 14, 0x2b67);
    heading->SetTheTextStyle(&headingStyle);
    heading->SetTheJustification(1);
    soldTradesView->AddOrderedEntry(heading);

    for (short targetNation = 0; targetNation < 23; ++targetNation) {
      if (nation->GetOverseasProfitFrom(static_cast<NationSlot>(targetNation)) == 0) {
        continue;
      }

      ++sellRow;
      tradeListEmpty = false;

      int headerBounds[2] = {200, 30};
      TCommodityLine* header = new TCommodityLine();
      header->ILineData(0, 30, headerBounds);
      header->commoditySlot = targetNation;
      soldTradesView->AddOptionEntry(header);

      for (short minorNation = 7; minorNation < 23; ++minorNation) {
        int allocation = nation->aidAllocationMatrix[(minorNation - 7) * 23 + targetNation];
        if (g_apTerrainTypeDescriptorTable[minorNation] == 0 || allocation == 0) {
          continue;
        }

        CString nationName;
        CString allocationText;
        int lineBounds[2] = {200, 30};
        TTextLine* line = new TTextLine();
        line->ITextLine(static_cast<short>(sellRow), 0, lineBounds, -1, 0);
        nationName = g_pSimMgr->GetCountryName(minorNation);
        g_pSimMgr->NumToCurrency(allocation, &allocationText);
        nationName += s_szTurnHistorySeparator + allocationText;
        line->SetCaptionText(&nationName);
        soldTradesView->AddOrderedEntry(line);
      }
    }
  }

  int totalsBounds[2] = {200, (nation->pressureCounter > 0 ? 5 : 4) * 30};
  TTradeTotalsLine* totals = new TTradeTotalsLine();
  totals->ILineData(0, 0, totalsBounds);
  totals->nationSlot = selectedNationSlot;
  soldTradesView->AddOrderedEntry(totals);

  boughtTradesView->CalculatePageStarts();
  soldTradesView->CalculatePageStarts();
  lastPageIndex = boughtTradesView->pageCount > soldTradesView->pageCount
                      ? boughtTradesView->pageCount - 1
                      : soldTradesView->pageCount - 1;

  TDealTabControl* tabs = static_cast<TDealTabControl*>(FindSubView(kControlTagTabs)); // 'tabs'
  tabs->AssertValid();
  tabs->Setup(0x2266, g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId]);
}

// FUNCTION: IMPERIALISM 0x005bbc30
void TDealBookPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId >= 0x2af8) {
    short tabIndex = commandId - 0x2af8;
    short categorySlot = g_tradeBookCategoryByTabAndTechState
        [g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId]][tabIndex];
    if (categorySlot != -1) {
      sellPageView->SetItem(categorySlot);
      buyPageView->SetItem(categorySlot);
      if (!alternatePageMode) {
        SwitchPages();
      }
      TStaticText* titLControl = static_cast<TStaticText*>(FindSubView(kControlTagTitL)); // 'titL'
      titLControl->AssertValid();
      CString templateText;
      g_pSimMgr->GetString(0x2741, 3, &templateText);
      CString categoryName;
      g_pSimMgr->GetString(0x2711, categorySlot, &categoryName);
      CString composedTitle;
      scanBracketExpressions(g_pSimMgr, &composedTitle, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(categoryName));
      titLControl->SetTextAndMaybeRefresh(&composedTitle, false);

      CRect titleBounds;
      titLControl->GetFrame(&titleBounds);
      InvalidateCityDialogRectRegion(&titleBounds, 1);

      TDropShadowText* rtilControl = static_cast<TDropShadowText*>(FindSubView(kControlTagRtil));
      rtilControl->AssertValid();
      if (!rtilControl->IsActionable()) {
        ApplyUiTextStyleAndThemeFlags(rtilControl, 0, 0x12, 0x2b6b, 0x2b6c);

        CString seasonName;
        CString yearText;
        yearText.Format(g_szDecimalFormat, 0x717 + g_pSimMgr->economicTurn / 4);
        g_pSimMgr->GetSeason(&seasonName);
        CString headerText = seasonName + s_szSpaceSeparator + yearText;
        rtilControl->SetTextAndMaybeRefresh(&headerText, false);
        rtilControl->Show(1, 1);
      }
      g_pSfxPlaybackSystem->PlaySoundEffect(0x13f0, 0, 1);
    }
  } else if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag == kControlTagLcor) { // 'lcor'
      if (currentPageIndex > 0) {
        ShowPage(currentPageIndex - 1, selectedNationSlot);
      }
    } else if (tag == kControlTagRcor) { // 'rcor'
      if (currentPageIndex < lastPageIndex) {
        ShowPage(currentPageIndex + 1, selectedNationSlot);
      }
    } else if (tag == kControlTagMark) { // 'mark'
      if (alternatePageMode) {
        SwitchPages();
      }
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005bc0d0
void TDealBookPicture::SwitchPages() {
  TPageView* hiddenPage1;
  TPageView* hiddenPage2;
  TTradePageSellView* visibleSellPage;
  TTradePageBuyView* visibleBuyPage;
  short pictureResourceId;

  if (!alternatePageMode) {
    TView* markControl = FindSubView(kControlTagMark);
    markControl->AssertValid();
    markControl->ViewEnable(1, 0);

    TStaticText* rtilControl = static_cast<TStaticText*>(FindSubView(kControlTagRtil));
    rtilControl->AssertValid();

    CString seasonName;
    CString yearText;
    yearText.Format(g_szDecimalFormat, 0x717 + g_pSimMgr->economicTurn / 4);
    g_pSimMgr->GetSeason(&seasonName);
    CString headerText = seasonName + s_szSpaceSeparator + yearText;
    rtilControl->SetTextAndMaybeRefresh(&headerText, false);

    CRect titleBounds;
    rtilControl->GetFrame(&titleBounds);
    InvalidateCityDialogRectRegion(&titleBounds, 1);

    TView* tabsControl = FindSubView(kControlTagTabs);
    SendStringCommand(0x2740, 4, tabsControl);

    hiddenPage1 = soldTradesView;
    hiddenPage2 = boughtTradesView;
    visibleSellPage = sellPageView;
    visibleBuyPage = buyPageView;
    pictureResourceId = 0x2263;
  } else {
    buyPageView->SetItem(-1);
    sellPageView->SetItem(-1);

    TView* tabsControl = FindSubView(kControlTagTabs);
    if (tabsControl == NULL) {
      FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x2a2);
    }

    TStaticText* titLControl = static_cast<TStaticText*>(FindSubView(kControlTagTitL));
    titLControl->AssertValid();
    titLControl->SetTextWithStrListID(0x2740, 0x19, false);
    CRect titLBounds;
    titLControl->GetFrame(&titLBounds);
    InvalidateCityDialogRectRegion(&titLBounds, 1);

    TStaticText* rtilControl = static_cast<TStaticText*>(FindSubView(kControlTagRtil));
    rtilControl->AssertValid();
    rtilControl->SetTextWithStrListID(0x2740, 0x1a, false);
    CRect rtilBounds;
    rtilControl->GetFrame(&rtilBounds);
    InvalidateCityDialogRectRegion(&rtilBounds, 1);

    TView* markControl = FindSubView(kControlTagMark);
    markControl->AssertValid();
    markControl->ViewEnable(0, 0);

    TView* tabsControl2 = FindSubView(kControlTagTabs);
    SendStringCommand(0x2740, 4, tabsControl2);

    hiddenPage1 = buyPageView;
    hiddenPage2 = sellPageView;
    visibleSellPage = soldTradesView;
    visibleBuyPage = boughtTradesView;
    pictureResourceId = 0x2260;
  }

  CPoint captureBuffer1(1000, 1000);
  hiddenPage1->Locate(captureBuffer1, true);
  CPoint captureBuffer2(1000, 1000);
  hiddenPage2->Locate(captureBuffer2, true);
  CPoint captureBuffer3(0x41, 0x59);
  visibleSellPage->Locate(captureBuffer3, true);
  CPoint captureBuffer4(0x13a, 0x59);
  visibleBuyPage->Locate(captureBuffer4, true);

  cachedSellPageView = visibleSellPage;
  cachedBuyPageView = visibleBuyPage;
  if (cachedBuyPageView->pageCount > cachedSellPageView->pageCount) {
    lastPageIndex = cachedBuyPageView->pageCount - 1;
  } else {
    lastPageIndex = cachedSellPageView->pageCount - 1;
  }

  SetPictureRsrcID(pictureResourceId, 1);
  alternatePageMode = !alternatePageMode;
  ShowPage(0, selectedNationSlot);
}
