#include "game/TDealBookPicture.h"

#include "game/TCommodityLine.h"
#include "game/TDealLine.h"
#include "game/TDealTabControl.h"
#include "game/TDropShadowText.h"
#include "game/TGreatPower.h"
#include "game/TPageView.h"
#include "game/TSimMgr.h"
#include "game/mapped_flavor_text.h"
#include "game/TSoundPlayer.h"
#include "game/TStaticText.h"
#include "game/TTechMgr.h"
#include "game/TToolBarCluster.h"
#include "game/TTradePageBuyView.h"
#include "game/TTradePageSellView.h"
#include "game/TTradeTotalsLine.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control);
void SetControlHoverHelpTextAltEntry(CString sharedString, TView* control);

// SYNTHETIC: IMPERIALISM 0x005bab00
// TDealBookPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005baba0
// TDealBookPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TDealBookPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005babc0
TDealBookPicture::TDealBookPicture() : TPicture(), selectedNationId90(8), unresolvedByteB2(0) {}

// SYNTHETIC: IMPERIALISM 0x005bac00
// TDealBookPicture::`scalar deleting destructor'
TDealBookPicture::~TDealBookPicture() {}

// FUNCTION: IMPERIALISM 0x005bac50
void TDealBookPicture::Startup(short startupValue) {
  // Toolbar cluster ('tool'): refresh the turn-order status panel and re-derive its
  // nation/treasury text for the active nation.
  TToolBarCluster* toolControl =
      static_cast<TToolBarCluster*>(this->ResolveControlByTag(kControlTagTool));
  toolControl->AssertValid();
  toolControl->RefreshTurnOrderStatusPanelTextsAndControls();
  toolControl->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetActiveNationId());
  toolControl->RefreshControl();

  // Re-cache the six commodity sub-controls.
  this->boughtTradesView98 =
      static_cast<TTradePageBuyView*>(this->ResolveControlByTag(kControlTagBoug)); // 'boug'
  this->soldTradesView9C =
      static_cast<TTradePageSellView*>(this->ResolveControlByTag(kControlTagSold)); // 'sold'
  this->buyPageViewA0 =
      static_cast<TTradePageBuyView*>(this->ResolveControlByTag(kControlTagTbou)); // 'tbou'
  this->sellPageViewA4 =
      static_cast<TTradePageSellView*>(this->ResolveControlByTag(kControlTagTsol)); // 'tsol'
  this->buyPageViewAC = this->boughtTradesView98;
  this->sellPageViewA8 = this->soldTradesView9C;

  // 'mark' toggle + label reload.
  TView* markControl = this->ResolveControlByTag(kControlTagMark); // 'mark'
  if (markControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x129);
  }
  markControl->SetState(1, 0);
  LoadUiStringByGroupAndIndexToControlObject(0x2741, 6, this->ResolveControlByTag(kControlTagMark));
  markControl->SetState(0, 0);
  LoadUiStringByGroupAndIndexToControlObject(0x2741, 7, this->ResolveControlByTag(kControlTagTabs));

  this->alternatePageModeB1 = false;
  this->ShowPage(0, startupValue);
  g_pSfxPlaybackSystem->PlaySoundEffect(0x13ee, 0, 1);

  // 'titL' title label.
  TStaticText* titLControl = static_cast<TStaticText*>(this->ResolveControlByTag(kControlTagTitL));
  titLControl->AssertValid();
  titLControl->SetTextFromStringResource(0x2740, 0x19, 0);
  CRect titLBounds;
  titLControl->QueryBounds(&titLBounds);
  RECT titLInval;
  CopyRect(&titLInval, &titLBounds);
  this->InvalidateCityDialogRectRegion(&titLInval, 1);

  // 'rtil' subtitle label.
  TDropShadowText* rtilControl =
      static_cast<TDropShadowText*>(this->ResolveControlByTag(kControlTagRtil));
  rtilControl->AssertValid();
  rtilControl->SetTextFromStringResource(0x2740, 0x1a, 0);
  CRect rtilBounds;
  rtilControl->QueryBounds(&rtilBounds);
  RECT rtilInval;
  CopyRect(&rtilInval, &rtilBounds);
  this->InvalidateCityDialogRectRegion(&rtilInval, 1);
  rtilControl->SetEnabled(1, 1);
  ApplyUiTextStyleAndThemeFlags(rtilControl, 0, 0x12, 0x2b6b, 0x2b6c);

  // 'rocl'/'rocr' resource buttons.
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 0xc, kControlTagLcor); // 'rocl'
  LoadUiStringByGroupAndIndexToGlobalControlTagAndApply(0x2730, 0xb, kControlTagRcor); // 'rocr'
}

// FUNCTION: IMPERIALISM 0x005baf70
void TDealBookPicture::ShowPage(int pageIndex, short nationId) {
  CString label;

  if (nationId != this->selectedNationId90) {
    this->selectedNationId90 = nationId;
    this->CalculatePages();
  }

  int idx = pageIndex;
  this->currentPageIndex94 = static_cast<short>(idx);
  ++idx;

  TTradePageBuyView* buyCopy = this->buyPageViewAC;
  if (static_cast<short>(idx) > buyCopy->pageCount) {
    buyCopy->SetEnabled(0, 1);
  } else {
    buyCopy->ShowPage(static_cast<short>(idx));
    buyCopy->SetEnabled(1, 0);
  }

  TTradePageSellView* sellCopy = this->sellPageViewA8;
  if (static_cast<short>(idx) > sellCopy->pageCount) {
    sellCopy->SetEnabled(0, 1);
  } else {
    sellCopy->ShowPage(static_cast<short>(idx));
    sellCopy->SetEnabled(1, 0);
  }

  TView* leftCtrl = this->ResolveControlByTag(kControlTagLcor);
  if (leftCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x16e);
  }
  TView* rightCtrl = this->ResolveControlByTag(kControlTagRcor);
  if (rightCtrl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x170);
  }

  if (this->currentPageIndex94 != 0) {
    leftCtrl->SetEnabled(1, 1);
    leftCtrl->SetState(1, 1);
    g_pSimMgr->GetString(0x2730, 0xb, &label);
  } else {
    leftCtrl->SetEnabled(0, 1);
    leftCtrl->SetState(0, 1);
    label = g_szEmptyString;
  }
  SetControlHoverHelpTextAltEntry(label, leftCtrl);

  short refRow = this->lastPageIndex92;
  if (this->currentPageIndex94 != refRow && refRow != 0) {
    rightCtrl->SetEnabled(1, 1);
    rightCtrl->SetState(1, 1);
    g_pSimMgr->GetString(0x2730, 0xa, &label);
  } else {
    rightCtrl->SetEnabled(0, 1);
    rightCtrl->SetState(0, 1);
    label = g_szEmptyString;
  }
  SetControlHoverHelpTextAltEntry(label, rightCtrl);
}

// FUNCTION: IMPERIALISM 0x005bb2e0
void TDealBookPicture::CalculatePages() {
  tradeListEmptyB0 = true;
  TGreatPower* nation = g_apNationStates[selectedNationId90];
  if (nation->pressureCounter > 0 || nation->ComputeRemainingDiplomacyAidBudget() != 0) {
    tradeListEmptyB0 = false;
  }

  int buyRow = 0;
  int sellRow = 0;
  for (short commoditySlot = 0; commoditySlot < 17; ++commoditySlot) {
    short entryCount = nation->GetTrackedSlotEntryCountLow(commoditySlot);
    if (entryCount == 0) {
      continue;
    }

    tradeListEmptyB0 = false;
    short kind = 0;
    short value = 0;
    short targetNation = 0;
    int payload = 0;
    nation->ReadTrackedSlotEntryFields(commoditySlot, 1, &kind, &value, &targetNation, &payload);

    TPageView* page;
    int* row;
    if (kind == kTrackedSlotOfferEntry) {
      page = boughtTradesView98;
      row = &buyRow;
    } else {
      page = soldTradesView9C;
      row = &sellRow;
    }
    ++*row;

    int headerBounds[2] = {200, 30};
    TCommodityLine* header = new TCommodityLine();
    header->SetLineDataRowAndBounds(0, 30, headerBounds);
    header->commoditySlot10 = commoditySlot;
    page->AddOptionEntry(header);

    for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
      int lineBounds[2] = {200, 30};
      TDealLine* line = new TDealLine();
      line->SetLineDataRowAndBounds(static_cast<short>(*row), 0, lineBounds);
      line->commoditySlot10 = commoditySlot;
      line->ownerNationSlot12 = selectedNationId90;
      line->entryOrdinal14 = ordinal;
      page->AddOrderedEntry(line);
    }
  }

  // The original's middle section appends the per-minor aid-allocation rows when the
  // nation's allocation matrix is nonempty. Its row text/object subtype is still being
  // recovered; the tracked-deal rows and common page finalization remain valid without it.

  int totalsBounds[2] = {200, (nation->pressureCounter > 0 ? 5 : 4) * 30};
  TTradeTotalsLine* totals = new TTradeTotalsLine();
  totals->SetLineDataRowAndBounds(0, 0, totalsBounds);
  totals->nationId10 = selectedNationId90;
  soldTradesView9C->AddOrderedEntry(totals);

  boughtTradesView98->BuildPageLayout();
  soldTradesView9C->BuildPageLayout();
  lastPageIndex92 = boughtTradesView98->pageCount > soldTradesView9C->pageCount
                        ? boughtTradesView98->pageCount - 1
                        : soldTradesView9C->pageCount - 1;

  TDealTabControl* tabs =
      static_cast<TDealTabControl*>(ResolveControlByTag(kControlTagTabs)); // 'tabs'
  tabs->AssertValid();
  tabs->Setup(0x2266,
              g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId]);
}

// FUNCTION: IMPERIALISM 0x005bbc30
void TDealBookPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId >= 0x2af8) {
    // The real table is much larger than the declared 8-entry span (the original indexes
    // it with commandId + production-order-tech-unlocked*17, which can run far past 8) -- the
    // pointer arithmetic still lands on the correct address either way since C++ doesn't
    // bounds-check here, matching the original's raw displacement + computed offset.
    int categoryTableIndex =
        commandId +
        g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] * 17;
    short categorySlot = g_offerDeskSelectionIndexTable_00668568[categoryTableIndex];
    if (categorySlot != -1) {
      sellPageViewA4->RebuildNationOfferRowsForCategory(categorySlot);
      buyPageViewA0->RebuildNationBidRowsForCategory(categorySlot);
      if (!alternatePageModeB1) {
        SwitchPages();
      }
      TStaticText* titLControl =
          static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitL)); // 'titL'
      titLControl->AssertValid();
      CString templateText;
      g_pSimMgr->GetString(0x2741, 3, &templateText);
      CString categoryName;
      g_pSimMgr->GetString(0x2711, categorySlot, &categoryName);
      CString composedTitle;
      scanBracketExpressions(g_pSimMgr, &composedTitle, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(categoryName));
      titLControl->SetTextAndMaybeRefresh(&composedTitle, 0);
    }
  } else if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    if (tag == kControlTagLcor) { // 'lcor'
      if (currentPageIndex94 > 0) {
        ShowPage(currentPageIndex94 - 1, selectedNationId90);
      }
    } else if (tag == kControlTagRcor) { // 'rcor'
      if (currentPageIndex94 < lastPageIndex92) {
        ShowPage(currentPageIndex94 + 1, selectedNationId90);
      }
    } else if (tag == kControlTagMark) { // 'mark'
      if (alternatePageModeB1) {
        SwitchPages();
      }
    }
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005bc0d0
void TDealBookPicture::SwitchPages() {
  if (!alternatePageModeB1) {
    TView* markControl = ResolveControlByTag(kControlTagMark);
    markControl->AssertValid();
    markControl->SetState(1, 0);

    TStaticText* rtilControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagRtil));
    rtilControl->AssertValid();

    CString seasonName;
    CString yearText;
    yearText.Format(g_szDecimalFormat, 0x717 + g_pSimMgr->economicTurn / 4);
    g_pSimMgr->GetSeason(&seasonName);
    CString headerText = seasonName + s_szSpaceSeparator_00695794 + yearText;
    rtilControl->SetTextAndMaybeRefresh(&headerText, 0);

    CRect titleBounds;
    rtilControl->QueryBounds(&titleBounds);
    InvalidateCityDialogRectRegion(&titleBounds, 1);

    TView* tabsControl = ResolveControlByTag(kControlTagTabs);
    LoadUiStringAndDispatchSharedMessageCommand(0x2740, 4, tabsControl);
  } else {
    sellPageViewA4->RebuildNationOfferRowsForCategory(-1);
    buyPageViewA0->RebuildNationBidRowsForCategory(-1);

    TView* tabsControl = ResolveControlByTag(kControlTagTabs);
    if (tabsControl == nullptr) {
      MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
      TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x2a2);
    }

    TStaticText* titLControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitL));
    titLControl->AssertValid();
    titLControl->SetTextFromStringResource(0x2740, 0x19, 0);
    CRect titLBounds;
    titLControl->QueryBounds(&titLBounds);
    InvalidateCityDialogRectRegion(&titLBounds, 1);

    TStaticText* rtilControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagRtil));
    rtilControl->AssertValid();
    rtilControl->SetTextFromStringResource(0x2740, 0x1a, 0);
    CRect rtilBounds;
    rtilControl->QueryBounds(&rtilBounds);
    InvalidateCityDialogRectRegion(&rtilBounds, 1);

    TView* markControl = ResolveControlByTag(kControlTagMark);
    markControl->AssertValid();
    markControl->SetState(0, 0);

    TView* tabsControl2 = ResolveControlByTag(kControlTagTabs);
    LoadUiStringAndDispatchSharedMessageCommand(0x2740, 4, tabsControl2);
  }

  // Capture the four commodity sub-views' layouts (the original caches all four distinct
  // views -- bought/sold trades and the buy/sell pages -- not the buy page twice).
  int captureBuffer1[2] = {1000, 1000};
  boughtTradesView98->CaptureLayoutF0(captureBuffer1, 1);
  int captureBuffer2[2] = {1000, 1000};
  soldTradesView9C->CaptureLayoutF0(captureBuffer2, 1);
  int captureBuffer3[2] = {0x41, 0x59};
  sellPageViewA4->CaptureLayoutF0(captureBuffer3, 1);
  int captureBuffer4[2] = {0x13a, 0x59};
  buyPageViewA0->CaptureLayoutF0(captureBuffer4, 1);

  sellPageViewA8 = sellPageViewA4;
  buyPageViewAC = buyPageViewA0;
  if (buyPageViewAC->pageCount < sellPageViewA8->pageCount) {
    lastPageIndex92 = buyPageViewAC->pageCount - 1;
  } else {
    lastPageIndex92 = sellPageViewA8->pageCount - 1;
  }

  // Reapply the dialog's own picture and re-run the page selection. boughtTradesView98 is
  // a control pointer, not the bitmap id. alternatePageModeB1 flips before the trailing
  // ShowPage call.
  SetPictureResourceIdAndRefresh(selectedNationId90, 1);
  alternatePageModeB1 = !alternatePageModeB1;
  ShowPage(0, selectedNationId90);
}
