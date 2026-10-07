#include "game/gfx/TAmbitApplication.h"
#include "game/resource_domain_types.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_tags_screens.h"
#include "game/ui_tags_widgets.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/trade_ui/TDealTabControl.h"
#include "game/trade_ui/TTradeBookView.h"
#include "game/ui_text_label_helpers_decls.h"
#include "game/globals/trade_ui_globals.h"

#include "game/core/CString.h"
#include "game/ui_widgets/TAmtBarCluster.h"
#include "game/ui_core/TApplication.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCountry.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_widgets/TDropShadowNumberText.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_widgets/TNextTradeCommand.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_screens/TPictureButton.h"
#include "game/ui_screens/TToggleButton.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TSoundPlayer.h"
#include "game/ui_widgets/TInfoBarText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TWindow.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_widgets/TToolBarCluster.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/ui_core/TUiEvent.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"

IMPLEMENT_DYNCREATE(TOfferDeskPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005be570
TOfferDeskPicture::TOfferDeskPicture()
    : TPicture(), selectionActive(false), acceptButton(0), rejectButton(0) {}

// FUNCTION: IMPERIALISM 0x005be5e0
TOfferDeskPicture::~TOfferDeskPicture() {}

// FUNCTION: IMPERIALISM 0x005be600
void TOfferDeskPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);

  TDropShadowText* treasury = static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagTrea));
  treasury->AssertValid();
  ApplyUiTextStyleAndThemeFlags(treasury, 0, 0xe, 0x2b6c, 0x2b6b);

  TDropShadowNumberText* maximum =
      static_cast<TDropShadowNumberText*>(ResolveControlByTag(kControlTagMCap));
  maximum->AssertValid();
  ApplyUiNumberTextStyleAndThemeColor(maximum, 0, 0xc, 0x2b6c, 0x2b6b);
  LoadUiStringByGroupAndIndexToControlObject(0x2740, 1, maximum);
  maximum->SetJustification(0, true);

  TDealTabControl* tabs = static_cast<TDealTabControl*>(ResolveControlByTag(kControlTagTabs));
  tabs->AssertValid();
  tabs->Setup(0x2264, g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId]);
  tabs->RefreshControl();

  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(ResolveControlByTag(kControlTagTool));
  toolbar->AssertValid();
  toolbar->AddInfoBehaviors();
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetPlayerCountry());

  TView* miniPicture = ResolveControlByTag(kControlTagMPic);
  miniPicture->AssertValid();

  TView* offerCluster = ResolveControlByTag(kControlTagClus);
  offerCluster->AssertValid();
  offerCluster->ViewEnable(0, 1);
  SetControlHoverHelpText(CString(g_szEmptyString), this);

  LoadUiStringByGroupAndIndexToControlObject(0x2740, 2, maximum);
  LoadUiStringByGroupAndIndexToControlObject(0x2740, 5, ResolveControlByTag(kControlTagDone));
  LoadUiStringByGroupAndIndexToControlObject(0x2740, 6, ResolveControlByTag(kControlTagReje));
  LoadUiStringByGroupAndIndexToControlObject(0x2740, 7, ResolveControlByTag(kControlTagAcce));

  TView* sheet = ResolveControlByTag(kControlTagShee);
  SetControlHoverHelpText(CString(g_szEmptyString), sheet);
  TView* wait = ResolveControlByTag(kControlTagWait);
  SetControlHoverHelpText(CString(g_szEmptyString), wait);
  TTradeBookView* book = static_cast<TTradeBookView*>(ResolveControlByTag(kControlTagBook));
  SetControlHoverHelpText(CString(g_szEmptyString), book);
  LoadUiStringByGroupAndIndexToControlObject(0x2740, 1, miniPicture);
  SetControlHoverHelpText(CString(g_szEmptyString), book->ResolveControlByTag(kControlTagList));
  LoadUiStringByGroupAndIndexToControlObject(0x2730, 3, ResolveControlByTag(kControlTagQuer));

  TStaticText* waitText = static_cast<TStaticText*>(wait->ResolveControlByTag(kControlTagText));
  waitText->AssertValid();
  TextStyle waitStyle;
  waitStyle.textColor = 0;
  BuildUiTextStyleDescriptor(&waitStyle, 0, 0xe, 0x2b67);
  waitText->InstallTextStyle(waitStyle, 0);
  waitText->SetJustification(1, false);

  acceptButton = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagAcce));
  acceptButton->AssertValid();
  acceptButton->clickSoundId = 0x1388;
  rejectButton = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagReje));
  rejectButton->AssertValid();
  rejectButton->clickSoundId = 0x1388;

  TPictureButton* formatButton = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagForM));
  formatButton->AssertValid();
  formatButton->clickSoundId = 0x1b58;
  LoadUiStringByGroupAndIndexToControlObject(0x2764, 0x12, formatButton);
}

// FUNCTION: IMPERIALISM 0x005bea00
void TOfferDeskPicture::PoseOfferSheet(short respondingNation, short offeringNation,
                                       short proposedAmount, short maxAmount, short commodityType) {
  bool waitingForLocalReply =
      respondingNation == -1 || respondingNation != g_pSimMgr->GetPlayerCountry();
  if (respondingNation == -1) {
    respondingNation = g_pSimMgr->GetPlayerCountry();
    offeringNation = respondingNation;
  }

  TView* sheet = ResolveControlByTag(kControlTagShee);
  TView* wait = ResolveControlByTag(kControlTagWait);

  CString commodityName;
  CString offeringNationName;
  CString respondingNationName;
  CString maximumAmountText;
  CString proposedAmountText;
  CString displayText;
  CString capacityText;

  CRect offerInvalidRect(0x143, 0xae, 0x220, 0x1ac);
  CRect iconInvalidRect(0x23c, 0x92, 0x268, 0xaa);
  RGBQUAD hiliteColor = {0x7f, 0x7f, 0x7f, 0};

  SetControlHoverHelpText(CString(g_szEmptyString), this);
  g_pCursorControlPanel = static_cast<TInfoBarText*>(ResolveControlByTag(kControlTagCurs));
  g_pCursorControlPanel->AssertValid();
  if (g_pCursorControlPanel == 0) {
    FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x613);
  }
  g_pCursorControlPanel->InitializeMapHintTextStyleAndThemeFlags(0x2b6c, 0x2b67);

  respondingNationSlot = respondingNation;
  offeringNationSlot = offeringNation;
  this->proposedAmount = proposedAmount;
  this->maxAmount = maxAmount;
  this->commodityType = commodityType;
  suppressEventFlag = 0;

  g_pSimMgr->GetCommodityName(commodityType, &commodityName);
  offeringNationName = g_pSimMgr->LoadNormalizedCredentialName(offeringNation);
  respondingNationName = g_pSimMgr->LoadNormalizedCredentialName(respondingNation);
  g_pSimMgr->NumToCurrency(maxAmount, &maximumAmountText);
  proposedAmountText.Format(g_szDecimalFormat, static_cast<int>(proposedAmount));

  if (waitingForLocalReply) {
    TStaticText* text = static_cast<TStaticText*>(wait->ResolveControlByTag(kControlTagText));
    text->AssertValid();
    TPicture* commodityIcon =
        static_cast<TPicture*>(wait->ResolveControlByTag(IMPERIALISM_FOURCC('i', 'c', 'o', 'w')));
    commodityIcon->AssertValid();

    CString messageTemplate;
    CString waitingText;
    if (commodityType == kResourceGold) {
      g_pSimMgr->GetString(0x2740, 0xb, &messageTemplate);
      commodityIcon->Show(0, 1);
      SetControlHoverHelpTextAltEntry(CString(g_cstrTradeTotalsBalanceSubstitution), commodityIcon);
    } else {
      g_pSimMgr->GetString(0x2740, 0xa, &messageTemplate);
      commodityIcon->SetPictureRsrcID(static_cast<short>(commodityType + 0x2bc), 1);
      commodityIcon->Show(1, 1);
    }
    scanBracketExpressions(g_pSimMgr, &waitingText, static_cast<LPCSTR>(messageTemplate),
                           static_cast<LPCSTR>(commodityName));
    text->SetTextAndMaybeRefresh(&waitingText, true);

    if (wait->ownerLocalX != g_offerDeskOffscreenPosition.x ||
        wait->ownerLocalY != g_offerDeskOffscreenPosition.y) {
      wait->Locate(g_offerDeskOffscreenPosition, true);
    }
    if (!selectionActive && (sheet->ownerLocalX != g_offerDeskSheetPosition.x ||
                             sheet->ownerLocalY != g_offerDeskSheetPosition.y)) {
      sheet->Locate(g_offerDeskSheetPosition, true);
    }

    TView* formatButton = ResolveControlByTag(kControlTagForM);
    formatButton->AssertValid();
    formatButton->ViewEnable(0, 0);
    GetWindow()->ForceRedraw();
    return;
  }

  SwitchToBook(0);
  sheet->Locate(g_offerDeskSheetPosition, false);
  wait->Locate(g_offerDeskOffscreenPosition, false);

  TView* acceptButton = ResolveControlByTag(kControlTagAcce);
  acceptButton->AssertValid();
  TView* rejectButton = ResolveControlByTag(kControlTagReje);
  rejectButton->AssertValid();
  acceptButton->ViewEnable(1, 0);
  rejectButton->ViewEnable(1, 0);

  TView* formatButton = ResolveControlByTag(kControlTagForM);
  formatButton->AssertValid();
  formatButton->ViewEnable(1, 0);

  if (g_pSimMgr->multiplayerSessionRole != kSessionRoleStandalone) {
    g_pSfxPlaybackSystem->PlaySoundEffect(0x13f2, 0, 1);
  }

  CString offerTemplate;
  g_pSimMgr->GetString(0x2740, 0xc, &offerTemplate);
  scanBracketExpressions(
      g_pSimMgr, &displayText, static_cast<LPCSTR>(offerTemplate),
      static_cast<LPCSTR>(offeringNationName), static_cast<LPCSTR>(proposedAmountText),
      static_cast<LPCSTR>(commodityName), static_cast<LPCSTR>(maximumAmountText));

  TextStyle style;
  style.textColor = 0;
  TStaticText* offerText =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('o', 'f', 'f', 'e')));
  offerText->AssertValid();
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6b);
  offerText->InstallTextStyle(style, 0);
  offerText->SetJustification(1, false);
  offerText->SetTextAndMaybeRefresh(&displayText, false);

  TStaticText* purchaseTitle =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('p', 'u', 'r', 'T')));
  purchaseTitle->AssertValid();
  purchaseTitle->InstallTextStyle(style, 0);
  purchaseTitle->SetJustification(-1, false);
  purchaseTitle->SetTextWithStrListID(0x2740, 0xe, true);

  TStaticText* unitText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagUnit));
  unitText->AssertValid();
  unitText->InstallTextStyle(style, 0);
  unitText->SetJustification(-2, false);
  unitText->SetTextWithStrListID(0x2740, 0xf, true);

  g_pSimMgr->GetString(0x2740, 0xf, &offerTemplate);
  scanBracketExpressions(g_pSimMgr, &displayText, static_cast<LPCSTR>(offerTemplate),
                         static_cast<LPCSTR>(commodityName));
  TStaticText* numberOfText =
      static_cast<TStaticText*>(ResolveControlByTag(IMPERIALISM_FOURCC('n', 'o', 'o', 'f')));
  numberOfText->AssertValid();
  numberOfText->InstallTextStyle(style, 0);
  numberOfText->SetJustification(-2, false);
  numberOfText->SetTextAndMaybeRefresh(&displayText, false);

  short capacity =
      g_apTerrainTypeDescriptorTable[g_pSimMgr->GetPlayerCountry()]->GetMerchantCapacity();
  capacityText.Format(g_szDecimalFormat, static_cast<int>(capacity));
  TStaticText* maximumText = static_cast<TStaticText*>(ResolveControlByTag(kControlTagMCap));
  maximumText->AssertValid();
  BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b67);
  maximumText->InstallTextStyle(style, 0);
  maximumText->SetJustification(1, false);
  maximumText->SetTextAndMaybeRefresh(&capacityText, true);
  maximumText->RefreshControl();

  sheet = ResolveControlByTag(kControlTagShee);
  sheet->AssertValid();
  sheet->RefreshControl();

  TNumberText* purchaseControl = static_cast<TNumberText*>(ResolveControlByTag(kControlTagPurc));
  purchaseControl->AssertValid();
  detailedErrorFlag = true;
  if (proposedAmount > maxAmount) {
    proposedAmount = maxAmount;
    detailedErrorFlag = false;
  }
  purchaseControl->maximumValue = proposedAmount;
  BuildUiTextStyleDescriptor(&style, 0, 0xe, 0x2b67);
  purchaseControl->InstallTextStyle(style, 0);
  purchaseControl->SetJustification(1, false);
  purchaseControl->SetControlValue(proposedAmount, 0);
  purchaseControl->BecomeTarget();
  purchaseControl->GetCurrentText(&proposedAmountText);
  purchaseControl->SetEditSelectionAndScrollCaret(
      0, static_cast<short>(proposedAmountText.GetLength()), 1);

  SetGlobalBlitTransparentColorRaw(purchaseControl->stylePayload->packedColor);
  g_pDisplayMgr->SetHiliteColor(&hiliteColor);

  TPicture* commodityIcon = static_cast<TPicture*>(ResolveControlByTag(kControlTagIcon));
  commodityIcon->AssertValid();
  commodityIcon->SetPictureRsrcID(static_cast<short>(commodityType + 0x2bc), 0);

  acceptButton = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagAcce));
  acceptButton->AssertValid();
  acceptButton->ViewEnable(1, 0);
  rejectButton = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagReje));
  rejectButton->AssertValid();
  rejectButton->ViewEnable(1, 0);

  TView* cluster = ResolveControlByTag(kControlTagClus);
  cluster->AssertValid();
  TToggleButton* noMore =
      static_cast<TToggleButton*>(cluster->ResolveControlByTag(kControlTagNomo));
  noMore->AssertValid();
  noMore->Show(1, 0);
  noMore->Select(false, false);

  TToolBarCluster* toolbar = static_cast<TToolBarCluster*>(ResolveControlByTag(kControlTagTool));
  toolbar->AssertValid();
  toolbar->UpdateControlTagTreaTextFromNationAndMapContext(g_pSimMgr->GetPlayerCountry());

  InvalidateCityDialogRectRegion(&offerInvalidRect, 1);
  InvalidateCityDialogRectRegion(&iconInvalidRect, 1);

  TDropShadowText* info = static_cast<TDropShadowText*>(ResolveControlByTag(kControlTagInfo));
  info->AssertValid();
  ApplyUiTextStyleAndThemeFlags(info, 0, 0xc, 0x2b6c, 0x2b6b);
  info->SetJustification(-2, false);

  selectionActive = false;
  ShowAdvice();
  g_pSfxPlaybackSystem->RequestAudioPresetChangeWithDeferredApply(4, true);
}

// FUNCTION: IMPERIALISM 0x005bf740
void TOfferDeskPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId >= 0x2af8) {
    short tabIndex = static_cast<short>(commandId - 0x2af8);
    short selectionIndex = g_tradeBookCategoryByTabAndTechState
        [g_pTechMgr->perTechUnlockFlag[TTechMgr::kProductionOrderTechId]][tabIndex];
    if (!selectionActive) {
      SwitchToBook(1);
    } else {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x13f0, 0, 1);
    }
    TTradeBookView* bookControl =
        static_cast<TTradeBookView*>(ResolveControlByTag(kControlTagBook));
    bookControl->SetItem(selectionIndex);
  } else if (commandId == 0xa) {
    if (tag == kControlTagAcce || tag == kControlTagReje) {
      CreateNextTradeCommandAndFormatPrompt(tag);
    } else if (tag == kControlTagForM) {
      g_pHelpMgr->ToggleTradeAdvice();
      ShowAdvice();
    }
  } else if (commandId == 0x14 && tag == kControlTagDone) {
    SwitchToBook(0);
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005bf860
void TOfferDeskPicture::DoKeyEvent(TToolboxEvent* event) {
  int commandCode = event->commandCode;
  if (commandCode == kUiKeyEnter || commandCode == kUiKeyReturn) {
    TPictureButton* button = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagAcce));
    if (button == 0) {
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(button->clickSoundId, 0, 1);
    QueueDeferredUiEventPacket(this, 0xa, button);
  } else if (commandCode == kUiKeyEscape) {
    TPictureButton* button = static_cast<TPictureButton*>(ResolveControlByTag(kControlTagReje));
    if (button == 0) {
      return;
    }
    g_pSfxPlaybackSystem->PlaySoundEffect(button->clickSoundId, 0, 1);
    QueueDeferredUiEventPacket(this, 0xa, button);
  }
}

// FUNCTION: IMPERIALISM 0x005bf930
void TOfferDeskPicture::ShowAdvice() {
  TGreatPower* gp = g_apNationStates[respondingNationSlot];
  TCity* city;
  if (gp == 0) {
    city = 0;
  } else {
    city = gp->city;
  }
  bool notAligned = false;
  bool hasSurplus = false;
  short avail;
  short relDelta;
  short stock;
  short needTgt;

  CString strTargetNation;
  CString strCommodity;
  CString strDominantName;
  CString strCityStock;
  CString strNeedTarget;
  CString strRelDelta;
  CString strAvail;
  CString strFinal;
  CString strPrefix;
  CString strNationClause;
  CString strTypeClause;
  CString strTemplate;

  TStaticText* info = static_cast<TStaticText*>(ResolveControlByTag(kControlTagInfo));
  info->AssertValid();
  info->SetJustification(-2, false);

  {
    strTargetNation = g_pSimMgr->LoadNormalizedCredentialName(offeringNationSlot);
  }
  g_pSimMgr->GetCommodityName(commodityType, &strCommodity);

  short compat =
      g_pDiplomacyTurnStateManager->GetEmbassyStatus(respondingNationSlot, offeringNationSlot);

  if (g_pHelpMgr->tradeAdviceDetailLevel == 0) {
    g_pSimMgr->GetString(0x2740, 9, &strFinal);
    info->SetJustification(1, false);
  } else if (g_pHelpMgr->tradeAdviceDetailLevel == 1) {
    if (compat >= 1 &&
        g_apTerrainTypeDescriptorTable[offeringNationSlot]->IsColonyOf(respondingNationSlot) == 0) {
      notAligned = true;
    }
    if (commodityType != kResourceCotton && commodityType != kResourceWool) {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(commodityType));
      relDelta = gp->purchasedItemsByResource[commodityType];
      // TCity models the 23 per-commodity stock shorts as named fields; index off the first.
      stock = (&city->cityStockCotton)[commodityType];
      needTgt = gp->needTargetByType[commodityType];
    } else {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(0));
      relDelta =
          static_cast<short>(gp->purchasedItemsByResource[1] + gp->purchasedItemsByResource[0]);
      stock = static_cast<short>(city->cityStockCotton + city->cityStockWool);
      needTgt = static_cast<short>(gp->needTargetByType[1] + gp->needTargetByType[0]);
    }
    if (avail > stock + relDelta + needTgt) {
      hasSurplus = true;
    }

    if (!notAligned && !hasSurplus) {
      if (g_apTerrainTypeDescriptorTable[offeringNationSlot]->IsColonyOf(respondingNationSlot)) {
        g_pSimMgr->GetString(0x2764, 0x10, &strTemplate);
      } else {
        g_pSimMgr->GetString(0x2764, 5, &strPrefix);
        g_pSimMgr->GetString(0x2764, 6, &strTemplate);
      }
      scanBracketExpressions(g_pSimMgr, &strNationClause, static_cast<LPCSTR>(strTemplate),
                             static_cast<LPCSTR>(strTargetNation));
      g_pSimMgr->GetString(0x2764, 7, &strTemplate);
    } else {
      g_pSimMgr->GetString(0x2764, 0, &strPrefix);
      if (notAligned) {
        g_pSimMgr->GetString(0x2764, (compat == 2) ? 1 : 2, &strTemplate);
        scanBracketExpressions(g_pSimMgr, &strNationClause, static_cast<LPCSTR>(strTemplate),
                               static_cast<LPCSTR>(strTargetNation));
      }
      g_pSimMgr->GetString(0x2764, hasSurplus ? 3 : 4, &strTemplate);
    }
    scanBracketExpressions(g_pSimMgr, &strTypeClause, static_cast<LPCSTR>(strTemplate),
                           static_cast<LPCSTR>(strCommodity));
    strFinal = strPrefix + strNationClause + strTypeClause;
  } else {
    CString strStatsIntro;
    CString strVerdict;
    if (commodityType != kResourceCotton && commodityType != kResourceWool) {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(commodityType));
      relDelta = gp->purchasedItemsByResource[commodityType];
      stock = (&city->cityStockCotton)[commodityType];
      needTgt = gp->needTargetByType[commodityType];
    } else {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(0));
      relDelta =
          static_cast<short>(gp->purchasedItemsByResource[1] + gp->purchasedItemsByResource[0]);
      stock = static_cast<short>(city->cityStockCotton + city->cityStockWool);
      needTgt = static_cast<short>(gp->needTargetByType[1] + gp->needTargetByType[0]);
    }
    strCityStock.Format(g_szDecimalFormat, static_cast<int>(stock));
    strNeedTarget.Format(g_szDecimalFormat, static_cast<int>(needTgt));
    strRelDelta.Format(g_szDecimalFormat, static_cast<int>(relDelta));
    strAvail.Format(g_szDecimalFormat, static_cast<int>(avail));
    if (offeringNationSlot < 7) {
      g_pSimMgr->GetString(0x2764, 8, &strTemplate);
      scanBracketExpressions(g_pSimMgr, &strStatsIntro, static_cast<LPCSTR>(strTemplate),
                             static_cast<LPCSTR>(strTargetNation));
    } else {
      short dominant = g_pDiplomacyTurnStateManager->GetFavoriteTradePartner(offeringNationSlot);
      {
        strDominantName = g_pSimMgr->LoadNormalizedCredentialName(dominant);
      }
      if (dominant == respondingNationSlot) {
        g_pSimMgr->GetString(0x2764, 0xe, &strTemplate);
        scanBracketExpressions(g_pSimMgr, &strStatsIntro, static_cast<LPCSTR>(strTemplate),
                               static_cast<LPCSTR>(strTargetNation));
      } else {
        g_pSimMgr->GetString(0x2764, 9, &strTemplate);
        scanBracketExpressions(g_pSimMgr, &strStatsIntro, static_cast<LPCSTR>(strTemplate),
                               static_cast<LPCSTR>(strTargetNation),
                               static_cast<LPCSTR>(strDominantName));
      }
    }
    short verdictIndex;
    if (compat == 2) {
      verdictIndex =
          g_apTerrainTypeDescriptorTable[offeringNationSlot]->IsColonyOf(respondingNationSlot)
              ? 0xf
              : 0xa;
    } else {
      verdictIndex = (compat == 1) ? 0xb : 0xc;
    }
    g_pSimMgr->GetString(0x2764, verdictIndex, &strTemplate);
    scanBracketExpressions(g_pSimMgr, &strVerdict, static_cast<LPCSTR>(strTemplate),
                           static_cast<LPCSTR>(strTargetNation));
    g_pSimMgr->GetString(0x2764, 0xd, &strTemplate);
    scanBracketExpressions(g_pSimMgr, &strTypeClause, static_cast<LPCSTR>(strTemplate),
                           static_cast<LPCSTR>(strCommodity), static_cast<LPCSTR>(strCityStock),
                           static_cast<LPCSTR>(strAvail), static_cast<LPCSTR>(strNeedTarget),
                           static_cast<LPCSTR>(strRelDelta));
    strFinal = strStatsIntro + strVerdict + strTypeClause;
  }

  CRect bounds;
  info->QueryBounds(&bounds);
  --bounds.left;
  --bounds.top;
  RECT grown = bounds;
  RECT inval;
  ::CopyRect(&inval, &grown);
  info->ownerContext->InvalidateCityDialogRectRegion(&inval, 1);
  info->SetTextAndMaybeRefresh(&strFinal, true);
}

// FUNCTION: IMPERIALISM 0x005c04f0
void TOfferDeskPicture::CreateNextTradeCommandAndFormatPrompt(int actionCode) {
  TView* clusterControl = ResolveControlByTag(kControlTagClus);
  if (clusterControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x83b);
  }

  TAmtBarCluster* noMoreControl =
      static_cast<TAmtBarCluster*>(clusterControl->ResolveControlByTag(kControlTagNomo));
  if (noMoreControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x83d);
  }
  suppressEventFlag = noMoreControl->IsTradeControlAtMinimum();

  TNumberText* purchaseControl = static_cast<TNumberText*>(ResolveControlByTag(kControlTagPurc));
  if (purchaseControl == NULL) {
    FailNilPointerWithAssert(s_SourcePathUTradeViews, 0x842);
  }
  proposedAmount = static_cast<short>(purchaseControl->UpdateControlCachedIntFromWindowText());

  bool quantityValid = true;
  if (actionCode == kControlTagReje) {
    proposedAmount = 0;
  } else if (proposedAmount > purchaseControl->maximumValue || proposedAmount < 0) {
    quantityValid = false;
  }

  if (quantityValid) {
    g_pTradeMgr->SetDealResults(respondingNationSlot, offeringNationSlot, proposedAmount, maxAmount,
                                commodityType, static_cast<char>(suppressEventFlag), false);

    TView* acceptButton = ResolveControlByTag(kControlTagAcce);
    acceptButton->AssertValid();
    TView* rejectButton = ResolveControlByTag(kControlTagReje);
    rejectButton->AssertValid();
    acceptButton->ViewEnable(0, 0);
    rejectButton->ViewEnable(0, 0);

    if (proposedAmount != 0) {
      TView* toolbar = g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagTool);
      if (toolbar != NULL) {
        static_cast<TAmtBarCluster*>(toolbar)->SetMoveAmount(
            static_cast<short>(respondingNationSlot));
      }
    }

    if (g_pSimMgr->multiplayerSessionRole != kSessionRoleClient) {
      TNextTradeCommand* command = new TNextTradeCommand();
      command->INextTradeCommand();
      g_pAmbitApplication->DispatchUiSelectionToHandler(command);
    }
  } else {
    CString errorMessage;
    CString localizedMessage;
    if (detailedErrorFlag) {
      g_pSimMgr->GetString(0x2740, 0x10, &localizedMessage);
    } else {
      CString maxValueTemplate;
      errorMessage.Format(g_szDecimalFormat, purchaseControl->maximumValue);
      g_pSimMgr->GetString(0x2740, 0x11, &maxValueTemplate);
      scanBracketExpressions(g_pSimMgr, &localizedMessage, static_cast<LPCSTR>(maxValueTemplate),
                             static_cast<LPCSTR>(errorMessage));
    }
    g_pDisplayMgr->ModalMessage(localizedMessage, g_ptControlStringModalMessage);
    purchaseControl->GetCurrentText(&errorMessage);
    purchaseControl->SetEditSelectionAndScrollCaret(0, static_cast<short>(errorMessage.GetLength()),
                                                    1);
  }
}

// FUNCTION: IMPERIALISM 0x005c0930
char TOfferDeskPicture::HandleMouseUp(const CPoint& point, TToolboxEvent* event, CPoint origin) {
  if (acceptButton != 0 && acceptButton->IsActionable()) {
    acceptButton->Show(0, 1);
  }
  if (rejectButton != 0 && rejectButton->IsActionable()) {
    rejectButton->Show(0, 1);
  }
  return TView::HandleMouseUp(point, event, origin);
}

// FUNCTION: IMPERIALISM 0x005c09d0
void TOfferDeskPicture::SwitchToBook(unsigned char activate) {
  if (activate == selectionActive) {
    return;
  }
  TView* bookControl = ResolveControlByTag(kControlTagBook);
  bookControl->AssertValid();
  TView* sheetControl = ResolveControlByTag(maxAmount == 0 ? kControlTagWait : kControlTagShee);
  if (sheetControl == 0) {
    FailNilPointerInUSmallViews(0x8a2);
  }
  TView* purchaseControl = ResolveControlByTag(kControlTagPurc);
  purchaseControl->AssertValid();
  purchaseControl->Show(activate == 0, 0);
  if (activate != 0) {
    CPoint bookLayout(0x3a, 0x2d);
    bookControl->Locate(bookLayout, false);
    sheetControl->Locate(g_offerDeskOffscreenPosition, false);
    SetPictureRsrcID(0x226f, 1);
    g_pSfxPlaybackSystem->PlaySoundEffect(0x13ee, 0, 1);
    TDealTabControl* tabsControl =
        static_cast<TDealTabControl*>(ResolveControlByTag(kControlTagTabs));
    tabsControl->AssertValid();
    tabsControl->Setup(0x2266, g_pTechMgr->perTechUnlockFlag[0x13]);
    tabsControl->RefreshControl();
    LoadUiStringAndDispatchSharedMessageCommand(0x2740, 4, tabsControl);
    TView* listControl = ResolveControlByTag(kControlTagList);
    listControl->AssertValid();
    LoadUiStringAndDispatchSharedMessageCommand(0x2740, 1, listControl);
  } else {
    bookControl->Locate(g_offerDeskOffscreenPosition, false);
    sheetControl->Locate(g_offerDeskSheetPosition, false);
    SetPictureRsrcID(0x2152, 1);
    g_pSfxPlaybackSystem->PlaySoundEffect(0x13ef, 0, 1);
    static_cast<TTradeBookView*>(bookControl)->SetItem(-1);
    TDealTabControl* tabsControl =
        static_cast<TDealTabControl*>(ResolveControlByTag(kControlTagTabs));
    tabsControl->AssertValid();
    tabsControl->Setup(0x2264, g_pTechMgr->perTechUnlockFlag[0x13]);
    tabsControl->selectedRow = -1;
    tabsControl->RefreshControl();
    LoadUiStringAndDispatchSharedMessageCommand(0x2740, 2, tabsControl);
    TView* listControl = ResolveControlByTag(kControlTagList);
    listControl->AssertValid();
    SetControlHoverHelpTextAltEntry(CString(g_szEmptyString), listControl);
  }
  selectionActive = activate;
}
