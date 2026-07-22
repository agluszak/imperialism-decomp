#include "game/TAmbitApplication.h"
#include "game/TOfferDeskPicture.h"

#include "game/CString.h"
#include "game/TAmtBarCluster.h"
#include "game/TApplication.h"
#include "game/TCity.h"
#include "game/TCountry.h"
#include "game/TDiplomacyMgr.h"
#include "game/TDisplayMgr.h"
#include "game/TGreatPower.h"
#include "game/THelpMgr.h"
#include "game/TNextTradeCommand.h"
#include "game/TNumberText.h"
#include "game/TSimMgr.h"
#include "game/TSoundPlayer.h"
#include "game/TStaticText.h"
#include "game/TTechMgr.h"
#include "game/TTradeMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
// SYNTHETIC: IMPERIALISM 0x005be4b0
// TOfferDeskPicture::CreateObject

// SYNTHETIC: IMPERIALISM 0x005be550
// TOfferDeskPicture::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOfferDeskPicture, TPicture)

// FUNCTION: IMPERIALISM 0x005be570
TOfferDeskPicture::TOfferDeskPicture()
    : TPicture(), selectionActive9e(false), acceptButtonA0(0), rejectButtonA4(0) {}

// SYNTHETIC: IMPERIALISM 0x005be5b0
// TOfferDeskPicture::`scalar deleting destructor'
TOfferDeskPicture::~TOfferDeskPicture() {}

// FUNCTION: IMPERIALISM 0x005be600
void TOfferDeskPicture::DoPostCreate(int arg) {
  TPicture::DoPostCreate(arg);
  // The original then sets up the offer-desk's per-nation control table (816 bytes) -- not
  // yet ported.
}

// FUNCTION: IMPERIALISM 0x005bea00
void TOfferDeskPicture::PoseOfferSheet(short sourceNation, short targetNation, short proposedAmount,
                                       short maxAmount, short commodityType) {
  if (sourceNation == -1) {
    sourceNation = g_pSimMgr->GetActiveNationId();
  }

  sourceNationSlot90 = sourceNation;
  targetNationSlot92 = targetNation;
  proposedAmount98 = proposedAmount;
  maxAmount94 = maxAmount;
  commodityType96 = commodityType;
  suppressEventFlag9a = 0;

  TNumberText* purchaseControl = static_cast<TNumberText*>(ResolveControlByTag('purc'));
  purchaseControl->AssertValid();
  purchaseControl->maximumValue = maxAmount;
  purchaseControl->SetControlValue(proposedAmount, 0);

  acceptButtonA0 = static_cast<TControl*>(ResolveControlByTag('acce'));
  acceptButtonA0->AssertValid();
  acceptButtonA0->SetState(0, 0);
  rejectButtonA4 = static_cast<TControl*>(ResolveControlByTag('reje'));
  rejectButtonA4->AssertValid();
  rejectButtonA4->SetState(0, 0);

  TView* cluster = ResolveControlByTag('clus');
  cluster->AssertValid();
  TView* noMore = cluster->ResolveControlByTag('nomo');
  noMore->AssertValid();
  noMore->SetEnabled(1, 0);
  noMore->SetState(0, 0);

  selectionActive9e = false;
  detailedErrorFlag9d = proposedAmount > maxAmount;
  RefreshSelectedNationOrderCompatibilityInfo();
  ResolveControlByTag('shee')->RefreshControl();
}

// FUNCTION: IMPERIALISM 0x005bf740
void TOfferDeskPicture::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  int tag = sourceHandler->controlTag;
  if (commandId >= 0x2af8) {
    short selectionIndex = g_offerDeskSelectionIndexTable_00668568
        [commandId +
         g_pCityOrderCapabilityState->perTechUnlockFlag180[TTechMgr::kProductionOrderTechId] *
             0x11];
    if (!selectionActive9e) {
      UpdateTradeSelectionStateAndRefreshUiIfChanged(1);
    } else {
      g_pSfxPlaybackSystem->PlaySoundEffect(0x13f0, 0, 1);
    }
    TControl* bookControl = static_cast<TControl*>(ResolveControlByTag(kControlTagBook));
    bookControl->UpdateSelectionRect(selectionIndex);
  } else if (commandId == 0xa) {
    if (tag == kControlTagAcce || tag == kControlTagReje) {
      CreateNextTradeCommandAndFormatPrompt(tag);
    } else if (tag == kControlTagForM) {
      g_pHelpMgr->CycleTradeScreenMode0To2();
      RefreshSelectedNationOrderCompatibilityInfo();
    }
  } else if (commandId == 0x14 && tag == kTagDone) {
    UpdateTradeSelectionStateAndRefreshUiIfChanged(0);
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005bf860
void TOfferDeskPicture::ForwardParam(int param) {}

// Rebuild the 'info' text control with the trade-compatibility explanation for the current
// source nation (+0x90), target nation (+0x92) and commodity (+0x96), formatted at the
// current help detail level (g_pHelpMgr->helpIndexReady: 0 minimal, 1 concise verdict,
// >=2 detailed numbers). Text comes from string-resource groups 0x2711 (commodity names),
// 0x2740 and 0x2764 (compatibility phrases, bracket-expanded via scanBracketExpressions).
// Commodity types 0/1 (Cotton+Wool) are always evaluated as a combined pair.
// FUNCTION: IMPERIALISM 0x005bf930
void TOfferDeskPicture::RefreshSelectedNationOrderCompatibilityInfo() {
  TGreatPower* gp = g_apNationStates[sourceNationSlot90];
  TCity* city;
  if (gp == 0) {
    city = 0;
  } else {
    city = gp->city;
  }
  unsigned char notAligned = 0;
  unsigned char hasSurplus = 0;
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

  TStaticText* info = static_cast<TStaticText*>(ResolveControlByTag(0x696e666f /* 'info' */));
  info->AssertValid();
  info->SetTextAlignmentAndMaybeRefresh(-2, 0);

  {
    strTargetNation = g_pSimMgr->LoadNormalizedCredentialName(targetNationSlot92);
  }
  g_pSimMgr->GetStringPrelude(commodityType96, &strCommodity);

  short compat = g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
      sourceNationSlot90, targetNationSlot92);

  if (g_pHelpMgr->helpIndexReady == 0) {
    g_pSimMgr->GetString(0x2740, 9, &strFinal);
    info->SetTextAlignmentAndMaybeRefresh(1, 0);
  } else if (g_pHelpMgr->helpIndexReady == 1) {
    if (compat >= 1 &&
        g_apTerrainTypeDescriptorTable[targetNationSlot92]->IsEncodedNationSlotMinus200Equal(
            sourceNationSlot90) == 0) {
      notAligned = 1;
    }
    if (commodityType96 != 0 && commodityType96 != 1) {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(commodityType96));
      relDelta = gp->relationDeltaSnapshot[commodityType96];
      // TCity models the 23 per-commodity stock shorts as named fields; index off the first.
      stock = (&city->cityStockCottonB6)[commodityType96];
      needTgt = gp->needTargetByType[commodityType96];
    } else {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(0));
      relDelta = static_cast<short>(gp->relationDeltaSnapshot[1] + gp->relationDeltaSnapshot[0]);
      stock = static_cast<short>(city->cityStockCottonB6 + city->cityStockWoolB8);
      needTgt = static_cast<short>(gp->needTargetByType[1] + gp->needTargetByType[0]);
    }
    if (avail > stock + relDelta + needTgt) {
      hasSurplus = 1;
    }

    if (notAligned == 0 && hasSurplus == 0) {
      if (g_apTerrainTypeDescriptorTable[targetNationSlot92]->IsEncodedNationSlotMinus200Equal(
              sourceNationSlot90) != 0) {
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
      if (notAligned != 0) {
        g_pSimMgr->GetString(0x2764, (compat == 2) ? 1 : 2, &strTemplate);
        scanBracketExpressions(g_pSimMgr, &strNationClause, static_cast<LPCSTR>(strTemplate),
                               static_cast<LPCSTR>(strTargetNation));
      }
      g_pSimMgr->GetString(0x2764, hasSurplus != 0 ? 3 : 4, &strTemplate);
    }
    scanBracketExpressions(g_pSimMgr, &strTypeClause, static_cast<LPCSTR>(strTemplate),
                           static_cast<LPCSTR>(strCommodity));
    strFinal = strPrefix + strNationClause + strTypeClause;
  } else {
    CString strStatsIntro;
    CString strVerdict;
    if (commodityType96 != 0 && commodityType96 != 1) {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(commodityType96));
      relDelta = gp->relationDeltaSnapshot[commodityType96];
      stock = (&city->cityStockCottonB6)[commodityType96];
      needTgt = gp->needTargetByType[commodityType96];
    } else {
      avail = static_cast<short>(gp->ComputeProductionMetricForOrderKind(0));
      relDelta = static_cast<short>(gp->relationDeltaSnapshot[1] + gp->relationDeltaSnapshot[0]);
      stock = static_cast<short>(city->cityStockCottonB6 + city->cityStockWoolB8);
      needTgt = static_cast<short>(gp->needTargetByType[1] + gp->needTargetByType[0]);
    }
    strCityStock.Format(g_szDecimalFormat, static_cast<int>(stock));
    strNeedTarget.Format(g_szDecimalFormat, static_cast<int>(needTgt));
    strRelDelta.Format(g_szDecimalFormat, static_cast<int>(relDelta));
    strAvail.Format(g_szDecimalFormat, static_cast<int>(avail));
    if (targetNationSlot92 < 7) {
      g_pSimMgr->GetString(0x2764, 8, &strTemplate);
      scanBracketExpressions(g_pSimMgr, &strStatsIntro, static_cast<LPCSTR>(strTemplate),
                             static_cast<LPCSTR>(strTargetNation));
    } else {
      short dominant = g_pDiplomacyTurnStateManager->SelectBestMajorNationForMinorByStandingAndNeed(
          targetNationSlot92);
      {
        strDominantName = g_pSimMgr->LoadNormalizedCredentialName(dominant);
      }
      if (dominant == sourceNationSlot90) {
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
          g_apTerrainTypeDescriptorTable[targetNationSlot92]->IsEncodedNationSlotMinus200Equal(
              sourceNationSlot90) != 0
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
  bounds.left = bounds.left - 1;
  bounds.top = bounds.top - 1;
  RECT grown = bounds;
  RECT inval;
  ::CopyRect(&inval, &grown);
  info->ownerContext->InvalidateCityDialogRectRegion(&inval, 1);
  info->SetTextAndMaybeRefresh(&strFinal, 1);
}

// Reads the 'clus'->'nomo' checkbox state and the 'purc' quantity field, validates the
// quantity against the 'purc' control's own max, and on success dispatches the trade
// proposal (TTradeMgr), resets the accept/reject buttons, notifies the toolbar, and queues
// a new TNextTradeCommand. On an out-of-range quantity, shows an error and re-selects the
// 'purc' field's text instead. `actionCode` is the triggering button's FourCC tag; 'reje'
// forces the proposed quantity to 0 (skipping validation entirely).
// FUNCTION: IMPERIALISM 0x005c04f0
void TOfferDeskPicture::CreateNextTradeCommandAndFormatPrompt(int actionCode) {
  TView* clusterControl = ResolveControlByTag('clus');
  if (clusterControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x83b);
  }

  TAmtBarCluster* noMoreControl =
      static_cast<TAmtBarCluster*>(clusterControl->ResolveControlByTag('nomo'));
  if (noMoreControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x83d);
  }
  suppressEventFlag9a = noMoreControl->IsTradeControlAtMinimum();

  TNumberText* purchaseControl = static_cast<TNumberText*>(ResolveControlByTag('purc'));
  if (purchaseControl == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUTradeViews_0069AA94, 0x842);
  }
  proposedAmount98 = static_cast<short>(purchaseControl->UpdateControlCachedIntFromWindowText());

  bool quantityValid = true;
  if (actionCode == 'reje') {
    proposedAmount98 = 0;
  } else if (proposedAmount98 > purchaseControl->maximumValue || proposedAmount98 < 0) {
    quantityValid = false;
  }

  if (quantityValid) {
    g_pNationInteractionStateManager->DispatchProposalAmountSlot60(
        sourceNationSlot90, targetNationSlot92, proposedAmount98, maxAmount94, commodityType96,
        static_cast<char>(suppressEventFlag9a), 0);

    TView* acceptButton = ResolveControlByTag('acce');
    acceptButton->AssertValid();
    TView* rejectButton = ResolveControlByTag('reje');
    rejectButton->AssertValid();
    acceptButton->SetState(0, 0);
    rejectButton->SetState(0, 0);

    if (proposedAmount98 != 0) {
      TView* toolbar = g_pDisplayMgr->activeDialog->ResolveControlByTag('tool');
      if (toolbar != nullptr) {
        static_cast<TAmtBarCluster*>(toolbar)->SetMoveAmount(
            static_cast<short>(sourceNationSlot90));
      }
    }

    if (g_pSimMgr->multiplayerSessionRole != 2) {
      TNextTradeCommand* command = new TNextTradeCommand();
      command->InitializeRangePairFromDiplomacyConstants();
      g_pGlobalUiRootController->DispatchUiSelectionToHandler(command);
    }
  } else {
    CString errorMessage;
    CString localizedMessage;
    if (detailedErrorFlag9d != 0) {
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
  (void)point;
  (void)event;
  (void)origin;
  return 0;
}

// FUNCTION: IMPERIALISM 0x005c09d0
void TOfferDeskPicture::UpdateTradeSelectionStateAndRefreshUiIfChanged(int activate) {
  (void)activate;
}
