#include "game/TTechItemView.h"

#include "game/TAssetMgr.h"
#include "game/TDeluxeText.h"
#include "game/TDialogBehavior.h"
#include "game/TSimMgr.h"
#include "game/TTechHistoryView.h"
#include "game/TTechMgr.h"
#include "game/TTextPictureButton.h"
#include "game/TUpDownPictureButton.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005b1200
// TTechItemView::`scalar deleting destructor'
TTechItemView::~TTechItemView() {}
// SYNTHETIC: IMPERIALISM 0x005b1250
// TTechItemView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005b12c0
// TTechItemView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTechItemView, TView)

// FUNCTION: IMPERIALISM 0x005b12e0
void TTechItemView::ConstructTTechItemViewBaseState(TView* panel, int* offsetLayout,
                                                    int* sizeLayout, int nationSlot, int techId) {
  CString techName;
  CString yearText;
  CString labelText;
  CString templateText;
  CString assembledText;

  InitializeUiResourceEntryFrameAndParent(panel->uiResourceContext40, panel, offsetLayout,
                                          sizeLayout, 5, 5, 0);
  nationSlot60 = nationSlot;
  techId64 = techId;

  // 'desc' picture button showing the tech illustration.
  {
    TUpDownPictureButton* descButton = new TUpDownPictureButton();
    int picOffset[2] = {0, 0};
    int picSize[2] = {0x40, 0x3f};
    descButton->InitializePictureEntryBaseAndRefresh(this, picOffset, picSize, 5, 5,
                                                     static_cast<short>(techId * 2 + 0x8ff));
    descButton->SetState(1, 0);
    descButton->controlTag = 0x64657363; // 'desc'
    LoadUiStringByGroupAndIndexToControlObject(0x274f, 8, descButton);
  }

  int titleStyleFlags = 0;
  int shadowStyleFlags = 0;
  MapUiThemeCodeToStyleFlags(0x2b6a, &titleStyleFlags);
  MapUiThemeCodeToStyleFlags(0x2b68, &shadowStyleFlags);
  TUiTextStyleDescriptor textStyle;
  BuildUiTextStyleDescriptor(&textStyle, 0, 0xc, 0x2b6a);
  CRect zeroRect(0, 0, 0, 0);

  // Title: tech name + newline + availability year.
  {
    TDeluxeText* titleControl = new TDeluxeText();
    int titleOffset[2] = {0x4d, 0};
    int titleSize[2] = {0x69, 0x3f};
    titleControl->ConstructTDeluxeTextBaseState(this, titleOffset, titleSize, &zeroRect, &textStyle,
                                                -2);
    titleControl->textColor98 = titleStyleFlags;
    titleControl->shadowTextColor9C = shadowStyleFlags;
    titleControl->dropShadowEnabledA0 = true;
    g_pSimMgr->GetString(0x2712, static_cast<short>(techId), &techName);
    yearText.Format(g_szDecimalFormat,
                    0x717 + g_pCityOrderCapabilityState->prioritySlots04[techId] / 4);
    labelText = techName + "\n" + yearText;
    titleControl->UpdateTextEntrySharedString(&labelText);
    titleControl->RecenterTextVerticallyFromMeasuredHeightAndMaybeInvalidate(0);
  }

  // Description text.
  {
    TDeluxeText* descText = new TDeluxeText();
    int descOffset[2] = {0x127, 0};
    int descSize[2] = {0x10d, 0x3f};
    descText->ConstructTDeluxeTextBaseState(this, descOffset, descSize, &zeroRect, &textStyle, -2);
    descText->textColor98 = titleStyleFlags;
    descText->shadowTextColor9C = shadowStyleFlags;
    descText->dropShadowEnabledA0 = true;
    g_pSimMgr->GetString(0x274e, static_cast<short>(techId - 1), &labelText);
    descText->UpdateTextEntrySharedString(&labelText);
    descText->RecenterTextVerticallyFromMeasuredHeightAndMaybeInvalidate(0);
  }

  // Status area: completion date, buy button, or missing-prerequisites line.
  TTechMgr* techMgr = g_pCityOrderCapabilityState;
  if (techMgr->orderCapRows277[nationSlot].techStatusByTechId[techId] == 2) {
    TDeluxeText* dateControl = new TDeluxeText();
    int dateOffset[2] = {0xba, 0};
    int dateSize[2] = {0x53, 0x3f};
    dateControl->ConstructTDeluxeTextBaseState(this, dateOffset, dateSize, &zeroRect, &textStyle,
                                               1);
    dateControl->textColor98 = titleStyleFlags;
    dateControl->shadowTextColor9C = shadowStyleFlags;
    dateControl->dropShadowEnabledA0 = true;
    g_pSimMgr->GetString(0x274f, 0, &templateText);
    yearText.Format(g_szDecimalFormat,
                    0x717 + techMgr->capRowsE4a6[nationSlot].completionYearOffsetByTechId[techId]);
    scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(yearText));
    dateControl->UpdateTextEntrySharedString(&assembledText);
    dateControl->RecenterTextVerticallyFromMeasuredHeightAndMaybeInvalidate(0);
  } else if (techMgr->AreTechItemPrerequisitePairCompleted(techId, nationSlot)) {
    short labelIndex;
    if (techMgr->orderCapRows277[nationSlot].techStatusByTechId[techId] == 1) {
      g_pSimMgr->GetString(0x274f, 3, &labelText);
      labelIndex = 0xa;
    } else {
      g_pSimMgr->NumToCurrency(g_anTechItemResearchCostByTechId[techId], &labelText);
      labelIndex = 9;
    }
    TTextPictureButton* buyButton = new TTextPictureButton();
    int buyOffset[2] = {0xba, 0x12};
    int buySize[2] = {0x53, 0x18};
    buyButton->InitializeTextPictureButtonAndTextStyle(this, buyOffset, buySize, 0x8ff, &labelText,
                                                       0xc, 0x2b6a, 0x2b68);
    buyButton->SetState(1, 0);
    buyButton->controlTag = 0x70757263; // 'purc'
    LoadUiStringByGroupAndIndexToControlObject(0x274f, labelIndex, buyButton);
  } else {
    int missing1;
    int missing2;
    techMgr->SelectMissingTechItemPrerequisitesFromPair(techId, nationSlot, &missing1, &missing2);
    TDeluxeText* prereqControl = new TDeluxeText();
    int prereqOffset[2] = {0xbd, 0};
    int prereqSize[2] = {0x53, 0x3f};
    prereqControl->ConstructTDeluxeTextBaseState(this, prereqOffset, prereqSize, &zeroRect,
                                                 &textStyle, 1);
    prereqControl->textColor98 = titleStyleFlags;
    prereqControl->shadowTextColor9C = shadowStyleFlags;
    prereqControl->dropShadowEnabledA0 = true;
    if (nationSlot == 0) {
      g_pSimMgr->GetString(0x274f, 2, &templateText);
      g_pSimMgr->GetString(0x2712, static_cast<short>(missing1), &labelText);
      scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(labelText));
    } else {
      g_pSimMgr->GetString(0x274f, 1, &templateText);
      g_pSimMgr->GetString(0x2712, static_cast<short>(missing1), &labelText);
      g_pSimMgr->GetString(0x2712, static_cast<short>(missing2), &techName);
      scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                             static_cast<LPCSTR>(labelText), static_cast<LPCSTR>(techName));
    }
    prereqControl->UpdateTextEntrySharedString(&assembledText);
    prereqControl->RecenterTextVerticallyFromMeasuredHeightAndMaybeInvalidate(0);
  }
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), controlTag);
}

// FUNCTION: IMPERIALISM 0x005b1e20
void TTechItemView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 10) {
    if (sourceHandler->controlTag == kControlTagPurc) {
      TTextPictureButton* purchaseButton = static_cast<TTextPictureButton*>(sourceHandler);
      TTechMgr* techMgr = g_pCityOrderCapabilityState;
      if (techMgr->orderCapRows277[nationSlot60].techStatusByTechId[techId64] == 0) {
        short activeNationId = g_pSimMgr->GetActiveNationId();
        int availableBudget = g_apNationStates[activeNationId]->ComputeAvailableDiplomacyBudget();
        if (g_anTechItemResearchCostByTechId[techId64] > availableBudget) {
          CString msg;
          g_pSimMgr->GetString(0x2745, 3, &msg);
          g_pUiRuntimeContext->ModalMessage(msg, g_ptTechItemModalMessage, 2, 0);
        } else {
          CString label;
          g_pSimMgr->GetString(0x274f, 3, &label);
          techMgr->ApplyTechItemPurchaseCostAndState(techId64, nationSlot60);
          purchaseButton->buttonText = label;
          purchaseButton->RefreshControl();
          LoadUiStringAndDispatchSharedMessageCommand(0x274f, 0xa, purchaseButton);
        }
      } else {
        techMgr->RefundTechItemPurchaseCostAndClearState(techId64, nationSlot60);
        CString label;
        g_pSimMgr->NumToCurrency(g_anTechItemResearchCostByTechId[techId64], &label);
        purchaseButton->buttonText = label;
        purchaseButton->RefreshControl();
        LoadUiStringAndDispatchSharedMessageCommand(0x274f, 9, purchaseButton);
      }
    } else if (sourceHandler->controlTag == kControlTagDesc) {
      // Turn-event dialog root for the tech-history popup (a TWindow, per this session's
      // established dialog-node pattern). Its 'DLOG' child is restyled via
      // TTechHistoryView::ConstructTTechHistoryViewBaseState; the rest of the modal sequence
      // matches the pattern already ported elsewhere this session
      // (DispatchUiRuntimeMessage102CAndRefreshActiveView, TArmyUnitView::
      // HandleCrossUArmyViewsNameCommand).
      TWindow* node = static_cast<TWindow*>(
          g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(0x942));
      TTechHistoryView* historyView =
          static_cast<TTechHistoryView*>(node->ResolveControlByTag(kControlTagGold /* 'DLOG' */));
      historyView->AssertValid();
      historyView->ConstructTTechHistoryViewBaseState(static_cast<short>(techId64));

      POINT placement;
      g_pUiRuntimeContext->ComputeTurnEventDialogPlacementByCode(node, &placement);
      historyView->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
      node->SetModality(1);
      TDialogBehavior* behavior = node->GetDialogBehavior();
      if (behavior != nullptr) {
        behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
      }
      node->PoseModally();
      node->Close();
      node->Free();
    }
  }
  TView::DoEvent(commandId, sourceHandler, event);
}
