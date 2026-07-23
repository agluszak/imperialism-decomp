#include "game/tactical_ui/TTechItemView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/assets/TAssetMgr.h"
#include "game/ui_widgets/TDeluxeText.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical_ui/TTechHistoryView.h"
#include "game/tactical_ui/TTechMgr.h"
#include "game/ui_screens/TTextPictureButton.h"
#include "game/ui_screens/TUpDownPictureButton.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
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
void TTechItemView::InitializeTechItem(TView* panel, int* offsetLayout, int* sizeLayout,
                                       int nationSlot, int techId) {
  CString techName;
  CString yearText;
  CString labelText;
  CString templateText;
  CString assembledText;

  InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, offsetLayout, sizeLayout,
                                          5, 5, 0);
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
    descButton->controlTag = kControlTagDesc; // 'desc'
    LoadUiStringByGroupAndIndexToControlObject(0x274f, 8, descButton);
  }

  COLORREF titleStyleFlags = 0;
  COLORREF shadowStyleFlags = 0;
  ResolveUiThemeColor(0x2b6a, &titleStyleFlags);
  ResolveUiThemeColor(0x2b68, &shadowStyleFlags);
  TextStyle textStyle;
  BuildUiTextStyleDescriptor(&textStyle, 0, 0xc, 0x2b6a);
  CRect zeroRect(0, 0, 0, 0);

  // Title: tech name + newline + availability year.
  {
    TDeluxeText* titleControl = new TDeluxeText();
    int titleOffset[2] = {0x4d, 0};
    int titleSize[2] = {0x69, 0x3f};
    titleControl->InitializeDeluxeText(this, titleOffset, titleSize, &zeroRect, &textStyle, -2);
    titleControl->textColor98 = titleStyleFlags;
    titleControl->shadowTextColor9C = shadowStyleFlags;
    titleControl->dropShadowEnabledA0 = true;
    g_pSimMgr->GetString(0x2712, static_cast<short>(techId), &techName);
    yearText.Format(g_szDecimalFormat,
                    0x717 + g_pCityOrderCapabilityState->prioritySlots04[techId] / 4);
    labelText = techName + "\n" + yearText;
    titleControl->UpdateTextEntrySharedString(&labelText);
    titleControl->CenterVertically(0);
  }

  // Description text.
  {
    TDeluxeText* descText = new TDeluxeText();
    int descOffset[2] = {0x127, 0};
    int descSize[2] = {0x10d, 0x3f};
    descText->InitializeDeluxeText(this, descOffset, descSize, &zeroRect, &textStyle, -2);
    descText->textColor98 = titleStyleFlags;
    descText->shadowTextColor9C = shadowStyleFlags;
    descText->dropShadowEnabledA0 = true;
    g_pSimMgr->GetString(0x274e, static_cast<short>(techId - 1), &labelText);
    descText->UpdateTextEntrySharedString(&labelText);
    descText->CenterVertically(0);
  }

  // Status area: completion date, buy button, or missing-prerequisites line.
  TTechMgr* techMgr = g_pCityOrderCapabilityState;
  if (techMgr->orderCapRows277[nationSlot].techStatusByTechId[techId] == 2) {
    TDeluxeText* dateControl = new TDeluxeText();
    int dateOffset[2] = {0xba, 0};
    int dateSize[2] = {0x53, 0x3f};
    dateControl->InitializeDeluxeText(this, dateOffset, dateSize, &zeroRect, &textStyle, 1);
    dateControl->textColor98 = titleStyleFlags;
    dateControl->shadowTextColor9C = shadowStyleFlags;
    dateControl->dropShadowEnabledA0 = true;
    g_pSimMgr->GetString(0x274f, 0, &templateText);
    yearText.Format(g_szDecimalFormat,
                    0x717 + techMgr->capRowsE4a6[nationSlot].completionYearOffsetByTechId[techId]);
    scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(yearText));
    dateControl->UpdateTextEntrySharedString(&assembledText);
    dateControl->CenterVertically(0);
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
    buyButton->controlTag = kControlTagPurc; // 'purc'
    LoadUiStringByGroupAndIndexToControlObject(0x274f, labelIndex, buyButton);
  } else {
    int missing1;
    int missing2;
    techMgr->SelectMissingTechItemPrerequisitesFromPair(techId, nationSlot, &missing1, &missing2);
    TDeluxeText* prereqControl = new TDeluxeText();
    int prereqOffset[2] = {0xbd, 0};
    int prereqSize[2] = {0x53, 0x3f};
    prereqControl->InitializeDeluxeText(this, prereqOffset, prereqSize, &zeroRect, &textStyle, 1);
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
    prereqControl->CenterVertically(0);
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
      // TTechHistoryView::PopulateTechHistory; the rest of the modal sequence
      // matches the pattern already ported elsewhere this session
      // (DispatchUiRuntimeMessage102CAndRefreshActiveView, TArmyUnitView::
      // HandleCrossUArmyViewsNameCommand).
      TWindow* node =
          static_cast<TWindow*>(g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(
              kTurnEventTechnologyHistory));
      TTechHistoryView* historyView =
          static_cast<TTechHistoryView*>(node->ResolveControlByTag(kControlTagDialog));
      historyView->AssertValid();
      historyView->PopulateTechHistory(static_cast<short>(techId64));

      POINT placement;
      g_pUiRuntimeContext->ComputeTurnEventDialogPlacementByCode(node, &placement);
      historyView->CaptureLayoutF0(reinterpret_cast<int*>(&placement), 0);
      node->SetModality(1);
      TDialogBehavior* behavior = node->GetDialogBehavior();
      if (behavior != nullptr) {
        behavior->defaultCommandCode = kControlTagOkay; // 'okay'
      }
      node->PoseModally();
      node->Close();
      node->Free();
    }
  }
  TView::DoEvent(commandId, sourceHandler, event);
}
