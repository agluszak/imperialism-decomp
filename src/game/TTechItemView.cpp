#include "game/TTechItemView.h"

#include "game/TDeluxeText.h"
#include "game/TSimMgr.h"
#include "game/TTechMgr.h"
#include "game/TTextPictureButton.h"
#include "game/TUpDownPictureButton.h"
#include "game/TViewMgr.h"
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
    titleControl->cursorThemeCode98 = titleStyleFlags;
    titleControl->cursorThemeCode9c = shadowStyleFlags;
    titleControl->fieldA0 = 1;
    g_pSimMgr->GetString(0x2712, static_cast<short>(techId), &techName);
    yearText.Format(g_szDecimalFormat,
                    0x717 + g_pCityOrderCapabilityState->prioritySlots04[techId] / 4);
    labelText = techName + "\n" + yearText;
    titleControl->UpdateTextEntrySharedString(&labelText);
    titleControl->RecenterTextFromMeasuredWidthAndMaybeInvalidate(0);
  }

  // Description text.
  {
    TDeluxeText* descText = new TDeluxeText();
    int descOffset[2] = {0x127, 0};
    int descSize[2] = {0x10d, 0x3f};
    descText->ConstructTDeluxeTextBaseState(this, descOffset, descSize, &zeroRect, &textStyle, -2);
    descText->cursorThemeCode98 = titleStyleFlags;
    descText->cursorThemeCode9c = shadowStyleFlags;
    descText->fieldA0 = 1;
    g_pSimMgr->GetString(0x274e, static_cast<short>(techId - 1), &labelText);
    descText->UpdateTextEntrySharedString(&labelText);
    descText->RecenterTextFromMeasuredWidthAndMaybeInvalidate(0);
  }

  // Status area: completion date, buy button, or missing-prerequisites line.
  TTechMgr* techMgr = g_pCityOrderCapabilityState;
  if (techMgr->orderCapRows277[nationSlot].techStatusByTechId[techId] == 2) {
    TDeluxeText* dateControl = new TDeluxeText();
    int dateOffset[2] = {0xba, 0};
    int dateSize[2] = {0x53, 0x3f};
    dateControl->ConstructTDeluxeTextBaseState(this, dateOffset, dateSize, &zeroRect, &textStyle,
                                               1);
    dateControl->cursorThemeCode98 = titleStyleFlags;
    dateControl->cursorThemeCode9c = shadowStyleFlags;
    dateControl->fieldA0 = 1;
    g_pSimMgr->GetString(0x274f, 0, &templateText);
    yearText.Format(g_szDecimalFormat,
                    0x717 + techMgr->capRowsE4a6[nationSlot].completionYearOffsetByTechId[techId]);
    scanBracketExpressions(g_pSimMgr, &assembledText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(yearText));
    dateControl->UpdateTextEntrySharedString(&assembledText);
    dateControl->RecenterTextFromMeasuredWidthAndMaybeInvalidate(0);
  } else if (techMgr->AreTechItemPrerequisitePairCompleted(techId, nationSlot)) {
    short labelIndex;
    if (techMgr->orderCapRows277[nationSlot].techStatusByTechId[techId] == 1) {
      g_pSimMgr->GetString(0x274f, 3, &labelText);
      labelIndex = 0xa;
    } else {
      g_pSimMgr->FormatIntegerString(g_anTechItemResearchCostByTechId[techId], &labelText);
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
    prereqControl->cursorThemeCode98 = titleStyleFlags;
    prereqControl->cursorThemeCode9c = shadowStyleFlags;
    prereqControl->fieldA0 = 1;
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
    prereqControl->RecenterTextFromMeasuredWidthAndMaybeInvalidate(0);
  }
  ApplySharedStringToGlobalControlTag(CString(g_szEmptyString), controlTag);
}

// FUNCTION: IMPERIALISM 0x005b1e20
void TTechItemView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
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
          g_pUiRuntimeContext->DispatchLocalizedUiMessageWithTemplateA13A0(
              msg, &g_cstrTechItemMessageStore, 2, 0);
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
        g_pSimMgr->FormatIntegerString(g_anTechItemResearchCostByTechId[techId64], &label);
        purchaseButton->buttonText = label;
        purchaseButton->RefreshControl();
        LoadUiStringAndDispatchSharedMessageCommand(0x274f, 9, purchaseButton);
      }
    } else if (sourceHandler->controlTag == kControlTagDesc) {
      // TODO: resolves the turn-event dialog node for message context 0x942 (a TWindow,
      // per this session's established dialog-node pattern), restyles its 'DLOG' child via
      // TTechHistoryView::ConstructTTechHistoryViewBaseState(techId64) -- a real,
      // currently-unowned 633-byte constructor (0x5b22c0) -- then runs the dialog modally
      // through the same TWindow sequence already ported elsewhere this session
      // (ComputeTurnEventDialogPlacementByCode, CaptureLayoutF0, SetField84(1),
      // GetEmbeddedDialogBehavior()->defaultCommandCode='okay',
      // ExecuteViewModalStateWithPushPopChain, CallVoidSlotA0, Free). Left unmodeled because
      // wiring the ConstructTTechHistoryViewBaseState call requires giving it a real curated
      // signature in original_entities.csv first (its current auto-generated stub signature
      // is a bare no-arg placeholder) -- a separate curation step, not a guess.
    }
  }
  TView::HandleEvent(commandId, sourceHandler, event);
}
