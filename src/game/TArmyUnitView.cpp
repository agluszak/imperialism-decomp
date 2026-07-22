#include "game/TArmyUnitView.h"

#include "game/TAssetMgr.h"
#include "game/TArmyCheckBox.h"
#include "game/TDialogBehavior.h"
#include "game/TDisplayMgr.h"
#include "game/TEditText.h"
#include "game/TMapUberPicture.h"
#include "game/TMilitaryUnit.h"
#include "game/TNumberedArrowButton.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/TStaticText.h"
#include "game/TViewMgr.h"
#include "game/TWindow.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004a9450
// TArmyUnitView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a94c0
// TArmyUnitView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyUnitView, TView)

// FUNCTION: IMPERIALISM 0x004a94e0
TArmyUnitView::TArmyUnitView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x004a9510
// TArmyUnitView::`scalar deleting destructor'
TArmyUnitView::~TArmyUnitView() {}

// FUNCTION: IMPERIALISM 0x004a95b0
void TArmyUnitView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  CString unitTypeName;
  CString descriptor;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  unitTypeName = militaryUnit60->name24;
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x10);
  DrawTextWithCachedQuickDrawStyleState(&unitTypeName);

  // Localized unit descriptor: string group 0x2746 substituting a literal 7 for the
  // special-cased unit-type 0xe, otherwise group 0x272c substituting the unit-type code.
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(2, 9, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  int unitTypeCode = militaryUnit60->unitOrder;
  if (unitTypeCode == 0xe) {
    g_pSimMgr->GetString(0x2746, 7, &descriptor);
  } else {
    g_pSimMgr->GetString(0x272c, unitTypeCode, &descriptor);
  }
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x1f);
  DrawTextWithCachedQuickDrawStyleState(&descriptor);
  SetQuickDrawFillColor(0);

  short level = militaryUnit60->field_34;
  short sVar1 = level / 0x19 + 1;
  if (sVar1 > 0x14) {
    sVar1 = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short sVar2 = (sVar1 < 5) ? 0x1a : ((sVar1 > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);

  {
    RECT srcRect = {0, sVar2, sVar1 * 4 - 1, sVar2 + 7};
    RECT dstRect = {0x43, 0x26, sVar1 * 4 + 0x42, 0x2d};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
  }

  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x41, 0x21);
  DrawCenteredGuideLineOnMapDc(0x41, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x21);

  short xpPercent = militaryUnit60->field_38;
  short barWidth = (xpPercent / 100) * 0xb;
  if (xpPercent % 100 > 0x31) {
    barWidth += 5;
  }
  if (barWidth != 0) {
    RECT srcRect = {0, 0, barWidth, 10};
    RECT dstRect = {0x94, 0x18, barWidth + 0x94, 0x22};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    SetQuickDrawStrokeColor(0x13);
  }
}

// FUNCTION: IMPERIALISM 0x004a9990
void TArmyUnitView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler->controlTag == kControlTagChec) {
    short availableCountDelta = 0;
    if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) {
      // Ctrl held: force the unit into escort-order mode (0xe) unless already there.
      if (militaryUnit60->unitOrder != 0xe) {
        if (militaryUnit60->unitOrder == 0) {
          availableCountDelta = -1;
        }
        militaryUnit60->SetOrders(static_cast<UnitOrder>(0xe), -1);
      }
    } else if (militaryUnit60->unitOrder != 0) {
      militaryUnit60->SetOrders(kUnitOrderIdle, -1);
      availableCountDelta = 1;
    } else {
      militaryUnit60->SetOrders(static_cast<UnitOrder>(3), -1);
      availableCountDelta = -1;
    }

    RECT invalidateRect = {0x40, 0x18, 0x108, 0x24};
    InvalidateCityDialogRectRegion(&invalidateRect, 1);

    TMapUberPicture* mapPicture = g_pUiRuntimeContext->mapUberPictureF0;
    TView* activeToolbar = mapPicture->categoryPages[mapPicture->activeUnitCategoryIndex96];
    if (activeToolbar != nullptr) {
      unsigned int arrowTag =
          kTagArmyRatioMin + g_awTacticalUnitCategoryCodeBySlot[militaryUnit60->orderType];
      TNumberedArrowButton* arrow =
          static_cast<TNumberedArrowButton*>(activeToolbar->ResolveControlByTag(arrowTag));
      arrow->SetValue(static_cast<short>(arrow->value84 + availableCountDelta), 1);
      g_pUiRuntimeContext->RefreshMainViewNationIndicatorForCurrentTurnEvent();
    }
  } else if (sourceHandler->controlTag == kControlTagUpgr) {
    if (militaryUnit60->Upgrade()) {
      TView* sourceView = static_cast<TView*>(sourceHandler);
      sourceView->SetEnabled(0, 1);
      SetControlHoverHelpTextAltEntry(CString(g_pMiniCivSharedText_0064cb18), sourceView);

      TArmyCheckBox* checkControl =
          static_cast<TArmyCheckBox*>(ResolveControlByTag(kControlTagChec));
      checkControl->AssertValid();
      checkControl->iconStripHorizontalOffset88 =
          (checkControl->checkedFrameOffsetApplied8c + militaryUnit60->orderType * 2) << 6;
      checkControl->RefreshControl();

      TStaticText* tbr1 = static_cast<TStaticText*>(
          g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagTbr1));
      tbr1->GetNextHandler();
      tbr1->SetTextAlignmentAndMaybeRefresh(static_cast<short>(g_pSimMgr->GetActiveNationId()), 0);
    } else {
      CString msg;
      g_pSimMgr->GetString(0x2745, 3, &msg);
      g_pUiRuntimeContext->ModalMessage(msg, g_ptArmyOrderModalMessage, 2, 0);
    }
  } else if (sourceHandler->controlTag == kControlTagName) {
    HandleCrossUArmyViewsNameCommand();
  }
  TView::DoEvent(commandId, sourceHandler, event);
}

// TArmyUnitView-only despite the generic Ghidra symbol name (0x4a9ca0) -- confirmed by the
// caller: TShipView::DoEvent's 'name' branch actually calls a different function
// (RunEngineerOrderNameEditDialogAndApply, 0x565a40), not this one, so there is no
// Runs the unit-rename dialog: seeds an edit box with militaryUnit60's current name, runs
// it modally, and (unless cancelled) commits the typed text back to the represented unit.
// FUNCTION: IMPERIALISM 0x004a9ca0
void TArmyUnitView::HandleCrossUArmyViewsNameCommand() {
  TWindow* node = static_cast<TWindow*>(
      g_pUiViewManager->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNameUnit));
  if (node == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag(s_SourcePathUArmyViews_00695858, 0x204);
  }

  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TStaticText* titleControl = static_cast<TStaticText*>(node->ResolveControlByTag(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextFromStringResource(0x2746, 1, 1);
  titleControl->textStyle78 = style;

  TEditText* nameControl = static_cast<TEditText*>(node->ResolveControlByTag(kControlTagName));
  nameControl->AssertValid();
  nameControl->maxCharacterCount = 0x18;
  CString editedName;
  editedName = militaryUnit60->name24;
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&editedName, 1);
  nameControl->textStyle78 = style;

  node->SetModality(1);
  TDialogBehavior* behavior = node->GetDialogBehavior();
  if (behavior != nullptr) {
    behavior->defaultCommandCode = 0x6f6b6179; // 'okay'
  }
  int modalResult = node->PoseModally();
  nameControl->GetCurrentText(&editedName);
  if (modalResult != 0x636e636c /* 'cncl' */) {
    militaryUnit60->name24 = editedName;
  }
  RefreshControl();
}
