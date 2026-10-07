#include "game/military/TArmyUnitView.h"
#include "game/ui_tags_common.h"

#include "game/assets/TAssetMgr.h"
#include "game/military_ui/TArmyCheckBox.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TEditText.h"
#include "game/map/TMapUberPicture.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_widgets/TNumberedArrowButton.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/military_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TArmyUnitView, TView)

// FUNCTION: IMPERIALISM 0x004a94e0
TArmyUnitView::TArmyUnitView() : TView() {}

// FUNCTION: IMPERIALISM 0x004a9540
TArmyUnitView::~TArmyUnitView() {}

// FUNCTION: IMPERIALISM 0x004a9560
void TArmyUnitView::IArmyUnitView(TView* panel, int* offsetLayout, int* sizeLayout,
                                  int sizeDeterminerX, int sizeDeterminerY, TMilitaryUnit* unit) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, sizeDeterminerX,
                                          sizeDeterminerY, 0);
  militaryUnit = unit;
}

// FUNCTION: IMPERIALISM 0x004a95b0
void TArmyUnitView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws

  CString unitTypeName;
  CString descriptor;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  unitTypeName = militaryUnit->name;
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x10);
  DrawTextWithCachedQuickDrawStyleState(&unitTypeName);

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(2, 9, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  int unitTypeCode = militaryUnit->unitOrder;
  if (unitTypeCode == 0xe) {
    g_pSimMgr->GetString(0x2746, 7, &descriptor);
  } else {
    g_pSimMgr->GetString(0x272c, unitTypeCode, &descriptor);
  }
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x1f);
  DrawTextWithCachedQuickDrawStyleState(&descriptor);
  SetQuickDrawFillColor(0);

  short level = militaryUnit->strength;
  short barLength = level / 25 + 1;
  if (barLength > 0x14) {
    barLength = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short barSpriteRow = (barLength < 5) ? 0x1a : ((barLength > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface =
      g_pMacViewMgr->tileOverlayStripWorlds[0]->GetBlitSurface();

  {
    RECT srcRect = {0, barSpriteRow, barLength * 4 - 1, barSpriteRow + 7};
    RECT dstRect = {0x43, 0x26, barLength * 4 + 0x42, 0x2d};
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

  short xpPercent = militaryUnit->experiencePercent;
  short barWidth = (xpPercent / 100) * 11;
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
      if (militaryUnit->unitOrder != 0xe) {
        if (militaryUnit->unitOrder == 0) {
          availableCountDelta = -1;
        }
        militaryUnit->SetOrders(static_cast<UnitOrder>(0xe), -1);
      }
    } else if (militaryUnit->unitOrder != 0) {
      militaryUnit->SetOrders(kUnitOrderIdle, -1);
      availableCountDelta = 1;
    } else {
      militaryUnit->SetOrders(static_cast<UnitOrder>(3), -1);
      availableCountDelta = -1;
    }

    RECT invalidateRect = {0x40, 0x18, 0x108, 0x24};
    InvalidateCityDialogRectRegion(&invalidateRect, 1);

    TMapUberPicture* mapPicture = g_pViewMgr->mapUberPicture;
    TView* activeToolbar = mapPicture->categoryPages[mapPicture->activeUnitCategoryIndex];
    if (activeToolbar != NULL) {
      unsigned int arrowTag =
          kControlTagArmyRatioFirst + g_awTacticalUnitCategoryCodeBySlot[militaryUnit->orderType];
      TNumberedArrowButton* arrow =
          static_cast<TNumberedArrowButton*>(activeToolbar->FindSubView(arrowTag));
      arrow->SetValue(static_cast<short>(arrow->number + availableCountDelta), true);
      g_pViewMgr->RefreshMainViewNationIndicatorForCurrentTurnEvent();
    }
  } else if (sourceHandler->controlTag == kControlTagUpgr) {
    if (militaryUnit->Upgrade()) {
      TView* sourceView = static_cast<TView*>(sourceHandler);
      sourceView->Show(0, 1);
      SetControlHoverHelpTextAltEntry(CString(g_pMiniCivSharedText), sourceView);

      TArmyCheckBox* checkControl = static_cast<TArmyCheckBox*>(FindSubView(kControlTagChec));
      checkControl->AssertValid();
      checkControl->iconStripHorizontalOffset =
          (checkControl->checkedFrameOffsetApplied + militaryUnit->orderType * 2) << 6;
      checkControl->RefreshControl();

      TStaticText* tbr1 =
          static_cast<TStaticText*>(g_pDisplayMgr->activeDialog->FindSubView(kControlTagTbr1));
      tbr1->AssertValid();
      tbr1->SetJustification(static_cast<short>(g_pSimMgr->GetPlayerCountry()), false);
    } else {
      CString msg;
      g_pSimMgr->GetString(0x2745, 3, &msg);
      g_pViewMgr->ModalMessage(msg, g_ptArmyOrderModalMessage, 2, 0);
    }
  } else if (sourceHandler->controlTag == kControlTagName) {
    RenameUnit();
  }
  TView::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x004a9ca0
void TArmyUnitView::RenameUnit() {
  TWindow* node = g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventNameUnit);
  if (node == NULL) {
    FailNilPointerWithAssert(s_SourcePathUArmyViews, 0x204);
  }

  TextStyle style;
  BuildUiTextStyleDescriptor(&style, 0, 0xc, 0x2b6a);

  TStaticText* titleControl = static_cast<TStaticText*>(node->FindSubView(kControlTagTitl));
  titleControl->AssertValid();
  titleControl->SetTextWithStrListID(0x2746, 1, true);
  titleControl->textStyle = style;

  TEditText* nameControl = static_cast<TEditText*>(node->FindSubView(kControlTagName));
  nameControl->AssertValid();
  nameControl->maxCharacterCount = 0x18;
  CString editedName;
  editedName = militaryUnit->name;
  nameControl->InitDialogWindowAndSyncTitleIfChanged(&editedName, 1);
  nameControl->textStyle = style;

  node->SetModality(true);
  TDialogBehavior* behavior = node->GetDialogBehavior();
  if (behavior != NULL) {
    behavior->defaultCommandCode = kControlTagOkay; // 'okay'
  }
  int modalResult = node->PoseModally();
  nameControl->GetCurrentText(&editedName);
  if (modalResult != kControlTagCncl) {
    militaryUnit->name = editedName;
  }
  RefreshControl();
}
