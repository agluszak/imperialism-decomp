#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

#include "game/core/CString.h"
#include "game/gfx/TAmbitApplication.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/ui_core/THelpMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/ui_core/TPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x0045d390
TTacticalToolbar::~TTacticalToolbar() {}

IMPLEMENT_DYNCREATE(TTacticalToolbar, TCluster)

// FUNCTION: IMPERIALISM 0x005ac840
void TTacticalToolbar::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TView* helpControl = FindSubView(kControlTagHelp);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x20, helpControl);
  TView* targControl = FindSubView(kControlTagTarg);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x21, targControl);
  TView* doneControl = FindSubView(kControlTagDone);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x22, doneControl);
  TView* retrControl = FindSubView(kControlTagRetr);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x23, retrControl);
  TView* autoControl = FindSubView(kControlTagAuto);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x24, autoControl);

  CString empty1(g_szEmptyString);
  SetControlHoverHelpText(empty1, ownerContext);
  CString empty2(g_szEmptyString);
  SetControlHoverHelpText(empty2, this);
}

// FUNCTION: IMPERIALISM 0x005ac950
void TTacticalToolbar::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  TQuickDrawBlitSurface* iconStripSurface =
      g_pMacViewMgr->tileOverlayStripWorlds[0]->GetBlitSurface();

  TArmyTacUnit* sideAUnit = static_cast<TArmyTacUnit*>(currentUnit);
  if (sideAUnit != NULL) {
    int qualityPercent = sideAUnit->sourceUnit->experiencePercent;
    short barWidth = static_cast<short>(sideAUnit->qualityLevel) * 11;
    if (qualityPercent % 100 > 0x31) {
      barWidth += 5;
    }
    if (barWidth != 0) {
      RECT srcRect = {0, 0, barWidth, 10};
      RECT dstRect = {2, 0x119, barWidth + 2, 0x123};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      BlitRectWithOptionalTransparency(iconStripSurface,
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                       &dstRect, 0x24, 0);
      SetQuickDrawStrokeColor(0x13);
    }
  }

  TArmyTacUnit* sideBUnit = otherSideCurrentUnit;
  if (sideBUnit != NULL) {
    short barWidth = static_cast<short>(sideBUnit->qualityLevel) * 11;
    int qualityPercent = sideBUnit->sourceUnit->experiencePercent;
    if (qualityPercent % 100 > 0x31) {
      barWidth += 5;
    }
    if (barWidth != 0) {
      RECT srcRect = {0, 0, barWidth, 10};
      RECT dstRect = {2, 0x159, barWidth + 2, 0x163};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      BlitRectWithOptionalTransparency(iconStripSurface,
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                       &dstRect, 0x24, 0);
      SetQuickDrawStrokeColor(0x13);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005acb50
void TTacticalToolbar::UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit) {
  currentUnit = unit;
  TPicture* currControl = static_cast<TPicture*>(FindSubView(kControlTagCurr));
  currControl->AssertValid();
  if (unit != 0) {
    currControl->SetPictureRsrcID(static_cast<short>(unit->unitType * 2 + 0xf1e + unit->side), 1);
    currControl->Show(1, 1);
  } else {
    currControl->Show(0, 1);
  }
  RECT labelRect;
  labelRect.left = 2;
  labelRect.top = 0x119;
  labelRect.right = 0x39;
  labelRect.bottom = 0x123;
  InvalidateCityDialogRectRegion(&labelRect, 1);
  CString unitName;
  if (unit != 0) {
    unit->AssertValid();
    unitName = static_cast<TArmyTacUnit*>(unit)->sourceUnit->name;
  }
  AssignSharedStringToTaggedControlAndProcessState(static_cast<const char*>(unitName),
                                                   kControlTagDialog);
}

// FUNCTION: IMPERIALISM 0x005acc90
void TTacticalToolbar::UpdateTacticalOtherSideUnitControl(TArmyTacUnit* unit) {
  otherSideCurrentUnit = unit;
  TPicture* tpicControl = static_cast<TPicture*>(FindSubView(kControlTagTpic));
  tpicControl->AssertValid();
  if (unit != 0) {
    tpicControl->SetPictureRsrcID(static_cast<short>(unit->unitType * 2 + 0xf1e + unit->side), 1);
    tpicControl->Show(1, 1);
  } else {
    tpicControl->Show(0, 1);
  }
  RECT portraitRect;
  portraitRect.left = 2;
  portraitRect.top = 0x159;
  portraitRect.right = 0x39;
  portraitRect.bottom = 0x163;
  InvalidateCityDialogRectRegion(&portraitRect, 1);
}

// FUNCTION: IMPERIALISM 0x005acd60
void TTacticalToolbar::SetActionMode(int mode) {
  if (mode == 0) {
    TView* targControl = FindSubView(kControlTagTarg);
    targControl->AssertValid();
    targControl->Show(0, 1);
    targControl->ViewEnable(0, 1);
    TPicture* doneControl = static_cast<TPicture*>(FindSubView(kControlTagDone));
    doneControl->AssertValid();
    doneControl->SetPictureRsrcID(0xed4, 1);
    TPicture* retrControl = static_cast<TPicture*>(FindSubView(kControlTagRetr));
    retrControl->AssertValid();
    retrControl->SetPictureRsrcID(0xed2, 1);
    TView* autoControl = FindSubView(kControlTagAuto);
    autoControl->AssertValid();
    autoControl->Show(0, 1);
    autoControl->ViewEnable(0, 1);
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x2e, FindSubView(kControlTagDone));
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x2f, FindSubView(kControlTagRetr));
  } else {
    TView* targControl = FindSubView(kControlTagTarg);
    targControl->AssertValid();
    targControl->Show(1, 1);
    targControl->ViewEnable(1, 1);
    TPicture* doneControl = static_cast<TPicture*>(FindSubView(kControlTagDone));
    doneControl->AssertValid();
    doneControl->SetPictureRsrcID(0xece, 1);
    TPicture* retrControl = static_cast<TPicture*>(FindSubView(kControlTagRetr));
    retrControl->AssertValid();
    retrControl->SetPictureRsrcID(0xed0, 1);
    TView* autoControl = FindSubView(kControlTagAuto);
    autoControl->AssertValid();
    autoControl->Show(1, 1);
    autoControl->ViewEnable(1, 1);
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x22, FindSubView(kControlTagDone));
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x23, FindSubView(kControlTagRetr));
  }
}

// FUNCTION: IMPERIALISM 0x005acf90
void TTacticalToolbar::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kControlTagDone:
    case kControlTagAuto:
    case kControlTagRetr:
    case kControlTagTarg:
      battle->HandleTacticalBattleCommandTag(tag);
      break;
    case kControlTagHelp:
      g_pHelpMgr->ShowLatestHelp();
      break;
    default:
      break;
    }
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
  g_pAmbitApplication->SetTarget(ownerContext);
}
