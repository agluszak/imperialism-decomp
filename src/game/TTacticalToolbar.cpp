#include "game/TTacticalToolbar.h"

#include "game/CString.h"
#include "game/TAmbitApplication.h"
#include "game/TArmyTacUnit.h"
#include "game/THelpMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalUnit.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_text_label_helpers_decls.h"

// 0x5c4910, ported in ui_text_label_helpers.cpp.
void LoadUiStringAndDispatchSharedMessageCommand(short group, short index, TView* control);

// SYNTHETIC: IMPERIALISM 0x0045d360
// TTacticalToolbar::`scalar deleting destructor'
TTacticalToolbar::~TTacticalToolbar() {}
// SYNTHETIC: IMPERIALISM 0x005ac780
// TTacticalToolbar::CreateObject

// SYNTHETIC: IMPERIALISM 0x005ac820
// TTacticalToolbar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalToolbar, TCluster)

TTacticalToolbar::TTacticalToolbar() {}

// FUNCTION: IMPERIALISM 0x005ac840
void TTacticalToolbar::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  TView* helpControl = ResolveControlByTag(kControlTagHelp);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x20, helpControl);
  TView* targControl = ResolveControlByTag(kControlTagTarg);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x21, targControl);
  TView* doneControl = ResolveControlByTag(kTagDone);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x22, doneControl);
  TView* retrControl = ResolveControlByTag(kControlTagRetr);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x23, retrControl);
  TView* autoControl = ResolveControlByTag(kControlTagAuto);
  LoadUiStringByGroupAndIndexToControlObject(0x273d, 0x24, autoControl);

  CString empty1(g_szEmptyString);
  SetControlHoverHelpText(empty1, ownerContext);
  CString empty2(g_szEmptyString);
  SetControlHoverHelpText(empty2, this);
}

// Draws each side's xp progress bar (bar width = qualityLevel * 11, +5 rounding bump
// past .50) from the shared per-level icon strip, same idiom as
// TArmyBoyView/TArmyUnitView::Draw.
// FUNCTION: IMPERIALISM 0x005ac950
void TTacticalToolbar::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);

  TArmyTacUnit* sideAUnit = static_cast<TArmyTacUnit*>(currentUnit8C);
  if (sideAUnit != nullptr) {
    int qualityPercent = sideAUnit->sourceUnit38->field_38;
    short barWidth = static_cast<short>(sideAUnit->qualityLevel10) * 0xb;
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

  TArmyTacUnit* sideBUnit = otherSideCurrentUnit90;
  if (sideBUnit != nullptr) {
    short barWidth = static_cast<short>(sideBUnit->qualityLevel10) * 0xb;
    int qualityPercent = sideBUnit->sourceUnit38->field_38;
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

// Stores the selected unit, updates the 'curr' portrait control (bitmap
// 0xf1e + unitType*2 + side), and writes the unit's name into the dialog label.
// FUNCTION: IMPERIALISM 0x005acb50
void TTacticalToolbar::UpdateTacticalCurrentUnitControlAndDialogLabel(TTacticalUnit* unit) {
  currentUnit8C = unit;
  TPicture* currControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagCurr));
  currControl->AssertValid();
  if (unit != 0) {
    currControl->SetPictureResourceIdAndRefresh(
        static_cast<short>(unit->unitTypeC * 2 + 0xf1e + unit->side20), 1);
    currControl->SetEnabled(1, 1);
  } else {
    currControl->SetEnabled(0, 1);
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
    // Army tactical units carry the source TMilitaryUnit whose display name feeds the
    // dialog label (the slot receives TArmyTacUnit in the army battle).
    unitName = static_cast<TArmyTacUnit*>(unit)->sourceUnit38->name24;
  }
  AssignSharedStringToTaggedControlAndProcessState(static_cast<const char*>(unitName),
                                                   kControlTagDialog);
}

// FUNCTION: IMPERIALISM 0x005acc90
void TTacticalToolbar::UpdateTacticalOtherSideUnitControl(TArmyTacUnit* unit) {
  otherSideCurrentUnit90 = unit;
  TPicture* tpicControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagTpic));
  tpicControl->AssertValid();
  if (unit != 0) {
    tpicControl->SetPictureResourceIdAndRefresh(
        static_cast<short>(unit->unitTypeC * 2 + 0xf1e + unit->side20), 1);
    tpicControl->SetEnabled(1, 1);
  } else {
    tpicControl->SetEnabled(0, 1);
  }
  RECT portraitRect;
  portraitRect.left = 2;
  portraitRect.top = 0x159;
  portraitRect.right = 0x39;
  portraitRect.bottom = 0x163;
  InvalidateCityDialogRectRegion(&portraitRect, 1);
}

// FUNCTION: IMPERIALISM 0x005acd60
void TTacticalToolbar::ConfigureTacticalTargetDoneRetreatAutoControls(int mode) {
  if (mode == 0) {
    // Deployment phase: 'targ'/'auto' disarmed, 'done'/'retr' show the setup bitmaps
    // and the setup label strings (group 0x273d, indexes 0x2e/0x2f).
    TView* targControl = ResolveControlByTag(kControlTagTarg);
    targControl->AssertValid();
    targControl->SetEnabled(0, 1);
    targControl->SetState(0, 1);
    TPicture* doneControl = static_cast<TPicture*>(ResolveControlByTag(kTagDone));
    doneControl->AssertValid();
    doneControl->SetPictureResourceIdAndRefresh(0xed4, 1);
    TPicture* retrControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagRetr));
    retrControl->AssertValid();
    retrControl->SetPictureResourceIdAndRefresh(0xed2, 1);
    TView* autoControl = ResolveControlByTag(kControlTagAuto);
    autoControl->AssertValid();
    autoControl->SetEnabled(0, 1);
    autoControl->SetState(0, 1);
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x2e, ResolveControlByTag(kTagDone));
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x2f, ResolveControlByTag(kControlTagRetr));
  } else {
    // Live battle: 'targ'/'auto' armed, 'done'/'retr' show the battle bitmaps and the
    // battle label strings (indexes 0x22/0x23).
    TView* targControl = ResolveControlByTag(kControlTagTarg);
    targControl->AssertValid();
    targControl->SetEnabled(1, 1);
    targControl->SetState(1, 1);
    TPicture* doneControl = static_cast<TPicture*>(ResolveControlByTag(kTagDone));
    doneControl->AssertValid();
    doneControl->SetPictureResourceIdAndRefresh(0xece, 1);
    TPicture* retrControl = static_cast<TPicture*>(ResolveControlByTag(kControlTagRetr));
    retrControl->AssertValid();
    retrControl->SetPictureResourceIdAndRefresh(0xed0, 1);
    TView* autoControl = ResolveControlByTag(kControlTagAuto);
    autoControl->AssertValid();
    autoControl->SetEnabled(1, 1);
    autoControl->SetState(1, 1);
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x22, ResolveControlByTag(kTagDone));
    LoadUiStringAndDispatchSharedMessageCommand(0x273d, 0x23, ResolveControlByTag(kControlTagRetr));
  }
}

// FUNCTION: IMPERIALISM 0x005acf90
void TTacticalToolbar::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    unsigned int tag = sourceHandler->controlTag;
    switch (tag) {
    case kTagDone:
    case kControlTagAuto:
    case kControlTagRetr:
    case kControlTagTarg:
      battle88->HandleTacticalBattleCommandTag(tag);
      break;
    case kControlTagHelp:
      g_pHelpMgr->SelectAndActivatePendingEventForCurrentView();
      break;
    default:
      break;
    }
  }
  TCluster::DoEvent(commandId, sourceHandler, event);
  g_pGlobalUiRootController->SetTarget(ownerContext);
}
