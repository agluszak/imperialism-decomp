#include "game/military_ui/TMiniArmyView.h"
#include "game/military_ui/TSuperArmyRoster.h"
#include "game/ui_tags_common.h"

#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TEventHandler.h"
#include "game/military/TMilitaryUnit.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/military_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004aad20
void TMiniArmyView::Hilite() {}

// FUNCTION: IMPERIALISM 0x004aad70
TMiniArmyView::~TMiniArmyView() {}

IMPLEMENT_DYNCREATE(TMiniArmyView, TControl)

// FUNCTION: IMPERIALISM 0x004aae30
void TMiniArmyView::InitializeForMilitaryUnit(TView* panel, int* offsetLayout, int* sizeLayout,
                                              TMilitaryUnit* unit) {
  InitializeUiResourceEntryFrameAndParent(0, panel, offsetLayout, sizeLayout, 5, 5, 0);
  militaryUnit = unit;
  eventNumber = 0x22;
  SetControlHoverHelpText(g_pMiniCivSharedText, this);
}

// FUNCTION: IMPERIALISM 0x004aaeb0
void TMiniArmyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CString name = militaryUnit->name;
  CString displayName = name;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xc, 0x2b6a, 3);
  if (MeasureTextExtentWithCachedQuickDrawStyle(&displayName) > 100) {
    CString truncated;
    do {
      truncated = displayName.Mid(0, displayName.GetLength() - 1);
      displayName = truncated;
      truncated += "...";
    } while (MeasureTextExtentWithCachedQuickDrawStyle(&truncated) > 100);
    displayName = truncated;
  }
  SetQuickDrawTextOriginWithContextOffset(0xa, 0xc);
  DrawTextWithCachedQuickDrawStyleState(&displayName);

  short level = militaryUnit->strength;
  short barLength = level / 25 + 1;
  if (barLength > 0x14) {
    barLength = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short barSpriteRow = (barLength < 5) ? 0x1a : ((barLength > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface =
      g_pMacViewMgr->tileOverlayStripWorlds[0]->GetBlitSurface();
  RECT srcRect = {0, barSpriteRow, barLength * 4 - 1, barSpriteRow + 7};
  RECT dstRect = {0x8c, 4, barLength * 4 + 0x8b, 0xb};
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(iconStripSurface,
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);

  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x8a, 6);
  DrawCenteredGuideLineOnMapDc(0x8a, 0xc);
  DrawCenteredGuideLineOnMapDc(0xdc, 0xc);
  DrawCenteredGuideLineOnMapDc(0xdc, 6);
}

// FUNCTION: IMPERIALISM 0x004ab1d0
void TMiniArmyView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (sourceHandler->controlTag == kControlTagUpgr) {
    if (militaryUnit->Upgrade()) {
      TView* sourceView = static_cast<TView*>(sourceHandler);
      sourceView->Show(0, 1);
      SetControlHoverHelpTextAltEntry(CString(g_pMiniCivSharedText), sourceView);
      TStaticText* tbr1 =
          static_cast<TStaticText*>(g_pDisplayMgr->activeDialog->FindSubView(kControlTagTbr1));
      tbr1->AssertValid();
      tbr1->SetJustification(static_cast<short>(g_pSimMgr->GetPlayerCountry()), false);
    } else {
      CString msg;
      g_pSimMgr->GetString(0x2745, 3, &msg);
      g_pViewMgr->ModalMessage(msg, g_ptArmyOrderModalMessage, 2, 0);
    }
  } else if (sourceHandler == this) {
    TSuperArmyRoster* roster = static_cast<TSuperArmyRoster*>(ownerContext);
    roster->AssertValid();
    roster->selectedCityRecordIndex = militaryUnit->tileIndex;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
