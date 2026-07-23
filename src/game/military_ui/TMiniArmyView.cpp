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
#include "game/globals/prelude.h"
#include "game/globals/military_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004aad20
void TMiniArmyView::Hilite() {}

// SYNTHETIC: IMPERIALISM 0x004aad40
// TMiniArmyView::`scalar deleting destructor'
TMiniArmyView::~TMiniArmyView() {}
// SYNTHETIC: IMPERIALISM 0x004aad90
// TMiniArmyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004aae10
// TMiniArmyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniArmyView, TControl)

TMiniArmyView::TMiniArmyView() {}

// FUNCTION: IMPERIALISM 0x004aaeb0
void TMiniArmyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CString name = militaryUnit84->name24;
  CString displayName = name;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xc, 0x2b6a, 3);
  if (MeasureTextExtentWithCachedQuickDrawStyle(&displayName) > 100) {
    // Shrink the working copy one character at a time, appending an ellipsis, until the
    // "name..." form fits within 100px. displayName holds the last-dropped (pre-ellipsis)
    // form during the loop and the final ellipsized form afterward.
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

  short level = militaryUnit84->field_34;
  short sVar1 = level / 0x19 + 1;
  if (sVar1 > 0x14) {
    sVar1 = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short sVar2 = (sVar1 < 5) ? 0x1a : ((sVar1 > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface =
      g_pStrategicMapViewSystem->atlas694[0]->GetBlitSurface();
  RECT srcRect = {0, sVar2, sVar1 * 4 - 1, sVar2 + 7};
  RECT dstRect = {0x8c, 4, sVar1 * 4 + 0x8b, 0xb};
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
    if (militaryUnit84->Upgrade()) {
      TView* sourceView = static_cast<TView*>(sourceHandler);
      sourceView->SetEnabled(0, 1);
      SetControlHoverHelpTextAltEntry(CString(g_pMiniCivSharedText_0064cb18), sourceView);
      TStaticText* tbr1 = static_cast<TStaticText*>(
          g_pDisplayMgr->activeDialog->ResolveControlByTag(kControlTagTbr1));
      tbr1->GetNextHandler();
      tbr1->SetTextAlignmentAndMaybeRefresh(static_cast<short>(g_pSimMgr->GetActiveNationId()), 0);
    } else {
      CString msg;
      g_pSimMgr->GetString(0x2745, 3, &msg);
      g_pUiRuntimeContext->ModalMessage(msg, g_ptArmyOrderModalMessage, 2, 0);
    }
  } else if (sourceHandler == this) {
    TSuperArmyRoster* roster = static_cast<TSuperArmyRoster*>(ownerContext);
    roster->AssertValid();
    roster->selectedIndex84 = militaryUnit84->tileIndex06;
  }
  TControl::DoEvent(commandId, sourceHandler, event);
}
