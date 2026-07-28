#include "game/trade_ui/TTradeBidNationView.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005bdaf0
// TTradeBidNationView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005bdb20
TTradeBidNationView::~TTradeBidNationView() {}
// SYNTHETIC: IMPERIALISM 0x005bdb40
// TTradeBidNationView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bdbb0
// TTradeBidNationView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeBidNationView, TView)

// FUNCTION: IMPERIALISM 0x005bdc20
void TTradeBidNationView::Draw(RECT* rectBuffer) {
  UpdatePaletteIndexWithDefaultFallback(0x10);
  short iconLeft = static_cast<short>(nationSlot << 5);
  RECT srcRect = {iconLeft, 0, iconLeft + 0x20, 0x18};
  RECT dstRect = {0, 0, 0x20, 0x18};
  BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas680->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);
  SetQuickDrawStrokeColor(0xffffff);

  CString label = g_pSimMgr->LoadNormalizedCredentialName(nationSlot);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b6a);
  SetQuickDrawTextOriginWithContextOffset(0x28, 0xc);
  DrawTextWithCachedQuickDrawStyleState(&label);

  if (nationSlot < 7 && g_pSimMgr->mode == 7) {
    short counter = g_apNationStates[nationSlot]->GetAvailableMerchantCapacity();
    label.Format(g_szDecimalFormat, static_cast<int>(counter));
    short measuredWidth = MeasureTextExtentWithCachedQuickDrawStyle(&label);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(frameWidth34 - measuredWidth - 4),
                                            0xc);
    DrawTextWithCachedQuickDrawStyleState(&label);
  }
}
