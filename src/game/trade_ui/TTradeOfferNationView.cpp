#include "game/trade_ui/TTradeOfferNationView.h"

#include "game/ui_screens/CString.h"
#include "game/city_ui/TLongintList.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005bd1a0
// TTradeOfferNationView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005bd1d0
TTradeOfferNationView::~TTradeOfferNationView() {}
// SYNTHETIC: IMPERIALISM 0x005bd1f0
// TTradeOfferNationView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bd260
// TTradeOfferNationView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeOfferNationView, TView)

// FUNCTION: IMPERIALISM 0x005bd2d0
void TTradeOfferNationView::Draw(RECT* rectBuffer) {
  CString finalText;
  CString templateText;
  CString valueText;
  CString offerNationName = g_pSimMgr->LoadNormalizedCredentialName(nationSlot62);

  short cellValue =
      g_pNationInteractionStateManager->categoryRows[categorySlot60].cells18[nationSlot62];
  if (cellValue == 1) {
    g_pSimMgr->GetString(0x2740, 7, &templateText);
    scanBracketExpressions(g_pSimMgr, &finalText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(offerNationName));
  } else {
    valueText.Format(g_szDecimalFormat, static_cast<int>(cellValue));
    g_pSimMgr->GetString(0x2740, 8, &templateText);
    scanBracketExpressions(g_pSimMgr, &finalText, static_cast<LPCSTR>(templateText),
                           static_cast<LPCSTR>(offerNationName), static_cast<LPCSTR>(valueText));
  }

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0x2b6a);
  SetQuickDrawTextOriginWithContextOffset(0, 8);
  DrawTextWithCachedQuickDrawStyleState(&finalText);

  TLongintList* nudgeList =
      g_pNationInteractionStateManager->AllocateAndPopulateLinkedValueCollectionFromRosterFilter(
          categorySlot60, nationSlot62);
  UpdatePaletteIndexWithDefaultFallback(0x10);
  for (int i = 1; i < 8; ++i) {
    if (i > nudgeList->GetSize()) {
      break;
    }
    long val = nudgeList->At(i);
    short srcLeft = static_cast<short>(val << 5);
    RECT srcRect = {srcLeft, 0, srcLeft + 0x20, 0x18};
    short dstLeft = static_cast<short>(i * 0x20 - 0x20);
    RECT dstRect = {dstLeft, 0, dstLeft + 0x20, 0x18};
    BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas680->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
  }
  SetQuickDrawStrokeColor(0xffffff);
  nudgeList->Free();
}
