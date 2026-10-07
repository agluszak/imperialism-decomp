#include "game/military_ui/TItemBoyView.h"

#include "game/battle_report_records.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x004af9b0
TItemBoyView::~TItemBoyView() {}

IMPLEMENT_DYNCREATE(TItemBoyView, TView)

// FUNCTION: IMPERIALISM 0x004af9f0
void TItemBoyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CString label;
  CString kindText;
  CString countText;

  short kindIdx = battleDetail->resourceType;
  g_pSimMgr->GetCommodityName(kindIdx, &kindText);

  short count = battleDetail->stockOrRequired;
  countText.Format(g_szDecimalFormat, count);

  CString templateText;
  g_pSimMgr->GetString(0x273c, 0x1d, &templateText);

  scanBracketExpressions(g_pSimMgr, &label, static_cast<const char*>(templateText),
                         static_cast<const char*>(countText), static_cast<const char*>(kindText));

  ActuallyDraw(&label);
}

// FUNCTION: IMPERIALISM 0x004afb60
void TItemBoyView::ActuallyDraw(CString* header) {
  ApplyTextStyle(0, 0xa, 0x2b6a);
  SetQuickDrawTextOriginWithContextOffset(0x1a, 0x14);
  DrawTextWithCachedQuickDrawStyleState(header);

  int perRow = (frameWidth - 0x3a) / battleDetail->stockOrRequired;
  if (perRow > 0x20) {
    perRow = 0x20;
  }

  int i = 0;
  int y = 0x3a;
  if (battleDetail->stockOrRequired > 0) {
    do {
      short kindIdx = battleDetail->resourceType;
      RECT srcRect = {kindIdx * 32, 0, (kindIdx + 1) * 32, 0x17};
      RECT dstRect = {y - 0x20, 0x19, y, 0x30};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      TQuickDrawBlitSurface* iconStripSurface = g_pMacViewMgr->commodityIconWorld->GetBlitSurface();
      BlitRectWithOptionalTransparency(iconStripSurface,
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                       &dstRect, 0x24, 0);
      ++i;
      y += perRow;
    } while (i < battleDetail->stockOrRequired);
  }

  SetQuickDrawStrokeColor(0x13);
}
