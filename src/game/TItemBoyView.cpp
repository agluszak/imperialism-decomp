#include "game/TItemBoyView.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/mapped_flavor_text.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004af980
// TItemBoyView::`scalar deleting destructor'
TItemBoyView::~TItemBoyView() {}
// SYNTHETIC: IMPERIALISM 0x004af910
// TItemBoyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004af9d0
// TItemBoyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TItemBoyView, TView)

TItemBoyView::TItemBoyView() {}

// FUNCTION: IMPERIALISM 0x004af9f0
void TItemBoyView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CString label;
  CString kindText;
  CString countText;

  // field60 is re-read fresh at each site here (not cached in a local) -- matches the
  // original, which re-fetches `this->field60` for every access instead of keeping it
  // live in a register across these calls.
  short kindIdx = *reinterpret_cast<short*>(static_cast<char*>(field60));
  g_pSimMgr->GetStringPrelude(kindIdx, &kindText);

  short count = *reinterpret_cast<short*>(static_cast<char*>(field60) + 2);
  countText.Format(g_szDecimalFormat, count);

  CString templateText;
  g_pSimMgr->GetString(0x273c, 0x1d, &templateText);

  // Template expander: substitutes [0]/[1] brackets in templateText with countText and
  // kindText, writing the composed header into `label`.
  scanBracketExpressions(g_pSimMgr, &label, static_cast<const char*>(templateText),
                         static_cast<const char*>(countText), static_cast<const char*>(kindText));

  DrawItemHeaderAndIconRows(&label);
}

// FUNCTION: IMPERIALISM 0x004afb60
void TItemBoyView::DrawItemHeaderAndIconRows(CString* header) {
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xa, 0x2b6a);
  SetQuickDrawTextOriginWithContextOffset(0x1a, 0x14);
  DrawTextWithCachedQuickDrawStyleState(header);

  short* context = reinterpret_cast<short*>(field60);
  int perRow = (frameWidth34 - 0x3a) / context[1];
  if (perRow > 0x20) {
    perRow = 0x20;
  }

  int i = 0;
  int y = 0x3a;
  if (context[1] > 0) {
    do {
      short kindIdx = context[0];
      RECT srcRect = {kindIdx * 0x20, 0, (kindIdx + 1) * 0x20, 0x17};
      RECT dstRect = {y - 0x20, 0x19, y, 0x30};
      UpdatePaletteIndexWithDefaultFallback(0x10);
      // Item icon strip is cached at a different TMacViewMgr slot (+0x674) than the
      // Army/Navy boy views' level-icon strip (+0x694).
      TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
          *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x674) +
          4);
      BlitRectWithOptionalTransparency(iconStripSurface,
                                       g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                       &dstRect, 0x24, 0);
      ++i;
      y += perRow;
      // Ground truth re-reads field60 from `this` every iteration rather than caching
      // the context pointer/count across the (opaque) blit call.
      context = reinterpret_cast<short*>(field60);
    } while (i < context[1]);
  }

  SetQuickDrawStrokeColor(0x13);
}
