#include "game/ui_core/TNumberedItem.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// Binary descriptor base is TView (0x6495a0), not TMegaPicture — original macro arg.
IMPLEMENT_DYNCREATE(TNumberedItem, TView)

// FUNCTION: IMPERIALISM 0x005077c0
TNumberedItem::TNumberedItem() : TMegaPicture() {
  iconRowIndex = 0;
  badgeCount = 0;
}

// FUNCTION: IMPERIALISM 0x00507830
TNumberedItem::~TNumberedItem() {}

// FUNCTION: IMPERIALISM 0x00507850
void TNumberedItem::INumberedItem(TView* panel, int* position, int* size,
                                                   short resourceIconIndex, short count) {
  InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, position, size, 5, 5, 0);
  iconRowIndex = resourceIconIndex;
  badgeCount = count;
}

// FUNCTION: IMPERIALISM 0x005078a0
void TNumberedItem::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  RECT srcRect = {iconRowIndex * 0x20, 0, iconRowIndex * 0x20 + 0x1f, 0x17};
  RECT dstRect = {0, 0, 0x1f, 0x17};
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas674->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);

  UpdatePaletteIndexWithDefaultFallback(0x13);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 9, 0x2b67);
  short x;
  short y = static_cast<short>(frameHeight) - 5;
  if (badgeCount < 10) {
    x = static_cast<short>(frameWidth) - 8;
  } else if (badgeCount < 100) {
    x = static_cast<short>(frameWidth) - 0x10;
  } else {
    x = static_cast<short>(frameWidth) - 0x18;
  }
  SetQuickDrawTextOriginWithContextOffset(x, y);
  CString countText;
  countText.Format(g_szDecimalFormat, static_cast<int>(badgeCount));
  DrawTextWithCachedQuickDrawStyleState(&countText);
}
