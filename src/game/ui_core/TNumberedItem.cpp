#include "game/ui_core/TNumberedItem.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00507700
// TNumberedItem::CreateObject

// SYNTHETIC: IMPERIALISM 0x005077a0
// TNumberedItem::GetRuntimeClass

// Binary descriptor base is TView (0x6495a0), not TMegaPicture — original macro arg.
IMPLEMENT_DYNCREATE(TNumberedItem, TView)

// FUNCTION: IMPERIALISM 0x005077c0
TNumberedItem::TNumberedItem() : TMegaPicture() {
  iconRowIndexAc = 0;
  badgeCountAe = 0;
}

// SYNTHETIC: IMPERIALISM 0x00507800
// TNumberedItem::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00507830
TNumberedItem::~TNumberedItem() {}

// FUNCTION: IMPERIALISM 0x00507850
void TNumberedItem::InitializeNumberedResourceItem(TView* panel, int* position, int* size,
                                                   short resourceIconIndex, short count) {
  InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, position, size, 5, 5, 0);
  iconRowIndexAc = resourceIconIndex;
  badgeCountAe = count;
}

// Draws the numbered badge background (row iconRowIndexAc of a shared icon strip)
// then the badge count as decimal text, positioned to clear more digits' worth of
// space as the count grows past 1/2/3 digits.
// FUNCTION: IMPERIALISM 0x005078a0
void TNumberedItem::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  RECT srcRect = {iconRowIndexAc * 0x20, 0, iconRowIndexAc * 0x20 + 0x1f, 0x17};
  RECT dstRect = {0, 0, 0x1f, 0x17};
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(g_pStrategicMapViewSystem->atlas674->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);

  UpdatePaletteIndexWithDefaultFallback(0x13);
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 9, 0x2b67);
  short x;
  short y = static_cast<short>(frameHeight38) - 5;
  if (badgeCountAe < 10) {
    x = static_cast<short>(frameWidth34) - 8;
  } else if (badgeCountAe < 100) {
    x = static_cast<short>(frameWidth34) - 0x10;
  } else {
    x = static_cast<short>(frameWidth34) - 0x18;
  }
  SetQuickDrawTextOriginWithContextOffset(x, y);
  CString countText;
  countText.Format(g_szDecimalFormat, static_cast<int>(badgeCountAe));
  DrawTextWithCachedQuickDrawStyleState(&countText);
}
