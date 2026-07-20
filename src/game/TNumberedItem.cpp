#include "game/TNumberedItem.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x005077c0
TNumberedItem::TNumberedItem() : TMegaPicture() {}

// FUNCTION: IMPERIALISM 0x00507850
void TNumberedItem::InitializeNumberedResourceItem(TView* panel, int* position, int* size,
                                                   short resourceIconIndex, short count) {
  InitializeUiResourceEntryFrameAndParent(panel->uiResourceContext40, panel, position, size, 5, 5,
                                          0);
  iconRowIndexAc = resourceIconIndex;
  badgeCountAe = count;
}

// SYNTHETIC: IMPERIALISM 0x00507700
// TNumberedItem::CreateObject

// SYNTHETIC: IMPERIALISM 0x005077a0
// TNumberedItem::GetRuntimeClass

// Binary descriptor base is TView (0x6495a0), not TMegaPicture — original macro arg.
IMPLEMENT_DYNCREATE(TNumberedItem, TView)

// SYNTHETIC: IMPERIALISM 0x00507800
// TNumberedItem::`scalar deleting destructor'
TNumberedItem::~TNumberedItem() {}

// Draws the numbered badge background (row iconRowIndexAc of a shared icon strip)
// then the badge count as decimal text, positioned to clear more digits' worth of
// space as the count grows past 1/2/3 digits.
// FUNCTION: IMPERIALISM 0x005078a0
void TNumberedItem::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  RECT srcRect = {iconRowIndexAc * 0x20, 0, iconRowIndexAc * 0x20 + 0x1f, 0x17};
  RECT dstRect = {0, 0, 0x1f, 0x17};
  ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback(0x10);
  TQuickDrawBlitSurface* badgeStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x674) + 4);
  BlitRectWithOptionalTransparency(badgeStripSurface,
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
