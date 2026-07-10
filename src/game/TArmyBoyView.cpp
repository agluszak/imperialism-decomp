#include "game/TArmyBoyView.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x004aeb50
// TArmyBoyView::`scalar deleting destructor'
TArmyBoyView::~TArmyBoyView() {}
// SYNTHETIC: IMPERIALISM 0x004aeae0
// TArmyBoyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004aeba0
// TArmyBoyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyBoyView, TView)

TArmyBoyView::TArmyBoyView() {}

// FUNCTION: IMPERIALISM 0x004aebc0
void TArmyBoyView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  char* context = static_cast<char*>(field60);
  short level = *reinterpret_cast<short*>(context + 2);

  ApplyUiTextStyleAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x17);
  CString nameString(context + 4);
  DrawTextWithCachedStyle(&nameString);
  SetQuickDrawFillColor(0);

  // The blit source surface is a per-level icon strip cached on TMacViewMgr; that
  // field isn't recovered yet, so it's read via a raw offset like the rest of this
  // function's still-untyped context object.
  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);

  if (level < 1) {
    // TODO(class-recovery): the real body builds a localized "in training" string via
    // g_pLocalizationTable's vtable slot 0x10.4 (same unrecovered-class gap as
    // TDeluxeText::BuildCityViewProductionControls_Impl / TTaskForce's format-string
    // expander) before measuring/drawing it centered. Left unimplemented rather than
    // guessed.
  } else {
    short sVar1 = level / 0x19 + 1;
    if (sVar1 > 0x14) {
      sVar1 = 0x14;
    }
    // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
    short sVar2 = (sVar1 < 5) ? 0x1a : ((sVar1 > 0xe) ? 10 : 18);
    RECT srcRect = {0, sVar2, sVar1 * 4 - 1, sVar2 + 7};
    RECT dstRect = {0x43, 0x1f, sVar1 * 4 + 0x42, 0x26};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
  }

  SetQuickDrawFillColor(0);
  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x41, 0x21);
  DrawCenteredGuideLineOnMapDc(0x41, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x21);

  short xpPercent = *reinterpret_cast<short*>(context + 0x24);
  short barWidth = xpPercent * 0xb;
  if (xpPercent % 100 > 0x31) {
    barWidth += 5;
  }
  if (barWidth != 0) {
    RECT srcRect = {0, 0, barWidth, 10};
    RECT dstRect = {0x94, 0x1f, barWidth + 0x94, 0x29};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    SetQuickDrawStrokeColor(0x13);
  }
}
