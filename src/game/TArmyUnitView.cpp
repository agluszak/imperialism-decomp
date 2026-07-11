#include "game/TArmyUnitView.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x004a9450
// TArmyUnitView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a94c0
// TArmyUnitView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyUnitView, TView)

TArmyUnitView::TArmyUnitView() {}

// SYNTHETIC: IMPERIALISM 0x004a9510
// TArmyUnitView::`scalar deleting destructor'
TArmyUnitView::~TArmyUnitView() {}

// FUNCTION: IMPERIALISM 0x004a95b0
void TArmyUnitView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  char* context = static_cast<char*>(field60);

  ApplyUiTextStyleAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  CString unitTypeName = *reinterpret_cast<CString*>(context + 0x24);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x10);
  DrawTextWithCachedStyle(&unitTypeName);

  // TODO(class-recovery): the localized descriptor string (one of two format
  // templates, 0x2746 with a numeric substitution when the unit-type code == 0xe,
  // else 0x272c) is built via g_pLocalizationTable's vtable slot 0x84.4 -- same
  // unrecovered-class gap as TDeluxeText::BuildCityViewProductionControls_Impl.
  ApplyUiTextStyleAndSyncColor(2, 9, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x1f);
  SetQuickDrawFillColor(0);

  short level = *reinterpret_cast<short*>(context + 0x34);
  short sVar1 = level / 0x19 + 1;
  if (sVar1 > 0x14) {
    sVar1 = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short sVar2 = (sVar1 < 5) ? 0x1a : ((sVar1 > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);

  {
    RECT srcRect = {0, sVar2, sVar1 * 4 - 1, sVar2 + 7};
    RECT dstRect = {0x43, 0x26, sVar1 * 4 + 0x42, 0x2d};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
  }

  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x41, 0x21);
  DrawCenteredGuideLineOnMapDc(0x41, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x27);
  DrawCenteredGuideLineOnMapDc(0x93, 0x21);

  short xpPercent = *reinterpret_cast<short*>(context + 0x38);
  short barWidth = (xpPercent / 100) * 0xb;
  if (xpPercent % 100 > 0x31) {
    barWidth += 5;
  }
  if (barWidth != 0) {
    RECT srcRect = {0, 0, barWidth, 10};
    RECT dstRect = {0x94, 0x18, barWidth + 0x94, 0x22};
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(iconStripSurface,
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &dstRect, 0x24, 0);
    SetQuickDrawStrokeColor(0x13);
  }
}

// FUNCTION: IMPERIALISM 0x004a9990
void TArmyUnitView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}
