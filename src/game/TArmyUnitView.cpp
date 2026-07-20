#include "game/TArmyUnitView.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/TSimMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"
// SYNTHETIC: IMPERIALISM 0x004a9450
// TArmyUnitView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004a94c0
// TArmyUnitView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyUnitView, TView)

// FUNCTION: IMPERIALISM 0x004a94e0
TArmyUnitView::TArmyUnitView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x004a9510
// TArmyUnitView::`scalar deleting destructor'
TArmyUnitView::~TArmyUnitView() {}

// FUNCTION: IMPERIALISM 0x004a95b0
void TArmyUnitView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  char* context = static_cast<char*>(field60);

  CString unitTypeName;
  CString descriptor;

  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 0xc, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  unitTypeName = *reinterpret_cast<CString*>(context + 0x24);
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x10);
  DrawTextWithCachedQuickDrawStyleState(&unitTypeName);

  // Localized unit descriptor: string group 0x2746 substituting a literal 7 for the
  // special-cased unit-type 0xe, otherwise group 0x272c substituting the unit-type code.
  ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(2, 9, 0);
  SetQuickDrawColorAndSyncGlobals(0x1c474b);
  int unitTypeCode = *reinterpret_cast<int*>(context + 8);
  if (unitTypeCode == 0xe) {
    g_pSimMgr->GetString(0x2746, 7, &descriptor);
  } else {
    g_pSimMgr->GetString(0x272c, unitTypeCode, &descriptor);
  }
  SetQuickDrawTextOriginWithContextOffset(0x40, 0x1f);
  DrawTextWithCachedQuickDrawStyleState(&descriptor);
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
