#include "game/TMiniArmyView.h"

#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x004aad20
undefined TMiniArmyView::OrphanRetStub_004aad20() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x004aad40
// TMiniArmyView::`scalar deleting destructor'
TMiniArmyView::~TMiniArmyView() {}
// SYNTHETIC: IMPERIALISM 0x004aad90
// TMiniArmyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x004aae10
// TMiniArmyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniArmyView, TControl)

TMiniArmyView::TMiniArmyView() {}

// FUNCTION: IMPERIALISM 0x004aaeb0
void TMiniArmyView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  char* context = static_cast<char*>(field84);
  CString name = *reinterpret_cast<CString*>(context + 0x24);
  CString displayName = name;

  InitializeUiTextStyleDescriptorAndApplyQuickDraw(0, 0xc, 0x2b6a, 3);
  if (MeasureTextExtentWithCachedQuickDrawStyle(&displayName) > 100) {
    // Shrink the working copy one character at a time, appending an ellipsis, until the
    // "name..." form fits within 100px. displayName holds the last-dropped (pre-ellipsis)
    // form during the loop and the final ellipsized form afterward.
    CString truncated;
    do {
      truncated = displayName.Mid(0, displayName.GetLength() - 1);
      displayName = truncated;
      truncated += "...";
    } while (MeasureTextExtentWithCachedQuickDrawStyle(&truncated) > 100);
    displayName = truncated;
  }
  SetQuickDrawTextOriginWithContextOffset(0xa, 0xc);
  DrawTextWithCachedStyle(&displayName);

  short level = *reinterpret_cast<short*>(context + 0x34);
  short sVar1 = level / 0x19 + 1;
  if (sVar1 > 0x14) {
    sVar1 = 0x14;
  }
  // Level-bucket row within the icon strip: <5 -> row 0x1a, 5-14 -> row 18, >14 -> row 10.
  short sVar2 = (sVar1 < 5) ? 0x1a : ((sVar1 > 0xe) ? 10 : 18);

  TQuickDrawBlitSurface* iconStripSurface = reinterpret_cast<TQuickDrawBlitSurface*>(
      *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pStrategicMapViewSystem) + 0x694) + 4);
  RECT srcRect = {0, sVar2, sVar1 * 4 - 1, sVar2 + 7};
  RECT dstRect = {0x8c, 4, sVar1 * 4 + 0x8b, 0xb};
  UpdatePaletteIndexWithDefaultFallback(0x10);
  BlitRectWithOptionalTransparency(iconStripSurface,
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                   &dstRect, 0x24, 0);

  SetQuickDrawStrokeColor(0x13);
  SetQuickDrawTextOriginWithContextOffset(0x8a, 6);
  DrawCenteredGuideLineOnMapDc(0x8a, 0xc);
  DrawCenteredGuideLineOnMapDc(0xdc, 0xc);
  DrawCenteredGuideLineOnMapDc(0xdc, 6);
}

// FUNCTION: IMPERIALISM 0x004ab1d0
void TMiniArmyView::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {}
