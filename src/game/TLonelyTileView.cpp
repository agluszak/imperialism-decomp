#include "game/TLonelyTileView.h"

#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/UiRuntimeContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x00505a50
// TLonelyTileView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00505ac0
// TLonelyTileView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLonelyTileView, TView)

TLonelyTileView::TLonelyTileView() {}

// SYNTHETIC: IMPERIALISM 0x00505b10
// TLonelyTileView::`scalar deleting destructor'
TLonelyTileView::~TLonelyTileView() {}

// FUNCTION: IMPERIALISM 0x00505b60
void TLonelyTileView::ApplyRectSlot110(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other ApplyRectSlot110s
  RECT destRect;
  QueryContentBounds(&destRect);

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  if (controlTag == 0x74696c65 /* 'tile' */ && mapUberPicture->invalidationFlag94 != 0) {
    // TODO(class-recovery): this branch's blit source is
    // mapUberPicture->subview2A8's own +0x350 field -- subview2A8's concrete pointee
    // class (beyond TMapUberPicture) isn't recovered.
  } else if (controlTag == 0x74696c32 /* 'til2' */ && mapUberPicture->invalidationFlag94 != 0) {
    g_pGlobalMapState->LookupTileSpriteVariantOffsetByTerrainAndGate(tileIndex60);
    // TODO(class-recovery): blit source is *(g_pStrategicMapViewSystem + 0x668) + 4 --
    // that TMacViewMgr field isn't recovered yet.
  } else {
    g_pGlobalMapState->LookupTileSpriteVariantOffsetByTerrainAndGate(tileIndex60);
    // TODO(class-recovery): same unrecovered TMacViewMgr field as the 'til2' branch.
  }
  // TODO(class-recovery): every branch converges on
  // BlitRectWithOptionalTransparency(srcSurface, g_pActiveQuickDrawSurfaceContext's
  // blit surface, srcRect, &destRect, 0, 0) then
  // UpdatePaletteIndexWithDefaultFallback(0x13); left unmodeled since the source
  // surface/rect above aren't recovered yet and destRect alone isn't enough to fake it.
  (void)destRect;
}
