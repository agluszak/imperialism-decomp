#include "game/TLonelyTileView.h"

#include "game/TMacViewMgr.h"
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

// FUNCTION: IMPERIALISM 0x00505ae0
TLonelyTileView::TLonelyTileView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x00505b10
// TLonelyTileView::`scalar deleting destructor'
TLonelyTileView::~TLonelyTileView() {}

// FUNCTION: IMPERIALISM 0x00505b60
void TLonelyTileView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CRect destRect;
  QueryContentBounds(&destRect);

  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  RECT srcRect;
  TQuickDrawBlitSurface* srcSurface;
  if (controlTag == 0x74696c65 /* 'tile' */ && mapUberPicture->invalidationFlag94 != 0) {
    // The tile-sprite atlas surface hangs off subview2A8+0x350 (a TQuickDrawSurfaceContext
    // that isn't a recovered TMapUberPicture member, so it's read via a raw offset).
    TQuickDrawSurfaceContext* tileAtlasCtx = *reinterpret_cast<TQuickDrawSurfaceContext**>(
        reinterpret_cast<char*>(mapUberPicture->subview2A8) + 0x350);
    // The sprite-variant byte lives in g_pGlobalMapState's per-tile descriptor table
    // (36-byte records) at +0x10; the atlas column is variant * 64.
    char* tileTable = *reinterpret_cast<char**>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc);
    int spriteX =
        static_cast<int>(*reinterpret_cast<signed char*>(tileTable + tileIndex60 * 36 + 0x10)) << 6;
    srcRect.left = spriteX;
    srcRect.top = 0;
    srcRect.right = spriteX + 0x40;
    srcRect.bottom = 0x40;
    SetQuickDrawFillColor(0);
    srcSurface = tileAtlasCtx->GetBlitSurface();
  } else if (controlTag == 0x74696c32 /* 'til2' */ && mapUberPicture->invalidationFlag94 != 0) {
    short variant = g_pGlobalMapState->LookupTileSpriteVariantOffsetByTerrainAndGate(tileIndex60);
    srcRect.left = variant;
    srcRect.top = 0;
    srcRect.right = variant + 0x40;
    srcRect.bottom = 0x40;
    SetQuickDrawFillColor(0);
    srcSurface = g_pStrategicMapViewSystem->atlas668->GetBlitSurface();
  } else {
    short variant = g_pGlobalMapState->LookupTileSpriteVariantOffsetByTerrainAndGate(tileIndex60);
    srcRect.left = variant;
    srcRect.top = 0;
    srcRect.right = variant + 0x40;
    srcRect.bottom = 0x40;
    SetQuickDrawFillColor(0);
    srcSurface = g_pStrategicMapViewSystem->atlas668->GetBlitSurface();
  }

  BlitRectWithOptionalTransparency(srcSurface, g_pActiveQuickDrawSurfaceContext->GetBlitSurface(),
                                   &srcRect, &destRect, 0, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}
