#include "game/ui_screens/TLonelyTileView.h"
#include "game/ui_tags_screens.h"

#include "game/ui_core/TMacViewMgr.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"
// SYNTHETIC: IMPERIALISM 0x00505a50
// TLonelyTileView::CreateObject

// SYNTHETIC: IMPERIALISM 0x00505ac0
// TLonelyTileView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TLonelyTileView, TView)

// FUNCTION: IMPERIALISM 0x00505ae0
TLonelyTileView::TLonelyTileView() : TView() {}

// SYNTHETIC: IMPERIALISM 0x00505b10
// TLonelyTileView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00505b40
TLonelyTileView::~TLonelyTileView() {}

// FUNCTION: IMPERIALISM 0x00505b60
void TLonelyTileView::Draw(RECT* rectBuffer) {
  (void)rectBuffer; // dead parameter in this override, like the other Draws
  CRect destRect;
  QueryContentBounds(&destRect);

  TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPictureF0;
  RECT srcRect;
  if (controlTag == kControlTagTile && mapUberPicture->invalidationFlag94 != 0) {
    TQuickDrawSurfaceContext* tileAtlasCtx = mapUberPicture->subview2A8->quickDrawSurface350;
    // The tile's transient marker-slot index selects a 64-pixel atlas column.
    int spriteX =
        static_cast<int>(g_pGlobalMapState->terrainStateTable[tileIndex60].markerSlotIndex10) << 6;
    srcRect.left = spriteX;
    srcRect.top = 0;
    srcRect.right = spriteX + 0x40;
    srcRect.bottom = 0x40;
    SetQuickDrawFillColor(0);
    BlitRectWithOptionalTransparency(tileAtlasCtx->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &destRect, 0, 0);
  } else if (controlTag == kControlTagTil2 && mapUberPicture->invalidationFlag94 != 0) {
    short variant = g_pGlobalMapState->LookupTileSpriteVariantOffsetByTerrainAndGate(tileIndex60);
    srcRect.left = variant;
    srcRect.top = 0;
    srcRect.right = variant + 0x40;
    srcRect.bottom = 0x40;
    SetQuickDrawFillColor(0);
    BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas668->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &destRect, 0, 0);
  } else {
    short variant = g_pGlobalMapState->LookupTileSpriteVariantOffsetByTerrainAndGate(tileIndex60);
    srcRect.left = variant;
    srcRect.top = 0;
    srcRect.right = variant + 0x40;
    srcRect.bottom = 0x40;
    SetQuickDrawFillColor(0);
    BlitRectWithOptionalTransparency(g_pMacViewMgr->atlas668->GetBlitSurface(),
                                     g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &srcRect,
                                     &destRect, 0, 0);
  }
  UpdatePaletteIndexWithDefaultFallback(0x13);
}
