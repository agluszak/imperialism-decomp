#include "game/TTacArmyView.h"
#include "game/TWindow.h"

#include "game/CDib.h"
#include "game/TEventHandler.h"
#include "game/TMapMgr.h"
#include "game/TTacticalBattle.h"
#include "game/TAnimation.h"
#include "game/TAnimator.h"
#include "game/TViewMgr.h"
#include "game/TArmyBattle.h"
#include "game/TArmyTacUnit.h"
#include "game/TDisplayMgr.h"
#include "game/TPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/TTacticalPlayer.h"
#include "game/TTacticalToolbar.h"
#include "game/TTacticalUnit.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_guards.h"
#include "game/quickdraw_regions.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/ui_invalidation_guard.h"

// The original repeats this DIB vertical-flip adjustment before every atlas blit;
// defined inline so MSVC5 (/Ob1) inlines it back to the original's straight-line form.
static inline void OffsetRectForSurfaceDibFlip(TQuickDrawSurfaceContext* ctx, RECT* r) {
  if (ctx->blitSurface.surfaceDib != 0) {
    int height = ctx->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (height < 1) {
      height = -height;
    }
    OffsetRect(r, 0, (height - r->top) - r->bottom);
  }
}

// SYNTHETIC: IMPERIALISM 0x0045d310
// TTacArmyView::`scalar deleting destructor'
TTacArmyView::~TTacArmyView() {}
// SYNTHETIC: IMPERIALISM 0x005a9cf0
// TTacArmyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a9d70
// TTacArmyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacArmyView, TTacticalBattleView)

TTacArmyView::TTacArmyView() {}

// Live battle-view initializer (not a real constructor despite the symbols.csv name):
// caches the tactical tile / sprite metric globals, (re)allocates the offscreen
// battlefield surface and renders the per-composition backdrop bitmap
// (compositionClass + 0xf0a) into it (plus the 286x450 fort strip 0xf0e on the right
// edge when the site is fortified), loads the unit/fort/effect sprite atlases, wires
// the 'tool' toolbar and 'coat' picture to the battle, and refreshes the view.
// Everything past the backdrop-loader null test is skipped when the backdrop bitmap
// is missing (the loader handle then leaks, as in the original).
// Listing 0x005a9d90 inlines the loader's exact-type non-virtual destructor.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x005a9d90
void TTacArmyView::ConstructTTacArmyViewBaseState(int compositionClass, TArmyBattle* battle) {
  int savedFlags = 0;
  tileWidthPx88 = g_nTacticalTileWidthPx_006A5430;
  tileRowHeightPx8C = g_nTacticalTileRowHeightPx_006A5434;
  unitSpriteCellWidth90 = g_nTacticalUnitSpriteCellWidth_006A5498;
  unitSpriteCellHeight94 = g_nTacticalUnitSpriteCellHeight_006A549C;
  tileColumnsPerRow80 = 0x1d;
  // Release order in the original: +0x64, +0x68, +0xbc, +0x6c, +0x70, +0x74.
  if (battlefieldSurface64 != 0) {
    g_pDisplayMgr->RemoveGWorld(battlefieldSurface64);
  }
  if (unitSpriteAtlasSurface68 != 0) {
    g_pDisplayMgr->RemoveGWorld(unitSpriteAtlasSurface68);
  }
  if (unitSpriteScratchSurfaceBC != 0) {
    g_pDisplayMgr->RemoveGWorld(unitSpriteScratchSurfaceBC);
  }
  if (fortLevelAtlasSurface6C != 0) {
    g_pDisplayMgr->RemoveGWorld(fortLevelAtlasSurface6C);
  }
  if (tileScratchSurface70 != 0) {
    g_pDisplayMgr->RemoveGWorld(tileScratchSurface70);
  }
  if (effectAtlasSurface74 != 0) {
    g_pDisplayMgr->RemoveGWorld(effectAtlasSurface74);
  }

  TQuickDrawSurfaceContext* savedContext;
  GetGWorld(&savedContext, &savedFlags);
  // Two rect buffers reused across every init/blit below (the original's frame holds
  // exactly two RECT locals).
  RECT bounds;
  RECT overlayBounds;
  bounds.top = 0;
  bounds.right = g_nTacticalBattlefieldSurfaceWidth_006A5448;
  bounds.left = 0;
  bounds.bottom = g_nTacticalBattlefieldSurfaceHeight_006A544C;
  g_pDisplayMgr->MakeNewGWorld(battlefieldSurface64, 8, bounds);
  TBitmapResourceLoader** loaderHandle =
      CreateBitmapResourceLoaderHandle(static_cast<unsigned short>(compositionClass + 0xf0a));
  SetGWorld(battlefieldSurface64, savedFlags);
  LockPixels(GetGWorldPixMap(battlefieldSurface64));
  QDLoadResource(loaderHandle);
  TBitmapResourceLoader* loader = *loaderHandle;
  if (loader != 0) {
    loader->EnsureBitmapResourceLoadedAndCopyRectSize();
    loader->flags |= 1;
    ResetQuickDrawStrokeState();
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, &bounds);
    loader = *loaderHandle;
    loader->ReleaseBitmapResource();
    loader->flags &= 0xfe;
    delete loader;
    delete loaderHandle;
    UnlockPixels(GetGWorldPixMap(battlefieldSurface64));
    SetGWorld(savedContext, savedFlags);

    if (battle->fortLevel49 != 0) {
      TQuickDrawSurfaceContext* fortStripSurface =
          LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xf0e);
      bounds.left = 0;
      bounds.top = 0;
      bounds.right = 0x11e;
      bounds.bottom = 0x1c2;
      overlayBounds.left = g_nTacticalBattlefieldSurfaceWidth_006A5448 - 0x11e;
      overlayBounds.top = 0;
      overlayBounds.right = g_nTacticalBattlefieldSurfaceWidth_006A5448;
      overlayBounds.bottom = 0x1c2;
      ResetQuickDrawStrokeState();
      UpdatePaletteIndexWithDefaultFallback(0x13);
      SetQuickDrawFillColorFromPaletteIndex(0);
      BlitQuickDrawSurfaces(fortStripSurface->GetBlitSurface(),
                            battlefieldSurface64->GetBlitSurface(), &bounds, &overlayBounds, 0);
      g_pDisplayMgr->RemoveGWorld(fortStripSurface);
    }

    unitSpriteAtlasSurface68 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xee2);
    short fortLevel = battle->fortLevel49;
    fortLevelAtlasSurface6C = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(
        static_cast<unsigned short>(fortLevel != 0 ? fortLevel + 0xee6 : 0xee7));
    effectAtlasSurface74 = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xeeb);

    bounds.right = tileWidthPx88;
    bounds.bottom = tileRowHeightPx8C;
    bounds.left = 0;
    bounds.top = 0;
    g_pDisplayMgr->MakeNewGWorld(tileScratchSurface70, 8, bounds);

    field84 = -1;
    tacticalBattle60 = battle;
    battlefieldColumnCountD8 = static_cast<short>(battle->battlefieldColumnCount34);
    scrollableContentWidth7A = static_cast<short>((battle->battlefieldColumnCount34 + 1) *
                                                  static_cast<short>(tileWidthPx88));
    battlefieldOriginOffsetXD4 = static_cast<short>((0x1d - battle->battlefieldColumnCount34) *
                                                    static_cast<short>(tileWidthPx88));

    TTacticalToolbar* toolbar =
        static_cast<TTacticalToolbar*>(ownerContext->ResolveControlByTag(kControlTagTool));
    if (toolbar == 0) {
      FailNilPointerWithAssert(s_SourcePathUTacViews_00699FF4, 0x497);
    }
    toolbar->battle88 = battle;
    toolbar->unitSpriteAtlasSurface94 = unitSpriteAtlasSurface68;
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(tacticalBattle60->selectedUnit1c);
    toolbar->ConfigureTacticalTargetDoneRetreatAutoControls(0);
    toolbarD0 = toolbar;

    TPicture* coatControl =
        static_cast<TPicture*>(ownerContext->ResolveControlByTag(kControlTagCoat));
    coatControl->AssertValid();
    coatControl->SetPictureResourceIdAndRefresh(
        static_cast<short>(
            (&tacticalBattle60->tacticalPlayer14)[tacticalBattle60->currentSideC]->nationIndex1C +
            0xea6),
        1);

    overlayBounds.left = 0;
    overlayBounds.right = unitSpriteCellWidth90 * 2;
    overlayBounds.top = 0;
    overlayBounds.bottom = unitSpriteCellHeight94 * 3;
    g_pDisplayMgr->MakeNewGWorld(unitSpriteScratchSurfaceBC, 8, overlayBounds);
    RefreshControl();
    GetWindow()->ForceRedraw();
  }
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

// Presents the battle view: blits the scrolled backdrop slice from
// battlefieldSurface64 into the primary render surface, draws all 0x1b3 tiles inside
// a saved/restored QuickDraw clip, presents to the restored active surface, then
// draws the UI overlay.
// FUNCTION: IMPERIALISM 0x005aa2e0
void TTacArmyView::Draw(RECT* rectBuffer) {
  int savedFlags = 0;
  RECT clipRect;
  clipRect = *rectBuffer;

  TQuickDrawSurfaceContext* savedContext;
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedFlags);
  LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
  LockPixels(GetGWorldPixMap(battlefieldSurface64));

  // Backdrop source-x origin: the battlefield bitmap is right-aligned inside the
  // 0x1d-column grid, shifted by the current horizontal scroll.
  battlefieldOriginOffsetXD4 = static_cast<short>(
      (0x1d - tacticalBattle60->battlefieldColumnCount34) * static_cast<short>(tileWidthPx88));
  int sourceOffsetX = battlefieldOriginOffsetXD4 + viewOriginX78;

  RECT backdropSrcRect;
  backdropSrcRect.left = clipRect.left + sourceOffsetX;
  backdropSrcRect.top = clipRect.top;
  backdropSrcRect.right = clipRect.right + sourceOffsetX;
  backdropSrcRect.bottom = clipRect.bottom;
  RECT presentDstRect;
  presentDstRect.left = clipRect.left;
  presentDstRect.top = clipRect.top;
  presentDstRect.right = clipRect.right;
  presentDstRect.bottom = clipRect.bottom;

  ResetQuickDrawStrokeState();
  SetQuickDrawStrokeColor(0xffffff);
  SetQuickDrawFillColor(0);

  RECT backdropDstRect;
  backdropDstRect.left = clipRect.left;
  backdropDstRect.top = clipRect.top;
  backdropDstRect.right = clipRect.right;
  backdropDstRect.bottom = clipRect.bottom;

  // Bottom-up DIB flip, same idiom as TFocusAnimation.cpp.
  if (battlefieldSurface64->blitSurface.surfaceDib != 0) {
    int backdropHeight =
        battlefieldSurface64->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (backdropHeight < 1) {
      backdropHeight = -backdropHeight;
    }
    OffsetRect(&backdropSrcRect, 0,
               (backdropHeight - backdropSrcRect.top) - backdropSrcRect.bottom);
  }
  if (g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib != 0) {
    int primaryHeight =
        g_pPrimaryRenderSurfaceContext->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (primaryHeight < 1) {
      primaryHeight = -primaryHeight;
    }
    OffsetRect(&backdropDstRect, 0, (primaryHeight - backdropDstRect.top) - backdropDstRect.bottom);
  }
  // Backdrop: battlefield surface -> primary render surface.
  BlitQuickDrawSurfaces(battlefieldSurface64->GetBlitSurface(),
                        g_pPrimaryRenderSurfaceContext->GetBlitSurface(), &backdropSrcRect,
                        &backdropDstRect, 0);

  if (tacticalBattle60 != 0) {
    // Save/restore the QuickDraw clip around the per-tile pass.
    CTemporaryRegion savedClip;
    GetClip(savedClip.tempRgn);
    int tileIndex;
    for (tileIndex = 0; tileIndex < 0x1b3; tileIndex++) {
      DrawTacticalTileInClipRect(tileIndex, &clipRect);
    }
    SetClip(savedClip.tempRgn);
  }

  SetGWorld(savedContext, savedFlags);
  ResetQuickDrawStrokeState();
  SetQuickDrawStrokeColor(0xffffff);
  // Present: primary render surface -> the restored active surface.
  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &clipRect,
                        &presentDstRect, 0);
  DrawUiTilesAndOverlay();
  UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
  UnlockPixels(GetGWorldPixMap(battlefieldSurface64));
}

// FUNCTION: IMPERIALISM 0x005aa900
undefined TTacArmyView::DrawTacticalTileInClipRect(int tileIndex, RECT* clipRect) {
  int row = tileIndex / tileColumnsPerRow80;
  int x = (tileIndex % tileColumnsPerRow80) * tileWidthPx88 - viewOriginX78;
  if (row & 1) {
    x += tileWidthPx88 / 2;
  }
  int y = row * tileRowHeightPx8C;
  RECT tileScreenRect = {x, y, x + tileWidthPx88, y + tileRowHeightPx8C};
  RECT scratchRect;
  if (!SectRect(&tileScreenRect, clipRect, &scratchRect)) {
    return 0;
  }

  // Painted tile corners: the right half is dropped when the tile pokes past the view
  // content width.
  RECT halfRect;
  RECT* corners;
  if (frameWidth34 < tileScreenRect.right) {
    halfRect.left = x;
    halfRect.top = y;
    halfRect.right = x + tileWidthPx88 / 2;
    halfRect.bottom = y + tileRowHeightPx8C;
    corners = &halfRect;
  } else {
    corners = &tileScreenRect;
  }
  int paintLeft = corners->left;
  int paintTop = corners->top;
  int paintRight = corners->right;
  int paintBottom = corners->bottom;

  int rowParity = (tileIndex / 0x1d) & 1;
  int sideSlot = rowParity + (tileIndex % 0x1d) * 2;

  // Fort-wall edge classification for this tile (0 = none; 1/2 = even-row wall
  // right/left of the seam; 3 = odd-row wall).
  TacticalTileRecord* grid = tacticalBattle60->tileGrid4;
  short edgeKind = 0;
  if (rowParity == 0) {
    if (tileIndex > 0) {
      if (grid[tileIndex].deployMark8 < 2) {
        if (grid[tileIndex - 1].deployMark8 > 1) {
          edgeKind = 2;
        }
      } else {
        edgeKind = 1;
      }
    }
  } else if (grid[tileIndex].deployMark8 >= 2) {
    edgeKind = 3;
  }

  unsigned char wallBreached = 0;
  if ((((edgeKind == 1 || edgeKind == 3) && !tacticalBattle60->HasFortWallGarrison(tileIndex)) ||
       (edgeKind == 2 && !tacticalBattle60->HasFortWallGarrison(tileIndex)))) {
    wallBreached = 1;
  }
  unsigned char gunSlotRow = 0;
  unsigned char gunSlotOccupied = 0;
  if (edgeKind != 0) {
    int wallNeighbor;
    if (edgeKind == 1) {
      wallNeighbor = tileIndex + 0x1d;
    } else if (edgeKind == 2) {
      wallNeighbor = tileIndex + 0x1c;
    } else {
      wallNeighbor = tileIndex;
    }
    if (tacticalBattle60->IsTacticalTileAtFortWallSectionSlot(wallNeighbor)) {
      gunSlotRow = 1;
      if (grid[wallNeighbor].occupant4 != 0) {
        gunSlotOccupied = 1;
      }
    }
  }

  // Column guide ticks between deployment columns (setup phase only).
  if (tacticalBattle60->battleLive10 == 0 && rowParity > 0) {
    g_pUiRuntimeContext->SetForeColor(0);
    if (tacticalBattle60->ApplyGridColumnSelectionGuard(tileIndex) &&
        grid[tileIndex].occupant4 == 0) {
      int yMid = tileRowHeightPx8C / 2;
      SetQuickDrawFillColor(0);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(paintLeft),
                                              static_cast<short>(y + yMid + 1));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(paintRight),
                                   static_cast<short>(y + yMid + 1));
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(paintLeft),
                                              static_cast<short>(y + yMid + 1));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(paintRight),
                                   static_cast<short>(y + yMid + 1));
      g_pUiRuntimeContext->SetForeColor(0);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(paintLeft),
                                              static_cast<short>(y + yMid - 1));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(paintRight),
                                   static_cast<short>(y + yMid - 1));
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(paintLeft),
                                              static_cast<short>(y + yMid - 1));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(paintRight),
                                   static_cast<short>(y + yMid - 1));
    }
  }

  // Trench overlay: pick the segment sprite from the per-tile 6-bit direction mask.
  short trenchSpriteBase = 0;
  if (grid[tileIndex].trenchMask10 != 0) {
    int segmentPairSprite[36] = {0,   0xe,  0xc, 0x11, 9,  0x12, 0xe,  0,   0x11, 9, 0x12, 0xc,
                                 0xc, 0x11, 0,   0x13, 10, 0x13, 0x11, 9,   0x13, 0, 0x10, 8,
                                 9,   0x12, 10,  0x10, 0,  0xb,  0x12, 0xc, 0x13, 8, 0xb,  0};
    int singleSegmentSprite[6] = {0x19, 0x1a, 0x1b, 0x16, 0x17, 0x18};
    unsigned char mask = grid[tileIndex].trenchMask10;
    int firstBit = -1;
    int secondBit = -1;
    for (int bit = 0; bit < 6; ++bit) {
      if ((mask & (1 << bit)) != 0) {
        if (firstBit == -1) {
          firstBit = bit;
        } else if (secondBit == -1) {
          secondBit = bit;
        }
      }
    }
    short spriteIndex;
    if ((mask & 0x80) == 0) {
      if (secondBit == -1) {
        spriteIndex = static_cast<short>(singleSegmentSprite[firstBit]);
      } else {
        spriteIndex = static_cast<short>(segmentPairSprite[secondBit + firstBit * 6]);
      }
    } else {
      spriteIndex = static_cast<short>(firstBit + 1);
    }
    trenchSpriteBase = spriteIndex * static_cast<short>(tileWidthPx88);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0);
    RECT dstRect = tileScreenRect;
    if ((mask & 0x80) != 0) {
      RECT fullSrc = {0, 0, tileWidthPx88, tileRowHeightPx8C};
      OffsetRectForSurfaceDibFlip(effectAtlasSurface74, &fullSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &dstRect);
      BlitRectWithOptionalTransparency(&effectAtlasSurface74->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &fullSrc,
                                       &dstRect, 0x24, 0);
      dstRect = tileScreenRect;
    }
    RECT segSrc = {trenchSpriteBase, 0, trenchSpriteBase + tileWidthPx88, tileRowHeightPx8C};
    OffsetRectForSurfaceDibFlip(effectAtlasSurface74, &segSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &dstRect);
    BlitRectWithOptionalTransparency(&effectAtlasSurface74->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &segSrc,
                                     &dstRect, 0x24, 0);
    SetQuickDrawStrokeColor(0);
  }

  // Fort-wall bitmap for odd-row wall tiles.
  if (grid[tileIndex].deployMark8 == 1) {
    short fortCell = tacticalBattle60->IsTacticalSideCategoryCoverageIncompleteOrFlagOff();
    short fortSpriteX =
        static_cast<short>(fortCell * 3) * static_cast<short>(unitSpriteCellWidth90);
    RECT fortSrc = {fortSpriteX, 0, fortSpriteX + unitSpriteCellWidth90, tileRowHeightPx8C};
    RECT fortDst = tileScreenRect;
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0);
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface6C, &fortSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &fortDst);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface6C->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &fortSrc,
                                     &fortDst, 0x24, 0);
    SetQuickDrawStrokeColor(0);
  } else if ((gunSlotOccupied || wallBreached || edgeKind == 2) && edgeKind != 0) {
    // Wall segment selected by breach/occupancy state.
    short wallCol = wallBreached ? 0xb : 5;
    short wallSpriteX = (edgeKind + wallCol) * static_cast<short>(tileWidthPx88);
    if (!gunSlotOccupied && !wallBreached) {
      wallSpriteX = static_cast<short>(tileWidthPx88);
    }
    RECT wallSrc = {wallSpriteX, 0, wallSpriteX + tileWidthPx88, tileRowHeightPx8C};
    RECT wallDst = tileScreenRect;
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface6C, &wallSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &wallDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface6C->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &wallSrc,
                                     &wallDst, 0x24, 0);
    SetQuickDrawStrokeColor(0);
  }

  // Trench-connection markers into the neighboring tiles.
  int trenchLinks = 0;
  if (rowParity == 0) {
    // even rows link via the previous-row pair
    if (tileIndex - 0x1d >= 0 && grid[tileIndex - 0x1d].deployMark8 == 1) {
      trenchLinks |= 2;
    }
    if (tileIndex - 0x1c >= 0 && grid[tileIndex - 0x1c].deployMark8 == 1) {
      trenchLinks |= 1;
    }
  }

  // Per-direction trench segment sprites for the link mask.
  for (int segment = 0x15; segment - 0x14 < 4; ++segment) {
    if ((trenchLinks & (1 << (segment - 0x15))) != 0) {
      ResetQuickDrawStrokeState();
      UpdatePaletteIndexWithDefaultFallback(0);
      RECT linkSrc = {segment * tileWidthPx88, 0, (segment + 1) * tileWidthPx88, tileRowHeightPx8C};
      RECT linkDst = tileScreenRect;
      OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface6C, &linkSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &linkDst);
      BlitRectWithOptionalTransparency(&fortLevelAtlasSurface6C->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &linkSrc,
                                       &linkDst, 0x24, 0);
      SetQuickDrawStrokeColor(0);
    }
  }

  // Occupant unit sprite (with hex selection outline for the active unit).
  TTacticalUnit* occupant = grid[tileIndex].occupant4;
  if (occupant != 0) {
    if (occupant == tacticalBattle60->selectedUnit1c) {
      g_pUiAnimator->FindRegisteredAnimationByTag(0x13);
      SetQuickDrawFillColorFromPaletteIndex(0);
      DrawHexSelectionOutlineSegments(&tileScreenRect);
      SetQuickDrawFillColorFromPaletteIndex(0);
      DrawHexSelectionOutlineSegments(&tileScreenRect);
    }
    short spriteY = occupant->side20 == 0 ? 0 : static_cast<short>(unitSpriteCellHeight94);
    short spriteX =
        static_cast<short>(occupant->unitTypeC) * static_cast<short>(unitSpriteCellWidth90);
    RECT unitSrc = {spriteX, spriteY, spriteX + unitSpriteCellWidth90,
                    spriteY + unitSpriteCellHeight94};
    RECT unitDst;
    ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(occupant, &unitDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0);
    if (ClipSrcRectToBoundsAndOffsetDstRect(corners, &unitDst, &unitSrc)) {
      OffsetRectForSurfaceDibFlip(unitSpriteAtlasSurface68, &unitSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &unitDst);
      BlitRectWithOptionalTransparency(&unitSpriteAtlasSurface68->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &unitSrc,
                                       &unitDst, 0x24, 0);
    }
    SetQuickDrawStrokeColor(0);
  }

  // Wall-tile decoration pass for the edge kinds not covered above.
  if (grid[tileIndex].deployMark8 == 1 || (edgeKind != 0 && !gunSlotOccupied && edgeKind != 2)) {
    short deckSpriteX;
    if (edgeKind == 0) {
      deckSpriteX = static_cast<short>(unitSpriteCellWidth90) * 2;
    } else if (!wallBreached) {
      if (!gunSlotRow) {
        deckSpriteX = (edgeKind - 1) * static_cast<short>(tileWidthPx88);
      } else if (!gunSlotOccupied) {
        deckSpriteX = (edgeKind + 2) * static_cast<short>(tileWidthPx88);
      } else {
        deckSpriteX = (edgeKind + 8) * static_cast<short>(tileWidthPx88);
      }
    } else {
      deckSpriteX = (edgeKind + 0xe) * static_cast<short>(tileWidthPx88);
    }
    RECT deckSrc = {deckSpriteX, 0, deckSpriteX + tileWidthPx88, tileRowHeightPx8C};
    RECT deckDst = tileScreenRect;
    if (paintLeft < 0) {
      deckSrc.left = -paintLeft;
      deckDst.left = 0;
    }
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface6C, &deckSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &deckDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface6C->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &deckSrc,
                                     &deckDst, 0x24, 0);
    SetQuickDrawStrokeColor(0);
  }

  // Strength/ammo indicator bars for the occupant.
  if (occupant != 0) {
    int barMidX = tileWidthPx88 / 2 + paintLeft;
    RECT barRect;
    barRect.left = barMidX - 9;
    barRect.right = barMidX + 0xb;
    barRect.top = y - 4;
    barRect.bottom = y - 1;
    SetQuickDrawFillColor(0);
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);
    g_pUiRuntimeContext->SetForeColor(0x33);
    barRect.left -= 1;
    barRect.right -= 1;
    barRect.top -= 1;
    barRect.bottom -= 1;
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);
    g_pUiRuntimeContext->SetForeColor(6);
    barRect.right = barRect.left + (occupant->strength4 + 0x18) / 0x19;
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);
    g_pUiRuntimeContext->SetForeColor(0x34);
    // Second stat bar reads the derived unit's morale at +0x34 (army occupants are
    // TArmyTacUnit); the base TTacticalUnit's +0x30 is the attack-target pointer, not a bar.
    barRect.right = barRect.left + (static_cast<TArmyTacUnit*>(occupant)->morale34 + 0x18) / 0x19;
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);

    short tierOffset = g_pGlobalMapState->GetMapImprovementTierBucketOffset(0);
    RECT flagSrc = {0, tierOffset, 6, tierOffset + 9};
    RECT flagDst = {paintBottom - 0xc, barRect.top - 6, paintBottom - 3, barRect.top};
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &flagDst);
    SetQuickDrawFillColor(0);
    SetQuickDrawStrokeColor(0);
    BlitRectWithOptionalTransparency(&g_pStrategicMapViewSystem->atlas6b8->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &flagSrc,
                                     &flagDst, 0, 0);
    SetQuickDrawFillColor(0);
    QDFrameRect(&flagDst);
    if (occupant->selectedFlag18 != 0) {
      SetQuickDrawFillColor(0);
      flagDst.left -= 1;
      flagDst.top += 1;
      flagDst.right += 1;
      QDFrameRect(&flagDst);
    }
    if (g_nForceTacticalBattleViewFlag_006A4758 != 0) {
      SetQuickDrawFillColor(0);
      SetQuickDrawTextOriginWithContextOffset(0, 0);
      RenderTacticalBattleSelectionAndUnitOverlayPass_Impl(
          static_cast<char>(static_cast<short>(occupant->aiStateCode2c) + 0x61));
    }
  }

  // Selection-marker animation redraw hook.
  TAnimation* selectionAnim = g_pUiAnimator->FindRegisteredAnimationByTag(0x13);
  if (selectionAnim != 0) {
    POINT offset = {0, 0};
    selectionAnim->DrawNextFrame(&offset);
  }

  // Neighbor units bleeding into this tile from the row-adjacent tiles.
  for (int neighborPick = 0; neighborPick < 2; ++neighborPick) {
    int neighborIdx = neighborPick == 0 ? tileIndex - 0x1d : tileIndex - 0x1c;
    if (neighborIdx < 0) {
      continue;
    }
    TTacticalUnit* neighborUnit = grid[neighborIdx].occupant4;
    if (neighborUnit == 0) {
      continue;
    }
    short nSpriteY = neighborUnit->side20 == 0 ? 0 : static_cast<short>(unitSpriteCellHeight94);
    short nSpriteX =
        static_cast<short>(neighborUnit->unitTypeC) * static_cast<short>(unitSpriteCellWidth90);
    RECT nSrc = {nSpriteX, nSpriteY, nSpriteX + unitSpriteCellWidth90,
                 nSpriteY + unitSpriteCellHeight94};
    RECT nDst;
    ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(neighborUnit, &nDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0);
    if (ClipSrcRectToBoundsAndOffsetDstRect(corners, &nDst, &nSrc)) {
      OffsetRectForSurfaceDibFlip(unitSpriteAtlasSurface68, &nSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &nDst);
      BlitRectWithOptionalTransparency(&unitSpriteAtlasSurface68->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &nSrc, &nDst,
                                       0x24, 0);
    }
    SetQuickDrawStrokeColor(0);
  }

  // Gun-slot wall overlay when the slot row is occupied.
  if (edgeKind != 0 && gunSlotRow && edgeKind != 2) {
    short slotSpriteX = (edgeKind + 8) * static_cast<short>(tileWidthPx88);
    RECT slotSrc = {slotSpriteX, 0, slotSpriteX + tileWidthPx88, tileRowHeightPx8C};
    RECT slotDst = {paintLeft, paintTop + 1, paintLeft + tileWidthPx88,
                    paintTop + 1 + tileRowHeightPx8C};
    if (paintLeft < 0) {
      slotSrc.left = -paintLeft;
      slotDst.left = 0;
    }
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface6C, &slotSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &slotDst);
    UpdatePaletteIndexWithDefaultFallback(0);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface6C->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &slotSrc,
                                     &slotDst, 0x24, 0);
    SetQuickDrawStrokeColor(0);
  }

  // Deployment-zone tick marks along the column midline.
  if (tacticalBattle60->tileMoveCostArray24[sideSlot] > 0) {
    int tickMidX = tileWidthPx88 / 2 + paintLeft;
    SetQuickDrawFillColor(0);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX), static_cast<short>(y));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX), static_cast<short>(y));
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX - 1),
                                            static_cast<short>(y));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX - 1), static_cast<short>(y));
    if ((row < 2 && tacticalBattle60->currentSideC == 0) ||
        (row / 2 == tacticalBattle60->battlefieldColumnCount34 - 1 &&
         tacticalBattle60->currentSideC == 1)) {
      SetQuickDrawFillColorFromPaletteIndex(0);
    } else if (tacticalBattle60->tileThreatLevelArray28[tileIndex] == 0) {
      g_pUiRuntimeContext->SetForeColor(0);
    } else {
      g_pUiRuntimeContext->SetForeColor(0);
    }
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX), static_cast<short>(y));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX), static_cast<short>(y));
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX - 1),
                                            static_cast<short>(y));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX - 1), static_cast<short>(y));
  }
  return 0;
}
