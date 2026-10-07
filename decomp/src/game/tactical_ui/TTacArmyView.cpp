#include "game/tactical_ui/TTacArmyView.h"
#include "game/ui_tags_common.h"
#include "game/ui_core/TWindow.h"

#include "game/gfx/CDib.h"
#include "game/ui_core/TEventHandler.h"
#include "game/map/TMapMgr.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/app/TAnimation.h"
#include "game/app/TAnimator.h"
#include "game/ui_core/TViewMgr.h"
#include "game/tactical/TArmyBattle.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/gfx/TDisplayMgr.h"
#include "game/ui_core/TPicture.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/map/TTacticalPlayer.h"
#include "game/tactical_ui/TTacticalToolbar.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_ui_globals.h"
#include "game/quickdraw_guards.h"
#include "game/gfx/quickdraw_regions.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"

static void OffsetRectForSurfaceDibFlip(TQuickDrawSurfaceContext* ctx, RECT* r) {
  if (ctx->blitSurface.surfaceDib != 0) {
    int height = ctx->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (height < 1) {
      height = -height;
    }
    OffsetRect(r, 0, (height - r->top) - r->bottom);
  }
}

// FUNCTION: IMPERIALISM 0x0045d340
TTacArmyView::~TTacArmyView() {}

IMPLEMENT_DYNCREATE(TTacArmyView, TTacticalBattleView)

IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
enum FortWallEdgeKind {
  kFortWallEdgeNone = 0,
  kFortWallEdgeEvenRowRight = 1,
  kFortWallEdgeEvenRowLeft = 2,
  kFortWallEdgeOddRow = 3
};

// FUNCTION: IMPERIALISM 0x005a9d90
void TTacArmyView::StuffValues(int compositionClass, TArmyBattle* battle) {
  int savedFlags = 0;
  tileWidthPx = g_tacticalTileSize.cx;
  tileRowHeightPx = g_tacticalTileSize.cy;
  unitSpriteCellWidth = g_tacticalUnitSpriteCellSize.cx;
  unitSpriteCellHeight = g_tacticalUnitSpriteCellSize.cy;
  tileColumnsPerRow = 0x1d;
  // Release order in the original: +0x64, +0x68, +0xbc, +0x6c, +0x70, +0x74.
  if (battlefieldSurface != 0) {
    g_pDisplayMgr->RemoveGWorld(battlefieldSurface);
  }
  if (unitSpriteAtlasSurface != 0) {
    g_pDisplayMgr->RemoveGWorld(unitSpriteAtlasSurface);
  }
  if (unitSpriteScratchSurface != 0) {
    g_pDisplayMgr->RemoveGWorld(unitSpriteScratchSurface);
  }
  if (fortLevelAtlasSurface != 0) {
    g_pDisplayMgr->RemoveGWorld(fortLevelAtlasSurface);
  }
  if (tileScratchSurface != 0) {
    g_pDisplayMgr->RemoveGWorld(tileScratchSurface);
  }
  if (effectAtlasSurface != 0) {
    g_pDisplayMgr->RemoveGWorld(effectAtlasSurface);
  }

  TQuickDrawSurfaceContext* savedContext;
  GetGWorld(&savedContext, &savedFlags);
  RECT bounds;
  RECT overlayBounds;
  bounds.top = 0;
  bounds.right = g_tacticalBattlefieldSurfaceSize.cx;
  bounds.left = 0;
  bounds.bottom = g_tacticalBattlefieldSurfaceSize.cy;
  g_pDisplayMgr->MakeNewGWorld(battlefieldSurface, 8, bounds);
  TBitmapResourceLoader** loaderHandle =
      CreateBitmapResourceLoaderHandle(static_cast<unsigned short>(compositionClass + 0xf0a));
  SetGWorld(battlefieldSurface, savedFlags);
  LockPixels(GetGWorldPixMap(battlefieldSurface));
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
    UnlockPixels(GetGWorldPixMap(battlefieldSurface));
    SetGWorld(savedContext, savedFlags);

    if (battle->fortLevel != 0) {
      TQuickDrawSurfaceContext* fortStripSurface =
          LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xf0e);
      bounds.left = 0;
      bounds.top = 0;
      bounds.right = 0x11e;
      bounds.bottom = 0x1c2;
      overlayBounds.left = g_tacticalBattlefieldSurfaceSize.cx - 0x11e;
      overlayBounds.top = 0;
      overlayBounds.right = g_tacticalBattlefieldSurfaceSize.cx;
      overlayBounds.bottom = 0x1c2;
      ResetQuickDrawStrokeState();
      UpdatePaletteIndexWithDefaultFallback(0x13);
      SetQuickDrawFillColorFromPaletteIndex(0);
      BlitRectWithOptionalTransparency(fortStripSurface->GetBlitSurface(),
                                       battlefieldSurface->GetBlitSurface(), &bounds,
                                       &overlayBounds, 0);
      g_pDisplayMgr->RemoveGWorld(fortStripSurface);
    }

    unitSpriteAtlasSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xee2);
    short fortLevel = battle->fortLevel;
    fortLevelAtlasSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(
        static_cast<unsigned short>(fortLevel != 0 ? fortLevel + 0xee6 : 0xee7));
    effectAtlasSurface = LoadBitmapResourceSurfaceAndRestoreQuickDrawContext(0xeeb);

    bounds.right = tileWidthPx;
    bounds.bottom = tileRowHeightPx;
    bounds.left = 0;
    bounds.top = 0;
    g_pDisplayMgr->MakeNewGWorld(tileScratchSurface, 8, bounds);

    hoveredTileIndex = -1;
    tacticalBattle = battle;
    battlefieldColumnCount = static_cast<short>(battle->battlefieldColumnCount);
    scrollableContentWidth =
        static_cast<short>((battle->battlefieldColumnCount + 1) * static_cast<short>(tileWidthPx));
    battlefieldOriginOffsetX = static_cast<short>((0x1d - battle->battlefieldColumnCount) *
                                                  static_cast<short>(tileWidthPx));

    TTacticalToolbar* toolbar =
        static_cast<TTacticalToolbar*>(ownerContext->FindSubView(kControlTagTool));
    if (toolbar == 0) {
      FailNilPointerWithAssert(s_SourcePathUTacViews, 0x497);
    }
    toolbar->battle = battle;
    toolbar->unitSpriteAtlasSurface = unitSpriteAtlasSurface;
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(tacticalBattle->selectedUnit);
    toolbar->SetActionMode(0);
    this->toolbar = toolbar;

    TPicture* coatControl = static_cast<TPicture*>(ownerContext->FindSubView(kControlTagCoat));
    coatControl->AssertValid();
    coatControl->SetPictureRsrcID(
        static_cast<short>(tacticalBattle->players[tacticalBattle->currentSide]->nationIndex +
                           0xea6),
        1);

    overlayBounds.left = 0;
    overlayBounds.right = unitSpriteCellWidth * 2;
    overlayBounds.top = 0;
    overlayBounds.bottom = unitSpriteCellHeight * 3;
    g_pDisplayMgr->MakeNewGWorld(unitSpriteScratchSurface, 8, overlayBounds);
    RefreshControl();
    GetWindow()->ForceRedraw();
  }
}
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE

// FUNCTION: IMPERIALISM 0x005aa2e0
void TTacArmyView::Draw(RECT* rectBuffer) {
  int savedFlags = 0;
  RECT clipRect;
  clipRect = *rectBuffer;

  TQuickDrawSurfaceContext* savedContext;
  GetGWorld(&savedContext, &savedFlags);
  SetGWorld(g_pPrimaryRenderSurfaceContext, savedFlags);
  LockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
  LockPixels(GetGWorldPixMap(battlefieldSurface));

  battlefieldOriginOffsetX = static_cast<short>((0x1d - tacticalBattle->battlefieldColumnCount) *
                                                static_cast<short>(tileWidthPx));
  int sourceOffsetX = battlefieldOriginOffsetX + viewOriginX;

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
  if (battlefieldSurface->blitSurface.surfaceDib != 0) {
    int backdropHeight =
        battlefieldSurface->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
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
  BlitRectWithOptionalTransparency(battlefieldSurface->GetBlitSurface(),
                                   g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   &backdropSrcRect, &backdropDstRect, 0);

  if (tacticalBattle != 0) {
    // Save/restore the QuickDraw clip around the per-tile pass.
    CTemporaryRegion savedClip;
    GetClip(savedClip.tempRgn);
    TacticalTileIndex tileIndex;
    for (tileIndex = 0; tileIndex < 0x1b3; tileIndex++) {
      DrawTile(tileIndex, &clipRect);
    }
    SetClip(savedClip.tempRgn);
  }

  SetGWorld(savedContext, savedFlags);
  ResetQuickDrawStrokeState();
  SetQuickDrawStrokeColor(0xffffff);
  // Present: primary render surface -> the restored active surface.
  BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &clipRect,
                                   &presentDstRect, 0);
  DoGlideAni();
  UnlockPixels(GetGWorldPixMap(g_pPrimaryRenderSurfaceContext));
  UnlockPixels(GetGWorldPixMap(battlefieldSurface));
}

// FUNCTION: IMPERIALISM 0x005aa900
void TTacArmyView::DrawTile(TacticalTileIndex tileIndex, RECT* clipRect) {
  bool wallBreached = false;
  bool gunSlotRow = false;
  bool gunSlotOccupied = false;
  int row = tileIndex / tileColumnsPerRow;
  int x = (tileIndex % tileColumnsPerRow) * tileWidthPx - viewOriginX;
  if (row & 1) {
    x += tileWidthPx / 2;
  }
  int y = row * tileRowHeightPx;
  RECT tileScreenRect = {x, y, x + tileWidthPx, y + tileRowHeightPx};
  RECT scratchRect;
  if (!SectRect(&tileScreenRect, clipRect, &scratchRect)) {
    return;
  }

  RECT halfRect;
  RECT* corners;
  if (frameWidth < tileScreenRect.right) {
    halfRect.left = x;
    halfRect.top = y;
    halfRect.right = x + tileWidthPx / 2;
    halfRect.bottom = y + tileRowHeightPx;
    corners = &halfRect;
  } else {
    corners = &tileScreenRect;
  }
  int paintLeft = corners->left;
  int paintTop = corners->top;
  int paintRight = corners->right;
  int paintBottom = corners->bottom;

  int hexRow = tileIndex / 0x1d;
  int rowParity = hexRow & 1;
  int sideSlot = rowParity + (tileIndex % 0x1d) * 2;

  TacticalTileRecord* grid = tacticalBattle->tileGrid;
  short edgeKind = kFortWallEdgeNone;
  if (rowParity == 0) {
    if (tileIndex > 0) {
      if (grid[tileIndex].deployMark < 2) {
        if (grid[tileIndex - 1].deployMark > 1) {
          edgeKind = kFortWallEdgeEvenRowLeft;
        }
      } else {
        edgeKind = kFortWallEdgeEvenRowRight;
      }
    }
  } else if (grid[tileIndex].deployMark >= 2) {
    edgeKind = kFortWallEdgeOddRow;
  }

  if (((edgeKind == kFortWallEdgeEvenRowRight || edgeKind == kFortWallEdgeOddRow) &&
       !tacticalBattle->HasFortWallGarrison(tileIndex)) ||
      (edgeKind == kFortWallEdgeEvenRowLeft &&
       !tacticalBattle->HasFortWallGarrison(tileIndex - 1))) {
    wallBreached = true;
  }
  if (edgeKind != kFortWallEdgeNone) {
    int wallNeighbor;
    if (edgeKind == kFortWallEdgeEvenRowRight) {
      wallNeighbor = tileIndex + 0x1d;
    } else if (edgeKind == kFortWallEdgeEvenRowLeft) {
      wallNeighbor = tileIndex + 0x1c;
    } else {
      wallNeighbor = tileIndex;
    }
    if (tacticalBattle->IsTacticalTileAtFortWallSectionSlot(wallNeighbor)) {
      gunSlotRow = true;
      if (grid[wallNeighbor].occupant != 0) {
        gunSlotOccupied = true;
      }
    }
  }

  if (tacticalBattle->battleLive == 0 && hexRow > 0) {
    g_pViewMgr->SetForeColor(0x35);
    if (tacticalBattle->ApplyGridColumnSelectionGuard(tileIndex) && grid[tileIndex].occupant == 0) {
      const int centerY = tileScreenRect.top + tileRowHeightPx / 2;
      const int centerX = tileScreenRect.left + tileWidthPx / 2;
      SetQuickDrawFillColor(0);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(centerX - 2),
                                              static_cast<short>(centerY));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(centerX + 2), static_cast<short>(centerY));
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(centerX - 1),
                                              static_cast<short>(centerY + 1));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(centerX + 1),
                                   static_cast<short>(centerY + 1));
      g_pViewMgr->SetForeColor(0x34);
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(centerX - 1),
                                              static_cast<short>(centerY - 1));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(centerX + 1),
                                   static_cast<short>(centerY - 1));
      SetQuickDrawTextOriginWithContextOffset(static_cast<short>(centerX - 1),
                                              static_cast<short>(centerY));
      DrawCenteredGuideLineOnMapDc(static_cast<short>(centerX + 1), static_cast<short>(centerY));
    }
  }

  // Trench overlay: pick the segment sprite from the per-tile 6-bit direction mask.
  short trenchSpriteBase = 0;
  if (grid[tileIndex].trenchMask != 0) {
    int segmentPairSprite[36] = {0,    0x0e, 0x0a, 0x07, 0x14, 0x0d, 0x0e, 0,    0x13,
                                 0x11, 0x09, 0x15, 0x0a, 0x13, 0,    0x0c, 0x10, 0x08,
                                 0x07, 0x11, 0x0c, 0,    0x12, 0x0b, 0x14, 0x09, 0x10,
                                 0x12, 0,    0x0f, 0x0d, 0x15, 0x08, 0x0b, 0x0f, 0};
    int singleSegmentSprite[6] = {0x19, 0x1a, 0x1b, 0x16, 0x17, 0x18};
    unsigned char mask = grid[tileIndex].trenchMask;
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
    trenchSpriteBase = spriteIndex * static_cast<short>(tileWidthPx);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    RECT dstRect = tileScreenRect;
    if ((mask & 0x80) != 0) {
      RECT fullSrc = {0, 0, tileWidthPx, tileRowHeightPx};
      OffsetRectForSurfaceDibFlip(effectAtlasSurface, &fullSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &dstRect);
      BlitRectWithOptionalTransparency(&effectAtlasSurface->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &fullSrc,
                                       &dstRect, 0x24, 0);
      dstRect = tileScreenRect;
    }
    RECT segSrc = {trenchSpriteBase, 0, trenchSpriteBase + tileWidthPx, tileRowHeightPx};
    OffsetRectForSurfaceDibFlip(effectAtlasSurface, &segSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &dstRect);
    BlitRectWithOptionalTransparency(&effectAtlasSurface->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &segSrc,
                                     &dstRect, 0x24, 0);
    SetQuickDrawStrokeColor(0xffffff);
  }

  // Adjacency for the trench-link pass below.
  TacticalTileIndex tileNeighbors[6];
  tacticalBattle->GetNeighborList(tileIndex, tileNeighbors);

  short fortCell = 0;

  if (grid[tileIndex].deployMark == 1) {
    fortCell = ComputeTacticalUnitSpriteOrientationIndexByAdjacentType1Occupancy(tileIndex);
    short fortSpriteCell = static_cast<short>(fortCell * 3);
    short fortSpriteX = fortSpriteCell * static_cast<short>(unitSpriteCellWidth);
    RECT fortSrc = {fortSpriteX, 0, fortSpriteX + unitSpriteCellWidth, tileRowHeightPx};
    RECT fortDst = tileScreenRect;
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface, &fortSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &fortDst);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &fortSrc,
                                     &fortDst, 0x24, 0);
    SetQuickDrawStrokeColor(0xffffff);

    TTacticalUnit* edgeUnit = 0;
    if (rowParity != 0) {
      if (fortCell == 1 || fortCell == 5) {
        edgeUnit = grid[tileNeighbors[5]].occupant;
      }
    } else if (fortCell == 2 || fortCell == 4) {
      edgeUnit = grid[tileNeighbors[0]].occupant;
    }
    if (edgeUnit != 0) {
      short edgeSpriteX =
          static_cast<short>(edgeUnit->unitType) * static_cast<short>(unitSpriteCellWidth);
      if (rowParity != 0) {
        edgeSpriteX += static_cast<short>(unitSpriteCellWidth / 2);
      }
      short edgeSpriteY = edgeUnit->side == 0 ? 0 : static_cast<short>(unitSpriteCellHeight);
      RECT edgeSrc = {edgeSpriteX, edgeSpriteY, edgeSpriteX + unitSpriteCellWidth,
                      edgeSpriteY + unitSpriteCellHeight};
      RECT edgeDst;
      ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(edgeUnit, &edgeDst);
      ResetQuickDrawStrokeState();
      UpdatePaletteIndexWithDefaultFallback(0x10);
      if (ClipSrcRectToBoundsAndOffsetDstRect(corners, &edgeDst, &edgeSrc)) {
        OffsetRectForSurfaceDibFlip(unitSpriteAtlasSurface, &edgeSrc);
        OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &edgeDst);
        BlitRectWithOptionalTransparency(&unitSpriteAtlasSurface->blitSurface,
                                         &g_pActiveQuickDrawSurfaceContext->blitSurface, &edgeSrc,
                                         &edgeDst, 0x24, 0);
      }
      SetQuickDrawStrokeColor(0xffffff);
    }

    fortSpriteX = static_cast<short>(fortSpriteCell + 1) * static_cast<short>(unitSpriteCellWidth);
    fortSrc.left = fortSpriteX;
    fortSrc.top = 0;
    fortSrc.right = fortSpriteX + unitSpriteCellWidth;
    fortSrc.bottom = tileRowHeightPx;
    fortDst = tileScreenRect;
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface, &fortSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &fortDst);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &fortSrc,
                                     &fortDst, 0x24, 0);
    SetQuickDrawStrokeColor(0xffffff);
  } else if ((gunSlotOccupied || wallBreached || edgeKind == kFortWallEdgeEvenRowLeft) &&
             edgeKind != kFortWallEdgeNone) {
    // Wall segment selected by breach/occupancy state.
    short wallCol = wallBreached ? 0xb : 5;
    short wallSpriteX = (edgeKind + wallCol) * static_cast<short>(tileWidthPx);
    if (!gunSlotOccupied && !wallBreached) {
      wallSpriteX = static_cast<short>(tileWidthPx);
    }
    RECT wallSrc = {wallSpriteX, 0, wallSpriteX + tileWidthPx, tileRowHeightPx};
    RECT wallDst = tileScreenRect;
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface, &wallSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &wallDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &wallSrc,
                                     &wallDst, 0x24, 0);
    SetQuickDrawStrokeColor(0xffffff);
  }

  unsigned char trenchLink[4] = {0, 0, 0, 0};
  if (rowParity == 0) {
    const TacticalTileIndex anchor = tileNeighbors[4];
    if (anchor != -1 && grid[anchor].deployMark == 1) {
      if (tileNeighbors[5] != -1 && grid[tileNeighbors[5]].deployMark == 1) {
        trenchLink[2] = 1;
      }
      if (tileNeighbors[3] != -1 && grid[tileNeighbors[3]].deployMark == 1) {
        trenchLink[0] = 1;
      }
    }
  } else {
    const TacticalTileIndex anchor = tileNeighbors[1];
    if (anchor != -1 && grid[anchor].deployMark == 1) {
      if (tileNeighbors[0] != -1 && grid[tileNeighbors[0]].deployMark == 1) {
        trenchLink[3] = 1;
      }
      if (tileNeighbors[2] != -1 && grid[tileNeighbors[2]].deployMark == 1) {
        trenchLink[1] = 1;
      }
    }
  }

  // Per-direction trench segment sprites for the link mask.
  for (int segment = 0x15; segment - 0x14 < 4; ++segment) {
    if (trenchLink[segment - 0x15] != 0) {
      ResetQuickDrawStrokeState();
      UpdatePaletteIndexWithDefaultFallback(0x10);
      RECT linkSrc = {segment * tileWidthPx, 0, (segment + 1) * tileWidthPx, tileRowHeightPx};
      RECT linkDst = tileScreenRect;
      OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface, &linkSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &linkDst);
      BlitRectWithOptionalTransparency(&fortLevelAtlasSurface->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &linkSrc,
                                       &linkDst, 0x24, 0);
      SetQuickDrawStrokeColor(0xffffff);
    }
  }

  // Occupant unit sprite (with hex selection outline for the active unit).
  TTacticalUnit* occupant = grid[tileIndex].occupant;
  if (occupant != 0) {
    if (occupant == tacticalBattle->selectedUnit) {
      short selectionPalette[2] = {0x13, 0};
      TAnimation* blink = g_pUiAnimator->FindAni(0x2711);
      RECT selectionRect = tileScreenRect;
      SetQuickDrawFillColorFromPaletteIndex(blink == 0 ? 0x13
                                                       : selectionPalette[blink->frameIndex]);
      DrawHexSelectionOutlineSegments(&selectionRect);
      selectionRect.left += 1;
      selectionRect.top += 1;
      SetQuickDrawFillColorFromPaletteIndex(0);
      DrawHexSelectionOutlineSegments(&selectionRect);
    }
    short spriteY = occupant->side == 0 ? 0 : static_cast<short>(unitSpriteCellHeight);
    short spriteX =
        static_cast<short>(occupant->unitType) * static_cast<short>(unitSpriteCellWidth);
    RECT unitSrc = {spriteX, spriteY, spriteX + unitSpriteCellWidth,
                    spriteY + unitSpriteCellHeight};
    RECT unitDst;
    ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(occupant, &unitDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    if (ClipSrcRectToBoundsAndOffsetDstRect(corners, &unitDst, &unitSrc)) {
      OffsetRectForSurfaceDibFlip(unitSpriteAtlasSurface, &unitSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &unitDst);
      BlitRectWithOptionalTransparency(&unitSpriteAtlasSurface->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &unitSrc,
                                       &unitDst, 0x24, 0);
    }
    SetQuickDrawStrokeColor(0xffffff);
  }

  // Wall-tile decoration pass for the edge kinds not covered above.
  if (grid[tileIndex].deployMark == 1 ||
      (edgeKind != kFortWallEdgeNone && !gunSlotOccupied && edgeKind != kFortWallEdgeEvenRowLeft)) {
    short deckSpriteX;
    if (edgeKind == kFortWallEdgeNone) {
      deckSpriteX = static_cast<short>(fortCell * 3 + 2) * static_cast<short>(unitSpriteCellWidth);
    } else if (!wallBreached) {
      if (!gunSlotRow) {
        deckSpriteX = (edgeKind - 1) * static_cast<short>(tileWidthPx);
      } else if (!gunSlotOccupied) {
        deckSpriteX = (edgeKind + 2) * static_cast<short>(tileWidthPx);
      } else {
        deckSpriteX = (edgeKind + 8) * static_cast<short>(tileWidthPx);
      }
    } else {
      deckSpriteX = (edgeKind + 0xe) * static_cast<short>(tileWidthPx);
    }
    RECT deckSrc = {deckSpriteX, 0, deckSpriteX + tileWidthPx, tileRowHeightPx};
    RECT deckDst = tileScreenRect;
    if (paintLeft < 0) {
      deckSrc.left = -paintLeft;
      deckDst.left = 0;
    }
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface, &deckSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &deckDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &deckSrc,
                                     &deckDst, 0x24, 0);
    SetQuickDrawStrokeColor(0xffffff);
  }

  // Strength/ammo indicator bars for the occupant.
  if (occupant != 0) {
    int barMidX = tileWidthPx / 2 + paintLeft;
    RECT barRect;
    barRect.left = barMidX - 9;
    barRect.right = barMidX + 0xb;
    barRect.top = y - 4;
    barRect.bottom = y - 1;
    SetQuickDrawFillColor(0);
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);
    g_pViewMgr->SetForeColor(0x33);
    barRect.left -= 1;
    barRect.right -= 1;
    barRect.top -= 1;
    barRect.bottom -= 1;
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);
    g_pViewMgr->SetForeColor(6);
    barRect.right = barRect.left + (occupant->strength + 0x18) / 0x19;
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);
    g_pViewMgr->SetForeColor(0x34);
    barRect.right = barRect.left + (static_cast<TArmyTacUnit*>(occupant)->morale + 0x18) / 0x19;
    FillRectWithQuickDrawBrushAndContextOffset(&barRect);

    short tierOffset = g_pGlobalMapState->GetFortFlagOffset(0);
    RECT flagSrc = {0, tierOffset, 6, tierOffset + 9};
    RECT flagDst = {barRect.left - 0xc, barRect.bottom - 6, barRect.left - 3, barRect.bottom};
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &flagDst);
    SetQuickDrawFillColor(0);
    SetQuickDrawStrokeColor(0xffffff);
    BlitRectWithOptionalTransparency(&g_pMacViewMgr->mapArtWorld->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &flagSrc,
                                     &flagDst, 0, 0);
    SetQuickDrawFillColor(occupant->selectedFlag ? 0xffffff : 0);
    flagDst.left -= 1;
    flagDst.top -= 1;
    flagDst.right += 1;
    flagDst.bottom += 1;
    QDFrameRect(&flagDst);
    if (occupant->selectedFlag) {
      SetQuickDrawFillColor(0);
      flagDst.left -= 1;
      flagDst.top -= 1;
      flagDst.right += 1;
      flagDst.bottom += 1;
      QDFrameRect(&flagDst);
    }
    if (g_nForceTacticalBattleViewFlag) {
      SetQuickDrawFillColor(0);
      SetQuickDrawTextOriginWithContextOffset(
          static_cast<short>(tileScreenRect.left + tileWidthPx - 8),
          static_cast<short>(tileScreenRect.bottom - 2));
      RenderTacticalBattleSelectionAndUnitOverlayPass(
          static_cast<char>(static_cast<short>(occupant->aiStateCode) + 0x61));
    }
  }

  if (occupant != 0 || edgeKind != kFortWallEdgeNone) {
    TAnimation* selectionAnim = g_pUiAnimator->FindAni(tileIndex);
    if (selectionAnim != 0) {
      POINT offset = {0, 0};
      selectionAnim->DrawNextFrame(&offset);
    }
  }

  // Neighbor units bleeding into this tile from adjacency slots 3 and 2.
  for (int neighborPick = 0; neighborPick < 2; ++neighborPick) {
    TacticalTileIndex neighborIdx = neighborPick == 0 ? tileNeighbors[3] : tileNeighbors[2];
    if (neighborIdx == -1) {
      continue;
    }
    TTacticalUnit* neighborUnit = grid[neighborIdx].occupant;
    if (neighborUnit == 0) {
      continue;
    }
    short nSpriteY = neighborUnit->side == 0 ? 0 : static_cast<short>(unitSpriteCellHeight);
    short nSpriteX =
        static_cast<short>(neighborUnit->unitType) * static_cast<short>(unitSpriteCellWidth);
    RECT nSrc = {nSpriteX, nSpriteY, nSpriteX + unitSpriteCellWidth,
                 nSpriteY + unitSpriteCellHeight};
    RECT nDst;
    ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(neighborUnit, &nDst);
    ResetQuickDrawStrokeState();
    UpdatePaletteIndexWithDefaultFallback(0x10);
    if (ClipSrcRectToBoundsAndOffsetDstRect(corners, &nDst, &nSrc)) {
      OffsetRectForSurfaceDibFlip(unitSpriteAtlasSurface, &nSrc);
      OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &nDst);
      BlitRectWithOptionalTransparency(&unitSpriteAtlasSurface->blitSurface,
                                       &g_pActiveQuickDrawSurfaceContext->blitSurface, &nSrc, &nDst,
                                       0x24, 0);
    }
    SetQuickDrawStrokeColor(0xffffff);
  }

  // Gun-slot wall overlay when an occupant is present in the wall slot.
  if (edgeKind != kFortWallEdgeNone && gunSlotOccupied && edgeKind != kFortWallEdgeEvenRowLeft) {
    short slotSpriteX = (edgeKind + 8) * static_cast<short>(tileWidthPx);
    RECT slotSrc = {slotSpriteX, 0, slotSpriteX + tileWidthPx, tileRowHeightPx};
    RECT slotDst = {paintLeft, paintTop + 1, paintLeft + tileWidthPx,
                    paintTop + 1 + tileRowHeightPx};
    if (paintLeft < 0) {
      slotSrc.left = -paintLeft;
      slotDst.left = 0;
    }
    OffsetRectForSurfaceDibFlip(fortLevelAtlasSurface, &slotSrc);
    OffsetRectForSurfaceDibFlip(g_pActiveQuickDrawSurfaceContext, &slotDst);
    UpdatePaletteIndexWithDefaultFallback(0x10);
    BlitRectWithOptionalTransparency(&fortLevelAtlasSurface->blitSurface,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &slotSrc,
                                     &slotDst, 0x24, 0);
    SetQuickDrawStrokeColor(0xffffff);
  }

  // Deployment-zone tick marks along the column midline.
  if (tacticalBattle->tileMoveCostArray[sideSlot] > 0) {
    int tickMidX = tileWidthPx / 2 + paintLeft;
    int tickMidY = tileRowHeightPx / 2 + paintTop;
    SetQuickDrawFillColor(0);
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX - 2),
                                            static_cast<short>(tickMidY));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX + 2), static_cast<short>(tickMidY));
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX - 1),
                                            static_cast<short>(tickMidY + 1));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX + 1),
                                 static_cast<short>(tickMidY + 1));
    if ((row < 2 && tacticalBattle->currentSide == 0) ||
        (row / 2 == tacticalBattle->battlefieldColumnCount - 1 &&
         tacticalBattle->currentSide == 1)) {
      SetQuickDrawFillColorFromPaletteIndex(0x13);
    } else if (tacticalBattle->tileThreatLevelArray[tileIndex] == 0) {
      g_pViewMgr->SetForeColor(0x34);
    } else {
      g_pViewMgr->SetForeColor(0x33);
    }
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX - 1),
                                            static_cast<short>(tickMidY - 1));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX + 1),
                                 static_cast<short>(tickMidY - 1));
    SetQuickDrawTextOriginWithContextOffset(static_cast<short>(tickMidX - 1),
                                            static_cast<short>(tickMidY));
    DrawCenteredGuideLineOnMapDc(static_cast<short>(tickMidX + 1), static_cast<short>(tickMidY));
  }
}
