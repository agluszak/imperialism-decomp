#include "game/TTacArmyView.h"

#include "game/TAnimation.h"
#include "game/TArmyBattle.h"
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

// SYNTHETIC: IMPERIALISM 0x0045d310
// TTacArmyView::`scalar deleting destructor'
TTacArmyView::~TTacArmyView() {}
// SYNTHETIC: IMPERIALISM 0x005a9cf0
// TTacArmyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a9d70
// TTacArmyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacArmyView, TTacticalBattleView)

TTacArmyView::TTacArmyView() {}

// Legacy free-function bridge for the palette fill-color setter (autogen stub
// 0x4950f0); same pattern as TTransFocusAnimation.cpp / TViewMgr.cpp.
extern undefined4 SetQuickDrawFillColorFromPaletteIndex(void);

// Live battle-view initializer (not a real constructor despite the symbols.csv name):
// caches the tactical tile / sprite metric globals, (re)allocates the offscreen
// battlefield surface and renders the per-composition backdrop bitmap
// (compositionClass + 0xf0a) into it (plus the 286x450 fort strip 0xf0e on the right
// edge when the site is fortified), loads the unit/fort/effect sprite atlases, wires
// the 'tool' toolbar and 'coat' picture to the battle, and refreshes the view.
// Everything past the backdrop-loader null test is skipped when the backdrop bitmap
// is missing (the loader handle then leaks, as in the original).
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
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&battlefieldSurface64);
  }
  if (unitSpriteAtlasSurface68 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&unitSpriteAtlasSurface68);
  }
  if (unitSpriteScratchSurfaceBC != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&unitSpriteScratchSurfaceBC);
  }
  if (fortLevelAtlasSurface6C != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&fortLevelAtlasSurface6C);
  }
  if (tileScratchSurface70 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&tileScratchSurface70);
  }
  if (effectAtlasSurface74 != 0) {
    g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&effectAtlasSurface74);
  }

  TQuickDrawSurfaceContext* savedContext;
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  // Two rect buffers reused across every init/blit below (the original's frame holds
  // exactly two RECT locals).
  RECT bounds;
  RECT overlayBounds;
  bounds.top = 0;
  bounds.right = g_nTacticalBattlefieldSurfaceWidth_006A5448;
  bounds.left = 0;
  bounds.bottom = g_nTacticalBattlefieldSurfaceHeight_006A544C;
  g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&battlefieldSurface64, 8, &bounds);
  TBitmapResourceLoader** loaderHandle =
      CreateBitmapResourceLoaderHandle(static_cast<unsigned short>(compositionClass + 0xf0a));
  SetActiveQuickDrawSurfaceContext(battlefieldSurface64, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(battlefieldSurface64));
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
    ::operator delete(loaderHandle);
    NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(battlefieldSurface64));
    SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);

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
      UpdatePaletteIndexWithFallback(0x13);
      SetQuickDrawFillColorFromPaletteIndex(0);
      BlitQuickDrawSurfaces(fortStripSurface->GetBlitSurface(),
                            battlefieldSurface64->GetBlitSurface(), &bounds, &overlayBounds, 0);
      g_pDisplayMgr->FreeQuickDrawSurfaceContextSlot(&fortStripSurface);
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
    g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&tileScratchSurface70, 8, &bounds);

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
    g_pDisplayMgr->InitializeBitmapSurfaceContextWithRetry(&unitSpriteScratchSurfaceBC, 8,
                                                           &overlayBounds);
    RefreshControl();
    OwnerPanel()->InvokeSlot13C();
  }
}

// Presents the battle view: blits the scrolled backdrop slice from
// battlefieldSurface64 into the primary render surface, draws all 0x1b3 tiles inside
// a saved/restored QuickDraw clip, presents to the restored active surface, then
// draws the UI overlay.
// FUNCTION: IMPERIALISM 0x005aa2e0
void TTacArmyView::ApplyRectSlot110(RECT* rectBuffer) {
  int savedFlags = 0;
  RECT clipRect;
  clipRect = *rectBuffer;

  TQuickDrawSurfaceContext* savedContext;
  GetActiveQuickDrawSurfaceContextAndFlags(&savedContext, &savedFlags);
  SetActiveQuickDrawSurfaceContext(g_pPrimaryRenderSurfaceContext, savedFlags);
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));
  ReturnConstantTrueQuickDrawFlag(GetSurfaceNodeSlot(battlefieldSurface64));

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
  if (battlefieldSurface64->surfaceDib != 0) {
    int backdropHeight = battlefieldSurface64->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (backdropHeight < 1) {
      backdropHeight = -backdropHeight;
    }
    OffsetRect(&backdropSrcRect, 0,
               (backdropHeight - backdropSrcRect.top) - backdropSrcRect.bottom);
  }
  if (g_pPrimaryRenderSurfaceContext->surfaceDib != 0) {
    int primaryHeight =
        g_pPrimaryRenderSurfaceContext->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
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

  SetActiveQuickDrawSurfaceContext(savedContext, savedFlags);
  ResetQuickDrawStrokeState();
  SetQuickDrawStrokeColor(0xffffff);
  // Present: primary render surface -> the restored active surface.
  BlitQuickDrawSurfaces(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                        g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &clipRect,
                        &presentDstRect, 0);
  DrawUiTilesAndOverlay();
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(g_pPrimaryRenderSurfaceContext));
  NoOpQuickDrawLifecycleHookB(GetSurfaceNodeSlot(battlefieldSurface64));
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

  // TODO(codegen): the rest of the original (terrain-edge blend selection using
  // tileGrid4/deployMark8/trenchMask10 and a 36-entry edge-blend table, the unit
  // sprite draw dispatch, the hex-selection outline, and the fort-height indicator
  // bars) is severely decompiler-degraded here (Ghidra flags "type propagation
  // algorithm not settling"; nearly every call's argument list is dropped). Needs a
  // raw-disassembly-driven follow-up pass rather than a guessed transcription. Left
  // unmodeled.
  (void)tileScreenRect;
  return 0;
}
