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
      reinterpret_cast<void(__cdecl*)(int)>(SetQuickDrawFillColorFromPaletteIndex)(0);
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

// FUNCTION: IMPERIALISM 0x005aa2e0
void TTacArmyView::ApplyRectSlot110(RECT* rectBuffer) {}

// FUNCTION: IMPERIALISM 0x005aa900
undefined TTacArmyView::OrphanRetStub_005a83c0() {
  return 0;
}
