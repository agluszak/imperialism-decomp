#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

class TTacticalBattle;
class TTacticalUnit;
class TTacticalToolbar;

// VTABLE: IMPERIALISM 0x0066a380
class TTacticalBattleView : public TView {
public:
  DECLARE_DYNCREATE(TTacticalBattleView)
  virtual ~TTacticalBattleView() override;
  virtual void Free() override;
  virtual void DoKeyEvent(TToolboxEvent* event) override;
  virtual void DoSetCursor(CPoint* point, RgnHandle hitArg) override;
  virtual void AdjustCursor(CPoint* point, RgnHandle hitArg) override;
  virtual void DoPostCreate(int arg) override;
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) override;
  virtual void UpdateTile(TacticalTileIndex tileIndex);
  virtual void InvalidateUnit(TTacticalUnit* unit);
  virtual void UnitRect(TTacticalUnit* unit, RECT* rectOut);
  virtual void Scroll(MapScrollEdgeMaskStorage scrollDirection);
  virtual void DrawTile(TacticalTileIndex tileIndex, RECT* clipRect);
  virtual void PlayAni(TacticalTileIndex tileIndex, int effectId, int frameCount);
  virtual void PlayAni(RECT* rect, int effectId, int frameCount, TacticalTileIndex tileIndex,
                       int mode);
  virtual void GlideUnit(TTacticalUnit* unit, TacticalTileIndex fromTileIndex,
                         TacticalTileIndex toTileIndex);
  virtual void DoGlideAni();
  TTacticalBattle* tacticalBattle;                         // +0x60 the battle this view renders
  struct TQuickDrawSurfaceContext* battlefieldSurface;     // +0x64 0x5dc x 0x1c2 backdrop
  struct TQuickDrawSurfaceContext* unitSpriteAtlasSurface; // +0x68 bitmap 0xee2 atlas
  struct TQuickDrawSurfaceContext* fortLevelAtlasSurface;  // +0x6c fort bitmap 0xee6+lvl/0xee7
  struct TQuickDrawSurfaceContext* tileScratchSurface;     // +0x70 one-tile scratch
  struct TQuickDrawSurfaceContext* effectAtlasSurface;     // +0x74 bitmap 0xeeb effects
  short viewOriginX;            // +0x78 horizontal scroll origin (pixels)
  short scrollableContentWidth; // +0x7a total content width (scroll clamp max)
  unsigned char pad7c[4];
  int tileColumnsPerRow;      // +0x80 = 0x1d (grid stride)
  int hoveredTileIndex;       // +0x84 currently highlighted tile, -1 when none
  int tileWidthPx;            // +0x88 tile width in pixels
  int tileRowHeightPx;        // +0x8c tile row height in pixels
  int unitSpriteCellWidth;    // +0x90 sprite-sheet cell width
  int unitSpriteCellHeight;   // +0x94 sprite-sheet cell height / facing-row offset
  bool modalAnimWaitDoneFlag; // +0x98 0 during the 0x5a9170 modal wait, then 1
  unsigned char pad99[3];
  int moveAnimStepX;          // +0x9c (toX-fromX)/3 animation step
  int moveAnimStepY;          // +0xa0 (toY-fromY)/3 animation step
  int moveAnimUnitOffsetX;    // +0xa4 unit x offset in the anim rect; -1 = idle
  int moveAnimUnitOffsetY;    // +0xa8 unit y offset in the anim rect
  RECT moveAnimSpriteSrcRect; // +0xac sprite-sheet source rect
  struct TQuickDrawSurfaceContext* unitSpriteScratchSurface; // +0xbc 2x3-cell scratch
  RECT moveAnimScreenRect;                                   // +0xc0 on-screen animation rect
  TTacticalToolbar* toolbar;

  TTacticalBattleView();

  void SetCurrentPlayer(unsigned char side);
  void InvalidateTile(TacticalTileIndex tileIndex);
  void MakeTileVisible(TacticalTileIndex tileIndex);
  void UpdateSelectionBlink();
  // Maps a screen point to a clamped hex (row, col) on this battle's grid.
  void ConvertPoint(POINT* screenPoint, int* outRow, int* outCol);
  // Validates the full local `{0,0,width,height}` bounds through TView's slot 0x32.
  void SyncStatusPanelBounds();
  void KillSelectionBlink();
  // Writes the on-screen RECT of a bare hex tile (no unit growth).
  void Tile2Rect(RECT* rectOut, TacticalTileIndex tileIndex);
  void GetUnitSpriteRect(TTacticalUnit* unit, RECT* rectOut);
  short GetUnitFacing(TacticalTileIndex tileIndex);

  short battlefieldOriginOffsetX;
};
ASSERT_SIZE(TTacticalBattleView, 0xd8);

BOOL __cdecl ClipSrcRectToBoundsAndOffsetDstRect(RECT* bounds, RECT* dstRect, RECT* srcRect);

void __stdcall DrawHexSelectionOutlineSegments(RECT* rect);
