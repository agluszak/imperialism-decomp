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
  virtual ~TTacticalBattleView() override;                // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                           // slot 0x07 0x5a8430
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x5a8550
  virtual void DoSetCursor(CPoint* point,
                           RgnHandle hitArg) override; // slot 0x2c 0x5a8ca0
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(
      CPoint* point,
      RgnHandle hitArg) override;              // slot 0x35 0x5a8d40
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x5a84d0
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override;                // slot 0x47 0x5a8660
  virtual void UpdateTile(TacticalTileIndex tileIndex);               // slot 0x68 0x5a8900
  virtual void InvalidateUnit(TTacticalUnit* unit);                   // slot 0x69 0x5a89a0
  virtual void UnitRect(TTacticalUnit* unit, RECT* rectOut);          // slot 0x6a 0x5a89f0
  virtual void Scroll(MapScrollEdgeMaskStorage scrollDirection);      // slot 0x6b 0x5a8be0
  virtual void DrawTile(TacticalTileIndex tileIndex, RECT* clipRect); // slot 0x6c 0x5a83c0
  virtual void PlayAni(TacticalTileIndex tileIndex, int effectId,
                       int frameCount); // slot 0x6d 0x5a9090
  virtual void PlayAni(RECT* rect, int effectId, int frameCount, TacticalTileIndex tileIndex,
                       int mode); // slot 0x6e 0x5a9170 (ret 0x14)
  virtual void GlideUnit(TTacticalUnit* unit, TacticalTileIndex fromTileIndex,
                         TacticalTileIndex toTileIndex);   // slot 0x6f 0x5a9240
  virtual void DoGlideAni();                               // slot 0x70 0x5a9550
  TTacticalBattle* tacticalBattle;                         // +0x60 the battle this view renders
  struct TQuickDrawSurfaceContext* battlefieldSurface;     // +0x64 0x5dc x 0x1c2 backdrop
  struct TQuickDrawSurfaceContext* unitSpriteAtlasSurface; // +0x68 bitmap 0xee2 atlas
  struct TQuickDrawSurfaceContext* fortLevelAtlasSurface;  // +0x6c fort bitmap 0xee6+lvl/0xee7
  struct TQuickDrawSurfaceContext* tileScratchSurface;     // +0x70 one-tile scratch
  struct TQuickDrawSurfaceContext* effectAtlasSurface;     // +0x74 bitmap 0xeeb effects
  short viewOriginX;            // +0x78 horizontal scroll origin (pixels)
  short scrollableContentWidth; // +0x7a total content width (scroll clamp max)
  unsigned char pad7c[4];       // +0x7c
  int tileColumnsPerRow;        // +0x80 = 0x1d (grid stride)
  int hoveredTileIndex;         // +0x84 currently highlighted tile, -1 when none
  int tileWidthPx;              // +0x88 tile width in pixels
  int tileRowHeightPx;          // +0x8c tile row height in pixels
  int unitSpriteCellWidth;      // +0x90 sprite-sheet cell width
  int unitSpriteCellHeight;     // +0x94 sprite-sheet cell height / facing-row offset
  bool modalAnimWaitDoneFlag;   // +0x98 0 during the 0x5a9170 modal wait, then 1
  unsigned char pad99[3];       // +0x99
  int moveAnimStepX;            // +0x9c (toX-fromX)/3 animation step
  int moveAnimStepY;            // +0xa0 (toY-fromY)/3 animation step
  int moveAnimUnitOffsetX;      // +0xa4 unit x offset in the anim rect; -1 = idle
  int moveAnimUnitOffsetY;      // +0xa8 unit y offset in the anim rect
  RECT moveAnimSpriteSrcRect;   // +0xac sprite-sheet source rect
  struct TQuickDrawSurfaceContext* unitSpriteScratchSurface; // +0xbc 2x3-cell scratch
  RECT moveAnimScreenRect;                                   // +0xc0 on-screen animation rect
  TTacticalToolbar* toolbar;

  TTacticalBattleView();

  void SetCurrentPlayer(unsigned char side);         // 0x5a9b40
  void InvalidateTile(TacticalTileIndex tileIndex);  // 0x5a8860
  void MakeTileVisible(TacticalTileIndex tileIndex); // 0x5a8ac0
  void UpdateSelectionBlink();                       // 0x5a9bb0
  // Maps a screen point to a clamped hex (row, col) on this battle's grid.
  void ConvertPoint(POINT* screenPoint, int* outRow, int* outCol);
  // Validates the full local `{0,0,width,height}` bounds through TView's slot 0x32.
  void SyncStatusPanelBounds(); // 0x5a8790
  void KillSelectionBlink();    // 0x5a9cc0
  // Writes the on-screen RECT of a bare hex tile (no unit growth).
  void Tile2Rect(RECT* rectOut, TacticalTileIndex tileIndex);
  void ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(TTacticalUnit* unit, RECT* rectOut);
  short
  ComputeTacticalUnitSpriteOrientationIndexByAdjacentType1Occupancy(TacticalTileIndex tileIndex);

  short battlefieldOriginOffsetX; // +0xd4
};
ASSERT_SIZE(TTacticalBattleView, 0xd8);

BOOL __cdecl ClipSrcRectToBoundsAndOffsetDstRect(RECT* bounds, RECT* dstRect, RECT* srcRect);

void __stdcall DrawHexSelectionOutlineSegments(RECT* rect);
