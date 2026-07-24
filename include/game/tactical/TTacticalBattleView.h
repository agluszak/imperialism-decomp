#pragma once

#include "compat.h"

#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class astruct_13;
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
                              CPoint origin) override;              // slot 0x47 0x5a8660
  virtual void TacticalBattleViewSlot68(int param_1);               // slot 0x68 0x5a8900
  virtual void InvalidateTacticalUnitTileRect(TTacticalUnit* unit); // slot 0x69 0x5a89a0
  // Writes the on-screen RECT of a unit's tile (grown 0x18 px upward, bottom-4;
  // zero RECT when tileIndex8 == -1). Hedged name.
  virtual void ComputeTacticalUnitTileScreenRect(TTacticalUnit* unit,
                                                 RECT* rectOut); // slot 0x6a 0x5a89f0
  virtual void Scroll(MapScrollEdgeMaskStorage scrollDirection); // slot 0x6b 0x5a8be0
  // Per-tile drawer for the rect applier's 0..0x1b2 pass (base = no-op; the army view
  // override renders the tile). Old OrphanRetStub name was junk; ret 8 = 2 args.
  virtual void DrawTacticalTileInClipRect(TacticalTileIndex tileIndex,
                                          RECT* clipRect); // slot 0x6c 0x5a83c0
  virtual void
  RunOneTimeAnimationModalWaitAndInvalidateCityDialog(RECT* rect, int effectId, int frameCount,
                                                      TacticalTileIndex tileIndex,
                                                      int mode); // slot 0x6d 0x5a9170 (ret 0x14)
  virtual void PlayTacticalTileEffect(TacticalTileIndex tileIndex, int effectId,
                                      int frameCount); // slot 0x6e 0x5a9090
  virtual void
  AnimateTacticalUnitMoveBetweenTiles(TTacticalUnit* unit, TacticalTileIndex fromTileIndex,
                                      TacticalTileIndex toTileIndex); // slot 0x6f 0x5a9240
  // Takes no args (bare ret; the old astruct_13* param was a Ghidra artifact).
  virtual void DrawUiTilesAndOverlay(); // slot 0x70 0x5a9550
  // View-local slice (+0x60..; TView ends at +0x5c). Offsets verified in the tile-rect
  // and move-animation bodies; gaps unobserved.
  TTacticalBattle* tacticalBattle60; // +0x60 the battle this view renders
  // Offscreen surfaces allocated/loaded by the live-battle initializer (0x5a9d90);
  // all released through RemoveGWorld.
  struct TQuickDrawSurfaceContext* battlefieldSurface64;     // +0x64 0x5dc x 0x1c2 backdrop
  struct TQuickDrawSurfaceContext* unitSpriteAtlasSurface68; // +0x68 bitmap 0xee2 atlas
  struct TQuickDrawSurfaceContext* fortLevelAtlasSurface6C;  // +0x6c fort bitmap 0xee6+lvl/0xee7
  struct TQuickDrawSurfaceContext* tileScratchSurface70;     // +0x70 one-tile scratch
  struct TQuickDrawSurfaceContext* effectAtlasSurface74;     // +0x74 bitmap 0xeeb effects
  short viewOriginX78;                   // +0x78 horizontal scroll origin (pixels)
  short scrollableContentWidth7A;        // +0x7a total content width (scroll clamp max)
  unsigned char pad7c[4];                // +0x7c
  int tileColumnsPerRow80;               // +0x80 = 0x1d (grid stride)
  int field84;                           // +0x84 set -1 by 0x5a9d90; use unobserved
  int tileWidthPx88;                     // +0x88 tile width in pixels
  int tileRowHeightPx8C;                 // +0x8c tile row height in pixels
  int unitSpriteCellWidth90;             // +0x90 sprite-sheet cell width
  int unitSpriteCellHeight94;            // +0x94 sprite-sheet cell height / facing-row offset
  unsigned char modalAnimWaitDoneFlag98; // +0x98 0 during the 0x5a9170 modal wait, then 1
  unsigned char pad99[3];                // +0x99
  int moveAnimStepX9C;                   // +0x9c (toX-fromX)/3 animation step
  int moveAnimStepYA0;                   // +0xa0 (toY-fromY)/3 animation step
  int moveAnimUnitOffsetXA4;             // +0xa4 unit x offset in the anim rect; -1 = idle
  int moveAnimUnitOffsetYA8;             // +0xa8 unit y offset in the anim rect
  RECT moveAnimSpriteSrcRectAC;          // +0xac sprite-sheet source rect
  struct TQuickDrawSurfaceContext* unitSpriteScratchSurfaceBC; // +0xbc 2x3-cell scratch
  RECT moveAnimScreenRectC0;                                   // +0xc0 on-screen animation rect
  // +0xd0 zeroed by ctor; the only subclass (TTacArmyView, 0x5a9d90) resolves the
  // 'tool' control here and stores it as a TTacticalToolbar*.
  TTacticalToolbar* toolbarD0;

  TTacticalBattleView();

  // Tactical-battle UI helpers dispatched from the TTacticalBattle command handlers
  // (all __thiscall on the live view; verified at every call site).
  void UpdateTacticalActionControlBitmapForCurrentUnit(char side);        // 0x5a9b40
  void InvalidateTacticalHexTileRect(TacticalTileIndex tileIndex);        // 0x5a8860
  void CenterViewportAroundGridIndexAndSnap(TacticalTileIndex tileIndex); // 0x5a8ac0
  void SpawnTacticalUiMarkerAtUnitTile();                                 // 0x5a9bb0
  // Maps a screen point to a clamped hex (row, col) on this battle's grid. 0x5a86d0.
  void ConvertScreenPointToHexGridCoordClamped(POINT* screenPoint, int* outRow, int* outCol);
  // Validates the full local `{0,0,width,height}` bounds through TView's slot 0x32.
  void SyncStatusPanelBounds();       // 0x5a8790
  void TriggerTacticalUiUpdate2711(); // 0x5a9cc0
  // Writes the on-screen RECT of a bare hex tile (no unit growth). 0x5a87d0.
  void ComputeTacticalHexTileScreenRect(RECT* rectOut, TacticalTileIndex tileIndex);
  // Writes unit's on-screen sprite rect (tile rect grown 0x14px upward), then applies
  // a trench-facing pixel offset (unrecovered table) when the unit's tile is a fresh
  // trench-deploy mark, or clips the rect off-screen for a specific hidden-in-trench
  // case. 0x5aa7d0.
  void ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(TTacticalUnit* unit, RECT* rectOut);
  // Orientation-index lookup (0-6ish) for a unit sprite at tileIndex, based on which
  // of the two "opposite" hex neighbors (by parity of tileIndex) are trench-deploy
  // tiles; indexes an unrecovered 20-short table. 0x5aa670.
  short
  ComputeTacticalUnitSpriteOrientationIndexByAdjacentType1Occupancy(TacticalTileIndex tileIndex);

  // +0xd4 -- never touched by this class's own ctor; the only subclass (TTacArmyView,
  // 0x5a9d90) writes a battlefield x-origin offset here as a short. +0xd6 is still
  // unconfirmed padding.
  short battlefieldOriginOffsetXD4;
  unsigned char padD6[2];
};
ASSERT_SIZE(TTacticalBattleView, 0xd8);

// Clips srcRect to bounds, shifting dstRect by the same per-edge delta so the two
// stay in sync (the standard blit-clip prologue before a QuickDraw surface blit).
// Returns non-zero iff the clipped srcRect is still non-empty. 0x005a6940
BOOL __cdecl ClipSrcRectToBoundsAndOffsetDstRect(RECT* bounds, RECT* dstRect, RECT* srcRect);

// Draws four short corner-tick brackets around rect's edges (a hex-selection
// highlight idiom), shrinking rect->right/bottom by 1 first. 0x005a99e0
void __stdcall DrawHexSelectionOutlineSegments(RECT* rect);
