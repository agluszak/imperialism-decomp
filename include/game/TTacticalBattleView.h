#pragma once

#include "game/TView.h"
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
  virtual ~TTacticalBattleView() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x5a8430
  // slot 0x08 ShallowClone inherited unchanged (0x48bfd0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a IsEnabled inherited unchanged (0x48a240)
  // slot 0x0b SetEnable inherited unchanged (0x48a260)
  // slot 0x0c GetNextHandler inherited unchanged (0x48a2c0)
  // slot 0x0d DispatchQueuedUiCommandAndRelease inherited unchanged (0x48a3b0)
  // slot 0x0e DispatchUiSelectionToHandler inherited unchanged (0x48a3f0)
  // slot 0x0f DoEvent inherited unchanged (0x48a280)
  // slot 0x10 HandleEvent inherited unchanged (0x48a2e0)
  // slot 0x11 DoMenuCommand inherited unchanged (0x48a310)
  virtual void DoKeyEvent(TToolboxEvent* event) override; // slot 0x12 0x5a8550
  // slot 0x13 DoIdle inherited unchanged (0x48a480)
  // slot 0x14 GetIdleFreq inherited unchanged (0x415d50)
  // slot 0x15 SetIdleFreq inherited unchanged (0x415d70)
  // slot 0x16 GetWindow inherited unchanged (0x48b180)
  // slot 0x17 WantsToBeTarget inherited unchanged (0x48a530)
  // slot 0x18 WillingToResignTarget inherited unchanged (0x48a550)
  // slot 0x19 ResignedTarget inherited unchanged (0x48a690)
  // slot 0x1a TargetValidationFailed inherited unchanged (0x48a6b0)
  // slot 0x1b TargetValidationSucceeded inherited unchanged (0x48a650)
  // slot 0x1c BecameWindowTarget inherited unchanged (0x48a6d0)
  // slot 0x1d ResignedWindowTarget inherited unchanged (0x48a670)
  // slot 0x1e BecameTarget inherited unchanged (0x48a6f0)
  // slot 0x1f BecomeTarget inherited unchanged (0x48a570)
  // slot 0x20 ResignTarget inherited unchanged (0x48a5e0)
  // slot 0x21 SelectOwner inherited unchanged (0x48a710)
  // slot 0x22 IsTarget inherited unchanged (0x48a500)
  // slot 0x23 RemoveBehavior inherited unchanged (0x48a4a0)
  // slot 0x24 AddBehavior inherited unchanged (0x48a4d0)
  // slot 0x25 ResolveControlByTag inherited unchanged (0x48afd0)
  // slot 0x26 SwitchActiveChildAndNotify inherited unchanged (0x48af80)
  // slot 0x27 Open inherited unchanged (0x48c820)
  // slot 0x28 Close inherited unchanged (0x48c890)
  // slot 0x29 SetEnabled inherited unchanged (0x48b1c0)
  // slot 0x2a SetState inherited unchanged (0x48b070)
  // slot 0x2b GetField4E inherited unchanged (0x427200)
  virtual void DoSetCursor(CPoint* point,
                           RgnHandle hitArg) override; // slot 0x2c 0x5a8ca0
  // slot 0x2d HandleHelp inherited unchanged (0x48c1c0)
  // slot 0x2e GetDrawableRegion inherited unchanged (0x48c1e0)
  // slot 0x2f GetEventNumber inherited unchanged (0x430bd0)
  // slot 0x30 InvalidateOffsetRegionUsingChildClipRect inherited unchanged (0x48b4b0)
  // slot 0x31 ForwardMapViewVirtualC4IfPresent inherited unchanged (0x48ab90)
  // slot 0x32 ValidateControlRectIfWindowActive inherited unchanged (0x48b690)
  // slot 0x33 EvaluateControlInputGate inherited unchanged (0x48c000)
  // slot 0x34 HasRenderableParentAndContent inherited unchanged (0x48c050)
  virtual void HandleCursorHoverSelectionByChildHitTestAndFallback(
      CPoint* point,
      RgnHandle hitArg) override; // slot 0x35 0x5a8d40
  // slot 0x36 DispatchControlEventToChildrenAndSelf inherited unchanged (0x48aaf0)
  virtual void DoPostCreate(int arg) override; // slot 0x37 0x5a84d0
  // slot 0x38 NoOpUiCallback inherited unchanged (0x48abc0)
  // slot 0x39 RefreshControl inherited unchanged (0x48b6d0)
  // slot 0x3a GetRootView inherited unchanged (0x48b1a0)
  // slot 0x3b IsActionable inherited unchanged (0x48b200)
  // slot 0x3c CaptureLayoutF0 inherited unchanged (0x48b250)
  // slot 0x3d CaptureLayout inherited unchanged (0x48b3f0)
  // slot 0x3e Refresh inherited unchanged (0x48b770)
  // slot 0x3f PostRender inherited unchanged (0x427220)
  // slot 0x40 BindMapQuickDrawDc inherited unchanged (0x48b7b0)
  // slot 0x41 ReleaseMapQuickDrawDc inherited unchanged (0x48b7e0)
  // slot 0x42 EnsureField48Buffer inherited unchanged (0x48b810)
  // slot 0x43 PaintVisibleChildrenIntersectingClipRect inherited unchanged (0x48b8d0)
  // slot 0x44 Draw inherited unchanged (0x430bf0)
  // slot 0x45 PaintOrInvalidateControl inherited unchanged (0x48b860)
  // slot 0x46 HandleMouseDown inherited unchanged (0x48c450)
  virtual void DoMouseCommand(CPoint& point, TToolboxEvent* event,
                              CPoint origin) override; // slot 0x47 0x5a8660
  // slot 0x48 HandleMouseUp inherited unchanged (0x48c590)
  // slot 0x49 HandleMouseCommandToSelf inherited unchanged (0x427240)
  // slot 0x4a QueryContentBounds inherited unchanged (0x427260)
  // slot 0x4b QueryBounds inherited unchanged (0x427290)
  // slot 0x4c TranslateRectToWindow inherited unchanged (0x4272d0)
  // slot 0x4d TranslatePointToParentChain4D inherited unchanged (0x48ba80)
  // slot 0x4e TranslatePointToParentChain4E inherited unchanged (0x48ba40)
  // slot 0x4f ForceRedraw inherited unchanged (0x48b700)
  // slot 0x50 LocalToSuperVRect inherited unchanged (0x48bb00)
  // slot 0x51 SuperToLocal inherited unchanged (0x427330)
  // slot 0x52 ViewToQDPt inherited unchanged (0x48bb60)
  // slot 0x53 ViewToQDRect inherited unchanged (0x48bbb0)
  // slot 0x54 AddControlPosToPoint inherited unchanged (0x48bc30)
  // slot 0x55 OffsetRectByCachedPos inherited unchanged (0x48bc60)
  // slot 0x56 GetAbsolutePosition inherited unchanged (0x48bb30)
  // slot 0x57 GetDrawableQDRect inherited unchanged (0x429410)
  // slot 0x58 GetQDExtent inherited unchanged (0x48bce0)
  // slot 0x59 UpdateCoordinates inherited unchanged (0x48b2d0)
  // slot 0x5a UpdateRectCacheIfChangedAndInvalidateCityDialog inherited unchanged (0x48c380)
  // slot 0x5b PointInBoundsAndActionable inherited unchanged (0x48c6d0)
  // slot 0x5c AttachChildControl inherited unchanged (0x48abe0)
  // slot 0x5d DetachUiElementFromOwnerListAndClearBackref inherited unchanged (0x48ae60)
  // slot 0x5e GetHelpState inherited unchanged (0x48c970)
  // slot 0x5f ContainsMouse inherited unchanged (0x48c990)
  // slot 0x60 GoAwayByUser inherited unchanged (0x48c9e0)
  // slot 0x61 MoveByUser inherited unchanged (0x48ca00)
  // slot 0x62 ResizeByUser inherited unchanged (0x48ca20)
  // slot 0x63 ZoomByUser inherited unchanged (0x48ca40)
  // slot 0x64 DrawRectangleInCurrentUiContext inherited unchanged (0x48c750)
  // slot 0x65 AssertMcAppUILine1914 inherited unchanged (0x48c7a0)
  // slot 0x66 AssertMcAppUILine1922 inherited unchanged (0x48c7d0)
  // slot 0x67 WindowToLocal inherited unchanged (0x48bac0)
  virtual undefined TacticalBattleViewSlot68(int param_1);          // slot 0x68 0x5a8900
  virtual void InvalidateTacticalUnitTileRect(TTacticalUnit* unit); // slot 0x69 0x5a89a0
  // Writes the on-screen RECT of a unit's tile (grown 0x18 px upward, bottom-4;
  // zero RECT when tileIndex8 == -1). Hedged name.
  virtual undefined ComputeTacticalUnitTileScreenRect(TTacticalUnit* unit,
                                                      RECT* rectOut); // slot 0x6a 0x5a89f0
  virtual void
  AdjustTacticalUnitVerticalOffsetAndRefreshMarker(short scrollDirection); // slot 0x6b 0x5a8be0
  // Per-tile drawer for the rect applier's 0..0x1b2 pass (base = no-op; the army view
  // override renders the tile). Old OrphanRetStub name was junk; ret 8 = 2 args.
  virtual undefined DrawTacticalTileInClipRect(TacticalTileIndex tileIndex,
                                               RECT* clipRect); // slot 0x6c 0x5a83c0
  virtual undefined
  RunOneTimeAnimationModalWaitAndInvalidateCityDialog(RECT* rect, int effectId, int frameCount,
                                                      TacticalTileIndex tileIndex,
                                                      int mode); // slot 0x6d 0x5a9170 (ret 0x14)
  virtual undefined PlayTacticalTileEffect(TacticalTileIndex tileIndex, int effectId,
                                           int frameCount); // slot 0x6e 0x5a9090
  virtual undefined
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

// Clips srcRect to bounds, shifting dstRect by the same per-edge delta so the two
// stay in sync (the standard blit-clip prologue before a QuickDraw surface blit).
// Returns non-zero iff the clipped srcRect is still non-empty. 0x005a6940
BOOL __cdecl ClipSrcRectToBoundsAndOffsetDstRect(RECT* bounds, RECT* dstRect, RECT* srcRect);

// Draws four short corner-tick brackets around rect's edges (a hex-selection
// highlight idiom), shrinking rect->right/bottom by 1 first. 0x005a99e0
void __stdcall DrawHexSelectionOutlineSegments(RECT* rect);
