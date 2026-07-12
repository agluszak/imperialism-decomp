# WIP: 0x5aa900 TTacArmyView::DrawTacticalTileInClipRect (6235 bytes) port notes
Delete when the port lands. Currently near-0% (baseline 1.9%). Decompile banked at
scratchpad/tactile.dec (840 lines; re-dump with `just ghidra-decompile 0x5aa900` after rollbacks).

## All callees resolved -- every one already ported
- 0x405493 -> BlitRectWithOptionalTransparency (13 calls), 0x402bdf -> SetQuickDrawStrokeColor (11),
  0x4010be -> UpdatePaletteIndexWithDefaultFallback (11), 0x4088aa -> ResetQuickDrawStrokeState (10),
  0x406b86 -> SetQuickDrawFillColor (7), 0x40330f -> SetQuickDrawFillColorFromPaletteIndex,
  0x4043cc -> ClipRect_AdjustOffset_Validate, 0x4035d5 -> ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset,
  0x40633e -> IntersectRectWrapper, 0x405f7e -> RenderTacticalBattleSelectionAndUnitOverlayPass_Impl(5a42e0),
  0x403715 -> CreateTArmyBattleInstance(5a4690), 0x409070 -> ApplyGridColumnSelectionGuard(5a41c0),
  0x4079f5 -> DrawHexSelectionOutlineSegments, 0x405c27 -> DrawFrameRectOrUpdateClipRegion,
  0x4055ec -> FindLinkedListNodeByIdFieldAt18(4a0d30 -- NOTE: that address is TAnimator::AddObjectToUiTransientRegistry?! verify).
  Also SetQuickDrawTextOriginWithContextOffset / DrawCenteredGuideLineOnMapDc (named in decompile),
  0x4032ec / 0x405b87 unresolved yet.

## Receiver model (all named already)
this = TTacArmyView : TTacticalBattleView. Fields: tacticalBattle60 (TTacticalBattle*),
tileGrid4 = battle->+4 (TacticalTileRecord stride 0x14: terrainType0, occupant4, deployMark8,
mineRunStateC, trenchMask10), viewOriginX78, tileColumnsPerRow80(0x1d), tileWidthPx88,
tileRowHeightPx8C, unitSpriteCellWidth90/Height94, surfaces 64/68/6c/70/74, battle->+0x10.

## Function shape (param_1 = tile index; ~7 passes)
1. Tile rect: col=idx%29(field80), row=idx/29; x=col*tileW - viewOriginX78 (+tileW/2 on odd rows);
   y=row*rowH; IntersectRectWrapper early-out; when x+tileW > this->field34(TView) use 4-dword alt rect.
2. Edge/terrain classification (rows: idx+0x1d / idx+0x1c) -> local_124 in {0,1,2,3}; overlay flags via
   RenderTacticalBattleSelection... checks.
3. Column guide lines (battle->+0x10==0 && row>0): g_pUiRuntimeContext vslot 0x34, ApplyGridColumnSelectionGuard,
   SetQuickDrawFillColor + 4x {SetQuickDrawTextOriginWithContextOffset; DrawCenteredGuideLineOnMapDc} at
   yMid=rowH/2 offsets +1/-1.
4. TRENCH pass (tileGrid[idx].trenchMask10 != 0): local int table (pairs decoded in scratchpad lines 175-250:
   {0,0xe,..}, 36 ints = 6x6 trench-segment sprite index matrix by (secondBit + firstBit*6)) + int[6]
   {0x19,0x1a,0x1b,0x16,0x17,0x18} single-segment sprite indices; mask bit-scan finds first/second set bits
   (bits 0-5; bit 7 = full-trench flag -> spriteIndex = firstBit+1 and an EXTRA full-tile blit first);
   srcX = spriteIndex * tileWidthPx88 from the trench atlas; blit; stroke color reset.
   REPEATED MOTIF (good inline-helper candidate IF original inlined it): DIB vertical-flip offset --
   `if (surfaceDib) { h = abs(dib->m_pInfoHeader->bmiHeader.biHeight); OffsetRect(&r, 0, h - top - bottom); }`
   appears per-surface before each blit (g_pActiveQuickDrawSurfaceContext, fortLevelAtlasSurface6C, ...).
5. FORT-WALL pass (tileGrid[row-part].deployMark8 == 1?? decompile line ~310: [grid + local_110 + 8] == 1):
   fort atlas 6c, srcX = level*3*cellW90 pattern (sVar4*3 etc.), scratch via 0x405b87.
6. UNIT pass: occupant4 sprite via ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset + atlas 68 blits,
   selection outline via DrawHexSelectionOutlineSegments (2 calls), frame rects via DrawFrameRectOrUpdateClipRegion.
7. Read tail (scratchpad lines 330-840) for passes 5-7 detail -- NOT yet transcribed.

## Port strategy agreed with user
Dedup the repeated blocks with `static` inline-able local helpers (MSVC5 /Ob1 inlines
functions defined inline; verify codegen matches vs writing blocks out longhand -- if the
original emitted straight-line repeats, a static helper that fully inlines gives identical
bytes while deduplicating source). Candidates: the DIB-flip offset block, the
{ResetQuickDrawStrokeState; UpdatePaletteIndexWithDefaultFallback} pair, srcRect+blit setup.

## Unit-pass block decoded (decompile lines 330-410) -- THE canonical repeated motif
unit = tileGrid[neighborIdx].occupant4; if (unit):
  srcX = unit->+0x0c * cellW90 (+ cellW90/2 when odd row); srcY = unit->+0x20 ? cellH94 : 0;
  srcRect = {srcX, srcY, +cellW90, +cellH94};
  ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset(...); ResetQuickDrawStrokeState();
  UpdatePaletteIndexWithDefaultFallback();
  if (ClipRect_AdjustOffset_Validate(&dst)) {
    <DIB-flip offset on unitSpriteAtlasSurface68 for srcRect>
    <DIB-flip offset on g_pActiveQuickDrawSurfaceContext for dstRect>
    BlitRectWithOptionalTransparency(&atlas68->blitSurface /* ctx+4 */,
                                     &g_pActiveQuickDrawSurfaceContext->blitSurface, &src, &dst);
  }
  SetQuickDrawStrokeColor(&...);
Neighbor selection: edgeKind(local_124) 1/5 -> puStack_b0 idx, 2/4 -> local_c4 idx (the row-adjacent
tiles computed in the prologue). Fort pass mirrors this with fortLevelAtlasSurface6C and
srcX=(level*3[+facing])*cellW90.
