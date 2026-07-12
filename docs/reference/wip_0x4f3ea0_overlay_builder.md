# WIP: 0x4f3ea0 TDiplomacyMapView::BuildDiplomacyNationOverlayGeometryAndHitMasks port notes

Delete when the port lands. Currently a claimed manual {} stub.

# NEXT PORT: 0x4f3ea0 TDiplomacyMapView::BuildDiplomacyNationOverlayGeometryAndHitMasks (1534B)
Banked: overlay_4f3ea0.dec / overlay_4f3ea0.asm in scratchpad. Currently a claimed manual `{}` stub in TDiplomacyMapView.cpp.
Shape: EH-framed; three 46-byte short-array locals zeroed (label X/extent/Y arrays for 23 nations: asStack_a0/70/40 + local_9c/6c/3c pairs = short[23]x3);
1. field9c = CreateClipStateRegionWrapperObject(); for i in 0..0x16: if g_apTerrainTypeDescriptorTable[i]: CombineTwoRegionsIntoDestinationAndUpdateBox(field9c, g_pStrategicMapViewSystem->GetClipRegionSlotByIndex(i));
2. this+0x514=0x31, +0x518=0x2d, +0x51c=0x24d, +0x520=0x159 (origin/extent block -- extend TDiplomacyMapView fields 51c/520!).
3. ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(0, 10, 0x2b68).
4. Per nation i (rects at this+0x1eb0 stride 0x10, masks at this+0xc4? pLStack chain, buffers at +0x2078?):
   region = GetClipRegionSlotByIndex(i); BuildDiplomacyNationOverlayGeometryAndHitMasks_Impl(0x4955f0 -- UNPORTED, check); CopyRect(rect, region->box); width rounded up to 8; mask = operator new(w*h); per pixel byte: 8 IsPointInsideHitRegion tests packed LSB-first (+= bit); WrapperFor_thunk_BuildDiplomacyOverlayHitMaskOpcodeStream(mask, g_pPrimaryRenderSurfaceContext, 1);
   label: CString name; if region non-empty (GetRegionBoxToRectIfPresent) : anchor=GetOrComputeOverlayAnchorTileIndex(); x=(anchor%0x6c)*5+0x31; y=(anchor/0x6c+9)*5; LoadNationDisplayNameSharedRefFromField8(&name); w=MeasureTextExtentWithCachedQuickDrawStyle(...); label-collision slide loop (LAB_004f4157..) storing per-nation label X/Y/width into the three short arrays and into object fields [pLStack_d0[0x5c]/[0x5d]] = nation object +0x170/0x174?;
   read rest of decompile lines 180-285 for the collision loop details.
Ownership: IsPointInsideHitRegion/GetRegionBoxToRectIfPresent (quickdraw_regions, ported); 0x4d5cf0/0x4d7170/0x4d7a40 -- check.

## Collision loop (decompile lines 180-240)
Per candidate label position (x=anchor%108*5+0x31, y=(anchor/108+9)*5): scan placed labels j in 0..0x16;
overlap test uses per-label arrays width[23] (default 0x5a when 0), x[23], y[23] (the three zeroed short-array locals);
on overlap nudge y+1 (or y-1 in the second clause) up to 0x14 attempts then advance j. On placement:
store x/y/width into the arrays + nation object label rect at TCountry [0x5c..0x5f]*4 (=+0x170..0x17c),
call thunk 0x40849f(labelRect, buf+8), and write the marker rect from ownerNationSlot%108*5 (+0x29/-8/+0x39/+8)
into TCountry [0xb8..0xbb]*4 (=+0x2e0..0x2ec). Empty-region nations zero their four label fields + rect.
Remaining to identify: thunk 0x40849f, 0x4d5cf0 (mask opcode stream builder), 0x4d7170 (anchor tile), 0x4955f0 (_Impl -- possibly unowned stub).
