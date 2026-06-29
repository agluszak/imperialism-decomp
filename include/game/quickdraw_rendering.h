#pragma once

#include "game/mfc.h"

void SetQuickDrawFillColor(int fillColor);
void SetQuickDrawStrokeColor(int strokeColor);
void SetGlobalQuickDrawOrigin(short originX, short originY);
void SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB);
void SnapshotHitRegionToClipCache(int* clipDescriptor);
void ResetQuickDrawStrokeState();
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect);

// QuickDraw clip region functions
undefined4 ApplyHitRegionToClipState(void);
undefined4 ApplyRectClipRegionToGlobalClipState(void);

undefined4 SetQuickDrawTextOriginWithContextOffset(void);
undefined4 DrawCenteredGuideLineOnMapDc(void);

undefined4 UpdatePaletteIndexWithDefaultFallback(void);
undefined4 ApplyUiTextStyleDescriptorToQuickDrawAndSyncColor(void);
