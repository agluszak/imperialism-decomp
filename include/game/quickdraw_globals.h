#pragma once

#include "game/TQuickDrawSurfaceContext.h"

extern int g_nQuickDrawStrokeStylePrimary;
extern int g_nQuickDrawStrokeStyleSecondary;
extern int g_bQuickDrawStrokePairDirty;
extern int g_pGlobalClipRegionHandleObject;
extern int g_Quick_Draw_Color_State_006950FC;
extern int g_uQuickDrawCurrentColor;
extern int g_uQuickDrawStrokeColor;
extern int g_nQuickDrawOriginX;
extern int g_nQuickDrawOriginY;

void SetQuickDrawFillColor(int fillColor);
void SetQuickDrawStrokeColor(int strokeColor);
void SetGlobalQuickDrawOrigin(short originX, short originY);
void SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(short styleParamA, short styleParamB);
void SnapshotHitRegionToClipCache(int* clipDescriptor);
void ResetQuickDrawStrokeState();
void FillRectWithQuickDrawBrushAndContextOffset(RECT* rect);
