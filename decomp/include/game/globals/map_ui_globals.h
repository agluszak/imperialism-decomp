#pragma once
#include "game/globals/global_types.h"

extern int g_wMapDialogViewportTileSpan;

// Most recently clicked strategic-map tile.
extern int g_lastClickedMapTileIndex;

extern int g_cityRegionIdRemapTable[256];

extern int g_coarseHexColOffsetEvenRow[6];

extern int g_coarseHexRowOffset[6];

extern int g_coarseHexColOffsetOddRow[6];

extern int g_mapGenDesertQuota;

extern int g_mapGenMountainQuota;

extern int g_mapGenHillsQuota;

extern int g_mapGenForestQuota;

extern int g_mapGenSwampQuota;

extern int g_mapGenRiverCount;

extern int g_riverConnectionTypeByDirectionPair[6][6];

extern "C" {
extern TQuickDrawSurfaceContext* g_pCitySiteCachedPrimaryRenderSurfaceContext;

// Counts strategic-map tile cache misses serviced by TMapDialog::Draw.
extern short g_MapTileCacheMissCount6A3454;

extern short g_aStrategicMapNeighborHighlightTiles[6];
extern short g_aCitySiteNeighborHighlightTiles[6];

extern CPoint g_MapInteractionPreviewPoint;

extern int g_MapInteractionPreviewRowParity;

extern int g_MapInteractionPreviewColumnParity;

extern "C" char s_SourcePathUMapDlog[];

extern double g_MapPreviewScaleX6A3410;

extern double g_MapPreviewScaleY6A33D0;

extern short g_MapPreviewVerticalOffset6A3448;

extern double g_mapCellRowScale;

extern double g_mapCellColumnScale;

extern double g_mapProjectionColumnScale;
extern double g_mapProjectionRowScale;
extern short g_mapProjectionSeamColumn;

} // extern "C"
