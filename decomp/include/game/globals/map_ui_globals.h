#pragma once
#include "game/globals/global_types.h"

extern int g_wMapDialogViewportTileSpan; // 0x6a33b0

// Most recently clicked strategic-map tile.
extern int g_lastClickedMapTileIndex_006a4608;

extern int g_cityRegionIdRemapTable_006a3498[0x100];

extern const int g_coarseHexColOffsetEvenRow_00697498[6];

extern const int g_coarseHexRowOffset_006974b0[6];

extern const int g_coarseHexColOffsetOddRow_006974c8[6];

extern int g_mapGenDesertQuota_006a38bc;

extern int g_mapGenMountainQuota_006a3470;

extern int g_mapGenHillsQuota_006a38c0;

extern int g_mapGenForestQuota_006a38f8;

extern int g_mapGenSwampQuota_006a38e0;

extern int g_mapGenRiverCount_006a38e4;

extern const int g_riverConnectionTypeByDirectionPair_00697568[6][6];

extern "C" {
extern TQuickDrawSurfaceContext* g_pCitySiteCachedPrimaryRenderSurfaceContext;

// Counts strategic-map tile cache misses serviced by TMapDialog::Draw.
extern short g_MapTileCacheMissCount6A3454;

extern short g_aStrategicMapNeighborHighlightTiles_00697310[6];
extern short g_aCitySiteNeighborHighlightTiles_00697320[6];

extern CPoint g_MapInteractionPreviewPoint_006a3370;

extern int g_MapInteractionPreviewRowParity_006a33b4;

extern int g_MapInteractionPreviewColumnParity_006a33b8;

extern "C" const char s_SourcePathUMapDlog_006973D0[];

extern double g_MapPreviewScaleX6A3410;

extern double g_MapPreviewScaleY6A33D0;

extern short g_MapPreviewVerticalOffset6A3448;

extern double g_mapCellRowScale_006a3360;

extern double g_mapCellColumnScale_006a3388;

extern double g_mapProjectionColumnScale_006a32f8;
extern double g_mapProjectionRowScale_006a3320;
extern short g_mapProjectionSeamColumn_006a3348;

} // extern "C"
