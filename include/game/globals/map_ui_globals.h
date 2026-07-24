#pragma once
// Split from global_data_tables.h by tools/analysis/split_globals.py
// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;
// assignment evidence: docs/reference/subsystem_assignment.csv.
#include "game/globals/prelude.h"

// Map-dialog viewport width in tiles (0x51ac40 centers on a tile by column - span/2).
// int, not short: 0x51adf0 reads the full dword; word readers use static_cast<short>.
extern int g_wMapDialogViewportTileSpan; // 0x6a33b0

// Scratch remap from pre-existing city-region id to compact id. The load-map form of
// TMapMaker::AssignOrCompactCityRegionIdsAndRebuildBorders clears all 256 entries to -1 before populating it.
extern int g_cityRegionIdRemapTable_006a3498[0x100];

// Coarse 27x15 region-grid neighbour deltas. These are a second set of the same
// offset-coordinate hex directions used by TMapMaker::GetAdjacentRegionGridCell.
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

// TCitySiteView's currently painted six-neighbor highlight set. Each entry is a map tile
// index or -1; the paint pass restores the previous cells before replacing this cache.
extern short g_aStrategicMapNeighborHighlightTiles_00697320[6];

// Strategic-map preview cursor and the two half-cell parity remainders maintained while
// converting its point into a viewport cell.
extern CPoint g_MapInteractionPreviewPoint_006a3370;

extern int g_MapInteractionPreviewRowParity_006a33b4;

extern int g_MapInteractionPreviewColumnParity_006a33b8;

extern "C" const char s_SourcePathUMapDlog_006973D0[];

extern double g_MapPreviewScaleX6A3410;

extern double g_MapPreviewScaleY6A33D0;

extern short g_MapPreviewVerticalOffset6A3448;

// Strategic-map screen-coordinate conversion scales (1/64). MSVC500 emits their
// dynamic initializers at 0x519910/0x519940, matching the original BSS-backed globals.
extern double g_mapCellRowScale_006a3360;

extern double g_mapCellColumnScale_006a3388;

} // extern "C"
