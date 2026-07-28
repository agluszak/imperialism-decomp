#pragma once
// Subsystem-owned global declarations. Definitions and address markers live in
// src/game/core/global_data_tables.cpp.
#include "game/globals/prelude.h"

extern POINT g_ptMapModeModalMessage; // @ 0x6a45c0

extern SeapointStretch g_seapointQuadTable_006a3478;

extern SeaSegmentStretch g_regionBorderLinkTable_006a3900;

// Per-hex-direction adjacency bit masks (1,2,4,8,16,32), indexed by direction 0..5. Read
// byte-wise (OR'd into per-tile adjacency mask bytes) by the tile-adjacency update pass.
extern const unsigned short g_hexDirectionBitMasks_00696e40[6];

// Second copy of the per-hex-direction adjacency bit mask table (1,2,4,8,16,32,0), indexed
// by direction 0..6 (index 6 is an unused trailing zero); read byte-wise into
// TTerrainStateRecord::adjacencyBits06 by SetHexAdjacencyDirectionFlagsForTilePair.
extern const unsigned short g_hexDirectionBitMasksAlt_00696ea8[7];

// One-shot assert-suppression flags for the UMapper overlay-segment passes (0x006a3910 for the
// scanline fill, 0x006a3914 for the route rebuild).
extern int g_bOverlayScanlineFillAssertSuppressed;

extern int g_bOverlayRouteRebuildAssertSuppressed;

extern char s_mcflavor_00697238[];

extern char g_szScriptFileName_006972f8[];

extern char g_szFmtZone_006972e8[];

extern char g_szFmtShip_006972d0[];

extern char g_szFmtArmy_006972bc[];

extern char g_szFmtCivi_006972ac[];

extern char g_szFmtPort_006972a0[];

extern char g_szFmtRail_00697294[];

extern char g_szFmtCapa_00697280[];

extern char g_szFmtLabo_00697268[];

extern char g_szFmtEmba_00697254[];

extern char g_szFmtYear_00697248[];

extern "C" {

// Per-civilian-order-type map-improvement sprite class (0x697040), read by
// TMapMgr::GetMapImprovementSpriteBaseOffset via TCivUnit::orderType; only indices 0-8 are
// non-zero (values 0-8), true bound beyond that unconfirmed.
extern short g_anMapImprovementSpriteClassByOrderType[9];

extern "C" const char s_szDoubleNewline_00699438[];

// Assert source-path string for the USuperMap TU (TMapUberPicture family).
extern "C" const char g_szDoubleQuote[];
extern "C" const int kLoungeStatusGlyphIds[5];
extern "C" const char s_SourcePathUSuperMap_0069943C[];

// Default mini-map viewport-marker width. Retail derives the nine-column span during
// CRT initialization from the UStatusViews.cpp 1/64 coordinate scale.
extern "C" short g_defaultMarkerBoxWidth_006a460c;

extern unsigned char g_abResourceTypeUsesHighNibbleFlag[24];

// TMapMgr.cpp — per-resourceType capability-category code, compared for equality against
// a caller-supplied category code by FindMaxResourceCapabilityValueForTile (0x513720).
extern unsigned char g_abResourceTypeCapabilityCategory[24];

// TMapMgr.cpp — hex-area neighbor lookup tables.
extern short g_Build_Hex_Area_LookupTable_00696E70[];

extern short g_Build_Hex_Area_LookupTable_00696E80[];

// TMapMgr.cpp — per-StrategicTerrainKind capability table at 0x00696f08, read by
// MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA for both the origin tile and each
// of its hex neighbors. Technology checks update its Hills, Mountain, and Swamp elements.
extern unsigned char g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainCount];

// TMapMgr.cpp — per-StrategicTerrainKind priority score, read by
// TMapMgr::UpdateTilePrimaryAndSecondaryNeighborLinksByPriority (0x50fca0) to rank same-city
// hex neighbors when picking primaryNeighborTileIndex40/secondaryNeighborTileIndex3e. Indexed
// all eight strategic terrain kinds; read raw at 0x00696e10.
extern short g_anStrategicTerrainNeighborLinkPriority[kStrategicTerrainCount];

// TMapMgr.cpp — running region-marker id, assigned to a tile's regionSubtypeTag05 by
// TMapMgr::FloodFillTileRegionMarker (0x5143d0) and incremented (low 16 bits only) after each
// call. Read raw at 0x00696d90 (initial value 1).
extern int g_nNextRegionMarkerId;

// TMapMgr.cpp — per-tile sprite-variant bitmap-strip offset tables, indexed
// [gateFlag][spriteVariantIndex01] (table39 by spriteVariantIndex01 alone). Read by the
// rendering-variant lookup family (0x516150/0x5161a0/0x5161e0/0x516220).
extern short g_awTileSpriteVariantOffsetTable38[16][2];

extern short g_awTileSpriteVariantOffsetTable39[8];

extern short g_awTileSpriteVariantOffsetTable3a[16][5];

extern short g_awTileSpriteVariantOffsetTable3b[16][2];

extern const float g_HexHighlightScreenScale_00658640;

extern float g_TileHeatmapNeighborDiffusionFactor;

} // extern "C"
