#pragma once
#include "game/globals/global_types.h"
#include "game/civilian_domain_types.h"

extern POINT g_ptMapModeModalMessage;

extern SeapointStretch g_seapointQuadTable;

extern SeaSegmentStretch g_regionBorderLinkTable;

extern unsigned short g_hexDirectionBitMasks[6];

extern unsigned short g_hexDirectionBitMasksAlt[7];
extern short g_railDirectionAddMasks[6];
extern short g_railDirectionSubtractMasks[6];

extern int g_bOverlayScanlineFillAssertSuppressed;

extern int g_bOverlayRouteRebuildAssertSuppressed;
extern bool g_applyMiniMapVerticalClipOffset;

extern char g_szScriptFileName[];

extern char g_szFmtZone[];

extern char g_szFmtShip[];

extern char g_szFmtArmy[];

extern char g_szFmtCivi[];

extern char g_szFmtPort[];

extern char g_szFmtRail[];

extern char g_szFmtCapa[];

extern char g_szFmtLabo[];

extern char g_szFmtEmba[];

extern char g_szFmtYear[];

extern "C" {

extern short g_anMapImprovementSpriteClassByOrderType[kCivilianUnitKindCount];

extern "C" char s_szDoubleNewline[];

// Assert source-path string for the USuperMap TU (TMapUberPicture family).
extern "C" char g_szDoubleQuote[];
extern "C" const int kLoungeStatusGlyphIds[5];
extern "C" char s_SourcePathUSuperMap[];

extern "C" short g_defaultMarkerBoxWidth;

extern unsigned char g_abResourceTypeUsesHighNibbleFlag[24];

extern char g_abResourceTypeCapabilityCategory[24];

// TMapMgr.cpp — hex-area neighbor lookup tables.
extern short g_hexColumnStepByDirection[6];

extern short g_hexRowStepByDirection[6];

extern unsigned char g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainCount];

extern short g_anStrategicTerrainNeighborLinkPriority[kStrategicTerrainCount];

extern int g_nNextRegionMarkerId;

extern short g_awTileSpriteVariantOffsetTable38[16][2];

extern short g_awTileSpriteVariantOffsetTable39[8];

extern short g_awTileSpriteVariantOffsetTable3a[16][5];

extern short g_awTileSpriteVariantOffsetTable3b[16][2];

extern const float g_HexHighlightScreenScale;

extern float g_TileHeatmapNeighborDiffusionFactor;
extern unsigned char g_abUniversityRequirementLevelById[24][4];
extern unsigned char g_abResourceTypeMiniCivMentionFlag[24];
extern short g_anResourceTypeRequiredOrderType[24];
extern unsigned char g_abResourceTypeAlwaysQualifies[24];
extern unsigned char g_abGateFlagQualifies[24];

// Hex neighbor column/row deltas, indexed by direction 0..5 and row parity.
extern const int g_hexColOffsetEvenRow[6];
extern const int g_hexRowOffset[6];
extern const int g_hexColOffsetOddRow[6];

extern unsigned int g_mapGenLcgState;
extern int g_regionSeedGridRows;
extern int g_regionSeedGridCols;

// Zone status-code PRNG and ocean-dialog seed viewport offsets.
extern unsigned int g_zoneStatusCodePrngSeed;
extern int g_nOceanDialogSeedViewportOffsetX;
extern int g_nOceanDialogSeedViewportOffsetY;

} // extern "C"
