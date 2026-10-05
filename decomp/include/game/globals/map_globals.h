#pragma once
#include "game/globals/global_types.h"
#include "game/civilian_domain_types.h"

extern POINT g_ptMapModeModalMessage; // @ 0x6a45c0

extern SeapointStretch g_seapointQuadTable_006a3478;

extern SeaSegmentStretch g_regionBorderLinkTable_006a3900;

extern const unsigned short g_hexDirectionBitMasks_00696e40[6];

extern const unsigned short g_hexDirectionBitMasksAlt_00696ea8[7];
extern const short g_railDirectionAddMasks_00696eb8[6];
extern const short g_railDirectionSubtractMasks_00696ec8[6];

extern int g_bOverlayScanlineFillAssertSuppressed;

extern int g_bOverlayRouteRebuildAssertSuppressed;
extern bool g_applyMiniMapVerticalClipOffset_006993e8;

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

extern short g_anMapImprovementSpriteClassByOrderType[kCivilianUnitKindCount];

extern "C" const char s_szDoubleNewline_00699438[];

// Assert source-path string for the USuperMap TU (TMapUberPicture family).
extern "C" const char g_szDoubleQuote[];
extern "C" const int kLoungeStatusGlyphIds[5];
extern "C" const char s_SourcePathUSuperMap_0069943C[];

extern "C" short g_defaultMarkerBoxWidth_006a460c;

extern unsigned char g_abResourceTypeUsesHighNibbleFlag[24];

extern char g_abResourceTypeCapabilityCategory[24];

// TMapMgr.cpp — hex-area neighbor lookup tables.
extern short g_Build_Hex_Area_LookupTable_00696E70[6];

extern short g_Build_Hex_Area_LookupTable_00696E80[6];

extern unsigned char g_abStrategicTerrainSeedGateProfileA[kStrategicTerrainCount];

extern short g_anStrategicTerrainNeighborLinkPriority[kStrategicTerrainCount];

extern int g_nNextRegionMarkerId;

extern short g_awTileSpriteVariantOffsetTable38[16][2];

extern short g_awTileSpriteVariantOffsetTable39[8];

extern short g_awTileSpriteVariantOffsetTable3a[16][5];

extern short g_awTileSpriteVariantOffsetTable3b[16][2];

extern const float g_HexHighlightScreenScale_00658640;

extern float g_TileHeatmapNeighborDiffusionFactor;
extern unsigned char g_abUniversityRequirementLevelById[24][4];
extern unsigned char g_abResourceTypeMiniCivMentionFlag[24];
extern short g_anResourceTypeRequiredOrderType[24];
extern unsigned char g_abResourceTypeAlwaysQualifies[24];
extern unsigned char g_abGateFlagQualifies[24];

// Hex neighbor column/row deltas, indexed by direction 0..5 and row parity.
extern const int g_hexColOffsetEvenRow_00697450[6];
extern const int g_hexRowOffset_00697468[6];
extern const int g_hexColOffsetOddRow_00697480[6];

extern unsigned int g_mapGenLcgState_006a38e8;
extern int g_regionSeedGridRows_006a38ec;
extern int g_regionSeedGridCols_006a38f0;

// Zone status-code PRNG and ocean-dialog seed viewport offsets.
extern unsigned int g_zoneStatusCodePrngSeed_006a5aec;
extern int g_nOceanDialogSeedViewportOffsetX;
extern int g_nOceanDialogSeedViewportOffsetY;

} // extern "C"
