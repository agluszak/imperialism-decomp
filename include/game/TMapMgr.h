#pragma once

#include "game/CString.h"
#include "game/TObject.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"

// Forward declarations for types referenced by generated signatures.
class TCivUnit;
class TStream;
class TTown;
class TMilitaryUnit;

struct GlobalMapTileRecord {
  char pad_00_to_1f[0x20];
  TCivUnit* firstCivilianOrder; // 0x20
};

struct TTerrainStateRecordView {
  // Region/terrain class (0-7), the switch key read by the map-gen resource-assignment
  // dispatcher (0x511610) and by several rendering-variant lookups (e.g. 0x516150); also
  // widely compared against fixed small values (2/3/5) elsewhere in this file and in
  // TZone.cpp/TCivMgr.cpp. Confirmed via raw-listing cross-checks across those callers --
  // not padding.
  // Signed: the rendering-variant lookup family (0x516150/0x5161a0/0x5161e0/0x516220)
  // reads this with MOVSX when computing a table index, not MOVZX.
  signed char terrainType00;
  // Per-tile sprite/adjacency variant index, read by the rendering-variant lookup family
  // (0x516150/0x5161a0/0x5161e0/0x516220) and written by
  // UpdateMapTileAdjacencyMasksAndVariantForTile's streak-length bookkeeping. Same
  // evidence basis as terrainType00 above; also MOVSX-read there.
  signed char spriteVariantIndex01;
  unsigned char roadFlag;
  // Previous owner-nation tag: the map context info panel (0x51b1c0) compares it with
  // ownerNationTag04 and renders a "(formerly of <nation>)" suffix when they differ.
  signed char formerOwnerNationTag03;
  signed char ownerNationTag04; // 0x04
  // Read as a signed byte and equality-compared between a town's own tile and its hex
  // neighbors by MarkType5NeighborTilesUnavailableByNationCapability (matches a coastal
  // water tile to "its" town) -- not padding, though the exact semantic beyond that one
  // equality test isn't otherwise identified.
  signed char regionSubtypeTag05; // 0x05
  signed char adjacencyBits06;    // 0x06
  // Per-direction (kHexDirectionBitMask) owner-nation border bitmask, accumulated by
  // TMapMgr::UpdateTileNeighborBorderInfluenceCounters (0x50fe10): bit N set means hex
  // neighbor N (or, for a water tile, the land tile across the water gap in that direction)
  // has a different ownerNationTag04. Bits 0x40/0x80 are set as compound "opposite/adjacent
  // pair differs" flags by the same function's tail checks. Not padding.
  unsigned char ownerBorderMask07; // 0x07
  // Per-direction cityRecordIndex border bitmask, same accumulation site as
  // ownerBorderMask07 but comparing cityRecordIndex instead of ownerNationTag04 (only
  // touched when UpdateTileNeighborBorderInfluenceCounters's mode param != 2). Not padding.
  unsigned char cityBorderMask08; // 0x08
  // Per-direction "this land tile borders open water" bitmask, same accumulation site;
  // only ever written for a non-water tile whose neighbor is water. Not padding.
  unsigned char waterAdjacencyMask09; // 0x09
  unsigned char adjacencyMaskA0a;     // 0x0a -- per-direction bit mask (land coastline/edges)
  unsigned char adjacencyMaskB0b;     // 0x0b -- per-direction bit mask (region/water borders)
  // Packed civilian/military development-class nibbles (offset 0xc): written by
  // SetCivilianDevelopmentClassNibble (0x5136a0), read by
  // GetTileCivilianWorkOrderCostClassNibble (high or low nibble by fUseHighNibble) and by
  // the recruit-search-eligibility family (0x5155c0 reads the high nibble, 0x515890 the
  // low nibble) as a per-tile development/need threshold. Not padding.
  // Signed: GetTileCivilianWorkOrderCostClassNibble's high-nibble read is SAR (arithmetic
  // shift), not SHR.
  signed char developmentClassNibbles0c;
  // Sentinel flag (0 / 0x7f) set by SetCivilianDevelopmentClassNibble alongside the high
  // nibble; gates recruit-search eligibility in 0x5155c0. Not padding.
  unsigned char pendingDevelopmentFlag0d;
  unsigned char recruitSearchVisited0e; // 0x0e
  // 0x0f -- cleared to 0 across all 0x1950 tiles by
  // TMapMgr::ClearPerTileByte0FForAllMapTiles (0x409250); read signed (> 0) by the tile
  // context menu (0x504e90) to gate menu item 0x2a.
  signed char perTileVisitedFlag0f;
  // Index (0..89, -1 = none) of the TMapDialog transient tile-marker slot this tile occupies;
  // reset to 0xff by TMapDialog's marker-release path. Read MOVSX (signed).
  signed char markerSlotIndex10;
  signed char resourceTypeByEdge[2];
  // Signed: same MOVSX-index evidence as terrainType00/spriteVariantIndex01 above.
  signed char gateFlag;
  short cityRecordIndex;
  // Tile action class (structure/site type): equality-compared against 2..6/0xe/0x10/0x11
  // by the tile context menu (0x504e90) to pick menu items 0x2b..0x31; read signed by
  // map_overlay_geometry; reset to -1 by the TMapMgr table init.
  signed char tileActionClass16;
  unsigned char railFlags17; // 0x17
  // Secondary/alternate owner nation tag (offset 0x18): the recruit-search-eligibility
  // family (0x5155c0, 0x515890) accepts a tile as owned by a nation if EITHER
  // ownerNationTag04 OR this byte matches -- a genuine second owner slot, not padding.
  signed char secondaryOwnerNationTag18;
  unsigned char pad19;
  // Per-tile ordinal within its tile-action-class bucket (GetMapContextActionCode 0x559a70
  // uses it to pick the Nth queued TTaskForce entry whose required_count matches the tile's
  // class). Not padding.
  short tileActionOrdinal1a;
  unsigned char activeFlags1c; // 0x1c
  unsigned char pad1d[0x20 - 0x1d];
  TCivUnit* firstCivilianOrder20; // 0x20
};

// Field evidence beyond the original recovery: TMultiplayerMgr::DispatchCityRedrawInvalidateEvent
// (0x54abf0) snapshots the whole record field-by-field and skips exactly bytes 0x09, 0x3d and
// 0x96..0x97 — so 0x3e/0x40/0x94 are real short fields (formerly folded into pads) and 0xa4 is
// the CString city display name (also read by AssignCityRecordDisplayName).
struct TGlobalMapCityScoreRecord {
  signed char ownerNationCode00;
  // Previous/founding owner nation code: the tile context menu (0x504e90) renders a
  // "formerly of <nation>" line when it differs from ownerNationCode00 (same idiom as
  // TTerrainStateRecordView::formerOwnerNationTag03); read signed everywhere.
  signed char formerOwnerNationCode01;
  // Signed: 0x517540's switch on this reads it via MOVSX, not MOVZX.
  signed char developmentStage;
  unsigned char fortLevel03; // fort level (indexes g_awEngineerFortBuildCostByLevel)
  // +0x04 — tile index this city record is anchored to (-1 = none); rebound by
  // the 0x00516100-family setters and matched against TCountry::homeRegionIndex.
  short cityTileIndex04;
  short lastTurnTick;
  signed char adjacentRegionCount08;
  unsigned char pad09;
  short adjacentRegionIds0A[0x18];
  signed char linkedRegionCount;
  unsigned char byte3B;
  unsigned char byte3C;
  unsigned char pad3D;
  // Secondary/primary same-cityRecordIndex neighbor tile index, chosen by
  // TMapMgr::UpdateTilePrimaryAndSecondaryNeighborLinksByPriority (0x50fca0) via a
  // per-terrainType00 priority table (g_anTerrainTypeNeighborLinkPriority), with same-city
  // neighbors preferred; also snapshotted by the city-redraw packet.
  short secondaryNeighborTileIndex3e; // 0x3e
  short primaryNeighborTileIndex40;   // 0x40
  short linkedRegionIds[0x20];
  // 0x82..0x95 — per-resource-type development counters, indexed by resourceType - 7
  // (resource types 7..0x10). One array everywhere: the development advance
  // (TGreatPower 0x4dbf00) increments individual entries against building caps, the
  // city-redraw packet (TMultiplayerMgr) snapshots/patches all ten words, and the map
  // context info panel (0x51b1c0) renders each nonzero entry as "<count> <resource
  // name>" via GetString(0x2711, resourceType). Formerly split into
  // stage1CounterA..stage2CounterC / pad88 / field94 names.
  short resourceDevelopmentCounts82[10];
  unsigned char pad96[2];
  TMilitaryUnit* stationedUnitChain98; // 0x98
  int cityScoreValue;
  unsigned char padA0;
  // Per-nation-slot bitmask (bit N = nation slot N), tested by
  // TArmyMgr::ComputeCivilianMapCursorStateIndex to gate an enemy-city order when the
  // pending nation has previously been adjacent/hostile here. Exact set-site not yet
  // identified.
  unsigned char exploredByNationMaskA1;
  unsigned char padA2;
  // Region-class code (0..23), read via MOVSX in
  // TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask to index a 24-entry
  // per-class "seen" flag array.
  signed char regionClassA3;
  CString cityNameA4; // 0xa4 — city display name
};

// Resolve a raw TGlobalMapCityScoreRecord* back into its cityScoreTable index; the
// second arg is provably dead in the original (kept for the call-shape). 0x0050e2c0,
// defined in TNavyMgr.cpp.
int GetCityIndexFromCityStatePointer(TGlobalMapCityScoreRecord* cityState, int unusedArg);

// 0x5127e0: tileIndex -> (hex raster column*2 (+1 on odd rows), row = tileIndex/0x6c).
// Genuine __cdecl free function (pure arithmetic).
void SplitTileIndexToHexRasterColumnX2AndRow(short tileIndex, short* outColX2,
                                             unsigned short* outRow);
// 0x5125a0: tileIndex -> (row = tileIndex/0x6c, col = tileIndex%0x6c). Genuine __cdecl
// free function (pure arithmetic); Ghidra's TMapDialog:: label is spurious (no `this`).
void SplitTileIndexToRowAndColumn(short tileIndex, short* outRow, short* outCol);
// 0x5123e0: recordBase + recordIndex * 0x6c (strided record address). __cdecl free function.
int ComputeStridedRecordAddress6C(int recordBase, int recordIndex);

struct HexSpiralSearchState {
  int row;
  int col;
  int ring;
  int direction;
  int stepInRing;
};

// 0x00512dd0. Hex direction (0-6) from sourceTile to destTile on the 0x6c(108)-wide map. Free
// __cdecl function (no `this`), defined in TMapMgr.cpp.
extern "C" short __cdecl GetHexDirectionBetweenTiles(short sourceTile, short destTile);

// 0x00512930. Heap-allocates (`operator new`, caller frees via `operator delete`) and fills a
// `radius*6`-entry tile-index ring around centerTileIndex: each of the 6 hex directions gets
// one "corner" tile at exactly `radius` steps out, followed by (radius-1) more tiles walking
// the ring's edge toward the next corner. Distinct from the stack-buffer, direct-neighbors-only
// ComputeHexNeighborTileIndices. Free __cdecl function (no `this`), defined in TMapMgr.cpp.
extern "C" short* __cdecl BuildHexAreaTileIndexList(short centerTileIndex, short radius);

// VTABLE: IMPERIALISM 0x006587e0
class TMapMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TMapMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TMapMgr)
  virtual ~TMapMgr() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x50e7a0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x50e620
  virtual void Free() override;                    // slot 0x07 0x50e510
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // Lazily allocates terrainStateTable (0x1950 tiles, raw 0x24-byte records) and
  // cityScoreTable (0x180 records, real TGlobalMapCityScoreRecord[] so CString members
  // construct), then resets every record to its sentinel defaults (-1 for
  // unassigned owner/region/index fields, 0 for counters/masks, 999 for lastTurnTick).
  virtual void AllocateAndResetTerrainAndCityScoreTables(); // slot 0x0a 0x50e8b0
  virtual undefined BuildOrLoadGlobalMapStateForSession(CString param_1,
                                                        char* param_2);     // slot 0x0b 0x50ec90
  virtual undefined LoadPoliticalMapRegionSubtypeTableFromResourceStream(); // slot 0x0c 0x50f200
  virtual unsigned char*
  UpdateMapTileAdjacencyMasksAndVariantForTile(uint param_1); // slot 0x0d 0x510210
  // If tileIndex's gateFlag != 1 (not yet initialized): resets terrainType00 to 0 and
  // resourceTypeByEdge to {0x11, 0xff}, refreshes gateFlag via
  // ResolveRegionTileSubtypeCodeForTileIndex, then for each hex neighbor clears the
  // corresponding "opposite direction" bit in that neighbor's adjacencyMaskA0a if set.
  virtual void InitializeTileNeighborConnectionMaskIfNeeded(short tileIndex); // slot 0x0e 0x5107e0
  // Recomputes tileIndex's ownerBorderMask07/cityBorderMask08/waterAdjacencyMask09 from its 6
  // hex neighbors. For each direction: if the neighbor is off-map, always counts as a border
  // (bit set unconditionally); if tileIndex is water, only counts a differently-owned water
  // neighbor as a border when mode==0; if tileIndex is land, a water neighbor sets
  // waterAdjacencyMask09, a differently-owned land neighbor sets ownerBorderMask07, and (when
  // mode != 2) a different-cityRecordIndex neighbor sets cityBorderMask08. For a water tile,
  // a second pass checks each adjacent pair of hex directions (d, (d+1)%6) across the water
  // gap for a land/land owner or city mismatch. Finishes by OR-ing in 0x40/0x80 compound
  // flags on cityBorderMask08 and ownerBorderMask07 based on specific neighbor-pair
  // mismatches.
  virtual void UpdateTileNeighborBorderInfluenceCounters(short tileIndex,
                                                         short mode); // slot 0x0f 0x50fe10
  // Map-gen resource-type assignment for a single tile: for water (terrainType00==5), marks
  // resourceTypeByEdge[0]=0x13 if any hex neighbor is land; for the other 7 terrain classes,
  // rolls the map-gen LCG against fixed percentage thresholds to assign resourceTypeByEdge[0]
  // (terrainType00==3 can additionally fill resourceTypeByEdge[1]), then always resolves and
  // stores the tile's border/subtype code via ResolveRegionTileSubtypeCodeForTileIndex into
  // gateFlag.
  virtual short UpdateStrategicMapTileIconVariantState(short tileIndex); // slot 0x10 0x511610
  // For each of the 7 nations: collects every linkedRegionIds entry across that nation's
  // owned cities into a heap scratch array, tallies resourceTypeByEdge occurrences by type
  // (0-23) across those regions, then for resourceType 3 and (independently) 4 whose tally
  // is 0: picks a region with gateFlag 8 or 9 and an empty resourceTypeByEdge[0] slot if one
  // exists (else an LCG-random region not already gateFlag 8/9, forcing its gateFlag to 8),
  // assigns resourceTypeByEdge = {3-or-4, -1}, and refreshes gateFlag via
  // ResolveRegionTileSubtypeCodeForTileIndex.
  virtual void TMapMaker_EnsureRegionClassHasSubtype3And4AssignmentsWithRng(); // slot 0x11
                                                                               // 0x511a70
  // If field8 is idle: forces hexNeighborWrapHorizontally20 and (re)opens the "mapdata"
  // session stream via BuildOrLoadGlobalMapStateForSession. If field4 is idle: ticks the
  // strategic map view's UI-progress method. Called from
  // DispatchTurnEvent7DDForActiveNation.
  virtual void TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress(); // slot 0x12 0x511e80
  // Ensures the map data stream is ready (slot 0x12), then dispatches turn-event 0x7dd
  // (a UI refresh notification) to g_pUiRuntimeContext for the active nation.
  virtual void DispatchTurnEvent7DDForActiveNation();      // slot 0x13 0x511ed0
  virtual void ResetAllTileSpriteVariantIndexToSentinel(); // slot 0x14 0x5178c0
  void RefreshMapContextRotatingStatusStrings();
  // Builds the set of region classes (TGlobalMapCityScoreRecord::regionClassA3) present in
  // nationA's owned regions (plus every minor nation tied to nationA per
  // IsEncodedNationSlotMinus200Equal, i.e. encodedNationSlot - 200 == nationA), then
  // returns true if nationB (plus its tied minors) owns any region sharing one of those
  // classes.
  virtual bool
  TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(short nationA,
                                                              short nationB); // slot 0x15 0x511f30
  // False if any of cityRecordIndex's adjacent regions already has ownerNationCode00 ==
  // nationTag; otherwise true only if there's also no second-degree link
  // (CollectSecondDegreeLinksMatchingNodeType returns 0 into a scratch buffer) AND no
  // TZone map-action-context already tracks this region
  // (FindMapActionContextContainingNodeByIndex, a free function on TZone's
  // secondaryNeighbors list).
  virtual bool
  IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(int cityRecordIndex,
                                                       short nationTag); // slot 0x16 0x5121d0
  virtual int IsShiftKeyDown();                                          // slot 0x17 0x5122b0
  virtual int IsAltKeyDown();                                            // slot 0x18 0x5122d0
  virtual void ForwardComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(
      undefined4 param_1); // slot 0x19 0x511f10
  // OR's the hex-direction bit (g_hexDirectionBitMasksAlt_00696ea8) for the direction from
  // sourceTile to destTile into sourceTile's adjacencyBits06, and the opposite direction's
  // bit into destTile's adjacencyBits06. Real signature has 3 stack slots (RET 0xc); the
  // third is never read.
  virtual void SetHexAdjacencyDirectionFlagsForTilePair(short sourceTile, short destTile,
                                                        int unusedParam3); // slot 0x1a 0x513f60
  // Walks terrainStateTable[tileIndex].firstCivilianOrder20 (a TCivUnit list threaded via
  // TUnit::nextOnTile) for a node whose orderType matches.
  virtual bool TileHasCivilianOrderOfType(short tileIndex, short orderType); // slot 0x1b 0x514310
  // Same walk as above, additionally requiring TUnit::field_8 == field8Value.
  virtual bool TileHasCivilianOrderOfTypeAndField8(short tileIndex, short orderType,
                                                   short field8Value); // slot 0x1c 0x514360
  // Seeds recruitSearchVisited0e across all tiles: 1 (already visited/blocked) for every
  // tile NOT owned by ownerNationTag, 0 (unvisited seed candidate) for tiles it owns, and
  // flags field9 = 1 ("search in progress"). Pairs with ResetRecruitSearchVisitedState below.
  virtual void
  SeedRecruitSearchVisitedStateExcludingNation(short ownerNationTag); // slot 0x1d 0x514e40
  // Seeds recruitSearchVisited0e from g_pSelectedCivilianOrderState->selectedEntry instead
  // of an explicit nation tag: if there's no selected order, or its tileIndex06 (a TUnit field,
  // sentinel-inited to 0xffff) is nonzero, every tile is marked 1 (blocked); only when
  // tileIndex06 == 0 does it fall back to seeding per-tile from activeFlags1c bit 4 (an
  // otherwise-unused bit of that byte -- not otherwise cross-referenced in this codebase).
  virtual void SeedRecruitSearchVisitedStateFromSelectedCivilianOrder(); // slot 0x1e 0x514e80
  // Seeds recruitSearchVisited0e like the SeedRecruitSearchVisitedState* family: eligible
  // only if the tile is owned by nationTag and its terrainType00 isn't 2/3/4, gated further
  // by IsValidSecondaryNationHomeTileCandidate (0x513980, not yet ported).
  virtual void WrapperFor_IsValidSecondaryNationHomeTileCandidate_At00514dc0(
      short nationTag); // slot 0x1f 0x514dc0
  // Resets recruitSearchVisited0e to 0 across all tiles and clears field9 back to idle.
  virtual void ResetRecruitSearchVisitedState(); // slot 0x20 0x514ef0
  // Seeds recruitSearchVisited0e excluding terrainStateTable[pCivilianOrderEntry->tileIndex06]'s
  // owner (like SeedRecruitSearchVisitedStateExcludingNation, inlined here rather than
  // called). If orderType is 1 or 7, field_1C == 0, and the reference tile's
  // activeFlags1c/gateFlag or bit-2 gate passes, and (when the reference tile is owned by
  // pCivilianOrderEntry->field_18) its FindTownMarkerForTileByOwnerNation entry is
  // enabled: clears recruitSearchVisited0e for every not-at-war minor nation's
  // TMinor::homeRegionIndex tile (via TDiplomacyMgr::IsNationPairAtWar) and every enabled
  // TTown on the owning TGreatPower's townMarkerList.
  virtual void SeedRecruitSearchVisitedStateAndClearAlliedTerritory(
      class TCivUnit* pCivilianOrderEntry); // slot 0x21 0x514f20
  // Military-recruit counterpart of the SeedRecruitSearchVisitedState* family above: scans
  // `candidates` (fixed 6 slots) for the last non-null entry, seeds recruitSearchVisited0e =
  // 1 across all tiles and clears it for the found unit's own tile
  // (TUnit::tileIndex06), then clears it for the 6 hex neighbors of either the unit's
  // orderTargetTiles28[orderTargetSlot-1] (when orderTargetSlot != 0) or its own tile,
  // provided the neighbor is owned by the same nation (TUnit::field_18) or is at war with it
  // (TDiplomacyMgr::IsNationPairAtWar). Bails immediately if no candidate is non-null.
  virtual void SeedRecruitSearchVisitedStateFromMilitaryUnitCandidates(
      class TMilitaryUnit* const candidates[6],
      short orderTargetSlot); // slot 0x22 0x5150e0
  // Seeds recruitSearchVisited0e like the SeedRecruitSearchVisitedState* family: eligible
  // only for water tiles (always) or tiles owned by pCivilianOrderEntry->field_18 (nationTag)
  // or diplomatically compatible (TDiplomacyMgr::LookupOrderCompatibilityMatrixValue == 2),
  // further gated on gateFlag being in {8,9} (or {10,11,12} when
  // g_pCityOrderCapabilityState->orderCapRows277[nationTag].techStatusByTechId[0x13] == 2), and
  // finally on this nation's bit not already being set in pendingDevelopmentFlag0d.
  virtual void WrapperFor_LookupOrderCompatibilityMatrixValue_At00515330(
      class TCivUnit* pCivilianOrderEntry); // slot 0x23 0x515330
  // Seeds recruitSearchVisited0e (defaults to 1/ineligible, unlike the sibling slot above):
  // requires the tile be diplomatically compatible
  // (TDiplomacyMgr::LookupOrderCompatibilityMatrixValue == 2, ownerNationTag04 >= 7),
  // secondaryOwnerNationTag18 == -1, g_abGateFlagQualifies[gateFlag] != 0, and at least one
  // of its two edge resourceTypes qualifying (0/1/2 always; 3/4/0x15/0x16, or 6 when
  // techStatusByTechId[0x13] == 2, only when this nation's bit is already set in
  // pendingDevelopmentFlag0d).
  virtual void WrapperFor_LookupOrderCompatibilityMatrixValue_At00515460(
      class TCivUnit* pCivilianOrderEntry); // slot 0x24 0x515460
  // Seeds recruitSearchVisited0e like the SeedRecruitSearchVisitedState* family, but each
  // tile is eligible only if it's owned by pCivilianOrderEntry->field_18 (via
  // ownerNationTag04 or secondaryOwnerNationTag18) and pendingDevelopmentFlag0d != 0, and
  // then gated on whether its high development nibble is below the max capability value
  // (over its qualifying resourceTypeByEdge entries) from
  // g_pCityOrderCapabilityState->capabilityValueByNationAndResource. Which resourceTypes
  // qualify depends on pCivilianOrderEntry->orderType (== 0 selects {3,4,21,22}, else {6}).
  virtual void SeedRecruitSearchVisitedStateByCapabilityThreshold(
      class TCivUnit* pCivilianOrderEntry); // slot 0x25 0x5155c0
  // Seeds recruitSearchVisited0e = 1 across all tiles, then for each of the order's nation's
  // enabled TTown markers, clears it (0) on any hex-adjacent water tile that shares the
  // town's regionSubtypeTag05 and whose developmentClassNibbles0c is below
  // TTechMgr::capabilityValueByNationAndResource[nationTag][19].
  virtual void MarkType5NeighborTilesUnavailableByNationCapability(
      class TCivUnit* pCivilianOrderEntry); // slot 0x26 0x515720
  // Sibling of SeedRecruitSearchVisitedStateByCapabilityThreshold: defaults every tile to
  // blocked, then clears it if owned by pCivilianOrderEntry->field_18 (via
  // ownerNationTag04 or secondaryOwnerNationTag18) and g_abGateFlagQualifies[gateFlag] is
  // set, and the max capability value (over qualifying resourceTypeByEdge entries -- an
  // entry qualifies if g_anResourceTypeRequiredOrderType[resourceType] matches
  // pCivilianOrderEntry->orderType, and either g_abResourceTypeAlwaysQualifies[resourceType]
  // or ownerNationTag04 matches) exceeds the low development nibble.
  virtual void SeedRecruitSearchVisitedStateByCapabilityThresholdAlt(
      class TCivUnit* pCivilianOrderEntry); // slot 0x27 0x515890
  // Seeds recruitSearchVisited0e = 1 for all tiles, then (if the order's terrain-type gate
  // passes) walks the 6 direct hex neighbors of pCivilianOrderEntry->tileIndex06 via
  // BuildHexAreaTileIndexList(tile, 1) and clears recruitSearchVisited0e for any neighbor
  // whose terrain type also gates and whose owner nation matches, provided
  // this tile's adjacencyBits06 doesn't already have that direction's bit set. Also flips 3
  // notification flag globals based on nation-indexed OrderCapRow padding bytes (see
  // TTechMgr::OrderCapRow's tech-status gate comments (ids 0x17/0x06/0x0c)).
  virtual void MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA(
      class TCivUnit* pCivilianOrderEntry); // slot 0x28 0x5159b0
  // Same shape as ProfileA (slot 0x28), but the terrainType00 gate is a per-call local
  // 8-entry table built from the same 3 OrderCapRow checks (rather than ProfileA's shared
  // global table), and it additionally clears the origin tile's own recruitSearchVisited0e
  // when its regionSubtypeTag05 is -1 or its city's fortLevel03 is below 3.
  virtual void MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileB(
      class TCivUnit* pCivilianOrderEntry); // slot 0x29 0x515b10
  // Picks up to 2 of cityRecordIndex's 6 hex neighbors as "linked" tiles, ranked by
  // g_anTerrainTypeNeighborLinkPriority[terrainType00] (same-cityRecordIndex neighbors get a
  // +0x14 bonus in the second pass): the top-ranked same-city neighbor becomes
  // primaryNeighborTileIndex40, then the next-best remaining neighbor (any city) becomes
  // secondaryNeighborTileIndex3e. Faithfully reproduces the original's own out-of-bounds
  // stack read (local_c[-1]) when a pass finds no eligible neighbor at all.
  virtual void
  UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(short cityRecordIndex); // slot 0x2a 0x50fca0
  // Looks up whether tileIndex's region has an eligible stationed unit
  // (TArmyMgr::HasEligibleStationedUnitInRegion) but discards the result -- the original's
  // own call site never reads the return value either, so this is vestigial/dead code.
  virtual void ApplyUnitMovementClassForTileIfValid(int tileIndex); // slot 0x2b 0x515d60
  // Moves cityRecordIndex's "anchor" tile (cityScoreTable[cityRecordIndex].cityTileIndex04,
  // reused here as a tile index) to newTileIndex: clears the old anchor tile's activeFlags1c
  // (0x20 bit) and refreshes its gateFlag/resourceTypeByEdge[0], sets the new tile's
  // activeFlags1c to 0x22 and its gateFlag, points cityTileIndex04 at it, then clears the
  // 0x20 bit from all of the city's linkedRegionIds tiles (unconditionally, even if
  // newTileIndex is itself one of them -- matches the original's literal statement order).
  // Finishes by recomputing the city's primary/secondary neighbor links.
  virtual void
  SetRegionTileSubtypeAndRefreshNeighborFlags(short cityRecordIndex,
                                              short newTileIndex); // slot 0x2c 0x515f80
  // Real body is just `ret 0xc` (pops 3 stack dwords, no other instructions) -- no evidence
  // for the real parameter types since none are read; typed as unused ints to match the
  // stack-cleanup byte count.
  virtual void NoOpVirtualSlot2D(int param_1, int param_2, int param_3); // slot 0x2d 0x515de0
  // Reassigns cityRecordIndex's ownerNationCode00 to newNationTag: first tells
  // SetTileOwnerAndInvalidateNeighborState to update every one of the city's linkedRegionIds,
  // then updates the city's own owned-region-list membership (real TCountry virtuals on
  // g_apTerrainTypeDescriptorTable, resolved from the ILT thunks at 0x4081a2/0x407f72's
  // siblings), sets g_pMapContextActionManager's per-nation slot, notifies the new owner
  // (TGreatPower::NotifyActionSlot94) unless it's the local player's own turn, and creates a
  // turn-12 event when running in multiplayer-host mode.
  virtual void
  DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(short cityRecordIndex,
                                                         int newNationTag); // slot 0x2e 0x513290
  // Searches cityScoreTable[cityRecordIndex].adjacentRegionIds0A[0..11] for regionId;
  // on a hit returns the parallel entry at [i+12] (see TMultiplayerMgr's
  // CityRedrawInvalidateTurnEventPacket, which already splits this same 24-entry array
  // into adjacentRegionIds0A[12]/adjacentRegionIds22[12] for wire serialization). Returns
  // -1 if not found. Kept as one raw array (not two named fields) because
  // RedistributeUnitOrderQueueToRandomAdjacentRegion (0x4a35e0) scans all 24 entries as one
  // flat, -1-terminated list -- a genuinely dual-purpose layout.
  virtual short FindLinkedRegionIdForAdjacentRegion(int cityRecordIndex,
                                                    int regionId); // slot 0x2f 0x516090
  // If nationSlotParam < 7, marks that nation's capital-tile city (found via
  // g_apTerrainTypeDescriptorTable[nationSlotParam]->homeRegionIndex used as a
  // terrainStateTable index -- same dual-use pattern flagged on
  // TGlobalMapCityScoreRecord::cityTileIndex04) as developmentStage 2. param_2 is unused
  // by this body but the original callee epilogue pops 8 bytes (2 stack args), matching
  // slot 0x2f's signature.
  virtual void SetCapitalCityDevelopmentStageIfValidNationSlot(int nationSlotParam,
                                                               int param_2); // slot 0x30 0x516100
  // Looks up terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex], then indexes
  // g_abUniversityRequirementLevelById[resourceType][developmentClassNibbles0c's high
  // nibble if g_abResourceTypeUsesHighNibbleFlag[resourceType] is set, else the raw
  // (unmasked) byte].
  virtual byte FindResourceCapabilityRequirementLevel(short tileIndex,
                                                      short edgeIndex); // slot 0x31 0x513610
  virtual byte GetTileCivilianWorkOrderCostClassNibble(short nTileIndex,
                                                       char fUseHighNibble); // slot 0x32 0x513660
  // Packs value into developmentClassNibbles0c's low or high nibble (selectHighNibble
  // picks which); when writing the high nibble with a positive value and param4 != 0,
  // also sets pendingDevelopmentFlag0d = 0x7f.
  virtual void SetCivilianDevelopmentClassNibble(short tileIndex, char selectHighNibble, byte value,
                                                 char param4); // slot 0x33 0x5136a0
  // For each of tileIndex's 2 resourceTypeByEdge entries (skipping the -1 sentinel) whose
  // g_abResourceTypeCapabilityCategory matches categoryCode, reads
  // g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationSlot][resourceType]
  // and returns the max across both edges (0 if neither qualifies).
  virtual short FindMaxResourceCapabilityValueForTile(short tileIndex, char categoryCode,
                                                      int nationSlot); // slot 0x34 0x513720
  // Finds the edge (0 or 1) whose resourceTypeByEdge matches resourceType, then dispatches
  // to FindResourceCapabilityRequirementLevel (slot 0x31) for that edge; 0 if no edge
  // matches.
  virtual byte
  FindResourceCapabilityRequirementLevelByType(short tileIndex,
                                               char resourceType); // slot 0x35 0x5135a0
  // Looks up the TTown marker for tileIndex on its owning nation's townMarkerList
  // (g_apNationStates[terrainStateTable[tileIndex].ownerNationTag04]->townMarkerList),
  // matching TTown::regionId14 == tileIndex.
  virtual class TTown* FindTownMarkerForTileByOwnerNation(short tileIndex); // slot 0x36 0x513170
  // Updates terrainStateTable[regionId]'s owner nation, refreshes its own and its 6
  // neighbors' border-influence counters via UpdateTileNeighborBorderInfluenceCounters, and
  // -- if the tile carries a town (activeFlags1c & 0x14) and the old owner is a great power
  // (< 7) -- moves that TTown marker from the old owner's townMarkerList to the new owner's,
  // updating TTown::ownerNation1c.
  virtual void SetTileOwnerAndInvalidateNeighborState(short regionId,
                                                      short newNationTag); // slot 0x37 0x5133f0
  // Rendering-variant lookup family: pick a bitmap-strip byte offset for a tile's
  // sprite, indexed by gateFlag and/or spriteVariantIndex01. Tables verified via
  // raw-listing + ghidra-read-data at 0x38: 0x696f10, 0x39: 0x696f50, 0x3a: 0x696f60,
  // 0x3b: 0x697000.
  virtual short
  LookupTileSpriteVariantOffsetByTerrainAndGate(short nTileIndex); // slot 0x38 0x516150
  virtual short
  LookupTileSpriteVariantOffsetByAdjacencyMaskB(short nTileIndex); // slot 0x39 0x5161a0
  virtual short
  LookupTileSpriteVariantOffsetByGateAndVariant(short nTileIndex); // slot 0x3a 0x5161e0
  virtual short
  LookupTileSpriteVariantOffsetByGateAndVariantAlt(short nTileIndex); // slot 0x3b 0x516220
  // Body is a 64x7 lookup table (`table[bitmaskIndex][direction]`), materialized as
  // literal per-element stack stores in the original (not static rodata) -- reproduced
  // as a local (non-static) initializer to match. Column 0 always equals the row index
  // (bitmaskIndex, 0-63 = a 6-bit adjacency mask, matching the file's 6-hex-direction
  // domain); columns 1-6 are small 0-3 variant codes, same value range as
  // gateFlag/spriteVariantIndex01 in the sibling rendering-variant family
  // (0x516150 etc.) directly above this slot. No callers besides the vtable itself, so
  // the exact semantic role of each column beyond "some adjacency-keyed variant code"
  // isn't identified.
  virtual short LookupAdjacencyBitmaskVariantByDirection(char bitmaskIndex,
                                                         char direction); // slot 0x3c 0x516260
  // Real signature has 3 stack args (RET 0xc), not 1 -- bitmaskIndex/direction forward
  // unchanged into LookupAdjacencyBitmaskVariantByDirection (slot 0x3c); returns 0 if that
  // lookup is 0, else (lookup+0x15)<<6 or (lookup+0x20)<<6 depending on useAltOffset.
  virtual int MapImprovementOffsetFromAdjacencyVariant(char bitmaskIndex, char direction,
                                                       char useAltOffset); // slot 0x3d 0x517410
  // Real signature has 3 stack args (RET 0xc), not 0 -- see body for the exact combination
  // of 3 calls into LookupAdjacencyBitmaskVariantByDirection (slot 0x3c).
  virtual short MapImprovementOffsetFromAdjacencyVariantTriple(char bitmaskIndex, char direction,
                                                               short param3); // slot 0x3e 0x517480
  // Real body is just `mov ax, 0xc80; ret` -- a bare constant, no callers besides the
  // vtable itself so its purpose isn't identified.
  virtual short GetFixedConstant0xc80(); // slot 0x3f 0x517520
  // Picks a fixed bitmap offset from activeFlags1c bits 0/1, gated by categoryCode < 7:
  // when < 7 and bit1 is set, refines further by cityScoreTable[cityRecordIndex]'s
  // developmentStage (0/1/2 -> 0x700/0x740/0x780); else falls back to the >=7 family
  // (0x9c0/0x980).
  virtual int
  GetMapImprovementOffsetByActiveFlagsAndCityStage(short tileIndex,
                                                   short categoryCode); // slot 0x40 0x517540
  // Real signature has 2 stack slots (RET 8); the second is never read. Dispatches to
  // FindTownMarkerForTileByOwnerNation (slot 0x36) and combines its transportLinkedFlag4c
  // with activeFlags1c bits 2/4 to pick one of 6 fixed bitmap offsets.
  virtual short GetMapImprovementOffsetByTownTransportLink(short tileIndex,
                                                           int unusedParam2); // slot 0x41 0x517600
  // (index + 0x23) << 6 -- a bitmap-strip row offset, 64 bytes/row; sits in the same
  // "map improvement" offset family as the following GetMapImprovementTierBucketOffset/
  // GetMapImprovementSpriteBaseOffset slots (also 64-byte-row arithmetic). No callers other
  // than the vtable itself, so the specific bitmap it indexes isn't identified.
  virtual int GetMapImprovementBitmapRowOffsetForIndex(int index); // slot 0x42 0x5176a0
  // index * 36 -- matches the terrainStateTable record stride (sizeof(TTerrainStateRecordView)
  // == 0x24) used inline throughout this file; no `this` use and no other callers, so this
  // is modeled as the raw arithmetic it computes rather than presumed to index a specific array.
  virtual int ComputeTerrainRecordByteOffsetForIndex(int index); // slot 0x43 0x5176c0
  // Bitmap-strip row offset (64-byte rows) for a map-improvement tier: tier*9 below tier 7,
  // else a fixed overflow row.
  virtual short GetMapImprovementTierBucketOffset(short tier); // slot 0x44 0x5176e0
  // Bitmap-strip base offset for a map-improvement class: 0x6c0 flat if param_2, else
  // g_anMapImprovementSpriteClassByOrderType[param_1]*64, +0x480 unless param_3.
  virtual short GetMapImprovementSpriteBaseOffset(short param_1, char param_2,
                                                  char param_3); // slot 0x45 0x517780
  // Looks up the improvement sprite base offset for civUnit's own order type/idle state via
  // the slot above, but discards the result -- same vestigial pattern as
  // ApplyUnitMovementClassForTileIfValid.
  virtual void ApplyMapImprovementSelectionState(class TCivUnit* civUnit); // slot 0x46 0x517710
  // Real signature has 2 stack slots (RET 8); the second is never read -- same pattern as
  // GetMapImprovementOffsetByTownTransportLink above.
  virtual int GetMapImprovementTileOffsetFromClass(char classCode,
                                                   int unusedParam2); // slot 0x47 0x5177d0
  // Bitmap tile-sprite offset (16-byte cells) for a tile's improvement class, gated on
  // activeFlags1c bits 0/5/2 (checked in that priority order) and scaled by
  // ownerNationTag04 below tier 7, else a fixed overflow cell.
  virtual short GetMapImprovementTileSpriteOffset(short tileIndex); // slot 0x48 0x5177f0
  // slot 0x49 0x5145b0 -- RET 8 confirms two stack args (the earlier pMapContext/param_4 were
  // Ghidra artifacts); every call site passes (tile index, owner nation tag).
  virtual int QueueDepotConstructionOrder(short nTileIndex, short nNationId);
  virtual void QueuePortConstructionOrder(short nTileIndex, short nNationId); // slot 0x4a 0x5147d0
  virtual void SetProvinceCapitalTileFlagBit08(short nProvinceId);            // slot 0x4b 0x5149d0
  virtual void FloodFillTileRegionMarker(short nTileIndex,
                                         short nOwnerNationId); // slot 0x4c 0x5143d0
  // Moves cityRecordIndex's anchor to nTileIndex (real call into
  // SetRegionTileSubtypeAndRefreshNeighborFlags), sets its activeFlags1c to 0x37 (0x17 then
  // OR 0x20), and calls FloodFillTileRegionMarker(nTileIndex, nOwnerNationId). Then, for each
  // of the 6 hex neighbors plus nTileIndex itself (direction 6 is a self special-case, not a
  // 7th real hex direction), if that tile shares nTileIndex's regionSubtypeTag05 and has a
  // port/depot-eligible resourceTypeByEdge entry (17 or 18) whose gateFlag qualifies
  // (g_abGateFlagQualifies), calls SetCivilianDevelopmentClassNibble(neighborTile, 0, 1, 1) on
  // it. Finishes by calling EnsurePortZoneForTile(nTileIndex) and refreshing nTileIndex's
  // gateFlag via ResolveRegionTileSubtypeCodeForTileIndex.
  virtual void
  SetTileTransportFlagsTo0x37AndRefreshNeighbors(short nTileIndex,
                                                 short nOwnerNationId); // slot 0x4d 0x514a20
  // === END GENERATED DECLS (TMapMgr) ===

  // Recomputes the per-region strategic-score heatmap (cityScoreTable[*].cityScoreValue)
  // used by turn-AI order planning, then updates cityScoreTotal with the mean. 0x00518130.
  void RecomputeTileStrategicScoreHeatmap();

  // Global map session state (g_pGlobalMapState @ 0x006A43D4). RTTI object size 0x28
  // covers the TObject head; tile/city tables are heap-backed pointers below.
  //
  // terrainStateTable/cityScoreTable/tileOwnershipTable/cityScoreTotal previously sat 4
  // bytes too early (declared starting at +0x08). Ground truth from TMapMgr::ReadFrom's
  // decompile (0x50e620, whose own field_0xNN offsets are Ghidra-authoritative -- they
  // are not subject to the header's prior offset comments): field_0xc is dereferenced as
  // a pointer and filled with a 0x38f40-byte buffer (0x1950 tiles * 0x24-byte records,
  // matching TTerrainStateRecordView exactly), field_0x10 is a pointer walked in 0x180
  // steps of 0xa8 bytes (matching TGlobalMapCityScoreRecord exactly), and the following
  // divisor field lands at field_0x18 -- confirmed independently by 3 call sites reading
  // [g_pGlobalMapState+0x10] with the cityScoreTable stride/sub-offsets directly (bd
  // 1uj.8, bd 1uj.23: TDefendProvinceMission::ResetValue0CToZero 0x53ed00 and
  // TGreatPower::ComputeAdvisoryMapNodeScoreFactorByCaseMetric 0x4e8750, both FILD
  // dword ptr [.. + 0x9c] -- an int-to-float CONVERSION of cityScoreValue, not a raw
  // bit-reinterpret). field_0x1c (scenarioTagText1c) and field_0x20
  // (hexNeighborWrapHorizontally20) already matched their declared offsets, so the gap
  // is confined to +0x04..+0x0c: 4 stream-read scalars whose semantics aren't identified
  // yet (kept generic below), aligning the first pointer to +0x0c.
  // Only ever written, and only as a single byte (MOV byte ptr [this+4],0 in ReadFrom's
  // decompile) -- not a genuine short; a real 2-byte field there would leave its high byte
  // unaccounted for.
  unsigned char field4;   // +0x04 -- zeroed unconditionally near the end of ReadFrom
  unsigned char pad5;     // +0x05
  short field6;           // +0x06 -- 2-byte stream read
  unsigned char field8;   // +0x08 -- 1-byte stream read
  unsigned char field9;   // +0x09 -- 1-byte stream read
  unsigned char pad0a[2]; // +0x0a -- alignment gap before the +0x0c pointer
  TTerrainStateRecordView* terrainStateTable; // +0x0c
  TGlobalMapCityScoreRecord* cityScoreTable;  // +0x10
  // Per-tile ownership/region table (0x24-byte records, one per map tile: terrain/region
  // tag at +0x04 valid in [7,22], owner-nation byte at +0x18). Full record layout is
  // unknown, so accessed via byte offsets.
  signed char* tileOwnershipTable; // +0x14
  int cityScoreTotal;              // +0x18
  // Real CString, not a raw char* -- ~TMapMgr's own decompile (0x50e490) shows an explicit
  // CString::~CString() call on this field (LEA ECX,[this+0x1c]; CALL 0x6058e2), the sole
  // action the base destructor performs.
  CString scenarioTagText1c;          // +0x1c
  char hexNeighborWrapHorizontally20; // +0x20
  char pad21;                         // +0x21
  short pendingRiverMouthTile22;      // +0x22 -- tile awaiting a river-mouth variant assign
  unsigned char field24;              // +0x24 -- zeroed by the ctor; no observed reader yet

  static void ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles,
                                            char wrapHorizontally);
  static short GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction);
  static short StepHexTileIndexByDirectionWithWrapRules(short tileIndex, short direction);
  static bool StepHexRowColByDirectionWithWrapRules(int* row, int* col, int direction);
  static void AdvanceSpiralSearchStateAndStepHexCoordinates(struct HexSpiralSearchState* state);
  static short TileIndexFromRowCol(int row, int col);

  short ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(short terrainType, char wrapBias);

  char AreNationsBorderLinked(int nationA, int nationB);
  // 0x517dd0. True if any of cityRecordIndex's adjacent regions is owned by nationCode.
  // When allowFallback is set and nationCode is a great power (<=6), also tries each minor
  // nation slot 7..22: if that minor's TCountry entry exists and
  // IsEncodedNationSlotMinus200Equal(nationCode) holds for it, checks whether the minor's own
  // slot number is among cityRecordIndex's adjacent owners too.
  bool HasDirectOrFallbackLinkedNodeType(int cityRecordIndex, int nationCode, char allowFallback);
  // 0x515e50. Despite the name, checks whether regionIndex is in nodeContext's
  // adjacent-region list -- see the .cpp body comment.
  char TileHasMovementClassId(int nodeContext, int regionIndex);
  // 0x518a20. Returns true on the first linked region with terrainStateTable
  // activeFlags1c bit 2 SET (not "all clear" as the name implies) -- see the .cpp
  // body comment.
  char AreAllLinkedEntriesTerrainFlagBit2Clear(int regionIndex);
  void SetRegionDevelopmentStageByte(short regionId, unsigned char stage);
  int SetTileTransportFlags(short nTileIndex, unsigned short wTileTransportFlags);
  void ApplyRailSectionEndpointDirectionFlags(short sourceTile, short destTile, short ownerNation);
  // 0x514080. Rescind counterpart -- see the .cpp body comment.
  void ApplyEngineerRailCostDeltaForConnectedTiles(short tileA, short tileB, short ownerNation);
  short FindReachableRecruitSpawnTileWithVisitedReset(short startTileIndex, char allowActiveFlag2);
  // 0x515f40. Write a city display-name CString into cityScoreTable[cityRecordIndex]+0xa4.
  void SetGlobalMapCellSharedLabel(int cityRecordIndex, CString* name);
  // 0x518b40. Developer purchase cost of a tile's two edge resources (weights the trade
  // manager's proposal-weight metric). Reattributed from TCivToolbar (heuristic 46).
  int CalculateDeveloperTilePurchaseCost(short nTileIndex);

  // 0x517f80. For each of cityRecordIndex's adjacent regions that itself has at least one
  // adjacent region, appends it to nodeBuffer (capacity assumed by caller) once if
  // cityScoreTable[cityRecordIndex].ownerNationCode00 == nationTag -- despite iterating a
  // "second degree" (neighbor-of-neighbor) loop, the comparison is against the *origin*
  // region's own owner on every inner iteration, not the neighbor's or second-degree
  // neighbor's; reproduced as-is (this is the real disassembly, not a simplification).
  // Returns the number of entries appended.
  int CollectSecondDegreeLinksMatchingNodeType(int cityRecordIndex, int nationTag, int* nodeBuffer);

  // 0x518d90 (thiscall, no explicit args). TODO(port): clears perTileVisitedFlag0f
  // across the whole terrainStateTable, then walks the active nation's
  // militaryUnitList44 (CIterator) and, for each order whose tile is diplomatically
  // linked (via g_pDiplomacyTurnStateManager's vtable slot 8.0x04 war-state check and a
  // pair of unresolved geometry helpers at 0x40907f/0x408b8e), stamps a per-tile
  // direction-overlay code into perTileVisitedFlag0f and notifies
  // mapUberPictureF0->InvalidateTileMarkerChain (slot 0x76). Left as a declared-for-real
  // stub -- the two geometry helpers and the TDiplomacyMgrVtbl slot aren't recovered yet
  // (see bd imperialism-decomp-1uj.61).
  void MarkDirectionalMapOverlayFlagsForNationOrders();

  // 0x5108d0. Map-tile sprite-variant resolver: reads the tile's terrain type
  // (terrainStateTable byte 0) and feature/subtype code (byte 2, the field the layout
  // calls roadFlag), inspects the west (tile-1) and NE-row (tile-0x6b) neighbors, and
  // picks a sprite-variant id -- using the map-generation LCG (g_mapGenLcgState_006a38e8)
  // to break ties. Called by UpdateMapTileAdjacencyMasksAndVariantForTile (0x510210).
  int ResolveMapTileVariantSpriteFromAdjacencyState(int nTileIndex);

  // 0x5112f0/0x511360/0x5113d0/0x511440. Predicate helpers for the variant resolver:
  // each returns 1 iff the neighbor tile's byte-2 feature code is in a specific set of
  // adjacency-continuation codes (west-run set A/B, north-run set C/D).
  char CheckTileVariantCodeMembershipSetA(short tileIndex);
  char CheckTileVariantCodeMembershipSetB(short tileIndex);
  char CheckTileVariantCodeMembershipSetC(short tileIndex);
  char CheckTileVariantCodeMembershipSetD(short tileIndex);

  // 0x513ed0. True if either of the tile's two edge resources is a prospecting-discovery
  // candidate (codes 3/4/0x15/0x16, or 6 when the active nation has a production order).
  byte CheckTileProspectingDiscoveryCandidate(short nTileIndex);

  // 0x514110. Resolves a tile's border/subtype icon code from terrainType00, keyed off
  // resourceTypeByEdge[0]/gateFlag/activeFlags1c depending on terrain class; falls back to
  // returning gateFlag verbatim once it's been assigned (non-(-1)). Called by the region
  // subtype/border-refresh family (0x50f200, 0x5107e0, 0x511a70, 0x514a20, 0x515f80) and by
  // UpdateStrategicMapTileIconVariantState (0x511610).
  short ResolveRegionTileSubtypeCodeForTileIndex(short tileIndex);

  TCivUnit* GetFirstCivilianOrderOnTile(short tileIndex) {
    return terrainStateTable[tileIndex].firstCivilianOrder20;
  }

  // 0x514250. Walks the tile's civilian-order chain (GetFirstCivilianOrderOnTile) for the
  // first entry owned by nationId. Reattributed from TCivToolbar (Ghidra bucket heuristic;
  // `this` at the callsite is the global map state, not a TCivToolbar).
  TCivUnit* GetTileUnitEntryByOwner(short tileIndex, short nationId);

  // 0x513980, 632 bytes, __thiscall, 1 arg (tileIndex), returns bool. Called by
  // WrapperFor_IsValidSecondaryNationHomeTileCandidate_At00514dc0. TODO stub: large body not
  // yet ported.
  bool IsValidSecondaryNationHomeTileCandidate(short tileIndex);

  char CallMetricSlotC4(int regionIndex, int edgeIndex);
  short QueryIconStripXSlot110(int iconCode);
  void NotifyCityRecordSlot12C(int cityRecordIndex);
  void LinkRegionToNationSlot134(int regionId, int nationSlot);
  void AssignCityRecordDisplayName(int cityRecordIndex, CString* dest);
  void DumpAndResetMapScriptState(); // 0x00519140

  // Join-empire (mode 0) reset: walk the +0x0c tile table (0x24-byte records, one per
  // tile) and clear the owner-nation byte (+0x18) wherever it matches nationSlot for
  // tiles tagged in [7,22]. 0x00518470, __thiscall, one int param.
  void ApplyJoinEmpireMode0GlobalDiplomacyReset(int nationSlot);

  // Ground truth 0x00518bd0 (reached through the ILT thunk at 0x004079af): hex-neighbor
  // direction math (adjacentRegionIds0A-style lookup via g_Build_Hex_Area_LookupTable_*)
  // that marks an adjacent tile's rail/road direction byte and, if mapUberPictureF0 is
  // set, forwards to its own slot-0x76 (byte 0x1d8) virtual. Left as a stub pending a
  // dedicated pass -- the body is 343 bytes of hex-grid arithmetic, out of scope for the
  // TArmyMgr callers that merely need a real, correctly-typed call site.
  void MarkAdjacentHexOrderDirectionAndSelectTile(int tileIndex, int contextArg, char flag);

  // Resolves cityScoreTable[tileIndex].ownerNationCode00, following one level of
  // g_apTerrainTypeDescriptorTable[ownerCode]->needLevelByNation[1]'s 100/200-banded
  // redirect encoding when it is >= 200 (annexation/transfer chain). 0x00514290,
  // __thiscall, one int stack arg.
  short ResolveTileOwnerNationCodeNormalized(int tileIndex);

  // Tallies cityScoreTable[cityIndex]'s linked regions by their terrain gateFlag (bucketed
  // via kGateFlagScoreBucket) into 3 running totals, then returns an opaque 0-3
  // composition class from their relative sizes (3 if the city's own owner-nation tile has
  // activeFlags1c bit 0 set, short-circuiting the tally). Consumed by
  // TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup as
  // TArmyBattle::InitializeBattleSetupAndMaybeDispatchTurnEventED8's 3rd argument; the
  // exact real-world meaning of the bucket totals or the 0-3 codes isn't recovered.
  // 0x00519010, __thiscall, one int stack arg.
  int ClassifyCityGateTerrainComposition(int cityIndex);

  // Fills outProfileBySlot[0..6] with the AI profile id chosen for each great-power slot
  // that TSimMgr has marked open (scenarioSetupRows0 == 2), or 3 for a slot that is not
  // open. Slots are ranked by how isolated their region class is (unique / shared with a
  // minor / shared with another great power) and profiles are handed out in a fixed
  // priority order. 0x00519610, __thiscall on g_pGlobalMapState, one short* stack arg
  // (`RET 0x4`); the sole caller is TSimMgr::RebuildNationStateSlotsAndAvailability, which
  // loads ECX from g_pGlobalMapState (0x6a43d4) rather than passing its own `this`.
  void ChooseNationSetupProfilesForOpenSlots(short* outProfileBySlot);

  // Returns cityScoreTable[index].stationedUnitChain98 when index is in [0, 0x180), else
  // nullptr -- the same "validate then fetch the tile's unit chain head" idiom already
  // inlined at several other TArmyMgr callsites, but here it's the original's own
  // standalone function. 0x004a4190, __thiscall, one short stack arg.
  TMilitaryUnit* ValidateGridIndexRange0To17F(short index);

  // Clears terrainStateTable[i].perTileVisitedFlag0f for every one of the 0x1950
  // (108x60) map tiles. 0x00409250, __thiscall, no args.
  void ClearPerTileByte0FForAllMapTiles();

  // Marks field6 ready and, on first call (g_pStrategicMapViewSystem->atlas668 still
  // null), tail-calls TMacViewMgr::RenderOffscreenBitmapGridStripAndRestoreContext to
  // build it. 0x0050e4e0, __thiscall.
  void InitializeGlobalMapState();

  TMapMgr();
};

// Retail body ignores provinceId and returns the constant weight 0x21 (33); the
// mission-scoring family converts it to float for the accumulate dampening factor.
short __stdcall GetProvinceUnitOrderWeight(short provinceId); // 0x5184e0
