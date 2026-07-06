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
  unsigned char pad03;
  signed char ownerNationTag04; // 0x04
  unsigned char pad05;
  signed char adjacencyBits06; // 0x06
  unsigned char pad07[0x0a - 0x07];
  unsigned char adjacencyMaskA0a; // 0x0a -- per-direction bit mask (land coastline/edges)
  unsigned char adjacencyMaskB0b; // 0x0b -- per-direction bit mask (region/water borders)
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
  // TMapMgr::ClearPerTileByte0FForAllMapTiles (0x409250); reader/setter beyond that not
  // yet identified.
  unsigned char perTileVisitedFlag0f;
  unsigned char pad10;
  signed char resourceTypeByEdge[2];
  // Signed: same MOVSX-index evidence as terrainType00/spriteVariantIndex01 above.
  signed char gateFlag;
  short cityRecordIndex;
  unsigned char pad16;
  unsigned char railFlags17; // 0x17
  // Secondary/alternate owner nation tag (offset 0x18): the recruit-search-eligibility
  // family (0x5155c0, 0x515890) accepts a tile as owned by a nation if EITHER
  // ownerNationTag04 OR this byte matches -- a genuine second owner slot, not padding.
  signed char secondaryOwnerNationTag18;
  unsigned char pad19[3];
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
  unsigned char byte01;
  // Signed: 0x517540's switch on this reads it via MOVSX, not MOVZX.
  signed char developmentStage;
  unsigned char fortLevel03; // fort level (indexes g_awEngineerFortBuildCostByLevel)
  short ownerNationSlot;
  short lastTurnTick;
  signed char adjacentRegionCount08;
  unsigned char pad09;
  short adjacentRegionIds0A[0x18];
  signed char linkedRegionCount;
  unsigned char byte3B;
  unsigned char byte3C;
  unsigned char pad3D;
  short field3E; // 0x3e — snapshotted by the city-redraw packet
  short field40; // 0x40 — snapshotted by the city-redraw packet
  short linkedRegionIds[0x21];
  short stage1CounterA;
  short stage1CounterB;
  short pad88;
  short stage1CounterC;
  short stage1CounterD;
  short stage2CounterA;
  short stage2CounterB;
  short stage2CounterC;
  short field94; // 0x94 — snapshotted by the city-redraw packet
  unsigned char pad96[2];
  TMilitaryUnit* stationedUnitChain98; // 0x98
  int cityScoreValue;
  unsigned char padA0;
  // Per-nation-slot bitmask (bit N = nation slot N), tested by
  // TArmyMgr::ComputeCivilianMapCursorStateIndex to gate an enemy-city order when the
  // pending nation has previously been adjacent/hostile here. Exact set-site not yet
  // identified.
  unsigned char exploredByNationMaskA1;
  unsigned char padA2[2];
  CString cityNameA4; // 0xa4 — city display name
};

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

// TODO(manifest): describe TMapMgr and its role. Base edge (TObject) recovered from RTTI
// CRuntimeClass chain: TMapMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x006587e0
class TMapMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TMapMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TMapMgr)
  virtual ~TMapMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x50e7a0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x50e620
  virtual void Free() override;                    // slot 0x07 0x50e510
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined WrapperFor_AllocateWithFallbackHandler_At0050e8b0(); // slot 0x0a 0x50e8b0
  virtual undefined BuildOrLoadGlobalMapStateForSession(CString param_1,
                                                        char* param_2);     // slot 0x0b 0x50ec90
  virtual undefined LoadPoliticalMapRegionSubtypeTableFromResourceStream(); // slot 0x0c 0x50f200
  virtual unsigned char*
  UpdateMapTileAdjacencyMasksAndVariantForTile(uint param_1);                  // slot 0x0d 0x510210
  virtual undefined InitializeTileNeighborConnectionMaskIfNeeded(int param_1); // slot 0x0e 0x5107e0
  virtual undefined UpdateTileNeighborBorderInfluenceCounters(short param_1,
                                                              short param_2); // slot 0x0f 0x50fe10
  // Map-gen resource-type assignment for a single tile: for water (terrainType00==5), marks
  // resourceTypeByEdge[0]=0x13 if any hex neighbor is land; for the other 7 terrain classes,
  // rolls the map-gen LCG against fixed percentage thresholds to assign resourceTypeByEdge[0]
  // (terrainType00==3 can additionally fill resourceTypeByEdge[1]), then always resolves and
  // stores the tile's border/subtype code via ResolveRegionTileSubtypeCodeForTileIndex into
  // gateFlag.
  virtual short UpdateStrategicMapTileIconVariantState(short tileIndex); // slot 0x10 0x511610
  virtual undefined
  TMapMaker_EnsureRegionClassHasSubtype3And4AssignmentsWithRng(); // slot 0x11 0x511a70
  // If field8 is idle: forces hexNeighborWrapHorizontally20 and (re)opens the "mapdata"
  // session stream via BuildOrLoadGlobalMapStateForSession. If field4 is idle: ticks the
  // strategic map view's UI-progress method. Called from
  // DispatchTurnEvent7DDForActiveNation.
  virtual void TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress(); // slot 0x12 0x511e80
  // Ensures the map data stream is ready (slot 0x12), then dispatches turn-event 0x7dd
  // (a UI refresh notification) to g_pUiRuntimeContext for the active nation.
  virtual void DispatchTurnEvent7DDForActiveNation();      // slot 0x13 0x511ed0
  virtual void ResetAllTileSpriteVariantIndexToSentinel(); // slot 0x14 0x5178c0
  virtual undefined
  TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(short param_1,
                                                              short param_2); // slot 0x15 0x511f30
  virtual undefined
  IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(int param_1,
                                                       short param_2); // slot 0x16 0x5121d0
  virtual int IsShiftKeyDown();                                        // slot 0x17 0x5122b0
  virtual int IsAltKeyDown();                                          // slot 0x18 0x5122d0
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
  // of an explicit nation tag: if there's no selected order, or its field_6 (a TUnit field,
  // sentinel-inited to 0xffff) is nonzero, every tile is marked 1 (blocked); only when
  // field_6 == 0 does it fall back to seeding per-tile from activeFlags1c bit 4 (an
  // otherwise-unused bit of that byte -- not otherwise cross-referenced in this codebase).
  virtual void SeedRecruitSearchVisitedStateFromSelectedCivilianOrder(); // slot 0x1e 0x514e80
  // Seeds recruitSearchVisited0e like the SeedRecruitSearchVisitedState* family: eligible
  // only if the tile is owned by nationTag and its terrainType00 isn't 2/3/4, gated further
  // by IsValidSecondaryNationHomeTileCandidate (0x513980, not yet ported).
  virtual void WrapperFor_IsValidSecondaryNationHomeTileCandidate_At00514dc0(
      short nationTag); // slot 0x1f 0x514dc0
  // Resets recruitSearchVisited0e to 0 across all tiles and clears field9 back to idle.
  virtual void ResetRecruitSearchVisitedState(); // slot 0x20 0x514ef0
  // Seeds recruitSearchVisited0e excluding terrainStateTable[pCivilianOrderEntry->field_6]'s
  // owner (like SeedRecruitSearchVisitedStateExcludingNation, inlined here rather than
  // called). If orderType is 1 or 7, field_1C == 0, and the reference tile's
  // activeFlags1c/gateFlag or bit-2 gate passes, and (when the reference tile is owned by
  // pCivilianOrderEntry->field_18) its FindTownMarkerForTileByOwnerNation entry is
  // enabled: clears recruitSearchVisited0e for every not-at-war minor nation's
  // TMinor::ownerNationSlot tile (via TDiplomacyMgr::IsNationPairAtWar) and every enabled
  // TTown on the owning TGreatPower's townMarkerList.
  virtual void SeedRecruitSearchVisitedStateAndClearAlliedTerritory(
      class TCivUnit* pCivilianOrderEntry); // slot 0x21 0x514f20
  // Military-recruit counterpart of the SeedRecruitSearchVisitedState* family above: scans
  // `candidates` (fixed 6 slots) for the last non-null entry, seeds recruitSearchVisited0e =
  // 1 across all tiles and clears it for the found unit's own tile
  // (TUnit::field_6), then clears it for the 6 hex neighbors of either the unit's
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
  // g_pCityOrderCapabilityState->orderCapRows277[nationTag].recruitTierFlag27b == 2), and
  // finally on this nation's bit not already being set in pendingDevelopmentFlag0d.
  virtual void WrapperFor_LookupOrderCompatibilityMatrixValue_At00515330(
      class TCivUnit* pCivilianOrderEntry); // slot 0x23 0x515330
  // Seeds recruitSearchVisited0e (defaults to 1/ineligible, unlike the sibling slot above):
  // requires the tile be diplomatically compatible
  // (TDiplomacyMgr::LookupOrderCompatibilityMatrixValue == 2, ownerNationTag04 >= 7),
  // secondaryOwnerNationTag18 == -1, g_abGateFlagQualifies[gateFlag] != 0, and at least one
  // of its two edge resourceTypes qualifying (0/1/2 always; 3/4/0x15/0x16, or 6 when
  // recruitTierFlag27b == 2, only when this nation's bit is already set in
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
  virtual undefined
  MarkType5NeighborTilesUnavailableByNationCapability(int param_1); // slot 0x26 0x515720
  // Sibling of SeedRecruitSearchVisitedStateByCapabilityThreshold: defaults every tile to
  // blocked, then clears it if owned by pCivilianOrderEntry->field_18 (via
  // ownerNationTag04 or secondaryOwnerNationTag18) and g_abGateFlagQualifies[gateFlag] is
  // set, and the max capability value (over qualifying resourceTypeByEdge entries -- an
  // entry qualifies if g_anResourceTypeRequiredOrderType[resourceType] matches
  // pCivilianOrderEntry->orderType, and either g_abResourceTypeAlwaysQualifies[resourceType]
  // or ownerNationTag04 matches) exceeds the low development nibble.
  virtual void SeedRecruitSearchVisitedStateByCapabilityThresholdAlt(
      class TCivUnit* pCivilianOrderEntry); // slot 0x27 0x515890
  virtual undefined
  MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA(int param_1); // slot 0x28 0x5159b0
  virtual undefined
  MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileB(int param_1); // slot 0x29 0x515b10
  virtual undefined
  UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(int param_1); // slot 0x2a 0x50fca0
  // Looks up whether tileIndex's region has an eligible stationed unit
  // (TArmyMgr::HasEligibleStationedUnitInRegion) but discards the result -- the original's
  // own call site never reads the return value either, so this is vestigial/dead code.
  virtual void ApplyUnitMovementClassForTileIfValid(int tileIndex); // slot 0x2b 0x515d60
  virtual undefined SetRegionTileSubtypeAndRefreshNeighborFlags(int param_1,
                                                                int param_2); // slot 0x2c 0x515f80
  // Real body is just `ret 0xc` (pops 3 stack dwords, no other instructions) -- no evidence
  // for the real parameter types since none are read; typed as unused ints to match the
  // stack-cleanup byte count.
  virtual void NoOpVirtualSlot2D(int param_1, int param_2, int param_3); // slot 0x2d 0x515de0
  virtual undefined
  DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(short param_1,
                                                         undefined4 param_2); // slot 0x2e 0x513290
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
  // g_apTerrainTypeDescriptorTable[nationSlotParam]->ownerNationSlot used as a
  // terrainStateTable index -- same dual-use pattern flagged on
  // TGlobalMapCityScoreRecord::ownerNationSlot) as developmentStage 2. param_2 is unused
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
  virtual undefined SetTileOwnerAndInvalidateNeighborState(short param_1,
                                                           short param_2); // slot 0x37 0x5133f0
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
  virtual int QueueDepotConstructionOrder(int* pMapContext, short nTileIndex, short nNationId,
                                          undefined2 param_4); // slot 0x49 0x5145b0
  virtual void QueuePortConstructionOrder(int* pMapContext, short nTileIndex, short nNationId,
                                          undefined2 param_4);     // slot 0x4a 0x5147d0
  virtual void SetProvinceCapitalTileFlagBit08(short nProvinceId); // slot 0x4b 0x5149d0
  virtual void FloodFillTileRegionMarker(short nTileIndex,
                                         short nOwnerNationId); // slot 0x4c 0x5143d0
  virtual void
  SetTileTransportFlagsTo0x37AndRefreshNeighbors(short nTileIndex); // slot 0x4d 0x514a20
  // === END GENERATED DECLS (TMapMgr) ===

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

  static void ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles,
                                            char wrapHorizontally);
  static short GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction);
  static short StepHexTileIndexByDirectionWithWrapRules(short tileIndex, short direction);
  static bool StepHexRowColByDirectionWithWrapRules(int* row, int* col, int direction);
  static void AdvanceSpiralSearchStateAndStepHexCoordinates(struct HexSpiralSearchState* state);
  static short TileIndexFromRowCol(int row, int col);

  short ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(short terrainType, char wrapBias);

  char AreNationsBorderLinked(int nationA, int nationB);
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
  // 0x518b40. Developer purchase cost of a tile's two edge resources (weights the trade
  // manager's proposal-weight metric). Reattributed from TCivToolbar (heuristic 46).
  int CalculateDeveloperTilePurchaseCost(short nTileIndex);

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

  // Returns cityScoreTable[index].stationedUnitChain98 when index is in [0, 0x180), else
  // nullptr -- the same "validate then fetch the tile's unit chain head" idiom already
  // inlined at several other TArmyMgr callsites, but here it's the original's own
  // standalone function. 0x004a4190, __thiscall, one short stack arg.
  TMilitaryUnit* ValidateGridIndexRange0To17F(short index);

  // Clears terrainStateTable[i].perTileVisitedFlag0f for every one of the 0x1950
  // (108x60) map tiles. 0x00409250, __thiscall, no args.
  void ClearPerTileByte0FForAllMapTiles();

  TMapMgr();
};

// Retail body ignores provinceId and returns the constant weight 0x21 (33); the
// mission-scoring family converts it to float for the accumulate dampening factor.
short __stdcall GetProvinceUnitOrderWeight(short provinceId); // 0x5184e0

// === BEGIN GENERATED (TMapMgr) — refreshed by `just gen-class TMapMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x006587e0 (78 slots), object size 0x28, base TObject
//   slot 0x00  byte 0x00  0x0050e3b0  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x0050e460  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x0050e7a0  override  WriteTo
//   slot 0x06  byte 0x18  0x0050e620  override  ReadFrom
//   slot 0x07  byte 0x1c  0x0050e510  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0050e8b0  override  WrapperFor_AllocateWithFallbackHandler_At0050e8b0
//   slot 0x0b  byte 0x2c  0x0050ec90  override  BuildOrLoadGlobalMapStateForSession
//   slot 0x0c  byte 0x30  0x0050f200  override  LoadPoliticalMapRegionSubtypeTableFromResourceStream
//   slot 0x0d  byte 0x34  0x00510210  override  UpdateMapTileAdjacencyMasksAndVariantForTile
//   slot 0x0e  byte 0x38  0x005107e0  override  InitializeTileNeighborConnectionMaskIfNeeded
//   slot 0x0f  byte 0x3c  0x0050fe10  override  UpdateTileNeighborBorderInfluenceCounters
//   slot 0x10  byte 0x40  0x00511610  override  UpdateStrategicMapTileIconVariantState
//   slot 0x11  byte 0x44  0x00511a70  override  TMapMaker_EnsureRegionClassHasSubtype3And4AssignmentsWithRng
//   slot 0x12  byte 0x48  0x00511e80  override  TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress
//   slot 0x13  byte 0x4c  0x00511ed0  override  DispatchTurnEvent7DDForActiveNation
//   slot 0x14  byte 0x50  0x005178c0  override  OrphanLeaf_NoCall_Ins08_005178c0
//   slot 0x15  byte 0x54  0x00511f30  override  TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask
//   slot 0x16  byte 0x58  0x005121d0  override  IsNodeTypeLinkUnavailableAndNoActiveMapActionContext
//   slot 0x17  byte 0x5c  0x005122b0  override  IsShiftKeyDown
//   slot 0x18  byte 0x60  0x005122d0  override  IsAltKeyDown
//   slot 0x19  byte 0x64  0x00511f10  override  ForwardComputeRepresentativeTileIndexForTerrainTypeWithWrapBias
//   slot 0x1a  byte 0x68  0x00513f60  override  SetHexAdjacencyDirectionFlagsForTilePair
//   slot 0x1b  byte 0x6c  0x00514310  override  OrphanLeaf_NoCall_Ins18_00514310
//   slot 0x1c  byte 0x70  0x00514360  override  OrphanLeaf_NoCall_Ins31_00514360
//   slot 0x1d  byte 0x74  0x00514e40  override  OrphanLeaf_NoCall_Ins15_00514e40
//   slot 0x1e  byte 0x78  0x00514e80  override  OrphanLeaf_NoCall_Ins28_00514e80
//   slot 0x1f  byte 0x7c  0x00514dc0  override  WrapperFor_IsValidSecondaryNationHomeTileCandidate_At00514dc0
//   slot 0x20  byte 0x80  0x00514ef0  override  OrphanLeaf_NoCall_Ins09_00514ef0
//   slot 0x21  byte 0x84  0x00514f20  override  OrphanCallChain_C5_I115_00514f20
//   slot 0x22  byte 0x88  0x005150e0  override  OrphanCallChain_C1_I159_005150e0
//   slot 0x23  byte 0x8c  0x00515330  override  WrapperFor_LookupOrderCompatibilityMatrixValue_At00515330
//   slot 0x24  byte 0x90  0x00515460  override  WrapperFor_LookupOrderCompatibilityMatrixValue_At00515460
//   slot 0x25  byte 0x94  0x005155c0  override  OrphanLeaf_NoCall_Ins83_005155c0
//   slot 0x26  byte 0x98  0x00515720  override  MarkType5NeighborTilesUnavailableByNationCapability
//   slot 0x27  byte 0x9c  0x00515890  override  OrphanLeaf_NoCall_Ins69_00515890
//   slot 0x28  byte 0xa0  0x005159b0  override  MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA
//   slot 0x29  byte 0xa4  0x00515b10  override  MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileB
//   slot 0x2a  byte 0xa8  0x0050fca0  override  UpdateTilePrimaryAndSecondaryNeighborLinksByPriority
//   slot 0x2b  byte 0xac  0x00515d60  override  ApplyUnitMovementClassForTileIfValid
//   slot 0x2c  byte 0xb0  0x00515f80  override  SetRegionTileSubtypeAndRefreshNeighborFlags
//   slot 0x2d  byte 0xb4  0x00515de0  override  OrphanRetStub_00515de0
//   slot 0x2e  byte 0xb8  0x00513290  override  DispatchFormationEntryActionsAndMaybeCreateTurnEvent12
//   slot 0x2f  byte 0xbc  0x00516090  override  OrphanLeaf_NoCall_Ins27_00516090
//   slot 0x30  byte 0xc0  0x00516100  override  OrphanLeaf_NoCall_Ins18_00516100
//   slot 0x31  byte 0xc4  0x00513610  override  OrphanLeaf_NoCall_Ins14_00513610
//   slot 0x32  byte 0xc8  0x00513660  override  GetTileCivilianWorkOrderCostClassNibble
//   slot 0x33  byte 0xcc  0x005136a0  override  OrphanLeaf_NoCall_Ins35_005136a0
//   slot 0x34  byte 0xd0  0x00513720  override  OrphanLeaf_NoCall_Ins37_00513720
//   slot 0x35  byte 0xd4  0x005135a0  override  OrphanCallChain_C1_I29_005135a0
//   slot 0x36  byte 0xd8  0x00513170  override  OrphanCallChain_C3_I43_00513170
//   slot 0x37  byte 0xdc  0x005133f0  override  SetTileOwnerAndInvalidateNeighborState
//   slot 0x38  byte 0xe0  0x00516150  override  OrphanLeaf_NoCall_Ins14_00516150
//   slot 0x39  byte 0xe4  0x005161a0  override  OrphanLeaf_NoCall_Ins12_005161a0
//   slot 0x3a  byte 0xe8  0x005161e0  override  OrphanLeaf_NoCall_Ins10_005161e0
//   slot 0x3b  byte 0xec  0x00516220  override  OrphanLeaf_NoCall_Ins09_00516220
//   slot 0x3c  byte 0xf0  0x00516260  override  OrphanLeaf_NoCall_Ins464_00516260
//   slot 0x3d  byte 0xf4  0x00517410  override  OrphanCallChain_C3_I41_00517410
//   slot 0x3e  byte 0xf8  0x00517480  override  OrphanCallChain_C3_I49_00517480
//   slot 0x3f  byte 0xfc  0x00517520  override  OrphanVtableAssignStub_00517520
//   slot 0x40  byte 0x100  0x00517540  override  OrphanLeaf_NoCall_Ins55_00517540
//   slot 0x41  byte 0x104  0x00517600  override  OrphanCallChain_C1_I46_00517600
//   slot 0x42  byte 0x108  0x005176a0  override  OrphanLeaf_NoCall_Ins04_005176a0
//   slot 0x43  byte 0x10c  0x005176c0  override  OrphanLeaf_NoCall_Ins04_005176c0
//   slot 0x44  byte 0x110  0x005176e0  override  GetMapImprovementTierBucketOffset
//   slot 0x45  byte 0x114  0x00517780  override  GetMapImprovementSpriteBaseOffset
//   slot 0x46  byte 0x118  0x00517710  override  ApplyMapImprovementSelectionState
//   slot 0x47  byte 0x11c  0x005177d0  override  GetMapImprovementTileOffsetFromClass
//   slot 0x48  byte 0x120  0x005177f0  override  GetMapImprovementTileSpriteOffset
//   slot 0x49  byte 0x124  0x005145b0  override  QueueDepotConstructionOrder
//   slot 0x4a  byte 0x128  0x005147d0  override  QueuePortConstructionOrder
//   slot 0x4b  byte 0x12c  0x005149d0  new       SetProvinceCapitalTileFlagBit08
//   slot 0x4c  byte 0x130  0x005143d0  new       FloodFillTileRegionMarker
//   slot 0x4d  byte 0x134  0x00514a20  new       SetTileTransportFlagsTo0x37AndRefreshNeighbors
// object size 0x28 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TMapMgr) ===
