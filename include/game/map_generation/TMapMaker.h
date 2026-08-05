#pragma once

#include "game/app/TObject.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/strategic_terrain.h"

struct Province;

// One full-resolution map-generator tile record. The random-template passes copy the
// complete 0x24-byte record as nine dwords; individual gameplay fields remain owned by
// TTerrainStateRecord after generation.
struct MapGeneratorTileRecord {
  int words[9];
};
ASSERT_SIZE(MapGeneratorTileRecord, 0x24);

// VTABLE: IMPERIALISM 0x006598f8
class TMapMaker : public TObject {
  DECLARE_DYNCREATE(TMapMaker)
public:
  TMapMaker();
  virtual ~TMapMaker() override;

  // Picks a random cell of regionClassGrid10[15][27] using two LCG values.
  // ABI: two pointer arguments, void return. slot 10 / 0x28
  virtual void PickRandomRegionGridCell(unsigned int* outColumn, unsigned int* outRow);
  // Runs one full terrain-generation attempt; the driver retries until validation passes.
  // slot 11 / 0x2c
  virtual void RunMapGenerationAttempt();
  // Recursively assigns a region class to a coarse grid cell and its best-scoring hex
  // neighbour, retrying up to retryBudget times. Returns the successful assignment count.
  // slot 12 / 0x30
  virtual int AssignRegionClassToCellAndNeighbors(int cellIndex, int mode, int classIndex,
                                                  int retryBudget);
  // Merges major-nation region groups; false on an incompatible neighbor group. slot 13 / 0x34
  virtual char TryMergeRegionGroupWithNeighborsRestrictedToMajors(int cellIndex, int classIndex);
  // Expands assigned city-region ids into the tile grid. slot 14 / 0x38
  virtual void ExpandRegionGridIntoTilesAndAllocateCityRecords();
  // Places terrain features according to their generation quotas. slot 15 / 0x3c
  virtual void PlaceTerrainFeatureQuotas();
  // Merges region groups for every terrain class. slot 16 / 0x40
  virtual char TryMergeRegionGroupWithNeighbors(int cellIndex, int classIndex);
  // Smooths interior city-region tile ownership from neighboring records. slot 17 / 0x44
  virtual void SmoothCityRegionOwnershipByNeighborSampling();
  // Grows a linear mountain-range terrain feature. slot 18 / 0x48
  // ORACLE: Mac TMapMaker::SeedMountainRange(long, long, long).
  virtual int SeedMountainRange(int tileIndex, int retryBudget, int direction);
  // slot 19 / 0x4c
  virtual void CreateDeserts();
  // Walks the city-region tile ring starting at `coarseIndex`, converting empty tiles
  // ('\0') to '6' with probability `percentChance`/100; returns the number marked.
  // slot 20 / 0x50
  virtual int TundraBand(int row, int percentChance);
  // Same city-region ring probabilistic marking as slot 0x50 but also marks a hex
  // neighbour of each converted tile. slot 21 / 0x54
  virtual int DesertBand(int row, int percentChance);
  // Places a city marker and probabilistically spreads it to neighbors. slot 22 / 0x58
  virtual int PlaceCityMarkerAndSpreadNeighbors(int tileIndex, int retryBudget, char markerVariant);
  virtual void CreateRivers(); // slot 23 / 0x5c
  // Recursively grows a river segment toward water. slot 24 / 0x60
  virtual char GrowRiver(long tileIndex, long incomingDirection, long outgoingDirection, long depth,
                         unsigned char startedOnHills);
  // Finalizes or compacts city-region ids and rebuilds their borders. slot 25 / 0x64
  virtual void AssignOrCompactCityRegionIdsAndRebuildBorders(int mode);
  // Post-attempt validity probe: nonzero means the driver must regenerate. slot 26 / 0x68
  virtual char ErrorCheck();
  virtual void TargetValidationSucceeded(); // slot 27 / 0x6c
  // Marks the region record of tileIndex, then visits its six hex neighbours.
  // slot 28 / 0x70
  virtual void EraseZones(long coarseIndex);
  // Resolves the region-grid cell adjacent to cell in hex direction 0..5. slot 29 / 0x74
  virtual int GetAdjacentRegionGridCell(int cell, int direction);
  // Runs between region-grid expansion and terrain-feature placement. slot 30 / 0x78
  virtual void RandomizeRegionTemplatesAndSmoothOwnership();
  // Copies a region-template bank using a random source variant. slot 31 / 0x7c
  virtual void CopyRegionTemplateBankWithRandomVariant(int coarseIndex, short regionClass,
                                                       short unusedClass, short northClass,
                                                       short southClass);
  // Copies a region-template bank to a neighboring coarse-grid cell. slot 32 / 0x80
  virtual void CopyRegionTemplateBankToNeighborCell(int coarseIndex, short regionClass,
                                                    short unusedClass, short northClass,
                                                    short unusedClass2);
  virtual MapGeneratorTileRecord*
  GetFineGridCellBasePointerFromCoarseIndex(int coarseIndex); // slot 33 / 0x84

  // LAYOUT: the vtable ends at slot 0x21, followed by null slots 0x22..0x28. The
  // SeaSegmentStretch and SeapointStretch vtables are adjacent data, not TMapMaker methods.

  // City-region id (tile[4] - 0x17) at a tile index, or -1 if the tile is out of range or
  // not a water tile. 0x0052a670.
  int GetCityRegionIdAtTileIndex(int tileIndex);

  // ORACLE: Mac TMapMaker::CheckProvs(). Composite map-generation rejection predicate:
  // virtual ErrorCheck, empty-column scan, then full terrain-class frontier coverage.
  // 0x00526620.
  char CheckProvs();

  // True when some column of regionClassGrid10 is entirely unassigned (all 15 rows == -1).
  // 0x00526710.
  char ValidateAllColumnsHaveAssignedRegionClass();

  // True when every one of the 23 region classes has at least one assigned grid cell
  // adjacent to an unassigned cell (mask of frontier-touching classes == 0x7fffff).
  // 0x00526760.
  char ValidateTerrainClassAdjacencyCoverageMask();

  // True when every terrain class present on the map has at least one valid seed candidate
  // (a land tile whose hex neighbourhood holds a city-region tile with uniform-class
  // neighbours); reservoir-samples the chosen candidate per class. 0x005267f0.
  char ValidateSeedCandidateExistsForEachTerrainClass();

  // Scans every tile's hex neighbours and emits a Seapoint into the overlay-quad table for
  // each city-region border edge (single edges + 3-region triple junctions). 0x0052c1a0.
  void BuildCityRegionBorderOverlaySegments();

  // Match the per-edge overlay points into the region-border segment table. Although the
  // body only touches global scratch tables, its sole retail caller loads this into ECX.
  // 0x0052cae0.
  void BuildOverlaySpanRecordsFromQuadBorderLinks();

  // Give every still-unclaimed border-segment side its own region id: walk the
  // region-border table and, for each side whose carried attribute is still -1, take the
  // next ordinal from cityRegionCount2a4 and flood it along that side's chain. 0x0052b820.
  void AssignRegionIdsToUnclaimedBorderSegmentSides();

  // Compacts city-region ids into a contiguous range, propagating labels across same-region
  // hex neighbours; writes tile[4] = newId + 0x17 and updates cityRegionCount2a4. 0x0052d1f0.
  void ReindexContiguousCityRegionIds();

  // Seeds city regions on a lattice with LCG jitter then floods ids to adjacent city tiles.
  // 0x0052a160.
  void GenerateCityRegionIdsBySeedAndNeighborPropagation();

  // Rotates the map columns so the peak city-tile-density band is recentred. 0x00529960.
  void RotateMapColumnsByPeakCityTileDensity();

  // Randomly mirrors template banks within a fine-grid cell for each neighbour class that
  // differs from the base class. 0x005293d0.
  unsigned int RandomizeRegionTemplateBanksForMismatchedNeighborClasses(int coarseIndex,
                                                                        unsigned short baseClass,
                                                                        unsigned short class3,
                                                                        unsigned short class4,
                                                                        unsigned short class5);

  // Scanline-fills city-region ids across the overlay grid from the region-border SeaSegment
  // table: for each cell, find the nearest crossing segment and write its region. 0x0052b9b0.
  void AssignCityRegionIdsFromOverlayScanlineIntersections();

  // Merges undersized city regions into a neighbour and compacts region ids.
  // Non-virtual (paired by address marker). 0x0052d750.
  void MergeSmallCityRegionsAndCompactIds();

  // Rebuilds the map-order route buffer + active map-action contexts from the region-border
  // SeaSegment table: cleans degenerate links, allocates a CRect route record per live link,
  // wires mutual primary-neighbour adjacency between each link's two region contexts, then
  // refreshes port-zone adjacency and zone status codes. 0x0052e350.
  void RebuildUMapperRouteRecordsAndActiveMapRects();

  // Second-phase entry: parses the map-tuning string into the terrain-class quota
  // globals, seeds the map-gen PRNG from the string hash, then loops generation
  // attempts (RunMapGenerationAttempt + validity checks), assigns region ids, runs
  // the follow-on passes, applies the easter-egg keyword terrain overrides, and
  // retries the whole pipeline until ValidateSeedCandidateExistsForEachTerrainClass
  // accepts the map. 0x525a30, __thiscall, RET 0xc.
  void GenerateMapFromTuningStringAndApplyScenarioOverrides(char* tileGrid, Province* cityTable,
                                                            CString* tuningString);

  // --- data fields (raw pad except the ones the ported passes read) ---
  char pad_04[0x08 - 0x04]; // +0x04
  // Compact the city-region ids in place: walk every grid record, map each distinct
  // region class (record[4] - 0x17) to the next free ordinal through
  // g_cityRegionIdRemapTable_006a3498, write the remapped id back, and leave the final
  // ordinal count in cityRegionCount2a4. 0x0052a0a0, __thiscall.
  void CompactCityRegionIds();

  // For each active city region, find the first entry still carrying its negative
  // placeholder (-2, -3, ...) and hand it the next sequential value from *nextValue.
  // Returns how many entries were assigned. 0x0052d6b0, __thiscall.
  int AssignSequentialValuesToRegionPlaceholders(short* tileValues, int* nextValue);

  // ORACLE: Mac TMapMaker::ZoneCorner(long). Selects the row containing the longest
  // contiguous run of nationCode, then returns the wrap-aware average owned column in
  // that row. Returns -1 when the selected row contains no matching tile. 0x00529c80.
  int ZoneCorner(long nationCode);

  // Centroid tile of every grid record owned by `nationCode` (record[4]). Tiles hugging
  // both the left (col < 0x19) and right (col > 0x53) edges mean the territory wraps: with
  // useWrapOffset the column sum is biased by leftEdgeCount * 0x6c, otherwise the sweep is
  // redone snapping each column to the dominant edge. Returns -1 when nothing matches.
  // 0x00529d90, __thiscall.
  int ComputeOwnedTerritoryCentroidTile(int nationCode, char useWrapOffset);

  // Repair pass: for every grid entry whose value is < -1 (orphaned), adopt the value of
  // the first hex neighbour that holds a valid value and belongs to the same terrain
  // class (record[0] == 5 keyed by record[4] - 0x17). Returns the number repaired.
  // 0x0052d4b0, __thiscall.
  int RepairOrphanedTileValuesFromNeighbors(short* tileValues);

  char* mapTileGrid08; // +0x08 base of the 6480-tile (108x60) grid, stride 0x24

  // ORACLE: IsSeaTile. The tile's terrain kind byte is water. 0x0052a600.
  unsigned char IsSeaTile(int tileIndex);
  // ORACLE: SetSeaZoneIndex. Stores the sea-zone ordinal into the tile's owner
  // tag byte (+0x04), biased by 0x17 -- the same bias the map-order context applies
  // when it turns an owner tag back into a context-array index. 0x0052a6b0.
  void SetSeaZoneIndex(int tileIndex, char zoneIndex);
  // +0x0c the city-score record table, stored verbatim by the 0x525a30 entry
  // (the caller passes TMapMgr::cityScoreTable).
  Province* cityScoreTable0c;
  // +0x10 region-class grid: 15 rows x 27 columns of region-class bytes (-1 = unassigned).
  signed char regionClassGrid10[15][27];
  char pad_1a5[0x1a8 - 0x1a5]; // +0x1a5
  // +0x1a8 per-class-index union-find group-membership lists: up to 3 member class
  // indices per group id (index 0..6 = major-nation groups), -1 terminated. Read/written
  // alongside cityRegionNextId1fc/cityRegionIds200 by the region-merge slots
  // (TryMergeRegionGroupWithNeighborsRestrictedToMajors/TryMergeRegionGroupWithNeighbors,
  // 0x527300/0x5274d0) and reset here by RunMapGenerationAttempt.
  int groupMemberLists1a8[7][3];
  // +0x1fc next city-region id + the 0x17-entry id table the driver backfills
  // (-1 slots get ++cityRegionNextId1fc).
  int cityRegionNextId1fc;
  int cityRegionIds200[0x17];
  // +0x25c..+0x29c: a 0x40-byte hole with no observed access. RunMapGenerationAttempt's
  // three inits stop exactly at +0x25c (regionClassGrid10 is 0x65 dwords + 1 byte from
  // +0x10, groupMemberLists1a8 is 7x3 dwords, and cityRegionIds200 is 7 + 16 dwords from
  // +0x200), a field-xref sweep at every dword offset in the range returns zero
  // accesses, and no indexed access reaches past cityRegionIds200[0x17]. Kept opaque
  // rather than overlaid with invented fields.
  char unusedHole25c[0x29c - 0x25c];
  // Reset to -1 by RunMapGenerationAttempt alongside the other per-attempt scratch
  // state; not yet observed read anywhere. 0x0052712c.
  int lastMinorSeedCandidate29c;
  char pad_2a0[0x2a1 - 0x2a0]; // +0x2a0
  // +0x2a1 mode byte copied in by the BuildOrLoadGlobalMapStateForSession caller.
  unsigned char modeByte2a1;
  char pad_2a2[2];
  int cityRegionCount2a4; // +0x2a4 number of active city regions
};

ASSERT_SIZE(TMapMaker, 0x2a8);
