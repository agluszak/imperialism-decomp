#pragma once

#include "game/app/TObject.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/strategic_terrain.h"

struct Province;

// VTABLE: IMPERIALISM 0x006598f8
class TMapMaker : public TObject {
  DECLARE_DYNCREATE(TMapMaker)
public:
  TMapMaker();
  virtual ~TMapMaker() override;

  // Draws two LCG values into out-pointers: *outColumn = rng % 27, *outRow = rng % 15
  // (a random cell of regionClassGrid10[15][27]). Verified RET 0x8 (2 stack pointer args,
  // void return) -- the header's previous 0-arg `char IsEnabled()` was templated off
  // TView/TEventHandler's real slot-10 virtual of that name and does not describe this
  // slot (TMapMaker derives from TObject, not TView, so the shared ordinal is a
  // coincidence). slot 10 / 0x28
  virtual void PickRandomRegionGridCell(unsigned int* outColumn, unsigned int* outRow);
  // Runs one full terrain-generation attempt over the tile grid (was junk-named
  // SetControlValue; 0-arg __thiscall, verified RET 0). Driver retries it until the
  // validity checks pass. slot 11 / 0x2c
  virtual void RunMapGenerationAttempt();
  // Verified RET 0x10 (4 stack args) from both the caller (0x526c20, which pushes 4
  // explicit ints) and the callee's own frame layout -- the header's previous 0-arg
  // "GetNextHandler() -> TEventHandler*" was templated off TEventHandler's real
  // virtual of the same name/slot position and does not describe this class's real
  // slot. Recursively assigns a region class to a coarse grid cell and its
  // best-scoring hex neighbour, retrying up to `retryBudget` times; returns the
  // number of successful assignments. slot 12 / 0x30
  virtual int AssignRegionClassToCellAndNeighbors(int cellIndex, int mode, int classIndex,
                                                  int retryBudget);
  // Verified 2 stack int args + char return from the 0x527040 call site (pushes
  // classIndex then cellIndex, tests AL) -- the header's previous 1-arg void*
  // signature was templated off TEventHandler::DispatchQueuedUiCommandAndRelease and
  // does not describe this class's real slot. Only tried for major nations
  // (classIndex < 7). Union-find merge of `classIndex`'s region group against each hex
  // neighbour's already-assigned class: allocates a new group id, adopts a neighbour's
  // group, or absorbs a neighbour into this class's group (in whichever direction has
  // no group yet), tracking up to 3 member class-indices per group id in
  // `groupMemberLists1a8` (+0x1a8). Returns false the moment two neighbours already
  // belong to two DIFFERENT established groups, or a group's member list is full;
  // otherwise merges/allocates group ids as a side effect and returns true. slot 13 / 0x34
  virtual char TryMergeRegionGroupWithNeighborsRestrictedToMajors(int cellIndex, int classIndex);
  // Map-gen pass dispatched right after city-region ids are assigned (was junk-named
  // DispatchUiSelectionToHandler; 0-arg __thiscall, verified RET 0). slot 14 / 0x38
  virtual void ExpandRegionGridIntoTilesAndAllocateCityRecords();
  // Map-gen pass (was junk-named DoEvent with 3 phantom args; 0-arg __thiscall).
  // slot 15 / 0x3c
  virtual void PlaceTerrainFeatureQuotas();
  // Verified 2 stack int args + char return, same call site/args as slot 0x34 above
  // (tried for every class, not just majors) -- the header's previous 3-arg
  // TEventHandler-shaped HandleEvent signature does not describe this class's real
  // slot. Same union-find neighbor-merge as slot 0x34 above but WITHOUT the +0x1a8
  // group-membership bookkeeping: a class with an existing group can only merge by
  // adopting a neighbour's group (or forming a new one when neither has one yet) --
  // if this class already has a group and the neighbour doesn't, that's treated as a
  // conflict (returns false) rather than expanding this class's group. slot 16 / 0x40
  virtual char TryMergeRegionGroupWithNeighbors(int cellIndex, int classIndex);
  // Verified 0 stack args (bare RET) -- the header's previous 1-arg form was wrong,
  // templated off a neighboring slot's shape rather than checked. Two-pass smoothing
  // of the full-resolution generation grid's tile ownership (offset+4 field): pass 1
  // erodes tiles with 0-2 same-owner hex neighbors (50%/75% chance for 1/2) into a
  // differing neighbor's full record when one exists; pass 2 replaces any tile with
  // NO same-owner neighbor at all into a uniformly-random neighbor's record. Only
  // processes rows 1..58 (skips the border rows). slot 17 / 0x44
  virtual void SmoothCityRegionOwnershipByNeighborSampling();
  // Verified 3 stack int args from both the caller (0x527730, which pushes 3
  // explicit ints) and Ghidra's own (correct, for once) 3-param signature recovery
  // on the callee itself -- the header's previous 1-arg form was wrong. Recursively
  // walks the hex grid from `tileIndex` in direction `featureType` (0..5, cycled via
  // random retry on collision) up to `retryBudget` steps, laying a linear terrain
  // feature (river/road-shaped); returns the number of steps placed. Uses the same
  // g_hexColOffsetEvenRow_00697450/g_hexRowOffset_00697468/g_hexColOffsetOddRow_00697480
  // hex-direction tables as GetNeighborTileIDArray. slot 18 / 0x48
  virtual int ForwardParam(int tileIndex, int retryBudget, int featureType);
  // Verified 0 stack args from the caller (0x527730 calls it with no pushes) -- the
  // header's previous 1-arg form was wrong. slot 19 / 0x4c
  virtual void CreateDeserts();
  // Walks the city-region tile ring starting at `coarseIndex`, converting empty tiles
  // ('\0') to '6' with probability `percentChance`/100; returns the number marked.
  // Verified RET 0x8 (2 stack int args, int return) -- the previous 0-arg
  // `GetIdleFreq()` was templated off TView's real slot-20 virtual and
  // does not describe this slot. slot 20 / 0x50
  virtual int TundraBand(int row, int percentChance);
  // Same city-region ring probabilistic marking as slot 0x50 but also marks a hex
  // neighbour of each converted tile. Verified RET 0x8 (2 stack int args, int return) --
  // the previous 1-arg `SetIdleFreq(int)` was templated off TView's real
  // slot-21 virtual and does not describe this slot. slot 21 / 0x54
  virtual int DesertBand(int row, int percentChance);
  // Verified RET 0xc (3 stack args), from both Ghidra's own (correct) signature
  // recovery and the self-recursive call inside the callee itself -- the header's
  // previous 0-arg `TView*`-returning form was templated off TView's real
  // GetWindow and does not describe this slot. Claims `tileIndex` (marking it 1,
  // plus a variant byte at +0x13 selected by `markerVariant`), refuses if any hex
  // neighbor is already a marker (byte 6), then recursively spreads to neighbors
  // (46% chance each) until `retryBudget` spreads land. Returns the spread count.
  // slot 22 / 0x58
  virtual int PlaceCityMarkerAndSpreadNeighbors(int tileIndex, int retryBudget, char markerVariant);
  virtual void CreateRivers(); // slot 23 / 0x5c
  // Recursively grows one river segment from `tileIndex` toward water, refusing tiles
  // that already carry a river byte, mountains below the surface and hills unless the
  // run began on hills; on reaching water at depth >= 5 it stamps the outgoing direction
  // and unwinds, writing each tile's connection type from
  // g_riverConnectionTypeByDirectionPair. The parameter names below come from the ported
  // body, not from Ghidra. slot 24 / 0x60
  virtual char GrowRiver(long tileIndex, long incomingDirection, long outgoingDirection, long depth,
                         unsigned char startedOnHills);
  // Map-gen finalize pass (was junk-named ResignedTarget; takes one mode arg the
  // driver passes as 0 -- verified RET 4). slot 25 / 0x64
  virtual void AssignOrCompactCityRegionIdsAndRebuildBorders(int mode);
  // Post-attempt validity probe: nonzero means the attempt failed and the driver
  // regenerates (was junk-named TargetValidationFailed(int); really a 0-arg __thiscall
  // returning AL). slot 26 / 0x68
  virtual char ErrorCheck();
  virtual void TargetValidationSucceeded(); // slot 27 / 0x6c
  // Marks the region record of tile `tileIndex` (byte 0xf7) then visits its six hex
  // neighbours via slots 0x1d/0x1c. Verified RET 0x4 (1 stack short arg, void return) --
  // the previous 0-arg `BecameWindowTarget()` was templated off TEventHandler's
  // real slot-28 virtual and does not describe this slot. slot 28 / 0x70
  virtual void EraseZones(long coarseIndex);
  // Resolves the region-grid cell adjacent to `cell` in hex `direction` 0..5 (was
  // junk-named ResignedWindowTarget; verified two-arg __thiscall returning
  // the neighbour cell index). slot 29 / 0x74
  virtual int GetAdjacentRegionGridCell(int cell, int direction);
  // Map-gen pass run between ExpandRegionGridIntoTilesAndAllocateCityRecords and PlaceTerrainFeatureQuotas (was junk-named
  // DispatchCityProductionAction1B; 0-arg __thiscall). slot 30 / 0x78
  virtual void RandomizeRegionTemplatesAndSmoothOwnership();
  // Copies a 36-byte (9-dword) region-template bank between fine-grid cells (resolved
  // via slot 0x21), selecting the source variant by LCG randomness. RET 0x14 = 5 stack
  // dwords, and the body reads the trailing four as words (MOV DX,word ptr [ESP+0x10] /
  // CMP word ptr [ESP+0x18],DX), so they are shorts, not dwords. slot 31 / 0x7c
  virtual void CopyRegionTemplateBankWithRandomVariant(int coarseIndex, short regionClass,
                                                       short unusedClass, short northClass,
                                                       short southClass);
  // Copies a 36-byte region-template bank to a neighbouring cell (slots 0x1d/0x21) with
  // an LCG-gated second copy. Verified RET 0x14 (5 stack dwords) -- the previous 0-arg
  // `char ResignTarget()` was templated off TView's real slot-32 virtual and
  // does not describe this slot. Arg types beyond the dword count are provisional.
  // slot 32 / 0x80
  virtual void CopyRegionTemplateBankToNeighborCell(int coarseIndex, short regionClass,
                                                    short unusedClass, short northClass,
                                                    short unusedClass2);
  virtual char* GetFineGridCellBasePointerFromCoarseIndex(int coarseIndex); // slot 33 / 0x84

  // TMapMaker's real vtable (0x006598f8) ends at its last reachable slot (0x21 /
  // SelectOwner above); slots 0x22..0x28 are a literal NULL tail (matching the
  // TZone::vtable convention, see TZone.h). The two non-NULL pointers the extractor lists
  // beyond that run (slots 0x29/0x2a → 0x0052a760/0x0052c0a0) are NOT TMapMaker methods:
  // they are the single vtable slots of two adjacent stretch<T> tables laid out right after
  // TMapMaker's vtable (SeaSegmentStretch @ 0x0065999c, SeapointStretch @ 0x006599a0). Those
  // append virtuals are owned in sea_geometry.cpp; see sea_geometry.h.

  // City-region id (tile[4] - 0x17) at a tile index, or -1 if the tile is out of range or
  // not a water tile. 0x0052a670.
  int GetCityRegionIdAtTileIndex(int tileIndex);

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
