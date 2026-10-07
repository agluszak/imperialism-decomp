#pragma once

#include "game/app/TObject.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/strategic_terrain.h"

struct Province;

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

  // Picks a random cell of regionClassGrid[15][27] using two LCG values.
  // ABI: two pointer arguments, void return. slot 10 / 0x28
  virtual void PickRandomRegionGridCell(unsigned int* outColumn, unsigned int* outRow);
  virtual void RunMapGenerationAttempt();
  virtual int SelectGPZone(int cellIndex, int mode, int classIndex, int retryBudget);
  // Merges major-nation region groups; false on an incompatible neighbor group. slot 13 / 0x34
  virtual bool TryMergeRegionGroupWithNeighborsRestrictedToMajors(int cellIndex, int classIndex);
  // Expands assigned city-region ids into the tile grid. slot 14 / 0x38
  virtual void ExpandRegionGridIntoTilesAndAllocateCityRecords();
  // Places terrain features according to their generation quotas. slot 15 / 0x3c
  virtual void PlaceTerrainFeatureQuotas();
  // Merges region groups for every terrain class. slot 16 / 0x40
  virtual bool TryMergeRegionGroupWithNeighbors(int cellIndex, int classIndex);
  // Smooths interior city-region tile ownership from neighboring records. slot 17 / 0x44
  virtual void SmoothCityRegionOwnershipByNeighborSampling();
  // Grows a linear mountain-range terrain feature. slot 18 / 0x48
  // ORACLE: Mac TMapMaker::SeedMountainRange(long, long, long).
  virtual int SeedMountainRange(int tileIndex, int retryBudget, int direction);
  // slot 19 / 0x4c
  virtual void CreateDeserts();
  virtual int TundraBand(int row, int percentChance);
  virtual int DesertBand(int row, int percentChance);
  // Places a city marker and probabilistically spreads it to neighbors. slot 22 / 0x58
  virtual int PlantForestCluster(int tileIndex, int retryBudget, bool markerVariant);
  virtual void CreateRivers(); // slot 23 / 0x5c
  // Recursively grows a river segment toward water. slot 24 / 0x60
  virtual bool GrowRiver(long tileIndex, long incomingDirection, long outgoingDirection, long depth,
                         bool startedOnHills);
  // Finalizes or compacts city-region ids and rebuilds their borders. slot 25 / 0x64
  virtual void AssignOrCompactCityRegionIdsAndRebuildBorders(int mode);
  // Post-attempt validity probe: nonzero means the driver must regenerate. slot 26 / 0x68
  virtual bool ErrorCheck();
  virtual void TargetValidationSucceeded(); // slot 27 / 0x6c
  virtual void EraseZones(long coarseIndex);
  void ClearRegionClassIndexReferences(int classIndex) {
    signed char* regionClassGridFlat = &regionClassGrid[0][0];
    for (int cell = 0; cell < 15 * 27; ++cell) {
      if (regionClassGridFlat[cell] == classIndex) {
        regionClassGridFlat[cell] = -1;
      }
    }
    for (int group = 0; group < 7; ++group) {
      for (int member = 0; member < 3; ++member) {
        if (groupMemberLists[group][member] == classIndex) {
          groupMemberLists[group][member] = -1;
        }
      }
    }
  }
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

  int GetCityRegionIdAtTileIndex(int tileIndex);

  void TranslateZones(); // 0x005272c0

  // ORACLE: Mac TMapMaker::CheckProvs(). Composite map-generation rejection predicate:
  // virtual ErrorCheck, empty-column scan, then full terrain-class frontier coverage.
  // 0x00526620.
  bool CheckProvs();

  bool ValidateAllColumnsHaveAssignedRegionClass();

  bool ValidateTerrainClassAdjacencyCoverageMask();

  char ValidateSeedCandidateExistsForEachTerrainClass();

  void BuildCityRegionBorderOverlaySegments();

  void BuildOverlaySpanRecordsFromQuadBorderLinks();

  void AssignRegionIdsToUnclaimedBorderSegmentSides();

  void ReindexContiguousCityRegionIds();

  void GenerateWaterRegionIdsBySeedAndNeighborPropagation();

  // Rotates the map columns so the peak city-tile-density band is recentred. 0x00529960.
  void RotateMapColumnsByPeakWaterTileDensity();

  unsigned int RandomizeRegionTemplateBanksForMismatchedNeighborClasses(int coarseIndex,
                                                                        unsigned short baseClass,
                                                                        unsigned short class3,
                                                                        unsigned short class4,
                                                                        unsigned short class5);

  void AssignWaterRegionIdsFromOverlayScanlineIntersections();

  void MergeSmallCityRegionsAndCompactIds();

  void RebuildUMapperRouteRecordsAndActiveMapRects();

  void WriteTileGridToFile(const char* path);

  void GenerateNewMap(char* tileGrid, Province* cityTable, CString* tuningString);

  // --- data fields (raw pad except the ones the ported passes read) ---
  char pad_04[0x08 - 0x04]; // +0x04
  void CompactCityRegionIds();

  int AssignSequentialValuesToRegionPlaceholders(short* tileValues, int* nextValue);

  // ORACLE: Mac TMapMaker::ZoneCorner(long). Selects the row containing the longest
  // contiguous run of nationCode, then returns the wrap-aware average owned column in
  // that row. Returns -1 when the selected row contains no matching tile. 0x00529c80.
  int ZoneCorner(long nationCode);

  int ComputeOwnedTerritoryCentroidTile(int nationCode, char useWrapOffset);

  int RepairOrphanedTileValuesFromNeighbors(short* tileValues);

  char* mapTileGrid; // +0x08 base of the 6480-tile (108x60) grid, stride 0x24

  int CountSeaTilesInColumn(int column); // 0x00529910
  // ORACLE: IsSeaTile. The tile's terrain kind byte is water. 0x0052a600.
  bool IsSeaTile(int tileIndex);
  // Coordinate overload: the first argument is column and the second is row.
  bool IsSeaTile(int column, int row); // 0x0052a630
  // ORACLE: SetSeaZoneIndex. Stores the sea-zone ordinal into the tile's owner
  // tag byte (+0x04), biased by 0x17 -- the same bias the map-order context applies
  // when it turns an owner tag back into a context-array index. 0x0052a6b0.
  void SetSeaZoneIndex(int tileIndex, char zoneIndex);
  Province* cityScoreTable;
  // +0x10 region-class grid: 15 rows x 27 columns of region-class bytes (-1 = unassigned).
  signed char regionClassGrid[15][27];
  char pad_1a5[0x1a8 - 0x1a5]; // +0x1a5
  int groupMemberLists[7][3];
  int cityRegionNextId;
  int cityRegionIds[0x17];
  char unusedHole25c[0x29c - 0x25c];
  int lastMinorSeedCandidate;
  char pad_2a0[0x2a1 - 0x2a0]; // +0x2a0
  // +0x2a1 mode byte copied in by the BuildOrLoadGlobalMapStateForSession caller.
  unsigned char modeByte2a1;
  char pad_2a2[2];
  int cityRegionCount; // +0x2a4 number of active city regions
};

ASSERT_SIZE(TMapMaker, 0x2a8);
