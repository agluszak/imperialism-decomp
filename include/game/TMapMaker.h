#pragma once

#include "game/TObject.h"
#include "game/TEventHandler.h"
#include "game/TView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006598f8
class TMapMaker : public TObject {
  DECLARE_DYNAMIC(TMapMaker)
public:
  TMapMaker();
  virtual ~TMapMaker() override;

  virtual char GetBoolSlot28();                                  // slot 10 / 0x28
  virtual void SetControlValue(int value);                       // slot 11 / 0x2c
  virtual TEventHandler* QueryStepValue();                       // slot 12 / 0x30
  virtual void DispatchQueuedUiCommandAndRelease(void* payload); // slot 13 / 0x34
  virtual void DispatchUiSelectionToHandler(void* payload);      // slot 14 / 0x38
  virtual void HandleEvent(int commandId, TEventHandler* sourceHandler,
                           TEvent* event); // slot 15 / 0x3c
  virtual void DispatchEvent(int commandId, TEventHandler* sourceHandler,
                             TEvent* event);                              // slot 16 / 0x40
  virtual void vmethod_0017(int param);                                   // slot 17 / 0x44
  virtual void ForwardParam(int param);                                   // slot 18 / 0x48
  virtual char DoIdle(int action);                // slot 19 / 0x4c
  virtual int GetCityDialogValueDword10();                                // slot 20 / 0x50
  virtual void SetCityDialogValueDword10(int value);                      // slot 21 / 0x54
  virtual TView* OwnerPanel();                                            // slot 22 / 0x58
  virtual char vmethod_0023();                                            // slot 23 / 0x5c
  virtual char vmethod_0024();                                            // slot 24 / 0x60
  virtual void vmethod_0025();                                            // slot 25 / 0x64
  virtual void vmethod_0026(int gate);                                    // slot 26 / 0x68
  virtual void HandleCityProductionNoOp();                                // slot 27 / 0x6c
  virtual void DispatchUiCommand19ToParent();                             // slot 28 / 0x70
  virtual void DispatchCityProductionAction1A();                          // slot 29 / 0x74
  virtual void DispatchCityProductionAction1B();                          // slot 30 / 0x78
  virtual char ActivateCityProductionViewIfAllowed();                     // slot 31 / 0x7c
  virtual char vmethod_0080();                                            // slot 32 / 0x80
  virtual int GetFineGridCellBasePointerFromCoarseIndex(int coarseIndex); // slot 33 / 0x84

  // TMapMaker's real vtable (0x006598f8) ends at its last reachable slot (0x21 /
  // vmethod_0081 above); slots 0x22..0x28 are a literal NULL tail (matching the
  // TZone::vtable convention, see TZone.h). The two non-NULL pointers the extractor lists
  // beyond that run (slots 0x29/0x2a → 0x0052a760/0x0052c0a0) are NOT TMapMaker methods:
  // they are the single vtable slots of two adjacent stretch<T> tables laid out right after
  // TMapMaker's vtable (SeaSegmentStretch @ 0x0065999c, SeapointStretch @ 0x006599a0). Those
  // append virtuals are owned in sea_geometry.cpp; see sea_geometry.h.

  // City-region id (tile[4] - 0x17) at a tile index, or -1 if the tile is out of range or
  // not a city-region tile (tile[0] != 5). 0x0052a670.
  int GetCityRegionIdAtTileIndex(int tileIndex);

  // Scans every tile's hex neighbours and emits a Seapoint into the overlay-quad table for
  // each city-region border edge (single edges + 3-region triple junctions). 0x0052c1a0.
  void BuildCityRegionBorderOverlaySegments();

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

  // --- data fields (raw pad except the two the region-merge pass reads) ---
  char pad_04[0x08 - 0x04];  // +0x04
  char* mapTileGrid08;       // +0x08 base of the 6480-tile (108x60) grid, stride 0x24
  char pad_0c[0x2a4 - 0x0c]; // +0x0c
  int cityRegionCount2a4;    // +0x2a4 number of active city regions
};

ASSERT_SIZE(TMapMaker, 0x2a8);

