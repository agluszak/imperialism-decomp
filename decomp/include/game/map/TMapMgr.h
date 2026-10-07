#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/civilian_domain_types.h"
#include "game/map_domain_types.h"
#include "game/map/map_records.h"
#include "game/mfc.h"
#include "game/unit_domain_types.h"

class TStream;
class TTown;
class TLongintList;

void ByteSwapCityScoreTableShortFields(Province* table);

void SplitTileIndexToHexRasterColumnX2AndRow(StrategicTileIndex tileIndex, short* outColX2,
                                             unsigned short* outRow);
// 0x5125a0: tileIndex -> (row = tileIndex/kStrategicMapColumns, col = tileIndex%kStrategicMapColumns).
// ABI: genuine __cdecl free function.
void SplitTileIndexToRowAndColumn(StrategicTileIndex tileIndex, short* outRow, short* outCol);
int ComputeStrategicHexTileDistance(StrategicTileIndex tileA, StrategicTileIndex tileB);

short __stdcall ResolveRiverSpriteVariantForConnectionMask(unsigned char connectionMask,
                                                           bool waterTerrain);
int TileIndexFromColumnRow(int recordBase, int recordIndex);
StrategicTileIndex TraceTerrainFlowToNearestSeaTile(StrategicTileIndex tileIndex);

extern "C" StrategicTileIndex* __cdecl BuildHexAreaTileIndexList(StrategicTileIndex centerTileIndex,
                                                                 short radius);

// Free map-coordinate helper used by legacy strategic-map callers.
StrategicTileIndex StepStrategicTileIndexAcrossWrappedRow(StrategicTileIndex tileIndex,
                                                          StrategicHexDirectionStorage direction);

bool IsValidStrategicTileIndex(short tileIndex);

// VTABLE: IMPERIALISM 0x006587e0
class TMapMgr : public TObject {
public:
  void SetMapTileStateByteAndNotifyObserver(StrategicTileIndex tileIndex,
                                            int stateByte);          // 0x515e00
  short GetProvinceUnitOrderWeight(ProvinceIndexStorage provinceId); // 0x5184e0
  DECLARE_DYNCREATE(TMapMgr)
  virtual ~TMapMgr() override;                     // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x50e7a0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x50e620
  virtual void Free() override;                    // slot 0x07 0x50e510
  virtual void InitializeMap();                    // slot 0x0a 0x50e8b0
  virtual bool GenerateMap(const char* mapStreamName,
                           char* tuningOverride);                           // slot 0x0b 0x50ec90
  virtual void LoadPoliticalMapRegionSubtypeTableFromResourceStream();      // slot 0x0c 0x50f200
  virtual void AssignPictToTile(StrategicTileIndex tileIndex);              // slot 0x0d 0x510210
  virtual void InitializeTileNeighborConnectionMaskIfNeeded(int tileIndex); // slot 0x0e 0x5107e0
  virtual void UpdateTileNeighborBorderInfluenceCounters(StrategicTileIndex tileIndex,
                                                         short mode); // slot 0x0f 0x50fe10
  virtual short
  UpdateStrategicMapTileIconVariantState(StrategicTileIndex tileIndex); // slot 0x10 0x511610
  virtual void GuaranteeResources(); // slot 0x11 0x511a70, Mac oracle

  void ReadInRGBMap(const MapPixelSourceView* source);
  virtual void PrepareMap();                              // slot 0x12 0x511e80
  virtual void ShowMap();                                 // slot 0x13 0x511ed0
  virtual void ResetAllTileMarkerSlotIndicesToSentinel(); // slot 0x14 0x5178c0
  void GenerateProvinceNames();
  virtual bool IsSameContinent(short nationA,
                               short nationB); // slot 0x15 0x511f30
  void MarkOwnedRegionClasses(TLongintList* regionList, bool* regionClassSeen);
  bool AnyOwnedRegionClassSeen(TLongintList* regionList, const bool* regionClassSeen);
  virtual bool
  IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(ProvinceIndex cityRecordIndex,
                                                       short nationTag); // slot 0x16 0x5121d0
  virtual int IsShiftKeyDown();                                          // slot 0x17 0x5122b0
  virtual int IsAltKeyDown();                                            // slot 0x18 0x5122d0
  virtual short ComputeRepresentativeTileIndexForNation(int nationSlot); // slot 0x19 0x511f10
  virtual void SetHexAdjacencyDirectionFlagsForTilePair(StrategicTileIndex sourceTile,
                                                        StrategicTileIndex destTile,
                                                        int unusedParam3); // slot 0x1a 0x513f60
  // Both lookup helpers take signed-word discriminants at the listing-proven stack boundary.
  virtual bool IsUnitPresent(StrategicTileIndex tileIndex,
                             CivilianUnitKindStorage unitKind); // slot 0x1b 0x514310
  virtual bool IsUnitPresentWithOrders(StrategicTileIndex tileIndex,
                                       CivilianUnitKindStorage unitKind,
                                       UnitOrderStorage order); // slot 0x1c 0x514360
  virtual void DimByOwner(short ownerNationTag);                // slot 0x1d 0x514e40
  virtual void SeedRecruitSearchVisitedStateFromSelectedCivilianOrder(
      class TCivUnit* unusedOrder);                 // slot 0x1e 0x514e80
  virtual void DimByValidCitySite(short nationTag); // slot 0x1f 0x514dc0
  // Resets recruitSearchVisited to 0 across all tiles and clears field9 back to idle.
  virtual void ResetRecruitSearchVisitedState();                   // slot 0x20 0x514ef0
  virtual void DimByUnitMove(class TCivUnit* pCivilianOrderEntry); // slot 0x21 0x514f20
  virtual void DimByMarching(class TMilitaryUnit* const candidates[6],
                             short orderTargetSlot);                  // slot 0x22 0x5150e0
  virtual void DimByProspecting(class TCivUnit* pCivilianOrderEntry); // slot 0x23 0x515330
  virtual void DimByDevelopment(class TCivUnit* pCivilianOrderEntry); // slot 0x24 0x515460
  virtual void DimByMining(class TCivUnit* pCivilianOrderEntry);      // slot 0x25 0x5155c0
  virtual void DimByFishing(class TCivUnit* pCivilianOrderEntry);     // slot 0x26 0x515720
  virtual void DimByCompany(class TCivUnit* pCivilianOrderEntry);     // slot 0x27 0x515890
  virtual void DimByTrackLaying(class TCivUnit* pCivilianOrderEntry); // slot 0x28 0x5159b0
  virtual void DimByEngineering(class TCivUnit* pCivilianOrderEntry); // slot 0x29 0x515b10
  virtual void UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(
      ProvinceIndex cityRecordIndex);                               // slot 0x2a 0x50fca0
  virtual void ApplyUnitMovementClassForTileIfValid(int tileIndex); // slot 0x2b 0x515d60
  void FloodContinent(int recordIndex, int classCode);
  void AssignContinents();
  void RebuildTileOwnerNeighborCachesAndFallbackAssignments();
  bool LoadScenarioMapStateFromTableResource(int scenarioIndex);

  virtual void SetRegionTileSubtypeAndRefreshNeighborFlags(ProvinceIndex cityRecordIndex,
                                                           int newTileIndex); // slot 0x2c 0x515f80
  virtual void NoOpVirtualSlot2D(int, int, int);                              // slot 0x2d 0x515de0
  virtual void ChangeProvinceOwner(ProvinceIndexStorage cityRecordIndex,
                                   short newNationTag); // slot 0x2e 0x513290
  virtual StrategicTileIndex
  FindLinkedTileForAdjacentProvince(ProvinceIndex cityRecordIndex,
                                    ProvinceIndex regionId); // slot 0x2f 0x516090
  virtual void SetCapitalCityDevelopmentStageIfValidNationSlot(int nationSlotParam,
                                                               int unused); // slot 0x30 0x516100
  virtual byte GetResourceAmtAt(StrategicTileIndex tileIndex,
                                short edgeIndex); // slot 0x31 0x513610
  virtual char GetDevelopmentLevel(StrategicTileIndex nTileIndex,
                                   bool fUseHighNibble); // slot 0x32 0x513660
  virtual void SetDevelopmentLevel(StrategicTileIndex tileIndex, bool selectHighNibble, byte value,
                                   bool markPending); // slot 0x33 0x5136a0
  virtual short GetMaxDevelopmentLevel(StrategicTileIndex tileIndex, char categoryCode,
                                       int nationSlot); // slot 0x34 0x513720
  virtual byte GetAmountOf(StrategicTileIndex tileIndex,
                           char resourceType);                // slot 0x35 0x5135a0
  virtual class TTown* GetTown(StrategicTileIndex tileIndex); // slot 0x36 0x513170
  virtual void SetOwner(short regionId, short newNationTag);  // slot 0x37 0x5133f0
  virtual short LookupTileSpriteVariantOffsetByTerrainAndGate(
      StrategicTileIndex nTileIndex); // slot 0x38 0x516150
  virtual short LookupTileSpriteVariantOffsetByAdjacencyMaskB(
      StrategicTileIndex nTileIndex); // slot 0x39 0x5161a0
  virtual short LookupTileSpriteVariantOffsetByGateAndVariant(
      StrategicTileIndex nTileIndex); // slot 0x3a 0x5161e0
  virtual short LookupTileSpriteVariantOffsetByGateAndVariantAlt(
      StrategicTileIndex nTileIndex); // slot 0x3b 0x516220
  virtual short GetCoastTileNumber(char bitmaskIndex,
                                   char direction); // slot 0x3c 0x516260
  virtual short GetCoastTileOffset(char bitmaskIndex, char direction,
                                   char useAltOffset); // slot 0x3d 0x517410
  virtual short GetDeltaTileOffset(char bitmaskIndex, char direction,
                                   short terrainPict); // slot 0x3e 0x517480
  virtual short GetWrapSeamOffset();                   // slot 0x3f 0x517520
  virtual int
  GetMapImprovementOffsetByActiveFlagsAndCityStage(StrategicTileIndex tileIndex,
                                                   short categoryCode);  // slot 0x40 0x517540
  virtual short GetTownOffset(StrategicTileIndex tileIndex, int unused); // slot 0x41 0x517600
  virtual int GetMapImprovementBitmapRowOffsetForIndex(int index);       // slot 0x42 0x5176a0
  virtual int ComputeTerrainRecordByteOffsetForIndex(int index);         // slot 0x43 0x5176c0
  virtual short GetFortFlagOffset(short nation);                         // slot 0x44 0x5176e0
  // ABI: MSVC emits overloaded virtuals in reverse declaration order.
  virtual short GetUnitOffset(class TCivUnit* unit); // slot 0x46 0x517710, Mac oracle
  virtual short GetUnitOffset(short orderType, bool military, bool idle); // slot 0x45 0x517780
  virtual int GetTinyIngotOffset(char ingotKind, int unused);             // slot 0x47 0x5177d0
  virtual short
  GetMapImprovementTileSpriteOffset(StrategicTileIndex tileIndex); // slot 0x48 0x5177f0
  // ABI: RET 8; every call site passes (tile index, owner nation tag).
  virtual int BuildRailhead(StrategicTileIndex nTileIndex, short nNationId);
  virtual void BuildPort(StrategicTileIndex nTileIndex,
                         short nNationId);                  // slot 0x4a 0x5147d0
  virtual void BuildFort(ProvinceIndexStorage nProvinceId); // slot 0x4b 0x5149d0
  virtual void FloodFillTileRegionMarker(StrategicTileIndex nTileIndex,
                                         short nOwnerNationId);                // slot 0x4c 0x5143d0
  virtual void PlaceCity(StrategicTileIndex nTileIndex, short nOwnerNationId); // slot 0x4d 0x514a20

  void RecomputeTileStrategicScoreHeatmap();

  void VerifyMapDataAndWriteReport();

  // Global map session state (g_pGlobalMapState @ 0x006A43D4). LAYOUT: TObject occupies
  // the head; four stream-read scalars fill +0x04..+0x09, terrainStateTable is +0x0c,
  // cityScoreTable is +0x10, and the complete object is 0x28 bytes.
  // Set after the strategic-map palette preview surface has been rendered; cleared by
  // construction/stream load so the map-data readiness path rebuilds it once.
  bool strategicMapPalettePreviewReady;   // +0x04
  unsigned char pad5;                     // +0x05
  short mapViewOriginTile;                // +0x06
  unsigned char mapDataReady;             // +0x08
  unsigned char recruitSearchActive;      // +0x09
  unsigned char pad0a[2];                 // +0x0a -- alignment gap before the +0x0c pointer
  TTerrainStateRecord* terrainStateTable; // +0x0c
  bool HasAdjacentProvinceOwnedByNation(int provinceIndex, int ownerNationCode);

  Province* cityScoreTable; // +0x10
  // +0x14 has no observed access in the binary.
  void* unused14;
  int cityScoreTotal;                       // +0x18
  CString scenarioTagText;                  // +0x1c
  char hexNeighborWrapHorizontally;         // +0x20
  char pad21;                               // +0x21
  StrategicTileIndex pendingRiverMouthTile; // +0x22 -- pending river-mouth tile
  bool field24;                             // +0x24 -- zeroed by the ctor; no observed reader yet

  static void GetNeighborTileIDArray(StrategicTileIndex tileIndex,
                                     StrategicTileIndex* neighborTiles,
                                     unsigned char wrapHorizontally);
  static StrategicTileIndex GetNeighborTileID(StrategicTileIndex tileIndex,
                                              StrategicHexDirectionStorage direction);
  static StrategicTileIndex GetNeighborTileID(StrategicTileIndex tileIndex,
                                              StrategicHexDirection direction) {
    return GetNeighborTileID(tileIndex, EncodeStrategicHexDirection(direction));
  }
  static StrategicHexDirectionStorage GetDirectionFrom(StrategicTileIndex sourceTile,
                                                       StrategicTileIndex destTile);
  static StrategicTileIndex
  StepHexTileIndexByDirectionWithWrapRules(StrategicTileIndex tileIndex,
                                           StrategicHexDirectionStorage direction);
  static StrategicTileIndex
  StepHexTileIndexByDirectionWithWrapRules(StrategicTileIndex tileIndex,
                                           StrategicHexDirection direction) {
    return StepHexTileIndexByDirectionWithWrapRules(tileIndex,
                                                    EncodeStrategicHexDirection(direction));
  }
  static bool StepHexRowColByDirectionWithWrapRules(int* row, int* col, int direction);
  static void AdvanceSpiralSearchStateAndStepHexCoordinates(struct HexSpiralSearchState* state);

  short ComputeRepresentativeTileIndexForNationWithWrapBias(short nationSlot, bool wrapBias);

  bool AreNationsBorderLinked(int nationA, int nationB);
  bool HasDirectOrFallbackLinkedNodeType(ProvinceIndex cityRecordIndex, int nationCode,
                                         bool allowFallback);
  int CollectSecondDegreeLinksWithMinorNationFallback(ProvinceIndex cityRecordIndex, int nationTag,
                                                      int* nodeBuffer, bool allowFallback);
  bool IsProvinceAdjacentTo(int sourceProvinceIndex, int candidateProvinceIndex);
  // ORACLE: Mac TMapMgr::HasPortInProvince(int). Returns true on the first linked tile
  // whose terrainStateTable activeFlags has the port bit (0x04) set.
  bool HasPortInProvince(int provinceIndex);
  void SetTownSize(short regionId, unsigned char stage);
  void SetTileTransportFlags(StrategicTileIndex nTileIndex, unsigned short wTileTransportFlags);
  void AddRailSegment(StrategicTileIndex sourceTile, StrategicTileIndex destTile,
                      short ownerNation);
  void ApplyEngineerRailCostDeltaForConnectedTiles(StrategicTileIndex tileA,
                                                   StrategicTileIndex tileB, short ownerNation);
  StrategicTileIndex
  FindReachableRecruitSpawnTileWithVisitedReset(StrategicTileIndex startTileIndex,
                                                bool allowActiveFlag2);
  StrategicTileIndex SearchOpenTile(StrategicTileIndex tileIndex, short ownerNationTag,
                                    bool allowActiveFlag2); // 0x00514cd0
  void GetProvinceName(int provinceIndex, CString* outName);
  void SetProvinceName(ProvinceIndex cityRecordIndex, CString* name);
  int LandPrice(StrategicTileIndex nTileIndex);

  int CollectSecondDegreeLinksMatchingNodeType(ProvinceIndex cityRecordIndex, int nationTag,
                                               int* nodeBuffer);

  void ConfirmArrows();

  int ResolveMapTileVariantSpriteFromAdjacencyState(int nTileIndex);

  bool CheckTileVariantCodeMembershipSetA(StrategicTileIndex tileIndex);
  bool CheckTileVariantCodeMembershipSetB(StrategicTileIndex tileIndex);
  bool CheckTileVariantCodeMembershipSetC(StrategicTileIndex tileIndex);
  bool CheckTileVariantCodeMembershipSetD(StrategicTileIndex tileIndex);

  byte AreMineralsPresent(StrategicTileIndex nTileIndex);
  bool CanBuildPortAtTile(StrategicTileIndex tileIndex);
  bool HasReachableSeaTileOutsideActiveType3Or4DiplomaticMask(StrategicTileIndex tileIndex);
  bool HasActiveLinkedTileWithReachableSea(int regionIndex);

  short ResolveRegionTileSubtypeCodeForTileIndex(StrategicTileIndex tileIndex);

  TCivUnit* GetFirstCivilianOrderOnTile(StrategicTileIndex tileIndex) {
    return terrainStateTable[tileIndex].firstCivilianOrder;
  }

  TCivUnit* GetMyFirstUnit(StrategicTileIndex tileIndex, short nationId);

  bool IsValidSecondaryNationHomeTileCandidate(StrategicTileIndex tileIndex);

  void ResetTileToBaseTransportFlag(StrategicTileIndex tileIndex);

  void AssignCityRecordDisplayName(ProvinceIndex cityRecordIndex, CString* dest);
  void DumpAndResetMapScriptState(); // 0x00519140

  void ApplyJoinEmpireMode0GlobalDiplomacyReset(int nationSlot);

  void ActivateMarchingArrow(int tileIndex, int contextArg, bool flag);

  short FindCountry(int tileIndex);

  int ClassifyCityGateTerrainComposition(int cityIndex);

  void ChooseNationSetupProfilesForOpenSlots(short* outProfileBySlot);

  // ORACLE: Mac TMapMgr::GetMilitaryMaster(long). Returns the province's stationed-unit
  // chain when provinceIndex is in [0, 0x180), otherwise NULL. Windows takes a short.
  // 0x004a4190, __thiscall, one stack argument.
  TMilitaryUnit* GetMilitaryMaster(short provinceIndex);

  // ORACLE: Mac TMapMgr::DimmingOff(). Clears perTileVisitedFlag for all kStrategicTileCount
  // strategic-map tiles. 0x00515db0, __thiscall, no args.
  void DimmingOff();

  void IMapMgr();

  TMapMgr();
};
ASSERT_SIZE(TMapMgr, 0x28);

Province* __stdcall GetProvinceByTileIndex(short nTileIndex);

void ByteSwapScenarioTileRecordWords(ScenarioTileDiskRecord* tileRecords);
