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
// ABI: __cdecl free function.
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
  void SetMapTileStateByteAndNotifyObserver(StrategicTileIndex tileIndex, int stateByte);
  short GetProvinceUnitOrderWeight(ProvinceIndexStorage provinceId);
  DECLARE_DYNCREATE(TMapMgr)
  virtual ~TMapMgr() override;
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void Free() override;
  virtual void InitializeMap();
  virtual bool GenerateMap(const char* mapStreamName, char* tuningOverride);
  virtual void LoadPoliticalMapRegionSubtypeTableFromResourceStream();
  virtual void AssignPictToTile(StrategicTileIndex tileIndex);
  virtual void InitializeTileNeighborConnectionMaskIfNeeded(int tileIndex);
  virtual void UpdateTileNeighborBorderInfluenceCounters(StrategicTileIndex tileIndex, short mode);
  virtual short UpdateStrategicMapTileIconVariantState(StrategicTileIndex tileIndex);
  virtual void GuaranteeResources();

  void ReadInRGBMap(const MapPixelSourceView* source);
  virtual void PrepareMap();
  virtual void ShowMap();
  virtual void ResetAllTileMarkerSlotIndicesToSentinel();
  void GenerateProvinceNames();
  virtual bool IsSameContinent(short nationA, short nationB);
  void MarkOwnedRegionClasses(TLongintList* regionList, bool* regionClassSeen);
  bool AnyOwnedRegionClassSeen(TLongintList* regionList, const bool* regionClassSeen);
  virtual bool IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(ProvinceIndex cityRecordIndex,
                                                                    short nationTag);
  virtual int IsShiftKeyDown();
  virtual int IsAltKeyDown();
  virtual short ComputeRepresentativeTileIndexForNation(int nationSlot);
  virtual void SetHexAdjacencyDirectionFlagsForTilePair(StrategicTileIndex sourceTile,
                                                        StrategicTileIndex destTile,
                                                        int unusedParam3);
  // Both lookup helpers take signed-word discriminants at the listing-proven stack boundary.
  virtual bool IsUnitPresent(StrategicTileIndex tileIndex, CivilianUnitKindStorage unitKind);
  virtual bool IsUnitPresentWithOrders(StrategicTileIndex tileIndex,
                                       CivilianUnitKindStorage unitKind, UnitOrderStorage order);
  virtual void DimByOwner(short ownerNationTag);
  virtual void SeedRecruitSearchVisitedStateFromSelectedCivilianOrder(class TCivUnit* unusedOrder);
  virtual void DimByValidCitySite(short nationTag);
  // Resets recruitSearchVisited to 0 across all tiles and clears field9 back to idle.
  virtual void ResetRecruitSearchVisitedState();
  virtual void DimByUnitMove(class TCivUnit* pCivilianOrderEntry);
  virtual void DimByMarching(class TMilitaryUnit* const candidates[6], short orderTargetSlot);
  virtual void DimByProspecting(class TCivUnit* pCivilianOrderEntry);
  virtual void DimByDevelopment(class TCivUnit* pCivilianOrderEntry);
  virtual void DimByMining(class TCivUnit* pCivilianOrderEntry);
  virtual void DimByFishing(class TCivUnit* pCivilianOrderEntry);
  virtual void DimByCompany(class TCivUnit* pCivilianOrderEntry);
  virtual void DimByTrackLaying(class TCivUnit* pCivilianOrderEntry);
  virtual void DimByEngineering(class TCivUnit* pCivilianOrderEntry);
  virtual void UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(ProvinceIndex cityRecordIndex);
  virtual void ApplyUnitMovementClassForTileIfValid(int tileIndex);
  void FloodContinent(int recordIndex, int classCode);
  void AssignContinents();
  void RebuildTileOwnerNeighborCachesAndFallbackAssignments();
  bool LoadScenarioMapStateFromTableResource(int scenarioIndex);

  virtual void SetRegionTileSubtypeAndRefreshNeighborFlags(ProvinceIndex cityRecordIndex,
                                                           int newTileIndex);
  virtual void NoOpVirtualSlot2D(int, int, int);
  virtual void ChangeProvinceOwner(ProvinceIndexStorage cityRecordIndex, short newNationTag);
  virtual StrategicTileIndex FindLinkedTileForAdjacentProvince(ProvinceIndex cityRecordIndex,
                                                               ProvinceIndex regionId);
  virtual void SetCapitalCityDevelopmentStageIfValidNationSlot(int nationSlotParam, int unused);
  virtual byte GetResourceAmtAt(StrategicTileIndex tileIndex, short edgeIndex);
  virtual char GetDevelopmentLevel(StrategicTileIndex nTileIndex, bool fUseHighNibble);
  virtual void SetDevelopmentLevel(StrategicTileIndex tileIndex, bool selectHighNibble, byte value,
                                   bool markPending);
  virtual short GetMaxDevelopmentLevel(StrategicTileIndex tileIndex, char categoryCode,
                                       int nationSlot);
  virtual byte GetAmountOf(StrategicTileIndex tileIndex, char resourceType);
  virtual class TTown* GetTown(StrategicTileIndex tileIndex);
  virtual void SetOwner(short regionId, short newNationTag);
  virtual short LookupTileSpriteVariantOffsetByTerrainAndGate(StrategicTileIndex nTileIndex);
  virtual short LookupTileSpriteVariantOffsetByAdjacencyMaskB(StrategicTileIndex nTileIndex);
  virtual short LookupTileSpriteVariantOffsetByGateAndVariant(StrategicTileIndex nTileIndex);
  virtual short LookupTileSpriteVariantOffsetByGateAndVariantAlt(StrategicTileIndex nTileIndex);
  virtual short GetCoastTileNumber(char bitmaskIndex, char direction);
  virtual short GetCoastTileOffset(char bitmaskIndex, char direction, char useAltOffset);
  virtual short GetDeltaTileOffset(char bitmaskIndex, char direction, short terrainPict);
  virtual short GetWrapSeamOffset();
  virtual int GetMapImprovementOffsetByActiveFlagsAndCityStage(StrategicTileIndex tileIndex,
                                                               short categoryCode);
  virtual short GetTownOffset(StrategicTileIndex tileIndex, int unused);
  virtual int GetMapImprovementBitmapRowOffsetForIndex(int index);
  virtual int ComputeTerrainRecordByteOffsetForIndex(int index);
  virtual short GetFortFlagOffset(short nation);
  // ABI: MSVC emits overloaded virtuals in reverse declaration order.
  virtual short GetUnitOffset(class TCivUnit* unit);
  virtual short GetUnitOffset(short orderType, bool military, bool idle);
  virtual int GetTinyIngotOffset(char ingotKind, int unused);
  virtual short GetMapImprovementTileSpriteOffset(StrategicTileIndex tileIndex);
  // ABI: RET 8; every call site passes (tile index, owner nation tag).
  virtual int BuildRailhead(StrategicTileIndex nTileIndex, short nNationId);
  virtual void BuildPort(StrategicTileIndex nTileIndex, short nNationId);
  virtual void BuildFort(ProvinceIndexStorage nProvinceId);
  virtual void FloodFillTileRegionMarker(StrategicTileIndex nTileIndex, short nOwnerNationId);
  virtual void PlaceCity(StrategicTileIndex nTileIndex, short nOwnerNationId);

  void RecomputeTileStrategicScoreHeatmap();

  void VerifyMapDataAndWriteReport();

  // LAYOUT: 0x28 bytes; terrainStateTable at +0x0c, cityScoreTable at +0x10.
  // Set once the palette preview is rendered; cleared on construction and load.
  bool strategicMapPalettePreviewReady;
  short mapViewOriginTile;
  unsigned char mapDataReady;
  unsigned char recruitSearchActive;
  unsigned char pad0a[2]; // alignment gap before the +0x0c pointer
  TTerrainStateRecord* terrainStateTable;
  bool HasAdjacentProvinceOwnedByNation(int provinceIndex, int ownerNationCode);

  Province* cityScoreTable;
  // +0x14 has no observed access in the binary.
  void* unused14;
  int cityScoreTotal;
  CString scenarioTagText;
  char hexNeighborWrapHorizontally;
  char pad21;
  StrategicTileIndex pendingRiverMouthTile; // pending river-mouth tile
  bool field24;                             // zeroed by the ctor; no observed reader yet

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
                                    bool allowActiveFlag2);
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
  void DumpAndResetMapScriptState();

  void ApplyJoinEmpireMode0GlobalDiplomacyReset(int nationSlot);

  void ActivateMarchingArrow(int tileIndex, int contextArg, bool flag);

  short FindCountry(int tileIndex);

  int ClassifyCityGateTerrainComposition(int cityIndex);

  void ChooseNationSetupProfilesForOpenSlots(short* outProfileBySlot);

  // ORACLE: Mac TMapMgr::GetMilitaryMaster(long); Windows takes a short.
  TMilitaryUnit* GetMilitaryMaster(short provinceIndex);

  void DimmingOff();

  void IMapMgr();

  TMapMgr();
};
ASSERT_SIZE(TMapMgr, 0x28);

Province* __stdcall GetProvinceByTileIndex(short nTileIndex);

void ByteSwapScenarioTileRecordWords(ScenarioTileDiskRecord* tileRecords);
