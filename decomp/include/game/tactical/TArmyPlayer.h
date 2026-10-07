#pragma once

#include "game/map/TTacticalPlayer.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

class TArmyStack;
class TTacticalUnit;

// VTABLE: IMPERIALISM 0x006695f0
class TArmyPlayer : public TTacticalPlayer {
public:
  DECLARE_DYNCREATE(TArmyPlayer)
  // NOOP: verified empty in original 0x0059b170
  virtual ~TArmyPlayer() override {}   // slot 0x01 (scalar deleting destructor)
  virtual void StartBattle() override; // slot 0x0a 0x59b830
  virtual void NextMove() override;    // slot 0x0b 0x59e3e0
  virtual void ApplyChanges(unsigned char sideWonFlag) override;             // slot 0x0d 0x59b3e0
  virtual void RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) override; // slot 0x0e 0x59b4f0
  virtual void AddTacticalUnitToUnitListHead(TTacticalUnit* unit) override;  // slot 0x0f 0x59b540
  virtual void ProceedAfterBattleIntroAccepted() override;                   // slot 0x11 0x59eb40
  virtual void AutoDeploySideUnitsAndMarkReady();                            // slot 0x12 0x59bc80
  virtual void DeploymentClick(TacticalTileIndex tileIndex);                 // slot 0x13 0x59c3c0
  virtual void RunTacticalAutoTurnControllerForActiveUnit();                 // slot 0x14 0x59e4f0
  virtual bool SwitchToAutoPlay();                                           // slot 0x15 0x59ea60

  TArmyStack* armyStack;          // +0x28
  float projectionMetrics[5];     // +0x2c
  short maxUnitRange;             // +0x40 max GetUnitRange over active units
  short maxNonArtilleryUnitRange; // +0x42 same, skipping aiClass-2 units
  int lastAppliedCursorMode;      // +0x44 init -1; SelectAndApply... early-outs on equality
  // Target-selection mode: == 1 also engages morale-broken (state1c == 1) units.
  int targetingMode;                   // +0x48
  int cachedFortBombardmentTargetTile; // +0x4c init -1; cached fort-bombardment target tile for indirect fire
  char randomParityByte50;             // +0x50 coin flip at side init (move-first side?)
  bool hasArtilleryOrSappers; // +0x51 active units only
  unsigned char pad52[2];     // +0x52

  // NOOP: verified empty in original 0x0059b112
  TArmyPlayer() {}

  void SelectAndApplyTacticalCursorModeProfile(int cursorProfileMode);
  void ApplyTacticalStanceProfileForCurrentCursorMode();

  void AccumulateTacticalProjectionMetricsAndUnitRanges();
  void ApplyDefenderHoldLineStanceByActionClass(); // mode 0, 0x59caf0
  // Assigns state 7 to category-0 units and state 12 to every other unit.
  void AssignJobsByZeroCategory();                 // 0x59cc70
  void ApplyDefenderBombardStanceByActionClass();  // mode 2, 0x59cd00
  void ApplyAttackerSiegeStanceByActionClass();    // mode 3, 0x59ce90
  void ApplyAttackerAssaultStanceByActionClass();  // mode 4, 0x59d020
  void ApplyAttackerStandoffStanceByActionClass(); // mode 5, 0x59d1a0
  void ApplyUnopposedAdvanceStanceByActionClass(); // mode 6, 0x59d320
  void SetAllUnitAiStateCodesTo13();
  bool OpponentHasDeployedActiveArtilleryUnit();

  void BuildTacticalActionPriorityBucketsWithGridGuard();      // 0x59bcf0
  void DispatchTacticalActionClassSelectionAcrossCursorList(); // 0x59bf20
  // Prunes unitList down to the free-tile capacity. 0x59b990.
  void RecomputeTacticalCursorProjectionScoresAndPruneList(int maxUnitCount);
  // Per-class deployment tile selectors.
  int SelectTacticalTileByActionClassAdjacencyPriority(); // 0x59c140
  int SelectTacticalTileIndexByColumnPriorityVariantA();  // 0x59bfe0
  int SelectTacticalTileIndexByColumnPriorityVariantB();  // 0x59c2a0
  // Weighted tile-heuristic selectors for the auto-turn controller.
  int FindBestMove(TTacticalUnit* unit,
                   int* heuristicWeights15); // 0x59d530
  int SelectBestTacticalTargetTileByActionHeuristics(TTacticalUnit* unit,
                                                     int flag); // 0x59e110
  unsigned int BuildTacticalActionClassAndPositionFlags(TacticalTileIndex referenceTileIndex,
                                                        TTacticalUnit* unit); // 0x59e8a0
  // Minimum GetBaseActionPoints among active units in AI states 2 or 4; 1000 if none.
  int GetMinimumActiveUnitRangeForStates2Or4(); // 0x59e9c0

  int ScoreTacticalTileHoldPositionBonus(TTacticalUnit* unit,
                                         TacticalTileIndex tileIndex); // 0x59d6b0
  int ScoreTacticalTileFireOpportunityAndTargetApproach(TTacticalUnit* unit,
                                                        TacticalTileIndex tileIndex); // 0x59d6e0
  int ScoreTacticalTileSapperWallApproachColumn(TTacticalUnit* unit,
                                                TacticalTileIndex tileIndex); // 0x59d810
  int ScoreTacticalTileAdjacentEnemyContact(TTacticalUnit* unit,
                                            TacticalTileIndex tileIndex); // 0x59d8a0
  int ScoreTacticalTileEnemyEngagementExposureCount(TTacticalUnit* unit,
                                                    TacticalTileIndex tileIndex); // 0x59d940
  int ScoreTacticalTileRetreatEdgeRowProximity(TTacticalUnit* unit,
                                               TacticalTileIndex tileIndex); // 0x59da20
  int ScoreTacticalTileCoverTerrainBonus(TTacticalUnit* unit,
                                         TacticalTileIndex tileIndex); // 0x59dac0
  int ScoreTacticalTileAdjacentRallyTargetBonus(TTacticalUnit* unit,
                                                TacticalTileIndex tileIndex); // 0x59db00
  int ScoreTacticalTileDistanceFieldAdvance(TTacticalUnit* unit,
                                            TacticalTileIndex tileIndex); // 0x59dba0
  int ScoreTacticalTileFriendlyArtillerySpacing(TTacticalUnit* unit,
                                                TacticalTileIndex tileIndex); // 0x59dbe0
  int ScoreTacticalTileArtilleryFiringLaneColumn(TTacticalUnit* unit,
                                                 TacticalTileIndex tileIndex); // 0x59dcd0
  int ScoreTacticalTileEnemyArtilleryExposureCount(TTacticalUnit* unit,
                                                   TacticalTileIndex tileIndex); // 0x59dd40
  int ScoreTacticalTileEngageableEnemyStandoff(TTacticalUnit* unit,
                                               TacticalTileIndex tileIndex); // 0x59de30
  int ScoreTacticalTileEnemyArtilleryHuntBonus(TTacticalUnit* unit,
                                               TacticalTileIndex tileIndex); // 0x59dfe0
  int ScoreTacticalTileEnemyEdgeColumnZoneBonus(TTacticalUnit* unit,
                                                TacticalTileIndex tileIndex); // 0x59e0d0

  void IArmyPlayer(TArmyStack* stack, bool isOurSide, unsigned char watchFlag, int nationIndex);
};

ASSERT_SIZE(TArmyPlayer, 0x54);
ASSERT_OFFSET(TArmyPlayer, projectionMetrics, 0x2c);
ASSERT_OFFSET(TArmyPlayer, hasArtilleryOrSappers, 0x51);

typedef int (TArmyPlayer::*TacticalTileHeuristicScorerFn)(TTacticalUnit* unit,
                                                          TacticalTileIndex tileIndex);

float __cdecl ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
    float* vector, const short* referenceProfile, int count);
