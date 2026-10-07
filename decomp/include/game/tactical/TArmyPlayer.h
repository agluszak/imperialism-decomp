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
  virtual ~TArmyPlayer() override {}
  virtual void StartBattle() override;
  virtual void NextMove() override;
  virtual void ApplyChanges(unsigned char sideWonFlag) override;
  virtual void RemoveCapturedUnit(TTacticalUnit* unit) override;
  virtual void AddCapturedUnit(TTacticalUnit* unit) override;
  virtual void ProceedAfterBattleIntroAccepted() override;
  virtual void AutoDeploy();
  virtual void DeploymentClick(TacticalTileIndex tileIndex);
  virtual void AutoMove();
  virtual bool SwitchToAutoPlay();

  TArmyStack* armyStack;
  float projectionMetrics[5];
  short maxUnitRange;             // +0x40 max GetUnitRange over active units
  short maxNonArtilleryUnitRange; // +0x42 same, skipping aiClass-2 units
  int lastAppliedCursorMode;      // +0x44 init -1; SelectAndApply... early-outs on equality
  // Target-selection mode: == 1 also engages morale-broken (state1c == 1) units.
  int targetingMode;
  int cachedFortBombardmentTargetTile; // +0x4c init -1; cached fort-bombardment target tile for indirect fire
  char randomParityByte50;             // +0x50 coin flip at side init (move-first side?)
  bool hasArtilleryOrSappers; // +0x51 active units only

  // NOOP: verified empty in original 0x0059b112
  TArmyPlayer() {}

  void SelectStrategy(int cursorProfileMode);
  void AssignJobs();

  void CalculateAttributes();
  void AssignDefendJobs(); // mode 0
  // Assigns state 7 to category-0 units and state 12 to every other unit.
  void AssignJobsByZeroCategory();
  void AssignBombardJobs();                        // mode 2
  void ApplyAttackerSiegeStanceByActionClass();    // mode 3
  void AssignFrontalAssaultJobs();                 // mode 4
  void ApplyAttackerStandoffStanceByActionClass(); // mode 5
  void AssignCleanUpJobs();                        // mode 6
  void AssignRetreatJobs();
  bool EnemyArtillery();

  void BuildTacticalActionPriorityBucketsWithGridGuard();
  void DispatchTacticalActionClassSelectionAcrossCursorList();
  // Prunes unitList down to the free-tile capacity.
  void SelectBestUnits(int maxUnitCount);
  // Per-class deployment tile selectors.
  int SelectTacticalTileByActionClassAdjacencyPriority();
  int SelectTacticalTileIndexByColumnPriorityVariantA();
  int SelectTacticalTileIndexByColumnPriorityVariantB();
  // Weighted tile-heuristic selectors for the auto-turn controller.
  int FindBestMove(TTacticalUnit* unit, int* heuristicWeights15);
  int SelectTarget(TTacticalUnit* unit, int flag);
  unsigned int BuildTacticalActionClassAndPositionFlags(TacticalTileIndex referenceTileIndex,
                                                        TTacticalUnit* unit);
  // Minimum GetBaseActionPoints among active units in AI states 2 or 4; 1000 if none.
  int GetMinimumActiveUnitRangeForStates2Or4();

  int FactorStayPut(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorTargetEnemy(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorSapFort(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorMeleeEnemy(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorEnemyFire(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorRetreat(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorRoughTerrain(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorNearCowards(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int ScoreTacticalTileDistanceFieldAdvance(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int ScoreTacticalTileFriendlyArtillerySpacing(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int ScoreTacticalTileArtilleryFiringLaneColumn(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorHitByArty(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorTargetMaxRange(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int FactorHitEnemyArtillery(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  int ScoreTacticalTileEnemyEdgeColumnZoneBonus(TTacticalUnit* unit, TacticalTileIndex tileIndex);

  void IArmyPlayer(TArmyStack* stack, bool isOurSide, unsigned char watchFlag, int nationIndex);
};

ASSERT_SIZE(TArmyPlayer, 0x54);
ASSERT_OFFSET(TArmyPlayer, projectionMetrics, 0x2c);
ASSERT_OFFSET(TArmyPlayer, hasArtilleryOrSappers, 0x51);

typedef int (TArmyPlayer::*TacticalTileHeuristicScorerFn)(TTacticalUnit* unit,
                                                          TacticalTileIndex tileIndex);

float __cdecl ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
    float* vector, const short* referenceProfile, int count);
