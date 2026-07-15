#pragma once

#include "game/TTacticalPlayer.h"
#include "game/mfc.h"

class TArmyStack;
class TTacticalUnit;

// VTABLE: IMPERIALISM 0x006695f0
class TArmyPlayer : public TTacticalPlayer {
public:
  // === BEGIN GENERATED DECLS (TArmyPlayer) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TArmyPlayer)
  virtual ~TArmyPlayer() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59aee0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void StartBattle() override;              // slot 0x0a 0x59b830
  virtual void AdvanceTacticalTurnPulse() override; // slot 0x0b 0x59e3e0
  // slot 0x0c NoOpTacticalPlayerHook0C inherited unchanged (0x59adb0)
  virtual void CommitTacticalResultsToSourceUnits(int unused) override;      // slot 0x0d 0x59b3e0
  virtual void RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) override; // slot 0x0e 0x59b4f0
  virtual void AddTacticalUnitToUnitListHead(TTacticalUnit* unit) override;  // slot 0x0f 0x59b540
  // slot 0x10 AlwaysTrueTacticalPredicate10 inherited unchanged (0x59adf0)
  virtual void ProceedAfterBattleIntroAccepted() override;   // slot 0x11 0x59eb40
  virtual void AutoDeploySideUnitsAndMarkReady();            // slot 0x12 0x59bc80
  virtual undefined TArmyTacUnit_VtblSlot07();               // slot 0x13 0x59c3c0
  virtual void RunTacticalAutoTurnControllerForActiveUnit(); // slot 0x14 0x59e4f0
  virtual undefined TArmyTacUnit_VtblSlot09();               // slot 0x15 0x59ea60
  // === END GENERATED DECLS (TArmyPlayer) ===

  // Partial slice (object is 0x54): only the side's combatant stack is recovered so
  // far; stored by InitializeTacticalSideFromArmyUnitList and read back by
  // TArmyBattle::WriteTo.
  TArmyStack* armyStack28; // +0x28
  // Aggregated projection metrics for the side, rebuilt by
  // AccumulateTacticalProjectionMetricsAndUnitRanges (0x59b5b0) from the active
  // records' float vectors.
  float projectionScoreSums2C[5];   // +0x2c
  short maxUnitRange40;             // +0x40 max GetUnitRange over active units
  short maxNonArtilleryUnitRange42; // +0x42 same, skipping aiClass-2 units
  int lastAppliedCursorMode44;      // +0x44 init -1; SelectAndApply... early-outs on equality
  // Target-selection mode: == 1 also engages morale-broken (state1c == 1) units.
  int field48;             // +0x48
  int field4C;             // +0x4c init -1; cached fort-bombardment target tile for indirect fire
  char randomParityByte50; // +0x50 coin flip at side init (move-first side?)
  char field51;            // +0x51 init 0
  unsigned char pad52[2];  // +0x52

  // Both original construction sites (0x5a4790, 0x5a4990) inline the ctor as a bare
  // vptr store.
  TArmyPlayer() {}

  // Applies the tactical cursor/UI mode profile for this side.
  // 0x0059c440, __thiscall, ret 4.
  void SelectAndApplyTacticalCursorModeProfile(int cursorProfileMode);

  // Rebuilds projectionScoreSums2C/maxUnitRange40/42 and field51 (active artillery or
  // sapper present) from the active records, then folds sums[0]/sums[1] into
  // distribution-similarity scores vs the 0x697870 reference profiles. 0x59b5b0.
  void AccumulateTacticalProjectionMetricsAndUnitRanges();
  // Per-mode stance-profile appliers: set each record's aiStateCode2c by action class
  // for the matching cursor mode (mode number noted per address).
  void SetAllUnitAiStateCodesTo13();               // 0x59ca32
  void ApplyDefenderHoldLineStanceByActionClass(); // mode 0, 0x59caf0
  void ApplyDefenderBombardStanceByActionClass();  // mode 2, 0x59cd00
  void ApplyAttackerSiegeStanceByActionClass();    // mode 3, 0x59ce90
  void ApplyAttackerAssaultStanceByActionClass();  // mode 4, 0x59d020
  void ApplyAttackerStandoffStanceByActionClass(); // mode 5, 0x59d1a0
  void ApplyUnopposedAdvanceStanceByActionClass(); // mode 6, 0x59d320
  // Whether the opposing side has a deployed, still-active artillery-class unit.
  // 0x0059d470, __thiscall.
  unsigned char OpponentHasDeployedActiveArtilleryUnit();

  // Auto-deploy helpers (0x59bc80 dispatcher). Curated names kept; behaviorally these
  // are the zone-score-table and per-class-tile-selector deploy strategies.
  void BuildTacticalActionPriorityBucketsWithGridGuard();      // 0x59bcf0
  void DispatchTacticalActionClassSelectionAcrossCursorList(); // 0x59bf20
  // Prunes unitList4 down to the free-tile capacity. 0x59b990.
  void RecomputeTacticalCursorProjectionScoresAndPruneList(int maxUnitCount);
  // Per-class deployment tile selectors.
  int SelectTacticalTileByActionClassAdjacencyPriority(); // 0x59c140
  int SelectTacticalTileIndexByColumnPriorityVariantA();  // 0x59bfe0
  int SelectTacticalTileIndexByColumnPriorityVariantB();  // 0x59c2a0
  // Weighted tile-heuristic selectors for the auto-turn controller.
  int SelectBestTacticalTileByWeightedHeuristics(TTacticalUnit* unit,
                                                 int* heuristicWeights15); // 0x59d530
  int SelectBestTacticalTargetTileByActionHeuristics(TTacticalUnit* unit,
                                                     int flag); // 0x59e110

  // The fifteen per-tile heuristic scorers driven (via the 0x6994c0 member-function-
  // pointer table) by SelectBestTacticalTileByWeightedHeuristics; entry i pairs with
  // weight column i of g_anTacticalTileHeuristicWeightsByAiState_00699500.
  int ScoreTacticalTileHoldPositionBonus(TTacticalUnit* unit, int tileIndex); // 0x59d6b0
  int ScoreTacticalTileFireOpportunityAndTargetApproach(TTacticalUnit* unit,
                                                        int tileIndex);              // 0x59d6e0
  int ScoreTacticalTileSapperWallApproachColumn(TTacticalUnit* unit, int tileIndex); // 0x59d810
  int ScoreTacticalTileAdjacentEnemyContact(TTacticalUnit* unit, int tileIndex);     // 0x59d8a0
  int ScoreTacticalTileEnemyEngagementExposureCount(TTacticalUnit* unit,
                                                    int tileIndex);                  // 0x59d940
  int ScoreTacticalTileRetreatEdgeRowProximity(TTacticalUnit* unit, int tileIndex);  // 0x59da20
  int ScoreTacticalTileCoverTerrainBonus(TTacticalUnit* unit, int tileIndex);        // 0x59dac0
  int ScoreTacticalTileAdjacentRallyTargetBonus(TTacticalUnit* unit, int tileIndex); // 0x59db00
  int ScoreTacticalTileDistanceFieldAdvance(TTacticalUnit* unit, int tileIndex);     // 0x59dba0
  int ScoreTacticalTileFriendlyArtillerySpacing(TTacticalUnit* unit, int tileIndex); // 0x59dbe0
  int ScoreTacticalTileArtilleryFiringLaneColumn(TTacticalUnit* unit,
                                                 int tileIndex); // 0x59dcd0
  int ScoreTacticalTileEnemyArtilleryExposureCount(TTacticalUnit* unit,
                                                   int tileIndex);                   // 0x59dd40
  int ScoreTacticalTileEngageableEnemyStandoff(TTacticalUnit* unit, int tileIndex);  // 0x59de30
  int ScoreTacticalTileEnemyArtilleryHuntBonus(TTacticalUnit* unit, int tileIndex);  // 0x59dfe0
  int ScoreTacticalTileEnemyEdgeColumnZoneBonus(TTacticalUnit* unit, int tileIndex); // 0x59e0d0

  // Builds the side's tactical unit records from the stack's army unit chain and
  // stores the stack into armyStack28. 0x0059b1b0, __thiscall, ret 0x10.
  void InitializeTacticalSideFromArmyUnitList(TArmyStack* stack, int isOurSide, char watchFlag,
                                              int nationIndex);
};

ASSERT_SIZE(TArmyPlayer, 0x54);

// The per-tile heuristic scorer table type (0x6994c0, declared in
// global_data_tables.h): entry i pairs with weight column i of
// g_anTacticalTileHeuristicWeightsByAiState_00699500.
typedef int (TArmyPlayer::*TacticalTileHeuristicScorerFn)(TTacticalUnit* unit, int tileIndex);

// Distribution-similarity score between a five-component vector and a reference
// profile row (movsx short reads). Owned alongside its only tactical
// caller. 0x005362c0, __cdecl.
float __cdecl ComputeDistributionSimilarityScoreFromVectorAndReferenceProfile(
    float* vector, unsigned short* referenceProfile, int count);
