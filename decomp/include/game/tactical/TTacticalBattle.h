#pragma once

#include "game/app/TObject.h"
#include "game/ui_tags_common.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

class TArmyTacUnit;
class TList;
class TTacticalBattleView;
class TTacticalPlayer;
class TTacticalUnit;

enum TacticalBattleOutcome {
  kTacticalBattleInProgress = 0,
  kTacticalBattleSide0Victory = 1,
  kTacticalBattleSide1Victory = 2
};
typedef int TacticalBattleOutcomeStorage;

struct TacticalTileRecord {
  int terrainType; // terrain code 0..4 (indexes the move-cost table row)
  TTacticalUnit* occupant;
  int deployMark;   // 1 = trench-deploy mark; > 1 = fort-wall level
  int mineRunState; // sap/mine-run state: -1 clear, 2 queued, 0/1 advance
  unsigned char trenchMask;
  unsigned char pad11[3];
};

// VTABLE: IMPERIALISM 0x0066a088
class TTacticalBattle : public TObject {
public:
  DECLARE_DYNCREATE(TTacticalBattle)
  // FUNCTION: IMPERIALISM 0x0059f7d0
  virtual ~TTacticalBattle() override {}
  virtual void Free() override;
  virtual void CalculateMoveMap(TTacticalUnit* unit);
  virtual void CalculateDangerMap(TTacticalUnit* unit);
  // Places a unit on a battle-grid tile (deployment). Base is a no-op stub.
  virtual void DeployUnit(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  virtual void MoveAndCycle(TTacticalUnit* unit, TacticalTileIndex targetTileIndex);
  virtual bool InZOC(TacticalTileIndex tileIndex, TacticalHexDirection hexDirection, char side);
  virtual void FireAndCycle(TTacticalUnit* unit, TacticalTileIndex targetTileIndex);
  virtual void FireOn(TTacticalUnit* attackerUnit, TacticalTileIndex targetTileIndex);
  // Moves a unit's record onto the opposing side's player list (artillery capture).
  virtual void TransferTacticalUnitToOpposingSide(TTacticalUnit* unit);
  virtual void EndBattle(unsigned char sideWonFlag);
  virtual void BeginDig(TArmyTacUnit* unit, TacticalTileIndex targetTileIndex);
  virtual void ContinueDig(TArmyTacUnit* unit);
  virtual void ClearTunnel(TacticalTileIndex tileIndex);
  virtual void RallyUnit(TTacticalUnit* rallyingUnit, TArmyTacUnit* rallyTarget);
  virtual void MineWall(TTacticalUnit* unit, TacticalTileIndex tileIndex);
  virtual void DigTunnel(TTacticalUnit* unit, TacticalTileIndex tileIndex);

  TacticalTileRecord* tileGrid;    // per-tile grid, allocated by battle setup
  TTacticalBattleView* battleView; // live view; null when the battle runs headless
  int currentSide;                 // side (0/1) of the current selection; serialized
  int battleLive;                  // serialized battle-header dword
  // Side players, indexed by currentSide and TTacticalUnit::side.
  TTacticalPlayer* players[2]; // side 0, +0x18 side 1
  TTacticalUnit* selectedUnit;
  TList* recordList;
  short* tileMoveCostArray;   // per-tile move cost (-1 unreached); filled by slot 0x0a
  char* tileThreatLevelArray; // per-tile threat level; filled by slot 0x0b
  int* tileCandidateScorePlane;
  int* tileIntArray;          // advance-distance field (0x5a4460); -1 = unreached
  int battlefieldColumnCount; // playable column count of this battle
  int battleSiteIndex;        // cityScoreTable row of the battle site
  int tacticalTileCount;      // = 0x1b3 (435 = 15*29 battle tiles)
  int tacticalTileStride;
  TacticalBattleOutcomeStorage battleOutcome;
  bool pendingEndOfActionFlag;
  char fortLevel; // serialized; nonzero suppresses depl trench-marking
  unsigned char pad4a[2];
  int currentTacticalActionCode; // serialized
  int compositionClass;          // stack-composition class of the battle
  int fortStrengthPoints[8];
  int roundCounter;

  TTacticalBattle();

  void StartBattle();

  void InitTacticalBattle(TTacticalPlayer* ourPlayer, TTacticalPlayer* enemyPlayer);

  TArmyTacUnit* SeekLinkedListCursorByNestedId(int nestedId);
  void LaSelect(TTacticalUnit* unit, bool remoteFlag);
  void DispatchTacticalActionByHoverStateIndex(TacticalTileIndex tileIndex);
  void ProcessTacticalUnitState1TurnStep(TTacticalUnit* unit);
  void UndeployUnit(TacticalTileIndex tileIndex);
  void LaMove(TTacticalUnit* unit, TacticalTileIndex fromTileIndex, TacticalTileIndex toTileIndex,
              bool remoteFlag);
  void LaFireOn(TTacticalUnit* attackerUnit, TTacticalUnit* targetUnit,
                TacticalTileIndex targetTileIndex, int damageA, int damageB, char effectCode2C,
                bool remoteFlag);
  float FindMoraleBonus(unsigned char side);
  void LaMine(TacticalTileIndex tileIndex, int amount, bool remoteFlag);
  void LaDig(TTacticalUnit* unit, TacticalTileIndex targetTileIndex, bool remoteFlag);
  void LaRally(TArmyTacUnit* unit, int newMorale, int newState, bool remoteFlag);
  void LaDeploy(TArmyTacUnit* unit, TacticalTileIndex tileIndex, bool remoteFlag);
  void HandleRetreatCommand();
  void FinishedDeploying();

  void HandleTacticalBattleCommandTag(int commandTag);
  void NextMove();
  void CycleTarget();
  // Helpers the command family dispatches into (all __thiscall on the battle).
  void ApplyTacticalDoneSelectionAndRefreshUi(TTacticalUnit* unit);
  void GetNeighborList(TacticalTileIndex tileIndex, TacticalTileIndex* outNeighborTiles6);
  bool ValidMove();
  void BeginFighting();
  bool AreNeighbors(TacticalTileIndex tileIndex, TacticalTileIndex candidateTileIndex);
  void DamageFort(TacticalTileIndex tileIndex, int consumeAmount);
  void CheckForVictory();
  void FinishedMove();
  void Cycle();
  // Paths the unit toward the target tile.
  void MoveTacticalUnitTowardTile(TTacticalUnit* unit, TacticalTileIndex targetTileIndex);
  bool ValidTargets();
  TacticalTileIndex FindFortWallTileCrossedByFiringLine(TacticalTileIndex targetTileIndex,
                                                        TacticalTileIndex attackerTileIndex);
  int SeekPath(TacticalTileIndex walkTileIndex, int pathDepth, TacticalTileIndex goalTileIndex,
               TacticalTileIndex* outPathTiles);
  // Reaction checks fired when a unit enters a tile; nonzero stops the walk.
  bool CheckOpportunityFire(TacticalTileIndex tileIndex);
  unsigned char IsTacticalTargetTileReachableForAction(TacticalTileIndex attackerTileIndex,
                                                       TacticalTileIndex targetTileIndex,
                                                       char directFireFlag, int range);
  unsigned char CanFireOn(TTacticalUnit* unit, TacticalTileIndex targetTileIndex);
  int GetTileCursor(TacticalTileIndex tileIndex);
  short ResolveTacticalHoverCursorResourceId(TacticalTileIndex tileIndex);
  void MakeRetreatMap(char ourSideFlag);
  bool IsTacticalTileAtFortWallSectionSlot(TacticalTileIndex tileIndex);
  // Deployment-zone queries.
  int CountDeploymentTiles();
  bool ApplyGridColumnSelectionGuard(TacticalTileIndex tileIndex);
  // True when there is no fort or a wall section is breached.
  bool IsFortBreachedOrMissing();
  bool HasFortWallGarrison(TacticalTileIndex tileIndex);
};

ASSERT_SIZE(TTacticalBattle, 0x78);
ASSERT_OFFSET(TTacticalBattle, players, 0x14);
ASSERT_OFFSET(TTacticalBattle, selectedUnit, 0x1c);

short __cdecl CompareTacticalUnitsForTurnOrder(void* a, void* b, void* context);
