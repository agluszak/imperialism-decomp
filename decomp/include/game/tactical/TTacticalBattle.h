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
  int terrainType;          // +0x00 terrain code 0..4 (indexes the move-cost table row)
  TTacticalUnit* occupant;  // +0x04
  int deployMark;           // +0x08 1 = trench-deploy mark; > 1 = fort-wall level
  int mineRunState;         // +0x0c sap/mine-run state: -1 clear, 2 queued, 0/1 advance
  unsigned char trenchMask; // +0x10
  unsigned char pad11[3];   // +0x11
};

// VTABLE: IMPERIALISM 0x0066a088
class TTacticalBattle : public TObject {
public:
  DECLARE_DYNCREATE(TTacticalBattle)
  // FUNCTION: IMPERIALISM 0x0059f7d0
  virtual ~TTacticalBattle() override {}                // slot 0x01 (scalar deleting destructor)
  virtual void Free() override;                         // slot 0x07 0x59fb50
  virtual void CalculateMoveMap(TTacticalUnit* unit);   // slot 0x0a 0x59ff20
  virtual void CalculateDangerMap(TTacticalUnit* unit); // slot 0x0b 0x5a02e0
  // Places a unit on a battle-grid tile (deployment). Base is a no-op stub.
  virtual void DeployUnit(TTacticalUnit* unit,
                          TacticalTileIndex tileIndex); // slot 0x0c 0x59f710
  virtual void MoveAndCycle(TTacticalUnit* unit,
                            TacticalTileIndex targetTileIndex); // slot 0x0d 0x5a1bd0
  virtual bool InZOC(TacticalTileIndex tileIndex, TacticalHexDirection hexDirection,
                     char side); // slot 0x0e 0x5a1400
  virtual void FireAndCycle(TTacticalUnit* unit,
                            TacticalTileIndex targetTileIndex); // slot 0x0f 0x5a1ca0
  virtual void FireOn(TTacticalUnit* attackerUnit,
                      TacticalTileIndex targetTileIndex); // slot 0x10 0x5a1ee0
  // Moves a unit's record onto the opposing side's player list (artillery capture).
  virtual void TransferTacticalUnitToOpposingSide(TTacticalUnit* unit); // slot 0x11 0x5a2700
  virtual void EndBattle(unsigned char sideWonFlag); // slot 0x12 0x59f730, Mac oracle
  virtual void BeginDig(TArmyTacUnit* unit,
                        TacticalTileIndex targetTileIndex); // slot 0x13 0x5a3190
  virtual void ContinueDig(TArmyTacUnit* unit);             // slot 0x14 0x5a3210
  virtual void ClearTunnel(TacticalTileIndex tileIndex);    // slot 0x15 0x5a3320
  virtual void RallyUnit(TTacticalUnit* rallyingUnit,
                         TArmyTacUnit* rallyTarget); // slot 0x16 0x5a3810
  virtual void MineWall(TTacticalUnit* unit,
                        TacticalTileIndex tileIndex); // slot 0x17 0x5a34d0
  virtual void DigTunnel(TTacticalUnit* unit,
                         TacticalTileIndex tileIndex); // slot 0x18 0x5a3640

  TacticalTileRecord* tileGrid;    // +0x04 per-tile grid, allocated by battle setup (0x59f890)
  TTacticalBattleView* battleView; // +0x08 live view; null when the battle runs headless
  int currentSide;                 // +0x0c side (0/1) of the current selection; serialized
  int battleLive;                  // +0x10 serialized battle-header dword
  // Owned side players, indexed by currentSide and TTacticalUnit::side.
  // ABI: SetTargeting (0x5a5b90) indexes pointers at +0x14 with a four-byte stride;
  // Free (0x59fb50) releases side 0 before side 1.
  TTacticalPlayer* players[2]; // +0x14 side 0, +0x18 side 1
  TTacticalUnit* selectedUnit; // +0x1c
  TList* recordList;           // +0x20
  short* tileMoveCostArray;    // +0x24 per-tile move cost (-1 unreached); filled by slot 0x0a
  char* tileThreatLevelArray;  // +0x28 per-tile threat level; filled by slot 0x0b
  int* tileCandidateScorePlane;
  int* tileIntArray;          // +0x30 advance-distance field (0x5a4460); -1 = unreached
  int battlefieldColumnCount; // +0x34 playable column count of this battle
  int battleSiteIndex;        // +0x38 cityScoreTable row of the battle site
  int tacticalTileCount;      // +0x3c = 0x1b3 (435 = 15*29 battle tiles)
  int tacticalTileStride;     // +0x40 = 0x1d (29)
  TacticalBattleOutcomeStorage battleOutcome; // +0x44
  bool pendingEndOfActionFlag;                // +0x48
  char fortLevel;                // +0x49 serialized; nonzero suppresses depl trench-marking
  unsigned char pad4a[2];        // +0x4a
  int currentTacticalActionCode; // +0x4c serialized
  int compositionClass;          // +0x50 stack-composition class of the battle
  int fortStrengthPoints[8];     // +0x54
  int roundCounter;              // +0x74

  TTacticalBattle();

  void StartBattle();

  void InitTacticalBattle(TTacticalPlayer* ourPlayer, TTacticalPlayer* enemyPlayer);

  TArmyTacUnit* SeekLinkedListCursorByNestedId(int nestedId);                // 0x5a53e0
  void LaSelect(TTacticalUnit* unit, bool remoteFlag);                       // 0x5a1010
  void DispatchTacticalActionByHoverStateIndex(TacticalTileIndex tileIndex); // 0x5a3370
  void ProcessTacticalUnitState1TurnStep(TTacticalUnit* unit);
  void UndeployUnit(TacticalTileIndex tileIndex); // 0x5a14d0, Mac oracle
  void LaMove(TTacticalUnit* unit, TacticalTileIndex fromTileIndex, TacticalTileIndex toTileIndex,
              bool remoteFlag); // 0x5a1910
  void LaFireOn(TTacticalUnit* attackerUnit, TTacticalUnit* targetUnit,
                TacticalTileIndex targetTileIndex, int damageA, int damageB, char effectCode2C,
                bool remoteFlag);            // 0x5a24a0
  float FindMoraleBonus(unsigned char side); // 0x5a2630, Mac oracle
  void LaMine(TacticalTileIndex tileIndex, int amount,
              bool remoteFlag); // 0x5a35a0
  void LaDig(TTacticalUnit* unit, TacticalTileIndex targetTileIndex,
             bool remoteFlag); // 0x5a36d0
  void LaRally(TArmyTacUnit* unit, int newMorale, int newState,
               bool remoteFlag); // 0x5a38e0
  void LaDeploy(TArmyTacUnit* unit, TacticalTileIndex tileIndex,
                bool remoteFlag); // 0x5a4370
  void HandleRetreatCommand();
  void FinishedDeploying();

  void HandleTacticalBattleCommandTag(int commandTag);
  void NextMove(); // 0x5a0e20
  void CycleTarget();
  // Helpers the command family dispatches into (all __thiscall on the battle).
  void ApplyTacticalDoneSelectionAndRefreshUi(TTacticalUnit* unit); // 0x59fe40
  // Mac identities: GetNeighborList(long, long*) and AreNeighbors(long, long).
  void GetNeighborList(TacticalTileIndex tileIndex,
                       TacticalTileIndex* outNeighborTiles6); // 0x5a0420
  bool ValidMove();                                           // 0x5a1b50
  void BeginFighting();                                       // 0x59fcd0
  bool AreNeighbors(TacticalTileIndex tileIndex,
                    TacticalTileIndex candidateTileIndex); // 0x5a0550
  void DamageFort(TacticalTileIndex tileIndex,
                  int consumeAmount); // 0x5a3c20
  void CheckForVictory();             // 0x5a2750
  void FinishedMove();
  void Cycle();
  // Paths the unit toward the target tile. 0x5a1520, __thiscall.
  void MoveTacticalUnitTowardTile(TTacticalUnit* unit, TacticalTileIndex targetTileIndex);
  bool ValidTargets();
  TacticalTileIndex FindFortWallTileCrossedByFiringLine(TacticalTileIndex targetTileIndex,
                                                        TacticalTileIndex attackerTileIndex);
  int SeekPath(TacticalTileIndex walkTileIndex, int pathDepth, TacticalTileIndex goalTileIndex,
               TacticalTileIndex* outPathTiles);
  // Reaction checks fired when a unit enters a tile; nonzero stops the walk. 0x5a1a20.
  bool CheckOpportunityFire(TacticalTileIndex tileIndex);
  unsigned char IsTacticalTargetTileReachableForAction(TacticalTileIndex attackerTileIndex,
                                                       TacticalTileIndex targetTileIndex,
                                                       char directFireFlag, int range);
  unsigned char CanFireOn(TTacticalUnit* unit,
                          TacticalTileIndex targetTileIndex); // 0x5a3cc0, Mac oracle
  int GetTileCursor(TacticalTileIndex tileIndex);
  short ResolveTacticalHoverCursorResourceId(TacticalTileIndex tileIndex); // 0x005a0a90
  void MakeRetreatMap(char ourSideFlag);
  bool IsTacticalTileAtFortWallSectionSlot(TacticalTileIndex tileIndex);
  // Deployment-zone queries. 0x5a4240 / 0x5a41c0 / 0x5a4330.
  int CountDeploymentTiles();
  bool ApplyGridColumnSelectionGuard(TacticalTileIndex tileIndex);
  // True when there is no fort or a wall section is breached.
  bool IsTacticalSideCategoryCoverageIncompleteOrFlagOff();
  bool HasFortWallGarrison(TacticalTileIndex tileIndex);
};

ASSERT_SIZE(TTacticalBattle, 0x78);
ASSERT_OFFSET(TTacticalBattle, players, 0x14);
ASSERT_OFFSET(TTacticalBattle, selectedUnit, 0x1c);

short __cdecl CompareTacticalUnitsForTurnOrder(void* a, void* b, void* context); // 0x59f610
