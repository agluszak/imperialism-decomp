#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class TArmyTacUnit;
class TList;
class TTacticalBattleView;
class TTacticalPlayer;
class TTacticalUnit;

// One 0x14-byte battle-grid tile record (array at TTacticalBattle::tileGrid4).
// +0x08 is written 1 when a trench-capable unit deploys; +0x10 is the trench-link
// bitmask: bits 0-5 = hex directions, 0x80 = first dig on a bare tile, 0x40 replaces
// it once a link exists.
struct TacticalTileRecord {
  int terrainType0;           // +0x00 terrain code 0..4 (indexes the move-cost table row)
  TTacticalUnit* occupant4;   // +0x04
  int deployMark8;            // +0x08 1 = trench-deploy mark; > 1 = fort-wall level
  int mineRunStateC;          // +0x0c sap/mine-run state: -1 clear, 2 queued, 0/1 advance
  unsigned char trenchMask10; // +0x10
  unsigned char pad11[3];     // +0x11
};

// Runs one tactical battle (army or navy branch): owns the hex battle grid, the two
// side players, and the tactical unit records; executes the tagged tactical commands
// (select/move/fire/mine/digg/raly/depl) locally and echoes them to multiplayer.
// Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalBattle ->
// TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a088
class TTacticalBattle : public TObject {
public:
  DECLARE_DYNCREATE(TTacticalBattle)
  virtual ~TTacticalBattle() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x59fb50
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void
  ComputeTacticalReachableTileCostsByUnitCategory(TTacticalUnit* unit);       // slot 0x0a 0x59ff20
  virtual void PropagateTileAccessibilityStrengthLevels(TTacticalUnit* unit); // slot 0x0b 0x5a02e0
  // Places a unit on a battle-grid tile (deployment). Base is a no-op stub.
  virtual void DeployTacticalUnitToTile(TTacticalUnit* unit, int tileIndex); // slot 0x0c 0x59f710
  virtual void MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
      TTacticalUnit* unit, int targetTileIndex); // slot 0x0d 0x5a1bd0
  // Whether either neighbor tile flanking hex direction `hexDirection` around
  // `tileIndex` holds a unit of the other side.
  virtual unsigned char HasEnemyUnitOnTilesFlankingHexDirection(int tileIndex, int hexDirection,
                                                                char side); // slot 0x0e 0x5a1400
  virtual void ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(
      TTacticalUnit* unit, int targetTileIndex); // slot 0x0f 0x5a1ca0
  virtual void
  EvaluateAndResolveTacticalActionAgainstTileOccupant(TTacticalUnit* attackerUnit,
                                                      int targetTileIndex); // slot 0x10 0x5a1ee0
  // Moves a unit's record onto the opposing side's player list (artillery capture).
  virtual void TransferTacticalUnitToOpposingSide(TTacticalUnit* unit); // slot 0x11 0x5a2700
  // Called once the battle's outcome is decided (TNextMoveCommand::DoIt, 0x5a6620).
  // Base is a no-op stub; TArmyBattle/TNavyBattle override with the real per-side
  // outcome processing. The old "CreateTTacticalBattleInstance" name was Ghidra junk
  // (the function finalizes an existing battle, it never constructs one).
  virtual undefined FinalizeTacticalBattleOutcome(int sideWonFlag); // slot 0x12 0x59f730
  virtual void
  MarkTacticalTileStateQueuedAndMaybeDispatchPacket(TArmyTacUnit* unit,
                                                    int targetTileIndex); // slot 0x13 0x5a3190
  virtual void AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(
      TArmyTacUnit* unit);                                       // slot 0x14 0x5a3210
  virtual void ClearTacticalTileStateRunByStride(int tileIndex); // slot 0x15 0x5a3320
  virtual undefined
  ComputeRallyStrengthAndQueueTacticalRallyCommand(TTacticalUnit* rallyingUnit,
                                                   TArmyTacUnit* rallyTarget); // slot 0x16 0x5a3810
  virtual void ExecuteTacticalMineActionAndQueuePacket(TTacticalUnit* unit,
                                                       int tileIndex); // slot 0x17 0x5a34d0
  virtual void
  ExecuteTacticalDigActionAndConsumeUnitActionPoints(TTacticalUnit* unit,
                                                     int tileIndex); // slot 0x18 0x5a3640

  // Offset-faithful layout (object is 0x78 per RTTI; TArmyBattle adds no bytes).
  // The ctor (0x59f770) zeroes +4, +8, +0x24, +0x1c, +0x34, +0x74, +0x20 -- in that
  // store order -- and leaves everything else (including the two player slots)
  // uninitialized. Serialized fields per TArmyBattle::ReadFrom/WriteTo (0x5a4990/
  // 0x5a4da0); grid/view fields per the tactical command handlers.
  TacticalTileRecord* tileGrid4;    // +0x04 per-tile grid, allocated by battle setup (0x59f890)
  TTacticalBattleView* battleView8; // +0x08 live view; null when the battle runs headless
  int currentSideC;                 // +0x0c side (0/1) of the current selection; serialized
  // battleLive10: 0 until the setup/sort step marks the battle live (see
  // "marks the battle live (battleLive10 = 1)" below); tested before per-round work runs.
  int battleLive10; // +0x10 serialized battle-header dword
  // The two battle players (Mac oracle: TTacticalBattle::InitTacticalBattle(
  // TTacticalPlayer*, TTacticalPlayer*)). Windows evidence: TTacticalBattle::Free
  // (0x59fb50) Free()s both; 0x5a2700 dispatches slots 0x0e/0x0f on them; 0x59fc20
  // dispatches slot 0x0a on the +0x18 one -- all slots TTacticalPlayer carries.
  TTacticalPlayer* tacticalPlayer14; // +0x14
  TTacticalPlayer* tacticalPlayer18; // +0x18
  // Currently selected/linked unit record; re-resolved by source-unit id in
  // TArmyBattle::ReadFrom, set by ApplyTacticalDoneSelectionAndRefreshUi.
  TTacticalUnit* selectedUnit1c; // +0x1c
  // Allocated by TArmyBattle::AllocateRecordList (0x59f7f0), called separately after
  // construction; TArmyBattle::ReadFrom appends the deserialized units here.
  TList* recordList20; // +0x20
  // Four owned per-tile work planes, (re)allocated by BuildTacticalBattleStateFromBothSides
  // and freed (POD operator delete) by Free (0x59fb50).
  short* tileMoveCostArray24;   // +0x24 per-tile move cost (-1 unreached); filled by slot 0x0a
  char* tileThreatLevelArray28; // +0x28 per-tile threat level; filled by slot 0x0b
  int* tileIntArray2c;          // +0x2c TODO(verify): use not yet observed
  int* tileIntArray30;          // +0x30 advance-distance field (0x5a4460); -1 = unreached
  int battlefieldColumnCount34; // +0x34 playable column count of this battle
  int battleSiteIndex38;        // +0x38 cityScoreTable row of the battle site
  int tacticalTileCount3c;      // +0x3c = 0x1b3 (435 = 15*29 battle tiles)
  int tacticalTileStride40;     // +0x40 = 0x1d (29)
  // battleOutcomeCode44: 0 undecided; 1 = side 0 still standing before round 35 (side-0
  // win), 2 = side-1 win (see the round-cutoff check near roundCounter74 below).
  int battleOutcomeCode44; // +0x44 serialized; 0x5a5320 sets it to 1
  // pendingEndOfActionFlag48: cleared when the 0x232a end-of-action turn event is queued
  // (news a TCommand); TArmyPlayer's move/target-selection loops (via the battle14
  // back-pointer) gate on it being nonzero. No observed set site in ported code yet.
  char pendingEndOfActionFlag48; // +0x48
  char fortLevel49;              // +0x49 serialized; nonzero suppresses depl trench-marking
  unsigned char pad4a[2];        // +0x4a
  // Hover/action code chosen for the current tile (0..0xc). Code 7 is a dig action,
  // so MoveTacticalUnitBetweenTiles suppresses its ordinary move animation.
  int currentTacticalActionCode4c; // +0x4c serialized
  int compositionClass50;          // +0x50 stack-composition class of the battle
  // Per-row-pair fort strength pools (one slot per two grid rows, tile/58), seeded by
  // LoadBattleSetupTabDataByIndex from g_anFortStrengthPointsByFortLevel; consumed by
  // the mine action, gates passability in slot 0x0a.
  int fortStrengthPoints54[8]; // +0x54
  // roundCounter74: current battle round; battleOutcomeCode44 is only decided once a side
  // has no live units and roundCounter74 < 0x23 (35).
  int roundCounter74; // +0x74

  TTacticalBattle();

  // Start the battle by kicking the +0x18 player's StartBattle hook (Mac oracle:
  // TTacticalBattle::StartBattle(); original body is a bare mov/mov/jmp forwarder).
  // Called right after a battle object is created (TArmyMgr setup) or deserialized
  // (network join). 0x0059fc20.
  void StartBattle();

  // Battle-state assembly (Mac oracle: InitTacticalBattle); sets tacticalPlayer14/18
  // and allocates the tile grid. 0x0059f890.
  void BuildTacticalBattleStateFromBothSides(TTacticalPlayer* ourPlayer,
                                             TTacticalPlayer* enemyPlayer);

  // Tactical command family (local execution + multiplayer echo; turn events
  // 0x29/0x2a re-enter these with remoteFlag = 1 on the battle at
  // g_pActiveTacticalBattle). Signatures verified against the handler prologues and
  // the 0x545940 dispatcher's pushes.
  TArmyTacUnit* SeekLinkedListCursorByNestedId(int nestedId);                 // 0x5a53e0
  void SetCurrentTacticalUnitSelection(TTacticalUnit* unit, char remoteFlag); // 0x5a1010
  void DispatchTacticalActionByHoverStateIndex(int tileIndex);                // 0x5a3370
  // Per-turn upkeep for a unit sitting in state 1 (morale broken): retreats it toward the
  // lowest-distance-field tile (BuildTacticalDistanceFieldForSide), then -- if still
  // morale-broken -- scores its odds of being removed from the battle by comparing a
  // quality-weighted threshold from nearby same-side units against a random roll (always
  // fatal if the retreat couldn't move the unit at all), and always queues the end-of-
  // action turn event. 0x5a10e0.
  void ProcessTacticalUnitState1TurnStep(TTacticalUnit* unit);
  void MoveTacticalUnitBetweenTiles(TTacticalUnit* unit, int fromTileIndex, int toTileIndex,
                                    char remoteFlag); // 0x5a1910
  void ApplyTacticalActionEffectsAndMaybeRemoveUnit(TTacticalUnit* attackerUnit,
                                                    TTacticalUnit* targetUnit, int targetTileIndex,
                                                    int damageA, int damageB, char effectCode2C,
                                                    char remoteFlag);             // 0x5a24a0
  void HandleTacticalCommandTag_mine(int tileIndex, int amount, char remoteFlag); // 0x5a35a0
  void HandleTacticalCommandTag_digg(TTacticalUnit* unit, int targetTileIndex,
                                     char remoteFlag); // 0x5a36d0
  void HandleTacticalCommandTag_raly(TArmyTacUnit* unit, int newMorale, int newState,
                                     char remoteFlag); // 0x5a38e0
  void HandleTacticalCommandTag_depl(TArmyTacUnit* unit, int tileIndex,
                                     char remoteFlag); // 0x5a4370
  // Hands the round over once the current side is done deploying: flips currentSideC,
  // selects the incoming side's next unit, refreshes the 'tool' toolbar, then either
  // finalizes the deployment phase or kicks the incoming side's StartBattle. 0x59fd10.
  void HandleTacticalCommandTag_retr();
  // Ends the deployment phase once both sides are ready: retires undeployed units,
  // sorts the record list into turn order, marks the battle live (battleLive10 = 1), arms
  // the live-battle toolbar controls and queues the 0x232a event. 0x59fdb0, __thiscall.
  void FinalizeTacticalTurnStateAndQueueEvent232A();

  // Top-level tactical toolbar command dispatch for the current side (tags done/auto/retr/
  // skip/targ); no-op unless the current side is human-watched. 0x5a0c50, __thiscall.
  void HandleTacticalBattleCommandTag(int commandTag);
  // "targ" command: cycles the selected unit's target to the next reachable enemy unit,
  // recentering the view on it (or plays a "no target" cue). 0x5a3f10, __thiscall.
  void HandleTacticalCommandTag_targ();
  // Sets the current side's navy ship-panel display mode (hull/crew/sail) from the navy
  // toolbar; the players are TNavyPlayer in a sea battle. 0x5a5b90, __thiscall.
  void SetCurrentSideNavyShipDisplayMode(int mode);

  // Helpers the command family dispatches into (all __thiscall on the battle).
  void ApplyTacticalDoneSelectionAndRefreshUi(TTacticalUnit* unit);                   // 0x59fe40
  void ComputeHexNeighborTileIndices_005A0420(int tileIndex, int* outNeighborTiles6); // 0x5a0420
  unsigned char IsHexNeighborTileIndex(int tileIndex,
                                       int candidateTileIndex); // 0x5a0550
  void ConsumeFortStrengthPointsAndInvalidateIfDepleted(int tileIndex,
                                                        int consumeAmount); // 0x5a3c20
  void EvaluateTacticalSideStateAndShowBattleSummaryDialog();               // 0x5a2750
  // Queues the 0x232a end-of-action turn event (news a TCommand and clears pendingEndOfActionFlag48).
  // 0x5a0d60, __thiscall.
  void QueueTacticalEventPacket232A();
  // Advances the turn cursor to the next live unit in recordList20's turn order,
  // skipping destroyed (state1c == 3) records; on wraparound bumps roundCounter74 and
  // ends the battle once it reaches 35 rounds (EvaluateTacticalSideStateAndShowBattle-
  // SummaryDialog + QueueTacticalEventPacket232A). Selects the found unit and either
  // runs its morale-broken turn step, its sap/mine tile-state advance (category 8 with
  // a pending sapTargetTileIndex40), or the current side's AdvanceTacticalTurnPulse.
  // Called from TNextMoveCommand::DoIt (0x5a6620) when the battle isn't yet decided.
  // 0x5a0ea0, __thiscall, no args.
  void AdvanceToNextTacticalUnitTurnStep();
  // Paths the unit toward the target tile. 0x5a1520, __thiscall.
  void MoveTacticalUnitTowardTile(TTacticalUnit* unit, int targetTileIndex);
  // Whether the selected unit still has a valid follow-up target for the current
  // action. 0x5a1d70, __thiscall.
  unsigned char HasValidTacticalFollowupTargetForCurrentAction();
  // Fort-wall tile index where the firing line between the two tiles crosses the wall
  // column, 0 when it does not. 0x5a3a70, __thiscall.
  int FindFortWallTileCrossedByFiringLine(int targetTileIndex, int attackerTileIndex);
  // Recursive distance-field path builder into outPathTiles (caller pre-seeds
  // outPathTiles[0] = target); returns the path depth or -1. 0x5a16e0.
  int BuildPathToTargetByDistanceField(int walkTileIndex, int pathDepth, int goalTileIndex,
                                       int* outPathTiles);
  // Reaction checks fired when a unit enters a tile; nonzero stops the walk. 0x5a1a20.
  unsigned char ResolveTacticalReactionChecksForTile(int tileIndex);
  // Whether the target tile is reachable for the current action (range scaled by the
  // attacker category's direct-fire flag). 0x5a3d30, ret 0x10.
  unsigned char IsTacticalTargetTileReachableForAction(int attackerTileIndex, int targetTileIndex,
                                                       char directFireFlag, int range);
  // Hover-cursor state for `tileIndex` relative to the current selection/side: not-your-turn
  // (1), pre-battle-live setup checks (own-unit hover 0xc, blocked 2, deployment zone 3), and
  // once the battle is live: own-tile reselect (6), reachable empty move tile (4), manned fort
  // wall (9), adjacent dig/mine target (7), adjacent rally target (8), ranged/fire attack
  // target (5), adjacent melee attack target (0xa). 0 when nothing applies. 0x5a05a0.
  int ComputeTacticalHoverCursorStateIndex(int tileIndex);
  short ResolveTacticalHoverCursorResourceId(int tileIndex); // 0x005a0a90
  // Builds the per-tile distance field into tileIntArray30 for the given side
  // (consumed by the AI advance heuristic). 0x5a4460.
  void BuildTacticalDistanceFieldForSide(char ourSideFlag);
  // Whether the tile sits on a fort-wall gun-slot row (5/7/9) at the wall column.
  // 0x5a4690.
  unsigned char IsTacticalTileAtFortWallSectionSlot(int tileIndex);
  // Deployment-zone queries. 0x5a4240 / 0x5a41c0 / 0x5a4330.
  int CountFreeDeploymentZoneTilesForCurrentSide();
  unsigned char ApplyGridColumnSelectionGuard(int tileIndex);
  // True when there is no fort or a wall section is breached (curated name kept).
  unsigned char IsTacticalSideCategoryCoverageIncompleteOrFlagOff();
  // True when tileIndex is a fort-wall tile (deployMark8 > 1) whose double-row group
  // still has a positive fortStrengthPoints54 entry (garrison intact). 0x5a42e0.
  bool HasFortWallGarrison(int tileIndex);
};

ASSERT_SIZE(TTacticalBattle, 0x78);

// Turn-order comparator for the battle record list (0x59fdb0 passes it to
// SortBy): higher base action points first, then higher quality, then the +0x24
// serialized word. Returns its -1/0/1 verdict in AX (short); the context argument
// (the battle, passed by the SortBy call site) is unused.
short __cdecl CompareTacticalUnitsForTurnOrder(void* a, void* b, void* context); // 0x59f610
