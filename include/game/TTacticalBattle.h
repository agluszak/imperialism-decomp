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
  // === BEGIN GENERATED DECLS (TTacticalBattle) — refreshed by recover-class; do not hand-edit ===
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
  virtual undefined OrphanRetStub_0059f710();                                 // slot 0x0c 0x59f710
  virtual undefined MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
      int param_1, undefined4 param_2); // slot 0x0d 0x5a1bd0
  virtual undefined
  WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400(undefined4 param_1, int param_2,
                                                            char param_3); // slot 0x0e 0x5a1400
  virtual undefined
  ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(int param_1); // slot 0x0f 0x5a1ca0
  virtual undefined
  EvaluateAndResolveTacticalActionAgainstTileOccupant(int* param_1,
                                                      int param_2); // slot 0x10 0x5a1ee0
  virtual undefined OrphanCallChain_C4_I30_005a2700(int param_1);   // slot 0x11 0x5a2700
  virtual undefined CreateTTacticalBattleInstance();                // slot 0x12 0x59f730
  virtual void
  MarkTacticalTileStateQueuedAndMaybeDispatchPacket(TArmyTacUnit* unit,
                                                    int targetTileIndex); // slot 0x13 0x5a3190
  virtual void AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(
      TArmyTacUnit* unit);                                       // slot 0x14 0x5a3210
  virtual void ClearTacticalTileStateRunByStride(int tileIndex); // slot 0x15 0x5a3320
  virtual undefined
  ComputeRallyStrengthAndQueueTacticalRallyCommand(int param_1); // slot 0x16 0x5a3810
  virtual void ExecuteTacticalMineActionAndQueuePacket(TTacticalUnit* unit,
                                                       int tileIndex); // slot 0x17 0x5a34d0
  virtual undefined
  ExecuteTacticalDigActionAndConsumeUnitActionPoints(int* param_1,
                                                     undefined4 param_2); // slot 0x18 0x5a3640
  // === END GENERATED DECLS (TTacticalBattle) ===

  // Offset-faithful layout (object is 0x78 per RTTI; TArmyBattle adds no bytes).
  // The ctor (0x59f770) zeroes +4, +8, +0x24, +0x1c, +0x34, +0x74, +0x20 -- in that
  // store order -- and leaves everything else (including the two player slots)
  // uninitialized. Serialized fields per TArmyBattle::ReadFrom/WriteTo (0x5a4990/
  // 0x5a4da0); grid/view fields per the tactical command handlers.
  TacticalTileRecord* tileGrid4;    // +0x04 per-tile grid, allocated by battle setup (0x59f890)
  TTacticalBattleView* battleView8; // +0x08 live view; null when the battle runs headless
  int currentSideC;                 // +0x0c side (0/1) of the current selection; serialized
  int field10;                      // +0x10 serialized battle-header dword
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
  int* tileIntArray30;          // +0x30 TODO(verify): use not yet observed
  int battlefieldColumnCount34; // +0x34 playable column count of this battle
  int battleSiteIndex38;        // +0x38 cityScoreTable row of the battle site
  int tacticalTileCount3c;      // +0x3c = 0x1b3 (435 = 15*29 battle tiles)
  int tacticalTileStride40;     // +0x40 = 0x1d (29)
  int field44;                  // +0x44 serialized; 0x5a5320 sets it to 1
  char field48;                 // +0x48
  char fortLevel49;             // +0x49 serialized; nonzero suppresses depl trench-marking
  unsigned char pad4a[2];       // +0x4a
  int field4c;                  // +0x4c serialized; == 7 suppresses the move animation
  int compositionClass50;       // +0x50 stack-composition class of the battle
  // Per-row-pair fort strength pools (one slot per two grid rows, tile/58), seeded by
  // LoadBattleSetupTabDataByIndex from g_anFortStrengthPointsByFortLevel; consumed by
  // the mine action, gates passability in slot 0x0a.
  int fortStrengthPoints54[8]; // +0x54
  int field74;                 // +0x74

  TTacticalBattle();

  // Start the battle by kicking the +0x18 player's StartBattle hook (Mac oracle:
  // TTacticalBattle::StartBattle(); original body is a bare mov/mov/jmp forwarder).
  // Called right after a battle object is created (TArmyMgr setup) or deserialized
  // (network join). 0x0059fc20.
  undefined StartBattle();

  // Battle-state assembly (Mac oracle: InitTacticalBattle); sets tacticalPlayer14/18
  // and allocates the tile grid. Body TODO. 0x0059f890.
  void BuildTacticalBattleStateFromBothSides(TTacticalPlayer* ourPlayer,
                                             TTacticalPlayer* enemyPlayer);

  // Tactical command family (local execution + multiplayer echo; turn events
  // 0x29/0x2a re-enter these with remoteFlag = 1 on the battle at
  // g_pActiveTacticalBattle). Signatures verified against the handler prologues and
  // the 0x545940 dispatcher's pushes.
  TArmyTacUnit* SeekLinkedListCursorByNestedId(int nestedId);                 // 0x5a53e0
  void SetCurrentTacticalUnitSelection(TTacticalUnit* unit, char remoteFlag); // 0x5a1010
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

  // Helpers the command family dispatches into (all __thiscall on the battle;
  // bodies TODO).
  void ApplyTacticalDoneSelectionAndRefreshUi(TTacticalUnit* unit);                   // 0x59fe40
  void ComputeHexNeighborTileIndices_005A0420(int tileIndex, int* outNeighborTiles6); // 0x5a0420
  void ConsumeFortStrengthPointsAndInvalidateIfDepleted(int tileIndex,
                                                        int consumeAmount); // 0x5a3c20
  void EvaluateTacticalSideStateAndShowBattleSummaryDialog();               // 0x5a2750
  // Queues the 0x232a end-of-action turn event (news a TCommand and clears field48).
  // Body TODO. 0x5a0d60, __thiscall.
  void QueueTacticalEventPacket232A();
};

ASSERT_SIZE(TTacticalBattle, 0x78);
