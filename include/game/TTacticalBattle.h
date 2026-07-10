#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class TList;
class TTacticalPlayer;

// TODO(manifest): describe TTacticalBattle and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalBattle -> TObject -> CObject.
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
  virtual undefined
  ComputeTacticalReachableTileCostsByUnitCategory(int param_1);              // slot 0x0a 0x59ff20
  virtual undefined PropagateTileAccessibilityStrengthLevels(char* param_1); // slot 0x0b 0x5a02e0
  virtual undefined OrphanRetStub_0059f710();                                // slot 0x0c 0x59f710
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
  virtual undefined
  MarkTacticalTileStateQueuedAndMaybeDispatchPacket(int* param_1,
                                                    int param_2); // slot 0x13 0x5a3190
  virtual undefined
  AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(int param_1); // slot 0x14 0x5a3210
  virtual undefined ClearTacticalTileStateRunByStride(int param_1);      // slot 0x15 0x5a3320
  virtual undefined
  ComputeRallyStrengthAndQueueTacticalRallyCommand(int param_1); // slot 0x16 0x5a3810
  virtual undefined ExecuteTacticalMineActionAndQueuePacket(int param_1,
                                                            int param_2); // slot 0x17 0x5a34d0
  virtual undefined
  ExecuteTacticalDigActionAndConsumeUnitActionPoints(int* param_1,
                                                     undefined4 param_2); // slot 0x18 0x5a3640
  // === END GENERATED DECLS (TTacticalBattle) ===

  // Offset-faithful layout (object is 0x78 per RTTI; TArmyBattle adds no bytes).
  // The ctor (0x59f770) zeroes +4, +8, +0x24, +0x1c, +0x34, +0x74, +0x20 -- in that
  // store order -- and leaves everything else (including the two player slots)
  // uninitialized.
  int field4;                      // +0x04
  int field8;                      // +0x08
  unsigned char pad0c[0x14 - 0xc]; // +0x0c
  // The two battle players (Mac oracle: TTacticalBattle::InitTacticalBattle(
  // TTacticalPlayer*, TTacticalPlayer*)). Windows evidence: TTacticalBattle::Free
  // (0x59fb50) Free()s both; 0x5a2700 dispatches slots 0x0e/0x0f on them; 0x59fc20
  // dispatches slot 0x0a on the +0x18 one -- all slots TTacticalPlayer carries.
  TTacticalPlayer* tacticalPlayer14; // +0x14
  TTacticalPlayer* tacticalPlayer18; // +0x18
  int field1c;                       // +0x1c
  // Allocated by TArmyBattle::AllocateRecordList (0x59f7f0), called separately after
  // construction; TArmyBattle::ReadFrom appends the deserialized units here.
  TList* recordList20;              // +0x20
  int field24;                      // +0x24
  unsigned char pad28[0x34 - 0x28]; // +0x28
  int field34;                      // +0x34
  unsigned char pad38[0x74 - 0x38]; // +0x38
  int field74;                      // +0x74

  TTacticalBattle();

  // Start the battle by kicking the +0x18 player's StartBattle hook (Mac oracle:
  // TTacticalBattle::StartBattle(); original body is a bare mov/mov/jmp forwarder).
  // Called right after a battle object is created (TArmyMgr setup) or deserialized
  // (network join). 0x0059fc20.
  undefined StartBattle();

  // Network tactical-command receive family (turn events 0x29/0x2a dispatch on the
  // live battle at g_pActiveTacticalBattle). All __thiscall on the battle object;
  // signatures verified against the 0x545940 dispatcher's pushes. Bodies TODO.
  // The 'unit' values are whatever SeekLinkedListCursorByNestedId returns (a unit-list
  // node; the 'fire' path reads its +0x8 dword) — void* until that type is recovered.
  void* SeekLinkedListCursorByNestedId(int nestedId);         // 0x5a53e0
  void SetCurrentTacticalUnitSelection(void* unit, int flag); // 0x5a1010
  void MoveTacticalUnitBetweenTiles(void* unit, int arg20, int arg24,
                                    int flag); // 0x5a1910
  void ApplyTacticalActionEffectsAndMaybeRemoveUnit(void* attackerUnit, void* targetUnit,
                                                    int targetUnitField8, int arg24, int arg28,
                                                    char arg2C, int flag); // 0x5a24a0
  void HandleTacticalCommandTag_mine(int arg20, int arg24, int flag);      // 0x5a35a0
  void HandleTacticalCommandTag_digg(void* unit, int arg20, int flag);     // 0x5a36d0
  void HandleTacticalCommandTag_raly(void* unit, int arg20, int arg24,
                                     int flag);                        // 0x5a38e0
  void HandleTacticalCommandTag_depl(void* unit, int arg20, int flag); // 0x5a4370
};

ASSERT_SIZE(TTacticalBattle, 0x78);
