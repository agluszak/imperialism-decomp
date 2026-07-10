#pragma once

#include "game/TTacticalPlayer.h"
#include "game/mfc.h"

class TArmyStack;
class TTacticalUnit;

// TODO(manifest): describe TArmyPlayer and its role. Base edge (TTacticalPlayer) recovered from RTTI CRuntimeClass chain: TArmyPlayer -> TTacticalPlayer -> TObject -> CObject.
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
  TArmyStack* armyStack28;          // +0x28
  unsigned char pad2c[0x44 - 0x2c]; // +0x2c
  int field44;                      // +0x44 init -1 (0x59b1b0)
  unsigned char pad48[0x4c - 0x48]; // +0x48
  int field4C;                      // +0x4c init -1
  char randomParityByte50;          // +0x50 coin flip at side init (move-first side?)
  char field51;                     // +0x51 init 0
  unsigned char pad52[2];           // +0x52

  // Both original construction sites (0x5a4790, 0x5a4990) inline the ctor as a bare
  // vptr store.
  TArmyPlayer() {}

  // Applies the tactical cursor/UI mode profile for this side. Body TODO.
  // 0x0059c440, __thiscall, ret 4.
  void SelectAndApplyTacticalCursorModeProfile(int cursorProfileMode);

  // Auto-deploy helpers (0x59bc80 dispatcher). Curated names kept; behaviorally these
  // are the zone-score-table and per-class-tile-selector deploy strategies.
  void BuildTacticalActionPriorityBucketsWithGridGuard();      // 0x59bcf0
  void DispatchTacticalActionClassSelectionAcrossCursorList(); // 0x59bf20
  // Prunes unitList4 down to the free-tile capacity. Body TODO. 0x59b990.
  void RecomputeTacticalCursorProjectionScoresAndPruneList(int maxUnitCount);
  // Per-class deployment tile selectors. Bodies TODO.
  int SelectTacticalTileByActionClassAdjacencyPriority(); // 0x59c140
  int SelectTacticalTileIndexByColumnPriorityVariantA();  // 0x59bfe0
  int SelectTacticalTileIndexByColumnPriorityVariantB();  // 0x59c2a0
  // Weighted tile-heuristic selectors for the auto-turn controller. Bodies TODO.
  int SelectBestTacticalTileByWeightedHeuristics(TTacticalUnit* unit,
                                                 int* heuristicWeights15); // 0x59d530
  int SelectBestTacticalTargetTileByActionHeuristics(TTacticalUnit* unit,
                                                     int flag); // 0x59e110

  // Builds the side's tactical unit records from the stack's army unit chain and
  // stores the stack into armyStack28. 0x0059b1b0, __thiscall, ret 0x10. Body TODO.
  void InitializeTacticalSideFromArmyUnitList(TArmyStack* stack, int isOurSide, char watchFlag,
                                              int nationIndex);
};

ASSERT_SIZE(TArmyPlayer, 0x54);
