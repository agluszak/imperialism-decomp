#include "game/TNavyBattle.h"

#include "game/TTacticalBattleView.h"
#include "game/TTacticalPlayer.h"
#include "game/TTacticalToolbar.h"
#include "game/TTacticalUnit.h"
#include "game/ui_control_tags.h"

// SYNTHETIC: IMPERIALISM 0x005a54d0
// TNavyBattle::`scalar deleting destructor'
TNavyBattle::~TNavyBattle() {}
// SYNTHETIC: IMPERIALISM 0x005a5480
// TNavyBattle::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a5520
// TNavyBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyBattle, TTacticalBattle)

TNavyBattle::TNavyBattle() {}

// FUNCTION: IMPERIALISM 0x005a55c0
void TNavyBattle::DeployTacticalUnitToTile(TTacticalUnit* unit, int tileIndex) {
  // A ship may only deploy on its side's two deploy rows (side 0: rows
  // battlefieldColumnCount34-6..-5; side 1: rows 5..6 -- the field acts as a row
  // bound here) onto an empty tile. On success it places the ship, invalidates its
  // tile rect, advances the current side's selection, and once that side is fully
  // deployed flips the side, refreshes the 'tool' toolbar, and either finalizes
  // deployment or kicks the incoming side's StartBattle (the navy analogue of
  // HandleTacticalCommandTag_retr's tail).
  unsigned char sideIsZero = (unit->side20 == 0);
  unsigned char canDeploy = 1;
  int rowIndex = tileIndex / 29;
  if (sideIsZero != 0) {
    if (rowIndex < battlefieldColumnCount34 - 6) {
      canDeploy = 0;
    } else if (rowIndex > battlefieldColumnCount34 - 5) {
      canDeploy = 0;
    }
  } else {
    if (rowIndex > 6) {
      canDeploy = 0;
    } else if (rowIndex < 5) {
      canDeploy = 0;
    }
  }
  if (tileGrid4[tileIndex].occupant4 != 0) {
    canDeploy = 0;
  }
  if (canDeploy == 0) {
    return;
  }

  unit->tileIndex8 = tileIndex;
  tileGrid4[tileIndex].occupant4 = unit;
  if (battleView8 != 0) {
    battleView8->InvalidateTacticalUnitTileRect(unit);
  }

  selectedUnit1c = (&tacticalPlayer14)[currentSideC]->SelectNextTacticalUnitForDoneCommand();
  if ((&tacticalPlayer14)[currentSideC]->sideReadyFlag10 == 0) {
    return;
  }

  currentSideC = (currentSideC == 0);
  selectedUnit1c = (&tacticalPlayer14)[currentSideC]->SelectNextTacticalUnitForDoneCommand();

  if (battleView8 != 0) {
    TTacticalToolbar* toolbar = static_cast<TTacticalToolbar*>(
        battleView8->ownerContext->ResolveControlByTag(kControlTagTool));
    toolbar->AssertValid();
    toolbar->UpdateTacticalCurrentUnitControlAndDialogLabel(selectedUnit1c);
    toolbar->InvokeSlot13C();
  }

  if ((&tacticalPlayer14)[currentSideC]->sideReadyFlag10 != 0) {
    FinalizeTacticalTurnStateAndQueueEvent232A();
    return;
  }
  (&tacticalPlayer14)[currentSideC]->StartBattle();
}

// FUNCTION: IMPERIALISM 0x005a5730
void TNavyBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant(TTacticalUnit* attackerUnit,
                                                                      int targetTileIndex) {
  (void)attackerUnit;
  (void)targetTileIndex;
}

// FUNCTION: IMPERIALISM 0x005a59f0
void TNavyBattle::ComputeTacticalReachableTileCostsByUnitCategory(TTacticalUnit* unit) {
  (void)unit;
}

// FUNCTION: IMPERIALISM 0x005a5b70
undefined TNavyBattle::CreateTTacticalBattleInstance() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5bc0
void TNavyBattle::ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(TTacticalUnit* unit,
                                                                            int targetTileIndex) {
  (void)unit;
  (void)targetTileIndex;
}

// FUNCTION: IMPERIALISM 0x005a5c50
void TNavyBattle::MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
    TTacticalUnit* unit, int targetTileIndex) {
  (void)unit;
  (void)targetTileIndex;
}
