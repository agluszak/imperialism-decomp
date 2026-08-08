#include "game/tactical/TNavyPlayer.h"
#include "game/TList.h"
#include "game/navy/TShip.h"

#include "game/ui_core/CIterator.h"
#include "game/tactical/TNavyTacUnit.h"
#include "game/navy/TTaskForce.h"
// SYNTHETIC: IMPERIALISM 0x0059eb80
// TNavyPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059ebb0
// TNavyPlayer::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x0059ebe0
// TNavyPlayer::~TNavyPlayer

// SYNTHETIC: IMPERIALISM 0x0059ec00
// TNavyPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyPlayer, TTacticalPlayer)

// FUNCTION: IMPERIALISM 0x0059ec20
void TNavyPlayer::INavyPlayer(TTaskForce* force, char isOurSide, char watchFlag, int nationIndex) {
  isOurSideFlagC = isOurSide;
  sideReadyFlag10 = 0;
  watchFlagD = watchFlag;
  nationIndex1C = nationIndex;
  cursorIndex18 = 0;
  fieldF = 0;
  field20 = 0;
  targetingMode2c = kNavyTargetingHull;

  unitList4 = new TList();
  sideReadyFlag10 = 0;

  for (TMapOrderChildLinkNode* node = force->shipList; node != nullptr; node = node->next) {
    TShip* ship = static_cast<TShip*>(node->payload);
    TNavyTacUnit* unit = new TNavyTacUnit();
    unit->InitializeFromSourceShip(ship);
    unitList4->AddTail(unit);
    // The enemy side starts with every unit flagged; our own side does not.
    if (isOurSide == 0) {
      unit->selectedFlag18 = 1;
    }
  }

  cursorIndex18 = 0;
  taskForce28 = force;
}
// Writes each surviving ship's losses back to its source fleet (nation drops
// to the unit's remaining strength), then marks this side's fleet order node
// eliminated and prunes its order head.
// FUNCTION: IMPERIALISM 0x0059edd0
void TNavyPlayer::ApplyChanges(unsigned char sideWonFlag) {
  (void)sideWonFlag;
  CIterator unitIter(unitList4);
  for (TNavyTacUnit* unit = static_cast<TNavyTacUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TNavyTacUnit*>(unitIter.Advance())) {
    TShip* sourceShip = unit->GetSourceShip();
    sourceShip->Damage(static_cast<short>(sourceShip->strength - unit->strength4));
  }
  taskForce28->defeated = 1;
  taskForce28->SinkOrSwimShips();
}

// FUNCTION: IMPERIALISM 0x0059ee60
void TNavyPlayer::RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) {
  CPtrList* entries = &unitList4->listState;
  POSITION pos = entries->Find(unit, 0);
  if (pos != 0) {
    entries->RemoveAt(pos);
  }
}

// Takes over a captured ship: prepends it to this side's list, flips its side marker,
// and hands its source fleet's order node to this nation.
// FUNCTION: IMPERIALISM 0x0059eea0
void TNavyPlayer::AddTacticalUnitToUnitListHead(TTacticalUnit* unit) {
  unitList4->listState.AddHead(unit);
  unit->FlipUnitSideAffiliation();
  static_cast<TNavyTacUnit*>(unit)->GetSourceShip()->Capture(static_cast<short>(nationIndex1C));
}
