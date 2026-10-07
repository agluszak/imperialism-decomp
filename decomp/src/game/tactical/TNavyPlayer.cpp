#include "game/tactical/TNavyPlayer.h"
#include "game/TList.h"
#include "game/navy/TShip.h"

#include "game/ui_core/CIterator.h"
#include "game/tactical/TNavyTacUnit.h"
#include "game/navy/TTaskForce.h"

IMPLEMENT_DYNCREATE(TNavyPlayer, TTacticalPlayer)

// FUNCTION: IMPERIALISM 0x0059ec20
void TNavyPlayer::INavyPlayer(TTaskForce* force, char isOurSide, bool watchFlag, int nationIndex) {
  isOurSideFlag = isOurSide;
  sideReadyFlag = false;
  this->watchFlag = watchFlag;
  this->nationIndex = nationIndex;
  cursorIndex = 0;
  retreatOrdered = false;
  skipRequested = false;
  targetingMode = kNavyTargetingHull;

  unitList = new TList();
  sideReadyFlag = false;

  for (TMapOrderChildLinkNode* node = force->shipList; node != NULL; node = node->next) {
    TShip* ship = node->payload;
    TNavyTacUnit* unit = new TNavyTacUnit();
    unit->InitializeFromSourceShip(ship);
    unitList->AddTail(unit);
    // The enemy side starts with every unit flagged; our own side does not.
    if (isOurSide == 0) {
      unit->selectedFlag = true;
    }
  }

  cursorIndex = 0;
  taskForce = force;
}

// FUNCTION: IMPERIALISM 0x0059edd0
void TNavyPlayer::ApplyChanges(unsigned char sideWonFlag) {
  CIterator unitIter(unitList);
  for (TNavyTacUnit* unit = static_cast<TNavyTacUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TNavyTacUnit*>(unitIter.Advance())) {
    TShip* sourceShip = unit->GetRealShip();
    sourceShip->Damage(static_cast<short>(sourceShip->strength - unit->strength));
  }
  taskForce->defeated = 1;
  taskForce->SinkOrSwimShips();
}

// FUNCTION: IMPERIALISM 0x0059ee60
void TNavyPlayer::RemoveCapturedUnit(TTacticalUnit* unit) {
  CPtrList* entries = &unitList->listState;
  POSITION pos = entries->Find(unit, 0);
  if (pos != 0) {
    entries->RemoveAt(pos);
  }
}

// FUNCTION: IMPERIALISM 0x0059eea0
void TNavyPlayer::AddCapturedUnit(TTacticalUnit* unit) {
  unitList->listState.AddHead(unit);
  unit->FlipUnitSideAffiliation();
  static_cast<TNavyTacUnit*>(unit)->GetRealShip()->Capture(static_cast<short>(nationIndex));
}
