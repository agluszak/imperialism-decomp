#include "game/TNavyPlayer.h"
#include "game/TShip.h"

#include "game/CIterator.h"
#include "game/TNavyTacUnit.h"
#include "game/TTaskForce.h"

// SYNTHETIC: IMPERIALISM 0x0059ebb0
// TNavyPlayer::`scalar deleting destructor'
TNavyPlayer::~TNavyPlayer() {}
// SYNTHETIC: IMPERIALISM 0x0059eb80
// TNavyPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059ec00
// TNavyPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyPlayer, TTacticalPlayer)

TNavyPlayer::TNavyPlayer() {}

// Writes each surviving ship's losses back to its source fleet (required_count drops
// to the unit's remaining strength), then marks this side's fleet order node
// eliminated and prunes its order head.
// FUNCTION: IMPERIALISM 0x0059edd0
void TNavyPlayer::CommitTacticalResultsToSourceUnits(int unused) {
  (void)unused;
  CIterator unitIter(unitList4);
  for (TNavyTacUnit* unit = static_cast<TNavyTacUnit*>(unitIter.Reset()); unitIter.More();
       unit = static_cast<TNavyTacUnit*>(unitIter.Advance())) {
    TShip* force = unit->GetSourceTaskForce();
    force->DecrementRequiredCount(static_cast<short>(force->stockLevel1c - unit->strength4));
  }
  taskForce28->eliminatedFlag26 = 1;
  taskForce28->PruneInactiveTaskForceOrderHead();
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
  static_cast<TNavyTacUnit*>(unit)
      ->GetSourceTaskForce()
      ->ReassignOrderNodeNationAndRebindParentCounters(static_cast<short>(nationIndex1C));
}
