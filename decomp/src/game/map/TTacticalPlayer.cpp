#include "game/map/TTacticalPlayer.h"

#include "game/ui_core/CIterator.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x0059ad70
void TTacticalPlayer::StartBattle() {}

// FUNCTION: IMPERIALISM 0x0059ad90
void TTacticalPlayer::NextMove() {}

// FUNCTION: IMPERIALISM 0x0059adb0
void TTacticalPlayer::DoClick(int unused) {}

// FUNCTION: IMPERIALISM 0x0059add0
void TTacticalPlayer::ApplyChanges(unsigned char sideWonFlag) {}

// FUNCTION: IMPERIALISM 0x0059adf0
bool TTacticalPlayer::AlwaysTrueTacticalPredicate10(TTacticalUnit* unit) {
  return true;
}

// FUNCTION: IMPERIALISM 0x0059ae10
void TTacticalPlayer::ProceedAfterBattleIntroAccepted() {}

IMPLEMENT_DYNCREATE(TTacticalPlayer, TObject)

// Frees both unit lists (payloads included) and self-deletes.
// FUNCTION: IMPERIALISM 0x0059aea0
void TTacticalPlayer::ITacticalPlayer(unsigned char isOurSide, unsigned char watch,
                                      int nationIndex) {
  isOurSideFlag = isOurSide;
  watchFlag = watch;
  retreatOrdered = false;
  sideReadyFlag = false;
  cursorIndex = 0;
  this->nationIndex = nationIndex;
  skipRequested = false;
}

// FUNCTION: IMPERIALISM 0x0059aee0
void TTacticalPlayer::Free() {
  if (unitList != 0) {
    unitList->FreeList();
  }
  if (secondaryList != 0) {
    secondaryList->FreeList();
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x0059af20
TTacticalUnit* TTacticalPlayer::GetNextUnit() {
  int startCursor = cursorIndex;
  TTacticalUnit* unit;
  do {
    ++cursorIndex;
    if (cursorIndex > unitList->GetCount()) {
      cursorIndex = 1; // based ordinal wrap
    }
    unit = static_cast<TTacticalUnit*>(unitList->GetEntryByOrdinal(cursorIndex));
    if (cursorIndex == startCursor) {
      break; // wrapped all the way around
    }
  } while (unit->tileIndex != -2);
  // The loop STOPS at tileIndex == -2: it seeks the next NOT-YET-PLACED unit.
  if (unit->tileIndex != -2) {
    sideReadyFlag = true; // no undeployed unit left -> side ready
  }
  // The original re-fetches the entry; keep the second virtual call.
  return static_cast<TTacticalUnit*>(unitList->GetEntryByOrdinal(cursorIndex));
}

// FUNCTION: IMPERIALISM 0x0059afa0
void TTacticalPlayer::RemoveCapturedUnit(TTacticalUnit* unit) {
  CPtrList* entries = &unitList->listState;
  POSITION pos = entries->Find(unit, 0);
  if (pos != 0) {
    entries->RemoveAt(pos);
  }
}

// FUNCTION: IMPERIALISM 0x0059afe0
void TTacticalPlayer::AddCapturedUnit(TTacticalUnit* unit) {
  unitList->listState.AddHead(unit);
  unit->FlipUnitSideAffiliation();
}

// FUNCTION: IMPERIALISM 0x0059b010
bool TTacticalPlayer::IsPlayer() {
  return nationIndex == g_pSimMgr->GetPlayerCountry();
}

// FUNCTION: IMPERIALISM 0x0059b040
void TTacticalPlayer::HandleSkipCommand() {
  if (g_awTacticalUnitCategoryCodeBySlot[battle->selectedUnit->unitType] != 8) {
    skipRequested = true;
    battle->FinishedMove();
  }
}

// FUNCTION: IMPERIALISM 0x0059b740
void TTacticalPlayer::RemoveReserves() {
  int ordinal;
  for (ordinal = unitList->GetCount(); ordinal > 0; --ordinal) {
    TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitList->GetEntryByOrdinal(ordinal));
    if (unit->tileIndex == -2) {
      TTacticalPlayer::RemoveCapturedUnit(unit);
      secondaryList->listState.AddHead(unit);
    }
  }
  CIterator reserveIter(secondaryList);
  for (TTacticalUnit* retired = static_cast<TTacticalUnit*>(reserveIter.Reset());
       reserveIter.More(); retired = static_cast<TTacticalUnit*>(reserveIter.Advance())) {
    CPtrList* recordEntries = &battle->recordList->listState;
    POSITION recordPos = recordEntries->Find(retired, 0);
    if (recordPos != 0) {
      recordEntries->RemoveAt(recordPos);
    }
  }
}
