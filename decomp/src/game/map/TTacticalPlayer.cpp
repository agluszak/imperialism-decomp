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

// True no-op in the original (bare ret); TArmyPlayer's override is the per-tick
// battle pump.
// FUNCTION: IMPERIALISM 0x0059ad90
void TTacticalPlayer::NextMove() {}

// FUNCTION: IMPERIALISM 0x0059adb0
void TTacticalPlayer::DoClick(int unused) {
  (void)unused;
}

// FUNCTION: IMPERIALISM 0x0059add0
void TTacticalPlayer::ApplyChanges(unsigned char sideWonFlag) {
  (void)sideWonFlag;
}

// FUNCTION: IMPERIALISM 0x0059adf0
unsigned char TTacticalPlayer::AlwaysTrueTacticalPredicate10(TTacticalUnit* unit) {
  (void)unit;
  return 1;
}

// FUNCTION: IMPERIALISM 0x0059ae10
void TTacticalPlayer::ProceedAfterBattleIntroAccepted() {}

IMPLEMENT_DYNCREATE(TTacticalPlayer, TObject)

// Frees both unit lists (payloads included) and self-deletes.
// FUNCTION: IMPERIALISM 0x0059aea0
void TTacticalPlayer::ITacticalPlayer(unsigned char isOurSide, unsigned char watch,
                                      int nationIndex) {
  isOurSideFlag = isOurSide;
  watchFlagD = watch;
  fieldF = false;
  sideReadyFlag = false;
  cursorIndex = 0;
  nationIndex1C = nationIndex;
  field20 = false;
}

// FUNCTION: IMPERIALISM 0x0059aee0
void TTacticalPlayer::Free() {
  if (unitList4 != 0) {
    unitList4->FreePayloadsAndDestroy();
  }
  if (secondaryList != 0) {
    secondaryList->FreePayloadsAndDestroy();
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x0059af20
TTacticalUnit* TTacticalPlayer::SelectNextTacticalUnitForDoneCommand() {
  int startCursor = cursorIndex;
  TTacticalUnit* unit;
  do {
    cursorIndex = cursorIndex + 1;
    if (cursorIndex > unitList4->GetCount()) {
      cursorIndex = 1; // 1-based ordinal wrap
    }
    unit = static_cast<TTacticalUnit*>(unitList4->GetEntryByOrdinal(cursorIndex));
    if (cursorIndex == startCursor) {
      break; // wrapped all the way around
    }
  } while (unit->tileIndex8 != -2);
  // The loop STOPS at tileIndex8 == -2: it seeks the next NOT-YET-PLACED unit.
  if (unit->tileIndex8 != -2) {
    sideReadyFlag = true; // no undeployed unit left -> side ready
  }
  // The original re-fetches the entry; keep the second virtual call.
  return static_cast<TTacticalUnit*>(unitList4->GetEntryByOrdinal(cursorIndex));
}

// FUNCTION: IMPERIALISM 0x0059afa0
void TTacticalPlayer::RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) {
  CPtrList* entries = &unitList4->listState;
  POSITION pos = entries->Find(unit, 0);
  if (pos != 0) {
    entries->RemoveAt(pos);
  }
}

// Takes over a unit from the other side: prepends it to this side's list and flips
// its side marker.
// FUNCTION: IMPERIALISM 0x0059afe0
void TTacticalPlayer::AddTacticalUnitToUnitListHead(TTacticalUnit* unit) {
  unitList4->listState.AddHead(unit);
  unit->FlipUnitSideAffiliation();
}

// FUNCTION: IMPERIALISM 0x0059b010
bool TTacticalPlayer::IsTacticalControllerOwnedByActiveNation() {
  return nationIndex1C == g_pSimMgr->GetPlayerCountry();
}

// "skip" tactical command: unless the selected unit's type category is 8, mark this side and
// queue the end-of-action turn event on the battle.
// FUNCTION: IMPERIALISM 0x0059b040
void TTacticalPlayer::HandleTacticalCommandTag_skip() {
  if (g_awTacticalUnitCategoryCodeBySlot[battle14->selectedUnit1c->unitTypeC] != 8) {
    field20 = true;
    battle14->FinishTacticalActionAndPostNextMoveCommand();
  }
}

// FUNCTION: IMPERIALISM 0x0059b740
void TTacticalPlayer::RetireUndeployedUnitsToReserveList() {
  int ordinal;
  for (ordinal = unitList4->GetCount(); ordinal > 0; --ordinal) {
    TTacticalUnit* unit = static_cast<TTacticalUnit*>(unitList4->GetEntryByOrdinal(ordinal));
    if (unit->tileIndex8 == -2) {
      CPtrList* entries = &unitList4->listState;
      POSITION pos = entries->Find(unit, 0);
      if (pos != 0) {
        entries->RemoveAt(pos);
      }
      secondaryList->listState.AddHead(unit);
    }
  }
  CIterator reserveIter(secondaryList);
  for (TTacticalUnit* retired = static_cast<TTacticalUnit*>(reserveIter.Reset());
       reserveIter.More(); retired = static_cast<TTacticalUnit*>(reserveIter.Advance())) {
    CPtrList* recordEntries = &battle14->recordList->listState;
    POSITION recordPos = recordEntries->Find(retired, 0);
    if (recordPos != 0) {
      recordEntries->RemoveAt(recordPos);
    }
  }
}
