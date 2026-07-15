#include "game/TTacticalPlayer.h"

#include "game/CIterator.h"
#include "game/TSimMgr.h"
#include "game/TTacticalBattle.h"
#include "game/TTacticalUnit.h"
#include "game/global_data_tables.h"

void TTacticalPlayer::StartBattle() {}

// True no-op in the original (bare ret); TArmyPlayer's override is the per-tick
// battle pump.
void TTacticalPlayer::AdvanceTacticalTurnPulse() {}

void TTacticalPlayer::NoOpTacticalPlayerHook0C(int unused) {
  (void)unused;
}

void TTacticalPlayer::CommitTacticalResultsToSourceUnits(int unused) {
  (void)unused;
}

unsigned char TTacticalPlayer::AlwaysTrueTacticalPredicate10(TTacticalUnit* unit) {
  (void)unit;
  return 1;
}

void TTacticalPlayer::ProceedAfterBattleIntroAccepted() {}
// SYNTHETIC: IMPERIALISM 0x0059ad40
// TTacticalPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059ae30
// TTacticalPlayer::`scalar deleting destructor'

// Trivial virtual destructor: restores the vtable pointer and returns (7 bytes at
// 0x0059ae60). Ghidra mislabeled this address as `CreateTTacticalPlayerInstance`; the
// scalar deleting destructor above calls it.
// FUNCTION: IMPERIALISM 0x0059ae60
TTacticalPlayer::~TTacticalPlayer() {}

// SYNTHETIC: IMPERIALISM 0x0059ae80
// TTacticalPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalPlayer, TObject)

// Frees both unit lists (payloads included) and self-deletes.
// FUNCTION: IMPERIALISM 0x0059aee0
void TTacticalPlayer::Free() {
  if (unitList4 != 0) {
    unitList4->FreePayloadsAndDestroy();
  }
  if (secondaryList8 != 0) {
    secondaryList8->FreePayloadsAndDestroy();
  }
  delete this;
}

// FUNCTION: IMPERIALISM 0x0059af20
TTacticalUnit* TTacticalPlayer::SelectNextTacticalUnitForDoneCommand() {
  int startCursor = cursorIndex18;
  TTacticalUnit* unit;
  do {
    cursorIndex18 = cursorIndex18 + 1;
    if (cursorIndex18 > unitList4->GetCount()) {
      cursorIndex18 = 1; // 1-based ordinal wrap
    }
    unit = static_cast<TTacticalUnit*>(unitList4->GetEntryByOrdinal(cursorIndex18));
    if (cursorIndex18 == startCursor) {
      break; // wrapped all the way around
    }
  } while (unit->tileIndex8 != -2);
  // The loop STOPS at tileIndex8 == -2: it seeks the next NOT-YET-PLACED unit.
  if (unit->tileIndex8 != -2) {
    sideReadyFlag10 = 1; // no undeployed unit left -> side ready
  }
  // The original re-fetches the entry; keep the second virtual call.
  return static_cast<TTacticalUnit*>(unitList4->GetEntryByOrdinal(cursorIndex18));
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
unsigned char TTacticalPlayer::IsTacticalControllerOwnedByActiveNation() {
  return static_cast<unsigned char>(nationIndex1C == g_pSimMgr->GetActiveNationId());
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
      secondaryList8->listState.AddHead(unit);
    }
  }
  CIterator reserveIter(secondaryList8);
  for (TTacticalUnit* retired = static_cast<TTacticalUnit*>(reserveIter.Reset());
       reserveIter.More(); retired = static_cast<TTacticalUnit*>(reserveIter.Advance())) {
    CPtrList* recordEntries = &battle14->recordList20->listState;
    POSITION recordPos = recordEntries->Find(retired, 0);
    if (recordPos != 0) {
      recordEntries->RemoveAt(recordPos);
    }
  }
}
