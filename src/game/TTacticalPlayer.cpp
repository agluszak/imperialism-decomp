#include "game/TTacticalPlayer.h"

#include "game/TSimMgr.h"
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

unsigned char TTacticalPlayer::AlwaysTrueTacticalPredicate10(int unused) {
  (void)unused;
  return 1;
}

void TTacticalPlayer::ProceedAfterBattleIntroAccepted() {}
// SYNTHETIC: IMPERIALISM 0x0059ad40
// TTacticalPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059ae30
// TTacticalPlayer::`scalar deleting destructor'
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

void TTacticalPlayer::RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) {
  // TODO: port body @ 0x59afa0 (unitList4 find + remove).
  (void)unit;
}

void TTacticalPlayer::AddTacticalUnitToUnitListHead(TTacticalUnit* unit) {
  // TODO: port body @ 0x59afe0 (unitList4 AddHead).
  (void)unit;
}

// FUNCTION: IMPERIALISM 0x0059af20
TTacticalUnit* TTacticalPlayer::SelectNextTacticalUnitForDoneCommand() {
  int startCursor = cursorIndex18;
  TTacticalUnit* unit;
  do {
    cursorIndex18 = cursorIndex18 + 1;
    if (unitList4->GetCount() < cursorIndex18) {
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

// FUNCTION: IMPERIALISM 0x0059b010
unsigned char TTacticalPlayer::IsTacticalControllerOwnedByActiveNation() {
  return static_cast<unsigned char>(nationIndex1C == g_pSimMgr->GetActiveNationId());
}
