#include "game/TTacticalPlayer.h"

#include "game/TSimMgr.h"
#include "game/TTacticalUnit.h"
#include "game/global_data_tables.h"

undefined TTacticalPlayer::StartBattle() {
  return 0;
}

undefined TTacticalPlayer::OrphanRetStub_0059ad90() {
  return 0;
}

undefined TTacticalPlayer::TArmyTacUnit_VtblSlot00() {
  return 0;
}

undefined TTacticalPlayer::OrphanRetStub_0059add0() {
  return 0;
}

undefined TTacticalPlayer::TArmyTacUnit_VtblSlot04() {
  return 0;
}

undefined TTacticalPlayer::OrphanRetStub_0059ae10() {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0059ad40
// TTacticalPlayer::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059ae30
// TTacticalPlayer::`scalar deleting destructor'
TTacticalPlayer::~TTacticalPlayer() {}

// SYNTHETIC: IMPERIALISM 0x0059ae80
// TTacticalPlayer::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalPlayer, TObject)

void TTacticalPlayer::Free() {}

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
  // TODO: port body @ 0x59af20 (walks unitList4 via GetCount/GetEntryByOrdinal from
  // cursorIndex18, returns the first unit with tileIndex8 != -2).
  return 0;
}

// FUNCTION: IMPERIALISM 0x0059b010
unsigned char TTacticalPlayer::IsTacticalControllerOwnedByActiveNation() {
  return static_cast<unsigned char>(nationIndex1C == g_pSimMgr->GetActiveNationId());
}
