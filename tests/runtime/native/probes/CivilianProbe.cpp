#include "CivilianProbe.h"

#include "game/app/TAnimation.h"
#include "game/app/TCivAnimation2.h"
#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TSortedList.h"

namespace {

TSortedList* RosterForNation(short nationSlot) {
  TGreatPower* nation = nationSlot >= 0 ? g_apNationStates[nationSlot] : 0;
  return nation != 0 ? nation->trackedObjectList : 0;
}

} // namespace

TCivUnit* CivilianProbe::CivilianWithPersistentId(short nationSlot, int persistentUnitId) {
  TSortedList* roster = RosterForNation(nationSlot);
  if (roster == 0) {
    return 0;
  }
  for (int ordinal = 1; ordinal <= roster->GetCount(); ++ordinal) {
    CObject* entry = static_cast<CObject*>(roster->GetEntryByOrdinal(ordinal));
    if (entry == 0 || entry->IsKindOf(RUNTIME_CLASS(TCivUnit)) == 0) {
      continue;
    }
    TCivUnit* civilian = static_cast<TCivUnit*>(entry);
    if (civilian->persistentUnitId20 == persistentUnitId) {
      return civilian;
    }
  }
  return 0;
}

int CivilianProbe::CivilianCount(short nationSlot) {
  TSortedList* roster = RosterForNation(nationSlot);
  return roster != 0 ? roster->GetCount() : -1;
}

bool CivilianProbe::IsCivilianSpriteAnimation(TAnimation* animation) {
  return animation != 0 && animation->IsKindOf(RUNTIME_CLASS(TCivAnimation2)) != 0;
}
