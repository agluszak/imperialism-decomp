#include "StartingCiviliansProbe.h"

#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TSortedList.h"

namespace {

// An Introductory game grants each nation this many civilians to start with.
const int kIntroductoryStartingCivilians = 5;

TSortedList* RosterForNation(short nationSlot) {
  TGreatPower* nation = nationSlot >= 0 ? g_apNationStates[nationSlot] : 0;
  return nation != 0 ? nation->trackedObjectList : 0;
}

} // namespace

RuntimeActionResult StartingCiviliansProbe::VerifyForNation(short nationSlot) {
  TSortedList* roster = RosterForNation(nationSlot);
  if (roster == 0) {
    return RuntimeActionResult::Failure("the active nation has no tracked-object list");
  }
  // The list's class is part of the contract, not a formality: the game walks it as a sorted list
  // of TCivUnit, so a pointer to some other collection would be read with the wrong element type.
  if (roster->IsKindOf(RUNTIME_CLASS(TSortedList)) == 0) {
    return RuntimeActionResult::Failure(
        "the active nation's tracked-object list is not a TSortedList");
  }
  int civilianCount = 0;
  for (int ordinal = 1; ordinal <= roster->GetCount(); ++ordinal) {
    CObject* entry = static_cast<CObject*>(roster->GetEntryByOrdinal(ordinal));
    if (entry == 0 || entry->IsKindOf(RUNTIME_CLASS(TCivUnit)) == 0) {
      CString detail;
      detail.Format("tracked-object entry %d is not a civilian", ordinal);
      return RuntimeActionResult::Failure(detail);
    }
    ++civilianCount;
    if (static_cast<TCivUnit*>(entry)->tileIndex06 < 0) {
      CString detail;
      detail.Format("starting civilian %d has no map tile", ordinal);
      return RuntimeActionResult::Failure(detail);
    }
  }
  if (civilianCount < kIntroductoryStartingCivilians) {
    CString detail;
    detail.Format("the active nation received %d starting civilians, not %d", civilianCount,
                  kIntroductoryStartingCivilians);
    return RuntimeActionResult::Failure(detail);
  }
  return RuntimeActionResult::Success();
}

TCivUnit* StartingCiviliansProbe::CivilianForNation(short nationSlot, int ordinal) {
  TSortedList* roster = RosterForNation(nationSlot);
  if (roster == 0 || ordinal < 1 || ordinal > roster->GetCount()) {
    return 0;
  }
  CObject* entry = static_cast<CObject*>(roster->GetEntryByOrdinal(ordinal));
  return entry != 0 && entry->IsKindOf(RUNTIME_CLASS(TCivUnit)) != 0 ? static_cast<TCivUnit*>(entry)
                                                                     : 0;
}
