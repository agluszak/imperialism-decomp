#pragma once

#include "game/ui_core/TSortedList.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c9a0
class TArmyStackList : public TSortedList {
public:
  DECLARE_DYNCREATE(TArmyStackList)
  virtual ~TArmyStackList() override; // slot 0x01 (scalar deleting destructor)
  // Descending three-way compare of TArmyStack::field6. The payload type comes from the
  // one instance: TArmyMgr::pendingUnitPool0c, whose ctor installs this class's vtable
  // (0x64c9a0 at 0x4a193a) and whose readers cast every entry to TArmyStack*.
  short Compare(void* a, void* b) override; // slot 0x1b byte 0x6c 0x4a8560

  // Defined inline, like TSortedList's own ctor: the construction site inlines the base
  // TObject-vtbl + CPtrList(10) sequence and then stores this class's vtable (0x4a193a).
  // The marker claims the COMDAT copy the binary also carries.
  // FUNCTION: IMPERIALISM 0x004a8450
  TArmyStackList() : TSortedList() {}
};
