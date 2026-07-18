#pragma once

#include "game/TSortedList.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0064c9a0
class TArmyStackList : public TSortedList {
public:
  DECLARE_DYNCREATE(TArmyStackList)
  virtual ~TArmyStackList() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x488820)
  // slot 0x06 ReadFrom inherited unchanged (0x488800)
  // slot 0x07 Free inherited unchanged (0x488790)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a AddHead inherited unchanged (0x4885d0)
  // slot 0x0b AddHeadEx inherited unchanged (0x4885f0)
  // slot 0x0c AddTail inherited unchanged (0x488610)
  // slot 0x0d AddTailEx inherited unchanged (0x488630)
  // slot 0x0e AddTailSlot38 inherited unchanged (0x488650)
  // slot 0x0f RemoveTail inherited unchanged (0x488670)
  // slot 0x10 AddTailSlot40 inherited unchanged (0x488690)
  // slot 0x11 RemoveHead inherited unchanged (0x4886b0)
  // slot 0x12 GetCount inherited unchanged (0x4886d0)
  // slot 0x13 GetEntryByOrdinal inherited unchanged (0x4886f0)
  // slot 0x14 RemoveAtOrdinal inherited unchanged (0x488720)
  // slot 0x15 FreePayloads inherited unchanged (0x488750)
  // slot 0x16 FreePayloadsAndDestroy inherited unchanged (0x4887b0)
  // slot 0x17 RemoveAll inherited unchanged (0x4887e0)
  // slot 0x18 SetAtOrdinal inherited unchanged (0x488840)
  // slot 0x19 OrphanLeaf_NoCall_Ins07_004d8920 inherited unchanged (0x487d90)
  // slot 0x1a OrphanCallChain_C11_I88_004874b0 inherited unchanged (0x487dd0)
  // Descending three-way compare of the short at +0x6 of each payload (stack-size
  // ordering; the payload record type is not yet recovered).
  short Compare(void* a, void* b) override; // slot 0x1b byte 0x6c 0x4a8560
  // slot 0x1c VTableSlot1C inherited unchanged (0x487b60)
  // slot 0x1d QueueCityRecruitmentSupportCommandsIfDeficit inherited unchanged (0x487bd0)
  // slot 0x1e GetTTaskClassNamePointer inherited unchanged (0x487cc0)

  TArmyStackList();
};
