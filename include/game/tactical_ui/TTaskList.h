#pragma once

#include "game/TList.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066aa48
class TTaskList : public TList {
public:
  DECLARE_DYNCREATE(TTaskList)
  virtual ~TTaskList() override;                           // slot 0x01 (scalar deleting destructor)
  virtual unsigned char ContainsTask(short citySlotIndex); // slot 0x1f byte 0x7c 0x5aed50

  TTaskList();
};
