#pragma once

#include "compat.h"

#include "game/TList.h"
#include "game/mfc.h"

class TTask;

// VTABLE: IMPERIALISM 0x0066aa48
class TTaskList : public TList {
public:
  DECLARE_DYNCREATE(TTaskList)
  virtual ~TTaskList() override;                           // slot 0x01 (scalar deleting destructor)
  virtual unsigned char ContainsTask(short citySlotIndex); // slot 0x1f byte 0x7c 0x5aed50

  TTaskList();
  // MacApp-style initializer run right after construction (TCity's ctor calls it through
  // 0x004054d9); the original body is a bare RET.
  void ITaskList();
  // Non-virtual append entry point -- the whole body is a dispatch to the virtual AddTail
  // slot. Every queue-a-task site calls this out-of-line copy rather than dispatching
  // inline, which is how the 15 xrefs to 0x5aeca0 are shaped.
  POSITION Insert(TTask* task);
};
ASSERT_SIZE(TTaskList, 0x20);
