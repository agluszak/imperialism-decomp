#pragma once

#include "compat.h"

#include "game/TList.h"
#include "game/mfc.h"

class TTask;

// VTABLE: IMPERIALISM 0x0066aa48
class TTaskList : public TList {
public:
  DECLARE_DYNCREATE(TTaskList)
  virtual ~TTaskList() override;
  virtual bool ContainsTask(short citySlotIndex);

  TTaskList();
  void ITaskList();
  void AddTask(TTask* task);
  void ProcessTasks();
};
ASSERT_SIZE(TTaskList, 0x20);
