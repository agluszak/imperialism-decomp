#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

class TStream;
class TTaskList;

// VTABLE: IMPERIALISM 0x0066a970
class TTask : public TObject {
public:
  DECLARE_DYNCREATE(TTask)
  // FUNCTION: IMPERIALISM 0x005adbe0
  virtual ~TTask() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual bool Execute(TTaskList* taskList);

  TTask();
  void ITask(short citySlotType);

  short citySlotIndex;     // index into the owning TCity's order-slot table
  short remainingAttempts; // retry countdown; Execute() forces completion at 0
};
ASSERT_SIZE(TTask, 0x8);
