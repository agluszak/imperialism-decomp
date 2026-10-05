#pragma once

#include "compat.h"

#include "game/app/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TTaskList;

// VTABLE: IMPERIALISM 0x0066a970
class TTask : public TObject {
public:
  DECLARE_DYNCREATE(TTask)
  // FUNCTION: IMPERIALISM 0x005adbe0
  virtual ~TTask() override {}                     // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5adc50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5adc90
  virtual bool Execute(TTaskList* taskList); // slot 0x0a 0x5adc30

  TTask();
  void ITask(short citySlotType);

  short citySlotIndex;     // +0x04 — index into the owning TCity's order-slot table
  short remainingAttempts; // +0x06 — retry countdown; Execute() forces completion at 0
};
ASSERT_SIZE(TTask, 0x8);
