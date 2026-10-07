#pragma once

#include "compat.h"

#include "game/tactical_ui/TTask.h"
#include "game/mfc.h"

class TStream;
class TCity;
class TTaskList;

// VTABLE: IMPERIALISM 0x0066a9a8
class TCityTask : public TTask {
public:
  DECLARE_DYNCREATE(TCityTask)
  // FUNCTION: IMPERIALISM 0x005add70
  virtual ~TCityTask() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual bool Execute(TTaskList* taskList) override;
  virtual void IncompleteTraining(TTaskList* taskList);
  virtual void IncompleteMaterials();
  virtual void IncompleteCapacity(TTaskList* taskList);
  virtual void IncompleteLandUnit(TTaskList* taskList);
  virtual void IncompleteGoods(TTaskList* taskList);

  TCityTask();

  void ICityTask(short citySlotType, TCity* owner, short amount);

  TCity* ownerCity;
  short requestedAmount;            // quantity still needed
  short alreadyQueuedFlag;          // set after a follow-up task is queued
  unsigned char serializedTaskKind; // 1 for TCityTask, 2 for TShipBuildingTask
};
ASSERT_SIZE(TCityTask, 0x14);
