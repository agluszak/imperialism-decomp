#pragma once

#include "compat.h"

#include "game/tactical_ui/TCityTask.h"
#include "game/mfc.h"

class TStream;

// VTABLE: IMPERIALISM 0x0066a9f8
class TShipBuildingTask : public TCityTask {
public:
  DECLARE_DYNCREATE(TShipBuildingTask)
  // FUNCTION: IMPERIALISM 0x005ae6f0
  virtual ~TShipBuildingTask() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual bool Execute(TTaskList* taskList) override;

  TShipBuildingTask();

  void IShipBuildingTask(short citySlotType, TCity* owner, short requestedShipType);

  short requestedShipType;
  short waitingForShipOrderAdvance;
};
ASSERT_SIZE(TShipBuildingTask, 0x18);
