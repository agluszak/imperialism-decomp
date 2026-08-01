#pragma once

#include "compat.h"

#include "game/tactical_ui/TCityTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0066a9f8
class TShipBuildingTask : public TCityTask {
public:
  DECLARE_DYNCREATE(TShipBuildingTask)
  // FUNCTION: IMPERIALISM 0x005ae6f0
  virtual ~TShipBuildingTask() override {}         // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5ae9e0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5aea70
  // Resolves the requested ship type's six resource deficits against city stock, queues
  // one TCityTask for each remaining deficit, then waits for city ship order slot 0 to advance.
  virtual bool Tick(TSortedList* commandQueue) override; // slot 0x0a 0x5ae780

  TShipBuildingTask();

  void IShipBuildingTask(short citySlotType, TCity* owner,
                         short requestedShipType); // 0x005ae710

  short requestedShipType14;
  short waitingForShipOrderAdvance16;
};
ASSERT_SIZE(TShipBuildingTask, 0x18);
