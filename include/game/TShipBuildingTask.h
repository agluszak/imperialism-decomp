#pragma once

#include "game/TCityTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0066a9f8
class TShipBuildingTask : public TCityTask {
public:
// === BEGIN GENERATED DECLS (TShipBuildingTask) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TShipBuildingTask)
  virtual ~TShipBuildingTask() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override; // slot 0x05 0x5ae9e0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5aea70
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins04_005adc30() override; // slot 0x0a 0x5ae780
  // slot 0x0b QueueCityOrderType10CommandIfReady inherited unchanged (0x5ae010)
  // slot 0x0c ApplyProductionDistributionToCitySlots inherited unchanged (0x5ae420)
  // slot 0x0d QueueCityRecruitmentSupportCommandsIfDeficit inherited unchanged (0x5ae0e0)
  // slot 0x0e QueueCityOrderInputDeltaCommands inherited unchanged (0x5ae240)
  // slot 0x0f QueueCityProductionOrderCommand inherited unchanged (0x5ae4b0)
// === END GENERATED DECLS (TShipBuildingTask) ===

  TShipBuildingTask();
};

