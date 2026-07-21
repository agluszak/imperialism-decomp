#pragma once

#include "game/TCityTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0066a9f8
class TShipBuildingTask : public TCityTask {
public:
  DECLARE_DYNCREATE(TShipBuildingTask)
  virtual ~TShipBuildingTask() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5ae9e0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5aea70
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // body 0x5ae780 (472B, unported): compares against ownerCity->shipOrderSlots[0]'s
  // resourceTypeIndex48, then drains per-resource-cost tables (0x695b50.. globals indexed
  // by shipClassIndex*2) against the order's trackingSlots10, queueing a follow-up
  // TCityTask per shortfall. field14/field16 (ship class index + a companion short) still
  // need their own recovery pass before this can be ported.
  virtual bool Tick(TSortedList* commandQueue) override; // slot 0x0a 0x5ae780
  // slot 0x0b QueueCityOrderType10CommandIfReady inherited unchanged (0x5ae010)
  // slot 0x0c ApplyProductionDistributionToCitySlots inherited unchanged (0x5ae420)
  // slot 0x0d QueueCityRecruitmentSupportCommandsIfDeficit inherited unchanged (0x5ae0e0)
  // slot 0x0e QueueCityOrderInputDeltaCommands inherited unchanged (0x5ae240)
  // slot 0x0f QueueCityProductionOrderCommand inherited unchanged (0x5ae4b0)

  TShipBuildingTask();

  // Original object size is 0x18 (CRuntimeClass m_nObjectSize); the source class ended at 0x14.
  // Trailing 4 bytes are two shorts (Tick reads both +0x14 and +0x16 independently) --
  // not yet semantically recovered.
  short field14;
  short field16;
};
