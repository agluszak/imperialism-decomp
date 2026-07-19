#pragma once

#include "game/TTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// VTABLE: IMPERIALISM 0x0066a9a8
class TCityTask : public TTask {
public:
  DECLARE_DYNCREATE(TCityTask)
  virtual ~TCityTask() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5ae570
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5ae5e0
  // slot 0x07 Free inherited unchanged (0x4798b0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanLeaf_NoCall_Ins04_005adc30(int) override;   // slot 0x0a 0x5adde0
  virtual undefined QueueCityOrderType10CommandIfReady(int* param_1); // slot 0x0b 0x5ae010
  virtual void ApplyProductionDistributionToCitySlots();              // slot 0x0c 0x5ae420
  virtual void
  QueueCityRecruitmentSupportCommandsIfDeficit(void* pCommandQueue);       // slot 0x0d 0x5ae0e0
  virtual void DeserializeCityProductionQueueCommand(void* pCommandQueue); // slot 0x0e 0x5ae240
  virtual void OrphanRetStub_0059add0(void* pCommandQueue);                // slot 0x0f 0x5ae4b0

  TCityTask();

  // Original object size is 0x14 (CRuntimeClass m_nObjectSize); the source class ended at 0x8. Trailing 12 byte(s) not yet semantically recovered — declared so sizeof and the recomp's allocation size match the original.
  int field08;
  int field0c;
  int field10;
};
