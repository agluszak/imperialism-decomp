#pragma once

#include "compat.h"

#include "game/tactical_ui/TTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TCity;
class TTaskList;

// VTABLE: IMPERIALISM 0x0066a9a8
class TCityTask : public TTask {
public:
  DECLARE_DYNCREATE(TCityTask)
  // FUNCTION: IMPERIALISM 0x005add70
  virtual ~TCityTask() override {}                 // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5ae570
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5ae5e0
  virtual bool Execute(TTaskList* taskList) override;   // slot 0x0a 0x5adde0
  virtual void IncompleteTraining(TTaskList* taskList); // slot 0x0b 0x5ae010
  virtual void IncompleteMaterials();                   // slot 0x0c 0x5ae420
  virtual void IncompleteCapacity(TTaskList* taskList); // slot 0x0d 0x5ae0e0
  virtual void IncompleteLandUnit(TTaskList* taskList); // slot 0x0e 0x5ae240
  virtual void IncompleteGoods(TTaskList* taskList);    // slot 0x0f 0x5ae4b0

  TCityTask(); // 0x005add20

  void ICityTask(short citySlotType, TCity* owner,
                 short amount); // 0x005add90

  TCity* ownerCity;                 // +0x08
  short requestedAmount;            // +0x0c — quantity still needed
  short alreadyQueuedFlag;          // +0x0e — set after a follow-up task is queued
  unsigned char serializedTaskKind; // +0x10 — 1 for TCityTask, 2 for TShipBuildingTask
};
ASSERT_SIZE(TCityTask, 0x14);
