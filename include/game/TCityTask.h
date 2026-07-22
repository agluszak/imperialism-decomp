#pragma once

#include "game/TTask.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TCity;
class TSortedList;

// A queued city production/order command: references the owning city and an amount
// still to be sourced, dispatching to a type-specific queueing helper based on the
// base TTask::citySlotIndex. Constructed via `new TCityTask()` +
// InitializeCityProductionQueueCommand(city, type, amount) (0x5add90), then handed to a
// command queue.
// VTABLE: IMPERIALISM 0x0066a9a8
class TCityTask : public TTask {
public:
  DECLARE_DYNCREATE(TCityTask)
  virtual ~TCityTask() override;                   // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5ae570
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5ae5e0
  // Tries to satisfy requestedAmount directly from the owning city's stock
  // (TCity::DirectTransport) for slot indices 0..6, then always re-checks the order's
  // MaxOrder()/quantityField04 headroom, filling the order's OrderSheet and draining
  // per-resource DirectTransport calls when short, bumping the order's SetQuantity
  // either way. Finally dispatches to the type-specific queueing override selected by
  // citySlotIndex (ApplyProductionDistributionToCitySlots / QueueCityProductionOrderCommand /
  // QueueCityRecruitmentSupportCommandsIfDeficit / QueueCityOrderInputDeltaCommands /
  // QueueCityOrderType10CommandIfReady), then falls back to the base countdown when the
  // request wasn't fully satisfied. Renamed from the placeholder
  // OrphanLeaf_NoCall_Ins04_005adc30.
  virtual bool Tick(TSortedList* commandQueue) override;                      // slot 0x0a 0x5adde0
  virtual void QueueCityOrderType10CommandIfReady(TSortedList* commandQueue); // slot 0x0b 0x5ae010
  virtual void ApplyProductionDistributionToCitySlots();                      // slot 0x0c 0x5ae420
  virtual void
  QueueCityRecruitmentSupportCommandsIfDeficit(TSortedList* commandQueue);  // slot 0x0d 0x5ae0e0
  virtual void QueueCityOrderInputDeltaCommands(TSortedList* commandQueue); // slot 0x0e 0x5ae240
  virtual void QueueCityProductionOrderCommand(TSortedList* commandQueue);  // slot 0x0f 0x5ae4b0

  TCityTask(); // 0x005add20

  // Sets up a freshly-`new`'d TCityTask before it's handed to a command queue: default
  // remainingAttempts is 4, except citySlotType 5 (steel) gets only 3.
  void InitializeCityProductionQueueCommand(short citySlotType, TCity* owner,
                                            short amount); // 0x005add90

  TCity* ownerCity;          // +0x08
  short requestedAmount;     // +0x0c — quantity still needed
  short alreadyQueuedFlag;   // +0x0e — set once a follow-up TCityTask has been queued this tick
  unsigned char pendingFlag; // +0x10 — always 1 on construction; not restored by ReadFrom
};
