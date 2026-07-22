#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TSortedList;

// VTABLE: IMPERIALISM 0x0066a970
class TTask : public TObject {
public:
  DECLARE_DYNCREATE(TTask)
  virtual ~TTask() override;                       // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5adc50
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5adc90
  // Base behavior: decrement remainingAttempts and report whether it just hit zero.
  // TCityTask's override (0x5adde0) replaces this with real per-tick order-fulfillment
  // logic but keeps the same "decrement counter, report expiry" tail. Renamed from the
  // placeholder OrphanLeaf_NoCall_Ins04_005adc30.
  virtual bool Tick(TSortedList* commandQueue); // slot 0x0a 0x5adc30

  TTask();

  // Fields recovered from TCityTask's Tick/WriteTo/ReadFrom overrides (0x5adde0/0x5ae570/
  // 0x5ae5e0): both halves of the original single `field04` are accessed and serialized
  // as independent 2-byte fields, matching the object's total size of 0x8.
  short citySlotIndex;     // +0x04 — index into the owning TCity's order-slot table
  short remainingAttempts; // +0x06 — retry countdown; Tick() forces completion at 0
};
