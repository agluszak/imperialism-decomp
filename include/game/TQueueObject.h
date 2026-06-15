#pragma once

#include "game/TIndexAndRankList.h"
#include "game/CPtrArray.h"

// Recovered: nation turn/proposal/diplomacy queues are TSortedByRelationshipList
// instances (TIndexAndRankList vtable 0x00654d38). Provisional slot names map to
// the real TIndexAndRankList virtuals in TIndexAndRankList.h.
// Vtable is inherited from TIndexAndRankList (0x00672eac base / 0x00654d38 leaf);
// TQueueObject adds no virtuals, so it has no vtable of its own to annotate.
class TQueueObject : public TIndexAndRankList {
public:
  void WritePackedIntSlot38(int* packedValue) { AddEntrySlot38(packedValue); }
  void* GetEntryAt1BasedSlot2C(int index) { return GetEntrySlot2C(index); }
  void ApplyMessageSlot14(void* message) {
    (void)message;
    slot14();
  }
  void Call18(int arg1 = 0) {
    (void)arg1;
    slot18();
  }
  void Call1C() { ResetPtrListRecordsSlot1C(); }
  void Release1C() { ResetPtrListRecordsSlot1C(); }
  void Call20() { slot20(); }
  void Call24() { ReleaseSlot24(); }

  // Legacy name for CPtrArray::count at +0x8 on list-backed queues.
  int GetEntryCount() const { return static_cast<const CPtrArray*>(this)->GetSize(); }
};
