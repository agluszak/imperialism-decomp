#pragma once

#include "game/TIndexAndRankList.h"
#include "game/CPtrArray.h"

// Recovered: nation turn/proposal/diplomacy queues are TSortedByRelationshipList
// instances (TIndexAndRankList vtable 0x00654d38).
class TQueueObject : public TIndexAndRankList {
public:
  void WritePackedIntSlot38(int* packedValue) {
    AddEntrySlot38(packedValue);
  }
  void* GetEntryAt1BasedSlot2C(int index) {
    return GetEntrySlot2C(index);
  }

  int GetEntryCount() const {
    return static_cast<const CPtrArray*>(this)->GetSize();
  }
};
