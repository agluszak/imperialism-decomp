#pragma once

#include "decomp_types.h"

class TPtrList;

// Global singleton at g_pInterNationEventQueueManager (0x006A43E8).
// Ghidra labels calls through this pointer as TCountry* / TGreatPower*; that is
// the Windows nation-state vtable bucket, not this object. Layout matches
// InterNationEventQueueManager in ghidra_autogen/imperialism/Classes.h:
// per-nation buckets at 0xED4, shared type-0x0F merge queue at 0xEF0.
class TInterNationEventQueueManager {
public:
  void QueueInterNationEventRecordDeduped(int eventCode, int nationA, int nationB,
                                          char isReplayBypass);
  void QueueInterNationEventIntoNationBucket(int eventCode, int payloadOrNation,
                                             char isReplayBypass);
  void QueueInterNationEventType0FWithBitmaskMerge(int eventCode, int nationA, int nationB,
                                                   char isReplayBypass);
  void AddOrUpdateBilateralActionRelationEntry(int eventCode, int nationA, int nationB);

private:
  TPtrList* GetInterNationQueueByEventCode(int eventCode);

  unsigned char pad00[0x58C];
  TPtrList* dedupRecordQueue58c;
  unsigned char pad590[0xED4 - 0x590];
  // The queues are TPtrList instances (vtable 0x649068): the ctor 0x55b710
  // allocates the 7 buckets with relationType 0x24 and the shared record
  // queue with relationType 0x10.
  TPtrList* perNationEventBuckets[7];
  TPtrList* sharedEventRecordQueue;
  int perNationUiCounters7[7];
};
