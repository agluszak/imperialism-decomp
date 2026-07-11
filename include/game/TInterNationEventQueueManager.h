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
  // 0x55cd00 — type-0x11 event: with the bypass flag clear in a live multiplayer
  // session it re-emits over the network as turn-event 0x22 instead of queueing
  // locally. Was misattributed to TSimMgr (the receiver at every callsite is the
  // 0x6a43e8 queue-manager global, e.g. the machine's case 0x22 receive path).
  void QueueInterNationEventType11(int eventParam, int value, char isReplayBypass);
  void AddOrUpdateBilateralActionRelationEntry(int eventCode, int nationA, int nationB);
  void InitializeInterNationEventQueueManager();

private:
  TPtrList* GetInterNationQueueByEventCode(int eventCode);

  unsigned char pad00[0x58C];
  TPtrList* dedupRecordQueue58c;
  unsigned char pad590[0xED4 - 0x590];
  // The queues are TPtrList instances (vtable 0x649068): the ctor 0x55b710
  // allocates the 7 buckets with recordSize14 0x24 and the shared record
  // queue with recordSize14 0x10.
  TPtrList* perNationEventBuckets[7];
  TPtrList* sharedEventRecordQueue;
  int perNationUiCounters7[7];
};
